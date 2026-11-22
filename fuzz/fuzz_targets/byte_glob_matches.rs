//! Fuzz the matcher against a second, slower one written separately, over patterns and names
//! longer than the host tests' exhaustive cross-check reaches.
//!
//! The first byte splits the rest of the input into a pattern and a name, each cut to 64 bytes so
//! the reference stays cheap. For every pair, under both leading-dot rules:
//!
//! - nothing panics, and the step count is at most `step_bound` of the two lengths;
//! - `match_steps`, `matches_with` and (under the default rule) `matches` agree with each other
//!   and with the reference;
//! - a pattern with no magic has a literal, matches exactly that literal under
//!   `LeadingDot::Ordinary`, and a pattern with magic has none.
//!
//! The reference parses the pattern into a list of elements once and then fills a table of
//! "does pattern suffix `j` match name suffix `i`". It shares no code with the crate: an
//! agreement is two readings of the syntax, not one reading run twice.

#![no_main]

use byte_glob::{LeadingDot, has_magic, literal, match_steps, matches, matches_with, step_bound};
use libfuzzer_sys::fuzz_target;

const MAXIMUM_BYTES: usize = 64;

/// One element of a parsed pattern.
enum Element {
    /// `*`
    Star,
    /// `?`
    Any,
    /// One byte, however it was written.
    Byte(u8),
    /// A closed bracket expression, as the set of bytes it matches, negation applied.
    Class([bool; 256]),
}

/// Parse a bracket expression opened at `open`: the set it matches and the index after its `]`,
/// or `None` when no `]` closes it.
fn class(pattern: &[u8], open: usize) -> Option<([bool; 256], usize)> {
    let mut k = open + 1;
    let negated = matches!(pattern.get(k), Some(b'!' | b'^'));
    if negated {
        k += 1;
    }
    let mut set = [false; 256];
    let mut first = true;
    loop {
        let byte = *pattern.get(k)?;
        if byte == b']' && !first {
            if negated {
                for member in &mut set {
                    *member = !*member;
                }
            }
            return Some((set, k + 1));
        }
        first = false;
        // A backslash inside a class escapes the byte after it, when there is one.
        let (low, after_low) = match (byte, pattern.get(k + 1)) {
            (b'\\', Some(&escaped)) => (escaped, k + 2),
            _ => (byte, k + 1),
        };
        // A `-` makes a range only when a byte other than `]` follows it.
        let range_end = match (pattern.get(after_low), pattern.get(after_low + 1)) {
            (Some(b'-'), Some(&end)) if end != b']' => Some(after_low + 1),
            _ => None,
        };
        match range_end {
            Some(start) => {
                let (high, after_high) = match (pattern[start], pattern.get(start + 1)) {
                    (b'\\', Some(&escaped)) => (escaped, start + 2),
                    (end, _) => (end, start + 1),
                };
                for member in low..=high {
                    set[usize::from(member)] = true;
                }
                k = after_high;
            }
            None => {
                set[usize::from(low)] = true;
                k = after_low;
            }
        }
    }
}

/// Parse a whole pattern. An unclosed `[` and a trailing `\` are the bytes they are.
fn parse(pattern: &[u8]) -> Vec<Element> {
    let mut elements = Vec::new();
    let mut j = 0;
    while let Some(&byte) = pattern.get(j) {
        match byte {
            b'*' => {
                elements.push(Element::Star);
                j += 1;
            }
            b'?' => {
                elements.push(Element::Any);
                j += 1;
            }
            b'\\' => match pattern.get(j + 1) {
                Some(&escaped) => {
                    elements.push(Element::Byte(escaped));
                    j += 2;
                }
                None => {
                    elements.push(Element::Byte(b'\\'));
                    j += 1;
                }
            },
            b'[' => match class(pattern, j) {
                Some((set, next)) => {
                    elements.push(Element::Class(set));
                    j = next;
                }
                None => {
                    elements.push(Element::Byte(b'['));
                    j += 1;
                }
            },
            _ => {
                elements.push(Element::Byte(byte));
                j += 1;
            }
        }
    }
    elements
}

/// The reference matcher: a table over every pair of suffixes, filled from the end.
fn reference_matches(pattern: &[u8], name: &[u8], dot: LeadingDot) -> bool {
    let elements = parse(pattern);
    if dot == LeadingDot::Special
        && name.first() == Some(&b'.')
        && !matches!(elements.first(), Some(Element::Byte(b'.')))
    {
        return false;
    }
    let width = name.len() + 1;
    // `table[j * width + i]`: elements `j..` match name bytes `i..`.
    let mut table = vec![false; (elements.len() + 1) * width];
    table[elements.len() * width + name.len()] = true;
    for j in (0..elements.len()).rev() {
        for i in (0..=name.len()).rev() {
            let here = match &elements[j] {
                Element::Star => {
                    table[(j + 1) * width + i] || (i < name.len() && table[j * width + i + 1])
                }
                Element::Any => i < name.len() && table[(j + 1) * width + i + 1],
                Element::Byte(byte) => {
                    i < name.len() && name[i] == *byte && table[(j + 1) * width + i + 1]
                }
                Element::Class(set) => {
                    i < name.len() && set[usize::from(name[i])] && table[(j + 1) * width + i + 1]
                }
            };
            table[j * width + i] = here;
        }
    }
    table[0]
}

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let cut = usize::from(split).min(rest.len());
    let (pattern, name) = rest.split_at(cut);
    let pattern = &pattern[..pattern.len().min(MAXIMUM_BYTES)];
    let name = &name[..name.len().min(MAXIMUM_BYTES)];

    for dot in [LeadingDot::Special, LeadingDot::Ordinary] {
        let outcome = match_steps(pattern, name, dot);
        assert!(outcome.steps <= step_bound(pattern.len(), name.len()));
        assert_eq!(outcome.matched, matches_with(pattern, name, dot));
        assert_eq!(outcome.matched, reference_matches(pattern, name, dot));
    }
    assert_eq!(
        matches(pattern, name),
        matches_with(pattern, name, LeadingDot::Special)
    );

    let mut buffer = [0u8; MAXIMUM_BYTES];
    let named = literal(pattern, &mut buffer);
    if has_magic(pattern) {
        assert_eq!(named, None);
    } else {
        let named = named.expect("a pattern with no magic has a literal");
        assert!(matches_with(pattern, named, LeadingDot::Ordinary));
        assert_eq!(
            matches_with(pattern, name, LeadingDot::Ordinary),
            name == named
        );
    }
});
