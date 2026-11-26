//! An `fnmatch(3)`-style glob matcher over bytes, for one file name.
//!
//! [`matches()`] answers whether a pattern matches a name. It is a total function on two byte
//! strings: no input or output, no allocation, no `unsafe`, a cost bound a caller can compute
//! before matching, and Kani proofs of the corners.
//!
//! # Examples
//!
//! ```
//! use byte_glob::{matches, matches_with, Case, LeadingDot, MatchOptions, Pattern};
//!
//! assert!(matches(b"*.txt", b"notes.txt"));
//! assert!(!matches(b"*", b".hidden")); // a leading dot needs a literal dot
//! assert!(matches(b"*.txt", b"dir/notes.txt")); // one name: `/` is a byte
//!
//! let listing = MatchOptions::new()
//!     .with_leading_dot(LeadingDot::Ordinary)
//!     .with_case(Case::AsciiInsensitive);
//! assert!(matches_with(b"*.txt", b".NOTES.TXT", listing));
//!
//! // One pattern, many names: prepare it once.
//! let logs = Pattern::new(b"*.log");
//! assert!(logs.matches(b"server.log"));
//! assert!(!logs.matches(b"server.txt"));
//! ```

//! Three things a caller does not guess:
//!
//! - **Bytes, not characters.** The match is `fnmatch(3)` in the C locale, so `?` is one byte.
//! - **One name, not a path.** `/` is an ordinary byte. `matches(b"*.txt", b"dir/notes.txt")` is
//!   `true`: a `*` crosses separators, and a caller that matches a path splits it first.
//! - **A leading `.` needs a literal `.`** by default ([`LeadingDot::Special`]). `.` and `..` are ordinary
//!   names to the matcher, so `.*` matches both; the layer that enumerates a directory decides
//!   whether to offer them.
//!
//! A malformed pattern means itself, and there is no `**`, qualifier or POSIX class.
//! The work of [`match_steps`] is bounded by [`step_bound`]. [`has_magic`]
//! is not counted: it decodes a `[` by scanning to its closing `]` or the end,
//! so a pattern of `n` unterminated brackets costs about `n * n / 2` byte reads, which is
//! small at the lengths of a shell word.
//!
//! # Syntax
//! | syntax | meaning |
//! |---|---|
//! | `*` | any run of bytes, including none |
//! | `?` | exactly one byte |
//! | `[abc]` | one byte from the set |
//! | `[a-z]` | one byte from the inclusive range |
//! | `[!abc]`, `[^abc]` | one byte *not* in the set |
//! | `\x` | the byte `x`, with no special meaning |
//! | anything else | itself |

#![no_std]
#![forbid(unsafe_code)]

/// Whether a leading `.` in the name is special.
///
/// This is `fnmatch(3)`'s `FNM_PERIOD` as a named type rather than a flag bit, so the compiler can
/// say which rule a call site chose.
///
/// `#[non_exhaustive]`: there are two rules today, and a later version may add a third, such as
/// a dot that is special only after a `/` for a caller matching paths. A `match` on it outside
/// this crate carries a wildcard arm.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum LeadingDot {
    /// A name starting with `.` matches only a pattern starting with a **literal** `.` (which `\.`
    /// counts as, and `[.]` does not). What [`matches()`] uses, and what a shell user expects: `*`
    /// does not list `.config`.
    Special,
    /// A leading `.` is an ordinary byte. `*` matches `.config`. For callers matching against
    /// something that is not a user-facing filename listing.
    Ordinary,
}

/// Whether a letter in the pattern matches the other case of itself in the name.
///
/// `#[non_exhaustive]`, so a later version can add a rule without breaking a `match` on it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Case {
    /// A byte matches only itself: `*.txt` does not match `NOTES.TXT`. What [`matches()`] uses,
    /// and what `fnmatch(3)` does without `FNM_CASEFOLD`.
    Sensitive,
    /// An ASCII letter in the name matches either case of itself in the pattern, in a literal and
    /// in a bracket expression: `*.txt` matches `NOTES.TXT`, and `[a-c]` matches `B`. A bracket
    /// expression asks whether the name's byte or its other case is a member, and a negated one
    /// complements that answer, so `[!a]` matches neither `a` nor `A`. Every other byte, each byte
    /// of a multibyte UTF-8 character included, matches only itself. `fnmatch(3)`'s
    /// `FNM_CASEFOLD` in the C locale, for a caller such as a reader of a volume that folds case.
    AsciiInsensitive,
}

/// How a match reads the pattern and the name: the third argument of [`matches_with`] and
/// [`match_steps`].
///
/// [`MatchOptions::new`] and [`Default`] are both exactly what [`matches()`] uses, and the
/// `with_` methods change one rule at a time:
///
/// ```
/// use byte_glob::{matches_with, LeadingDot, MatchOptions};
///
/// let listing = MatchOptions::new().with_leading_dot(LeadingDot::Ordinary);
/// assert!(matches_with(b"*", b".config", listing));
/// assert!(!matches_with(b"*", b".config", MatchOptions::default()));
/// ```
///
/// `#[non_exhaustive]`, so a later version can add a rule without a new function or a breaking
/// change. Its fields are public to read and to assign; a value is built with
/// [`MatchOptions::new`] rather than a struct expression.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub struct MatchOptions {
    /// Whether a leading `.` in the name needs a literal `.` in the pattern.
    /// [`LeadingDot::Special`] unless changed.
    pub leading_dot: LeadingDot,
    /// Whether an ASCII letter matches its other case. [`Case::Sensitive`] unless changed.
    pub case: Case,
}

impl MatchOptions {
    /// The rules [`matches()`] uses: a leading `.` is special, and case is significant.
    pub const fn new() -> Self {
        MatchOptions {
            leading_dot: LeadingDot::Special,
            case: Case::Sensitive,
        }
    }

    /// These options with the leading-dot rule replaced.
    #[must_use]
    pub const fn with_leading_dot(mut self, leading_dot: LeadingDot) -> Self {
        self.leading_dot = leading_dot;
        self
    }

    /// These options with the case rule replaced.
    ///
    /// ```
    /// use byte_glob::{matches, matches_with, Case, MatchOptions};
    ///
    /// let folded = MatchOptions::new().with_case(Case::AsciiInsensitive);
    /// assert!(!matches(b"*.txt", b"NOTES.TXT"));
    /// assert!(matches_with(b"*.txt", b"NOTES.TXT", folded));
    /// ```
    #[must_use]
    pub const fn with_case(mut self, case: Case) -> Self {
        self.case = case;
        self
    }
}

/// The same value as [`MatchOptions::new`], which is what [`matches()`] uses.
impl Default for MatchOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// **Does `pattern` match `name`?** A leading `.` in the name is special; see [`LeadingDot`].
///
/// `name` is one name, not a path: `/` is an ordinary byte, so `*` matches across it.
///
/// Total: every pair of byte strings has an answer, and no pattern makes this panic or hang.
///
/// # Examples
///
/// ```
/// use byte_glob::{matches, matches_with, has_magic, LeadingDot, MatchOptions};
///
/// assert!(matches(b"*.txt", b"notes.txt"));
/// assert!(!matches(b"*.txt", b"notes.md"));
///
/// // One byte, not one character, and not a leading dot.
/// assert!(matches(b"?ar", b"bar"));
/// assert!(!matches(b"*", b".hidden"));
///
/// // One name, not a path: `/` is an ordinary byte.
/// assert!(matches(b"*.txt", b"dir/notes.txt"));
/// let ordinary = MatchOptions::new().with_leading_dot(LeadingDot::Ordinary);
/// assert!(matches_with(b"*", b".hidden", ordinary));
///
/// // Classes, ranges, negation.
/// assert!(matches(b"[abc]at", b"cat"));
/// assert!(matches(b"log[0-9].txt", b"log7.txt"));
/// assert!(matches(b"[!a]at", b"cat"));
/// assert!(!matches(b"[!c]at", b"cat"));
///
/// // A malformed pattern is a literal, not an error.
/// assert!(matches(b"[foo", b"[foo"));
///
/// // The shell asks of a word: is it a pattern at all?
/// assert!(has_magic(b"*.txt"));
/// assert!(!has_magic(br"a\*b"));
/// ```
pub fn matches(pattern: &[u8], name: &[u8]) -> bool {
    match_steps(pattern, name, MatchOptions::new()).matched
}

/// [`matches()`], with the rules under the caller's control; see [`MatchOptions`].
///
/// # Examples
///
/// ```
/// use byte_glob::{matches, matches_with, LeadingDot, MatchOptions};
///
/// let ordinary = MatchOptions::new().with_leading_dot(LeadingDot::Ordinary);
/// assert!(!matches(b"*", b".config")); // `*` does not list dotfiles
/// assert!(matches(b".*", b".config")); // an explicit dot does
/// assert!(matches_with(b"*", b".config", ordinary)); // ... unless you ask otherwise
/// ```
pub fn matches_with(pattern: &[u8], name: &[u8], options: MatchOptions) -> bool {
    match_steps(pattern, name, options).matched
}

/// **Could this pattern match anything other than one fixed name?**
///
/// True when the pattern contains an unescaped `*` or `?`, or a bracket expression that is actually
/// closed. False means the pattern is a literal: it names exactly one file, with its escapes stripped.
///
/// Precise rather than eager, so an unterminated `[` is a literal byte: a false "yes" costs the
/// shell a directory enumeration for a word that names one file.
///
/// # Examples
///
/// ```
/// use byte_glob::has_magic;
///
/// assert!(has_magic(b"*.txt"));
/// assert!(has_magic(b"log[0-9]"));
/// assert!(!has_magic(b"notes.txt"));
/// assert!(!has_magic(br"a\*b")); // an escaped `*` is a literal
/// assert!(!has_magic(b"[foo")); // never closed, so a literal `[`
/// ```
pub fn has_magic(pattern: &[u8]) -> bool {
    let mut j = 0;
    while let Some((elem, _)) = decode(pattern, j, 0, Case::Sensitive) {
        match elem {
            Element::Byte { next, .. } => j = next,
            _ => return true,
        }
    }
    false
}

/// The one name a magic-free pattern names, with its escapes stripped, written into `out`.
///
/// `None` when the pattern has magic or the name does not fit. The tests and proofs use it to state
/// that a pattern with no magic matches exactly this name; the crate itself has no caller.
#[cfg(any(test, kani))]
fn literal<'a>(pattern: &[u8], out: &'a mut [u8]) -> Option<&'a [u8]> {
    let mut j = 0;
    let mut n = 0;
    while let Some((elem, _)) = decode(pattern, j, 0, Case::Sensitive) {
        match elem {
            Element::Byte { byte, next } => {
                *out.get_mut(n)? = byte;
                n += 1;
                j = next;
            }
            _ => return None,
        }
    }
    Some(&out[..n])
}

/// What [`match_steps`] found: the answer, and what it cost.
///
/// `#[non_exhaustive]`, so a later version can report more about a match without breaking a
/// caller that reads these two fields.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub struct Outcome {
    /// Whether the pattern matched the name: what [`matches_with`] returns for the same arguments.
    pub matched: bool,
    /// The steps the match took. A step is one byte of pattern examined, including the bytes a
    /// bracket expression is scanned over and the ones re-examined after a backtrack; it is not a
    /// wall-clock measure. The one promise about it is that it is at most [`step_bound`] of the
    /// two lengths. Its exact value is not promised across versions.
    pub steps: usize,
}

/// [`matches_with`], plus the number of steps it took: the cost of the match, made observable.
///
/// It exists so the claim "this cannot blow up" is an inequality something checks rather than a
/// paragraph: [`Outcome::steps`] is at most [`step_bound`] of the two lengths.
///
/// # Examples
///
/// ```
/// use byte_glob::{match_steps, step_bound, MatchOptions};
///
/// let outcome = match_steps(b"a*a*b", b"aaaa", MatchOptions::new());
/// assert!(!outcome.matched);
/// assert!(outcome.steps <= step_bound(5, 4));
/// ```
pub fn match_steps(pattern: &[u8], name: &[u8], options: MatchOptions) -> Outcome {
    // One copy of the loop per case rule, so the common case-sensitive match pays nothing for the
    // fold: with the rule a constant, the compiler drops the test of it from every step.
    match options.case {
        Case::Sensitive => match_steps_under(pattern, name, options.leading_dot, Case::Sensitive),
        Case::AsciiInsensitive => {
            match_steps_under(pattern, name, options.leading_dot, Case::AsciiInsensitive)
        }
    }
}

/// [`match_steps`] under one case rule, inlined into each arm of its `match` on the rule.
#[inline(always)]
fn match_steps_under(pattern: &[u8], name: &[u8], leading_dot: LeadingDot, case: Case) -> Outcome {
    let mut steps = 0usize;

    // The leading-dot rule, applied once and up front. It is a property of the two strings' first
    // bytes, so putting it in the loop would only mean asking it repeatedly.
    if leading_dot == LeadingDot::Special
        && name.first() == Some(&b'.')
        && !opens_with_a_literal_dot(pattern)
    {
        return Outcome {
            matched: false,
            steps,
        };
    }

    let n = name.len();
    let mut i = 0usize; // next byte of `name` to account for
    let mut j = 0usize; // next element of `pattern` to apply

    // The single backtrack point: where to resume in the pattern after the most recent `*`, and how
    // much of the name that `*` is currently absorbing. `None` until a `*` is seen, and a later `*`
    // simply replaces it. This is the whole anti-blowup argument (the README, "How it avoids blowup").
    let mut star_next: Option<usize> = None;
    let mut star_absorbed = 0usize;

    loop {
        if i >= n {
            // The name is spent. Nothing can be gained by backtracking, since that only makes the
            // `*` absorb more of a name that has no more bytes, so the answer is fixed: whatever is
            // left of the pattern has to be able to match emptiness, and only `*` can.
            while pattern.get(j) == Some(&b'*') {
                j += 1;
                steps += 1;
            }
            return Outcome {
                matched: j == pattern.len(),
                steps,
            };
        }

        let advanced = match decode(pattern, j, name[i], case) {
            // Pattern exhausted with name left over. Not a match here; the backtrack below decides
            // whether an earlier `*` can swallow the remainder.
            None => false,
            Some((elem, scanned)) => {
                steps += scanned;
                match elem {
                    Element::Star => {
                        star_next = Some(j + 1);
                        star_absorbed = i;
                        j += 1;
                        true
                    }
                    Element::Any { next } => {
                        i += 1;
                        j = next;
                        true
                    }
                    Element::Byte { byte, next } => {
                        if literal_matches(byte, name[i], case) {
                            i += 1;
                            j = next;
                            true
                        } else {
                            false
                        }
                    }
                    Element::Class { hit, next } => {
                        if hit {
                            i += 1;
                            j = next;
                            true
                        } else {
                            false
                        }
                    }
                }
            }
        };

        if advanced {
            continue;
        }

        match star_next {
            // Retry with the last `*` absorbing one more byte. `star_absorbed` only ever grows, and
            // it is bounded by the name's length, which is what makes the total work polynomial.
            Some(resume) => {
                star_absorbed += 1;
                i = star_absorbed;
                j = resume;
                steps += 1;
            }
            None => {
                return Outcome {
                    matched: false,
                    steps,
                };
            }
        }
    }
}

/// **A pattern prepared once, for matching against many names.**
///
/// [`Pattern::matches_with`] gives the same answer as [`matches_with`] for every name and every
/// [`MatchOptions`], and a Kani proof checks that they agree. What preparing buys: the part of the
/// pattern after its last `*` matches a fixed number of bytes, so a prepared pattern tests that
/// part against the end of the name first, and runs the backtracking match only on the part
/// before it. A name whose ending does not fit is refused without a backtrack, and a long run of
/// `?` after a `*` costs one pass rather than one pass per byte the `*` could absorb.
///
/// It borrows the pattern and allocates nothing. [`Pattern::new`] reads the pattern once, at the
/// cost of [`has_magic`]; for a pattern used once, [`matches()`] is as fast.
///
/// ```
/// use byte_glob::Pattern;
///
/// let logs = Pattern::new(b"*.log");
/// let names: [&[u8]; 3] = [b"server.log", b"notes.txt", b".hidden.log"];
/// let matched: Vec<_> = names.iter().filter(|name| logs.matches(name)).collect();
/// assert_eq!(matched, [&b"server.log"]);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Pattern<'a> {
    /// The pattern as given.
    bytes: &'a [u8],
    /// Where the part after the last `*` starts, and how many name bytes it matches; `None` when
    /// the pattern has no `*`.
    tail: Option<(usize, usize)>,
    /// Whether the pattern opens with a literal `.`, for the leading-dot rule.
    opens_with_a_literal_dot: bool,
}

impl<'a> Pattern<'a> {
    /// Prepare `pattern`. Every byte string is a pattern, as it is for [`matches()`].
    pub fn new(pattern: &'a [u8]) -> Self {
        let mut tail = None;
        let mut j = 0;
        while let Some((elem, _)) = decode(pattern, j, 0, Case::Sensitive) {
            j = match elem {
                Element::Star => {
                    tail = Some((j + 1, 0));
                    j + 1
                }
                Element::Any { next }
                | Element::Byte { next, .. }
                | Element::Class { next, .. } => {
                    if let Some((_, width)) = &mut tail {
                        *width += 1;
                    }
                    next
                }
            };
        }
        Pattern {
            bytes: pattern,
            tail,
            opens_with_a_literal_dot: opens_with_a_literal_dot(pattern),
        }
    }

    /// **Does this pattern match `name`?** The same answer as [`matches()`].
    pub fn matches(&self, name: &[u8]) -> bool {
        self.matches_with(name, MatchOptions::new())
    }

    /// This pattern against `name` under `options`: the same answer as [`matches_with`].
    pub fn matches_with(&self, name: &[u8], options: MatchOptions) -> bool {
        if options.leading_dot == LeadingDot::Special
            && name.first() == Some(&b'.')
            && !self.opens_with_a_literal_dot
        {
            return false;
        }
        // The leading-dot rule is settled, so what follows matches with the dot ordinary.
        let options = options.with_leading_dot(LeadingDot::Ordinary);
        let Some((tail_start, tail_width)) = self.tail else {
            return match_steps(self.bytes, name, options).matched;
        };
        let Some(head_width) = name.len().checked_sub(tail_width) else {
            return false;
        };
        let (head_name, tail_name) = name.split_at(head_width);

        // After the last `*` every element matches exactly one byte, so the tail lines up with
        // the end of the name and needs no search.
        let mut j = tail_start;
        for &c in tail_name {
            j = match decode(self.bytes, j, c, options.case) {
                Some((Element::Any { next }, _)) => next,
                Some((Element::Byte { byte, next }, _))
                    if literal_matches(byte, c, options.case) =>
                {
                    next
                }
                Some((Element::Class { hit: true, next }, _)) => next,
                _ => return false,
            };
        }
        // The head ends in that `*`, which absorbs whatever the rest of the head leaves over.
        match_steps(&self.bytes[..tail_start], head_name, options).matched
    }
}

/// **The most steps a match of these two lengths can cost**, computable before matching starts.
///
/// At most `name_bytes + 1` backtracks, between two of them `i + j` strictly increases up to
/// `name_bytes + pattern_bytes`, and each iteration is at most one pass over the pattern to decode and
/// one to test a bracket expression. Saturating, so absurd lengths give `usize::MAX` rather than a
/// wrapped bound. Loose on purpose: the point is polynomial in both lengths with no term in the
/// number of `*`s. The README, "How it avoids blowup", gives the argument.
///
/// # Examples
///
/// A caller that takes patterns from outside can refuse a pair whose worst case is past a budget,
/// before matching:
///
/// ```
/// use byte_glob::{match_steps, step_bound, MatchOptions};
///
/// const BUDGET: usize = 1_000_000;
/// let (pattern, name) = (&b"*a*a*a*b"[..], &b"aaaaaaaaaaaaaaaa"[..]);
/// let bound = step_bound(pattern.len(), name.len());
/// assert!(bound <= BUDGET);
/// assert!(match_steps(pattern, name, MatchOptions::new()).steps <= bound);
///
/// // Saturating: absurd lengths give the largest bound, not a wrapped one.
/// assert_eq!(step_bound(usize::MAX, usize::MAX), usize::MAX);
/// ```
pub const fn step_bound(pattern_bytes: usize, name_bytes: usize) -> usize {
    let iterations = name_bytes
        .saturating_add(2)
        .saturating_mul(name_bytes.saturating_add(pattern_bytes).saturating_add(1));
    iterations
        .saturating_mul(pattern_bytes.saturating_mul(2).saturating_add(2))
        .saturating_add(pattern_bytes)
        .saturating_add(2)
}

// ---- the pattern's elements ------------------------------------------------------------------

/// One element of a pattern, **resolved against the name byte it is being applied to**.
///
/// [`Element::Class`] carries a `hit` rather than its body's bounds because a bracket expression is
/// scanned once, deciding membership as it goes: two loops nested in the match loop were past what
/// Kani could unroll.
///
/// Callers with no name byte in hand ([`has_magic`], [`literal`], [`opens_with_a_literal_dot`]) pass
/// any byte and any case rule, and read only the variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Element {
    /// `*`
    Star,
    /// `?`, and where the pattern continues after it.
    Any { next: usize },
    /// A literal byte, which may have arrived as `\x`, as an unterminated `[`, or as itself.
    Byte { byte: u8, next: usize },
    /// A closed `[...]`, and whether the byte it was asked about is in it (negation applied).
    Class { hit: bool, next: usize },
}

/// Decode the element at `j` as applied to the name byte `c` under the case rule `case`, and say
/// how many pattern bytes that cost.
///
/// `None` at the end of the pattern. Every other input decodes to something: this is where "there
/// is no malformed pattern" is implemented, by turning an unclosed `[` and a trailing `\` into the
/// bytes they are.
#[inline(always)]
fn decode(pattern: &[u8], j: usize, c: u8, case: Case) -> Option<(Element, usize)> {
    let byte = *pattern.get(j)?;
    let elem = match byte {
        b'*' => (Element::Star, 1),
        b'?' => (Element::Any { next: j + 1 }, 1),
        b'\\' => match pattern.get(j + 1) {
            Some(&escaped) => (
                Element::Byte {
                    byte: escaped,
                    next: j + 2,
                },
                2,
            ),
            // Nothing to escape. bash and fnmatch(3) both read this as the backslash itself.
            None => (
                Element::Byte {
                    byte: b'\\',
                    next: j + 1,
                },
                1,
            ),
        },
        b'[' => {
            let (closed, scanned) = class_at(pattern, j, c);
            match closed {
                Some((hit, next)) => match case {
                    Case::Sensitive => (Element::Class { hit, next }, scanned),
                    Case::AsciiInsensitive => {
                        let (hit, folding) = folded_class(pattern, j, c, hit);
                        (Element::Class { hit, next }, scanned + folding)
                    }
                },
                // No closing bracket anywhere, so it was never a bracket expression. The scan that
                // established that is charged for; it is the one place a step costs more than O(1).
                None => (
                    Element::Byte {
                        byte: b'[',
                        next: j + 1,
                    },
                    scanned,
                ),
            }
        }
        _ => (Element::Byte { byte, next: j + 1 }, 1),
    };
    Some(elem)
}

/// Walk the bracket expression opened at `open`, deciding in one pass both where it ends and whether
/// `c` is a member of it.
///
/// Returns `(Some((hit, next)), scanned)` for a closed expression, with negation already applied, or
/// `(None, scanned)` when there is no closing `]`, in which case the caller treats the `[` as a
/// literal byte. `scanned` is charged either way. A `!` or `^` right after `[` negates; a `]` right
/// after that is a member; a `-` is a range only before a byte that is not the terminator, so
/// `[a-]` and `[-a]` both mean "a hyphen or an a".
fn class_at(pattern: &[u8], open: usize, c: u8) -> (Option<(bool, usize)>, usize) {
    let mut k = open + 1;
    let negated = matches!(pattern.get(k), Some(b'!') | Some(b'^'));
    let mut scanned = 1usize;
    if negated {
        k += 1;
        scanned += 1;
    }

    let mut hit = false;
    let mut at_start = true;

    loop {
        let Some(&byte) = pattern.get(k) else {
            return (None, scanned);
        };
        scanned += 1;
        if byte == b']' && !at_start {
            return (Some((hit ^ negated, k + 1)), scanned);
        }
        at_start = false;

        // An escape inside a class, which is how `[\]]` names a `]`. Strict POSIX bracket
        // expressions have no escapes; glibc's fnmatch and bash both honor one, and matching them
        // is worth more than matching the standard nobody implements.
        let (lo, after_lo) = if byte == b'\\' && k + 1 < pattern.len() {
            scanned += 1;
            (pattern[k + 1], k + 2)
        } else {
            (byte, k + 1)
        };

        let ranged = pattern.get(after_lo) == Some(&b'-')
            && matches!(pattern.get(after_lo + 1), Some(&b) if b != b']');
        if ranged {
            let start = after_lo + 1;
            let (hi, after_hi) = if pattern[start] == b'\\' && start + 1 < pattern.len() {
                (pattern[start + 1], start + 2)
            } else {
                (pattern[start], start + 1)
            };
            scanned += after_hi - after_lo;
            // A reversed range (`[z-a]`) is empty. POSIX calls it undefined; glibc makes it match
            // nothing, which is the answer that cannot surprise anyone into a larger grant.
            if lo <= c && c <= hi {
                hit = true;
            }
            k = after_hi;
        } else {
            if lo == c {
                hit = true;
            }
            k = after_lo;
        }
    }
}

/// Under the case fold, whether the bracket expression opened at `open` matches `c`, given that
/// it answered `hit` for `c` itself, and what the second pass cost.
///
/// The name's byte is a member when either case of it is. `class_at` applies the negation, so a
/// plain class asks whether either case hit, and a negated one whether neither was a member,
/// which is both cases hitting the complement. A byte that is not an ASCII letter has no other
/// case and costs no second pass.
fn folded_class(pattern: &[u8], open: usize, c: u8, hit: bool) -> (bool, usize) {
    let other = other_case(c);
    if other == c {
        return (hit, 0);
    }
    let (closed, scanned) = class_at(pattern, open, other);
    let other_hit = closed.is_some_and(|(other_hit, _)| other_hit);
    let negated = matches!(pattern.get(open + 1), Some(b'!') | Some(b'^'));
    let folded = if negated {
        hit && other_hit
    } else {
        hit || other_hit
    };
    (folded, scanned)
}

/// Does a literal byte of the pattern match this byte of the name, under this case rule?
#[inline(always)]
fn literal_matches(literal: u8, c: u8, case: Case) -> bool {
    match case {
        Case::Sensitive => literal == c,
        Case::AsciiInsensitive => literal.eq_ignore_ascii_case(&c),
    }
}

/// The other case of an ASCII letter, and any other byte unchanged.
const fn other_case(c: u8) -> u8 {
    if c.is_ascii_lowercase() {
        c.to_ascii_uppercase()
    } else {
        c.to_ascii_lowercase()
    }
}

/// Does the pattern begin with a literal `.`?
///
/// `.` and `\.` do; `[.]`, `*` and `?` do not. That is glibc's `FNM_PERIOD` rule, and the reason a
/// bracket expression does not count is that the rule exists to stop a *wildcard* reaching a
/// dotfile, and a class is a wildcard however few members it has.
fn opens_with_a_literal_dot(pattern: &[u8]) -> bool {
    matches!(
        decode(pattern, 0, 0, Case::Sensitive),
        Some((Element::Byte { byte: b'.', .. }, _))
    )
}

/// The README's examples, run as doctests so they cannot drift from the code.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod verification;
