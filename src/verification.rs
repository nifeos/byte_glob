//! The proofs, and the bounds they run under.
//!
//! The harnesses quantify over every byte value of patterns and names up to three bytes (2^48
//! pairs, every arm of the decoder) but not over length. The length-independent claims are the
//! host tests': the exhaustive cross-check and the 100,000-byte blowup tests. The README's
//! "What is proven" says the same.

use super::*;

/// **Three, measured rather than chosen**: four bytes each passed 3 gigabytes and ten minutes. Three
/// reaches `[a]`, `\*a`, a trailing backslash, an unterminated bracket and two stars; `[!a]`
/// and `[a-b]` are reached by `a_negated_class_is_the_exact_complement_of_the_class`.
const P: usize = 3;
const N: usize = 3;

/// Either leading-dot rule and either case rule, chosen symbolically.
fn any_options() -> MatchOptions {
    let dot = if kani::any() {
        LeadingDot::Special
    } else {
        LeadingDot::Ordinary
    };
    let case = if kani::any() {
        Case::Sensitive
    } else {
        Case::AsciiInsensitive
    };
    MatchOptions::new().with_leading_dot(dot).with_case(case)
}

/// The rules with a leading `.` as an ordinary byte, so a harness is about the matcher alone.
const ORDINARY: MatchOptions = MatchOptions::new().with_leading_dot(LeadingDot::Ordinary);

/// Two symbolic lengths, within the bound above, so the empty pattern, the empty name and a
/// pattern that ends mid-class are all reached. Symbolic length is the costliest thing here.
fn any_lengths() -> (usize, usize) {
    let plen: usize = kani::any();
    let nlen: usize = kani::any();
    kani::assume(plen <= P);
    kani::assume(nlen <= N);
    (plen, nlen)
}

/// Falsification: replayable `falsifications/verification.matching_is_total.patch`
/// **Matching is total.**
///
/// For every pattern and name of up to three arbitrary bytes, under every [`MatchOptions`]: no
/// panic, overflow or out-of-bounds index, and the loop terminates within the unwinding bound,
/// which is the property that matters for an untrusted pattern.
#[kani::proof]
#[kani::unwind(11)]
fn matching_is_total() {
    let pattern: [u8; P] = kani::any();
    let name: [u8; N] = kani::any();
    let (plen, nlen) = any_lengths();
    let _ = match_steps(&pattern[..plen], &name[..nlen], any_options());
}

/// Falsification: replayable `falsifications/verification.the_cost_never_exceeds_the_bound.patch`
/// **The cost of a match never exceeds the bound computed from the two lengths alone**, over
/// every pattern and name of up to three arbitrary bytes.
///
/// This proves the accounting, not the absence of blowup: `step_bound(3, 3)` is 285, which no
/// matcher exceeds on three bytes, but an off-by-one in the charging shows here. Separate from
/// totality because `step_bound`'s multiplies on top of the match loop exhausted the solver.
#[kani::proof]
#[kani::unwind(11)]
fn the_cost_never_exceeds_the_bound() {
    let pattern: [u8; P] = kani::any();
    let name: [u8; N] = kani::any();
    let (plen, nlen) = any_lengths();

    let steps = match_steps(&pattern[..plen], &name[..nlen], any_options()).steps;
    assert!(steps <= step_bound(plen, nlen));
}

/// Falsification: replayable `falsifications/verification.no_magic_means_the_pattern_is_its_own_only_match.patch`
/// **A pattern with no magic in it matches exactly one name: itself, unescaped**, over every
/// pattern of up to three arbitrary bytes, escape corners and unterminated brackets included.
/// The shell's grant planner rests on it: if [`has_magic`] says no, it asks for one name.
/// Stated with [`LeadingDot::Ordinary`], as the next two harnesses are; the leading-dot policy has
/// its own harness, and a symbolic choice here doubled the solver's time.
#[kani::proof]
#[kani::unwind(11)]
fn no_magic_means_the_pattern_is_its_own_only_match() {
    let pattern: [u8; P] = kani::any();
    let name: [u8; N] = kani::any();
    let (plen, nlen) = any_lengths();
    let p = &pattern[..plen];
    let n = &name[..nlen];

    // An assumption rather than an early `return`, to state the restriction; it is no faster.
    kani::assume(!has_magic(p));
    let mut buf = [0u8; P];
    let lit = literal(p, &mut buf).expect("a magic-free pattern always has a literal");
    assert_eq!(matches_with(p, n, ORDINARY), n == lit);
}

/// Falsification: replayable `falsifications/verification.star_matches_anything_and_question_matches_one_byte.patch`
/// **`*` matches every name, and `?` matches exactly the one-byte names.**
///
/// The two base cases, over every name of up to three arbitrary bytes. Stated with
/// [`LeadingDot::Ordinary`] so they are claims about the matcher; the leading-dot policy is the next
/// harness, separately, because it is a separate thing.
#[kani::proof]
#[kani::unwind(12)]
fn star_matches_anything_and_question_matches_one_byte() {
    let name: [u8; N] = kani::any();
    let nlen: usize = kani::any();
    kani::assume(nlen <= N);
    let n = &name[..nlen];

    assert!(matches_with(b"*", n, ORDINARY));
    assert!(matches_with(b"**", n, ORDINARY));
    assert_eq!(matches_with(b"?", n, ORDINARY), nlen == 1);
    assert_eq!(matches_with(b"??", n, ORDINARY), nlen == 2);
    // `*` around anything still matches everything that thing matches.
    assert_eq!(matches_with(b"*?*", n, ORDINARY), nlen >= 1);
}

/// Falsification: replayable `falsifications/verification.the_dot_rule_only_touches_names_that_start_with_a_dot.patch`
/// **The leading-dot rule is exactly "a wildcard cannot reach a dotfile".**
///
/// Under [`LeadingDot::Special`] a name beginning with `.` matches only a pattern beginning with a
/// literal `.`, and any other name matches identically under both settings. The name is bounded
/// at two bytes, enough for a predicate on its first byte; the pattern keeps three so `.*`,
/// `\.x` and `[.]` are reachable.
#[kani::proof]
#[kani::unwind(9)]
fn the_dot_rule_only_touches_names_that_start_with_a_dot() {
    const DOT_N: usize = 2;
    let pattern: [u8; P] = kani::any();
    let name: [u8; DOT_N] = kani::any();
    let plen: usize = kani::any();
    let nlen: usize = kani::any();
    kani::assume(plen <= P);
    kani::assume(nlen <= DOT_N);
    let p = &pattern[..plen];
    let n = &name[..nlen];

    let special = matches_with(p, n, MatchOptions::new());
    let ordinary = matches_with(p, n, ORDINARY);

    if n.first() == Some(&b'.') {
        // Special is never more permissive, and is permissive only for a pattern that says `.`.
        assert!(!special || ordinary);
        assert!(!special || opens_with_a_literal_dot(p));
    } else {
        assert_eq!(special, ordinary);
    }
}

/// Falsification: replayable `falsifications/verification.a_negated_class_is_the_exact_complement_of_the_class.patch`
/// **`[xy]` and `[!xy]` partition the byte space**, over every two-byte class body and every
/// byte, the range spelling `[a-b]` included; this also reaches the four- and five-byte forms.
///
/// The body excludes `!` and `^` at its head (`[!!y]` is the complement of `[!y]`, as Kani's
/// counterexample showed), and `]` and `\`, which make the two spellings different patterns.
#[kani::proof]
#[kani::unwind(10)]
fn a_negated_class_is_the_exact_complement_of_the_class() {
    let body: [u8; 2] = kani::any();
    let c: u8 = kani::any();

    kani::assume(body[0] != b']' && body[1] != b']');
    kani::assume(body[0] != b'\\' && body[1] != b'\\');
    kani::assume(body[0] != b'!' && body[0] != b'^');

    let plain = [b'[', body[0], body[1], b']'];
    let negated = [b'[', b'!', body[0], body[1], b']'];
    let name = [c];

    assert_eq!(
        matches_with(&plain, &name, ORDINARY),
        !matches_with(&negated, &name, ORDINARY)
    );
    // Not vacuous: the range spelling is inside the quantifier, so this is a claim about `[a-b]`
    // as well as about `[ab]`.
    kani::cover!(body[1] == b'-');
    kani::cover!(matches_with(&plain, &name, ORDINARY));
}

/// Falsification: replayable `falsifications/verification.the_case_fold_ignores_the_case_of_the_name.patch`
/// **Under the case fold, the case of the name's letters changes no answer**, over every pattern
/// and name of up to three arbitrary bytes: a name and the same name with every ASCII letter
/// lowercased match the same patterns, in literals, sets, ranges and negations alike.
#[kani::proof]
#[kani::unwind(11)]
fn the_case_fold_ignores_the_case_of_the_name() {
    let pattern: [u8; P] = kani::any();
    let name: [u8; N] = kani::any();
    let (plen, nlen) = any_lengths();
    let p = &pattern[..plen];
    let n = &name[..nlen];
    let mut lower = name;
    lower.make_ascii_lowercase();
    let folded = ORDINARY.with_case(Case::AsciiInsensitive);

    assert_eq!(
        matches_with(p, n, folded),
        matches_with(p, &lower[..nlen], folded)
    );
    // Not vacuous: an uppercase letter in the name reaches a pattern that matches it.
    kani::cover!(n.first().is_some_and(u8::is_ascii_uppercase) && matches_with(p, n, folded));
}

/// Falsification: replayable `falsifications/verification.a_prepared_pattern_agrees_with_the_plain_match.patch`
/// **A prepared pattern gives the plain match's answer**, over every pattern and name of up to
/// three arbitrary bytes and every [`MatchOptions`]: the tail after the last `*` lined up with the
/// end of the name, then the head, decide exactly what the one-backtrack match decides.
#[kani::proof]
#[kani::unwind(11)]
fn a_prepared_pattern_agrees_with_the_plain_match() {
    let pattern: [u8; P] = kani::any();
    let name: [u8; N] = kani::any();
    let (plen, nlen) = any_lengths();
    let p = &pattern[..plen];
    let n = &name[..nlen];
    let options = any_options();

    assert_eq!(
        Pattern::new(p).matches_with(n, options),
        matches_with(p, n, options)
    );
}
