# Changelog

Dates are UTC. One line per release, what changed and why, so a reader of the diff has the
sentence beside it.

## Unreleased

- First version.
- Removed the public function `literal`. Nothing outside the crate's own tests, proofs and fuzz target called it. `has_magic` still tells a caller whether a pattern names exactly one file. An item removed before the first release costs no user, while one removed after it would break users. The proof of that property now reads the name through a private helper that exists only under test and Kani.
- `matches_with` and `match_steps` take a `MatchOptions` value in place of a `LeadingDot`, so a later rule is a new field rather than a new function. `MatchOptions::new()` and `MatchOptions::default()` are what `matches` uses; `with_leading_dot` and `with_case` change one rule.
- Added `Case`, with `Case::AsciiInsensitive` for a case-insensitive match of ASCII letters, as `fnmatch(3)` does with `FNM_CASEFOLD` in the C locale. A reader of a volume that folds case needs it.
- Added `Pattern`, a pattern decoded once for matching many names. It tests the part after the last `*` against the end of the name before any backtracking, and gives the same answers as `matches_with`.
- `LeadingDot` and `Case` are `#[non_exhaustive]`, so a later rule is not a breaking change. `LeadingDot` and `Outcome` derive `Hash`, so a caller can key a map on them.
- The crate page opens with a summary and examples, and the README's examples run as doctests. The manifest names the documentation and the `no-std::no-alloc` and `filesystem` categories.

## BUGS

- The template's lag check guards the CI pin, not this file; a change that matters to a user of
  the crate belongs in a release line here.
