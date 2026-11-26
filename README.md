# byte_glob

[![check](https://github.com/partsfoundry/byte_glob/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/partsfoundry/byte_glob/actions/workflows/ci.yml?query=branch%3Amain)
[![proofs](https://github.com/partsfoundry/byte_glob/actions/workflows/proofs.yml/badge.svg?branch=main)](https://github.com/partsfoundry/byte_glob/actions/workflows/proofs.yml?query=branch%3Amain)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/partsfoundry/byte_glob#license)
[![minimum Rust version](https://img.shields.io/badge/rust-1.88%2B-blue.svg)](https://github.com/partsfoundry/byte_glob/blob/main/Cargo.toml)

An `fnmatch(3)`-style matcher for one file name. A pattern and a name go in, a `bool` comes out. It
is a total function on two byte strings: `no_std`, no allocation, no `unsafe`, no dependency, a cost
bound a caller can compute before matching, and eight Kani proofs of its corners.

Three things a caller does not guess:

- Bytes, not characters. The match is `fnmatch(3)` in the C locale, so `?` matches one byte,
  which is half of a two-byte UTF-8 character.
- One name, not a path. `/` is an ordinary byte, so `matches(b"*.txt", b"dir/notes.txt")` is
  `true`. A caller that matches a path splits it first. Recursive descent (`**`) belongs to the
  layer that walks directories, because descending is an authority, not a match.
- A leading `.` needs a literal `.` by default (`LeadingDot::Special`), the reading that grants less.
  `*` does not match `.config`; `[.]config` does not either, because a bracket expression is a
  wildcard however few members it has. `.` and `..` are ordinary names to the matcher, so `.*`
  matches both. The layer that enumerates a directory decides whether to offer them.

A malformed pattern means itself: an unterminated `[` is a literal `[`, and a trailing `\` is a
literal `\`. There is no error case, because a pattern comes from outside and an error path for
every typo is a cost. There are no `**`, no zsh-style qualifiers (they need type, time and size per
candidate, which is more authority than listing a directory) and no POSIX (Portable Operating System Interface) classes.

## The contract

- `matches(pattern, name)` and `matches_with(pattern, name, options)`: does the pattern match the
  name. `MatchOptions` holds the rules, and `MatchOptions::new()` and `MatchOptions::default()` are
  both what `matches` uses. `with_leading_dot(LeadingDot::Ordinary)` treats a leading `.` as any
  other byte, and `with_case(Case::AsciiInsensitive)` lets an ASCII letter match either case.
- `Pattern::new(pattern)`: a pattern prepared once for many names. `Pattern::matches` and
  `Pattern::matches_with` give the same answers as the functions above. The part after the last
  `*` matches a fixed number of bytes, so a prepared pattern tests it against the end of the name
  before any backtracking.
- `has_magic(pattern)`: is the word a pattern at all. False means the pattern names exactly one
  file.
- `match_steps(pattern, name, options)` and `step_bound(pattern_bytes, name_bytes)`: the cost of a
  match, and the most it can be, computed from the two lengths alone. `match_steps` returns an
  `Outcome` whose `matched` is the answer and whose `steps` is at most `step_bound`; the exact
  count is not promised across versions.

Syntax: `*` any run of bytes, `?` one byte, `[abc]` a set, `[a-z]` a range, `[!abc]` or `[^abc]` the
complement, `\x` the byte `x`, anything else itself.

## EXAMPLES

```rust
use byte_glob::{matches, matches_with, has_magic, Case, LeadingDot, MatchOptions, Pattern};

assert!(matches(b"*.txt", b"notes.txt"));
assert!(!matches(b"*", b".hidden"));
let ordinary = MatchOptions::new().with_leading_dot(LeadingDot::Ordinary);
assert!(matches_with(b"*", b".hidden", ordinary));
assert!(matches(b"*.txt", b"dir/notes.txt")); // one name: `/` is a byte

let folded = MatchOptions::new().with_case(Case::AsciiInsensitive);
assert!(matches_with(b"*.txt", b"NOTES.TXT", folded));

let logs = Pattern::new(b"*.log"); // one pattern, many names
assert!(logs.matches(b"server.log"));
assert!(!logs.matches(b"server.txt"));

assert!(has_magic(b"*.txt"));
assert!(!has_magic(br"a\*b"));
```

## What is proven

Eight Kani harnesses (`src/verification.rs`), each with a falsification patch that turns it red.
They quantify over every byte value of patterns and names up to three bytes (2^48 pairs per
harness) but not over length: four bytes each did not finish. Matching is total under
every rule. The step count never exceeds `step_bound`. A pattern with no magic matches exactly
itself. `*` and `?` have their base meanings. The dot rule touches only names that start with a
dot. A negated class is the exact complement of its class. Under the case fold, the case of the
name's letters changes no answer. A prepared `Pattern` gives the same answer as `matches_with`. The length-independent claims are
host tests: an exhaustive cross-check against a naive matcher over every pattern of up to five
bytes and every name of up to three, and a 100,000-byte adversarial run held under the bound.

## How it avoids blowup

The matcher keeps exactly one backtrack point, the most recent `*`, which is the algorithm
`fnmatch` implementations use to avoid the exponential split a recursive matcher tries. A retry
position advances monotonically, so a match makes at most `name_bytes + 1` backtracks, and between
two of them the name position plus the pattern position strictly increases. The work is polynomial
in the two lengths with no term in the number of `*`s. `has_magic` is not counted by
`match_steps`: it decodes a `[` by scanning to its closing `]`, so `n` unterminated brackets cost
about `n * n / 2` byte reads.

`cargo bench` runs the three shapes that make a backtracking matcher blow up (ten stars and no
match across 4,096 bytes, a star before a 63-byte tail, 256 unterminated brackets) and one
ordinary pattern. For each it prints the time a match takes, its step count beside `step_bound`,
and the time a step takes, so a step that got slower shows where the count cannot. The times
belong to the machine that runs it, so this README states none.

## Corners

Every row is a place a real implementation has been wrong, and a test pins it.

| input | answer | why |
|---|---|---|
| `[foo` | literal `[foo` | no closing `]`, so it was never a bracket expression |
| `[]]` | matches `]` | `]` right after `[` or `[!` is a member |
| `[a-]` | matches `a` and `-` | a `-` with nothing after it is a member, not a range |
| `[-a]` | matches `-` and `a` | the same rule at the other end |
| `[z-a]` | matches nothing | a reversed range is empty, the answer that cannot grant more |
| `[\]]` | matches `]` | POSIX has no escapes in brackets; glibc and bash honor one |
| `a\` | matches `a\` | a trailing backslash has nothing to escape |
| empty pattern | matches only the empty name | |
| `[[:alpha:]]` | matches `a]`, `:]`, ... | no POSIX classes: the class `[[:alpha:]` then a literal `]` |

## Building and testing

```sh
cargo test
cargo build --lib --target x86_64-unknown-none   # also aarch64-unknown-none-softfloat, riscv64imac-unknown-none-elf
cargo kani
cargo +nightly fuzz run byte_glob_matches   # cargo-fuzz; checks against a separately written matcher
```

## BUGS

- The harnesses do not quantify over length.

## Minimum Rust version

Rust 1.88.

## License

Licensed under either of MIT (LICENSE-MIT) or Apache-2.0 (LICENSE-APACHE), at your option.
