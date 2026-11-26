# Changelog

Dates are UTC. One line per release, what changed and why, so a reader of the diff has the
sentence beside it.

## Unreleased

- First version.
- Removed the public function `literal`. Nothing outside the crate's own tests, proofs and fuzz target called it. `has_magic` still tells a caller whether a pattern names exactly one file. An item removed before the first release costs no user, while one removed after it would break users. The proof of that property now reads the name through a private helper that exists only under test and Kani.

## BUGS

- The template's lag check guards the CI pin, not this file; a change that matters to a user of
  the crate belongs in a release line here.
