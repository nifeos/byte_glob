//! The measurements the README's "How it avoids blowup" points to. Run with `cargo bench`; it
//! needs no dependency beyond the standard library.
//!
//! Each workload matches one pattern against one name a fixed number of times, seven times over,
//! and reports the fastest of the seven in nanoseconds per match and per step: the fastest run is
//! the one the rest of the machine disturbed least. `black_box` keeps the compiler from folding
//! the work away. Each line also prints the step count of one match and the `step_bound` for the
//! two lengths, so a regression the step count cannot see (a step that got slower) shows beside
//! one it can.
//!
//! The workloads are the three shapes that make a backtracking matcher blow up, and one ordinary
//! pattern for scale:
//!
//! - `a*a*a*a*a*a*a*a*a*a*b` against 4,096 bytes of `a`: ten stars and no `b`, the split a
//!   recursive matcher tries every way;
//! - `*` then 63 `?` then `b`, against 4,096 bytes of `a`: a star and a long tail that nearly
//!   matches, which is quadratic here and pinned to stay so;
//! - 256 bytes of `[` against 256 bytes of `[`: every unterminated bracket scans to the end;
//! - `*.txt` against `notes.txt`.

use std::hint::black_box;
use std::time::Instant;

use byte_glob::{LeadingDot, match_steps, step_bound};

const RUNS: usize = 7;

/// The fastest of `RUNS` runs of `matches` matches of `pattern` against `name`, in nanoseconds per
/// match.
fn nanoseconds_per_match(matches: u32, pattern: &[u8], name: &[u8]) -> f64 {
    let mut fastest = f64::INFINITY;
    for _ in 0..RUNS {
        let start = Instant::now();
        for _ in 0..matches {
            black_box(match_steps(
                black_box(pattern),
                black_box(name),
                LeadingDot::Special,
            ));
        }
        let elapsed = start.elapsed().as_nanos() as f64 / f64::from(matches);
        fastest = fastest.min(elapsed);
    }
    fastest
}

fn report(workload: &str, matches: u32, pattern: &[u8], name: &[u8]) {
    let nanoseconds = nanoseconds_per_match(matches, pattern, name);
    let steps = match_steps(pattern, name, LeadingDot::Special).steps;
    println!(
        "{workload}: {nanoseconds:.0} nanoseconds a match, {steps} steps of a bound of {}, \
         {:.1} nanoseconds a step",
        step_bound(pattern.len(), name.len()),
        nanoseconds / steps as f64,
    );
}

fn main() {
    let long_name = [b'a'; 4096];

    report(
        "ten stars, no b, 4,096 bytes",
        200,
        b"a*a*a*a*a*a*a*a*a*a*b",
        &long_name,
    );

    let mut tail = [b'?'; 65];
    tail[0] = b'*';
    tail[64] = b'b';
    report("a star and 63 ?, 4,096 bytes", 20, &tail, &long_name);

    let brackets = [b'['; 256];
    report("256 unterminated [", 200, &brackets, &brackets);

    report("*.txt against notes.txt", 1_000_000, b"*.txt", b"notes.txt");
}
