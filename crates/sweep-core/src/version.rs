//! Version ordering, the way `pacman` defines it.
//!
//! A package cache holds several generations of the same package, and
//! `foo-1.10-1` is newer than `foo-1.9-1` even though it sorts first as text.
//! Deciding which archive to keep therefore needs `vercmp`, not string order.
//!
//! This is a port of `libalpm`'s comparison (`lib/libalpm/version.c`, pacman
//! 7.1), kept close to the original on purpose: the rules are surprising enough
//! — separators count, digits beat letters, a trailing letter run never beats an
//! empty string — that "a reasonable implementation" and the real one disagree
//! on real version strings. The differential test at the bottom checks this
//! against the `vercmp` binary whenever it is installed, so a port that drifts
//! is a failing test rather than a silently wrong deletion.
//!
//! Comparison works on bytes: a version reaches this module from a file name,
//! and a file name is not required to be UTF-8.

use std::cmp::Ordering;

/// Compares two `[epoch:]version[-release]` strings.
///
/// Returns the ordering of `a` relative to `b`, matching `vercmp a b` and
/// `alpm_pkg_vercmp`: negative/`Less` means `a` is older.
pub fn vercmp(a: &[u8], b: &[u8]) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }

    let (epoch_a, version_a, release_a) = parse_evr(a);
    let (epoch_b, version_b, release_b) = parse_evr(b);

    // A missing epoch is epoch 0, so `1.0` and `0:1.0` are the same version.
    // `parse_evr` yields an empty slice for "absent" and compares as "0".
    let epoch = segment(epoch_or_zero(epoch_a), epoch_or_zero(epoch_b));
    if epoch != Ordering::Equal {
        return epoch;
    }

    let version = segment(version_a, version_b);
    if version != Ordering::Equal {
        return version;
    }

    // `1.0` and `1.0-1` are equal: a release that neither side states cannot
    // make one of them older.
    match (release_a, release_b) {
        (Some(left), Some(right)) => segment(left, right),
        _ => Ordering::Equal,
    }
}

fn epoch_or_zero(epoch: &[u8]) -> &[u8] {
    if epoch.is_empty() {
        b"0"
    } else {
        epoch
    }
}

/// Splits `[epoch:]version[-release]`.
///
/// The epoch is the leading digit run that ends at a colon; the release is
/// everything after the *last* hyphen of what remains. A version that contains
/// a hyphen without being an EVR (there is no such package version, but the
/// split must not invent one) therefore puts the tail in the release slot,
/// which is what `libalpm` does too.
fn parse_evr(evr: &[u8]) -> (&[u8], &[u8], Option<&[u8]>) {
    let mut end = 0;
    while end < evr.len() && evr[end].is_ascii_digit() {
        end += 1;
    }
    let (epoch, rest) = if end < evr.len() && evr[end] == b':' {
        (&evr[..end], &evr[end + 1..])
    } else {
        (&evr[..0], evr)
    };

    match rest.iter().rposition(|byte| *byte == b'-') {
        Some(at) => (epoch, &rest[..at], Some(&rest[at + 1..])),
        None => (epoch, rest, None),
    }
}

/// One segment run: alternating separator and alphanumeric runs, compared in
/// order. See `rpmvercmp` in `libalpm/version.c`.
fn segment(a: &[u8], b: &[u8]) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }

    // `ptr1`/`ptr2` remember where the previous segment ended, because the
    // length of the separator run between two segments is itself significant:
    // `1..0` is greater than `1.0`.
    let (mut one, mut two) = (0, 0);
    let (mut ptr1, mut ptr2) = (0, 0);

    while one < a.len() && two < b.len() {
        while one < a.len() && !a[one].is_ascii_alphanumeric() {
            one += 1;
        }
        while two < b.len() && !b[two].is_ascii_alphanumeric() {
            two += 1;
        }
        // One side ran out before the other had a segment to compare: the
        // trailing work is decided after the loop, not here.
        if one >= a.len() || two >= b.len() {
            break;
        }

        if one - ptr1 != two - ptr2 {
            return (one - ptr1).cmp(&(two - ptr2));
        }
        ptr1 = one;
        ptr2 = two;

        let numeric = a[ptr1].is_ascii_digit();
        let mut end1 = ptr1;
        let mut end2 = ptr2;
        if numeric {
            while end1 < a.len() && a[end1].is_ascii_digit() {
                end1 += 1;
            }
            while end2 < b.len() && b[end2].is_ascii_digit() {
                end2 += 1;
            }
        } else {
            while end1 < a.len() && a[end1].is_ascii_alphabetic() {
                end1 += 1;
            }
            while end2 < b.len() && b[end2].is_ascii_alphabetic() {
                end2 += 1;
            }
        }

        // The other side had a segment of a different type: a number is newer
        // than a letter run, so `1.0` is newer than `1.0rc`.
        if end2 == ptr2 {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let mut left = &a[ptr1..end1];
        let mut right = &b[ptr2..end2];
        if numeric {
            // Leading zeros never make a number bigger, and the comparison is
            // on length first, so a string compare would be enough only after
            // this trim makes both lengths meaningful.
            while left.first() == Some(&b'0') {
                left = &left[1..];
            }
            while right.first() == Some(&b'0') {
                right = &right[1..];
            }
            if left.len() != right.len() {
                return left.len().cmp(&right.len());
            }
        }
        match left.cmp(right) {
            Ordering::Equal => {}
            other => return other,
        }

        one = end1;
        two = end2;
    }

    let done_a = one >= a.len();
    let done_b = two >= b.len();
    if done_a && done_b {
        return Ordering::Equal;
    }

    // The "final showdown" of `rpmvercmp`, which is not "whoever has bytes
    // left wins": a remaining *alpha* run never beats an empty string.
    //
    //   - one empty and the other not alpha  -> one is older
    //   - one starting with an alpha run     -> one is older
    //   - otherwise                          -> one is newer
    //
    // Without this, `1.0` would sort below `1.0rc1`, which is how pacman
    // decides a release candidate is newer than the release.
    let tail_a = a.get(one).copied().unwrap_or(0);
    let tail_b = b.get(two).copied().unwrap_or(0);
    if (done_a && !tail_b.is_ascii_alphabetic()) || tail_a.is_ascii_alphabetic() {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> i32 {
        match vercmp(a.as_bytes(), b.as_bytes()) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    #[test]
    fn the_documented_examples_hold() {
        // Each of these is a case where text order and version order disagree.
        assert_eq!(cmp("1.0", "1.0"), 0);
        assert_eq!(cmp("1.0", "2.0"), -1);
        assert_eq!(cmp("2.0", "1.0"), 1);
        assert_eq!(cmp("1.9", "1.10"), -1, "10 is newer than 9, not older");
        assert_eq!(cmp("1.0.", "1.0"), 1, "a trailing separator is greater");
        assert_eq!(cmp("1.0", "1.0."), -1);
        assert_eq!(cmp("1..0", "1.0"), 1, "a longer separator run is greater");
        assert_eq!(
            cmp("1.0rc1", "1.0"),
            -1,
            "a trailing alpha run never beats an empty string: rc is older"
        );
        assert_eq!(cmp("1.0", "1.0rc1"), 1);
        assert_eq!(cmp("1.0rc1", "1.0rc2"), -1);
        assert_eq!(cmp("1.0", "1.0.0"), -1, "a further segment wins");
        assert_eq!(cmp("1.0.0", "1.0"), 1);
        assert_eq!(cmp("1.0-1", "1.0-2"), -1, "the release is compared");
        assert_eq!(cmp("2:1.0", "3.0"), 1, "an epoch outranks the version");
        assert_eq!(cmp("1.0", "0:1.0"), 0, "a missing epoch is epoch zero");
        assert_eq!(cmp("1.0+git", "1.0"), 1);
        assert_eq!(cmp("1.0_1", "1.0.1"), 0, "separators of equal length tie");
        assert_eq!(cmp("001", "1"), 0, "leading zeros do not change a number");
        assert_eq!(cmp("1.001", "1.1"), 0);
        assert_eq!(cmp("", ""), 0);
        assert_eq!(cmp("", "1"), -1);
    }

    #[test]
    fn a_trailing_separator_is_not_the_same_as_a_trailing_segment() {
        // The case that makes the finale worth porting rather than approximating:
        // `1.0.` ends in a separator, `1.0rc1` ends in a letter run, and pacman
        // puts the separator higher. A naive "whoever has bytes left wins" puts
        // the letter run higher and would keep the wrong archive.
        assert_eq!(cmp("1.0.", "1.0rc1"), 1);
        assert_eq!(cmp("1.0rc1", "1.0."), -1);
        assert_eq!(cmp("1.0.", "1.0a"), 1);
        assert_eq!(cmp("1.0a", "1.0."), -1);
        // Two trailing separators are the same version as one, because the
        // comparison stops once both sides reach the end.
        assert_eq!(cmp("1.0~~", "1.0~"), 0);
        assert_eq!(cmp("1.0..", "1.0."), 0);
        // A trailing hyphen belongs to the release, not to the separator run,
        // so `1.0-` and `1.0` are the same version rather than ordered.
        assert_eq!(cmp("1.0-", "1.0"), 0);
    }

    #[test]
    fn nothing_panics_on_arbitrary_bytes() {
        // Version strings arrive from file names, and a file name is bytes. A
        // non-UTF-8 one must compare, not crash.
        let inputs: [&[u8]; 6] = [b"", b":", b"-", b"1:", b":::", b"\xff\xfe1.0-\xff"];
        for left in inputs {
            for right in inputs {
                let _ = vercmp(left, right);
            }
        }
    }

    /// The real `vercmp`, if this machine has it.
    ///
    /// A hand-written port of an ordering is the kind of code that is right on
    /// the examples its author thought of. This compares a sample of pairs with
    /// the implementation pacman itself uses; when `vercmp` is missing the test
    /// says so and passes, because "this distro has no pacman" is not a defect.
    ///
    /// The corpus mixes real Arch version shapes (epochs, `+r123+gsha` suffixes,
    /// pkgrel) with generated strings that stress the separator rules, so the
    /// sample is not just the cases the port was written against.
    #[test]
    fn agrees_with_pacmans_vercmp_where_it_is_installed() {
        use std::process::Command;

        let available = Command::new("vercmp")
            .args(["1", "1"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if !available {
            eprintln!("skipping: vercmp is not installed");
            return;
        }

        let curated = [
            "1.0",
            "1.0.0",
            "1.0.",
            "1..0",
            "1.0a",
            "1.0rc1",
            "1.0rc2",
            "1.0-1",
            "1.0-2",
            "2:1.0",
            "0:1.0",
            "1:1.0-1",
            "10.0",
            "9.9",
            "1.01",
            "1.001",
            "1.10",
            "1.9",
            "2.44+r50+g1848099f063e-3",
            "2.44+r51+g1848099f063e-3",
            "5.0.1",
            "5.0.10",
            "20260817.0-2.1",
            "20260816.0-2.1",
            "1.0alpha",
            "1.0.alpha",
            "1.0_beta",
            "0.8.0-3.1",
            "0.8.0-10.1",
            "1-1",
            "1-10",
            "r100.abc",
            "r99.abc",
            "1.0~rc1",
            "1.0+",
            "1.0-",
            "-1.0",
            "1:0",
            "1:0-1",
            "2:0-1",
        ];
        let generated = generated_versions();

        let mut checked = 0usize;
        let mut compare = |left: &str, right: &str| {
            let output = Command::new("vercmp")
                .args([left, right])
                .output()
                .expect("vercmp runs");
            let expected: i32 = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse()
                .expect("vercmp prints -1, 0 or 1");
            assert_eq!(
                cmp(left, right),
                expected,
                "vercmp disagrees: ours says {} for {left:?} vs {right:?}, pacman says {expected}",
                cmp(left, right)
            );
            checked += 1;
        };

        // Every curated version against a handful of others: one process per
        // comparison is the only interface `vercmp` has, so the full square of
        // sixty versions would be an unpleasant test.
        for (index, left) in curated.iter().enumerate() {
            for step in [1usize, 3, 7, 11, 17, 23] {
                compare(left, curated[(index * 13 + step) % curated.len()]);
            }
        }
        // The generated strings are all pairs on a stride, which spreads the
        // sample across the whole set rather than one neighbourhood.
        for (index, left) in generated.iter().enumerate() {
            for (offset, right) in generated.iter().enumerate() {
                if (index * 7 + offset) % 11 == 0 {
                    compare(left, right);
                }
            }
        }

        assert!(checked > 250, "the sample must actually cover the corpus");
    }

    /// Deterministic pseudo-random version strings.
    ///
    /// A generator rather than a list, so the shapes are not limited to the ones
    /// that came to mind while writing the port.
    fn generated_versions() -> Vec<String> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet: [&str; 10] = ["0", "1", "9", "10", "007", "a", "rc", "z", ".", "-"];
        let mut out = Vec::new();
        for _ in 0..24 {
            let mut version = String::new();
            let pieces = 1 + (next() % 5) as usize;
            for _ in 0..pieces {
                version.push_str(alphabet[(next() % alphabet.len() as u64) as usize]);
            }
            if next() % 4 == 0 {
                version = format!("{}:{version}", next() % 3);
            }
            if next() % 3 == 0 {
                version = format!("{version}-{}", next() % 4);
            }
            out.push(version);
        }
        out
    }
}
