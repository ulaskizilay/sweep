//! Number formatting shared by every human-facing report.
//!
//! One function, because two copies drift: `sweep clean` printing `3.1 GiB` and
//! `sweep status` printing `3174.2 MiB` for the same number is the kind of
//! inconsistency that makes a user distrust both.

/// Bytes as a short human string: `0 B`, `1023 B`, `1.0 KiB`, `3.4 TiB`.
pub(crate) fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A count with thousands separators, because `4042 files` is read as `404`.
pub(crate) fn human_count(count: u64) -> String {
    let digits = count.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// `1 file`, `2 files`, `10,000 files`.
///
/// The singular case is the whole reason this exists: "removed 1 packages"
/// reads as a bug in the program, not as a small run.
pub(crate) fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{} {noun}s", human_count(count as u64))
    }
}

/// `1.4 TiB` for a percent: one decimal, never more.
pub(crate) fn percent(part: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (part as f64 / total as f64) * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_stays_readable() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024 * 3), "3.0 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024 * 1024), "1.0 TiB");
    }

    #[test]
    fn counts_get_separators() {
        assert_eq!(human_count(0), "0");
        assert_eq!(human_count(999), "999");
        assert_eq!(human_count(1000), "1,000");
        assert_eq!(human_count(4_042), "4,042");
        assert_eq!(human_count(1_234_567), "1,234,567");
    }

    #[test]
    fn a_zero_total_is_not_a_division_by_zero() {
        assert_eq!(percent(5, 0), 0.0);
        assert_eq!(percent(1, 2), 50.0);
    }
}
