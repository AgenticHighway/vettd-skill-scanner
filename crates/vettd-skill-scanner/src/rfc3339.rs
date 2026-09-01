//! RFC 3339 UTC timestamp formatting and validation, implemented on `std`
//! alone so the engine and shim do not depend on a time library.
//!
//! The `time` crate was originally pinned for this, but the patched release
//! that clears the `time` RUSTSEC advisory requires Rust 1.88 — newer than
//! the repo's pinned 1.85.1 toolchain. A ~20-line civil-date conversion
//! removes the dependency (and the advisory) entirely. `observed_at` only
//! needs second precision in `YYYY-MM-DDTHH:MM:SSZ`; no sub-second digits.

use std::sync::OnceLock;

use regex::Regex;

/// Convert days since the Unix epoch into a `(year, month, day)` civil date.
///
/// Howard Hinnant's `civil_from_days` algorithm, in the public domain.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Current UTC time as an RFC 3339 string, e.g. `2026-08-31T14:05:00Z`.
///
/// Second precision, `Z` offset, no sub-second digits. Used by the HTTP shim
/// to stamp `observed_at` for a scan.
pub fn now_utc_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be at or after the Unix epoch");
    let secs = now.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3600) as u32;
    let minute = ((rem % 3600) / 60) as u32;
    let second = (rem % 60) as u32;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Validate a caller-supplied RFC 3339 timestamp before it is copied onto
/// every signal.
///
/// `observed_at` is wire-required: a missing or malformed value would fail
/// validation of the entire scanner job response. This is a boundary guard,
/// not a parser — it rejects empty and clearly-invalid strings while
/// accepting anything the shim (or a first-party CLI) produces.
///
/// The check is calendar-aware: the day must exist in the actual month of the
/// given year (leap years included), and the UTC offset must fall within the
/// RFC 3339 `time-numoffset` range (hours 00-23, minutes 00-59).
pub fn is_valid_rfc3339(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)$")
            .expect("valid RFC3339 regex")
    });
    if !re.is_match(value) || value.len() < 19 {
        return false;
    }
    // Coarse range checks on the fixed-width date/time fields. Fractional
    // seconds are validated by the regex alone; the offset is checked below.
    let date = &value[..10];
    let time = &value[11..19];
    let (Ok(year), Ok(month), Ok(day)) = (
        date[0..4].parse::<i32>(),
        date[5..7].parse::<u32>(),
        date[8..10].parse::<u32>(),
    ) else {
        return false;
    };
    let (Ok(hour), Ok(minute), Ok(second)) = (
        time[0..2].parse::<u32>(),
        time[3..5].parse::<u32>(),
        time[6..8].parse::<u32>(),
    ) else {
        return false;
    };
    if year < 0 || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    if !(1..=12).contains(&month) || !(1..=days_in_month(year, month)).contains(&day) {
        return false;
    }
    if value.ends_with('Z') {
        return true;
    }
    // The offset is the trailing fixed-width `±hh:mm` the regex already
    // matched; only its magnitude still needs range checking.
    let offset = &value[value.len() - 6..];
    let (Ok(offset_hour), Ok(offset_minute)) =
        (offset[1..3].parse::<u32>(), offset[4..6].parse::<u32>())
    else {
        return false;
    };
    offset_hour <= 23 && offset_minute <= 59
}

/// Days in `month` of `year`, Gregorian calendar, leap years included.
fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, is_valid_rfc3339, now_utc_rfc3339};

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        // 2026-08-31 is 20696 days after the epoch.
        assert_eq!(civil_from_days(20_696), (2026, 8, 31));
    }

    #[test]
    fn accepts_valid_rfc3339() {
        for value in [
            "2026-08-31T00:00:00Z",
            "2026-08-31T14:05:00Z",
            "2026-08-31T14:05:00.123Z",
            "2026-08-31T14:05:00+02:00",
            "2026-01-01T23:59:59-05:00",
            "2026-08-31T14:05:00.123+02:00",
            // Calendar boundary: the day exists in its month.
            "2024-02-29T12:00:00Z",
            "2026-02-28T12:00:00Z",
            "2026-12-31T12:00:00Z",
            // RFC 3339 `time-numoffset` permits offsets through +23:59.
            "2026-08-31T14:05:00+23:59",
            "2026-08-31T14:05:00-23:59",
            "2026-08-31T14:05:00+00:00",
            "2026-08-31T14:05:00-00:00",
        ] {
            assert!(is_valid_rfc3339(value), "expected valid: {value}");
        }
    }

    #[test]
    fn rejects_invalid_rfc3339() {
        for value in [
            "",
            "not-a-timestamp",
            "2026-08-31",
            "2026-08-31T00:00:00",
            "2026-13-01T00:00:00Z",
            "2026-08-32T00:00:00Z",
            "2026-08-31T24:00:00Z",
            "2026-08-31T00:60:00Z",
        ] {
            assert!(!is_valid_rfc3339(value), "expected invalid: {value}");
        }
    }

    #[test]
    fn rejects_calendar_impossible_dates() {
        // The day must exist in the actual month of the given year. 2026 is
        // not a leap year; 1900 is a century year (no leap), 2000 is
        // divisible by 400 (leap).
        for value in [
            // 2026-02-29 does not exist (2026 is not a leap year).
            "2026-02-29T00:00:00Z",
            // 30/31-day months that only have 30/28 days.
            "2026-04-31T00:00:00Z",
            "2026-06-31T00:00:00Z",
            "2026-09-31T00:00:00Z",
            "2026-11-31T00:00:00Z",
            "2026-02-30T00:00:00Z",
            // 1900-02-29 does not exist (divisible by 100, not 400).
            "1900-02-29T00:00:00Z",
        ] {
            assert!(!is_valid_rfc3339(value), "expected invalid: {value}");
        }
        assert!(
            is_valid_rfc3339("2000-02-29T00:00:00Z"),
            "400-year leap day is valid"
        );
    }

    #[test]
    fn rejects_out_of_range_utc_offsets() {
        // RFC 3339 `time-numoffset` bounds the offset to hours 00-23 and
        // minutes 00-59. Anything beyond is not a real time offset.
        for value in [
            "2026-08-31T00:00:00+24:00",
            "2026-08-31T00:00:00-24:00",
            "2026-08-31T00:00:00+23:60",
            "2026-08-31T00:00:00-23:60",
            "2026-08-31T00:00:00+70:00",
            "2026-08-31T00:00:00.5+24:00",
            "2026-08-31T00:00:00Z+02:00",
        ] {
            assert!(!is_valid_rfc3339(value), "expected invalid: {value}");
        }
    }

    #[test]
    fn now_utc_rfc3339_is_valid_and_utc() {
        let value = now_utc_rfc3339();
        assert!(is_valid_rfc3339(&value));
        assert!(value.ends_with('Z'));
    }
}
