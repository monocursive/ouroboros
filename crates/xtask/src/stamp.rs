//! A UTC stamp without a date crate.
//!
//! The J1 dependency policy bans `chrono` and `time`, and the driver needs one
//! sortable directory name per run. Days-to-civil is Howard Hinnant's
//! algorithm, which is exact for the proleptic Gregorian calendar.

use std::time::{SystemTime, UNIX_EPOCH};

/// `YYYYmmddTHHMMSSZ` for a Unix timestamp in seconds.
#[must_use]
pub fn utc_stamp_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// `YYYY-mm-ddTHH:MM:SSZ`, the RFC 3339 form, for report text.
#[must_use]
pub fn rfc3339_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// The current UTC stamp.
#[must_use]
pub fn utc_stamp_now() -> String {
    utc_stamp_from_unix(unix_now())
}

/// The current time in whole seconds since the Unix epoch.
#[must_use]
pub fn unix_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants_convert_exactly() {
        assert_eq!(utc_stamp_from_unix(0), "19700101T000000Z");
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        // 2026-09-22T04:44:50Z, the reference-host measurement in this slice.
        assert_eq!(utc_stamp_from_unix(1_790_052_290), "20260922T044450Z");
        assert_eq!(rfc3339_from_unix(1_790_052_290), "2026-09-22T04:44:50Z");
    }

    #[test]
    fn leap_days_and_year_boundaries_are_right() {
        // 2024-02-29T12:00:00Z
        assert_eq!(utc_stamp_from_unix(1_709_208_000), "20240229T120000Z");
        // 2000-02-29T00:00:00Z: the century that is a leap year.
        assert_eq!(utc_stamp_from_unix(951_782_400), "20000229T000000Z");
        // 1999-12-31T23:59:59Z and the second after it.
        assert_eq!(utc_stamp_from_unix(946_684_799), "19991231T235959Z");
        assert_eq!(utc_stamp_from_unix(946_684_800), "20000101T000000Z");
    }

    #[test]
    fn stamps_sort_chronologically_as_strings() {
        let a = utc_stamp_from_unix(1_700_000_000);
        let b = utc_stamp_from_unix(1_700_000_001);
        let c = utc_stamp_from_unix(1_800_000_000);
        assert!(a < b && b < c, "{a} {b} {c}");
    }

    #[test]
    fn now_is_after_this_slice_was_written() {
        // 2026-01-01T00:00:00Z. A clock far in the past would make run
        // directories collide and sort wrongly, so it is worth asserting.
        assert!(unix_now() > 1_767_225_600, "system clock is before 2026");
    }
}
