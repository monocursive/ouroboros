//! UTC stamps for run directories and reports.
//!
//! The dependency policy bans a date crate; the records crate already
//! formats RFC 3339 from Unix seconds (`rfc3339_utc_from_unix`), and the
//! sortable directory stamp is that text without its separators.

use std::time::{SystemTime, UNIX_EPOCH};

/// `YYYYmmddTHHMMSSZ` for a Unix timestamp in seconds.
#[must_use]
pub fn utc_stamp_from_unix(secs: i64) -> String {
    rfc3339_from_unix(secs).replace(['-', ':'], "")
}

/// `YYYY-mm-ddTHH:MM:SSZ`, the RFC 3339 form, for report text.
#[must_use]
pub fn rfc3339_from_unix(secs: i64) -> String {
    ukai_jail::records::rfc3339_utc_from_unix(secs)
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
