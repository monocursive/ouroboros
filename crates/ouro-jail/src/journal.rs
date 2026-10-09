//! Read-only journal access for tail and learning. Complete envelopes retain
//! their original bytes; a partial final frame is never printed as evidence.
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::state::{
    AttemptId,
    anchored::{Dir, Name},
};

pub fn attempt_path(data: &Path, selected: Option<&str>) -> Result<PathBuf, String> {
    let base = data.join("attempts");
    let id = if let Some(id) = selected {
        AttemptId::parse(id)
            .map_err(|e| e.message)?
            .as_str()
            .to_owned()
    } else {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&base).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if AttemptId::parse(&name).is_err()
                || !entry.file_type().map_err(|e| e.to_string())?.is_dir()
            {
                continue;
            }
            entries.push((
                entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .map_err(|e| e.to_string())?,
                name,
            ));
        }
        entries.sort();
        entries.pop().ok_or("no recorded attempt")?.1
    };
    Ok(base.join(id))
}

pub fn open(attempt: &Path, file: &str) -> io::Result<File> {
    let parent = Dir::open_trusted(
        attempt
            .parent()
            .ok_or_else(|| io::Error::other("no attempt parent"))?,
    )?;
    let name = Name::new(
        attempt
            .file_name()
            .ok_or_else(|| io::Error::other("no attempt name"))?
            .as_encoded_bytes(),
    )?;
    let dir = parent.open_dir_at(&name, None)?;
    let file = dir.open_read_at(&Name::new(file.as_bytes())?, None)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("journal object is not a regular file"));
    }
    Ok(file)
}

pub fn tail(
    attempt: &Path,
    follow: bool,
    json: bool,
    since: Option<&str>,
    output: &mut impl Write,
) -> Result<(), String> {
    if let Some(since) = since
        && !valid_timestamp(since)
    {
        return Err("--since must be a UTC timestamp YYYY-MM-DDTHH:MM:SSZ".into());
    }
    let file = open(attempt, "trace.ndjson").map_err(|e| e.to_string())?;
    let lock = open(attempt, "jail.lock").map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(file);
    let mut pending = Vec::new();
    let mut drained_after_close = false;
    loop {
        let bytes = reader.fill_buf().map_err(|e| e.to_string())?;
        if bytes.is_empty() {
            let ended = !follow
                || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0;
            if ended && drained_after_close {
                if !pending.is_empty() {
                    return Err("incomplete final journal frame".into());
                }
                return Ok(());
            }
            if ended {
                drained_after_close = true;
                continue;
            }
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let used = bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |i| i + 1);
        pending.extend_from_slice(&bytes[..used]);
        reader.consume(used);
        if pending.len() > 1024 * 1024 {
            return Err("journal frame exceeds 1 MiB".into());
        }
        if !pending.ends_with(b"\n") {
            continue;
        }
        let event: serde_json::Value =
            serde_json::from_slice(&pending).map_err(|e| e.to_string())?;
        let at = event["observed_at"].as_str().unwrap_or("");
        // Compare against the whole-second prefix: a recorded fractional
        // timestamp within that second sorts before its trailing Z.
        if since.is_none_or(|start| at >= &start[..19]) {
            if json {
                output.write_all(&pending).map_err(|e| e.to_string())?;
            } else {
                let line = format!(
                    "{} {} {} {}",
                    at,
                    event["source"].as_str().unwrap_or("?"),
                    event["operation"].as_str().unwrap_or("?"),
                    event["fields"]
                );
                writeln!(output, "{}", crate::records::escape_control(&line))
                    .map_err(|e| e.to_string())?;
            }
            output.flush().map_err(|e| e.to_string())?;
        }
        pending.clear();
    }
}

fn valid_timestamp(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
        || ![0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
            .iter()
            .all(|r| b[r.clone()].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| {
        b[range]
            .iter()
            .fold(0u32, |n, v| n * 10 + u32::from(v - b'0'))
    };
    let year = number(0..4);
    let days = match number(5..7) {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&number(8..10))
        && number(11..13) < 24
        && number(14..16) < 60
        && number(17..19) < 60
}

#[cfg(test)]
mod tests {
    #[test]
    fn since_includes_fractional_events_in_the_start_second() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = dir.path().join("attempt");
        std::fs::create_dir(&attempt).unwrap();
        std::fs::write(attempt.join("jail.lock"), b"").unwrap();
        let before = b"{\"observed_at\":\"2026-09-28T12:00:00.999Z\"}\n";
        let included = b"{\"observed_at\":\"2026-09-28T12:00:01.001Z\"}\n";
        std::fs::write(
            attempt.join("trace.ndjson"),
            [before.as_slice(), included.as_slice()].concat(),
        )
        .unwrap();
        let mut output = Vec::new();
        super::tail(
            &attempt,
            false,
            true,
            Some("2026-09-28T12:00:01Z"),
            &mut output,
        )
        .unwrap();
        assert_eq!(output, included);
    }

    #[test]
    fn since_requires_a_real_utc_calendar_time() {
        for good in ["2026-09-28T00:00:00Z", "2024-02-29T23:59:59Z"] {
            assert!(super::valid_timestamp(good));
        }
        for bad in [
            "2026-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-09-31T00:00:00Z",
            "2026-09-28T24:00:00Z",
            "xxxx-xx-xxTxx:xx:xxZ",
            "2026-09-28T00:00:00+00:00",
        ] {
            assert!(!super::valid_timestamp(bad));
        }
    }

    // Portable-mutation regressions (audit 2026-10-08) begin

    /// J1: a torn final frame — truncated mid-frame, no LF — is never
    /// printed as evidence; the tail refuses.
    #[test]
    fn a_torn_final_frame_is_refused_not_printed() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = dir.path().join("attempt");
        std::fs::create_dir(&attempt).unwrap();
        std::fs::write(attempt.join("jail.lock"), b"").unwrap();
        let whole = b"{\"observed_at\":\"2026-09-28T12:00:00Z\"}\n";
        std::fs::write(
            attempt.join("trace.ndjson"),
            [whole.as_slice(), &b"{\"observed_at\":\"2026-"[..]].concat(),
        )
        .unwrap();
        let mut output = Vec::new();
        let error = super::tail(&attempt, false, true, None, &mut output)
            .expect_err("a torn final frame must refuse");
        assert!(error.contains("incomplete"), "{error}");
        // Only the complete frame is evidence; nothing torn is printed.
        assert_eq!(output, whole);
    }

    /// J3: a frame over the 1 MiB bound is refused, even when it is complete
    /// and valid JSON — a bounded reader never prints an unbounded frame.
    #[test]
    fn an_oversized_frame_is_refused_even_when_complete() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = dir.path().join("attempt");
        std::fs::create_dir(&attempt).unwrap();
        std::fs::write(attempt.join("jail.lock"), b"").unwrap();
        let mut frame = b"{\"observed_at\":\"2026-09-28T12:00:00Z\",\"pad\":\"".to_vec();
        frame.resize(1024 * 1024 + 512, b'x');
        frame.extend(b"\"}\n");
        std::fs::write(attempt.join("trace.ndjson"), &frame).unwrap();
        let mut output = Vec::new();
        let error = super::tail(&attempt, false, true, None, &mut output)
            .expect_err("a frame over 1 MiB must refuse");
        assert!(error.contains("1 MiB"), "{error}");
        assert!(output.is_empty());
    }

    /// J4: a `--attempt` value is an attempt id, never a path: `../x` must
    /// refuse before it can name a directory outside `attempts/`.
    #[test]
    fn an_attempt_selection_may_not_contain_path_separators() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["../x", "att_../../etc", "a/b", ".", ".."] {
            assert!(
                super::attempt_path(dir.path(), Some(bad)).is_err(),
                "`{bad}` must refuse"
            );
        }
        let good = "att_00000000-0000-4000-8000-000000000001";
        assert_eq!(
            super::attempt_path(dir.path(), Some(good)).unwrap(),
            dir.path().join("attempts").join(good)
        );
    }
    // Portable-mutation regressions end
}
