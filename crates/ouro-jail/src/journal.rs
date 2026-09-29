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
}
