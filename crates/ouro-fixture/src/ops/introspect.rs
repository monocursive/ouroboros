//! The modes that report what the process sees: its arguments, a byte
//! stream, its environment's names, its descriptors, its status and its
//! identity.

use std::ffi::{OsString, c_int};
use std::os::unix::ffi::OsStrExt;

use serde_json::Value;

use crate::cli::IntrospectMode;
use crate::report::{OpReport, Reporter, write_all};

/// Run one introspection mode. True when it reported what it set out to.
pub(crate) fn run(rep: &Reporter, mode: IntrospectMode) -> bool {
    match mode {
        IntrospectMode::EchoArgs { argv } => {
            echo_args(rep, &argv);
            true
        }
        IntrospectMode::StdoutBytes { count } => stream_bytes(rep, 1, count, "stdout-bytes"),
        IntrospectMode::StderrBytes { count } => stream_bytes(rep, 2, count, "stderr-bytes"),
        IntrospectMode::Env => {
            env_names(rep);
            true
        }
        IntrospectMode::Fds => fds(rep),
        IntrospectMode::Status => status(rep),
        IntrospectMode::Identity => identity(rep),
    }
}

fn echo_args(rep: &Reporter, argv: &[OsString]) {
    let mut report = OpReport::new("echo-args");
    report.set("count", argv.len());
    let items: Vec<Value> = argv
        .iter()
        .map(|a| {
            let bytes = a.as_bytes();
            let mut m = serde_json::Map::new();
            m.insert("len".into(), Value::from(bytes.len()));
            m.insert(
                "bytes".into(),
                Value::Array(bytes.iter().map(|b| Value::from(*b)).collect()),
            );
            m.insert(
                "lossy".into(),
                Value::String(String::from_utf8_lossy(bytes).into_owned()),
            );
            Value::Object(m)
        })
        .collect();
    report.set("argv", Value::Array(items));
    report.result(argv.len() as i64, None);
    rep.emit(&report);
}

/// How much of the pattern one write carries: a multiple of 256, so the
/// chunks tile the stream exactly.
const STREAM_CHUNK: usize = 64 * 1024;
const _: () = assert!(STREAM_CHUNK.is_multiple_of(256));

/// Byte `i` of the stream is `i % 256`, so every byte value including NUL
/// appears and any truncation or re-encoding is visible.
fn stream_bytes(rep: &Reporter, fd: c_int, count: u64, name: &str) -> bool {
    let pattern = crate::bounded::pattern(STREAM_CHUNK);
    let mut left = count;
    let mut ok = true;
    while left > 0 {
        let n = std::cmp::min(left, STREAM_CHUNK as u64) as usize;
        if !write_all(fd, &pattern[..n]) {
            ok = false;
            break;
        }
        left -= n as u64;
    }
    let mut report = OpReport::new(name);
    report.set("fd", fd);
    report.set("requested", count);
    report.set("written", count - left);
    report.set("pattern", "byte i = i % 256");
    report.result((count - left) as i64, None);
    rep.emit(&report);
    ok
}

fn env_names(rep: &Reporter) {
    let mut names: Vec<String> = Vec::new();
    let mut non_utf8 = 0usize;
    for (k, _value) in std::env::vars_os() {
        if std::str::from_utf8(k.as_bytes()).is_err() {
            non_utf8 += 1;
        }
        names.push(String::from_utf8_lossy(k.as_bytes()).into_owned());
    }
    names.sort();
    let mut report = OpReport::new("env");
    report.set("count", names.len());
    report.set("non_utf8_names", non_utf8);
    report.set(
        "names",
        Value::Array(names.into_iter().map(Value::from).collect()),
    );
    report.set("values_reported", false);
    report.result(0, None);
    rep.emit(&report);
}

/// The kernel's own list of this process's open descriptors.
///
/// `/proc/self/fd` on Linux and `/dev/fd` on Darwin are the authoritative
/// enumerations. Probing a range instead used to stop at 4096, so a leaked
/// descriptor numbered above that was invisible and X06 ("no private
/// authority reaches it") could pass with the leak in place.
fn fd_directory() -> &'static str {
    if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    }
}

/// Descriptor numbers the kernel says are open, or `None` when the directory
/// could not be listed. The directory's own descriptor is excluded: it is
/// closed before the numbers are confirmed.
pub fn open_fd_numbers() -> Option<Vec<c_int>> {
    let entries = std::fs::read_dir(fd_directory()).ok()?;
    let mut numbers: Vec<c_int> = Vec::new();
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str()
            && let Ok(n) = name.parse::<c_int>()
        {
            numbers.push(n);
        }
    }
    // `entries` is dropped here, closing the descriptor the listing used, so
    // the confirmation pass below drops it from the result.
    numbers.sort_unstable();
    Some(numbers)
}

/// The soft descriptor limit, or `None` when `getrlimit` fails.
fn soft_fd_limit() -> Option<u64> {
    // SAFETY: `rl` is a live rlimit struct, which is what `getrlimit` writes.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl) } == 0).then_some(rl.rlim_cur)
}

fn describe_fd(fd: c_int) -> Option<Value> {
    // SAFETY: `F_GETFD` only reads the descriptor flags and is safe for any
    // integer; a closed descriptor returns -1 with EBADF.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return None;
    }
    let kind = crate::unix::file_kind(fd).unwrap_or("unreadable");
    let mut m = serde_json::Map::new();
    m.insert("fd".into(), Value::from(fd));
    m.insert("kind".into(), Value::from(kind));
    m.insert("cloexec".into(), Value::from(flags & libc::FD_CLOEXEC != 0));
    Some(Value::Object(m))
}

fn fds(rep: &Reporter) -> bool {
    let limit = soft_fd_limit();
    let (numbers, source, complete) = match (open_fd_numbers(), limit) {
        (Some(n), _) => (n, fd_directory().to_string(), true),
        // Fall back to probing the whole soft limit rather than a fixed
        // slice of it, and say that is what happened.
        (None, Some(limit)) => {
            let cap = c_int::try_from(limit).unwrap_or(c_int::MAX);
            (
                (0..cap).collect(),
                format!("scan 0..{cap}"),
                u64::try_from(cap).is_ok_and(|cap| cap >= limit),
            )
        }
        // Neither the kernel's list nor the limit: nothing was scanned, and
        // nothing may be claimed complete.
        (None, None) => (
            Vec::new(),
            "none (the soft limit is unknown)".to_string(),
            false,
        ),
    };

    let open: Vec<Value> = numbers.into_iter().filter_map(describe_fd).collect();

    let mut report = OpReport::new("fds");
    report.set("source", source);
    report.set("soft_limit", limit);
    report.set("complete", complete);
    report.set("count", open.len());
    report.set("fds", Value::Array(open));
    report.set("paths_reported", false);
    report.result(0, None);
    rep.emit(&report);
    // An enumeration that could have missed a descriptor is not a result.
    complete
}

fn status(rep: &Reporter) -> bool {
    let mut report = OpReport::new("status");
    #[cfg(target_os = "linux")]
    {
        const WANTED: &[&str] = &[
            "Uid",
            "Gid",
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
            "NoNewPrivs",
            "Seccomp",
            "Seccomp_filters",
            "NSpid",
            "TracerPid",
        ];
        match std::fs::read_to_string("/proc/self/status") {
            Ok(text) => {
                let mut found = serde_json::Map::new();
                for line in text.lines() {
                    if let Some((k, v)) = line.split_once(':')
                        && WANTED.contains(&k)
                    {
                        found.insert(k.to_string(), Value::from(v.trim()));
                    }
                }
                let missing: Vec<&&str> =
                    WANTED.iter().filter(|k| !found.contains_key(**k)).collect();
                report.set("fields", Value::Object(found));
                report.set(
                    "missing",
                    Value::Array(missing.into_iter().map(|k| Value::from(*k)).collect()),
                );
                report.set("source", "/proc/self/status");
                report.result(0, None);
                rep.emit(&report);
                true
            }
            Err(e) => {
                report.set("source", "/proc/self/status");
                report.result(-1, e.raw_os_error());
                rep.emit(&report);
                false
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        report.set(
            "unsupported",
            format!(
                "/proc/self/status is a Linux interface; unsupported on this platform ({})",
                std::env::consts::OS
            ),
        );
        report.result(-1, None);
        let e = crate::report::Emitted::unusable(report);
        rep.emit(&e.report);
        false
    }
}

/// This process as it sees itself: the number `getpid` returns (a namespace
/// pid inside a pid namespace), its start time and its `NSpid` line.
fn identity(rep: &Reporter) -> bool {
    let mut report = OpReport::new("identity");
    // SAFETY: `getpid` takes no arguments.
    let pid = unsafe { libc::getpid() };
    report.set("pid", pid);
    #[cfg(target_os = "linux")]
    {
        let start = std::fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|raw| {
                let tail = raw[raw.rfind(')')? + 1..].to_string();
                tail.split_whitespace().nth(19)?.parse::<u64>().ok()
            });
        report.set("start_ticks", start.map_or(Value::Null, Value::from));
        let nspid = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("NSpid:").map(|v| v.trim().to_string()))
            });
        report.set("nspid", nspid.map_or(Value::Null, Value::from));
        report.result(0, None);
        rep.emit(&report);
        true
    }
    #[cfg(not(target_os = "linux"))]
    {
        report.set(
            "unsupported",
            "start ticks and NSpid are Linux /proc interfaces",
        );
        report.result(-1, None);
        let e = crate::report::Emitted::unusable(report);
        rep.emit(&e.report);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_byte_pattern_covers_every_byte_value() {
        // The chunk `stream_bytes` writes, twice over: the stream it makes.
        let chunk = crate::bounded::pattern(STREAM_CHUNK);
        let stream: Vec<u8> = chunk.iter().chain(&chunk).copied().collect();
        let mut seen = [false; 256];
        for b in &stream[..256] {
            seen[*b as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
        assert_eq!(stream[0], 0, "NUL is in the stream");
        assert_eq!(
            stream,
            crate::bounded::pattern(2 * STREAM_CHUNK),
            "chunks tile the stream exactly"
        );
    }
}
