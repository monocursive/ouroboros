//! The claim the whole fixture rests on: the syscall a test names is the
//! syscall the kernel sees.
//!
//! This is not obvious. glibc's `open()` issues `openat`, and several other
//! wrappers rewrite themselves to their `*at` form, so a fixture built on the
//! wrappers would silently rename operations in a trace and every closed-set
//! assertion downstream would be about the wrong call. `crates/…/raw.rs`
//! therefore goes through `syscall(SYS_x, …)` on Linux, and this test checks
//! the result against a tracer rather than against the source.
//!
//! `strace` is the tracer here because it is independent of anything this
//! repository builds. jail-v1 §5.2 already pins it on the reference host as
//! the observer stand-in (backend-evaluation.md §2.1, strace 6.19). If it is
//! missing the test skips, which `OURO_CONFORMANCE=1` turns into a failure:
//! the reference host having lost a tool the evidence pinned is worth failing
//! over, not worth passing quietly.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Command;

use ouro_fixture::harness::{self, TempDir};

const TRACED: &str = "open,openat,openat2,creat,mkdir,mkdirat,rename,renameat,renameat2,\
                      unlink,unlinkat,rmdir,link,linkat,symlink,symlinkat,execve,execveat,connect";

fn strace_available() -> bool {
    Command::new("strace")
        .arg("-V")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run the fixture under strace and return the trace text.
fn traced(log: &Path, args: &[&str]) -> String {
    let status = Command::new("strace")
        .arg("-f")
        .arg("-e")
        .arg(format!("trace={TRACED}"))
        .arg("-o")
        .arg(log)
        .arg(harness::fixture_path())
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("strace must run");
    assert!(
        status.success(),
        "the fixture failed under strace: {args:?} -> {status:?}"
    );
    std::fs::read_to_string(log).expect("strace must have written its log")
}

/// Does the trace contain a call to `name` mentioning `needle`?
fn called(trace: &str, name: &str, needle: &str) -> bool {
    trace.lines().any(|line| {
        let body = line.trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ');
        body.starts_with(&format!("{name}(")) && line.contains(needle)
    })
}

#[test]
fn each_via_reaches_the_kernel_as_exactly_that_syscall() {
    if !strace_available() {
        harness::skip_or_fail("strace is not installed on this host");
        return;
    }
    let dir = TempDir::new("ouro-fixture-identity").unwrap();
    let log = dir.path().join("trace");

    // open: the case that motivates the whole raw layer. glibc's `open()`
    // wrapper issues `openat`, so a wrapper-based fixture would report `open`
    // while the kernel saw `openat`.
    for (via, syscall) in [
        ("openat", "openat"),
        ("open", "open"),
        ("creat", "creat"),
        ("openat2", "openat2"),
    ] {
        let path = dir.path().join(format!("f-{via}"));
        let trace = traced(
            &log,
            &[
                "open",
                &path.display().to_string(),
                "--via",
                via,
                "--create",
                "--write",
            ],
        );
        assert!(
            called(&trace, syscall, &path.display().to_string()),
            "--via {via} did not issue {syscall}; trace:\n{trace}"
        );
        for other in ["openat", "open", "creat", "openat2"] {
            if other != syscall {
                assert!(
                    !called(&trace, other, &path.display().to_string()),
                    "--via {via} also issued {other}; trace:\n{trace}"
                );
            }
        }
        assert!(path.is_file(), "--via {via} did not create the file");
    }
}

#[test]
fn the_directory_and_link_variants_are_distinct_at_the_kernel() {
    if !strace_available() {
        harness::skip_or_fail("strace is not installed on this host");
        return;
    }
    let dir = TempDir::new("ouro-fixture-identity").unwrap();
    let log = dir.path().join("trace");

    for (mode, via, syscall) in [("mkdir", "mkdir", "mkdir"), ("mkdir", "mkdirat", "mkdirat")] {
        let path = dir.path().join(format!("d-{via}"));
        let trace = traced(&log, &[mode, &path.display().to_string(), "--via", via]);
        assert!(
            called(&trace, syscall, &path.display().to_string()),
            "{mode} --via {via} did not issue {syscall}; trace:\n{trace}"
        );
    }

    for (via, syscall) in [
        ("rename", "rename"),
        ("renameat", "renameat"),
        ("renameat2", "renameat2"),
    ] {
        let from = dir.path().join(format!("r-{via}"));
        let to = dir.path().join(format!("r2-{via}"));
        traced(
            &log,
            &["open", &from.display().to_string(), "--create", "--write"],
        );
        let trace = traced(
            &log,
            &[
                "rename",
                &from.display().to_string(),
                &to.display().to_string(),
                "--via",
                via,
            ],
        );
        assert!(
            called(&trace, syscall, &from.display().to_string()),
            "rename --via {via} did not issue {syscall}; trace:\n{trace}"
        );
        assert!(to.is_file());
    }

    for (mode, via, syscall, extra) in [
        ("unlink", "unlink", "unlink", None),
        ("unlink", "unlinkat", "unlinkat", None),
        ("symlink", "symlink", "symlink", Some("target")),
        ("symlink", "symlinkat", "symlinkat", Some("target")),
    ] {
        let path = dir.path().join(format!("{mode}-{via}"));
        if extra.is_none() {
            traced(
                &log,
                &["open", &path.display().to_string(), "--create", "--write"],
            );
        }
        let args: Vec<String> = match extra {
            Some(target) => vec![
                mode.into(),
                target.into(),
                path.display().to_string(),
                "--via".into(),
                via.into(),
            ],
            None => vec![
                mode.into(),
                path.display().to_string(),
                "--via".into(),
                via.into(),
            ],
        };
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let trace = traced(&log, &refs);
        assert!(
            called(&trace, syscall, &path.display().to_string()),
            "{mode} --via {via} did not issue {syscall}; trace:\n{trace}"
        );
    }
}

#[test]
fn a_refused_path_produces_no_syscall_at_all() {
    // The unsafe boundary, checked from outside: an interior NUL must not
    // reach the kernel, so the trace must contain none of the traced calls on
    // the truncated prefix.
    if !strace_available() {
        harness::skip_or_fail("strace is not installed on this host");
        return;
    }
    let dir = TempDir::new("ouro-fixture-identity").unwrap();
    let log = dir.path().join("trace");
    let target = dir.path().join("boundary");
    let script = dir.path().join("nul.json");
    let with_nul = format!("{}\u{0}ignored", target.display());
    std::fs::write(
        &script,
        serde_json::json!([["open", with_nul, "--create", "--write"]]).to_string(),
    )
    .unwrap();

    // The fixture exits 3 here, so this does not use `traced`, which requires
    // success.
    let status = Command::new("strace")
        .arg("-f")
        .arg("-e")
        .arg(format!("trace={TRACED}"))
        .arg("-o")
        .arg(&log)
        .arg(harness::fixture_path())
        .args(["script", &script.display().to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(3), "the refusal must fail the run");

    let trace = std::fs::read_to_string(&log).unwrap();
    assert!(
        !trace.contains(&target.display().to_string()),
        "a syscall saw the truncated path; trace:\n{trace}"
    );
    assert!(!target.exists());
}
