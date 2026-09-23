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
                      unlink,unlinkat,rmdir,link,linkat,symlink,symlinkat,execve,execveat,connect,\
                      mknod,mknodat,truncate,ftruncate";

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
fn the_node_creation_variants_are_distinct_at_the_kernel() {
    if !strace_available() {
        harness::skip_or_fail("strace is not installed on this host");
        return;
    }
    let dir = TempDir::new("ouro-fixture-identity").unwrap();
    let log = dir.path().join("trace");

    for (via, syscall) in [("mknod", "mknod"), ("mknodat", "mknodat")] {
        let path = dir.path().join(format!("n-{via}"));
        let trace = traced(&log, &["mknod", &path.display().to_string(), "--via", via]);
        assert!(
            called(&trace, syscall, &path.display().to_string()),
            "mknod --via {via} did not issue {syscall}; trace:\n{trace}"
        );
        let other = if syscall == "mknod" {
            "mknodat"
        } else {
            "mknod"
        };
        assert!(
            !called(&trace, other, &path.display().to_string()),
            "mknod --via {via} also issued {other}; trace:\n{trace}"
        );
        use std::os::unix::fs::FileTypeExt;
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_fifo(),
            "--via {via} did not create a fifo"
        );
    }
}

#[test]
fn truncate_names_a_path_to_the_kernel_and_ftruncate_names_only_a_descriptor() {
    // This is the distinction the two modes exist to make visible: a tracer
    // that attributes by path can attribute `truncate` and cannot attribute
    // `ftruncate`, whose only argument is a descriptor number.
    if !strace_available() {
        harness::skip_or_fail("strace is not installed on this host");
        return;
    }
    let dir = TempDir::new("ouro-fixture-identity").unwrap();
    let log = dir.path().join("trace");

    let by_path = dir.path().join("t-path");
    std::fs::write(&by_path, vec![b'x'; 100]).unwrap();
    let trace = traced(&log, &["truncate", &by_path.display().to_string(), "4096"]);
    assert!(
        called(&trace, "truncate", &by_path.display().to_string()),
        "truncate did not issue truncate; trace:\n{trace}"
    );
    assert!(
        !called(&trace, "ftruncate", &by_path.display().to_string()),
        "truncate issued ftruncate; trace:\n{trace}"
    );
    assert_eq!(std::fs::metadata(&by_path).unwrap().len(), 4096);

    let by_fd = dir.path().join("t-fd");
    std::fs::write(&by_fd, vec![b'x'; 100]).unwrap();
    let trace = traced(&log, &["ftruncate", &by_fd.display().to_string(), "2048"]);
    let named = by_fd.display().to_string();
    assert!(
        called(&trace, "openat", &named),
        "the open that names the path is missing; trace:\n{trace}"
    );
    assert!(
        trace.lines().any(|l| l
            .trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ')
            .starts_with("ftruncate(")),
        "ftruncate is missing; trace:\n{trace}"
    );
    assert!(
        !called(&trace, "ftruncate", &named),
        "ftruncate cannot carry the path, yet the trace shows it doing so:\n{trace}"
    );
    assert!(
        !called(&trace, "truncate", &named),
        "the fd-based mode issued the path-based syscall; trace:\n{trace}"
    );
    assert_eq!(std::fs::metadata(&by_fd).unwrap().len(), 2048);
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

/// The socket-level and inner-sandbox syscalls the J3 modes name.
const TRACED_J3: &str = "socket,socketpair,bind,listen,accept4,connect,sendto,sendmsg,recvmsg,\
                         prctl,landlock_create_ruleset,landlock_add_rule,landlock_restrict_self,\
                         seccomp,execve";

/// Run the fixture under strace with the J3 set; return the exit code and
/// the trace text.
fn traced_j3(log: &Path, args: &[&str]) -> (Option<i32>, String) {
    let status = Command::new("strace")
        .arg("-f")
        .arg("-e")
        .arg(format!("trace={TRACED_J3}"))
        .arg("-o")
        .arg(log)
        .arg(harness::fixture_path())
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("strace must run");
    let trace = std::fs::read_to_string(log).expect("strace must have written its log");
    (status.code(), trace)
}

#[test]
fn the_socket_modes_reach_the_kernel_as_the_syscalls_their_lines_name() {
    if !strace_available() {
        harness::skip_or_fail("strace is not installed on this host");
        return;
    }
    let dir = TempDir::new("ouro-fixture-identity").unwrap();
    let log = dir.path().join("trace");
    let sock = dir.path().join("echo.sock").display().to_string();
    let fixture = harness::fixture_path().display().to_string();

    // Listener and a spawned client: both processes are traced (-f).
    let (code, trace) = traced_j3(
        &log,
        &[
            "unix-listen",
            &sock,
            "--accept",
            "1",
            "--",
            &fixture,
            "unix-connect",
            &sock,
            "--exchange",
        ],
    );
    assert_eq!(code, Some(0), "trace:\n{trace}");
    assert!(
        called(&trace, "socket", "AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC"),
        "{trace}"
    );
    assert!(called(&trace, "bind", &sock), "{trace}");
    assert!(called(&trace, "listen", ""), "{trace}");
    assert!(called(&trace, "accept4", "SOCK_CLOEXEC"), "{trace}");
    assert!(called(&trace, "connect", &sock), "{trace}");

    // SCM_RIGHTS: the descriptor rides in a control message.
    let sock = dir.path().join("scm.sock").display().to_string();
    let passed = dir.path().join("passed").display().to_string();
    std::fs::write(&passed, b"x").unwrap();
    let (code, trace) = traced_j3(
        &log,
        &[
            "scm-recv", &sock, "--", &fixture, "scm-send", &sock, &passed,
        ],
    );
    assert_eq!(code, Some(0), "trace:\n{trace}");
    assert!(called(&trace, "sendmsg", "SCM_RIGHTS"), "{trace}");
    assert!(called(&trace, "recvmsg", "SCM_RIGHTS"), "{trace}");

    // Unconnected UDP names its destination in `sendto` itself.
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = peer.local_addr().unwrap().port();
    let (code, trace) = traced_j3(
        &log,
        &["udp-sendto", &format!("127.0.0.1:{port}"), "--bytes", "5"],
    );
    assert_eq!(code, Some(0), "trace:\n{trace}");
    assert!(
        called(&trace, "sendto", &format!("sin_port=htons({port})")),
        "{trace}"
    );
    assert!(
        !called(&trace, "connect", ""),
        "unconnected means no connect:\n{trace}"
    );

    let (code, trace) = traced_j3(&log, &["unix-socketpair-dgram"]);
    assert_eq!(code, Some(0), "trace:\n{trace}");
    assert!(
        called(&trace, "socketpair", "AF_UNIX, SOCK_DGRAM, 0"),
        "{trace}"
    );
}

#[test]
fn a_refused_socket_address_produces_no_syscall_at_all() {
    if !strace_available() {
        harness::skip_or_fail("strace is not installed on this host");
        return;
    }
    let dir = TempDir::new("ouro-fixture-identity").unwrap();
    let log = dir.path().join("trace");
    let long = dir.path().join("s".repeat(200)).display().to_string();
    let (code, trace) = traced_j3(&log, &["unix-connect", &long]);
    assert_eq!(code, Some(3), "the refusal must fail the run");
    for name in ["socket", "connect"] {
        assert!(!called(&trace, name, ""), "{name} ran; trace:\n{trace}");
    }
}

#[test]
fn sandbox_exec_installs_each_layer_before_the_exec() {
    if !strace_available() {
        harness::skip_or_fail("strace is not installed on this host");
        return;
    }
    let dir = TempDir::new("ouro-fixture-identity").unwrap();
    let log = dir.path().join("trace");
    let fixture = harness::fixture_path().display().to_string();
    let (code, trace) = traced_j3(
        &log,
        &[
            "sandbox-exec",
            "--landlock-ro",
            "/",
            "--landlock-rw",
            &dir.path().display().to_string(),
            "--seccomp-errno",
            "mkdirat",
            "--",
            &fixture,
            "exit",
            "0",
        ],
    );
    assert_eq!(code, Some(0), "trace:\n{trace}");
    let order: Vec<&str> = [
        "prctl(PR_SET_NO_NEW_PRIVS, 1",
        "landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)",
        "landlock_create_ruleset({handled_access_fs=",
        "landlock_add_rule(",
        "landlock_restrict_self(",
        "seccomp(SECCOMP_SET_MODE_FILTER",
    ]
    .into_iter()
    .collect();
    let mut at = 0usize;
    for needle in &order {
        let found = trace[at..]
            .find(needle)
            .unwrap_or_else(|| panic!("`{needle}` missing or out of order; trace:\n{trace}"));
        at += found + needle.len();
    }
    // The exec of the command comes after every layer (the first execve is
    // strace starting the fixture itself).
    assert!(
        trace[at..].contains("execve("),
        "no exec after the layers:\n{trace}"
    );
    assert!(
        trace.contains("parent_fd="),
        "the packed path_beneath attribute decoded with its descriptor:\n{trace}"
    );
}
