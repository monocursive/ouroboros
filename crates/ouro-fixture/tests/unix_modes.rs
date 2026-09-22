//! The AF_UNIX modes as real processes: listen/connect round trips (stream,
//! seqpacket, every address-length variant), the spawned-client form, the
//! abstract namespace, datagram socket creation, SCM_RIGHTS between two
//! fixture processes, and the host-side probe.
//!
//! Synchronisation is by protocol: a test waits for the listener's `listen`
//! line before starting a client, or lets the listener start the client
//! itself after it listens. Nothing sleeps. Linux-only features report
//! `unsupported` on macOS and are asserted to.

mod common;

use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, Instant};

use std::ffi::OsString;

use common::*;
#[cfg(target_os = "linux")]
use ouro_fixture::harness::ProbeKind;
use ouro_fixture::harness::UnixProbe;
use ouro_fixture::sockaddr::sun_path_capacity;

const LINUX: bool = cfg!(target_os = "linux");

fn accept_op() -> &'static str {
    if LINUX { "accept4" } else { "accept" }
}

// ------------------------------------------------------------ round trips

fn round_trip(seqpacket: bool) {
    let dir = Dir::new();
    let sock = dir.at_str("echo.sock");
    let mut listen_args = vec!["unix-listen", sock.as_str(), "--accept", "1"];
    let mut connect_args = vec!["unix-connect", sock.as_str(), "--exchange"];
    if seqpacket {
        listen_args.push("--seqpacket");
        connect_args.push("--seqpacket");
    }
    let mut listener = Live::start(&listen_args);
    let ready = listener.wait_for("listen");
    assert_eq!(ready["ret"], 0, "{ready}");

    let out = run(&connect_args);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(ops(&l), ["socket", "connect", "exchange"]);
    assert_eq!(
        l[0]["args"]["type"],
        if seqpacket {
            "SOCK_SEQPACKET"
        } else {
            "SOCK_STREAM"
        }
    );
    assert_eq!(l[1]["ret"], 0);
    assert_eq!(l[1]["args"]["abstract"], false);
    assert_eq!(l[2]["args"]["echoed"], true);

    let (code, seen) = listener.finish();
    assert_eq!(code, 0, "{seen:?}");
    assert_eq!(
        ops(&seen),
        ["socket", "bind", "listen", accept_op(), "echo"]
    );
    let echo = last(&seen, "echo");
    assert_eq!(echo["args"]["line_bytes"], l[2]["args"]["sent"]);
    assert!(
        echo["args"]["line"]
            .as_str()
            .unwrap()
            .starts_with("ouro-fixture exchange")
    );
}

#[test]
fn a_stream_listener_and_client_round_trip() {
    round_trip(false);
}

#[test]
fn a_seqpacket_round_trip_works_on_linux_and_is_unsupported_elsewhere() {
    if LINUX {
        round_trip(true);
        return;
    }
    let dir = Dir::new();
    for args in [
        vec![
            "unix-listen".to_string(),
            dir.at_str("s"),
            "--accept".into(),
            "1".into(),
            "--seqpacket".into(),
        ],
        vec![
            "unix-connect".to_string(),
            dir.at_str("s"),
            "--seqpacket".into(),
        ],
    ] {
        let out = run(&args);
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
        let l = lines(&out);
        assert_eq!(l.len(), 1, "{l:?}");
        assert_eq!(l[0]["op"], "socket");
        assert!(
            l[0]["args"]["unsupported"]
                .as_str()
                .unwrap()
                .contains("unsupported on this platform")
        );
    }
    assert!(!dir.path().join("s").exists(), "nothing was bound");
}

#[test]
fn every_address_length_variant_reaches_the_same_listener() {
    let dir = Dir::new();
    let sock = dir.at_str("len.sock");
    let mut listener = Live::start(&["unix-listen", &sock, "--accept", "3"]);
    listener.wait_for("listen");
    let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path) as u64;
    let path_len = sock.len() as u64;
    for (variant, expected) in [
        ("exact", offset + path_len),
        ("nul", offset + path_len + 1),
        ("full", size_of::<libc::sockaddr_un>() as u64),
    ] {
        let out = run(&["unix-connect", &sock, "--len", variant, "--exchange"]);
        assert_eq!(code(&out), 0, "{variant}: {}", describe(&out));
        let c = last(&lines(&out), "connect").clone();
        assert_eq!(c["args"]["len_variant"], variant);
        assert_eq!(c["args"]["addrlen"], expected, "{variant}");
    }
    let (code, seen) = listener.finish();
    assert_eq!(code, 0, "{seen:?}");
}

#[test]
fn a_listener_starts_its_client_only_once_it_listens() {
    let dir = Dir::new();
    let sock = dir.at_str("spawn.sock");
    let script = dir.at_str("client.json");
    std::fs::write(
        &script,
        serde_json::to_string(&[
            ["unix-connect", sock.as_str(), "--exchange"],
            ["unix-connect", sock.as_str(), "--exchange"],
        ])
        .unwrap(),
    )
    .unwrap();
    let fixture = fixture().into_os_string().into_string().unwrap();
    let out = run(&[
        "unix-listen",
        &sock,
        "--accept",
        "2",
        "--",
        &fixture,
        "script",
        &script,
    ]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    let names = ops(&l);
    let listen_at = names.iter().position(|o| o == "listen").unwrap();
    let exec_at = names.iter().position(|o| o == "execve").unwrap();
    assert!(
        listen_at < exec_at,
        "the client starts after the listen: {names:?}"
    );
    assert_eq!(names.iter().filter(|o| *o == "echo").count(), 2);
    assert_eq!(
        names.iter().filter(|o| *o == "exchange").count(),
        2,
        "the client's lines too"
    );
    let wait = last(&l, "wait");
    assert_eq!(wait["args"]["code"], 0);
    assert_eq!(wait["args"]["killed_at_deadline"], false);
}

#[test]
fn a_spawned_client_inherits_no_socket_of_the_listener() {
    // The listening socket is close-on-exec, so the client started after the
    // listen sees none of it: no private authority crosses the exec (X06).
    let dir = Dir::new();
    let sock = dir.at_str("x06.sock");
    let script = dir.at_str("client.json");
    std::fs::write(
        &script,
        serde_json::to_string(&[
            vec!["fds"],
            vec!["unix-connect", sock.as_str(), "--exchange"],
        ])
        .unwrap(),
    )
    .unwrap();
    let fixture = fixture().into_os_string().into_string().unwrap();
    let out = run(&[
        "unix-listen",
        &sock,
        "--accept",
        "1",
        "--",
        &fixture,
        "script",
        &script,
    ]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    let listener_fd = l[0]["ret"].as_i64().unwrap();
    assert_eq!(l[0]["op"], "socket");
    let fds = last(&l, "fds")["args"]["fds"].as_array().unwrap().clone();
    assert!(
        fds.iter().all(|f| f["kind"] != "socket"),
        "the client inherited a socket: {fds:?}"
    );
    assert!(
        fds.iter().all(|f| f["fd"] != listener_fd),
        "the listener's descriptor {listener_fd} reached the client: {fds:?}"
    );
}

#[test]
fn a_spawned_client_that_never_finishes_is_killed_at_the_deadline() {
    let dir = Dir::new();
    let sock = dir.at_str("hang.sock");
    let fixture = fixture().into_os_string().into_string().unwrap();
    let started = Instant::now();
    let out = run(&[
        "unix-listen",
        &sock,
        "--accept",
        "1",
        "--timeout-ms",
        "300",
        "--",
        &fixture,
        "sleep",
        "30000",
    ]);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the wait is bounded, not the child's 30 s"
    );
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(last(&l, accept_op())["errno"], "ETIMEDOUT");
    let wait = last(&l, "wait");
    assert_eq!(wait["args"]["killed_at_deadline"], true, "{wait}");
    assert_eq!(wait["args"]["signal"], libc::SIGKILL);
}

#[test]
fn a_listener_nobody_calls_stops_at_its_deadline() {
    let dir = Dir::new();
    let started = Instant::now();
    let out = run(&[
        "unix-listen",
        &dir.at_str("idle.sock"),
        "--accept",
        "1",
        "--timeout-ms",
        "200",
    ]);
    assert!(started.elapsed() < Duration::from_secs(10), "bounded");
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
    let a = last(&lines(&out), accept_op()).clone();
    assert_eq!(a["errno"], "ETIMEDOUT");
    assert_eq!(a["args"]["errno_source"], "fixture_deadline");
}

#[test]
fn a_bind_expected_to_fail_stops_there() {
    let dir = Dir::new();
    let taken = dir.at_str("taken");
    std::fs::write(&taken, b"x").unwrap();
    let out = run(&[
        "unix-listen",
        &taken,
        "--accept",
        "1",
        "--expect",
        "EADDRINUSE",
    ]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    assert_eq!(ops(&lines(&out)), ["socket", "bind"]);

    let out = run(&["unix-listen", &taken, "--accept", "1"]);
    assert_eq!(
        code(&out),
        EXIT_EXPECTATION_FAILED,
        "an unexpected bind failure fails"
    );
}

// ------------------------------------------------------------- refusals

#[test]
fn an_address_that_does_not_fit_is_refused_before_any_socket_exists() {
    // The unsafe boundary under `connect`/`bind`: the length handed to the
    // kernel never exceeds the live sockaddr. Try to exceed it.
    let dir = Dir::new();
    let long = dir.path().join("p".repeat(sun_path_capacity() + 8));
    for mode in [["unix-connect"].as_slice(), ["unix-listen"].as_slice()] {
        let mut args: Vec<OsString> = mode.iter().map(Into::into).collect();
        args.push(long.clone().into_os_string());
        if mode[0] == "unix-listen" {
            args.extend(["--accept".into(), "1".into()]);
        }
        let out = run(&args);
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
        let l = lines(&out);
        assert_eq!(l.len(), 1, "no socket line: {l:?}");
        assert_eq!(l[0]["args"]["refused"], "path_too_long");
    }
    // A path that fits exactly without its NUL is refused for `nul` and
    // accepted (the kernel answers) for `exact`.
    let base = dir.path().as_os_str().as_bytes().len() + 1;
    let fill = "q".repeat(sun_path_capacity().saturating_sub(base));
    let exact = dir.path().join(&fill);
    assert_eq!(exact.as_os_str().as_bytes().len(), sun_path_capacity());
    let args = |extra: &[&str]| -> Vec<OsString> {
        let mut v = vec![
            OsString::from("unix-connect"),
            exact.clone().into_os_string(),
        ];
        v.extend(extra.iter().map(OsString::from));
        v
    };
    let out = run(&args(&["--len", "nul"]));
    assert_eq!(
        last(&lines(&out), "connect")["args"]["refused"],
        "path_too_long"
    );
    let out = run(&args(&["--len", "exact", "--expect", "ENOENT"]));
    assert_eq!(code(&out), 0, "{}", describe(&out));
    assert_eq!(
        last(&lines(&out), "connect")["args"]["addrlen"],
        size_of::<libc::sockaddr_un>()
    );
}

#[test]
fn an_interior_nul_in_a_script_path_is_refused() {
    let dir = Dir::new();
    let script = dir.at_str("nul.json");
    let path = format!("{}\u{0}tail", dir.at_str("s"));
    std::fs::write(
        &script,
        serde_json::to_string(&[["unix-connect", path.as_str()]]).unwrap(),
    )
    .unwrap();
    let out = run(&["script", &script]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(l.len(), 1);
    assert_eq!(l[0]["args"]["refused"], "interior_nul");
}

#[test]
fn a_missing_socket_is_the_kernels_enoent() {
    let dir = Dir::new();
    let out = run(&[
        "unix-connect",
        &dir.at_str("absent.sock"),
        "--expect",
        "ENOENT",
    ]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    assert_eq!(last(&lines(&out), "connect")["errno"], "ENOENT");
}

// ----------------------------------------------------------------- probes

#[test]
fn the_probe_counts_a_pathname_connect_and_stays_zero_when_untouched() {
    let dir = Dir::new();
    let reached = UnixProbe::bind(&dir.path().join("reached.sock")).unwrap();
    let untouched = UnixProbe::bind(&dir.path().join("untouched.sock")).unwrap();
    let out = run(&["unix-connect", &dir.at_str("reached.sock")]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    assert_eq!(reached.stop(), 1);
    assert_eq!(untouched.stop(), 0);
}

#[test]
fn an_exchange_with_a_probe_ends_at_eof_not_at_a_hang() {
    let dir = Dir::new();
    let probe = UnixProbe::bind(&dir.path().join("mute.sock")).unwrap();
    let started = Instant::now();
    let out = run(&[
        "unix-connect",
        &dir.at_str("mute.sock"),
        "--exchange",
        "--timeout-ms",
        "5000",
    ]);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "EOF, not the deadline"
    );
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "nothing echoed");
    // The probe closes at once, so the client sees either EOF on its read or
    // EPIPE on its write, depending on which came first. Both are "no echo,
    // no hang"; neither is a deadline.
    let x = last(&lines(&out), "exchange").clone();
    assert_ne!(x["args"]["echoed"], true, "{x}");
    assert_ne!(x["args"]["errno_source"], "fixture_deadline", "{x}");
    assert!(
        x["args"]["echoed"] == false || x["errno"] == "EPIPE" || x["errno"] == "ECONNRESET",
        "{x}"
    );
    assert_eq!(probe.stop(), 1);
}

#[test]
fn the_abstract_namespace_works_on_linux_and_is_unsupported_elsewhere() {
    let name = format!("ouro-fixture-test-{}", std::process::id());
    #[cfg(not(target_os = "linux"))]
    {
        let out = run(&["unix-abstract-connect", &name]);
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
        let l = lines(&out);
        assert_eq!(ops(&l), ["connect"]);
        assert!(
            l[0]["args"]["unsupported"]
                .as_str()
                .unwrap()
                .contains("unsupported on this platform")
        );
    }
    #[cfg(target_os = "linux")]
    {
        let probe = UnixProbe::bind_abstract(name.as_bytes(), ProbeKind::Stream).unwrap();
        let out = run(&["unix-abstract-connect", &name]);
        assert_eq!(code(&out), 0, "{}", describe(&out));
        let c = last(&lines(&out), "connect").clone();
        assert_eq!(c["args"]["abstract"], true);
        assert_eq!(c["args"]["name"], name.as_str());
        assert_eq!(probe.stop(), 1);

        let out = run(&[
            "unix-abstract-connect",
            &format!("{name}-nobody"),
            "--expect",
            "ECONNREFUSED",
        ]);
        assert_eq!(code(&out), 0, "{}", describe(&out));

        let seq = UnixProbe::bind_abstract(format!("{name}-seq").as_bytes(), ProbeKind::Seqpacket)
            .unwrap();
        let out = run(&[
            "unix-abstract-connect",
            &format!("{name}-seq"),
            "--seqpacket",
        ]);
        assert_eq!(code(&out), 0, "{}", describe(&out));
        assert_eq!(seq.stop(), 1);
    }
}

// --------------------------------------------------------------- datagram

#[test]
fn datagram_sockets_and_pairs_are_created_outside_any_filter() {
    let out = run(&["unix-socket-dgram"]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(ops(&l), ["socket"]);
    assert_eq!(l[0]["args"]["type"], "SOCK_DGRAM");
    assert!(l[0]["ret"].as_i64().unwrap() >= 0);

    let out = run(&["unix-socketpair-dgram"]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(ops(&l), ["socketpair"]);
    let fds = l[0]["args"]["fds"].as_array().unwrap();
    assert_eq!(fds.len(), 2);
    assert_ne!(fds[0], fds[1]);

    for mode in ["unix-socket-dgram", "unix-socketpair-dgram"] {
        let out = run(&[mode, "--cloexec", "--nonblock"]);
        let l = lines(&out);
        if LINUX {
            assert_eq!(code(&out), 0, "{}", describe(&out));
            assert_eq!(
                l[0]["args"]["type_flags"],
                serde_json::json!(["SOCK_CLOEXEC", "SOCK_NONBLOCK"])
            );
            // SOCK_RAW is a datagram socket for AF_UNIX on Linux, which is
            // why a filter must mask the type before comparing it.
            let out = run(&[mode, "--raw"]);
            assert_eq!(code(&out), 0, "{}", describe(&out));
            assert_eq!(lines(&out)[0]["args"]["type"], "SOCK_RAW");
        } else {
            assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
            assert!(l[0]["args"]["unsupported"].is_string());
        }
    }
}

// ------------------------------------------------------------- SCM_RIGHTS

fn scm_round_trip(passed: &str, kind: &str) {
    let dir = Dir::new();
    let sock = dir.at_str("scm.sock");
    let mut receiver = Live::start(&["scm-recv", &sock]);
    receiver.wait_for("listen");
    let out = run(&["scm-send", &sock, passed]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(ops(&l), ["openat", "socket", "connect", "sendmsg"]);
    assert_eq!(last(&l, "sendmsg")["ret"], 1);

    let (code, seen) = receiver.finish();
    assert_eq!(code, 0, "{seen:?}");
    let r = last(&seen, "recvmsg");
    assert_eq!(r["args"]["fds_received"], 1);
    assert_eq!(r["args"]["ctrunc"], false);
    assert_eq!(last(&seen, "fstat")["args"]["kind"], kind);
}

#[test]
fn a_file_descriptor_crosses_between_two_fixture_processes() {
    let dir = Dir::new();
    let file = dir.at_str("passed.txt");
    std::fs::write(&file, b"payload").unwrap();
    scm_round_trip(&file, "regular");
}

#[test]
fn a_directory_descriptor_crosses_too() {
    let dir = Dir::new();
    scm_round_trip(&dir.at_str(""), "directory");
}

#[test]
fn scm_recv_can_start_the_sender_itself() {
    let dir = Dir::new();
    let sock = dir.at_str("self.sock");
    let file = dir.at_str("f");
    std::fs::write(&file, b"x").unwrap();
    let fixture = fixture().into_os_string().into_string().unwrap();
    let out = run(&["scm-recv", &sock, "--", &fixture, "scm-send", &sock, &file]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(last(&l, "recvmsg")["args"]["fds_received"], 1);
    assert_eq!(
        last(&l, "sendmsg")["ret"],
        1,
        "the child's line is in the same stream"
    );
    assert_eq!(last(&l, "wait")["args"]["code"], 0);
}

#[test]
fn scm_send_to_nothing_stops_at_the_connect() {
    let dir = Dir::new();
    let file = dir.at_str("f");
    std::fs::write(&file, b"x").unwrap();
    let out = run(&[
        "scm-send",
        &dir.at_str("absent.sock"),
        &file,
        "--expect",
        "ENOENT",
    ]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    assert_eq!(ops(&lines(&out)), ["openat", "socket", "connect"]);
}

#[test]
fn a_message_without_a_descriptor_fails_scm_recv() {
    let dir = Dir::new();
    let sock = dir.at_str("plain.sock");
    let mut receiver = Live::start(&["scm-recv", &sock]);
    receiver.wait_for("listen");
    let out = run(&["unix-connect", &sock, "--exchange", "--timeout-ms", "2000"]);
    // The receiver reads one message and closes without echoing.
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
    let (code, seen) = receiver.finish();
    assert_eq!(code, EXIT_EXPECTATION_FAILED, "{seen:?}");
    assert_eq!(last(&seen, "recvmsg")["args"]["fds_received"], 0);
    assert!(seen.iter().all(|v| v["op"] != "fstat"));
}
