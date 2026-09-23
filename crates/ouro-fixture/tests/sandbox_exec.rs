//! `sandbox-exec`: the inner sandbox a vendor agent puts around its tools.
//!
//! On Linux these run unprivileged, outside the jail, against the real
//! kernel: Landlock must deny a write outside the granted tree and allow one
//! inside it, TCP connect must be denied when asked, the seccomp filter must
//! turn a named syscall into EPERM and leave the rest alone, and any failed
//! step must stop the mode before it runs the command. Every "the command
//! ran" or "did not run" is checked against a file on disk, not only a line.
//!
//! On macOS the mode must report `unsupported` and run nothing.

mod common;

use std::path::Path;

use common::*;

fn fixture_str() -> String {
    fixture().into_os_string().into_string().unwrap()
}

#[test]
fn an_unknown_syscall_name_is_a_usage_error_before_anything_runs() {
    let dir = Dir::new();
    let marker = dir.at_str("marker");
    let out = run(&[
        "sandbox-exec",
        "--seccomp-errno",
        "not_a_syscall",
        "--",
        &fixture_str(),
        "open",
        &marker,
        "--create",
        "--write",
    ]);
    assert_eq!(code(&out), EXIT_USAGE, "{}", describe(&out));
    assert!(lines(&out).is_empty());
    assert!(!Path::new(&marker).exists());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn sandbox_exec_is_unsupported_here_and_runs_nothing() {
    let dir = Dir::new();
    let marker = dir.at_str("marker");
    let out = run(&[
        "sandbox-exec",
        "--",
        &fixture_str(),
        "open",
        &marker,
        "--create",
        "--write",
    ]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(ops(&l), ["sandbox-exec"]);
    assert!(
        l[0]["args"]["unsupported"]
            .as_str()
            .unwrap()
            .contains("unsupported on this platform")
    );
    assert!(
        !Path::new(&marker).exists(),
        "the command must not have run"
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// The Landlock ABI this kernel reports, through the mode's own probe.
    fn landlock_abi() -> i64 {
        let out = run(&[
            "sandbox-exec",
            "--landlock-ro",
            "/",
            "--",
            &fixture_str(),
            "exit",
            "0",
        ]);
        let l = lines(&out);
        let probe = l
            .iter()
            .find(|v| v["op"] == "landlock_create_ruleset" && v["args"]["purpose"] == "abi_probe")
            .unwrap_or_else(|| panic!("no ABI probe: {}", describe(&out)));
        probe["ret"].as_i64().unwrap()
    }

    #[test]
    fn landlock_denies_a_write_outside_the_grant_and_allows_one_inside() {
        let granted = Dir::new();
        let other = Dir::new();
        let inside = granted.at_str("inside");
        let outside = other.at_str("outside");

        let out = run(&[
            "sandbox-exec",
            "--landlock-ro",
            "/",
            "--landlock-rw",
            &granted.at_str(""),
            "--",
            &fixture_str(),
            "open",
            &inside,
            "--create",
            "--write",
        ]);
        assert_eq!(code(&out), 0, "{}", describe(&out));
        let l = lines(&out);
        let names = ops(&l);
        assert_eq!(
            names,
            [
                "prctl",
                "landlock_create_ruleset",
                "landlock_create_ruleset",
                "openat",
                "landlock_add_rule",
                "openat",
                "landlock_add_rule",
                "landlock_restrict_self",
                "openat",
            ],
            "{}",
            describe(&out)
        );
        assert!(l[1]["ret"].as_i64().unwrap() >= 1, "ABI probe: {}", l[1]);
        assert_eq!(l[4]["args"]["grant"], "rw");
        assert_eq!(l[6]["args"]["grant"], "ro");
        assert!(Path::new(&inside).is_file(), "the granted write happened");

        let out = run(&[
            "sandbox-exec",
            "--landlock-ro",
            "/",
            "--landlock-rw",
            &granted.at_str(""),
            "--",
            &fixture_str(),
            "open",
            &outside,
            "--create",
            "--write",
            "--expect",
            "EACCES",
        ]);
        assert_eq!(code(&out), 0, "{}", describe(&out));
        assert_eq!(last(&lines(&out), "openat")["errno"], "EACCES");
        assert!(
            !Path::new(&outside).exists(),
            "the denied write did not happen"
        );

        // Control: the same write without the sandbox succeeds, so the
        // denial above is the sandbox's and not the directory's.
        let out = run(&["open", &outside, "--create", "--write"]);
        assert_eq!(code(&out), 0, "{}", describe(&out));
        assert!(Path::new(&outside).is_file());
    }

    #[test]
    fn landlock_can_deny_every_tcp_connect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let abi = landlock_abi();
        let out = run(&[
            "sandbox-exec",
            "--landlock-deny-tcp",
            "--",
            &fixture_str(),
            "connect",
            &addr,
            "--expect",
            "EACCES",
        ]);
        if abi < 4 {
            assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
            let refusal = last(&lines(&out), "landlock_create_ruleset").clone();
            assert!(
                refusal["args"]["unsupported"]
                    .as_str()
                    .unwrap()
                    .contains("ABI 4")
            );
            assert!(
                lines(&out).iter().all(|v| v["op"] != "connect"),
                "nothing ran"
            );
            return;
        }
        assert_eq!(code(&out), 0, "{}", describe(&out));
        let l = lines(&out);
        let ruleset = l
            .iter()
            .find(|v| v["op"] == "landlock_create_ruleset" && v["args"]["abi"].is_i64())
            .unwrap();
        assert_eq!(
            ruleset["args"]["handled_access_fs"], "0x0",
            "no filesystem rule asked"
        );
        assert_eq!(ruleset["args"]["handled_access_net"], "0x2");
        assert_eq!(last(&l, "connect")["errno"], "EACCES");

        let out = run(&["connect", &addr]);
        assert_eq!(code(&out), 0, "control: the connect works unsandboxed");
    }

    #[test]
    fn a_named_syscall_returns_eperm_and_the_rest_still_work() {
        let dir = Dir::new();
        let blocked = dir.at_str("blocked-dir");
        let allowed = dir.at_str("allowed-file");
        let status_script = dir.at_str("steps.json");
        std::fs::write(
            &status_script,
            serde_json::to_string(&[
                vec!["mkdir", blocked.as_str(), "--expect", "EPERM"],
                vec!["open", allowed.as_str(), "--create", "--write"],
                vec!["status"],
            ])
            .unwrap(),
        )
        .unwrap();
        let out = run(&[
            "sandbox-exec",
            "--seccomp-errno",
            "mkdirat",
            "--seccomp-errno",
            "mkdir",
            "--",
            &fixture_str(),
            "script",
            &status_script,
        ]);
        assert_eq!(code(&out), 0, "{}", describe(&out));
        let l = lines(&out);
        assert_eq!(ops(&l)[..2], ["prctl", "seccomp"]);
        let seccomp = &l[1];
        assert_eq!(seccomp["ret"], 0);
        assert_eq!(seccomp["args"]["numbers"], serde_json::json!([258, 83]));
        assert_eq!(last(&l, "mkdirat")["errno"], "EPERM");
        assert!(!Path::new(&blocked).exists());
        assert!(
            Path::new(&allowed).is_file(),
            "an unnamed syscall still works"
        );
        let fields = &last(&l, "status")["args"]["fields"];
        assert_eq!(fields["NoNewPrivs"], "1");
        assert_eq!(fields["Seccomp"], "2", "filter mode");
    }

    #[test]
    fn a_step_that_fails_stops_before_the_command_runs() {
        let dir = Dir::new();
        let marker = dir.at_str("marker");
        let out = run(&[
            "sandbox-exec",
            "--landlock-rw",
            &dir.at_str("does-not-exist"),
            "--landlock-ro",
            "/",
            "--",
            &fixture_str(),
            "open",
            &marker,
            "--create",
            "--write",
        ]);
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
        let l = lines(&out);
        let failed = last(&l, "openat");
        assert_eq!(failed["errno"], "ENOENT");
        assert_eq!(failed["args"]["purpose"], "landlock_path_beneath");
        assert!(l.iter().all(|v| v["op"] != "landlock_restrict_self"));
        assert!(
            !Path::new(&marker).exists(),
            "the command must not have run"
        );
    }

    #[test]
    fn a_denied_execve_is_reported_not_hidden() {
        let out = run(&[
            "sandbox-exec",
            "--seccomp-errno",
            "execve",
            "--",
            &fixture_str(),
            "exit",
            "0",
        ]);
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
        let exec = last(&lines(&out), "execve").clone();
        assert_eq!(exec["errno"], "EPERM");
    }

    #[test]
    fn datagram_creation_is_refused_by_a_filter_that_names_it() {
        // The stock-host shape of the agent filter's datagram rule, done by
        // the fixture itself: `socket` named, so the creation is EPERM.
        let out = run(&[
            "sandbox-exec",
            "--seccomp-errno",
            "socket",
            "--",
            &fixture_str(),
            "unix-socket-dgram",
            "--expect",
            "EPERM",
        ]);
        assert_eq!(code(&out), 0, "{}", describe(&out));
        assert_eq!(last(&lines(&out), "socket")["errno"], "EPERM");
    }
}
