//! How the fixture ends when a mode stops without its result: a usage error
//! refuses before anything runs, and an operation the fixture needed for
//! itself that failed is its own exit code, so a test can tell the two
//! apart.

use std::ffi::OsString;

mod common;
use common::{EXIT_USAGE, code, lines, run};

const EXIT_FIXTURE_FAILED: i32 = ouro_fixture::EXIT_FIXTURE_FAILED as i32;

#[test]
fn a_dirfd_the_fixture_cannot_open_is_its_own_failure_not_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let made = dir.path().join("made");
    let absent = dir.path().join("absent");
    let out = run(&[
        OsString::from("mkdir"),
        made.clone().into_os_string(),
        OsString::from("--via"),
        OsString::from("mkdirat"),
        OsString::from("--dirfd"),
        absent.into_os_string(),
    ]);
    assert_eq!(code(&out), EXIT_FIXTURE_FAILED, "{out:?}");
    // The open it attempted is on its line; the mkdirat never ran.
    let l = lines(&out);
    assert_eq!(l.len(), 1, "{l:?}");
    assert_eq!(l[0]["op"], "openat");
    assert_eq!(l[0]["args"]["purpose"], "dirfd");
    assert_eq!(l[0]["ret"], -1);
    assert!(!made.exists());
}

#[test]
fn a_dirfd_with_the_wrong_call_is_a_usage_error_before_anything_runs() {
    let dir = tempfile::tempdir().unwrap();
    let made = dir.path().join("made");
    let out = run(&[
        OsString::from("mkdir"),
        made.clone().into_os_string(),
        OsString::from("--via"),
        OsString::from("mkdir"),
        OsString::from("--dirfd"),
        dir.path().as_os_str().to_os_string(),
    ]);
    assert_eq!(code(&out), EXIT_USAGE, "{out:?}");
    assert!(lines(&out).is_empty(), "nothing ran");
    assert!(!made.exists());
}

#[test]
fn a_later_script_step_refused_when_it_runs_is_not_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let made = dir.path().join("made-by-step-0");
    let script = dir.path().join("script.json");
    std::fs::write(
        &script,
        serde_json::to_vec(&serde_json::json!([
            ["mkdir", made.to_str().unwrap()],
            ["raise", "NOTASIGNAL"]
        ]))
        .unwrap(),
    )
    .unwrap();
    let out = run(&[OsString::from("script"), script.into_os_string()]);
    // Step 0 acted, so the refusal of step 1 cannot claim nothing ran.
    assert!(made.is_dir());
    assert_eq!(lines(&out).len(), 1, "{out:?}");
    assert_eq!(code(&out), EXIT_FIXTURE_FAILED, "{out:?}");

    // The same refusal as the first step is a usage error: nothing ran.
    let first = dir.path().join("first.json");
    std::fs::write(&first, r#"[["raise", "NOTASIGNAL"]]"#).unwrap();
    let out = run(&[OsString::from("script"), first.into_os_string()]);
    assert_eq!(code(&out), EXIT_USAGE, "{out:?}");
    assert!(lines(&out).is_empty());
}

#[test]
fn a_perf_launch_result_that_cannot_be_written_is_the_fixtures_failure() {
    let dir = tempfile::tempdir().unwrap();
    // The launch runs; only the result file's directory is missing.
    let out = run(&[
        OsString::from("perf-launch"),
        OsString::from("--sample-ms"),
        OsString::from("0"),
        OsString::from("--out"),
        dir.path().join("absent/result.json").into_os_string(),
        OsString::from("--"),
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from("exit 0"),
    ]);
    assert_eq!(code(&out), EXIT_FIXTURE_FAILED, "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("cannot write"),
        "{out:?}"
    );
}

/// A fork the fixture needs for itself, refused by the kernel: with
/// `RLIMIT_NPROC` at 0 the fixture still starts (exec does not check the
/// limit) and its own `fork` fails with `EAGAIN`. Root is not bound by the
/// limit, so as root the forks succeed and the modes run.
#[test]
fn a_fork_the_fixture_cannot_make_is_its_own_failure() {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    for args in [
        &["exec", "--", "/bin/sh", "-c", "exit 0"][..],
        &["background", "0"],
    ] {
        let mut command = common::command(args);
        // SAFETY: the closure runs in the forked child before exec and calls
        // only `setrlimit`, which is async-signal-safe, on a live struct.
        unsafe {
            command.pre_exec(|| {
                let none = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_NPROC, &raw const none) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let out = command.output().expect("the fixture starts");
        if root {
            assert_eq!(code(&out), 0, "{args:?}: {out:?}");
        } else {
            assert_eq!(code(&out), EXIT_FIXTURE_FAILED, "{args:?}: {out:?}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("fork failed"),
                "{args:?}: {out:?}"
            );
        }
    }
}

/// A mode with two directory arguments checks both before opening either:
/// a second one the kernel cannot take is a usage error with nothing run,
/// not one that follows the first's reported open. (A NUL cannot be in a
/// process argument, so the step comes from a script.)
#[test]
fn every_dirfd_is_checked_before_any_is_opened() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("script.json");
    std::fs::write(
        &script,
        serde_json::to_vec(&serde_json::json!([[
            "rename",
            dir.path().join("a").to_str().unwrap(),
            dir.path().join("b").to_str().unwrap(),
            "--via",
            "renameat",
            "--dirfd",
            dir.path().to_str().unwrap(),
            "--dirfd2",
            "x\u{0}y"
        ]]))
        .unwrap(),
    )
    .unwrap();
    let out = run(&[OsString::from("script"), script.into_os_string()]);
    assert_eq!(code(&out), EXIT_USAGE, "{out:?}");
    assert!(lines(&out).is_empty(), "nothing ran: {:?}", lines(&out));
}
