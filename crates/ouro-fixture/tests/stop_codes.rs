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
