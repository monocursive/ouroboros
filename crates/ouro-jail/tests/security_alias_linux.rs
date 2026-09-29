//! Real private mount namespaces exercise the same coordinate guard used at launch.
#![cfg(target_os = "linux")]
mod common;
use ouro_jail::state::mount_alias::{alias_conflict, alias_containment};
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn guarded_aliases_are_detected_across_devices_and_below_mountpoints() {
    if !common::live() {
        return;
    }
    let backing = tempfile::tempdir().unwrap();
    let submount = tempfile::tempdir_in("/dev/shm").unwrap();
    std::fs::create_dir_all(backing.path().join("state/nested")).unwrap();
    // Let the already-supported backend establish the fixture mounts. The
    // tracee needs no mount authority or CAP_SYS_ADMIN after exec.
    let output = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(backing.path())
        .arg("/tmp/backing")
        .arg("--ro-bind")
        .arg(backing.path())
        .arg("/tmp/alias")
        .arg("--ro-bind")
        .arg(submount.path())
        .arg("/tmp/backing/state/nested")
        .arg("--ro-bind")
        .arg(submount.path())
        .arg("/tmp/visible/cache")
        .args(["--proc", "/proc", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "private_mount_alias_fixture",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "private mount namespace helper"]
fn private_mount_alias_fixture() {
    use std::os::unix::fs::MetadataExt as _;
    assert_ne!(
        std::fs::metadata("/tmp/backing/state").unwrap().dev(),
        std::fs::metadata("/tmp/backing/state/nested")
            .unwrap()
            .dev(),
        "fixture must cross filesystem devices"
    );
    let guard = Path::new("/tmp/backing/state");
    assert!(
        alias_conflict(&[PathBuf::from("/tmp/visible")], guard)
            .unwrap()
            .is_some()
    );
    assert!(
        alias_conflict(&[PathBuf::from("/tmp/alias/state")], guard)
            .unwrap()
            .is_some()
    );
    assert!(
        alias_containment(&[PathBuf::from("/tmp/alias/state")], guard)
            .unwrap()
            .is_some()
    );
    assert!(
        alias_containment(&[PathBuf::from("/tmp")], guard)
            .unwrap()
            .is_none()
    );
    assert!(
        alias_conflict(&[PathBuf::from("/tmp/visible/unrelated")], guard)
            .unwrap()
            .is_none()
    );
}
