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
    let backing = common::private_tempdir();
    // A second filesystem to mount below the guarded path: the check is
    // about crossing devices.
    let submount = match tempfile::tempdir_in("/dev/shm") {
        Ok(dir) => dir,
        Err(error) => {
            ouro_fixture::harness::skip_or_fail(&format!(
                "no tmpfs at /dev/shm to put a second device under the guard: {error}"
            ));
            return;
        }
    };
    std::fs::create_dir_all(backing.path().join("state/nested")).unwrap();
    // Let the already-supported backend establish the fixture mounts. The
    // tracee needs no mount authority or CAP_SYS_ADMIN after exec.
    let output = Command::new(common::bwrap_path())
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
        // The build directory may itself be under the hidden host /tmp.
        .arg("--ro-bind")
        .arg(std::env::current_exe().unwrap())
        .args([
            "/tmp/ouro-alias-test",
            "--proc",
            "/proc",
            "--",
            "/tmp/ouro-alias-test",
        ])
        .args(common::helper_args("private_mount_alias_fixture"))
        .env(common::HELPER_VAR, "private_mount_alias_fixture")
        .output()
        .unwrap();
    common::assert_helper_ran("private_mount_alias_fixture", &output);
}

#[test]
#[ignore = "private mount namespace helper"]
fn private_mount_alias_fixture() {
    use std::os::unix::fs::MetadataExt as _;
    if !common::running_helper("private_mount_alias_fixture") {
        return;
    }
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
