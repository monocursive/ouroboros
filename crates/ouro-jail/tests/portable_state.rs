//! Attempt state: durable replacement, the lease and the unsafe-path refusals.
//!
//! §7 requires create-new temporary file, write, file sync, atomic rename and
//! parent-directory sync, and says a successful rename alone is not a durable
//! acknowledgment. The failure-window test abandons the write before the rename
//! and checks that the previous file is intact: either the old or the new file
//! is there, never a half-written one.
//!
//! The lease test runs a second process, because `flock` is per open file
//! description and a same-process second lock would prove nothing about the
//! exclusivity a second supervisor would see.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

use ouro_jail::records::ErrorCode;
use ouro_jail::state::{self, AttemptDir, AttemptId, Lease, TempWrite};

mod common;

/// The environment variable that turns the child helper below into a prober.
const LOCK_PROBE: &str = "OURO_TEST_LOCK_PROBE";
/// The exit status the child uses when the lease is already held.
const BUSY: i32 = 3;

fn private_dir(root: &Path, name: &str) -> std::path::PathBuf {
    let path = root.join(name);
    std::fs::create_dir_all(&path).expect("a directory");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    path
}

#[test]
fn a_durable_replacement_leaves_the_old_file_when_it_is_abandoned() {
    let temp = common::private_tempdir();
    let data = private_dir(temp.path(), "data");
    let target = data.join("jail.json");
    state::replace_atomically(&target, b"first").expect("the first write");
    assert_eq!(std::fs::read(&target).expect("readable"), b"first");

    // Simulate a failure between the sync and the rename.
    let pending = TempWrite::create(&target, b"second").expect("a pending write");
    let pending_path = pending.temp_path().to_path_buf();
    assert!(
        pending_path.exists(),
        "the temporary file is a separate file"
    );
    assert_eq!(
        std::fs::read(&target).expect("readable"),
        b"first",
        "the target is untouched until the rename"
    );
    drop(pending);
    assert_eq!(
        std::fs::read(&target).expect("readable"),
        b"first",
        "an abandoned replacement leaves the old file"
    );
    assert!(
        !pending_path.exists(),
        "the abandoned temporary file does not accumulate"
    );

    state::replace_atomically(&target, b"second").expect("the second write");
    assert_eq!(std::fs::read(&target).expect("readable"), b"second");
    let mode = std::fs::metadata(&target)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "state files are private");
}

#[test]
fn the_lease_is_exclusive_across_processes() {
    let temp = common::private_tempdir();
    let data = private_dir(temp.path(), "data");
    let lock = data.join("jail.lock");

    let probe = || {
        let status = Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--ignored", "--exact", "lock_probe_child_helper"])
            .env(LOCK_PROBE, &lock)
            .status()
            .expect("the child runs");
        status.code().expect("the child exits normally")
    };

    let held = Lease::acquire(&lock)
        .expect("the lock file opens")
        .expect("the lease is free");
    assert_eq!(probe(), BUSY, "a second process cannot take a held lease");
    drop(held);
    assert_eq!(probe(), 0, "the lease is released when it is dropped");
}

/// The child half of [`the_lease_is_exclusive_across_processes`].
///
/// Ignored so it never runs in an ordinary pass; the parent invokes it by name
/// with `--ignored`.
#[test]
#[ignore = "child helper invoked by the_lease_is_exclusive_across_processes"]
fn lock_probe_child_helper() {
    let Some(path) = std::env::var_os(LOCK_PROBE) else {
        panic!("the helper needs {LOCK_PROBE}");
    };
    let code = match Lease::acquire(Path::new(&path)) {
        Ok(Some(_lease)) => 0,
        Ok(None) => BUSY,
        Err(_) => 4,
    };
    std::process::exit(code);
}

#[test]
fn a_symlinked_state_root_refuses() {
    let temp = common::private_tempdir();
    let real = private_dir(temp.path(), "real");
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("a symlink");
    let error = state::check_state_dir(&link).expect_err("a symlinked root refuses");
    assert_eq!(error.code, ErrorCode::UnsafeStatePath);
    assert_eq!(error.exit_code(), 125);
    // The target itself is fine, so the refusal is about the link, not the mode.
    state::check_state_dir(&real).expect("the real directory is private");
}

#[test]
fn a_group_or_world_accessible_state_root_refuses() {
    let temp = common::private_tempdir();
    for mode in [0o755u32, 0o770, 0o701] {
        let path = temp.path().join(format!("mode{mode:o}"));
        std::fs::create_dir(&path).expect("a directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("permissions");
        let error = state::check_state_dir(&path)
            .expect_err(&format!("mode {mode:o} is not a private state directory"));
        assert_eq!(error.code, ErrorCode::UnsafeStatePath);
        assert_eq!(error.exit_code(), 125);
    }
}

#[test]
fn a_file_where_a_state_directory_belongs_refuses() {
    let temp = common::private_tempdir();
    let path = temp.path().join("not-a-directory");
    std::fs::write(&path, b"x").expect("a file");
    let error = state::check_state_dir(&path).expect_err("a file is not a state directory");
    assert_eq!(error.code, ErrorCode::UnsafeStatePath);
}

#[test]
fn the_attempt_directory_has_the_layout_of_section_seven() {
    let temp = common::private_tempdir();
    let data = private_dir(temp.path(), "data");
    let id = AttemptId::generate();
    let dir = AttemptDir::new(&data, &id);
    dir.create(&data).expect("the attempt root is created");

    assert_eq!(dir.root(), data.join("attempts").join(id.as_str()));
    for (path, name) in [
        (dir.lock_path(), "jail.lock"),
        (dir.state_path(), "jail-state.json"),
        (dir.policy_path(), "policy.json"),
        (dir.receipt_path(), "jail.json"),
        (dir.trace_path(), "trace.ndjson"),
        (dir.vendor_state_path(), "vendor-state"),
        (dir.scratch_path(), "scratch"),
    ] {
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some(name)
        );
        assert_eq!(path.parent(), Some(dir.root()));
    }
    for path in [&data, &data.join("attempts"), &dir.root().to_path_buf()] {
        let mode = std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "{} is private", path.display());
    }
}

// J4-R: §7's claim is an exclusive publication of a complete file.
#[test]
fn j4_r02_an_exclusive_publication_never_replaces_an_existing_file() {
    let temp = common::private_tempdir();
    let data = private_dir(temp.path(), "data");
    let target = data.join("jail-state.json");
    assert_eq!(
        state::create_exclusively_at(state::Site::Claim, &target, b"{\"first\":true}").unwrap(),
        state::Published::Created
    );
    assert_eq!(
        state::create_exclusively_at(state::Site::Claim, &target, b"{\"second\":true}").unwrap(),
        state::Published::Exists,
        "a second claim is refused"
    );
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"{\"first\":true}",
        "the existing claim is untouched"
    );
    let leftover: Vec<String> = std::fs::read_dir(&data)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(
        leftover.is_empty(),
        "no temporary file is left: {leftover:?}"
    );
}
