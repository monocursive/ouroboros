//! J3 launch profiles, credentials and vendor-state cleanup, live on Linux.
#![cfg(target_os = "linux")]
//!
//! Two kinds of evidence, kept apart because §6.1 keeps them apart:
//!
//! - Mechanism: `tool` and `build` reject launch credentials (§6.1); `agent`
//!   stages them through `ouro-jail run` since J3 wave 2, proved end to end
//!   in `conformance_j3_agent.rs` (C01). The staging and bind mechanism is run
//!   directly: `credentials::stage` into a real vendor-state directory, then a
//!   real bubblewrap boundary built from the same `BwrapPlan` rows the
//!   platform renders, binding the staged descriptors. What the child reads,
//!   what it may write and what it can see are read back inside the boundary.
//! - End to end: `ouro-jail run --launch` with credential-free `tool`-jail
//!   fixture profiles, which create vendor state (`state_var`,
//!   `home_is_state`, `state_subdirs`), so its lifecycle, the environment
//!   mapping and cleanup after normal exit, refusal and interruption are
//!   proved through the binary.
//!
//! Every credential here is a fixture file this test writes; none is an
//! operator's. Rows: C01, C02, P04 (credential special files).

use std::ffi::OsString;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use ouro_fixture::harness::{self, Jail, Run};
use ouro_jail::cleanup;
use ouro_jail::credentials::{self, REASON_SOURCE_MUTABLE};
use ouro_jail::platform::linux::bwrap::{BwrapPlan, CredentialBind, VENDOR_STATE_INSIDE_PATH};
use ouro_jail::platform::linux::clock::Deadline;
use ouro_jail::platform::linux::exec::{self, FdMap};
use ouro_jail::policy::{CredentialDecl, LaunchSnapshot};
use ouro_jail::records::{ErrorCode, NativeString};
use ouro_jail::state::anchored::{Dir, Name};
use serde_json::Value;

mod common;

const VENDOR_FD: i32 = 16;
const BIND_FD: i32 = 20;

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn fixture_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn text(value: &str) -> NativeString {
    NativeString::Text(value.to_owned())
}

fn decl(id: &str, source: &Path, dest: &str, mode: &str) -> CredentialDecl {
    CredentialDecl {
        id: id.to_owned(),
        source: NativeString::from_bytes(source.as_os_str().as_encoded_bytes()).unwrap(),
        dest: text(dest),
        mode: mode.to_owned(),
    }
}

fn launch_of(credentials: Vec<CredentialDecl>) -> LaunchSnapshot {
    LaunchSnapshot {
        state_var: None,
        home_is_state: false,
        state_subdirs: vec![text("sessions")],
        credentials,
    }
}

/// A fresh attempt-like directory with an empty vendor-state beneath it and a
/// sibling the child must never see.
struct Staging {
    _root: tempfile::TempDir,
    root: PathBuf,
    attempt: Dir,
    vendor: Dir,
    creds: PathBuf,
}

impl Staging {
    fn new() -> Staging {
        let dir = common::private_tempdir();
        let root = dir.path().canonicalize().unwrap();
        let attempt_path = root.join("attempt");
        private_dir(&attempt_path);
        fixture_file(&attempt_path.join("jail-state.json"), b"{\"sibling\":true}");
        let creds = root.join("creds");
        private_dir(&creds);
        let attempt = Dir::open_trusted(&attempt_path).unwrap();
        let vendor = attempt
            .mkdir_at(&Name::new(b"vendor-state").unwrap(), 0o700)
            .unwrap();
        Staging {
            _root: dir,
            root,
            attempt,
            vendor,
            creds,
        }
    }

    fn vendor_path(&self) -> PathBuf {
        self.root.join("attempt/vendor-state")
    }
}

// ---------------------------------------------------------------------------
// Mechanism: staged objects in a real boundary
// ---------------------------------------------------------------------------

const INSIDE: &str = r#"
import errno, json, os, sys
state = sys.argv[1]
out = {}
def attempt(label, fn):
    try:
        fn()
        out[label] = "ok"
    except OSError as e:
        out[label] = errno.errorcode.get(e.errno, str(e.errno))
out["bind_read"] = open(state + "/conf/config.toml", "rb").read().decode()
attempt("bind_write", lambda: open(state + "/conf/config.toml", "ab").write(b"x"))
attempt("bind_unlink", lambda: os.unlink(state + "/conf/config.toml"))
attempt("bind_rename", lambda: os.rename(state + "/conf/config.toml", state + "/stolen"))
out["copy_read"] = open(state + "/auth.json", "rb").read().decode()
attempt("copy_write", lambda: open(state + "/auth.json", "wb").write(b"refreshed-inside"))
attempt("state_create", lambda: open(state + "/child-file", "wb").write(b"c"))
out["run_ouro"] = sorted(os.listdir("/run/ouro"))
out["state_parent"] = sorted(os.listdir(state + "/.."))
out["sibling_visible"] = os.path.exists(state + "/../jail-state.json")
rows = []
for line in open("/proc/self/mountinfo"):
    fields = line.split()
    if fields[4].startswith("/run/ouro/state"):
        rows.append([fields[4], "ro" if "ro" in fields[5].split(",") else "rw"])
out["mounts"] = sorted(rows)
os.symlink("/", state + "/root-link")
os.symlink("/etc/passwd", state + "/passwd-link")
print(json.dumps(out))
"#;

/// Runs `inner` in a real `tool`-shaped bubblewrap boundary with the staged
/// vendor state bound by descriptor at [`VENDOR_STATE_INSIDE_PATH`] and one
/// `bind_ro` view at `conf/config.toml`, rendered by the platform's own plan.
fn run_with_views(
    staging: &Staging,
    bind_fd: &std::os::fd::OwnedFd,
    workspace: &Path,
    inner: Vec<OsString>,
) -> exec::Captured {
    let scratch = common::private_tempdir();
    let mut plan = BwrapPlan::tool(
        workspace,
        scratch.path(),
        Path::new(env!("CARGO_BIN_EXE_ouro-jail")),
    );
    plan.bwrap = common::bwrap_path();
    plan.vendor_state = Some(staging.vendor_path());
    plan.vendor_state_fd = Some(VENDOR_FD);
    plan.credential_binds = vec![CredentialBind {
        fd: Some(BIND_FD),
        destination: Path::new(VENDOR_STATE_INSIDE_PATH).join("conf/config.toml"),
    }];
    plan.inner = inner;
    let rendered = plan.render().unwrap();
    assert!(
        !rendered.argv.iter().any(|arg| {
            arg.as_encoded_bytes() == staging.vendor_path().as_os_str().as_encoded_bytes()
        }),
        "vendor state is bound by descriptor, never by its host path"
    );
    let mut fds = FdMap::new();
    fds.add(staging.vendor.try_clone_fd().unwrap(), VENDOR_FD)
        .unwrap();
    fds.add(bind_fd.try_clone().unwrap(), BIND_FD).unwrap();
    let mut command = Command::new(&rendered.argv[0]);
    command.args(&rendered.argv[1..]);
    command.stdin(std::process::Stdio::null());
    fds.apply(&mut command);
    let captured = exec::run_captured(&mut command, Deadline::after(Duration::from_secs(30)))
        .expect("bubblewrap runs");
    drop(fds);
    assert!(!captured.timed_out);
    captured
}

fn python(script: &str, args: &[&str]) -> Vec<OsString> {
    let mut out = vec![
        OsString::from("/usr/bin/python3"),
        OsString::from("-c"),
        OsString::from(script),
    ];
    out.extend(args.iter().map(OsString::from));
    out
}

/// Stages `auth.json` (`copy_rw`) and `conf/config.toml` (`bind_ro`).
fn stage_two(staging: &Staging) -> (PathBuf, PathBuf, std::os::fd::OwnedFd) {
    let auth = staging.creds.join("auth.json");
    let config = staging.creds.join("config.toml");
    fixture_file(&auth, b"fixture-auth-original");
    fixture_file(&config, b"fixture-config-original");
    let launch = launch_of(vec![
        decl("auth", &auth, "auth.json", "copy_rw"),
        decl("config", &config, "conf/config.toml", "bind_ro"),
    ]);
    let mut staged = credentials::stage(&launch, staging.vendor.as_fd(), &[])
        .unwrap_or_else(|refusal| panic!("staging: {:?}", refusal.error));
    assert_eq!(staged.len(), 2);
    assert_eq!(staged[1].record.digest, None);
    assert_eq!(
        staged[1].record.digest_unavailable_reason.as_deref(),
        Some(REASON_SOURCE_MUTABLE),
        "a file on a writable filesystem is live, so its content is not established"
    );
    let (bind_fd, _dest) = staged[1].bind.take().expect("a bind handle");
    (auth, config, bind_fd)
}

#[test]
fn c01_bind_ro_is_the_exact_staged_object_read_only_and_copy_rw_is_a_private_copy() {
    if !common::live() {
        return;
    }
    let staging = Staging::new();
    let (auth, config, bind_fd) = stage_two(&staging);
    let original = {
        let metadata = std::fs::metadata(&config).unwrap();
        (metadata.dev(), metadata.ino())
    };
    // Move the staged source aside and put an impostor under its old name:
    // the view must be the object staging examined, not what the name names.
    let moved = staging.creds.join("config.moved");
    std::fs::rename(&config, &moved).unwrap();
    fixture_file(&config, b"fixture-config-IMPOSTOR");

    let workspace = common::private_tempdir();
    let captured = run_with_views(
        &staging,
        &bind_fd,
        workspace.path(),
        python(INSIDE, &[VENDOR_STATE_INSIDE_PATH]),
    );
    assert_eq!(captured.code(), Some(0), "stderr: {}", captured.stderr);
    let out: Value = serde_json::from_str(captured.stdout.trim()).unwrap();

    assert_eq!(out["bind_read"], "fixture-config-original", "{out}");
    assert_eq!(out["bind_write"], "EROFS");
    assert_ne!(
        out["bind_unlink"], "ok",
        "a read-only view cannot be removed"
    );
    assert_ne!(out["bind_rename"], "ok");
    assert_eq!(out["copy_read"], "fixture-auth-original");
    assert_eq!(out["copy_write"], "ok", "copy_rw is writable inside");
    assert_eq!(out["state_create"], "ok");
    assert_eq!(out["run_ouro"], serde_json::json!(["jail", "state"]));
    assert_eq!(
        out["state_parent"],
        serde_json::json!(["jail", "state"]),
        "the parent of vendor state is the sandbox's own /run/ouro"
    );
    assert_eq!(out["sibling_visible"], false);
    assert_eq!(
        out["mounts"],
        serde_json::json!([
            ["/run/ouro/state", "rw"],
            ["/run/ouro/state/conf/config.toml", "ro"]
        ])
    );

    // Nothing was written back: not through the view, not from the copy.
    assert_eq!(std::fs::read(&auth).unwrap(), b"fixture-auth-original");
    assert_eq!(std::fs::read(&moved).unwrap(), b"fixture-config-original");
    let moved_identity = {
        let metadata = std::fs::metadata(&moved).unwrap();
        (metadata.dev(), metadata.ino())
    };
    assert_eq!(moved_identity, original);
    assert_eq!(
        ouro_jail::state::anchored::fstat(bind_fd.as_fd())
            .unwrap()
            .identity(),
        original
    );
    assert_eq!(std::fs::read(&config).unwrap(), b"fixture-config-IMPOSTOR");
    assert_eq!(
        std::fs::read(staging.vendor_path().join("auth.json")).unwrap(),
        b"refreshed-inside"
    );

    // Cleanup removes the child's links themselves and the view's mount
    // point, which on the host is an empty file, never the source.
    let removal = cleanup::remove_tree_at(
        &staging.attempt,
        &Name::new(b"vendor-state").unwrap(),
        Some(staging.vendor.stat().unwrap().identity()),
        cleanup::Limits::DEFAULT,
    );
    assert!(removal.complete, "{removal:?}");
    assert!(cleanup::absent(&staging.vendor_path()));
    assert!(Path::new("/etc/passwd").exists());
    assert!(staging.root.join("attempt/jail-state.json").exists());
    assert_eq!(std::fs::read(&moved).unwrap(), b"fixture-config-original");
}

#[test]
fn c01_a_bind_ro_source_replaced_after_staging_is_never_bound() {
    if !common::live() {
        return;
    }
    // Measured on bubblewrap 0.11.1: `--ro-bind-fd` resolves the descriptor's
    // magic link to a path, binds it, then compares the mount with the
    // descriptor. A staged source that was unlinked and replaced therefore
    // has no path to resolve, and the boundary refuses to start: the
    // impostor is never bound and the target never runs.
    let staging = Staging::new();
    let (_auth, config, bind_fd) = stage_two(&staging);
    fixture_file(
        &staging.creds.join("config.new"),
        b"fixture-config-IMPOSTOR",
    );
    std::fs::rename(staging.creds.join("config.new"), &config).unwrap();
    let workspace = common::private_tempdir();
    let marker = workspace.path().join("ran");
    let captured = run_with_views(
        &staging,
        &bind_fd,
        workspace.path(),
        vec![
            OsString::from("/usr/bin/touch"),
            marker.clone().into_os_string(),
        ],
    );
    assert_ne!(captured.code(), Some(0), "stdout: {}", captured.stdout);
    assert!(
        !marker.exists(),
        "the target ran over a replaced credential"
    );
    assert!(!captured.stdout.contains("IMPOSTOR"));
}

/// Measured on bubblewrap 0.11.1 (`strace`): `--ro-bind-fd N` does not mount
/// through the descriptor. It `readlink`s `/proc/self/fd/N` into a path,
/// mounts that path, then compares `fstat(N)` with the mounted destination
/// and dies on a mismatch. This forces the race: `strace` delays the bind's
/// `mount(2)` while the test puts an impostor at the resolved path. The
/// boundary must refuse to start, so the target never reads the impostor.
#[test]
fn c01_bwrap_refuses_a_bind_ro_source_swapped_between_resolution_and_mount() {
    if !common::live() || !common::reference_host("strace-driven bubblewrap measurement") {
        return;
    }
    let strace = Path::new("/usr/bin/strace");
    if !strace.is_file() {
        harness::skip_or_fail("the reference host has no /usr/bin/strace");
        return;
    }
    let staging = Staging::new();
    let (_auth, config, bind_fd) = stage_two(&staging);
    let workspace = common::private_tempdir();
    let marker = workspace.path().join("read");

    // Render the platform's own plan, then run it under strace.
    let scratch = common::private_tempdir();
    let mut plan = BwrapPlan::tool(
        workspace.path(),
        scratch.path(),
        Path::new(env!("CARGO_BIN_EXE_ouro-jail")),
    );
    plan.bwrap = common::bwrap_path();
    plan.vendor_state = Some(staging.vendor_path());
    plan.vendor_state_fd = Some(VENDOR_FD);
    plan.credential_binds = vec![CredentialBind {
        fd: Some(BIND_FD),
        destination: Path::new(VENDOR_STATE_INSIDE_PATH).join("conf/config.toml"),
    }];
    plan.inner = vec![
        OsString::from("/usr/bin/cp"),
        OsString::from("/run/ouro/state/conf/config.toml"),
        marker.clone().into_os_string(),
    ];
    let rendered = plan.render().unwrap();

    // Which `mount(2)` is the view's bind: count them in an undelayed run.
    let count_run = |extra: &[&str]| {
        let trace = scratch.path().join("trace");
        let mut command = Command::new(strace);
        command
            .args(["-f", "-o"])
            .arg(&trace)
            .args(["-e", "trace=mount"])
            .args(extra)
            .args(&rendered.argv);
        command.stdin(std::process::Stdio::null());
        let mut fds = FdMap::new();
        fds.add(staging.vendor.try_clone_fd().unwrap(), VENDOR_FD)
            .unwrap();
        fds.add(bind_fd.try_clone().unwrap(), BIND_FD).unwrap();
        fds.apply(&mut command);
        let child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        drop(fds);
        (child, trace)
    };
    let (child, trace) = count_run(&[]);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&marker).unwrap(), b"fixture-config-original");
    std::fs::remove_file(&marker).unwrap();
    let text = std::fs::read_to_string(&trace).unwrap();
    let mounts: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("mount("))
        .collect();
    let index = mounts
        .iter()
        .position(|line| line.contains("config.toml\", \"/newroot/run/ouro/state/conf"))
        .expect("the view's bind appears in the trace")
        + 1;

    let (child, _) = count_run(&[
        "-e",
        &format!("inject=mount:delay_enter=3000000:when={index}"),
    ]);
    std::thread::sleep(Duration::from_millis(1500));
    std::fs::rename(&config, staging.creds.join("config.moved")).unwrap();
    fixture_file(&config, b"fixture-config-IMPOSTOR");
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "the boundary started over a swapped source"
    );
    assert!(stderr.contains("Race condition"), "{stderr}");
    assert!(!marker.exists(), "the target ran");
}

#[test]
fn p04_a_fifo_source_is_refused_without_ever_being_opened_for_io() {
    // A writer blocks in open(2) until some reader opens the FIFO. Staging
    // refuses it after an O_PATH open, which is not a reader: the writer must
    // still be blocked afterwards.
    let staging = Staging::new();
    let fifo = staging.creds.join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let opened = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&opened);
    let writer_path = fifo.clone();
    let writer = std::thread::spawn(move || {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&writer_path)
            .unwrap();
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        drop(file);
    });
    std::thread::sleep(Duration::from_millis(50));
    let launch = launch_of(vec![decl("pipe", &fifo, "pipe", "copy_rw")]);
    let credentials::StagingRefusal { error, staged } =
        credentials::stage(&launch, staging.vendor.as_fd(), &[])
            .expect_err("a FIFO source refuses");
    assert_eq!(error.code, ErrorCode::CredentialUnavailable);
    assert!(error.message.contains("a FIFO"), "{}", error.message);
    assert!(staged.is_empty());
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !opened.load(std::sync::atomic::Ordering::SeqCst),
        "staging opened the FIFO for reading"
    );
    // Release the writer: open the FIFO as a reader ourselves.
    let reader = std::fs::File::open(&fifo).unwrap();
    writer.join().unwrap();
    drop(reader);
    assert!(!staging.vendor_path().join("pipe").exists());
}

#[test]
fn p04_every_special_or_oversized_source_refuses_at_staging_on_this_host() {
    let staging = Staging::new();
    let socket = staging.creds.join("sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let link = staging.creds.join("link");
    std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();
    let directory = staging.creds.join("dir");
    private_dir(&directory);
    let big = staging.creds.join("big");
    let file = std::fs::File::create(&big).unwrap();
    file.set_len(credentials::COPY_BUDGET + 1).unwrap();
    std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
    for (label, source, mode, needle) in [
        (
            "device",
            Path::new("/dev/null"),
            "bind_ro",
            "a character device",
        ),
        ("socket", socket.as_path(), "copy_rw", "a socket"),
        ("symlink", link.as_path(), "bind_ro", "a symlink"),
        ("directory", directory.as_path(), "copy_rw", "a directory"),
        ("oversize", big.as_path(), "copy_rw", "budget"),
    ] {
        let launch = launch_of(vec![decl(label, source, label, mode)]);
        let credentials::StagingRefusal { error, staged } =
            credentials::stage(&launch, staging.vendor.as_fd(), &[]).expect_err(label);
        assert_eq!(error.code, ErrorCode::CredentialUnavailable, "{label}");
        assert!(error.message.contains(needle), "{label}: {}", error.message);
        assert!(
            !error.message.contains(&*staging.creds.to_string_lossy()),
            "{label}: the refusal names no path"
        );
        assert!(staged.is_empty());
        assert!(!staging.vendor_path().join(label).exists(), "{label}");
    }
    // The subdirectory was created before the first credential, 0700.
    let mode = std::fs::metadata(staging.vendor_path().join("sessions"))
        .unwrap()
        .mode();
    assert_eq!(mode & 0o7777, 0o700);
}

// ---------------------------------------------------------------------------
// End to end: `ouro-jail run --launch` with tool-jail fixture profiles
// ---------------------------------------------------------------------------

const PLAIN_PROFILE: &str = r#"
name = "fixture"
jail = "tool"
state_var = "FIX_HOME"
home_is_state = true
state_subdirs = ["sessions/a", "cache"]

[environment]
FIX_MODE = "fixture-mode-value"
FIX_CACHE = { state = "cache" }
"#;

fn write_profile(jail: &Jail, name: &str, text: &str) {
    let dir = jail.config_dir().join("launch");
    private_dir(&dir);
    fixture_file(&dir.join(format!("{name}.toml")), text.as_bytes());
}

fn launched(profile: &str, text: &str) -> (Jail, PathBuf) {
    let jail = Jail::new().unwrap();
    write_profile(&jail, profile, text);
    let workspace = jail.root().join("workspace");
    private_dir(&workspace);
    let jail = jail
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--launch")
        .arg(profile)
        .trace()
        .control();
    (jail, workspace)
}

fn attempt_of(run: &Run) -> PathBuf {
    let attempts = run.data_dir.join("attempts");
    let mut found: Vec<PathBuf> = std::fs::read_dir(&attempts)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
    found.pop().unwrap()
}

fn jail_json(attempt: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(attempt.join("jail.json")).unwrap()).unwrap()
}

fn state_json(attempt: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(attempt.join("jail-state.json")).unwrap()).unwrap()
}

const CHILD: &str = r#"
import json, os, stat, sys
env = os.environ
out = {k: env.get(k) for k in ["FIX_HOME", "HOME", "FIX_CACHE", "FIX_MODE"]}
home = env["FIX_HOME"]
out["subdir_mode"] = oct(stat.S_IMODE(os.stat(home + "/sessions/a").st_mode))
out["root_mode"] = oct(stat.S_IMODE(os.stat(home).st_mode))
out["run_ouro"] = sorted(os.listdir("/run/ouro"))
out["sibling_visible"] = os.path.exists(home + "/../jail-state.json")
open(home + "/sessions/a/state", "w").write("child state")
# Links out of vendor state: to a host path the child cannot even see, to a
# directory, to the workspace, and to the root.
os.symlink(sys.argv[1], home + "/host-file-link")
os.symlink(sys.argv[2], home + "/host-dir-link")
os.symlink(sys.argv[3], home + "/workspace-link")
os.symlink("/", home + "/root-link")
os.mkfifo(home + "/fifo")
deep = home + "/deep"
for _ in range(300):
    deep += "/d"
os.makedirs(deep)
os.makedirs(home + "/locked/inner")
open(home + "/locked/inner/f", "w").write("x")
os.chmod(home + "/locked/inner", 0)
os.chmod(home + "/locked", 0o100)
print(json.dumps(out))
"#;

#[test]
fn c02_a_normal_exit_cleans_vendor_state_and_planted_links_cannot_redirect_deletion() {
    if !common::live() {
        return;
    }
    let (jail, workspace) = launched("fixture", PLAIN_PROFILE);
    let outside = jail.root().join("outside");
    private_dir(&outside);
    fixture_file(&outside.join("precious"), b"host bytes");
    fixture_file(&workspace.join("keep.txt"), b"workspace bytes");
    let run = jail
        .target([
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from(CHILD),
            outside.join("precious").into_os_string(),
            outside.clone().into_os_string(),
            workspace.join("keep.txt").into_os_string(),
        ])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let child: Value = serde_json::from_str(run.stdout_text().trim()).unwrap();
    assert_eq!(child["FIX_HOME"], VENDOR_STATE_INSIDE_PATH);
    assert_eq!(child["HOME"], VENDOR_STATE_INSIDE_PATH);
    assert_eq!(child["FIX_CACHE"], "/run/ouro/state/cache");
    assert_eq!(child["FIX_MODE"], "fixture-mode-value");
    assert_eq!(child["subdir_mode"], "0o700");
    assert_eq!(child["root_mode"], "0o700");
    assert_eq!(child["run_ouro"], serde_json::json!(["jail", "state"]));
    assert_eq!(child["sibling_visible"], false);

    let attempt = attempt_of(&run);
    let receipt = jail_json(&attempt);
    assert_eq!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "complete", "{receipt:#}");
    assert_eq!(receipt["credentials"], serde_json::json!([]));
    let names: Vec<&str> = receipt["applied"]["environment_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    for name in ["FIX_HOME", "HOME", "FIX_CACHE", "FIX_MODE"] {
        assert!(names.contains(&name), "{name} in {names:?}");
    }
    assert!(
        !receipt.to_string().contains("fixture-mode-value"),
        "environment values never reach the receipt"
    );
    let mounts = receipt["applied"]["filesystem"]["mounts"]
        .as_array()
        .unwrap();
    assert!(
        mounts
            .iter()
            .any(|row| row["path"] == VENDOR_STATE_INSIDE_PATH && row["mode"] == "rw"),
        "{mounts:?}"
    );
    assert!(cleanup::absent(&attempt.join("vendor-state")));
    assert_eq!(
        std::fs::read(outside.join("precious")).unwrap(),
        b"host bytes"
    );
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(workspace.join("keep.txt")).unwrap(),
        b"workspace bytes"
    );
    assert_eq!(state_json(&attempt)["state_cleanup"], "complete");
}

/// Withholds the gate after `prepared`, and returns the finished run.
fn withheld(jail: Jail, marker: &Path) -> Run {
    let mut spawned = jail
        .gate()
        .receipt()
        .target([
            OsString::from("/usr/bin/touch"),
            marker.as_os_str().to_owned(),
        ])
        .spawn()
        .unwrap();
    spawned
        .owner()
        .await_prepared()
        .expect("a prepared message");
    let prepared = spawned.receipt_value().expect("a prepared receipt");
    assert_eq!(prepared["phase"], "prepared");
    assert_eq!(
        prepared["state_cleanup"], "pending",
        "vendor state exists now"
    );
    spawned.owner().withhold();
    let run = spawned.wait().unwrap();
    assert_eq!(run.code(), Some(125), "stderr: {}", run.stderr_text());
    assert!(!marker.exists(), "the target ran without a release");
    run
}

#[test]
fn c02_a_refusal_after_setup_with_a_verified_teardown_cleans_vendor_state() {
    if !common::live() {
        return;
    }
    // Observation off: the teardown's verification rests on the namespace
    // init and the cgroup alone, which this host establishes.
    let (jail, workspace) = launched("fixture", PLAIN_PROFILE);
    let run = withheld(jail.args(["--observe", "off"]), &workspace.join("ran"));
    let attempt = attempt_of(&run);
    let receipt = jail_json(&attempt);
    assert_eq!(receipt["phase"], "refused");
    assert_eq!(receipt["lifetime"]["tree_empty"], true, "{receipt:#}");
    assert_eq!(receipt["state_cleanup"], "complete", "{receipt:#}");
    assert!(cleanup::absent(&attempt.join("vendor-state")));
    assert_eq!(state_json(&attempt)["state_cleanup"], "complete");
}

#[test]
fn c02_a_withheld_gate_with_observation_on_verifies_the_teardown_and_cleans() {
    if !common::live() {
        return;
    }
    // Observation on: the observer is attached to the blocked launcher when
    // the gate closes. The teardown is verified by the init's pidfd, the
    // reaped backend and watcher, the unpopulated leaf and the observer's own
    // account; before J3 it was read once from `/proc` and raced the reaping
    // of the init's zombie, so this ran several times to show it no longer
    // depends on that timing.
    for round in 0..5 {
        let (jail, workspace) = launched("fixture", PLAIN_PROFILE);
        let run = withheld(jail, &workspace.join("ran"));
        let attempt = attempt_of(&run);
        let receipt = jail_json(&attempt);
        assert_eq!(receipt["phase"], "refused", "round {round}");
        assert_eq!(receipt["policy"]["observe"], "on");
        assert_eq!(
            receipt["lifetime"]["tree_empty"], true,
            "round {round}: {receipt:#}"
        );
        assert_eq!(
            receipt["lifetime"]["integrity"], "verified",
            "round {round}"
        );
        assert!(
            receipt["lifetime"]["verified_at"].is_string(),
            "round {round}"
        );
        assert_eq!(
            receipt["state_cleanup"], "complete",
            "round {round}: {receipt:#}"
        );
        assert!(
            cleanup::absent(&attempt.join("vendor-state")),
            "round {round}"
        );
        assert_eq!(state_json(&attempt)["state_cleanup"], "complete");
        // The placeholders for the absent `.git` and `.ouroboros` literals
        // went with the verified teardown; nothing is left in the workspace.
        let left: Vec<_> = std::fs::read_dir(&workspace)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "round {round}: {left:?}");
    }
}

#[test]
fn c02_a_release_failure_after_the_backend_died_verifies_the_teardown_and_cleans() {
    if !common::live() {
        return;
    }
    // Deterministic release failure: kill the backend while the launcher is
    // blocked, wait until it has exited, then send a valid release. The
    // platform finds its lifetime resources gone and refuses the release;
    // the teardown it runs is verified, and the refused receipt says so.
    let (jail, workspace) = launched("fixture", PLAIN_PROFILE);
    let marker = workspace.join("ran");
    let mut spawned = jail
        .gate()
        .receipt()
        .target([
            OsString::from("/usr/bin/touch"),
            marker.as_os_str().to_owned(),
        ])
        .spawn()
        .unwrap();
    let prepared = spawned
        .owner()
        .await_prepared()
        .expect("a prepared message");
    let receipt = spawned.receipt_value().expect("a prepared receipt");
    assert_eq!(
        receipt["state_cleanup"], "pending",
        "vendor state exists now"
    );
    let bwrap = receipt["lifetime"]["native"]["details"]["bwrap_pid"]
        .as_i64()
        .expect("the backend pid is recorded");
    assert!(
        Command::new("kill")
            .args(["-KILL", &bwrap.to_string()])
            .status()
            .unwrap()
            .success()
    );
    // Wait until both the backend and the outside watcher have exited: the
    // platform checks the watcher, which exits only after it sees the
    // backend's death. Releasing earlier races that, and a release that wins
    // the race is an ordinary (unknown-outcome) run, not this refusal.
    let watcher = receipt["lifetime"]["native"]["details"]["watcher_pid"]
        .as_i64()
        .expect("the watcher pid is recorded");
    let exited = |pid: i64| {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat.rsplit(')').next().map(|rest| rest.trim().to_owned()))
            .is_none_or(|rest| rest.starts_with('Z'))
    };
    let gone = std::time::Instant::now() + Duration::from_secs(5);
    while !(exited(bwrap) && exited(watcher)) {
        assert!(std::time::Instant::now() < gone, "the backend did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    spawned
        .owner()
        .release(
            &harness::gate::Release::Valid,
            prepared["attempt_id"].as_str().unwrap(),
            receipt["policy"]["digest"].as_str().unwrap(),
        )
        .unwrap();
    let run = spawned.wait().unwrap();
    let attempt = attempt_of(&run);
    let receipt = jail_json(&attempt);
    assert_eq!(
        run.code(),
        Some(125),
        "stderr: {}\ncontrol: {:?}\nreceipt: {receipt:#}",
        run.stderr_text(),
        run.control_messages()
    );
    assert!(!marker.exists(), "the target never ran");
    assert_eq!(receipt["phase"], "refused");
    assert_eq!(receipt["exec_observed"], false);
    assert_eq!(
        receipt["outcome"]["error"]["code"], "backend_unavailable",
        "{receipt:#}"
    );
    assert_eq!(receipt["lifetime"]["tree_empty"], true, "{receipt:#}");
    assert_eq!(receipt["lifetime"]["integrity"], "verified");
    assert_eq!(receipt["state_cleanup"], "complete", "{receipt:#}");
    assert!(cleanup::absent(&attempt.join("vendor-state")));
}

#[test]
fn c02_a_refusal_before_any_boundary_cleans_vendor_state() {
    if !common::live() {
        return;
    }
    // §8.3: a socket on stdout refuses in preparation, before any boundary
    // exists and after vendor state was created and registered.
    let jail = Jail::new().unwrap();
    write_profile(&jail, "fixture", PLAIN_PROFILE);
    let workspace = jail.root().join("workspace");
    private_dir(&workspace);
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let output = Command::new(harness::jail_path())
        .args(["run", "--launch", "fixture", "--workspace"])
        .arg(&workspace)
        .args(["--", "/usr/bin/true"])
        .env("OURO_DATA_DIR", jail.data_dir())
        .env("OURO_CONFIG_DIR", jail.config_dir())
        .stdout(std::process::Stdio::from(std::os::fd::OwnedFd::from(
            theirs,
        )))
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    drop(ours);
    assert_eq!(
        output.status.code(),
        Some(125),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let attempts: Vec<PathBuf> = std::fs::read_dir(jail.data_dir().join("attempts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(attempts.len(), 1);
    let receipt = jail_json(&attempts[0]);
    assert_eq!(receipt["phase"], "refused");
    assert_eq!(receipt["lifetime"]["boundary"], "pending", "{receipt:#}");
    assert_eq!(receipt["state_cleanup"], "complete", "{receipt:#}");
    assert!(cleanup::absent(&attempts[0].join("vendor-state")));
    assert_eq!(state_json(&attempts[0])["state_cleanup"], "complete");
}

#[test]
fn c02_an_interrupted_cleanup_stays_pending_and_gc_resumes_it() {
    if !common::live() {
        return;
    }
    let (jail, _workspace) = launched("fixture", PLAIN_PROFILE);
    // More entries than one cleanup pass visits. Observation is off: this is
    // about cleanup, and a hundred thousand traced opens are not.
    let run = jail
        .args(["--observe", "off"])
        .target([
            "/usr/bin/python3",
            "-c",
            "import os\nd = os.environ['FIX_HOME'] + '/many'\nos.mkdir(d)\n\
             [open(d + '/' + str(i), 'w').close() for i in range(100001)]",
        ])
        .timeout(Duration::from_secs(300))
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let attempt = attempt_of(&run);
    let receipt = jail_json(&attempt);
    assert_eq!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "pending");
    assert_eq!(receipt["cleanup_error"], cleanup::REASON_BUDGET);
    assert!(attempt.join("vendor-state").exists());
    let revision = receipt["revision"].as_u64().unwrap();

    let gc = Command::new(harness::jail_path())
        .args(["gc", "--json"])
        .env("OURO_DATA_DIR", &run.data_dir)
        .env("OURO_CONFIG_DIR", run.data_dir.with_file_name("config"))
        .output()
        .unwrap();
    assert!(
        gc.status.success(),
        "{}",
        String::from_utf8_lossy(&gc.stderr)
    );
    let report: Value = serde_json::from_slice(&gc.stdout).unwrap();
    assert_eq!(
        report["entries"][0]["action"], "removed_vendor_state",
        "{report}"
    );
    assert!(cleanup::absent(&attempt.join("vendor-state")));
    let receipt = jail_json(&attempt);
    assert_eq!(receipt["state_cleanup"], "complete");
    assert_eq!(receipt["revision"].as_u64().unwrap(), revision + 1);
    assert_eq!(state_json(&attempt)["state_cleanup"], "complete");
}

#[test]
fn c01_launch_refusals_happen_before_any_attempt_exists() {
    if !common::live() {
        return;
    }
    let credential = common::private_tempdir();
    let source = credential.path().canonicalize().unwrap().join("token");
    fixture_file(&source, b"fixture-token");
    for (label, text) in [
        (
            "tool with credentials",
            format!(
                "name = \"bad\"\njail = \"tool\"\n[credentials.t]\nsource = \"{}\"\n\
                 dest = \"t\"\nmode = \"copy_rw\"\n",
                source.display()
            ),
        ),
        (
            "LD_PRELOAD",
            "name = \"bad\"\njail = \"tool\"\n[environment]\nLD_PRELOAD = \"/x.so\"\n".to_owned(),
        ),
        (
            "DYLD_INSERT_LIBRARIES",
            "name = \"bad\"\njail = \"tool\"\nstate_var = \"DYLD_INSERT_LIBRARIES\"\n".to_owned(),
        ),
        (
            "unsafe state_subdirs",
            "name = \"bad\"\njail = \"tool\"\nstate_subdirs = [\"../out\"]\n".to_owned(),
        ),
    ] {
        let (jail, _) = launched("bad", &text);
        let run = jail.target(["/usr/bin/true"]).run().unwrap();
        assert_eq!(run.code(), Some(2), "{label}: {}", run.stderr_text());
        assert!(
            !run.data_dir.join("attempts").exists()
                || std::fs::read_dir(run.data_dir.join("attempts"))
                    .unwrap()
                    .count()
                    == 0,
            "{label}: no attempt was allocated"
        );
    }
    assert_eq!(std::fs::read(&source).unwrap(), b"fixture-token");
}

// J3-agent begin: wave 2 wired `agent`; the launch profile now runs as it does
#[test]
fn an_agent_launch_profile_runs_exactly_as_agent_does_on_this_host() {
    if !common::live() {
        return;
    }
    let credential = common::private_tempdir();
    let source = credential.path().canonicalize().unwrap().join("token");
    fixture_file(&source, b"fixture-token");
    let profile = format!(
        "name = \"agentish\"\njail = \"agent\"\nstate_var = \"A_HOME\"\n\
         [credentials.t]\nsource = \"{}\"\ndest = \"t\"\nmode = \"copy_rw\"\n",
        source.display()
    );
    let (jail, _) = launched("agentish", &profile);
    let launched_run = jail.target(["/usr/bin/true"]).run().unwrap();

    let plain = Jail::new().unwrap();
    let workspace = plain.root().join("workspace");
    private_dir(&workspace);
    let plain_run = plain
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--profile")
        .arg("agent")
        .target(["/usr/bin/true"])
        .run()
        .unwrap();

    assert_eq!(
        launched_run.code(),
        Some(0),
        "{}",
        launched_run.stderr_text()
    );
    assert_eq!(launched_run.code(), plain_run.code());
    let launched_receipt = jail_json(&attempt_of(&launched_run));
    let plain_receipt = jail_json(&attempt_of(&plain_run));
    assert_eq!(launched_receipt["phase"], "settled");
    assert_eq!(plain_receipt["phase"], "settled");
    assert_eq!(launched_receipt["credentials"][0]["id"], "t");
    assert_eq!(launched_receipt["credentials"][0]["mode"], "copy_rw");
    assert_eq!(launched_receipt["state_cleanup"], "complete");
    assert!(cleanup::absent(
        &attempt_of(&launched_run).join("vendor-state")
    ));
    assert_eq!(std::fs::read(&source).unwrap(), b"fixture-token");
}
// J3-agent end

// ---------------------------------------------------------------------------
// J3 review findings, adopted as live tests
// ---------------------------------------------------------------------------

/// Runs one `#[ignore]`d test of this binary inside a single bubblewrap
/// layer (a user and PID namespace, no host configuration), with `binds`
/// added after the runtime roots. Returns the combined output; panics with it
/// when the inner test failed.
fn run_inner_test(name: &str, binds: &[(&str, &Path, &str)], env: &[(&str, &Path)]) -> String {
    let exe = std::env::current_exe().unwrap();
    let mut command = Command::new(common::bwrap_path());
    command.args(["--unshare-user", "--unshare-pid", "--die-with-parent"]);
    for root in ouro_jail::platform::linux::bwrap::RUNTIME_ROOTS
        .iter()
        .filter_map(|path| ouro_jail::platform::linux::fs::resolve_runtime_root(Path::new(path)))
    {
        match root {
            ouro_jail::platform::linux::fs::RootSpec::RoBind(path) => {
                command.arg("--ro-bind").arg(&path).arg(&path);
            }
            ouro_jail::platform::linux::fs::RootSpec::Symlink { path, target } => {
                command.arg("--symlink").arg(&target).arg(&path);
            }
        }
    }
    command.args(["--proc", "/proc", "--dev", "/dev"]);
    for (flag, source, destination) in binds {
        command.arg(flag).arg(source).arg(destination);
    }
    command.arg("--ro-bind").arg(&exe).arg("/testbin");
    for (key, value) in env {
        command.env(key, value);
    }
    command.args([
        "/testbin",
        "--ignored",
        "--exact",
        name,
        "--nocapture",
        "--test-threads=1",
    ]);
    let output = command.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "{name} failed inside bubblewrap:\n{text}"
    );
    assert!(text.contains("1 passed"), "{name} did not run:\n{text}");
    text
}

#[test]
#[ignore = "runs inside bubblewrap from m1_a_read_only_bind_of_a_writable_filesystem_gets_no_digest"]
fn m1_inner_bind_ro_digest_on_a_read_only_bind_of_a_writable_filesystem() {
    // Reviewer's R4: `/r` is a read-only bind of the writable directory that
    // is also mounted writable at `/w`. ST_RDONLY holds at `/r`, yet the
    // inode changes through `/w`, so no digest may be recorded.
    let vendor = Dir::open_trusted(Path::new("/vs")).unwrap();
    let launch = LaunchSnapshot {
        state_var: None,
        home_is_state: false,
        state_subdirs: Vec::new(),
        credentials: vec![CredentialDecl {
            id: "cfg".into(),
            source: text("/r/cfg.toml"),
            dest: text("cfg.toml"),
            mode: "bind_ro".into(),
        }],
    };
    let staged = credentials::stage(&launch, vendor.as_fd(), &[])
        .unwrap_or_else(|refusal| panic!("staging refused: {:?}", refusal.error));
    let record = staged[0].record.clone();
    println!("receipt row: {record:?}");
    assert_eq!(record.digest, None);
    assert_eq!(
        record.digest_unavailable_reason.as_deref(),
        Some("source_mutable")
    );
    std::fs::write("/w/cfg.toml", b"content written after staging").unwrap();
}

#[test]
fn m1_a_read_only_bind_of_a_writable_filesystem_gets_no_digest() {
    if !common::live() {
        return;
    }
    let root = common::private_tempdir();
    let base = root.path().canonicalize().unwrap();
    private_dir(&base.join("src"));
    private_dir(&base.join("vs"));
    fixture_file(&base.join("src/cfg.toml"), b"fixture config at staging");
    let output = run_inner_test(
        "m1_inner_bind_ro_digest_on_a_read_only_bind_of_a_writable_filesystem",
        &[
            ("--bind", &base.join("src"), "/w"),
            ("--ro-bind", &base.join("src"), "/r"),
            ("--bind", &base.join("vs"), "/vs"),
        ],
        &[],
    );
    assert!(output.contains("source_mutable"), "{output}");
}

#[test]
#[ignore = "runs inside bubblewrap from foreign_owners_and_same_device_mounts_are_refused"]
fn foreign_inner_owner_and_mount_checks() {
    use ouro_jail::state::anchored::fstat;
    // Inside an unprivileged user namespace, anything root owns shows as the
    // overflow uid: a foreign owner a same-UID test can actually produce.
    let passwd = std::fs::File::open("/own/rootfile").unwrap();
    assert_ne!(
        fstat(passwd.as_fd()).unwrap().uid,
        ouro_jail::state::effective_uid(),
        "the bound root-owned file must look foreign here"
    );
    let reasons = |source: &str| {
        let launch = LaunchSnapshot {
            state_var: None,
            home_is_state: false,
            state_subdirs: Vec::new(),
            credentials: vec![CredentialDecl {
                id: "c".into(),
                source: text(source),
                dest: text("c"),
                mode: "copy_rw".into(),
            }],
        };
        ouro_jail::credentials::inspect(&launch, &[])[0].reason_code
    };
    // RM13: the file itself is foreign, its directory is ours.
    assert_eq!(reasons("/own/rootfile"), "source_foreign_owner");
    // RM14: a directory on the walk is foreign.
    assert_eq!(reasons("/etc/passwd"), "source_path_foreign_owner");

    let own = Dir::open_trusted(Path::new("/own")).unwrap();
    // RM04: a foreign-owned root is refused as foreign, before anything else.
    let removal = cleanup::remove_tree_at(
        &own,
        &Name::new(b"foreigndir").unwrap(),
        None,
        cleanup::Limits::DEFAULT,
    );
    assert_eq!(
        removal.reason.as_deref(),
        Some("managed_directory_foreign_owner"),
        "{removal:?}"
    );
    // RM53: a bind mount of the same filesystem inside the tree has the same
    // st_dev; only statx's mount-root attribute sees it, and nothing beneath
    // it may be removed.
    let removal = cleanup::remove_tree_at(
        &own,
        &Name::new(b"tree").unwrap(),
        None,
        cleanup::Limits::DEFAULT,
    );
    assert_eq!(
        removal.reason.as_deref(),
        Some("mount_crossing_refused"),
        "{removal:?}"
    );
    assert!(Path::new("/own/tree/mnt/keep").exists());
    println!("foreign and mount checks held");
}

#[test]
fn foreign_owners_and_same_device_mounts_are_refused() {
    if !common::live() {
        return;
    }
    let root = common::private_tempdir();
    let base = root.path().canonicalize().unwrap();
    let own = base.join("own");
    private_dir(&own);
    fixture_file(&own.join("rootfile"), b"");
    private_dir(&own.join("foreigndir"));
    private_dir(&own.join("tree/mnt"));
    let other = base.join("other");
    private_dir(&other);
    fixture_file(&other.join("keep"), b"not beneath the tree");
    let output = run_inner_test(
        "foreign_inner_owner_and_mount_checks",
        &[
            ("--bind", &own, "/own"),
            ("--ro-bind", Path::new("/etc/passwd"), "/own/rootfile"),
            ("--ro-bind", Path::new("/usr/share"), "/own/foreigndir"),
            ("--ro-bind", Path::new("/etc"), "/etc"),
            ("--bind", &other, "/own/tree/mnt"),
        ],
        &[],
    );
    assert!(output.contains("foreign and mount checks held"), "{output}");
    assert_eq!(
        std::fs::read(other.join("keep")).unwrap(),
        b"not beneath the tree"
    );
}

#[test]
fn h1_a_read_only_chain_past_the_hoist_depth_no_longer_outlives_the_attempt() {
    if !common::live() {
        return;
    }
    // Reviewer's live L1: a 140-deep chain of 0500 directories holding a copy
    // stopped every cleanup pass at the hoist with EACCES.
    let (jail, workspace) = launched("fixture", PLAIN_PROFILE);
    let trap = workspace.join("trap.py");
    std::fs::write(
        &trap,
        "import os\nh = os.environ['FIX_HOME']\ncur = h + '/trap'\nos.mkdir(cur)\ndirs = []\n\
         for _ in range(140):\n    cur += '/d'\n    os.mkdir(cur)\n    dirs.append(cur)\n\
         open(cur + '/copy-of-a-credential', 'w').write('fixture bytes')\n\
         for d in reversed(dirs):\n    os.chmod(d, 0o500)\n",
    )
    .unwrap();
    let run = jail
        .args(["--observe", "off"])
        .target([OsString::from("/usr/bin/python3"), trap.into_os_string()])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let attempt = attempt_of(&run);
    let receipt = jail_json(&attempt);
    assert_eq!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "complete", "{receipt:#}");
    assert!(cleanup::absent(&attempt.join("vendor-state")));
}

#[test]
fn a_non_launch_exec_error_verifies_its_teardown() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    private_dir(&workspace);
    let run = jail
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .target([workspace.join("no-such-binary").into_os_string()])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(125), "stderr: {}", run.stderr_text());
    let attempt = attempt_of(&run);
    let receipt = jail_json(&attempt);
    assert_eq!(receipt["phase"], "refused");
    assert_eq!(receipt["outcome"]["kind"], "exec_error");
    assert_eq!(receipt["lifetime"]["tree_empty"], true, "{receipt:#}");
    assert_eq!(receipt["lifetime"]["integrity"], "verified");
    assert!(receipt["lifetime"]["verified_at"].is_string());
    assert_eq!(receipt["state_cleanup"], "not_needed");
}
