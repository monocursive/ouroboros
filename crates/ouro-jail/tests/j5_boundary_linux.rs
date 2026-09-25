#![cfg(target_os = "linux")]
//! J5 boundary proof: the §15 clauses of F01–F04, S02–S04, N01, N05 and R06
//! that had no live test on the reference host (J5 gap analysis §1.2).
//!
//! Every test drives the real `ouro-jail run` binary through the shared
//! harness against one small fixture that attempts the single operation the
//! specification says must fail (or must be recorded) and reports the raw
//! syscall result. This is defensive conformance testing of our own sandbox
//! against our own fixtures on our own host: no general-purpose bypass
//! tooling, one measured operation per clause. Live tests need
//! `OURO_CONFORMANCE=1` and the reference host; under it a skip is a failure.
//!
//! The clauses each test closes are named in its doc comment, with the
//! enforcement point a mutation would delete (so a test that could not fail
//! is a finding against the author, per the J5 contract).

use std::ffi::OsString;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ouro_fixture::harness::{self, Jail, Run, TraceConsumer, UnixProbe};
use serde_json::Value;

mod common;

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

const PYTHON: &str = "/usr/bin/python3";

/// A `run --profile <profile>` over a private workspace holding the
/// conformance fixture at `<workspace>/bin/ouro-fixture`, trace and control
/// plumbed. Mirrors the `case` helpers of the J2/J3 suites.
struct Case {
    jail: Jail,
    workspace: PathBuf,
    fixture: PathBuf,
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn fixture_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn case(profile: &str) -> Case {
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    private_dir(&workspace.join("bin"));
    let fixture = workspace.join("bin/ouro-fixture");
    std::fs::copy(harness::fixture_path(), &fixture).unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755)).unwrap();
    let jail = jail
        .arg("run")
        .arg("--profile")
        .arg(profile)
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control();
    Case {
        jail,
        workspace,
        fixture,
    }
}

impl Case {
    /// A fixture `script` of `steps` written into the workspace; returns the
    /// target argv that runs it.
    fn script(&self, name: &str, steps: &Value) -> Vec<OsString> {
        let path = self.workspace.join(format!("{name}.json"));
        std::fs::write(&path, serde_json::to_vec(steps).unwrap()).unwrap();
        vec![
            self.fixture.clone().into_os_string(),
            OsString::from("script"),
            path.into_os_string(),
        ]
    }
}

/// A Python target: `/usr/bin/python3 -c SCRIPT`, from the read-only `/usr`.
fn py(script: &str) -> Vec<OsString> {
    vec![
        OsString::from(PYTHON),
        OsString::from("-c"),
        OsString::from(script),
    ]
}

/// The last JSON object a Python target printed.
fn py_out(run: &Run) -> Value {
    let text = run.stdout_text();
    let line = text
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| {
            panic!(
                "the target printed no JSON: stdout {text:?}, stderr {}",
                run.stderr_text()
            )
        });
    serde_json::from_str(line).unwrap()
}

/// Every receipt and trace event validated against the checked-in schemas
/// and the rules they cannot state; returns the settled receipt.
fn settled(run: &Run) -> Value {
    validate(run);
    run.receipt_phase("settled").unwrap_or_else(|| {
        panic!(
            "no settled receipt: exit {:?}, stderr {}",
            run.code(),
            run.stderr_text()
        )
    })
}

fn validate(run: &Run) {
    let validators = common::validators();
    for receipt in run.receipts() {
        validators["jail-receipt"]
            .validate(&receipt)
            .unwrap_or_else(|error| panic!("a receipt fails its schema: {error}\n{receipt:#}"));
        common::assert_semantic_receipt(&receipt);
    }
    for event in run.trace_events() {
        validators["jail-event"]
            .validate(event)
            .unwrap_or_else(|error| panic!("an event fails its schema: {error}\n{event:#}"));
    }
}

/// The fixture's report lines for one operation, in order.
fn ops<'a>(lines: &'a [Value], op: &str) -> Vec<&'a Value> {
    lines.iter().filter(|line| line["op"] == op).collect()
}

// ===========================================================================
// F01: a workspace symlink to a HOME secret reads as absent (§15 F01;
// north-star §4.10)
// ===========================================================================

/// A real secret file lives outside every granted root, at a stand-in
/// operator home. The workspace holds a symlink pointing at it by absolute
/// path. Attempted, live, by the contained child: `openat` of that symlink.
/// Verdict: the open is a performed `ENOENT` — the target is simply not in
/// the child's mount namespace — and the secret's bytes never reach the
/// child's stdout. The enforcement point is the closed mount view (only the
/// declared roots are bound); binding the operator home would make the open
/// succeed and this fail.
#[test]
fn f01_a_workspace_symlink_to_a_home_secret_reads_as_absent() {
    if !common::live() {
        return;
    }
    let c = case("tool");
    // Outside the workspace, outside every bound root: a real host secret.
    let home = c.jail.root().join("operator-home/.ssh");
    private_dir(&home);
    let secret = home.join("id_ed25519");
    const SECRET: &[u8] = b"OURO-J5-F01-SECRET-must-never-be-read-by-the-child\n";
    fixture_file(&secret, SECRET);
    // The secret is genuinely readable from outside the jail, so the boundary
    // — not a missing file — is what the test proves.
    assert_eq!(std::fs::read(&secret).unwrap(), SECRET);
    // A workspace symlink to it by absolute path.
    std::os::unix::fs::symlink(&secret, c.workspace.join("escape")).unwrap();

    let steps = serde_json::json!([["open", c.workspace.join("escape"), "--expect", "ENOENT"]]);
    let argv = c.script("f01", &steps);
    let run = c.jail.target(argv).run().unwrap();
    assert_eq!(
        run.code(),
        Some(0),
        "the symlink did not read as absent: stderr {}",
        run.stderr_text()
    );
    let lines = run.fixture_lines();
    let open = ops(&lines, "openat");
    assert_eq!(open.len(), 1, "{lines:#?}");
    assert_eq!(open[0]["errno"], "ENOENT", "{}", open[0]);
    assert!(
        !run.stdout_text().contains("SECRET"),
        "the secret's bytes reached the child"
    );
    settled(&run);
}

// ===========================================================================
// F02: mount replacement of a protected object (§15 F02; §9.1)
// ===========================================================================

/// A protected deep `.git` exists at scan time and is bound read-only over
/// itself. Attempted, live, by the contained child: replace that mounted
/// object — `mount --bind` over it, `umount2` it, `move_mount` it, and the
/// new mount API (`open_tree`, `fsopen`). Verdict: every mount-family call
/// fails `EPERM`, the `.git/HEAD` still holds its original bytes, and a write
/// to it is still `EROFS`: the protected object cannot be mount-replaced. The
/// mount defense is two independent locks — the baseline seccomp deny of the
/// mount syscalls (§9.2) and the dropped capabilities (CapEff = 0, no
/// `CAP_SYS_ADMIN` for an unprivileged-user-namespace bind). Removing the
/// seccomp deny alone leaves the guarantee standing on the capability lock
/// (measured: the mount still returns `EPERM`); the guarantee reddens only
/// when the whole mount defense is removed, which then lets the object be
/// replaced. The test asserts the observable guarantee F02 states, not one
/// of the two mechanisms.
#[test]
fn f02_mount_replacement_of_a_protected_git_is_denied() {
    if !common::live() {
        return;
    }
    let c = case("tool");
    let git = c.workspace.join("deep/nested/.git");
    private_dir(&git);
    fixture_file(&git.join("HEAD"), b"ref: refs/heads/main\n");

    let head = c.workspace.join("deep/nested/.git/HEAD");
    let git_dir = git.to_str().unwrap().to_owned();
    let head_path = head.to_str().unwrap().to_owned();
    let script = format!(
        r#"
import ctypes, errno, json, os
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
GIT = {git:?}.encode()
HEAD = {head:?}.encode()
def call(nr, *args):
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(nr), *args)
    return "ok(%d)" % r if r >= 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
out = {{}}
src = b"/tmp\0"
none = b"none\0"
# mount("/tmp", GIT, "none", MS_BIND, NULL)
out["mount_bind"] = call(165, src, GIT + b"\0", none, 0x1000, 0)
# umount2(GIT, MNT_DETACH)
out["umount2"] = call(166, GIT + b"\0", 2)
# move_mount(AT_FDCWD, "/tmp", AT_FDCWD, GIT, 0)
out["move_mount"] = call(429, -100, src, -100, GIT + b"\0", 0)
# open_tree(AT_FDCWD, GIT, 0)
out["open_tree"] = call(428, -100, GIT + b"\0", 0)
# fsopen("tmpfs", 0)
out["fsopen"] = call(430, b"tmpfs\0", 0)
# The protected object is unchanged and still read-only.
out["head"] = open(HEAD, "rb").read().decode()
try:
    open(HEAD, "w")
    out["write"] = "ok"
except OSError as e:
    out["write"] = errno.errorcode.get(e.errno, str(e.errno))
print(json.dumps(out))
"#,
        git = git_dir,
        head = head_path,
    );
    let run = c.jail.target(py(&script)).run().unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    for call in ["mount_bind", "umount2", "move_mount", "open_tree", "fsopen"] {
        assert_eq!(out[call], "EPERM", "{call} was not denied: {out}");
    }
    assert_eq!(out["head"], "ref: refs/heads/main\n", "the object changed");
    assert_eq!(out["write"], "EROFS", "the object is not read-only: {out}");
    settled(&run);
}

// ===========================================================================
// F03: a new deep protected segment is outside existing_and_root (§15 F03;
// §9.1 "A newly created protected segment ... remains outside ...
// existing_and_root coverage")
// ===========================================================================

/// An ordinary nested directory exists at scan time with no `.git` beneath
/// it. Attempted, live, by the contained child: create a `.git` directory
/// there and write inside it. Verdict: both succeed — the segment did not
/// exist when the walk pinned coverage, so it is not protected, which is the
/// documented Linux limit — and the settled receipt records the coverage as
/// `existing_and_root`, naming the limit rather than claiming every
/// descendant. The enforcement point is `scan_coverage`; a build that
/// claimed `all_descendants` would refuse (proved elsewhere) and a build that
/// silently protected the new segment would make the writes fail.
#[test]
fn f03_a_new_deep_protected_segment_is_outside_existing_and_root_coverage() {
    if !common::live() {
        return;
    }
    let c = case("tool");
    // Present at scan time, ordinary, no protected segment inside it.
    private_dir(&c.workspace.join("proj/sub"));

    let steps = serde_json::json!([
        // The child creates a protected segment that did not exist at launch.
        ["mkdir", "proj/sub/.git", "--expect", "ok"],
        // ... and writes into it: outside existing_and_root, so it is writable.
        [
            "open",
            "proj/sub/.git/config",
            "--create",
            "--write",
            "--expect",
            "ok"
        ]
    ]);
    let argv = c.script("f03", &steps);
    let run = c.jail.target(argv).run().unwrap();
    assert_eq!(
        run.code(),
        Some(0),
        "a new deep .git was not writable: stderr {}",
        run.stderr_text()
    );
    let receipt = settled(&run);
    assert_eq!(
        receipt["applied"]["filesystem"]["protected_coverage"], "existing_and_root",
        "the receipt does not name the coverage limit: {receipt:#}"
    );
}

// ===========================================================================
// F04: scan-limit exhaustion refuses without a claimed complete boundary
// (§15 F04; §9.1 "Reaching a bound refuses instead of claiming complete
// existing_and_root coverage")
// ===========================================================================

/// The workspace holds a directory chain deeper than the fixed depth bound
/// (128). Attempted, live, through `ouro-jail run`: prepare a `tool` boundary
/// over it. Verdict: preparation refuses before any target exec (exit 125),
/// the target's marker file is never created, and the refused receipt carries
/// no applied filesystem boundary — it never claims `existing_and_root`
/// coverage it could not establish. The enforcement point is the depth check
/// in the protected scan mapped to a preparation refusal; removing it would
/// let the run reach exec with a partial walk.
#[test]
fn f04_a_workspace_deeper_than_the_scan_limit_refuses_without_claiming_coverage() {
    if !common::live() {
        return;
    }
    let c = case("tool");
    // 130 nested directories: past the depth-128 bound of the protected scan.
    let mut deep = c.workspace.join("deep");
    for _ in 0..130 {
        deep = deep.join("d");
    }
    std::fs::create_dir_all(&deep).unwrap();

    // A marker the target would create if it ever ran. It must not appear.
    let marker = c.workspace.join("marker");
    let steps = serde_json::json!([["open", &marker, "--create", "--write", "--expect", "ok"]]);
    let argv = c.script("f04", &steps);
    let run = c.jail.target(argv).run().unwrap();

    assert_eq!(
        run.code(),
        Some(125),
        "a workspace past the scan limit did not refuse before exec: stderr {}",
        run.stderr_text()
    );
    assert!(!marker.exists(), "the target ran despite the refusal");
    let receipts = run.receipts();
    assert!(!receipts.is_empty(), "no refused receipt was written");
    for receipt in &receipts {
        let _ = common::checked_receipt(receipt.clone());
        assert_ne!(
            receipt["phase"], "settled",
            "a refusal settled: {receipt:#}"
        );
        // A refusal before the boundary exists carries no applied filesystem,
        // so it cannot claim a complete protected boundary.
        let coverage = &receipt["applied"]["filesystem"]["protected_coverage"];
        assert!(
            coverage.is_null(),
            "the refused receipt claims coverage it never established: {coverage}"
        );
        assert_ne!(receipt["containment"], "enforced", "{receipt:#}");
    }
    let refused = receipts
        .iter()
        .find(|r| r["outcome"]["kind"] == "refused")
        .unwrap_or_else(|| panic!("no refused outcome: {receipts:#?}"));
    let message = refused["outcome"]["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        message.contains("depth") || message.contains("coverage") || message.contains("partial"),
        "the refusal does not name the scan limit: {}",
        refused["outcome"]["error"]
    );
}

/// F04's other half (§15 F04, "source-identity swap refuses"; §9.1 mount
/// handoff). Attempted, live: the workspace directory is replaced by a fresh
/// object between resolution (source pinning) and the mount handoff, using the
/// `OURO_JAIL_TEST_MOUNT_SWAP` rendezvous seam — the supervisor pins the
/// sources, signals `pinned`, and waits for `go` before verifying. The test
/// renames the pinned workspace away and creates a new directory at its path,
/// then releases the handoff. Verdict: the handoff verification finds the
/// pinned inode replaced and the run refuses before exec (exit 125, no target
/// marker), with a refused receipt whose error names the replacement — never
/// a bind of the substituted object. The enforcement point is the
/// `pin.verify()` refusal loop (`platform.rs`): deleting it lets the run bind
/// the replacement and reach exec (verified RED on the host).
#[test]
fn f04_a_source_identity_swap_at_the_mount_handoff_refuses() {
    if !common::live() {
        return;
    }
    let c = case("tool");
    let workspace = c.workspace.clone();
    let root = c.jail.root().to_path_buf();
    let rendezvous = root.join("swap-rv");
    private_dir(&rendezvous);
    let marker = workspace.join("marker");
    let steps = serde_json::json!([["open", &marker, "--create", "--write", "--expect", "ok"]]);
    let argv = c.script("f04swap", &steps);

    let spawned = c
        .jail
        .env("OURO_JAIL_TEST_MOUNT_SWAP", &rendezvous)
        .receipt()
        .target(argv)
        .spawn()
        .unwrap();

    // Wait for the supervisor to finish pinning the mount sources.
    let pinned = rendezvous.join("pinned");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !pinned.exists() {
        assert!(
            Instant::now() < deadline,
            "the mount-swap seam never signalled `pinned`"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    // Replace the pinned workspace with a fresh object at the same path, then
    // let the handoff verification run.
    std::fs::rename(&workspace, root.join("workspace.gone")).unwrap();
    private_dir(&workspace);
    std::fs::write(rendezvous.join("go"), b"1").unwrap();

    let run = spawned.wait().unwrap();
    assert_eq!(
        run.code(),
        Some(125),
        "a swapped mount source did not refuse before exec: stderr {}",
        run.stderr_text()
    );
    assert!(!marker.exists(), "the target ran despite the swap");
    let receipts = run.receipts();
    let refused = receipts
        .iter()
        .find(|r| r["outcome"]["kind"] == "refused")
        .unwrap_or_else(|| panic!("no refused receipt: {receipts:#?}"));
    let _ = common::checked_receipt((*refused).clone());
    assert_ne!(refused["containment"], "enforced", "{refused:#}");
    let message = refused["outcome"]["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        message.contains("replaced") || message.contains("changed"),
        "the refusal does not name the source swap: {}",
        refused["outcome"]["error"]
    );
    // The swap refusal happens before any boundary exists, so this receipt has
    // no native lifetime details; the seam is recorded in jail state at claim
    // time (S9), which is not part of this clause's assertion.
}

// ===========================================================================
// S02: a host namespace fd cannot be opened or entered (§15 S02)
// ===========================================================================

/// Attempted, live, by the contained child: hold each namespace fd it can
/// open (its own, and the private pid namespace's init) and `setns` into it;
/// and enumerate the pids its `/proc` shows. Verdict: `setns` on every
/// namespace fd is `EPERM` (the baseline denies it), the private `/proc`
/// shows only the sandbox's own handful of pids, and none is the supervisor
/// on the host — there is no host namespace fd to reach. The enforcement
/// points are the `--unshare-*` namespaces with a private `/proc` and the
/// seccomp deny of `setns`.
#[test]
fn s02_a_host_namespace_fd_cannot_be_opened_or_entered() {
    if !common::live() {
        return;
    }
    let c = case("tool");
    const SCRIPT: &str = r#"
import ctypes, errno, json, os
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def setns(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as e:
        return "open:" + errno.errorcode.get(e.errno, str(e.errno))
    ctypes.set_errno(0)
    r = libc.syscall(308, fd, 0)  # setns(fd, 0)
    os.close(fd)
    return "ok" if r == 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
out = {
    "setns_self_net": setns("/proc/self/ns/net"),
    "setns_self_user": setns("/proc/self/ns/user"),
    "setns_pid1_mnt": setns("/proc/1/ns/mnt"),
    "proc_pids": sorted(int(p) for p in os.listdir("/proc") if p.isdigit()),
}
print(json.dumps(out))
"#;
    let spawned = c.jail.target(py(SCRIPT)).spawn().unwrap();
    let supervisor = spawned.pid() as i64;
    let run = spawned.wait().unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    for key in ["setns_self_net", "setns_self_user", "setns_pid1_mnt"] {
        assert_eq!(out[key], "EPERM", "{key} was not denied: {out}");
    }
    let pids: Vec<i64> = out["proc_pids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_i64().unwrap())
        .collect();
    assert!(
        pids.iter().all(|pid| *pid < 100),
        "the private pid namespace shows host pids: {pids:?}"
    );
    assert!(
        !pids.contains(&supervisor),
        "the supervisor pid {supervisor} is visible inside the boundary"
    );
    settled(&run);
}

/// S02.6: no cgroup filesystem is mounted or reachable in the child (§15 S02).
/// Attempted, live, from inside tool/build/agent: read `/proc/self/mountinfo`
/// for any cgroup/cgroup2 mount, look at `/sys/fs/cgroup`, and try to open a
/// fresh cgroup2 tree with `open_tree` and `fsopen`. Verdict: no cgroup or
/// cgroup2 mount appears in the child's mount table, `/sys/fs/cgroup` is not a
/// cgroup mount (absent, or masked/empty), and `open_tree`/`fsopen("cgroup2")`
/// fail — so the child has no view of and cannot create a cgroup filesystem.
/// `none` is uncontained by definition (host view, its own cgroup visible), so
/// it is not covered here. The absent mount is by construction (the contained
/// mount plan mounts only the declared roots, `/proc` and `/dev` — pinned by
/// the milestone freeze and the `bwrap` mount-table tests); `fsopen`/
/// `open_tree` are additionally denied by the baseline seccomp filter and the
/// dropped capabilities (creating a mount needs `CAP_SYS_ADMIN`), defence in
/// depth on top of the empty mount view.
#[test]
fn s02_no_cgroup_filesystem_is_reachable_in_the_child() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import os, ctypes, errno, json
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def call(nr, *a):
    ctypes.set_errno(0)
    rc = libc.syscall(ctypes.c_long(nr), *a)
    return 'ok' if rc >= 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
out = {}
mi = open('/proc/self/mountinfo').read().splitlines()
out['cgroup_mounts'] = [l for l in mi if ' cgroup ' in (' ' + l + ' ') or ' cgroup2 ' in (' ' + l + ' ')]
out['sysfs_cgroup_listing'] = sorted(os.listdir('/sys/fs/cgroup')) if os.path.isdir('/sys/fs/cgroup') else None
out['open_tree'] = call(428, -100, b'/sys/fs/cgroup\0', 0)   # open_tree(AT_FDCWD, ..., 0)
out['fsopen'] = call(430, b'cgroup2\0', 0)                   # fsopen("cgroup2", 0)
print(json.dumps(out))
"#;
    for profile in ["tool", "build", "agent"] {
        let c = case(profile);
        let jail = if profile == "build" {
            c.jail.args(["--limit", "mem=64MiB"])
        } else {
            c.jail
        };
        let run = jail.target(py(SCRIPT)).run().unwrap();
        assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
        let out = py_out(&run);
        assert_eq!(
            out["cgroup_mounts"],
            serde_json::json!([]),
            "{profile}: a cgroup filesystem is mounted in the child: {out}"
        );
        // /sys/fs/cgroup is not a populated cgroup tree: absent, or (if the
        // path exists) not a cgroupfs, so it holds no cgroup control files.
        if let Some(listing) = out["sysfs_cgroup_listing"].as_array() {
            assert!(
                !listing.iter().any(|name| name == "cgroup.procs"),
                "{profile}: /sys/fs/cgroup is a live cgroup mount: {out}"
            );
        }
        assert_ne!(
            out["open_tree"], "ok",
            "{profile}: open_tree succeeded: {out}"
        );
        assert_ne!(
            out["fsopen"], "ok",
            "{profile}: fsopen(cgroup2) succeeded: {out}"
        );
        settled(&run);
    }
}

// ===========================================================================
// S03: the outer boundaries cannot be reversed inside `agent` (§15 S03
// "Attempts to undo each outer boundary fail"; §9.2)
// ===========================================================================

/// Attempted, live, by the `agent` child, once with observation on and once
/// with it off: clear `no_new_privs`; add an allow-everything seccomp filter
/// and then make syscalls the baseline denies; reach the execution cgroup
/// through `/sys/fs/cgroup`; and, after restricting itself with Landlock,
/// regain the access it just gave up. Verdict, under both observation modes:
/// `no_new_privs` stays 1 (`prctl` refuses to clear it); a stacked permissive
/// filter cannot loosen the baseline (`keyctl` stays `EPERM`); the cgroupfs is
/// absent so the resource boundary is unreachable; and a second, permissive
/// Landlock ruleset does not restore a denied write. Each is a one-way
/// boundary the child cannot walk back.
///
/// The seccomp leg is probed with `keyctl`, a `DENY_EPERM` syscall that is
/// NOT in the closed set and that the observer does not independently block,
/// so its `EPERM` comes solely from the seccomp baseline — removing `keyctl`
/// from `DENY_EPERM` reddens this test under both observation modes (verified
/// on the host). `ptrace` is also probed, but only as a defence-in-depth
/// check under observation ON: the closed-set observer ptrace-attaches the
/// target, so `PTRACE_TRACEME` returns `EPERM` ("already traced") independent
/// of the baseline, and under observation OFF it is not attached and the
/// baseline alone must hold — which the `keyctl` leg proves. So the ptrace
/// value is asserted `EPERM` only when observing, and never stands in for the
/// seccomp-stacking clause.
#[test]
fn s03_the_outer_boundaries_cannot_be_reversed_inside_agent() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import ctypes, errno, json, os, struct
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
out = {}

def status(field):
    for line in open("/proc/self/status"):
        if line.startswith(field + ":"):
            return line.split()[1]
    return None

def call(nr, *args):
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(nr), *args)
    return "ok" if r >= 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))

# --- no_new_privs: set, and refuse to clear ---
out["nnp_before"] = status("NoNewPrivs")
ctypes.set_errno(0)
r = libc.prctl(38, 0, 0, 0, 0)   # PR_SET_NO_NEW_PRIVS, 0
out["clear_nnp"] = "ok" if r == 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
out["nnp_after"] = status("NoNewPrivs")

# --- seccomp: a permissive filter cannot loosen the stacked baseline ---
class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]
ALLOW = (SockFilter * 1)(SockFilter(0x06, 0, 0, 0x7fff0000))  # BPF_RET|BPF_K ALLOW
prog = SockFprog(1, ALLOW)
ctypes.set_errno(0)
r = libc.syscall(317, 1, 0, ctypes.byref(prog))  # seccomp(SET_MODE_FILTER, 0, prog)
out["add_allow_filter"] = "ok" if r >= 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
out["filters"] = status("Seccomp_filters")
# keyctl(0): a DENY_EPERM syscall outside the closed set that the observer does
# not touch, so its EPERM is the seccomp baseline alone (isolates the clause).
out["keyctl_after_allow"] = call(250, 0, 0, 0, 0)
# ptrace(PTRACE_TRACEME): defence in depth (observer + baseline) when observed.
out["ptrace_after_allow"] = call(101, 0, 0, 0, 0)

# --- cgroup: the execution boundary is not reachable from inside ---
try:
    open("/sys/fs/cgroup/cgroup.procs")
    out["cgroup_procs"] = "reachable"
except OSError as e:
    out["cgroup_procs"] = errno.errorcode.get(e.errno, str(e.errno))

# --- Landlock: a domain only narrows, never widens ---
def landlock():
    RW = os.path.join(os.getcwd(), "ll-rw")
    os.makedirs(RW, exist_ok=True)
    target = os.path.join(RW, "probe")
    # ruleset handling read-file only: no write right granted anywhere.
    attr = struct.pack("<QIQQ", 0x2, 0, 0, 0)  # handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE
    ctypes.set_errno(0)
    rs = libc.syscall(444, attr, len(attr), 0)  # landlock_create_ruleset
    if rs < 0:
        return "create:" + errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
    ctypes.set_errno(0)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        return "nnp"
    ctypes.set_errno(0)
    r = libc.syscall(446, rs, 0)  # landlock_restrict_self
    if r != 0:
        return "restrict:" + errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
    os.close(rs)
    try:
        open(target, "w")
        denied = "ok"
    except OSError as e:
        denied = errno.errorcode.get(e.errno, str(e.errno))
    # A second, empty ruleset (grants nothing new): the write stays denied.
    attr2 = struct.pack("<QIQQ", 0x2, 0, 0, 0)
    rs2 = libc.syscall(444, attr2, len(attr2), 0)
    if rs2 >= 0:
        libc.syscall(446, rs2, 0)
        os.close(rs2)
    try:
        open(target, "w")
        after = "ok"
    except OSError as e:
        after = errno.errorcode.get(e.errno, str(e.errno))
    return {"first": denied, "after_second_ruleset": after}
out["landlock"] = landlock()
print(json.dumps(out))
"#;
    for observe in ["on", "off"] {
        let c = case("agent");
        let run = c
            .jail
            .args(["--observe", observe])
            .target(py(SCRIPT))
            .run()
            .unwrap();
        assert_eq!(
            run.code(),
            Some(0),
            "{observe}: stderr {}",
            run.stderr_text()
        );
        let out = py_out(&run);
        // no_new_privs is set and cannot be cleared.
        assert_eq!(out["nnp_before"], "1", "{observe}: {out}");
        assert_ne!(
            out["clear_nnp"], "ok",
            "{observe}: no_new_privs cleared: {out}"
        );
        assert_eq!(out["nnp_after"], "1", "{observe}: {out}");
        // The permissive filter stacks but cannot loosen the baseline. keyctl
        // is denied by the baseline alone, so this holds under both modes.
        assert_eq!(out["add_allow_filter"], "ok", "{observe}: {out}");
        assert_eq!(
            out["keyctl_after_allow"], "EPERM",
            "{observe}: a stacked permissive filter loosened the seccomp baseline: {out}"
        );
        // Under observation the observer's ptrace attach is a second lock;
        // under observation off the baseline alone holds (the keyctl leg).
        if observe == "on" {
            assert_eq!(
                out["ptrace_after_allow"], "EPERM",
                "observed: ptrace was not held by observer+baseline: {out}"
            );
        }
        // The execution cgroup is not reachable through the child's mount view.
        assert_eq!(out["cgroup_procs"], "ENOENT", "{observe}: {out}");
        // Landlock only narrows.
        assert_eq!(out["landlock"]["first"], "EACCES", "{observe}: {out}");
        assert_eq!(
            out["landlock"]["after_second_ruleset"], "EACCES",
            "{observe}: a second Landlock ruleset widened a denied access: {out}"
        );
        settled(&run);
    }
}

// ===========================================================================
// S04: io_uring across profiles (§15 S04; §9.2)
// ===========================================================================

/// Attempted, live, by the `agent` and by the `build` child: each io_uring
/// entry point, native and through the i386 compatibility ABI. Verdict:
/// `io_uring_setup`, `io_uring_enter` and `io_uring_register` all fail
/// `EPERM` for both profiles — `build` shares the `tool` baseline and
/// `agent`'s baseline includes the io_uring denials — so no ring can be set
/// up. The enforcement point is the io_uring entries in the seccomp deny
/// list; dropping any one lets that profile create a ring.
#[test]
fn s04_agent_and_build_refuse_every_io_uring_interface() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import ctypes, errno, json, struct
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
out = {}
X32 = 0x40000000
for nr in (425, 426, 427):
    row = {}
    for abi, label in ((0, "native"), (X32, "x32")):
        ctypes.set_errno(0)
        r = libc.syscall(nr | abi, 0, 0, 0, 0, 0, 0)
        row[label] = "ok(%d)" % r if r >= 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
    out[str(nr)] = row
print(json.dumps(out))
"#;
    for profile in ["agent", "build"] {
        let c = case(profile);
        let jail = if profile == "build" {
            c.jail.args(["--limit", "mem=64MiB"])
        } else {
            c.jail
        };
        let run = jail.target(py(SCRIPT)).run().unwrap();
        assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
        let out = py_out(&run);
        for nr in ["425", "426", "427"] {
            for abi in ["native", "x32"] {
                assert_eq!(
                    out[nr][abi], "EPERM",
                    "{profile}: io_uring {nr}/{abi} was not denied: {out}"
                );
            }
        }
        settled(&run);
    }
}

/// Attempted, live, by the `none` child: `io_uring_setup`. Verdict: it
/// succeeds — `none` installs no containment filter (§9.3), which is the
/// documented io_uring exclusion `none` retains: the ring is neither refused
/// nor observed. The contrast with the contained profiles above is what a
/// deleted `none` filter-suppression would break (a filter would make this
/// `EPERM`). The observation half — that a ring's submitted operations are
/// never traced — is the closed-set table's own test
/// (`j4_closed_set_linux`); this asserts only the enforcement exclusion.
#[test]
fn s04_none_installs_no_io_uring_filter() {
    let (jail, _) = match none_case("on") {
        Some(pair) => pair,
        None => return,
    };
    const SCRIPT: &str = r#"
import ctypes, errno, json, os
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
params = (ctypes.c_ubyte * 120)()
ctypes.set_errno(0)
r = libc.syscall(425, 8, ctypes.byref(params))  # io_uring_setup(8, params)
out = {"ret": r, "errno": None if r >= 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))}
if r >= 0:
    os.close(r)
print(json.dumps(out))
"#;
    let run = jail.target(py(SCRIPT)).run().unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    assert!(
        out["ret"].as_i64().unwrap() >= 0,
        "none refused io_uring_setup ({out}); it installs no filter"
    );
    let receipt = settled(&run);
    assert_eq!(receipt["child_protection"], "unprotected", "{receipt:#}");
    assert_eq!(receipt["applied"]["syscalls"], Value::Null, "{receipt:#}");
}

/// A newly set-up io_uring ring, or a skip note when the host refuses one.
fn io_uring_ring() -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd as _;
    let mut params = [0u64; 16]; // io_uring_params is 120 bytes; 128 is enough.
    // SAFETY: the kernel writes at most the 120-byte params struct into `params`.
    let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
    assert!(
        fd >= 0,
        "the reference host must permit io_uring_setup: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: a successful io_uring_setup returns a fresh owned descriptor.
    unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) }
}

/// S04.6: an io_uring ring on stdout or stderr refuses before exec (§15 S04;
/// §8.3 stdio inspection). The existing `review_linux.rs::r3_io_uring_as_stdio_refuses_before_exec`
/// covers stdin only. Attempted, live: `ouro-jail run` with the ring as the
/// target's stdout, then as its stderr. Verdict: each refuses before exec
/// (exit 125), the target never runs, and the refusal names an anonymous
/// inode / invalid fd. The enforcement point is `validate_stdio`'s
/// `anon_inode:` refusal over fds 0/1/2 (`platform.rs`): deleting it lets the
/// ring through as stdout/stderr.
#[test]
fn s04_an_io_uring_on_stdout_or_stderr_refuses_before_exec() {
    if !common::live() {
        return;
    }
    use std::process::{Command, Stdio};
    for stream in ["stdout", "stderr"] {
        let jail = Jail::new().unwrap();
        let workspace = jail.root().join("workspace");
        private_dir(&workspace);
        let fixture = workspace.join("ouro-fixture");
        std::fs::copy(harness::fixture_path(), &fixture).unwrap();
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755)).unwrap();
        let ring = io_uring_ring();
        let mut cmd = Command::new(harness::jail_path());
        cmd.arg("run")
            .arg("--workspace")
            .arg(&workspace)
            .arg("--")
            .arg(&fixture)
            .arg("exit")
            .arg("0")
            .env("OURO_DATA_DIR", jail.data_dir())
            .env("OURO_CONFIG_DIR", jail.config_dir());
        if stream == "stdout" {
            cmd.stdout(Stdio::from(ring)).stderr(Stdio::piped());
        } else {
            cmd.stderr(Stdio::from(ring)).stdout(Stdio::piped());
        }
        let out = cmd.output().expect("run");
        if stream == "stdout" {
            // stderr is a real pipe here, so the refusal is emitted: exit 125,
            // naming stdout and the anonymous inode. The target's stdout is the
            // ring (uncapturable), so the refusal message + 125 is the proof it
            // did not exec.
            assert_eq!(
                out.status.code(),
                Some(125),
                "stdout: an io_uring ring on stdout did not refuse before exec: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("stdout")
                    && (stderr.contains("anonymous inode") || stderr.contains("invalid_fd")),
                "stdout: the refusal does not name stdout / the anonymous inode: {stderr}"
            );
        } else {
            // stderr IS the ring, so `ouro-jail` cannot emit its refusal
            // diagnostic; it still refuses before exec — the fixture `exit 0`
            // would print a report to its (piped) stdout, and that stdout is
            // empty, so the target never ran — and it exits with the refusal
            // code, not a panic: a diagnostic that cannot be written is
            // dropped, never allowed to change the exit code (§6.4).
            assert!(
                out.stdout.is_empty(),
                "stderr: the target ran despite the io_uring ring on stderr: {:?}",
                String::from_utf8_lossy(&out.stdout)
            );
            assert_eq!(
                out.status.code(),
                Some(125),
                "stderr: an unwritable stderr must not turn the refusal into another exit"
            );
        }
    }
}

/// S04.7: `agent` and `build` inherit no ring (§15 S04; §9.2 "No ring fd may
/// be inherited"). Attempted, live: an io_uring ring is created in the parent
/// and duplicated to a HIGH descriptor (200) with close-on-exec clear, so an
/// ordinary fork/exec would inherit it, then `ouro-jail run` starts the
/// target. The high number matters: the harness assigns its channel targets
/// from fd 3 upward and `dup2`s the trace channel onto low fds, so a ring
/// created at fd 3 would be overwritten before the jail ever ran (the earlier
/// version of this test was vacuous for that reason); fd 200 is above every
/// channel target and is genuinely inheritable. Verdict: the ring never
/// reaches the target — its `/proc/self/fd` holds no io_uring anonymous inode
/// (the spec's guarantee is non-inheritance, not a refusal). The enforcement
/// point is `close_range_cloexec()` in the backend bootstrap's pre-exec
/// (`exec.rs`): deleting it lets the ring at fd 200 survive into the target
/// (verified RED on the host — `bwrap` does NOT close inherited descriptors).
#[test]
fn s04_agent_and_build_inherit_no_ring() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import os, json
fds = {}
for name in os.listdir('/proc/self/fd'):
    try: fds[name] = os.readlink('/proc/self/fd/' + name)
    except OSError: fds[name] = '?'
print(json.dumps(fds))
"#;
    for profile in ["agent", "build"] {
        let ring = io_uring_ring();
        // Park the ring at fd 200, above every harness channel target, with
        // close-on-exec clear (F_DUPFD does not set it), so it is genuinely
        // inheritable and not overwritten by the plumbed channels.
        // SAFETY: `ring` is a live owned descriptor; F_DUPFD takes a scalar.
        let high = unsafe { libc::fcntl(ring.as_raw_fd(), libc::F_DUPFD, 200) };
        assert!(high >= 200, "could not park the ring at a high fd: {high}");
        let c = case(profile);
        let jail = if profile == "build" {
            c.jail.args(["--limit", "mem=64MiB"])
        } else {
            c.jail
        };
        let run = jail.target(py(SCRIPT)).run().unwrap();
        // Keep both descriptors open across the run so the ring is genuinely
        // inheritable, then close our copies.
        // SAFETY: `high` is our own duplicate descriptor.
        unsafe {
            libc::close(high);
        }
        drop(ring);
        assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
        let fds = py_out(&run);
        for (fd, target) in fds.as_object().unwrap() {
            assert!(
                !target.as_str().unwrap_or("").contains("io_uring"),
                "{profile}: the target inherited an io_uring ring at fd {fd}: {target}"
            );
        }
        settled(&run);
    }
}

// ===========================================================================
// N01: build direct egress fails (§15 N01)
// ===========================================================================

/// Attempted, live, by the `build` child, ignoring every proxy variable:
/// TCP to a remote address, TCP over IPv6, a UDP send, and a DNS query.
/// Verdict: each fails `ENETUNREACH` — `build` has a private network
/// namespace with no proxy and no host egress — and the settled receipt
/// records the network mode as `none`. This closes the N01 gap that the
/// egress loop tested only `agent` and `tool`. The enforcement point is the
/// `build` profile's `NetworkMode::None` (a network namespace with only
/// loopback); widening it would let a connect leave.
#[test]
fn n01_build_direct_egress_fails() {
    if !common::live() {
        return;
    }
    // `build` grants no workspace, so the target is `/usr/bin/python3` from the
    // read-only `/usr`, ignoring every proxy variable by construction.
    let c = case("build");
    const SCRIPT: &str = r#"
import errno, json, socket
out = {}
def attempt(family, kind, host, port):
    s = socket.socket(family, kind)
    s.settimeout(2)
    try:
        if kind == socket.SOCK_DGRAM:
            s.sendto(b"x" * 16, (host, port))
        else:
            s.connect((host, port))
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
    finally:
        s.close()
out["tcp4"] = attempt(socket.AF_INET, socket.SOCK_STREAM, "10.255.255.1", 80)
out["tcp6"] = attempt(socket.AF_INET6, socket.SOCK_STREAM, "2001:db8::1", 80)
out["udp4"] = attempt(socket.AF_INET, socket.SOCK_DGRAM, "10.255.255.1", 53)
print(json.dumps(out))
"#;
    let run = c
        .jail
        .args(["--limit", "mem=64MiB"])
        .target(py(SCRIPT))
        .run()
        .unwrap();
    assert_eq!(
        run.code(),
        Some(0),
        "build direct egress was not refused: stderr {}",
        run.stderr_text()
    );
    let out = py_out(&run);
    for key in ["tcp4", "tcp6", "udp4"] {
        assert_eq!(
            out[key], "ENETUNREACH",
            "{key} left the build network namespace: {out}"
        );
    }
    let receipt = settled(&run);
    assert_eq!(receipt["applied"]["network"]["mode"], "none", "{receipt:#}");
}

// ===========================================================================
// N05: late aliases and late extra-grant sockets are unreachable; nested
// sandbox IPC works (§15 N05; §10)
// ===========================================================================

/// Attempted, live, by the `agent` child: connect to a host socket bound in
/// an operator `--rw` extra grant *after* the boundary existed. Verdict: it is
/// refused `EACCES` by the Unix-peer mediation — it resolves the node in the
/// child's view and admits only a listener in the attempt's own network
/// namespace, whenever the socket appeared — the host peer never saw a
/// connection, and the authorized proxy still works. This closes the N05 gap
/// that extra-grant sockets were only ever bound *before* launch
/// (`conformance_j3_agent.rs::n05_host_peers_existing_late_aliased_and_in_every_grant_are_unreachable`
/// binds late sockets in the workspace/scratch/vendor roots after `prepared`
/// but binds extra-grant sockets before launch; the late-hardlink and
/// late-symlink-in-workspace cases the first draft also had are the identical
/// connect-time mediation as that test's late workspace socket, so they are
/// dropped as duplicates). The enforcement point is the seccomp-notification
/// connect mediation's deny of a node with no listener in this namespace;
/// making that branch allow lets the late socket through.
#[test]
fn n05_a_late_socket_in_an_extra_grant_is_unreachable() {
    if !common::live() {
        return;
    }
    let c = case("agent");
    let extra_rw = c.jail.root().join("extra-rw");
    private_dir(&extra_rw);

    let steps = serde_json::json!([
        [
            "unix-connect",
            extra_rw.join("late-extra.sock"),
            "--expect",
            "EACCES"
        ],
        // The authorized proxy still works, proving the mediation is live.
        ["unix-connect", "/run/ouro/proxy/proxy.sock"]
    ]);
    let argv = c.script("n05-late", &steps);
    let mut spawned = c
        .jail
        .args(["--rw", extra_rw.to_str().unwrap()])
        .gate()
        .receipt()
        .target(argv)
        .spawn()
        .unwrap();
    let message = spawned.owner().await_prepared().expect("prepared");
    let receipt = common::checked_receipt(spawned.receipt_value().expect("a prepared receipt"));
    // The host peer is bound now, after the boundary and its mounts exist in
    // the extra grant: no launch-time enumeration saw it.
    let extra = UnixProbe::bind(&extra_rw.join("late-extra.sock")).unwrap();
    spawned
        .owner()
        .release(
            &harness::gate::Release::Valid,
            message["attempt_id"].as_str().unwrap(),
            receipt["policy"]["digest"].as_str().unwrap(),
        )
        .unwrap();
    let run = spawned.wait().unwrap();
    assert_eq!(
        run.code(),
        Some(0),
        "the late extra-grant socket was reachable: stdout {}\nstderr {}",
        run.stdout_text(),
        run.stderr_text()
    );
    assert_eq!(extra.stop(), 0, "the extra-grant host peer was reached");
    let lines = run.fixture_lines();
    let connects = ops(&lines, "connect");
    assert_eq!(connects.len(), 2, "{lines:#?}");
    assert_eq!(connects[0]["errno"], "EACCES", "{}", connects[0]);
    assert_eq!(connects[1]["errno"], Value::Null, "the proxy connect");
    settled(&run);
}

/// Attempted, live, by the `agent` child: inside an inner Landlock+seccomp
/// sandbox (the nesting `agent` guarantees), a listener and a client both run
/// by the attempt exchange a line over an AF_UNIX socket in scratch. Verdict:
/// the exchange succeeds — §10 keeps same-attempt IPC, "including nested
/// sandbox IPC", allowed; the mediation governs only connects to host peers,
/// and a connect to the attempt's own listener is admitted. This closes the
/// N05 gap that nested IPC was never tested. The enforcement point is the
/// mediator's listener-in-this-namespace check; a mediator that refused every
/// pathname connect would break this legitimate case.
#[test]
fn n05_nested_sandbox_ipc_is_allowed() {
    if !common::live() {
        return;
    }
    let c = case("agent");
    let fixture = c.fixture.to_string_lossy().into_owned();
    let bin = c.workspace.join("bin").to_string_lossy().into_owned();
    // The inner sandbox grants read-write beneath scratch (where the socket
    // lives) and read-only beneath the fixture directory, /usr and /etc, then
    // execs a listener that spawns a client once it is listening.
    let shell = format!(
        "{fixture} sandbox-exec --landlock-rw /tmp --landlock-ro {bin} \
         --landlock-ro /usr --landlock-ro /etc \
         -- {fixture} unix-listen /tmp/inner-ipc.sock --accept 1 \
         -- {fixture} unix-connect /tmp/inner-ipc.sock --exchange"
    );
    let run = c
        .jail
        .target(["/bin/sh", "-c", shell.as_str()])
        .run()
        .unwrap();
    assert_eq!(
        run.code(),
        Some(0),
        "nested-sandbox IPC failed: stdout {}\nstderr {}",
        run.stdout_text(),
        run.stderr_text()
    );
    let lines = run.fixture_lines();
    // The inner sandbox actually started (Landlock was applied), and the
    // exchange completed inside it.
    let landlock = ops(&lines, "landlock_restrict_self");
    assert!(
        !landlock.is_empty() && landlock[0]["errno"].is_null(),
        "the inner sandbox did not start: {lines:#?}"
    );
    let exchanges = ops(&lines, "exchange");
    assert_eq!(exchanges.len(), 1, "{lines:#?}");
    assert!(exchanges[0]["errno"].is_null(), "{}", exchanges[0]);
    settled(&run);
}

// ===========================================================================
// R06: a detected escaped descendant loses integrity and retains state
// (§15 R06, SECOND sentence; §9.3)
// ===========================================================================

/// This test proves R06's SECOND sentence — "Detected descendant escape loses
/// integrity and retains state" — NOT the third. The third sentence ("an
/// unobserved migrated descendant is not certified dead by registered-boundary
/// verification") cannot be produced as a deterministic live fixture on the
/// stock host: with observation off the subreaper + zombie-cgroup checks
/// detect every escape (so nothing is "unobserved"), and the genuinely-unseen
/// case §9.3 names is a race the design declines to promise to catch. The
/// third sentence is recorded as a limit in the acceptance map, proved by the
/// registered-boundary scope label on the verified path
/// (`conformance_j3_none.rs::r05_clean_none_evidence_stays_unprotected`,
/// `::none_gate_closed_refuses_after_a_verified_teardown`, and the unit test
/// `uncontained.rs::a_clean_none_tree_is_empty_only_in_the_registered_scope`).
///
/// Attempted, live, `none` with observation off: the target forks a descendant
/// that migrates itself into a sibling cgroup the jail did not register and
/// survives; the target then exits cleanly. Verdict: the escape is DETECTED
/// (subreaper + membership check), so `tree_empty` is never set true and the
/// run never settles; integrity is `lost`, the target's own clean exit is
/// preserved from its own wait fact, and state is retained. The enforcement
/// point is the escape detection in `uncontained.rs`: deleting the escaped-
/// membership arms makes the empty leaf falsely certify the survivor dead
/// (the run exits 0/verified instead of 1/lost — verified RED on the host).
#[test]
fn r06_a_detected_escaped_descendant_loses_integrity_and_retains_state() {
    let (jail, _) = match none_case("off") {
        Some(pair) => pair,
        None => return,
    };
    let destination = Destination::new("r06-descendant");
    let moved = jail.root().join("moved");
    // The target forks a descendant, which waits for the go-ahead, migrates
    // into the sibling cgroup, records its pid and lives on; the target then
    // exits 0 without waiting for it.
    let code = format!(
        "import os, time\n\
         r, w = os.pipe()\n\
         if os.fork() == 0:\n\
         \x20   os.close(w)\n\
         \x20   null = os.open('/dev/null', os.O_RDWR)\n\
         \x20   for fd in (0, 1, 2): os.dup2(null, fd)\n\
         \x20   os.read(r, 1)\n\
         \x20   open({dest:?}, 'w').write('0')\n\
         \x20   open({moved:?}, 'w').write(str(os.getpid()))\n\
         \x20   time.sleep(60)\n\
         \x20   os._exit(0)\n\
         os.close(r)\n\
         os._exit(0)\n",
        dest = destination.path.join("cgroup.procs").to_str().unwrap(),
        moved = moved.to_str().unwrap(),
    );
    let run = jail
        .target([PYTHON, "-c", &code])
        .run()
        .expect("the jail runs");
    validate(&run);
    assert_eq!(run.code(), Some(1), "stderr: {}", run.stderr_text());
    assert!(moved.exists(), "the descendant never migrated");
    let receipt = run
        .receipts()
        .into_iter()
        .max_by_key(|r| r["revision"].as_u64().unwrap_or(0))
        .unwrap();
    let _ = common::checked_receipt(receipt.clone());
    // The detected escape loses integrity: no settlement, no tree-empty,
    // integrity lost, registered-boundary scope.
    assert_ne!(
        receipt["phase"], "settled",
        "an empty leaf settled: {receipt:#}"
    );
    assert_eq!(
        receipt["lifetime"]["tree_empty"],
        Value::Null,
        "{receipt:#}"
    );
    assert_eq!(receipt["lifetime"]["integrity"], "lost", "{receipt:#}");
    assert_eq!(
        receipt["lifetime"]["verification_scope"], "registered_boundary",
        "{receipt:#}"
    );
    // The target's own clean exit stays its own independent fact.
    assert_eq!(receipt["outcome"]["kind"], "exited", "{receipt:#}");
    assert_eq!(receipt["outcome"]["code"], 0, "{receipt:#}");
    assert!(run.control_kind("settled").is_empty());
    // State is retained (not cleaned) for an integrity loss.
    assert_ne!(receipt["state_cleanup"], "complete", "{receipt:#}");
    // R06.5: the detected escape retains its state — the registered leaf is
    // kept, and it is the pinned inode (not a look-alike). `none` stages no
    // vendor state (it refuses `--launch`), so there is no vendor state on
    // this path; vendor-state retention on an integrity loss is a
    // contained-profile concern, proved by
    // `portable_launch::rm11_a_teardown_that_lost_integrity_retains_vendor_state_and_says_why`.
    // Enforcement: `uncontained.rs` `self.leaf.retain()` on a detected loss;
    // removing it lets the leaf be cleaned and this assertion reddens.
    let leaf = &receipt["lifetime"]["native"]["details"]["execution_cgroup"];
    let leaf_path = PathBuf::from(leaf["path"].as_str().expect("a leaf path"));
    let leaf_inode = leaf["inode"].as_u64().expect("a leaf inode");
    let meta = std::fs::metadata(&leaf_path)
        .unwrap_or_else(|e| panic!("the registered leaf was not retained: {e}: {leaf_path:?}"));
    assert_eq!(
        meta.ino(),
        leaf_inode,
        "the retained leaf is not the pinned one: {leaf_path:?}"
    );
    // Clean up the retained empty leaf this attempt left, by pinned inode only.
    remove_empty_leaf(&leaf_path, leaf_inode);
}

/// Remove an empty cgroup this attempt left, only when the directory at
/// `path` is still the pinned `inode` (never a look-alike another run made).
fn remove_empty_leaf(path: &Path, inode: u64) {
    if std::fs::metadata(path).is_ok_and(|m| m.ino() == inode) {
        let _ = std::fs::remove_dir(path);
    }
}

// ===========================================================================
// R03: a wall deadline is enforced under trace transport pressure (§15 R03;
// §13.3 "Disk sync runs independently of the supervision loop"). The gap
// (rev-A H7): the mapped R03 tests cover neither a wall while the trace
// consumer has DISCONNECTED nor a wall during a genuine PARTIAL write. The
// existing `j4_trace_linux.rs::j4_r03_the_wall_is_enforced_while_the_trace_is_saturated`
// covers a fully-full pipe (a `Never` consumer, writes short at Ok(0)); these
// two add the disconnect and partial-write conditions.
// ===========================================================================

/// A `tool` run over a workspace whose target opens `opens` files (long names,
/// each an observed closed-set write that emits a ~630 B trace frame) then
/// sleeps `sleep_ms`, with `--evidence best-effort` so trace loss degrades
/// rather than stopping the attempt, leaving only the wall to end it.
fn pressure_case(opens: usize, sleep_ms: u64) -> (Case, Vec<OsString>) {
    let c = case("tool");
    let long = "n".repeat(160);
    let mut steps: Vec<Value> = (0..opens)
        .map(|index| serde_json::json!(["open", format!("{long}{index}"), "--create", "--write"]))
        .collect();
    steps.push(serde_json::json!(["sleep", sleep_ms.to_string()]));
    let argv = c.script("r03-pressure", &Value::Array(steps));
    (c, argv)
}

/// The wall fires on time while a trace WRITE IS PARTIAL. Attempted, live: a
/// `tool` run with a 2 s wall and a `Never` trace consumer (reads nothing
/// while the jail runs), and enough events (~630 B each) that the pipe fills
/// and, behind it, the whole external queue. The frame that crosses the full
/// boundary is written only in part before the fd goes `WouldBlock`, then the
/// queue overflows and evidence is lost. The target would run 30 s. Verdict:
/// the run still ends by `wall_expiry` within a few seconds with the wall
/// recorded hit, one trace loss is recorded, and the captured trace is a
/// recognisable prefix (never a torn frame followed by more bytes) — the
/// supervision loop never waits on the full/partial trace write. The
/// enforcement point is the nonblocking external trace fd
/// (`trace.rs FdSink::from_raw_fd` calls `set_nonblocking`): with a blocking fd
/// the write to the full pipe blocks the supervision loop forever (the
/// consumer reads nothing until after exit), the wall never fires, and the run
/// hits the harness timeout (verified RED on the host by removing
/// `set_nonblocking`).
///
/// Whether the captured prefix ends exactly on a frame boundary or mid-frame
/// (a torn last line) depends on where 64 KiB of ~630 B frames lands, so this
/// asserts recognisability, not tornness. A guaranteed torn write needs a
/// smaller pipe or a larger-than-pipe event, neither available to this slice
/// (the pipe size lives in the harness, the frame writer in `trace.rs`).
#[test]
fn r03_a_wall_fires_on_time_under_a_saturated_trace() {
    if !common::live() {
        return;
    }
    let (c, argv) = pressure_case(8_000, 30_000);
    let started = Instant::now();
    let run = c
        .jail
        .trace_consumer(TraceConsumer::Never)
        .args(["--evidence", "best-effort", "--limit", "wall=2s"])
        .timeout(Duration::from_secs(90))
        .target(argv)
        .run()
        .unwrap();
    let elapsed = started.elapsed();
    let receipt = last_pressure_receipt(&run);
    assert_eq!(
        receipt["outcome"]["cause"], "wall_expiry",
        "the wall did not end the run: {receipt:#}"
    );
    assert_eq!(receipt["outcome"]["kind"], "signaled", "{receipt:#}");
    let wall = wall_row(&receipt);
    assert_eq!(
        wall["hit"], true,
        "the wall is not recorded hit: {receipt:#}"
    );
    assert_eq!(wall["mechanism"], "boottime-deadline");
    assert_recognisable_prefix(&run);
    assert_one_evidence_loss(&receipt);
    assert!(
        elapsed < Duration::from_secs(9),
        "the wall fired late under a saturated trace: {elapsed:?}"
    );
}

// R03's other named condition — a wall enforced while the trace consumer has
// DISCONNECTED — is NOT shipped as a live test here: it is not mutation-
// provable and so would be a test that cannot fail (see B2/notes.md and
// B2/requests.md, R03.2). A closed pipe returns EPIPE to the writer at once
// and never blocks it, so a disconnect cannot delay the wall by construction —
// no jail-code deletion makes it block — and the disconnect loss is fail-safe-
// recorded in several places (deleting the flush_now write-error path AND the
// drain_final undelivered path both left the loss recorded, verified GREEN
// survivor on the host). The disconnect HANDLING is already proved by
// `j4_trace_linux.rs::j4_r03_disconnect_best_effort_continues` and
// `::j4_r03_disconnect_strict_stops`; the "cannot block the wall" property is
// covered by the mutation-provable saturation test above (a stalled-but-open
// consumer is the only case that can block a writer).

/// R03.7: a wall that expires while the consumer is saturated but not yet
/// declared lost is enforced on time (§15 R03). The other wall tests use a 2 s
/// wall, longer than the 1 s no-progress deadline, so the trace loss is
/// declared before the wall fires. Here the run is STRICT (a declared loss
/// would stop the attempt) and the wall is 500 ms — shorter than the 1 s
/// no-progress deadline — with a `Never` consumer and enough events (well over
/// the 4 MiB queue) to saturate the pipe and queue deterministically before
/// the wall. Verdict: the run ends by `wall_expiry` (the target is signalled),
/// on time (a few seconds, far under its 30 s sleep), NOT by an evidence loss
/// — the wall is enforced while the trace is saturated but before the loss is
/// declared. Saturation is guaranteed by the event volume, not timed by a
/// sleep. The enforcement point is the nonblocking external trace fd
/// (`trace.rs FdSink::from_raw_fd set_nonblocking`): a blocking fd hangs the
/// supervision loop on the full pipe and the wall never fires (harness
/// timeout).
#[test]
fn r03_a_wall_expires_before_the_saturation_loss_is_declared() {
    if !common::live() {
        return;
    }
    // Far more than the 4 MiB external queue, so the pipe and queue are full
    // well before the 500 ms wall — saturation is by volume, not by timing.
    let (c, argv) = pressure_case(10_000, 30_000);
    let started = Instant::now();
    let run = c
        .jail
        .trace_consumer(TraceConsumer::Never)
        .args(["--evidence", "strict", "--limit", "wall=500ms"])
        .timeout(Duration::from_secs(90))
        .target(argv)
        .run()
        .unwrap();
    let elapsed = started.elapsed();
    let receipt = last_pressure_receipt(&run);
    // The wall — not the still-undeclared saturation loss — ended the run.
    assert_eq!(
        receipt["outcome"]["cause"], "wall_expiry",
        "under strict, the run ended by something other than the wall (a loss \
         declared before the wall would have stopped it): {receipt:#}"
    );
    assert_eq!(receipt["outcome"]["kind"], "signaled", "{receipt:#}");
    let wall = wall_row(&receipt);
    assert_eq!(
        wall["hit"], true,
        "the wall is not recorded hit: {receipt:#}"
    );
    assert!(
        elapsed < Duration::from_secs(6),
        "the wall fired late while the trace was saturated: {elapsed:?}"
    );
}

/// The latest receipt of a pressure run, schema- and semantic-checked. Unlike
/// `settled`, a best-effort trace loss makes the run exit 1, so this does not
/// require a `settled` phase.
fn last_pressure_receipt(run: &Run) -> Value {
    let validators = common::validators();
    let mut latest = None;
    for receipt in run.receipts() {
        validators["jail-receipt"]
            .validate(&receipt)
            .unwrap_or_else(|error| panic!("a receipt fails its schema: {error}\n{receipt:#}"));
        common::assert_semantic_receipt(&receipt);
        let revision = receipt["revision"].as_u64().unwrap_or(0);
        if latest.as_ref().is_none_or(|(seen, _)| *seen <= revision) {
            latest = Some((revision, receipt));
        }
    }
    latest
        .map(|(_, receipt)| receipt)
        .unwrap_or_else(|| panic!("no receipt; stderr: {}", run.stderr_text()))
}

fn wall_row(receipt: &Value) -> Value {
    receipt["applied"]["limits"]
        .as_array()
        .unwrap_or_else(|| panic!("no applied limits: {receipt:#}"))
        .iter()
        .find(|row| row["key"] == "wall")
        .unwrap_or_else(|| panic!("no wall limit: {receipt:#}"))
        .clone()
}

/// Exactly one `evidence_lost` error: the trace transport loss, recorded once.
fn assert_one_evidence_loss(receipt: &Value) {
    let empty = Vec::new();
    let count = receipt["errors"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|error| error["code"] == "evidence_lost")
        .count();
    assert_eq!(
        count, 1,
        "one loss expected, one evidence_lost error: {:#?}",
        receipt["errors"]
    );
}

/// The captured trace is a recognisable prefix: whole frames, then at most a
/// torn last line — never a torn frame followed by more bytes (which no §13.3
/// writer produces). A saturated write leaves exactly this.
fn assert_recognisable_prefix(run: &Run) {
    let readback = run
        .trace_readback
        .as_ref()
        .expect("a trace fd was captured");
    assert_ne!(
        readback.state,
        ouro_fixture::harness::TraceState::Corrupt,
        "a torn frame was followed by more bytes"
    );
    assert!(!readback.frames.is_empty(), "the prefix has no whole frame");
}

// ===========================================================================
// O03: truncation and unmatched exit produce gaps, never fabricated results
// (§15 O03; tracer/session.rs). Neither the truncation branch (a required
// structure the kernel accepted but the tracer could not read) nor an
// unmatched exit is producible on the stock host without a race, so each is
// driven through a documented tracer seam (session.rs) and asserted through
// `ouro-jail run`. Tagged live-cli: the real tracer runs against a real
// tracee; the seam only manufactures the loss the tracer already records.
// ===========================================================================

/// A `none` run (observation on, best-effort) whose target is the fixture
/// performing one covered `mkdir` on a uniquely-marked path. The tracer seam
/// `env_var` is set to that marker, so it fires on this call and never on the
/// observer capability probe (whose paths do not contain it). Returns the
/// settled receipt (best-effort degrades rather than stopping).
fn o03_run(env_var: &str) -> Option<Value> {
    const MARKER: &str = "o03-marked-target";
    let (jail, _) = none_case("on")?;
    let dir = jail.root().join(MARKER);
    let argv = vec![
        harness::fixture_path().into_os_string(),
        OsString::from("mkdir"),
        dir.into_os_string(),
    ];
    let run = jail
        .env(env_var, MARKER)
        .args(["--evidence", "best-effort"])
        .target(argv)
        .run()
        .expect("the jail runs");
    validate(&run);
    // A recorded gap under best-effort is an evidence loss, so the run is a
    // tool error (exit 1), not a clean settle.
    assert_eq!(
        run.code(),
        Some(1),
        "{env_var}: a run with a recorded gap is a tool error: stderr {}",
        run.stderr_text()
    );
    let receipt = last_pressure_receipt(&run);
    // The seam is recorded in the receipt's native details (S9).
    let seams = &receipt["lifetime"]["native"]["details"]["test_seams"];
    assert!(
        seams[env_var].is_string(),
        "{env_var}: the tracer seam is not recorded: {receipt:#}"
    );
    Some(receipt)
}

/// The (class, gap) for the first coverage class degraded with a gap of
/// `reason`, or a panic naming what was found.
fn degraded_gap(receipt: &Value, reason: &str) -> Value {
    let coverage = receipt["coverage"]
        .as_object()
        .unwrap_or_else(|| panic!("no coverage: {receipt:#}"));
    for (class, entry) in coverage {
        if let Some(gaps) = entry["gaps"].as_array() {
            for gap in gaps {
                if gap["reason"] == reason {
                    assert_eq!(
                        entry["status"], "degraded",
                        "{class}: a class with a {reason} gap is degraded: {entry:#}"
                    );
                    assert_eq!(
                        entry["observed_count"],
                        Value::Null,
                        "{class}: a degraded class has no fabricated count: {entry:#}"
                    );
                    return gap.clone();
                }
            }
        }
    }
    panic!("no {reason} gap in any coverage class: {receipt:#}");
}

/// O03 truncation: a required path the kernel accepted but the tracer could
/// not read becomes a `path_unreadable` gap, never a result. Attempted, live:
/// a `none` run with `OURO_JAIL_TEST_TRACER_TRUNCATE_PATH=1`, whose fixture
/// makes one covered `mkdir` that succeeds. Verdict: the covered call is a
/// `path_unreadable` gap in a degraded coverage class with a null (never
/// fabricated, never zero) count, and one `evidence_lost` error records it.
/// The enforcement point is `self.gap(GapReason::PathUnreadable, ..)` in
/// `session.rs`: deleting it makes the truncated call vanish (no gap, and the
/// class stays active) rather than becoming a gap — verified RED on the host.
#[test]
fn o03_a_truncated_path_is_a_gap_not_a_result() {
    let Some(receipt) = o03_run("OURO_JAIL_TEST_TRACER_TRUNCATE_PATH") else {
        return;
    };
    let gap = degraded_gap(&receipt, "path_unreadable");
    assert!(
        gap["classes"]
            .as_array()
            .is_some_and(|classes| !classes.is_empty()),
        "the gap names no class: {gap}"
    );
    assert_one_evidence_loss(&receipt);
}

/// O03 unmatched exit: a syscall exit with no entry to pair with becomes an
/// `unmatched_exit` gap, never a result. Attempted, live: a `none` run with
/// `OURO_JAIL_TEST_TRACER_UNMATCHED_EXIT=1`, whose fixture makes one covered
/// call whose entry the tracer drops, so its exit is unmatched. Verdict: an
/// `unmatched_exit` gap appears in a degraded coverage class with a null
/// count, and one `evidence_lost` error records it. The enforcement point is
/// `self.gap(GapReason::UnmatchedExit, ..)` in `session.rs` (session.rs
/// ~1463): deleting it makes the unmatched exit silently vanish rather than
/// becoming a gap — verified RED on the host.
#[test]
fn o03_an_unmatched_exit_is_a_gap_not_a_result() {
    let Some(receipt) = o03_run("OURO_JAIL_TEST_TRACER_UNMATCHED_EXIT") else {
        return;
    };
    let _ = degraded_gap(&receipt, "unmatched_exit");
    assert_one_evidence_loss(&receipt);
}

// ===========================================================================
// X06.4: no tracing privilege — ptrace and pidfd_getfd against every process
// the child can address fail (§15 X06; J5-B1 review MEDIUM: the old test never
// called pidfd_getfd and targeted a pid absent from the child's namespace).
// ===========================================================================

/// The Python probe: for every process the child can address (its own /proc,
/// minus itself) and every ancestor up the PPid chain, open a pidfd, try to
/// steal each of its first descriptors with `pidfd_getfd`, and try to seize it
/// with `ptrace(PTRACE_SEIZE)`. Reports one JSON object per target.
const X06_PROBE: &str = r#"
import os, ctypes, json
libc = ctypes.CDLL(None, use_errno=True)
def call(nr, *a):
    ctypes.set_errno(0)
    rc = libc.syscall(nr, *[ctypes.c_long(x) for x in a])
    return [rc, ctypes.get_errno()]
def comm(pid):
    try: return open('/proc/%d/comm' % pid).read().strip()
    except OSError: return '?'
def probe(pid):
    pfd = call(434, pid, 0)              # pidfd_open
    getfd = []
    if pfd[0] >= 0:
        for n in range(0, 6):
            r = call(438, pfd[0], n, 0)  # pidfd_getfd
            getfd.append(0 if r[0] >= 0 else r[1])
            if r[0] >= 0: os.close(r[0])
        os.close(pfd[0])
    pt = call(101, 0x4206, pid, 0, 0)    # ptrace(PTRACE_SEIZE)
    return {'pid': pid, 'comm': comm(pid), 'pidfd_ok': pfd[0] >= 0,
            'getfd_errnos': getfd, 'ptrace_ok': pt[0] >= 0, 'ptrace_errno': pt[1]}
def caps():
    out = {}
    for line in open('/proc/self/status'):
        if line[:3] == 'Cap':
            k, v = line.split(':'); out[k.strip()] = v.strip()
    return out
me = os.getpid()
addressable = [probe(int(d)) for d in os.listdir('/proc') if d.isdigit() and int(d) != me]
ancestors = []; p = os.getppid(); seen = set()
while p > 1 and p not in seen:
    seen.add(p); ancestors.append(probe(p))
    try: p = int(open('/proc/%d/stat' % p).read().split(') ')[1].split()[1])
    except (OSError, IndexError): break
print(json.dumps({'me': me, 'caps': caps(), 'addressable': addressable, 'ancestors': ancestors}))
"#;

/// No CONTAINED target may steal a descriptor or seize a tracer over any
/// process it can address. Verdict, from inside `tool`, `build` and `agent`:
/// `pidfd_getfd` and `ptrace(PTRACE_SEIZE)` fail against every addressable
/// process and every ancestor — the child's `/proc` holds only its own pid
/// namespace (bubblewrap's init, and under `agent` the launcher and bridge),
/// so the supervisor and observer are not even addressable. The
/// mutation-provable anchor is the jail's capability drop: the child's
/// CapEff/CapPrm/CapInh/CapAmb are empty (adding a capability, e.g.
/// `bwrap --cap-add CAP_SYS_PTRACE` with the CapEff check disabled, reddens
/// this — verified on the host). The `pidfd_getfd`/`ptrace` denials themselves
/// are kernel-enforced defence in depth (the user-namespace credential
/// mapping, and the baseline seccomp `ptrace` deny) on top of that empty set.
///
/// `none` is not covered here: it is uncontained, its child shares the host
/// pid namespace, and — as a normal same-uid process — it may legitimately
/// address and even ptrace other same-uid processes (its own descendants, or,
/// depending on the host's ptrace scope, unrelated peers). The X06 guarantee
/// that matters for `none` is that the SUPERVISOR and OBSERVER stay closed to
/// the child, which `r05_the_supervisors_own_proc_is_closed_to_a_same_uid_peer`
/// proves via the `PR_SET_DUMPABLE 0` hardening.
#[test]
fn x06_no_tracing_privilege_reaches_the_child() {
    if !common::live() {
        return;
    }
    for profile in ["tool", "build", "agent"] {
        let c = case(profile);
        let jail = if profile == "build" {
            c.jail.args(["--limit", "mem=64MiB"])
        } else {
            c.jail
        };
        let run = jail.target(py(X06_PROBE)).run().unwrap();
        assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
        let out = py_out(&run);
        // The jail's mechanism: an empty capability set for the child.
        for key in ["CapEff", "CapPrm", "CapInh", "CapAmb"] {
            let value = out["caps"][key].as_str().unwrap_or("?");
            assert!(
                value.trim_matches('0').is_empty(),
                "{profile}: {key} is not empty: {value}"
            );
        }
        assert_no_tracing(profile, &out);
        // Contained: the child's /proc is its own pid namespace only — a small
        // set of low pids; the supervisor/observer (host processes) are absent.
        let pids: Vec<i64> = out["addressable"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["pid"].as_i64().unwrap())
            .collect();
        assert!(
            pids.iter().all(|pid| *pid < 100),
            "{profile}: the child addresses a host pid (supervisor/observer reachable): {pids:?}"
        );
        settled(&run);
    }
}

/// Every probed target (addressable process and ancestor) refused both
/// `pidfd_getfd` (EPERM for every descriptor tried) and `ptrace` (never
/// succeeded). A target may hand out no descriptor and be seized by no tracer.
fn assert_no_tracing(profile: &str, out: &Value) {
    let mut targets: Vec<&Value> = out["addressable"].as_array().unwrap().iter().collect();
    targets.extend(out["ancestors"].as_array().unwrap().iter());
    assert!(
        !targets.is_empty(),
        "{profile}: no target was probed: {out:#}"
    );
    for target in targets {
        assert_eq!(
            target["ptrace_ok"], false,
            "{profile}: ptrace SEIZE succeeded against {}: {target}",
            target["comm"]
        );
        for errno in target["getfd_errnos"].as_array().unwrap() {
            assert_eq!(
                errno.as_i64(),
                Some(i64::from(libc::EPERM)),
                "{profile}: pidfd_getfd did not fail EPERM against {}: {target}",
                target["comm"]
            );
        }
    }
}

// ===========================================================================
// R05.3: forging the receipt, trace and jail state mid-run is outside local
// evidence assurance while the run still ends as it would (§15 R05; §9.3).
// ===========================================================================

/// Attempted, live, `none` (observation on, and — per the J5-B1 review F3 — no
/// external `--trace-fd`, so the trace is kept in the local `trace.ndjson`
/// sink the run actually reads, created at prepare time): the target, the same
/// uid as the supervisor, overwrites the attempt's receipt (`jail.json`),
/// local trace sink (`trace.ndjson`) and jail state (`jail-state.json`) WHILE
/// the run is live — each of which already exists at that moment — then exits
/// 0. Verdict: the run's own outcome is exactly what it would be without the
/// forgery — it settles, exits 0, the tree verifies — and its records still
/// make no protection claim (`unprotected`); no error and no note reports the
/// tampering, because `none` offers no local evidence assurance against a
/// same-uid peer (§9.3: "same-UID interference remains possible ...
/// `unprotected` is never upgraded"). This strengthens
/// `conformance_j3_none.rs::r05_same_uid_tampering...`, which forges only the
/// static `policy.json`. The mutation-provable anchor is the `none`
/// `unprotected` labeling (records.rs `Containment::None => Unprotected`):
/// a build that upgraded `none` to protected reddens the `unprotected`
/// assertion. R05 is about the ABSENCE of assurance, so the test asserts the
/// product does not falsely claim to have detected the forgery.
#[test]
fn r05_forging_records_mid_run_is_outside_local_evidence_assurance() {
    if !none_live() {
        return;
    }
    let jail = Jail::new().expect("a private harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).expect("the workspace");
    let data = jail.data_dir();
    // none, observation on, NO --trace-fd: the trace goes to the local
    // trace.ndjson sink (opened at prepare time), so it exists mid-run and the
    // child forges the file the run really keeps, not a decoy the run ignores.
    let jail = jail
        .arg("run")
        .args(["--profile", "none", "--observe", "on", "--workspace"])
        .arg(&workspace)
        .receipt();
    // The same-uid child recovers the attempt directory (a host path it can
    // see under `none`) and overwrites all three live record files — asserting
    // each existed first — then lives long enough for the supervisor to keep
    // running past the forgery.
    let code = format!(
        "import glob, os, time\n\
         d = glob.glob({data:?} + '/attempts/*/')[0]\n\
         forged = []\n\
         for name, body in [('jail.json', '{{\"forged\":\"receipt\"}}'), \
             ('trace.ndjson', '{{\"forged\":\"trace\"}}\\n'), \
             ('jail-state.json', '{{\"forged\":\"state\"}}')]:\n\
         \x20   p = os.path.join(d, name)\n\
         \x20   existed = os.path.exists(p)\n\
         \x20   open(p, 'w').write(body)\n\
         \x20   forged.append('%s:%s' % (name, existed))\n\
         print('FORGED ' + ' '.join(forged))\n\
         time.sleep(0.3)\n",
        data = data.to_str().unwrap(),
    );
    let run = jail
        .target([PYTHON, "-c", &code])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    // Every forged record existed before the child overwrote it — the forgery
    // hit the files the run actually keeps, not decoys.
    let forged = run
        .stdout_text()
        .lines()
        .find(|line| line.starts_with("FORGED "))
        .unwrap_or_else(|| panic!("the child did not forge: {}", run.stdout_text()))
        .to_owned();
    for name in [
        "jail.json:True",
        "trace.ndjson:True",
        "jail-state.json:True",
    ] {
        assert!(
            forged.contains(name),
            "a forged record did not exist before the forge (a decoy, not a live record): {forged}"
        );
    }
    // The run's own outcome is exactly what it would be without the forgery.
    let receipt = run
        .receipt_phase("settled")
        .unwrap_or_else(|| panic!("no settled receipt: {}", run.stderr_text()));
    let _ = common::checked_receipt(receipt.clone());
    assert_eq!(receipt["outcome"]["kind"], "exited", "{receipt:#}");
    assert_eq!(receipt["outcome"]["code"], 0, "{receipt:#}");
    assert_eq!(receipt["lifetime"]["integrity"], "verified", "{receipt:#}");
    // ...and the records still make no protection claim.
    assert_eq!(receipt["containment"], "none", "{receipt:#}");
    assert_eq!(receipt["child_protection"], "unprotected", "{receipt:#}");
    // Nothing in the product claims to have detected the tampering: R05 is
    // about the absence of assurance, not detection.
    assert!(
        run.receipt_errors().is_empty(),
        "the product raised an error over same-uid tampering it cannot detect: {:?}",
        run.receipt_errors()
    );
    let errors = receipt["errors"].as_array().cloned().unwrap_or_default();
    assert!(
        errors.is_empty(),
        "the settled receipt claims to have detected the forgery: {errors:#?}"
    );
}

// ===========================================================================
// X06.5 / R05.4: the supervisor's own /proc is closed to a same-uid peer
// (§15 X06, R05; §9.3). J5-B1 review F4: without hardening, a `none` child can
// reopen /proc/<supervisor>/fd/<trace,control> and inject into the operator's
// live streams, read the supervisor's environ, and ptrace-seize it — host Yama
// is the only lock. The product now makes the supervisor non-dumpable
// (main.rs PR_SET_DUMPABLE 0), which closes /proc/<pid>/{fd,environ,mem} and
// makes ptrace fail by the kernel's dumpable check, independent of Yama.
// ===========================================================================

/// From inside `none` (where the supervisor is a reachable ancestor) the
/// same-uid target cannot open the supervisor's `/proc/<pid>/environ` or
/// `/proc/<pid>/fd/<n>` (its live trace/control channels), nor `ptrace`-seize
/// it: every attempt fails `EACCES`/`EPERM`. From inside `tool` the supervisor
/// is outside the child's pid namespace and not addressable at all. The lock
/// is the kernel's dumpable check (`PR_SET_DUMPABLE 0` in main.rs), not host
/// Yama — which a peer can waive with `PR_SET_PTRACER`; the reviewer confirmed
/// the failures hold with a supervisor Yama exception (M5) applied. Enforcement
/// point: the `PR_SET_DUMPABLE 0` hunk in main.rs; removing it lets the child
/// read the supervisor's environ and fd and inject into the live streams
/// (verified RED on the host).
#[test]
fn r05_the_supervisors_own_proc_is_closed_to_a_same_uid_peer() {
    if !none_live() {
        return;
    }
    // The child finds the supervisor (comm ouro-jail up the PPid chain), reads
    // the trace/control fd numbers from its cmdline, and tries to open its
    // environ and those fds and to ptrace-seize it.
    const CODE: &str = r#"
import os, ctypes, json
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def comm(p):
    try: return open('/proc/%d/comm' % p).read().strip()
    except OSError: return '?'
def ppid(p):
    return int(open('/proc/%d/stat' % p).read().split(') ')[1].split()[1])
p = os.getppid(); sup = None
while p > 1:
    if comm(p) == 'ouro-jail':
        sup = p; break
    p = ppid(p)
out = {'sup': sup}
def attempt(fn):
    try: fn(); return 'ok'
    except OSError as e: return e.errno
out['environ'] = attempt(lambda: open('/proc/%d/environ' % sup, 'rb').read())
out['fd_dir'] = attempt(lambda: os.listdir('/proc/%d/fd' % sup))
argv = open('/proc/%d/cmdline' % sup, 'rb').read().split(b'\0')
for flag in (b'--trace-fd', b'--control-fd'):
    if flag in argv:
        n = int(argv[argv.index(flag) + 1])
        out[flag.decode()] = attempt(lambda: os.close(os.open('/proc/%d/fd/%d' % (sup, n), os.O_WRONLY)))
ctypes.set_errno(0)
r = libc.syscall(101, 0x4206, sup, 0, 0)  # ptrace(PTRACE_SEIZE, sup)
out['ptrace'] = 'ok' if r >= 0 else ctypes.get_errno()
print(json.dumps(out))
"#;
    // none: the supervisor is reachable, and every access to its /proc fails.
    let (jail, _) = none_case("on").expect("none precondition already checked");
    let run = jail
        .target([PYTHON, "-c", CODE])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(0), "none: {}", run.stderr_text());
    let out = py_out(&run);
    assert!(
        out["sup"].as_i64().is_some(),
        "none: the supervisor was not found up the ancestor chain: {out}"
    );
    // environ and the fd directory are closed (EACCES); the trace/control
    // channels cannot be reopened; ptrace cannot seize the supervisor.
    assert_eq!(
        out["environ"],
        i64::from(libc::EACCES),
        "none: environ readable: {out}"
    );
    assert_eq!(
        out["fd_dir"],
        i64::from(libc::EACCES),
        "none: fd dir readable: {out}"
    );
    for flag in ["--trace-fd", "--control-fd"] {
        if let Some(errno) = out[flag].as_i64() {
            assert_eq!(
                errno,
                i64::from(libc::EACCES),
                "none: {flag} reopened: {out}"
            );
        } else {
            panic!("none: {flag} channel was written, not refused: {out}");
        }
    }
    assert_ne!(
        out["ptrace"], "ok",
        "none: ptrace seized the supervisor: {out}"
    );
    // The forged marks never reach the operator's live streams.
    assert!(
        !String::from_utf8_lossy(&run.trace_bytes).contains("forged"),
        "none: a forged line reached the live trace stream"
    );
    // tool: the supervisor is not even addressable (its host pid is outside
    // the child's pid namespace); the reach the none child had does not exist.
    let c = case("tool");
    let probe = r#"
import os, json
sup = [int(d) for d in os.listdir('/proc') if d.isdigit()
       and (open('/proc/%s/comm' % d).read().strip() if os.path.exists('/proc/%s/comm' % d) else '') == 'ouro-jail']
print(json.dumps({'ouro_jail_pids_visible': sup}))
"#;
    let run = c.jail.target(py(probe)).run().expect("the jail runs");
    assert_eq!(run.code(), Some(0), "tool: {}", run.stderr_text());
    assert_eq!(
        py_out(&run)["ouro_jail_pids_visible"],
        serde_json::json!([]),
        "tool: the supervisor is visible inside the pid namespace"
    );
    settled(&run);
}

// ---------------------------------------------------------------------------
// `none`-specific support (delegated-scope precondition, sibling cgroups)
// ---------------------------------------------------------------------------

/// A `none` invocation over a private workspace, or `None` when this host is
/// not the provisioned reference host with a usable delegated leaf.
fn none_case(observe: &str) -> Option<(Jail, PathBuf)> {
    if !none_live() {
        return None;
    }
    let jail = Jail::new().expect("a private harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).expect("the workspace");
    let jail = jail
        .arg("run")
        .arg("--profile")
        .arg("none")
        .arg("--observe")
        .arg(observe)
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control();
    Some((jail, workspace))
}

/// The delegated-scope precondition the live `none` cases share: the same
/// leaf probe `none`'s tree termination rests on, plus the interpreter.
fn none_live() -> bool {
    if !common::live() {
        return false;
    }
    let leaf = ouro_jail::platform::linux::probe::run_one(
        "cgroup_delegated_leaf",
        &harness::jail_path(),
        Path::new("bwrap"),
    );
    if leaf.status != ouro_jail::platform::linux::probe::ProbeStatus::Available {
        harness::skip_or_fail(&format!(
            "J5 none needs a delegated user scope with a usable leaf: {}",
            leaf.evidence
        ));
        return false;
    }
    if !Path::new(PYTHON).is_file() {
        harness::skip_or_fail("the none fixtures are python3 scripts");
        return false;
    }
    true
}

/// A migration destination beside the attempt's leaf: the same kind of cgroup
/// an uncontained child can create for itself. Emptied and removed on drop,
/// and only ever a cgroup this test created.
struct Destination {
    path: PathBuf,
}

impl Destination {
    fn new(tag: &str) -> Destination {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        // SAFETY: getuid takes no arguments and cannot fail.
        let root = ouro_jail::platform::linux::cgroup::delegated_root(unsafe { libc::getuid() })
            .expect("the delegated subtree exists");
        let path = root.join(format!(
            "ouro-j5b2-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("a destination cgroup");
        Destination { path }
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        // Only processes the attempt moved here: the test made this cgroup.
        let populated = |dir: &Path| {
            std::fs::read_to_string(dir.join("cgroup.events"))
                .unwrap_or_default()
                .lines()
                .any(|line| line == "populated 1")
        };
        if self.path.exists() && populated(&self.path) {
            let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
            let deadline = Instant::now() + Duration::from_secs(5);
            while populated(&self.path) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let _ = std::fs::remove_dir(&self.path);
    }
}
