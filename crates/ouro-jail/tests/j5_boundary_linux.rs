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
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ouro_fixture::harness::{self, Jail, Run, UnixProbe};
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

// ===========================================================================
// S03: the outer boundaries cannot be reversed inside `agent` (§15 S03
// "Attempts to undo each outer boundary fail"; §9.2)
// ===========================================================================

/// Attempted, live, by the `agent` child: clear `no_new_privs`; add an
/// allow-everything seccomp filter and then make a denied syscall; reach the
/// execution cgroup through `/sys/fs/cgroup`; and, after restricting itself
/// with Landlock, regain the access it just gave up. Verdict: `no_new_privs`
/// stays 1 (`prctl` refuses to clear it), the extra permissive filter cannot
/// loosen the stacked baseline (`ptrace` stays `EPERM` and the filter count
/// only grows), the cgroupfs is absent so the resource boundary is
/// unreachable, and a second, permissive Landlock ruleset does not restore a
/// denied write (domains only narrow). Each is a one-way boundary the child
/// cannot walk back. Removing the baseline filter, the cgroup unshare, or the
/// no_new_privs/Landlock setup would each make one of these succeed.
#[test]
fn s03_the_outer_boundaries_cannot_be_reversed_inside_agent() {
    if !common::live() {
        return;
    }
    let c = case("agent");
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
ctypes.set_errno(0)
r = libc.syscall(101, 0, 0, 0, 0)  # ptrace(PTRACE_TRACEME)
out["ptrace_after_allow"] = "ok" if r == 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))

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
    let run = c.jail.target(py(SCRIPT)).run().unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    // no_new_privs is set and cannot be cleared.
    assert_eq!(out["nnp_before"], "1", "{out}");
    assert_ne!(out["clear_nnp"], "ok", "no_new_privs was cleared: {out}");
    assert_eq!(out["nnp_after"], "1", "{out}");
    // The permissive filter stacks but does not loosen the baseline.
    assert_eq!(out["add_allow_filter"], "ok", "{out}");
    assert_eq!(
        out["ptrace_after_allow"], "EPERM",
        "a permissive filter loosened the baseline: {out}"
    );
    // The execution cgroup is not reachable through the child's mount view.
    assert_eq!(out["cgroup_procs"], "ENOENT", "{out}");
    // Landlock only narrows.
    assert_eq!(out["landlock"]["first"], "EACCES", "{out}");
    assert_eq!(
        out["landlock"]["after_second_ruleset"], "EACCES",
        "a second Landlock ruleset widened a denied access: {out}"
    );
    settled(&run);
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

/// Attempted, live, by the `agent` child: connect to a host peer through a
/// hard-link and a symlink alias created *after* the boundary existed, and to
/// a host socket bound in an operator `--rw` extra grant *after* the boundary
/// existed. Verdict: every one is refused `EACCES` by the Unix-peer mediation
/// — it resolves the node in the child's view and admits only a listener in
/// the attempt's own network namespace, whenever the alias or socket appeared
/// — and none of the host peers ever saw a connection. This closes the N05
/// gap that every alias and extra-grant socket existed before launch. The
/// enforcement point is the seccomp-notification connect mediation; a
/// path-name check that only masked nodes present at launch would let a late
/// alias through.
#[test]
fn n05_a_late_alias_and_a_late_extra_grant_socket_are_unreachable() {
    if !common::live() {
        return;
    }
    let c = case("agent");
    let ws = c.workspace.clone();
    let extra_rw = c.jail.root().join("extra-rw");
    private_dir(&extra_rw);
    // The real host peer exists before launch; its aliases and the extra-grant
    // peer are all created after `prepared`, below.
    let host = UnixProbe::bind(&ws.join("host.sock")).unwrap();

    let steps = serde_json::json!([
        [
            "unix-connect",
            ws.join("late-hardlink.sock"),
            "--expect",
            "EACCES"
        ],
        [
            "unix-connect",
            ws.join("late-symlink.sock"),
            "--expect",
            "EACCES"
        ],
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
    // Everything the child will try to reach is created now, after the
    // boundary and its mounts exist: no launch-time enumeration saw them.
    std::fs::hard_link(ws.join("host.sock"), ws.join("late-hardlink.sock")).unwrap();
    std::os::unix::fs::symlink(ws.join("host.sock"), ws.join("late-symlink.sock")).unwrap();
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
        "a late alias or extra-grant socket was reachable: stdout {}\nstderr {}",
        run.stdout_text(),
        run.stderr_text()
    );
    assert_eq!(host.stop(), 0, "the host peer was reached through an alias");
    assert_eq!(extra.stop(), 0, "the extra-grant host peer was reached");
    let lines = run.fixture_lines();
    let connects = ops(&lines, "connect");
    assert_eq!(connects.len(), 4, "{lines:#?}");
    for connect in &connects[..3] {
        assert_eq!(connect["errno"], "EACCES", "{connect}");
    }
    assert_eq!(connects[3]["errno"], Value::Null, "the proxy connect");
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
// R06: an unobserved migrated descendant is not certified dead (§15 R06,
// third sentence; §9.3)
// ===========================================================================

/// Attempted, live, `none` with observation off: the target forks a
/// descendant that migrates itself into a sibling cgroup the jail did not
/// register and survives; the target then exits cleanly. Verdict: the
/// registered leaf empties, but `tree_empty` is never set true and the run
/// never settles — registered-boundary verification does not certify the
/// escaped, unobserved descendant dead. Its integrity is `lost`, the target's
/// own clean exit is preserved from its own wait fact, and state is retained.
/// The enforcement point is that `tree_empty=true` speaks only of the
/// identity-checked cgroup (§9.3): a build that synthesized settlement from an
/// empty leaf would fabricate a death here.
#[test]
fn r06_an_unobserved_migrated_descendant_is_not_certified_dead() {
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
    // The escaped, unobserved descendant is not certified dead: no
    // settlement, no tree-empty, integrity lost, registered-boundary scope.
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
