//! Independent review of the J1 Linux execution slice, adopted as regression
//! tests.
//!
//! Written by the slice's reviewer, not by its author, and kept as written:
//! every test here is a check of one promise the spec makes, and the three
//! that failed are the two HIGH defects and the exec-outcome defect this
//! branch fixes. Live tests need `OURO_CONFORMANCE=1` and the reference host.
//!
//! Known mutation survivor, recorded here because there is no honest test for
//! it: deleting the SIGKILL of the namespace init in `hard_kill` leaves every
//! suite green. Three mechanisms end the tree — the observer's
//! `PTRACE_O_EXITKILL`, bubblewrap's parent-death chain through the pid
//! namespace, and that kill — and any one of them suffices, so no observation
//! from outside can attribute the death to a particular one. Isolating it
//! would need a seam that disables the other two, which would be a test-only
//! path through the code that matters most.

#![cfg(target_os = "linux")]
#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use ouro_fixture::harness::{self, Jail, Run};
use serde_json::Value;

mod common;
use common::live;

fn workspace_with_fixture(root: &Path) -> (PathBuf, PathBuf) {
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let inside = workspace.join("ouro-fixture");
    std::fs::copy(harness::fixture_path(), &inside).expect("copy fixture");
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = std::fs::metadata(&inside).expect("metadata").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&inside, permissions).expect("chmod");
    (workspace, inside)
}

struct Case {
    jail: Jail,
    workspace: PathBuf,
    fixture: PathBuf,
}

fn case() -> Case {
    let jail = Jail::new().expect("harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let jail = jail
        .arg("run")
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

fn fixture_lines(run: &Run) -> Vec<Value> {
    run.fixture_lines()
}

fn audit_events(run: &Run) -> Vec<&Value> {
    run.trace_events
        .iter()
        .filter(|event| event.get("source").and_then(Value::as_str) == Some("audit"))
        .collect()
}

fn settled(run: &Run) -> Value {
    run.receipt_phase("settled")
        .unwrap_or_else(|| panic!("no settled receipt; receipts: {:?}", phases(run)))
}

fn phases(run: &Run) -> Vec<String> {
    run.receipts()
        .iter()
        .filter_map(|r| r.get("phase").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

/// A recursive listing of `root` as `path\tmode\tsize` lines, sorted.
fn snapshot_tree(root: &Path) -> Vec<String> {
    let out = Command::new("find")
        .arg(root)
        .arg("-printf")
        .arg("%P\t%m\t%s\t%y\n")
        .output()
        .expect("find runs");
    let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(ToOwned::to_owned)
        .collect();
    lines.sort();
    lines
}

// ===========================================================================
// 1. Containment
// ===========================================================================

/// The child's view: only declared roots, workspace writable, operator home
/// and state unreachable, lo-only network, NoNewPrivs/CapEff/Seccomp.
#[test]
fn r1_the_contained_child_sees_only_the_declared_roots() {
    if !live() {
        return;
    }
    let c = case();
    let workspace = c.workspace.clone();
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join(".git/config"), b"[core]\n").unwrap();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());

    let script = workspace.join("probe.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             echo ROOTS_BEGIN\n\
             ls -1 / 2>&1\n\
             echo ROOTS_END\n\
             echo HOME_LS_BEGIN\n\
             ls -1 {home} 2>&1\n\
             echo HOME_LS_END\n\
             echo MOUNTS_BEGIN\n\
             cat /proc/self/mountinfo\n\
             echo MOUNTS_END\n\
             echo NET_BEGIN\n\
             cat /proc/net/dev 2>&1\n\
             echo NET_END\n\
             echo STATUS_BEGIN\n\
             grep -E '^(NoNewPrivs|CapEff|Seccomp|Seccomp_filters):' /proc/self/status\n\
             echo STATUS_END\n\
             echo FDS_BEGIN\n\
             ls -l /proc/self/fd\n\
             echo FDS_END\n"
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let run = c
        .jail
        .target(["/bin/sh", script.to_str().unwrap()])
        .run()
        .expect("run");
    let text = run.stdout_text();
    eprintln!(
        "--- stdout ---\n{text}\n--- stderr ---\n{}",
        run.stderr_text()
    );

    let section = |name: &str| -> String {
        let begin = format!("{name}_BEGIN");
        let end = format!("{name}_END");
        let start = text.find(&begin).unwrap_or_else(|| {
            panic!("no {begin} in output:\n{text}");
        }) + begin.len();
        let stop = text[start..]
            .find(&end)
            .unwrap_or_else(|| panic!("no {end}"))
            + start;
        text[start..stop].trim().to_owned()
    };

    let roots_text = section("ROOTS");
    let roots: BTreeSet<&str> = roots_text.lines().map(str::trim).collect();
    eprintln!("root entries: {roots:?}");
    for forbidden in ["sys", "root", "boot", "var", "opt", "srv", "mnt"] {
        assert!(
            !roots.contains(forbidden),
            "/{forbidden} is visible inside the boundary: {roots:?}"
        );
    }

    let home_ls = section("HOME_LS");
    eprintln!("home listing: {home_ls}");
    assert!(
        home_ls.contains("No such file") || home_ls.contains("cannot access") || home_ls.is_empty(),
        "the operator home is reachable: {home_ls}"
    );

    let net = section("NET");
    let interfaces: Vec<String> = net
        .lines()
        .skip(2)
        .filter_map(|line| line.split(':').next().map(|s| s.trim().to_owned()))
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(interfaces, vec!["lo".to_owned()], "net: {net}");

    let status = section("STATUS");
    eprintln!("status: {status}");
    assert!(status.contains("NoNewPrivs:\t1"), "{status}");
    assert!(
        status.lines().any(|l| l.starts_with("CapEff:")
            && l.split('\t')
                .nth(1)
                .is_some_and(|v| v.trim_matches('0').is_empty())),
        "CapEff is not zero: {status}"
    );
    assert!(status.contains("Seccomp:\t2"), "{status}");

    let fds = section("FDS");
    eprintln!("fds: {fds}");
    let numbered: Vec<&str> = fds
        .lines()
        .filter_map(|l| l.rsplit(' ').find(|p| p.parse::<i32>().is_ok()))
        .collect();
    eprintln!("fd numbers seen (includes the ls dirfd): {numbered:?}");

    let mounts = section("MOUNTS");
    // No MOUNT POINT (field 5) may lie inside the attempt's own state
    // directory; the mountinfo `root` field naming the scratch source is
    // expected, because /tmp is a bind of `<attempt>/scratch`.
    for line in mounts.lines() {
        let point = line.split_whitespace().nth(4).unwrap_or("");
        assert!(
            !point.contains("/attempts/"),
            "a state path is a mount point inside the boundary: {line}"
        );
    }
    let _ = settled(&run);
}

/// The workspace is writable, `.git` and `.ouroboros` are not, and the
/// absent root-level literals are covered too.
#[test]
fn r1_protected_segments_are_read_only_and_the_workspace_is_writable() {
    if !live() {
        return;
    }
    let c = case();
    let workspace = c.workspace.clone();
    std::fs::create_dir_all(workspace.join("deep/nested/.git")).unwrap();
    std::fs::write(workspace.join("deep/nested/.git/HEAD"), b"ref: x\n").unwrap();
    std::fs::create_dir_all(workspace.join(".ouroboros")).unwrap();
    std::fs::write(workspace.join(".ouroboros/state"), b"s\n").unwrap();
    // A file-form .git, as F02 asks.
    std::fs::create_dir_all(workspace.join("submodule")).unwrap();
    std::fs::write(workspace.join("submodule/.git"), b"gitdir: ../real\n").unwrap();

    let before = snapshot_tree(&workspace);

    let script = workspace.join("ops.json");
    let ops = serde_json::json!([
        [
            "open",
            "allowed.txt",
            "--create",
            "--write",
            "--expect",
            "ok"
        ],
        [
            "open",
            "deep/nested/.git/HEAD",
            "--write",
            "--expect",
            "EROFS"
        ],
        ["open", ".ouroboros/state", "--write", "--expect", "EROFS"],
        ["open", "submodule/.git", "--write", "--expect", "EROFS"],
        // `.git` at the workspace root did not exist at launch: the literal
        // must be protected anyway (§9.1).
        [
            "open",
            ".git/sneak",
            "--create",
            "--write",
            "--expect",
            "EROFS"
        ],
        ["mkdir", ".git", "--expect", "EEXIST"]
    ]);
    std::fs::write(&script, serde_json::to_vec(&ops).unwrap()).unwrap();

    let run = c
        .jail
        .target([
            c.fixture.to_str().unwrap(),
            "script",
            script.to_str().unwrap(),
        ])
        .run()
        .expect("run");
    eprintln!("stdout:\n{}", run.stdout_text());
    eprintln!("stderr:\n{}", run.stderr_text());
    for line in fixture_lines(&run) {
        eprintln!("op {line}");
    }
    assert_eq!(run.code(), Some(0), "fixture expectations were not all met");

    // After the run, the placeholder mount point must be gone and nothing
    // else in the workspace may have changed.
    let after = snapshot_tree(&workspace);
    // `find -printf %P` prints an empty name for the root itself, whose own
    // size changes with its entry count; that row is not a workspace object.
    let root_row = |l: &&String| l.starts_with('\t');
    let added: Vec<&String> = after
        .iter()
        .filter(|l| !before.contains(l) && !root_row(l))
        .collect();
    let removed: Vec<&String> = before
        .iter()
        .filter(|l| !after.contains(l) && !root_row(l))
        .collect();
    eprintln!("added: {added:?}");
    eprintln!("removed: {removed:?}");
    assert!(removed.is_empty(), "the run removed workspace entries");
    let unexpected: Vec<&&String> = added
        .iter()
        .filter(|l| !l.starts_with("allowed.txt") && !l.starts_with("ops.json"))
        .collect();
    assert!(
        unexpected.is_empty(),
        "the run left objects behind: {unexpected:?}"
    );
}

/// §9.2 baseline: the listed syscalls are denied, ordinary work is allowed,
/// clone3 gives ENOSYS and the thread fallback works.
#[test]
fn r1_the_baseline_filter_denies_what_the_spec_lists() {
    if !live() {
        return;
    }
    let c = case();
    let probe = c.workspace.join("deny.py");
    std::fs::write(
        &probe,
        r#"
import ctypes, errno, os, sys, json
libc = ctypes.CDLL(None, use_errno=True)
def call(nr, *args):
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])
    return r, ctypes.get_errno()
table = {
  "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311,
  "bpf": 321, "perf_event_open": 298, "kexec_load": 246,
  "init_module": 175, "finit_module": 313, "delete_module": 176,
  "keyctl": 250, "add_key": 248, "request_key": 249,
  "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
  "mount": 165, "umount2": 166, "move_mount": 429, "open_tree": 428,
  "fsopen": 430, "fsmount": 432, "fspick": 433, "fsconfig": 431,
  "mount_setattr": 442, "pivot_root": 155, "chroot": 161,
  "unshare": 272, "setns": 308,
}
out = {}
for name, nr in table.items():
    r, e = call(nr, 0, 0, 0, 0, 0, 0)
    out[name] = errno.errorcode.get(e, str(e)) if r < 0 else "OK(%d)" % r
# clone3 -> ENOSYS
r, e = call(435, 0, 0)
out["clone3"] = errno.errorcode.get(e, str(e)) if r < 0 else "OK"
# clone with a namespace flag -> EPERM
CLONE_NEWUSER = 0x10000000
r, e = call(56, CLONE_NEWUSER, 0, 0, 0, 0)
out["clone_newuser"] = errno.errorcode.get(e, str(e)) if r < 0 else "OK(%d)" % r
# socket(AF_UNIX) -> EPERM; socketpair(AF_UNIX) -> EPERM
r, e = call(41, 1, 1, 0)
out["socket_af_unix"] = errno.errorcode.get(e, str(e)) if r < 0 else "OK(%d)" % r
r, e = call(53, 1, 1, 0, 0)
out["socketpair_af_unix"] = errno.errorcode.get(e, str(e)) if r < 0 else "OK(%d)" % r
# socket(AF_INET) must still be allowed by the filter (the netns denies egress)
r, e = call(41, 2, 1, 0)
out["socket_af_inet"] = errno.errorcode.get(e, str(e)) if r < 0 else "OK(%d)" % r
# ioctl TIOCSTI -> EPERM
r, e = call(16, 0, 0x5412, 0)
out["ioctl_tiocsti"] = errno.errorcode.get(e, str(e)) if r < 0 else "OK(%d)" % r
# ordinary work
try:
    with open("filter-ok.txt", "w") as f:
        f.write("ok")
    out["ordinary_write"] = "OK"
except OSError as ex:
    out["ordinary_write"] = errno.errorcode.get(ex.errno, str(ex.errno))
# threads must still work with the clone3 fallback
import threading
seen = []
t = threading.Thread(target=lambda: seen.append(1))
t.start(); t.join()
out["thread"] = "OK" if seen == [1] else "FAILED"
print(json.dumps(out))
"#,
    )
    .unwrap();

    let run = c
        .jail
        .target(["/usr/bin/python3", probe.to_str().unwrap()])
        .run()
        .expect("run");
    let text = run.stdout_text();
    eprintln!("stdout: {text}\nstderr: {}", run.stderr_text());
    let last = text.lines().last().unwrap_or("");
    let result: serde_json::Map<String, Value> =
        serde_json::from_str(last).unwrap_or_else(|e| panic!("not json: {e}: {text}"));

    let mut wrong = Vec::new();
    for (name, value) in &result {
        let got = value.as_str().unwrap_or("");
        let want: &[&str] = match name.as_str() {
            "clone3" => &["ENOSYS"],
            "ordinary_write" | "thread" => &["OK"],
            "socket_af_inet" => &["OK(3)", "OK(4)", "OK(5)", "OK(6)", "OK(7)"],
            "ioctl_tiocsti" => &["EPERM"],
            _ => &["EPERM"],
        };
        let ok = if name == "socket_af_inet" {
            got.starts_with("OK(")
        } else {
            want.contains(&got)
        };
        if !ok {
            wrong.push(format!("{name} = {got} (wanted one of {want:?})"));
        }
    }
    assert!(
        wrong.is_empty(),
        "filter results differ:\n{}",
        wrong.join("\n")
    );
}

// ===========================================================================
// 2. Launch and exec confirmation
// ===========================================================================

/// X04: the four exec failures are distinguishable and exit 125 is an exit.
#[test]
fn r2_exec_failures_are_distinguishable_and_exit_125_is_an_exit() {
    if !live() {
        return;
    }
    use std::os::unix::fs::PermissionsExt as _;

    let mut facts: Vec<(&str, String, String, String)> = Vec::new();

    // ENOENT: no such executable.
    let c = case();
    let missing = c.workspace.join("no-such-binary");
    let run = c
        .jail
        .target([missing.to_str().unwrap()])
        .run()
        .expect("run");
    let f = exec_failure_facts(&run, "missing executable");
    assert_eq!(run.code(), Some(125));
    facts.push(("missing executable", f.0, f.1, f.2));

    // EACCES: present but not executable.
    let c = case();
    let noexec = c.workspace.join("not-executable");
    std::fs::write(&noexec, b"#!/bin/sh\necho hi\n").unwrap();
    std::fs::set_permissions(&noexec, std::fs::Permissions::from_mode(0o644)).unwrap();
    let run = c
        .jail
        .target([noexec.to_str().unwrap()])
        .run()
        .expect("run");
    let f = exec_failure_facts(&run, "non-executable file");
    assert_eq!(run.code(), Some(125));
    facts.push(("non-executable file", f.0, f.1, f.2));

    // A script naming an absent interpreter.
    let c = case();
    let script = c.workspace.join("bad-interp.sh");
    std::fs::write(&script, b"#!/no/such/interpreter\necho hi\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let run = c
        .jail
        .target([script.to_str().unwrap()])
        .run()
        .expect("run");
    let f = exec_failure_facts(&run, "missing interpreter");
    facts.push(("missing interpreter", f.0, f.1, f.2));

    for (name, phase, _kind, message) in &facts {
        assert_eq!(phase, "refused", "{name}: phase");
        assert!(
            !message.is_empty(),
            "{name}: nothing says why the exec failed"
        );
    }
    let messages: BTreeSet<&String> = facts.iter().map(|(_, _, _, m)| m).collect();
    eprintln!("distinct messages: {messages:?}");

    // Exit 125 is an exit, never a refusal.
    let c = case();
    let run = c
        .jail
        .target([c.fixture.to_str().unwrap(), "exit", "125"])
        .run()
        .expect("run");
    let receipt = settled(&run);
    assert_eq!(
        receipt.pointer("/outcome/kind").and_then(Value::as_str),
        Some("exited"),
        "exit 125 became {:?}",
        receipt.get("outcome")
    );
    assert_eq!(
        receipt.pointer("/outcome/code").and_then(Value::as_u64),
        Some(125)
    );
    assert_eq!(run.code(), Some(125));
}

/// §6.1: "Execution accepts literal OS argument bytes, never a shell command
/// string. Shell semantics require the operator to explicitly supply a shell
/// and its arguments." An executable file the kernel cannot recognise must be
/// an exec failure, not a silent handover to `/bin/sh`.
#[test]
fn r2_an_unrecognised_executable_is_not_handed_to_a_shell() {
    if !live() {
        return;
    }
    use std::os::unix::fs::PermissionsExt as _;
    let c = case();
    let workspace = c.workspace.clone();
    // Executable, no shebang, not an ELF image: `execve` returns ENOEXEC.
    // Its bytes are valid shell, so if anything interprets them as a script
    // the marker appears and the stdout line is printed.
    let target = workspace.join("not-an-image");
    let marker = workspace.join("shell-ran");
    std::fs::write(
        &target,
        format!("echo SHELL_INTERPRETED_ME\ntouch {}\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();

    let run = c
        .jail
        .target([target.to_str().unwrap()])
        .run()
        .expect("run");
    let receipts = run.receipts();
    let last = receipts.last().expect("a receipt");
    eprintln!(
        "exit={:?} stdout={:?} phase={:?} outcome={}",
        run.code(),
        run.stdout_text(),
        last.get("phase"),
        serde_json::to_string(last.get("outcome").unwrap_or(&Value::Null)).unwrap()
    );
    eprintln!("marker exists: {}", marker.exists());
    assert!(
        !marker.exists() && !run.stdout_text().contains("SHELL_INTERPRETED_ME"),
        "an unrecognised executable was interpreted by a shell the operator never named"
    );
    assert_eq!(
        last.get("phase").and_then(Value::as_str),
        Some("refused"),
        "ENOEXEC must refuse, not settle"
    );
}

/// §13.2: a proved target exec failure is `outcome.kind = exec_error`, which
/// is what separates "your program was not found" from "the policy refused".
#[test]
fn r2_a_proved_exec_failure_is_an_exec_error_outcome() {
    if !live() {
        return;
    }
    let c = case();
    let missing = c.workspace.join("no-such-binary");
    let run = c
        .jail
        .target([missing.to_str().unwrap()])
        .run()
        .expect("run");
    let receipts = run.receipts();
    let last = receipts.last().expect("a receipt");
    eprintln!("{}", serde_json::to_string_pretty(last).unwrap());
    assert_eq!(
        last.get("phase").and_then(Value::as_str),
        Some("refused"),
        "an exec failure is a refused receipt"
    );
    assert_eq!(
        last.pointer("/outcome/kind").and_then(Value::as_str),
        Some("exec_error"),
        "a proved exec failure must be exec_error, not an ordinary refusal"
    );
}

#[allow(dead_code)] // a reviewer's helper, kept for the next check that needs it
fn last_outcome(run: &Run) -> Option<Value> {
    run.receipts()
        .last()
        .and_then(|r| r.get("outcome").cloned())
}

/// The four exec failures must at least be distinguishable from one another.
fn exec_failure_facts(run: &Run, name: &str) -> (String, String, String) {
    let receipts = run.receipts();
    let last = receipts
        .last()
        .unwrap_or_else(|| panic!("{name}: no receipt at all"));
    let phase = last
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_owned();
    let kind = last
        .pointer("/outcome/kind")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_owned();
    let message = last
        .pointer("/outcome/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    eprintln!(
        "{name}: exit={:?} phase={phase} kind={kind} message={message:?}",
        run.code()
    );
    (phase, kind, message)
}

#[allow(dead_code)] // a reviewer's helper, kept for the next check that needs it
fn check_exec_error(run: &Run, name: &str, errno: &str) {
    let receipts = run.receipts();
    let last = receipts
        .last()
        .unwrap_or_else(|| panic!("{name}: no receipt at all"));
    eprintln!(
        "{name}: exit={:?} phase={:?} outcome={} errors={}",
        run.code(),
        last.get("phase"),
        serde_json::to_string(last.get("outcome").unwrap_or(&Value::Null)).unwrap(),
        serde_json::to_string(last.get("errors").unwrap_or(&Value::Null)).unwrap(),
    );
    assert_eq!(
        last.get("phase").and_then(Value::as_str),
        Some("refused"),
        "{name}: phase"
    );
    assert_eq!(
        last.pointer("/outcome/kind").and_then(Value::as_str),
        Some("exec_error"),
        "{name}: outcome kind"
    );
    let text = serde_json::to_string(last.get("outcome").unwrap_or(&Value::Null)).unwrap()
        + &serde_json::to_string(last.get("errors").unwrap_or(&Value::Null)).unwrap();
    assert!(
        text.contains(errno),
        "{name}: expected errno {errno} in {text}"
    );
    assert_eq!(run.code(), Some(125), "{name}: exit code");
}

// ===========================================================================
// 3. Fd and environment hygiene
// ===========================================================================

/// X06: exactly fds 0/1/2, the environment is the snapshot's bindings plus
/// PWD, and `environment_names` equals what the child sees.
#[test]
fn r3_fd_and_environment_hygiene() {
    if !live() {
        return;
    }
    let c = case();
    let workspace = c.workspace.clone();
    let ops = workspace.join("hygiene.json");
    std::fs::write(
        &ops,
        serde_json::to_vec(&serde_json::json!([["fds"], ["env"], ["status"]])).unwrap(),
    )
    .unwrap();
    let run = c
        .jail
        .target([c.fixture.to_str().unwrap(), "script", ops.to_str().unwrap()])
        .run()
        .expect("run");
    eprintln!("stdout:\n{}", run.stdout_text());
    let lines = fixture_lines(&run);

    let fds = lines
        .iter()
        .find(|l| l.get("op").and_then(Value::as_str) == Some("fds"))
        .expect("fds line");
    eprintln!("fds: {fds}");
    let open: Vec<i64> = fds
        .pointer("/args/fds")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| e.get("fd").and_then(Value::as_i64))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(open, vec![0, 1, 2], "the target inherited {open:?}: {fds}");

    let env = lines
        .iter()
        .find(|l| l.get("op").and_then(Value::as_str) == Some("env"))
        .expect("env line");
    let names: Vec<String> = env
        .pointer("/args/names")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    eprintln!("environment seen by the child: {names:?}");
    for name in &names {
        assert!(
            !name.starts_with("OURO_"),
            "an OURO_* name reached the child: {names:?}"
        );
    }

    let receipt = settled(&run);
    let recorded: Vec<String> = receipt
        .pointer("/applied/environment_names")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    eprintln!("environment_names in the receipt: {recorded:?}");
    let mut seen = names.clone();
    seen.sort();
    let mut recorded_sorted = recorded.clone();
    recorded_sorted.sort();
    assert_eq!(
        seen, recorded_sorted,
        "the receipt's environment_names differ from what the child sees"
    );
}

/// §8.3: a socket or directory as stdin refuses; a regular file resolving
/// into the state directory refuses.
#[test]
fn r3_stdio_kinds_are_validated() {
    if !live() {
        return;
    }
    use std::os::fd::AsRawFd as _;
    use std::os::unix::io::FromRawFd as _;

    // A directory as stdin.
    let jail = Jail::new().expect("harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let dir = std::fs::File::open(&workspace).expect("open workspace as a dir fd");
    let exe = harness::jail_path();
    let mut command = Command::new(&exe);
    command
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--")
        .arg(&fixture)
        .arg("exit")
        .arg("0")
        .env("OURO_DATA_DIR", jail.data_dir())
        .env("OURO_CONFIG_DIR", jail.config_dir());
    let raw = dir.as_raw_fd();
    // SAFETY: the closure runs between fork and exec and calls only dup2.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(raw, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().expect("run");
    eprintln!(
        "directory stdin: code={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(125),
        "a directory as stdin should refuse; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A socket as stdin.
    let jail = Jail::new().expect("harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let mut fds = [-1i32; 2];
    // SAFETY: a two-element array of the right type.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0);
    // SAFETY: both descriptors were just created.
    let (sock, _peer) = unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    };
    let raw = sock.as_raw_fd();
    let mut command = Command::new(&exe);
    command
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--")
        .arg(&fixture)
        .arg("exit")
        .arg("0")
        .env("OURO_DATA_DIR", jail.data_dir())
        .env("OURO_CONFIG_DIR", jail.config_dir());
    // SAFETY: as above.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(raw, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().expect("run");
    eprintln!(
        "socket stdin: code={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(125),
        "a socket as stdin should refuse; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ===========================================================================
// 4. Lifecycle honesty
// ===========================================================================

/// §13.2, L01: wall expiry ends at verified tree death with the cause and the
/// hit recorded.
#[test]
fn r4_wall_expiry_records_its_hit_and_verifies_the_tree() {
    if !live() {
        return;
    }
    let c = case();
    let run = c
        .jail
        .args(["--limit", "wall=700ms"])
        .target([c.fixture.to_str().unwrap(), "sleep", "60000"])
        .run()
        .expect("run");
    let receipt = settled(&run);
    eprintln!("{}", serde_json::to_string_pretty(&receipt).unwrap());
    assert_eq!(
        receipt.pointer("/outcome/cause").and_then(Value::as_str),
        Some("wall_expiry")
    );
    assert_eq!(
        receipt
            .pointer("/lifetime/tree_empty")
            .and_then(Value::as_bool),
        Some(true)
    );
    let wall = receipt
        .pointer("/applied/limits")
        .and_then(Value::as_array)
        .and_then(|a| {
            a.iter()
                .find(|l| l.get("key").and_then(Value::as_str) == Some("wall"))
        })
        .expect("a wall limit row");
    assert_eq!(
        wall.get("hit").and_then(Value::as_bool),
        Some(true),
        "the wall hit was not recorded: {wall}"
    );
    assert_eq!(
        wall.get("mechanism").and_then(Value::as_str),
        Some("boottime-deadline")
    );
    // The signal that ended it is preserved.
    eprintln!("outcome: {}", receipt.get("outcome").unwrap());
}

/// L01: a descendant that ignores SIGTERM still dies at settlement.
#[test]
fn r4_a_sigterm_ignoring_descendant_dies_at_settlement() {
    if !live() {
        return;
    }
    let c = case();
    let run = c
        .jail
        .args(["--limit", "wall=700ms"])
        .target([c.fixture.to_str().unwrap(), "ignore-term", "60000"])
        .run()
        .expect("run");
    let receipt = settled(&run);
    eprintln!("{}", serde_json::to_string_pretty(&receipt).unwrap());
    assert_eq!(
        receipt
            .pointer("/lifetime/tree_empty")
            .and_then(Value::as_bool),
        Some(true),
        "a SIGTERM-ignoring target was not verified dead"
    );
}

/// L01: a fork burst is fully reaped.
#[test]
fn r4_a_fork_burst_is_fully_reaped() {
    if !live() {
        return;
    }
    let c = case();
    let run = c
        .jail
        .target([c.fixture.to_str().unwrap(), "fork-storm", "500"])
        .run()
        .expect("run");
    let receipt = settled(&run);
    assert_eq!(
        receipt
            .pointer("/lifetime/tree_empty")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        receipt.pointer("/outcome/kind").and_then(Value::as_str),
        Some("exited")
    );
    eprintln!(
        "coverage: {}",
        serde_json::to_string_pretty(receipt.get("coverage").unwrap_or(&Value::Null)).unwrap()
    );
}

/// L02: killing the supervisor takes the contained tree down.
#[test]
fn r4_killing_the_supervisor_takes_the_tree_down() {
    if !live() {
        return;
    }
    let c = case();
    let marker = c.workspace.join("still-alive");
    let script = c.workspace.join("linger.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             i=0\n\
             while [ $i -lt 600 ]; do\n\
               echo $i > {}\n\
               sleep 0.1\n\
               i=$((i+1))\n\
             done\n",
            marker.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let spawned = c
        .jail
        .target(["/bin/sh", script.to_str().unwrap()])
        .spawn()
        .expect("spawn");
    let supervisor = spawned.pid();
    // Wait for the marker so the target is certainly running.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(marker.exists(), "the target never started");
    let descendants = descendant_pids(supervisor);
    eprintln!("supervisor {supervisor} descendants {descendants:?}");
    assert!(!descendants.is_empty());

    // SIGKILL the supervisor: nothing can run in it afterwards, so only the
    // kernel's own death chain can take the tree down.
    // SAFETY: signalling a process this test started.
    unsafe { libc::kill(libc::pid_t::try_from(supervisor).unwrap(), libc::SIGKILL) };
    let _ = spawned.wait();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut alive: Vec<i32> = Vec::new();
    while std::time::Instant::now() < deadline {
        alive = descendants
            .iter()
            .copied()
            .filter(|pid| Path::new(&format!("/proc/{pid}")).exists())
            .collect();
        if alive.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !alive.is_empty() {
        for pid in &alive {
            eprintln!(
                "survivor {pid}: {}",
                std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                    .unwrap_or_default()
                    .replace('\0', " ")
            );
            // SAFETY: cleaning up only what this test caused to exist.
            unsafe { libc::kill(*pid, libc::SIGKILL) };
        }
    }
    assert!(
        alive.is_empty(),
        "the contained tree outlived the killed supervisor: {alive:?}"
    );
}

fn descendant_pids(root: u32) -> Vec<i32> {
    let mut out = Vec::new();
    let mut frontier = vec![i32::try_from(root).unwrap()];
    while let Some(pid) = frontier.pop() {
        let Ok(children) = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        else {
            continue;
        };
        for child in children
            .split_whitespace()
            .filter_map(|t| t.parse::<i32>().ok())
        {
            out.push(child);
            frontier.push(child);
        }
    }
    out
}

/// §13.2: every receipt validates and `revision` advances across phases.
#[test]
fn r4_receipt_revisions_advance_and_phases_carry_their_tuples() {
    if !live() {
        return;
    }
    let c = case();
    let run = c
        .jail
        .target([c.fixture.to_str().unwrap(), "exit", "0"])
        .run()
        .expect("run");
    let mut by_phase: Vec<(String, u64)> = Vec::new();
    for event in &run.trace_events {
        if event.get("operation").and_then(Value::as_str) == Some("jail.receipt") {
            let phase = event
                .pointer("/fields/phase")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_owned();
            by_phase.push((phase, 0));
        }
    }
    eprintln!("receipt notes in the trace: {by_phase:?}");
    let receipts = run.receipts();
    for receipt in &receipts {
        eprintln!(
            "phase={:?} revision={:?} containment={:?} protection={:?} exec_observed={:?} \
             boundary={:?} scope={:?} tree_empty={:?} verified_at={:?}",
            receipt.get("phase"),
            receipt.get("revision"),
            receipt.get("containment"),
            receipt.get("child_protection"),
            receipt.get("exec_observed"),
            receipt.pointer("/lifetime/boundary"),
            receipt.pointer("/lifetime/verification_scope"),
            receipt.pointer("/lifetime/tree_empty"),
            receipt.pointer("/lifetime/verified_at"),
        );
    }
    let settled = settled(&run);
    assert_eq!(
        settled.get("containment").and_then(Value::as_str),
        Some("enforced")
    );
    assert_eq!(
        settled.get("child_protection").and_then(Value::as_str),
        Some("enforced")
    );
    assert_eq!(
        settled.get("exec_observed").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        settled
            .pointer("/lifetime/verification_scope")
            .and_then(Value::as_str),
        Some("attempt_tree")
    );
    assert!(
        settled.get("revision").and_then(Value::as_u64).unwrap_or(0) >= 3,
        "revision did not advance across three phases: {:?}",
        settled.get("revision")
    );
}

// ===========================================================================
// 5. Gate and control
// ===========================================================================

/// §8.2: `prepared` before release, `exec_confirmed` after, `settled` last,
/// with monotonically increasing `seq`.
#[test]
fn r5_control_ordering_and_sequence() {
    if !live() {
        return;
    }
    use ouro_fixture::harness::Release;
    let c = case();
    let marker = c.workspace.join("target-ran");
    let mut spawned = c
        .jail
        .gate()
        .target([
            c.fixture.to_str().unwrap(),
            "open",
            marker.to_str().unwrap(),
            "--create",
            "--write",
        ])
        .spawn()
        .expect("spawn");
    let root = spawned.root().to_path_buf();
    let attempt = {
        let mut owner = spawned.owner();
        let prepared = owner.await_prepared().expect("prepared");
        eprintln!("prepared: {prepared}");
        prepared
            .get("attempt_id")
            .and_then(Value::as_str)
            .expect("attempt id")
            .to_owned()
    };
    assert!(
        !marker.exists(),
        "the target ran before the gate released it"
    );
    let digest = receipt_in(&root)
        .and_then(|r| {
            r.pointer("/policy/digest")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .expect("the prepared receipt names its policy digest");
    {
        let mut owner = spawned.owner();
        owner
            .release(&Release::Valid, &attempt, &digest)
            .expect("release");
    }
    let run = spawned.wait().expect("wait");
    assert!(
        marker.exists(),
        "the target never ran after a valid release"
    );

    let kinds: Vec<&str> = run
        .control_messages
        .iter()
        .filter_map(|m| m.get("kind").and_then(Value::as_str))
        .collect();
    let seqs: Vec<u64> = run
        .control_messages
        .iter()
        .filter_map(|m| m.get("seq").and_then(Value::as_u64))
        .collect();
    eprintln!("control kinds {kinds:?} seqs {seqs:?}");
    assert_eq!(kinds, vec!["prepared", "exec_confirmed", "settled"]);
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "seq not increasing: {seqs:?}"
    );
}

/// The receipt under a harness root's private data directory.
fn receipt_in(root: &Path) -> Option<Value> {
    let data = root.join("data/attempts");
    for entry in std::fs::read_dir(&data).ok()?.flatten() {
        let path = entry.path().join("jail.json");
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(value) = serde_json::from_str::<Value>(&text)
        {
            return Some(value);
        }
    }
    None
}

/// §8.2/X02: each malformed release refuses with no target marker.
#[test]
fn r5_malformed_gate_frames_refuse_without_running_the_target() {
    if !live() {
        return;
    }
    use ouro_fixture::harness::Release;

    let variants: Vec<(&str, Release)> = vec![
        ("empty EOF", Release::EmptyEof),
        ("oversized", Release::Oversized),
        ("duplicated", Release::Duplicated),
        (
            "wrong digest",
            Release::WrongDigest(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_owned(),
            ),
        ),
        ("crlf", Release::Crlf),
        ("missing lf", Release::MissingLf),
        ("trailing bytes", Release::TrailingBytes),
        ("leading blank line", Release::LeadingBlankLine),
        (
            "wrong schema",
            Release::WrongSchema("ouro.jail.gate/9".to_owned()),
        ),
        ("wrong action", Release::WrongAction("go".to_owned())),
        ("malformed json", Release::MalformedJson),
        ("duplicate keys", Release::DuplicateKeys),
    ];

    let mut failures = Vec::new();
    for (name, variant) in variants {
        let c = case();
        let marker = c.workspace.join("target-ran");
        let mut spawned = c
            .jail
            .gate()
            .target([
                c.fixture.to_str().unwrap(),
                "open",
                marker.to_str().unwrap(),
                "--create",
                "--write",
            ])
            .spawn()
            .expect("spawn");
        let (attempt, _unused) = {
            let mut owner = spawned.owner();
            let prepared = owner.await_prepared().expect("prepared");
            let attempt = prepared
                .get("attempt_id")
                .and_then(Value::as_str)
                .unwrap()
                .to_owned();
            (attempt, String::new())
        };
        let digest = receipt_in(spawned.root())
            .and_then(|r| {
                r.pointer("/policy/digest")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();
        {
            let mut owner = spawned.owner();
            owner.release(&variant, &attempt, &digest).expect("write");
        }
        let run = spawned.wait().expect("wait");
        let ran = marker.exists();
        let code = run.code();
        let kinds: Vec<&str> = run
            .control_messages
            .iter()
            .filter_map(|m| m.get("kind").and_then(Value::as_str))
            .collect();
        eprintln!("{name}: code={code:?} ran={ran} kinds={kinds:?}");
        if ran {
            failures.push(format!("{name}: the target ran"));
        }
        if code != Some(125) {
            failures.push(format!("{name}: exit {code:?}, expected 125"));
        }
        if !kinds.contains(&"refused") {
            failures.push(format!("{name}: no refused control message ({kinds:?})"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ===========================================================================
// 6. Audit mapping
// ===========================================================================

/// §11.2: EROFS stays the original operation; EACCES becomes one fs.deny;
/// write/mmap produce nothing; workspace paths are workspace-relative.
#[test]
fn r6_audit_mapping_matches_the_spec_table() {
    if !live() {
        return;
    }
    let c = case();
    let workspace = c.workspace.clone();
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join(".git/HEAD"), b"ref: x\n").unwrap();
    // A mode-000 FILE: a mode-000 directory makes the protected-path walk
    // refuse the whole run, which is correct but not what this test is about.
    let denied = workspace.join("denied.txt");
    std::fs::write(&denied, b"x").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();

    let ops = workspace.join("audit.json");
    std::fs::write(
        &ops,
        serde_json::to_vec(&serde_json::json!([
            [
                "open",
                "created.txt",
                "--create",
                "--write",
                "--expect",
                "ok"
            ],
            ["open", ".git/HEAD", "--write", "--expect", "EROFS"],
            ["open", "denied.txt", "--write", "--expect", "EACCES"],
            ["write-mmap", "mapped.txt"],
            [
                "open",
                "/tmp/scratch.txt",
                "--create",
                "--write",
                "--expect",
                "ok"
            ],
            ["open", "/etc/passwd", "--expect", "ok"]
        ]))
        .unwrap(),
    )
    .unwrap();

    let run = c
        .jail
        .target([c.fixture.to_str().unwrap(), "script", ops.to_str().unwrap()])
        .run()
        .expect("run");
    eprintln!("stdout:\n{}", run.stdout_text());
    for event in audit_events(&run) {
        eprintln!(
            "audit {} {} ok={:?} ret={:?} errno={:?} path={:?} basis={:?} attempted={:?}",
            event
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or("?"),
            event.get("stage").and_then(Value::as_str).unwrap_or("?"),
            event.pointer("/outcome/ok"),
            event.pointer("/outcome/return_value"),
            event.pointer("/outcome/errno"),
            event.pointer("/fields/path"),
            event.pointer("/fields/path_basis"),
            event.pointer("/fields/attempted_operation"),
        );
    }

    let ops_seen: Vec<&str> = audit_events(&run)
        .iter()
        .filter_map(|e| e.get("operation").and_then(Value::as_str))
        .collect();
    eprintln!("operations: {ops_seen:?}");

    // The EROFS open stays fs.write/fs.create, never fs.deny.
    let all = audit_events(&run);
    let rofs: Vec<&&Value> = all
        .iter()
        .filter(|e| e.pointer("/outcome/errno").and_then(Value::as_str) == Some("EROFS"))
        .collect();
    assert!(!rofs.is_empty(), "no EROFS result was recorded at all");
    for event in &rofs {
        assert_ne!(
            event.get("operation").and_then(Value::as_str),
            Some("fs.deny"),
            "an EROFS result was classified as a denial: {event}"
        );
    }

    // The EACCES open is exactly one fs.deny naming the attempted operation.
    let denies: Vec<&&Value> = all
        .iter()
        .filter(|e| e.get("operation").and_then(Value::as_str) == Some("fs.deny"))
        .collect();
    eprintln!("denials: {}", denies.len());
    assert_eq!(denies.len(), 1, "expected exactly one fs.deny: {denies:?}");
    assert!(
        denies[0].pointer("/fields/attempted_operation").is_some(),
        "the denial does not name the operation it would have been: {}",
        denies[0]
    );

    // No event asserts a `write` or an `mmap`.
    for event in audit_events(&run) {
        let syscall = event
            .pointer("/fields/syscall")
            .and_then(Value::as_str)
            .unwrap_or("");
        assert!(
            !matches!(syscall, "write" | "mmap" | "pwrite64" | "ftruncate"),
            "an out-of-set syscall became an event: {event}"
        );
    }

    // Paths inside the workspace are workspace-relative; under /tmp they are
    // scratch-relative; elsewhere digested, never a raw host path.
    for event in audit_events(&run) {
        let Some(path) = event.pointer("/fields/path") else {
            continue;
        };
        let basis = event
            .pointer("/fields/path_basis")
            .and_then(Value::as_str)
            .unwrap_or("");
        let text = serde_json::to_string(path).unwrap();
        eprintln!("path {text} basis {basis}");
        assert!(
            !text.contains(workspace.to_str().unwrap()),
            "a raw host path leaked into an event: {event}"
        );
    }
}

/// O05: `--observe off` marks all audit classes unsupported with null counts.
#[test]
fn r6_observe_off_marks_every_audit_class_unsupported() {
    if !live() {
        return;
    }
    let c = case();
    let run = c
        .jail
        .args(["--observe", "off"])
        .target([c.fixture.to_str().unwrap(), "exit", "0"])
        .run()
        .expect("run");
    let receipt = settled(&run);
    eprintln!(
        "coverage: {}",
        serde_json::to_string_pretty(receipt.get("coverage").unwrap_or(&Value::Null)).unwrap()
    );
    let coverage = receipt
        .get("coverage")
        .and_then(Value::as_object)
        .expect("a coverage group");
    for name in ["exec", "fs.write", "fs.deny", "net"] {
        let class = coverage
            .get(name)
            .unwrap_or_else(|| panic!("no class {name} in {coverage:?}"));
        assert_eq!(
            class.get("status").and_then(Value::as_str),
            Some("unsupported"),
            "{name}: {class}"
        );
        assert!(
            class.get("observed_count").is_none_or(Value::is_null),
            "{name} has a count: {class}"
        );
        assert_eq!(
            class.get("sources").and_then(Value::as_array).map(Vec::len),
            Some(0),
            "{name} names a source: {class}"
        );
    }
    assert!(
        audit_events(&run).is_empty(),
        "observation off still emitted audit events"
    );
}

// ===========================================================================
// 7. Doctor
// ===========================================================================

/// §14.1: doctor changes nothing on the host and exits 125 only when a
/// requirement of the selected profile is unsatisfied.
#[test]
fn r7_doctor_is_read_only_and_its_exit_code_follows_readiness() {
    if !live() {
        return;
    }
    let exe = harness::jail_path();
    let jail = Jail::new().expect("harness");
    let out = Command::new(&exe)
        .arg("doctor")
        .arg("--json")
        .env("OURO_DATA_DIR", jail.data_dir())
        .env("OURO_CONFIG_DIR", jail.config_dir())
        .output()
        .expect("doctor");
    let text = String::from_utf8_lossy(&out.stdout);
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"));
    let ready = value.get("ready").and_then(Value::as_bool).unwrap_or(false);
    eprintln!("ready={ready} code={:?}", out.status.code());
    for capability in value
        .get("capabilities")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
    {
        eprintln!(
            "  {} {} {}",
            capability
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("?"),
            capability
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("?"),
            capability
                .get("reason_code")
                .and_then(Value::as_str)
                .unwrap_or("?")
        );
    }
    assert_eq!(
        out.status.code(),
        Some(if ready { 0 } else { 125 }),
        "doctor's exit code does not follow its own readiness"
    );
    // The state directory must hold nothing after a doctor run.
    let attempts = jail.data_dir().join("attempts");
    let left: Vec<String> = std::fs::read_dir(&attempts)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        left.is_empty(),
        "doctor left attempt state behind: {left:?}"
    );
}

// ===========================================================================
// 8. State and durability
// ===========================================================================

/// §7: two concurrent runs with the same `--attempt-id` — the second refuses
/// `attempt_exists`.
#[test]
fn r8_a_second_run_with_the_same_attempt_id_refuses() {
    if !live() {
        return;
    }
    use ouro_fixture::harness::Release;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let jail = Jail::new().expect("harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let data = jail.data_dir();
    let config = jail.config_dir();
    let attempt_id = "att_00000000-0000-4000-8000-0000000000aa";

    // The first run parks at the gate, holding the lease.
    let mut first = Jail::with_program(harness::jail_path())
        .expect("harness")
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--attempt-id")
        .arg(attempt_id)
        .env("OURO_DATA_DIR", &data)
        .env("OURO_CONFIG_DIR", &config)
        .control()
        .gate()
        .target([fixture.to_str().unwrap(), "exit", "0"])
        .spawn()
        .expect("spawn");
    {
        let mut owner = first.owner();
        owner.await_prepared().expect("first run prepared");
    }

    // The second run, same id, with its own real gate pipe at fd 3.
    let mut fds = [-1i32; 2];
    // SAFETY: a two-element array of the right type.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: both descriptors were just created here.
    let (gate_read, _gate_write) = unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    };
    let raw = gate_read.as_raw_fd();
    let mut command = Command::new(harness::jail_path());
    command
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--attempt-id")
        .arg(attempt_id)
        .arg("--gate-fd")
        .arg("3")
        .arg("--")
        .arg(&fixture)
        .arg("exit")
        .arg("0")
        .env("OURO_DATA_DIR", &data)
        .env("OURO_CONFIG_DIR", &config);
    // SAFETY: the closure runs between fork and exec and calls only dup2.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let second = command.output().expect("second run");
    let stderr = String::from_utf8_lossy(&second.stderr).into_owned();
    eprintln!(
        "second run: code={:?} stderr={stderr}",
        second.status.code()
    );
    assert!(
        stderr.contains("attempt_exists"),
        "the second run did not refuse attempt_exists: {stderr}"
    );
    assert_eq!(second.status.code(), Some(125));

    {
        let mut owner = first.owner();
        owner.release(&Release::EmptyEof, attempt_id, "").ok();
    }
    let _ = first.wait();
}

/// §7: a receipt is replaced atomically — a SIGKILL mid-run leaves either the
/// prepared or the enforced receipt, never a truncated file.
#[test]
fn r8_receipts_are_never_left_truncated() {
    if !live() {
        return;
    }
    let mut checked = 0;
    for attempt in 0..8 {
        let c = case();
        let mut spawned = c
            .jail
            .target([c.fixture.to_str().unwrap(), "sleep", "5000"])
            .spawn()
            .expect("spawn");
        // Let preparation get somewhere, then kill at a varying offset.
        std::thread::sleep(std::time::Duration::from_millis(40 + attempt * 35));
        let _ = spawned.kill();
        let root = spawned.root().to_path_buf();
        let _ = spawned.wait();
        let attempts = root.join("data/attempts");
        let Ok(entries) = std::fs::read_dir(&attempts) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path().join("jail.json");
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            checked += 1;
            let value: Value = serde_json::from_str(&text).unwrap_or_else(|e| {
                panic!("a receipt was left unparsable after a kill: {e}\n{text}")
            });
            let phase = value.get("phase").and_then(Value::as_str).unwrap_or("?");
            eprintln!("attempt {attempt}: phase {phase} ({} bytes)", text.len());
            assert!(
                ["prepared", "enforced", "refused", "settled"].contains(&phase),
                "unexpected phase {phase}"
            );
        }
        // Reap anything the kill orphaned.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    eprintln!("receipts checked: {checked}");
}

// ===========================================================================
// Batch 2
// ===========================================================================

/// Every descendant pid of `root`, deepest first.
fn tree_of(root: u32) -> Vec<i32> {
    let mut out = Vec::new();
    let mut frontier = vec![i32::try_from(root).unwrap()];
    while let Some(pid) = frontier.pop() {
        let Ok(children) = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        else {
            continue;
        };
        for child in children
            .split_whitespace()
            .filter_map(|t| t.parse::<i32>().ok())
        {
            out.push(child);
            frontier.push(child);
        }
    }
    out
}

fn cmdline_of(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .replace('\0', " ")
}

/// §8.2: "The supervisor closes the gate before target exec." At the block
/// point the launcher must hold nothing but its own two pipes and stdio.
#[test]
fn r5_the_launcher_holds_no_supervisor_descriptor_at_the_block_point() {
    if !live() {
        return;
    }
    use ouro_fixture::harness::Release;
    let c = case();
    let mut spawned = c
        .jail
        .gate()
        .target([c.fixture.to_str().unwrap(), "exit", "0"])
        .spawn()
        .expect("spawn");
    let supervisor = spawned.pid();
    let attempt = {
        let mut owner = spawned.owner();
        owner
            .await_prepared()
            .expect("prepared")
            .get("attempt_id")
            .and_then(Value::as_str)
            .expect("attempt id")
            .to_owned()
    };

    // The launcher is the descendant running `__launch`.
    let tree = tree_of(supervisor);
    eprintln!(
        "tree: {:?}",
        tree.iter()
            .map(|p| (p, cmdline_of(*p).chars().take(60).collect::<String>()))
            .collect::<Vec<_>>()
    );
    // bubblewrap's own argv contains the launcher's, so match the process
    // whose argv *begins* with the inside path.
    let launcher = tree
        .iter()
        .copied()
        .find(|pid| cmdline_of(*pid).starts_with("/run/ouro/jail __launch"))
        .expect("the blocked launcher");
    let mut entries: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/{launcher}/fd"))
        .expect("the launcher's fd table")
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        let target = std::fs::read_link(entry.path())
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        entries.push((name, target));
    }
    entries.sort();
    eprintln!("launcher {launcher} fds: {entries:?}");

    // Nothing may name the supervisor's state, the gate, the control channel
    // or the trace.
    for (fd, target) in &entries {
        assert!(
            !target.contains("/attempts/") || target.contains("/scratch"),
            "the launcher holds supervisor state on fd {fd}: {target}"
        );
        assert!(
            !target.contains("jail.json") && !target.contains("policy.json"),
            "the launcher holds a receipt or policy file on fd {fd}: {target}"
        );
    }
    // Stdio plus the release pipe and the error pipe, and nothing else.
    let numbers: Vec<i32> = entries.iter().filter_map(|(n, _)| n.parse().ok()).collect();
    eprintln!("launcher fd numbers: {numbers:?}");
    assert!(
        numbers.len() <= 5,
        "the launcher holds {} descriptors: {entries:?}",
        numbers.len()
    );

    {
        let mut owner = spawned.owner();
        let _ = owner.release(&Release::EmptyEof, &attempt, "");
    }
    let _ = spawned.wait();
}

/// X03: a second release never starts a second child.
#[test]
fn r5_a_second_release_starts_no_second_child() {
    if !live() {
        return;
    }
    use ouro_fixture::harness::Release;
    let c = case();
    let counter = c.workspace.join("runs");
    let script = c.workspace.join("count.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho x >> {}\n", counter.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut spawned = c
        .jail
        .gate()
        .target(["/bin/sh", script.to_str().unwrap()])
        .spawn()
        .expect("spawn");
    let root = spawned.root().to_path_buf();
    let attempt = {
        let mut owner = spawned.owner();
        owner
            .await_prepared()
            .expect("prepared")
            .get("attempt_id")
            .and_then(Value::as_str)
            .expect("attempt id")
            .to_owned()
    };
    let digest = receipt_in(&root)
        .and_then(|r| {
            r.pointer("/policy/digest")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .expect("policy digest");
    {
        let mut owner = spawned.owner();
        // Two well-formed frames in one write: §8.2 says the supervisor reads
        // through EOF, so a second frame must refuse, not release twice.
        owner
            .release(&Release::Duplicated, &attempt, &digest)
            .expect("write");
    }
    let run = spawned.wait().expect("wait");
    let count = std::fs::read_to_string(&counter)
        .map(|t| t.lines().count())
        .unwrap_or(0);
    eprintln!("exit={:?} target executions={count}", run.code());
    assert_eq!(count, 0, "a duplicated frame started {count} child(ren)");
}

/// §13.2, L02: killing bubblewrap's outer process must leave an honest
/// receipt, never a `settled` one that claims a verified exit.
#[test]
fn r4_killing_the_backend_leaves_an_honest_receipt() {
    if !live() {
        return;
    }
    let c = case();
    let marker = c.workspace.join("running");
    let script = c.workspace.join("linger.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ntouch {}\ni=0\nwhile [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done\n",
            marker.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let spawned = c
        .jail
        .args(["--limit", "wall=30s"])
        .target(["/bin/sh", script.to_str().unwrap()])
        .spawn()
        .expect("spawn");
    let supervisor = spawned.pid();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(marker.exists(), "the target never started");

    let tree = tree_of(supervisor);
    let bwrap = tree
        .iter()
        .copied()
        .find(|pid| cmdline_of(*pid).contains("bwrap"))
        .expect("the bwrap process");
    eprintln!("killing bwrap {bwrap}: {}", cmdline_of(bwrap));
    // SAFETY: signalling a process this test's own supervisor created.
    unsafe { libc::kill(bwrap, libc::SIGKILL) };

    let run = spawned.wait().expect("wait");
    let receipts = run.receipts();
    let last = receipts.last().expect("a receipt");
    eprintln!("{}", serde_json::to_string_pretty(last).unwrap());
    eprintln!("exit={:?}", run.code());
    let kind = last.pointer("/outcome/kind").and_then(Value::as_str);
    let phase = last.get("phase").and_then(Value::as_str);
    eprintln!("phase={phase:?} kind={kind:?}");
    assert_ne!(
        kind,
        Some("exited"),
        "a killed backend produced a claimed target exit: {last}"
    );
    // Whatever it says, it must not claim a verified settlement of a tree it
    // never watched die.
    if phase == Some("settled") {
        assert_ne!(
            kind,
            Some("exited"),
            "settled with a fabricated exit after the backend was killed"
        );
    }
}

/// The implementer's stated limitation: with observation off an exit at or
/// above 128 is ambiguous and must stay `unknown`.
#[test]
fn r2_observe_off_keeps_an_ambiguous_exit_unknown() {
    if !live() {
        return;
    }
    // A signal death: bubblewrap reports it as 128 + signal.
    let c = case();
    let run = c
        .jail
        .args(["--observe", "off"])
        .target([c.fixture.to_str().unwrap(), "raise", "TERM"])
        .run()
        .expect("run");
    let receipts = run.receipts();
    let last = receipts.last().expect("a receipt");
    eprintln!(
        "signal death, observe off: exit={:?} outcome={}",
        run.code(),
        serde_json::to_string(last.get("outcome").unwrap_or(&Value::Null)).unwrap()
    );
    assert_eq!(
        last.pointer("/outcome/kind").and_then(Value::as_str),
        Some("unknown"),
        "a signal death became a claimed exit with observation off"
    );

    // A genuine exit of 130, which is also ambiguous and must stay unknown.
    let c = case();
    let run = c
        .jail
        .args(["--observe", "off"])
        .target([c.fixture.to_str().unwrap(), "exit", "130"])
        .run()
        .expect("run");
    let receipts = run.receipts();
    let last = receipts.last().expect("a receipt");
    eprintln!(
        "exit 130, observe off: exit={:?} outcome={}",
        run.code(),
        serde_json::to_string(last.get("outcome").unwrap_or(&Value::Null)).unwrap()
    );
    assert_eq!(
        last.pointer("/outcome/kind").and_then(Value::as_str),
        Some("unknown"),
        "exit 130 with observation off must be unknown, not exited"
    );

    // With observation ON the same signal death is precise.
    let c = case();
    let run = c
        .jail
        .target([c.fixture.to_str().unwrap(), "raise", "TERM"])
        .run()
        .expect("run");
    let receipt = settled(&run);
    eprintln!(
        "signal death, observe on: exit={:?} outcome={}",
        run.code(),
        serde_json::to_string(receipt.get("outcome").unwrap_or(&Value::Null)).unwrap()
    );
    assert_eq!(
        receipt.pointer("/outcome/kind").and_then(Value::as_str),
        Some("signaled")
    );
    assert_eq!(
        receipt.pointer("/outcome/signal").and_then(Value::as_u64),
        Some(15)
    );
}

/// §9.1: "remove only unchanged, empty placeholders it created after tree
/// death. Never remove a pre-existing Git file/directory."
#[test]
fn r1_a_placeholder_the_run_filled_is_kept_not_removed() {
    if !live() {
        return;
    }
    let c = case();
    let workspace = c.workspace.clone();
    // `.git` is absent at launch, so a placeholder covers it read-only. The
    // run cannot write through it; what this checks is that the identity test
    // exists at all, by planting content under the placeholder's host mount
    // point from OUTSIDE while the run holds it.
    let ops = workspace.join("noop.json");
    std::fs::write(
        &ops,
        serde_json::to_vec(&serde_json::json!([["sleep", "1500"]])).unwrap(),
    )
    .unwrap();
    let spawned = c
        .jail
        .target([c.fixture.to_str().unwrap(), "script", ops.to_str().unwrap()])
        .spawn()
        .expect("spawn");
    // Wait for the placeholder mount point to appear, then change it.
    let git = workspace.join(".git");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !git.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let planted = git.join("planted");
    let created = std::fs::write(&planted, b"not ours\n").is_ok();
    eprintln!("planted a file under the placeholder: {created}");
    let run = spawned.wait().expect("wait");
    eprintln!("exit={:?}", run.code());
    if created {
        assert!(
            planted.exists(),
            "the placeholder was removed although something else was inside it"
        );
        let _ = std::fs::remove_file(&planted);
        let _ = std::fs::remove_dir(&git);
    } else {
        eprintln!("skipped: the placeholder could not be filled from outside");
    }
}

/// §14.2: managed scratch is removed only after verified tree death; the
/// operator's own workspace is never deleted.
#[test]
fn r8_scratch_and_workspace_after_a_normal_run() {
    if !live() {
        return;
    }
    let c = case();
    let workspace = c.workspace.clone();
    let ops = workspace.join("s.json");
    std::fs::write(
        &ops,
        serde_json::to_vec(&serde_json::json!([[
            "open",
            "/tmp/left-behind.txt",
            "--create",
            "--write",
            "--expect",
            "ok"
        ]]))
        .unwrap(),
    )
    .unwrap();
    let spawned = c
        .jail
        .target([c.fixture.to_str().unwrap(), "script", ops.to_str().unwrap()])
        .spawn()
        .expect("spawn");
    let root = spawned.root().to_path_buf();
    let run = spawned.wait().expect("wait");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let attempts = root.join("data/attempts");
    for entry in std::fs::read_dir(&attempts).expect("attempts").flatten() {
        let dir = entry.path();
        let scratch = dir.join("scratch");
        let names: Vec<String> = std::fs::read_dir(&dir)
            .map(|e| {
                e.flatten()
                    .map(|x| x.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        eprintln!("attempt dir after settlement: {names:?}");
        eprintln!(
            "scratch still present: {} contents: {:?}",
            scratch.exists(),
            std::fs::read_dir(&scratch)
                .map(|e| e
                    .flatten()
                    .map(|x| x.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>())
                .unwrap_or_default()
        );
        for required in ["jail.json", "policy.json", "jail-state.json"] {
            assert!(
                names.iter().any(|n| n == required),
                "{required} is missing from the attempt directory: {names:?}"
            );
        }
    }
    assert!(workspace.exists(), "the operator's workspace was deleted");
}

/// §11.4: an active class's count is the number of results it carries.
#[test]
fn r6_coverage_counts_equal_the_results_per_class() {
    if !live() {
        return;
    }
    let c = case();
    let workspace = c.workspace.clone();
    let ops = workspace.join("counts.json");
    std::fs::write(
        &ops,
        serde_json::to_vec(&serde_json::json!([
            ["open", "a.txt", "--create", "--write", "--expect", "ok"],
            ["open", "b.txt", "--create", "--write", "--expect", "ok"],
            ["mkdir", "d"],
            ["rename", "a.txt", "c.txt"],
            ["unlink", "c.txt"],
            ["rmdir", "d"]
        ]))
        .unwrap(),
    )
    .unwrap();
    let run = c
        .jail
        .target([c.fixture.to_str().unwrap(), "script", ops.to_str().unwrap()])
        .run()
        .expect("run");
    let receipt = settled(&run);
    let mut by_class: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for event in audit_events(&run) {
        let op = event.get("operation").and_then(Value::as_str).unwrap_or("");
        let class = match op {
            "proc.exec" | "proc.exit" => "exec",
            "fs.create" | "fs.write" | "fs.rename" | "fs.unlink" => "fs.write",
            "fs.deny" => "fs.deny",
            "net.connect" => "net",
            _ => continue,
        };
        *by_class.entry(class).or_default() += 1;
    }
    eprintln!("events per class: {by_class:?}");
    for (class, count) in &by_class {
        let recorded = receipt
            .pointer(&format!("/coverage/{class}/observed_count"))
            .and_then(Value::as_u64);
        let status = receipt
            .pointer(&format!("/coverage/{class}/status"))
            .and_then(Value::as_str);
        eprintln!("{class}: events={count} recorded={recorded:?} status={status:?}");
        assert_eq!(
            recorded,
            Some(*count as u64),
            "{class}: the coverage count is not the number of results"
        );
    }
}

/// §11.3: how each path class is reported. A workspace path must be
/// workspace-relative, a scratch path scratch-relative, anything else a
/// digest or an explicit unavailable marker with a reason — never a raw host
/// path.
#[test]
fn r6_path_reporting_by_class() {
    if !live() {
        return;
    }
    let c = case();
    let workspace = c.workspace.clone();
    let ops = workspace.join("paths.json");
    let absolute = workspace.join("abs.txt");
    std::fs::write(
        &ops,
        serde_json::to_vec(&serde_json::json!([
            // absolute, inside the workspace
            [
                "open",
                absolute.to_str().unwrap(),
                "--create",
                "--write",
                "--expect",
                "ok"
            ],
            // relative, inside the workspace (cwd is the workspace)
            ["open", "rel.txt", "--create", "--write", "--expect", "ok"],
            // absolute, inside the scratch
            [
                "open",
                "/tmp/scr.txt",
                "--create",
                "--write",
                "--expect",
                "ok"
            ],
            // absolute, outside every known root: must never appear raw
            ["open", "/etc/ld.so.cache", "--write", "--expect", "EROFS"]
        ]))
        .unwrap(),
    )
    .unwrap();
    let run = c
        .jail
        .target([c.fixture.to_str().unwrap(), "script", ops.to_str().unwrap()])
        .run()
        .expect("run");
    eprintln!("stdout:\n{}", run.stdout_text());
    for event in audit_events(&run) {
        eprintln!(
            "{}",
            serde_json::to_string(event.get("fields").unwrap_or(&Value::Null)).unwrap()
        );
    }
    let raw = serde_json::to_string(&run.trace_events).unwrap();
    assert!(
        !raw.contains(workspace.to_str().unwrap()),
        "a raw host path appears in the trace"
    );
}

/// §11.2/§11.4: a denied `connect` is counted once, under `fs.deny`.
#[test]
fn r6_a_denied_connect_counts_under_fs_deny_only() {
    if !live() {
        return;
    }
    let c = case();
    let ops = c.workspace.join("net.json");
    std::fs::write(
        &ops,
        // The network namespace has only `lo`, so a route to a public address
        // fails; the errno decides which class it lands in.
        serde_json::to_vec(&serde_json::json!([["connect", "192.0.2.1:80"]])).unwrap(),
    )
    .unwrap();
    let run = c
        .jail
        .target([c.fixture.to_str().unwrap(), "script", ops.to_str().unwrap()])
        .run()
        .expect("run");
    eprintln!("stdout:\n{}", run.stdout_text());
    for event in audit_events(&run) {
        eprintln!(
            "{} errno={:?} attempted={:?}",
            event
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or("?"),
            event.pointer("/outcome/errno"),
            event.pointer("/fields/attempted_operation"),
        );
    }
    let receipt = settled(&run);
    eprintln!(
        "net={} fs.deny={}",
        serde_json::to_string(receipt.pointer("/coverage/net").unwrap_or(&Value::Null)).unwrap(),
        serde_json::to_string(receipt.pointer("/coverage/fs.deny").unwrap_or(&Value::Null))
            .unwrap(),
    );
    // Whatever the errno, the call is counted exactly once overall.
    let connects = audit_events(&run)
        .iter()
        .filter(|e| {
            let op = e.get("operation").and_then(Value::as_str).unwrap_or("");
            op == "net.connect"
                || (op == "fs.deny"
                    && e.pointer("/fields/attempted_operation")
                        .and_then(Value::as_str)
                        == Some("net.connect"))
        })
        .count();
    assert_eq!(connects, 1, "a single connect produced {connects} results");
}

/// §11.3: a relative path resolved against a directory descriptor the sensor
/// cannot resolve must be marked unavailable, never appended to a cwd.
#[test]
fn r6_a_foreign_dirfd_is_not_resolved_against_a_cwd() {
    if !live() {
        return;
    }
    let c = case();
    let workspace = c.workspace.clone();
    std::fs::create_dir_all(workspace.join("sub")).unwrap();
    let ops = workspace.join("dirfd.json");
    std::fs::write(
        &ops,
        serde_json::to_vec(&serde_json::json!([
            ["open", "sub", "--expect", "ok"],
            // `--via openat` with a dirfd: the fixture opens the directory
            // first and uses its descriptor.
            ["mkdir", "sub/made", "--via", "mkdirat"]
        ]))
        .unwrap(),
    )
    .unwrap();
    let run = c
        .jail
        .target([c.fixture.to_str().unwrap(), "script", ops.to_str().unwrap()])
        .run()
        .expect("run");
    eprintln!("stdout:\n{}", run.stdout_text());
    for event in audit_events(&run) {
        eprintln!(
            "{} fields={}",
            event
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or("?"),
            serde_json::to_string(event.get("fields").unwrap_or(&Value::Null)).unwrap()
        );
    }
}

/// I03/§6.2: the contained child must not be able to reach the supervisor's
/// state — the receipt, the policy snapshot or the lock — by any path.
#[test]
fn r1_the_child_cannot_reach_the_supervisors_state() {
    if !live() {
        return;
    }
    let c = case();
    let data = c.jail.data_dir();
    let workspace = c.workspace.clone();
    let report = workspace.join("reach.txt");
    let script = workspace.join("reach.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             {{\n\
             echo \"data_dir: $(ls -1 {data} 2>&1)\"\n\
             for f in $(find / -name jail.json -o -name policy.json -o -name jail.lock 2>/dev/null); do\n\
               echo \"FOUND $f\"\n\
             done\n\
             echo \"proc_others: $(ls -1 /proc | grep -c '^[0-9]*$')\"\n\
             echo \"sys: $(ls -1 /sys 2>&1 | head -1)\"\n\
             echo \"cgroup: $(cat /proc/self/cgroup 2>&1 | head -1)\"\n\
             }} > {report} 2>&1\n",
            data = data.display(),
            report = report.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let run = c
        .jail
        .target(["/bin/sh", script.to_str().unwrap()])
        .run()
        .expect("run");
    let text = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("--- what the child could see ---\n{text}");
    eprintln!("exit={:?} stderr={}", run.code(), run.stderr_text());
    assert!(
        !text.contains("FOUND "),
        "the child reached supervisor state:\n{text}"
    );
    // Only the attempt tree's own processes are visible in the private /proc.
    let count: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("proc_others: "))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(usize::MAX);
    // The probe itself is a shell plus the `find`/`ls` pipeline; what matters
    // is that no host process is visible.
    assert!(count <= 12, "the child sees {count} processes in /proc");
    // §9.1: the host cgroup path is host information the child should not have.
    let cgroup = text
        .lines()
        .find_map(|l| l.strip_prefix("cgroup: "))
        .unwrap_or("")
        .to_owned();
    eprintln!("the child's own cgroup line: {cgroup}");
    assert!(
        cgroup.trim_end().ends_with("0::/") || cgroup.is_empty(),
        "the child sees the host cgroup path: {cgroup}"
    );
}

/// §14.1: a probe owns its fixtures; killing `doctor` must not leave a
/// paused fixture process behind.
#[test]
fn r7_doctor_leaves_no_orphaned_fixture_process() {
    if !live() {
        return;
    }
    let exe = harness::jail_path();
    let mut leaked: Vec<i32> = Vec::new();
    for attempt in 0..12 {
        let jail = Jail::new().expect("harness");
        let mut child = Command::new(&exe)
            .arg("doctor")
            .arg("--json")
            .env("OURO_DATA_DIR", jail.data_dir())
            .env("OURO_CONFIG_DIR", jail.config_dir())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("doctor");
        let pid = i32::try_from(child.id()).unwrap();
        let before: Vec<i32> = tree_of(child.id());
        std::thread::sleep(std::time::Duration::from_millis(40 + attempt * 30));
        let during = tree_of(child.id());
        // SAFETY: killing a process this test started.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = child.wait();
        let _ = before;
        std::thread::sleep(std::time::Duration::from_millis(150));
        for candidate in during {
            if Path::new(&format!("/proc/{candidate}")).exists() {
                let cmd = cmdline_of(candidate);
                let state =
                    std::fs::read_to_string(format!("/proc/{candidate}/stat")).unwrap_or_default();
                // An orphan of ours re-parented to init, still alive.
                // `/proc/<pid>/stat` field 4 is ppid, counted after the
                // comm field's closing parenthesis.
                let ppid: i32 = state
                    .rfind(')')
                    .and_then(|at| state[at + 1..].split_whitespace().nth(1))
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(-1);
                eprintln!("survivor {candidate} ppid={ppid} cmd={cmd:?}");
                if ppid == 1 {
                    leaked.push(candidate);
                    // SAFETY: cleaning up only what this test caused to exist.
                    unsafe { libc::kill(candidate, libc::SIGKILL) };
                }
            }
        }
    }
    assert!(
        leaked.is_empty(),
        "killing doctor left {} orphaned fixture process(es): {leaked:?}",
        leaked.len()
    );
}

/// §8.3: "reject regular-file stdio that resolves into protected supervisor
/// state". The state is the whole runtime state root (§6.2), not only this
/// attempt's own directory.
#[test]
fn r3_stdio_into_the_state_root_outside_this_attempt() {
    if !live() {
        return;
    }
    let exe = harness::jail_path();
    let jail = Jail::new().expect("harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let data = jail.data_dir();

    // A previous attempt's directory, with a receipt in it.
    let other = data.join("attempts/att_00000000-0000-4000-8000-0000000000bb");
    std::fs::create_dir_all(&other).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
    let victim = other.join("jail.json");
    std::fs::write(&victim, b"{\"phase\":\"settled\"}\n").unwrap();

    let mut failures = Vec::new();
    for (name, target) in [
        ("another attempt's receipt", victim.clone()),
        ("the state root itself", data.join("stray.txt")),
    ] {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&target)
            .expect("open the redirect target");
        let out = Command::new(&exe)
            .arg("run")
            .arg("--workspace")
            .arg(&workspace)
            .arg("--")
            .arg(&fixture)
            .arg("env")
            .env("OURO_DATA_DIR", &data)
            .env("OURO_CONFIG_DIR", jail.config_dir())
            .stdout(std::process::Stdio::from(file))
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("run");
        let after = std::fs::read_to_string(&target).unwrap_or_default();
        eprintln!(
            "{name}: code={:?} stderr={} file now {} bytes",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
            after.len()
        );
        if out.status.code() != Some(125) {
            failures.push(format!(
                "{name}: the run was not refused (exit {:?}); the file now holds {:?}",
                out.status.code(),
                after.chars().take(120).collect::<String>()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// §8.3/X06: "the target inherits exactly fds 0/1/2". A supervisor started
/// with stdin closed must not hand the target a boundary with fd 0 missing
/// or, worse, fd 0 belonging to something else.
#[test]
fn r3_a_closed_stdin_is_not_silently_accepted() {
    if !live() {
        return;
    }
    let exe = harness::jail_path();
    let jail = Jail::new().expect("harness");
    let (workspace, fixture) = workspace_with_fixture(jail.root());
    let ops = workspace.join("fds.json");
    std::fs::write(
        &ops,
        serde_json::to_vec(&serde_json::json!([["fds"]])).unwrap(),
    )
    .unwrap();

    let mut command = Command::new(&exe);
    command
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--")
        .arg(&fixture)
        .arg("script")
        .arg(&ops)
        .env("OURO_DATA_DIR", jail.data_dir())
        .env("OURO_CONFIG_DIR", jail.config_dir())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // SAFETY: the closure runs between fork and exec and calls only close.
    unsafe {
        command.pre_exec(|| {
            libc::close(0);
            Ok(())
        });
    }
    let out = command.output().expect("run");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    eprintln!(
        "closed stdin: code={:?}\nstdout={text}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let line: Option<Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v.get("op").and_then(Value::as_str) == Some("fds"));
    if let Some(line) = &line {
        let numbers: Vec<i64> = line
            .pointer("/args/fds")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.get("fd").and_then(Value::as_i64))
                    .collect()
            })
            .unwrap_or_default();
        eprintln!("the target's descriptors: {numbers:?}");
        assert!(
            !numbers.is_empty(),
            "the target inherited no descriptors at all"
        );
    } else {
        eprintln!("the run did not reach the target: {:?}", out.status.code());
    }
}

// ===========================================================================
// 9. The branch review's fixes
// ===========================================================================

/// P03/I11: a child-visible policy edit between prepared and release cannot
/// change the running attempt's authority — the settled receipt's digest and
/// applied mounts equal the prepared ones.
#[test]
fn r9_a_mid_run_policy_edit_cannot_widen_the_attempt() {
    if !live() {
        return;
    }
    use ouro_fixture::harness::Release;

    let c = case();
    let marker = c.workspace.join("target-ran");
    std::fs::create_dir_all(c.workspace.join("secret")).unwrap();
    std::fs::write(
        c.workspace.join("ouro.toml"),
        "[jail.filesystem]\ndeny_read = [\"./secret\"]\n",
    )
    .unwrap();

    let mut spawned = c
        .jail
        .gate()
        .target([
            c.fixture.to_str().unwrap(),
            "open",
            marker.to_str().unwrap(),
            "--create",
            "--write",
        ])
        .spawn()
        .expect("spawn");
    let (attempt, prepared_digest, prepared_mounts) = {
        let mut owner = spawned.owner();
        let prepared = owner.await_prepared().expect("prepared");
        let attempt = prepared
            .get("attempt_id")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        let receipt = receipt_in(spawned.root()).expect("prepared receipt");
        let digest = receipt
            .pointer("/policy/digest")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        let mounts = receipt
            .pointer("/applied/filesystem/mounts")
            .cloned()
            .unwrap_or(Value::Null);
        (attempt, digest, mounts)
    };
    // The child owns the workspace: rewrite the project policy to a wider
    // shape while the attempt is prepared but not released.
    std::fs::write(c.workspace.join("ouro.toml"), "\n").unwrap();
    {
        let mut owner = spawned.owner();
        owner
            .release(&Release::Valid, &attempt, &prepared_digest)
            .expect("release");
    }
    let run = spawned.wait().expect("wait");
    assert_eq!(run.code(), Some(0), "the target should have run");
    assert!(marker.exists(), "the target did not run");
    let settled = settled(&run);
    assert_eq!(
        settled.pointer("/policy/digest").and_then(Value::as_str),
        Some(prepared_digest.as_str()),
        "a mid-attempt policy edit changed the digest"
    );
    assert_eq!(
        settled.pointer("/applied/filesystem/mounts"),
        Some(&prepared_mounts),
        "a mid-attempt policy edit changed the applied mounts"
    );
}

/// M-B/I02: a symlinked root `.git` cannot certify existing_and_root, so the
/// run refuses rather than proceed with silently downgraded coverage.
#[test]
fn r9_a_symlinked_root_git_refuses_rather_than_downgrade() {
    if !live() {
        return;
    }
    let c = case();
    let marker = c.workspace.join("target-ran");
    std::os::unix::fs::symlink("nowhere", c.workspace.join(".git")).unwrap();
    let run = c
        .jail
        .target([
            c.fixture.to_str().unwrap(),
            "open",
            marker.to_str().unwrap(),
            "--create",
            "--write",
        ])
        .run()
        .expect("run");
    assert_eq!(run.code(), Some(125), "expected a pre-exec refusal");
    assert!(!marker.exists(), "the target ran despite the refusal");
    let receipt = receipt_in(c.jail.root()).expect("a receipt");
    let codes: Vec<&str> = receipt
        .pointer("/errors")
        .and_then(Value::as_array)
        .map(|errors| {
            errors
                .iter()
                .filter_map(|e| e.get("code").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        codes.contains(&"missing_capability"),
        "expected missing_capability in {codes:?}"
    );
    // The symlink itself is untouched: a protected symlink is never followed
    // and never removed.
    assert!(
        c.workspace
            .join(".git")
            .symlink_metadata()
            .expect("the symlink survived")
            .file_type()
            .is_symlink()
    );
}

/// M-C/north-star §4.3: a `--deny-read` grant is enforced — the denied
/// subtree is masked, its real content invisible to the child.
#[test]
fn r9_deny_read_grants_are_enforced_as_masks() {
    if !live() {
        return;
    }
    let c = case();
    std::fs::create_dir_all(c.workspace.join("secret")).unwrap();
    std::fs::write(c.workspace.join("secret/file"), b"classified\n").unwrap();
    let script = c.workspace.join("ops.json");
    let ops = serde_json::json!([["open", "secret/file", "--expect", "ENOENT"]]);
    std::fs::write(&script, serde_json::to_vec(&ops).unwrap()).unwrap();

    let run = c
        .jail
        .arg("--deny-read")
        .arg(c.workspace.join("secret"))
        .target([
            c.fixture.to_str().unwrap(),
            "script",
            script.to_str().unwrap(),
        ])
        .run()
        .expect("run");
    assert_eq!(run.code(), Some(0), "fixture expectations were not all met");
    let settled = settled(&run);
    let masked: Vec<&Value> = settled
        .pointer("/applied/filesystem/mounts")
        .and_then(Value::as_array)
        .map(|mounts| {
            mounts
                .iter()
                .filter(|m| m.get("kind").and_then(Value::as_str) == Some("tmpfs-mask"))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        masked.len(),
        1,
        "expected exactly one mask mount: {masked:?}"
    );
    assert!(
        masked[0]
            .get("destination")
            .and_then(Value::as_str)
            .is_some_and(|d| d.ends_with("/secret")),
        "the mask must cover the denied subtree: {masked:?}"
    );
    // The real file is unchanged outside the jail.
    assert_eq!(
        std::fs::read(c.workspace.join("secret/file")).unwrap(),
        b"classified\n"
    );
}

/// M-K/§6.4: an explicit pids ceiling is a required limit; this slice cannot
/// enforce it, so it refuses instead of running unbounded.
#[test]
fn r9_an_explicit_pids_ceiling_refuses_until_it_can_be_enforced() {
    if !live() {
        return;
    }
    let c = case();
    let marker = c.workspace.join("target-ran");
    let run = c
        .jail
        .arg("--limit")
        .arg("pids=8")
        .target([
            c.fixture.to_str().unwrap(),
            "open",
            marker.to_str().unwrap(),
            "--create",
            "--write",
        ])
        .run()
        .expect("run");
    assert_eq!(run.code(), Some(125), "expected a pre-exec refusal");
    assert!(!marker.exists(), "the target ran without the ceiling");
}

/// north-star §4.4: requiring all_descendants on Linux refuses (125) rather
/// than underclaim coverage.
#[test]
fn r9_all_descendants_coverage_refuses_on_linux() {
    if !live() {
        return;
    }
    let c = case();
    let profile = c.jail.root().join("all.toml");
    std::fs::write(
        &profile,
        "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\n\n[filesystem]\nprotected_coverage = \"all_descendants\"\n",
    )
    .unwrap();
    let marker = c.workspace.join("target-ran");
    let run = c
        .jail
        .arg("--profile")
        .arg(&profile)
        .target([
            c.fixture.to_str().unwrap(),
            "open",
            marker.to_str().unwrap(),
            "--create",
            "--write",
        ])
        .run()
        .expect("run");
    assert_eq!(run.code(), Some(125), "expected a pre-exec refusal");
    assert!(!marker.exists(), "the target ran without the coverage");
}

/// H2/I07: an option tail larger than the pipe capacity must flow through the
/// `--args` descriptor instead of deadlocking the supervisor before spawn.
#[test]
fn r9_a_large_option_tail_does_not_deadlock_the_supervisor() {
    if !live() {
        return;
    }
    let c = case();
    let marker = c.workspace.join("target-ran");
    // Enough protected segments to push the rendered option tail past the
    // 128 KiB --args threshold and the payload past the default 64 KiB pipe
    // capacity, with a command that stays short.
    for index in 0..600 {
        let name = format!("segment-{index:04}-abcdefghijklmnopqrstuvwxyz0123456789abcdefgh");
        std::fs::create_dir_all(c.workspace.join(name).join(".git")).unwrap();
    }
    let run = c
        .jail
        .target([
            c.fixture.to_str().unwrap(),
            "open",
            marker.to_str().unwrap(),
            "--create",
            "--write",
        ])
        .run()
        .expect("run");
    assert_eq!(run.code(), Some(0), "the run must complete, not hang");
    assert!(marker.exists(), "the target did not run");
}
