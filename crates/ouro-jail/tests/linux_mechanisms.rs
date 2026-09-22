#![cfg(target_os = "linux")]
//! Live tests for the Linux mechanisms of J1 phase 1.
//!
//! Every test here runs on the reference host and fails when the mechanism it
//! names does not hold. Nothing is asserted from a flag that was passed; each
//! claim is read back from `/proc`, from a syscall's errno, or from the
//! filesystem after the sandbox is gone.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ouro_jail::platform::linux::bwrap::{
    self, BwrapPlan, Placeholder, PlaceholderOutcome, inner_launch_command,
};
use ouro_jail::platform::linux::cgroup;
use ouro_jail::platform::linux::clock::{Deadline, boottime_ns};
use ouro_jail::platform::linux::exec::{self, FdMap};
use ouro_jail::platform::linux::fs as jfs;
use ouro_jail::platform::linux::identity::{self, ProcessIdentity};
use ouro_jail::platform::linux::launch;
use ouro_jail::platform::linux::probe::{self, ProbeStatus};
use ouro_jail::platform::linux::seccomp;
use ouro_jail::platform::linux::tracer;

const RELEASE_FD: i32 = 12;
const ERROR_FD: i32 = 13;
const SECCOMP_FD: i32 = 10;
const ARGS_FD: i32 = 14;

fn jail_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ouro-jail"))
}

mod common;
use common::{bwrap_path, live, reference_host};

fn temp_dir(tag: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("ouro-j1-{tag}-"))
        .tempdir()
        .expect("temp dir")
}

fn parse_fields(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

// ===========================================================================
// clock and identity
// ===========================================================================

#[test]
fn the_boot_clock_advances_and_a_deadline_expires() {
    let start = boottime_ns();
    let deadline = Deadline::after(Duration::from_millis(30));
    assert!(!deadline.expired());
    while !deadline.expired() {
        std::hint::spin_loop();
    }
    let elapsed = boottime_ns() - start;
    assert!(
        elapsed >= 30_000_000,
        "deadline fired after only {elapsed} ns"
    );
}

#[test]
fn our_own_identity_is_live_and_names_this_boot() {
    let me = ProcessIdentity::own().expect("own identity");
    assert!(me.is_live());
    assert_eq!(me.boot_id, identity::boot_id().unwrap());
    assert!(!me.boot_id.is_empty());
    assert!(me.start_time_ticks > 0);
}

#[test]
fn an_exited_childs_identity_is_not_live() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    let recorded = ProcessIdentity::capture(pid).expect("capture while alive");
    assert!(recorded.is_live(), "the child is running");
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        !recorded.is_live(),
        "a reaped pid must not be reported as live"
    );
}

#[test]
fn a_reused_pid_is_rejected_by_its_birth_time() {
    // Simulate reuse: take a pid that certainly exists — our own — and pair it
    // with a birth time it does not have. A liveness check that only asked
    // "does this pid exist?" would pass; this one must not.
    let me = ProcessIdentity::own().unwrap();
    let impostor = ProcessIdentity {
        pid: me.pid,
        boot_id: me.boot_id.clone(),
        start_time_ticks: me.start_time_ticks + 1,
    };
    assert!(me.is_live());
    assert!(
        !impostor.is_live(),
        "a live pid with a different birth time is a different process"
    );

    let wrong_boot = ProcessIdentity {
        boot_id: "00000000-0000-4000-8000-000000000000".to_owned(),
        ..me.clone()
    };
    assert!(!wrong_boot.is_live(), "another boot is another process");
}

#[test]
fn a_pidfd_signals_an_owned_child_and_the_child_is_reaped_as_signalled() {
    use std::os::unix::process::ExitStatusExt as _;
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    let pidfd = identity::pidfd_open(pid).expect("pidfd_open");
    identity::pidfd_send_signal(std::os::fd::AsRawFd::as_raw_fd(&pidfd), libc::SIGKILL)
        .expect("pidfd_send_signal");
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

#[test]
fn namespace_ids_children_and_cmdline_describe_an_owned_child() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let pid = i32::try_from(child.id()).unwrap();

    let mine = identity::ns_ids(identity::ProcessIdentity::own().unwrap().pid);
    let theirs = identity::ns_ids(pid);
    assert!(mine.pid.is_some() && mine.mnt.is_some() && mine.net.is_some() && mine.user.is_some());
    assert_eq!(
        mine.pid, theirs.pid,
        "an ordinary child shares our pid namespace"
    );

    let kids = tracer::children(identity::ProcessIdentity::own().unwrap().pid);
    assert!(kids.contains(&pid), "children() missed our own child {pid}");
    let descendants = tracer::descendants(identity::ProcessIdentity::own().unwrap().pid);
    assert!(descendants.contains(&pid));

    let argv = tracer::cmdline(pid).unwrap();
    assert_eq!(argv[0], b"/bin/sleep");
    assert_eq!(tracer::nspid(pid).unwrap(), vec![pid]);

    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn a_path_with_an_interior_nul_never_reaches_a_syscall() {
    use ouro_jail::platform::linux::sys::{PathError, cstring_from_path};
    let bad = PathBuf::from(OsStr::from_bytes(b"/tmp/one\0two"));
    assert_eq!(
        cstring_from_path(&bad),
        Err(PathError::InteriorNul { offset: 8 })
    );
    // And the walk refuses it rather than opening `/tmp/one`.
    assert!(matches!(
        jfs::scan_protected(&bad),
        Err(jfs::ScanError::Path(PathError::InteriorNul { .. }))
    ));
}

// ===========================================================================
// fs: the protected-segment walk
// ===========================================================================

fn build_workspace(root: &Path) {
    fs::create_dir_all(root.join("src/deep/nested")).unwrap();
    fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
    // A root-level .git directory.
    fs::create_dir_all(root.join(".git/objects")).unwrap();
    fs::write(root.join(".git/config"), b"[core]\n").unwrap();
    // A nested repository, five levels down.
    fs::create_dir_all(root.join("src/deep/nested/vendor/.git")).unwrap();
    // A file-form .git, as a worktree leaves behind.
    fs::create_dir_all(root.join("src/worktree")).unwrap();
    fs::write(root.join("src/worktree/.git"), b"gitdir: /elsewhere\n").unwrap();
    // A .ouroboros directory that is not at the root.
    fs::create_dir_all(root.join("src/.ouroboros")).unwrap();
}

#[test]
fn the_walk_finds_nested_and_file_form_protected_segments() {
    let dir = temp_dir("scan");
    let root = dir.path();
    build_workspace(root);

    let scan = jfs::scan_protected(root).expect("scan");
    let mut found: Vec<String> = scan
        .segments
        .iter()
        .map(|s| {
            format!(
                "{} {:?}",
                s.path.strip_prefix(root).unwrap().display(),
                s.kind
            )
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        vec![
            ".git Directory".to_owned(),
            "src/.ouroboros Directory".to_owned(),
            "src/deep/nested/vendor/.git Directory".to_owned(),
            "src/worktree/.git File".to_owned(),
        ]
    );
    // Nothing inside a protected segment is walked into.
    assert!(
        !scan
            .segments
            .iter()
            .any(|s| s.path.to_string_lossy().contains(".git/objects")),
        "the walk descended into a protected segment"
    );
    for segment in &scan.segments {
        assert!(segment.ino > 0, "no inode recorded for {segment:?}");
    }
}

#[test]
fn root_level_literals_are_reported_present_or_absent() {
    let dir = temp_dir("literals");
    let root = dir.path();
    build_workspace(root);
    let scan = jfs::scan_protected(root).unwrap();
    assert_eq!(
        scan.root_literals,
        vec![
            (
                ".git".to_owned(),
                jfs::RootLiteralState::Present(jfs::SegmentKind::Directory)
            ),
            (".ouroboros".to_owned(), jfs::RootLiteralState::Absent),
        ]
    );
    assert_eq!(scan.absent_root_literals(), vec![".ouroboros"]);
}

#[test]
fn a_symlink_named_git_is_not_reported_as_a_segment_inside_the_root() {
    let outside = temp_dir("outside");
    fs::create_dir(outside.path().join(".git")).unwrap();
    let dir = temp_dir("symlink");
    let root = dir.path();
    fs::create_dir(root.join("sub")).unwrap();
    std::os::unix::fs::symlink(outside.path().join(".git"), root.join("sub/.git")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.join("escape")).unwrap();

    let scan = jfs::scan_protected(root).unwrap();
    assert!(
        scan.segments.is_empty(),
        "a symlink must not authorise its target: {:?}",
        scan.segments
    );
    assert_eq!(scan.skipped_symlinks, vec![root.join("sub/.git")]);
    // The walk must not have followed `escape` into the other tree either.
    assert_eq!(
        scan.entries_seen, 3,
        "walked further than the root's own entries"
    );
}

#[test]
fn the_entry_limit_refuses_rather_than_claiming_partial_coverage() {
    let dir = temp_dir("entries");
    let root = dir.path();
    for n in 0..50 {
        fs::write(root.join(format!("file{n}")), b"").unwrap();
    }
    let limits = jfs::ScanLimits {
        max_entries: 10,
        max_depth: 128,
    };
    match jfs::scan_protected_with(root, limits) {
        Err(jfs::ScanError::EntryLimit { limit }) => assert_eq!(limit, 10),
        other => panic!("expected an entry-limit refusal, got {other:?}"),
    }
}

#[test]
fn the_depth_limit_refuses_rather_than_claiming_partial_coverage() {
    let dir = temp_dir("depth");
    let mut path = dir.path().to_path_buf();
    for n in 0..10 {
        path = path.join(format!("d{n}"));
    }
    fs::create_dir_all(&path).unwrap();
    let limits = jfs::ScanLimits {
        max_entries: 100_000,
        max_depth: 4,
    };
    match jfs::scan_protected_with(dir.path(), limits) {
        Err(jfs::ScanError::DepthLimit { limit, .. }) => assert_eq!(limit, 4),
        other => panic!("expected a depth-limit refusal, got {other:?}"),
    }
    // The spec's own limits do not trip on this tree.
    assert!(jfs::scan_protected(dir.path()).is_ok());
}

#[test]
fn the_default_limits_are_the_ones_the_spec_fixes() {
    assert_eq!(jfs::ScanLimits::DEFAULT.max_entries, 100_000);
    assert_eq!(jfs::ScanLimits::DEFAULT.max_depth, 128);
}

#[test]
fn an_unreadable_directory_is_a_refusal_not_a_shorter_answer() {
    let dir = temp_dir("unreadable");
    let closed = dir.path().join("closed");
    fs::create_dir(&closed).unwrap();
    fs::create_dir(closed.join(".git")).unwrap();
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
    let result = jfs::scan_protected(dir.path());
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();
    match result {
        Err(jfs::ScanError::Unreadable { path, errno }) => {
            assert_eq!(path, closed);
            assert_eq!(errno, libc::EACCES);
        }
        other => panic!("expected an unreadable refusal, got {other:?}"),
    }
}

#[test]
fn a_pinned_path_notices_that_it_was_replaced() {
    let dir = temp_dir("pin");
    let target = dir.path().join("input");
    fs::create_dir(&target).unwrap();
    let pin = jfs::PinnedPath::open(&target).expect("pin");
    pin.verify().expect("unchanged right after pinning");

    fs::remove_dir(&target).unwrap();
    match pin.verify() {
        Err(jfs::PinError::Missing { errno, .. }) => assert_eq!(errno, libc::ENOENT),
        other => panic!("expected Missing, got {other:?}"),
    }

    // Recreate it: same name, different inode.
    fs::create_dir(&target).unwrap();
    match pin.verify() {
        Err(jfs::PinError::Replaced {
            expected, found, ..
        }) => {
            assert_eq!(expected, pin.identity());
            assert_ne!(expected, found);
        }
        other => panic!("expected Replaced, got {other:?}"),
    }
}

#[test]
fn this_hosts_runtime_roots_are_merged_usr_symlinks() {
    if !reference_host("the merged-/usr layout") {
        return;
    }
    let usr = jfs::resolve_runtime_root(Path::new("/usr"));
    assert!(
        matches!(usr, Some(jfs::RootSpec::RoBind(_))),
        "/usr should be a real directory, got {usr:?}"
    );
    let bin = jfs::resolve_runtime_root(Path::new("/bin"));
    match bin {
        Some(jfs::RootSpec::Symlink { ref target, .. }) => {
            assert_eq!(target, Path::new("usr/bin"));
        }
        other => panic!("/bin on this host is {other:?}, not a merged-usr symlink"),
    }
    assert_eq!(jfs::resolve_runtime_root(Path::new("/lib32")), None);
    assert!(jfs::resolve_runtime_root(Path::new("/no/such/root")).is_none());
}

// ===========================================================================
// seccomp, through bubblewrap
// ===========================================================================

/// Raw syscalls the fixture makes, run once with the baseline filter and once
/// without it, so that the difference shows the filter is the cause.
const DENIAL_FIXTURE: &str = r#"
import ctypes, errno, os, socket, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
filtered = sys.argv[1] == "1"
def sc(label, nr, *args):
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])
    if r >= 0:
        print("%s=ok" % label)
    else:
        print("%s=%s" % (label, errno.errorcode.get(ctypes.get_errno(), "E?")))
sc("bpf", 321, 0, 0, 0)
sc("perf_event_open", 298, 0, 0, 0, 0, 0)
sc("io_uring_setup", 425, 1, 0)
sc("io_uring_enter", 426, -1, 0, 0, 0, 0, 0)
sc("io_uring_register", 427, -1, 0, 0, 0)
sc("mount", 165, 0, 0, 0, 0, 0)
sc("umount2", 166, 0, 0)
sc("unshare_newuser", 272, 0x10000000)
sc("setns", 308, -1, 0)
sc("pivot_root", 155, 0, 0)
sc("chroot", 161, 0)
sc("keyctl", 250, 0, 0, 0, 0, 0)
sc("add_key", 248, 0, 0, 0, 0, 0)
sc("request_key", 249, 0, 0, 0, 0)
sc("init_module", 175, 0, 0, 0)
sc("finit_module", 313, -1, 0, 0)
sc("delete_module", 176, 0, 0)
sc("kexec_load", 246, 0, 0, 0, 0)
sc("kexec_file_load", 320, -1, -1, 0, 0, 0)
sc("process_vm_readv", 310, os.getpid(), 0, 0, 0, 0, 0)
sc("process_vm_writev", 311, os.getpid(), 0, 0, 0, 0, 0)
sc("open_tree", 428, -1, 0, 0)
sc("move_mount", 429, -1, 0, -1, 0, 0)
sc("fsopen", 430, 0, 0)
sc("fsconfig", 431, -1, 0, 0, 0, 0)
sc("fsmount", 432, -1, 0, 0)
sc("fspick", 433, -1, 0, 0)
sc("mount_setattr", 442, -1, 0, 0, 0, 0)
sc("clone3", 435, 0, 0)
sc("socket_afunix", 41, 1, 1, 0)
sc("socketpair_afunix", 53, 1, 1, 0, 0)
sc("ioctl_tiocsti", 16, 0, 0x5412, 0)
sc("ioctl_other", 16, -1, 0x5401, 0)
sc("socket_afinet", 41, 2, 1, 0)
if filtered:
    sc("ptrace_traceme", 101, 0, 0, 0, 0)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(("192.0.2.1", 80))
    print("connect=ok")
except OSError as e:
    print("connect=%s" % errno.errorcode.get(e.errno, "E?"))
ctypes.set_errno(0)
r = libc.syscall(ctypes.c_long(56), ctypes.c_long(0x00020000 | 17), 0, 0, 0, 0)
if r == 0:
    os._exit(0)
print("clone_newns=%s" % (errno.errorcode.get(ctypes.get_errno(), "E?") if r < 0 else "ok"))
"#;

/// Ordinary work that must keep working under the filter.
const ALLOWED_FIXTURE: &str = r#"
import os, threading, sys
fd = os.open("/tmp/allowed.txt", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, b"written-inside")
os.close(fd)
print("open_write=ok")
box = []
threads = [threading.Thread(target=lambda: box.append(1)) for _ in range(4)]
for t in threads: t.start()
for t in threads: t.join()
print("threads=%d" % len(box))
pid = os.fork()
if pid == 0:
    os.execv("/usr/bin/true", ["/usr/bin/true"])
    os._exit(9)
print("fork_exec_status=%d" % os.waitpid(pid, 0)[1])
print("readback=%s" % open("/tmp/allowed.txt").read())
"#;

struct SandboxOutcome {
    fields: BTreeMap<String, String>,
    stdout: String,
    stderr: String,
    code: Option<i32>,
    _workspace: tempfile::TempDir,
    scratch: tempfile::TempDir,
}

impl SandboxOutcome {
    fn field(&self, key: &str) -> &str {
        self.fields.get(key).map_or("<missing>", String::as_str)
    }

    fn code(&self) -> Option<i32> {
        self.code
    }
}

/// Run a command inside a `tool`-profile sandbox, optionally with the
/// baseline filter, and collect its `key=value` output.
fn run_in_tool_sandbox(inner: Vec<OsString>, with_filter: bool) -> SandboxOutcome {
    let workspace = temp_dir("ws");
    let scratch = temp_dir("scratch");
    let mut plan = BwrapPlan::tool(workspace.path(), scratch.path(), &jail_exe());
    plan.bwrap = bwrap_path();
    plan.inner = inner;

    let mut fds = FdMap::new();
    if with_filter {
        let program = seccomp::tool_baseline().unwrap();
        let fd = seccomp::program_pipe(&program).unwrap();
        plan.seccomp_fd = Some(SECCOMP_FD);
        fds.add(fd, SECCOMP_FD).unwrap();
    }
    let rendered = plan.render().unwrap();
    let mut command = Command::new(&rendered.argv[0]);
    command.args(&rendered.argv[1..]);
    // Never leave a terminal on the child's stdin: the TIOCSTI check in the
    // fixture would otherwise inject into a real terminal when the filter is
    // absent, which is the very thing the filter exists to stop.
    command.stdin(Stdio::null());
    fds.apply(&mut command);
    let captured = exec::run_captured(&mut command, Deadline::after(Duration::from_secs(20)))
        .expect("run bwrap");
    drop(fds);
    assert!(
        !captured.timed_out,
        "the sandbox run did not finish in time"
    );
    let code = captured.code();
    SandboxOutcome {
        fields: parse_fields(&captured.stdout),
        stdout: captured.stdout,
        stderr: captured.stderr,
        code,
        _workspace: workspace,
        scratch,
    }
}

fn python_inner(script: &str, args: &[&str]) -> Vec<OsString> {
    let mut inner = vec![
        OsString::from("/usr/bin/python3"),
        OsString::from("-c"),
        OsString::from(script),
    ];
    inner.extend(args.iter().map(OsString::from));
    inner
}

#[test]
fn the_baseline_filter_denies_the_syscalls_the_spec_lists() {
    if !live() {
        return;
    }
    let with = run_in_tool_sandbox(python_inner(DENIAL_FIXTURE, &["1"]), true);
    assert_eq!(
        with.code(),
        Some(0),
        "fixture failed: {} {}",
        with.stdout,
        with.stderr
    );

    for name in [
        "bpf",
        "perf_event_open",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "mount",
        "umount2",
        "unshare_newuser",
        "setns",
        "pivot_root",
        "chroot",
        "keyctl",
        "add_key",
        "request_key",
        "init_module",
        "finit_module",
        "delete_module",
        "kexec_load",
        "kexec_file_load",
        "process_vm_readv",
        "process_vm_writev",
        "open_tree",
        "move_mount",
        "fsopen",
        "fsconfig",
        "fsmount",
        "fspick",
        "mount_setattr",
        "socket_afunix",
        "socketpair_afunix",
        "ioctl_tiocsti",
        "ptrace_traceme",
        "clone_newns",
    ] {
        assert_eq!(
            with.field(name),
            "EPERM",
            "{name} was not denied with EPERM; whole report:\n{}",
            with.stdout
        );
    }
    assert_eq!(
        with.field("clone3"),
        "ENOSYS",
        "clone3 must answer ENOSYS so glibc falls back to clone"
    );

    // Selectivity: the filter must not be a blanket denial.
    assert_eq!(
        with.field("ioctl_other"),
        "EBADF",
        "an ioctl that is not TIOCSTI must reach the kernel"
    );
    assert_eq!(
        with.field("socket_afinet"),
        "ok",
        "AF_INET sockets stay allowed; the network namespace is the boundary"
    );
    assert_eq!(
        with.field("connect"),
        "ENETUNREACH",
        "there is no route out of the network namespace"
    );
}

#[test]
fn the_filter_is_what_denies_them_not_the_host() {
    if !live() {
        return;
    }
    // The same fixture without `--seccomp`. For the syscalls an unprivileged
    // process may ordinarily make, the answer must differ; otherwise a green
    // denial test would prove nothing about the filter.
    let without = run_in_tool_sandbox(python_inner(DENIAL_FIXTURE, &["0"]), false);
    assert_eq!(
        without.code(),
        Some(0),
        "fixture failed: {} {}",
        without.stdout,
        without.stderr
    );

    for name in [
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "keyctl",
        "add_key",
        "request_key",
        "socket_afunix",
        "socketpair_afunix",
        "ioctl_tiocsti",
        "process_vm_readv",
        "process_vm_writev",
    ] {
        assert_ne!(
            without.field(name),
            "EPERM",
            "{name} is EPERM even without the filter, so the denial test proves nothing; \
             whole report:\n{}",
            without.stdout
        );
    }
    assert_ne!(
        without.field("clone3"),
        "ENOSYS",
        "without the filter clone3 exists on this kernel; with it, it must answer ENOSYS"
    );
}

#[test]
fn ordinary_work_still_works_under_the_filter() {
    if !live() {
        return;
    }
    let run = run_in_tool_sandbox(python_inner(ALLOWED_FIXTURE, &[]), true);
    assert_eq!(
        run.code(),
        Some(0),
        "fixture failed: {} {}",
        run.stdout,
        run.stderr
    );
    assert_eq!(run.field("open_write"), "ok");
    assert_eq!(
        run.field("threads"),
        "4",
        "glibc must fall back from clone3 to clone"
    );
    assert_eq!(run.field("fork_exec_status"), "0");
    assert_eq!(run.field("readback"), "written-inside");
    // The scratch directory is the child's /tmp, so the file landed on the
    // host inside the scratch and nowhere else.
    assert_eq!(
        fs::read_to_string(run.scratch.path().join("allowed.txt")).unwrap(),
        "written-inside"
    );
}

#[test]
fn the_syscall_numbers_are_this_kernels_numbers() {
    const HEADER: &str = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h";
    let raw = fs::read_to_string(HEADER).unwrap_or_else(|e| {
        panic!("{HEADER}: {e}; install libc6-dev so the syscall table can be checked")
    });
    let mut table = BTreeMap::new();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("#define __NR_") {
            let mut parts = rest.split_ascii_whitespace();
            if let (Some(name), Some(number)) = (parts.next(), parts.next())
                && let Ok(number) = number.parse::<u32>()
            {
                table.insert(name.to_owned(), number);
            }
        }
    }
    assert!(table.len() > 300, "only {} syscalls parsed", table.len());

    let mut checked = 0usize;
    for (name, nr) in seccomp::DENY_EPERM {
        assert_eq!(table.get(*name), Some(nr), "{name} has the wrong number");
        checked += 1;
    }
    for (name, nr) in [
        ("clone3", seccomp::NR_CLONE3),
        ("clone", seccomp::NR_CLONE),
        ("socket", seccomp::NR_SOCKET),
        ("socketpair", seccomp::NR_SOCKETPAIR),
        ("ioctl", seccomp::NR_IOCTL),
    ] {
        assert_eq!(table.get(name), Some(&nr), "{name} has the wrong number");
        checked += 1;
    }
    // The observer's closed set, checked against the numbers the narrowing
    // filter really installs rather than against a second copy of the table.
    // The nineteen names are jail-v1 §11.2's list.
    const CLOSED_SET_NAMES: [&str; 22] = [
        "execve",
        "execveat",
        "open",
        "openat",
        "openat2",
        "creat",
        "rename",
        "renameat",
        "renameat2",
        "unlink",
        "unlinkat",
        "rmdir",
        "mkdir",
        "mkdirat",
        // Revision 8 grew the set: a node is a directory entry, and a
        // truncation by path is a mutation of a named file.
        "mknod",
        "mknodat",
        "truncate",
        "link",
        "linkat",
        "symlink",
        "symlinkat",
        "connect",
    ];
    let expected: std::collections::BTreeSet<u32> = CLOSED_SET_NAMES
        .iter()
        .map(|name| {
            *table
                .get(*name)
                .unwrap_or_else(|| panic!("{name} is not in this kernel's syscall table"))
        })
        .collect();
    let installed: std::collections::BTreeSet<u32> = tracer::narrowing_filter()
        .iter()
        // A `jeq #k` in the narrowing filter is a syscall number it traces;
        // the architecture compare and the x32 mask are the other immediates.
        .filter(|insn| insn.code == 0x15 && insn.k < 0x4000_0000)
        .map(|insn| insn.k)
        .collect();
    assert_eq!(
        installed, expected,
        "the narrowing filter does not trace exactly the closed set"
    );
    checked += expected.len();
    assert_eq!(
        checked,
        seccomp::DENY_EPERM.len() + 5 + CLOSED_SET_NAMES.len()
    );
}

// ===========================================================================
// the inside launcher
// ===========================================================================

struct Launcher {
    child: Child,
    release: Option<OwnedFd>,
    error: OwnedFd,
}

impl Launcher {
    fn release(&mut self) {
        let fd = self.release.take().expect("released twice");
        let mut file = std::fs::File::from(fd);
        file.write_all(&[1]).expect("write the release byte");
    }

    fn close_release_without_releasing(&mut self) {
        drop(self.release.take().expect("released twice"));
    }

    /// Everything the launcher wrote to the error pipe, read to EOF.
    fn error_bytes(&mut self) -> Vec<u8> {
        let fd = self.error.try_clone().unwrap();
        let mut file = std::fs::File::from(fd);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn finish(self) -> exec::Captured {
        let Self { child, error, .. } = self;
        drop(error);
        exec::finish_captured(child, Deadline::after(Duration::from_secs(20))).unwrap()
    }
}

/// Spawn the launcher directly, outside any sandbox.
fn spawn_launcher(narrow: bool, target: &[&OsStr]) -> Launcher {
    let (release_r, release_w) = exec::pipe().unwrap();
    let (error_r, error_w) = exec::pipe().unwrap();
    let mut fds = FdMap::new();
    fds.add(release_r, RELEASE_FD).unwrap();
    fds.add(error_w, ERROR_FD).unwrap();

    let mut command = Command::new(jail_exe());
    command
        .arg("__launch")
        .arg("--release-fd")
        .arg(RELEASE_FD.to_string())
        .arg("--error-fd")
        .arg(ERROR_FD.to_string());
    if narrow {
        command.arg("--narrow");
    }
    command.arg("--");
    command.args(target);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    fds.apply(&mut command);
    let child = command.spawn().unwrap();
    drop(fds);
    Launcher {
        child,
        release: Some(release_w),
        error: error_r,
    }
}

#[test]
fn the_launcher_execs_the_target_only_after_the_release_byte() {
    let dir = temp_dir("release");
    let marker = dir.path().join("marker");
    let script = format!("echo ran > {}", marker.display());
    let mut launcher = spawn_launcher(
        false,
        &[OsStr::new("/bin/sh"), OsStr::new("-c"), OsStr::new(&script)],
    );

    // Before release the target has not run. The launcher is blocked in
    // read(), which is observable rather than assumed.
    let pid = i32::try_from(launcher.child.id()).unwrap();
    let argv = tracer::cmdline(pid).unwrap();
    assert_eq!(argv[1], b"__launch", "the launcher has not exec'd yet");
    assert!(!marker.exists(), "the target ran before release");

    launcher.release();
    let error = launcher.error_bytes();
    let captured = launcher.finish();
    assert!(
        error.is_empty(),
        "a successful exec writes nothing: {error:?}"
    );
    assert_eq!(captured.code(), Some(0));
    assert_eq!(fs::read_to_string(&marker).unwrap().trim(), "ran");
}

#[test]
fn a_closed_release_pipe_means_no_exec_and_exit_124() {
    let dir = temp_dir("norelease");
    let marker = dir.path().join("marker");
    let script = format!("echo ran > {}", marker.display());
    let mut launcher = spawn_launcher(
        false,
        &[OsStr::new("/bin/sh"), OsStr::new("-c"), OsStr::new(&script)],
    );
    launcher.close_release_without_releasing();
    let error = launcher.error_bytes();
    let captured = launcher.finish();
    assert_eq!(captured.code(), Some(launch::EXIT_NO_RELEASE));
    assert!(error.is_empty());
    assert!(
        !marker.exists(),
        "the target ran even though it was never released"
    );
}

#[test]
fn a_missing_executable_is_reported_as_enoent_on_the_error_pipe() {
    let mut launcher = spawn_launcher(false, &[OsStr::new("/no/such/program")]);
    launcher.release();
    let error = launcher.error_bytes();
    let captured = launcher.finish();
    assert_eq!(
        launch::decode_error_report(&error),
        Some(libc::ENOENT),
        "error pipe carried {error:?}"
    );
    assert_eq!(captured.code(), Some(launch::EXIT_EXEC_FAILED));
}

#[test]
fn a_non_executable_file_is_reported_as_eacces_on_the_error_pipe() {
    let dir = temp_dir("eacces");
    let target = dir.path().join("not-executable");
    fs::write(&target, b"#!/bin/sh\necho no\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let mut launcher = spawn_launcher(false, &[target.as_os_str()]);
    launcher.release();
    let error = launcher.error_bytes();
    let captured = launcher.finish();
    assert_eq!(launch::decode_error_report(&error), Some(libc::EACCES));
    assert_eq!(captured.code(), Some(launch::EXIT_EXEC_FAILED));
}

#[test]
fn the_narrowing_filter_with_no_tracer_fails_the_exec_closed() {
    // This is the property the supervisor relies on. If the tracer is not
    // there, `execve` is in the closed set, SECCOMP_RET_TRACE has no tracer to
    // notify, and the kernel answers ENOSYS. The target does not run.
    let dir = temp_dir("narrow");
    let marker = dir.path().join("marker");
    let script = format!("echo ran > {}", marker.display());
    let mut launcher = spawn_launcher(
        true,
        &[OsStr::new("/bin/sh"), OsStr::new("-c"), OsStr::new(&script)],
    );
    launcher.release();
    let error = launcher.error_bytes();
    let captured = launcher.finish();
    assert_eq!(
        launch::decode_error_report(&error),
        Some(libc::ENOSYS),
        "error pipe carried {error:?}"
    );
    assert_eq!(captured.code(), Some(launch::EXIT_EXEC_FAILED));
    assert!(!marker.exists(), "the target ran without a tracer");
}

#[test]
fn a_launcher_given_a_closed_descriptor_refuses_as_a_usage_error() {
    let captured = exec::run_captured(
        Command::new(jail_exe())
            .arg("__launch")
            .arg("--release-fd")
            .arg("999")
            .arg("--error-fd")
            .arg("998")
            .arg("--")
            .arg("/bin/true"),
        Deadline::after(Duration::from_secs(10)),
    )
    .unwrap();
    assert_eq!(captured.code(), Some(launch::EXIT_USAGE));
    assert!(
        captured.stderr.contains("is not open"),
        "stderr was {:?}",
        captured.stderr
    );
}

// ===========================================================================
// the `tool` bubblewrap plan, end to end
// ===========================================================================

struct ToolRun {
    fields: BTreeMap<String, String>,
    captured: exec::Captured,
    before: Vec<OsString>,
    after: Vec<OsString>,
    placeholder_outcomes: Vec<PlaceholderOutcome>,
    placeholder_identities: Vec<((u64, u64), (u64, u64))>,
    workspace: PathBuf,
    _dirs: (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir),
}

/// Build the full `tool` plan over a scanned workspace, run the inside
/// launcher and the inside probe helper through it, and clean the
/// placeholders up afterwards.
fn run_tool_profile(force_args_fd: bool, narrow: bool) -> ToolRun {
    let ws_dir = temp_dir("tool-ws");
    let scratch_dir = temp_dir("tool-scratch");
    let holder_dir = temp_dir("tool-holders");
    let workspace = ws_dir.path().to_path_buf();
    let scratch = scratch_dir.path().to_path_buf();

    fs::create_dir_all(workspace.join(".git")).unwrap();
    fs::write(workspace.join(".git/config"), b"[core]\n").unwrap();
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/lib.rs"), b"// source\n").unwrap();
    fs::write(scratch.join("scratch-marker"), b"marker\n").unwrap();

    let scan = jfs::scan_protected(&workspace).expect("scan the workspace");
    assert_eq!(scan.absent_root_literals(), vec![".ouroboros"]);

    // Taken before the placeholders exist, so that the comparison afterwards
    // shows the workspace as the operator handed it over.
    let before = jfs::listing(&workspace).unwrap();

    let mut plan = BwrapPlan::tool(&workspace, &scratch, &jail_exe());
    plan.bwrap = bwrap_path();
    plan.protected = scan
        .segments
        .iter()
        .map(|s| bwrap::ProtectedBind {
            source: s.path.clone(),
            fd: None,
        })
        .collect();
    let mut placeholders = Vec::new();
    for (index, literal) in scan.absent_root_literals().iter().enumerate() {
        let source = holder_dir.path().join(format!("holder{index}"));
        placeholders
            .push(Placeholder::create(&source, &workspace.join(literal)).expect("placeholder"));
    }
    plan.placeholders = placeholders
        .iter()
        .map(|placeholder| placeholder.mount().clone())
        .collect();

    let checks = [
        "status".to_owned(),
        format!("ws_write=write:{}/allowed.txt", workspace.display()),
        format!("git_write=write:{}/.git/config", workspace.display()),
        format!("git_mkdir=mkdir:{}/.git/objects", workspace.display()),
        format!("absent_mkdir=mkdir:{}/.ouroboros/x", workspace.display()),
        format!("absent_write=write:{}/.ouroboros/x", workspace.display()),
        "home=stat:/home/ouro-ci".to_owned(),
        "operator_home=listdir:/home".to_owned(),
        "tmp=listdir:/tmp".to_owned(),
    ];
    let mut target = vec![
        OsString::from(bwrap::JAIL_INSIDE_PATH),
        OsString::from(probe::INSIDE_SUBCOMMAND),
    ];
    target.extend(checks.iter().map(OsString::from));
    plan.inner = inner_launch_command(RELEASE_FD, ERROR_FD, narrow, &target);
    plan.force_args_fd = force_args_fd;

    let mut fds = FdMap::new();
    let program = seccomp::tool_baseline().unwrap();
    fds.add(seccomp::program_pipe(&program).unwrap(), SECCOMP_FD)
        .unwrap();
    plan.seccomp_fd = Some(SECCOMP_FD);

    let (release_r, release_w) = exec::pipe().unwrap();
    let (error_r, error_w) = exec::pipe().unwrap();
    fds.add(release_r, RELEASE_FD).unwrap();
    fds.add(error_w, ERROR_FD).unwrap();

    let (status_r, status_w) = exec::pipe().unwrap();
    plan.json_status_fd = Some(11);
    fds.add(status_w, 11).unwrap();

    if force_args_fd {
        plan.args_fd = Some(ARGS_FD);
    }
    let rendered = plan.render().unwrap();
    if let Some(payload) = rendered.args_payload.as_ref() {
        let (args_r, args_w) = exec::pipe().unwrap();
        let mut file = std::fs::File::from(args_w);
        file.write_all(payload).unwrap();
        drop(file);
        fds.add(args_r, ARGS_FD).unwrap();
    }

    let mut command = Command::new(&rendered.argv[0]);
    command.args(&rendered.argv[1..]);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    fds.apply(&mut command);
    let child = command.spawn().unwrap();
    drop(fds);

    // Release, then read everything the run produced.
    let mut release = std::fs::File::from(release_w);
    release.write_all(&[1]).unwrap();
    drop(release);

    let mut error = std::fs::File::from(error_r);
    let mut error_bytes = Vec::new();
    error.read_to_end(&mut error_bytes).unwrap();
    assert!(
        error_bytes.is_empty(),
        "exec failed with errno {:?}",
        launch::decode_error_report(&error_bytes)
    );

    let mut status = std::fs::File::from(status_r);
    let mut status_text = String::new();
    status.read_to_string(&mut status_text).unwrap();

    let captured = exec::finish_captured(child, Deadline::after(Duration::from_secs(20))).unwrap();
    assert!(!captured.timed_out, "the tool run did not finish in time");

    let parsed_status = bwrap::parse_json_status(&status_text);
    assert!(
        parsed_status.child_pid.is_some(),
        "bubblewrap reported no namespace init pid: {status_text:?}"
    );
    assert_eq!(
        parsed_status.exit_code,
        Some(0),
        "status was {status_text:?}"
    );

    // The identity each handle pins, beside what the name refers to now —
    // after bubblewrap has bound a mount over it and unmounted it again. A
    // real run is the case the comparison has to survive.
    let placeholder_identities: Vec<((u64, u64), (u64, u64))> = placeholders
        .iter()
        .map(|placeholder| {
            let seen = fs::symlink_metadata(placeholder.destination())
                .expect("the placeholder destination survived the run");
            (placeholder.identity(), (seen.dev(), seen.ino()))
        })
        .collect();
    let placeholder_outcomes = placeholders
        .iter()
        .map(Placeholder::remove_if_unchanged)
        .collect();
    let after = jfs::listing(&workspace).unwrap();

    ToolRun {
        fields: parse_fields(&captured.stdout),
        captured,
        before,
        after,
        placeholder_outcomes,
        placeholder_identities,
        workspace,
        _dirs: (ws_dir, scratch_dir, holder_dir),
    }
}

#[test]
fn the_tool_profile_grants_what_it_says_and_nothing_else() {
    if !live() {
        return;
    }
    let run = run_tool_profile(false, false);
    let field = |k: &str| run.fields.get(k).map_or("<missing>", String::as_str);
    let report = &run.captured.stdout;
    assert_eq!(
        run.captured.code(),
        Some(0),
        "stderr: {}",
        run.captured.stderr
    );

    // Filesystem
    assert_eq!(field("ws_write"), "ok", "workspace not writable\n{report}");
    assert_eq!(
        field("git_write"),
        "EROFS",
        "an existing .git accepted a write\n{report}"
    );
    assert_eq!(field("git_mkdir"), "EROFS");
    assert_eq!(
        field("absent_mkdir"),
        "EROFS",
        "an absent root-level literal was not protected\n{report}"
    );
    assert_eq!(field("absent_write"), "EROFS");
    assert_eq!(
        field("home"),
        "ENOENT",
        "the operator's home is visible inside the jail\n{report}"
    );
    assert_eq!(
        field("operator_home"),
        "ENOENT",
        "/home itself is visible inside the jail\n{report}"
    );
    assert!(
        field("tmp").split(',').any(|n| n == "scratch-marker"),
        "/tmp inside is not the scratch directory: {}\n{report}",
        field("tmp")
    );
    // And the workspace write landed on the host workspace, not somewhere
    // bubblewrap improvised inside the scratch.
    assert!(
        run.workspace.join("allowed.txt").is_file(),
        "the file the sandbox created is not in the host workspace"
    );

    // Process and namespaces
    assert_eq!(field("capeff"), "0000000000000000");
    assert_eq!(field("nonewprivs"), "1");
    assert_eq!(field("seccomp"), "2", "the baseline filter is not in force");
    assert_eq!(field("netdev"), "lo", "the sandbox can see host interfaces");
    assert_eq!(field("jail_exec"), "true");
    assert_eq!(field("cwd"), run.workspace.to_string_lossy());
    // bubblewrap sets PWD itself when --chdir is used; the two names the
    // plan asks for are the only ones it adds.
    assert_eq!(
        field("env_names"),
        "PATH,PWD,TMPDIR",
        "--clearenv leaked names"
    );
    let pids: Vec<&str> = field("proc_pids").split(',').collect();
    assert!(
        pids.len() <= 3 && pids.contains(&"1"),
        "/proc shows host processes: {:?}",
        field("proc_pids")
    );
    // Read from the private /proc of the inner pid namespace, NSpid shows
    // only that namespace's view, and the pid there is a small one. The
    // outer-to-inner mapping is the supervisor's to read from the host /proc.
    let inner_pid: u32 = field("nspid")
        .parse()
        .unwrap_or_else(|e| panic!("NSpid inside was {:?}: {e}", field("nspid")));
    assert!(
        inner_pid <= 4,
        "inner pid {inner_pid} is not a namespace pid"
    );

    // The placeholder is gone and the workspace is otherwise as it was. The
    // read-only bind bubblewrap placed over the mount point, and took away
    // again, left the underlying object alone: the identity registered at
    // creation is still the one the name refers to.
    for (registered, seen) in &run.placeholder_identities {
        assert_eq!(
            registered, seen,
            "a run changed what the placeholder's name refers to"
        );
    }
    assert_eq!(
        run.placeholder_outcomes,
        vec![PlaceholderOutcome::Removed(
            run.workspace.join(".ouroboros")
        )]
    );
    let added: Vec<&OsString> = run
        .after
        .iter()
        .filter(|p| !run.before.contains(p))
        .collect();
    let removed: Vec<&OsString> = run
        .before
        .iter()
        .filter(|p| !run.after.contains(p))
        .collect();
    assert_eq!(
        added,
        vec![&OsString::from("allowed.txt")],
        "the run changed the workspace beyond the file it wrote"
    );
    assert!(removed.is_empty(), "the run removed {removed:?}");
}

#[test]
fn the_same_plan_works_when_handed_over_the_args_descriptor() {
    if !live() {
        return;
    }
    let run = run_tool_profile(true, false);
    assert_eq!(
        run.captured.code(),
        Some(0),
        "stderr: {}",
        run.captured.stderr
    );
    assert_eq!(run.fields.get("ws_write").map(String::as_str), Some("ok"));
    assert_eq!(
        run.fields.get("git_write").map(String::as_str),
        Some("EROFS")
    );
    assert_eq!(run.fields.get("seccomp").map(String::as_str), Some("2"));
}

#[test]
fn bubblewrap_creates_an_absent_bind_destination_and_leaves_it_behind() {
    if !live() {
        return;
    }
    // The measurement behind the placeholder design: given a destination that
    // does not exist inside a bind-mounted workspace, bubblewrap creates the
    // mount point on the shared inode and never removes it. Registering the
    // identity before use, rather than discovering it afterwards, is what
    // makes the cleanup safe.
    let ws_dir = temp_dir("leftover-ws");
    let scratch_dir = temp_dir("leftover-scratch");
    let empty_dir = temp_dir("leftover-empty");
    let workspace = ws_dir.path();
    let destination = workspace.join(".absent-literal");
    assert!(!destination.exists());

    let mut plan = BwrapPlan::tool(workspace, scratch_dir.path(), &jail_exe());
    plan.bwrap = bwrap_path();
    plan.extra_ro_binds = vec![(empty_dir.path().to_path_buf(), destination.clone())];
    plan.inner = vec![OsString::from("/usr/bin/true")];
    let rendered = plan.render().unwrap();
    let mut command = Command::new(&rendered.argv[0]);
    command.args(&rendered.argv[1..]);
    let captured =
        exec::run_captured(&mut command, Deadline::after(Duration::from_secs(20))).unwrap();
    assert_eq!(captured.code(), Some(0), "stderr: {}", captured.stderr);

    let meta = fs::metadata(&destination)
        .expect("bubblewrap left no mount point behind; the placeholder design can be simplified");
    assert!(meta.is_dir());
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
    fs::remove_dir(&destination).unwrap();
}

/// The two kinds of directory the placeholder check has to hold on: one whose
/// filesystem hands a freed inode number straight back, and one that does not.
///
/// This is not decoration. A registered device and inode pair is only an
/// identity while the number cannot be reused, and whether it is reused
/// immediately is a property of the filesystem: tmpfs under `/tmp` does not,
/// ext4 under `$HOME` does. A check tested only on tmpfs is a check tested
/// only where the bug is invisible, which is how this defect reached a hosted
/// runner in the first place.
fn identity_bases(tag: &str) -> Vec<tempfile::TempDir> {
    let mut bases = vec![temp_dir(tag)];
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if home.is_dir()
            && let Ok(dir) = tempfile::Builder::new()
                .prefix(&format!("ouro-j1-{tag}-"))
                .tempdir_in(&home)
        {
            bases.push(dir);
        }
    }
    for base in &bases {
        eprintln!(
            "identity base {} is on {}",
            base.path().display(),
            filesystem_name(base.path())
        );
    }
    bases
}

/// The filesystem behind a path, named where the magic number is one of the
/// two this test cares about.
fn filesystem_name(path: &Path) -> String {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return "unknown".to_owned();
    };
    // SAFETY: `c` is a NUL-terminated path that outlives the call and `buf` is
    // a live, writable statfs.
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::statfs(c.as_ptr(), &raw mut buf) } != 0 {
        return "unknown".to_owned();
    }
    // The magic numbers the kernel documents for the two filesystems this
    // test distinguishes. The literals take `f_type`'s own type, which is
    // signed on some targets and unsigned on others; both hold these values.
    match buf.f_type {
        0x0102_1994 => "tmpfs".to_owned(),
        0x0000_EF53 => "ext2/ext3/ext4".to_owned(),
        other => format!("filesystem {other:#x}"),
    }
}

/// Whether a directory hands a freed inode number straight back.
///
/// Reported, not asserted: the placeholder check must hold either way, and
/// which filesystem does which is the host's business, not this crate's.
fn reuses_inode_numbers(base: &Path) -> bool {
    let probe = base.join("reuse-probe");
    for _ in 0..8 {
        fs::create_dir(&probe).expect("probe dir");
        let first = fs::symlink_metadata(&probe).expect("probe stat").ino();
        fs::remove_dir(&probe).expect("remove probe dir");
        fs::create_dir(&probe).expect("probe dir again");
        let second = fs::symlink_metadata(&probe)
            .expect("probe stat again")
            .ino();
        fs::remove_dir(&probe).expect("remove probe dir again");
        if first == second {
            return true;
        }
    }
    false
}

#[test]
fn a_placeholder_that_changed_is_kept_not_removed() {
    for base in identity_bases("holder") {
        let base = base.path();
        eprintln!(
            "{}: inode numbers are {}",
            base.display(),
            if reuses_inode_numbers(base) {
                "reused immediately"
            } else {
                "not reused immediately"
            }
        );
        let source = base.join("source");
        let destination = base.join("dest");
        let placeholder = Placeholder::create(&source, &destination).unwrap();

        fs::write(destination.join("something"), b"x").unwrap();
        assert_eq!(
            placeholder.remove_if_unchanged(),
            PlaceholderOutcome::KeptNotEmpty(destination.clone())
        );
        fs::remove_file(destination.join("something")).unwrap();

        // Replace it with a different directory of the same name. On a
        // filesystem that reuses inode numbers the replacement would arrive
        // wearing the registered one, were the registered inode free to be
        // handed out — the held handle is what stops that.
        fs::remove_dir(&destination).unwrap();
        fs::create_dir(&destination).unwrap();
        match placeholder.remove_if_unchanged() {
            PlaceholderOutcome::KeptChanged(path, reason) => {
                assert_eq!(path, destination);
                assert!(reason.contains("identity changed"), "reason was {reason}");
            }
            other => panic!(
                "a replaced placeholder must be kept under {}, got {other:?}",
                base.display()
            ),
        }
        assert!(destination.exists(), "a replaced placeholder was removed");
        fs::remove_dir(&destination).unwrap();
    }
}

/// The mechanism the check above rests on, stated on its own.
#[test]
fn a_held_handle_denies_a_recreated_directory_the_same_inode() {
    for base in identity_bases("pinned") {
        let base = base.path();
        let reuses = reuses_inode_numbers(base);
        eprintln!(
            "{} ({}): inode numbers are {}",
            base.display(),
            filesystem_name(base),
            if reuses {
                "reused immediately"
            } else {
                "not reused immediately"
            }
        );

        let source = base.join("source");
        let destination = base.join("dest");
        let placeholder = Placeholder::create(&source, &destination).unwrap();
        let (registered_dev, registered_ino) = placeholder.identity();

        // The handle is still open across this.
        fs::remove_dir(&destination).unwrap();
        fs::create_dir(&destination).unwrap();
        let replacement = fs::symlink_metadata(&destination).unwrap();
        assert_ne!(
            (replacement.dev(), replacement.ino()),
            (registered_dev, registered_ino),
            "a recreated directory got the pinned inode back under {} ({}); \
             the handle did not pin it",
            base.display(),
            filesystem_name(base)
        );

        // And the removal that follows from it refuses to touch the stranger.
        assert!(matches!(
            placeholder.remove_if_unchanged(),
            PlaceholderOutcome::KeptChanged(..)
        ));
        assert!(destination.exists());

        // Dropping the placeholder releases the inode; only then may the
        // number come back, which is what the fix turns on.
        drop(placeholder);
        fs::remove_dir(&destination).unwrap();
    }
}

/// §9.1 says "unchanged", and the permissions are part of what was
/// registered: a placeholder someone has chmod'd is not the thing that was
/// created, even when it is the same inode.
#[test]
fn a_placeholder_whose_permissions_changed_is_kept_not_removed() {
    let dir = temp_dir("chmod-holder");
    let source = dir.path().join("source");
    let destination = dir.path().join("dest");
    let placeholder = Placeholder::create(&source, &destination).unwrap();

    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
    match placeholder.remove_if_unchanged() {
        PlaceholderOutcome::KeptChanged(path, reason) => {
            assert_eq!(path, destination);
            assert!(
                reason.contains("permissions changed"),
                "reason was {reason}"
            );
        }
        other => panic!("a chmod'd placeholder must be kept, got {other:?}"),
    }
    assert!(destination.exists());
}

#[test]
fn a_pre_existing_destination_is_never_treated_as_a_placeholder() {
    let dir = temp_dir("preexisting");
    let source = dir.path().join("source");
    let destination = dir.path().join(".git");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("config"), b"[core]\n").unwrap();
    match Placeholder::create(&source, &destination) {
        Err(bwrap::PlaceholderError::DestinationExists(p)) => assert_eq!(p, destination),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(destination.join("config").exists());
}

#[test]
fn this_hosts_backend_version_is_the_pinned_one() {
    if !live() {
        return;
    }
    let version = bwrap::bwrap_version(&bwrap_path()).expect("bwrap --version");
    assert_eq!(version.major, 0);
    assert!(
        version.minor >= 11,
        "bubblewrap {} is older than the evaluated backend",
        version.raw
    );
}

// ===========================================================================
// cgroups
// ===========================================================================

#[test]
fn a_delegated_leaf_records_the_kernels_own_answer() {
    if !reference_host("a systemd-delegated cgroup subtree") {
        return;
    }
    // SAFETY: fork; the child calls only `pause`, which is
    // async-signal-safe, and never returns.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        loop {
            // SAFETY: pause takes no arguments and is async-signal-safe.
            unsafe { libc::pause() };
        }
    }
    assert!(pid > 0, "fork failed");

    let attempt = cgroup::try_leaf(&format!("ouro-j1-test-{pid}.leaf"), pid, "pids");
    // SAFETY: `pid` is this test's own child.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &raw mut status, 0);
    }
    let cleanup = cgroup::remove_leaf(&attempt);

    let own = attempt.own_cgroup.clone().expect("own cgroup");
    assert!(own.starts_with("/user.slice/"), "own cgroup is {own}");
    let root = attempt
        .delegated_root
        .clone()
        .expect("the reference host delegates a subtree to this account");
    assert!(root.ends_with("user@1001.service"), "{}", root.display());

    // From an SSH session scope the common-ancestor rule forbids the move.
    match attempt.status {
        cgroup::LeafStatus::Moved if attempt.common_ancestor_ok => {}
        cgroup::LeafStatus::MoveFailed { errno } => {
            assert!(
                errno == libc::EACCES || errno == libc::EPERM,
                "the move failed with an unexpected errno {errno}"
            );
            eprintln!(
                "measured: cgroup move from {own} into {} fails with {}",
                root.display(),
                ouro_jail::platform::linux::sys::errno_name(errno)
            );
        }
        ref other => panic!("unexpected placement result: {other}"),
    }
    assert_eq!(attempt.moved(), attempt.common_ancestor_ok);
    cleanup.expect("the leaf must be removed again");
    assert!(
        !attempt.path.as_ref().unwrap().exists(),
        "the leaf was left behind on the host"
    );
    assert!(
        !attempt.subtree_control_changed,
        "the host's delegated subtree already offers pids; nothing should have changed"
    );
}

// ===========================================================================
// doctor probes
// ===========================================================================

#[test]
fn the_probes_report_the_statuses_this_host_warrants() {
    if !live() {
        return;
    }
    let results = probe::run_all(&jail_exe(), &bwrap_path());
    let by_name: BTreeMap<&str, &probe::ProbeResult> =
        results.iter().map(|r| (r.name, r)).collect();
    assert_eq!(by_name.len(), probe::PROBE_NAMES.len());

    // The cgroup rows depend on the session, not only on the host: a leaf can
    // be created and populated only from inside the delegated user subtree,
    // which the conformance driver enters with `systemd-run --user --scope`
    // and a plain SSH session does not. Derive the expectation from those two
    // facts rather than from the probe under test.
    // SAFETY: getuid takes no arguments and cannot fail.
    let in_delegation = cgroup::delegated_root(unsafe { libc::getuid() }).is_some_and(|root| {
        let relative = format!(
            "/{}",
            root.strip_prefix(cgroup::CGROUP_ROOT)
                .expect("the delegated root lies beneath the cgroup mount")
                .display()
        );
        cgroup::own_cgroup().is_ok_and(|own| cgroup::common_ancestor_ok(&own, &relative))
    });
    assert!(
        in_delegation || !ouro_fixture::harness::live_required(),
        "conformance runs inside the delegated user scope; this session is outside it"
    );
    let cgroup_status = if in_delegation {
        ProbeStatus::Available
    } else {
        ProbeStatus::Unavailable
    };

    let expected = [
        ("bwrap_present", ProbeStatus::Available),
        ("user_namespace", ProbeStatus::Available),
        ("pid_namespace", ProbeStatus::Available),
        ("network_namespace", ProbeStatus::Available),
        ("mount_readonly_bind", ProbeStatus::Available),
        ("seccomp_filter_load", ProbeStatus::Available),
        ("ptrace_seize_descendant", ProbeStatus::Available),
        ("observer_closed_set", ProbeStatus::Available),
        ("cgroup_delegated_leaf", cgroup_status),
        ("cgroup_pids", cgroup_status),
        ("cgroup_memory", cgroup_status),
        ("cgroup_cpu", cgroup_status),
        // `available` here means the restriction is on.
        ("apparmor_userns_restriction", ProbeStatus::Available),
        // Which is why nesting is denied.
        ("nested_user_namespace", ProbeStatus::Unavailable),
    ];
    for (name, status) in expected {
        let result = by_name[name];
        assert_eq!(
            result.status, status,
            "{name}: expected {status}, got {} ({}): {}",
            result.status, result.reason_code, result.evidence
        );
        assert!(!result.evidence.is_empty(), "{name} reported no evidence");
        eprintln!("{name} = {} ({})", result.status, result.evidence);
    }
    assert_eq!(
        by_name["nested_user_namespace"].reason_code,
        "nested_sandbox_denied"
    );
    assert_eq!(
        by_name["apparmor_userns_restriction"].reason_code,
        "restriction_on"
    );
}
