//! Shared scaffolding for the suites that drive the bare tracer over the C
//! fixtures in `tests/fixtures/`.
//!
//! Each fixture is one C program built at test time with the system
//! compiler ([`Fixture`]). An observer fixture doubles as the inside launcher
//! of jail-v1 §3.6 (`launch` in `fixtures/common.h`): it installs the filter
//! this crate produces — read from a file, never a second copy of the
//! program — blocks reading one byte from stdin, and then execs the target.
//! That is the sequence the product's launcher performs, so the tests
//! exercise the attach window as it really exists. Every other mode prints
//! one [`Report`] line per operation.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ouro_fixture::harness::{self, Jail, Run};
use ouro_jail::platform::linux::identity;
use ouro_jail::platform::linux::seccomp;
use ouro_jail::platform::linux::tracer::{
    ClosedOp, GapReason, OpSet, Tracer, TracerConfig, TracerEvent, TracerSummary, cmdline,
    descendants,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// One tracer at a time
// ---------------------------------------------------------------------------

/// Serialise the checks of a test binary that drives the tracer.
///
/// Every check here drives real processes. A tracer's thread owns
/// `waitpid(-1, __WALL)` for the whole process, so while one is attached it
/// reaps *every* child this process has, including the `gcc` a second check is
/// waiting on and the launcher a second tracer just seized. Two of them at
/// once do not race on any data structure; they steal each other's children,
/// and the loser waits for a status that has already been collected.
///
/// That is a property of the binary, not of how it is invoked, so it is
/// enforced here rather than by passing `--test-threads=1`: the checks are
/// correct under any parallelism the runner chooses. Each test binary has its
/// own copy of this lock, which is all it needs: a tracer only reaps the
/// children of its own process.
pub fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    // A check that panicked while holding this poisoned it. There is no shared
    // state behind the lock — only the process's children, which that check no
    // longer has — so the next one takes the guard and carries on.
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Building a fixture
// ---------------------------------------------------------------------------

/// What every fixture includes: `report`, the inside launcher, and the native
/// spelling of each pathname call.
const COMMON_H: &str = include_str!("../fixtures/common.h");

/// The compiler, named absolutely like every other program these checks run.
const GCC: &str = "/usr/bin/gcc";

/// A C fixture: one program, built at most once per test binary.
pub struct Fixture {
    /// The program's name: its source file is `<name>.c`.
    pub name: &'static str,
    /// Its source (`include_str!` of `tests/fixtures/<name>.c`).
    pub source: &'static str,
    /// Whether it links with `-pthread`.
    pub pthread: bool,
    /// The filter its launcher installs, written beside it as `filter.bin`.
    pub filter: fn() -> Vec<u8>,
}

/// A built fixture: the program and the filter file its launcher installs.
#[derive(Clone, Debug)]
pub struct Built {
    pub helper: PathBuf,
    pub filter: PathBuf,
}

impl Built {
    /// `helper launch FILTER`: the launcher, waiting for the program to exec
    /// and its arguments.
    pub fn launcher(&self) -> Command {
        let mut command = Command::new(&self.helper);
        command.arg("launch").arg(&self.filter);
        command
    }
}

impl Fixture {
    /// The fixture, built on first use in this process.
    ///
    /// # Errors
    /// Why it could not be built: no compiler, or what the compiler said.
    pub fn build(&self) -> Result<Built, String> {
        static BUILT: Mutex<BTreeMap<&'static str, Result<Built, String>>> =
            Mutex::new(BTreeMap::new());
        BUILT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(self.name)
            .or_insert_with(|| compile(self))
            .clone()
    }

    /// [`Fixture::build`], or `None` after `skipped:` (a failure under
    /// `OURO_CONFORMANCE=1`) naming why it could not be built.
    pub fn built(&self) -> Option<Built> {
        match self.build() {
            Ok(built) => Some(built),
            Err(error) => {
                harness::skip_or_fail(&format!("the {} fixture: {error}", self.name));
                None
            }
        }
    }

    /// Prepare the check `name`: every path in `tools` installed, the fixture
    /// built, and a private working directory. `None` means the check skipped
    /// (`skipped:` names why) and must return.
    pub fn setup(&self, name: &str, tools: &[&str]) -> Option<Work> {
        for path in tools {
            if !Path::new(path).exists() {
                harness::skip_or_fail(&format!("{name}: {path} is not installed"));
                return None;
            }
        }
        let built = match self.build() {
            Ok(built) => built,
            Err(error) => {
                harness::skip_or_fail(&format!(
                    "{name}: the {} fixture could not be built: {error}",
                    self.name
                ));
                return None;
            }
        };
        Some(Work {
            dir: super::private_tempdir(),
            built,
        })
    }
}

/// Compile `fixture` into a directory named by the digest of everything the
/// build reads: the source, `common.h`, the compiler flags and the filter
/// bytes.
///
/// The directory is under Cargo's scratch area for integration tests
/// (`CARGO_TARGET_TMPDIR`), not the shared `/tmp`, and it is reused by every
/// later run of any test binary that builds the same inputs. A directory per
/// process would have to be removed when the process exits, which a test
/// binary has no hook for; one per content is never orphaned, and only grows
/// when the inputs change (`cargo clean` removes them all). The build happens
/// in a staging directory named by this process's id and is renamed into
/// place only once complete, so a concurrent build of the same inputs, or one
/// that died half-way, never leaves a directory that looks built.
fn compile(fixture: &Fixture) -> Result<Built, String> {
    if !Path::new(GCC).exists() {
        return Err(format!("{GCC} is not installed"));
    }
    // `-B` beside the compiler, so building the fixture does not depend on
    // `PATH`: `gcc` looks up `as` and `ld` there. A host that has the compiler
    // but not its assembler still skips, with that as the reason.
    let mut flags = vec!["-O1", "-Wall"];
    if fixture.pthread {
        flags.push("-pthread");
    }
    flags.push("-B/usr/bin");
    let filter = (fixture.filter)();
    let mut digest = Sha256::new();
    for part in [
        fixture.source.as_bytes(),
        COMMON_H.as_bytes(),
        flags.join(" ").as_bytes(),
        &filter,
    ] {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    let digest: String = digest.finalize()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("c-fixtures");
    let dir = root.join(format!("{}-{digest}", fixture.name));
    let built = Built {
        helper: dir.join("helper"),
        filter: dir.join("filter.bin"),
    };
    if dir.is_dir() {
        // Complete only with both outputs: a build cache that restores the
        // directory but not the compiled helper (as CI's target cache can)
        // must rebuild, not hand every check a launcher that is not there.
        if built.helper.is_file() && built.filter.is_file() {
            return Ok(built);
        }
        std::fs::remove_dir_all(&dir).map_err(|e| format!("remove {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
    remove_dead_staging(&root);
    let staging = root.join(format!(".{}-{digest}.{}", fixture.name, std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir(&staging).map_err(|e| format!("create {}: {e}", staging.display()))?;
    let result = stage(fixture, &staging, &flags, &filter).and_then(|()| {
        match std::fs::rename(&staging, &dir) {
            Ok(()) => Ok(()),
            // Another process built the same inputs first: its directory is
            // complete, since it got there by the same rename.
            Err(_) if dir.is_dir() => Ok(()),
            Err(error) => Err(format!("rename into {}: {error}", dir.display())),
        }
    });
    let _ = std::fs::remove_dir_all(&staging);
    result.map(|()| built)
}

/// Write the sources and the filter into `staging` and compile there.
fn stage(fixture: &Fixture, staging: &Path, flags: &[&str], filter: &[u8]) -> Result<(), String> {
    let source = staging.join(format!("{}.c", fixture.name));
    std::fs::write(&source, fixture.source).map_err(|e| format!("write the source: {e}"))?;
    std::fs::write(staging.join("common.h"), COMMON_H)
        .map_err(|e| format!("write common.h: {e}"))?;
    let out = Command::new(GCC)
        .args(flags)
        .arg("-o")
        .arg(staging.join("helper"))
        .arg(&source)
        .output()
        .map_err(|e| format!("run gcc: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "gcc failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    // The launcher installs the bytes this crate produces. There is no second
    // copy of the program anywhere in the tests.
    std::fs::write(staging.join("filter.bin"), filter).map_err(|e| format!("write filter.bin: {e}"))
}

/// Remove the staging directories of builds whose process is gone: one that
/// was killed mid-build leaves its staging directory behind.
fn remove_dead_staging(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|name| name.starts_with('.'))
            .and_then(|name| name.rsplit_once('.'))
            .and_then(|(_, pid)| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if !Path::new(&format!("/proc/{pid}")).exists() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

// ---------------------------------------------------------------------------
// A check's working directory, and the launcher it runs
// ---------------------------------------------------------------------------

/// A check's private working directory (mode 0700, removed when the check
/// ends), and the built fixture it runs.
pub struct Work {
    dir: TempDir,
    built: Built,
}

impl std::ops::Deref for Work {
    type Target = Built;

    fn deref(&self) -> &Built {
        &self.built
    }
}

impl Work {
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// `name` in the working directory, as text.
    pub fn path(&self, name: &str) -> String {
        self.dir().join(name).to_string_lossy().into_owned()
    }

    /// The working directory, as text.
    pub fn base(&self) -> String {
        self.dir().to_string_lossy().into_owned()
    }

    /// The fixture program, as text.
    pub fn helper_s(&self) -> String {
        self.helper.to_string_lossy().into_owned()
    }
}

/// A launcher that is running and blocked on its release pipe.
pub struct Launched {
    pub pid: libc::pid_t,
    /// Signals reach this process and no other, even after the tracer reaped
    /// it and its number went to someone else.
    pidfd: OwnedFd,
    release: ChildStdin,
    pub output: BufReader<ChildStdout>,
}

impl Launched {
    /// Wait until the launcher has finished its own exec and installed the
    /// filter. Seizing before that would attach in the middle of an exec this
    /// test never asked about, and the kernel would rightly report that
    /// transition too.
    fn await_ready(&mut self) {
        let mut line = String::new();
        self.output
            .read_line(&mut line)
            .expect("the launcher announces itself");
        let report = Report::parse(line.trim_end_matches('\n'))
            .unwrap_or_else(|| panic!("unparseable readiness line {line:?}"));
        assert_eq!(report.label, "ready", "unexpected first line {line:?}");
    }

    /// Let the launcher exec.
    pub fn release(&mut self) {
        self.release
            .write_all(b"g")
            .expect("write the release byte");
        self.release.flush().expect("flush the release byte");
    }

    /// The rest of the fixture's stdout, as bytes. Used where the output
    /// carries a pathname that is not required to be text.
    pub fn raw_output(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = self.output.read_to_end(&mut buf);
        buf
    }

    /// The rest of the fixture's stdout, one [`Report`] per line it parses.
    pub fn lines(&mut self) -> Vec<Report> {
        let mut out = Vec::new();
        let mut line = String::new();
        while self.output.read_line(&mut line).unwrap_or(0) > 0 {
            if let Some(report) = Report::parse(line.trim_end_matches('\n')) {
                out.push(report);
            }
            line.clear();
        }
        out
    }

    /// Send `signal` to the launcher, or to the program it became.
    ///
    /// # Errors
    /// `ESRCH` once the process has been reaped.
    pub fn signal(&self, signal: libc::c_int) -> std::io::Result<()> {
        identity::pidfd_send_signal(self.pidfd.as_raw_fd(), signal)
    }
}

impl Drop for Launched {
    fn drop(&mut self) {
        // The tracer thread owns every wait in this process, so the child is
        // never waited on here. Killing is only a safety net for a test that
        // failed before releasing; a process that already ended is ESRCH.
        let _ = self.signal(libc::SIGKILL);
    }
}

/// Spawn `command` (the launcher, or a process it runs under) with its stdin
/// as the release pipe and its stdout read here, and wait for "ready".
pub fn spawn_launcher(mut command: Command) -> Launched {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the launcher");
    let pid = child.id() as libc::pid_t;
    // Before anything can reap it: no tracer is attached yet, and the child
    // is never waited on here.
    let pidfd = identity::pidfd_open(pid).expect("a pidfd for the launcher");
    let release = child.stdin.take().expect("stdin pipe");
    let output = BufReader::new(child.stdout.take().expect("stdout pipe"));
    // `std::process::Child` never reaps on drop, and the tracer thread owns
    // every wait in this process, so the handle itself is not kept.
    drop(child);
    let mut launched = Launched {
        pid,
        pidfd,
        release,
        output,
    };
    launched.await_ready();
    launched
}

/// The launcher, with the observer's filter only (the `none` shape), set to
/// exec `argv`.
pub fn launch(work: &Work, argv: &[&str]) -> Launched {
    let mut command = work.launcher();
    command.args(argv);
    spawn_launcher(command)
}

/// The `tool` enforcement baseline, then the observer's filter: the contained
/// shape (`launch2` in `common.h`), set to exec `argv`.
pub fn launch_tool(work: &Work, argv: &[&str]) -> Launched {
    let baseline = seccomp::tool_baseline().expect("the tool baseline");
    let path = work.path("baseline.bin");
    std::fs::write(&path, baseline.to_bytes()).expect("write the baseline");
    let mut command = Command::new(&work.helper);
    command
        .arg("launch2")
        .arg(&path)
        .arg(&work.filter)
        .args(argv);
    spawn_launcher(command)
}

/// Wait for the inside launcher to appear under `root` and return its host
/// pid, validated by its argv.
pub fn find_launcher(root: libc::pid_t, argv0: &[u8], budget: Duration) -> Option<libc::pid_t> {
    let mut found = None;
    let _ = super::within(budget, || {
        found = descendants(root).into_iter().find(|pid| {
            cmdline(*pid).is_some_and(|argv| argv.first().is_some_and(|first| first == argv0))
        });
        found.is_some()
    });
    found
}

/// A FIFO at `path`, mode 0600.
pub fn mkfifo(path: impl AsRef<Path>) {
    let path = path.as_ref();
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("a path");
    // SAFETY: `c` is a NUL-terminated path that outlives the call, which
    // reads it and nothing else.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(
        rc,
        0,
        "mkfifo {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
}

// ---------------------------------------------------------------------------
// What the fixture said
// ---------------------------------------------------------------------------

/// One line of fixture output (`report_line` in `common.h`):
/// `label <TAB> raw return <TAB> errno <TAB> path <TAB> path2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub label: String,
    pub raw: i64,
    pub errno: i32,
    pub path: String,
    pub path2: String,
}

impl Report {
    pub fn parse(line: &str) -> Option<Report> {
        let mut fields = line.split('\t');
        let label = fields.next()?.to_string();
        let raw = fields.next()?.parse().ok()?;
        let errno = fields.next()?.parse().ok()?;
        Some(Report {
            label,
            raw,
            errno,
            path: fields.next().unwrap_or_default().to_string(),
            path2: fields.next().unwrap_or_default().to_string(),
        })
    }

    /// Every line of `text` that parses.
    pub fn parse_all(text: &str) -> Vec<Report> {
        text.lines().filter_map(Report::parse).collect()
    }

    /// The signed raw syscall return the kernel produced, which is what the
    /// observer reports: the value on success, `-errno` on failure.
    pub fn ret(&self) -> i64 {
        if self.errno == 0 {
            self.raw
        } else {
            -i64::from(self.errno)
        }
    }

    /// The first line labelled `label`.
    pub fn find<'a>(reports: &'a [Report], label: &str) -> &'a Report {
        reports
            .iter()
            .find(|r| r.label == label)
            .unwrap_or_else(|| panic!("no fixture line {label:?} in {reports:#?}"))
    }
}

// ---------------------------------------------------------------------------
// What the observer said
// ---------------------------------------------------------------------------

/// Everything the observer said, and its counters.
pub struct Observed {
    pub events: Vec<TracerEvent>,
    pub summary: TracerSummary,
}

impl Observed {
    pub fn syscalls(&self) -> Vec<&TracerEvent> {
        self.events
            .iter()
            .filter(|event| matches!(event, TracerEvent::Syscall { .. }))
            .collect()
    }

    pub fn of_op(&self, op: ClosedOp) -> Vec<&TracerEvent> {
        self.events
            .iter()
            .filter(|event| matches!(event, TracerEvent::Syscall { op: o, .. } if *o == op))
            .collect()
    }

    pub fn exits(&self) -> Vec<(libc::pid_t, i32)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Exit { pid, status, .. } => Some((*pid, *status)),
                _ => None,
            })
            .collect()
    }

    pub fn execs(&self) -> Vec<libc::pid_t> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Exec { pid, .. } => Some(*pid),
                _ => None,
            })
            .collect()
    }

    pub fn forks(&self) -> Vec<(libc::pid_t, libc::pid_t)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Fork { parent, child, .. } => Some((*parent, *child)),
                _ => None,
            })
            .collect()
    }

    pub fn gaps(&self) -> Vec<(GapReason, OpSet, Option<u64>)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Gap {
                    reason, ops, count, ..
                } => Some((*reason, *ops, *count)),
                _ => None,
            })
            .collect()
    }

    pub fn has_gap(&self, reason: GapReason) -> bool {
        self.gaps().iter().any(|(r, _, _)| *r == reason)
    }

    /// The exits of children of this process that were never traced.
    pub fn untraced_exits(&self) -> Vec<(libc::pid_t, i32)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::UntracedChildExit { pid, status } => Some((*pid, *status)),
                _ => None,
            })
            .collect()
    }

    pub fn finished(&self) -> bool {
        self.events
            .iter()
            .any(|event| matches!(event, TracerEvent::Finished))
    }
}

/// Attach, with a message that names what was refused.
pub fn attach(pid: libc::pid_t, config: TracerConfig) -> Tracer {
    Tracer::attach(pid, config).unwrap_or_else(|err| panic!("attach to {pid} failed: {err}"))
}

/// Read every event until `Finished` (kept as the last event) or `budget`
/// runs out, then take the summary.
pub fn collect(tracer: Tracer, budget: Duration) -> Observed {
    let deadline = Instant::now() + budget;
    let mut events = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tracer.events().recv_timeout(left) {
            Ok(TracerEvent::Finished) => {
                events.push(TracerEvent::Finished);
                break;
            }
            Ok(event) => events.push(event),
            Err(_) => break,
        }
    }
    let summary = tracer.finish();
    Observed { events, summary }
}

/// The primary and secondary path of a syscall event, as text.
pub fn paths(event: &TracerEvent) -> (String, String) {
    match event {
        TracerEvent::Syscall { args, .. } => (
            args.path
                .as_ref()
                .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
                .unwrap_or_default(),
            args.path2
                .as_ref()
                .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
                .unwrap_or_default(),
        ),
        _ => (String::new(), String::new()),
    }
}

/// The primary path of a syscall event, as text.
pub fn primary(event: &TracerEvent) -> String {
    paths(event).0
}

/// The syscall and operation the native table reports for an operation the
/// fixtures make through `native_*` in `common.h`, named here by its x86_64
/// spelling. AArch64 has only the `*at` calls, and reports `rmdir` as the
/// `unlinkat` it is.
pub fn native_expectation(syscall: &'static str, op: ClosedOp) -> (&'static str, ClosedOp) {
    if cfg!(target_arch = "aarch64") {
        match syscall {
            "mkdir" => ("mkdirat", op),
            "rename" => ("renameat", op),
            "link" => ("linkat", op),
            "symlink" => ("symlinkat", op),
            "unlink" => ("unlinkat", op),
            "rmdir" => ("unlinkat", ClosedOp::Unlink),
            "creat" | "open" => ("openat", op),
            "mknod" => ("mknodat", op),
            _ => (syscall, op),
        }
    } else {
        (syscall, op)
    }
}

// ---------------------------------------------------------------------------
// A fixture run through the product
// ---------------------------------------------------------------------------

/// One `ouro-jail run` over a private workspace holding the fixture at
/// `<workspace>/bin/<name>`, a FIFO nobody opens for reading at
/// `<workspace>/fifo`, and an empty `<workspace>/ops`.
pub struct Case {
    pub jail: Jail,
    pub workspace: PathBuf,
    pub helper: PathBuf,
    pub fifo: PathBuf,
    pub ops: PathBuf,
}

impl Fixture {
    /// A [`Case`] of `profile` and `evidence` on `jail`, with a trace and a
    /// control transcript; `None` after `skipped:` when the fixture could not
    /// be built.
    pub fn case_on(&self, jail: Jail, profile: &str, evidence: &str) -> Option<Case> {
        let built = self.built()?;
        let workspace = jail.root().join("workspace");
        private_dir(&workspace.join("bin"));
        private_dir(&workspace.join("ops"));
        let helper = workspace.join("bin").join(self.name);
        std::fs::copy(&built.helper, &helper).expect("copy the fixture into the workspace");
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755))
            .expect("make the fixture executable");
        let fifo = workspace.join("fifo");
        mkfifo(&fifo);
        let jail = jail
            .arg("run")
            .arg("--profile")
            .arg(profile)
            .arg("--evidence")
            .arg(evidence)
            .arg("--workspace")
            .arg(&workspace)
            .trace()
            .control();
        Some(Case {
            jail,
            ops: workspace.join("ops"),
            workspace,
            helper,
            fifo,
        })
    }
}

impl Case {
    /// The fixture's argv for `mode` and its arguments.
    pub fn argv(&self, mode: &str, rest: &[&dyn AsRef<std::ffi::OsStr>]) -> Vec<OsString> {
        let mut argv = vec![self.helper.clone().into_os_string(), OsString::from(mode)];
        argv.extend(rest.iter().map(|arg| arg.as_ref().to_os_string()));
        argv
    }
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).expect("create a workspace directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("make a workspace directory private");
}

/// The trace events whose source is the observer.
pub fn audit_events(run: &Run) -> Vec<&Value> {
    run.trace_events()
        .iter()
        .filter(|event| event["source"] == "audit")
        .collect()
}

/// The class entry, asserted active with exactly `count` results.
pub fn assert_active(receipt: &Value, class: &str, count: u64) {
    let entry = &receipt["coverage"][class];
    assert_eq!(entry["status"], "active", "{class}: {entry:#}");
    assert_eq!(
        entry["observed_count"], count,
        "{class}: the count must be what the fixture did: {entry:#}"
    );
    assert!(
        entry["gaps"].as_array().expect("a gap list").is_empty(),
        "{class}"
    );
}
