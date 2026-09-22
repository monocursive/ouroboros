//! The test harness: everything a test needs *outside* the jail.
//!
//! [`Jail`] builds a private state directory, plumbs the gate, control and
//! trace pipes, runs `ouro-jail` and hands back a [`Run`] with the exit status,
//! the byte-exact streams, the receipts, the control messages and the trace
//! events. [`gate::GateOwner`] plays the trusted owner of jail-v1 §8.2.
//!
//! The harness never sleeps to synchronise. It waits on pipe readability, on
//! EOF and on process exit. Timeouts exist only so a hang fails a test instead
//! of stalling a suite, and are never used to order events.

pub mod gate;
pub mod pipes;
pub mod tempdir;

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use serde_json::Value;

pub use gate::{ExpectedPlan, GateOwner, Proposal, Release};
pub use pipes::{Direction, GateWriter, LineReader};
pub use tempdir::TempDir;

/// True when the suite is running in conformance mode, where a skip is a
/// failure (jail-v1 §16: "a required live capability being skipped makes the
/// conformance job fail").
#[must_use]
pub fn live_required() -> bool {
    std::env::var("OURO_CONFORMANCE").as_deref() == Ok("1")
}

/// Skip a live test, or fail it when conformance mode forbids skipping.
///
/// Call it and return:
///
/// ```ignore
/// if !cfg!(target_os = "linux") {
///     harness::skip_or_fail("Linux only");
///     return;
/// }
/// ```
pub fn skip_or_fail(reason: &str) {
    assert!(
        !live_required(),
        "OURO_CONFORMANCE=1 forbids skipping: {reason}"
    );
    eprintln!("skipped: {reason}");
}

// ------------------------------------------------------------ binary lookup

fn is_executable(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.is_file() && m.permissions().mode() & 0o111 != 0
    })
}

/// Look for `name` beside the running test binary: `target/<profile>/deps/…`
/// puts built binaries one level up, and a plain `target/<profile>/…` run puts
/// them next to it.
fn sibling(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?;
    for _ in 0..3 {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
    None
}

/// An advisory lock held for the duration of a `cargo build`, so parallel test
/// binaries do not race. The lock is released explicitly in `Drop`: a forked
/// child would otherwise hold it until it execs.
struct BuildLock {
    file: std::fs::File,
}

impl BuildLock {
    fn acquire(path: &Path) -> io::Result<BuildLock> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;
        // SAFETY: `file` is an open descriptor owned by this value.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(BuildLock { file })
    }
}

impl Drop for BuildLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor is still open and owned here.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Last resort: build the package on demand.
///
/// This runs *inside* `cargo test`, which already holds the lock on the
/// workspace build directory, so the nested build is given a target directory
/// of its own. Sharing one would block forever, and sharing a build directory
/// between trees is a known source of stale cross-tree artifacts here.
fn build_package(package: &str, name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let release = exe.components().any(|c| c.as_os_str() == "release");
    let work = std::env::temp_dir().join("ouro-fixture-harness");
    let _lock = BuildLock::acquire(&work.join(format!("{package}.lock"))).ok()?;
    if let Some(found) = sibling(name) {
        return Some(found); // another process built it while we waited
    }
    let target_dir = work.join(format!("target-{package}"));
    let mut cmd = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    cmd.arg("build")
        .arg("-p")
        .arg(package)
        .env("CARGO_TARGET_DIR", &target_dir);
    if release {
        cmd.arg("--release");
    }
    eprintln!(
        "ouro-fixture harness: {name} not found beside the test binary; \
         building it into {}",
        target_dir.display()
    );
    let status = cmd.status().ok()?;
    if !status.success() {
        return None;
    }
    let built = target_dir
        .join(if release { "release" } else { "debug" })
        .join(name);
    is_executable(&built)
        .then_some(built)
        .or_else(|| sibling(name))
}

/// The `ouro-fixture` binary: `OURO_FIXTURE_BIN`, else a sibling of the test
/// binary, else built on demand under a lock.
#[must_use]
pub fn fixture_path() -> PathBuf {
    if let Some(p) = std::env::var_os("OURO_FIXTURE_BIN") {
        return PathBuf::from(p);
    }
    sibling("ouro-fixture")
        .or_else(|| build_package("ouro-fixture", "ouro-fixture"))
        .expect("ouro-fixture not found: set OURO_FIXTURE_BIN or run `cargo build -p ouro-fixture`")
}

/// The `ouro-jail` binary, or `None` when this tree has not built one yet.
#[must_use]
pub fn try_jail_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("OURO_JAIL_BIN") {
        let p = PathBuf::from(p);
        return is_executable(&p).then_some(p);
    }
    sibling("ouro-jail")
}

/// The `ouro-jail` binary. Panics with the remediation when it is absent: a
/// live test must fail loudly rather than quietly test nothing.
#[must_use]
pub fn jail_path() -> PathBuf {
    try_jail_path()
        .expect("ouro-jail not found: set OURO_JAIL_BIN or run `cargo build -p ouro-jail`")
}

// --------------------------------------------------------------- the builder

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Kind {
    Control,
    Gate,
    Trace,
}

impl Kind {
    const fn flag(self) -> &'static str {
        match self {
            Kind::Control => "--control-fd",
            Kind::Gate => "--gate-fd",
            Kind::Trace => "--trace-fd",
        }
    }

    const fn direction(self) -> Direction {
        match self {
            Kind::Gate => Direction::JailReads,
            Kind::Control | Kind::Trace => Direction::JailWrites,
        }
    }
}

/// One `ouro-jail` invocation with its private state and channels.
#[must_use]
pub struct Jail {
    program: PathBuf,
    args: Vec<OsString>,
    target_argv: Vec<OsString>,
    envs: Vec<(OsString, Option<OsString>)>,
    root: TempDir,
    kinds: Vec<Kind>,
    receipt: Option<PathBuf>,
    stdin: Option<Vec<u8>>,
    pub timeout: Duration,
}

impl Jail {
    /// A run of the real `ouro-jail`.
    pub fn new() -> io::Result<Jail> {
        Jail::with_program(jail_path())
    }

    /// A run of some other program with the same plumbing, for testing the
    /// harness itself against a stand-in.
    pub fn with_program(program: impl Into<PathBuf>) -> io::Result<Jail> {
        let root = TempDir::new("ouro-jail-harness")?;
        std::fs::create_dir_all(root.path().join("data"))?;
        std::fs::create_dir_all(root.path().join("config"))?;
        Ok(Jail {
            program: program.into(),
            args: Vec::new(),
            target_argv: Vec::new(),
            envs: Vec::new(),
            root,
            kinds: Vec::new(),
            receipt: None,
            stdin: None,
            timeout: Duration::from_secs(60),
        })
    }

    /// The private `OURO_DATA_DIR` for this run.
    #[must_use]
    pub fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    /// The private `OURO_CONFIG_DIR` for this run.
    #[must_use]
    pub fn config_dir(&self) -> PathBuf {
        self.root.path().join("config")
    }

    /// The private root holding both, plus anything a test writes.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    pub fn arg(mut self, a: impl AsRef<OsStr>) -> Jail {
        self.args.push(a.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Jail
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    pub fn env(mut self, k: impl AsRef<OsStr>, v: impl AsRef<OsStr>) -> Jail {
        self.envs
            .push((k.as_ref().to_os_string(), Some(v.as_ref().to_os_string())));
        self
    }

    pub fn env_remove(mut self, k: impl AsRef<OsStr>) -> Jail {
        self.envs.push((k.as_ref().to_os_string(), None));
        self
    }

    /// Bytes fed to the child's stdin; without this, stdin is `/dev/null`.
    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Jail {
        self.stdin = Some(bytes.into());
        self
    }

    /// Ask for `--control-fd`.
    pub fn control(mut self) -> Jail {
        self.kinds.push(Kind::Control);
        self
    }

    /// Ask for `--gate-fd`.
    pub fn gate(mut self) -> Jail {
        self.kinds.push(Kind::Gate);
        self
    }

    /// Ask for `--trace-fd`.
    pub fn trace(mut self) -> Jail {
        self.kinds.push(Kind::Trace);
        self
    }

    /// Ask for `--receipt <root>/receipt.json`.
    pub fn receipt(mut self) -> Jail {
        self.receipt = Some(self.root.path().join("receipt.json"));
        self
    }

    /// The program the jail should run, appended after `--`.
    pub fn target<I, S>(mut self, argv: I) -> Jail
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.target_argv
            .extend(argv.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    /// The `ouro-fixture` binary, as a target argv prefix.
    pub fn target_fixture<I, S>(self, argv: I) -> Jail
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut full: Vec<OsString> = vec![fixture_path().into_os_string()];
        full.extend(argv.into_iter().map(|a| a.as_ref().to_os_string()));
        self.target(full)
    }

    /// Start the jail. The channels are live; nothing has been waited on.
    pub fn spawn(self) -> io::Result<Spawned> {
        let Jail {
            program,
            args,
            target_argv,
            envs,
            root,
            kinds,
            receipt,
            stdin,
            timeout,
        } = self;

        let mut channels: Vec<pipes::Channel> = kinds
            .iter()
            .map(|k| pipes::Channel::new(k.direction()))
            .collect::<io::Result<_>>()?;
        pipes::assign_targets(&mut channels);

        let mut argv: Vec<OsString> = args;
        for (kind, channel) in kinds.iter().zip(channels.iter()) {
            argv.push(kind.flag().into());
            argv.push(channel.target.to_string().into());
        }
        if let Some(path) = &receipt {
            argv.push("--receipt".into());
            argv.push(path.clone().into_os_string());
        }
        if !target_argv.is_empty() {
            argv.push("--".into());
            argv.extend(target_argv.iter().cloned());
        }

        let plan: Vec<(RawFd, RawFd)> = channels
            .iter()
            .map(|c| (c.theirs.as_raw_fd(), c.target))
            .collect();

        let mut cmd = Command::new(&program);
        cmd.args(&argv)
            .env("OURO_DATA_DIR", root.path().join("data"))
            .env("OURO_CONFIG_DIR", root.path().join("config"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        for (k, v) in &envs {
            match v {
                Some(v) => {
                    cmd.env(k, v);
                }
                None => {
                    cmd.env_remove(k);
                }
            }
        }
        // SAFETY: the closure runs between `fork` and `exec` in the child. It
        // calls only `dup2` and `fcntl`, both async-signal-safe, over a plan
        // built before the fork whose targets collide with no source.
        unsafe {
            cmd.pre_exec(move || pipes::place_in_child(&plan));
        }

        let mut child = cmd.spawn()?;

        // Close the jail's ends here so EOF propagates when the jail exits.
        let mut ours: Vec<std::os::fd::OwnedFd> = Vec::new();
        for c in channels {
            let pipes::Channel {
                ours: o, theirs, ..
            } = c;
            drop(theirs);
            ours.push(o);
        }

        if let Some(bytes) = stdin
            && let Some(mut pipe) = child.stdin.take()
        {
            use std::io::Write as _;
            pipe.write_all(&bytes)?;
        }

        let mut control = None;
        let mut gate = None;
        let mut trace_reader = None;
        for (kind, fd) in kinds.iter().zip(ours) {
            match kind {
                Kind::Control => {
                    let mut r = LineReader::new(fd);
                    r.timeout = timeout;
                    control = Some(r);
                }
                Kind::Gate => gate = Some(GateWriter::new(fd)),
                Kind::Trace => {
                    let mut r = LineReader::new(fd);
                    r.timeout = timeout;
                    trace_reader = Some(r);
                }
            }
        }

        let stdout = child.stdout.take().map(drain_thread);
        let stderr = child.stderr.take().map(drain_thread);

        Ok(Spawned {
            child,
            control,
            gate,
            trace_reader,
            stdout,
            stderr,
            root,
            receipt,
            control_seen: Vec::new(),
        })
    }

    /// Start the jail and wait for it, with no owner interaction.
    pub fn run(self) -> io::Result<Run> {
        self.spawn()?.wait()
    }
}

fn drain_thread<R: std::io::Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut r, &mut buf);
        buf
    })
}

/// A running jail with its channels attached.
pub struct Spawned {
    child: Child,
    control: Option<LineReader>,
    gate: Option<GateWriter>,
    trace_reader: Option<LineReader>,
    stdout: Option<std::thread::JoinHandle<Vec<u8>>>,
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
    root: TempDir,
    receipt: Option<PathBuf>,
    control_seen: Vec<Value>,
}

impl Spawned {
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// The prepared receipt written to `--receipt PATH`, when it is there yet.
    #[must_use]
    pub fn receipt_value(&self) -> Option<Value> {
        let path = self.receipt.as_ref()?;
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// The scripted gate owner for this run. Panics when the run asked for
    /// neither `--control-fd` nor `--gate-fd`.
    pub fn owner(&mut self) -> GateOwner<'_> {
        let control = self
            .control
            .as_mut()
            .expect("this run has no control channel: call Jail::control()");
        GateOwner::new(control, &mut self.gate, &mut self.control_seen)
    }

    /// Kill this jail. Only ever the process the harness started itself.
    pub fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }

    /// Wait for exit and collect everything.
    pub fn wait(mut self) -> io::Result<Run> {
        // A gate the test never used is closed here, which is the "withheld
        // then EOF" case; `gate_closed_by_harness` records that it was us.
        let gate_closed_by_harness = self.gate.take().is_some();

        let status = self.child.wait()?;

        let mut control_messages = std::mem::take(&mut self.control_seen);
        if let Some(mut reader) = self.control.take() {
            for line in reader.drain().unwrap_or_default() {
                if line.is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_slice::<Value>(&line) {
                    control_messages.push(v);
                }
            }
        }

        let mut trace_events = Vec::new();
        if let Some(mut reader) = self.trace_reader.take() {
            for line in reader.drain().unwrap_or_default() {
                if line.is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_slice::<Value>(&line) {
                    trace_events.push(v);
                }
            }
        }

        let stdout = self
            .stdout
            .take()
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();
        let stderr = self
            .stderr
            .take()
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();

        Ok(Run {
            status,
            stdout,
            stderr,
            control_messages,
            trace_events,
            data_dir: self.root.path().join("data"),
            receipt_path: self.receipt.take(),
            gate_closed_by_harness,
            _root: self.root,
        })
    }
}

/// Everything one jail run produced.
pub struct Run {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub control_messages: Vec<Value>,
    pub trace_events: Vec<Value>,
    pub data_dir: PathBuf,
    pub receipt_path: Option<PathBuf>,
    /// True when the harness, not the test, closed the gate at `wait` time.
    pub gate_closed_by_harness: bool,
    _root: TempDir,
}

impl Run {
    #[must_use]
    pub fn code(&self) -> Option<i32> {
        self.status.code()
    }

    #[must_use]
    pub fn signal(&self) -> Option<i32> {
        self.status.signal()
    }

    #[must_use]
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    #[must_use]
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// The fixture's own report lines, parsed from stdout.
    #[must_use]
    pub fn fixture_lines(&self) -> Vec<Value> {
        self.stdout
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .filter_map(|l| serde_json::from_slice::<Value>(l).ok())
            .collect()
    }

    /// Every receipt found under the private data directory.
    ///
    /// `jail.json` is read as one JSON document when it parses that way and as
    /// NDJSON otherwise, because jail-v1 §7 fixes the file name but the J1
    /// core slice chooses between the two encodings.
    #[must_use]
    pub fn receipts(&self) -> Vec<Value> {
        let mut out = Vec::new();
        collect_receipts(&self.data_dir, &mut out);
        if let Some(p) = &self.receipt_path
            && let Ok(text) = std::fs::read_to_string(p)
        {
            push_json(&text, &mut out);
        }
        out
    }

    /// The last receipt with this phase, when there is one.
    #[must_use]
    pub fn receipt_phase(&self, phase: &str) -> Option<Value> {
        let mut last = None;
        for r in self.receipts() {
            if r.get("phase").and_then(Value::as_str) == Some(phase) {
                last = Some(r);
            }
        }
        last
    }

    /// Control messages of one kind, in order.
    #[must_use]
    pub fn control_kind(&self, kind: &str) -> Vec<&Value> {
        self.control_messages
            .iter()
            .filter(|m| m.get("kind").and_then(Value::as_str) == Some(kind))
            .collect()
    }
}

fn collect_receipts(dir: &Path, out: &mut Vec<Value>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_receipts(&path, out);
        } else if path.file_name() == Some(OsStr::new("jail.json"))
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            push_json(&text, out);
        }
    }
}

fn push_json(text: &str, out: &mut Vec<Value>) {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        out.push(v);
        return;
    }
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            out.push(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_required_follows_the_conformance_variable_exactly() {
        // The process environment is shared between tests, so this asserts the
        // predicate against whatever the suite was started with rather than
        // mutating it.
        let expected = std::env::var("OURO_CONFORMANCE").as_deref() == Ok("1");
        assert_eq!(live_required(), expected);
    }

    #[test]
    fn skip_or_fail_panics_only_in_conformance_mode() {
        if live_required() {
            let r = std::panic::catch_unwind(|| skip_or_fail("deliberate"));
            assert!(r.is_err(), "a skip must fail under OURO_CONFORMANCE=1");
        } else {
            skip_or_fail("deliberate: this line is expected in the log");
        }
    }

    #[test]
    fn the_fixture_binary_is_locatable_and_executable() {
        let p = fixture_path();
        assert!(is_executable(&p), "{} is not executable", p.display());
    }

    #[test]
    fn a_missing_jail_binary_is_reported_as_missing_not_faked() {
        // In this worktree `ouro-jail` does not exist yet (the core slice owns
        // it), so the harness must say so rather than invent a path.
        match try_jail_path() {
            Some(p) => assert!(is_executable(&p)),
            None => {
                let r = std::panic::catch_unwind(jail_path);
                assert!(r.is_err(), "jail_path must panic when there is no binary");
            }
        }
    }

    #[test]
    fn the_builder_gives_each_run_its_own_private_state() {
        let a = Jail::with_program("/bin/true").unwrap();
        let b = Jail::with_program("/bin/true").unwrap();
        assert_ne!(a.data_dir(), b.data_dir());
        assert!(a.data_dir().is_dir() && a.config_dir().is_dir());
    }

    #[test]
    fn receipts_read_both_a_single_document_and_ndjson() {
        let dir = TempDir::new("ouro-receipts-test").unwrap();
        let nested = dir.path().join("attempts/att_1");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("jail.json"), r#"{"phase":"prepared"}"#).unwrap();
        let other = dir.path().join("attempts/att_2");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(
            other.join("jail.json"),
            "{\"phase\":\"prepared\"}\n{\"phase\":\"settled\"}\n",
        )
        .unwrap();

        let mut out = Vec::new();
        collect_receipts(dir.path(), &mut out);
        let phases: Vec<&str> = out
            .iter()
            .filter_map(|v| v.get("phase").and_then(Value::as_str))
            .collect();
        assert_eq!(phases.len(), 3, "got {phases:?}");
        assert!(phases.contains(&"settled"));
    }

    #[test]
    fn the_build_lock_is_released_when_dropped() {
        let dir = TempDir::new("ouro-lock-test").unwrap();
        let path = dir.path().join("x.lock");
        {
            let _lock = BuildLock::acquire(&path).unwrap();
        }
        // A second acquisition must not block; the bound is the test timeout.
        let _again = BuildLock::acquire(&path).unwrap();
    }
}
