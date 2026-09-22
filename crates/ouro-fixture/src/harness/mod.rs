//! The test harness: everything a test needs *outside* the jail.
//!
//! [`Jail`] builds a private state directory, plumbs the gate, control and
//! trace pipes, runs `ouro-jail` and hands back a [`Run`] with the exit status,
//! the byte-exact streams, the receipts, the control messages and the trace
//! events. [`gate::GateOwner`] plays the trusted owner of jail-v1 §8.2.
//! [`HttpServer`] is a loopback origin that records the requests it saw, and
//! [`UnixProbe`] a host socket that records whether anything reached it.
//!
//! The harness never sleeps to synchronise. It waits on pipe readability, on
//! EOF and on process exit. Timeouts exist only so a hang fails a test instead
//! of stalling a suite, and are never used to order events.

pub mod gate;
pub mod http;
pub mod pipes;
pub mod tempdir;
pub mod unix_probe;

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use serde_json::Value;

pub use gate::{ExpectedPlan, GateOwner, Proposal, Release};
pub use http::{HttpServer, SeenRequest};
pub use pipes::{Direction, GateWriter, LineReader};
pub use tempdir::TempDir;
pub use unix_probe::{ProbeKind, UnixProbe};

/// The name of the variable that turns a skip into a failure.
pub const CONFORMANCE_VAR: &str = "OURO_CONFORMANCE";

/// Conformance mode is exactly `OURO_CONFORMANCE=1`, and nothing else.
///
/// Separated from the environment so a plain `cargo test` proves the rule.
/// Deleting the comparison is caught here, not only under the variable.
#[must_use]
pub fn conformance_mode(value: Option<&str>) -> bool {
    value == Some("1")
}

/// True when the suite is running in conformance mode, where a skip is a
/// failure (jail-v1 §16: "a required live capability being skipped makes the
/// conformance job fail").
#[must_use]
pub fn live_required() -> bool {
    conformance_mode(std::env::var(CONFORMANCE_VAR).ok().as_deref())
}

/// What a skip must do. `Err` is the message the caller must panic with.
///
/// Also separated from the environment: a mutation that lets a skip pass in
/// conformance mode is caught by a plain unit test.
pub fn skip_decision(live_required: bool, reason: &str) -> Result<String, String> {
    if live_required {
        Err(format!("{CONFORMANCE_VAR}=1 forbids skipping: {reason}"))
    } else {
        Ok(format!("skipped: {reason}"))
    }
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
    match skip_decision(live_required(), reason) {
        Ok(note) => eprintln!("{note}"),
        Err(message) => panic!("{message}"),
    }
}

// ------------------------------------------------------------ binary lookup

fn is_executable(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.is_file() && m.permissions().mode() & 0o111 != 0
    })
}

/// Look for `name` beside the running test binary.
///
/// Cargo writes binaries to `target/<profile>/`, and integration tests run
/// from `target/<profile>/deps/`. Those two directories are the only places a
/// binary of this workspace can legitimately be, so the search stops there.
/// It used to try a third level, `target/` itself, where Cargo never writes:
/// anything found there is stale or stray, and the harness would have run it.
fn sibling(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let here = exe.parent()?;
    let candidates: [Option<PathBuf>; 2] = [
        Some(here.join(name)),
        // Only step up out of `deps/`, never out of the profile directory.
        (here.file_name() == Some(OsStr::new("deps")))
            .then(|| here.parent().map(|p| p.join(name)))
            .flatten(),
    ];
    candidates.into_iter().flatten().find(|c| is_executable(c))
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
/// A stable short key for a path, so two worktrees never share a build
/// directory. FNV-1a, because a hash crate is not worth a dependency here.
fn path_key(p: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in p.as_os_str().as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn build_package(package: &str, name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let release = exe.components().any(|c| c.as_os_str() == "release");
    // Keyed on the manifest directory: a single shared target directory let
    // two worktrees hand each other's binary back, which is the stale
    // cross-tree artifact this project has already been bitten by.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let work = std::env::temp_dir().join(format!("ouro-fixture-harness-{}", path_key(&root)));
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

/// An override from the environment, accepted only when it is executable.
///
/// A pointer at something that is not there is a configuration error, not a
/// reason to fall back to whatever else the tree happens to contain.
fn override_from(value: Option<&OsStr>) -> Option<PathBuf> {
    let p = PathBuf::from(value?);
    is_executable(&p).then_some(p)
}

/// Turn an optional binary into a required one.
///
/// Separated from the lookup so the panic is proved by a plain unit test
/// rather than by the tree happening not to contain the binary. A missing
/// binary must fail loudly; the mutation that returns some other path instead
/// is caught here.
#[must_use]
pub fn require_binary(found: Option<PathBuf>, name: &str, env_var: &str) -> PathBuf {
    match found {
        Some(p) => p,
        None => panic!(
            "{name} not found: set {env_var} to an executable path, \
             or run `cargo build -p {name}`"
        ),
    }
}

/// The `ouro-fixture` binary, or `None` when this tree has not built one.
#[must_use]
pub fn try_fixture_path() -> Option<PathBuf> {
    if let Some(v) = std::env::var_os("OURO_FIXTURE_BIN") {
        return override_from(Some(v.as_os_str()));
    }
    sibling("ouro-fixture").or_else(|| build_package("ouro-fixture", "ouro-fixture"))
}

/// The `ouro-fixture` binary: `OURO_FIXTURE_BIN`, else a sibling of the test
/// binary, else built on demand under a lock.
#[must_use]
pub fn fixture_path() -> PathBuf {
    require_binary(try_fixture_path(), "ouro-fixture", "OURO_FIXTURE_BIN")
}

/// The `ouro-jail` binary, or `None` when this tree has not built one yet.
#[must_use]
pub fn try_jail_path() -> Option<PathBuf> {
    if let Some(v) = std::env::var_os("OURO_JAIL_BIN") {
        return override_from(Some(v.as_os_str()));
    }
    sibling("ouro-jail")
}

/// The `ouro-jail` binary. Panics with the remediation when it is absent: a
/// live test must fail loudly rather than quietly test nothing.
#[must_use]
pub fn jail_path() -> PathBuf {
    require_binary(try_jail_path(), "ouro-jail", "OURO_JAIL_BIN")
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
        // §6.2 requires the state root to be 0700 or stricter, and
        // `create_dir_all` applies the process umask, which on a host with
        // umask 002 leaves 0775. Setting the mode explicitly is what makes the
        // run reach preparation instead of refusing `unsafe_state_path`.
        for name in ["data", "config"] {
            let path = root.path().join(name);
            std::fs::create_dir_all(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
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

    /// Bound child execution and every channel drain by one deadline.
    pub fn timeout(mut self, timeout: Duration) -> Jail {
        self.timeout = timeout;
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
        let deadline = std::time::Instant::now() + timeout;

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
        let channel_targets: Vec<RawFd> = channels.iter().map(|c| c.target).collect();

        let mut cmd = Command::new(&program);
        cmd.process_group(0);
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

        // Written on a thread: past the pipe capacity (64 KiB on Linux) a
        // direct `write_all` blocks until the target reads, with no bound,
        // and X05 asks for large streams.
        let stdin_writer = match (stdin, child.stdin.take()) {
            (Some(bytes), Some(mut pipe)) => Some(std::thread::spawn(move || {
                use std::io::Write as _;
                let r = (|| {
                    nonblocking(pipe.as_raw_fd())?;
                    let mut left = bytes.as_slice();
                    while !left.is_empty() {
                        if std::time::Instant::now() >= deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "stdin exceeded harness deadline",
                            ));
                        }
                        match pipe.write(left) {
                            Ok(0) => {
                                return Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "stdin write stalled",
                                ));
                            }
                            Ok(n) => left = &left[n..],
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5))
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(e) => return Err(e),
                        }
                    }
                    Ok(())
                })();
                drop(pipe);
                r
            })),
            _ => None,
        };

        let mut control = None;
        let mut gate = None;
        let mut trace_reader = None;
        for (kind, fd) in kinds.iter().zip(ours) {
            match kind {
                Kind::Control => {
                    let mut r = LineReader::new(fd);
                    r.timeout = timeout;
                    r.set_deadline(deadline);
                    control = Some(r);
                }
                Kind::Gate => gate = Some(GateWriter::new(fd)),
                Kind::Trace => {
                    let mut r = LineReader::new(fd);
                    r.timeout = timeout;
                    r.set_deadline(deadline);
                    trace_reader = Some(r);
                }
            }
        }

        let stdout = child.stdout.take().map(|pipe| drain_thread(pipe, deadline));
        let stderr = child.stderr.take().map(|pipe| drain_thread(pipe, deadline));

        Ok(Spawned {
            deadline,
            child,
            control,
            gate,
            trace_reader,
            stdout,
            stderr,
            stdin_writer,
            channel_targets,
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

fn nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: reads/updates flags on an owned descriptor; no pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain_thread<R: std::io::Read + AsRawFd + Send + 'static>(
    mut r: R,
    deadline: std::time::Instant,
) -> std::thread::JoinHandle<io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        nonblocking(r.as_raw_fd())?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stdio exceeded harness deadline",
                ));
            }
            match r.read(&mut chunk) {
                Ok(0) => return Ok(buf),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    })
}

/// A running jail with its channels attached.
pub struct Spawned {
    deadline: std::time::Instant,
    child: Child,
    control: Option<LineReader>,
    gate: Option<GateWriter>,
    trace_reader: Option<LineReader>,
    stdout: Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
    stderr: Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
    stdin_writer: Option<std::thread::JoinHandle<io::Result<()>>>,
    channel_targets: Vec<RawFd>,
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

    /// The descriptor numbers the jail was told to use for its channels, so a
    /// test can assert that none of them reached the target.
    #[must_use]
    pub fn channel_targets(&self) -> &[RawFd] {
        &self.channel_targets
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

        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if std::time::Instant::now() >= self.deadline {
                // SAFETY: this is the process group created for our unreaped child.
                unsafe {
                    libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
                }
                let _ = self.child.kill();
                let reap = std::time::Instant::now() + Duration::from_secs(1);
                while matches!(self.child.try_wait(), Ok(None)) && std::time::Instant::now() < reap
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "jail exceeded harness deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        };

        let mut channels_timed_out: Vec<String> = Vec::new();

        let mut control_messages = std::mem::take(&mut self.control_seen);
        if let Some(mut reader) = self.control.take() {
            let drained = reader.drain();
            if let Some(e) = &drained.error {
                channels_timed_out.push(format!("control: {e}"));
            }
            for line in drained.lines {
                if line.is_empty() {
                    continue;
                }
                control_messages.push(serde_json::from_slice::<Value>(&line).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("malformed control message: {e}"),
                    )
                })?);
            }
        }

        let mut trace_events = Vec::new();
        if let Some(mut reader) = self.trace_reader.take() {
            let drained = reader.drain();
            if let Some(e) = &drained.error {
                channels_timed_out.push(format!("trace: {e}"));
            }
            for line in drained.lines {
                if line.is_empty() {
                    continue;
                }
                trace_events.push(serde_json::from_slice::<Value>(&line).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("malformed trace event: {e}"),
                    )
                })?);
            }
        }

        if !channels_timed_out.is_empty() {
            eprintln!(
                "ouro-fixture harness: channel never reached EOF ({}); \
                 the transcript below is partial",
                channels_timed_out.join(", ")
            );
        }

        if let Some(h) = self.stdin_writer.take()
            && let Ok(Err(e)) = h.join()
            && e.kind() != io::ErrorKind::BrokenPipe
        {
            // A target that never read its stdin gives BrokenPipe, which is
            // its business; anything else is the harness failing.
            return Err(e);
        }

        let stdout = self
            .stdout
            .take()
            .map(|h| {
                h.join()
                    .map_err(|_| io::Error::other("stdout reader panicked"))?
            })
            .transpose()?
            .unwrap_or_default();
        let stderr = self
            .stderr
            .take()
            .map(|h| {
                h.join()
                    .map_err(|_| io::Error::other("stderr reader panicked"))?
            })
            .transpose()?
            .unwrap_or_default();

        // Receipts are read once, now, so a read or parse error is a recorded
        // fact rather than a silently empty list that makes every negative
        // assertion pass.
        let data_dir = self.root.path().join("data");
        let mut receipts = Vec::new();
        let mut receipt_errors = Vec::new();
        collect_receipts(&data_dir, &mut receipts, &mut receipt_errors);
        if let Some(p) = &self.receipt {
            match std::fs::read_to_string(p) {
                Ok(text) => push_json(&text, p, &mut receipts, &mut receipt_errors),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => receipt_errors.push(format!("{}: {e}", p.display())),
            }
        }

        Ok(Run {
            status,
            stdout,
            stderr,
            control_messages,
            trace_events,
            data_dir,
            receipt_path: self.receipt.take(),
            gate_closed_by_harness,
            channels_timed_out,
            receipts,
            receipt_errors,
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
    /// Non-empty when a channel never reached EOF, so `control_messages` and
    /// `trace_events` are a partial transcript. Every helper that could turn
    /// that into a vacuous pass panics instead; see
    /// [`Run::assert_channels_complete`].
    pub channels_timed_out: Vec<String>,
    receipts: Vec<Value>,
    receipt_errors: Vec<String>,
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

    /// Panic when a channel did not reach EOF.
    ///
    /// An absent message only means something when the transcript is known to
    /// be complete. Every helper below that a test uses to assert an absence
    /// calls this first.
    pub fn assert_channels_complete(&self) {
        if let Err(message) = channel_guard(
            &self.channels_timed_out,
            self.control_messages.len(),
            self.trace_events.len(),
        ) {
            panic!("{message}");
        }
    }

    /// Every receipt read from the private data directory, once, at `wait`.
    ///
    /// `jail.json` is read as one JSON document when it parses that way and as
    /// NDJSON otherwise, because jail-v1 §7 fixes the file name but the J1
    /// core slice chooses between the two encodings. A file that exists and
    /// cannot be read or parsed panics: an unreadable receipt used to come
    /// back as an empty list, which made "the run produced no refused receipt"
    /// pass without reading anything.
    #[must_use]
    pub fn receipts(&self) -> Vec<Value> {
        assert!(
            self.receipt_errors.is_empty(),
            "receipts could not be read: {}",
            self.receipt_errors.join("; ")
        );
        self.receipts.clone()
    }

    /// The receipt read errors, without panicking. For a test about them.
    #[must_use]
    pub fn receipt_errors(&self) -> &[String] {
        &self.receipt_errors
    }

    /// The last receipt with this phase, when there is one.
    ///
    /// `jail.json` holds the latest receipt only (§7, atomically replaced), so
    /// after a completed run the earlier phases are not there; read them
    /// through `Spawned::receipt_value()` while the attempt is still gated, or
    /// from `control_messages`.
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

    /// Control messages of one kind, in order. Panics on a partial transcript.
    #[must_use]
    pub fn control_kind(&self, kind: &str) -> Vec<&Value> {
        self.assert_channels_complete();
        self.control_messages
            .iter()
            .filter(|m| m.get("kind").and_then(Value::as_str) == Some(kind))
            .collect()
    }

    /// The whole control transcript. Panics on a partial one.
    #[must_use]
    pub fn control_messages(&self) -> &[Value] {
        self.assert_channels_complete();
        &self.control_messages
    }

    /// The whole trace transcript. Panics on a partial one.
    #[must_use]
    pub fn trace_events(&self) -> &[Value] {
        self.assert_channels_complete();
        &self.trace_events
    }
}

/// Whether an absence in the transcript means anything.
///
/// `Err` is the message the caller must panic with: a channel that never
/// reached EOF leaves a partial transcript, and every "no such message"
/// assertion against it would pass without reading anything.
pub fn channel_guard(timed_out: &[String], controls: usize, traces: usize) -> Result<(), String> {
    if timed_out.is_empty() {
        return Ok(());
    }
    Err(format!(
        "a channel never reached EOF ({}), so the {controls} control message(s) and \
         {traces} trace event(s) collected are a partial transcript: an absence \
         proves nothing here. Inspect `channels_timed_out` and the partial \
         fields directly if that is what the test means to do.",
        timed_out.join(", ")
    ))
}

fn collect_receipts(dir: &Path, out: &mut Vec<Value>, errors: &mut Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        // An absent data directory is not an error: a refusal before state
        // creation leaves none. An unreadable one is.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return,
        Err(e) => {
            errors.push(format!("{}: {e}", dir.display()));
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_receipts(&path, out, errors);
        } else if path.file_name() == Some(OsStr::new("jail.json")) {
            match std::fs::read_to_string(&path) {
                Ok(text) => push_json(&text, &path, out, errors),
                Err(e) => errors.push(format!("{}: {e}", path.display())),
            }
        }
    }
}

/// One receipt file: a single JSON document, or NDJSON. A file that is
/// neither is an error, not an empty result.
fn push_json(text: &str, from: &Path, out: &mut Vec<Value>, errors: &mut Vec<String>) {
    match serde_json::from_str::<Value>(text) {
        Ok(v) => out.push(v),
        Err(whole) => {
            let mut lines = 0usize;
            let mut parsed = Vec::new();
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                lines += 1;
                match serde_json::from_str::<Value>(line) {
                    Ok(v) => parsed.push(v),
                    Err(e) => {
                        errors.push(format!(
                            "{}: neither one JSON document ({whole}) nor NDJSON ({e})",
                            from.display()
                        ));
                        return;
                    }
                }
            }
            if lines == 0 {
                errors.push(format!("{}: empty receipt file", from.display()));
                return;
            }
            out.extend(parsed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_mode_is_exactly_the_value_one() {
        // Proved without touching the environment, so a plain `cargo test`
        // catches a mutation that deletes the comparison.
        assert!(conformance_mode(Some("1")));
        assert!(!conformance_mode(Some("0")));
        assert!(!conformance_mode(Some("")));
        assert!(!conformance_mode(Some("true")));
        assert!(!conformance_mode(Some("1 ")));
        assert!(!conformance_mode(None));
    }

    #[test]
    fn live_required_reads_that_rule_from_the_environment() {
        let expected = conformance_mode(std::env::var(CONFORMANCE_VAR).ok().as_deref());
        assert_eq!(live_required(), expected);
    }

    #[test]
    fn a_skip_is_a_failure_in_conformance_mode_and_a_note_otherwise() {
        // Both branches, in plain mode: the rule is proved even when the
        // suite is not running under the variable.
        let failed = skip_decision(true, "bubblewrap is absent")
            .expect_err("conformance mode must refuse a skip");
        assert!(failed.contains("forbids skipping"), "{failed}");
        assert!(failed.contains("bubblewrap is absent"), "{failed}");

        let noted =
            skip_decision(false, "bubblewrap is absent").expect("plain mode records the skip");
        assert_eq!(noted, "skipped: bubblewrap is absent");

        // And the wrapper really panics on the Err branch.
        let r = std::panic::catch_unwind(|| match skip_decision(true, "x") {
            Ok(note) => eprintln!("{note}"),
            Err(m) => panic!("{m}"),
        });
        assert!(r.is_err());
    }

    #[test]
    fn a_required_binary_that_is_absent_panics_whatever_the_tree_contains() {
        // The guard used to be exercised only when `ouro-jail` happened to be
        // missing, so a fallback to some other path was invisible in a normal
        // build.
        let r = std::panic::catch_unwind(|| require_binary(None, "ouro-jail", "OURO_JAIL_BIN"));
        let message = *r
            .unwrap_err()
            .downcast::<String>()
            .expect("the panic carries its remediation");
        assert!(message.contains("ouro-jail not found"), "{message}");
        assert!(message.contains("OURO_JAIL_BIN"), "{message}");

        let found = PathBuf::from("/bin/sh");
        assert_eq!(
            require_binary(Some(found.clone()), "ouro-jail", "OURO_JAIL_BIN"),
            found
        );
    }

    #[test]
    fn an_override_must_point_at_something_executable() {
        assert_eq!(override_from(None), None);
        assert_eq!(
            override_from(Some(OsStr::new("/nonexistent/ouro-jail"))),
            None,
            "a pointer at nothing is a configuration error, not a fallback"
        );
        let dir = TempDir::new("ouro-override").unwrap();
        let plain = dir.path().join("not-executable");
        std::fs::write(&plain, b"#!/bin/sh\n").unwrap();
        assert_eq!(override_from(Some(plain.as_os_str())), None);
        assert_eq!(
            override_from(Some(OsStr::new("/bin/sh"))),
            Some(PathBuf::from("/bin/sh"))
        );
    }

    #[test]
    fn the_binary_search_never_leaves_the_profile_directory() {
        // `target/` itself is not a Cargo output location; a binary found
        // there is stale or stray and used to be run anyway.
        let exe = std::env::current_exe().unwrap();
        let here = exe.parent().unwrap();
        assert_eq!(
            here.file_name(),
            Some(OsStr::new("deps")),
            "this test assumes the usual integration-test layout"
        );
        let profile = here.parent().unwrap();
        let target_root = profile.parent().unwrap();

        let stray = target_root.join("ouro-stray-probe");
        std::fs::write(&stray, b"#!/bin/sh\nexit 9\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stray, std::fs::Permissions::from_mode(0o755)).unwrap();
        let found = sibling("ouro-stray-probe");
        std::fs::remove_file(&stray).unwrap();
        assert_eq!(found, None, "the search reached target/ itself");
    }

    #[test]
    fn a_partial_transcript_refuses_to_answer_questions_about_absence() {
        assert!(channel_guard(&[], 0, 0).is_ok());
        let message = channel_guard(&["control: timed out".to_string()], 2, 0)
            .expect_err("a timed-out channel must not look like silence");
        assert!(message.contains("partial transcript"), "{message}");
        assert!(message.contains("control: timed out"), "{message}");
        assert!(message.contains("2 control message(s)"), "{message}");
    }

    #[test]
    fn a_receipt_that_cannot_be_parsed_is_an_error_not_an_empty_list() {
        let dir = TempDir::new("ouro-receipt-errors").unwrap();
        let attempt = dir.path().join("attempts/att_1");
        std::fs::create_dir_all(&attempt).unwrap();
        std::fs::write(attempt.join("jail.json"), b"{ half written").unwrap();

        let mut out = Vec::new();
        let mut errors = Vec::new();
        collect_receipts(dir.path(), &mut out, &mut errors);
        assert!(out.is_empty());
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("jail.json"), "{errors:?}");

        // An empty file is an error too, not zero receipts.
        std::fs::write(attempt.join("jail.json"), b"").unwrap();
        let (mut out, mut errors) = (Vec::new(), Vec::new());
        collect_receipts(dir.path(), &mut out, &mut errors);
        assert_eq!(errors.len(), 1, "{errors:?}");

        // An absent data directory is not an error: a refusal before state
        // creation leaves none.
        let (mut out, mut errors) = (Vec::new(), Vec::new());
        collect_receipts(&dir.path().join("nothing-here"), &mut out, &mut errors);
        assert!(out.is_empty() && errors.is_empty());
    }

    #[test]
    fn two_worktrees_never_share_one_on_demand_build_directory() {
        let a = path_key(Path::new("/a/worktrees/one/crates/ouro-fixture"));
        let b = path_key(Path::new("/a/worktrees/two/crates/ouro-fixture"));
        assert_ne!(a, b);
        assert_eq!(a.len(), 16);
        assert_eq!(
            a,
            path_key(Path::new("/a/worktrees/one/crates/ouro-fixture"))
        );
    }

    #[test]
    fn the_fixture_binary_is_locatable_and_executable() {
        let p = fixture_path();
        assert!(is_executable(&p), "{} is not executable", p.display());
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
        let mut errors = Vec::new();
        collect_receipts(dir.path(), &mut out, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
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
