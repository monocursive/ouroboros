//! Owning a runtime as a child process: where its files live, what environment it gets,
//! how readiness is decided, and how it is asked to stop.
//!
//! ## The data directory is the rendezvous
//!
//! `Ouroboros.Gateway.Listener` binds an ephemeral port and publishes it to
//! `gateway.json` in `OUROBOROS_DATA_DIR`, 0600, with the OS pid alongside it. That file
//! is the whole discovery mechanism: this client never pre-chooses a port, so there is
//! no window in which two daemons race for a number one of them picked in advance. The
//! token is written next to it, because the published facts alone are not enough to
//! connect and a token on a command line is visible to every process on the host.
//!
//! A `--dev` daemon gets a *different* data directory. A development runtime and a real
//! one that shared `gateway.json` would each be discoverable as the other.
//!
//! ## What "stale" means, and what it does not
//!
//! `gateway.json` is removed on graceful termination and left behind by a kill, which is
//! why it carries a pid. A publication whose pid is dead is stale and is removed before
//! spawning. A publication whose pid is *alive* is never overwritten: a daemon this
//! client cannot talk to is a situation to report, not to resolve by starting a second
//! one in the same directory.
//!
//! ## The child is its own session
//!
//! Every spawn calls `setsid`, so a terminal signal reaches `ouro` alone. In the
//! supervised mode that is what lets ctrl-c run an ordered SIGTERM → grace → SIGKILL
//! instead of racing the shell; in `ouro daemon` it is what lets the runtime outlive the
//! client that started it.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rand::TryRngCore;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use zeroize::Zeroize;

use crate::transport::Secret;

#[cfg(feature = "embed")]
pub mod embed;

/// What the gateway publishes after it binds.
pub const PUBLICATION_FILE: &str = "gateway.json";

/// Where a spawner leaves the token it generated. The gateway is told the path through
/// `OUROBOROS_GATEWAY_TOKEN_FILE` and publishes neither the path nor the secret, so this
/// name is a convention between `ouro daemon` and `ouro attach`, not a protocol fact.
pub const TOKEN_FILE: &str = "gateway.token";

/// Where a detached daemon's output goes. A daemon that outlives its spawner cannot keep
/// writing into the spawner's pipes.
pub const DAEMON_LOG_FILE: &str = "daemon.log";

const READY_POLL: Duration = Duration::from_millis(150);

/// A cold `mix run` compiles the whole project first, which is minutes, not seconds.
pub const DEV_READY_DEADLINE: Duration = Duration::from_secs(300);

/// An extracted release starts a compiled system; anything past this is a failure that
/// has not printed itself yet.
pub const RELEASE_READY_DEADLINE: Duration = Duration::from_secs(60);

/// Where the client's files live. Both roots follow the XDG variables directly rather
/// than the platform conventions `dirs` would otherwise apply, because the daemon reads
/// `OUROBOROS_DATA_DIR` and the two halves have to agree on one path.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl Paths {
    pub fn discover(dev: bool) -> Result<Self> {
        let leaf = if dev { "ouroboros-dev" } else { "ouroboros" };

        Ok(Self {
            data_dir: xdg_root("XDG_DATA_HOME", ".local/share")?.join(leaf),
            cache_dir: xdg_root("XDG_CACHE_HOME", ".cache")?.join("ouroboros"),
        })
    }

    pub fn publication(&self) -> PathBuf {
        self.data_dir.join(PUBLICATION_FILE)
    }

    pub fn token_file(&self) -> PathBuf {
        self.data_dir.join(TOKEN_FILE)
    }

    pub fn daemon_log(&self) -> PathBuf {
        self.data_dir.join(DAEMON_LOG_FILE)
    }

    pub fn releases(&self) -> PathBuf {
        self.cache_dir.join("releases")
    }
}

fn xdg_root(variable: &str, fallback: &str) -> Result<PathBuf> {
    if let Some(value) = std::env::var_os(variable) {
        let path = PathBuf::from(value);

        if path.is_absolute() {
            return Ok(path);
        }
    }

    let home = dirs::home_dir().ok_or_else(|| {
        anyhow!(
            "neither {variable} nor a home directory is set, so there is \
             nowhere to keep this runtime's files"
        )
    })?;

    Ok(home.join(fallback))
}

/// `gateway.json`, decoded tolerantly: a newer gateway may publish more.
#[derive(Debug, Clone, Deserialize)]
pub struct Publication {
    pub port: u16,
    #[serde(default)]
    pub protocol: u32,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub pid: i32,
    #[serde(default)]
    pub scope: String,
}

/// Reads the publication, or `None` when the gateway has not written one.
pub fn read_publication(data_dir: &Path) -> Result<Option<Publication>> {
    let path = data_dir.join(PUBLICATION_FILE);

    let contents = match fs::read(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context(format!("reading {}", path.display())),
    };

    serde_json::from_slice(&contents)
        .map(Some)
        .with_context(|| format!("{} is not a gateway publication", path.display()))
}

/// Refuses a publication this user does not own. `ouro stop` signals the pid this file
/// names, and a file somebody else can write is a file that can name somebody else's pid.
pub fn read_owned_publication(data_dir: &Path) -> Result<Option<Publication>> {
    let path = data_dir.join(PUBLICATION_FILE);

    match fs::metadata(&path) {
        Ok(metadata) => {
            // SAFETY: geteuid cannot fail and touches no memory.
            let us = unsafe { libc::geteuid() };

            if metadata.uid() != us {
                bail!(
                    "{} belongs to uid {}, not to uid {us}; this client will not act on a \
                     daemon it does not own",
                    path.display(),
                    metadata.uid()
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context(format!("reading {}", path.display())),
    }

    read_publication(data_dir)
}

pub fn remove_publication(data_dir: &Path) -> Result<()> {
    match fs::remove_file(data_dir.join(PUBLICATION_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Whether a pid names a live process this user can see.
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }

    // SAFETY: signal 0 performs the existence and permission check and delivers nothing.
    let outcome = unsafe { libc::kill(pid, 0) };

    outcome == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Sends one signal, naming the pid on failure.
pub fn send_signal(pid: i32, signal: i32) -> Result<()> {
    // SAFETY: kill/2 with a pid this client obtained from its own child or from a
    // publication file it verified it owns.
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();

    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }

    Err(anyhow!("cannot signal pid {pid}: {error}"))
}

/// Writes a fresh token and returns it. 32 bytes of OS randomness rendered as hex, which
/// is 64 bytes on the wire — comfortably past the gateway's 32-byte floor.
pub fn write_token(path: &Path) -> Result<Secret> {
    let mut bytes = [0u8; 32];

    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| anyhow!("cannot read OS randomness for a gateway token: {error}"))?;

    let mut token = String::with_capacity(64);

    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(token, "{byte:02x}");
    }

    bytes.zeroize();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // create+truncate rather than create_new: a spawn that follows a crashed daemon
    // rewrites the token, and the mode is set on the open so the secret is never briefly
    // readable by anyone else.
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;

    let outcome = io::Write::write_all(&mut file, token.as_bytes())
        .and_then(|()| io::Write::flush(&mut file))
        .and_then(|()| {
            fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        });

    if let Err(error) = outcome {
        token.zeroize();
        return Err(anyhow::Error::from(error).context(format!("writing {}", path.display())));
    }

    let secret = Secret::new(token.clone());
    token.zeroize();

    Ok(secret)
}

/// Reads a token file, trimming the trailing newline a human's editor adds. The gateway
/// trims the same way.
pub fn read_token(path: &Path) -> Result<Secret> {
    let mut contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let secret = Secret::new(contents.trim().to_string());
    contents.zeroize();

    if secret.expose().is_empty() {
        bail!(
            "{} is empty; the gateway refuses a blank token",
            path.display()
        );
    }

    Ok(secret)
}

/// The environment a spawned runtime is given, as overrides onto the caller's own.
///
/// Cluster variables pass through untouched: a host that already carries
/// `OUROBOROS_CLUSTER_STRATEGY` or `OUROBOROS_NODE` is a host whose operator decided how
/// this node joins a cluster, and `OUROBOROS_DIST=none` would contradict that decision —
/// `rel/env.sh.eex` refuses the combination outright. Nothing else about an existing
/// server workflow changes, because nothing else is set.
pub fn spawn_env(
    caller: &[(String, String)],
    data_dir: &Path,
    token_file: &Path,
) -> Vec<(String, String)> {
    let clustered = ["OUROBOROS_CLUSTER_STRATEGY", "OUROBOROS_NODE"]
        .iter()
        .any(|name| {
            caller
                .iter()
                .any(|(key, value)| key == name && !value.trim().is_empty())
        });

    let mut env = vec![
        ("OUROBOROS_GATEWAY".to_string(), "1".to_string()),
        ("OUROBOROS_GATEWAY_SCOPE".to_string(), "operate".to_string()),
        (
            "OUROBOROS_GATEWAY_ALLOW_SHUTDOWN".to_string(),
            "1".to_string(),
        ),
        ("OUROBOROS_GATEWAY_PORT".to_string(), "0".to_string()),
        (
            "OUROBOROS_GATEWAY_TOKEN_FILE".to_string(),
            token_file.display().to_string(),
        ),
        (
            "OUROBOROS_DATA_DIR".to_string(),
            data_dir.display().to_string(),
        ),
    ];

    if !clustered {
        env.push(("OUROBOROS_DIST".to_string(), "none".to_string()));
    }

    env
}

/// The current environment as pairs, for [`spawn_env`].
pub fn caller_env() -> Vec<(String, String)> {
    std::env::vars().collect()
}

/// What to start.
#[derive(Debug, Clone)]
pub enum Launcher {
    /// `mix run --no-halt` in a checkout. No release, no embed, and the compile is the
    /// caller's to wait for.
    Dev { repo_root: PathBuf },
    /// `bin/ouroboros start` from an extracted release. `start` runs in the foreground,
    /// which is what makes it supervisable; `daemon` would hand the process to `run_erl`
    /// and leave this client watching a pid that exits immediately.
    Release { root: PathBuf },
}

impl Launcher {
    fn program(&self) -> OsString {
        match self {
            Self::Dev { .. } => OsString::from("mix"),
            Self::Release { root } => root.join("bin").join("ouroboros").into_os_string(),
        }
    }

    fn args(&self) -> Vec<&'static str> {
        match self {
            Self::Dev { .. } => vec!["run", "--no-halt"],
            Self::Release { .. } => vec!["start"],
        }
    }

    fn working_dir(&self) -> &Path {
        match self {
            Self::Dev { repo_root } => repo_root,
            Self::Release { root } => root,
        }
    }

    pub fn ready_deadline(&self) -> Duration {
        match self {
            Self::Dev { .. } => DEV_READY_DEADLINE,
            Self::Release { .. } => RELEASE_READY_DEADLINE,
        }
    }
}

/// Walks up from `start` looking for this project's checkout.
pub fn find_repo_root(start: &Path) -> Result<PathBuf> {
    let start = start
        .canonicalize()
        .with_context(|| format!("resolving {}", start.display()))?;

    for candidate in start.ancestors() {
        if candidate.join("mix.exs").is_file()
            && candidate.join("lib").join("ouroboros.ex").is_file()
        {
            return Ok(candidate.to_path_buf());
        }
    }

    bail!(
        "--dev runs `mix run --no-halt` in an ouroboros checkout, and none contains {}",
        start.display()
    )
}

/// Where a spawned child's output goes.
#[derive(Debug, Clone)]
pub enum Output {
    /// Piped into this process and accumulated in a bounded ring.
    Ring,
    /// Appended to a file, for a daemon that outlives this process.
    File(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug)]
pub struct LogLine {
    pub stream: Stream,
    pub text: String,
}

/// A bounded window of child output. Slice 3b's Logs tab reads it; Slice 3a prints the
/// tail when a child exits or fails to become ready.
#[derive(Clone)]
pub struct LogRing {
    inner: Arc<Mutex<Ring>>,
}

struct Ring {
    lines: VecDeque<LogLine>,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
    dropped: u64,
}

impl Default for LogRing {
    fn default() -> Self {
        Self::new(2_000, 512 * 1024)
    }
}

impl LogRing {
    pub fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Ring {
                lines: VecDeque::new(),
                bytes: 0,
                max_lines,
                max_bytes,
                dropped: 0,
            })),
        }
    }

    pub fn push(&self, stream: Stream, text: String) {
        let Ok(mut ring) = self.inner.lock() else {
            return;
        };

        ring.bytes += text.len();
        ring.lines.push_back(LogLine { stream, text });

        while ring.lines.len() > ring.max_lines || ring.bytes > ring.max_bytes {
            match ring.lines.pop_front() {
                Some(line) => {
                    ring.bytes -= line.text.len();
                    ring.dropped += 1;
                }
                None => break,
            }
        }
    }

    /// The last `count` lines, oldest first.
    pub fn tail(&self, count: usize) -> Vec<LogLine> {
        let Ok(ring) = self.inner.lock() else {
            return Vec::new();
        };

        let skip = ring.lines.len().saturating_sub(count);
        ring.lines.iter().skip(skip).cloned().collect()
    }

    pub fn dropped(&self) -> u64 {
        self.inner.lock().map(|ring| ring.dropped).unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|ring| ring.lines.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A single log line is bounded too: one runaway `inspect` should cost a truncation,
/// not the ring.
const MAX_LOG_LINE: usize = 8 * 1024;

async fn pump<R: AsyncRead + Unpin>(mut source: R, stream: Stream, ring: LogRing) {
    let mut chunk = vec![0u8; 8 * 1024];
    let mut line: Vec<u8> = Vec::new();

    loop {
        let read = match source.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };

        for byte in &chunk[..read] {
            if *byte == b'\n' {
                ring.push(stream, String::from_utf8_lossy(&line).into_owned());
                line.clear();
            } else {
                line.push(*byte);

                if line.len() >= MAX_LOG_LINE {
                    ring.push(stream, String::from_utf8_lossy(&line).into_owned());
                    line.clear();
                }
            }
        }
    }

    if !line.is_empty() {
        ring.push(stream, String::from_utf8_lossy(&line).into_owned());
    }
}

/// A runtime this client started.
pub struct Daemon {
    child: Option<Child>,
    pid: i32,
    logs: LogRing,
}

impl Daemon {
    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn logs(&self) -> LogRing {
        self.logs.clone()
    }

    /// Whether the child has already exited, without waiting for it.
    pub fn exited(&mut self) -> Option<ExitStatus> {
        self.child.as_mut()?.try_wait().ok().flatten()
    }

    /// Waits for the gateway to publish a port it can be reached on.
    ///
    /// Any stale publication was removed before the spawn, so existence plus a live pid
    /// is the whole readiness test — no mtime comparison that a coarse filesystem clock
    /// could get wrong.
    pub async fn wait_ready(&mut self, data_dir: &Path, deadline: Duration) -> Result<Publication> {
        let started = Instant::now();

        loop {
            if let Some(status) = self.exited() {
                bail!(
                    "the runtime exited before it published a gateway ({status}){}",
                    self.log_tail(40)
                );
            }

            if let Ok(Some(publication)) = read_publication(data_dir) {
                if pid_alive(publication.pid) {
                    return Ok(publication);
                }
            }

            if started.elapsed() >= deadline {
                // A publication that exists but did not decode is the more useful error,
                // so it is re-read strictly once the deadline has passed.
                read_publication(data_dir)?;

                bail!(
                    "the runtime did not publish {} in {}s{}",
                    data_dir.join(PUBLICATION_FILE).display(),
                    deadline.as_secs(),
                    self.log_tail(40)
                );
            }

            tokio::time::sleep(READY_POLL).await;
        }
    }

    /// SIGTERM, a bounded grace, then SIGKILL. OTP's signal server turns SIGTERM into an
    /// orderly `init:stop`, so the grace is the runtime's shutdown, not a courtesy.
    pub async fn terminate(&mut self, grace: Duration) -> Result<Option<ExitStatus>> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };

        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }

        send_signal(self.pid, libc::SIGTERM)?;

        match tokio::time::timeout(grace, child.wait()).await {
            Ok(status) => Ok(Some(status?)),
            Err(_elapsed) => {
                child.kill().await?;
                Ok(Some(child.wait().await?))
            }
        }
    }

    /// Gives up the child without stopping it. `ouro daemon` exits this way.
    pub fn detach(&mut self) {
        self.child = None;
    }

    pub fn log_tail(&self, count: usize) -> String {
        let lines = self.logs.tail(count);

        if lines.is_empty() {
            return String::new();
        }

        let mut rendered = String::from("\n--- last output from the runtime ---");

        for line in lines {
            rendered.push('\n');
            rendered.push_str(&line.text);
        }

        rendered
    }
}

/// Starts a runtime as a child process in its own session.
pub fn spawn(
    launcher: &Launcher,
    data_dir: &Path,
    token_file: &Path,
    output: Output,
) -> Result<Daemon> {
    fs::create_dir_all(data_dir).with_context(|| format!("creating {}", data_dir.display()))?;

    let mut command = Command::new(launcher.program());
    command.args(launcher.args());
    command.current_dir(launcher.working_dir());
    command.stdin(Stdio::null());

    for (key, value) in spawn_env(&caller_env(), data_dir, token_file) {
        command.env(key, value);
    }

    let logs = LogRing::default();

    match &output {
        Output::Ring => {
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
        }
        Output::File(path) => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("opening {}", path.display()))?;

            let errors = file.try_clone()?;
            command.stdout(Stdio::from(file));
            command.stderr(Stdio::from(errors));
        }
    }

    // SAFETY: setsid is async-signal-safe and is the only call made between fork and
    // exec. A child in its own session does not receive the terminal's signals, which is
    // what makes both the supervised shutdown sequence and the detached daemon possible.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        });
    }

    let mut child = command.spawn().with_context(|| {
        format!(
            "starting {} in {}",
            launcher.program().to_string_lossy(),
            launcher.working_dir().display()
        )
    })?;

    let pid = child
        .id()
        .ok_or_else(|| anyhow!("the runtime exited before it could be identified"))?
        as i32;

    if matches!(output, Output::Ring) {
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(pump(stdout, Stream::Stdout, logs.clone()));
        }

        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(pump(stderr, Stream::Stderr, logs.clone()));
        }
    }

    Ok(Daemon {
        child: Some(child),
        pid,
        logs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SCRATCH: AtomicU32 = AtomicU32::new(0);

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ouro-test-{name}-{}-{}",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));

        fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    #[test]
    fn spawn_env_sets_the_gateway_posture_and_turns_distribution_off() {
        let env = spawn_env(&[], Path::new("/data"), Path::new("/data/gateway.token"));
        let lookup = |name: &str| {
            env.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };

        assert_eq!(lookup("OUROBOROS_GATEWAY"), Some("1".into()));
        assert_eq!(lookup("OUROBOROS_GATEWAY_SCOPE"), Some("operate".into()));
        assert_eq!(lookup("OUROBOROS_GATEWAY_ALLOW_SHUTDOWN"), Some("1".into()));
        assert_eq!(lookup("OUROBOROS_GATEWAY_PORT"), Some("0".into()));
        assert_eq!(lookup("OUROBOROS_DATA_DIR"), Some("/data".into()));
        assert_eq!(
            lookup("OUROBOROS_GATEWAY_TOKEN_FILE"),
            Some("/data/gateway.token".into())
        );
        assert_eq!(lookup("OUROBOROS_DIST"), Some("none".into()));
    }

    #[test]
    fn a_clustered_caller_keeps_distribution() {
        for name in ["OUROBOROS_CLUSTER_STRATEGY", "OUROBOROS_NODE"] {
            let caller = vec![(name.to_string(), "epmd".to_string())];
            let env = spawn_env(&caller, Path::new("/data"), Path::new("/data/t"));

            assert!(
                !env.iter().any(|(key, _)| key == "OUROBOROS_DIST"),
                "{name} must not be contradicted by OUROBOROS_DIST=none"
            );
        }
    }

    #[test]
    fn a_blank_cluster_variable_is_not_a_cluster() {
        let caller = vec![("OUROBOROS_NODE".to_string(), "  ".to_string())];
        let env = spawn_env(&caller, Path::new("/data"), Path::new("/data/t"));

        assert!(env.iter().any(|(key, _)| key == "OUROBOROS_DIST"));
    }

    #[test]
    fn a_written_token_is_private_and_long_enough() {
        let dir = scratch("token");
        let path = dir.join("gateway.token");

        let secret = write_token(&path).expect("a token");

        assert_eq!(secret.expose().len(), 64);
        assert!(secret.expose().chars().all(|c| c.is_ascii_hexdigit()));

        let mode = fs::metadata(&path).expect("the token file").mode() & 0o777;
        assert_eq!(mode, 0o600, "the token must not be readable by anyone else");

        let read_back = read_token(&path).expect("a readable token");
        assert_eq!(read_back.expose(), secret.expose());

        let second = write_token(&path).expect("a second token");
        assert_ne!(second.expose(), secret.expose());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_publication_decodes_and_tolerates_new_fields() {
        let dir = scratch("publication");

        fs::write(
            dir.join(PUBLICATION_FILE),
            br#"{"port":54321,"protocol":1,"node":"nonode@nohost","pid":42,"scope":"operate","future":true}"#,
        )
        .expect("a publication");

        let publication = read_publication(&dir).expect("readable").expect("present");

        assert_eq!(publication.port, 54321);
        assert_eq!(publication.protocol, 1);
        assert_eq!(publication.pid, 42);
        assert_eq!(publication.scope, "operate");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_publication_is_not_an_error() {
        let dir = scratch("absent");

        assert!(read_publication(&dir).expect("readable").is_none());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn our_own_pid_is_alive_and_pid_zero_is_not() {
        assert!(pid_alive(std::process::id() as i32));
        assert!(!pid_alive(0));
        assert!(!pid_alive(-1));
    }

    #[test]
    fn the_ring_drops_the_oldest_lines_and_counts_them() {
        let ring = LogRing::new(3, 1024);

        for index in 0..5 {
            ring.push(Stream::Stderr, format!("line {index}"));
        }

        let tail: Vec<String> = ring.tail(10).into_iter().map(|line| line.text).collect();

        assert_eq!(tail, vec!["line 2", "line 3", "line 4"]);
        assert_eq!(ring.dropped(), 2);
    }

    #[test]
    fn the_ring_is_bounded_by_bytes_as_well_as_lines() {
        let ring = LogRing::new(1_000, 16);

        ring.push(Stream::Stdout, "0123456789".into());
        ring.push(Stream::Stdout, "abcdefghij".into());

        assert_eq!(ring.len(), 1);
        assert_eq!(ring.tail(10)[0].text, "abcdefghij");
    }
}
