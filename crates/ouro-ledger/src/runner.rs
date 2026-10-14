//! The launch owner: durably admit before opening the jail's existing gate.
use crate::protocol::RunState;

mod argv_capture;
#[cfg(target_os = "linux")]
mod evidence;
#[cfg(target_os = "linux")]
mod owned;
use std::ffi::OsString;
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt, net::UnixStream};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Child;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use ouro_records::canonical;
use ouro_records::records;
use records::{ControlKind, ControlMessage, Phase, Receipt};
use serde_json::Value;
#[cfg(target_os = "linux")]
use serde_json::json;

use crate::daemon::Client;
#[cfg(target_os = "linux")]
use crate::protocol::ClaimedOwner;
#[cfg(target_os = "linux")]
use crate::protocol::{CAPTURE_STREAMS, MAX_CAPTURE_BYTES, MAX_FRAME_BYTES};
use crate::protocol::{LedgerError, Result, RunRecord};

/// The operator's literal execution request. Raw argv is persisted only with
/// explicit capture; detached submission uses a private socket either way.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunOptions {
    pub data: PathBuf,
    pub jail: PathBuf,
    pub request_id: String,
    pub prepared: Option<String>,
    pub policy_args: Vec<OsString>,
    pub argv: Vec<OsString>,
    pub batch: bool,
    /// Descriptor role only; never serialize a process-local fd number.
    #[serde(default)]
    pub separate_control: bool,
    pub detached: bool,
    pub captures: Vec<String>,
    #[serde(default)]
    pub redact: Vec<String>,
    pub capture_limit: u64,
    pub best_effort: bool,
    pub launch: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

pub struct RunResult {
    pub record: RunRecord,
    pub exit_code: i32,
}

/// Resolve the same immutable metadata the owner checks at admission, without
/// preparing or executing a child. Fleet can bind it before dispatch.
pub fn resolve_request(options: &RunOptions) -> Result<Value> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(error("launch planning requires Linux"))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(resolve(options)?.payload)
    }
}

/// A launch request resolved against one pinned jail image.
#[cfg(target_os = "linux")]
struct Resolved {
    image: File,
    image_digest: String,
    payload: Value,
}

/// Every check a launch request gets, shared by planning, preparation and
/// launch so that none of them can accept what another refuses.
#[cfg(target_os = "linux")]
fn resolve(options: &RunOptions) -> Result<Resolved> {
    if options.detached && options.separate_control {
        return Err(error(
            "detached owners cannot depend on a client control descriptor",
        ));
    }
    if options.argv.is_empty() {
        return Err(error("run needs a program after --"));
    }
    if options.capture_limit > MAX_CAPTURE_BYTES {
        return Err(error("capture limit exceeds 16 MiB per stream"));
    }
    if options
        .captures
        .iter()
        .any(|s| !CAPTURE_STREAMS.contains(&s.as_str()))
    {
        return Err(error("capture accepts stdout, stderr and argv only"));
    }
    let image = pinned_image(&options.jail)?;
    let digest = image_digest(&image)?;
    let plan = plan(options, &image)?;
    if image_digest(&image)? != digest {
        return Err(error("jail image changed during policy resolution"));
    }
    let payload = payload(options, &plan, &digest)?;
    crate::store::validate_payload(&payload)?;
    Ok(Resolved {
        image,
        image_digest: digest,
        payload,
    })
}

fn error(message: impl Into<String>) -> LedgerError {
    LedgerError::refused(message)
}

/// Start a writer on demand. The writer has no terminal or child-stream fds.
pub fn connect_or_start(data: &Path) -> Result<Client> {
    if let Some(client) = Client::reachable(data)? {
        return Ok(client);
    }
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--data-dir",
            data.to_str()
                .ok_or_else(|| error("data path must be UTF-8"))?,
            "serve",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe and this closure only uses libc.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(client) = Client::connect(data) {
            // Reap the on-demand daemon when it eventually exits; it outlives this owner.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(client);
        }
        if child.try_wait()?.is_some() {
            return Err(error(
                "ledger writer refused to start; inspect the private data directory",
            ));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error(
                "ledger writer did not become ready within five seconds",
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "linux")]
fn plan(options: &RunOptions, image: &File) -> Result<Value> {
    let mut command = image_command(image);
    command
        .arg("explain")
        .args(&options.policy_args)
        .arg("--json")
        .env("OURO_DATA_DIR", &options.data)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit());
    // Capture is bounded even if an operator-selected executable is defective.
    command.stdout(Stdio::piped());
    let mut child = OwnedChild(
        command
            .spawn()
            .map_err(|e| error(format!("starting pinned jail policy resolution: {e}")))?,
    );
    let mut pipe = child
        .0
        .stdout
        .take()
        .ok_or_else(|| error("missing explain pipe"))?;
    // SAFETY: this changes only the owned read end of the planning pipe.
    unsafe {
        if libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; PIPE_READ_BYTES];
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(error("jail explain exceeded frame bound"));
        }
        if Instant::now() >= deadline {
            return Err(error("jail policy resolution exceeded thirty seconds"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(error("jail policy resolution exceeded thirty seconds"));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if !status.success() {
        return Err(error("jail policy resolution refused"));
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    if value["component"] != "ouro-jail" || !value["policy"]["digest"].is_string() {
        return Err(error("unrecognized jail policy response"));
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn image_digest(image: &File) -> Result<String> {
    let mut file = image.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let bytes = crate::protocol::read_bounded(
        file,
        MAX_IMAGE_BYTES,
        "jail executable exceeds image bound",
    )?;
    Ok(canonical::sha256_prefixed(&bytes))
}

#[cfg(target_os = "linux")]
fn payload(options: &RunOptions, plan: &Value, image_digest: &str) -> Result<Value> {
    let argv: Vec<Vec<u8>> = options.argv.iter().map(|s| s.as_bytes().to_vec()).collect();
    let requirements: Vec<Value> = plan["requirements"]
        .as_array()
        .ok_or_else(|| error("missing policy requirements"))?
        .iter()
        .map(|r| r["name"].clone())
        .collect();
    let mut request = json!({"schema":crate::schemas::REQUEST, "argv_digest":canonical::argv_digest(&argv),
        "policy_digest":plan["policy"]["digest"], "requirements":requirements,
        "profile":plan["policy"]["name"], "jail_image_digest":image_digest,
        "io":{"mode":if options.batch {"batch"} else {"foreground"},"pty":false},
        "capture":{"streams":options.captures,"limit_bytes":options.capture_limit},
        "evidence":if options.best_effort {"best-effort"} else {"strict"}});
    if !options.redact.is_empty() {
        let mut selectors = options.redact.clone();
        selectors.sort();
        request["redact"] = json!(selectors);
        crate::redaction::validate_policy(&request)?;
    }
    if options.separate_control {
        request["io"]["control"] = "separate_fd".into();
    }
    if options.detached {
        request["owner_lifetime"] = "systemd_user_service".into();
    }
    if let Some(launch) = &options.launch {
        request["launch"] = json!(launch);
    }
    if !options.tags.is_empty() {
        crate::discovery::validate_tags(&options.tags)?;
        let mut tags = options.tags.clone();
        tags.sort();
        request["tags"] = json!(tags);
    }
    Ok(request)
}

#[cfg(target_os = "linux")]
fn pinned_image(path: &Path) -> Result<File> {
    use std::os::unix::fs::MetadataExt as _;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| error(format!("opening pinned jail image {}: {e}", path.display())))?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.mode() & 0o111 == 0 || meta.mode() & 0o022 != 0 {
        return Err(error(
            "jail executable must be a regular executable file without group/world write permission",
        ));
    }
    let mut header = [0; 4];
    file.read_exact(&mut header)?;
    if header != *b"\x7fELF" {
        return Err(error("jail executable must be a native ELF image"));
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn image_command(image: &File) -> Command {
    let fd = image.as_raw_fd();
    let mut command = Command::new(format!("/proc/self/fd/{fd}"));
    // SAFETY: the owned pinned executable descriptor remains open through spawn.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

/// Compare all prepared identity bindings before any durable admission.
pub fn check_prepared(
    receipt: &Value,
    control: &ControlMessage,
    run: &RunRecord,
) -> Result<Receipt> {
    let typed: Receipt = serde_json::from_value(receipt.clone())?;
    let violations = records::semantic::receipt(receipt);
    if !violations.is_empty() {
        return Err(error(format!("invalid prepared receipt: {violations:?}")));
    }
    let digest = records::semantic::receipt_digest(receipt).map_err(|e| error(e.to_string()))?;
    if control.kind != ControlKind::Prepared
        || control.schema != records::SCHEMA_CONTROL
        || control.receipt_phase != Phase::Prepared
        || typed.phase != Phase::Prepared
        || typed.attempt_id != run.attempt_id
        || control.attempt_id != run.attempt_id
        || digest != control.receipt_digest
        || typed.policy.digest != run.payload["policy_digest"]
        || typed.argv_digest.as_deref() != run.payload["argv_digest"].as_str()
        || serde_json::to_value(&typed.policy.requirements)? != run.payload["requirements"]
    {
        return Err(error(
            "prepared jail receipt does not match the reserved policy, argv, requirements and attempt",
        ));
    }
    Ok(typed)
}

#[cfg(target_os = "linux")]
struct Frames {
    stream: UnixStream,
    pending: Vec<u8>,
    eof: bool,
}
#[cfg(target_os = "linux")]
impl Frames {
    fn new(stream: UnixStream) -> Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            pending: Vec::new(),
            eof: false,
        })
    }
    fn drain(&mut self) -> Result<Vec<Value>> {
        let mut result = Vec::new();
        let mut bytes = [0_u8; PIPE_READ_BYTES];
        // Bound work per loop as well as pending memory.
        for _ in 0..32 {
            match self.stream.read(&mut bytes) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => self.pending.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
            while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
                if end + 1 > MAX_FRAME_BYTES {
                    return Err(error("oversized jail event/control frame"));
                }
                result.push(serde_json::from_slice(&self.pending[..end])?);
                self.pending.drain(..=end);
            }
            if self.pending.len() > MAX_FRAME_BYTES {
                return Err(error("unterminated oversized jail frame"));
            }
        }
        if self.eof && !self.pending.is_empty() {
            return Err(error("truncated jail event/control frame"));
        }
        Ok(result)
    }
}

#[cfg(target_os = "linux")]
fn read_receipt(path: &Path, phase: &str) -> Result<Value> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            error(format!(
                "opening {phase} canonical jail receipt {}: {e}",
                path.display()
            ))
        })?;
    if !file.metadata()?.is_file() {
        return Err(error("receipt is not a regular file"));
    }
    let bytes = crate::protocol::read_bounded(
        file,
        MAX_FRAME_BYTES as u64,
        "receipt exceeded frame bound",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Foreground forwarding is display, not evidence. A terminal slower than the
/// child or a lost terminal stops it; the owner keeps draining and capturing,
/// and the capture records what was not delivered instead of failing the run.
#[cfg(target_os = "linux")]
struct Tee {
    sender: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    finished: std::sync::mpsc::Receiver<std::io::Result<()>>,
    result: Option<std::io::Result<()>>,
    delivered: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stopped: Option<&'static str>,
}

/// After the child's streams end, queued output gets this long to reach the
/// terminal before the run is recorded; the rest is reported undelivered.
#[cfg(target_os = "linux")]
const FORWARDING_GRACE: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const HEARTBEAT: Duration = Duration::from_millis(250);
/// The longest the owner loop sleeps when it cannot be woken by the jail's
/// exit (no pidfd).
#[cfg(target_os = "linux")]
const EXIT_POLL: Duration = Duration::from_millis(5);
/// One read from a jail pipe or socket.
#[cfg(target_os = "linux")]
const PIPE_READ_BYTES: usize = 8192;
/// Reads a forwarded stream may queue for the terminal: at most 1 MiB, so
/// the owner never waits on a client write.
#[cfg(target_os = "linux")]
const TEE_QUEUE_READS: usize = 128;
/// The largest jail executable the owner hashes.
#[cfg(target_os = "linux")]
const MAX_IMAGE_BYTES: u64 = 256 * 1_048_576;

/// A descriptor that becomes readable when `pid` exits. The caller holds the
/// unreaped child, so the pid cannot name another process.
#[cfg(target_os = "linux")]
fn exit_descriptor(pid: u32) -> Option<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags by value and reads no memory.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    // SAFETY: a successful pidfd_open returned a new descriptor owned only here.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Sleep until one of `fds` is readable or `timeout` passes. Readiness is
/// only a wake-up: the caller re-checks every stream, deadline and the child.
#[cfg(target_os = "linux")]
fn wait_readable(fds: &[RawFd], timeout: Duration) {
    let mut polls: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    // Round up so a wait never ends just short of the deadline it aims at.
    let millis = timeout.as_micros().div_ceil(1000).min(i32::MAX as u128) as i32;
    // SAFETY: `polls` is an initialized array of descriptors that stay open
    // for the call; poll writes only their revents.
    let ready = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, millis) };
    if ready < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
        // Never spin on a failing poll; a signal (cancellation) ends it early.
        std::thread::sleep(timeout.min(EXIT_POLL));
    }
}

#[cfg(target_os = "linux")]
impl Tee {
    fn stdio(name: &str) -> Result<Self> {
        use std::os::fd::FromRawFd as _;
        let source = if name == "stdout" {
            libc::STDOUT_FILENO
        } else {
            libc::STDERR_FILENO
        };
        // SAFETY: duplicate the caller's descriptor into an independently owned CLOEXEC fd.
        let fd = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fcntl returned a new descriptor exclusively owned here.
        Ok(Self::new(unsafe { File::from_raw_fd(fd) }))
    }
    fn new(mut sink: File) -> Self {
        use std::sync::atomic::Ordering;
        let delivered = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let written = delivered.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(TEE_QUEUE_READS);
        let (done, finished) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = (|| {
                for bytes in receiver {
                    sink.write_all(&bytes)?;
                    written.fetch_add(bytes.len() as u64, Ordering::Release);
                }
                Ok(())
            })();
            let _ = done.send(result);
        });
        Self {
            sender: Some(sender),
            finished,
            result: None,
            delivered,
            stopped: None,
        }
    }
    fn forward(&mut self, bytes: &[u8]) {
        use std::sync::mpsc::TrySendError;
        let Some(sender) = &self.sender else {
            return;
        };
        let reason = match sender.try_send(bytes.to_vec()) {
            Ok(()) => return,
            Err(TrySendError::Full(_)) => "queue_full",
            Err(TrySendError::Disconnected(_)) => "sink_failed",
        };
        self.sender = None;
        self.stopped = Some(reason);
    }
    /// No more bytes; the sink drains what is already queued.
    fn close(&mut self) {
        self.sender = None;
    }
    /// Whether the sink has drained or failed, without waiting for it.
    fn done(&mut self) -> bool {
        use std::sync::mpsc::TryRecvError;
        if self.result.is_none() {
            self.result = match self.finished.try_recv() {
                Ok(result) => Some(result),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Err(std::io::ErrorKind::BrokenPipe.into())),
            };
        }
        self.result.is_some()
    }
    /// What reached the terminal by now. Delivery is never an owner failure.
    fn report(&mut self, observed: u64) -> Value {
        self.close();
        self.done();
        let state = match &self.result {
            Some(Ok(())) if self.stopped.is_none() => "complete",
            Some(Ok(())) => "stopped",
            Some(Err(_)) => {
                self.stopped.get_or_insert("sink_failed");
                "stopped"
            }
            None => "unfinished",
        };
        let delivered = self.delivered.load(std::sync::atomic::Ordering::Acquire);
        let mut forwarding = json!({"state":state,"delivered_bytes":delivered,
            "undelivered_bytes":observed.saturating_sub(delivered)});
        if let Some(reason) = self.stopped {
            forwarding["reason"] = json!(reason);
        }
        forwarding
    }
}

#[cfg(target_os = "linux")]
struct Capture {
    stream: File,
    file: Option<File>,
    observed: u64,
    stored: u64,
    limit: u64,
    eof: bool,
    name: &'static str,
    tee: Option<Tee>,
}

#[cfg(target_os = "linux")]
fn output_pipe() -> Result<(File, File)> {
    use std::os::fd::FromRawFd as _;
    let mut fds = [-1; 2];
    // SAFETY: pipe2 writes exactly two new descriptors to this owned array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the successful pipe2 returned distinct descriptors exclusively owned here.
    let parent = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: as above, for the write end.
    let child = unsafe { File::from_raw_fd(fds[1]) };
    // SAFETY: scalar fcntl calls on the read end `parent` owns.
    let flags = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        // SAFETY: as above.
        || unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((parent, child))
}

fn write_capture(writer: &mut impl Write, mut bytes: &[u8], stored: &mut u64) -> Result<()> {
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()),
            Ok(n) => {
                *stored += n as u64;
                bytes = &bytes[n..];
            }
            Err(problem) if problem.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(problem) => return Err(problem.into()),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
impl Capture {
    fn drain(&mut self) -> Result<()> {
        let mut buffer = [0_u8; PIPE_READ_BYTES];
        for _ in 0..32 {
            let n = match self.stream.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            self.observed = self.observed.saturating_add(n as u64);
            if let Some(file) = self.file.as_mut() {
                let keep = (self.limit - self.stored).min(n as u64) as usize;
                write_capture(file, &buffer[..keep], &mut self.stored)?;
            }
            if let Some(tee) = self.tee.as_mut() {
                tee.forward(&buffer[..n]);
            }
        }
        Ok(())
    }
    fn finish(&mut self, complete: bool) -> Result<Value> {
        if let Some(file) = self.file.as_mut() {
            file.sync_all()?;
        }
        let mut metadata = if self.file.is_some() {
            json!({"state":if complete && self.eof {"captured"} else {"incomplete"},"limit_bytes":self.limit,"observed_bytes":self.observed,"stored_bytes":self.stored,"truncated":self.observed>self.stored,"path":format!("artifacts/{}.bin",self.name)})
        } else {
            json!({"state":"not_captured","observed_bytes":self.observed})
        };
        if let Some(tee) = self.tee.as_mut() {
            metadata["forwarding"] = tee.report(self.observed);
        }
        Ok(metadata)
    }
    fn close_forwarding(&mut self) {
        if let Some(tee) = self.tee.as_mut() {
            tee.close();
        }
    }
    fn forwarding_done(&mut self) -> bool {
        self.tee.as_mut().is_none_or(Tee::done)
    }
}

/// Give the terminal a bounded grace to show what is queued; whatever it has
/// not shown by then is recorded as undelivered. The writer closes an owner
/// connection that stays silent for its 2 s request timeout, which a grace
/// can reach, so the owner keeps sending heartbeats until it ends or one fails.
#[cfg(target_os = "linux")]
fn forwarding_grace(
    captures: &mut [Capture],
    grace: Duration,
    last_heartbeat: &mut Instant,
    failure: &mut Option<LedgerError>,
    mut heartbeat: impl FnMut() -> Result<()>,
) {
    for item in captures.iter_mut() {
        item.close_forwarding();
    }
    let deadline = Instant::now() + grace;
    while !captures.iter_mut().all(Capture::forwarding_done) && Instant::now() < deadline {
        if failure.is_none() && last_heartbeat.elapsed() >= HEARTBEAT {
            if let Err(problem) = heartbeat() {
                *failure = Some(problem);
            }
            *last_heartbeat = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(target_os = "linux")]
fn terminate(child: &mut Child) {
    // A trailing frame or drain failure can arrive after try_wait reaped the
    // jail. Never signal that cached pid: it may already belong to another process.
    if !matches!(child.try_wait(), Ok(None)) {
        return;
    }
    // The jail handles TERM and proves its own tree death. A forced exit cannot establish it.
    // SAFETY: kill takes scalars; the child is unreaped, so its pid is still ours.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
struct OwnedChild(Child);
#[cfg(target_os = "linux")]
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            terminate(&mut self.0);
        }
    }
}

/// Launch exactly one reserved attempt. Existing owners and settled runs are never relaunched.
pub fn run(options: &RunOptions) -> Result<RunResult> {
    if options.detached {
        return Err(error(
            "detached runs must enter through the independent service launcher",
        ));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(error(
            "ledger launch ownership is currently Linux-only; local store inspection is available",
        ))
    }
    #[cfg(target_os = "linux")]
    run_linux(options, None)
}

#[cfg(target_os = "linux")]
pub(crate) fn run_notifying(
    options: &RunOptions,
    notify: &mut dyn FnMut(&RunRecord),
) -> Result<RunResult> {
    run_linux(options, Some(notify))
}

#[cfg(target_os = "linux")]
fn run_linux(
    options: &RunOptions,
    mut notify: Option<&mut dyn FnMut(&RunRecord)>,
) -> Result<RunResult> {
    let Resolved {
        image,
        image_digest: expected_image,
        payload,
    } = resolve(options)?;
    let mut client = if options.detached {
        // Losing the independent writer must never create a replacement inside
        // this attempt's service cgroup. Strict evidence fails closed instead.
        Client::connect(&options.data)?
    } else {
        connect_or_start(&options.data)?
    };
    let run = if let Some(id) = &options.prepared {
        let existing = client.show(id)?;
        if existing.payload != payload {
            return Err(error("prepared run payload differs from this request"));
        }
        existing
    } else {
        client.prepare(&options.request_id, &payload)?
    };
    if run.state == RunState::Settled || run.state == RunState::Denied {
        if let Some(notify) = notify.as_mut() {
            notify(&run);
        }
        return Ok(RunResult {
            exit_code: record_exit(&run),
            record: run,
        });
    }
    if run.owner.is_some() || run.state != RunState::Prepared {
        if let Some(notify) = notify.as_mut() {
            notify(&run);
            return Ok(RunResult {
                exit_code: record_exit(&run),
                record: run,
            });
        }
        return Err(error(format!(
            "{} already has a launch owner; inspect or reconcile it, never restart it",
            run.run_id
        )));
    }
    let claim = client.claim_owner(&run.run_id)?;
    if let Some(notify) = notify.as_mut() {
        notify(&client.show(&run.run_id)?);
    }
    let mut local_exit_saved = false;
    let result = owned::run_owned(
        options,
        &image,
        &expected_image,
        &run,
        &claim,
        &mut client,
        &mut local_exit_saved,
    );
    if result.is_err() && !local_exit_saved {
        // Covers setup, finalization and lost mutation replies while this
        // library caller remains alive. Existing terminal evidence is preserved.
        record_unknown(
            options,
            &run,
            &mut client,
            &claim.owner_token,
            "owner-returned-error",
            &unknown_body("launch_owner_failed", None),
        );
    }
    result
}

/// An owner's unresolved outcome: the reason, a matching degraded coverage
/// gap and, once the child's streams are finalized, their capture state.
#[cfg(target_os = "linux")]
fn unknown_body(reason: &str, capture: Option<&serde_json::Map<String, Value>>) -> Value {
    let mut body = json!({"reason":reason,
        "outcome":{"kind":"unknown","unknown":true,"unknown_reason":reason},
        "coverage":{"status":"degraded","gaps":[{"reason":reason}]}});
    if let Some(capture) = capture {
        body["capture"] = Value::Object(capture.clone());
    }
    body
}

#[cfg(target_os = "linux")]
fn record_unknown(
    options: &RunOptions,
    run: &RunRecord,
    client: &mut Client,
    owner_token: &str,
    request_id: &str,
    body: &Value,
) {
    // Only called after the owned child is stopped. Preserve terminal evidence
    // when an earlier acknowledgement was lost, and never restart the writer.
    if let Ok(current) = client.show(&run.run_id)
        && current.state.is_terminal()
    {
        return;
    }
    if client
        .append_owner(
            &run.run_id,
            request_id,
            "outcome_unknown",
            None,
            body,
            owner_token,
        )
        .is_ok()
    {
        return;
    }
    // Termination or a bounded foreground drain can outlast the idle socket
    // timeout. Reconnect to the existing writer and prove the same owner birth;
    // this grants no new execution and supplies no acknowledgement if it fails.
    if let Ok(mut fresh) = Client::connect(&options.data)
        && let Ok(current) = fresh.show(&run.run_id)
        && !current.state.is_terminal()
        && let Ok(claim) = fresh.claim_owner(&run.run_id)
    {
        let _ = fresh.append_owner(
            &run.run_id,
            request_id,
            "outcome_unknown",
            None,
            body,
            &claim.owner_token,
        );
    }
}

/// The operator's note about a stream whose foreground forwarding did not
/// finish, saying exactly how much of what was not shown the capture holds:
/// the capture keeps the stream's first `stored_bytes`, the terminal was shown
/// its first `delivered_bytes`.
pub fn forwarding_warning(name: &str, capture: &Value) -> Option<String> {
    let forwarding = &capture["forwarding"];
    if !forwarding.is_object() || forwarding["state"] == "complete" {
        return None;
    }
    let unshown = forwarding["undelivered_bytes"].as_u64().unwrap_or(0);
    if unshown == 0 {
        return None;
    }
    let shown = forwarding["delivered_bytes"].as_u64().unwrap_or(0);
    let held = capture["stored_bytes"]
        .as_u64()
        .unwrap_or(0)
        .saturating_sub(shown)
        .min(unshown);
    let kept = if capture["state"] == "not_captured" {
        "this stream is not captured".into()
    } else if held == unshown {
        "the capture holds them".into()
    } else if held == 0 {
        "the capture holds none of them".into()
    } else {
        format!("the capture holds the first {held} of them")
    };
    Some(format!(
        "{name} forwarding {}: {unshown} bytes had not reached the terminal when the run was \
         recorded; {kept}",
        records::escape_control(forwarding["state"].as_str().unwrap_or("unknown"))
    ))
}

pub fn record_exit(record: &RunRecord) -> i32 {
    if record
        .outcome
        .as_ref()
        .is_some_and(|outcome| outcome["kind"] == "exec_error")
    {
        return 125;
    }
    if let Some(outcome) = record.outcome.as_ref()
        && outcome["kind"] == "signaled"
        && let Some(signal) = outcome["signal"]
            .as_u64()
            .and_then(|n| i32::try_from(n).ok())
    {
        return 128 + signal;
    }
    record
        .outcome
        .as_ref()
        .and_then(|o| o["code"].as_i64())
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(if record.state == RunState::Denied {
            125
        } else {
            1
        })
}

/// Resolve the jail executable once, never constructing a shell command.
pub fn jail_binary(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(fs::canonicalize(path)?);
    }
    let sibling = std::env::current_exe()?.with_file_name("ouro-jail");
    if sibling.is_file() {
        return Ok(fs::canonicalize(sibling)?);
    }
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let path = dir.join("ouro-jail");
        if path.is_file() {
            return Ok(fs::canonicalize(path)?);
        }
    }
    Err(error(
        "ouro-jail is missing; install it beside ouro-ledger or use --jail-bin",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[cfg(target_os = "linux")]
    #[test]
    fn the_owner_wait_sleeps_when_idle_and_wakes_on_bytes_or_exit() {
        let (reader, mut writer) = output_pipe().unwrap();
        let started = Instant::now();
        wait_readable(&[reader.as_raw_fd()], Duration::from_millis(60));
        assert!(started.elapsed() >= Duration::from_millis(50));
        writer.write_all(b"x").unwrap();
        let started = Instant::now();
        wait_readable(&[reader.as_raw_fd()], Duration::from_secs(10));
        assert!(started.elapsed() < Duration::from_secs(5));
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 0.2"])
            .spawn()
            .unwrap();
        let exited = exit_descriptor(child.id()).expect("pidfd_open on the reference kernel");
        let started = Instant::now();
        wait_readable(&[exited.as_raw_fd()], Duration::from_secs(10));
        assert!(started.elapsed() < Duration::from_secs(5));
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn planning_applies_every_launch_check_before_touching_the_jail() {
        type Edit = fn(&mut RunOptions);
        let options = |edit: Edit| {
            let mut options = RunOptions {
                data: "/nonexistent/data".into(),
                jail: "/nonexistent/ouro-jail".into(),
                request_id: "plan".into(),
                prepared: None,
                policy_args: vec![],
                argv: vec!["true".into()],
                batch: true,
                separate_control: false,
                detached: false,
                captures: vec![],
                redact: vec![],
                capture_limit: 1,
                best_effort: false,
                launch: None,
                tags: vec![],
            };
            edit(&mut options);
            options
        };
        let cases: [(Edit, &str); 4] = [
            (
                |o| (o.detached, o.separate_control) = (true, true),
                "client control descriptor",
            ),
            (|o| o.argv.clear(), "program after --"),
            (
                |o| o.capture_limit = MAX_CAPTURE_BYTES + 1,
                "16 MiB per stream",
            ),
            (
                |o| o.captures = vec!["environment".into()],
                "stdout, stderr and argv only",
            ),
        ];
        for (edit, refusal) in cases {
            let refused = resolve_request(&options(edit)).unwrap_err();
            assert!(refused.to_string().contains(refusal), "{refused}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unknown_bodies_name_one_reason_and_carry_finalized_captures() {
        assert_eq!(
            unknown_body("launch_owner_failed", None),
            json!({"reason":"launch_owner_failed",
                "outcome":{"kind":"unknown","unknown":true,"unknown_reason":"launch_owner_failed"},
                "coverage":{"status":"degraded","gaps":[{"reason":"launch_owner_failed"}]}})
        );
        let capture = json!({"stdout":{"state":"incomplete"}});
        assert_eq!(
            unknown_body("finalization_failed", capture.as_object())["capture"],
            capture
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_blocked_terminal_stops_forwarding_but_never_capture_or_the_owner() {
        let (source, mut child) = output_pipe().unwrap();
        // Nothing reads this terminal, so its writer blocks once the pipe is full.
        let (unread_terminal, terminal) = output_pipe().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut capture = Capture {
            stream: source,
            file: Some(File::create(temp.path().join("stdout.bin")).unwrap()),
            observed: 0,
            stored: 0,
            limit: crate::protocol::MAX_CAPTURE_BYTES,
            eof: false,
            name: "stdout",
            tee: Some(Tee::new(terminal)),
        };
        let chunk = vec![b'x'; 32 * 1024];
        for _ in 0..96 {
            child.write_all(&chunk).unwrap();
            capture.drain().unwrap();
        }
        drop(child);
        while !capture.eof {
            capture.drain().unwrap();
        }
        let observed = 96 * chunk.len() as u64;
        assert_eq!((capture.observed, capture.stored), (observed, observed));
        capture.close_forwarding();
        assert!(!capture.forwarding_done());
        let metadata = capture.finish(true).unwrap();
        assert_eq!(metadata["state"], "captured");
        let forwarding = &metadata["forwarding"];
        assert_eq!(forwarding["reason"], "queue_full");
        assert_eq!(forwarding["state"], "unfinished");
        let delivered = forwarding["delivered_bytes"].as_u64().unwrap();
        assert!(delivered < observed);
        assert_eq!(forwarding["undelivered_bytes"], observed - delivered);
        drop(unread_terminal);

        // A terminal that goes away stops forwarding the same way.
        let (unread_terminal, terminal) = output_pipe().unwrap();
        drop(unread_terminal);
        let mut tee = Tee::new(terminal);
        tee.forward(b"lost");
        tee.close();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !tee.done() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let forwarding = tee.report(4);
        assert_eq!(forwarding["state"], "stopped");
        assert_eq!(forwarding["reason"], "sink_failed");
        assert_eq!(forwarding["delivered_bytes"], 0);
        assert_eq!(forwarding["undelivered_bytes"], 4);

        // A terminal that keeps up shows everything.
        let mut tee = Tee::new(File::create(temp.path().join("terminal")).unwrap());
        tee.forward(b"shown");
        tee.close();
        while !tee.done() {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            tee.report(5),
            json!({"state":"complete","delivered_bytes":5,"undelivered_bytes":0})
        );
    }

    #[test]
    fn a_forwarding_warning_says_exactly_what_the_capture_holds() {
        let warning = |capture: Value| forwarding_warning("stdout", &capture);
        let forwarding = |state: &str, shown: u64, unshown: u64| json!({"state":state,"delivered_bytes":shown,"undelivered_bytes":unshown});
        let prefix = "stdout forwarding stopped: 2031616 bytes had not reached the terminal \
                      when the run was recorded";
        // An 8-byte capture of a 2 MiB stream holds none of the unshown bytes.
        assert_eq!(
            warning(json!({"state":"captured","stored_bytes":8,"truncated":true,
                "forwarding":forwarding("stopped",65536,2_031_616)})),
            Some(format!("{prefix}; the capture holds none of them"))
        );
        assert_eq!(
            warning(
                json!({"state":"captured","stored_bytes":2_097_152,"truncated":false,
                "forwarding":forwarding("stopped",65536,2_031_616)})
            ),
            Some(format!("{prefix}; the capture holds them"))
        );
        assert_eq!(
            warning(
                json!({"state":"captured","stored_bytes":65636,"truncated":true,
                "forwarding":forwarding("stopped",65536,2_031_616)})
            ),
            Some(format!("{prefix}; the capture holds the first 100 of them"))
        );
        assert_eq!(
            warning(json!({"state":"not_captured","observed_bytes":2_097_152,
                "forwarding":forwarding("stopped",65536,2_031_616)})),
            Some(format!("{prefix}; this stream is not captured"))
        );
        // Nothing to warn about: everything shown, or nothing left unshown.
        for state in ["complete", "stopped", "unfinished"] {
            assert_eq!(
                warning(json!({"state":"captured","stored_bytes":5,
                    "forwarding":forwarding(state,5,0)})),
                None
            );
        }
        assert_eq!(warning(json!({"state":"captured","stored_bytes":5})), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_owner_keeps_its_writer_connection_alive_through_the_forwarding_grace() {
        let (source, child) = output_pipe().unwrap();
        // Nothing reads this terminal, so its queue never drains.
        let (_unread_terminal, terminal) = output_pipe().unwrap();
        let mut capture = Capture {
            stream: source,
            file: None,
            observed: 0,
            stored: 0,
            limit: 0,
            eof: false,
            name: "stdout",
            tee: Some(Tee::new(terminal)),
        };
        let mut child = child;
        let chunk = vec![b'x'; 32 * 1024];
        for _ in 0..8 {
            child.write_all(&chunk).unwrap();
            capture.drain().unwrap();
        }
        let mut captures = [capture];
        // A grace well past the writer's 2 s idle limit.
        let grace = HEARTBEAT * 12;
        let started = Instant::now();
        let mut last_heartbeat = Instant::now();
        let mut failure = None;
        let mut beats = 0;
        forwarding_grace(
            &mut captures,
            grace,
            &mut last_heartbeat,
            &mut failure,
            || {
                beats += 1;
                Ok(())
            },
        );
        assert!(started.elapsed() >= grace);
        assert!(failure.is_none());
        assert!(beats >= 10, "{beats} heartbeats in {grace:?}");
        // A failed heartbeat is the owner's failure, and the last one sent.
        let mut beats = 0;
        forwarding_grace(
            &mut captures,
            HEARTBEAT * 4,
            &mut last_heartbeat,
            &mut failure,
            || {
                beats += 1;
                Err(error("writer gone"))
            },
        );
        assert_eq!(beats, 1);
        assert!(failure.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capture_keeps_the_exact_short_write_count_before_disk_failure() {
        struct FailingDisk {
            interrupted: bool,
            bytes: Vec<u8>,
        }
        impl Write for FailingDisk {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                if !self.bytes.is_empty() {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
                }
                let n = bytes.len().min(4);
                self.bytes.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut disk = FailingDisk {
            interrupted: false,
            bytes: Vec::new(),
        };
        let cap = 7;
        let mut stored = 0;
        assert!(write_capture(&mut disk, &b"abcdefghijk"[..cap], &mut stored).is_err());
        assert_eq!(disk.bytes, b"abcd");
        assert_eq!(stored, disk.bytes.len() as u64);
        assert!(stored <= cap as u64);
    }

    #[test]
    fn prepared_gate_compares_each_identity_and_receipt_digest() {
        let receipt = crate::test_support::prepared_receipt();
        let control:ControlMessage=serde_json::from_value(json!({"schema":records::SCHEMA_CONTROL,"attempt_id":receipt["attempt_id"],"seq":1,"kind":"prepared","receipt_phase":"prepared","receipt_digest":records::semantic::receipt_digest(&receipt).unwrap(),"outcome":receipt["outcome"],"error":null})).unwrap();
        let run:RunRecord=serde_json::from_value(json!({"schema":"ouro.ledger.run/1","run_id":"run_01234567890123456789012345678901","attempt_id":receipt["attempt_id"],"request_id":"test","payload":{"argv_digest":receipt["argv_digest"],"policy_digest":receipt["policy"]["digest"],"requirements":receipt["policy"]["requirements"]},"state":"prepared","child_protection":"unprotected","owner":null,"outcome":null,"coverage":{},"settlement":"pending","receipts":[],"capture":{},"chain":{"head_seq":1,"head_digest":null}})).unwrap();
        check_prepared(&receipt, &control, &run).unwrap();
        for path in ["attempt_id", "argv_digest"] {
            let mut changed = receipt.clone();
            changed[path] = json!("different");
            assert!(check_prepared(&changed, &control, &run).is_err());
        }
        let mut changed = run.clone();
        changed.payload["policy_digest"] = json!("sha256:different");
        assert!(check_prepared(&receipt, &control, &changed).is_err());
        let mut changed = run.clone();
        changed.payload["requirements"] = json!([]);
        assert!(check_prepared(&receipt, &control, &changed).is_err());
        let mut changed = control.clone();
        changed.receipt_digest = "sha256:different".into();
        assert!(check_prepared(&receipt, &changed, &run).is_err());
    }
}
