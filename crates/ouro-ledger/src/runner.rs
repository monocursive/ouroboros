//! The launch owner: durably admit before opening the jail's existing gate.

#[cfg(target_os = "linux")]
mod evidence;
use std::ffi::OsString;
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
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
#[cfg(target_os = "linux")]
use records::GateFrame;
use records::{ControlKind, ControlMessage, Phase, Receipt};
use serde_json::Value;
#[cfg(target_os = "linux")]
use serde_json::json;

use crate::daemon::Client;
#[cfg(target_os = "linux")]
use crate::protocol::ClaimedOwner;
use crate::protocol::{LedgerError, Result, RunRecord};

#[cfg(target_os = "linux")]
const FRAME_MAX: usize = 1_048_576;
#[cfg(target_os = "linux")]
const CAPTURE_MAX: u64 = 16 * 1_048_576;

/// The operator's literal execution request. Raw argv is never persisted;
/// detached submission transfers it to the owner over a private socket.
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
    pub detached: bool,
    pub captures: Vec<String>,
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

fn error(message: impl Into<String>) -> LedgerError {
    LedgerError(message.into())
}

/// Start a writer on demand. The writer has no terminal or child-stream fds.
pub fn connect_or_start(data: &Path) -> Result<Client> {
    if let Ok(client) = Client::connect(data) {
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
    let mut chunk = [0_u8; 8192];
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
        if bytes.len() > FRAME_MAX {
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
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(256 * 1_048_576 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 256 * 1_048_576 {
        return Err(error("jail executable exceeds image bound"));
    }
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
    let mut request = json!({"schema":"ouro.ledger.request/1", "argv_digest":canonical::argv_digest(&argv),
        "policy_digest":plan["policy"]["digest"], "requirements":requirements,
        "profile":plan["policy"]["name"], "jail_image_digest":image_digest,
        "io":{"mode":if options.batch {"batch"} else {"foreground"},"pty":false},
        "capture":{"streams":options.captures,"limit_bytes":options.capture_limit},
        "evidence":if options.best_effort {"best-effort"} else {"strict"}});
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
        let mut bytes = [0_u8; 8192];
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
                if end + 1 > FRAME_MAX {
                    return Err(error("oversized jail event/control frame"));
                }
                result.push(serde_json::from_slice(&self.pending[..end])?);
                self.pending.drain(..=end);
            }
            if self.pending.len() > FRAME_MAX {
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
    let mut bytes = Vec::new();
    file.take((FRAME_MAX + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > FRAME_MAX {
        return Err(error("receipt exceeded frame bound"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(target_os = "linux")]
struct Tee {
    sender: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    finished: std::sync::mpsc::Receiver<std::io::Result<()>>,
}

#[cfg(target_os = "linux")]
impl Tee {
    fn new(name: &str) -> Result<Self> {
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
        let mut sink = unsafe { File::from_raw_fd(fd) };
        // At most 1 MiB queued per selected stream. The owner never waits on a client write.
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(128);
        let (done, finished) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = (|| {
                for bytes in receiver {
                    sink.write_all(&bytes)?;
                }
                Ok(())
            })();
            let _ = done.send(result);
        });
        Ok(Self {
            sender: Some(sender),
            finished,
        })
    }
    fn forward(&mut self, bytes: &[u8]) -> Result<()> {
        if self
            .sender
            .as_ref()
            .is_none_or(|s| s.try_send(bytes.to_vec()).is_err())
        {
            self.sender.take();
            return Err(error(
                "foreground output forwarding exceeded its bound or lost its sink",
            ));
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        self.sender.take();
        self.finished
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| {
                error("foreground output forwarding did not finish within two seconds")
            })??;
        Ok(())
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
    let child = unsafe { File::from_raw_fd(fds[1]) };
    let flags = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((parent, child))
}

#[cfg(target_os = "linux")]
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
        let mut buffer = [0_u8; 8192];
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
                tee.forward(&buffer[..n])?;
            }
        }
        Ok(())
    }
    fn finish(&mut self, complete: bool) -> Result<Value> {
        if let Some(file) = self.file.as_mut() {
            file.sync_all()?;
        }
        if let Some(tee) = self.tee.as_mut() {
            tee.finish()?;
        }
        Ok(if self.file.is_some() {
            json!({"state":if complete && self.eof {"captured"} else {"incomplete"},"limit_bytes":self.limit,"observed_bytes":self.observed,"stored_bytes":self.stored,"truncated":self.observed>self.stored,"path":format!("artifacts/{}.bin",self.name)})
        } else {
            json!({"state":"not_captured","observed_bytes":self.observed})
        })
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
    if options.argv.is_empty() {
        return Err(error("run needs a program after --"));
    }
    if options.capture_limit > CAPTURE_MAX {
        return Err(error("capture limit exceeds 16 MiB per stream"));
    }
    if options
        .captures
        .iter()
        .any(|s| s != "stdout" && s != "stderr")
    {
        return Err(error("this slice captures stdout/stderr only"));
    }
    let image = pinned_image(&options.jail)?;
    let expected_image = image_digest(&image)?;
    let plan = plan(options, &image)?;
    if image_digest(&image)? != expected_image {
        return Err(error("jail image changed during policy resolution"));
    }
    let payload = payload(options, &plan, &expected_image)?;
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
    if run.state == "settled" || run.state == "denied" {
        if let Some(notify) = notify.as_mut() {
            notify(&run);
        }
        return Ok(RunResult {
            exit_code: record_exit(&run),
            record: run,
        });
    }
    if run.owner.is_some() || run.state != "prepared" {
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
    let result = run_owned(options, &image, &expected_image, &run, &claim, &mut client);
    if result.is_err() && !evidence::completion_pending(options, &run) {
        // Covers setup, finalization and lost mutation replies while this
        // library caller remains alive. Existing terminal evidence is preserved.
        record_unknown(
            options,
            &run,
            &mut client,
            &claim.owner_token,
            "owner-returned-error",
            &json!({"reason":"launch_owner_failed",
                "outcome":{"kind":"unknown","unknown":true,"unknown_reason":"launch_owner_failed"},
                "coverage":{"status":"degraded","gaps":[{"reason":"launch_owner_failed"}]}}),
        );
    }
    result
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
        && !["prepared", "admitted"].contains(&current.state.as_str())
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
        && ["prepared", "admitted"].contains(&current.state.as_str())
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

#[cfg(target_os = "linux")]
fn run_owned(
    options: &RunOptions,
    image: &File,
    expected_image: &str,
    run: &RunRecord,
    claim: &ClaimedOwner,
    client: &mut Client,
) -> Result<RunResult> {
    let mut evidence = evidence::Evidence::new(options, run, claim)?;
    let run_dir = options.data.join("ledger").join(&run.run_id);
    // Read the jail's canonical receipt. Its copy fence correctly forbids an
    // additional --receipt inside DATA; the unified DATA root protects the ledger too.
    let receipt_path = options
        .data
        .join("attempts")
        .join(&claim.attempt_id)
        .join("jail.json");
    let (trace_parent, trace_child) = UnixStream::pair()?;
    let (control_parent, control_child) = UnixStream::pair()?;
    let (mut gate_parent, gate_child) = UnixStream::pair()?;
    let mut command = image_command(image);
    command
        .arg("run")
        .args(&options.policy_args)
        .arg("--attempt-id")
        .arg(&claim.attempt_id)
        .arg("--trace-fd")
        .arg(trace_child.as_raw_fd().to_string())
        .arg("--control-fd")
        .arg(control_child.as_raw_fd().to_string())
        .arg("--gate-fd")
        .arg(gate_child.as_raw_fd().to_string())
        .arg("--")
        .args(&options.argv)
        .env("OURO_DATA_DIR", &options.data);
    command.stdin(if options.batch {
        Stdio::null()
    } else {
        Stdio::inherit()
    });
    let mut captures = Vec::new();
    for name in ["stdout", "stderr"] {
        if options.batch || options.captures.iter().any(|s| s == name) {
            // Socket stdio would be host-socket authority; the jail correctly
            // rejects it. Keep the child write end blocking and drain a pipe.
            let (parent, child) = output_pipe()?;
            let selected = options.captures.iter().any(|s| s == name);
            let file = if selected {
                Some(
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(run_dir.join(format!("artifacts/{name}.bin")))?,
                )
            } else {
                None
            };
            if name == "stdout" {
                command.stdout(Stdio::from(child));
            } else {
                command.stderr(Stdio::from(child));
            }
            captures.push(Capture {
                stream: parent,
                file,
                observed: 0,
                stored: 0,
                limit: options.capture_limit,
                eof: false,
                name,
                tee: if options.batch {
                    None
                } else {
                    Some(Tee::new(name)?)
                },
            });
        } else if name == "stdout" {
            command.stdout(Stdio::inherit());
        } else {
            command.stderr(Stdio::inherit());
        }
    }
    let fds = [
        trace_child.as_raw_fd(),
        control_child.as_raw_fd(),
        gate_child.as_raw_fd(),
    ];
    let parent_pid = std::process::id() as libc::pid_t;
    // SAFETY: async-signal-safe syscalls only; no allocation or locks after fork.
    unsafe {
        command.pre_exec(move || {
            for fd in fds {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    let mut child = OwnedChild(match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            client.append_owner(
                &run.run_id,
                "spawn-refused",
                "denied",
                None,
                &json!({"reason":"jail_spawn_failed"}),
                &claim.owner_token,
            )?;
            return Err(e.into());
        }
    });
    drop(command);
    drop(trace_child);
    drop(control_child);
    drop(gate_child);
    let mut trace = Frames::new(trace_parent)?;
    let mut control = Frames::new(control_parent)?;
    let mut gate = Some(&mut gate_parent);
    let mut admitted = false;
    let mut terminal: Option<ControlMessage> = None;
    let mut terminal_seen = None;
    let mut control_seq = 0_u64;
    let mut last_trace: Option<Value> = None;
    let mut last_heartbeat = Instant::now();
    let mut failure = None;
    let mut exit = None;
    let preparation_deadline = Instant::now() + Duration::from_secs(30);
    let mut exit_seen = None;
    let mut cancel_sent = false;
    let result: Result<()> = (|| {
        loop {
            if options.detached && crate::service::cancel_requested() && !cancel_sent {
                cancel_sent = true;
                if let Some(pipe) = gate.take() {
                    pipe.shutdown(std::net::Shutdown::Write)?;
                }
                if child.0.try_wait()?.is_none() {
                    // The direct child is unreaped, so its pid cannot be reused.
                    unsafe {
                        libc::kill(child.0.id() as i32, libc::SIGTERM);
                    }
                }
            }
            for value in control.drain()? {
                let message: ControlMessage = serde_json::from_value(value)?;
                if message.schema != records::SCHEMA_CONTROL
                    || message.attempt_id != run.attempt_id
                    || message.seq != control_seq + 1
                {
                    return Err(error("invalid jail control identity or sequence"));
                }
                control_seq = message.seq;
                if terminal.is_some() {
                    return Err(error("jail emitted control after its terminal record"));
                }
                match message.kind {
                    ControlKind::Prepared => {
                        if cancel_sent {
                            continue;
                        }
                        if admitted {
                            return Err(error("duplicate prepared control"));
                        }
                        let receipt = read_receipt(&receipt_path, "prepared")?;
                        let typed = check_prepared(&receipt, &message, run)?;
                        // Native Linux exec holds the executing inode against writes
                        // (ETXTBSY). Bind the actual live jail image before durable admission.
                        let executing =
                            File::open(format!("/proc/{}/exe", child.0.id())).map_err(|e| {
                                error(format!(
                                    "binding prepared jail image for pid {}: {e}",
                                    child.0.id()
                                ))
                            })?;
                        if image_digest(&executing)? != expected_image {
                            return Err(error(
                                "executing jail image differs from the prepared image digest",
                            ));
                        }
                        client.append_owner(
                            &run.run_id,
                            "admission",
                            "admitted",
                            None,
                            &json!({"receipt":receipt,"receipt_digest":message.receipt_digest}),
                            &claim.owner_token,
                        )?;
                        evidence.admitted()?;
                        let release = GateFrame {
                            schema: records::SCHEMA_GATE.into(),
                            action: "release".into(),
                            attempt_id: claim.attempt_id.clone(),
                            policy_digest: typed.policy.digest,
                        };
                        let mut frame = serde_json::to_vec(&release)?;
                        frame.push(b'\n');
                        let pipe = gate.take().ok_or_else(|| error("gate already consumed"))?;
                        pipe.write_all(&frame)?;
                        pipe.shutdown(std::net::Shutdown::Write)?;
                        admitted = true;
                    }
                    ControlKind::ExecConfirmed => {
                        if !admitted {
                            return Err(error("exec before durable admission"));
                        }
                    }
                    ControlKind::Refused | ControlKind::Settled | ControlKind::Unsettled => {
                        terminal = Some(message);
                        terminal_seen = Some(Instant::now());
                    }
                }
            }
            for event in trace.drain()? {
                evidence.source(client, &event)?;
                last_trace = Some(event);
            }
            for capture in &mut captures {
                capture.drain()?;
            }
            if last_heartbeat.elapsed() >= Duration::from_millis(250) {
                evidence.heartbeat(client)?;
                last_heartbeat = Instant::now();
            }
            if exit.is_none() {
                exit = child.0.try_wait()?;
                if exit.is_some() {
                    exit_seen = Some(Instant::now());
                }
            }
            if exit.is_some() && trace.eof && control.eof && captures.iter().all(|c| c.eof) {
                break;
            }
            if control.eof && terminal.is_none() && exit.is_none() {
                return Err(error(
                    "jail closed control without terminal lifecycle evidence",
                ));
            }
            if !admitted && Instant::now() >= preparation_deadline {
                return Err(error("jail preparation exceeded thirty seconds"));
            }
            if exit_seen.is_some_and(|t| t.elapsed() > Duration::from_secs(5)) {
                return Err(error("jail exited without bounded final stream drain"));
            }
            if terminal_seen.is_some_and(|t| t.elapsed() > Duration::from_secs(5)) && exit.is_none()
            {
                return Err(error(
                    "jail did not exit within five seconds of terminal control",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    })();
    if let Err(e) = result {
        failure = Some(e);
        gate.take();
        drop(gate_parent);
        terminate(&mut child.0);
    }
    let mut capture = serde_json::Map::new();
    let complete = failure.is_none();
    for item in &mut captures {
        match item.finish(complete) {
            Ok(value) => {
                capture.insert(item.name.into(), value);
            }
            Err(problem) => {
                failure.get_or_insert(problem);
                capture.insert(item.name.into(), json!({"state":"incomplete","observed_bytes":item.observed,"stored_bytes":item.stored}));
            }
        }
    }
    for name in ["stdout", "stderr"] {
        capture
            .entry(name)
            .or_insert_with(|| json!({"state":"not_captured"}));
    }
    if let Err(problem) = File::open(run_dir.join("artifacts")).and_then(|dir| dir.sync_all()) {
        failure.get_or_insert(problem.into());
    }
    if let Some(problem) = failure {
        // An unreachable writer supplies no acknowledgement. A later orphan reconciliation says unknown.
        record_unknown(
            options,
            run,
            client,
            &claim.owner_token,
            "owner-failure",
            &json!({"reason":"owner_or_evidence_failure","capture":capture,
                "outcome":{"kind":"unknown","unknown":true,"unknown_reason":"owner_or_evidence_failure"},
                "coverage":{"status":"degraded","gaps":[{"reason":"owner_or_evidence_failure"}]}}),
        );
        return Err(problem);
    }
    let finalized: Result<_> = (|| {
        let receipt = read_receipt(&receipt_path, "terminal")?;
        let typed: Receipt = serde_json::from_value(receipt.clone())?;
        let digest =
            records::semantic::receipt_digest(&receipt).map_err(|e| error(e.to_string()))?;
        let final_control =
            terminal.ok_or_else(|| error("jail exited without a terminal control record"))?;
        Ok((receipt, typed, digest, final_control))
    })();
    let (receipt, typed, digest, final_control) = match finalized {
        Ok(values) => values,
        Err(problem) => {
            record_unknown(
                options,
                run,
                client,
                &claim.owner_token,
                "finalization-failed",
                &json!({"reason":"finalization_failed","capture":capture,
                    "outcome":{"kind":"unknown","unknown":true,"unknown_reason":"finalization_failed"},
                    "coverage":{"status":"degraded","gaps":[{"reason":"finalization_failed"}]}}),
            );
            return Err(problem);
        }
    };
    if typed.attempt_id != run.attempt_id
        || digest != final_control.receipt_digest
        || typed.phase != final_control.receipt_phase
        || !records::semantic::receipt(&receipt).is_empty()
        || last_trace.as_ref().is_none_or(|event| {
            !records::semantic::trace_ends_with(std::slice::from_ref(event), &receipt).is_empty()
        })
    {
        record_unknown(
            options,
            run,
            client,
            &claim.owner_token,
            "invalid-final",
            &json!({"reason":"final_receipt_or_trace_mismatch",
                "outcome":{"kind":"unknown","unknown":true,"unknown_reason":"final_receipt_or_trace_mismatch"},
                "coverage":{"status":"degraded","gaps":[{"reason":"final_receipt_or_trace_mismatch"}]}}),
        );
        return Err(error("terminal receipt/control/trace did not corroborate"));
    }
    let kind = if !admitted && typed.phase == Phase::Refused {
        "denied"
    } else if typed.phase == Phase::Settled && typed.lifetime.tree_empty == Some(true)
        || admitted
            && typed.phase == Phase::Refused
            && typed.outcome.kind == records::OutcomeKind::ExecError
            && !typed.exec_observed
            && typed.lifetime.tree_empty == Some(true)
            && typed.lifetime.integrity == "verified"
            && typed.lifetime.verification_scope.as_deref() == Some("attempt_tree")
    {
        "settled"
    } else {
        "outcome_unknown"
    };
    evidence.finish(client, kind, json!({"receipt":receipt,"receipt_digest":digest,"outcome":typed.outcome,"coverage":typed.coverage,"capture":capture}), final_control)?;
    let record = client.show(&run.run_id)?;
    let exit_code = exit.map_or(1, |s| {
        s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
    });
    Ok(RunResult { record, exit_code })
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
        .unwrap_or(if record.state == "denied" { 125 } else { 1 })
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
        let receipt: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/receipt-prepared.json"
        ))
        .unwrap();
        let control:ControlMessage=serde_json::from_value(json!({"schema":records::SCHEMA_CONTROL,"attempt_id":receipt["attempt_id"],"seq":1,"kind":"prepared","receipt_phase":"prepared","receipt_digest":records::semantic::receipt_digest(&receipt).unwrap(),"outcome":receipt["outcome"],"error":null})).unwrap();
        let run:RunRecord=serde_json::from_value(json!({"schema":"ouro.ledger.run/1","run_id":"run_01234567890123456789012345678901","attempt_id":receipt["attempt_id"],"request_id":"test","payload":{"argv_digest":receipt["argv_digest"],"policy_digest":receipt["policy"]["digest"],"requirements":receipt["policy"]["requirements"]},"state":"prepared","child_protection":"pending","owner":null,"outcome":null,"coverage":{},"settlement":"pending","receipts":[],"capture":{},"chain":{"head_seq":1,"head_digest":null}})).unwrap();
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
