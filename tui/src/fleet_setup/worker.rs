//! The detached deployment worker (seams S2 and S3).
//!
//! `ouro fleet worker start` forks a worker that is *not* a child of whoever asked for
//! it: `setsid` gives it its own session and process group, its stdio goes to a private
//! log, and it inherits no descriptor from the caller. That is the whole point — the
//! broker starts it from inside the BEAM, and the BEAM stopping (which is exactly what
//! first-time local setup does) must not take the deployment with it. The parent prints
//! one JSON line naming the socket and the instance, and exits.
//!
//! `ouro fleet worker run` is the foreground form the detached child execs. It writes a
//! capability file, listens on a private Unix socket, and runs the same
//! [`super::engine::Engine`] the CLI runs. A client attaches with the capability and its
//! subject/session, which is what every challenge is then bound to; the worker checks
//! the capability in constant time and the peer's uid against its own.
//!
//! Nothing here logs a `respond` frame. It is the one frame that may carry a secret.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use super::challenge::{Answer, Binding, Challenge, Registry};
use super::engine::{Engine, Outcome};
use super::journal::{Handle as JournalHandle, Journal};
use super::{refuse, ChallengeRequest, Conversation, Event, OperationRequest, OperationState};

/// The instance id the parent mints and the child adopts. Not a secret — the capability
/// file is — so an environment variable is the right place for it.
pub const INSTANCE_ENV: &str = "OUROBOROS_DEPLOY_INSTANCE";

/// How long `start` waits for the child to answer before reporting a failure.
const LISTEN_DEADLINE: Duration = Duration::from_secs(20);
/// How long one readiness probe may take. It is a round trip over a local socket.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a finished worker stays reachable so an attached client can read the result.
const DONE_LINGER: Duration = Duration::from_secs(60);
/// How long one broadcast may take to reach one client before that client is dropped.
const BROADCAST_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// What `sockaddr_un` will hold, with room for the platform's own accounting.
const MAX_SOCKET_PATH: usize = 100;
/// A worker nobody attaches to in this long exits and cleans up.
///
/// The broker cannot cancel a worker whose capability file it refused to read — reading
/// it is what would disclose the capability — so a worker that is never attached to has
/// to bound its own life. The fifteen-minute abandonment timeout is for a worker that
/// *was* attached and then was not; this is for one that never was.
pub const ATTACH_DEADLINE: Duration = Duration::from_secs(60);

/// What `ouro fleet worker start` prints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Started {
    pub socket: PathBuf,
    pub instance: String,
}

impl Started {
    pub fn to_value(&self) -> Value {
        json!({ "socket": self.socket.display().to_string(), "instance": self.instance })
    }
}

/// Fork the detached worker and wait until it is listening.
pub fn start(data_dir: &Path, operation: &str) -> Result<Started> {
    use std::os::unix::process::CommandExt as _;

    super::validate_operation_id(operation)?;
    super::ensure_deploy_dir(data_dir)?;
    // The request is the worker's input and must exist, and be private, before anything
    // starts: the seam gives `worker start` an operation id and a data directory and
    // nothing else, precisely so that a target, an account and a port never appear in
    // `ps`.
    let request = OperationRequest::read(data_dir, operation)?;
    // The sanitized target goes into the journal here, before the child exists, so an
    // operation that never gets as far as connecting still says what it was for.
    {
        let mut journal = Journal::open(data_dir, operation, request.kind)?;
        if journal.record().target.is_none() {
            journal.set_target(super::journal::TargetIdentity {
                machine: request.machine.clone(),
                address: request.address.clone(),
                port: request.ssh_port,
                ssh_user: request.ssh_user.clone(),
                ..super::journal::TargetIdentity::default()
            })?;
        }
    }

    let socket = super::socket_path(data_dir, operation);
    let _ = std::fs::remove_file(&socket);
    let instance = super::random_hex(16)?;
    let log = open_private_log(&super::log_path(data_dir, operation))?;
    let errors = log.try_clone().context("cloning the worker log")?;

    let executable = std::env::current_exe().context("resolving this executable")?;
    let mut command = std::process::Command::new(executable);
    command
        .arg("fleet")
        .arg("worker")
        .arg("run")
        .arg("--operation")
        .arg(operation)
        .arg("--data-dir")
        .arg(data_dir)
        .env(INSTANCE_ENV, &instance)
        .env("OUROBOROS_DATA_DIR", data_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(errors));
    // SAFETY: `umask` and `setsid` are async-signal-safe and are the only calls made
    // between fork and exec. The new session is what makes the worker outlive both the
    // process that asked for it and the BEAM that process belongs to.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Everything above stdio, closed. A worker started from inside the BEAM
            // inherits whatever descriptors that process left without CLOEXEC — sockets,
            // journals, a half-written file — and holds them for the life of an
            // operation that outlives its spawner on purpose. There is no `closefrom` on
            // macOS, so this is the loop.
            let highest = libc::getdtablesize();
            for descriptor in 3..highest {
                libc::close(descriptor);
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("starting the deployment worker")?;

    let log = super::log_path(data_dir, operation);
    let capability = super::capability_path(data_dir, operation);
    let deadline = Instant::now() + LISTEN_DEADLINE;
    loop {
        // Readiness is a round trip, not a path. `UnixListener::bind` creates the socket
        // file and then calls `listen`, so the path exists for a moment during which a
        // connect is refused — and a broker that connects once in that moment gives up
        // on a worker that is about to be perfectly fine. This asks the worker a
        // question and waits for its answer.
        // Both halves of seam S3, because the broker uses both the instant this line is
        // printed: it reads the capability file and then connects with what it found.
        // Either one alone is a worker that is only half there.
        if published(&capability) && answers(&socket) {
            // The child has read its request and is serving; the document has served its
            // purpose and does not outlive the handoff.
            OperationRequest::consume(data_dir, operation)?;
            return Ok(Started { socket, instance });
        }
        if let Some(status) = child.try_wait()? {
            return refuse(
                "worker_failed",
                format!(
                    "the deployment worker exited before it was serving ({status}); its log is {}{}",
                    log.display(),
                    log_tail(&log)
                ),
            );
        }
        if Instant::now() >= deadline {
            let unmet = if published(&capability) {
                "answer on its socket"
            } else {
                "publish its capability file"
            };
            return refuse(
                "worker_failed",
                format!(
                    "the deployment worker did not {unmet} within {} seconds; its log is {}{}",
                    LISTEN_DEADLINE.as_secs(),
                    log.display(),
                    log_tail(&log)
                ),
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Whether the worker has published its capability, to the letter of seam S3.
///
/// The broker `lstat`s this file before it reads the secret and refuses anything that is
/// not a private regular file of this account's, so the parent holds the socket line
/// until the file would satisfy that same check.
fn published(capability: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let Ok(metadata) = std::fs::symlink_metadata(capability) else {
        return false;
    };
    metadata.is_file()
        && metadata.permissions().mode() & 0o777 == 0o600
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.len() > 0
}

/// Which file a path names right now, as the kernel counts identity.
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

/// Remove a file on the way out, but only while it is still the one this worker made.
///
/// A second worker for the same operation binds its own socket and publishes its own
/// capability over the first one's paths. A departing worker that unlinks those paths
/// regardless takes its successor's socket and secret with it — which a broker reads as
/// a worker that never published a capability, or as one it can never reach.
fn unpublish(path: &Path, made: Option<(u64, u64)>) {
    if made.is_some() && file_identity(path) == made {
        let _ = std::fs::remove_file(path);
    }
}

/// Ask the worker one question and see whether it answers.
///
/// Deliberately a frame the worker refuses: seam S3's first frame is always `attach`, so
/// `status` comes back `not_attached` — which is a *complete* round trip through the
/// accept loop, the uid check and the frame reader, and therefore the only honest answer
/// to "is it serving yet?".
fn answers(socket: &Path) -> bool {
    let Ok(stream) = UnixStream::connect(socket) else {
        return false;
    };
    if stream.set_read_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(PROBE_TIMEOUT)).is_err()
    {
        return false;
    }
    let mut writer = match stream.try_clone() {
        Ok(writer) => writer,
        Err(_) => return false,
    };
    if writeln!(writer, "{}", json!({"v": 1, "id": "probe", "op": "status"}))
        .and_then(|()| writer.flush())
        .is_err()
    {
        return false;
    }
    let mut line = String::new();
    if BufReader::new(stream).read_line(&mut line).unwrap_or(0) == 0 {
        return false;
    }
    serde_json::from_str::<Value>(line.trim())
        .ok()
        .and_then(|frame| {
            frame
                .get("reason")
                .and_then(Value::as_str)
                .map(|reason| reason == "not_attached")
        })
        .unwrap_or(false)
}

/// The end of the worker's own log, for a failure an operator would otherwise have to go
/// and read a file to understand.
fn log_tail(path: &Path) -> String {
    const TAIL: usize = 600;
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let mut start = text.len().saturating_sub(TAIL);
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    let tail = super::sanitize_remote_text(&text[start..], TAIL);
    if tail.is_empty() {
        String::new()
    } else {
        format!(" and ends: {tail}")
    }
}

fn open_private_log(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening the worker log {}", path.display()))
}

/// Everything the socket thread and the engine thread share.
struct Shared {
    operation: String,
    instance: String,
    capability: String,
    registry: Registry,
    /// Shared with the engine thread: this side writes the operation's owner and any
    /// takeover, that side writes its steps.
    journal: JournalHandle,
    state: Mutex<OperationState>,
    subscribers: Mutex<Vec<Subscriber>>,
    last_activity: Mutex<Instant>,
    cancelled: AtomicBool,
    /// Whether any client has ever completed an `attach`. A bare connection is not one:
    /// the parent's own readiness probe connects, asks one question and leaves, and that
    /// must not count as somebody taking charge of the operation.
    attached_ever: AtomicBool,
    finished: Mutex<Option<Value>>,
}

struct Subscriber {
    id: u64,
    binding: Binding,
    writer: UnixStream,
}

impl Shared {
    fn touch(&self) {
        *self.last_activity.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
    }

    fn set_state(&self, state: OperationState) {
        *self.state.lock().unwrap_or_else(|p| p.into_inner()) = state;
    }

    fn state(&self) -> OperationState {
        *self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn attached(&self) -> usize {
        self.subscribers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// The binding a challenge issued right now belongs to: the attached client.
    fn current_binding(&self) -> Option<Binding> {
        self.subscribers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last()
            .map(|subscriber| subscriber.binding.clone())
    }

    /// Send one event to every attached client.
    ///
    /// The writes happen *outside* the subscribers lock and against a write deadline.
    /// Holding the lock across a blocking `write_all` meant one attached client that
    /// stopped reading wedged the engine thread the first time it reported progress —
    /// and every `status`, `respond` and `attach` behind it. A client that cannot keep
    /// up is dropped; the journal is the durable record it can come back to.
    fn broadcast(&self, event: Value) {
        let line = format!("{event}\n");
        let targets: Vec<(u64, UnixStream)> = {
            let subscribers = self.subscribers.lock().unwrap_or_else(|p| p.into_inner());
            subscribers
                .iter()
                .filter_map(|subscriber| {
                    subscriber
                        .writer
                        .try_clone()
                        .ok()
                        .map(|writer| (subscriber.id, writer))
                })
                .collect()
        };
        let mut wedged = Vec::new();
        for (id, mut writer) in targets {
            let _ = writer.set_write_timeout(Some(BROADCAST_WRITE_TIMEOUT));
            if writer
                .write_all(line.as_bytes())
                .and_then(|()| writer.flush())
                .is_err()
            {
                wedged.push(id);
            }
        }
        if !wedged.is_empty() {
            let mut subscribers = self.subscribers.lock().unwrap_or_else(|p| p.into_inner());
            subscribers.retain(|subscriber| !wedged.contains(&subscriber.id));
        }
    }

    /// Drop every subscriber whose subject is not this one, closing their sockets.
    ///
    /// Used by `takeover`: recording the handover and leaving the previous owner
    /// attached left them reading every event — including the metadata of challenges
    /// issued to their successor — and able to cancel the operation.
    fn evict_other_subjects(&self, owner: &str) -> usize {
        let mut subscribers = self.subscribers.lock().unwrap_or_else(|p| p.into_inner());
        let before = subscribers.len();
        subscribers.retain(|subscriber| {
            if subscriber.binding.subject == owner {
                return true;
            }
            let _ = subscriber.writer.shutdown(std::net::Shutdown::Both);
            false
        });
        before - subscribers.len()
    }

    fn status(&self) -> Value {
        let pending: Vec<Value> = self
            .registry
            .pending_kinds()
            .into_iter()
            .map(|(id, kind)| json!({"challenge": id, "kind": kind.as_str()}))
            .collect();
        json!({
            "operation": self.operation,
            "instance": self.instance,
            "state": self.state().as_str(),
            "owner": self.journal.owner(),
            "attached": self.attached(),
            "pending": pending,
            "done": self.finished.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        })
    }
}

/// The worker's [`Conversation`]: a challenge goes to the attached client and the engine
/// thread blocks until a bound, single-use answer comes back.
struct WorkerConversation {
    shared: Arc<Shared>,
}

impl Conversation for WorkerConversation {
    fn ask(&self, request: ChallengeRequest) -> Result<Answer> {
        let binding = self.shared.current_binding();
        let challenge: Challenge =
            self.shared
                .registry
                .issue(request.kind, request.metadata, binding)?;
        self.shared.touch();
        self.shared
            .broadcast(challenge_event(&self.shared, &challenge));
        let answer = self.shared.registry.wait(&challenge.challenge)?;
        self.shared.touch();
        Ok(answer)
    }

    fn notify(&self, event: Event) {
        self.shared.touch();
        let frame = match event {
            Event::State(state) => {
                self.shared.set_state(state);
                json!({"v": 1, "event": "state", "state": state.as_str()})
            }
            Event::Step {
                machine,
                step,
                outcome,
                detail,
            } => json!({
                "v": 1, "event": "step", "machine": machine, "step": step,
                "outcome": outcome, "detail": detail,
            }),
            Event::Log(line) => {
                json!({"v": 1, "event": "log", "line": super::sanitize_remote_text(&line, 300)})
            }
        };
        self.shared.broadcast(frame);
    }

    fn cancelled(&self) -> bool {
        self.shared.cancelled.load(Ordering::SeqCst)
    }
}

/// How the worker builds its engine. Split out so a test can run the same loop with a
/// different gateway or service seam without a second copy of the server.
pub struct WorkerConfig {
    pub data_dir: PathBuf,
    pub token_file: PathBuf,
    pub gateway: Arc<dyn super::gateway::Gateway>,
    pub services: Arc<dyn super::service::ServiceActions>,
    pub programs: super::ssh::Programs,
    pub trust_tools: super::trust::Tools,
    pub user_known_hosts: Option<PathBuf>,
    pub origin: crate::update::release::Origin,
    pub version: String,
}

/// Serve one operation until it finishes, is cancelled, or is abandoned.
pub fn run(config: WorkerConfig, operation: &str) -> Result<()> {
    super::validate_operation_id(operation)?;
    let data_dir = config.data_dir.clone();
    super::ensure_deploy_dir(&data_dir)?;
    let request = OperationRequest::read(&data_dir, operation)?;

    let capability = super::random_hex(32)?;
    let capability_path = super::capability_path(&data_dir, operation);
    // Seam S3, and the order matters: the capability is published *before* the socket is
    // bound, so that anything able to connect can already read what it must send. The
    // parent checks for both before it prints the socket line, and the broker reads the
    // file the instant that line appears.
    super::write_private_atomic(&capability_path, capability.as_bytes())?;
    let published_capability = file_identity(&capability_path);

    let socket_path = super::socket_path(&data_dir, operation);
    // Named before it is attempted: `sockaddr_un` caps a path at about a hundred bytes,
    // and a data directory plus a 64-character operation id passes that. Failing here
    // says which path and why; failing at `bind` left the caller with "the worker exited
    // before it listened" and a log file to go and read.
    if socket_path.as_os_str().len() > MAX_SOCKET_PATH {
        return refuse(
            "socket_path_too_long",
            format!(
                "{} is {} bytes and a Unix socket path cannot exceed about {MAX_SOCKET_PATH}. Use a shorter data directory or a shorter operation id",
                socket_path.display(),
                socket_path.as_os_str().len()
            ),
        );
    }
    let _ = std::fs::remove_file(&socket_path);
    // Created private and *stays* private: the umask closes the window between `bind`
    // and `set_permissions` in which a socket would otherwise exist at 0777 & ~umask,
    // and the explicit mode is what a broker checks with `lstat` before it connects.
    // SAFETY: umask is process-global; this worker serves one operation and sets it for
    // the rest of its life, which is what every file it writes wants anyway.
    unsafe {
        libc::umask(0o077);
    }
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding {}", socket_path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", socket_path.display()))?;
    }
    listener
        .set_nonblocking(true)
        .context("configuring the worker socket")?;
    let bound_socket = file_identity(&socket_path);

    let journal = JournalHandle::new(Journal::open(&data_dir, operation, request.kind)?);
    let shared = Arc::new(Shared {
        operation: operation.to_string(),
        instance: std::env::var(INSTANCE_ENV).unwrap_or_else(|_| "unknown".to_string()),
        capability,
        registry: Registry::new(),
        state: Mutex::new(journal.state()),
        journal: journal.clone(),
        subscribers: Mutex::new(Vec::new()),
        last_activity: Mutex::new(Instant::now()),
        cancelled: AtomicBool::new(false),
        attached_ever: AtomicBool::new(false),
        finished: Mutex::new(None),
    });

    let engine_thread = {
        let shared = Arc::clone(&shared);
        let conversation: Arc<dyn Conversation> = Arc::new(WorkerConversation {
            shared: Arc::clone(&shared),
        });
        let engine = Engine {
            data_dir: config.data_dir.clone(),
            token_file: config.token_file.clone(),
            request,
            conversation,
            gateway: config.gateway,
            services: config.services,
            programs: config.programs,
            trust_tools: config.trust_tools,
            user_known_hosts: config.user_known_hosts,
            origin: config.origin,
            version: config.version,
            // A worker's operation belongs to the first client that attaches to it, not
            // to the account the worker happens to run as.
            owner: None,
        };
        std::thread::Builder::new()
            .name("ouro-deploy".to_string())
            .spawn(move || {
                let result = engine.run_with(&journal);
                let frame = match &result {
                    Ok(outcome) => done_frame(outcome),
                    Err(error) => json!({
                        "v": 1, "event": "done", "ok": false,
                        "reason": super::reason_of(error).unwrap_or("failed"),
                        "detail": super::sanitize_remote_text(&format!("{error:#}"), 400),
                    }),
                };
                *shared.finished.lock().unwrap_or_else(|p| p.into_inner()) = Some(frame.clone());
                shared.touch();
                shared.broadcast(frame);
                result.map(|_| ())
            })
            .context("starting the deployment engine")?
    };

    let mut next_subscriber = 0_u64;
    let mut done_at: Option<Instant> = None;
    let started_at = Instant::now();
    let mut never_attached = false;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                next_subscriber += 1;
                let shared = Arc::clone(&shared);
                let id = next_subscriber;
                shared.touch();
                let _ = std::thread::Builder::new()
                    .name(format!("ouro-deploy-client-{id}"))
                    .spawn(move || {
                        let _ = serve_client(stream, id, shared);
                    });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }

        let finished = shared
            .finished
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some();
        if finished {
            let at = *done_at.get_or_insert_with(Instant::now);
            // Linger briefly so an attached client reads the result; a client that has
            // already detached is not waited for, and the journal is the durable answer
            // for anyone who comes back later.
            if shared.attached() == 0 || at.elapsed() >= DONE_LINGER {
                break;
            }
        } else if !shared.attached_ever.load(Ordering::SeqCst)
            && started_at.elapsed() >= ATTACH_DEADLINE
        {
            // Nobody ever came. Stop the engine and let it unwind; the journal is
            // written after it has, so its own "the challenge expired" does not
            // overwrite the reason that actually matters.
            never_attached = true;
            shared.cancelled.store(true, Ordering::SeqCst);
            shared.registry.invalidate_all();
            break;
        } else {
            let idle = shared
                .last_activity
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .elapsed();
            if shared.attached() == 0 && idle >= super::WORKER_IDLE_TIMEOUT {
                // Bounded abandonment: do not hold the issuer's locks for an inspection
                // nobody is watching.
                shared.cancelled.store(true, Ordering::SeqCst);
                shared.registry.invalidate_all();
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    shared.registry.invalidate_all();
    let result = engine_thread.join();
    if never_attached {
        let _ = shared.journal.fail(
            OperationState::Interrupted,
            format!(
                "never_attached: no client attached within {} seconds of this worker starting",
                ATTACH_DEADLINE.as_secs()
            ),
        );
    }
    unpublish(&socket_path, bound_socket);
    unpublish(&capability_path, published_capability);
    // A worker that exits without its parent having consumed the request — the
    // never-attached case, or a crash between `bind` and the socket line — takes the
    // document describing the target with it.
    let _ = OperationRequest::consume(&data_dir, operation);
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => refuse("worker_failed", "the deployment engine panicked"),
    }
}

/// The one shape a question takes on the wire, whether it is asked now or replayed to a
/// client that attached after it was asked.
fn challenge_event(shared: &Arc<Shared>, challenge: &Challenge) -> Value {
    json!({
        "v": 1,
        "event": "challenge",
        "operation": shared.operation,
        "challenge": challenge.challenge,
        "kind": challenge.kind.as_str(),
        "expires_at": challenge.expires_at,
        "metadata": challenge.metadata,
    })
}

fn done_frame(outcome: &Outcome) -> Value {
    json!({
        "v": 1,
        "event": "done",
        "ok": outcome.complete(),
        "state": outcome.state.as_str(),
        "summary": outcome.summary,
        "next": outcome.next,
        "residue": outcome.residue,
        "unknown": outcome.unknown,
    })
}

/// One client connection: `attach` first, then ops until it says goodbye.
fn serve_client(stream: UnixStream, id: u64, shared: Arc<Shared>) -> Result<()> {
    // The listener polls, so it is non-blocking — and an accepted socket inherits that
    // on macOS. A non-blocking read of a client that has not spoken yet returns
    // `WouldBlock`, which would end this connection before its first frame.
    stream
        .set_nonblocking(false)
        .context("configuring the client connection")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3600)))
        .context("bounding the client read")?;
    let mut writer = stream.try_clone().context("cloning the client socket")?;

    // Seam S3: the peer must be this same account. A capability file is a secret; the
    // uid check is the boundary that makes it one.
    let peer = peer_uid(&stream)?;
    if !super::askpass::same_account(peer) {
        let _ = write_reply(
            &mut writer,
            &Value::Null,
            false,
            json!({"reason": "peer_uid_mismatch", "detail": "this socket answers only the account that owns the operation"}),
        );
        return Ok(());
    }

    let mut reader = BufReader::new(stream);
    let mut attached = false;
    loop {
        let mut line = String::new();
        let read = reader
            .by_ref()
            .take(super::MAX_FRAME_BYTES as u64 + 1)
            .read_line(&mut line)
            .context("reading a client frame")?;
        if read == 0 {
            break;
        }
        if read > super::MAX_FRAME_BYTES {
            let _ = write_reply(
                &mut writer,
                &Value::Null,
                false,
                json!({"reason": "frame_too_large", "detail": "a frame over 1 MiB is not read"}),
            );
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        shared.touch();
        let Ok(Value::Object(frame)) = serde_json::from_str::<Value>(line.trim()) else {
            let _ = write_reply(
                &mut writer,
                &Value::Null,
                false,
                json!({"reason": "bad_request", "detail": "a request is one JSON object per line"}),
            );
            continue;
        };
        let id_value = frame.get("id").cloned().unwrap_or(Value::Null);
        let op = frame.get("op").and_then(Value::as_str).unwrap_or("");

        if !attached {
            if op != "attach" {
                let _ = write_reply(
                    &mut writer,
                    &id_value,
                    false,
                    json!({"reason": "not_attached", "detail": "the first frame on a connection is `attach`"}),
                );
                continue;
            }
            match attach(&frame, &shared, id, &writer) {
                Ok(reply) => {
                    attached = true;
                    let _ = write_reply(&mut writer, &id_value, true, reply);
                    // A worker asks its first question before anything can attach to it.
                    // Whatever is still unanswered and unowned becomes this client's,
                    // and is put in front of it now.
                    if let Some(binding) = subscriber_binding(&shared, id) {
                        for challenge in shared.registry.claim_unbound(&binding) {
                            let event = challenge_event(&shared, &challenge);
                            let _ = writer
                                .write_all(format!("{event}\n").as_bytes())
                                .and_then(|()| writer.flush());
                        }
                    }
                }
                Err(error) => {
                    let _ = write_reply(
                        &mut writer,
                        &id_value,
                        false,
                        json!({
                            "reason": super::reason_of(&error).unwrap_or("refused"),
                            "detail": format!("{error}"),
                        }),
                    );
                }
            }
            continue;
        }

        match op {
            "status" => {
                let _ = write_reply(&mut writer, &id_value, true, shared.status());
            }
            "respond" => {
                // Deliberately not logged, in any form: this is the one frame that may
                // carry a secret.
                let challenge = frame.get("challenge").and_then(Value::as_str).unwrap_or("");
                let response = frame.get("response").cloned().unwrap_or(Value::Null);
                if !owns(&shared, id) {
                    let _ = write_reply(
                        &mut writer,
                        &id_value,
                        false,
                        json!({
                            "reason": "not_owner",
                            "detail": "this operation belongs to another subject now",
                        }),
                    );
                    continue;
                }
                let binding = subscriber_binding(&shared, id);
                match shared
                    .registry
                    .respond(challenge, binding.as_ref(), &response)
                {
                    Ok(()) => {
                        let _ = write_reply(&mut writer, &id_value, true, json!({}));
                    }
                    Err(error) => {
                        let _ = write_reply(
                            &mut writer,
                            &id_value,
                            false,
                            json!({
                                "reason": super::reason_of(&error).unwrap_or("refused"),
                                "detail": format!("{error}"),
                            }),
                        );
                    }
                }
            }
            "cancel" => {
                // Only the operation's current owner may stop it. A session that has
                // been taken over keeps neither its challenges nor this.
                if !owns(&shared, id) {
                    let _ = write_reply(
                        &mut writer,
                        &id_value,
                        false,
                        json!({
                            "reason": "not_owner",
                            "detail": "this operation belongs to another subject now",
                        }),
                    );
                    continue;
                }
                shared.cancelled.store(true, Ordering::SeqCst);
                shared.registry.invalidate_all();
                let _ = write_reply(&mut writer, &id_value, true, json!({"cancelling": true}));
            }
            "detach" => {
                detach(&shared, id);
                let _ = write_reply(&mut writer, &id_value, true, json!({}));
                attached = false;
            }
            "bye" => {
                detach(&shared, id);
                let _ = write_reply(&mut writer, &id_value, true, json!({}));
                break;
            }
            other => {
                let _ = write_reply(
                    &mut writer,
                    &id_value,
                    false,
                    json!({
                        "reason": "unsupported_op",
                        "detail": format!("`{}` is not an operation this worker answers", super::sanitize_remote_text(other, 40)),
                    }),
                );
            }
        }
    }
    detach(&shared, id);
    Ok(())
}

fn attach(
    frame: &Map<String, Value>,
    shared: &Arc<Shared>,
    id: u64,
    writer: &UnixStream,
) -> Result<Value> {
    let capability = frame.get("cap").and_then(Value::as_str).unwrap_or("");
    if !super::constant_time_eq(capability, &shared.capability) {
        return refuse(
            "bad_capability",
            "this operation's capability file does not contain that value",
        );
    }
    let subject = frame
        .get("subject")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let session = frame
        .get("session")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if subject.is_empty() || session.is_empty() {
        return refuse(
            "bad_request",
            "`attach` names the authenticated subject and its client session, which every challenge is then bound to",
        );
    }

    // An operation belongs to the subject that started it. A second subject attaching to
    // a live operation would otherwise be handed its password challenge, which is how a
    // resumed operation becomes somebody else's; taking it over is allowed, and is an
    // explicit act that both names get written down for.
    let owner = shared.journal.owner();
    let takeover = frame
        .get("takeover")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut takeover_step = None;
    match owner.as_deref() {
        None => shared.journal.claim(&subject)?,
        Some(existing) if existing == subject => {}
        Some(existing) if takeover => {
            takeover_step = Some(shared.journal.note_takeover(Some(existing), &subject)?);
            // Whatever the previous owner left pending is theirs no longer, and no
            // unconsumed secret of theirs survives the handover — and neither does their
            // connection: a session that kept reading would see every challenge issued
            // to its successor.
            shared.registry.invalidate_all();
            shared.evict_other_subjects(&subject);
        }
        Some(existing) => {
            return refuse(
                "not_owner",
                format!(
                    "operation {} belongs to {existing}. Attach with `takeover` to continue it as {subject}; it will be recorded",
                    shared.operation
                ),
            )
        }
    }

    shared.attached_ever.store(true, Ordering::SeqCst);
    let binding = Binding { subject, session };
    shared
        .subscribers
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(Subscriber {
            id,
            binding,
            writer: writer.try_clone().context("cloning the client socket")?,
        });
    if let Some(step) = &takeover_step {
        shared.broadcast(json!({
            "v": 1,
            "event": "step",
            "machine": step.machine,
            "step": step.step,
            "outcome": step.outcome,
            "detail": step.detail,
        }));
    }
    Ok(json!({
        "operation": shared.operation,
        "instance": shared.instance,
        "state": shared.state().as_str(),
        "owner": shared.journal.owner(),
    }))
}

fn detach(shared: &Arc<Shared>, id: u64) {
    let mut subscribers = shared.subscribers.lock().unwrap_or_else(|p| p.into_inner());
    let before = subscribers.len();
    subscribers.retain(|subscriber| subscriber.id != id);
    if subscribers.len() != before && subscribers.is_empty() {
        // A lost authentication session invalidates its pending challenge and drops any
        // unconsumed secret. The step then waits for a fresh one.
        drop(subscribers);
        shared.registry.invalidate_all();
    }
}

/// Whether this connection speaks for the operation's current owner.
///
/// The second of two gates, and the one no ordinary sequence of frames reaches: a
/// takeover evicts every other subject before this is ever consulted, and a client of
/// another subject cannot attach without taking over. It is here for the case eviction
/// cannot cover — `shutdown` on a socket can fail, and then the old session is off the
/// subscriber list but still connected, which is exactly when "who owns this operation"
/// has to be asked again rather than assumed. Mutating it away therefore survives the
/// suite; that is a statement about reachability, not about whether it should be here.
fn owns(shared: &Arc<Shared>, id: u64) -> bool {
    match (subscriber_binding(shared, id), shared.journal.owner()) {
        (Some(binding), Some(owner)) => binding.subject == owner,
        // An operation with no recorded owner has not been claimed by anyone, so the
        // attached client is as entitled as any.
        (Some(_), None) => true,
        _ => false,
    }
}

fn subscriber_binding(shared: &Arc<Shared>, id: u64) -> Option<Binding> {
    shared
        .subscribers
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|subscriber| subscriber.id == id)
        .map(|subscriber| subscriber.binding.clone())
}

fn write_reply(writer: &mut UnixStream, id: &Value, ok: bool, fields: Value) -> Result<()> {
    let frame = super::envelope(id, ok, fields);
    writer
        .write_all(format!("{frame}\n").as_bytes())
        .and_then(|()| writer.flush())
        .context("answering a client")
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd as _;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the descriptor is owned by `stream`, and both out-pointers name
    // initialized local storage.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("reading the client's uid");
    }
    Ok(uid)
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd as _;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the descriptor is owned by `stream`; the option buffer and its length
    // describe initialized local storage of exactly that size.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast::<libc::c_void>(),
            &mut length,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("reading the client's uid");
    }
    Ok(credentials.uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line `start` prints is the seam's, and nothing about the operation reaches
    /// the command line beyond its id and its data directory.
    #[test]
    fn the_started_line_names_the_socket_and_the_instance() {
        let started = Started {
            socket: PathBuf::from("/data/fleet/deploy/op-0123456789ab.sock"),
            instance: "ff00".into(),
        };
        assert_eq!(
            started.to_value(),
            json!({
                "socket": "/data/fleet/deploy/op-0123456789ab.sock",
                "instance": "ff00"
            })
        );
    }

    /// Readiness is an answer, not a path.
    ///
    /// A socket file exists from the moment `bind` returns — before `listen`, before the
    /// accept loop, and for as long after a worker dies as nobody unlinks it. Each of
    /// these is a path that exists and a worker that is not serving.
    #[test]
    fn a_socket_that_exists_is_not_a_worker_that_answers() {
        let dir = std::env::temp_dir().join(format!("o-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");

        let missing = dir.join("absent.sock");
        assert!(!answers(&missing), "nothing there answers nothing");

        // A path that exists and is not a socket at all.
        let regular = dir.join("regular.sock");
        std::fs::write(&regular, b"not a socket").expect("a written file");
        assert!(regular.try_exists().unwrap_or(false));
        assert!(!answers(&regular), "a file is not a listener");

        // Bound, listening, and never accepting: the connect succeeds and the write
        // lands in the backlog, so only waiting for the reply tells the truth.
        let deaf = dir.join("deaf.sock");
        let _listener = UnixListener::bind(&deaf).expect("a bound socket");
        assert!(deaf.try_exists().unwrap_or(false));
        assert!(!answers(&deaf), "a listener that never speaks is not ready");

        // And one that answers the way the worker does.
        let live = dir.join("live.sock");
        let listener = UnixListener::bind(&live).expect("a bound socket");
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("a connection");
            let mut writer = stream.try_clone().expect("a cloned socket");
            let mut line = String::new();
            BufReader::new(stream)
                .read_line(&mut line)
                .expect("a probe frame");
            writeln!(
                writer,
                "{}",
                json!({"v": 1, "id": "probe", "ok": false, "reason": "not_attached"})
            )
            .expect("a written reply");
        });
        assert!(answers(&live), "the worker's own refusal is the greeting");
        server.join().expect("the server thread");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The capability check is the broker's, made before the socket line is printed.
    #[test]
    fn a_capability_is_a_private_regular_file_of_this_account_with_something_in_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("o-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");

        assert!(
            !published(&dir.join("absent.cap")),
            "nothing is not a capability"
        );
        assert!(!published(&dir), "a directory is not a capability");

        let empty = dir.join("empty.cap");
        std::fs::write(&empty, b"").expect("a written file");
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600))
            .expect("a private mode");
        assert!(!published(&empty), "an empty file is a half-written one");

        let loose = dir.join("loose.cap");
        std::fs::write(&loose, b"cafe").expect("a written file");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644))
            .expect("a loose mode");
        assert!(!published(&loose), "a readable secret is not a secret");

        let good = dir.join("good.cap");
        std::fs::write(&good, b"cafe").expect("a written file");
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600))
            .expect("a private mode");
        assert!(published(&good));

        let link = dir.join("link.cap");
        std::os::unix::fs::symlink(&good, &link).expect("a symlink");
        assert!(!published(&link), "a link to a capability is not one");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A worker removes what it made, and only while it is still what it made.
    #[test]
    fn a_departing_worker_unpublishes_its_own_files_and_no_others() {
        let dir = std::env::temp_dir().join(format!("o-unpub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");

        let path = dir.join("op.cap");
        std::fs::write(&path, b"mine").expect("a written file");
        let mine = file_identity(&path);
        assert!(mine.is_some());

        // A successor replaced the file at that path: it is not this worker's to remove.
        std::fs::remove_file(&path).expect("the old file");
        std::fs::write(&path, b"theirs").expect("a successor's file");
        unpublish(&path, mine);
        assert_eq!(
            std::fs::read_to_string(&path).expect("still there"),
            "theirs",
            "a departing worker leaves its successor's file alone"
        );

        // And its own, it takes with it.
        unpublish(&path, file_identity(&path));
        assert!(!path.try_exists().expect("a readable directory"));

        // A file that was never made is not removed, and nothing panics.
        unpublish(&path, None);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
