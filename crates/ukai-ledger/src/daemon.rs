//! Authenticated same-user Unix ingress. Only this daemon owns the store lock.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    faults,
    protocol::{
        AppendReceipt, CatalogPage, CatalogRequest, ClaimedOwner, DEFAULT_VERIFY_LIMIT,
        DiscoveryPage, DiscoveryRequest, ErrorKind, GcPlan, GcResult, LedgerError, MAX_CONNECTIONS,
        MAX_FRAME_BYTES, OperatorIntent, PROTOCOL_VERSION, Peer, ReadPage, ReadRequest, Request,
        Response, Result, RunRecord, StoreStatus, TailPage, TailRequest, VerifyPage, VerifyReport,
    },
    store::{Store, VerifyPlan},
};

const TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(10);
const ACCEPT_BACKOFF_LIMIT: Duration = Duration::from_secs(1);
const GC_TIMEOUT: Duration = Duration::from_secs(300);
/// A verify page is re-read by its connection, never by the writer thread,
/// so waiting on one large run delays only the client that asked for it.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(300);
/// The connection stops re-reading here and reports what it did not check,
/// leaving room to ask the writer about GC and to send the page in time.
const VERIFY_WORK: Duration = VERIFY_TIMEOUT.saturating_sub(Duration::from_secs(20));

fn response_timeout(request: &Request) -> Duration {
    match request {
        Request::Gc { dry_run: false, .. } => GC_TIMEOUT,
        Request::Verify { .. } => VERIFY_TIMEOUT,
        _ => TIMEOUT,
    }
}

pub struct Client {
    stream: UnixStream,
    transport_failed: bool,
}

impl Client {
    /// Connect to the live writer and require that it speaks this protocol.
    pub fn connect(data: &Path) -> Result<Self> {
        let mut client = Self::open(data)?;
        client.check_protocol()?;
        Ok(client)
    }

    /// An authenticated connection whose protocol has not been checked yet.
    pub fn open(data: &Path) -> Result<Self> {
        let path = data.join("ledger/serve.sock");
        let meta = fs::symlink_metadata(&path)?;
        if !crate::fsx::owner_only(&meta) {
            return Err(LedgerError::refused(
                "daemon socket is not owned and private",
            ));
        }
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let server = peer_credentials(&stream)?;
        if server.uid != crate::fsx::euid() {
            return Err(LedgerError::refused(
                "daemon peer uid is not the current user",
            ));
        }
        Ok(Self {
            stream,
            transport_failed: false,
        })
    }

    /// A writer of another version could misread or refuse every request;
    /// say so once, instead of failing later on an undecodable reply.
    pub(crate) fn check_protocol(&mut self) -> Result<()> {
        protocol_mismatch(&self.ping()?).map_or(Ok(()), Err)
    }

    /// The writer that answers for `data` in this protocol, or `None` when
    /// none answers. One that answers in another protocol is a refusal, never
    /// an absence: starting a second writer would only fail on the store lock.
    pub(crate) fn reachable(data: &Path) -> Result<Option<Self>> {
        let Ok(mut client) = Self::open(data) else {
            return Ok(None);
        };
        client.check_protocol()?;
        Ok(Some(client))
    }

    fn request<T: DeserializeOwned>(&mut self, request: Request) -> Result<T> {
        // Any incomplete exchange poisons this connection; never reuse it after
        // a lost reply. Explicit writer refusals remain hard errors.
        if self.transport_failed {
            return Err(LedgerError::new(
                ErrorKind::Io(std::io::ErrorKind::BrokenPipe),
                "daemon connection requires reconnect",
            ));
        }
        self.transport_failed = true;
        write_frame(&mut self.stream, &request)?;
        self.stream
            .set_read_timeout(Some(response_timeout(&request)))?;
        let response = read_frame::<Response>(&mut self.stream);
        self.stream.set_read_timeout(Some(TIMEOUT))?;
        let response = response?;
        self.transport_failed = false;
        match response {
            Response::Ok { value } => Ok(serde_json::from_value(value)?),
            Response::Error { message } => Err(LedgerError::remote(message)),
        }
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn transport_failed(&self) -> bool {
        self.transport_failed
    }
    pub fn reconcile_pending(&mut self, run_id: &str) -> Result<RunRecord> {
        self.request(Request::ReconcilePending {
            run_id: run_id.into(),
        })
    }
    pub fn ping(&mut self) -> Result<Value> {
        self.request(Request::Ping)
    }
    pub fn append(&mut self, intent: &OperatorIntent) -> Result<AppendReceipt> {
        self.request(Request::Append {
            intent: intent.clone(),
        })
    }
    pub fn tail(&mut self, request: &TailRequest) -> Result<TailPage> {
        self.request(Request::Tail {
            request: request.clone(),
        })
    }
    pub fn prepare(&mut self, request_id: &str, payload: &Value) -> Result<RunRecord> {
        self.request(Request::Prepare {
            request_id: request_id.into(),
            payload: payload.clone(),
        })
    }
    pub fn claim_owner(&mut self, run_id: &str) -> Result<ClaimedOwner> {
        self.request(Request::ClaimOwner {
            run_id: run_id.into(),
        })
    }
    pub fn append_owner(
        &mut self,
        run_id: &str,
        request_id: &str,
        kind: &str,
        effect_id: Option<&str>,
        body: &Value,
        token: &str,
    ) -> Result<AppendReceipt> {
        self.request(Request::AppendOwner {
            run_id: run_id.into(),
            request_id: request_id.into(),
            kind: kind.into(),
            effect_id: effect_id.map(str::to_owned),
            body: body.clone(),
            token: token.into(),
        })
    }
    pub fn append_source(
        &mut self,
        run_id: &str,
        event: &Value,
        token: &str,
    ) -> Result<AppendReceipt> {
        self.request(Request::AppendSource {
            run_id: run_id.into(),
            event: event.clone(),
            token: token.into(),
        })
    }
    pub fn show(&mut self, run_id: &str) -> Result<RunRecord> {
        self.request(Request::Show {
            run_id: run_id.into(),
        })
    }
    pub fn show_with_transcript(&mut self, run_id: &str) -> Result<Value> {
        self.request(Request::ShowWithTranscript {
            run_id: run_id.into(),
        })
    }
    /// Every run's projection, through the paginated catalog.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn runs(&mut self) -> Result<Vec<RunRecord>> {
        let mut runs = Vec::new();
        let mut after = None;
        loop {
            let page = self.catalog(&CatalogRequest {
                filter: Default::default(),
                after: after.take(),
                limit: crate::discovery::MAX_CATALOG_LIMIT,
            })?;
            for summary in &page.runs {
                runs.push(self.show(&summary.run_id)?);
            }
            if page.done {
                return Ok(runs);
            }
            after = page.next_after;
        }
    }
    pub fn catalog(&mut self, request: &CatalogRequest) -> Result<CatalogPage> {
        self.request(Request::Catalog {
            request: request.clone(),
        })
    }
    pub fn discover(&mut self, request: &DiscoveryRequest) -> Result<DiscoveryPage> {
        self.request(Request::Discover {
            request: request.clone(),
        })
    }
    /// Fresh verification of one run, or of every run page by page.
    pub fn verify(&mut self, run_id: Option<&str>) -> Result<Vec<VerifyReport>> {
        let mut reports = Vec::new();
        let mut after = None;
        loop {
            let page: VerifyPage = self.request(Request::Verify {
                run_id: run_id.map(str::to_owned),
                after: after.take(),
                limit: DEFAULT_VERIFY_LIMIT,
            })?;
            reports.extend(page.reports);
            match page.next_after {
                Some(next) if !page.done => after = Some(next),
                _ => return Ok(reports),
            }
        }
    }
    pub fn status(&mut self) -> Result<StoreStatus> {
        self.request(Request::Status)
    }
    pub fn read(&mut self, request: &ReadRequest) -> Result<ReadPage> {
        self.request(Request::Read {
            request: request.clone(),
        })
    }
    pub fn settle_orphans(&mut self) -> Result<Vec<RunRecord>> {
        self.request(Request::SettleOrphans)
    }
    pub fn hold(&mut self, run_id: &str, request_id: &str) -> Result<AppendReceipt> {
        self.request(Request::Hold {
            run_id: run_id.into(),
            request_id: request_id.into(),
        })
    }
    pub fn release(&mut self, run_id: &str, request_id: &str) -> Result<AppendReceipt> {
        self.request(Request::Release {
            run_id: run_id.into(),
            request_id: request_id.into(),
        })
    }
    pub fn gc_plan_policy(
        &mut self,
        retain_days: Option<u32>,
        capture_retain_days: Option<u32>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<GcPlan> {
        self.request(Request::Gc {
            dry_run: true,
            retain_days,
            capture_retain_days,
            after: after.map(str::to_owned),
            limit,
        })
    }
    pub fn gc_policy(
        &mut self,
        retain_days: Option<u32>,
        capture_retain_days: Option<u32>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<GcResult> {
        self.request(Request::Gc {
            dry_run: false,
            retain_days,
            capture_retain_days,
            after: after.map(str::to_owned),
            limit,
        })
    }
}

/// Why a writer that answered `ping` with `writer` cannot serve this client.
/// A writer older than protocol versioning names no protocol at all.
pub fn protocol_mismatch(writer: &Value) -> Option<LedgerError> {
    if writer["protocol"] == PROTOCOL_VERSION {
        return None;
    }
    let spoken = match writer["protocol"].as_u64() {
        Some(version) => format!("protocol {version}"),
        None => "an unversioned protocol".into(),
    };
    Some(LedgerError::refused(format!(
        "ledger writer speaks {spoken}, this client speaks protocol {PROTOCOL_VERSION}; \
         restart the writer once its runs settle"
    )))
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(LedgerError::refused(
            "socket frame exceeds its 1048576-byte limit",
        ));
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    Ok(serde_json::from_slice(&read_frame_bytes(reader)?)?)
}

/// An out-of-bounds length is `InvalidData`; anything else is transport.
fn read_frame_bytes(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut size = [0; 4];
    reader.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("socket frame exceeds its {MAX_FRAME_BYTES}-byte limit"),
        ));
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// The next request, or the refusal to send before closing a connection
/// whose frames cannot be trusted. A transport error closes it silently.
fn next_request(socket: &mut impl Read) -> std::result::Result<Request, Option<String>> {
    let bytes = match read_frame_bytes(socket) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            return Err(Some(format!("invalid_frame: {error}")));
        }
        Err(_) => return Err(None),
    };
    serde_json::from_slice(&bytes).map_err(|error| {
        let detail: String = error.to_string().chars().take(256).collect();
        Some(format!(
            "unsupported_request: this writer (protocol {PROTOCOL_VERSION}) cannot decode \
             the request; client and writer versions may differ: {detail}"
        ))
    })
}

/// Transient accept failures (descriptor or memory exhaustion, a connection
/// reset while queued) must not stop the writer from accepting later ones.
fn transient_accept_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::EINTR
                | libc::EAGAIN
                | libc::ECONNABORTED
                | libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::EPROTO
        )
    )
}

/// Refuse a connection the writer cannot serve now. A fresh socket's send
/// buffer holds this small frame, so the acceptor never waits on a client
/// that does not read.
fn refuse_busy(mut socket: &UnixStream, reason: &str) {
    let _ = socket.set_nonblocking(true);
    let _ = write_frame(
        &mut socket,
        &Response::Error {
            message: format!("writer_busy: {reason}; retry"),
        },
    );
}

/// A connection handler on its own thread. Starting one can fail under
/// resource pressure, which the acceptor survives.
type Spawn = fn(Box<dyn FnOnce() + Send>) -> std::io::Result<()>;

fn spawn_thread(handler: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
    thread::Builder::new().spawn(handler).map(drop)
}

/// Accept until a non-transient failure, which is returned. Connections past
/// the bound, or whose handler cannot start, are refused explicitly rather
/// than dropped. Repeated failures to accept, and to start handlers, each
/// back off on their own: a connection accepted between two handlers that
/// cannot start does not make the second wait any shorter.
fn accept_connections(
    listener: UnixListener,
    sender: mpsc::SyncSender<Message>,
    spawn: Spawn,
    pause: fn(Duration),
) -> LedgerError {
    let count = Arc::new(AtomicUsize::new(0));
    let mut accept_wait = ACCEPT_BACKOFF;
    let mut spawn_wait = ACCEPT_BACKOFF;
    loop {
        let socket = match listener.accept() {
            Ok((socket, _)) => {
                accept_wait = ACCEPT_BACKOFF;
                socket
            }
            Err(error) if transient_accept_error(&error) => {
                eprintln!("ukai-ledger: retrying accept after {error}");
                pause(accept_wait);
                accept_wait = (accept_wait * 2).min(ACCEPT_BACKOFF_LIMIT);
                continue;
            }
            Err(error) => return error.into(),
        };
        let Ok(peer) = peer_credentials(&socket) else {
            continue;
        };
        if peer.uid != crate::fsx::euid() {
            continue;
        }
        if count.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            count.fetch_sub(1, Ordering::AcqRel);
            refuse_busy(
                &socket,
                &format!("the writer already serves {MAX_CONNECTIONS} connections"),
            );
            continue;
        }
        // Shared, so the connection can still be refused if its thread
        // cannot start.
        let socket = Arc::new(socket);
        let handler = {
            let (socket, sender, count) = (socket.clone(), sender.clone(), count.clone());
            move || {
                serve_connection(&socket, &peer, &sender);
                count.fetch_sub(1, Ordering::AcqRel);
            }
        };
        match spawn(Box::new(handler)) {
            Ok(()) => spawn_wait = ACCEPT_BACKOFF,
            Err(error) => {
                count.fetch_sub(1, Ordering::AcqRel);
                refuse_busy(&socket, "the writer cannot start a connection handler now");
                eprintln!("ukai-ledger: refusing a connection after {error}");
                pause(spawn_wait);
                spawn_wait = (spawn_wait * 2).min(ACCEPT_BACKOFF_LIMIT);
            }
        }
    }
}

/// Why a connection gets no answer from the writer thread.
#[derive(Clone, Copy)]
enum Unanswered {
    /// The bounded queue is full, or the writer is gone; the client is told.
    QueueFull,
    /// The writer did not answer in time; the connection closes.
    Lost,
}

fn ask<T>(
    sender: &mpsc::SyncSender<Message>,
    peer: &Peer,
    timeout: Duration,
    work: impl FnOnce(mpsc::SyncSender<T>) -> Work,
) -> std::result::Result<T, Unanswered> {
    let (reply, response) = mpsc::sync_channel(1);
    let message = Message {
        work: work(reply),
        peer: peer.clone(),
    };
    sender
        .try_send(message)
        .map_err(|_| Unanswered::QueueFull)?;
    response.recv_timeout(timeout).map_err(|_| Unanswered::Lost)
}

fn serve_connection(mut socket: &UnixStream, peer: &Peer, sender: &mpsc::SyncSender<Message>) {
    let _ = socket.set_read_timeout(Some(TIMEOUT));
    let _ = socket.set_write_timeout(Some(TIMEOUT));
    loop {
        let request = match next_request(&mut socket) {
            Ok(request) => request,
            Err(refusal) => {
                if let Some(message) = refusal {
                    let _ = write_frame(&mut socket, &Response::Error { message });
                }
                return;
            }
        };
        let response = match request {
            Request::Verify {
                run_id,
                after,
                limit,
            } => verify(
                sender,
                peer,
                run_id.as_deref(),
                after.as_deref(),
                limit,
                VERIFY_WORK,
            ),
            request => ask(sender, peer, response_timeout(&request), |reply| {
                Work::Request(request, reply)
            }),
        };
        let response = match response {
            Ok(response) => response,
            Err(Unanswered::QueueFull) => {
                let _ = write_frame(
                    &mut socket,
                    &Response::Error {
                        message: "bounded daemon queue is full".into(),
                    },
                );
                return;
            }
            Err(Unanswered::Lost) => return,
        };
        if write_frame(&mut socket, &response).is_err() {
            return;
        }
    }
}

/// One fresh verification page. The writer only plans it and says whether a
/// GC ran; the canonical history is re-read here, on this connection's
/// thread, so owners keep their writer while a large run is verified.
/// One fresh verification page, re-read on the connection's thread for at
/// most `work`; what is not re-read by then is reported as not checked.
fn verify(
    sender: &mpsc::SyncSender<Message>,
    peer: &Peer,
    run_id: Option<&str>,
    after: Option<&str>,
    limit: u32,
    work: Duration,
) -> std::result::Result<Response, Unanswered> {
    let deadline = Instant::now() + work;
    // Asking the writer stays possible past the deadline, so a stopped
    // re-read is still reported rather than dropped.
    let wait = || {
        deadline
            .saturating_duration_since(Instant::now())
            .max(TIMEOUT)
    };
    let unanswered = std::cell::Cell::new(None);
    let lost = |problem| {
        unanswered.set(Some(problem));
        LedgerError::new(
            ErrorKind::Io(std::io::ErrorKind::TimedOut),
            "the writer did not answer",
        )
    };
    let page = crate::store::verify_page(
        &mut |run_id, after, limit| {
            ask(sender, peer, wait(), |reply| Work::PlanVerify {
                run_id: run_id.map(str::to_owned),
                after: after.map(str::to_owned),
                limit,
                reply,
            })
            .map_err(lost)?
        },
        &mut || ask(sender, peer, wait(), Work::GcGeneration).map_err(lost),
        &mut || Instant::now() < deadline,
        run_id,
        after,
        limit,
    );
    if let Some(problem) = unanswered.get() {
        return Err(problem);
    }
    let response = match page.and_then(|page| Ok(serde_json::to_value(page)?)) {
        Ok(value) => Response::Ok { value },
        Err(error) => Response::Error {
            message: error.into_message(),
        },
    };
    Ok(response)
}

#[derive(Clone)]
struct Capability {
    run_id: String,
    role: &'static str,
    peer: Peer,
    token_id: String,
}

/// What a connection asks of the single writer thread, each with its reply.
enum Work {
    Request(Request, mpsc::SyncSender<Response>),
    /// The writer's cheap half of a fresh verification page.
    PlanVerify {
        run_id: Option<String>,
        after: Option<String>,
        limit: u32,
        reply: mpsc::SyncSender<Result<VerifyPlan>>,
    },
    GcGeneration(mpsc::SyncSender<u64>),
}

struct Message {
    work: Work,
    peer: Peer,
}

pub fn serve(data: &Path) -> Result<()> {
    let retention = crate::config::load()?;
    let mut store = Store::open(data)?;
    store.retention = retention;
    let path = store.root().join("serve.sock");
    if let Ok(meta) = fs::symlink_metadata(&path) {
        use std::os::unix::fs::FileTypeExt as _;
        if !meta.file_type().is_socket() || meta.uid() != crate::fsx::euid() {
            return Err(LedgerError::refused(
                "refusing unsafe existing daemon socket",
            ));
        }
        fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    fs::File::open(store.root())?.sync_all()?;
    let (sender, receiver) = mpsc::sync_channel::<Message>(MAX_CONNECTIONS);
    let acceptor =
        thread::spawn(move || accept_connections(listener, sender, spawn_thread, thread::sleep));
    let mut capabilities = BTreeMap::new();
    #[cfg(target_os = "linux")]
    let recovery_peer = peer_identity(crate::fsx::euid(), std::process::id())?;
    let mut last_recovery = std::time::Instant::now() - Duration::from_secs(1);
    // A writer that can no longer accept connections cannot serve owners; it
    // exits with the acceptor's error rather than as a clean shutdown.
    while !acceptor.is_finished() {
        if last_recovery.elapsed() >= Duration::from_secs(1) {
            #[cfg(target_os = "linux")]
            store.recover_pending_orphans(&recovery_peer);
            last_recovery = std::time::Instant::now();
        }
        let message = match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(message) => message,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        match message.work {
            Work::Request(request, reply) => {
                let _scope = faults::enter(|| faults::Scope::of_request(&request));
                let response = match dispatch(&mut store, &mut capabilities, request, &message.peer)
                {
                    Ok(value) => Response::Ok { value },
                    Err(error) => Response::Error {
                        message: error.into_message(),
                    },
                };
                if matches!(response, Response::Ok { .. }) {
                    faults::hit(faults::Point::ReplyBeforeSend)?;
                }
                // A dropped reply never rolls back a persisted request or its receipt.
                let _ = reply.try_send(response);
            }
            Work::PlanVerify {
                run_id,
                after,
                limit,
                reply,
            } => {
                let _ =
                    reply.try_send(store.plan_verify(run_id.as_deref(), after.as_deref(), limit));
            }
            Work::GcGeneration(reply) => {
                let _ = reply.try_send(store.gc_generation());
            }
        }
        store.flush_index();
    }
    let problem = acceptor.join().unwrap_or_else(|_| {
        LedgerError::new(
            ErrorKind::Io(std::io::ErrorKind::Other),
            "the connection acceptor panicked",
        )
    });
    let message = format!("ledger writer stopped accepting connections: {problem}");
    Err(problem.with_message(message))
}

fn authorize<'a>(
    tokens: &'a BTreeMap<String, Capability>,
    token: &str,
    run_id: &str,
    role: &str,
    peer: &Peer,
) -> Result<&'a str> {
    let capability = tokens
        .get(token)
        .ok_or_else(|| LedgerError::refused("unknown role capability"))?;
    if capability.run_id != run_id || capability.role != role || capability.peer != *peer {
        return Err(LedgerError::refused(
            "capability role, attempt or peer mismatch",
        ));
    }
    if !peer_alive(peer) {
        return Err(LedgerError::refused(
            "authenticated peer birth identity is no longer live",
        ));
    }
    Ok(&capability.token_id)
}

fn dispatch(
    store: &mut Store,
    tokens: &mut BTreeMap<String, Capability>,
    request: Request,
    peer: &Peer,
) -> Result<Value> {
    match request {
        Request::Append { intent } => {
            Ok(serde_json::to_value(store.append_operator(&intent, peer)?)?)
        }
        Request::Tail { request } => Ok(serde_json::to_value(store.tail(&request)?)?),
        Request::Prepare {
            request_id,
            payload,
        } => Ok(serde_json::to_value(store.prepare(
            &request_id,
            &payload,
            peer,
        )?)?),
        Request::ClaimOwner { run_id } => {
            if !cfg!(target_os = "linux") {
                return Err(LedgerError::refused(
                    "launch ownership currently requires Linux pid birth identities; readers remain available",
                ));
            }
            store.claim_owner(&run_id, peer)?;
            // Only one live pair per owner/run; repeated claims revoke the old pair.
            tokens.retain(|_, token| token.run_id != run_id);
            let owner_token = issue(tokens, &run_id, "owner", peer);
            let producer_token = issue(tokens, &run_id, "producer", peer);
            Ok(serde_json::to_value(ClaimedOwner {
                attempt_id: store.show(&run_id)?.attempt_id,
                owner_token,
                producer_token,
            })?)
        }
        Request::AppendOwner {
            run_id,
            request_id,
            kind,
            effect_id,
            body,
            token,
        } => {
            let token_id = authorize(tokens, &token, &run_id, "owner", peer)?;
            Ok(serde_json::to_value(store.append_owner(
                &run_id,
                &request_id,
                &kind,
                effect_id.as_deref(),
                &body,
                peer,
                token_id,
            )?)?)
        }
        Request::AppendSource {
            run_id,
            event,
            token,
        } => {
            let token_id = authorize(tokens, &token, &run_id, "producer", peer)?;
            Ok(serde_json::to_value(
                store.append_source(&run_id, &event, peer, token_id)?,
            )?)
        }
        Request::Show { run_id } => Ok(serde_json::to_value(store.show(&run_id)?)?),
        Request::ShowWithTranscript { run_id } => store.show_with_transcript(&run_id),
        Request::Catalog { request } => Ok(serde_json::to_value(store.catalog(&request)?)?),
        Request::Discover { request } => Ok(serde_json::to_value(store.discover(&request)?)?),
        // Connections re-read history themselves; see `verify`.
        Request::Verify { .. } => Err(LedgerError::refused(
            "fresh verification is never run on the writer thread",
        )),
        Request::Status => Ok(serde_json::to_value(store.status())?),
        Request::Read { request } => Ok(serde_json::to_value(store.read(&request)?)?),
        Request::Ping => Ok(
            json!({"schema":crate::schemas::DOCTOR,"protocol":PROTOCOL_VERSION,"writer":"available","launch_owner_supported":cfg!(target_os="linux"),"frame_limit_bytes":MAX_FRAME_BYTES,"queue_limit":MAX_CONNECTIONS,"scope":"local","managed_authorization":false,"index":store.index_status(),"retention":{"retain_days":store.retention.resolve(None,None).map_err(LedgerError::refused)?.retain_days,"capture_retain_days":store.retention.resolve(None,None).map_err(LedgerError::refused)?.capture_retain_days}}),
        ),
        Request::ReconcilePending { run_id } => Ok(serde_json::to_value(
            store.reconcile_pending(&run_id, peer, &peer_alive)?,
        )?),
        Request::SettleOrphans => Ok(serde_json::to_value(
            store.settle_orphans(peer, peer_alive)?,
        )?),
        Request::Hold { run_id, request_id } => Ok(serde_json::to_value(store.hold(
            &run_id,
            &request_id,
            peer,
        )?)?),
        Request::Release { run_id, request_id } => Ok(serde_json::to_value(store.release(
            &run_id,
            &request_id,
            peer,
        )?)?),
        Request::Gc {
            dry_run,
            retain_days,
            capture_retain_days,
            after,
            limit,
        } => {
            if !dry_run {
                return Ok(serde_json::to_value(store.gc_policy(
                    retain_days,
                    capture_retain_days,
                    after.as_deref(),
                    limit,
                    peer,
                )?)?);
            }
            Ok(serde_json::to_value(store.gc_plan_policy(
                retain_days,
                capture_retain_days,
                after.as_deref(),
                limit,
            )?)?)
        }
    }
}

fn issue(
    tokens: &mut BTreeMap<String, Capability>,
    run_id: &str,
    role: &'static str,
    peer: &Peer,
) -> String {
    let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    tokens.insert(
        secret.clone(),
        Capability {
            run_id: run_id.into(),
            role,
            peer: peer.clone(),
            token_id: Uuid::new_v4().simple().to_string(),
        },
    );
    secret
}

#[cfg(target_os = "linux")]
pub fn peer_credentials(socket: &UnixStream) -> Result<Peer> {
    let mut credential = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size = std::mem::size_of_val(&credential) as libc::socklen_t;
    // SAFETY: the socket is open for this call, and the output pointer and
    // its length describe the one live ucred the kernel fills.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    peer_identity(credential.uid, credential.pid as u32)
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_identity(uid: u32, pid: u32) -> Result<Peer> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let suffix = stat
        .rsplit_once(')')
        .ok_or_else(|| LedgerError::refused("process stat identity is malformed"))?
        .1;
    let start = suffix
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| LedgerError::refused("process start identity unavailable"))?;
    Ok(Peer {
        uid,
        pid,
        birth: format!("boot:{boot_id}:start:{start}"),
        boot_id,
    })
}

#[cfg(target_os = "macos")]
pub fn peer_credentials(socket: &UnixStream) -> Result<Peer> {
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: the socket is open for this call; both outputs are live locals.
    if unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut pid: libc::pid_t = 0;
    let mut size = std::mem::size_of_val(&pid) as libc::socklen_t;
    // SAFETY: the socket is open for this call, and the output pointer and
    // its length describe the one live pid_t the kernel fills.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Peer {
        uid,
        pid: pid as u32,
        birth: "unavailable".into(),
        boot_id: "unavailable".into(),
    })
}

pub fn peer_alive(peer: &Peer) -> bool {
    #[cfg(target_os = "linux")]
    {
        peer_identity(peer.uid, peer.pid).is_ok_and(|current| current == *peer)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = peer;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::{peer as fixture_peer, request as request_payload};

    /// A writer process kept on a leash: killed when the test ends.
    struct Worker(std::process::Child);
    impl Drop for Worker {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    const SLOW_VERIFY_WORKER: &str = "UKAI_LEDGER_SLOW_VERIFY_WORKER";
    const FRAME_DELAY: Duration = Duration::from_millis(50);

    /// Re-reading one run takes several times the 2 s request timeout here,
    /// yet the writer keeps answering status, ping and appends meanwhile.
    #[test]
    fn a_slow_fresh_verification_never_holds_the_writer_from_other_clients() {
        if let Some(data) = std::env::var_os(SLOW_VERIFY_WORKER) {
            crate::faults::slow_verification(FRAME_DELAY);
            serve(Path::new(&data)).unwrap();
            unreachable!("the writer serves until it is killed");
        }
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let frames = 80;
        let run_id = {
            let mut store = Store::open(&data).unwrap();
            let run = store
                .prepare("slow-verify", &request_payload(), &fixture_peer())
                .unwrap();
            for n in 1..frames {
                store
                    .hold(&run.run_id, &format!("hold-{n}"), &fixture_peer())
                    .unwrap();
            }
            run.run_id
        };
        let log = fs::File::create(temp.path().join("writer.log")).unwrap();
        let _writer = Worker(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "daemon::tests::a_slow_fresh_verification_never_holds_the_writer_from_other_clients",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(SLOW_VERIFY_WORKER, &data)
                .env("UKAI_CONFIG_DIR", temp.path().join("config"))
                .stdin(std::process::Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while Client::connect(&data).is_err() {
            assert!(Instant::now() < deadline, "the writer never became ready");
            thread::sleep(Duration::from_millis(20));
        }
        let verifier = {
            let (data, run_id) = (data.clone(), run_id.clone());
            thread::spawn(move || {
                let started = Instant::now();
                let reports = Client::connect(&data).unwrap().verify(Some(&run_id));
                (started.elapsed(), reports)
            })
        };
        thread::sleep(Duration::from_millis(300));
        let mut client = Client::connect(&data).unwrap();
        for _ in 0..3 {
            // Each call fails on its own 2 s timeout if the writer is held.
            assert_eq!(client.status().unwrap().runs, 1);
            assert_eq!(client.ping().unwrap()["protocol"], PROTOCOL_VERSION);
            thread::sleep(Duration::from_millis(500));
        }
        client.hold(&run_id, "during-verify").unwrap();
        let (elapsed, reports) = verifier.join().unwrap();
        let report = &reports.unwrap()[0];
        assert!(elapsed >= FRAME_DELAY * frames, "{elapsed:?}");
        // The re-read covers what was accepted when the page was planned.
        assert!(report.local_consistency, "{report:?}");
        assert_eq!(report.events, u64::from(frames));
    }

    /// A private data directory with a listening writer socket.
    /// Connects to a writer that refuses the connection at once. The refusal
    /// frame is written and the writer's end closed before the read timeout
    /// may even be set: macOS then refuses the socket option with `EINVAL`,
    /// although the frame is already buffered for the read that follows.
    fn connect_to_a_refusal(data: &Path) -> UnixStream {
        let refused = UnixStream::connect(data.join("ledger/serve.sock")).unwrap();
        if let Err(error) = refused.set_read_timeout(Some(TIMEOUT)) {
            assert!(
                cfg!(target_os = "macos") && error.raw_os_error() == Some(libc::EINVAL),
                "{error}"
            );
        }
        refused
    }

    fn listening(temp: &Path) -> (std::path::PathBuf, UnixListener) {
        let data = temp.join("data");
        crate::fsx::create_dir_all(&data.join("ledger")).unwrap();
        let path = data.join("ledger/serve.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (data, listener)
    }

    /// Answers every forwarded request with `value`, as a stand-in writer.
    fn answer_requests(receiver: mpsc::Receiver<Message>, value: Value) {
        thread::spawn(move || {
            for message in receiver {
                if let Work::Request(_, reply) = message.work {
                    let _ = reply.try_send(Response::Ok {
                        value: value.clone(),
                    });
                }
            }
        });
    }

    #[test]
    fn a_connection_whose_thread_cannot_start_is_refused_and_accepting_continues() {
        static STARTS: AtomicUsize = AtomicUsize::new(0);
        fn first_start_fails(handler: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
            if STARTS.fetch_add(1, Ordering::AcqRel) == 0 {
                return Err(std::io::Error::from_raw_os_error(libc::EAGAIN));
            }
            spawn_thread(handler)
        }
        let temp = tempfile::tempdir().unwrap();
        let (data, listener) = listening(temp.path());
        let (sender, receiver) = mpsc::sync_channel(MAX_CONNECTIONS);
        answer_requests(receiver, json!({"protocol":PROTOCOL_VERSION}));
        thread::spawn(move || {
            accept_connections(listener, sender, first_start_fails, thread::sleep)
        });
        let mut refused = connect_to_a_refusal(&data);
        match read_frame::<Response>(&mut refused).unwrap() {
            Response::Error { message } => assert!(
                message.starts_with("writer_busy: the writer cannot start a connection handler"),
                "{message}"
            ),
            response => panic!("unexpected {response:?}"),
        }
        // The acceptor survived and serves the next connection.
        Client::connect(&data).unwrap();
        assert_eq!(STARTS.load(Ordering::Acquire), 2);
    }

    #[test]
    fn a_fresh_verification_stops_at_its_work_deadline_and_says_so() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let run_id = {
            let mut store = Store::open(&data).unwrap();
            let run = store
                .prepare("deadline", &request_payload(), &fixture_peer())
                .unwrap();
            run.run_id
        };
        let (sender, receiver) = mpsc::sync_channel::<Message>(MAX_CONNECTIONS);
        let writer = thread::spawn(move || {
            let store = Store::open(&data).unwrap();
            for message in receiver {
                match message.work {
                    Work::PlanVerify {
                        run_id,
                        after,
                        limit,
                        reply,
                    } => {
                        let _ = reply.try_send(store.plan_verify(
                            run_id.as_deref(),
                            after.as_deref(),
                            limit,
                        ));
                    }
                    Work::GcGeneration(reply) => {
                        let _ = reply.try_send(store.gc_generation());
                    }
                    Work::Request(..) => {}
                }
            }
        });
        let response = verify(
            &sender,
            &fixture_peer(),
            Some(&run_id),
            None,
            1,
            Duration::ZERO,
        );
        drop(sender);
        writer.join().unwrap();
        let Ok(Response::Ok { value }) = response else {
            panic!("the writer did not plan the page");
        };
        let page: VerifyPage = serde_json::from_value(value).unwrap();
        assert!(!page.reports[0].local_consistency);
        assert_eq!(
            page.reports[0].problems,
            [
                "fresh verification stopped at its time limit after re-reading 0 canonical bytes; \
              the rest of this run was not checked"
            ]
        );
    }

    #[test]
    fn handlers_that_cannot_start_back_off_and_release_their_slots() {
        // More handlers than the connection bound cannot start; later ones can.
        static STARTS: AtomicUsize = AtomicUsize::new(0);
        static WAITS: std::sync::Mutex<Vec<Duration>> = std::sync::Mutex::new(Vec::new());
        fn starts_fail(handler: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
            if STARTS.fetch_add(1, Ordering::AcqRel) <= MAX_CONNECTIONS {
                return Err(std::io::Error::from_raw_os_error(libc::EAGAIN));
            }
            spawn_thread(handler)
        }
        fn record(wait: Duration) {
            WAITS.lock().unwrap().push(wait);
        }
        let temp = tempfile::tempdir().unwrap();
        let (data, listener) = listening(temp.path());
        let (sender, receiver) = mpsc::sync_channel(MAX_CONNECTIONS);
        answer_requests(receiver, json!({"protocol":PROTOCOL_VERSION}));
        thread::spawn(move || accept_connections(listener, sender, starts_fail, record));
        // Each refused connection is accepted successfully first.
        for _ in 0..=MAX_CONNECTIONS {
            let mut refused = connect_to_a_refusal(&data);
            match read_frame::<Response>(&mut refused).unwrap() {
                Response::Error { message } => assert!(
                    message
                        .starts_with("writer_busy: the writer cannot start a connection handler"),
                    "{message}"
                ),
                response => panic!("unexpected {response:?}"),
            }
        }
        // No handler that never started kept its slot.
        Client::connect(&data).unwrap();
        // Repeated failures wait longer each time, up to the bound.
        let waits = WAITS.lock().unwrap().clone();
        assert_eq!(waits.len(), MAX_CONNECTIONS + 1);
        let mut expected = ACCEPT_BACKOFF;
        for wait in waits {
            assert_eq!(wait, expected);
            expected = (expected * 2).min(ACCEPT_BACKOFF_LIMIT);
        }
        assert_eq!(expected, ACCEPT_BACKOFF_LIMIT);
    }

    #[test]
    fn a_writer_of_another_protocol_is_refused_with_its_version_never_restarted() {
        let temp = tempfile::tempdir().unwrap();
        let (data, _) = listening(temp.path());
        fs::remove_file(data.join("ledger/serve.sock")).unwrap();
        // No writer answers: the caller may start one.
        assert!(Client::reachable(&data).unwrap().is_none());
        for (writer, spoken) in [
            (
                json!({"protocol":PROTOCOL_VERSION + 1}),
                format!("protocol {}", PROTOCOL_VERSION + 1),
            ),
            (
                json!({"writer":"available"}),
                "an unversioned protocol".into(),
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let (data, listener) = listening(temp.path());
            let (sender, receiver) = mpsc::sync_channel(MAX_CONNECTIONS);
            answer_requests(receiver, writer);
            thread::spawn(move || {
                accept_connections(listener, sender, spawn_thread, thread::sleep)
            });
            let expected = format!(
                "ledger writer speaks {spoken}, this client speaks protocol {PROTOCOL_VERSION}; \
                 restart the writer once its runs settle"
            );
            assert_eq!(Client::connect(&data).err().unwrap().message(), expected);
            // Reachable but incompatible is a refusal, not an absent writer.
            assert_eq!(Client::reachable(&data).err().unwrap().message(), expected);
        }
        let temp = tempfile::tempdir().unwrap();
        let (data, listener) = listening(temp.path());
        let (sender, receiver) = mpsc::sync_channel(MAX_CONNECTIONS);
        answer_requests(receiver, json!({"protocol":PROTOCOL_VERSION}));
        thread::spawn(move || accept_connections(listener, sender, spawn_thread, thread::sleep));
        assert!(Client::reachable(&data).unwrap().is_some());
    }

    #[test]
    fn forged_producer_role_attempt_and_peer_are_all_refused() {
        let peer = fixture_peer();
        let mut tokens = BTreeMap::new();
        let token = issue(&mut tokens, "run-1", "producer", &peer);
        assert!(authorize(&tokens, "guessed-token", "run-1", "producer", &peer).is_err());
        assert!(authorize(&tokens, &token, "run-2", "producer", &peer).is_err());
        assert!(authorize(&tokens, &token, "run-1", "owner", &peer).is_err());
        let mut stranger = peer.clone();
        stranger.pid += 1;
        assert!(authorize(&tokens, &token, "run-1", "producer", &stranger).is_err());
        stranger = peer.clone();
        stranger.birth = "reused-pid".into();
        assert!(authorize(&tokens, &token, "run-1", "producer", &stranger).is_err());
    }

    #[test]
    fn protocol_refuses_caller_claimed_roles_and_oversized_frames() {
        let forged = br#"{"op":"prepare","request_id":"x","payload":{},"actor":"owner"}"#;
        assert!(serde_json::from_slice::<Request>(forged).is_err());
        for op in ["hold", "release"] {
            let forged = json!({"op":op,"run_id":"run_00000000000000000000000000000000","request_id":"stable","actor":"operator"});
            assert!(serde_json::from_value::<Request>(forged).is_err());
        }
        let forged =
            br#"{"op":"append_source","run_id":"x","event":{},"token":"x","role":"producer"}"#;
        assert!(serde_json::from_slice::<Request>(forged).is_err());
        let bytes = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert!(read_frame::<Value>(&mut bytes.as_slice()).is_err());
        assert!(write_frame(&mut Vec::new(), &json!("x".repeat(MAX_FRAME_BYTES))).is_err());
    }

    #[test]
    fn gc_wire_collects_an_empty_store_without_starting_readers() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let mut tokens = BTreeMap::new();
        let result = dispatch(
            &mut store,
            &mut tokens,
            Request::Gc {
                dry_run: false,
                retain_days: Some(90),
                capture_retain_days: None,
                after: None,
                limit: 25,
            },
            &fixture_peer(),
        )
        .unwrap();
        assert_eq!(result["schema"], "ukai.ledger.gc-result/1");
        assert_eq!(result["pruned"], json!([]));
        assert!(store.runs().is_empty());
        assert!(!store.root().join("readers").exists());
    }

    #[test]
    fn frame_roundtrip_handles_interrupted_transport_without_accepting_partial_json() {
        let request = Request::Prepare {
            request_id: "stable".into(),
            payload: json!({"profile":"none"}),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).unwrap();
        assert!(
            matches!(read_frame::<Request>(&mut bytes.as_slice()).unwrap(),Request::Prepare { request_id,.. } if request_id == "stable")
        );
        for boundary in [0, 1, 3, 4, bytes.len() - 1] {
            assert!(read_frame::<Request>(&mut &bytes[..boundary]).is_err());
        }
    }
}
