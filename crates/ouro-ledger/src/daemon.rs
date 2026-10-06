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
    time::Duration,
};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    protocol::{
        AppendReceipt, CatalogPage, CatalogRequest, ClaimedOwner, DiscoveryPage, DiscoveryRequest,
        GcPlan, GcResult, LedgerError, MAX_CONNECTIONS, MAX_FRAME_BYTES, OperatorIntent, Peer,
        ReadPage, ReadRequest, Request, Response, Result, RunRecord, TailPage, TailRequest,
        VerifyReport,
    },
    store::Store,
};

const TIMEOUT: Duration = Duration::from_secs(2);
const GC_TIMEOUT: Duration = Duration::from_secs(300);

fn response_timeout(request: &Request) -> Duration {
    if matches!(request, Request::Gc { dry_run: false, .. }) {
        GC_TIMEOUT
    } else {
        TIMEOUT
    }
}

pub struct Client {
    stream: UnixStream,
}

impl Client {
    pub fn connect(data: &Path) -> Result<Self> {
        let path = data.join("ledger/serve.sock");
        let meta = fs::symlink_metadata(&path)?;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(LedgerError("daemon socket is not owned and private".into()));
        }
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let server = peer_credentials(&stream)?;
        if server.uid != unsafe { libc::geteuid() } {
            return Err(LedgerError(
                "daemon peer uid is not the current user".into(),
            ));
        }
        Ok(Self { stream })
    }

    fn request<T: DeserializeOwned>(&mut self, request: Request) -> Result<T> {
        write_frame(&mut self.stream, &request)?;
        self.stream
            .set_read_timeout(Some(response_timeout(&request)))?;
        let response = read_frame::<Response>(&mut self.stream);
        self.stream.set_read_timeout(Some(TIMEOUT))?;
        match response? {
            Response::Ok { value } => Ok(serde_json::from_value(value)?),
            Response::Error { message } => Err(LedgerError(message)),
        }
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
    pub fn runs(&mut self) -> Result<Vec<RunRecord>> {
        self.request(Request::Runs)
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
    pub fn verify(&mut self, run_id: Option<&str>) -> Result<Vec<VerifyReport>> {
        self.request(Request::Verify {
            run_id: run_id.map(str::to_owned),
        })
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
    pub fn gc_plan(&mut self, retain_days: u32, after: Option<&str>, limit: u32) -> Result<GcPlan> {
        self.request(Request::Gc {
            dry_run: true,
            retain_days: Some(retain_days),
            capture_retain_days: None,
            after: after.map(str::to_owned),
            limit,
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
    pub fn gc(&mut self, retain_days: u32, after: Option<&str>, limit: u32) -> Result<GcResult> {
        self.request(Request::Gc {
            dry_run: false,
            retain_days: Some(retain_days),
            capture_retain_days: None,
            after: after.map(str::to_owned),
            limit,
        })
    }
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(LedgerError(
            "socket frame exceeds its 1048576-byte limit".into(),
        ));
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    let mut size = [0; 4];
    reader.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(LedgerError(
            "socket frame exceeds its 1048576-byte limit".into(),
        ));
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[derive(Clone)]
struct Capability {
    run_id: String,
    role: &'static str,
    peer: Peer,
    token_id: String,
}

struct Message {
    request: Request,
    peer: Peer,
    reply: mpsc::SyncSender<Response>,
}

pub fn serve(data: &Path) -> Result<()> {
    let retention = crate::config::load()?;
    let mut store = Store::open(data)?;
    store.retention = retention;
    let path = store.root().join("serve.sock");
    if let Ok(meta) = fs::symlink_metadata(&path) {
        use std::os::unix::fs::FileTypeExt as _;
        if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
            return Err(LedgerError("refusing unsafe existing daemon socket".into()));
        }
        fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    fs::File::open(store.root())?.sync_all()?;
    let (sender, receiver) = mpsc::sync_channel::<Message>(MAX_CONNECTIONS);
    let count = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for accepted in listener.incoming() {
            let Ok(mut socket) = accepted else {
                break;
            };
            let Ok(peer) = peer_credentials(&socket) else {
                continue;
            };
            if peer.uid != unsafe { libc::geteuid() } {
                continue;
            }
            if count.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                count.fetch_sub(1, Ordering::AcqRel);
                continue;
            }
            let sender = sender.clone();
            let count = count.clone();
            thread::spawn(move || {
                let _ = socket.set_read_timeout(Some(TIMEOUT));
                let _ = socket.set_write_timeout(Some(TIMEOUT));
                while let Ok(request) = read_frame::<Request>(&mut socket) {
                    let timeout = response_timeout(&request);
                    let (reply, response) = mpsc::sync_channel(1);
                    let message = Message {
                        request,
                        peer: peer.clone(),
                        reply,
                    };
                    if sender.try_send(message).is_err() {
                        let _ = write_frame(
                            &mut socket,
                            &Response::Error {
                                message: "bounded daemon queue is full".into(),
                            },
                        );
                        break;
                    }
                    let Ok(value) = response.recv_timeout(timeout) else {
                        break;
                    };
                    if write_frame(&mut socket, &value).is_err() {
                        break;
                    }
                }
                count.fetch_sub(1, Ordering::AcqRel);
            });
        }
    });
    let mut capabilities = BTreeMap::new();
    while let Ok(message) = receiver.recv() {
        let result = dispatch(
            &mut store,
            &mut capabilities,
            message.request,
            &message.peer,
        );
        let response = match result {
            Ok(value) => Response::Ok { value },
            Err(error) => Response::Error { message: error.0 },
        };
        // A dropped reply never rolls back a persisted request or its receipt.
        let _ = message.reply.try_send(response);
        store.flush_index();
    }
    Ok(())
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
        .ok_or_else(|| LedgerError("unknown role capability".into()))?;
    if capability.run_id != run_id || capability.role != role || capability.peer != *peer {
        return Err(LedgerError(
            "capability role, attempt or peer mismatch".into(),
        ));
    }
    if !peer_alive(peer) {
        return Err(LedgerError(
            "authenticated peer birth identity is no longer live".into(),
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
                return Err(LedgerError("launch ownership currently requires Linux pid birth identities; readers remain available".into()));
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
        Request::Runs => Ok(serde_json::to_value(store.legacy_runs()?)?),
        Request::Catalog { request } => Ok(serde_json::to_value(store.catalog(&request)?)?),
        Request::Discover { request } => Ok(serde_json::to_value(store.discover(&request)?)?),
        Request::Verify { run_id } => Ok(serde_json::to_value(store.verify(run_id.as_deref())?)?),
        Request::Read { request } => Ok(serde_json::to_value(store.read(&request)?)?),
        Request::Ping => Ok(
            json!({"schema":"ouro.ledger.doctor/1","writer":"available","launch_owner_supported":cfg!(target_os="linux"),"frame_limit_bytes":MAX_FRAME_BYTES,"queue_limit":MAX_CONNECTIONS,"scope":"local","managed_authorization":false,"index":store.index_status(),"retention":{"retain_days":store.retention.resolve(None,None).map_err(|e|LedgerError(e.into()))?.retain_days,"capture_retain_days":store.retention.resolve(None,None).map_err(|e|LedgerError(e.into()))?.capture_retain_days}}),
        ),
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
fn peer_identity(uid: u32, pid: u32) -> Result<Peer> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let suffix = stat
        .rsplit_once(')')
        .ok_or_else(|| LedgerError("process stat identity is malformed".into()))?
        .1;
    let start = suffix
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| LedgerError("process start identity unavailable".into()))?;
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
    if unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut pid: libc::pid_t = 0;
    let mut size = std::mem::size_of_val(&pid) as libc::socklen_t;
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

    fn fixture_peer() -> Peer {
        Peer {
            uid: unsafe { libc::geteuid() },
            pid: std::process::id(),
            birth: "fixture".into(),
            boot_id: "fixture".into(),
        }
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
        assert_eq!(result["schema"], "ouro.ledger.gc-result/1");
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
