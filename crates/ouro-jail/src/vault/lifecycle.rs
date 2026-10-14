//! Supervisor-owned live sources and bounded OAuth2 refresh. Never retries an
//! uncertain rotating grant: a persisted pending marker requires reauthorization.
use super::Secret;
use crate::{
    credentials::{read_vault_source, read_vault_source_version, update_vault_source},
    proxy::Reason,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEncoding {
    #[default]
    Form,
    Json,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshPolicy {
    pub token_url: String,
    pub client_id: String,
    #[serde(default = "default_margin")]
    pub refresh_before_seconds: u64,
    #[serde(default)]
    pub encoding: TokenEncoding,
}
fn default_margin() -> u64 {
    300
}
impl RefreshPolicy {
    pub(super) fn validate(&self, allow_plaintext: bool) -> Result<(), String> {
        let (scheme, rest) = self
            .token_url
            .split_once("://")
            .ok_or("refresh URL needs HTTPS")?;
        let (authority, path) = rest
            .split_once('/')
            .ok_or("refresh URL needs an explicit path")?;
        super::origin(&format!("{scheme}://{authority}"))?;
        if scheme != "https" && !(scheme == "http" && allow_plaintext) {
            return Err("refresh requires HTTPS; fixtures need plaintext opt-in".into());
        }
        super::validate_path(&format!("/{path}"))?;
        if self.client_id.trim().is_empty()
            || self.client_id.len() > 512
            || !self.client_id.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || self.refresh_before_seconds > 3600
        {
            return Err("invalid refresh client or margin".into());
        }
        Ok(())
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(transparent)]
struct SecretText(String);
impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    access_token: SecretText,
    refresh_token: SecretText,
    expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id_token: Option<SecretText>,
    #[serde(default)]
    revoked: bool,
    #[serde(default)]
    refresh_pending: bool,
}
#[derive(Deserialize)]
struct Response {
    access_token: SecretText,
    #[serde(default)]
    refresh_token: Option<SecretText>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    id_token: Option<SecretText>,
}
fn valid(value: &[u8]) -> bool {
    !value.is_empty() && value.len() <= 8192 && value.iter().all(|b| matches!(b, 0x20..=0x7e))
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn encode(doc: &Document) -> Result<Zeroizing<Vec<u8>>, Reason> {
    serde_json::to_vec(doc)
        .map(Zeroizing::new)
        .map_err(|_| Reason::CredentialUnavailable)
}
pub(crate) type Audit = Arc<dyn Fn(&str, u64, &'static str) -> bool + Send + Sync>;
type SourceLocation = (Vec<u8>, Vec<(u64, u64)>);
struct Pending {
    bytes: Zeroizing<Vec<u8>>,
    epoch: crate::state::anchored::Stat,
    expires_at: u64,
}
struct State {
    value: Zeroizing<Vec<u8>>,
    generation: u64,
    denied: bool,
    epoch: Option<crate::state::anchored::Stat>,
    pending: Option<Pending>,
}
pub(super) struct Runtime {
    source: Option<SourceLocation>,
    refresh: Option<RefreshPolicy>,
    state: Mutex<State>,
    exchange: Mutex<()>,
    audit: Mutex<Option<(String, Audit)>>,
    early_notes: Mutex<Vec<(u64, &'static str)>>,
    last_error: Mutex<Option<&'static str>>,
}
impl Runtime {
    pub(super) fn static_value(value: Zeroizing<Vec<u8>>) -> Self {
        Self {
            source: None,
            refresh: None,
            state: Mutex::new(State {
                value,
                generation: 1,
                denied: false,
                epoch: None,
                pending: None,
            }),
            exchange: Mutex::new(()),
            audit: Mutex::new(None),
            early_notes: Mutex::new(Vec::new()),
            last_error: Mutex::new(None),
        }
    }
    pub(super) fn source(
        path: Vec<u8>,
        forbidden: Vec<(u64, u64)>,
        refresh: Option<RefreshPolicy>,
    ) -> Result<Self, String> {
        let result = Self {
            source: Some((path, forbidden)),
            refresh,
            ..Self::static_value(Zeroizing::new(Vec::new()))
        };
        result.current().map_err(|_| {
            format!(
                "vault source unavailable, invalid, revoked or refresh failed ({})",
                result
                    .last_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .unwrap_or("source_refused")
            )
        })?;
        Ok(result)
    }
    fn emit(&self, generation: u64, transition: &'static str) -> bool {
        let audit = self.audit.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((id, audit)) = audit.as_ref() {
            audit(id, generation, transition)
        } else {
            let mut notes = self.early_notes.lock().unwrap_or_else(|e| e.into_inner());
            if notes.len() >= 8 {
                return false;
            }
            notes.push((generation, transition));
            true
        }
    }
    fn deny(&self, reason: Reason) -> Reason {
        self.deny_if(reason, None)
    }
    fn deny_if(&self, reason: Reason, generation: Option<u64>) -> Reason {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if generation.is_some_and(|generation| generation != state.generation) {
            return reason;
        }
        if !state.denied {
            state.pending = None;
            state.value.zeroize();
            state.value.clear();
            state.generation = state.generation.saturating_add(1);
            state.denied = true;
            let _ = self.emit(state.generation, "revoked");
        }
        reason
    }
    pub(super) fn current(&self) -> Result<(Zeroizing<Vec<u8>>, u64), Reason> {
        let Some((path, forbidden)) = &self.source else {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            return Ok((state.value.clone(), state.generation));
        };
        let (raw, mut epoch) = read_vault_source_version(path, forbidden, 65536)
            .map_err(|_| self.deny(Reason::CredentialRevoked))?;
        let value = if let Some(policy) = &self.refresh {
            let doc: Document =
                serde_json::from_slice(&raw).map_err(|_| self.deny(Reason::CredentialRevoked))?;
            if doc.revoked
                || !valid(doc.access_token.0.as_bytes())
                || !valid(doc.refresh_token.0.as_bytes())
            {
                return Err(self.deny(Reason::CredentialRevoked));
            }
            if doc.refresh_pending {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if !state.denied
                    && state.pending.as_ref().is_some_and(|p| {
                        p.expires_at > now()
                            && p.bytes.as_slice() == raw.as_slice()
                            && p.epoch.unchanged_since(&epoch)
                    })
                {
                    return Ok((state.value.clone(), state.generation));
                }
                drop(state);
                return Err(self.deny(Reason::CredentialRevoked));
            }
            if doc.expires_at <= now().saturating_add(policy.refresh_before_seconds) {
                // Only one local exchange. Other attempts contend through the
                // source CAS + flock and observe the persisted pending marker.
                let _guard = self.exchange.lock().unwrap_or_else(|e| e.into_inner());
                let fresh = read_vault_source(path, forbidden, 65536)
                    .map_err(|_| self.deny(Reason::CredentialRevoked))?;
                if fresh.as_slice() != raw.as_slice() {
                    return Err(Reason::CredentialUnavailable);
                }
                let value = self.exchange_token(policy, path, forbidden, raw, epoch, doc)?;
                let (_, current) = read_vault_source_version(path, forbidden, 65536)
                    .map_err(|_| self.deny(Reason::CredentialRevoked))?;
                epoch = current;
                value
            } else {
                Zeroizing::new(doc.access_token.0.as_bytes().to_vec())
            }
        } else {
            if !valid(&raw) {
                return Err(self.deny(Reason::CredentialRevoked));
            }
            raw
        };
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.denied
            || state.value.as_slice() != value.as_slice()
            || state.epoch.is_some_and(|old| !old.unchanged_since(&epoch))
        {
            state.generation = state.generation.saturating_add(1);
            if !self.emit(state.generation, "loaded") {
                return Err(Reason::CredentialUnavailable);
            }
            state.value = value;
            state.denied = false;
        }
        state.epoch = Some(epoch);
        Ok((state.value.clone(), state.generation))
    }
    fn exchange_token(
        &self,
        policy: &RefreshPolicy,
        path: &[u8],
        forbidden: &[(u64, u64)],
        raw: Zeroizing<Vec<u8>>,
        source_epoch: crate::state::anchored::Stat,
        mut doc: Document,
    ) -> Result<Zeroizing<Vec<u8>>, Reason> {
        let identity = source_epoch.identity();
        let preserve = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            !state.denied
                && doc.expires_at > now()
                && state.value.as_slice() == doc.access_token.0.as_bytes()
                && state
                    .epoch
                    .is_some_and(|epoch| epoch.unchanged_since(&source_epoch))
        };
        if !preserve {
            self.deny(Reason::CredentialUnavailable);
        }
        doc.refresh_pending = true;
        let pending = encode(&doc)?;
        update_vault_source(path, forbidden, &raw, identity, &pending)
            .map_err(|_| self.deny(Reason::CredentialUnavailable))?;
        let (confirmed, pending_epoch) = read_vault_source_version(path, forbidden, 65536)
            .map_err(|_| self.deny(Reason::CredentialRevoked))?;
        if confirmed.as_slice() != pending.as_slice() || pending_epoch.identity() != identity {
            return Err(self.deny(Reason::CredentialRevoked));
        }
        let generation = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.pending = preserve.then(|| Pending {
                bytes: pending.clone(),
                epoch: pending_epoch,
                expires_at: doc.expires_at,
            });
            state.generation
        };
        if !self.emit(generation, "refresh_started") {
            return Err(self.deny(Reason::CredentialUnavailable));
        }
        let result = (|| {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .proxy(None)
                .max_redirects(0)
                .http_status_as_error(false)
                .max_idle_connections(0)
                .timeout_global(Some(Duration::from_secs(8)))
                .max_response_header_size(16384)
                .build()
                .into();
            *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some("issuer_transport");
            let (content_type, body) = grant_body(policy, &doc.refresh_token.0)?;
            let mut response = agent
                .post(&policy.token_url)
                .header("Content-Type", content_type)
                .send(body.as_slice())
                .map_err(|_| Reason::CredentialUnavailable)?;
            if response.status().as_u16() != 200 {
                let reason = match response.status().as_u16() {
                    400 => "issuer_http_400",
                    401 => "issuer_http_401",
                    403 => "issuer_http_403",
                    429 => "issuer_http_429",
                    500..=599 => "issuer_http_5xx",
                    300..=399 => "issuer_redirect_refused",
                    _ => "issuer_http_refused",
                };
                *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason);
                return Err(Reason::CredentialUnavailable);
            }
            *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) =
                Some("issuer_invalid_response");
            let mut bytes = Zeroizing::new(Vec::new());
            response
                .body_mut()
                .as_reader()
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(|_| Reason::CredentialUnavailable)?;
            if bytes.len() > 65536 {
                return Err(Reason::CredentialUnavailable);
            }
            let response: Response =
                serde_json::from_slice(&bytes).map_err(|_| Reason::CredentialUnavailable)?;
            if !valid(response.access_token.0.as_bytes())
                || response
                    .token_type
                    .as_ref()
                    .is_some_and(|t| !t.eq_ignore_ascii_case("bearer"))
            {
                return Err(Reason::CredentialUnavailable);
            }
            let expiry = expiry(&response)?;
            doc.access_token = response.access_token;
            if response.id_token.is_some() {
                doc.id_token = response.id_token;
            }
            if let Some(token) = response.refresh_token {
                if !valid(token.0.as_bytes()) {
                    return Err(Reason::CredentialUnavailable);
                }
                doc.refresh_token = token;
            }
            doc.expires_at = expiry;
            doc.refresh_pending = false;
            let replacement = encode(&doc)?;
            update_vault_source(path, forbidden, &pending, identity, &replacement)
                .map_err(|_| Reason::CredentialRevoked)?;
            // Deletion/replacement during exchange or commit never releases a token.
            let check =
                read_vault_source(path, forbidden, 65536).map_err(|_| Reason::CredentialRevoked)?;
            if check.as_slice() != replacement.as_slice() {
                return Err(Reason::CredentialRevoked);
            }
            let generation = self
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .generation;
            if !self.emit(generation, "refreshed") {
                return Err(Reason::CredentialUnavailable);
            }
            *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
            Ok(Zeroizing::new(doc.access_token.0.as_bytes().to_vec()))
        })();
        self.state.lock().unwrap_or_else(|e| e.into_inner()).pending = None;
        if result.is_err() {
            self.deny(Reason::CredentialUnavailable);
            let generation = self
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .generation;
            let _ = self.emit(generation, "refresh_failed");
        }
        result
    }
    fn live(&self, generation: u64) -> bool {
        // Never start a network exchange from a stream's revocation check.
        if let Some((path, forbidden)) = &self.source {
            let Ok((raw, epoch)) = read_vault_source_version(path, forbidden, 65536) else {
                self.deny_if(Reason::CredentialRevoked, Some(generation));
                return false;
            };
            let value = if self.refresh.is_some() {
                let Ok(doc) = serde_json::from_slice::<Document>(&raw) else {
                    self.deny_if(Reason::CredentialRevoked, Some(generation));
                    return false;
                };
                if doc.refresh_pending && !doc.revoked && doc.expires_at > now() {
                    let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    let permitted = !state.denied
                        && state.generation == generation
                        && state.pending.as_ref().is_some_and(|p| {
                            p.expires_at > now()
                                && p.bytes.as_slice() == raw.as_slice()
                                && p.epoch.unchanged_since(&epoch)
                        });
                    drop(state);
                    if !permitted {
                        self.deny_if(Reason::CredentialRevoked, Some(generation));
                    }
                    return permitted;
                }
                if doc.revoked || doc.refresh_pending || doc.expires_at <= now() {
                    self.deny_if(Reason::CredentialRevoked, Some(generation));
                    return false;
                }
                Zeroizing::new(doc.access_token.0.as_bytes().to_vec())
            } else {
                raw
            };
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let permitted = !state.denied
                && state.generation == generation
                && state.epoch.is_some_and(|old| old.unchanged_since(&epoch))
                && state.value.as_slice() == value.as_slice();
            drop(state);
            if !permitted {
                self.deny_if(Reason::CredentialRevoked, Some(generation));
            }
            return permitted;
        }
        true
    }
}
fn grant_body(
    policy: &RefreshPolicy,
    refresh: &str,
) -> Result<(&'static str, Zeroizing<Vec<u8>>), Reason> {
    match policy.encoding {
        TokenEncoding::Form => {
            let mut body = Zeroizing::new(String::from("grant_type=refresh_token&client_id="));
            form(&mut body, &policy.client_id);
            body.push_str("&refresh_token=");
            form(&mut body, refresh);
            Ok((
                "application/x-www-form-urlencoded",
                Zeroizing::new(body.as_bytes().to_vec()),
            ))
        }
        TokenEncoding::Json => {
            #[derive(Serialize)]
            struct Grant<'a> {
                grant_type: &'static str,
                client_id: &'a str,
                refresh_token: &'a str,
            }
            serde_json::to_vec(&Grant {
                grant_type: "refresh_token",
                client_id: &policy.client_id,
                refresh_token: refresh,
            })
            .map(|body| ("application/json", Zeroizing::new(body)))
            .map_err(|_| Reason::CredentialUnavailable)
        }
    }
}
fn expiry(response: &Response) -> Result<u64, Reason> {
    use base64::Engine as _;
    let now = now();
    let ttl = match response.expires_in {
        Some(ttl) if ttl > 0 && ttl <= 31_536_000 => Some(now.saturating_add(ttl)),
        Some(_) => return Err(Reason::CredentialUnavailable),
        None => None,
    };
    let jwt = (|| {
        let mut parts = response.access_token.0.split('.');
        let _header = parts.next()?;
        let claims = parts.next()?;
        let _signature = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let decoded = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(claims)
                .ok()?,
        );
        #[derive(Deserialize)]
        struct Claims {
            exp: u64,
        }
        serde_json::from_slice::<Claims>(&decoded)
            .ok()
            .map(|c| c.exp)
    })();
    let expiry = match (ttl, jwt) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => return Err(Reason::CredentialUnavailable),
    };
    if expiry <= now || expiry > now.saturating_add(31_536_000) {
        return Err(Reason::CredentialUnavailable);
    }
    Ok(expiry)
}

fn form(out: &mut String, value: &str) {
    use std::fmt::Write;
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}
#[derive(Default)]
pub struct Lease {
    entries: Vec<(Arc<Secret>, u64)>,
    /// The connection's initiator, which every process-bound entry needs.
    initiator: super::origin::Initiator,
}
impl Lease {
    pub(super) fn add(&mut self, secret: Arc<Secret>, generation: u64) {
        self.entries.push((secret, generation));
    }
    /// Adds the entries of a lease bound to the same connection.
    pub(crate) fn extend(&mut self, other: Self) {
        self.entries.extend(other.entries);
        self.initiator = other.initiator;
    }
    pub(crate) fn bind(&mut self, initiator: &super::origin::Initiator) {
        self.initiator = initiator.clone();
    }
    pub(crate) fn check(&self) -> Result<(), Reason> {
        for (secret, generation) in &self.entries {
            if !secret.runtime.live(*generation) {
                return Err(Reason::CredentialRevoked);
            }
            if !secret.policy.binaries.is_empty() {
                self.initiator.check(&secret.executables)?;
            }
        }
        Ok(())
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) struct Monitor {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    secrets: Vec<Arc<Secret>>,
}
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Monitor {
    pub(super) fn new(secrets: Vec<Arc<Secret>>) -> Self {
        Self {
            stop: Arc::new((Mutex::new(false), Condvar::new())),
            thread: Mutex::new(None),
            secrets,
        }
    }
    pub(super) fn start(&self, audit: Audit) -> Result<(), String> {
        for secret in &self.secrets {
            *secret
                .runtime
                .audit
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some((secret.id.clone(), audit.clone()));
            let notes = std::mem::take(
                &mut *secret
                    .runtime
                    .early_notes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
            );
            let had_notes = !notes.is_empty();
            for (generation, transition) in notes {
                if !secret.runtime.emit(generation, transition) {
                    return Err("vault lifecycle trace unavailable".into());
                }
            }
            let generation = secret
                .runtime
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .generation;
            if !had_notes && !secret.runtime.emit(generation, "loaded") {
                return Err("vault lifecycle trace unavailable".into());
            }
        }
        if !self.secrets.iter().any(|s| s.runtime.refresh.is_some()) {
            return Ok(());
        }
        let stop = self.stop.clone();
        let secrets = self.secrets.clone();
        let handle = std::thread::Builder::new()
            .name("vault-refresh".into())
            .spawn(move || {
                loop {
                    let lock = stop.0.lock().unwrap_or_else(|e| e.into_inner());
                    if *lock {
                        break;
                    }
                    let (lock, _) = stop
                        .1
                        .wait_timeout(lock, Duration::from_millis(100))
                        .unwrap_or_else(|e| e.into_inner());
                    if *lock {
                        break;
                    }
                    drop(lock);
                    for secret in &secrets {
                        if *stop.0.lock().unwrap_or_else(|e| e.into_inner()) {
                            break;
                        }
                        if secret.runtime.refresh.is_some() {
                            let _ = secret.runtime.current();
                        }
                    }
                }
            })
            .map_err(|_| "vault refresh worker unavailable".to_owned())?;
        *self.thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        Ok(())
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        *self.stop.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.stop.1.notify_all();
        if let Some(handle) = self
            .thread
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = handle.join();
        }
    }
}

/// Interrupt even blocked response headers/uploads when the source is revoked.
/// Reuses the admitted socket Arcs; no additional descriptors or secret copies.
pub(crate) struct Watch {
    stop: Arc<(Mutex<bool>, Condvar)>,
    revoked: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Watch {
    pub(crate) fn start(
        lease: Arc<Lease>,
        client: Arc<std::os::unix::net::UnixStream>,
        upstream: Arc<std::net::TcpStream>,
    ) -> Result<Self, Reason> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = if lease.is_empty() {
            None
        } else {
            let stopped = stop.clone();
            let failed = revoked.clone();
            Some(
                std::thread::Builder::new()
                    .name("vault-lease".into())
                    .stack_size(96 * 1024)
                    .spawn(move || {
                        loop {
                            if lease.check().is_err() {
                                failed.store(true, std::sync::atomic::Ordering::SeqCst);
                                let _ = client.shutdown(std::net::Shutdown::Both);
                                let _ = upstream.shutdown(std::net::Shutdown::Both);
                                break;
                            }
                            let lock = stopped.0.lock().unwrap_or_else(|e| e.into_inner());
                            if *lock {
                                break;
                            }
                            let (lock, _) = stopped
                                .1
                                .wait_timeout(lock, Duration::from_millis(100))
                                .unwrap_or_else(|e| e.into_inner());
                            if *lock {
                                break;
                            }
                        }
                    })
                    .map_err(|_| Reason::ResourceExhausted)?,
            )
        };
        Ok(Self {
            stop,
            revoked,
            thread,
        })
    }
    pub(crate) fn revoked(&self) -> bool {
        self.revoked.load(std::sync::atomic::Ordering::SeqCst)
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        *self.stop.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.stop.1.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialLease")
            .field("count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    };
    #[cfg(target_os = "linux")]
    use std::{io::Write, net::TcpListener};
    fn file(bytes: &[u8]) -> (tempfile::TempDir, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("token");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (dir, path.as_os_str().as_bytes().to_vec())
    }
    #[cfg(target_os = "linux")]
    fn doc(expiry: u64) -> Vec<u8> {
        format!(
            r#"{{"access_token":"old-access","refresh_token":"old-refresh","expires_at":{expiry}}}"#
        )
        .into_bytes()
    }
    #[cfg(target_os = "linux")]
    fn issuer(status: u16, response: &'static str) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                socket.read_exact(&mut b).unwrap();
                head.push(b[0]);
            }
            let length = String::from_utf8_lossy(&head)
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|n| n.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            write!(socket,"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).unwrap();
            body
        });
        (url, handle)
    }
    #[cfg(target_os = "linux")]
    const SUCCESS: &str = r#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"token_type":"Bearer"}"#;
    #[test]
    fn live_source_rotation_deletion_and_private_modes_fail_closed() {
        let (_dir, path) = file(b"first");
        let runtime = Runtime::source(path.clone(), vec![], None).unwrap();
        let (_, generation) = runtime.current().unwrap();
        assert!(runtime.live(generation));
        fs::write(std::ffi::OsStr::from_bytes(&path), b"second").unwrap();
        assert!(!runtime.live(generation));
        assert_eq!(&*runtime.current().unwrap().0, b"second");
        fs::set_permissions(
            std::ffi::OsStr::from_bytes(&path),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(runtime.current().is_err());
        fs::remove_file(std::ffi::OsStr::from_bytes(&path)).unwrap();
        assert!(runtime.current().is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn refresh_persists_rotated_token_before_publication_and_idle_worker_refreshes() {
        let (url, issuer) = issuer(200, SUCCESS);
        let (_dir, path) = file(&doc(now() + 100));
        let policy = super::super::Policy {
            hosts: vec!["https://fixture.test".into()],
            allow_plaintext: true,
            refresh: Some(RefreshPolicy {
                token_url: url,
                client_id: "test client".into(),
                refresh_before_seconds: 0,
                encoding: TokenEncoding::Form,
            }),
            ..Default::default()
        };
        let secret =
            Arc::new(Secret::from_source("api".into(), policy, path.clone(), vec![]).unwrap());
        let monitor = Monitor::new(vec![secret.clone()]);
        let notes = Arc::new(Mutex::new(Vec::new()));
        let recorded = notes.clone();
        monitor
            .start(Arc::new(move |_, _, transition| {
                recorded.lock().unwrap().push(transition);
                true
            }))
            .unwrap();
        fs::write(std::ffi::OsStr::from_bytes(&path), doc(now())).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let raw = fs::read(std::ffi::OsStr::from_bytes(&path)).unwrap();
            // File commit precedes the mandatory audit callback. Observing
            // the replacement bytes alone is not completion of the worker;
            // wait for both facts without relaxing the deadline or assertions.
            if raw.windows(11).any(|v| v == b"new-refresh")
                && notes.lock().unwrap().contains(&"refreshed")
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(&*secret.runtime.current().unwrap().0, b"new-access");
        let body = issuer.join().unwrap();
        assert_eq!(
            body,
            b"grant_type=refresh_token&client_id=test%20client&refresh_token=old-refresh"
        );
        assert!(notes.lock().unwrap().contains(&"refreshed"));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn failed_rotating_exchange_stays_pending_and_never_retries() {
        let (url, issuer) = issuer(400, "{\"error\":\"invalid_grant\"}");
        let (_dir, path) = file(&doc(now()));
        let runtime = Runtime {
            source: Some((path.clone(), vec![])),
            refresh: Some(RefreshPolicy {
                token_url: url,
                client_id: "test".into(),
                refresh_before_seconds: 0,
                encoding: TokenEncoding::Form,
            }),
            ..Runtime::static_value(Zeroizing::new(Vec::new()))
        };
        assert!(runtime.current().is_err());
        issuer.join().unwrap();
        let raw = fs::read(std::ffi::OsStr::from_bytes(&path)).unwrap();
        assert!(
            serde_json::from_slice::<Document>(&raw)
                .unwrap()
                .refresh_pending
        );
        assert!(runtime.current().is_err());
    }
    #[test]
    fn refresh_authority_rejects_redirect_shapes_and_plaintext_without_opt_in() {
        for url in [
            "http://fixture.test/token",
            "https://fixture.test/token?redirect=evil",
            "https://fixture.test/../token",
            "https://user@fixture.test/token",
            "https://fixture.test/%2ftoken",
        ] {
            assert!(
                RefreshPolicy {
                    token_url: url.into(),
                    client_id: "test".into(),
                    refresh_before_seconds: 0,
                    encoding: TokenEncoding::Form,
                }
                .validate(false)
                .is_err()
            );
        }
        assert!(
            RefreshPolicy {
                token_url: "https://issuer.fixture.test/oauth/token".into(),
                client_id: "test".into(),
                refresh_before_seconds: 300,
                encoding: TokenEncoding::Form,
            }
            .validate(false)
            .is_ok()
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod handoff_tests {
    use super::*;
    use std::{
        io::Write,
        net::TcpListener,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        sync::mpsc,
    };
    #[test]
    fn proactive_refresh_preserves_valid_old_lease_until_commit_and_stale_lease_cannot_revoke_new_token()
     {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("token");
        let expiry = now() + 4;
        std::fs::write(&path,format!(r#"{{"access_token":"old-access","refresh_token":"old-refresh","expires_at":{expiry}}}"#)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let (ready, received) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let issuer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                socket.read_exact(&mut b).unwrap();
                head.push(b[0]);
            }
            let len = String::from_utf8_lossy(&head)
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let mut body = vec![0; len];
            socket.read_exact(&mut body).unwrap();
            ready.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            let body =
                r#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}"#;
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let policy = super::super::Policy {
            hosts: vec!["https://fixture.test".into()],
            allow_plaintext: true,
            refresh: Some(RefreshPolicy {
                token_url: url,
                client_id: "test".into(),
                refresh_before_seconds: 2,
                encoding: TokenEncoding::Form,
            }),
            ..Default::default()
        };
        let secret = Arc::new(
            Secret::from_source(
                "api".into(),
                policy,
                path.as_os_str().as_bytes().to_vec(),
                vec![],
            )
            .unwrap(),
        );
        let (_, old) = secret.runtime.current().unwrap();
        let monitor = Monitor::new(vec![secret.clone()]);
        monitor.start(Arc::new(|_, _, _| true)).unwrap();
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(secret.runtime.live(old));
        assert_eq!(&*secret.runtime.current().unwrap().0, b"old-access");
        release.send(()).unwrap();
        issuer.join().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let new = loop {
            if let Ok((value, generation)) = secret.runtime.current()
                && value.as_slice() == b"new-access"
            {
                break generation;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_ne!(old, new);
        assert!(!secret.runtime.live(old));
        assert!(secret.runtime.live(new));
        assert_eq!(&*secret.runtime.current().unwrap().0, b"new-access");
    }
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    #[test]
    fn json_and_form_grants_are_explicit_and_expiry_falls_back_to_issuer_jwt() {
        use base64::Engine as _;
        let mut policy = RefreshPolicy {
            token_url: "https://issuer.test/token".into(),
            client_id: "public client".into(),
            refresh_before_seconds: 300,
            encoding: TokenEncoding::Form,
        };
        let (content, body) = grant_body(&policy, "private fixture").unwrap();
        assert_eq!(content, "application/x-www-form-urlencoded");
        assert!(
            body.windows(b"refresh_token=private%20fixture".len())
                .any(|b| b == b"refresh_token=private%20fixture")
        );
        policy.encoding = TokenEncoding::Json;
        let (content, body) = grant_body(&policy, "private fixture").unwrap();
        assert_eq!(content, "application/json");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["refresh_token"], "private fixture");
        assert_eq!(value["grant_type"], "refresh_token");
        let expiry = now() + 120;
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{{\"exp\":{expiry}}}"));
        let token = format!("e30.{claims}.fixture");
        let response: Response = serde_json::from_value(
            serde_json::json!({"access_token":token,"refresh_token":"rotated-fixture"}),
        )
        .unwrap();
        assert_eq!(super::expiry(&response).unwrap(), expiry);
        let with_ttl: Response =
            serde_json::from_value(serde_json::json!({"access_token":token,"expires_in":3600}))
                .unwrap();
        assert_eq!(super::expiry(&with_ttl).unwrap(), expiry);
        let opaque: Response =
            serde_json::from_value(serde_json::json!({"access_token":"opaque"})).unwrap();
        assert!(super::expiry(&opaque).is_err());
        let bad: Response =
            serde_json::from_value(serde_json::json!({"access_token":token,"expires_in":0}))
                .unwrap();
        assert!(super::expiry(&bad).is_err());
    }
}
