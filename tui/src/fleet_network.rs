//! The Tailscale adapter: what this machine's installed network client can see.
//!
//! ## What this module is allowed to do
//!
//! Read-only discovery. It runs the installed `tailscale` client with a fixed argument
//! array, reads its JSON, and shapes it into the inventory and diagnostics the fleet
//! commands print. It starts no runtime, opens no SSH connection, writes no fleet state,
//! and contacts no peer except the one an operator names to `fleet doctor --peer`.
//!
//! ## Six outcomes, not one `offline`
//!
//! The proposal's Inventory section asks for distinct empty states, because "no devices"
//! has five different repairs. [`DiscoveryCode`] keeps them apart: the client is not
//! installed, this machine is signed out, the local API refused us, the client is
//! installed but has nothing to say, it has nothing to say about *peers*, or it answered.
//! Each carries a stable snake_case code for `--json` and a sentence for a person.
//!
//! ## What is *not* used to identify a Tailscale network
//!
//! Not a `100.x` address prefix, and not a `.ts.net` DNS suffix. Headscale issues its own
//! ranges and its own MagicDNS suffix, and the proposal includes Headscale clients in v1.
//! The decisions here come from the JSON's own fields — `BackendState`, `Self`, `Peer`,
//! `TailscaleIPs` — and an address is treated as this fleet's private address because the
//! client reported it, not because of how it is spelled.
//!
//! ## What "direct" and "relayed" are allowed to mean
//!
//! Only freshly observed data. `Relay` in `tailscale status --json` is the peer's *home*
//! DERP region and is populated for peers that are offline and unreachable, so it is
//! inventory, never a claim about the path in use. A non-empty `CurAddr` is an observed
//! direct path; anything else reads as `unknown` until a probe says otherwise.
//! `fleet doctor --peer` is that probe, and it reports what `tailscale ping` printed.
//!
//! ## Everything a peer says is hostile text
//!
//! A hostname, a MagicDNS label, an OS string and a last-seen time are all written by the
//! device that reports them, and they land in a terminal. Unsanitized, a hostname carrying
//! newlines and the right indentation forges a whole extra row reading `fleet_member`, an
//! ESC sequence clears the screen or repositions the cursor over what was already printed,
//! a bidi override reverses a name, and a four-thousand character name scrolls the real
//! rows away. [`human`] is the single funnel every peer-derived string passes through on
//! the way to a person: controls and bidi overrides are removed, whitespace is collapsed
//! to single spaces, and the result is truncated to a column budget. The JSON forms keep
//! the raw values, because `serde_json` escapes them and a machine reader wants what the
//! client actually said.
//!
//! Anything derived from the client's own output also passes through [`redact_urls`]. The
//! Tailscale CLI prints `To authenticate, visit: https://login.tailscale.com/a/<secret>`
//! on stderr when a node key has expired, and that URL is a credential: whoever opens it
//! adds a device to the tailnet. It is replaced before it is ever stored.
//!
//! ## Bounds
//!
//! Every invocation is a fixed argument array, a five second deadline, at most 4 MiB of
//! captured output, and a child that is killed when the future is dropped. Nothing from a
//! peer reaches a shell. Fixtures for the parsed shapes live in
//! `tui/tests/fixtures/tailscale/` and record the client version they were taken from.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

use crate::fleet::{self, Summary};
use crate::fleet_protocol;

/// How long any one client invocation may take. Discovery is a local API call over a
/// unix socket; five seconds is a wedged daemon, not a slow one.
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the `--peer` route probe may take. `tailscale ping` is given three seconds of
/// its own and this is the outer bound on the child that runs it.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

/// The most output this adapter will hold from one invocation. A tailnet of a few
/// thousand devices is well inside it; anything past it is a refusal, not a truncation,
/// because half a JSON document parses as a missing field rather than as an error.
pub const MAX_OUTPUT: usize = 4 * 1024 * 1024;

/// An absolute path to the client, for an installation this lookup does not know about.
/// It must be absolute for the same reason `ouro wasm` requires it of its helper: a
/// relative name would make the working directory decide which program runs.
pub const CLIENT_ENV: &str = "OUROBOROS_TAILSCALE";

/// Where the client is looked for after `$PATH`, in order.
///
/// After, not before: the macOS app bundle's CLI is first here, and from a process with no
/// GUI login session — a daemon, a service — it prints `The Tailscale GUI failed to start`
/// and exits 0. A `tailscale` on `$PATH` is the one the operator installed to be run from
/// anywhere, so it is asked first, and a candidate that answers with no status document is
/// skipped for the next one rather than ending discovery (see [`inventory`]).
const KNOWN_LOCATIONS: [&str; 4] = [
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/bin/tailscale",
    "/usr/local/bin/tailscale",
    "/opt/homebrew/bin/tailscale",
];

// ------------------------------------------------------------------ locating the client

/// Where a located client came from, so a diagnostic can say which one it ran.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientSource {
    Environment,
    Path,
    KnownLocation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Client {
    pub program: PathBuf,
    pub source: ClientSource,
}

/// The installed client, or `None` when there is none to run.
pub fn locate_client() -> Option<Client> {
    locate_clients().into_iter().next()
}

/// Every installed client this lookup knows about, in the order they are tried.
pub fn locate_clients() -> Vec<Client> {
    locate_clients_with(
        std::env::var_os(CLIENT_ENV).as_deref(),
        std::env::var_os("PATH").as_deref(),
        &KNOWN_LOCATIONS,
    )
}

/// The first candidate of [`locate_clients_with`].
///
/// Only the tests ask this question — production wants the whole ordered list, because
/// a candidate that runs and answers with no status document is skipped for the next —
/// so it is compiled only for them rather than left as dead weight.
#[cfg(test)]
fn locate_client_with(
    override_path: Option<&OsStr>,
    search_path: Option<&OsStr>,
    fallbacks: &[&str],
) -> Option<Client> {
    locate_clients_with(override_path, search_path, fallbacks)
        .into_iter()
        .next()
}

/// The lookup, with its three inputs named so a test can drive it without touching the
/// process environment — and without the real client on this machine answering for a
/// case that is supposed to have no client at all.
///
/// An override names exactly one program. Otherwise every executable `tailscale` on
/// `$PATH` comes first, in `$PATH` order, then the known locations, each path once.
fn locate_clients_with(
    override_path: Option<&OsStr>,
    search_path: Option<&OsStr>,
    fallbacks: &[&str],
) -> Vec<Client> {
    if let Some(named) = override_path.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(named);
        // Absolute, for the reason `ouro wasm` requires it of its helper: a relative name
        // would make the working directory decide which program runs, so a `tailscale`
        // dropped into a repository an operator happens to be standing in would be
        // executed as this machine's network client.
        //
        // A rejected override is not a silent fall through to another program either: an
        // operator who named a client meant that one, and running a different one under
        // their instruction is worse than running none.
        return (path.is_absolute() && executable(&path))
            .then_some(Client {
                program: path,
                source: ClientSource::Environment,
            })
            .into_iter()
            .collect();
    }

    let mut found: Vec<Client> = Vec::new();
    let mut push = |program: PathBuf, source: ClientSource| {
        if executable(&program) && !found.iter().any(|client| client.program == program) {
            found.push(Client { program, source });
        }
    };

    if let Some(search_path) = search_path {
        for directory in std::env::split_paths(search_path) {
            if directory.as_os_str().is_empty() {
                continue;
            }
            push(directory.join("tailscale"), ClientSource::Path);
        }
    }
    for fallback in fallbacks {
        push(PathBuf::from(fallback), ClientSource::KnownLocation);
    }
    found
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    // `metadata` follows symlinks on purpose: `/opt/homebrew/bin/tailscale` is one.
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

// ------------------------------------------------------------------- bounded invocation

#[derive(Debug)]
struct Captured {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
enum RunError {
    /// The program could not be started at all.
    Spawn(std::io::Error),
    Timeout,
    TooMuchOutput,
    Io(std::io::Error),
}

impl RunError {
    /// A sentence for an operator. The adapter's failures reach human output, so none of
    /// them is allowed to be a `Debug` dump of an internal enum.
    fn describe(&self) -> String {
        match self {
            Self::Spawn(error) => format!("the Tailscale client could not be started: {error}"),
            Self::Timeout => "the Tailscale client did not answer in time".into(),
            Self::TooMuchOutput => {
                "the Tailscale client returned more output than this adapter will read".into()
            }
            Self::Io(error) => format!("reading the Tailscale client's output failed: {error}"),
        }
    }
}

/// How long the stderr drain may keep the command waiting once the child itself has
/// exited. A grandchild that inherited the pipe and is still holding it open — a
/// backgrounded `sleep`, a wrapper's helper — must not turn a complete, correct answer on
/// stdout into a five second timeout. What has been read by then is what is reported.
const STDERR_GRACE: Duration = Duration::from_millis(250);

/// The stderr drain's handle, which aborts rather than detaches when it is dropped.
///
/// A detached task would keep the read end of a pipe open for as long as whatever
/// inherited the write end lives, which is exactly the orphan this guard exists to avoid.
struct Drain(Option<tokio::task::JoinHandle<()>>);

impl Drain {
    /// Gives the drain `grace` to finish on its own; aborts it if it does not. Either way
    /// the bytes it has already put in the shared buffer are kept.
    async fn finish(mut self, grace: Duration) {
        let Some(handle) = self.0.as_mut() else {
            return;
        };
        if tokio::time::timeout(grace, handle).await.is_ok() {
            self.0 = None;
        }
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

/// Runs the client with a fixed argument array under the deadline and the output bound.
///
/// `kill_on_drop` is what makes this cancellation-safe: if the caller's future is
/// dropped — an operator pressing Ctrl-C, a surface tearing down — the child is signalled
/// rather than left holding a pipe.
async fn run(program: &Path, args: &[&str], timeout: Duration) -> Result<Captured, RunError> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(RunError::Spawn)?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");

    // stderr is drained by its own task so a child that writes a warning there and a
    // document to stdout cannot deadlock against a full pipe buffer. Past the bound it
    // is discarded rather than left unread: stderr is only ever a first line and a
    // permission marker here, and a child blocked writing to it would never exit.
    //
    // The bytes go into a shared buffer rather than the task's return value, so the ones
    // already read survive a drain that has to be abandoned — see `Drain::finish`.
    let noise = Arc::new(Mutex::new(Vec::new()));
    let filling = Arc::clone(&noise);
    let drain = Drain(Some(tokio::spawn(async move {
        let mut chunk = [0u8; 8192];
        loop {
            match stderr.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let mut held = filling.lock().expect("an uncontended stderr buffer");
                    let room = MAX_OUTPUT.saturating_sub(held.len());
                    held.extend_from_slice(&chunk[..read.min(room)]);
                }
            }
        }
    })));

    // The whole read owns the child, so dropping this future — a deadline, a cancelled
    // operator, a refusal below — drops the child and `kill_on_drop` signals it, and
    // drops `Drain`, which aborts the stderr task rather than detaching it.
    let collected = tokio::time::timeout(timeout, async move {
        let mut out = Vec::new();
        let mut bounded = stdout.take(MAX_OUTPUT as u64 + 1);
        bounded.read_to_end(&mut out).await.map_err(RunError::Io)?;
        if out.len() > MAX_OUTPUT {
            return Err(RunError::TooMuchOutput);
        }
        let status = child.wait().await.map_err(RunError::Io)?;
        drain.finish(STDERR_GRACE).await;
        Ok(Captured {
            status: status.code(),
            stdout: out,
            stderr: noise.lock().expect("an uncontended stderr buffer").clone(),
        })
    })
    .await;

    match collected {
        Ok(result) => result,
        Err(_elapsed) => Err(RunError::Timeout),
    }
}

// --------------------------------------------------------------------- the client's JSON

/// Only the fields this feature uses, every one defaulted.
///
/// The Tailscale CLI documents that this format may change. Deserializing into a struct
/// of `Option`s means an added key is ignored and a removed key becomes `None`, which the
/// classifier turns into a named `unavailable` rather than a panic or a false `ok`.
#[derive(Debug, Default, Deserialize)]
struct RawStatus {
    #[serde(default, rename = "BackendState")]
    backend_state: Option<String>,
    #[serde(default, rename = "AuthURL")]
    auth_url: Option<String>,
    #[serde(default, rename = "Version")]
    version: Option<String>,
    #[serde(default, rename = "MagicDNSSuffix")]
    magic_dns_suffix: Option<String>,
    #[serde(default, rename = "Self")]
    self_node: Option<RawNode>,
    #[serde(default, rename = "Peer")]
    peer: Option<BTreeMap<String, RawNode>>,
}

#[derive(Debug, Default, Deserialize)]
struct RawNode {
    #[serde(default, rename = "HostName")]
    host_name: Option<String>,
    #[serde(default, rename = "DNSName")]
    dns_name: Option<String>,
    #[serde(default, rename = "OS")]
    os: Option<String>,
    #[serde(default, rename = "Online")]
    online: Option<bool>,
    #[serde(default, rename = "TailscaleIPs")]
    tailscale_ips: Option<Vec<String>>,
    #[serde(default, rename = "CurAddr")]
    cur_addr: Option<String>,
    #[serde(default, rename = "Relay")]
    relay: Option<String>,
    #[serde(default, rename = "LastSeen")]
    last_seen: Option<String>,
    /// Tailscale `PublicKey`, e.g. `nodekey:…`. Absent or empty becomes `None`.
    #[serde(default, rename = "PublicKey")]
    public_key: Option<String>,
    /// Tailscale `ID` (stable node id). Absent or empty becomes `None`.
    #[serde(default, rename = "ID")]
    id: Option<String>,
}

// --------------------------------------------------------------------------- public DTOs

/// The distinct outcomes the proposal's Inventory section requires.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryCode {
    /// No client executable was found to run.
    #[default]
    ClientMissing,
    /// The client is installed and this machine is not logged in to a network.
    SignedOut,
    /// The local API refused this account.
    PermissionDenied,
    /// Installed, reachable, and unable to answer: stopped, starting, wedged, or
    /// answering something this client cannot read.
    Unavailable,
    /// Answered, and its visible peer set is empty. Network policy may limit that set.
    NoVisiblePeers,
    /// Answered with at least one visible peer.
    Ok,
}

impl DiscoveryCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientMissing => "client_missing",
            Self::SignedOut => "signed_out",
            Self::PermissionDenied => "permission_denied",
            Self::Unavailable => "unavailable",
            Self::NoVisiblePeers => "no_visible_peers",
            Self::Ok => "ok",
        }
    }

    /// Whether this outcome leaves the operator with a usable peer list.
    pub fn answered(self) -> bool {
        matches!(self, Self::NoVisiblePeers | Self::Ok)
    }
}

/// Why an `unavailable` outcome is unavailable. Separate from [`DiscoveryCode`] so the
/// six states stay the six states while the repair stays specific.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    BackendStopped,
    BackendStarting,
    BackendNoState,
    /// A `BackendState` this client does not recognise.
    BackendUnrecognized,
    /// The document parsed and a field this feature requires was absent.
    MissingField,
    /// The output was not a JSON object at all.
    ParseFailure,
    /// The client exceeded its deadline.
    Timeout,
    /// The client exited non-zero for a reason that is not a permission refusal.
    CommandFailed,
    /// More output than this adapter will hold.
    OutputTooLarge,
}

/// An observed connection path. `Unknown` is the default and the honest answer for a peer
/// whose current address the client did not report.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathObservation {
    Direct,
    Relayed,
    #[default]
    Unknown,
}

/// One device as the network client sees it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Device {
    /// The device's own reported hostname.
    pub host_name: Option<String>,
    /// MagicDNS name with its trailing dot stripped, which is the display form.
    pub dns_name: Option<String>,
    pub os: Option<String>,
    pub online: Option<bool>,
    pub ipv4: Option<Ipv4Addr>,
    /// The peer's home DERP region. Inventory only — never a statement about the path.
    pub relay_region: Option<String>,
    pub path: PathObservation,
    /// The address the client reported as currently in use, when it reported one.
    pub path_detail: Option<String>,
    /// RFC 3339, when the client reported a real one. Tailscale writes the zero time for
    /// a peer it is currently connected to; that is reported as `None`, not as year one.
    pub last_seen: Option<String>,
    /// Tailscale `PublicKey` (`nodekey:…`). The durable peer identity.
    pub node_key: Option<String>,
    /// Tailscale `ID`. Stable across a node key rotation the PublicKey is not.
    pub stable_id: Option<String>,
}

impl Device {
    /// The name to show, preferring what the device calls itself over its DNS label.
    pub fn display_name(&self) -> Option<String> {
        self.host_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .or_else(|| {
                self.dns_name
                    .as_deref()
                    .and_then(|name| name.split('.').next())
                    .filter(|label| !label.is_empty())
                    .map(str::to_string)
            })
    }
}

/// Facts about the client itself, independent of what it could see.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ClientFacts {
    pub program: Option<String>,
    pub source: Option<ClientSource>,
    /// The `Version` the client reported, which is the daemon's version.
    pub version: Option<String>,
    pub backend_state: Option<String>,
    pub magic_dns_suffix: Option<String>,
}

/// Everything one `tailscale status --json` call established.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Inventory {
    pub code: DiscoveryCode,
    pub reason: Option<UnavailableReason>,
    /// One sentence naming the repair. Never carries an auth URL or any credential.
    pub detail: Option<String>,
    pub client: ClientFacts,
    pub self_device: Option<Device>,
    pub peers: Vec<Device>,
}

impl Inventory {
    fn failed(code: DiscoveryCode, reason: Option<UnavailableReason>, detail: &str) -> Self {
        Self {
            code,
            reason,
            detail: Some(detail.to_string()),
            ..Self::default()
        }
    }

    /// A stable one-line summary for the human surfaces.
    pub fn headline(&self) -> String {
        match self.code {
            DiscoveryCode::ClientMissing => {
                "no Tailscale client is installed on this machine".into()
            }
            DiscoveryCode::SignedOut => {
                "the Tailscale client is installed and this machine is signed out".into()
            }
            DiscoveryCode::PermissionDenied => {
                "the Tailscale client refused this account's request".into()
            }
            DiscoveryCode::Unavailable => {
                "the Tailscale client could not report this machine's network".into()
            }
            DiscoveryCode::NoVisiblePeers => {
                "the Tailscale client sees no other devices on this network".into()
            }
            DiscoveryCode::Ok => format!(
                "the Tailscale client sees {} device{} on this network",
                self.peers.len(),
                if self.peers.len() == 1 { "" } else { "s" }
            ),
        }
    }
}

// ----------------------------------------------------------------------------- discovery

/// Reads this machine's network inventory. Contacts no peer.
///
/// Candidates are tried in [`locate_clients`] order. One that ran and exited 0 without a
/// status document — the macOS app bundle's CLI from a session with no GUI, which prints a
/// sentence instead — is skipped while another candidate remains; the last answer stands
/// when none of them did better.
pub async fn inventory() -> Inventory {
    let candidates = locate_clients();
    if candidates.is_empty() {
        return Inventory::failed(
            DiscoveryCode::ClientMissing,
            None,
            "install Tailscale and sign this machine in to the network the fleet uses, \
             or set OUROBOROS_TAILSCALE to an absolute path to the client",
        );
    }

    let last = candidates.len() - 1;
    for (index, client) in candidates.iter().enumerate() {
        let inventory = inventory_with(client).await;
        let no_document = inventory.reason == Some(UnavailableReason::ParseFailure);
        if no_document && index < last {
            continue;
        }
        return inventory;
    }
    unreachable!("a non-empty candidate list answers on its last element")
}

async fn inventory_with(client: &Client) -> Inventory {
    let captured = run(&client.program, &["status", "--json"], CLIENT_TIMEOUT).await;
    let mut inventory = match captured {
        Ok(captured) => classify(&captured.stdout, &captured.stderr, captured.status),
        Err(RunError::Spawn(error)) => Inventory::failed(
            DiscoveryCode::ClientMissing,
            None,
            &format!("{} could not be started: {error}", client.program.display()),
        ),
        Err(RunError::Timeout) => Inventory::failed(
            DiscoveryCode::Unavailable,
            Some(UnavailableReason::Timeout),
            &format!(
                "the Tailscale client did not answer within {} seconds; check that its \
                 background service is running",
                CLIENT_TIMEOUT.as_secs()
            ),
        ),
        Err(RunError::TooMuchOutput) => Inventory::failed(
            DiscoveryCode::Unavailable,
            Some(UnavailableReason::OutputTooLarge),
            "the Tailscale client returned more than 4 MiB; this adapter refuses to read \
             a partial device list",
        ),
        Err(RunError::Io(error)) => Inventory::failed(
            DiscoveryCode::Unavailable,
            Some(UnavailableReason::CommandFailed),
            &format!("reading the Tailscale client's output failed: {error}"),
        ),
    };
    inventory.client.program = Some(client.program.display().to_string());
    inventory.client.source = Some(client.source);
    inventory
}

/// Whether a refusal reads as "this account may not ask", separately from every other
/// non-zero exit.
///
/// The exact wording was not observed on the machine these fixtures came from — doing so
/// would have meant changing that machine's Tailscale state — so this matches the generic
/// permission vocabulary rather than one release's sentence, and anything it does not
/// match stays a plain `command_failed` instead of being guessed into this state.
fn reads_as_permission_denied(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    [
        "access denied",
        "permission denied",
        "operation not permitted",
        "must be root",
        "run as root",
        "not permitted",
        "unauthorized",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

/// Turns one invocation's three outputs into an inventory.
///
/// Separated from the spawn so every state below is driven by a fixture in a test rather
/// than by a machine in a particular condition. Note that `stderr` never participates in
/// parsing: the client on the machine these fixtures came from prints a client/daemon
/// version warning there before every command, and treating that as an error would make
/// discovery fail on a perfectly working installation.
fn classify(stdout: &[u8], stderr: &[u8], status: Option<i32>) -> Inventory {
    let stderr_text = String::from_utf8_lossy(stderr);
    let parsed: Option<RawStatus> = serde_json::from_slice(stdout).ok();

    let Some(raw) = parsed else {
        if status != Some(0) {
            let detail = first_line(&stderr_text);
            return if reads_as_permission_denied(&stderr_text) {
                Inventory::failed(
                    DiscoveryCode::PermissionDenied,
                    None,
                    &format!(
                        "the Tailscale client refused this request: {detail}. Run the \
                         fleet commands as the account that owns the Tailscale login"
                    ),
                )
            } else {
                Inventory::failed(
                    DiscoveryCode::Unavailable,
                    Some(UnavailableReason::CommandFailed),
                    &format!("`tailscale status --json` failed: {detail}"),
                )
            };
        }
        // What it printed instead is the diagnosis — `The Tailscale GUI failed to start`
        // names a client that needs a login session, and a page of HTML names a proxy —
        // so the first line goes into the detail, bounded and with any URL redacted.
        return Inventory::failed(
            DiscoveryCode::Unavailable,
            Some(UnavailableReason::ParseFailure),
            &format!(
                "the Tailscale client answered with no status document: {}",
                first_line(&String::from_utf8_lossy(stdout))
            ),
        );
    };

    // A zero exit with a readable document but a permission complaint on stderr is still
    // a refusal — check it before the document's contents are trusted.
    if status != Some(0) && reads_as_permission_denied(&stderr_text) {
        return Inventory::failed(
            DiscoveryCode::PermissionDenied,
            None,
            &format!(
                "the Tailscale client refused this request: {}. Run the fleet commands \
                 as the account that owns the Tailscale login",
                first_line(&stderr_text)
            ),
        );
    }

    let facts = ClientFacts {
        program: None,
        source: None,
        version: trimmed(raw.version.as_deref()),
        backend_state: trimmed(raw.backend_state.as_deref()),
        magic_dns_suffix: trimmed(raw.magic_dns_suffix.as_deref()),
    };

    let signed_out = trimmed(raw.auth_url.as_deref()).is_some();
    let state = facts.backend_state.as_deref();

    let unavailable = |reason: UnavailableReason, detail: &str| Inventory {
        client: facts.clone(),
        ..Inventory::failed(DiscoveryCode::Unavailable, Some(reason), detail)
    };

    match state {
        None => {
            return unavailable(
                UnavailableReason::MissingField,
                "the Tailscale client's status carried no BackendState; this build of \
                 Ouroboros cannot establish the client's condition",
            )
        }
        Some("NeedsLogin") | Some("NeedsMachineAuth") => {
            return Inventory {
                client: facts.clone(),
                ..Inventory::failed(
                    DiscoveryCode::SignedOut,
                    None,
                    "sign this machine in with `tailscale up`, then run this command again",
                )
            }
        }
        Some("Stopped") => {
            return unavailable(
                UnavailableReason::BackendStopped,
                "the Tailscale client is stopped; start it with `tailscale up`",
            )
        }
        Some("Starting") => {
            return unavailable(
                UnavailableReason::BackendStarting,
                "the Tailscale client is still starting; run this command again shortly",
            )
        }
        Some("NoState") => {
            return unavailable(
                UnavailableReason::BackendNoState,
                "the Tailscale client has no state yet; start it and sign in",
            )
        }
        Some("Running") => {}
        Some(other) => {
            let detail = format!(
                "the Tailscale client reported an unrecognised state `{other}`; this \
                 build of Ouroboros cannot act on it"
            );
            return unavailable(UnavailableReason::BackendUnrecognized, &detail);
        }
    }

    // `Running` with a login URL outstanding is a re-authentication, not a working
    // network. The URL itself is a credential and is never printed or recorded.
    if signed_out {
        return Inventory {
            client: facts.clone(),
            ..Inventory::failed(
                DiscoveryCode::SignedOut,
                None,
                "this machine has an outstanding Tailscale login; complete it with \
                 `tailscale up`, then run this command again",
            )
        };
    }

    let Some(self_raw) = raw.self_node else {
        return unavailable(
            UnavailableReason::MissingField,
            "the Tailscale client reported no Self device, so this machine's own private \
             address is unknown",
        );
    };

    let self_device = device(&self_raw);
    let mut peers: Vec<Device> = raw.peer.unwrap_or_default().values().map(device).collect();
    // A stable order, so two runs of `ouro fleet devices` diff as a change in the network
    // rather than as a change in a map's iteration.
    peers.sort_by(|left, right| {
        left.display_name()
            .cmp(&right.display_name())
            .then_with(|| left.ipv4.cmp(&right.ipv4))
    });

    Inventory {
        code: if peers.is_empty() {
            DiscoveryCode::NoVisiblePeers
        } else {
            DiscoveryCode::Ok
        },
        reason: None,
        detail: peers.is_empty().then(|| {
            "this machine is signed in and its client reports no other devices. Network \
             policy can limit what a client is shown"
                .to_string()
        }),
        client: facts,
        self_device: Some(self_device),
        peers,
    }
}

fn device(raw: &RawNode) -> Device {
    let ipv4 = raw
        .tailscale_ips
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find_map(|address| address.trim().parse::<Ipv4Addr>().ok());
    let cur_addr = trimmed(raw.cur_addr.as_deref());
    Device {
        host_name: trimmed(raw.host_name.as_deref()),
        dns_name: trimmed(raw.dns_name.as_deref())
            .map(|name| name.trim_end_matches('.').to_string())
            .filter(|name| !name.is_empty()),
        os: trimmed(raw.os.as_deref()),
        online: raw.online,
        ipv4,
        relay_region: trimmed(raw.relay.as_deref()),
        path: if cur_addr.is_some() {
            PathObservation::Direct
        } else {
            PathObservation::Unknown
        },
        path_detail: cur_addr,
        last_seen: trimmed(raw.last_seen.as_deref()).filter(|seen| !is_zero_time(seen)),
        node_key: trimmed(raw.public_key.as_deref()),
        stable_id: trimmed(raw.id.as_deref()),
    }
}

/// Tailscale writes `0001-01-01T00:00:00Z` for "not applicable" — a currently connected
/// peer has no last-seen time. Reporting year one as an observation time would be a lie
/// with a timestamp on it.
fn is_zero_time(value: &str) -> bool {
    value.starts_with("0001-01-01")
}

fn trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

// --------------------------------------------------------------- hostile text, made safe

/// The widest a single peer-derived field may print. Wide enough for a real MagicDNS name
/// on a narrow terminal, narrow enough that a four-thousand character hostname cannot
/// scroll the rows above it out of the scrollback.
pub const FIELD_COLUMNS: usize = 72;

/// How much of a client's own message may reach a person. Longer than a field because it
/// is a sentence rather than a name, and still bounded, because it is text a program this
/// one did not write chose to print.
pub const MESSAGE_COLUMNS: usize = 300;

/// What is left of `text` once it cannot move a cursor, repaint a screen, reverse itself,
/// or forge a line.
///
/// Removed: C0 and C1 controls including ESC, DEL, and the newlines and tabs that would
/// otherwise let one field draw several rows; default-ignorable code points (zero-width
/// spaces, joiners, variation selectors, bidi overrides and isolates, soft hyphen, BOM),
/// which never count toward display width and are how `bui\u{200b}ld-linux` is made to
/// look like `build-linux`. Runs of whitespace collapse to one space. Combining-mark
/// runs are capped per base character, and the result is cut to `columns` display
/// columns *and* `columns * 4` characters — a 60 kB string of graves would otherwise
/// pass a width budget of zero.
pub fn human(text: &str, columns: usize) -> String {
    use unicode_width::UnicodeWidthChar;

    let mut out = String::new();
    let mut width = 0;
    let mut chars = 0;
    let mut combining_run = 0;
    let mut space_pending = false;
    let mut truncated = false;
    let max_chars = columns.saturating_mul(4);

    for character in text.chars() {
        if ignorable(character) {
            continue;
        }
        if character.is_control() || character.is_whitespace() {
            // A removed control collapses like the whitespace around it rather than
            // joining two halves of a forged word together.
            space_pending = !out.is_empty();
            combining_run = 0;
            continue;
        }
        let character_width = character.width().unwrap_or(0);
        if character_width == 0 {
            if out.is_empty() || combining_run >= MAX_COMBINING_PER_BASE {
                continue;
            }
            if chars >= max_chars {
                truncated = true;
                break;
            }
            out.push(character);
            chars += 1;
            combining_run += 1;
            continue;
        }
        combining_run = 0;
        let separator = usize::from(space_pending);
        // One column is kept for the ellipsis so the cut is visible rather than silent.
        if width + separator + character_width > columns.saturating_sub(1)
            || chars + separator >= max_chars
        {
            truncated = true;
            break;
        }
        if space_pending {
            out.push(' ');
            width += 1;
            chars += 1;
            space_pending = false;
        }
        out.push(character);
        width += character_width;
        chars += 1;
    }

    if truncated {
        out.push('…');
    }
    out
}

/// Combining marks kept on one base character. Extra marks are dropped: a thousand
/// graves on one letter is not a name, it is a way to pass a 60 kB string through a
/// column budget that counts display width.
const MAX_COMBINING_PER_BASE: usize = 2;

/// Default-ignorable code points: they do not draw, so they never consume a column,
/// and they are how one device name is made to look like another's.
///
/// The TUI's Devices view used to keep a private copy of this list and strip before
/// calling [`human`]. The list lives here so every surface that prints a peer-written
/// string applies the same filter.
pub fn ignorable(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'
            | '\u{1160}'
            | '\u{17b4}'
            | '\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

/// Replaces every `http://` or `https://` run with a placeholder.
///
/// `tailscale` prints `To authenticate, visit: https://login.tailscale.com/a/<secret>` on
/// stderr when a node key has expired, and `ouro fleet devices` would otherwise copy it
/// into a JSON document an operator pastes into a ticket. That URL is a bearer credential:
/// whoever opens it joins a device to the tailnet. Nothing derived from the client's own
/// output is stored before it passes through here.
pub fn redact_urls(text: &str) -> String {
    const PLACEHOLDER: &str = "<redacted url>";
    // Lowercased once: scanning the original with a fresh lowercase on every match was
    // quadratic in the number of `http` runs.
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while let Some(rel) = lower[index..].find("http") {
        let start = index + rel;
        let tail = &text[start..];
        let scheme = ["https://", "http://"].iter().find(|scheme| {
            tail.len() >= scheme.len() && tail[..scheme.len()].eq_ignore_ascii_case(scheme)
        });
        let Some(scheme) = scheme else {
            // A bare "http" that is not the start of a URL: keep it and move past it.
            out.push_str(&text[index..start + 4]);
            index = start + 4;
            continue;
        };
        out.push_str(&text[index..start]);
        out.push_str(PLACEHOLDER);
        // A URL ends at the first character that cannot be inside one.
        let end = tail[scheme.len()..]
            .find(|character: char| character.is_whitespace() || character.is_control())
            .map_or(tail.len(), |offset| scheme.len() + offset);
        index = start + end;
    }
    out.push_str(&text[index..]);
    out
}

/// The first non-empty line of a program's output, redacted and bounded.
///
/// Every path that stores something the client printed goes through here, so the
/// redaction and the length bound are properties of the funnel rather than of each
/// caller's memory.
fn first_line(text: &str) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no output");
    human(&redact_urls(line), MESSAGE_COLUMNS)
}

// -------------------------------------------------------------------- the device route

/// What one `tailscale ping` established about the route to a device.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteCode {
    Reachable,
    TimedOut,
    /// The client answered something this build cannot read, or could not be run.
    Unknown,
    /// The name or address given does not match a device this client can see.
    PeerUnknown,
    /// The name given matches more than one visible device. The real tailnet this was
    /// built against has a peer literally named `localhost`, so this is not a corner:
    /// picking one silently would probe whichever the map iterated first.
    PeerAmbiguous,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RouteProbe {
    pub code: RouteCode,
    /// The device this probe was aimed at, as the operator named it.
    pub peer: String,
    pub address: Option<Ipv4Addr>,
    pub path: PathObservation,
    pub detail: String,
}

/// What an operator's `--peer` resolved to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerResolution {
    /// Exactly one device, and the address the client reported for it.
    One(Ipv4Addr),
    /// More than one visible device answers to that name.
    Ambiguous(Vec<Ipv4Addr>),
    /// Nothing visible answers to it.
    None,
}

/// Resolves an operator's `--peer` to one visible device's IPv4 address.
///
/// The order matters. A name that is in this machine's roster is resolved through *the
/// profile* — the address the operator themselves bound with `fleet create` or
/// `fleet members add` — before anything a peer said is consulted. Otherwise a tailnet
/// device that sets its own hostname to a roster machine's name would capture the probe:
/// `doctor --peer attic` would report the impostor reachable and call the fleet healthy.
///
/// After that, a literal address must be one the client actually reported, and a name is
/// matched against the MagicDNS name (which the coordination server assigns and keeps
/// unique) and the device's own hostname (which it does not). A name that matches more
/// than one device is ambiguous rather than silently first-wins.
pub fn resolve_peer(summary: &Summary, inventory: &Inventory, peer: &str) -> PeerResolution {
    let wanted = peer.trim().trim_end_matches('.').to_ascii_lowercase();
    if wanted.is_empty() {
        return PeerResolution::None;
    }

    let devices = || inventory.peers.iter().chain(inventory.self_device.iter());

    // 1. The operator's own roster, by machine name.
    if let Some(member) = summary.profile.as_ref().and_then(|profile| {
        profile
            .members
            .iter()
            .find(|member| member.machine.trim().to_ascii_lowercase() == wanted)
    }) {
        let host = member
            .host
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let matched: Vec<Ipv4Addr> = devices()
            .filter(|device| matches_member(device, &host))
            .filter_map(|device| device.ipv4)
            .collect();
        return match matched.as_slice() {
            [address] => PeerResolution::One(*address),
            [] => PeerResolution::None,
            _several => PeerResolution::Ambiguous(matched),
        };
    }

    // 2. A literal address the client reported for some visible device.
    if let Ok(address) = wanted.parse::<Ipv4Addr>() {
        return if devices().any(|device| device.ipv4 == Some(address)) {
            PeerResolution::One(address)
        } else {
            PeerResolution::None
        };
    }

    // 3. A name a visible device answers to.
    let matched: Vec<Ipv4Addr> = devices()
        .filter(|device| device_answers_to(device, &wanted))
        .filter_map(|device| device.ipv4)
        .collect();
    match matched.as_slice() {
        [address] => PeerResolution::One(*address),
        [] => PeerResolution::None,
        _several => PeerResolution::Ambiguous(matched),
    }
}

/// Whether a visible device answers to `wanted`, which is already lowercased and has no
/// trailing dot.
fn device_answers_to(device: &Device, wanted: &str) -> bool {
    [
        device.host_name.clone(),
        device.dns_name.clone(),
        device
            .dns_name
            .as_deref()
            .and_then(|name| name.split('.').next())
            .map(str::to_string),
    ]
    .into_iter()
    .flatten()
    .any(|candidate| candidate.trim().to_ascii_lowercase() == wanted)
}

/// One bounded overlay probe of one operator-selected device.
///
/// An overlay ping establishes that the two clients can exchange packets. It does not
/// establish that the distribution ports are open, which is why this is a separate
/// `doctor` layer from the runtime's own connectivity check.
pub async fn probe_route(summary: &Summary, inventory: &Inventory, peer: &str) -> RouteProbe {
    let unknown = |code: RouteCode, address, detail: String| RouteProbe {
        code,
        peer: peer.to_string(),
        address,
        path: PathObservation::Unknown,
        detail,
    };

    // Resolution happens before the client is even located, so a name that resolves to
    // nothing costs no invocation at all. An address is probed only when this machine's
    // client reported it for a device, or when it is the address the operator themselves
    // bound for a roster member: a dotted quad typed on the command line is never sent to
    // the network on the strength of being well formed.
    let address = match resolve_peer(summary, inventory, peer) {
        PeerResolution::One(address) => address,
        PeerResolution::Ambiguous(candidates) => {
            let listed = candidates
                .iter()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            return unknown(
                RouteCode::PeerAmbiguous,
                None,
                format!(
                    "`{peer}` matches more than one visible device ({listed}); name the \
                     one you mean by its private address"
                ),
            );
        }
        PeerResolution::None => {
            return unknown(
                RouteCode::PeerUnknown,
                None,
                format!(
                    "`{peer}` does not match a device this machine's Tailscale client can \
                     see; run `ouro fleet devices` for the visible list"
                ),
            )
        }
    };

    let Some(client) = locate_client() else {
        return unknown(
            RouteCode::Unknown,
            Some(address),
            "no Tailscale client is installed to probe the route with".into(),
        );
    };

    let target = address.to_string();
    let captured = run(
        &client.program,
        &["ping", "-c", "1", "--timeout", "3s", &target],
        PROBE_TIMEOUT,
    )
    .await;

    match captured {
        Ok(captured) => {
            let mut probe = read_ping(&String::from_utf8_lossy(&captured.stdout), captured.status);
            probe.peer = peer.to_string();
            probe.address = Some(address);
            if probe.code == RouteCode::Unknown && probe.detail.is_empty() {
                probe.detail = first_line(&String::from_utf8_lossy(&captured.stderr));
            }
            probe
        }
        Err(RunError::Timeout) => unknown(
            RouteCode::TimedOut,
            Some(address),
            format!(
                "`tailscale ping {target}` did not finish within {} seconds",
                PROBE_TIMEOUT.as_secs()
            ),
        ),
        Err(error) => unknown(RouteCode::Unknown, Some(address), error.describe()),
    }
}

/// Reads `tailscale ping`'s one-line result.
///
/// Two forms were observed on the client these fixtures came from:
/// `pong from NAME (100.x.y.z) via [ADDR]:PORT in 17ms` for a reachable device, and
/// `ping "100.x.y.z" timed out` with exit 1 for one that did not answer. The relayed
/// form is recognised by the `via DERP(` marker the CLI documents; it was not observed
/// here, because every reachable device on the capture network had a direct path. An
/// unrecognised line is `unknown`, not a guess.
fn read_ping(stdout: &str, status: Option<i32>) -> RouteProbe {
    // The same funnel the client's stderr goes through: bounded, and with any URL
    // removed. `tailscale ping` prints an authentication URL here when the node key has
    // expired, and an unbounded line is an unbounded line wherever it came from.
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| human(&redact_urls(line), MESSAGE_COLUMNS))
        .unwrap_or_default();

    let mut probe = RouteProbe {
        code: RouteCode::Unknown,
        peer: String::new(),
        address: None,
        path: PathObservation::Unknown,
        detail: line.clone(),
    };

    if line.starts_with("pong from ") {
        probe.code = RouteCode::Reachable;
        probe.path = match line.split_once(" via ") {
            Some((_, rest)) if rest.starts_with("DERP(") => PathObservation::Relayed,
            Some((_, rest)) if !rest.trim().is_empty() => PathObservation::Direct,
            _unstated => PathObservation::Unknown,
        };
        return probe;
    }
    if line.contains("timed out") {
        probe.code = RouteCode::TimedOut;
        return probe;
    }
    if status == Some(0) && !line.is_empty() {
        probe.detail =
            format!("the Tailscale client answered something this build cannot read: {line}");
    }
    probe
}

// ---------------------------------------------------------------------- bindable address

/// Whether this machine can bind the address it would advertise to the fleet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "code", content = "detail")]
pub enum BindCheck {
    Bindable,
    NotBindable(String),
    /// No address to check — discovery did not establish one.
    Unknown,
}

/// Proves the selected private address is assigned to a local interface.
///
/// This is `fleet::ensure_local_bind_address`, the same check `fleet create` and
/// `fleet create --from` run before they install credentials: an advertised address that
/// cannot be bound turns a generated recovery service into a boot loop. Discovery calls
/// the same function rather than a second opinion about the same fact.
pub fn bindable(address: Ipv4Addr) -> BindCheck {
    match fleet::ensure_local_bind_address(&address.to_string()) {
        Ok(_bound) => BindCheck::Bindable,
        Err(error) => BindCheck::NotBindable(format!("{error:#}")),
    }
}

/// The bind check for this machine's own discovered address.
pub fn self_bindable(inventory: &Inventory) -> BindCheck {
    match inventory
        .self_device
        .as_ref()
        .and_then(|device| device.ipv4)
    {
        Some(address) => bindable(address),
        None => BindCheck::Unknown,
    }
}

// --------------------------------------------------------------------------- device rows

/// What Ouroboros knows about a device, which is a different question from whether the
/// network can see it. The codes are the proposal's observed-state table.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// This machine, with a fleet profile of its own.
    ThisDevice,
    /// This machine, with no fleet profile yet.
    ThisDeviceWithoutProfile,
    /// In this machine's roster. Whether it is reachable and compatible is a live
    /// runtime question this read-only listing does not ask.
    FleetMember,
    /// In the roster and not among the visible peers. Not visible is not powered off.
    FleetMemberNotVisible,
    /// Visible, usable, and never inspected. Not "uninstalled".
    DiscoveredInstallationUnknown,
    /// Visible and reported offline by the client.
    PeerOffline,
    /// Reported an OS no Ouroboros release targets.
    UnsupportedPlatform,
    /// Visible with no IPv4 address the fleet could use.
    NoUsableIpv4,
}

impl DeviceState {
    /// The next thing an operator can do, in the proposal's words.
    pub fn action(self) -> &'static str {
        match self {
            Self::ThisDevice => "view device",
            Self::ThisDeviceWithoutProfile => "set up this device",
            Self::FleetMember => "view device",
            Self::FleetMemberNotVisible => "diagnose",
            Self::DiscoveredInstallationUnknown => "deploy Ouroboros",
            Self::PeerOffline => "refresh or inspect",
            Self::UnsupportedPlatform => "nothing to deploy",
            Self::NoUsableIpv4 => "nothing to deploy",
        }
    }

    /// The same state as a person reads it. The snake_case identifier is the `--json`
    /// contract and belongs there; a column in a terminal is prose.
    pub fn label(self) -> &'static str {
        match self {
            Self::ThisDevice => "this machine, set up",
            Self::ThisDeviceWithoutProfile => "this machine, not set up here",
            Self::FleetMember => "in this machine's fleet",
            Self::FleetMemberNotVisible => "in the fleet, not visible on this network",
            Self::DiscoveredInstallationUnknown => "not inspected yet",
            Self::PeerOffline => "offline, not inspected",
            Self::UnsupportedPlatform => "no supported release for this platform",
            Self::NoUsableIpv4 => "no private IPv4 address the fleet can use",
        }
    }
}

/// The platforms the release matrix covers. A device reporting anything else is named as
/// a blocker rather than offered a deployment that has no artifact.
fn supported_platform(os: &str) -> bool {
    matches!(
        os.trim().to_ascii_lowercase().as_str(),
        "macos" | "darwin" | "linux"
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceRow {
    /// The name to show. The operator's roster name wins over the device's own, which is
    /// the rule `App::machine_label` already applies in the UI.
    pub name: String,
    /// The roster name, when this device is in this machine's roster.
    pub machine: Option<String>,
    pub os: Option<String>,
    /// The private address: the roster's advertised host, or the peer's IPv4.
    pub address: Option<String>,
    pub online: Option<bool>,
    /// When the client last saw it, for a device it is not currently connected to.
    pub last_seen: Option<String>,
    pub path: PathObservation,
    pub state: DeviceState,
    pub action: &'static str,
    /// Set when a visible device calls itself by a roster machine's name while *not*
    /// being that member's advertised address. Naming it is the whole point: a device
    /// that adopts a member's name is either a mistake worth fixing or an attempt to be
    /// mistaken for it, and silently listing it as an ordinary peer says neither.
    #[serde(rename = "name_conflicts_with_roster")]
    pub name_conflict: Option<String>,
    /// Tailscale `PublicKey`, when this row is a visible device rather than a roster
    /// member the client cannot see.
    pub node_key: Option<String>,
    /// Tailscale `ID`, same visibility as [`Self::node_key`].
    pub stable_id: Option<String>,
    /// A valid machine name to offer when this device is set up or added: the roster name
    /// for a member, otherwise [`machine_slug`] of the display name, or `None` when nothing
    /// valid can be made of it. A surface pre-fills a form with this and never with `name`,
    /// which is a display string the device chose and which the validator refuses.
    pub suggested_machine: Option<String>,
}

/// Merges this machine's roster with the visible peers.
///
/// Known members are retained when discovery is unavailable — a client that cannot answer
/// is not evidence that the fleet has no members — and a visible peer is never labelled
/// uninstalled, because nothing here has inspected one.
pub fn device_rows(summary: &Summary, inventory: &Inventory) -> Vec<DeviceRow> {
    let profile = summary.profile.as_ref();
    let mut rows = Vec::new();
    let mut claimed: Vec<usize> = Vec::new();

    let local_machine = profile.map(|profile| profile.machine.as_str());
    let self_device = inventory.self_device.as_ref();

    // This machine first: it is the one row whose action is local.
    let self_row = DeviceRow {
        name: local_machine
            .map(str::to_string)
            .or_else(|| self_device.and_then(Device::display_name))
            .or_else(short_hostname)
            .unwrap_or_else(|| "this machine".into()),
        machine: local_machine.map(str::to_string),
        os: self_device
            .and_then(|device| device.os.clone())
            .or_else(|| Some(std::env::consts::OS.to_string())),
        address: profile.map(|profile| profile.host.clone()).or_else(|| {
            self_device
                .and_then(|device| device.ipv4)
                .map(|ip| ip.to_string())
        }),
        online: inventory.code.answered().then_some(true),
        last_seen: None,
        // This machine's path to itself is whatever the client observed, and `unknown`
        // when there is no client to have observed anything. A hardcoded `direct` would
        // be a claim about a network this row has not looked at.
        path: self_device.map_or(PathObservation::Unknown, |device| device.path),
        state: if profile.is_some() {
            DeviceState::ThisDevice
        } else {
            DeviceState::ThisDeviceWithoutProfile
        },
        action: if profile.is_some() {
            DeviceState::ThisDevice.action()
        } else {
            DeviceState::ThisDeviceWithoutProfile.action()
        },
        suggested_machine: None,
        name_conflict: None,
        node_key: self_device.and_then(|device| device.node_key.clone()),
        stable_id: self_device.and_then(|device| device.stable_id.clone()),
    };
    rows.push(self_row);

    // Roster members next, matched to a visible peer where one matches.
    for member in profile
        .map(|profile| profile.members.as_slice())
        .unwrap_or_default()
    {
        if Some(member.machine.as_str()) == local_machine {
            continue;
        }
        let matched = inventory
            .peers
            .iter()
            .enumerate()
            .find(|(_index, peer)| matches_member(peer, &member.host));
        if let Some((index, peer)) = matched {
            claimed.push(index);
            rows.push(DeviceRow {
                name: member.machine.clone(),
                machine: Some(member.machine.clone()),
                os: peer.os.clone(),
                address: Some(member.host.clone()),
                online: peer.online,
                last_seen: peer.last_seen.clone(),
                path: peer.path,
                state: DeviceState::FleetMember,
                action: DeviceState::FleetMember.action(),
                suggested_machine: None,
                name_conflict: None,
                node_key: peer.node_key.clone(),
                stable_id: peer.stable_id.clone(),
            });
        } else {
            rows.push(DeviceRow {
                name: member.machine.clone(),
                machine: Some(member.machine.clone()),
                os: None,
                address: Some(member.host.clone()),
                online: None,
                last_seen: None,
                path: PathObservation::Unknown,
                state: DeviceState::FleetMemberNotVisible,
                action: DeviceState::FleetMemberNotVisible.action(),
                suggested_machine: None,
                name_conflict: None,
                node_key: None,
                stable_id: None,
            });
        }
    }

    // Everything else the client can see.
    for (index, peer) in inventory.peers.iter().enumerate() {
        if claimed.contains(&index) {
            continue;
        }
        let state = if peer.ipv4.is_none() {
            DeviceState::NoUsableIpv4
        } else if peer.os.as_deref().is_some_and(|os| !supported_platform(os)) {
            DeviceState::UnsupportedPlatform
        } else if peer.online == Some(false) {
            DeviceState::PeerOffline
        } else {
            DeviceState::DiscoveredInstallationUnknown
        };
        rows.push(DeviceRow {
            name: peer
                .display_name()
                .or_else(|| peer.ipv4.map(|ip| ip.to_string()))
                .unwrap_or_else(|| "unnamed device".into()),
            machine: None,
            os: peer.os.clone(),
            address: peer.ipv4.map(|ip| ip.to_string()),
            online: peer.online,
            last_seen: peer.last_seen.clone(),
            path: peer.path,
            state,
            action: state.action(),
            suggested_machine: None,
            name_conflict: roster_name_collision(profile, peer),
            node_key: peer.node_key.clone(),
            stable_id: peer.stable_id.clone(),
        });
    }

    for row in &mut rows {
        row.suggested_machine = row.machine.clone().or_else(|| machine_slug(&row.name));
    }

    rows
}

/// This host's name up to its first dot, for the self row when the network client gave
/// no name for it.
fn short_hostname() -> Option<String> {
    let hostname = fleet::local_hostname().ok()?;
    let short = hostname.split('.').next().unwrap_or(&hostname).trim();
    (!short.is_empty()).then(|| short.to_string())
}

/// A machine name a person would accept, made from a name a device chose.
///
/// The validator (`fleet::validate_machine`) takes 1–40 ASCII letters, digits and
/// hyphens, starting and ending with a letter or digit. So: lower-cased, apostrophes
/// dropped (`Monocursive’s MacBook Pro` reads better as `monocursives-macbook-pro` than
/// with a hyphen where the apostrophe was), every other run of non-alphanumerics folded
/// to one hyphen, hyphens trimmed from both ends, cut at 40. `None` when nothing is left.
pub fn machine_slug(name: &str) -> Option<String> {
    let mut slug = String::new();
    let mut separator_due = false;
    for character in name.chars() {
        if character == '\'' || character == '\u{2019}' {
            continue;
        }
        if !character.is_ascii_alphanumeric() {
            separator_due = !slug.is_empty();
            continue;
        }
        let needed = if separator_due { 2 } else { 1 };
        if slug.len() + needed > 40 {
            break;
        }
        if separator_due {
            slug.push('-');
            separator_due = false;
        }
        slug.push(character.to_ascii_lowercase());
    }
    let slug = slug.trim_matches('-').to_string();
    (!slug.is_empty()).then_some(slug)
}

/// The roster machine name a visible device is calling itself by, when it is not that
/// member's advertised address.
fn roster_name_collision(profile: Option<&fleet::Profile>, peer: &Device) -> Option<String> {
    let claimed = peer
        .host_name
        .as_deref()
        .map(|name| name.trim().to_ascii_lowercase())?;
    profile?
        .members
        .iter()
        .find(|member| member.machine.trim().to_ascii_lowercase() == claimed)
        .map(|member| member.machine.clone())
}

/// Whether a visible peer is the roster member that advertises `host`.
///
/// Only the advertised host decides — the address or private DNS name the operator bound
/// with `fleet create` or `fleet members add`. It is compared against the peer's IPv4
/// address and its MagicDNS name, both of which the coordination server assigns and keeps
/// unique within a network.
///
/// The peer's *hostname* is deliberately not consulted. A hostname is whatever the device
/// says it is, it is not unique, and matching on it let any tailnet device claim a roster
/// row by renaming itself: the row would then show the impostor's platform, presence and
/// connection path against the real member's address, the impostor would vanish from the
/// available list, and `doctor --peer <member>` would report it reachable. A device that
/// adopts a member's name is surfaced by [`roster_name_collision`] instead, as the
/// separate device it is.
fn matches_member(peer: &Device, host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    let candidates = [
        peer.ipv4.map(|ip| ip.to_string()),
        peer.dns_name.clone(),
        peer.dns_name
            .as_deref()
            .and_then(|name| name.split('.').next())
            .map(str::to_string),
    ];
    candidates
        .into_iter()
        .flatten()
        .any(|candidate| candidate.trim().to_ascii_lowercase() == host)
}

// ----------------------------------------------------------------------------- rendering

/// A peer-derived optional field, made safe for a terminal, or the word `unknown`.
///
/// Every human-path field goes through this rather than through `unwrap_or`, so adding a
/// column cannot accidentally add an unsanitized one.
fn or_unknown(value: Option<&str>) -> String {
    match value {
        Some(value) => human(value, FIELD_COLUMNS),
        None => "unknown".into(),
    }
}

fn presence(row: &DeviceRow) -> String {
    // `LastSeen` is a string the peer's client put in a JSON document; it is no more
    // trustworthy than a hostname and is bounded and stripped the same way.
    let seen = row
        .last_seen
        .as_deref()
        .map(|seen| human(seen, FIELD_COLUMNS));
    match (row.online, seen) {
        (Some(true), _connected) => "online now".into(),
        (Some(false), Some(seen)) => format!("offline, last seen {seen}"),
        (Some(false), None) => "offline".into(),
        (None, Some(seen)) => format!("unknown, last seen {seen}"),
        (None, None) => "unknown".into(),
    }
}

/// `ouro fleet devices`, for a person.
pub fn render_devices(summary: &Summary, inventory: &Inventory) -> String {
    let rows = device_rows(summary, inventory);
    let mut text = String::from("Fleet devices\n");
    for row in rows
        .iter()
        .filter(|row| row.machine.is_some() || row.state == DeviceState::ThisDeviceWithoutProfile)
    {
        text.push_str(&render_row(row));
    }
    if !rows.iter().any(|row| row.machine.is_some()) {
        text.push_str(
            "      There is no fleet on this machine yet; `ouro fleet create` starts one.\n",
        );
    }

    text.push_str(&format!(
        "\nAvailable on this network — {}\n",
        inventory.headline()
    ));
    let available: Vec<_> = rows
        .iter()
        .filter(|row| row.machine.is_none() && row.state != DeviceState::ThisDeviceWithoutProfile)
        .collect();
    if available.is_empty() {
        match &inventory.detail {
            // `detail` can carry a line the client printed, so it is bounded here too.
            Some(detail) => text.push_str(&format!("  {}\n", human(detail, MESSAGE_COLUMNS))),
            None => text.push_str("  (none)\n"),
        }
    }
    for row in available {
        text.push_str(&render_row(row));
    }

    text.push_str(
        "\nNothing above was contacted over SSH and no device was inspected; an \
         installation state is only established by a preflight.\n",
    );
    text
}

/// One row, four fixed lines, and no field that a device can make into a fifth.
///
/// `row.name` and the platform come from the device; the state and the action are this
/// build's own words. The state prints as prose — the snake_case identifier is the
/// `--json` contract and has no business in a terminal column.
fn render_row(row: &DeviceRow) -> String {
    let mut text = format!(
        "  {}\n      address      {}\n      platform     {}\n      network      {}\n      ouroboros    {} · {}\n",
        human(&row.name, FIELD_COLUMNS),
        or_unknown(row.address.as_deref()),
        or_unknown(row.os.as_deref()),
        presence(row),
        row.state.label(),
        row.action,
    );
    if let Some(machine) = &row.name_conflict {
        text.push_str(&format!(
            "      [note] this device calls itself `{}`, which is the name of a machine in this fleet at a different address. It is not that machine.\n",
            human(machine, FIELD_COLUMNS),
        ));
    }
    text
}

/// `ouro fleet devices --json`.
pub fn devices_json(summary: &Summary, inventory: &Inventory) -> Value {
    json!({
        "fleet_protocol_revision": fleet_protocol::FLEET_PROTOCOL_REVISION,
        "discovery": discovery_json(inventory),
        "devices": device_rows(summary, inventory),
    })
}

fn discovery_json(inventory: &Inventory) -> Value {
    json!({
        "code": inventory.code,
        "reason": inventory.reason,
        "detail": inventory.detail,
        "client": inventory.client,
        "self": inventory.self_device,
        "visible_peers": inventory.peers.len(),
    })
}

/// `ouro fleet status --json`.
///
/// `problems` carries the same sentences the human form prints; `ready` and the nested
/// `code` fields are the machine-readable part. Facts this machine could not establish
/// are `null`, never a default that reads like an observation.
pub fn status_json(summary: &Summary, inventory: &Inventory, live: Option<&Value>) -> Value {
    let build = fleet_protocol::build_metadata();
    json!({
        "build": build,
        "profile": summary.profile,
        "tls": summary.tls,
        "problems": summary.problems,
        "ready": status_ready(summary),
        "network": discovery_json(inventory),
        "bindable_self_address": self_bindable(inventory),
        "live": live,
    })
}

/// Whether this machine's fleet setup is complete. A machine with no profile is not a
/// healthy standalone machine for this command's purposes: `--json` is the onboarding
/// preflight's view, and "no profile yet" is exactly the incomplete setup it reports.
pub fn status_ready(summary: &Summary) -> bool {
    summary.profile.is_some() && summary.tls && summary.problems.is_empty()
}

/// The `doctor` network-client layer.
///
/// A missing or signed-out client is a **note**, not a failure: the proposal keeps the
/// existing manual private-network workflows supported, and a fleet configured by hand
/// over a private LAN has no Tailscale client to find. What an operator explicitly asked
/// for — a `--peer` route probe — is a failure when it does not succeed.
pub fn doctor_network_layer(inventory: &Inventory) -> Value {
    json!({
        "code": inventory.code,
        "reason": inventory.reason,
        "detail": inventory.detail,
        "client_version": inventory.client.version,
        "client_program": inventory.client.program,
        "problem": false,
    })
}

pub fn doctor_route_layer(probe: &RouteProbe) -> Value {
    json!({
        "code": probe.code,
        "peer": probe.peer,
        "address": probe.address.map(|address| address.to_string()),
        "path": probe.path,
        "detail": probe.detail,
        "problem": probe.code != RouteCode::Reachable,
    })
}

/// `ouro fleet doctor --json`.
pub fn doctor_json(
    report: &fleet::DoctorReport,
    inventory: &Inventory,
    probe: Option<&RouteProbe>,
) -> Value {
    let mut layers = json!({ "network_client": doctor_network_layer(inventory) });
    if let Some(probe) = probe {
        layers["device_route"] = doctor_route_layer(probe);
    }
    json!({
        "healthy": doctor_healthy(report, probe),
        "scope": report.scope(),
        "build": fleet_protocol::build_metadata(),
        "checks": report
            .entries()
            .into_iter()
            .map(|(level, message)| json!({ "level": level, "message": message }))
            .collect::<Vec<_>>(),
        "layers": layers,
    })
}

/// A doctor run is healthy when every existing check passed and any probe the operator
/// explicitly asked for succeeded.
pub fn doctor_healthy(report: &fleet::DoctorReport, probe: Option<&RouteProbe>) -> bool {
    report.healthy && probe.is_none_or(|probe| probe.code == RouteCode::Reachable)
}

/// The two new layers, appended to the existing human doctor text.
///
/// Every marker here is `[note]`. `refresh_doctor_report`'s `[fix]` means "this run is
/// not healthy, and the command exited non-zero because of it"; nothing in these layers
/// feeds [`doctor_healthy`] except a probe the operator explicitly asked for, whose
/// outcome is printed as its own verdict line. A `[fix]` that a green verdict and a zero
/// exit contradict two lines later is worse than no marker at all.
pub fn render_doctor_layers(
    summary: &Summary,
    inventory: &Inventory,
    probe: Option<&RouteProbe>,
) -> String {
    let mut text = format!(
        "\nNetwork client — {}\n  {}\n",
        or_unknown(inventory.client.version.as_deref()),
        inventory.headline()
    );
    if let Some(detail) = &inventory.detail {
        text.push_str(&format!("  {}\n", human(detail, MESSAGE_COLUMNS)));
    }
    if let Some(device) = &inventory.self_device {
        text.push_str(&format!(
            "  this device  {} · {}\n",
            or_unknown(device.dns_name.as_deref()),
            device.ipv4.map_or_else(
                || "no private IPv4 address".to_string(),
                |ip| ip.to_string()
            )
        ));
        // The address the client discovered and the address the fleet advertises are two
        // different facts, and an operator reading one of them as the other is how a
        // profile ends up pointing somewhere this machine cannot bind. Name both when
        // they differ, and never call the discovered one "advertised".
        let advertised = summary
            .profile
            .as_ref()
            .map(|profile| profile.host.as_str());
        match (advertised, device.ipv4) {
            (Some(advertised), Some(discovered)) if advertised != discovered.to_string() => {
                text.push_str(&format!(
                    "  [note] this fleet advertises {advertised}, which is not the private \
                     address the network client discovered. That is expected for a manually \
                     configured host, and a mistake if this machine was meant to use the \
                     private network.\n"
                ));
            }
            _same_or_unknown => {}
        }
        if let BindCheck::NotBindable(_cause) = self_bindable(inventory) {
            // The cause sentence comes from `fleet::ensure_local_bind_address`, which is
            // written for `fleet create`'s *advertised* host. Repeating it here would
            // call the discovered address the advertised one, which is the confusion
            // this layer exists to prevent. `--json` keeps the raw cause under
            // `bindable_self_address`.
            text.push_str(
                "  [note] the private address the network client discovered is not \
                 assigned to a local interface, so this machine could not bind it.\n",
            );
        }
    }
    if let Some(probe) = probe {
        let path = match probe.path {
            PathObservation::Direct => "direct path observed",
            PathObservation::Relayed => "relayed path observed",
            PathObservation::Unknown => "connection path not observed",
        };
        text.push_str(&format!(
            "\nDevice route — {}\n  {} · {path}\n  {}\n",
            human(&probe.peer, FIELD_COLUMNS),
            match probe.code {
                RouteCode::Reachable => "reachable over the private network",
                RouteCode::TimedOut => "the overlay probe timed out",
                RouteCode::Unknown => "the route could not be established",
                RouteCode::PeerUnknown => "no visible device matches that name",
                RouteCode::PeerAmbiguous => "more than one visible device answers to that name",
            },
            human(&probe.detail, MESSAGE_COLUMNS),
        ));
        text.push_str(
            "  An overlay probe does not establish that the distribution ports are open.\n",
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tailscale");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}"))
            .unwrap_or_else(|error| panic!("fixture {name} is readable: {error}"))
    }

    fn running() -> Inventory {
        classify(&fixture("running-with-peers.json"), b"", Some(0))
    }

    // --------------------------------------------------------------- locating the client

    fn plant(dir: &Path, name: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\n").expect("writing a candidate");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("setting a candidate's mode");
        path
    }

    #[test]
    fn the_override_wins_over_the_path_and_a_rejected_one_falls_through_to_nothing() {
        let dir = tempdir();
        let on_path = plant(dir.path(), "tailscale", 0o755);
        let named = plant(dir.path(), "named-client", 0o755);
        let unreadable = dir.path().join("absent-client");

        let found = locate_client_with(
            Some(named.as_os_str()),
            Some(dir.path().as_os_str()),
            &["/nonexistent/tailscale"],
        )
        .expect("the named client is used");
        assert_eq!(found.program, named);
        assert_eq!(found.source, ClientSource::Environment);

        // An override that names a client which is not there does not quietly run
        // another one: the operator said which program to use.
        assert_eq!(
            locate_client_with(
                Some(unreadable.as_os_str()),
                Some(dir.path().as_os_str()),
                &["/nonexistent/tailscale"],
            ),
            None
        );

        // A relative override would make the working directory decide which program is
        // this machine's network client. It is refused, and refused all the way — not
        // resolved against the cwd, and not fallen back on either.
        assert_eq!(
            locate_client_with(
                Some(OsStr::new("tailscale")),
                Some(dir.path().as_os_str()),
                &["/nonexistent/tailscale"],
            ),
            None,
            "a relative OUROBOROS_TAILSCALE must never be run"
        );
        assert_eq!(
            locate_client_with(
                Some(OsStr::new("./named-client")),
                Some(dir.path().as_os_str()),
                &["/nonexistent/tailscale"],
            ),
            None
        );

        let found = locate_client_with(None, Some(dir.path().as_os_str()), &["/nonexistent/x"])
            .expect("PATH answers when no override does");
        assert_eq!(found.program, on_path);
        assert_eq!(found.source, ClientSource::Path);
    }

    #[test]
    fn path_is_preferred_to_a_known_location_and_every_candidate_is_kept_in_order() {
        let dir = tempdir();
        let on_path = plant(dir.path(), "tailscale", 0o755);
        let known = plant(dir.path(), "known-client", 0o755);
        let found = locate_client_with(
            None,
            Some(dir.path().as_os_str()),
            &[known.to_str().expect("utf-8 path")],
        )
        .expect("PATH wins");
        assert_eq!(found.program, on_path);
        assert_eq!(found.source, ClientSource::Path);

        let all = locate_clients_with(
            None,
            Some(dir.path().as_os_str()),
            &[
                known.to_str().expect("utf-8 path"),
                on_path.to_str().expect("utf-8 path"),
                "/nonexistent/tailscale",
            ],
        );
        assert_eq!(
            all.iter()
                .map(|client| client.program.clone())
                .collect::<Vec<_>>(),
            vec![on_path.clone(), known.clone()],
            "PATH first, then the known locations, each program once, absent ones skipped"
        );
        assert_eq!(all[1].source, ClientSource::KnownLocation);

        let only_known = locate_clients_with(None, None, &[known.to_str().expect("utf-8 path")]);
        assert_eq!(only_known.len(), 1);
        assert_eq!(only_known[0].source, ClientSource::KnownLocation);
    }

    #[test]
    fn a_machine_slug_is_what_the_validator_accepts() {
        assert_eq!(
            machine_slug("Monocursive’s MacBook Pro").as_deref(),
            Some("monocursives-macbook-pro")
        );
        assert_eq!(machine_slug("raspberrypi").as_deref(), Some("raspberrypi"));
        assert_eq!(
            machine_slug("  build_linux (2) ").as_deref(),
            Some("build-linux-2")
        );
        assert_eq!(machine_slug("---").as_deref(), None);
        assert_eq!(machine_slug("").as_deref(), None);
        assert_eq!(machine_slug("日本語").as_deref(), None);
        let long = machine_slug(&"a".repeat(50)).expect("a slug");
        assert_eq!(long.len(), 40);
        let cut_on_separator = machine_slug(&format!("{}-b", "a".repeat(39))).expect("a slug");
        assert_eq!(
            cut_on_separator,
            "a".repeat(39),
            "a name is never cut to a trailing hyphen"
        );
        for slug in [
            machine_slug("Monocursive’s MacBook Pro").unwrap(),
            long.clone(),
            cut_on_separator.clone(),
        ] {
            fleet::validate_machine(&slug).expect("every slug validates");
        }
    }

    #[test]
    fn a_non_executable_candidate_is_not_a_client() {
        let dir = tempdir();
        plant(dir.path(), "tailscale", 0o644);
        assert_eq!(
            locate_client_with(None, Some(dir.path().as_os_str()), &[]),
            None,
            "a file named tailscale that cannot be executed is not an installed client"
        );

        let fallback = plant(dir.path(), "fallback", 0o755);
        let found = locate_client_with(
            None,
            Some(dir.path().as_os_str()),
            &[fallback.to_str().expect("utf-8 path")],
        )
        .expect("the known location answers");
        assert_eq!(found.source, ClientSource::KnownLocation);
    }

    // ------------------------------------------------------------------- the six states

    #[test]
    fn a_running_client_with_peers_reports_ok_and_reads_self() {
        let inventory = running();
        assert_eq!(inventory.code, DiscoveryCode::Ok);
        assert_eq!(inventory.reason, None);
        assert_eq!(inventory.client.backend_state.as_deref(), Some("Running"));
        assert_eq!(inventory.client.version.as_deref(), Some("1.102.1"));

        let device = inventory.self_device.as_ref().expect("Self parsed");
        assert_eq!(device.host_name.as_deref(), Some("operator-laptop"));
        assert_eq!(
            device.node_key.as_deref(),
            Some("nodekey:a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4")
        );
        assert_eq!(device.stable_id.as_deref(), Some("n1000000000000010CNTRL"));
        assert_eq!(
            device.dns_name.as_deref(),
            Some("operator-laptop.tailnet-example.ts.net"),
            "the display form has no trailing dot"
        );
        assert_eq!(device.os.as_deref(), Some("macOS"));
        assert_eq!(device.ipv4, Some(Ipv4Addr::new(100, 64, 12, 21)));
        assert_eq!(
            device.last_seen, None,
            "a connected device's zero last-seen time is not an observation"
        );

        let names: Vec<_> = inventory
            .peers
            .iter()
            .filter_map(Device::display_name)
            .collect();
        assert_eq!(
            names,
            vec!["build-linux", "ipv6-only-box", "old-pi", "pocket-phone"],
            "peers come back in a stable order"
        );
    }

    #[test]
    fn a_relay_region_is_never_read_as_a_relayed_path() {
        let inventory = running();
        let online = inventory
            .peers
            .iter()
            .find(|peer| peer.display_name().as_deref() == Some("build-linux"))
            .expect("the online Linux peer");
        assert_eq!(online.online, Some(true));
        assert_eq!(online.path, PathObservation::Direct);
        assert_eq!(online.relay_region.as_deref(), Some("lhr"));

        let offline = inventory
            .peers
            .iter()
            .find(|peer| peer.display_name().as_deref() == Some("old-pi"))
            .expect("the offline peer");
        assert_eq!(offline.online, Some(false));
        assert_eq!(
            offline.relay_region.as_deref(),
            Some("par"),
            "an unreachable peer still carries a home DERP region"
        );
        assert_eq!(
            offline.path,
            PathObservation::Unknown,
            "a configured relay region is not an observed relayed path"
        );
        assert_eq!(
            offline.last_seen.as_deref(),
            Some("2026-09-17T07:50:00.1Z"),
            "a peer this client is not connected to has a real last-seen time"
        );
    }

    #[test]
    fn signed_out_is_its_own_state_and_never_prints_the_login_url() {
        let inventory = classify(&fixture("needs-login.json"), b"", Some(0));
        assert_eq!(inventory.code, DiscoveryCode::SignedOut);
        assert_eq!(inventory.reason, None);
        assert_eq!(
            inventory.client.backend_state.as_deref(),
            Some("NeedsLogin")
        );
        let rendered = serde_json::to_string(&inventory).expect("serializes");
        assert!(
            !rendered.contains("login.example") && !rendered.to_lowercase().contains("authurl"),
            "a login URL is a credential and never reaches output: {rendered}"
        );
    }

    #[test]
    fn a_running_client_with_an_outstanding_login_is_signed_out_not_ok() {
        let inventory = classify(&fixture("running-needs-reauth.json"), b"", Some(0));
        assert_eq!(
            inventory.code,
            DiscoveryCode::SignedOut,
            "BackendState Running with an AuthURL outstanding is a re-authentication"
        );
    }

    /// Three states a fixture never reached before, each with its own repair. Collapsing
    /// them into `unrecognised` would tell an operator whose client is still starting
    /// that this build cannot act on their client at all.
    #[test]
    fn every_backend_state_this_build_knows_has_its_own_reason() {
        for (name, code, reason) in [
            ("needs-machine-auth.json", DiscoveryCode::SignedOut, None),
            (
                "starting.json",
                DiscoveryCode::Unavailable,
                Some(UnavailableReason::BackendStarting),
            ),
            (
                "no-state.json",
                DiscoveryCode::Unavailable,
                Some(UnavailableReason::BackendNoState),
            ),
        ] {
            let inventory = classify(&fixture(name), b"", Some(0));
            assert_eq!(inventory.code, code, "{name}");
            assert_eq!(inventory.reason, reason, "{name}");
            assert_ne!(
                inventory.reason,
                Some(UnavailableReason::BackendUnrecognized),
                "{name} is a state this build knows, not one it cannot read"
            );
        }
    }

    #[test]
    fn stopped_is_unavailable_with_its_own_reason() {
        let inventory = classify(&fixture("stopped.json"), b"", Some(0));
        assert_eq!(inventory.code, DiscoveryCode::Unavailable);
        assert_eq!(inventory.reason, Some(UnavailableReason::BackendStopped));
        assert_eq!(
            inventory.client.version.as_deref(),
            Some("1.102.1"),
            "a stopped client still answers for its own version"
        );
    }

    #[test]
    fn a_missing_self_device_is_unavailable_rather_than_an_empty_fleet() {
        let inventory = classify(&fixture("missing-self.json"), b"", Some(0));
        assert_eq!(inventory.code, DiscoveryCode::Unavailable);
        assert_eq!(inventory.reason, Some(UnavailableReason::MissingField));
        assert!(inventory.peers.is_empty());
    }

    #[test]
    fn an_empty_peer_set_is_not_the_same_answer_as_no_answer() {
        let inventory = classify(&fixture("no-peers.json"), b"", Some(0));
        assert_eq!(inventory.code, DiscoveryCode::NoVisiblePeers);
        assert!(inventory.self_device.is_some());
        assert!(
            inventory
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("policy")),
            "an empty visible set is a policy question, not a claim that the tailnet is empty"
        );
    }

    #[test]
    fn a_permission_refusal_is_distinct_from_any_other_failure() {
        let denied = classify(b"", b"Access denied: cannot read status\n", Some(1));
        assert_eq!(denied.code, DiscoveryCode::PermissionDenied);
        assert_eq!(denied.reason, None);

        let other = classify(b"", b"failed to connect to local tailscaled\n", Some(1));
        assert_eq!(other.code, DiscoveryCode::Unavailable);
        assert_eq!(other.reason, Some(UnavailableReason::CommandFailed));

        // A refusal that still printed a readable document is still a refusal. Without
        // this the document would be believed and an empty, working-looking network
        // reported to an operator whose client would not answer them.
        let with_document = classify(
            &fixture("running-but-refused.json"),
            &fixture("permission-denied.stderr"),
            Some(1),
        );
        assert_eq!(
            with_document.code,
            DiscoveryCode::PermissionDenied,
            "a non-zero exit and a permission complaint outrank a parseable document"
        );
    }

    #[test]
    fn garbage_on_stdout_is_a_named_parse_failure_that_quotes_the_client() {
        let inventory = classify(b"<html>not json</html>", b"", Some(0));
        assert_eq!(inventory.code, DiscoveryCode::Unavailable);
        assert_eq!(inventory.reason, Some(UnavailableReason::ParseFailure));
        let detail = inventory.detail.as_deref().unwrap_or_default();
        assert!(detail.contains("not json"), "{detail}");
        assert!(
            !detail.contains("older"),
            "no claim about build age: {detail}"
        );

        // The macOS app bundle's CLI, from a process with no GUI session.
        let gui = classify(
            "The Tailscale GUI failed to start: The operation couldn\u{2019}t be completed.\n"
                .as_bytes(),
            b"",
            Some(0),
        );
        assert_eq!(gui.reason, Some(UnavailableReason::ParseFailure));
        assert!(gui
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("The Tailscale GUI failed to start"));
    }

    #[test]
    fn a_missing_backend_state_is_unavailable_rather_than_assumed_running() {
        let inventory = classify(br#"{"Self":{"HostName":"x"}}"#, b"", Some(0));
        assert_eq!(inventory.reason, Some(UnavailableReason::MissingField));

        let inventory = classify(br#"{"BackendState":"Dreaming"}"#, b"", Some(0));
        assert_eq!(
            inventory.reason,
            Some(UnavailableReason::BackendUnrecognized),
            "a state this build does not know is named, not guessed at"
        );
    }

    #[test]
    fn the_version_warning_on_stderr_does_not_fail_a_perfectly_good_status() {
        let warning = std::fs::read(format!("{FIXTURES}/version-warning.stderr"))
            .expect("the stderr fixture is readable");
        let inventory = classify(&fixture("running-with-peers.json"), &warning, Some(0));
        assert_eq!(
            inventory.code,
            DiscoveryCode::Ok,
            "the client prints a client/daemon version warning before every command"
        );
    }

    #[test]
    fn an_unknown_field_is_ignored_and_a_removed_one_is_unknown() {
        let inventory = classify(
            br#"{"BackendState":"Running","SomethingNew":{"a":1},
                 "Self":{"HostName":"solo","SomethingElse":7},"Peer":{}}"#,
            b"",
            Some(0),
        );
        assert_eq!(inventory.code, DiscoveryCode::NoVisiblePeers);
        let device = inventory.self_device.expect("Self parsed");
        assert_eq!(device.host_name.as_deref(), Some("solo"));
        assert_eq!(device.os, None, "an absent field reports unknown");
        assert_eq!(device.ipv4, None);
        assert_eq!(device.online, None);
    }

    /// The whole point of not keying on `100.` or `.ts.net`: a Headscale tailnet uses
    /// different ranges and a different MagicDNS suffix and must read identically.
    #[test]
    fn a_headscale_shaped_network_reads_the_same_as_a_tailscale_one() {
        let inventory = classify(&fixture("headscale-running.json"), b"", Some(0));
        assert_eq!(inventory.code, DiscoveryCode::Ok);
        assert_eq!(
            inventory.client.magic_dns_suffix.as_deref(),
            Some("headscale.internal")
        );
        let peer = &inventory.peers[0];
        assert_eq!(peer.ipv4, Some(Ipv4Addr::new(10, 63, 0, 4)));
        assert_eq!(
            peer.dns_name.as_deref(),
            Some("build-linux.headscale.internal")
        );
    }

    // ------------------------------------------------------------------------ the probe

    #[test]
    fn a_pong_names_the_path_it_observed_and_nothing_it_did_not() {
        let direct = read_ping(
            "pong from build-linux (100.64.12.44) via [2001:db8::1]:41641 in 17ms\n",
            Some(0),
        );
        assert_eq!(direct.code, RouteCode::Reachable);
        assert_eq!(direct.path, PathObservation::Direct);

        let relayed = read_ping(
            "pong from build-linux (100.64.12.44) via DERP(lhr) in 41ms\n",
            Some(0),
        );
        assert_eq!(relayed.code, RouteCode::Reachable);
        assert_eq!(
            relayed.path,
            PathObservation::Relayed,
            "a relay is a valid connection, reported as what it is"
        );

        let timed_out = read_ping("ping \"100.64.12.10\" timed out\n", Some(1));
        assert_eq!(timed_out.code, RouteCode::TimedOut);
        assert_eq!(timed_out.path, PathObservation::Unknown);

        let unreadable = read_ping("something entirely new\n", Some(0));
        assert_eq!(unreadable.code, RouteCode::Unknown);
        assert_eq!(unreadable.path, PathObservation::Unknown);

        let silent = read_ping("", Some(1));
        assert_eq!(silent.code, RouteCode::Unknown);
        assert!(
            silent.detail.is_empty(),
            "nothing printed is nothing to report"
        );

        // `tailscale ping` prints an authentication URL here when the node key expired.
        let expired = read_ping(
            "To authenticate, visit: https://login.example/a/DEADBEEF\n",
            Some(1),
        );
        assert!(
            !expired.detail.contains("login.example") && expired.detail.contains("<redacted url>"),
            "a login URL is a credential wherever the client prints it: {}",
            expired.detail
        );

        // And an unbounded line from a program this one did not write stays bounded.
        // A fixed sentence of this build's own, plus a quote bounded to MESSAGE_COLUMNS.
        let shouty = read_ping(&format!("pong {}\n", "x".repeat(5000)), Some(0));
        assert!(
            shouty.detail.chars().count() <= MESSAGE_COLUMNS + 80,
            "the detail is bounded: {} characters",
            shouty.detail.chars().count()
        );
        assert!(shouty.detail.ends_with('…'), "and the cut is visible");
    }

    // ------------------------------------------------------------- hostile text

    #[test]
    fn a_name_can_never_move_a_cursor_forge_a_row_or_run_off_the_screen() {
        let inventory = classify(&fixture("hostile-names.json"), b"", Some(0));
        assert_eq!(inventory.code, DiscoveryCode::Ok);
        assert_eq!(inventory.peers.len(), 8);

        let text = render_devices(&summary_with(&[]), &inventory);

        // Nothing that can address a terminal survives.
        for (index, byte) in text.bytes().enumerate() {
            assert!(
                byte >= 0x20 || byte == b'\n',
                "a control byte {byte:#04x} reached the terminal at offset {index}"
            );
            assert_ne!(byte, 0x7f, "DEL reached the terminal at offset {index}");
        }
        assert!(
            !text.contains('\u{202e}'),
            "a bidi override reached the terminal"
        );

        // Eight peers plus this machine, and the forged row did not become a ninth.
        // Each row's first line is the only one with exactly two leading spaces.
        let rows = text
            .lines()
            .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
            .count();
        assert_eq!(rows, 9, "one row per device and not one more:\n{text}");
        assert_eq!(
            text.matches("      ouroboros    ").count(),
            9,
            "and one state line per row, so no field drew its own"
        );
        assert!(
            !text.contains("ghost"),
            "the forged row's trailing name did not become a row of its own"
        );

        // The four-thousand character name is cut, visibly.
        assert!(!text.contains(&"L".repeat(FIELD_COLUMNS + 1)));
        assert!(text.contains('…'), "the cut is shown rather than silent");

        assert!(
            !text.contains('\u{200b}'),
            "a zero-width space must not reach the terminal"
        );
        assert!(
            text.contains("build-linux"),
            "the zero-width twin renders as the clean name it was impersonating: {text}"
        );
        let combining_marks = text.chars().filter(|c| *c == '\u{0300}').count();
        assert!(
            combining_marks <= 2,
            "a 1k combining-mark name is capped, not drawn in full: {combining_marks}"
        );

        // A hostile LastSeen is a peer-written string like any other.
        assert!(!text.contains("OWNED\u{1b}"));
        for line in text.lines() {
            assert!(
                line.chars().count() < 400,
                "no single line runs away: {line:?}"
            );
        }
    }

    #[test]
    fn the_sanitizer_keeps_what_a_real_name_needs_and_drops_what_a_terminal_obeys() {
        assert_eq!(human("build-linux", FIELD_COLUMNS), "build-linux");
        assert_eq!(
            human("host.tailnet-example.ts.net", FIELD_COLUMNS),
            "host.tailnet-example.ts.net"
        );
        // Non-ASCII names are ordinary names, not something to strip.
        assert_eq!(human("café-münchen", FIELD_COLUMNS), "café-münchen");
        assert_eq!(
            human("Mönch\u{2019}s MacBook", FIELD_COLUMNS),
            "Mönch\u{2019}s MacBook"
        );

        // The ESC is what a terminal obeys; `[2J` without it is four printable
        // characters. They are left alone deliberately: stripping "anything that looks
        // like a CSI sequence" would silently rewrite a device legitimately named
        // `[2J`, and this function's job is to make text inert, not to guess at it.
        assert_eq!(human("a\u{1b}[2Jb", FIELD_COLUMNS), "a [2Jb");
        assert_eq!(human("a\u{1b}b", FIELD_COLUMNS), "a b");
        assert_eq!(human("a\u{7f}b", FIELD_COLUMNS), "a b");
        assert_eq!(human("a\u{9b}b", FIELD_COLUMNS), "a b", "C1 CSI too");
        assert_eq!(human("a\nb\tc", FIELD_COLUMNS), "a b c");
        assert_eq!(human("  padded  ", FIELD_COLUMNS), "padded");
        // Default-ignorable code points are dropped, not collapsed to a space, so a
        // zero-width space cannot split a name and a bidi override cannot reverse one.
        assert_eq!(human("gpj.\u{202e}gnp", FIELD_COLUMNS), "gpj.gnp");
        assert_eq!(human("a\u{2066}b\u{2069}c", FIELD_COLUMNS), "abc");
        assert_eq!(human("bui\u{200b}ld-linux", FIELD_COLUMNS), "build-linux");
        assert_eq!(human("", FIELD_COLUMNS), "");

        // The budget is display columns, so a wide script is cut where it looks cut.
        let wide = human(&"漢".repeat(40), 11);
        assert_eq!(wide.chars().filter(|c| *c == '漢').count(), 5);
        assert!(wide.ends_with('…'));

        // Combining marks do not consume a column, so a width budget alone would let a
        // 60 kB grave-accented letter through. Cap the run and the character count.
        let combining = format!("b{}", "\u{0300}".repeat(1000));
        let scrubbed = human(&combining, FIELD_COLUMNS);
        assert!(
            scrubbed.chars().count() <= FIELD_COLUMNS * 4 + 1,
            "combining-mark names stay bounded: {} characters",
            scrubbed.chars().count()
        );
        assert_ne!(
            scrubbed, "b",
            "a capped combining run is still not the clean name"
        );
        assert_ne!(
            scrubbed, "build-linux",
            "a combining-mark name must not collide with a real hostname"
        );
        let marks = scrubbed.chars().filter(|c| *c == '\u{0300}').count();
        assert!(
            marks <= 2,
            "combining marks are capped per base: {scrubbed:?}"
        );
    }

    #[test]
    fn a_url_is_removed_wherever_it_appears_and_the_rest_of_the_sentence_survives() {
        assert_eq!(
            redact_urls("To authenticate, visit: https://login.example/a/SECRET now"),
            "To authenticate, visit: <redacted url> now"
        );
        assert_eq!(
            redact_urls("see http://a/1 and HTTPS://B/2"),
            "see <redacted url> and <redacted url>"
        );
        assert_eq!(
            redact_urls("no scheme here, just the word http and httpd"),
            "no scheme here, just the word http and httpd"
        );
        assert_eq!(redact_urls("https://only"), "<redacted url>");
        assert_eq!(redact_urls("plain text"), "plain text");
    }

    #[test]
    fn an_authentication_url_on_stderr_never_reaches_a_stored_field() {
        // Both shapes the client prints: the indented three-line form, and the one-line
        // form `tailscale status` uses when a node key has expired.
        for name in ["auth-url.stderr", "auth-url-oneline.stderr"] {
            let inventory = classify(b"", &fixture(name), Some(1));
            let rendered = serde_json::to_string(&inventory).expect("serializes");
            assert!(
                !rendered.contains("login.example") && !rendered.contains("0123456789abcdef"),
                "{name}: the URL a person would click to join a device to the tailnet \
                 reached output: {rendered}"
            );
        }

        let one_line = classify(b"", &fixture("auth-url-oneline.stderr"), Some(1));
        assert!(
            one_line
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("<redacted url>")),
            "and the sentence still says what happened: {:?}",
            one_line.detail
        );
    }

    /// An unbounded stderr line is an unbounded line on someone's terminal.
    #[test]
    fn the_clients_own_message_is_bounded_before_it_is_stored() {
        let shouting = format!("{}\n", "z".repeat(9000));
        let inventory = classify(b"", shouting.as_bytes(), Some(1));
        let detail = inventory.detail.expect("a detail");
        assert!(
            detail.chars().count() <= MESSAGE_COLUMNS + 64,
            "a client's line cannot fill a screen: {} characters",
            detail.chars().count()
        );
    }

    #[test]
    fn a_peer_is_resolved_by_the_clients_own_fields_and_never_invented() {
        let inventory = running();
        let standalone = Summary {
            profile: None,
            tls: false,
            problems: Vec::new(),
        };
        let address = Ipv4Addr::new(100, 64, 12, 44);
        for spelling in [
            "build-linux",
            "BUILD-LINUX",
            "build-linux.tailnet-example.ts.net",
            "build-linux.tailnet-example.ts.net.",
            "100.64.12.44",
        ] {
            assert_eq!(
                resolve_peer(&standalone, &inventory, spelling),
                PeerResolution::One(address),
                "`{spelling}` names the same visible device"
            );
        }
        // A well-formed address is not an address this client reported. Probing one
        // would turn `--peer` into a way to send packets to anything on the overlay.
        assert_eq!(
            resolve_peer(&standalone, &inventory, "100.64.12.99"),
            PeerResolution::None
        );
        assert_eq!(
            resolve_peer(&standalone, &inventory, "203.0.113.7"),
            PeerResolution::None
        );
        assert_eq!(
            resolve_peer(&standalone, &inventory, "not-a-device"),
            PeerResolution::None
        );
        assert_eq!(
            resolve_peer(&standalone, &inventory, "  "),
            PeerResolution::None
        );
    }

    /// The real tailnet these fixtures came from has a peer literally named `localhost`.
    /// Two devices answering to one name is an ordinary Tuesday, and picking whichever a
    /// map iterated first would probe a device the operator did not mean.
    #[test]
    fn an_ambiguous_name_is_refused_rather_than_resolved_to_whichever_came_first() {
        let inventory = classify(&fixture("duplicate-names.json"), b"", Some(0));
        let standalone = Summary {
            profile: None,
            tls: false,
            problems: Vec::new(),
        };
        let PeerResolution::Ambiguous(mut candidates) =
            resolve_peer(&standalone, &inventory, "build-linux")
        else {
            panic!("two devices answer to `build-linux`");
        };
        candidates.sort();
        assert_eq!(
            candidates,
            vec![
                Ipv4Addr::new(100, 64, 12, 44),
                Ipv4Addr::new(100, 64, 12, 200)
            ]
        );

        // Their unique MagicDNS names still resolve, which is the way out of it.
        assert_eq!(
            resolve_peer(&standalone, &inventory, "aaa.tailnet-example.ts.net"),
            PeerResolution::One(Ipv4Addr::new(100, 64, 12, 44))
        );
    }

    /// HIGH-3, the resolution half. A device that renames itself after a roster machine
    /// must not capture that machine's probe.
    #[test]
    fn a_roster_name_resolves_through_the_operators_own_profile_not_a_peers_hostname() {
        let spoofed = classify(&fixture("roster-spoof.json"), b"", Some(0));
        let summary = summary_with(&[("attic", "100.64.12.77")]);

        assert_eq!(
            resolve_peer(&summary, &spoofed, "attic"),
            PeerResolution::None,
            "the real attic is not visible, and the impostor does not stand in for it"
        );

        // The same name resolves to the real member as soon as the member is the device
        // at that address — which is the only thing that makes it the member.
        let honest = classify(&fixture("running-with-peers.json"), b"", Some(0));
        let honest_summary = summary_with(&[("buildbox", "100.64.12.44")]);
        assert_eq!(
            resolve_peer(&honest_summary, &honest, "buildbox"),
            PeerResolution::One(Ipv4Addr::new(100, 64, 12, 44))
        );

        // And the impostor is still reachable under the name it actually owns.
        assert_eq!(
            resolve_peer(&summary, &spoofed, "impostor.tailnet-example.ts.net"),
            PeerResolution::One(Ipv4Addr::new(100, 64, 12, 250))
        );
    }

    /// HIGH-3, the inventory half.
    #[test]
    fn a_device_that_adopts_a_roster_name_is_listed_as_itself_and_named_as_a_conflict() {
        let spoofed = classify(&fixture("roster-spoof.json"), b"", Some(0));
        let summary = summary_with(&[("attic", "100.64.12.77")]);
        let rows = device_rows(&summary, &spoofed);

        let member = state_of(&rows, "attic");
        assert_eq!(
            member.state,
            DeviceState::FleetMemberNotVisible,
            "the roster row belongs to the advertised address, and nothing is there"
        );
        assert_eq!(member.address.as_deref(), Some("100.64.12.77"));
        assert_eq!(
            member.os, None,
            "the impostor's platform is not the member's"
        );
        assert_eq!(member.online, None);

        // The impostor is still listed — it is a real device on this network — under its
        // own identity, with the collision said out loud.
        let impostor = rows
            .iter()
            .find(|row| row.address.as_deref() == Some("100.64.12.250"))
            .expect("the impostor is listed as the separate device it is");
        assert_eq!(impostor.machine, None);
        assert_eq!(
            impostor.name_conflict.as_deref(),
            Some("attic"),
            "a device wearing a member's name is named as doing so"
        );
        assert_eq!(
            impostor.state,
            DeviceState::UnsupportedPlatform,
            "it is a Windows box, judged on what it reported about itself"
        );

        let text = render_devices(&summary, &spoofed);
        assert!(
            text.contains("It is not that machine."),
            "the human list says so too: {text}"
        );
    }

    // ------------------------------------------------------------------- the device rows

    fn summary_with(members: &[(&str, &str)]) -> Summary {
        summary_at("100.64.12.21", members)
    }

    fn summary_at(host: &str, members: &[(&str, &str)]) -> Summary {
        let profile = fleet::Profile {
            tags: json!({"tags": []}),
            schema: 1,
            fleet_id: "f".into(),
            name: "studio's fleet".into(),
            machine: "studio".into(),
            host: host.to_string(),
            node: format!("ouro-studio@{host}"),
            role: "core".into(),
            members: std::iter::once(fleet::Member {
                machine: "studio".into(),
                host: host.to_string(),
                node: format!("ouro-studio@{host}"),
            })
            .chain(members.iter().map(|(machine, host)| fleet::Member {
                machine: (*machine).to_string(),
                host: (*host).to_string(),
                node: format!("ouro-{machine}@{host}"),
            }))
            .collect(),
            tombstones: Vec::new(),
            roster_revision: 1,
            gateway_port: 1,
            epmd_port: 2,
            dist_port_min: 3,
            dist_port_max: 4,
        };
        Summary {
            profile: Some(profile),
            tls: true,
            problems: Vec::new(),
        }
    }

    fn state_of<'a>(rows: &'a [DeviceRow], name: &str) -> &'a DeviceRow {
        rows.iter().find(|row| row.name == name).unwrap_or_else(|| {
            panic!(
                "a row for {name} in {:?}",
                rows.iter().map(|r| &r.name).collect::<Vec<_>>()
            )
        })
    }

    /// The device's own reported name wins over its DNS label, and the DNS label is the
    /// fallback rather than the other way round: `App::machine_label` applies the same
    /// preference in the UI, and two surfaces calling one device two names is how an
    /// operator ends up deploying to the wrong one.
    #[test]
    fn a_devices_own_name_wins_over_its_dns_label_and_the_label_is_the_fallback() {
        let named = Device {
            host_name: Some("build-linux".into()),
            dns_name: Some("zzz.tailnet-example.ts.net".into()),
            ..Device::default()
        };
        assert_eq!(named.display_name().as_deref(), Some("build-linux"));

        let unnamed = Device {
            host_name: None,
            dns_name: Some("zzz.tailnet-example.ts.net".into()),
            ..Device::default()
        };
        assert_eq!(unnamed.display_name().as_deref(), Some("zzz"));

        let blank = Device {
            host_name: Some("   ".into()),
            dns_name: Some("zzz.tailnet-example.ts.net".into()),
            ..Device::default()
        };
        assert_eq!(
            blank.display_name().as_deref(),
            Some("zzz"),
            "a whitespace-only hostname is no name at all"
        );

        assert_eq!(Device::default().display_name(), None);
    }

    #[test]
    fn a_visible_peer_is_never_labelled_uninstalled_before_it_is_inspected() {
        let rows = device_rows(&summary_with(&[]), &running());
        let discovered = state_of(&rows, "build-linux");
        assert_eq!(
            discovered.state,
            DeviceState::DiscoveredInstallationUnknown,
            "an Ouroboros state is established by a preflight, not by discovery"
        );
        assert_eq!(discovered.action, "deploy Ouroboros");
        assert_eq!(discovered.address.as_deref(), Some("100.64.12.44"));
    }

    #[test]
    fn each_blocker_in_the_proposals_table_is_its_own_row_state() {
        let rows = device_rows(&summary_with(&[]), &running());
        assert_eq!(state_of(&rows, "old-pi").state, DeviceState::PeerOffline);
        assert_eq!(
            state_of(&rows, "pocket-phone").state,
            DeviceState::UnsupportedPlatform,
            "an iOS device has no Ouroboros release to deploy"
        );
        assert_eq!(
            state_of(&rows, "ipv6-only-box").state,
            DeviceState::NoUsableIpv4
        );
    }

    #[test]
    fn a_roster_member_keeps_the_operators_name_and_a_missing_one_is_not_powered_off() {
        let summary = summary_with(&[("buildbox", "100.64.12.44"), ("attic", "100.64.12.77")]);
        let rows = device_rows(&summary, &running());

        let member = state_of(&rows, "buildbox");
        assert_eq!(
            member.state,
            DeviceState::FleetMember,
            "a visible roster member is a member, matched on the client's own fields"
        );
        assert_eq!(member.machine.as_deref(), Some("buildbox"));
        assert_eq!(member.os.as_deref(), Some("linux"));
        assert!(
            !rows.iter().any(|row| row.name == "build-linux"),
            "the matched peer is not listed a second time under its own hostname"
        );

        let absent = state_of(&rows, "attic");
        assert_eq!(absent.state, DeviceState::FleetMemberNotVisible);
        assert_eq!(
            absent.online, None,
            "not visible is not known to be offline"
        );
        assert_eq!(absent.action, "diagnose");
    }

    /// This machine's row describes this machine, and it has not observed a path to
    /// itself when there is no client to observe one with.
    #[test]
    fn the_self_row_reports_the_path_the_client_observed_and_not_a_hardcoded_one() {
        let blind = Inventory::failed(DiscoveryCode::ClientMissing, None, "install it");
        let rows = device_rows(&summary_with(&[]), &blind);
        assert_eq!(
            rows[0].path,
            PathObservation::Unknown,
            "with no network client there is no observed path to report"
        );
        assert_eq!(rows[0].online, None, "and no presence either");

        // `running-with-peers.json` reports an empty `CurAddr` for Self, so even a
        // working client leaves this unknown rather than direct.
        let rows = device_rows(&summary_with(&[]), &running());
        assert_eq!(rows[0].path, PathObservation::Unknown);

        let observed = Inventory {
            self_device: Some(Device {
                path: PathObservation::Direct,
                ..Device::default()
            }),
            ..running()
        };
        assert_eq!(
            device_rows(&summary_with(&[]), &observed)[0].path,
            PathObservation::Direct
        );
    }

    #[test]
    fn a_machine_without_a_profile_is_offered_local_setup_and_keeps_its_peers() {
        let standalone = Summary {
            profile: None,
            tls: false,
            problems: Vec::new(),
        };
        let rows = device_rows(&standalone, &running());
        assert_eq!(
            rows[0].state,
            DeviceState::ThisDeviceWithoutProfile,
            "the current device without a fleet profile sets itself up locally"
        );
        assert_eq!(rows[0].name, "operator-laptop");
        assert!(rows.len() > 1, "discovery still lists the visible peers");
        assert!(!status_ready(&standalone));
    }

    #[test]
    fn known_members_survive_a_client_that_cannot_answer() {
        let summary = summary_with(&[("buildbox", "100.64.12.44")]);
        let blind = classify(&fixture("stopped.json"), b"", Some(0));
        let rows = device_rows(&summary, &blind);
        assert_eq!(
            state_of(&rows, "buildbox").state,
            DeviceState::FleetMemberNotVisible,
            "a client that cannot answer is not evidence that the fleet has no members"
        );
        assert_eq!(rows.len(), 2, "this machine and its one roster member");
    }

    // --------------------------------------------------------------------- the JSON shapes

    #[test]
    fn the_json_shapes_carry_stable_codes_and_null_for_what_is_unknown() {
        let summary = summary_with(&[("attic", "100.64.12.77")]);
        let value = devices_json(&summary, &running());
        assert_eq!(value["discovery"]["code"], "ok");
        assert!(value["discovery"]["reason"].is_null());
        assert_eq!(value["discovery"]["visible_peers"], 4);

        let devices = value["devices"].as_array().expect("an array");
        let absent = devices
            .iter()
            .find(|row| row["name"] == "attic")
            .expect("the roster member with no visible peer");
        assert_eq!(absent["state"], "fleet_member_not_visible");
        assert!(absent["online"].is_null(), "an unknown fact is null");
        assert!(absent["os"].is_null());

        let linux = devices
            .iter()
            .find(|row| row["name"] == "build-linux")
            .expect("the Linux peer");
        assert_eq!(
            linux["node_key"],
            "nodekey:b2c3d4e5b2c3d4e5b2c3d4e5b2c3d4e5b2c3d4e5b2c3d4e5b2c3d4e5b2c3d4e5"
        );
        assert_eq!(linux["stable_id"], "n1000000000000020CNTRL");
        assert_eq!(
            value["discovery"]["self"]["node_key"],
            "nodekey:a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"
        );
        assert_eq!(
            value["discovery"]["self"]["stable_id"],
            "n1000000000000010CNTRL"
        );

        let unavailable = devices_json(&summary, &classify(&fixture("stopped.json"), b"", Some(0)));
        assert_eq!(unavailable["discovery"]["code"], "unavailable");
        assert_eq!(unavailable["discovery"]["reason"], "backend_stopped");
        assert!(unavailable["discovery"]["self"].is_null());
    }

    #[test]
    fn status_json_names_the_build_and_refuses_to_call_an_unset_machine_ready() {
        let summary = summary_with(&[]);
        let value = status_json(&summary, &running(), None);
        assert_eq!(
            value["build"]["fleet_protocol_revision"],
            fleet_protocol::FLEET_PROTOCOL_REVISION
        );
        assert_eq!(value["ready"], true);
        assert_eq!(value["profile"]["machine"], "studio");
        assert!(
            value["live"].is_null(),
            "a stopped runtime is null, not false"
        );

        let broken = Summary {
            profile: summary.profile.clone(),
            tls: false,
            problems: vec!["a missing certificate".into()],
        };
        let value = status_json(&broken, &running(), None);
        assert_eq!(value["ready"], false);
        assert_eq!(value["problems"][0], "a missing certificate");
    }

    /// What the layers claim and what the command exits with are one fact, checked
    /// together: a layer that says `problem` while `healthy` stays true would be a
    /// verdict an operator cannot act on.
    #[test]
    fn a_layers_problem_flag_and_the_commands_verdict_are_the_same_fact() {
        let report = fleet::doctor_stopped(fleet::doctor(Path::new("/nonexistent/data-dir")));
        let reachable = RouteProbe {
            code: RouteCode::Reachable,
            peer: "buildbox".into(),
            address: Some(Ipv4Addr::new(100, 64, 12, 44)),
            path: PathObservation::Relayed,
            detail: "pong".into(),
        };

        for inventory in [
            Inventory::failed(DiscoveryCode::ClientMissing, None, "install it"),
            Inventory::failed(DiscoveryCode::SignedOut, None, "sign in"),
            running(),
        ] {
            // A fleet configured by hand over a private LAN has no client to find, and
            // that is not a broken fleet: the layer never changes the verdict.
            let without = doctor_json(&report, &inventory, None);
            assert_eq!(
                without["layers"]["network_client"]["problem"], false,
                "{:?} must not fail a doctor nobody asked to probe anything",
                inventory.code
            );
            assert_eq!(
                without["healthy"],
                doctor_healthy(&report, None),
                "the document's verdict is the command's exit code"
            );

            let asked = doctor_json(&report, &inventory, Some(&reachable));
            assert_eq!(asked["layers"]["device_route"]["problem"], false);
            assert_eq!(asked["layers"]["device_route"]["path"], "relayed");
        }

        // Every probe outcome that is not `reachable` is a problem, and each one turns
        // the verdict — this is the only thing in these layers that can.
        for code in [
            RouteCode::TimedOut,
            RouteCode::Unknown,
            RouteCode::PeerUnknown,
            RouteCode::PeerAmbiguous,
        ] {
            let probe = RouteProbe {
                code,
                ..reachable.clone()
            };
            assert_eq!(doctor_route_layer(&probe)["problem"], true, "{code:?}");
            assert!(
                !doctor_healthy(&report, Some(&probe)),
                "{code:?} must fail the command the operator ran"
            );
        }
    }

    #[test]
    fn the_human_layers_say_what_was_observed_and_what_was_not() {
        let text = render_doctor_layers(
            &summary_at("10.9.9.9", &[]),
            &running(),
            Some(&RouteProbe {
                code: RouteCode::Reachable,
                peer: "buildbox".into(),
                address: Some(Ipv4Addr::new(100, 64, 12, 44)),
                path: PathObservation::Unknown,
                detail: "pong from build-linux".into(),
            }),
        );
        assert!(text.contains("Network client — 1.102.1"));
        assert!(text.contains("connection path not observed"));
        assert!(text.contains("does not establish that the distribution ports are open"));

        // A layer that never changes the verdict never prints the marker that means the
        // verdict changed. `[fix]` beside "locally ready" and a zero exit is a lie in
        // three lines.
        assert!(
            !text.contains("[fix]"),
            "these layers are notes, and the verdict says so: {text}"
        );
        assert!(
            text.contains("[note] this fleet advertises 10.9.9.9"),
            "the advertised address and the discovered one are named separately: {text}"
        );
        assert!(
            !text.contains("advertised address 100.64.12.21"),
            "the discovered address is never described as the advertised one: {text}"
        );

        // When they are the same address there is nothing to warn about.
        let same = render_doctor_layers(&summary_with(&[]), &running(), None);
        assert!(!same.contains("this fleet advertises"), "{same}");
        assert!(!same.contains("[fix]"), "{same}");
    }

    #[test]
    fn the_human_device_list_separates_the_fleet_from_the_network() {
        let text = render_devices(&summary_with(&[("attic", "100.64.12.77")]), &running());
        assert!(text.starts_with("Fleet devices\n"));
        assert!(text.contains("Available on this network"));
        assert!(text.contains("no device was inspected"));

        let blind = render_devices(
            &summary_with(&[("attic", "100.64.12.77")]),
            &classify(&fixture("stopped.json"), b"", Some(0)),
        );
        assert!(
            blind.contains("attic"),
            "known members survive blind discovery"
        );
        assert!(blind.contains("stopped"));
    }

    /// `suggested_machine` is for a form, and a form only.
    ///
    /// It exists so a setup form can be pre-filled with a name the validator will take,
    /// instead of "Monocursive’s MacBook Pro" or "this device". It is not what a device
    /// is *called*: printing it in a terminal would show a person a name nothing on the
    /// network answers to, beside the name it does.
    #[test]
    fn the_suggested_form_name_is_in_the_json_and_never_in_the_terminal() {
        let summary = summary_with(&[("attic", "100.64.12.77")]);
        let value = devices_json(&summary, &running());
        let suggestions: Vec<(String, String)> = value["devices"]
            .as_array()
            .expect("devices")
            .iter()
            .filter_map(|row| {
                Some((
                    row["name"].as_str()?.to_string(),
                    row["suggested_machine"].as_str()?.to_string(),
                ))
            })
            .collect();
        assert!(
            !suggestions.is_empty(),
            "a form has something to pre-fill with: {value}"
        );
        for (_, suggestion) in &suggestions {
            fleet::validate_machine(suggestion)
                .unwrap_or_else(|error| panic!("`{suggestion}` is not a usable name: {error}"));
        }

        let text = render_devices(&summary, &running());
        for (name, suggestion) in &suggestions {
            if name == suggestion {
                // The device is already called something valid; there is nothing the
                // human list could be showing that the JSON invented.
                continue;
            }
            assert!(
                !text.contains(suggestion.as_str()),
                "`{suggestion}` is a form's pre-fill, not what `{name}` is called:\n{text}"
            );
        }
    }

    /// The `--json` `state` is a contract for scripts; a terminal column is prose. The
    /// two are checked against each other so neither can drift into the other's job.
    #[test]
    fn the_human_column_reads_as_words_and_the_json_keeps_the_codes() {
        let summary = summary_with(&[("attic", "100.64.12.77")]);
        let text = render_devices(&summary, &running());
        assert!(
            text.contains("not inspected yet · deploy Ouroboros"),
            "{text}"
        );
        assert!(
            text.contains("offline, not inspected · refresh or inspect"),
            "{text}"
        );
        assert!(
            text.contains("no supported release for this platform · nothing to deploy"),
            "{text}"
        );
        assert!(
            text.contains("in the fleet, not visible on this network · diagnose"),
            "{text}"
        );

        for state in [
            DeviceState::ThisDevice,
            DeviceState::ThisDeviceWithoutProfile,
            DeviceState::FleetMember,
            DeviceState::FleetMemberNotVisible,
            DeviceState::DiscoveredInstallationUnknown,
            DeviceState::PeerOffline,
            DeviceState::UnsupportedPlatform,
            DeviceState::NoUsableIpv4,
        ] {
            let code = serde_json::to_value(state).expect("a code");
            let code = code.as_str().expect("a string code");
            assert!(code.contains('_') || !code.contains(' '), "{code}");
            assert!(
                !text.contains(code),
                "the snake_case `{code}` belongs to --json and not to a terminal:\n{text}"
            );
            assert!(
                !state.label().contains('_'),
                "`{}` is a code, not prose",
                state.label()
            );
        }

        let value = devices_json(&summary, &running());
        let codes: Vec<_> = value["devices"]
            .as_array()
            .expect("devices")
            .iter()
            .map(|row| row["state"].as_str().expect("a state code").to_string())
            .collect();
        assert!(codes.contains(&"discovered_installation_unknown".to_string()));
        assert!(codes.contains(&"fleet_member_not_visible".to_string()));
    }

    // ------------------------------------------------------------------- bounded running

    fn tempdir() -> tempdir::TempDir {
        tempdir::TempDir::new("ouro-fleet-network")
    }

    /// A minimal owned temporary directory, so this module's tests need no new crate.
    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn new(prefix: &str) -> Self {
                let path = std::env::temp_dir().join(format!(
                    "{prefix}-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("a clock after 1970")
                        .as_nanos()
                ));
                std::fs::create_dir_all(&path).expect("a private temporary directory");
                Self(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).expect("writing a fake client");
        file.write_all(body.as_bytes())
            .expect("writing a fake client");
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("making the fake client executable");
        path
    }

    #[tokio::test]
    async fn the_deadline_kills_a_client_that_never_answers() {
        let dir = tempdir();
        let program = script(dir.path(), "slow", "#!/bin/sh\nsleep 30\n");
        let started = std::time::Instant::now();
        let error = run(&program, &["status"], Duration::from_millis(200))
            .await
            .expect_err("a client past its deadline is a failure");
        assert!(matches!(error, RunError::Timeout));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the child is killed on drop rather than waited on"
        );
    }

    #[tokio::test]
    async fn output_past_the_bound_is_refused_rather_than_truncated() {
        let dir = tempdir();
        // Five MiB on stdout, plus noise on stderr that must not deadlock the refusal.
        let program = script(
            dir.path(),
            "loud",
            "#!/bin/sh\nprintf 'warning\\n' >&2\n\
             head -c 5000000 /dev/zero | tr '\\0' 'a'\n",
        );
        let error = run(&program, &[], Duration::from_secs(20))
            .await
            .expect_err("more than 4 MiB is a refusal");
        assert!(
            matches!(error, RunError::TooMuchOutput),
            "half a JSON document parses as missing fields, so it is never accepted"
        );
    }

    #[tokio::test]
    async fn stderr_noise_before_the_json_does_not_break_a_discovery() {
        let dir = tempdir();
        let program = script(
            dir.path(),
            "tailscale",
            "#!/bin/sh\nprintf 'Warning: client version mismatch\\n' >&2\n\
             printf '{\"BackendState\":\"Running\",\"Self\":{\"HostName\":\"solo\"},\"Peer\":{}}'\n",
        );
        let inventory = inventory_with(&Client {
            program: program.clone(),
            source: ClientSource::Path,
        })
        .await;
        assert_eq!(inventory.code, DiscoveryCode::NoVisiblePeers);
        assert_eq!(
            inventory.client.program.as_deref(),
            Some(program.display().to_string().as_str())
        );
    }

    /// A complete, correct answer on stdout must not be thrown away because something
    /// the client left behind is still holding the stderr pipe.
    #[tokio::test]
    async fn a_grandchild_holding_stderr_does_not_turn_a_good_answer_into_a_timeout() {
        let dir = tempdir();
        let fixture_path = format!("{FIXTURES}/running-with-peers.json");
        let program = script(
            dir.path(),
            "tailscale",
            &format!(
                "#!/bin/sh\nprintf 'Warning: version skew\\n' >&2\n\
                 cat {fixture_path}\nsleep 120 >/dev/null 2>&1 &\nexit 0\n"
            ),
        );
        let started = std::time::Instant::now();
        let inventory = inventory_with(&Client {
            program,
            source: ClientSource::Path,
        })
        .await;
        assert_eq!(
            inventory.code,
            DiscoveryCode::Ok,
            "the child exited 0 with a complete document; an orphan on its stderr is not \
             this command's problem"
        );
        assert!(
            started.elapsed() < CLIENT_TIMEOUT,
            "and the answer came back inside the deadline, not at it"
        );
    }

    #[tokio::test]
    async fn a_client_that_cannot_be_started_is_missing_rather_than_broken() {
        let inventory = inventory_with(&Client {
            program: PathBuf::from("/nonexistent/tailscale"),
            source: ClientSource::Environment,
        })
        .await;
        assert_eq!(inventory.code, DiscoveryCode::ClientMissing);
    }

    #[test]
    fn the_bind_check_is_the_one_fleet_create_runs() {
        assert_eq!(bindable(Ipv4Addr::LOCALHOST), BindCheck::Bindable);
        // 192.0.2.0/24 is TEST-NET-1: reserved for documentation and never assigned to
        // an interface, so this is the "advertised address is not local" refusal.
        assert!(matches!(
            bindable(Ipv4Addr::new(192, 0, 2, 1)),
            BindCheck::NotBindable(_)
        ));
        assert_eq!(
            self_bindable(&Inventory::default()),
            BindCheck::Unknown,
            "no discovered address is unknown, not unbindable"
        );
    }
}
