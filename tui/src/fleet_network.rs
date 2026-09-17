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
const FALLBACK_PATHS: [&str; 4] = [
    "/opt/homebrew/bin/tailscale",
    "/usr/local/bin/tailscale",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/bin/tailscale",
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
    locate_client_with(
        std::env::var_os(CLIENT_ENV).as_deref(),
        std::env::var_os("PATH").as_deref(),
        &FALLBACK_PATHS,
    )
}

/// The lookup, with its three inputs named so a test can drive it without touching the
/// process environment — and without the real client on this machine answering for a
/// case that is supposed to have no client at all.
fn locate_client_with(
    override_path: Option<&OsStr>,
    search_path: Option<&OsStr>,
    fallbacks: &[&str],
) -> Option<Client> {
    if let Some(named) = override_path.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(named);
        // A rejected override is not a silent fall through to another program: an
        // operator who named a client meant that one.
        return executable(&path).then_some(Client {
            program: path,
            source: ClientSource::Environment,
        });
    }

    if let Some(search_path) = search_path {
        for directory in std::env::split_paths(search_path) {
            if directory.as_os_str().is_empty() {
                continue;
            }
            let candidate = directory.join("tailscale");
            if executable(&candidate) {
                return Some(Client {
                    program: candidate,
                    source: ClientSource::Path,
                });
            }
        }
    }

    fallbacks
        .iter()
        .map(PathBuf::from)
        .find(|path| executable(path))
        .map(|program| Client {
            program,
            source: ClientSource::KnownLocation,
        })
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
    let noise = tokio::spawn(async move {
        let mut captured = Vec::new();
        let _ = (&mut stderr)
            .take(MAX_OUTPUT as u64)
            .read_to_end(&mut captured)
            .await;
        let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
        captured
    });

    // The whole read owns the child, so dropping this future — a deadline, a cancelled
    // operator, a refusal below — drops the child and `kill_on_drop` signals it.
    let collected = tokio::time::timeout(timeout, async move {
        let mut out = Vec::new();
        let mut bounded = stdout.take(MAX_OUTPUT as u64 + 1);
        bounded.read_to_end(&mut out).await.map_err(RunError::Io)?;
        if out.len() > MAX_OUTPUT {
            return Err(RunError::TooMuchOutput);
        }
        let status = child.wait().await.map_err(RunError::Io)?;
        Ok(Captured {
            status: status.code(),
            stdout: out,
            stderr: noise.await.unwrap_or_default(),
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
pub async fn inventory() -> Inventory {
    match locate_client() {
        None => Inventory::failed(
            DiscoveryCode::ClientMissing,
            None,
            "install Tailscale and sign this machine in to the network the fleet uses, \
             or set OUROBOROS_TAILSCALE to an absolute path to the client",
        ),
        Some(client) => inventory_with(&client).await,
    }
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
        return Inventory::failed(
            DiscoveryCode::Unavailable,
            Some(UnavailableReason::ParseFailure),
            "the Tailscale client's status was not readable as JSON; this build of \
             Ouroboros may be older than the client",
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

fn first_line(text: &str) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no output");
    line.chars().take(300).collect()
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

/// Resolves an operator's `--peer` to one visible device's IPv4 address.
///
/// Accepts the device's hostname, its MagicDNS name or first label, or the address
/// itself. Matching is on the client's own reported fields; no address shape is assumed.
pub fn resolve_peer(inventory: &Inventory, peer: &str) -> Option<Ipv4Addr> {
    let wanted = peer.trim().trim_end_matches('.').to_ascii_lowercase();
    if wanted.is_empty() {
        return None;
    }
    if let Ok(address) = wanted.parse::<Ipv4Addr>() {
        return inventory
            .peers
            .iter()
            .chain(inventory.self_device.iter())
            .any(|device| device.ipv4 == Some(address))
            .then_some(address);
    }
    inventory
        .peers
        .iter()
        .chain(inventory.self_device.iter())
        .find(|device| {
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
        })
        .and_then(|device| device.ipv4)
}

/// One bounded overlay probe of one operator-selected device.
///
/// An overlay ping establishes that the two clients can exchange packets. It does not
/// establish that the distribution ports are open, which is why this is a separate
/// `doctor` layer from the runtime's own connectivity check.
pub async fn probe_route(inventory: &Inventory, peer: &str) -> RouteProbe {
    let unknown = |code: RouteCode, address, detail: String| RouteProbe {
        code,
        peer: peer.to_string(),
        address,
        path: PathObservation::Unknown,
        detail,
    };

    let Some(client) = locate_client() else {
        return unknown(
            RouteCode::Unknown,
            None,
            "no Tailscale client is installed to probe the route with".into(),
        );
    };
    let Some(address) = resolve_peer(inventory, peer) else {
        return unknown(
            RouteCode::PeerUnknown,
            None,
            format!(
                "`{peer}` does not match a device this machine's Tailscale client can \
                 see; run `ouro fleet devices` for the visible list"
            ),
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
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .to_string();

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
    if status == Some(0) {
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
            Self::PeerOffline => "refresh or inspect details",
            Self::UnsupportedPlatform => "no supported Ouroboros release",
            Self::NoUsableIpv4 => "no usable private IPv4 address",
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
            .unwrap_or_else(|| "this device".into()),
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
        path: PathObservation::Direct,
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
            .find(|(_index, peer)| matches_member(peer, &member.host, &member.machine));
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
        });
    }

    rows
}

/// Whether a visible peer is the roster member that advertises `host`.
///
/// The roster's host is an address or a private DNS name the operator chose. It is
/// compared against the peer's own reported fields — never against an address prefix.
fn matches_member(peer: &Device, host: &str, machine: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let machine = machine.trim().to_ascii_lowercase();
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
        peer.host_name.clone(),
    ];
    candidates.into_iter().flatten().any(|candidate| {
        let candidate = candidate.trim().to_ascii_lowercase();
        candidate == host || (!machine.is_empty() && candidate == machine)
    })
}

// ----------------------------------------------------------------------------- rendering

fn or_unknown(value: Option<&str>) -> &str {
    value.unwrap_or("unknown")
}

fn presence(row: &DeviceRow) -> String {
    match (row.online, row.last_seen.as_deref()) {
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
            Some(detail) => text.push_str(&format!("  {detail}\n")),
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

fn render_row(row: &DeviceRow) -> String {
    format!(
        "  {}\n      address      {}\n      platform     {}\n      network      {}\n      ouroboros    {} — {}\n",
        row.name,
        or_unknown(row.address.as_deref()),
        or_unknown(row.os.as_deref()),
        presence(row),
        serde_json::to_value(row.state)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".into()),
        row.action,
    )
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
pub fn render_doctor_layers(inventory: &Inventory, probe: Option<&RouteProbe>) -> String {
    let mut text = format!(
        "\nNetwork client — {}\n  {}\n",
        or_unknown(inventory.client.version.as_deref()),
        inventory.headline()
    );
    if let Some(detail) = &inventory.detail {
        text.push_str(&format!("  {detail}\n"));
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
        if let BindCheck::NotBindable(reason) = self_bindable(inventory) {
            text.push_str(&format!("  [fix] {reason}\n"));
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
            probe.peer,
            match probe.code {
                RouteCode::Reachable => "reachable over the private network",
                RouteCode::TimedOut => "the overlay probe timed out",
                RouteCode::Unknown => "the route could not be established",
                RouteCode::PeerUnknown => "no visible device matches that name",
            },
            probe.detail,
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

        let found = locate_client_with(None, Some(dir.path().as_os_str()), &["/nonexistent/x"])
            .expect("PATH answers when no override does");
        assert_eq!(found.program, on_path);
        assert_eq!(found.source, ClientSource::Path);
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
    }

    #[test]
    fn garbage_on_stdout_is_a_named_parse_failure() {
        let inventory = classify(b"<html>not json</html>", b"", Some(0));
        assert_eq!(inventory.code, DiscoveryCode::Unavailable);
        assert_eq!(inventory.reason, Some(UnavailableReason::ParseFailure));
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
    }

    #[test]
    fn a_peer_is_resolved_by_the_clients_own_fields_and_never_invented() {
        let inventory = running();
        let address = Ipv4Addr::new(100, 64, 12, 44);
        for spelling in [
            "build-linux",
            "BUILD-LINUX",
            "build-linux.tailnet-example.ts.net",
            "build-linux.tailnet-example.ts.net.",
            "100.64.12.44",
        ] {
            assert_eq!(
                resolve_peer(&inventory, spelling),
                Some(address),
                "`{spelling}` names the same visible device"
            );
        }
        assert_eq!(resolve_peer(&inventory, "100.64.12.99"), None);
        assert_eq!(resolve_peer(&inventory, "not-a-device"), None);
        assert_eq!(resolve_peer(&inventory, "  "), None);
    }

    // ------------------------------------------------------------------- the device rows

    fn summary_with(members: &[(&str, &str)]) -> Summary {
        let profile = fleet::Profile {
            tags: json!({"tags": []}),
            schema: 1,
            fleet_id: "f".into(),
            name: "studio's fleet".into(),
            machine: "studio".into(),
            host: "100.64.12.21".into(),
            node: "ouro-studio@100.64.12.21".into(),
            role: "core".into(),
            members: std::iter::once(fleet::Member {
                machine: "studio".into(),
                host: "100.64.12.21".into(),
                node: "ouro-studio@100.64.12.21".into(),
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

        let phone = devices
            .iter()
            .find(|row| row["name"] == "pocket-phone")
            .expect("the iOS peer");
        assert_eq!(phone["state"], "unsupported_platform");
        assert_eq!(phone["path"], "unknown");

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

    #[test]
    fn the_doctor_layers_fail_only_on_what_was_asked_for() {
        let missing = Inventory::failed(DiscoveryCode::ClientMissing, None, "install it");
        assert_eq!(
            doctor_network_layer(&missing)["problem"],
            false,
            "a private LAN fleet has no client to find, and that is not a broken fleet"
        );

        let reachable = RouteProbe {
            code: RouteCode::Reachable,
            peer: "buildbox".into(),
            address: Some(Ipv4Addr::new(100, 64, 12, 44)),
            path: PathObservation::Relayed,
            detail: "pong".into(),
        };
        assert_eq!(doctor_route_layer(&reachable)["problem"], false);
        assert_eq!(doctor_route_layer(&reachable)["path"], "relayed");

        let timed_out = RouteProbe {
            code: RouteCode::TimedOut,
            ..reachable
        };
        assert_eq!(doctor_route_layer(&timed_out)["problem"], true);
    }

    #[test]
    fn the_human_layers_say_what_was_observed_and_what_was_not() {
        let text = render_doctor_layers(
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
    }

    #[test]
    fn the_human_device_list_separates_the_fleet_from_the_network() {
        let text = render_devices(&summary_with(&[("attic", "100.64.12.77")]), &running());
        assert!(text.starts_with("Fleet devices\n"));
        assert!(text.contains("Available on this network"));
        assert!(text.contains("discovered_installation_unknown — deploy Ouroboros"));
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
