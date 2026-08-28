//! Add another trusted machine from the first Ouroboros instance.
//!
//! The operator-facing shape is one command, two transports:
//!
//! - `ouro fleet add user@host` probes the destination over SSH (or Tailscale SSH),
//!   copies a matching `ouro` binary when that is honest, copies one private invitation
//!   as a file, and runs `ouro fleet enroll` there.
//! - `ouro fleet add --print-script` (and the TUI "I'll set it up myself" path) writes
//!   the same invitation locally and prints a short enroll recipe. Use this when the
//!   Linux laptop is asleep, when SSH is not available from this Mac, or when the
//!   destination architecture cannot run this Mac's binary.
//!
//! The invitation never appears on a command line, in argv, or in progress text. A
//! mismatched OS/CPU is a named limit, not a silent copy of the wrong ERTS — but when a
//! release artifact for that exact OS/CPU *and* this exact version is already sitting in
//! a `dist` directory, the add finds it and copies that instead of refusing.
//!
//! `--setup-tailscale` is the one place this file changes the destination beyond
//! Ouroboros' own files: with that consent it runs the vendor's Tailscale installer and
//! `tailscale up` as root there, surfaces the sign-in URL on this terminal, and waits for
//! a tailnet address. Without it, a destination with no private address is refused, as
//! before.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::fleet::{self, Ports};

/// How this Mac reaches the other machine's shell.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Via {
    #[default]
    Ssh,
    Tailscale,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Tailscale => "tailscale",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ssh" => Ok(Self::Ssh),
            "tailscale" => Ok(Self::Tailscale),
            other => bail!("--via must be ssh or tailscale, got {other}"),
        }
    }
}

/// Where guided-enrollment progress and the Tailscale sign-in URL go.
///
/// The URL is operator-facing, time-critical, and credential-bearing, so it is written
/// straight to the terminal and never into the add log, an invitation, or a howto file.
pub trait Notify {
    fn line(&mut self, text: &str);
}

/// Production for the CLI: stderr, so a piped `ouro fleet add` still shows the URL.
#[derive(Clone, Copy, Debug, Default)]
pub struct StderrNotify;

impl Notify for StderrNotify {
    fn line(&mut self, text: &str) {
        eprintln!("{text}");
    }
}

/// The TUI owns the whole screen; nothing may be printed underneath it.
#[derive(Clone, Copy, Debug, Default)]
pub struct SilentNotify;

impl Notify for SilentNotify {
    fn line(&mut self, _text: &str) {}
}

/// How long guided Tailscale enrollment waits, and how often it asks. Split out of the
/// flow so the timeout path is a test rather than five real minutes of waiting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollBudget {
    pub interval: Duration,
    /// Rounds spent waiting for `tailscale up` to print its sign-in URL.
    pub url_attempts: u32,
    /// Rounds spent waiting for the operator to finish that sign-in.
    pub ip_attempts: u32,
}

impl Default for PollBudget {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            url_attempts: 24,
            ip_attempts: 60,
        }
    }
}

impl PollBudget {
    fn url_window(self) -> Duration {
        self.interval * self.url_attempts.max(1)
    }

    fn ip_window(self) -> Duration {
        self.interval * self.ip_attempts.max(1)
    }
}

/// Everything one add may do beyond addressing. `Default` is exactly the flow that
/// shipped before: no guided enrollment, dist artifacts discovered from the environment.
#[derive(Clone, Debug, Default)]
pub struct AddOptions {
    /// Operator consent for guided Tailscale enrollment. It runs the vendor's installer
    /// and `tailscale up` as root on the destination.
    pub setup_tailscale: bool,
    /// Overrides where a cross-platform dist artifact is looked for. `None` discovers the
    /// roots from `OUROBOROS_DIST_DIR`, this executable's real path, and the CWD.
    pub dist_roots: Option<Vec<PathBuf>>,
    pub tailscale_poll: PollBudget,
}

/// What a successful add did, without repeating invitation bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub machine: String,
    pub host: String,
    pub kind: OutcomeKind,
    pub log: Vec<String>,
    pub recipe: Option<Recipe>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutcomeKind {
    /// SSH reached the host, the matching binary was installed or already present, and
    /// enroll ran there.
    Enrolled,
    /// SSH reached the host and the invitation is waiting, but this Mac cannot install
    /// the right binary. The recipe is what remains.
    InviteDelivered,
    /// No SSH. The invitation is on this Mac; the recipe is what to run on the other one.
    Prepared,
    /// This Mac became a fleet owner; no second machine was added yet.
    Created,
    /// This Mac joined from a copied invitation and is ready to run.
    Joined,
}

/// Operator-facing steps that never include cookies, keys, or invitation JSON.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipe {
    pub machine: String,
    pub invite_path: PathBuf,
    pub lines: Vec<String>,
}

impl Recipe {
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }
}

/// Facts this Mac needs before it can invite. None of these are credentials.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Probe {
    pub os: String,
    pub arch: String,
    pub home: String,
    pub ouro: Option<String>,
    pub ouro_version: Option<String>,
    pub tailscale_ip: Option<String>,
    pub tailscale_dns: Option<String>,
    pub hostname: Option<String>,
}

impl Probe {
    pub fn triple(&self) -> Result<String> {
        triple(&self.os, &self.arch)
    }

    pub fn suggested_host(&self) -> Option<String> {
        self.tailscale_dns
            .clone()
            .or_else(|| self.tailscale_ip.clone())
    }

    pub fn suggested_machine(&self) -> Option<String> {
        self.hostname
            .as_deref()
            .or(self.tailscale_dns.as_deref())
            .and_then(|value| fleet::machine_from_host(value).ok())
    }
}

/// This Mac's Tailscale identity, for the owner-host field on a first add.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalIdentity {
    pub machine: Option<String>,
    pub host: Option<String>,
}

/// A host this operator already knows, from Tailscale or `~/.ssh/config`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub source: CandidateSource,
    pub label: String,
    pub target: String,
    pub host: Option<String>,
    pub os: Option<String>,
    pub online: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateSource {
    Tailscale,
    SshConfig,
}

/// Non-secret restart plan used when the first Mac is still standalone.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Intent {
    pub schema: u8,
    pub owner_machine: String,
    pub owner_host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add: Option<AddPlan>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddPlan {
    pub kind: AddKind,
    pub machine: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub via: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddKind {
    Ssh,
    Prepare,
}

/// Non-secret restart plan for joining from a copied invitation on this machine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JoinIntent {
    pub schema: u8,
    pub invitation: String,
    #[serde(default)]
    pub delete: bool,
    #[serde(default)]
    pub service: bool,
}

const INTENT_SCHEMA: u8 = 1;
const PROBE_SCRIPT: &str = r#"set -e
printf 'os=%s\n' "$(uname -s)"
printf 'arch=%s\n' "$(uname -m)"
printf 'home=%s\n' "$HOME"
printf 'hostname=%s\n' "$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)"
if command -v ouro >/dev/null 2>&1; then
  printf 'ouro=%s\n' "$(command -v ouro)"
  ouro version 2>/dev/null | awk 'NR == 1 {print "version=" $0}'
else
  printf 'ouro=\n'
fi
if command -v tailscale >/dev/null 2>&1; then
  printf 'tailscale=yes\n'
  printf 'tailscale_ip=%s\n' "$(tailscale ip -4 2>/dev/null | head -n 1)"
  printf 'tailscale_dns=%s\n' "$(tailscale status --json 2>/dev/null | tr -d '\n' | sed -n 's/.*"Self":{.*"DNSName":"\([^"]*\)".*/\1/p')"
else
  printf 'tailscale=no\n'
fi
"#;

/// The vendor's own documented one-liner, printed verbatim before it runs because it
/// downloads and executes code as root on someone else's machine. `curl` stays
/// unprivileged; only the shell that interprets the script is elevated.
const TAILSCALE_INSTALL: &str = "curl -fsSL https://tailscale.com/install.sh | sudo -n sh";

/// Both facts guided enrollment branches on, in one round trip. It always exits 0 so a
/// missing `tailscale` or a locked-down `sudo` is an answer rather than a transport error.
const TAILSCALE_CAPABILITY_SCRIPT: &str = r#"if command -v tailscale >/dev/null 2>&1; then
  printf 'tailscale=present\n'
else
  printf 'tailscale=missing\n'
fi
if sudo -n true >/dev/null 2>&1; then
  printf 'sudo=yes\n'
else
  printf 'sudo=no\n'
fi
"#;

/// `tailscale up` blocks until the operator authenticates, so it is started detached with
/// its output in a private temp file this flow then polls. An address already present
/// means a rerun of the same add: report it and start nothing.
const TAILSCALE_UP_SCRIPT: &str = r#"existing=$(tailscale ip -4 2>/dev/null | head -n 1)
if [ -n "$existing" ]; then
  printf 'state=up\n'
  exit 0
fi
umask 077
log=$(mktemp /tmp/ouro-tailscale-up.XXXXXX) || exit 1
nohup sudo -n tailscale up </dev/null >"$log" 2>&1 &
printf 'state=starting\n'
printf 'log=%s\n' "$log"
"#;

const TAILSCALE_IP_SCRIPT: &str = r#"printf 'ip=%s\n' "$(tailscale ip -4 2>/dev/null | head -n 1)"
"#;

/// Remote shell used by [`add_with`]. Tests inject a fake; production uses SSH.
pub trait Remote {
    fn run(&self, target: &str, script: &str) -> Result<String>;
    fn copy_to(&self, local: &Path, target: &str, remote_path: &str) -> Result<()>;
}

#[derive(Clone, Copy, Debug)]
pub struct SshRemote {
    pub via: Via,
}

impl Remote for SshRemote {
    fn run(&self, target: &str, script: &str) -> Result<String> {
        let output = ssh_command(self.via, target)
            .arg(script)
            .output()
            .with_context(|| format!("running {} against {target}", self.via.as_str()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "{} {target} failed ({status}): {stderr}",
                self.via.as_str(),
                status = output.status
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn copy_to(&self, local: &Path, target: &str, remote_path: &str) -> Result<()> {
        let spec = format!("{target}:{remote_path}");
        let output = match self.via {
            Via::Ssh => {
                let mut command = Command::new("scp");
                command
                    .arg("-o")
                    .arg("BatchMode=yes")
                    .arg("-p")
                    .arg(local)
                    .arg(&spec);
                command
                    .output()
                    .with_context(|| format!("copying {} to {spec}", local.display()))?
            }
            Via::Tailscale => {
                // `tailscale scp` is not universal; file copy over `tailscale ssh` cat
                // keeps the invitation off argv and works with Tailscale SSH ACLs.
                let bytes = fs::read(local).with_context(|| {
                    format!("reading {} to copy over Tailscale SSH", local.display())
                })?;
                let mut child = ssh_command(Via::Tailscale, target)
                    .arg(format!(
                        "umask 077 && cat > {remote_path}.partial && mv {remote_path}.partial {remote_path} && chmod 600 {remote_path}"
                    ))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .with_context(|| format!("starting tailscale ssh to copy onto {target}"))?;
                {
                    let stdin = child.stdin.as_mut().ok_or_else(|| {
                        anyhow!("tailscale ssh stdin was not available for the invitation copy")
                    })?;
                    stdin
                        .write_all(&bytes)
                        .context("writing the invitation over Tailscale SSH")?;
                }
                let output = child
                    .wait_with_output()
                    .context("waiting for the Tailscale SSH invitation copy")?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    bail!(
                        "tailscale ssh copy to {target} failed ({status}): {stderr}",
                        status = output.status
                    );
                }
                return Ok(());
            }
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "scp to {spec} failed ({status}): {stderr}",
                status = output.status
            );
        }
        Ok(())
    }
}

fn ssh_command(via: Via, target: &str) -> Command {
    match via {
        Via::Ssh => {
            let mut command = Command::new("ssh");
            command.arg("-o").arg("BatchMode=yes").arg(target);
            command
        }
        Via::Tailscale => {
            let mut command = Command::new("tailscale");
            command.arg("ssh").arg(target);
            command
        }
    }
}

pub fn local_triple() -> Result<String> {
    triple(std::env::consts::OS, std::env::consts::ARCH)
}

pub fn triple(os: &str, arch: &str) -> Result<String> {
    let os = os.trim().to_ascii_lowercase();
    let arch = arch.trim().to_ascii_lowercase();
    let arch = match arch.as_str() {
        "arm64" | "aarch64" => "aarch64",
        "x86_64" | "amd64" => "x86_64",
        other => bail!("unsupported CPU architecture `{other}` for a packaged ouro binary"),
    };
    match os.as_str() {
        "darwin" | "macos" => Ok(format!("{arch}-apple-darwin")),
        "linux" => Ok(format!("{arch}-unknown-linux-gnu")),
        other => bail!("unsupported OS `{other}` for a packaged ouro binary"),
    }
}

/// This binary's release version.
///
/// It is the same `CARGO_PKG_VERSION` that `ouro version` prints on its first line and
/// that `ouro update` fences on, so an artifact resolved by the name below is an artifact
/// of *this* build. `make dist` takes its version from the packaged release tarball; the
/// crate and the mix project are held at one number deliberately. If they ever diverge,
/// the lookup below simply misses and the operator gets the honest recipe — never a
/// binary the fleet would refuse to form with anyway.
pub fn local_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Byte-for-byte the name `make dist` (and `make dist-linux`) writes into `dist/`.
pub fn dist_artifact_name(version: &str, triple: &str) -> String {
    format!("ouro-{version}-{triple}")
}

/// Candidate `dist` directories, most specific first.
///
/// Pure, so the search order is a test rather than a description: an explicit
/// `OUROBOROS_DIST_DIR`, then every `dist` above this executable's real path (a checkout's
/// `tui/target/release/ouro` therefore finds the repo root's), then `./dist`.
fn dist_roots(env_dir: Option<&str>, exe: Option<&Path>, cwd: Option<&Path>) -> Vec<PathBuf> {
    fn push(roots: &mut Vec<PathBuf>, root: PathBuf) {
        if !roots.contains(&root) {
            roots.push(root);
        }
    }

    let mut roots = Vec::new();
    if let Some(dir) = env_dir.map(str::trim).filter(|dir| !dir.is_empty()) {
        push(&mut roots, PathBuf::from(dir));
    }
    if let Some(exe) = exe {
        // `ancestors()` starts at the file itself; `skip(1)` starts at its directory.
        for ancestor in exe.ancestors().skip(1) {
            push(&mut roots, ancestor.join("dist"));
        }
    }
    if let Some(cwd) = cwd {
        push(&mut roots, cwd.join("dist"));
    }
    roots
}

fn discovered_dist_roots() -> Vec<PathBuf> {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.canonicalize().ok());
    let cwd = std::env::current_dir().ok();
    dist_roots(
        std::env::var("OUROBOROS_DIST_DIR").ok().as_deref(),
        exe.as_deref(),
        cwd.as_deref(),
    )
}

/// What a `dist` search found for one destination triple.
#[derive(Clone, Debug, Eq, PartialEq)]
enum DistLookup {
    Found(PathBuf),
    /// Right OS/CPU, wrong Ouroboros version. Placement fences on an exact version match,
    /// so this is named and refused rather than copied.
    VersionMismatch {
        path: PathBuf,
        found: String,
    },
    Missing,
}

fn find_dist_artifact(roots: &[PathBuf], version: &str, triple: &str) -> DistLookup {
    let wanted = dist_artifact_name(version, triple);
    let mut mismatch = None;
    for root in roots {
        let candidate = root.join(&wanted);
        if candidate.is_file() {
            return DistLookup::Found(candidate);
        }
        if mismatch.is_none() {
            mismatch = other_version_for(root, triple);
        }
    }
    match mismatch {
        Some((path, found)) => DistLookup::VersionMismatch { path, found },
        None => DistLookup::Missing,
    }
}

/// The first `dist` entry built for this destination but at some other version.
fn other_version_for(root: &Path, triple: &str) -> Option<(PathBuf, String)> {
    let suffix = format!("-{triple}");
    let mut found: Vec<(PathBuf, String)> = fs::read_dir(root)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            let version = path
                .file_name()?
                .to_str()?
                .strip_prefix("ouro-")?
                .strip_suffix(&suffix)?
                .to_string();
            (!version.is_empty()).then_some((path, version))
        })
        .collect();
    // Directory order is filesystem order; sort so the named artifact is stable.
    found.sort();
    found.into_iter().next()
}

/// The directories actually looked in, for a refusal that can be acted on.
fn searched_text(roots: &[PathBuf]) -> String {
    let dirs: Vec<String> = roots
        .iter()
        .filter(|root| root.is_dir())
        .map(|root| root.display().to_string())
        .collect();
    if dirs.is_empty() {
        "no `dist` directory (none exists beside this binary, above it, or in the current directory)".to_string()
    } else {
        dirs.join(", ")
    }
}

pub fn parse_probe(text: &str) -> Result<Probe> {
    let mut probe = Probe::default();
    for raw in text.lines() {
        let Some((key, value)) = raw.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_end_matches('.').to_string();
        match key {
            "os" => probe.os = value,
            "arch" => probe.arch = value,
            "home" => probe.home = value,
            "hostname" if !value.is_empty() => probe.hostname = Some(value),
            "ouro" if !value.is_empty() => probe.ouro = Some(value),
            "tailscale_ip" if !value.is_empty() => probe.tailscale_ip = Some(value),
            "tailscale_dns" if !value.is_empty() => probe.tailscale_dns = Some(value),
            // `ouro version`'s first line, which the probe prefixes with `version=` so it
            // arrives in the same `key=value` shape as everything else here.
            "version" if !value.is_empty() && probe.ouro_version.is_none() => {
                probe.ouro_version = Some(value)
            }
            _ => {}
        }
    }
    if probe.os.is_empty() || probe.arch.is_empty() || probe.home.is_empty() {
        bail!("the remote probe did not report os, arch, and home");
    }
    Ok(probe)
}

pub fn discover() -> (Vec<Candidate>, LocalIdentity) {
    let mut candidates = Vec::new();
    if let Ok(text) = fs::read_to_string(ssh_config_path()) {
        candidates.extend(parse_ssh_config(&text));
    }
    let mut local = LocalIdentity::default();
    if let Some(text) = tailscale_status_json() {
        candidates.extend(parse_tailscale_status(&text));
        local = parse_local_identity(&text);
    }
    (candidates, local)
}

pub fn discover_candidates() -> Vec<Candidate> {
    discover().0
}

fn ssh_config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/"))
        .join(".ssh/config")
}

pub fn parse_ssh_config(text: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    // Inside a `Match` block a lowercase `host` line is a criterion, not a section
    // header, so its arguments must not become add targets. Only a `Match` line starts
    // such a block; a capitalized `Host` line always ends one.
    let mut in_match = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((keyword, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        match keyword.to_ascii_lowercase().as_str() {
            "match" => {
                in_match = true;
                continue;
            }
            "host" => {
                if in_match && keyword == "host" {
                    continue;
                }
                in_match = false;
            }
            _ => continue,
        }
        for alias in rest.split_whitespace() {
            if alias.contains('*') || alias.contains('?') || alias.starts_with('!') {
                continue;
            }
            if alias.eq_ignore_ascii_case("github.com") || alias.eq_ignore_ascii_case("gitlab.com")
            {
                continue;
            }
            candidates.push(Candidate {
                source: CandidateSource::SshConfig,
                label: alias.to_string(),
                target: alias.to_string(),
                host: None,
                os: None,
                online: None,
            });
        }
    }
    candidates
}

fn tailscale_status_json() -> Option<String> {
    let output = Command::new("tailscale")
        .arg("status")
        .arg("--json")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn parse_tailscale_status(text: &str) -> Vec<Candidate> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    if let Some(peer_map) = value.get("Peer").and_then(|peer| peer.as_object()) {
        for peer in peer_map.values() {
            let Some(candidate) = candidate_from_tailscale_peer(peer) else {
                continue;
            };
            candidates.push(candidate);
        }
    }
    candidates
}

pub fn parse_local_identity(text: &str) -> LocalIdentity {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return LocalIdentity::default();
    };
    let Some(this) = value.get("Self") else {
        return LocalIdentity::default();
    };
    let host = this
        .get("DNSName")
        .and_then(|value| value.as_str())
        .map(|dns| dns.trim_end_matches('.').to_string())
        .filter(|dns| !dns.is_empty())
        .or_else(|| {
            this.get("TailscaleIPs")
                .and_then(|value| value.as_array())
                .and_then(|ips| ips.iter().find_map(|ip| ip.as_str()))
                .map(str::to_string)
        });
    let hostname = this
        .get("HostName")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let machine = match hostname {
        Some(name) if fleet::validate_machine(name).is_ok() => Some(name.to_ascii_lowercase()),
        _ => host
            .as_deref()
            .and_then(|host| fleet::machine_from_host(host).ok()),
    };
    LocalIdentity { machine, host }
}

fn candidate_from_tailscale_peer(peer: &serde_json::Value) -> Option<Candidate> {
    let host_name = peer.get("HostName")?.as_str()?.trim();
    if host_name.is_empty() {
        return None;
    }
    let dns = peer
        .get("DNSName")
        .and_then(|value| value.as_str())
        .map(|dns| dns.trim_end_matches('.').to_string())
        .filter(|dns| !dns.is_empty());
    let ip = peer
        .get("TailscaleIPs")
        .and_then(|value| value.as_array())
        .and_then(|ips| ips.iter().find_map(|ip| ip.as_str()))
        .map(str::to_string);
    let os = peer
        .get("OS")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let online = peer.get("Online").and_then(|value| value.as_bool());
    let target = dns.clone().unwrap_or_else(|| host_name.to_string());
    Some(Candidate {
        source: CandidateSource::Tailscale,
        label: host_name.to_string(),
        target,
        host: dns.or(ip),
        os,
        online,
    })
}

pub fn write_intent(data_dir: &Path, intent: &Intent) -> Result<()> {
    fleet::validate_machine(&intent.owner_machine)?;
    if let Some(add) = &intent.add {
        fleet::validate_machine(&add.machine)?;
    }
    if intent.schema != INTENT_SCHEMA {
        bail!("unsupported add-intent schema {}", intent.schema);
    }
    let path = fleet::add_intent_path(data_dir);
    let bytes = serde_json::to_vec_pretty(intent).context("encoding the add-machine intent")?;
    // A stale plan from an earlier failed restart must not wedge the flow: this file is
    // this owner's own non-secret note, so a fresh confirm replaces it outright.
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("removing {}", path.display()));
        }
    }
    write_private_new(&path, &bytes, "add-machine intent")
}

pub fn load_intent(data_dir: &Path) -> Result<Option<Intent>> {
    let path = fleet::add_intent_path(data_dir);
    if !path
        .try_exists()
        .with_context(|| format!("inspecting {}", path.display()))?
    {
        return Ok(None);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    let intent: Intent = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a valid add-machine intent", path.display()))?;
    if intent.schema != INTENT_SCHEMA {
        bail!(
            "{} has unsupported schema {}; leave it in place and inspect it before retrying",
            path.display(),
            intent.schema
        );
    }
    Ok(Some(intent))
}

pub fn take_intent(data_dir: &Path) -> Result<Option<Intent>> {
    let intent = load_intent(data_dir)?;
    if intent.is_some() {
        fs::remove_file(fleet::add_intent_path(data_dir)).with_context(|| {
            format!(
                "removing consumed add-machine intent {}",
                fleet::add_intent_path(data_dir).display()
            )
        })?;
    }
    Ok(intent)
}

/// Create the owner fleet from a saved first-run intent, then add or prepare the other
/// machine. The owner runtime must already be stopped. The intent stays on disk until the
/// add succeeds, so a failed SSH step can be retried without recreating the fleet.
pub fn apply_intent(data_dir: &Path) -> Result<Outcome> {
    let intent = load_intent(data_dir)?.ok_or_else(|| {
        anyhow!(
            "no add-machine intent at {}; this restart has nothing to apply",
            fleet::add_intent_path(data_dir).display()
        )
    })?;
    if fleet::load(data_dir)?.is_none() {
        fleet::create(
            data_dir,
            intent.fleet_name.as_deref(),
            &intent.owner_machine,
            &intent.owner_host,
            Ports::DEFAULT,
        )?;
    }
    let outcome = match &intent.add {
        None => Outcome {
            machine: intent.owner_machine.clone(),
            host: intent.owner_host.clone(),
            kind: OutcomeKind::Created,
            log: vec![format!(
                "this Mac is fleet owner `{}` at {}",
                intent.owner_machine, intent.owner_host
            )],
            recipe: None,
        },
        Some(add) => match add.kind {
            AddKind::Prepare => {
                prepare(data_dir, &add.machine, &add.host, Some(&intent.owner_host))?
            }
            AddKind::Ssh => {
                let target = add.target.as_deref().ok_or_else(|| {
                    anyhow!("the saved add-machine intent is missing the SSH target")
                })?;
                let via = Via::parse(&add.via)?;
                let binary = add.binary.as_deref().map(Path::new);
                add_with(
                    data_dir,
                    target,
                    Some(&add.machine),
                    Some(&add.host),
                    via,
                    binary,
                    Some(&intent.owner_host),
                    &SshRemote { via },
                )?
            }
        },
    };
    let _ = take_intent(data_dir)?;
    Ok(outcome)
}

pub fn write_join_intent(data_dir: &Path, intent: &JoinIntent) -> Result<()> {
    if intent.schema != INTENT_SCHEMA {
        bail!("unsupported join-intent schema {}", intent.schema);
    }
    if intent.invitation.trim().is_empty() {
        bail!("join needs the path to the invitation file");
    }
    enroll_preflight(Path::new(&intent.invitation))?;
    let path = fleet::join_intent_path(data_dir);
    let bytes = serde_json::to_vec_pretty(intent).context("encoding the join intent")?;
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("removing {}", path.display()));
        }
    }
    write_private_new(&path, &bytes, "join intent")
}

pub fn load_join_intent(data_dir: &Path) -> Result<Option<JoinIntent>> {
    let path = fleet::join_intent_path(data_dir);
    if !path
        .try_exists()
        .with_context(|| format!("inspecting {}", path.display()))?
    {
        return Ok(None);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    let intent: JoinIntent = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a valid join intent", path.display()))?;
    if intent.schema != INTENT_SCHEMA {
        bail!(
            "{} has unsupported schema {}; leave it in place and inspect it before retrying",
            path.display(),
            intent.schema
        );
    }
    Ok(Some(intent))
}

pub fn take_join_intent(data_dir: &Path) -> Result<Option<JoinIntent>> {
    let intent = load_join_intent(data_dir)?;
    if intent.is_some() {
        fs::remove_file(fleet::join_intent_path(data_dir)).with_context(|| {
            format!(
                "removing consumed join intent {}",
                fleet::join_intent_path(data_dir).display()
            )
        })?;
    }
    Ok(intent)
}

/// Join from a saved invitation path after this standalone runtime has been stopped.
pub fn apply_join_intent(data_dir: &Path) -> Result<Outcome> {
    let intent = load_join_intent(data_dir)?.ok_or_else(|| {
        anyhow!(
            "no join intent at {}; this restart has nothing to apply",
            fleet::join_intent_path(data_dir).display()
        )
    })?;
    let invitation = PathBuf::from(&intent.invitation);
    enroll_preflight(&invitation)?;
    let profile = fleet::join(data_dir, &invitation, Ports::DEFAULT)?;
    let mut log = vec![format!(
        "joined {} as {} at {}",
        profile.name, profile.machine, profile.host
    )];
    if intent.delete {
        fs::remove_file(&invitation).with_context(|| {
            format!(
                "joined, but could not delete invitation {}",
                invitation.display()
            )
        })?;
        log.push(format!("deleted {}", invitation.display()));
    }
    let recipe = if intent.service {
        match fleet::service_install(data_dir) {
            Ok(installed) => {
                log.push(format!(
                    "recovery unit written at {}",
                    installed.path.display()
                ));
                Some(Recipe {
                    machine: profile.machine.clone(),
                    invite_path: invitation,
                    lines: vec![
                        format!("# Activate recovery (does not start on its own):"),
                        installed.activation,
                    ],
                })
            }
            Err(error) => {
                log.push(format!(
                    "joined, but recovery was not installed: {error:#}. Run Keep this machine running after the daemon is healthy."
                ));
                None
            }
        }
    } else {
        None
    };
    let _ = take_join_intent(data_dir)?;
    Ok(Outcome {
        machine: profile.machine,
        host: profile.host,
        kind: OutcomeKind::Joined,
        log,
        recipe,
    })
}

/// Apply a saved first-run add or join. The owner runtime must already be stopped.
pub fn apply_pending(data_dir: &Path) -> Result<Outcome> {
    if load_intent(data_dir)?.is_some() {
        apply_intent(data_dir)
    } else if load_join_intent(data_dir)?.is_some() {
        apply_join_intent(data_dir)
    } else {
        bail!(
            "no add-machine or join intent in {}; this restart has nothing to apply",
            data_dir.display()
        )
    }
}

pub fn prepare(
    data_dir: &Path,
    machine: &str,
    host: &str,
    owner_host: Option<&str>,
) -> Result<Outcome> {
    let invite = write_pending_invite(data_dir, machine, host)?;
    let recipe = enroll_recipe(machine, host, &invite, owner_host, None);
    write_howto(&invite, &recipe)?;
    Ok(Outcome {
        machine: machine.to_string(),
        host: host.to_string(),
        kind: OutcomeKind::Prepared,
        log: vec![format!(
            "wrote a private invitation for {machine} at {}",
            invite.display()
        )],
        recipe: Some(recipe),
    })
}

pub fn add(
    data_dir: &Path,
    target: &str,
    machine: Option<&str>,
    host: Option<&str>,
    via: Via,
    binary: Option<&Path>,
    owner_host: Option<&str>,
) -> Result<Outcome> {
    add_with(
        data_dir,
        target,
        machine,
        host,
        via,
        binary,
        owner_host,
        &SshRemote { via },
    )
}

/// The CLI's entry point: real SSH, operator options, and a terminal to print to.
#[allow(clippy::too_many_arguments)]
pub fn add_guided(
    data_dir: &Path,
    target: &str,
    machine: Option<&str>,
    host: Option<&str>,
    via: Via,
    binary: Option<&Path>,
    owner_host: Option<&str>,
    options: &AddOptions,
    notify: &mut dyn Notify,
) -> Result<Outcome> {
    add_with_options(
        data_dir,
        target,
        machine,
        host,
        via,
        binary,
        owner_host,
        &SshRemote { via },
        options,
        notify,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn add_with(
    data_dir: &Path,
    target: &str,
    machine: Option<&str>,
    host: Option<&str>,
    via: Via,
    binary: Option<&Path>,
    owner_host: Option<&str>,
    remote: &dyn Remote,
) -> Result<Outcome> {
    add_with_options(
        data_dir,
        target,
        machine,
        host,
        via,
        binary,
        owner_host,
        remote,
        &AddOptions::default(),
        &mut SilentNotify,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn add_with_options(
    data_dir: &Path,
    target: &str,
    machine: Option<&str>,
    host: Option<&str>,
    via: Via,
    binary: Option<&Path>,
    owner_host: Option<&str>,
    remote: &dyn Remote,
    options: &AddOptions,
    notify: &mut dyn Notify,
) -> Result<Outcome> {
    let mut log = Vec::new();
    log.push(format!("probing {target} over {}", via.as_str()));
    let probe_text = remote.run(target, PROBE_SCRIPT)?;
    let mut probe = parse_probe(&probe_text)?;
    require_safe_unix_path(&probe.home, "home")?;
    let remote_triple = probe.triple()?;
    let local = local_triple()?;
    log.push(format!("remote is {remote_triple} (home {})", probe.home));

    let requested_host = host
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    // Guided enrollment runs before any invitation exists, so a refusal or a timeout here
    // leaves nothing private on either machine.
    if options.setup_tailscale {
        if let Some(host) = &requested_host {
            log.push(format!(
                "--setup-tailscale did nothing: --host {host} already names how the fleet reaches {target}"
            ));
        } else if let Some(existing) = probe.suggested_host() {
            log.push(format!(
                "--setup-tailscale did nothing: {target} already answers on {existing}"
            ));
        } else {
            setup_tailscale(remote, target, options.tailscale_poll, &mut log, notify)?;
            let reprobed = remote.run(target, PROBE_SCRIPT)?;
            probe = parse_probe(&reprobed)?;
            require_safe_unix_path(&probe.home, "home")?;
            log.push(format!("re-probed {target} after Tailscale enrollment"));
        }
    }

    let host = requested_host
        .or_else(|| probe.suggested_host())
        .ok_or_else(|| {
            anyhow!(
                "could not prove a private address for {target}; pass --host with a Tailscale MagicDNS name or private IPv4 address, or rerun with --setup-tailscale to install Tailscale and sign in on that machine (it runs the vendor's installer and `tailscale up` as root there)"
            )
        })?;
    let machine = machine
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| probe.suggested_machine())
        .ok_or_else(|| anyhow!("could not derive a machine name for {target}; pass --machine"))?;
    fleet::validate_machine(&machine)?;

    let invite = write_pending_invite(data_dir, &machine, &host)?;
    log.push(format!("created a private invitation for {machine}"));

    let remote_invite = format!(
        "{}/.local/share/ouroboros/incoming/{machine}.ouro",
        probe.home.trim_end_matches('/')
    );
    let incoming_dir = format!(
        "{}/.local/share/ouroboros/incoming",
        probe.home.trim_end_matches('/')
    );
    remote.run(target, &format!("mkdir -p -m 700 '{incoming_dir}'"))?;
    remote.copy_to(&invite, target, &remote_invite)?;
    log.push(format!("copied the invitation to {target}:{remote_invite}"));

    let dist_roots = options
        .dist_roots
        .clone()
        .unwrap_or_else(discovered_dist_roots);
    let install = install_plan(
        &local,
        &remote_triple,
        binary,
        probe.ouro.as_deref(),
        local_version(),
        &dist_roots,
    )
    .map_err(|error| pending_invite_error(error, &invite))?;
    match &install {
        InstallPlan::UseExisting(path) => {
            log.push(format!("remote already has {path}"));
            enroll_remote(remote, target, path, &remote_invite)
                .map_err(|error| pending_invite_error(error, &invite))?;
            finish_enroll(&mut log, &invite, &machine, &host, OutcomeKind::Enrolled)
        }
        InstallPlan::Copy { path, note } => {
            if let Some(note) = note {
                log.push(note.clone());
            }
            let remote_bin = format!("{}/.local/bin/ouro", probe.home.trim_end_matches('/'));
            remote
                .run(
                    target,
                    &format!(
                        "mkdir -p -m 755 '{}/.local/bin'",
                        probe.home.trim_end_matches('/')
                    ),
                )
                .map_err(|error| pending_invite_error(error, &invite))?;
            remote
                .copy_to(path, target, &format!("{remote_bin}.partial"))
                .map_err(|error| pending_invite_error(error, &invite))?;
            remote
                .run(
                    target,
                    &format!(
                        "mv '{remote_bin}.partial' '{remote_bin}' && chmod 755 '{remote_bin}'"
                    ),
                )
                .map_err(|error| pending_invite_error(error, &invite))?;
            log.push(format!("installed {} as {remote_bin}", path.display()));
            enroll_remote(remote, target, &remote_bin, &remote_invite)
                .map_err(|error| pending_invite_error(error, &invite))?;
            finish_enroll(&mut log, &invite, &machine, &host, OutcomeKind::Enrolled)
        }
        InstallPlan::RecipeOnly { reason } => {
            log.push(reason.clone());
            let recipe = enroll_recipe(
                &machine,
                &host,
                &invite,
                owner_host,
                Some(&format!(
                    "ssh {target} 'export PATH=\"$HOME/.local/bin:$PATH\"; ouro fleet enroll {remote_invite} --delete'"
                )),
            );
            write_howto(&invite, &recipe)?;
            Ok(Outcome {
                machine,
                host,
                kind: OutcomeKind::InviteDelivered,
                log,
                recipe: Some(recipe),
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum InstallPlan {
    UseExisting(String),
    /// `note` is the one line the add log gains when the path was resolved rather than
    /// named by the operator, so the run records which artifact it picked.
    Copy {
        path: PathBuf,
        note: Option<String>,
    },
    RecipeOnly {
        reason: String,
    },
}

/// Wrap a failure after the invitation was copied so the operator knows exactly what
/// private material is now where, and what to do before retrying.
fn pending_invite_error(error: anyhow::Error, invite: &Path) -> anyhow::Error {
    error.context(format!(
        "the invitation remains at {} (mode 0600); if it may already have been copied, treat it as issued — otherwise delete it with rm before adding again",
        invite.display()
    ))
}

/// Remove the local copy of a consumed invitation. A failed removal is logged, never
/// silent: the file is membership material.
fn finish_enroll(
    log: &mut Vec<String>,
    invite: &Path,
    machine: &str,
    host: &str,
    kind: OutcomeKind,
) -> Result<Outcome> {
    match fs::remove_file(invite) {
        Ok(()) => {}
        Err(error) => log.push(format!(
            "could not remove the local invitation {}: {error}; delete it by hand",
            invite.display()
        )),
    }
    log.push(format!("{machine} enrolled and its daemon is starting"));
    Ok(Outcome {
        machine: machine.to_string(),
        host: host.to_string(),
        kind,
        log: std::mem::take(log),
        recipe: None,
    })
}

fn install_plan(
    local_triple: &str,
    remote_triple: &str,
    binary: Option<&Path>,
    remote_ouro: Option<&str>,
    version: &str,
    dist_roots: &[PathBuf],
) -> Result<InstallPlan> {
    if let Some(path) = binary {
        if !path.is_file() {
            bail!("--binary {} is not a file", path.display());
        }
        return Ok(InstallPlan::Copy {
            path: path.to_path_buf(),
            note: None,
        });
    }
    if let Some(path) = remote_ouro {
        return Ok(InstallPlan::UseExisting(path.to_string()));
    }
    if local_triple == remote_triple {
        let exe = std::env::current_exe()
            .context("locating this ouro executable")?
            .canonicalize()
            .context("resolving this ouro executable")?;
        return Ok(InstallPlan::Copy {
            path: exe,
            note: None,
        });
    }
    // Different OS/CPU: this build cannot run there, but a release artifact built for
    // that triple at this exact version can.
    let wanted = dist_artifact_name(version, remote_triple);
    match find_dist_artifact(dist_roots, version, remote_triple) {
        DistLookup::Found(path) => Ok(InstallPlan::Copy {
            note: Some(format!(
                "this Mac is {local_triple} and the destination is {remote_triple}; resolved {wanted} at {}",
                path.display()
            )),
            path,
        }),
        DistLookup::VersionMismatch { path, found } => Ok(InstallPlan::RecipeOnly {
            reason: format!(
                "this Mac is {local_triple}; the destination is {remote_triple}. {artifact} is built for that destination but is version {found}, and this ouro is {version}. A fleet only forms between matching Ouroboros versions, so it was not copied. Build the matching artifact with `make dist-linux` (it writes {wanted}), or pass --binary with a {remote_triple} build of {version}. The invitation is already on the destination.",
                artifact = path.display()
            ),
        }),
        DistLookup::Missing => Ok(InstallPlan::RecipeOnly {
            reason: format!(
                "this Mac is {local_triple}; the destination is {remote_triple}. Ouroboros cannot copy this binary there, and no {wanted} was found in {searched}. Build one with `make dist-linux`, pass --binary with a {remote_triple} build of {version}, or set OUROBOROS_DIST_DIR to the directory holding it. Otherwise install the matching ouro on that machine and run the printed enroll command. The invitation is already on the destination.",
                searched = searched_text(dist_roots)
            ),
        }),
    }
}

// -----------------------------------------------------------------------------------
// Guided Tailscale enrollment
// -----------------------------------------------------------------------------------

/// Install Tailscale on the destination and sign it in, with the operator watching.
///
/// Every remote interaction goes through [`Remote`]. Nothing here touches an invitation:
/// this runs before one exists, so a refusal or a timeout leaves no private material
/// anywhere. The sign-in URL reaches `notify` and nothing else.
fn setup_tailscale(
    remote: &dyn Remote,
    target: &str,
    budget: PollBudget,
    log: &mut Vec<String>,
    notify: &mut dyn Notify,
) -> Result<()> {
    let facts = key_values(&remote.run(target, TAILSCALE_CAPABILITY_SCRIPT)?);
    let installed = value_of(&facts, "tailscale") == Some("present");
    let sudo = value_of(&facts, "sudo") == Some("yes");

    if !sudo {
        let blocked = if installed {
            "`sudo tailscale up`"
        } else {
            "the Tailscale installer"
        };
        bail!(
            "guided Tailscale enrollment needs passwordless sudo on {target}, and `sudo -n true` failed there, so {blocked} cannot run. Nothing was changed on {target} and no invitation was created. Install and sign in to Tailscale on that machine yourself and run this add again, or pass --host with a private address it already answers on"
        );
    }

    if installed {
        log.push(format!("tailscale is already installed on {target}"));
    } else {
        notify.line(&format!(
            "{target}: installing Tailscale with the vendor's own installer, as root:"
        ));
        notify.line(&format!("  {TAILSCALE_INSTALL}"));
        remote.run(target, TAILSCALE_INSTALL)?;
        let after = key_values(&remote.run(target, TAILSCALE_CAPABILITY_SCRIPT)?);
        if value_of(&after, "tailscale") != Some("present") {
            bail!(
                "the Tailscale installer ran on {target}, but `tailscale` is still not on its PATH. Install it by hand there and run this add again; no invitation was created"
            );
        }
        log.push(format!("installed Tailscale on {target}"));
    }

    notify.line(&format!("{target}: running as root: sudo tailscale up"));
    let started = key_values(&remote.run(target, TAILSCALE_UP_SCRIPT)?);
    match value_of(&started, "state") {
        Some("up") => {
            log.push(format!("tailscale was already up on {target}"));
            Ok(())
        }
        Some("starting") => {
            let log_path = value_of(&started, "log")
                .filter(|path| !path.is_empty())
                .ok_or_else(|| {
                    anyhow!("`tailscale up` on {target} did not report where it writes its output")
                })?
                .to_string();
            // The path came back from the destination, so it is data until it is proven
            // safe to interpolate into the next command.
            require_safe_unix_path(&log_path, "tailscale up output path")?;
            let url = wait_for_auth_url(remote, target, &log_path, budget)?;
            notify.line("");
            notify.line("Open this link and approve the machine (a one-time Tailscale sign-in):");
            notify.line(&format!("  {url}"));
            notify.line(&format!(
                "Waiting up to {} for {target} to receive a tailnet address...",
                human_duration(budget.ip_window())
            ));
            // The URL is a live sign-in link. It goes to this terminal and nowhere else:
            // not the add log, not the invitation, not the howto file.
            log.push(format!(
                "printed the Tailscale sign-in URL for {target} to this terminal"
            ));
            let waited = wait_for_tailnet_address(remote, target, budget);
            // Best effort: `tailscale up` wrote that URL into a temp file on the
            // destination, so remove it whether or not the wait succeeded.
            let _ = remote.run(target, &format!("rm -f '{log_path}'"));
            waited?;
            log.push(format!("{target} has a Tailscale address"));
            Ok(())
        }
        other => bail!(
            "`tailscale up` on {target} reported an unexpected state (`{}`); run it there by hand and run this add again",
            other.unwrap_or("")
        ),
    }
}

fn wait_for_auth_url(
    remote: &dyn Remote,
    target: &str,
    log_path: &str,
    budget: PollBudget,
) -> Result<String> {
    for _ in 0..budget.url_attempts.max(1) {
        std::thread::sleep(budget.interval);
        // Remote output is data: it is scanned for one URL-shaped token and never echoed.
        let text = remote.run(
            target,
            &format!("head -c 4096 '{log_path}' 2>/dev/null || true"),
        )?;
        if let Some(url) = auth_url(&text) {
            return Ok(url);
        }
    }
    bail!(
        "`sudo tailscale up` on {target} printed no sign-in URL within {}. Run `sudo tailscale up` there and follow the link it prints, then run this add again. Nothing was enrolled and no invitation was created",
        human_duration(budget.url_window())
    )
}

fn wait_for_tailnet_address(remote: &dyn Remote, target: &str, budget: PollBudget) -> Result<()> {
    for _ in 0..budget.ip_attempts.max(1) {
        std::thread::sleep(budget.interval);
        let facts = key_values(&remote.run(target, TAILSCALE_IP_SCRIPT)?);
        if value_of(&facts, "ip").is_some_and(|ip| !ip.is_empty()) {
            return Ok(());
        }
    }
    bail!(
        "{target} still has no Tailscale address after {}. Finish the sign-in in the browser, then run the same `ouro fleet add` command again: with Tailscale installed and up it reuses both and continues. Nothing was enrolled and no invitation was created",
        human_duration(budget.ip_window())
    )
}

/// The first URL-shaped token in remote output, or nothing.
///
/// `tailscale up` prints `To authenticate, visit:` and then the link, but the surrounding
/// prose is not a contract. The token is accepted only if every character is URL-safe
/// ASCII, so nothing from the destination can carry an escape sequence to this terminal.
fn auth_url(text: &str) -> Option<String> {
    fn url_safe(c: char) -> bool {
        c.is_ascii_alphanumeric() || "-._~:/?#[]@!$&'()*+,;=%".contains(c)
    }

    text.split_whitespace()
        .map(|token| token.trim_end_matches(['.', ',', ')', ']', '>', '"', '\'']))
        .find(|token| {
            token.starts_with("https://")
                && token.len() > "https://".len()
                && token.len() <= 512
                && token.chars().all(url_safe)
        })
        .map(str::to_string)
}

/// `key=value` lines, the shape every script in this file answers in.
fn key_values(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn value_of<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn human_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 60 && seconds.is_multiple_of(60) {
        let minutes = seconds / 60;
        format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" })
    } else {
        format!("{seconds}s")
    }
}

fn enroll_remote(remote: &dyn Remote, target: &str, ouro: &str, invite: &str) -> Result<()> {
    // The invitation travels as a `.ouro` file. Refusing anything else keeps membership
    // material from ever being passed as inline text on a remote command line.
    if !invite.ends_with(".ouro") {
        bail!("refusing to enroll with a path that is not an .ouro invitation file");
    }
    let script = format!("chmod 600 '{invite}' && '{ouro}' fleet enroll '{invite}' --delete");
    remote.run(target, &script).map(|_| ())
}

fn write_pending_invite(data_dir: &Path, machine: &str, host: &str) -> Result<PathBuf> {
    fleet::ensure_pending_dir(data_dir)?;
    let output = fleet::pending_invite_path(data_dir, machine)?;
    if output.try_exists()? {
        bail!(
            "a pending invitation for `{machine}` already exists at {}. If it was never copied, delete it with `rm {}` and run this add again; if it may have been copied, treat it as issued and enroll it there.",
            output.display(),
            output.display()
        );
    }
    fleet::invite(data_dir, machine, host, &output, Ports::DEFAULT)?;
    Ok(output)
}

fn enroll_recipe(
    machine: &str,
    host: &str,
    invite: &Path,
    owner_host: Option<&str>,
    ssh_enroll: Option<&str>,
) -> Recipe {
    let mut lines = vec![
        format!("# Enroll {machine} ({host}) into this fleet."),
        "# The .ouro file is private membership material. Do not paste it into chat.".to_string(),
        String::new(),
        "# 1. Install matching ouro on that OS/CPU (same version; a Mac binary will not run on Linux).".to_string(),
    ];
    if let Some(owner) = owner_host.filter(|host| !host.is_empty()) {
        lines.push(format!(
            "# 2. Copy the invitation: scp {owner}:{} ./{machine}.ouro",
            invite.display()
        ));
        lines.push("#    or, if this Mac already copied it: skip to step 3.".to_string());
    } else {
        lines.push(format!(
            "# 2. Copy {} to that machine as {machine}.ouro (mode 0600).",
            invite.display()
        ));
    }
    lines.push(format!("chmod 600 {machine}.ouro"));
    lines.push(format!("ouro fleet enroll {machine}.ouro --delete"));
    lines.push("ouro fleet service install   # then run the activation command it prints".into());
    if let Some(ssh_enroll) = ssh_enroll {
        lines.push(String::new());
        lines.push(
            "# If ouro is already installed on the destination, this one line is enough:".into(),
        );
        lines.push(ssh_enroll.to_string());
    }
    Recipe {
        machine: machine.to_string(),
        invite_path: invite.to_path_buf(),
        lines,
    }
}

fn require_safe_unix_path(path: &str, what: &str) -> Result<()> {
    let unsafe_char = |c: char| {
        matches!(
            c,
            '\'' | '"'
                | '\\'
                | '\n'
                | '\r'
                | '\0'
                | ';'
                | '|'
                | '&'
                | '`'
                | '$'
                | '*'
                | '?'
                | '('
                | ')'
                | ' '
                | '\t'
        )
    };
    if !path.starts_with('/') || path.contains(unsafe_char) {
        bail!("remote {what} `{path}` is not a safe absolute path; use --print-script instead");
    }
    Ok(())
}

fn write_howto(invite: &Path, recipe: &Recipe) -> Result<()> {
    let path = invite.with_extension("howto");
    write_private_new(&path, recipe.text().as_bytes(), "enroll recipe")
}

fn write_private_new(path: &Path, bytes: &[u8], description: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent
            .try_exists()
            .with_context(|| format!("inspecting {}", parent.display()))?
        {
            bail!(
                "{} does not exist; cannot write {description}",
                parent.display()
            );
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| {
            format!(
                "creating private {description} {}; choose a new path rather than overwriting",
                path.display()
            )
        })?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {description} {}", path.display()))?;
    file.sync_all()?;
    Ok(())
}

pub fn render_list(candidates: &[Candidate]) -> String {
    if candidates.is_empty() {
        return "No Tailscale peers or SSH config hosts were found. Name a destination as user@host.\n".into();
    }
    let mut text = String::from("Machines this Mac already knows:\n");
    for candidate in candidates {
        let source = match candidate.source {
            CandidateSource::Tailscale => "tailscale",
            CandidateSource::SshConfig => "ssh",
        };
        let online = match candidate.online {
            Some(true) => " online",
            Some(false) => " offline",
            None => "",
        };
        let os = candidate
            .os
            .as_deref()
            .map(|os| format!(" {os}"))
            .unwrap_or_default();
        let host = candidate
            .host
            .as_deref()
            .map(|host| format!(" host={host}"))
            .unwrap_or_default();
        text.push_str(&format!(
            "  {source:<9} {label:<16} {target}{os}{online}{host}\n",
            label = candidate.label,
            target = candidate.target
        ));
    }
    text.push_str("\nAdd one with `ouro fleet add TARGET --machine NAME --host HOST`.\n");
    text
}

pub fn render_outcome(outcome: &Outcome) -> String {
    let mut text = String::new();
    for line in &outcome.log {
        text.push_str(line);
        text.push('\n');
    }
    text.push('\n');
    match outcome.kind {
        OutcomeKind::Enrolled => {
            text.push_str(&format!(
                "{machine} is joining at {host}. On this Mac run `ouro fleet status`.\nProvider sign-in stays on that machine; start a session there after it is connected.\n",
                machine = outcome.machine,
                host = outcome.host
            ));
        }
        OutcomeKind::InviteDelivered | OutcomeKind::Prepared => {
            if let Some(recipe) = &outcome.recipe {
                text.push_str(&recipe.text());
                text.push('\n');
            }
        }
        OutcomeKind::Created => {
            text.push_str(
                "This Mac is the fleet owner. /machines still adds the laptop and servers.\n",
            );
        }
        OutcomeKind::Joined => {
            text.push_str(&format!(
                "This machine is {machine} at {host}. Provider sign-in stays here.\n",
                machine = outcome.machine,
                host = outcome.host
            ));
            if let Some(recipe) = &outcome.recipe {
                text.push_str(&recipe.text());
                text.push('\n');
            }
        }
    }
    text
}

/// Local join + daemon is implemented by the CLI so spawn/lock stay in one process.
/// This helper only documents that enroll must not print invitation bytes.
pub fn enroll_preflight(invitation: &Path) -> Result<()> {
    if !invitation.is_file() {
        bail!("{} is not an invitation file", invitation.display());
    }
    let metadata = fs::symlink_metadata(invitation)
        .with_context(|| format!("inspecting {}", invitation.display()))?;
    if metadata.mode() & 0o077 != 0 {
        bail!(
            "{} must be mode 0600 before enroll; run chmod 600 first. Nothing was joined",
            invitation.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A remote whose every answer is written down in the test that needs it. Replies are
    /// served in order and the last one repeats, so a poll can be scripted as
    /// "not yet, not yet, here it is".
    #[derive(Default)]
    struct ScriptedRemote {
        runs: Mutex<Vec<String>>,
        copies: Mutex<Vec<(PathBuf, String)>>,
        probes: Mutex<VecDeque<String>>,
        capability: Mutex<VecDeque<String>>,
        up: Mutex<VecDeque<String>>,
        log_reads: Mutex<VecDeque<String>>,
        ip_polls: Mutex<VecDeque<String>>,
    }

    fn queue(replies: &[&str]) -> Mutex<VecDeque<String>> {
        Mutex::new(replies.iter().map(|reply| reply.to_string()).collect())
    }

    impl ScriptedRemote {
        fn serve(queue: &Mutex<VecDeque<String>>, what: &str) -> Result<String> {
            let mut queue = queue.lock().unwrap();
            if queue.len() > 1 {
                return Ok(queue.pop_front().expect("length was checked"));
            }
            queue
                .front()
                .cloned()
                .ok_or_else(|| anyhow!("the scripted remote has no {what} reply"))
        }

        fn ran(&self, needle: &str) -> bool {
            self.runs
                .lock()
                .unwrap()
                .iter()
                .any(|script| script.contains(needle))
        }
    }

    impl Remote for ScriptedRemote {
        fn run(&self, _target: &str, script: &str) -> Result<String> {
            self.runs.lock().unwrap().push(script.to_string());
            if script.contains("printf 'os=") {
                return Self::serve(&self.probes, "probe");
            }
            if script.contains("printf 'tailscale=present") {
                return Self::serve(&self.capability, "capability");
            }
            if script == TAILSCALE_INSTALL {
                return Ok(String::new());
            }
            if script.contains("tailscale up") {
                return Self::serve(&self.up, "tailscale up");
            }
            if script.starts_with("head -c") {
                return Self::serve(&self.log_reads, "tailscale up log");
            }
            if script.contains("printf 'ip=") {
                return Self::serve(&self.ip_polls, "tailscale ip");
            }
            Ok(String::new())
        }

        fn copy_to(&self, local: &Path, _target: &str, remote_path: &str) -> Result<()> {
            self.copies
                .lock()
                .unwrap()
                .push((local.to_path_buf(), remote_path.to_string()));
            Ok(())
        }
    }

    /// The injected live-print seam.
    #[derive(Default)]
    struct Lines(Vec<String>);

    impl Notify for Lines {
        fn line(&mut self, text: &str) {
            self.0.push(text.to_string());
        }
    }

    impl Lines {
        fn text(&self) -> String {
            self.0.join("\n")
        }
    }

    /// An OS/CPU that is never this host's, so a cross-triple test stays cross-triple
    /// wherever it is run.
    fn foreign_os_arch() -> (&'static str, &'static str) {
        if local_triple().unwrap() == "x86_64-unknown-linux-gnu" {
            ("Darwin", "arm64")
        } else {
            ("Linux", "x86_64")
        }
    }

    fn foreign_triple() -> String {
        let (os, arch) = foreign_os_arch();
        triple(os, arch).unwrap()
    }

    fn probe_text(tailscale: bool, ouro: bool) -> String {
        let (os, arch) = foreign_os_arch();
        let mut text = format!("os={os}\narch={arch}\nhome=/home/op\nhostname=vps\n");
        if ouro {
            text.push_str("ouro=/home/op/.local/bin/ouro\nversion=ouro 0.1.0\n");
        } else {
            text.push_str("ouro=\n");
        }
        if tailscale {
            // A CGNAT literal rather than a MagicDNS name: `fleet::invite` resolves what
            // it is given, and these tests must not depend on a resolver.
            text.push_str("tailscale=yes\ntailscale_ip=100.64.0.8\n");
        } else {
            text.push_str("tailscale=no\n");
        }
        text
    }

    const UP_STARTING: &str = "state=starting\nlog=/tmp/ouro-tailscale-up.abc123\n";
    const AUTH_LOG: &str =
        "To authenticate, visit:\n\n\thttps://login.tailscale.com/a/deadbeef\n\n";

    /// A budget that spends no wall-clock time, so timeouts are testable.
    fn instant_budget(url_attempts: u32, ip_attempts: u32) -> PollBudget {
        PollBudget {
            interval: Duration::ZERO,
            url_attempts,
            ip_attempts,
        }
    }

    /// A `dist` directory holding one artifact, named exactly as `make dist` names it.
    fn dist_fixture(label: &str, version: &str, triple: &str) -> PathBuf {
        let root = scratch(label);
        let artifact = root.join(dist_artifact_name(version, triple));
        fs::write(&artifact, b"#!/bin/sh\n# not a real ouro\n").unwrap();
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o755)).unwrap();
        root
    }

    /// Every regular file under `root`, so a test can prove a secret is in none of them.
    fn all_file_text(root: &Path) -> String {
        let mut text = String::new();
        let Ok(entries) = fs::read_dir(root) else {
            return text;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                text.push_str(&all_file_text(&path));
            } else if let Ok(contents) = fs::read_to_string(&path) {
                text.push_str(&contents);
            }
        }
        text
    }

    struct FakeRemote {
        probe: String,
        runs: Mutex<Vec<String>>,
        copies: Mutex<Vec<(PathBuf, String)>>,
        fail_enroll: bool,
    }

    impl FakeRemote {
        fn linux(home: &str) -> Self {
            Self {
                probe: format!(
                    "os=Linux\narch=x86_64\nhome={home}\nhostname=vps\nouro=\ntailscale=yes\ntailscale_ip=100.64.0.8\ntailscale_dns=vps.tailnet.ts.net.\n"
                ),
                runs: Mutex::new(Vec::new()),
                copies: Mutex::new(Vec::new()),
                fail_enroll: false,
            }
        }
    }

    impl Remote for FakeRemote {
        fn run(&self, _target: &str, script: &str) -> Result<String> {
            self.runs.lock().unwrap().push(script.to_string());
            if script.contains("uname") || script.contains("printf 'os=") {
                return Ok(self.probe.clone());
            }
            if self.fail_enroll && script.contains("fleet enroll") {
                bail!("remote enroll refused");
            }
            Ok(String::new())
        }

        fn copy_to(&self, local: &Path, _target: &str, remote_path: &str) -> Result<()> {
            self.copies
                .lock()
                .unwrap()
                .push((local.to_path_buf(), remote_path.to_string()));
            Ok(())
        }
    }

    fn scratch(label: &str) -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;

        let path = std::env::temp_dir().join(format!(
            "ouro-fleet-add-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }

    #[test]
    fn a_linux_probe_names_the_gnu_triple_and_prefers_magicdns() {
        let probe = parse_probe(
            "os=Linux\narch=x86_64\nhome=/home/op\nhostname=vps\nouro=\ntailscale_ip=100.64.0.8\ntailscale_dns=vps.tailnet.ts.net.\n",
        )
        .unwrap();
        assert_eq!(probe.triple().unwrap(), "x86_64-unknown-linux-gnu");
        assert_eq!(
            probe.suggested_host().as_deref(),
            Some("vps.tailnet.ts.net")
        );
        assert_eq!(probe.suggested_machine().as_deref(), Some("vps"));
    }

    /// The probe and the parse have to agree on the spelling, and for a while they did
    /// not: the script printed `version_ouro 0.1.0`, which carries no `=` and so never
    /// reached the match at all. Pinned from the script rather than from a retyped copy
    /// of it, because a divergence there is exactly what went unnoticed.
    #[test]
    fn the_probe_reports_the_ouro_version_the_remote_prints() {
        assert!(
            PROBE_SCRIPT.contains(r#"{print "version=" $0}"#),
            "the probe must emit the version as key=value: {PROBE_SCRIPT}"
        );

        let probe = parse_probe(
            "os=Linux\narch=x86_64\nhome=/home/op\nouro=/home/op/.local/bin/ouro\nversion=ouro 0.1.0\ntailscale=no\n",
        )
        .unwrap();

        assert_eq!(probe.ouro.as_deref(), Some("/home/op/.local/bin/ouro"));
        assert_eq!(probe.ouro_version.as_deref(), Some("ouro 0.1.0"));
    }

    #[test]
    fn a_remote_without_ouro_reports_no_version() {
        let probe =
            parse_probe("os=Linux\narch=x86_64\nhome=/home/op\nouro=\ntailscale=no\n").unwrap();

        assert!(probe.ouro.is_none());
        assert!(probe.ouro_version.is_none());
    }

    #[test]
    fn macos_arm_and_linux_amd_are_different_triples() {
        assert_eq!(triple("Darwin", "arm64").unwrap(), "aarch64-apple-darwin");
        assert_eq!(
            triple("Linux", "amd64").unwrap(),
            "x86_64-unknown-linux-gnu"
        );
        assert!(triple("Windows", "amd64").is_err());
    }

    #[test]
    fn ssh_config_skips_globs_and_forges() {
        let hosts =
            parse_ssh_config("Host github.com\nHost vps-prod vps-dev\nHost laptop*\nHost studio\n");
        let labels: Vec<_> = hosts.iter().map(|host| host.label.as_str()).collect();
        assert_eq!(labels, ["vps-prod", "vps-dev", "studio"]);
    }

    #[test]
    fn ssh_config_match_criteria_are_not_hosts_but_host_sections_resume() {
        let hosts = parse_ssh_config(
            "Match exec check-vpn\n    host vpn-box\n    User op\nMatch all\n    host ignored-too\nHost studio\nhost laptop\n",
        );
        let labels: Vec<_> = hosts.iter().map(|host| host.label.as_str()).collect();
        assert_eq!(labels, ["studio", "laptop"]);
    }

    #[test]
    fn tailscale_peers_become_add_targets() {
        let json = r#"{
            "Self": {"HostName":"mac","DNSName":"mac.tailnet.ts.net.","Online":true,"OS":"macOS"},
            "Peer": {
                "key1": {"HostName":"linux-laptop","DNSName":"linux-laptop.tailnet.ts.net.","Online":true,"OS":"linux","TailscaleIPs":["100.64.0.2"]},
                "key2": {"HostName":"vps","DNSName":"vps.tailnet.ts.net.","Online":false,"OS":"linux","TailscaleIPs":["100.64.0.8"]}
            }
        }"#;
        let peers = parse_tailscale_status(json);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].target, "linux-laptop.tailnet.ts.net");
        assert_eq!(peers[1].online, Some(false));
        let local = parse_local_identity(json);
        assert_eq!(local.machine.as_deref(), Some("mac"));
        assert_eq!(local.host.as_deref(), Some("mac.tailnet.ts.net"));
    }

    #[test]
    fn prepare_writes_an_invite_and_a_howto_without_secrets() {
        let data = scratch("prepare");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let outcome = prepare(&data, "vps", "localhost", Some("studio.tailnet.ts.net")).unwrap();
        assert_eq!(outcome.kind, OutcomeKind::Prepared);
        let invite = fleet::pending_invite_path(&data, "vps").unwrap();
        assert!(invite.is_file());
        let howto = fs::read_to_string(invite.with_extension("howto")).unwrap();
        assert!(howto.contains("ouro fleet enroll vps.ouro --delete"));
        assert!(!howto.contains("BEGIN"));
        assert!(!howto.contains("cookie"));
        let invitation = fs::read_to_string(&invite).unwrap();
        assert!(
            invitation.contains("cookie"),
            "the invitation file itself holds membership material"
        );
        assert!(!howto.contains(&invitation));
    }

    #[test]
    fn ssh_add_without_a_matching_binary_still_copies_only_the_invite_file() {
        let data = scratch("cross-arch");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let remote = FakeRemote::linux("/home/op");
        // Empty roots, not discovered ones: whether this machine happens to have run
        // `make dist-linux` must not decide what this test asserts.
        let outcome = add_with_options(
            &data,
            "op@vps",
            Some("vps"),
            Some("localhost"),
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
            &AddOptions {
                dist_roots: Some(Vec::new()),
                ..AddOptions::default()
            },
            &mut SilentNotify,
        )
        .unwrap();
        assert_eq!(outcome.kind, OutcomeKind::InviteDelivered);
        let copies = remote.copies.lock().unwrap();
        assert_eq!(copies.len(), 1);
        assert!(copies[0].1.ends_with("vps.ouro"));
        let runs = remote.runs.lock().unwrap();
        assert!(
            runs.iter()
                .all(|script| !script.contains("cookie") && !script.contains("BEGIN CERTIFICATE")),
            "membership material must not appear on the SSH command line: {runs:?}"
        );
        assert!(
            outcome
                .log
                .iter()
                .any(|line| line.contains("cannot copy this binary")),
            "{:?}",
            outcome.log
        );
        assert!(outcome.recipe.is_some());
    }

    #[test]
    fn ssh_add_refuses_to_interpolate_an_unsafe_remote_home() {
        let data = scratch("unsafe-home");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let remote = FakeRemote::linux("/tmp/x;id");
        let error = add_with(
            &data,
            "op@vps",
            Some("vps"),
            Some("localhost"),
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("safe absolute path"), "{error}");
        assert!(remote.copies.lock().unwrap().is_empty());
    }

    #[test]
    fn a_failed_enroll_names_the_pending_invitation_that_remains() {
        let data = scratch("enroll-fail");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let mut remote = FakeRemote::linux("/home/op");
        remote.fail_enroll = true;
        let error = add_with(
            &data,
            "op@vps",
            Some("vps"),
            Some("localhost"),
            Via::Ssh,
            Some(std::env::current_exe().unwrap().as_path()),
            Some("studio.tailnet.ts.net"),
            &remote,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("the invitation remains at"), "{error}");
        assert!(error.contains("vps.ouro"), "{error}");
    }

    #[test]
    fn enroll_remote_only_accepts_ouro_invitation_files() {
        let remote = FakeRemote::linux("/home/op");
        let error = enroll_remote(&remote, "op@vps", "/usr/bin/ouro", "/tmp/invite.json")
            .unwrap_err()
            .to_string();
        assert!(error.contains(".ouro"), "{error}");
        assert!(remote.runs.lock().unwrap().is_empty());
    }

    #[test]
    fn intent_round_trips_privately_and_apply_creates_then_prepares() {
        let data = scratch("intent");
        let intent = Intent {
            schema: 1,
            owner_machine: "studio".into(),
            owner_host: "localhost".into(),
            fleet_name: Some("Studio fleet".into()),
            add: Some(AddPlan {
                kind: AddKind::Prepare,
                machine: "laptop".into(),
                host: "localhost".into(),
                target: None,
                via: "ssh".into(),
                binary: None,
            }),
        };
        write_intent(&data, &intent).unwrap();
        let path = fleet::add_intent_path(&data);
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o777, 0o600);
        // A stale plan from a failed restart must never wedge the next confirm.
        let mut retry = intent.clone();
        retry.add.as_mut().unwrap().machine = "vps".into();
        write_intent(&data, &retry).unwrap();
        assert_eq!(
            load_intent(&data).unwrap().unwrap().add.unwrap().machine,
            "vps"
        );
        let outcome = apply_intent(&data).unwrap();
        assert_eq!(outcome.machine, "vps");
        assert!(fleet::load(&data).unwrap().is_some());
        assert!(!path.exists(), "the intent is consumed");
        assert!(fleet::pending_invite_path(&data, "vps").unwrap().is_file());
    }

    #[test]
    fn create_only_intent_makes_this_mac_the_owner() {
        let data = scratch("create-only");
        write_intent(
            &data,
            &Intent {
                schema: 1,
                owner_machine: "studio".into(),
                owner_host: "localhost".into(),
                fleet_name: Some("Studio fleet".into()),
                add: None,
            },
        )
        .unwrap();
        let outcome = apply_intent(&data).unwrap();
        assert_eq!(outcome.kind, OutcomeKind::Created);
        assert_eq!(outcome.machine, "studio");
        assert!(fleet::load(&data).unwrap().is_some());
        assert!(!fleet::add_intent_path(&data).exists());
    }

    #[test]
    fn enroll_preflight_refuses_a_group_readable_invitation() {
        let dir = scratch("enroll-mode");
        let invite = dir.join("open.ouro");
        fs::write(&invite, "{}").unwrap();
        fs::set_permissions(&invite, fs::Permissions::from_mode(0o644)).unwrap();
        let error = enroll_preflight(&invite).unwrap_err().to_string();
        assert!(error.contains("0600"), "{error}");
    }

    // -------------------------------------------------------------------------------
    // Resolving a cross-platform dist artifact
    // -------------------------------------------------------------------------------

    /// The name searched for has to be the name `make dist` writes, and the version in it
    /// has to be the version this binary reports. Both are pinned here rather than
    /// described, because a silent divergence would mean either a miss on every lookup or
    /// — worse — copying a build the fleet then refuses to form with.
    #[test]
    fn the_dist_artifact_name_pins_the_running_version_and_the_make_dist_shape() {
        assert_eq!(local_version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(
            crate::update::running_version().to_string(),
            local_version(),
            "`ouro update` and the dist lookup must fence on one version"
        );
        assert_eq!(
            crate::proto::client_name(),
            format!("ouro {}", local_version()),
            "`ouro version` prints this string on its first line"
        );
        assert_eq!(
            dist_artifact_name(local_version(), "x86_64-unknown-linux-gnu"),
            format!("ouro-{}-x86_64-unknown-linux-gnu", local_version()),
            "make dist writes dist/ouro-<version>-<triple>"
        );
    }

    #[test]
    fn dist_roots_search_the_env_override_then_upward_then_the_cwd() {
        let roots = dist_roots(
            Some("/opt/ouro-artifacts"),
            Some(Path::new("/src/repo/tui/target/release/ouro")),
            Some(Path::new("/src/repo/tui")),
        );
        assert_eq!(roots[0], PathBuf::from("/opt/ouro-artifacts"));
        assert_eq!(roots[1], PathBuf::from("/src/repo/tui/target/release/dist"));
        assert_eq!(roots[2], PathBuf::from("/src/repo/tui/target/dist"));
        assert_eq!(roots[3], PathBuf::from("/src/repo/tui/dist"));
        assert_eq!(
            roots[4],
            PathBuf::from("/src/repo/dist"),
            "a checkout's release binary must find the repo root's dist"
        );
        // `/src/repo/tui/dist` is both an ancestor root and the CWD root; it appears once.
        assert_eq!(
            roots
                .iter()
                .filter(|root| *root == Path::new("/src/repo/tui/dist"))
                .count(),
            1
        );
        // An empty or unset override contributes nothing.
        let bare = dist_roots(Some("   "), None, Some(Path::new("/work")));
        assert_eq!(bare, vec![PathBuf::from("/work/dist")]);
    }

    #[test]
    fn a_cross_triple_install_plan_resolves_a_matching_dist_artifact() {
        let root = dist_fixture("dist-hit", "9.9.9", "x86_64-unknown-linux-gnu");
        let plan = install_plan(
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            None,
            None,
            "9.9.9",
            &[root.join("nowhere"), root.clone()],
        )
        .unwrap();
        let InstallPlan::Copy { path, note } = plan else {
            panic!("a matching artifact must become a Copy: {plan:?}");
        };
        assert_eq!(path, root.join("ouro-9.9.9-x86_64-unknown-linux-gnu"));
        let note = note.expect("a resolved artifact records where it came from");
        assert!(
            note.contains("resolved ouro-9.9.9-x86_64-unknown-linux-gnu"),
            "{note}"
        );
        assert!(note.contains(&root.display().to_string()), "{note}");
    }

    #[test]
    fn the_env_dist_dir_wins_over_a_dist_directory_above_this_binary() {
        let preferred = dist_fixture("dist-env", "9.9.9", "x86_64-unknown-linux-gnu");
        let fallback = dist_fixture("dist-walkup", "9.9.9", "x86_64-unknown-linux-gnu");
        let plan = install_plan(
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            None,
            None,
            "9.9.9",
            &[preferred.clone(), fallback.clone()],
        )
        .unwrap();
        let InstallPlan::Copy { path, .. } = plan else {
            panic!("both roots hold the artifact; the first must win");
        };
        assert!(path.starts_with(&preferred), "{}", path.display());
        assert!(!path.starts_with(&fallback), "{}", path.display());
    }

    /// Placement fences on an exact version match, so a build for the right CPU but the
    /// wrong version is named and left alone — never copied to save the operator a step.
    #[test]
    fn a_dist_artifact_of_another_version_is_named_and_refused_not_copied() {
        let root = dist_fixture("dist-mismatch", "0.2.0", "x86_64-unknown-linux-gnu");
        let plan = install_plan(
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            None,
            None,
            "0.1.0",
            std::slice::from_ref(&root),
        )
        .unwrap();
        let InstallPlan::RecipeOnly { reason } = plan else {
            panic!("a version mismatch must refuse, not copy");
        };
        assert!(reason.contains("is version 0.2.0"), "{reason}");
        assert!(reason.contains("this ouro is 0.1.0"), "{reason}");
        assert!(reason.contains("was not copied"), "{reason}");
        assert!(reason.contains("make dist-linux"), "{reason}");
        assert!(
            reason.contains("ouro-0.1.0-x86_64-unknown-linux-gnu"),
            "the refusal must name the artifact that would work: {reason}"
        );
    }

    #[test]
    fn a_missing_dist_artifact_names_the_file_the_directories_and_make_dist_linux() {
        let empty = scratch("dist-empty");
        let plan = install_plan(
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            None,
            None,
            "0.1.0",
            std::slice::from_ref(&empty),
        )
        .unwrap();
        let InstallPlan::RecipeOnly { reason } = plan else {
            panic!("nothing to copy must stay a recipe");
        };
        assert!(reason.contains("cannot copy this binary"), "{reason}");
        assert!(
            reason.contains("ouro-0.1.0-x86_64-unknown-linux-gnu"),
            "{reason}"
        );
        assert!(reason.contains(&empty.display().to_string()), "{reason}");
        assert!(reason.contains("make dist-linux"), "{reason}");
        assert!(reason.contains("OUROBOROS_DIST_DIR"), "{reason}");

        // With nowhere to look at all, the refusal says so rather than naming ghosts.
        let nothing = install_plan(
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            None,
            None,
            "0.1.0",
            &[],
        )
        .unwrap();
        let InstallPlan::RecipeOnly { reason } = nothing else {
            panic!("no roots must stay a recipe");
        };
        assert!(reason.contains("no `dist` directory"), "{reason}");
        assert!(reason.contains("make dist-linux"), "{reason}");
    }

    /// The resolved artifact must take the same route a `--binary` one takes: staged as
    /// `.partial`, moved into place, chmod 755, then enroll. Nothing about the copy path
    /// changes because the path was found rather than typed.
    #[test]
    fn a_resolved_dist_artifact_flows_through_the_copy_path_and_enrolls() {
        let data = scratch("dist-copy-flow");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let root = dist_fixture("dist-copy", local_version(), &foreign_triple());
        let artifact = root.join(dist_artifact_name(local_version(), &foreign_triple()));

        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(true, false)]),
            ..ScriptedRemote::default()
        };
        let outcome = add_with_options(
            &data,
            "op@vps",
            Some("vps"),
            Some("100.64.0.8"),
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
            &AddOptions {
                dist_roots: Some(vec![root.clone()]),
                ..AddOptions::default()
            },
            &mut SilentNotify,
        )
        .unwrap();

        assert_eq!(outcome.kind, OutcomeKind::Enrolled);
        let copies = remote.copies.lock().unwrap();
        assert_eq!(copies.len(), 2, "the invitation and the binary: {copies:?}");
        assert!(copies[0].1.ends_with("vps.ouro"));
        assert_eq!(copies[1].0, artifact);
        assert_eq!(copies[1].1, "/home/op/.local/bin/ouro.partial");
        drop(copies);
        assert!(remote.ran("mv '/home/op/.local/bin/ouro.partial' '/home/op/.local/bin/ouro'"));
        assert!(remote.ran("fleet enroll '/home/op/.local/share/ouroboros/incoming/vps.ouro'"));
        assert!(
            outcome
                .log
                .iter()
                .any(|line| line.contains("resolved") && line.contains("ouro-")),
            "the add log must record which artifact was chosen: {:?}",
            outcome.log
        );
        assert!(
            outcome
                .log
                .iter()
                .any(|line| line.contains(&artifact.display().to_string())),
            "the add log must record where it was found: {:?}",
            outcome.log
        );
    }

    // -------------------------------------------------------------------------------
    // Guided Tailscale enrollment
    // -------------------------------------------------------------------------------

    #[test]
    fn an_add_without_setup_tailscale_names_the_flag_when_no_address_is_provable() {
        let data = scratch("no-address");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(false, false)]),
            ..ScriptedRemote::default()
        };
        let error = add_with_options(
            &data,
            "op@vps",
            Some("vps"),
            None,
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
            &AddOptions::default(),
            &mut SilentNotify,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("could not prove a private address"),
            "{error}"
        );
        assert!(error.contains("--setup-tailscale"), "{error}");
        assert!(error.contains("as root"), "{error}");
        assert!(remote.copies.lock().unwrap().is_empty());
        assert!(!fleet::pending_invite_path(&data, "vps").unwrap().exists());
    }

    #[test]
    fn setup_tailscale_installs_surfaces_the_url_and_waits_for_the_address() {
        let data = scratch("guided-install");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(false, false), &probe_text(true, true)]),
            capability: queue(&[
                "tailscale=missing\nsudo=yes\n",
                "tailscale=present\nsudo=yes\n",
            ]),
            up: queue(&[UP_STARTING]),
            log_reads: queue(&["", AUTH_LOG]),
            ip_polls: queue(&["ip=\n", "ip=100.64.0.8\n"]),
            ..ScriptedRemote::default()
        };
        let mut notify = Lines::default();
        let outcome = add_with_options(
            &data,
            "op@vps",
            None,
            None,
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
            &AddOptions {
                setup_tailscale: true,
                dist_roots: Some(Vec::new()),
                tailscale_poll: instant_budget(3, 3),
            },
            &mut notify,
        )
        .unwrap();

        // The exact command is printed before it runs, because it fetches and executes
        // code as root on someone else's machine.
        let printed = notify.text();
        assert!(printed.contains(TAILSCALE_INSTALL), "{printed}");
        assert!(
            printed.contains("https://login.tailscale.com/a/deadbeef"),
            "the sign-in URL must reach the operator live: {printed}"
        );
        assert!(printed.contains("sudo tailscale up"), "{printed}");
        assert!(remote.ran(TAILSCALE_INSTALL));
        assert!(remote.ran("rm -f '/tmp/ouro-tailscale-up.abc123'"));

        // The re-probe supplies both the machine name and the tailnet address.
        assert_eq!(outcome.machine, "vps");
        assert_eq!(outcome.host, "100.64.0.8");
        assert_eq!(outcome.kind, OutcomeKind::Enrolled);
        assert!(outcome
            .log
            .iter()
            .any(|line| line.contains("installed Tailscale on op@vps")));
        assert!(outcome
            .log
            .iter()
            .any(|line| line.contains("re-probed op@vps")));
    }

    #[test]
    fn setup_tailscale_refuses_without_passwordless_sudo_and_changes_nothing() {
        let data = scratch("guided-nosudo");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(false, false)]),
            capability: queue(&["tailscale=missing\nsudo=no\n"]),
            ..ScriptedRemote::default()
        };
        let mut notify = Lines::default();
        let error = add_with_options(
            &data,
            "op@vps",
            Some("vps"),
            None,
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
            &AddOptions {
                setup_tailscale: true,
                dist_roots: Some(Vec::new()),
                tailscale_poll: instant_budget(3, 3),
            },
            &mut notify,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("passwordless sudo on op@vps"), "{error}");
        assert!(error.contains("sudo -n true"), "{error}");
        assert!(error.contains("the Tailscale installer"), "{error}");
        assert!(error.contains("Nothing was changed"), "{error}");
        assert!(!remote.ran("install.sh"), "the installer must not have run");
        assert!(!remote.ran("tailscale up"));
        assert!(remote.copies.lock().unwrap().is_empty());
        assert!(!fleet::pending_invite_path(&data, "vps").unwrap().exists());
        assert!(notify.0.is_empty(), "{:?}", notify.0);
    }

    /// Resuming after a timeout is "run the same command again". That is only true if a
    /// second run installs nothing and starts nothing when Tailscale is already up.
    #[test]
    fn setup_tailscale_reuses_an_installed_tailscale_that_is_already_up() {
        let data = scratch("guided-idempotent");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(false, false), &probe_text(true, true)]),
            capability: queue(&["tailscale=present\nsudo=yes\n"]),
            up: queue(&["state=up\n"]),
            ..ScriptedRemote::default()
        };
        let mut notify = Lines::default();
        let outcome = add_with_options(
            &data,
            "op@vps",
            Some("vps"),
            None,
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
            &AddOptions {
                setup_tailscale: true,
                dist_roots: Some(Vec::new()),
                tailscale_poll: instant_budget(3, 3),
            },
            &mut notify,
        )
        .unwrap();

        assert_eq!(outcome.kind, OutcomeKind::Enrolled);
        assert!(
            !remote.ran("install.sh"),
            "a present tailscale is not reinstalled"
        );
        assert!(
            !remote.ran("head -c"),
            "an already-up tailnet needs no URL poll"
        );
        assert!(outcome
            .log
            .iter()
            .any(|line| line.contains("already installed")));
        assert!(outcome.log.iter().any(|line| line.contains("already up")));
    }

    #[test]
    fn setup_tailscale_timeout_names_how_to_resume() {
        let data = scratch("guided-timeout");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(false, false)]),
            capability: queue(&["tailscale=present\nsudo=yes\n"]),
            up: queue(&[UP_STARTING]),
            log_reads: queue(&[AUTH_LOG]),
            ip_polls: queue(&["ip=\n"]),
            ..ScriptedRemote::default()
        };
        let mut notify = Lines::default();
        let error = add_with_options(
            &data,
            "op@vps",
            Some("vps"),
            None,
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
            &AddOptions {
                setup_tailscale: true,
                dist_roots: Some(Vec::new()),
                tailscale_poll: instant_budget(2, 4),
            },
            &mut notify,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("still has no Tailscale address"), "{error}");
        assert!(
            error.contains("run the same `ouro fleet add` command again"),
            "{error}"
        );
        assert!(error.contains("Nothing was enrolled"), "{error}");
        assert!(!fleet::pending_invite_path(&data, "vps").unwrap().exists());
        // The temp file `tailscale up` wrote the URL into is removed either way.
        assert!(remote.ran("rm -f '/tmp/ouro-tailscale-up.abc123'"));
        assert_eq!(
            remote
                .runs
                .lock()
                .unwrap()
                .iter()
                .filter(|script| script.contains("printf 'ip="))
                .count(),
            4,
            "the poll is bounded by the budget"
        );
    }

    #[test]
    fn setup_tailscale_is_a_no_op_when_the_destination_already_has_an_address() {
        let data = scratch("guided-noop");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(true, true)]),
            ..ScriptedRemote::default()
        };
        let mut notify = Lines::default();
        let outcome = add_with_options(
            &data,
            "op@vps",
            Some("vps"),
            None,
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
            &AddOptions {
                setup_tailscale: true,
                dist_roots: Some(Vec::new()),
                tailscale_poll: instant_budget(3, 3),
            },
            &mut notify,
        )
        .unwrap();

        assert_eq!(outcome.kind, OutcomeKind::Enrolled);
        assert!(
            outcome
                .log
                .iter()
                .any(|line| line.contains("--setup-tailscale did nothing")
                    && line.contains("100.64.0.8")),
            "{:?}",
            outcome.log
        );
        assert!(
            !remote.ran("sudo -n true"),
            "nothing is asked of the destination"
        );
        assert!(!remote.ran("tailscale up"));
        assert!(notify.0.is_empty(), "{:?}", notify.0);
    }

    /// The sign-in link is a live credential. It belongs on the terminal and nowhere the
    /// add can persist it: not the log the TUI keeps, not the invitation, not the howto.
    #[test]
    fn the_tailscale_sign_in_url_never_reaches_the_add_log_or_a_file() {
        let data = scratch("guided-url-privacy");
        fleet::create(&data, None, "studio", "localhost", Ports::DEFAULT).unwrap();
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(false, false), &probe_text(true, false)]),
            capability: queue(&["tailscale=present\nsudo=yes\n"]),
            up: queue(&[UP_STARTING]),
            log_reads: queue(&[AUTH_LOG]),
            ip_polls: queue(&["ip=100.64.0.8\n"]),
            ..ScriptedRemote::default()
        };
        let mut notify = Lines::default();
        let outcome = add_with_options(
            &data,
            "op@vps",
            Some("vps"),
            None,
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
            &AddOptions {
                setup_tailscale: true,
                dist_roots: Some(Vec::new()),
                tailscale_poll: instant_budget(3, 3),
            },
            &mut notify,
        )
        .unwrap();

        // Cross-triple with no artifact: the invitation and the howto both stay on disk.
        assert_eq!(outcome.kind, OutcomeKind::InviteDelivered);
        assert!(notify.text().contains("login.tailscale.com"));
        assert!(
            !outcome.log.join("\n").contains("login.tailscale.com"),
            "{:?}",
            outcome.log
        );
        assert!(!render_outcome(&outcome).contains("login.tailscale.com"));
        assert!(
            !all_file_text(&data).contains("login.tailscale.com"),
            "no file under the data directory may hold the sign-in URL"
        );
        assert!(
            remote
                .runs
                .lock()
                .unwrap()
                .iter()
                .all(|script| !script.contains("login.tailscale.com")),
            "and it is never sent back to the destination on a command line"
        );
    }

    /// Remote output is data. Only a URL-shaped, URL-safe token is ever surfaced, so a
    /// destination cannot paint this terminal with an escape sequence.
    #[test]
    fn only_a_url_safe_token_is_taken_from_remote_tailscale_output() {
        assert_eq!(
            auth_url(AUTH_LOG).as_deref(),
            Some("https://login.tailscale.com/a/deadbeef")
        );
        assert_eq!(
            auth_url("To authenticate, visit: https://login.tailscale.com/a/beef.").as_deref(),
            Some("https://login.tailscale.com/a/beef"),
            "trailing sentence punctuation is not part of the link"
        );
        assert_eq!(
            auth_url("visit: https://login.tailscale.com/a/\u{1b}[2Jwipe").as_deref(),
            None,
            "an escape sequence disqualifies the token"
        );
        assert_eq!(auth_url("http://login.tailscale.com/a/x"), None);
        assert_eq!(auth_url("https://"), None);
        assert_eq!(auth_url("Backend state: NeedsLogin\n"), None);
    }
}
