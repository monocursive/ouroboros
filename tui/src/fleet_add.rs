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
    #[cfg(test)]
    pub release_key: Option<crate::update::PublicKey>,
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
pub const TAILSCALE_INSTALL: &str = "curl -fsSL https://tailscale.com/install.sh | sudo -n sh";

/// The operator-facing quote of what guided enrollment starts detached — the exact
/// `sudo -n tailscale up` inside [`TAILSCALE_UP_SCRIPT`]. Public so every consent surface
/// quotes this one string instead of holding a copy that can drift.
pub const TAILSCALE_UP_COMMAND: &str = "sudo -n tailscale up";

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
    fn run_controlled(&self, target: &str, script: &str, cancel: &Cancel) -> Result<String> {
        check_cancel(cancel)?;
        self.run(target, script)
    }
    fn copy_controlled(
        &self,
        local: &Path,
        target: &str,
        path: &str,
        cancel: &Cancel,
    ) -> Result<()> {
        check_cancel(cancel)?;
        self.copy_to(local, target, path)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SshRemote {
    pub via: Via,
}

impl Remote for SshRemote {
    fn run(&self, target: &str, script: &str) -> Result<String> {
        self.run_controlled(target, script, &Cancel::default())
    }

    fn copy_to(&self, local: &Path, target: &str, remote_path: &str) -> Result<()> {
        self.copy_controlled(local, target, remote_path, &Cancel::default())
    }

    fn run_controlled(&self, target: &str, script: &str, cancel: &Cancel) -> Result<String> {
        validate_target(target)?;
        let mut command = ssh_command(self.via, target);
        command.arg(script).stdin(Stdio::null());
        let output =
            crate::subprocess::output(command, Duration::from_secs(180), || cancel.is_cancelled())?;
        if !output.status.success() {
            bail!(
                "{} {target} failed ({}): {}",
                self.via.as_str(),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn copy_controlled(
        &self,
        local: &Path,
        target: &str,
        remote_path: &str,
        cancel: &Cancel,
    ) -> Result<()> {
        validate_target(target)?;
        require_safe_unix_path(remote_path, "copy destination")?;
        let command = match self.via {
            Via::Ssh => {
                let mut command = Command::new("scp");
                command
                    .args([
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "ConnectTimeout=15",
                        "-o",
                        "ServerAliveInterval=10",
                        "-o",
                        "ServerAliveCountMax=3",
                        "-p",
                        "--",
                    ])
                    .arg(local)
                    .arg(format!("{target}:{remote_path}"))
                    .stdin(Stdio::null());
                command
            }
            Via::Tailscale => {
                let mut command = ssh_command(Via::Tailscale, target);
                command.arg(format!("umask 077 && cat > '{remote_path}.partial' && mv '{remote_path}.partial' '{remote_path}' && chmod 600 '{remote_path}'"))
                    .stdin(Stdio::from(fs::File::open(local)?));
                command
            }
        };
        let output =
            crate::subprocess::output(command, Duration::from_secs(900), || cancel.is_cancelled())?;
        if !output.status.success() {
            bail!(
                "copy to {target} failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}

fn validate_target(target: &str) -> Result<()> {
    if target.is_empty()
        || target.starts_with('-')
        || target
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "'\"`;|&$()\\".contains(c))
    {
        bail!("invalid SSH target; use a host or user@host");
    }
    Ok(())
}

struct ControlledRemote<'a> {
    inner: &'a dyn Remote,
    cancel: &'a Cancel,
}
impl Remote for ControlledRemote<'_> {
    fn run(&self, target: &str, script: &str) -> Result<String> {
        self.inner.run_controlled(target, script, self.cancel)
    }
    fn copy_to(&self, local: &Path, target: &str, path: &str) -> Result<()> {
        self.inner.copy_controlled(local, target, path, self.cancel)
    }
}

fn ssh_command(via: Via, target: &str) -> Command {
    match via {
        Via::Ssh => {
            let mut command = Command::new("ssh");
            command
                .args([
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=15",
                    "-o",
                    "ServerAliveInterval=10",
                    "-o",
                    "ServerAliveCountMax=3",
                    "--",
                ])
                .arg(target);
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
    apply_intent_with_ports(data_dir, Ports::DEFAULT)
}

fn apply_intent_with_ports(data_dir: &Path, ports: Ports) -> Result<Outcome> {
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
            ports,
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

// -----------------------------------------------------------------------------------
// The deploy pipeline as a typed event stream — the client integration seam.
//
// Every surface that runs an add (CLI, TUI stepper, desktop pane) renders the same
// pipeline; this contract is what they render. `spawn_add` runs the pipeline on its
// own thread and hands each event to the caller's sink as it happens, so a UI shows
// live progress instead of a log dump at the end. The variants below are the whole
// vocabulary: today the bridge emits `Line` plus a terminal event; the pipeline
// internals emit the typed variants at each stage as they are wired to this seam.
// -----------------------------------------------------------------------------------

/// One event from a running `fleet add`. Terminal variants are `Done` and `Failed`;
/// exactly one of them ends every run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddEvent {
    /// Free-form progress, exactly what the CLI would print.
    Line(String),
    /// The destination answered the probe.
    Probed {
        triple: String,
        home: String,
        tailscale: Option<String>,
        hostname: Option<String>,
        has_ouro: bool,
    },
    /// What the network step decided for how the fleet reaches the destination.
    Network(NetworkPlan),
    /// The Tailscale sign-in link. Time-critical and credential-bearing: render it for
    /// the operator (copyable in a terminal, clickable on the desktop) and keep it out
    /// of logs and files, exactly as the CLI does.
    AuthUrl(String),
    /// Waiting for the destination to receive a tailnet address after the sign-in.
    WaitingForAddress { elapsed_s: u64, budget_s: u64 },
    /// Which binary will run on the destination.
    Install(InstallDecision),
    /// A copy is in flight: "binary" or "invitation".
    Copying { what: &'static str },
    /// `ouro fleet enroll` is running on the destination.
    Enrolling,
    /// The add finished; the outcome carries the log and any recipe.
    Done(Outcome),
    /// The add failed. `residue` names what the failure left behind and what to do
    /// about it (a pending invitation, a joined-but-stopped destination), one line per
    /// fact, so a UI can render guidance instead of a bare error.
    Failed { error: String, residue: Vec<String> },
}

/// How the fleet will reach the destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkPlan {
    /// The operator named the address.
    HostProvided(String),
    /// The destination already answers on a tailnet address.
    TailscaleExisting(String),
    /// Guided enrollment will install and sign in Tailscale there (consented).
    GuidedSetup,
}

/// Which binary the destination will run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallDecision {
    /// The destination already has a matching `ouro`.
    RemoteExisting(String),
    /// This executable's triple matches; it copies itself.
    SelfCopy,
    /// A local file this Mac will copy: a cross-platform dist artifact resolved for the
    /// destination's triple, or the one the operator named with `--binary`. Both are a
    /// path on this Mac that is about to become the destination's `ouro`.
    DistArtifact(PathBuf),
    /// Nothing installable; the invitation is delivered with a recipe.
    RecipeOnly,
}

/// Everything one add needs, owned, so the pipeline can run on its own thread.
#[derive(Clone, Debug)]
pub struct AddParams {
    pub data_dir: PathBuf,
    pub target: String,
    pub machine: Option<String>,
    pub host: Option<String>,
    pub via: Via,
    pub binary: Option<PathBuf>,
    pub owner_host: Option<String>,
    pub options: AddOptions,
}

/// Where a running add delivers its events. One method, so a UI thread's channel, a
/// terminal, or a test's vector are all the same thing to the pipeline.
pub trait EventSink {
    fn emit(&mut self, event: AddEvent);
}

/// Adapts a closure into an [`EventSink`].
pub struct FnSink<F>(pub F);

impl<F: FnMut(AddEvent)> EventSink for FnSink<F> {
    fn emit(&mut self, event: AddEvent) {
        (self.0)(event);
    }
}

/// Renders the event stream back into the line-oriented [`Notify`] the CLI and the
/// pre-event callers already speak.
///
/// This is the one place that turns typed events into operator text, so the CLI and
/// `add_with_options` cannot drift apart: the typed variants a line-oriented surface has
/// nothing to say about are dropped, because the add log already carries those facts and
/// the CLI prints it at the end. `AuthUrl` is the exception — the sign-in link is
/// time-critical, so it is printed the moment it exists, exactly as before.
pub struct NotifyEvents<'notify> {
    notify: &'notify mut dyn Notify,
}

impl<'notify> NotifyEvents<'notify> {
    pub fn new(notify: &'notify mut dyn Notify) -> Self {
        Self { notify }
    }
}

impl EventSink for NotifyEvents<'_> {
    fn emit(&mut self, event: AddEvent) {
        match event {
            AddEvent::Line(text) => self.notify.line(&text),
            AddEvent::AuthUrl(url) => {
                self.notify.line("");
                self.notify
                    .line("Open this link and approve the machine (a one-time Tailscale sign-in):");
                self.notify.line(&format!("  {url}"));
            }
            _ => {}
        }
    }
}

/// The stop request shared with a running add.
///
/// It is checked at every pipeline boundary and while SSH/scp runs. Cancellation
/// interrupts the local operation and closes its process group.
/// The remote command may already have changed the host, so failures report residue.
#[derive(Clone, Debug, Default)]
pub struct Cancel(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A running add. Dropping the handle does not stop the pipeline; `cancel` requests a
/// stop at the next boundary or during a running SSH/copy operation. `join` waits for
/// cleanup and the final residue report.
pub struct AddHandle {
    cancel: Cancel,
    join: std::thread::JoinHandle<()>,
}

impl AddHandle {
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn join(self) {
        let _ = self.join.join();
    }
}

/// Run a real SSH add on its own thread, delivering every event to `sink` as it
/// happens. Exactly one terminal event (`Done` or `Failed`) is delivered last.
pub fn spawn_add(params: AddParams, sink: impl Fn(AddEvent) + Send + Sync + 'static) -> AddHandle {
    let cancel = Cancel::new();
    let flag = cancel.clone();
    let join = std::thread::spawn(move || {
        let remote = SshRemote { via: params.via };
        let mut sink = FnSink(sink);
        let _ = add_with_events(&params, &remote, &flag, &mut sink);
    });
    AddHandle { cancel, join }
}

/// Run one add on this thread, delivering every event to `sink` as it happens —
/// including exactly one terminal event.
///
/// The returned `Result` is the same one [`add_with_options`] returns, so a caller that
/// already reports failures its own way (the CLI, which exits on an `Err`) can ignore the
/// terminal event and keep its exit path while still rendering the live stream.
pub fn add_with_events(
    params: &AddParams,
    remote: &dyn Remote,
    cancel: &Cancel,
    sink: &mut dyn EventSink,
) -> Result<Outcome> {
    let (result, residue) = add_pipeline(
        &params.data_dir,
        &params.target,
        params.machine.as_deref(),
        params.host.as_deref(),
        params.via,
        params.binary.as_deref(),
        params.owner_host.as_deref(),
        remote,
        &params.options,
        sink,
        cancel,
    );
    match &result {
        Ok(outcome) => sink.emit(AddEvent::Done(outcome.clone())),
        Err(error) => sink.emit(AddEvent::Failed {
            error: format!("{error:#}"),
            residue,
        }),
    }
    result
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
    let mut sink = NotifyEvents::new(notify);
    add_pipeline(
        data_dir,
        target,
        machine,
        host,
        via,
        binary,
        owner_host,
        remote,
        options,
        &mut sink,
        &Cancel::default(),
    )
    .0
}

/// The pipeline plus the residue it would leave behind if it stopped right now.
///
/// The residue is a side channel rather than a return value because it is true of the
/// run, not of the error: a cancel and a refused enroll at the same point leave exactly
/// the same private material behind, and both callers need to say so.
#[allow(clippy::too_many_arguments)]
fn add_pipeline(
    data_dir: &Path,
    target: &str,
    machine: Option<&str>,
    host: Option<&str>,
    via: Via,
    binary: Option<&Path>,
    owner_host: Option<&str>,
    remote: &dyn Remote,
    options: &AddOptions,
    sink: &mut dyn EventSink,
    cancel: &Cancel,
) -> (Result<Outcome>, Vec<String>) {
    let mut residue = Residue::default();
    let remote = ControlledRemote {
        inner: remote,
        cancel,
    };
    let result = run_add(
        data_dir,
        target,
        machine,
        host,
        via,
        binary,
        owner_host,
        &remote,
        options,
        sink,
        cancel,
        &mut residue,
    );
    let lines = if result.is_ok() {
        Vec::new()
    } else {
        residue.lines()
    };
    (result, lines)
}

#[allow(clippy::too_many_arguments)]
fn run_add(
    data_dir: &Path,
    target: &str,
    machine: Option<&str>,
    host: Option<&str>,
    via: Via,
    binary: Option<&Path>,
    owner_host: Option<&str>,
    remote: &dyn Remote,
    options: &AddOptions,
    sink: &mut dyn EventSink,
    cancel: &Cancel,
    residue: &mut Residue,
) -> Result<Outcome> {
    let mut log = Vec::new();
    log.push(format!("probing {target} over {}", via.as_str()));
    check_cancel(cancel)?;
    let probe_text = remote.run(target, PROBE_SCRIPT)?;
    let mut probe = parse_probe(&probe_text)?;
    require_safe_unix_path(&probe.home, "home")?;
    let remote_triple = probe.triple()?;
    let local = local_triple()?;
    sink.emit(probed(&probe, &remote_triple));
    log.push(format!("remote is {remote_triple} (home {})", probe.home));

    let requested_host = host
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let host_was_requested = requested_host.is_some();
    let mut guided = false;

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
            // The decision is announced before the work starts: guided enrollment is
            // minutes of installing, signing in, and polling.
            guided = true;
            sink.emit(AddEvent::Network(NetworkPlan::GuidedSetup));
            setup_tailscale(
                remote,
                target,
                options.tailscale_poll,
                &mut log,
                sink,
                cancel,
            )?;
            check_cancel(cancel)?;
            let reprobed = remote.run(target, PROBE_SCRIPT)?;
            probe = parse_probe(&reprobed)?;
            require_safe_unix_path(&probe.home, "home")?;
            // The triple the rest of this add acts on is still the first probe's: the
            // re-probe is the same machine, and reporting a triple the pipeline does not
            // use would mislead whatever renders this.
            sink.emit(probed(&probe, &remote_triple));
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
    if !guided {
        sink.emit(AddEvent::Network(if host_was_requested {
            NetworkPlan::HostProvided(host.clone())
        } else {
            NetworkPlan::TailscaleExisting(host.clone())
        }));
    }

    let machine = machine
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| probe.suggested_machine())
        .ok_or_else(|| anyhow!("could not derive a machine name for {target}; pass --machine"))?;
    fleet::validate_machine(&machine)?;

    if let Some(path) = &probe.ouro {
        require_safe_unix_path(path, "ouro executable")?;
        let expected = format!("ouro {}", local_version());
        if binary.is_none() && probe.ouro_version.as_deref() != Some(expected.as_str()) {
            bail!("destination runs {}; this fleet requires {expected}. Upgrade it with a verified matching release before enrollment", probe.ouro_version.as_deref().unwrap_or("an unknown ouro version"));
        }
    }
    let dist_roots = options
        .dist_roots
        .clone()
        .unwrap_or_else(discovered_dist_roots);
    let mut install = install_plan(
        &local,
        &remote_triple,
        binary,
        probe.ouro.as_deref(),
        local_version(),
        &dist_roots,
    )?;
    let key = crate::update::release_public_key();
    #[cfg(test)]
    let key = options.release_key.clone().or(key);
    let mut verified = match &install {
        InstallPlan::Copy { path, .. } if binary.is_some() || local != remote_triple => {
            let wanted = dist_artifact_name(local_version(), &remote_triple);
            if path.file_name().and_then(|name| name.to_str()) != Some(wanted.as_str()) {
                bail!("deployment artifact must be named {wanted} and accompanied by signed SHA256SUMS");
            }
            let source = crate::update::Source::Directory(
                path.parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf(),
            );
            Some(
                crate::update::fleet_artifact(
                    &source,
                    local_version(),
                    &remote_triple,
                    key.as_ref(),
                )
                .context("verifying deployment artifact before issuing an invitation")?,
            )
        }
        _ => None,
    };

    if matches!(install, InstallPlan::RecipeOnly { .. }) && key.is_some() {
        check_cancel(cancel)?;
        verified = Some(
            crate::update::fleet_artifact(
                &crate::update::fleet_release_source(local_version())?,
                local_version(),
                &remote_triple,
                key.as_ref(),
            )
            .context("fetching a verified matching release before issuing an invitation")?,
        );
        install = InstallPlan::Copy {
            path: verified.as_ref().unwrap().path.clone(),
            note: Some("downloaded and verified the matching signed release".into()),
        };
    }
    if let InstallPlan::UseExisting(path) = &install {
        let protocol = remote
            .run(target, &format!("'{path}' fleet protocol"))
            .context(
            "destination must support secure fleet management protocol 2; upgrade its ouro first",
        )?;
        if protocol.trim() != "2" {
            bail!("destination does not support secure fleet management protocol 2; upgrade its ouro first");
        }
    }
    // When first-run setup has not started the owner yet, verify the remote service
    // and TLS runtime now and explicitly leave peer connectivity pending.
    let peer = if crate::runtime::read_live_publication(data_dir)?.is_some() {
        fleet::load(data_dir)?.map(|profile| profile.node)
    } else {
        None
    };

    // The last boundary before private material exists anywhere.
    check_cancel(cancel)?;
    let invite = write_pending_invite(data_dir, &machine, &host)?;
    residue.invite = Some(invite.clone());
    log.push(format!("created a private invitation for {machine}"));

    let remote_invite = format!(
        "{}/.local/share/ouroboros/incoming/{machine}.ouro",
        probe.home.trim_end_matches('/')
    );
    let incoming_dir = format!(
        "{}/.local/share/ouroboros/incoming",
        probe.home.trim_end_matches('/')
    );
    check_cancel(cancel)?;
    remote.run(target, &format!("mkdir -p -m 700 '{incoming_dir}'"))?;
    check_cancel(cancel)?;
    sink.emit(AddEvent::Copying { what: "invitation" });
    remote.copy_to(&invite, target, &remote_invite)?;
    residue.delivered = Some(remote_invite.clone());
    log.push(format!("copied the invitation to {target}:{remote_invite}"));

    sink.emit(AddEvent::Install(install_decision(&install, binary)));
    match &install {
        InstallPlan::UseExisting(path) => {
            log.push(format!("remote already has {path}"));
            check_cancel(cancel)?;
            residue.enrolling = Some(machine.clone());
            sink.emit(AddEvent::Enrolling);
            enroll_remote(remote, target, path, &remote_invite, peer.as_deref())
                .map_err(|error| pending_invite_error(error, &invite))?;
            finish_enroll(
                &mut log,
                &invite,
                &machine,
                &host,
                OutcomeKind::Enrolled,
                peer.is_some(),
            )
        }
        InstallPlan::Copy { path, note } => {
            let path = verified
                .as_ref()
                .map(|artifact| artifact.path.as_path())
                .unwrap_or(path.as_path());
            if let Some(note) = note {
                log.push(note.clone());
            }
            let remote_bin = format!("{}/.local/bin/ouro", probe.home.trim_end_matches('/'));
            check_cancel(cancel)?;
            remote
                .run(
                    target,
                    &format!(
                        "mkdir -p -m 755 '{}/.local/bin'",
                        probe.home.trim_end_matches('/')
                    ),
                )
                .map_err(|error| pending_invite_error(error, &invite))?;
            check_cancel(cancel)?;
            sink.emit(AddEvent::Copying { what: "binary" });
            remote
                .copy_to(path, target, &format!("{remote_bin}.partial"))
                .map_err(|error| pending_invite_error(error, &invite))?;
            check_cancel(cancel)?;
            remote
                .run(
                    target,
                    &format!(
                        "mv '{remote_bin}.partial' '{remote_bin}' && chmod 755 '{remote_bin}'"
                    ),
                )
                .map_err(|error| pending_invite_error(error, &invite))?;
            log.push(format!("installed {} as {remote_bin}", path.display()));
            check_cancel(cancel)?;
            residue.enrolling = Some(machine.clone());
            sink.emit(AddEvent::Enrolling);
            enroll_remote(remote, target, &remote_bin, &remote_invite, peer.as_deref())
                .map_err(|error| pending_invite_error(error, &invite))?;
            finish_enroll(
                &mut log,
                &invite,
                &machine,
                &host,
                OutcomeKind::Enrolled,
                peer.is_some(),
            )
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

/// What a stopped add left behind, as facts rather than as prose.
///
/// Every field is set at the moment the thing it names becomes true, so whatever stops
/// the run — a refused enroll, a cancel, a dropped SSH connection — reports the same
/// residue. The one-line form goes on the error chain for the CLI; the line-per-fact form
/// rides on `Failed` for a UI that can render guidance.
#[derive(Clone, Debug, Default)]
struct Residue {
    /// The private invitation this add created on this Mac.
    invite: Option<PathBuf>,
    /// Where it was copied on the destination, once that copy succeeded.
    delivered: Option<String>,
    /// The machine name, set once `ouro fleet enroll` is about to run there: from this
    /// point a failure may have a completed join behind it.
    enrolling: Option<String>,
}

impl Residue {
    fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(invite) = &self.invite {
            lines.extend(invite_residue(invite));
        }
        if let Some(delivered) = &self.delivered {
            lines.push(format!("a copy of it is on the destination at {delivered}"));
        }
        if let Some(machine) = &self.enrolling {
            lines.push(format!(
                "`ouro fleet enroll` had already started on the destination: if its join completed before this, {machine} may be joined and running; inspect its fleet doctor and service status"
            ));
            lines.push(format!(
                "`ouro daemon` on {machine} starts it, and rerunning this same add converges it once the invitation above is removed"
            ));
        }
        lines
    }
}

/// The two facts an invitation that is already out leaves behind. Joined with `; ` they
/// are the single line the CLI error chain has always carried.
fn invite_residue(invite: &Path) -> [String; 2] {
    [
        format!("the invitation remains at {} (mode 0600)", invite.display()),
        "if it may already have been copied, treat it as issued — otherwise delete it with rm before adding again".to_string(),
    ]
}

/// Wrap a failure after the invitation was copied so the operator knows exactly what
/// private material is now where, and what to do before retrying.
fn pending_invite_error(error: anyhow::Error, invite: &Path) -> anyhow::Error {
    error.context(invite_residue(invite).join("; "))
}

/// A pipeline boundary. The flag is only ever set through [`AddHandle::cancel`], so this
/// is a no-op for every caller that does not spawn one.
fn check_cancel(cancel: &Cancel) -> Result<()> {
    if cancel.is_cancelled() {
        bail!("cancelled by the operator");
    }
    Ok(())
}

/// Everything the destination answered, as the event a UI renders.
fn probed(probe: &Probe, triple: &str) -> AddEvent {
    AddEvent::Probed {
        triple: triple.to_string(),
        home: probe.home.clone(),
        tailscale: probe.suggested_host(),
        hostname: probe.hostname.clone(),
        has_ouro: probe.ouro.is_some(),
    }
}

/// The plan as the decision a UI names. `--binary` and a resolved dist artifact are both
/// a local path this Mac is about to copy; only the same-triple self-copy has neither an
/// operator-given path nor a resolution note.
fn install_decision(plan: &InstallPlan, binary: Option<&Path>) -> InstallDecision {
    match plan {
        InstallPlan::UseExisting(path) => InstallDecision::RemoteExisting(path.clone()),
        InstallPlan::Copy { path, note } => {
            if binary.is_some() || note.is_some() {
                InstallDecision::DistArtifact(path.clone())
            } else {
                InstallDecision::SelfCopy
            }
        }
        InstallPlan::RecipeOnly { .. } => InstallDecision::RecipeOnly,
    }
}

/// Remove the local copy of a consumed invitation. A failed removal is logged, never
/// silent: the file is membership material.
fn finish_enroll(
    log: &mut Vec<String>,
    invite: &Path,
    machine: &str,
    host: &str,
    kind: OutcomeKind,
    peer_verified: bool,
) -> Result<Outcome> {
    match fs::remove_file(invite) {
        Ok(()) => {}
        Err(error) => log.push(format!(
            "could not remove the local invitation {}: {error}; delete it by hand",
            invite.display()
        )),
    }
    log.push(format!(
        "{machine} enrolled; recovery service and TLS runtime verified"
    ));
    log.push(if peer_verified { "compatible BEAM connection to the owner verified".into() }
        else { "owner runtime is stopped; peer connectivity remains pending until it starts. Verify fleet status, or run fleet ready --peer OWNER_NODE on the destination".into() });
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
/// anywhere. The sign-in URL reaches `sink` as [`AddEvent::AuthUrl`] and nothing else.
fn setup_tailscale(
    remote: &dyn Remote,
    target: &str,
    budget: PollBudget,
    log: &mut Vec<String>,
    sink: &mut dyn EventSink,
    cancel: &Cancel,
) -> Result<()> {
    check_cancel(cancel)?;
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
        sink.emit(AddEvent::Line(format!(
            "{target}: installing Tailscale with the vendor's own installer, as root:"
        )));
        sink.emit(AddEvent::Line(format!("  {TAILSCALE_INSTALL}")));
        check_cancel(cancel)?;
        remote.run(target, TAILSCALE_INSTALL)?;
        check_cancel(cancel)?;
        let after = key_values(&remote.run(target, TAILSCALE_CAPABILITY_SCRIPT)?);
        if value_of(&after, "tailscale") != Some("present") {
            bail!(
                "the Tailscale installer ran on {target}, but `tailscale` is still not on its PATH. Install it by hand there and run this add again; no invitation was created"
            );
        }
        log.push(format!("installed Tailscale on {target}"));
    }

    sink.emit(AddEvent::Line(format!(
        "{target}: running as root: sudo tailscale up"
    )));
    check_cancel(cancel)?;
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
            let url = wait_for_auth_url(remote, target, &log_path, budget, cancel)?;
            // The URL is a live sign-in link. It reaches the operator through the event
            // stream and nowhere else: not the add log, not the invitation, not the howto
            // file. `NotifyEvents` renders it as the same three lines the CLI printed.
            sink.emit(AddEvent::AuthUrl(url));
            sink.emit(AddEvent::Line(format!(
                "Waiting up to {} for {target} to receive a tailnet address...",
                human_duration(budget.ip_window())
            )));
            log.push(format!(
                "printed the Tailscale sign-in URL for {target} to this terminal"
            ));
            let waited = wait_for_tailnet_address(remote, target, budget, sink, cancel);
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
    cancel: &Cancel,
) -> Result<String> {
    for _ in 0..budget.url_attempts.max(1) {
        check_cancel(cancel)?;
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

fn wait_for_tailnet_address(
    remote: &dyn Remote,
    target: &str,
    budget: PollBudget,
    sink: &mut dyn EventSink,
    cancel: &Cancel,
) -> Result<()> {
    for round in 0..budget.ip_attempts.max(1) {
        check_cancel(cancel)?;
        std::thread::sleep(budget.interval);
        // Elapsed is the schedule this loop actually slept, not a wall clock: it is what
        // the budget promised, and it keeps the event stream reproducible in tests.
        sink.emit(AddEvent::WaitingForAddress {
            elapsed_s: (budget.interval * (round + 1)).as_secs(),
            budget_s: budget.ip_window().as_secs(),
        });
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

fn enroll_remote(
    remote: &dyn Remote,
    target: &str,
    ouro: &str,
    invite: &str,
    peer: Option<&str>,
) -> Result<()> {
    // The invitation travels as a `.ouro` file. Refusing anything else keeps membership
    // material from ever being passed as inline text on a remote command line.
    if !invite.ends_with(".ouro") {
        bail!("refusing to enroll with a path that is not an .ouro invitation file");
    }
    require_safe_unix_path(ouro, "ouro executable")?;
    require_safe_unix_path(invite, "invitation")?;
    let peer_arg = match peer {
        Some(node)
            if node
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"@._-".contains(&byte)) =>
        {
            format!(" --peer '{node}'")
        }
        Some(_) => bail!("invalid owner node identity"),
        None => String::new(),
    };
    let script = format!(
        "chmod 600 '{invite}' && '{ouro}' fleet enroll '{invite}' --delete --activate{peer_arg}"
    );
    let output = remote.run(target, &script)?;
    if !output.lines().any(|line| line == "OURO_FLEET_READY") {
        bail!("destination did not acknowledge managed fleet readiness; inspect its fleet doctor and service status, then retry fleet service start");
    }
    Ok(())
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
                "{machine} is enrolled at {host} with managed recovery. Connection verification is reported above; inspect `ouro fleet status`.\nProvider sign-in stays on that machine; start a session there after it is connected.\n",
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
        /// Refuse the remote enroll, the one failure that happens after the invitation is
        /// already on the destination.
        fail_enroll: bool,
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
            if self.fail_enroll && script.contains("fleet enroll") {
                bail!("remote enroll refused");
            }
            if script.contains("fleet protocol") {
                return Ok("2\n".into());
            }
            if script.contains("fleet enroll") {
                return Ok("OURO_FLEET_READY\n".into());
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
        fs::write(&artifact, b"\x7fELF signed test artifact").unwrap();
        let bytes = fs::read(&artifact).unwrap();
        let digest =
            crate::update::hex(ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref());
        let sums = format!(
            "{digest}  {}\n",
            artifact.file_name().unwrap().to_str().unwrap()
        );
        let key = crate::update::tests::TestKey::new(42);
        fs::write(root.join("SHA256SUMS"), &sums).unwrap();
        fs::write(
            root.join("SHA256SUMS.minisig"),
            key.sign(sums.as_bytes(), true, "fleet test"),
        )
        .unwrap();
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
            if script.contains("fleet protocol") {
                return Ok("2\n".into());
            }
            if script.contains("fleet enroll") {
                return Ok("OURO_FLEET_READY\n".into());
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(true, false)]),
            ..ScriptedRemote::default()
        };
        // Keep the remote architecture foreign to the test host and the roots empty:
        // neither the CI platform nor a local `make dist-linux` should decide this result.
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
        let mut remote = FakeRemote::linux("/home/op");
        remote.fail_enroll = true;
        remote
            .probe
            .push_str("ouro=/home/op/.local/bin/ouro\nversion=ouro 0.1.0\n");
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
        assert!(error.contains("the invitation remains at"), "{error}");
        assert!(error.contains("vps.ouro"), "{error}");
    }

    #[test]
    fn enroll_remote_only_accepts_ouro_invitation_files() {
        let remote = FakeRemote::linux("/home/op");
        let error = enroll_remote(&remote, "op@vps", "/usr/bin/ouro", "/tmp/invite.json", None)
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
        let outcome = apply_intent_with_ports(&data, fleet::ephemeral_ports()).unwrap();
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
        let outcome = apply_intent_with_ports(&data, fleet::ephemeral_ports()).unwrap();
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
                release_key: Some(
                    crate::update::PublicKey::parse(
                        &crate::update::tests::TestKey::new(42).public_key_file(),
                    )
                    .unwrap(),
                ),
                dist_roots: Some(vec![root.clone()]),
                ..AddOptions::default()
            },
            &mut SilentNotify,
        )
        .unwrap();

        assert_eq!(outcome.kind, OutcomeKind::Enrolled);
        assert!(remote.ran("--delete --activate"));
        let copies = remote.copies.lock().unwrap();
        assert_eq!(copies.len(), 2, "the invitation and the binary: {copies:?}");
        assert!(copies[0].1.ends_with("vps.ouro"));
        assert_ne!(copies[1].0, artifact, "copy a verified private snapshot");
        assert!(!copies[1].0.exists(), "snapshot cleaned after transfer");
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

    #[test]
    fn unsigned_corrupt_and_wrong_key_artifacts_fail_before_credentials_exist() {
        for failure in ["unsigned", "corrupt", "wrong-key", "unprovisioned"] {
            let data = scratch(failure);
            fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
            let root = dist_fixture(failure, local_version(), &foreign_triple());
            let key =
                crate::update::tests::TestKey::new(if failure == "wrong-key" { 43 } else { 42 });
            if failure == "unsigned" {
                fs::remove_file(root.join("SHA256SUMS.minisig")).unwrap();
            }
            if failure == "corrupt" {
                fs::write(
                    root.join(dist_artifact_name(local_version(), &foreign_triple())),
                    b"replacement",
                )
                .unwrap();
            }
            let remote = ScriptedRemote {
                probes: queue(&[&probe_text(true, false)]),
                ..Default::default()
            };
            let result = add_with_options(
                &data,
                "op@vps",
                Some("vps"),
                Some("100.64.0.8"),
                Via::Ssh,
                None,
                None,
                &remote,
                &AddOptions {
                    dist_roots: Some(vec![root.clone()]),
                    release_key: if failure == "unprovisioned" {
                        None
                    } else {
                        Some(crate::update::PublicKey::parse(&key.public_key_file()).unwrap())
                    },
                    ..Default::default()
                },
                &mut SilentNotify,
            );
            assert!(result.is_err(), "{failure}");
            assert!(
                remote.copies.lock().unwrap().is_empty(),
                "{failure} leaked an invitation"
            );
            assert_eq!(fleet::load(&data).unwrap().unwrap().members.len(), 1);
            fs::remove_dir_all(data).unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn existing_remote_version_must_match_before_issuing_an_invitation() {
        let data = scratch("remote-version");
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(true, true).replace("ouro 0.1.0", "ouro 0.0.1")]),
            ..Default::default()
        };
        let error = add_with(
            &data,
            "op@vps",
            Some("vps"),
            Some("100.64.0.8"),
            Via::Ssh,
            None,
            None,
            &remote,
        )
        .unwrap_err();
        assert!(error.to_string().contains("requires ouro"), "{error:#}");
        assert!(remote.copies.lock().unwrap().is_empty());
        assert_eq!(fleet::load(&data).unwrap().unwrap().members.len(), 1);
        fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn matching_version_with_an_old_management_protocol_does_not_receive_credentials() {
        let data = scratch("old-protocol");
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
        let inner = ScriptedRemote {
            probes: queue(&[&probe_text(true, true)]),
            ..Default::default()
        };
        struct OldProtocol<'a>(&'a ScriptedRemote);
        impl Remote for OldProtocol<'_> {
            fn run(&self, target: &str, script: &str) -> Result<String> {
                if script.contains("fleet protocol") {
                    Ok("1\n".into())
                } else {
                    self.0.run(target, script)
                }
            }
            fn copy_to(&self, local: &Path, target: &str, path: &str) -> Result<()> {
                self.0.copy_to(local, target, path)
            }
        }
        assert!(add_with(
            &data,
            "op@vps",
            Some("vps"),
            Some("100.64.0.8"),
            Via::Ssh,
            None,
            None,
            &OldProtocol(&inner)
        )
        .is_err());
        assert!(inner.copies.lock().unwrap().is_empty());
        assert_eq!(fleet::load(&data).unwrap().unwrap().members.len(), 1);
        fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn replacing_the_source_after_verification_cannot_change_the_transfer() {
        let root = dist_fixture("artifact-snapshot", local_version(), &foreign_triple());
        let source_path = root.join(dist_artifact_name(local_version(), &foreign_triple()));
        let original = fs::read(&source_path).unwrap();
        let key = crate::update::PublicKey::parse(
            &crate::update::tests::TestKey::new(42).public_key_file(),
        )
        .unwrap();
        let verified = crate::update::fleet_artifact(
            &crate::update::Source::Directory(root.clone()),
            local_version(),
            &foreign_triple(),
            Some(&key),
        )
        .unwrap();
        fs::write(source_path, b"substituted executable").unwrap();
        assert_eq!(fs::read(&verified.path).unwrap(), original);
        assert_eq!(
            fs::metadata(verified.path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let temporary = verified.path.clone();
        drop(verified);
        assert!(!temporary.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_ssh_exit_without_managed_readiness_is_not_enrollment_success() {
        let remote = FakeRemote::linux("/home/op");
        // This remote only returns a readiness marker for enrollment commands. Wrap it
        // to model an old binary that exits successfully without proving readiness.
        struct OldRemote;
        impl Remote for OldRemote {
            fn run(&self, _: &str, _: &str) -> Result<String> {
                Ok(String::new())
            }
            fn copy_to(&self, _: &Path, _: &str, _: &str) -> Result<()> {
                unreachable!()
            }
        }
        assert!(
            enroll_remote(&OldRemote, "op@vps", "/usr/bin/ouro", "/tmp/vps.ouro", None).is_err()
        );
        assert!(enroll_remote(
            &remote,
            "op@vps",
            "/usr/bin/ouro",
            "/tmp/vps.ouro",
            Some("ouro-core@127.0.0.1")
        )
        .is_ok());
        assert!(remote
            .runs
            .lock()
            .unwrap()
            .iter()
            .any(|script| script.contains("--peer 'ouro-core@127.0.0.1'")));
    }

    // -------------------------------------------------------------------------------
    // Guided Tailscale enrollment
    // -------------------------------------------------------------------------------

    #[test]
    fn an_add_without_setup_tailscale_names_the_flag_when_no_address_is_provable() {
        let data = scratch("no-address");
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
                release_key: None,
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
                release_key: None,
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
                release_key: None,
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
                release_key: None,
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
                release_key: None,
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
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
                release_key: None,
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

    // -------------------------------------------------------------------------------
    // The event stream: what every client surface renders
    // -------------------------------------------------------------------------------

    #[derive(Default)]
    struct Events(Vec<AddEvent>);

    impl EventSink for Events {
        fn emit(&mut self, event: AddEvent) {
            self.0.push(event);
        }
    }

    /// A remote that trips the cancel flag once a named copy has gone through, so a test
    /// can cancel at an exact point between two stages rather than by racing a thread.
    struct CancelAfterCopy<'remote> {
        inner: &'remote ScriptedRemote,
        cancel: Cancel,
        suffix: &'remote str,
    }

    impl Remote for CancelAfterCopy<'_> {
        fn run(&self, target: &str, script: &str) -> Result<String> {
            self.inner.run(target, script)
        }

        fn copy_to(&self, local: &Path, target: &str, remote_path: &str) -> Result<()> {
            let result = self.inner.copy_to(local, target, remote_path);
            if remote_path.ends_with(self.suffix) {
                self.cancel.cancel();
            }
            result
        }
    }

    fn add_params(
        data: &Path,
        machine: Option<&str>,
        host: Option<&str>,
        options: AddOptions,
    ) -> AddParams {
        AddParams {
            data_dir: data.to_path_buf(),
            target: "op@vps".to_string(),
            machine: machine.map(str::to_string),
            host: host.map(str::to_string),
            via: Via::Ssh,
            binary: None,
            owner_host: Some("studio.tailnet.ts.net".to_string()),
            options,
        }
    }

    /// Exactly one terminal event ends every run, and it is last.
    fn split_terminal(mut events: Vec<AddEvent>) -> (Vec<AddEvent>, AddEvent) {
        let terminal = events.pop().expect("a run delivers a terminal event");
        assert!(
            matches!(terminal, AddEvent::Done(_) | AddEvent::Failed { .. }),
            "the last event must be terminal: {terminal:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, AddEvent::Done(_) | AddEvent::Failed { .. })),
            "only the last event may be terminal: {events:?}"
        );
        (events, terminal)
    }

    #[test]
    fn a_guided_tailscale_add_emits_the_whole_typed_sequence() {
        let data = scratch("events-guided");
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
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
        let params = add_params(
            &data,
            None,
            None,
            AddOptions {
                release_key: None,
                setup_tailscale: true,
                dist_roots: Some(Vec::new()),
                tailscale_poll: instant_budget(3, 3),
            },
        );
        let mut events = Events::default();
        let outcome = add_with_events(&params, &remote, &Cancel::default(), &mut events).unwrap();
        let (stream, terminal) = split_terminal(events.0);

        assert_eq!(
            stream,
            vec![
                AddEvent::Probed {
                    triple: foreign_triple(),
                    home: "/home/op".into(),
                    tailscale: None,
                    hostname: Some("vps".into()),
                    has_ouro: false,
                },
                AddEvent::Network(NetworkPlan::GuidedSetup),
                AddEvent::Line(
                    "op@vps: installing Tailscale with the vendor's own installer, as root:".into()
                ),
                AddEvent::Line(format!("  {TAILSCALE_INSTALL}")),
                AddEvent::Line("op@vps: running as root: sudo tailscale up".into()),
                AddEvent::AuthUrl("https://login.tailscale.com/a/deadbeef".into()),
                AddEvent::Line(
                    "Waiting up to 0s for op@vps to receive a tailnet address...".into()
                ),
                AddEvent::WaitingForAddress {
                    elapsed_s: 0,
                    budget_s: 0,
                },
                AddEvent::WaitingForAddress {
                    elapsed_s: 0,
                    budget_s: 0,
                },
                // The re-probe is a second, honest `Probed`: the address is what changed.
                AddEvent::Probed {
                    triple: foreign_triple(),
                    home: "/home/op".into(),
                    tailscale: Some("100.64.0.8".into()),
                    hostname: Some("vps".into()),
                    has_ouro: true,
                },
                AddEvent::Copying { what: "invitation" },
                AddEvent::Install(InstallDecision::RemoteExisting(
                    "/home/op/.local/bin/ouro".into()
                )),
                AddEvent::Enrolling,
            ]
        );
        assert_eq!(terminal, AddEvent::Done(outcome.clone()));
        assert_eq!(outcome.kind, OutcomeKind::Enrolled);
        assert_eq!(outcome.host, "100.64.0.8");

        // The seam keeps the guarantee the notify path had: the live link is an event and
        // never a log line, an outcome field, or a file.
        assert!(!outcome.log.join("\n").contains("login.tailscale.com"));
        assert!(!all_file_text(&data).contains("login.tailscale.com"));
    }

    #[test]
    fn a_cross_triple_dist_artifact_add_names_the_resolved_path_in_its_install_event() {
        let data = scratch("events-dist");
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
        let root = dist_fixture("events-dist-root", local_version(), &foreign_triple());
        let artifact = root.join(dist_artifact_name(local_version(), &foreign_triple()));
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(true, false)]),
            ..ScriptedRemote::default()
        };
        let params = add_params(
            &data,
            Some("vps"),
            Some("100.64.0.8"),
            AddOptions {
                release_key: Some(
                    crate::update::PublicKey::parse(
                        &crate::update::tests::TestKey::new(42).public_key_file(),
                    )
                    .unwrap(),
                ),
                dist_roots: Some(vec![root.clone()]),
                ..AddOptions::default()
            },
        );
        let mut events = Events::default();
        let outcome = add_with_events(&params, &remote, &Cancel::default(), &mut events).unwrap();
        let (stream, terminal) = split_terminal(events.0);

        assert_eq!(
            stream,
            vec![
                AddEvent::Probed {
                    triple: foreign_triple(),
                    home: "/home/op".into(),
                    tailscale: Some("100.64.0.8".into()),
                    hostname: Some("vps".into()),
                    has_ouro: false,
                },
                AddEvent::Network(NetworkPlan::HostProvided("100.64.0.8".into())),
                AddEvent::Copying { what: "invitation" },
                AddEvent::Install(InstallDecision::DistArtifact(artifact)),
                AddEvent::Copying { what: "binary" },
                AddEvent::Enrolling,
            ]
        );
        assert_eq!(terminal, AddEvent::Done(outcome.clone()));
        assert_eq!(outcome.kind, OutcomeKind::Enrolled);
    }

    /// A refused enroll is the failure that leaves the most behind: an invitation here, a
    /// copy of it there, and a join that may or may not have completed.
    #[test]
    fn a_failure_after_the_invitation_copy_carries_its_residue() {
        let data = scratch("events-residue");
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
        let remote = ScriptedRemote {
            probes: queue(&[&probe_text(true, true)]),
            fail_enroll: true,
            ..ScriptedRemote::default()
        };
        let params = add_params(
            &data,
            Some("vps"),
            Some("100.64.0.8"),
            AddOptions {
                dist_roots: Some(Vec::new()),
                ..AddOptions::default()
            },
        );
        let mut events = Events::default();
        let error = add_with_events(&params, &remote, &Cancel::default(), &mut events).unwrap_err();
        let (stream, terminal) = split_terminal(events.0);
        let invite = fleet::pending_invite_path(&data, "vps").unwrap();

        assert_eq!(
            stream,
            vec![
                AddEvent::Probed {
                    triple: foreign_triple(),
                    home: "/home/op".into(),
                    tailscale: Some("100.64.0.8".into()),
                    hostname: Some("vps".into()),
                    has_ouro: true,
                },
                AddEvent::Network(NetworkPlan::HostProvided("100.64.0.8".into())),
                AddEvent::Copying { what: "invitation" },
                AddEvent::Install(InstallDecision::RemoteExisting(
                    "/home/op/.local/bin/ouro".into()
                )),
                AddEvent::Enrolling,
            ]
        );
        assert_eq!(
            terminal,
            AddEvent::Failed {
                error: format!("{error:#}"),
                residue: vec![
                    format!("the invitation remains at {} (mode 0600)", invite.display()),
                    "if it may already have been copied, treat it as issued — otherwise delete it with rm before adding again".into(),
                    "a copy of it is on the destination at /home/op/.local/share/ouroboros/incoming/vps.ouro".into(),
                    "`ouro fleet enroll` had already started on the destination: if its join completed before this, vps may be joined and running; inspect its fleet doctor and service status".into(),
                    "`ouro daemon` on vps starts it, and rerunning this same add converges it once the invitation above is removed".into(),
                ],
            }
        );
        // The CLI's error text is unchanged by the restructuring: the first two residue
        // facts are still one line on the error chain.
        assert!(
            error.to_string().contains("the invitation remains at")
                && error.to_string().contains("treat it as issued"),
            "{error:#}"
        );
        assert!(
            invite.exists(),
            "the invitation the residue names must be there"
        );
    }

    /// A cancel never half-reports: the run stops at the next boundary and says exactly
    /// what it had already done, no more.
    #[test]
    fn a_cancel_between_stages_fails_with_only_the_residue_that_is_true() {
        let data = scratch("events-cancel");
        fleet::create(&data, None, "studio", "localhost", fleet::ephemeral_ports()).unwrap();
        let scripted = ScriptedRemote {
            probes: queue(&[&probe_text(true, true)]),
            ..ScriptedRemote::default()
        };
        let cancel = Cancel::new();
        let remote = CancelAfterCopy {
            inner: &scripted,
            cancel: cancel.clone(),
            suffix: "vps.ouro",
        };
        let params = add_params(
            &data,
            Some("vps"),
            Some("100.64.0.8"),
            AddOptions {
                dist_roots: Some(Vec::new()),
                ..AddOptions::default()
            },
        );
        let mut events = Events::default();
        let error = add_with_events(&params, &remote, &cancel, &mut events).unwrap_err();
        let (stream, terminal) = split_terminal(events.0);
        let invite = fleet::pending_invite_path(&data, "vps").unwrap();

        assert_eq!(
            stream,
            vec![
                AddEvent::Probed {
                    triple: foreign_triple(),
                    home: "/home/op".into(),
                    tailscale: Some("100.64.0.8".into()),
                    hostname: Some("vps".into()),
                    has_ouro: true,
                },
                AddEvent::Network(NetworkPlan::HostProvided("100.64.0.8".into())),
                AddEvent::Copying { what: "invitation" },
                AddEvent::Install(InstallDecision::RemoteExisting(
                    "/home/op/.local/bin/ouro".into()
                )),
            ]
        );
        assert_eq!(
            terminal,
            AddEvent::Failed {
                error: "cancelled by the operator".into(),
                residue: vec![
                    format!("the invitation remains at {} (mode 0600)", invite.display()),
                    "if it may already have been copied, treat it as issued — otherwise delete it with rm before adding again".into(),
                    "a copy of it is on the destination at /home/op/.local/share/ouroboros/incoming/vps.ouro".into(),
                ],
            }
        );
        assert_eq!(format!("{error:#}"), "cancelled by the operator");
        assert!(
            !scripted.ran("fleet enroll"),
            "a cancel before the enroll boundary must not enroll: {:?}",
            scripted.runs.lock().unwrap()
        );
        assert!(invite.exists());
    }

    /// The bridge the CLI and the pre-event callers share: typed events become exactly the
    /// lines `ouro fleet add` has always printed, and nothing else reaches the terminal.
    #[test]
    fn notify_events_renders_the_sign_in_link_and_drops_what_the_log_already_says() {
        let mut lines = Lines::default();
        let mut sink = NotifyEvents::new(&mut lines);
        sink.emit(AddEvent::Line(
            "op@vps: running as root: sudo tailscale up".into(),
        ));
        sink.emit(AddEvent::AuthUrl(
            "https://login.tailscale.com/a/deadbeef".into(),
        ));
        sink.emit(AddEvent::Probed {
            triple: "x86_64-unknown-linux-gnu".into(),
            home: "/home/op".into(),
            tailscale: None,
            hostname: None,
            has_ouro: false,
        });
        sink.emit(AddEvent::Copying { what: "binary" });
        sink.emit(AddEvent::Enrolling);

        assert_eq!(
            lines.0,
            vec![
                "op@vps: running as root: sudo tailscale up".to_string(),
                String::new(),
                "Open this link and approve the machine (a one-time Tailscale sign-in):"
                    .to_string(),
                "  https://login.tailscale.com/a/deadbeef".to_string(),
            ]
        );
    }
}
