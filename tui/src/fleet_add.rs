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
//! mismatched OS/CPU is a named limit, not a silent copy of the wrong ERTS.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    pub add: AddPlan,
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

const INTENT_SCHEMA: u8 = 1;
const PROBE_SCRIPT: &str = r#"set -e
printf 'os=%s\n' "$(uname -s)"
printf 'arch=%s\n' "$(uname -m)"
printf 'home=%s\n' "$HOME"
printf 'hostname=%s\n' "$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)"
if command -v ouro >/dev/null 2>&1; then
  printf 'ouro=%s\n' "$(command -v ouro)"
  ouro version 2>/dev/null | awk '{print "version_" $0}'
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
            key if key.starts_with("version_") && probe.ouro_version.is_none() => {
                let line = raw.trim().trim_start_matches("version_").trim();
                if line.starts_with("ouro ") || line.starts_with("release") {
                    probe.ouro_version = Some(line.to_string());
                }
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
    fleet::validate_machine(&intent.add.machine)?;
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
    let outcome = match intent.add.kind {
        AddKind::Prepare => prepare(
            data_dir,
            &intent.add.machine,
            &intent.add.host,
            Some(&intent.owner_host),
        )?,
        AddKind::Ssh => {
            let target = intent
                .add
                .target
                .ok_or_else(|| anyhow!("the saved add-machine intent is missing the SSH target"))?;
            let via = Via::parse(&intent.add.via)?;
            let binary = intent.add.binary.as_deref().map(Path::new);
            add_with(
                data_dir,
                &target,
                Some(&intent.add.machine),
                Some(&intent.add.host),
                via,
                binary,
                Some(&intent.owner_host),
                &SshRemote { via },
            )?
        }
    };
    let _ = take_intent(data_dir)?;
    Ok(outcome)
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
    let mut log = Vec::new();
    log.push(format!("probing {target} over {}", via.as_str()));
    let probe_text = remote.run(target, PROBE_SCRIPT)?;
    let probe = parse_probe(&probe_text)?;
    require_safe_unix_path(&probe.home, "home")?;
    let remote_triple = probe.triple()?;
    let local = local_triple()?;
    log.push(format!("remote is {remote_triple} (home {})", probe.home));

    let host = host
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| probe.suggested_host())
        .ok_or_else(|| {
            anyhow!(
                "could not prove a private address for {target}; pass --host with a Tailscale MagicDNS name or private IPv4 address"
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

    let install = install_plan(&local, &remote_triple, binary, probe.ouro.as_deref())?;
    match &install {
        InstallPlan::UseExisting(path) => {
            log.push(format!("remote already has {path}"));
            enroll_remote(remote, target, path, &remote_invite)
                .map_err(|error| pending_invite_error(error, &invite))?;
            finish_enroll(&mut log, &invite, &machine, &host, OutcomeKind::Enrolled)
        }
        InstallPlan::Copy(path) => {
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

enum InstallPlan {
    UseExisting(String),
    Copy(PathBuf),
    RecipeOnly { reason: String },
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
) -> Result<InstallPlan> {
    if let Some(path) = binary {
        if !path.is_file() {
            bail!("--binary {} is not a file", path.display());
        }
        return Ok(InstallPlan::Copy(path.to_path_buf()));
    }
    if let Some(path) = remote_ouro {
        return Ok(InstallPlan::UseExisting(path.to_string()));
    }
    if local_triple == remote_triple {
        let exe = std::env::current_exe()
            .context("locating this ouro executable")?
            .canonicalize()
            .context("resolving this ouro executable")?;
        return Ok(InstallPlan::Copy(exe));
    }
    Ok(InstallPlan::RecipeOnly {
        reason: format!(
            "this Mac is {local_triple}; the destination is {remote_triple}. Ouroboros cannot copy this binary there. Install the matching ouro on that machine, then run the printed enroll command. The invitation is already on the destination."
        ),
    })
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
    use std::sync::Mutex;

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
        let outcome = add_with(
            &data,
            "op@vps",
            Some("vps"),
            Some("localhost"),
            Via::Ssh,
            None,
            Some("studio.tailnet.ts.net"),
            &remote,
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
            add: AddPlan {
                kind: AddKind::Prepare,
                machine: "laptop".into(),
                host: "localhost".into(),
                target: None,
                via: "ssh".into(),
                binary: None,
            },
        };
        write_intent(&data, &intent).unwrap();
        let path = fleet::add_intent_path(&data);
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o777, 0o600);
        // A stale plan from a failed restart must never wedge the next confirm.
        let mut retry = intent.clone();
        retry.add.machine = "vps".into();
        write_intent(&data, &retry).unwrap();
        assert_eq!(load_intent(&data).unwrap().unwrap().add.machine, "vps");
        let outcome = apply_intent(&data).unwrap();
        assert_eq!(outcome.machine, "vps");
        assert!(fleet::load(&data).unwrap().is_some());
        assert!(!path.exists(), "the intent is consumed");
        assert!(fleet::pending_invite_path(&data, "vps").unwrap().is_file());
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
}
