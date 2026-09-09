//! This machine's cluster identity, and the EPMD it owns while its runtime runs.
//!
//! `create` mints the identity — node name, private cookie, a self-signed CA and node
//! certificate for TLS distribution, a private EPMD port — and `runtime_env` turns it
//! into the environment the packaged release boots with. The profile deliberately
//! contains only non-secret facts: the BEAM cookie, the node key and the CA key live in
//! separate mode-0600 files and are passed to the release by path.
//!
//! Nothing here enrolls another machine. Two machines join a cluster because an operator
//! gave them the same cookie and named each other, which is `docs/FLEET.md`.

use std::collections::BTreeSet;
use std::ffi::CStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rand::{rngs::OsRng, TryRngCore};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_parser::{extensions::GeneralName, pem::parse_x509_pem};
use zeroize::{Zeroize, Zeroizing};

use crate::runtime;

pub const FLEET_DIR: &str = "fleet";
pub const PROFILE_FILE: &str = "profile.json";
pub const COOKIE_FILE: &str = "cookie";
pub const CA_CERT_FILE: &str = "ca-cert.pem";
pub const CA_KEY_FILE: &str = "ca-key.pem";
pub const NODE_CERT_FILE: &str = "node-cert.pem";
pub const NODE_KEY_FILE: &str = "node-key.pem";
pub const TLS_OPTFILE: &str = "ssl_dist.conf";
pub const VM_ARGS_FILE: &str = "vm.args";
pub const EPMD_OWNER_FILE: &str = "epmd-owner.json";
pub const EPMD_OWNER_LOCK_FILE: &str = "epmd-owner.lock";
pub const CLUSTER_DIRECTORY_DIR: &str = "cluster-directory";
const CLUSTER_CHECKPOINTS_DIR: &str = "checkpoints";
const CLUSTER_CHECKPOINT_FILE: &str = "JMVhBnhGdi3kKCz92XK5UwsBskr_HhSrc81LxYXn7a4.term";
const MAX_CLUSTER_CHECKPOINT_TEMPS: usize = 4;

// Every default pinned port lives below 32768, the floor of Linux's default ephemeral
// range (32768-60999; macOS uses 49152-65535). The first defaults did not — gateway
// 47000-47999 and distribution 43700-43729 — and a real enrollment died on it: the
// kernel numbered a fleet-owned loopback client socket with the machine's own pinned
// gateway port during boot, the gateway's bind failed `eaddrinuse`, and moments later
// `ss -tlnp` showed nothing because the holder was never a listener. Existing profiles
// keep their recorded numbers; `fleet doctor` warns when they overlap the live range.
pub const DEFAULT_DIST_PORT_MIN: u16 = 13_700;
pub const DEFAULT_DIST_PORT_MAX: u16 = 13_729;
pub const DEFAULT_GATEWAY_BASE: u16 = 17_000;
pub const DEFAULT_GATEWAY_SPAN: u16 = 1_000;
pub const DEFAULT_EPMD_BASE: u16 = 14_000;
pub const DEFAULT_EPMD_SPAN: u16 = 1_000;
const PROFILE_SCHEMA: u8 = 1;
const MAX_CA_VALIDITY_DAYS: i64 = 12 * 366;
const MAX_NODE_VALIDITY_DAYS: i64 = 7 * 366;
const STAGING_PREFIX: &str = ".fleet.setup.";
const EPMD_OWNER_SCHEMA: u8 = 1;
const EPMD_START_DEADLINE: Duration = Duration::from_secs(5);
const EPMD_STOP_DEADLINE: Duration = Duration::from_secs(5);
const EPMD_WATCH_INTERVAL: Duration = Duration::from_millis(250);
const EPMD_WATCH_FAILURES: u8 = 4;

const fn initial_roster_revision() -> u64 {
    1
}

const fn legacy_epmd_port() -> u16 {
    4369
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Member {
    pub machine: String,
    pub host: String,
    pub node: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct EpmdOwner {
    schema: u8,
    fleet_id: String,
    host: String,
    address: Ipv4Addr,
    port: u16,
    pid: i32,
    executable: PathBuf,
    executable_dev: u64,
    executable_ino: u64,
    lock_dev: u64,
    lock_ino: u64,
}

/// Runtime-scoped health watch for the EPMD listener selected during startup.
///
/// A child is present only when this exact launcher spawned the foreground daemon. A
/// compatible incumbent remains unowned and is observed but never signalled. Sustained
/// listener loss is reported to the Daemon that still owns the exact BEAM child handle;
/// that owner performs the safe stop which lets Restart=always/KeepAlive recover.
pub(crate) struct EpmdRuntimeWatch {
    child: Option<Child>,
    address: Ipv4Addr,
    port: u16,
    failed_probes: u8,
    last_probe: Option<Instant>,
}

impl EpmdRuntimeWatch {
    pub(crate) fn new(child: Option<Child>, address: Ipv4Addr, port: u16) -> Self {
        Self {
            child,
            address,
            port,
            failed_probes: 0,
            last_probe: None,
        }
    }

    pub(crate) fn child_lost(&mut self) -> Option<String> {
        let address = self.address;
        let port = self.port;
        let epmd = self.child.as_mut()?;
        match epmd.try_wait() {
            Ok(Some(status)) => Some(format!("owned EPMD {address}:{port} exited with {status}")),
            Ok(None) => None,
            Err(error) => Some(format!(
                "owned EPMD {address}:{port} health could not be read: {error}"
            )),
        }
    }

    /// One boot-time health step, called from the starter's readiness loop before the
    /// detached monitor exists. It observes and reports; it never kills, because the
    /// failure path that receives the report owns the cleanup and must find the exact
    /// child still attributable. NAMES probes run on the blocking pool so the readiness
    /// loop does not stall the async runtime on a connect timeout.
    pub(crate) async fn health(&mut self) -> Option<String> {
        if let Some(reason) = self.child_lost() {
            return Some(reason);
        }

        // The readiness loop polls faster than the monitor; keep the NAMES cadence so a
        // boot does not multiply loopback connections beyond what supervision would make.
        if let Some(last) = self.last_probe {
            if last.elapsed() < EPMD_WATCH_INTERVAL {
                return None;
            }
        }
        self.last_probe = Some(Instant::now());

        let address = self.address;
        let port = self.port;
        let ok = tokio::task::spawn_blocking(move || names_healthy(address, port))
            .await
            .ok()?;
        if ok {
            self.failed_probes = 0;
            return None;
        }
        self.failed_probes = self.failed_probes.saturating_add(1);
        if self.failed_probes >= EPMD_WATCH_FAILURES {
            return Some(format!(
                "EPMD {address}:{port} failed {EPMD_WATCH_FAILURES} consecutive NAMES probes"
            ));
        }
        None
    }

    /// Removes exactly what this spawn created: the foreground EPMD child plus the
    /// ownership marker and lock written for it. A reused compatible incumbent has no
    /// child here and is deliberately left running and unowned — `Ok(false)` says so.
    pub(crate) fn reap_spawned(mut self, data_dir: &Path) -> Result<bool> {
        let Some(mut child) = self.child.take() else {
            return Ok(false);
        };
        if child.try_wait()?.is_none() {
            child
                .kill()
                .context("stopping the packaged EPMD this start launched")?;
        }
        let _ = child.wait();

        // The child held the inherited flock across exec; reaping it released the lock,
        // so the marker-and-lock pair can be removed through the same guarded path a
        // stale-artifact cleanup uses. The release is not atomic with the reap under
        // load, hence the short bounded wait.
        let deadline = Instant::now() + EPMD_STOP_DEADLINE;
        loop {
            match remove_epmd_owner_artifacts(data_dir) {
                Ok(()) => return Ok(true),
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
                Err(error) => {
                    return Err(error).context(
                        "the packaged EPMD was stopped, but its ownership artifacts could not be removed",
                    );
                }
            }
        }
    }

    /// Gives up the child handle without stopping the daemon. A deliberate detach means
    /// the EPMD keeps serving the fleet after this process exits.
    pub(crate) fn disarm(&mut self) {
        self.child = None;
    }

    /// Drop/cancellation backstop: SIGKILL the packaged child this start launched and
    /// best-effort remove its marker. An incumbent has no child here and is left running.
    pub(crate) fn abort_spawned(&mut self, data_dir: &Path) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
        let _ = remove_epmd_owner_artifacts(data_dir);
    }

    pub(crate) fn supervise(mut self) -> tokio::sync::oneshot::Receiver<String> {
        let (failure, receiver) = tokio::sync::oneshot::channel();
        let mut child = self.child.take();
        let address = self.address;
        let port = self.port;
        thread::spawn(move || {
            let mut failed_probes = 0_u8;
            loop {
                if failure.is_closed() {
                    // A newly spawned foreground EPMD is still our child. Keep one
                    // detached waiter so a later leave/exit is reaped rather than left
                    // as a zombie while a long-lived UI process remains open.
                    if let Some(child) = child.as_mut() {
                        let _ = child.wait();
                    }
                    return;
                }

                if let Some(epmd) = child.as_mut() {
                    match epmd.try_wait() {
                        Ok(Some(status)) => {
                            let _ = failure
                                .send(format!("owned EPMD {address}:{port} exited with {status}"));
                            return;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            let _ = failure.send(format!(
                                "owned EPMD {address}:{port} health could not be read: {error}"
                            ));
                            return;
                        }
                    }
                }

                if names_healthy(address, port) {
                    failed_probes = 0;
                } else {
                    failed_probes = failed_probes.saturating_add(1);
                    if failed_probes >= EPMD_WATCH_FAILURES {
                        // Only a child this launcher created is eligible for a signal.
                        // A reused compatible daemon is external and remains untouched.
                        if let Some(epmd) = child.as_mut() {
                            let _ = epmd.kill();
                            let _ = epmd.wait();
                        }
                        let _ = failure.send(format!(
                            "EPMD {address}:{port} failed {EPMD_WATCH_FAILURES} consecutive NAMES probes"
                        ));
                        return;
                    }
                }
                thread::sleep(EPMD_WATCH_INTERVAL);
            }
        });
        receiver
    }
}

impl Drop for EpmdRuntimeWatch {
    fn drop(&mut self) {
        // If BEAM spawning fails after we created EPMD, do not orphan the foreground
        // child without a health owner. The durable marker remains as an explicit stale
        // fact and the next serialized startup clears it after proving the port closed.
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Profile {
    #[serde(default = "empty_tags")]
    pub tags: Value,
    pub schema: u8,
    pub fleet_id: String,
    pub name: String,
    pub machine: String,
    pub host: String,
    pub node: String,
    pub role: String,
    pub members: Vec<Member>,
    /// Machines this operator has declared permanently gone, by
    /// `ouro fleet sessions forget --accept-state-loss`. A tombstone is the operator's
    /// explicit statement, and it is what `fleet.forget_session_owner` requires before it
    /// will release a dead machine's durable session-owner evidence: a partitioned but
    /// live owner is never robbed of its sessions by an automatic rule. Defaulted so a
    /// profile written before this field reads as "nothing declared gone".
    #[serde(default)]
    pub tombstones: Vec<Member>,
    #[serde(default = "initial_roster_revision")]
    pub roster_revision: u64,
    pub gateway_port: u16,
    #[serde(default = "legacy_epmd_port")]
    pub epmd_port: u16,
    pub dist_port_min: u16,
    pub dist_port_max: u16,
}

impl Profile {
    pub fn expected_peers(&self) -> usize {
        self.members
            .iter()
            .filter(|member| member.node != self.node)
            .count()
    }
}

/// Non-secret state suitable for Settings and status panes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    pub profile: Option<Profile>,
    pub tls: bool,
    pub problems: Vec<String>,
}

impl Summary {
    pub fn standalone(&self) -> bool {
        self.profile.is_none() && self.problems.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ports {
    pub gateway: Option<u16>,
    /// A single listener port is useful for several test nodes on one host. `None` uses
    /// the small production range, allowing the OS to select an available listener.
    pub dist: Option<u16>,
    /// `None` derives the fleet-specific EPMD port from the fleet id on create. An
    /// explicit port keeps test fleets out of that derived space, where a probe or a
    /// retirement check could meet an unrelated live daemon.
    pub epmd: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub machine: String,
    pub host: String,
    pub inferred_machine: bool,
    pub inferred_host: bool,
}

impl Ports {
    pub const DEFAULT: Self = Self {
        gateway: None,
        dist: None,
        epmd: None,
    };
}

/// Distinct free loopback ports for one test fleet. Suites must never touch the
/// production port spaces — the dist range plus the derived EPMD and gateway spaces —
/// because a live same-host lab legitimately occupies them. OS-assigned ports are
/// screened against all three so a test never collides with that lab.
#[cfg(test)]
pub(crate) fn ephemeral_ports() -> Ports {
    let mut held = Vec::new();
    let mut ports = Vec::new();
    while ports.len() < 3 {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free ephemeral loopback port");
        let port = listener
            .local_addr()
            .expect("a bound loopback address")
            .port();
        // Keeping every allocation bound until all three are chosen makes them distinct.
        held.push(listener);
        if port != legacy_epmd_port()
            && !(DEFAULT_DIST_PORT_MIN..=DEFAULT_DIST_PORT_MAX).contains(&port)
            && !(DEFAULT_EPMD_BASE..DEFAULT_EPMD_BASE + DEFAULT_EPMD_SPAN).contains(&port)
            && !(DEFAULT_GATEWAY_BASE..DEFAULT_GATEWAY_BASE + DEFAULT_GATEWAY_SPAN).contains(&port)
        {
            ports.push(port);
        }
    }
    Ports {
        gateway: Some(ports[0]),
        dist: Some(ports[1]),
        epmd: Some(ports[2]),
    }
}

struct Materials {
    ca_cert_pem: String,
    ca_key_pem: Option<String>,
    node_cert_pem: String,
    node_key_pem: String,
    cookie: String,
}

impl Drop for Materials {
    fn drop(&mut self) {
        if let Some(key) = &mut self.ca_key_pem {
            key.zeroize();
        }
        self.node_key_pem.zeroize();
        self.cookie.zeroize();
    }
}

pub fn fleet_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(FLEET_DIR)
}

pub fn profile_path(data_dir: &Path) -> PathBuf {
    fleet_dir(data_dir).join(PROFILE_FILE)
}

fn epmd_owner_path(data_dir: &Path) -> PathBuf {
    fleet_dir(data_dir).join(EPMD_OWNER_FILE)
}

fn epmd_owner_lock_path(data_dir: &Path) -> PathBuf {
    fleet_dir(data_dir).join(EPMD_OWNER_LOCK_FILE)
}

/// Resolves optional beginner inputs without inventing a network address. An inferred
/// host has to look routable and resolve locally; otherwise the error asks for the one
/// fact only the operator can know.
pub fn resolve_identity(machine: Option<&str>, host: Option<&str>) -> Result<Identity> {
    let inferred_host = host
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none();
    let host = match host.map(str::trim).filter(|value| !value.is_empty()) {
        Some(host) => host.to_string(),
        None => local_hostname()?,
    };
    validate_host(&host)?;
    if inferred_host {
        validate_inferred_host(&host)?;
    }

    let inferred_machine = machine
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none();
    let machine = match machine.map(str::trim).filter(|value| !value.is_empty()) {
        Some(machine) => machine.to_string(),
        None => machine_from_host(&host)?,
    };
    validate_machine(&machine)?;
    Ok(Identity {
        machine,
        host,
        inferred_machine,
        inferred_host,
    })
}

fn validate_inferred_host(host: &str) -> Result<()> {
    let local_only = host.eq_ignore_ascii_case("localhost")
        || host_is_local_only(host)
        || host.to_ascii_lowercase().ends_with(".local");
    let has_network_signal = host.parse::<std::net::Ipv4Addr>().is_ok() || host.contains('.');
    if local_only || !has_network_signal {
        bail!(
            "Ouroboros found local hostname `{host}`, but cannot safely assume another machine can reach it. Rerun with explicit `--host HOST`, using a Tailscale MagicDNS name, private DNS name, or private IPv4 address (example: `ouro fleet create --machine studio-mini --host studio-mini.tailnet.ts.net`). Explicit loopback remains available for same-host labs"
        );
    }
    ensure_usable_ipv4_resolution(host).with_context(|| {
        format!(
            "Ouroboros cannot safely publish inferred hostname `{host}`; rerun with an explicit reachable `--host HOST`"
        )
    })
}

pub fn load(data_dir: &Path) -> Result<Option<Profile>> {
    let path = profile_path(data_dir);
    if !path
        .try_exists()
        .with_context(|| format!("inspecting {}", path.display()))?
    {
        if fleet_dir(data_dir).try_exists().with_context(|| {
            format!(
                "inspecting incomplete fleet directory {}",
                fleet_dir(data_dir).display()
            )
        })? {
            bail!(
                "{} exists without {}. Restore profile.json from a backup to keep this machine's cluster identity, or run `ouro fleet leave` on this stopped machine to clear the recognized private files and start over with `ouro fleet create`",
                fleet_dir(data_dir).display(),
                path.display()
            );
        }
        return Ok(None);
    }

    let text = read_private(&path, "fleet profile")?;
    let profile: Profile = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a valid fleet profile", path.display()))?;
    validate_profile(&profile)?;
    Ok(Some(profile))
}

/// Tags describe this machine; they never change membership or permissions.
pub fn tags(
    data_dir: &Path,
    machine: Option<&str>,
    change: Option<(&str, bool)>,
) -> Result<Vec<String>> {
    let _lock = lock_live_fleet_update(data_dir, "ouro fleet tag")?;
    let mut profile =
        load(data_dir)?.context("this machine is standalone; create or join a fleet first")?;
    if let Some(machine) = machine {
        if machine != profile.machine && machine != profile.node {
            bail!(
                "this profile belongs to {}; run `ouro fleet tag` on machine {} to edit its tags",
                profile.machine,
                machine
            );
        }
    }
    if let Some((tag, add)) = change {
        if add {
            validate_tags(&[tag.to_string()])?;
            let mut tags = validated_tags(&profile.tags)?;
            if !tags.iter().any(|existing| existing == tag) {
                tags.push(tag.to_string());
            }
            validate_tags(&tags)?;
            profile.tags = serde_json::to_value(tags)?;
        } else {
            // Removal is also the repair path for a malformed advisory tag. Keep every
            // other profile field untouched, and validate the resulting list before writing.
            let mut tags =
                profile.tags.as_array().cloned().context(
                    "fleet tags must be a list; repair only the tags field in the profile",
                )?;
            tags.retain(|value| value.as_str() != Some(tag));
            let repaired = Value::Array(tags);
            validated_tags(&repaired)?;
            profile.tags = repaired;
        }
        write_profile(data_dir, &profile)?;
    }
    validated_tags(&profile.tags)
}

/// Record, on this machine's roster only, that another machine is permanently gone.
///
/// This is the only writer of [`Profile::tombstones`], and the tombstone is the whole
/// reason `fleet.forget_session_owner` has something to check. Nothing infers a tombstone
/// from a disconnect: an unreachable peer is a peer this machine keeps retrying, so a
/// partitioned owner is never robbed of its sessions. The operator saying
/// `--accept-state-loss` is the statement, and this is where it is written down.
///
/// The member moves out of `members` into `tombstones` and the roster revision advances,
/// so `ouro fleet status` stops expecting it. The roster is not replicated: every
/// remaining machine needs the same command run locally.
///
/// Idempotent — a machine already declared gone is returned unchanged, so a retry after a
/// failed gateway call asks the runtime again rather than refusing.
pub fn forget_machine(data_dir: &Path, machine: &str) -> Result<Member> {
    let _lock = lock_live_fleet_update(data_dir, "ouro fleet sessions forget")?;
    let mut profile = load(data_dir)?.context(
        "this machine is standalone; there is no cluster roster to declare a machine gone in",
    )?;
    if machine == profile.machine || machine == profile.node {
        bail!(
            "{machine} is this machine; `ouro fleet leave` retires this machine's own identity, and `ouro fleet sessions forget` is for a machine that is gone for good"
        );
    }
    if let Some(gone) = profile
        .tombstones
        .iter()
        .find(|entry| entry.machine == machine || entry.node == machine)
    {
        return Ok(gone.clone());
    }
    let Some(index) = profile
        .members
        .iter()
        .position(|entry| entry.machine == machine || entry.node == machine)
    else {
        bail!(
            "this machine's roster has no member named {machine}; `ouro fleet status` prints the names it knows"
        );
    };
    let removed = profile.members.remove(index);
    profile.roster_revision = profile
        .roster_revision
        .checked_add(1)
        .ok_or_else(|| anyhow!("this machine's roster revision is exhausted"))?;
    profile.tombstones.push(removed.clone());
    profile
        .tombstones
        .sort_by(|left, right| left.node.cmp(&right.node));
    write_profile(data_dir, &profile).context(
        "recording the machine as permanently gone before retiring its session evidence",
    )?;
    Ok(removed)
}

/// Undo [`forget_machine`] when the runtime refused to retire the evidence.
///
/// The refusal that matters is a machine that turned out to be connected: the roster must
/// not quietly lose a member whose sessions this cluster is still answering for.
pub fn restore_machine(data_dir: &Path, restored: &Member) -> Result<()> {
    let _lock = lock_live_fleet_update(data_dir, "ouro fleet sessions forget")?;
    let mut profile = load(data_dir)?
        .context("this machine is standalone; there is no cluster roster to restore a member to")?;
    profile
        .tombstones
        .retain(|entry| entry.node != restored.node);
    if !profile
        .members
        .iter()
        .any(|entry| entry.node == restored.node)
    {
        profile.members.push(restored.clone());
        profile
            .members
            .sort_by(|left, right| left.node.cmp(&right.node));
    }
    profile.roster_revision = profile
        .roster_revision
        .checked_add(1)
        .ok_or_else(|| anyhow!("this machine's roster revision is exhausted"))?;
    write_profile(data_dir, &profile).context("restoring the member the runtime refused to forget")
}

/// Add another machine to *this* machine's roster.
///
/// The roster is not replicated and never was: this writes `<data dir>/fleet/profile.json`
/// here and nowhere else, so an operator runs it once per remaining machine. It exists so
/// they never hand-edit that file — `validate_profile` refuses several shapes a careful
/// person still gets wrong, starting with `node` not being `ouro-<machine>@<host>`.
///
/// It takes the same live lock `ouro fleet tag` takes rather than requiring a stopped
/// runtime, because the running node re-reads the profile on its next reconnect sweep
/// (about a second later) and starts dialing the new member without a restart.
pub fn add_member(
    data_dir: &Path,
    machine: &str,
    host: &str,
    node: Option<&str>,
) -> Result<Member> {
    validate_machine(machine)?;
    validate_host(host)?;
    let added = member(machine, host);
    if let Some(node) = node {
        if node != added.node {
            bail!(
                "machine `{machine}` at `{host}` is node {}, not {node}; a node name is always `ouro-<machine>@<host>`",
                added.node
            );
        }
    }
    let _lock = lock_live_fleet_update(data_dir, "ouro fleet members add")?;
    let mut profile = load(data_dir)?.context(
        "this machine is standalone; `ouro fleet create` gives it a cluster identity before it can have a roster",
    )?;
    if let Some(gone) = profile
        .tombstones
        .iter()
        .find(|entry| entry.machine == machine || entry.node == added.node)
    {
        bail!(
            "this machine's roster records {} as gone for good; `ouro fleet sessions restore {}` puts it back before it can be added again",
            gone.node,
            gone.machine
        );
    }
    if let Some(existing) = profile
        .members
        .iter()
        .find(|entry| entry.machine == machine || entry.node == added.node)
    {
        if existing == &added {
            return Ok(added);
        }
        bail!(
            "this machine's roster already names {} as {}; `ouro fleet members remove {}` first if its address changed",
            existing.machine,
            existing.node,
            existing.machine
        );
    }
    profile.members.push(added.clone());
    profile
        .members
        .sort_by(|left, right| left.node.cmp(&right.node));
    profile.roster_revision = profile
        .roster_revision
        .checked_add(1)
        .ok_or_else(|| anyhow!("this machine's roster revision is exhausted"))?;
    write_profile(data_dir, &profile).context("adding the machine to this machine's roster")?;
    Ok(added)
}

/// Take a machine out of *this* machine's roster.
///
/// This is the counterpart of `ouro fleet leave` run on that machine: it stops this one
/// dialing it and stops `ouro fleet status` expecting it. It writes no tombstone — a
/// tombstone is the operator saying durable session-owner evidence may be released, which
/// is `ouro fleet sessions forget`.
pub fn remove_member(data_dir: &Path, machine: &str) -> Result<Member> {
    let _lock = lock_live_fleet_update(data_dir, "ouro fleet members remove")?;
    let mut profile = load(data_dir)?
        .context("this machine is standalone; there is no cluster roster to edit")?;
    if machine == profile.machine || machine == profile.node {
        bail!(
            "{machine} is this machine; `ouro fleet leave` retires its own identity, and `ouro fleet members remove` edits this machine's view of the others"
        );
    }
    let Some(index) = profile
        .members
        .iter()
        .position(|entry| entry.machine == machine || entry.node == machine)
    else {
        if let Some(gone) = profile
            .tombstones
            .iter()
            .find(|entry| entry.machine == machine || entry.node == machine)
        {
            bail!(
                "this machine's roster already records {} as gone for good; nothing was changed",
                gone.node
            );
        }
        bail!(
            "this machine's roster has no member named {machine}; `ouro fleet status` prints the names it knows"
        );
    };
    let removed = profile.members.remove(index);
    profile.roster_revision = profile
        .roster_revision
        .checked_add(1)
        .ok_or_else(|| anyhow!("this machine's roster revision is exhausted"))?;
    write_profile(data_dir, &profile).context("taking the machine out of this machine's roster")?;
    Ok(removed)
}

fn empty_tags() -> Value {
    Value::Array(Vec::new())
}

fn validated_tags(value: &Value) -> Result<Vec<String>> {
    let tags: Vec<String> = serde_json::from_value(value.clone()).context(
        "fleet tags must be a list of strings; repair only the tags field in the profile",
    )?;
    validate_tags(&tags)?;
    Ok(tags)
}

fn validate_tags(tags: &[String]) -> Result<()> {
    if tags.len() > 32 {
        bail!("fleet tags must contain at most 32 tags");
    }
    for tag in tags {
        let valid = !tag.is_empty()
            && tag.len() <= 64
            && (tag.as_bytes()[0].is_ascii_lowercase() || tag.as_bytes()[0].is_ascii_digit())
            && tag
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._:-".contains(&c));
        if !valid {
            bail!("invalid fleet tag {tag:?}; use 1–64 lowercase letters, digits, dots, underscores, colons or hyphens, starting with a letter or digit");
        }
    }
    Ok(())
}

/// Optional posture facts remain readable against an older runtime.
pub fn render_machine_facts(machine: &Value) -> String {
    let Some(facts) = machine.get("facts").filter(|value| value.is_object()) else {
        return "platform unknown · tags unknown".into();
    };
    let os = facts.get("os").and_then(Value::as_str).unwrap_or("unknown");
    let arch = facts
        .get("arch")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let tags = facts
        .get("tags")
        .and_then(Value::as_array)
        .map(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .take(32)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|tags| !tags.is_empty())
        .unwrap_or_else(|| "—".into());
    let mut text = format!("{os}/{arch} · tags: {tags}");
    if let Some(error) = facts.get("tags_error").and_then(Value::as_str) {
        text.push_str(&format!(" · {error}"));
    }
    text
}

pub fn summary(data_dir: &Path) -> Summary {
    let staging_problem = match inspect_orphan_staging(data_dir) {
        Ok(staging) if staging.is_empty() => None,
        Ok(staging) => Some(format!(
            "{} interrupted private fleet setup director{} require recovery before startup",
            staging.len(),
            if staging.len() == 1 { "y" } else { "ies" }
        )),
        Err(error) => Some(format!("interrupted fleet setup is unsafe: {error:#}")),
    };
    match load(data_dir) {
        Ok(profile) => Summary {
            tls: profile.is_some(),
            profile,
            problems: staging_problem.into_iter().collect(),
        },
        Err(error) => {
            let mut problems = staging_problem.into_iter().collect::<Vec<_>>();
            problems.push(format!("{error:#}"));
            Summary {
                profile: None,
                tls: false,
                problems,
            }
        }
    }
}

pub fn create(
    data_dir: &Path,
    fleet_name: Option<&str>,
    machine: &str,
    host: &str,
    ports: Ports,
) -> Result<Profile> {
    validate_machine(machine)?;
    validate_host(host)?;
    ensure_usable_ipv4_resolution(host)?;
    validate_ports(ports)?;
    let fleet_name = fleet_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{machine}'s fleet"));
    validate_fleet_name(&fleet_name)?;
    ensure_data_dir(data_dir)?;
    let _lock = lock_stopped_fleet_mutation(data_dir, "ouro fleet create")?;
    ensure_local_bind_address(host)?;

    let final_dir = fleet_dir(data_dir);
    if final_dir
        .try_exists()
        .with_context(|| format!("inspecting {}", final_dir.display()))?
    {
        bail!(
            "this machine already has fleet state in {}; run `ouro fleet status` instead, or stop the runtime and run `ouro fleet leave` before creating a different fleet",
            final_dir.display()
        );
    }

    let fleet_id = random_hex(12)?;
    let member = member(machine, host);
    let epmd_port = ports.epmd.unwrap_or_else(|| default_epmd_port(&fleet_id));
    ensure_epmd_port_available(host, epmd_port)?;
    let (dist_port_min, dist_port_max) = dist_ports(ports.dist);
    let profile = Profile {
        tags: empty_tags(),
        schema: PROFILE_SCHEMA,
        fleet_id: fleet_id.clone(),
        name: fleet_name,
        machine: machine.to_string(),
        host: host.to_string(),
        node: member.node.clone(),
        role: "core".to_string(),
        members: vec![member.clone()],
        tombstones: Vec::new(),
        roster_revision: initial_roster_revision(),
        gateway_port: ports
            .gateway
            .unwrap_or_else(|| default_gateway_port(&fleet_id, machine)),
        epmd_port,
        dist_port_min,
        dist_port_max,
    };
    ensure_runtime_ports_available(&profile)?;

    let materials = new_fleet_materials(&profile, &member)?;
    install_new_profile(data_dir, &profile, &materials)?;
    Ok(profile)
}

/// The non-secret and secret facts `create --from` reads out of a privately copied
/// `<data dir>/fleet/` directory.
struct SourceFleet {
    fleet_id: String,
    name: String,
    members: Vec<Member>,
    tombstones: Vec<Member>,
    roster_revision: u64,
    epmd_port: u16,
    dist_port_min: u16,
    dist_port_max: u16,
    ca_cert_pem: String,
    ca_key_pem: Zeroizing<String>,
    cookie: Zeroizing<String>,
}

/// Read a copy of another machine's fleet directory, and refuse anything less than a
/// complete one.
///
/// "Complete" is the whole point: the CA certificate alone cannot sign, a CA key alone
/// cannot be bound to a certificate, and a cookie without the profile names no fleet. The
/// source machine's own leaf is validated against the CA and key here, which is what
/// proves the three files belong together before this machine trusts them.
fn read_source_fleet(dir: &Path) -> Result<SourceFleet> {
    ensure_private_dir(dir).with_context(|| {
        format!(
            "{} must be a private copy of another machine's fleet directory",
            dir.display()
        )
    })?;
    for (name, description) in [
        (PROFILE_FILE, "copied fleet profile"),
        (COOKIE_FILE, "copied fleet cookie"),
        (CA_CERT_FILE, "copied fleet CA certificate"),
        (CA_KEY_FILE, "copied fleet CA key"),
        (NODE_CERT_FILE, "copied node certificate"),
        (NODE_KEY_FILE, "copied node key"),
    ] {
        ensure_private_file(&dir.join(name), description).with_context(|| {
            format!(
                "{} is not a complete copy of a machine's fleet directory; copy the whole of `<data dir>/fleet/` from the first machine, privately",
                dir.display()
            )
        })?;
    }
    let text = read_private(&dir.join(PROFILE_FILE), "copied fleet profile")?;
    let profile: Profile = serde_json::from_str(&text).with_context(|| {
        format!(
            "{} is not a valid fleet profile",
            dir.join(PROFILE_FILE).display()
        )
    })?;
    validate_profile(&profile)?;
    let cookie = Zeroizing::new(read_private(&dir.join(COOKIE_FILE), "copied fleet cookie")?);
    validate_cookie(&cookie, &dir.join(COOKIE_FILE).display().to_string())?;
    let ca_cert_pem = read_private(&dir.join(CA_CERT_FILE), "copied fleet CA certificate")?;
    let ca_key_pem = Zeroizing::new(read_private(&dir.join(CA_KEY_FILE), "copied fleet CA key")?);
    let node_cert_pem = read_private(&dir.join(NODE_CERT_FILE), "copied node certificate")?;
    let node_key_pem = Zeroizing::new(read_private(&dir.join(NODE_KEY_FILE), "copied node key")?);
    validate_tls_identity(
        &member(&profile.machine, &profile.host),
        &ca_cert_pem,
        &node_cert_pem,
        &node_key_pem,
        Some(&ca_key_pem),
        "copied fleet directory",
    )?;
    Ok(SourceFleet {
        fleet_id: profile.fleet_id,
        name: profile.name,
        members: profile.members,
        tombstones: profile.tombstones,
        roster_revision: profile.roster_revision,
        epmd_port: profile.epmd_port,
        dist_port_min: profile.dist_port_min,
        dist_port_max: profile.dist_port_max,
        ca_cert_pem,
        ca_key_pem,
        cookie,
    })
}

/// Give this machine an identity inside a cluster that already exists, from a private
/// copy of the first machine's `<data dir>/fleet/`.
///
/// This is the file-based floor of `docs/proposals/core.md` §3 D4. The operator moves the
/// directory the way they move any other private file; this reads the CA, the key and the
/// cookie out of it and signs exactly one leaf — this machine's. Nothing is sent
/// anywhere, nothing is installed, no machine is contacted, and no CA key is written
/// here: the authority to sign a further machine stays where `ca-key.pem` already is.
/// The first machine learns about this one when an operator runs `ouro fleet members add`
/// on it.
pub fn create_from(
    data_dir: &Path,
    source_dir: &Path,
    machine: &str,
    host: &str,
    ports: Ports,
) -> Result<Profile> {
    validate_machine(machine)?;
    validate_host(host)?;
    ensure_usable_ipv4_resolution(host)?;
    validate_ports(ports)?;
    ensure_data_dir(data_dir)?;
    let _lock = lock_stopped_fleet_mutation(data_dir, "ouro fleet create --from")?;
    ensure_local_bind_address(host)?;

    let final_dir = fleet_dir(data_dir);
    if final_dir
        .try_exists()
        .with_context(|| format!("inspecting {}", final_dir.display()))?
    {
        bail!(
            "this machine already has fleet state in {}; run `ouro fleet status` instead, or stop the runtime and run `ouro fleet leave` before joining a different cluster",
            final_dir.display()
        );
    }

    let source = read_source_fleet(source_dir)?;
    let local = member(machine, host);
    if let Some(existing) = source
        .members
        .iter()
        .chain(source.tombstones.iter())
        .find(|entry| entry.machine == machine || entry.node == local.node)
    {
        bail!(
            "the copied roster already names machine `{}` as {}; `ouro fleet create --from` mints a machine that is not in it yet and will not reissue an existing one. Give this machine another `--machine` name, or move that machine's own fleet directory back to it",
            existing.machine,
            existing.node
        );
    }

    let mut members = source.members.clone();
    members.push(local.clone());
    members.sort_by(|left, right| left.node.cmp(&right.node));
    // One cluster is one EPMD port and one distribution range: `runtime_env` publishes
    // `ERL_EPMD_PORT` per machine and every peer dials it, so the copy's numbers are the
    // right default. An explicit port stays available for several test nodes on one host.
    let epmd_port = ports.epmd.unwrap_or(source.epmd_port);
    ensure_epmd_port_available(host, epmd_port)?;
    let (dist_port_min, dist_port_max) = match ports.dist {
        Some(_) => dist_ports(ports.dist),
        None => (source.dist_port_min, source.dist_port_max),
    };
    let profile = Profile {
        tags: empty_tags(),
        schema: PROFILE_SCHEMA,
        fleet_id: source.fleet_id.clone(),
        name: source.name.clone(),
        machine: machine.to_string(),
        host: host.to_string(),
        node: local.node.clone(),
        role: "core".to_string(),
        members,
        // The operator's statements about machines that are gone travel with the roster;
        // a machine already declared gone must not come back as a member on a machine
        // that joins later.
        tombstones: source.tombstones.clone(),
        roster_revision: source.roster_revision.saturating_add(1),
        gateway_port: ports
            .gateway
            .unwrap_or_else(|| default_gateway_port(&source.fleet_id, machine)),
        epmd_port,
        dist_port_min,
        dist_port_max,
    };
    validate_profile(&profile)?;
    ensure_runtime_ports_available(&profile)?;

    let materials = joined_fleet_materials(&local, &source)?;
    // The leaf has to satisfy the same check `runtime_env` runs before every boot, and it
    // has to satisfy it against the copied CA bytes, not against a re-encoding of them.
    validate_tls_identity(
        &local,
        &materials.ca_cert_pem,
        &materials.node_cert_pem,
        &materials.node_key_pem,
        None,
        "newly signed node credentials",
    )?;
    install_new_profile(data_dir, &profile, &materials)?;
    Ok(profile)
}

/// Rewrite only the generated files from this machine's existing profile.
///
/// `ssl_dist.conf` and `vm.args` are the two files `validate_materials` compares
/// byte-for-byte, and a profile written by an older Ouroboros carries a policy string
/// this build no longer generates. The repair for that is not `leave` plus `create`:
/// those mint a new fleet id, a new CA and a new cookie, so every other machine stops
/// trusting this one and, with no enrollment, nothing can re-establish it. Identity, CA,
/// cookie, members and tombstones are untouched here.
pub fn regenerate(data_dir: &Path) -> Result<Profile> {
    ensure_data_dir(data_dir)?;
    let _lock = lock_stopped_fleet_mutation(data_dir, "ouro fleet create --regenerate")?;
    let profile = load(data_dir)?.context(
        "this machine has no cluster identity to regenerate; `ouro fleet create` mints one, and `ouro fleet create --from` mints one inside an existing cluster",
    )?;
    let root = fleet_dir(data_dir);
    let (tls, vm_args) = generated_runtime_files(data_dir, &profile)?;
    write_private_atomic(&root.join(TLS_OPTFILE), tls.as_bytes())?;
    write_private_atomic(&root.join(VM_ARGS_FILE), vm_args.as_bytes())?;
    validate_materials(data_dir, false).context(
        "the regenerated policy files still do not describe a startable machine; the remaining problem is in the credentials, not in the generated files",
    )?;
    Ok(profile)
}

/// Environment overrides for a packaged runtime. `None` preserves the operator's
/// existing environment workflow exactly; a profile is authoritative when present.
pub fn runtime_env(data_dir: &Path) -> Result<Option<Vec<(String, String)>>> {
    let staging = inspect_orphan_staging(data_dir)?;
    if !staging.is_empty() {
        bail!(
            "{} interrupted private fleet setup director{} remain in {}. Refusing to start standalone or distributed runtime until `ouro fleet doctor` is clean; retry `ouro fleet create` to recover under the lifecycle lock",
            staging.len(),
            if staging.len() == 1 { "y" } else { "ies" },
            data_dir.display()
        );
    }
    let Some(profile) = load(data_dir)? else {
        return Ok(None);
    };
    validate_materials(data_dir, false)?;
    let root = fleet_dir(data_dir);
    let bind_address = resolve_fleet_ipv4(&profile.host).with_context(|| {
        format!(
            "resolving the private IPv4 interface for local machine {}",
            profile.machine
        )
    })?;
    let hosts = profile
        .members
        .iter()
        .map(|member| member.node.as_str())
        .collect::<Vec<_>>()
        .join(",");

    Ok(Some(vec![
        ("OUROBOROS_DIST".into(), "name".into()),
        ("OUROBOROS_NODE".into(), profile.node.clone()),
        ("OUROBOROS_NODE_ROLE".into(), profile.role.clone()),
        ("OUROBOROS_MACHINE_NAME".into(), profile.machine.clone()),
        ("OUROBOROS_FLEET_ID".into(), profile.fleet_id.clone()),
        (
            "OUROBOROS_COOKIE_FILE".into(),
            root.join(COOKIE_FILE).display().to_string(),
        ),
        // Mix releases translate RELEASE_COOKIE into a process argument. This random
        // value is intentionally disposable; config/runtime.exs replaces it from the
        // private file before any cluster/application child starts. The real cookie is
        // never present in argv or the environment.
        (
            "OUROBOROS_BOOT_COOKIE_DECOY".into(),
            format!("ouro_boot_{}", random_hex(16)?),
        ),
        ("OUROBOROS_CLUSTER_STRATEGY".into(), "epmd".into()),
        // EPMD otherwise listens on every interface. Keep both discovery and the TLS
        // distribution listener on the one private address this profile advertises.
        ("ERL_EPMD_ADDRESS".into(), bind_address.to_string()),
        ("ERL_EPMD_PORT".into(), profile.epmd_port.to_string()),
        ("OUROBOROS_CLUSTER_HOSTS".into(), hosts),
        ("OUROBOROS_CLUSTER_RECONNECT_MS".into(), "1000".into()),
        ("OUROBOROS_DIST_TLS".into(), "1".into()),
        (
            "OUROBOROS_DIST_TLS_OPTFILE".into(),
            root.join(TLS_OPTFILE).display().to_string(),
        ),
        (
            "RELEASE_VM_ARGS".into(),
            root.join(VM_ARGS_FILE).display().to_string(),
        ),
        (
            "OUROBOROS_GATEWAY_PORT".into(),
            profile.gateway_port.to_string(),
        ),
    ]))
}

pub fn render_status(data_dir: &Path) -> Result<String> {
    let Some(profile) = load(data_dir)? else {
        return Ok(format!(
            "Standalone machine\n  No cluster identity is configured in {}.\n\nNext: `ouro fleet create` gives this machine a node name, a private cookie and TLS materials; see docs/FLEET.md to form a cluster with a second machine.\n",
            data_dir.display()
        ));
    };

    let runtime = runtime::read_publication(data_dir)?;
    let (runtime_text, runtime_live) = match runtime {
        Some(publication) if runtime::publication_is_live(&publication)? => (
            format!(
                "running (pid {}, node {})",
                publication.pid, publication.node
            ),
            true,
        ),
        Some(publication) => (
            format!("stopped (stale publication for pid {})", publication.pid),
            false,
        ),
        None => ("stopped".to_string(), false),
    };
    let peers = profile.expected_peers();
    let epmd_lifecycle = epmd_ownership_status(data_dir, &profile);
    let mut text = format!(
        "{}\n  fleet id     {}\n  machine      {}\n  address      {}\n  node         {}\n  role         runs agents\n  runtime      {}\n  expected     {} machine{} ({} peer{})\n  transport    TLS (certificate + private cookie file)\n  gateway      127.0.0.1:{}\n  EPMD         fleet-specific port {}\n  EPMD owner   {}\n  dist ports   {}..{}\n",
        profile.name,
        profile.fleet_id,
        profile.machine,
        profile.host,
        profile.node,
        runtime_text,
        profile.members.len(),
        plural(profile.members.len()),
        peers,
        plural(peers),
        profile.gateway_port,
        profile.epmd_port,
        epmd_lifecycle,
        profile.dist_port_min,
        profile.dist_port_max
    );
    text.push_str("  machines     ");
    text.push_str(
        &profile
            .members
            .iter()
            .map(|member| member.machine.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );
    text.push('\n');
    if !profile.tombstones.is_empty() {
        text.push_str("  gone         ");
        text.push_str(
            &profile
                .tombstones
                .iter()
                .map(|member| member.machine.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
        text.push_str(" (declared gone for good; `ouro fleet sessions restore NAME` undoes it)\n");
    }
    if !runtime_live {
        text.push_str("\nNext: `ouro daemon`. It will keep retrying machines that start later.\n");
    } else {
        text.push_str("\nConnected peers are shown by `ouro attach --print`; `ouro fleet doctor` checks this machine's setup.\n");
    }
    Ok(text)
}

/// Renders the runtime's last-known directory. The gateway value is treated as a
/// tolerant projection so an older/newer runtime can add fields without breaking this
/// client; malformed essentials return `None` and the caller falls back to local state.
pub fn render_live_status(data_dir: &Path, value: &Value) -> Option<String> {
    let profile = load(data_dir).ok().flatten()?;
    let summary = value.get("summary")?;
    let reported_expected = summary.get("expected")?.as_u64()?;
    let connected = summary.get("connected")?.as_u64()?;
    let machines = value.get("machines")?.as_array()?;
    let reported_nodes = machines
        .iter()
        .filter_map(|machine| machine.get("node").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let configured_missing = profile
        .members
        .iter()
        .filter(|member| !reported_nodes.contains(member.node.as_str()))
        .collect::<Vec<_>>();
    let union_size = profile
        .members
        .iter()
        .map(|member| member.node.as_str())
        .chain(reported_nodes.iter().copied())
        .collect::<BTreeSet<_>>()
        .len() as u64;
    // A newer peer may be discovered after this machine's invitation was written. A
    // directory can therefore know more connected machines than its static seed list;
    // never render the nonsensical "expected 2 · connected 3" while older runtimes are
    // still in use.
    let expected = reported_expected.max(connected).max(union_size);
    let offline = summary
        .get("offline")?
        .as_u64()?
        .saturating_add(configured_missing.len() as u64)
        .max(expected.saturating_sub(connected));
    let incompatible = summary
        .get("incompatible")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let reconnect_ms = value
        .pointer("/formation/reconnect_ms")
        .and_then(Value::as_u64)
        .unwrap_or(1_000);
    let tls = value
        .pointer("/security/tls")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut text = format!(
        "{}\n  machine      {}\n  formation    known {} · connected {} · offline {}\n  recovery     retrying offline machines every {} ms\n  transport    {}\n",
        profile.name,
        profile.machine,
        expected,
        connected,
        offline,
        reconnect_ms,
        if tls { "TLS verified" } else { "NOT TLS — run `ouro fleet doctor`" }
    );
    if incompatible > 0 {
        text.push_str(&format!(
            "  compatibility {} incompatible machine{}\n",
            incompatible,
            plural(incompatible as usize)
        ));
    }
    text.push_str("\nMachines\n");
    for machine in machines {
        let reported_name = machine
            .get("machine")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let node = machine
            .get("node")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let name = profile
            .members
            .iter()
            .find(|member| member.node == node)
            .map(|member| member.machine.as_str())
            .unwrap_or(reported_name);
        let state = machine
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let role = machine
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let marker = match state {
            "local" | "connected" => "●",
            "offline" => "○",
            _ => "?",
        };
        text.push_str(&format!(
            "  {marker} {name:<18} {state:<10} {role:<8} {node}\n"
        ));
        text.push_str(&format!("      {}\n", render_machine_facts(machine)));
        if state == "offline" {
            let retry = if machine.get("expected?").and_then(Value::as_bool) == Some(false) {
                "not in the active roster"
            } else {
                "automatic retry is active"
            };
            if let Some(last) = machine.get("last_down_at").and_then(Value::as_str) {
                text.push_str(&format!("      last disconnected {last}; {retry}\n"));
            } else {
                text.push_str(&format!("      not seen yet; {retry}\n"));
            }
        }
    }
    // The creator records an invitation immediately, while a live runtime learned its
    // seed list at boot. Keep that not-yet-joined machine visible instead of letting the
    // live projection erase the user's just-completed action.
    for member in configured_missing {
        text.push_str(&format!(
            "  ○ {:<18} {:<10} {:<8} {}\n",
            member.machine, "invited", "expected", member.node
        ));
        text.push_str(
            "      not joined yet; it can connect inward now, and this machine loads it as an outbound seed on its next restart\n",
        );
    }
    // A declared-gone machine is out of `members`, so neither the local roster nor the
    // live directory mentions it. Printing it is the only way an operator can see that a
    // `sessions forget` — or a client that died halfway through one — happened at all.
    for gone in &profile.tombstones {
        text.push_str(&format!(
            "  ✕ {:<18} {:<10} {:<8} {}\n",
            gone.machine, "gone", "declared", gone.node
        ));
        text.push_str(
            "      declared gone for good on this machine; `ouro fleet sessions restore NAME` undoes it\n",
        );
    }
    text.push_str(&format!(
        "\nAuthority: this machine's credentials cannot be reissued from anywhere else. Back up {} securely.\n",
        fleet_dir(data_dir).display()
    ));
    text.push_str("\nUse `ouro new --machine NAME --provider PROVIDER --workspace /absolute/path/on/NAME/project` to place an agent; the workspace is the destination path on that machine. Run `ouro fleet doctor` for firewall, certificate, and version guidance.\n");
    Some(text)
}

pub struct DoctorReport {
    pub text: String,
    pub healthy: bool,
    data_dir: PathBuf,
    checks: Vec<Check>,
    scope: String,
}

pub fn doctor(data_dir: &Path) -> DoctorReport {
    let mut checks = Vec::new();
    match inspect_orphan_staging(data_dir) {
        Ok(staging) if staging.is_empty() => {}
        Ok(staging) => checks.push(problem(format!(
            "{} interrupted private fleet setup {} outside the active profile. Retry `ouro fleet create` to clean it safely under the lifecycle lock, then rerun doctor",
            staging.len(),
            if staging.len() == 1 { "remains" } else { "directories remain" }
        ))),
        Err(error) => checks.push(problem(format!(
            "interrupted fleet setup cannot be recovered safely: {error:#}"
        ))),
    }
    // `ouro fleet leave` is the only command that removes this directory and it refuses
    // one holding an entry it does not recognize. Naming them here is what keeps that
    // refusal from being a silent dead end.
    let root = fleet_dir(data_dir);
    match root.try_exists() {
        Ok(true) => match unrecognized_fleet_entries(&root) {
            Ok(unknown) if unknown.is_empty() => {}
            Ok(unknown) => checks.push(problem(format!(
                "{} holds {} entr{} no Ouroboros command recognizes ({}). `ouro fleet leave` refuses to remove a directory containing them; move or inspect them first",
                root.display(),
                unknown.len(),
                if unknown.len() == 1 { "y" } else { "ies" },
                unknown.join(", ")
            ))),
            Err(error) => checks.push(problem(format!(
                "the fleet directory cannot be listed: {error:#}"
            ))),
        },
        Ok(false) => {}
        Err(error) => checks.push(problem(format!(
            "the fleet directory cannot be inspected: {error:#}"
        ))),
    }
    let profile = match load(data_dir) {
        Ok(Some(profile)) => {
            checks.push(ok(format!(
                "profile describes {} as {}",
                profile.machine, profile.node
            )));
            Some(profile)
        }
        Ok(None) => {
            checks.push(problem("no fleet profile; this machine is standalone"));
            None
        }
        Err(error) => {
            checks.push(problem(format!("profile cannot be read: {error:#}")));
            None
        }
    };

    if let Some(profile) = &profile {
        if let Err(error) = validated_tags(&profile.tags) {
            checks.push(warn(format!("advisory tags ignored: {error:#}. Remove the named tag with `ouro fleet tag remove TAG`, or repair only the tags field in the profile; fleet identity remains valid")));
        }
        match validate_materials(data_dir, false) {
            Ok(()) => checks.push(ok(
                "TLS certificate, key, cookie, and VM arguments are private and readable",
            )),
            Err(error) => checks.push(problem(format!("security material: {error:#}"))),
        }

        if let Some(range) = local_ephemeral_port_range() {
            for warning in ephemeral_overlap_warnings(profile, range) {
                checks.push(warn(warning));
            }
        }

        let publication_running = match runtime::read_live_publication(data_dir) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(error) => {
                checks.push(problem(format!(
                    "gateway publication cannot be trusted: {error:#}"
                )));
                false
            }
        };
        let owner_running = match runtime::read_owned_runtime_owner(data_dir) {
            Ok(Some(owner)) => match runtime::runtime_owner_is_live(&owner) {
                Ok(live) => live,
                Err(error) => {
                    checks.push(problem(format!(
                        "runtime owner incarnation cannot be verified: {error:#}"
                    )));
                    false
                }
            },
            Ok(None) => false,
            Err(error) => {
                checks.push(problem(format!(
                    "runtime owner marker cannot be trusted: {error:#}"
                )));
                false
            }
        };
        let runtime_running = publication_running || owner_running;
        if !runtime_running {
            match ensure_runtime_ports_available(profile) {
                Ok(()) => checks.push(ok(format!(
                    "stopped-runtime preflight found local gateway 127.0.0.1:{} and at least one TLS distribution port in {}-{} available",
                    profile.gateway_port, profile.dist_port_min, profile.dist_port_max
                ))),
                Err(error) => checks.push(problem(format!(
                    "stopped-runtime listener preflight: {error:#}"
                ))),
            }
        }
        for member in &profile.members {
            match resolve_fleet_ipv4(&member.host) {
                Ok(address) => {
                    if address.is_loopback() {
                        checks.push(warn(format!(
                            "{} uses loopback address {address}; this is a local-only test topology and cannot connect another machine",
                            member.machine
                        )));
                    } else {
                        checks.push(ok(format!(
                            "{} address {} resolves to private IPv4 {address}",
                            member.machine, member.host
                        )));
                    }
                    if member.node == profile.node {
                        match TcpListener::bind((address, 0)) {
                            Ok(listener) => {
                                drop(listener);
                                if address.is_loopback() {
                                    match ensure_epmd_port_available(
                                        &profile.host,
                                        profile.epmd_port,
                                    ) {
                                        Ok(EpmdPortState::CompatibleRunning) => checks.push(warn(format!(
                                            "same-host lab uses a compatible loopback EPMD {address}:{} that does not occupy another local IPv4 interface; this topology is intentionally local-only",
                                            profile.epmd_port
                                        ))),
                                        Ok(EpmdPortState::Available) if runtime_running => checks.push(problem(format!(
                                            "same-host runtime is marked live but no EPMD answers on loopback {address}:{}; inspect the runtime/startup log before relying on reconnection",
                                            profile.epmd_port
                                        ))),
                                        Ok(EpmdPortState::Available) => checks.push(warn(format!(
                                            "same-host lab loopback EPMD {address}:{} is available for the next start; this topology is intentionally local-only",
                                            profile.epmd_port
                                        ))),
                                        Err(error) => checks.push(problem(format!(
                                            "same-host lab EPMD preflight: {error:#}"
                                        ))),
                                    }
                                } else {
                                    match ensure_epmd_port_available(
                                        &profile.host,
                                        profile.epmd_port,
                                    ) {
                                        Ok(EpmdPortState::CompatibleRunning) => checks.push(ok(format!(
                                            "a compatible fleet-specific EPMD answers on advertised private address {address}:{} and loopback, but not another local IPv4 interface; it may legitimately remain after the BEAM runtime stops",
                                            profile.epmd_port
                                        ))),
                                        Ok(EpmdPortState::Available) if runtime_running => checks.push(problem(format!(
                                            "runtime is marked live but no EPMD answers on advertised private address {address}:{}. Inspect the runtime and startup log; do not open host-global default port 4369",
                                            profile.epmd_port
                                        ))),
                                        Ok(EpmdPortState::Available) => checks.push(ok(format!(
                                            "fleet-specific private EPMD address {address}:{} is available; default host-global port 4369 is not used",
                                            profile.epmd_port
                                        ))),
                                        Err(error) => checks.push(problem(format!(
                                            "private EPMD preflight: {error:#}"
                                        ))),
                                    }
                                }
                            }
                            Err(error) => checks.push(problem(format!(
                                "local advertised address {address} is not available on this machine: {error}. Fix --host/private DNS, then recreate or rejoin the fleet before starting"
                            ))),
                        }
                    } else if runtime_running {
                        let epmd = epmd_responds(address, profile.epmd_port);
                        if epmd {
                            checks.push(ok(format!(
                                "{} host {} answers on private EPMD address {address}:{}",
                                member.machine, member.host, profile.epmd_port
                            )));
                        } else {
                            checks.push(warn(format!(
                                "{} host {} is not answering on private EPMD address {address}:{} yet; the machine may be offline or a firewall may block it",
                                member.machine, member.host, profile.epmd_port
                            )));
                        }
                    }
                }
                Err(error) => checks.push(problem(format!(
                    "{} address {} cannot be used safely: {error:#}",
                    member.machine, member.host
                ))),
            }
        }

        checks.push(epmd_ownership_doctor_check(data_dir, profile));

        match runtime::read_publication(data_dir) {
            Ok(Some(publication))
                if runtime::publication_is_live(&publication).unwrap_or(false) =>
            {
                checks.push(ok(format!(
                    "runtime is running as {} (pid {})",
                    publication.node, publication.pid
                )))
            }
            Ok(Some(publication)) => checks.push(warn(format!(
                "runtime is stopped; its old publication names absent pid {}",
                publication.pid
            ))),
            Ok(None) => checks.push(warn("runtime is stopped; start it with `ouro daemon`")),
            Err(error) => checks.push(problem(format!(
                "runtime publication cannot be read: {error:#}"
            ))),
        }

        if !profile.tombstones.is_empty() {
            checks.push(warn(format!(
                "this machine's roster declares {} gone for good: {}. They are out of `members`, so nothing dials them and `ouro fleet status` does not expect them; `ouro fleet sessions restore NAME` undoes one",
                profile.tombstones.len(),
                profile
                    .tombstones
                    .iter()
                    .map(|member| member.machine.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        checks.push(warn(format!(
            "this machine's cluster credentials cannot be reissued from anywhere else. Back up {} securely; there is no recovery from disk loss",
            fleet_dir(data_dir).display()
        )));
    }

    build_doctor_report(data_dir, checks, "local profile, host, and runtime checks")
}

fn build_doctor_report(data_dir: &Path, checks: Vec<Check>, scope: &str) -> DoctorReport {
    let mut report = DoctorReport {
        text: String::new(),
        healthy: false,
        data_dir: data_dir.to_path_buf(),
        checks,
        scope: scope.to_string(),
    };
    refresh_doctor_report(&mut report);
    report
}

fn refresh_doctor_report(report: &mut DoctorReport) {
    report.healthy = report
        .checks
        .iter()
        .all(|check| check.level != CheckLevel::Problem);
    let mut text = format!(
        "Fleet doctor — {}\n  scope        {}\n",
        report.data_dir.display(),
        report.scope
    );
    for check in &report.checks {
        text.push_str(&format!("  {} {}\n", check.level.marker(), check.message));
    }
    if report.healthy {
        let networking = if report.scope.starts_with("live") {
            "Fleet networking is ready; local security and live distributed-runtime checks passed."
        } else {
            "Fleet networking is locally ready; live remote compatibility and connectivity were not checked."
        };
        text.push_str(&format!("\n{networking}\n"));
    } else {
        text.push_str(
            "\nNot ready. Fix the items marked [fix], then run `ouro fleet doctor` again. No secret values were printed.\n",
        );
    }
    report.text = text;
}

/// Labels the safe stopped fallback honestly: there is no live directory to verify.
pub fn doctor_stopped(mut report: DoctorReport) -> DoctorReport {
    report.scope = "local checks only (runtime stopped)".into();
    refresh_doctor_report(&mut report);
    report
}

/// A published runtime that cannot answer its live doctor is not treated as healthy.
pub fn doctor_live_unavailable(
    mut report: DoctorReport,
    diagnostic: impl Into<String>,
) -> DoctorReport {
    report.scope = "local checks; live runtime check unavailable".into();
    report.checks.push(problem(format!(
        "live fleet doctor could not be reached: {}. Retry after checking `ouro status`; saved profile checks alone cannot prove remote compatibility",
        diagnostic.into()
    )));
    refresh_doctor_report(&mut report);
    report
}

/// Merges the authenticated runtime's distributed checks with local file/service facts.
pub fn merge_live_doctor(mut report: DoctorReport, value: &Value) -> DoctorReport {
    report.scope = "live runtime + local profile, host, and service checks".into();
    let parsed = (|| -> Result<(bool, Vec<Check>)> {
        let healthy = value
            .get("healthy?")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("response is missing boolean healthy?"))?;
        let entries = value
            .get("checks")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("response is missing checks[]"))?;
        let mut checks = Vec::with_capacity(entries.len());
        for entry in entries {
            let status = entry
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("a live check is missing status"))?;
            let message = live_doctor_text(entry.get("message"), "message")?;
            let guidance = entry
                .get("guidance")
                .map(|value| live_doctor_text(Some(value), "guidance"))
                .transpose()?;
            let message = match (status, guidance) {
                // Older gateways may attach remediation mechanically even when the
                // underlying check is healthy. A green check must never tell a newcomer
                // to repair working state.
                ("ok", _) | (_, None) => format!("live runtime: {message}"),
                (_, Some(guidance)) => format!("live runtime: {message}. Next: {guidance}"),
            };
            checks.push(match status {
                "ok" => ok(message),
                "warning" => warn(message),
                "error" => problem(message),
                other => bail!("a live check has unknown status `{other}`"),
            });
        }
        Ok((healthy, checks))
    })();

    match parsed {
        Ok((healthy, checks)) => {
            let has_problem = checks
                .iter()
                .any(|check| check.level == CheckLevel::Problem);
            report.checks.extend(checks);
            if !healthy && !has_problem {
                report.checks.push(problem(
                    "live fleet doctor reported unhealthy without an error check; align every machine's Ouroboros version, fleet protocol revision, and OTP release (CPU architecture may differ), then retry",
                ));
            }
        }
        Err(error) => report.checks.push(problem(format!(
            "live fleet doctor returned an unreadable response: {error}"
        ))),
    }
    refresh_doctor_report(&mut report);
    report
}

fn live_doctor_text(value: Option<&Value>, field: &str) -> Result<String> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("a live check is missing string {field}"))?;
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        bail!("a live check has blank {field}");
    }
    let mut bounded = normalized.chars().take(500).collect::<String>();
    if normalized.chars().count() > 500 {
        bounded.push('…');
    }
    Ok(bounded)
}

/// Removes only the known fleet files, and only while no runtime owns this data dir.
/// Unknown entries are refused before anything is deleted.
/// What `leave` removed, so the caller can say it out loud.
///
/// `machine` is `None` for a directory whose `profile.json` is missing or unreadable —
/// the state a crash between `install_new_profile`'s staging rename and its fsync leaves.
/// `leave` is the only command that removes a fleet directory, so it has to work on that
/// directory too; the recognized private files are removed either way and named in
/// `removed`.
#[derive(Debug)]
pub struct Removal {
    pub machine: Option<String>,
    pub profile_readable: bool,
    pub removed: Vec<String>,
}

pub fn leave(data_dir: &Path) -> Result<Option<Removal>> {
    leave_with_epmd_program(data_dir, None)
}

/// Packaged CLI path: the current embedded release supplies its own EPMD control binary
/// so cleanup never resolves a security-sensitive command through PATH.
pub fn leave_with_epmd(data_dir: &Path, epmd_program: &Path) -> Result<Option<Removal>> {
    leave_with_epmd_program(data_dir, Some(epmd_program))
}

fn leave_with_epmd_program(
    data_dir: &Path,
    epmd_program: Option<&Path>,
) -> Result<Option<Removal>> {
    ensure_data_dir(data_dir)?;
    let _lock = lock_stopped_fleet_mutation(data_dir, "ouro fleet leave")?;

    let dir = fleet_dir(data_dir);
    if !dir
        .try_exists()
        .with_context(|| format!("inspecting {}", dir.display()))?
    {
        return Ok(None);
    }
    // An unreadable profile must not lock the operator out of the one command that
    // cleans up: every other surface refuses such a directory, so refusing here too
    // leaves `rm -rf` as the only repair. The EPMD retirement below already accepts
    // `None` and then trusts only the ownership marker and its lock.
    let profile = load(data_dir).unwrap_or_default();
    retire_epmd_before_profile_removal(data_dir, profile.as_ref(), epmd_program)?;
    let removed = remove_recognized_fleet_dir(&dir)?;
    Ok(Some(Removal {
        machine: profile.as_ref().map(|profile| profile.machine.clone()),
        profile_readable: profile.is_some(),
        removed,
    }))
}

fn retire_epmd_before_profile_removal(
    data_dir: &Path,
    profile: Option<&Profile>,
    epmd_program: Option<&Path>,
) -> Result<()> {
    let marker = load_epmd_owner(data_dir)?;
    let lock_path = epmd_owner_lock_path(data_dir);
    let Some(owner) = marker else {
        if lock_path.try_exists()? {
            if epmd_unmarked_lock_held(data_dir)? {
                bail!(
                    "{} is held without a complete ownership marker. Ouroboros cannot prove which process inherited it, so no daemon or credential was removed. Stop the interrupted packaged starter, then retry `ouro fleet leave`",
                    lock_path.display()
                );
            }
            remove_unlocked_epmd_lock(&lock_path)?;
        }
        let Some(profile) = profile else {
            return Ok(());
        };
        match ensure_epmd_port_available(&profile.host, profile.epmd_port)? {
            EpmdPortState::Available => return Ok(()),
            EpmdPortState::CompatibleRunning => {
                bail!(
                    "a compatible EPMD is still running on {}:{} but this profile has no positive Ouroboros ownership lease for it. It may predate this fleet and was not killed. Stop it through the process/service that started it, verify `ouro fleet doctor` reports the EPMD port available, then retry `ouro fleet leave`; the profile and credentials were retained",
                    resolve_fleet_ipv4(&profile.host)?,
                    profile.epmd_port
                );
            }
        }
    };

    validate_epmd_owner_shape(&owner)?;
    if let Some(profile) = profile {
        validate_epmd_owner(&owner, profile)?;
    }
    let held = epmd_owner_lock_held(data_dir, &owner)?;
    let alive = runtime::pid_alive(owner.pid);
    let state = ensure_owned_epmd_listener_state(&owner)?;

    if !held && state == OwnedEpmdListenerState::Available {
        // No process holds the exact inherited lease and no listener exists. The
        // recorded numeric PID may have been reused after reboot, but no process is
        // targeted in this cleanup branch.
        remove_epmd_owner_artifacts(data_dir)?;
        return Ok(());
    }
    if !alive
        || !held
        || !matches!(
            state,
            OwnedEpmdListenerState::CompatibleRunning | OwnedEpmdListenerState::LoopbackOnly
        )
    {
        bail!(
            "fleet EPMD ownership cannot be proved safely (recorded pid {} alive: {alive}, inherited lock held: {held}, port state: {state:?}). Nothing was killed and the fleet profile was retained. Stop the EPMD through its known owner, verify `ouro fleet doctor` reports port {} available, then retry",
            owner.pid,
            owner.port
        );
    }

    stop_owned_empty_epmd(data_dir, &owner, epmd_program)
}

fn stop_owned_empty_epmd(
    data_dir: &Path,
    owner: &EpmdOwner,
    epmd_program: Option<&Path>,
) -> Result<()> {
    // Loopback is mandatory for real EPMD even when the recorded private interface has
    // disappeared. Querying it avoids re-resolving mutable DNS for a destructive target.
    let names = epmd_registered_names(Ipv4Addr::LOCALHOST, owner.port)?;
    if !names.is_empty() {
        let shown = names.into_iter().take(5).collect::<Vec<_>>().join(", ");
        bail!(
            "owned fleet EPMD {}:{} still advertises registered node name(s): {}. No daemon or credential was removed. Stop every runtime using this fleet-specific port, then retry `ouro fleet leave`",
            owner.address,
            owner.port,
            shown
        );
    }

    if epmd_program.is_none() {
        // Library fallback has no current embedded release to supply a trusted helper,
        // so its historical executable must still be the exact recorded inode. The
        // packaged CLI always passes its freshly extracted helper and does not depend on
        // an old cache generation surviving GC.
        validate_epmd_owner_executable(owner)?;
    }
    let epmd_program = epmd_program.unwrap_or(&owner.executable);
    let (epmd_program, _) = validate_epmd_program(epmd_program).with_context(|| {
        "a trusted packaged EPMD control binary is required before the owned daemon can be retired; run this command with the current packaged ouro binary"
    })?;
    run_epmd_kill(&epmd_program, owner.port)?;

    let deadline = Instant::now() + EPMD_STOP_DEADLINE;
    loop {
        let recorded_closed = epmd_probe(owner.address, owner.port) != EpmdProbe::Compatible;
        let loopback_closed = owner.address.is_loopback()
            || epmd_probe(Ipv4Addr::LOCALHOST, owner.port) != EpmdProbe::Compatible;
        let listener_closed = recorded_closed && loopback_closed;
        let lock_released = !epmd_owner_lock_held(data_dir, owner)?;
        if listener_closed && lock_released {
            break;
        }
        if Instant::now() >= deadline {
            bail!(
                "packaged EPMD kill returned, but cleanup could not prove the exact inherited lock and listeners closed (recorded pid {}, inherited lock released: {lock_released}, listener closed: {listener_closed}). The fleet profile was retained for recovery",
                owner.pid
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
    remove_epmd_owner_artifacts(data_dir)
}

fn run_epmd_kill(epmd_program: &Path, port: u16) -> Result<()> {
    let mut child = Command::new(epmd_program)
        .args(["-port", &port.to_string(), "-kill"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| {
            format!(
                "starting packaged EPMD control {} for port {port}",
                epmd_program.display()
            )
        })?;
    let deadline = Instant::now() + EPMD_STOP_DEADLINE;
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            bail!(
                "packaged EPMD refused to stop owned empty port {port} ({status}); no fleet credential was removed"
            );
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            let _ = child.wait();
            bail!(
                "packaged EPMD control timed out while stopping port {port}; no fleet credential was removed"
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn epmd_registered_names(address: Ipv4Addr, port: u16) -> Result<Vec<String>> {
    let socket = (address, port).into();
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_millis(500))
        .with_context(|| format!("connecting to EPMD NAMES at {address}:{port}"))?;
    let timeout = Some(Duration::from_millis(500));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    stream.write_all(&[0, 1, 110])?;
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .context("reading EPMD NAMES header")?;
    if u32::from_be_bytes(header) != u32::from(port) {
        bail!("listener did not return the expected EPMD port in its NAMES response");
    }
    let mut body = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                if body.len() + count > 64 * 1024 {
                    bail!("EPMD NAMES response exceeded 64 KiB");
                }
                body.extend_from_slice(&chunk[..count]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error).context("reading EPMD NAMES response"),
        }
    }
    let body = String::from_utf8(body).context("EPMD NAMES response was not UTF-8")?;
    Ok(body
        .lines()
        .filter_map(|line| line.strip_prefix("name "))
        .filter_map(|line| line.split_once(" at port ").map(|(name, _)| name))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect())
}

fn remove_recognized_fleet_dir(dir: &Path) -> Result<Vec<String>> {
    ensure_private_dir(dir)?;
    let known = known_fleet_files();
    let mut present = Vec::new();
    let mut names = Vec::new();
    let mut cluster_directory = None;
    let unknown = unrecognized_fleet_entries(dir)?;
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == CLUSTER_DIRECTORY_DIR {
            cluster_directory = Some(entry.path());
            names.push(name.to_string());
        } else if known.contains(name) || retired_revocation_file(name) {
            present.push(entry.path());
            names.push(name.to_string());
        }
    }
    if !unknown.is_empty() {
        bail!(
            "{} contains unknown entries ({}); nothing was removed. Move or inspect them, then retry",
            dir.display(),
            unknown.join(", ")
        );
    }
    names.sort();
    // Validate the complete recognized shape before unlinking the first credential.
    // A late symlink or foreign file must leave every known secret intact.
    for path in &present {
        ensure_private_file(path, "fleet file")?;
    }
    let checkpoint_files = cluster_directory
        .as_deref()
        .map(validate_cluster_directory)
        .transpose()?;

    for path in present {
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    if let (Some(cluster_directory), Some(checkpoint_files)) =
        (cluster_directory.as_deref(), checkpoint_files)
    {
        remove_validated_cluster_directory(cluster_directory, checkpoint_files)?;
    }
    fs::remove_dir(dir).with_context(|| format!("removing empty {}", dir.display()))?;
    sync_parent(dir)?;
    Ok(names)
}

/// Entries in `<data dir>/fleet/` that no lifecycle command recognizes.
///
/// `leave` refuses to remove such a directory, so anything listed here is a dead end
/// until the operator moves it: `doctor` therefore names them instead of calling the
/// machine healthy.
fn unrecognized_fleet_entries(dir: &Path) -> Result<Vec<String>> {
    let known = known_fleet_files();
    let mut unknown = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            unknown.push(name.to_string_lossy().into_owned());
            continue;
        };
        if name == CLUSTER_DIRECTORY_DIR || known.contains(name) || retired_revocation_file(name) {
            continue;
        }
        unknown.push(name.to_string());
    }
    unknown.sort();
    Ok(unknown)
}

/// `revoke-<64 hex>.json`: the CA-attested revocation artifact this reduction deleted the
/// producer of.
///
/// The files themselves are durable state on any machine whose lab ever revoked one —
/// written by the previous `ouro fleet join` and by `Ouroboros.Cluster.Revocations` — and
/// nothing else in the tree reads them any more. Recognizing the shape is what keeps
/// `ouro fleet leave` able to retire such a machine's identity at all.
fn retired_revocation_file(name: &str) -> bool {
    name.strip_prefix("revoke-")
        .and_then(|rest| rest.strip_suffix(".json"))
        .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn validate_cluster_directory(path: &Path) -> Result<Vec<PathBuf>> {
    ensure_private_dir(path)
        .with_context(|| format!("validating recognized {}", path.display()))?;
    let mut checkpoints = None;
    let mut unknown = Vec::new();
    for entry in fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_str() == Some(CLUSTER_CHECKPOINTS_DIR) {
            checkpoints = Some(entry.path());
        } else {
            unknown.push(name.to_string_lossy().into_owned());
        }
    }
    if !unknown.is_empty() {
        bail!(
            "{} contains unknown cluster-directory entries ({}); no fleet credential was removed",
            path.display(),
            unknown.join(", ")
        );
    }
    let Some(checkpoints) = checkpoints else {
        // A freshly created durable directory may not have written its first checkpoint
        // yet. The empty, exact root is still a recognized stopped shape.
        return Ok(Vec::new());
    };
    ensure_private_dir(&checkpoints)
        .with_context(|| format!("validating recognized {}", checkpoints.display()))?;

    let mut files = Vec::new();
    let mut unknown = Vec::new();
    let mut temporary_files = 0_usize;
    for entry in
        fs::read_dir(&checkpoints).with_context(|| format!("reading {}", checkpoints.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let recognized = name.to_str().is_some_and(|name| {
            if name == CLUSTER_CHECKPOINT_FILE {
                return true;
            }
            let temporary = name
                .strip_prefix(&format!("{CLUSTER_CHECKPOINT_FILE}.tmp-"))
                .is_some_and(|suffix| {
                    suffix.len() == 16
                        && suffix
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                });
            if temporary {
                temporary_files += 1;
            }
            temporary
        });
        if recognized {
            ensure_private_file(&entry.path(), "cluster directory checkpoint")?;
            files.push(entry.path());
        } else {
            unknown.push(name.to_string_lossy().into_owned());
        }
    }
    if !unknown.is_empty() {
        bail!(
            "{} contains unknown checkpoint entries ({}); no fleet credential was removed",
            checkpoints.display(),
            unknown.join(", ")
        );
    }
    if temporary_files > MAX_CLUSTER_CHECKPOINT_TEMPS {
        bail!(
            "{} contains {} interrupted checkpoint temporaries (maximum recognized recovery set is {}); no fleet credential was removed",
            checkpoints.display(),
            temporary_files,
            MAX_CLUSTER_CHECKPOINT_TEMPS
        );
    }
    Ok(files)
}

fn remove_validated_cluster_directory(path: &Path, checkpoint_files: Vec<PathBuf>) -> Result<()> {
    let checkpoints = path.join(CLUSTER_CHECKPOINTS_DIR);
    for checkpoint in checkpoint_files {
        fs::remove_file(&checkpoint)
            .with_context(|| format!("removing checkpoint {}", checkpoint.display()))?;
    }
    if checkpoints.try_exists()? {
        fs::remove_dir(&checkpoints)
            .with_context(|| format!("removing empty {}", checkpoints.display()))?;
    }
    fs::remove_dir(path).with_context(|| format!("removing empty {}", path.display()))?;
    sync_parent(path)
}

fn known_fleet_files() -> BTreeSet<&'static str> {
    [
        PROFILE_FILE,
        COOKIE_FILE,
        CA_CERT_FILE,
        CA_KEY_FILE,
        NODE_CERT_FILE,
        NODE_KEY_FILE,
        TLS_OPTFILE,
        VM_ARGS_FILE,
        EPMD_OWNER_FILE,
        EPMD_OWNER_LOCK_FILE,
    ]
    .into_iter()
    .collect()
}

fn install_new_profile(data_dir: &Path, profile: &Profile, materials: &Materials) -> Result<()> {
    let final_dir = fleet_dir(data_dir);
    let staging = data_dir.join(format!(
        ".fleet.setup.{}.{}",
        std::process::id(),
        random_hex(6)?
    ));
    DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .with_context(|| format!("creating private staging directory {}", staging.display()))?;

    let result = (|| {
        write_private_atomic(&staging.join(COOKIE_FILE), materials.cookie.as_bytes())?;
        write_private_atomic(
            &staging.join(CA_CERT_FILE),
            materials.ca_cert_pem.as_bytes(),
        )?;
        if let Some(ca_key) = &materials.ca_key_pem {
            write_private_atomic(&staging.join(CA_KEY_FILE), ca_key.as_bytes())?;
        }
        write_private_atomic(
            &staging.join(NODE_CERT_FILE),
            materials.node_cert_pem.as_bytes(),
        )?;
        write_private_atomic(
            &staging.join(NODE_KEY_FILE),
            materials.node_key_pem.as_bytes(),
        )?;
        let (tls, vm_args) = generated_runtime_files(data_dir, profile)?;
        write_private_atomic(&staging.join(TLS_OPTFILE), tls.as_bytes())?;
        write_private_atomic(&staging.join(VM_ARGS_FILE), vm_args.as_bytes())?;
        let profile_bytes = serde_json::to_vec_pretty(profile).context("encoding fleet profile")?;
        write_private_atomic(&staging.join(PROFILE_FILE), &profile_bytes)?;
        fs::rename(&staging, &final_dir)
            .with_context(|| format!("publishing fleet profile at {}", final_dir.display()))?;
        sync_parent(&final_dir)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

/// Return strict, privately-owned setup directories left by an interrupted create/join.
/// A name or entry that merely resembles our staging namespace but is not provably ours
/// is a hard error: lifecycle commands never recursively delete ambiguous data.
fn inspect_orphan_staging(data_dir: &Path) -> Result<Vec<PathBuf>> {
    let uid = unsafe { libc::geteuid() };
    let mut staging = Vec::new();
    let entries = match fs::read_dir(data_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(staging),
        Err(error) => return Err(error).context(format!("reading {}", data_dir.display())),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(STAGING_PREFIX) {
            continue;
        }
        if !strict_staging_name(name) {
            bail!(
                "{} uses Ouroboros's private setup namespace but has an invalid name; it was not removed. Inspect it manually before retrying",
                entry.path().display()
            );
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspecting interrupted setup {}", path.display()))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != uid
            || metadata.mode() & 0o777 != 0o700
        {
            bail!(
                "interrupted setup {} is not a same-user mode-0700 real directory (directory={}, uid={}, mode={:o}); it was not removed",
                path.display(),
                metadata.file_type().is_dir(),
                metadata.uid(),
                metadata.mode() & 0o777
            );
        }
        validate_staging_entries(&path, uid)?;
        staging.push(path);
    }
    staging.sort();
    Ok(staging)
}

fn strict_staging_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(STAGING_PREFIX) else {
        return false;
    };
    let Some((pid, random)) = rest.split_once('.') else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && random.len() == 12
        && random
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && !random.contains('.')
}

fn validate_staging_entries(path: &Path, uid: u32) -> Result<Vec<PathBuf>> {
    let known = known_fleet_files();
    let mut entries = Vec::new();
    for entry in fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let entry = entry?;
        let entry_path = entry.path();
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            anyhow!(
                "interrupted setup {} contains a non-UTF-8 entry; it was not removed",
                path.display()
            )
        })?;
        if !known.contains(name) && !is_generated_staging_temp(name, &known) {
            bail!(
                "interrupted setup {} contains unknown entry `{name}`; it was not removed",
                path.display()
            );
        }
        let metadata = fs::symlink_metadata(&entry_path).with_context(|| {
            format!("inspecting interrupted setup file {}", entry_path.display())
        })?;
        if !metadata.file_type().is_file()
            || metadata.uid() != uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            bail!(
                "interrupted setup file {} is unsafe (regular={}, uid={}, mode={:o}, links={}); it was not removed",
                entry_path.display(),
                metadata.file_type().is_file(),
                metadata.uid(),
                metadata.mode() & 0o777,
                metadata.nlink()
            );
        }
        entries.push(entry_path);
    }
    entries.sort();
    Ok(entries)
}

fn is_generated_staging_temp(name: &str, known: &BTreeSet<&'static str>) -> bool {
    known.iter().any(|base| {
        let prefix = format!(".{base}.");
        let Some(rest) = name
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(".tmp"))
        else {
            return false;
        };
        let Some((pid, random)) = rest.split_once('.') else {
            return false;
        };
        !pid.is_empty()
            && pid.bytes().all(|byte| byte.is_ascii_digit())
            && random.len() == 12
            && random
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && !random.contains('.')
    })
}

fn recover_orphan_staging(data_dir: &Path) -> Result<usize> {
    let staging = inspect_orphan_staging(data_dir)?;
    let uid = unsafe { libc::geteuid() };
    for path in &staging {
        // Revalidate while holding the lifecycle lock, then truncate each unique private
        // inode before unlinking it. This is best-effort media hygiene; encrypted disks
        // remain the correct protection against physical recovery.
        for entry in validate_staging_entries(path, uid)? {
            let expected = fs::symlink_metadata(&entry)?;
            let file = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&entry)
                .with_context(|| format!("opening interrupted setup file {}", entry.display()))?;
            let opened = file.metadata()?;
            if opened.dev() != expected.dev()
                || opened.ino() != expected.ino()
                || opened.nlink() != 1
            {
                bail!(
                    "interrupted setup file {} changed during recovery; it was not removed",
                    entry.display()
                );
            }
            file.set_len(0)?;
            file.sync_all()?;
            let current = fs::symlink_metadata(&entry)?;
            if current.dev() != opened.dev() || current.ino() != opened.ino() {
                bail!(
                    "interrupted setup file {} was replaced during recovery; it was not removed",
                    entry.display()
                );
            }
            fs::remove_file(&entry)
                .with_context(|| format!("removing interrupted setup file {}", entry.display()))?;
        }
        fs::remove_dir(path)
            .with_context(|| format!("removing interrupted setup directory {}", path.display()))?;
        sync_parent(path)?;
    }
    Ok(staging.len())
}

fn write_profile(data_dir: &Path, profile: &Profile) -> Result<()> {
    validate_profile(profile)?;
    let bytes = serde_json::to_vec_pretty(profile).context("encoding fleet profile")?;
    write_private_atomic(&profile_path(data_dir), &bytes)
}

fn generated_runtime_files(data_dir: &Path, profile: &Profile) -> Result<(String, String)> {
    if !data_dir.is_absolute() {
        bail!(
            "fleet data directory must be absolute, got {}",
            data_dir.display()
        );
    }
    let root = fleet_dir(data_dir);
    let cert = erl_string(&root.join(NODE_CERT_FILE))?;
    let key = erl_string(&root.join(NODE_KEY_FILE))?;
    let ca = erl_string(&root.join(CA_CERT_FILE))?;
    let optfile = erl_string(&root.join(TLS_OPTFILE))?;
    let bind_address = resolve_fleet_ipv4(&profile.host).with_context(|| {
        format!(
            "resolving the private IPv4 interface advertised by {}",
            profile.node
        )
    })?;
    let [a, b, c, d] = bind_address.octets();
    let tls = format!(
        "[\n  {{server, [{{certfile, \"{cert}\"}}, {{keyfile, \"{key}\"}}, {{cacertfile, \"{ca}\"}}, {{verify, verify_peer}}, {{fail_if_no_peer_cert, true}}, {{secure_renegotiate, true}}, {{reuse_sessions, false}}, {{session_tickets, disabled}}]}},\n  {{client, [{{certfile, \"{cert}\"}}, {{keyfile, \"{key}\"}}, {{cacertfile, \"{ca}\"}}, {{verify, verify_peer}}, {{secure_renegotiate, true}}, {{reuse_sessions, false}}, {{session_tickets, disabled}}]}}\n].\n"
    );
    let vm_args = format!(
        "## Generated by `ouro fleet`; safe to inspect (contains paths, never secrets).\n-proto_dist inet_tls\n-ssl_dist_optfile \"{optfile}\"\n-kernel inet_dist_use_interface {{{a},{b},{c},{d}}}\n-kernel inet_dist_listen_min {} inet_dist_listen_max {}\n",
        profile.dist_port_min, profile.dist_port_max
    );
    Ok((tls, vm_args))
}

/// The mutual-TLS policy the Ouroboros before this reduction generated.
///
/// Nothing emits this string; it exists so a profile written by that build gets a refusal
/// that names the repair instead of one that sends its operator round a loop. It is the
/// current policy plus a `verify_fun` in `Ouroboros.Cluster.Revocations`, the module that
/// went with the revocation authority.
fn previous_generated_tls(data_dir: &Path) -> Result<String> {
    let root = fleet_dir(data_dir);
    let cert = erl_string(&root.join(NODE_CERT_FILE))?;
    let key = erl_string(&root.join(NODE_KEY_FILE))?;
    let ca = erl_string(&root.join(CA_CERT_FILE))?;
    let policy = erl_string(&root)?;
    Ok(format!(
        "[\n  {{server, [{{certfile, \"{cert}\"}}, {{keyfile, \"{key}\"}}, {{cacertfile, \"{ca}\"}}, {{verify, verify_peer}}, {{fail_if_no_peer_cert, true}}, {{secure_renegotiate, true}}, {{reuse_sessions, false}}, {{session_tickets, disabled}}, {{verify_fun, {{fun 'Elixir.Ouroboros.Cluster.Revocations':verify/3, \"{policy}\"}}}}]}},\n  {{client, [{{certfile, \"{cert}\"}}, {{keyfile, \"{key}\"}}, {{cacertfile, \"{ca}\"}}, {{verify, verify_peer}}, {{secure_renegotiate, true}}, {{reuse_sessions, false}}, {{session_tickets, disabled}}, {{verify_fun, {{fun 'Elixir.Ouroboros.Cluster.Revocations':verify/3, \"{policy}\"}}}}]}}\n].\n"
    ))
}

fn new_fleet_materials(profile: &Profile, local: &Member) -> Result<Materials> {
    let year = current_utc_year()?;
    let mut ca_params = CertificateParams::default();
    ca_params.not_before = date_time_ymd(year - 1, 1, 1);
    ca_params.not_after = date_time_ymd(year + 10, 1, 1);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(
        DnType::CommonName,
        format!("Ouroboros fleet {} CA", profile.fleet_id),
    );
    let ca_key = KeyPair::generate().context("generating the fleet CA key")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("generating the fleet CA certificate")?;
    let ca_cert_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();
    let (node_cert_pem, node_key_pem) = signed_node_with(local, &ca_cert, &ca_key)?;
    Ok(Materials {
        ca_cert_pem,
        ca_key_pem: Some(ca_key_pem),
        node_cert_pem,
        node_key_pem,
        cookie: random_hex(32)?,
    })
}

/// Mint this machine's leaf under a CA that already exists.
///
/// This is the same signing step `new_fleet_materials` performs for the first machine's
/// own leaf, against a CA read out of a copied fleet directory instead of one just
/// generated. `from_ca_cert_pem` recovers only what signing needs — the CA's subject name
/// and its subject key identifier — so the issued leaf carries the copied CA's issuer name
/// and authority key id and verifies against the copied CA bytes, which are what gets
/// installed. `ca_key_pem` is deliberately `None`: this machine gets the CA certificate,
/// never the CA key.
fn joined_fleet_materials(local: &Member, source: &SourceFleet) -> Result<Materials> {
    let ca_params = CertificateParams::from_ca_cert_pem(&source.ca_cert_pem)
        .context("reading the copied fleet CA certificate")?;
    let ca_key =
        KeyPair::from_pem(&source.ca_key_pem).context("reading the copied fleet CA key")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("binding the copied fleet CA certificate to its key for signing")?;
    let (node_cert_pem, node_key_pem) = signed_node_with(local, &ca_cert, &ca_key)?;
    Ok(Materials {
        ca_cert_pem: source.ca_cert_pem.clone(),
        ca_key_pem: None,
        node_cert_pem,
        node_key_pem,
        cookie: source.cookie.to_string(),
    })
}

fn signed_node_with(
    member: &Member,
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> Result<(String, String)> {
    let year = current_utc_year()?;
    let mut params = CertificateParams::new(vec![member.host.clone()])
        .context("using the machine address as a certificate name")?;
    params.not_before = date_time_ymd(year - 1, 1, 1);
    params.not_after = date_time_ymd(year + 5, 1, 1);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, member.node.clone());
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().context("generating a node TLS key")?;
    let cert = params
        .signed_by(&key, ca_cert, ca_key)
        .context("signing the node TLS certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn validate_profile(profile: &Profile) -> Result<()> {
    if profile.schema != PROFILE_SCHEMA {
        bail!(
            "fleet profile schema {} is not supported by this ouro (supports {})",
            profile.schema,
            PROFILE_SCHEMA
        );
    }
    if profile.fleet_id.len() != 24 || !profile.fleet_id.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("fleet profile has an invalid fleet id");
    }
    validate_fleet_name(&profile.name)?;
    validate_machine(&profile.machine)?;
    validate_host(&profile.host)?;
    if profile.node != member(&profile.machine, &profile.host).node {
        bail!("fleet profile node does not match its machine name and host");
    }
    if profile.role != "core" {
        bail!("fleet profile role must be `core`, got `{}`", profile.role);
    }
    if profile.members.is_empty() || !profile.members.iter().any(|m| m.node == profile.node) {
        bail!("fleet profile must include this machine in its member list");
    }
    if profile.roster_revision == 0 {
        bail!("fleet profile roster revision must be positive");
    }
    let mut nodes = BTreeSet::new();
    let mut machines = BTreeSet::new();
    for member in &profile.members {
        validate_machine(&member.machine)?;
        validate_host(&member.host)?;
        if member.node != self::member(&member.machine, &member.host).node {
            bail!(
                "fleet member {} has a node that does not match its name and host",
                member.machine
            );
        }
        if !nodes.insert(&member.node) {
            bail!("fleet profile repeats node {}", member.node);
        }
        if !machines.insert(&member.machine) {
            bail!("fleet profile repeats machine {}", member.machine);
        }
    }
    let mut removed_nodes = BTreeSet::new();
    for removed in &profile.tombstones {
        validate_machine(&removed.machine)?;
        validate_host(&removed.host)?;
        if removed.node != self::member(&removed.machine, &removed.host).node {
            bail!(
                "fleet tombstone {} has a node that does not match its name and host",
                removed.machine
            );
        }
        if removed.node == profile.node {
            bail!("fleet profile cannot tombstone the machine it belongs to");
        }
        if nodes.contains(&removed.node) || machines.contains(&removed.machine) {
            bail!(
                "fleet roster marks machine {} both active and removed",
                removed.machine
            );
        }
        if !removed_nodes.insert(&removed.node) {
            bail!("fleet roster repeats removed node {}", removed.node);
        }
    }
    validate_port(profile.gateway_port, "gateway port")?;
    validate_port(profile.epmd_port, "EPMD port")?;
    if profile.epmd_port == 4369 {
        bail!(
            "fleet profile uses host-global EPMD port 4369, which cannot prove a private listener. Rebuild/rejoin this fleet with a current Ouroboros release to get a fleet-specific EPMD port"
        );
    }
    if profile.epmd_port == profile.gateway_port {
        bail!("fleet EPMD port overlaps the local gateway port");
    }
    validate_port(profile.dist_port_min, "distribution port minimum")?;
    validate_port(profile.dist_port_max, "distribution port maximum")?;
    if profile.dist_port_min > profile.dist_port_max {
        bail!("distribution port minimum exceeds its maximum");
    }
    if (profile.dist_port_min..=profile.dist_port_max).contains(&profile.epmd_port) {
        bail!("fleet EPMD port overlaps the TLS distribution listener range");
    }
    if (profile.dist_port_min..=profile.dist_port_max).contains(&profile.gateway_port) {
        bail!("local gateway port overlaps the TLS distribution listener range");
    }
    Ok(())
}

fn validate_materials(data_dir: &Path, require_ca_key: bool) -> Result<()> {
    let root = fleet_dir(data_dir);
    for (name, description) in [
        (PROFILE_FILE, "fleet profile"),
        (COOKIE_FILE, "fleet cookie"),
        (CA_CERT_FILE, "fleet CA certificate"),
        (NODE_CERT_FILE, "node certificate"),
        (NODE_KEY_FILE, "node key"),
        (TLS_OPTFILE, "TLS option file"),
        (VM_ARGS_FILE, "VM arguments"),
    ] {
        ensure_private_file(&root.join(name), description)?;
    }
    if require_ca_key || root.join(CA_KEY_FILE).try_exists()? {
        ensure_private_file(&root.join(CA_KEY_FILE), "fleet CA key")?;
    }
    let profile = load(data_dir)?
        .ok_or_else(|| anyhow!("fleet profile disappeared while validating credentials"))?;
    let cookie = Zeroizing::new(read_private(&root.join(COOKIE_FILE), "fleet cookie")?);
    validate_cookie(&cookie, &root.join(COOKIE_FILE).display().to_string())?;
    let ca_cert = read_private(&root.join(CA_CERT_FILE), "fleet CA certificate")?;
    let node_cert = read_private(&root.join(NODE_CERT_FILE), "node certificate")?;
    let node_key = Zeroizing::new(read_private(&root.join(NODE_KEY_FILE), "node key")?);
    let ca_key = if root.join(CA_KEY_FILE).try_exists()? {
        Some(Zeroizing::new(read_private(
            &root.join(CA_KEY_FILE),
            "fleet CA key",
        )?))
    } else {
        None
    };
    let local = member(&profile.machine, &profile.host);
    validate_tls_identity(
        &local,
        &ca_cert,
        &node_cert,
        &node_key,
        ca_key.as_deref().map(String::as_str),
        "installed fleet credentials",
    )?;
    let actual_tls = read_private(&root.join(TLS_OPTFILE), "TLS option file")?;
    let actual_vm_args = read_private(&root.join(VM_ARGS_FILE), "VM arguments")?;
    let (expected_tls, expected_vm_args) = generated_runtime_files(data_dir, &profile)?;
    if actual_tls != expected_tls {
        // A file that is exactly the policy the previous build generated is not a
        // weakened policy, and "restore from a trusted backup" is a loop for it: the
        // trusted backup is that same file.
        if actual_tls == previous_generated_tls(data_dir)? {
            bail!(
                "{} is the strict generated mutual-TLS policy of an older Ouroboros: it routes verification through `Ouroboros.Cluster.Revocations`, a module this build does not have. Rewrite it from this profile with `ouro fleet create --regenerate` on this stopped machine, which keeps this fleet id, CA, cookie and roster",
                root.join(TLS_OPTFILE).display()
            );
        }
        bail!(
            "{} does not match the strict generated mutual-TLS policy for this profile; startup is refused. Rewrite it from this profile with `ouro fleet create --regenerate`, or restore this file from a trusted backup",
            root.join(TLS_OPTFILE).display()
        );
    }
    if actual_vm_args.as_bytes() != expected_vm_args.as_bytes() {
        bail!(
            "{} does not match the generated TLS/port policy for this profile; startup is refused. Rewrite it from this profile with `ouro fleet create --regenerate`, or restore this file from a trusted backup",
            root.join(VM_ARGS_FILE).display()
        );
    }
    Ok(())
}

/// Parse and cryptographically bind every TLS material to the profile identity before
/// BEAM sees it. Parsing a PEM header is not enough: the leaf must be current, carry the
/// expected node/host identity, match its private key, and verify under the included CA.
fn validate_tls_identity(
    member: &Member,
    ca_cert_pem: &str,
    node_cert_pem: &str,
    node_key_pem: &str,
    ca_key_pem: Option<&str>,
    description: &str,
) -> Result<()> {
    let (ca_remaining, ca_pem) = parse_x509_pem(ca_cert_pem.as_bytes())
        .map_err(|_| anyhow!("{description} CA certificate is not valid PEM"))?;
    if ca_pem.label != "CERTIFICATE" || !ca_remaining.iter().all(u8::is_ascii_whitespace) {
        bail!("{description} CA certificate must contain exactly one certificate PEM block");
    }
    let ca = ca_pem
        .parse_x509()
        .map_err(|_| anyhow!("{description} CA certificate is not valid X.509"))?;

    let (node_remaining, node_pem) = parse_x509_pem(node_cert_pem.as_bytes())
        .map_err(|_| anyhow!("{description} node certificate is not valid PEM"))?;
    if node_pem.label != "CERTIFICATE" || !node_remaining.iter().all(u8::is_ascii_whitespace) {
        bail!("{description} node certificate must contain exactly one certificate PEM block");
    }
    let node = node_pem
        .parse_x509()
        .map_err(|_| anyhow!("{description} node certificate is not valid X.509"))?;

    if !ca.validity().is_valid() {
        bail!("{description} CA certificate is not currently valid");
    }
    let ca_validity_days = (ca.validity().not_after - ca.validity().not_before)
        .ok_or_else(|| anyhow!("{description} CA certificate validity cannot be represented"))?
        .whole_days();
    if !(1..=MAX_CA_VALIDITY_DAYS).contains(&ca_validity_days) {
        bail!(
            "{description} CA certificate validity is unreasonably long; rebuild the fleet with a current Ouroboros release"
        );
    }
    if ca.subject() != ca.issuer() {
        bail!("{description} CA certificate is not self-issued");
    }
    let ca_constraints = ca
        .basic_constraints()
        .map_err(|_| anyhow!("{description} CA certificate has invalid basic constraints"))?
        .ok_or_else(|| anyhow!("{description} CA certificate is missing basic constraints"))?;
    if !ca_constraints.value.ca {
        bail!("{description} CA certificate is not authorized to sign certificates");
    }
    let ca_usage = ca
        .key_usage()
        .map_err(|_| anyhow!("{description} CA certificate has invalid key usage"))?
        .ok_or_else(|| anyhow!("{description} CA certificate is missing key usage"))?;
    if !ca_usage.value.key_cert_sign() {
        bail!("{description} CA certificate cannot sign node certificates");
    }
    ca.verify_signature(None)
        .map_err(|_| anyhow!("{description} CA certificate self-signature is invalid"))?;

    if !node.validity().is_valid() {
        bail!("{description} node certificate is not currently valid");
    }
    let node_validity_days = (node.validity().not_after - node.validity().not_before)
        .ok_or_else(|| anyhow!("{description} node certificate validity cannot be represented"))?
        .whole_days();
    if !(1..=MAX_NODE_VALIDITY_DAYS).contains(&node_validity_days) {
        bail!(
            "{description} node certificate validity is unreasonably long; ask the fleet owner for a fresh invitation"
        );
    }
    if node.validity().not_after > ca.validity().not_after {
        bail!("{description} node certificate outlives its fleet CA certificate");
    }
    if node.issuer() != ca.subject() {
        bail!("{description} node certificate issuer does not match the included CA");
    }
    node.verify_signature(Some(&ca.tbs_certificate.subject_pki))
        .map_err(|_| anyhow!("{description} node certificate is not signed by the included CA"))?;
    if node.is_ca() {
        bail!("{description} node certificate is incorrectly marked as a CA");
    }

    let node_usage = node
        .key_usage()
        .map_err(|_| anyhow!("{description} node certificate has invalid key usage"))?
        .ok_or_else(|| anyhow!("{description} node certificate is missing key usage"))?;
    if !node_usage.value.digital_signature() {
        bail!("{description} node certificate cannot authenticate TLS handshakes");
    }
    let extended = node
        .extended_key_usage()
        .map_err(|_| anyhow!("{description} node certificate has invalid extended key usage"))?
        .ok_or_else(|| anyhow!("{description} node certificate is missing extended key usage"))?;
    if !extended.value.server_auth || !extended.value.client_auth {
        bail!(
            "{description} node certificate must allow both TLS server and client authentication"
        );
    }

    let mut common_names = node.subject().iter_common_name();
    let common_name = common_names
        .next()
        .ok_or_else(|| anyhow!("{description} node certificate is missing its node name"))?
        .as_str()
        .map_err(|_| anyhow!("{description} node certificate has an unreadable node name"))?;
    if common_name != member.node || common_names.next().is_some() {
        bail!(
            "{description} node certificate identity does not match machine `{}`",
            member.machine
        );
    }

    let alternative_names = node
        .subject_alternative_name()
        .map_err(|_| anyhow!("{description} node certificate has invalid subject names"))?
        .ok_or_else(|| anyhow!("{description} node certificate is missing its machine address"))?;
    let host_matches = match member.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => alternative_names.value.general_names.iter().any(|name| {
            matches!(name, GeneralName::IPAddress(bytes) if *bytes == address.octets())
        }),
        Ok(IpAddr::V6(_)) => false,
        Err(_) => alternative_names.value.general_names.iter().any(
            |name| matches!(name, GeneralName::DNSName(host) if host.eq_ignore_ascii_case(&member.host)),
        ),
    };
    if !host_matches {
        bail!(
            "{description} node certificate address does not match machine `{}`",
            member.machine
        );
    }

    let node_key = KeyPair::from_pem(node_key_pem)
        .with_context(|| format!("{description} node private key is invalid"))?;
    if node_key.public_key_der() != node.tbs_certificate.subject_pki.raw {
        bail!("{description} node private key does not match its certificate");
    }
    if let Some(ca_key_pem) = ca_key_pem {
        let ca_key = KeyPair::from_pem(ca_key_pem)
            .with_context(|| format!("{description} CA private key is invalid"))?;
        if ca_key.public_key_der() != ca.tbs_certificate.subject_pki.raw {
            bail!("{description} CA private key does not match its certificate");
        }
    }
    Ok(())
}

fn validate_cookie(cookie: &str, description: &str) -> Result<()> {
    if cookie.len() != 64
        || !cookie
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!(
            "{description} must contain exactly 64 lowercase hexadecimal characters with no whitespace or newline"
        );
    }
    Ok(())
}

pub fn validate_machine(machine: &str) -> Result<()> {
    let valid = !machine.is_empty()
        && machine.len() <= 40
        && machine
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        && machine
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && machine
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric());
    if !valid {
        bail!(
            "machine name `{machine}` must be 1–40 letters, numbers, or hyphens, starting and ending with a letter or number (example: studio-mini)"
        );
    }
    Ok(())
}

fn local_hostname() -> Result<String> {
    let mut buffer = [0 as libc::c_char; 256];
    // SAFETY: `buffer` is writable for the exact length supplied. A final zero is forced
    // in case a platform truncates without terminating.
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr(), buffer.len()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("detecting this machine's hostname");
    }
    buffer[buffer.len() - 1] = 0;
    // SAFETY: `buffer` is terminated above and remains live for this conversion.
    let hostname = unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .trim()
        .to_string();
    if hostname.is_empty() {
        bail!("the operating system returned a blank hostname; pass --host explicitly");
    }
    Ok(hostname)
}

pub fn machine_from_host(host: &str) -> Result<String> {
    let source = if host.parse::<IpAddr>().is_ok() {
        host.to_string()
    } else {
        host.split('.').next().unwrap_or(host).to_string()
    };
    let mut machine = String::new();
    let mut previous_hyphen = false;
    for character in source.chars() {
        if machine.len() >= 40 {
            break;
        }
        let character = character.to_ascii_lowercase();
        if character.is_ascii_alphanumeric() {
            machine.push(character);
            previous_hyphen = false;
        } else if !previous_hyphen && !machine.is_empty() {
            machine.push('-');
            previous_hyphen = true;
        }
    }
    while machine.ends_with('-') {
        machine.pop();
    }
    validate_machine(&machine).with_context(|| {
        format!("deriving a friendly machine name from host `{host}`; pass --machine explicitly")
    })?;
    Ok(machine)
}

fn validate_fleet_name(name: &str) -> Result<()> {
    if name.trim().is_empty()
        || name.chars().count() > 60
        || name.chars().any(|character| character.is_control())
    {
        bail!("fleet name must be 1–60 printable characters");
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
        bail!(
            "host `{host}` is an IPv6 address, but IPv6 fleet distribution is not yet supported. Use a Tailscale/private DNS name resolving to IPv4 or an IPv4 address"
        );
    }
    if host.contains(':') {
        bail!(
            "host `{host}` contains `:`, which cannot be used by the current IPv4 fleet distribution. Use a Tailscale/private DNS name resolving to IPv4 or an IPv4 address"
        );
    }
    if let Ok(IpAddr::V4(address)) = host.parse::<IpAddr>() {
        if address.is_unspecified()
            || address.is_multicast()
            || address.is_link_local()
            || address.octets() == [255, 255, 255, 255]
        {
            bail!(
                "host `{host}` is not a usable fleet machine address. Use a Tailscale/private DNS name resolving to IPv4 or a reachable private IPv4 address"
            );
        }
        if !private_fleet_ipv4(address) {
            bail!(
                "host `{host}` is a public IPv4 address. Ouroboros v1 refuses to expose EPMD/BEAM distribution on the public internet; use a Tailscale address, private DNS name, or private IPv4 address"
            );
        }
    }
    let valid = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && !host.ends_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !valid || host.contains('@') || host.contains(',') {
        bail!(
            "host `{host}` must be an IP address or DNS name every fleet machine can reach (a Tailscale/MagicDNS name is recommended)"
        );
    }
    Ok(())
}

fn ensure_usable_ipv4_resolution(host: &str) -> Result<()> {
    resolve_fleet_ipv4(host).map(|_| ())
}

/// Prove the advertised address can actually be bound on this machine before installing
/// credentials. This uses an ephemeral port and immediately drops it; the distribution
/// and gateway ports remain untouched. A split-DNS typo then fails at create/join rather
/// than turning a generated recovery service into a boot loop.
fn ensure_local_bind_address(host: &str) -> Result<Ipv4Addr> {
    let address = resolve_fleet_ipv4(host)?;
    let listener = TcpListener::bind((address, 0)).with_context(|| {
        format!(
            "advertised address {address} for host `{host}` is not assigned to a local interface. Use this machine's Tailscale/private IPv4 address or a private DNS name that resolves to it"
        )
    })?;
    drop(listener);
    Ok(address)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EpmdPortState {
    Available,
    CompatibleRunning,
}

/// Listener state used only after a durable ownership marker and its exact inherited
/// lock have been validated. Unlike the general preflight, this deliberately tolerates
/// an owned daemon that remains reachable on EPMD's mandatory loopback listener after
/// its recorded private address disappeared (for example after a Tailscale address
/// change). That narrow state is safe to retire, but is never inferred for an unowned
/// listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnedEpmdListenerState {
    Available,
    CompatibleRunning,
    LoopbackOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EpmdProbe {
    Absent,
    Compatible,
    Incompatible,
}

/// Starts the packaged EPMD as an explicitly owned foreground child when this profile's
/// port was absent. A private inherited flock is the positive ownership proof: an empty
/// compatible daemon without that exact lease is never marked or later killed.
pub(crate) fn ensure_owned_epmd_for_runtime(
    data_dir: &Path,
    epmd_program: &Path,
) -> Result<Option<EpmdRuntimeWatch>> {
    let Some(profile) = load(data_dir)? else {
        return Ok(None);
    };
    let address = resolve_fleet_ipv4(&profile.host)?;
    let marker_path = epmd_owner_path(data_dir);
    let lock_path = epmd_owner_lock_path(data_dir);

    if marker_path.try_exists()? {
        let owner = load_epmd_owner(data_dir)?
            .ok_or_else(|| anyhow!("{} exists but could not be read", marker_path.display()))?;
        validate_epmd_owner(&owner, &profile)?;
        let held = epmd_owner_lock_held(data_dir, &owner)?;
        let alive = runtime::pid_alive(owner.pid);
        let state = ensure_owned_epmd_listener_state(&owner)?;
        match (alive, held, state) {
            (true, true, OwnedEpmdListenerState::CompatibleRunning) if owner.address == address => {
                return Ok(Some(EpmdRuntimeWatch::new(None, owner.address, owner.port)));
            }
            (true, true, OwnedEpmdListenerState::CompatibleRunning)
            | (true, true, OwnedEpmdListenerState::LoopbackOnly) => {
                // The exact owned daemon still has its mandatory loopback endpoint, but
                // its recorded address differs from the profile's current resolution or
                // is no longer assigned. Retire that empty, positively owned daemon
                // before the ordinary preflight evaluates the newly resolved address.
                stop_owned_empty_epmd(data_dir, &owner, Some(epmd_program)).with_context(|| {
                    format!(
                        "retiring owned EPMD {}:{} before rebinding fleet host `{}` to {address}",
                        owner.address, owner.port, profile.host
                    )
                })?;
            }
            (_, false, OwnedEpmdListenerState::Available) => {
                // The inherited lease and listener are the process identity. A numeric
                // PID alone may name a reaped zombie or an unrelated process after
                // reboot, so it must not strand a safe stale-file cleanup.
                remove_epmd_owner_artifacts(data_dir)?;
            }
            (_, false, OwnedEpmdListenerState::CompatibleRunning)
            | (_, false, OwnedEpmdListenerState::LoopbackOnly) => {
                bail!(
                    "recorded fleet EPMD pid {} no longer holds its exact ownership lock, but a compatible replacement answers on port {}. Ouroboros cannot prove it owns that daemon, so it was preserved. Stop it through the process that started it, verify `ouro fleet doctor` reports the EPMD port available, then retry startup",
                    owner.pid,
                    profile.epmd_port
                );
            }
            _ => {
                bail!(
                    "fleet EPMD ownership is inconsistent (pid {} alive: {alive}, inherited lock held: {held}, port state: {state:?}). Nothing was started or killed; run `ouro fleet doctor` and inspect {}",
                    owner.pid,
                    marker_path.display()
                );
            }
        }
    } else if lock_path.try_exists()? {
        let held = epmd_unmarked_lock_held(data_dir)?;
        if held {
            bail!(
                "{} is still locked without a complete ownership marker. Ouroboros cannot prove which process inherited it; nothing was started or killed. Stop the interrupted packaged Ouroboros starter, then retry",
                lock_path.display()
            );
        }
        ensure_private_file(&lock_path, "EPMD ownership lock")?;
        fs::remove_file(&lock_path)
            .with_context(|| format!("removing stale {}", lock_path.display()))?;
        sync_parent(&lock_path)?;
    }

    let state = ensure_epmd_port_available(&profile.host, profile.epmd_port)?;
    if state == EpmdPortState::CompatibleRunning {
        // This daemon predated the launcher observation. It is safe to reuse after the
        // scope checks above, but it deliberately remains unowned and unkillable by leave.
        return Ok(Some(EpmdRuntimeWatch::new(
            None,
            address,
            profile.epmd_port,
        )));
    }

    start_owned_epmd(data_dir, &profile, address, epmd_program).map(Some)
}

fn start_owned_epmd(
    data_dir: &Path,
    profile: &Profile,
    address: Ipv4Addr,
    epmd_program: &Path,
) -> Result<EpmdRuntimeWatch> {
    let (epmd_program, executable) = validate_epmd_program(epmd_program)?;
    let lock_path = epmd_owner_lock_path(data_dir);
    let marker_path = epmd_owner_path(data_dir);
    let mut lock = Some(create_epmd_lock(&lock_path)?);
    let lock_metadata = lock
        .as_ref()
        .expect("the ownership lock was just created")
        .metadata()?;
    let lock_fd = lock
        .as_ref()
        .expect("the ownership lock was just created")
        .as_raw_fd();

    let mut command = Command::new(&epmd_program);
    command
        .args([
            "-address",
            &address.to_string(),
            "-port",
            &profile.epmd_port.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    inherit_epmd_lock_on_exec(&mut command, lock_fd);
    // SAFETY: fcntl and setsid are async-signal-safe and are the only pre-exec operations.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            drop(lock.take());
            remove_unlocked_epmd_lock(&lock_path)?;
            return Err(error).with_context(|| {
                format!(
                    "starting packaged EPMD {} on {}:{}",
                    epmd_program.display(),
                    address,
                    profile.epmd_port
                )
            });
        }
    };
    let pid = child.id() as i32;
    let deadline = Instant::now() + EPMD_START_DEADLINE;
    loop {
        if let Some(status) = child.try_wait()? {
            drop(lock.take());
            // Reaping the wrapper and observing the inherited flock disappear are not
            // one atomic event under load. Use the bounded cleanup path here too instead
            // of turning that short release window into a failed startup and stranded
            // ownership file.
            clean_failed_epmd_child(&mut child, &lock_path)?;
            bail!(
                "packaged EPMD exited before owning {}:{} ({status}); no ownership marker was written",
                address,
                profile.epmd_port
            );
        }
        match owned_epmd_ready(address, profile.epmd_port) {
            Ok(true) => break,
            Ok(false) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(false) => {
                drop(lock.take());
                clean_failed_epmd_child(&mut child, &lock_path)?;
                bail!(
                    "packaged EPMD pid {pid} did not publish the NAMES protocol on {}:{} within {} seconds; it was stopped and no ownership marker was written",
                    address,
                    profile.epmd_port,
                    EPMD_START_DEADLINE.as_secs()
                );
            }
            Err(error) => {
                drop(lock.take());
                clean_failed_epmd_child(&mut child, &lock_path)?;
                return Err(error).context("packaged EPMD listener validation failed");
            }
        }
    }

    // The parent deliberately releases its copy. The exact foreground epmd must still
    // hold the lock across exec before any durable ownership claim is published.
    drop(lock.take());
    if !epmd_lock_held(&lock_path, lock_metadata.dev(), lock_metadata.ino())? {
        clean_failed_epmd_child(&mut child, &lock_path)?;
        bail!(
            "packaged EPMD pid {pid} did not retain its inherited ownership lock across exec; it was stopped and will never be treated as owned"
        );
    }

    let owner = EpmdOwner {
        schema: EPMD_OWNER_SCHEMA,
        fleet_id: profile.fleet_id.clone(),
        host: profile.host.clone(),
        address,
        port: profile.epmd_port,
        pid,
        executable: epmd_program,
        executable_dev: executable.dev(),
        executable_ino: executable.ino(),
        lock_dev: lock_metadata.dev(),
        lock_ino: lock_metadata.ino(),
    };
    let bytes = serde_json::to_vec_pretty(&owner).context("encoding EPMD ownership marker")?;
    if let Err(error) = write_private_new(&marker_path, &bytes, "EPMD ownership marker") {
        clean_failed_epmd_child(&mut child, &lock_path)?;
        return Err(error).context(
            "packaged EPMD was stopped because its ownership marker could not be published",
        );
    }
    Ok(EpmdRuntimeWatch::new(
        Some(child),
        address,
        profile.epmd_port,
    ))
}

fn validate_epmd_program(path: &Path) -> Result<(PathBuf, fs::Metadata)> {
    if !path.is_absolute() {
        bail!("packaged EPMD path must be absolute: {}", path.display());
    }
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolving packaged EPMD {}", path.display()))?;
    let metadata = fs::symlink_metadata(&canonical)
        .with_context(|| format!("inspecting packaged EPMD {}", canonical.display()))?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file() || metadata.uid() != uid || metadata.mode() & 0o111 == 0 {
        bail!(
            "packaged EPMD {} must be an executable regular file owned by uid {uid}",
            canonical.display()
        );
    }
    Ok((canonical, metadata))
}

fn create_epmd_lock(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("creating EPMD ownership lock {}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if !try_lock_epmd_file(&file)? {
        bail!("new EPMD ownership lock was unexpectedly already held");
    }
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error())
            .context("making the launcher copy of the EPMD ownership lock close-on-exec");
    }
    file.sync_all()?;
    sync_parent(path)?;
    Ok(file)
}

fn inherit_epmd_lock_on_exec(command: &mut Command, fd: RawFd) {
    // The parent keeps this descriptor close-on-exec. Clearing the flag only in this
    // command's post-fork child prevents an unrelated concurrent spawn from retaining
    // the ownership lease.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags == -1 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn try_lock_epmd_file(file: &File) -> Result<bool> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error
        .raw_os_error()
        .is_some_and(|code| code == libc::EAGAIN || code == libc::EWOULDBLOCK)
    {
        Ok(false)
    } else {
        Err(error).context("checking the EPMD ownership lock")
    }
}

fn open_epmd_lock(path: &Path) -> Result<File> {
    ensure_private_file(path, "EPMD ownership lock")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening EPMD ownership lock {}", path.display()))?;
    let metadata = file.metadata()?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file() || metadata.uid() != uid || metadata.mode() & 0o777 != 0o600
    {
        bail!("EPMD ownership lock changed while it was being opened");
    }
    Ok(file)
}

fn epmd_lock_held(path: &Path, dev: u64, ino: u64) -> Result<bool> {
    let file = open_epmd_lock(path)?;
    let metadata = file.metadata()?;
    if metadata.dev() != dev || metadata.ino() != ino {
        bail!("EPMD ownership lock inode no longer matches its marker");
    }
    Ok(!try_lock_epmd_file(&file)?)
}

fn epmd_owner_lock_held(data_dir: &Path, owner: &EpmdOwner) -> Result<bool> {
    epmd_lock_held(
        &epmd_owner_lock_path(data_dir),
        owner.lock_dev,
        owner.lock_ino,
    )
}

fn epmd_unmarked_lock_held(data_dir: &Path) -> Result<bool> {
    let path = epmd_owner_lock_path(data_dir);
    let file = open_epmd_lock(&path)?;
    Ok(!try_lock_epmd_file(&file)?)
}

fn clean_failed_epmd_child(child: &mut Child, lock_path: &Path) -> Result<()> {
    if child.try_wait()?.is_none() {
        child
            .kill()
            .context("stopping an EPMD child whose ownership could not be established")?;
        let _ = child.wait();
    }

    let deadline = Instant::now() + EPMD_STOP_DEADLINE;
    loop {
        match try_remove_unlocked_epmd_lock(lock_path)? {
            true => return Ok(()),
            false if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            false => {
                bail!(
                    "{} remains held after the EPMD child was stopped; refusing to remove it",
                    lock_path.display()
                )
            }
        }
    }
}

fn remove_unlocked_epmd_lock(path: &Path) -> Result<()> {
    if try_remove_unlocked_epmd_lock(path)? {
        Ok(())
    } else {
        bail!(
            "{} remains held after the EPMD child was stopped; refusing to remove it",
            path.display()
        )
    }
}

fn try_remove_unlocked_epmd_lock(path: &Path) -> Result<bool> {
    if !path.try_exists()? {
        return Ok(true);
    }
    let file = open_epmd_lock(path)?;
    if !try_lock_epmd_file(&file)? {
        return Ok(false);
    }
    fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    sync_parent(path)?;
    Ok(true)
}

fn load_epmd_owner(data_dir: &Path) -> Result<Option<EpmdOwner>> {
    let path = epmd_owner_path(data_dir);
    if !path.try_exists()? {
        return Ok(None);
    }
    let bytes = read_private(&path, "EPMD ownership marker")?;
    let owner = serde_json::from_str(&bytes)
        .with_context(|| format!("decoding EPMD ownership marker {}", path.display()))?;
    Ok(Some(owner))
}

fn validate_epmd_owner(owner: &EpmdOwner, profile: &Profile) -> Result<()> {
    validate_epmd_owner_shape(owner)?;
    if owner.fleet_id != profile.fleet_id
        || owner.host != profile.host
        || owner.port != profile.epmd_port
    {
        bail!(
            "EPMD ownership marker does not exactly match this fleet/profile; nothing will be started or killed"
        );
    }
    Ok(())
}

fn validate_epmd_owner_shape(owner: &EpmdOwner) -> Result<()> {
    if owner.schema != EPMD_OWNER_SCHEMA
        || owner.fleet_id.len() != 24
        || owner.host.is_empty()
        || owner.port == 0
        || owner.pid <= 0
        || !owner.executable.is_absolute()
        || owner.executable_dev == 0
        || owner.executable_ino == 0
        || owner.lock_dev == 0
        || owner.lock_ino == 0
    {
        bail!("EPMD ownership marker has invalid or incomplete identity fields");
    }
    validate_host(&owner.host).context("validating EPMD ownership host")?;
    if !owner.address.is_loopback() && !private_fleet_ipv4(owner.address) {
        bail!("EPMD ownership address is not a permitted private or loopback IPv4 address");
    }
    Ok(())
}

fn validate_epmd_owner_executable(owner: &EpmdOwner) -> Result<()> {
    let metadata = fs::symlink_metadata(&owner.executable).with_context(|| {
        format!(
            "the packaged EPMD recorded by the ownership marker is unavailable at {}",
            owner.executable.display()
        )
    })?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.dev() != owner.executable_dev
        || metadata.ino() != owner.executable_ino
    {
        bail!(
            "the packaged EPMD at {} no longer matches the regular-file inode recorded by the ownership marker; nothing will be killed",
            owner.executable.display()
        );
    }
    Ok(())
}

fn epmd_ownership_status(data_dir: &Path, profile: &Profile) -> String {
    match load_epmd_owner(data_dir) {
        Ok(Some(owner)) => {
            let state = ensure_owned_epmd_listener_state(&owner);
            let valid = validate_epmd_owner(&owner, profile).is_ok();
            let held = epmd_owner_lock_held(data_dir, &owner).unwrap_or(false);
            let alive = runtime::pid_alive(owner.pid);
            match (valid, alive, held, state) {
                (true, true, true, Ok(OwnedEpmdListenerState::CompatibleRunning)) => format!(
                    "Ouro-owned pid {}; safely retired only when empty during leave",
                    owner.pid
                ),
                (true, true, true, Ok(OwnedEpmdListenerState::LoopbackOnly)) => format!(
                    "Ouro-owned pid {}; recorded address changed — next packaged restart or leave safely retires the empty daemon",
                    owner.pid
                ),
                _ => "uncertain ownership — run `ouro fleet doctor`; leave fails closed".into(),
            }
        }
        Ok(None) if epmd_owner_lock_path(data_dir).exists() => {
            "incomplete ownership lease — run `ouro fleet doctor`; leave fails closed".into()
        }
        Ok(None) => match ensure_epmd_port_available(&profile.host, profile.epmd_port) {
            Ok(EpmdPortState::Available) => {
                "not running; next packaged start will establish ownership".into()
            }
            Ok(EpmdPortState::CompatibleRunning) => {
                "external/unowned; leave retains the profile until its owner stops it".into()
            }
            Err(_) => "listener conflict — run `ouro fleet doctor`".into(),
        },
        Err(_) => "ownership marker unreadable — run `ouro fleet doctor`".into(),
    }
}

fn epmd_ownership_doctor_check(data_dir: &Path, profile: &Profile) -> Check {
    let marker = match load_epmd_owner(data_dir) {
        Ok(marker) => marker,
        Err(error) => {
            return problem(format!(
                "EPMD ownership marker cannot be trusted: {error:#}. Nothing will be killed and leave fails closed"
            ));
        }
    };
    let Some(owner) = marker else {
        let lock = epmd_owner_lock_path(data_dir);
        if lock.exists() {
            return match epmd_unmarked_lock_held(data_dir) {
                Ok(true) => problem(format!(
                    "{} is held without a complete ownership marker. Stop the interrupted packaged starter; nothing will be killed and leave fails closed",
                    lock.display()
                )),
                Ok(false) => warn(format!(
                    "{} is an unlocked interrupted ownership file; the next packaged start or leave can remove it safely",
                    lock.display()
                )),
                Err(error) => problem(format!(
                    "EPMD ownership lock cannot be trusted: {error:#}; leave fails closed"
                )),
            };
        }
        let state = match ensure_epmd_port_available(&profile.host, profile.epmd_port) {
            Ok(state) => state,
            Err(error) => {
                return problem(format!(
                    "EPMD ownership cannot be evaluated until the listener conflict is fixed: {error:#}"
                ));
            }
        };
        return match state {
            EpmdPortState::Available => ok(format!(
                "fleet-specific EPMD port {} is stopped; the next packaged start will establish a private inherited ownership lease",
                profile.epmd_port
            )),
            EpmdPortState::CompatibleRunning => warn(format!(
                "compatible EPMD {}:{} has no positive Ouroboros ownership lease. It may predate this fleet and will never be killed automatically; stop it through its owner and rerun doctor before `ouro fleet leave`, which retains the profile while it remains",
                profile.host,
                profile.epmd_port
            )),
        };
    };

    if let Err(error) = validate_epmd_owner(&owner, profile) {
        return problem(format!(
            "EPMD ownership marker does not match this profile: {error:#}; nothing will be killed and leave fails closed"
        ));
    }
    let held = match epmd_owner_lock_held(data_dir, &owner) {
        Ok(held) => held,
        Err(error) => {
            return problem(format!(
                "EPMD ownership lock cannot be verified: {error:#}; leave fails closed"
            ));
        }
    };
    let state = match ensure_owned_epmd_listener_state(&owner) {
        Ok(state) => state,
        Err(error) => {
            return problem(format!(
                "EPMD ownership cannot be evaluated until the listener conflict is fixed: {error:#}"
            ));
        }
    };
    let alive = runtime::pid_alive(owner.pid);
    match (alive, held, state) {
        (true, true, OwnedEpmdListenerState::CompatibleRunning) => ok(format!(
            "packaged EPMD pid {} owns {}:{} through the expected inherited private lock; leave will stop it only after all registered names are gone",
            owner.pid, owner.address, owner.port
        )),
        (true, true, OwnedEpmdListenerState::LoopbackOnly) => warn(format!(
            "packaged EPMD pid {} still owns loopback port {}, but its recorded private address {} is no longer reachable. The next packaged restart or leave can retire this empty daemon safely before rebinding; no unowned daemon will be signalled",
            owner.pid, owner.port, owner.address
        )),
        (_, false, OwnedEpmdListenerState::Available) => warn(format!(
            "stale EPMD ownership marker has no inherited lock or listener (recorded pid {} may be gone or reused); the next packaged start or leave can clear only those stale files safely",
            owner.pid
        )),
        _ => problem(format!(
            "EPMD ownership is inconsistent (pid {} alive: {alive}, inherited lock held: {held}, port state: {state:?}). Nothing will be killed and leave fails closed",
            owner.pid
        )),
    }
}

fn remove_epmd_owner_artifacts(data_dir: &Path) -> Result<()> {
    let marker = epmd_owner_path(data_dir);
    let lock = epmd_owner_lock_path(data_dir);
    let owner = load_epmd_owner(data_dir)?;
    let lock_file = if lock.try_exists()? {
        let file = open_epmd_lock(&lock)?;
        let metadata = file.metadata()?;
        if let Some(owner) = owner.as_ref() {
            if metadata.dev() != owner.lock_dev || metadata.ino() != owner.lock_ino {
                bail!(
                    "EPMD ownership lock inode changed before cleanup; no ownership artifact was removed"
                );
            }
        }
        if !try_lock_epmd_file(&file)? {
            bail!(
                "{} is still held; no ownership artifact was removed",
                lock.display()
            );
        }
        Some(file)
    } else {
        if owner.is_some() {
            bail!(
                "EPMD ownership marker exists without its exact lock; no ownership artifact was removed"
            );
        }
        None
    };

    if owner.is_some() {
        fs::remove_file(&marker).with_context(|| format!("removing {}", marker.display()))?;
    }
    if lock_file.is_some() {
        fs::remove_file(&lock).with_context(|| format!("removing {}", lock.display()))?;
    }
    if owner.is_some() || lock_file.is_some() {
        sync_parent(&marker)?;
    }
    drop(lock_file);
    Ok(())
}

fn ensure_epmd_port_available(host: &str, port: u16) -> Result<EpmdPortState> {
    let address = resolve_fleet_ipv4(host)?;
    ensure_epmd_address_port_available(address, port)
}

// Preflight may reserve sockets before a process starts. Readiness must only probe:
// binding here races our own child, either stealing its port or misreporting its
// newly bound socket as somebody else's conflict. Both listeners and the interface
// fence still have to pass before the launcher records ownership.
fn owned_epmd_ready(address: Ipv4Addr, port: u16) -> Result<bool> {
    let advertised = epmd_probe(address, port);
    let loopback = if address.is_loopback() {
        advertised
    } else {
        epmd_probe(Ipv4Addr::LOCALHOST, port)
    };
    if advertised == EpmdProbe::Incompatible || loopback == EpmdProbe::Incompatible {
        bail!("packaged EPMD port {port} accepts TCP but does not speak the documented NAMES protocol");
    }
    if advertised == EpmdProbe::Compatible && loopback == EpmdProbe::Compatible {
        ensure_epmd_not_exposed_on_other_interfaces(address, port)?;
        return Ok(true);
    }
    Ok(false)
}

fn ensure_owned_epmd_listener_state(owner: &EpmdOwner) -> Result<OwnedEpmdListenerState> {
    let recorded = epmd_probe(owner.address, owner.port);
    let loopback = if owner.address.is_loopback() {
        recorded
    } else {
        epmd_probe(Ipv4Addr::LOCALHOST, owner.port)
    };

    if recorded == EpmdProbe::Incompatible || loopback == EpmdProbe::Incompatible {
        bail!(
            "owned fleet EPMD port {} accepts TCP through a listener that does not speak the documented NAMES protocol. Nothing will be killed until the listener identity is repaired",
            owner.port
        );
    }

    match (recorded, loopback) {
        (EpmdProbe::Absent, EpmdProbe::Absent) => Ok(OwnedEpmdListenerState::Available),
        (EpmdProbe::Compatible, EpmdProbe::Compatible) => {
            ensure_epmd_not_exposed_on_other_interfaces(owner.address, owner.port)?;
            Ok(OwnedEpmdListenerState::CompatibleRunning)
        }
        (EpmdProbe::Absent, EpmdProbe::Compatible) => {
            // EPMD always retains loopback. With the exact inherited ownership lock,
            // this is the expected shape when the recorded private interface vanished.
            ensure_epmd_not_exposed_on_other_interfaces(owner.address, owner.port)?;
            Ok(OwnedEpmdListenerState::LoopbackOnly)
        }
        (EpmdProbe::Compatible, EpmdProbe::Absent) => bail!(
            "owned fleet EPMD answers on recorded address {}:{} but not on its mandatory loopback listener. Nothing will be killed because that is not a valid EPMD listener shape",
            owner.address,
            owner.port
        ),
        // Incompatible states are rejected above.
        (EpmdProbe::Incompatible, _) | (_, EpmdProbe::Incompatible) => unreachable!(),
    }
}

fn ensure_epmd_address_port_available(address: Ipv4Addr, port: u16) -> Result<EpmdPortState> {
    let mut addresses = vec![address];
    if address != Ipv4Addr::LOCALHOST {
        addresses.push(Ipv4Addr::LOCALHOST);
    }

    let probes = addresses
        .iter()
        .map(|address| epmd_probe(*address, port))
        .collect::<Vec<_>>();
    if probes.iter().all(|probe| *probe == EpmdProbe::Compatible) {
        ensure_epmd_not_exposed_on_other_interfaces(address, port)?;
        return Ok(EpmdPortState::CompatibleRunning);
    }
    if probes.contains(&EpmdProbe::Incompatible) {
        bail!(
            "fleet EPMD port {port} accepts TCP but does not speak the documented EPMD NAMES protocol. Stop that non-EPMD or incompatible listener, then retry"
        );
    }
    if probes.contains(&EpmdProbe::Compatible) {
        bail!(
            "a real EPMD answers on only part of the required fleet listener set for port {port} (advertised {address} plus loopback). Stop that EPMD and retry so Ouroboros can bind both safely"
        );
    }

    let mut listeners = Vec::with_capacity(addresses.len());
    for bind_address in addresses {
        let listener = TcpListener::bind((bind_address, port)).with_context(|| {
            format!(
                "fleet EPMD address {bind_address}:{port} is already used by a non-EPMD or incompatible listener. Stop the process holding that fleet-specific port, then retry; default EPMD 4369 is intentionally not used"
            )
        })?;
        listeners.push(listener);
    }
    drop(listeners);
    Ok(EpmdPortState::Available)
}

/// EPMD always listens on loopback in addition to `-address`. Prove that a compatible
/// incumbent does not also occupy every other local IPv4 interface (the observable
/// effect of a wildcard bind) before reusing it.
fn ensure_epmd_not_exposed_on_other_interfaces(advertised: Ipv4Addr, port: u16) -> Result<()> {
    for address in local_ipv4_interfaces()? {
        if address == advertised || address.is_loopback() || address.is_unspecified() {
            continue;
        }
        let listener = TcpListener::bind((address, port)).with_context(|| {
            format!(
                "compatible EPMD port {port} is also occupied on unrelated local interface {address}; Ouroboros cannot prove the daemon is restricted to advertised {advertised} plus loopback. Stop that EPMD and retry so the fleet does not reuse a wildcard listener"
            )
        })?;
        drop(listener);
    }
    Ok(())
}

fn local_ipv4_interfaces() -> Result<BTreeSet<Ipv4Addr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("enumerating local IPv4 interfaces for EPMD scope validation");
    }
    let mut addresses = BTreeSet::new();
    let mut current = head;
    while !current.is_null() {
        let interface = unsafe { &*current };
        let socket = interface.ifa_addr;
        if !socket.is_null() && unsafe { (*socket).sa_family as i32 } == libc::AF_INET {
            let ipv4 = unsafe { &*(socket.cast::<libc::sockaddr_in>()) };
            addresses.insert(Ipv4Addr::from(ipv4.sin_addr.s_addr.to_ne_bytes()));
        }
        current = interface.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    Ok(addresses)
}

/// The documented EPMD NAMES request is a length-prefixed byte 110. A genuine daemon
/// replies with its own port as a four-byte big-endian integer before any name lines.
fn epmd_responds(address: Ipv4Addr, port: u16) -> bool {
    epmd_probe(address, port) == EpmdProbe::Compatible
}

fn names_healthy(address: Ipv4Addr, port: u16) -> bool {
    let advertised = epmd_responds(address, port);
    let loopback = address.is_loopback() || epmd_responds(Ipv4Addr::LOCALHOST, port);
    advertised && loopback
}

fn epmd_probe(address: Ipv4Addr, port: u16) -> EpmdProbe {
    let socket = (address, port).into();
    let Ok(mut stream) = TcpStream::connect_timeout(&socket, Duration::from_millis(250)) else {
        return EpmdProbe::Absent;
    };
    let timeout = Some(Duration::from_millis(250));
    if stream.set_read_timeout(timeout).is_err()
        || stream.set_write_timeout(timeout).is_err()
        || stream.write_all(&[0, 1, 110]).is_err()
    {
        return EpmdProbe::Incompatible;
    }
    let mut response = [0_u8; 4];
    if stream.read_exact(&mut response).is_ok() && u32::from_be_bytes(response) == u32::from(port) {
        EpmdProbe::Compatible
    } else {
        EpmdProbe::Incompatible
    }
}

/// This machine's ephemeral (dynamic) local port range, when the operating system will
/// say. A pinned fleet port inside it can be handed out by the kernel as the source
/// port of any outgoing connection; the runtime's later bind then loses `eaddrinuse`
/// with no listener anywhere in sight. `None` on platforms that do not expose it.
fn local_ephemeral_port_range() -> Option<(u16, u16)> {
    #[cfg(target_os = "linux")]
    {
        let text = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
        let mut parts = text.split_whitespace();
        let low = parts.next()?.parse().ok()?;
        let high = parts.next()?.parse().ok()?;
        Some((low, high))
    }
    #[cfg(target_os = "macos")]
    {
        fn sysctl_port(name: &str) -> Option<u16> {
            let name = std::ffi::CString::new(name).ok()?;
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>();
            // SAFETY: the buffer is a live c_int and `len` names its exact size.
            let rc = unsafe {
                libc::sysctlbyname(
                    name.as_ptr(),
                    (&raw mut value).cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc != 0 {
                return None;
            }
            u16::try_from(value).ok()
        }
        Some((
            sysctl_port("net.inet.ip.portrange.first")?,
            sysctl_port("net.inet.ip.portrange.last")?,
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// One warning per pinned port family that the kernel could also hand to an outgoing
/// connection. Pure over the profile and an observed range so the exposure is testable
/// without a particular kernel's sysctls.
fn ephemeral_overlap_warnings(profile: &Profile, range: (u16, u16)) -> Vec<String> {
    let (low, high) = range;
    let inside = |port: u16| (low..=high).contains(&port);
    let advice = format!(
        "the kernel can hand that number to any outgoing connection, and a runtime start \
         then fails `eaddrinuse` with no visible listener. The gateway retries its bind \
         briefly; to remove the collision entirely, reserve the port from ephemeral use \
         (Linux: net.ipv4.ip_local_reserved_ports) or re-form the fleet with ports below {low}"
    );
    let mut warnings = Vec::new();
    if inside(profile.gateway_port) {
        warnings.push(format!(
            "pinned local gateway port {} is inside this machine's ephemeral port range {low}-{high}: {advice}",
            profile.gateway_port
        ));
    }
    if inside(profile.epmd_port) {
        warnings.push(format!(
            "pinned fleet EPMD port {} is inside this machine's ephemeral port range {low}-{high}: {advice}",
            profile.epmd_port
        ));
    }
    if profile.dist_port_min <= high && profile.dist_port_max >= low {
        warnings.push(format!(
            "pinned TLS distribution range {}-{} overlaps this machine's ephemeral port range {low}-{high}: {advice}",
            profile.dist_port_min, profile.dist_port_max
        ));
    }
    warnings
}

/// Reserve every local listener policy before publishing credentials. The sockets are
/// intentionally released immediately; holding the lifecycle lock prevents another
/// Ouroboros starter for this data directory from winning the gap.
fn ensure_runtime_ports_available(profile: &Profile) -> Result<()> {
    validate_profile(profile)?;
    let gateway = TcpListener::bind((Ipv4Addr::LOCALHOST, profile.gateway_port)).with_context(
        || {
            format!(
                "local gateway port 127.0.0.1:{} is already in use. Stop the process using it, or choose a different `--gateway-port`, then retry; no fleet credential was installed",
                profile.gateway_port
            )
        },
    )?;
    drop(gateway);

    let address = resolve_fleet_ipv4(&profile.host)?;
    let mut last_error = None;
    for port in profile.dist_port_min..=profile.dist_port_max {
        match TcpListener::bind((address, port)) {
            Ok(listener) => {
                drop(listener);
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }
    let range = if profile.dist_port_min == profile.dist_port_max {
        profile.dist_port_min.to_string()
    } else {
        format!("{}-{}", profile.dist_port_min, profile.dist_port_max)
    };
    bail!(
        "TLS distribution port {range} is unavailable on advertised address {address}{}. Stop the process using that port, or choose a free `--dist-port`, then retry; no fleet credential was installed",
        last_error
            .map(|error| format!(": {error}"))
            .unwrap_or_default()
    )
}

/// Resolve the advertised name to exactly one address for both EPMD and distribution.
/// Sorting makes multi-A-record selection independent of resolver answer order. Public
/// addresses are deliberately not candidates: v1 has no acknowledgement mode for
/// exposing the Erlang distribution control plane outside a private overlay/network.
fn resolve_fleet_ipv4(host: &str) -> Result<Ipv4Addr> {
    if let Ok(IpAddr::V4(address)) = host.parse::<IpAddr>() {
        if !usable_ipv4(address) {
            bail!(
                "host `{host}` is not a usable IPv4 address; use a Tailscale/private DNS name or reachable private IPv4 address"
            );
        }
        if !private_fleet_ipv4(address) {
            bail!(
                "host `{host}` is public IPv4 address {address}. Ouroboros v1 refuses a public EPMD/BEAM listener; use Tailscale, private DNS, or a private IPv4 address"
            );
        }
        return Ok(address);
    }
    let resolved = (host, 0)
        .to_socket_addrs()
        .with_context(|| format!("resolving fleet host `{host}`"))?
        .filter_map(|address| match address.ip() {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        })
        .collect::<Vec<_>>();
    select_fleet_ipv4(host, resolved)
}

fn select_fleet_ipv4(host: &str, resolved: Vec<Ipv4Addr>) -> Result<Ipv4Addr> {
    let mut resolved = resolved
        .into_iter()
        .filter(|address| usable_ipv4(*address))
        .collect::<Vec<_>>();
    resolved.sort_unstable_by_key(|address| address.octets());
    resolved.dedup();
    if resolved.is_empty() {
        bail!(
            "host `{host}` does not resolve to a usable IPv4 address. Ouroboros v1 uses IPv4 BEAM distribution; use a Tailscale/private DNS name with an A record or a reachable IPv4 address"
        );
    }
    match resolved.as_slice() {
        [address] if private_fleet_ipv4(*address) => Ok(*address),
        [address] => Err(anyhow!(
            "host `{host}` resolves to public IPv4 address {address}. Ouroboros v1 refuses a public EPMD/BEAM listener; use Tailscale/private DNS or a private IPv4 address"
        )),
        addresses => bail!(
            "host `{host}` resolves to {} usable IPv4 addresses ({}). Ouroboros v1 requires exactly one private canonical address so every peer dials the same interface and never falls back to a public A record; use a single-record Tailscale/private DNS name or an explicit private IPv4 address",
            addresses.len(),
            addresses
                .iter()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn usable_ipv4(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_link_local()
        && address.octets() != [255, 255, 255, 255]
}

fn private_fleet_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, _, _] = address.octets();
    usable_ipv4(address)
        && (address.is_private()
            || address.is_loopback()
            // RFC 6598 shared address space is used by Tailscale's default tailnet
            // addresses and is private to that overlay even though is_private() is false.
            || (first == 100 && (64..=127).contains(&second)))
}

pub fn host_is_local_only(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || resolve_fleet_ipv4(host).is_ok_and(|address| address.is_loopback())
}

fn lock_live_fleet_update(data_dir: &Path, command: &str) -> Result<runtime::SpawnLock> {
    let lock = runtime::acquire_spawn_lock(data_dir).map_err(|error| {
        anyhow!(
            "serializing `{command}` with another Ouroboros lifecycle/profile update: {error:#}"
        )
    })?;
    recover_orphan_staging(data_dir)?;
    Ok(lock)
}

/// Takes the same namespace lock as runtime start/stop and proves the data directory is
/// stopped while holding it. The guard remains in scope for the complete profile
/// mutation, so a concurrent starter cannot adopt half-written or soon-to-be-deleted
/// credentials.
fn lock_stopped_fleet_mutation(data_dir: &Path, command: &str) -> Result<runtime::SpawnLock> {
    let lock = runtime::acquire_spawn_lock(data_dir).map_err(|error| {
        anyhow!("serializing `{command}` with runtime start and stop: {error:#}")
    })?;

    if let runtime::LockedPublication::Live(publication) =
        runtime::reconcile_publication_under_spawn_lock(data_dir, &lock)?
    {
        bail!(
            "runtime pid {} is still using this data directory; run `ouro stop`, wait for it to finish, then retry `{command}`",
            publication.pid
        );
    }

    if let Some(owner) = runtime::read_owned_runtime_owner(data_dir)? {
        if runtime::runtime_owner_is_live(&owner)? {
            bail!(
                "runtime pid {} still owns this data directory even though its gateway is not published; run `ouro stop`, wait for it to finish, then retry `{command}`",
                owner.pid
            );
        }
    }

    runtime::ensure_no_live_runtime_owner(data_dir)
        .with_context(|| format!("proving the runtime is stopped before `{command}`"))?;
    recover_orphan_staging(data_dir)?;
    Ok(lock)
}

fn validate_ports(ports: Ports) -> Result<()> {
    if let Some(port) = ports.gateway {
        validate_port(port, "gateway port")?;
    }
    if let Some(port) = ports.dist {
        validate_port(port, "distribution port")?;
        if port == 4369 {
            bail!("distribution port 4369 is reserved for EPMD; choose another port");
        }
    }
    if let Some(port) = ports.epmd {
        validate_port(port, "EPMD port")?;
        if port == 4369 {
            bail!(
                "EPMD port 4369 is the host-global default and cannot prove a private listener; choose a fleet-specific port"
            );
        }
    }
    Ok(())
}

fn validate_port(port: u16, name: &str) -> Result<()> {
    if port == 0 {
        bail!("{name} must be between 1 and 65535");
    }
    Ok(())
}

fn dist_ports(port: Option<u16>) -> (u16, u16) {
    port.map(|port| (port, port))
        .unwrap_or((DEFAULT_DIST_PORT_MIN, DEFAULT_DIST_PORT_MAX))
}

fn member(machine: &str, host: &str) -> Member {
    Member {
        machine: machine.to_string(),
        host: host.to_string(),
        node: format!("ouro-{machine}@{host}"),
    }
}

fn default_gateway_port(fleet_id: &str, machine: &str) -> u16 {
    let hash = fleet_id
        .bytes()
        .chain(machine.bytes())
        .fold(2_166_136_261_u32, |hash, byte| {
            hash.wrapping_mul(16_777_619) ^ u32::from(byte)
        });
    DEFAULT_GATEWAY_BASE + (hash % u32::from(DEFAULT_GATEWAY_SPAN)) as u16
}

fn default_epmd_port(fleet_id: &str) -> u16 {
    let hash = fleet_id.bytes().fold(2_166_136_261_u32, |hash, byte| {
        hash.wrapping_mul(16_777_619) ^ u32::from(byte)
    });
    DEFAULT_EPMD_BASE + (hash % u32::from(DEFAULT_EPMD_SPAN)) as u16
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut random = vec![0_u8; bytes];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|error| anyhow!("cannot read OS randomness: {error}"))?;
    let mut encoded = String::with_capacity(bytes * 2);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

fn current_utc_year() -> Result<i32> {
    let seconds: libc::time_t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the system clock is before the Unix epoch")?
        .as_secs()
        .try_into()
        .context("the current time does not fit the platform clock")?;
    // SAFETY: both pointers name initialized storage for the duration of the call;
    // `gmtime_r` writes only the supplied `tm` and has no shared static result.
    let mut calendar: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&seconds, &mut calendar) }.is_null() {
        bail!("the operating system could not convert the current UTC year");
    }
    Ok(calendar.tm_year + 1900)
}

fn ensure_data_dir(data_dir: &Path) -> Result<()> {
    if !data_dir.is_absolute() {
        bail!(
            "fleet data directory must be absolute, got {}",
            data_dir.display()
        );
    }
    fs::create_dir_all(data_dir).with_context(|| format!("creating {}", data_dir.display()))
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {}", path.display()))?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        bail!(
            "{} must be a private directory owned by uid {} (mode 0700); found directory={}, uid={}, mode={:o}",
            path.display(),
            uid,
            metadata.file_type().is_dir(),
            metadata.uid(),
            metadata.mode() & 0o777
        );
    }
    Ok(())
}

fn ensure_private_file(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {description} {}", path.display()))?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file() || metadata.uid() != uid || metadata.mode() & 0o777 != 0o600
    {
        bail!(
            "{} must be a private regular {description} owned by uid {} at mode 0600; found regular={}, uid={}, mode={:o}",
            path.display(),
            uid,
            metadata.file_type().is_file(),
            metadata.uid(),
            metadata.mode() & 0o777
        );
    }
    Ok(())
}

fn read_private(path: &Path, description: &str) -> Result<String> {
    ensure_private_file(path, description)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| {
            format!(
                "opening {description} {} without following links",
                path.display()
            )
        })?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("reading {description} {}", path.display()))?;
    Ok(text)
}

fn write_private_new(path: &Path, bytes: &[u8], description: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("creating private {description} {}; choose a new --out path rather than overwriting an existing file", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {description} {}", path.display()))?;
    file.sync_all()?;
    sync_parent(path)?;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    File::open(parent)
        .with_context(|| format!("opening parent directory {} for sync", parent.display()))?
        .sync_all()
        .with_context(|| format!("syncing parent directory {}", parent.display()))
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("fleet-file");
    let temporary = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        random_hex(6)?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .with_context(|| format!("creating private temporary file {}", temporary.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("writing {}", path.display()));
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("publishing {}", path.display()));
    }
    sync_parent(path)
}

fn erl_string(path: &Path) -> Result<String> {
    let raw = path
        .to_str()
        .ok_or_else(|| anyhow!("fleet path is not valid UTF-8: {}", path.display()))?;
    if raw.chars().any(|c| matches!(c, '\n' | '\r' | '\0')) {
        bail!(
            "fleet path contains a control character: {}",
            path.display()
        );
    }
    Ok(raw.replace('\\', "\\\\").replace('"', "\\\""))
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckLevel {
    Ok,
    Warn,
    Problem,
}

impl CheckLevel {
    fn marker(self) -> &'static str {
        match self {
            Self::Ok => "[ok]",
            Self::Warn => "[note]",
            Self::Problem => "[fix]",
        }
    }
}

struct Check {
    level: CheckLevel,
    message: String,
}

fn ok(message: impl Into<String>) -> Check {
    Check {
        level: CheckLevel::Ok,
        message: message.into(),
    }
}

fn warn(message: impl Into<String>) -> Check {
    Check {
        level: CheckLevel::Warn,
        message: message.into(),
    }
}

fn problem(message: impl Into<String>) -> Check {
    Check {
        level: CheckLevel::Problem,
        message: message.into(),
    }
}

const DEFAULT_GATEWAY_MAX_FRAME: u64 = 1_048_576;
const DEFAULT_GATEWAY_QUEUE_LIMIT: u64 = 1_000;

/// The only operator authority settings a packaged fleet runtime may inherit. The
/// launcher removes every ambient `OUROBOROS_*` variable first, then reapplies these
/// normalized values beside the profile-owned environment.
pub(crate) fn validated_runtime_authority_env(
    caller: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    let value = |name: &str| {
        caller
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let workspace_roots = value("OUROBOROS_WORKSPACE_ROOTS")
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    validate_inherited_workspace_roots(&workspace_roots)
        .context("validating inherited OUROBOROS_WORKSPACE_ROOTS")?;
    let gateway_max_frame = parse_runtime_limit(
        "OUROBOROS_GATEWAY_MAX_FRAME",
        value("OUROBOROS_GATEWAY_MAX_FRAME"),
        DEFAULT_GATEWAY_MAX_FRAME,
        1_024,
    )?;
    let gateway_queue_limit = parse_runtime_limit(
        "OUROBOROS_GATEWAY_QUEUE_LIMIT",
        value("OUROBOROS_GATEWAY_QUEUE_LIMIT"),
        DEFAULT_GATEWAY_QUEUE_LIMIT,
        1,
    )?;
    let mut environment = vec![
        ("OUROBOROS_WORKSPACE_ROOTS".into(), workspace_roots),
        (
            "OUROBOROS_GATEWAY_MAX_FRAME".into(),
            gateway_max_frame.to_string(),
        ),
        (
            "OUROBOROS_GATEWAY_QUEUE_LIMIT".into(),
            gateway_queue_limit.to_string(),
        ),
    ];
    if value("OUROBOROS_COLLECTOR_CONFIG").is_some() {
        bail!("the custody collector must run separately with release eval, not the fleet agent launcher");
    }
    if let Some(policy) = value("OUROBOROS_AUDIT_CONFIG") {
        let path = Path::new(policy);
        if !path.is_absolute() {
            bail!("OUROBOROS_AUDIT_CONFIG must be an absolute policy path");
        }
        uncontrolled_path_text(path).context("validating the inherited audit policy path")?;
        // The release validates privacy, content and keys before boot.
        // Preserve the operator's policy through the fleet environment scrubber.
        environment.push(("OUROBOROS_AUDIT_CONFIG".into(), policy.into()));
    }
    if let Some(mode) = value("OUROBOROS_AUDIT_MODE") {
        if !matches!(mode, "standard" | "local" | "required") {
            bail!("OUROBOROS_AUDIT_MODE must be standard, local or required");
        }
        environment.push(("OUROBOROS_AUDIT_MODE".into(), mode.into()));
    }
    Ok(environment)
}

fn parse_runtime_limit(name: &str, raw: Option<&str>, default: u64, minimum: u64) -> Result<u64> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };
    let value = raw
        .parse::<u64>()
        .with_context(|| format!("{name} must be a base-10 integer of at least {minimum}"))?;
    if value < minimum {
        bail!("{name} must be an integer of at least {minimum}, got {value}");
    }
    Ok(value)
}

fn validate_inherited_workspace_roots(value: &str) -> Result<()> {
    if value.chars().any(char::is_control) {
        bail!("inherited OUROBOROS_WORKSPACE_ROOTS contains a control character");
    }
    if value.is_empty() {
        return Ok(());
    }
    let entries = std::env::split_paths(value).collect::<Vec<_>>();
    if entries.is_empty() || entries.iter().any(|entry| !entry.is_absolute()) {
        bail!("inherited OUROBOROS_WORKSPACE_ROOTS must contain only absolute directories");
    }
    for entry in entries {
        uncontrolled_path_text(&entry).context("validating an inherited workspace root")?;
    }
    Ok(())
}

fn uncontrolled_path_text(path: &Path) -> Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow!("path is not valid UTF-8: {}", path.display()))?;
    if text.chars().any(|character| character.is_control()) {
        bail!("path contains a control character: {}", path.display());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    pub(super) fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ouro-fleet-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(&path).unwrap(),
            Ok(_metadata) => fs::remove_file(&path).unwrap(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => panic!("cannot inspect scratch root {}: {error}", path.display()),
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).unwrap();
        path
    }

    #[test]
    fn tags_round_trip_and_validate_before_persisting() {
        let dir = scratch("tags");
        fs::create_dir(dir.join("fleet")).unwrap();
        let profile = sample_profile("studio");
        write_profile(&dir, &profile).unwrap();
        assert_eq!(
            tags(&dir, None, Some(("xcode", true))).unwrap(),
            vec!["xcode"]
        );
        assert_eq!(
            tags(&dir, None, Some(("xcode", true))).unwrap(),
            vec!["xcode"]
        );
        assert_eq!(
            load(&dir).unwrap().unwrap().tags,
            serde_json::json!(["xcode"])
        );
        assert!(tags(&dir, None, Some(("BAD tag", true)))
            .unwrap_err()
            .to_string()
            .contains("BAD tag"));
        assert_eq!(
            tags(&dir, None, Some(("xcode", false))).unwrap(),
            Vec::<String>::new()
        );
        let mut invalid = profile;
        invalid.tags = serde_json::json!(["BAD"]);
        let encoded = serde_json::to_vec(&invalid).unwrap();
        write_private_atomic(&profile_path(&dir), &encoded).unwrap();
        assert!(doctor(&dir).text.contains("BAD"));
        assert!(
            load(&dir).unwrap().is_some(),
            "advisory tags cannot block daemon profile loading"
        );
        assert_eq!(
            tags(&dir, None, Some(("BAD", false))).unwrap(),
            Vec::<String>::new()
        );
        for malformed in [
            serde_json::json!([null]),
            serde_json::json!({"invalid": true}),
        ] {
            invalid.tags = malformed.clone();
            write_profile(&dir, &invalid).unwrap();
            assert_eq!(load(&dir).unwrap().unwrap().tags, malformed);
            assert!(doctor(&dir).text.contains("advisory tags ignored"));
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The tombstone is the operator's statement that a machine is gone, and the only
    /// thing `fleet.forget_session_owner` will act on. It is written here, by hand, never
    /// inferred from a machine being unreachable.
    #[test]
    fn declaring_a_machine_gone_moves_it_out_of_the_roster_and_can_be_undone() {
        let dir = scratch("forget-machine");
        fs::create_dir(dir.join("fleet")).unwrap();
        let mut profile = sample_profile("studio");
        let vps = member("vps", "vps.tailnet.ts.net");
        profile.members.push(vps.clone());
        write_profile(&dir, &profile).unwrap();
        assert!(
            load(&dir).unwrap().unwrap().tombstones.is_empty(),
            "an unreachable peer is not a peer anyone declared gone"
        );

        assert_eq!(forget_machine(&dir, "vps").unwrap(), vps);
        let after = load(&dir).unwrap().unwrap();
        assert_eq!(
            after.members,
            vec![member("studio", "studio.tailnet.ts.net")]
        );
        assert_eq!(after.tombstones, vec![vps.clone()]);
        assert_eq!(after.roster_revision, profile.roster_revision + 1);
        assert_eq!(after.expected_peers(), 0);

        // A gateway call that failed is retried against the same statement, so the second
        // run must reach the gateway rather than refuse, and must not move the roster on.
        assert_eq!(forget_machine(&dir, &vps.node).unwrap(), vps);
        assert_eq!(
            load(&dir).unwrap().unwrap().roster_revision,
            profile.roster_revision + 1
        );

        // The runtime refusing — the machine turned out to be connected — puts it back.
        restore_machine(&dir, &vps).unwrap();
        let restored = load(&dir).unwrap().unwrap();
        assert!(restored.tombstones.is_empty());
        assert!(restored.members.contains(&vps));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn declaring_a_machine_gone_refuses_this_machine_and_a_name_the_roster_never_had() {
        let dir = scratch("forget-machine-refusals");
        fs::create_dir(dir.join("fleet")).unwrap();
        let profile = sample_profile("studio");
        write_profile(&dir, &profile).unwrap();

        for own in ["studio", "ouro-studio@studio.tailnet.ts.net"] {
            let refusal = forget_machine(&dir, own).unwrap_err().to_string();
            assert!(refusal.contains("ouro fleet leave"), "{refusal}");
        }
        let unknown = forget_machine(&dir, "ghost").unwrap_err().to_string();
        assert!(unknown.contains("no member named ghost"), "{unknown}");
        assert!(load(&dir).unwrap().unwrap().tombstones.is_empty());

        // A profile written before this field reads as "nothing declared gone" rather
        // than as a profile this machine refuses to start from.
        let mut encoded: Value =
            serde_json::from_str(&fs::read_to_string(profile_path(&dir)).unwrap()).unwrap();
        assert!(encoded
            .as_object_mut()
            .unwrap()
            .remove("tombstones")
            .is_some());
        write_private_atomic(
            &profile_path(&dir),
            &serde_json::to_vec_pretty(&encoded).unwrap(),
        )
        .unwrap();
        assert!(load(&dir).unwrap().unwrap().tombstones.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_hand_edited_roster_cannot_call_a_machine_both_active_and_gone() {
        let mut both = sample_profile("studio");
        let vps = member("vps", "vps.tailnet.ts.net");
        both.members.push(vps.clone());
        both.tombstones.push(vps);
        let refusal = validate_profile(&both).unwrap_err().to_string();
        assert!(refusal.contains("both active and removed"), "{refusal}");

        let mut itself = sample_profile("studio");
        itself
            .tombstones
            .push(member("studio", "studio.tailnet.ts.net"));
        let refusal = validate_profile(&itself).unwrap_err().to_string();
        assert!(
            refusal.contains("cannot tombstone the machine it belongs to"),
            "{refusal}"
        );

        let mut mismatched = sample_profile("studio");
        mismatched.tombstones.push(Member {
            machine: "vps".into(),
            host: "vps.tailnet.ts.net".into(),
            node: "ouro-elsewhere@vps.tailnet.ts.net".into(),
        });
        let refusal = validate_profile(&mismatched).unwrap_err().to_string();
        assert!(refusal.contains("fleet tombstone vps"), "{refusal}");
    }

    #[test]
    fn facts_render_with_tags_and_older_peers_stay_unknown() {
        assert_eq!(
            render_machine_facts(&serde_json::json!({})),
            "platform unknown · tags unknown"
        );
        assert_eq!(
            render_machine_facts(
                &serde_json::json!({"facts": {"os": "macos", "arch": "aarch64", "tags": ["xcode", "ios"]}})
            ),
            "macos/aarch64 · tags: xcode ios"
        );
    }

    /// What an operator does when they move `<data dir>/fleet/` to the second machine.
    fn copy_fleet_dir(from: &Path, to: &Path) {
        fs::DirBuilder::new().mode(0o700).create(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            fs::copy(entry.path(), &target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn env_value<'a>(environment: &'a [(String, String)], key: &str) -> &'a str {
        environment
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("{key} is not in the computed runtime environment"))
    }

    /// Plan §3 D4 keeps the cluster and drops enrollment: "an operator copies the binary
    /// to each machine and sets the cluster environment by hand". Copying files by hand
    /// therefore has to be enough to form the two-machine mutual-TLS cluster FLEET.md
    /// describes — one CA, one cookie, two leaves, two rosters. Nothing below opens a
    /// socket to another machine or installs anything.
    #[test]
    fn a_second_machine_is_created_from_a_private_copy_of_the_first_machines_fleet_directory() {
        let one = scratch("create-from-one");
        let two = scratch("create-from-two");
        let carried = scratch("create-from-carried");

        let first = create(
            &one,
            Some("Workshop"),
            "studio",
            "127.0.0.1",
            ephemeral_ports(),
        )
        .expect("the first machine mints its own CA");
        let copy = carried.join("fleet");
        copy_fleet_dir(&fleet_dir(&one), &copy);

        // An incomplete copy is refused before anything is written.
        let partial = carried.join("partial");
        copy_fleet_dir(&fleet_dir(&one), &partial);
        fs::remove_file(partial.join(CA_KEY_FILE)).unwrap();
        let error = create_from(&two, &partial, "vps", "127.0.0.1", ephemeral_ports())
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a complete copy"), "{error}");
        assert!(!fleet_dir(&two).exists(), "a refusal wrote fleet state");

        // A name the copied roster already holds is refused: `--from` mints a machine
        // that is not in the cluster yet, it does not reissue one that is.
        let error = create_from(&two, &copy, "studio", "127.0.0.1", ephemeral_ports())
            .unwrap_err()
            .to_string();
        assert!(error.contains("already names machine `studio`"), "{error}");
        assert!(!fleet_dir(&two).exists(), "a refusal wrote fleet state");

        let second = create_from(&two, &copy, "vps", "127.0.0.1", ephemeral_ports())
            .expect("the second machine signs its leaf with the copied CA");

        // One cluster: one id, one name, one cookie.
        assert_eq!(second.fleet_id, first.fleet_id);
        assert_eq!(second.name, first.name);
        assert_eq!(
            read_private(&fleet_dir(&two).join(COOKIE_FILE), "cookie").unwrap(),
            read_private(&fleet_dir(&one).join(COOKIE_FILE), "cookie").unwrap()
        );
        // The signing authority stays on the machine that already holds it.
        assert!(
            !fleet_dir(&two).join(CA_KEY_FILE).exists(),
            "the second machine was given the CA key"
        );

        // Both leaves chain to the one CA, checked against the first machine's own CA
        // bytes rather than against a re-encoding of them.
        let ca = read_private(&fleet_dir(&one).join(CA_CERT_FILE), "CA").unwrap();
        assert_eq!(
            ca,
            read_private(&fleet_dir(&two).join(CA_CERT_FILE), "CA").unwrap()
        );
        for (data, machine) in [(&one, "studio"), (&two, "vps")] {
            validate_tls_identity(
                &member(machine, "127.0.0.1"),
                &ca,
                &read_private(&fleet_dir(data).join(NODE_CERT_FILE), "leaf").unwrap(),
                &read_private(&fleet_dir(data).join(NODE_KEY_FILE), "leaf key").unwrap(),
                None,
                "test",
            )
            .unwrap_or_else(|error| {
                panic!("{machine}'s leaf does not chain to the one CA: {error:#}")
            });
        }

        // The second machine already expects both; the first has to be told, locally.
        assert_eq!(
            second
                .members
                .iter()
                .map(|member| member.machine.as_str())
                .collect::<Vec<_>>(),
            vec!["studio", "vps"]
        );
        assert_eq!(first.members.len(), 1);
        let added = add_member(&one, "vps", "127.0.0.1", Some("ouro-vps@127.0.0.1")).unwrap();
        assert_eq!(added, member("vps", "127.0.0.1"));
        let after = load(&one).unwrap().unwrap();
        assert_eq!(after.members.len(), 2);
        assert_eq!(after.roster_revision, first.roster_revision + 1);
        // Idempotent, so a repeated command is not an error and does not move the revision.
        assert_eq!(add_member(&one, "vps", "127.0.0.1", None).unwrap(), added);
        assert_eq!(
            load(&one).unwrap().unwrap().roster_revision,
            after.roster_revision
        );
        let error = add_member(&one, "vps", "127.0.0.2", None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already names vps"), "{error}");
        let error = add_member(&one, "vps", "127.0.0.1", Some("vps"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("ouro-vps@127.0.0.1"), "{error}");

        // Both machines validate, and both boot with the same two-node seed list.
        for data in [&one, &two] {
            let environment = runtime_env(data)
                .unwrap_or_else(|error| panic!("{} refuses to start: {error:#}", data.display()))
                .expect("a profile is installed");
            let hosts = env_value(&environment, "OUROBOROS_CLUSTER_HOSTS");
            assert!(hosts.contains("ouro-studio@127.0.0.1"), "{hosts}");
            assert!(hosts.contains("ouro-vps@127.0.0.1"), "{hosts}");
            assert_eq!(
                env_value(&environment, "OUROBOROS_FLEET_ID"),
                first.fleet_id
            );
        }
        assert!(doctor(&one).text.contains("vps"));

        // `members remove` is the counterpart of `leave` on the other machine, and it is
        // not a tombstone: nothing durable is retired by it.
        let error = remove_member(&one, "studio").unwrap_err().to_string();
        assert!(error.contains("`ouro fleet leave`"), "{error}");
        assert_eq!(remove_member(&one, "vps").unwrap(), added);
        let after = load(&one).unwrap().unwrap();
        assert_eq!(after.members, vec![member("studio", "127.0.0.1")]);
        assert!(after.tombstones.is_empty());

        fs::remove_dir_all(one).ok();
        fs::remove_dir_all(two).ok();
        fs::remove_dir_all(carried).ok();
    }

    /// F1: `revoke-<64 hex>.json` is durable state on any machine whose lab ever revoked
    /// one, and `leave` is the only command that removes a fleet directory. Recognizing
    /// the shape is what keeps such a machine retirable; naming everything else is what
    /// keeps the refusal from being silent.
    #[test]
    fn leave_retires_a_directory_holding_a_retired_revocation_and_doctor_names_what_it_cannot() {
        let data = scratch("leave-revocation");
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        let artifact = fleet_dir(&data).join(format!("revoke-{}.json", "ab".repeat(32)));
        write_private_atomic(&artifact, b"{\"schema\":1}").unwrap();

        // The artifact is inert but recognized, so it is not something doctor asks the
        // operator to move, and it does not make the machine unhealthy.
        let report = doctor(&data);
        assert!(report.healthy, "{}", report.text);
        assert!(!report.text.contains("no Ouroboros command recognizes"));

        // An entry nothing recognizes is still a refusal, and doctor now says which.
        write_private_atomic(&fleet_dir(&data).join("operator-note"), b"keep me").unwrap();
        let report = doctor(&data);
        assert!(!report.healthy);
        assert!(
            report.text.contains("[fix]") && report.text.contains("operator-note"),
            "{}",
            report.text
        );
        let error = leave(&data).unwrap_err().to_string();
        assert!(error.contains("operator-note"), "{error}");
        assert!(artifact.exists(), "a refusal removed a file");

        fs::remove_file(fleet_dir(&data).join("operator-note")).unwrap();
        let removal = leave(&data)
            .unwrap()
            .expect("a fleet directory was present");
        assert!(removal
            .removed
            .iter()
            .any(|name| name.starts_with("revoke-")));
        assert!(!fleet_dir(&data).exists());
        fs::remove_dir_all(data).ok();
    }

    /// F2: a crash between `install_new_profile`'s staging rename and its fsync leaves a
    /// fleet directory with no `profile.json`. Every surface refuses such a directory, so
    /// `leave` refusing it too is a total lockout repairable only by hand.
    #[test]
    fn leave_clears_a_fleet_directory_whose_profile_never_landed() {
        let data = scratch("leave-incomplete");
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        fs::remove_file(profile_path(&data)).unwrap();

        for message in [
            load(&data).unwrap_err().to_string(),
            runtime_env(&data).unwrap_err().to_string(),
            doctor(&data).text,
        ] {
            assert!(
                !message.contains("--discard-incomplete"),
                "a surface still names a flag that does not parse: {message}"
            );
            assert!(message.contains("ouro fleet leave"), "{message}");
        }

        let removal = leave(&data)
            .unwrap()
            .expect("a fleet directory was present");
        assert!(!removal.profile_readable);
        assert_eq!(removal.machine, None);
        assert!(removal.removed.iter().any(|name| name == COOKIE_FILE));
        assert!(removal.removed.iter().any(|name| name == CA_KEY_FILE));
        assert!(!fleet_dir(&data).exists());
        assert!(load(&data).unwrap().is_none());
        fs::remove_dir_all(data).ok();
    }

    /// F4: the previous Ouroboros generated a policy that routed verification through a
    /// module this build deleted. "Restore from a trusted backup" is a loop for that file
    /// — the backup is the file — and `leave` + `create` mints a new fleet id, CA and
    /// cookie, which is a rebuild of the trust domain, not a repair.
    #[test]
    fn regenerating_repairs_a_generated_policy_written_by_an_older_ouroboros() {
        let data = scratch("regenerate");
        let created = create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        let root = fleet_dir(&data);
        let current = fs::read_to_string(root.join(TLS_OPTFILE)).unwrap();
        let previous = previous_generated_tls(&data).unwrap();
        assert_ne!(previous, current);
        write_private_atomic(&root.join(TLS_OPTFILE), previous.as_bytes()).unwrap();

        let error = runtime_env(&data).unwrap_err().to_string();
        assert!(error.contains("Cluster.Revocations"), "{error}");
        assert!(error.contains("--regenerate"), "{error}");
        assert!(
            !error.contains("trusted backup"),
            "the loop remedy is still offered for the one file it loops on: {error}"
        );

        let regenerated = regenerate(&data).unwrap();
        assert_eq!(regenerated.fleet_id, created.fleet_id);
        assert_eq!(regenerated.members, created.members);
        assert_eq!(
            fs::read_to_string(root.join(TLS_OPTFILE)).unwrap(),
            current,
            "regenerate did not restore the current generated policy"
        );
        assert!(runtime_env(&data).unwrap().is_some());
        assert!(doctor(&data).healthy);

        // A policy nobody generated is still a refusal, and it still names the repair.
        let weakened = current.replace("verify_peer", "verify_none");
        write_private_atomic(&root.join(TLS_OPTFILE), weakened.as_bytes()).unwrap();
        let error = runtime_env(&data).unwrap_err().to_string();
        assert!(error.contains("--regenerate"), "{error}");
        assert!(error.contains("trusted backup"), "{error}");
        fs::remove_dir_all(data).ok();
    }

    /// The other half of `test/cluster_dist_tls_test.exs`. That test drives `:ssl` with a
    /// committed copy of this policy and proves what it refuses; this one fails if the
    /// generator stops emitting exactly that copy. Without the pair, an edit that drops
    /// `verify_peer` from one half only changes the string the drift test compares to
    /// itself, and nothing in either language notices.
    #[test]
    fn the_generated_policy_is_the_one_the_handshake_test_drives_ssl_with() {
        let data = scratch("generated-policy-template");
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        let root = fleet_dir(&data);
        let generated = fs::read_to_string(root.join(TLS_OPTFILE)).unwrap();
        let template = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../test/support/fleet_tls/ssl_dist.conf.template"),
        )
        .expect("the committed template the Elixir handshake test consults");
        assert_eq!(
            generated,
            template.replace("@FLEET_DIR@", root.to_str().unwrap()),
            "`generated_runtime_files` no longer emits the policy test/cluster_dist_tls_test.exs proves the behaviour of; regenerate test/support/fleet_tls/ as its README says"
        );
        fs::remove_dir_all(data).ok();
    }

    /// F5: a client that dies between the tombstone write and the gateway reply leaves a
    /// silently shrunk roster. It is safe, but it has to be visible and it has to have an
    /// undo.
    #[test]
    fn a_machine_declared_gone_is_named_by_status_and_doctor_and_can_be_restored() {
        let dir = scratch("tombstone-visible");
        fs::create_dir(dir.join("fleet")).unwrap();
        let mut profile = sample_profile("studio");
        let vps = member("vps", "vps.tailnet.ts.net");
        profile.members.push(vps.clone());
        write_profile(&dir, &profile).unwrap();

        forget_machine(&dir, "vps").unwrap();
        let status = render_status(&dir).unwrap();
        assert!(status.contains("gone"), "{status}");
        assert!(status.contains("vps"), "{status}");
        assert!(status.contains("sessions restore"), "{status}");
        let report = doctor(&dir);
        assert!(
            report.text.contains("gone for good") && report.text.contains("vps"),
            "{}",
            report.text
        );

        // `members add` refuses to quietly undo the operator's statement.
        let error = add_member(&dir, "vps", "vps.tailnet.ts.net", None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("sessions restore vps"), "{error}");

        restore_machine(&dir, &vps).unwrap();
        let after = load(&dir).unwrap().unwrap();
        assert!(after.tombstones.is_empty());
        assert!(after.members.contains(&vps));
        assert!(!render_status(&dir).unwrap().contains("gone for good"));
        fs::remove_dir_all(dir).ok();
    }

    fn sample_profile(machine: &str) -> Profile {
        Profile {
            tags: empty_tags(),
            schema: PROFILE_SCHEMA,
            fleet_id: "00112233445566778899aabb".into(),
            name: "Workshop fleet".into(),
            machine: machine.into(),
            host: "studio.tailnet.ts.net".into(),
            node: format!("ouro-{machine}@studio.tailnet.ts.net"),
            role: "core".into(),
            members: vec![member(machine, "studio.tailnet.ts.net")],
            tombstones: Vec::new(),
            roster_revision: initial_roster_revision(),
            gateway_port: 48_111,
            epmd_port: 14_111,
            dist_port_min: 44_111,
            dist_port_max: 44_111,
        }
    }

    fn fake_epmd(port: u16, stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(250)))
                            .unwrap();
                        let mut request = [0_u8; 3];
                        if stream.read_exact(&mut request).is_ok() && request == [0, 1, 110] {
                            stream.write_all(&u32::from(port).to_be_bytes()).unwrap();
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fake EPMD accept failed: {error}"),
                }
            }
        })
    }

    fn assign_free_loopback_epmd_port(data_dir: &Path) -> Profile {
        let mut profile = load(data_dir).unwrap().unwrap();
        loop {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            if port != legacy_epmd_port()
                && port != profile.gateway_port
                && !(profile.dist_port_min..=profile.dist_port_max).contains(&port)
            {
                profile.epmd_port = port;
                write_profile(data_dir, &profile).unwrap();
                return profile;
            }
        }
    }

    #[test]
    fn create_is_private_complete_and_never_places_the_cookie_in_runtime_env() {
        let data = scratch("create");
        let profile = create(
            &data,
            Some("Studio fleet"),
            "studio-mini",
            "localhost",
            Ports {
                gateway: Some(48_001),
                dist: Some(44_001),
                ..ephemeral_ports()
            },
        )
        .unwrap();

        assert_eq!(profile.node, "ouro-studio-mini@localhost");
        assert_eq!(profile.name, "Studio fleet");
        assert_eq!(profile.gateway_port, 48_001);
        assert_eq!(profile.dist_port_min, 44_001);
        let loaded = load(&data).unwrap().unwrap();
        assert_eq!(loaded, profile);

        for name in [
            PROFILE_FILE,
            COOKIE_FILE,
            CA_CERT_FILE,
            CA_KEY_FILE,
            NODE_CERT_FILE,
            NODE_KEY_FILE,
            TLS_OPTFILE,
            VM_ARGS_FILE,
        ] {
            assert_eq!(
                fs::metadata(fleet_dir(&data).join(name)).unwrap().mode() & 0o777,
                0o600,
                "{name}"
            );
        }
        assert_eq!(fs::metadata(fleet_dir(&data)).unwrap().mode() & 0o077, 0);

        let env = runtime_env(&data).unwrap().unwrap();
        assert!(
            env.iter()
                .any(|(key, value)| key == "OUROBOROS_COOKIE_FILE"
                    && value.ends_with("/fleet/cookie"))
        );
        assert!(!env.iter().any(|(key, _)| key == "OUROBOROS_COOKIE"));
        assert!(env
            .iter()
            .any(|(key, value)| key == "RELEASE_VM_ARGS" && value.ends_with("/fleet/vm.args")));
        assert!(env
            .iter()
            .any(|(key, value)| key == "ERL_EPMD_ADDRESS" && value == "127.0.0.1"));
        assert!(env
            .iter()
            .any(|(key, value)| key == "OUROBOROS_FLEET_ID" && value == &profile.fleet_id));
        let vm = fs::read_to_string(fleet_dir(&data).join(VM_ARGS_FILE)).unwrap();
        assert!(vm.contains("-proto_dist inet_tls"));
        assert!(vm.contains("inet_dist_use_interface {127,0,0,1}"));
        assert!(vm.contains("inet_dist_listen_min 44001 inet_dist_listen_max 44001"));

        let (_, ca_pem) = parse_x509_pem(
            &fs::read(fleet_dir(&data).join(CA_CERT_FILE)).expect("generated CA PEM"),
        )
        .unwrap();
        let ca = ca_pem.parse_x509().unwrap();
        assert!(
            (ca.validity().not_after - ca.validity().not_before)
                .unwrap()
                .whole_days()
                <= MAX_CA_VALIDITY_DAYS
        );
        let (_, node_pem) = parse_x509_pem(
            &fs::read(fleet_dir(&data).join(NODE_CERT_FILE)).expect("generated node PEM"),
        )
        .unwrap();
        let node = node_pem.parse_x509().unwrap();
        assert!(
            (node.validity().not_after - node.validity().not_before)
                .unwrap()
                .whole_days()
                <= MAX_NODE_VALIDITY_DAYS
        );

        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn create_refuses_occupied_gateway_and_distribution_ports_before_install() {
        let created = scratch("occupied-create-ports");
        let gateway = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let gateway_port = gateway.local_addr().unwrap().port();
        let free_dist = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let free_dist_port = free_dist.local_addr().unwrap().port();
        drop(free_dist);
        let error = create(
            &created,
            None,
            "owner",
            "127.0.0.1",
            Ports {
                gateway: Some(gateway_port),
                dist: Some(free_dist_port),
                ..ephemeral_ports()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("local gateway port"), "{error}");
        assert!(
            error.contains("no fleet credential was installed"),
            "{error}"
        );
        assert!(!fleet_dir(&created).exists());
        drop(gateway);

        let distribution = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let distribution_port = distribution.local_addr().unwrap().port();
        let free_gateway = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let free_gateway_port = free_gateway.local_addr().unwrap().port();
        drop(free_gateway);
        let occupied_dist = scratch("occupied-dist-ports");
        let error = create(
            &occupied_dist,
            None,
            "owner",
            "127.0.0.1",
            Ports {
                gateway: Some(free_gateway_port),
                dist: Some(distribution_port),
                ..ephemeral_ports()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("TLS distribution port"), "{error}");
        assert!(
            error.contains("no fleet credential was installed"),
            "{error}"
        );
        assert!(!fleet_dir(&occupied_dist).exists());

        fs::remove_dir_all(created).ok();
        fs::remove_dir_all(occupied_dist).ok();
    }

    #[test]
    fn interrupted_private_setup_is_recovered_but_ambiguous_staging_fails_closed() {
        let recovered = scratch("staging-recovered");
        let staging = recovered.join(".fleet.setup.123.001122aabbcc");
        DirBuilder::new().mode(0o700).create(&staging).unwrap();
        write_private_new(&staging.join(COOKIE_FILE), b"interrupted-secret", "fixture").unwrap();
        create(&recovered, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        assert!(!staging.exists());
        assert!(fleet_dir(&recovered).exists());

        let unsafe_data = scratch("staging-unsafe");
        let unsafe_staging = unsafe_data.join(".fleet.setup.456.ffeeddccbbaa");
        DirBuilder::new()
            .mode(0o755)
            .create(&unsafe_staging)
            .unwrap();
        let error = create(&unsafe_data, None, "owner", "127.0.0.1", ephemeral_ports())
            .unwrap_err()
            .to_string();
        assert!(error.contains("mode-0700 real directory"), "{error}");
        assert!(unsafe_staging.exists());
        assert!(!fleet_dir(&unsafe_data).exists());

        fs::remove_dir_all(recovered).ok();
        fs::remove_dir_all(unsafe_data).ok();
    }

    #[test]
    fn stopped_mutations_share_the_runtime_lock_and_refuse_every_live_owner_shape() {
        let live = scratch("live-mutation");
        write_private_atomic(
            &live.join(runtime::PUBLICATION_FILE),
            format!(
                r#"{{"port":47001,"protocol":1,"node":"ouro-live@127.0.0.1","pid":{},"scope":"operate"}}"#,
                std::process::id()
            )
            .as_bytes(),
        )
        .unwrap();

        for error in [
            create(&live, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap_err(),
            leave(&live).unwrap_err(),
        ] {
            let error = error.to_string();
            assert!(error.contains("`ouro stop`"), "{error}");
            assert!(error.contains("then retry"), "{error}");
        }
        assert!(!fleet_dir(&live).exists());

        fs::remove_file(live.join(runtime::PUBLICATION_FILE)).unwrap();
        let held = runtime::acquire_spawn_lock(&live).unwrap();
        let concurrent = create(&live, None, "owner", "127.0.0.1", ephemeral_ports())
            .unwrap_err()
            .to_string();
        assert!(concurrent.contains("another ouro"), "{concurrent}");
        assert!(!fleet_dir(&live).exists());
        drop(held);

        let unpublished = scratch("unpublished-mutation");
        write_private_atomic(
            &unpublished.join(runtime::RUNTIME_OWNER_FILE),
            format!(r#"{{"pid":{},"owner":"test-live-vm"}}"#, std::process::id()).as_bytes(),
        )
        .unwrap();
        let error = create(&unpublished, None, "owner", "127.0.0.1", ephemeral_ports())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("even though its gateway is not published"),
            "{error}"
        );
        assert!(error.contains("`ouro stop`"), "{error}");
        assert!(!fleet_dir(&unpublished).exists());

        fs::remove_dir_all(live).ok();
        fs::remove_dir_all(unpublished).ok();
    }

    #[test]
    fn unusable_ipv6_and_colon_hosts_are_refused_before_any_credential_is_created() {
        let data = scratch("ipv6");
        let error = create(&data, None, "owner", "::1", ephemeral_ports())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("IPv6 fleet distribution is not yet supported"),
            "{error}"
        );
        assert!(!fleet_dir(&data).exists());

        for host in ["0.0.0.0", "169.254.1.2", "224.0.0.1", "255.255.255.255"] {
            let error = create(&data, None, "owner", host, ephemeral_ports())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("not a usable fleet machine address"),
                "{error}"
            );
            assert!(!fleet_dir(&data).exists());
        }
        let public = create(&data, None, "owner", "8.8.8.8", ephemeral_ports())
            .unwrap_err()
            .to_string();
        assert!(public.contains("public IPv4 address"), "{public}");
        assert!(public.contains("refuses to expose EPMD/BEAM"), "{public}");
        assert!(!fleet_dir(&data).exists());
        assert!(private_fleet_ipv4("100.64.0.1".parse().unwrap()));
        assert!(private_fleet_ipv4("10.0.0.1".parse().unwrap()));
        assert!(!private_fleet_ipv4("1.1.1.1".parse().unwrap()));
        let error = create(&data, None, "owner", "ipv6-only.invalid", ephemeral_ports())
            .unwrap_err()
            .to_string();
        assert!(error.contains("resolving fleet host"), "{error}");
        assert!(!fleet_dir(&data).exists());

        // `create` refuses both of these in `validate_host`, before any resolution is
        // attempted, so neither reaches the "resolving to IPv4" branch the deleted
        // `invite` arm used to exercise here; that branch is covered by
        // `fleet_dns_requires_one_canonical_private_ipv4`. Pin each host to the refusal it
        // actually gets rather than accepting either of two.
        for (host, refusal) in [
            ("2001:db8::1", "IPv6 fleet distribution is not yet supported"),
            ("host:epmd", "contains `:`"),
        ] {
            let error = create(&data, None, "owner", host, ephemeral_ports())
                .unwrap_err()
                .to_string();
            assert!(error.contains(refusal), "{error}");
            assert!(!fleet_dir(&data).exists());
        }

        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        assert_eq!(load(&data).unwrap().unwrap().members.len(), 1);
        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn fleet_dns_requires_one_canonical_private_ipv4() {
        let error = select_fleet_ipv4(
            "multi.internal",
            vec![
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("2 usable IPv4 addresses"), "{error}");
        assert!(
            error.contains("exactly one private canonical address"),
            "{error}"
        );
        let mixed = select_fleet_ipv4(
            "mixed.internal",
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(8, 8, 8, 8)],
        )
        .unwrap_err()
        .to_string();
        assert!(
            mixed.contains("10.0.0.1, 8.8.8.8") || mixed.contains("8.8.8.8, 10.0.0.1"),
            "{mixed}"
        );
        assert!(mixed.contains("public A record"), "{mixed}");
        assert_eq!(
            select_fleet_ipv4(
                "one.internal",
                vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 1),],
            )
            .unwrap(),
            Ipv4Addr::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn owned_epmd_readiness_waits_for_a_protocol_listener_and_rejects_other_services() {
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        assert!(!owned_epmd_ready(Ipv4Addr::LOCALHOST, port).unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let server = fake_epmd(port, stop.clone());
        assert!(owned_epmd_ready(Ipv4Addr::LOCALHOST, port).unwrap());
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();

        let other = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let error = owned_epmd_ready(Ipv4Addr::LOCALHOST, other.local_addr().unwrap().port())
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not speak"), "{error}");
    }

    #[test]
    fn epmd_preflight_reuses_a_real_lingering_daemon_and_rejects_arbitrary_listeners() {
        assert!(local_ipv4_interfaces()
            .unwrap()
            .contains(&Ipv4Addr::LOCALHOST));
        let epmd = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = epmd.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = epmd.accept().unwrap();
            let mut request = [0_u8; 3];
            connection.read_exact(&mut request).unwrap();
            assert_eq!(request, [0, 1, 110]);
            connection
                .write_all(&u32::from(port).to_be_bytes())
                .unwrap();
        });
        assert_eq!(
            ensure_epmd_port_available("127.0.0.1", port).unwrap(),
            EpmdPortState::CompatibleRunning
        );
        server.join().unwrap();

        let arbitrary = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let arbitrary_port = arbitrary.local_addr().unwrap().port();
        let error = ensure_epmd_port_available("127.0.0.1", arbitrary_port)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("non-EPMD or incompatible listener"),
            "{error}"
        );
        drop(arbitrary);
    }

    #[test]
    fn inherited_epmd_lock_survives_exec_and_releases_only_when_the_child_exits() {
        let data = scratch("epmd-inherited-lock");
        fs::create_dir_all(fleet_dir(&data)).unwrap();
        let lock_path = epmd_owner_lock_path(&data);
        let lock = create_epmd_lock(&lock_path).unwrap();
        let metadata = lock.metadata().unwrap();
        let sleep = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix sleep executable");
        let mut command = Command::new(sleep);
        inherit_epmd_lock_on_exec(&mut command, lock.as_raw_fd());
        let mut child = command.arg("30").spawn().unwrap();
        drop(lock);

        assert!(epmd_lock_held(&lock_path, metadata.dev(), metadata.ino()).unwrap());
        child.kill().unwrap();
        child.wait().unwrap();

        // `wait` proves this child was reaped; the lock may still outlive it by the
        // window `assert_epmd_lock_released` describes.
        assert_epmd_lock_released(&lock_path, &metadata);
        remove_epmd_owner_artifacts(&data).unwrap();
        fs::remove_dir_all(data).ok();
    }

    /// Asserts the lock at `lock_path` is released within production's own bounded window
    /// rather than at this instant. Another test in this process may have forked while the
    /// parent still held the descriptor; that child retains the same open-file description
    /// — and with it the lock — until its exec applies FD_CLOEXEC, which is a window the
    /// hosted runner's two cores stretch to tens of milliseconds. Production cleanup already
    /// treats that as a short bounded release, so the tests assert the same contract. An
    /// unrelated child that had truly inherited the lock would hold it for its whole life,
    /// well past this window, so the bound keeps the distinction it is there to prove.
    fn assert_epmd_lock_released(lock_path: &Path, metadata: &fs::Metadata) {
        let deadline = Instant::now() + EPMD_STOP_DEADLINE;
        while epmd_lock_held(lock_path, metadata.dev(), metadata.ino()).unwrap()
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(
            !epmd_lock_held(lock_path, metadata.dev(), metadata.ino()).unwrap(),
            "the EPMD lock remained held after its bounded release window"
        );
    }

    #[test]
    fn unrelated_children_do_not_inherit_the_epmd_ownership_lock() {
        let data = scratch("epmd-unrelated-lock");
        fs::create_dir_all(fleet_dir(&data)).unwrap();
        let lock_path = epmd_owner_lock_path(&data);
        let lock = create_epmd_lock(&lock_path).unwrap();
        let metadata = lock.metadata().unwrap();
        let sleep = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix sleep executable");
        let mut child = Command::new(sleep).arg("30").spawn().unwrap();
        drop(lock);

        // The child lives for thirty seconds; a lock it had inherited would be held for
        // all of them, so a release inside the bounded window proves it was not.
        assert_epmd_lock_released(&lock_path, &metadata);
        child.kill().unwrap();
        child.wait().unwrap();
        remove_epmd_owner_artifacts(&data).unwrap();
        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn owned_epmd_watch_reaps_a_crash_and_reports_health_loss() {
        let sleep = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix sleep executable");
        let epmd = Command::new(sleep).arg("30").spawn().unwrap();
        let epmd_pid = epmd.id() as i32;
        let failure = EpmdRuntimeWatch::new(Some(epmd), Ipv4Addr::LOCALHOST, 65_300).supervise();

        runtime::send_signal(epmd_pid, libc::SIGKILL).unwrap();
        let reason = failure.blocking_recv().unwrap();
        assert!(reason.contains("owned EPMD"), "{reason}");
        assert!(
            !runtime::pid_alive(epmd_pid),
            "the EPMD child was not reaped"
        );
    }

    #[test]
    fn failed_startup_validation_reaps_its_own_epmd_and_never_an_incumbent() {
        let data = scratch("epmd-reap-failed-start");
        create(&data, None, "owner", "127.0.0.1", Ports::DEFAULT).unwrap();
        let profile = assign_free_loopback_epmd_port(&data);

        // The exact shape start_owned_epmd leaves behind: a foreground child holding the
        // inherited flock, and a durable marker naming that lock's inode.
        let lock_path = epmd_owner_lock_path(&data);
        let lock = create_epmd_lock(&lock_path).unwrap();
        let lock_metadata = lock.metadata().unwrap();
        let sleep = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix sleep executable");
        let mut command = Command::new(sleep);
        inherit_epmd_lock_on_exec(&mut command, lock.as_raw_fd());
        let child = command.arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        drop(lock);
        assert!(epmd_lock_held(&lock_path, lock_metadata.dev(), lock_metadata.ino()).unwrap());

        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let executable_metadata = fs::symlink_metadata(&executable).unwrap();
        let owner = EpmdOwner {
            schema: EPMD_OWNER_SCHEMA,
            fleet_id: profile.fleet_id.clone(),
            host: profile.host.clone(),
            address: Ipv4Addr::LOCALHOST,
            port: profile.epmd_port,
            pid,
            executable,
            executable_dev: executable_metadata.dev(),
            executable_ino: executable_metadata.ino(),
            lock_dev: lock_metadata.dev(),
            lock_ino: lock_metadata.ino(),
        };
        write_private_new(
            &epmd_owner_path(&data),
            &serde_json::to_vec_pretty(&owner).unwrap(),
            "test EPMD ownership marker",
        )
        .unwrap();

        let watch = EpmdRuntimeWatch::new(Some(child), Ipv4Addr::LOCALHOST, profile.epmd_port);
        assert!(watch.reap_spawned(&data).unwrap());
        assert!(
            !runtime::pid_alive(pid),
            "the launched EPMD survived the failed start"
        );
        assert!(!epmd_owner_path(&data).try_exists().unwrap());
        assert!(!epmd_owner_lock_path(&data).try_exists().unwrap());

        // A reused compatible incumbent has no child here; reaping must refuse to touch
        // anything and say that nothing was stopped.
        let incumbent = EpmdRuntimeWatch::new(None, Ipv4Addr::LOCALHOST, profile.epmd_port);
        assert!(!incumbent.reap_spawned(&data).unwrap());

        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn aborting_a_boot_watch_kills_the_spawned_child_and_never_an_incumbent() {
        let data = scratch("epmd-abort-boot");
        create(&data, None, "owner", "127.0.0.1", Ports::DEFAULT).unwrap();
        let sleep = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix sleep executable");
        let child = Command::new(sleep).arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let mut watch = EpmdRuntimeWatch::new(Some(child), Ipv4Addr::LOCALHOST, 65_301);
        watch.abort_spawned(&data);
        assert!(
            !runtime::pid_alive(pid),
            "Drop/cancellation must stop the packaged EPMD this start launched"
        );

        let mut incumbent = EpmdRuntimeWatch::new(None, Ipv4Addr::LOCALHOST, 65_301);
        incumbent.abort_spawned(&data);
        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn doctor_warns_when_pinned_ports_sit_inside_the_ephemeral_range() {
        let first_generation = Profile {
            tags: empty_tags(),
            schema: PROFILE_SCHEMA,
            fleet_id: "cafecafecafecafecafecafe".into(),
            name: "lab".into(),
            machine: "vps".into(),
            host: "127.0.0.1".into(),
            node: "ouro-vps@127.0.0.1".into(),
            role: "core".into(),
            members: vec![member("vps", "127.0.0.1")],
            tombstones: Vec::new(),
            roster_revision: initial_roster_revision(),
            // The exact exposure a real enrollment died on: gateway and distribution
            // pinned inside Linux's default ephemeral range, EPMD safely below it.
            gateway_port: 47_704,
            epmd_port: 14_321,
            dist_port_min: 43_700,
            dist_port_max: 43_729,
        };
        let warnings = ephemeral_overlap_warnings(&first_generation, (32_768, 60_999));
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("47704"), "{}", warnings[0]);
        assert!(warnings[0].contains("eaddrinuse"), "{}", warnings[0]);
        assert!(warnings[1].contains("43700-43729"), "{}", warnings[1]);

        let current_defaults = Profile {
            gateway_port: default_gateway_port("cafecafecafecafecafecafe", "vps"),
            epmd_port: default_epmd_port("cafecafecafecafecafecafe"),
            dist_port_min: DEFAULT_DIST_PORT_MIN,
            dist_port_max: DEFAULT_DIST_PORT_MAX,
            ..first_generation
        };
        assert_eq!(
            ephemeral_overlap_warnings(&current_defaults, (32_768, 60_999)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn reused_epmd_watch_reports_loss_without_signalling_any_process() {
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let stop = Arc::new(AtomicBool::new(false));
        let server = fake_epmd(port, stop.clone());
        let sleep = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix sleep executable");
        let mut unrelated = Command::new(sleep).arg("30").spawn().unwrap();
        let unrelated_pid = unrelated.id() as i32;
        let failure = EpmdRuntimeWatch::new(None, Ipv4Addr::LOCALHOST, port).supervise();

        assert!(epmd_responds(Ipv4Addr::LOCALHOST, port));
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();
        let reason = failure.blocking_recv().unwrap();
        assert!(reason.contains("consecutive NAMES probes"), "{reason}");
        assert!(
            runtime::pid_alive(unrelated_pid),
            "the listener watch signalled a process it did not own"
        );
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
    }

    #[test]
    fn leave_preserves_an_unowned_compatible_epmd_and_all_credentials() {
        let data = scratch("epmd-unowned-leave");
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        let profile = assign_free_loopback_epmd_port(&data);
        let stop = Arc::new(AtomicBool::new(false));
        let server = fake_epmd(profile.epmd_port, stop.clone());

        let error = leave(&data).unwrap_err().to_string();
        assert!(
            error.contains("no positive Ouroboros ownership lease"),
            "{error}"
        );
        assert!(error.contains("was not killed"), "{error}");
        assert!(fleet_dir(&data).join(COOKIE_FILE).exists());
        assert!(profile_path(&data).exists());

        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();
        assert!(leave(&data).unwrap().is_some());
        assert!(!fleet_dir(&data).exists());
        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn stale_epmd_marker_cleanup_ignores_a_reused_numeric_pid_without_lock_or_listener() {
        let data = scratch("epmd-reused-pid");
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        let profile = assign_free_loopback_epmd_port(&data);
        let lock_path = epmd_owner_lock_path(&data);
        let lock = create_epmd_lock(&lock_path).unwrap();
        let lock_metadata = lock.metadata().unwrap();
        drop(lock);
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let executable_metadata = fs::symlink_metadata(&executable).unwrap();
        let owner = EpmdOwner {
            schema: EPMD_OWNER_SCHEMA,
            fleet_id: profile.fleet_id.clone(),
            host: profile.host.clone(),
            address: Ipv4Addr::LOCALHOST,
            port: profile.epmd_port,
            pid: std::process::id() as i32,
            executable,
            executable_dev: executable_metadata.dev(),
            executable_ino: executable_metadata.ino(),
            lock_dev: lock_metadata.dev(),
            lock_ino: lock_metadata.ino(),
        };
        write_private_new(
            &epmd_owner_path(&data),
            &serde_json::to_vec_pretty(&owner).unwrap(),
            "test stale EPMD ownership marker",
        )
        .unwrap();

        assert!(
            runtime::pid_alive(owner.pid),
            "the fixture PID must be live"
        );
        assert!(leave(&data).unwrap().is_some());
        assert!(
            runtime::pid_alive(owner.pid),
            "leave targeted an unrelated PID"
        );
        assert!(!fleet_dir(&data).exists());
        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn leave_retires_owned_epmd_after_address_change_and_release_gc() {
        let data = scratch("epmd-upgrade-leave");
        create(&data, None, "leaf", "127.0.0.1", ephemeral_ports()).unwrap();
        let profile = assign_free_loopback_epmd_port(&data);
        let lock_path = epmd_owner_lock_path(&data);
        let lock = create_epmd_lock(&lock_path).unwrap();
        let lock_metadata = lock.metadata().unwrap();

        let sleep = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix sleep executable");
        let mut command = Command::new(sleep);
        inherit_epmd_lock_on_exec(&mut command, lock.as_raw_fd());
        let mut child = command.arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let waiter = thread::spawn(move || child.wait().unwrap());
        drop(lock);
        assert!(epmd_lock_held(&lock_path, lock_metadata.dev(), lock_metadata.ino()).unwrap());

        let historical_program = data.join("deleted-release-epmd");
        write_private_new(&historical_program, b"#!/bin/sh\nexit 1\n", "test EPMD").unwrap();
        fs::set_permissions(&historical_program, fs::Permissions::from_mode(0o700)).unwrap();
        let historical_metadata = fs::symlink_metadata(&historical_program).unwrap();
        fs::remove_file(&historical_program).unwrap();

        let current_program = data.join("current-release-epmd");
        write_private_new(
            &current_program,
            format!("#!/bin/sh\nkill -TERM {pid}\n").as_bytes(),
            "test EPMD control",
        )
        .unwrap();
        fs::set_permissions(&current_program, fs::Permissions::from_mode(0o700)).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let server = fake_epmd(profile.epmd_port, stop.clone());
        let stop_after_pid = stop.clone();
        let listener_watcher = thread::spawn(move || {
            while runtime::pid_alive(pid) {
                thread::sleep(Duration::from_millis(5));
            }
            stop_after_pid.store(true, Ordering::Relaxed);
        });

        let owner = EpmdOwner {
            schema: EPMD_OWNER_SCHEMA,
            fleet_id: profile.fleet_id.clone(),
            host: profile.host.clone(),
            // Model a private DNS/Tailscale change: this is the address recorded when
            // EPMD started, but only its mandatory loopback listener remains reachable.
            address: Ipv4Addr::new(10, 255, 254, 253),
            port: profile.epmd_port,
            pid,
            executable: historical_program.clone(),
            executable_dev: historical_metadata.dev(),
            executable_ino: historical_metadata.ino(),
            lock_dev: lock_metadata.dev(),
            lock_ino: lock_metadata.ino(),
        };
        write_private_new(
            &epmd_owner_path(&data),
            &serde_json::to_vec_pretty(&owner).unwrap(),
            "test EPMD ownership marker",
        )
        .unwrap();
        assert_eq!(
            ensure_owned_epmd_listener_state(&owner).unwrap(),
            OwnedEpmdListenerState::LoopbackOnly
        );

        let fallback = leave(&data).unwrap_err().to_string();
        assert!(
            fallback.contains("recorded by the ownership marker is unavailable"),
            "{fallback}"
        );
        assert!(profile_path(&data).exists());
        assert!(runtime::pid_alive(pid));

        assert!(leave_with_epmd(&data, &current_program).unwrap().is_some());
        assert!(!fleet_dir(&data).exists());
        assert!(!runtime::pid_alive(pid));
        waiter.join().unwrap();
        listener_watcher.join().unwrap();
        server.join().unwrap();

        fs::remove_file(current_program).unwrap();
        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn startup_retires_loopback_only_owned_epmd_before_rebinding_changed_address() {
        let data = scratch("epmd-address-change-start");
        create(&data, None, "leaf", "127.0.0.1", ephemeral_ports()).unwrap();
        let profile = assign_free_loopback_epmd_port(&data);
        let lock_path = epmd_owner_lock_path(&data);
        let lock = create_epmd_lock(&lock_path).unwrap();
        let lock_metadata = lock.metadata().unwrap();

        let sleep = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix sleep executable");
        let mut command = Command::new(sleep);
        inherit_epmd_lock_on_exec(&mut command, lock.as_raw_fd());
        let mut child = command.arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let waiter = thread::spawn(move || child.wait().unwrap());
        drop(lock);
        assert!(epmd_lock_held(&lock_path, lock_metadata.dev(), lock_metadata.ino()).unwrap());

        let current_program = data.join("current-release-epmd");
        write_private_new(
            &current_program,
            format!("#!/bin/sh\nkill -TERM {pid}\n").as_bytes(),
            "test EPMD control",
        )
        .unwrap();
        fs::set_permissions(&current_program, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = current_program.canonicalize().unwrap();
        let executable_metadata = fs::symlink_metadata(&executable).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let server = fake_epmd(profile.epmd_port, stop.clone());
        let stop_after_pid = stop.clone();
        let listener_watcher = thread::spawn(move || {
            while runtime::pid_alive(pid) {
                thread::sleep(Duration::from_millis(5));
            }
            stop_after_pid.store(true, Ordering::Relaxed);
        });

        let owner = EpmdOwner {
            schema: EPMD_OWNER_SCHEMA,
            fleet_id: profile.fleet_id.clone(),
            host: profile.host.clone(),
            address: Ipv4Addr::new(10, 255, 254, 252),
            port: profile.epmd_port,
            pid,
            executable,
            executable_dev: executable_metadata.dev(),
            executable_ino: executable_metadata.ino(),
            lock_dev: lock_metadata.dev(),
            lock_ino: lock_metadata.ino(),
        };
        write_private_new(
            &epmd_owner_path(&data),
            &serde_json::to_vec_pretty(&owner).unwrap(),
            "test EPMD ownership marker",
        )
        .unwrap();

        let error = match ensure_owned_epmd_for_runtime(&data, &current_program) {
            Ok(_) => panic!("the replacement fixture should exit before publishing EPMD"),
            Err(error) => format!("{error:#}"),
        };
        assert!(
            error.contains("packaged EPMD exited before owning 127.0.0.1"),
            "{error}"
        );
        assert!(
            !epmd_owner_path(&data).exists() && !epmd_owner_lock_path(&data).exists(),
            "the old ownership identity or failed replacement lock was stranded"
        );
        assert_eq!(
            ensure_epmd_port_available(&profile.host, profile.epmd_port).unwrap(),
            EpmdPortState::Available
        );
        assert!(profile_path(&data).exists());

        waiter.join().unwrap();
        listener_watcher.join().unwrap();
        server.join().unwrap();
        fs::remove_file(current_program).unwrap();
        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn ownership_identity_uses_the_recorded_private_address_not_mutable_dns() {
        let mut profile = sample_profile("studio-mini");
        profile.host = "changed-after-start.invalid".into();
        profile.node = member(&profile.machine, &profile.host).node;
        profile.members = vec![member(&profile.machine, &profile.host)];
        let owner = EpmdOwner {
            schema: EPMD_OWNER_SCHEMA,
            fleet_id: profile.fleet_id.clone(),
            host: profile.host.clone(),
            address: Ipv4Addr::new(10, 9, 8, 7),
            port: profile.epmd_port,
            pid: 42,
            executable: PathBuf::from("/deleted/release/erts/bin/epmd"),
            executable_dev: 1,
            executable_ino: 2,
            lock_dev: 3,
            lock_ino: 4,
        };

        validate_epmd_owner(&owner, &profile).unwrap();
    }

    #[test]
    fn create_refuses_an_advertised_private_address_not_assigned_locally() {
        let unavailable = (1_u8..=254)
            .map(|last| Ipv4Addr::new(10, 255, 254, last))
            .find(|address| TcpListener::bind((*address, 0)).is_err())
            .expect("at least one RFC1918 test address is not assigned to this test host");

        let created = scratch("nonlocal-create");
        let error = create(
            &created,
            None,
            "owner",
            &unavailable.to_string(),
            ephemeral_ports(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("not assigned to a local interface"),
            "{error}"
        );
        assert!(!fleet_dir(&created).exists());

        fs::remove_dir_all(created).ok();
    }

    #[test]
    fn installed_cookie_validation_matches_the_beam_exactly() {
        for malformed in [
            "a".repeat(63),
            "A".repeat(64),
            format!("{}\n", "a".repeat(64)),
        ] {
            let error = validate_cookie(&malformed, "installed cookie")
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("exactly 64 lowercase hexadecimal"),
                "{error}"
            );
        }
        validate_cookie(&"a".repeat(64), "installed cookie").unwrap();

        let owner = scratch("cookie-owner");
        create(&owner, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        write_private_atomic(&fleet_dir(&owner).join(COOKIE_FILE), &[b'A'; 64]).unwrap();
        let report = doctor(&owner);
        assert!(!report.healthy);
        assert!(
            report.text.contains("exactly 64 lowercase hexadecimal"),
            "{}",
            report.text
        );

        fs::remove_dir_all(owner).ok();
    }

    #[test]
    fn doctor_rejects_installed_key_mismatches_before_beam_uses_them() {
        let owner = scratch("tls-installed-owner");
        let other_owner = scratch("tls-installed-other");
        create(&owner, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        create(
            &other_owner,
            None,
            "other-owner",
            "127.0.0.1",
            ephemeral_ports(),
        )
        .unwrap();

        let unrelated_node_key = KeyPair::generate().unwrap().serialize_pem();
        write_private_atomic(
            &fleet_dir(&owner).join(NODE_KEY_FILE),
            unrelated_node_key.as_bytes(),
        )
        .unwrap();
        let report = doctor(&owner);
        assert!(!report.healthy);
        assert!(
            report.text.contains("node private key does not match"),
            "{}",
            report.text
        );

        // An unrelated authority's node certificate is not this machine's identity, even
        // though both are well-formed: doctor compares the installed pair, not its shape.
        let other_node_cert =
            fs::read_to_string(fleet_dir(&other_owner).join(NODE_CERT_FILE)).unwrap();
        let other_node_key =
            fs::read_to_string(fleet_dir(&other_owner).join(NODE_KEY_FILE)).unwrap();
        write_private_atomic(
            &fleet_dir(&owner).join(NODE_CERT_FILE),
            other_node_cert.as_bytes(),
        )
        .unwrap();
        write_private_atomic(
            &fleet_dir(&owner).join(NODE_KEY_FILE),
            other_node_key.as_bytes(),
        )
        .unwrap();
        let report = doctor(&owner);
        assert!(!report.healthy);
        assert!(
            report.text.contains("node certificate") || report.text.contains("CA"),
            "{}",
            report.text
        );

        fs::remove_dir_all(owner).ok();
        fs::remove_dir_all(other_owner).ok();
    }

    #[test]
    fn startup_and_doctor_reject_any_generated_tls_or_vm_policy_drift() {
        let data = scratch("generated-policy-drift");
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        let root = fleet_dir(&data);
        let original_tls = fs::read_to_string(root.join(TLS_OPTFILE)).unwrap();
        let weakened = original_tls.replace("verify_peer", "verify_none");
        assert_ne!(weakened, original_tls);
        write_private_atomic(&root.join(TLS_OPTFILE), weakened.as_bytes()).unwrap();

        let startup = runtime_env(&data).unwrap_err().to_string();
        assert!(
            startup.contains("strict generated mutual-TLS policy"),
            "{startup}"
        );
        let report = doctor(&data);
        assert!(!report.healthy);
        assert!(
            report.text.contains("strict generated mutual-TLS policy"),
            "{}",
            report.text
        );

        write_private_atomic(&root.join(TLS_OPTFILE), original_tls.as_bytes()).unwrap();
        let original_vm = fs::read_to_string(root.join(VM_ARGS_FILE)).unwrap();
        let wrong_path = original_vm.replace("ssl_dist.conf", "other.conf");
        assert_ne!(wrong_path, original_vm);
        write_private_atomic(&root.join(VM_ARGS_FILE), wrong_path.as_bytes()).unwrap();
        let startup = runtime_env(&data).unwrap_err().to_string();
        assert!(startup.contains("generated TLS/port policy"), "{startup}");
        let report = doctor(&data);
        assert!(!report.healthy);
        assert!(
            report.text.contains("generated TLS/port policy"),
            "{}",
            report.text
        );

        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn leave_refuses_unknown_files_before_deleting_any_known_secret() {
        let data = scratch("leave-unknown");
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        write_private_atomic(&fleet_dir(&data).join("operator-note"), b"keep me").unwrap();
        let error = leave(&data).unwrap_err().to_string();
        assert!(error.contains("unknown entries"), "{error}");
        assert!(fleet_dir(&data).join(COOKIE_FILE).exists());

        fs::remove_file(fleet_dir(&data).join("operator-note")).unwrap();
        assert!(leave(&data).unwrap().is_some());
        assert!(!fleet_dir(&data).exists());
        assert!(leave(&data).unwrap().is_none());
        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn leave_removes_only_the_exact_private_cluster_checkpoint_shape() {
        let data = scratch("leave-cluster-directory");
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        let cluster = fleet_dir(&data).join(CLUSTER_DIRECTORY_DIR);
        let checkpoints = cluster.join(CLUSTER_CHECKPOINTS_DIR);
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&checkpoints)
            .unwrap();
        write_private_new(
            &checkpoints.join(CLUSTER_CHECKPOINT_FILE),
            b"node-name-only checkpoint",
            "cluster checkpoint fixture",
        )
        .unwrap();
        write_private_new(
            &checkpoints.join(format!("{CLUSTER_CHECKPOINT_FILE}.tmp-Abcdefghijkl_123")),
            b"interrupted atomic checkpoint",
            "cluster checkpoint temporary fixture",
        )
        .unwrap();

        assert!(leave(&data).unwrap().is_some());
        assert!(!fleet_dir(&data).exists());

        let unsafe_data = scratch("leave-cluster-directory-symlink");
        create(&unsafe_data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        let cluster = fleet_dir(&unsafe_data).join(CLUSTER_DIRECTORY_DIR);
        let checkpoints = cluster.join(CLUSTER_CHECKPOINTS_DIR);
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&checkpoints)
            .unwrap();
        let target = unsafe_data.join("checkpoint-target");
        write_private_new(&target, b"must remain", "checkpoint target").unwrap();
        std::os::unix::fs::symlink(&target, checkpoints.join(CLUSTER_CHECKPOINT_FILE)).unwrap();
        let error = leave(&unsafe_data).unwrap_err().to_string();
        assert!(error.contains("private regular"), "{error}");
        assert!(fleet_dir(&unsafe_data).join(COOKIE_FILE).exists());
        assert_eq!(fs::read(&target).unwrap(), b"must remain");

        fs::remove_dir_all(data).ok();
        fs::remove_dir_all(unsafe_data).ok();
    }

    #[test]
    fn validation_errors_teach_the_expected_shape() {
        let data = scratch("validation");
        let machine = create(&data, None, "bad name", "127.0.0.1", ephemeral_ports())
            .unwrap_err()
            .to_string();
        assert!(machine.contains("studio-mini"), "{machine}");
        let host = create(&data, None, "good", "name@host", ephemeral_ports())
            .unwrap_err()
            .to_string();
        assert!(host.contains("Tailscale"), "{host}");
        let port = create(
            &data,
            None,
            "good",
            "127.0.0.1",
            Ports {
                gateway: None,
                dist: Some(4369),
                epmd: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(port.contains("reserved for EPMD"), "{port}");
        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn beginner_identity_can_derive_a_safe_machine_label_from_an_explicit_host() {
        let identity = resolve_identity(None, Some("Studio_Mini.tailnet.ts.net")).unwrap();
        assert_eq!(identity.machine, "studio-mini");
        assert_eq!(identity.host, "Studio_Mini.tailnet.ts.net");
        assert!(identity.inferred_machine);
        assert!(!identity.inferred_host);

        assert_eq!(machine_from_host("10.2.3.4").unwrap(), "10-2-3-4");
    }

    #[test]
    fn inferred_local_only_or_mdns_names_require_an_explicit_host_choice() {
        for host in ["localhost", "127.0.0.1", "studio-mini", "studio-mini.local"] {
            let error = validate_inferred_host(host).unwrap_err().to_string();
            assert!(error.contains("explicit `--host HOST`"), "{host}: {error}");
            assert!(error.contains("same-host labs"), "{host}: {error}");
        }
    }

    #[test]
    fn stale_publication_status_recommends_restart_not_attach() {
        let data = scratch("stale-status-guidance");
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        write_private_atomic(
            &data.join(runtime::PUBLICATION_FILE),
            br#"{"port":47004,"protocol":1,"node":"ouro-owner@127.0.0.1","pid":2147483647,"scope":"operate"}"#,
        )
        .unwrap();

        let rendered = render_status(&data).unwrap();
        assert!(rendered.contains("stale publication"), "{rendered}");
        assert!(rendered.contains("Next: `ouro daemon`"), "{rendered}");
        assert!(!rendered.contains("`ouro attach --print`"), "{rendered}");

        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn summary_never_contains_secret_material() {
        let data = scratch("summary");
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
        let cookie = fs::read_to_string(fleet_dir(&data).join(COOKIE_FILE)).unwrap();
        let rendered = format!("{:?}", summary(&data));
        assert!(!rendered.contains(cookie.trim()));
        assert!(rendered.contains("owner"));
        fs::remove_dir_all(data).ok();
    }

    #[test]
    fn doctor_merges_live_errors_into_the_local_report() {
        let local = build_doctor_report(
            Path::new("/tmp/fleet-doctor-fixture"),
            vec![
                ok("local TLS material is private"),
                warn("service inactive"),
            ],
            "local checks only",
        );
        assert!(local.healthy);

        let live = merge_live_doctor(
            local,
            &serde_json::json!({
                "healthy?": false,
                "checks": [
                    {"id": "distribution", "status": "ok", "message": "BEAM distribution is running"},
                    {
                        "id": "machine_connectivity",
                        "status": "error",
                        "message": "alpha is offline; Ouroboros will keep retrying",
                        "guidance": "Start Ouroboros on alpha and check EPMD"
                    }
                ]
            }),
        );
        assert!(!live.healthy);
        assert!(live.text.contains("live runtime: alpha is offline"));
        assert!(live.text.contains("Next: Start Ouroboros on alpha"));
        assert!(live.text.contains("live runtime + local profile"));

        let healthy_live = merge_live_doctor(
            build_doctor_report(
                Path::new("/tmp/fleet-doctor-fixture"),
                vec![ok("local")],
                "local",
            ),
            &serde_json::json!({
                "healthy?": true,
                "checks": [{
                    "id": "distribution",
                    "status": "ok",
                    "message": "BEAM distribution is running",
                    "guidance": "stale compatibility guidance must stay hidden"
                }]
            }),
        );
        assert!(healthy_live.healthy);
        assert!(healthy_live
            .text
            .contains("live runtime: BEAM distribution is running"));
        assert!(!healthy_live.text.contains("stale compatibility guidance"));

        let malformed = merge_live_doctor(
            build_doctor_report(
                Path::new("/tmp/fleet-doctor-fixture"),
                vec![ok("local")],
                "local",
            ),
            &serde_json::json!({"healthy?": true, "checks": [{"status": "future"}]}),
        );
        assert!(!malformed.healthy);
        assert!(malformed.text.contains("unreadable response"));

        let stopped = doctor_stopped(build_doctor_report(
            Path::new("/tmp/fleet-doctor-fixture"),
            vec![ok("local")],
            "local",
        ));
        assert!(stopped.text.contains("local checks only (runtime stopped)"));
        assert!(stopped
            .text
            .contains("live remote compatibility and connectivity were not checked"));
    }
}
