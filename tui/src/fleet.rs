//! This machine's cluster identity, and the bundle that carries a fleet to a second one.
//!
//! `create` mints the identity — node name, private cookie, a self-signed CA and node
//! certificate for TLS distribution, one distribution port — and `runtime_env` turns it
//! into the environment the packaged release boots with. The profile deliberately
//! contains only non-secret facts: the BEAM cookie, the node key and the CA key live in
//! separate mode-0600 files and are passed to the release by path.
//!
//! One fleet is one shared secret set (`docs/proposals/fleet-kiss.md` §1): every member
//! holds the cookie and the CA pair, and each mints its own leaf. [`bundle`] reads that
//! set out of this machine's fleet directory and [`join`] installs it on another. There
//! is no EPMD daemon, no per-member certificate ceremony, no receipt and no replicated
//! roster — `members` is a list of dial hints, and nothing here writes another machine's
//! profile.

use std::collections::BTreeSet;
use std::ffi::CStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, ToSocketAddrs};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
/// One number per fleet (§2). The reserved range above stays reserved so a test never
/// collides with a live same-host lab that predates this simplification.
pub const DEFAULT_DIST_PORT: u16 = 13_700;
const PROFILE_SCHEMA: u8 = 2;
const MAX_CA_VALIDITY_DAYS: i64 = 12 * 366;
const MAX_NODE_VALIDITY_DAYS: i64 = 7 * 366;
const STAGING_PREFIX: &str = ".fleet.setup.";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Member {
    pub machine: String,
    pub host: String,
    pub node: String,
    /// That member's TLS distribution listener, which is how a peer reaches it without
    /// an EPMD daemon to ask (§4).
    pub dist_port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Profile {
    pub schema: u8,
    pub fleet_id: String,
    pub name: String,
    pub machine: String,
    pub host: String,
    pub node: String,
    pub role: String,
    /// This node's own TLS distribution listener. One number per fleet in production;
    /// per-member so two nodes can share one host in the lab and in tests.
    pub dist_port: u16,
    pub gateway_port: u16,
    /// Every machine this one knows, always including itself. Dial hints, never a
    /// replicated roster: nothing here is written on another machine (§1).
    pub members: Vec<Member>,
    #[serde(default = "empty_tags")]
    pub tags: Value,
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    /// `None` uses `DEFAULT_DIST_PORT`. An explicit port is what lets several nodes
    /// share one host in the lab and in tests.
    pub dist: Option<u16>,
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
    };
}

/// Distinct free loopback ports for one test fleet. Suites must never touch the
/// production port spaces — the reserved distribution range and the derived gateway
/// space — because a live same-host lab legitimately occupies them. OS-assigned ports
/// are screened against both so a test never collides with that lab.
/// Public so `tui/tests/` can honour the same rule: an integration test that creates a
/// fleet chooses its ports here rather than letting `create` use production ones.
#[doc(hidden)]
pub fn ephemeral_ports() -> Ports {
    let mut held = Vec::new();
    let mut ports = Vec::new();
    while ports.len() < 2 {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free ephemeral loopback port");
        let port = listener
            .local_addr()
            .expect("a bound loopback address")
            .port();
        // Keeping both allocations bound until both are chosen makes them distinct.
        held.push(listener);
        if port != 65_358
            && port != 4369
            && !(DEFAULT_DIST_PORT_MIN..=DEFAULT_DIST_PORT_MAX).contains(&port)
            && !(DEFAULT_GATEWAY_BASE..DEFAULT_GATEWAY_BASE + DEFAULT_GATEWAY_SPAN).contains(&port)
        {
            ports.push(port);
        }
    }
    Ports {
        gateway: Some(ports[0]),
        dist: Some(ports[1]),
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

/// The one sentence a profile written before the fleet simplification gets.
///
/// §2 and §12: there is no migration, and a machine on a schema-1 profile cannot form a
/// fleet with a schema-2 machine. `ouro fleet status`, `ouro fleet doctor` and the
/// launcher all reach this through [`load`].
pub const SCHEMA_1_SENTENCE: &str = "this fleet was created by an older Ouroboros; run `ouro fleet leave` here and set the fleet up again.";

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
                "{} exists without {}. Restore profile.json from a backup to keep this machine's cluster identity, or run `ouro fleet leave` on this stopped machine to clear it and set the fleet up again",
                fleet_dir(data_dir).display(),
                path.display()
            );
        }
        return Ok(None);
    }

    let text = read_private(&path, "fleet profile")?;
    // The schema is read before the document is shaped. A schema-1 profile cannot
    // deserialize into schema 2 at all, and its operator has to get §2's sentence rather
    // than a serde message about a field that no longer exists.
    let document: Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a valid fleet profile", path.display()))?;
    match document.get("schema").and_then(Value::as_u64) {
        Some(schema) if schema == u64::from(PROFILE_SCHEMA) => {}
        Some(schema) if schema > u64::from(PROFILE_SCHEMA) => bail!(
            "fleet profile schema {schema} was written by a newer Ouroboros than this one (supports {PROFILE_SCHEMA}); upgrade this machine"
        ),
        _ => bail!("{SCHEMA_1_SENTENCE}"),
    }
    let profile: Profile = serde_json::from_value(document)
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

/// Take a machine out of *this* machine's roster.
///
/// The roster is not replicated and never was (§1): this writes
/// `<data dir>/fleet/profile.json` here and nowhere else, and a stale entry on another
/// machine costs that machine a backed-off dial and nothing else. Both `ouro fleet
/// forget NAME` and the local half of `ouro fleet leave --machine NAME` are this edit.
pub fn remove_member(data_dir: &Path, machine: &str) -> Result<Member> {
    let _lock = lock_live_fleet_update(data_dir, "ouro fleet forget")?;
    remove_member_locked(data_dir, machine)
}

/// `ouro fleet forget NAME`: the local answer to a machine that cannot be reached.
///
/// The command name is the operator's statement. There is no tombstone and no restore:
/// the runtime is asked separately to retire the machine's session-owner evidence, and
/// it refuses while that machine is connected.
pub fn forget_machine(data_dir: &Path, machine: &str) -> Result<Member> {
    remove_member(data_dir, machine)
}

/// The edit itself, for a caller that already holds the lifecycle lock. The lock is not
/// re-entrant — it is a same-user pid claim, and a second claim sees the first as a live
/// holder — so the locking entry point above and this one are the same edit, split at
/// the lock.
fn remove_member_locked(data_dir: &Path, machine: &str) -> Result<Member> {
    let mut profile = load(data_dir)?
        .context("this machine is standalone; there is no cluster roster to edit")?;
    if same_name(machine, &profile.machine) || same_name(machine, &profile.node) {
        bail!(
            "{machine} is this machine; `ouro fleet leave` retires its own identity, and `ouro fleet forget` edits this machine's view of the others"
        );
    }
    let Some(index) = profile
        .members
        .iter()
        .position(|entry| same_name(&entry.machine, machine) || same_name(&entry.node, machine))
    else {
        bail!(
            "this machine's roster has no member named {machine}; `ouro fleet status` prints the names it knows"
        );
    };
    let removed = profile.members.remove(index);
    write_profile(data_dir, &profile).context("taking the machine out of this machine's roster")?;
    Ok(removed)
}

/// Add another machine to *this* machine's roster.
///
/// This is the local half of `ouro fleet add`: the operator's own list gains the machine
/// that was just installed. It takes the live lock rather than requiring a stopped
/// runtime, because the running node re-reads the profile on its next reconnect sweep
/// (about a second later) and starts dialing the new member without a restart.
pub fn add_member(
    data_dir: &Path,
    machine: &str,
    host: &str,
    dist_port: u16,
    node: Option<&str>,
) -> Result<Member> {
    // Checked before the lock is taken, so a typo never waits on another lifecycle
    // command; `add_member_locked` checks the same things again for the caller that
    // arrives already holding it.
    validate_machine(machine)?;
    validate_host(host)?;
    validate_port(dist_port, "distribution port")?;
    let _lock = lock_live_fleet_update(data_dir, "ouro fleet add")?;
    add_member_locked(data_dir, machine, host, dist_port, node)
}

/// The edit itself, for a caller that already holds the lifecycle lock.
fn add_member_locked(
    data_dir: &Path,
    machine: &str,
    host: &str,
    dist_port: u16,
    node: Option<&str>,
) -> Result<Member> {
    let added = member(machine, host, dist_port);
    if let Some(node) = node {
        if node != added.node {
            bail!(
                "machine `{machine}` at `{host}` is node {}, not {node}; a node name is always `ouro-<machine>@<host>`",
                added.node
            );
        }
    }
    let mut profile = load(data_dir)?.context(
        "this machine is standalone; `ouro fleet setup` gives it a cluster identity before it can have a roster",
    )?;
    if let Some(existing) = profile
        .members
        .iter()
        .find(|entry| same_name(&entry.machine, machine) || same_name(&entry.node, &added.node))
    {
        if existing == &added {
            return Ok(added);
        }
        bail!(
            "this machine's roster already names {} as {} on distribution port {}; `ouro fleet forget {}` first if its address changed",
            existing.machine,
            existing.node,
            existing.dist_port,
            existing.machine
        );
    }
    if profile.members.len() >= MAX_MEMBERS {
        bail!("this machine's roster already holds the maximum of {MAX_MEMBERS} members");
    }
    profile.members.push(added.clone());
    profile
        .members
        .sort_by(|left, right| left.node.cmp(&right.node));
    write_profile(data_dir, &profile).context("adding the machine to this machine's roster")?;
    Ok(added)
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
    let dist_port = ports.dist.unwrap_or(DEFAULT_DIST_PORT);
    let member = member(machine, host, dist_port);
    let profile = Profile {
        schema: PROFILE_SCHEMA,
        fleet_id: fleet_id.clone(),
        name: fleet_name,
        machine: machine.to_string(),
        host: host.to_string(),
        node: member.node.clone(),
        role: "core".to_string(),
        dist_port,
        gateway_port: ports
            .gateway
            .unwrap_or_else(|| default_gateway_port(&fleet_id, machine)),
        members: vec![member.clone()],
        tags: empty_tags(),
    };
    ensure_runtime_ports_available(&profile)?;

    let materials = new_fleet_materials(&profile, &member)?;
    install_new_profile(data_dir, &profile, &materials)?;
    Ok(profile)
}

/// Environment overrides for a packaged runtime. `None` preserves the operator's
/// existing environment workflow exactly; a profile is authoritative when present.
///
/// There is no EPMD daemon any more (§1, §4): the runtime's `-epmd_module` resolves a
/// peer's distribution port out of `OUROBOROS_DIST_PORTS`, which is this profile's
/// members, and listens on `OUROBOROS_DIST_PORT`, which is this machine's own.
pub fn runtime_env(data_dir: &Path) -> Result<Option<Vec<(String, String)>>> {
    let staging = inspect_orphan_staging(data_dir)?;
    if !staging.is_empty() {
        bail!(
            "{} interrupted private fleet setup director{} remain in {}. Refusing to start standalone or distributed runtime until `ouro fleet doctor` is clean; retry `ouro fleet setup` to recover under the lifecycle lock",
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
    let hosts = profile
        .members
        .iter()
        .filter(|member| member.node != profile.node)
        .map(|member| member.node.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let dist_ports = profile
        .members
        .iter()
        .map(|member| format!("{}={}", member.host, member.dist_port))
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
        ("OUROBOROS_DIST_PORT".into(), profile.dist_port.to_string()),
        ("OUROBOROS_DIST_PORTS".into(), dist_ports),
    ]))
}

pub fn render_status(data_dir: &Path) -> Result<String> {
    let Some(profile) = load(data_dir)? else {
        return Ok(format!(
            "Standalone machine\n  No cluster identity is configured in {}.\n\nNext: `ouro fleet setup` gives this machine a node name, a private cookie and TLS materials; `ouro fleet add` brings a second machine in. docs/FLEET.md has the whole recipe.\n",
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
    let mut text = format!(
        "{}\n  fleet id     {}\n  machine      {}\n  address      {}\n  node         {}\n  role         runs agents\n  runtime      {}\n  expected     {} machine{} ({} peer{})\n  transport    TLS (certificate + private cookie file)\n  gateway      127.0.0.1:{}\n  dist port    {}\n",
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
        profile.dist_port
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
    text.push_str(&format!(
        "\nAuthority: this machine's credentials cannot be reissued from anywhere else. Back up {} securely.\n",
        fleet_dir(data_dir).display()
    ));
    text.push_str("\nUse `ouro new --machine NAME --workspace /absolute/path/on/NAME/project` to place an agent; the workspace is the destination path on that machine. Run `ouro fleet doctor` for firewall, certificate, and version guidance.\n");
    Some(text)
}

pub struct DoctorReport {
    pub text: String,
    pub healthy: bool,
    data_dir: PathBuf,
    checks: Vec<Check>,
    scope: String,
}

impl DoctorReport {
    /// What this run covered, for a machine-readable form of the same report.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The checks as `(level, message)` in report order, where the level is the stable
    /// code `[ok]`, `[note]` and `[fix]` stand for in the text.
    pub fn entries(&self) -> Vec<(&'static str, &str)> {
        self.checks
            .iter()
            .map(|check| (check.level.code(), check.message.as_str()))
            .collect()
    }
}

pub fn doctor(data_dir: &Path) -> DoctorReport {
    let mut checks = Vec::new();
    match inspect_orphan_staging(data_dir) {
        Ok(staging) if staging.is_empty() => {}
        Ok(staging) => checks.push(problem(format!(
            "{} interrupted private fleet setup {} outside the active profile. Retry `ouro fleet setup` to clean it safely under the lifecycle lock, then rerun doctor",
            staging.len(),
            if staging.len() == 1 { "remains" } else { "directories remain" }
        ))),
        Err(error) => checks.push(problem(format!(
            "interrupted fleet setup cannot be recovered safely: {error:#}"
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
                    "stopped-runtime preflight found local gateway 127.0.0.1:{} and TLS distribution port {} available",
                    profile.gateway_port, profile.dist_port
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
                            Ok(listener) => drop(listener),
                            Err(error) => checks.push(problem(format!(
                                "local advertised address {address} is not available on this machine: {error}. Fix --host/private DNS, then set this fleet up again before starting"
                            ))),
                        }
                    }
                }
                Err(error) => checks.push(problem(format!(
                    "{} address {} cannot be used safely: {error:#}",
                    member.machine, member.host
                ))),
            }
        }

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

/// What `leave` removed, so the caller can say it out loud.
///
/// `machine` is `None` for a directory whose `profile.json` is missing or unreadable —
/// the state a crash between `install_new_profile`'s staging rename and its fsync
/// leaves. `leave` is the only command that removes a fleet directory, so it has to work
/// on that directory too; what was there is named in `removed` either way.
#[derive(Debug)]
pub struct Removal {
    pub machine: Option<String>,
    pub profile_readable: bool,
    pub removed: Vec<String>,
}

/// Retire this machine's cluster credentials: a stop-gated deletion of `<data dir>/fleet/`.
///
/// There is nothing left to negotiate with. The EPMD daemon is gone (§1) and the
/// receipts are gone (§6), so once the lifecycle lock has proved this data directory is
/// stopped, the whole tree goes.
pub fn leave(data_dir: &Path) -> Result<Option<Removal>> {
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
    // would leave `rm -rf` as the only repair.
    let profile = load(data_dir).unwrap_or_default();
    let removed = remove_fleet_dir(&dir)?;
    Ok(Some(Removal {
        machine: profile.as_ref().map(|profile| profile.machine.clone()),
        profile_readable: profile.is_some(),
        removed,
    }))
}

/// The deletion itself, after the top-level entries have been named for the report.
///
/// `ensure_private_dir` is what refuses a symlink or a directory this user does not own
/// before anything is unlinked; the removal is then the whole tree, because a fleet
/// directory that is missing half its files is exactly the directory `leave` exists for.
fn remove_fleet_dir(dir: &Path) -> Result<Vec<String>> {
    ensure_private_dir(dir)?;
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    fs::remove_dir_all(dir).with_context(|| format!("removing {}", dir.display()))?;
    sync_parent(dir)?;
    Ok(names)
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

/// The two generated files, rendered with the data directory's *canonical* path.
///
/// Canonical, because the same directory is named two ways on this machine's own
/// services: an operator types `/tmp/x` or `~/x`, and the service unit carries the
/// resolved `/private/tmp/x` — and a policy file that spelled the directory one way was
/// refused as "not the generated policy" by a runtime started under the other. On macOS
/// `/tmp` is a symlink, so the first local setup from a web page, whose LaunchAgent
/// names the resolved directory, never started at all.
fn generated_runtime_files(data_dir: &Path, profile: &Profile) -> Result<(String, String)> {
    generated_runtime_files_spelled(&canonical_data_dir(data_dir), profile)
}

/// The data directory with every symlink resolved, or as given when it cannot be.
fn canonical_data_dir(data_dir: &Path) -> PathBuf {
    std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf())
}

/// The generated files with the data directory spelled exactly as given.
///
/// What every Ouroboros before this one wrote, and therefore what an installed profile
/// may still hold. The strict check does not render this spelling back: it resolves the
/// paths the file on disk names instead ([`respelled`]), which accepts any spelling of
/// the one directory and nothing else.
fn generated_runtime_files_spelled(data_dir: &Path, profile: &Profile) -> Result<(String, String)> {
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
        "## Generated by `ouro fleet`; safe to inspect (contains paths, never secrets).\n-proto_dist inet_tls\n-ssl_dist_optfile \"{optfile}\"\n-start_epmd false\n-epmd_module Elixir.Ouroboros.Cluster.Epmd\n-kernel inet_dist_use_interface {{{a},{b},{c},{d}}}\n-kernel inet_dist_listen_min {port} inet_dist_listen_max {port}\n",
        port = profile.dist_port
    );
    Ok((tls, vm_args))
}

/// `text` with every quoted path that resolves to a file directly inside
/// `canonical_root` rewritten in its resolved spelling.
///
/// A policy file that names the fleet directory through a symlink — `/tmp/…` where the
/// service unit says `/private/tmp/…`, or the spelling an older build wrote — then
/// compares equal to the generated one, and a path that resolves anywhere else, or a
/// value that is not a path at all, is left exactly as it is and fails the comparison.
/// The files a generated policy may name inside the fleet directory.
const GENERATED_FILES: [&str; 4] = [CA_CERT_FILE, NODE_CERT_FILE, NODE_KEY_FILE, TLS_OPTFILE];

fn respelled(text: &str, canonical_root: &Path) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('"') {
        out.push_str(&rest[..=open]);
        rest = &rest[open + 1..];
        let Some(close) = rest.find('"') else {
            break;
        };
        let quoted = &rest[..close];
        // The *directory* the file names is what gets resolved, never the file: a
        // symlink somewhere else that points into the fleet directory would resolve
        // into it and read as the generated policy while the file on disk — the one
        // the BEAM hands to `ssl` — still named the outside path, which whoever owns
        // that symlink can point anywhere later. So the spelling has to be a spelling
        // of the fleet directory itself, followed by one of the generated file names.
        let literal = Path::new(quoted);
        let respelled = match (literal.parent(), literal.file_name()) {
            (Some(parent), Some(name)) if GENERATED_FILES.iter().any(|file| name == *file) => {
                parent
                    .canonicalize()
                    .ok()
                    .filter(|directory| directory == canonical_root)
                    .map(|directory| directory.join(name))
            }
            _other => None,
        };
        match respelled.and_then(|path| erl_string(&path).ok()) {
            Some(spelling) => out.push_str(&spelling),
            None => out.push_str(quoted),
        }
        out.push('"');
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
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
        bail!("{SCHEMA_1_SENTENCE}");
    }
    if profile.fleet_id.len() != 24 || !profile.fleet_id.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("fleet profile has an invalid fleet id");
    }
    validate_fleet_name(&profile.name)?;
    validate_machine(&profile.machine)?;
    validate_host(&profile.host)?;
    validate_port(profile.dist_port, "distribution port")?;
    if profile.node != member(&profile.machine, &profile.host, profile.dist_port).node {
        bail!("fleet profile node does not match its machine name and host");
    }
    if profile.role != "core" {
        bail!("fleet profile role must be `core`, got `{}`", profile.role);
    }
    let local = profile
        .members
        .iter()
        .find(|entry| entry.node == profile.node)
        .ok_or_else(|| anyhow!("fleet profile must include this machine in its member list"))?;
    if local.dist_port != profile.dist_port {
        bail!(
            "fleet profile lists this machine on distribution port {} and listens on {}",
            local.dist_port,
            profile.dist_port
        );
    }
    let mut nodes = BTreeSet::new();
    let mut machines = BTreeSet::new();
    for member in &profile.members {
        validate_member(member)?;
        if !nodes.insert(&member.node) {
            bail!("fleet profile repeats node {}", member.node);
        }
        if !machines.insert(&member.machine) {
            bail!("fleet profile repeats machine {}", member.machine);
        }
    }
    validate_port(profile.gateway_port, "gateway port")?;
    if profile.gateway_port == profile.dist_port {
        bail!("local gateway port overlaps the TLS distribution listener port");
    }
    Ok(())
}

/// One roster entry: a name, a reachable host, the node those two spell, and the port
/// that member's distribution listener answers on.
fn validate_member(entry: &Member) -> Result<()> {
    validate_machine(&entry.machine)?;
    validate_host(&entry.host)?;
    validate_port(entry.dist_port, "distribution port")?;
    if entry.node != member(&entry.machine, &entry.host, entry.dist_port).node {
        bail!(
            "fleet member {} has a node that does not match its name and host",
            entry.machine
        );
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
    let local = member(&profile.machine, &profile.host, profile.dist_port);
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
    // A profile written by an earlier build, or under another spelling of a symlinked
    // directory, names the same files another way. The paths the file on disk names are
    // resolved before the comparison, so one policy compares equal however the
    // directory was spelled, and a policy that names anything else does not.
    let canonical_root = fleet_dir(&canonical_data_dir(data_dir));
    let actual_tls_matches = respelled(&actual_tls, &canonical_root) == expected_tls;
    let actual_vm_args_matches =
        respelled(&actual_vm_args, &canonical_root).as_bytes() == expected_vm_args.as_bytes();
    if !actual_tls_matches {
        bail!(
            "{} does not match the strict generated mutual-TLS policy for this profile; startup is refused. Restore this file from a trusted backup, or run `ouro fleet leave` on this stopped machine and set the fleet up again",
            root.join(TLS_OPTFILE).display()
        );
    }
    if !actual_vm_args_matches {
        bail!(
            "{} does not match the generated TLS/port policy for this profile; startup is refused. Restore this file from a trusted backup, or run `ouro fleet leave` on this stopped machine and set the fleet up again",
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
    validate_tls_materials(
        member,
        ca_cert_pem,
        node_cert_pem,
        Some(node_key_pem),
        ca_key_pem,
        description,
    )
}

/// The same check, for the one caller that legitimately holds no private key: an issuer
/// validating a leaf it just minted for a key that lives on another machine. Every rule
/// below applies to both; only the private-key half is conditional.
fn validate_tls_materials(
    member: &Member,
    ca_cert_pem: &str,
    node_cert_pem: &str,
    node_key_pem: Option<&str>,
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

    if let Some(node_key_pem) = node_key_pem {
        let node_key = KeyPair::from_pem(node_key_pem)
            .with_context(|| format!("{description} node private key is invalid"))?;
        if node_key.public_key_der() != node.tbs_certificate.subject_pki.raw {
            bail!("{description} node private key does not match its certificate");
        }
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

pub fn local_hostname() -> Result<String> {
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
    if host.parse::<IpAddr>().is_err() {
        // Everything that reaches here is being treated as a DNS name, and a name is
        // what goes into the certificate as a DNS subject-alternative name. The
        // resolver is more permissive than that: `127.1`, `2130706433` and `0x7f.0.0.1`
        // are all `127.0.0.1` to `getaddrinfo`, so a host spelled that way would be
        // dialed as an address and certified as a name, and two members could spell one
        // address two ways and be two node names for one machine. RFC 1123 already
        // forbids an all-numeric top label; this refuses those spellings by that rule,
        // along with the empty labels a leading or trailing dot produces.
        let mut labels = host.split('.').peekable();
        let mut last = "";
        while let Some(label) = labels.next() {
            if label.is_empty() {
                bail!(
                    "host `{host}` has an empty name label; write the address or name without a leading, trailing or doubled `.`"
                );
            }
            if labels.peek().is_none() {
                last = label;
            }
        }
        if last.bytes().all(|byte| byte.is_ascii_digit())
            || last.starts_with("0x")
            || last.starts_with("0X")
        {
            bail!(
                "host `{host}` is neither a dotted-quad IPv4 address nor a DNS name: its last label is numeric, and a resolver would read the whole host as an address written another way. Use the dotted-quad spelling, such as 127.0.0.1"
            );
        }
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
pub(crate) fn ensure_local_bind_address(host: &str) -> Result<Ipv4Addr> {
    let address = resolve_fleet_ipv4(host)?;
    let listener = TcpListener::bind((address, 0)).with_context(|| {
        format!(
            "advertised address {address} for host `{host}` is not assigned to a local interface. Use this machine's Tailscale/private IPv4 address or a private DNS name that resolves to it"
        )
    })?;
    drop(listener);
    Ok(address)
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
    if inside(profile.dist_port) {
        warnings.push(format!(
            "pinned TLS distribution port {} is inside this machine's ephemeral port range {low}-{high}: {advice}",
            profile.dist_port
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
    let dist = TcpListener::bind((address, profile.dist_port)).with_context(|| {
        format!(
            "TLS distribution port {} is unavailable on advertised address {address}. Stop the process using that port, or choose a free `--dist-port`, then retry; no fleet credential was installed",
            profile.dist_port
        )
    })?;
    drop(dist);
    Ok(())
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
            bail!("distribution port 4369 is the historical EPMD port; choose another port");
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

fn member(machine: &str, host: &str, dist_port: u16) -> Member {
    Member {
        machine: machine.to_string(),
        host: host.to_string(),
        node: format!("ouro-{machine}@{host}"),
        dist_port,
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

    /// The same three levels as stable codes, for `--json`.
    fn code(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warning",
            Self::Problem => "problem",
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

// ---------------------------------------------------------------------------
// The bundle: one fleet is one shared secret set, and each machine mints its own leaf.
//
// `docs/proposals/fleet-kiss.md` §1 withdrew the per-member certificate ceremony.
// Because any connected member already has unrestricted remote-call authority over
// every other, "the CA key never leaves the operator" and "only the operator can
// admit" were never true after the first connection, and there was no revocation to
// make them matter. So what travels from the operator to a new machine is a
// [`Bundle`] — the cookie and the CA pair — and [`join`] signs that machine's own
// leaf from it, on that machine, with its own host in the subject alternative name,
// because OTP's TLS distribution verifies the server certificate against the dialed
// host. A leaked or lost member is answered by making a new fleet.
// ---------------------------------------------------------------------------

/// The largest roster this code will install. A stale dial hint costs a backed-off dial
/// and nothing else, but a member list is still something a remote peer hands over, so
/// it is bounded.
const MAX_MEMBERS: usize = 64;

/// A PEM field larger than this is not a certificate or a key; it is somebody filling a
/// frame. The helper caps the whole line at 1 MiB, and this caps one field inside it.
const MAX_BUNDLE_PEM_BYTES: usize = 16 * 1024;

/// The bundle wire schema, which is the profile's.
pub const BUNDLE_SCHEMA: u8 = PROFILE_SCHEMA;

/// A refusal with a stable machine-readable reason.
///
/// The helper turns these into `{"ok": false, "reason": "...", "detail": "..."}`;
/// an orchestrator branches on `reason` and shows `detail`. Carried through `anyhow`
/// so the library functions keep one error type and callers that do not care see an
/// ordinary message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Refusal {
    pub reason: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for Refusal {}

impl Refusal {
    fn new(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

/// The stable reason behind an error, when one was declared.
pub fn refusal(error: &anyhow::Error) -> Option<&Refusal> {
    error.downcast_ref::<Refusal>()
}

fn refuse<T>(reason: &'static str, detail: impl Into<String>) -> Result<T> {
    Err(Refusal::new(reason, detail).into())
}

/// A validation failure from an existing fleet check, given a reason code.
fn refusing(reason: &'static str, error: anyhow::Error) -> anyhow::Error {
    Refusal::new(reason, format!("{error:#}")).into()
}

/// Do two names denote the same machine?
///
/// `validate_machine` has always accepted upper case, and every identity comparison in
/// this file was a byte comparison, so `Vps` was a different machine from `vps` to the
/// roster. That is not a spelling difference: it is one machine holding two identities.
/// [`join`] mints only lower-case names, and every comparison against a name that is
/// *already* on disk folds case so the existing entry shadows.
pub fn same_name(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

/// The machine names [`join`] is willing to mint.
///
/// Stricter than [`validate_machine`] on purpose, and only for the new path: an
/// operator's existing mixed-case roster entry keeps working, and nothing new joins it.
fn validate_joined_machine(machine: &str) -> Result<()> {
    validate_machine(machine).map_err(|error| refusing("invalid_request", error))?;
    if machine.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return refuse(
            "invalid_request",
            format!(
                "machine name `{machine}` must be lower case here: `{}` and `{machine}` would be two identities for one machine, and joining mints one",
                machine.to_ascii_lowercase()
            ),
        );
    }
    Ok(())
}

/// The one spelling of a host this code will put in a certificate.
///
/// A DNS name is case-insensitive and may carry the trailing root dot, so `LOCALHOST`,
/// `localhost.` and `localhost` are one host written three ways — and three different
/// node names, if the spelling the operator typed is the spelling that gets minted.
/// `validate_host` separately refuses the numeric spellings of an IPv4 literal that a
/// resolver would accept. What comes back here is what the roster, the node name, the
/// certificate's common name and its subject-alternative name all use.
pub fn canonical_host(host: &str) -> Result<String> {
    let trimmed = host.trim();
    let canonical = trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    validate_host(&canonical).map_err(|error| refusing("invalid_request", error))?;
    Ok(canonical)
}

/// What travels from the operator to a new member, inside one helper frame over SSH.
///
/// Two of these fields are secrets — the fleet cookie and the CA private key — so the
/// struct zeroizes them on drop and its `Debug` is hand-written to print neither. It is
/// deserialized with `deny_unknown_fields`: a sender that adds a field is refused rather
/// than silently ignored.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema: u8,
    pub fleet_id: String,
    pub name: String,
    pub cookie: String,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub dist_port: u16,
    pub members: Vec<Member>,
}

impl Drop for Bundle {
    fn drop(&mut self) {
        self.cookie.zeroize();
        self.ca_key_pem.zeroize();
    }
}

/// Hand-written so neither secret can reach a log, a panic message or an error chain
/// through a derived `Debug`.
impl std::fmt::Debug for Bundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Bundle")
            .field("schema", &self.schema)
            .field("fleet_id", &self.fleet_id)
            .field("name", &self.name)
            .field("cookie", &"<redacted>")
            .field("ca_key_pem", &"<redacted>")
            .field("dist_port", &self.dist_port)
            .field("members", &self.members.len())
            .finish_non_exhaustive()
    }
}

/// Read this machine's fleet directory as the bundle a new member needs.
///
/// Every byte of it is already on this disk: §1 is explicit that the CA key is shared,
/// and `create` keeps `ca-key.pem` for exactly this reason.
pub fn bundle(data_dir: &Path) -> Result<Bundle> {
    let profile = load(data_dir)?.context(
        "this machine is standalone; `ouro fleet setup` gives it a fleet before it can add another machine to one",
    )?;
    let root = fleet_dir(data_dir);
    let cookie = read_private(&root.join(COOKIE_FILE), "fleet cookie")?;
    validate_cookie(&cookie, &root.join(COOKIE_FILE).display().to_string())?;
    let ca_cert_pem = read_private(&root.join(CA_CERT_FILE), "fleet CA certificate")?;
    let ca_key_pem = read_private(&root.join(CA_KEY_FILE), "fleet CA key").context(
        "this machine holds no fleet CA key, so it cannot hand a bundle to another machine",
    )?;
    let bundle = Bundle {
        schema: BUNDLE_SCHEMA,
        fleet_id: profile.fleet_id,
        name: profile.name,
        cookie,
        ca_cert_pem,
        ca_key_pem,
        dist_port: profile.dist_port,
        members: profile.members,
    };
    validate_bundle(&bundle)?;
    Ok(bundle)
}

/// Give this machine an identity inside a fleet that already exists.
///
/// The bundle's CA signs exactly one leaf — this machine's — and the private key for it
/// is generated here and never sent anywhere. `members` becomes the bundle's list plus
/// this machine; nothing is written on any other machine, because §1 withdrew the
/// replicated roster.
pub fn join(
    data_dir: &Path,
    bundle: &Bundle,
    machine: &str,
    host: &str,
    ports: Ports,
) -> Result<Profile> {
    validate_bundle(bundle)?;
    validate_joined_machine(machine)?;
    let host = canonical_host(host)?;
    validate_ports(ports).map_err(|error| refusing("invalid_request", error))?;
    ensure_usable_ipv4_resolution(&host).map_err(|error| refusing("unusable_host", error))?;
    ensure_data_dir(data_dir)?;
    let _lock = lock_stopped_fleet_mutation(data_dir, "ouro fleet helper install")?;
    ensure_local_bind_address(&host).map_err(|error| refusing("unusable_host", error))?;

    let dist_port = ports.dist.unwrap_or(bundle.dist_port);
    let local = member(machine, &host, dist_port);
    let final_dir = fleet_dir(data_dir);
    // `symlink_metadata`, because `try_exists` follows a link: a `fleet` symlink
    // pointing anywhere would read as absent and the write would then fail with whatever
    // the filesystem said. This is a state an orchestrator has to be able to branch on.
    match fs::symlink_metadata(&final_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            return refuse_existing_fleet(data_dir, bundle, machine)
        }
        Ok(metadata) => {
            return refuse(
                "fleet_present",
                format!(
                    "{} already exists and is not a directory (symlink={}); nothing was installed. Inspect it, then move it aside",
                    final_dir.display(),
                    metadata.file_type().is_symlink()
                ),
            )
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(
                anyhow::Error::from(error).context(format!("inspecting {}", final_dir.display()))
            )
        }
    }

    let mut members = bundle.members.clone();
    if !members.iter().any(|entry| entry.node == local.node) {
        members.push(local.clone());
    }
    members.sort_by(|left, right| left.node.cmp(&right.node));
    if members.len() > MAX_MEMBERS {
        return refuse(
            "bundle_invalid",
            format!(
                "this machine would make {} members, and a roster over {MAX_MEMBERS} is not installed",
                members.len()
            ),
        );
    }

    let profile = Profile {
        schema: PROFILE_SCHEMA,
        fleet_id: bundle.fleet_id.clone(),
        name: bundle.name.clone(),
        machine: machine.to_string(),
        host: host.clone(),
        node: local.node.clone(),
        role: "core".to_string(),
        dist_port,
        gateway_port: ports
            .gateway
            .unwrap_or_else(|| default_gateway_port(&bundle.fleet_id, machine)),
        members,
        tags: empty_tags(),
    };
    validate_profile(&profile).map_err(|error| refusing("bundle_invalid", error))?;
    ensure_runtime_ports_available(&profile)?;

    let materials = bundle_materials(&local, bundle)?;
    // The leaf has to satisfy the same check `runtime_env` runs before every boot, and
    // against the bundle's CA bytes rather than a re-encoding of them.
    validate_tls_identity(
        &local,
        &materials.ca_cert_pem,
        &materials.node_cert_pem,
        &materials.node_key_pem,
        materials.ca_key_pem.as_deref(),
        "newly signed node credentials",
    )
    .map_err(|error| refusing("bundle_invalid", error))?;
    install_new_profile(data_dir, &profile, &materials)?;
    Ok(profile)
}

/// The two stable refusals for a machine that already has a fleet directory.
///
/// `already_installed` is the idempotent case an orchestrator retries into: this fleet,
/// this machine, nothing rewritten. Everything else is `fleet_present`, including the
/// same fleet under another machine name, because that profile is somebody's identity.
fn refuse_existing_fleet(data_dir: &Path, bundle: &Bundle, machine: &str) -> Result<Profile> {
    match load(data_dir) {
        Ok(Some(profile))
            if profile.fleet_id == bundle.fleet_id && same_name(&profile.machine, machine) =>
        {
            refuse(
                "already_installed",
                format!(
                    "{} is already {} in fleet {}; nothing was rewritten",
                    profile.machine, profile.node, profile.fleet_id
                ),
            )
        }
        Ok(Some(profile)) => refuse(
            "fleet_present",
            format!(
                "this machine is already {} in fleet {} ({}); nothing was installed",
                profile.machine, profile.name, profile.fleet_id
            ),
        ),
        Ok(None) | Err(_) => refuse(
            "fleet_present",
            format!(
                "{} already exists and does not describe a machine this bundle can join; nothing was installed",
                fleet_dir(data_dir).display()
            ),
        ),
    }
}

/// Mint this machine's leaf under the bundle's CA.
///
/// `from_ca_cert_pem` recovers only what signing needs — the CA's subject name and its
/// subject key identifier — so the issued leaf carries the bundle CA's issuer name and
/// authority key id and verifies against the bundle CA bytes, which are what gets
/// installed. The CA key is installed too: §1 made it the fleet's shared secret.
fn bundle_materials(local: &Member, bundle: &Bundle) -> Result<Materials> {
    let ca_params = CertificateParams::from_ca_cert_pem(&bundle.ca_cert_pem)
        .context("reading the fleet CA certificate out of the bundle")?;
    let ca_key = KeyPair::from_pem(&bundle.ca_key_pem)
        .context("reading the fleet CA key out of the bundle")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("binding the fleet CA certificate to its key for signing")?;
    let (node_cert_pem, node_key_pem) = signed_node_with(local, &ca_cert, &ca_key)?;
    Ok(Materials {
        ca_cert_pem: bundle.ca_cert_pem.clone(),
        ca_key_pem: Some(bundle.ca_key_pem.clone()),
        node_cert_pem,
        node_key_pem,
        cookie: bundle.cookie.clone(),
    })
}

/// Everything about a bundle that can be checked without touching this machine's disk.
fn validate_bundle(bundle: &Bundle) -> Result<()> {
    if bundle.schema != BUNDLE_SCHEMA {
        return refuse(
            "bundle_invalid",
            format!(
                "bundle schema {} is not supported by this ouro (supports {BUNDLE_SCHEMA})",
                bundle.schema
            ),
        );
    }
    if bundle.fleet_id.len() != 24 || !bundle.fleet_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return refuse("bundle_invalid", "the bundle has an invalid fleet id");
    }
    validate_fleet_name(&bundle.name).map_err(|error| refusing("bundle_invalid", error))?;
    validate_cookie(&bundle.cookie, "the bundle cookie")
        .map_err(|error| refusing("bundle_invalid", error))?;
    validate_port(bundle.dist_port, "distribution port")
        .map_err(|error| refusing("bundle_invalid", error))?;
    if bundle.members.len() > MAX_MEMBERS {
        return refuse(
            "bundle_invalid",
            format!(
                "the bundle names {} members, over the {MAX_MEMBERS} this ouro installs",
                bundle.members.len()
            ),
        );
    }
    for entry in &bundle.members {
        validate_member(entry).map_err(|error| refusing("bundle_invalid", error))?;
    }
    if bundle.ca_cert_pem.len() > MAX_BUNDLE_PEM_BYTES
        || bundle.ca_key_pem.len() > MAX_BUNDLE_PEM_BYTES
    {
        return refuse(
            "bundle_invalid",
            format!("a bundle PEM field is over {MAX_BUNDLE_PEM_BYTES} bytes"),
        );
    }
    Ok(())
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
        let profile = loopback_test_profile("studio");
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

    /// The same directory spelled two ways — through a symlink and resolved — is one
    /// directory, and the generated policy has to validate under both: the service unit
    /// names the resolved path, the operator typed the other one, and on macOS `/tmp`
    /// itself is a symlink. A profile an older build wrote under the typed spelling is
    /// still accepted, so an upgrade refuses nothing that was fine before it.
    #[test]
    fn a_symlinked_data_dir_validates_under_either_spelling() {
        let root = scratch("symlinked-data-dir");
        let real = root.join("real");
        fs::create_dir_all(&real).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let typed = link.join("data");
        let resolved = real.join("data");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&resolved)
            .unwrap();

        create(&typed, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();

        // Written with the resolved spelling, whichever one was typed.
        let tls = fs::read_to_string(fleet_dir(&typed).join(TLS_OPTFILE)).unwrap();
        let canonical = fs::canonicalize(&resolved).unwrap();
        assert!(
            tls.contains(&canonical.display().to_string()),
            "the policy names the resolved directory: {tls}"
        );
        validate_materials(&typed, false).unwrap();
        validate_materials(&resolved, false).unwrap();

        // An older profile spelled the directory as typed; still one policy.
        let profile = load(&typed).unwrap().unwrap();
        let (older_tls, older_vm_args) = generated_runtime_files_spelled(&typed, &profile).unwrap();
        assert_ne!(
            older_tls, tls,
            "the two spellings differ, or this test proves nothing"
        );
        write_private_atomic(&fleet_dir(&typed).join(TLS_OPTFILE), older_tls.as_bytes()).unwrap();
        write_private_atomic(
            &fleet_dir(&typed).join(VM_ARGS_FILE),
            older_vm_args.as_bytes(),
        )
        .unwrap();
        validate_materials(&typed, false).unwrap();
        validate_materials(&resolved, false).unwrap();

        // A policy that is neither spelling is still refused.
        write_private_atomic(
            &fleet_dir(&typed).join(TLS_OPTFILE),
            older_tls.replace("verify_peer", "verify_none").as_bytes(),
        )
        .unwrap();
        let refused = validate_materials(&resolved, false).unwrap_err();
        assert!(format!("{refused:#}").contains("strict generated mutual-TLS policy"));

        // And so is a policy naming the CA through a symlink *outside* the fleet
        // directory that happens to point into it today: the file on disk names the
        // outside path, and whoever owns that symlink can point it anywhere tomorrow.
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let alias = elsewhere.join(CA_CERT_FILE);
        std::os::unix::fs::symlink(fleet_dir(&resolved).join(CA_CERT_FILE), &alias).unwrap();
        let canonical_ca = fleet_dir(&canonical).join(CA_CERT_FILE);
        let via_alias = tls.replace(
            &canonical_ca.display().to_string(),
            &alias.display().to_string(),
        );
        assert_ne!(
            via_alias, tls,
            "the policy has to name the alias, or this proves nothing"
        );
        write_private_atomic(&fleet_dir(&typed).join(TLS_OPTFILE), via_alias.as_bytes()).unwrap();
        let refused = validate_materials(&resolved, false).unwrap_err();
        assert!(
            format!("{refused:#}").contains("strict generated mutual-TLS policy"),
            "a path outside the fleet directory is never respelled into it: {refused:#}"
        );

        // A generated name under another directory, and another name under the fleet
        // directory, are left exactly as written and refused.
        let other_name = tls.replace(CA_CERT_FILE, "ca-cert.pem.bak");
        write_private_atomic(&fleet_dir(&typed).join(TLS_OPTFILE), other_name.as_bytes()).unwrap();
        assert!(validate_materials(&resolved, false).is_err());
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
        // Generated under the resolved spelling of the directory (`/private/var/…` on
        // macOS, where the temp dir is reached through a symlink).
        let root = fleet_dir(&fs::canonicalize(&data).unwrap());
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
        let mut profile = loopback_test_profile("studio");
        let vps = member("vps", "127.0.0.1");
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

        // The live projection comes from a runtime that never heard of the machine
        // either, so without this the tombstone is invisible on the surface an operator
        // with a running daemon actually sees.
        let live = serde_json::json!({
            "summary": {"expected": 1, "connected": 1, "offline": 0, "incompatible": 0},
            "machines": [{
                "machine": "studio",
                "node": profile.node,
                "state": "local",
                "role": "core"
            }]
        });
        let rendered = render_live_status(&dir, &live).expect("a live projection");
        assert!(rendered.contains(&vps.node), "{rendered}");
        assert!(rendered.contains("sessions restore"), "{rendered}");

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

    // Doctor performs real local listener checks even when other fixture material is
    // missing. Give those tests numeric loopback hosts and allocated test ports.
    fn loopback_test_profile(machine: &str) -> Profile {
        let ports = ephemeral_ports();
        let local = member(machine, "127.0.0.1");
        Profile {
            host: local.host.clone(),
            node: local.node.clone(),
            members: vec![local],
            gateway_port: ports.gateway.unwrap(),
            epmd_port: ports.epmd.unwrap(),
            dist_port_min: ports.dist.unwrap(),
            dist_port_max: ports.dist.unwrap(),
            ..sample_profile(machine)
        }
    }

    fn fake_epmd(port: u16, stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
        assert_ne!(port, 65_358, "never use the protected runtime endpoint");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Port-availability and ownership checks can overlap. A bare TCP
                        // reachability probe sends no NAMES request; handling it inline
                        // would hold the only accept loop for the read timeout and make a
                        // simultaneous real protocol probe observe a reset or timeout.
                        thread::spawn(move || {
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_millis(250)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_millis(250)))
                                .unwrap();
                            let mut request = [0_u8; 3];
                            if stream.read_exact(&mut request).is_ok() && request == [0, 1, 110] {
                                stream.write_all(&u32::from(port).to_be_bytes()).unwrap();
                            }
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fake EPMD accept failed: {error}"),
                }
            }
        })
    }

    // Keep the allocated listener owned until the fixture is dropped. No client probes
    // a released ephemeral port, including the operator's protected runtime endpoint.
    fn epmd_probe_test_listener(address: Ipv4Addr) -> TcpListener {
        loop {
            let listener = TcpListener::bind((address, 0)).unwrap();
            if listener.local_addr().unwrap().port() != 65_358 {
                return listener;
            }
        }
    }

    struct EpmdProtocolFixture {
        port: u16,
        stop: Arc<AtomicBool>,
        server: Option<thread::JoinHandle<()>>,
    }

    impl EpmdProtocolFixture {
        fn new(mut respond: impl FnMut(&mut TcpStream, u16) + Send + 'static) -> Self {
            let listener = epmd_probe_test_listener(Ipv4Addr::LOCALHOST);
            let port = listener.local_addr().unwrap().port();
            listener.set_nonblocking(true).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let server_stop = stop.clone();
            let server = thread::spawn(move || {
                while !server_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            // Accepted sockets inherit O_NONBLOCK on some platforms.
                            // The fixture's bounded read/write timeouts need blocking I/O.
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_millis(250)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_millis(250)))
                                .unwrap();
                            let mut request = [0_u8; 3];
                            stream.read_exact(&mut request).unwrap();
                            assert_eq!(request, [0, 1, 110]);
                            respond(&mut stream, port);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("EPMD protocol fixture accept failed: {error}"),
                    }
                }
            });
            Self {
                port,
                stop,
                server: Some(server),
            }
        }
    }

    impl Drop for EpmdProtocolFixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            let result = self.server.take().unwrap().join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }

    fn assign_free_loopback_epmd_port(data_dir: &Path) -> Profile {
        let mut profile = load(data_dir).unwrap().unwrap();
        loop {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            if port != 65_358
                && port != legacy_epmd_port()
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
            (
                "2001:db8::1",
                "IPv6 fleet distribution is not yet supported",
            ),
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
    fn owned_epmd_readiness_requires_both_protocols_and_rejects_any_wrong_header() {
        let states = [
            EpmdProbe::Absent,
            EpmdProbe::Compatible,
            EpmdProbe::Incompatible,
            EpmdProbe::Unresponsive,
        ];
        for advertised in states {
            for loopback in states {
                let mut scope_checked = false;
                let result = owned_epmd_probes_ready(advertised, loopback, 14_111, || {
                    scope_checked = true;
                    Ok(())
                });
                let both_compatible =
                    advertised == EpmdProbe::Compatible && loopback == EpmdProbe::Compatible;
                assert_eq!(scope_checked, both_compatible);
                if [advertised, loopback].contains(&EpmdProbe::Incompatible) {
                    assert!(result.is_err(), "{advertised:?}, {loopback:?}");
                } else {
                    assert_eq!(
                        result.unwrap(),
                        both_compatible,
                        "{advertised:?}, {loopback:?}"
                    );
                }
            }
        }
        let error =
            owned_epmd_probes_ready(EpmdProbe::Compatible, EpmdProbe::Compatible, 14_111, || {
                bail!("fixture interface exposure")
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "fixture interface exposure");
    }

    #[test]
    fn owned_epmd_readiness_waits_for_a_protocol_listener_and_rejects_other_services() {
        let epmd = EpmdProtocolFixture::new(|stream, port| {
            stream.write_all(&u32::from(port).to_be_bytes()).unwrap();
        });
        assert!(owned_epmd_ready(
            Ipv4Addr::LOCALHOST,
            epmd.port,
            Instant::now() + EPMD_START_DEADLINE
        )
        .unwrap());

        let other = EpmdProtocolFixture::new(|stream, _| {
            stream.write_all(b"HTTP").unwrap();
        });
        let error = owned_epmd_ready(
            Ipv4Addr::LOCALHOST,
            other.port,
            Instant::now() + EPMD_START_DEADLINE,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not speak"), "{error}");
    }

    #[test]
    fn owned_epmd_readiness_retries_incomplete_names_only_before_its_deadline() {
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let mut first = true;
        let epmd = EpmdProtocolFixture::new(move |stream, port| {
            if first {
                first = false;
                // Withhold the first response until the probe times out and closes its
                // own socket. The next connection then gets a complete NAMES header.
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                assert_eq!(stream.read(&mut [0_u8; 1]).unwrap(), 0);
                closed_tx.send(()).unwrap();
            } else {
                stream.write_all(&u32::from(port).to_be_bytes()).unwrap();
            }
        });
        let deadline = Instant::now() + EPMD_START_DEADLINE;
        assert!(!owned_epmd_ready(Ipv4Addr::LOCALHOST, epmd.port, deadline).unwrap());
        closed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(owned_epmd_ready(Ipv4Addr::LOCALHOST, epmd.port, deadline).unwrap());

        let silent = epmd_probe_test_listener(Ipv4Addr::LOCALHOST);
        let port = silent.local_addr().unwrap().port();
        let deadline = Instant::now() + Duration::from_millis(40);
        assert!(!owned_epmd_ready(Ipv4Addr::LOCALHOST, port, deadline).unwrap());

        let expired = epmd_probe_test_listener(Ipv4Addr::LOCALHOST);
        let port = expired.local_addr().unwrap().port();
        assert!(!owned_epmd_ready(Ipv4Addr::LOCALHOST, port, Instant::now()).unwrap());
        expired.set_nonblocking(true).unwrap();
        assert_eq!(
            expired.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn epmd_probe_only_treats_connection_refusal_as_absence() {
        assert_eq!(
            epmd_connect_error(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            EpmdProbe::Absent
        );
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
        ] {
            assert_eq!(
                epmd_connect_error(&io::Error::from(kind)),
                EpmdProbe::Unresponsive,
                "{kind:?} must not prove listener absence"
            );
        }
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(
                epmd_connect_error(&io::Error::from_raw_os_error(errno)),
                EpmdProbe::Unresponsive,
                "resource exhaustion must not prove listener absence"
            );
        }
    }

    #[test]
    fn epmd_probe_distinguishes_short_names_from_a_complete_wrong_header() {
        let epmd = EpmdProtocolFixture::new(|stream, port| {
            stream
                .write_all(&u32::from(port).to_be_bytes()[..3])
                .unwrap();
        });
        assert_eq!(
            epmd_probe(Ipv4Addr::LOCALHOST, epmd.port),
            EpmdProbe::Unresponsive
        );
        let error = ensure_epmd_port_available("127.0.0.1", epmd.port)
            .unwrap_err()
            .to_string();
        assert!(error.contains("could not be validated"), "{error}");

        // This classifier does not read ownership artifacts or act on the PID. Even an
        // already-owned listener must remain unclassified until NAMES is validated.
        let owner = EpmdOwner {
            schema: EPMD_OWNER_SCHEMA,
            fleet_id: String::new(),
            host: "127.0.0.1".into(),
            address: Ipv4Addr::LOCALHOST,
            port: epmd.port,
            pid: 0,
            executable: PathBuf::new(),
            executable_dev: 0,
            executable_ino: 0,
            lock_dev: 0,
            lock_ino: 0,
        };
        let error = ensure_owned_epmd_listener_state(&owner)
            .unwrap_err()
            .to_string();
        assert!(error.contains("could not be validated"), "{error}");
    }

    #[test]
    fn epmd_preflight_reuses_a_real_lingering_daemon_and_rejects_arbitrary_listeners() {
        assert!(local_ipv4_interfaces()
            .unwrap()
            .contains(&Ipv4Addr::LOCALHOST));
        let epmd = EpmdProtocolFixture::new(|stream, port| {
            stream.write_all(&u32::from(port).to_be_bytes()).unwrap();
        });
        assert_eq!(
            ensure_epmd_port_available("127.0.0.1", epmd.port).unwrap(),
            EpmdPortState::CompatibleRunning
        );

        let arbitrary = epmd_probe_test_listener(Ipv4Addr::LOCALHOST);
        let arbitrary_port = arbitrary.local_addr().unwrap().port();
        let error = ensure_epmd_port_available("127.0.0.1", arbitrary_port)
            .unwrap_err()
            .to_string();
        assert!(error.contains("could not be validated"), "{error}");
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
        let listener = epmd_probe_test_listener(Ipv4Addr::LOCALHOST);
        let port = listener.local_addr().unwrap().port();
        let sleep = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix sleep executable");
        let epmd = Command::new(sleep).arg("30").spawn().unwrap();
        let epmd_pid = epmd.id() as i32;
        let failure = EpmdRuntimeWatch::new(Some(epmd), Ipv4Addr::LOCALHOST, port).supervise();

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
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
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
        create(&data, None, "owner", "127.0.0.1", ephemeral_ports()).unwrap();
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
        let server = EpmdProtocolFixture::new(|stream, port| {
            stream.write_all(&u32::from(port).to_be_bytes()).unwrap();
        });
        let port = server.port;
        let sleep = [Path::new("/bin/sleep"), Path::new("/usr/bin/sleep")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix sleep executable");
        let mut unrelated = Command::new(sleep).arg("30").spawn().unwrap();
        let unrelated_pid = unrelated.id() as i32;
        let failure = EpmdRuntimeWatch::new(None, Ipv4Addr::LOCALHOST, port).supervise();

        assert!(epmd_responds(Ipv4Addr::LOCALHOST, port));
        drop(server);
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

        let listener_stopped = data.join("fake-epmd-stopped");
        let current_program = data.join("current-release-epmd");
        write_private_new(
            &current_program,
            format!(
                "#!/bin/sh\nkill -TERM {pid}\nwhile [ ! -e '{}' ]; do sleep 0.01; done\n",
                listener_stopped.display()
            )
            .as_bytes(),
            "test EPMD control",
        )
        .unwrap();
        fs::set_permissions(&current_program, fs::Permissions::from_mode(0o700)).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let server = fake_epmd(profile.epmd_port, stop.clone());
        let stop_after_pid = stop.clone();
        let stopped_after_pid = listener_stopped.clone();
        let stopped_port = profile.epmd_port;
        let listener_watcher = thread::spawn(move || {
            while runtime::pid_alive(pid) {
                thread::sleep(Duration::from_millis(5));
            }
            stop_after_pid.store(true, Ordering::Relaxed);
            loop {
                match TcpListener::bind((Ipv4Addr::LOCALHOST, stopped_port)) {
                    Ok(listener) => {
                        drop(listener);
                        fs::write(&stopped_after_pid, b"stopped").unwrap();
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("checking fake EPMD shutdown failed: {error}"),
                }
            }
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

        let listener_stopped = data.join("fake-epmd-stopped");
        let current_program = data.join("current-release-epmd");
        write_private_new(
            &current_program,
            format!(
                "#!/bin/sh\nkill -TERM {pid}\nwhile [ ! -e '{}' ]; do sleep 0.01; done\n",
                listener_stopped.display()
            )
            .as_bytes(),
            "test EPMD control",
        )
        .unwrap();
        fs::set_permissions(&current_program, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = current_program.canonicalize().unwrap();
        let executable_metadata = fs::symlink_metadata(&executable).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let server = fake_epmd(profile.epmd_port, stop.clone());
        let stop_after_pid = stop.clone();
        let stopped_after_pid = listener_stopped.clone();
        let stopped_port = profile.epmd_port;
        let listener_watcher = thread::spawn(move || {
            while runtime::pid_alive(pid) {
                thread::sleep(Duration::from_millis(5));
            }
            stop_after_pid.store(true, Ordering::Relaxed);
            loop {
                match TcpListener::bind((Ipv4Addr::LOCALHOST, stopped_port)) {
                    Ok(listener) => {
                        drop(listener);
                        fs::write(&stopped_after_pid, b"stopped").unwrap();
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("checking fake EPMD shutdown failed: {error}"),
                }
            }
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

    // -----------------------------------------------------------------------
    // Admission. The property under every test here is a boundary: the CA key stays
    // on the issuer, the issuer's own node key stays in its own directory, the
    // target's key stays on the target, and the cookie travels but is never written
    // anywhere a reader other than the BEAM would look.
    // -----------------------------------------------------------------------

    fn issuer_fleet(label: &str) -> PathBuf {
        let data = scratch(label);
        create(
            &data,
            Some("the lab"),
            "studio",
            "127.0.0.1",
            ephemeral_ports(),
        )
        .unwrap();
        data
    }

    /// A request built the way `prepare_admission` builds one, with the certificate
    /// parameters opened up so a test can ask for something it must not get.
    fn crafted_request(
        operation: &str,
        machine: &str,
        host: &str,
        mutate: impl FnOnce(&mut CertificateParams),
    ) -> AdmissionRequest {
        let local = member(machine, host);
        let mut params = CertificateParams::new(vec![local.host.clone()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, local.node.clone());
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        mutate(&mut params);
        let key = KeyPair::generate().unwrap();
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
        AdmissionRequest {
            schema: ADMISSION_SCHEMA,
            operation: operation.to_string(),
            machine: machine.to_string(),
            host: host.to_string(),
            node: local.node.clone(),
            key_fingerprint: public_fingerprint(key.public_key_der().as_ref()),
            csr_pem,
        }
    }

    fn pem_block(label: &str, der: &[u8]) -> String {
        use base64::Engine as _;
        let body = base64::engine::general_purpose::STANDARD.encode(der);
        let mut text = format!("-----BEGIN {label}-----\r\n");
        for chunk in body.as_bytes().chunks(64) {
            text.push_str(std::str::from_utf8(chunk).unwrap());
            text.push_str("\r\n");
        }
        text.push_str(&format!("-----END {label}-----\r\n"));
        text
    }

    fn reason_of(error: &anyhow::Error) -> &str {
        admission_error(error)
            .map(|declared| declared.reason)
            .unwrap_or_else(|| panic!("an admission refusal must declare a reason: {error:#}"))
    }

    /// The whole path, and the four boundaries it exists to keep.
    ///
    /// The target generates its key and keeps it; the issuer signs a certificate for a
    /// key it does not hold; the materials that travel carry no private key at all; and
    /// what lands on the target is a machine the boot path will start.
    #[test]
    fn a_machine_is_admitted_without_any_private_key_crossing_its_boundary() {
        let issuer = issuer_fleet("issuer-admits");
        let target = scratch("target-admitted");
        let operation = "op-2026-09-17-a1";

        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        assert_eq!(request.node, "ouro-vps@127.0.0.1");

        // The target's key is on the target, at 0600, and in exactly one place.
        let staging = admission_dir(&target, operation);
        ensure_private_file(&staging.join(NODE_KEY_FILE), "staged node key").unwrap();
        let staged_key = read_private(&staging.join(NODE_KEY_FILE), "staged node key").unwrap();
        assert!(staged_key.contains("PRIVATE KEY"));
        assert!(
            !request.csr_pem.contains("PRIVATE KEY"),
            "a signing request carries a public key and a signature over it, never the key"
        );
        assert!(
            !serde_json::to_string(&request)
                .unwrap()
                .contains("PRIVATE KEY"),
            "nothing that leaves the target carries the key it just generated"
        );

        let materials = issue_member_certificate(&issuer, &request).unwrap();
        let wire = serde_json::to_string(&materials).unwrap();
        assert!(
            !wire.contains("PRIVATE KEY"),
            "the materials carry the CA certificate, the new leaf and the cookie, and no key"
        );
        assert!(
            !wire.contains("ca_key_pem"),
            "there is no field on the wire that could hold the authority to sign"
        );
        let issuer_node_key = read_private(
            &fleet_dir(&issuer).join(NODE_KEY_FILE),
            "the issuer's node key",
        )
        .unwrap();
        assert!(
            !wire.contains(issuer_node_key.trim()),
            "the issuer's own node key is not part of anything it sends"
        );
        let ca_key =
            read_private(&fleet_dir(&issuer).join(CA_KEY_FILE), "the fleet CA key").unwrap();
        assert!(
            !wire.contains(ca_key.trim()),
            "the CA key stays on the machine that minted it"
        );
        assert!(
            !wire.contains(&staged_key),
            "the target's key never travels"
        );

        let profile = install_admission(&target, &materials, ephemeral_ports()).unwrap();
        assert_eq!(profile.node, "ouro-vps@127.0.0.1");
        assert_eq!(profile.fleet_id, load(&issuer).unwrap().unwrap().fleet_id);
        assert_eq!(
            profile
                .members
                .iter()
                .map(|member| member.machine.as_str())
                .collect::<Vec<_>>(),
            vec!["studio", "vps"],
            "the newcomer installs the complete agreed roster, itself included"
        );

        // The admitted machine holds no authority to admit a third.
        assert!(
            !fleet_dir(&target).join(CA_KEY_FILE).try_exists().unwrap(),
            "an admitted machine is given a CA certificate, never the CA key"
        );
        assert!(
            !staging.try_exists().unwrap(),
            "the operation's staging directory is gone once the fleet directory is complete"
        );
        // And it is a machine the boot path will actually start.
        validate_materials(&target, false).unwrap();
        assert!(runtime_env(&target).unwrap().is_some());
        // The cookie it boots with is the fleet's.
        assert_eq!(
            read_private(&fleet_dir(&target).join(COOKIE_FILE), "cookie").unwrap(),
            read_private(&fleet_dir(&issuer).join(COOKIE_FILE), "cookie").unwrap()
        );
    }

    /// Repeating a `prepare` answers with what was already prepared, and a second
    /// operation on a machine with one pending is refused rather than minting a
    /// second identity nobody will be able to tell from the first.
    #[test]
    fn preparing_twice_answers_once_and_a_second_operation_is_refused() {
        let target = scratch("target-repeat-prepare");
        let operation = "op-repeat-0001";

        let first = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        let second = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        assert_eq!(
            first, second,
            "an interrupted answer costs a round trip, not an identity"
        );

        let other = prepare_admission(&target, "op-repeat-0002", "vps", "127.0.0.1").unwrap_err();
        assert_eq!(reason_of(&other), "operation_in_progress");

        let renamed = prepare_admission(&target, operation, "laptop", "127.0.0.1").unwrap_err();
        assert_eq!(
            reason_of(&renamed),
            "identity_mismatch",
            "a prepared identity is not quietly reassigned to another machine name"
        );

        let installed = issuer_fleet("target-already-in-a-fleet");
        let refused =
            prepare_admission(&installed, "op-already-0001", "vps", "127.0.0.1").unwrap_err();
        assert_eq!(reason_of(&refused), "fleet_exists");
    }

    /// A request asking for authority, for a name it was not approved for, or signed
    /// by a key it does not hold.
    ///
    /// The privilege case is deliberately *not* a refusal: the issuer builds every
    /// parameter of the certificate itself, so a request may ask for `CA:true` and for
    /// the right to sign certificates and simply not receive them. The name cases are
    /// refusals, because a request for a name that will not be issued is a request
    /// whose sender is about to be surprised.
    #[test]
    fn a_hostile_request_gets_no_authority_no_extra_name_and_no_certificate_at_all() {
        let issuer = issuer_fleet("issuer-hostile");

        let greedy = crafted_request("op-hostile-0001", "vps", "127.0.0.1", |params| {
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    // basicConstraints: SEQUENCE { BOOLEAN TRUE }
                    &[2, 5, 29, 19],
                    vec![0x30, 0x03, 0x01, 0x01, 0xff],
                ));
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
        });
        // The request really does ask for both, or the assertions below would pass
        // against a request that never asked for anything.
        let (_, asked) = parse_x509_pem(greedy.csr_pem.as_bytes()).unwrap();
        let (_, parsed) = X509CertificationRequest::from_der(&asked.contents).unwrap();
        let requested: Vec<_> = parsed
            .requested_extensions()
            .expect("a request carrying extensions")
            .collect();
        assert!(
            requested.iter().any(|extension| matches!(
                extension,
                x509_parser::extensions::ParsedExtension::BasicConstraints(constraints)
                    if constraints.ca
            )),
            "the request must actually ask to be a certificate authority"
        );
        assert!(
            requested.iter().any(|extension| matches!(
                extension,
                x509_parser::extensions::ParsedExtension::KeyUsage(usage)
                    if usage.key_cert_sign()
            )),
            "and must actually ask for the right to sign certificates"
        );

        let materials = issue_member_certificate(&issuer, &greedy).unwrap();
        let (_, block) = parse_x509_pem(materials.node_cert_pem.as_bytes()).unwrap();
        let issued = block.parse_x509().unwrap();
        assert!(
            !issued.is_ca(),
            "a request that asks to be a CA is answered with a leaf"
        );
        let usage = issued.key_usage().unwrap().unwrap();
        assert!(
            !usage.value.key_cert_sign() && !usage.value.crl_sign(),
            "the issuer sets the key usages, so a request cannot ask for the right to sign"
        );
        assert!(usage.value.digital_signature() && usage.value.key_encipherment());

        let issuer = issuer_fleet("issuer-hostile-names");
        for (label, request) in [
            (
                "an extra certificate name",
                crafted_request("op-hostile-0002", "vps", "127.0.0.1", |params| {
                    params.subject_alt_names.push(rcgen::SanType::DnsName(
                        "studio.internal".try_into().unwrap(),
                    ));
                }),
            ),
            (
                "another machine's node name",
                crafted_request("op-hostile-0003", "vps", "127.0.0.1", |params| {
                    params.distinguished_name = DistinguishedName::new();
                    params
                        .distinguished_name
                        .push(DnType::CommonName, "ouro-studio@127.0.0.1");
                }),
            ),
            (
                "another machine's address",
                crafted_request("op-hostile-0004", "vps", "127.0.0.1", |params| {
                    params.subject_alt_names =
                        vec![rcgen::SanType::IpAddress("10.0.0.9".parse().unwrap())];
                }),
            ),
        ] {
            let error = issue_member_certificate(&issuer, &request).unwrap_err();
            assert_eq!(
                reason_of(&error),
                "csr_identity_mismatch",
                "{label} must be refused"
            );
        }

        // Proof of possession: a request whose signature is not the key's.
        let mut forged = crafted_request("op-hostile-0005", "vps", "127.0.0.1", |_| {});
        let (_, block) = parse_x509_pem(forged.csr_pem.as_bytes()).unwrap();
        let mut der = block.contents.clone();
        let last = der.len() - 1;
        der[last] ^= 0xff;
        forged.csr_pem = pem_block("CERTIFICATE REQUEST", &der);
        let error = issue_member_certificate(&issuer, &forged).unwrap_err();
        assert_eq!(reason_of(&error), "csr_signature_invalid");

        // And a request whose fingerprint describes a different key than it carries.
        let mut mislabelled = crafted_request("op-hostile-0006", "vps", "127.0.0.1", |_| {});
        mislabelled.key_fingerprint = public_fingerprint(b"not this key");
        let error = issue_member_certificate(&issuer, &mislabelled).unwrap_err();
        assert_eq!(reason_of(&error), "csr_identity_mismatch");
    }

    #[test]
    fn retiring_an_undelivered_admission_allows_a_new_operation_but_not_replay() {
        let issuer = issuer_fleet("issuer-retire");
        let target = scratch("target-retire");
        let old = prepare_admission(&target, "op-retire-old", "vps", "127.0.0.1").unwrap();
        issue_member_certificate(&issuer, &old).unwrap();
        assert_eq!(remove_member(&issuer, "vps").unwrap().machine, "vps");
        let receipt = read_receipt(&issuer, &old.operation).unwrap().unwrap();
        assert!(receipt.has_step("issue") && receipt.has_step("retire"));
        assert_eq!(
            reason_of(&issue_member_certificate(&issuer, &old).unwrap_err()),
            "operation_replayed"
        );
        let new = crafted_request("op-retire-new", "vps", "127.0.0.1", |_| {});
        issue_member_certificate(&issuer, &new).unwrap();
        let duplicate = crafted_request("op-retire-duplicate", "vps", "127.0.0.1", |_| {});
        assert_eq!(
            reason_of(&issue_member_certificate(&issuer, &duplicate).unwrap_err()),
            "machine_already_issued"
        );
    }

    #[test]
    fn issuance_releases_the_roster_fence_before_delivery() {
        let issuer = issuer_fleet("issuer-fence");
        let target = scratch("target-fence");
        let request = prepare_admission(&target, "op-fenced", "vps", "127.0.0.1").unwrap();
        let profile = load(&issuer).unwrap().unwrap();
        issue_member_certificate_checked(&issuer, &request, Some(&profile)).unwrap();
        add_member(&issuer, "concurrent", "127.0.0.2", None).unwrap();
        let error = apply_roster_change(
            &issuer,
            "op-fenced-roster",
            profile.roster_revision,
            &RosterChange::Add {
                machine: "vps".into(),
                host: "127.0.0.1".into(),
                node: None,
            },
        )
        .unwrap_err();
        assert_eq!(reason_of(&error), "roster_conflict");
        let current = load(&issuer).unwrap().unwrap();
        apply_roster_change(
            &issuer,
            "op-fenced-roster",
            current.roster_revision,
            &RosterChange::Add {
                machine: "vps".into(),
                host: "127.0.0.1".into(),
                node: None,
            },
        )
        .unwrap();
        let profile = load(&issuer).unwrap().unwrap();
        assert!(profile.members.iter().any(|member| member.machine == "vps"));
        assert!(profile
            .members
            .iter()
            .any(|member| member.machine == "concurrent"));
    }

    /// One machine, one identity: not twice under one operation id, not twice under
    /// two, and never for a name the roster or its tombstones already spent.
    #[test]
    fn an_issuer_refuses_a_replay_a_second_identity_and_a_name_it_already_knows() {
        let issuer = issuer_fleet("issuer-replay");
        let target = scratch("target-replay");

        let request = prepare_admission(&target, "op-replay-0001", "vps", "127.0.0.1").unwrap();
        issue_member_certificate(&issuer, &request).unwrap();

        let replayed = issue_member_certificate(&issuer, &request).unwrap_err();
        assert_eq!(reason_of(&replayed), "operation_replayed");

        let again = crafted_request("op-replay-0002", "vps", "127.0.0.1", |_| {});
        let error = issue_member_certificate(&issuer, &again).unwrap_err();
        assert_eq!(
            reason_of(&error),
            "machine_already_issued",
            "a second identity for one machine is a duplicate, not a retry"
        );

        add_member(&issuer, "laptop", "127.0.0.1", None).unwrap();
        let known = crafted_request("op-replay-0003", "laptop", "127.0.0.1", |_| {});
        assert_eq!(
            reason_of(&issue_member_certificate(&issuer, &known).unwrap_err()),
            "machine_known"
        );

        forget_machine(&issuer, "laptop").unwrap();
        let gone = crafted_request("op-replay-0004", "laptop", "127.0.0.1", |_| {});
        assert_eq!(
            reason_of(&issue_member_certificate(&issuer, &gone).unwrap_err()),
            "machine_known",
            "a machine declared gone for good does not come back through admission"
        );

        // A machine that never had a fleet cannot admit anything.
        let standalone = scratch("standalone-issuer");
        let nothing = crafted_request("op-replay-0005", "vps", "127.0.0.1", |_| {});
        assert_eq!(
            reason_of(&issue_member_certificate(&standalone, &nothing).unwrap_err()),
            "no_fleet"
        );
    }

    /// The target's half of the boundary: materials that would hand it authority, or
    /// a certificate for someone else's key, are refused before anything is written.
    #[test]
    fn install_refuses_materials_carrying_a_key_an_unknown_field_or_a_foreign_certificate() {
        let issuer = issuer_fleet("issuer-bad-materials");
        let target = scratch("target-bad-materials");
        let request = prepare_admission(&target, "op-materials-001", "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request).unwrap();

        // A sender that adds the CA key as a field is refused by the shape itself: a
        // target must notice being handed authority rather than quietly drop it.
        let mut wire = serde_json::to_value(&materials).unwrap();
        wire.as_object_mut().unwrap().insert(
            "ca_key_pem".to_string(),
            Value::String("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".into()),
        );
        let error = serde_json::from_value::<AdmissionMaterials>(wire).unwrap_err();
        assert!(
            error.to_string().contains("ca_key_pem"),
            "the refusal must name the field that does not belong: {error}"
        );

        // And a sender that hides one inside a field that does belong.
        let mut smuggled = materials.clone();
        smuggled.ca_cert_pem = format!(
            "{}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            smuggled.ca_cert_pem
        );
        assert_eq!(
            reason_of(&install_admission(&target, &smuggled, ephemeral_ports()).unwrap_err()),
            "materials_carry_private_key"
        );

        // A certificate for a key this machine did not prepare cannot be installed
        // against the key it did.
        let other = scratch("target-other-key");
        let other_request =
            prepare_admission(&other, "op-materials-002", "vps", "127.0.0.1").unwrap();
        let other_materials =
            issue_member_certificate(&issuer_fleet("issuer-other-key"), &other_request).unwrap();
        let mut foreign = materials.clone();
        foreign.node_cert_pem = other_materials.node_cert_pem.clone();
        assert_eq!(
            reason_of(&install_admission(&target, &foreign, ephemeral_ports()).unwrap_err()),
            "materials_invalid",
            "a leaf minted for another machine's key is not this machine's identity"
        );
        assert!(
            !fleet_dir(&target).try_exists().unwrap(),
            "nothing is published while the materials are still being checked"
        );

        // And a target that never prepared has no key to bind a certificate to.
        let empty = scratch("target-never-prepared");
        assert_eq!(
            reason_of(&install_admission(&empty, &materials, ephemeral_ports()).unwrap_err()),
            "staging_missing"
        );
    }

    /// The one commit point, from both sides of it.
    ///
    /// A crash before the rename leaves a staging directory holding some of the final
    /// files; rerunning with the same materials rewrites them and finishes. A crash
    /// after the rename leaves a complete fleet whose receipt has not been closed;
    /// rerunning returns the installed profile and closes it. Neither leaves a second
    /// identity, and neither needs the issuer again.
    #[test]
    fn an_interrupted_install_is_finished_by_repeating_it_with_the_same_materials() {
        let issuer = issuer_fleet("issuer-crash");
        let target = scratch("target-crash");
        let operation = "op-crash-000001";
        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request).unwrap();

        // The state a crash between the first write and the rename leaves behind: the
        // cookie and the CA certificate landed, nothing else did.
        let staging = admission_dir(&target, operation);
        write_private_atomic(&staging.join(COOKIE_FILE), materials.cookie.as_bytes()).unwrap();
        write_private_atomic(
            &staging.join(CA_CERT_FILE),
            materials.ca_cert_pem.as_bytes(),
        )
        .unwrap();
        assert!(
            !fleet_dir(&target).try_exists().unwrap(),
            "a half-written staging directory is not a fleet"
        );
        assert!(
            load(&target).unwrap().is_none(),
            "and nothing reads it as one"
        );

        let ports = ephemeral_ports();
        let profile = install_admission(&target, &materials, ports).unwrap();
        validate_materials(&target, false).unwrap();

        // The state a crash between the rename and the closing receipt leaves behind.
        let receipt_path = receipts_dir(&target).join(format!("{operation}.json"));
        let mut receipt: Receipt =
            serde_json::from_str(&read_private(&receipt_path, "receipt").unwrap()).unwrap();
        receipt.steps.retain(|step| step.step != "install");
        write_private_atomic(&receipt_path, &serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();

        let again = install_admission(&target, &materials, ports).unwrap();
        assert_eq!(again, profile, "a finished install repeats its own answer");
        assert!(
            read_receipt(&target, operation)
                .unwrap()
                .unwrap()
                .has_step("install"),
            "and closes the record the crash left open"
        );

        let third = install_admission(&target, &materials, ports).unwrap();
        assert_eq!(third, profile);

        // A machine that belongs to a different fleet is not overwritten by materials
        // that happen to name the same operation.
        let stranger = scratch("target-stranger");
        create(&stranger, None, "vps", "127.0.0.1", ephemeral_ports()).unwrap();
        assert_eq!(
            reason_of(&install_admission(&stranger, &materials, ephemeral_ports()).unwrap_err()),
            "fleet_exists"
        );
    }

    /// What gets promoted is a fleet directory and nothing else.
    ///
    /// The rename that commits an identity is also what turns this directory into one
    /// `ouro fleet leave` has to be able to remove, and that command refuses a
    /// directory holding an entry it does not recognize. A killed earlier attempt can
    /// leave a half-written temporary behind, and the request record has no business
    /// surviving either.
    #[test]
    fn promotion_carries_no_leftover_of_the_attempt_that_was_interrupted() {
        let issuer = issuer_fleet("issuer-prune");
        let target = scratch("target-prune");
        let operation = "op-prune-0000001";
        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request).unwrap();
        let staging = admission_dir(&target, operation);

        // Exactly what a SIGKILL between `write_private_atomic`'s create and its
        // rename leaves in the directory.
        let orphan = staging.join(format!(
            ".{COOKIE_FILE}.{}.0123456789ab.tmp",
            std::process::id()
        ));
        write_private_new(&orphan, b"half a cookie", "interrupted write").unwrap();
        assert!(staging.join(ADMISSION_REQUEST_FILE).try_exists().unwrap());

        install_admission(&target, &materials, ephemeral_ports()).unwrap();

        let root = fleet_dir(&target);
        assert!(unrecognized_fleet_entries(&root).unwrap().is_empty());
        assert!(!root.join(ADMISSION_REQUEST_FILE).try_exists().unwrap());
        assert!(!root.join(orphan.file_name().unwrap()).try_exists().unwrap());
        // Which is to say: this machine can be retired again.
        leave(&target).unwrap().expect("a retired machine");

        // An entry this code cannot account for stops the promotion instead.
        let second = scratch("target-prune-unknown");
        let request = prepare_admission(&second, operation, "vps", "127.0.0.1").unwrap();
        let materials =
            issue_member_certificate(&issuer_fleet("issuer-prune-2"), &request).unwrap();
        write_private_new(
            &admission_dir(&second, operation).join("somebody-elses-file"),
            b"not ours",
            "a planted file",
        )
        .unwrap();
        let error = install_admission(&second, &materials, ephemeral_ports()).unwrap_err();
        assert_eq!(reason_of(&error), "invalid_staging");
        assert!(
            !fleet_dir(&second).try_exists().unwrap(),
            "nothing was published"
        );
    }

    /// A roster edit states the revision it was computed against, so an operator whose
    /// view is stale is told rather than silently overwriting a later edit.
    #[test]
    fn a_roster_change_against_a_stale_revision_is_refused_with_the_revision_it_needs() {
        let data = issuer_fleet("roster-conflict");
        let start = load(&data).unwrap().unwrap().roster_revision;

        let outcome = apply_roster_change(
            &data,
            "op-roster-00001",
            start,
            &RosterChange::Add {
                machine: "vps".to_string(),
                host: "127.0.0.1".to_string(),
                node: None,
            },
        )
        .unwrap();
        assert!(outcome.changed);
        assert_eq!(outcome.roster_revision, start + 1);
        assert_eq!(outcome.member.node, "ouro-vps@127.0.0.1");

        // The same change replayed against the revision it was computed from.
        let error = apply_roster_change(
            &data,
            "op-roster-00002",
            start,
            &RosterChange::Remove {
                machine: "vps".to_string(),
            },
        )
        .unwrap_err();
        let declared = admission_error(&error).expect("a declared refusal");
        assert_eq!(declared.reason, "roster_conflict");
        assert_eq!(
            declared.roster_revision,
            Some(start + 1),
            "the refusal carries the revision the caller has to re-read"
        );
        assert_eq!(
            load(&data).unwrap().unwrap().members.len(),
            2,
            "a refused change changes nothing"
        );

        let removed = apply_roster_change(
            &data,
            "op-roster-00003",
            start + 1,
            &RosterChange::Remove {
                machine: "vps".to_string(),
            },
        )
        .unwrap();
        assert_eq!(removed.roster_revision, start + 2);

        let forgotten = apply_roster_change(
            &data,
            "op-roster-00004",
            start + 2,
            &RosterChange::Add {
                machine: "laptop".to_string(),
                host: "127.0.0.1".to_string(),
                node: Some("ouro-laptop@127.0.0.1".to_string()),
            },
        )
        .unwrap();
        let gone = apply_roster_change(
            &data,
            "op-roster-00005",
            forgotten.roster_revision,
            &RosterChange::Forget {
                machine: "laptop".to_string(),
            },
        )
        .unwrap();
        assert_eq!(
            load(&data).unwrap().unwrap().tombstones[0].machine,
            "laptop"
        );
        assert!(gone.changed);

        // An edit the roster refuses on its own terms keeps its own explanation.
        let error = apply_roster_change(
            &data,
            "op-roster-00006",
            load(&data).unwrap().unwrap().roster_revision,
            &RosterChange::Remove {
                machine: "nobody".to_string(),
            },
        )
        .unwrap_err();
        assert_eq!(reason_of(&error), "roster_refused");

        let standalone = scratch("roster-standalone");
        assert_eq!(
            reason_of(
                &apply_roster_change(
                    &standalone,
                    "op-roster-00007",
                    1,
                    &RosterChange::Remove {
                        machine: "vps".to_string(),
                    },
                )
                .unwrap_err()
            ),
            "no_fleet"
        );
    }

    /// Receipts are the durable record a lost connection is reconciled from, and the
    /// one file in this feature a person is most likely to read. They carry step
    /// names, times, outcomes and public fingerprints, and nothing else.
    #[test]
    fn receipts_record_every_step_and_never_a_cookie_a_key_or_a_token() {
        let issuer = issuer_fleet("issuer-receipts");
        let target = scratch("target-receipts");
        let operation = "op-receipt-0001";

        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        // Before the fleet exists the record lives with the key it describes.
        let staged = read_receipt(&target, operation).unwrap().unwrap();
        assert!(staged.has_step("prepare"));
        assert_eq!(
            staged.key_fingerprint.as_deref(),
            Some(request.key_fingerprint.as_str())
        );

        let materials = issue_member_certificate(&issuer, &request).unwrap();
        let issued = read_receipt(&issuer, operation).unwrap().unwrap();
        assert!(issued.has_step("issue"));

        install_admission(&target, &materials, ephemeral_ports()).unwrap();
        let receipt_path = receipts_dir(&target).join(format!("{operation}.json"));
        ensure_private_file(&receipt_path, "operation receipt").unwrap();
        let text = read_private(&receipt_path, "operation receipt").unwrap();
        let installed: Receipt = serde_json::from_str(&text).unwrap();
        assert_eq!(
            installed
                .steps
                .iter()
                .map(|step| step.step.as_str())
                .collect::<Vec<_>>(),
            vec!["prepare", "install_staged", "install"],
            "the record survives the rename that commits the identity"
        );
        assert!(installed.steps.iter().all(|step| step.at.ends_with('Z')));

        let cookie = read_private(&fleet_dir(&target).join(COOKIE_FILE), "cookie").unwrap();
        assert!(
            !text.contains(&cookie),
            "a receipt never carries the cookie"
        );
        assert!(
            !text.contains("PRIVATE KEY"),
            "a receipt never carries key material"
        );
        assert!(
            text.contains(&request.key_fingerprint),
            "it carries the public fingerprint that names the key instead"
        );

        // An operation this machine never saw has no receipt to append to.
        assert!(read_receipt(&target, "op-receipt-9999").unwrap().is_none());
        assert_eq!(
            reason_of(
                &append_receipt_step(&target, "op-receipt-9999", "started", "ok", None)
                    .unwrap_err()
            ),
            "unknown_operation"
        );

        let appended =
            append_receipt_step(&target, operation, "service_started", "ok", Some("by hand"))
                .unwrap();
        assert_eq!(appended.steps.len(), 4);
        for hostile in ["", "a\nb"] {
            assert_eq!(
                reason_of(
                    &append_receipt_step(&target, operation, hostile, "ok", None).unwrap_err()
                ),
                "invalid_request"
            );
        }
        // The file is bounded: a peer cannot grow it without limit.
        for index in 0..MAX_RECEIPT_STEPS {
            let step = format!("filler-{index}");
            if append_receipt_step(&target, operation, &step, "ok", None).is_err() {
                break;
            }
        }
        assert_eq!(
            reason_of(
                &append_receipt_step(&target, operation, "one-more", "ok", None).unwrap_err()
            ),
            "receipt_full"
        );
    }

    /// An operation id names a directory and a file on a machine an operator does not
    /// have a shell on, so it is checked before it is either.
    #[test]
    fn an_operation_id_cannot_name_a_path() {
        for hostile in [
            "../../etc/passwd",
            "op/../../root",
            "op.with.dots",
            "OP-UPPERCASE1",
            "short",
            "-leading-hyphen",
            "trailing-hyphen-",
            "double--hyphen",
            "",
        ] {
            assert!(
                validate_operation_id(hostile).is_err(),
                "`{hostile}` must not be usable as an operation id"
            );
        }
        validate_operation_id("op-2026-09-17-a1").unwrap();
        validate_operation_id("0123456789abcdef").unwrap();
    }

    /// Inspection is what an orchestrator reads before it decides anything, so it
    /// answers for a standalone machine, one with an operation pending, and one that
    /// has been admitted — and it answers with no secret at all.
    #[test]
    fn inspection_reports_identity_and_pending_work_and_no_secret() {
        let target = scratch("target-inspect");
        let blank = inspect_local(&target).unwrap();
        assert!(blank.fleet.is_none());
        assert!(blank.pending_operations.is_empty());
        assert!(!blank.runtime_running);
        assert_eq!(blank.data_dir, target.display().to_string());
        assert_eq!(blank.os, std::env::consts::OS);

        let operation = "op-inspect-0001";
        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        assert_eq!(
            inspect_local(&target).unwrap().pending_operations,
            vec![operation.to_string()]
        );

        let issuer = issuer_fleet("issuer-inspect");
        let materials = issue_member_certificate(&issuer, &request).unwrap();
        install_admission(&target, &materials, ephemeral_ports()).unwrap();

        let admitted = inspect_local(&target).unwrap();
        assert!(admitted.pending_operations.is_empty());
        let fleet = admitted.fleet.expect("an admitted machine has a fleet");
        assert_eq!(fleet.node, "ouro-vps@127.0.0.1");
        assert_eq!(fleet.members, vec!["studio".to_string(), "vps".to_string()]);
        let rendered = serde_json::to_string(&inspect_local(&target).unwrap()).unwrap();
        let cookie = read_private(&fleet_dir(&target).join(COOKIE_FILE), "cookie").unwrap();
        assert!(!rendered.contains(&cookie));
        assert!(!rendered.contains("PRIVATE KEY"));
    }

    /// Materials hold the fleet's cookie, so the one way they could leak it is a
    /// derived `Debug` in a panic message or an error chain. There is not one.
    #[test]
    fn admission_materials_redact_their_cookie_when_printed() {
        let issuer = issuer_fleet("issuer-debug");
        let target = scratch("target-debug");
        let request = prepare_admission(&target, "op-debug-000001", "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request).unwrap();

        let printed = format!("{materials:?}");
        assert!(!printed.contains(&materials.cookie));
        assert!(printed.contains("<redacted>"));
        assert!(printed.contains(&materials.operation));
    }

    #[test]
    fn preparation_cleanup_is_scoped_and_refuses_materials() {
        let target = scratch("discard-prep");
        let op = "op-discard-prep";
        prepare_admission(&target, op, "vps", "127.0.0.1").unwrap();
        discard_preparation(&target, "op-other-prep").unwrap();
        assert!(admission_dir(&target, op).exists());
        let cookie = admission_dir(&target, op).join(COOKIE_FILE);
        write_private_new(&cookie, b"not-yet-installed", "test materials").unwrap();
        assert!(discard_preparation(&target, op).is_err());
        assert!(admission_dir(&target, op).join(NODE_KEY_FILE).exists());
        fs::remove_file(cookie).unwrap();
        discard_preparation(&target, op).unwrap();
        assert!(!admission_dir(&target, op).exists());
        discard_preparation(&target, op).unwrap();
        let _ = fs::remove_dir_all(target);
    }

    /// `ouro fleet leave` retires a machine that was admitted, receipts and all. The
    /// receipts directory is a recognized entry, not an unknown one that would make
    /// the command refuse to remove a single credential.
    #[test]
    fn leave_retires_an_admitted_machine_together_with_its_receipts() {
        let issuer = issuer_fleet("issuer-leave");
        let target = scratch("target-leave");
        let request = prepare_admission(&target, "op-leave-0000001", "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request).unwrap();
        install_admission(&target, &materials, ephemeral_ports()).unwrap();

        assert!(doctor(&target)
            .text
            .lines()
            .all(|line| !line.contains("unknown entries")));

        let removal = leave(&target)
            .unwrap()
            .expect("an admitted machine to retire");
        assert!(removal.removed.iter().any(|name| name == RECEIPTS_DIR));
        assert!(!fleet_dir(&target).try_exists().unwrap());

        // An unknown entry beside the receipts is still a refusal.
        let other = scratch("target-leave-unknown");
        create(&other, None, "vps", "127.0.0.1", ephemeral_ports()).unwrap();
        fs::create_dir(fleet_dir(&other).join(RECEIPTS_DIR)).unwrap();
        fs::set_permissions(
            fleet_dir(&other).join(RECEIPTS_DIR),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        write_private_atomic(
            &fleet_dir(&other).join(RECEIPTS_DIR).join("notes.txt"),
            b"hand written",
        )
        .unwrap();
        let error = leave(&other).unwrap_err();
        assert!(
            format!("{error:#}").contains("receipts/notes.txt"),
            "{error:#}"
        );
        assert!(fleet_dir(&other).join(COOKIE_FILE).try_exists().unwrap());
        // And `doctor` names the same entry, by the same predicate: a refusal nothing
        // reports is a dead end an operator cannot get out of.
        let report = doctor(&other);
        assert!(!report.healthy);
        assert!(
            report.text.contains("receipts/notes.txt"),
            "doctor must name what leave refuses over:\n{}",
            report.text
        );
    }

    // -----------------------------------------------------------------------
    // Adversarial review of the first commit. Each test below is one of the
    // reviewer's exploits with its assertion turned the other way up.
    // -----------------------------------------------------------------------

    /// One machine is one identity, however it is spelled.
    ///
    /// Every identity comparison here used to be a byte comparison while
    /// `validate_machine` accepted upper case, so `Vps` was a different machine from
    /// `vps` to the roster, to the tombstones and to the ledger of machines already
    /// issued for. A machine the operator had declared gone for good came back under a
    /// shift key, with the fleet cookie, and `ouro fleet doctor` called it healthy.
    #[test]
    fn a_second_spelling_of_a_machine_name_is_the_same_machine() {
        let issuer = issuer_fleet("issuer-case");

        // Nothing new is minted under a name that is not lower case.
        let target = scratch("target-case");
        for spelling in ["Vps", "VPS", "vPs"] {
            let error =
                prepare_admission(&target, "op-case-0000001", spelling, "127.0.0.1").unwrap_err();
            assert_eq!(reason_of(&error), "invalid_request", "{spelling}");
            assert!(
                format!("{error:#}").contains("lower case"),
                "the refusal has to say what to do instead: {error:#}"
            );
        }
        let request = prepare_admission(&target, "op-case-0000001", "vps", "127.0.0.1").unwrap();
        issue_member_certificate(&issuer, &request).unwrap();

        // A roster written by an older `ouro fleet members add`, which still accepts
        // either case, still shadows: the entry on disk wins whichever way it is spelled.
        let legacy = issuer_fleet("issuer-case-legacy");
        add_member(&legacy, "Vps", "127.0.0.1", None).unwrap();
        let hand_crafted = crafted_request("op-case-0000002", "vps", "127.0.0.1", |_| {});
        assert_eq!(
            reason_of(&issue_member_certificate(&legacy, &hand_crafted).unwrap_err()),
            "machine_known",
            "a lower-case request must not slip past a mixed-case roster entry"
        );
        forget_machine(&legacy, "Vps").unwrap();
        assert_eq!(
            reason_of(&issue_member_certificate(&legacy, &hand_crafted).unwrap_err()),
            "machine_known",
            "and a machine declared gone for good stays gone under any spelling"
        );

        // The same rule inside the issuer's own ledger of what it has issued.
        let upper = crafted_request("op-case-0000003", "VPS", "127.0.0.1", |_| {});
        assert_eq!(
            reason_of(&issue_member_certificate(&issuer, &upper).unwrap_err()),
            "invalid_request"
        );
        let mut folded = crafted_request("op-case-0000004", "vps", "127.0.0.1", |_| {});
        folded.machine = "vps".to_string();
        assert_eq!(
            reason_of(&issue_member_certificate(&issuer, &folded).unwrap_err()),
            "machine_already_issued"
        );

        // And the issuer's own name is not available as a second spelling.
        let its_own = crafted_request("op-case-0000005", "studio", "127.0.0.1", |_| {});
        assert_eq!(
            reason_of(&issue_member_certificate(&issuer, &its_own).unwrap_err()),
            "machine_known"
        );
    }

    /// The same folding on the roster editors an operator types, not only on admission.
    #[test]
    fn roster_editors_treat_a_second_spelling_as_the_same_machine() {
        let dir = scratch("members-case");
        create(&dir, None, "studio", "127.0.0.1", ephemeral_ports()).unwrap();
        add_member(&dir, "Vps", "127.0.0.1", None).unwrap();

        let error = add_member(&dir, "vps", "127.0.0.1", None)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("already names"),
            "vps beside Vps is one machine: {error}"
        );
        assert_eq!(
            load(&dir)
                .unwrap()
                .unwrap()
                .members
                .iter()
                .filter(|member| same_name(&member.machine, "vps"))
                .count(),
            1,
            "a refused add must not write a second spelling"
        );

        let removed = remove_member(&dir, "vps").unwrap();
        assert_eq!(removed.machine, "Vps");
        assert!(load(&dir)
            .unwrap()
            .unwrap()
            .members
            .iter()
            .all(|member| !same_name(&member.machine, "vps")));

        add_member(&dir, "Vps", "127.0.0.1", None).unwrap();
        let forgotten = forget_machine(&dir, "vps").unwrap();
        assert_eq!(forgotten.machine, "Vps");
        let after = load(&dir).unwrap().unwrap();
        assert!(after
            .members
            .iter()
            .all(|member| !same_name(&member.machine, "vps")));
        assert_eq!(after.tombstones, vec![forgotten]);

        fs::remove_dir_all(dir).ok();
    }

    /// One address is one node name, however it is spelled.
    ///
    /// A resolver reads `127.1`, `2130706433` and `0x7f.0.0.1` as `127.0.0.1`, and this
    /// code used to read all three as DNS names — so a member could be dialed at an
    /// address and certified under a name, and two members could spell one address two
    /// ways and be two node names for one machine.
    #[test]
    fn a_second_spelling_of_an_address_is_the_same_address() {
        for numeric in ["127.1", "2130706433", "0x7f.0.0.1", "0x7f000001"] {
            let error = validate_host(numeric).unwrap_err();
            assert!(
                format!("{error:#}").contains("dotted-quad"),
                "`{numeric}` must be refused as an address written another way: {error:#}"
            );
        }
        for empty_label in ["127.0.0.1.", ".127.0.0.1", "studio..internal"] {
            assert!(
                validate_host(empty_label).is_err(),
                "`{empty_label}` has an empty label"
            );
        }

        // What survives canonicalises, and the canonical spelling is what gets minted.
        assert_eq!(canonical_host("LOCALHOST").unwrap(), "localhost");
        assert_eq!(canonical_host("localhost.").unwrap(), "localhost");
        assert_eq!(canonical_host("127.0.0.1.").unwrap(), "127.0.0.1");
        assert_eq!(
            canonical_host("Studio.Tailnet.TS.net").unwrap(),
            "studio.tailnet.ts.net"
        );

        let target = scratch("target-host-case");
        let request = prepare_admission(&target, "op-host-0000001", "vps", "127.0.0.1.").unwrap();
        assert_eq!(
            request.node, "ouro-vps@127.0.0.1",
            "the trailing root dot is not part of a node name"
        );
        assert_eq!(request.host, "127.0.0.1");

        // An issuer will not accept a request that spells the host another way, even
        // when the spelling is one a resolver would accept.
        let issuer = issuer_fleet("issuer-host-case");
        let mut uncanonical = crafted_request("op-host-0000002", "vps", "127.0.0.1", |_| {});
        uncanonical.host = "127.0.0.1.".to_string();
        uncanonical.node = "ouro-vps@127.0.0.1.".to_string();
        assert_eq!(
            reason_of(&issue_member_certificate(&issuer, &uncanonical).unwrap_err()),
            "invalid_request"
        );
    }

    /// The receipt cannot be filled up to make a completed install report failure.
    ///
    /// A peer drives `receipt append` itself, so it can put the file one step from its
    /// cap and then ask for the install. The rename used to land and the closing step
    /// used to fail, so the machine was admitted, `doctor`-healthy, and reported as
    /// failed — for ever, because every retry died on the same cap. Both remaining
    /// lifecycle steps are now reserved before the first credential is written.
    #[test]
    fn a_full_receipt_refuses_the_install_before_a_credential_is_written() {
        let issuer = issuer_fleet("issuer-receipt-cap");
        let target = scratch("target-receipt-cap");
        let operation = "op-cap-00000001";

        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        // `prepare` wrote one step; pad to 63, one short of the cap.
        for index in 0..62 {
            append_receipt_step(&target, operation, &format!("probe-{index}"), "ok", None).unwrap();
        }
        assert_eq!(
            read_receipt(&target, operation)
                .unwrap()
                .unwrap()
                .steps
                .len(),
            63
        );

        let materials = issue_member_certificate(&issuer, &request).unwrap();
        let error = install_admission(&target, &materials, ephemeral_ports()).unwrap_err();
        assert_eq!(reason_of(&error), "receipt_full");
        assert!(
            !fleet_dir(&target).try_exists().unwrap(),
            "a refusal means the machine was not admitted, and this one was refused"
        );
        assert!(
            !admission_dir(&target, operation)
                .join(COOKIE_FILE)
                .try_exists()
                .unwrap(),
            "and no credential was written on the way to that refusal"
        );

        // Exactly two steps of headroom is enough, and one fewer is not.
        let second = scratch("target-receipt-edge");
        let request = prepare_admission(&second, operation, "vps", "127.0.0.1").unwrap();
        for index in 0..61 {
            append_receipt_step(&second, operation, &format!("probe-{index}"), "ok", None).unwrap();
        }
        assert_eq!(
            read_receipt(&second, operation)
                .unwrap()
                .unwrap()
                .steps
                .len(),
            62
        );
        let materials = issue_member_certificate(&issuer_fleet("issuer-edge"), &request).unwrap();
        let (profile, warnings) =
            install_admission_reporting(&second, &materials, ephemeral_ports()).unwrap();
        assert_eq!(profile.node, "ouro-vps@127.0.0.1");
        assert!(warnings.is_empty(), "{warnings:?}");
        let receipt = read_receipt(&second, operation).unwrap().unwrap();
        assert_eq!(receipt.steps.len(), MAX_RECEIPT_STEPS);
        assert!(receipt.has_step("install"));
    }

    /// Nothing after the rename may turn an admitted machine into a failure.
    ///
    /// By the time the rename has happened the machine holds the cookie, the CA
    /// certificate and its own leaf. If the closing record cannot be written — a full
    /// disk, a receipts directory somebody chmodded — the answer is still "admitted",
    /// with the problem said out loud.
    #[test]
    fn a_record_that_cannot_be_closed_is_a_warning_and_never_a_failure() {
        let issuer = issuer_fleet("issuer-close");
        let target = scratch("target-close");
        let operation = "op-close-0000001";
        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request).unwrap();
        install_admission(&target, &materials, ephemeral_ports()).unwrap();

        // Exactly the state a hostile or broken filesystem leaves: the record is there
        // and cannot be read back at the mode this code requires.
        let receipt_path = receipts_dir(&target).join(format!("{operation}.json"));
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o644)).unwrap();
        let profile = load(&target).unwrap().unwrap();
        let warnings = close_install_record(
            &target,
            &ReceiptSeed {
                operation: operation.to_string(),
                machine: profile.machine.clone(),
                host: profile.host.clone(),
                node: profile.node.clone(),
                key_fingerprint: Some(materials.key_fingerprint.clone()),
            },
            &profile,
        );
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("was admitted"),
            "the warning must say the machine is in the fleet: {warnings:?}"
        );
    }

    /// A refused promotion leaves no credential behind, and what it does leave is named.
    ///
    /// The fleet cookie used to be written into the staging directory before the
    /// directory had been proven promotable, so a refusal left the cookie in a private
    /// namespace that `doctor`, `leave` and orphan-staging recovery all ignored.
    #[test]
    fn a_refused_promotion_writes_no_credential_and_the_residue_is_reported_and_retired() {
        let issuer = issuer_fleet("issuer-residue");
        let target = scratch("target-residue");
        let operation = "op-residue-00001";
        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request).unwrap();

        let staging = admission_dir(&target, operation);
        write_private_new(&staging.join("notes.txt"), b"planted\n", "a planted file").unwrap();
        let error = install_admission(&target, &materials, ephemeral_ports()).unwrap_err();
        assert_eq!(reason_of(&error), "invalid_staging");
        assert!(
            !staging.join(COOKIE_FILE).try_exists().unwrap(),
            "the cookie must not be written before the directory may be promoted"
        );
        assert!(
            !staging.join(CA_CERT_FILE).try_exists().unwrap()
                && !staging.join(NODE_CERT_FILE).try_exists().unwrap()
        );

        // What is left is this machine's own prepared key, and doctor says so.
        let report = doctor(&target);
        assert!(!report.healthy);
        assert!(
            report.text.contains(operation),
            "doctor must name the pending operation:\n{}",
            report.text
        );

        // `leave` is the command that retires this machine's credentials, and a pending
        // admission is one — but not while it holds something this code did not write.
        let refused = leave(&target).unwrap_err();
        assert!(format!("{refused:#}").contains("notes.txt"), "{refused:#}");
        assert!(staging.join(NODE_KEY_FILE).try_exists().unwrap());

        fs::remove_file(staging.join("notes.txt")).unwrap();
        let removal = leave(&target)
            .unwrap()
            .expect("a pending admission to retire");
        assert_eq!(
            removal.removed,
            vec![format!("{ADMISSION_PREFIX}{operation}")]
        );
        assert!(
            !staging.try_exists().unwrap(),
            "the prepared key is gone with it"
        );
        assert!(
            !doctor(&target).text.contains(operation),
            "and doctor has nothing left to name"
        );
    }

    /// One unreadable receipt must not stop a fleet ever admitting anything again.
    ///
    /// The replay ledger is a directory of files. Reading it used to be fatal to
    /// `issue_member_certificate`, so a single file dropped in there bricked admission
    /// for every operation; the weakened check is a warning in the record instead.
    #[test]
    fn an_unreadable_receipt_weakens_the_ledger_and_says_so_rather_than_bricking_it() {
        let issuer = issuer_fleet("issuer-bad-receipt");
        let target = scratch("target-bad-receipt");
        let receipts = receipts_dir(&issuer);
        DirBuilder::new().mode(0o700).create(&receipts).unwrap();
        write_private_atomic(&receipts.join("op-corrupt-00001.json"), b"{not json").unwrap();

        let request = prepare_admission(&target, "op-ledger-000001", "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request)
            .expect("one unreadable record must not stop this machine issuing for another machine");
        assert_eq!(materials.node, "ouro-vps@127.0.0.1");

        let receipt = read_receipt(&issuer, "op-ledger-000001").unwrap().unwrap();
        let warning = receipt
            .steps
            .iter()
            .find(|step| step.step == "records_unreadable")
            .expect("the weakened check is recorded");
        assert_eq!(warning.outcome, "warning");
        assert!(warning.detail.as_deref().unwrap().contains("op-corrupt"));
    }

    /// Two roster edits computed against one revision cannot both apply.
    ///
    /// The revision was read outside the lifecycle lock and the edit took it
    /// afterwards, so two callers could both read revision 1, both pass the check and
    /// both apply — which is the lost update the check exists to prevent.
    #[test]
    fn two_roster_changes_against_one_revision_cannot_both_apply() {
        for attempt in 0..8 {
            let data = Arc::new(issuer_fleet(&format!("roster-race-{attempt}")));
            let revision = load(&data).unwrap().unwrap().roster_revision;
            let barrier = Arc::new(std::sync::Barrier::new(2));

            let handles: Vec<_> = ["alpha", "beta"]
                .into_iter()
                .map(|machine| {
                    let data = Arc::clone(&data);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        let change = RosterChange::Add {
                            machine: machine.to_string(),
                            host: "127.0.0.1".to_string(),
                            node: None,
                        };
                        barrier.wait();
                        apply_roster_change(
                            &data,
                            &format!("op-race-{machine}-01"),
                            revision,
                            &change,
                        )
                    })
                })
                .collect();
            let results: Vec<_> = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect();

            let winners = results.iter().filter(|result| result.is_ok()).count();
            assert_eq!(
                winners,
                1,
                "exactly one edit may win a revision, attempt {attempt}: {:?}",
                results
                    .iter()
                    .map(|result| result
                        .as_ref()
                        .map(|outcome| outcome.roster_revision)
                        .map_err(|error| reason_of(error).to_string()))
                    .collect::<Vec<_>>()
            );
            for error in results.iter().filter_map(|result| result.as_ref().err()) {
                assert!(
                    matches!(reason_of(error), "roster_conflict" | "lock_unavailable"),
                    "the loser is told which of the two happened: {}",
                    reason_of(error)
                );
            }
            assert_eq!(
                load(&data).unwrap().unwrap().roster_revision,
                revision + 1,
                "and the roster moved exactly one revision"
            );
        }
    }

    /// The roster will not hold two spellings of one machine either.
    #[test]
    fn a_roster_change_refuses_a_second_spelling_and_finds_the_first() {
        let data = issuer_fleet("roster-case");
        let revision = load(&data).unwrap().unwrap().roster_revision;

        // A legacy entry, written by the command that still accepts either case.
        add_member(&data, "Vps", "127.0.0.1", None).unwrap();
        let revision = revision + 1;
        assert_eq!(load(&data).unwrap().unwrap().roster_revision, revision);

        let error = apply_roster_change(
            &data,
            "op-roster-case-1",
            revision,
            &RosterChange::Add {
                machine: "vps".to_string(),
                host: "127.0.0.1".to_string(),
                node: None,
            },
        )
        .unwrap_err();
        assert_eq!(reason_of(&error), "roster_refused");
        assert_eq!(
            load(&data).unwrap().unwrap().members.len(),
            2,
            "a refused change changes nothing"
        );

        // Naming it in lower case still finds the entry that is there.
        let removed = apply_roster_change(
            &data,
            "op-roster-case-2",
            revision,
            &RosterChange::Remove {
                machine: "vps".to_string(),
            },
        )
        .unwrap();
        assert_eq!(removed.member.machine, "Vps");

        // And an upper-case name is never accepted from the wire at all.
        assert_eq!(
            reason_of(
                &apply_roster_change(
                    &data,
                    "op-roster-case-3",
                    removed.roster_revision,
                    &RosterChange::Add {
                        machine: "Laptop".to_string(),
                        host: "127.0.0.1".to_string(),
                        node: None,
                    },
                )
                .unwrap_err()
            ),
            "invalid_request"
        );
    }

    /// Materials name a key by fingerprint, and it has to be the key this machine has.
    #[test]
    fn install_refuses_materials_that_name_a_key_this_machine_did_not_prepare() {
        let issuer = issuer_fleet("issuer-fingerprint");
        let target = scratch("target-fingerprint");
        let operation = "op-print-0000001";
        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request).unwrap();

        let mut lying = materials.clone();
        lying.key_fingerprint = public_fingerprint(b"some other key");
        let error = install_admission(&target, &lying, ephemeral_ports()).unwrap_err();
        assert_eq!(reason_of(&error), "materials_invalid");
        assert!(!fleet_dir(&target).try_exists().unwrap());

        // The honest ones still install.
        install_admission(&target, &materials, ephemeral_ports()).unwrap();
        assert_eq!(
            read_receipt(&target, operation)
                .unwrap()
                .unwrap()
                .key_fingerprint
                .as_deref(),
            Some(materials.key_fingerprint.as_str()),
            "and the record names the key that was really used"
        );
    }

    /// An idempotent answer that ignores what it was handed is not idempotent.
    ///
    /// Repeating an install is how a lost connection is resolved, so it answers `ok` —
    /// but only for the credentials that are actually installed. A second set under the
    /// same operation id is a different question with the same name.
    #[test]
    fn repeating_an_install_with_different_credentials_is_refused() {
        let issuer = issuer_fleet("issuer-differ");
        let target = scratch("target-differ");
        let operation = "op-differ-000001";
        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request).unwrap();
        let ports = ephemeral_ports();
        install_admission(&target, &materials, ports).unwrap();
        install_admission(&target, &materials, ports).expect("the same materials repeat");

        for (label, mutate) in [
            (
                "a different cookie",
                Box::new(|materials: &mut AdmissionMaterials| {
                    materials.cookie = "0".repeat(64);
                }) as Box<dyn Fn(&mut AdmissionMaterials)>,
            ),
            (
                "a different CA",
                Box::new(|materials: &mut AdmissionMaterials| {
                    let other = issuer_fleet("issuer-differ-other");
                    materials.ca_cert_pem =
                        read_private(&fleet_dir(&other).join(CA_CERT_FILE), "a CA").unwrap();
                }),
            ),
        ] {
            let mut different = materials.clone();
            mutate(&mut different);
            let error = install_admission(&target, &different, ports).unwrap_err();
            assert_eq!(reason_of(&error), "materials_differ", "{label}");
        }

        // A machine that belongs to another fleet is not answered for at all.
        let elsewhere = issuer_fleet("issuer-elsewhere");
        let stranger = scratch("target-elsewhere");
        let its_request = prepare_admission(&stranger, operation, "vps", "127.0.0.1").unwrap();
        let its_materials = issue_member_certificate(&elsewhere, &its_request).unwrap();
        assert_eq!(
            reason_of(&install_admission(&target, &its_materials, ports).unwrap_err()),
            "fleet_exists",
            "materials for another fleet under this operation id are not this machine's"
        );
    }

    /// The guards the mutation harness could reach but no test could.
    ///
    /// Each block below is one deleted check made observable: a request naming two
    /// nodes, a machine holding the CA certificate but not its key, an issuer whose own
    /// CA is not one this build would accept, a request whose node name does not follow
    /// from its machine and host, a staged key swapped under a prepared operation, and a
    /// receipt that belongs to another machine.
    #[test]
    fn every_issuer_guard_refuses_something_a_test_can_produce() {
        let issuer = issuer_fleet("issuer-guards");

        // M03: two common names, the second of which is the approved one.
        let two_names = crafted_request("op-guard-0000001", "vps", "127.0.0.1", |params| {
            params.distinguished_name.push(
                DnType::CustomDnType(vec![2, 5, 4, 3]),
                "ouro-studio@127.0.0.1",
            );
        });
        assert_eq!(
            reason_of(&issue_member_certificate(&issuer, &two_names).unwrap_err()),
            "csr_identity_mismatch",
            "a certificate with two names is a certificate for two machines"
        );

        // M15: a node name that does not follow from the machine and the host.
        let mut renamed = crafted_request("op-guard-0000002", "vps", "127.0.0.1", |_| {});
        renamed.node = "ouro-studio@127.0.0.1".to_string();
        assert_eq!(
            reason_of(&issue_member_certificate(&issuer, &renamed).unwrap_err()),
            "invalid_request"
        );

        // M11: a machine given the CA certificate and not the key cannot admit.
        let joiner = scratch("joiner-no-ca-key");
        let copy = scratch("joiner-copy").join("fleet");
        copy_fleet_dir(&fleet_dir(&issuer), &copy);
        create_from(&joiner, &copy, "vps", "127.0.0.1", ephemeral_ports()).unwrap();
        assert!(!fleet_dir(&joiner).join(CA_KEY_FILE).try_exists().unwrap());
        let asking = crafted_request("op-guard-0000003", "laptop", "127.0.0.1", |_| {});
        assert_eq!(
            reason_of(&issue_member_certificate(&joiner, &asking).unwrap_err()),
            "no_ca_key"
        );

        // M13: the issuer validates what it just minted with the rules the runtime
        // applies, so a CA this build would refuse at boot cannot be used to admit.
        let hostile = issuer_fleet("issuer-hostile-ca");
        let year = current_utc_year().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.not_before = date_time_ymd(year - 1, 1, 1);
        // Twenty years: longer than `validate_tls_identity` will accept from anyone.
        ca_params.not_after = date_time_ymd(year + 19, 1, 1);
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "a CA nobody should accept");
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        write_private_atomic(
            &fleet_dir(&hostile).join(CA_CERT_FILE),
            ca_cert.pem().as_bytes(),
        )
        .unwrap();
        write_private_atomic(
            &fleet_dir(&hostile).join(CA_KEY_FILE),
            ca_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let asking = crafted_request("op-guard-0000004", "vps", "127.0.0.1", |_| {});
        let error = issue_member_certificate(&hostile, &asking).unwrap_err();
        assert!(
            format!("{error:#}").contains("unreasonably long"),
            "the issuer must check its own work: {error:#}"
        );

        // The same statement about the key rather than the certificate: the leaf that
        // comes back carries exactly the key the request proved possession of. The
        // issuer signs the key it was handed, so no input can make this false; the
        // check inside `issue_member_certificate` is an assertion about rcgen, not a
        // guard against a caller, and deleting it fails no test. Asserted, not provoked.
        let honest = crafted_request("op-guard-0000005", "vps", "127.0.0.1", |_| {});
        let materials = issue_member_certificate(&issuer, &honest).unwrap();
        let (_, block) = parse_x509_pem(honest.csr_pem.as_bytes()).unwrap();
        let (_, parsed) = X509CertificationRequest::from_der(&block.contents).unwrap();
        assert_eq!(
            certificate_public_key(&materials.node_cert_pem, "the issued leaf").unwrap(),
            parsed.certification_request_info.subject_pki.raw.to_vec()
        );
    }

    /// The guards on the target's side of the same list.
    #[test]
    fn every_target_guard_refuses_something_a_test_can_produce() {
        // One issuer per block: an issuer mints one identity per machine name, which is
        // the point of `machine_already_issued` and not what these blocks are about.
        // M30: the staged key is swapped under a prepared operation.
        let target = scratch("target-swapped-key");
        let operation = "op-guard-0000010";
        let first = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        let replacement = KeyPair::generate().unwrap();
        write_private_atomic(
            &admission_dir(&target, operation).join(NODE_KEY_FILE),
            replacement.serialize_pem().as_bytes(),
        )
        .unwrap();
        let error = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap_err();
        assert_eq!(
            reason_of(&error),
            "identity_mismatch",
            "a request is only an answer while the key it names is the staged one"
        );
        let _ = &first;

        // M34: a receipt that records another machine is not this operation's receipt.
        let other = scratch("target-foreign-receipt");
        let operation = "op-guard-0000011";
        let request = prepare_admission(&other, operation, "vps", "127.0.0.1").unwrap();
        let path = admission_dir(&other, operation)
            .join(RECEIPTS_DIR)
            .join(format!("{operation}.json"));
        let mut receipt: Receipt =
            serde_json::from_str(&read_private(&path, "receipt").unwrap()).unwrap();
        receipt.node = "ouro-laptop@127.0.0.1".to_string();
        write_private_atomic(&path, &serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
        let materials =
            issue_member_certificate(&issuer_fleet("issuer-foreign-receipt"), &request).unwrap();
        assert_eq!(
            reason_of(&install_admission(&other, &materials, ephemeral_ports()).unwrap_err()),
            "identity_mismatch"
        );

        // M26: a fleet on disk whose receipt does not say this operation installed it.
        let third = scratch("target-no-evidence");
        let operation = "op-guard-0000012";
        let request = prepare_admission(&third, operation, "vps", "127.0.0.1").unwrap();
        let materials =
            issue_member_certificate(&issuer_fleet("issuer-no-evidence"), &request).unwrap();
        let ports = ephemeral_ports();
        install_admission(&third, &materials, ports).unwrap();
        let path = receipts_dir(&third).join(format!("{operation}.json"));
        let mut receipt: Receipt =
            serde_json::from_str(&read_private(&path, "receipt").unwrap()).unwrap();
        receipt
            .steps
            .retain(|step| step.step != "install" && step.step != "install_staged");
        write_private_atomic(&path, &serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
        assert_eq!(
            reason_of(&install_admission(&third, &materials, ports).unwrap_err()),
            "fleet_exists",
            "without a record of this operation installing it, the fleet here is somebody else's"
        );

        // M25: the same operation id, a different fleet, an already-installed machine.
        let fourth = scratch("target-other-fleet");
        let operation = "op-guard-0000013";
        let request = prepare_admission(&fourth, operation, "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer_fleet("issuer-fourth"), &request).unwrap();
        install_admission(&fourth, &materials, ephemeral_ports()).unwrap();
        let elsewhere = issuer_fleet("issuer-other-fleet");
        let elsewhere_target = scratch("target-other-fleet-src");
        let its_request =
            prepare_admission(&elsewhere_target, operation, "vps", "127.0.0.1").unwrap();
        let its_materials = issue_member_certificate(&elsewhere, &its_request).unwrap();
        assert_eq!(
            reason_of(&install_admission(&fourth, &its_materials, ephemeral_ports()).unwrap_err()),
            "fleet_exists"
        );
    }

    /// M20: the spec names the stopped-runtime lock, and `install` takes it.
    ///
    /// A running BEAM holds the credentials in this directory open. Replacing them
    /// under it is how a node ends up with a profile its own runtime disagrees with.
    #[test]
    fn install_refuses_while_a_runtime_is_using_the_data_directory() {
        let issuer = issuer_fleet("issuer-live");
        let target = scratch("target-live");
        let operation = "op-live-00000001";
        let request = prepare_admission(&target, operation, "vps", "127.0.0.1").unwrap();
        let materials = issue_member_certificate(&issuer, &request).unwrap();

        // The same live-runtime shape `stopped_mutations_share_the_runtime_lock_and_
        // refuse_every_live_owner_shape` plants for `create`.
        write_private_atomic(
            &target.join(runtime::PUBLICATION_FILE),
            format!(
                r#"{{"port":47001,"protocol":1,"node":"ouro-vps@127.0.0.1","pid":{},"scope":"operate"}}"#,
                std::process::id()
            )
            .as_bytes(),
        )
        .unwrap();

        let error = install_admission(&target, &materials, ephemeral_ports()).unwrap_err();
        assert!(
            format!("{error:#}").contains("still using this data directory"),
            "install must take the lock that proves the runtime is stopped: {error:#}"
        );
        assert!(!fleet_dir(&target).try_exists().unwrap());

        fs::remove_file(target.join(runtime::PUBLICATION_FILE)).unwrap();
        install_admission(&target, &materials, ephemeral_ports()).unwrap();
    }
}
