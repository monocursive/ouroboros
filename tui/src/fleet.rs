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
            "Ouroboros found local hostname `{host}`, but cannot safely assume another machine can reach it. Rerun with explicit `--host HOST`, using a Tailscale MagicDNS name, private DNS name, or private IPv4 address (example: `ouro fleet setup --machine studio-mini --host studio-mini.tailnet.ts.net`). Explicit loopback remains available for same-host labs"
        );
    }
    ensure_usable_ipv4_resolution(host).with_context(|| {
        format!(
            "Ouroboros cannot safely publish inferred hostname `{host}`; rerun with an explicit reachable `--host HOST`"
        )
    })
}

/// The one sentence a profile this build cannot read gets.
///
/// §2 and §12: there is no migration, and a machine on a schema-1 profile cannot form a
/// fleet with a schema-2 machine. `ouro fleet status`, `ouro fleet doctor` and the
/// launcher all reach this through [`load`].
///
/// Word for word the runtime's own `@unsupported_profile_message`
/// (`lib/ouroboros/cluster.ex`), because `fleet.status` and `fleet.doctor` answer about
/// this same file with that sentence while the CLI answers with this one: an operator
/// who ran both and read two different sentences would reasonably conclude they were
/// two different faults. It names the disagreement rather than its direction — a
/// profile from a *newer* Ouroboros is the same file, the same repair, the same words.
pub const SCHEMA_1_SENTENCE: &str = "this fleet's profile was written by a different version of Ouroboros than the one running here; run `ouro fleet leave` here and set the fleet up again.";

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
        return refuse(
            "machine_unknown",
            format!("this machine's roster has no member named {machine}; `ouro fleet status` prints the names it knows"),
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
///
/// `OUROBOROS_DIST_PORTS` is keyed by the **full node name**, one entry per member
/// including this one. `Ouroboros.Cluster.Epmd.port_please/2` consults `name@host`
/// first and falls back to a bare host key, and a full-name key is what makes two lab
/// nodes on one host resolvable at all — two `host=port` entries for one host cannot
/// both be true. `OUROBOROS_DIST_PORT_MIN`/`_MAX` are gone with the range: the
/// generated `vm.args` pins `inet_dist_listen_min/max` to `dist_port` directly.
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
        .map(|member| format!("{}={}", member.node, member.dist_port))
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
    leave_locked(data_dir)
}

/// Remote removal must name the identity it is authorized to retire. Unlike a local
/// repair, it cannot delete an unreadable or repurposed fleet directory.
pub(crate) fn check_removal_identity(data_dir: &Path, machine: &str, fleet_id: &str) -> Result<()> {
    match load(data_dir).map_err(|error| refusing("fleet_unreadable", error))? {
        Some(profile) if same_name(&profile.machine, machine) && profile.fleet_id == fleet_id => Ok(()),
        None if !fleet_dir(data_dir).try_exists()? => Ok(()),
        _ => refuse(
            "identity_mismatch",
            "this data directory no longer holds the machine and fleet named by the removal; nothing was removed",
        ),
    }
}

pub(crate) fn leave_matching(
    data_dir: &Path,
    machine: &str,
    fleet_id: &str,
) -> Result<Option<Removal>> {
    ensure_data_dir(data_dir)?;
    let _lock = lock_stopped_fleet_mutation(data_dir, "ouro fleet helper leave")?;
    // Recheck after the stop/service calls, under the same lock as the deletion.
    check_removal_identity(data_dir, machine, fleet_id)?;
    leave_locked(data_dir)
}

fn leave_locked(data_dir: &Path) -> Result<Option<Removal>> {
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
    // Folded, because `same_name` is what every *other* reader of this list compares
    // with: `remove_member`, `add_member` and the engine's roster edits all match a
    // machine case-insensitively, so a profile holding both `pi` and `Pi` is one where
    // "the member named pi" has two answers and a removal takes whichever `find` reached
    // first. Byte-exact de-duplication called that profile valid.
    let mut nodes = BTreeSet::new();
    let mut machines = BTreeSet::new();
    for member in &profile.members {
        validate_member(member)?;
        if !nodes.insert(member.node.to_ascii_lowercase()) {
            bail!("fleet profile repeats node {}", member.node);
        }
        if !machines.insert(member.machine.to_ascii_lowercase()) {
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

/// What a join does about a fleet directory that is already there.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Existing {
    /// Refuse it: `already_installed` for the idempotent replay, `fleet_present` for a
    /// profile that is somebody's identity. Nothing on that machine is touched.
    #[default]
    Refuse,
    /// Replace it, because §7's `install` was asked to (`replace: true`). The deletion
    /// happens under this function's own lock and *after* every check that could refuse
    /// the request, which is the difference between "the operator asked for this fleet
    /// to be replaced" and "a malformed request left a machine with nothing".
    Replace,
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
    join_over(data_dir, bundle, machine, host, ports, Existing::Refuse)
}

/// The same, told what to do about a fleet that is already on this machine.
///
/// §7's `install` used to reach `Existing::Replace` by calling [`leave`] first, from the
/// helper, before anything about the request had been looked at — so a bundle with a
/// cookie that is not 64 hex characters, or a machine name this build will not mint,
/// deleted the cookie, the shared CA key and this machine's node key and then refused.
/// The two halves are one operation here: one lock, every refusal raised before the old
/// directory is touched, and the removal immediately before the rename that publishes
/// the new one.
pub fn join_over(
    data_dir: &Path,
    bundle: &Bundle,
    machine: &str,
    host: &str,
    ports: Ports,
    existing: Existing,
) -> Result<Profile> {
    validate_bundle(bundle)?;
    validate_joined_machine(machine)?;
    let host = canonical_host(host)?;
    validate_ports(ports).map_err(|error| refusing("invalid_request", error))?;
    ensure_usable_ipv4_resolution(&host).map_err(|error| refusing("unusable_host", error))?;
    ensure_data_dir(data_dir)?;
    // The stop gate, and the one lock this whole operation runs under — including the
    // removal a `replace` performs, which used to take this same lock separately from
    // inside `leave`. Its refusal carries §7's own reason: an operator told `helper
    // refused` about a machine whose runtime is simply still up has been told nothing.
    let _lock = lock_stopped_fleet_mutation(data_dir, "ouro fleet helper install")
        .map_err(|error| refusing("runtime_running", error))?;
    ensure_local_bind_address(&host).map_err(|error| refusing("unusable_host", error))?;

    let dist_port = ports.dist.unwrap_or(bundle.dist_port);
    let local = member(machine, &host, dist_port);
    let final_dir = fleet_dir(data_dir);
    // `symlink_metadata`, because `try_exists` follows a link: a `fleet` symlink
    // pointing anywhere would read as absent and the write would then fail with whatever
    // the filesystem said. This is a state an orchestrator has to be able to branch on.
    //
    // A `replace` only *notes* that there is something to remove. What it removes it
    // with is `remove_fleet_dir`, below, once nothing can refuse any more.
    let mut replacing = false;
    match fs::symlink_metadata(&final_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => match existing {
            Existing::Refuse => return refuse_existing_fleet(data_dir, bundle, machine),
            Existing::Replace => replacing = true,
        },
        Ok(metadata) => {
            // Never replaced, whatever was asked: a symlink or a file wearing this name
            // is not a fleet this machine installed, and removing it would be removing
            // something nobody here can describe.
            return refuse(
                "fleet_present",
                format!(
                    "{} already exists and is not a directory (symlink={}); nothing was installed. Inspect it, then move it aside",
                    final_dir.display(),
                    metadata.file_type().is_symlink()
                ),
            );
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
    // The last thing before the publishing rename, and the only step between the two.
    // Everything that could have refused this request has run: the bundle is valid, the
    // machine name is one this build mints, the host resolves and binds, the ports are
    // free, and the leaf has been signed and checked against the CA it came with.
    if replacing {
        remove_fleet_dir(&final_dir).map_err(|error| refusing("fleet_present", error))?;
    }
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
    // `validate_ports`, not `validate_port`: the fleet's distribution port has one more
    // rule than "not zero", and it is the rule that matters. 4369 is EPMD's historical
    // port, refused on `--dist-port` since the day that flag existed — and a bundle
    // carrying it went straight through, because this was the one caller that checked
    // the number instead of the policy.
    validate_ports(Ports {
        gateway: None,
        dist: Some(bundle.dist_port),
    })
    .map_err(|error| refusing("bundle_invalid", error))?;
    // §2: `members` always includes the machine that wrote the profile, so a bundle
    // naming nobody is not a fleet this machine can join — it is a document that would
    // install a member list with one entry, this machine, and no way to reach anything.
    if bundle.members.is_empty() {
        return refuse(
            "bundle_invalid",
            "the bundle names no members; a fleet's member list always includes the machine that made it",
        );
    }
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
    use std::sync::atomic::{AtomicU64, Ordering};

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

    fn env_value<'a>(environment: &'a [(String, String)], key: &str) -> &'a str {
        environment
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("{key} is not in the computed runtime environment"))
    }

    fn reason_of(error: &anyhow::Error) -> &str {
        refusal(error)
            .map(|declared| declared.reason)
            .unwrap_or("<undeclared>")
    }

    fn sample_profile(machine: &str) -> Profile {
        Profile {
            schema: PROFILE_SCHEMA,
            fleet_id: "00112233445566778899aabb".into(),
            name: "Workshop fleet".into(),
            machine: machine.into(),
            host: "studio.tailnet.ts.net".into(),
            node: format!("ouro-{machine}@studio.tailnet.ts.net"),
            role: "core".into(),
            dist_port: 44_111,
            gateway_port: 48_111,
            members: vec![member(machine, "studio.tailnet.ts.net", 44_111)],
            tags: empty_tags(),
        }
    }

    /// Doctor performs real local listener checks even when other fixture material is
    /// missing. Give those tests numeric loopback hosts and allocated test ports.
    fn loopback_test_profile(machine: &str) -> Profile {
        let ports = ephemeral_ports();
        let local = member(machine, "127.0.0.1", ports.dist.unwrap());
        Profile {
            host: local.host.clone(),
            node: local.node.clone(),
            members: vec![local],
            gateway_port: ports.gateway.unwrap(),
            dist_port: ports.dist.unwrap(),
            ..sample_profile(machine)
        }
    }

    /// A fleet on loopback, with ports no live lab can be using.
    fn create_local(label: &str, machine: &str) -> (PathBuf, Profile) {
        let dir = scratch(label);
        let profile =
            create(&dir, None, machine, "127.0.0.1", ephemeral_ports()).expect("a loopback fleet");
        (dir, profile)
    }

    #[test]
    fn tags_round_trip_and_validate_before_persisting() {
        let dir = scratch("tags");
        fs::create_dir(dir.join("fleet")).unwrap();
        let profile = loopback_test_profile("studio");
        write_profile(&dir, &profile).expect("a profile");

        assert!(tags(&dir, None, None).expect("no tags yet").is_empty());
        assert_eq!(
            tags(&dir, None, Some(("xcode", true))).expect("one tag"),
            vec!["xcode".to_string()]
        );
        // Idempotent: adding the same tag twice is one tag.
        assert_eq!(
            tags(&dir, None, Some(("xcode", true))).expect("still one tag"),
            vec!["xcode".to_string()]
        );
        assert!(tags(&dir, None, Some(("Bad Tag", true))).is_err());
        assert_eq!(
            tags(&dir, None, Some(("xcode", false))).expect("removal"),
            Vec::<String>::new()
        );
    }

    /// §2 and §12: a profile written before the simplification gets one sentence, and
    /// every surface that reads a profile reaches it through `load`.
    #[test]
    fn a_schema_one_profile_is_refused_with_the_one_sentence() {
        let dir = scratch("schema-1");
        fs::create_dir(dir.join("fleet")).unwrap();
        let legacy = serde_json::json!({
            "schema": 1,
            "fleet_id": "00112233445566778899aabb",
            "name": "Workshop fleet",
            "machine": "studio",
            "host": "127.0.0.1",
            "node": "ouro-studio@127.0.0.1",
            "role": "core",
            "members": [{"machine": "studio", "host": "127.0.0.1", "node": "ouro-studio@127.0.0.1"}],
            "tombstones": [],
            "roster_revision": 1,
            "gateway_port": 17342,
            "epmd_port": 14001,
            "dist_port_min": 13700,
            "dist_port_max": 13729,
        });
        write_private_atomic(
            &profile_path(&dir),
            serde_json::to_string_pretty(&legacy).unwrap().as_bytes(),
        )
        .unwrap();

        let error = load(&dir).expect_err("a schema-1 profile is refused");
        assert!(
            format!("{error:#}").contains(SCHEMA_1_SENTENCE),
            "{error:#}"
        );
        // The launcher.
        let error = runtime_env(&dir).expect_err("the launcher refuses it too");
        assert!(
            format!("{error:#}").contains(SCHEMA_1_SENTENCE),
            "{error:#}"
        );
        // `fleet status`.
        let error = render_status(&dir).expect_err("status refuses it too");
        assert!(
            format!("{error:#}").contains(SCHEMA_1_SENTENCE),
            "{error:#}"
        );
        // `fleet doctor` names it rather than calling the machine standalone.
        let report = doctor(&dir);
        assert!(!report.healthy);
        assert!(report.text.contains(SCHEMA_1_SENTENCE), "{}", report.text);
        // And `summary`, which is what Settings reads.
        let summary = summary(&dir);
        assert!(summary.profile.is_none());
        assert!(
            summary
                .problems
                .iter()
                .any(|problem| problem.contains(SCHEMA_1_SENTENCE)),
            "{:?}",
            summary.problems
        );
    }

    /// The whole of §2 and §3 for a machine that has just been created: private files,
    /// a profile with the fields the contract names, and an environment that carries the
    /// cookie only by path.
    #[test]
    fn create_is_private_complete_and_never_places_the_cookie_in_runtime_env() {
        let (dir, profile) = create_local("create", "studio");
        assert_eq!(profile.schema, 2);
        assert_eq!(profile.role, "core");
        assert_eq!(profile.members.len(), 1);
        assert_eq!(profile.members[0].dist_port, profile.dist_port);
        assert_eq!(profile.node, format!("ouro-studio@{}", profile.host));

        let root = fleet_dir(&dir);
        for (name, mode) in [
            (PROFILE_FILE, 0o600),
            (COOKIE_FILE, 0o600),
            (CA_CERT_FILE, 0o600),
            // §2: `create` keeps the CA key on disk, because it is part of the bundle.
            (CA_KEY_FILE, 0o600),
            (NODE_CERT_FILE, 0o600),
            (NODE_KEY_FILE, 0o600),
            (TLS_OPTFILE, 0o600),
            (VM_ARGS_FILE, 0o600),
        ] {
            let metadata = fs::symlink_metadata(root.join(name))
                .unwrap_or_else(|error| panic!("{name} is missing: {error}"));
            assert!(metadata.file_type().is_file(), "{name} must be a real file");
            assert_eq!(metadata.permissions().mode() & 0o777, mode, "{name}");
        }
        // Nothing EPMD-shaped is written any more.
        for name in ["epmd-owner.json", "epmd-owner.lock"] {
            assert!(!root.join(name).try_exists().unwrap(), "{name}");
        }

        let cookie = fs::read_to_string(root.join(COOKIE_FILE)).unwrap();
        let environment = runtime_env(&dir).unwrap().expect("a fleet environment");
        for (_, value) in &environment {
            assert!(
                !value.contains(&cookie),
                "the cookie reached the environment"
            );
        }

        // §3's table.
        assert_eq!(env_value(&environment, "OUROBOROS_DIST"), "name");
        assert_eq!(env_value(&environment, "OUROBOROS_NODE"), profile.node);
        assert_eq!(
            env_value(&environment, "OUROBOROS_CLUSTER_STRATEGY"),
            "epmd"
        );
        assert_eq!(
            env_value(&environment, "OUROBOROS_CLUSTER_RECONNECT_MS"),
            "1000"
        );
        assert_eq!(
            env_value(&environment, "OUROBOROS_DIST_PORT"),
            profile.dist_port.to_string()
        );
        // Keyed by the full node name, including this machine's own.
        assert_eq!(
            env_value(&environment, "OUROBOROS_DIST_PORTS"),
            format!("{}={}", profile.node, profile.dist_port)
        );
        assert!(
            !environment
                .iter()
                .any(|(name, _)| name == "OUROBOROS_DIST_PORT_MIN"
                    || name == "OUROBOROS_DIST_PORT_MAX"),
            "the range is gone; vm.args pins one port"
        );
        // The single machine is not its own peer.
        assert_eq!(env_value(&environment, "OUROBOROS_CLUSTER_HOSTS"), "");
        assert!(
            !environment
                .iter()
                .any(|(name, _)| name.starts_with("ERL_EPMD_")),
            "§3 removed ERL_EPMD_ADDRESS and ERL_EPMD_PORT"
        );

        // §3's generated vm.args.
        let vm_args = fs::read_to_string(root.join(VM_ARGS_FILE)).unwrap();
        for required in [
            "-proto_dist inet_tls",
            "-start_epmd false",
            "-epmd_module Elixir.Ouroboros.Cluster.Epmd",
            &format!(
                "-kernel inet_dist_listen_min {port} inet_dist_listen_max {port}",
                port = profile.dist_port
            ),
        ] {
            assert!(
                vm_args.contains(required),
                "missing `{required}`:\n{vm_args}"
            );
        }
    }

    /// §2's whole second-machine story, without a network: one bundle, one leaf minted
    /// locally, two machines that trust each other.
    #[test]
    fn a_second_machine_joins_from_a_bundle_and_mints_its_own_leaf() {
        let (one, first) = create_local("join-one", "studio");
        let two = scratch("join-two");

        let bundle = bundle(&one).expect("a bundle");
        assert_eq!(bundle.schema, 2);
        assert_eq!(bundle.fleet_id, first.fleet_id);
        assert_eq!(bundle.members.len(), 1);
        // §2: the bundle's `Debug` prints no secret.
        let printed = format!("{bundle:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains(&bundle.cookie));
        assert!(!printed.contains("BEGIN PRIVATE KEY"));

        let ports = ephemeral_ports();
        let second = join(&two, &bundle, "buildbox", "127.0.0.1", ports).expect("a joined machine");
        assert_eq!(second.fleet_id, first.fleet_id);
        assert_eq!(second.name, first.name);
        assert_eq!(second.machine, "buildbox");
        assert_eq!(second.dist_port, ports.dist.unwrap());
        // members = bundle.members ∪ self
        let mut names: Vec<&str> = second
            .members
            .iter()
            .map(|entry| entry.machine.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(names, vec!["buildbox", "studio"]);
        // The first machine's entry keeps its own port, not this one's.
        let recorded = second
            .members
            .iter()
            .find(|entry| entry.machine == "studio")
            .expect("the first machine is a dial hint");
        assert_eq!(recorded.dist_port, first.dist_port);

        // §2: every member holds the CA key, and the leaf validates against the bundle CA.
        assert!(fleet_dir(&two).join(CA_KEY_FILE).try_exists().unwrap());
        validate_materials(&two, true).expect("a startable second machine");
        assert_eq!(
            fs::read_to_string(fleet_dir(&one).join(CA_CERT_FILE)).unwrap(),
            fs::read_to_string(fleet_dir(&two).join(CA_CERT_FILE)).unwrap(),
            "one fleet is one CA"
        );
        assert_eq!(
            fs::read_to_string(fleet_dir(&one).join(COOKIE_FILE)).unwrap(),
            fs::read_to_string(fleet_dir(&two).join(COOKIE_FILE)).unwrap(),
            "one fleet is one cookie"
        );
        assert_ne!(
            fs::read_to_string(fleet_dir(&one).join(NODE_KEY_FILE)).unwrap(),
            fs::read_to_string(fleet_dir(&two).join(NODE_KEY_FILE)).unwrap(),
            "each machine generates its own node key"
        );

        // And the operator's own list gains the new machine, here and nowhere else.
        let added = add_member(&one, "buildbox", "127.0.0.1", second.dist_port, None)
            .expect("the local roster edit");
        assert_eq!(added.node, second.node);
        let reloaded = load(&one).unwrap().expect("a profile");
        assert_eq!(reloaded.members.len(), 2);
        let environment = runtime_env(&one).unwrap().expect("a fleet environment");
        assert_eq!(
            env_value(&environment, "OUROBOROS_CLUSTER_HOSTS"),
            second.node,
            "§3: every member node except self"
        );
        // Two nodes on one host: only a full-name key can tell them apart.
        let ports = env_value(&environment, "OUROBOROS_DIST_PORTS");
        assert!(
            ports.contains(&format!("{}={}", second.node, second.dist_port)),
            "{ports}"
        );
        assert!(
            ports.contains(&format!("{}={}", reloaded.node, reloaded.dist_port)),
            "{ports}"
        );
    }

    /// The two stable refusals §7 branches on, plus the bundle shapes `join` will not
    /// install at all.
    #[test]
    fn join_refuses_an_existing_fleet_and_an_invalid_bundle() {
        let (one, _first) = create_local("refuse-one", "studio");
        let two = scratch("refuse-two");
        let bundle = bundle(&one).expect("a bundle");

        // A machine that already holds a *different* fleet.
        let other =
            create(&two, None, "buildbox", "127.0.0.1", ephemeral_ports()).expect("another fleet");
        let error = join(&two, &bundle, "buildbox", "127.0.0.1", ephemeral_ports())
            .expect_err("a different fleet is present");
        assert_eq!(reason_of(&error), "fleet_present");
        // Nothing was rewritten.
        assert_eq!(load(&two).unwrap().unwrap().fleet_id, other.fleet_id);

        // The idempotent case: this fleet, this machine.
        let three = scratch("refuse-three");
        join(&three, &bundle, "buildbox", "127.0.0.1", ephemeral_ports()).expect("a join");
        let error = join(&three, &bundle, "buildbox", "127.0.0.1", ephemeral_ports())
            .expect_err("a second join");
        assert_eq!(reason_of(&error), "already_installed");

        // The same fleet under another machine's name is still somebody's identity.
        let error = join(&three, &bundle, "vps", "127.0.0.1", ephemeral_ports())
            .expect_err("a different machine name");
        assert_eq!(reason_of(&error), "fleet_present");

        // And the shapes that never reach the disk at all.
        let four = scratch("refuse-four");
        let mut broken = Bundle {
            schema: 2,
            fleet_id: bundle.fleet_id.clone(),
            name: bundle.name.clone(),
            cookie: bundle.cookie.clone(),
            ca_cert_pem: bundle.ca_cert_pem.clone(),
            ca_key_pem: bundle.ca_key_pem.clone(),
            dist_port: bundle.dist_port,
            members: bundle.members.clone(),
        };
        broken.schema = 1;
        assert_eq!(
            reason_of(&join(&four, &broken, "vps", "127.0.0.1", ephemeral_ports()).unwrap_err()),
            "bundle_invalid"
        );
        broken.schema = 2;
        broken.cookie = "not a cookie".into();
        assert_eq!(
            reason_of(&join(&four, &broken, "vps", "127.0.0.1", ephemeral_ports()).unwrap_err()),
            "bundle_invalid"
        );
        broken.cookie = bundle.cookie.clone();
        // §1 mints only lower-case names: two spellings of one machine is two identities.
        assert_eq!(
            reason_of(&join(&four, &broken, "VPS", "127.0.0.1", ephemeral_ports()).unwrap_err()),
            "invalid_request"
        );
        assert!(
            !fleet_dir(&four).try_exists().unwrap(),
            "nothing was written"
        );

        // §2's member list always includes the machine that wrote it, so a bundle that
        // names nobody is not a fleet.
        broken.members = Vec::new();
        assert_eq!(
            reason_of(&join(&four, &broken, "vps", "127.0.0.1", ephemeral_ports()).unwrap_err()),
            "bundle_invalid"
        );
        broken.members = bundle.members.clone();

        // The distribution port is checked against the *policy*, not against zero.
        // `--dist-port 4369` has always been refused — it is EPMD's historical port —
        // and a bundle carrying the same number went in, because this path validated
        // one port instead of the pair.
        broken.dist_port = 4369;
        let epmd = join(&four, &broken, "vps", "127.0.0.1", ephemeral_ports()).unwrap_err();
        assert_eq!(reason_of(&epmd), "bundle_invalid", "{epmd:#}");
        assert!(
            format!("{epmd:#}").contains("4369"),
            "the refusal names the port: {epmd:#}"
        );
        broken.dist_port = 0;
        assert_eq!(
            reason_of(&join(&four, &broken, "vps", "127.0.0.1", ephemeral_ports()).unwrap_err()),
            "bundle_invalid"
        );
        assert!(
            !fleet_dir(&four).try_exists().unwrap(),
            "nothing was written"
        );
    }

    /// A member list is a set of *identities*, and `pi` and `Pi` are one identity.
    ///
    /// Every other reader of this list folds case — `same_name` is what `add_member`,
    /// `remove_member` and the engine's roster edits compare with — so a profile holding
    /// both spellings is one where "the member named pi" has two answers and a removal
    /// takes whichever `find` reached first. De-duplicating byte-exactly called that
    /// profile valid and let it be written.
    #[test]
    fn a_profile_that_names_one_machine_twice_is_refused_however_it_is_spelled() {
        let (data, profile) = create_local("dedupe", "studio");
        let _ = data;

        let twice = |first: &str, second: &str| {
            let mut broken = profile.clone();
            broken.members = vec![
                member(first, "127.0.0.1", profile.dist_port),
                member(second, "127.0.0.2", profile.dist_port),
            ];
            // The profile's own machine has to stay in its own list.
            broken.machine = first.to_string();
            broken.host = "127.0.0.1".to_string();
            broken.node = member(first, "127.0.0.1", profile.dist_port).node;
            validate_profile(&broken)
        };

        // Byte-exact, which was already refused.
        let exact = twice("studio", "studio").expect_err("one node, twice");
        assert!(format!("{exact:#}").contains("repeats"), "{exact:#}");
        // And the spelling that was not: one machine wearing two cases.
        let folded = twice("studio", "STUDIO").expect_err("one machine, two spellings");
        assert!(format!("{folded:#}").contains("repeats"), "{folded:#}");
        // Two genuinely different machines are still a valid list.
        twice("studio", "buildbox").expect("two machines are two members");
    }

    #[test]
    fn remote_leave_rechecks_identity_at_the_deletion_boundary() {
        let (dir, profile) = create_local("leave-recheck", "studio");
        check_removal_identity(&dir, "studio", &profile.fleet_id).unwrap();
        leave(&dir).unwrap();
        let replacement = create(
            &dir,
            Some("replacement"),
            "studio",
            "127.0.0.1",
            ephemeral_ports(),
        )
        .unwrap();
        let error = leave_matching(&dir, "studio", &profile.fleet_id).unwrap_err();
        assert_eq!(refusal(&error).unwrap().reason, "identity_mismatch");
        assert_eq!(load(&dir).unwrap().unwrap().fleet_id, replacement.fleet_id);
    }

    /// §2: `leave` is a stop-gated deletion of `fleet/`, and it works on a directory
    /// whose `profile.json` never landed.
    #[test]
    fn leave_removes_the_whole_directory_including_one_with_no_profile() {
        let (dir, _profile) = create_local("leave", "studio");
        // Something the runtime wrote beside the credentials, which used to need a
        // recognized shape before `leave` would touch it.
        let durable = fleet_dir(&dir)
            .join("cluster-directory")
            .join("checkpoints");
        fs::create_dir_all(&durable).unwrap();
        fs::write(durable.join("anything.term"), b"opaque").unwrap();

        let removal = leave(&dir).expect("a removal").expect("a fleet was there");
        assert_eq!(removal.machine.as_deref(), Some("studio"));
        assert!(removal.profile_readable);
        assert!(removal.removed.contains(&PROFILE_FILE.to_string()));
        assert!(!fleet_dir(&dir).try_exists().unwrap());
        assert!(load(&dir).unwrap().is_none());
        // Idempotent.
        assert!(leave(&dir).expect("a second leave").is_none());

        // A directory whose profile never landed is exactly the one `leave` exists for.
        let stump = scratch("leave-stump");
        fs::create_dir(stump.join("fleet")).unwrap();
        fs::set_permissions(stump.join("fleet"), fs::Permissions::from_mode(0o700)).unwrap();
        write_private_atomic(&fleet_dir(&stump).join(COOKIE_FILE), b"x").unwrap();
        let removal = leave(&stump)
            .expect("a removal")
            .expect("a directory was there");
        assert!(!removal.profile_readable);
        assert_eq!(removal.machine, None);
        assert!(!fleet_dir(&stump).try_exists().unwrap());
    }

    /// `ouro fleet forget NAME` is the local roster removal, and nothing else.
    #[test]
    fn forgetting_a_machine_edits_only_this_machines_list() {
        let (dir, profile) = create_local("forget", "studio");
        add_member(&dir, "vps", "127.0.0.2", profile.dist_port, None).expect("a member");
        assert_eq!(load(&dir).unwrap().unwrap().members.len(), 2);

        // A machine the roster never had.
        let error = forget_machine(&dir, "absent").expect_err("an unknown machine");
        assert!(format!("{error:#}").contains("has no member named absent"));
        // This machine.
        let error = forget_machine(&dir, "studio").expect_err("this machine");
        assert!(format!("{error:#}").contains("`ouro fleet leave`"));

        let removed = forget_machine(&dir, "VPS").expect("a case-insensitive removal");
        assert_eq!(removed.machine, "vps");
        assert_eq!(load(&dir).unwrap().unwrap().members.len(), 1);
    }

    /// The profile a hand edit can produce, and what each refusal teaches.
    #[test]
    fn validation_errors_teach_the_expected_shape() {
        let mut profile = sample_profile("studio");
        profile.role = "worker".into();
        assert!(format!("{:#}", validate_profile(&profile).unwrap_err()).contains("`core`"));

        let mut profile = sample_profile("studio");
        profile.node = "studio@host".into();
        assert!(validate_profile(&profile).is_err());

        let mut profile = sample_profile("studio");
        profile.members[0].dist_port = profile.dist_port + 1;
        assert!(
            format!("{:#}", validate_profile(&profile).unwrap_err()).contains("distribution port")
        );

        let mut profile = sample_profile("studio");
        profile.gateway_port = profile.dist_port;
        assert!(format!("{:#}", validate_profile(&profile).unwrap_err()).contains("overlaps"));

        let mut profile = sample_profile("studio");
        profile
            .members
            .push(member("studio", "studio.tailnet.ts.net", profile.dist_port));
        assert!(validate_profile(&profile).is_err());

        assert!(validate_machine("studio-mini").is_ok());
        assert!(validate_machine("-studio").is_err());
        assert!(validate_cookie(&"a".repeat(64), "test").is_ok());
        assert!(validate_cookie(&"A".repeat(64), "test").is_err());
        assert!(validate_cookie(&"a".repeat(63), "test").is_err());
    }

    /// Fleet hosts are private IPv4 or names that resolve to exactly one.
    #[test]
    fn unusable_hosts_are_refused_before_any_credential_is_created() {
        for hostile in [
            "::1",
            "fd00::1",
            "host:22",
            "1.2.3.4",
            "0.0.0.0",
            "studio..tailnet",
            "100.64.0.1.",
        ] {
            assert!(validate_host(hostile).is_err(), "{hostile} must be refused");
        }
        for fine in [
            "100.64.0.1",
            "10.0.0.5",
            "127.0.0.1",
            "studio.tailnet.ts.net",
        ] {
            assert!(validate_host(fine).is_ok(), "{fine} must be accepted");
        }
        // The canonical spelling is what goes in a certificate.
        assert_eq!(canonical_host("LOCALHOST").unwrap(), "localhost");
        assert_eq!(canonical_host("127.0.0.1.").unwrap(), "127.0.0.1");
        assert!(same_name("Vps", "vps"));
    }

    /// §2's port-isolation convention, minus the EPMD field.
    #[test]
    fn ephemeral_ports_avoid_every_production_port_space() {
        for _ in 0..8 {
            let ports = ephemeral_ports();
            let gateway = ports.gateway.expect("a gateway port");
            let dist = ports.dist.expect("a dist port");
            assert_ne!(gateway, dist);
            for port in [gateway, dist] {
                assert_ne!(port, 4369);
                assert!(!(DEFAULT_DIST_PORT_MIN..=DEFAULT_DIST_PORT_MAX).contains(&port));
                assert!(
                    !(DEFAULT_GATEWAY_BASE..DEFAULT_GATEWAY_BASE + DEFAULT_GATEWAY_SPAN)
                        .contains(&port)
                );
            }
        }
        assert_eq!(DEFAULT_DIST_PORT, 13_700);
        assert_eq!(Ports::DEFAULT.dist, None);
    }

    /// A generated policy file that does not match the profile stops a boot.
    #[test]
    fn startup_and_doctor_reject_generated_policy_drift() {
        let (dir, _profile) = create_local("drift", "studio");
        let optfile = fleet_dir(&dir).join(TLS_OPTFILE);
        let original = fs::read_to_string(&optfile).unwrap();
        write_private_atomic(
            &optfile,
            original.replace("verify_peer", "verify_none").as_bytes(),
        )
        .unwrap();
        let error = runtime_env(&dir).expect_err("a weakened policy");
        assert!(format!("{error:#}").contains("does not match"));
        let report = doctor(&dir);
        assert!(!report.healthy);

        write_private_atomic(&optfile, original.as_bytes()).unwrap();
        runtime_env(&dir).expect("the restored policy starts");
    }

    /// The cookie, the node key and the CA key never reach a status or summary document.
    #[test]
    fn summary_and_status_never_contain_secret_material() {
        let (dir, _profile) = create_local("secrets", "studio");
        let root = fleet_dir(&dir);
        let cookie = fs::read_to_string(root.join(COOKIE_FILE)).unwrap();
        let node_key = fs::read_to_string(root.join(NODE_KEY_FILE)).unwrap();
        let ca_key = fs::read_to_string(root.join(CA_KEY_FILE)).unwrap();

        let rendered = serde_json::to_string(&summary(&dir)).unwrap();
        let status = render_status(&dir).unwrap();
        let report = doctor(&dir).text;
        for document in [rendered, status, report] {
            for secret in [&cookie, &node_key, &ca_key] {
                assert!(!document.contains(secret.trim()), "a secret was printed");
            }
            assert!(!document.contains("BEGIN PRIVATE KEY"));
            // §12: the revision and the tombstones are gone from every document.
            assert!(!document.contains("fleet_protocol_revision"));
            assert!(!document.to_lowercase().contains("tombstone"));
            assert!(!document.contains("EPMD"));
        }
    }

    /// A live runtime's checks are merged into the local report rather than replacing it.
    #[test]
    fn doctor_merges_live_errors_into_the_local_report() {
        let (dir, _profile) = create_local("live-doctor", "studio");
        let local = doctor(&dir);
        let merged = merge_live_doctor(
            local,
            &serde_json::json!({
                "healthy?": false,
                "checks": [
                    {"status": "error", "message": "two machines disagree about their version",
                     "guidance": "upgrade both"},
                ],
            }),
        );
        assert!(!merged.healthy);
        assert!(merged.text.contains("live runtime: two machines disagree"));
        assert!(merged.text.contains("Next: upgrade both"));
        assert!(merged.scope().starts_with("live"));

        let unavailable = doctor_live_unavailable(doctor(&dir), "connection refused");
        assert!(!unavailable.healthy);
        assert!(unavailable.text.contains("connection refused"));
    }

    /// A beginner's inputs become a safe identity, or an explicit question.
    #[test]
    fn identity_resolution_derives_a_label_or_asks() {
        let identity = resolve_identity(None, Some("studio-mini.tailnet.ts.net"));
        match identity {
            Ok(identity) => {
                assert_eq!(identity.machine, "studio-mini");
                assert!(identity.inferred_machine);
                assert!(!identity.inferred_host);
            }
            // A machine with no resolver for that name is a legitimate environment.
            Err(error) => assert!(format!("{error:#}").contains("studio-mini")),
        }
        assert_eq!(
            machine_from_host("Build-Linux.local").unwrap(),
            "build-linux"
        );
        assert!(host_is_local_only("localhost"));
    }

    /// Creating a fleet twice, or on an occupied port, refuses before anything is written.
    #[test]
    fn create_refuses_an_existing_fleet_and_an_occupied_port() {
        let (dir, _profile) = create_local("occupied", "studio");
        let error = create(&dir, None, "studio", "127.0.0.1", ephemeral_ports())
            .expect_err("a second create");
        assert!(format!("{error:#}").contains("already has fleet state"));

        let other = scratch("occupied-two");
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken = held.local_addr().unwrap().port();
        let ports = Ports {
            gateway: Some(taken),
            dist: ephemeral_ports().dist,
        };
        let error =
            create(&other, None, "buildbox", "127.0.0.1", ports).expect_err("an occupied gateway");
        assert!(format!("{error:#}").contains("already in use"));
        assert!(!fleet_dir(&other).try_exists().unwrap());
    }

    /// An interrupted `create` leaves a private staging directory, and the next
    /// lifecycle command recovers it rather than guessing at it.
    #[test]
    fn interrupted_private_setup_is_recovered_but_ambiguous_staging_fails_closed() {
        let dir = scratch("staging");
        let staging = dir.join(format!(".fleet.setup.{}.0123456789ab", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&staging).unwrap();
        write_private_atomic(&staging.join(COOKIE_FILE), &[b'a'; 64]).unwrap();
        assert!(!inspect_orphan_staging(&dir).unwrap().is_empty());
        assert_eq!(recover_orphan_staging(&dir).unwrap(), 1);
        assert!(inspect_orphan_staging(&dir).unwrap().is_empty());

        // A name in the namespace that this code did not write is a hard error.
        let hostile = dir.join(".fleet.setup.not-a-pid");
        fs::DirBuilder::new().mode(0o700).create(&hostile).unwrap();
        assert!(inspect_orphan_staging(&dir).is_err());
    }
}
