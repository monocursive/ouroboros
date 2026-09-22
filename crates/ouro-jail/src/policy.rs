//! Policy resolution, the immutable snapshot and §6.3 narrowing.
//!
//! Implements jail-v1 §6.2 (precedence), §6.3 (policy shape and narrowing) and
//! the `ouro.jail.policy-snapshot/1` shape of
//! `docs/specs/jail-v1/policy-snapshot.schema.json`.
//!
//! Authority is compared after expansion and path resolution, never as TOML
//! ordering or string prefixes: `/work/a` is not an ancestor of `/work/ab`.
//! Denial wins over an overlapping allow, read-only carve-outs override
//! writable parents, and an unknown or ambiguous subset relationship refuses
//! instead of widening.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::network::{HostRule, NetworkMode};
use crate::records::{
    ErrorCode, ErrorStage, EvidenceMode, JailError, NativeString, ObserveMode, Os, Remediation,
    SCHEMA_NETWORK, SCHEMA_POLICY_SNAPSHOT,
};

/// The built-in profile a policy is based on (§6.3, north star §4.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileName {
    /// A vendor agent under the nesting profile.
    Agent,
    /// That agent's shell or a test command.
    Tool,
    /// A package build.
    Build,
    /// An explicit uncontained run.
    None,
}

impl ProfileName {
    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileName::Agent => "agent",
            ProfileName::Tool => "tool",
            ProfileName::Build => "build",
            ProfileName::None => "none",
        }
    }

    /// Parses a built-in profile name, or `None` when the argument names a file.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "agent" => Some(ProfileName::Agent),
            "tool" => Some(ProfileName::Tool),
            "build" => Some(ProfileName::Build),
            "none" => Some(ProfileName::None),
            _ => None,
        }
    }

    /// Whether this profile applies containment at all.
    #[must_use]
    pub fn is_contained(self) -> bool {
        !matches!(self, ProfileName::None)
    }
}

/// The managed or host root a path reference is expressed against.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootToken {
    /// An absolute host path.
    Host,
    /// Relative to the workspace root.
    Workspace,
    /// Relative to the scratch root.
    Scratch,
    /// Relative to the vendor-state root.
    VendorState,
}

/// A path reference: `{root, path}` with the relative-suffix rules of
/// `canonicalization.md`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRef {
    /// Which root the path is relative to.
    pub root: RootToken,
    /// An absolute path for `host`, a relative suffix otherwise; empty means
    /// the root itself.
    pub path: NativeString,
}

impl PathRef {
    /// Builds a host-rooted reference from absolute bytes.
    #[must_use]
    pub fn host(path: NativeString) -> Self {
        PathRef {
            root: RootToken::Host,
            path,
        }
    }

    /// The path's components, with empty segments dropped.
    #[must_use]
    pub fn components(&self) -> Vec<&[u8]> {
        self.path
            .as_bytes()
            .split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty())
            .collect()
    }

    /// Whether `self` is `other` or one of its ancestors, compared component by
    /// component so that `/work/a` is not an ancestor of `/work/ab`.
    #[must_use]
    pub fn contains(&self, other: &PathRef) -> bool {
        if self.root != other.root {
            return false;
        }
        let mine = self.components();
        let theirs = other.components();
        mine.len() <= theirs.len() && theirs[..mine.len()] == mine[..]
    }

    /// A lossy rendering for diagnostics only.
    #[must_use]
    pub fn to_display(&self) -> String {
        let root = match self.root {
            RootToken::Host => "host",
            RootToken::Workspace => "workspace",
            RootToken::Scratch => "scratch",
            RootToken::VendorState => "vendor_state",
        };
        format!("{root}:{}", self.path.to_display())
    }
}

/// The scratch root: a managed attempt directory or an explicit host path.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScratchRoot {
    /// A new private attempt directory.
    Managed,
    /// An operator-supplied host path.
    Host {
        /// The absolute host path.
        path: NativeString,
    },
}

/// The vendor-state root, present only when a launch profile requires it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VendorStateRoot {
    /// Managed beneath the attempt directory.
    Managed,
}

/// `roots` field group.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roots {
    /// The absolute resolved workspace.
    pub workspace: NativeString,
    /// The scratch root.
    pub scratch: ScratchRoot,
    /// The vendor-state root, or null.
    pub vendor_state: Option<VendorStateRoot>,
}

/// Protected-path coverage (north star §4.4).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedCoverage {
    /// No protected-segment coverage is required.
    None,
    /// Segments existing at launch plus the workspace's own root literals.
    ExistingAndRoot,
    /// Any protected segment created at any depth during the run.
    AllDescendants,
}

impl ProtectedCoverage {
    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProtectedCoverage::None => "none",
            ProtectedCoverage::ExistingAndRoot => "existing_and_root",
            ProtectedCoverage::AllDescendants => "all_descendants",
        }
    }

    /// Parses the wire spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "none" => Some(ProtectedCoverage::None),
            "existing_and_root" => Some(ProtectedCoverage::ExistingAndRoot),
            "all_descendants" => Some(ProtectedCoverage::AllDescendants),
            _ => None,
        }
    }
}

/// `filesystem` field group of the snapshot.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSnapshot {
    /// Effective writable references.
    pub read_write: Vec<PathRef>,
    /// Effective visible-but-read-only references.
    pub read_only: Vec<PathRef>,
    /// Effective denied references.
    pub deny_read: Vec<PathRef>,
    /// Protected path segments, for example `.git`.
    pub protected_segments: Vec<String>,
    /// The coverage the policy requires.
    pub protected_coverage: ProtectedCoverage,
}

/// `network` field group of the snapshot.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct NetworkSnapshot {
    /// `none`, `host` or `proxy`.
    pub mode: String,
    /// Canonical allow rules.
    pub allow: Vec<String>,
    /// `ouro.jail.network/1` for proxy mode, null otherwise.
    pub ruleset: Option<String>,
    /// Canonical IPv6 CIDRs from the host manifest.
    pub translation_prefixes: Vec<String>,
}

/// One ceiling in the snapshot: decimal string plus whether it is required.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitCeiling {
    /// The value as a decimal string, in ms, count, bytes or percent.
    pub value: String,
    /// Whether enforcement is required rather than preferred.
    pub required: bool,
}

/// `limits` field group of the snapshot.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSnapshot {
    /// Wall clock, milliseconds. Wall always exists (§6.4).
    pub wall: Option<LimitCeiling>,
    /// Process count.
    pub pids: Option<LimitCeiling>,
    /// Memory, bytes.
    pub mem: Option<LimitCeiling>,
    /// CPU bandwidth, percent where 100 is one core.
    pub cpu: Option<LimitCeiling>,
}

/// `observation` field group of the snapshot.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSnapshot {
    /// Requested observation mode.
    pub mode: ObserveMode,
    /// Requested evidence mode.
    pub evidence: EvidenceMode,
}

/// An environment value: a native string or a managed-path reference.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EnvValue {
    /// A managed root reference such as the scratch directory.
    Path(PathRef),
    /// A literal value in the native-string codec.
    Native(NativeString),
}

/// One environment binding.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvBinding {
    /// The variable name.
    pub name: String,
    /// The bound value.
    pub value: EnvValue,
}

/// `environment` field group of the snapshot.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSnapshot {
    /// Whether the host environment is inherited (`none` only).
    pub inherit_host: bool,
    /// Explicit effective bindings, unique by name.
    pub bindings: Vec<EnvBinding>,
}

/// A resolved launch credential declaration (§12).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDecl {
    /// Unique logical id.
    pub id: String,
    /// Absolute native source path.
    pub source: NativeString,
    /// Relative native destination under vendor state.
    pub dest: NativeString,
    /// `copy_rw` or `bind_ro`.
    pub mode: String,
}

/// `launch` field group of the snapshot, null without a launch profile.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSnapshot {
    /// The variable naming vendor state, or null.
    pub state_var: Option<String>,
    /// Whether HOME points at vendor state.
    pub home_is_state: bool,
    /// Relative directories created under vendor state.
    pub state_subdirs: Vec<NativeString>,
    /// Declared credentials.
    pub credentials: Vec<CredentialDecl>,
}

/// The canonical resolved policy snapshot (`ouro.jail.policy-snapshot/1`).
///
/// This is the complete digest input. It carries no provenance, no capability
/// measurement, no attempt id and no chosen backend (canonicalization.md).
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PolicySnapshot {
    /// Always [`SCHEMA_POLICY_SNAPSHOT`].
    pub schema: String,
    /// The base built-in profile.
    pub profile: ProfileName,
    /// The built-in semantic contract version, `1`.
    pub profile_version: u8,
    /// `linux` or `macos`; never a probe result.
    pub platform: Os,
    /// Resolved roots.
    pub roots: Roots,
    /// Effective filesystem authority.
    pub filesystem: FilesystemSnapshot,
    /// Effective network authority.
    pub network: NetworkSnapshot,
    /// Effective ceilings.
    pub limits: LimitsSnapshot,
    /// Observation choices.
    pub observation: ObservationSnapshot,
    /// Effective environment.
    pub environment: EnvironmentSnapshot,
    /// Launch declarations, or null.
    pub launch: Option<LaunchSnapshot>,
}

impl PolicySnapshot {
    /// Serializes the snapshot to the canonical JSON value.
    ///
    /// Set arrays are deduplicated by canonical bytes and sorted by them;
    /// keyed collections (environment bindings, credentials) are sorted by
    /// their key, which is the only order their uniqueness rule admits.
    ///
    /// # Errors
    /// Returns an internal error when the value cannot be canonicalized.
    pub fn to_canonical_value(&self) -> Result<serde_json::Value, JailError> {
        let mut value = serde_json::to_value(self).map_err(|error| {
            JailError::new(
                ErrorCode::InternalError,
                ErrorStage::Resolving,
                Remediation::InspectState,
                format!("the policy snapshot could not be serialized: {error}"),
            )
        })?;
        for path in [
            &["filesystem", "read_write"][..],
            &["filesystem", "read_only"][..],
            &["filesystem", "deny_read"][..],
            &["filesystem", "protected_segments"][..],
            &["network", "allow"][..],
            &["network", "translation_prefixes"][..],
            &["launch", "state_subdirs"][..],
        ] {
            sort_set_at(&mut value, path)?;
        }
        Ok(value)
    }

    /// The canonical RFC 8785 bytes of this snapshot.
    ///
    /// # Errors
    /// Returns an internal error when the value cannot be canonicalized.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, JailError> {
        let value = self.to_canonical_value()?;
        canonical::to_jcs(&value).map_err(JailError::from)
    }

    /// The `policy_digest` of this snapshot.
    ///
    /// # Errors
    /// Returns an internal error when the value cannot be canonicalized.
    pub fn digest(&self) -> Result<String, JailError> {
        let value = self.to_canonical_value()?;
        canonical::policy_digest(&value).map_err(JailError::from)
    }
}

fn sort_set_at(value: &mut serde_json::Value, path: &[&str]) -> Result<(), JailError> {
    let mut node = value;
    for key in path {
        node = match node.get_mut(key) {
            Some(serde_json::Value::Null) | None => return Ok(()),
            Some(next) => next,
        };
    }
    let Some(items) = node.as_array_mut() else {
        return Ok(());
    };
    let mut encoded: Vec<(Vec<u8>, serde_json::Value)> = Vec::with_capacity(items.len());
    for item in items.iter() {
        encoded.push((
            canonical::to_jcs(item).map_err(JailError::from)?,
            item.clone(),
        ));
    }
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    encoded.dedup_by(|left, right| left.0 == right.0);
    *items = encoded.into_iter().map(|(_, item)| item).collect();
    Ok(())
}

// ---------------------------------------------------------------------------
// Resolution inputs (§6.2)
// ---------------------------------------------------------------------------

/// One ceiling while resolving: the parsed value, the operator's spelling and
/// whether enforcement is required.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ceiling {
    /// The parsed value in the canonical unit.
    pub value: u64,
    /// The spelling the operator used, kept for the receipt's `requested`.
    pub requested: String,
    /// Whether enforcement is required rather than preferred.
    pub required: bool,
}

/// The four ceilings, each present or absent.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Ceilings {
    /// Wall clock in milliseconds.
    pub wall: Option<Ceiling>,
    /// Process count.
    pub pids: Option<Ceiling>,
    /// Memory in bytes.
    pub mem: Option<Ceiling>,
    /// CPU percentage.
    pub cpu: Option<Ceiling>,
}

impl Ceilings {
    fn get(&self, key: LimitKey) -> &Option<Ceiling> {
        match key {
            LimitKey::Wall => &self.wall,
            LimitKey::Pids => &self.pids,
            LimitKey::Mem => &self.mem,
            LimitKey::Cpu => &self.cpu,
        }
    }

    fn set(&mut self, key: LimitKey, ceiling: Option<Ceiling>) {
        match key {
            LimitKey::Wall => self.wall = ceiling,
            LimitKey::Pids => self.pids = ceiling,
            LimitKey::Mem => self.mem = ceiling,
            LimitKey::Cpu => self.cpu = ceiling,
        }
    }
}

/// The four supported limit keys (§6.4).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum LimitKey {
    /// Wall-clock deadline.
    Wall,
    /// Process count ceiling.
    Pids,
    /// Memory ceiling.
    Mem,
    /// CPU bandwidth ceiling.
    Cpu,
}

impl LimitKey {
    /// Every key, in a stable order.
    pub const ALL: [LimitKey; 4] = [LimitKey::Wall, LimitKey::Pids, LimitKey::Mem, LimitKey::Cpu];

    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LimitKey::Wall => "wall",
            LimitKey::Pids => "pids",
            LimitKey::Mem => "mem",
            LimitKey::Cpu => "cpu",
        }
    }

    /// Parses the wire spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "wall" => Some(LimitKey::Wall),
            "pids" => Some(LimitKey::Pids),
            "mem" => Some(LimitKey::Mem),
            "cpu" => Some(LimitKey::Cpu),
            _ => None,
        }
    }
}

/// The built-in baseline a profile expands to before any file or flag.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProfileBaseline {
    /// Writable references.
    pub read_write: Vec<PathRef>,
    /// Visible read-only references.
    pub read_only: Vec<PathRef>,
    /// Denied references.
    pub deny_read: Vec<PathRef>,
    /// Protected segments.
    pub protected_segments: Vec<String>,
    /// Required coverage.
    pub protected_coverage: ProtectedCoverage,
    /// Network mode.
    pub network_mode: NetworkMode,
    /// Canonical allow rules.
    pub network_allow: Vec<HostRule>,
    /// Ceilings.
    pub limits: Ceilings,
    /// Observation defaults.
    pub observation: ObservationSnapshot,
    /// Environment baseline.
    pub environment: EnvironmentSnapshot,
}

/// Where a configuration layer came from (§6.2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LayerOrigin {
    /// A selected operator profile file, which narrows its built-in base.
    OperatorProfileFile(String),
    /// The operator's own `config.toml`.
    OperatorConfig(String),
    /// The documented environment allow-list.
    Environment,
    /// Explicit CLI grants and limits.
    CommandLine,
    /// The workspace-root `ouro.toml`, which can only narrow.
    ProjectConfig(String),
}

impl LayerOrigin {
    /// A safe label for provenance records.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            LayerOrigin::OperatorProfileFile(name) => format!("operator-profile:{name}"),
            LayerOrigin::OperatorConfig(name) => format!("operator-config:{name}"),
            LayerOrigin::Environment => "environment".to_owned(),
            LayerOrigin::CommandLine => "cli".to_owned(),
            LayerOrigin::ProjectConfig(name) => format!("project-config:{name}"),
        }
    }
}

/// The semantic delta one configuration layer contributes.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct PolicyDelta {
    /// Raw `filesystem.read_write` entries, unresolved native bytes.
    pub read_write: Vec<Vec<u8>>,
    /// Raw `filesystem.read_only` entries.
    pub read_only: Vec<Vec<u8>>,
    /// Raw `filesystem.deny_read` entries.
    pub deny_read: Vec<Vec<u8>>,
    /// `filesystem.protected_coverage`.
    pub protected_coverage: Option<ProtectedCoverage>,
    /// `network.mode`.
    pub network_mode: Option<NetworkMode>,
    /// Raw `network.allow` entries.
    pub network_allow: Vec<String>,
    /// Ceilings this layer sets.
    pub limits: Ceilings,
    /// `observation.mode`.
    pub observe: Option<ObserveMode>,
    /// `observation.evidence`.
    pub evidence: Option<EvidenceMode>,
    /// A key this layer is forbidden to carry, already detected by the parser.
    pub forbidden_key: Option<String>,
}

/// One configuration layer in §6.2 order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Layer {
    /// Where it came from.
    pub origin: LayerOrigin,
    /// The directory relative paths in this layer resolve against, if any.
    pub base_dir: Option<Vec<u8>>,
    /// The key prefix used when reporting an exact key path.
    pub key_prefix: String,
    /// Whether §6.3 narrowing applies to this layer.
    pub narrowing: bool,
    /// The layer's delta.
    pub delta: PolicyDelta,
}

/// Everything `resolve` needs (§6.2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolveInputs {
    /// The platform this policy is resolved for.
    pub platform: Os,
    /// The base built-in profile.
    pub base_profile: ProfileName,
    /// The display name of the selected policy, for the receipt.
    pub policy_name: String,
    /// The built-in baseline that profile expands to.
    pub baseline: ProfileBaseline,
    /// The absolute resolved workspace.
    pub workspace: Vec<u8>,
    /// The scratch root.
    pub scratch: ScratchRoot,
    /// The vendor-state root, or none.
    pub vendor_state: Option<VendorStateRoot>,
    /// The operator home used to expand a leading `~/` in operator files.
    pub operator_home: Option<Vec<u8>>,
    /// Configured NAT64 prefixes from the host manifest.
    pub translation_prefixes: Vec<String>,
    /// The layers, in §6.2 order.
    pub layers: Vec<Layer>,
}

/// One provenance record: which input established which key.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ProvenanceEntry {
    /// A safe origin label.
    pub origin: String,
    /// The key path this input set.
    pub key: String,
    /// A safe detail, never an environment value or credential.
    pub detail: Option<String>,
}

/// The resolver's result: an immutable snapshot plus separate provenance.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Resolved {
    /// The canonical snapshot.
    pub snapshot: PolicySnapshot,
    /// Its `policy_digest`.
    pub digest: String,
    /// Input provenance, deliberately not part of the digest.
    pub provenance: Vec<ProvenanceEntry>,
    /// Derived capability requirements.
    pub requirements: Vec<String>,
    /// Requested limit spellings for the receipt's `applied.limits`.
    pub ceilings: Ceilings,
    /// The display name of the selected policy.
    pub policy_name: String,
}

// ---------------------------------------------------------------------------
// Effective authority
// ---------------------------------------------------------------------------

/// The access a path has under an authority.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AccessMode {
    /// No matching grant: the path is not part of the authority at all.
    Absent,
    /// Denied by a matching `deny_read`.
    Denied,
    /// Visible and read-only.
    ReadOnly,
    /// Writable.
    ReadWrite,
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Authority {
    read_write: Vec<PathRef>,
    read_only: Vec<PathRef>,
    deny_read: Vec<PathRef>,
    protected_coverage: ProtectedCoverage,
    protected_segments: Vec<String>,
    network_mode: NetworkMode,
    network_allow: Vec<HostRule>,
    limits: Ceilings,
    observation: ObservationSnapshot,
}

impl Authority {
    /// The access `target` has, by longest matching ancestor.
    ///
    /// At equal specificity denial wins over read-only, which wins over
    /// writable (§6.3: "Denial wins over an overlapping allow. Read-only
    /// carve-outs override writable parents.").
    fn mode_at(&self, target: &PathRef) -> AccessMode {
        let mut best_len = 0usize;
        let mut mode = AccessMode::Absent;
        let rank = |entry: &PathRef,
                    candidate: AccessMode,
                    best_len: &mut usize,
                    mode: &mut AccessMode| {
            if !entry.contains(target) {
                return;
            }
            let len = entry.components().len();
            let candidate_rank = match candidate {
                AccessMode::Denied => 3,
                AccessMode::ReadOnly => 2,
                AccessMode::ReadWrite => 1,
                AccessMode::Absent => 0,
            };
            let current_rank = match mode {
                AccessMode::Denied => 3,
                AccessMode::ReadOnly => 2,
                AccessMode::ReadWrite => 1,
                AccessMode::Absent => 0,
            };
            if len > *best_len || (len == *best_len && candidate_rank > current_rank) {
                *best_len = len;
                *mode = candidate;
            }
        };
        for entry in &self.read_write {
            rank(entry, AccessMode::ReadWrite, &mut best_len, &mut mode);
        }
        for entry in &self.read_only {
            rank(entry, AccessMode::ReadOnly, &mut best_len, &mut mode);
        }
        for entry in &self.deny_read {
            rank(entry, AccessMode::Denied, &mut best_len, &mut mode);
        }
        mode
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

fn refuse(code: ErrorCode, key: &str, message: String) -> JailError {
    JailError::new(
        code,
        ErrorStage::Resolving,
        Remediation::Configuration,
        message,
    )
    .with_key_path(key)
}

/// Lexically normalizes `raw` against `base_dir` without touching the
/// filesystem.
///
/// Portable code does not resolve symlinks: §9.1 pins source identity with
/// directory handles at preparation, which is the Linux slice's job. A `..`
/// that would escape the root refuses instead of clamping.
fn normalize_path(base_dir: Option<&[u8]>, raw: &[u8], key: &str) -> Result<Vec<u8>, JailError> {
    if raw.is_empty() {
        return Err(refuse(
            ErrorCode::InvalidConfig,
            key,
            "a filesystem path may not be empty".to_owned(),
        ));
    }
    if raw.contains(&0) {
        return Err(refuse(
            ErrorCode::InvalidConfig,
            key,
            "a filesystem path may not contain NUL".to_owned(),
        ));
    }
    let mut joined: Vec<u8> = Vec::new();
    if raw.starts_with(b"/") {
        joined.extend_from_slice(raw);
    } else {
        let Some(base) = base_dir else {
            return Err(refuse(
                ErrorCode::InvalidConfig,
                key,
                "a relative path has no directory to resolve against".to_owned(),
            ));
        };
        joined.extend_from_slice(base);
        joined.push(b'/');
        joined.extend_from_slice(raw);
    }
    let mut components: Vec<&[u8]> = Vec::new();
    for part in joined.split(|byte| *byte == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                if components.pop().is_none() {
                    return Err(refuse(
                        ErrorCode::InvalidConfig,
                        key,
                        "a path escapes the filesystem root with `..`".to_owned(),
                    ));
                }
            }
            other => components.push(other),
        }
    }
    let mut out = Vec::new();
    for component in components {
        out.push(b'/');
        out.extend_from_slice(component);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    Ok(out)
}

fn expand_home(raw: &[u8], home: Option<&[u8]>) -> Vec<u8> {
    if let Some(rest) = raw.strip_prefix(b"~/")
        && let Some(home) = home
    {
        let mut out = home.to_vec();
        out.push(b'/');
        out.extend_from_slice(rest);
        return out;
    }
    raw.to_vec()
}

struct Tokenizer {
    workspace: Vec<u8>,
    scratch: Option<Vec<u8>>,
}

impl Tokenizer {
    /// Represents an absolute host path with the most specific managed root
    /// that contains it, in the order vendor_state, scratch, workspace, host
    /// (canonicalization.md).
    fn tokenize(&self, absolute: &[u8], key: &str) -> Result<PathRef, JailError> {
        // vendor_state has no host location in this slice; it is attempt-local
        // and only a launch profile (J3) introduces references beneath it.
        if let Some(scratch) = &self.scratch
            && let Some(rest) = relative_suffix(scratch, absolute)
        {
            return Ok(PathRef {
                root: RootToken::Scratch,
                path: native(rest, key)?,
            });
        }
        if let Some(rest) = relative_suffix(&self.workspace, absolute) {
            return Ok(PathRef {
                root: RootToken::Workspace,
                path: native(rest, key)?,
            });
        }
        Ok(PathRef {
            root: RootToken::Host,
            path: native(absolute.to_vec(), key)?,
        })
    }
}

fn native(bytes: Vec<u8>, key: &str) -> Result<NativeString, JailError> {
    NativeString::from_bytes(bytes)
        .map_err(|error| refuse(ErrorCode::InvalidConfig, key, error.to_string()))
}

fn relative_suffix(root: &[u8], absolute: &[u8]) -> Option<Vec<u8>> {
    let root_components: Vec<&[u8]> = root
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
        .collect();
    let path_components: Vec<&[u8]> = absolute
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
        .collect();
    if path_components.len() < root_components.len()
        || path_components[..root_components.len()] != root_components[..]
    {
        return None;
    }
    let mut out = Vec::new();
    for (index, component) in path_components[root_components.len()..].iter().enumerate() {
        if index > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(component);
    }
    Some(out)
}

/// Resolves configuration into an immutable snapshot with its digest,
/// provenance and requirements (§6.2, §6.3).
///
/// # Errors
/// Returns [`ErrorCode::PolicyWidening`] with the exact key path when a
/// narrowing layer adds authority, and [`ErrorCode::InvalidConfig`] for a value
/// this implementation cannot compare or a key a layer may not carry.
pub fn resolve(inputs: &ResolveInputs) -> Result<Resolved, JailError> {
    let scratch_host = match &inputs.scratch {
        ScratchRoot::Managed => None,
        ScratchRoot::Host { path } => Some(path.as_bytes().to_vec()),
    };
    let tokenizer = Tokenizer {
        workspace: inputs.workspace.clone(),
        scratch: scratch_host,
    };

    let mut authority = Authority {
        read_write: inputs.baseline.read_write.clone(),
        read_only: inputs.baseline.read_only.clone(),
        deny_read: inputs.baseline.deny_read.clone(),
        protected_coverage: inputs.baseline.protected_coverage,
        protected_segments: inputs.baseline.protected_segments.clone(),
        network_mode: inputs.baseline.network_mode,
        network_allow: inputs.baseline.network_allow.clone(),
        limits: inputs.baseline.limits.clone(),
        observation: inputs.baseline.observation,
    };
    let mut provenance = vec![ProvenanceEntry {
        origin: format!("builtin-profile:{}", inputs.base_profile.as_str()),
        key: "profile".to_owned(),
        detail: None,
    }];

    for layer in &inputs.layers {
        apply_layer(inputs, &tokenizer, &mut authority, &mut provenance, layer)?;
    }

    let snapshot = build_snapshot(inputs, &authority)?;
    let digest = snapshot.digest()?;
    let requirements = crate::capability::requirements(&snapshot);
    Ok(Resolved {
        snapshot,
        digest,
        provenance,
        requirements,
        ceilings: authority.limits,
        policy_name: inputs.policy_name.clone(),
    })
}

fn apply_layer(
    inputs: &ResolveInputs,
    tokenizer: &Tokenizer,
    authority: &mut Authority,
    provenance: &mut Vec<ProvenanceEntry>,
    layer: &Layer,
) -> Result<(), JailError> {
    let prefix = &layer.key_prefix;
    if let Some(key) = &layer.delta.forbidden_key {
        return Err(refuse(
            ErrorCode::PolicyWidening,
            &format!("{prefix}{key}"),
            format!("`{key}` may not appear in {}", layer.origin.label()),
        ));
    }

    // Narrowing decisions compare against the authority as it was before this
    // layer, so one layer cannot bootstrap itself into wider authority.
    let base = authority.clone();
    let expand = |raw: &[u8]| match layer.origin {
        LayerOrigin::ProjectConfig(_) => raw.to_vec(),
        _ => expand_home(raw, inputs.operator_home.as_deref()),
    };

    for (kind, entries) in [
        ("read_write", &layer.delta.read_write),
        ("read_only", &layer.delta.read_only),
        ("deny_read", &layer.delta.deny_read),
    ] {
        let key = format!("{prefix}filesystem.{kind}");
        for raw in entries {
            let absolute = normalize_path(layer.base_dir.as_deref(), &expand(raw), &key)?;
            let reference = tokenizer.tokenize(&absolute, &key)?;
            if layer.narrowing {
                let mode = base.mode_at(&reference);
                let allowed = match kind {
                    "read_write" => mode == AccessMode::ReadWrite,
                    "read_only" => {
                        matches!(mode, AccessMode::ReadWrite | AccessMode::ReadOnly)
                    }
                    _ => true,
                };
                if !allowed {
                    return Err(refuse(
                        ErrorCode::PolicyWidening,
                        &key,
                        format!(
                            "{} adds `{kind}` authority for {} that the base does not grant",
                            layer.origin.label(),
                            reference.to_display()
                        ),
                    ));
                }
            }
            match kind {
                "read_write" => authority.read_write.push(reference),
                "read_only" => authority.read_only.push(reference),
                _ => authority.deny_read.push(reference),
            }
            provenance.push(ProvenanceEntry {
                origin: layer.origin.label(),
                key: key.clone(),
                detail: None,
            });
        }
    }

    if let Some(coverage) = layer.delta.protected_coverage {
        let key = format!("{prefix}filesystem.protected_coverage");
        if layer.narrowing && coverage < base.protected_coverage {
            return Err(refuse(
                ErrorCode::PolicyWidening,
                &key,
                format!(
                    "{} weakens protected coverage from `{}` to `{}`",
                    layer.origin.label(),
                    base.protected_coverage.as_str(),
                    coverage.as_str()
                ),
            ));
        }
        authority.protected_coverage = coverage;
        provenance.push(ProvenanceEntry {
            origin: layer.origin.label(),
            key,
            detail: Some(coverage.as_str().to_owned()),
        });
    }

    if let Some(mode) = layer.delta.network_mode {
        let key = format!("{prefix}network.mode");
        if layer.narrowing && mode.authority_rank() > base.network_mode.authority_rank() {
            return Err(refuse(
                ErrorCode::PolicyWidening,
                &key,
                format!(
                    "{} widens the network from `{}` to `{}`",
                    layer.origin.label(),
                    base.network_mode.as_str(),
                    mode.as_str()
                ),
            ));
        }
        authority.network_mode = mode;
        provenance.push(ProvenanceEntry {
            origin: layer.origin.label(),
            key,
            detail: Some(mode.as_str().to_owned()),
        });
    }

    for raw in &layer.delta.network_allow {
        let key = format!("{prefix}network.allow");
        if base.network_mode != NetworkMode::Proxy {
            // §6.1: `tool` and `build` reject proxy grants, and a policy with
            // no proxy has nothing for a host rule to authorize. Accepting it
            // silently would leave an operator believing a grant applied.
            return Err(refuse(
                ErrorCode::InvalidConfig,
                &key,
                format!(
                    "network mode is `{}`, which accepts no host grants",
                    base.network_mode.as_str()
                ),
            ));
        }
        let rules = HostRule::parse(raw).map_err(|error| {
            let code = if layer.narrowing {
                // The subset relationship is unknown, which §6.3 refuses.
                ErrorCode::PolicyWidening
            } else {
                ErrorCode::InvalidConfig
            };
            let prefix = if layer.narrowing {
                "unknown subset: "
            } else {
                ""
            };
            refuse(code, &key, format!("{prefix}{error}"))
        })?;
        for rule in rules {
            if layer.narrowing && !base.network_allow.iter().any(|base| base.covers(&rule)) {
                return Err(refuse(
                    ErrorCode::PolicyWidening,
                    &key,
                    format!(
                        "{} adds the host grant `{}`, which no base rule covers",
                        layer.origin.label(),
                        rule.canonical()
                    ),
                ));
            }
            authority.network_allow.push(rule);
        }
        provenance.push(ProvenanceEntry {
            origin: layer.origin.label(),
            key,
            detail: None,
        });
    }

    for key in LimitKey::ALL {
        let Some(ceiling) = layer.delta.limits.get(key).clone() else {
            continue;
        };
        let key_path = format!("{prefix}limits.{}", key.as_str());
        if layer.narrowing
            && let Some(existing) = base.limits.get(key)
            && ceiling.value > existing.value
        {
            return Err(refuse(
                ErrorCode::PolicyWidening,
                &key_path,
                format!(
                    "{} raises the `{}` ceiling from {} to {}",
                    layer.origin.label(),
                    key.as_str(),
                    existing.value,
                    ceiling.value
                ),
            ));
        }
        authority.limits.set(key, Some(ceiling.clone()));
        provenance.push(ProvenanceEntry {
            origin: layer.origin.label(),
            key: key_path,
            detail: Some(ceiling.requested),
        });
    }

    if let Some(mode) = layer.delta.observe {
        let key = format!("{prefix}observation.mode");
        if layer.narrowing && mode == ObserveMode::Off && base.observation.mode == ObserveMode::On {
            return Err(refuse(
                ErrorCode::PolicyWidening,
                &key,
                format!("{} disables observation", layer.origin.label()),
            ));
        }
        authority.observation.mode = mode;
        provenance.push(ProvenanceEntry {
            origin: layer.origin.label(),
            key,
            detail: None,
        });
    }

    if let Some(evidence) = layer.delta.evidence {
        let key = format!("{prefix}observation.evidence");
        if layer.narrowing
            && evidence == EvidenceMode::BestEffort
            && base.observation.evidence == EvidenceMode::Strict
        {
            return Err(refuse(
                ErrorCode::PolicyWidening,
                &key,
                format!(
                    "{} weakens evidence from `strict` to `best-effort`",
                    layer.origin.label()
                ),
            ));
        }
        authority.observation.evidence = evidence;
        provenance.push(ProvenanceEntry {
            origin: layer.origin.label(),
            key,
            detail: None,
        });
    }

    Ok(())
}

fn build_snapshot(
    inputs: &ResolveInputs,
    authority: &Authority,
) -> Result<PolicySnapshot, JailError> {
    let workspace = native(inputs.workspace.clone(), "workspace")?;
    let ceiling = |ceiling: &Option<Ceiling>| {
        ceiling.as_ref().map(|value| LimitCeiling {
            value: value.value.to_string(),
            required: value.required,
        })
    };
    let mut bindings = inputs.baseline.environment.bindings.clone();
    bindings.sort_by(|left, right| left.name.cmp(&right.name));
    let mut seen = BTreeMap::new();
    for binding in &bindings {
        if seen.insert(binding.name.clone(), ()).is_some() {
            return Err(refuse(
                ErrorCode::InvalidConfig,
                "environment.bindings",
                format!("duplicate environment binding `{}`", binding.name),
            ));
        }
    }
    // canonicalization.md: a non-proxy policy carries no allow rules and no
    // ruleset, so narrowing a proxy to `none` cannot smuggle its former grants
    // into the digest.
    let proxy = authority.network_mode == NetworkMode::Proxy;
    Ok(PolicySnapshot {
        schema: SCHEMA_POLICY_SNAPSHOT.to_owned(),
        profile: inputs.base_profile,
        profile_version: 1,
        platform: inputs.platform,
        roots: Roots {
            workspace,
            scratch: inputs.scratch.clone(),
            vendor_state: inputs.vendor_state,
        },
        filesystem: FilesystemSnapshot {
            read_write: authority.read_write.clone(),
            read_only: authority.read_only.clone(),
            deny_read: authority.deny_read.clone(),
            protected_segments: authority.protected_segments.clone(),
            protected_coverage: authority.protected_coverage,
        },
        network: NetworkSnapshot {
            mode: authority.network_mode.as_str().to_owned(),
            allow: if proxy {
                authority
                    .network_allow
                    .iter()
                    .map(HostRule::canonical)
                    .collect()
            } else {
                // A non-proxy policy cannot smuggle unused grants into the
                // digest (canonicalization.md §"Policy input").
                Vec::new()
            },
            ruleset: proxy.then(|| SCHEMA_NETWORK.to_owned()),
            translation_prefixes: if proxy {
                inputs.translation_prefixes.clone()
            } else {
                Vec::new()
            },
        },
        limits: LimitsSnapshot {
            wall: ceiling(&authority.limits.wall),
            pids: ceiling(&authority.limits.pids),
            mem: ceiling(&authority.limits.mem),
            cpu: ceiling(&authority.limits.cpu),
        },
        observation: authority.observation,
        environment: EnvironmentSnapshot {
            inherit_host: inputs.baseline.environment.inherit_host,
            bindings,
        },
        launch: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(root: RootToken, path: &str) -> PathRef {
        PathRef {
            root,
            path: NativeString::Text(path.to_owned()),
        }
    }

    #[test]
    fn path_containment_compares_components_not_string_prefixes() {
        let a = reference(RootToken::Workspace, "a");
        assert!(a.contains(&reference(RootToken::Workspace, "a")));
        assert!(a.contains(&reference(RootToken::Workspace, "a/b")));
        assert!(!a.contains(&reference(RootToken::Workspace, "ab")));
        assert!(!a.contains(&reference(RootToken::Scratch, "a/b")));
    }

    #[test]
    fn denial_wins_and_read_only_overrides_a_writable_parent() {
        let authority = Authority {
            read_write: vec![reference(RootToken::Workspace, "")],
            read_only: vec![reference(RootToken::Workspace, "vendor")],
            deny_read: vec![reference(RootToken::Workspace, "vendor/secrets")],
            protected_coverage: ProtectedCoverage::None,
            protected_segments: Vec::new(),
            network_mode: NetworkMode::None,
            network_allow: Vec::new(),
            limits: Ceilings::default(),
            observation: ObservationSnapshot {
                mode: ObserveMode::On,
                evidence: EvidenceMode::Strict,
            },
        };
        assert_eq!(
            authority.mode_at(&reference(RootToken::Workspace, "src")),
            AccessMode::ReadWrite
        );
        assert_eq!(
            authority.mode_at(&reference(RootToken::Workspace, "vendor/lib")),
            AccessMode::ReadOnly
        );
        assert_eq!(
            authority.mode_at(&reference(RootToken::Workspace, "vendor/secrets/token")),
            AccessMode::Denied
        );
        assert_eq!(
            authority.mode_at(&reference(RootToken::Host, "/etc")),
            AccessMode::Absent
        );
    }

    #[test]
    fn normalize_refuses_an_escape_and_resolves_dot_segments() {
        assert_eq!(
            normalize_path(Some(b"/srv/demo"), b"./fixtures", "k").expect("normalizes"),
            b"/srv/demo/fixtures".to_vec()
        );
        assert_eq!(
            normalize_path(Some(b"/srv/demo"), b"a/../b", "k").expect("normalizes"),
            b"/srv/demo/b".to_vec()
        );
        assert!(normalize_path(None, b"../../..", "k").is_err());
        assert!(normalize_path(Some(b"/srv"), b"", "k").is_err());
    }
}
