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
use std::os::unix::ffi::OsStrExt as _;

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
    /// canonicalization.md: "sort every array lexicographically by each
    /// element's RFC 8785 UTF-8 bytes". Set arrays are also deduplicated by
    /// those bytes; keyed collections (environment bindings, credentials) are
    /// sorted by them too but never deduplicated, since their keys are unique
    /// and a duplicate is refused where the collection is built. A credential's
    /// canonical bytes begin with its `dest` (member names sort `dest`, `id`,
    /// `mode`, `source`), so that order is not id order.
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
        // J4-D7 begin: keyed collections follow the same byte order
        for path in [
            &["environment", "bindings"][..],
            &["launch", "credentials"][..],
        ] {
            sort_keyed_at(&mut value, path)?;
        }
        // J4-D7 end
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
    sort_by_canonical_bytes_at(value, path, true)
}

// J4-D7 begin
fn sort_keyed_at(value: &mut serde_json::Value, path: &[&str]) -> Result<(), JailError> {
    sort_by_canonical_bytes_at(value, path, false)
}

fn sort_by_canonical_bytes_at(
    value: &mut serde_json::Value,
    path: &[&str],
    dedup: bool,
) -> Result<(), JailError> {
    // J4-D7 end
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
    if dedup {
        encoded.dedup_by(|left, right| left.0 == right.0);
    }
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
    // J3-launch begin: the §6.2 step-2 launch-profile layer
    /// An operator launch profile (`<config-dir>/launch/<name>.toml`), whose
    /// `network.allow` is an operator grant.
    LaunchProfile(String),
    // J3-launch end
}

impl LayerOrigin {
    /// Whether this layer's entries are explicit operator grants (§13.2, A2).
    ///
    /// The command line and the operator's own `config.toml` add authority on
    /// purpose. A profile file and a project file may only narrow, so nothing
    /// they contain is a grant.
    #[must_use]
    pub fn is_operator_grant(&self) -> bool {
        matches!(
            self,
            LayerOrigin::CommandLine | LayerOrigin::OperatorConfig(_)
        )
        // J3-launch begin: a launch profile's allowed hosts are operator grants
        || matches!(self, LayerOrigin::LaunchProfile(_))
        // J3-launch end
    }

    /// Whether the paths in this layer are written by an untrusted party.
    ///
    /// §2: "The child, its descendants, its workspace and project
    /// configuration are untrusted." §6.2 steps 1 to 4 are trusted operator
    /// inputs; step 5, the workspace-root `ouro.toml`, is not. An untrusted
    /// path is compared by filesystem identity, because its spelling is chosen
    /// by whoever is being contained.
    #[must_use]
    pub fn is_untrusted(&self) -> bool {
        matches!(self, LayerOrigin::ProjectConfig(_))
    }

    /// A safe label for provenance records.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            LayerOrigin::OperatorProfileFile(name) => format!("operator-profile:{name}"),
            LayerOrigin::OperatorConfig(name) => format!("operator-config:{name}"),
            LayerOrigin::Environment => "environment".to_owned(),
            LayerOrigin::CommandLine => "cli".to_owned(),
            LayerOrigin::ProjectConfig(name) => format!("project-config:{name}"),
            // J3-launch begin: provenance label
            LayerOrigin::LaunchProfile(name) => format!("launch-profile:{name}"),
            // J3-launch end
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
    /// Whether a file explicitly supplied the allow set, including an empty set.
    pub network_allow_present: bool,
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
    /// The explicit operator grants, for the receipt's `policy.grants`.
    ///
    /// §13.2 records "grants and requirements", and north star §4.2 calls
    /// `--rw` and `--allow-host` "separate explicit grants, recorded in the
    /// receipt". The profile baseline is not a grant: it is what the named
    /// profile means, and listing it would drown the operator's own additions.
    pub grants: Vec<crate::records::Grant>,
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
    /// The access `target` has.
    ///
    /// §6.3 has two rules and they are not the same rule. "Denial wins over an
    /// overlapping allow" is absolute: a `deny_read` ancestor denies every
    /// descendant, however deep and however specific the allow beneath it is.
    /// "Read-only carve-outs override writable parents" is the longest-match
    /// rule, and it decides only between read-only and writable.
    ///
    /// Making denial merely the most specific match was the defect: a project
    /// file could re-grant a denied subtree just by naming a path one component
    /// deeper than the denial.
    fn mode_at(&self, target: &PathRef) -> AccessMode {
        if self.deny_read.iter().any(|entry| entry.contains(target)) {
            return AccessMode::Denied;
        }
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
            // Absent < read-write < read-only, so a root-level entry still
            // beats "nothing matched", and a carve-out still beats a writable
            // entry at the same depth.
            let rank_of = |mode: AccessMode| match mode {
                AccessMode::ReadOnly => 2u8,
                AccessMode::ReadWrite => 1,
                AccessMode::Denied | AccessMode::Absent => 0,
            };
            let candidate_rank = rank_of(candidate);
            let current_rank = rank_of(*mode);
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
        mode
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Filesystem identity for untrusted paths (§6.3)
// ---------------------------------------------------------------------------

/// A filesystem object's identity: the pair the kernel uses, not its spelling.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

fn identity_of(path: &std::path::Path) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::symlink_metadata(path).ok()?;
    Some(FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

fn as_path(bytes: &[u8]) -> &std::path::Path {
    std::path::Path::new(std::ffi::OsStr::from_bytes(bytes))
}

/// Resolves an untrusted absolute path to the identity chain of its components.
///
/// §6.3 requires authority to be compared "after expansion and path
/// resolution", and §2 makes the workspace untrusted. Comparing spellings lets
/// the contained party re-grant a denied subtree three ways: a symlink beside
/// it, a case variation on a case-folding filesystem, and a symlink that leaves
/// the workspace entirely. So each component is `lstat`ed without following
/// anything:
///
/// - a symlink component refuses: what it names is not what it spells, and
///   following it would be trusting the child's choice of target;
/// - a component that does not exist, or that cannot be inspected, refuses:
///   the subset relationship is unknown, and §6.3 says unknown refuses. An
///   absent object is not merely unidentifiable, it is racy: the child can
///   create it as a symlink before the backend binds it;
/// - a non-directory in the middle refuses for the same reason.
///
/// Only grants come here. A denial is compared lexically, because it can only
/// remove authority whatever it names.
///
/// The returned chain is every component's identity from the filesystem root
/// down to the object itself, which is what makes "lies beneath a denied
/// object" decidable without following a link.
fn untrusted_identities(
    absolute: &[u8],
    key: &str,
    origin: &str,
) -> Result<Vec<FileIdentity>, JailError> {
    let unknown = |reason: &str| {
        refuse(
            ErrorCode::PolicyWidening,
            key,
            format!(
                "unknown subset: {origin} names a path this resolver cannot compare by \
                 filesystem identity ({reason})"
            ),
        )
    };

    let components: Vec<&[u8]> = absolute
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
        .collect();
    let mut chain = Vec::with_capacity(components.len() + 1);
    let mut walked: Vec<u8> = Vec::with_capacity(absolute.len());

    let root = std::path::Path::new("/");
    chain.push(identity_of(root).ok_or_else(|| unknown("the filesystem root is unreadable"))?);

    for (index, component) in components.iter().enumerate() {
        walked.push(b'/');
        walked.extend_from_slice(component);
        let path = as_path(&walked);
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(unknown("the object does not exist"));
            }
            Err(error) => return Err(unknown(&format!("it cannot be inspected: {error}"))),
        };
        if metadata.file_type().is_symlink() {
            return Err(refuse(
                ErrorCode::PolicyWidening,
                key,
                format!(
                    "unknown subset: {origin} names a path through a symlink, whose target is \
                     chosen by the contained party"
                ),
            ));
        }
        let last = index + 1 == components.len();
        if !last && !metadata.is_dir() {
            return Err(unknown("a component in the middle is not a directory"));
        }
        use std::os::unix::fs::MetadataExt as _;
        chain.push(FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        });
    }
    Ok(chain)
}

/// The denied entry whose identity appears in `chain`, if any.
///
/// `chain` is the candidate's component identities, so a match anywhere in it
/// means the candidate *is* a denied object or lies beneath one. Denied
/// entries without a host location (a managed scratch or vendor-state root)
/// have no identity yet and are left to the lexical rules.
fn denied_identity<'a>(
    tokenizer: &Tokenizer,
    base: &'a Authority,
    chain: &[FileIdentity],
) -> Option<(&'a PathRef, FileIdentity)> {
    for entry in &base.deny_read {
        let Some(host) = tokenizer.host_path(entry) else {
            continue;
        };
        let Some(identity) = identity_of(as_path(&host)) else {
            continue;
        };
        if chain.contains(&identity) {
            return Some((entry, identity));
        }
    }
    None
}

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

    /// Where a reference lives on this host, when that is known.
    ///
    /// A managed scratch or vendor-state reference has no host location until
    /// the attempt directory exists, so it has no identity to compare and the
    /// caller falls back to the lexical rules for it.
    fn host_path(&self, reference: &PathRef) -> Option<Vec<u8>> {
        let root = match reference.root {
            RootToken::Host => return Some(reference.path.as_bytes().to_vec()),
            RootToken::Workspace => self.workspace.clone(),
            RootToken::Scratch => self.scratch.clone()?,
            RootToken::VendorState => return None,
        };
        let suffix = reference.path.as_bytes();
        if suffix.is_empty() {
            return Some(root);
        }
        let mut out = root;
        out.push(b'/');
        out.extend_from_slice(suffix);
        Some(out)
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
    // §6.3: "Equivalent semantic inputs have the same digest despite different
    // provenance." The roots enter the snapshot normalized, so `/srv/work`,
    // `/srv/work/`, `/srv//work` and `/srv/other/../work` are one digest rather
    // than four. Resolving symlinks needs a filesystem and belongs to the
    // caller that has one; this is the part the library can always do.
    let workspace = normalize_path(None, &inputs.workspace, "workspace")?;
    let scratch = match &inputs.scratch {
        ScratchRoot::Managed => ScratchRoot::Managed,
        ScratchRoot::Host { path } => ScratchRoot::Host {
            path: native(normalize_path(None, path.as_bytes(), "scratch")?, "scratch")?,
        },
    };
    let scratch_host = match &scratch {
        ScratchRoot::Managed => None,
        ScratchRoot::Host { path } => Some(path.as_bytes().to_vec()),
    };
    let tokenizer = Tokenizer {
        workspace: workspace.clone(),
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
    let mut grants: Vec<crate::records::Grant> = Vec::new();

    for layer in &inputs.layers {
        apply_layer(
            inputs,
            &tokenizer,
            &mut authority,
            &mut provenance,
            &mut grants,
            layer,
        )?;
    }

    let snapshot = build_snapshot(inputs, &authority, workspace, scratch)?;
    let digest = snapshot.digest()?;
    let requirements = crate::capability::requirements(&snapshot);
    Ok(Resolved {
        snapshot,
        digest,
        provenance,
        requirements,
        ceilings: authority.limits,
        policy_name: inputs.policy_name.clone(),
        grants,
    })
}

fn apply_layer(
    inputs: &ResolveInputs,
    tokenizer: &Tokenizer,
    authority: &mut Authority,
    provenance: &mut Vec<ProvenanceEntry>,
    grants: &mut Vec<crate::records::Grant>,
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
    // §6.2: "Only operator files expand a leading `~/` against the operator
    // home." CLI paths are relative to the invocation cwd and a project file's
    // paths are the contained party's own text, so `~/x` on the command line
    // names the literal directory `~/x` under the cwd, never the home.
    let expand = |raw: &[u8]| match layer.origin {
        LayerOrigin::OperatorProfileFile(_) | LayerOrigin::OperatorConfig(_) => {
            expand_home(raw, inputs.operator_home.as_deref())
        }
        _ => raw.to_vec(),
    };

    for (kind, entries) in [
        ("read_write", &layer.delta.read_write),
        ("read_only", &layer.delta.read_only),
        ("deny_read", &layer.delta.deny_read),
    ] {
        let key = format!("{prefix}filesystem.{kind}");
        let grant = kind != "deny_read";
        for raw in entries {
            let absolute = normalize_path(layer.base_dir.as_deref(), &expand(raw), &key)?;
            let reference = tokenizer.tokenize(&absolute, &key)?;
            // A grant written by the contained party is compared by filesystem
            // identity. A denial is not, and the asymmetry is the point: a
            // denial can only remove authority, so naming a symlink or a path
            // that does not exist costs nothing. A grant naming an absent path
            // is different, because there is nothing to pin: between this
            // resolution and the backend's bind the child can create that path
            // as a symlink, and §9.1 forbids following an untrusted symlink
            // between policy validation and grant construction. So an absent
            // grant target refuses as an unknown subset.
            if layer.origin.is_untrusted() && grant {
                let chain = untrusted_identities(&absolute, &key, &layer.origin.label())?;
                if let Some(denied) = denied_identity(tokenizer, &base, &chain) {
                    return Err(refuse(
                        ErrorCode::PolicyWidening,
                        &key,
                        format!(
                            "{} adds `{kind}` authority for an object that is {} the denied \
                             {}, whatever its spelling",
                            layer.origin.label(),
                            if chain.last() == Some(&denied.1) {
                                "exactly"
                            } else {
                                "beneath"
                            },
                            denied.0.to_display()
                        ),
                    ));
                }
            }
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
            if layer.origin.is_operator_grant() {
                grants.push(crate::records::Grant {
                    kind: kind.to_owned(),
                    value: native(absolute.clone(), &key)?,
                    by: "operator".to_owned(),
                });
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

    if layer.narrowing
        && (layer.delta.network_allow_present || !layer.delta.network_allow.is_empty())
    {
        authority.network_allow.clear();
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
            if layer.origin.is_operator_grant() {
                grants.push(crate::records::Grant {
                    kind: "allow_host".to_owned(),
                    value: NativeString::Text(rule.canonical()),
                    by: "operator".to_owned(),
                });
            }
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
    workspace: Vec<u8>,
    scratch: ScratchRoot,
) -> Result<PolicySnapshot, JailError> {
    let workspace = native(workspace, "workspace")?;
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
            scratch,
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
