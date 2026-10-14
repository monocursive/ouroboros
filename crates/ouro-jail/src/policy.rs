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

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::ffi::OsStrExt as _;

use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::network::{HostRule, HostRuleError, NetworkMode, Rules};
use crate::records::{
    ErrorCode, ErrorStage, EvidenceMode, JailError, NativeString, ObserveMode, Os, Remediation,
    SCHEMA_NETWORK, SCHEMA_POLICY_SNAPSHOT,
};

pub(crate) mod path;

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
    /// Every built-in profile.
    pub const ALL: [ProfileName; 4] = [
        ProfileName::Agent,
        ProfileName::Tool,
        ProfileName::Build,
        ProfileName::None,
    ];

    /// The wire spelling, the one table of names: [`ProfileName::parse`]
    /// reads it, and a test holds the serde spelling to it.
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
        Self::ALL
            .into_iter()
            .find(|profile| profile.as_str() == text)
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
        path::components(self.path.as_bytes()).collect()
    }

    /// Whether `self` is `other` or one of its ancestors, compared component by
    /// component so that `/work/a` is not an ancestor of `/work/ab`.
    #[must_use]
    pub fn contains(&self, other: &PathRef) -> bool {
        self.root == other.root
            && path::strip_ancestor(self.path.as_bytes(), other.path.as_bytes()).is_some()
    }

    /// A lossy rendering for diagnostics only, the root in its wire
    /// spelling.
    #[must_use]
    pub fn to_display(&self) -> String {
        let root = serde_json::to_value(self.root)
            .ok()
            .and_then(|root| root.as_str().map(str::to_owned))
            .unwrap_or_default();
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
    /// Every coverage, weakest first.
    pub const ALL: [ProtectedCoverage; 3] = [
        ProtectedCoverage::None,
        ProtectedCoverage::ExistingAndRoot,
        ProtectedCoverage::AllDescendants,
    ];

    /// The wire spelling, the one table of names (see
    /// [`ProfileName::as_str`]).
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
        Self::ALL
            .into_iter()
            .find(|coverage| coverage.as_str() == text)
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
    /// The `allow` rules every grant of which omitted its port: the TLS shape,
    /// which admits no plaintext HTTP (network-rules.md, audit 2026-10-08
    /// L21). The canonical spelling always writes the port, so this is the
    /// only place the snapshot, and so its digest, says whether a grant named
    /// it. Omitted when empty, so a policy without such a grant keeps its
    /// digest (canonicalization.md).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tls_only: Vec<String>,
    /// `ouro.jail.network/1` for proxy mode, null otherwise.
    pub ruleset: Option<String>,
    /// Canonical IPv6 CIDRs from the host manifest.
    pub translation_prefixes: Vec<String>,
}

impl NetworkSnapshot {
    /// The rules the `agent` proxy enforces: each `allow` rule, explicit
    /// unless `tls_only` lists it, and the translation prefixes. Parsing a
    /// canonical rule alone would make every omitted-port grant explicit.
    ///
    /// # Errors
    /// [`HostRuleError`] when a rule does not parse, a `tls_only` entry is
    /// not an `allow` rule, or a translation prefix is not an IPv6 CIDR.
    pub fn proxy_rules(&self) -> Result<Rules, HostRuleError> {
        if self
            .tls_only
            .iter()
            .any(|entry| !self.allow.contains(entry))
        {
            return Err(HostRuleError::Malformed(
                "a TLS-only rule is not one of the allow rules",
            ));
        }
        let rules = self
            .allow
            .iter()
            .map(|entry| {
                HostRule::parse(entry).map(|rule| HostRule {
                    explicit_port: !self.tls_only.contains(entry),
                    ..rule
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Rules::new(rules, &self.translation_prefixes)
    }
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

/// `limits` field group of the snapshot. The default sets no ceiling.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSnapshot {
    /// Wall clock, milliseconds. Wall always exists (§6.4).
    pub wall: Option<LimitCeiling>,
    /// Process count.
    pub pids: Option<LimitCeiling>,
    /// Memory, bytes.
    pub mem: Option<LimitCeiling>,
    /// Swap bytes, separate from RAM. Zero disables swap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap: Option<LimitCeiling>,
    /// Aggregate writable filesystem capacity in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<LimitCeiling>,
    /// Aggregate writable filesystem inode capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inodes: Option<LimitCeiling>,
    /// CPU bandwidth, percent where 100 is one core.
    pub cpu: Option<LimitCeiling>,
}

/// `observation` field group of the snapshot.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSnapshot {
    /// Opt-in capture of read-only open attempts for candidate-policy learning.
    #[serde(default, skip_serializing_if = "is_false")]
    pub learning: bool,
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

/// How a launch credential reaches the child (§12).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    /// A private copy in vendor state, writable by the child.
    CopyRw,
    /// The source object itself, bound read-only into vendor state.
    BindRo,
    /// Never staged: the vault proxy adds it to the requests it admits.
    Vault,
}

impl CredentialMode {
    /// Every mode.
    pub const ALL: [CredentialMode; 3] = [
        CredentialMode::CopyRw,
        CredentialMode::BindRo,
        CredentialMode::Vault,
    ];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            CredentialMode::CopyRw => "copy_rw",
            CredentialMode::BindRo => "bind_ro",
            CredentialMode::Vault => "vault",
        }
    }

    /// The mode `text` spells, if any.
    #[must_use]
    pub fn parse(text: &str) -> Option<CredentialMode> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == text)
    }
}

/// A resolved launch credential declaration (§12).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDecl {
    /// HTTP credential policy for mode vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<crate::vault::Policy>,
    /// Unique logical id.
    pub id: String,
    /// Absolute native source path.
    pub source: NativeString,
    /// Relative native destination under vendor state (`.vault-<id>` for
    /// `vault`, which stages no file there).
    pub dest: NativeString,
    /// How it reaches the child.
    pub mode: CredentialMode,
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
/// Its serialized form is the complete digest input. It carries no
/// provenance, no capability measurement, no attempt id and no chosen backend
/// (canonicalization.md).
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct PolicySnapshot {
    /// Optional operator argv accident filters.
    #[serde(skip_serializing_if = "crate::commands::Rules::is_empty")]
    pub commands: crate::commands::Rules,
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
        // Every path is checked against the serialized shape: a renamed or
        // missing field is an internal error, never a silently unsorted array
        // and so a second digest for the same policy.
        for path in [
            &["filesystem", "read_write"][..],
            &["filesystem", "read_only"][..],
            &["filesystem", "deny_read"][..],
            &["filesystem", "protected_segments"][..],
            &["network", "allow"][..],
            &["network", "translation_prefixes"][..],
        ] {
            sort_at(&mut value, path, Absent::Never, Order::Set)?;
        }
        sort_at(
            &mut value,
            &["network", "tls_only"],
            Absent::WhenEmpty,
            Order::Set,
        )?;
        sort_at(
            &mut value,
            &["launch", "state_subdirs"],
            Absent::UnderNull,
            Order::Set,
        )?;
        if let Some(credentials) = value
            .pointer_mut("/launch/credentials")
            .and_then(serde_json::Value::as_array_mut)
        {
            for credential in credentials {
                if let Some(vault) = credential.get_mut("vault") {
                    for field in ["paths", "binaries"] {
                        sort_at(vault, &[field], Absent::WhenEmpty, Order::Set)?;
                    }
                }
            }
        }
        // Keyed collections follow the same byte order
        sort_at(
            &mut value,
            &["environment", "bindings"],
            Absent::Never,
            Order::Keyed,
        )?;
        sort_at(
            &mut value,
            &["launch", "credentials"],
            Absent::UnderNull,
            Order::Keyed,
        )?;
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

/// When a sorted array may legitimately be missing from the serialized
/// snapshot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Absent {
    /// Always serialized.
    Never,
    /// Beneath a field group that serializes as `null` when absent
    /// (`launch`).
    UnderNull,
    /// Skipped from serialization when empty.
    WhenEmpty,
}

/// How an array is ordered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Order {
    /// A set: sorted and deduplicated by canonical bytes.
    Set,
    /// A keyed collection: sorted by canonical bytes, never deduplicated.
    Keyed,
}

fn sort_at(
    value: &mut serde_json::Value,
    path: &[&str],
    absent: Absent,
    order: Order,
) -> Result<(), JailError> {
    let missing = |what: &str| {
        JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Resolving,
            Remediation::InspectState,
            format!(
                "the serialized policy snapshot {what} at `{}`",
                path.join(".")
            ),
        )
    };
    let mut node = value;
    for key in path {
        node = match node.get_mut(key) {
            Some(serde_json::Value::Null) if absent == Absent::UnderNull => return Ok(()),
            None if absent == Absent::WhenEmpty => return Ok(()),
            Some(next) => next,
            None => return Err(missing("has no field")),
        };
    }
    let Some(items) = node.as_array_mut() else {
        return Err(missing("has no array"));
    };
    let mut encoded: Vec<(Vec<u8>, serde_json::Value)> = Vec::with_capacity(items.len());
    for item in items.iter() {
        encoded.push((
            canonical::to_jcs(item).map_err(JailError::from)?,
            item.clone(),
        ));
    }
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    if order == Order::Set {
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

/// The resource ceilings, each present or absent.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Ceilings {
    /// Wall clock in milliseconds.
    pub wall: Option<Ceiling>,
    /// Process count.
    pub pids: Option<Ceiling>,
    /// Memory in bytes.
    pub mem: Option<Ceiling>,
    /// Swap bytes; zero disables swap.
    pub swap: Option<Ceiling>,
    /// Aggregate writable filesystem capacity in bytes.
    pub storage: Option<Ceiling>,
    /// Aggregate writable filesystem inode capacity.
    pub inodes: Option<Ceiling>,
    /// CPU percentage.
    pub cpu: Option<Ceiling>,
}

impl Ceilings {
    fn get(&self, key: LimitKey) -> &Option<Ceiling> {
        match key {
            LimitKey::Wall => &self.wall,
            LimitKey::Pids => &self.pids,
            LimitKey::Mem => &self.mem,
            LimitKey::Swap => &self.swap,
            LimitKey::Storage => &self.storage,
            LimitKey::Inodes => &self.inodes,
            LimitKey::Cpu => &self.cpu,
        }
    }

    fn set(&mut self, key: LimitKey, ceiling: Option<Ceiling>) {
        match key {
            LimitKey::Wall => self.wall = ceiling,
            LimitKey::Pids => self.pids = ceiling,
            LimitKey::Mem => self.mem = ceiling,
            LimitKey::Swap => self.swap = ceiling,
            LimitKey::Storage => self.storage = ceiling,
            LimitKey::Inodes => self.inodes = ceiling,
            LimitKey::Cpu => self.cpu = ceiling,
        }
    }
}

/// The supported limit keys (§6.4).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum LimitKey {
    /// Wall-clock deadline.
    Wall,
    /// Process count ceiling.
    Pids,
    /// Memory ceiling.
    Mem,
    /// Swap ceiling, independent of RAM.
    Swap,
    /// Aggregate allocated filesystem bytes.
    Storage,
    /// Filesystem inode capacity.
    Inodes,
    /// CPU bandwidth ceiling.
    Cpu,
}

impl LimitKey {
    /// Every key, in a stable order.
    pub const ALL: [LimitKey; 7] = [
        LimitKey::Wall,
        LimitKey::Pids,
        LimitKey::Mem,
        LimitKey::Swap,
        LimitKey::Storage,
        LimitKey::Inodes,
        LimitKey::Cpu,
    ];

    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LimitKey::Wall => "wall",
            LimitKey::Pids => "pids",
            LimitKey::Mem => "mem",
            LimitKey::Swap => "swap",
            LimitKey::Storage => "storage",
            LimitKey::Inodes => "inodes",
            LimitKey::Cpu => "cpu",
        }
    }

    /// Parses the wire spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|key| key.as_str() == text)
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
    // The §6.2 step-2 launch-profile layer
    /// An operator launch profile (`<config-dir>/launch/<name>.toml`), whose
    /// `network.allow` is an operator grant.
    LaunchProfile(String),
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
        // A launch profile's allowed hosts are operator grants
        || matches!(self, LayerOrigin::LaunchProfile(_))
    }

    /// Whether this layer may RAISE a resource ceiling above the base
    /// profile's (issue draft 07).
    ///
    /// A ceiling limits the contained party — its runtime, memory, process
    /// count — so raising one grants the child no authority the operator did
    /// already have: an operator-owned file has at least the authority of the
    /// same operator's `--limit` flag. The untrusted project file keeps the
    /// §6.3 refusal: the contained party must not extend its own runtime.
    #[must_use]
    pub fn may_raise_ceilings(&self) -> bool {
        matches!(
            self,
            LayerOrigin::CommandLine
                | LayerOrigin::OperatorConfig(_)
                | LayerOrigin::OperatorProfileFile(_)
                | LayerOrigin::LaunchProfile(_)
        )
    }

    /// Whether a leading `~/` in this layer's paths names the operator home.
    ///
    /// §6.2: "Only operator files expand a leading `~/` against the operator
    /// home." The operator's profile file, `config.toml` and launch profiles
    /// are operator files. CLI paths are relative to the invocation cwd (the
    /// shell already expanded any `~` it meant) and a project file's paths
    /// are the contained party's own text, so there `~/x` names the literal
    /// directory `~/x` beneath the base, never the home.
    #[must_use]
    pub fn expands_home(&self) -> bool {
        matches!(
            self,
            LayerOrigin::OperatorProfileFile(_)
                | LayerOrigin::OperatorConfig(_)
                | LayerOrigin::LaunchProfile(_)
        )
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

    /// Whether §6.3 narrowing applies: the layer may only remove authority
    /// from what the layers before it established. A selected operator
    /// profile file narrows its built-in base, and the workspace-root
    /// `ouro.toml` is the contained party's own file.
    #[must_use]
    pub fn narrows(&self) -> bool {
        matches!(
            self,
            LayerOrigin::OperatorProfileFile(_) | LayerOrigin::ProjectConfig(_)
        )
    }

    /// The prefix of the exact key paths this layer's refusals name: a
    /// profile file's keys are top-level, `config.toml` and `ouro.toml` keep
    /// theirs under `[jail]`, a launch profile's are `launch.*`, and the
    /// environment and command line name their own variables and flags.
    #[must_use]
    pub fn key_prefix(&self) -> &'static str {
        match self {
            LayerOrigin::OperatorConfig(_) | LayerOrigin::ProjectConfig(_) => "jail.",
            LayerOrigin::LaunchProfile(_) => "launch.",
            LayerOrigin::OperatorProfileFile(_)
            | LayerOrigin::Environment
            | LayerOrigin::CommandLine => "",
        }
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
            LayerOrigin::LaunchProfile(name) => format!("launch-profile:{name}"),
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
}

/// One configuration layer in §6.2 order. Whether it narrows and how its key
/// paths are spelled follow from its origin ([`LayerOrigin::narrows`],
/// [`LayerOrigin::key_prefix`]), so a call site cannot get them wrong.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Layer {
    /// Where it came from.
    pub origin: LayerOrigin,
    /// The directory relative paths in this layer resolve against, if any.
    pub base_dir: Option<Vec<u8>>,
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

    let components: Vec<&[u8]> = path::components(absolute).collect();
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
/// Audit 2026-09-25-2, S3: whether a `deny_read` entry is `/`, `/run`,
/// `/run/ouro` or beneath `/run/ouro`. The sandbox's own plumbing lives
/// there (the jail binary, the proxy socket directory, staged state), and a
/// mask renders after every staged mount, so such a denial would remove the
/// boundary's own infrastructure instead of narrowing the child's authority.
fn masks_boundary_plumbing(absolute: &[u8]) -> bool {
    const PREFIX: &[u8] = b"/run/ouro";
    absolute == b"/"
        || absolute == b"/run"
        || absolute.starts_with(PREFIX)
            && (absolute.len() == PREFIX.len() || absolute[PREFIX.len()] == b'/')
}

/// Lexically normalizes `raw` against `base_dir` without touching the
/// filesystem ([`path::normalize`]).
///
/// Portable code does not resolve symlinks: §9.1 pins source identity with
/// directory handles at preparation, which is the Linux slice's job. A `..`
/// that would escape the root refuses instead of clamping.
fn normalize_path(base_dir: Option<&[u8]>, raw: &[u8], key: &str) -> Result<Vec<u8>, JailError> {
    path::normalize(base_dir, raw).map_err(|refusal| path_refusal(refusal, key))
}

fn path_refusal(refusal: path::Refusal, key: &str) -> JailError {
    let message = match refusal {
        path::Refusal::Empty => "a filesystem path may not be empty",
        path::Refusal::Nul => "a filesystem path may not contain NUL",
        path::Refusal::Relative => "a relative path has no directory to resolve against",
        path::Refusal::EscapesRoot => "a path escapes the filesystem root with `..`",
        path::Refusal::HomeUnavailable => {
            "a `~/` path needs the operator home, which is unavailable"
        }
        path::Refusal::HomeNotAbsolute => {
            "a `~/` path needs the operator home, and HOME is not an absolute path"
        }
    };
    refuse(ErrorCode::InvalidConfig, key, message.to_owned())
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
    path::strip_ancestor(root, absolute).map(|rest| path::join(&rest))
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

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
    let prefix = layer.origin.key_prefix();
    let narrowing = layer.origin.narrows();

    // Narrowing decisions compare against the authority as it was before this
    // layer, so one layer cannot bootstrap itself into wider authority.
    let base = authority.clone();
    let expand = |raw: &[u8], key: &str| {
        if layer.origin.expands_home() {
            path::expand_home(raw, inputs.operator_home.as_deref())
                .map_err(|refusal| path_refusal(refusal, key))
        } else {
            Ok(raw.to_vec())
        }
    };

    for (kind, entries) in [
        ("read_write", &layer.delta.read_write),
        ("read_only", &layer.delta.read_only),
        ("deny_read", &layer.delta.deny_read),
    ] {
        let key = format!("{prefix}filesystem.{kind}");
        let grant = kind != "deny_read";
        for raw in entries {
            let absolute = normalize_path(layer.base_dir.as_deref(), &expand(raw, &key)?, &key)?;
            if kind == "deny_read" && masks_boundary_plumbing(&absolute) {
                // Audit 2026-09-25-2, S3: a denial is always admitted as
                // narrowing — except one whose mask would cover the
                // boundary's own plumbing. `/run`, `/run/ouro` and beneath
                // hold the jail binary, the proxy socket directory and the
                // staged state of the *next* run in this workspace, and the
                // mask renders after every staged mount, so it would remove
                // them rather than narrow the child. Refused for every
                // layer, trusted or not.
                return Err(refuse(
                    ErrorCode::InvalidConfig,
                    &key,
                    format!(
                        "denies `{}` at {}, which would mask the boundary's own \
                         plumbing under /run/ouro rather than narrow the child",
                        String::from_utf8_lossy(&absolute),
                        layer.origin.label()
                    ),
                ));
            }
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
            if narrowing {
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
        if narrowing && coverage < base.protected_coverage {
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
        if narrowing && mode.authority_rank() > base.network_mode.authority_rank() {
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
        if let Some(reason) = unapplied_network_mode(inputs.base_profile, mode) {
            return Err(refuse(ErrorCode::InvalidConfig, &key, reason));
        }
        authority.network_mode = mode;
        provenance.push(ProvenanceEntry {
            origin: layer.origin.label(),
            key,
            detail: Some(mode.as_str().to_owned()),
        });
    }

    if narrowing && (layer.delta.network_allow_present || !layer.delta.network_allow.is_empty()) {
        authority.network_allow.clear();
    }
    for raw in &layer.delta.network_allow {
        let key = format!("{prefix}network.allow");
        // §6.1: `tool` and `build` reject proxy grants, whatever mode a layer
        // writes: only `agent` starts a proxy, so a host rule anywhere else
        // would be recorded as a grant that never applied.
        if inputs.base_profile != ProfileName::Agent {
            return Err(refuse(
                ErrorCode::InvalidConfig,
                &key,
                format!(
                    "the `{}` profile rejects proxy grants (jail-v1 §6.1); only `agent` has a \
                     proxy",
                    inputs.base_profile.as_str()
                ),
            ));
        }
        // Within `agent`, the mode this layer leaves, its own `network.mode`
        // included: a file that switches to `none` and lists hosts asks for
        // grants nothing would apply.
        if authority.network_mode != NetworkMode::Proxy {
            return Err(refuse(
                ErrorCode::InvalidConfig,
                &key,
                format!(
                    "network mode is `{}`, which accepts no host grants",
                    authority.network_mode.as_str()
                ),
            ));
        }
        let rule = HostRule::parse(raw).map_err(|error| {
            let code = if narrowing {
                // The subset relationship is unknown, which §6.3 refuses.
                ErrorCode::PolicyWidening
            } else {
                ErrorCode::InvalidConfig
            };
            let prefix = if narrowing { "unknown subset: " } else { "" };
            refuse(code, &key, format!("{prefix}{error}"))
        })?;
        if layer.origin.is_operator_grant() {
            grants.push(crate::records::Grant {
                kind: "allow_host".to_owned(),
                value: NativeString::Text(rule.canonical()),
                by: "operator".to_owned(),
            });
        }
        if narrowing && !base.network_allow.iter().any(|base| base.covers(&rule)) {
            return Err(refuse(
                ErrorCode::PolicyWidening,
                &key,
                format!(
                    "{} adds the host grant `{}`{}, which no base rule covers",
                    layer.origin.label(),
                    rule.canonical(),
                    if rule.explicit_port {
                        " with an explicit port (which admits plaintext HTTP)"
                    } else {
                        ""
                    }
                ),
            ));
        }
        authority.network_allow.push(rule);
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
        // Issue draft 07: a resource ceiling limits the contained party, so
        // an operator-owned layer may raise it exactly like the same
        // operator's `--limit` flag. Only the untrusted project file (and
        // layers that may not grant at all) keep the §6.3 refusal.
        if !layer.origin.may_raise_ceilings()
            && let Some(existing) = base.limits.get(key)
            && ceiling.value > existing.value
        {
            return Err(refuse(
                ErrorCode::PolicyWidening,
                &key_path,
                format!(
                    "{} raises the `{}` ceiling from {} to {} (pass --limit {}= on the \
                     command line, which an operator may always do)",
                    layer.origin.label(),
                    key.as_str(),
                    existing.value,
                    ceiling.value,
                    key.as_str()
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
        if narrowing && mode == ObserveMode::Off && base.observation.mode == ObserveMode::On {
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
        if narrowing
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

/// Why `profile` cannot apply the network `mode` a layer asks for, if it
/// cannot. Only `agent` starts a proxy (§6.1: `tool` and `build` reject proxy
/// grants), and the contained profiles always run in a network namespace of
/// their own (§10: "`tool` and `build` have no network proxy and no host
/// network access"), so `host` is `none`'s alone. A snapshot recording a mode
/// the boundary never applies would be a grant that never applied. `none`
/// asking for `none` is left to its requirements, which refuse it as
/// unsatisfiable (I02).
fn unapplied_network_mode(profile: ProfileName, mode: NetworkMode) -> Option<String> {
    match (profile, mode) {
        (ProfileName::Agent, NetworkMode::Proxy)
        | (ProfileName::None, NetworkMode::Host)
        | (_, NetworkMode::None) => None,
        (_, NetworkMode::Proxy) => Some(format!(
            "the `{}` profile has no proxy (jail-v1 §6.1); only `agent` does",
            profile.as_str()
        )),
        (_, NetworkMode::Host) => Some(format!(
            "the `{}` profile runs in a network namespace of its own; only `none` uses the \
             host network",
            profile.as_str()
        )),
    }
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
    // A rule is TLS-only when no grant of it named its port: a second grant
    // with the port written out admits plaintext, and the proxy admits
    // plaintext when any explicit rule permits the destination.
    let explicit: BTreeSet<String> = authority
        .network_allow
        .iter()
        .filter(|rule| rule.explicit_port)
        .map(HostRule::canonical)
        .collect();
    let tls_only: Vec<String> = authority
        .network_allow
        .iter()
        .filter(|rule| !rule.explicit_port)
        .map(HostRule::canonical)
        .filter(|canonical| !explicit.contains(canonical))
        .collect();
    Ok(PolicySnapshot {
        commands: crate::commands::Rules::default(),
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
            tls_only: if proxy { tls_only } else { Vec::new() },
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
            swap: ceiling(&authority.limits.swap),
            storage: ceiling(&authority.limits.storage),
            inodes: ceiling(&authority.limits.inodes),
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

// §9.1 — an operator grant may not expose a pseudo filesystem
/// Whether a filesystem `f_type` magic is `proc`, `sysfs`, cgroup (v1 or v2)
/// or devtmpfs. The Linux platform reads it with `fstatfs` on the resolved,
/// pinned source; keeping the set here lets the resolution rule and its test
/// stay portable.
#[must_use]
pub fn is_pseudo_fs_magic(f_type: i64) -> bool {
    // proc, sysfs, cgroup v1, cgroup v2 (statfs magic numbers, uapi/magic.h).
    const PROC: i64 = 0x0000_9fa0;
    const SYSFS: i64 = 0x6265_6572;
    const CGROUP: i64 = 0x0027_e0eb;
    const CGROUP2: i64 = 0x6367_7270;
    // Security 2026-09-27 (audit 3 A3): devtmpfs. There is no DEV_SUPER_MAGIC
    // in uapi/magic.h and none in libc: a mainline devtmpfs superblock
    // reports TMPFS_MAGIC or RAMFS_MAGIC, so on a real host a `/dev` grant is
    // caught by the mount-topology branch (fstype `devtmpfs` in the Linux
    // platform's mount list), not here. This literal pins the magic for a
    // kernel that reports one; it matches no current filesystem's `f_type`.
    const DEVTMPFS: i64 = 0x0000_137d;
    matches!(f_type, PROC | SYSFS | CGROUP | CGROUP2 | DEVTMPFS)
}

/// Whether an operator grant of `resolved` would expose host `/proc`, `/sys`,
/// cgroupfs, devtmpfs or the `/run` runtime tree (jail-v1 §9.1: "Do not
/// expose host `/proc`, `/sys`, cgroupfs" — audit 3 A3 adds devtmpfs and the
/// `/run` tree).
///
/// `source_on_pseudo_fs` is the platform's `fstatfs` verdict on the resolved
/// source itself: true catches a grant whose source is on such a filesystem
/// (a direct `--ro /proc`, a `--ro /proc/1`, a symlink resolving onto one).
/// `pseudo_mounts` are the mount points of every proc/sysfs/cgroup/devtmpfs
/// mount and of every tmpfs mounted at or beneath `/run`; a grant that is an
/// ancestor of, equal to, or **beneath** any of them exposes or enters it
/// (`--ro /` reaches `/proc` and `/sys`; `--rw /run/user/1000` and
/// `--rw /dev/shm` enter the runtime trees even though tmpfs is not
/// distinguishable by `fstatfs` alone). The decision is on filesystem
/// identity and mount topology, never on how the grant was spelled.
#[must_use]
pub fn grant_exposes_pseudo_fs(
    resolved: &std::path::Path,
    source_on_pseudo_fs: bool,
    pseudo_mounts: &[std::path::PathBuf],
) -> bool {
    if source_on_pseudo_fs {
        return true;
    }
    pseudo_mounts
        .iter()
        .any(|mount| mount.starts_with(resolved) || resolved.starts_with(mount))
}

fn is_false(value: &bool) -> bool {
    !value
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A credential mode's serde spelling is its `as_str`, and `parse`
    /// reads back exactly those spellings, so a snapshot's bytes and its
    /// digest do not depend on which one wrote it.
    #[test]
    fn each_credential_mode_has_one_spelling() {
        for mode in CredentialMode::ALL {
            assert_eq!(
                serde_json::to_value(mode).unwrap(),
                serde_json::Value::from(mode.as_str())
            );
            assert_eq!(CredentialMode::parse(mode.as_str()), Some(mode));
        }
        for text in ["", "Vault", "copy-rw", "bind_ro "] {
            assert_eq!(CredentialMode::parse(text), None, "{text:?}");
        }
    }

    fn reference(root: RootToken, path: &str) -> PathRef {
        PathRef {
            root,
            path: NativeString::Text(path.to_owned()),
        }
    }

    /// A sort path that the serialized snapshot does not have is an internal
    /// error, not a silently unsorted array; only the declared absences pass.
    #[test]
    fn a_missing_sort_path_is_an_internal_error() {
        let mut value = serde_json::json!({
            "filesystem": {"read_write": ["b", "a", "a"]},
            "launch": null,
            "vault": {},
        });
        sort_at(
            &mut value,
            &["filesystem", "read_write"],
            Absent::Never,
            Order::Set,
        )
        .expect("present");
        assert_eq!(
            value["filesystem"]["read_write"],
            serde_json::json!(["a", "b"])
        );
        for (path, absent) in [
            (&["filesystem", "read_only"][..], Absent::Never),
            (&["network", "allow"][..], Absent::Never),
            (&["launch", "state_subdirs"][..], Absent::Never),
            (&["vault", "paths"][..], Absent::UnderNull),
        ] {
            let error =
                sort_at(&mut value, path, absent, Order::Set).expect_err("a missing path refuses");
            assert_eq!(error.code, ErrorCode::InternalError, "{path:?}");
        }
        sort_at(
            &mut value,
            &["launch", "state_subdirs"],
            Absent::UnderNull,
            Order::Set,
        )
        .expect("launch is null");
        sort_at(
            &mut value,
            &["vault", "paths"],
            Absent::WhenEmpty,
            Order::Set,
        )
        .expect("an empty vault list is skipped");
    }

    /// What each §6.2 layer may do follows from where it came from: only the
    /// operator profile file and the project file narrow, only operator
    /// files expand `~/`, and the key prefixes match the files' own tables.
    #[test]
    fn layer_behaviour_follows_its_origin() {
        let name = || "x".to_owned();
        for (origin, narrows, prefix, home) in [
            (LayerOrigin::OperatorProfileFile(name()), true, "", true),
            (LayerOrigin::OperatorConfig(name()), false, "jail.", true),
            (LayerOrigin::LaunchProfile(name()), false, "launch.", true),
            (LayerOrigin::Environment, false, "", false),
            (LayerOrigin::CommandLine, false, "", false),
            (LayerOrigin::ProjectConfig(name()), true, "jail.", false),
        ] {
            assert_eq!(origin.narrows(), narrows, "{origin:?}");
            assert_eq!(origin.key_prefix(), prefix, "{origin:?}");
            assert_eq!(origin.expands_home(), home, "{origin:?}");
        }
    }

    /// `as_str` is the one table of wire names: `parse` reads it, and the
    /// serde spelling the snapshot writes must agree with it.
    #[test]
    fn wire_spellings_have_one_source() {
        fn serde_name(value: impl Serialize) -> String {
            serde_json::to_value(value)
                .expect("serializes")
                .as_str()
                .expect("a string")
                .to_owned()
        }
        for profile in ProfileName::ALL {
            assert_eq!(serde_name(profile), profile.as_str());
            assert_eq!(ProfileName::parse(profile.as_str()), Some(profile));
        }
        for coverage in ProtectedCoverage::ALL {
            assert_eq!(serde_name(coverage), coverage.as_str());
            assert_eq!(ProtectedCoverage::parse(coverage.as_str()), Some(coverage));
        }
        for key in LimitKey::ALL {
            assert_eq!(LimitKey::parse(key.as_str()), Some(key));
        }
        assert_eq!(ProfileName::parse("Agent"), None);
        assert_eq!(
            reference(RootToken::VendorState, "a").to_display(),
            "vendor_state:a"
        );
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
                learning: false,
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
}
