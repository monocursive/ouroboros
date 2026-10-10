//! Data-only launch profiles (jail-v1 §6.1, §6.2, §12).
//!
//! A launch profile is operator TOML at `<config-dir>/launch/<name>.toml`. It
//! names environment mappings, credential inputs, allowed hosts and a default
//! contained jail, and nothing else: it cannot supply or rewrite argv, cannot
//! select `none`, and carries no command, no include and no interpolation.
//! This module turns one file into semantic policy and is the only place the
//! launch grammar is known; no agent is named anywhere in it (I02). The
//! bundled examples under `crates/ouro-jail/profiles/launch/` are data an
//! operator copies by hand; the runtime never discovers them.
//!
//! What a launch profile contributes, and where:
//!
//! - `network.allow` enters resolution as the §6.2 step-2 layer, before the
//!   environment, the CLI and the project file, so a project `ouro.toml` can
//!   still shrink it and the CLI can still add to it.
//! - `environment`, `state_var`, `home_is_state`, `state_subdirs` and the
//!   credentials become the snapshot's environment bindings, the managed
//!   vendor-state root and the `launch` field group, after resolution; no
//!   narrowing layer can name any of them.
//!
//! Validation follows §12: every `LD_*` and `DYLD_*` name refuses, and so do
//! the names the backend controls or generates (the reserved `OURO_*` names,
//! the contained baseline, the proxy variables and the C library's
//! loader/runtime controls, which would reach the trusted launcher before the
//! target does). Credential destinations and `state_subdirs` are relative,
//! `.`/`..`-free and mutually consistent. The file itself must be a regular
//! file this operator owns, mode 0600 or stricter, with one link, reached by a
//! no-follow walk, and neither it nor any directory above it may be a
//! child-writable grant.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::policy::{
    CredentialDecl, EnvBinding, EnvValue, LaunchSnapshot, Layer, LayerOrigin, PathRef, PolicyDelta,
    ProfileName, ProvenanceEntry, Resolved, RootToken, VendorStateRoot,
};
use crate::records::{ErrorCode, ErrorStage, JailError, NativeString, Remediation};
use crate::state::anchored::{self, Dir, Kind};

/// The largest launch file read (the files are a few hundred bytes).
pub const LAUNCH_FILE_MAX: u64 = 64 * 1024;

/// Environment names the baseline and the platform generate: a launch
/// profile cannot bind them (§12: "backend-control names").
pub const GENERATED_NAMES: &[&str] = &["PATH", "LANG", "TERM", "TZ", "TMPDIR", "HOME"];

/// Proxy variables, which the `agent` network plumbing generates (§12:
/// "Generated HOME/state paths and proxy variables"). Matched without case,
/// because clients read both spellings.
pub const PROXY_NAMES: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "FTP_PROXY",
];

/// Names the C runtime reads to load code or data into every process,
/// including the trusted launcher that runs before the target (§12: "Any
/// runtime-library need belongs in an explicit evaluated launch
/// configuration, not a general loader-injection escape hatch"). `LD_*`,
/// `DYLD_*` and `MALLOC_*` are refused by prefix as well.
pub const RUNTIME_CONTROL_NAMES: &[&str] = &[
    "GCONV_PATH",
    "GETCONF_DIR",
    "GLIBC_TUNABLES",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "LOCPATH",
    "NIS_PATH",
    "NLSPATH",
    "RESOLV_HOST_CONF",
    "RES_OPTIONS",
    "TZDIR",
];

/// Why an environment name cannot come from a launch profile, or `None`.
#[must_use]
pub fn reserved_reason(name: &str) -> Option<&'static str> {
    let upper = name.to_ascii_uppercase();
    if upper.starts_with("LD_") || upper.starts_with("DYLD_") {
        return Some("a dynamic-loader name (every LD_* and DYLD_* name is refused)");
    }
    if crate::environment::is_reserved(OsStr::new(name)) || upper.starts_with("OURO_") {
        return Some("a reserved Ouroboros name");
    }
    if upper.starts_with("MALLOC_") || RUNTIME_CONTROL_NAMES.contains(&name) {
        return Some("a C runtime control name that reaches the trusted launcher");
    }
    if PROXY_NAMES.contains(&upper.as_str()) {
        return Some("a proxy variable, which the network plumbing generates");
    }
    if GENERATED_NAMES.contains(&name) {
        return Some("a name the contained baseline generates");
    }
    None
}

/// Whether `name` is a portable environment variable name.
#[must_use]
pub fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && name.len() <= 256
}

/// Whether `name` matches the launch-name grammar `[a-z][a-z0-9_-]{0,63}`.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
        && name.len() <= 64
}

/// Whether `id` is a credential id: `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`.
#[must_use]
pub fn valid_credential_id(id: &str) -> bool {
    let mut bytes = id.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        && id.len() <= 64
}

// ---------------------------------------------------------------------------
// The file grammar
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchFile {
    #[serde(default)]
    bundles: Vec<String>,
    #[serde(default)]
    filesystem: crate::config::FilesystemSection,
    name: String,
    jail: String,
    state_var: Option<String>,
    #[serde(default)]
    home_is_state: bool,
    #[serde(default)]
    state_subdirs: Vec<String>,
    #[serde(default)]
    environment: BTreeMap<String, EnvEntry>,
    #[serde(default)]
    credentials: BTreeMap<String, CredentialEntry>,
    network: Option<LaunchNetwork>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EnvEntry {
    Text(String),
    State(StateReference),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateReference {
    state: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialEntry {
    source: String,
    #[serde(default)]
    dest: String,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    allow_plaintext: bool,
    /// Vault placement: `header = { name = "x-api-key" }` or
    /// `header = { name = "authorization", prefix = "Bearer " }`.
    #[serde(default)]
    header: Option<CredentialHeaderEntry>,
    mode: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialHeaderEntry {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    prefix: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchNetwork {
    #[serde(default)]
    allow: Vec<String>,
}

/// One resolved launch profile.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LaunchProfile {
    /// The profile name, equal to the file stem.
    pub name: String,
    /// Embedded data or an explicitly loaded operator file.
    pub resolution: String,
    /// Data-only fragments included in this profile.
    pub bundles: Vec<String>,
    /// Explicit filesystem additions from the profile and fragments.
    pub filesystem: crate::config::FilesystemSection,
    /// The default contained jail.
    pub jail: ProfileName,
    /// The variable pointed at vendor state, if any.
    pub state_var: Option<String>,
    /// Whether `HOME` points at vendor state.
    pub home_is_state: bool,
    /// Relative directories created under vendor state.
    pub state_subdirs: Vec<NativeString>,
    /// Explicit environment bindings, sorted by name.
    pub environment: Vec<EnvBinding>,
    /// Credential declarations, sorted by id, sources absolute.
    pub credentials: Vec<CredentialDecl>,
    /// Raw `network.allow` rules, parsed by the policy layer.
    pub network_allow: Vec<String>,
    /// The identities of every directory from `/` to the file, then the file.
    pub file_chain: Vec<(u64, u64)>,
    /// The canonical path of the file, for diagnostics and the lexical check.
    pub file_path: PathBuf,
}

impl LaunchProfile {
    /// Whether this profile needs a vendor-state directory (§7: "only when a
    /// launch profile requires it").
    #[must_use]
    pub fn needs_vendor_state(&self) -> bool {
        self.state_var.is_some()
            || self.home_is_state
            || !self.state_subdirs.is_empty()
            || !self.credentials.is_empty()
            || self
                .environment
                .iter()
                .any(|binding| matches!(&binding.value, EnvValue::Path(_)))
    }
}

fn invalid(key: impl Into<String>, message: impl Into<String>) -> JailError {
    JailError::new(
        ErrorCode::InvalidConfig,
        ErrorStage::Resolving,
        Remediation::Configuration,
        message.into(),
    )
    .with_key_path(key)
}

fn native(bytes: Vec<u8>, key: &str) -> Result<NativeString, JailError> {
    NativeString::from_bytes(bytes).map_err(|error| invalid(key, error.to_string()))
}

/// Lexically normalizes an absolute path: `.` dropped, `..` pops, and a `..`
/// above the root refuses. A symlink component is refused later by the
/// no-follow walk, so lexical and physical resolution cannot disagree.
fn normalize_absolute(bytes: &[u8], key: &str) -> Result<Vec<u8>, JailError> {
    if !bytes.starts_with(b"/") {
        return Err(invalid(key, "the path is not absolute"));
    }
    if bytes.contains(&0) {
        return Err(invalid(key, "the path contains NUL"));
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in bytes.split(|byte| *byte == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                if parts.pop().is_none() {
                    return Err(invalid(key, "the path escapes `/` with `..`"));
                }
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return Err(invalid(key, "the path names the filesystem root"));
    }
    let mut out = Vec::with_capacity(bytes.len());
    for part in parts {
        out.push(b'/');
        out.extend_from_slice(part);
    }
    Ok(out)
}

fn relative_components(
    text: &str,
    key: &str,
    allow_empty: bool,
) -> Result<Vec<Vec<u8>>, JailError> {
    if text.is_empty() && allow_empty {
        return Ok(Vec::new());
    }
    let components = anchored::split_relative(text.as_bytes()).map_err(|error| {
        invalid(
            key,
            format!("`{text}` is not a relative path beneath vendor state: {error}"),
        )
    })?;
    // Vendor state is attempt-private and removed at settlement, so the
    // protected-path coverage a receipt reports (the workspace's own root
    // literals and the protected segments existing at launch in the scanned
    // roots) does not extend to it, and no placeholder is made there. It is
    // created empty; refusing protected names here keeps it free of any
    // protected segment the profile itself would plant at launch, so there
    // is nothing in it that coverage could be read as describing.
    if let Some(protected) = components.iter().find(|name| {
        crate::profiles::PROTECTED_SEGMENTS
            .iter()
            .any(|segment| segment.as_bytes() == name.as_bytes())
    }) {
        return Err(invalid(
            key,
            format!(
                "`{text}` names the protected segment `{}` inside vendor state",
                String::from_utf8_lossy(protected.as_bytes())
            ),
        ));
    }
    Ok(components
        .iter()
        .map(|name| name.as_bytes().to_vec())
        .collect())
}

fn is_prefix(shorter: &[Vec<u8>], longer: &[Vec<u8>]) -> bool {
    shorter.len() <= longer.len() && longer[..shorter.len()] == shorter[..]
}

/// Parses and validates one launch file's text (§12).
///
/// `base_dir` is the directory holding the file (relative sources resolve
/// against it) and `home` the operator home for a leading `~/`.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] with the exact key path for every grammar or
/// validation failure, and [`ErrorCode::PolicyWidening`] for `jail = "none"`.
pub fn parse(
    text: &str,
    expected_name: &str,
    base_dir: &[u8],
    home: Option<&[u8]>,
) -> Result<LaunchProfile, JailError> {
    let mut file: LaunchFile = toml::from_str(text)
        .map_err(|error| invalid("launch", format!("launch profile: {}", error.message())))?;
    // Launch profiles are a widening layer (the launch `network_layer`
    // forwards grants only), so a declared narrowing key must refuse here
    // rather than parse into silence: the operator would believe a
    // `deny_read` that never applied.
    if file.filesystem.protected_coverage.is_some() || !file.filesystem.deny_read.is_empty() {
        return Err(invalid(
            "launch.filesystem",
            "launch profiles contribute grants only; narrowing belongs to the policy file",
        ));
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fragment {
        #[serde(default)]
        environment: BTreeMap<String, EnvEntry>,
        #[serde(default)]
        filesystem: crate::config::FilesystemSection,
        network: Option<LaunchNetwork>,
    }
    let mut fragments = BTreeSet::new();
    for name in &file.bundles {
        if !fragments.insert(name.clone()) {
            return Err(invalid("launch.bundles", "duplicate fragment"));
        }
        let source = bundled_fragment(name)
            .ok_or_else(|| invalid("launch.bundles", format!("unknown fragment: {name}")))?;
        let fragment: Fragment =
            toml::from_str(source).map_err(|e| invalid("launch.bundles", e.to_string()))?;
        for (key, value) in fragment.environment {
            if file.environment.insert(key.clone(), value).is_some() {
                return Err(invalid(
                    "launch.bundles",
                    format!("conflicting environment binding: {key}"),
                ));
            }
        }
        if fragment.filesystem.protected_coverage.is_some()
            || !fragment.filesystem.deny_read.is_empty()
        {
            return Err(invalid(
                "launch.bundles",
                "fragments contribute grants only",
            ));
        }
        file.filesystem
            .read_only
            .extend(fragment.filesystem.read_only);
        file.filesystem
            .read_write
            .extend(fragment.filesystem.read_write);
        if let Some(network) = fragment.network {
            file.network
                .get_or_insert(LaunchNetwork { allow: Vec::new() })
                .allow
                .extend(network.allow);
        }
    }
    if file
        .filesystem
        .read_only
        .iter()
        .any(|path| file.filesystem.read_write.contains(path))
    {
        return Err(invalid(
            "launch.filesystem",
            "conflicting read-only and writable grants",
        ));
    }
    if file.name != expected_name {
        return Err(invalid(
            "launch.name",
            format!(
                "`name = \"{}\"` does not match the file `{expected_name}.toml`",
                file.name
            ),
        ));
    }
    let jail = match file.jail.as_str() {
        "agent" => ProfileName::Agent,
        "tool" => ProfileName::Tool,
        "build" => ProfileName::Build,
        "none" => {
            // §6.1: `--profile none` is the only way to select `none`.
            return Err(JailError::new(
                ErrorCode::PolicyWidening,
                ErrorStage::Resolving,
                Remediation::Configuration,
                "a launch profile may not select `none`; only `--profile none` does".to_owned(),
            )
            .with_key_path("launch.jail"));
        }
        other => {
            return Err(invalid(
                "launch.jail",
                format!("`{other}` is not a contained built-in profile"),
            ));
        }
    };

    let check_name = |name: &str, key: &str| -> Result<(), JailError> {
        if !valid_env_name(name) {
            return Err(invalid(key, format!("`{name}` is not an environment name")));
        }
        if let Some(reason) = reserved_reason(name) {
            return Err(invalid(key, format!("`{name}` is {reason}")));
        }
        Ok(())
    };

    let state_var = match file.state_var {
        Some(name) => {
            check_name(&name, "launch.state_var")?;
            Some(name)
        }
        None => None,
    };

    // state_subdirs: a set of relative directories, no duplicates.
    let mut subdir_components: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut state_subdirs: Vec<NativeString> = Vec::new();
    let mut seen_subdirs = BTreeSet::new();
    for subdir in &file.state_subdirs {
        let components = relative_components(subdir, "launch.state_subdirs", false)?;
        if !seen_subdirs.insert(components.clone()) {
            return Err(invalid(
                "launch.state_subdirs",
                format!("`{subdir}` is listed twice"),
            ));
        }
        subdir_components.push(components);
        state_subdirs.push(NativeString::Text(subdir.clone()));
    }

    let mut environment: Vec<EnvBinding> = Vec::new();
    for (name, entry) in &file.environment {
        let key = format!("launch.environment.{name}");
        check_name(name, &key)?;
        if state_var.as_deref() == Some(name.as_str()) {
            return Err(invalid(
                &key,
                format!("`{name}` is already the state variable"),
            ));
        }
        let value = match entry {
            EnvEntry::Text(text) => {
                if text.contains('\0') {
                    return Err(invalid(&key, "an environment value may not contain NUL"));
                }
                EnvValue::Native(NativeString::Text(text.clone()))
            }
            EnvEntry::State(reference) => {
                relative_components(&reference.state, &key, true)?;
                EnvValue::Path(PathRef {
                    root: RootToken::VendorState,
                    path: NativeString::Text(reference.state.clone()),
                })
            }
        };
        environment.push(EnvBinding {
            name: name.clone(),
            value,
        });
    }

    let mut credentials: Vec<CredentialDecl> = Vec::new();
    let mut destinations: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
    let mut vault_names = std::collections::BTreeSet::new();
    for (id, entry) in &file.credentials {
        let key = format!("launch.credentials.{id}");
        if !valid_credential_id(id) {
            return Err(invalid(&key, format!("`{id}` is not a credential id")));
        }
        if entry.mode != "copy_rw" && entry.mode != "bind_ro" && entry.mode != "vault" {
            return Err(invalid(
                format!("{key}.mode"),
                format!("`{}` is not `copy_rw`, `bind_ro` or `vault`", entry.mode),
            ));
        }
        let vault = if entry.mode == "vault" {
            if !vault_names.insert(id.to_ascii_uppercase().replace(['.', '-'], "_")) {
                return Err(invalid(
                    &key,
                    "vault ids collide as environment variable names",
                ));
            }
            if !entry.dest.is_empty() {
                return Err(invalid(&key, "vault credentials have no destination file"));
            }
            let policy = crate::vault::Policy {
                hosts: entry.hosts.clone(),
                allow_plaintext: entry.allow_plaintext,
                header: entry.header.as_ref().map(|header| crate::vault::Header {
                    name: header
                        .name
                        .clone()
                        .unwrap_or_else(|| "authorization".to_owned()),
                    prefix: header.prefix.clone(),
                }),
            };
            policy.validate().map_err(|e| invalid(&key, e))?;
            Some(policy)
        } else {
            if !entry.hosts.is_empty() || entry.allow_plaintext || entry.header.is_some() {
                return Err(invalid(
                    &key,
                    "hosts/allow_plaintext/header require vault mode",
                ));
            }
            None
        };
        let destination = if vault.is_some() {
            format!(".vault-{id}")
        } else {
            entry.dest.clone()
        };
        let dest = relative_components(&destination, &format!("{key}.dest"), false)?;
        for (other, other_dest) in &destinations {
            if is_prefix(other_dest, &dest) || is_prefix(&dest, other_dest) {
                return Err(invalid(
                    format!("{key}.dest"),
                    format!("the destination conflicts with credential `{other}`"),
                ));
            }
        }
        for (subdir, components) in file.state_subdirs.iter().zip(&subdir_components) {
            // A subdirectory may contain a credential file; it may not be one,
            // nor lie beneath one.
            if is_prefix(&dest, components) {
                return Err(invalid(
                    "launch.state_subdirs",
                    format!("`{subdir}` conflicts with the destination of credential `{id}`"),
                ));
            }
        }
        destinations.push((id.clone(), dest));

        let source_key = format!("{key}.source");
        let raw = entry.source.as_bytes();
        let expanded: Vec<u8> = if let Some(rest) = raw.strip_prefix(b"~/") {
            let Some(home) = home else {
                return Err(invalid(
                    &source_key,
                    "a `~/` source needs the operator home, which is unavailable",
                ));
            };
            let mut out = home.to_vec();
            out.push(b'/');
            out.extend_from_slice(rest);
            out
        } else if raw.starts_with(b"/") {
            raw.to_vec()
        } else {
            let mut out = base_dir.to_vec();
            out.push(b'/');
            out.extend_from_slice(raw);
            out
        };
        let source = normalize_absolute(&expanded, &source_key)?;
        credentials.push(CredentialDecl {
            id: id.clone(),
            source: native(source, &source_key)?,
            dest: NativeString::Text(destination),
            vault,
            mode: entry.mode.clone(),
        });
    }

    Ok(LaunchProfile {
        name: file.name,
        resolution: "operator file".into(),
        bundles: file.bundles,
        filesystem: file.filesystem,
        jail,
        state_var,
        home_is_state: file.home_is_state,
        state_subdirs,
        environment,
        credentials,
        network_allow: file
            .network
            .map(|network| network.allow)
            .unwrap_or_default(),
        file_chain: Vec::new(),
        file_path: PathBuf::new(),
    })
}

// ---------------------------------------------------------------------------
// Loading the file
// ---------------------------------------------------------------------------

fn unsafe_launch(message: impl Into<String>) -> JailError {
    invalid("--launch", message)
}

/// The directory `--launch NAME` loads profiles from: `<config-dir>/launch`
/// (§6.1). One spelling for the loader and the isolation check, so they can
/// never disagree about what the launch directory is.
#[must_use]
pub fn launch_directory(config_dir: &Path) -> std::path::PathBuf {
    config_dir.join("launch")
}

/// Loads `<config-dir>/launch/<name>.toml` (§6.2, §12).
///
/// The launch directory is an operator location, so its own spelling is
/// resolved (a symlinked `~/.config` is the operator's choice); from `/` down
/// to the file everything is then opened again with a no-follow walk, each
/// directory must be owned by root or this operator and not writable by others
/// without the sticky bit, and the file must be a regular file this operator
/// owns, mode 0600 or stricter, with exactly one link. The identity of every
/// step is kept, so [`check_outside_writable`] can compare by identity rather
/// than by spelling.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] with key `--launch` for a bad name, a missing
/// or unsafe file, and every [`parse`] error.
pub fn load(
    config_dir: &Path,
    name: &str,
    home: Option<&Path>,
) -> Result<LaunchProfile, JailError> {
    if !valid_name(name) {
        return Err(unsafe_launch(format!(
            "`{name}` is not a launch profile name ([a-z][a-z0-9_-]{{0,63}})"
        )));
    }
    let operator_path = launch_directory(config_dir).join(format!("{name}.toml"));
    match operator_path.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(text) = bundled_profile(name) {
                let mut profile = parse(
                    text,
                    name,
                    config_dir.as_os_str().as_bytes(),
                    home.map(|h| h.as_os_str().as_bytes()),
                )?;
                profile.resolution = "bundled".into();
                return Ok(profile);
            }
        }
        Err(e) => return Err(unsafe_launch(e.to_string())),
        Ok(_) => {}
    }
    let directory = launch_directory(config_dir);
    let directory = std::fs::canonicalize(&directory).map_err(|error| {
        unsafe_launch(format!(
            "the launch profile directory {} cannot be resolved: {error}",
            directory.display()
        ))
    })?;
    let file_name = format!("{name}.toml");
    let file_path = directory.join(&file_name);

    let components = anchored::split_absolute(directory.as_os_str().as_bytes())
        .map_err(|error| unsafe_launch(error.to_string()))?;
    let mut chain: Vec<(u64, u64)> = Vec::new();
    let mut current = Dir::open_root_for_walk()
        .map_err(|error| unsafe_launch(format!("`/` cannot be opened: {error}")))?;
    let root_stat = current
        .stat()
        .map_err(|error| unsafe_launch(error.to_string()))?;
    check_launch_directory(&root_stat, Path::new("/"))?;
    chain.push(root_stat.identity());
    let mut walked = PathBuf::from("/");
    for component in &components {
        walked.push(OsStr::from_bytes(component.as_bytes()));
        let stat = current.stat_at(component).map_err(|error| {
            unsafe_launch(format!("{} cannot be inspected: {error}", walked.display()))
        })?;
        if stat.kind != Kind::Directory {
            return Err(unsafe_launch(format!(
                "{} is {}; the launch profile path changed while it was resolved",
                walked.display(),
                stat.kind.describe()
            )));
        }
        check_launch_directory(&stat, &walked)?;
        current = current
            .open_walk_at(component, Some(&stat))
            .map_err(|error| {
                unsafe_launch(format!("{} cannot be opened: {error}", walked.display()))
            })?;
        chain.push(stat.identity());
    }

    let entry = anchored::Name::new(file_name.as_bytes())
        .map_err(|error| unsafe_launch(error.to_string()))?;
    let stat = match current.stat_at(&entry) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(unsafe_launch(format!(
                "there is no launch profile {}",
                file_path.display()
            )));
        }
        Err(error) => {
            return Err(unsafe_launch(format!(
                "{} cannot be inspected: {error}",
                file_path.display()
            )));
        }
    };
    if stat.kind != Kind::Regular {
        return Err(unsafe_launch(format!(
            "{} is {}; a launch profile must be a regular file",
            file_path.display(),
            stat.kind.describe()
        )));
    }
    // On Linux the walk handle is `O_PATH`, which `openat` accepts as an
    // anchor; the file itself is opened for reading, never followed.
    let file = current.open_read_at(&entry, Some(&stat)).map_err(|error| {
        unsafe_launch(format!("{} cannot be opened: {error}", file_path.display()))
    })?;
    let opened = anchored::fstat(std::os::fd::AsFd::as_fd(&file))
        .map_err(|error| unsafe_launch(error.to_string()))?;
    if opened.identity() != stat.identity() || opened.kind != Kind::Regular {
        return Err(unsafe_launch(format!(
            "{} was replaced while it was opened",
            file_path.display()
        )));
    }
    crate::state::check_ownership(&file_path, opened.uid, opened.mode, 0o600).map_err(|error| {
        unsafe_launch(format!(
            "a launch profile must be operator-owned, mode 0600: {}",
            error.message
        ))
    })?;
    if opened.nlink != 1 {
        return Err(unsafe_launch(format!(
            "{} has {} hard links; another name for it could lie inside a child-writable grant",
            file_path.display(),
            opened.nlink
        )));
    }
    if opened.size > LAUNCH_FILE_MAX {
        return Err(unsafe_launch(format!(
            "{} is {} bytes; the maximum is {LAUNCH_FILE_MAX}",
            file_path.display(),
            opened.size
        )));
    }
    let mut bytes = Vec::new();
    file.take(LAUNCH_FILE_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| unsafe_launch(format!("{}: {error}", file_path.display())))?;
    if bytes.len() as u64 > LAUNCH_FILE_MAX {
        return Err(unsafe_launch(format!(
            "{} grew past {LAUNCH_FILE_MAX} bytes while it was read",
            file_path.display()
        )));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| unsafe_launch(format!("{} is not UTF-8", file_path.display())))?;
    chain.push(opened.identity());

    let mut profile = parse(
        &text,
        name,
        directory.as_os_str().as_bytes(),
        home.map(|home| home.as_os_str().as_bytes()),
    )?;
    profile.file_chain = chain;
    profile.file_path = file_path;
    Ok(profile)
}

fn check_launch_directory(stat: &anchored::Stat, path: &Path) -> Result<(), JailError> {
    let euid = crate::state::effective_uid();
    if stat.uid != 0 && stat.uid != euid {
        return Err(unsafe_launch(format!(
            "{} is owned by uid {}, neither root nor this operator",
            path.display(),
            stat.uid
        )));
    }
    if crate::state::writable_by_others(stat.mode, stat.uid, stat.gid) && stat.mode & 0o1000 == 0 {
        return Err(unsafe_launch(format!(
            "{} has mode {:04o}: writable by others without the sticky bit",
            path.display(),
            stat.mode
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// §6.1: whether the base profile permits this launch profile.
///
/// "An explicit contained profile may override a launch default only when its
/// requirements still permit that launch profile's credentials/network.
/// `tool` and `build` reject launch credentials and proxy grants." The same
/// rule holds when the launch profile names `tool` or `build` itself. `none`
/// never runs a launch profile.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] naming the rejected key.
pub fn check_jail_permits(base: ProfileName, launch: &LaunchProfile) -> Result<(), JailError> {
    if base == ProfileName::None {
        return Err(JailError::new(
            ErrorCode::PolicyWidening,
            ErrorStage::Resolving,
            Remediation::Configuration,
            "a launch profile runs under a contained profile; `none` does not stage vendor state \
             or credentials"
                .to_owned(),
        )
        .with_key_path("--launch"));
    }
    if base != ProfileName::Agent && !launch.credentials.is_empty() {
        return Err(invalid(
            "launch.credentials",
            format!(
                "the `{}` profile rejects launch credentials (jail-v1 §6.1); only `agent` stages \
                 them",
                base.as_str()
            ),
        ));
    }
    if base != ProfileName::Agent && !launch.network_allow.is_empty() {
        return Err(invalid(
            "launch.network.allow",
            format!(
                "the `{}` profile rejects proxy grants (jail-v1 §6.1); only `agent` has a proxy",
                base.as_str()
            ),
        ));
    }
    Ok(())
}

/// The §6.2 step-2 layer: the launch profile's allowed hosts.
#[must_use]
pub fn network_layer(launch: &LaunchProfile) -> Option<Layer> {
    if launch.network_allow.is_empty()
        && launch.filesystem.read_only.is_empty()
        && launch.filesystem.read_write.is_empty()
    {
        return None;
    }
    Some(Layer {
        origin: LayerOrigin::LaunchProfile(launch.name.clone()),
        base_dir: launch
            .file_path
            .parent()
            .map(|parent| parent.as_os_str().as_bytes().to_vec()),
        key_prefix: "launch.".to_owned(),
        narrowing: false,
        delta: PolicyDelta {
            read_only: launch
                .filesystem
                .read_only
                .iter()
                .map(|p| p.as_bytes().to_vec())
                .collect(),
            read_write: launch
                .filesystem
                .read_write
                .iter()
                .map(|p| p.as_bytes().to_vec())
                .collect(),
            network_allow: launch.network_allow.clone(),
            network_allow_present: true,
            ..PolicyDelta::default()
        },
    })
}

/// Adds the launch profile's environment, vendor state and `launch` field
/// group to a resolved policy, then recomputes its digest and requirements.
///
/// The environment bindings join the baseline's (names are unique; §12's
/// reserved names were refused by [`parse`]). `state_var` and `home_is_state`
/// bind to the vendor-state root reference, never to a host path. Vendor
/// state becomes a managed root and a writable reference only when the
/// profile needs it.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] for a duplicate environment name, and the
/// canonicalization errors of the snapshot digest.
pub fn apply(mut resolved: Resolved, launch: &LaunchProfile) -> Result<Resolved, JailError> {
    let origin = format!("launch-profile:{}", launch.name);
    resolved.provenance.push(ProvenanceEntry {
        origin: origin.clone(),
        key: "launch.resolution".into(),
        detail: Some(
            if launch.resolution == "operator file" && bundled_profile(&launch.name).is_some() {
                "operator file (shadows bundled)".into()
            } else {
                launch.resolution.clone()
            },
        ),
    });
    for bundle in &launch.bundles {
        resolved.provenance.push(ProvenanceEntry {
            origin: origin.clone(),
            key: "launch.bundles".into(),
            detail: Some(bundle.clone()),
        });
    }
    let snapshot = &mut resolved.snapshot;
    let vendor_root = PathRef {
        root: RootToken::VendorState,
        path: NativeString::Text(String::new()),
    };
    let mut names: BTreeSet<String> = snapshot
        .environment
        .bindings
        .iter()
        .map(|binding| binding.name.clone())
        .collect();
    let mut additions: Vec<EnvBinding> = Vec::new();
    if let Some(name) = &launch.state_var {
        additions.push(EnvBinding {
            name: name.clone(),
            value: EnvValue::Path(vendor_root.clone()),
        });
    }
    if launch.home_is_state {
        additions.push(EnvBinding {
            name: "HOME".to_owned(),
            value: EnvValue::Path(vendor_root.clone()),
        });
    }
    additions.extend(launch.environment.iter().cloned());
    for binding in additions {
        if !names.insert(binding.name.clone()) {
            return Err(invalid(
                format!("launch.environment.{}", binding.name),
                format!("`{}` is already bound", binding.name),
            ));
        }
        resolved.provenance.push(ProvenanceEntry {
            origin: origin.clone(),
            key: format!("environment.bindings.{}", binding.name),
            detail: None,
        });
        snapshot.environment.bindings.push(binding);
    }
    snapshot
        .environment
        .bindings
        .sort_by(|left, right| left.name.cmp(&right.name));

    if launch.needs_vendor_state() {
        snapshot.roots.vendor_state = Some(VendorStateRoot::Managed);
        if !snapshot.filesystem.read_write.contains(&vendor_root) {
            snapshot.filesystem.read_write.push(vendor_root);
        }
    }
    let mut credentials = launch.credentials.clone();
    credentials.sort_by(|left, right| left.id.cmp(&right.id));
    for credential in &credentials {
        resolved.provenance.push(ProvenanceEntry {
            origin: origin.clone(),
            key: format!("launch.credentials.{}", credential.id),
            detail: Some(credential.mode.clone()),
        });
    }
    snapshot.launch = Some(LaunchSnapshot {
        state_var: launch.state_var.clone(),
        home_is_state: launch.home_is_state,
        state_subdirs: launch.state_subdirs.clone(),
        credentials,
    });
    resolved.provenance.push(ProvenanceEntry {
        origin,
        key: "launch".to_owned(),
        detail: Some(launch.name.clone()),
    });
    resolved.digest = resolved.snapshot.digest()?;
    resolved.requirements = crate::capability::requirements(&resolved.snapshot);
    Ok(resolved)
}

/// Refuses a launch profile inside any child-writable grant, or inside the
/// workspace (§12, north star §4.5).
///
/// Compared by identity against every directory on the file's no-follow
/// walk, including other mountpoints of the same writable filesystem tree.
/// A root that does not exist yet cannot contain the file.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] at key `--launch`.
pub fn check_outside_writable(launch: &LaunchProfile, roots: &[PathBuf]) -> Result<(), JailError> {
    if launch.resolution == "bundled" {
        return Ok(());
    }
    let forbidden = crate::state::mount_alias::forbidden_identities(roots)
        .map_err(|error| unsafe_launch(format!("writable grants cannot be inspected: {error}")))?;
    for root in roots {
        let lexical = std::fs::canonicalize(root)
            .ok()
            .is_some_and(|canonical| launch.file_path.starts_with(canonical));
        if lexical {
            return Err(unsafe_launch(format!(
                "the launch profile {} lies inside the child-visible grant {}; the contained \
                 party could rewrite its own authority (the workspace defaults to the \
                 current directory; run from the project directory or pass --workspace)",
                launch.file_path.display(),
                root.display()
            )));
        }
    }
    if launch
        .file_chain
        .iter()
        .any(|identity| forbidden.contains(identity))
    {
        return Err(unsafe_launch(format!(
            "the launch profile {} lies inside a child-visible writable grant, possibly through \
             a bind mount; the contained party could rewrite its own authority",
            launch.file_path.display()
        )));
    }
    Ok(())
}

#[path = "../profiles/embedded.rs"]
mod embedded;
use embedded::bundled_fragment;
pub use embedded::bundled_profile;

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &[u8] = b"/operator/config/launch";

    fn parse_ok(text: &str) -> LaunchProfile {
        parse(text, "demo", BASE, Some(b"/home/op")).expect("valid launch profile")
    }

    fn parse_err(text: &str) -> JailError {
        match parse(text, "demo", BASE, Some(b"/home/op")) {
            Ok(profile) => panic!("expected a refusal, got {profile:?}"),
            Err(error) => error,
        }
    }

    /// The audit: no test parsed `mode = "vault"`. A valid vault credential
    /// parses to the expected declaration; every invalid shape refuses.
    #[test]
    fn vault_credentials_parse_and_invalid_shapes_refuse() {
        let profile = parse_ok(
            r#"
name = "demo"
jail = "agent"
[credentials.api]
source = "/home/op/token"
mode = "vault"
hosts = ["https://api.example.com"]
header = { name = "x-api-key" }
"#,
        );
        let credential = profile
            .credentials
            .iter()
            .find(|credential| credential.id == "api")
            .expect("the vault credential parses");
        assert_eq!(credential.mode, "vault");
        assert_eq!(credential.dest.as_bytes(), b".vault-api");
        let vault = credential
            .vault
            .as_ref()
            .expect("vault mode carries a policy");
        assert_eq!(vault.hosts, vec!["https://api.example.com".to_owned()]);
        assert!(!vault.allow_plaintext);
        assert_eq!(
            vault.header.as_ref().map(|header| header.name.as_str()),
            Some("x-api-key")
        );

        // A Bearer prefix placement parses with its default header name.
        let profile = parse_ok(
            r#"
name = "demo"
jail = "agent"
[credentials.api]
source = "/home/op/token"
mode = "vault"
hosts = ["https://api.example.com"]
header = { prefix = "Bearer " }
"#,
        );
        let vault = profile
            .credentials
            .iter()
            .find(|credential| credential.id == "api")
            .and_then(|credential| credential.vault.as_ref())
            .expect("the vault credential parses");
        assert_eq!(
            vault.header.as_ref().map(|h| h.name.as_str()),
            Some("authorization")
        );
        assert_eq!(
            vault.header.as_ref().and_then(|h| h.prefix.as_deref()),
            Some("Bearer ")
        );

        // A header outside vault mode refuses.
        let error = parse_err(
            r#"
name = "demo"
jail = "agent"
[credentials.api]
source = "/home/op/token"
mode = "copy_rw"
dest = "token"
header = { name = "x-api-key" }
"#,
        );
        assert_eq!(error.key_path.as_deref(), Some("launch.credentials.api"));
        assert!(error.message.contains("header"), "{}", error.message);

        // An invalid header name refuses with the validation message.
        let error = parse_err(
            r#"
name = "demo"
jail = "agent"
[credentials.api]
source = "/home/op/token"
mode = "vault"
hosts = ["https://api.example.com"]
header = { name = "bad header" }
"#,
        );
        assert!(error.message.contains("token"), "{}", error.message);

        // An unknown mode string refuses.
        let error = parse_err(
            r#"
name = "demo"
jail = "agent"
[credentials.api]
source = "/home/op/token"
mode = "carrier"
"#,
        );
        assert_eq!(
            error.key_path.as_deref(),
            Some("launch.credentials.api.mode")
        );

        // Vault credentials need hosts.
        let error = parse_err(
            r#"
name = "demo"
jail = "agent"
[credentials.api]
source = "/home/op/token"
mode = "vault"
"#,
        );
        assert_eq!(error.key_path.as_deref(), Some("launch.credentials.api"));
        assert!(error.message.contains("1..64"), "{}", error.message);

        // Plaintext hosts still need the allow_plaintext opt-in.
        let error = parse_err(
            r#"
name = "demo"
jail = "agent"
[credentials.api]
source = "/home/op/token"
mode = "vault"
hosts = ["http://api.example.com"]
"#,
        );
        assert_eq!(error.key_path.as_deref(), Some("launch.credentials.api"));
        assert!(
            error.message.contains("allow_plaintext"),
            "{}",
            error.message
        );

        // Vault credentials take no destination file.
        let error = parse_err(
            r#"
name = "demo"
jail = "agent"
[credentials.api]
source = "/home/op/token"
mode = "vault"
hosts = ["https://api.example.com"]
dest = "token"
"#,
        );
        assert_eq!(error.key_path.as_deref(), Some("launch.credentials.api"));
        assert!(
            error.message.contains("no destination file"),
            "{}",
            error.message
        );

        // Hosts outside vault mode refuse rather than dropping silently.
        let error = parse_err(
            r#"
name = "demo"
jail = "agent"
[credentials.api]
source = "/home/op/token"
dest = "token"
mode = "copy_rw"
hosts = ["https://api.example.com"]
"#,
        );
        assert_eq!(error.key_path.as_deref(), Some("launch.credentials.api"));
        assert!(
            error.message.contains("require vault mode"),
            "{}",
            error.message
        );
    }

    #[test]
    fn filesystem_narrowing_keys_refuse_rather_than_parse_into_silence() {
        let error = parse_err(
            r#"
name = "demo"
jail = "agent"
[filesystem]
read_only = ["/usr"]
deny_read = ["/etc/shadow"]
"#,
        );
        assert_eq!(error.key_path.as_deref(), Some("launch.filesystem"));
        let error = parse_err(
            r#"
name = "demo"
jail = "agent"
[filesystem]
protected_coverage = "/usr"
"#,
        );
        assert_eq!(error.key_path.as_deref(), Some("launch.filesystem"));
    }

    #[test]
    fn a_complete_profile_resolves_sources_and_sorts_nothing_it_should_not() {
        let profile = parse_ok(
            r#"
name = "demo"
jail = "agent"
state_var = "DEMO_HOME"
home_is_state = true
state_subdirs = ["cfg/sub", "data"]
[environment]
DEMO_MODE = "batch"
DEMO_DATA = { state = "data" }
[credentials.auth]
source = "~/.demo/auth.json"
dest = "auth.json"
mode = "copy_rw"
[credentials.cfg]
source = "cfg.toml"
dest = "cfg/cfg.toml"
mode = "bind_ro"
[network]
allow = ["api.example.com:443"]
"#,
        );
        assert_eq!(profile.jail, ProfileName::Agent);
        assert_eq!(
            profile.credentials[0].source.as_bytes(),
            b"/home/op/.demo/auth.json"
        );
        assert_eq!(
            profile.credentials[1].source.as_bytes(),
            b"/operator/config/launch/cfg.toml"
        );
        assert!(profile.needs_vendor_state());
        assert_eq!(profile.network_allow, vec!["api.example.com:443"]);
    }

    #[test]
    fn every_loader_and_backend_name_refuses() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "ld_audit",
            "DYLD_INSERT_LIBRARIES",
            "dyld_library_path",
            "OURO_TOKEN",
            "GLIBC_TUNABLES",
            "GCONV_PATH",
            "MALLOC_CHECK_",
            "HTTPS_PROXY",
            "https_proxy",
            "PATH",
            "TMPDIR",
            "HOME",
        ] {
            let error = parse_err(&format!(
                "name = \"demo\"\njail = \"tool\"\n[environment]\n{name} = \"x\"\n"
            ));
            assert_eq!(error.code, ErrorCode::InvalidConfig, "{name}");
            assert_eq!(
                error.key_path.as_deref(),
                Some(format!("launch.environment.{name}").as_str())
            );
            let error = parse_err(&format!(
                "name = \"demo\"\njail = \"tool\"\nstate_var = \"{name}\"\n"
            ));
            assert_eq!(
                error.key_path.as_deref(),
                Some("launch.state_var"),
                "{name}"
            );
        }
    }

    #[test]
    fn unsafe_state_subdirs_and_conflicts_refuse() {
        for subdirs in [
            r#"[""]"#,
            r#"["/abs"]"#,
            r#"["a/../b"]"#,
            r#"["./a"]"#,
            r#"["a//b"]"#,
            r#"["a/"]"#,
            r#"["a", "a"]"#,
            r#"["auth.json"]"#,
            r#"["auth.json/inner"]"#,
            r#"["a/.git"]"#,
            r#"[".ouroboros"]"#,
        ] {
            let error = parse_err(&format!(
                "name = \"demo\"\njail = \"agent\"\nstate_subdirs = {subdirs}\n\
                 [credentials.auth]\nsource = \"/c/a\"\ndest = \"auth.json\"\nmode = \"copy_rw\"\n"
            ));
            assert_eq!(error.code, ErrorCode::InvalidConfig, "{subdirs}");
        }
    }

    #[test]
    fn destinations_must_be_relative_and_disjoint() {
        for (first, second) in [
            ("a", "a"),
            ("a", "a/b"),
            ("../a", "b"),
            ("/abs", "b"),
            ("a/./b", "c"),
        ] {
            let error = parse_err(&format!(
                "name = \"demo\"\njail = \"agent\"\n\
                 [credentials.one]\nsource = \"/c/1\"\ndest = \"{first}\"\nmode = \"copy_rw\"\n\
                 [credentials.two]\nsource = \"/c/2\"\ndest = \"{second}\"\nmode = \"bind_ro\"\n"
            ));
            assert_eq!(error.code, ErrorCode::InvalidConfig, "{first} {second}");
        }
    }

    #[test]
    fn the_grammar_refuses_argv_none_unknown_keys_and_commands() {
        for text in [
            "name = \"demo\"\njail = \"none\"\n",
            "name = \"other\"\njail = \"tool\"\n",
            "name = \"demo\"\njail = \"tool\"\nargv = [\"x\"]\n",
            "name = \"demo\"\njail = \"tool\"\ncommand = \"x\"\n",
            "name = \"demo\"\njail = \"tool\"\n[environment]\nA = [\"sh\", \"-c\"]\n",
            "name = \"demo\"\njail = \"tool\"\n[environment]\nA = { run = \"x\" }\n",
            "name = \"demo\"\njail = \"tool\"\n[environment]\nA = 1\n",
            "name = \"demo\"\njail = \"tool\"\nname = \"demo\"\n",
            "name = \"demo\"\njail = \"custom.toml\"\n",
        ] {
            let error = parse_err(text);
            assert!(
                matches!(
                    error.code,
                    ErrorCode::InvalidConfig | ErrorCode::PolicyWidening
                ),
                "{text}: {error:?}"
            );
        }
    }

    #[test]
    fn tool_and_build_reject_credentials_and_proxy_grants_and_none_rejects_all() {
        let with_credentials = parse_ok(
            "name = \"demo\"\njail = \"agent\"\n[credentials.a]\nsource = \"/c/a\"\ndest = \"a\"\nmode = \"copy_rw\"\n",
        );
        let with_hosts =
            parse_ok("name = \"demo\"\njail = \"agent\"\n[network]\nallow = [\"a.example:443\"]\n");
        let plain = parse_ok("name = \"demo\"\njail = \"tool\"\nstate_var = \"X_HOME\"\n");
        for base in [ProfileName::Tool, ProfileName::Build] {
            assert_eq!(
                check_jail_permits(base, &with_credentials)
                    .unwrap_err()
                    .key_path
                    .as_deref(),
                Some("launch.credentials")
            );
            assert_eq!(
                check_jail_permits(base, &with_hosts)
                    .unwrap_err()
                    .key_path
                    .as_deref(),
                Some("launch.network.allow")
            );
            assert!(check_jail_permits(base, &plain).is_ok());
        }
        assert!(check_jail_permits(ProfileName::Agent, &with_credentials).is_ok());
        assert!(check_jail_permits(ProfileName::None, &plain).is_err());
    }

    #[test]
    fn names_follow_their_grammars() {
        assert!(valid_name("demo-1_x"));
        for bad in ["", "Demo", "1demo", "de/mo", "de.mo", &"a".repeat(65)] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert!(valid_credential_id("auth.json"));
        assert!(!valid_credential_id(".hidden"));
        assert!(valid_env_name("A_1"));
        assert!(!valid_env_name("1A"));
        assert!(!valid_env_name("A-B"));
        assert!(!valid_env_name("A=B"));
    }
}
