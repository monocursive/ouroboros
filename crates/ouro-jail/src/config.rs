//! Configuration files, the environment allow-list and limit parsing.
//!
//! Implements jail-v1 §6.2 (paths and precedence), the file keys of §6.3 and
//! the limit grammar of §6.4.
//!
//! Unknown keys refuse rather than being ignored, so a future policy key can
//! never be silently dropped by an older binary. Duplicate keys refuse because
//! TOML itself forbids them and the parser reports them; a test pins that.
//! Only the four documented environment variables are read; every other
//! `OURO_*` name is ignored, so a submitter cannot smuggle authority in.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

use serde::Deserialize;

use crate::network::NetworkMode;
use crate::policy::{Ceiling, Ceilings, LimitKey, PolicyDelta, ProtectedCoverage};
use crate::records::{
    ErrorCode, ErrorStage, EvidenceMode, JailError, ObserveMode, Remediation, SCHEMA_POLICY,
};

/// The documented environment allow-list (§6.2 step 3).
pub const ENVIRONMENT_ALLOW_LIST: &[&str] = &[
    "OURO_CONFIG_DIR",
    "OURO_DATA_DIR",
    "OURO_JAIL_OBSERVE",
    "OURO_JAIL_EVIDENCE",
];

fn invalid(key: &str, message: impl Into<String>) -> JailError {
    JailError::new(
        ErrorCode::InvalidConfig,
        ErrorStage::Resolving,
        Remediation::Configuration,
        message.into(),
    )
    .with_key_path(key)
}

/// A TOML scalar that may be written as an integer or as a string with a unit.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(untagged)]
pub enum Scalar {
    /// An integer literal.
    Integer(i64),
    /// A string literal, possibly carrying a unit.
    Text(String),
}

impl Scalar {
    fn as_text(&self) -> String {
        match self {
            Scalar::Integer(value) => value.to_string(),
            Scalar::Text(text) => text.clone(),
        }
    }
}

/// `[filesystem]` in a policy file.
#[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSection {
    /// `filesystem.read_write`.
    #[serde(default)]
    pub read_write: Vec<String>,
    /// `filesystem.read_only`.
    #[serde(default)]
    pub read_only: Vec<String>,
    /// `filesystem.deny_read`.
    #[serde(default)]
    pub deny_read: Vec<String>,
    /// `filesystem.protected_coverage`.
    pub protected_coverage: Option<String>,
}

/// `[network]` in a policy file.
#[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    /// `network.mode`.
    pub mode: Option<String>,
    /// `network.allow`.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// `[limits]` in a policy file.
#[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    /// `limits.wall`.
    pub wall: Option<Scalar>,
    /// `limits.pids`.
    pub pids: Option<Scalar>,
    /// `limits.mem`.
    pub mem: Option<Scalar>,
    /// `limits.cpu`.
    pub cpu: Option<Scalar>,
}

/// `[observation]` in a policy file.
#[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSection {
    /// `observation.mode`.
    pub mode: Option<String>,
    /// `observation.evidence`.
    pub evidence: Option<String>,
}

/// A selected operator profile file (§6.3). `extends` is required.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Must be `ouro.jail.policy/1`.
    pub schema: String,
    /// Exactly one built-in contained profile.
    pub extends: String,
    /// Filesystem keys.
    #[serde(default)]
    pub filesystem: FilesystemSection,
    /// Network keys.
    #[serde(default)]
    pub network: NetworkSection,
    /// Limit keys.
    #[serde(default)]
    pub limits: LimitsSection,
    /// Observation keys.
    #[serde(default)]
    pub observation: ObservationSection,
}

/// The `[jail]` table shared by `config.toml` and a project `ouro.toml`.
#[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailSection {
    /// `jail.schema`.
    pub schema: Option<String>,
    /// `jail.profile`: a built-in name or an operator profile file path.
    /// Forbidden in a project file.
    pub profile: Option<String>,
    /// `jail.extends`: forbidden in a project file and in `config.toml`.
    pub extends: Option<String>,
    /// Filesystem keys.
    #[serde(default)]
    pub filesystem: FilesystemSection,
    /// Network keys.
    #[serde(default)]
    pub network: NetworkSection,
    /// Limit keys.
    #[serde(default)]
    pub limits: LimitsSection,
    /// Observation keys.
    #[serde(default)]
    pub observation: ObservationSection,
}

/// `[jail_host.network]`: host configuration, forbidden in project files.
#[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailHostNetwork {
    /// Canonical IPv6 CIDRs of the provisioned network.
    #[serde(default)]
    pub translation_prefixes: Vec<String>,
}

/// `[jail_host]`.
#[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailHostSection {
    /// Network host configuration.
    pub network: Option<JailHostNetwork>,
}

/// The operator's `config.toml`.
#[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorConfig {
    /// Jail defaults.
    pub jail: Option<JailSection>,
    /// Host configuration.
    pub jail_host: Option<JailHostSection>,
}

/// The workspace-root `ouro.toml`.
#[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    /// The project's narrowing section.
    pub jail: Option<JailSection>,
}

/// Parses a selected operator profile file.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for a syntax error, an unknown key, a
/// duplicate key or a wrong `schema` value.
pub fn parse_policy_file(text: &str) -> Result<PolicyFile, JailError> {
    let file: PolicyFile =
        toml::from_str(text).map_err(|error| invalid("profile", error.message().to_owned()))?;
    if file.schema != SCHEMA_POLICY {
        return Err(invalid(
            "schema",
            format!("expected schema `{SCHEMA_POLICY}`, found `{}`", file.schema),
        ));
    }
    Ok(file)
}

/// Parses the operator's `config.toml`.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for a syntax error, an unknown key or a
/// duplicate key.
pub fn parse_operator_config(text: &str) -> Result<OperatorConfig, JailError> {
    toml::from_str(text).map_err(|error| invalid("config", error.message().to_owned()))
}

/// Parses a project `ouro.toml`.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for a syntax error, an unknown key or a
/// duplicate key.
pub fn parse_project_config(text: &str) -> Result<ProjectConfig, JailError> {
    toml::from_str(text).map_err(|error| invalid("jail", error.message().to_owned()))
}

/// Builds the semantic delta of a policy file's body.
///
/// `prefix` is the key-path prefix used when reporting an exact key path, so a
/// project file reports `jail.limits.wall` and a profile file `limits.wall`.
/// `explicit_required` marks every ceiling this layer sets as required (§6.4:
/// "Every explicit limit from CLI, operator or project config is required").
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for an unparsable value.
pub fn delta_from_sections(
    prefix: &str,
    filesystem: &FilesystemSection,
    network: &NetworkSection,
    limits: &LimitsSection,
    observation: &ObservationSection,
) -> Result<PolicyDelta, JailError> {
    let mut delta = PolicyDelta {
        read_write: filesystem
            .read_write
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect(),
        read_only: filesystem
            .read_only
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect(),
        deny_read: filesystem
            .deny_read
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect(),
        ..PolicyDelta::default()
    };
    if let Some(coverage) = &filesystem.protected_coverage {
        delta.protected_coverage = Some(ProtectedCoverage::parse(coverage).ok_or_else(|| {
            invalid(
                &format!("{prefix}filesystem.protected_coverage"),
                format!("unknown protected coverage `{coverage}`"),
            )
        })?);
    }
    if let Some(mode) = &network.mode {
        delta.network_mode = Some(match mode.as_str() {
            "none" => NetworkMode::None,
            "proxy" => NetworkMode::Proxy,
            "host" => NetworkMode::Host,
            other => {
                return Err(invalid(
                    &format!("{prefix}network.mode"),
                    format!("unknown network mode `{other}`"),
                ));
            }
        });
    }
    delta.network_allow = network.allow.clone();
    delta.limits = ceilings_from_section(prefix, limits, true)?;
    if let Some(mode) = &observation.mode {
        delta.observe = Some(parse_observe(&format!("{prefix}observation.mode"), mode)?);
    }
    if let Some(evidence) = &observation.evidence {
        delta.evidence = Some(parse_evidence(
            &format!("{prefix}observation.evidence"),
            evidence,
        )?);
    }
    Ok(delta)
}

/// Parses every ceiling a `[limits]` section sets.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for a zero, negative, unbounded,
/// overflowing or unknown value.
pub fn ceilings_from_section(
    prefix: &str,
    limits: &LimitsSection,
    required: bool,
) -> Result<Ceilings, JailError> {
    let mut out = Ceilings::default();
    for (key, scalar) in [
        (LimitKey::Wall, &limits.wall),
        (LimitKey::Pids, &limits.pids),
        (LimitKey::Mem, &limits.mem),
        (LimitKey::Cpu, &limits.cpu),
    ] {
        let Some(scalar) = scalar else { continue };
        let text = scalar.as_text();
        let key_path = format!("{prefix}limits.{}", key.as_str());
        let value = parse_limit_value(&key_path, key, &text)?;
        let ceiling = Some(Ceiling {
            value,
            requested: text,
            required,
        });
        match key {
            LimitKey::Wall => out.wall = ceiling,
            LimitKey::Pids => out.pids = ceiling,
            LimitKey::Mem => out.mem = ceiling,
            LimitKey::Cpu => out.cpu = ceiling,
        }
    }
    Ok(out)
}

/// Parses one `--limit KEY=VALUE` argument list into ceilings.
///
/// Duplicate keys refuse (§6.4).
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for an unknown key, a duplicate key or
/// an unparsable value.
pub fn ceilings_from_cli(arguments: &[String]) -> Result<Ceilings, JailError> {
    let mut out = Ceilings::default();
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    for argument in arguments {
        let Some((key, value)) = argument.split_once('=') else {
            return Err(invalid("--limit", format!("`{argument}` is not KEY=VALUE")));
        };
        let Some(limit) = LimitKey::parse(key) else {
            return Err(invalid(
                "--limit",
                format!("unknown limit key `{key}`; expected wall, pids, mem or cpu"),
            ));
        };
        if !seen.insert(limit.as_str()) {
            return Err(invalid(
                &format!("--limit {}", limit.as_str()),
                format!("`{}` is supplied more than once", limit.as_str()),
            ));
        }
        let key_path = format!("--limit {}", limit.as_str());
        let parsed = parse_limit_value(&key_path, limit, value)?;
        let ceiling = Some(Ceiling {
            value: parsed,
            requested: value.to_owned(),
            required: true,
        });
        match limit {
            LimitKey::Wall => out.wall = ceiling,
            LimitKey::Pids => out.pids = ceiling,
            LimitKey::Mem => out.mem = ceiling,
            LimitKey::Cpu => out.cpu = ceiling,
        }
    }
    Ok(out)
}

/// Parses one limit value in its key's grammar (§6.4).
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for a zero, negative, unbounded,
/// overflowing or unknown value.
pub fn parse_limit_value(key_path: &str, key: LimitKey, text: &str) -> Result<u64, JailError> {
    match key {
        LimitKey::Wall => parse_scaled(
            key_path,
            text,
            &[("ms", 1), ("s", 1000), ("m", 60_000), ("h", 3_600_000)],
            true,
        ),
        LimitKey::Mem => parse_scaled(
            key_path,
            text,
            &[
                ("KiB", 1024),
                ("MiB", 1024 * 1024),
                ("GiB", 1024 * 1024 * 1024),
            ],
            false,
        ),
        LimitKey::Pids | LimitKey::Cpu => parse_scaled(key_path, text, &[], false),
    }
}

/// Parses `<digits><unit>` with checked multiplication.
///
/// The units are tried longest-first so `ms` is not read as `m` followed by a
/// stray `s`. `unit_required` is true for `wall`, whose grammar has no bare
/// integer form.
fn parse_scaled(
    key_path: &str,
    text: &str,
    units: &[(&str, u64)],
    unit_required: bool,
) -> Result<u64, JailError> {
    let trimmed = text.trim();
    let mut sorted: Vec<&(&str, u64)> = units.iter().collect();
    sorted.sort_by_key(|(unit, _)| std::cmp::Reverse(unit.len()));
    let (digits, multiplier) = match sorted
        .iter()
        .find(|(unit, _)| trimmed.len() > unit.len() && trimmed.ends_with(unit))
    {
        Some((unit, multiplier)) => (&trimmed[..trimmed.len() - unit.len()], *multiplier),
        None => {
            if unit_required {
                return Err(invalid(
                    key_path,
                    format!("`{text}` needs one of the units ms, s, m or h"),
                ));
            }
            (trimmed, 1)
        }
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(
            key_path,
            format!("`{text}` is not a positive integer with an accepted unit"),
        ));
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(invalid(key_path, format!("`{text}` has a leading zero")));
    }
    let base: u64 = digits
        .parse()
        .map_err(|_| invalid(key_path, format!("`{text}` does not fit in 64 bits")))?;
    if base == 0 {
        return Err(invalid(
            key_path,
            format!("`{text}` is zero; a ceiling must be positive"),
        ));
    }
    base.checked_mul(multiplier)
        .ok_or_else(|| invalid(key_path, format!("`{text}` overflows 64 bits")))
}

/// Parses `observation.mode`.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for an unknown value.
pub fn parse_observe(key_path: &str, text: &str) -> Result<ObserveMode, JailError> {
    match text {
        "on" => Ok(ObserveMode::On),
        "off" => Ok(ObserveMode::Off),
        other => Err(invalid(
            key_path,
            format!("unknown observation mode `{other}`; expected on or off"),
        )),
    }
}

/// Parses `observation.evidence`.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for an unknown value.
pub fn parse_evidence(key_path: &str, text: &str) -> Result<EvidenceMode, JailError> {
    match text {
        "strict" => Ok(EvidenceMode::Strict),
        "best-effort" => Ok(EvidenceMode::BestEffort),
        other => Err(invalid(
            key_path,
            format!("unknown evidence mode `{other}`; expected strict or best-effort"),
        )),
    }
}

/// The operator settings read from the environment allow-list (§6.2 step 3).
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct EnvSettings {
    /// `OURO_CONFIG_DIR`.
    pub config_dir: Option<PathBuf>,
    /// `OURO_DATA_DIR`.
    pub data_dir: Option<PathBuf>,
    /// `OURO_JAIL_OBSERVE`.
    pub observe: Option<ObserveMode>,
    /// `OURO_JAIL_EVIDENCE`.
    pub evidence: Option<EvidenceMode>,
}

/// Reads the four allowed environment settings; ignores every other variable.
///
/// No environment-derived path or host grant is accepted (§6.2), so the two
/// path variables only relocate the operator's own directories.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] when an allowed variable has an
/// unparsable value.
pub fn env_settings(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<EnvSettings, JailError> {
    let mut settings = EnvSettings::default();
    if let Some(value) = lookup("OURO_CONFIG_DIR") {
        settings.config_dir = Some(PathBuf::from(value));
    }
    if let Some(value) = lookup("OURO_DATA_DIR") {
        settings.data_dir = Some(PathBuf::from(value));
    }
    if let Some(value) = lookup("OURO_JAIL_OBSERVE") {
        let text = value
            .to_str()
            .ok_or_else(|| invalid("OURO_JAIL_OBSERVE", "the value is not UTF-8"))?;
        settings.observe = Some(parse_observe("OURO_JAIL_OBSERVE", text)?);
    }
    if let Some(value) = lookup("OURO_JAIL_EVIDENCE") {
        let text = value
            .to_str()
            .ok_or_else(|| invalid("OURO_JAIL_EVIDENCE", "the value is not UTF-8"))?;
        settings.evidence = Some(parse_evidence("OURO_JAIL_EVIDENCE", text)?);
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_units_scale_and_a_bare_integer_refuses() {
        assert_eq!(
            parse_limit_value("k", LimitKey::Wall, "5m").expect("parses"),
            300_000
        );
        assert_eq!(
            parse_limit_value("k", LimitKey::Wall, "300s").expect("parses"),
            300_000
        );
        assert_eq!(
            parse_limit_value("k", LimitKey::Wall, "2h").expect("parses"),
            7_200_000
        );
        assert_eq!(
            parse_limit_value("k", LimitKey::Wall, "250ms").expect("parses"),
            250
        );
        assert!(parse_limit_value("k", LimitKey::Wall, "300").is_err());
        assert!(parse_limit_value("k", LimitKey::Wall, "0s").is_err());
        assert!(parse_limit_value("k", LimitKey::Wall, "-1s").is_err());
        assert!(parse_limit_value("k", LimitKey::Wall, "forever").is_err());
    }

    #[test]
    fn memory_units_are_binary_and_overflow_refuses() {
        assert_eq!(
            parse_limit_value("k", LimitKey::Mem, "512MiB").expect("parses"),
            512 * 1024 * 1024
        );
        assert_eq!(
            parse_limit_value("k", LimitKey::Mem, "1024").expect("parses"),
            1024
        );
        assert!(parse_limit_value("k", LimitKey::Mem, "18446744073709551615GiB").is_err());
        assert!(parse_limit_value("k", LimitKey::Mem, "0KiB").is_err());
    }

    #[test]
    fn a_duplicate_cli_limit_refuses() {
        let error = ceilings_from_cli(&["wall=1m".to_owned(), "wall=2m".to_owned()])
            .expect_err("duplicates refuse");
        assert_eq!(error.code, ErrorCode::InvalidConfig);
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn an_unknown_cli_limit_key_refuses() {
        let error = ceilings_from_cli(&["disk=1".to_owned()]).expect_err("an unknown key refuses");
        assert_eq!(error.code, ErrorCode::InvalidConfig);
    }

    #[test]
    fn a_duplicate_toml_key_refuses() {
        let error = parse_policy_file(
            "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\n[limits]\nwall = \"1m\"\nwall = \"2m\"\n",
        )
        .expect_err("TOML forbids duplicate keys");
        assert_eq!(error.code, ErrorCode::InvalidConfig);
    }

    #[test]
    fn an_unknown_toml_key_refuses() {
        let error = parse_policy_file(
            "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\nfuture_key = 1\n",
        )
        .expect_err("unknown keys are never ignored");
        assert_eq!(error.code, ErrorCode::InvalidConfig);
    }

    #[test]
    fn the_environment_allow_list_ignores_everything_else() {
        let lookup = |name: &str| match name {
            "OURO_JAIL_OBSERVE" => Some(OsString::from("off")),
            "OURO_JAIL_PROFILE" => Some(OsString::from("none")),
            "OURO_RW" => Some(OsString::from("/")),
            _ => None,
        };
        let settings = env_settings(&lookup).expect("parses");
        assert_eq!(settings.observe, Some(ObserveMode::Off));
        assert_eq!(settings.config_dir, None);
        assert_eq!(settings.data_dir, None);
        assert_eq!(settings.evidence, None);
        assert_eq!(ENVIRONMENT_ALLOW_LIST.len(), 4);
    }
}
