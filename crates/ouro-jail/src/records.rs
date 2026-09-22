//! Wire records: receipts, events, control messages, the gate frame and the
//! error object.
//!
//! Implements jail-v1 §13 (wire records, receipts and bounded trace), §13.1
//! (event envelope), §13.2 (receipt lifecycle and shape), §8.2 (managed gate
//! protocol) and the error/exit-code table of §6.4. The native-string codec is
//! `docs/specs/jail-v1/canonicalization.md` §"Native strings"; it is shared by
//! receipt grant values, mount paths and the private policy snapshot.
//!
//! Nothing here records a fact the caller did not establish. Every "unknown" is
//! a `None`/`null` and no constructor invents an outcome.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ---------------------------------------------------------------------------
// Schema identifiers (§13, §6.3, §8.2). `version --json` announces these and a
// test compares them with the checked-in schema files.
// ---------------------------------------------------------------------------

/// `ouro.jail.receipt/1`: the receipt record (`jail-receipt.schema.json`).
pub const SCHEMA_RECEIPT: &str = "ouro.jail.receipt/1";
/// `ouro.event/1`: the shared source-event envelope (`event.schema.json`).
pub const SCHEMA_EVENT: &str = "ouro.event/1";
/// `ouro.jail.policy/1`: the public policy file shape and the digest domain.
pub const SCHEMA_POLICY: &str = "ouro.jail.policy/1";
/// `ouro.jail.policy-snapshot/1`: the canonical resolved snapshot.
pub const SCHEMA_POLICY_SNAPSHOT: &str = "ouro.jail.policy-snapshot/1";
/// `ouro.jail.policy-file/1`: the private `policy.json` envelope.
pub const SCHEMA_POLICY_FILE: &str = "ouro.jail.policy-file/1";
/// `ouro.jail.gate/1`: the managed release frame (§8.2).
pub const SCHEMA_GATE: &str = "ouro.jail.gate/1";
/// `ouro.jail.control/1`: the control-channel NDJSON message (§8.2).
pub const SCHEMA_CONTROL: &str = "ouro.jail.control/1";
/// `ouro.jail.network/1`: the host-rule set (`network-rules.md`).
pub const SCHEMA_NETWORK: &str = "ouro.jail.network/1";
/// `linux-closed-v1`: the observed operation set (§11.2).
pub const CLOSED_SET_LINUX_V1: &str = "linux-closed-v1";

/// Maximum gate frame, including the single trailing LF (§8.2).
pub const GATE_FRAME_MAX: usize = 1024;
/// Maximum control frame (§8.2).
pub const CONTROL_FRAME_MAX: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Native strings (canonicalization.md)
// ---------------------------------------------------------------------------

/// A Unix byte string as it appears in records.
///
/// Valid UTF-8 encodes as a JSON string; any other byte sequence encodes as
/// `{"encoding":"base64","data":...}`. A native value never contains NUL, and
/// bytes that *are* valid UTF-8 must use the string form.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum NativeString {
    /// Valid UTF-8, encoded as a JSON string.
    Text(String),
    /// Not valid UTF-8, encoded as the base64 object.
    Bytes(Vec<u8>),
}

/// Why a byte sequence or encoded value is not a valid native string.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NativeStringError {
    /// Native values cannot contain NUL.
    ContainsNul,
    /// The base64 payload is not canonical RFC 4648 with padding.
    NoncanonicalBase64,
    /// The decoded bytes are valid UTF-8, so the string form is required.
    Utf8MustUseStringForm,
}

impl fmt::Display for NativeStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            NativeStringError::ContainsNul => "native value contains NUL",
            NativeStringError::NoncanonicalBase64 => "noncanonical base64 payload",
            NativeStringError::Utf8MustUseStringForm => "UTF-8 bytes must use the JSON string form",
        };
        f.write_str(text)
    }
}

impl NativeString {
    /// Chooses the codec branch for `bytes`, refusing an embedded NUL.
    ///
    /// # Errors
    /// Returns [`NativeStringError::ContainsNul`] when `bytes` contains a NUL.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, NativeStringError> {
        let bytes = bytes.into();
        if bytes.contains(&0) {
            return Err(NativeStringError::ContainsNul);
        }
        match String::from_utf8(bytes) {
            Ok(text) => Ok(NativeString::Text(text)),
            Err(error) => Ok(NativeString::Bytes(error.into_bytes())),
        }
    }

    /// The literal bytes this value stands for.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            NativeString::Text(text) => text.as_bytes(),
            NativeString::Bytes(bytes) => bytes,
        }
    }

    /// The value as text, or `None` when the bytes are not UTF-8.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            NativeString::Text(text) => Some(text),
            NativeString::Bytes(_) => None,
        }
    }

    /// A lossy rendering for human-readable diagnostics only; never a record.
    #[must_use]
    pub fn to_display(&self) -> String {
        String::from_utf8_lossy(self.as_bytes()).into_owned()
    }
}

impl Serialize for NativeString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            NativeString::Text(text) => serializer.serialize_str(text),
            NativeString::Bytes(bytes) => {
                use serde::ser::SerializeMap as _;
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("encoding", "base64")?;
                map.serialize_entry("data", &BASE64.encode(bytes))?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for NativeString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NativeVisitor;

        impl<'de> Visitor<'de> for NativeVisitor {
            type Value = NativeString;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a UTF-8 string or a base64 native-byte object")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<NativeString, E> {
                if value.as_bytes().contains(&0) {
                    return Err(E::custom(NativeStringError::ContainsNul));
                }
                Ok(NativeString::Text(value.to_owned()))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NativeString, A::Error> {
                let mut encoding: Option<String> = None;
                let mut data: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "encoding" => {
                            if encoding.is_some() {
                                return Err(de::Error::duplicate_field("encoding"));
                            }
                            encoding = Some(map.next_value()?);
                        }
                        "data" => {
                            if data.is_some() {
                                return Err(de::Error::duplicate_field("data"));
                            }
                            data = Some(map.next_value()?);
                        }
                        other => {
                            return Err(de::Error::unknown_field(other, &["encoding", "data"]));
                        }
                    }
                }
                let encoding = encoding.ok_or_else(|| de::Error::missing_field("encoding"))?;
                let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                if encoding != "base64" {
                    return Err(de::Error::custom("unknown native-string encoding"));
                }
                let bytes = BASE64
                    .decode(data.as_bytes())
                    .map_err(|_| de::Error::custom(NativeStringError::NoncanonicalBase64))?;
                if BASE64.encode(&bytes) != data {
                    return Err(de::Error::custom(NativeStringError::NoncanonicalBase64));
                }
                if bytes.contains(&0) {
                    return Err(de::Error::custom(NativeStringError::ContainsNul));
                }
                if std::str::from_utf8(&bytes).is_ok() {
                    return Err(de::Error::custom(NativeStringError::Utf8MustUseStringForm));
                }
                Ok(NativeString::Bytes(bytes))
            }
        }

        deserializer.deserialize_any(NativeVisitor)
    }
}

// ---------------------------------------------------------------------------
// RFC 3339 UTC (§13.1: wall time is UTC RFC 3339)
// ---------------------------------------------------------------------------

/// Formats `time` as `YYYY-MM-DDThh:mm:ssZ` in UTC.
///
/// Hand-rolled from the proleptic Gregorian civil-from-days algorithm; the
/// dependency policy forbids a date crate. Sub-second precision is dropped,
/// which the schema's `date-time` format permits. Times before the Unix epoch
/// are supported.
#[must_use]
pub fn rfc3339_utc(time: SystemTime) -> String {
    let seconds = match time.duration_since(UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX),
    };
    rfc3339_utc_from_unix(seconds)
}

/// Formats a Unix timestamp in seconds as RFC 3339 UTC.
#[must_use]
pub fn rfc3339_utc_from_unix(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60,
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to (y, m, d).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * shifted_month + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    })
    .unwrap_or(1);
    (if month <= 2 { year + 1 } else { year }, month, day)
}

// ---------------------------------------------------------------------------
// Errors (§6.4)
// ---------------------------------------------------------------------------

/// The stable error code list of §6.4.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Invalid CLI or configuration syntax, or a forbidden value.
    InvalidConfig,
    /// A narrowing file widened the authority it inherits (§6.3).
    PolicyWidening,
    /// The runtime state root failed its ownership/mode/symlink checks (§6.2).
    UnsafeStatePath,
    /// Execution is not implemented for this platform (§3.2).
    UnsupportedPlatform,
    /// A capability the resolved policy requires is not available (§3.1).
    MissingCapability,
    /// The enforcement backend is absent or unusable.
    BackendUnavailable,
    /// The observer could not attach; `--observe on` refuses (§11.4).
    ObserverUnavailable,
    /// The `agent` nesting probe failed (§9.2).
    NestingFailed,
    /// A declared launch credential is missing or unusable (§12).
    CredentialUnavailable,
    /// A supplied fd is closed, mis-directed or shared (§6.1).
    InvalidFd,
    /// The gate frame was malformed, oversized or did not match (§8.2).
    GateInvalid,
    /// The gate reached EOF without a release frame (§8.2).
    GateClosed,
    /// The preparation or gate budget expired (§8.2).
    PrepareTimeout,
    /// The attempt directory already carries a jail claim (§7).
    AttemptExists,
    /// The target `exec` failed; no target instruction ran (§8.1).
    ExecFailed,
    /// Observation evidence was lost (§11.4).
    EvidenceLost,
    /// Tree death could not be verified within its budget (§9.3).
    TreeUnknown,
    /// Persisting state failed or is ambiguous (§7).
    StateWriteFailed,
    /// A defect in this implementation, reported rather than papered over.
    InternalError,
}

impl ErrorCode {
    /// The snake_case wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidConfig => "invalid_config",
            ErrorCode::PolicyWidening => "policy_widening",
            ErrorCode::UnsafeStatePath => "unsafe_state_path",
            ErrorCode::UnsupportedPlatform => "unsupported_platform",
            ErrorCode::MissingCapability => "missing_capability",
            ErrorCode::BackendUnavailable => "backend_unavailable",
            ErrorCode::ObserverUnavailable => "observer_unavailable",
            ErrorCode::NestingFailed => "nesting_failed",
            ErrorCode::CredentialUnavailable => "credential_unavailable",
            ErrorCode::InvalidFd => "invalid_fd",
            ErrorCode::GateInvalid => "gate_invalid",
            ErrorCode::GateClosed => "gate_closed",
            ErrorCode::PrepareTimeout => "prepare_timeout",
            ErrorCode::AttemptExists => "attempt_exists",
            ErrorCode::ExecFailed => "exec_failed",
            ErrorCode::EvidenceLost => "evidence_lost",
            ErrorCode::TreeUnknown => "tree_unknown",
            ErrorCode::StateWriteFailed => "state_write_failed",
            ErrorCode::InternalError => "internal_error",
        }
    }
}

/// The lifecycle stage an error was raised in (§8.1 state machine).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorStage {
    /// Parsing and resolving authority.
    Resolving,
    /// Probing the selected mechanisms.
    Probing,
    /// Creating boundaries and the blocked launcher.
    Preparing,
    /// Waiting for the managed gate.
    Prepared,
    /// Between release and confirmed target exec.
    Released,
    /// The target is running.
    Running,
    /// Terminating the tree.
    Stopping,
    /// Verifying tree death and draining observations.
    Reconciling,
    /// After settlement, including vendor-state cleanup.
    Settled,
}

impl ErrorStage {
    /// The snake_case wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorStage::Resolving => "resolving",
            ErrorStage::Probing => "probing",
            ErrorStage::Preparing => "preparing",
            ErrorStage::Prepared => "prepared",
            ErrorStage::Released => "released",
            ErrorStage::Running => "running",
            ErrorStage::Stopping => "stopping",
            ErrorStage::Reconciling => "reconciling",
            ErrorStage::Settled => "settled",
        }
    }
}

/// The required `remediation_category` of §6.4. Guidance, never an auto-retry.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Remediation {
    /// The operator's configuration or command line must change.
    Configuration,
    /// The host must be provisioned differently.
    HostSetup,
    /// This implementation does not offer the requested property.
    Unsupported,
    /// The condition may be transient.
    Retry,
    /// Look at the retained attempt state before acting.
    InspectState,
}

/// The error object as it appears in a receipt (`$defs/error`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorObject {
    /// Stable code from [`ErrorCode`].
    pub code: String,
    /// Lifecycle stage from [`ErrorStage`].
    pub stage: String,
    /// A safe message: never raw argv, environment values or credentials.
    pub message: String,
    /// The exact configuration key path, when the error names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    /// Required remediation category.
    pub remediation_category: Remediation,
}

/// A refusal or tool failure with everything a receipt and a stderr line need.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct JailError {
    /// Stable code from §6.4.
    pub code: ErrorCode,
    /// The lifecycle stage.
    pub stage: ErrorStage,
    /// A safe message (§6.4: no raw credentials, argv or environment values).
    pub message: String,
    /// The exact configuration key path when one applies (§6.3).
    pub key_path: Option<String>,
    /// Remediation category.
    pub remediation: Remediation,
}

impl JailError {
    /// Builds an error without a key path.
    #[must_use]
    pub fn new(
        code: ErrorCode,
        stage: ErrorStage,
        remediation: Remediation,
        message: impl Into<String>,
    ) -> Self {
        JailError {
            code,
            stage,
            message: message.into(),
            key_path: None,
            remediation,
        }
    }

    /// Attaches the exact configuration key path this error names.
    #[must_use]
    pub fn with_key_path(mut self, key_path: impl Into<String>) -> Self {
        self.key_path = Some(key_path.into());
        self
    }

    /// The process exit status for this error (§6.4).
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        exit_code_for(self.code)
    }

    /// The wire form for `errors[]` and `outcome.error`.
    #[must_use]
    pub fn to_object(&self) -> ErrorObject {
        ErrorObject {
            code: self.code.as_str().to_owned(),
            stage: self.stage.as_str().to_owned(),
            message: self.message.clone(),
            key_path: self.key_path.clone(),
            remediation_category: self.remediation,
        }
    }
}

impl fmt::Display for JailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ouro-jail: error {} at {} [{}]: {}",
            self.code.as_str(),
            self.stage.as_str(),
            remediation_str(self.remediation),
            self.message
        )?;
        if let Some(path) = &self.key_path {
            write!(f, " (key: {path})")?;
        }
        Ok(())
    }
}

impl std::error::Error for JailError {}

fn remediation_str(remediation: Remediation) -> &'static str {
    match remediation {
        Remediation::Configuration => "configuration",
        Remediation::HostSetup => "host_setup",
        Remediation::Unsupported => "unsupported",
        Remediation::Retry => "retry",
        Remediation::InspectState => "inspect_state",
    }
}

/// The single implementation of the §6.4 exit-code policy for errors.
///
/// Refusal before user exec is 125, invalid configuration is 2, and every other
/// tool failure is 1. Successful child execution reports the child's own code
/// elsewhere; this function never sees that case.
#[must_use]
pub fn exit_code_for(code: ErrorCode) -> i32 {
    match code {
        ErrorCode::InvalidConfig => 2,
        ErrorCode::PolicyWidening
        | ErrorCode::UnsafeStatePath
        | ErrorCode::UnsupportedPlatform
        | ErrorCode::MissingCapability
        | ErrorCode::BackendUnavailable
        | ErrorCode::ObserverUnavailable
        | ErrorCode::NestingFailed
        | ErrorCode::CredentialUnavailable
        | ErrorCode::InvalidFd
        | ErrorCode::GateInvalid
        | ErrorCode::GateClosed
        | ErrorCode::PrepareTimeout
        | ErrorCode::AttemptExists
        | ErrorCode::ExecFailed => 125,
        ErrorCode::EvidenceLost
        | ErrorCode::TreeUnknown
        | ErrorCode::StateWriteFailed
        | ErrorCode::InternalError => 1,
    }
}

// ---------------------------------------------------------------------------
// Receipt (§13.2)
// ---------------------------------------------------------------------------

/// Receipt lifecycle phase (§13.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Preparation complete, no target instruction has run.
    Prepared,
    /// Target exec confirmed.
    Enforced,
    /// Tree death verified.
    Settled,
    /// A proved refusal before target exec.
    Refused,
}

/// Whether a contained boundary was applied (§13.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Containment {
    /// The final policy is not yet established.
    Pending,
    /// A contained profile was applied.
    Enforced,
    /// The `none` profile: no containment at all.
    None,
}

/// The protection label (§13.2, I08). Derived from [`Containment`], never set.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildProtection {
    /// No contained boundary is established yet.
    Pending,
    /// A contained boundary is established.
    Enforced,
    /// `none`: never upgraded, including after a clean exit (I08).
    Unprotected,
}

/// Operating system tag used by the portable records.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    /// Linux.
    Linux,
    /// macOS.
    Macos,
}

impl Os {
    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Macos => "macos",
        }
    }
}

/// `platform` field group.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformRecord {
    /// `linux` or `macos`.
    pub os: Os,
    /// Architecture string as the host reports it.
    pub arch: String,
    /// Kernel/build string.
    pub kernel: String,
}

/// `jail` field group: this binary and the enforcement backend.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailRecord {
    /// Always `ouro-jail`.
    pub component: String,
    /// This binary's version.
    pub version: String,
    /// Backend identity, or null when no backend was selected.
    pub backend: Option<String>,
    /// Backend version, or null.
    pub backend_version: Option<String>,
}

/// An operator grant as recorded in the receipt.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Grant kind, for example `read_write` or `allow_host`.
    pub kind: String,
    /// The granted value in the native-string codec.
    pub value: NativeString,
    /// Always `operator`: the schema admits no other grantor.
    pub by: String,
}

/// Observation mode (§6.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserveMode {
    /// Observation requested.
    On,
    /// Observation explicitly disabled by the operator.
    Off,
}

/// Evidence mode (§11.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EvidenceMode {
    /// Loss stops the attempt.
    #[serde(rename = "strict")]
    Strict,
    /// Loss continues with degraded coverage.
    #[serde(rename = "best-effort")]
    BestEffort,
}

/// `policy` field group.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRecord {
    /// Display name of the selected policy.
    pub name: String,
    /// Canonical policy digest (§6.3).
    pub digest: String,
    /// Requested observation mode.
    pub observe: ObserveMode,
    /// Requested evidence mode.
    pub evidence: EvidenceMode,
    /// Derived capability requirements.
    pub requirements: Vec<String>,
    /// Explicit operator grants.
    pub grants: Vec<Grant>,
}

/// A mount as actually applied.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedMount {
    /// The path inside the child's view.
    pub path: NativeString,
    /// `rw`, `ro` or `hidden`.
    pub mode: String,
}

/// Applied filesystem plan, or null when none was applied.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedFilesystem {
    /// The mechanism that applied it.
    pub mechanism: String,
    /// The coverage actually obtained (§4.4 of the north star).
    pub protected_coverage: String,
    /// The rendered mount table.
    pub mounts: Vec<AppliedMount>,
}

/// Applied network plan.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedNetwork {
    /// `pending`, `none`, `proxy` or `host`.
    pub mode: String,
    /// The mechanism, or null when nothing was applied.
    pub mechanism: Option<String>,
    /// Canonical allowed host rules.
    pub allowed_hosts: Vec<String>,
}

/// Applied syscall filter, or null when none was installed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedSyscalls {
    /// The mechanism, for example `seccomp-bpf`.
    pub mechanism: String,
    /// Digest of the exact filter program.
    pub digest: String,
}

/// One requested limit and what became of it (§6.4, §13.2).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedLimit {
    /// `wall`, `pids`, `mem` or `cpu`.
    pub key: String,
    /// The requested value as the operator wrote it.
    pub requested: String,
    /// Whether the policy requires enforcement.
    pub required: bool,
    /// Whether a mechanism actually enforced it.
    pub applied: bool,
    /// The mechanism, null when unapplied.
    pub mechanism: Option<String>,
    /// `process`, `tree` or null when unapplied.
    pub scope: Option<String>,
    /// Whether the ceiling was hit; null when unknown or unapplied.
    pub hit: Option<bool>,
}

/// `applied` field group.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applied {
    /// Applied filesystem plan, or null.
    pub filesystem: Option<AppliedFilesystem>,
    /// Applied network plan.
    pub network: AppliedNetwork,
    /// Applied syscall filter, or null.
    pub syscalls: Option<AppliedSyscalls>,
    /// Requested limits and their fate.
    pub limits: Vec<AppliedLimit>,
    /// Environment names present in the child; never values (I09).
    pub environment_names: Vec<String>,
    /// Environment names removed from an inherited environment.
    pub removed_environment_names: Vec<String>,
}

/// Per-source health (§11.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    /// Available but not yet applied.
    Supported,
    /// Applied and collecting.
    Active,
    /// A required interval is missing.
    Degraded,
    /// Disabled or unimplemented.
    Unsupported,
}

/// `observer.sources`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHealth {
    /// The supervisor's own facts.
    pub wrapper: SourceStatus,
    /// The closed-set observer.
    pub audit: SourceStatus,
    /// The outside proxy.
    pub proxy: SourceStatus,
}

/// A bounded coverage gap (§11.4).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    /// The coverage classes this gap affects.
    pub classes: Vec<String>,
    /// The source that lost the interval.
    pub source: String,
    /// Start of the affected interval, decimal nanoseconds.
    pub start_ns: String,
    /// End of the interval, or null when it is still open.
    pub end_ns: Option<String>,
    /// A safe reason string.
    pub reason: String,
    /// Lost results when exactly known, otherwise null.
    pub lost_count: Option<u64>,
}

/// `observer` field group.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverRecord {
    /// The observer backend that ran, or null.
    pub backend: Option<String>,
    /// The closed set identifier, or null.
    pub set: Option<String>,
    /// Whether attachment was established for this attempt.
    pub attached: bool,
    /// Per-source health.
    pub sources: SourceHealth,
    /// Bounded gap summaries.
    pub gaps: Vec<Gap>,
}

/// One coverage class entry (§11.4).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageEntry {
    /// `supported`, `active`, `degraded` or `unsupported`.
    pub status: SourceStatus,
    /// The single assigned source, empty when unsupported.
    pub sources: Vec<String>,
    /// Result count, null unless the class is active.
    pub observed_count: Option<u64>,
    /// Gaps affecting this class.
    pub gaps: Vec<Gap>,
}

impl CoverageEntry {
    /// The honest entry for a class that is not implemented or disabled.
    #[must_use]
    pub fn unsupported() -> Self {
        CoverageEntry {
            status: SourceStatus::Unsupported,
            sources: Vec::new(),
            observed_count: None,
            gaps: Vec::new(),
        }
    }
}

/// `coverage` field group: exactly the six classes of §11.4.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    /// `proc.exec` and `proc.exit` results.
    pub exec: CoverageEntry,
    /// Mutating opens and directory-entry changes.
    #[serde(rename = "fs.write")]
    pub fs_write: CoverageEntry,
    /// EACCES/EPERM results from the closed set.
    #[serde(rename = "fs.deny")]
    pub fs_deny: CoverageEntry,
    /// Audit-source `net.connect` results.
    pub net: CoverageEntry,
    /// Applied ceilings with a confirmed hit.
    pub limits: CoverageEntry,
    /// Proxy-source `net.connect` results.
    #[serde(rename = "proxy.net")]
    pub proxy_net: CoverageEntry,
}

impl Coverage {
    /// All six classes unsupported: the honest shape before anything attaches.
    #[must_use]
    pub fn all_unsupported() -> Self {
        Coverage {
            exec: CoverageEntry::unsupported(),
            fs_write: CoverageEntry::unsupported(),
            fs_deny: CoverageEntry::unsupported(),
            net: CoverageEntry::unsupported(),
            limits: CoverageEntry::unsupported(),
            proxy_net: CoverageEntry::unsupported(),
        }
    }
}

/// Portable process identity wrapper (§7).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    /// Platform-specific identity kind, for example `linux_boot_start`.
    pub kind: String,
    /// The identity's fields.
    pub value: serde_json::Map<String, serde_json::Value>,
}

/// `process` field group, null before an identity exists.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRecord {
    /// Diagnostic numeric pid.
    pub pid: u32,
    /// The stable identity.
    pub identity: ProcessIdentity,
}

/// OS-tagged native lifetime details.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLifetime {
    /// `linux` or `macos`.
    pub os: Os,
    /// Platform-specific identities.
    pub details: serde_json::Map<String, serde_json::Value>,
}

/// `lifetime` field group (§13.2).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifetime {
    /// `pending`, `pid_namespace`, `supervisor_cgroup` or `native_tree`.
    pub boundary: String,
    /// Native details, null while the boundary is pending.
    pub native: Option<NativeLifetime>,
    /// True only after verified emptiness; null when unknown.
    pub tree_empty: Option<bool>,
    /// Verification time, only with a non-null `tree_empty`.
    pub verified_at: Option<String>,
    /// `attempt_tree`, `registered_boundary` or null.
    pub verification_scope: Option<String>,
    /// `pending`, `verified` or `lost`.
    pub integrity: String,
}

impl Lifetime {
    /// The tuple for a refusal before boundary creation (§13.2).
    #[must_use]
    pub fn pending() -> Self {
        Lifetime {
            boundary: "pending".to_owned(),
            native: None,
            tree_empty: None,
            verified_at: None,
            verification_scope: None,
            integrity: "pending".to_owned(),
        }
    }
}

/// `outcome.kind` (§13.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    /// No target result yet.
    Pending,
    /// A proved refusal before target exec.
    Refused,
    /// The target exited with a code.
    Exited,
    /// The target was terminated by a signal.
    Signaled,
    /// The target `exec` itself failed.
    ExecError,
    /// The facts needed are missing.
    Unknown,
}

/// `outcome` field group.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    /// What became of the target.
    pub kind: OutcomeKind,
    /// Exit code for `exited`, otherwise null.
    pub code: Option<u8>,
    /// Signal number for `signaled`, otherwise null.
    pub signal: Option<u32>,
    /// Why termination happened, when known.
    pub cause: Option<String>,
    /// The error that explains a refusal or failure.
    pub error: Option<ErrorObject>,
}

impl Outcome {
    /// The refusal outcome carrying `error`.
    #[must_use]
    pub fn refused(error: &JailError) -> Self {
        Outcome {
            kind: OutcomeKind::Refused,
            code: None,
            signal: None,
            cause: None,
            error: Some(error.to_object()),
        }
    }

    /// The outcome before anything is known.
    #[must_use]
    pub fn pending() -> Self {
        Outcome {
            kind: OutcomeKind::Pending,
            code: None,
            signal: None,
            cause: None,
            error: None,
        }
    }
}

/// Vendor-state cleanup progress (§12).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateCleanup {
    /// No vendor state was created.
    NotNeeded,
    /// Deletion has not finished.
    Pending,
    /// Deletion and the directory sync completed.
    Complete,
}

/// A staged credential's provenance (§12).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRecord {
    /// Unique logical id.
    pub id: String,
    /// `copy_rw` or `bind_ro`.
    pub mode: String,
    /// Content digest, or null.
    pub digest: Option<String>,
    /// Why the digest is absent; null when a digest is present.
    pub digest_unavailable_reason: Option<String>,
}

/// The receipt record (`ouro.jail.receipt/1`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Always [`SCHEMA_RECEIPT`].
    pub schema: String,
    /// `att_<uuid v4>`.
    pub attempt_id: String,
    /// Starts at 1, advances on each successful replacement.
    pub revision: u64,
    /// Lifecycle phase.
    pub phase: Phase,
    /// Platform identity.
    pub platform: PlatformRecord,
    /// This binary and the backend.
    pub jail: JailRecord,
    /// Requested policy.
    pub policy: PolicyRecord,
    /// Whether containment was applied.
    pub containment: Containment,
    /// Derived protection label (I08).
    pub child_protection: ChildProtection,
    /// False until target exec is confirmed.
    pub exec_observed: bool,
    /// Digest of the literal operator argv, or null.
    pub argv_digest: Option<String>,
    /// What was actually applied.
    pub applied: Applied,
    /// Observer identity and health.
    pub observer: ObserverRecord,
    /// Per-class coverage.
    pub coverage: Coverage,
    /// Process identity, null before one exists.
    pub process: Option<ProcessRecord>,
    /// Boundary and tree facts.
    pub lifetime: Lifetime,
    /// Target outcome.
    pub outcome: Outcome,
    /// Vendor-state cleanup progress.
    pub state_cleanup: StateCleanup,
    /// A safe cleanup failure reason, or null.
    pub cleanup_error: Option<String>,
    /// Creation time, RFC 3339 UTC.
    pub created_at: String,
    /// Last update time, RFC 3339 UTC.
    pub updated_at: String,
    /// Errors recorded for this attempt.
    pub errors: Vec<ErrorObject>,
    /// Staged credential provenance.
    pub credentials: Vec<CredentialRecord>,
}

/// The single in-memory account of an attempt.
///
/// One builder produces every phase from it (§13.2), so a phase cannot carry a
/// field group the attempt never established. `child_protection` is always
/// derived from `containment`, which is how I08 is kept structurally true.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AttemptRecord {
    /// `att_<uuid v4>`.
    pub attempt_id: String,
    /// Receipt revision; the caller advances it on each replacement.
    pub revision: u64,
    /// Platform identity.
    pub platform: PlatformRecord,
    /// This binary and the backend.
    pub jail: JailRecord,
    /// Requested policy.
    pub policy: PolicyRecord,
    /// Whether containment was applied.
    pub containment: Containment,
    /// False until target exec is confirmed.
    pub exec_observed: bool,
    /// Digest of the literal operator argv, or null.
    pub argv_digest: Option<String>,
    /// What was actually applied.
    pub applied: Applied,
    /// Observer identity and health.
    pub observer: ObserverRecord,
    /// Per-class coverage.
    pub coverage: Coverage,
    /// Process identity, null before one exists.
    pub process: Option<ProcessRecord>,
    /// Boundary and tree facts.
    pub lifetime: Lifetime,
    /// Target outcome.
    pub outcome: Outcome,
    /// Vendor-state cleanup progress.
    pub state_cleanup: StateCleanup,
    /// A safe cleanup failure reason, or null.
    pub cleanup_error: Option<String>,
    /// Creation time.
    pub created_at: SystemTime,
    /// Last update time.
    pub updated_at: SystemTime,
    /// Errors recorded for this attempt.
    pub errors: Vec<ErrorObject>,
    /// Staged credential provenance.
    pub credentials: Vec<CredentialRecord>,
}

impl AttemptRecord {
    /// The protection label this attempt's containment implies (I08).
    #[must_use]
    pub fn child_protection(&self) -> ChildProtection {
        match self.containment {
            Containment::Pending => ChildProtection::Pending,
            Containment::Enforced => ChildProtection::Enforced,
            Containment::None => ChildProtection::Unprotected,
        }
    }

    /// Renders the receipt for `phase` from this account.
    #[must_use]
    pub fn receipt(&self, phase: Phase) -> Receipt {
        Receipt {
            schema: SCHEMA_RECEIPT.to_owned(),
            attempt_id: self.attempt_id.clone(),
            revision: self.revision,
            phase,
            platform: self.platform.clone(),
            jail: self.jail.clone(),
            policy: self.policy.clone(),
            containment: self.containment,
            child_protection: self.child_protection(),
            exec_observed: self.exec_observed,
            argv_digest: self.argv_digest.clone(),
            applied: self.applied.clone(),
            observer: self.observer.clone(),
            coverage: self.coverage.clone(),
            process: self.process.clone(),
            lifetime: self.lifetime.clone(),
            outcome: self.outcome.clone(),
            state_cleanup: self.state_cleanup,
            cleanup_error: self.cleanup_error.clone(),
            created_at: rfc3339_utc(self.created_at),
            updated_at: rfc3339_utc(self.updated_at),
            errors: self.errors.clone(),
            credentials: self.credentials.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Events (§13.1)
// ---------------------------------------------------------------------------

/// Event source (§13.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    /// The jail process itself.
    Wrapper,
    /// The closed-set observer.
    Audit,
    /// The outside proxy.
    Proxy,
}

/// Event stage (§13.1). An `attempt` has a null outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStage {
    /// The call was seen entering.
    Attempt,
    /// A result was established.
    Result,
}

/// A policy decision, null when the source establishes none (§13.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// The proxy allowed the request.
    Allow,
    /// The proxy denied the request.
    Deny,
}

/// How a result was established (§13.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    /// An ordinary syscall return.
    SyscallReturn,
    /// A confirmed kernel exec transition.
    ExecTransition,
    /// Final thread-group death.
    ProcessExit,
    /// A proxy connection closed.
    ProxyClose,
    /// A fact the supervisor itself established.
    Wrapper,
}

/// Event outcome (§13.1).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventOutcome {
    /// Whether the operation succeeded; null when unknown.
    pub ok: Option<bool>,
    /// Signed raw return value, when one exists. Always present, because the
    /// schema admits null here and a confirmed exec has no return value.
    #[serde(default)]
    pub return_value: Option<i64>,
    /// Errno name, when the call failed. Always present for the same reason.
    #[serde(default)]
    pub errno: Option<String>,
    /// How the result was established.
    pub completion: Completion,
    /// Proxy bytes in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    /// Proxy bytes out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    /// Proxy duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// One source event (`ouro.event/1`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// Always [`SCHEMA_EVENT`].
    pub schema: String,
    /// The attempt this event belongs to.
    pub attempt_id: String,
    /// Which source established it.
    pub source: EventSource,
    /// Per-source sequence, starting at 1.
    pub source_seq: u64,
    /// Wall time, RFC 3339 UTC.
    pub observed_at: String,
    /// Elapsed continuous time as decimal nanoseconds.
    pub monotonic_ns: String,
    /// The operation name from the shared inventory.
    pub operation: String,
    /// `attempt` or `result`.
    pub stage: EventStage,
    /// A policy decision, or null.
    pub decision: Option<Decision>,
    /// The result, null at `attempt` stage.
    pub outcome: Option<EventOutcome>,
    /// Source-specific fields; never raw argv or environment values (I09).
    pub fields: serde_json::Map<String, serde_json::Value>,
}

impl Event {
    /// A wrapper lifecycle note (`fields.kind = lifecycle`).
    #[must_use]
    pub fn lifecycle_note(
        attempt_id: &str,
        source_seq: u64,
        observed_at: SystemTime,
        monotonic_ns: u128,
        transition: &str,
    ) -> Self {
        let mut fields = serde_json::Map::new();
        fields.insert("kind".to_owned(), serde_json::Value::from("lifecycle"));
        fields.insert("transition".to_owned(), serde_json::Value::from(transition));
        Event {
            schema: SCHEMA_EVENT.to_owned(),
            attempt_id: attempt_id.to_owned(),
            source: EventSource::Wrapper,
            source_seq,
            observed_at: rfc3339_utc(observed_at),
            monotonic_ns: monotonic_ns.to_string(),
            operation: "note".to_owned(),
            stage: EventStage::Result,
            decision: None,
            outcome: Some(EventOutcome {
                ok: Some(true),
                return_value: None,
                errno: None,
                completion: Completion::Wrapper,
                bytes_in: None,
                bytes_out: None,
                duration_ms: None,
            }),
            fields,
        }
    }

    /// A wrapper coverage-gap note (`fields.kind = coverage_gap`).
    #[must_use]
    pub fn coverage_gap_note(
        attempt_id: &str,
        source_seq: u64,
        observed_at: SystemTime,
        monotonic_ns: u128,
        gap: &Gap,
    ) -> Self {
        let mut fields = serde_json::Map::new();
        fields.insert("kind".to_owned(), serde_json::Value::from("coverage_gap"));
        fields.insert(
            "classes".to_owned(),
            serde_json::Value::from(gap.classes.clone()),
        );
        fields.insert(
            "source".to_owned(),
            serde_json::Value::from(gap.source.clone()),
        );
        fields.insert(
            "start_ns".to_owned(),
            serde_json::Value::from(gap.start_ns.clone()),
        );
        fields.insert(
            "end_ns".to_owned(),
            match &gap.end_ns {
                Some(value) => serde_json::Value::from(value.clone()),
                None => serde_json::Value::Null,
            },
        );
        fields.insert(
            "reason".to_owned(),
            serde_json::Value::from(gap.reason.clone()),
        );
        fields.insert(
            "lost_count".to_owned(),
            match gap.lost_count {
                Some(value) => serde_json::Value::from(value),
                None => serde_json::Value::Null,
            },
        );
        Event {
            schema: SCHEMA_EVENT.to_owned(),
            attempt_id: attempt_id.to_owned(),
            source: EventSource::Wrapper,
            source_seq,
            observed_at: rfc3339_utc(observed_at),
            monotonic_ns: monotonic_ns.to_string(),
            operation: "note".to_owned(),
            stage: EventStage::Result,
            decision: None,
            outcome: Some(EventOutcome {
                ok: Some(true),
                return_value: None,
                errno: None,
                completion: Completion::Wrapper,
                bytes_in: None,
                bytes_out: None,
                duration_ms: None,
            }),
            fields,
        }
    }

    /// A wrapper `jail.receipt` event referencing a persisted receipt.
    #[must_use]
    pub fn receipt_note(
        attempt_id: &str,
        source_seq: u64,
        observed_at: SystemTime,
        monotonic_ns: u128,
        phase: Phase,
        receipt_digest: &str,
    ) -> Self {
        let mut fields = serde_json::Map::new();
        fields.insert(
            "phase".to_owned(),
            serde_json::to_value(phase).unwrap_or(serde_json::Value::Null),
        );
        fields.insert(
            "receipt_digest".to_owned(),
            serde_json::Value::from(receipt_digest),
        );
        Event {
            schema: SCHEMA_EVENT.to_owned(),
            attempt_id: attempt_id.to_owned(),
            source: EventSource::Wrapper,
            source_seq,
            observed_at: rfc3339_utc(observed_at),
            monotonic_ns: monotonic_ns.to_string(),
            operation: "jail.receipt".to_owned(),
            stage: EventStage::Result,
            decision: None,
            outcome: Some(EventOutcome {
                ok: Some(true),
                return_value: None,
                errno: None,
                completion: Completion::Wrapper,
                bytes_in: None,
                bytes_out: None,
                duration_ms: None,
            }),
            fields,
        }
    }
}

// ---------------------------------------------------------------------------
// Control messages (§8.2)
// ---------------------------------------------------------------------------

/// Control message kind (§8.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    /// Preparation is complete and the target is still blocked.
    Prepared,
    /// Target exec was confirmed.
    ExecConfirmed,
    /// The attempt refused before target exec.
    Refused,
    /// Tree death was verified.
    Settled,
}

/// One control-channel message (`ouro.jail.control/1`).
///
/// Reporting only: it carries a receipt phase and digest plus a safe outcome,
/// never raw argv (§8.2, I09).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlMessage {
    /// Always [`SCHEMA_CONTROL`].
    pub schema: String,
    /// The attempt this message belongs to.
    pub attempt_id: String,
    /// Monotonically increasing message number.
    pub seq: u64,
    /// What happened.
    pub kind: ControlKind,
    /// The receipt phase this message accompanies.
    pub receipt_phase: Phase,
    /// The digest of that receipt's bytes.
    pub receipt_digest: String,
    /// A safe outcome summary.
    pub outcome: Outcome,
    /// The error object for a refusal, or null.
    pub error: Option<ErrorObject>,
}

impl ControlMessage {
    /// Serializes one NDJSON frame, refusing to emit an oversized one.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InternalError`] when the frame exceeds
    /// [`CONTROL_FRAME_MAX`]; §8.2 forbids emitting it.
    pub fn to_frame(&self) -> Result<Vec<u8>, JailError> {
        let mut bytes = serde_json::to_vec(self).map_err(|error| {
            JailError::new(
                ErrorCode::InternalError,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("control message could not be serialized: {error}"),
            )
        })?;
        bytes.push(b'\n');
        if bytes.len() > CONTROL_FRAME_MAX {
            return Err(JailError::new(
                ErrorCode::InternalError,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!(
                    "control frame of {} bytes exceeds the {CONTROL_FRAME_MAX} byte maximum",
                    bytes.len()
                ),
            ));
        }
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Gate frame (§8.2)
// ---------------------------------------------------------------------------

/// The managed release frame (`ouro.jail.gate/1`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct GateFrame {
    /// Always [`SCHEMA_GATE`].
    pub schema: String,
    /// Always `release`.
    pub action: String,
    /// The attempt the owner is releasing.
    pub attempt_id: String,
    /// The policy digest the owner compared.
    pub policy_digest: String,
}

impl<'de> Deserialize<'de> for GateFrame {
    /// Rejects unknown keys and duplicate object keys (§8.2).
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FrameVisitor;

        impl<'de> Visitor<'de> for FrameVisitor {
            type Value = GateFrame;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an ouro.jail.gate/1 release object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<GateFrame, A::Error> {
                let mut schema: Option<String> = None;
                let mut action: Option<String> = None;
                let mut attempt_id: Option<String> = None;
                let mut policy_digest: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    let slot = match key.as_str() {
                        "schema" => &mut schema,
                        "action" => &mut action,
                        "attempt_id" => &mut attempt_id,
                        "policy_digest" => &mut policy_digest,
                        other => {
                            return Err(de::Error::unknown_field(
                                other,
                                &["schema", "action", "attempt_id", "policy_digest"],
                            ));
                        }
                    };
                    if slot.is_some() {
                        return Err(de::Error::custom(format!("duplicate object key `{key}`")));
                    }
                    *slot = Some(map.next_value()?);
                }
                Ok(GateFrame {
                    schema: schema.ok_or_else(|| de::Error::missing_field("schema"))?,
                    action: action.ok_or_else(|| de::Error::missing_field("action"))?,
                    attempt_id: attempt_id.ok_or_else(|| de::Error::missing_field("attempt_id"))?,
                    policy_digest: policy_digest
                        .ok_or_else(|| de::Error::missing_field("policy_digest"))?,
                })
            }
        }

        deserializer.deserialize_map(FrameVisitor)
    }
}

/// What the supervisor expects the owner to release.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GateExpectation {
    /// The attempt id this supervisor owns.
    pub attempt_id: String,
    /// The canonical policy digest of this attempt.
    pub policy_digest: String,
}

/// Parses the complete gate payload read through EOF (§8.2).
///
/// The only valid payload is one UTF-8 JSON object followed by exactly one LF
/// and nothing else. Every other shape refuses, so an extra frame or trailing
/// bytes cannot be accepted after exec.
///
/// # Errors
/// Returns [`ErrorCode::GateClosed`] for an empty payload and
/// [`ErrorCode::GateInvalid`] for every malformed or mismatched frame.
pub fn parse_release(payload: &[u8], expected: &GateExpectation) -> Result<GateFrame, JailError> {
    let invalid = |message: &str| {
        JailError::new(
            ErrorCode::GateInvalid,
            ErrorStage::Prepared,
            Remediation::Configuration,
            message.to_owned(),
        )
    };

    if payload.is_empty() {
        return Err(JailError::new(
            ErrorCode::GateClosed,
            ErrorStage::Prepared,
            Remediation::InspectState,
            "the gate reached EOF without a release frame".to_owned(),
        ));
    }
    if payload.len() > GATE_FRAME_MAX {
        return Err(invalid(&format!(
            "gate payload of {} bytes exceeds the {GATE_FRAME_MAX} byte maximum",
            payload.len()
        )));
    }
    if payload.contains(&b'\r') {
        return Err(invalid("gate frame contains CR; only a single LF is valid"));
    }
    let Some((line, tail)) = payload.split_at_checked(payload.len() - 1) else {
        return Err(invalid("gate frame is empty"));
    };
    if tail != b"\n" {
        return Err(invalid("gate frame does not end in exactly one LF"));
    }
    if line.contains(&b'\n') {
        return Err(invalid("gate payload contains more than one line"));
    }
    let text = std::str::from_utf8(line).map_err(|_| invalid("gate frame is not UTF-8"))?;
    let frame: GateFrame = serde_json::from_str(text).map_err(|error| {
        invalid(&format!(
            "gate frame is not a valid release object: {error}"
        ))
    })?;
    if frame.schema != SCHEMA_GATE {
        return Err(invalid("gate frame has the wrong schema"));
    }
    if frame.action != "release" {
        return Err(invalid("gate frame has the wrong action"));
    }
    if frame.attempt_id != expected.attempt_id {
        return Err(invalid("gate frame names a different attempt"));
    }
    if frame.policy_digest != expected.policy_digest {
        return Err(invalid("gate frame carries a different policy digest"));
    }
    Ok(frame)
}

/// Reads the gate to EOF and parses the single release frame (§8.2).
///
/// Reads one byte past the maximum so an oversized payload is detected rather
/// than truncated into a valid-looking frame.
///
/// # Errors
/// Returns the errors of [`parse_release`], plus [`ErrorCode::GateInvalid`]
/// when the fd cannot be read.
pub fn read_release(
    reader: &mut impl std::io::Read,
    expected: &GateExpectation,
) -> Result<GateFrame, JailError> {
    let mut payload = Vec::new();
    let mut limited = reader.take(u64::try_from(GATE_FRAME_MAX).unwrap_or(u64::MAX) + 1);
    std::io::Read::read_to_end(&mut limited, &mut payload).map_err(|error| {
        JailError::new(
            ErrorCode::GateInvalid,
            ErrorStage::Prepared,
            Remediation::InspectState,
            format!("the gate could not be read: {error}"),
        )
    })?;
    parse_release(&payload, expected)
}

use std::io::Read as _;
