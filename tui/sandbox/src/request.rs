//! The wire format: one JSON object describing the policy for one command.
//!
//! This is the whole protocol. There is no session, no handshake, and no second message:
//! the helper is `exec`-shaped, not server-shaped, because it exists to *become* the
//! command. A JSON-RPC loop would mean the helper outliving the thing it sandboxes, which
//! is the opposite of what `--die-with-parent` buys the bubblewrap backend.
//!
//! ```text
//! ouro-sandbox exec --request '<json>'   -- /bin/sh -c 'ls'
//! ouro-sandbox exec --request-file PATH  -- /bin/sh -c 'ls'
//! ouro-sandbox exec --request-file -     -- /bin/sh -c 'ls'   # one line on stdin
//! ```
//!
//! The daemon uses `--request`. It cannot use stdin: the provider's own exec seam spawns
//! every child with stdin closed (`lib/ouroboros/provider/native/exec.ex`, `{:stdin,
//! :close}`), so a stdin-delivered request would arrive at a closed descriptor. Stdin is
//! supported anyway because it is the ergonomic form for a human and for this crate's own
//! integration tests, and because a request read from a pipe is not visible in `ps`.
//!
//! When the request *is* read from stdin it is read one byte at a time up to the first
//! newline. That is deliberate and not an oversight: a buffered reader would consume
//! bytes past the newline into its own buffer and silently steal them from the command,
//! which inherits this descriptor. The request is a few kilobytes, so the syscall count
//! is irrelevant next to being wrong.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;

/// The only version this helper speaks. A request that omits it is treated as `1`; a
/// request that names anything else is refused rather than interpreted optimistically,
/// because a policy the helper half-understands is a policy with a hole in it.
pub const PROTOCOL_VERSION: u32 = 1;

/// What the workspace may be written through. Mirrors the Elixir
/// `Ouroboros.Provider.Native.Sandbox` mode vocabulary one for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Nothing is writable but the scratch directory.
    ReadOnly,
    /// The writable roots are writable; `.git` and `.ouroboros` beneath them are not.
    WorkspaceWrite,
    /// One approved re-run: as `WorkspaceWrite`, but only `.ouroboros` stays fenced.
    /// The `.git` fence is what the operator just lifted, so re-imposing it here would
    /// make the approval a no-op.
    WorkspaceWriteEscalated,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::ReadOnly => "read_only",
            Mode::WorkspaceWrite => "workspace_write",
            Mode::WorkspaceWriteEscalated => "workspace_write_escalated",
        }
    }

    /// Whether the policy grants any writable root at all beyond scratch.
    pub fn grants_roots(self) -> bool {
        !matches!(self, Mode::ReadOnly)
    }
}

/// Ceilings applied with `setrlimit(2)` before the command is executed.
///
/// Every field is optional and an absent field means "inherit", not "unlimited": this
/// helper never *raises* a limit it was not asked to raise, so a request cannot be used
/// to widen the resource envelope the daemon already runs under.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// `RLIMIT_NPROC`. The fork-bomb fence.
    pub max_processes: Option<u64>,
    /// `RLIMIT_FSIZE`, in bytes. The fill-the-disk fence.
    pub max_file_bytes: Option<u64>,
    /// `RLIMIT_CPU`, in seconds. A belt against the wall-clock deadline the daemon
    /// already imposes; a spinning command is stopped by whichever fires first.
    pub cpu_seconds: Option<u64>,
    /// `RLIMIT_CORE`, in bytes. Defaults to 0 when absent — see `Plan`.
    pub core_bytes: Option<u64>,
}

/// One command's policy, as it arrives on the wire.
///
/// `deny_unknown_fields` is the point of the struct: a daemon that sends a field this
/// helper does not implement gets a refusal, not silent under-enforcement. That is the
/// same reasoning that makes the Elixir side refuse an unrecognised `sandbox_mode`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default = "default_version")]
    pub version: u32,
    pub mode: Mode,
    /// Where the command starts. Absent means "wherever the helper was spawned".
    #[serde(default)]
    pub cwd: Option<String>,
    /// The per-command scratch directory `$TMPDIR` points at. Always writable, whatever
    /// the mode.
    pub scratch: String,
    /// Roots the command may write under, in `workspace_write`.
    #[serde(default)]
    pub writable: Vec<String>,
    /// Absolute locations that stay read-only even when they fall inside a writable root
    /// — the node's data directory, the operator's config.
    #[serde(default)]
    pub protected: Vec<String>,
    /// Path *components* that may never be written or created beneath a writable root:
    /// `.git`, `.ouroboros`.
    #[serde(default)]
    pub denied_names: Vec<String>,
    /// External network. `false` unshares a network namespace.
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub limits: Limits,
    /// The `fs_filter.c` shared object, when the daemon built one.
    ///
    /// It rides in the request rather than in the environment because the daemon's own
    /// exec seam passes children an allowlisted environment, and because this keeps the
    /// Elixir side's `wrap/4` a pure function of the policy. `OUROBOROS_FS_FILTER_LIBRARY`
    /// is honoured as a fallback so the helper stays runnable by hand.
    #[serde(default)]
    pub fs_filter_library: Option<String>,
}

fn default_version() -> u32 {
    PROTOCOL_VERSION
}

/// Why a request could not be turned into a policy.
///
/// Every variant is a *refusal*, never a downgrade. There is no "ignored the bad field
/// and carried on" path in this type, because the caller of this helper is a sandbox and
/// a sandbox that proceeds on a policy it could not parse is worse than one that refuses.
#[derive(Debug, PartialEq, Eq)]
pub enum RequestError {
    UnsupportedVersion(u32),
    Malformed(String),
    NotAbsolute { field: &'static str, path: String },
    EmptyScratch,
    DeniedNameNotAComponent(String),
    WritableWithoutRoots,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestError::UnsupportedVersion(v) => write!(
                f,
                "request version {v} is not supported; this helper speaks version {PROTOCOL_VERSION}"
            ),
            RequestError::Malformed(why) => write!(f, "malformed request: {why}"),
            RequestError::NotAbsolute { field, path } => write!(
                f,
                "{field} must be an absolute path, got {path:?}; a relative path in a \
                 sandbox policy would be resolved against a working directory the policy \
                 itself is about to change"
            ),
            RequestError::EmptyScratch => write!(f, "scratch must be a non-empty absolute path"),
            RequestError::DeniedNameNotAComponent(name) => write!(
                f,
                "denied_names entry {name:?} is not a single path component; this helper \
                 fences names, not paths"
            ),
            RequestError::WritableWithoutRoots => write!(
                f,
                "mode read_only was given writable roots; refusing rather than silently \
                 honouring one of the two"
            ),
        }
    }
}

impl std::error::Error for RequestError {}

/// A validated request. Construction is the validation: there is no way to build one of
/// these that has a relative path or a mode/roots contradiction in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub mode: Mode,
    pub cwd: Option<String>,
    pub scratch: String,
    pub writable: Vec<String>,
    pub protected: Vec<String>,
    pub denied_names: Vec<String>,
    pub network: bool,
    pub limits: Limits,
    pub fs_filter_library: Option<String>,
}

impl Policy {
    /// Parses and validates one JSON request.
    pub fn from_json(raw: &str) -> Result<Policy, RequestError> {
        let request: Request = serde_json::from_str(raw)
            .map_err(|error| RequestError::Malformed(error.to_string()))?;
        Policy::from_request(request)
    }

    pub fn from_request(request: Request) -> Result<Policy, RequestError> {
        if request.version != PROTOCOL_VERSION {
            return Err(RequestError::UnsupportedVersion(request.version));
        }

        if request.scratch.is_empty() {
            return Err(RequestError::EmptyScratch);
        }
        absolute("scratch", &request.scratch)?;

        for path in &request.writable {
            absolute("writable", path)?;
        }
        for path in &request.protected {
            absolute("protected", path)?;
        }

        for name in &request.denied_names {
            if name.is_empty() || name.contains('/') || name == "." || name == ".." {
                return Err(RequestError::DeniedNameNotAComponent(name.clone()));
            }
        }

        if let Some(cwd) = &request.cwd {
            absolute("cwd", cwd)?;
        }

        // A read_only policy that carries writable roots is a caller bug in one of two
        // directions and the helper cannot tell which, so it refuses instead of picking.
        if !request.mode.grants_roots() && !request.writable.is_empty() {
            return Err(RequestError::WritableWithoutRoots);
        }

        Ok(Policy {
            mode: request.mode,
            cwd: request.cwd,
            // The scratch directory is writable by definition, but it is also the one
            // path that must not appear twice in the plan, so it is held apart from
            // `writable` here and re-joined by the plan compiler.
            writable: dedup_sorted(
                request
                    .writable
                    .into_iter()
                    .filter(|p| *p != request.scratch),
            ),
            protected: dedup_sorted(request.protected.into_iter()),
            denied_names: dedup_sorted(request.denied_names.into_iter()),
            scratch: request.scratch,
            network: request.network,
            limits: request.limits,
            fs_filter_library: request.fs_filter_library.filter(|path| !path.is_empty()),
        })
    }
}

fn absolute(field: &'static str, path: &str) -> Result<(), RequestError> {
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(RequestError::NotAbsolute {
            field,
            path: path.to_string(),
        })
    }
}

/// Sorted and de-duplicated. Sorted because the plan this feeds is compared byte for byte
/// in tests, and a policy whose meaning depends on the order two roots arrived in is a
/// policy that is hard to reason about.
fn dedup_sorted<I: Iterator<Item = String>>(items: I) -> Vec<String> {
    items.collect::<BTreeSet<_>>().into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> String {
        r#"{"mode":"read_only","scratch":"/tmp/s"}"#.to_string()
    }

    #[test]
    fn parses_a_minimal_read_only_request() {
        let policy = Policy::from_json(&minimal()).unwrap();
        assert_eq!(policy.mode, Mode::ReadOnly);
        assert_eq!(policy.scratch, "/tmp/s");
        assert!(policy.writable.is_empty());
        assert!(!policy.network);
        assert_eq!(policy.limits, Limits::default());
    }

    #[test]
    fn version_defaults_to_the_only_version_and_rejects_any_other() {
        assert!(Policy::from_json(&minimal()).is_ok());
        assert_eq!(
            Policy::from_json(r#"{"version":2,"mode":"read_only","scratch":"/tmp/s"}"#),
            Err(RequestError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        // The whole point of `deny_unknown_fields`: a daemon that grew a policy knob this
        // helper does not implement must not get a command that runs under the old one.
        let error =
            Policy::from_json(r#"{"mode":"read_only","scratch":"/tmp/s","allow_everything":true}"#)
                .unwrap_err();
        assert!(matches!(error, RequestError::Malformed(_)), "{error:?}");
    }

    #[test]
    fn every_path_field_must_be_absolute() {
        for (field, json) in [
            ("scratch", r#"{"mode":"read_only","scratch":"tmp/s"}"#),
            (
                "writable",
                r#"{"mode":"workspace_write","scratch":"/tmp/s","writable":["ws"]}"#,
            ),
            (
                "protected",
                r#"{"mode":"read_only","scratch":"/tmp/s","protected":["srv"]}"#,
            ),
            (
                "cwd",
                r#"{"mode":"read_only","scratch":"/tmp/s","cwd":"ws"}"#,
            ),
        ] {
            match Policy::from_json(json) {
                Err(RequestError::NotAbsolute { field: got, .. }) => assert_eq!(got, field),
                other => panic!("{field}: expected NotAbsolute, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_denied_name_must_be_one_component() {
        for bad in ["a/b", "", ".", ".."] {
            let json =
                format!(r#"{{"mode":"read_only","scratch":"/tmp/s","denied_names":["{bad}"]}}"#);
            assert!(
                matches!(
                    Policy::from_json(&json),
                    Err(RequestError::DeniedNameNotAComponent(_))
                ),
                "expected refusal for {bad:?}"
            );
        }
        assert!(Policy::from_json(
            r#"{"mode":"read_only","scratch":"/tmp/s","denied_names":[".git"]}"#
        )
        .is_ok());
    }

    #[test]
    fn read_only_with_writable_roots_is_a_contradiction_and_is_refused() {
        assert_eq!(
            Policy::from_json(r#"{"mode":"read_only","scratch":"/tmp/s","writable":["/ws"]}"#),
            Err(RequestError::WritableWithoutRoots)
        );
    }

    #[test]
    fn scratch_is_held_apart_from_the_writable_roots() {
        // The plan compiler mounts scratch itself; a duplicate would mean two mounts at
        // one destination and a plan that no longer reads as the policy.
        let policy = Policy::from_json(
            r#"{"mode":"workspace_write","scratch":"/tmp/s","writable":["/ws","/tmp/s"]}"#,
        )
        .unwrap();
        assert_eq!(policy.writable, vec!["/ws".to_string()]);
    }

    #[test]
    fn roots_are_sorted_and_deduplicated() {
        let policy = Policy::from_json(
            r#"{"mode":"workspace_write","scratch":"/tmp/s","writable":["/b","/a","/b"]}"#,
        )
        .unwrap();
        assert_eq!(policy.writable, vec!["/a".to_string(), "/b".to_string()]);
    }

    #[test]
    fn every_mode_in_the_elixir_vocabulary_round_trips() {
        for (json, mode) in [
            ("read_only", Mode::ReadOnly),
            ("workspace_write", Mode::WorkspaceWrite),
            ("workspace_write_escalated", Mode::WorkspaceWriteEscalated),
        ] {
            let policy =
                Policy::from_json(&format!(r#"{{"mode":"{json}","scratch":"/tmp/s"}}"#)).unwrap();
            assert_eq!(policy.mode, mode);
            assert_eq!(policy.mode.as_str(), json);
        }
    }

    #[test]
    fn an_unknown_mode_is_refused() {
        assert!(matches!(
            Policy::from_json(r#"{"mode":"danger_full_access","scratch":"/tmp/s"}"#),
            Err(RequestError::Malformed(_))
        ));
    }

    #[test]
    fn the_fs_filter_library_rides_in_the_request_and_an_empty_one_is_no_library() {
        let named = Policy::from_json(
            r#"{"mode":"read_only","scratch":"/tmp/s","fs_filter_library":"/priv/f.so"}"#,
        )
        .unwrap();
        assert_eq!(named.fs_filter_library.as_deref(), Some("/priv/f.so"));

        // The daemon sends "" when it has no library built rather than omitting the key,
        // and an empty LD_PRELOAD would make every exec in the sandbox fail.
        let empty =
            Policy::from_json(r#"{"mode":"read_only","scratch":"/tmp/s","fs_filter_library":""}"#)
                .unwrap();
        assert_eq!(empty.fs_filter_library, None);

        let absent = Policy::from_json(&minimal()).unwrap();
        assert_eq!(absent.fs_filter_library, None);
    }

    #[test]
    fn limits_parse_and_default_to_inherit() {
        let policy = Policy::from_json(
            r#"{"mode":"read_only","scratch":"/tmp/s","limits":{"max_processes":64}}"#,
        )
        .unwrap();
        assert_eq!(policy.limits.max_processes, Some(64));
        assert_eq!(policy.limits.max_file_bytes, None);
    }
}
