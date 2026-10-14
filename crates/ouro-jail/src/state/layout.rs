//! Where attempt state lives: the configuration and data directories
//! (§6.2), the attempt id grammar and the attempt directory layout (§7).

use std::path::{Path, PathBuf};

use super::{PROXY_DIR_NAME, VENDOR_STATE_NAME, create_private_dir, unsafe_path};
use crate::config::EnvSettings;
use crate::records::{ErrorCode, ErrorStage, JailError, Remediation};

/// Resolves the configuration directory (§6.2).
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when neither `OURO_CONFIG_DIR` nor a
/// home directory names a location.
pub fn config_dir(settings: &EnvSettings, home: Option<&Path>) -> Result<PathBuf, JailError> {
    if let Some(dir) = &settings.config_dir {
        return Ok(dir.clone());
    }
    let home = home.ok_or_else(|| {
        unsafe_path(
            Path::new("~/.config/ouro"),
            "no home directory and no OURO_CONFIG_DIR",
        )
    })?;
    let home = crate::config::absolute_dir(crate::config::HOME_VAR, home)?;
    Ok(home.join(".config").join("ouro"))
}

/// Resolves the runtime state directory (§6.2).
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when neither `OURO_DATA_DIR` nor a
/// home directory names a location.
pub fn data_dir(settings: &EnvSettings, home: Option<&Path>) -> Result<PathBuf, JailError> {
    if let Some(dir) = &settings.data_dir {
        return Ok(dir.clone());
    }
    let home = home.ok_or_else(|| {
        unsafe_path(
            Path::new("~/.local/share/ouro"),
            "no home directory and no OURO_DATA_DIR",
        )
    })?;
    let home = crate::config::absolute_dir(crate::config::HOME_VAR, home)?;
    Ok(home.join(".local").join("share").join("ouro"))
}

/// An attempt identifier: `att_` plus a UUIDv4 with the RFC 9562 variant (§7).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct AttemptId(String);

impl AttemptId {
    /// Allocates a new cryptographically random identifier.
    #[must_use]
    pub fn generate() -> Self {
        AttemptId(format!("att_{}", uuid::Uuid::new_v4()))
    }

    /// Validates a caller-supplied identifier before any path is derived (§7).
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidConfig`], a usage error, when the grammar
    /// does not match. An id is never an arbitrary directory argument.
    pub fn parse(text: &str) -> Result<Self, JailError> {
        let usage = || {
            JailError::new(
                ErrorCode::InvalidConfig,
                ErrorStage::Resolving,
                Remediation::Configuration,
                "an attempt id must be `att_` followed by a lowercase UUIDv4 \
                 with the RFC 9562 variant"
                    .to_owned(),
            )
            .with_key_path("--attempt-id")
        };
        let uuid = text.strip_prefix("att_").ok_or_else(usage)?;
        let groups: Vec<&str> = uuid.split('-').collect();
        if groups.len() != 5 {
            return Err(usage());
        }
        let lengths = [8usize, 4, 4, 4, 12];
        for (group, length) in groups.iter().zip(lengths) {
            if group.len() != length
                || !group
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(usage());
            }
        }
        if !groups[2].starts_with('4') {
            return Err(usage());
        }
        if !matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b') {
            return Err(usage());
        }
        Ok(AttemptId(text.to_owned()))
    }

    /// The identifier as it appears in records.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `jail.lock`'s name inside an attempt directory.
pub const LOCK_NAME: &str = "jail.lock";
/// `jail-state.json`'s name inside an attempt directory.
pub const STATE_NAME: &str = "jail-state.json";
/// `policy.json`'s name inside an attempt directory.
pub const POLICY_NAME: &str = "policy.json";
/// The receipt's name inside an attempt directory.
pub const RECEIPT_NAME: &str = "jail.json";
/// The default trace's name inside an attempt directory.
pub const TRACE_NAME: &str = "trace.ndjson";
/// Managed scratch's name inside an attempt directory.
pub const SCRATCH_NAME: &str = "scratch";
/// The placeholder holders' name inside an attempt directory.
pub const PLACEHOLDERS_NAME: &str = "placeholders";
/// The managed directories of an attempt: removed at settlement, or by `gc`
/// once the tree's end is proven, when the attempt's scratch is managed.
pub const MANAGED_DIRS: [&str; 2] = [SCRATCH_NAME, PLACEHOLDERS_NAME];

/// The attempt directory layout of §7.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AttemptDir {
    root: PathBuf,
}

impl AttemptDir {
    /// `<data>/attempts/<attempt-id>/`.
    #[must_use]
    pub fn new(data_dir: &Path, id: &AttemptId) -> Self {
        AttemptDir {
            root: data_dir.join("attempts").join(id.as_str()),
        }
    }

    // N7
    /// The layout of the attempt rooted at `root`, as a platform that was
    /// handed the attempt directory names it.
    #[must_use]
    pub fn from_root(root: PathBuf) -> Self {
        AttemptDir { root }
    }

    /// The attempt root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `jail.lock`: the exclusive live-supervisor lease.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.root.join(LOCK_NAME)
    }

    /// `jail-state.json`: identity, lifecycle and owned resources.
    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        self.root.join(STATE_NAME)
    }

    /// `policy.json`: the immutable resolved policy envelope.
    #[must_use]
    pub fn policy_path(&self) -> PathBuf {
        self.root.join(POLICY_NAME)
    }

    /// `jail.json`: the latest receipt.
    #[must_use]
    pub fn receipt_path(&self) -> PathBuf {
        self.root.join(RECEIPT_NAME)
    }

    /// `trace.ndjson`: the default bounded standalone event sink.
    #[must_use]
    pub fn trace_path(&self) -> PathBuf {
        self.root.join(TRACE_NAME)
    }

    /// `vendor-state/`: created only when a launch profile requires it.
    #[must_use]
    pub fn vendor_state_path(&self) -> PathBuf {
        self.root.join(VENDOR_STATE_NAME)
    }

    /// `scratch/`: the default child-writable scratch directory.
    #[must_use]
    pub fn scratch_path(&self) -> PathBuf {
        self.root.join(SCRATCH_NAME)
    }

    /// `placeholders/`: the holders of workspace paths a run masks.
    #[must_use]
    pub fn placeholders_path(&self) -> PathBuf {
        self.root.join(PLACEHOLDERS_NAME)
    }

    /// Creates the attempt root, checking every ancestor this tool owns.
    ///
    /// # Errors
    /// Returns [`ErrorCode::UnsafeStatePath`] when the state root or the
    /// attempts directory fails its symlink, ownership or mode check, and
    /// [`ErrorCode::StateWriteFailed`] when a directory cannot be created.
    pub fn create(&self, data_dir: &Path) -> Result<(), JailError> {
        create_private_dir(data_dir)?;
        let attempts = data_dir.join("attempts");
        create_private_dir(&attempts)?;
        create_private_dir(&self.root)?;
        Ok(())
    }
}

/// The jail-owned names of an attempt directory (§7), which an existing
/// attempt root must not already hold before this supervisor claims it.
pub const JAIL_OWNED_NAMES: [&str; 9] = [
    LOCK_NAME,
    STATE_NAME,
    POLICY_NAME,
    RECEIPT_NAME,
    TRACE_NAME,
    VENDOR_STATE_NAME,
    SCRATCH_NAME,
    PLACEHOLDERS_NAME,
    PROXY_DIR_NAME,
];

/// Refuses an attempt root that already holds any jail-owned artifact (§7:
/// "An existing attempt root is acceptable only with validated
/// ownership/permissions and no previous jail state or jail-owned
/// artifacts").
///
/// Called before the lease is taken, so `jail.lock` is checked too: any
/// `jail.lock` present then was not created by this supervisor.
///
/// # Errors
/// Returns [`ErrorCode::AttemptExists`] naming the first artifact found.
pub fn check_fresh_attempt(attempt_dir: &AttemptDir) -> Result<(), JailError> {
    for name in JAIL_OWNED_NAMES {
        match std::fs::symlink_metadata(attempt_dir.root().join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(JailError::new(
                    ErrorCode::AttemptExists,
                    ErrorStage::Resolving,
                    Remediation::InspectState,
                    format!(
                        "the attempt directory already holds the jail-owned `{name}`; a prior \
                         attempt, live or dead, owns it"
                    ),
                ));
            }
            Err(error) => {
                return Err(unsafe_path(
                    &attempt_dir.root().join(name),
                    format!("cannot be inspected: {error}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testing::{UnwrapErrOrPanic as _, private_tempdir};

    #[test]
    fn an_attempt_root_holding_any_jail_owned_artifact_is_not_fresh() {
        // J3 review H2: §7 refuses every jail-owned artifact, not only
        // `jail-state.json`; `jail.lock` included, since the check runs before
        // this supervisor takes its own lease.
        for name in JAIL_OWNED_NAMES {
            let dir = private_tempdir();
            let data = dir.path().canonicalize().unwrap().join("data");
            let attempt = AttemptDir::new(&data, &AttemptId::generate());
            attempt.create(&data).unwrap();
            assert!(
                check_fresh_attempt(&attempt).is_ok(),
                "{name}: empty is fresh"
            );
            std::fs::write(attempt.root().join("owner-reservation.json"), b"{}").unwrap();
            assert!(
                check_fresh_attempt(&attempt).is_ok(),
                "an owner's own file is fine"
            );
            if name.contains('.') {
                std::fs::write(attempt.root().join(name), b"").unwrap();
            } else {
                std::fs::create_dir(attempt.root().join(name)).unwrap();
            }
            let error = check_fresh_attempt(&attempt).unwrap_err();
            assert_eq!(error.code, ErrorCode::AttemptExists, "{name}");
            assert!(error.message.contains(name), "{name}: {}", error.message);
        }
    }

    #[test]
    fn a_generated_attempt_id_round_trips_through_the_grammar() {
        let id = AttemptId::generate();
        assert!(id.as_str().starts_with("att_"));
        assert_eq!(AttemptId::parse(id.as_str()).expect("valid"), id);
    }

    #[test]
    fn a_malformed_attempt_id_is_a_usage_error() {
        for bad in [
            "att_00000000-0000-0000-8000-000000000001",
            "att_00000000-0000-4000-0000-000000000001",
            "att_00000000000040008000000000000001",
            "att_00000000-0000-4000-8000-00000000000G",
            "00000000-0000-4000-8000-000000000001",
            "att_../../etc",
            "att_00000000-0000-4000-8000-000000000001-extra",
            "ATT_00000000-0000-4000-8000-000000000001",
        ] {
            let error = AttemptId::parse(bad)
                .unwrap_err_or_panic(&format!("`{bad}` must refuse the grammar check"));
            assert_eq!(error.code, ErrorCode::InvalidConfig, "{bad}");
            assert_eq!(error.exit_code(), 2, "{bad}");
        }
        assert!(
            AttemptId::parse("att_00000000-0000-4000-b000-000000000001").is_ok(),
            "variant nibble b is valid"
        );
    }
}
