//! What jail state registers before it exists (§7, §8.1 step 2, §12):
//! vendor state and the protocol it shares with the proxy directory, staged
//! credentials' private provenance, the execution leaf, and cleanup
//! progress.

use std::time::SystemTime;

use super::record::state_parse_failed;
use super::{
    AttemptDir, CredentialEntry, DIRECTORY_MODE, Decimal, Field, JailState, Site, VendorStateEntry,
    anchored, open_attempt_dir, read_attempt_state, unsafe_path, update_attempt_state,
    write_failed,
};
use crate::records::{JailError, StateCleanup};

/// The vendor-state directory's name inside an attempt directory (§7).
pub const VENDOR_STATE_NAME: &str = "vendor-state";

/// What jail state records about an attempt's vendor state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VendorRegistration {
    /// The directory's `(dev, ino)`, once it has been created.
    pub identity: Option<(u64, u64)>,
    /// Cleanup progress as last recorded.
    pub state_cleanup: StateCleanup,
    /// The safe reason recorded with a `pending` status, if any.
    pub reason: Option<String>,
}

/// One staged credential's private provenance, kept in jail state only.
///
/// §12: "Source identity/paths and credential contents stay in private
/// operational state, never the receipt." This is that private state: the
/// source object's identity and size, never its path (which `policy.json`
/// already holds) and never its bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateCredential {
    /// The logical id.
    pub id: String,
    /// How it reaches the child: `copy_rw` or `bind_ro`.
    pub mode: crate::policy::CredentialMode,
    /// Source device.
    pub source_dev: u64,
    /// Source inode.
    pub source_ino: u64,
    /// Source size at staging.
    pub source_size: u64,
    /// The content digest as staging computed it (`sha256:…`), or the null
    /// staging recorded. Audit 2026-09-25-2, S6: the receipt publishes no
    /// verifier of secret bytes (it is the artifact meant to be shared, and
    /// a plain digest is an offline guessing oracle); the operator verifies
    /// against this private record instead.
    pub content_digest: Option<String>,
}

/// What jail state says about vendor state, or `None` when none was ever
/// registered.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when jail state cannot be read, and
/// when it names vendor state with a cleanup status it cannot parse.
pub fn vendor_registration(
    attempt_dir: &AttemptDir,
) -> Result<Option<VendorRegistration>, JailError> {
    let state = read_attempt_state(attempt_dir)?;
    let Some(vendor) = state.vendor_state.get() else {
        return Ok(None);
    };
    let state_cleanup = match state.state_cleanup.get() {
        Some(status @ (StateCleanup::Pending | StateCleanup::Complete)) => *status,
        // Registered vendor state is never `not_needed`; no status at all is
        // a state file this tool did not write.
        other => {
            return Err(state_parse_failed(format!(
                "vendor state is registered with cleanup status {other:?}"
            )));
        }
    };
    Ok(Some(VendorRegistration {
        identity: vendor.identity(),
        state_cleanup,
        reason: state.cleanup_reason.get().cloned(),
    }))
}

/// A directory of the attempt that jail state registers before it is
/// created (§7: vendor state, §10: the proxy directory).
pub(crate) struct Registration {
    /// Its name in the attempt directory.
    pub name: &'static str,
    /// What it is, for the refusal when something is already there.
    pub what: &'static str,
    /// Writes the registration, its identity null, before `mkdirat`.
    pub register: fn(&mut JailState),
    /// Records the created directory's `(dev, ino)`.
    pub identify: fn(&mut JailState, (u64, u64)),
    /// Withdraws a registration whose directory this attempt did not make.
    pub withdraw: fn(&mut JailState),
}

/// Registers a directory in jail state, then creates it mode 0700, then
/// records its identity and syncs the attempt directory (§7).
///
/// The registration is durable before `mkdirat` runs, so a crash between
/// the two leaves a registered, absent directory, which cleanup treats as
/// removed, never an unregistered directory nobody will clean. The identity
/// is recorded before anything else can fail: nothing removes a registered
/// directory whose identity was not recorded. Something already there is
/// not this attempt's, and nothing created means nothing to clean: either
/// way the registration is withdrawn, so no later cleanup can remove what
/// this attempt did not make (J3 review H2). An entry this call may have
/// made (a failure after `mkdirat`) stays registered with no identity,
/// which cleanup retains rather than deletes. `between` runs once the
/// registration is durable and before the directory exists.
///
/// # Errors
/// [`ErrorCode::StateWriteFailed`] when a state write or the creation
/// fails, [`ErrorCode::UnsafeStatePath`] when the attempt directory fails
/// its checks or the name already exists.
pub(crate) fn create_registered_dir(
    attempt_dir: &AttemptDir,
    registration: &Registration,
    between: &mut dyn FnMut(&AttemptDir),
) -> Result<anchored::Dir, JailError> {
    let path = attempt_dir.root().join(registration.name);
    update_attempt_state(Site::LaunchState, attempt_dir, registration.register)?;
    between(attempt_dir);
    let attempt = open_attempt_dir(attempt_dir)?;
    let name = anchored::Name::new(registration.name.as_bytes())
        .map_err(|error| write_failed(attempt_dir.root(), &error))?;
    let dir = match attempt.mkdir_at(&name, DIRECTORY_MODE) {
        Ok(dir) => dir,
        Err(error) => {
            let exists = error.kind() == std::io::ErrorKind::AlreadyExists;
            if exists || attempt.stat_at(&name).is_err() {
                update_attempt_state(Site::LaunchState, attempt_dir, registration.withdraw)?;
            }
            return Err(if exists {
                unsafe_path(
                    &path,
                    format!(
                        "already exists in a fresh attempt; it is not this attempt's {}",
                        registration.what
                    ),
                )
            } else {
                write_failed(&path, &error)
            });
        }
    };
    let identity = dir
        .stat()
        .map_err(|error| write_failed(&path, &error))?
        .identity();
    update_attempt_state(Site::LaunchState, attempt_dir, |state| {
        (registration.identify)(state, identity);
    })?;
    attempt
        .sync()
        .map_err(|error| write_failed(attempt_dir.root(), &error))?;
    Ok(dir)
}

/// How vendor state is registered (§7, §12): "Register vendor state before
/// the first copy, create it mode 0700", its cleanup `pending` from then on.
const VENDOR_STATE_REGISTRATION: Registration = Registration {
    name: VENDOR_STATE_NAME,
    what: "vendor state",
    register: |state| {
        state.vendor_state = Field::Set(VendorStateEntry {
            name: Field::Set(VENDOR_STATE_NAME.to_owned()),
            registered_at: Field::Set(crate::records::rfc3339_utc(SystemTime::now())),
            dev: Field::Null,
            ino: Field::Null,
            credentials: Field::Set(Vec::new()),
            rest: serde_json::Map::new(),
        });
        state.state_cleanup = Field::Set(StateCleanup::Pending);
        state.cleanup_reason = Field::Null;
    },
    identify: |state, (dev, ino)| {
        let vendor = state.vendor_state.get_or_insert_default();
        vendor.dev = Field::Set(Decimal(dev));
        vendor.ino = Field::Set(Decimal(ino));
    },
    // Jail state no longer names it, so nothing will ever clean it.
    withdraw: |state| {
        state.vendor_state = Field::Null;
        state.vendor_state_withdrawn =
            Field::Set("the directory was not created by this attempt".to_owned());
        state.state_cleanup = Field::Set(StateCleanup::NotNeeded);
        state.cleanup_reason = Field::Null;
    },
};

/// Registers vendor state in jail state, then creates it
/// ([`create_registered_dir`]); cleanup refuses to delete anything but the
/// directory whose identity it records.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when either state write or the
/// creation fails, and [`ErrorCode::UnsafeStatePath`] when the attempt
/// directory fails its checks or `vendor-state` already exists.
pub fn create_vendor_state(attempt_dir: &AttemptDir) -> Result<anchored::Dir, JailError> {
    create_registered_dir(attempt_dir, &VENDOR_STATE_REGISTRATION, &mut |_| {})
}

/// Records the private provenance of staged credentials in jail state.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when the state write fails.
pub fn record_staged_credentials(
    attempt_dir: &AttemptDir,
    staged: &[PrivateCredential],
) -> Result<(), JailError> {
    let rows: Vec<CredentialEntry> = staged
        .iter()
        .map(|row| CredentialEntry {
            id: row.id.clone(),
            mode: row.mode.as_str().to_owned(),
            source_dev: Decimal(row.source_dev),
            source_ino: Decimal(row.source_ino),
            source_size: Decimal(row.source_size),
            content_digest: Field::or_null(row.content_digest.clone()),
            rest: serde_json::Map::new(),
        })
        .collect();
    update_attempt_state(Site::LaunchState, attempt_dir, |state| {
        state.vendor_state.get_or_insert_default().credentials = Field::Set(rows);
    })
}

// N7
/// Registers the execution leaf in jail state (§7): `identity` `None` names
/// it before `mkdir` (P15), `Some((device, inode))` identifies it right
/// after, before anything is placed in it (P16). `gc` reads the leaf from
/// here, so a crash anywhere after the name is durable leaves a leaf `gc`
/// can find (§14.2).
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when jail state cannot be read or
/// durably replaced, or the path is not UTF-8 (a cgroup path this build
/// makes always is).
#[cfg(target_os = "linux")]
pub fn register_execution_leaf(
    attempt_dir: &AttemptDir,
    path: &std::path::Path,
    identity: Option<(u64, u64)>,
) -> Result<(), JailError> {
    if path.to_str().is_none() {
        return Err(state_parse_failed(format!(
            "the execution leaf path {} is not UTF-8",
            path.display()
        )));
    }
    let site = if identity.is_some() {
        Site::ExecutionLeafIdentity
    } else {
        Site::ExecutionLeaf
    };
    update_attempt_state(site, attempt_dir, |state| {
        state.execution_cgroup = Field::Set(super::LeafEntry::new(path.to_path_buf(), identity));
    })
}

/// Records cleanup progress in jail state, atomically and durably.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when the state write fails.
pub fn record_cleanup(
    attempt_dir: &AttemptDir,
    status: StateCleanup,
    reason: Option<&str>,
) -> Result<(), JailError> {
    record_cleanup_at(Site::CleanupRecord, attempt_dir, status, reason)
}

/// [`record_cleanup`] at a named site (`gc` resuming a cleanup is its own).
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when the state write fails.
pub fn record_cleanup_at(
    site: Site,
    attempt_dir: &AttemptDir,
    status: StateCleanup,
    reason: Option<&str>,
) -> Result<(), JailError> {
    update_attempt_state(site, attempt_dir, |state| {
        state.state_cleanup = Field::Set(status);
        state.cleanup_reason = Field::or_null(reason.map(str::to_owned));
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::ErrorCode;
    use crate::state::testing::{claimed_attempt, raw_state};

    #[test]
    fn a_vendor_state_that_already_exists_is_withdrawn_not_registered() {
        let (_dir, attempt) = claimed_attempt();
        std::fs::create_dir(attempt.vendor_state_path()).unwrap();
        std::fs::write(attempt.vendor_state_path().join("precious"), b"keep").unwrap();
        let error = create_vendor_state(&attempt).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsafeStatePath);
        assert_eq!(vendor_registration(&attempt).unwrap(), None);
        let state = raw_state(&attempt);
        assert_eq!(state["state_cleanup"], "not_needed");
        assert!(attempt.vendor_state_path().join("precious").exists());
    }

    #[test]
    fn created_vendor_state_is_registered_with_its_identity() {
        use std::os::unix::fs::MetadataExt as _;
        let (_dir, attempt) = claimed_attempt();
        let vendor = create_vendor_state(&attempt).unwrap();
        let metadata = std::fs::metadata(attempt.vendor_state_path()).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        let registration = vendor_registration(&attempt).unwrap().unwrap();
        assert_eq!(
            registration.identity,
            Some((metadata.dev(), metadata.ino()))
        );
        assert_eq!(
            registration.state_cleanup,
            crate::records::StateCleanup::Pending
        );
        assert_eq!(
            vendor.stat().unwrap().identity(),
            (metadata.dev(), metadata.ino())
        );
    }
}
