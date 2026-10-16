//! Attempt state: directories, ids, the durable replacement and the lease.
//!
//! Implements jail-v1 §6.2 (state paths and their safety rules) and §7 (attempt
//! id grammar, the attempt directory layout and durable persistence), one
//! concern per module, every item re-exported here.
//!
//! A successful rename alone is not a durable acknowledgment (§7), so a
//! replacement is: create a new temporary file in the same directory, write,
//! `fsync` the file, rename, then `fsync` the parent directory. The temporary
//! file is only ever renamed by [`TempWrite::commit`] (or linked by
//! [`TempWrite::publish_new`] for the exclusive claim), so an abandoned write
//! leaves the previous file untouched. Every step goes through the persistence
//! seam of [`persist`], and every write names its site (R02).

use std::path::Path;

use crate::records::{ErrorCode, ErrorStage, JailError, Remediation};

pub(crate) mod accounts;
pub mod anchored;
mod durable;
mod layout;
mod lease;
pub mod mount_alias;
#[cfg(target_os = "linux")]
pub(crate) mod mountinfo;
// The persistence seam (§7, §13.2, §13.3; R02)
pub(crate) mod persist;
pub(crate) mod proxy_dir;
pub(crate) mod record;
mod registration;
mod safety;
mod uncontained;

pub use crate::sys::{effective_gid, effective_uid, real_uid};
pub use durable::{
    Published, TempWrite, create_exclusively_at, leftover_temp_files, replace_atomically,
};
pub(crate) use durable::{
    is_record_temp_name, leftover_temp_files_within, replace_atomically_at, write_fully,
};
pub use layout::{
    AttemptDir, AttemptId, JAIL_OWNED_NAMES, SCRATCH_NAME, check_fresh_attempt, config_dir,
    data_dir,
};
pub(crate) use layout::{MANAGED_DIRS, POLICY_NAME, RECEIPT_NAME, STATE_NAME};
pub use lease::{Lease, LeaseProbe};
pub use persist::{
    ABORT_AT_SEAM, PersistIo, Persister, RealIo, Site, test_seams_in, with_persist_io,
};
pub(crate) use persist::{
    CrashPoint, Installed, Pending, Progress, Stalled, crash_point, current_io, install,
    plain_decimal, test_seams,
};
#[cfg(target_os = "linux")]
pub(crate) use proxy_dir::PROXY_SOCKET_NAME;
pub use proxy_dir::{PROXY_DIR_NAME, ProxySocketIdentity};
pub(crate) use proxy_dir::{
    ProxyDirRemoval, create_proxy_dir, gc_proxy_dir, record_proxy_socket, remove_proxy_dir,
};
pub(crate) use record::{
    CredentialEntry, Decimal, Field, GcAction, JailState, LeafEntry, Owner, ProxyDirEntry,
    SCHEMA_STATE, STATE_FILE_MAX, SocketEntry, VendorStateEntry, read_attempt_state,
    update_attempt_state,
};
#[cfg(target_os = "linux")]
pub(crate) use registration::register_execution_leaf;
pub(crate) use registration::{
    PrivateCredential, VENDOR_STATE_NAME, create_vendor_state, record_cleanup, record_cleanup_at,
    record_staged_credentials, vendor_registration,
};
pub(crate) use registration::{Registration, create_registered_dir};
pub(crate) use safety::{
    DIRECTORY_MODE, FILE_MODE, check_state_file, create_private_dir, open_attempt_dir, read_capped,
    read_capped_checked, writable_by_others,
};
pub use safety::{check_ownership, check_state_dir};
pub use uncontained::uncontained_settled_path;
pub(crate) use uncontained::{UncontainedEpoch, uncontained_epoch};
pub(crate) use uncontained::{UncontainedRun, ctime_of};

fn unsafe_path(path: &Path, message: impl Into<String>) -> JailError {
    JailError::new(
        ErrorCode::UnsafeStatePath,
        ErrorStage::Resolving,
        Remediation::HostSetup,
        format!("{}: {}", path.display(), message.into()),
    )
}

fn write_failed(path: &Path, error: &std::io::Error) -> JailError {
    JailError::new(
        ErrorCode::StateWriteFailed,
        ErrorStage::Preparing,
        Remediation::InspectState,
        format!("{}: {error}", path.display()),
    )
}

/// What the state modules' tests share.
#[cfg(test)]
pub(crate) mod testing {
    use super::{AttemptDir, AttemptId, SCHEMA_STATE, replace_atomically};

    /// A 0700 temporary directory whatever the umask: a state root under a
    /// group-writable one is refused, rightly.
    pub(crate) fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("a temporary directory")
    }

    /// Jail state as the JSON on disk.
    pub(crate) fn raw_state(attempt: &AttemptDir) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(attempt.state_path()).unwrap()).unwrap()
    }

    /// A claimed attempt root whose jail state registers nothing.
    pub(crate) fn claimed_attempt() -> (tempfile::TempDir, AttemptDir) {
        let dir = private_tempdir();
        let data = dir.path().canonicalize().unwrap().join("data");
        let attempt = AttemptDir::new(&data, &AttemptId::generate());
        attempt.create(&data).unwrap();
        let state = serde_json::json!({
            "schema": SCHEMA_STATE,
            "vendor_state": null,
            "state_cleanup": "not_needed",
        });
        replace_atomically(&attempt.state_path(), &serde_json::to_vec(&state).unwrap()).unwrap();
        (dir, attempt)
    }

    /// `expect_err` with a caller-supplied message, so a passing case names the
    /// input that was supposed to refuse.
    pub(crate) trait UnwrapErrOrPanic<E> {
        fn unwrap_err_or_panic(self, message: &str) -> E;
    }

    impl<T: std::fmt::Debug, E> UnwrapErrOrPanic<E> for Result<T, E> {
        fn unwrap_err_or_panic(self, message: &str) -> E {
            match self {
                Ok(value) => panic!("{message}, got {value:?}"),
                Err(error) => error,
            }
        }
    }
}
