//! The proxy directory in jail state (jail-v1 §10, §14.2).
//!
//! A proxy-mode attempt's `proxy/` is registered before it is created
//! ([`create_registered_dir`]), its socket node's identity is recorded once
//! it is bound, and it is removed exactly once, by the supervisor after its
//! proxy stopped or by `gc` after the supervisor died, through one anchored
//! removal ([`remove_registered_dir`]) that only removes the registered
//! directory and, for `gc`, the socket node recorded at bind.

use std::path::PathBuf;

use super::{
    AttemptDir, Decimal, Field, JailState, ProxyDirEntry, Registration, Site, SocketEntry,
    anchored, create_registered_dir, open_attempt_dir, read_attempt_state, update_attempt_state,
};
use crate::records::JailError;

/// The proxy directory's name inside an attempt directory (§10).
pub const PROXY_DIR_NAME: &str = "proxy";
/// The proxy socket's name inside the proxy directory (§10).
pub const PROXY_SOCKET_NAME: &str = "proxy.sock";

impl AttemptDir {
    /// `proxy/`: created only for a proxy-mode profile.
    #[must_use]
    pub fn proxy_dir_path(&self) -> PathBuf {
        self.root().join(PROXY_DIR_NAME)
    }
}

/// How the proxy directory is registered: "an operator-owned 0700
/// directory registered before creation" (§10).
const PROXY_DIR_REGISTRATION: Registration = Registration {
    name: PROXY_DIR_NAME,
    what: "proxy directory",
    register: |state| {
        state.proxy_dir = Field::Set(ProxyDirEntry {
            name: Field::Set(PROXY_DIR_NAME.to_owned()),
            registered_at: Field::Set(crate::records::rfc3339_utc(std::time::SystemTime::now())),
            dev: Field::Null,
            ino: Field::Null,
            removed: Field::Set(false),
            ..ProxyDirEntry::default()
        });
    },
    identify: |state, (dev, ino)| {
        let proxy = state.proxy_dir.get_or_insert_default();
        proxy.dev = Field::Set(Decimal(dev));
        proxy.ino = Field::Set(Decimal(ino));
    },
    withdraw: |state| {
        state.proxy_dir = Field::Null;
        state.proxy_dir_withdrawn =
            Field::Set("the directory was not created by this attempt".to_owned());
    },
};

/// Registers the proxy directory in jail state, then creates it mode 0700
/// ([`create_registered_dir`]).
///
/// # Errors
/// [`crate::records::ErrorCode::StateWriteFailed`] when a state write or the
/// creation fails, [`crate::records::ErrorCode::UnsafeStatePath`] when the
/// attempt directory fails its checks or `proxy` already exists.
pub fn create_proxy_dir(attempt_dir: &AttemptDir) -> Result<anchored::Dir, JailError> {
    create_proxy_dir_observed(attempt_dir, &mut |_| {})
}

/// [`create_proxy_dir`], calling `between` after the registration is durable
/// and before the directory exists: the seam a test uses to observe that
/// order (§10: "registered before creation").
///
/// # Errors
/// As [`create_proxy_dir`].
pub fn create_proxy_dir_observed(
    attempt_dir: &AttemptDir,
    between: &mut dyn FnMut(&AttemptDir),
) -> Result<anchored::Dir, JailError> {
    create_registered_dir(attempt_dir, &PROXY_DIR_REGISTRATION, between)
}

/// The proxy socket node as bound: enough to recognise it after a crash.
/// `(dev, ino)` alone is not an identity across a delete and a recreate
/// (ext4 hands a freed inode straight back), so the node's change time, set
/// when it was created and untouched since, goes with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProxySocketIdentity {
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// Change time, seconds and nanoseconds.
    pub ctime: (i64, i64),
}

impl ProxySocketIdentity {
    /// The identity a `stat` of the node shows.
    #[must_use]
    pub fn of(stat: &anchored::Stat) -> Self {
        ProxySocketIdentity {
            dev: stat.dev,
            ino: stat.ino,
            ctime: stat.ctime,
        }
    }
}

/// Records the bound proxy socket's identity under the registered proxy
/// directory, so `gc` can remove exactly that node after a crash.
///
/// # Errors
/// [`crate::records::ErrorCode::StateWriteFailed`] when the state write
/// fails.
pub fn record_proxy_socket(
    attempt_dir: &AttemptDir,
    socket: &ProxySocketIdentity,
) -> Result<(), JailError> {
    update_attempt_state(Site::LaunchState, attempt_dir, |state| {
        state.proxy_dir.get_or_insert_default().socket = Field::Set(SocketEntry {
            dev: Decimal(socket.dev),
            ino: Decimal(socket.ino),
            ctime_sec: Decimal(socket.ctime.0),
            ctime_nsec: Decimal(socket.ctime.1),
            rest: serde_json::Map::new(),
        });
    })
}

/// What became of the proxy directory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyDirRemoval {
    /// None was registered, or its removal was recorded earlier.
    Nothing,
    /// Removed now (or found already gone), and recorded.
    Removed,
    /// Would be removed (a `gc` dry run).
    WouldRemove,
    /// Retained because it cannot be proven the attempt's own (§14.2:
    /// "unverifiable identities ... are retained"), with the reason: a skip
    /// reported with its reason, not a failed cleanup.
    Retained(&'static str),
    /// Retained because reading or removing it failed: a cleanup that did
    /// not complete (§6.4, `gc` exits 1).
    Failed(&'static str),
}

impl ProxyDirRemoval {
    /// The report's spelling, `None` when there was nothing to do.
    #[must_use]
    pub fn describe(&self) -> Option<String> {
        match self {
            ProxyDirRemoval::Nothing => None,
            ProxyDirRemoval::Removed => Some("removed".to_owned()),
            ProxyDirRemoval::WouldRemove => Some("would_remove".to_owned()),
            ProxyDirRemoval::Retained(reason) => Some(format!("retained: {reason}")),
            ProxyDirRemoval::Failed(reason) => Some(format!("failed: {reason}")),
        }
    }
}

/// Who removes the proxy directory, and so what may be unlinked in it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// The supervisor, once the platform stopped the proxy and removed the
    /// socket node it bound (by its pinned identity): anything still in the
    /// directory is not provably the jail's, so only an empty directory is
    /// removed. It holds nothing the child could write (it is bound
    /// read-only), so this does not wait for tree death.
    Settlement,
    /// `gc`, under the lease of an attempt whose supervisor is gone: its
    /// proxy died with it, and the socket node is unlinked first, only when
    /// its `(dev, ino, ctime)` is the one recorded at bind.
    Gc {
        /// The socket node's identity as recorded, if it was.
        socket: Option<ProxySocketIdentity>,
        /// Report only; change nothing.
        dry_run: bool,
    },
}

/// Removes the registered, empty proxy directory (§10). Settlement removes
/// what the platform left; see [`gc_proxy_dir`] for a dead supervisor's.
///
/// # Errors
/// [`crate::records::ErrorCode::StateWriteFailed`] when jail state cannot be
/// read or updated.
pub fn remove_proxy_dir(attempt_dir: &AttemptDir) -> Result<ProxyDirRemoval, JailError> {
    remove_recorded(attempt_dir, Site::LaunchState, |_| Mode::Settlement)
}

/// `gc` of the proxy directory of an attempt whose supervisor is gone (the
/// caller holds its lease). The socket node is unlinked only when its
/// `(dev, ino, ctime)` is the one recorded when it was bound, and the
/// directory only when it is the registered one and then empty; anything
/// else is retained and said so.
///
/// # Errors
/// [`crate::records::ErrorCode::StateWriteFailed`] when jail state cannot be
/// read or updated.
pub fn gc_proxy_dir(attempt_dir: &AttemptDir, dry_run: bool) -> Result<ProxyDirRemoval, JailError> {
    remove_recorded(attempt_dir, Site::GcProxyDir, |proxy| Mode::Gc {
        socket: proxy.socket.get().map(|socket| ProxySocketIdentity {
            dev: socket.dev.0,
            ino: socket.ino.0,
            ctime: (socket.ctime_sec.0, socket.ctime_nsec.0),
        }),
        dry_run,
    })
}

/// The registered directory's removal in `mode`, recorded at `site`: removed
/// (by `gc`: `removed_by`), retained with the reason, or failed with the
/// reason. A dry run records nothing.
fn remove_recorded(
    attempt_dir: &AttemptDir,
    site: Site,
    mode: impl FnOnce(&ProxyDirEntry) -> Mode,
) -> Result<ProxyDirRemoval, JailError> {
    let state: JailState = read_attempt_state(attempt_dir)?;
    let Some(proxy) = state.proxy_dir.get() else {
        return Ok(ProxyDirRemoval::Nothing);
    };
    if proxy.removed.get() == Some(&true) {
        return Ok(ProxyDirRemoval::Nothing);
    }
    let mode = mode(proxy);
    let outcome = remove_registered_dir(attempt_dir, proxy.identity(), mode);
    if outcome != ProxyDirRemoval::WouldRemove {
        update_attempt_state(site, attempt_dir, |state| {
            let proxy = state.proxy_dir.get_or_insert_default();
            match outcome {
                ProxyDirRemoval::Removed => {
                    proxy.removed = Field::Set(true);
                    if matches!(mode, Mode::Gc { .. }) {
                        proxy.removed_by = Field::Set("gc".to_owned());
                    }
                }
                ProxyDirRemoval::Retained(reason) => proxy.retained = Field::Set(reason.to_owned()),
                ProxyDirRemoval::Failed(reason) => proxy.failed = Field::Set(reason.to_owned()),
                ProxyDirRemoval::Nothing | ProxyDirRemoval::WouldRemove => {}
            }
        })?;
    }
    Ok(outcome)
}

/// The names a proxy directory may hold: its socket node, and nothing else.
const LISTED_NAMES: usize = 1;

/// Removes the registered proxy directory, anchored and never followed, and
/// only while it is the object registered: an identity never recorded was
/// never proven this attempt's. In `Mode::Gc` the recorded socket node is
/// unlinked first; in `Mode::Settlement` nothing in the directory is.
fn remove_registered_dir(
    attempt_dir: &AttemptDir,
    registered: Option<(u64, u64)>,
    mode: Mode,
) -> ProxyDirRemoval {
    let removed = match mode {
        Mode::Gc { dry_run: true, .. } => ProxyDirRemoval::WouldRemove,
        _ => ProxyDirRemoval::Removed,
    };
    let Ok(attempt) = open_attempt_dir(attempt_dir) else {
        return ProxyDirRemoval::Failed("attempt_directory_unusable");
    };
    let Ok(name) = anchored::Name::new(PROXY_DIR_NAME.as_bytes()) else {
        return ProxyDirRemoval::Failed("name_invalid");
    };
    let stat = match attempt.stat_at(&name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return removed,
        Err(_) => return ProxyDirRemoval::Failed("proxy_directory_unreadable"),
    };
    let Some(registered) = registered else {
        // Created, and the supervisor died before it recorded what it
        // created: nothing proves this directory is the one it made.
        return ProxyDirRemoval::Retained("proxy_directory_unrecorded");
    };
    if registered != stat.identity() || stat.kind != anchored::Kind::Directory {
        return ProxyDirRemoval::Retained("proxy_directory_identity_changed");
    }
    if let Mode::Gc { socket, dry_run } = mode {
        match remove_socket(&attempt, &name, &stat, socket, dry_run) {
            Ok(()) if dry_run => return removed,
            Ok(()) => {}
            Err(outcome) => return outcome,
        }
    }
    match attempt.rmdir_at(&name) {
        Ok(()) => {}
        // Anything still in it is not provably the jail's: it is never
        // emptied by name, the directory is retained instead.
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {
            return ProxyDirRemoval::Retained("proxy_directory_not_empty");
        }
        Err(_) => return ProxyDirRemoval::Failed("proxy_directory_removal_failed"),
    }
    if attempt.sync().is_err() {
        return ProxyDirRemoval::Failed("sync_failed");
    }
    removed
}

/// `gc`'s unlink of the socket node recorded at bind, the only object the
/// proxy directory may hold. Anything else there, or a node whose identity
/// is not the recorded one, retains the directory.
fn remove_socket(
    attempt: &anchored::Dir,
    name: &anchored::Name,
    stat: &anchored::Stat,
    socket: Option<ProxySocketIdentity>,
    dry_run: bool,
) -> Result<(), ProxyDirRemoval> {
    let Ok(proxy) = attempt.open_dir_at(name, Some(stat)) else {
        return Err(ProxyDirRemoval::Failed("proxy_directory_unreadable"));
    };
    let Ok(listing) = proxy.names(LISTED_NAMES) else {
        return Err(ProxyDirRemoval::Failed("proxy_directory_unreadable"));
    };
    if !listing.complete {
        return Err(ProxyDirRemoval::Retained(
            "proxy_directory_holds_a_foreign_object",
        ));
    }
    let entries = listing.names;
    let Ok(socket_name) = anchored::Name::new(PROXY_SOCKET_NAME.as_bytes()) else {
        return Err(ProxyDirRemoval::Failed("name_invalid"));
    };
    for entry in &entries {
        if entry.as_bytes() != socket_name.as_bytes() {
            return Err(ProxyDirRemoval::Retained(
                "proxy_directory_holds_a_foreign_object",
            ));
        }
        let Ok(node) = proxy.stat_at(entry) else {
            return Err(ProxyDirRemoval::Failed("proxy_socket_unreadable"));
        };
        match socket {
            None => return Err(ProxyDirRemoval::Retained("proxy_socket_unrecorded")),
            Some(recorded)
                if node.kind == anchored::Kind::Socket
                    && ProxySocketIdentity::of(&node) == recorded => {}
            Some(_) => return Err(ProxyDirRemoval::Retained("proxy_socket_identity_changed")),
        }
    }
    if !dry_run && !entries.is_empty() && proxy.unlink_at(&socket_name).is_err() {
        return Err(ProxyDirRemoval::Failed("proxy_socket_removal_failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::testing::{claimed_attempt, raw_state};
    use super::*;
    use crate::records::ErrorCode;

    #[test]
    fn the_proxy_directory_is_registered_created_private_and_removed_by_identity() {
        use std::os::unix::fs::MetadataExt as _;
        let (_dir, attempt) = claimed_attempt();
        let proxy = create_proxy_dir(&attempt).unwrap();
        let metadata = std::fs::metadata(attempt.proxy_dir_path()).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        let state = raw_state(&attempt);
        assert_eq!(state["proxy_dir"]["dev"], metadata.dev().to_string());
        assert_eq!(state["proxy_dir"]["ino"], metadata.ino().to_string());
        assert_eq!(
            proxy.stat().unwrap().identity(),
            (metadata.dev(), metadata.ino())
        );
        // A leftover socket node is not provably ours: retained, not deleted.
        // Bound through the directory descriptor: macOS's 104-byte
        // `sun_path` cannot hold a temporary attempt path.
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;
            let _listener = std::os::unix::net::UnixListener::bind(format!(
                "/proc/self/fd/{}/{PROXY_SOCKET_NAME}",
                proxy.as_fd().as_raw_fd()
            ))
            .unwrap();
            assert_eq!(
                remove_proxy_dir(&attempt).unwrap(),
                ProxyDirRemoval::Retained("proxy_directory_not_empty")
            );
            assert!(attempt.proxy_dir_path().join(PROXY_SOCKET_NAME).exists());
            std::fs::remove_file(attempt.proxy_dir_path().join(PROXY_SOCKET_NAME)).unwrap();
        }
        assert_eq!(
            remove_proxy_dir(&attempt).unwrap(),
            ProxyDirRemoval::Removed
        );
        assert!(!attempt.proxy_dir_path().exists());
        assert_eq!(raw_state(&attempt)["proxy_dir"]["removed"], true);
        assert_eq!(
            remove_proxy_dir(&attempt).unwrap(),
            ProxyDirRemoval::Nothing,
            "a removal recorded earlier"
        );
    }

    #[test]
    fn the_proxy_directory_is_registered_before_it_exists() {
        let (_dir, attempt) = claimed_attempt();
        let mut seen = None;
        let _proxy = create_proxy_dir_observed(&attempt, &mut |attempt| {
            let state = raw_state(attempt);
            seen = Some((
                state["proxy_dir"]["name"].clone(),
                state["proxy_dir"]["ino"].clone(),
                attempt.proxy_dir_path().exists(),
            ));
        })
        .unwrap();
        assert_eq!(
            seen,
            Some((serde_json::json!("proxy"), serde_json::Value::Null, false)),
            "registered, identity not yet known, directory not yet there"
        );
    }

    #[test]
    fn gc_retains_a_proxy_directory_whose_identity_was_never_recorded() {
        let (_dir, attempt) = claimed_attempt();
        drop(create_proxy_dir(&attempt).unwrap());
        update_attempt_state(Site::Unnamed, &attempt, |state| {
            let proxy = state.proxy_dir.get_or_insert_default();
            proxy.dev = Field::Null;
            proxy.ino = Field::Null;
        })
        .unwrap();
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirRemoval::Retained("proxy_directory_unrecorded")
        );
        assert!(attempt.proxy_dir_path().exists());
        assert_eq!(
            raw_state(&attempt)["proxy_dir"]["retained"],
            "proxy_directory_unrecorded"
        );
        // Registered and never created (the supervisor died in between):
        // nothing to remove, and it is recorded as done.
        let (_dir, attempt) = claimed_attempt();
        drop(create_proxy_dir(&attempt).unwrap());
        std::fs::remove_dir(attempt.proxy_dir_path()).unwrap();
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirRemoval::Removed
        );
    }

    #[cfg(target_os = "linux")]
    fn bind_in(proxy: &anchored::Dir) -> std::os::unix::net::UnixListener {
        use std::os::fd::AsRawFd as _;
        std::os::unix::net::UnixListener::bind(format!(
            "/proc/self/fd/{}/{PROXY_SOCKET_NAME}",
            proxy.as_fd().as_raw_fd()
        ))
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_removes_the_recorded_socket_node_and_the_directory_and_records_it() {
        let (_dir, attempt) = claimed_attempt();
        let proxy = create_proxy_dir(&attempt).unwrap();
        drop(bind_in(&proxy));
        let name = anchored::Name::new(PROXY_SOCKET_NAME.as_bytes()).unwrap();
        let node = proxy.stat_at(&name).unwrap();
        record_proxy_socket(&attempt, &ProxySocketIdentity::of(&node)).unwrap();
        assert_eq!(
            gc_proxy_dir(&attempt, true).unwrap(),
            ProxyDirRemoval::WouldRemove
        );
        assert!(
            attempt.proxy_dir_path().join(PROXY_SOCKET_NAME).exists(),
            "dry run"
        );
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirRemoval::Removed
        );
        assert!(!attempt.proxy_dir_path().exists());
        let state = raw_state(&attempt);
        assert_eq!(state["proxy_dir"]["removed"], true);
        assert_eq!(state["proxy_dir"]["removed_by"], "gc");
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirRemoval::Nothing
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_retains_a_socket_it_cannot_prove_it_bound() {
        // Unrecorded: the supervisor died between bind and record.
        let (_dir, attempt) = claimed_attempt();
        let proxy = create_proxy_dir(&attempt).unwrap();
        drop(bind_in(&proxy));
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirRemoval::Retained("proxy_socket_unrecorded")
        );
        assert!(attempt.proxy_dir_path().join(PROXY_SOCKET_NAME).exists());
        // Replaced after it was recorded, by a node that may even reuse the
        // freed inode number: the change time tells them apart.
        let (_dir, attempt) = claimed_attempt();
        let proxy = create_proxy_dir(&attempt).unwrap();
        drop(bind_in(&proxy));
        let name = anchored::Name::new(PROXY_SOCKET_NAME.as_bytes()).unwrap();
        let node = proxy.stat_at(&name).unwrap();
        record_proxy_socket(&attempt, &ProxySocketIdentity::of(&node)).unwrap();
        proxy.unlink_at(&name).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        drop(bind_in(&proxy));
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirRemoval::Retained("proxy_socket_identity_changed")
        );
        assert!(attempt.proxy_dir_path().join(PROXY_SOCKET_NAME).exists());
        // Anything else in the directory is not the jail's to delete.
        let (_dir, attempt) = claimed_attempt();
        drop(create_proxy_dir(&attempt).unwrap());
        std::fs::write(attempt.proxy_dir_path().join("other"), b"x").unwrap();
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirRemoval::Retained("proxy_directory_holds_a_foreign_object")
        );
        assert!(attempt.proxy_dir_path().join("other").exists());
    }

    #[test]
    fn a_replaced_or_populated_proxy_directory_is_retained() {
        let (_dir, attempt) = claimed_attempt();
        drop(create_proxy_dir(&attempt).unwrap());
        std::fs::write(attempt.proxy_dir_path().join("keep"), b"not ours").unwrap();
        assert_eq!(
            remove_proxy_dir(&attempt).unwrap(),
            ProxyDirRemoval::Retained("proxy_directory_not_empty")
        );
        assert!(attempt.proxy_dir_path().join("keep").exists());

        let (_dir, attempt) = claimed_attempt();
        // Held open, so the replacement cannot be handed the same inode
        // number (ext4 reuses a freed one at once).
        let _held = create_proxy_dir(&attempt).unwrap();
        std::fs::remove_dir(attempt.proxy_dir_path()).unwrap();
        std::fs::create_dir(attempt.proxy_dir_path()).unwrap();
        assert_eq!(
            remove_proxy_dir(&attempt).unwrap(),
            ProxyDirRemoval::Retained("proxy_directory_identity_changed"),
            "a directory that is not the registered one is never removed"
        );
        assert!(attempt.proxy_dir_path().exists());

        let (_dir, attempt) = claimed_attempt();
        std::fs::create_dir(attempt.proxy_dir_path()).unwrap();
        assert_eq!(
            create_proxy_dir(&attempt).unwrap_err().code,
            ErrorCode::UnsafeStatePath
        );
        assert_eq!(
            remove_proxy_dir(&attempt).unwrap(),
            ProxyDirRemoval::Nothing
        );
        assert!(attempt.proxy_dir_path().exists(), "not ours, never removed");
    }

    /// Both removals call a directory whose identity was never recorded what
    /// it is: unrecorded, never proven this attempt's (settlement used to
    /// call it changed).
    #[test]
    fn both_removals_retain_an_unrecorded_directory_as_unrecorded() {
        for gc in [false, true] {
            let (_dir, attempt) = claimed_attempt();
            drop(create_proxy_dir(&attempt).unwrap());
            update_attempt_state(Site::Unnamed, &attempt, |state| {
                let proxy = state.proxy_dir.get_or_insert_default();
                proxy.dev = Field::Null;
                proxy.ino = Field::Null;
            })
            .unwrap();
            let outcome = if gc {
                gc_proxy_dir(&attempt, false).unwrap()
            } else {
                remove_proxy_dir(&attempt).unwrap()
            };
            assert_eq!(
                outcome,
                ProxyDirRemoval::Retained("proxy_directory_unrecorded"),
                "gc {gc}"
            );
            assert!(attempt.proxy_dir_path().exists());
        }
    }

    /// A removal that could not read or remove what it had to is a failed
    /// cleanup (§6.4), not a retention: both removals say so, and jail state
    /// records it as `failed`, never as `retained`.
    #[test]
    fn both_removals_record_a_failure_as_failed() {
        use std::os::unix::fs::PermissionsExt as _;
        for gc in [false, true] {
            let (_dir, attempt) = claimed_attempt();
            drop(create_proxy_dir(&attempt).unwrap());
            // An attempt directory others can read fails its checks.
            std::fs::set_permissions(attempt.root(), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            let outcome = if gc {
                gc_proxy_dir(&attempt, false).unwrap()
            } else {
                remove_proxy_dir(&attempt).unwrap()
            };
            std::fs::set_permissions(attempt.root(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            assert_eq!(
                outcome,
                ProxyDirRemoval::Failed("attempt_directory_unusable"),
                "gc {gc}"
            );
            let state = raw_state(&attempt);
            assert_eq!(
                state["proxy_dir"]["failed"], "attempt_directory_unusable",
                "gc {gc}"
            );
            assert!(state["proxy_dir"].get("retained").is_none(), "gc {gc}");
            assert!(attempt.proxy_dir_path().exists());
        }
    }
}
