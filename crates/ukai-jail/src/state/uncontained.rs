//! The uncontained-run markers (audit 6 F1): when the last `--profile none`
//! run's tree ended, so later runs can refuse trusted files its child could
//! have written.

use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::{DIRECTORY_MODE, Site, TempWrite, current_io, effective_uid, unsafe_path};
use crate::records::{ErrorCode, ErrorStage, JailError, Remediation};

/// Security 2026-09-29 (audit 6 F1): the settled marker's name. A
/// `--profile none` child sees the whole host, so any trusted file
/// (`config.toml`, a launch profile, a `--profile FILE` policy) that existed
/// before the end of such a run could have been written by its child. The
/// marker's own ctime is that end; later runs refuse trusted files that do
/// not postdate it.
const UNCONTAINED_SETTLED: &str = "uncontained.epoch";
/// The live markers' names are `uncontained.<attempt id>.live`: one per
/// uncontained run, written before its target is released and removed only
/// once that run's settled marker is written. While one exists, a run is in
/// progress or ended without settling, and no trusted file can be dated.
const UNCONTAINED_LIVE_PREFIX: &str = "uncontained.";
const UNCONTAINED_LIVE_SUFFIX: &str = ".live";

/// The settled marker's path under a marker directory.
#[must_use]
pub fn uncontained_settled_path(dir: &Path) -> PathBuf {
    dir.join(UNCONTAINED_SETTLED)
}

fn uncontained_live_path(dir: &Path, attempt_id: &str) -> PathBuf {
    dir.join(format!(
        "{UNCONTAINED_LIVE_PREFIX}{attempt_id}{UNCONTAINED_LIVE_SUFFIX}"
    ))
}

/// What the markers say about uncontained runs on this host.
///
/// The markers live in the data directory *and* the configuration
/// directory (review of audit 6 F1): the two are chosen independently
/// (`UKAI_DATA_DIR`, `UKAI_CONFIG_DIR`), and a run that shares either with
/// an uncontained one sees its markers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UncontainedEpoch {
    /// The newest settled marker's ctime: when the last uncontained run's
    /// tree was gone.
    pub settled: Option<SystemTime>,
    /// Live markers: uncontained runs in progress, or ones that ended
    /// without settling (a supervisor killed outright, a settled marker the
    /// run could not write).
    pub live: Vec<PathBuf>,
    /// A settled marker recorded that its live marker was deleted while the
    /// run was live (audit 2026-10-15 M1): the uncontained child shares the
    /// operator's uid, so the whole period the marker was gone is a window
    /// in which any trusted file could have been written undated. No file
    /// can be trusted until the operator checks the configuration and
    /// removes the marker.
    pub undatable: Option<PathBuf>,
}

/// A file's ctime — the one timestamp no unprivileged process can set — as
/// a `SystemTime`, or `None` when it is out of range.
#[must_use]
pub(crate) fn ctime_of(metadata: &std::fs::Metadata) -> Option<SystemTime> {
    let nanos = u32::try_from(metadata.ctime_nsec()).ok()?;
    let secs = u64::try_from(metadata.ctime()).ok()?;
    std::time::UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
}

/// Reads the markers in `dirs`.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] — fail closed, since a guard that
/// cannot see the epoch must not treat every file as newer than it — when a
/// directory or a settled marker cannot be inspected, when a settled marker
/// is not a regular file (a child can put a directory there so the run's
/// own marker cannot be written, review of audit 6 F1), or when its ctime
/// cannot be read.
pub fn uncontained_epoch(dirs: &[&Path]) -> Result<UncontainedEpoch, JailError> {
    let mut epoch = UncontainedEpoch::default();
    for dir in dirs {
        let settled = uncontained_settled_path(dir);
        match std::fs::symlink_metadata(&settled) {
            Ok(metadata) if metadata.is_file() => {
                let changed = ctime_of(&metadata)
                    .ok_or_else(|| unsafe_path(&settled, "the marker's ctime is out of range"))?;
                epoch.settled = epoch.settled.max(Some(changed));
                // Audit 2026-10-15 M1: a settled marker that records the
                // loss of its live marker makes the whole run undatable —
                // and a marker that cannot be read says the same thing,
                // because a guard that cannot see the loss must not date
                // around it.
                if settled_records_loss(&settled).unwrap_or(true) {
                    epoch.undatable = Some(settled.clone());
                }
            }
            Ok(_) => {
                return Err(unsafe_path(
                    &settled,
                    "the uncontained-run marker is not a regular file, so the end of the last \
                     `--profile none` run cannot be dated; check the trusted configuration, \
                     then remove it",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(unsafe_path(
                    &settled,
                    format!("the uncontained-run marker cannot be inspected: {error}"),
                ));
            }
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(unsafe_path(
                    dir,
                    format!("the uncontained-run markers cannot be listed: {error}"),
                ));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|error| {
                unsafe_path(
                    dir,
                    format!("the uncontained-run markers cannot be listed: {error}"),
                )
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(UNCONTAINED_LIVE_PREFIX) && name.ends_with(UNCONTAINED_LIVE_SUFFIX)
            {
                epoch.live.push(entry.path());
            }
        }
    }
    epoch.live.sort();
    Ok(epoch)
}

/// Whether a settled marker's content records that its live marker was lost
/// while the run was live. `Err` when the marker cannot be read, which the
/// caller reads as loss (fail closed).
fn settled_records_loss(settled: &Path) -> std::io::Result<bool> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(settled)?;
    let mut head = [0u8; 128];
    let read = file.read(&mut head)?;
    Ok(head[..read].ends_with(b"loss\n"))
}

/// The guard of one uncontained run's markers.
///
/// [`UncontainedRun::arm`] writes a live marker into every marker
/// directory before the target is released, and refuses the run when it
/// cannot. Dropping the guard — after the run's tree is gone, so no live
/// descendant can order its own writes after the marker — writes the
/// settled marker durably (its directory synced), and only then removes the
/// live one and syncs the directory again, so no crash can leave the live
/// marker gone without the settled one. A failure to settle leaves the live
/// marker in place, which later runs read as "cannot date", so the failure
/// fails closed; it is also reported on stderr, because a `Drop` cannot
/// refuse the run. Every write goes through the persistence seam at
/// [`Site::UncontainedMarker`].
pub(crate) struct UncontainedRun {
    markers: Vec<Marker>,
    /// Whether any live marker vanished — or was left unpinned and so could
    /// not be verified — while the run was live (audit 2026-10-15 M1). The
    /// settled marker records it, and the epoch then refuses every trusted
    /// file until the operator clears it.
    lost: bool,
}

/// One live marker: its directory, its path, its contents, and an `O_PATH`
/// handle on the exact inode that was written. Unlinking the path leaves
/// the handle, and its `st_nlink` reaching zero is the deletion signal.
///
/// The handle is taken just after the seam write (a rename-based durable
/// replace, so the pin cannot be folded into the write), which leaves a
/// window a same-uid process can win: a swap in between pins a
/// replacement, and the original's deletion goes unrecorded. That is
/// forensics only, of the same kind as the poll cadence — what refuses
/// trusted files is a live marker at the path, whatever inode it is.
struct Marker {
    dir: PathBuf,
    live: PathBuf,
    handle: Option<std::os::fd::OwnedFd>,
}

impl UncontainedRun {
    /// Writes this run's live marker into each of `dirs`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when a marker cannot be
    /// written: an uncontained run whose end no later run could date must
    /// not start. Markers already written are removed again.
    pub(crate) fn arm(dirs: &[&Path], attempt_id: &str) -> Result<Self, JailError> {
        let mut run = UncontainedRun {
            markers: Vec::new(),
            lost: false,
        };
        let contents = format!("live pid={} attempt={attempt_id}\n", std::process::id());
        for dir in dirs {
            let live = uncontained_live_path(dir, attempt_id);
            let armed = std::fs::DirBuilder::new()
                .recursive(true)
                .mode(DIRECTORY_MODE)
                .create(dir)
                .map_err(|error| error.to_string())
                .and_then(|()| {
                    write_marker(&live, contents.as_bytes()).map_err(|error| error.message)
                });
            if let Err(error) = armed {
                // Nothing was released yet: the markers already written
                // have nothing to settle.
                for marker in run.markers.drain(..) {
                    let _ = std::fs::remove_file(marker.live);
                }
                return Err(JailError::new(
                    ErrorCode::StateWriteFailed,
                    ErrorStage::Preparing,
                    Remediation::InspectState,
                    format!(
                        "{}: the uncontained-run marker could not be written ({error}); \
                         later runs use it to refuse trusted files an uncontained child \
                         could have written",
                        live.display()
                    ),
                ));
            }
            let handle = pin_live(&live);
            if handle.is_none() {
                // The marker is written and live, but its inode is not
                // pinned, so a deletion cannot be told apart from the
                // pin's own failure. The run stays armed — enforcement
                // needs only a live marker at the path — and the first
                // check reads the unpinned marker as lost, so the settled
                // marker records a loss rather than date across a run
                // whose marker was never verifiable. Said here, so the
                // later loss is not read as an observed deletion.
                eprintln!(
                    "ukai-jail: warning: the live uncontained-run marker {} could not \
                     be pinned; its deletion cannot be detected, and the settled \
                     marker will record the run as lost",
                    live.display()
                );
            }
            run.markers.push(Marker {
                dir: dir.to_path_buf(),
                handle,
                live,
            });
        }
        Ok(run)
    }

    /// Re-verifies every live marker and answers whether one vanished — or
    /// was left unpinned by [`Self::arm`] and so cannot be checked — since
    /// the last check. A vanished marker is rewritten at once — noting the
    /// restoration in its content — so a resolver that reads after this
    /// point refuses trusted files again; the period the marker was gone is
    /// what the settled marker later records as undatable.
    pub(crate) fn verify_live(&mut self) -> bool {
        let mut lost_now = false;
        for marker in &mut self.markers {
            let gone = marker.handle.as_ref().is_none_or(|fd| {
                // SAFETY: `zeroed` produces a `libc::stat` of entirely
                // zero bytes, a valid value `fstat` may overwrite, and the
                // `fstat` call takes the scalar fd of a live descriptor and
                // that one local buffer; nothing else aliases either.
                let statued = unsafe {
                    let mut stat: libc::stat = std::mem::zeroed();
                    let rc = libc::fstat(fd.as_raw_fd(), &mut stat);
                    (rc, stat.st_nlink)
                };
                statued == (0, 0)
            });
            if !gone {
                continue;
            }
            lost_now = true;
            self.lost = true;
            if write_marker(&marker.live, b"restored after deletion\n").is_ok() {
                marker.handle = pin_live(&marker.live);
            }
            // A rewrite that failed leaves the handle on the unlinked
            // inode: the next check reports the loss again, so the failure
            // cannot silently end the detection.
        }
        lost_now
    }
}

impl Drop for UncontainedRun {
    fn drop(&mut self) {
        let contents = format!(
            "settled {}{}\n",
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos()),
            if self.lost { " loss" } else { "" }
        );
        for marker in &self.markers {
            if let Err(error) = settle(&marker.dir, contents.as_bytes()) {
                eprintln!(
                    "ukai-jail: warning: the uncontained-run marker {} could not be written \
                     ({error}); {} stays in place, so later runs refuse every trusted \
                     configuration file until it is checked and the marker removed",
                    uncontained_settled_path(&marker.dir).display(),
                    marker.live.display()
                );
                continue;
            }
            if let Err(error) = remove_marker(&marker.dir, &marker.live) {
                eprintln!(
                    "ukai-jail: warning: the live uncontained-run marker {} could not be \
                     removed durably ({error}); while it stays, later runs refuse every \
                     trusted configuration file",
                    marker.live.display()
                );
            }
        }
    }
}

/// Pins the freshly written live marker: an `O_PATH` handle on the exact
/// inode, so a later `st_nlink == 0` is that inode's unlink, whatever name
/// or replacement appears at the path meanwhile.
fn pin_live(live: &Path) -> Option<std::os::fd::OwnedFd> {
    use std::os::unix::fs::OpenOptionsExt as _;
    // `O_PATH` on Linux (credentials.rs's rule): an open with no I/O side
    // effect, so a special file planted at the path cannot block it and the
    // descriptor names the exact inode whose link count is watched. Elsewhere
    // a nonblocking read descriptor serves the same fstat.
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH | libc::O_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::O_NONBLOCK | libc::O_CLOEXEC;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(live)
        .ok()
        .map(std::os::fd::OwnedFd::from)
}

/// Writes `dir`'s settled marker, first clearing what the uncontained child
/// could have put in its way: a non-file at the marker's path, or the
/// operator's own directory made unwritable. The child is gone by now, so
/// nothing re-creates the obstacle.
fn settle(dir: &Path, contents: &[u8]) -> Result<(), String> {
    let cleared = || -> std::io::Result<()> {
        let metadata = std::fs::symlink_metadata(dir)?;
        if metadata.is_dir()
            && metadata.uid() == effective_uid()
            && metadata.mode() & 0o700 != 0o700
        {
            std::fs::set_permissions(
                dir,
                std::fs::Permissions::from_mode((metadata.mode() & 0o7777) | 0o700),
            )?;
        }
        let settled = uncontained_settled_path(dir);
        match std::fs::symlink_metadata(&settled) {
            Ok(metadata) if metadata.is_dir() => remove_bounded(&settled)?,
            Ok(metadata) if !metadata.is_file() => std::fs::remove_file(&settled)?,
            _ => {}
        }
        Ok(())
    };
    cleared().map_err(|error| error.to_string())?;
    write_marker(&uncontained_settled_path(dir), contents).map_err(|error| error.message)
}

/// Removes the directory tree at `root` with bounded work (audit
/// 2026-10-15 P3): a `none` child can plant an arbitrarily large or deep
/// obstacle at the settled marker's path, and an unbounded walk in `Drop`
/// would spend unbounded time and recursion on it. Past either bound the
/// removal fails, `settle` fails, and the live marker stays — the designed
/// fail-closed outcome.
fn remove_bounded(root: &Path) -> std::io::Result<()> {
    /// Deepest directory chain removed; a deeper tree is an obstacle, not
    /// an accident.
    const MAX_DEPTH: usize = 64;
    /// Total entries removed; a larger tree is the same obstacle.
    const MAX_ENTRIES: usize = 10_000;
    fn walk(dir: &Path, depth: usize, budget: &mut usize) -> std::io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(std::io::Error::other("obstacle deeper than 64 levels"));
        }
        let mut below = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if *budget == 0 {
                return Err(std::io::Error::other("obstacle beyond 10,000 entries"));
            }
            *budget -= 1;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                below.push(path);
            } else {
                std::fs::remove_file(&path)?;
            }
        }
        for path in below {
            walk(&path, depth + 1, budget)?;
            std::fs::remove_dir(&path)?;
        }
        Ok(())
    }
    let mut budget = MAX_ENTRIES;
    walk(root, 0, &mut budget)?;
    std::fs::remove_dir(root)
}

/// Replaces the marker `target` durably through the persistence seam: an
/// exclusively created temporary beside it (never a planted name or link),
/// written and synced, renamed over it, then its directory synced; a failed
/// directory sync fails the write.
fn write_marker(target: &Path, contents: &[u8]) -> Result<(), JailError> {
    let io = current_io();
    TempWrite::create_at(Site::UncontainedMarker, target, contents, &*io)?.commit()
}

/// Removes the live marker `live` from `dir` and syncs `dir`, through the
/// persistence seam, so the removal is as durable as the settled marker
/// written before it.
fn remove_marker(dir: &Path, live: &Path) -> std::io::Result<()> {
    let io = current_io();
    match io.remove(Site::UncontainedMarker, live) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    io.sync_dir(Site::UncontainedMarker, dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testing::{UnwrapErrOrPanic as _, private_tempdir};
    use crate::state::{PersistIo, RealIo, install};

    /// Audit 2026-10-15 M1: deleting the live marker while the run is live
    /// is detected through the pinned inode, the marker is rewritten, and
    /// the settled marker records the loss — which makes every later epoch
    /// refuse to date trusted files until the operator clears it.
    #[test]
    fn a_deleted_live_marker_is_detected_restored_and_settled_with_loss() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let dirs = [data.as_path()];
        let mut guard = UncontainedRun::arm(&dirs, "att_loss").unwrap();
        let live = uncontained_live_path(&data, "att_loss");
        assert!(!guard.verify_live(), "an untouched marker reports no loss");
        std::fs::remove_file(&live).unwrap();
        assert!(guard.verify_live(), "the deletion is detected");
        assert!(
            live.symlink_metadata().is_ok_and(|meta| meta.is_file()),
            "the marker is rewritten immediately"
        );
        assert_eq!(
            std::fs::read(&live).unwrap(),
            b"restored after deletion\n",
            "the rewrite notes the restoration"
        );
        assert!(
            !guard.verify_live(),
            "the restored marker is stable on the next check"
        );
        drop(guard);
        let epoch = uncontained_epoch(&dirs).unwrap();
        assert!(epoch.live.is_empty());
        assert!(
            epoch.undatable.is_some(),
            "the settled marker's loss makes the epoch undatable: {epoch:?}"
        );
        let settled = uncontained_settled_path(&data);
        assert!(
            std::fs::read(&settled).unwrap().ends_with(b"loss\n"),
            "the settled marker records the loss in its content"
        );
    }

    /// Audit 2026-10-15 P3: a directory planted at the settled marker's path
    /// is cleared, and an oversized obstacle fails the settle (leaving the
    /// live marker, the fail-closed outcome) rather than walking it all.
    #[test]
    fn a_settled_path_obstacle_is_cleared_and_an_oversized_one_fails_settle() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let dirs = [data.as_path()];
        {
            let mut guard = UncontainedRun::arm(&dirs, "att_p3a").unwrap();
            std::fs::create_dir_all(uncontained_settled_path(&data).join("nested/deep")).unwrap();
            std::fs::write(
                uncontained_settled_path(&data).join("nested/deep/junk"),
                b"junk",
            )
            .unwrap();
            assert!(!guard.verify_live());
        }
        let settled = uncontained_settled_path(&data);
        assert!(settled.symlink_metadata().is_ok_and(|meta| meta.is_file()));
        // 10,001 planted entries exceed the bound: settle fails, the live
        // marker stays, and the epoch stays undatable.
        std::fs::remove_file(&settled).unwrap();
        std::fs::create_dir_all(&settled).unwrap();
        for n in 0..10_001 {
            std::fs::write(settled.join(format!("f{n}")), b"x").unwrap();
        }
        {
            let mut guard = UncontainedRun::arm(&dirs, "att_p3b").unwrap();
            assert!(!guard.verify_live());
        }
        // The obstacle survives and the live marker stays, so the epoch
        // itself refuses: undatable either way.
        let refused = uncontained_epoch(&dirs).unwrap_err();
        assert!(
            refused.message.contains("cannot be dated"),
            "the obstacle keeps the run undatable: {refused:?}"
        );
        assert!(
            uncontained_live_path(&data, "att_p3b")
                .symlink_metadata()
                .is_ok(),
            "the failed settle leaves the live marker in place"
        );
    }

    #[test]
    fn a_clean_run_settles_without_loss() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let dirs = [data.as_path()];
        let mut guard = UncontainedRun::arm(&dirs, "att_clean").unwrap();
        assert!(!guard.verify_live());
        drop(guard);
        let epoch = uncontained_epoch(&dirs).unwrap();
        assert!(epoch.undatable.is_none(), "{epoch:?}");
        assert!(epoch.settled.is_some());
    }

    #[test]
    fn an_uncontained_run_is_live_until_its_guard_settles_both_marker_directories() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = private_tempdir();
        let data = dir.path().join("data");
        let config = dir.path().join("config");
        std::fs::create_dir_all(&data).unwrap();
        let stale = dir.path().join("stale.toml");
        std::fs::write(&stale, b"x").unwrap();
        let dirs = [data.as_path(), config.as_path()];
        assert_eq!(
            uncontained_epoch(&dirs).unwrap(),
            UncontainedEpoch::default()
        );
        // Armed: a live marker in each directory (the missing config
        // directory is created private), and no settled one yet — a
        // concurrent run cannot date anything.
        let guard = UncontainedRun::arm(&dirs, "att_test").unwrap();
        let live = uncontained_epoch(&dirs).unwrap();
        assert_eq!(live.settled, None);
        assert_eq!(
            live.live,
            vec![
                uncontained_live_path(&config, "att_test"),
                uncontained_live_path(&data, "att_test"),
            ]
        );
        assert_eq!(
            config.symlink_metadata().unwrap().mode() & 0o777,
            0o700,
            "a created marker directory is private"
        );
        // Dropped once the tree is gone: settled markers, live ones gone,
        // the operator's file mode, and a ctime every earlier file predates
        // while a later re-save postdates it — the comparison the
        // supervisor's stale-file guard makes.
        drop(guard);
        let settled = uncontained_epoch(&dirs).unwrap();
        assert!(settled.live.is_empty(), "{settled:?}");
        let epoch = settled.settled.expect("settled on drop");
        for dir in dirs {
            let marker = uncontained_settled_path(dir).symlink_metadata().unwrap();
            assert!(marker.is_file());
            assert_eq!(marker.mode() & 0o777, 0o600);
        }
        let ctime = |path: &Path| ctime_of(&path.symlink_metadata().unwrap()).unwrap();
        assert!(ctime(&stale) <= epoch);
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&stale, b"x").unwrap();
        assert!(ctime(&stale) > epoch);
        // No temporary is left behind.
        for dir in dirs {
            let leftovers: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .filter(|name| name.to_string_lossy().ends_with(".tmp"))
                .collect();
            assert!(leftovers.is_empty(), "{leftovers:?}");
        }
    }

    /// Review of audit 6 F1: the child can put a directory where the settled
    /// marker goes, or make the directory unwritable, so the run's own write
    /// fails. The reader refuses a settled marker that is not a file, and the
    /// guard clears both obstacles before it settles.
    #[test]
    fn a_blocked_settled_marker_fails_closed_and_the_guard_clears_the_obstacle() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let dirs = [data.as_path()];
        let guard = UncontainedRun::arm(&dirs, "att_blocked").unwrap();
        // What the uncontained child does while it runs.
        std::fs::create_dir(uncontained_settled_path(&data)).unwrap();
        std::fs::write(uncontained_settled_path(&data).join("inside"), b"x").unwrap();
        let error = uncontained_epoch(&dirs).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsafeStatePath);
        assert!(error.message.contains("not a regular file"), "{error:?}");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o500)).unwrap();
        drop(guard);
        let epoch = uncontained_epoch(&dirs).unwrap();
        assert!(epoch.settled.is_some(), "{epoch:?}");
        assert!(epoch.live.is_empty(), "{epoch:?}");
        assert!(
            uncontained_settled_path(&data)
                .symlink_metadata()
                .unwrap()
                .is_file()
        );
    }

    /// A settle that cannot be written keeps the live marker, so every later
    /// run still refuses to date trusted files: the failure fails closed.
    #[test]
    fn a_settle_that_cannot_be_written_leaves_the_run_live() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let dirs = [data.as_path()];
        let guard = UncontainedRun::arm(&dirs, "att_unsettled").unwrap();
        // A marker directory replaced by something the guard does not
        // delete: a directory owned by the operator but whose marker path is
        // a non-empty directory it cannot remove because its own child is
        // read-only.
        let blocker = uncontained_settled_path(&data);
        std::fs::create_dir(&blocker).unwrap();
        std::fs::create_dir(blocker.join("locked")).unwrap();
        std::fs::write(blocker.join("locked").join("file"), b"x").unwrap();
        std::fs::set_permissions(
            blocker.join("locked"),
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        drop(guard);
        std::fs::set_permissions(
            blocker.join("locked"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let live = uncontained_live_path(&data, "att_unsettled");
        assert!(
            live.exists(),
            "the live marker must stay when settling failed"
        );
    }

    /// A persistence seam that logs the marker steps that order the settle,
    /// and can fail the markers' directory syncs.
    #[derive(Default)]
    struct MarkerIo {
        steps: std::sync::Mutex<Vec<String>>,
        fail_dir_sync: bool,
    }

    impl MarkerIo {
        fn log(&self, step: &str, path: &Path) {
            let name = path
                .file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
            self.steps.lock().unwrap().push(format!("{step} {name}"));
        }
    }

    impl PersistIo for MarkerIo {
        fn rename(&self, site: Site, from: &Path, to: &Path) -> std::io::Result<()> {
            assert_eq!(site, Site::UncontainedMarker);
            self.log("rename", to);
            RealIo.rename(site, from, to)
        }
        fn sync_dir(&self, site: Site, dir: &Path) -> std::io::Result<()> {
            assert_eq!(site, Site::UncontainedMarker);
            self.log("sync_dir", dir);
            if self.fail_dir_sync {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            RealIo.sync_dir(site, dir)
        }
        fn remove(&self, site: Site, path: &Path) -> std::io::Result<()> {
            assert_eq!(site, Site::UncontainedMarker);
            self.log("remove", path);
            RealIo.remove(site, path)
        }
    }

    /// The settle is durably ordered: the settled marker is renamed and its
    /// directory synced before the live marker is removed, and the removal
    /// is synced too. A crash can then leave both markers, which later runs
    /// read as "cannot date", but never the live one gone without the
    /// settled one.
    #[test]
    fn the_live_marker_goes_only_after_the_settled_one_is_durable() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let guard = UncontainedRun::arm(&[data.as_path()], "att_ordered").unwrap();
        let io = std::sync::Arc::new(MarkerIo::default());
        let installed = install(io.clone());
        drop(guard);
        drop(installed);
        assert_eq!(
            *io.steps.lock().unwrap(),
            [
                "rename uncontained.epoch",
                "sync_dir data",
                "remove uncontained.att_ordered.live",
                "sync_dir data",
            ]
        );
        assert!(!uncontained_live_path(&data, "att_ordered").exists());
    }

    /// A settled marker whose directory sync fails is not durable, so the
    /// settle fails and the live marker stays: later runs keep refusing to
    /// date trusted files rather than trust a marker a crash could lose.
    #[test]
    fn a_settle_whose_directory_sync_fails_leaves_the_run_live() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let guard = UncontainedRun::arm(&[data.as_path()], "att_unsynced").unwrap();
        let io = std::sync::Arc::new(MarkerIo {
            fail_dir_sync: true,
            ..MarkerIo::default()
        });
        let installed = install(io.clone());
        drop(guard);
        drop(installed);
        assert!(
            uncontained_live_path(&data, "att_unsynced").exists(),
            "{:?}",
            io.steps.lock().unwrap()
        );
        assert!(
            !uncontained_epoch(&[data.as_path()])
                .unwrap()
                .live
                .is_empty()
        );
    }

    #[test]
    fn an_uncontained_run_that_cannot_write_its_live_marker_does_not_arm() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let blocked = dir.path().join("file");
        std::fs::write(&blocked, b"x").unwrap();
        // The second directory lies beneath a regular file.
        let config = blocked.join("config");
        let error = UncontainedRun::arm(&[data.as_path(), config.as_path()], "att_refused")
            .err()
            .expect("an unwritable marker directory refuses");
        assert_eq!(error.code, ErrorCode::StateWriteFailed);
        assert!(
            !uncontained_live_path(&data, "att_refused").exists(),
            "the markers already written are removed"
        );
    }

    /// S1: the epoch takes the *newest* settled marker across the marker
    /// directories, not the last directory's. A `config.toml` written
    /// between a newer data-dir marker and an older config-dir marker must
    /// not be dated after the epoch.
    #[test]
    fn the_epoch_takes_the_newest_settled_marker_across_directories() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        let config = dir.path().join("config");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let dirs = [data.as_path(), config.as_path()];
        let ctime = |path: &Path| ctime_of(&path.symlink_metadata().unwrap()).unwrap();
        // The config directory settles first; then a trusted file is
        // written; then the data directory settles last.
        std::fs::write(uncontained_settled_path(&config), b"").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        let trusted = dir.path().join("config.toml");
        std::fs::write(&trusted, b"x").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        std::fs::write(uncontained_settled_path(&data), b"").unwrap();
        let epoch = uncontained_epoch(&dirs).unwrap();
        assert_eq!(
            epoch.settled,
            Some(ctime(&uncontained_settled_path(&data))),
            "the newest marker wins, not the last directory's: a file written \
             between the two markers must not be trusted"
        );
        // The symmetric case: the newest marker is in the config directory.
        std::thread::sleep(std::time::Duration::from_millis(30));
        std::fs::write(uncontained_settled_path(&config), b"").unwrap();
        let epoch = uncontained_epoch(&dirs).unwrap();
        assert_eq!(
            epoch.settled,
            Some(ctime(&uncontained_settled_path(&config)))
        );
    }

    /// S2: a marker directory that cannot be listed is refused, not skipped:
    /// skipping it would hide the live markers of a run in progress or one
    /// that ended without settling, and every trusted file would be dated.
    #[test]
    fn an_unreadable_marker_directory_is_refused_not_skipped() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o300)).unwrap();
        let error = uncontained_epoch(&[data.as_path()])
            .unwrap_err_or_panic("an unreadable marker directory must refuse");
        assert_eq!(error.code, ErrorCode::UnsafeStatePath, "{error:?}");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
