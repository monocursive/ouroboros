//! The uncontained-run markers (audit 6 F1): when the last `--profile none`
//! run's tree ended, so later runs can refuse trusted files its child could
//! have written.

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
/// (`OURO_DATA_DIR`, `OURO_CONFIG_DIR`), and a run that shares either with
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
    markers: Vec<(PathBuf, PathBuf)>,
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
        };
        let contents = format!("live pid={} attempt={attempt_id}\n", std::process::id());
        for dir in dirs {
            let live = uncontained_live_path(dir, attempt_id);
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(DIRECTORY_MODE)
                .create(dir)
                .map_err(|error| error.to_string())
                .and_then(|()| {
                    write_marker(&live, contents.as_bytes()).map_err(|error| error.message)
                })
                .map_err(|error| {
                    // Nothing was released yet: the markers already written
                    // have nothing to settle.
                    for (_, live) in run.markers.drain(..) {
                        let _ = std::fs::remove_file(live);
                    }
                    JailError::new(
                        ErrorCode::StateWriteFailed,
                        ErrorStage::Preparing,
                        Remediation::InspectState,
                        format!(
                            "{}: the uncontained-run marker could not be written ({error}); \
                             later runs use it to refuse trusted files an uncontained child \
                             could have written",
                            live.display()
                        ),
                    )
                })?;
            run.markers.push((dir.to_path_buf(), live));
        }
        Ok(run)
    }
}

impl Drop for UncontainedRun {
    fn drop(&mut self) {
        let contents = format!(
            "settled {}\n",
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        );
        for (dir, live) in &self.markers {
            if let Err(error) = settle(dir, contents.as_bytes()) {
                eprintln!(
                    "ouro-jail: warning: the uncontained-run marker {} could not be written \
                     ({error}); {} stays in place, so later runs refuse every trusted \
                     configuration file until it is checked and the marker removed",
                    uncontained_settled_path(dir).display(),
                    live.display()
                );
                continue;
            }
            if let Err(error) = remove_marker(dir, live) {
                eprintln!(
                    "ouro-jail: warning: the live uncontained-run marker {} could not be \
                     removed durably ({error}); while it stays, later runs refuse every \
                     trusted configuration file",
                    live.display()
                );
            }
        }
    }
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
            Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(&settled)?,
            Ok(metadata) if !metadata.is_file() => std::fs::remove_file(&settled)?,
            _ => {}
        }
        Ok(())
    };
    cleared().map_err(|error| error.to_string())?;
    write_marker(&uncontained_settled_path(dir), contents).map_err(|error| error.message)
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
