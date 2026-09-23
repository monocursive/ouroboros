//! The persistence seam: every durable write names its site and goes through
//! one replaceable set of I/O steps (jail-v1 §7, §13.2, §13.3; R02).
//!
//! §7 fixes the steps of a durable replacement: "create-new temporary file,
//! write, file sync, atomic rename, and parent-directory sync". R02 asks that
//! "disk-full/short-write/crash at each snapshot/receipt replacement leaves a
//! valid prior file or explicit incomplete state", which can only be shown by
//! failing each of those steps at each place a record is written. So:
//!
//! - [`Site`] names every such place (P1 to P13 in the J4 plan);
//! - [`PersistIo`] is the set of I/O steps, with the real implementation as
//!   its default methods, so a test replaces exactly the step it fails;
//! - the seam in force is per thread ([`install`], [`current_io`]): the
//!   release binary never installs one and always gets [`RealIo`];
//! - [`crash_point`] is the one test seam the release binary honours:
//!   `OURO_JAIL_TEST_ABORT_AT=<site>:<point>` aborts the process at that named
//!   point of the first replacement at that site, which is how a crash between
//!   two steps is produced without timing (S9). When it is set, it is recorded
//!   in jail state and in every receipt that has native lifetime details.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use super::FILE_MODE;

/// A named place where a record is made durable (R02). The J4 plan numbers
/// them P1 to P13 in this order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Site {
    /// P1: the exclusive claim of `jail-state.json` (§7).
    Claim,
    /// P2: the immutable `policy.json` (§8.1 step 1).
    Policy,
    /// P3: vendor-state, credential and proxy-directory records in jail
    /// state (§7, §10, §12).
    LaunchState,
    /// P4: the registered execution boundary in jail state (§7).
    Boundary,
    /// P5: the `prepared` receipt (§8.1 step 5).
    PreparedReceipt,
    /// P6: the `enforced` receipt after a confirmed exec (§8.1 step 7).
    EnforcedReceipt,
    /// P7: the receipt recording a detected lifetime-integrity loss (§9.3).
    IntegrityReceipt,
    /// P8: the terminal receipt written with `state_cleanup = pending` before
    /// vendor state is removed (§12).
    PendingReceipt,
    /// P9: the terminal receipt: `settled`, or the last nonsettled phase.
    TerminalReceipt,
    /// P10: the `refused` receipt.
    RefusedReceipt,
    /// P11: cleanup progress in jail state (§12).
    CleanupRecord,
    /// P12: `gc` resuming a cleanup: jail state and the receipt it completes.
    GcResume,
    /// P13: `gc`'s record of a dead attempt's proxy directory (§14.2).
    GcProxyDir,
    /// A replacement written through the plain API, outside any site.
    Unnamed,
}

impl Site {
    /// Every named site, P1 to P13.
    pub const ALL: [Site; 13] = [
        Site::Claim,
        Site::Policy,
        Site::LaunchState,
        Site::Boundary,
        Site::PreparedReceipt,
        Site::EnforcedReceipt,
        Site::IntegrityReceipt,
        Site::PendingReceipt,
        Site::TerminalReceipt,
        Site::RefusedReceipt,
        Site::CleanupRecord,
        Site::GcResume,
        Site::GcProxyDir,
    ];

    /// The snake_case name used by [`ABORT_AT_SEAM`] and in test names.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Site::Claim => "claim",
            Site::Policy => "policy",
            Site::LaunchState => "launch_state",
            Site::Boundary => "boundary",
            Site::PreparedReceipt => "prepared_receipt",
            Site::EnforcedReceipt => "enforced_receipt",
            Site::IntegrityReceipt => "integrity_receipt",
            Site::PendingReceipt => "pending_receipt",
            Site::TerminalReceipt => "terminal_receipt",
            Site::RefusedReceipt => "refused_receipt",
            Site::CleanupRecord => "cleanup_record",
            Site::GcResume => "gc_resume",
            Site::GcProxyDir => "gc_proxy_dir",
            Site::Unnamed => "unnamed",
        }
    }

    /// The site with this name, if any.
    #[must_use]
    pub fn parse(text: &str) -> Option<Site> {
        Site::ALL.into_iter().find(|site| site.as_str() == text)
    }
}

/// A named point between two steps of a durable replacement, where
/// [`ABORT_AT_SEAM`] can stop the process.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CrashPoint {
    /// The temporary file exists and holds every byte; nothing is synced.
    TempWritten,
    /// The temporary file is synced; the target is still the prior file.
    TempSynced,
    /// The new file is visible under the target name; the directory entry
    /// is not synced yet.
    Renamed,
    /// The replacement is complete.
    DirSynced,
}

impl CrashPoint {
    /// Every point, in the order a replacement passes them.
    pub const ALL: [CrashPoint; 4] = [
        CrashPoint::TempWritten,
        CrashPoint::TempSynced,
        CrashPoint::Renamed,
        CrashPoint::DirSynced,
    ];

    /// The snake_case name used by [`ABORT_AT_SEAM`].
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CrashPoint::TempWritten => "temp_written",
            CrashPoint::TempSynced => "temp_synced",
            CrashPoint::Renamed => "renamed",
            CrashPoint::DirSynced => "dir_synced",
        }
    }

    /// The point with this name, if any.
    #[must_use]
    pub fn parse(text: &str) -> Option<CrashPoint> {
        CrashPoint::ALL
            .into_iter()
            .find(|point| point.as_str() == text)
    }
}

/// The I/O steps of a durable replacement, as a seam (§7).
///
/// Every method has the real implementation as its default, so a test
/// overrides exactly the step it fails and nothing else changes. `write` is
/// one `write(2)` call: it may write fewer bytes than asked, and the caller
/// loops, which is what makes a short write followed by an error expressible.
pub trait PersistIo {
    /// Creates `path` exclusively, mode 0600, for writing.
    ///
    /// # Errors
    /// The `open` failure.
    fn create_new(&self, site: Site, path: &Path) -> io::Result<File> {
        let _ = site;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(path)
    }

    /// One write of at most `bytes.len()` bytes.
    ///
    /// # Errors
    /// The `write` failure.
    fn write(&self, site: Site, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        let _ = site;
        file.write(bytes)
    }

    /// Flushes the file's own data and metadata.
    ///
    /// # Errors
    /// The `fsync` failure.
    fn sync_file(&self, site: Site, file: &File) -> io::Result<()> {
        let _ = site;
        file.sync_all()
    }

    /// Atomically renames `from` over `to`.
    ///
    /// # Errors
    /// The `rename` failure.
    fn rename(&self, site: Site, from: &Path, to: &Path) -> io::Result<()> {
        let _ = site;
        std::fs::rename(from, to)
    }

    /// Links `from` as `to`, failing with `AlreadyExists` when `to` exists:
    /// the exclusive publication of a complete file (§7's claim).
    ///
    /// # Errors
    /// The `link` failure.
    fn link(&self, site: Site, from: &Path, to: &Path) -> io::Result<()> {
        let _ = site;
        std::fs::hard_link(from, to)
    }

    /// Flushes the directory entry a rename or link created.
    ///
    /// # Errors
    /// The `open` or `fsync` failure.
    fn sync_dir(&self, site: Site, dir: &Path) -> io::Result<()> {
        let _ = site;
        File::open(dir).and_then(|handle| handle.sync_all())
    }

    /// Removes an abandoned temporary file.
    ///
    /// # Errors
    /// The `unlink` failure.
    fn remove(&self, site: Site, path: &Path) -> io::Result<()> {
        let _ = site;
        std::fs::remove_file(path)
    }
}

/// The two durability primitives §7 names, as the narrow seam the J1 tests
/// were written against: every [`Durable`] is a [`PersistIo`] whose other
/// steps are real.
///
/// "A successful rename alone is not a durable acknowledgment", so both calls
/// have to happen and a test has to be able to see that they did.
pub trait Durable {
    /// Flushes the file's own data and metadata.
    ///
    /// # Errors
    /// Returns the underlying `fsync` failure.
    fn sync_file(&self, file: &File) -> io::Result<()>;

    /// Flushes the directory entry created by the rename.
    ///
    /// # Errors
    /// Returns the underlying open or `fsync` failure.
    fn sync_dir(&self, path: &Path) -> io::Result<()>;
}

impl<T: Durable + ?Sized> PersistIo for T {
    fn sync_file(&self, _site: Site, file: &File) -> io::Result<()> {
        Durable::sync_file(self, file)
    }

    fn sync_dir(&self, _site: Site, dir: &Path) -> io::Result<()> {
        Durable::sync_dir(self, dir)
    }
}

/// The real durability implementation of the narrow seam.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fsync;

impl Durable for Fsync {
    fn sync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        File::open(path).and_then(|handle| handle.sync_all())
    }
}

/// The real I/O: every step of [`PersistIo`] as the kernel performs it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RealIo;

impl PersistIo for RealIo {}

/// A seam that can be installed for a thread and handed to another one.
pub type SharedIo = Arc<dyn PersistIo + Send + Sync>;

thread_local! {
    static INSTALLED: RefCell<Option<SharedIo>> = const { RefCell::new(None) };
}

/// The seam in force on this thread: the installed one, or [`RealIo`].
#[must_use]
pub fn current_io() -> SharedIo {
    INSTALLED
        .with(|slot| slot.borrow().clone())
        .unwrap_or_else(|| Arc::new(RealIo))
}

/// Restores the previously installed seam when dropped.
#[must_use = "the seam is uninstalled when this guard is dropped"]
pub struct Installed {
    previous: Option<SharedIo>,
}

impl Drop for Installed {
    fn drop(&mut self) {
        let previous = self.previous.take();
        INSTALLED.with(|slot| *slot.borrow_mut() = previous);
    }
}

/// Installs `io` as this thread's seam until the guard is dropped.
///
/// Library-level only: the release binary never calls it, so a production run
/// always persists through [`RealIo`]. Tests use it to fail one step at one
/// site of a whole supervisor run.
pub fn install(io: SharedIo) -> Installed {
    let previous = INSTALLED.with(|slot| slot.borrow_mut().replace(io));
    Installed { previous }
}

/// Runs `body` with `io` as this thread's seam.
pub fn with_persist_io<R>(io: SharedIo, body: impl FnOnce() -> R) -> R {
    let _installed = install(io);
    body()
}

/// `OURO_JAIL_TEST_ABORT_AT=<site>:<point>`: abort the process at that named
/// point of the first replacement at that site (S9). Test-only; it can only
/// end an attempt early, never widen anything, and it is recorded wherever it
/// is in force. A value that does not name a site and a point is ignored.
pub const ABORT_AT_SEAM: &str = "OURO_JAIL_TEST_ABORT_AT";

fn abort_at() -> Option<(Site, CrashPoint)> {
    static ONCE: OnceLock<Option<(Site, CrashPoint)>> = OnceLock::new();
    *ONCE.get_or_init(|| {
        let raw = std::env::var(ABORT_AT_SEAM).ok()?;
        let (site, point) = raw.split_once(':')?;
        Some((Site::parse(site)?, CrashPoint::parse(point)?))
    })
}

/// Aborts the process when [`ABORT_AT_SEAM`] names this point of this site.
///
/// `abort` runs no destructor, so whatever a crash at this point would leave
/// on disk (a temporary file, an unsynced entry) is left.
pub fn crash_point(site: Site, point: CrashPoint) {
    if abort_at() == Some((site, point)) {
        std::process::abort();
    }
}

/// The test seams in force, for jail state and the receipt's native details
/// (S9: "each recorded in the receipt when set"), or `None` when there are
/// none.
#[must_use]
pub fn test_seams() -> Option<serde_json::Value> {
    let (site, point) = abort_at()?;
    Some(serde_json::json!({
        "abort_at": format!("{}:{}", site.as_str(), point.as_str()),
    }))
}
