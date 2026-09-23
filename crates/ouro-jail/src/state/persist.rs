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
//!   two steps is produced without timing (S9). Every `OURO_JAIL_TEST_*`
//!   variable set, this one included, is recorded in jail state and in every
//!   receipt that has native lifetime details ([`test_seams`]).

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use super::FILE_MODE;

/// A named place where a record is made durable (R02). The J4 plan numbers
/// them P1 to P13 in this order; J4 wave 2 adds P14 to P16.
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
    // J4 W2-S begin: P14 to P16
    /// P14: `gc`'s reconciliation records in jail state (`gc_actions`, S6).
    GcRecord,
    /// P15: the execution leaf's name in jail state, before `mkdir` (N7).
    ExecutionLeaf,
    /// P16: the execution leaf's device and inode in jail state, right after
    /// `mkdir` and before anything is placed in it (N7).
    ExecutionLeafIdentity,
    // J4 W2-S end
    /// A replacement written through the plain API, outside any site.
    Unnamed,
}

impl Site {
    /// Every named site, P1 to P16.
    pub const ALL: [Site; 16] = [
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
        Site::GcRecord,
        Site::ExecutionLeaf,
        Site::ExecutionLeafIdentity,
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
            Site::GcRecord => "gc_record",
            Site::ExecutionLeaf => "execution_leaf",
            Site::ExecutionLeafIdentity => "execution_leaf_identity",
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

/// The prefix of every test seam's environment name (S9).
pub const TEST_SEAM_PREFIX: &str = "OURO_JAIL_TEST_";

/// Every `OURO_JAIL_TEST_*` variable set in `vars`, as an object of name to
/// value, or `None` when none is (S9: "each recorded in the receipt when
/// set").
///
/// The record is a prefix scan, not a list of the seams this build knows, so
/// a seam added later is recorded without anyone remembering to add it here,
/// and a variable that happens to be ignored (an out-of-range value, a name
/// no build uses) is still recorded as set: the record says what the
/// environment asked for, not what each consumer made of it. A value that is
/// not UTF-8 is recorded lossily.
#[must_use]
pub fn test_seams_in(
    vars: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Option<serde_json::Value> {
    let seams: serde_json::Map<String, serde_json::Value> = vars
        .into_iter()
        .filter_map(|(name, value)| {
            let name = name.to_str()?.to_owned();
            name.starts_with(TEST_SEAM_PREFIX).then(|| {
                (
                    name,
                    serde_json::Value::from(value.to_string_lossy().into_owned()),
                )
            })
        })
        .collect();
    (!seams.is_empty()).then_some(serde_json::Value::Object(seams))
}

/// [`test_seams_in`] over this process's environment.
#[must_use]
pub fn test_seams() -> Option<serde_json::Value> {
    test_seams_in(std::env::vars_os())
}

// ---------------------------------------------------------------------------
// The persistence worker (§13.3)
// ---------------------------------------------------------------------------

/// §13.3: "Disk sync runs independently of the supervision loop with a
/// 5-second progress budget."
pub const PERSIST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// Why a persistence step did not complete: the worker made no progress for
/// the whole budget. The step may still complete later; nothing may assume
/// either way.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stalled {
    /// The budget that ran out.
    pub budget: std::time::Duration,
}

impl std::fmt::Display for Stalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "persistence made no progress within its {} second budget",
            self.budget.as_secs()
        )
    }
}

impl From<Stalled> for io::Error {
    fn from(stalled: Stalled) -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, stalled.to_string())
    }
}

type Work = Box<dyn FnOnce() + Send>;

struct Job {
    work: Work,
    /// Set by a waiter that gave up: the job is skipped if it has not
    /// started, so nothing it would have written lands later.
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

/// What the worker and its waiters share: when it last made progress, and
/// how many jobs are outstanding.
struct Shared {
    budget: std::time::Duration,
    last_progress: std::sync::Mutex<std::time::Instant>,
    outstanding: std::sync::atomic::AtomicUsize,
    abandoned: std::sync::atomic::AtomicBool,
    /// J4 W3, P1 (a): the cancellation flag of the job the worker is running,
    /// which every step of that job checks before it starts.
    running: std::sync::Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>,
}

impl Shared {
    fn progress(&self) {
        if let Ok(mut last) = self.last_progress.lock() {
            *last = std::time::Instant::now();
        }
    }

    /// Whether the job the worker is running was given up on: by its waiter
    /// (the budget ran out, or it was dropped) or by the persister.
    fn given_up(&self) -> bool {
        self.abandoned.load(std::sync::atomic::Ordering::SeqCst)
            || self.running.lock().map_or(true, |running| {
                running
                    .as_ref()
                    .is_some_and(|cancelled| cancelled.load(std::sync::atomic::Ordering::SeqCst))
            })
    }

    fn idle(&self) -> bool {
        self.outstanding.load(std::sync::atomic::Ordering::SeqCst) == 0
    }

    /// When the worker, if it makes no further progress, is stalled.
    fn stall_at(&self) -> std::time::Instant {
        let last = self
            .last_progress
            .lock()
            .map_or_else(|_| std::time::Instant::now(), |last| *last);
        last + self.budget
    }

    fn stalled(&self) -> bool {
        self.outstanding.load(std::sync::atomic::Ordering::SeqCst) > 0
            && std::time::Instant::now() >= self.stall_at()
    }
}

/// One thread that performs persistence, so a stalled disk stalls it and not
/// the supervision loop (§8.3: "slow disk/trace I/O must not block signal or
/// deadline handling"; §13.3).
///
/// Its progress budget is a no-progress bound: a job is stalled when the
/// worker has completed no I/O step for [`PERSIST_BUDGET`] while it is
/// outstanding. Work a waiter gave up on is skipped if it has not started,
/// and stops at its next step boundary if it has (J4 W3, P1 (a)): a
/// replacement whose file sync stalled and then completed never goes on to
/// its rename. The one step in progress in the kernel cannot be interrupted
/// and may still complete later, which is why a transition whose persistence
/// stalled is never acknowledged, and why the attempt's lease, once handed
/// to the persister ([`Persister::hold_lease`]), is never released while
/// such a step may be in flight. Dropping the persister abandons every job.
pub struct Persister {
    inner: Arc<Inner>,
    /// The attempt's lease (§7), released only once no persistence work is
    /// in flight (J4 W3, P1 (b)).
    lease: Option<super::Lease>,
}

struct Inner {
    jobs: std::sync::Mutex<Option<std::sync::mpsc::Sender<Job>>>,
    shared: Arc<Shared>,
}

/// A job submitted to the worker.
pub struct Pending<T> {
    result: std::sync::mpsc::Receiver<T>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    shared: Arc<Shared>,
}

impl<T> Drop for Pending<T> {
    fn drop(&mut self) {
        // Nobody will take the result: if the job has not started, it never
        // does, so nothing it would write lands after its waiter moved on.
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Where a submitted job stands.
pub enum Progress<T> {
    /// It completed with this result.
    Done(T),
    /// It is queued or running, and the worker is making progress.
    Waiting,
    /// The worker made no progress within the budget (or is gone).
    Stalled(Stalled),
}

/// A seam that makes every step progress for the worker's budget, and
/// starts no step of a job that was given up on.
struct Progressing {
    inner: SharedIo,
    shared: Arc<Shared>,
}

/// The error a step of abandoned work returns instead of running. Not
/// `Interrupted`, which the write loop retries: abandoned work must end.
fn abandoned_step(site: Site) -> io::Error {
    io::Error::other(format!(
        "the {} write was given up on; its remaining steps do not run (§13.3)",
        site.as_str()
    ))
}

impl Progressing {
    /// J4 W3, P1 (a): the step boundary. A job whose waiter gave up (its
    /// budget ran out, or the persister was dropped) starts no further step,
    /// so a replacement abandoned during its file sync never renames.
    fn admit(&self, site: Site) -> io::Result<()> {
        if self.shared.given_up() {
            return Err(abandoned_step(site));
        }
        Ok(())
    }

    fn step<T>(&self, result: io::Result<T>) -> io::Result<T> {
        self.shared.progress();
        result
    }
}

impl PersistIo for Progressing {
    fn create_new(&self, site: Site, path: &Path) -> io::Result<File> {
        self.admit(site)?;
        self.step(self.inner.create_new(site, path))
    }
    fn write(&self, site: Site, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.admit(site)?;
        self.step(self.inner.write(site, file, bytes))
    }
    fn sync_file(&self, site: Site, file: &File) -> io::Result<()> {
        self.admit(site)?;
        self.step(self.inner.sync_file(site, file))
    }
    fn rename(&self, site: Site, from: &Path, to: &Path) -> io::Result<()> {
        self.admit(site)?;
        self.step(self.inner.rename(site, from, to))
    }
    fn link(&self, site: Site, from: &Path, to: &Path) -> io::Result<()> {
        self.admit(site)?;
        self.step(self.inner.link(site, from, to))
    }
    fn sync_dir(&self, site: Site, dir: &Path) -> io::Result<()> {
        self.admit(site)?;
        self.step(self.inner.sync_dir(site, dir))
    }
    /// Not a step of the work: the removal of the job's own temporary file,
    /// which never replaced anything. It runs even for abandoned work, so
    /// giving up leaves no temporary file behind (a crash still can).
    fn remove(&self, site: Site, path: &Path) -> io::Result<()> {
        self.step(self.inner.remove(site, path))
    }
}

impl Persister {
    /// Starts the worker over this thread's seam, with the §13.3 budget.
    ///
    /// # Errors
    /// The thread could not be spawned.
    pub fn start() -> io::Result<Persister> {
        Persister::start_with(current_io(), PERSIST_BUDGET)
    }

    /// Starts the worker over `io`. `budget` never exceeds
    /// [`PERSIST_BUDGET`]: a caller can only shrink it.
    ///
    /// # Errors
    /// The thread could not be spawned.
    pub fn start_with(io: SharedIo, budget: std::time::Duration) -> io::Result<Persister> {
        let shared = Arc::new(Shared {
            budget: budget.min(PERSIST_BUDGET),
            last_progress: std::sync::Mutex::new(std::time::Instant::now()),
            outstanding: std::sync::atomic::AtomicUsize::new(0),
            abandoned: std::sync::atomic::AtomicBool::new(false),
            running: std::sync::Mutex::new(None),
        });
        let (jobs, queue) = std::sync::mpsc::channel::<Job>();
        let worker_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("ouro-persist".to_owned())
            .spawn(move || {
                let progressing: SharedIo = Arc::new(Progressing {
                    inner: io,
                    shared: Arc::clone(&worker_shared),
                });
                let _installed = install(progressing);
                for job in queue {
                    let skip = job.cancelled.load(std::sync::atomic::Ordering::SeqCst)
                        || worker_shared
                            .abandoned
                            .load(std::sync::atomic::Ordering::SeqCst);
                    if !skip {
                        if let Ok(mut running) = worker_shared.running.lock() {
                            *running = Some(Arc::clone(&job.cancelled));
                        }
                        worker_shared.progress();
                        (job.work)();
                        if let Ok(mut running) = worker_shared.running.lock() {
                            *running = None;
                        }
                    }
                    worker_shared.progress();
                    worker_shared
                        .outstanding
                        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
            })?;
        Ok(Persister {
            inner: Arc::new(Inner {
                jobs: std::sync::Mutex::new(Some(jobs)),
                shared,
            }),
            lease: None,
        })
    }

    /// J4 W3, P1 (b): hands the attempt's lease to the persister, which
    /// releases it when it is dropped only if no persistence work is in
    /// flight by then. §7: "The supervisor holds `jail.lock` through
    /// settlement/cleanup", and a write that may still land is part of that:
    /// a `gc` that took the lease while the supervisor's own rename was in
    /// flight could write the next revision, and the late rename then landed
    /// a different receipt with the same number.
    pub fn hold_lease(&mut self, lease: super::Lease) {
        self.lease = Some(lease);
    }

    /// Queues `work` on the worker; it runs with the worker's seam installed.
    pub fn submit<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Pending<T> {
        self.inner.submit(work)
    }

    /// Runs `work` on the worker and waits for it within the budget.
    ///
    /// # Errors
    /// [`Stalled`] when the worker made no progress within the budget.
    pub fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, Stalled> {
        self.submit(work).wait()
    }

    /// A seam for the supervisor's own thread that performs every step on
    /// the worker and waits for it within the budget: a stalled step returns
    /// a `TimedOut` error to the caller instead of blocking it.
    #[must_use]
    pub fn forwarding(&self) -> SharedIo {
        Arc::new(Forward {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Whether the worker is stalled right now.
    #[must_use]
    pub fn stalled(&self) -> bool {
        self.inner.shared.stalled()
    }

    /// The budget in force.
    #[must_use]
    pub fn budget(&self) -> std::time::Duration {
        self.inner.shared.budget
    }
}

impl Drop for Persister {
    fn drop(&mut self) {
        let shared = &self.inner.shared;
        shared
            .abandoned
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut jobs) = self.inner.jobs.lock() {
            jobs.take();
        }
        let Some(lease) = self.lease.take() else {
            return;
        };
        // Abandoned now, every job stops at its next step boundary and every
        // queued one is skipped: while the worker makes progress this takes
        // at most one step, and a step that makes none for the whole budget
        // is stalled.
        while !shared.idle() && !shared.stalled() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if shared.idle() {
            drop(lease);
        } else {
            // A step is stalled in the kernel and may still complete. The
            // lease is not unlocked: its descriptor stays open, so only the
            // end of the whole process (its last thread, the stalled one
            // included) releases it.
            std::mem::forget(lease);
        }
    }
}

impl Inner {
    fn submit<T: Send + 'static>(&self, work: impl FnOnce() -> T + Send + 'static) -> Pending<T> {
        let (sender, result) = std::sync::mpsc::sync_channel(1);
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let job = Job {
            work: Box::new(move || {
                let _ = sender.send(work());
            }),
            cancelled: Arc::clone(&cancelled),
        };
        // An idle worker's last progress is old; the budget of a new job
        // starts when it is submitted.
        if self
            .shared
            .outstanding
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            self.shared.progress();
        }
        let sent = self
            .jobs
            .lock()
            .ok()
            .and_then(|jobs| jobs.as_ref().map(|jobs| jobs.send(job).is_ok()))
            .unwrap_or(false);
        if !sent {
            // No worker: the job's sender is dropped with it, so the waiter
            // sees a disconnected result, which is reported as stalled.
            self.shared
                .outstanding
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
        Pending {
            result,
            cancelled,
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Pending<T> {
    fn stalled(&self) -> Stalled {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Stalled {
            budget: self.shared.budget,
        }
    }

    /// Where the job stands, without waiting.
    pub fn poll(&self) -> Progress<T> {
        match self.result.try_recv() {
            Ok(value) => Progress::Done(value),
            Err(std::sync::mpsc::TryRecvError::Empty) if !self.shared.stalled() => {
                Progress::Waiting
            }
            Err(_) => Progress::Stalled(self.stalled()),
        }
    }

    /// Waits for the job while the worker makes progress.
    ///
    /// # Errors
    /// [`Stalled`] when it made none within the budget.
    pub fn wait(&self) -> Result<T, Stalled> {
        loop {
            let remaining = self
                .shared
                .stall_at()
                .saturating_duration_since(std::time::Instant::now());
            match self
                .result
                .recv_timeout(remaining.max(std::time::Duration::from_millis(1)))
            {
                Ok(value) => return Ok(value),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) if !self.shared.stalled() => {}
                Err(_) => return Err(self.stalled()),
            }
        }
    }
}

/// The supervisor thread's seam while a [`Persister`] runs: every step is
/// performed on the worker, and a step that stalls returns `TimedOut`.
struct Forward {
    inner: Arc<Inner>,
}

impl Forward {
    fn call<T: Send + 'static>(
        &self,
        work: impl FnOnce(&dyn PersistIo) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        self.inner
            .submit(move || work(&*current_io()))
            .wait()
            .map_err(io::Error::from)?
    }
}

impl PersistIo for Forward {
    fn create_new(&self, site: Site, path: &Path) -> io::Result<File> {
        let path = path.to_path_buf();
        self.call(move |io| io.create_new(site, &path))
    }
    fn write(&self, site: Site, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        let mut file = file.try_clone()?;
        let bytes = bytes.to_vec();
        self.call(move |io| io.write(site, &mut file, &bytes))
    }
    fn sync_file(&self, site: Site, file: &File) -> io::Result<()> {
        let file = file.try_clone()?;
        self.call(move |io| io.sync_file(site, &file))
    }
    fn rename(&self, site: Site, from: &Path, to: &Path) -> io::Result<()> {
        let (from, to) = (from.to_path_buf(), to.to_path_buf());
        self.call(move |io| io.rename(site, &from, &to))
    }
    fn link(&self, site: Site, from: &Path, to: &Path) -> io::Result<()> {
        let (from, to) = (from.to_path_buf(), to.to_path_buf());
        self.call(move |io| io.link(site, &from, &to))
    }
    fn sync_dir(&self, site: Site, dir: &Path) -> io::Result<()> {
        let dir = dir.to_path_buf();
        self.call(move |io| io.sync_dir(site, &dir))
    }
    fn remove(&self, site: Site, path: &Path) -> io::Result<()> {
        let path = path.to_path_buf();
        self.call(move |io| io.remove(site, &path))
    }
}
