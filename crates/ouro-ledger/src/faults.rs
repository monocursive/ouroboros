//! The one fault seam. Production code names each persistence step it passes
//! with a [`Point`] and each operation it runs in with a [`Scope`]; only the
//! library's own test executable can arm a point. In every other build
//! [`hit`], [`partial_write`], [`enter`] and [`verify_frame`] are empty
//! inline functions: production binaries have no fault configuration,
//! environment switch or fault request to reach.

use std::{fs::File, io};

/// A step of a persistence operation where a test can fail, or kill, the
/// process that is taking it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum Point {
    /// Appending one canonical record to its active segment.
    EventBeforeWrite,
    /// Half of the record is written and synchronized before the fault.
    EventPartialWrite,
    EventBeforeSync,
    EventAfterSync,
    /// A successor segment exists but is not synchronized.
    RotationCreated,
    /// The successor segment and its directory entry are synchronized.
    RotationSynced,
    AppendBeforeDirectorySync,
    AppendAfterDirectorySync,
    /// A durable replacement (see `fsx::replace`) of `Replaced` at `Step`.
    Replace(Replaced, Step),
    /// Re-establishing a pending journal's durability before it is imported.
    JournalReadBeforeFileSync,
    JournalReadBeforeDirectorySync,
    /// Removing a pending journal after its evidence is canonical.
    CleanupBeforeTempUnlink,
    CleanupBeforeStateUnlink,
    CleanupBeforeDirectorySync,
    CleanupAfterDirectorySync,
    /// Publishing a GC retention anchor, then holding it in memory.
    GcIntentWrite,
    GcIntentSync,
    /// Unlinking one inventoried file, and synchronizing its directory.
    GcBeforeUnlink,
    GcAfterUnlink,
    GcDirectorySync,
    /// Publishing the GC completion marker, then synchronizing it.
    GcCompletion,
    GcCompletionSync,
    /// Publishing the pruned run projection.
    GcProjection,
    /// Synchronizing a reader checkpoint's directory.
    ReaderDirectorySync,
    /// The writer is about to send a successful reply.
    ReplyBeforeSend,
}

/// The file a durable replacement publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum Replaced {
    /// `run.json`.
    Projection,
    /// `segments.json`.
    Manifest,
    /// The owner's pending journal snapshot.
    Journal,
}

/// The steps of one durable replacement, in the order it takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum Step {
    BeforeTempUnlink,
    BeforeOpen,
    BeforeWrite,
    /// Half of the bytes are written and synchronized before the fault.
    PartialWrite,
    BeforeSync,
    BeforeRename,
    BeforeDirectorySync,
    AfterDirectorySync,
}

/// The operation a point is passed in, so a plan can fail one operation's
/// step without failing the same step of every other one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum Scope {
    /// Persisting one canonical record of this kind.
    Prepared,
    OwnerClaimed,
    Admitted,
    Denied,
    Settled,
    Note,
    OutcomeUnknown,
    Source,
    /// One pending journal operation. Owners create journals only on Linux.
    #[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
    PendingCreate,
    PendingRead,
    PendingOutage,
    PendingSource,
    PendingCompletion,
    PendingClear,
    PendingRemove,
}

impl Scope {
    /// The scope of persisting a canonical record of `kind`, if a plan can
    /// name it.
    pub(crate) fn of_record(kind: &str) -> Option<Self> {
        Some(match kind {
            "prepared" => Self::Prepared,
            "owner_claimed" => Self::OwnerClaimed,
            "admitted" => Self::Admitted,
            "denied" => Self::Denied,
            "settled" => Self::Settled,
            "note" => Self::Note,
            "outcome_unknown" => Self::OutcomeUnknown,
            "source" => Self::Source,
            _ => return None,
        })
    }

    /// The record a writer request persists, if a plan can name it.
    pub(crate) fn of_request(request: &crate::protocol::Request) -> Option<Self> {
        use crate::protocol::Request;
        match request {
            Request::Prepare { .. } => Some(Self::Prepared),
            Request::ClaimOwner { .. } => Some(Self::OwnerClaimed),
            Request::AppendOwner { kind, .. } => Self::of_record(kind),
            Request::AppendSource { .. } => Some(Self::Source),
            _ => None,
        }
    }
}

pub(crate) use seam::*;

#[cfg(not(test))]
mod seam {
    use super::{File, Point, Scope, io};

    /// Production: nothing is ever armed.
    #[inline(always)]
    pub(crate) fn hit(_: Point) -> io::Result<()> {
        Ok(())
    }

    /// Production: nothing is ever armed.
    #[inline(always)]
    pub(crate) fn partial_write(_: Point, _: &mut File, _: &[u8]) -> io::Result<()> {
        Ok(())
    }

    /// Production: no operation is ever recorded.
    #[inline(always)]
    pub(crate) fn enter(_: impl FnOnce() -> Option<Scope>) -> Entered {
        Entered
    }

    /// Production: verification never waits.
    #[inline(always)]
    pub(crate) fn verify_frame() {}

    pub(crate) struct Entered;
}

#[cfg(test)]
mod seam {
    use std::{
        cell::{Cell, RefCell},
        fs::OpenOptions,
        io::Write as _,
        os::unix::fs::OpenOptionsExt as _,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use serde::{Deserialize, Serialize};

    use super::{File, Point, Scope, Step, io};

    /// What an armed point does once it is reached.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) enum Action {
        /// The step fails with this errno.
        Error(i32),
        /// The process is killed with SIGKILL.
        Kill,
    }

    /// One armed fault.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct Plan {
        /// Only inside this operation; inside any operation when `None`.
        pub scope: Option<Scope>,
        pub point: Point,
        pub action: Action,
        /// Created when the point is reached, before the action, to prove
        /// the plan was not merely armed.
        pub marker: Option<PathBuf>,
        /// Every pass until disarmed, instead of the first one only.
        pub repeat: bool,
    }

    /// The errno a full disk gives before a write, and a failing device at
    /// any other step.
    fn errno(point: Point) -> i32 {
        match point {
            Point::EventBeforeWrite
            | Point::Replace(_, Step::BeforeWrite)
            | Point::GcIntentWrite
            | Point::GcProjection => libc::ENOSPC,
            _ => libc::EIO,
        }
    }

    impl Plan {
        /// Fail the first pass in `scope` with the errno that step would
        /// see, and mark it.
        pub(crate) fn error(scope: Scope, point: Point, marker: PathBuf) -> Self {
            Self {
                scope: Some(scope),
                point,
                action: Action::Error(errno(point)),
                marker: Some(marker),
                repeat: false,
            }
        }

        /// SIGKILL the process at its first pass, and mark it.
        pub(crate) fn kill(scope: Scope, point: Point, marker: PathBuf) -> Self {
            Self {
                scope: Some(scope),
                point,
                action: Action::Kill,
                marker: Some(marker),
                repeat: false,
            }
        }

        /// Fail every pass, in any operation, until disarmed.
        pub(crate) fn fail(point: Point) -> Self {
            Self {
                scope: None,
                point,
                action: Action::Error(errno(point)),
                marker: None,
                repeat: true,
            }
        }
    }

    thread_local! {
        static PLAN: RefCell<Option<Plan>> = const { RefCell::new(None) };
        static SCOPE: Cell<Option<Scope>> = const { Cell::new(None) };
    }

    /// Arm `plan` on this thread, replacing any armed plan.
    pub(crate) fn arm(plan: Plan) {
        PLAN.with(|p| *p.borrow_mut() = Some(plan));
    }

    pub(crate) fn disarm() {
        PLAN.with(|p| p.borrow_mut().take());
    }

    /// Restores the enclosing operation when dropped.
    pub(crate) struct Entered(Option<Scope>);

    impl Drop for Entered {
        fn drop(&mut self) {
            SCOPE.with(|scope| scope.set(self.0));
        }
    }

    /// Record that this thread runs the operation `scope` names.
    pub(crate) fn enter(scope: impl FnOnce() -> Option<Scope>) -> Entered {
        Entered(SCOPE.with(|current| current.replace(scope())))
    }

    /// The armed plan, if `point` is where it fires in the current operation.
    fn armed(point: Point) -> Option<Plan> {
        PLAN.with(|plan| {
            let mut plan = plan.borrow_mut();
            let fires = plan.as_ref().is_some_and(|plan| {
                plan.point == point
                    && plan
                        .scope
                        .is_none_or(|scope| SCOPE.with(|current| current.get() == Some(scope)))
            });
            if !fires {
                return None;
            }
            match plan.as_ref() {
                Some(armed) if armed.repeat => Some(armed.clone()),
                _ => plan.take(),
            }
        })
    }

    fn act(plan: Plan) -> io::Result<()> {
        if let Some(marker) = &plan.marker {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(marker)?;
            file.write_all(
                format!("{:?}:{:?}:{:?}\n", plan.scope, plan.point, plan.action).as_bytes(),
            )?;
            file.sync_all()?;
        }
        match plan.action {
            Action::Error(errno) => Err(io::Error::from_raw_os_error(errno)),
            Action::Kill => {
                // Signal this process only: no cached or reusable external pid.
                // SAFETY: raise takes a signal number by value.
                unsafe {
                    libc::raise(libc::SIGKILL);
                }
                panic!("SIGKILL returned unexpectedly")
            }
        }
    }

    /// Fail or kill here when the armed plan names `point`.
    pub(crate) fn hit(point: Point) -> io::Result<()> {
        armed(point).map_or(Ok(()), act)
    }

    /// When the armed plan names `point`, write and synchronize the first
    /// half of `bytes` before acting, as an interrupted write leaves it.
    pub(crate) fn partial_write(point: Point, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        let Some(plan) = armed(point) else {
            return Ok(());
        };
        file.write_all(&bytes[..bytes.len() / 2])?;
        file.sync_all()?;
        act(plan)
    }

    /// A delay before each canonical frame a fresh verification re-reads. It
    /// is process-wide, so only a dedicated worker process sets it.
    static VERIFY_FRAME_DELAY_MICROS: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn slow_verification(delay: Duration) {
        VERIFY_FRAME_DELAY_MICROS.store(delay.as_micros() as u64, Ordering::Relaxed);
    }

    pub(crate) fn verify_frame() {
        let micros = VERIFY_FRAME_DELAY_MICROS.load(Ordering::Relaxed);
        if micros > 0 {
            std::thread::sleep(Duration::from_micros(micros));
        }
    }
}
