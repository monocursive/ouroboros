//! The host seam: the only place `gc` asks the host anything or changes it
//! (the recorded owner's liveness, and the identity-checked probe, kill and
//! removal of the execution cgroup; on Linux `platform::linux::reconcile`).

use std::borrow::Cow;
use std::fmt;
use std::io;
use std::path::Path;
use std::time::Duration;

use crate::records::Os;
use crate::supervisor::Context;

/// Who is running `gc`: the platform identity and the current boot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HostIdentity {
    /// The OS this build runs on.
    pub os: Os,
    /// The architecture string the platform records in state.
    pub arch: String,
    /// The current boot, where the platform can name one.
    pub boot_id: Option<String>,
}

/// The supervisor birth identity jail state recorded (§7).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OwnerRecord {
    /// The pid as recorded: a number, never an address by itself.
    pub pid: u32,
    /// The boot it was recorded in.
    pub boot_id: String,
    /// Its birth time, field 22 of `/proc/<pid>/stat`.
    pub start_time_ticks: u64,
}

/// What the host says about a recorded owner in this boot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Liveness {
    /// The pid names the recorded process, and it has not exited.
    Alive,
    /// No process has the pid.
    Gone,
    /// The pid names a process born at another time: the pid was reused.
    Reused,
    /// The recorded process has exited and is not yet reaped.
    Exited,
    /// Liveness could not be read; the reason says why.
    Unknown(String),
}

/// An execution cgroup as its registration names it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LeafRecord {
    /// The leaf's path as created.
    pub path: std::path::PathBuf,
    /// Its device at creation.
    pub device: u64,
    /// Its inode at creation.
    pub inode: u64,
}

/// What the host found at a recorded leaf's path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LeafProbe {
    /// Nothing is there.
    Absent,
    /// A cgroup with another identity is there.
    Replaced,
    /// The registration or what is there cannot be verified; why.
    Unverifiable(String),
    /// The recorded cgroup itself, and whether any process is in it.
    Identified {
        /// `populated` from its `cgroup.events` (recursive).
        populated: bool,
    },
}

/// Why a host change `gc` asked for did not happen: the step that failed,
/// and the OS error, errno included, when there was one. gc's report carries
/// its text ([`fmt::Display`]).
#[derive(Debug)]
pub struct HostFailure {
    step: Cow<'static, str>,
    source: Option<io::Error>,
}

impl HostFailure {
    /// `step` failed for a reason no syscall reported.
    #[must_use]
    pub fn new(step: impl Into<Cow<'static, str>>) -> HostFailure {
        HostFailure {
            step: step.into(),
            source: None,
        }
    }

    /// `step` failed with the OS error `source`.
    #[must_use]
    pub fn os(step: &'static str, source: io::Error) -> HostFailure {
        HostFailure {
            step: Cow::Borrowed(step),
            source: Some(source),
        }
    }
}

impl fmt::Display for HostFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(f, "{}: {source}", self.step),
            None => f.write_str(&self.step),
        }
    }
}

impl std::error::Error for HostFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Every host question and every host change `gc` makes.
pub trait Host {
    /// The platform and the current boot.
    fn identity(&self) -> HostIdentity;
    /// Whether the recorded owner (of this boot) is alive.
    fn owner(&self, owner: &OwnerRecord) -> Liveness;
    /// What is at the recorded leaf's path.
    fn probe_leaf(&self, leaf: &LeafRecord) -> LeafProbe;
    /// Re-identifies the leaf, writes its `cgroup.kill` and waits at most
    /// `budget` for it to empty.
    ///
    /// # Errors
    /// Why the leaf was not identified, killed or seen empty.
    fn terminate_leaf(&self, leaf: &LeafRecord, budget: Duration) -> Result<(), HostFailure>;
    /// Re-identifies the leaf, checks it is empty and removes it (and any
    /// empty child cgroups), spending at most `entries` directory entries.
    ///
    /// # Errors
    /// Why the leaf was not identified, not empty or not removed.
    fn remove_leaf(&self, leaf: &LeafRecord, entries: &mut usize) -> Result<(), HostFailure>;
    /// What is at a leaf jail state registers by name only (a supervisor
    /// that died between the name and the identity, N7). `Identified` means
    /// only a cgroup v2 directory with an execution leaf's name directly
    /// under this user's delegated subtree; nothing recorded proves more.
    fn probe_named_leaf(&self, path: &Path) -> LeafProbe;
    /// Removes a leaf registered by name only, when it is empty (the kernel
    /// refuses to remove a populated cgroup). Never kills. Returns the
    /// identity of what it removed.
    ///
    /// # Errors
    /// Why the leaf was not found, not empty or not removed.
    fn remove_named_leaf(
        &self,
        path: &Path,
        entries: &mut usize,
    ) -> Result<(u64, u64), HostFailure>;
}

/// The host `gc` runs on: the platform's identity, and on Linux the
/// identity-checked mechanisms of `platform::linux::reconcile`.
pub(super) struct NativeHost {
    identity: HostIdentity,
}

impl NativeHost {
    pub(super) fn new(ctx: &Context) -> NativeHost {
        let platform = ctx.platform.identity();
        NativeHost {
            identity: HostIdentity {
                os: platform.os,
                arch: platform.arch,
                boot_id: ctx.platform.owner_identity().map(|owner| owner.boot_id),
            },
        }
    }
}

/// On Linux: the identity-checked mechanisms of `platform::linux::reconcile`.
#[cfg(target_os = "linux")]
impl Host for NativeHost {
    fn identity(&self) -> HostIdentity {
        self.identity.clone()
    }

    fn owner(&self, owner: &OwnerRecord) -> Liveness {
        crate::platform::linux::reconcile::owner_liveness(owner)
    }

    fn probe_leaf(&self, leaf: &LeafRecord) -> LeafProbe {
        crate::platform::linux::reconcile::probe_leaf(leaf)
    }

    fn terminate_leaf(&self, leaf: &LeafRecord, budget: Duration) -> Result<(), HostFailure> {
        crate::platform::linux::reconcile::terminate_leaf(leaf, budget)
    }

    fn remove_leaf(&self, leaf: &LeafRecord, entries: &mut usize) -> Result<(), HostFailure> {
        crate::platform::linux::reconcile::remove_leaf(leaf, entries)
    }

    fn probe_named_leaf(&self, path: &Path) -> LeafProbe {
        crate::platform::linux::reconcile::probe_named_leaf(path)
    }

    fn remove_named_leaf(
        &self,
        path: &Path,
        entries: &mut usize,
    ) -> Result<(u64, u64), HostFailure> {
        crate::platform::linux::reconcile::remove_named_leaf(path, entries)
    }
}

#[cfg(not(target_os = "linux"))]
const NO_MECHANISM: &str = "this platform has no execution cgroup mechanism";

/// Elsewhere: no process birth identity and no execution cgroup, so nothing
/// is verified and nothing is acted on.
#[cfg(not(target_os = "linux"))]
impl Host for NativeHost {
    fn identity(&self) -> HostIdentity {
        self.identity.clone()
    }

    fn owner(&self, _: &OwnerRecord) -> Liveness {
        Liveness::Unknown("this platform reads no process birth identity".to_owned())
    }

    fn probe_leaf(&self, _: &LeafRecord) -> LeafProbe {
        LeafProbe::Unverifiable(NO_MECHANISM.to_owned())
    }

    fn terminate_leaf(&self, _: &LeafRecord, _: Duration) -> Result<(), HostFailure> {
        Err(HostFailure::new(NO_MECHANISM))
    }

    fn remove_leaf(&self, _: &LeafRecord, _: &mut usize) -> Result<(), HostFailure> {
        Err(HostFailure::new(NO_MECHANISM))
    }

    fn probe_named_leaf(&self, _: &Path) -> LeafProbe {
        LeafProbe::Unverifiable(NO_MECHANISM.to_owned())
    }

    fn remove_named_leaf(&self, _: &Path, _: &mut usize) -> Result<(u64, u64), HostFailure> {
        Err(HostFailure::new(NO_MECHANISM))
    }
}
