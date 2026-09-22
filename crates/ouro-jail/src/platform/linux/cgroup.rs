//! Delegated cgroup v2 leaves.
//!
//! jail-v1 §9.3. Everything here is a measurement. Whether a leaf can be made
//! and whether a process can be moved into it are two separate questions with
//! two separate answers, and the kernel's common-ancestor rule means the
//! second can fail while the first succeeds. The result type keeps them
//! apart, and nothing here reports success it did not observe.

use std::fmt;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::sys::errno_name;

/// The unified cgroup v2 mount point.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// This process's cgroup, as a path relative to the v2 root.
///
/// # Errors
///
/// Any failure reading `/proc/self/cgroup`, or [`io::ErrorKind::InvalidData`]
/// when the file has no unified (`0::`) line, which means cgroup v1.
pub fn own_cgroup() -> io::Result<String> {
    let raw = fs::read_to_string("/proc/self/cgroup")?;
    parse_own_cgroup(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no unified (0::) line in /proc/self/cgroup",
        )
    })
}

/// Extract the `0::<path>` line.
#[must_use]
pub fn parse_own_cgroup(raw: &str) -> Option<String> {
    raw.lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
}

/// The delegated subtree for `uid`, when it exists and this process owns it.
///
/// With lingering enabled, systemd delegates the controllers to
/// `user@<uid>.service` and makes that directory writable by the user. A
/// directory that exists but is owned by someone else is not delegation, so
/// this returns `None` rather than a path that will fail later.
#[must_use]
pub fn delegated_root(uid: u32) -> Option<PathBuf> {
    let path = PathBuf::from(format!(
        "{CGROUP_ROOT}/user.slice/user-{uid}.slice/user@{uid}.service"
    ));
    let meta = fs::metadata(&path).ok()?;
    use std::os::unix::fs::MetadataExt as _;
    if meta.is_dir() && meta.uid() == uid {
        Some(path)
    } else {
        None
    }
}

/// The unified-hierarchy cgroup of `pid`, as a path relative to the v2 root
/// of this process's cgroup namespace.
///
/// A zombie still reports the cgroup it died in (measured on the reference
/// host); a process that is gone is an error, never a guess.
///
/// # Errors
///
/// Any failure reading `/proc/<pid>/cgroup`, or
/// [`io::ErrorKind::InvalidData`] when it has no unified (`0::`) line.
pub fn process_cgroup(pid: libc::pid_t) -> io::Result<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    parse_own_cgroup(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no unified (0::) line in the process's cgroup file",
        )
    })
}

/// Whether the cgroup path `member` is `boundary` or lies beneath it.
///
/// Component-wise, like [`common_ancestor_ok`]: `/a/leaf.x` is not inside
/// `/a/leaf`. A process in a cgroup the child created inside the boundary is
/// still inside it: population, `cgroup.kill` and the limits are recursive.
#[must_use]
pub fn within(member: &str, boundary: &str) -> bool {
    let boundary = boundary.trim_end_matches('/');
    !boundary.is_empty()
        && (member == boundary
            || member
                .strip_prefix(boundary)
                .is_some_and(|rest| rest.starts_with('/')))
}

/// Whether a process in `own` may move a process into `leaf`.
///
/// cgroup v2 requires write access to `cgroup.procs` of the common ancestor of
/// the source and destination cgroups. The only common ancestor a delegated
/// user can write is one inside the delegated subtree, so the rule reduces to:
/// the writer's own cgroup must lie inside the delegated root.
#[must_use]
pub fn common_ancestor_ok(own_cgroup: &str, delegated_relative: &str) -> bool {
    let own = own_cgroup.trim_end_matches('/');
    let delegated = delegated_relative.trim_end_matches('/');
    own == delegated || own.starts_with(&format!("{delegated}/"))
}

/// The controllers a cgroup directory makes available to its children.
///
/// # Errors
///
/// Any failure reading `cgroup.subtree_control`.
pub fn subtree_control(dir: &Path) -> io::Result<Vec<String>> {
    Ok(fs::read_to_string(dir.join("cgroup.subtree_control"))?
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect())
}

/// What happened when a leaf was attempted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafStatus {
    /// There is no delegated subtree for this uid.
    NotDelegated {
        /// Why.
        reason: String,
    },
    /// Creating the leaf directory failed.
    CreateFailed {
        /// The errno.
        errno: i32,
    },
    /// The leaf exists but enabling a controller in the parent failed.
    SubtreeControlFailed {
        /// The controller that could not be enabled.
        controller: String,
        /// The errno.
        errno: i32,
    },
    /// The leaf exists but the process could not be moved into it.
    MoveFailed {
        /// The errno the kernel gave for the write to `cgroup.procs`.
        errno: i32,
    },
    /// The leaf exists and the process is in it.
    Moved,
}

impl fmt::Display for LeafStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDelegated { reason } => write!(f, "not delegated: {reason}"),
            Self::CreateFailed { errno } => {
                write!(f, "leaf creation failed: {}", errno_name(*errno))
            }
            Self::SubtreeControlFailed { controller, errno } => write!(
                f,
                "enabling {controller} in the parent failed: {}",
                errno_name(*errno)
            ),
            Self::MoveFailed { errno } => {
                write!(f, "moving the process in failed: {}", errno_name(*errno))
            }
            Self::Moved => write!(f, "leaf created and process moved in"),
        }
    }
}

/// The full record of a leaf attempt, including the facts that explain it.
#[derive(Clone, Debug)]
pub struct LeafAttempt {
    /// What happened.
    pub status: LeafStatus,
    /// The leaf directory, when one was created.
    pub path: Option<PathBuf>,
    /// The delegated subtree, when one was found.
    pub delegated_root: Option<PathBuf>,
    /// This process's own cgroup at the time of the attempt.
    pub own_cgroup: Option<String>,
    /// Whether the kernel's common-ancestor rule permits the move at all.
    pub common_ancestor_ok: bool,
    /// The parent's `cgroup.subtree_control` before the attempt.
    pub subtree_control_before: Option<Vec<String>>,
    /// Whether this attempt changed `cgroup.subtree_control`.
    pub subtree_control_changed: bool,
}

impl LeafAttempt {
    /// Whether the leaf is usable: created and populated with the pid.
    #[must_use]
    pub fn moved(&self) -> bool {
        self.status == LeafStatus::Moved
    }
}

/// Create a leaf beneath the delegated subtree, make sure `controller` is
/// available in it, and move `pid` into it.
///
/// The common-ancestor check is recorded but the move is still attempted, so
/// that the result carries the kernel's own errno rather than this code's
/// prediction of it.
#[must_use]
pub fn try_leaf(name: &str, pid: libc::pid_t, controller: &str) -> LeafAttempt {
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let own = own_cgroup().ok();
    let Some(root) = delegated_root(uid) else {
        return LeafAttempt {
            status: LeafStatus::NotDelegated {
                reason: format!(
                    "no directory {CGROUP_ROOT}/user.slice/user-{uid}.slice/user@{uid}.service owned by uid {uid}"
                ),
            },
            path: None,
            delegated_root: None,
            own_cgroup: own,
            common_ancestor_ok: false,
            subtree_control_before: None,
            subtree_control_changed: false,
        };
    };

    let relative = root
        .strip_prefix(CGROUP_ROOT)
        .map(|p| format!("/{}", p.display()))
        .unwrap_or_default();
    let ancestor_ok = own
        .as_deref()
        .is_some_and(|own| common_ancestor_ok(own, &relative));

    let before = subtree_control(&root).ok();
    let mut changed = false;
    let leaf = root.join(name);

    if let Some(before) = before.as_ref()
        && !before.iter().any(|c| c == controller)
    {
        match fs::write(
            root.join("cgroup.subtree_control"),
            format!("+{controller}"),
        ) {
            Ok(()) => changed = true,
            Err(e) => {
                return LeafAttempt {
                    status: LeafStatus::SubtreeControlFailed {
                        controller: controller.to_owned(),
                        errno: e.raw_os_error().unwrap_or(libc::EIO),
                    },
                    path: None,
                    delegated_root: Some(root),
                    own_cgroup: own,
                    common_ancestor_ok: ancestor_ok,
                    subtree_control_before: before.clone().into(),
                    subtree_control_changed: false,
                };
            }
        }
    }

    if let Err(e) = fs::create_dir(&leaf) {
        return LeafAttempt {
            status: LeafStatus::CreateFailed {
                errno: e.raw_os_error().unwrap_or(libc::EIO),
            },
            path: None,
            delegated_root: Some(root),
            own_cgroup: own,
            common_ancestor_ok: ancestor_ok,
            subtree_control_before: before,
            subtree_control_changed: changed,
        };
    }

    let status = match fs::write(leaf.join("cgroup.procs"), pid.to_string()) {
        Ok(()) => LeafStatus::Moved,
        Err(e) => LeafStatus::MoveFailed {
            errno: e.raw_os_error().unwrap_or(libc::EIO),
        },
    };

    LeafAttempt {
        status,
        path: Some(leaf),
        delegated_root: Some(root),
        own_cgroup: own,
        common_ancestor_ok: ancestor_ok,
        subtree_control_before: before,
        subtree_control_changed: changed,
    }
}

/// Remove a leaf this process created and put the parent's
/// `cgroup.subtree_control` back the way it was found.
///
/// # Errors
///
/// A failure to remove the leaf. A failure to restore `subtree_control` is
/// reported the same way; the host must be left as it was found.
pub fn remove_leaf(attempt: &LeafAttempt) -> io::Result<()> {
    if let Some(path) = attempt.path.as_ref()
        && path.exists()
    {
        fs::remove_dir(path)?;
    }
    if attempt.subtree_control_changed
        && let Some(root) = attempt.delegated_root.as_ref()
        && let Some(before) = attempt.subtree_control_before.as_ref()
    {
        let now = subtree_control(root).unwrap_or_default();
        for controller in now {
            if !before.contains(&controller) {
                fs::write(
                    root.join("cgroup.subtree_control"),
                    format!("-{controller}"),
                )?;
            }
        }
    }
    Ok(())
}

/// Whether a cgroup has any process in it, recursively.
///
/// # Errors
///
/// Any failure reading `cgroup.events`.
pub fn populated(dir: &Path) -> io::Result<bool> {
    let raw = fs::read_to_string(dir.join("cgroup.events"))?;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("populated ") {
            return match value.trim() {
                "0" => Ok(false),
                "1" => Ok(true),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid population",
                )),
            };
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no populated line in cgroup.events",
    ))
}

/// A unique, pinned execution leaf. No controller is enabled or disabled by a
/// run: delegation is operator configuration, never a side effect of doctor.
pub struct ExecutionCgroup {
    path: PathBuf,
    dir: fs::File,
    /// The delegated parent, pinned so removal is by name relative to it.
    parent: fs::File,
    name: std::ffi::OsString,
    device: u64,
    inode: u64,
    limits: Vec<crate::records::AppliedLimit>,
    baseline: Counters,
    oom_killed: bool,
    removed: bool,
    /// Set by [`ExecutionCgroup::retain`]: never removed on drop.
    retained: bool,
}

#[derive(Default, Clone, Copy)]
struct Counters {
    pids: u64,
    memory: u64,
    oom: u64,
    cpu: u64,
}

impl ExecutionCgroup {
    /// Create and configure an empty leaf. Missing preferred controllers are
    /// recorded unapplied; a required controller always makes preparation fail.
    pub fn create(limits: &crate::policy::LimitsSnapshot) -> io::Result<Self> {
        let root = delegated_root(unsafe { libc::getuid() }).ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "no delegated cgroup")
        })?;
        let relative = root.strip_prefix(CGROUP_ROOT).map_err(io::Error::other)?;
        if !common_ancestor_ok(&own_cgroup()?, &format!("/{}", relative.display())) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "supervisor is outside the delegated subtree; launch it in a delegated user scope",
            ));
        }
        Self::create_beneath(&root, limits)
    }

    /// Low-level delegated-root entry point, also used to exercise controller
    /// absence under an owned, isolated subtree without changing host settings.
    pub fn create_beneath(root: &Path, limits: &crate::policy::LimitsSnapshot) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::getuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cgroup root is not owned",
            ));
        }
        let root_fd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)?;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(root_fd.as_raw_fd(), filesystem.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { filesystem.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
            return Err(io::Error::other("execution root is not cgroup v2"));
        }
        let path = root.join(format!(
            "ouro-{}.leaf",
            crate::state::AttemptId::generate().as_str()
        ));
        fs::create_dir(&path)?;
        let result = Self::open_created(&path, limits);
        if result.is_err() {
            let _ = fs::remove_dir(&path);
        }
        result
    }

    fn open_created(path: &Path, limits: &crate::policy::LimitsSnapshot) -> io::Result<Self> {
        let directory = |target: &Path| {
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(target)
        };
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("cgroup leaf path has no name"))?
            .to_owned();
        let parent = directory(
            path.parent()
                .ok_or_else(|| io::Error::other("cgroup leaf path has no parent"))?,
        )?;
        let dir = directory(path)?;
        let meta = dir.metadata()?;
        let mut leaf = Self {
            path: path.to_owned(),
            dir,
            parent,
            name,
            device: meta.dev(),
            inode: meta.ino(),
            limits: Vec::new(),
            baseline: Counters::default(),
            oom_killed: false,
            removed: false,
            retained: false,
        };
        // Verify kill permission before any target is placed here.
        leaf.file("cgroup.kill", true)?;
        leaf.file("cgroup.procs", true)?;
        if leaf.populated()? {
            return Err(io::Error::other("new cgroup is populated"));
        }
        for (key, ceiling, control) in [
            ("pids", limits.pids.as_ref(), "pids.max"),
            ("mem", limits.mem.as_ref(), "memory.max"),
            ("cpu", limits.cpu.as_ref(), "cpu.max"),
        ] {
            let Some(ceiling) = ceiling else { continue };
            let value = match key {
                "cpu" => cpu_max(&ceiling.value)?,
                "mem" => memory_max(&ceiling.value)?,
                _ => ceiling.value.clone(),
            };
            let applied = match leaf.write(control, &value) {
                Ok(()) => {
                    if leaf.read(control)?.trim() != value {
                        return Err(io::Error::other("cgroup limit read-back mismatch"));
                    }
                    true
                }
                Err(error) if ceiling.required => return Err(error),
                Err(_) => false,
            };
            leaf.limits.push(crate::records::AppliedLimit {
                key: key.to_owned(),
                requested: ceiling.value.clone(),
                required: ceiling.required,
                applied,
                mechanism: applied.then(|| control.to_owned()),
                scope: applied.then(|| "tree".to_owned()),
                hit: applied.then_some(false),
            });
        }
        leaf.baseline = leaf.counters()?;
        Ok(leaf)
    }

    /// Every control operation checks the pathname still names our held
    /// inode, then opens the kernel control relative to that inode, so a
    /// reused path is never signalled, even between the check and the open.
    /// Removal is by name in the pinned parent after the same check, and
    /// `rmdir` only ever removes an empty directory (see [`Self::remove`]).
    pub fn verify(&self) -> io::Result<()> {
        let meta = fs::symlink_metadata(&self.path)?;
        if meta.is_dir() && (meta.dev(), meta.ino()) == (self.device, self.inode) {
            Ok(())
        } else {
            Err(io::Error::other("execution cgroup identity changed"))
        }
    }

    fn file(&self, name: &str, write: bool) -> io::Result<fs::File> {
        self.verify()?;
        let name = std::ffi::CString::new(name).map_err(io::Error::other)?;
        let flags = (if write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        }) | libc::O_CLOEXEC
            | libc::O_NOFOLLOW;
        // SAFETY: owned directory descriptor and a terminated control filename.
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    fn read(&self, name: &str) -> io::Result<String> {
        let mut text = String::new();
        self.file(name, false)?
            .take(16384)
            .read_to_string(&mut text)?;
        Ok(text)
    }

    fn write(&self, name: &str, value: &str) -> io::Result<()> {
        self.file(name, true)?.write_all(value.as_bytes())
    }

    pub fn place(&self, pid: libc::pid_t) -> io::Result<()> {
        self.write("cgroup.procs", &pid.to_string())?;
        self.verify_member(pid)
    }

    pub fn verify_member(&self, pid: libc::pid_t) -> io::Result<()> {
        let members = self.read("cgroup.procs")?;
        if !members.lines().any(|line| line == pid.to_string()) {
            return Err(io::Error::other("target placement was not observed"));
        }
        Ok(())
    }

    /// Trusted setup may have consumed controller events. Attribute only
    /// counters after the blocked target and its charged helpers are ready.
    pub fn arm(&mut self) -> io::Result<()> {
        self.baseline = self.counters()?;
        Ok(())
    }

    pub fn kill(&self) -> io::Result<()> {
        self.write("cgroup.kill", "1")
    }

    pub fn populated(&self) -> io::Result<bool> {
        match counter(&self.read("cgroup.events")?, "populated")? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(io::Error::other("invalid cgroup population")),
        }
    }

    fn counters(&self) -> io::Result<Counters> {
        let mut out = Counters::default();
        for limit in self.limits.iter().filter(|limit| limit.applied) {
            match limit.key.as_str() {
                "pids" => out.pids = counter(&self.read("pids.events")?, "max")?,
                "mem" => {
                    let events = self.read("memory.events")?;
                    out.memory = counter(&events, "max")?;
                    out.oom = counter(&events, "oom_kill")?;
                }
                "cpu" => out.cpu = counter(&self.read("cpu.stat")?, "nr_throttled")?,
                _ => {}
            }
        }
        Ok(out)
    }

    /// Sample counters relative to this leaf's pre-release baseline. Returns
    /// newly hit ceilings; throttling and pids refusals do not invent a signal.
    pub fn sample(&mut self) -> io::Result<usize> {
        let now = self.counters()?;
        self.oom_killed |= now.oom > self.baseline.oom;
        let mut hits = 0;
        for limit in self.limits.iter_mut().filter(|limit| limit.applied) {
            let hit = match limit.key.as_str() {
                "pids" => now.pids > self.baseline.pids,
                "mem" => now.memory > self.baseline.memory || self.oom_killed,
                "cpu" => now.cpu > self.baseline.cpu,
                _ => false,
            };
            if hit && limit.hit != Some(true) {
                hits += 1;
                limit.hit = Some(true);
            }
        }
        Ok(hits)
    }

    pub fn limits(&self) -> Vec<crate::records::AppliedLimit> {
        self.limits.clone()
    }
    /// The leaf's path, as created.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// The leaf's path relative to the v2 root, the form `/proc/<pid>/cgroup`
    /// uses, or `None` when the leaf does not lie under [`CGROUP_ROOT`].
    #[must_use]
    pub fn relative_path(&self) -> Option<String> {
        let relative = self.path.strip_prefix(CGROUP_ROOT).ok()?;
        Some(format!("/{}", relative.to_str()?))
    }
    /// The filesystem identity pinned at creation: `(device, inode)`.
    #[must_use]
    pub fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }
    /// Keep the leaf when this value is dropped. jail-v1 §9.3: a boundary
    /// whose integrity was lost retains its state for explicit recovery,
    /// even when it happens to be empty.
    pub fn retain(&mut self) {
        self.retained = true;
    }
    pub fn oom_killed(&self) -> bool {
        self.oom_killed
    }
    pub fn invalidate_hits(&mut self) {
        for limit in &mut self.limits {
            if limit.applied && limit.hit != Some(true) {
                limit.hit = None;
            }
        }
    }
    pub fn registration(&self, backend: i32, init: i32) -> serde_json::Value {
        serde_json::json!({"path": self.path, "device": self.device, "inode": self.inode,
            "charged_helpers": [{"role": "bubblewrap", "pid": backend},
                {"role": "namespace_init", "pid": init}],
            "scope": "target_descendants_and_listed_helpers"})
    }
    /// Removes the empty leaf by name in its pinned parent. The identity
    /// check comes first and `AT_REMOVEDIR` refuses a nonempty directory, so
    /// a same-uid path swap between the two can at most lose its own empty
    /// replacement; the held leaf is never confused with it.
    pub fn remove(&mut self) -> io::Result<()> {
        self.verify()?;
        if self.populated()? {
            return Err(io::Error::other("execution cgroup is still populated"));
        }
        let name = std::ffi::CString::new(self.name.as_bytes()).map_err(io::Error::other)?;
        // SAFETY: owned parent directory descriptor and a terminated name.
        let rc =
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        self.removed = true;
        Ok(())
    }
}

impl Drop for ExecutionCgroup {
    fn drop(&mut self) {
        // A nonempty or unidentifiable leaf is retained for explicit recovery,
        // and so is one whose boundary integrity was lost.
        if !self.removed && !self.retained {
            let _ = self.remove();
        }
    }
}

fn counter(text: &str, key: &str) -> io::Result<u64> {
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(' ')?;
            (name == key).then(|| value.trim().parse().map_err(io::Error::other))
        })
        .unwrap_or_else(|| Err(io::Error::other(format!("missing cgroup counter {key}"))))
}

/// Memory ceilings apply at page granularity: the kernel keeps `memory.max`
/// in pages and rounds a byte value down, so the value written is the one it
/// reads back and the exact read-back check stays meaningful. A ceiling below
/// one page cannot be expressed and is an error.
fn memory_max(value: &str) -> io::Result<String> {
    let bytes: u64 = value.parse().map_err(io::Error::other)?;
    let page = page_size();
    let effective = bytes - bytes % page;
    if effective == 0 {
        return Err(io::Error::other(format!(
            "memory ceiling {bytes} is below one page of {page} bytes"
        )));
    }
    Ok(effective.to_string())
}

fn page_size() -> u64 {
    // SAFETY: sysconf takes one scalar and dereferences nothing.
    u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .unwrap_or(4096)
        .max(1)
}

/// Canonical CPU values are integer percentages; the period is exactly 100ms.
fn cpu_max(value: &str) -> io::Result<String> {
    let percent: u64 = value.parse().map_err(io::Error::other)?;
    let quota = percent
        .checked_mul(1000)
        .filter(|value| *value >= 1000)
        .ok_or_else(|| io::Error::other("invalid CPU ceiling"))?;
    Ok(format!("{quota} 100000"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_and_preferred_missing_controllers_are_distinct() {
        let dir = tempfile::tempdir().unwrap();
        for (name, value) in [
            ("cgroup.kill", ""),
            ("cgroup.procs", ""),
            ("cgroup.events", "populated 0\n"),
        ] {
            fs::write(dir.path().join(name), value).unwrap();
        }
        let mut limits = crate::policy::LimitsSnapshot {
            wall: None,
            mem: None,
            cpu: None,
            pids: Some(crate::policy::LimitCeiling {
                value: "256".into(),
                required: false,
            }),
        };
        let preferred = ExecutionCgroup::open_created(dir.path(), &limits).unwrap();
        assert!(!preferred.limits()[0].applied);
        assert_eq!(preferred.limits()[0].hit, None);
        limits.pids.as_mut().unwrap().required = true;
        assert!(ExecutionCgroup::open_created(dir.path(), &limits).is_err());
    }

    #[test]
    fn cgroup_path_replacement_never_targets_the_new_directory() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("leaf");
        fs::create_dir(&path).unwrap();
        for (name, value) in [
            ("cgroup.kill", ""),
            ("cgroup.procs", ""),
            ("cgroup.events", "populated 0\n"),
        ] {
            fs::write(path.join(name), value).unwrap();
        }
        let limits = crate::policy::LimitsSnapshot {
            wall: None,
            pids: None,
            mem: None,
            cpu: None,
        };
        let mut leaf = ExecutionCgroup::open_created(&path, &limits).unwrap();
        fs::rename(&path, root.path().join("original")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("cgroup.kill"), "untouched").unwrap();
        assert!(leaf.kill().is_err());
        assert!(leaf.remove().is_err());
        assert_eq!(
            fs::read_to_string(path.join("cgroup.kill")).unwrap(),
            "untouched"
        );
    }

    #[test]
    fn counters_and_cpu_quotas_refuse_unknown_or_overflow() {
        assert_eq!(cpu_max("25").unwrap(), "25000 100000");
        assert_eq!(cpu_max("250").unwrap(), "250000 100000");
        assert!(cpu_max("18446744073709551615").is_err());
        assert!(cpu_max("0").is_err());
        assert!(counter("frozen 0\n", "populated").is_err());
        assert!(counter("populated unknown\n", "populated").is_err());
    }

    #[test]
    fn memory_ceilings_are_written_at_page_granularity() {
        let page = page_size();
        assert_eq!(memory_max("67108864").unwrap(), "67108864");
        assert_eq!(
            memory_max(&(page * 3 + 1).to_string()).unwrap(),
            (page * 3).to_string()
        );
        assert_eq!(
            memory_max("100000000").unwrap(),
            (100_000_000 - 100_000_000 % page).to_string()
        );
        assert!(memory_max(&(page - 1).to_string()).is_err());
        assert!(memory_max("0").is_err());
        assert!(memory_max("many").is_err());
    }

    #[test]
    fn membership_is_containment_by_component() {
        let leaf = "/user.slice/user-1001.slice/user@1001.service/ouro-att_x.leaf";
        assert!(within(leaf, leaf));
        assert!(within(&format!("{leaf}/child-made"), leaf));
        assert!(within(leaf, &format!("{leaf}/")));
        assert!(!within(&format!("{leaf}.evil"), leaf));
        assert!(!within(
            "/user.slice/user-1001.slice/user@1001.service/app.slice/run-1.scope",
            leaf
        ));
        assert!(!within("/", leaf));
        assert!(!within(leaf, ""), "an empty boundary contains nothing");
        assert!(!within(leaf, "/"), "the root is not a registered boundary");
    }

    #[test]
    fn a_leaf_outside_the_cgroup_root_has_no_relative_path() {
        // Retention itself is observable only on cgroupfs, where an empty
        // leaf can be removed; the live R06 cases check it there.
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("leaf");
        fs::create_dir(&path).unwrap();
        for (name, value) in [
            ("cgroup.kill", ""),
            ("cgroup.procs", ""),
            ("cgroup.events", "populated 0\n"),
        ] {
            fs::write(path.join(name), value).unwrap();
        }
        let limits = crate::policy::LimitsSnapshot {
            wall: None,
            pids: None,
            mem: None,
            cpu: None,
        };
        let leaf = ExecutionCgroup::open_created(&path, &limits).unwrap();
        assert_eq!(leaf.relative_path(), None);
        assert_eq!(leaf.path(), path.as_path());
    }

    #[test]
    fn the_unified_line_is_the_one_that_counts() {
        let v2_only = "0::/user.slice/user-1001.slice/session-3.scope\n";
        assert_eq!(
            parse_own_cgroup(v2_only).as_deref(),
            Some("/user.slice/user-1001.slice/session-3.scope")
        );
        let hybrid = "1:name=systemd:/legacy\n0::/unified\n";
        assert_eq!(parse_own_cgroup(hybrid).as_deref(), Some("/unified"));
        assert_eq!(parse_own_cgroup("1:name=systemd:/legacy\n"), None);
    }

    #[test]
    fn the_common_ancestor_rule_is_containment_not_sibling_hood() {
        let delegated = "/user.slice/user-1001.slice/user@1001.service";
        assert!(common_ancestor_ok(delegated, delegated));
        assert!(common_ancestor_ok(
            &format!("{delegated}/app.slice/x.scope"),
            delegated
        ));
        // A login session is a sibling of user@.service, not inside it. This
        // is the case that makes the move fail on the reference host.
        assert!(!common_ancestor_ok(
            "/user.slice/user-1001.slice/session-3.scope",
            delegated
        ));
        assert!(!common_ancestor_ok("/", delegated));
        // A prefix that is not a path component must not count.
        assert!(!common_ancestor_ok(
            "/user.slice/user-1001.slice/user@1001.service.evil",
            delegated
        ));
    }
}
