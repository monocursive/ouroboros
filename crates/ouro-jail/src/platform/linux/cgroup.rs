//! Delegated cgroup v2 leaves.
//!
//! jail-v1 §9.3. Everything here is a measurement. Whether a leaf can be made
//! and whether a process can be moved into it are two separate questions with
//! two separate answers, and the kernel's common-ancestor rule means the
//! second can fail while the first succeeds; nothing here reports success it
//! did not observe.

use std::fs;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::fs::path_within;

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

/// Whether the cgroup path `member` is `boundary` or lies beneath it
/// ([`path_within`]): `/a/leaf.x` is not inside `/a/leaf`, and an empty
/// boundary or the root contains nothing. A process in a cgroup the child
/// created inside the boundary is still inside it: population, `cgroup.kill`
/// and the limits are recursive.
#[must_use]
pub fn within(member: &str, boundary: &str) -> bool {
    path_within(member.as_bytes(), boundary.as_bytes())
}

/// Whether a process in `own` may move a process into `leaf`.
///
/// cgroup v2 requires write access to `cgroup.procs` of the common ancestor of
/// the source and destination cgroups. The only common ancestor a delegated
/// user can write is one inside the delegated subtree, so the rule reduces to:
/// the writer's own cgroup must lie inside the delegated root — by the same
/// predicate as [`within`], so an empty or root delegation admits nothing.
#[must_use]
pub fn common_ancestor_ok(own_cgroup: &str, delegated_relative: &str) -> bool {
    path_within(own_cgroup.as_bytes(), delegated_relative.as_bytes())
}

/// Whether a cgroup has any process in it, recursively.
///
/// # Errors
///
/// Any failure reading `cgroup.events`.
pub fn populated(dir: &Path) -> io::Result<bool> {
    parse_populated(&fs::read_to_string(dir.join("cgroup.events"))?)
}

// Shared by `gc` reconciliation (jail-v1 §14.2)
/// The `populated` line of a `cgroup.events` file's contents.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] when the line is missing or is neither 0
/// nor 1: an unreadable population is never taken for an empty one.
pub fn parse_populated(raw: &str) -> io::Result<bool> {
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

/// The first component of an execution leaf's name.
pub const LEAF_PREFIX: &str = crate::gc::LEAF_PREFIX;
/// The last component of an execution leaf's name.
pub const LEAF_SUFFIX: &str = crate::gc::LEAF_SUFFIX;

/// The name an attempt's execution leaf has: `ouro-<attempt id>.leaf`
/// (J4 wave 3, G2: the leaf carries its attempt association, §9.3, and `gc`
/// never acts on a registration naming another attempt's leaf).
#[must_use]
pub fn leaf_name(attempt: &crate::state::AttemptId) -> String {
    crate::gc::leaf_name_of(attempt.as_str())
}

/// The name of a leaf that belongs to no attempt (a `doctor` probe's, a
/// test's): `ouro-probe-<random>.leaf`, which is never an execution leaf's
/// name, so no attempt's registration can make `gc` act on it.
#[must_use]
pub fn probe_leaf_name() -> String {
    let token = crate::state::AttemptId::generate();
    format!(
        "{LEAF_PREFIX}probe-{}{LEAF_SUFFIX}",
        token.as_str().trim_start_matches("att_")
    )
}

/// Whether `name` has exactly the shape [`leaf_name`] produces. `gc` acts
/// only on a recorded leaf whose name has it: a registration naming any other
/// directory under the delegated subtree is not an execution leaf.
#[must_use]
pub fn is_leaf_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_prefix(LEAF_PREFIX))
        .and_then(|rest| rest.strip_suffix(LEAF_SUFFIX))
        .is_some_and(|token| crate::state::AttemptId::parse(token).is_ok())
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
    swap: u64,
    oom: u64,
    cpu: u64,
}

// N7
/// What a leaf registration hook is told, in order (N7).
#[derive(Clone, Copy, Debug)]
pub enum LeafStep<'a> {
    /// The leaf's path, before `mkdir`: nothing exists at it yet.
    Named(&'a Path),
    /// The leaf exists, configured and empty, with the identity pinned at
    /// creation; nothing has been placed in it.
    Created {
        /// The leaf's path.
        path: &'a Path,
        /// Its device.
        device: u64,
        /// Its inode.
        inode: u64,
    },
}

/// A hook that makes each [`LeafStep`] durable before creation goes on.
pub type Register<'a> = &'a mut dyn FnMut(LeafStep<'_>) -> io::Result<()>;

impl ExecutionCgroup {
    /// Create and configure an empty leaf that belongs to no attempt (a
    /// probe's): its name is [`probe_leaf_name`]. Missing preferred
    /// controllers are recorded unapplied; a required controller always makes
    /// preparation fail.
    pub fn create(limits: &crate::policy::LimitsSnapshot) -> io::Result<Self> {
        Self::create_named(limits, &probe_leaf_name(), &mut |_| Ok(()))
    }

    // N7
    /// [`ExecutionCgroup::create`] for an attempt: the leaf is registered in
    /// the attempt's jail state by name before `mkdir` (P15) and by device
    /// and inode right after (P16), before anything is placed in it, so a
    /// supervisor that dies at any point leaves either no leaf or one that
    /// jail state names for `gc` (§7, §14.2).
    ///
    /// J4 wave 3 (G2): the leaf is `ouro-<attempt id>.leaf`, the attempt id
    /// being the attempt root's name (`<data>/attempts/<attempt id>`), so the
    /// leaf carries its attempt; `mkdir` is exclusive, so a directory of that
    /// name made by anyone else fails the creation rather than being adopted.
    ///
    /// The outer `Err` is a registration that failed: a persistence failure
    /// before exec, which refuses (S5), and no leaf is left behind unless
    /// its own removal failed (then jail state names it). The inner result
    /// is the creation's, as [`ExecutionCgroup::create`] reports it.
    ///
    /// # Errors
    /// The failed registration, as `state_write_failed`.
    pub fn create_for_attempt(
        limits: &crate::policy::LimitsSnapshot,
        attempt_root: &Path,
    ) -> Result<io::Result<Self>, crate::records::JailError> {
        let Some(attempt_id) = attempt_root
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| crate::state::AttemptId::parse(name).ok())
        else {
            return Err(crate::records::JailError::new(
                crate::records::ErrorCode::InternalError,
                crate::records::ErrorStage::Preparing,
                crate::records::Remediation::InspectState,
                format!(
                    "the attempt root {} is not named by an attempt id, so its execution leaf \
                     cannot carry the attempt",
                    attempt_root.display()
                ),
            ));
        };
        let attempt = crate::state::AttemptDir::from_root(attempt_root.to_path_buf());
        let mut unregistered = None;
        let created = Self::create_named(limits, &leaf_name(&attempt_id), &mut |step| {
            let (path, identity) = match step {
                LeafStep::Named(path) => (path, None),
                LeafStep::Created {
                    path,
                    device,
                    inode,
                } => (path, Some((device, inode))),
            };
            crate::state::register_execution_leaf(&attempt, path, identity).map_err(|error| {
                let failure = io::Error::other(error.message.clone());
                unregistered = Some(error);
                failure
            })
        });
        match unregistered {
            Some(error) => Err(error),
            None => Ok(created),
        }
    }

    /// [`ExecutionCgroup::create`] with the leaf named `name`, telling
    /// `register` each step first.
    pub fn create_named(
        limits: &crate::policy::LimitsSnapshot,
        name: &str,
        register: Register<'_>,
    ) -> io::Result<Self> {
        // SAFETY: getuid takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        let root = delegated_root(uid).ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "no delegated cgroup")
        })?;
        let relative = root.strip_prefix(CGROUP_ROOT).map_err(io::Error::other)?;
        if !common_ancestor_ok(&own_cgroup()?, &format!("/{}", relative.display())) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "supervisor is outside the delegated subtree; launch it in a delegated user scope",
            ));
        }
        Self::create_beneath_registered(&root, limits, name, register)
    }

    /// Low-level delegated-root entry point, also used to exercise controller
    /// absence under an owned, isolated subtree without changing host settings.
    pub fn create_beneath(root: &Path, limits: &crate::policy::LimitsSnapshot) -> io::Result<Self> {
        Self::create_beneath_registered(root, limits, &probe_leaf_name(), &mut |_| Ok(()))
    }

    /// [`ExecutionCgroup::create_beneath`] with the leaf named `name`,
    /// telling `register` each step first (N7): the name before `mkdir`, the
    /// identity before the leaf is returned. A failed registration of the
    /// identity removes the empty leaf again.
    pub fn create_beneath_registered(
        root: &Path,
        limits: &crate::policy::LimitsSnapshot,
        name: &str,
        register: Register<'_>,
    ) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(root)?;
        // SAFETY: getuid takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        if !metadata.is_dir() || metadata.uid() != uid {
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
        // SAFETY: `root_fd` is a live descriptor and `filesystem` is writable
        // storage of the type fstatfs fills.
        if unsafe { libc::fstatfs(root_fd.as_raw_fd(), filesystem.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fstatfs succeeded, so it initialized `filesystem`.
        if unsafe { filesystem.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
            return Err(io::Error::other("execution root is not cgroup v2"));
        }
        // J4 wave 3 (G2): the name is given (an attempt's own, or a probe's);
        // one path component, never a path.
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(io::Error::other(
                "an execution leaf's name is one component",
            ));
        }
        let path = root.join(name);
        // J4 W2-S: N7 — named durably before it exists.
        register(LeafStep::Named(&path))?;
        // Exclusive: an existing directory of this name is never adopted.
        fs::create_dir(&path)?;
        let leaf = match Self::open_created(&path, limits) {
            Ok(leaf) => leaf,
            Err(error) => {
                let _ = fs::remove_dir(&path);
                return Err(error);
            }
        };
        // J4 W2-S: N7 — identified durably before anything is placed in it.
        // On failure the leaf is dropped, which removes it (it is empty).
        let (device, inode) = leaf.identity();
        register(LeafStep::Created {
            path: &path,
            device,
            inode,
        })?;
        Ok(leaf)
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
            ("swap", limits.swap.as_ref(), "memory.swap.max"),
            ("cpu", limits.cpu.as_ref(), "cpu.max"),
        ] {
            let Some(ceiling) = ceiling else { continue };
            let value = match key {
                "cpu" => cpu_max(&ceiling.value)?,
                "mem" => memory_max(&ceiling.value)?,
                "swap" => swap_max(&ceiling.value)?,
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
                // Audit 2026-10-08 M3: a swap ceiling's `max` event counter
                // rises only on a refault reclaim may never raise, so `false`
                // would be a negative claim nothing establishes. Swap starts
                // unknown (§13.2: `null` when unknown); the readable event
                // counters back every other ceiling's `false`.
                hit: applied
                    .then(|| if key == "swap" { None } else { Some(false) })
                    .flatten(),
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
        // SAFETY: `fd` was just returned by `openat` and nothing else owns it.
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

    /// The registered, configured leaf for atomic child creation. The kernel
    /// takes this pinned directory descriptor, never a re-resolved pathname.
    /// Parent membership readback remains mandatory before watcher/release.
    pub(crate) fn spawn_handle(&self) -> io::Result<std::os::fd::OwnedFd> {
        self.verify()?;
        Ok(self.dir.try_clone()?.into())
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

    /// A write-only descriptor for this leaf's `cgroup.kill`, opened through
    /// the pinned directory after an identity check, for the lifetime
    /// watcher: if the supervisor dies it kills everything in the leaf
    /// (§9.3), not only the backend it holds a pidfd for.
    pub fn kill_handle(&self) -> io::Result<std::os::fd::OwnedFd> {
        Ok(self.file("cgroup.kill", true)?.into())
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
                // `fail` also counts global swap exhaustion. Only `max`
                // attributes a refusal to this cgroup's configured ceiling.
                "swap" => out.swap = counter(&self.read("memory.swap.events")?, "max")?,
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
        // Audit 2026-10-08 M3: a sampled `swap.current` at or above the
        // written ceiling is direct hit evidence, beside the `max` event
        // counter a refault may never raise.
        let swap_saturated = if self
            .limits
            .iter()
            .any(|limit| limit.applied && limit.key == "swap")
        {
            self.swap_saturated()?
        } else {
            false
        };
        let mut hits = 0;
        for limit in self.limits.iter_mut().filter(|limit| limit.applied) {
            let hit = match limit.key.as_str() {
                "pids" => now.pids > self.baseline.pids,
                "mem" => now.memory > self.baseline.memory || self.oom_killed,
                "swap" => now.swap > self.baseline.swap || swap_saturated,
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

    /// Whether the leaf's sampled `memory.swap.current` sits at or above its
    /// written `memory.swap.max`. `max` is unbounded and never saturated.
    fn swap_saturated(&self) -> io::Result<bool> {
        let read = |name: &str| -> io::Result<u64> {
            let text = self.read(name)?;
            text.trim()
                .parse()
                .map_err(|_| io::Error::other(format!("{name} is not a byte count")))
        };
        let current = read("memory.swap.current")?;
        let max = match self.read("memory.swap.max") {
            Ok(text) if text.trim() == "max" => return Ok(false),
            Ok(text) => text
                .trim()
                .parse()
                .map_err(|_| io::Error::other("memory.swap.max is not a byte count"))?,
            Err(error) => return Err(error),
        };
        Ok((max > 0 || current > 0) && current >= max)
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
    /// A leaf on an ordinary directory holding the control files, for tests
    /// that drive one integrity check in process.
    #[cfg(test)]
    pub(crate) fn open_for_test(path: &Path) -> io::Result<Self> {
        Self::open_created(
            path,
            &crate::policy::LimitsSnapshot {
                wall: None,
                pids: None,
                mem: None,
                swap: None,
                storage: None,
                inodes: None,
                cpu: None,
            },
        )
    }
    /// [`Self::open_for_test`] with `limits` written into the fake leaf's
    /// control files, so a test can make a counter read fail.
    #[cfg(test)]
    pub(crate) fn open_for_test_with(
        path: &Path,
        limits: &crate::policy::LimitsSnapshot,
    ) -> io::Result<Self> {
        Self::open_created(path, limits)
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

fn swap_max(value: &str) -> io::Result<String> {
    let bytes: u64 = value.parse().map_err(io::Error::other)?;
    // Rounding down preserves an upper bound, including sub-page ceilings.
    Ok((bytes - bytes % page_size()).to_string())
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
    fn swap_ceiling_and_attributed_hits_are_read_back() {
        let dir = tempfile::tempdir().unwrap();
        for (name, value) in [
            ("cgroup.kill", ""),
            ("cgroup.procs", ""),
            ("cgroup.events", "populated 0\n"),
            ("memory.swap.events", "high 0\nmax 4\nfail 8\n"),
            ("memory.swap.max", ""),
            ("memory.swap.current", "0"),
        ] {
            fs::write(dir.path().join(name), value).unwrap();
        }
        let limits = crate::policy::LimitsSnapshot {
            wall: None,
            pids: None,
            mem: None,
            cpu: None,
            storage: None,
            inodes: None,
            swap: Some(crate::policy::LimitCeiling {
                value: "0".into(),
                required: true,
            }),
        };
        let mut leaf = ExecutionCgroup::open_created(dir.path(), &limits).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("memory.swap.max")).unwrap(),
            "0"
        );
        // Audit 2026-10-08 M3: a swap ceiling's hit starts unknown, a
        // negative claim nothing establishes.
        assert_eq!(leaf.limits()[0].hit, None);
        fs::write(
            dir.path().join("memory.swap.events"),
            "high 0\nmax 4\nfail 9\n",
        )
        .unwrap();
        assert_eq!(
            leaf.sample().unwrap(),
            0,
            "global exhaustion is not our ceiling"
        );
        assert_eq!(leaf.limits()[0].hit, None);
        // Saturation is hit evidence too: a sampled `swap.current` at the
        // written `swap.max` (here 0) attributes the ceiling even with no
        // `max` event delta.
        fs::write(dir.path().join("memory.swap.current"), "1").unwrap();
        assert_eq!(leaf.sample().unwrap(), 1);
        assert_eq!(leaf.limits()[0].hit, Some(true));
        // The event-counter path attributes a hit on a fresh leaf as well.
        fs::write(dir.path().join("memory.swap.current"), "0").unwrap();
        let mut leaf = ExecutionCgroup::open_created(dir.path(), &limits).unwrap();
        assert_eq!(leaf.limits()[0].hit, None);
        fs::write(
            dir.path().join("memory.swap.events"),
            "high 0\nmax 5\nfail 10\n",
        )
        .unwrap();
        assert_eq!(leaf.sample().unwrap(), 1);
        assert_eq!(leaf.sample().unwrap(), 0);
        assert_eq!(leaf.limits()[0].hit, Some(true));
        fs::remove_file(dir.path().join("memory.swap.max")).unwrap();
        assert!(ExecutionCgroup::open_created(dir.path(), &limits).is_err());
        assert_eq!(swap_max("0").unwrap(), "0");
        assert_eq!(
            swap_max(&(page_size() + 1).to_string()).unwrap(),
            page_size().to_string()
        );
    }

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
            swap: None,
            storage: None,
            inodes: None,
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
            swap: None,
            storage: None,
            inodes: None,
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
    fn only_the_created_leaf_shape_is_a_leaf_name() {
        use std::ffi::OsStr;
        let token = crate::state::AttemptId::generate();
        let name = leaf_name(&token);
        assert!(is_leaf_name(OsStr::new(&name)));
        for other in [
            "ouro-att_x.leaf",
            "ouro-j3none-replace-1-0",
            "user@1001.service",
            "app.slice",
            &format!("{name}.evil"),
            &format!("x{name}"),
            &name.replace(".leaf", ""),
            &name.to_uppercase(),
            "",
        ] {
            assert!(!is_leaf_name(OsStr::new(other)), "{other}");
        }
        use std::os::unix::ffi::OsStrExt as _;
        assert!(!is_leaf_name(OsStr::from_bytes(b"ouro-\xff.leaf")));
    }

    #[test]
    fn population_is_read_from_its_own_line_only() {
        assert!(parse_populated("populated 1\nfrozen 0\n").unwrap());
        assert!(!parse_populated("frozen 0\npopulated 0\n").unwrap());
        for bad in [
            "",
            "frozen 1\n",
            "populated 2\n",
            "populated\n",
            "populated x\n",
        ] {
            assert!(parse_populated(bad).is_err(), "{bad:?}");
        }
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
            swap: None,
            storage: None,
            inodes: None,
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
        // The two predicates agree on a boundary that names nothing: an
        // empty or root delegation contains no cgroup.
        for empty in ["", "/"] {
            assert!(!common_ancestor_ok(delegated, empty), "{empty:?}");
            assert!(!within(delegated, empty), "{empty:?}");
        }
        // A prefix that is not a path component must not count.
        assert!(!common_ancestor_ok(
            "/user.slice/user-1001.slice/user@1001.service.evil",
            delegated
        ));
    }
}
