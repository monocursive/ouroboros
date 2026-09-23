//! `gc` reconciliation on Linux: the recorded owner's liveness and the
//! identity-checked probe, kill and removal of an execution cgroup a dead
//! supervisor left (jail-v1 §9.3, §14.2, §15 C03).
//!
//! "Never signal a PID recovered from a file without revalidating its
//! identity" (§9.3). Nothing here signals a pid at all. The owner's pid is
//! only read (`/proc/<pid>/stat`), and compared by birth time; the only kill
//! is a write of `cgroup.kill` opened relative to a descriptor of the leaf
//! directory whose `(device, inode)` the receipt registered.
//!
//! How a recorded leaf is pinned ([`pin`]):
//! 1. The path must be a direct child of this user's delegated subtree
//!    (`user@<uid>.service`) and have the name `ExecutionCgroup::create`
//!    gives (`ouro-<token>.leaf`): gc never follows a registration anywhere
//!    else in cgroupfs.
//! 2. The parent is opened `O_DIRECTORY | O_NOFOLLOW` and must be cgroup v2.
//! 3. The name is looked up in that parent (`fstatat`, no follow) and must be
//!    a directory with the recorded `(device, inode)`; it is then opened
//!    relative to the parent and the opened descriptor must still have that
//!    identity and be cgroup v2. cgroup v2 refuses `rename`, so a different
//!    cgroup at the path can only be a new directory, with a new inode; inode
//!    numbers of kernfs are not reused within a boot, and another boot is
//!    never probed (the decision checks the boot first).
//!
//! Every later operation uses that descriptor: `cgroup.events` and
//! `cgroup.kill` are opened relative to it, so a path swapped after the check
//! is never signalled. Removal is by name in the pinned parent after the same
//! identity check, and `rmdir` of a cgroup refuses a populated one (`EBUSY`),
//! so a same-uid swap between the check and the `unlinkat` can at most remove
//! an empty cgroup of the same user in the same delegated subtree.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use super::cgroup;
use super::identity;
use crate::gc::{LeafProbe, LeafRecord, Liveness, OwnerRecord};

/// How deep a child-made cgroup subtree inside a leaf may be before gc
/// retains it rather than holding more descriptors (§14.2: 128 open
/// directories; two are the leaf's parent and the leaf).
const MAX_CHILD_DEPTH: usize = 64;
/// How often a killed leaf's population is re-read.
const POLL: Duration = Duration::from_millis(10);

// ---------------------------------------------------------------------------
// The owner
// ---------------------------------------------------------------------------

/// Whether the recorded owner, of this boot, is alive (§7, §9.3).
///
/// Reads `/proc/<pid>/stat` once and compares the birth time: a different
/// one means the kernel reused the pid for another process. Signals nothing.
#[must_use]
pub fn owner_liveness(owner: &OwnerRecord) -> Liveness {
    let Ok(pid) = libc::pid_t::try_from(owner.pid) else {
        return Liveness::Unknown(format!("pid {} is out of range", owner.pid));
    };
    if pid <= 0 {
        return Liveness::Unknown(format!("pid {pid} names no process"));
    }
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(raw) => classify(&raw, owner.start_time_ticks),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            Liveness::Gone
        }
        Err(error) => Liveness::Unknown(format!("/proc/{pid}/stat: {error}")),
    }
}

/// What a `/proc/<pid>/stat` line says about a process recorded with
/// `recorded_start` as its birth time.
#[must_use]
pub fn classify(raw: &str, recorded_start: u64) -> Liveness {
    let start = match identity::parse_start_time_ticks(raw) {
        Ok(start) => start,
        Err(error) => return Liveness::Unknown(format!("stat: {error}")),
    };
    if start != recorded_start {
        return Liveness::Reused;
    }
    match identity::parse_state(raw) {
        // A zombie has exited; `X` is dead. Neither holds a lock or kills.
        Ok('Z' | 'X' | 'x') => Liveness::Exited,
        Ok(_) => Liveness::Alive,
        Err(error) => Liveness::Unknown(format!("stat: {error}")),
    }
}

// ---------------------------------------------------------------------------
// Descriptor-relative primitives
// ---------------------------------------------------------------------------

fn open_at(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: `dir` is an open directory descriptor the caller keeps open for
    // the call, `name` is NUL-terminated, and openat dereferences nothing
    // else; O_NOFOLLOW and O_CLOEXEC are added to whatever the caller asks.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat; nothing else owns it.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_dir(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: a NUL-terminated path; open dereferences nothing else.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by open; nothing else owns it.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// `(device, inode, is a directory)` of `name` in `dir`, not following it.
fn stat_at(dir: RawFd, name: &CStr) -> io::Result<(u64, u64, bool)> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: an open directory descriptor, a NUL-terminated name and a
    // pointer to memory the size of `struct stat`, which fstatat fills.
    let rc = unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat returned 0, so it initialised the whole struct.
    let stat = unsafe { stat.assume_init() };
    Ok((
        stat.st_dev,
        stat.st_ino,
        stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
    ))
}

fn is_cgroup2(file: &File) -> io::Result<bool> {
    let mut filesystem = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: an open descriptor and a pointer to memory the size of
    // `struct statfs`, which fstatfs fills.
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs returned 0, so it initialised the whole struct.
    Ok(unsafe { filesystem.assume_init() }.f_type == libc::CGROUP2_SUPER_MAGIC)
}

fn rmdir_at(dir: RawFd, name: &CStr) -> io::Result<()> {
    // SAFETY: an open directory descriptor and a NUL-terminated name.
    // AT_REMOVEDIR removes only an empty directory; a cgroup that holds a
    // process or a child cgroup is refused by the kernel (EBUSY).
    if unsafe { libc::unlinkat(dir, name.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The child directories of `dir`, charging every entry read to `entries`.
fn child_dirs(dir: &File, entries: &mut usize) -> Result<Vec<CString>, String> {
    // SAFETY: duplicating an open descriptor; F_DUPFD_CLOEXEC dereferences
    // nothing.
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(format!("dup: {}", io::Error::last_os_error()));
    }
    // SAFETY: `fd` is a fresh duplicate this function owns; fdopendir takes
    // it over on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so `fd` is still this function's alone.
        unsafe { libc::close(fd) };
        return Err(format!("fdopendir: {error}"));
    }
    // SAFETY: `stream` is a valid directory stream; a duplicate shares the
    // file offset, so start from the beginning whatever read it before.
    unsafe { libc::rewinddir(stream) };
    let mut names = Vec::new();
    let result = loop {
        // SAFETY: errno is thread-local; clearing it tells end-of-stream
        // (null, errno 0) from an error (null, errno set).
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` is a valid directory stream owned here.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            break match error.raw_os_error() {
                Some(0) | None => Ok(()),
                Some(_) => Err(format!("readdir: {error}")),
            };
        }
        if *entries == 0 {
            break Err("the per-invocation entry bound is reached".to_owned());
        }
        *entries -= 1;
        // SAFETY: readdir returned a valid entry whose `d_name` is a
        // NUL-terminated array inside it, valid until the next readdir.
        let (name, kind) = unsafe { (CStr::from_ptr((*entry).d_name.as_ptr()), (*entry).d_type) };
        if kind == libc::DT_DIR && name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    };
    // SAFETY: closes the stream, and with it the duplicate, exactly once.
    unsafe { libc::closedir(stream) };
    result.map(|()| names)
}

// ---------------------------------------------------------------------------
// The pinned leaf
// ---------------------------------------------------------------------------

/// A recorded leaf, opened and positively identified.
struct Pinned {
    dir: File,
    parent: File,
    name: CString,
    identity: (u64, u64),
}

/// Pins the recorded leaf under this user's delegated subtree.
fn pin(leaf: &LeafRecord) -> Result<Pinned, LeafProbe> {
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let Some(root) = cgroup::delegated_root(euid) else {
        return Err(LeafProbe::Unverifiable(
            "this user has no delegated cgroup subtree".to_owned(),
        ));
    };
    pin_under(&root, leaf)
}

/// [`pin`] with the delegated root given, so its refusals can be tested.
fn pin_under(root: &Path, leaf: &LeafRecord) -> Result<Pinned, LeafProbe> {
    let unverifiable = |why: String| LeafProbe::Unverifiable(why);
    if leaf.path.parent() != Some(root) {
        return Err(unverifiable(
            "the recorded leaf is not a direct child of this user's delegated cgroup subtree"
                .to_owned(),
        ));
    }
    let Some(name) = leaf
        .path
        .file_name()
        .filter(|name| cgroup::is_leaf_name(name))
    else {
        return Err(unverifiable(
            "the recorded name is not an execution leaf's name".to_owned(),
        ));
    };
    let name = CString::new(name.as_bytes()).map_err(|error| unverifiable(error.to_string()))?;
    let parent =
        open_dir(root).map_err(|error| unverifiable(format!("the delegated subtree: {error}")))?;
    match is_cgroup2(&parent) {
        Ok(true) => {}
        Ok(false) => {
            return Err(unverifiable(
                "the delegated subtree is not cgroup v2".to_owned(),
            ));
        }
        Err(error) => return Err(unverifiable(format!("the delegated subtree: {error}"))),
    }
    let identity = (leaf.device, leaf.inode);
    match stat_at(parent.as_raw_fd(), &name) {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Err(LeafProbe::Absent),
        Err(error) => return Err(unverifiable(format!("the recorded leaf: {error}"))),
        Ok((_, _, false)) => {
            return Err(unverifiable(
                "the recorded leaf's name is not a directory".to_owned(),
            ));
        }
        Ok((device, inode, true)) if (device, inode) != identity => {
            return Err(LeafProbe::Replaced);
        }
        Ok(_) => {}
    }
    let dir = match open_at(
        parent.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY,
    ) {
        Ok(dir) => dir,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Err(LeafProbe::Absent),
        Err(error) => return Err(unverifiable(format!("the recorded leaf: {error}"))),
    };
    let opened = {
        use std::os::unix::fs::MetadataExt as _;
        dir.metadata()
            .map(|meta| (meta.dev(), meta.ino()))
            .map_err(|error| unverifiable(format!("the recorded leaf: {error}")))?
    };
    // A swap between the lookup and the open is a different directory.
    if opened != identity {
        return Err(LeafProbe::Replaced);
    }
    match is_cgroup2(&dir) {
        Ok(true) => {}
        Ok(false) => {
            return Err(unverifiable(
                "the recorded leaf is not cgroup v2".to_owned(),
            ));
        }
        Err(error) => return Err(unverifiable(format!("the recorded leaf: {error}"))),
    }
    Ok(Pinned {
        dir,
        parent,
        name,
        identity,
    })
}

impl Pinned {
    fn control(&self, name: &CStr, write: bool) -> io::Result<File> {
        open_at(
            self.dir.as_raw_fd(),
            name,
            if write {
                libc::O_WRONLY
            } else {
                libc::O_RDONLY
            },
        )
    }

    fn populated(&self) -> Result<bool, String> {
        let mut text = String::new();
        self.control(c"cgroup.events", false)
            .and_then(|file| file.take(16384).read_to_string(&mut text))
            .and_then(|_| cgroup::parse_populated(&text))
            .map_err(|error| format!("cgroup.events: {error}"))
    }

    fn kill(&self) -> Result<(), String> {
        self.control(c"cgroup.kill", true)
            .and_then(|mut file| file.write_all(b"1"))
            .map_err(|error| format!("cgroup.kill: {error}"))
    }

    /// Removes the leaf by name in the pinned parent, while the name still
    /// is the pinned leaf, after removing the (empty) child cgroups a child
    /// made inside it.
    fn remove(&self, entries: &mut usize) -> Result<(), String> {
        match self.unlink() {
            Ok(()) => return Ok(()),
            Err(error)
                if error.raw_os_error() == Some(libc::EBUSY)
                    || error.raw_os_error() == Some(libc::ENOTEMPTY) => {}
            Err(error) => return Err(format!("rmdir: {error}")),
        }
        remove_children(&self.dir, 0, entries)?;
        if self.populated()? {
            return Err("populated again; an occupied cgroup is never removed".to_owned());
        }
        self.unlink().map_err(|error| format!("rmdir: {error}"))
    }

    fn unlink(&self) -> io::Result<()> {
        let (device, inode, directory) = stat_at(self.parent.as_raw_fd(), &self.name)?;
        if !directory || (device, inode) != self.identity {
            return Err(io::Error::other("the leaf's name now names another cgroup"));
        }
        rmdir_at(self.parent.as_raw_fd(), &self.name)
    }
}

/// Removes the empty child cgroups of `dir`, depth first, bounded in depth
/// and by `entries`.
fn remove_children(dir: &File, depth: usize, entries: &mut usize) -> Result<(), String> {
    if depth >= MAX_CHILD_DEPTH {
        return Err(format!(
            "the leaf holds child cgroups deeper than {MAX_CHILD_DEPTH} levels"
        ));
    }
    for name in child_dirs(dir, entries)? {
        let child = open_at(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|error| format!("a child cgroup: {error}"))?;
        remove_children(&child, depth + 1, entries)?;
        drop(child);
        rmdir_at(dir.as_raw_fd(), &name).map_err(|error| format!("a child cgroup: {error}"))?;
    }
    Ok(())
}

/// Whether this process itself runs inside the recorded leaf: gc never ends
/// its own cgroup.
fn holds_this_process(leaf: &LeafRecord) -> Result<bool, String> {
    let own = cgroup::own_cgroup().map_err(|error| format!("/proc/self/cgroup: {error}"))?;
    let relative = leaf
        .path
        .strip_prefix(cgroup::CGROUP_ROOT)
        .map_err(|_| "the recorded leaf is outside the cgroup v2 mount".to_owned())?;
    Ok(cgroup::within(&own, &format!("/{}", relative.display())))
}

fn describe(probe: &LeafProbe) -> String {
    match probe {
        LeafProbe::Absent => "the recorded leaf no longer exists".to_owned(),
        LeafProbe::Replaced => "the path names another cgroup".to_owned(),
        LeafProbe::Unverifiable(reason) => reason.clone(),
        LeafProbe::Identified { .. } => "identified".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// What gc asks and does
// ---------------------------------------------------------------------------

/// What is at the recorded leaf's path.
#[must_use]
pub fn probe_leaf(leaf: &LeafRecord) -> LeafProbe {
    let pinned = match pin(leaf) {
        Ok(pinned) => pinned,
        Err(probe) => return probe,
    };
    match holds_this_process(leaf) {
        Ok(false) => {}
        Ok(true) => {
            return LeafProbe::Unverifiable(
                "this gc process runs inside the recorded leaf".to_owned(),
            );
        }
        Err(error) => return LeafProbe::Unverifiable(error),
    }
    match pinned.populated() {
        Ok(populated) => LeafProbe::Identified { populated },
        Err(error) => LeafProbe::Unverifiable(error),
    }
}

/// Re-pins the leaf, writes its `cgroup.kill` (recursive, and it handles
/// concurrent forks, §9.3) and waits at most `budget` for `populated 0`.
///
/// # Errors
/// Why the leaf was not identified, killed or seen empty in time.
pub fn terminate_leaf(leaf: &LeafRecord, budget: Duration) -> Result<(), String> {
    let pinned = pin(leaf).map_err(|probe| describe(&probe))?;
    if holds_this_process(leaf)? {
        return Err("this gc process runs inside the recorded leaf".to_owned());
    }
    pinned.kill()?;
    let deadline = Instant::now() + budget;
    loop {
        if !pinned.populated()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "still populated {} ms after cgroup.kill",
                budget.as_millis()
            ));
        }
        std::thread::sleep(POLL);
    }
}

/// Re-pins the leaf, checks it is empty and removes it with its empty child
/// cgroups, spending at most `entries` directory entries.
///
/// # Errors
/// Why the leaf was not identified, not empty or not removed.
pub fn remove_leaf(leaf: &LeafRecord, entries: &mut usize) -> Result<(), String> {
    let pinned = pin(leaf).map_err(|probe| describe(&probe))?;
    if pinned.populated()? {
        return Err("populated; an occupied cgroup is never removed".to_owned());
    }
    pinned.remove(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_line(state: char, start: u64) -> String {
        // Fields 1 and 2, then field 3 (state) and 18 more up to field 22.
        let mut fields = vec![state.to_string()];
        fields.extend((4..22).map(|field| field.to_string()));
        fields.push(start.to_string());
        format!("4242 (a (tricky) name) {}", fields.join(" "))
    }

    #[test]
    fn birth_time_and_state_decide_liveness() {
        assert_eq!(classify(&stat_line('S', 900), 900), Liveness::Alive);
        assert_eq!(classify(&stat_line('R', 900), 900), Liveness::Alive);
        assert_eq!(classify(&stat_line('S', 901), 900), Liveness::Reused);
        assert_eq!(classify(&stat_line('Z', 900), 900), Liveness::Exited);
        assert_eq!(classify(&stat_line('X', 900), 900), Liveness::Exited);
        assert!(matches!(classify("garbage", 900), Liveness::Unknown(_)));
    }

    #[test]
    fn a_pid_that_cannot_name_a_process_is_unknown_or_gone() {
        let owner = |pid| OwnerRecord {
            pid,
            boot_id: String::new(),
            start_time_ticks: 1,
        };
        assert!(matches!(owner_liveness(&owner(0)), Liveness::Unknown(_)));
        assert!(matches!(
            owner_liveness(&owner(u32::MAX)),
            Liveness::Unknown(_)
        ));
        // This process, recorded with a birth time it does not have.
        let mine = owner(std::process::id());
        assert_eq!(owner_liveness(&mine), Liveness::Reused);
        let born =
            identity::start_time_ticks(libc::pid_t::try_from(std::process::id()).unwrap()).unwrap();
        assert_eq!(
            owner_liveness(&OwnerRecord {
                start_time_ticks: born,
                ..mine
            }),
            Liveness::Alive
        );
    }

    #[test]
    fn only_a_leaf_named_and_placed_as_created_is_ever_opened() {
        let root = tempfile::tempdir().unwrap();
        let token = crate::state::AttemptId::generate();
        let name = cgroup::leaf_name(&token);
        let leaf = |path: std::path::PathBuf| LeafRecord {
            path,
            device: 0,
            inode: 0,
        };
        // Not under the root, nested below it, or not a leaf name: refused
        // before anything is opened.
        for path in [
            Path::new("/sys/fs/cgroup").join(&name),
            root.path().join("nested").join(&name),
            root.path().join("ouro-j3none-replace-1-0"),
            root.path().join("user@1001.service"),
        ] {
            assert!(
                matches!(
                    pin_under(root.path(), &leaf(path.clone())),
                    Err(LeafProbe::Unverifiable(_))
                ),
                "{}",
                path.display()
            );
        }
        // Right place and name, but not cgroup v2: refused, even though it
        // exists and is a directory.
        std::fs::create_dir(root.path().join(&name)).unwrap();
        match pin_under(root.path(), &leaf(root.path().join(&name))) {
            Err(LeafProbe::Unverifiable(reason)) => {
                assert!(reason.contains("cgroup v2"), "{reason}")
            }
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("a tmpfs directory was pinned as a cgroup"),
        }
    }

    #[test]
    fn a_nul_in_a_recorded_name_is_refused_not_truncated() {
        let root = tempfile::tempdir().unwrap();
        let record = LeafRecord {
            path: root.path().join("ouro-\0.leaf"),
            device: 0,
            inode: 0,
        };
        assert!(matches!(
            pin_under(root.path(), &record),
            Err(LeafProbe::Unverifiable(_))
        ));
    }
}
