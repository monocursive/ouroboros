//! J12: the program `--from-path` runs (jail-launch-and-summary.md §3.3).
//!
//! `ukai-jail NAME` and `run --launch NAME --from-path` resolve the launch
//! name on the supervisor's own `PATH`, with the rule bubblewrap resolution
//! uses: the first absolute entry holding an executable regular file of that
//! name, canonicalized; empty and relative entries are never searched. The
//! result is then pinned by a no-follow walk from `/`, so the identity
//! recorded here is the object that walk reached, not whatever a name says
//! later:
//!
//! - every directory on the walk is owned by root or this operator and not
//!   writable by others without the sticky bit (the credential-source rule);
//! - from the install root down, no directory is writable by anyone but
//!   its owner, sticky or not (group write counts only through the owner's
//!   private group, the rule every other directory check of the jail uses:
//!   with Ubuntu's default umask 002 a user's own install directories are
//!   0775), and the executable is a regular file with an execute bit,
//!   neither group- nor other-writable at all (the vault's own executable
//!   pin), owned by root or this operator (stricter than §3.3 step 2, which
//!   names only the write bits: a file another local user owns can be
//!   rewritten in place under the identity a vault credential is bound to);
//! - the install root is the directory `program_root` levels above the
//!   executable, held open (`O_PATH` on Linux) so the platform binds exactly
//!   that object (`--ro-bind-fd`) and [`Program::recheck`] can walk to the
//!   executable again under it before release.
//!
//! The first bytes of the executable decide what else it needs. An ELF file
//! needs its loader, and every place its dynamic section lets the loader
//! open a library from, inside the runtime roots: those are opened by path
//! when it runs, so one in the install root would be code the pin does not
//! cover (review F2 of the F5 fix). A
//! `#!` interpreter inside the runtime roots needs nothing more. `#!/usr/bin/env
//! X` is expanded to `[X', E, ARG...]`, `X'` being `X` resolved the same way
//! on the operator's `PATH`, because inside the jail `env` would search the
//! fixed contained `PATH` instead; `X'` gets its own read-only root and the
//! same refusals. Every other form refuses naming the interpreter: options
//! to `env` (`-S`), several interpreter arguments, a nested script, an
//! interpreter outside the runtime roots.
//!
//! Nothing here names an agent (I02): the launch name is data.

use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::records::{ErrorCode, ErrorStage, JailError, Remediation};
use crate::state::anchored::{self, Dir, Kind, Name, Stat};

/// The key every refusal of this module names.
pub const KEY: &str = "--from-path";

/// The directories the interpreter and loader checks call the runtime roots:
/// the system trees every contained Linux profile binds read-only
/// ([`crate::profiles::LINUX_RUNTIME_ROOTS`] without its `/etc` files). The
/// same four names are the system trees on macOS, where execution is refused
/// and the check only decides what `explain` reports.
pub const RUNTIME_DIRECTORIES: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];

/// The most bytes of a `#!` line the kernel reads (`BINPRM_BUF_SIZE`), and
/// so the most this module reads to classify a script (§3.3 step 5).
pub const SHEBANG_MAX: usize = 256;
/// The longest ELF `PT_INTERP` string read.
const ELF_INTERP_MAX: u64 = 4096;
/// The most ELF program headers read.
const ELF_PHNUM_MAX: u64 = 512;

fn refused(code: ErrorCode, message: impl Into<String>) -> JailError {
    JailError::new(
        code,
        ErrorStage::Resolving,
        Remediation::Configuration,
        message.into(),
    )
    .with_key_path(KEY)
}

fn invalid(message: impl Into<String>) -> JailError {
    refused(ErrorCode::InvalidConfig, message)
}

fn widening(message: impl Into<String>) -> JailError {
    refused(ErrorCode::PolicyWidening, message)
}

/// The directory a derived read-only grant binds, held open.
#[derive(Clone, Debug)]
pub struct InstallRoot {
    /// The canonical directory.
    pub path: PathBuf,
    /// The handle the walk reached it by (`O_PATH` on Linux): the platform
    /// binds this object, and [`Program::recheck`] walks from it.
    pub handle: Arc<OwnedFd>,
    /// What `fstat` of the handle said at resolution.
    pub stat: Stat,
    /// The components from the root down to the executable, the file name
    /// last.
    below: Vec<Name>,
}

/// One pinned executable: the resolved program, or the interpreter an
/// `env` expansion made explicit.
#[derive(Clone, Debug)]
pub struct Executable {
    /// The canonical path, on the host and inside alike.
    pub path: PathBuf,
    /// Its identity, owner and mode at resolution.
    pub stat: Stat,
    /// The handle the walk reached it by.
    handle: Arc<OwnedFd>,
    /// The install root it is granted through.
    pub root: InstallRoot,
    /// Review F1: every symbolic link the `PATH` lookup passed through to
    /// reach it, by the link's own location (its directory resolved), so
    /// placement can refuse a lookup a child-writable root steered.
    pub found_through: Vec<PathBuf>,
    /// Review F5: its first bytes say ELF, so the launcher can execute it
    /// through a descriptor.
    elf: bool,
}

/// Review F1: what a `PATH` lookup found: the canonical file and every
/// symbolic link it followed on the way, each by its own location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// The canonical file.
    pub path: PathBuf,
    /// The links followed, in order, each at its resolved location.
    pub links: Vec<PathBuf>,
}

/// The most symbolic links one lookup follows (Linux's `MAXSYMLINKS`).
const LINKS_MAX: usize = 40;

/// Resolves `path` as `realpath(3)` does, by hand, recording the location of
/// every symbolic link it follows: the link's own name in its already
/// resolved directory.
///
/// # Errors
/// The `lstat`/`readlink` error, or `ELOOP` past [`LINKS_MAX`] links.
pub fn resolve_links(path: &Path) -> std::io::Result<Found> {
    walk_links(path, &mut |_| Ok(()))
}

/// [`resolve_links`], calling `visit` with every location the walk is about
/// to inspect, the final one included (each the next name in an already
/// resolved directory, so with no `.`, `..` or link in it), before it is
/// inspected; an error from `visit` stops the walk.
fn walk_links(
    path: &Path,
    visit: &mut dyn FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<Found> {
    use std::collections::VecDeque;
    use std::path::Component;
    let parts = |path: &Path| -> Vec<std::ffi::OsString> {
        path.components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_os_string()),
                Component::ParentDir => Some("..".into()),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
            })
            .collect()
    };
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not an absolute path",
        ));
    }
    let mut pending: VecDeque<std::ffi::OsString> = parts(path).into();
    let mut resolved = PathBuf::from("/");
    let mut links = Vec::new();
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let candidate = resolved.join(&part);
        visit(&candidate)?;
        let metadata = std::fs::symlink_metadata(&candidate)?;
        if !metadata.file_type().is_symlink() {
            resolved = candidate;
            continue;
        }
        if links.len() >= LINKS_MAX {
            return Err(std::io::Error::from_raw_os_error(libc::ELOOP));
        }
        let target = std::fs::read_link(&candidate)?;
        links.push(candidate);
        if target.is_absolute() {
            resolved = PathBuf::from("/");
        }
        for part in parts(&target).into_iter().rev() {
            pending.push_front(part);
        }
    }
    Ok(Found {
        path: resolved,
        links,
    })
}

/// What the executable's first bytes say it needs (§3.3 step 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Format {
    /// An ELF file; its loader, when it names one.
    Elf {
        /// The `PT_INTERP` path, absent for a static executable.
        loader: Option<PathBuf>,
    },
    /// A Mach-O file (macOS, where execution is refused).
    MachO,
    /// A `#!` script whose interpreter lies in the runtime roots.
    Script {
        /// The interpreter, as the line names it.
        interpreter: PathBuf,
    },
    /// `#!/usr/bin/env X`, expanded to `[X', E, ARG...]`.
    EnvExpanded {
        /// The `env` path the line names.
        env: PathBuf,
        /// The word after it.
        name: String,
    },
}

impl Format {
    /// The spelling `explain` and `doctor` use.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Format::Elf { .. } => "elf",
            Format::MachO => "mach-o",
            Format::Script { .. } => "script",
            Format::EnvExpanded { .. } => "env-expanded",
        }
    }
}

/// The program `--from-path` resolved.
#[derive(Clone, Debug)]
pub struct Program {
    /// The launch name, looked up on the operator's `PATH`.
    pub name: String,
    /// The resolved program `E`.
    pub program: Executable,
    /// What `E` needs.
    pub format: Format,
    /// `X'` after an `env` expansion.
    pub interpreter: Option<Executable>,
}

impl Program {
    /// The argv prefix the operator's arguments follow: `[E]`, or `[X', E]`
    /// after an `env` expansion. This is the argv the argv digest covers.
    #[must_use]
    pub fn argv_prefix(&self) -> Vec<Vec<u8>> {
        let mut argv = Vec::with_capacity(2);
        if let Some(interpreter) = &self.interpreter {
            argv.push(interpreter.path.as_os_str().as_bytes().to_vec());
        }
        argv.push(self.program.path.as_os_str().as_bytes().to_vec());
        argv
    }

    /// The executable a `binaries = ["@program"]` credential is bound to:
    /// `X'` after an expansion (so any script that interpreter runs could
    /// present the credential), `E` otherwise (§3.3 step 7).
    #[must_use]
    pub fn bound(&self) -> &Executable {
        self.interpreter.as_ref().unwrap_or(&self.program)
    }

    /// Every pinned executable, the program first.
    #[must_use]
    pub fn executables(&self) -> Vec<&Executable> {
        std::iter::once(&self.program)
            .chain(self.interpreter.as_ref())
            .collect()
    }

    /// The install roots, the program's first, each once.
    #[must_use]
    pub fn roots(&self) -> Vec<&InstallRoot> {
        let mut roots: Vec<&InstallRoot> = Vec::new();
        for executable in self.executables() {
            if !roots.iter().any(|root| root.path == executable.root.path) {
                roots.push(&executable.root);
            }
        }
        roots
    }

    /// Before release: every executable is still the object resolution
    /// pinned, reached again two ways: under the install root's own held
    /// handle (the object the platform binds), and by a fresh no-follow walk
    /// from `/` (what the path names now). Owner and mode are compared too,
    /// and every directory from the root down must still be closed to group
    /// and other writes (§3.3 step 3: "a swap between resolution and exec
    /// refuses instead of running another file").
    ///
    /// # Errors
    /// [`ErrorCode::PolicyWidening`] at [`KEY`] naming what changed.
    pub fn recheck(&self) -> Result<(), JailError> {
        for executable in self.executables() {
            executable.recheck()?;
        }
        Ok(())
    }

    /// Review F5: what the inside launcher checks after the release,
    /// immediately before it executes: every pinned executable at its argv
    /// index (`E` at 0, or `X'` at 0 and `E` at 1 after an `env`
    /// expansion), compared with what resolution recorded (the owner aside,
    /// see [`crate::platform::ExecPin`]). An ELF file at
    /// argv 0 is then executed through the descriptor the check opened, so
    /// no rename after the check can choose what runs. A `#!` script is
    /// opened again by name, by the kernel and by its interpreter, so it is
    /// checked by its path immediately before the exec instead.
    #[must_use]
    pub fn exec_pins(&self) -> Vec<crate::platform::ExecPin> {
        match &self.interpreter {
            Some(interpreter) => vec![interpreter.exec_pin(0), self.program.exec_pin(1)],
            None => vec![self.program.exec_pin(0)],
        }
    }
}

/// Review F5: a test seam. When this variable names a directory, the
/// supervisor writes `rechecked` there after the recheck before release and
/// waits up to ten seconds for `go`, so a test can swap the program in the
/// window the launcher's own check covers. Like every `UKAI_JAIL_TEST_*`
/// variable it is recorded in jail state and in every receipt with native
/// details; a value that is not a usable directory makes it a no-op.
pub const SWAP_SEAM: &str = "UKAI_JAIL_TEST_PROGRAM_SWAP";

/// The [`SWAP_SEAM`] rendezvous.
pub fn swap_rendezvous() {
    let Some(dir) = std::env::var_os(SWAP_SEAM) else {
        return;
    };
    let dir = PathBuf::from(dir);
    if std::fs::write(dir.join("rechecked"), b"1").is_err() {
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !dir.join("go").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

impl Executable {
    fn recheck(&self) -> Result<(), JailError> {
        let changed = |what: String| {
            widening(format!(
                "{} changed between resolution and release ({what}); identity mismatch, \
                 nothing was run",
                self.path.display()
            ))
        };
        let root = anchored::fstat(self.root.handle.as_fd())
            .map_err(|error| changed(format!("its install root cannot be inspected: {error}")))?;
        if (root.uid, root.mode) != (self.root.stat.uid, self.root.stat.mode)
            || root.kind != Kind::Directory
        {
            return Err(changed(
                "its install root's owner or mode changed".to_owned(),
            ));
        }
        let duplicate = self
            .root
            .handle
            .try_clone()
            .map_err(|error| changed(format!("its install root cannot be held: {error}")))?;
        let mut current = Dir::from_owned(duplicate);
        let Some((file, directories)) = self.root.below.split_last() else {
            return Err(changed("no path below its install root".to_owned()));
        };
        let mut walked = self.root.path.clone();
        for component in directories {
            walked.push(OsStr::from_bytes(component.as_bytes()));
            let stat = current
                .stat_at(component)
                .map_err(|error| changed(error.to_string()))?;
            if stat.kind != Kind::Directory {
                return Err(changed(format!(
                    "{} below its install root is {}",
                    walked.display(),
                    stat.kind.describe()
                )));
            }
            // The pin's own rule for a directory in the install root.
            check_directory(&stat, &walked, true).map_err(|error| changed(error.message))?;
            current = current
                .open_walk_at(component, Some(&stat))
                .map_err(|error| changed(error.to_string()))?;
        }
        let under_root = current
            .stat_at(file)
            .map_err(|error| changed(error.to_string()))?;
        let by_path = walk_stat(&self.path).map_err(changed)?;
        for (how, now) in [
            ("under its install root", under_root),
            ("by its path", by_path),
        ] {
            // Review F3: size, mtime, ctime and the link count too, so a
            // write in place or a new name since resolution is a change.
            if !now.unchanged_since(&self.stat)
                || (now.kind, now.uid, now.mode, now.nlink)
                    != (
                        self.stat.kind,
                        self.stat.uid,
                        self.stat.mode,
                        self.stat.nlink,
                    )
            {
                return Err(changed(format!(
                    "{how} it is {}:{} {} mode {:04o}, resolved as {}:{} mode {:04o}",
                    now.dev,
                    now.ino,
                    now.kind.describe(),
                    now.mode,
                    self.stat.dev,
                    self.stat.ino,
                    self.stat.mode
                )));
            }
        }
        Ok(())
    }

    /// The `(dev, ino)` resolution pinned.
    #[must_use]
    pub fn identity(&self) -> (u64, u64) {
        self.stat.identity()
    }

    /// Review F5: this executable as the launcher checks it at argv
    /// `index`; executed through a descriptor only as an ELF argv 0.
    fn exec_pin(&self, index: usize) -> crate::platform::ExecPin {
        crate::platform::ExecPin {
            index,
            by_descriptor: index == 0 && self.elf,
            identity: self.stat.identity(),
            size: self.stat.size,
            mtime: self.stat.mtime,
            ctime: self.stat.ctime,
            nlink: self.stat.nlink,
            mode: self.stat.mode,
        }
    }
}

/// Whether `uid` is root or this operator.
fn trusted_owner(uid: u32) -> bool {
    uid == 0 || uid == crate::state::effective_uid()
}

/// `fstatat` of an absolute path's final component after a no-follow walk
/// of its directories.
fn walk_stat(path: &Path) -> Result<Stat, String> {
    let components =
        anchored::split_absolute(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let Some((file, directories)) = components.split_last() else {
        return Err("it names `/`".to_owned());
    };
    let mut current = Dir::open_root_for_walk().map_err(|e| e.to_string())?;
    for component in directories {
        let stat = current.stat_at(component).map_err(|e| e.to_string())?;
        if stat.kind != Kind::Directory {
            return Err(format!("a component is {}", stat.kind.describe()));
        }
        current = current
            .open_walk_at(component, Some(&stat))
            .map_err(|e| e.to_string())?;
    }
    current.stat_at(file).map_err(|e| e.to_string())
}

/// Whether `path` (canonical) lies in [`RUNTIME_DIRECTORIES`].
#[must_use]
pub fn in_runtime_roots(path: &Path) -> bool {
    RUNTIME_DIRECTORIES
        .iter()
        .any(|root| path.starts_with(root))
}

/// Where an absolute path the kernel or the dynamic loader opens inside the
/// jail leads, when every location its resolution passes through lies in
/// the runtime roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// It names an existing object.
    Found,
    /// Its resolution stops inside the runtime roots (a missing name, a
    /// file used as a directory, a link loop): it names nothing there, and
    /// nothing below those read-only system trees can make it.
    Unreachable,
}

/// Review F2 of the F5 fix: follows the absolute `path` as the kernel does
/// (`..` after the link before it, `MAXSYMLINKS`), requiring every location
/// it passes through to lie in the runtime roots. Those are bound read-only
/// at their own paths inside, so the path names the same object inside as
/// here, and no file the pin leaves unchecked (the install root, a
/// child-writable root, the working directory) is on its way.
///
/// # Errors
/// The first location outside the runtime roots.
fn reach_in_runtime_roots(path: &Path) -> Result<Reach, PathBuf> {
    let mut outside = None;
    let walked = walk_links(path, &mut |location| {
        if in_runtime_roots(location) {
            Ok(())
        } else {
            outside = Some(location.to_path_buf());
            Err(std::io::Error::other("outside the runtime roots"))
        }
    });
    match (walked, outside) {
        (_, Some(location)) => Err(location),
        // `..` can end the walk at `/`, which no visit inspected.
        (Ok(found), None) if !in_runtime_roots(&found.path) => Err(found.path),
        (Ok(_), None) => Ok(Reach::Found),
        (Err(_), None) => Ok(Reach::Unreachable),
    }
}

/// Looks `name` up on a `PATH` value as bubblewrap resolution does: the
/// first absolute entry holding an executable regular file of that name,
/// canonicalized (operating.md, "install"). Empty and relative entries are
/// skipped and named in the refusal: either would let the invocation
/// directory, which a hostile repository controls, pick the program.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] at [`KEY`] when nothing matches.
pub fn find_on_path(name: &str, path: Option<&[u8]>) -> Result<PathBuf, JailError> {
    find_on_path_traced(name, path).map(|found| found.path)
}

/// [`find_on_path`], with every symbolic link the lookup followed.
///
/// # Errors
/// As [`find_on_path`].
pub fn find_on_path_traced(name: &str, path: Option<&[u8]>) -> Result<Found, JailError> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(invalid(format!("`{name}` is not a program name")));
    }
    let Some(path) = path else {
        return Err(invalid(format!(
            "PATH is unset, so `{name}` cannot be resolved; pass the program after `--` \
             without --from-path"
        )));
    };
    let mut skipped = Vec::new();
    for entry in path.split(|byte| *byte == b':') {
        if entry.is_empty() || entry[0] != b'/' {
            skipped.push(format!("{:?}", String::from_utf8_lossy(entry)));
            continue;
        }
        let candidate = Path::new(OsStr::from_bytes(entry)).join(name);
        let Ok(found) = resolve_links(&candidate) else {
            continue;
        };
        let canonical = found.path.clone();
        let Ok(metadata) = std::fs::metadata(&canonical) else {
            continue;
        };
        let Ok(c_path) = std::ffi::CString::new(canonical.as_os_str().as_bytes()) else {
            continue;
        };
        // SAFETY: `c_path` is a live NUL-terminated string; access reads it.
        let executable = unsafe { libc::access(c_path.as_ptr(), libc::X_OK) } == 0;
        if metadata.is_file() && executable {
            return Ok(found);
        }
    }
    let mut message = format!("no executable `{name}` in any absolute PATH entry");
    if !skipped.is_empty() {
        message.push_str(&format!(
            " (empty or relative entries are never searched: {})",
            skipped.join(", ")
        ));
    }
    Err(invalid(message))
}

/// Pins the canonical executable `path` by a no-follow walk from `/`, with
/// its install root `levels` directories above it (§3.3 steps 2 and 3).
///
/// # Errors
/// [`ErrorCode::PolicyWidening`] at [`KEY`] for a writable or foreign-owned
/// object on the way, [`ErrorCode::InvalidConfig`] for anything else that
/// stops the walk.
pub fn pin(path: &Path, levels: u8) -> Result<Executable, JailError> {
    let components = anchored::split_absolute(path.as_os_str().as_bytes())
        .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
    let Some((file, directories)) = components.split_last() else {
        return Err(invalid("the program names `/`"));
    };
    let levels = usize::from(levels);
    if levels == 0 || levels > directories.len() {
        return Err(widening(format!(
            "an install root {levels} levels above {} would be `/` or beyond it",
            path.display()
        )));
    }
    // The depth of the install root: 0 is `/`.
    let root_depth = directories.len() + 1 - levels;
    let mut current = Dir::open_root_for_walk()
        .map_err(|error| invalid(format!("`/` cannot be opened: {error}")))?;
    let mut walked = PathBuf::from("/");
    let mut root: Option<(Arc<OwnedFd>, Stat, PathBuf)> = None;
    let mut stat = current
        .stat()
        .map_err(|error| invalid(format!("`/` cannot be inspected: {error}")))?;
    check_directory(&stat, &walked, root_depth == 0)?;
    for (index, component) in directories.iter().enumerate() {
        let depth = index + 1;
        walked.push(OsStr::from_bytes(component.as_bytes()));
        stat = current
            .stat_at(component)
            .map_err(|error| invalid(format!("{}: {error}", walked.display())))?;
        if stat.kind != Kind::Directory {
            return Err(invalid(format!(
                "{} is {}; the program path changed while it was resolved",
                walked.display(),
                stat.kind.describe()
            )));
        }
        check_directory(&stat, &walked, depth >= root_depth)?;
        current = current
            .open_walk_at(component, Some(&stat))
            .map_err(|error| invalid(format!("{}: {error}", walked.display())))?;
        if depth == root_depth {
            let handle = current
                .try_clone_fd()
                .map_err(|error| invalid(format!("{}: {error}", walked.display())))?;
            root = Some((Arc::new(handle), stat, walked.clone()));
        }
    }
    let Some((root_handle, root_stat, root_path)) = root else {
        return Err(widening(format!(
            "the install root of {} would be `/`",
            path.display()
        )));
    };
    let stat = current
        .stat_at(file)
        .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
    check_executable(&stat, path)?;
    let handle = open_executable(&current, file, &stat)
        .map_err(|error| invalid(format!("{} cannot be opened: {error}", path.display())))?;
    let below = components[root_depth..].to_vec();
    Ok(Executable {
        path: path.to_path_buf(),
        stat,
        handle: Arc::new(handle),
        root: InstallRoot {
            path: root_path,
            handle: root_handle,
            stat: root_stat,
            below,
        },
        found_through: Vec::new(),
        elf: false,
    })
}

/// The directory rule of the walk: root or this operator, not writable by
/// others without the sticky bit; from the install root down
/// (`in_root`), not group- or other-writable at all.
fn check_directory(stat: &Stat, path: &Path, in_root: bool) -> Result<(), JailError> {
    if !trusted_owner(stat.uid) {
        return Err(widening(format!(
            "{} is owned by uid {}, neither root nor this operator",
            path.display(),
            stat.uid
        )));
    }
    if crate::state::writable_by_others(stat.mode, stat.uid, stat.gid) && stat.mode & 0o1000 == 0 {
        return Err(widening(format!(
            "{} has mode {:04o}: writable by others without the sticky bit",
            path.display(),
            stat.mode
        )));
    }
    if in_root && crate::state::writable_by_others(stat.mode, stat.uid, stat.gid) {
        return Err(widening(format!(
            "{} has mode {:04o}: a directory in the program's install root may not be \
             writable by anyone but its owner (a group write is allowed only for the owner's \
             private group)",
            path.display(),
            stat.mode
        )));
    }
    Ok(())
}

/// The executable rule: a regular file with an execute bit, owned by root
/// or this operator, writable by neither group nor others.
fn check_executable(stat: &Stat, path: &Path) -> Result<(), JailError> {
    if stat.kind != Kind::Regular {
        return Err(invalid(format!(
            "{} is {}, not a regular file",
            path.display(),
            stat.kind.describe()
        )));
    }
    if stat.mode & 0o111 == 0 {
        return Err(invalid(format!("{} is not executable", path.display())));
    }
    if stat.mode & 0o022 != 0 {
        return Err(widening(format!(
            "{} has mode {:04o}: a program may not be group- or other-writable",
            path.display(),
            stat.mode
        )));
    }
    if !trusted_owner(stat.uid) {
        return Err(widening(format!(
            "{} is owned by uid {}, neither root nor this operator",
            path.display(),
            stat.uid
        )));
    }
    // Review F3: a program this operator can write must have one name. A
    // second one (a package manager's hard-linked store) could lie inside a
    // child-writable root, and a write through it would rewrite, in place,
    // the file the operator's next unjailed launch runs. A root-owned file
    // with several names is safe from a non-root operator's agent: it cannot
    // write it through any of them.
    if stat.nlink != 1 && stat.uid == crate::state::effective_uid() {
        return Err(widening(format!(
            "{} has {} hard links; another name for a program you can write could lie where \
             the agent can write it",
            path.display(),
            stat.nlink
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_executable(dir: &Dir, name: &Name, stat: &Stat) -> std::io::Result<OwnedFd> {
    let handle = dir.open_path_at(name)?;
    let opened = anchored::fstat(handle.as_fd())?;
    if opened.identity() != stat.identity() || opened.kind != Kind::Regular {
        return Err(std::io::Error::other("it was replaced while it was opened"));
    }
    Ok(handle)
}

#[cfg(not(target_os = "linux"))]
fn open_executable(dir: &Dir, name: &Name, stat: &Stat) -> std::io::Result<OwnedFd> {
    dir.open_read_at(name, Some(stat)).map(OwnedFd::from)
}

/// The pinned executable, opened for reading through its handle.
fn reader(executable: &Executable) -> std::io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        anchored::reopen_checked(executable.handle.as_fd(), &executable.stat)
    }
    #[cfg(not(target_os = "linux"))]
    {
        executable.handle.try_clone().map(File::from)
    }
}

/// Reads up to `max` bytes at `offset`.
fn read_at(file: &File, offset: u64, max: u64) -> std::io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; usize::try_from(max).unwrap_or(0)];
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read_at(&mut buffer[filled..], offset + filled as u64) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// Resolves the launch name `name` on the `PATH` value `path`, pins it with
/// its install root `program_root` levels up, and classifies what it needs
/// (§3.3 steps 1 to 5).
///
/// # Errors
/// The refusal of the step that failed, at [`KEY`].
pub fn resolve(name: &str, path: Option<&[u8]>, program_root: u8) -> Result<Program, JailError> {
    let found = find_on_path_traced(name, path)?;
    let mut program = pin(&found.path, program_root)?;
    program.found_through = found.links;
    let mut format = classify(&program)?;
    program.elf = matches!(format, Format::Elf { .. });
    let interpreter = match &format {
        Format::Elf { .. } | Format::MachO | Format::Script { .. } => None,
        Format::EnvExpanded { env, name: word } => {
            let found = find_on_path_traced(word, path).map_err(|error| {
                refused(
                    ErrorCode::ExecInterpreterMissing,
                    format!(
                        "{} runs `{} {word}`, and `{word}` cannot be resolved: {}",
                        program.path.display(),
                        env.display(),
                        error.message
                    ),
                )
            })?;
            if in_runtime_roots(&found.path) {
                // Review F2, §3.3 step 5: an interpreter inside the runtime
                // roots needs nothing more; the expansion is for one outside
                // them. This is then a `#!` script with a system
                // interpreter, which `@program` refuses to bind.
                format = Format::Script {
                    interpreter: env.clone(),
                };
                return Ok(Program {
                    name: name.to_owned(),
                    program,
                    format,
                    interpreter: None,
                });
            }
            let mut interpreter = pin(&found.path, 1)?;
            interpreter.found_through = found.links;
            match classify(&interpreter)? {
                Format::Elf { .. } => interpreter.elf = true,
                Format::MachO => {}
                Format::Script { .. } | Format::EnvExpanded { .. } => {
                    return Err(invalid(format!(
                        "the interpreter {} of {} is itself a script; a nested script is not \
                         expanded",
                        interpreter.path.display(),
                        program.path.display()
                    )));
                }
            }
            Some(interpreter)
        }
    };
    Ok(Program {
        name: name.to_owned(),
        program,
        format,
        interpreter,
    })
}

/// What the executable's first bytes say it is. An ELF file's loader and
/// the libraries its dynamic section names are checked here (§3.3 step 5;
/// review F2 of the F5 fix): the kernel and the dynamic loader open them by
/// path when it runs, outside the pin.
fn classify(executable: &Executable) -> Result<Format, JailError> {
    let unreadable = |error: std::io::Error| {
        invalid(format!(
            "{} cannot be read: {error}",
            executable.path.display()
        ))
    };
    let file = reader(executable).map_err(unreadable)?;
    let head = read_at(&file, 0, SHEBANG_MAX as u64).map_err(unreadable)?;
    if head.starts_with(b"\x7fELF") {
        let elf = elf_headers(&file, &head)
            .map_err(|why| invalid(format!("{}: {why}", executable.path.display())))?;
        check_loader(executable, elf.loader.as_deref())?;
        check_libraries(executable, &elf.libraries)?;
        return Ok(Format::Elf { loader: elf.loader });
    }
    if head.starts_with(b"#!") {
        return shebang(executable, &head);
    }
    if cfg!(target_os = "macos")
        && [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
        ]
        .iter()
        .any(|magic| head.starts_with(magic))
    {
        return Ok(Format::MachO);
    }
    Err(invalid(format!(
        "{} is neither an ELF executable nor a `#!` script",
        executable.path.display()
    )))
}

/// The program header types read.
const PT_LOAD: u64 = 1;
const PT_DYNAMIC: u64 = 2;
const PT_INTERP: u64 = 3;
/// The dynamic tags read: the table's end, the string table and its size,
/// and the entries naming libraries or where to search for them.
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const DT_DEPAUDIT: u64 = 0x6fff_fefb;
const DT_AUDIT: u64 = 0x6fff_fefc;
const DT_AUXILIARY: u64 = 0x7fff_fffd;
const DT_FILTER: u64 = 0x7fff_ffff;
/// The largest dynamic section read (4096 64-bit entries).
const ELF_DYNAMIC_MAX: u64 = 64 * 1024;
/// The longest dynamic string read.
const ELF_STRING_MAX: u64 = 64 * 1024;

/// What an ELF file's headers say is opened by path when it runs.
#[derive(Debug, Default, PartialEq, Eq)]
struct Elf {
    /// The `PT_INTERP` path, absent for a static executable.
    loader: Option<PathBuf>,
    /// Every `DT_NEEDED`, `DT_FILTER`, `DT_AUXILIARY`, `DT_RPATH`,
    /// `DT_RUNPATH`, `DT_AUDIT` and `DT_DEPAUDIT` string before `DT_NULL`,
    /// with its tag, in table order.
    libraries: Vec<(u64, Vec<u8>)>,
}

/// Reads an ELF file's loader and dynamic section as the kernel and the
/// dynamic loader do: the first `PT_INTERP`; the dynamic section and its
/// string table at their addresses, mapped to file offsets through the
/// `PT_LOAD` segments (the loader never reads `PT_DYNAMIC`'s file offset);
/// the table up to `DT_NULL`. Several `PT_DYNAMIC` headers refuse (glibc
/// uses the last one).
fn elf_headers(file: &File, head: &[u8]) -> Result<Elf, String> {
    let truncated = || "its ELF headers are truncated".to_owned();
    let class64 = match head.get(4) {
        Some(1) => false,
        Some(2) => true,
        _ => return Err("its ELF class is not 32 or 64 bits".to_owned()),
    };
    let little = match head.get(5) {
        Some(1) => true,
        Some(2) => false,
        _ => return Err("its ELF byte order is unknown".to_owned()),
    };
    let field = |bytes: &[u8], offset: usize, width: usize| -> Option<u64> {
        let slice = bytes.get(offset..offset + width)?;
        let mut value: u64 = 0;
        for index in 0..width {
            let byte = if little {
                slice[width - 1 - index]
            } else {
                slice[index]
            };
            value = (value << 8) | u64::from(byte);
        }
        Some(value)
    };
    let (phoff, phentsize, phnum) = if class64 {
        (
            field(head, 32, 8).ok_or_else(truncated)?,
            field(head, 54, 2).ok_or_else(truncated)?,
            field(head, 56, 2).ok_or_else(truncated)?,
        )
    } else {
        (
            field(head, 28, 4).ok_or_else(truncated)?,
            field(head, 42, 2).ok_or_else(truncated)?,
            field(head, 44, 2).ok_or_else(truncated)?,
        )
    };
    let minimum = if class64 { 56 } else { 32 };
    let mut elf = Elf::default();
    if phnum == 0 {
        return Ok(elf);
    }
    if phentsize < minimum || phnum > ELF_PHNUM_MAX {
        return Err("its ELF program headers are malformed".to_owned());
    }
    let table = read_at(file, phoff, phentsize * phnum).map_err(|e| e.to_string())?;
    // (file offset, address, file size) of each `PT_LOAD`.
    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..phnum {
        let start = usize::try_from(index * phentsize).map_err(|_| truncated())?;
        let entry = table
            .get(start..start + usize::try_from(phentsize).map_err(|_| truncated())?)
            .ok_or_else(truncated)?;
        let (offset, address, size) = if class64 {
            (field(entry, 8, 8), field(entry, 16, 8), field(entry, 32, 8))
        } else {
            (field(entry, 4, 4), field(entry, 8, 4), field(entry, 16, 4))
        };
        let (offset, address, size) = (
            offset.ok_or_else(truncated)?,
            address.ok_or_else(truncated)?,
            size.ok_or_else(truncated)?,
        );
        match field(entry, 0, 4) {
            Some(PT_LOAD) => loads.push((offset, address, size)),
            Some(PT_DYNAMIC) => {
                if dynamic.replace((address, size)).is_some() {
                    return Err("it has several dynamic sections".to_owned());
                }
            }
            Some(PT_INTERP) if elf.loader.is_none() => {
                if size == 0 || size > ELF_INTERP_MAX {
                    return Err("its ELF interpreter path is malformed".to_owned());
                }
                let mut bytes = read_at(file, offset, size).map_err(|e| e.to_string())?;
                if bytes.len() as u64 != size {
                    return Err(truncated());
                }
                while bytes.last() == Some(&0) {
                    bytes.pop();
                }
                if bytes.is_empty() || bytes[0] != b'/' || bytes.contains(&0) {
                    return Err("its ELF interpreter path is not absolute".to_owned());
                }
                elf.loader = Some(PathBuf::from(OsStr::from_bytes(&bytes)));
            }
            _ => {}
        }
    }
    let Some((address, size)) = dynamic else {
        return Ok(elf);
    };
    // The file offset of `length` bytes at `address`, all inside the file
    // bytes of one loaded segment.
    let mapped = |address: u64, length: u64| -> Option<u64> {
        loads.iter().find_map(|&(offset, start, size)| {
            let delta = address.checked_sub(start)?;
            (delta.checked_add(length)? <= size).then_some(())?;
            offset.checked_add(delta)
        })
    };
    if size > ELF_DYNAMIC_MAX {
        return Err("its dynamic section is malformed".to_owned());
    }
    let at = mapped(address, size)
        .ok_or_else(|| "its dynamic section lies outside its loaded segments".to_owned())?;
    let table = read_at(file, at, size).map_err(|e| e.to_string())?;
    if table.len() as u64 != size {
        return Err(truncated());
    }
    let width = if class64 { 8 } else { 4 };
    let (mut strtab, mut strsz, mut named) = (None, None, Vec::new());
    for entry in table.chunks_exact(2 * width) {
        let (Some(tag), Some(value)) = (field(entry, 0, width), field(entry, width, width)) else {
            return Err(truncated());
        };
        match tag {
            DT_NULL => break,
            DT_STRTAB => strtab = Some(value),
            DT_STRSZ => strsz = Some(value),
            DT_NEEDED | DT_FILTER | DT_AUXILIARY | DT_RPATH | DT_RUNPATH | DT_AUDIT
            | DT_DEPAUDIT => {
                named.push((tag, value));
            }
            _ => {}
        }
    }
    if named.is_empty() {
        return Ok(elf);
    }
    let (Some(strtab), Some(strsz)) = (strtab, strsz) else {
        return Err("its dynamic section names libraries but no string table".to_owned());
    };
    let strings = mapped(strtab, strsz)
        .ok_or_else(|| "its dynamic string table lies outside its loaded segments".to_owned())?;
    for (tag, offset) in named {
        let at = strings
            .checked_add(offset)
            .filter(|_| offset < strsz)
            .ok_or_else(|| "a dynamic string lies outside its string table".to_owned())?;
        let bytes =
            read_at(file, at, (strsz - offset).min(ELF_STRING_MAX)).map_err(|e| e.to_string())?;
        let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
            return Err(format!(
                "a dynamic string is unterminated or longer than {ELF_STRING_MAX} bytes"
            ));
        };
        elf.libraries.push((tag, bytes[..end].to_vec()));
    }
    Ok(elf)
}

/// §3.3 step 5, enforced as written (review F2 of the F5 fix): an ELF
/// loader must lie in the runtime roots, by every location the kernel's
/// resolution of `PT_INTERP` passes through. The kernel opens it by path at
/// the exec, so one in the install root, which a process running as the
/// operator can replace, would run that process's code inside the pinned
/// program; and one reached through a link elsewhere names nothing inside.
fn check_loader(executable: &Executable, loader: Option<&Path>) -> Result<(), JailError> {
    let Some(loader) = loader else {
        return Ok(());
    };
    let missing = |why: String| {
        refused(
            ErrorCode::ExecInterpreterMissing,
            format!(
                "the ELF loader {} of {} {why}",
                loader.display(),
                executable.path.display()
            ),
        )
    };
    match reach_in_runtime_roots(loader) {
        Ok(Reach::Found) => Ok(()),
        Ok(Reach::Unreachable) => Err(missing("does not exist".to_owned())),
        Err(location) => Err(missing(format!(
            "lies outside the runtime roots ({} is not in {}); a loader anywhere else is \
             opened by path when the program runs, outside the pin",
            location.display(),
            RUNTIME_DIRECTORIES.join(", ")
        ))),
    }
}

/// Review F2 of the F5 fix: the dynamic loader opens by path every library
/// the pinned ELF file names, and searches its `DT_RPATH` and `DT_RUNPATH`
/// first. Every place it can open one from must lie in the runtime roots,
/// as the loader must, so no library comes from the install root (which a
/// process running as the operator can change), a child-writable root or
/// the working directory:
///
/// - a search path entry must be absolute once `$ORIGIN` (the program's own
///   directory, which `/proc/self/exe` names alike inside) is expanded, and
///   reach only the runtime roots. An empty or relative entry (searched from
///   the working directory) refuses, and so does one holding another `$`
///   token (`$LIB`, `$PLATFORM`), whose value this resolution does not know;
/// - a library name (`DT_NEEDED`, `DT_FILTER`, `DT_AUXILIARY`, or one of
///   the colon-separated `DT_AUDIT` and `DT_DEPAUDIT` names) with a `/` is
///   opened as that path: it must be absolute and reach only the runtime
///   roots. One holding a `$` refuses wherever the `$` is: glibc expands a
///   token there before deciding whether the name is a path (`${ORIGIN}x`
///   becomes one), musl never does. A name with neither is searched for on
///   the path checked here and in the system's own directories.
fn check_libraries(executable: &Executable, libraries: &[(u64, Vec<u8>)]) -> Result<(), JailError> {
    let origin = executable.path.parent().unwrap_or(Path::new("/"));
    for (tag, value) in libraries {
        let what = match *tag {
            DT_NEEDED => "DT_NEEDED",
            DT_RPATH => "DT_RPATH",
            DT_RUNPATH => "DT_RUNPATH",
            DT_FILTER => "DT_FILTER",
            DT_AUXILIARY => "DT_AUXILIARY",
            DT_AUDIT => "DT_AUDIT",
            _ => "DT_DEPAUDIT",
        };
        let refuse = |why: String| {
            widening(format!(
                "{} names `{}` in its {what}: {why}. --from-path pins the program's own file; a \
                 library it loads must come from the runtime roots ({})",
                executable.path.display(),
                String::from_utf8_lossy(value),
                RUNTIME_DIRECTORIES.join(", ")
            ))
        };
        let outside = |what: String, location: PathBuf| {
            format!(
                "{what} passes through {}, outside the runtime roots",
                location.display()
            )
        };
        if matches!(*tag, DT_RPATH | DT_RUNPATH) {
            for entry in value.split(|byte| *byte == b':') {
                let shown = String::from_utf8_lossy(entry);
                if entry.is_empty() {
                    return Err(refuse(
                        "an empty entry searches the working directory".to_owned(),
                    ));
                }
                let Some(expanded) = expand_origin(entry, origin) else {
                    return Err(refuse(format!(
                        "the entry `{shown}` holds a `$` token other than `$ORIGIN`"
                    )));
                };
                if expanded.first() != Some(&b'/') {
                    return Err(refuse(format!(
                        "the relative entry `{shown}` searches from the working directory"
                    )));
                }
                let expanded = Path::new(OsStr::from_bytes(&expanded));
                reach_in_runtime_roots(expanded).map_err(|location| {
                    refuse(outside(
                        format!("the entry `{shown}` ({})", expanded.display()),
                        location,
                    ))
                })?;
            }
            continue;
        }
        let names: Vec<&[u8]> = if matches!(*tag, DT_AUDIT | DT_DEPAUDIT) {
            value.split(|byte| *byte == b':').collect()
        } else {
            vec![value.as_slice()]
        };
        for name in names {
            let shown = String::from_utf8_lossy(name);
            if name.contains(&b'$') {
                return Err(refuse(format!(
                    "the library `{shown}` holds a `$`, which glibc may expand into a path"
                )));
            }
            if !name.contains(&b'/') {
                continue;
            }
            if name.first() != Some(&b'/') {
                return Err(refuse(format!(
                    "the relative library `{shown}` is opened from the working directory"
                )));
            }
            reach_in_runtime_roots(Path::new(OsStr::from_bytes(name)))
                .map_err(|location| refuse(outside(format!("the library `{shown}`"), location)))?;
        }
    }
    Ok(())
}

/// glibc's expansion of `$ORIGIN` in a search path entry: `${ORIGIN}`, or
/// `$ORIGIN` not followed by another identifier character, becomes
/// `origin`. `None` when the entry holds any other `$`.
fn expand_origin(entry: &[u8], origin: &Path) -> Option<Vec<u8>> {
    let mut expanded = Vec::with_capacity(entry.len());
    let mut rest = entry;
    while let Some(at) = rest.iter().position(|byte| *byte == b'$') {
        expanded.extend_from_slice(&rest[..at]);
        let after = &rest[at + 1..];
        let length = if after.starts_with(b"{ORIGIN}") {
            8
        } else if after.starts_with(b"ORIGIN")
            && !after
                .get(6)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            6
        } else {
            return None;
        };
        expanded.extend_from_slice(origin.as_os_str().as_bytes());
        rest = &after[length..];
    }
    expanded.extend_from_slice(rest);
    Some(expanded)
}

/// Classifies a `#!` line (§3.3 step 5).
fn shebang(executable: &Executable, head: &[u8]) -> Result<Format, JailError> {
    let path = executable.path.display();
    let Some(end) = head.iter().position(|byte| *byte == b'\n') else {
        return Err(invalid(format!(
            "the `#!` line of {path} is longer than {SHEBANG_MAX} bytes"
        )));
    };
    let line = &head[2..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let words: Vec<&[u8]> = line
        .split(|byte| *byte == b' ' || *byte == b'\t')
        .filter(|word| !word.is_empty())
        .collect();
    let Some((interpreter, arguments)) = words.split_first() else {
        return Err(invalid(format!(
            "the `#!` line of {path} names no interpreter"
        )));
    };
    let shown = String::from_utf8_lossy(interpreter).into_owned();
    if interpreter.first() != Some(&b'/') {
        return Err(invalid(format!(
            "{path} names the relative interpreter `{shown}`"
        )));
    }
    let interpreter = PathBuf::from(OsStr::from_bytes(interpreter));
    // `env` from the runtime roots is the one interpreter expanded: what it
    // would run is named, and resolved here instead of on the contained
    // `PATH`. An `env` anywhere else is an interpreter like any other.
    let system_env = interpreter.file_name() == Some(OsStr::new("env"))
        && std::fs::canonicalize(&interpreter).is_ok_and(|real| in_runtime_roots(&real));
    if system_env {
        let [word] = arguments else {
            return Err(invalid(format!(
                "{path} runs `{shown}` with {} words; only `#!{shown} NAME` is expanded",
                arguments.len()
            )));
        };
        let name = String::from_utf8_lossy(word).into_owned();
        if word.first() == Some(&b'-') || word.contains(&b'/') || word.contains(&b'=') {
            return Err(invalid(format!(
                "{path} runs `{shown} {name}`; only `#!{shown} NAME` is expanded"
            )));
        }
        return Ok(Format::EnvExpanded {
            env: interpreter,
            name,
        });
    }
    if arguments.len() > 1 {
        return Err(invalid(format!(
            "{path} passes several arguments to its interpreter `{shown}`"
        )));
    }
    let canonical = std::fs::canonicalize(&interpreter).map_err(|_| {
        refused(
            ErrorCode::ExecInterpreterMissing,
            format!("the interpreter `{shown}` of {path} does not exist"),
        )
    })?;
    if !in_runtime_roots(&canonical) {
        return Err(refused(
            ErrorCode::ExecInterpreterMissing,
            format!(
                "the interpreter `{shown}` of {path} lies outside the runtime roots; only \
                 `#!/usr/bin/env NAME` is expanded"
            ),
        ));
    }
    // A nested script: the kernel would follow it, this resolution does not.
    let mut nested = [0u8; 2];
    if File::open(&canonical)
        .and_then(|file| file.read_exact_at(&mut nested, 0))
        .is_ok()
        && &nested == b"#!"
    {
        return Err(invalid(format!(
            "the interpreter `{shown}` of {path} is itself a script; a nested script is not \
             expanded"
        )));
    }
    Ok(Format::Script { interpreter })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A synthetic `fstat` result: what a second local user's object looks
    /// like, which a single-uid test cannot create.
    fn synthetic(kind: Kind, uid: u32, mode: u32) -> Stat {
        Stat {
            dev: 1,
            ino: 2,
            kind,
            mode,
            uid,
            gid: u32::MAX - 1,
            nlink: 1,
            size: 0,
            mtime: (0, 0),
            ctime: (0, 0),
            mount_root: Some(false),
        }
    }

    /// The owner rules, which need a second local user to exercise end to
    /// end: a directory on the walk and the executable owned by someone other
    /// than root or this operator refuse; root and this operator pass.
    #[test]
    fn foreign_owners_refuse_on_the_walk_and_the_executable() {
        let me = crate::state::effective_uid();
        let other = if me == 4242 { 4243 } else { 4242 };
        let path = Path::new("/x");
        for in_root in [false, true] {
            assert!(
                check_directory(&synthetic(Kind::Directory, other, 0o755), path, in_root).is_err()
            );
            assert!(check_directory(&synthetic(Kind::Directory, me, 0o755), path, in_root).is_ok());
            assert!(check_directory(&synthetic(Kind::Directory, 0, 0o755), path, in_root).is_ok());
        }
        assert!(check_executable(&synthetic(Kind::Regular, other, 0o755), path).is_err());
        assert!(check_executable(&synthetic(Kind::Regular, me, 0o755), path).is_ok());
        assert!(check_executable(&synthetic(Kind::Regular, 0, 0o755), path).is_ok());
        // A root-owned program with several names is safe from this
        // operator's agent; one this operator owns is not.
        let mut linked = synthetic(Kind::Regular, 0, 0o755);
        linked.nlink = 2;
        assert_eq!(check_executable(&linked, path).is_ok(), me != 0);
        linked.uid = me;
        assert!(check_executable(&linked, path).is_err());
    }

    fn tree() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, root)
    }

    /// `bytes` as an executable at `path`, every directory made for it 0755
    /// whatever the process umask (a host with umask 002 makes 0775).
    fn executable(path: &Path, bytes: &[u8]) {
        let parent = path.parent().unwrap();
        let mut missing = Vec::new();
        let mut probe = parent.to_path_buf();
        while !probe.exists() {
            missing.push(probe.clone());
            probe.pop();
        }
        std::fs::create_dir_all(parent).unwrap();
        for directory in missing {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn path_of(dirs: &[&Path]) -> Vec<u8> {
        dirs.iter()
            .map(|dir| dir.as_os_str().as_bytes().to_vec())
            .collect::<Vec<_>>()
            .join(&b':')
    }

    #[test]
    fn the_first_absolute_entry_wins_and_relative_entries_are_never_searched() {
        let (_dir, root) = tree();
        let first = root.join("first");
        let second = root.join("second");
        executable(&first.join("agent"), b"#!/bin/sh\n");
        executable(&second.join("agent"), b"#!/bin/sh\n");
        let mut path = b":relative:".to_vec();
        path.extend(path_of(&[&first, &second]));
        assert_eq!(
            find_on_path("agent", Some(&path)).unwrap(),
            first.join("agent")
        );
        // A non-executable file is passed over.
        std::fs::set_permissions(first.join("agent"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert_eq!(
            find_on_path("agent", Some(&path)).unwrap(),
            second.join("agent")
        );
        let error = find_on_path("agent", Some(b":relative")).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig);
        assert_eq!(error.key_path.as_deref(), Some(KEY));
        assert!(
            error.message.contains("never searched"),
            "{}",
            error.message
        );
        assert!(find_on_path("agent", None).is_err());
    }

    #[test]
    fn a_symlink_chain_is_canonicalized_and_its_root_is_the_real_directory() {
        let (_dir, root) = tree();
        let versions = root.join("share/versions");
        executable(&versions.join("2.0"), b"#!/bin/sh\n");
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(root.join("share/link"), bin.join("agent")).unwrap();
        std::os::unix::fs::symlink(versions.join("2.0"), root.join("share/link")).unwrap();
        let program = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap();
        assert_eq!(program.program.path, versions.join("2.0"));
        assert_eq!(program.program.root.path, versions);
        assert_eq!(
            program.argv_prefix(),
            [versions.join("2.0").as_os_str().as_bytes()]
        );
        program.recheck().unwrap();
    }

    #[test]
    fn writable_objects_refuse_and_a_swap_fails_the_recheck() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        executable(&bin.join("agent"), b"#!/bin/sh\n");
        std::fs::set_permissions(bin.join("agent"), std::fs::Permissions::from_mode(0o775))
            .unwrap();
        let error = pin(&bin.join("agent"), 1).unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyWidening, "{}", error.message);
        std::fs::set_permissions(bin.join("agent"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        // Writable by others, sticky or not, inside the install root.
        for mode in [0o757, 0o1777] {
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(mode)).unwrap();
            let error = pin(&bin.join("agent"), 1).unwrap_err();
            assert_eq!(
                error.code,
                ErrorCode::PolicyWidening,
                "{mode:o}: {}",
                error.message
            );
        }
        // Group-writable: refused unless the group is the owner's private
        // one (Ubuntu's umask 002 gives a user's own directories 0775).
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o775)).unwrap();
        let private = crate::state::accounts::group_is_private_to(
            crate::state::effective_uid(),
            std::os::unix::fs::MetadataExt::gid(&std::fs::metadata(&bin).unwrap()),
        );
        assert_eq!(pin(&bin.join("agent"), 1).is_ok(), private);
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let program = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap();
        program.recheck().unwrap();
        // Replaced by a new file of the same name: another identity.
        std::fs::rename(bin.join("agent"), root.join("old")).unwrap();
        executable(&bin.join("agent"), b"#!/bin/sh\n");
        let error = program.recheck().unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyWidening);
        assert!(
            error.message.contains("identity mismatch"),
            "{}",
            error.message
        );
    }

    #[test]
    fn levels_above_the_executable_bound_the_root() {
        let (_dir, root) = tree();
        let file = root.join("a/b/agent");
        executable(&file, b"#!/bin/sh\n");
        assert_eq!(pin(&file, 2).unwrap().root.path, root.join("a"));
        let depth = file.components().count() - 1;
        assert!(pin(&file, u8::try_from(depth).unwrap()).is_err());
    }

    #[test]
    fn shebang_forms_are_classified_or_refused_naming_the_interpreter() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        let tools = root.join("tools");
        executable(&tools.join("node"), &static_elf());
        let path = path_of(&[&bin, &tools]);
        for (script, outcome) in [
            (&b"#!/bin/sh\nexit 0\n"[..], Ok("script")),
            (b"#!/bin/sh -e\n", Ok("script")),
            (b"#!/usr/bin/env node\n", Ok("env-expanded")),
            (b"#!/usr/bin/env -S node --flag\n", Err("only")),
            (b"#!/usr/bin/env node --flag\n", Err("only")),
            (b"#!/bin/sh -e -x\n", Err("several arguments")),
            (b"#!sh\n", Err("relative interpreter")),
            (b"#!/nonexistent/interp\n", Err("does not exist")),
            (b"no magic\n", Err("neither")),
        ] {
            executable(&bin.join("agent"), script);
            let shown = String::from_utf8_lossy(script);
            match (resolve("agent", Some(&path), 1), outcome) {
                (Ok(program), Ok(format)) => {
                    assert_eq!(program.format.as_str(), format, "{shown}");
                    if format == "env-expanded" {
                        let interpreter = program.interpreter.as_ref().unwrap();
                        assert_eq!(interpreter.path, tools.join("node"));
                        assert_eq!(interpreter.root.path, tools);
                        assert_eq!(
                            program.argv_prefix(),
                            [
                                tools.join("node").as_os_str().as_bytes(),
                                bin.join("agent").as_os_str().as_bytes()
                            ]
                        );
                        assert_eq!(program.bound().path, tools.join("node"));
                        assert_eq!(program.roots().len(), 2);
                    }
                }
                (Err(error), Err(fragment)) => {
                    assert!(
                        error.message.contains(fragment),
                        "{shown}: {}",
                        error.message
                    );
                    assert_eq!(error.key_path.as_deref(), Some(KEY));
                }
                (other, expected) => {
                    panic!("{shown}: {:?} vs {expected:?}", other.map(|p| p.format))
                }
            }
        }
        // A nested script behind `env` refuses naming it.
        executable(&tools.join("node"), b"#!/bin/sh\n");
        executable(&bin.join("agent"), b"#!/usr/bin/env node\n");
        let error = resolve("agent", Some(&path), 1).unwrap_err();
        assert!(error.message.contains("nested script"), "{}", error.message);
    }

    /// A 64-bit little-endian ELF header with no program header.
    fn static_elf() -> Vec<u8> {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf
    }

    #[test]
    fn an_elf_loader_is_read_from_its_program_headers() {
        // A minimal 64-bit little-endian ELF with one PT_INTERP header.
        let mut elf = vec![0u8; 64 + 56];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        let interp = b"/nonexistent/ld.so\0";
        let offset = elf.len() as u64;
        elf[64..68].copy_from_slice(&3u32.to_le_bytes());
        elf[64 + 8..64 + 16].copy_from_slice(&offset.to_le_bytes());
        elf[64 + 32..64 + 40].copy_from_slice(&(interp.len() as u64).to_le_bytes());
        elf.extend_from_slice(interp);
        let (_dir, root) = tree();
        let bin = root.join("bin");
        executable(&bin.join("agent"), &elf);
        let error = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::ExecInterpreterMissing,
            "{}",
            error.message
        );
        assert!(
            error.message.contains("/nonexistent/ld.so"),
            "{}",
            error.message
        );
        // Without the header: a static executable needs nothing.
        elf[56..58].copy_from_slice(&0u16.to_le_bytes());
        executable(&bin.join("agent"), &elf);
        let program = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap();
        assert_eq!(program.format, Format::Elf { loader: None });
    }

    // -----------------------------------------------------------------------
    // J12 adversarial review, 2026-10-16: each kills a mutant of a gate
    // -----------------------------------------------------------------------

    fn mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Kills: `recheck` without the install root's owner and mode.
    #[test]
    fn review_recheck_refuses_an_install_root_opened_to_group_writes() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        executable(&bin.join("agent"), &static_elf());
        let program = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap();
        program.recheck().unwrap();
        mode(&bin, 0o775);
        let error = program.recheck().unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyWidening, "{}", error.message);
    }

    /// Kills: `recheck` without the mode rule for directories below the
    /// install root.
    #[test]
    fn review_recheck_refuses_a_directory_below_the_root_opened_to_writes() {
        let (_dir, root) = tree();
        let file = root.join("a/b/agent");
        executable(&file, &static_elf());
        mode(&root.join("a"), 0o755);
        mode(&root.join("a/b"), 0o755);
        let program = resolve("agent", Some(root.join("a/b").as_os_str().as_bytes()), 2).unwrap();
        assert_eq!(program.program.root.path, root.join("a"));
        program.recheck().unwrap();
        mode(&root.join("a/b"), 0o777);
        assert!(program.recheck().is_err());
        // Sticky does not help inside the install root: anyone may still add
        // a file there.
        mode(&root.join("a/b"), 0o1777);
        assert!(program.recheck().is_err());
    }

    /// The object the platform binds is the held root, not what its path
    /// names: an executable replaced only inside the held root (the old
    /// root renamed away, a new root holding the original file under the
    /// old name) is invisible to the walk by path. Kills: `recheck` without
    /// its walk under the held handle.
    #[test]
    fn review_recheck_sees_a_swap_only_the_held_root_shows() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        executable(&bin.join("agent"), &static_elf());
        let program = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap();
        let held = root.join("bin.held");
        std::fs::rename(&bin, &held).unwrap();
        std::fs::create_dir(&bin).unwrap();
        mode(&bin, 0o755);
        std::fs::rename(held.join("agent"), bin.join("agent")).unwrap();
        executable(&held.join("agent"), b"#!/bin/sh\necho another file\n");
        let error = program.recheck().unwrap_err();
        assert!(
            error.message.contains("under its install root"),
            "{}",
            error.message
        );
    }

    /// Kills: `recheck` comparing identity only (a chmod keeps the inode).
    #[test]
    fn review_recheck_refuses_a_changed_mode_on_the_same_inode() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        executable(&bin.join("agent"), &static_elf());
        let program = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap();
        mode(&bin.join("agent"), 0o700);
        assert!(program.recheck().is_err());
    }

    /// Kills: `Program::recheck` checking only the program, not the
    /// interpreter an `env` expansion pinned (the credential's binding).
    #[test]
    fn review_recheck_covers_the_expanded_interpreter() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        let tools = root.join("tools");
        executable(&tools.join("node"), &static_elf());
        executable(&bin.join("agent"), b"#!/usr/bin/env node\n");
        let program = resolve("agent", Some(&path_of(&[&bin, &tools])), 1).unwrap();
        assert!(program.interpreter.is_some());
        program.recheck().unwrap();
        std::fs::rename(tools.join("node"), root.join("node.old")).unwrap();
        executable(&tools.join("node"), &static_elf());
        assert!(program.recheck().is_err());
    }

    /// Review F5: the launcher's pins are what resolution recorded, at the
    /// argv index each executable takes; only an ELF argv 0 is executed by
    /// descriptor, a script by its path.
    #[test]
    fn exec_pins_follow_the_argv_and_only_an_elf_argv0_runs_by_descriptor() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        let tools = root.join("tools");
        let expect =
            |executable: &Executable, index: usize, by_descriptor: bool| crate::platform::ExecPin {
                index,
                by_descriptor,
                identity: executable.stat.identity(),
                size: executable.stat.size,
                mtime: executable.stat.mtime,
                ctime: executable.stat.ctime,
                nlink: executable.stat.nlink,
                mode: executable.stat.mode,
            };
        executable(&bin.join("elf"), &static_elf());
        let elf = resolve("elf", Some(&path_of(&[&bin])), 1).unwrap();
        assert_eq!(elf.exec_pins(), [expect(&elf.program, 0, true)]);

        executable(&bin.join("script"), b"#!/bin/sh\n");
        let script = resolve("script", Some(&path_of(&[&bin])), 1).unwrap();
        assert_eq!(script.exec_pins(), [expect(&script.program, 0, false)]);

        executable(&tools.join("node"), &static_elf());
        executable(&bin.join("agent"), b"#!/usr/bin/env node\n");
        let expanded = resolve("agent", Some(&path_of(&[&bin, &tools])), 1).unwrap();
        let interpreter = expanded.interpreter.as_ref().unwrap();
        assert_eq!(
            expanded.exec_pins(),
            [
                expect(interpreter, 0, true),
                expect(&expanded.program, 1, false)
            ]
        );
        // The pins and the argv prefix name the same elements.
        let argv = expanded.argv_prefix();
        assert_eq!(argv[0], interpreter.path.as_os_str().as_bytes());
        assert_eq!(argv[1], expanded.program.path.as_os_str().as_bytes());
    }

    /// Review F5: every field of a pin is the executable's own. A fixture's file has one link and mode 0755, so
    /// a constant `nlink: 1` or `mode: 0o755` would otherwise pass.
    #[test]
    fn an_exec_pin_copies_every_recorded_field() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        executable(&bin.join("elf"), &static_elf());
        let mut program = resolve("elf", Some(&path_of(&[&bin])), 1).unwrap().program;
        program.stat.dev = 11;
        program.stat.ino = 12;
        program.stat.size = 13;
        program.stat.mtime = (14, 15);
        program.stat.ctime = (16, 17);
        program.stat.nlink = 3;
        program.stat.mode = 0o4711;
        let pin = program.exec_pin(0);
        assert_eq!(
            (
                pin.identity,
                pin.size,
                pin.mtime,
                pin.ctime,
                pin.nlink,
                pin.mode
            ),
            ((11, 12), 13, (14, 15), (16, 17), 3, 0o4711)
        );
    }

    /// Kills: `shebang` accepting an `env` option word, or an assignment,
    /// as the interpreter name when a file of that name exists on PATH.
    #[test]
    fn review_env_options_and_assignments_are_never_expanded() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        let tools = root.join("tools");
        for word in ["-node", "A=1"] {
            executable(&tools.join(word), &static_elf());
            executable(
                &bin.join("agent"),
                format!("#!/usr/bin/env {word}\n").as_bytes(),
            );
            let error = resolve("agent", Some(&path_of(&[&bin, &tools])), 1).unwrap_err();
            assert!(error.message.contains("only"), "{word}: {}", error.message);
        }
    }

    /// Kills: `shebang` accepting an existing interpreter outside the
    /// runtime roots.
    #[test]
    fn review_an_existing_interpreter_outside_the_runtime_roots_refuses() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        let interp = root.join("tools/interp");
        executable(&interp, &static_elf());
        executable(
            &bin.join("agent"),
            format!("#!{}\n", interp.display()).as_bytes(),
        );
        let error = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::ExecInterpreterMissing,
            "{}",
            error.message
        );
        assert!(
            error.message.contains("outside the runtime roots"),
            "{}",
            error.message
        );
    }

    /// Kills: `shebang` without its nested-script refusal (a `#!` file in
    /// the runtime roots as the interpreter). Skips where none exists.
    #[test]
    fn review_a_system_script_as_interpreter_refuses() {
        let Some(system_script) = ["/usr/bin", "/bin"]
            .iter()
            .filter_map(|dir| std::fs::read_dir(dir).ok())
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name() != Some(OsStr::new("env"))
                    && std::fs::canonicalize(path).is_ok_and(|real| {
                        in_runtime_roots(&real)
                            && std::fs::read(&real).is_ok_and(|bytes| bytes.starts_with(b"#!"))
                    })
            })
        else {
            return;
        };
        let (_dir, root) = tree();
        let bin = root.join("bin");
        executable(
            &bin.join("agent"),
            format!("#!{}\n", system_script.display()).as_bytes(),
        );
        let error = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap_err();
        assert!(
            error.message.contains("itself a script"),
            "{}",
            error.message
        );
    }

    /// Kills: `check_loader` accepting an existing loader outside the
    /// runtime roots and the install root.
    #[test]
    fn review_an_existing_loader_outside_the_roots_refuses() {
        let (_dir, root) = tree();
        let loader = root.join("elsewhere/ld.so");
        executable(&loader, &static_elf());
        let interp = format!("{}\0", loader.display()).into_bytes();
        let mut elf = vec![0u8; 64 + 56];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        let offset = elf.len() as u64;
        elf[64..68].copy_from_slice(&3u32.to_le_bytes());
        elf[64 + 8..64 + 16].copy_from_slice(&offset.to_le_bytes());
        elf[64 + 32..64 + 40].copy_from_slice(&(interp.len() as u64).to_le_bytes());
        elf.extend_from_slice(&interp);
        let bin = root.join("bin");
        executable(&bin.join("agent"), &elf);
        let error = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::ExecInterpreterMissing,
            "{}",
            error.message
        );
        assert!(error.message.contains("lies outside"), "{}", error.message);
    }

    /// Kills: `pin` without its bound on `levels` (a shallow executable and
    /// a large `program_root` would underflow the root depth).
    #[test]
    fn review_a_root_above_a_shallow_executable_refuses_without_panicking() {
        for levels in [2, 3, 4] {
            assert!(pin(Path::new("/bin/sh"), levels).is_err(), "{levels}");
        }
    }

    /// Kills: `shebang` reading a `#!` line with no newline in the first
    /// 256 bytes as if it ended there.
    #[test]
    fn review_an_overlong_shebang_line_refuses() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        let mut script = b"#!/bin/sh ".to_vec();
        script.extend(std::iter::repeat_n(b'x', 300));
        script.push(b'\n');
        executable(&bin.join("agent"), &script);
        let error = resolve("agent", Some(bin.as_os_str().as_bytes()), 1).unwrap_err();
        assert!(error.message.contains("longer than"), "{}", error.message);
    }

    /// Kills: `find_on_path` falling back to a default PATH when PATH is
    /// unset.
    #[test]
    fn review_an_unset_path_resolves_nothing() {
        assert!(find_on_path("env", None).is_err());
        assert!(find_on_path("sh", None).is_err());
    }

    /// Kills: `check_directory` without its in-root rule. A sticky,
    /// world-writable install root passes the writable-by-others rule (the
    /// sticky bit), so only the in-root rule refuses it; a group-writable
    /// one is masked by that rule wherever the group is shared (macOS).
    #[test]
    fn review_a_sticky_world_writable_install_root_refuses() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        executable(&bin.join("agent"), &static_elf());
        mode(&bin, 0o1777);
        let error = pin(&bin.join("agent"), 1).unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyWidening, "{}", error.message);
        mode(&bin, 0o755);
    }

    /// Kills: `check_executable` without its regular-file or execute-bit
    /// rule (`pin` is reached with whatever the path names by then).
    #[test]
    fn review_pin_refuses_a_directory_and_a_non_executable_file() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        std::fs::create_dir_all(bin.join("dir")).unwrap();
        mode(&bin, 0o755);
        mode(&bin.join("dir"), 0o755);
        assert!(pin(&bin.join("dir"), 1).is_err());
        executable(&bin.join("plain"), &static_elf());
        mode(&bin.join("plain"), 0o644);
        assert!(pin(&bin.join("plain"), 1).is_err());
    }

    /// Kills: `shebang` expanding every interpreter named `env`, not only
    /// the runtime roots' own.
    #[test]
    fn review_an_env_outside_the_runtime_roots_is_not_expanded() {
        let (_dir, root) = tree();
        let bin = root.join("bin");
        let tools = root.join("tools");
        executable(&tools.join("env"), &static_elf());
        executable(&tools.join("node"), &static_elf());
        executable(
            &bin.join("agent"),
            format!("#!{} node\n", tools.join("env").display()).as_bytes(),
        );
        let error = resolve("agent", Some(&path_of(&[&bin, &tools])), 1).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::ExecInterpreterMissing,
            "{}",
            error.message
        );
    }

    /// Kills: `in_runtime_roots` as a string prefix (`/libx32`,
    /// `/lib.usr-is-merged` exist on Debian and Ubuntu hosts).
    #[test]
    fn review_runtime_roots_are_compared_by_component() {
        for path in [
            "/usrx/bin/node",
            "/binary/sh",
            "/lib.usr-is-merged/x",
            "/libx32/ld.so",
            "/lib64x/ld",
        ] {
            assert!(!in_runtime_roots(Path::new(path)), "{path}");
        }
        assert!(in_runtime_roots(Path::new("/usr/bin/env")));
    }

    // -----------------------------------------------------------------------
    // Review F2 of the F5 fix: the loader and the libraries are opened by
    // path when the program runs, so every place they come from must be in
    // the runtime roots
    // -----------------------------------------------------------------------

    use ukai_fixture::elf::{self, Image};

    /// A file in the runtime roots on every host the tests run on. The
    /// loader check reads where a path leads, not what it holds.
    const SYSTEM_FILE: &str = "/usr/bin/env";

    /// Resolves `agent`, the ELF `image` placed in `root/bin`.
    fn resolve_image(root: &Path, image: &Image) -> Result<Program, JailError> {
        let bin = root.join("bin");
        executable(&bin.join("agent"), &image.bytes());
        resolve("agent", Some(bin.as_os_str().as_bytes()), 1)
    }

    /// `result` is a refusal at [`KEY`] with `code` and every fragment.
    fn assert_refused(
        result: Result<Program, JailError>,
        code: ErrorCode,
        fragments: &[&str],
        label: &str,
    ) {
        let error = match result {
            Ok(program) => panic!("{label}: resolved as {:?}", program.format),
            Err(error) => error,
        };
        assert_eq!(error.code, code, "{label}: {}", error.message);
        assert_eq!(error.key_path.as_deref(), Some(KEY), "{label}");
        for fragment in fragments {
            assert!(
                error.message.contains(fragment),
                "{label}: `{fragment}` not in: {}",
                error.message
            );
        }
    }

    /// A loader whose resolution stays in the runtime roots passes, `..`
    /// and links included.
    #[test]
    fn review_f2_a_loader_in_the_runtime_roots_passes() {
        let (_dir, root) = tree();
        for loader in [SYSTEM_FILE, "/usr/../usr/bin/env", "/bin/sh"] {
            let program = resolve_image(&root, &Image::new().interp(loader))
                .unwrap_or_else(|error| panic!("{loader}: {}", error.message));
            assert_eq!(
                program.format,
                Format::Elf {
                    loader: Some(PathBuf::from(loader))
                }
            );
        }
    }

    /// Kills: `check_loader` accepting a loader inside the install root
    /// (what it did before review F2): an existing file there refuses, as
    /// §3.3 step 5 says, with `exec_interpreter_missing`.
    #[test]
    fn review_f2_a_loader_in_the_install_root_refuses() {
        let (_dir, root) = tree();
        let loader = root.join("bin/ld.so");
        executable(&loader, &Image::new().bytes());
        assert_refused(
            resolve_image(&root, &Image::new().interp(loader.as_os_str().as_bytes())),
            ErrorCode::ExecInterpreterMissing,
            &[&loader.display().to_string(), "outside the runtime roots"],
            "install root",
        );
    }

    /// Kills: `check_loader` judging only where the loader's path ends (the
    /// old canonical check) or how it is spelled: a link outside the runtime
    /// roots to a system file, and a `..` climbing out of them, pass through
    /// a location the jail does not show from the host.
    #[test]
    fn review_f2_a_loader_reached_through_a_location_outside_the_roots_refuses() {
        let (_dir, root) = tree();
        let link = root.join("ld.so");
        std::os::unix::fs::symlink(SYSTEM_FILE, &link).unwrap();
        let climbing = format!("/usr/..{}", link.display());
        for loader in [link.display().to_string(), climbing] {
            assert_refused(
                resolve_image(&root, &Image::new().interp(&loader)),
                ErrorCode::ExecInterpreterMissing,
                &["outside the runtime roots"],
                &loader,
            );
        }
    }

    /// Kills: a loader whose resolution stops inside the runtime roots
    /// counted as found.
    #[test]
    fn review_f2_a_missing_loader_in_the_runtime_roots_refuses() {
        let (_dir, root) = tree();
        let loader = "/usr/ukai-no-such-loader.so";
        assert_refused(
            resolve_image(&root, &Image::new().interp(loader)),
            ErrorCode::ExecInterpreterMissing,
            &[loader, "does not exist"],
            loader,
        );
    }

    /// Kills: each refusal of a search path entry, under `DT_RUNPATH` and
    /// `DT_RPATH` alike: `$ORIGIN` (braced or not) inside the install root,
    /// an absolute entry outside the runtime roots, an empty entry anywhere
    /// in the list and a relative one (both searched from the working
    /// directory), and an entry holding a `$` token this resolution cannot
    /// follow.
    #[test]
    fn review_f2_a_search_path_outside_the_runtime_roots_refuses() {
        let (_dir, root) = tree();
        let elsewhere = root.join("lib");
        let elsewhere = elsewhere.to_str().unwrap();
        for (entry, fragment) in [
            ("$ORIGIN", "outside the runtime roots"),
            ("${ORIGIN}/../lib", "outside the runtime roots"),
            (elsewhere, "outside the runtime roots"),
            ("/usr/lib:/usr/..", "outside the runtime roots"),
            ("", "empty entry"),
            ("/usr/lib::/usr/lib", "empty entry"),
            ("/usr/lib:", "empty entry"),
            ("lib", "relative entry"),
            ("./", "relative entry"),
            ("/usr/$LIB", "`$` token"),
            ("/usr/${PLATFORM}/lib", "`$` token"),
            ("$ORIGINAL/lib", "`$` token"),
            ("$ORIGIN_lib", "`$` token"),
            ("/usr/lib/$", "`$` token"),
        ] {
            for (tag, name) in [(elf::DT_RUNPATH, "DT_RUNPATH"), (elf::DT_RPATH, "DT_RPATH")] {
                let image = Image::new().interp(SYSTEM_FILE).entry(tag, entry);
                assert_refused(
                    resolve_image(&root, &image),
                    ErrorCode::PolicyWidening,
                    &[
                        name,
                        fragment,
                        &root.join("bin/agent").display().to_string(),
                    ],
                    &format!("{name} {entry:?}"),
                );
            }
        }
    }

    /// The forms that stay in the runtime roots pass: absolute entries,
    /// `..` inside them, a trailing slash, an entry naming nothing there,
    /// names without a `/` (searched for on that path), absolute names in
    /// the runtime roots, and empty audit names.
    #[test]
    fn review_f2_libraries_from_the_runtime_roots_pass() {
        let (_dir, root) = tree();
        let image = Image::new()
            .interp(SYSTEM_FILE)
            .entry(elf::DT_NEEDED, "libc.so.6")
            .entry(elf::DT_FILTER, "libfilter.so")
            .entry(elf::DT_AUXILIARY, "/usr/lib/ukai-auxiliary.so")
            .entry(elf::DT_NEEDED, "/usr/lib/ukai-no-such-library.so")
            .entry(elf::DT_RUNPATH, "/usr/lib:/bin:/usr/lib/../bin/")
            .entry(elf::DT_RPATH, "/usr/ukai-no-such-directory/lib")
            .entry(elf::DT_AUDIT, "libaudit.so::/usr/lib/ukai-audit.so")
            .entry(elf::DT_DEPAUDIT, "libdepaudit.so");
        let program =
            resolve_image(&root, &image).unwrap_or_else(|error| panic!("{}", error.message));
        assert_eq!(program.format.as_str(), "elf");
    }

    /// Kills: each refusal of a library name, in `DT_NEEDED`, `DT_FILTER`,
    /// `DT_AUXILIARY` and each colon-separated `DT_AUDIT` and `DT_DEPAUDIT`
    /// name: a `$`, with or without a `/` (glibc expands `${ORIGIN}x` into
    /// a path; musl opens `$ORIGIN/x` unexpanded, from the working
    /// directory), a relative name with a `/` and an absolute one outside
    /// the runtime roots.
    #[test]
    fn review_f2_a_library_named_by_a_path_outside_the_runtime_roots_refuses() {
        let (_dir, root) = tree();
        let outside = root.join("bin/libx.so");
        let outside = outside.to_str().unwrap();
        for (tag, name, value, fragment) in [
            (
                elf::DT_NEEDED,
                "DT_NEEDED",
                "$ORIGIN/libx.so".to_owned(),
                "holds a `$`",
            ),
            (
                elf::DT_NEEDED,
                "DT_NEEDED",
                "${ORIGIN}x.so".to_owned(),
                "holds a `$`",
            ),
            (
                elf::DT_NEEDED,
                "DT_NEEDED",
                "lib$weird.so".to_owned(),
                "holds a `$`",
            ),
            (
                elf::DT_FILTER,
                "DT_FILTER",
                outside.to_owned(),
                "outside the runtime roots",
            ),
            (
                elf::DT_AUXILIARY,
                "DT_AUXILIARY",
                "x/y.so".to_owned(),
                "relative library",
            ),
            (
                elf::DT_AUDIT,
                "DT_AUDIT",
                "liba.so:$ORIGIN".to_owned(),
                "holds a `$`",
            ),
            (
                elf::DT_NEEDED,
                "DT_NEEDED",
                "lib/libx.so".to_owned(),
                "relative library",
            ),
            (
                elf::DT_NEEDED,
                "DT_NEEDED",
                outside.to_owned(),
                "outside the runtime roots",
            ),
            (
                elf::DT_AUDIT,
                "DT_AUDIT",
                format!("liba.so:{outside}"),
                "outside the runtime roots",
            ),
            (
                elf::DT_DEPAUDIT,
                "DT_DEPAUDIT",
                "liba.so:x/y.so".to_owned(),
                "relative library",
            ),
        ] {
            let image = Image::new().interp(SYSTEM_FILE).entry(tag, &value);
            assert_refused(
                resolve_image(&root, &image),
                ErrorCode::PolicyWidening,
                &[name, fragment],
                &format!("{name} {value:?}"),
            );
        }
    }

    /// Kills: `$ORIGIN` expanded to anything but the program's own
    /// directory (its install root, for one). A program pinned in `/usr/bin`
    /// with its install root at `/usr`: `$ORIGIN/../X` is `/usr/X`, in the
    /// runtime roots, and `$ORIGIN/../../X` is `/X`, outside them.
    #[test]
    fn review_f2_origin_is_the_program_s_own_directory() {
        let Some(system) = ["/usr/bin/dash", "/usr/bin/env", "/usr/bin/true"]
            .iter()
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .find(|path| path.parent() == Some(Path::new("/usr/bin")))
        else {
            panic!("no executable whose canonical path lies directly in /usr/bin");
        };
        let pinned = pin(&system, 2).unwrap();
        assert_eq!(pinned.root.path, Path::new("/usr"));
        let runpath = |entry: &str| check_libraries(&pinned, &[(DT_RUNPATH, entry.into())]);
        runpath("$ORIGIN/../ukai-no-such-x").unwrap();
        runpath("${ORIGIN}/../ukai-no-such-x").unwrap();
        let error = runpath("$ORIGIN/../../ukai-no-such-x").unwrap_err();
        assert!(
            error.message.contains("/ukai-no-such-x,"),
            "{}",
            error.message
        );
        assert_eq!(
            expand_origin(b"a$ORIGIN:${ORIGIN}/b", Path::new("/o")),
            Some(b"a/o:/o/b".to_vec())
        );
    }

    /// Kills: the dynamic section read at `PT_DYNAMIC`'s file offset, past
    /// `DT_NULL`, or in one class or byte order only; and the interpreter
    /// an `env` expansion pins left unchecked.
    #[test]
    fn review_f2_the_dynamic_section_is_read_as_the_loader_reads_it() {
        let (_dir, root) = tree();
        let origin = |image: Image| image.interp(SYSTEM_FILE).entry(elf::DT_RUNPATH, "$ORIGIN");
        for (label, image) in [
            ("64-bit little-endian", origin(Image::new())),
            ("64-bit big-endian", origin(Image::new().big_endian())),
            ("32-bit little-endian", origin(Image::new().class32())),
            (
                "32-bit big-endian",
                origin(Image::new().class32().big_endian()),
            ),
            ("decoy at the file offset", origin(Image::new().decoy())),
            ("static", Image::new().entry(elf::DT_RUNPATH, "$ORIGIN")),
        ] {
            assert_refused(
                resolve_image(&root, &image),
                ErrorCode::PolicyWidening,
                &["DT_RUNPATH"],
                label,
            );
        }
        // Past DT_NULL, no loader reads it.
        let image = Image::new()
            .interp(SYSTEM_FILE)
            .after_null(elf::DT_RUNPATH, "$ORIGIN");
        resolve_image(&root, &image).unwrap_or_else(|error| panic!("{}", error.message));

        // `X'` after an expansion is the program the credential binds.
        let tools = root.join("tools");
        executable(&tools.join("node"), &origin(Image::new()).bytes());
        executable(&root.join("bin/agent"), b"#!/usr/bin/env node\n");
        assert_refused(
            resolve("agent", Some(&path_of(&[&root.join("bin"), &tools])), 1),
            ErrorCode::PolicyWidening,
            &[&tools.join("node").display().to_string(), "DT_RUNPATH"],
            "expanded interpreter",
        );
    }

    /// A dynamic section the loader could not use either refuses, naming
    /// the program, instead of passing unchecked.
    #[test]
    fn review_f2_a_malformed_dynamic_section_refuses() {
        let (_dir, root) = tree();
        let bytes = Image::new()
            .interp(SYSTEM_FILE)
            .entry(elf::DT_RUNPATH, "/usr/lib")
            .bytes();
        // The dynamic table, at the third program header's file offset.
        let table = usize::try_from(u64::from_le_bytes(
            bytes[64 + 2 * 56 + 8..64 + 2 * 56 + 16].try_into().unwrap(),
        ))
        .unwrap();
        let find = |bytes: &[u8], tag: u64| {
            (table..)
                .step_by(16)
                .find(|at| bytes[*at..*at + 8] == tag.to_le_bytes())
                .unwrap()
        };
        let load = 64 + 56; // the second program header
        let mut cases: Vec<(&str, Vec<u8>, &str)> = Vec::new();
        // The one PT_LOAD maps nothing past the headers.
        let mut short = bytes.clone();
        short[load + 32..load + 40].copy_from_slice(&64u64.to_le_bytes());
        cases.push(("short load", short, "outside its loaded segments"));
        // DT_STRSZ too small for the entry's string.
        let mut small = bytes.clone();
        let strsz = find(&small, 10) + 8;
        small[strsz..strsz + 8].copy_from_slice(&1u64.to_le_bytes());
        cases.push(("small string table", small, "outside its string table"));
        // No DT_STRTAB at all.
        let mut nameless = bytes.clone();
        let strtab = find(&nameless, 5);
        nameless[strtab..strtab + 8].copy_from_slice(&0x6000_0000u64.to_le_bytes());
        cases.push(("no string table", nameless, "no string table"));
        // Two PT_DYNAMIC headers: the PT_LOAD retyped.
        let mut twice = bytes.clone();
        twice[load..load + 4].copy_from_slice(&2u32.to_le_bytes());
        cases.push((
            "several dynamic sections",
            twice,
            "several dynamic sections",
        ));
        for (label, bytes, fragment) in cases {
            executable(&root.join("bin/agent"), &bytes);
            let error = resolve("agent", Some(root.join("bin").as_os_str().as_bytes()), 1)
                .expect_err(label);
            assert_eq!(
                error.code,
                ErrorCode::InvalidConfig,
                "{label}: {}",
                error.message
            );
            assert!(
                error.message.contains(fragment),
                "{label}: {}",
                error.message
            );
        }
    }

    /// The parser against a real linker's layout: the host's own shell
    /// names a loader resolution accepts and its C library, and its
    /// dynamic section passes the library rules.
    #[cfg(target_os = "linux")]
    #[test]
    fn review_f2_the_host_shell_s_headers_are_read() {
        let shell = Path::new("/bin/sh").canonicalize().unwrap();
        let file = File::open(&shell).unwrap();
        let head = read_at(&file, 0, SHEBANG_MAX as u64).unwrap();
        let elf = elf_headers(&file, &head).unwrap();
        let loader = elf.loader.as_ref().expect("a dynamically linked /bin/sh");
        assert_eq!(
            reach_in_runtime_roots(loader),
            Ok(Reach::Found),
            "{}",
            loader.display()
        );
        assert!(
            elf.libraries
                .iter()
                .any(|(tag, name)| *tag == DT_NEEDED && name.starts_with(b"libc.")),
            "{:?}",
            elf.libraries
        );
        let pinned = pin(&shell, 1).unwrap();
        check_libraries(&pinned, &elf.libraries).unwrap();
    }
}
