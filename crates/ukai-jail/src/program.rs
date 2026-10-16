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
//! needs its loader inside the runtime roots (or its own install root). A
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
    let interpreter = match &format {
        Format::Elf { loader } => {
            check_loader(&program, loader.as_deref())?;
            None
        }
        Format::MachO | Format::Script { .. } => None,
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
                Format::Elf { loader } => check_loader(&interpreter, loader.as_deref())?,
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

/// What the executable's first bytes say it is.
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
        return elf_loader(&file, &head)
            .map(|loader| Format::Elf { loader })
            .map_err(|why| invalid(format!("{}: {why}", executable.path.display())));
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

/// The `PT_INTERP` path of an ELF file, if it has one.
fn elf_loader(file: &File, head: &[u8]) -> Result<Option<PathBuf>, String> {
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
    if phnum == 0 {
        return Ok(None);
    }
    if phentsize < minimum || phnum > ELF_PHNUM_MAX {
        return Err("its ELF program headers are malformed".to_owned());
    }
    let table = read_at(file, phoff, phentsize * phnum).map_err(|e| e.to_string())?;
    for index in 0..phnum {
        let start = usize::try_from(index * phentsize).map_err(|_| truncated())?;
        let entry = table
            .get(start..start + usize::try_from(phentsize).map_err(|_| truncated())?)
            .ok_or_else(truncated)?;
        // PT_INTERP
        if field(entry, 0, 4) != Some(3) {
            continue;
        }
        let (offset, size) = if class64 {
            (field(entry, 8, 8), field(entry, 32, 8))
        } else {
            (field(entry, 4, 4), field(entry, 16, 4))
        };
        let (offset, size) = (offset.ok_or_else(truncated)?, size.ok_or_else(truncated)?);
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
        return Ok(Some(PathBuf::from(OsStr::from_bytes(&bytes))));
    }
    Ok(None)
}

/// An ELF loader must be reachable inside: in the runtime roots, or in the
/// executable's own install root.
fn check_loader(executable: &Executable, loader: Option<&Path>) -> Result<(), JailError> {
    let Some(loader) = loader else {
        return Ok(());
    };
    let missing = |why: &str| {
        refused(
            ErrorCode::ExecInterpreterMissing,
            format!(
                "the ELF loader {} of {} {why}",
                loader.display(),
                executable.path.display()
            ),
        )
    };
    let canonical = std::fs::canonicalize(loader).map_err(|_| missing("does not exist"))?;
    if in_runtime_roots(&canonical) || canonical.starts_with(&executable.root.path) {
        Ok(())
    } else {
        Err(missing(
            "lies outside the runtime roots and the install root",
        ))
    }
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
}
