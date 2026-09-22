//! The bubblewrap plan for the `tool` profile: argv, mount table, and the
//! placeholder mount points an absent protected literal needs.
//!
//! jail-v1 §9.1 and §9.2, north-star §4.3. The plan is data; rendering it is
//! a pure function, so the argv and the mount table the receipt records come
//! from the same structure and cannot disagree.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::fs::{RootSpec, exists_resolved, resolve_runtime_root};
use super::sys::{PathError, cstring_from_os, empty_stat, errno_name, last_errno};

/// Where the jail's own binary is bound inside the sandbox.
pub const JAIL_INSIDE_PATH: &str = "/run/ouro/jail";
/// Where the scratch directory appears inside the sandbox.
pub const SCRATCH_INSIDE_PATH: &str = "/tmp";

/// The system roots the `tool` profile grants read-only (north-star §4.2).
pub const RUNTIME_ROOTS: [&str; 7] = [
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
];

/// The `/etc` files the `tool` profile grants read-only. `/etc/ld.so.cache` is
/// not in the north star's list but is needed for the dynamic loader to find
/// anything; it is granted when present and recorded in the mount table like
/// every other grant.
pub const ETC_PATHS: [&str; 7] = [
    "/etc/ssl",
    "/etc/resolv.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/localtime",
    "/etc/ld.so.cache",
];

/// Total rendered argv bytes past which the plan is handed over `--args FD`
/// instead of the command line. ARG_MAX is normally 2 MiB; this is the
/// "comfort" bound CONTRACT §3.6 asks for.
pub const ARGS_FD_THRESHOLD: usize = 128 * 1024;

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// The version bubblewrap reports, kept verbatim for the receipt's
/// `backend_version`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwrapVersion {
    /// The whole line, as printed.
    pub raw: String,
    /// Major component.
    pub major: u32,
    /// Minor component.
    pub minor: u32,
    /// Patch component, zero when not printed.
    pub patch: u32,
}

/// Parse `bubblewrap 0.11.1`.
#[must_use]
pub fn parse_version(line: &str) -> Option<BwrapVersion> {
    let raw = line.trim();
    let number = raw.split_whitespace().last()?;
    let mut parts = number.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some(BwrapVersion {
        raw: raw.to_owned(),
        major,
        minor,
        patch,
    })
}

/// Run `bwrap --version`.
///
/// # Errors
///
/// A failure to run the binary, or output that does not parse.
pub fn bwrap_version(bwrap: &Path) -> io::Result<BwrapVersion> {
    let out = Command::new(bwrap).arg("--version").output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{} --version exited {:?}",
            bwrap.display(),
            out.status.code()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    parse_version(&text).ok_or_else(|| io::Error::other(format!("unparsed version {text:?}")))
}

// ---------------------------------------------------------------------------
// Placeholders
// ---------------------------------------------------------------------------

/// A mount point created so that an absent protected literal can still be
/// covered by a read-only bind (jail-v1 §9.1: "Root-level protected literals
/// must also be protected when absent").
///
/// Bubblewrap will create a missing destination itself, inside the
/// bind-mounted workspace, and never remove it. Creating it here instead means
/// its exact inode identity and ownership are registered *before use*, which
/// is what the spec requires, and means the cleanup afterwards can tell "the
/// empty directory we made" from "something the run created".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placeholder {
    /// The empty directory bound over the destination.
    pub source: PathBuf,
    /// The mount point inside the workspace.
    pub destination: PathBuf,
    /// Device of the destination at registration.
    pub dev: u64,
    /// Inode of the destination at registration.
    pub ino: u64,
    /// Owning uid at registration.
    pub uid: u32,
    /// Permission bits at registration.
    pub mode: u32,
}

/// Why a placeholder could not be established.
#[derive(Debug)]
pub enum PlaceholderError {
    /// The destination already exists, so it is a pre-existing object and must
    /// be treated as one. Never removed.
    DestinationExists(PathBuf),
    /// A filesystem call failed.
    Io {
        /// What was being done.
        path: PathBuf,
        /// The errno.
        errno: i32,
    },
    /// A path could not be handed to a syscall.
    Path(PathError),
}

impl fmt::Display for PlaceholderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationExists(p) => {
                write!(f, "{} already exists; it is not a placeholder", p.display())
            }
            Self::Io { path, errno } => {
                write!(f, "{}: {}", path.display(), errno_name(*errno))
            }
            Self::Path(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PlaceholderError {}

/// What became of a placeholder after the tree died.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlaceholderOutcome {
    /// Unchanged and empty: removed.
    Removed(PathBuf),
    /// Already gone; nothing to do.
    AlreadyGone(PathBuf),
    /// Identity, ownership or mode changed: kept, with the reason.
    KeptChanged(PathBuf, String),
    /// Something is inside it: kept.
    KeptNotEmpty(PathBuf),
    /// Removal failed.
    KeptError(PathBuf, i32),
}

impl Placeholder {
    /// Create the empty source directory and the destination mount point, and
    /// register the destination's identity.
    ///
    /// # Errors
    ///
    /// [`PlaceholderError::DestinationExists`] when the destination is already
    /// there — the caller must then treat it as a pre-existing protected
    /// segment — or an I/O errno.
    pub fn create(source: &Path, destination: &Path) -> Result<Self, PlaceholderError> {
        let source_c = cstring_from_os(source.as_os_str()).map_err(PlaceholderError::Path)?;
        let dest_c = cstring_from_os(destination.as_os_str()).map_err(PlaceholderError::Path)?;

        // SAFETY: `source_c` is a NUL-terminated path that outlives the call.
        if unsafe { libc::mkdir(source_c.as_ptr(), 0o700) } != 0 {
            let errno = last_errno();
            if errno != libc::EEXIST {
                return Err(PlaceholderError::Io {
                    path: source.to_owned(),
                    errno,
                });
            }
        }
        // SAFETY: `dest_c` is a NUL-terminated path that outlives the call.
        if unsafe { libc::mkdir(dest_c.as_ptr(), 0o700) } != 0 {
            let errno = last_errno();
            return Err(if errno == libc::EEXIST {
                PlaceholderError::DestinationExists(destination.to_owned())
            } else {
                PlaceholderError::Io {
                    path: destination.to_owned(),
                    errno,
                }
            });
        }
        let stat = lstat(destination).map_err(|errno| PlaceholderError::Io {
            path: destination.to_owned(),
            errno,
        })?;
        Ok(Self {
            source: source.to_owned(),
            destination: destination.to_owned(),
            dev: stat.st_dev,
            ino: stat.st_ino,
            uid: stat.st_uid,
            mode: stat.st_mode & 0o7777,
        })
    }

    /// Remove the placeholder if it is still the empty directory that was
    /// registered.
    ///
    /// jail-v1 §9.1: "remove only unchanged, empty placeholders it created
    /// after tree death. Never remove a pre-existing Git file/directory."
    #[must_use]
    pub fn remove_if_unchanged(&self) -> PlaceholderOutcome {
        let path = self.destination.clone();
        let stat = match lstat(&path) {
            Ok(stat) => stat,
            Err(errno) if errno == libc::ENOENT => {
                return PlaceholderOutcome::AlreadyGone(path);
            }
            Err(errno) => return PlaceholderOutcome::KeptError(path, errno),
        };
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return PlaceholderOutcome::KeptChanged(path, "no longer a directory".to_owned());
        }
        if (stat.st_dev, stat.st_ino) != (self.dev, self.ino) {
            return PlaceholderOutcome::KeptChanged(
                path,
                format!(
                    "identity changed from {}:{} to {}:{}",
                    self.dev, self.ino, stat.st_dev, stat.st_ino
                ),
            );
        }
        if stat.st_uid != self.uid {
            return PlaceholderOutcome::KeptChanged(path, "owner changed".to_owned());
        }
        match std::fs::read_dir(&path) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return PlaceholderOutcome::KeptNotEmpty(path);
                }
            }
            Err(e) => {
                return PlaceholderOutcome::KeptError(path, e.raw_os_error().unwrap_or(libc::EIO));
            }
        }
        match std::fs::remove_dir(&path) {
            Ok(()) => {
                let _ = std::fs::remove_dir(&self.source);
                PlaceholderOutcome::Removed(path)
            }
            Err(e) => PlaceholderOutcome::KeptError(path, e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }
}

fn lstat(path: &Path) -> Result<libc::stat, i32> {
    let c = cstring_from_os(path.as_os_str()).map_err(|_| libc::EINVAL)?;
    let mut st = empty_stat();
    // SAFETY: `c` is NUL-terminated and outlives the call; `st` is writable.
    if unsafe { libc::lstat(c.as_ptr(), &raw mut st) } != 0 {
        return Err(last_errno());
    }
    Ok(st)
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// One row of the mount table the receipt records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountRow {
    /// `ro-bind`, `bind`, `symlink`, `proc`, `dev` or `placeholder`.
    pub kind: &'static str,
    /// The host source, or the symlink target, or nothing for `proc`/`dev`.
    pub source: Option<OsString>,
    /// The path inside the sandbox.
    pub destination: OsString,
}

/// Everything needed to build a bubblewrap invocation.
#[derive(Clone, Debug)]
pub struct BwrapPlan {
    /// Path to the `bwrap` binary.
    pub bwrap: PathBuf,
    /// System roots, already classified into binds and merged-`/usr` symlinks.
    pub roots: Vec<RootSpec>,
    /// `/etc` grants that exist on this host.
    pub etc_paths: Vec<PathBuf>,
    /// The writable workspace, mounted at the same path inside.
    pub workspace: PathBuf,
    /// The scratch directory, mounted at `/tmp` inside.
    pub scratch: PathBuf,
    /// Environment to set after `--clearenv`.
    pub env: Vec<(OsString, OsString)>,
    /// Existing protected segments, each bound read-only over itself.
    pub protected: Vec<PathBuf>,
    /// Extra read-only binds with a destination of their own, used by the
    /// doctor probes and by operator `--allow-host` grants.
    pub extra_ro_binds: Vec<(PathBuf, PathBuf)>,
    /// Placeholders for absent root-level literals.
    pub placeholders: Vec<Placeholder>,
    /// The jail binary to bind at [`JAIL_INSIDE_PATH`].
    pub jail_exe: PathBuf,
    /// Descriptor carrying the seccomp program.
    pub seccomp_fd: Option<RawFd>,
    /// Descriptor bubblewrap writes its own JSON status to.
    pub json_status_fd: Option<RawFd>,
    /// Descriptor to read the argument list from, when the list is long.
    pub args_fd: Option<RawFd>,
    /// Force the `--args` path even for a short list, so tests can exercise it.
    pub force_args_fd: bool,
    /// The command inside the sandbox, normally
    /// `/run/ouro/jail __launch ... -- PROGRAM ARG...`.
    pub inner: Vec<OsString>,
}

/// Why a plan cannot be rendered.
#[derive(Debug)]
pub enum PlanError {
    /// A path that must be absolute is not.
    NotAbsolute(&'static str, PathBuf),
    /// A path cannot be passed to a syscall.
    Path(&'static str, PathError),
    /// The plan asks for `--args` but no descriptor was provided.
    ArgsFdMissing,
    /// There is no command to run.
    NoCommand,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute(what, p) => {
                write!(f, "{what} must be an absolute path, got {}", p.display())
            }
            Self::Path(what, e) => write!(f, "{what}: {e}"),
            Self::ArgsFdMissing => write!(f, "the argument list needs --args but no fd was given"),
            Self::NoCommand => write!(f, "the plan has no command to run"),
        }
    }
}

impl std::error::Error for PlanError {}

/// A rendered invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// The argv to execute, including `bwrap` itself.
    pub argv: Vec<OsString>,
    /// When present, the NUL-separated argument list to write to
    /// [`BwrapPlan::args_fd`]; `argv` is then just `bwrap --args FD`.
    pub args_payload: Option<Vec<u8>>,
}

impl BwrapPlan {
    /// A `tool` plan with this host's runtime roots and `/etc` grants filled
    /// in, and the environment the profile allows.
    #[must_use]
    pub fn tool(workspace: &Path, scratch: &Path, jail_exe: &Path) -> Self {
        let roots = RUNTIME_ROOTS
            .iter()
            .filter_map(|p| resolve_runtime_root(Path::new(p)))
            .collect();
        let etc_paths = ETC_PATHS
            .iter()
            .map(Path::new)
            .filter(|p| exists_resolved(p))
            .map(Path::to_path_buf)
            .collect();
        Self {
            bwrap: PathBuf::from("bwrap"),
            roots,
            etc_paths,
            workspace: workspace.to_owned(),
            scratch: scratch.to_owned(),
            env: vec![
                (
                    OsString::from("PATH"),
                    OsString::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
                ),
                (
                    OsString::from("TMPDIR"),
                    OsString::from(SCRATCH_INSIDE_PATH),
                ),
            ],
            protected: Vec::new(),
            extra_ro_binds: Vec::new(),
            placeholders: Vec::new(),
            jail_exe: jail_exe.to_owned(),
            seccomp_fd: None,
            json_status_fd: None,
            args_fd: None,
            force_args_fd: false,
            inner: Vec::new(),
        }
    }

    /// The mount table, in the order the mounts are applied.
    #[must_use]
    pub fn mount_table(&self) -> Vec<MountRow> {
        let mut rows = Vec::new();
        for root in &self.roots {
            match root {
                RootSpec::RoBind(p) => rows.push(MountRow {
                    kind: "ro-bind",
                    source: Some(p.as_os_str().to_owned()),
                    destination: p.as_os_str().to_owned(),
                }),
                RootSpec::Symlink { path, target } => rows.push(MountRow {
                    kind: "symlink",
                    source: Some(target.as_os_str().to_owned()),
                    destination: path.as_os_str().to_owned(),
                }),
            }
        }
        for etc in &self.etc_paths {
            rows.push(MountRow {
                kind: "ro-bind",
                source: Some(etc.as_os_str().to_owned()),
                destination: etc.as_os_str().to_owned(),
            });
        }
        rows.push(MountRow {
            kind: "proc",
            source: None,
            destination: OsString::from("/proc"),
        });
        rows.push(MountRow {
            kind: "dev",
            source: None,
            destination: OsString::from("/dev"),
        });
        rows.push(MountRow {
            kind: "bind",
            source: Some(self.scratch.as_os_str().to_owned()),
            destination: OsString::from(SCRATCH_INSIDE_PATH),
        });
        rows.push(MountRow {
            kind: "bind",
            source: Some(self.workspace.as_os_str().to_owned()),
            destination: self.workspace.as_os_str().to_owned(),
        });
        for protected in &self.protected {
            rows.push(MountRow {
                kind: "ro-bind",
                source: Some(protected.as_os_str().to_owned()),
                destination: protected.as_os_str().to_owned(),
            });
        }
        for (source, destination) in &self.extra_ro_binds {
            rows.push(MountRow {
                kind: "ro-bind",
                source: Some(source.as_os_str().to_owned()),
                destination: destination.as_os_str().to_owned(),
            });
        }
        for placeholder in &self.placeholders {
            rows.push(MountRow {
                kind: "placeholder",
                source: Some(placeholder.source.as_os_str().to_owned()),
                destination: placeholder.destination.as_os_str().to_owned(),
            });
        }
        rows.push(MountRow {
            kind: "ro-bind",
            source: Some(self.jail_exe.as_os_str().to_owned()),
            destination: OsString::from(JAIL_INSIDE_PATH),
        });
        rows
    }

    /// Render the invocation.
    ///
    /// # Errors
    ///
    /// [`PlanError`] for a relative path, an unusable path, a missing command,
    /// or a long list with no `--args` descriptor.
    pub fn render(&self) -> Result<Rendered, PlanError> {
        if self.inner.is_empty() {
            return Err(PlanError::NoCommand);
        }
        for (what, path) in [
            ("workspace", &self.workspace),
            ("scratch", &self.scratch),
            ("jail binary", &self.jail_exe),
        ] {
            if !path.is_absolute() {
                return Err(PlanError::NotAbsolute(what, path.clone()));
            }
            cstring_from_os(path.as_os_str()).map_err(|e| PlanError::Path(what, e))?;
        }

        let mut tail: Vec<OsString> = Vec::new();
        // Scoped so the closure's borrow of `tail` ends before the length of
        // the rendered list is measured.
        {
            let mut push = |parts: &[&OsStr]| {
                for part in parts {
                    tail.push((*part).to_owned());
                }
            };

            for flag in [
                "--unshare-user",
                "--unshare-pid",
                "--unshare-net",
                "--unshare-ipc",
                "--unshare-uts",
                "--die-with-parent",
                "--new-session",
                "--clearenv",
            ] {
                push(&[OsStr::new(flag)]);
            }
            for (key, value) in &self.env {
                push(&[OsStr::new("--setenv"), key, value]);
            }
            for root in &self.roots {
                match root {
                    RootSpec::RoBind(p) => {
                        push(&[OsStr::new("--ro-bind"), p.as_os_str(), p.as_os_str()])
                    }
                    RootSpec::Symlink { path, target } => {
                        push(&[
                            OsStr::new("--symlink"),
                            target.as_os_str(),
                            path.as_os_str(),
                        ]);
                    }
                }
            }
            for etc in &self.etc_paths {
                push(&[OsStr::new("--ro-bind"), etc.as_os_str(), etc.as_os_str()]);
            }
            push(&[OsStr::new("--proc"), OsStr::new("/proc")]);
            push(&[OsStr::new("--dev"), OsStr::new("/dev")]);
            // The scratch is mounted first and the workspace second: bubblewrap
            // applies mounts in order, so the deeper path has to come last. A
            // workspace that happens to live under /tmp would otherwise be hidden
            // by the scratch, and the run would land in a directory bubblewrap
            // created inside the scratch instead of in the workspace.
            push(&[
                OsStr::new("--bind"),
                self.scratch.as_os_str(),
                OsStr::new(SCRATCH_INSIDE_PATH),
            ]);
            push(&[
                OsStr::new("--bind"),
                self.workspace.as_os_str(),
                self.workspace.as_os_str(),
            ]);
            for protected in &self.protected {
                push(&[
                    OsStr::new("--ro-bind"),
                    protected.as_os_str(),
                    protected.as_os_str(),
                ]);
            }
            for (source, destination) in &self.extra_ro_binds {
                push(&[
                    OsStr::new("--ro-bind"),
                    source.as_os_str(),
                    destination.as_os_str(),
                ]);
            }
            for placeholder in &self.placeholders {
                push(&[
                    OsStr::new("--ro-bind"),
                    placeholder.source.as_os_str(),
                    placeholder.destination.as_os_str(),
                ]);
            }
            push(&[
                OsStr::new("--ro-bind"),
                self.jail_exe.as_os_str(),
                OsStr::new(JAIL_INSIDE_PATH),
            ]);
            push(&[OsStr::new("--chdir"), self.workspace.as_os_str()]);
            if let Some(fd) = self.seccomp_fd {
                push(&[OsStr::new("--seccomp"), OsStr::new(&fd.to_string())]);
            }
            if let Some(fd) = self.json_status_fd {
                push(&[OsStr::new("--json-status-fd"), OsStr::new(&fd.to_string())]);
            }
        }
        let size: usize = tail
            .iter()
            .chain(self.inner.iter())
            .map(|part| part.as_bytes().len() + 1)
            .sum();

        if self.force_args_fd || size > ARGS_FD_THRESHOLD {
            let fd = self.args_fd.ok_or(PlanError::ArgsFdMissing)?;
            // Measured on bubblewrap 0.11.1: `--args FD` supplies options
            // only. A command inside the file leaves bubblewrap with nothing
            // to run and it exits with its usage message. The command stays on
            // the command line, after the `--` separator.
            let mut payload = Vec::with_capacity(size);
            for part in &tail {
                payload.extend_from_slice(part.as_bytes());
                payload.push(0);
            }
            let mut argv = vec![
                self.bwrap.as_os_str().to_owned(),
                OsString::from("--args"),
                OsString::from(fd.to_string()),
                OsString::from("--"),
            ];
            argv.extend(self.inner.iter().cloned());
            return Ok(Rendered {
                argv,
                args_payload: Some(payload),
            });
        }

        tail.push(OsString::from("--"));
        let mut argv = Vec::with_capacity(tail.len() + self.inner.len() + 1);
        argv.push(self.bwrap.as_os_str().to_owned());
        argv.extend(tail);
        argv.extend(self.inner.iter().cloned());
        Ok(Rendered {
            argv,
            args_payload: None,
        })
    }
}

/// Build the inner command line: the jail's own binary, re-executed inside.
#[must_use]
pub fn inner_launch_command(
    release_fd: RawFd,
    error_fd: RawFd,
    narrow: bool,
    target: &[OsString],
) -> Vec<OsString> {
    let mut out = vec![
        OsString::from(JAIL_INSIDE_PATH),
        OsString::from(super::launch::SUBCOMMAND),
        OsString::from("--release-fd"),
        OsString::from(release_fd.to_string()),
        OsString::from("--error-fd"),
        OsString::from(error_fd.to_string()),
    ];
    if narrow {
        out.push(OsString::from("--narrow"));
    }
    out.push(OsString::from("--"));
    out.extend(target.iter().cloned());
    out
}

/// One document bubblewrap writes to `--json-status-fd`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BwrapStatus {
    /// Host pid of the namespace init, when reported.
    pub child_pid: Option<libc::pid_t>,
    /// Exit code of the inner command, when reported.
    pub exit_code: Option<i32>,
}

/// Parse bubblewrap's JSON status stream.
///
/// The documents are flat objects with integer values, so this reads the two
/// keys the supervisor needs without pulling a JSON parser into the platform
/// layer. Anything it does not recognise is left `None` rather than guessed.
#[must_use]
pub fn parse_json_status(raw: &str) -> BwrapStatus {
    fn integer_after(raw: &str, key: &str) -> Option<i64> {
        let at = raw.find(&format!("\"{key}\""))?;
        let rest = &raw[at + key.len() + 2..];
        let colon = rest.find(':')?;
        let value: String = rest[colon + 1..]
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        value.parse().ok()
    }
    BwrapStatus {
        child_pid: integer_after(raw, "child-pid").and_then(|v| libc::pid_t::try_from(v).ok()),
        exit_code: integer_after(raw, "exit-code").and_then(|v| i32::try_from(v).ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse() {
        let v = parse_version("bubblewrap 0.11.1\n").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (0, 11, 1));
        assert_eq!(v.raw, "bubblewrap 0.11.1");
        assert_eq!(parse_version("bubblewrap 1.0").unwrap().patch, 0);
        assert!(parse_version("").is_none());
        assert!(parse_version("bubblewrap unknown").is_none());
    }

    #[test]
    fn json_status_documents_parse() {
        let raw = r#"{"child-pid": 12574, "mnt-namespace": 4026533229}
{"exit-code": 7}"#;
        assert_eq!(
            parse_json_status(raw),
            BwrapStatus {
                child_pid: Some(12574),
                exit_code: Some(7),
            }
        );
        assert_eq!(parse_json_status("{}"), BwrapStatus::default());
    }

    fn sample_plan() -> BwrapPlan {
        let mut plan = BwrapPlan::tool(
            Path::new("/work/space"),
            Path::new("/scratch/dir"),
            Path::new("/usr/local/bin/ouro-jail"),
        );
        plan.roots = vec![
            RootSpec::RoBind(PathBuf::from("/usr")),
            RootSpec::Symlink {
                path: PathBuf::from("/bin"),
                target: PathBuf::from("usr/bin"),
            },
        ];
        plan.etc_paths = vec![PathBuf::from("/etc/passwd")];
        plan.protected = vec![PathBuf::from("/work/space/.git")];
        plan.seccomp_fd = Some(10);
        plan.json_status_fd = Some(11);
        plan.inner = inner_launch_command(12, 13, true, &[OsString::from("/bin/true")]);
        plan
    }

    #[test]
    fn the_argv_has_the_profile_the_north_star_describes() {
        let rendered = sample_plan().render().unwrap();
        let text: Vec<String> = rendered
            .argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for flag in [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ] {
            assert!(text.contains(&flag.to_owned()), "missing {flag}");
        }
        let joined = text.join(" ");
        assert!(joined.contains("--symlink usr/bin /bin"));
        assert!(joined.contains("--ro-bind /usr /usr"));
        assert!(joined.contains("--bind /work/space /work/space"));
        assert!(joined.contains("--bind /scratch/dir /tmp"));
        assert!(joined.contains("--ro-bind /work/space/.git /work/space/.git"));
        assert!(joined.contains("--ro-bind /usr/local/bin/ouro-jail /run/ouro/jail"));
        assert!(joined.contains("--chdir /work/space"));
        assert!(joined.contains("--seccomp 10"));
        assert!(joined.contains("--json-status-fd 11"));
        assert!(joined.contains("--proc /proc --dev /dev"));
        assert!(joined.ends_with(
            "-- /run/ouro/jail __launch --release-fd 12 --error-fd 13 --narrow -- /bin/true"
        ));
        assert!(rendered.args_payload.is_none());
    }

    #[test]
    fn the_scratch_becomes_tmpdir() {
        let plan = sample_plan();
        let rendered = plan.render().unwrap();
        let text = rendered
            .argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("--setenv TMPDIR /tmp"));
    }

    #[test]
    fn a_long_list_moves_to_the_args_descriptor() {
        let mut plan = sample_plan();
        plan.args_fd = Some(14);
        plan.force_args_fd = true;
        let rendered = plan.render().unwrap();
        // The command stays on the command line: bubblewrap 0.11.1 takes only
        // options from the descriptor.
        assert_eq!(rendered.argv[0], OsString::from("bwrap"));
        assert_eq!(rendered.argv[1], OsString::from("--args"));
        assert_eq!(rendered.argv[2], OsString::from("14"));
        assert_eq!(rendered.argv[3], OsString::from("--"));
        assert_eq!(rendered.argv[4], OsString::from("/run/ouro/jail"));
        let payload = rendered.args_payload.unwrap();
        let parts: Vec<&[u8]> = payload.split(|b| *b == 0).collect();
        assert_eq!(parts[0], b"--unshare-user");
        assert!(
            !parts.iter().any(|p| *p == b"__launch"),
            "the command must not be in the arguments file"
        );
        assert!(
            !parts.iter().any(|p| *p == b"--"),
            "the separator belongs on the command line"
        );
        // The last option is the one the plan emits last.
        assert_eq!(parts[parts.len() - 2], b"11");
        // Splitting on NUL leaves one empty tail after the final terminator.
        assert_eq!(parts.last().unwrap(), b"");
    }

    #[test]
    fn a_long_list_without_a_descriptor_refuses() {
        let mut plan = sample_plan();
        plan.force_args_fd = true;
        assert!(matches!(plan.render(), Err(PlanError::ArgsFdMissing)));
    }

    #[test]
    fn a_relative_workspace_refuses() {
        let mut plan = sample_plan();
        plan.workspace = PathBuf::from("space");
        assert!(matches!(
            plan.render(),
            Err(PlanError::NotAbsolute("workspace", _))
        ));
    }

    #[test]
    fn a_plan_with_no_command_refuses() {
        let mut plan = sample_plan();
        plan.inner.clear();
        assert!(matches!(plan.render(), Err(PlanError::NoCommand)));
    }

    #[test]
    fn the_mount_table_lists_every_grant_the_argv_makes() {
        let plan = sample_plan();
        let rows = plan.mount_table();
        let destinations: Vec<String> = rows
            .iter()
            .map(|r| r.destination.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            destinations,
            vec![
                "/usr",
                "/bin",
                "/etc/passwd",
                "/proc",
                "/dev",
                "/tmp",
                "/work/space",
                "/work/space/.git",
                "/run/ouro/jail",
            ]
        );
        assert_eq!(rows[1].kind, "symlink");
        assert_eq!(rows[1].source.as_deref(), Some(OsStr::new("usr/bin")));
    }

    #[test]
    fn a_path_with_an_interior_nul_refuses() {
        use std::os::unix::ffi::OsStrExt as _;
        let mut plan = sample_plan();
        plan.workspace = PathBuf::from(OsStr::from_bytes(b"/work\0space"));
        assert!(matches!(
            plan.render(),
            Err(PlanError::Path("workspace", _))
        ));
    }
}
