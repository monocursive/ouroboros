//! J12: zero-config launch (jail-launch-and-summary.md §3.2 to §3.4).
//!
//! - [`discover_workspace`]: with `--from-path` and no `--workspace`, the
//!   nearest git top level, found by a no-follow walk; `git` itself is
//!   never run (a repository's own configuration can make it execute
//!   commands, `core.fsmonitor` for one, with the operator's authority).
//! - [`refuse_home_workspace`]: on every contained run, a workspace that is
//!   `/`, the operator's home or an ancestor of it refuses (§7, decision 2).
//! - [`program_layer`] and [`check_program_placement`]: the read-only
//!   install roots of the resolved program, as an operator layer before the
//!   project file (which can still deny-read them), and the refusals of
//!   §3.3 step 4.
//! - [`select_credentials`] and [`bind_program_token`]: the launch-profile
//!   keys `credentials_one_of` and `binaries = ["@program"]` (§3.4).
//! - [`child_cwd`]: the child starts where the operator stood, when that is
//!   beneath the workspace (§3.2 step 4).

use std::ffi::OsStr;
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use super::{Context, canonical_existing_prefix, child_writable_roots, overlaps, usage};
use crate::launch_profile::LaunchProfile;
use crate::policy::{Layer, LayerOrigin, PolicyDelta, ProvenanceEntry, Resolved, RootToken};
use crate::program::Program;
use crate::records::{ErrorCode, ErrorStage, JailError, NativeString, Remediation};
use crate::state::anchored::{self, Dir, Kind, Name};

/// The largest `.git` file read: git's own gitfile is one short line.
const GITFILE_MAX: u64 = 4096;

/// The provenance origin of everything `--from-path` derived (§3.3 step 6).
pub(super) const ORIGIN: &str = "program-resolution";

fn widening(key: &str, message: String) -> JailError {
    JailError::new(
        ErrorCode::PolicyWidening,
        ErrorStage::Resolving,
        Remediation::Configuration,
        message,
    )
    .with_key_path(key)
}

// ---------------------------------------------------------------------------
// The workspace (§3.2)
// ---------------------------------------------------------------------------

/// The nearest directory at or above `cwd` holding a `.git` entry that is
/// either a directory containing `HEAD` or a regular file of at most 4 KiB
/// whose first line begins `gitdir: ` (§3.2 step 1). The walk opens every
/// directory from `/` with no symlink followed and stops, as git does by
/// default, where the device changes. Nothing outside a repository is
/// guessed (step 2).
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] at `--workspace` outside a repository, or
/// when the invocation directory cannot be walked.
pub(super) fn discover_workspace(cwd: &Path) -> Result<PathBuf, JailError> {
    let unreadable = |error: std::io::Error| {
        usage(
            "--workspace",
            format!(
                "the invocation directory {} cannot be walked to find its repository: {error}",
                cwd.display()
            ),
        )
    };
    let cwd = std::fs::canonicalize(cwd).map_err(unreadable)?;
    let components = anchored::split_absolute(cwd.as_os_str().as_bytes()).map_err(unreadable)?;
    let mut levels: Vec<(PathBuf, Dir, anchored::Stat)> = Vec::with_capacity(components.len() + 1);
    let root = Dir::open_root_for_walk().map_err(unreadable)?;
    let root_stat = root.stat().map_err(unreadable)?;
    levels.push((PathBuf::from("/"), root, root_stat));
    for component in &components {
        let (parent_path, parent, _) = levels.last().expect("the root is first");
        let path = parent_path.join(OsStr::from_bytes(component.as_bytes()));
        let stat = parent.stat_at(component).map_err(unreadable)?;
        if stat.kind != Kind::Directory {
            return Err(unreadable(std::io::Error::other(format!(
                "{} is {}",
                path.display(),
                stat.kind.describe()
            ))));
        }
        let dir = parent
            .open_walk_at(component, Some(&stat))
            .map_err(unreadable)?;
        levels.push((path, dir, stat));
    }
    let found = nearest_top(
        levels
            .iter()
            .map(|(path, dir, stat)| (path.as_path(), stat.dev, || is_repository_top(dir))),
    );
    if let Some(top) = found {
        return Ok(top.to_path_buf());
    }
    Err(usage(
        "--workspace",
        format!(
            "{} is not inside a git repository; pass --workspace PATH",
            cwd.display()
        ),
    ))
}

/// The deepest level, walking up from the last, that is a repository's top
/// level, never crossing to another device than the last level's
/// (GIT_DISCOVERY_ACROSS_FILESYSTEM is off by default). `levels` run from
/// `/` down; each is its path, its device and how to ask whether it is a top
/// level, asked only for levels on the starting device.
fn nearest_top<'a, F: Fn() -> bool>(
    levels: impl DoubleEndedIterator<Item = (&'a Path, u64, F)>,
) -> Option<&'a Path> {
    let mut device = None;
    for (path, dev, is_top) in levels.rev() {
        if *device.get_or_insert(dev) != dev {
            return None;
        }
        if is_top() {
            return Some(path);
        }
    }
    None
}

/// Whether `dir` holds a `.git` that marks a repository's top level.
fn is_repository_top(dir: &Dir) -> bool {
    let Ok(git) = Name::new(b".git") else {
        return false;
    };
    let Ok(stat) = dir.stat_at(&git) else {
        return false;
    };
    match stat.kind {
        Kind::Directory => {
            let Ok(head) = Name::new(b"HEAD") else {
                return false;
            };
            dir.open_walk_at(&git, Some(&stat))
                .and_then(|inner| inner.stat_at(&head))
                .is_ok()
        }
        Kind::Regular if stat.size <= GITFILE_MAX => {
            let Ok(file) = dir.open_read_at(&git, Some(&stat)) else {
                return false;
            };
            let mut bytes = Vec::new();
            if file.take(GITFILE_MAX + 1).read_to_end(&mut bytes).is_err() {
                return false;
            }
            bytes.starts_with(b"gitdir: ")
        }
        _ => false,
    }
}

/// The operator's home directories: `HOME`, and the user database's entry
/// for this uid, each canonical where it exists. A workspace or an install
/// root at or above either refuses: `HOME` is what the operator's tools
/// write to, and the database entry is where their shell start-up files,
/// SSH keys and agent credentials live whatever `HOME` says.
pub(super) fn operator_homes(ctx: &Context) -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = Vec::new();
    let database = crate::state::accounts::user(crate::state::effective_uid())
        .ok()
        .flatten()
        .and_then(|user| user.home)
        .map(|home| PathBuf::from(OsStr::from_bytes(&home)));
    for home in ctx.home.iter().cloned().chain(database) {
        if !home.is_absolute() {
            continue;
        }
        let home = std::fs::canonicalize(&home).unwrap_or(home);
        if !homes.contains(&home) {
            homes.push(home);
        }
    }
    homes
}

/// Why `path` (canonical) may not be granted: it is `/`, a home, or an
/// ancestor of one. `None` when it is none of those.
pub(super) fn home_or_above(path: &Path, homes: &[PathBuf]) -> Option<String> {
    if path == Path::new("/") {
        return Some("the filesystem root".to_owned());
    }
    homes.iter().find_map(|home| {
        if home == path {
            Some(format!("the operator's home {}", home.display()))
        } else if home.starts_with(path) {
            Some(format!(
                "an ancestor of the operator's home {}",
                home.display()
            ))
        } else {
            None
        }
    })
}

/// §3.2 step 3: on every contained run, a workspace that is `/`, the
/// operator's home or an ancestor of it refuses, however it was chosen.
/// There is no flag to bypass it; `--profile none` grants no workspace.
///
/// # Errors
/// [`ErrorCode::PolicyWidening`] at `--workspace`.
pub(super) fn refuse_home_workspace(ctx: &Context, workspace: &Path) -> Result<(), JailError> {
    let workspace = canonical_existing_prefix(workspace);
    match home_or_above(&workspace, &operator_homes(ctx)) {
        Some(what) => Err(widening(
            "--workspace",
            format!(
                "the workspace {} is {what}; a contained run never grants it (its shell \
                 start-up files, SSH keys and agent credentials). Run from a project \
                 directory or pass --workspace PATH",
                workspace.display()
            ),
        )),
        None => Ok(()),
    }
}

/// §3.2 step 4: the child's working directory, relative to the workspace:
/// the invocation directory when it lies strictly beneath the workspace,
/// `None` (the root) otherwise.
pub(super) fn child_cwd(cwd: &Path, workspace: &Path) -> Option<NativeString> {
    let cwd = std::fs::canonicalize(cwd).ok()?;
    let relative = cwd.strip_prefix(workspace).ok()?;
    if relative.as_os_str().is_empty() {
        return None;
    }
    NativeString::from_bytes(relative.as_os_str().as_bytes().to_vec()).ok()
}

// ---------------------------------------------------------------------------
// The program (§3.3)
// ---------------------------------------------------------------------------

/// The layer of the derived read-only install roots: an operator layer,
/// applied after the command line and before the project file, so a project
/// `ukai.toml` can still deny-read a root (the agent then fails visibly) but
/// never add one.
pub(super) fn program_layer(program: &Program) -> Layer {
    Layer {
        origin: LayerOrigin::ProgramResolution,
        base_dir: None,
        delta: PolicyDelta {
            read_only: program
                .roots()
                .iter()
                .map(|root| root.path.as_os_str().as_bytes().to_vec())
                .collect(),
            ..PolicyDelta::default()
        },
    }
}

/// One derived install root, as `explain`, the pre-exec line and `doctor`
/// disclose it (§3.3 step 6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DerivedRoot {
    /// The directory.
    pub path: PathBuf,
    /// Whether it is a new read-only grant (`by: program_resolution` in the
    /// receipt), or already readable through a root before it.
    pub granted: bool,
    /// The root that already makes it readable, when it is not granted.
    pub covered_by: Option<String>,
}

/// What the resolution made of each install root: granted, or covered by a
/// root that already grants it (an npm install's root lies under `/usr`,
/// which is a runtime root already).
#[must_use]
pub fn derived_roots(program: &Program, resolved: &Resolved) -> Vec<DerivedRoot> {
    program
        .roots()
        .into_iter()
        .map(|root| {
            let value = root.path.as_os_str().as_bytes();
            let granted = resolved.grants.iter().any(|grant| {
                grant.by == "program_resolution"
                    && grant.kind == "read_only"
                    && grant.value.as_bytes() == value
            });
            let covered_by = (!granted)
                .then(|| {
                    resolved
                        .snapshot
                        .filesystem
                        .read_only
                        .iter()
                        .chain(&resolved.snapshot.filesystem.read_write)
                        .filter(|reference| reference.root == RootToken::Host)
                        .filter(|reference| {
                            Path::new(OsStr::from_bytes(value))
                                .starts_with(OsStr::from_bytes(reference.path.as_bytes()))
                        })
                        .max_by_key(|reference| reference.path.as_bytes().len())
                        .map(|reference| reference.path.to_display())
                })
                .flatten();
            DerivedRoot {
                path: root.path.clone(),
                granted,
                covered_by,
            }
        })
        .collect()
}

/// The line printed before exec when stderr is a terminal (§3.3 step 6):
/// the name, the argv it became and every derived root.
#[must_use]
pub fn program_line(program: &Program, resolved: &Resolved) -> String {
    let argv: Vec<String> = program
        .argv_prefix()
        .iter()
        .map(|word| crate::records::escape_control(&String::from_utf8_lossy(word)))
        .collect();
    let roots: Vec<String> = derived_roots(program, resolved)
        .iter()
        .map(|root| {
            let path = crate::records::escape_control(&root.path.display().to_string());
            match (&root.covered_by, root.granted) {
                (_, true) => format!("read-only: {path}"),
                (Some(by), false) => format!(
                    "already readable: {path} under {}",
                    crate::records::escape_control(by)
                ),
                (None, false) => format!("not granted: {path}"),
            }
        })
        .collect();
    format!(
        "ukai-jail: {} = {} ({})",
        crate::records::escape_control(&program.name),
        argv.join(" "),
        roots.join("; ")
    )
}

/// The provenance of the resolution itself: the program and, after an
/// `env` expansion, its interpreter.
pub(super) fn program_provenance(program: &Program) -> Vec<ProvenanceEntry> {
    let mut why = vec![ProvenanceEntry {
        origin: ORIGIN.to_owned(),
        key: "program".to_owned(),
        detail: Some(format!(
            "{} = {} ({})",
            program.name,
            program.program.path.display(),
            program.format.as_str()
        )),
    }];
    if let Some(interpreter) = &program.interpreter {
        why.push(ProvenanceEntry {
            origin: ORIGIN.to_owned(),
            key: "program.interpreter".to_owned(),
            detail: Some(interpreter.path.display().to_string()),
        });
    }
    why
}

/// What §3.3 step 4 compares an install root and an executable against.
pub(super) struct Placement<'a> {
    pub(super) resolved: &'a Resolved,
    pub(super) workspace: &'a Path,
    pub(super) config_dir: &'a Path,
    pub(super) data_dir: &'a Path,
    /// Every credential source the launch profile declares, staged or not.
    pub(super) sources: Vec<PathBuf>,
    pub(super) homes: Vec<PathBuf>,
}

/// §3.3 step 4: each install root (granted or covered) and each executable
/// refuses when it is `/`, a home or an ancestor of one; contains the
/// config directory, the data directory or a credential source of this
/// launch; lies inside or contains the workspace, the scratch, vendor state
/// (beneath the data directory) or any writable grant, or is reached from
/// one through a bind alias; or is, contains or lies beneath `/proc` or
/// `/sys` (the cgroup filesystem is beneath `/sys`). A contained agent that
/// could rewrite its own executable would run that code with the
/// operator's authority on the next host launch.
///
/// # Errors
/// [`ErrorCode::PolicyWidening`] at `--from-path` naming the root.
pub(super) fn check_program_placement(
    program: &Program,
    placement: &Placement<'_>,
) -> Result<(), JailError> {
    let refuse = |root: &Path, why: String| {
        widening(
            crate::program::KEY,
            format!(
                "the program {} would be granted through {}, which {why}",
                program.program.path.display(),
                root.display()
            ),
        )
    };
    let writable: Vec<PathBuf> = child_writable_roots(placement.resolved, placement.workspace)
        .iter()
        .map(|root| canonical_existing_prefix(root))
        .collect();
    let guarded: Vec<(PathBuf, &str)> = [
        (placement.config_dir, "the config directory"),
        (placement.data_dir, "the data directory"),
    ]
    .into_iter()
    .map(|(path, what)| (canonical_existing_prefix(path), what))
    .collect();
    let mut checked: Vec<&Path> = program
        .roots()
        .into_iter()
        .map(|root| root.path.as_path())
        .collect();
    checked.extend(
        program
            .executables()
            .into_iter()
            .map(|executable| executable.path.as_path()),
    );
    for root in checked {
        if let Some(what) = home_or_above(root, &placement.homes) {
            return Err(refuse(root, format!("is {what}")));
        }
        for (path, what) in &guarded {
            if overlaps(root, path) {
                return Err(refuse(root, format!("overlaps {what} {}", path.display())));
            }
        }
        for source in &placement.sources {
            if canonical_existing_prefix(source).starts_with(root) {
                return Err(refuse(
                    root,
                    "contains a credential source of this launch".to_owned(),
                ));
            }
        }
        if let Some(grant) = writable.iter().find(|grant| overlaps(root, grant)) {
            return Err(refuse(
                root,
                format!("overlaps the child-writable root {}", grant.display()),
            ));
        }
        for pseudo in ["/proc", "/sys"] {
            if overlaps(root, Path::new(pseudo)) {
                return Err(refuse(root, format!("overlaps {pseudo}")));
            }
        }
        if let Some(alias) = super::alias_conflict(&writable, root, crate::program::KEY)? {
            return Err(refuse(
                root,
                format!(
                    "is reached from a child-writable root through the bind alias {}",
                    alias.display()
                ),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The launch-profile keys (§3.4)
// ---------------------------------------------------------------------------

/// `credentials_one_of`: keeps the first listed credential whose source
/// exists and drops every other listed one; the rest of the profile's
/// credentials are untouched. Only absence counts as absent (the source, or
/// a directory on its path, does not exist): a source that exists and is
/// unsafe (a wrong mode, owner, link count, a symlink) is kept and refused
/// by staging, as today, never skipped in favour of the next one. None
/// present refuses before anything is prepared, listing each id with its
/// hint. Returns the provenance of each id skipped.
///
/// # Errors
/// [`ErrorCode::CredentialUnavailable`] at `launch.credentials_one_of` when
/// no listed source exists.
pub(super) fn select_credentials(
    launch: &mut LaunchProfile,
) -> Result<Vec<ProvenanceEntry>, JailError> {
    if launch.credentials_one_of.is_empty() {
        return Ok(Vec::new());
    }
    let origin = format!("launch-profile:{}", launch.name);
    let mut why = Vec::new();
    let mut chosen: Option<String> = None;
    for id in &launch.credentials_one_of {
        let Some(credential) = launch.credentials.iter().find(|c| &c.id == id) else {
            continue;
        };
        if crate::credentials::source_absent(credential.source.as_bytes()) {
            why.push(ProvenanceEntry {
                origin: origin.clone(),
                key: format!("launch.credentials.{id}"),
                detail: Some("skipped: absent".to_owned()),
            });
            continue;
        }
        chosen = Some(id.clone());
        break;
    }
    let Some(chosen) = chosen else {
        let listed: Vec<String> = launch
            .credentials_one_of
            .iter()
            .map(|id| match launch.hints.get(id) {
                Some(hint) => format!("`{id}` ({hint})"),
                None => format!("`{id}`"),
            })
            .collect();
        return Err(JailError::new(
            ErrorCode::CredentialUnavailable,
            ErrorStage::Resolving,
            Remediation::Configuration,
            format!(
                "launch profile `{}` needs one of its credentials, and none is present: {}",
                launch.name,
                listed.join("; ")
            ),
        )
        .with_key_path("launch.credentials_one_of"));
    };
    let dropped: Vec<String> = launch
        .credentials_one_of
        .iter()
        .filter(|id| **id != chosen)
        .cloned()
        .collect();
    for id in &dropped {
        if !why
            .iter()
            .any(|entry| entry.key == format!("launch.credentials.{id}"))
        {
            why.push(ProvenanceEntry {
                origin: origin.clone(),
                key: format!("launch.credentials.{id}"),
                detail: Some(format!("skipped: `{chosen}` comes first")),
            });
        }
    }
    launch
        .credentials
        .retain(|credential| !dropped.contains(&credential.id));
    Ok(why)
}

/// `binaries = ["@program"]`: binds the credential to the resolved program
/// (`X'` after an `env` expansion) under `--from-path`, and otherwise to
/// `PROGRAM` when it is an absolute path (canonical, so the binding names
/// the file the kernel reports as the connecting process's executable). A
/// run whose `PROGRAM` is not absolute refuses naming the key; `explain`
/// and `doctor` without `--from-path` have no program and keep the token.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] at `launch.credentials.<id>.binaries`.
pub(super) fn bind_program_token(
    launch: &mut LaunchProfile,
    program: Option<&Program>,
    argv0: Option<&[u8]>,
    executing: bool,
) -> Result<(), JailError> {
    for credential in &mut launch.credentials {
        let id = credential.id.clone();
        let Some(vault) = credential.vault.as_mut() else {
            continue;
        };
        if !vault
            .binaries
            .iter()
            .any(|binary| binary == crate::vault::PROGRAM_TOKEN)
        {
            continue;
        }
        let key = format!("launch.credentials.{id}.binaries");
        let path: Option<PathBuf> = match (program, argv0) {
            // A `#!` script run by a system interpreter never makes a
            // connection itself: the kernel reports the interpreter as the
            // connecting executable, so a binding to the script would refuse
            // every request, and one to the interpreter would admit every
            // script it runs. Neither is what `@program` says.
            (Some(program), _)
                if matches!(program.format, crate::program::Format::Script { .. }) =>
            {
                return Err(usage(
                    &key,
                    format!(
                        "`@program` binds a credential to the executable that makes its \
                         connections, and {} is a `#!` script whose connections come from its \
                         interpreter; name the executable in `binaries` instead",
                        program.program.path.display()
                    ),
                ));
            }
            (Some(program), _) => Some(program.bound().path.clone()),
            (None, Some(argv0)) if argv0.first() == Some(&b'/') => Some(
                std::fs::canonicalize(OsStr::from_bytes(argv0)).map_err(|error| {
                    usage(
                        &key,
                        format!(
                            "`@program` names PROGRAM {}, which cannot be resolved: {error}",
                            String::from_utf8_lossy(argv0)
                        ),
                    )
                })?,
            ),
            (None, Some(_)) if executing => {
                return Err(usage(
                    &key,
                    "`@program` needs --from-path or an absolute PROGRAM after `--`",
                ));
            }
            (None, _) => None,
        };
        let Some(path) = path else { continue };
        let Some(text) = path.to_str() else {
            return Err(usage(
                &key,
                format!(
                    "`@program` resolved to {}, which is not UTF-8",
                    path.display()
                ),
            ));
        };
        for binary in &mut vault.binaries {
            if binary == crate::vault::PROGRAM_TOKEN {
                text.clone_into(binary);
            }
        }
        vault.binaries.sort();
        vault.binaries.dedup();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// K34: discovery stops at a mount boundary, as git does by default,
    /// whether or not a repository lies beyond it.
    #[test]
    fn discovery_never_crosses_a_device_boundary() {
        let levels = |marks: &[(&'static str, u64, bool)]| -> Option<&'static str> {
            nearest_top(
                marks
                    .iter()
                    .map(|(path, dev, top)| (Path::new(*path), *dev, move || *top)),
            )
            .map(|path| path.to_str().unwrap())
        };
        // The same device all the way: the nearest top level wins.
        assert_eq!(
            levels(&[
                ("/", 1, false),
                ("/r", 1, true),
                ("/r/a", 1, false),
                ("/r/a/b", 1, false)
            ]),
            Some("/r")
        );
        assert_eq!(
            levels(&[
                ("/", 1, false),
                ("/r", 1, true),
                ("/r/a", 1, true),
                ("/r/a/b", 1, false)
            ]),
            Some("/r/a")
        );
        // A repository beyond a mount boundary is not found.
        assert_eq!(
            levels(&[
                ("/", 1, false),
                ("/r", 1, true),
                ("/r/m", 2, false),
                ("/r/m/b", 2, false)
            ]),
            None
        );
        // One on the starting device, beneath the boundary, is.
        assert_eq!(
            levels(&[("/", 1, true), ("/m", 2, true), ("/m/b", 2, false)]),
            Some("/m")
        );
        // A level beyond the boundary is never even asked.
        let asked = std::cell::Cell::new(false);
        let ask_root = || {
            asked.set(true);
            true
        };
        let never = || false;
        let checks: [(&Path, u64, &dyn Fn() -> bool); 2] =
            [(Path::new("/"), 1, &ask_root), (Path::new("/m"), 2, &never)];
        let found = nearest_top(checks.into_iter());
        assert_eq!(found, None);
        assert!(!asked.get());
    }

    #[test]
    fn home_or_above_names_root_home_and_ancestors_only() {
        let homes = [PathBuf::from("/home/u")];
        assert!(home_or_above(Path::new("/"), &homes).is_some());
        assert!(home_or_above(Path::new("/home"), &homes).is_some());
        assert!(home_or_above(Path::new("/home/u"), &homes).is_some());
        assert!(home_or_above(Path::new("/home/u/repo"), &homes).is_none());
        assert!(home_or_above(Path::new("/home/uu"), &homes).is_none());
        assert!(home_or_above(Path::new("/srv"), &homes).is_none());
    }
}
