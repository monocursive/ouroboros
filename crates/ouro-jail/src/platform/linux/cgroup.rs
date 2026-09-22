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
            return Ok(value.trim() == "1");
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no populated line in cgroup.events",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
