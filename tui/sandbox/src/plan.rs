//! Turning a validated `Policy` into an ordered list of things to do to the kernel.
//!
//! Everything in this module is portable and unit-tested on whatever machine runs
//! `cargo test`. It performs exactly one kind of I/O — reading directory entries under the
//! writable roots, to find the `.git` directories that already exist — and that reads the
//! same on macOS as on Linux. Nothing here calls a Linux syscall, so the interesting half
//! of the helper (what the policy *means*) is testable without a Linux box, and the Linux
//! half (`crate::linux`) is a executor with no policy decisions left in it.
//!
//! # Why the order is what it is
//!
//! The bubblewrap backend gets its semantics from bind order into a fresh root. This
//! helper does not build a fresh root — it stays in the host's own path namespace, which
//! means it cannot create a placeholder directory for a bind target without that
//! directory persisting on the real filesystem after the command ends. Littering a user's
//! workspace with empty `.git` directories would be worse than the hole it plugs.
//!
//! So the ordering is inverted relative to bwrap, and it is simpler:
//!
//! 1. **`BindWritable`** each writable root, *first*, while every source mount is still
//!    pristine. A bind mount is an independent mount object: once it exists, making the
//!    mount underneath it read-only does not make it read-only.
//! 2. **`Tmpfs`** the scratch directory — a fresh, private, writable filesystem.
//! 3. **`ReadOnlySweep`** every mount that existed before step 1. This is the default-deny:
//!    after it, the only writable things in the namespace are what steps 1 and 2 created.
//! 4. **`BindReadOnly`** the paths that must stay read-only *inside* what step 1 made
//!    writable.
//!
//! Step 4 is only ever about paths inside a writable root. A protected root that is not
//! inside one needs no bind at all, because step 3 already covers it — and emitting one
//! anyway would be a mount whose only effect is to make the plan look busier. This is the
//! one visible divergence from the bwrap argv, and `protected_outside_a_writable_root_
//! needs_no_bind` pins it.
//!
//! Nested roots are applied shallowest-first within each step, so a policy that puts a
//! writable worktree under the node's read-only data directory (the D7 case the bwrap
//! backend calls out) resolves the same way it does there.

use crate::request::{Limits, Mode, Policy};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// How deep beneath a writable root this helper looks for existing denied-name
/// directories, and how many entries it will visit doing it. Both mirror the bubblewrap
/// backend's own caps: a vendored dependency's `.git` is as much a repository as the
/// workspace's own, but an unbounded walk of a large tree on every `bash` call is a cost
/// the sandbox should not impose.
pub const MAX_SCAN_DEPTH: usize = 6;
pub const MAX_SCAN_VISITS: usize = 2_048;

/// One change to the mount namespace, in application order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountOp {
    /// Bind `path` onto itself and leave it writable. Emitted before any narrowing.
    BindWritable { path: String },
    /// A fresh private tmpfs at `path`.
    Tmpfs { path: String },
    /// Make every mount that existed before this plan started read-only, except the ones
    /// named here.
    ReadOnlySweep { keep_writable: Vec<String> },
    /// Bind `path` onto itself read-only. Only ever a path inside a `BindWritable`.
    BindReadOnly { path: String, why: ReadOnlyReason },
}

/// Why a path inside a writable root is being pinned read-only — carried so a denial can
/// be explained and so tests read as policy rather than as paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOnlyReason {
    /// The node's data directory or the operator's config, nested inside a writable root.
    ProtectedRoot,
    /// An existing `.git` / `.ouroboros` directory beneath a writable root.
    DeniedName,
}

/// The mounts this helper deliberately does not touch.
///
/// A read-only `/dev` makes `open("/dev/null", O_WRONLY)` fail, which breaks essentially
/// every shell pipeline, and a read-only `/proc` breaks tools that write their own
/// `/proc/self` knobs. bubblewrap solves this by mounting a *fresh minimal* `/dev` and
/// `/proc` inside its new root. This helper has no new root to mount them into, so it
/// leaves the host's own — writable. That is a real and documented difference in posture
/// from the bwrap backend, not a claim of equivalence.
///
/// Two consequences worth naming rather than discovering later. A device node under `/dev`
/// is writable to whatever the invoking user's own permissions already allow, which is the
/// unsandboxed baseline rather than bubblewrap's narrower one. And `/proc/net` continues to
/// describe the *original* network namespace, because procfs is not remounted after
/// `unshare(CLONE_NEWNET)` — an information difference, not a connectivity one: sockets
/// follow the process's namespace, so a network-denied command still gets `ENETUNREACH`.
/// Remounting `/proc` would fix the latter and is deliberately not done, because inside a
/// container it would also unmask the paths the container runtime masked there.
pub const KEEP_WRITABLE: &[&str] = &["/dev", "/proc"];

/// The Landlock half of the plan.
///
/// Deliberately *congruent* with the mount half: every path this grants write rights on is
/// a path the mount plan also leaves writable, and vice versa. That congruence is the
/// point, for two reasons.
///
/// The first is error semantics. A Landlock denial surfaces as `EACCES`
/// ("Permission denied"), which the Elixir side refuses to treat as a sandbox denial —
/// correctly, since an ordinary file mode produces exactly the same errno. A read-only
/// *mount* denial surfaces as `EROFS` ("Read-only file system"), which is unambiguous, and
/// the kernel checks the mount's read-only flag before it consults the LSM. So as long as
/// the two layers agree, every denial a command can actually provoke arrives as `EROFS` —
/// the same string the bwrap backend produces, and the one
/// `Ouroboros.Provider.Native.Sandbox.violation/3` already matches.
///
/// The second is that a congruent Landlock layer is not redundant, it is load-bearing. The
/// mount policy is only as true as the command's inability to undo it, and a process that
/// has just created its own user namespace holds `CAP_SYS_ADMIN` over its own mount
/// namespace — it could remount its way out. The helper drops that capability and seccomp
/// refuses the syscall, but both of those are things that could be got wrong. A Landlock
/// domain cannot be left, and it governs mounts created after it was installed. It is what
/// makes the mount policy true rather than merely intended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockPlan {
    /// Granted the read set. Always `/`: reads go anywhere the process could already read.
    pub read_roots: Vec<String>,
    /// Granted the read set and the write set.
    pub write_roots: Vec<String>,
    /// Granted the read set again, more specifically than an enclosing `write_root`, which
    /// is how Landlock expresses "writable, except here".
    pub read_only_overrides: Vec<String>,
}

/// The network posture.
///
/// Landlock ABI 4 can deny `bind(2)` and `connect(2)` over TCP, and this helper
/// deliberately does not use it. Those rights are not address-aware: denying `CONNECT_TCP`
/// denies it to `127.0.0.1` as well as to the internet, and an isolated network namespace
/// — which is what the bubblewrap backend gives, and what this mirrors — leaves loopback
/// working precisely so that a test suite binding `127.0.0.1` still runs. Trading that for
/// a second layer under the one mechanism that already produces the right errno
/// (`ENETUNREACH`) would break honest builds to harden nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPosture {
    /// Inherit the daemon's network. Only when the operator has opted in.
    Inherit,
    /// `unshare(CLONE_NEWNET)`: a private network namespace with loopback up and no route
    /// off the machine, which answers `ENETUNREACH`.
    Unshare,
}

/// `setrlimit(2)` ceilings, with this helper's defaults resolved in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLimits {
    pub max_processes: Option<u64>,
    pub max_file_bytes: Option<u64>,
    pub cpu_seconds: Option<u64>,
    /// Defaults to 0. A sandboxed command that dumps core writes a copy of its own memory
    /// into the workspace, and nothing in this runtime reads core files.
    pub core_bytes: u64,
}

impl From<&Limits> for ResolvedLimits {
    fn from(limits: &Limits) -> ResolvedLimits {
        ResolvedLimits {
            max_processes: limits.max_processes,
            max_file_bytes: limits.max_file_bytes,
            cpu_seconds: limits.cpu_seconds,
            core_bytes: limits.core_bytes.unwrap_or(0),
        }
    }
}

/// The name-based create filter: the one thing in the bwrap backend's contract that no
/// kernel mechanism available here can express.
///
/// Landlock has no name matching and no globs. Its rights are attached to inodes, which
/// means a rule can only be written for a path that exists when the ruleset is built.
/// `mkdir deps/foo/.git` names a path that does not exist yet, and the only Landlock right
/// that governs it is `LANDLOCK_ACCESS_FS_MAKE_DIR` *on the parent* — denying that would
/// deny every legitimate `mkdir` in the workspace too.
///
/// So this stays exactly where the bwrap backend left it: the `LD_PRELOAD` shim in
/// `c_src/fs_filter.c`, with the same reach and the same hole (a static binary that never
/// calls libc is outside it). The helper carries it rather than improving on it, and says
/// so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreloadFilter {
    pub library: String,
    /// Joined with `:` into `OUROBOROS_FS_DENY`, the variable `fs_filter.c` reads.
    pub denied_names: Vec<String>,
}

/// Everything the executor needs, with no policy decisions left in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub mode: Mode,
    pub mounts: Vec<MountOp>,
    pub landlock: LandlockPlan,
    pub network: NetworkPosture,
    pub limits: ResolvedLimits,
    pub preload: Option<PreloadFilter>,
    pub cwd: Option<String>,
}

impl Plan {
    /// Compiles a policy into a plan, scanning the writable roots for the denied-name
    /// directories that already exist.
    pub fn compile(policy: &Policy, fs_filter_library: Option<&str>) -> Plan {
        let mut writable_binds = policy.writable.clone();
        sort_shallowest_first(&mut writable_binds);

        let mut mounts: Vec<MountOp> = writable_binds
            .iter()
            .map(|path| MountOp::BindWritable { path: path.clone() })
            .collect();

        mounts.push(MountOp::Tmpfs {
            path: policy.scratch.clone(),
        });

        let mut keep_writable: Vec<String> =
            KEEP_WRITABLE.iter().map(|s| (*s).to_string()).collect();
        keep_writable.sort();
        mounts.push(MountOp::ReadOnlySweep { keep_writable });

        // Only paths *inside* a writable bind need pinning back: everything else is
        // already read-only from the sweep.
        let mut nested_protected: Vec<String> = policy
            .protected
            .iter()
            .filter(|path| inside_any(path, &writable_binds))
            .cloned()
            .collect();
        sort_shallowest_first(&mut nested_protected);

        let mut denied_dirs = existing_denied_dirs(&writable_binds, &policy.denied_names);
        sort_shallowest_first(&mut denied_dirs);

        for path in nested_protected {
            mounts.push(MountOp::BindReadOnly {
                path,
                why: ReadOnlyReason::ProtectedRoot,
            });
        }
        for path in denied_dirs.iter() {
            mounts.push(MountOp::BindReadOnly {
                path: path.clone(),
                why: ReadOnlyReason::DeniedName,
            });
        }

        // Derived from the mount plan rather than rebuilt alongside it, so the two cannot
        // drift: whatever the mounts leave writable is exactly what Landlock grants. The
        // `/dev` and `/proc` the sweep skips are added for the same reason.
        let mut write_roots = writable_mount_paths(&mounts);
        write_roots.extend(KEEP_WRITABLE.iter().map(|s| (*s).to_string()));
        let write_roots = dedup_sorted(write_roots);

        let mut read_only_overrides: Vec<String> = mounts
            .iter()
            .filter_map(|op| match op {
                MountOp::BindReadOnly { path, .. } => Some(path.clone()),
                _ => None,
            })
            .collect();
        read_only_overrides = dedup_sorted(read_only_overrides);

        let preload = match (fs_filter_library, policy.denied_names.as_slice()) {
            (Some(library), [_, ..]) => Some(PreloadFilter {
                library: library.to_string(),
                denied_names: policy.denied_names.clone(),
            }),
            _ => None,
        };

        Plan {
            mode: policy.mode,
            mounts,
            landlock: LandlockPlan {
                read_roots: vec!["/".to_string()],
                write_roots,
                read_only_overrides,
            },
            network: if policy.network {
                NetworkPosture::Inherit
            } else {
                NetworkPosture::Unshare
            },
            limits: ResolvedLimits::from(&policy.limits),
            preload,
            cwd: policy.cwd.clone(),
        }
    }
}

/// The mounts that end up writable: the bound roots and the scratch tmpfs, and nothing
/// else. `Plan::compile` derives the Landlock write set from this so the two layers are
/// congruent by construction rather than by review.
fn writable_mount_paths(mounts: &[MountOp]) -> Vec<String> {
    let mut paths: Vec<String> = mounts
        .iter()
        .filter_map(|op| match op {
            MountOp::BindWritable { path } | MountOp::Tmpfs { path } => Some(path.clone()),
            _ => None,
        })
        .collect();
    paths.sort();
    paths
}

/// Shallowest first, then lexicographic. A nested bind must be applied after the bind it
/// sits inside, or it is applied to a directory that is about to be shadowed.
fn sort_shallowest_first(paths: &mut [String]) {
    paths.sort_by(|a, b| depth(a).cmp(&depth(b)).then_with(|| a.cmp(b)));
}

fn depth(path: &str) -> usize {
    path.trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .count()
}

/// Whether `path` is `root` or lies beneath it. Component-wise, so `/ws-extra` is not
/// inside `/ws` — the string-prefix version of this test is a classic sandbox hole.
pub fn inside(path: &str, root: &str) -> bool {
    let path = Path::new(path);
    let root = Path::new(root);
    path == root || path.starts_with(root)
}

fn inside_any(path: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| inside(path, root))
}

fn dedup_sorted(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Every directory beneath `roots` whose file name is one of `names`, bounded.
///
/// `symlink_metadata` throughout: a symlink named `.git` is not a directory to bind, and
/// following it would let a workspace point the sandbox's read-only bind at somewhere
/// outside the workspace entirely.
fn existing_denied_dirs(roots: &[String], names: &[String]) -> Vec<String> {
    if names.is_empty() {
        return Vec::new();
    }

    let mut found = BTreeSet::new();
    let mut visits = 0usize;

    for root in roots {
        let mut queue: Vec<(PathBuf, usize)> = vec![(PathBuf::from(root), 0)];

        while let Some((dir, dir_depth)) = queue.pop() {
            if dir_depth > MAX_SCAN_DEPTH || visits >= MAX_SCAN_VISITS {
                break;
            }

            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_unreadable) => continue,
            };

            // Sorted, because the plan is compared byte for byte in tests and readdir
            // order is a property of the filesystem, not of the policy.
            let mut children: Vec<PathBuf> = entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .collect();
            children.sort();

            for child in children {
                visits += 1;
                if visits >= MAX_SCAN_VISITS {
                    break;
                }

                let is_dir = matches!(
                    std::fs::symlink_metadata(&child),
                    Ok(meta) if meta.is_dir()
                );
                if !is_dir {
                    continue;
                }

                let name = child
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                if names
                    .iter()
                    .any(|denied| denied.eq_ignore_ascii_case(&name))
                {
                    // A denied directory is pinned read-only and not descended into:
                    // everything under it is covered by the bind at its root.
                    found.insert(child.to_string_lossy().to_string());
                } else {
                    queue.push((child, dir_depth + 1));
                }
            }
        }
    }

    found.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Policy;

    fn policy(json: &str) -> Policy {
        Policy::from_json(json).expect("valid policy")
    }

    fn sweep() -> MountOp {
        MountOp::ReadOnlySweep {
            keep_writable: vec!["/dev".to_string(), "/proc".to_string()],
        }
    }

    #[test]
    fn read_only_gets_a_scratch_tmpfs_and_a_sweep_and_nothing_else() {
        let plan = Plan::compile(&policy(r#"{"mode":"read_only","scratch":"/tmp/s"}"#), None);

        assert_eq!(
            plan.mounts,
            vec![
                MountOp::Tmpfs {
                    path: "/tmp/s".to_string()
                },
                sweep(),
            ]
        );
        assert_eq!(
            writable_mount_paths(&plan.mounts),
            vec!["/tmp/s".to_string()]
        );
        assert_eq!(plan.network, NetworkPosture::Unshare);
    }

    #[test]
    fn writable_roots_are_bound_before_the_sweep_that_narrows_everything_else() {
        // The order is the whole design: a bind taken after the sweep would be a bind of
        // an already-read-only mount, and there is no widening it back.
        let plan = Plan::compile(
            &policy(r#"{"mode":"workspace_write","scratch":"/tmp/s","writable":["/ws"]}"#),
            None,
        );

        assert_eq!(
            plan.mounts,
            vec![
                MountOp::BindWritable {
                    path: "/ws".to_string()
                },
                MountOp::Tmpfs {
                    path: "/tmp/s".to_string()
                },
                sweep(),
            ]
        );
    }

    #[test]
    fn protected_outside_a_writable_root_needs_no_bind() {
        // The divergence from the bwrap argv, pinned. bubblewrap emits `--ro-bind` for
        // every protected root; here the sweep has already made it read-only and a bind
        // would be a mount with no effect.
        let plan = Plan::compile(
            &policy(
                r#"{"mode":"workspace_write","scratch":"/tmp/s","writable":["/ws"],
                    "protected":["/srv/data"]}"#,
            ),
            None,
        );

        assert!(
            !plan
                .mounts
                .iter()
                .any(|op| matches!(op, MountOp::BindReadOnly { .. })),
            "{:?}",
            plan.mounts
        );
    }

    #[test]
    fn a_writable_worktree_under_a_protected_root_stays_writable() {
        // The D7 case the bwrap backend calls out: the node's data directory is
        // read-only, but a session's worktree inside it is not.
        let plan = Plan::compile(
            &policy(
                r#"{"mode":"workspace_write","scratch":"/tmp/s",
                    "writable":["/srv/data/worktrees/s1"],"protected":["/srv/data"]}"#,
            ),
            None,
        );

        assert_eq!(
            plan.mounts,
            vec![
                MountOp::BindWritable {
                    path: "/srv/data/worktrees/s1".to_string()
                },
                MountOp::Tmpfs {
                    path: "/tmp/s".to_string()
                },
                sweep(),
            ]
        );
        assert!(writable_mount_paths(&plan.mounts).contains(&"/srv/data/worktrees/s1".to_string()));
    }

    #[test]
    fn a_protected_root_nested_inside_a_writable_root_is_pinned_back() {
        let plan = Plan::compile(
            &policy(
                r#"{"mode":"workspace_write","scratch":"/tmp/s","writable":["/ws"],
                    "protected":["/ws/.config/ouroboros"]}"#,
            ),
            None,
        );

        assert_eq!(
            plan.mounts.last(),
            Some(&MountOp::BindReadOnly {
                path: "/ws/.config/ouroboros".to_string(),
                why: ReadOnlyReason::ProtectedRoot,
            })
        );
    }

    #[test]
    fn inside_is_component_wise_not_a_string_prefix() {
        assert!(inside("/ws", "/ws"));
        assert!(inside("/ws/a/b", "/ws"));
        // The hole this exists to avoid.
        assert!(!inside("/ws-extra", "/ws"));
        assert!(!inside("/wsx", "/ws"));
    }

    #[test]
    fn nested_binds_are_applied_shallowest_first() {
        let plan = Plan::compile(
            &policy(
                r#"{"mode":"workspace_write","scratch":"/tmp/s",
                    "writable":["/a/b/c","/a"]}"#,
            ),
            None,
        );

        assert_eq!(
            &plan.mounts[..2],
            &[
                MountOp::BindWritable {
                    path: "/a".to_string()
                },
                MountOp::BindWritable {
                    path: "/a/b/c".to_string()
                },
            ]
        );
    }

    #[test]
    fn landlock_is_congruent_with_the_mount_plan() {
        // The invariant that keeps every reachable denial an EROFS rather than an EACCES.
        let plan = Plan::compile(
            &policy(r#"{"mode":"workspace_write","scratch":"/tmp/s","writable":["/ws"]}"#),
            None,
        );

        let mut mount_writable = writable_mount_paths(&plan.mounts);
        mount_writable.extend(KEEP_WRITABLE.iter().map(|s| (*s).to_string()));
        mount_writable.sort();

        assert_eq!(plan.landlock.write_roots, mount_writable);
        assert_eq!(plan.landlock.read_roots, vec!["/".to_string()]);
    }

    #[test]
    fn network_follows_the_policy_and_nothing_else() {
        let on = Plan::compile(
            &policy(r#"{"mode":"read_only","scratch":"/tmp/s","network":true}"#),
            None,
        );
        let off = Plan::compile(&policy(r#"{"mode":"read_only","scratch":"/tmp/s"}"#), None);

        assert_eq!(on.network, NetworkPosture::Inherit);
        assert_eq!(off.network, NetworkPosture::Unshare);
        // Neither posture changes the filesystem plan: the two halves of the sandbox are
        // independent, which is what lets an operator turn the network on without
        // widening anything else.
        assert_eq!(on.mounts, off.mounts);
        assert_eq!(on.landlock, off.landlock);
    }

    #[test]
    fn the_preload_filter_is_carried_only_when_there_is_a_library_and_a_name() {
        let with_names =
            policy(r#"{"mode":"workspace_write","scratch":"/tmp/s","denied_names":[".git"]}"#);
        let without_names = policy(r#"{"mode":"workspace_write","scratch":"/tmp/s"}"#);

        assert_eq!(
            Plan::compile(&with_names, Some("/priv/libouro_fs_filter.so")).preload,
            Some(PreloadFilter {
                library: "/priv/libouro_fs_filter.so".to_string(),
                denied_names: vec![".git".to_string()],
            })
        );
        assert_eq!(Plan::compile(&with_names, None).preload, None);
        assert_eq!(
            Plan::compile(&without_names, Some("/priv/libouro_fs_filter.so")).preload,
            None
        );
    }

    #[test]
    fn core_dumps_default_to_off_and_named_limits_are_carried() {
        let plan = Plan::compile(
            &policy(
                r#"{"mode":"read_only","scratch":"/tmp/s",
                    "limits":{"max_processes":64,"cpu_seconds":600}}"#,
            ),
            None,
        );
        assert_eq!(
            plan.limits,
            ResolvedLimits {
                max_processes: Some(64),
                max_file_bytes: None,
                cpu_seconds: Some(600),
                core_bytes: 0,
            }
        );
    }

    // ---------------------------------------------------------------- the fs walk

    struct TempTree(PathBuf);

    impl TempTree {
        fn new(tag: &str) -> TempTree {
            let base = std::env::temp_dir().join(format!(
                "ouro-sandbox-plan-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&base).unwrap();
            TempTree(base)
        }

        fn dir(&self, rel: &str) -> PathBuf {
            let path = self.0.join(rel);
            std::fs::create_dir_all(&path).unwrap();
            path
        }

        fn path(&self) -> String {
            self.0.to_string_lossy().to_string()
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn read_only_paths(plan: &Plan, reason: ReadOnlyReason) -> Vec<String> {
        plan.mounts
            .iter()
            .filter_map(|op| match op {
                MountOp::BindReadOnly { path, why } if *why == reason => Some(path.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn an_existing_git_directory_at_the_root_is_pinned_read_only() {
        let tree = TempTree::new("git-root");
        let git = tree.dir(".git");

        let plan = Plan::compile(
            &policy(&format!(
                r#"{{"mode":"workspace_write","scratch":"/tmp/s","writable":["{}"],
                     "denied_names":[".git",".ouroboros"]}}"#,
                tree.path()
            )),
            None,
        );

        assert_eq!(
            read_only_paths(&plan, ReadOnlyReason::DeniedName),
            vec![git.to_string_lossy().to_string()]
        );
    }

    #[test]
    fn a_vendored_dependencys_git_directory_is_found_too() {
        // Exactly the case the bwrap backend enumerates: no path regex, so a bind per
        // directory, and a nested repository is as much a repository as the top one.
        let tree = TempTree::new("nested");
        tree.dir(".git");
        let nested = tree.dir("deps/foo/.git");

        let plan = Plan::compile(
            &policy(&format!(
                r#"{{"mode":"workspace_write","scratch":"/tmp/s","writable":["{}"],
                     "denied_names":[".git"]}}"#,
                tree.path()
            )),
            None,
        );

        let found = read_only_paths(&plan, ReadOnlyReason::DeniedName);
        assert!(
            found.contains(&nested.to_string_lossy().to_string()),
            "{found:?}"
        );
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn a_denied_directory_is_not_descended_into() {
        // `.git/modules/x/.git` would otherwise be a second bind for no benefit: the bind
        // at `.git` already covers everything beneath it.
        let tree = TempTree::new("no-descend");
        tree.dir(".git/modules/x/.git");

        let plan = Plan::compile(
            &policy(&format!(
                r#"{{"mode":"workspace_write","scratch":"/tmp/s","writable":["{}"],
                     "denied_names":[".git"]}}"#,
                tree.path()
            )),
            None,
        );

        assert_eq!(read_only_paths(&plan, ReadOnlyReason::DeniedName).len(), 1);
    }

    #[test]
    fn a_symlink_named_git_is_not_treated_as_a_directory_to_bind() {
        let tree = TempTree::new("symlink");
        let outside = tree.dir("outside");
        let link = tree.0.join("work/.git");
        std::fs::create_dir_all(tree.0.join("work")).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let plan = Plan::compile(
            &policy(&format!(
                r#"{{"mode":"workspace_write","scratch":"/tmp/s","writable":["{}"],
                     "denied_names":[".git"]}}"#,
                tree.path()
            )),
            None,
        );

        // Following it would have pointed a read-only bind at `outside`, which is not what
        // the policy said.
        assert!(
            !read_only_paths(&plan, ReadOnlyReason::DeniedName)
                .contains(&link.to_string_lossy().to_string()),
            "{plan:?}"
        );
    }

    #[test]
    fn the_walk_matches_denied_names_case_insensitively() {
        // `fs_filter.c` compares case-insensitively, and a case-insensitive filesystem
        // would otherwise let `.GIT` through the enumerating layer while the preload
        // layer still caught it — two layers disagreeing about the same policy.
        let tree = TempTree::new("case");
        let upper = tree.dir(".GIT");

        let plan = Plan::compile(
            &policy(&format!(
                r#"{{"mode":"workspace_write","scratch":"/tmp/s","writable":["{}"],
                     "denied_names":[".git"]}}"#,
                tree.path()
            )),
            None,
        );

        assert_eq!(
            read_only_paths(&plan, ReadOnlyReason::DeniedName),
            vec![upper.to_string_lossy().to_string()]
        );
    }

    #[test]
    fn read_only_overrides_mirror_every_read_only_bind() {
        let tree = TempTree::new("overrides");
        let git = tree.dir(".git");

        let plan = Plan::compile(
            &policy(&format!(
                r#"{{"mode":"workspace_write","scratch":"/tmp/s","writable":["{}"],
                     "denied_names":[".git"]}}"#,
                tree.path()
            )),
            None,
        );

        assert_eq!(
            plan.landlock.read_only_overrides,
            vec![git.to_string_lossy().to_string()]
        );
    }

    #[test]
    fn an_escalated_policy_carries_only_the_ouroboros_fence() {
        // The Elixir side decides which names survive an escalation; this asserts the
        // helper honours the shorter list rather than re-imposing its own.
        let tree = TempTree::new("escalated");
        tree.dir(".git");
        let ouro = tree.dir(".ouroboros");

        let plan = Plan::compile(
            &policy(&format!(
                r#"{{"mode":"workspace_write_escalated","scratch":"/tmp/s","writable":["{}"],
                     "denied_names":[".ouroboros"]}}"#,
                tree.path()
            )),
            None,
        );

        assert_eq!(
            read_only_paths(&plan, ReadOnlyReason::DeniedName),
            vec![ouro.to_string_lossy().to_string()]
        );
    }
}
