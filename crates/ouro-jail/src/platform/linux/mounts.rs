//! The mount plan: grants, staged hand-offs, pins, placeholders and the
//! mount table read back (§9.1, §13.2).

use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::policy::{EnvValue, PathRef, PolicySnapshot, ProfileName, ProtectedCoverage, RootToken};
use crate::records::{AppliedMount, ErrorCode, ErrorStage, JailError, NativeString, Remediation};

use super::bwrap::{self, BwrapPlan, Placeholder, PlaceholderSet};
use super::exec::{self};
use super::fs as jfs;
use super::platform::{PINNED_FD_BASE, error, preparing};

/// Whether `path` is one of the device nodes a contained run may bind
/// individually (issue draft 15): the NVIDIA class an ML workload needs —
/// `nvidia[0-9]*`, `nvidiactl`, `nvidia-uvm`, `nvidia-uvm-tools`,
/// `nvidia-modeset` — directly under `/dev`, and really a character device.
/// Anything else under `/dev` keeps the §9.1 pseudo-filesystem refusal:
/// `/dev/kvm`, `/dev/fuse` and devtmpfs itself are host surfaces this
/// allowlist does not vouch for.
pub(crate) fn is_allowed_device_node(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    if path.parent() != Some(Path::new("/dev")) {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let named = matches!(
        name,
        "nvidiactl" | "nvidia-uvm" | "nvidia-uvm-tools" | "nvidia-modeset"
    ) || name
        .strip_prefix("nvidia")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()));
    named
        && std::fs::metadata(path)
            .map(|meta| meta.file_type().is_char_device())
            .unwrap_or(false)
}

/// The coverage the plan actually obtained, derived from the walk.
///
/// `existing_and_root` means every protected segment that existed at launch is
/// covered, plus the root-level literals. The walk earns that claim only if it
/// finished inside its bounds and skipped no protected name: a `.git` that was
/// a symlink is not followed and not covered, so a scan that met one has not
/// covered everything that existed and says `none` instead of overstating.
/// A segment created later, deeper in the tree, is outside the claim either
/// way (north-star §4.4).
// Vendor state is not a scanned root
/// The claim covers the scanned writable roots (the workspace, scratch and
/// operator `--rw` grants). Vendor state is attempt-private, removed at
/// settlement and never scanned, so it is outside the claim: a protected name
/// the child creates there protects nothing and is claimed by nothing.
pub(super) fn scan_coverage(scan: &jfs::ProtectedScan) -> String {
    let within_bounds = scan.entries_seen <= jfs::ScanLimits::DEFAULT.max_entries
        && scan.max_depth_seen <= jfs::ScanLimits::DEFAULT.max_depth;
    if within_bounds && scan.skipped_symlinks.is_empty() {
        "existing_and_root".to_owned()
    } else {
        "none".to_owned()
    }
}

/// The protected names the walk would not follow, as workspace-relative
/// strings for the receipt.
pub(super) fn skipped_protected_names(scan: &jfs::ProtectedScan) -> Vec<String> {
    scan.skipped_symlinks
        .iter()
        .filter_map(|path| path.strip_prefix(&scan.root).ok())
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}

/// The most rows a receipt's mount table records: the receipt schema's
/// `maxItems` for `applied.filesystem.mounts`. A boundary with more is
/// refused rather than recorded in part: a shortened table would still read
/// as the child's whole view (§13.2).
pub(super) const MOUNT_TABLE_ROWS_MAX: usize = 1024;

/// Refuses, before anything is spawned (and before the protected segments are
/// pinned), a plan whose mount table no receipt can record. Every protected
/// segment the walk found, and every placeholder, is one read-only bind, so a
/// workspace holding about a thousand `.git` directories passes the bound on
/// its own: a configuration to narrow, not a host to repair. The count is the
/// plan's lower bound ([`BwrapPlan::mount_rows_at_least`]) plus the `pending`
/// binds not yet in the plan, plus the `hidden` row of each protected name
/// the walk would not follow; `protected` is how many segments and
/// placeholders there are in all. [`recordable_mounts`] still refuses what
/// the host's own mounts add after the spawn.
pub(super) fn refuse_unrecordable_mounts(
    plan: &BwrapPlan,
    pending: usize,
    protected: usize,
    hidden: usize,
) -> Result<(), JailError> {
    let rows = plan.mount_rows_at_least() + pending + hidden;
    if rows <= MOUNT_TABLE_ROWS_MAX {
        return Ok(());
    }
    Err(error(
        ErrorCode::InvalidConfig,
        ErrorStage::Preparing,
        Remediation::Configuration,
        format!(
            "the writable roots (workspace, scratch and read-write grants) hold {} protected \
             segments, each bound read-only, so the boundary would hold at least {rows} mounts, \
             more than the {MOUNT_TABLE_ROWS_MAX} a receipt's mount table records; run over a \
             narrower workspace",
            protected + hidden
        ),
    ))
}

/// Descriptors the boundary opens beside its mount sources before the spawn
/// (pipes, the backend's pidfd, the status and argument channels).
pub(super) const MOUNT_DESCRIPTOR_HEADROOM: u64 = 64;

/// Makes room for `needed` more descriptors before they are opened, raising
/// the soft `RLIMIT_NOFILE` to the hard limit when the soft one is short
/// (only this process and its children, within what the operator allows).
/// A workspace whose mounts need more than even the hard limit allows is
/// refused as a configuration naming the count and the limits, never left
/// to fail half-way with `EMFILE`.
///
/// # Errors
/// That refusal, or a limit that cannot be read.
pub(super) fn reserve_mount_descriptors(needed: usize, protected: usize) -> Result<(), JailError> {
    let unreadable = |err: std::io::Error| {
        preparing(
            ErrorCode::BackendUnavailable,
            format!("the descriptor limit cannot be read: {err}"),
        )
    };
    let needed = u64::try_from(needed)
        .unwrap_or(u64::MAX)
        .saturating_add(MOUNT_DESCRIPTOR_HEADROOM);
    let open = || {
        crate::proxy::open_descriptor_count()
            .map(|open| u64::try_from(open).unwrap_or(u64::MAX))
            .map_err(unreadable)
    };
    let (soft, hard) = crate::proxy::nofile_limits().map_err(unreadable)?;
    if descriptor_shortfall(needed, open()?, soft, hard, protected).is_none() {
        return Ok(());
    }
    let (soft, hard) = crate::proxy::raise_nofile_soft_to_hard().map_err(unreadable)?;
    descriptor_shortfall(needed, open()?, soft, hard, protected).map_or(Ok(()), Err)
}

/// The refusal for `needed` more descriptors with `open` already open under
/// the `soft` and `hard` limits, or `None` when they fit.
pub(super) fn descriptor_shortfall(
    needed: u64,
    open: u64,
    soft: u64,
    hard: u64,
    protected: usize,
) -> Option<JailError> {
    (open.saturating_add(needed) > soft).then(|| {
        error(
            ErrorCode::InvalidConfig,
            ErrorStage::Preparing,
            Remediation::Configuration,
            format!(
                "binding the {protected} protected segments and the other mounts read-only takes \
                 {needed} more descriptors with {open} already open, more than RLIMIT_NOFILE \
                 allows (soft {soft}, hard {hard}); raise the limit or run over a narrower \
                 workspace"
            ),
        )
    })
}

/// The rows a receipt records, whole or not at all (§13.2). The plan's own
/// rows were bounded before the spawn ([`refuse_unrecordable_mounts`]); what
/// can still pass the bound here is what the host mounted beneath a path
/// the plan binds, since each bind brings those mounts along.
///
/// # Errors
/// A configuration refusal naming the count and the bound.
pub(super) fn recordable_mounts(mounts: Vec<AppliedMount>) -> Result<Vec<AppliedMount>, JailError> {
    if mounts.len() <= MOUNT_TABLE_ROWS_MAX {
        return Ok(mounts);
    }
    Err(error(
        ErrorCode::InvalidConfig,
        ErrorStage::Preparing,
        Remediation::Configuration,
        format!(
            "the boundary holds {} mounts, more than the {MOUNT_TABLE_ROWS_MAX} a receipt's \
             mount table records: the plan's own and the host's mounts beneath the paths it \
             binds; run over a narrower workspace or fewer grants",
            mounts.len()
        ),
    ))
}

/// The mount table the launcher actually sees, from `/proc/<pid>/mountinfo`
/// read as bytes (P01.8): one mount point that is not UTF-8 must not cost
/// the whole table.
///
/// # Errors
/// The read's error, or [`parse_mount_table`]'s.
pub(super) fn read_mount_table(pid: libc::pid_t) -> std::io::Result<Vec<AppliedMount>> {
    parse_mount_table(&std::fs::read(format!("/proc/{pid}/mountinfo"))?)
}

/// The `(mount point, mode)` rows of a `mountinfo` file's bytes. Fields are
/// separated by single spaces; a space, tab, newline or backslash inside a
/// path is an octal escape, so splitting on the byte is exact.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidData`] for a row without a mount point and
/// options, or a mount point holding a NUL: the table is read whole or not
/// at all.
pub(super) fn parse_mount_table(raw: &[u8]) -> std::io::Result<Vec<AppliedMount>> {
    let invalid = |what: String| std::io::Error::new(std::io::ErrorKind::InvalidData, what);
    let mut out = Vec::new();
    for line in raw
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<&[u8]> = line
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect();
        let (Some(point), Some(options)) = (fields.get(4), fields.get(5)) else {
            return Err(invalid(format!(
                "a mountinfo row has {} fields, not a mount point and options",
                fields.len()
            )));
        };
        let mode = if options
            .split(|byte| *byte == b',')
            .any(|item| item == b"ro")
        {
            "ro"
        } else {
            "rw"
        };
        let native = NativeString::from_bytes(decode_mountinfo_path(point))
            .map_err(|_| invalid("a mount point holds a NUL byte".to_owned()))?;
        out.push(AppliedMount {
            path: native,
            mode: mode.to_owned(),
        });
    }
    Ok(out)
}

/// `mountinfo` escapes space, tab, newline and backslash as octal.
pub(super) fn decode_mountinfo_path(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && let Some(value) = std::str::from_utf8(&bytes[index + 1..index + 4])
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 8).ok())
        {
            out.push(value);
            index += 4;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// Where a contained plan's paths are: what it binds that the snapshot does
/// not name.
pub(crate) struct PlanPaths<'a> {
    /// The backend binary.
    pub(crate) bwrap: &'a Path,
    /// The workspace, on the host and inside alike.
    pub(crate) workspace: &'a Path,
    /// The scratch directory the child sees at `/tmp`.
    pub(crate) scratch: &'a Path,
    /// The jail binary bound at [`bwrap::JAIL_INSIDE_PATH`].
    pub(crate) jail_exe: &'a Path,
    /// The attempt's proxy directory, which `agent` binds.
    pub(crate) proxy_dir: Option<&'a Path>,
}

/// The plan a contained snapshot starts from: [`BwrapPlan::tool`] with what
/// the snapshot alone decides — the storage seal, the workspace's access,
/// the environment and, for `agent`, the proxy directory by descriptor and
/// the proxy variables. Preparation adds what needs the host and the
/// attempt (grants, masks, staged state, pins); the freeze renders the
/// built-in baselines through this same function.
///
/// # Errors
/// An environment binding that does not resolve, or `agent` without a
/// proxy directory.
pub(crate) fn plan_for(
    snapshot: &PolicySnapshot,
    paths: &PlanPaths,
) -> Result<BwrapPlan, JailError> {
    let mut bplan = BwrapPlan::tool(paths.workspace, paths.scratch, paths.jail_exe);
    bplan.bounded_storage = super::storage::requested(&snapshot.limits);
    let names_workspace = |references: &[PathRef]| {
        references.iter().any(|reference| {
            host_path_of(reference, paths.workspace, paths.scratch)
                .is_ok_and(|path| path == paths.workspace)
        })
    };
    bplan.workspace_access = if names_workspace(&snapshot.filesystem.read_only) {
        bwrap::WorkspaceAccess::ReadOnly
    } else if names_workspace(&snapshot.filesystem.read_write) {
        bwrap::WorkspaceAccess::Writable
    } else {
        bwrap::WorkspaceAccess::Hidden
    };
    bplan.bwrap = paths.bwrap.to_path_buf();
    bplan.env = environment_for(snapshot, paths.workspace)?;
    // §10 — the proxy socket in its registered directory, bound read-only
    // by descriptor, and the proxy variables.
    if snapshot.profile == ProfileName::Agent {
        let Some(proxy_dir) = paths.proxy_dir else {
            return Err(preparing(
                ErrorCode::MissingCapability,
                "the `agent` proxy could not be established: no proxy directory was prepared",
            ));
        };
        bplan.proxy_dir = Some(bwrap::Staged {
            host: proxy_dir.to_path_buf(),
            fd: super::agent::PROXY_DIR_FD,
        });
        for (name, value) in super::bridge::proxy_environment() {
            bplan
                .env
                .push((OsString::from(name), OsString::from(value)));
        }
    }
    Ok(bplan)
}

/// The environment bindings of the snapshot, resolved to the paths the child
/// will see.
pub(super) fn environment_for(
    snapshot: &PolicySnapshot,
    workspace: &Path,
) -> Result<Vec<(OsString, OsString)>, JailError> {
    let mut out = Vec::new();
    for binding in &snapshot.environment.bindings {
        let value = match &binding.value {
            EnvValue::Native(native) => OsString::from_vec(native.as_bytes().to_vec()),
            EnvValue::Path(reference) => resolve_path_ref(reference, workspace)?,
        };
        out.push((OsString::from(binding.name.clone()), value));
    }
    Ok(out)
}

pub(super) fn resolve_path_ref(
    reference: &PathRef,
    workspace: &Path,
) -> Result<OsString, JailError> {
    let base: PathBuf = match reference.root {
        RootToken::Workspace => workspace.to_path_buf(),
        RootToken::Scratch => PathBuf::from(bwrap::SCRATCH_INSIDE_PATH),
        RootToken::Host => PathBuf::from("/"),
        // Vendor state as the child sees it
        RootToken::VendorState => PathBuf::from(bwrap::VENDOR_STATE_INSIDE_PATH),
    };
    let suffix = reference.path.as_bytes();
    if suffix.is_empty() {
        return Ok(base.into_os_string());
    }
    Ok(base.join(OsStr::from_bytes(suffix)).into_os_string())
}

/// The host-side path a reference names, for binding as a mount source.
/// Unlike [`resolve_path_ref`], which produces the destination the child
/// sees, this resolves the scratch token to the supervisor's scratch
/// directory rather than `/tmp`.
pub(super) fn host_path_of(
    reference: &PathRef,
    workspace: &Path,
    scratch: &Path,
) -> Result<PathBuf, JailError> {
    match reference.root {
        RootToken::Workspace => Ok(join_suffix(workspace, reference)),
        RootToken::Scratch => Ok(join_suffix(scratch, reference)),
        RootToken::Host => Ok(join_suffix(Path::new("/"), reference)),
        // Vendor state has no host path a grant may bind; it
        // is bound only by the descriptor the supervisor created it with.
        RootToken::VendorState => Err(error(
            ErrorCode::InvalidConfig,
            ErrorStage::Preparing,
            Remediation::Configuration,
            "vendor state is bound by descriptor, never as a path grant".to_owned(),
        )),
    }
}

// Checking and duplicating the staged hand-off
/// The staged objects bubblewrap binds by descriptor.
pub(super) struct StagedMounts {
    /// A duplicate of the vendor-state directory descriptor.
    pub(super) vendor: Option<OwnedFd>,
    /// Each `bind_ro` source descriptor and its in-sandbox destination.
    pub(super) credentials: Vec<(OwnedFd, PathBuf)>,
}

/// Checks the supervisor's hand-off against the policy and duplicates it.
///
/// The policy is the authority: vendor state is bound exactly when the
/// snapshot has a managed vendor-state root, and exactly the snapshot's
/// `bind_ro` declarations are bound, each by a descriptor whose object is
/// still the regular file staging identified. Anything else refuses; nothing
/// is ever bound by path. `tool` and `build` never bind a credential (§6.1).
pub(super) fn staged_mounts(
    snapshot: &PolicySnapshot,
    handoff: Option<&crate::credentials::LaunchHandoff>,
) -> Result<StagedMounts, JailError> {
    use crate::state::anchored::{Kind, fstat};
    use std::os::fd::AsFd as _;
    let refuse = |message: &str| {
        error(
            ErrorCode::InvalidConfig,
            ErrorStage::Preparing,
            Remediation::Configuration,
            message.to_owned(),
        )
    };
    let declared: Vec<&crate::policy::CredentialDecl> = snapshot
        .launch
        .iter()
        .flat_map(|launch| launch.credentials.iter())
        .collect();
    if !declared.is_empty() && snapshot.profile != ProfileName::Agent {
        return Err(refuse(
            "only the `agent` profile stages launch credentials (jail-v1 §6.1)",
        ));
    }
    let wants_vendor = snapshot.roots.vendor_state.is_some();
    let Some(handoff) = handoff else {
        if wants_vendor || !declared.is_empty() {
            return Err(refuse(
                "the policy has managed vendor state or credentials but nothing was staged",
            ));
        }
        return Ok(StagedMounts {
            vendor: None,
            credentials: Vec::new(),
        });
    };
    let vendor = match (&handoff.vendor_state, wants_vendor) {
        (Some(vendor), true) => vendor,
        (None, false) if handoff.binds.is_empty() => {
            return Ok(StagedMounts {
                vendor: None,
                credentials: Vec::new(),
            });
        }
        _ => {
            return Err(refuse(
                "the staged vendor state does not match the policy's vendor-state root",
            ));
        }
    };
    let stat = fstat(vendor.fd.as_fd()).map_err(|err| refuse(&err.to_string()))?;
    if stat.kind != Kind::Directory || stat.identity() != vendor.identity {
        return Err(refuse(
            "the staged vendor-state descriptor is not the registered directory",
        ));
    }
    let binds: Vec<&&crate::policy::CredentialDecl> = declared
        .iter()
        .filter(|declaration| declaration.mode == crate::credentials::MODE_BIND_RO)
        .collect();
    if binds.len() != handoff.binds.len() {
        return Err(refuse(
            "the staged read-only credentials do not match the policy's declarations",
        ));
    }
    let mut credentials = Vec::with_capacity(binds.len());
    for handle in &handoff.binds {
        if !binds
            .iter()
            .any(|declaration| declaration.id == handle.id && declaration.dest == handle.dest)
        {
            return Err(refuse(
                "a staged read-only credential is not one the policy declares",
            ));
        }
        let source = fstat(handle.fd.as_fd()).map_err(|err| refuse(&err.to_string()))?;
        if source.kind != Kind::Regular || source.identity() != handle.identity {
            return Err(refuse(
                "a staged read-only credential descriptor is not the object staging examined",
            ));
        }
        let destination = Path::new(bwrap::VENDOR_STATE_INSIDE_PATH)
            .join(OsStr::from_bytes(handle.dest.as_bytes()));
        let duplicate = handle
            .fd
            .try_clone()
            .map_err(|err| refuse(&err.to_string()))?;
        credentials.push((duplicate, destination));
    }
    let vendor = vendor
        .fd
        .try_clone()
        .map_err(|err| refuse(&err.to_string()))?;
    Ok(StagedMounts {
        vendor: Some(vendor),
        credentials,
    })
}

pub(super) type MountPreparation = (
    jfs::ProtectedScan,
    Vec<jfs::PinnedPath>,
    Vec<(OwnedFd, RawFd)>,
    PlaceholderSet,
);

/// `OURO_JAIL_TEST_MOUNT_SWAP=<dir>`: a test seam (J5-B2) that opens a
/// deterministic window at the §9.1 mount handoff. When the variable names a
/// directory, the supervisor writes `<dir>/pinned` once every mount source has
/// been pinned and then waits (bounded, 10 s) for `<dir>/go` before running the
/// handoff verification. A test replaces a pinned object in that window to
/// prove the verification refuses the replacement (F04 source-identity swap).
///
/// Test-only. It can only delay the verification that is already there — never
/// widen anything — and, like every `OURO_JAIL_TEST_*` variable, it is recorded
/// in jail state and in every receipt with native details
/// (`state::persist::test_seams`, S9). A value that is not a usable directory
/// makes the write and the poll no-ops, so a stray setting cannot hang a run.
pub const MOUNT_SWAP_SEAM: &str = "OURO_JAIL_TEST_MOUNT_SWAP";

pub(super) fn mount_swap_rendezvous() {
    let Some(dir) = std::env::var_os(MOUNT_SWAP_SEAM) else {
        return;
    };
    let dir = PathBuf::from(dir);
    if std::fs::write(dir.join("pinned"), b"1").is_err() {
        return;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !dir.join("go").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
}

// §9.1 pseudo-filesystem guard
/// Refuses any operator grant in `binds` whose resolved source exposes host
/// `/proc`, `/sys`, cgroupfs, devtmpfs or the `/run` runtime tree (jail-v1
/// §9.1), keyed by `key` (`filesystem.read_only` or `filesystem.read_write`).
/// A policy refusal (`policy_widening`, remediation `configuration`) before
/// any mount; a mount table that cannot be read refuses too (`host_setup`),
/// since without it no grant can be shown to be clear.
pub(crate) fn refuse_pseudo_fs_grants(
    binds: &[(PathBuf, PathBuf)],
    key: &str,
) -> Result<(), JailError> {
    if binds.is_empty() {
        return Ok(());
    }
    refuse_pseudo_fs_grants_among(binds, key, pseudo_fs_mount_points())
}

/// [`refuse_pseudo_fs_grants`] against a given read of the mount points.
pub(super) fn refuse_pseudo_fs_grants_among(
    binds: &[(PathBuf, PathBuf)],
    key: &str,
    mounts: std::io::Result<Vec<PathBuf>>,
) -> Result<(), JailError> {
    let mounts = mounts.map_err(|err| {
        error(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::HostSetup,
            format!(
                "this process's mount table cannot be read, so no grant can be shown to stay \
                 clear of host /proc, /sys, cgroupfs, devtmpfs and the /run runtime tree: {err}"
            ),
        )
        .with_key_path(key)
    })?;
    for (source, _destination) in binds {
        // Issue draft 15: an allowlisted device node is exactly the narrow
        // exception — one character device under /dev, never devtmpfs.
        if is_allowed_device_node(source) {
            continue;
        }
        // The check follows symlinks to the real object (`--ro <link>` where
        // the link resolves onto a pseudo filesystem must refuse); the later
        // pin opens with RESOLVE_NO_SYMLINKS for race safety.
        let resolved = std::fs::canonicalize(source).unwrap_or_else(|_| source.clone());
        let on_pseudo = source_on_pseudo_fs(&resolved);
        if crate::policy::grant_exposes_pseudo_fs(&resolved, on_pseudo, &mounts) {
            return Err(error(
                ErrorCode::PolicyWidening,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!(
                    "the grant {} exposes host /proc, /sys, cgroupfs, devtmpfs or the /run \
                     runtime tree, which a contained profile never binds (jail-v1 §9.1)",
                    source.display()
                ),
            )
            .with_key_path(key));
        }
    }
    Ok(())
}

/// Whether the object at `resolved` is on a proc, sysfs, cgroup or devtmpfs
/// filesystem, by `fstatfs` on an `O_PATH` handle. A path that cannot be
/// opened is not treated as pseudo here; the ancestor check and the later pin
/// catch the rest.
pub(super) fn source_on_pseudo_fs(resolved: &Path) -> bool {
    let Ok(c) = super::sys::cstring_from_path(resolved) else {
        return false;
    };
    // SAFETY: `c` is a NUL-terminated path that outlives the call; O_PATH
    // acquires no I/O authority.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    // SAFETY: `fd` was just opened and is owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fd` is live; `buf` is a writable statfs the call fills.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), buf.as_mut_ptr()) } < 0 {
        return false;
    }
    // SAFETY: fstatfs returned 0, so the struct is initialised.
    let f_type = unsafe { buf.assume_init() }.f_type;
    crate::policy::is_pseudo_fs_magic(f_type)
}

/// Security 2026-09-27 (audit 3 A3): the mount points of every proc, sysfs or
/// cgroup (v1 or v2) mount, every devtmpfs mount, and every tmpfs mounted at
/// or beneath `/run` (the operator's runtime tree — `/run` alone, nowhere
/// else, so a tmpfs-backed `/tmp` or scratch stays grantable), from
/// `/proc/self/mountinfo` read as bytes. The fstype is the field after the
/// ` - ` separator.
///
/// # Errors
/// The read's error: an unreadable table is not one without such mounts.
pub(super) fn pseudo_fs_mount_points() -> std::io::Result<Vec<PathBuf>> {
    Ok(parse_pseudo_fs_mount_points(&std::fs::read(
        "/proc/self/mountinfo",
    )?))
}

/// The pseudo-filesystem mount points of a `mountinfo` file's bytes, `/run`
/// always among them.
pub(super) fn parse_pseudo_fs_mount_points(raw: &[u8]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for line in raw.split(|byte| *byte == b'\n') {
        let Some(separator) = line.windows(3).position(|w| w == b" - ") else {
            continue;
        };
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        let Some(point) = fields.get(4) else { continue };
        let fstype = line[separator + 3..]
            .split(|byte| *byte == b' ')
            .next()
            .unwrap_or_default();
        let point = decode_mountinfo_path(point);
        let matches = match fstype {
            b"proc" | b"sysfs" | b"cgroup" | b"cgroup2" | b"devtmpfs" => true,
            // `/run` and its submounts only: a tmpfs anywhere else is an
            // ordinary place for a grant (tests use /tmp tempdirs).
            b"tmpfs" => point == b"/run" || point.starts_with(b"/run/"),
            _ => false,
        };
        if matches {
            out.push(PathBuf::from(std::ffi::OsStr::from_bytes(&point)));
        }
    }
    // Security 2026-09-27 (audit 4 B7): the runtime tree is refused by its
    // path as well, not only by the tmpfs fstype — a host whose `/run` (or a
    // subtree of it) is not tmpfs would otherwise slip the fstype branch
    // above, and `grant_exposes_pseudo_fs` refuses an entry however the
    // overlap runs (ancestor, equal or beneath).
    if !out.iter().any(|point| point == Path::new("/run")) {
        out.push(PathBuf::from("/run"));
    }
    out
}

/// Security 2026-09-25 (audit F5): write the sanitized `/etc/resolv.conf`
/// the child will be bound, and return its path.
///
/// The host file's `search`/`domain` lines name the operator's networks;
/// they are host facts no grant covers, and nothing in the child's network
/// namespace can use the resolver anyway, so the copy keeps the nameservers
/// only, with numeric addresses, and drops all other directives. The file
/// lives in the attempt's private state, is created fresh with mode 0600,
/// and is removed with the attempt by the existing state cleanup.
///
/// # Errors
///
/// [`JailError`] (`state_write_failed` at preparing) when the attempt state
/// cannot hold the copy; a host `/etc/resolv.conf` that cannot be read
/// produces an empty resolver file, never the unsanitized host file.
pub(super) fn stage_sanitized_resolv_conf(
    attempt_dir: &Path,
) -> Result<(PathBuf, &'static str), JailError> {
    const SOURCE: &str = "/etc/resolv.conf";
    use std::io::Read as _;
    let mut bytes = Vec::new();
    let host = std::fs::File::open(SOURCE).and_then(|f| f.take(65537).read_to_end(&mut bytes));
    let (sanitized, status) = sanitize_resolv_conf(host.is_ok().then_some(bytes.as_slice()));
    let dest = attempt_dir.join("resolv.conf");
    let write = || -> std::io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&dest)?;
        file.write_all(sanitized.as_bytes())?;
        if !sanitized.ends_with('\n') {
            file.write_all(b"\n")?;
        }
        Ok(())
    };
    write().map_err(|error| {
        preparing(
            ErrorCode::StateWriteFailed,
            format!("the sanitized resolver view could not be staged: {error}"),
        )
    })?;
    Ok((dest, status))
}

pub(super) fn sanitize_resolv_conf(bytes: Option<&[u8]>) -> (String, &'static str) {
    let text = bytes
        .filter(|b| b.len() <= 65536)
        .and_then(|b| std::str::from_utf8(b).ok());
    let Some(text) = text else {
        return (String::new(), "failed_closed");
    };
    let mut sanitized = String::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() == Some("nameserver") {
            let Some(ip) = words
                .next()
                .and_then(|v| v.parse::<std::net::IpAddr>().ok())
            else {
                return (String::new(), "failed_closed");
            };
            sanitized.push_str(&format!("nameserver {ip}\n"));
        }
    }
    (sanitized, "nameservers_only")
}

/// Pin every source once, scan the pinned writable roots, then give each bind
/// its own descriptor. Bubblewrap validates the mounted inode against that fd.
pub(super) fn prepare_mounts(
    plan: &mut BwrapPlan,
    attempt_dir: &Path,
    names: &[&str],
    coverage: ProtectedCoverage,
) -> Result<MountPreparation, JailError> {
    use std::collections::BTreeMap;
    let failure = |err: std::io::Error| {
        preparing(
            ErrorCode::BackendUnavailable,
            format!("mount source pinning failed: {err}"),
        )
    };
    let mut pins = BTreeMap::<PathBuf, jfs::PinnedPath>::new();
    let mut roots: Vec<(PathBuf, PathBuf)> = plan
        .extra_rw_binds
        .iter()
        .chain(plan.extra_dev_binds.iter())
        .cloned()
        .collect();
    if plan.workspace_access == bwrap::WorkspaceAccess::Writable {
        roots.push((plan.workspace.clone(), plan.workspace.clone()));
    }
    roots.push((
        plan.scratch.clone(),
        PathBuf::from(bwrap::SCRATCH_INSIDE_PATH),
    ));
    roots.sort();
    roots.dedup();
    let mut aggregate = jfs::ProtectedScan {
        root: PathBuf::from("/"),
        directories: Vec::new(),
        segments: Vec::new(),
        skipped_symlinks: Vec::new(),
        root_literals: Vec::new(),
        entries_seen: 0,
        max_depth_seen: 0,
    };
    // Every writable root is scanned before anything in it is pinned, so the
    // mounts the scans add are counted against the receipt's bound, and the
    // descriptors their pins take are reserved, before one is opened.
    let mut scans = Vec::new();
    for (root_index, (source, destination)) in roots.iter().enumerate() {
        let pin = jfs::PinnedPath::open(source).map_err(failure)?;
        if !pin.is_dir().map_err(failure)? {
            pins.insert(source.clone(), pin);
            continue;
        }
        if coverage == ProtectedCoverage::None {
            pins.insert(source.clone(), pin);
            continue;
        }
        let seen_before = aggregate.entries_seen;
        let scan = jfs::scan_pinned(
            &pin,
            names,
            jfs::ScanLimits {
                max_entries: jfs::ScanLimits::DEFAULT
                    .max_entries
                    .saturating_sub(seen_before),
                ..jfs::ScanLimits::DEFAULT
            },
        )
        .map_err(|err| preparing(ErrorCode::MissingCapability, err.to_string()))?;
        pins.insert(source.clone(), pin);
        if coverage == ProtectedCoverage::ExistingAndRoot && !scan.skipped_symlinks.is_empty() {
            return Err(preparing(
                ErrorCode::MissingCapability,
                "existing_and_root coverage cannot cover protected symlinks",
            ));
        }
        aggregate.entries_seen += scan.entries_seen;
        scans.push((root_index, source, destination, seen_before, scan));
    }
    let segments: usize = scans.iter().map(|(.., scan)| scan.segments.len()).sum();
    let holders: usize = scans
        .iter()
        .map(|(.., scan)| scan.absent_root_literals().len())
        .sum();
    let hidden: usize = scans
        .iter()
        .map(|(.., scan)| scan.skipped_symlinks.len())
        .sum();
    refuse_unrecordable_mounts(
        plan,
        segments + holders,
        segments + holders + plan.placeholders.len(),
        hidden,
    )?;
    // A pin per segment; a placeholder holds its own handle and its holder.
    reserve_mount_descriptors(segments + 2 * holders, segments + holders)?;

    // Every refusal below drops the set, which removes what it created.
    let mut placeholders = PlaceholderSet::default();
    for (root_index, source, destination, seen_before, mut scan) in scans {
        for segment in &scan.segments {
            let pinned = jfs::PinnedPath::open(&segment.path).map_err(failure)?;
            if pinned.identity() != (segment.dev, segment.ino) {
                return Err(preparing(
                    ErrorCode::BackendUnavailable,
                    "a protected object changed between scan and pin",
                ));
            }
            pins.insert(segment.path.clone(), pinned);
            plan.extra_ro_binds.push((
                segment.path.clone(),
                destination.join(
                    segment
                        .path
                        .strip_prefix(source)
                        .expect("scan beneath root"),
                ),
            ));
        }
        for directory in &scan.directories {
            directory
                .verify()
                .map_err(|e| preparing(ErrorCode::MissingCapability, e.to_string()))?;
        }
        let added_placeholders = !scan.absent_root_literals().is_empty();
        for literal in scan.absent_root_literals() {
            let holders = attempt_dir.join("placeholders");
            crate::state::create_private_dir(&holders)?;
            let holder = holders.join(format!("holder-{root_index}-{}", placeholders.len()));
            let placeholder = Placeholder::create(&holder, &source.join(&literal))
                .map_err(|err| preparing(ErrorCode::BackendUnavailable, err.to_string()))?;
            let mut mount = placeholder.mount().clone();
            mount.destination = destination.join(&literal);
            plan.placeholders.push(mount);
            placeholders.push(placeholder);
        }
        // Our placeholders mutate the root. Re-scan, rather than merely
        // accepting a new timestamp that could hide a concurrent mutation.
        if added_placeholders {
            let checked = jfs::scan_pinned(
                &pins[source],
                names,
                jfs::ScanLimits {
                    // The placeholders this pass just created add one
                    // entry each inside the root; the re-scan must be
                    // able to see them without tripping the bound a
                    // first scan at the cap would trip.
                    max_entries: jfs::ScanLimits::DEFAULT
                        .max_entries
                        .saturating_sub(seen_before)
                        .saturating_add(scan.absent_root_literals().len()),
                    ..jfs::ScanLimits::DEFAULT
                },
            )
            .map_err(|e| preparing(ErrorCode::MissingCapability, e.to_string()))?;
            let expected: std::collections::BTreeSet<_> = scan
                .absent_root_literals()
                .iter()
                .map(|name| source.join(name))
                .collect();
            let remaining: std::collections::BTreeSet<_> = checked
                .segments
                .iter()
                .filter(|s| !expected.contains(&s.path))
                .map(|s| (&s.path, s.dev, s.ino))
                .collect();
            if remaining
                != scan
                    .segments
                    .iter()
                    .map(|s| (&s.path, s.dev, s.ino))
                    .collect()
                || checked
                    .skipped_symlinks
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    != scan.skipped_symlinks.iter().collect()
            {
                return Err(preparing(
                    ErrorCode::MissingCapability,
                    "protected paths changed while placeholders were prepared",
                ));
            }
            scan.directories = checked.directories;
        }
        aggregate.directories.extend(scan.directories);
        aggregate.max_depth_seen = aggregate.max_depth_seen.max(scan.max_depth_seen);
        aggregate.segments.extend(scan.segments);
        aggregate.skipped_symlinks.extend(scan.skipped_symlinks);
    }
    // Bind ancestors before descendants, and never expose a second writable
    // alias of a protected source after applying its protection.
    let mut fds = Vec::new();
    let mut rows = plan.mount_table();
    // One duplicate per row bubblewrap binds from a descriptor, and a pin
    // per source not pinned yet.
    let prepared = rows
        .iter()
        .filter(|row| row.kind.preparation() != bwrap::MountPreparation::Nothing)
        .count();
    let unpinned: std::collections::BTreeSet<&OsString> = rows
        .iter()
        .filter(|row| row.kind.preparation() == bwrap::MountPreparation::PinSource)
        .filter_map(|row| row.source.as_ref())
        .filter(|source| !pins.contains_key(Path::new(source)))
        .collect();
    reserve_mount_descriptors(
        prepared + unpinned.len(),
        aggregate.segments.len() + plan.placeholders.len(),
    )?;
    for row in &mut rows {
        let source = match row.kind.preparation() {
            bwrap::MountPreparation::Nothing => continue,
            bwrap::MountPreparation::EmptyData => {
                // EOF supplies an empty file to bubblewrap; no host content
                // or writable source descriptor is exposed to the child.
                let (reader, writer) = exec::pipe().map_err(failure)?;
                drop(writer);
                let target = PINNED_FD_BASE + fds.len() as RawFd;
                fds.push((reader, target));
                row.fd = Some(target);
                continue;
            }
            bwrap::MountPreparation::PinSource => match &row.source {
                Some(source) => PathBuf::from(source),
                None => {
                    return Err(preparing(
                        ErrorCode::InternalError,
                        format!("a {} mount has no source to pin", row.kind),
                    ));
                }
            },
        };
        if !pins.contains_key(&source) {
            // Distribution-owned runtime aliases may be resolved here;
            // workspace/operator sources must never follow symlinks.
            let runtime = plan.etc_paths.contains(&source)
                || plan
                    .roots
                    .iter()
                    .any(|r| matches!(r, jfs::RootSpec::RoBind(p) if p == &source))
                || source == plan.jail_exe;
            let path = if runtime {
                std::fs::canonicalize(&source).map_err(failure)?
            } else {
                source.clone()
            };
            pins.insert(
                source.clone(),
                jfs::PinnedPath::open(&path).map_err(failure)?,
            );
        }
        let target = PINNED_FD_BASE + fds.len() as RawFd;
        fds.push((pins[&source].try_clone_fd().map_err(failure)?, target));
        row.fd = Some(target);
    }
    plan.set_mount_descriptors(rows)
        .map_err(|err| preparing(ErrorCode::InternalError, err.to_string()))?;
    Ok((aggregate, pins.into_values().collect(), fds, placeholders))
}

pub(super) fn absent_runtime_candidate(reference: &PathRef, host: &Path) -> bool {
    reference.root == RootToken::Host
        && crate::profiles::LINUX_RUNTIME_ROOTS
            .iter()
            .any(|candidate| host == Path::new(candidate))
        && std::fs::metadata(host).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// Join a root with a reference's native-byte suffix.
pub(super) fn join_suffix(base: &Path, reference: &PathRef) -> PathBuf {
    let suffix = reference.path.as_bytes();
    if suffix.is_empty() {
        return base.to_path_buf();
    }
    base.join(OsStr::from_bytes(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::Os;

    use super::super::exec::FdMap;
    use super::super::identity;

    /// Issue draft 15: only the NVIDIA class under `/dev` is allowlisted,
    /// and only as a real character device.
    #[test]
    fn only_nvidia_device_nodes_are_allowlisted() {
        for refused in [
            "/dev/kvm",
            "/dev/fuse",
            "/dev/nvidia0/inner",
            "/dev/nvidia",
            "/dev/nvidia-uvm-extra",
            "/usr/bin/nvidia0",
            "/dev",
        ] {
            assert!(
                !is_allowed_device_node(Path::new(refused)),
                "{refused} is not an allowlisted device node"
            );
        }
        // On a GPU host the nodes themselves qualify; where they are absent
        // the metadata check keeps the answer false.
        let on_gpu_host = Path::new("/dev/nvidiactl").exists();
        assert_eq!(
            is_allowed_device_node(Path::new("/dev/nvidiactl")),
            on_gpu_host
        );
    }

    /// Security 2026-09-27 (audit 4 B7): the runtime tree is in the refused
    /// set by its path, whatever fstype carries it — a host whose `/run` is
    /// not tmpfs would otherwise slip the fstype branch.
    #[test]
    fn audit4_run_is_refused_by_path_whatever_its_fstype() {
        for mounts in [
            super::pseudo_fs_mount_points().unwrap(),
            super::parse_pseudo_fs_mount_points(b"22 1 0:1 / / rw - ext4 /dev/vda1 rw\n"),
        ] {
            assert!(
                mounts
                    .iter()
                    .any(|point| point == std::path::Path::new("/run")),
                "the /run entry is unconditional: {mounts:?}"
            );
        }
    }

    /// A mount table that cannot be read is no proof that a grant stays
    /// clear of the pseudo filesystems: the guard refuses, it never passes.
    #[test]
    fn an_unreadable_mount_table_refuses_every_grant() {
        let grant = [(PathBuf::from("/srv/data"), PathBuf::from("/srv/data"))];
        let error = super::refuse_pseudo_fs_grants_among(
            &grant,
            "filesystem.read_only",
            Err(std::io::Error::from_raw_os_error(libc::EACCES)),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable);
        assert!(
            error.message.contains("mount table cannot be read"),
            "{}",
            error.message
        );
        assert!(
            super::refuse_pseudo_fs_grants_among(&grant, "filesystem.read_only", Ok(Vec::new()))
                .is_ok()
        );
    }

    #[test]
    fn resolver_sanitizer_never_falls_back_to_host_bytes() {
        for input in [
            None,
            Some(b"nameserver invalid".as_slice()),
            Some(b"nameserver 1.1.1.1\n\xff".as_slice()),
        ] {
            assert_eq!(
                super::sanitize_resolv_conf(input),
                (String::new(), "failed_closed")
            );
        }
        assert_eq!(
            super::sanitize_resolv_conf(Some(&vec![b'x'; 65537])).1,
            "failed_closed"
        );
        assert_eq!(
            super::sanitize_resolv_conf(Some(
                b"search private.example\nnameserver 1.1.1.1 # comment\noptions edns0\n"
            )),
            ("nameserver 1.1.1.1\n".into(), "nameservers_only")
        );
    }

    fn mount_plan(root: &Path) -> BwrapPlan {
        for name in ["workspace", "scratch", "external", "attempt"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        let mut plan = BwrapPlan::tool(
            &root.join("workspace"),
            &root.join("scratch"),
            &std::env::current_exe().unwrap(),
        );
        plan.roots.clear();
        plan.etc_paths.clear();
        plan.extra_rw_binds
            .push((root.join("external"), root.join("external")));
        plan
    }

    #[test]
    fn all_writable_roots_are_scanned_and_every_bind_is_pinned() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut plan = mount_plan(root);
        for name in ["workspace", "scratch", "external"] {
            std::fs::create_dir(root.join(name).join(".git")).unwrap();
        }
        let (scan, _pins, fds, placeholders) = prepare_mounts(
            &mut plan,
            &root.join("attempt"),
            &jfs::PROTECTED_LITERALS,
            ProtectedCoverage::ExistingAndRoot,
        )
        .unwrap();
        assert_eq!(scan.segments.len(), 3);
        assert_eq!(placeholders.len(), 3);
        let rows = plan.mount_table();
        for dest in [
            root.join("workspace/.git"),
            root.join("external/.git"),
            PathBuf::from("/tmp/.git"),
        ] {
            assert!(
                rows.iter()
                    .any(|row| row.destination == dest && row.kind == bwrap::MountKind::RoBind)
            );
        }
        assert_eq!(
            fds.len(),
            rows.iter().filter(|row| row.source.is_some()).count()
        );
        for row in plan.mount_rows().unwrap() {
            if row.kind.preparation() == bwrap::MountPreparation::PinSource {
                assert!(row.fd.is_some(), "{row:?}");
            }
        }
        drop(placeholders);
    }

    #[test]
    fn a_missing_root_ouroboros_gets_a_real_placeholder_from_the_scan() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut plan = mount_plan(root);
        std::fs::create_dir(root.join("workspace/.git")).unwrap();
        let attempt = root.join("attempt");
        let (_scan, _pins, _fds, placeholders) = prepare_mounts(
            &mut plan,
            &attempt,
            &jfs::PROTECTED_LITERALS,
            ProtectedCoverage::ExistingAndRoot,
        )
        .unwrap();
        // The real scan/placeholder path: `prepare_mounts` creates the holder
        // under the attempt directory and the placeholder object at the root,
        // and the plan mounts it there. (The returned aggregate scan carries
        // segments, not per-root literal states — the placeholder count and
        // the mount row are the observable facts.)
        assert!(!placeholders.is_empty());
        let rows = plan.mount_table();
        let row = rows
            .iter()
            .find(|row| {
                row.kind == bwrap::MountKind::Placeholder
                    && row.destination == root.join("workspace/.ouroboros")
            })
            .expect("a placeholder mount for the absent workspace literal");
        assert!(
            Path::new(row.source.as_ref().expect("a holder source"))
                .starts_with(attempt.join("placeholders")),
            "the holder is not the attempt's placeholder directory: {row:?}"
        );
        assert!(
            root.join("workspace/.ouroboros").is_dir(),
            "the placeholder does not exist at the root"
        );
        drop(placeholders);
        assert!(
            !root.join("workspace/.ouroboros").exists(),
            "placeholder removal left the literal behind"
        );
    }

    /// The placeholders' holder is supervisor state, created through the
    /// state module's check (§6.2): under an ancestor anyone can replace
    /// entries in, it refuses, and leaves no placeholder behind.
    #[test]
    fn placeholder_holders_are_checked_like_all_supervisor_state() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let mut plan = mount_plan(&root);
        let open = root.join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let attempt = open.join("attempt");
        std::fs::create_dir(&attempt).unwrap();
        let Err(error) = prepare_mounts(
            &mut plan,
            &attempt,
            &jfs::PROTECTED_LITERALS,
            ProtectedCoverage::ExistingAndRoot,
        ) else {
            panic!("a holder under a world-writable ancestor refuses");
        };
        assert_eq!(error.code, ErrorCode::UnsafeStatePath, "{}", error.message);
        for literal in [".git", ".ouroboros"] {
            assert!(!root.join("workspace").join(literal).exists(), "{literal}");
        }
    }

    #[test]
    fn protected_symlinks_in_extra_roots_refuse_before_launch() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut plan = mount_plan(root);
        std::os::unix::fs::symlink("elsewhere", root.join("external/.git")).unwrap();
        assert!(
            prepare_mounts(
                &mut plan,
                &root.join("attempt"),
                &jfs::PROTECTED_LITERALS,
                ProtectedCoverage::ExistingAndRoot
            )
            .is_err()
        );
    }

    #[test]
    fn large_protected_sets_keep_descriptor_backed_sources() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut plan = mount_plan(root);
        for index in 0..240 {
            std::fs::create_dir_all(root.join(format!("workspace/repo-{index}/.git"))).unwrap();
        }
        let (_, _pins, fds, placeholders) = prepare_mounts(
            &mut plan,
            &root.join("attempt"),
            &jfs::PROTECTED_LITERALS,
            ProtectedCoverage::ExistingAndRoot,
        )
        .unwrap();
        assert!(fds.len() > 240);
        let mut map = FdMap::with_target_limit(PINNED_FD_BASE + fds.len() as RawFd);
        for (fd, target) in fds {
            map.add(fd, target).unwrap();
        }
        drop(placeholders);
    }

    #[test]
    fn mountinfo_paths_decode_their_octal_escapes() {
        assert_eq!(
            decode_mountinfo_path(b"/work/a\\040b"),
            b"/work/a b".to_vec()
        );
        assert_eq!(decode_mountinfo_path(b"/plain"), b"/plain".to_vec());
    }

    // P01.8
    #[test]
    fn a_mount_point_that_is_not_utf8_keeps_the_whole_table() {
        let raw: &[u8] = b"22 1 0:1 / / ro,nosuid - tmpfs tmpfs ro\n\
            23 22 0:2 / /work/sec\xffret rw,nosuid - tmpfs tmpfs rw\n\
            24 22 0:3 / /work/a\\040b ro - tmpfs tmpfs ro\n";
        let table = parse_mount_table(raw).unwrap();
        let rows: Vec<(Vec<u8>, &str)> = table
            .iter()
            .map(|mount| (mount.path.as_bytes().to_vec(), mount.mode.as_str()))
            .collect();
        assert_eq!(
            rows,
            vec![
                (b"/".to_vec(), "ro"),
                (b"/work/sec\xffret".to_vec(), "rw"),
                (b"/work/a b".to_vec(), "ro"),
            ]
        );
    }

    /// The table is read whole or not at all: a row the parser cannot read
    /// refuses, and so does a table with more rows than a receipt records,
    /// as a configuration to narrow rather than a host to repair.
    #[test]
    fn a_mount_table_is_never_recorded_in_part() {
        assert!(parse_mount_table(b"22 1 0:1 / / ro - tmpfs tmpfs ro\n\n").is_ok());
        assert!(parse_mount_table(b"22 1 0:1\n").is_err(), "a short row");
        assert!(parse_mount_table(b"22 1 0:1 / /a\\000b ro - tmpfs t ro\n").is_err());
        let row = |index: usize| format!("{index} 1 0:1 / /m{index} ro - tmpfs tmpfs ro\n");
        let full: String = (0..MOUNT_TABLE_ROWS_MAX).map(row).collect();
        let full = parse_mount_table(full.as_bytes()).unwrap();
        assert_eq!(full.len(), MOUNT_TABLE_ROWS_MAX);
        let mut over = full.clone();
        over.push(full[0].clone());
        assert_eq!(recordable_mounts(full).unwrap().len(), MOUNT_TABLE_ROWS_MAX);
        let error = recordable_mounts(over).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig);
        assert_eq!(error.remediation, Remediation::Configuration);
        assert!(error.message.contains("1025 mounts"), "{}", error.message);
    }

    /// A workspace with about a thousand protected segments passes the bound
    /// on the plan's own rows: refused before anything is spawned, as a
    /// configuration, naming the segments and the bound. A protected name the
    /// walk would not follow costs a `hidden` row and counts too.
    #[test]
    fn a_plan_past_the_receipt_mount_bound_refuses_before_the_spawn() {
        let mut plan = BwrapPlan::tool(
            Path::new("/work"),
            Path::new("/scratch"),
            Path::new("/opt/ouro-jail"),
        );
        let fixed = plan.mount_rows_at_least();
        // As `prepare_mounts` binds each segment the walk found.
        let protect = |plan: &mut BwrapPlan, count: usize| {
            plan.extra_ro_binds = (0..count)
                .map(|index| {
                    let path = PathBuf::from(format!("/work/r{index}/.git"));
                    (path.clone(), path)
                })
                .collect();
        };
        let at_bound = MOUNT_TABLE_ROWS_MAX - fixed;
        protect(&mut plan, at_bound);
        assert_eq!(plan.mount_rows_at_least(), MOUNT_TABLE_ROWS_MAX);
        super::refuse_unrecordable_mounts(&plan, 0, at_bound, 0).unwrap();
        let error = super::refuse_unrecordable_mounts(&plan, 0, at_bound, 1).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig);

        protect(&mut plan, 1100);
        let error = super::refuse_unrecordable_mounts(&plan, 0, 1100, 0).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig);
        assert_eq!(error.stage, ErrorStage::Preparing);
        assert_eq!(error.remediation, Remediation::Configuration);
        assert!(
            error.message.contains("hold 1100 protected segments")
                && error
                    .message
                    .contains(&format!("at least {} mounts", fixed + 1100))
                && error.message.contains("1024"),
            "{}",
            error.message
        );
    }

    /// Pinning a workspace's protected segments either fits the descriptor
    /// limit or is refused as a configuration naming the count and the
    /// limits, never left to fail with `EMFILE` as a host problem.
    #[test]
    fn a_descriptor_budget_that_does_not_fit_is_a_configuration() {
        assert!(super::descriptor_shortfall(900, 100, 1024, 1024, 890).is_none());
        let error = super::descriptor_shortfall(1900, 100, 1024, 1024, 990).unwrap();
        assert_eq!(error.code, ErrorCode::InvalidConfig);
        assert_eq!(error.stage, ErrorStage::Preparing);
        assert_eq!(error.remediation, Remediation::Configuration);
        assert!(
            error.message.contains("990 protected segments")
                && error.message.contains("1900 more descriptors")
                && error.message.contains("soft 1024, hard 1024"),
            "{}",
            error.message
        );
        // Within this process's own limit a modest budget is reserved.
        super::reserve_mount_descriptors(16, 1).unwrap();
    }

    #[test]
    fn an_unreadable_environment_is_not_an_empty_one() {
        // SAFETY: getpid takes no arguments and cannot fail.
        let own = unsafe { libc::getpid() };
        assert!(!identity::read_environment_names(own).unwrap().is_empty());
        // No process has this pid: pid_max is far below it.
        assert!(identity::read_environment_names(libc::pid_t::MAX).is_err());
        assert!(read_mount_table(libc::pid_t::MAX).is_err());
    }

    // The staged hand-off is checked against the policy
    fn launch_snapshot(profile: ProfileName, bind_ro: bool) -> PolicySnapshot {
        use crate::policy::{
            CredentialDecl, LaunchSnapshot, ResolveInputs, ScratchRoot, VendorStateRoot,
        };
        let inputs = ResolveInputs {
            platform: Os::Linux,
            base_profile: profile,
            policy_name: profile.as_str().to_owned(),
            baseline: crate::profiles::baseline(profile, Os::Linux, &|_| None),
            workspace: b"/work".to_vec(),
            scratch: ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        };
        let mut snapshot = crate::policy::resolve(&inputs).unwrap().snapshot;
        snapshot.roots.vendor_state = Some(VendorStateRoot::Managed);
        snapshot.launch = Some(LaunchSnapshot {
            state_var: None,
            home_is_state: false,
            state_subdirs: Vec::new(),
            credentials: if bind_ro {
                vec![CredentialDecl {
                    vault: None,
                    id: "c".to_owned(),
                    source: NativeString::Text("/src/c".to_owned()),
                    dest: NativeString::Text("c".to_owned()),
                    mode: "bind_ro".to_owned(),
                }]
            } else {
                Vec::new()
            },
        });
        snapshot
    }

    fn handoff(root: &std::path::Path, bind: bool) -> crate::credentials::LaunchHandoff {
        use crate::credentials::{BindHandle, LaunchHandoff, VendorStateHandle};
        use crate::state::anchored::{Dir, Name, fstat};
        use std::os::fd::AsFd as _;
        use std::sync::Arc;
        let dir = Dir::open_trusted(root).unwrap();
        let vendor = dir.mkdir_at(&Name::new(b"v").unwrap(), 0o700).unwrap();
        std::fs::write(root.join("c"), b"c").unwrap();
        let source = dir.open_path_at(&Name::new(b"c").unwrap()).unwrap();
        let source_identity = fstat(source.as_fd()).unwrap().identity();
        let vendor_identity = vendor.stat().unwrap().identity();
        LaunchHandoff {
            vault: Vec::new(),
            vendor_state: Some(VendorStateHandle {
                host_path: root.join("v"),
                fd: Arc::new(vendor.into_fd()),
                identity: vendor_identity,
            }),
            binds: if bind {
                vec![BindHandle {
                    id: "c".to_owned(),
                    fd: Arc::new(source),
                    dest: NativeString::Text("c".to_owned()),
                    identity: source_identity,
                }]
            } else {
                Vec::new()
            },
        }
    }

    #[test]
    fn a_matching_hand_off_is_bound_and_every_mismatch_refuses() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap();
        let good = handoff(&path, true);
        let staged = super::staged_mounts(&launch_snapshot(ProfileName::Agent, true), Some(&good))
            .expect("a matching hand-off");
        assert!(staged.vendor.is_some());
        assert_eq!(staged.credentials.len(), 1);
        assert_eq!(
            staged.credentials[0].1,
            std::path::Path::new("/run/ouro/state/c")
        );

        // Credentials under `tool` (§6.1), even with a matching hand-off.
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Tool, true), Some(&good)).is_err()
        );
        // Managed vendor state with nothing staged, and credentials with no
        // vendor state at all.
        assert!(super::staged_mounts(&launch_snapshot(ProfileName::Agent, false), None).is_err());
        let mut stateless = launch_snapshot(ProfileName::Agent, true);
        stateless.roots.vendor_state = None;
        assert!(super::staged_mounts(&stateless, None).is_err());
        // A bind the policy does not declare.
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Agent, false), Some(&good)).is_err()
        );
        // A declared bind that was not staged.
        let other = tempfile::tempdir().unwrap();
        let unbound = handoff(&other.path().canonicalize().unwrap(), false);
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Agent, true), Some(&unbound))
                .is_err()
        );
        // A bind whose id or destination the policy does not declare, with
        // the count right (J3 review RM36).
        let mut renamed = good.clone();
        renamed.binds[0].dest = NativeString::Text("elsewhere".to_owned());
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Agent, true), Some(&renamed))
                .is_err()
        );
        let mut relabelled = good.clone();
        relabelled.binds[0].id = "other".to_owned();
        assert!(
            super::staged_mounts(
                &launch_snapshot(ProfileName::Agent, true),
                Some(&relabelled)
            )
            .is_err()
        );
        // A descriptor that is not the object staging recorded.
        let mut swapped = good.clone();
        swapped.binds[0].identity = (0, 0);
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Agent, true), Some(&swapped))
                .is_err()
        );
        let mut moved = good;
        if let Some(vendor) = moved.vendor_state.as_mut() {
            vendor.identity = (0, 0);
        }
        assert!(
            super::staged_mounts(&launch_snapshot(ProfileName::Agent, true), Some(&moved)).is_err()
        );
    }
}
