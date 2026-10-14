//! Admission for bounded tmpfs volumes and ext4/XFS user hard quotas.
//!
//! This counts kernel filesystem capacity, not directory sizes. Bind aliases
//! share one budget. All writable mounts are checked in the prepared namespace
//! before target release; profiles that can create mounts cannot use this path.
mod quota;

use crate::policy::{LimitCeiling, LimitKey, LimitsSnapshot};
use crate::records::AppliedLimit;
use crate::state::mountinfo;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) struct Storage {
    volumes: Vec<Volume>,
    limits: Vec<(StorageLimit, AppliedLimit)>,
    capacity_bytes: Option<u64>,
    capacity_inodes: Option<u64>,
    failure: Option<String>,
    /// The loss was found while the target still ran, the only timing that
    /// may make it `outcome.cause` (§6.4, audit 2026-10-08 L2): a loss first
    /// seen after the target's own end never does.
    lost_while_running: bool,
}

/// The two ceilings storage admission enforces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StorageLimit {
    /// `storage`: aggregate writable filesystem bytes.
    Bytes,
    /// `inodes`: aggregate writable filesystem inodes.
    Inodes,
}

impl StorageLimit {
    /// The storage ceiling for a policy key, if storage admission enforces
    /// it. Every key is named, so a new one does not compile until it is
    /// placed.
    fn for_key(key: LimitKey) -> Option<StorageLimit> {
        match key {
            LimitKey::Storage => Some(StorageLimit::Bytes),
            LimitKey::Inodes => Some(StorageLimit::Inodes),
            LimitKey::Wall | LimitKey::Pids | LimitKey::Mem | LimitKey::Swap | LimitKey::Cpu => {
                None
            }
        }
    }

    /// Every storage ceiling, in the policy's key order.
    fn all() -> impl Iterator<Item = StorageLimit> {
        LimitKey::ALL.into_iter().filter_map(StorageLimit::for_key)
    }

    /// The policy key this ceiling is.
    fn key(self) -> LimitKey {
        match self {
            StorageLimit::Bytes => LimitKey::Storage,
            StorageLimit::Inodes => LimitKey::Inodes,
        }
    }

    /// The ceiling the policy requested, if any.
    fn requested(self, limits: &LimitsSnapshot) -> Option<&LimitCeiling> {
        match self {
            StorageLimit::Bytes => limits.storage.as_ref(),
            StorageLimit::Inodes => limits.inodes.as_ref(),
        }
    }
}

/// How a writable filesystem's capacity is bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StorageMechanism {
    /// The calling user's ext4/XFS hard quota.
    UserHardQuota,
    /// A tmpfs mounted with a size and inode count.
    BoundedTmpfs,
}

impl StorageMechanism {
    /// The mechanism a whole admission records: a user quota when any volume
    /// charges one, so the aggregate is never described as tmpfs alone.
    fn of_all<'a>(volumes: impl IntoIterator<Item = &'a Volume>) -> Self {
        if volumes
            .into_iter()
            .any(|volume| volume.mechanism() == StorageMechanism::UserHardQuota)
        {
            StorageMechanism::UserHardQuota
        } else {
            StorageMechanism::BoundedTmpfs
        }
    }

    /// The spelling of the applied limit's `mechanism`, of the evidence's
    /// overall `mechanism`, and of the doctor probe.
    fn as_str(self) -> &'static str {
        match self {
            StorageMechanism::UserHardQuota => "filesystem-user-quota",
            StorageMechanism::BoundedTmpfs => "bounded-tmpfs-capacity",
        }
    }

    /// The spelling of one volume's `mechanism` in the evidence, which names
    /// the quota itself rather than the filesystem that carries it.
    fn volume_spelling(self) -> &'static str {
        match self {
            StorageMechanism::UserHardQuota => "user-hard-quota",
            StorageMechanism::BoundedTmpfs => "bounded-tmpfs-capacity",
        }
    }
}

struct Volume {
    file: File,
    uid: Option<u32>,
    bytes: Option<u64>,
    inodes: Option<u64>,
}

impl Volume {
    fn mechanism(&self) -> StorageMechanism {
        match self.uid {
            Some(_) => StorageMechanism::UserHardQuota,
            None => StorageMechanism::BoundedTmpfs,
        }
    }

    fn full(&self) -> io::Result<(bool, bool)> {
        if let Some(uid) = self.uid {
            let now = quota::read(&self.file, uid)?;
            if now.bytes != self.bytes || now.inodes != self.inodes {
                return Err(io::Error::other("user quota changed after admission"));
            }
            Ok((
                self.bytes.is_some_and(|max| now.bytes_used >= max),
                self.inodes.is_some_and(|max| now.inodes_used >= max),
            ))
        } else {
            let value = stat(&self.file)?;
            // The tmpfs capacity is re-verified every sample, like the quota
            // path above. A host-side remount to a smaller size is an
            // enforcement loss, never a hit.
            if tmpfs_capacity(&value)? != (self.bytes, self.inodes) {
                return Err(io::Error::other("tmpfs capacity changed after admission"));
            }
            Ok((value.f_bavail == 0, value.f_ffree == 0))
        }
    }
}

/// A tmpfs's hard capacity as `(bytes, inodes)`: blocks times block size,
/// and the inode count, each `None` where the tmpfs has no bound (a count of
/// zero).
///
/// # Errors
/// A capacity that cannot be a byte count.
fn tmpfs_capacity(value: &libc::statfs) -> io::Result<(Option<u64>, Option<u64>)> {
    let block_size = u64::try_from(value.f_bsize).map_err(io::Error::other)?;
    let bytes = if value.f_blocks == 0 {
        None
    } else {
        Some(
            value
                .f_blocks
                .checked_mul(block_size)
                .ok_or_else(|| io::Error::other("storage capacity overflow"))?,
        )
    };
    Ok((bytes, (value.f_files != 0).then_some(value.f_files)))
}

fn stat(file: &File) -> io::Result<libc::statfs> {
    let mut value = std::mem::MaybeUninit::uninit();
    // SAFETY: a live descriptor and writable statfs output.
    if unsafe { libc::fstatfs(file.as_raw_fd(), value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs initialized the structure on success.
    Ok(unsafe { value.assume_init() })
}

/// XFS geometry needs an ioctl-capable descriptor: ioctl rejects O_PATH.
/// Open it once, before releasing the target, and retain it for every quota
/// sample so a subsequent chmod cannot invalidate the readback.
fn sampling_file(file: File, value: &libc::statfs) -> io::Result<File> {
    if value.f_type != libc::XFS_SUPER_MAGIC {
        return Ok(file);
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// The hard capacities admission counts on one writable filesystem, and the
/// identity whose quota it charges (`None`: tmpfs, which charges none).
struct Ceiling {
    uid: Option<u32>,
    bytes: Option<u64>,
    inodes: Option<u64>,
}

impl Ceiling {
    fn mechanism(&self) -> StorageMechanism {
        match self.uid {
            Some(_) => StorageMechanism::UserHardQuota,
            None => StorageMechanism::BoundedTmpfs,
        }
    }
}

/// Why a writable filesystem has no ceiling admission can charge.
enum CeilingRefusal {
    /// Neither bounded tmpfs nor ext4/XFS: admission refuses the mount.
    Unbounded,
    /// ext4/XFS whose user hard quota cannot be read or enforced.
    Quota(io::Error),
    /// A capacity that cannot be a byte count.
    Overflow(io::Error),
}

/// Classifies one open filesystem the way [`Storage::admit`] classifies a
/// writable mount: a tmpfs's bounded block and inode capacity, or the
/// calling user's ext4/XFS hard quota.
fn ceiling(file: &File, value: &libc::statfs) -> Result<Ceiling, CeilingRefusal> {
    if value.f_type == libc::TMPFS_MAGIC {
        let (bytes, inodes) = tmpfs_capacity(value).map_err(CeilingRefusal::Overflow)?;
        return Ok(Ceiling {
            uid: None,
            bytes,
            inodes,
        });
    }
    if [libc::EXT4_SUPER_MAGIC, libc::XFS_SUPER_MAGIC].contains(&value.f_type) {
        // SAFETY: geteuid has no arguments or memory effects.
        let uid = unsafe { libc::geteuid() };
        let quota = quota::read(file, uid).map_err(CeilingRefusal::Quota)?;
        return Ok(Ceiling {
            uid: Some(uid),
            bytes: quota.bytes,
            inodes: quota.inodes,
        });
    }
    Err(CeilingRefusal::Unbounded)
}

/// What the doctor's `storage_ceiling` probe found for a writable
/// directory: the ceiling [`Storage::admit`] would charge, or why a
/// `--limit storage`/`--limit inodes` run would refuse the filesystem.
pub(super) enum CeilingProbe {
    /// A hard ceiling admission can charge.
    Bounded { evidence: String },
    /// A filesystem admission would refuse (§6.4).
    Unbounded {
        reason: &'static str,
        evidence: String,
    },
    /// The probe could not inspect the filesystem.
    Failed(String),
}

/// Classifies one directory the way [`Storage::admit`] classifies a
/// writable mount, so `doctor` measures the prerequisite a
/// `--limit storage`/`--limit inodes` run refuses without (§6.4).
pub(super) fn probe_ceiling(path: &Path) -> CeilingProbe {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(err) => return CeilingProbe::Failed(format!("{}: {err}", path.display())),
    };
    let value = match stat(&file) {
        Ok(value) => value,
        Err(err) => return CeilingProbe::Failed(format!("{}: {err}", path.display())),
    };
    let file = match sampling_file(file, &value) {
        Ok(file) => file,
        Err(err) => return CeilingProbe::Failed(format!("{}: {err}", path.display())),
    };
    let (mechanism, bytes, inodes) = match ceiling(&file, &value) {
        Ok(ceiling) => (ceiling.mechanism(), ceiling.bytes, ceiling.inodes),
        Err(CeilingRefusal::Quota(err)) => {
            return CeilingProbe::Unbounded {
                reason: "no_user_hard_quota",
                evidence: format!("{}: {err}", path.display()),
            };
        }
        Err(CeilingRefusal::Overflow(err)) => return CeilingProbe::Failed(err.to_string()),
        Err(CeilingRefusal::Unbounded) => {
            return CeilingProbe::Unbounded {
                reason: "unbounded_filesystem",
                evidence: format!(
                    "{}: writable filesystem of type {:#x} with no bounded tmpfs or user quota",
                    path.display(),
                    value.f_type
                ),
            };
        }
    };
    let missing = match (bytes, inodes) {
        (Some(bytes), Some(inodes)) => {
            return CeilingProbe::Bounded {
                evidence: format!(
                    "{}: {bytes} bytes, {inodes} inodes ({})",
                    mechanism.as_str(),
                    path.display()
                ),
            };
        }
        (None, None) => "bytes and inodes",
        (None, Some(_)) => "bytes",
        (Some(_), None) => "inodes",
    };
    CeilingProbe::Unbounded {
        reason: match mechanism {
            StorageMechanism::UserHardQuota => "no_user_hard_quota",
            StorageMechanism::BoundedTmpfs => "tmpfs_unbounded",
        },
        evidence: format!(
            "{} on {} has no hard bound for {missing}",
            mechanism.as_str(),
            path.display()
        ),
    }
}

/// The character devices bubblewrap binds individually into `/dev`, by
/// (major, minor): `null`, `zero`, `full`, `random`, `urandom` and `tty`.
/// Writing to them cannot allocate filesystem data or create sibling files.
/// No other device is exempt: an operator-granted device is not vouched for.
const ALLOCATION_FREE_DEVICES: [(u32, u32); 6] = [(1, 3), (1, 5), (1, 7), (1, 8), (1, 9), (5, 0)];

pub(super) fn requested(limits: &LimitsSnapshot) -> bool {
    StorageLimit::all().any(|limit| limit.requested(limits).is_some())
}

/// The largest mount inventory admission reads.
const MOUNTINFO_MAX: usize = 1024 * 1024;

/// The mount points of every writable mount in `raw`, a
/// `/proc/<pid>/mountinfo`, parsed by [`mountinfo::rows`].
///
/// A read-only mount (`ro` in the per-mount options) needs no ceiling. An
/// idmapped writable mount would charge a quota identity this code does not
/// see, so it refuses, as does a row the parser refuses or a mount point
/// that is not an absolute path without NUL: a row that cannot be read is
/// never a mount that was not there.
///
/// # Errors
/// An empty or oversized inventory, a malformed row, or an idmapped
/// writable mount.
fn writable_mount_points(raw: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    if raw.is_empty() || raw.len() > MOUNTINFO_MAX {
        return Err(io::Error::other(
            "storage mount inventory missing or too large",
        ));
    }
    let mut points = Vec::new();
    for row in mountinfo::rows(raw, usize::MAX)? {
        if row.has_option(b"ro") {
            continue;
        }
        if row.has_option(b"idmapped") {
            return Err(io::Error::other(
                "storage ceilings do not support idmapped writable mounts",
            ));
        }
        if !row.mount_point.starts_with(b"/") || row.mount_point.contains(&0) {
            return Err(io::Error::other("invalid storage mount point"));
        }
        points.push(row.mount_point);
    }
    Ok(points)
}

/// What one writable mount contributes to admission.
enum Admitted {
    /// It cannot allocate filesystem data: a device bubblewrap binds on its
    /// own, process metadata, a pty.
    Exempt,
    /// It is bounded: the filesystem's device and the volume to sample.
    Bounded(u64, Volume),
}

/// Classifies the writable mount at `point` in `pid`'s namespace, checking a
/// quota-bounded mount's existing inodes all charge the quota's user.
///
/// # Errors
/// A mount that cannot be opened or classified, or one with no ceiling
/// admission can charge.
fn admit_mount(
    pid: libc::pid_t,
    point: &[u8],
    scanned: &mut usize,
    deadline: super::clock::Deadline,
) -> io::Result<Admitted> {
    let mut path = format!("/proc/{pid}/root").into_bytes();
    path.extend_from_slice(point);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(PathBuf::from(std::ffi::OsString::from_vec(path)))?;
    let value = stat(&file)?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_char_device()
        && ALLOCATION_FREE_DEVICES
            .contains(&(libc::major(metadata.rdev()), libc::minor(metadata.rdev())))
    {
        return Ok(Admitted::Exempt);
    }
    // Process metadata and ptys do not allocate filesystem data.
    if [libc::PROC_SUPER_MAGIC, libc::DEVPTS_SUPER_MAGIC].contains(&value.f_type) {
        return Ok(Admitted::Exempt);
    }
    let file = sampling_file(file, &value)?;
    let ceiling = match ceiling(&file, &value) {
        Ok(ceiling) => ceiling,
        Err(CeilingRefusal::Quota(err)) => {
            return Err(io::Error::other(format!(
                "writable disk mount {} needs an enforced user hard quota: {err}",
                String::from_utf8_lossy(point)
            )));
        }
        Err(CeilingRefusal::Overflow(err)) => return Err(err),
        Err(CeilingRefusal::Unbounded) => {
            return Err(io::Error::other(format!(
                "writable mount {} needs bounded tmpfs or ext4/XFS user hard quotas",
                String::from_utf8_lossy(point)
            )));
        }
    };
    if let Some(uid) = ceiling.uid {
        // Check every grant, even another bind of an already-counted
        // filesystem: its existing inodes may have different owners.
        quota::check_owners(&file, uid, scanned, deadline)?;
    }
    Ok(Admitted::Bounded(
        metadata.dev(),
        Volume {
            file,
            uid: ceiling.uid,
            bytes: ceiling.bytes,
            inodes: ceiling.inodes,
        },
    ))
}

impl Storage {
    /// Admits every writable mount of `pid`'s mount namespace: each must be
    /// a bounded tmpfs or carry the calling user's hard quota, and their
    /// capacities, one per filesystem, must fit the requested ceilings.
    ///
    /// # Errors
    /// An unreadable inventory, a mount admission refuses, a requested
    /// resource some filesystem does not bound, or an aggregate capacity
    /// over the requested ceiling.
    pub(super) fn admit(
        pid: libc::pid_t,
        limits: &LimitsSnapshot,
        deadline: super::clock::Deadline,
    ) -> io::Result<Self> {
        // One byte past the bound is enough to refuse a larger table.
        let mut raw = Vec::new();
        io::Read::read_to_end(
            &mut io::Read::take(
                File::open(format!("/proc/{pid}/mountinfo"))?,
                u64::try_from(MOUNTINFO_MAX)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            ),
            &mut raw,
        )?;
        let mut volumes = BTreeMap::new();
        let mut scanned = 0;
        for point in writable_mount_points(&raw)? {
            if deadline.expired() {
                return Err(io::Error::other("storage admission deadline expired"));
            }
            let Admitted::Bounded(device, volume) =
                admit_mount(pid, &point, &mut scanned, deadline)?
            else {
                continue;
            };
            if volumes.contains_key(&device) {
                continue;
            }
            if (limits.storage.is_some() && volume.bytes.is_none())
                || (limits.inodes.is_some() && volume.inodes.is_none())
            {
                return Err(io::Error::other(
                    "writable filesystem has no hard ceiling for a requested resource",
                ));
            }
            volumes.insert(device, volume);
        }
        Self::aggregate(volumes.into_values().collect(), limits)
    }

    /// The admitted volumes' total capacity checked against the requested
    /// ceilings, and the limits it applies.
    fn aggregate(volumes: Vec<Volume>, limits: &LimitsSnapshot) -> io::Result<Self> {
        let total = |capacity: fn(&Volume) -> Option<u64>, what: &str| -> io::Result<(u64, bool)> {
            volumes
                .iter()
                .try_fold((0u64, true), |(sum, bounded), volume| {
                    let value = capacity(volume);
                    let sum = sum
                        .checked_add(value.unwrap_or(0))
                        .ok_or_else(|| io::Error::other(format!("{what} capacity overflow")))?;
                    Ok((sum, bounded && value.is_some()))
                })
        };
        let (bytes, bytes_bounded) = total(|volume| volume.bytes, "storage")?;
        let (inodes, inodes_bounded) = total(|volume| volume.inodes, "inode")?;
        let mechanism = StorageMechanism::of_all(&volumes);
        let mut applied = Vec::new();
        for limit in StorageLimit::all() {
            let Some(ceiling) = limit.requested(limits) else {
                continue;
            };
            let capacity = match limit {
                StorageLimit::Bytes => bytes,
                StorageLimit::Inodes => inodes,
            };
            let key = limit.key().as_str();
            let requested: u64 = ceiling.value.parse().map_err(io::Error::other)?;
            if capacity > requested {
                return Err(io::Error::other(format!(
                    "{key}: aggregate writable storage capacity {capacity} exceeds requested ceiling {requested}"
                )));
            }
            applied.push((
                limit,
                AppliedLimit {
                    key: key.into(),
                    requested: ceiling.value.clone(),
                    required: ceiling.required,
                    applied: true,
                    mechanism: Some(mechanism.as_str().into()),
                    scope: Some("tree".into()),
                    // Filesystems expose occupancy, not cumulative refusals.
                    // Never invent a negative hit claim from a polling sample.
                    hit: None,
                },
            ));
        }
        Ok(Self {
            volumes,
            limits: applied,
            capacity_bytes: bytes_bounded.then_some(bytes),
            capacity_inodes: inodes_bounded.then_some(inodes),
            failure: None,
            lost_while_running: false,
        })
    }

    pub(super) fn limits(&self) -> Vec<AppliedLimit> {
        let rows = self.limits.iter().map(|(_, limit)| limit);
        if self.failure.is_some() {
            // Enforcement that was lost no longer claims `applied: true`,
            // like `record_limit_unapplied`'s rows; the receipt's `errors[]`
            // entry names `storage_enforcement_lost`.
            return rows
                .map(|limit| AppliedLimit {
                    applied: false,
                    mechanism: None,
                    scope: None,
                    hit: None,
                    ..limit.clone()
                })
                .collect();
        }
        rows.cloned().collect()
    }

    /// The stored enforcement-loss message, for the receipt's `errors[]`.
    pub(super) fn loss(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    /// The ceiling's receipt evidence. `hard_links_denied` is what the
    /// installed syscall filter does with `link` and `linkat`, read from that
    /// program by the caller, never assumed here.
    pub(super) fn evidence(&self, hard_links_denied: bool) -> serde_json::Value {
        serde_json::json!({
            "mechanism": StorageMechanism::of_all(&self.volumes).as_str(),
            "volumes": self.volumes.iter().map(|volume| serde_json::json!({
                "mechanism": volume.mechanism().volume_spelling(),
                "uid": volume.uid,
                "capacity_bytes": volume.bytes,
                "capacity_inodes": volume.inodes,
            })).collect::<Vec<_>>(),
            "hard_links": if hard_links_denied { "denied" } else { "permitted" },
            "hard_link_denials": hard_links_denied.then_some("seccomp_errno_not_observed"),
            "filesystems": self.volumes.len(),
            "capacity_bytes": self.capacity_bytes,
            "capacity_inodes": self.capacity_inodes,
            "hit_evidence": "sampled_saturation_positive_only",
            "enforcement_lost": self.failure,
            "dev_shm": "read_only",
        })
    }

    /// Positive saturation evidence only. A missed transient stays unknown.
    /// A loss is sticky: every later sample replays it. `target_ended` is
    /// whether the target's own end is known at this sample, which decides
    /// whether a loss found now was found while it ran.
    pub(super) fn sample(&mut self, target_ended: bool) -> io::Result<Vec<String>> {
        let result = match &self.failure {
            Some(failure) => Err(io::Error::other(failure.clone())),
            None => self.sample_inner(),
        };
        if let Err(err) = &result {
            self.failure.get_or_insert_with(|| err.to_string());
            self.lost_while_running |= !target_ended;
        }
        result
    }

    /// Whether enforcement was lost while the target still ran (§6.4).
    pub(super) fn lost_while_running(&self) -> bool {
        self.failure.is_some() && self.lost_while_running
    }

    fn sample_inner(&mut self) -> io::Result<Vec<String>> {
        let mut bytes_full = false;
        let mut inodes_full = false;
        for volume in &self.volumes {
            let (full_bytes, full_inodes) = volume.full()?;
            bytes_full |= full_bytes;
            inodes_full |= full_inodes;
        }
        let mut hits = Vec::new();
        for (kind, limit) in &mut self.limits {
            let full = match kind {
                StorageLimit::Bytes => bytes_full,
                StorageLimit::Inodes => inodes_full,
            };
            if full && limit.hit != Some(true) {
                limit.hit = Some(true);
                hits.push(limit.key.clone());
            }
        }
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn xfs_sampling_descriptor_is_opened_once_and_survives_chmod() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let pinned = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(dir.path())
            .unwrap();
        let identity = pinned.metadata().unwrap();
        let mut value = stat(&pinned).unwrap();
        // Exercise the descriptor selection on any unit-test filesystem;
        // a native XFS fixture separately exercises the geometry ioctl.
        value.f_type = libc::XFS_SUPER_MAGIC;
        let file = sampling_file(pinned, &value).unwrap();
        // SAFETY: fcntl F_GETFL only queries the live descriptor.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::O_PATH, 0);
        assert_eq!(file.metadata().unwrap().ino(), identity.ino());
        assert_eq!(file.metadata().unwrap().dev(), identity.dev());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o0)).unwrap();
        assert!(stat(&file).is_ok());
        let mut geometry = [0u64; 32];
        // SAFETY: the complete XFS geometry output ABI on a live descriptor.
        let result = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                quota::XFS_IOC_FSGEOMETRY,
                geometry.as_mut_ptr(),
            )
        };
        if result != 0 {
            assert_ne!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    #[ignore = "requires a disposable XFS mount with enforced user hard quotas; set OURO_TEST_XFS_DIR"]
    fn xfs_hard_quota_admission_and_sampling_survive_chmod() {
        use std::os::unix::fs::PermissionsExt as _;
        let path =
            PathBuf::from(std::env::var_os("OURO_TEST_XFS_DIR").expect("XFS fixture directory"));
        assert!(matches!(probe_ceiling(&path), CeilingProbe::Bounded { .. }));
        let pinned = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&path)
            .unwrap();
        let value = stat(&pinned).unwrap();
        assert_eq!(value.f_type, libc::XFS_SUPER_MAGIC);
        // SAFETY: geteuid has no arguments or memory effects.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            quota::read(&pinned, uid).err().unwrap().raw_os_error(),
            Some(libc::EBADF)
        );
        let file = sampling_file(pinned, &value).unwrap();
        let admitted = ceiling(&file, &value).ok().expect("enforced hard quota");
        assert_eq!(admitted.uid, Some(uid));
        assert!(admitted.bytes.is_some());
        assert!(admitted.inodes.is_some());
        let volume = Volume {
            file,
            uid: admitted.uid,
            bytes: admitted.bytes,
            inodes: admitted.inodes,
        };
        assert_eq!(volume.full().unwrap(), (false, false));
        let permissions = fs::metadata(&path).unwrap().permissions();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
        let sample = volume.full();
        fs::set_permissions(&path, permissions).unwrap();
        assert_eq!(sample.unwrap(), (false, false));
    }

    /// A volume whose admitted tmpfs capacity matches its filesystem, or
    /// `offset_blocks` blocks larger — the stale, larger admission a
    /// host-side remount shrink leaves behind — with the directory it lives
    /// in, which must outlive it.
    fn tmpfs_volume(offset_blocks: u64) -> Option<(tempfile::TempDir, Volume)> {
        let dir = tempfile::tempdir().ok()?;
        let file = File::open(dir.path()).ok()?;
        let value = stat(&file).ok()?;
        if value.f_type != libc::TMPFS_MAGIC || value.f_blocks == 0 {
            // Unit coverage needs a bounded tmpfs to stand in for the mount.
            return None;
        }
        let block = u64::try_from(value.f_bsize).unwrap();
        let volume = Volume {
            file,
            uid: None,
            bytes: Some((value.f_blocks + offset_blocks) * block),
            inodes: Some(value.f_files),
        };
        Some((dir, volume))
    }

    #[test]
    fn tmpfs_capacity_shrink_after_admission_is_a_loss_not_a_hit() {
        let Some((_dir, mut volume)) = tmpfs_volume(0) else {
            return;
        };
        // An honest admission samples saturation, not a loss.
        assert_eq!(volume.full().unwrap(), (false, false));
        // A remount to a smaller size (the admitted capacity is now stale and
        // larger) is an enforcement loss, never a saturation hit.
        volume.bytes = tmpfs_volume(1).unwrap().1.bytes;
        assert_eq!(
            volume.full().unwrap_err().to_string(),
            "tmpfs capacity changed after admission"
        );
        // Inode capacity too.
        let (_dir, mut volume) = tmpfs_volume(0).unwrap();
        volume.inodes = volume.inodes.map(|files| files + 1);
        assert_eq!(
            volume.full().unwrap_err().to_string(),
            "tmpfs capacity changed after admission"
        );
        // An admitted-unbounded tmpfs that gained a bound is a change as well.
        let (_dir, mut volume) = tmpfs_volume(0).unwrap();
        volume.bytes = None;
        assert!(volume.full().is_err());
    }

    #[test]
    fn tmpfs_capacity_is_blocks_times_block_size_and_zero_is_unbounded() {
        // SAFETY: statfs is a plain C struct of integers, for which all-zero
        // is a valid value.
        let mut value: libc::statfs = unsafe { std::mem::zeroed() };
        value.f_bsize = 4096;
        value.f_blocks = 10;
        value.f_files = 7;
        assert_eq!(tmpfs_capacity(&value).unwrap(), (Some(40960), Some(7)));
        value.f_blocks = 0;
        value.f_files = 0;
        assert_eq!(tmpfs_capacity(&value).unwrap(), (None, None));
        value.f_blocks = u64::MAX;
        assert!(tmpfs_capacity(&value).is_err(), "an overflow is refused");
    }

    #[test]
    fn the_mount_inventory_names_writable_mounts_and_refuses_what_it_cannot_read() {
        let row = |point: &str, options: &str| {
            format!("36 35 98:0 / {point} {options} master:1 - ext4 /dev/root rw\n")
        };
        let text = [
            row("/", "ro,relatime"),
            row("/work\\040space", "rw,nosuid"),
            row("/tmp", "rw,noro"),
        ]
        .concat();
        assert_eq!(
            writable_mount_points(text.as_bytes()).unwrap(),
            [b"/work space".to_vec(), b"/tmp".to_vec()],
            "read-only mounts need no ceiling; an option merely containing ro is not ro"
        );
        for refused in [
            String::new(),
            row("/x", "rw,idmapped"),
            "36 35 98:0 / /x\n".to_owned(),
            row("relative", "rw"),
            row("/a\\000b", "rw"),
        ] {
            assert!(
                writable_mount_points(refused.as_bytes()).is_err(),
                "{refused:?}"
            );
        }
        assert!(writable_mount_points(&vec![b'x'; MOUNTINFO_MAX + 1]).is_err());
    }

    #[test]
    fn admission_sums_one_capacity_per_filesystem_and_names_the_mechanism() {
        let dir = tempfile::tempdir().unwrap();
        let volume = |uid: Option<u32>, bytes: Option<u64>, inodes: Option<u64>| Volume {
            file: File::open(dir.path()).unwrap(),
            uid,
            bytes,
            inodes,
        };
        let ceiling = |value: &str| LimitCeiling {
            value: value.to_owned(),
            required: true,
        };
        let limits = LimitsSnapshot {
            storage: Some(ceiling("300")),
            inodes: Some(ceiling("30")),
            ..LimitsSnapshot::default()
        };
        let tmpfs = Storage::aggregate(
            vec![
                volume(None, Some(100), Some(10)),
                volume(None, Some(200), Some(20)),
            ],
            &limits,
        )
        .unwrap();
        assert_eq!(
            (tmpfs.capacity_bytes, tmpfs.capacity_inodes),
            (Some(300), Some(30))
        );
        let rows = tmpfs.limits();
        assert_eq!(
            rows.iter()
                .map(|row| (row.key.as_str(), row.mechanism.as_deref()))
                .collect::<Vec<_>>(),
            [
                ("storage", Some("bounded-tmpfs-capacity")),
                ("inodes", Some("bounded-tmpfs-capacity"))
            ]
        );
        assert_eq!(
            tmpfs.evidence(true)["volumes"][0]["mechanism"],
            "bounded-tmpfs-capacity"
        );
        // One quota-backed volume makes the whole admission a quota's.
        let mixed = Storage::aggregate(
            vec![
                volume(Some(1000), Some(100), Some(10)),
                volume(None, Some(1), Some(1)),
            ],
            &limits,
        )
        .unwrap();
        assert_eq!(
            mixed.limits()[0].mechanism.as_deref(),
            Some("filesystem-user-quota")
        );
        assert_eq!(mixed.evidence(true)["mechanism"], "filesystem-user-quota");
        assert_eq!(
            mixed.evidence(true)["volumes"][0]["mechanism"],
            "user-hard-quota"
        );
        // More capacity than the ceiling refuses.
        let over = Storage::aggregate(vec![volume(None, Some(301), Some(1))], &limits);
        assert!(
            over.err()
                .is_some_and(|error| error.to_string().contains("exceeds requested ceiling"))
        );
        // Only the requested ceilings are applied.
        let bytes_only = LimitsSnapshot {
            storage: Some(ceiling("300")),
            ..LimitsSnapshot::default()
        };
        let applied = Storage::aggregate(vec![volume(None, Some(1), None)], &bytes_only).unwrap();
        assert_eq!(applied.limits().len(), 1);
        assert_eq!(
            applied.capacity_inodes, None,
            "an unbounded inode count is not a sum"
        );
        assert!(requested(&bytes_only));
        assert!(!requested(&LimitsSnapshot::default()));
    }

    /// A loss becomes `outcome.cause` only when it was found while the
    /// target ran: the first failed sample, or a replay of it, before the
    /// target's end is known. Found only after that end, it never does.
    #[test]
    fn only_a_loss_found_while_the_target_ran_can_be_the_cause() {
        let dir = tempfile::tempdir().unwrap();
        // A volume that is no bounded tmpfs of one byte: its first sample
        // finds the capacity changed, a real loss.
        let losing = || Storage {
            volumes: vec![Volume {
                file: File::open(dir.path()).unwrap(),
                uid: None,
                bytes: Some(1),
                inodes: None,
            }],
            limits: Vec::new(),
            capacity_bytes: Some(1),
            capacity_inodes: None,
            failure: None,
            lost_while_running: false,
        };
        let after = |ended: &[bool]| {
            let mut storage = losing();
            for target_ended in ended {
                assert!(storage.sample(*target_ended).is_err());
            }
            (storage.loss().is_some(), storage.lost_while_running())
        };
        assert_eq!(after(&[]), (false, false));
        assert_eq!(after(&[true]), (true, false));
        assert_eq!(after(&[true, true]), (true, false));
        assert_eq!(after(&[false]), (true, true));
        assert_eq!(after(&[false, true]), (true, true));
    }

    #[test]
    fn a_lost_enforcement_no_longer_claims_applied() {
        let mut storage = Storage {
            volumes: Vec::new(),
            limits: vec![(
                StorageLimit::Bytes,
                AppliedLimit {
                    key: "storage".into(),
                    requested: "1".into(),
                    required: true,
                    applied: true,
                    mechanism: Some("bounded-tmpfs-capacity".into()),
                    scope: Some("tree".into()),
                    hit: None,
                },
            )],
            capacity_bytes: Some(1),
            capacity_inodes: None,
            failure: None,
            lost_while_running: false,
        };
        assert!(storage.limits()[0].applied);
        assert!(storage.loss().is_none());
        storage.failure = Some("tmpfs capacity changed after admission".into());
        let row = &storage.limits()[0];
        // Like `record_limit_unapplied`'s rows, the ceiling no longer claims
        // `applied`, and its evidence is unknown.
        assert!(!row.applied);
        assert_eq!(row.mechanism, None);
        assert_eq!(row.scope, None);
        assert_eq!(row.hit, None);
        assert_eq!(
            storage.loss(),
            Some("tmpfs capacity changed after admission")
        );
    }
}
