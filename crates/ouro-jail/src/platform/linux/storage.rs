//! Admission for bounded tmpfs volumes and ext4/XFS user hard quotas.
//!
//! This counts kernel filesystem capacity, not directory sizes. Bind aliases
//! share one budget. All writable mounts are checked in the prepared namespace
//! before target release; profiles that can create mounts cannot use this path.
mod quota;

use crate::policy::LimitsSnapshot;
use crate::records::AppliedLimit;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) struct Storage {
    volumes: Vec<Volume>,
    limits: Vec<AppliedLimit>,
    capacity_bytes: Option<u64>,
    capacity_inodes: Option<u64>,
    failure: Option<String>,
}

struct Volume {
    file: File,
    uid: Option<u32>,
    bytes: Option<u64>,
    inodes: Option<u64>,
}

impl Volume {
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
        Ok(ceiling) => (
            if ceiling.uid.is_some() {
                "filesystem-user-quota"
            } else {
                "bounded-tmpfs-capacity"
            },
            ceiling.bytes,
            ceiling.inodes,
        ),
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
                    "{mechanism}: {bytes} bytes, {inodes} inodes ({})",
                    path.display()
                ),
            };
        }
        (None, None) => "bytes and inodes",
        (None, Some(_)) => "bytes",
        (Some(_), None) => "inodes",
    };
    CeilingProbe::Unbounded {
        reason: if mechanism == "filesystem-user-quota" {
            "no_user_hard_quota"
        } else {
            "tmpfs_unbounded"
        },
        evidence: format!(
            "{mechanism} on {} has no hard bound for {missing}",
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
    limits.storage.is_some() || limits.inodes.is_some()
}

impl Storage {
    pub(super) fn admit(
        pid: libc::pid_t,
        limits: &LimitsSnapshot,
        deadline: super::clock::Deadline,
    ) -> io::Result<Self> {
        let raw = fs::read(format!("/proc/{pid}/mountinfo"))?;
        if raw.is_empty() || raw.len() > 1024 * 1024 {
            return Err(io::Error::other(
                "storage mount inventory missing or too large",
            ));
        }
        let mut volumes = BTreeMap::new();
        let mut bytes = 0u64;
        let mut inodes = 0u64;
        let mut bytes_bounded = true;
        let mut inodes_bounded = true;
        let mut scanned = 0;
        for line in raw
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            if deadline.expired() {
                return Err(io::Error::other("storage admission deadline expired"));
            }
            let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
            let point = fields
                .get(4)
                .ok_or_else(|| io::Error::other("invalid storage mount row"))?;
            let options = fields
                .get(5)
                .ok_or_else(|| io::Error::other("missing storage mount options"))?;
            if options
                .split(|byte| *byte == b',')
                .any(|option| option == b"ro")
            {
                continue;
            }
            if options
                .split(|byte| *byte == b',')
                .any(|option| option == b"idmapped")
            {
                return Err(io::Error::other(
                    "storage ceilings do not support idmapped writable mounts",
                ));
            }
            let point = super::platform::decode_mountinfo_path(point);
            if !point.starts_with(b"/") || point.contains(&0) {
                return Err(io::Error::other("invalid storage mount point"));
            }
            let mut path = format!("/proc/{pid}/root").into_bytes();
            path.extend_from_slice(&point);
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
                continue;
            }
            // Process metadata and ptys do not allocate filesystem data.
            if [libc::PROC_SUPER_MAGIC, libc::DEVPTS_SUPER_MAGIC].contains(&value.f_type) {
                continue;
            }
            let device = metadata.dev();
            let file = sampling_file(file, &value)?;
            let (uid, capacity_bytes, capacity_inodes) = match ceiling(&file, &value) {
                Ok(ceiling) => (ceiling.uid, ceiling.bytes, ceiling.inodes),
                Err(CeilingRefusal::Quota(err)) => {
                    return Err(io::Error::other(format!(
                        "writable disk mount {} needs an enforced user hard quota: {err}",
                        String::from_utf8_lossy(&point)
                    )));
                }
                Err(CeilingRefusal::Overflow(err)) => return Err(err),
                Err(CeilingRefusal::Unbounded) => {
                    return Err(io::Error::other(format!(
                        "writable mount {} needs bounded tmpfs or ext4/XFS user hard quotas",
                        String::from_utf8_lossy(&point)
                    )));
                }
            };
            if let Some(uid) = uid {
                // Check every grant, even another bind of an already-counted
                // filesystem: its existing inodes may have different owners.
                quota::check_owners(&file, uid, &mut scanned, deadline)?;
            }
            if volumes.contains_key(&device) {
                continue;
            }
            if (limits.storage.is_some() && capacity_bytes.is_none())
                || (limits.inodes.is_some() && capacity_inodes.is_none())
            {
                return Err(io::Error::other(
                    "writable filesystem has no hard ceiling for a requested resource",
                ));
            }
            bytes_bounded &= capacity_bytes.is_some();
            inodes_bounded &= capacity_inodes.is_some();
            bytes = bytes
                .checked_add(capacity_bytes.unwrap_or(0))
                .ok_or_else(|| io::Error::other("storage capacity overflow"))?;
            inodes = inodes
                .checked_add(capacity_inodes.unwrap_or(0))
                .ok_or_else(|| io::Error::other("inode capacity overflow"))?;
            volumes.insert(
                device,
                Volume {
                    file,
                    uid,
                    bytes: capacity_bytes,
                    inodes: capacity_inodes,
                },
            );
        }
        let mechanism = if volumes.values().any(|volume| volume.uid.is_some()) {
            "filesystem-user-quota"
        } else {
            "bounded-tmpfs-capacity"
        };
        let mut applied = Vec::new();
        for (key, ceiling, capacity) in [
            ("storage", &limits.storage, bytes),
            ("inodes", &limits.inodes, inodes),
        ] {
            let Some(ceiling) = ceiling else { continue };
            let requested: u64 = ceiling.value.parse().map_err(io::Error::other)?;
            if capacity > requested {
                return Err(io::Error::other(format!(
                    "{key}: aggregate writable storage capacity {capacity} exceeds requested ceiling {requested}"
                )));
            }
            applied.push(AppliedLimit {
                key: key.into(),
                requested: ceiling.value.clone(),
                required: ceiling.required,
                applied: true,
                mechanism: Some(mechanism.into()),
                scope: Some("tree".into()),
                // Filesystems expose occupancy, not cumulative refusals.
                // Never invent a negative hit claim from a polling sample.
                hit: None,
            });
        }
        Ok(Self {
            volumes: volumes.into_values().collect(),
            limits: applied,
            capacity_bytes: bytes_bounded.then_some(bytes),
            capacity_inodes: inodes_bounded.then_some(inodes),
            failure: None,
        })
    }

    pub(super) fn limits(&self) -> Vec<AppliedLimit> {
        if self.failure.is_some() {
            // Audit 2026-10-08 L2: enforcement that was lost no longer claims
            // `applied: true`, like `record_limit_unapplied`'s rows; the
            // receipt's `errors[]` entry names `storage_enforcement_lost`.
            return self
                .limits
                .iter()
                .map(|limit| AppliedLimit {
                    applied: false,
                    mechanism: None,
                    scope: None,
                    hit: None,
                    ..limit.clone()
                })
                .collect();
        }
        self.limits.clone()
    }

    /// The stored enforcement-loss message, for the receipt's `errors[]`.
    pub(super) fn loss(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    pub(super) fn evidence(&self) -> serde_json::Value {
        serde_json::json!({
            "mechanism": if self.volumes.iter().any(|volume| volume.uid.is_some()) {
                "filesystem-user-quota"
            } else { "bounded-tmpfs-capacity" },
            "volumes": self.volumes.iter().map(|volume| serde_json::json!({
                "mechanism": if volume.uid.is_some() { "user-hard-quota" } else { "bounded-tmpfs-capacity" },
                "uid": volume.uid,
                "capacity_bytes": volume.bytes,
                "capacity_inodes": volume.inodes,
            })).collect::<Vec<_>>(),
            "hard_links": "denied",
            "hard_link_denials": "seccomp_errno_not_observed",
            "filesystems": self.volumes.len(),
            "capacity_bytes": self.capacity_bytes,
            "capacity_inodes": self.capacity_inodes,
            "hit_evidence": "sampled_saturation_positive_only",
            "enforcement_lost": self.failure,
            "dev_shm": "read_only",
        })
    }

    /// Positive saturation evidence only. A missed transient stays unknown.
    pub(super) fn sample(&mut self) -> io::Result<Vec<String>> {
        if let Some(failure) = &self.failure {
            return Err(io::Error::other(failure.clone()));
        }
        let result = self.sample_inner();
        if let Err(err) = &result {
            self.failure = Some(err.to_string());
        }
        result
    }

    pub(super) fn lost(&self) -> bool {
        self.failure.is_some()
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
        for limit in &mut self.limits {
            let full = if limit.key == "storage" {
                bytes_full
            } else {
                inodes_full
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
    fn a_lost_enforcement_no_longer_claims_applied() {
        let mut storage = Storage {
            volumes: Vec::new(),
            limits: vec![AppliedLimit {
                key: "storage".into(),
                requested: "1".into(),
                required: true,
                applied: true,
                mechanism: Some("bounded-tmpfs-capacity".into()),
                scope: Some("tree".into()),
                hit: None,
            }],
            capacity_bytes: Some(1),
            capacity_inodes: None,
            failure: None,
        };
        assert!(storage.limits()[0].applied);
        assert!(storage.loss().is_none());
        storage.failure = Some("tmpfs capacity changed after admission".into());
        let row = &storage.limits()[0];
        // Audit 2026-10-08 L2: like `record_limit_unapplied`'s rows, the
        // ceiling no longer claims `applied`, and its evidence is unknown.
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
