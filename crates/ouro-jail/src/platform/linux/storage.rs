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
use std::path::PathBuf;

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
            Ok((value.f_bavail == 0, value.f_ffree == 0))
        }
    }
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
            // Bubblewrap binds these device inodes individually. Writing to
            // them cannot allocate filesystem data or create sibling files.
            // Never exempt an arbitrary operator-granted device.
            if metadata.file_type().is_char_device()
                && matches!(
                    (libc::major(metadata.rdev()), libc::minor(metadata.rdev())),
                    (1, 3 | 5 | 7 | 8 | 9) | (5, 0)
                )
            {
                continue;
            }
            // Process metadata and ptys do not allocate filesystem data.
            if [libc::PROC_SUPER_MAGIC, libc::DEVPTS_SUPER_MAGIC].contains(&value.f_type) {
                continue;
            }
            let device = metadata.dev();
            let (uid, capacity_bytes, capacity_inodes) = if value.f_type == libc::TMPFS_MAGIC {
                let block_size = u64::try_from(value.f_bsize).map_err(io::Error::other)?;
                (
                    None,
                    if value.f_blocks == 0 {
                        None
                    } else {
                        Some(
                            value
                                .f_blocks
                                .checked_mul(block_size)
                                .ok_or_else(|| io::Error::other("storage capacity overflow"))?,
                        )
                    },
                    (value.f_files != 0).then_some(value.f_files),
                )
            } else if [libc::EXT4_SUPER_MAGIC, libc::XFS_SUPER_MAGIC].contains(&value.f_type) {
                // SAFETY: geteuid has no arguments or memory effects.
                let uid = unsafe { libc::geteuid() };
                let quota = quota::read(&file, uid).map_err(|err| {
                    io::Error::other(format!(
                        "writable disk mount {} needs an enforced user hard quota: {err}",
                        String::from_utf8_lossy(&point)
                    ))
                })?;
                // Check every grant, even another bind of an already-counted
                // filesystem: its existing inodes may have different owners.
                quota::check_owners(&file, uid, &mut scanned, deadline)?;
                (Some(uid), quota.bytes, quota.inodes)
            } else {
                return Err(io::Error::other(format!(
                    "writable mount {} needs bounded tmpfs or ext4/XFS user hard quotas",
                    String::from_utf8_lossy(&point)
                )));
            };
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
        self.limits.clone()
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
