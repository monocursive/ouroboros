//! Unprivileged readback of the caller's ext4/XFS user hard quotas.
//! The operator provisions limits; the runtime never changes global quota state.
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

// linux/dqblk_xfs.h: Q_XGETQSTATV's version-1 ABI, also implemented by ext4.
#[repr(C)]
#[derive(Default)]
struct QuotaState {
    version: i8,
    pad1: u8,
    flags: u16,
    in_core: u32,
    files: [[u64; 3]; 3],
    grace: [i32; 3],
    warnings: [u16; 3],
    pad3: u16,
    pad4: u32,
    padding: [u64; 7],
}

pub(super) struct Quota {
    pub bytes: Option<u64>,
    pub inodes: Option<u64>,
    pub bytes_used: u64,
    pub inodes_used: u64,
}

pub(super) fn read(file: &File, uid: u32) -> io::Result<Quota> {
    if uid == 0 {
        return Err(io::Error::other(
            "root is not an admissible user-quota identity",
        ));
    }
    let mut state = QuotaState {
        version: 1,
        ..QuotaState::default()
    };
    if super::stat(file)?.f_type == libc::XFS_SUPER_MAGIC {
        // XFS realtime space has a separate quota, not Q_GETQUOTA's block
        // hard limit. Refuse that filesystem layout rather than overlook it.
        // The mount is pinned; reopening its descriptor permits ioctl on an
        // O_PATH grant. O_NONBLOCK also avoids waiting on special-file grants.
        let readable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        // xfs_fsop_geom: 256 bytes, rtblocks at byte 40. Aligned storage
        // avoids binding unused fields to a particular kernel revision.
        let mut geometry = [0u64; 32];
        const XFS_IOC_FSGEOMETRY: libc::c_ulong = 0x8100_587e;
        // SAFETY: a live descriptor and the full initialized ioctl output ABI.
        if unsafe {
            libc::ioctl(
                readable.as_raw_fd(),
                XFS_IOC_FSGEOMETRY,
                geometry.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if geometry[5] != 0 {
            return Err(io::Error::other(
                "XFS realtime storage quotas are not supported",
            ));
        }
    }
    // SAFETY: a pinned descriptor and the exact, initialized 160-byte Linux ABI.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            file.as_raw_fd(),
            libc::QCMD((i32::from(b'X') << 8) | 8, libc::USRQUOTA),
            0,
            &raw mut state,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // Accounting alone (e.g. XFS uqnoenforce) is not a hard limit.
    if state.version != 1 || state.flags & 3 != 3 {
        return Err(io::Error::other(
            "user quota accounting and enforcement must both be active",
        ));
    }
    // SAFETY: dqblk is an integer-only kernel output structure.
    let mut quota: libc::dqblk = unsafe { std::mem::zeroed() };
    // SAFETY: the caller may query its own uid; the kernel fills a live dqblk.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            file.as_raw_fd(),
            libc::QCMD(libc::Q_GETQUOTA, libc::USRQUOTA),
            uid,
            &raw mut quota,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // QIF_BLIMITS, QIF_SPACE, QIF_ILIMITS and QIF_INODES must all be present.
    if quota.dqb_valid & 15 != 15 {
        return Err(io::Error::other("incomplete user quota readback"));
    }
    Ok(Quota {
        bytes: if quota.dqb_bhardlimit == 0 {
            None
        } else {
            Some(
                quota
                    .dqb_bhardlimit
                    .checked_mul(1024)
                    .ok_or_else(|| io::Error::other("quota byte capacity overflow"))?,
            )
        },
        inodes: (quota.dqb_ihardlimit != 0).then_some(quota.dqb_ihardlimit),
        bytes_used: quota.dqb_curspace,
        inodes_used: quota.dqb_curinodes,
    })
}

/// Every writable inode must charge this uid, including directories whose
/// entries consume blocks. Do not follow symlinks. Read-only submounts need
/// no quota; other writable filesystems are checked by the mount inventory.
/// Hard links are denied by the storage baseline so foreign-owned inodes
/// cannot be imported after this walk. The target has not been released yet.
pub(super) fn check_owners(
    root: &File,
    uid: u32,
    scanned: &mut usize,
    deadline: super::super::clock::Deadline,
) -> io::Result<()> {
    let device = root.metadata()?.dev();
    walk(root, uid, device, 0, &mut HashSet::new(), scanned, deadline)
}

fn walk(
    file: &File,
    uid: u32,
    device: u64,
    depth: usize,
    seen: &mut HashSet<(u64, u64)>,
    scanned: &mut usize,
    deadline: super::super::clock::Deadline,
) -> io::Result<()> {
    if deadline.expired() {
        return Err(io::Error::other("quota ownership walk deadline expired"));
    }
    let meta = file.metadata()?;
    let mut stat = std::mem::MaybeUninit::uninit();
    // SAFETY: a live descriptor and writable statvfs output.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatvfs initialized the output on success.
    let stat = unsafe { stat.assume_init() };
    if meta.dev() != device || stat.f_flag & libc::ST_RDONLY != 0 {
        return Ok(());
    }
    if meta.uid() != uid {
        return Err(io::Error::other(
            "writable disk inode is owned by a different quota identity",
        ));
    }
    if !meta.is_dir() || !seen.insert((meta.dev(), meta.ino())) {
        return Ok(());
    }
    if depth >= 128 {
        return Err(io::Error::other("quota ownership walk exceeds depth 128"));
    }
    let path = format!("/proc/self/fd/{}", file.as_raw_fd());
    for entry in fs::read_dir(&path)? {
        *scanned += 1;
        if *scanned > 100_000 {
            return Err(io::Error::other(
                "quota ownership walk exceeds 100000 entries",
            ));
        }
        let child = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(entry?.path())?;
        walk(&child, uid, device, depth + 1, seen, scanned, deadline)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_state_uses_the_version_one_kernel_layout() {
        assert_eq!(std::mem::size_of::<QuotaState>(), 160);
        assert_eq!(std::mem::offset_of!(QuotaState, flags), 2);
        assert_eq!(std::mem::offset_of!(QuotaState, files), 8);
    }

    #[test]
    fn ownership_scan_is_bounded_and_never_follows_symlinks() {
        use super::super::super::clock::Deadline;
        use std::time::Duration;
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/definitely-not-a-quota-fixture", root.path().join("link"))
            .unwrap();
        let root = File::open(root.path()).unwrap();
        let uid = root.metadata().unwrap().uid();
        assert!(check_owners(&root, uid, &mut 0, Deadline::after(Duration::from_secs(5))).is_ok());
        let exhausted = check_owners(
            &root,
            uid,
            &mut 100_000,
            Deadline::after(Duration::from_secs(5)),
        );
        assert!(
            exhausted
                .unwrap_err()
                .to_string()
                .contains("100000 entries")
        );
        let expired = check_owners(&root, uid, &mut 0, Deadline::after(Duration::ZERO));
        assert!(
            expired
                .unwrap_err()
                .to_string()
                .contains("deadline expired")
        );
        let wrong_owner = check_owners(
            &root,
            uid + 1,
            &mut 0,
            Deadline::after(Duration::from_secs(5)),
        );
        assert!(
            wrong_owner
                .unwrap_err()
                .to_string()
                .contains("different quota identity")
        );
    }
}
