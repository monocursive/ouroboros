//! Flat, descriptor-relative bundle I/O. No bundle-controlled path is followed.
use crate::protocol::{LedgerError, Result};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

fn name(value: &str) -> Result<CString> {
    if value.is_empty() || value == "." || value == ".." || value.contains('/') {
        return Err(LedgerError("unsafe bundle member name".into()));
    }
    CString::new(value).map_err(|_| LedgerError("unsafe bundle member name".into()))
}

fn owned(fd: libc::c_int) -> Result<File> {
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the successful open/dup caller transfers its unique descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn directory(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}

pub(super) fn child_dir(parent: &File, leaf: &str) -> Result<File> {
    let leaf = name(leaf)?;
    // SAFETY: parent and the C string remain live through openat.
    owned(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

pub(super) fn private(file: &File) -> Result<()> {
    let m = file.metadata()?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(LedgerError(
            "capture source must be owned and private".into(),
        ));
    }
    Ok(())
}

pub(super) fn member(parent: &File, leaf: &str, create: bool) -> Result<File> {
    let leaf = name(leaf)?;
    let mode = if create {
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL
    } else {
        libc::O_RDONLY
    };
    // SAFETY: parent and the C string remain live through openat.
    let file = owned(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            mode | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    })?;
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 {
        return Err(LedgerError(
            "bundle refuses nonregular or hard-linked files".into(),
        ));
    }
    Ok(file)
}

pub(super) fn names(parent: &File) -> Result<BTreeSet<String>> {
    // Open a new directory description: dup would share the enumeration offset.
    let dot = CString::new(".").expect("literal");
    // SAFETY: valid live descriptor and C string.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: ownership passes to fdopendir on success, otherwise we close it.
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(error.into());
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let dir = Directory(dir);
    let mut result = BTreeSet::new();
    loop {
        // POSIX distinguishes EOF from a directory read failure through errno.
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        // SAFETY: dir is exclusively owned; each name is copied before readdir repeats.
        let entry = unsafe { libc::readdir(dir.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error.into());
            }
            break;
        }
        let leaf = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()
            .map_err(|_| LedgerError("non-UTF8 bundle member".into()))?;
        if leaf == "." || leaf == ".." {
            continue;
        }
        result.insert(leaf.to_owned());
        if result.len() > 5 {
            return Err(LedgerError("unexpected bundle members".into()));
        }
    }
    Ok(result)
}

pub(super) struct Staging {
    pub dir: File,
    parent: File,
    temporary: CString,
    destination: CString,
    published: bool,
}

impl Staging {
    pub fn new(output: &Path) -> Result<Self> {
        let leaf = output
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| LedgerError("bundle output needs a UTF-8 directory name".into()))?;
        let destination = name(leaf)?;
        let parent_path = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = directory(parent_path)?;
        let temporary = name(&format!(".ouro-bundle-{}", uuid::Uuid::new_v4().simple()))?;
        // SAFETY: parent and C strings remain live throughout the operation.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), temporary.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let dir = match child_dir(&parent, temporary.to_str().expect("UUID")) {
            Ok(dir) => dir,
            Err(error) => {
                // SAFETY: remove only the empty private directory just created.
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(error);
            }
        };
        Ok(Self {
            dir,
            parent,
            temporary,
            destination,
            published: false,
        })
    }

    pub fn publish(mut self) -> Result<()> {
        self.dir.sync_all()?;
        // SAFETY: both names are single components relative to a pinned parent.
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                self.parent.as_raw_fd(),
                self.temporary.as_ptr(),
                self.parent.as_raw_fd(),
                self.destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                self.parent.as_raw_fd(),
                self.temporary.as_ptr(),
                self.parent.as_raw_fd(),
                self.destination.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let result = {
            return Err(LedgerError(
                "bundle publication unsupported on this platform".into(),
            ));
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.published = true;
        self.parent.sync_all().map_err(|e| LedgerError(format!(
            "bundle was published but parent sync failed: {e}; verify the destination before retrying")))
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        for leaf in [
            "bundle.json",
            "events.ndjson",
            "receipts.json",
            "stdout.bin",
            "stderr.bin",
        ] {
            let leaf = CString::new(leaf).expect("literal");
            // SAFETY: only fixed members of our pinned temporary directory are removed.
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), leaf.as_ptr(), 0);
            }
        }
        unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.temporary.as_ptr(),
                libc::AT_REMOVEDIR,
            );
        }
    }
}
