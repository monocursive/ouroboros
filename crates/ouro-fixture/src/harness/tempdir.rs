//! A private temporary directory, without a runtime dependency.
//!
//! The J1 contract allows `tempfile` only as a dev-dependency, and the harness
//! lives in the library so `ouro-jail`'s own tests can use it. Forty lines of
//! `mkdtemp` keep the binary's dependency set to `libc`, `clap`, `serde` and
//! `serde_json`.

use std::ffi::{CString, OsString};
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

/// A directory removed when this value is dropped, unless `OURO_HARNESS_KEEP`
/// is set, which leaves it behind and prints the path for inspection.
pub struct TempDir {
    path: PathBuf,
    keep: bool,
}

impl TempDir {
    /// Create `$TMPDIR/<prefix>-XXXXXX` with mode 0700.
    pub fn new(prefix: &str) -> io::Result<TempDir> {
        let mut template = std::env::temp_dir().into_os_string().into_vec();
        if template.last() != Some(&b'/') {
            template.push(b'/');
        }
        template.extend_from_slice(prefix.as_bytes());
        template.extend_from_slice(b"-XXXXXX");
        let c = CString::new(template).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "TMPDIR contains a NUL byte")
        })?;
        let mut bytes = c.into_bytes_with_nul();
        // SAFETY: `bytes` is a live NUL-terminated buffer ending in the six
        // `X` characters `mkdtemp` requires, and it is written in place.
        let p = unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast::<libc::c_char>()) };
        if p.is_null() {
            return Err(io::Error::last_os_error());
        }
        bytes.pop(); // drop the NUL
        Ok(TempDir {
            path: PathBuf::from(OsString::from_vec(bytes)),
            keep: std::env::var_os("OURO_HARNESS_KEEP").is_some(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Do not remove this directory when it is dropped.
    pub fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if self.keep {
            eprintln!("ouro-fixture harness: kept {}", self.path.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_creates_a_private_directory_and_removes_it_on_drop() {
        let path;
        {
            let dir = TempDir::new("ouro-fixture-test").unwrap();
            path = dir.path().to_path_buf();
            assert!(path.is_dir());
            std::fs::write(path.join("inside"), b"x").unwrap();

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o700, "mkdtemp must create mode 0700");
            }
        }
        assert!(!path.exists(), "the directory and its contents are removed");
    }

    #[test]
    fn two_directories_never_collide() {
        let a = TempDir::new("ouro-fixture-test").unwrap();
        let b = TempDir::new("ouro-fixture-test").unwrap();
        assert_ne!(a.path(), b.path());
    }
}
