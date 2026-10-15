use super::*;
use std::{
    fs, io,
    os::unix::{
        ffi::OsStringExt,
        fs::{PermissionsExt, symlink},
    },
};

fn arguments() -> Vec<OsString> {
    vec![
        "/bin/echo".into(),
        "".into(),
        "a b".into(),
        OsString::from_vec(b"private\xff\n".to_vec()),
    ]
}

#[test]
fn argv_capture_preserves_native_bytes_empty_arguments_and_every_truncation_boundary() {
    let expected = b"/bin/echo\0\0a b\0private\xff\n\0";
    let args = arguments();
    assert_eq!(observed_bytes(&args).unwrap(), expected.len() as u64);
    for limit in 0..=expected.len() + 1 {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.path().join("artifacts")).unwrap();
        fs::set_permissions(
            root.path().join("artifacts"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let mut metadata = json!({"state":"not_captured"});
        save(root.path(), &args, limit as u64, &mut metadata).unwrap();
        let kept = limit.min(expected.len());
        assert_eq!(
            fs::read(root.path().join("artifacts/argv.bin")).unwrap(),
            expected[..kept]
        );
        assert_eq!(metadata["state"], "captured");
        assert_eq!(metadata["observed_bytes"], expected.len());
        assert_eq!(metadata["stored_bytes"], kept);
        assert_eq!(metadata["truncated"], kept < expected.len());
        assert_eq!(metadata["encoding"], "nul_delimited");
        assert_eq!(
            fs::metadata(root.path().join("artifacts/argv.bin"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let prior = fs::read(root.path().join("artifacts/argv.bin")).unwrap();
        assert!(save(root.path(), &["replacement".into()], 100, &mut metadata).is_err());
        assert_eq!(
            fs::read(root.path().join("artifacts/argv.bin")).unwrap(),
            prior
        );
    }
}

#[test]
fn argv_short_writes_keep_the_exact_prefix_before_storage_failure() {
    struct Disk {
        bytes: Vec<u8>,
        remaining: usize,
    }
    impl Write for Disk {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            let n = bytes.len().min(self.remaining).min(2);
            self.bytes.extend_from_slice(&bytes[..n]);
            self.remaining -= n;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut disk = Disk {
        bytes: vec![],
        remaining: 12,
    };
    let mut stored = 0;
    assert!(write_prefix(&mut disk, &arguments(), 20, &mut stored).is_err());
    assert_eq!(stored, 12);
    assert_eq!(disk.bytes, b"/bin/echo\0\0a");
}

#[test]
fn argv_capture_refuses_symlinked_storage_and_nul_arguments() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let other = tempfile::tempdir().unwrap();
    symlink(other.path(), root.path().join("artifacts")).unwrap();
    assert!(save(root.path(), &arguments(), 100, &mut Value::Null).is_err());
    assert!(!other.path().join("argv.bin").exists());
    assert!(observed_bytes(&[OsString::from_vec(b"x\0y".to_vec())]).is_err());
}
