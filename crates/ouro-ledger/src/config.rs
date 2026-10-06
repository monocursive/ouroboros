//! Retention is resolved by the writer from the operator configuration at startup.
use crate::protocol::{LedgerError, Result};
use ouro_records::retention::LedgerRetention;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    ledger: Option<LedgerRetention>,
    // Other consumers own validation of their own sections.
    #[serde(rename = "jail")]
    _jail: Option<toml::Value>,
    #[serde(rename = "jail_host")]
    _jail_host: Option<toml::Value>,
}

pub fn load() -> Result<LedgerRetention> {
    let directory = std::env::var_os("OURO_CONFIG_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| Path::new(&p).join(".config/ouro")))
        .ok_or_else(|| {
            LedgerError("HOME or OURO_CONFIG_DIR is required to locate retention settings".into())
        })?;
    load_path(&directory.join("config.toml"))
}

pub fn load_path(path: &Path) -> Result<LedgerRetention> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LedgerRetention::default()),
        Err(e) => return Err(e.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(LedgerError(
            "retention config must be an owned regular file without group/other write access"
                .into(),
        ));
    }
    let mut text = String::new();
    file.take(65_537).read_to_string(&mut text)?;
    if text.len() > 65_536 {
        return Err(LedgerError("retention config exceeds 64 KiB".into()));
    }
    let config: Config =
        toml::from_str(&text).map_err(|e| LedgerError(format!("invalid operator config: {e}")))?;
    let Config {
        ledger,
        _jail: _,
        _jail_host: _,
    } = config;
    let retention = ledger.unwrap_or_default();
    retention
        .resolve(None, None)
        .map_err(|e| LedgerError(e.into()))?;
    Ok(retention)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn config_is_bounded_strict_and_does_not_silently_default_invalid_retention() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        assert_eq!(
            load_path(&path)
                .unwrap()
                .resolve(None, None)
                .unwrap()
                .retain_days,
            90
        );
        for text in [
            "[ledger]\nretain='0d'",
            "[ledger]\nretain='36501d'",
            "[ledger]\nretain='1h'",
            "[ledger]\nretain=90",
            "[ledger]\nretian='1d'",
            "[ledger]\nretain='2d'\ncapture_retain='3d'",
            "[ledger]\nretain='1d'\nretain='2d'",
            "[ledger]\nretain='+1d'",
            "[unknown]\nretain='1d'",
        ] {
            std::fs::write(&path, text).unwrap();
            assert!(load_path(&path).is_err(), "{text}");
        }
        std::fs::write(
            &path,
            "[jail]\nprofile='tool'\n[ledger]\nretain='30d'\ncapture_retain='2d'",
        )
        .unwrap();
        let config = load_path(&path).unwrap();
        assert_eq!(config.resolve(None, None).unwrap().capture_retain_days, 2);
        assert_eq!(config.resolve(Some(60), Some(3)).unwrap().retain_days, 60);
        assert!(config.resolve(Some(1), None).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load_path(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(load_path(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, " ".repeat(65_537)).unwrap();
        assert!(load_path(&path).is_err());
    }
}
