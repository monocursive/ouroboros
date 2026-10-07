//! Opt-in raw arguments: NUL-delimited native bytes, with a bounded prefix.
use super::{Result, error, write_capture};
use crate::bundle::files;
use serde_json::{Value, json};
use std::{ffi::OsString, io::Write, os::unix::ffi::OsStrExt, path::Path};

fn observed_bytes(argv: &[OsString]) -> Result<u64> {
    argv.iter().try_fold(0u64, |n, arg| {
        if arg.as_bytes().contains(&0) {
            return Err(error("argv cannot contain NUL"));
        }
        n.checked_add(arg.len() as u64)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| error("argv capture size overflow"))
    })
}

fn write_prefix(
    writer: &mut impl Write,
    argv: &[OsString],
    limit: u64,
    stored: &mut u64,
) -> Result<()> {
    for arg in argv {
        for bytes in [arg.as_bytes(), b"\0".as_slice()] {
            let keep = (limit - *stored).min(bytes.len() as u64) as usize;
            write_capture(writer, &bytes[..keep], stored)?;
        }
        if *stored == limit {
            break;
        }
    }
    Ok(())
}

// This helper is portable for file/encoding tests; actual launch remains Linux-only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn save(root: &Path, argv: &[OsString], limit: u64, metadata: &mut Value) -> Result<()> {
    let observed = observed_bytes(argv)?;
    let root = files::directory(root)?;
    files::private(&root)?;
    let artifacts = files::child_dir(&root, "artifacts")?;
    files::private(&artifacts)?;
    let mut file = files::member(&artifacts, "argv.bin", true)?;
    *metadata = json!({"state":"incomplete", "encoding":"nul_delimited", "argument_count":argv.len(),
        "limit_bytes":limit, "observed_bytes":observed, "stored_bytes":0,
        "truncated":observed>0, "path":"artifacts/argv.bin"});
    let mut stored = 0;
    let result = write_prefix(&mut file, argv, limit, &mut stored);
    metadata["stored_bytes"] = json!(stored);
    metadata["truncated"] = json!(observed > stored);
    result?;
    file.sync_all()?;
    artifacts.sync_all()?;
    metadata["state"] = json!("captured");
    Ok(())
}

#[cfg(test)]
mod tests;
