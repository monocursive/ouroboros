//! The durable replacement of a record (§7): create a new temporary file
//! beside it, write, sync the file, rename (or link, for the exclusive
//! claim), sync the directory, through the persistence seam
//! ([`super::persist`]); and what a crash leaves.

use std::fs::File;
use std::path::{Path, PathBuf};

use super::{
    AttemptDir, CrashPoint, POLICY_NAME, PersistIo, RECEIPT_NAME, STATE_NAME, Site, crash_point,
    current_io, write_failed,
};
use crate::records::JailError;

/// Writes every byte through the seam, one `write` at a time: a short write
/// is resumed at its offset, and an error after it is the write's error.
fn write_fully(
    io: &dyn PersistIo,
    site: Site,
    file: &mut File,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        match io.write(site, file, &bytes[written..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "the write made no progress",
                ));
            }
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// A pending durable replacement: written and synced, not yet renamed.
///
/// Dropping it without [`TempWrite::commit`] leaves the target file exactly as
/// it was, which is the "either the old or the new file" property of R02, and
/// removes the temporary file. A crash leaves the temporary file behind;
/// [`leftover_temp_files`] names what it left.
pub struct TempWrite<'a> {
    temp: PathBuf,
    target: PathBuf,
    site: Site,
    committed: bool,
    io: &'a dyn PersistIo,
}

impl std::fmt::Debug for TempWrite<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempWrite")
            .field("temp", &self.temp)
            .field("target", &self.target)
            .field("site", &self.site)
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

/// What an exclusive publication found (§7's claim).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Published {
    /// The complete file now exists under the target name.
    Created,
    /// The target already existed; nothing was published.
    Exists,
}

impl<'a> TempWrite<'a> {
    /// Creates the temporary file for a replacement of `target` at `site`
    /// beside it, through `io`, writes `bytes` and syncs it.
    ///
    /// The temporary file is removed on any failure here, so a failed write
    /// never leaves a partial file behind except when the process dies.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the file cannot be created,
    /// written or synced.
    pub fn create_at(
        site: Site,
        target: &Path,
        bytes: &[u8],
        io: &'a dyn PersistIo,
    ) -> Result<Self, JailError> {
        let directory = target.parent().ok_or_else(|| {
            write_failed(
                target,
                &std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent directory"),
            )
        })?;
        let name = target
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "state".to_owned());
        // A random UUIDv4: no two writers, in this process or another, race
        // on the same temporary name, and nobody can plant it in advance.
        let temp = directory.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
        let mut file = io
            .create_new(site, &temp)
            .map_err(|error| write_failed(&temp, &error))?;
        let pending = TempWrite {
            temp,
            target: target.to_path_buf(),
            site,
            committed: false,
            io,
        };
        write_fully(io, site, &mut file, bytes)
            .map_err(|error| write_failed(&pending.temp, &error))?;
        crash_point(site, CrashPoint::TempWritten);
        io.sync_file(site, &file)
            .map_err(|error| write_failed(&pending.temp, &error))?;
        crash_point(site, CrashPoint::TempSynced);
        Ok(pending)
    }

    /// The temporary file's path, for tests that inspect the failure window.
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        &self.temp
    }

    fn directory(&self) -> &Path {
        self.target
            .parent()
            .expect("create_at() already established a parent")
    }

    /// Renames the temporary file over the target and syncs the directory.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the rename or the directory
    /// sync fails; a rename that is not followed by a successful directory sync
    /// is reported rather than acknowledged.
    pub fn commit(mut self) -> Result<(), JailError> {
        self.io
            .rename(self.site, &self.temp, &self.target)
            .map_err(|error| write_failed(&self.target, &error))?;
        self.committed = true;
        crash_point(self.site, CrashPoint::Renamed);
        let directory = self.directory().to_path_buf();
        self.io
            .sync_dir(self.site, &directory)
            .map_err(|error| write_failed(&directory, &error))?;
        crash_point(self.site, CrashPoint::DirSynced);
        Ok(())
    }

    /// Publishes the complete file under the target name only if nothing is
    /// there yet (§7: "Claim it with exclusive creation"), then syncs the
    /// directory.
    ///
    /// A `link` is both exclusive and atomic: the name appears with every
    /// byte already written and synced, so no reader, and no crash, can ever
    /// see a partial claim. The temporary name is then only a second link to
    /// the same file and is removed; one a crash leaves is harmless.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the link fails for a
    /// reason other than an existing target, or the directory sync fails.
    pub fn publish_new(mut self) -> Result<Published, JailError> {
        match self.io.link(self.site, &self.temp, &self.target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(Published::Exists);
            }
            Err(error) => return Err(write_failed(&self.target, &error)),
        }
        self.committed = true;
        crash_point(self.site, CrashPoint::Renamed);
        let _ = self.io.remove(self.site, &self.temp);
        let directory = self.directory().to_path_buf();
        self.io
            .sync_dir(self.site, &directory)
            .map_err(|error| write_failed(&directory, &error))?;
        crash_point(self.site, CrashPoint::DirSynced);
        Ok(Published::Created)
    }
}

impl Drop for TempWrite<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Best effort: the target is intact either way, and a leftover
            // temporary file is visible state rather than a silent overwrite.
            let _ = self.io.remove(self.site, &self.temp);
        }
    }
}

/// Replaces `target` durably (§7) through this thread's seam.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when any step fails.
pub fn replace_atomically(target: &Path, bytes: &[u8]) -> Result<(), JailError> {
    replace_atomically_at(Site::Unnamed, target, bytes)
}

/// [`replace_atomically`] at a named site, through this thread's seam.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when any step fails.
pub fn replace_atomically_at(site: Site, target: &Path, bytes: &[u8]) -> Result<(), JailError> {
    let io = current_io();
    TempWrite::create_at(site, target, bytes, &*io)?.commit()
}

/// Creates `target` with `bytes` only if it does not exist, never exposing a
/// partial file (§7's claim), through this thread's seam.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when any step fails.
pub fn create_exclusively_at(
    site: Site,
    target: &Path,
    bytes: &[u8],
) -> Result<Published, JailError> {
    let io = current_io();
    TempWrite::create_at(site, target, bytes, &*io)?.publish_new()
}

/// The temporary files a crash left beside this attempt's records: names of
/// the form `.<record>.<uuid>.tmp` directly in the attempt root. They never
/// replaced anything (the prior file is intact), and nothing reads them.
///
/// # Errors
/// Returns the listing failure.
pub fn leftover_temp_files(attempt_dir: &AttemptDir) -> std::io::Result<Vec<String>> {
    leftover_temp_files_within(attempt_dir, usize::MAX).map(|listing| listing.names)
}

// Gc's leftovers (S7: the listing is charged)
/// [`leftover_temp_files`] reading at most `max_entries` names of the
/// attempt root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TempListing {
    /// The names found, sorted.
    pub names: Vec<String>,
    /// Names read from the attempt root (what the listing costs).
    pub read: usize,
    /// Whether every name was read before the bound.
    pub complete: bool,
}

/// [`leftover_temp_files`] within a bound of `max_entries` names read.
///
/// # Errors
/// Returns the listing failure.
pub fn leftover_temp_files_within(
    attempt_dir: &AttemptDir,
    max_entries: usize,
) -> std::io::Result<TempListing> {
    let mut names = Vec::new();
    let mut read = 0usize;
    let mut complete = true;
    for entry in std::fs::read_dir(attempt_dir.root())? {
        if read == max_entries {
            complete = false;
            break;
        }
        read += 1;
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') && name.ends_with(".tmp") {
            names.push(name);
        }
    }
    names.sort();
    Ok(TempListing {
        names,
        read,
        complete,
    })
}

/// The records a durable replacement writes directly in the attempt root.
pub const ROOT_RECORDS: [&str; 3] = [STATE_NAME, POLICY_NAME, RECEIPT_NAME];

/// Whether `name` is exactly what [`TempWrite`] names the temporary file of
/// one of [`ROOT_RECORDS`]: `.<record>.<uuid>.tmp`, the uuid hyphenated.
/// Only such a name is ever removed by `gc`; anything else is reported.
#[must_use]
pub fn is_record_temp_name(name: &str) -> bool {
    let Some(middle) = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((record, id)) = middle.rsplit_once('.') else {
        return false;
    };
    ROOT_RECORDS.contains(&record)
        && id.len() == 36
        && uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.hyphenated().to_string() == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_temporary_name_of_a_root_record_is_ours() {
        let id = uuid::Uuid::new_v4().to_string();
        for record in ROOT_RECORDS {
            assert!(
                is_record_temp_name(&format!(".{record}.{id}.tmp")),
                "{record}"
            );
        }
        for other in [
            format!(".trace.ndjson.{id}.tmp"),
            format!(".jail.json.{}.tmp", id.to_uppercase()),
            format!(".jail.json.{}.tmp", id.replace('-', "")),
            format!("jail.json.{id}.tmp"),
            format!(".jail.json.{id}"),
            ".jail.json..tmp".to_owned(),
            ".planted.tmp".to_owned(),
        ] {
            assert!(!is_record_temp_name(&other), "{other}");
        }
    }
}
