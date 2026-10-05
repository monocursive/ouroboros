//! Disposable SQLite query projection. Canonical streams are the only authority.
//!
//! Callers update this index after completing canonical persistence and must keep
//! index errors separate from admission and acknowledgement results. Startup
//! rebuilds from recovered records; no state is ever recovered from this file.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use rusqlite::{Connection, OpenFlags, config::DbConfig, limits::Limit, params};

use crate::protocol::{LedgerError, MAX_FRAME_BYTES, Result, RunRecord};

const INDEX: &str = "index.sqlite";
const SIDECARS: [&str; 3] = [
    "index.sqlite-journal",
    "index.sqlite-wal",
    "index.sqlite-shm",
];
const APPLICATION_ID: i32 = 0x4f55_524f; // OURO
const VERSION: i32 = 1;
const MAX_RUN_BYTES: usize = 4 * MAX_FRAME_BYTES;
// Bound a disposable file before asking SQLite to parse it and bound growth.
const MAX_INDEX_BYTES: u64 = 256 * 1024 * 1024;
const RUNS_SQL: &str = "CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    state TEXT NOT NULL,
    child_protection TEXT NOT NULL,
    settlement TEXT NOT NULL,
    head_seq TEXT NOT NULL,
    head_digest TEXT,
    run_json TEXT NOT NULL
) STRICT";
const UPSERT: &str = "INSERT INTO runs
    (run_id, attempt_id, request_id, state, child_protection, settlement,
     head_seq, head_digest, run_json)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
    ON CONFLICT(run_id) DO UPDATE SET
      attempt_id=excluded.attempt_id, request_id=excluded.request_id,
      state=excluded.state, child_protection=excluded.child_protection,
      settlement=excluded.settlement, head_seq=excluded.head_seq,
      head_digest=excluded.head_digest, run_json=excluded.run_json";

pub struct Projection {
    root: PathBuf,
    directory: File,
    file: File,
    connection: Connection,
}

fn sqlite<T>(result: rusqlite::Result<T>) -> Result<T> {
    result.map_err(|error| LedgerError(format!("SQLite projection: {error}")))
}

fn private_metadata(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err(LedgerError("unsafe SQLite projection path".into()));
    }
    Ok(())
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn private_file(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    private_metadata(&file.metadata()?, false)?;
    Ok(file)
}

fn sidecars(root: &Path) -> Result<()> {
    for name in SIDECARS {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let file = private_file(&path, false)?;
                if file.metadata()?.len() > MAX_INDEX_BYTES {
                    return Err(LedgerError(
                        "SQLite projection sidecar exceeds its bound".into(),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn connection(path: &Path) -> Result<Connection> {
    // Do not let SQLite create a file with process-umask-dependent permissions.
    // SQLite's NOFOLLOW rejects symlinks in ancestors too, including macOS's
    // /var alias and Linux's pinned /proc/self/fd directory. Resolve those
    // aliases only after the file has been opened and validated without following
    // its final component; the caller checks inode identity before writing SQL.
    let resolved = path.canonicalize()?;
    let connection = sqlite(Connection::open_with_flags(
        resolved,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    ))?;
    // This disposable work runs on the sole writer after handing off a reply.
    // Waiting on a projection lock would still delay the next durable request.
    sqlite(connection.busy_timeout(Duration::ZERO))?;
    sqlite(connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true))?;
    sqlite(connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false))?;
    sqlite(connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_RUN_BYTES as i32 + 4096))?;
    sqlite(connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 16_384))?;
    sqlite(connection.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0))?;
    Ok(connection)
}

fn valid_database(connection: &Connection) -> bool {
    let identity = connection.query_row(
        "SELECT application_id, user_version FROM pragma_application_id, pragma_user_version",
        [],
        |row| Ok((row.get::<_, i32>(0)?, row.get::<_, i32>(1)?)),
    );
    if identity != Ok((APPLICATION_ID, VERSION)) {
        return false;
    }
    let schema = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='runs'",
        [],
        |row| row.get::<_, String>(0),
    );
    let objects = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get::<_, i64>(0),
    );
    schema.is_ok_and(|schema| schema == RUNS_SQL)
        && objects == Ok(1)
        && connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
            .is_ok_and(|check| check == "ok")
}

impl Projection {
    pub fn open(root: &Path) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)?;
        private_metadata(&directory.metadata()?, true)?;
        // Linux opens remain relative to the pinned directory even if an
        // ancestor is renamed. macOS checks the original directory identity.
        #[cfg(target_os = "linux")]
        let anchored = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        #[cfg(not(target_os = "linux"))]
        let anchored = root.to_path_buf();
        sidecars(&anchored)?;
        let path = anchored.join(INDEX);
        let file = if fs::symlink_metadata(&path)
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        {
            private_file(&path, true)?
        } else {
            private_file(&path, false)?
        };
        let connection = connection(&path)?;
        let mut projection = Self {
            root: root.to_path_buf(),
            directory,
            file,
            connection,
        };
        // SQLite has not executed mutating SQL yet. Verify the preopened file
        // and directory still name the same private inodes before any writes.
        projection.check_paths()?;
        if projection.file.metadata()?.len() > MAX_INDEX_BYTES
            || !valid_database(&projection.connection)
        {
            projection.reset()?;
        }
        sqlite(projection.connection.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
             PRAGMA temp_store=MEMORY;",
        ))?;
        let page_size: i64 = sqlite(projection.connection.query_row(
            "PRAGMA page_size",
            [],
            |row| row.get(0),
        ))?;
        sqlite(projection.connection.pragma_update(
            None,
            "max_page_count",
            MAX_INDEX_BYTES as i64 / page_size,
        ))?;
        projection.check_paths()?;
        Ok(projection)
    }

    fn anchored(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.root.clone()
        }
    }

    fn check_paths(&self) -> Result<()> {
        let directory = self.directory.metadata()?;
        let named_directory = fs::symlink_metadata(&self.root)?;
        private_metadata(&directory, true)?;
        private_metadata(&named_directory, true)?;
        if !same_file(&directory, &named_directory) {
            return Err(LedgerError(
                "SQLite projection directory was replaced".into(),
            ));
        }
        let file = self.file.metadata()?;
        let named_file = fs::symlink_metadata(self.anchored().join(INDEX))?;
        private_metadata(&file, false)?;
        private_metadata(&named_file, false)?;
        if !same_file(&file, &named_file) {
            return Err(LedgerError("SQLite projection file was replaced".into()));
        }
        sidecars(&self.anchored())
    }

    fn reset(&mut self) -> Result<()> {
        self.check_paths()?;
        // Close before truncating a corrupt disposable file. The descriptor is
        // retained, so reset never follows a newly substituted path.
        let old = std::mem::replace(&mut self.connection, sqlite(Connection::open_in_memory())?);
        drop(old);
        self.check_paths()?;
        for name in SIDECARS {
            let path = self.anchored().join(name);
            if fs::symlink_metadata(&path).is_ok() {
                let file = private_file(&path, false)?;
                if !same_file(&file.metadata()?, &fs::symlink_metadata(&path)?) {
                    return Err(LedgerError("SQLite projection sidecar was replaced".into()));
                }
                fs::remove_file(path)?;
            }
        }
        self.file.set_len(0)?;
        self.file.sync_all()?;
        self.connection = connection(&self.anchored().join(INDEX))?;
        self.check_paths()?;
        sqlite(self.connection.execute_batch(&format!(
            "PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version={VERSION}; {RUNS_SQL};"
        )))?;
        self.directory.sync_all()?;
        Ok(())
    }

    pub fn rebuild(&mut self, runs: &[RunRecord]) -> Result<()> {
        self.check_paths()?;
        let transaction = sqlite(self.connection.transaction())?;
        sqlite(transaction.execute("DELETE FROM runs", []))?;
        for run in runs {
            insert(&transaction, run)?;
        }
        sqlite(transaction.commit())?;
        self.check_paths()
    }

    pub fn upsert(&mut self, run: &RunRecord) -> Result<()> {
        self.check_paths()?;
        insert(&self.connection, run)?;
        self.check_paths()
    }
}

fn insert(connection: &Connection, run: &RunRecord) -> Result<()> {
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_RUN_BYTES.saturating_sub(self.0.len()) {
                return Err(io::Error::other(
                    "SQLite projection run exceeds bounded frame",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut json = Bounded(Vec::new());
    serde_json::to_writer(&mut json, run)?;
    let json = String::from_utf8(json.0).map_err(|error| LedgerError(error.to_string()))?;
    sqlite(connection.execute(
        UPSERT,
        params![
            run.run_id,
            run.attempt_id,
            run.request_id,
            run.state,
            run.child_protection,
            run.settlement,
            run.chain.head_seq.to_string(),
            run.chain.head_digest,
            json,
        ],
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Chain;
    use serde_json::json;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    fn root() -> TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn run(id: &str) -> RunRecord {
        RunRecord {
            holds: vec![],
            history: None,
            schema: "ouro.ledger.run/1".into(),
            run_id: id.into(),
            attempt_id: format!("attempt_{id}"),
            request_id: format!("request_{id}"),
            payload: json!({"kind": "batch"}),
            state: "prepared".into(),
            child_protection: "unprotected".into(),
            owner: None,
            outcome: None,
            coverage: json!({"mode": "none"}),
            settlement: "pending".into(),
            receipts: vec![],
            capture: json!({}),
            chain: Chain {
                head_seq: 1,
                head_digest: Some("sha256:example".into()),
            },
        }
    }

    fn count(projection: &Projection) -> i64 {
        projection
            .connection
            .query_row("SELECT count(*) FROM runs", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn rebuild_and_upsert_survive_reopen_with_truthful_labels_and_u64_sequence() {
        let root = root();
        let mut projection = Projection::open(root.path()).unwrap();
        let mut record = run("one");
        projection.rebuild(&[record.clone(), run("stale")]).unwrap();
        record.state = "outcome_unknown".into();
        record.chain.head_seq = u64::MAX;
        record.coverage = json!({"loss": "explicit"});
        projection.upsert(&record).unwrap();
        drop(projection);
        let mut projection = Projection::open(root.path()).unwrap();
        assert_eq!(count(&projection), 2);
        let (sequence, encoded): (String, String) = projection
            .connection
            .query_row(
                "SELECT head_seq, run_json FROM runs WHERE run_id='one'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(sequence, u64::MAX.to_string());
        let loaded: RunRecord = serde_json::from_str(&encoded).unwrap();
        assert_eq!(loaded.child_protection, "unprotected");
        assert_eq!(loaded.coverage, record.coverage);
        projection.rebuild(&[record]).unwrap();
        assert_eq!(count(&projection), 1);
        assert_eq!(
            fs::metadata(root.path().join(INDEX)).unwrap().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn corrupt_or_missing_index_is_disposable_and_does_not_touch_canonical_bytes() {
        let root = root();
        let canonical = root.path().join("canonical.ndjson");
        fs::write(&canonical, b"canonical bytes\n").unwrap();
        let projection = Projection::open(root.path()).unwrap();
        drop(projection);
        fs::write(root.path().join(INDEX), b"not a SQLite database").unwrap();
        let mut projection = Projection::open(root.path()).unwrap();
        projection.rebuild(&[run("one")]).unwrap();
        assert_eq!(count(&projection), 1);
        drop(projection);
        fs::remove_file(root.path().join(INDEX)).unwrap();
        let mut projection = Projection::open(root.path()).unwrap();
        projection.rebuild(&[run("one")]).unwrap();
        assert_eq!(count(&projection), 1);
        assert_eq!(fs::read(canonical).unwrap(), b"canonical bytes\n");
    }

    #[test]
    fn foreign_identity_schema_and_extra_triggers_are_discarded() {
        for alteration in [
            "PRAGMA application_id=1",
            "PRAGMA user_version=2",
            "DROP TABLE runs; CREATE TABLE runs (run_id TEXT)",
            "CREATE TRIGGER poison AFTER INSERT ON runs BEGIN DELETE FROM runs; END",
        ] {
            let root = root();
            let mut projection = Projection::open(root.path()).unwrap();
            projection.upsert(&run("old")).unwrap();
            projection.connection.execute_batch(alteration).unwrap();
            drop(projection);
            let mut projection = Projection::open(root.path()).unwrap();
            assert_eq!(count(&projection), 0);
            projection.rebuild(&[run("rebuilt")]).unwrap();
            assert_eq!(count(&projection), 1);
        }
    }

    #[test]
    fn unsafe_database_and_sidecars_are_refused_without_following_targets() {
        for name in std::iter::once(INDEX).chain(SIDECARS) {
            for kind in ["symlink", "hardlink", "public", "directory"] {
                let root = root();
                let outside = root.path().join("outside");
                fs::write(&outside, b"unchanged").unwrap();
                fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
                let path = root.path().join(name);
                match kind {
                    "symlink" => symlink(&outside, &path).unwrap(),
                    "hardlink" => fs::hard_link(&outside, &path).unwrap(),
                    "public" => {
                        fs::write(&path, b"public").unwrap();
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                    }
                    "directory" => fs::create_dir(&path).unwrap(),
                    _ => unreachable!(),
                }
                assert!(Projection::open(root.path()).is_err(), "{name} {kind}");
                assert_eq!(fs::read(outside).unwrap(), b"unchanged");
            }
        }
    }

    #[test]
    fn replacing_or_linking_an_open_index_prevents_further_updates() {
        for hardlink in [false, true] {
            let root = root();
            let mut projection = Projection::open(root.path()).unwrap();
            projection.upsert(&run("one")).unwrap();
            if hardlink {
                fs::hard_link(root.path().join(INDEX), root.path().join("linked")).unwrap();
            } else {
                fs::rename(root.path().join(INDEX), root.path().join("old")).unwrap();
                fs::write(root.path().join(INDEX), b"replacement").unwrap();
                fs::set_permissions(root.path().join(INDEX), fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            assert!(projection.upsert(&run("two")).is_err());
            assert_eq!(count(&projection), 1);
        }
    }

    #[test]
    fn replacing_the_root_and_growing_sidecars_prevents_updates() {
        let parent = root();
        let root = parent.path().join("index-root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut projection = Projection::open(&root).unwrap();
        projection.upsert(&run("one")).unwrap();
        fs::rename(&root, parent.path().join("old-root")).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(projection.upsert(&run("two")).is_err());
        assert!(!root.join(INDEX).exists());
        assert_eq!(count(&projection), 1);

        let root = parent.path().join("bounded-root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut projection = Projection::open(&root).unwrap();
        let sidecar = private_file(&root.join(SIDECARS[0]), true).unwrap();
        sidecar.set_len(MAX_INDEX_BYTES + 1).unwrap();
        assert!(projection.upsert(&run("one")).is_err());
        assert_eq!(count(&projection), 0);
    }

    #[test]
    fn oversized_payload_rolls_back_rebuild_and_keeps_the_previous_projection() {
        let root = root();
        let mut projection = Projection::open(root.path()).unwrap();
        projection.upsert(&run("old")).unwrap();
        let mut oversized = run("large");
        oversized.payload = json!({"text": "x".repeat(MAX_RUN_BYTES)});
        assert!(projection.upsert(&oversized).is_err());
        assert!(projection.rebuild(&[run("new"), oversized]).is_err());
        assert_eq!(count(&projection), 1);
        let id: String = projection
            .connection
            .query_row("SELECT run_id FROM runs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(id, "old");
    }
}
