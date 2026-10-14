//! Bounded owner journal. This is pending evidence, never a second canonical writer.
use crate::{
    faults::{self, Point, Replaced, Scope, Step},
    protocol::{LedgerError, MAX_FRAME_BYTES, Peer, Result, RunRecord, read_bounded},
};
use ouro_records::canonical::{sha256_prefixed, to_jcs};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ffi::CStr,
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

pub(crate) const QUEUE_BYTES: usize = 256 * 1024;
pub(crate) const QUEUE_EVENTS: usize = 32;
// Prefix, three source tails, first transport-loss note, terminal record and header.
const JOURNAL_BYTES: usize = QUEUE_BYTES + 5 * MAX_FRAME_BYTES + 16 * 1024;
// Members of a run directory, named as the descriptor-relative calls take them.
const STATE_NAME: &CStr = c"owner-pending.json";
const NEXT_NAME: &CStr = c"owner-pending.next";
const LOCK_NAME: &CStr = c"owner-pending.lock";
pub(crate) const STATE: &str = text(STATE_NAME);
#[cfg(test)]
const NEXT: &str = text(NEXT_NAME);
#[cfg(test)]
const LOCK: &str = text(LOCK_NAME);

/// A step of replacing the journal snapshot.
const fn snapshot(step: Step) -> Point {
    Point::Replace(Replaced::Journal, step)
}

const fn text(name: &'static CStr) -> &'static str {
    match name.to_str() {
        Ok(text) => text,
        Err(_) => panic!("member names are ASCII"),
    }
}

#[cfg(test)]
mod crash_tests;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Completion {
    pub kind: String,
    pub body: Value,
    pub control: ouro_records::records::ControlMessage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    schema: String,
    run_id: String,
    attempt_id: String,
    payload_digest: String,
    pub owner: Peer,
    pub episode: u64,
    pub active: bool,
    overflow: bool,
    events: Vec<Value>,
    tails: BTreeMap<String, Value>,
    first_loss: Option<Value>,
    pub completion: Option<Completion>,
}

fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256_prefixed(
        &to_jcs(&serde_json::to_value(value)?).map_err(|e| LedgerError(e.to_string()))?,
    ))
}
fn invalid(message: &str) -> LedgerError {
    LedgerError(format!("owner pending journal: {message}"))
}

/// Every operation is relative to a pinned private run directory. A nonblocking
/// lock serializes snapshot replacement with reconciliation; inability to persist
/// is a hard owner failure, including a writer stalled while holding this lock.
pub(crate) struct Journal {
    dir: File,
    lock: File,
}

impl Drop for Journal {
    /// A child forked elsewhere in this process holds every inherited
    /// descriptor until it execs; unlocking the shared open file releases
    /// the lock for it too.
    fn drop(&mut self) {
        // SAFETY: flock takes the still-open descriptor and flags by value.
        unsafe {
            libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
impl Journal {
    #[cfg(any(target_os = "linux", test))]
    pub fn open(run_dir: &Path) -> Result<Self> {
        Self::try_open(run_dir)?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::WouldBlock).into())
    }
    /// The journal, or `None` while another open description holds its lock.
    pub fn try_open(run_dir: &Path) -> Result<Option<Self>> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = File::options()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(run_dir)?;
        let meta = dir.metadata()?;
        if meta.uid() != crate::os::euid() || meta.mode() & 0o077 != 0 {
            return Err(invalid("run directory is not owned and private"));
        }
        let lock = Self::file(&dir, LOCK_NAME, libc::O_RDWR | libc::O_CREAT)?;
        // SAFETY: flock takes the open descriptor and flags by value.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(error.into());
        }
        Ok(Some(Self { dir, lock }))
    }
    fn file(dir: &File, name: &CStr, flags: i32) -> Result<File> {
        // SAFETY: the directory descriptor and the NUL-terminated name stay
        // live through the call; the mode applies only with O_CREAT.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: a successful openat returned a new descriptor owned only here.
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != crate::os::euid()
            || meta.mode() & 0o077 != 0
        {
            return Err(invalid(
                "member is not a private owned single-link regular file",
            ));
        }
        Ok(file)
    }
    #[cfg(any(target_os = "linux", test))]
    pub fn create(&self, run: &RunRecord, owner: &Peer) -> Result<()> {
        let _scope = faults::enter(|| Some(Scope::PendingCreate));
        // Creation must never overwrite pending evidence from an earlier owner.
        let _initial = Self::file(
            &self.dir,
            STATE_NAME,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        self.replace(&State {
            schema: crate::schemas::PENDING.into(),
            run_id: run.run_id.clone(),
            attempt_id: run.attempt_id.clone(),
            payload_digest: digest(&run.payload)?,
            owner: owner.clone(),
            episode: 0,
            active: false,
            overflow: false,
            events: Vec::new(),
            tails: BTreeMap::new(),
            first_loss: None,
            completion: None,
        })
    }
    pub fn read(&self, run: &RunRecord) -> Result<State> {
        let _scope = faults::enter(|| Some(Scope::PendingRead));
        let mut file = Self::file(&self.dir, STATE_NAME, libc::O_RDONLY)?;
        if file.metadata()?.len() > JOURNAL_BYTES as u64 {
            return Err(invalid("size limit exceeded"));
        }
        let bytes = read_bounded(
            &mut file,
            JOURNAL_BYTES as u64,
            "owner pending journal: size limit exceeded",
        )?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            state: State,
            digest: String,
        }
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        let s = envelope.state;
        if digest(&s)? != envelope.digest
            || s.schema != crate::schemas::PENDING
            || s.run_id != run.run_id
            || s.attempt_id != run.attempt_id
            || s.payload_digest != digest(&run.payload)?
            || run.owner.as_ref() != Some(&s.owner)
        {
            return Err(invalid("checksum or durable owner/run binding mismatch"));
        }
        s.validate()?;
        // A complete replacement can survive an interrupted save without its
        // acknowledgement. Validate it, then establish durability before any
        // caller imports, clears or acknowledges that pending evidence.
        faults::hit(Point::JournalReadBeforeFileSync)?;
        file.sync_all()?;
        faults::hit(Point::JournalReadBeforeDirectorySync)?;
        self.dir.sync_all()?;
        Ok(s)
    }
    pub fn save(&self, state: &State) -> Result<()> {
        let _scope = faults::enter(|| {
            Some(if state.completion.is_some() {
                Scope::PendingCompletion
            } else if !state.active {
                Scope::PendingClear
            } else if state.pending().is_empty() {
                Scope::PendingOutage
            } else {
                Scope::PendingSource
            })
        });
        self.replace(state)
    }
    fn replace(&self, state: &State) -> Result<()> {
        state.validate()?;
        let bytes =
            serde_json::to_vec(&serde_json::json!({"digest":digest(state)?,"state":state}))?;
        if bytes.len() > JOURNAL_BYTES {
            return Err(invalid("size limit exceeded"));
        }
        // A stale replacement from an interrupted write has no authority.
        faults::hit(snapshot(Step::BeforeTempUnlink))?;
        self.unlink(NEXT_NAME)?;
        faults::hit(snapshot(Step::BeforeOpen))?;
        let mut next = Self::file(
            &self.dir,
            NEXT_NAME,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        faults::hit(snapshot(Step::BeforeWrite))?;
        faults::partial_write(snapshot(Step::PartialWrite), &mut next, &bytes)?;
        next.write_all(&bytes)?;
        faults::hit(snapshot(Step::BeforeSync))?;
        next.sync_all()?;
        faults::hit(snapshot(Step::BeforeRename))?;
        // SAFETY: both names are static NUL-terminated members of the one
        // directory descriptor, which stays open through the call.
        if unsafe {
            libc::renameat(
                self.dir.as_raw_fd(),
                NEXT_NAME.as_ptr(),
                self.dir.as_raw_fd(),
                STATE_NAME.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        faults::hit(snapshot(Step::BeforeDirectorySync))?;
        self.dir.sync_all()?;
        faults::hit(snapshot(Step::AfterDirectorySync))?;
        Ok(())
    }
    fn unlink(&self, name: &CStr) -> Result<()> {
        // SAFETY: the directory descriptor and the NUL-terminated name stay
        // live through the call.
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        Ok(())
    }
    pub fn remove(self) -> Result<()> {
        let _scope = faults::enter(|| Some(Scope::PendingRemove));
        faults::hit(Point::CleanupBeforeTempUnlink)?;
        self.unlink(NEXT_NAME)?;
        faults::hit(Point::CleanupBeforeStateUnlink)?;
        self.unlink(STATE_NAME)?;
        // Keep the mutex inode for the lifetime of the run directory. Unlinking
        // a held flock lets another opener lock a different inode concurrently.
        faults::hit(Point::CleanupBeforeDirectorySync)?;
        self.dir.sync_all()?;
        faults::hit(Point::CleanupAfterDirectorySync)?;
        Ok(())
    }
}

impl State {
    fn validate(&self) -> Result<()> {
        if self.events.len() > QUEUE_EVENTS
            || serde_json::to_vec(&self.events)?.len() > QUEUE_BYTES
            || self.tails.len() > 3
            || (self.active && self.episode == 0)
            || (!self.active
                && (!self.events.is_empty()
                    || !self.tails.is_empty()
                    || self.first_loss.is_some()
                    || self.overflow))
        {
            return Err(invalid("invalid bounded queue state"));
        }
        for (source, event) in &self.tails {
            if !["wrapper", "audit", "proxy"].contains(&source.as_str())
                || event["source"] != *source
            {
                return Err(invalid("invalid source tail"));
            }
        }
        for event in self
            .events
            .iter()
            .chain(self.tails.values())
            .chain(self.first_loss.iter())
        {
            if serde_json::to_vec(event)?.len() > MAX_FRAME_BYTES
                || event["attempt_id"] != self.attempt_id
                || !["wrapper", "audit", "proxy"].contains(&event["source"].as_str().unwrap_or(""))
                || event["source_seq"].as_u64().is_none_or(|n| n == 0)
            {
                return Err(invalid("invalid pending event"));
            }
        }
        if let Some(c) = &self.completion
            && (serde_json::to_vec(c)?.len() > MAX_FRAME_BYTES
                || !["settled", "outcome_unknown"].contains(&c.kind.as_str()))
        {
            return Err(invalid("invalid exit record"));
        }
        Ok(())
    }
    pub fn outage(&mut self) -> Result<()> {
        if !self.active {
            self.episode = self
                .episode
                .checked_add(1)
                .ok_or_else(|| invalid("episode exhausted"))?;
            self.active = true;
        }
        Ok(())
    }
    #[cfg(any(target_os = "linux", test))]
    pub fn push(&mut self, event: Value) -> Result<()> {
        if self.completion.is_some() {
            return Err(invalid("exit record is sealed"));
        }
        self.outage()?;
        let size = serde_json::to_vec(&event)?.len();
        if size > MAX_FRAME_BYTES {
            return Err(invalid("event exceeds frame limit"));
        }
        if !self.overflow
            && self.events.len() < QUEUE_EVENTS
            && serde_json::to_vec(&self.events)?.len() + size < QUEUE_BYTES
        {
            self.events.push(event);
        } else {
            self.overflow = true;
            if event["fields"]["kind"] == "trace_transport_loss" && self.first_loss.is_none() {
                self.first_loss = Some(event.clone());
            }
            let source = event["source"]
                .as_str()
                .ok_or_else(|| invalid("missing source"))?
                .to_owned();
            self.tails.insert(source, event);
        }
        self.validate()
    }
    pub fn pending(&self) -> Vec<Value> {
        let mut events = self.events.clone();
        let mut tails: Vec<_> = self
            .tails
            .values()
            .chain(self.first_loss.iter())
            .cloned()
            .collect();
        // Preserve each producer's sequence and retain the final wrapper receipt last.
        tails.sort_by_key(|e| {
            (
                e["source"] == "wrapper",
                e["source"].as_str().unwrap_or("").to_owned(),
                e["source_seq"].as_u64().unwrap_or(0),
            )
        });
        tails.dedup_by(|a, b| a["source"] == b["source"] && a["source_seq"] == b["source_seq"]);
        events.extend(tails);
        events
    }
    pub fn clear(&mut self) {
        self.active = false;
        self.overflow = false;
        self.events.clear();
        self.tails.clear();
        self.first_loss = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use ouro_records::records;
    use serde_json::json;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        time::SystemTime,
    };
    const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    pub(super) fn fixture(evidence: &str, admit: bool) -> (tempfile::TempDir, Store, RunRecord) {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let owner = Peer {
            uid: crate::os::euid(),
            pid: std::process::id(),
            birth: "pending-fixture".into(),
            boot_id: "pending-boot".into(),
        };
        let mut receipt: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/receipt-prepared.json"
        ))
        .unwrap();
        let payload = json!({"schema":"ouro.ledger.request/1","profile":"tool","argv_digest":receipt["argv_digest"],"policy_digest":receipt["policy"]["digest"],"requirements":receipt["policy"]["requirements"],"jail_image_digest":receipt["argv_digest"],"io":{"mode":"batch","pty":false},"capture":{"streams":[],"limit_bytes":1024},"evidence":evidence});
        let run = store.prepare("pending-test", &payload, &owner).unwrap();
        store.claim_owner(&run.run_id, &owner).unwrap();
        if admit {
            receipt["attempt_id"] = json!(run.attempt_id);
            store
                .append_owner(
                    &run.run_id,
                    "admission",
                    "admitted",
                    None,
                    &json!({"receipt":receipt}),
                    &owner,
                    TOKEN,
                )
                .unwrap();
        }
        let run = store.show(&run.run_id).unwrap();
        Journal::open(&store.root().join(&run.run_id))
            .unwrap()
            .create(&run, &owner)
            .unwrap();
        (temp, store, run)
    }
    pub(super) fn event(run: &RunRecord, seq: u64) -> Value {
        serde_json::to_value(records::Event::lifecycle_note(
            &run.attempt_id,
            seq,
            SystemTime::UNIX_EPOCH,
            seq.into(),
            "pending_test",
        ))
        .unwrap()
    }

    #[test]
    fn queue_is_bounded_and_retains_latest_sequence_for_explicit_loss() {
        let (_temp, mut store, run) = fixture("best-effort", true);
        let journal = Journal::open(&store.root().join(&run.run_id)).unwrap();
        let mut state = journal.read(&run).unwrap();
        for seq in 1..=1000 {
            state.push(event(&run, seq)).unwrap();
        }
        assert_eq!(state.events.len(), QUEUE_EVENTS);
        assert_eq!(state.tails.len(), 1);
        assert_eq!(state.pending().last().unwrap()["source_seq"], 1000);
        journal.save(&state).unwrap();
        assert!(
            fs::metadata(store.root().join(&run.run_id).join(STATE))
                .unwrap()
                .len()
                < QUEUE_BYTES as u64
        );
        drop(journal);
        let reconciled = store
            .reconcile_pending(&run.run_id, run.owner.as_ref().unwrap(), &|_| true)
            .unwrap();
        let gaps = reconciled.coverage["ledger"]["gaps"].as_array().unwrap();
        assert!(
            gaps.iter()
                .any(|g| g["from_source_seq"] == 33 && g["to_source_seq"] == 999)
        );
        assert!(store.verify(Some(&run.run_id)).unwrap()[0].local_consistency);
    }

    #[test]
    fn lost_source_and_reconciliation_replies_replay_once_across_writer_restart() {
        let (temp, mut store, run) = fixture("best-effort", true);
        let owner = run.owner.as_ref().unwrap();
        let first = event(&run, 1);
        let acknowledged = store
            .append_source(&run.run_id, &first, owner, TOKEN)
            .unwrap();
        let dir = store.root().join(&run.run_id);
        let journal = Journal::open(&dir).unwrap();
        let mut state = journal.read(&run).unwrap();
        // The owner did not receive the already durable reply.
        state.push(first.clone()).unwrap();
        state.push(event(&run, 2)).unwrap();
        journal.save(&state).unwrap();
        drop(journal);
        drop(store);
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let recovered = store
            .reconcile_pending(&run.run_id, owner, &|_| true)
            .unwrap();
        assert_eq!(recovered.chain.head_seq, acknowledged.seq + 2); // marker and second source
        assert_eq!(
            store
                .append_source(&run.run_id, &first, owner, TOKEN)
                .unwrap(),
            acknowledged
        );
        // Simulate a crash before the journal clear was persisted: old snapshot
        // includes every already imported record, with exactly the same identities.
        Journal::open(&dir).unwrap().save(&state).unwrap();
        drop(store);
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let replay = store
            .reconcile_pending(&run.run_id, owner, &|_| true)
            .unwrap();
        assert_eq!(replay.chain, recovered.chain);
        assert_eq!(replay.coverage, recovered.coverage);
        assert!(store.verify(Some(&run.run_id)).unwrap()[0].local_consistency);
    }

    #[test]
    fn recovery_cannot_admit_strict_runs_or_impersonate_a_live_owner() {
        for (evidence, admit) in [
            ("strict", true),
            ("best-effort", false),
            ("best-effort", true),
        ] {
            let (_temp, mut store, run) = fixture(evidence, admit);
            let mut stranger = run.owner.clone().unwrap();
            if evidence == "best-effort" && admit {
                stranger.birth.push_str("-other");
            }
            let before = run.chain.clone();
            assert!(
                store
                    .reconcile_pending(&run.run_id, &stranger, &|_| true)
                    .is_err()
            );
            assert_eq!(store.show(&run.run_id).unwrap().chain, before);
        }
    }

    #[test]
    fn journal_rejects_rebinding_corruption_unsafe_members_and_competing_writer() {
        let (_temp, store, run) = fixture("best-effort", true);
        let dir = store.root().join(&run.run_id);
        let journal = Journal::open(&dir).unwrap();
        assert!(Journal::open(&dir).is_err());
        let mut other = run.clone();
        other.owner.as_mut().unwrap().birth.push_str("-reused-pid");
        assert!(journal.read(&other).is_err());
        let original = fs::read(dir.join(STATE)).unwrap();
        fs::write(dir.join(STATE), b"{\"incomplete\":").unwrap();
        assert!(journal.read(&run).is_err());
        fs::write(dir.join(STATE), &original).unwrap();
        fs::hard_link(dir.join(STATE), dir.join("hardlink")).unwrap();
        assert!(journal.read(&run).is_err());
        fs::remove_file(dir.join("hardlink")).unwrap();
        fs::set_permissions(dir.join(STATE), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(journal.read(&run).is_err());
        fs::remove_file(dir.join(STATE)).unwrap();
        symlink("unrelated", dir.join(STATE)).unwrap();
        assert!(journal.read(&run).is_err());
        assert!(!dir.join("unrelated").exists());
    }

    #[test]
    fn failed_snapshot_replacement_preserves_previous_pending_evidence() {
        let (_temp, store, run) = fixture("best-effort", true);
        let dir = store.root().join(&run.run_id);
        let journal = Journal::open(&dir).unwrap();
        let mut state = journal.read(&run).unwrap();
        state.push(event(&run, 1)).unwrap();
        journal.save(&state).unwrap();
        let before = fs::read(dir.join(STATE)).unwrap();
        fs::create_dir(dir.join(NEXT)).unwrap();
        state.push(event(&run, 2)).unwrap();
        assert!(journal.save(&state).is_err());
        assert_eq!(fs::read(dir.join(STATE)).unwrap(), before);
        assert_eq!(journal.read(&run).unwrap().pending().len(), 1);
    }
}
