//! Bounded owner journal. This is pending evidence, never a second canonical writer.
use crate::protocol::{LedgerError, MAX_FRAME_BYTES, Peer, Result, RunRecord};
use ouro_records::canonical::{sha256_prefixed, to_jcs};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::{Read, Write},
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
const STATE: &str = "owner-pending.json";
const NEXT: &str = "owner-pending.next";
const LOCK: &str = "owner-pending.lock";

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
    _lock: File,
}
impl Journal {
    pub fn open(run_dir: &Path) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = File::options()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(run_dir)?;
        let meta = dir.metadata()?;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(invalid("run directory is not owned and private"));
        }
        let lock = Self::file(&dir, LOCK, libc::O_RDWR | libc::O_CREAT)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { dir, _lock: lock })
    }
    fn file(dir: &File, name: &str, flags: i32) -> Result<File> {
        let name = CString::new(name).map_err(|_| invalid("invalid member name"))?;
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
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != unsafe { libc::geteuid() }
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
        // Creation must never overwrite pending evidence from an earlier owner.
        let _initial = Self::file(
            &self.dir,
            STATE,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        self.save(&State {
            schema: "ouro.ledger.pending/1".into(),
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
        let file = Self::file(&self.dir, STATE, libc::O_RDONLY)?;
        if file.metadata()?.len() > JOURNAL_BYTES as u64 {
            return Err(invalid("size limit exceeded"));
        }
        let mut bytes = Vec::new();
        file.take(JOURNAL_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > JOURNAL_BYTES {
            return Err(invalid("size limit exceeded"));
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            state: State,
            digest: String,
        }
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        let s = envelope.state;
        if digest(&s)? != envelope.digest
            || s.schema != "ouro.ledger.pending/1"
            || s.run_id != run.run_id
            || s.attempt_id != run.attempt_id
            || s.payload_digest != digest(&run.payload)?
            || run.owner.as_ref() != Some(&s.owner)
        {
            return Err(invalid("checksum or durable owner/run binding mismatch"));
        }
        s.validate()?;
        Ok(s)
    }
    pub fn save(&self, state: &State) -> Result<()> {
        state.validate()?;
        let bytes =
            serde_json::to_vec(&serde_json::json!({"digest":digest(state)?,"state":state}))?;
        if bytes.len() > JOURNAL_BYTES {
            return Err(invalid("size limit exceeded"));
        }
        // A stale replacement from an interrupted write has no authority.
        self.unlink(NEXT)?;
        let mut next = Self::file(
            &self.dir,
            NEXT,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        next.write_all(&bytes)?;
        next.sync_all()?;
        let from = CString::new(NEXT).unwrap();
        let to = CString::new(STATE).unwrap();
        if unsafe {
            libc::renameat(
                self.dir.as_raw_fd(),
                from.as_ptr(),
                self.dir.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        self.dir.sync_all()?;
        Ok(())
    }
    fn unlink(&self, name: &str) -> Result<()> {
        let name = CString::new(name).unwrap();
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        Ok(())
    }
    pub fn remove(self) -> Result<()> {
        self.unlink(NEXT)?;
        self.unlink(STATE)?;
        self.unlink(LOCK)?;
        self.dir.sync_all()?;
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

    fn fixture(evidence: &str, admit: bool) -> (tempfile::TempDir, Store, RunRecord) {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let owner = Peer {
            uid: unsafe { libc::geteuid() },
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
    fn event(run: &RunRecord, seq: u64) -> Value {
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
