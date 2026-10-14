use super::*;
use crate::{
    faults::{self, Plan, Point, Replaced, Scope, Step},
    store::Store,
};
use ouro_records::records;
use serde_json::json;
use std::{
    fs,
    os::{
        fd::FromRawFd,
        unix::{fs::MetadataExt, process::ExitStatusExt},
    },
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime},
};

const SAVE_POINTS: [Point; 8] = [
    Point::Replace(Replaced::Journal, Step::BeforeTempUnlink),
    Point::Replace(Replaced::Journal, Step::BeforeOpen),
    Point::Replace(Replaced::Journal, Step::BeforeWrite),
    Point::Replace(Replaced::Journal, Step::PartialWrite),
    Point::Replace(Replaced::Journal, Step::BeforeSync),
    Point::Replace(Replaced::Journal, Step::BeforeRename),
    Point::Replace(Replaced::Journal, Step::BeforeDirectorySync),
    Point::Replace(Replaced::Journal, Step::AfterDirectorySync),
];
const REMOVE_POINTS: [Point; 4] = [
    Point::CleanupBeforeTempUnlink,
    Point::CleanupBeforeStateUnlink,
    Point::CleanupBeforeDirectorySync,
    Point::CleanupAfterDirectorySync,
];
const SAVE_KINDS: [Scope; 5] = [
    Scope::PendingCreate,
    Scope::PendingOutage,
    Scope::PendingSource,
    Scope::PendingCompletion,
    Scope::PendingClear,
];
const WORKER_ENV: &str = "OURO_PENDING_TEST_WORKER";
const WORKER: &str =
    "pending::crash_tests::journal_sigkill_matrix_preserves_pending_and_canonical_history";

fn completion(run: &RunRecord) -> Completion {
    let mut receipt: Value = serde_json::from_str(include_str!(
        "../../../../docs/specs/jail-v1/examples/receipt-tool.json"
    ))
    .unwrap();
    receipt["attempt_id"] = json!(run.attempt_id);
    let control = serde_json::from_value(json!({"schema":records::SCHEMA_CONTROL,"attempt_id":run.attempt_id,"seq":1,"kind":"settled","receipt_phase":"settled","receipt_digest":records::semantic::receipt_digest(&receipt).unwrap(),"outcome":receipt["outcome"],"error":receipt["outcome"]["error"]})).unwrap();
    Completion {
        kind: "settled".into(),
        body: json!({"receipt":receipt,"outcome":receipt["outcome"],"coverage":receipt["coverage"]}),
        control,
    }
}
fn setup(kind: Scope) -> (tempfile::TempDir, Store, RunRecord) {
    let (temp, store, run) = tests::fixture("best-effort", true);
    let dir = store.root().join(&run.run_id);
    let journal = Journal::open(&dir).unwrap();
    let mut state = journal.read(&run).unwrap();
    match kind {
        Scope::PendingCreate => fs::remove_file(dir.join(STATE)).unwrap(),
        Scope::PendingSource | Scope::PendingClear => {
            state.push(tests::event(&run, 1)).unwrap();
            journal.save(&state).unwrap();
        }
        Scope::PendingCompletion | Scope::PendingRemove => {
            let done = completion(&run);
            state
                .push(
                    serde_json::to_value(records::Event::receipt_note(
                        &run.attempt_id,
                        1,
                        SystemTime::UNIX_EPOCH,
                        1,
                        records::Phase::Settled,
                        &done.control.receipt_digest,
                    ))
                    .unwrap(),
                )
                .unwrap();
            if kind == Scope::PendingRemove {
                state.completion = Some(done);
            }
            journal.save(&state).unwrap();
        }
        Scope::PendingOutage => {}
        _ => unreachable!(),
    }
    fs::write(dir.join(NEXT), b"stale temporary evidence has no authority").unwrap();
    drop(journal);
    (temp, store, run)
}
fn perform(store: &mut Store, run: &RunRecord, kind: Scope) -> Result<()> {
    let owner = run.owner.as_ref().unwrap();
    if kind == Scope::PendingClear || kind == Scope::PendingRemove {
        return store
            .reconcile_pending(&run.run_id, owner, &|_| true)
            .map(|_| ());
    }
    let journal = Journal::open(&store.root().join(&run.run_id))?;
    if kind == Scope::PendingCreate {
        return journal.create(run, owner);
    }
    let mut state = journal.read(run)?;
    match kind {
        Scope::PendingOutage => state.outage()?,
        Scope::PendingSource => state.push(tests::event(run, 2))?,
        Scope::PendingCompletion => state.completion = Some(completion(run)),
        _ => unreachable!(),
    }
    journal.save(&state)
}
fn cases() -> impl Iterator<Item = (Scope, Point)> {
    SAVE_KINDS
        .into_iter()
        .flat_map(|kind| SAVE_POINTS.into_iter().map(move |point| (kind, point)))
        .chain(
            REMOVE_POINTS
                .into_iter()
                .map(|point| (Scope::PendingRemove, point)),
        )
}
fn published(point: Point) -> bool {
    matches!(
        point,
        Point::Replace(
            Replaced::Journal,
            Step::BeforeDirectorySync | Step::AfterDirectorySync
        )
    )
}
fn recover(data: &Path, run: &RunRecord, kind: Scope, point: Point, before: &[u8]) {
    let mut store = Store::open(data).unwrap();
    let events = store.root().join(&run.run_id).join("events-0001.ndjson");
    assert!(fs::read(&events).unwrap().starts_with(before));
    let owner = run.owner.as_ref().unwrap();
    // Incomplete initialization has no readable journal. Orphan reconciliation
    // records unknown while retaining that invalid local evidence for inspection.
    let _ = store.reconcile_pending(&run.run_id, owner, &|_| false);
    store.settle_orphans(owner, |_| false).unwrap();
    let recovered = store.show(&run.run_id).unwrap();
    let expected =
        if kind == Scope::PendingRemove || (kind == Scope::PendingCompletion && published(point)) {
            "settled"
        } else {
            "outcome_unknown"
        };
    assert_eq!(
        recovered.state, expected,
        "{kind:?}/{point:?}: {recovered:?}"
    );
    let accepted = fs::read(&events).unwrap();
    assert!(accepted.starts_with(before));
    let _ = store.reconcile_pending(&run.run_id, owner, &|_| false);
    store.settle_orphans(owner, |_| false).unwrap();
    assert_eq!(
        fs::read(&events).unwrap(),
        accepted,
        "recovery duplicated history: {kind:?}/{point:?}"
    );
    assert_eq!(store.runs().len(), 1);
    assert_eq!(store.runs()[0].attempt_id, run.attempt_id);
    assert!(store.verify(Some(&run.run_id)).unwrap()[0].local_consistency);
}

#[test]
fn journal_io_error_matrix_preserves_previous_or_complete_replacements() {
    for (kind, point) in cases() {
        let (temp, mut store, run) = setup(kind);
        let dir = store.root().join(&run.run_id);
        let old = fs::read(dir.join(STATE)).unwrap_or_default();
        let canonical = fs::read(dir.join("events-0001.ndjson")).unwrap();
        let marker = temp.path().join("fault");
        faults::arm(Plan::error(kind, point, marker.clone()));
        assert!(
            perform(&mut store, &run, kind).is_err(),
            "{kind:?}/{point:?}"
        );
        faults::disarm();
        assert!(marker.exists(), "hook was not reached: {kind:?}/{point:?}");
        if kind != Scope::PendingRemove && !published(point) {
            assert_eq!(
                fs::read(dir.join(STATE)).unwrap(),
                old,
                "{kind:?}/{point:?}"
            );
        }
        drop(store);
        recover(&temp.path().join("data"), &run, kind, point, &canonical);
    }
}

#[test]
fn recovery_sync_errors_do_not_import_or_acknowledge_a_complete_journal() {
    for point in [
        Point::JournalReadBeforeFileSync,
        Point::JournalReadBeforeDirectorySync,
    ] {
        let (temp, mut store, run) = setup(Scope::PendingRemove);
        let dir = store.root().join(&run.run_id);
        let canonical = fs::read(dir.join("events-0001.ndjson")).unwrap();
        let pending = fs::read(dir.join(STATE)).unwrap();
        for attempt in 0..2 {
            let marker = temp.path().join(format!("fault-{attempt}"));
            faults::arm(Plan::error(Scope::PendingRead, point, marker.clone()));
            assert!(
                store
                    .reconcile_pending(&run.run_id, run.owner.as_ref().unwrap(), &|_| false)
                    .is_err()
            );
            faults::disarm();
            assert!(marker.exists());
            assert_eq!(fs::read(dir.join("events-0001.ndjson")).unwrap(), canonical);
            assert_eq!(fs::read(dir.join(STATE)).unwrap(), pending);
        }
        drop(store);
        recover(
            &temp.path().join("data"),
            &run,
            Scope::PendingRemove,
            point,
            &canonical,
        );
    }
}

#[test]
fn cleanup_keeps_the_same_mutex_inode_for_future_openers() {
    let (_temp, store, run) = setup(Scope::PendingOutage);
    let dir = store.root().join(&run.run_id);
    let old_lock = File::open(dir.join(LOCK)).unwrap();
    let journal = Journal::open(&dir).unwrap();
    assert!(Journal::open(&dir).is_err());
    journal.remove().unwrap();
    let reopened = Journal::open(&dir).unwrap();
    assert_eq!(
        old_lock.metadata().unwrap().ino(),
        reopened.lock.metadata().unwrap().ino()
    );
    assert!(Journal::open(&dir).is_err());
    assert!(!dir.join(STATE).exists());
    assert!(!dir.join(NEXT).exists());
}

#[test]
fn a_dropped_journal_unlocks_even_while_a_copy_of_its_descriptor_lives() {
    let (_temp, store, run) = setup(Scope::PendingOutage);
    let dir = store.root().join(&run.run_id);
    let journal = Journal::open(&dir).unwrap();
    // A child forked by another thread holds a copy until it execs.
    // SAFETY: dup takes the open descriptor by value; the copy is owned below.
    let copy = unsafe { libc::dup(journal.lock.as_raw_fd()) };
    assert!(copy >= 0);
    // SAFETY: dup returned a new descriptor owned only here.
    let copy = unsafe { File::from_raw_fd(copy) };
    drop(journal);
    Journal::open(&dir).unwrap();
    drop(copy);
}

struct Process {
    child: Child,
    log: PathBuf,
}
impl Process {
    fn spawn(command: &mut Command, log: PathBuf) -> Self {
        let file = File::create(&log).unwrap();
        let child = command
            .stdin(Stdio::null())
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .unwrap();
        Self { child, log }
    }
    fn finish(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "process timed out: {}",
                fs::read_to_string(&self.log).unwrap()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    #[cfg(target_os = "linux")]
    fn kill(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn worker(config: Value) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", WORKER, "--test-threads=1", "--nocapture"])
        .env(WORKER_ENV, config.to_string());
    command
}
fn dispatch_worker(config: Value) {
    #[cfg(target_os = "linux")]
    if config["mode"] == "owner" {
        launch::owner_worker(config);
        return;
    }
    let data = Path::new(config["data"].as_str().unwrap());
    let mut store = Store::open(data).unwrap();
    let run = store.runs().remove(0);
    let plan: Plan = serde_json::from_value(config["plan"].clone()).unwrap();
    let kind = plan.scope.expect("a matrix plan names its operation");
    faults::arm(plan);
    perform(&mut store, &run, kind).unwrap();
    panic!("worker missed its SIGKILL hook");
}

#[test]
fn journal_sigkill_matrix_preserves_pending_and_canonical_history() {
    if let Ok(config) = std::env::var(WORKER_ENV) {
        dispatch_worker(serde_json::from_str(&config).unwrap());
        return;
    }
    for (kind, point) in cases() {
        let (temp, store, run) = setup(kind);
        let data = temp.path().join("data");
        let dir = store.root().join(&run.run_id);
        let old = fs::read(dir.join(STATE)).unwrap_or_default();
        let canonical = fs::read(dir.join("events-0001.ndjson")).unwrap();
        drop(store);
        let marker = temp.path().join("fault");
        let plan = Plan::kill(kind, point, marker.clone());
        let mut process = Process::spawn(
            &mut worker(json!({"data":data,"plan":plan})),
            temp.path().join("worker.log"),
        );
        assert_eq!(
            process.finish().signal(),
            Some(libc::SIGKILL),
            "{kind:?}/{point:?}: {}",
            fs::read_to_string(&process.log).unwrap()
        );
        assert!(marker.exists());
        if kind != Scope::PendingRemove && !published(point) {
            assert_eq!(
                fs::read(dir.join(STATE)).unwrap(),
                old,
                "{kind:?}/{point:?}"
            );
        }
        recover(&data, &run, kind, point, &canonical);
    }
}

#[cfg(target_os = "linux")]
mod launch;
