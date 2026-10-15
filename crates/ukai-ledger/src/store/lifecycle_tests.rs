//! Exercise real persistence operations in a test-only instrumented writer.
use std::{
    fs,
    os::unix::process::ExitStatusExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime},
};

use serde_json::json;
use ukai_records::records;

use super::*;
use crate::{
    faults::{self, Plan, Point, Replaced, Scope, Step},
    protocol::{Peer, RunRecord},
};

const KINDS: [Scope; 5] = [
    Scope::Prepared,
    Scope::OwnerClaimed,
    Scope::Admitted,
    Scope::Source,
    Scope::Settled,
];
const POINTS: [Point; 14] = [
    Point::EventBeforeWrite,
    Point::EventPartialWrite,
    Point::EventBeforeSync,
    Point::EventAfterSync,
    Point::Replace(Replaced::Projection, Step::BeforeWrite),
    Point::Replace(Replaced::Projection, Step::BeforeSync),
    Point::Replace(Replaced::Projection, Step::BeforeRename),
    Point::Replace(Replaced::Projection, Step::BeforeDirectorySync),
    Point::Replace(Replaced::Manifest, Step::BeforeWrite),
    Point::Replace(Replaced::Manifest, Step::BeforeSync),
    Point::Replace(Replaced::Manifest, Step::BeforeRename),
    Point::Replace(Replaced::Manifest, Step::BeforeDirectorySync),
    Point::AppendBeforeDirectorySync,
    Point::AppendAfterDirectorySync,
];
const WORKER: &str = "store::lifecycle_tests::sigkill_at_every_lifecycle_boundary_preserves_identity_and_canonical_bytes";
const WORKER_ENV: &str = "UKAI_LEDGER_TEST_WORKER";

use crate::test_support::{TOKEN, request as payload};

/// An owner that is not this process, so nothing here reads as its live owner.
fn peer() -> Peer {
    Peer {
        pid: 424242,
        ..crate::test_support::peer()
    }
}
fn receipt(run: &RunRecord, final_receipt: bool) -> Value {
    let mut receipt: Value = serde_json::from_str(if final_receipt {
        include_str!("../../../../docs/specs/jail-v1/examples/receipt-tool.json")
    } else {
        include_str!("../../../../docs/specs/jail-v1/examples/receipt-prepared.json")
    })
    .unwrap();
    receipt["attempt_id"] = json!(run.attempt_id);
    receipt
}
fn perform(store: &mut Store, kind: Scope) -> Result<()> {
    if kind == Scope::Prepared {
        return store.prepare("matrix", &payload(), &peer()).map(|_| ());
    }
    let run = store.runs().into_iter().next().unwrap();
    match kind {
        Scope::OwnerClaimed => store.claim_owner(&run.run_id, &peer()),
        Scope::Admitted => store
            .append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":receipt(&run, false)}),
                &peer(),
                TOKEN,
            )
            .map(|_| ()),
        Scope::Source => store
            .append_source(
                &run.run_id,
                &serde_json::to_value(records::Event::lifecycle_note(
                    &run.attempt_id,
                    1,
                    SystemTime::UNIX_EPOCH,
                    1,
                    "matrix",
                ))
                .unwrap(),
                &peer(),
                TOKEN,
            )
            .map(|_| ()),
        Scope::Settled => {
            let receipt = receipt(&run, true);
            store.append_owner(&run.run_id, "settle", "settled", None, &json!({"receipt":receipt,"outcome":receipt["outcome"],"coverage":receipt["coverage"]}), &peer(), TOKEN).map(|_| ())
        }
        _ => panic!("unexpected matrix operation"),
    }
}
fn setup(data: &Path, kind: Scope) -> Store {
    let mut store = Store::open(data).unwrap();
    for prerequisite in KINDS {
        if prerequisite == kind {
            break;
        }
        if prerequisite == Scope::Source {
            let run = store.runs().remove(0);
            let digest = records::semantic::receipt_digest(&receipt(&run, true)).unwrap();
            let event = serde_json::to_value(records::Event::receipt_note(
                &run.attempt_id,
                1,
                SystemTime::UNIX_EPOCH,
                1,
                records::Phase::Settled,
                &digest,
            ))
            .unwrap();
            store
                .append_source(&run.run_id, &event, &peer(), TOKEN)
                .unwrap();
        } else {
            perform(&mut store, prerequisite).unwrap();
        }
    }
    store
}
fn canonical(store: &Store) -> Vec<u8> {
    let run = store.runs().remove(0);
    fs::read(store.root().join(run.run_id).join("events-0001.ndjson")).unwrap()
}
fn check_recovery(data: &Path, kind: Scope, point: Point, before: &[u8]) {
    let mut store = Store::open(data).unwrap();
    assert_eq!(
        canonical(&store),
        before,
        "recovery must retain every canonical byte: {kind:?}/{point:?}"
    );
    let run = store.runs().remove(0);
    let partial = point == Point::EventPartialWrite
        || (kind == Scope::Prepared && point == Point::EventBeforeWrite);
    if partial {
        assert!(
            store.stream(&run.run_id).unwrap().is_poisoned(),
            "{kind:?}/{point:?}"
        );
        assert!(
            perform(&mut store, kind).is_err(),
            "ambiguous prefix must not acknowledge: {kind:?}/{point:?}"
        );
        assert_eq!(canonical(&store), before);
        return;
    }
    assert!(
        !store.stream(&run.run_id).unwrap().is_poisoned(),
        "{kind:?}/{point:?}"
    );
    let head = run.chain.head_seq;
    perform(&mut store, kind).unwrap();
    let expected = head + u64::from(point == Point::EventBeforeWrite);
    assert_eq!(
        store.runs()[0].chain.head_seq,
        expected,
        "{kind:?}/{point:?}"
    );
    let accepted = canonical(&store);
    perform(&mut store, kind).unwrap();
    assert_eq!(
        canonical(&store),
        accepted,
        "retry must not duplicate {kind:?}/{point:?}"
    );
    assert_eq!(store.runs()[0].chain.head_seq, expected);
    if point != Point::EventBeforeWrite {
        assert_eq!(accepted, before);
    }
}

#[test]
fn io_errors_at_every_lifecycle_boundary_refuse_ack_until_recovery() {
    for kind in KINDS {
        for point in POINTS {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("data");
            let mut store = setup(&data, kind);
            let marker = temp.path().join("fault");
            faults::arm(Plan::error(kind, point, marker.clone()));
            assert!(
                perform(&mut store, kind).is_err(),
                "fault did not refuse {kind:?}/{point:?}"
            );
            faults::disarm();
            assert!(marker.exists(), "hook was not reached: {kind:?}/{point:?}");
            let bytes = canonical(&store);
            assert!(
                perform(&mut store, kind).is_err(),
                "live poisoned retry acknowledged {kind:?}/{point:?}"
            );
            assert_eq!(canonical(&store), bytes);
            drop(store);
            check_recovery(&data, kind, point, &bytes);
        }
    }
}

struct Process {
    child: Child,
    log: PathBuf,
}
impl Process {
    fn spawn(command: &mut Command, log: PathBuf) -> Self {
        let output = fs::File::create(&log).unwrap();
        let child = command
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap();
        Self { child, log }
    }
    fn finish(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "worker timed out: {}",
                fs::read_to_string(&self.log).unwrap()
            );
            thread::sleep(Duration::from_millis(10));
        }
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
fn worker(mode: &str, data: &Path, plan: &Plan) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", WORKER, "--test-threads=1", "--nocapture"])
        .env(
            WORKER_ENV,
            json!({"mode":mode,"data":data,"plan":plan}).to_string(),
        );
    command
}

fn fault_worker() {
    let config: Value =
        serde_json::from_str(&std::env::var(WORKER_ENV).expect("matrix worker configuration"))
            .unwrap();
    let data = Path::new(config["data"].as_str().unwrap());
    let plan: Plan = serde_json::from_value(config["plan"].clone()).unwrap();
    if config["mode"] == "daemon" {
        faults::arm(plan);
        crate::daemon::serve(data).unwrap();
    } else {
        let mut store = Store::open(data).unwrap();
        let kind = plan.scope.expect("a matrix plan names its operation");
        faults::arm(plan);
        perform(&mut store, kind).unwrap();
    }
    panic!("worker did not reach its SIGKILL hook");
}

#[test]
fn sigkill_at_every_lifecycle_boundary_preserves_identity_and_canonical_bytes() {
    // The selected test is also its own subprocess entry point. The parent
    // always runs the full matrix; no test is skipped or marked ignored.
    if std::env::var_os(WORKER_ENV).is_some() {
        fault_worker();
        unreachable!("the instrumented worker must terminate at its fault");
    }
    for kind in KINDS {
        for point in POINTS {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("data");
            drop(setup(&data, kind));
            let marker = temp.path().join("fault");
            let plan = Plan::kill(kind, point, marker.clone());
            let mut process = Process::spawn(
                &mut worker("store", &data, &plan),
                temp.path().join("worker.log"),
            );
            assert_eq!(
                process.finish().signal(),
                Some(libc::SIGKILL),
                "{kind:?}/{point:?}: {}",
                fs::read_to_string(&process.log).unwrap()
            );
            assert!(marker.exists(), "hook not reached: {kind:?}/{point:?}");
            let root = data.join("ledger");
            let run_dir = fs::read_dir(&root)
                .unwrap()
                .filter_map(|e| e.ok())
                .find(|e| e.file_name().to_string_lossy().starts_with("run_"))
                .unwrap()
                .path();
            let bytes = fs::read(run_dir.join("events-0001.ndjson")).unwrap();
            check_recovery(&data, kind, point, &bytes);
        }
    }
}

#[cfg(target_os = "linux")]
mod launch;
