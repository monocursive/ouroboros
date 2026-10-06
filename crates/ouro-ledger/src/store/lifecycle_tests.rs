//! Exercise real persistence operations in a test-only instrumented writer.
use super::*;
use crate::faults::{self, Plan};
use std::{
    os::unix::process::ExitStatusExt as _,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const KINDS: [&str; 5] = ["prepared", "owner_claimed", "admitted", "source", "settled"];
const POINTS: [&str; 14] = [
    "event.before_write",
    "event.partial_write",
    "event.before_sync",
    "event.after_sync",
    "projection.before_write",
    "projection.before_sync",
    "projection.before_rename",
    "projection.before_directory_sync",
    "manifest.before_write",
    "manifest.before_sync",
    "manifest.before_rename",
    "manifest.before_directory_sync",
    "append.before_directory_sync",
    "append.after_directory_sync",
];
const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const WORKER: &str = "store::lifecycle_tests::sigkill_at_every_lifecycle_boundary_preserves_identity_and_canonical_bytes";
const WORKER_ENV: &str = "OURO_LEDGER_TEST_WORKER";

fn peer() -> Peer {
    Peer {
        uid: unsafe { libc::geteuid() },
        pid: 424242,
        birth: "fixture-birth".into(),
        boot_id: "fixture-boot".into(),
    }
}
fn payload() -> Value {
    let receipt: Value = serde_json::from_str(include_str!(
        "../../../../docs/specs/jail-v1/examples/receipt-prepared.json"
    ))
    .unwrap();
    json!({"schema":"ouro.ledger.request/1","profile":"tool","argv_digest":receipt["argv_digest"],"policy_digest":receipt["policy"]["digest"],"requirements":receipt["policy"]["requirements"],"jail_image_digest":receipt["argv_digest"],"io":{"mode":"batch","pty":false},"capture":{"streams":[],"limit_bytes":1_048_576},"evidence":"strict"})
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
fn perform(store: &mut Store, kind: &str) -> Result<()> {
    if kind == "prepared" {
        return store.prepare("matrix", &payload(), &peer()).map(|_| ());
    }
    let run = store.runs().into_iter().next().unwrap();
    match kind {
        "owner_claimed" => store.claim_owner(&run.run_id, &peer()),
        "admitted" => store
            .append_owner(
                &run.run_id,
                "admit",
                kind,
                None,
                &json!({"receipt":receipt(&run, false)}),
                &peer(),
                TOKEN,
            )
            .map(|_| ()),
        "source" => store
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
        "settled" => {
            let receipt = receipt(&run, true);
            store.append_owner(&run.run_id, "settle", kind, None, &json!({"receipt":receipt,"outcome":receipt["outcome"],"coverage":receipt["coverage"]}), &peer(), TOKEN).map(|_| ())
        }
        _ => panic!("unexpected matrix operation"),
    }
}
fn setup(data: &Path, kind: &str) -> Store {
    let mut store = Store::open(data).unwrap();
    for prerequisite in KINDS {
        if prerequisite == kind {
            break;
        }
        if prerequisite == "source" {
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
fn check_recovery(data: &Path, kind: &str, point: &str, before: &[u8]) {
    let mut store = Store::open(data).unwrap();
    assert_eq!(
        canonical(&store),
        before,
        "recovery must retain every canonical byte: {kind}/{point}"
    );
    let run = store.runs().remove(0);
    let partial =
        point == "event.partial_write" || (kind == "prepared" && point == "event.before_write");
    if partial {
        assert!(
            !store.stream(&run.run_id).unwrap().poisoned.is_empty(),
            "{kind}/{point}"
        );
        assert!(
            perform(&mut store, kind).is_err(),
            "ambiguous prefix must not acknowledge: {kind}/{point}"
        );
        assert_eq!(canonical(&store), before);
        return;
    }
    assert!(
        store.stream(&run.run_id).unwrap().poisoned.is_empty(),
        "{kind}/{point}"
    );
    let head = run.chain.head_seq;
    perform(&mut store, kind).unwrap();
    let expected = head + u64::from(point == "event.before_write");
    assert_eq!(store.runs()[0].chain.head_seq, expected, "{kind}/{point}");
    let accepted = canonical(&store);
    perform(&mut store, kind).unwrap();
    assert_eq!(
        canonical(&store),
        accepted,
        "retry must not duplicate {kind}/{point}"
    );
    assert_eq!(store.runs()[0].chain.head_seq, expected);
    if point != "event.before_write" {
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
            faults::arm(Plan {
                kind: kind.into(),
                point: point.into(),
                action: "error".into(),
                marker: marker.clone(),
            });
            assert!(
                perform(&mut store, kind).is_err(),
                "fault did not refuse {kind}/{point}"
            );
            faults::disarm();
            assert!(marker.exists(), "hook was not reached: {kind}/{point}");
            let bytes = canonical(&store);
            assert!(
                perform(&mut store, kind).is_err(),
                "live poisoned retry acknowledged {kind}/{point}"
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
        let kind = plan.kind.clone();
        faults::arm(plan);
        perform(&mut store, &kind).unwrap();
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
            let plan = Plan {
                kind: kind.into(),
                point: point.into(),
                action: "kill".into(),
                marker: temp.path().join("fault"),
            };
            let mut process = Process::spawn(
                &mut worker("store", &data, &plan),
                temp.path().join("worker.log"),
            );
            assert_eq!(
                process.finish().signal(),
                Some(libc::SIGKILL),
                "{kind}/{point}: {}",
                fs::read_to_string(&process.log).unwrap()
            );
            assert!(plan.marker.exists(), "hook not reached: {kind}/{point}");
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
