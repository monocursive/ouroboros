//! Real writer and jail, instrumenting only the launch owner's journal calls.
use super::*;
use crate::{
    daemon::Client,
    runner::{self, RunOptions},
};
use std::os::unix::fs::PermissionsExt;

fn binary(name: &str, variable: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join(name)
        })
}
fn options(root: &Path, kind: &str) -> RunOptions {
    let script = if matches!(kind, "pending.outage" | "pending.source") {
        "printf x >> executions; touch started; while test ! -f release; do sleep 0.02; done"
    } else {
        "printf x >> executions"
    };
    RunOptions {
        data: root.join("data"),
        jail: root.join("ouro-jail"),
        request_id: "pending-crash".into(),
        prepared: None,
        policy_args: vec![
            "--profile".into(),
            "tool".into(),
            "--observe".into(),
            "on".into(),
            "--evidence".into(),
            "best-effort".into(),
            "--workspace".into(),
            root.join("workspace").into_os_string(),
            "--limit".into(),
            "wall=10s".into(),
        ],
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        batch: true,
        separate_control: false,
        detached: false,
        captures: vec![],
        capture_limit: 1024,
        best_effort: true,
        launch: None,
        tags: vec![],
    }
}
pub(super) fn owner_worker(config: Value) {
    let root = Path::new(config["root"].as_str().unwrap());
    let plan: Plan = serde_json::from_value(config["plan"].clone()).unwrap();
    let opts = options(root, &plan.kind);
    let marker = plan.marker.clone();
    let action = plan.action.clone();
    faults::arm(plan);
    let result = runner::run(&opts);
    assert!(
        marker.exists(),
        "owner never reached fault: {}",
        result.err().map(|e| e.to_string()).unwrap_or_default()
    );
    assert_eq!(action, "error", "owner survived its kill hook");
    assert!(
        result.is_err(),
        "local I/O failure must not return a successful launch result"
    );
}
fn writer(ledger: &Path, root: &Path, label: &str) -> Process {
    let mut command = Command::new(ledger);
    command
        .env("OURO_CONFIG_DIR", root.join("config"))
        .arg("--data-dir")
        .arg(root.join("data"))
        .arg("serve");
    let mut process = Process::spawn(&mut command, root.join(format!("{label}.log")));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Client::connect(&root.join("data"))
            .and_then(|mut c| c.ping())
            .is_ok()
        {
            return process;
        }
        assert!(
            process.child.try_wait().unwrap().is_none(),
            "writer exited: {}",
            fs::read_to_string(&process.log).unwrap()
        );
        assert!(Instant::now() < deadline, "writer startup timed out");
        thread::sleep(Duration::from_millis(10));
    }
}
fn wait_for(owner: &mut Process, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            owner.child.try_wait().unwrap().is_none(),
            "owner exited early: {}",
            fs::read_to_string(&owner.log).unwrap()
        );
        assert!(
            Instant::now() < deadline,
            "owner did not reach test boundary: {}",
            fs::read_to_string(&owner.log).unwrap()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn stopped(root: &Path, run: &RunRecord) {
    let path = root
        .join("data/attempts")
        .join(&run.attempt_id)
        .join("jail.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(bytes) = fs::read(&path)
            && let Ok(receipt) = serde_json::from_slice::<Value>(&bytes)
            && matches!(
                receipt["phase"].as_str(),
                Some("settled" | "unsettled" | "refused")
            )
        {
            assert_eq!(receipt["attempt_id"], run.attempt_id);
            assert!(records::semantic::receipt(&receipt).is_empty(), "{receipt}");
            assert_eq!(receipt["lifetime"]["tree_empty"], true, "{receipt}");
            assert_eq!(receipt["lifetime"]["integrity"], "verified", "{receipt}");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "jail did not verify tree termination: {}",
            fs::read_to_string(&path).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn replay(ledger: &Path, root: &Path, kind: &str) -> Command {
    let opts = options(root, kind);
    let mut command = Command::new(ledger);
    command
        .env("OURO_CONFIG_DIR", root.join("config"))
        .arg("--data-dir")
        .arg(&opts.data)
        .args(["run", "--request-id", "pending-crash", "--jail-bin"])
        .arg(&opts.jail)
        .arg("--workspace")
        .arg(root.join("workspace"))
        .args([
            "--jail",
            "tool",
            "--observe",
            "on",
            "--evidence",
            "best-effort",
            "--limit",
            "wall=10s",
            "--capture-limit",
            "1024",
            "--io",
            "batch",
            "--json",
            "--",
        ])
        .args(&opts.argv);
    command
}

#[test]
fn real_owner_journal_crashes_never_bypass_admission_or_repeat_execution() {
    let ledger = binary("ouro-ledger", "OURO_LEDGER_BIN");
    let jail = binary("ouro-jail", "OURO_JAIL_BIN");
    if !Command::new(&jail)
        .args(["doctor", "--json"])
        .output()
        .is_ok_and(|o| {
            o.status.success()
                && serde_json::from_slice::<Value>(&o.stdout).is_ok_and(|v| v["ready"] == true)
        })
    {
        ouro_fixture::harness::skip_or_fail("pending journal matrix needs a real ready ouro-jail");
        return;
    }
    assert!(
        ledger.is_file(),
        "build the production ledger before this matrix"
    );
    for action in ["error", "kill"] {
        for (kind, point) in cases().filter(|(kind, _)| *kind != "pending.clear") {
            let case = format!("{action}/{kind}/{point}");
            let temp = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let root = temp.path();
            fs::create_dir(root.join("config")).unwrap();
            fs::set_permissions(root.join("config"), fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(root.join("workspace")).unwrap();
            fs::copy(&jail, root.join("ouro-jail")).unwrap();
            fs::set_permissions(root.join("ouro-jail"), fs::Permissions::from_mode(0o700)).unwrap();
            let mut daemon = writer(&ledger, root, "writer");
            let plan = Plan {
                kind: kind.into(),
                point: point.into(),
                action: action.into(),
                marker: root.join("fault"),
            };
            let mut command = worker(json!({"mode":"owner","root":root,"plan":plan}));
            command.env("OURO_CONFIG_DIR", root.join("config"));
            let mut owner = Process::spawn(&mut command, root.join("owner.log"));
            let outage = matches!(kind, "pending.outage" | "pending.source");
            if outage {
                wait_for(&mut owner, || root.join("workspace/started").exists());
                let run = Client::connect(&root.join("data"))
                    .unwrap()
                    .runs()
                    .unwrap()
                    .remove(0);
                daemon.kill();
                if kind == "pending.source" {
                    let pending = root.join("data/ledger").join(&run.run_id).join(STATE);
                    wait_for(&mut owner, || {
                        plan.marker.exists()
                            || fs::read(&pending)
                                .ok()
                                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                                .is_some_and(|v| v["state"]["active"] == true)
                    });
                    if !plan.marker.exists() {
                        fs::write(root.join("workspace/release"), b"").unwrap();
                    }
                }
            }
            let status = owner.finish();
            if action == "kill" {
                assert_eq!(
                    status.signal(),
                    Some(libc::SIGKILL),
                    "{case}: {}",
                    fs::read_to_string(&owner.log).unwrap()
                );
            } else {
                assert!(
                    status.success(),
                    "{case}: {}",
                    fs::read_to_string(&owner.log).unwrap()
                );
            }
            assert!(plan.marker.exists(), "{case}");
            if !outage {
                daemon.kill();
            }
            let store = Store::open(&root.join("data")).unwrap();
            let run = store.runs().remove(0);
            let path = store.root().join(&run.run_id).join("events-0001.ndjson");
            let before = fs::read(&path).unwrap();
            drop(store);
            stopped(root, &run);
            let executions = fs::read(root.join("workspace/executions")).unwrap_or_default();
            assert_eq!(
                executions,
                if kind == "pending.create" {
                    b"".as_slice()
                } else {
                    b"x".as_slice()
                },
                "{case}"
            );
            let _restarted = writer(&ledger, root, "restart");
            let mut client = Client::connect(&root.join("data")).unwrap();
            client.settle_orphans().unwrap();
            let recovered = client.show(&run.run_id).unwrap();
            let expected = if kind == "pending.remove"
                || (kind == "pending.completion" && action == "kill" && published(point))
            {
                "settled"
            } else {
                "outcome_unknown"
            };
            assert_eq!(recovered.state, expected, "{case}: {recovered:?}");
            let mut retry =
                Process::spawn(&mut replay(&ledger, root, kind), root.join("replay.log"));
            let replay_status = retry.finish();
            assert!(
                !fs::read_to_string(&retry.log)
                    .unwrap()
                    .contains("different prepare payload"),
                "replay must match original payload: {case}"
            );
            assert_eq!(
                replay_status.success(),
                expected == "settled",
                "{case}: {}",
                fs::read_to_string(&retry.log).unwrap()
            );
            assert_eq!(
                fs::read(root.join("workspace/executions")).unwrap_or_default(),
                executions,
                "{case}"
            );
            let runs = client.runs().unwrap();
            assert_eq!(runs.len(), 1);
            assert_eq!(runs[0].attempt_id, run.attempt_id);
            assert_eq!(runs[0].run_id, run.run_id);
            assert!(fs::read(path).unwrap().starts_with(&before), "{case}");
            eprintln!("pending launch case passed: {case}");
        }
    }
}
