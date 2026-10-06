//! Production owner and jail, with only the writer running in the test harness.
use super::*;
use crate::daemon::Client;

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
fn ready(data: &Path, writer: &mut Process) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Client::connect(data)
            .and_then(|mut client| client.ping())
            .is_ok()
        {
            return;
        }
        assert!(
            writer.child.try_wait().unwrap().is_none(),
            "writer exited: {}",
            fs::read_to_string(&writer.log).unwrap()
        );
        assert!(Instant::now() < deadline, "writer never became ready");
        thread::sleep(Duration::from_millis(10));
    }
}
fn owner(ledger: &Path, root: &Path, evidence: &str) -> Command {
    let mut command = Command::new(ledger);
    command
        .env("OURO_CONFIG_DIR", root.join("config"))
        .arg("--data-dir")
        .arg(root.join("data"))
        .args(["run", "--request-id", "lost-reply", "--jail-bin"])
        .arg(root.join("ouro-jail"))
        .arg("--workspace")
        .arg(root.join("workspace"))
        .args([
            "--jail",
            "tool",
            "--limit",
            "wall=10s",
            "--io",
            "batch",
            "--json",
            "--evidence",
            evidence,
            "--",
            "/bin/sh",
            "-c",
            "printf x >> executions",
        ]);
    command
}
fn executions(root: &Path) -> Vec<u8> {
    let file = root.join("workspace/executions");
    if file.exists() {
        fs::read(file).unwrap()
    } else {
        vec![]
    }
}
fn stopped(data: &Path, run: &RunRecord) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(bytes) = fs::read(
            data.join("attempts")
                .join(&run.attempt_id)
                .join("jail.json"),
        ) && let Ok(receipt) = serde_json::from_slice::<Value>(&bytes)
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
            "jail tree did not stop: {}",
            run.attempt_id
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn real_launch_gate_survives_admission_settlement_and_lost_reply_crashes() {
    let ledger = binary("ouro-ledger", "OURO_LEDGER_BIN");
    let jail = binary("ouro-jail", "OURO_JAIL_BIN");
    let doctor = Command::new(&jail).args(["doctor", "--json"]).output();
    if !doctor.is_ok_and(|output| {
        output.status.success()
            && serde_json::from_slice::<Value>(&output.stdout)
                .is_ok_and(|value| value["ready"] == true && value["component"] == "ouro-jail")
    }) {
        ouro_fixture::harness::skip_or_fail("lifecycle matrix needs a real ready ouro-jail");
        return;
    }
    assert!(
        ledger.is_file(),
        "build the production ledger binary before the native matrix"
    );
    for evidence in ["strict", "best-effort"] {
        let cases = ["admitted", "settled"]
            .into_iter()
            .flat_map(|kind| POINTS.into_iter().map(move |point| (kind, point)))
            .chain(KINDS.into_iter().map(|kind| (kind, "reply.before_send")));
        for (kind, point) in cases {
            let case = format!("{evidence}/{kind}/{point}");
            let temp = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let root = temp.path();
            let data = root.join("data");
            fs::create_dir(root.join("config")).unwrap();
            fs::set_permissions(root.join("config"), fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(root.join("workspace")).unwrap();
            fs::copy(&jail, root.join("ouro-jail")).unwrap();
            fs::set_permissions(root.join("ouro-jail"), fs::Permissions::from_mode(0o700)).unwrap();
            let plan = Plan {
                kind: kind.into(),
                point: point.into(),
                action: "kill".into(),
                marker: root.join("fault"),
            };
            let mut writer = Process::spawn(
                worker("daemon", &data, &plan).env("OURO_CONFIG_DIR", root.join("config")),
                root.join("writer.log"),
            );
            ready(&data, &mut writer);
            let mut launch =
                Process::spawn(&mut owner(&ledger, root, evidence), root.join("owner.log"));
            let status = launch.finish();
            assert_eq!(
                writer.finish().signal(),
                Some(libc::SIGKILL),
                "{case}: writer {} owner {status}: {}",
                fs::read_to_string(&writer.log).unwrap(),
                fs::read_to_string(&launch.log).unwrap()
            );
            assert!(
                plan.marker.exists(),
                "{case}: requested hook was never reached"
            );
            let before = executions(root);
            match kind {
                "prepared" | "owner_claimed" | "admitted" => assert!(
                    before.is_empty(),
                    "gate opened without acknowledgement: {case}"
                ),
                "settled" => assert_eq!(before, b"x", "{case}"),
                "source" => assert!(before.len() <= 1, "{case}"),
                _ => unreachable!(),
            }
            let store = Store::open(&data).unwrap();
            let run = store.runs().remove(0);
            let bytes = canonical(&store);
            drop(store);
            if !matches!(kind, "prepared" | "owner_claimed") {
                stopped(&data, &run);
            }
            let mut restart = Command::new(&ledger);
            restart
                .env("OURO_CONFIG_DIR", root.join("config"))
                .arg("--data-dir")
                .arg(&data)
                .arg("serve");
            let mut writer = Process::spawn(&mut restart, root.join("restarted.log"));
            ready(&data, &mut writer);
            let mut client = Client::connect(&data).unwrap();
            client.settle_orphans().unwrap();
            let recovered = client.show(&run.run_id).unwrap();
            if kind == "settled" {
                let expected = if point == "event.partial_write"
                    || (point == "event.before_write" && evidence == "strict")
                {
                    "outcome_unknown"
                } else {
                    "settled"
                };
                assert_eq!(recovered.state, expected, "{case}: {recovered:?}");
            }
            let mut replay =
                Process::spawn(&mut owner(&ledger, root, evidence), root.join("replay.log"));
            replay.finish();
            assert_eq!(
                executions(root),
                if kind == "prepared" {
                    b"x".to_vec()
                } else {
                    before
                },
                "replay executed another child: {case}"
            );
            let runs = client.runs().unwrap();
            assert_eq!(runs.len(), 1, "{case}");
            assert_eq!(runs[0].run_id, run.run_id, "{case}");
            assert_eq!(runs[0].attempt_id, run.attempt_id, "{case}");
            let after = fs::read(
                data.join("ledger")
                    .join(&run.run_id)
                    .join("events-0001.ndjson"),
            )
            .unwrap();
            assert!(
                after.starts_with(&bytes),
                "canonical history was rewritten: {case}"
            );
            if point == "event.partial_write" {
                assert_eq!(after, bytes, "poisoned stream was extended: {case}");
            }
            eprintln!("lifecycle launch case passed: {case}");
        }
    }
}
