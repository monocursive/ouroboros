//! Real local CLI/socket/store round trips; no jail or launch owner is exercised.
#![cfg(unix)]

use std::{
    fs::{self, OpenOptions},
    os::unix::{
        fs::{FileTypeExt as _, OpenOptionsExt as _, PermissionsExt as _},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

const WAIT_LIMIT: Duration = Duration::from_secs(5);

#[test]
fn doctor_does_not_start_a_session_writer() {
    let mut cli = LocalCli::new();
    let output = cli.invoke(&["doctor", "--json"]);
    assert!(!output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ready"], false);
    assert_eq!(value["writer"], "unreachable");
    assert!(!cli.data.join("ledger/serve.sock").exists());
}

#[test]
fn retention_cli_persists_holds_and_preview_never_starts_or_mutates_a_writer() {
    let mut cli = LocalCli::new();
    assert!(!cli.invoke(&["gc", "--dry-run", "--json"]).status.success());
    assert!(!cli.data.join("ledger").exists());
    assert!(!cli.invoke(&["gc", "--json"]).status.success());
    assert!(!cli.data.join("ledger").exists());
    let writer = cli.start_writer();
    let run = successful_preparation(&cli.prepare("retention-cli", &fixture_request()));
    let run_id = run["run_id"].as_str().unwrap();
    let held = cli.json(&["hold", run_id, "--request-id", "stable-hold", "--json"]);
    assert_eq!(held["operation"], "hold");
    assert_eq!(
        cli.json(&["show", run_id, "--json"])["holds"],
        json!(["operator"])
    );
    drop(writer);
    let _writer = cli.start_writer();
    assert_eq!(
        cli.json(&["hold", run_id, "--request-id", "stable-hold", "--json"]),
        held
    );
    let before = fs::read(
        cli.data
            .join("ledger")
            .join(run_id)
            .join("events-0001.ndjson"),
    )
    .unwrap();
    let projection = fs::read(cli.data.join("ledger").join(run_id).join("run.json")).unwrap();
    let plan = cli.json(&["gc", "--dry-run", "--json"]);
    assert_eq!(plan["schema"], "ouro.ledger.gc-plan/1");
    assert_eq!(plan["retain_days"], 90);
    assert_eq!(plan["deletion_supported"], true);
    assert_eq!(plan["verification_required"], true);
    assert_eq!(plan["runs"][0]["candidate"], false);
    assert!(
        plan["runs"][0]["keep_reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("operator_hold"))
    );
    assert_eq!(
        fs::read(
            cli.data
                .join("ledger")
                .join(run_id)
                .join("events-0001.ndjson")
        )
        .unwrap(),
        before
    );
    assert_eq!(
        fs::read(cli.data.join("ledger").join(run_id).join("run.json")).unwrap(),
        projection
    );
    assert!(!cli.data.join("ledger/readers").exists());
    let released = cli.json(&[
        "release",
        run_id,
        "--request-id",
        "stable-release",
        "--json",
    ]);
    assert_eq!(released["operation"], "release");
    assert_eq!(
        cli.json(&["hold", run_id, "--request-id", "stable-hold", "--json"]),
        held
    );
    assert!(cli.json(&["show", run_id, "--json"]).get("holds").is_none());
    assert!(
        !cli.invoke(&["release", run_id, "--request-id", "stable-hold"])
            .status
            .success()
    );
    let generated = cli.json(&["hold", run_id, "--json"]);
    assert!(
        generated["request_id"]
            .as_str()
            .unwrap()
            .starts_with("retention_")
    );
    assert!(
        !cli.invoke(&["gc", "--dry-run", "--limit", "101"])
            .status
            .success()
    );
    assert!(
        !cli.invoke(&["gc", "--dry-run", "--retain-days", "0"])
            .status
            .success()
    );
}

#[test]
fn gc_cli_prunes_aged_fixture_history_and_preserves_preparation_identity_after_restart() {
    use ouro_records::canonical::{sha256_prefixed, to_jcs};
    use std::{io::Write, time::SystemTime};
    let mut cli = LocalCli::new();
    let mut records =
        include_str!("../../../docs/specs/ledger-v1/fixtures/exec-failure-records.ndjson")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
    let run_id = records[0]["run_id"].as_str().unwrap().to_owned();
    let request_id = records[0]["body"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let payload = records[0]["body"]["payload"].clone();
    let run_dir = cli.data.join("ledger").join(&run_id);
    for path in [
        cli.data.join("ledger"),
        run_dir.clone(),
        run_dir.join("artifacts"),
        run_dir.join("receipts"),
    ] {
        fs::create_dir(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let timestamp =
        ouro_records::records::rfc3339_utc(SystemTime::now() - Duration::from_secs(2 * 86_400));
    let mut previous = None::<String>;
    let mut stream = Vec::new();
    for record in &mut records {
        record["prev"] = json!(previous);
        record["received_at"] = json!(timestamp);
        let bytes = to_jcs(record).unwrap();
        previous = Some(sha256_prefixed(&bytes));
        stream.extend(bytes);
        stream.push(b'\n');
    }
    private_file(&run_dir.join("events-0001.ndjson"))
        .write_all(&stream)
        .unwrap();
    let writer = cli.start_writer();
    let plan = cli.json(&["gc", "--dry-run", "--retain-days", "1", "--json"]);
    assert_eq!(plan["runs"][0]["candidate"], true);
    assert!(run_dir.join("events-0001.ndjson").exists());
    let result = cli.json(&["gc", "--retain-days", "1", "--json"]);
    assert_eq!(result["failed"], json!([]));
    assert_eq!(result["pruned"][0]["run_id"], run_id);
    assert!(!run_dir.join("events-0001.ndjson").exists());
    let shown = cli.json(&["show", &run_id, "--json"]);
    assert_eq!(shown["history"]["state"], "pruned");
    assert_eq!(shown["state"], "settled");
    assert_eq!(shown["outcome"]["kind"], "exec_error");
    let exported = cli.invoke(&["export", &run_id, "--ndjson", "--json"]);
    assert!(!exported.status.success());
    assert!(exported.stdout.is_empty());
    assert!(String::from_utf8_lossy(&exported.stderr).contains("pruned"));
    drop(writer);
    let _writer = cli.start_writer();
    let again = cli.json(&["gc", "--retain-days", "1", "--json"]);
    assert_eq!(again["pruned"], result["pruned"]);
    let prepared = successful_preparation(&cli.prepare(&request_id, &payload));
    assert_eq!(prepared["run_id"], run_id);
    assert_eq!(prepared["history"]["state"], "pruned");
    let verified = cli.json(&["verify", &run_id, "--json"]);
    assert_eq!(verified[0]["local_consistency"], true);
    assert_eq!(verified[0]["events"], 0);
    assert_eq!(verified[0]["history"]["state"], "pruned");
}

#[test]
fn writer_owns_persistent_policy_and_cli_capture_expiry_preserves_export_after_restart() {
    use ouro_records::canonical::{sha256_prefixed, to_jcs};
    use std::{io::Write, time::SystemTime};
    let mut cli = LocalCli::new();
    let config = cli.temp.path().join("config");
    fs::create_dir(&config).unwrap();
    let path = config.join("config.toml");
    fs::write(&path, "[ledger]\nretain='30d'\ncapture_retain='1d'\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut records =
        include_str!("../../../docs/specs/ledger-v1/fixtures/exec-failure-records.ndjson")
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .collect::<Vec<_>>();
    let id = records[0]["run_id"].as_str().unwrap().to_owned();
    records[0]["body"]["payload"]["capture"]["streams"] = json!(["stdout"]);
    records.last_mut().unwrap()["body"]["capture"] = json!({"stdout":{"state":"captured","stored_bytes":7,"path":"artifacts/stdout.bin"},"stderr":{"state":"not_captured"}});
    let root = cli.data.join("ledger").join(&id);
    for p in [
        cli.data.join("ledger"),
        root.clone(),
        root.join("artifacts"),
        root.join("receipts"),
    ] {
        fs::create_dir(&p).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let timestamp =
        ouro_records::records::rfc3339_utc(SystemTime::now() - Duration::from_secs(3 * 86_400));
    let mut prev = None::<String>;
    let mut bytes = Vec::new();
    for r in &mut records {
        r["prev"] = json!(prev);
        r["received_at"] = json!(timestamp);
        let line = to_jcs(r).unwrap();
        prev = Some(sha256_prefixed(&line));
        bytes.extend(line);
        bytes.push(b'\n');
    }
    private_file(&root.join("events-0001.ndjson"))
        .write_all(&bytes)
        .unwrap();
    private_file(&root.join("artifacts/stdout.bin"))
        .write_all(b"capture")
        .unwrap();
    let writer = cli.start_writer();
    fs::write(&path, "[ledger]\nretain='60d'\ncapture_retain='2d'\n").unwrap();
    let plan = cli.json(&["gc", "--dry-run", "--json"]);
    assert_eq!(plan["retain_days"], 30);
    assert_eq!(plan["capture_retain_days"], 1);
    assert!(
        !cli.invoke(&[
            "gc",
            "--retain-days",
            "1",
            "--capture-retain-days",
            "2",
            "--json"
        ])
        .status
        .success()
    );
    assert_eq!(fs::read(root.join("events-0001.ndjson")).unwrap(), bytes);
    drop(writer);
    let writer = cli.start_writer();
    let plan = cli.json(&["gc", "--dry-run", "--json"]);
    assert_eq!(plan["retain_days"], 60);
    assert_eq!(plan["capture_retain_days"], 2);
    assert_eq!(
        cli.json(&["doctor", "--json"])["retention"],
        json!({"retain_days":60,"capture_retain_days":2})
    );
    assert_eq!(plan["runs"][0]["candidate"], false);
    assert_eq!(plan["runs"][0]["captures_candidate"], true);
    let result = cli.json(&["gc", "--json"]);
    assert_eq!(result["failed"], json!([]));
    assert_eq!(result["pruned"], json!([]));
    assert_eq!(result["captures_pruned"][0]["removed_bytes"], 7);
    assert!(!root.join("artifacts/stdout.bin").exists());
    drop(writer);
    let _writer = cli.start_writer();
    let shown = cli.json(&["show", &id, "--json"]);
    assert!(shown["history"].is_null());
    assert_eq!(shown["capture_history"]["state"], "pruned");
    let export = cli.invoke(&["export", &id, "--ndjson", "--json"]);
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert_eq!(export.stdout, bytes);
    let verified = cli.json(&["verify", &id, "--json"]);
    assert_eq!(verified[0]["local_consistency"], true);
    assert_eq!(verified[0]["events"], records.len());
    let repeated = cli.json(&["gc", "--json"]);
    assert_eq!(repeated["failed"], json!([]));
    assert_eq!(repeated["pruned"], json!([]));
    assert_eq!(fs::read(root.join("events-0001.ndjson")).unwrap(), bytes);
}

/// Own every subprocess from spawn through wait, including assertion failures.
struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn private_file(path: &Path) -> fs::File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("private subprocess output")
}

struct LocalCli {
    temp: tempfile::TempDir,
    data: PathBuf,
    command_count: usize,
}

impl LocalCli {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("private test directory");
        let data = temp.path().join("data");
        fs::create_dir(&data).expect("private data directory");
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            temp,
            data,
            command_count: 0,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ouro-ledger"));
        command.arg("--data-dir").arg(&self.data);
        command.env("OURO_CONFIG_DIR", self.temp.path().join("config"));
        command.stdin(Stdio::null());
        command
    }

    fn start_writer(&mut self) -> Process {
        self.command_count += 1;
        let log = self
            .temp
            .path()
            .join(format!("serve-{}.stderr", self.command_count));
        let mut writer = Process(
            self.command()
                .arg("serve")
                .stdout(Stdio::null())
                .stderr(Stdio::from(private_file(&log)))
                .spawn()
                .expect("start real writer"),
        );
        let deadline = Instant::now() + WAIT_LIMIT;
        let socket = self.data.join("ledger/serve.sock");
        loop {
            assert!(
                Instant::now() < deadline,
                "writer did not listen within {WAIT_LIMIT:?}: {}",
                fs::read_to_string(&log).unwrap_or_default()
            );
            if let Some(status) = writer.0.try_wait().expect("writer status") {
                panic!(
                    "writer exited {status}: {}",
                    fs::read_to_string(&log).unwrap_or_default()
                );
            }
            if fs::symlink_metadata(&socket).is_ok_and(|meta| {
                meta.file_type().is_socket() && meta.permissions().mode() & 0o777 == 0o600
            }) && UnixStream::connect(&socket).is_ok()
            {
                return writer;
            }
            thread::sleep(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    /// Files avoid pipe backpressure; the subprocess has its own bounded wait.
    fn invoke(&mut self, arguments: &[&str]) -> Output {
        self.command_count += 1;
        let stdout = self
            .temp
            .path()
            .join(format!("command-{}.stdout", self.command_count));
        let stderr = self
            .temp
            .path()
            .join(format!("command-{}.stderr", self.command_count));
        let mut process = Process(
            self.command()
                .args(arguments)
                .stdout(Stdio::from(private_file(&stdout)))
                .stderr(Stdio::from(private_file(&stderr)))
                .spawn()
                .expect("start real CLI"),
        );
        let deadline = Instant::now() + WAIT_LIMIT;
        let status = loop {
            if let Some(status) = process.0.try_wait().expect("CLI status") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "CLI {arguments:?} did not terminate within {WAIT_LIMIT:?}"
            );
            thread::sleep(Duration::from_millis(10));
        };
        Output {
            status,
            stdout: fs::read(stdout).expect("CLI stdout"),
            stderr: fs::read(stderr).expect("CLI stderr"),
        }
    }

    fn json(&mut self, arguments: &[&str]) -> Value {
        let output = self.invoke(arguments);
        assert!(
            output.status.success(),
            "{arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "unexpected CLI diagnostic");
        serde_json::from_slice(&output.stdout).expect("one actual CLI JSON value")
    }

    fn prepare(&mut self, request_id: &str, payload: &Value) -> Output {
        let file = self.temp.path().join("request.json");
        fs::write(&file, serde_json::to_vec(payload).unwrap()).unwrap();
        self.invoke(&[
            "prepare",
            "--request-id",
            request_id,
            "--body-file",
            file.to_str().unwrap(),
            "--json",
        ])
    }
}

fn fixture_request() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/specs/ledger-v1/fixtures/request.json"
    ))
    .unwrap()
}

fn successful_preparation(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "prepare failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("prepare JSON")
}

fn assert_consistent_unlaunched_report(report: &Value, run_id: &str) {
    let reports = report.as_array().expect("verification is an array");
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0]["run_id"], run_id);
    assert_eq!(reports[0]["local_consistency"], true);
    assert_eq!(reports[0]["events"], 1);
    assert_eq!(reports[0]["problems"], json!([]));
    assert_eq!(reports[0]["child_protection"], "unprotected");
    assert_eq!(reports[0]["coverage"], json!({"status":"unobserved"}));
}

#[test]
fn preparation_replay_and_inspection_survive_writer_restart() {
    let mut cli = LocalCli::new();
    let writer = cli.start_writer();
    let payload = fixture_request();
    let original = successful_preparation(&cli.prepare("portable-stable-request", &payload));
    assert_eq!(original["schema"], "ouro.ledger.run/1");
    assert_eq!(original["request_id"], "portable-stable-request");
    assert_eq!(original["payload"], payload);
    assert_eq!(original["state"], "prepared");
    assert_eq!(original["settlement"], "pending");
    assert_eq!(original["child_protection"], "unprotected");
    assert_eq!(original["coverage"], json!({"status":"unobserved"}));
    assert!(original["owner"].is_null());
    assert!(original["outcome"].is_null());
    assert_eq!(original["chain"]["head_seq"], 1);
    let run_id = original["run_id"].as_str().unwrap().to_owned();
    let attempt_id = original["attempt_id"].as_str().unwrap();
    assert!(run_id.starts_with("run_"));
    assert!(attempt_id.starts_with("att_"));
    assert_eq!(
        successful_preparation(&cli.prepare("portable-stable-request", &payload)),
        original,
        "an identical request must return the original identities and chain head"
    );

    let mut conflict = payload.clone();
    conflict["capture"]["limit_bytes"] = json!(33);
    let refused = cli.prepare("portable-stable-request", &conflict);
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("different prepare payload"),
        "the valid alternate payload must refuse because its request id is already bound"
    );
    assert_eq!(cli.json(&["show", &run_id, "--json"]), original);
    assert_eq!(cli.json(&["runs", "--json"]), json!([original.clone()]));
    let verification = cli.json(&["verify", &run_id, "--json"]);
    assert_consistent_unlaunched_report(&verification, &run_id);
    let doctor = cli.json(&["doctor", "--json"]);
    assert_eq!(doctor["component"], "ouro-ledger");
    assert_eq!(doctor["ready"], true);
    assert_eq!(doctor["writer"], "reachable");
    assert_eq!(doctor["store"], verification);
    assert_eq!(doctor["managed_authorization"], "not_implemented");

    let stream = cli
        .data
        .join("ledger")
        .join(&run_id)
        .join("events-0001.ndjson");
    let bytes_before_restart = fs::read(&stream).unwrap();
    drop(writer); // Kill and wait before the next writer acquires the same store.
    let _restarted_writer = cli.start_writer();
    assert_eq!(cli.json(&["show", &run_id, "--json"]), original);
    assert_eq!(
        successful_preparation(&cli.prepare("portable-stable-request", &payload)),
        original,
        "recovery must retain the original run/attempt identities and replay mapping"
    );
    assert!(
        !cli.prepare("portable-stable-request", &conflict)
            .status
            .success()
    );
    assert_eq!(cli.json(&["runs", "--json"]), json!([original]));
    assert_consistent_unlaunched_report(&cli.json(&["verify", "--json"]), &run_id);
    assert_eq!(fs::read(&stream).unwrap(), bytes_before_restart);
}

#[test]
fn locked_disposable_index_does_not_delay_the_next_daemon_request() {
    let mut cli = LocalCli::new();
    let _writer = cli.start_writer();
    let mut client = ouro_ledger::daemon::Client::connect(&cli.data).unwrap();
    assert_eq!(client.ping().unwrap()["index"]["state"], "ready");

    let index = rusqlite::Connection::open(cli.data.join("ledger/index.sqlite")).unwrap();
    index.execute_batch("BEGIN IMMEDIATE").unwrap();
    let payload = fixture_request();
    let original = client.prepare("locked-index-request", &payload).unwrap();
    let stream = cli
        .data
        .join("ledger")
        .join(&original.run_id)
        .join("events-0001.ndjson");
    let canonical = fs::read(&stream).unwrap();

    // This request uses the real client's existing two-second timeout. The
    // writer must stop trying the disposable index while another connection
    // retains its write lock, so the next request still reaches dispatch.
    let status = client
        .ping()
        .expect("index contention must not stall the writer");
    assert_eq!(status["index"]["state"], "unavailable");
    assert!(
        status["index"]["error"]
            .as_str()
            .unwrap()
            .contains("database is locked")
    );
    assert_eq!(
        serde_json::to_value(client.prepare("locked-index-request", &payload).unwrap()).unwrap(),
        serde_json::to_value(&original).unwrap(),
        "retry keeps the original identities and receipt while the index stays locked"
    );
    assert_eq!(
        serde_json::to_value(client.runs().unwrap()).unwrap(),
        json!([original])
    );
    assert_eq!(original.chain.head_seq, 1);
    let report = serde_json::to_value(client.verify(Some(&original.run_id)).unwrap()).unwrap();
    assert_consistent_unlaunched_report(&report, &original.run_id);
    assert_eq!(fs::read(stream).unwrap(), canonical);
    index.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn prepare_cli_refuses_raw_metadata_without_persisting_it() {
    const SENTINEL: &str = "portable-raw-argv-must-never-enter-the-store";
    let mut cli = LocalCli::new();
    let _writer = cli.start_writer();
    let mut unsafe_payload = fixture_request();
    unsafe_payload["raw_argv"] = json!([SENTINEL]);
    let refused = cli.prepare("portable-unsafe-metadata", &unsafe_payload);
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    let diagnostic = String::from_utf8_lossy(&refused.stderr);
    assert!(diagnostic.contains("digest-only request plan"));
    assert!(!diagnostic.contains(SENTINEL));
    assert_eq!(cli.json(&["runs", "--json"]), json!([]));

    let accepted =
        successful_preparation(&cli.prepare("portable-safe-metadata", &fixture_request()));
    let run_id = accepted["run_id"].as_str().unwrap();
    let directory = cli.data.join("ledger").join(run_id);
    for file in ["events-0001.ndjson", "run.json"] {
        let bytes = fs::read(directory.join(file)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains(SENTINEL), "raw argument persisted in {file}");
        assert!(
            !text.contains("raw_argv"),
            "raw argv field persisted in {file}"
        );
    }
    assert_consistent_unlaunched_report(&cli.json(&["verify", "--json"]), run_id);
}
