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
