//! Real reader CLI/socket round trips over synthetic canonical fixtures, without a jail.
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

use ouro_records::canonical::{sha256_prefixed, to_jcs};
use serde_json::{Value, json};

const RUN: &str = "run_11111111111111111111111111111111";

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
        .unwrap()
}

struct Fixture {
    // The daemon must be stopped before TempDir removes its store.
    writer: Option<Process>,
    temp: tempfile::TempDir,
    data: PathBuf,
    stream: PathBuf,
    bytes: Vec<u8>,
    records: Vec<Value>,
    snapshot: Value,
    commands: usize,
}

impl Fixture {
    fn new(mut records: Vec<Value>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let directory = data.join("ledger").join(RUN);
        fs::create_dir_all(&directory).unwrap();
        for path in [&data, &data.join("ledger"), &directory] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut bytes = Vec::new();
        let mut previous = None;
        for (index, record) in records.iter_mut().enumerate() {
            record["seq"] = json!(index + 1);
            record["prev"] = json!(previous);
            record["received_at"] = json!(format!("2026-09-30T12:00:{:02}Z", index + 1));
            let encoded = to_jcs(record).unwrap();
            previous = Some(sha256_prefixed(&encoded));
            bytes.extend(encoded);
            bytes.push(b'\n');
        }
        let stream = directory.join("events-0001.ndjson");
        use std::io::Write as _;
        private_file(&stream).write_all(&bytes).unwrap();
        let snapshot = json!({"head_seq":records.len(),"head_digest":previous});
        let mut fixture = Self {
            writer: None,
            temp,
            data,
            stream,
            bytes,
            records,
            snapshot,
            commands: 0,
        };
        fixture.start_writer();
        fixture
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ouro-ledger"));
        command
            .arg("--data-dir")
            .arg(&self.data)
            .stdin(Stdio::null());
        command
    }

    fn start_writer(&mut self) {
        self.commands += 1;
        let log = self.temp.path().join(format!("writer-{}", self.commands));
        self.writer = Some(Process(
            self.command()
                .arg("serve")
                .stdout(Stdio::null())
                .stderr(Stdio::from(private_file(&log)))
                .spawn()
                .unwrap(),
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        let socket = self.data.join("ledger/serve.sock");
        loop {
            assert!(
                Instant::now() < deadline,
                "writer readiness exceeded five seconds"
            );
            if let Some(status) = self.writer.as_mut().unwrap().0.try_wait().unwrap() {
                panic!(
                    "writer exited {status}: {}",
                    fs::read_to_string(&log).unwrap()
                );
            }
            if fs::symlink_metadata(&socket).is_ok_and(|meta| {
                meta.file_type().is_socket() && meta.permissions().mode() & 0o777 == 0o600
            }) && UnixStream::connect(&socket).is_ok()
            {
                return;
            }
            thread::sleep(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn run(&mut self, arguments: &[&str]) -> Output {
        self.commands += 1;
        let stdout = self.temp.path().join(format!("stdout-{}", self.commands));
        let stderr = self.temp.path().join(format!("stderr-{}", self.commands));
        let mut child = Process(
            self.command()
                .args(arguments)
                .stdout(Stdio::from(private_file(&stdout)))
                .stderr(Stdio::from(private_file(&stderr)))
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "reader CLI {arguments:?} timed out"
            );
            thread::sleep(Duration::from_millis(10));
        };
        Output {
            status,
            stdout: fs::read(stdout).unwrap(),
            stderr: fs::read(stderr).unwrap(),
        }
    }

    fn query(&mut self, extra: &[&str]) -> Value {
        let mut arguments = vec!["query", "--run", RUN, "--execs", "--json"];
        arguments.extend_from_slice(extra);
        let output = self.run(&arguments);
        assert!(
            output.status.success(),
            "query: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

fn records() -> Vec<Value> {
    include_str!("../../../docs/specs/ledger-v1/fixtures/exec-failure-records.ndjson")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn query_filters_paginate_exact_attribution_and_refuse_cursor_rebinding() {
    let mut records = records();
    let mut second_exec = records[4].clone();
    second_exec["source_seq"] = json!(2);
    second_exec["request_id"] = json!("source:audit:2");
    records.insert(5, second_exec);
    let mut fixture = Fixture::new(records);
    let first = fixture.query(&["--limit", "1"]);
    assert_eq!(first["snapshot"], fixture.snapshot);
    assert_eq!(first["child_protection"], "enforced");
    assert!(first["coverage"].is_object());
    assert_eq!(first["records"], json!([fixture.records[4].clone()]));
    let cursor = first["next_cursor"]
        .as_str()
        .expect("second match needs a cursor")
        .to_owned();
    let second = fixture.query(&["--limit", "1", "--cursor", &cursor]);
    assert_eq!(second["snapshot"], first["snapshot"]);
    assert_eq!(second["records"], json!([fixture.records[5].clone()]));
    assert_eq!(
        fixture.query(&["--limit", "1", "--cursor", &cursor]),
        second
    );

    let rebound = fixture.run(&[
        "query", "--run", RUN, "--paths", "--limit", "1", "--cursor", &cursor, "--json",
    ]);
    assert!(!rebound.status.success());
    assert!(rebound.stdout.is_empty());
    assert!(
        !fixture
            .run(&[
                "query", "--run", RUN, "--execs", "--limit", "2", "--cursor", &cursor, "--json"
            ])
            .status
            .success()
    );
    let bounded = fixture.query(&[
        "--stage",
        "result",
        "--since",
        "2026-09-30T12:00:06Z",
        "--until",
        "2026-09-30T12:00:07Z",
    ]);
    assert_eq!(bounded["records"], json!([fixture.records[5].clone()]));
    assert_eq!(fixture.query(&["--stage", "attempt"])["records"], json!([]));

    for extra in [
        vec!["--limit", "0"],
        vec!["--limit", "1001"],
        vec!["--since", "2026-02-30T12:00:00Z"],
        vec!["--stage", "decision"],
    ] {
        let mut arguments = vec!["query", "--run", RUN, "--execs", "--json"];
        arguments.extend(extra);
        assert!(
            !fixture.run(&arguments).status.success(),
            "invalid reader restriction accepted"
        );
    }
    drop(fixture.writer.take());
    fixture.start_writer();
    let expired = fixture.run(&[
        "query", "--run", RUN, "--execs", "--limit", "1", "--cursor", &cursor, "--json",
    ]);
    assert!(!expired.status.success());
    assert!(expired.stdout.is_empty());
    assert_eq!(
        fs::read(&fixture.stream).unwrap(),
        fixture.bytes,
        "readers must not rewrite canonical history"
    );
}

#[test]
fn export_keeps_large_canonical_record_bytes_out_of_status_metadata() {
    let mut records = records();
    let mut note = records[3].clone();
    note["kind"] = json!("note");
    note["request_id"] = json!("large-fixture-note");
    note["body"] = json!({"message":"x".repeat(200_000)});
    records.insert(5, note);
    let mut fixture = Fixture::new(records);
    let output = fixture.run(&["export", RUN, "--ndjson", "--json"]);
    assert!(
        output.status.success(),
        "export: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout, fixture.bytes,
        "export must preserve exact canonical bytes and delimiters"
    );
    let statuses = status_events(&output.stderr);
    let status = statuses.last().expect("finished status");
    assert_eq!(status["schema"], "ouro.ledger.export/1");
    assert_eq!(status["event"], "finished");
    assert_eq!(status["snapshot"], fixture.snapshot);
    assert_eq!(status["bytes_written"], fixture.bytes.len());
    assert_eq!(status["local_consistency"], true);
    assert_eq!(status["stream_status"], "complete");
    assert_eq!(status["done"], true);
    assert_eq!(status["child_protection"], "enforced");
    assert!(status.get("ndjson").is_none() && status.get("records").is_none());
    let checkpoint = statuses
        .iter()
        .rfind(|event| event["event"] == "checkpoint")
        .expect("large export needs a checkpoint");
    let prefix = checkpoint["bytes_written"].as_u64().unwrap() as usize;
    let cursor = checkpoint["next_cursor"].as_str().unwrap();
    let resumed = fixture.run(&["export", RUN, "--ndjson", "--json", "--cursor", cursor]);
    assert!(
        resumed.status.success(),
        "resume: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let mut combined = output.stdout[..prefix].to_vec();
    combined.extend_from_slice(&resumed.stdout);
    assert_eq!(
        combined, fixture.bytes,
        "checkpoint resume must preserve one exact original snapshot"
    );
    assert_eq!(
        status_events(&resumed.stderr).last().unwrap()["snapshot"],
        fixture.snapshot
    );
    assert_eq!(fs::read(&fixture.stream).unwrap(), fixture.bytes);
}

#[test]
fn incomplete_history_exports_only_verified_prefix_and_exits_nonzero() {
    let mut fixture = Fixture::new(records());
    drop(fixture.writer.take());
    use std::io::Write as _;
    OpenOptions::new()
        .append(true)
        .open(&fixture.stream)
        .unwrap()
        .write_all(b"{\"incomplete\":")
        .unwrap();
    let damaged = fs::read(&fixture.stream).unwrap();
    fixture.start_writer();
    let output = fixture.run(&["export", RUN, "--ndjson", "--json"]);
    assert!(!output.status.success());
    assert_eq!(output.stdout, fixture.bytes);
    let statuses = status_events(&output.stderr);
    let status = statuses.last().expect("incomplete export status");
    assert_eq!(status["local_consistency"], false);
    assert_ne!(status["stream_status"], "complete");
    assert!(!status["problems"].as_array().unwrap().is_empty());
    assert_eq!(status["bytes_written"], fixture.bytes.len());
    assert_eq!(
        fs::read(&fixture.stream).unwrap(),
        damaged,
        "reader must retain the damaged tail"
    );
}

#[test]
fn live_writer_detects_unexpected_tail_before_export() {
    let mut fixture = Fixture::new(records());
    use std::io::Write as _;
    OpenOptions::new()
        .append(true)
        .open(&fixture.stream)
        .unwrap()
        .write_all(b"{\"incomplete\":")
        .unwrap();
    let damaged = fs::read(&fixture.stream).unwrap();
    let output = fixture.run(&["export", RUN, "--ndjson", "--json"]);
    assert!(!output.status.success());
    assert_eq!(output.stdout, fixture.bytes);
    let statuses = status_events(&output.stderr);
    let status = statuses.last().expect("incomplete live export status");
    assert_eq!(status["snapshot"], fixture.snapshot);
    assert_eq!(status["local_consistency"], false);
    assert_eq!(status["stream_status"], "incomplete");
    assert!(!status["problems"].as_array().unwrap().is_empty());
    assert_eq!(status["bytes_written"], fixture.bytes.len());
    assert_eq!(fs::read(&fixture.stream).unwrap(), damaged);
    assert!(
        fixture
            .writer
            .as_mut()
            .unwrap()
            .0
            .try_wait()
            .unwrap()
            .is_none(),
        "this case must exercise the original live writer"
    );
}

#[test]
fn closed_export_sink_exits_nonzero_without_finished_success() {
    let mut records = records();
    for index in 0..2 {
        let mut note = records[3].clone();
        note["kind"] = json!("note");
        note["request_id"] = json!(format!("closed-sink-note-{index}"));
        note["body"] = json!({"message":"x".repeat(800_000)});
        records.insert(5, note);
    }
    let mut fixture = Fixture::new(records);
    fixture.commands += 1;
    let stderr = fixture
        .temp
        .path()
        .join(format!("stderr-{}", fixture.commands));
    let mut child = Process(
        fixture
            .command()
            .args(["export", RUN, "--ndjson", "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::from(private_file(&stderr)))
            .spawn()
            .unwrap(),
    );
    let mut pipe = child.0.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        use std::io::Read as _;
        let mut prefix = [0_u8; 8];
        let result = pipe.read_exact(&mut prefix).map(|()| prefix);
        drop(pipe);
        let _ = sender.send(result);
    });
    let prefix = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("export did not produce a prefix within five seconds")
        .expect("export closed before producing its prefix");
    reader.join().unwrap();
    assert_eq!(prefix.as_slice(), &fixture.bytes[..8]);
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "closed export sink did not stop");
        thread::sleep(Duration::from_millis(10));
    };
    assert!(!status.success());
    let metadata = fs::read_to_string(stderr).unwrap();
    assert!(metadata.lines().all(|line| {
        match serde_json::from_str::<Value>(line) {
            Ok(event) => !(event["event"] == "finished" && event["done"] == true),
            Err(_) => true,
        }
    }));
    assert_eq!(
        fs::read(&fixture.stream).unwrap(),
        fixture.bytes,
        "failed output must not change canonical history"
    );
}

fn status_events(bytes: &[u8]) -> Vec<Value> {
    std::str::from_utf8(bytes)
        .expect("status NDJSON is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("each status line is JSON"))
        .collect()
}
