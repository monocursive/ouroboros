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

    fn restart(&mut self) {
        drop(self.writer.take());
        self.start_writer();
    }

    fn add_run(&mut self, run: &str, mut records: Vec<Value>) {
        use std::io::Write as _;
        drop(self.writer.take());
        let directory = self.data.join("ledger").join(run);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let mut previous = None;
        let mut file = private_file(&directory.join("events-0001.ndjson"));
        for record in &mut records {
            record["run_id"] = json!(run);
            if record["kind"] == "prepared" {
                record["body"]["request_id"] = json!(format!("fixture-{run}"));
                record["request_id"] = json!(format!("prepare:fixture-{run}"));
            }
            record["prev"] = json!(previous);
            let encoded = to_jcs(record).unwrap();
            previous = Some(sha256_prefixed(&encoded));
            file.write_all(&encoded).unwrap();
            file.write_all(b"\n").unwrap();
        }
        drop(file);
        self.start_writer();
    }

    fn checkpoint(&self, cursor: &str) -> PathBuf {
        self.data
            .join("ledger/readers")
            .join(format!("{}.json", &cursor[..32]))
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
    assert_eq!(
        fixture.query(&["--limit", "1", "--cursor", &cursor]),
        second
    );
    assert_eq!(
        fs::read(&fixture.stream).unwrap(),
        fixture.bytes,
        "readers must not rewrite canonical history"
    );
}

#[test]
fn daemon_restart_preserves_query_progress_and_rejects_forged_or_corrupt_cursors() {
    let mut records = records();
    for index in 1..4 {
        let mut source = records[4].clone();
        source["source_seq"] = json!(index + 1);
        source["request_id"] = json!(format!("source:audit:{}", index + 1));
        records.insert(4 + index, source);
    }
    let mut fixture = Fixture::new(records);
    let first = fixture.query(&["--limit", "1"]);
    let cursor = first["next_cursor"].as_str().unwrap().to_owned();
    fixture.restart();
    let second = fixture.query(&["--limit", "1", "--cursor", &cursor]);
    assert_eq!(second["snapshot"], first["snapshot"]);
    assert_eq!(second["records"], json!([fixture.records[5].clone()]));
    fixture.restart();
    assert_eq!(
        fixture.query(&["--limit", "1", "--cursor", &cursor]),
        second
    );
    let next = second["next_cursor"].as_str().unwrap();
    let third = fixture.query(&["--limit", "1", "--cursor", next]);
    assert_eq!(third["records"], json!([fixture.records[6].clone()]));

    let mut forged = cursor.clone();
    forged.pop();
    forged.push(if cursor.ends_with('a') { 'b' } else { 'a' });
    let forged_output = fixture.run(&[
        "query", "--run", RUN, "--execs", "--limit", "1", "--cursor", &forged, "--json",
    ]);
    assert!(!forged_output.status.success());
    assert!(forged_output.stdout.is_empty());

    let checkpoint = fixture.checkpoint(next);
    let mut corrupt: Value = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
    corrupt["checkpoint"]["current"] = json!("0".repeat(32));
    fs::write(&checkpoint, serde_json::to_vec(&corrupt).unwrap()).unwrap();
    fixture.restart();
    let corrupt_output = fixture.run(&[
        "query", "--run", RUN, "--execs", "--limit", "1", "--cursor", next, "--json",
    ]);
    assert!(!corrupt_output.status.success());
    assert!(corrupt_output.stdout.is_empty());
    assert_eq!(fs::read(&fixture.stream).unwrap(), fixture.bytes);
}

#[test]
fn dropped_socket_reply_replays_the_checkpointed_page_after_restart() {
    use ouro_ledger::{
        daemon::write_frame,
        protocol::{ReadFilter, ReadRequest, ReadSelector, Request},
    };
    let mut records = records();
    let mut source = records[4].clone();
    source["source_seq"] = json!(2);
    source["request_id"] = json!("source:audit:2");
    records.insert(5, source);
    let mut fixture = Fixture::new(records);
    let first = fixture.query(&["--limit", "1"]);
    let cursor = first["next_cursor"].as_str().unwrap().to_owned();
    let mut socket = UnixStream::connect(fixture.data.join("ledger/serve.sock")).unwrap();
    write_frame(
        &mut socket,
        &Request::Read {
            request: ReadRequest {
                run_id: RUN.into(),
                filter: ReadFilter {
                    selector: ReadSelector::Execs,
                    stage: None,
                    since: None,
                    until: None,
                },
                cursor: Some(cursor.clone()),
                limit: 1,
            },
        },
    )
    .unwrap();
    // Keep the socket open but unread until the durable checkpoint proves the
    // daemon accepted the request. Closing before accept races peer attribution.
    let checkpoint = fixture.checkpoint(&cursor);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let durable: Value = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
        if durable["checkpoint"]["prior"]["token"] == cursor[32..] {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "lost reply checkpoint was not persisted"
        );
        thread::sleep(Duration::from_millis(10));
    }
    // Drop the reply without receiving any page, then recover the accepted advance.
    drop(socket);
    fixture.restart();
    let second = fixture.query(&["--limit", "1", "--cursor", &cursor]);
    assert_eq!(second["snapshot"], first["snapshot"]);
    assert_eq!(second["records"], json!([fixture.records[5].clone()]));
    assert_eq!(
        fixture.query(&["--limit", "1", "--cursor", &cursor]),
        second
    );
    assert_eq!(fs::read(&fixture.stream).unwrap(), fixture.bytes);
}

#[test]
fn daemon_restart_refuses_public_symlinked_and_hardlinked_checkpoint_files() {
    for unsafe_kind in ["public", "symlink", "hardlink"] {
        let mut fixture = Fixture::new(records());
        let first = fixture.query(&["--limit", "1"]);
        let cursor = first["next_cursor"].as_str().unwrap();
        let checkpoint = fixture.checkpoint(cursor);
        drop(fixture.writer.take());
        match unsafe_kind {
            "public" => {
                fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "symlink" => {
                let original = fixture.temp.path().join("original-checkpoint");
                fs::rename(&checkpoint, &original).unwrap();
                std::os::unix::fs::symlink(original, &checkpoint).unwrap();
            }
            "hardlink" => {
                fs::hard_link(&checkpoint, fixture.temp.path().join("linked-checkpoint")).unwrap()
            }
            _ => unreachable!(),
        }
        fixture.start_writer();
        let output = fixture.run(&[
            "query", "--run", RUN, "--execs", "--limit", "1", "--cursor", cursor, "--json",
        ]);
        assert!(
            !output.status.success(),
            "accepted {unsafe_kind} checkpoint"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read(&fixture.stream).unwrap(), fixture.bytes);
    }
}

#[test]
fn durable_session_capacity_and_expiry_survive_daemon_restart() {
    let mut fixture = Fixture::new(records());
    let mut cursors = Vec::new();
    for _ in 0..32 {
        cursors.push(
            fixture.query(&["--limit", "1"])["next_cursor"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    fixture.restart();
    let full = fixture.run(&["query", "--run", RUN, "--execs", "--limit", "1", "--json"]);
    assert!(!full.status.success());
    assert!(full.stdout.is_empty());
    assert!(String::from_utf8_lossy(&full.stderr).contains("session limit"));
    let checkpoint = fixture.checkpoint(&cursors[0]);
    let mut expired: Value = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
    expired["checkpoint"]["created"] = json!(0);
    expired["digest"] = json!(sha256_prefixed(&to_jcs(&expired["checkpoint"]).unwrap()));
    fs::write(&checkpoint, serde_json::to_vec(&expired).unwrap()).unwrap();
    fixture.restart();
    let expired_cursor = fixture.run(&[
        "query",
        "--run",
        RUN,
        "--execs",
        "--limit",
        "1",
        "--cursor",
        &cursors[0],
        "--json",
    ]);
    assert!(!expired_cursor.status.success());
    assert!(expired_cursor.stdout.is_empty());
    assert!(!checkpoint.exists());
    assert_eq!(
        fixture.query(&["--limit", "1"])["records"],
        json!([fixture.records[4].clone()])
    );
    assert_eq!(
        fs::read_dir(fixture.data.join("ledger/readers"))
            .unwrap()
            .count(),
        32
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
    drop(fixture.writer.take());
    fixture.start_writer();
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

const OTHER_RUN: &str = "run_22222222222222222222222222222222";

#[test]
fn cross_run_pages_keep_attribution_and_resume_independently_after_restart() {
    let mut fixture = Fixture::new(records());
    fixture.add_run(OTHER_RUN, fixture.records.clone());
    let args = [
        "query", "--run", RUN, "--run", OTHER_RUN, "--execs", "--limit", "1", "--json",
    ];
    let first = fixture.run(&args);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first["snapshot_scope"], "independent_per_run");
    for (i, run) in [RUN, OTHER_RUN].iter().enumerate() {
        assert_eq!(first["pages"][i]["run_id"], *run);
        assert_eq!(first["pages"][i]["records"][0]["run_id"], *run);
        assert_eq!(
            first["pages"][i]["records"][0]["provenance"]["role"],
            "producer"
        );
        assert_eq!(first["pages"][i]["child_protection"], "enforced");
    }
    let a = format!(
        "{RUN}={}",
        first["pages"][0]["next_cursor"].as_str().unwrap()
    );
    let b = format!(
        "{OTHER_RUN}={}",
        first["pages"][1]["next_cursor"].as_str().unwrap()
    );
    fixture.restart();
    let mut resume = args.to_vec();
    resume.extend(["--resume", &a, "--resume", &b]);
    let second = fixture.run(&resume);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert!(
        second["pages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["done"] == true && p["records"] == json!([]))
    );
    let replay = fixture.run(&resume);
    assert_eq!(
        serde_json::from_slice::<Value>(&replay.stdout).unwrap(),
        second
    );
    let rebound = format!(
        "{RUN}={}",
        first["pages"][1]["next_cursor"].as_str().unwrap()
    );
    let rejected = fixture.run(&[
        "query", "--run", RUN, "--run", OTHER_RUN, "--execs", "--limit", "1", "--resume", &rebound,
        "--json",
    ]);
    assert!(!rejected.status.success());
    let rejected: Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(rejected["problems"][0]["run_id"], RUN);
    assert_eq!(rejected["pages"][0]["run_id"], OTHER_RUN);
}

#[test]
fn cross_run_rejects_duplicate_runs_and_malformed_continuations() {
    let mut fixture = Fixture::new(records());
    for extra in [
        vec!["--run", RUN],
        vec!["--resume", "bad"],
        vec!["--resume", "run_unknown=abc"],
    ] {
        let mut args = vec!["query", "--run", RUN, "--execs"];
        args.extend(extra);
        assert!(!fixture.run(&args).status.success());
    }
}

#[test]
fn diff_counts_preserve_provenance_and_paginate_without_claiming_entity_equivalence() {
    let mut fixture = Fixture::new(records());
    let mut altered = fixture.records.clone();
    altered[4]["outcome"]["errno"] = json!("EIO");
    altered[4]["outcome"]["return_value"] = json!(-5);
    fixture.add_run(OTHER_RUN, altered);
    let args = ["diff", RUN, OTHER_RUN, "--limit", "1", "--json"];
    let result = fixture.run(&args);
    assert!(
        result.status.success(),
        "{} {}",
        String::from_utf8_lossy(&result.stderr),
        String::from_utf8_lossy(&result.stdout)
    );
    let first: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(first["complete"], true);
    assert_eq!(first["total_changes"], 2);
    assert_eq!(first["classes"]["exec"]["status"], "comparable");
    assert_eq!(first["classes"]["proxy.net"]["status"], "incomparable");
    assert_eq!(first["classes"]["proxy.net"]["left_reason"], "unobserved");
    assert_eq!(first["left"]["child_protection"], "enforced");
    assert_eq!(first["changes"][0]["observation"]["stage"], "result");
    assert_eq!(first["changes"][0]["observation"]["source"], "audit");
    let after = first["next_after"].as_str().unwrap();
    fixture.restart();
    let mut args = args.to_vec();
    args.extend(["--after", after]);
    let result = fixture.run(&args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let second: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(second["next_after"], Value::Null);
    assert_eq!(second["changes"].as_array().unwrap().len(), 1);
    assert_ne!(first["changes"], second["changes"]);
    for page in [&first, &second] {
        let change = &page["changes"][0];
        let reference = if change["left_count"] == 1 {
            &change["left_first_record"]
        } else {
            &change["right_first_record"]
        };
        assert_eq!(reference["seq"], 5);
        assert_eq!(reference["provenance"]["role"], "producer");
    }
    assert!(
        !fixture
            .run(&["diff", OTHER_RUN, RUN, "--after", after, "--json"])
            .status
            .success()
    );
    let body = fixture.temp.path().join("operator-note.json");
    fs::write(&body, b"{}").unwrap();
    assert!(
        fixture
            .run(&[
                "append",
                "--run",
                RUN,
                "--request-id",
                "diff-head-change",
                "--kind",
                "note",
                "--body-file",
                body.to_str().unwrap(),
                "--json"
            ])
            .status
            .success()
    );
    let result = fixture.run(&args);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("snapshot changed"));
}

#[test]
fn diff_corrupt_or_missing_history_never_returns_a_successful_empty_comparison() {
    use std::io::Write as _;
    let mut fixture = Fixture::new(records());
    fixture.add_run(OTHER_RUN, fixture.records.clone());
    OpenOptions::new()
        .append(true)
        .open(&fixture.stream)
        .unwrap()
        .write_all(b"unexpected\n")
        .unwrap();
    let result = fixture.run(&["diff", RUN, OTHER_RUN, "--json"]);
    assert!(!result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["complete"], false);
    assert_eq!(report["changes"], json!([]));
    assert_eq!(
        report["classes"]["exec"]["left_reason"],
        "incomplete_evidence"
    );
    assert_eq!(report["right"]["complete"], true);
    let result = fixture.run(&[
        "diff",
        "run_33333333333333333333333333333333",
        OTHER_RUN,
        "--json",
    ]);
    assert!(!result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["left"]["child_protection"], "unknown");
    assert!(report["left"]["problem"].is_string());
}
