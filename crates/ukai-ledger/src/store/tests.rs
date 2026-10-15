use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::{
        fd::AsRawFd as _,
        unix::fs::{MetadataExt as _, PermissionsExt as _},
    },
    path::Path,
    time::SystemTime,
};

use serde_json::json;
use ukai_records::records;

use super::*;
use crate::{
    faults::{self, Plan, Point, Replaced, Scope, Step},
    fsx,
    manifest::{self, STREAM},
    protocol::{
        AppendReceipt, MAX_FRAME_BYTES, MAX_VERIFY_LIMIT, ReadPage, ReadRequest, RunRecord,
    },
    store::{stream::PoisonKind, writer::private_file},
};

mod pending;
mod reader;
mod redaction;
mod retention;
mod rotation;
mod rules;
mod writer;

/// The call failed with the refusal named by `expected`, not with some
/// unrelated error that merely makes it fail.
#[track_caller]
pub(super) fn assert_refused<T>(result: Result<T>, expected: &str) {
    match result {
        Ok(_) => panic!("expected a refusal containing {expected:?}, but the call succeeded"),
        Err(error) => assert!(
            error.message().contains(expected),
            "expected a refusal containing {expected:?}, got {:?}",
            error.message()
        ),
    }
}

pub(super) use crate::test_support::{TOKEN, peer, request as payload};

fn prepared(run: &RunRecord) -> Value {
    let mut receipt = crate::test_support::prepared_receipt();
    receipt["attempt_id"] = json!(run.attempt_id);
    receipt
}

pub(super) fn create() -> (tempfile::TempDir, Store, RunRecord) {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let run = store.prepare("test-prepare", &payload(), &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    (temp, store, run)
}

pub(super) fn note(
    store: &mut Store,
    run: &RunRecord,
    key: &str,
    body: Value,
) -> Result<AppendReceipt> {
    store.append_owner(&run.run_id, key, "note", None, &body, &peer(), TOKEN)
}

pub(super) fn gc_fixture() -> (tempfile::TempDir, Store, RunRecord) {
    gc_fixture_captures(&[("stdout", b"private-capture")])
}

pub(super) fn gc_fixture_captures(
    captures: &[(&str, &[u8])],
) -> (tempfile::TempDir, Store, RunRecord) {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let mut plan = payload();
    plan["profile"] = json!("none");
    plan["capture"]["streams"] = json!(captures.iter().map(|(name, _)| *name).collect::<Vec<_>>());
    let run = store.prepare("gc-prepare", &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    store.set_segment_limit(1);
    source_fixture(&mut store, &run, "exec", 1, None);
    store
        .append_owner(
            &run.run_id,
            "gc-note",
            "note",
            Some("effect-1"),
            &json!({"note":"private-note-body"}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let mut metadata = json!({"stdout":{"state":"not_captured"},"stderr":{"state":"not_captured"}});
    for (name, contents) in captures {
        let path = format!("artifacts/{name}.bin");
        let mut file = private_file(
            &store.root().join(&run.run_id).join(&path),
            OpenOptions::new().create(true),
        )
        .unwrap();
        file.write_all(contents).unwrap();
        file.sync_all().unwrap();
        metadata[name] = json!({"state":"captured","stored_bytes":contents.len(),"path":path});
    }
    store
        .append_owner(
            &run.run_id,
            "gc-denial",
            "denied",
            None,
            &json!({"outcome":{"kind":"refused"},"capture":metadata}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    (temp, store, run)
}

pub(super) fn gc_future() -> SystemTime {
    SystemTime::now() + std::time::Duration::from_secs(2 * 86_400)
}

fn capture_policy() -> ukai_records::retention::RetentionPolicy {
    ukai_records::retention::RetentionPolicy {
        retain_days: 90,
        capture_retain_days: 1,
    }
}

fn read_request(run: &RunRecord, selector: crate::protocol::ReadSelector) -> ReadRequest {
    ReadRequest {
        run_id: run.run_id.clone(),
        filter: crate::protocol::ReadFilter {
            selector,
            stage: None,
            since: None,
            until: None,
        },
        cursor: None,
        limit: 100,
    }
}

fn read_all(store: &mut Store, mut request: ReadRequest) -> (Vec<ReadPage>, String) {
    let mut pages = vec![];
    let mut bytes = String::new();
    for _ in 0..1000 {
        let page = store.read(&request).unwrap();
        bytes.push_str(&page.ndjson);
        request.cursor = page.next_cursor.clone();
        let done = page.done;
        pages.push(page);
        if done {
            return (pages, bytes);
        }
    }
    panic!("reader did not finish its bounded snapshot");
}

fn source_fixture(store: &mut Store, run: &RunRecord, fixture: &str, seq: u64, path: Option<&str>) {
    let fixtures = [
        (
            "exec",
            include_str!("../../../../docs/specs/jail-v1/examples/event-exec.json"),
        ),
        (
            "exit",
            include_str!("../../../../docs/specs/jail-v1/examples/event-exit.json"),
        ),
        (
            "path",
            include_str!("../../../../docs/specs/jail-v1/examples/event-open.json"),
        ),
        (
            "deny",
            include_str!("../../../../docs/specs/jail-v1/examples/event-deny.json"),
        ),
        (
            "host",
            include_str!("../../../../docs/specs/jail-v1/examples/event-connect.json"),
        ),
        (
            "proxy",
            include_str!("../../../../docs/specs/jail-v1/examples/event-proxy-deny.json"),
        ),
    ];
    let mut event: Value = serde_json::from_str(
        fixtures
            .iter()
            .find(|(name, _)| *name == fixture)
            .unwrap()
            .1,
    )
    .unwrap();
    event["attempt_id"] = json!(run.attempt_id);
    event["source_seq"] = json!(seq);
    if let Some(path) = path {
        event["fields"]["path"]["value"] = json!(path);
    }
    store
        .append_source(&run.run_id, &event, &peer(), TOKEN)
        .unwrap();
}

/// Rewrite the canonical records and drop the segment manifest, so only the
/// edited records' own rules can refuse them on the next start.
fn rewrite_without_manifest(store: &Store, run: &RunRecord, edit: impl FnOnce(&mut Vec<Value>)) {
    let directory = store.root().join(&run.run_id);
    let mut records: Vec<Value> = fs::read(directory.join(STREAM))
        .unwrap()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    edit(&mut records);
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend(canonical(&record).unwrap());
        bytes.push(b'\n');
    }
    fs::write(directory.join(STREAM), bytes).unwrap();
    fs::remove_file(directory.join(manifest::NAME)).unwrap();
}

fn segment_bytes(directory: &Path) -> Vec<u8> {
    manifest::names(directory)
        .unwrap()
        .iter()
        .flat_map(|name| fs::read(directory.join(name)).unwrap())
        .collect()
}
