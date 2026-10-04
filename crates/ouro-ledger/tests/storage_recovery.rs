//! Restart and disk-damage boundaries using the public store over private fixtures.
#![cfg(unix)]

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use ouro_ledger::{
    protocol::{AppendReceipt, Peer, ReadFilter, ReadRequest, ReadSelector, RunRecord},
    store::Store,
};
use ouro_records::canonical::{sha256_prefixed, to_jcs};
use serde_json::{Value, json};

const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn peer() -> Peer {
    Peer {
        uid: unsafe { libc::geteuid() },
        pid: std::process::id(),
        birth: "storage-recovery-fixture".into(),
        boot_id: "storage-recovery-boot".into(),
    }
}

fn payload() -> Value {
    let receipt: Value = serde_json::from_str(include_str!(
        "../../../docs/specs/jail-v1/examples/receipt-prepared.json"
    ))
    .unwrap();
    json!({
        "schema": "ouro.ledger.request/1",
        "profile": "tool",
        "argv_digest": receipt["argv_digest"],
        "policy_digest": receipt["policy"]["digest"],
        "requirements": receipt["policy"]["requirements"],
        "jail_image_digest": receipt["argv_digest"],
        "io": {"mode": "batch", "pty": false},
        "capture": {"streams": [], "limit_bytes": 1_048_576},
        "evidence": "strict"
    })
}

struct Fixture {
    _temp: tempfile::TempDir,
    data: PathBuf,
    run: RunRecord,
}

impl Fixture {
    fn new() -> (Self, Store) {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut store = Store::open(&data).unwrap();
        let run = store
            .prepare("prepare-recovery", &payload(), &peer())
            .unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        (
            Self {
                _temp: temp,
                data,
                run,
            },
            store,
        )
    }

    fn directory(&self) -> PathBuf {
        self.data.join("ledger").join(&self.run.run_id)
    }

    fn stream(&self) -> PathBuf {
        self.directory().join("events-0001.ndjson")
    }

    fn manifest(&self) -> PathBuf {
        self.directory().join("segments.json")
    }

    fn append(&self, store: &mut Store, key: &str, effect: Option<&str>) -> AppendReceipt {
        store
            .append_owner(
                &self.run.run_id,
                key,
                "note",
                effect,
                &json!({"purpose": key}),
                &peer(),
                TOKEN,
            )
            .unwrap()
    }

    fn append_large(&self, store: &mut Store, key: &str) {
        store
            .append_owner(
                &self.run.run_id,
                key,
                "note",
                None,
                &json!({"purpose": key, "padding": "x".repeat(100_000)}),
                &peer(),
                TOKEN,
            )
            .unwrap();
    }

    fn read_request(&self) -> ReadRequest {
        ReadRequest {
            run_id: self.run.run_id.clone(),
            filter: ReadFilter {
                selector: ReadSelector::All,
                stage: None,
                since: None,
                until: None,
            },
            cursor: None,
            limit: 1,
        }
    }
}

fn synced_replace(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn disposable_projections_rebuild_without_rebinding_owner_requests_or_effects() {
    for projection_damage in [
        None,
        Some(b"invalid SQLite and projection bytes".as_slice()),
    ] {
        let (fixture, mut store) = Fixture::new();
        let receipt = fixture.append(&mut store, "immutable-note", Some("immutable-effect"));
        let expected = store.show(&fixture.run.run_id).unwrap();
        let canonical = fs::read(fixture.stream()).unwrap();
        let manifest = fs::read(fixture.manifest()).unwrap();
        drop(store);

        for projection in [
            fixture.directory().join("run.json"),
            fixture.data.join("ledger/index.sqlite"),
        ] {
            match projection_damage {
                Some(bytes) => synced_replace(&projection, bytes),
                None => fs::remove_file(&projection).unwrap(),
            }
        }

        let mut recovered = Store::open(&fixture.data).unwrap();
        let replay = recovered
            .prepare("prepare-recovery", &payload(), &peer())
            .unwrap();
        assert_eq!(replay.run_id, fixture.run.run_id);
        assert_eq!(replay.attempt_id, fixture.run.attempt_id);
        assert_eq!(replay.chain, expected.chain);
        assert_eq!(replay.owner, Some(peer()));
        assert_eq!(
            fixture.append(&mut recovered, "immutable-note", Some("immutable-effect")),
            receipt
        );
        assert!(
            recovered
                .append_owner(
                    &fixture.run.run_id,
                    "new-request",
                    "note",
                    Some("immutable-effect"),
                    &json!({"purpose": "changed"}),
                    &peer(),
                    TOKEN,
                )
                .is_err()
        );
        let mut other_owner = peer();
        other_owner.birth = "replacement-owner".into();
        assert!(
            recovered
                .claim_owner(&fixture.run.run_id, &other_owner)
                .is_err()
        );
        assert_eq!(fs::read(fixture.stream()).unwrap(), canonical);
        assert_eq!(fs::read(fixture.manifest()).unwrap(), manifest);
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }
}

#[test]
fn complete_unacknowledged_tail_promotes_manifest_and_replays_original_receipt() {
    let (fixture, mut store) = Fixture::new();
    let committed_manifest = fs::read(fixture.manifest()).unwrap();
    let receipt = fixture.append(&mut store, "lost-acknowledgement", None);
    let complete_bytes = fs::read(fixture.stream()).unwrap();
    let promoted_manifest = fs::read(fixture.manifest()).unwrap();
    assert_ne!(committed_manifest, promoted_manifest);
    drop(store);

    synced_replace(&fixture.manifest(), &committed_manifest);
    let mut recovered = Store::open(&fixture.data).unwrap();
    assert_eq!(
        fixture.append(&mut recovered, "lost-acknowledgement", None),
        receipt
    );
    assert_eq!(fs::read(fixture.stream()).unwrap(), complete_bytes);
    assert_eq!(fs::read(fixture.manifest()).unwrap(), promoted_manifest);
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn valid_prefix_truncation_below_manifest_refuses_replay_and_new_preparations() {
    let (fixture, mut store) = Fixture::new();
    let prefix = fs::read(fixture.stream()).unwrap();
    fixture.append(&mut store, "durable-note", None);
    let manifest = fs::read(fixture.manifest()).unwrap();
    drop(store);

    synced_replace(&fixture.stream(), &prefix);
    let mut recovered = Store::open(&fixture.data).unwrap();
    assert_eq!(
        recovered.show(&fixture.run.run_id).unwrap().state,
        "outcome_unknown"
    );
    assert!(!recovered.verify(None).unwrap()[0].local_consistency);
    assert!(
        recovered
            .prepare("fresh-attempt", &payload(), &peer())
            .is_err()
    );
    assert!(
        recovered
            .append_owner(
                &fixture.run.run_id,
                "durable-note",
                "note",
                None,
                &json!({"purpose": "durable-note"}),
                &peer(),
                TOKEN,
            )
            .is_err()
    );
    assert_eq!(fs::read(fixture.stream()).unwrap(), prefix);
    assert_eq!(fs::read(fixture.manifest()).unwrap(), manifest);
}

#[test]
fn incomplete_tail_is_retained_and_does_not_rewrite_committed_manifest() {
    let (fixture, mut store) = Fixture::new();
    fixture.append(&mut store, "durable-note", None);
    let manifest = fs::read(fixture.manifest()).unwrap();
    drop(store);
    let mut file = OpenOptions::new()
        .append(true)
        .open(fixture.stream())
        .unwrap();
    file.write_all(b"{\"interrupted\":").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let interrupted = fs::read(fixture.stream()).unwrap();

    let mut recovered = Store::open(&fixture.data).unwrap();
    assert!(!recovered.verify(None).unwrap()[0].local_consistency);
    assert_eq!(
        recovered.show(&fixture.run.run_id).unwrap().state,
        "outcome_unknown"
    );
    assert!(
        recovered
            .prepare("fresh-attempt", &payload(), &peer())
            .is_err()
    );
    assert_eq!(fs::read(fixture.stream()).unwrap(), interrupted);
    assert_eq!(fs::read(fixture.manifest()).unwrap(), manifest);
}

#[test]
fn recomputing_a_valid_local_chain_cannot_override_durable_manifest_history() {
    let (fixture, mut store) = Fixture::new();
    fixture.append(&mut store, "immutable-note", None);
    drop(store);
    let original = fs::read_to_string(fixture.stream()).unwrap();
    let mut records: Vec<Value> = original
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    records.last_mut().unwrap()["body"]["purpose"] = json!("rewritten-history");
    let mut previous = None;
    let mut altered = Vec::new();
    for record in &mut records {
        record["prev"] = json!(previous);
        let encoded = to_jcs(record).unwrap();
        previous = Some(sha256_prefixed(&encoded));
        altered.extend(encoded);
        altered.push(b'\n');
    }
    synced_replace(&fixture.stream(), &altered);

    let mut recovered = Store::open(&fixture.data).unwrap();
    assert!(!recovered.verify(None).unwrap()[0].local_consistency);
    assert_eq!(
        recovered.show(&fixture.run.run_id).unwrap().state,
        "outcome_unknown"
    );
    assert!(
        recovered
            .prepare("fresh-attempt", &payload(), &peer())
            .is_err()
    );
    assert_eq!(fs::read(fixture.stream()).unwrap(), altered);
}

#[test]
fn legacy_stream_without_manifest_migrates_without_duplicating_history() {
    let (fixture, mut store) = Fixture::new();
    let receipt = fixture.append(&mut store, "legacy-note", Some("legacy-effect"));
    let original = fs::read(fixture.stream()).unwrap();
    drop(store);
    fs::remove_file(fixture.manifest()).unwrap();

    let mut recovered = Store::open(&fixture.data).unwrap();
    assert!(fixture.manifest().is_file());
    assert_eq!(
        fixture.append(&mut recovered, "legacy-note", Some("legacy-effect")),
        receipt
    );
    assert_eq!(fs::read(fixture.stream()).unwrap(), original);
    assert_eq!(
        fs::metadata(fixture.manifest())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn durable_cursor_retry_keeps_original_page_and_snapshot_after_restart_and_append() {
    let (fixture, mut store) = Fixture::new();
    fixture.append_large(&mut store, "snapshot-note-one");
    fixture.append_large(&mut store, "snapshot-note-two");
    let original = fs::read_to_string(fixture.stream()).unwrap();
    let mut request = fixture.read_request();
    let first = store.read(&request).unwrap();
    request.cursor = first.next_cursor.clone();
    assert!(request.cursor.is_some());
    let second = store.read(&request).unwrap();
    drop(store);

    let mut recovered = Store::open(&fixture.data).unwrap();
    fixture.append(&mut recovered, "after-snapshot", None);
    assert_eq!(recovered.read(&request).unwrap(), second);
    assert_eq!(recovered.read(&request).unwrap(), second);
    let mut exported = first.ndjson.clone();
    exported.push_str(&second.ndjson);
    request.cursor = second.next_cursor.clone();
    assert!(request.cursor.is_some());
    let mut done = false;
    for _ in 0..10 {
        let page = recovered.read(&request).unwrap();
        assert_eq!(page.snapshot, first.snapshot);
        exported.push_str(&page.ndjson);
        if page.done {
            done = true;
            break;
        }
        request.cursor = page.next_cursor;
    }
    assert!(done);
    assert_eq!(exported, original);
    assert!(recovered.show(&fixture.run.run_id).unwrap().chain.head_seq > first.snapshot.head_seq);
}

#[test]
fn durable_cursor_refuses_changed_checkpoint_and_replaced_canonical_inode() {
    for replace_canonical in [false, true] {
        let (fixture, mut store) = Fixture::new();
        fixture.append_large(&mut store, "snapshot-note");
        let mut request = fixture.read_request();
        let first = store.read(&request).unwrap();
        request.cursor = first.next_cursor;
        let cursor = request.cursor.as_ref().unwrap();
        let session_id = &cursor[..32];
        let checkpoint = fixture
            .data
            .join("ledger/readers")
            .join(format!("{session_id}.json"));
        drop(store);

        if replace_canonical {
            let original = fs::read(fixture.stream()).unwrap();
            let replacement = fixture.directory().join("replacement.ndjson");
            fs::write(&replacement, original).unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(&replacement, fixture.stream()).unwrap();
        } else {
            let mut envelope: Value =
                serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
            envelope["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
            synced_replace(&checkpoint, &to_jcs(&envelope).unwrap());
        }

        let mut recovered = Store::open(&fixture.data).unwrap();
        assert!(recovered.read(&request).is_err());
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }
}

#[test]
fn poisoned_durable_snapshot_cannot_resume_with_clean_consistency_labels() {
    let (fixture, mut store) = Fixture::new();
    fixture.append_large(&mut store, "snapshot-note-one");
    fixture.append_large(&mut store, "snapshot-note-two");
    let mut request = fixture.read_request();
    let first = store.read(&request).unwrap();
    request.cursor = first.next_cursor;
    assert!(request.cursor.is_some());
    let prior_cursor = request.cursor.clone();
    let second = store.read(&request).unwrap();
    let current_cursor = second.next_cursor;
    assert!(current_cursor.is_some());
    drop(store);

    let mut manifest: Value =
        serde_json::from_slice(&fs::read(fixture.manifest()).unwrap()).unwrap();
    manifest["replay_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    let mut altered = to_jcs(&manifest).unwrap();
    altered.push(b'\n');
    synced_replace(&fixture.manifest(), &altered);

    let mut recovered = Store::open(&fixture.data).unwrap();
    assert!(!recovered.verify(None).unwrap()[0].local_consistency);
    assert_eq!(
        recovered.show(&fixture.run.run_id).unwrap().state,
        "outcome_unknown"
    );
    for cursor in [prior_cursor, current_cursor] {
        request.cursor = cursor;
        if let Ok(page) = recovered.read(&request) {
            assert!(!page.local_consistency);
        }
    }
}
