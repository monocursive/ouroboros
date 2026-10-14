use super::*;
use crate::faults::{Plan, Point, Replaced, Scope, Step};
use std::os::unix::fs::PermissionsExt as _;
mod redaction;

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

#[test]
fn detached_request_lifetime_is_validated_and_cannot_rebind_a_request() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = Store::open(temp.path()).unwrap();
    let mut plan = payload();
    plan["owner_lifetime"] = "systemd_user_service".into();
    let run = store.prepare("detached", &plan, &peer()).unwrap();
    assert_refused(
        store.prepare("detached", &payload(), &peer()),
        "request id already maps to a different prepare payload",
    );
    drop(store);
    let mut store = Store::open(temp.path()).unwrap();
    assert_eq!(
        store.prepare("detached", &plan, &peer()).unwrap().run_id,
        run.run_id
    );
    plan["io"]["mode"] = "foreground".into();
    assert_refused(
        store.prepare("foreground", &plan, &peer()),
        "prepare only accepts the versioned digest-only request plan",
    );
    plan["io"]["mode"] = "batch".into();
    plan["owner_lifetime"] = "unchecked_double_fork".into();
    assert_refused(
        store.prepare("unproved", &plan, &peer()),
        "prepare only accepts the versioned digest-only request plan",
    );
}
fn prepared(run: &RunRecord) -> Value {
    let mut receipt = crate::test_support::prepared_receipt();
    receipt["attempt_id"] = json!(run.attempt_id);
    receipt
}

#[test]
fn pending_recovery_keeps_the_journal_through_canonical_persistence_failures() {
    use crate::pending::Journal;
    for fault in [
        Point::EventBeforeWrite,
        Point::EventPartialWrite,
        Point::EventBeforeSync,
        Point::Replace(Replaced::Projection, Step::BeforeWrite),
        Point::Replace(Replaced::Manifest, Step::BeforeWrite),
        Point::AppendBeforeDirectorySync,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut store = Store::open(&data).unwrap();
        let mut plan = payload();
        plan["evidence"] = "best-effort".into();
        let run = store.prepare("pending-fault", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        store
            .append_owner(
                &run.run_id,
                "admission",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                TOKEN,
            )
            .unwrap();
        let run = store.show(&run.run_id).unwrap();
        let dir = store.root().join(&run.run_id);
        let journal = Journal::open(&dir).unwrap();
        journal.create(&run, &peer()).unwrap();
        let mut pending = journal.read(&run).unwrap();
        pending
            .push(
                serde_json::to_value(records::Event::lifecycle_note(
                    &run.attempt_id,
                    1,
                    SystemTime::now(),
                    1,
                    "pending_test",
                ))
                .unwrap(),
            )
            .unwrap();
        journal.save(&pending).unwrap();
        let before = fs::read(dir.join("owner-pending.json")).unwrap();
        drop(journal);
        faults::arm(Plan::fail(fault));
        assert!(
            store
                .reconcile_pending(&run.run_id, &peer(), &|_| true)
                .is_err()
        );
        faults::disarm();
        assert_eq!(fs::read(dir.join("owner-pending.json")).unwrap(), before);
        drop(store);
        let mut store = Store::open(&data).unwrap();
        let result = store.reconcile_pending(&run.run_id, &peer(), &|_| true);
        if matches!(fault, Point::EventPartialWrite) {
            assert_refused(
                result,
                "ambiguous canonical history refuses pending recovery",
            );
            assert!(!store.verify(None).unwrap()[0].local_consistency);
        } else {
            let recovered = result.unwrap();
            assert_eq!(recovered.chain.head_seq, run.chain.head_seq + 2);
            assert_eq!(
                store
                    .reconcile_pending(&run.run_id, &peer(), &|_| true)
                    .unwrap()
                    .chain,
                recovered.chain
            );
            assert!(store.verify(None).unwrap()[0].local_consistency);
        }
    }
}
#[test]
fn orphan_settlement_records_why_pending_evidence_was_refused() {
    use crate::pending::{Journal, STATE};
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let mut plan = payload();
    plan["evidence"] = "best-effort".into();
    let run = store.prepare("pending-refused", &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    store
        .append_owner(
            &run.run_id,
            "admission",
            "admitted",
            None,
            &json!({"receipt":prepared(&run)}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let run = store.show(&run.run_id).unwrap();
    let directory = store.root().join(&run.run_id);
    Journal::open(&directory)
        .unwrap()
        .create(&run, &peer())
        .unwrap();
    // Decoding this journal fails with an error that quotes its value.
    fs::write(
        directory.join(STATE),
        b"{\"state\":\"journal-value-7f3a\",\"digest\":\"x\"}",
    )
    .unwrap();
    let refusal = store
        .reconcile_pending(&run.run_id, &peer(), &|_| false)
        .unwrap_err();
    assert!(
        refusal.message().contains("journal-value-7f3a"),
        "{refusal}"
    );
    let settled = store.settle_orphans(&peer(), |_| false).unwrap();
    assert_eq!(settled[0].state, "outcome_unknown");
    assert_eq!(
        settled[0].outcome.as_ref().unwrap()["unknown_reason"],
        "pending evidence could not be reconciled"
    );
    let stream = fs::read(directory.join(STREAM)).unwrap();
    let last: Value = serde_json::from_slice(
        stream[..stream.len() - 1]
            .rsplit(|b| *b == b'\n')
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(last["request_id"], "reconcile:pending-invalid");
    // History keeps the refusal's class, never its text.
    assert_eq!(
        last["body"],
        json!({"reason":"invalid_pending_evidence","refusal":"journal_unreadable",
            "outcome":{"kind":"unknown","unknown":true,
                "unknown_reason":"pending evidence could not be reconciled"},
            "coverage":{"status":"degraded","gaps":[{"reason":"invalid_pending_evidence"}]}})
    );
    assert!(!String::from_utf8_lossy(&stream).contains("journal-value-7f3a"));
}

#[cfg(target_os = "linux")]
#[test]
fn unreconcilable_pending_evidence_is_recorded_once_and_retried_only_after_a_change() {
    use crate::pending::{Journal, STATE};
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let mut plan = payload();
    plan["evidence"] = "best-effort".into();
    let run = store.prepare("pending-invalid", &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    store
        .append_owner(
            &run.run_id,
            "admission",
            "admitted",
            None,
            &json!({"receipt":prepared(&run)}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let run = store.show(&run.run_id).unwrap();
    let journal = store.root().join(&run.run_id).join(STATE);
    Journal::open(&store.root().join(&run.run_id))
        .unwrap()
        .create(&run, &peer())
        .unwrap();
    fs::write(&journal, b"{\"damaged\":true}").unwrap();
    // The fixture owner's birth identity is not this process's: it is dead.
    store.recover_pending_orphans(&peer());
    let recorded = store.show(&run.run_id).unwrap();
    assert_eq!(recorded.state, "outcome_unknown");
    assert_eq!(
        recorded.outcome.unwrap()["unknown_reason"],
        "pending evidence could not be reconciled"
    );
    assert!(journal.exists(), "the refused journal stays for inspection");
    // Reconciliation opens (and recreates) the journal's lock file, so its
    // absence shows an unchanged journal was not retried.
    let lock = store.root().join(&run.run_id).join("owner-pending.lock");
    fs::remove_file(&lock).unwrap();
    store.recover_pending_orphans(&peer());
    assert!(!lock.exists(), "an unchanged failed journal was retried");
    fs::write(&journal, b"{\"damaged\":\"again\"}").unwrap();
    store.recover_pending_orphans(&peer());
    assert!(lock.exists(), "a changed journal must be retried");
    assert_eq!(
        store.show(&run.run_id).unwrap().chain,
        recorded.chain,
        "a terminal run gains no second unknown outcome"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_reconciliation_the_journal_did_not_refuse_is_not_recorded_and_is_retried() {
    use crate::pending::Journal;
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let mut plan = payload();
    plan["evidence"] = "best-effort".into();
    let run = store.prepare("pending-busy", &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    store
        .append_owner(
            &run.run_id,
            "admission",
            "admitted",
            None,
            &json!({"receipt":prepared(&run)}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let run = store.show(&run.run_id).unwrap();
    let journal = Journal::open(&store.root().join(&run.run_id)).unwrap();
    journal.create(&run, &peer()).unwrap();
    // While another holder keeps the journal locked, nothing is decided.
    let now = std::time::Instant::now();
    store.recover_pending_orphans_at(&peer(), now);
    assert_eq!(store.show(&run.run_id).unwrap().state, "admitted");
    drop(journal);
    // Once its retry is due, the unchanged journal is tried again and
    // reconciled.
    store.recover_pending_orphans_at(&peer(), now + std::time::Duration::from_secs(3));
    let reconciled = store.show(&run.run_id).unwrap();
    assert_eq!(reconciled.state, "outcome_unknown");
    assert_eq!(
        reconciled.outcome.unwrap()["unknown_reason"],
        "pending owner has no durable local exit record"
    );
}

fn create() -> (tempfile::TempDir, Store, RunRecord) {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let run = store.prepare("test-prepare", &payload(), &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    (temp, store, run)
}

#[test]
fn retention_holds_replay_without_reapplying_an_old_intent_after_release() {
    let (temp, mut store, run) = create();
    store.set_segment_limit(1);
    let original = fs::read(store.root().join(&run.run_id).join(STREAM)).unwrap();
    let held = store.hold(&run.run_id, "hold-1", &peer()).unwrap();
    assert_eq!(store.show(&run.run_id).unwrap().holds, ["operator"]);
    assert_eq!(store.hold(&run.run_id, "hold-1", &peer()).unwrap(), held);
    assert_refused(
        store.release(&run.run_id, "hold-1", &peer()),
        "request id conflicts with its immutable payload",
    );
    let released = store.release(&run.run_id, "release-1", &peer()).unwrap();
    assert_eq!(released.seq, held.seq + 1);
    assert_eq!(store.hold(&run.run_id, "hold-1", &peer()).unwrap(), held);
    assert!(store.show(&run.run_id).unwrap().holds.is_empty());
    assert_refused(
        store.append_owner(
            &run.run_id,
            "forged",
            "hold",
            None,
            &json!({}),
            &peer(),
            TOKEN,
        ),
        "invalid owner intent",
    );
    let path = store.root().join(&run.run_id).join(manifest::name(2));
    let record: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(record["provenance"]["role"], "operator");
    assert!(record["provenance"]["token_id"].is_null());
    drop(store);
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(store.hold(&run.run_id, "hold-1", &peer()).unwrap(), held);
    assert_eq!(
        store.release(&run.run_id, "release-1", &peer()).unwrap(),
        released
    );
    assert!(store.show(&run.run_id).unwrap().holds.is_empty());
    store.hold(&run.run_id, "hold-2", &peer()).unwrap();
    assert_eq!(
        store.release(&run.run_id, "release-1", &peer()).unwrap(),
        released
    );
    assert_eq!(store.show(&run.run_id).unwrap().holds, ["operator"]);
    assert_eq!(
        fs::read(store.root().join(&run.run_id).join(STREAM)).unwrap(),
        original
    );
    assert!(store.verify(None).unwrap()[0].local_consistency);
    drop(store);
    assert_eq!(
        Store::open(&temp.path().join("data"))
            .unwrap()
            .show(&run.run_id)
            .unwrap()
            .holds,
        ["operator"]
    );
}

#[test]
fn retention_faults_preserve_history_and_recover_one_original_receipt() {
    for release in [false, true] {
        for fault in [
            Point::EventBeforeWrite,
            Point::RotationCreated,
            Point::RotationSynced,
            Point::EventPartialWrite,
            Point::EventBeforeSync,
            Point::Replace(Replaced::Projection, Step::BeforeWrite),
            Point::Replace(Replaced::Manifest, Step::BeforeWrite),
            Point::AppendBeforeDirectorySync,
        ] {
            let (temp, mut store, run) = create();
            if release {
                store.hold(&run.run_id, "first-hold", &peer()).unwrap();
            }
            store.set_segment_limit(1);
            let before = store.show(&run.run_id).unwrap().chain.head_seq;
            faults::arm(Plan::fail(fault));
            let apply = |store: &mut Store| {
                if release {
                    store.release(&run.run_id, "retry", &peer())
                } else {
                    store.hold(&run.run_id, "retry", &peer())
                }
            };
            assert!(apply(&mut store).is_err());
            faults::disarm();
            assert!(
                apply(&mut store).is_err(),
                "uncertain writes cannot acknowledge before restart"
            );
            let directory = store.root().join(&run.run_id);
            let history = manifest::names(&directory)
                .unwrap()
                .into_iter()
                .map(|name| {
                    let bytes = fs::read(directory.join(&name)).unwrap();
                    (name, bytes)
                })
                .collect::<Vec<_>>();
            drop(store);
            let mut store = Store::open(&temp.path().join("data")).unwrap();
            for (name, bytes) in &history {
                assert_eq!(&fs::read(directory.join(name)).unwrap(), bytes);
            }
            if matches!(fault, Point::EventPartialWrite) {
                assert_refused(
                    apply(&mut store),
                    "stream is poisoned; no dependent dispatch or sequence reuse",
                );
                assert!(!store.verify(None).unwrap()[0].local_consistency);
            } else {
                let receipt = apply(&mut store).unwrap();
                assert_eq!(receipt.seq, before + 1);
                assert_eq!(apply(&mut store).unwrap(), receipt);
                assert_eq!(store.show(&run.run_id).unwrap().holds.is_empty(), release);
                assert!(store.verify(None).unwrap()[0].local_consistency);
            }
        }
    }
}

#[test]
fn retention_preview_keeps_active_unknown_held_recent_and_damaged_runs() {
    use std::time::Duration;
    let (_temp, mut store, run) = create();
    store
        .append_owner(
            &run.run_id,
            "denial",
            "denied",
            None,
            &json!({"outcome":{"kind":"refused"}}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let now = SystemTime::now();
    let future = now + Duration::from_secs(90 * 86_400);
    let plan = store.gc_plan_at(90, None, 100, now).unwrap();
    assert!(
        plan.runs[0]
            .keep_reasons
            .iter()
            .any(|r| r == "retention_window")
    );
    assert!(
        store
            .gc_plan_at(90, None, 100, now - Duration::from_secs(10))
            .unwrap()
            .runs[0]
            .keep_reasons
            .iter()
            .any(|r| r == "clock_before_activity")
    );
    assert!(store.gc_plan_at(90, None, 100, future).unwrap().runs[0].candidate);
    store.hold(&run.run_id, "keep", &peer()).unwrap();
    assert!(
        store.gc_plan_at(90, None, 100, future).unwrap().runs[0]
            .keep_reasons
            .iter()
            .any(|r| r == "operator_hold")
    );
    store.release(&run.run_id, "unhold", &peer()).unwrap();
    let active = store.prepare("active", &payload(), &peer()).unwrap();
    let unknown = store.prepare("unknown", &payload(), &peer()).unwrap();
    store.claim_owner(&unknown.run_id, &peer()).unwrap();
    store
        .append_owner(
            &unknown.run_id,
            "unknown",
            "outcome_unknown",
            None,
            &json!({}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let plan = store.gc_plan_at(90, None, 100, future).unwrap();
    assert!(
        plan.runs
            .iter()
            .find(|r| r.run_id == active.run_id)
            .unwrap()
            .keep_reasons
            .iter()
            .any(|r| r == "active_run")
    );
    assert!(
        plan.runs
            .iter()
            .find(|r| r.run_id == unknown.run_id)
            .unwrap()
            .keep_reasons
            .iter()
            .any(|r| r == "outcome_unknown")
    );
    let first = store.gc_plan_at(90, None, 1, future).unwrap();
    let second = store
        .gc_plan_at(90, first.next_after.as_deref(), 100, future)
        .unwrap();
    assert_eq!(second.runs.len(), 2);
    assert!(second.runs.iter().all(|r| r.run_id > first.runs[0].run_id));
    assert!(second.next_after.is_none());
    assert_refused(
        store.gc_plan(0, None, 1),
        "retention requires 1..36500 days",
    );
    assert_refused(
        store.gc_plan(u32::MAX, None, 1),
        "retention requires 1..36500 days",
    );
    assert_refused(
        store.gc_plan(90, None, 101),
        "GC preview requires 1..36500 retention days and 1..100 runs per page",
    );
    assert_refused(store.gc_plan(90, Some("../escape"), 1), "invalid run id");
    assert!(serde_json::to_vec(&plan).unwrap().len() < MAX_FRAME_BYTES);
    let path = store.root().join(&run.run_id).join(STREAM);
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(b"partial").unwrap();
    let plan = store.gc_plan_at(90, None, 100, future).unwrap();
    assert!(
        plan.runs
            .iter()
            .find(|r| r.run_id == run.run_id)
            .unwrap()
            .keep_reasons
            .iter()
            .any(|r| r == "canonical_layout_changed")
    );
}

#[test]
fn retention_preview_pins_durable_readers_without_expiring_or_repairing_files() {
    use std::time::Duration;
    let (temp, mut store, run) = create();
    store
        .read(&read_request(&run, crate::protocol::ReadSelector::All))
        .unwrap();
    let directory = store.root().join("readers");
    let checkpoint = fs::read_dir(&directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let bytes = fs::read(&checkpoint).unwrap();
    drop(store);
    let store = Store::open(&temp.path().join("data")).unwrap();
    let now = SystemTime::now();
    let plan = store.gc_plan_at(90, None, 100, now).unwrap();
    assert!(
        plan.runs[0]
            .keep_reasons
            .iter()
            .any(|r| r == "reader_snapshot")
    );
    let later = store
        .gc_plan_at(90, None, 100, now + Duration::from_secs(601))
        .unwrap();
    assert!(
        !later.runs[0]
            .keep_reasons
            .iter()
            .any(|r| r == "reader_snapshot")
    );
    assert_eq!(fs::read(&checkpoint).unwrap(), bytes);
    fs::write(&checkpoint, b"corrupt").unwrap();
    assert!(
        store.gc_plan_at(90, None, 100, now).unwrap().runs[0]
            .keep_reasons
            .iter()
            .any(|r| r == "reader_checkpoint_unknown")
    );
    assert_eq!(fs::read(&checkpoint).unwrap(), b"corrupt");
    fs::remove_file(&checkpoint).unwrap();
    std::os::unix::fs::symlink("../writer.lock", &checkpoint).unwrap();
    assert!(
        store.gc_plan_at(90, None, 100, now).unwrap().runs[0]
            .keep_reasons
            .iter()
            .any(|r| r == "reader_checkpoint_unknown")
    );
}
fn note(store: &mut Store, run: &RunRecord, key: &str, body: Value) -> Result<AppendReceipt> {
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

fn capture_policy() -> ouro_records::retention::RetentionPolicy {
    ouro_records::retention::RetentionPolicy {
        retain_days: 90,
        capture_retain_days: 1,
    }
}

#[test]
fn capture_expiry_preserves_canonical_bytes_queries_replays_and_later_history_gc() {
    let (temp, mut store, run) = gc_fixture();
    let directory = store.root().join(&run.run_id);
    let snapshots: Vec<_> = manifest::names(&directory)
        .unwrap()
        .into_iter()
        .map(|n| (n.clone(), fs::read(directory.join(n)).unwrap()))
        .collect();
    let before = store.show(&run.run_id).unwrap();
    let plan = store
        .gc_plan_policy_at(capture_policy(), None, 100, gc_future())
        .unwrap();
    assert!(!plan.runs[0].candidate);
    assert!(plan.runs[0].captures_candidate);
    let result = store
        .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
        .unwrap();
    assert!(result.failed.is_empty(), "{:?}", result.failed);
    assert!(result.pruned.is_empty());
    assert_eq!(result.captures_pruned[0].removed_bytes, 15);
    assert!(!directory.join("artifacts/stdout.bin").exists());
    let after = store.show(&run.run_id).unwrap();
    assert_eq!(after.chain, before.chain);
    assert!(after.history.is_none());
    assert_eq!(after.capture_history.as_ref().unwrap().state, "pruned");
    assert_eq!(after.capture["stdout"]["pruned_bytes"], 15);
    assert_eq!(after.child_protection, "unprotected");
    assert!(store.verify(None).unwrap()[0].local_consistency);
    for (name, bytes) in &snapshots {
        assert_eq!(fs::read(directory.join(name)).unwrap(), *bytes);
    }
    let held = store
        .hold(&run.run_id, "after-capture-expiry", &peer())
        .unwrap();
    drop(store);
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(
        store
            .hold(&run.run_id, "after-capture-expiry", &peer())
            .unwrap(),
        held
    );
    assert_eq!(
        store.show(&run.run_id).unwrap().capture["stdout"]["state"],
        "pruned"
    );
    assert!(store.verify(None).unwrap()[0].local_consistency);
    store
        .release(&run.run_id, "release-after-expiry", &peer())
        .unwrap();
    let whole = store.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
    assert!(whole.failed.is_empty(), "{:?}", whole.failed);
    assert_eq!(whole.pruned.len(), 1);
    drop(store);
    let store = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(
        store.show(&run.run_id).unwrap().capture["stdout"]["pruned_bytes"],
        15
    );
    assert!(store.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn capture_expiry_recovers_each_deletion_boundary_and_never_removes_history() {
    for fault in [
        Point::GcIntentWrite,
        Point::GcIntentSync,
        Point::GcBeforeUnlink,
        Point::GcAfterUnlink,
        Point::GcDirectorySync,
        Point::GcCompletion,
        Point::GcCompletionSync,
        Point::GcProjection,
    ] {
        let (temp, mut store, run) =
            gc_fixture_captures(&[("stdout", b"private-capture"), ("stderr", b"second")]);
        let directory = store.root().join(&run.run_id);
        let names = manifest::names(&directory).unwrap();
        let original: Vec<_> = names
            .iter()
            .map(|n| fs::read(directory.join(n)).unwrap())
            .collect();
        faults::arm(Plan::fail(fault));
        let result = store
            .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
            .unwrap();
        faults::disarm();
        assert_eq!(result.failed.len(), 1);
        if matches!(
            fault,
            Point::GcIntentWrite | Point::GcIntentSync | Point::GcBeforeUnlink
        ) {
            assert_eq!(
                fs::read(directory.join("artifacts/stdout.bin")).unwrap(),
                b"private-capture"
            );
        }
        if matches!(fault, Point::GcIntentSync | Point::GcBeforeUnlink) {
            assert_refused(
                store.hold(&run.run_id, "during-expiry", &peer()),
                "capture pruning is incomplete; retry GC or restart before mutations",
            );
            let _ = store.verify(None); // A verifier cannot delete the pending capture.
            assert!(directory.join("artifacts/stdout.bin").exists());
        }
        drop(store);
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let retry = store
            .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
            .unwrap();
        assert!(retry.failed.is_empty(), "{:?}", retry.failed);
        assert!(!directory.join("artifacts/stdout.bin").exists());
        assert!(!directory.join("artifacts/stderr.bin").exists());
        assert!(store.verify(None).unwrap()[0].local_consistency);
        for (name, bytes) in names.iter().zip(original) {
            assert_eq!(fs::read(directory.join(name)).unwrap(), bytes);
        }
    }
}

#[test]
fn capture_expiry_refuses_changed_reappearing_or_unanchored_files() {
    for mode in [
        "changed",
        "symlink",
        "hardlink",
        "anchor",
        "reappeared",
        "canonical",
        "chain",
        "segment",
    ] {
        let (temp, mut store, run) = gc_fixture();
        let directory = store.root().join(&run.run_id);
        faults::arm(Plan::fail(Point::GcBeforeUnlink));
        assert_eq!(
            store
                .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
                .unwrap()
                .failed
                .len(),
            1
        );
        faults::disarm();
        let path = directory.join("artifacts/stdout.bin");
        match mode {
            "changed" => fs::write(&path, b"changed-capture").unwrap(),
            "symlink" => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink("../events-0001.ndjson", &path).unwrap();
            }
            "hardlink" => {
                fs::remove_file(&path).unwrap();
                fs::hard_link(directory.join(STREAM), &path).unwrap();
            }
            "anchor" => fs::write(directory.join("captures-gc.json"), b"corrupt").unwrap(),
            "chain" | "segment" => {
                let path = directory.join("captures-gc.json");
                let mut anchor: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                if mode == "chain" {
                    anchor["retained"]["chain"]["head_digest"] =
                        json!(format!("sha256:{}", "a".repeat(64)));
                } else {
                    anchor["retained"]["files"][0]["path"] = json!(STREAM);
                }
                anchor["digest"] = json!(digest(&anchor["retained"]).unwrap());
                let mut bytes = canonical(&anchor).unwrap();
                bytes.push(b'\n');
                fs::write(path, bytes).unwrap();
            }
            "canonical" => fs::write(directory.join(STREAM), b"corrupt\n").unwrap(),
            "reappeared" => {
                store
                    .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
                    .unwrap();
                private_file(&path, OpenOptions::new().create(true))
                    .unwrap()
                    .write_all(b"private-capture")
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(store);
        let opened = Store::open(&temp.path().join("data"));
        if matches!(mode, "canonical" | "hardlink") {
            assert!(!opened.unwrap().verify(None).unwrap()[0].local_consistency);
        } else {
            assert!(opened.is_err(), "{mode}");
        }
        assert!(fs::symlink_metadata(path).is_ok());
    }
}

#[test]
fn capture_expiry_removes_empty_selected_files_without_claiming_removed_bytes() {
    let (_temp, mut store, run) = gc_fixture_captures(&[("stdout", b"")]);
    let result = store
        .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
        .unwrap();
    assert!(result.failed.is_empty());
    assert_eq!(result.captures_pruned[0].removed_files, 1);
    assert_eq!(result.captures_pruned[0].removed_bytes, 0);
    assert!(
        !store
            .root()
            .join(&run.run_id)
            .join("artifacts/stdout.bin")
            .exists()
    );
    assert!(store.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn capture_expiry_keeps_holds_unknown_outcomes_active_runs_and_reader_pins() {
    for reason in [
        "operator_hold",
        "outcome_unknown",
        "active_run",
        "reader_snapshot",
    ] {
        let (_temp, mut store, run) = gc_fixture();
        match reason {
            "operator_hold" => {
                store.hold(&run.run_id, "keep-captures", &peer()).unwrap();
            }
            "outcome_unknown" => {
                store
                    .streams_mut()
                    .get_mut(&run.run_id)
                    .unwrap()
                    .run_mut()
                    .state = "outcome_unknown".into()
            }
            "active_run" => {
                store
                    .streams_mut()
                    .get_mut(&run.run_id)
                    .unwrap()
                    .run_mut()
                    .state = "admitted".into()
            }
            "reader_snapshot" => {
                let request = ReadRequest {
                    run_id: run.run_id.clone(),
                    filter: crate::protocol::ReadFilter {
                        selector: crate::protocol::ReadSelector::All,
                        stage: None,
                        since: None,
                        until: None,
                    },
                    limit: 1,
                    cursor: None,
                };
                store.read(&request).unwrap();
            }
            _ => unreachable!(),
        }
        // Reader expiry must not be simulated by moving the wall clock ahead.
        let plan = store
            .gc_plan_policy_at(
                capture_policy(),
                None,
                100,
                if reason == "reader_snapshot" {
                    SystemTime::now()
                } else {
                    gc_future()
                },
            )
            .unwrap();
        assert!(!plan.runs[0].captures_candidate);
        assert!(
            plan.runs[0]
                .captures_keep_reasons
                .iter()
                .any(|s| s == reason)
        );
        assert!(
            store
                .root()
                .join(&run.run_id)
                .join("artifacts/stdout.bin")
                .exists()
        );
    }
}

#[test]
fn gc_prunes_segments_and_captures_but_preserves_replays_effects_and_none_labels() {
    let (temp, mut store, run) = gc_fixture();
    let original = store.show(&run.run_id).unwrap();
    let replay = store.stream(&run.run_id).unwrap().replay().clone();
    let directory = store.root().join(&run.run_id);
    let manifest = fs::read(directory.join("segments.json")).unwrap();
    let result = store.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
    assert!(result.failed.is_empty(), "{:?}", result.failed);
    assert_eq!(result.pruned.len(), 1);
    assert!(result.pruned[0].removed_files >= 4);
    assert!(!directory.join(STREAM).exists());
    assert!(!directory.join("artifacts/stdout.bin").exists());
    assert_eq!(fs::read(directory.join("segments.json")).unwrap(), manifest);
    let anchor = fs::read_to_string(directory.join("gc.json")).unwrap();
    assert!(!anchor.contains("private-note-body") && !anchor.contains("private-capture"));
    let projected = store.show(&run.run_id).unwrap();
    assert_eq!(projected.chain, original.chain);
    assert_eq!(projected.state, "denied");
    assert_eq!(projected.child_protection, "unprotected");
    assert_eq!(projected.history.as_ref().unwrap().state, "pruned");
    assert_eq!(projected.capture["stdout"]["state"], "pruned");
    assert_eq!(projected.capture["stdout"]["stored_bytes"], 0);
    assert_eq!(projected.capture["stdout"]["pruned_bytes"], 15);
    assert!(
        store
            .read(&read_request(&run, crate::protocol::ReadSelector::All))
            .unwrap_err()
            .message()
            .contains("pruned")
    );
    assert_refused(
        store.hold(&run.run_id, "too-late", &peer()),
        "run history was pruned; new mutations are refused",
    );
    store.flush_index();
    drop(store);
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(
        recovered
            .prepare("gc-prepare", &run.payload, &peer())
            .unwrap()
            .run_id,
        run.run_id
    );
    let mut conflicting = run.payload.clone();
    conflicting["argv_digest"] = json!(format!("sha256:{}", "f".repeat(64)));
    assert_refused(
        recovered.prepare("gc-prepare", &conflicting, &peer()),
        "request id already maps to a different prepare payload",
    );
    recovered.claim_owner(&run.run_id, &peer()).unwrap();
    let note = recovered
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
    assert_eq!(note, replay["gc-note"].receipt);
    assert_refused(
        recovered.append_owner(
            &run.run_id,
            "new-key",
            "note",
            Some("effect-1"),
            &json!({"note":"private-note-body"}),
            &peer(),
            TOKEN,
        ),
        "run history was pruned; new mutations are refused",
    );
    assert_refused(
        recovered.append_owner(
            &run.run_id,
            "gc-note",
            "note",
            Some("effect-1"),
            &json!({"note":"changed"}),
            &peer(),
            TOKEN,
        ),
        "request id conflicts with its immutable payload",
    );
    source_fixture(&mut recovered, &run, "exec", 1, None);
    assert_eq!(recovered.stream(&run.run_id).unwrap().replay(), &replay);
    let verified = recovered.verify(Some(&run.run_id)).unwrap();
    assert!(verified[0].local_consistency, "{:?}", verified[0]);
    assert_eq!(verified[0].events, 0);
    assert_eq!(verified[0].history.as_ref().unwrap().state, "pruned");
    assert_eq!(verified[0].child_protection, "unprotected");
    let again = recovered.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
    assert_eq!(
        serde_json::to_value(&again.pruned).unwrap(),
        serde_json::to_value(&result.pruned).unwrap()
    );
    assert_eq!(
        fs::read_to_string(directory.join("gc.json")).unwrap(),
        anchor
    );
}

#[test]
fn gc_recovers_every_deletion_boundary_without_losing_replay_or_chain_anchors() {
    for fault in [
        Point::GcIntentWrite,
        Point::GcIntentSync,
        Point::GcBeforeUnlink,
        Point::GcAfterUnlink,
        Point::GcDirectorySync,
        Point::GcCompletion,
        Point::GcCompletionSync,
        Point::GcProjection,
    ] {
        let (temp, mut store, run) = gc_fixture();
        let replay = store.stream(&run.run_id).unwrap().replay().clone();
        let directory = store.root().join(&run.run_id);
        let manifest = fs::read(directory.join("segments.json")).unwrap();
        faults::arm(Plan::fail(fault));
        let failed = store.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
        faults::disarm();
        assert_eq!(failed.failed.len(), 1);
        assert!(failed.pruned.is_empty());
        if matches!(fault, Point::GcIntentWrite) {
            assert!(!directory.join("gc.json").exists());
            assert!(directory.join(STREAM).exists());
        } else {
            assert!(directory.join("gc.json").exists());
            assert_refused(
                store.read(&read_request(&run, crate::protocol::ReadSelector::All)),
                "run history was pruned; canonical query and export are unavailable",
            );
            assert_refused(
                store.hold(&run.run_id, "after-decision", &peer()),
                "run history was pruned; new mutations are refused",
            );
        }
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        let retried = recovered.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
        assert!(retried.failed.is_empty(), "{:?}", retried.failed);
        assert_eq!(retried.pruned.len(), 1);
        assert_eq!(fs::read(directory.join("segments.json")).unwrap(), manifest);
        assert_eq!(recovered.stream(&run.run_id).unwrap().replay(), &replay);
        assert!(!directory.join(STREAM).exists());
        assert!(!directory.join("artifacts/stdout.bin").exists());
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }
}

#[test]
fn gc_revalidates_bytes_and_refuses_changed_files_or_symlinked_capture_directories() {
    for mode in ["canonical", "capture", "symlink", "anchor"] {
        let (temp, mut store, run) = gc_fixture();
        let directory = store.root().join(&run.run_id);
        let outside = temp.path().join("outside");
        fsx::create_dir_all(&outside).unwrap();
        fs::write(outside.join("stdout.bin"), b"must be kept").unwrap();
        if mode != "canonical" {
            faults::arm(Plan::fail(Point::GcBeforeUnlink));
            assert_eq!(
                store
                    .gc_at(1, None, 100, &peer(), gc_future())
                    .unwrap()
                    .failed
                    .len(),
                1
            );
            faults::disarm();
        }
        match mode {
            "canonical" => {
                let path = directory.join(manifest::name(3));
                let bytes = fs::read_to_string(&path).unwrap();
                assert!(bytes.contains("private-note-body"));
                fs::write(
                    path,
                    bytes.replace("private-note-body", "changed-note-body"),
                )
                .unwrap();
            }
            "capture" => {
                fs::write(directory.join("artifacts/stdout.bin"), b"changed-capture").unwrap();
            }
            "symlink" => {
                fs::rename(
                    directory.join("artifacts"),
                    directory.join("preserved-artifacts"),
                )
                .unwrap();
                std::os::unix::fs::symlink(&outside, directory.join("artifacts")).unwrap();
            }
            "anchor" => {
                fs::write(directory.join("gc.json"), b"broken\n").unwrap();
            }
            _ => unreachable!(),
        }
        let first = fs::read(directory.join(STREAM)).unwrap();
        let failed = store.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
        assert_eq!(failed.failed.len(), 1, "{mode}");
        assert_eq!(fs::read(directory.join(STREAM)).unwrap(), first);
        assert_eq!(
            fs::read(outside.join("stdout.bin")).unwrap(),
            b"must be kept"
        );
        if matches!(mode, "canonical" | "hardlink") {
            assert!(!directory.join("gc.json").exists());
        } else {
            drop(store);
            assert!(Store::open(&temp.path().join("data")).is_err());
        }
    }
}

#[test]
fn gc_keeps_held_unknown_recent_and_live_reader_runs_and_refuses_active_launches() {
    let (_temp, mut store, run) = gc_fixture();
    assert!(store.gc(1, None, 100, &peer()).unwrap().pruned.is_empty());
    store.hold(&run.run_id, "hold", &peer()).unwrap();
    assert!(
        store
            .gc_at(1, None, 100, &peer(), gc_future())
            .unwrap()
            .pruned
            .is_empty()
    );
    store.release(&run.run_id, "release", &peer()).unwrap();
    let active = store.prepare("active", &payload(), &peer()).unwrap();
    store.claim_owner(&active.run_id, &peer()).unwrap();
    assert!(
        store
            .gc_at(1, None, 100, &peer(), gc_future())
            .unwrap_err()
            .message()
            .contains("quiescent")
    );
    store.settle_orphans(&peer(), |_| false).unwrap();
    store
        .read(&read_request(&run, crate::protocol::ReadSelector::All))
        .unwrap();
    // Model a reader begun at the injected collection clock, after the run aged.
    let now = gc_future();
    let entry = fs::read_dir(store.root().join("readers"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut envelope: Value = serde_json::from_slice(&fs::read(&entry).unwrap()).unwrap();
    envelope["checkpoint"]["created"] =
        json!(now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    envelope["digest"] = json!(digest(&envelope["checkpoint"]).unwrap());
    fs::write(&entry, canonical(&envelope).unwrap()).unwrap();
    let result = store.gc_at(1, None, 100, &peer(), now).unwrap();
    assert!(result.pruned.is_empty());
    assert!(
        result.kept.iter().any(
            |r| r.run_id == run.run_id && r.keep_reasons.iter().any(|r| r == "reader_snapshot")
        )
    );
    assert!(result.kept.iter().any(
        |r| r.run_id == active.run_id && r.keep_reasons.iter().any(|r| r == "outcome_unknown")
    ));
    let result = store
        .gc_at(
            1,
            None,
            100,
            &peer(),
            now + std::time::Duration::from_secs(601),
        )
        .unwrap();
    assert_eq!(result.pruned.len(), 1);
    assert_eq!(result.pruned[0].run_id, run.run_id);
    assert_eq!(store.show(&active.run_id).unwrap().state, "outcome_unknown");
}

#[test]
fn gc_never_removes_files_reappearing_after_completion() {
    let (temp, mut store, run) = gc_fixture();
    let directory = store.root().join(&run.run_id);
    assert_eq!(
        store
            .gc_at(1, None, 100, &peer(), gc_future())
            .unwrap()
            .pruned
            .len(),
        1
    );
    private_file(&directory.join(STREAM), OpenOptions::new().create(true))
        .unwrap()
        .write_all(b"restored history")
        .unwrap();
    assert!(!store.verify(None).unwrap()[0].local_consistency);
    let retry = store.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
    assert_eq!(retry.failed.len(), 1);
    assert_eq!(
        fs::read(directory.join(STREAM)).unwrap(),
        b"restored history"
    );
    drop(store);
    assert_refused(
        Store::open(&temp.path().join("data")),
        "GC inventory file identity or content changed; bytes preserved",
    );
    assert_eq!(
        fs::read(directory.join(STREAM)).unwrap(),
        b"restored history"
    );
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

#[test]
fn reader_snapshot_export_is_exact_bounded_and_retries_the_identical_prior_page() {
    let (temp, mut store, run) = create();
    for n in 0..80 {
        note(&mut store, &run, &format!("note:{n}"), json!({"index":n})).unwrap();
    }
    let path = temp
        .path()
        .join("data/ledger")
        .join(&run.run_id)
        .join(STREAM);
    let original = fs::read_to_string(&path).unwrap();
    let mut request = read_request(&run, crate::protocol::ReadSelector::All);
    let first = store.read(&request).unwrap();
    assert!(!first.done);
    assert!(first.scanned_through_seq <= crate::protocol::READ_SCAN_FRAMES as u64);
    let snapshot = first.snapshot.clone();
    note(&mut store, &run, "after-snapshot", json!({"later":true})).unwrap();
    request.cursor = first.next_cursor.clone();
    let second = store.read(&request).unwrap();
    assert_eq!(second, store.read(&request).unwrap());
    assert_eq!(second.snapshot, snapshot);
    request.cursor = second.next_cursor.clone();
    let (pages, remaining) = read_all(&mut store, request);
    assert_eq!(
        format!("{}{}{}", first.ndjson, second.ndjson, remaining),
        original
    );
    assert!(
        pages
            .iter()
            .all(|p| p.ndjson.len() <= crate::protocol::READ_CHUNK_BYTES && p.local_consistency)
    );
    assert_eq!(
        store.show(&run.run_id).unwrap().chain.head_seq,
        snapshot.head_seq + 1
    );
    assert_eq!(
        fs::read_to_string(&path).unwrap().lines().count() as u64,
        snapshot.head_seq + 1
    );
}

#[test]
fn reader_filters_original_source_operations_stage_and_writer_time() {
    let (_temp, mut store, run) = create();
    for (fixture, seq) in [
        ("exec", 1),
        ("exit", 2),
        ("path", 3),
        ("deny", 4),
        ("host", 5),
        ("proxy", 1),
    ] {
        source_fixture(&mut store, &run, fixture, seq, None);
    }
    for (selector, count) in [
        (crate::protocol::ReadSelector::Execs, 2),
        (crate::protocol::ReadSelector::Paths, 2),
        (crate::protocol::ReadSelector::Hosts, 2),
        (crate::protocol::ReadSelector::Denials, 2),
    ] {
        let (pages, _) = read_all(&mut store, read_request(&run, selector));
        let events: Vec<_> = pages.iter().flat_map(|p| &p.records).collect();
        assert_eq!(events.len(), count);
        assert!(events.iter().all(|e| e["schema"] == records::SCHEMA_EVENT
            && e["stage"] == "result"
            && e["provenance"]["role"] == "producer"));
    }
    let mut request = read_request(&run, crate::protocol::ReadSelector::Execs);
    request.filter.stage = Some(crate::protocol::ReadStage::Attempt);
    let (pages, _) = read_all(&mut store, request);
    assert!(pages.iter().all(|p| p.records.is_empty()));
    let mut request = read_request(&run, crate::protocol::ReadSelector::Execs);
    request.filter.since = Some("2099-01-01T00:00:00Z".into());
    assert!(
        read_all(&mut store, request)
            .0
            .iter()
            .all(|p| p.records.is_empty())
    );
    let mut request = read_request(&run, crate::protocol::ReadSelector::Execs);
    request.filter.until = Some("2000-01-01T00:00:00Z".into());
    assert!(
        read_all(&mut store, request)
            .0
            .iter()
            .all(|p| p.records.is_empty())
    );
}

#[test]
fn reader_large_utf8_records_are_fully_verified_before_chunks_and_query_block_replays() {
    let (temp, mut store, run) = create();
    source_fixture(&mut store, &run, "path", 1, Some("small"));
    source_fixture(&mut store, &run, "path", 2, Some(&"€\\\"".repeat(80_000)));
    let original = fs::read_to_string(
        temp.path()
            .join("data/ledger")
            .join(&run.run_id)
            .join(STREAM),
    )
    .unwrap();
    let mut request = read_request(&run, crate::protocol::ReadSelector::Paths);
    let mut blocked = None;
    for _ in 0..100 {
        let page = store.read(&request).unwrap();
        if page.oversized_record.is_some() {
            assert_eq!(page, store.read(&request).unwrap());
            blocked = Some(page);
            break;
        }
        assert!(!page.done);
        request.cursor = page.next_cursor;
    }
    let blocked = blocked.unwrap();
    assert_eq!(blocked.oversized_record.unwrap().seq, 4);
    let (pages, export) = read_all(
        &mut store,
        read_request(&run, crate::protocol::ReadSelector::All),
    );
    assert_eq!(export, original);
    assert!(pages.iter().any(|p| p.ndjson.is_empty() && !p.done));
    for page in pages {
        assert!(page.ndjson.len() <= crate::protocol::READ_CHUNK_BYTES);
        let response = crate::protocol::Response::Ok {
            value: serde_json::to_value(&page).unwrap(),
        };
        assert!(serde_json::to_vec(&response).unwrap().len() < MAX_FRAME_BYTES);
        let mut frame = vec![];
        crate::daemon::write_frame(&mut frame, &response).unwrap();
    }
}

#[test]
fn reader_refuses_filtered_corruption_and_reports_extra_tails_without_mutation() {
    let (temp, mut store, run) = create();
    note(&mut store, &run, "irrelevant", json!({"value":"original"})).unwrap();
    source_fixture(&mut store, &run, "exec", 1, None);
    let path = temp
        .path()
        .join("data/ledger")
        .join(&run.run_id)
        .join(STREAM);
    let original = fs::read_to_string(&path).unwrap();
    let altered = original.replace("original", "modified");
    fs::write(&path, &altered).unwrap();
    let (pages, _) = read_all(
        &mut store,
        read_request(&run, crate::protocol::ReadSelector::Execs),
    );
    assert!(pages.iter().all(|p| p.records.is_empty()));
    assert_eq!(pages.last().unwrap().stream_status, "corrupt");
    assert!(!pages.last().unwrap().local_consistency);
    assert_eq!(fs::read_to_string(&path).unwrap(), altered);
    fs::write(&path, format!("{original}{{\"torn\":")).unwrap();
    let (pages, bytes) = read_all(
        &mut store,
        read_request(&run, crate::protocol::ReadSelector::All),
    );
    assert_eq!(bytes, original);
    assert!(
        pages
            .iter()
            .all(|p| !p.local_consistency && p.stream_status == "corrupt")
    );
    assert!(fs::read_to_string(&path).unwrap().ends_with("{\"torn\":"));
}

#[test]
fn reader_new_page_refuses_truncation_of_a_previously_verified_cached_large_frame() {
    let (temp, mut store, run) = create();
    source_fixture(&mut store, &run, "path", 1, Some(&"€".repeat(230_000)));
    let path = temp
        .path()
        .join("data/ledger")
        .join(&run.run_id)
        .join(STREAM);
    let length = fs::metadata(&path).unwrap().len();
    let mut request = read_request(&run, crate::protocol::ReadSelector::All);
    let mut exercised = false;
    for _ in 0..100 {
        let page = store.read(&request).unwrap();
        if page.scanned_through_seq == 3 && !page.done && !page.ndjson.is_empty() {
            assert!(request.cursor.is_some());
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(length - 1)
                .unwrap();
            // A lost reply may retry the exact historical page, but a new
            // continuation cannot publish the rest of its cached frame.
            assert_eq!(store.read(&request).unwrap(), page);
            request.cursor = page.next_cursor;
            let next = store.read(&request).unwrap();
            assert!(next.done && !next.local_consistency);
            assert_eq!(next.stream_status, "corrupt");
            assert!(next.ndjson.is_empty());
            assert!(next.problems.iter().any(|p| p.contains("truncated")));
            assert_eq!(fs::metadata(&path).unwrap().len(), length - 1);
            exercised = true;
            break;
        }
        assert!(!page.done);
        request.cursor = page.next_cursor;
    }
    assert!(exercised);
}

#[test]
fn reader_cursor_cannot_change_scope_and_survives_restart() {
    let (temp, mut store, run) = create();
    for n in 0..40 {
        note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
    }
    let request = read_request(&run, crate::protocol::ReadSelector::All);
    let page = store.read(&request).unwrap();
    let mut resumed = request.clone();
    resumed.cursor = page.next_cursor;
    let mut wrong = resumed.clone();
    wrong.filter.selector = crate::protocol::ReadSelector::Execs;
    assert!(
        store
            .read(&wrong)
            .unwrap_err()
            .message()
            .contains("mismatch")
    );
    wrong = resumed.clone();
    wrong.limit += 1;
    assert!(
        store
            .read(&wrong)
            .unwrap_err()
            .message()
            .contains("mismatch")
    );
    wrong = resumed.clone();
    wrong.cursor.as_mut().unwrap().replace_range(63..64, "z");
    assert_refused(store.read(&wrong), "invalid reader cursor");
    drop(store);
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    assert!(recovered.read(&resumed).unwrap().local_consistency);
    for _ in 0..40 {
        assert!(
            read_all(
                &mut recovered,
                read_request(&run, crate::protocol::ReadSelector::Execs)
            )
            .0
            .last()
            .unwrap()
            .done
        );
    }
}

#[test]
fn durable_reader_refuses_rechecksummed_forged_snapshot_labels() {
    for field in ["state", "child_protection", "coverage", "zero_head"] {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut store = Store::open(&data).unwrap();
        let mut plan = payload();
        plan["profile"] = json!("none");
        let run = store.prepare("none-reader", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        for n in 0..40 {
            note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
        }
        let mut request = read_request(&run, crate::protocol::ReadSelector::All);
        let first = store.read(&request).unwrap();
        assert_eq!(first.state, "prepared");
        assert_eq!(first.child_protection, "unprotected");
        request.cursor = first.next_cursor;
        let cursor = request.cursor.as_ref().unwrap();
        let checkpoint_path = store
            .root()
            .join("readers")
            .join(format!("{}.json", &cursor[..32]));
        let canonical_path = store.root().join(&run.run_id).join(STREAM);
        let original = fs::read(&canonical_path).unwrap();
        drop(store);

        let mut envelope: Value =
            serde_json::from_slice(&fs::read(&checkpoint_path).unwrap()).unwrap();
        let template = &mut envelope["checkpoint"]["template"];
        match field {
            "state" => {
                template["state"] = json!("settled");
                template["stream_status"] = json!("complete");
            }
            "child_protection" => template["child_protection"] = json!("enforced"),
            "coverage" => template["coverage"]["status"] = json!("active"),
            "zero_head" => {
                template["snapshot"] = json!({"head_seq":0,"head_digest":null});
                template["state"] = json!("settled");
                template["child_protection"] = json!("enforced");
                template["stream_status"] = json!("complete");
                envelope["checkpoint"]["accepted_bytes"] = json!(0);
                envelope["checkpoint"]["position"] = json!({
                    "offset":0,"frame_start":0,"pending_bytes":0,
                    "ready_emitted":null,"next_seq":1,"previous_digest":null,"verified":0
                });
            }
            _ => unreachable!(),
        }
        envelope["digest"] = json!(digest(&envelope["checkpoint"]).unwrap());
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&checkpoint_path)
            .unwrap();
        file.write_all(&canonical(&envelope).unwrap()).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let mut recovered = Store::open(&data).unwrap();
        let error = recovered.read(&request).unwrap_err();
        assert!(
            error.message().contains("snapshot"),
            "forged {field}: {}",
            error.message()
        );
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
        let canonical_run = recovered.show(&run.run_id).unwrap();
        assert_eq!(canonical_run.state, "prepared");
        assert_eq!(canonical_run.child_protection, "unprotected");
        assert_eq!(fs::read(&canonical_path).unwrap(), original);
    }
}

#[test]
fn durable_reader_preserves_snapshot_labels_after_a_later_state_change() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let mut store = Store::open(&data).unwrap();
    let mut plan = payload();
    plan["profile"] = json!("none");
    let run = store.prepare("none-reader", &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    for n in 0..40 {
        note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
    }
    let original = fs::read_to_string(store.root().join(&run.run_id).join(STREAM)).unwrap();
    let mut request = read_request(&run, crate::protocol::ReadSelector::All);
    let first = store.read(&request).unwrap();
    request.cursor = first.next_cursor.clone();
    assert!(request.cursor.is_some());
    store
        .append_owner(
            &run.run_id,
            "later-state",
            "outcome_unknown",
            None,
            &json!({"coverage":{"status":"degraded"}}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    drop(store);

    let mut recovered = Store::open(&data).unwrap();
    assert_eq!(
        recovered.show(&run.run_id).unwrap().state,
        "outcome_unknown"
    );
    let second = recovered.read(&request).unwrap();
    assert_eq!(recovered.read(&request).unwrap(), second);
    let mut pages = vec![second.clone()];
    let mut exported = format!("{}{}", first.ndjson, second.ndjson);
    if !second.done {
        request.cursor = second.next_cursor;
        let (remaining, bytes) = read_all(&mut recovered, request);
        pages.extend(remaining);
        exported.push_str(&bytes);
    }
    for page in &pages {
        assert!(page.local_consistency);
        assert_eq!(page.snapshot, first.snapshot);
        assert_eq!(page.state, "prepared");
        assert_eq!(page.child_protection, "unprotected");
        assert_eq!(page.coverage, first.coverage);
    }
    assert!(pages.last().unwrap().done);
    assert_eq!(exported, original);
}

#[test]
fn durable_reader_sync_failure_refuses_retries_until_recovery_barrier_succeeds() {
    let (_temp, mut store, run) = create();
    for n in 0..40 {
        note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
    }
    let canonical_path = store.root().join(&run.run_id).join(STREAM);
    let original = fs::read_to_string(&canonical_path).unwrap();
    let mut request = read_request(&run, crate::protocol::ReadSelector::All);
    let first = store.read(&request).unwrap();
    request.cursor = first.next_cursor.clone();
    let cursor = request.cursor.as_ref().unwrap();
    let checkpoint_path = store
        .root()
        .join("readers")
        .join(format!("{}.json", &cursor[..32]));
    let initial_checkpoint = fs::read(&checkpoint_path).unwrap();

    faults::arm(Plan::fail(Point::Replace(
        Replaced::ReaderCheckpoint,
        Step::BeforeDirectorySync,
    )));
    assert!(store.read(&request).is_err());
    let failed_checkpoint = fs::read(&checkpoint_path).unwrap();
    assert_ne!(failed_checkpoint, initial_checkpoint);
    let envelope: Value = serde_json::from_slice(&failed_checkpoint).unwrap();
    assert_eq!(envelope["checkpoint"]["prior"]["token"], cursor[32..]);
    assert!(store.read(&request).is_err());
    assert_eq!(fs::read(&checkpoint_path).unwrap(), failed_checkpoint);
    assert_eq!(fs::read_to_string(&canonical_path).unwrap(), original);

    faults::disarm();
    let second = store.read(&request).unwrap();
    assert_eq!(
        json!(digest(&serde_json::to_value(&second).unwrap()).unwrap()),
        envelope["checkpoint"]["prior"]["response_digest"]
    );
    assert_eq!(store.read(&request).unwrap(), second);
    assert_eq!(fs::read(&checkpoint_path).unwrap(), failed_checkpoint);
    let mut exported = format!("{}{}", first.ndjson, second.ndjson);
    if !second.done {
        request.cursor = second.next_cursor;
        let (_, remaining) = read_all(&mut store, request);
        exported.push_str(&remaining);
    }
    assert_eq!(exported, original);
    assert_eq!(fs::read_to_string(&canonical_path).unwrap(), original);
    assert!(store.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn a_checkpoint_rewritten_in_place_is_validated_again() {
    let (_temp, mut store, run) = create();
    for n in 0..40 {
        note(&mut store, &run, &format!("n{n}"), json!({"v":n})).unwrap();
    }
    let mut request = read_request(&run, crate::protocol::ReadSelector::All);
    request.limit = 1;
    let first = store.read(&request).unwrap();
    request.cursor = first.next_cursor.clone();
    let second = store.read(&request).unwrap();
    let cursor = second.next_cursor.clone().unwrap();
    let path = store
        .root()
        .join("readers")
        .join(format!("{}.json", &cursor[..32]));
    let mut bytes = fs::read(&path).unwrap();
    let digest = bytes.windows(7).position(|w| w == b"sha256:").unwrap();
    bytes[digest + 7] = if bytes[digest + 7] == b'0' {
        b'1'
    } else {
        b'0'
    };
    fs::write(&path, &bytes).unwrap();
    request.cursor = Some(cursor);
    assert_refused(
        store.read(&request),
        "reader checkpoint is corrupt or unavailable; start a new snapshot",
    );
}

#[test]
fn corrupt_reader_checkpoint_is_isolated_bounded_and_expires() {
    let (_temp, mut store, run) = create();
    for n in 0..40 {
        note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
    }
    let canonical_path = store.root().join(&run.run_id).join(STREAM);
    let original = fs::read(&canonical_path).unwrap();
    let fresh = read_request(&run, crate::protocol::ReadSelector::All);
    let initial = store.read(&fresh).unwrap();
    assert!(!initial.done);
    let mut corrupt_request = fresh.clone();
    corrupt_request.cursor = initial.next_cursor;
    let cursor = corrupt_request.cursor.as_ref().unwrap();
    let directory = store.root().join("readers");
    let checkpoint_path = directory.join(format!("{}.json", &cursor[..32]));
    let mut envelope: Value = serde_json::from_slice(&fs::read(&checkpoint_path).unwrap()).unwrap();
    envelope["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    let altered = canonical(&envelope).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&checkpoint_path)
        .unwrap();
    file.write_all(&altered).unwrap();
    file.sync_all().unwrap();
    drop(file);

    assert_refused(
        store.read(&corrupt_request),
        "reader checkpoint is corrupt or unavailable; start a new snapshot",
    );
    for _ in 0..31 {
        let unrelated = store.read(&fresh).unwrap();
        assert!(!unrelated.done);
        assert!(unrelated.local_consistency);
        assert_eq!(unrelated.snapshot, initial.snapshot);
    }
    assert_eq!(fs::read(&checkpoint_path).unwrap(), altered);
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 32);
    assert!(
        store
            .read(&fresh)
            .unwrap_err()
            .message()
            .contains("session limit")
    );
    assert_refused(
        store.read(&corrupt_request),
        "reader checkpoint is corrupt or unavailable; start a new snapshot",
    );

    File::open(&checkpoint_path)
        .unwrap()
        .set_times(
            fs::FileTimes::new()
                .set_modified(SystemTime::now() - std::time::Duration::from_secs(601)),
        )
        .unwrap();
    let after_expiry = store.read(&fresh).unwrap();
    assert!(after_expiry.local_consistency);
    assert_eq!(after_expiry.snapshot, initial.snapshot);
    assert!(!checkpoint_path.exists());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 32);
    assert_refused(
        store.read(&corrupt_request),
        "reader cursor expired or is unknown; start a new snapshot, do not append it to an old export",
    );
    assert_eq!(fs::read(&canonical_path).unwrap(), original);
    assert!(store.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn durable_reader_refuses_a_rechecksummed_empty_snapshot_template() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let mut store = Store::open(&data).unwrap();
    let mut plan = payload();
    plan["profile"] = json!("none");
    let run = store.prepare("none-reader", &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    for n in 0..40 {
        note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
    }
    let mut request = read_request(&run, crate::protocol::ReadSelector::All);
    let first = store.read(&request).unwrap();
    request.cursor = first.next_cursor;
    let cursor = request.cursor.as_ref().unwrap();
    let checkpoint_path = store
        .root()
        .join("readers")
        .join(format!("{}.json", &cursor[..32]));
    let canonical_path = store.root().join(&run.run_id).join(STREAM);
    let original = fs::read(&canonical_path).unwrap();
    drop(store);

    // A clean empty snapshot cannot exist: every restorable stream opens
    // at durable preparation, so the zero-record claim must corroborate
    // the canonical accepted state instead of passing vacuously.
    let mut envelope: Value = serde_json::from_slice(&fs::read(&checkpoint_path).unwrap()).unwrap();
    envelope["checkpoint"]["template"]["snapshot"] = json!({"head_seq":0,"head_digest":null});
    envelope["checkpoint"]["template"]["state"] = json!("settled");
    envelope["checkpoint"]["template"]["stream_status"] = json!("complete");
    envelope["checkpoint"]["template"]["child_protection"] = json!("enforced");
    envelope["checkpoint"]["accepted_bytes"] = json!(0);
    envelope["checkpoint"]["position"] = json!({
        "offset":0,"frame_start":0,"pending_bytes":0,"ready_emitted":null,
        "next_seq":1,"previous_digest":null,"verified":0});
    envelope["digest"] = json!(digest(&envelope["checkpoint"]).unwrap());
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&checkpoint_path)
        .unwrap();
    file.write_all(&canonical(&envelope).unwrap()).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let mut recovered = Store::open(&data).unwrap();
    let error = recovered.read(&request).unwrap_err();
    assert!(error.message().contains("corrupt"), "forged empty: {error}");
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
    let canonical_run = recovered.show(&run.run_id).unwrap();
    assert_eq!(canonical_run.state, "prepared");
    assert_eq!(canonical_run.child_protection, "unprotected");
    assert_eq!(canonical_run.chain.head_seq, first.snapshot.head_seq);
    assert_eq!(fs::read(&canonical_path).unwrap(), original);
}

#[test]
fn lifetime_lock_refuses_a_second_writer() {
    let (temp, _store, _) = create();
    assert!(
        matches!(Store::open(&temp.path().join("data")), Err(error) if error.message().contains("writer"))
    );
}

#[test]
fn a_closed_writer_releases_its_lock_even_while_a_copy_of_its_descriptor_lives() {
    let (temp, store, _) = create();
    // A child forked by another thread holds a copy until it execs.
    // SAFETY: dup takes the open descriptor by value; the copy is owned below.
    let copy = unsafe { libc::dup(store.lock().as_raw_fd()) };
    assert!(copy >= 0);
    // SAFETY: dup returned a new descriptor owned only here.
    let copy = unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(copy) };
    drop(store);
    Store::open(&temp.path().join("data")).unwrap();
    drop(copy);
}

#[test]
fn full_length_request_id_prepares_replays_and_recovers_without_ambiguous_state() {
    let temp = tempfile::tempdir().unwrap();
    let request_id = "x".repeat(128);
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let run = store.prepare(&request_id, &payload(), &peer()).unwrap();
    assert_eq!(run.request_id, request_id);
    assert_eq!(
        run.run_id,
        store
            .prepare(&request_id, &payload(), &peer())
            .unwrap()
            .run_id
    );
    assert!(store.verify(None).unwrap()[0].local_consistency);
    assert!(!store.status().preparation_blocked);
    drop(store);
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(
        run.run_id,
        recovered
            .prepare(&request_id, &payload(), &peer())
            .unwrap()
            .run_id
    );
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
    assert!(!recovered.status().preparation_blocked);
}

#[test]
fn lost_replies_replay_same_run_and_exact_receipt_after_recovery() {
    let (temp, mut store, run) = create();
    let first = note(
        &mut store,
        &run,
        "stable",
        json!({"meaning":"persisted but reply lost"}),
    )
    .unwrap();
    assert_eq!(
        first,
        note(
            &mut store,
            &run,
            "stable",
            json!({"meaning":"persisted but reply lost"})
        )
        .unwrap()
    );
    assert_refused(
        note(&mut store, &run, "stable", json!({"meaning":"changed"})),
        "request id conflicts with its immutable payload",
    );
    drop(store);
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(
        recovered
            .prepare("test-prepare", &payload(), &peer())
            .unwrap()
            .run_id,
        run.run_id
    );
    assert_eq!(
        first,
        note(
            &mut recovered,
            &run,
            "stable",
            json!({"meaning":"persisted but reply lost"})
        )
        .unwrap()
    );
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn different_payload_cannot_rebind_prepare_or_effect_identity() {
    let (_temp, mut store, run) = create();
    assert_refused(
        store.prepare("test-prepare", &json!({"different":true}), &peer()),
        "prepare only accepts the versioned digest-only request plan",
    );
    store
        .append_owner(
            &run.run_id,
            "effect-first",
            "note",
            Some("effect-1"),
            &json!({"v":1}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    assert_refused(
        store.append_owner(
            &run.run_id,
            "effect-second",
            "note",
            Some("effect-1"),
            &json!({"v":2}),
            &peer(),
            TOKEN,
        ),
        "effect id conflicts with its immutable payload",
    );
}

#[test]
fn interrupted_write_is_retained_poisoned_and_never_truncated_on_recovery() {
    let (temp, mut store, run) = create();
    let stream_path = store.root().join(&run.run_id).join(STREAM);
    let before = fs::read(&stream_path).unwrap();
    faults::arm(Plan::fail(Point::EventPartialWrite));
    assert!(note(&mut store, &run, "partial", json!({"v":"half record"})).is_err());
    let broken = fs::read(&stream_path).unwrap();
    assert!(broken.len() > before.len());
    faults::disarm();
    assert_refused(
        note(&mut store, &run, "retry", json!({})),
        "stream is poisoned; no dependent dispatch or sequence reuse",
    );
    drop(store);
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(fs::read(&stream_path).unwrap(), broken);
    assert!(!recovered.verify(None).unwrap()[0].local_consistency);
    assert_eq!(
        recovered.show(&run.run_id).unwrap().state,
        "outcome_unknown"
    );
    assert_refused(
        recovered.prepare("different", &payload(), &peer()),
        "ambiguous recovery blocks new preparation; inspect verify",
    );
    assert_refused(
        note(&mut recovered, &run, "partial", json!({"v":"half record"})),
        "stream is poisoned; no dependent dispatch or sequence reuse",
    );
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

#[test]
fn the_most_severe_poison_decides_a_stream_status() {
    let poison = |kinds: &[PoisonKind]| -> Vec<Poison> {
        kinds.iter().map(|kind| Poison::new(*kind, "x")).collect()
    };
    assert_eq!(poison_status(&[]), None);
    for kinds in [
        [PoisonKind::Incomplete, PoisonKind::Corrupt],
        [PoisonKind::Corrupt, PoisonKind::Incomplete],
        [PoisonKind::Incomplete, PoisonKind::Unanchored],
    ] {
        assert_eq!(poison_status(&poison(&kinds)), Some("corrupt"), "{kinds:?}");
    }
    assert_eq!(
        poison_status(&poison(&[PoisonKind::Incomplete])),
        Some("incomplete")
    );
}

#[test]
fn integrity_violations_read_as_corrupt_and_interruptions_as_incomplete() {
    let mixed_attempt = |records: &mut Vec<Value>| {
        records.last_mut().unwrap()["attempt_id"] =
            json!("att_00000000-0000-4000-8000-000000000000");
    };
    let duplicate_request = |records: &mut Vec<Value>| {
        let mut copy = records.last().unwrap().clone();
        copy["seq"] = json!(copy["seq"].as_u64().unwrap() + 1);
        copy["prev"] = json!(sha256_prefixed(
            &canonical(records.last().unwrap()).unwrap()
        ));
        records.push(copy);
    };
    let corrupt = |problem: &str, edit: &dyn Fn(&mut Vec<Value>)| {
        let (temp, mut store, run) = create();
        note(&mut store, &run, "first", json!({"v":1})).unwrap();
        rewrite_without_manifest(&store, &run, edit);
        drop(store);
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(store.verify(None).unwrap()[0].problems, [problem]);
        let page = store
            .read(&read_request(&run, crate::protocol::ReadSelector::All))
            .unwrap();
        assert!(!page.local_consistency, "{problem}");
        assert_eq!(page.stream_status, "corrupt", "{problem}");
    };
    corrupt("mixed attempt identity", &mixed_attempt);
    corrupt(
        "duplicate request id in canonical stream",
        &duplicate_request,
    );
    let (temp, mut store, run) = create();
    note(&mut store, &run, "first", json!({"v":1})).unwrap();
    let path = store.root().join(&run.run_id).join(STREAM);
    drop(store);
    let mut torn = fs::read(&path).unwrap();
    torn.extend_from_slice(b"{\"torn\":");
    fs::write(&path, torn).unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(
        store.verify(None).unwrap()[0].problems,
        ["interrupted canonical frame; bytes retained"]
    );
    let page = store
        .read(&read_request(&run, crate::protocol::ReadSelector::All))
        .unwrap();
    assert!(!page.local_consistency);
    assert_eq!(page.stream_status, "incomplete");
}

#[test]
fn append_refuses_every_intent_that_recovery_would_refuse() {
    let (temp, mut store, run) = create();
    for (forged, refusal) in [
        (
            json!({"kind":"note","request_id":"note","body":{"receipt":prepared(&run)}}),
            "notes cannot replace receipt or state projections",
        ),
        (
            json!({"kind":"outcome_unknown","request_id":"unknown","body":{"token_id":"x"}}),
            "intent body cannot supply reserved identity token_id",
        ),
    ] {
        let refused = store
            .append(&run.run_id, forged, "owner", &peer(), None)
            .unwrap_err();
        assert!(refused.to_string().contains(refusal), "{refused}");
    }
    drop(store);
    let store = Store::open(&temp.path().join("data")).unwrap();
    assert!(store.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn verification_pages_are_bounded_by_runs_and_bytes_and_status_reads_no_history() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let mut ids: Vec<_> = (0..3)
        .map(|n| {
            store
                .prepare(&format!("verify-{n}"), &payload(), &peer())
                .unwrap()
                .run_id
        })
        .collect();
    ids.sort();
    for limit in [0, MAX_VERIFY_LIMIT + 1] {
        assert_refused(
            store.verify_page(None, None, limit),
            "verify limit must be between 1 and 100",
        );
    }
    let first = store.verify_page(None, None, 2).unwrap();
    assert_eq!(first.reports.len(), 2);
    assert!(!first.done);
    assert_eq!(first.next_after.as_deref(), Some(ids[1].as_str()));
    let last = store
        .verify_page(None, first.next_after.as_deref(), 2)
        .unwrap();
    assert_eq!(last.reports[0].run_id, ids[2]);
    assert!(last.done && last.next_after.is_none());
    // A page re-reads at most its byte budget, but never fewer than one run.
    store.set_verify_page_bytes(1);
    let one = store.verify_page(None, None, MAX_VERIFY_LIMIT).unwrap();
    assert_eq!(one.reports.len(), 1);
    assert_eq!(one.next_after.as_deref(), Some(ids[0].as_str()));
    assert_eq!(store.verify(None).unwrap().len(), 3);
    // Reports carry the bounded coverage summary, not raw gap payloads.
    assert_eq!(
        one.reports[0].coverage,
        crate::reader::coverage_summary(&json!({"status":"unobserved"}))
    );
    assert!(store.status().ready());
    assert_eq!(store.status().runs, 3);
    // Status reflects accepted state; damage on disk waits for verify.
    fs::write(store.root().join(&ids[0]).join(STREAM), b"damaged\n").unwrap();
    assert!(store.status().ready());
    assert!(!store.verify_page(Some(&ids[0]), None, 1).unwrap().reports[0].local_consistency);
    faults::arm(Plan::fail(Point::EventBeforeWrite));
    assert!(store.hold(&ids[1], "lost", &peer()).is_err());
    faults::disarm();
    let status = store.status();
    assert_eq!(status.ambiguous_runs, 1);
    assert!(!status.ready());
}

#[test]
fn every_persistence_failure_stops_acknowledgements_until_recovery() {
    for fault in [
        Point::EventBeforeWrite,
        Point::EventBeforeSync,
        Point::Replace(Replaced::Projection, Step::BeforeWrite),
        Point::Replace(Replaced::Manifest, Step::BeforeWrite),
        Point::AppendBeforeDirectorySync,
    ] {
        let (temp, mut store, run) = create();
        faults::arm(Plan::fail(fault));
        assert!(note(&mut store, &run, "uncertain", json!({"v":1})).is_err());
        faults::disarm();
        assert_refused(
            note(&mut store, &run, "new", json!({"v":2})),
            "stream is poisoned; no dependent dispatch or sequence reuse",
        );
        assert!(!store.verify(None).unwrap()[0].local_consistency);
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        let acknowledgement = note(&mut recovered, &run, "uncertain", json!({"v":1})).unwrap();
        assert!(acknowledgement.seq > 2);
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }
}

#[test]
fn recovery_sync_failure_cannot_publish_or_acknowledge_an_unflushed_tail() {
    let (temp, mut store, run) = create();
    let directory = store.root().join(&run.run_id);
    let stream_path = directory.join(STREAM);
    let manifest_path = directory.join("segments.json");
    let projection_path = directory.join("run.json");
    let old_manifest = fs::read(&manifest_path).unwrap();
    let old_projection = fs::read(&projection_path).unwrap();
    faults::arm(Plan::fail(Point::EventBeforeSync));
    let body = json!({"v":"written without successful sync"});
    assert!(note(&mut store, &run, "unflushed", body.clone()).is_err());
    faults::disarm();
    let unflushed = fs::read(&stream_path).unwrap();
    let last_frame = unflushed
        .split(|byte| *byte == b'\n')
        .rfind(|frame| !frame.is_empty())
        .unwrap();
    let record: Value = serde_json::from_slice(last_frame).unwrap();
    let original_receipt = AppendReceipt {
        seq: record["seq"].as_u64().unwrap(),
        digest: sha256_prefixed(last_frame),
    };
    drop(store);

    let syncs = std::cell::Cell::new(0);
    let data = temp.path().join("data");
    let failed = Store::open_with_recovery_sync(&data, |_| {
        syncs.set(syncs.get() + 1);
        assert_eq!(fs::read(&manifest_path).unwrap(), old_manifest);
        assert_eq!(fs::read(&projection_path).unwrap(), old_projection);
        Err(std::io::Error::from_raw_os_error(libc::EIO))
    });
    assert!(failed.is_err());
    assert_eq!(syncs.get(), 1);
    assert_eq!(fs::read(&manifest_path).unwrap(), old_manifest);
    assert_eq!(fs::read(&projection_path).unwrap(), old_projection);
    assert_eq!(fs::read(&stream_path).unwrap(), unflushed);

    let mut recovered = Store::open_with_recovery_sync(&data, |file| {
        syncs.set(syncs.get() + 1);
        assert_eq!(fs::read(&manifest_path).unwrap(), old_manifest);
        assert_eq!(fs::read(&projection_path).unwrap(), old_projection);
        file.sync_all()
    })
    .unwrap();
    assert_eq!(syncs.get(), 2);
    assert_eq!(
        note(&mut recovered, &run, "unflushed", body).unwrap(),
        original_receipt
    );
    assert_eq!(fs::read(&stream_path).unwrap(), unflushed);
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn index_failure_after_acknowledgement_does_not_poison_or_reexecute() {
    let (temp, mut store, run) = create();
    let external = temp.path().join("outside-index");
    fs::write(&external, b"must stay unchanged").unwrap();
    let index = store.root().join("index.sqlite");
    fs::remove_file(&index).unwrap();
    std::os::unix::fs::symlink(&external, &index).unwrap();
    let receipt = note(&mut store, &run, "durable-without-index", json!({"v":1})).unwrap();
    store.flush_index();
    assert_eq!(store.index_status()["state"], "unavailable");
    assert_eq!(fs::read(external).unwrap(), b"must stay unchanged");
    assert!(store.verify(None).unwrap()[0].local_consistency);
    assert_eq!(
        note(&mut store, &run, "durable-without-index", json!({"v":1})).unwrap(),
        receipt
    );
}

#[test]
fn admission_cannot_change_reserved_policy_or_argv() {
    let (_temp, mut store, run) = create();
    let mut receipt = prepared(&run);
    receipt["argv_digest"] = json!("sha256:bad");
    assert_refused(
        store.append_owner(
            &run.run_id,
            "admit",
            "admitted",
            None,
            &json!({"receipt":receipt}),
            &peer(),
            TOKEN,
        ),
        "record violates frozen jail-receipt schema",
    );
    // Well-formed receipts for another argv or policy reach the binding check.
    let other = json!(format!("sha256:{}", "e".repeat(64)));
    for path in ["/argv_digest", "/policy/digest"] {
        let mut receipt = prepared(&run);
        *receipt.pointer_mut(path).unwrap() = other.clone();
        assert_refused(
            store.append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":receipt}),
                &peer(),
                TOKEN,
            ),
            "intent receipt does not match prepared policy, argv, requirements and attempt",
        );
    }
    let first = store
        .append_owner(
            &run.run_id,
            "admit",
            "admitted",
            None,
            &json!({"receipt":prepared(&run)}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    assert_eq!(
        first,
        store
            .append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                TOKEN
            )
            .unwrap()
    );
    assert_refused(
        store.append_owner(
            &run.run_id,
            "admit-again",
            "admitted",
            None,
            &json!({"receipt":prepared(&run)}),
            &peer(),
            TOKEN,
        ),
        "admission or refusal is only valid from prepared",
    );
}

#[test]
fn source_replay_and_gap_are_preserved_when_projection_is_updated() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let mut plan = payload();
    plan["evidence"] = json!("best-effort");
    let run = store.prepare("gap-test", &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    let event = serde_json::to_value(records::Event::lifecycle_note(
        &run.attempt_id,
        2,
        SystemTime::now(),
        1,
        "test",
    ))
    .unwrap();
    let first = store
        .append_source(&run.run_id, &event, &peer(), TOKEN)
        .unwrap();
    assert_eq!(
        first,
        store
            .append_source(&run.run_id, &event, &peer(), TOKEN)
            .unwrap()
    );
    let mut changed = event.clone();
    changed["fields"]["message"] = json!("conflicting source sequence");
    assert_refused(
        store.append_source(&run.run_id, &changed, &peer(), TOKEN),
        "request id conflicts with its immutable payload",
    );
    store
        .append_owner(
            &run.run_id,
            "coverage",
            "outcome_unknown",
            None,
            &json!({"coverage":{"exec":"active"}}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    assert_eq!(
        store.show(&run.run_id).unwrap().coverage["ledger"]["status"],
        "degraded"
    );
}

#[test]
fn owner_death_records_unknown_without_restart_or_tree_claim() {
    let (_temp, mut store, run) = create();
    let records = store.settle_orphans(&peer(), |_| false).unwrap();
    assert_eq!(records[0].state, "outcome_unknown");
    let outcome = records[0].outcome.as_ref().unwrap();
    assert_eq!(outcome["unknown"], true);
    // The reconciler's own unknown is the run's reason, not a child outcome.
    assert!(outcome.get("observed_child_outcome").is_none(), "{outcome}");
    assert_eq!(
        outcome["unknown_reason"],
        "owner birth identity is no longer live; tree termination and unrecorded effects are not inferred"
    );
    let mut stranger = peer();
    stranger.birth = "new-process-birth".into();
    assert_refused(
        store.claim_owner(&run.run_id, &stranger),
        "attempt already has an owner; dead owners require reconciliation and are never restarted",
    );
}

#[test]
fn none_cannot_claim_enforced_protection_on_admission_or_in_its_projection() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let mut store = Store::open(&data).unwrap();
    let mut plan = payload();
    plan["profile"] = json!("none");
    let run = store.prepare("none", &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    let receipt = prepared(&run);
    assert_eq!(receipt["child_protection"], "enforced");
    let refused = store
        .append_owner(
            &run.run_id,
            "admit",
            "admitted",
            None,
            &json!({"receipt":receipt}),
            &peer(),
            TOKEN,
        )
        .unwrap_err();
    assert!(
        refused
            .to_string()
            .contains("none cannot claim enforced child protection"),
        "{refused}"
    );
    // An unresolved outcome may still carry the jail's receipt; its label
    // never upgrades a none run's projection.
    store
        .append_owner(
            &run.run_id,
            "unknown",
            "outcome_unknown",
            None,
            &json!({"receipt":receipt}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    assert_eq!(
        store.show(&run.run_id).unwrap().child_protection,
        "unprotected"
    );
    assert_eq!(
        store.verify(None).unwrap()[0].child_protection,
        "unprotected"
    );
    drop(store);
    let store = Store::open(&data).unwrap();
    assert_eq!(
        store.show(&run.run_id).unwrap().child_protection,
        "unprotected"
    );
}

#[test]
fn recovery_poisons_an_enforced_admission_of_a_none_run() {
    let (temp, mut store, run) = create();
    store
        .append_owner(
            &run.run_id,
            "admit",
            "admitted",
            None,
            &json!({"receipt":prepared(&run)}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    // Re-chain the history as a none preparation: only recovery's own
    // intent check can refuse the enforced admission that follows it.
    rewrite_without_manifest(&store, &run, |records| {
        records[0]["body"]["payload"]["profile"] = json!("none");
        for index in 1..records.len() {
            let prev = sha256_prefixed(&canonical(&records[index - 1]).unwrap());
            records[index]["prev"] = json!(prev);
        }
    });
    drop(store);
    let store = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(
        store.verify(None).unwrap()[0].problems,
        ["none cannot claim enforced child protection"]
    );
    assert_eq!(store.show(&run.run_id).unwrap().state, "outcome_unknown");
}

#[test]
fn unsafe_store_paths_and_oversized_events_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(temp.path(), temp.path().join("link")).unwrap();
    assert!(Store::open(&temp.path().join("link")).is_err());
    let (_temp, mut store, run) = create();
    assert_refused(
        note(
            &mut store,
            &run,
            "large",
            json!({"body":"x".repeat(MAX_FRAME_BYTES)}),
        ),
        "canonical event exceeds bounded frame limit",
    );
    assert_refused(store.show("../../escape"), "invalid run id");
}

#[test]
fn flattened_source_is_the_original_frozen_envelope_plus_writer_fields() {
    let (_temp, mut store, run) = create();
    let source = serde_json::to_value(records::Event::lifecycle_note(
        &run.attempt_id,
        1,
        SystemTime::now(),
        1,
        "prepared",
    ))
    .unwrap();
    store
        .append_source(&run.run_id, &source, &peer(), TOKEN)
        .unwrap();
    let bytes = fs::read(store.root().join(&run.run_id).join(STREAM)).unwrap();
    let mut canonical: Value = serde_json::from_slice(
        bytes
            .split(|byte| *byte == b'\n')
            .rfind(|line| !line.is_empty())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(canonical["schema"], records::SCHEMA_EVENT);
    assert!(canonical.get("body").is_none());
    for field in [
        "run_id",
        "seq",
        "prev",
        "received_at",
        "provenance",
        "kind",
        "request_id",
    ] {
        canonical.as_object_mut().unwrap().remove(field);
    }
    assert_eq!(canonical, source);
    assert!(store.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn strict_transport_gap_and_private_metadata_refuse_without_an_ack() {
    let (_temp, mut store, run) = create();
    let source = serde_json::to_value(records::Event::lifecycle_note(
        &run.attempt_id,
        2,
        SystemTime::now(),
        1,
        "prepared",
    ))
    .unwrap();
    assert_refused(
        store.append_source(&run.run_id, &source, &peer(), TOKEN),
        "strict producer transport loss was durably recorded; stop admission and execution",
    );
    let mut source = source;
    source["source_seq"] = json!(1);
    source["fields"]["raw_environment"] = json!("seed-secret-must-not-leak");
    let error = store
        .append_source(&run.run_id, &source, &peer(), TOKEN)
        .unwrap_err();
    assert!(!error.message().contains("seed-secret"));
    let mut plan = payload();
    plan["argv"] = json!(["seed-secret-must-not-leak"]);
    let error = store.prepare("raw-metadata", &plan, &peer()).unwrap_err();
    assert!(!error.message().contains("seed-secret"));
    assert_eq!(store.show(&run.run_id).unwrap().chain.head_seq, 3);
    assert_eq!(
        store.show(&run.run_id).unwrap().coverage["ledger"]["status"],
        "degraded"
    );
    assert_refused(
        store.append_source(&run.run_id, &source, &peer(), TOKEN),
        "record violates frozen jail-event schema",
    );
}

#[test]
fn settlement_requires_matching_final_receipt_and_trace_and_closes_observations() {
    let (_temp, mut store, run) = create();
    store
        .append_owner(
            &run.run_id,
            "admit",
            "admitted",
            None,
            &json!({"receipt":prepared(&run)}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let mut receipt: Value = serde_json::from_str(include_str!(
        "../../../../docs/specs/jail-v1/examples/receipt-tool.json"
    ))
    .unwrap();
    receipt["attempt_id"] = json!(run.attempt_id);
    let body =
        json!({"receipt":receipt,"outcome":receipt["outcome"],"coverage":receipt["coverage"]});
    assert_refused(
        store.append_owner(
            &run.run_id,
            "settle",
            "settled",
            None,
            &body,
            &peer(),
            TOKEN,
        ),
        "terminal trace and receipt do not corroborate",
    );
    let receipt_digest = records::semantic::receipt_digest(&receipt).unwrap();
    let event = serde_json::to_value(records::Event::receipt_note(
        &run.attempt_id,
        1,
        SystemTime::now(),
        1,
        records::Phase::Settled,
        &receipt_digest,
    ))
    .unwrap();
    store
        .append_source(&run.run_id, &event, &peer(), TOKEN)
        .unwrap();
    let settled = store
        .append_owner(
            &run.run_id,
            "settle",
            "settled",
            None,
            &body,
            &peer(),
            TOKEN,
        )
        .unwrap();
    assert_eq!(
        settled,
        store
            .append_owner(
                &run.run_id,
                "settle",
                "settled",
                None,
                &body,
                &peer(),
                TOKEN
            )
            .unwrap()
    );
    assert_eq!(store.show(&run.run_id).unwrap().state, "settled");
    let event = serde_json::to_value(records::Event::lifecycle_note(
        &run.attempt_id,
        2,
        SystemTime::now(),
        2,
        "after_settlement",
    ))
    .unwrap();
    assert_refused(
        store.append_source(&run.run_id, &event, &peer(), TOKEN),
        "terminal run cannot ingest new observations",
    );
}

#[test]
fn refused_receipt_requires_the_same_attempt_and_final_source_note() {
    let (_temp, mut store, run) = create();
    let mut receipt: Value = serde_json::from_str(include_str!(
        "../../../../docs/specs/jail-v1/examples/receipt-exec-refused.json"
    ))
    .unwrap();
    receipt["attempt_id"] = json!(run.attempt_id);
    let body =
        json!({"receipt":receipt,"outcome":receipt["outcome"],"coverage":receipt["coverage"]});
    assert_refused(
        store.append_owner(&run.run_id, "denied", "denied", None, &body, &peer(), TOKEN),
        "terminal trace and receipt do not corroborate",
    );
    let receipt_digest = records::semantic::receipt_digest(&receipt).unwrap();
    let event = serde_json::to_value(records::Event::receipt_note(
        &run.attempt_id,
        1,
        SystemTime::now(),
        1,
        records::Phase::Refused,
        &receipt_digest,
    ))
    .unwrap();
    store
        .append_source(&run.run_id, &event, &peer(), TOKEN)
        .unwrap();
    store
        .append_owner(&run.run_id, "denied", "denied", None, &body, &peer(), TOKEN)
        .unwrap();
    assert_eq!(store.show(&run.run_id).unwrap().state, "denied");
}

#[test]
fn source_exec_outcomes_do_not_become_the_run_outcome_on_ingress_or_recovery() {
    let (temp, mut store, run) = create();
    store
        .append_owner(
            &run.run_id,
            "admit",
            "admitted",
            None,
            &json!({"receipt":prepared(&run)}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let mut event: Value = serde_json::from_str(include_str!(
        "../../../../docs/specs/jail-v1/examples/event-exec.json"
    ))
    .unwrap();
    event["attempt_id"] = json!(run.attempt_id);
    event["source_seq"] = json!(1);
    store
        .append_source(&run.run_id, &event, &peer(), TOKEN)
        .unwrap();
    assert_eq!(store.show(&run.run_id).unwrap().state, "admitted");
    assert_eq!(store.show(&run.run_id).unwrap().outcome, None);
    let stored = fs::read_to_string(
        temp.path()
            .join("data/ledger")
            .join(&run.run_id)
            .join("events-0001.ndjson"),
    )
    .unwrap();
    let source: Value = serde_json::from_str(stored.lines().last().unwrap()).unwrap();
    assert_eq!(source["outcome"], event["outcome"]);
    drop(store);
    let recovered = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(recovered.show(&run.run_id).unwrap().outcome, None);
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn admitted_exec_failure_settles_only_with_a_correlated_verified_empty_attempt() {
    let (temp, mut store, run) = create();
    let mut receipt: Value = serde_json::from_str(include_str!(
        "../../../../docs/specs/jail-v1/examples/receipt-exec-refused.json"
    ))
    .unwrap();
    receipt["attempt_id"] = json!(run.attempt_id);
    receipt["outcome"]["cause"] = json!("ENOENT");
    let body = json!({"receipt":receipt,"coverage":receipt["coverage"]});
    // A known exec error cannot retroactively stand in for admission.
    assert_refused(
        store.append_owner(
            &run.run_id,
            "settle",
            "settled",
            None,
            &body,
            &peer(),
            TOKEN,
        ),
        "settlement requires durable admission",
    );
    store
        .append_owner(
            &run.run_id,
            "admit",
            "admitted",
            None,
            &json!({"receipt":prepared(&run)}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    for kind in ["denied", "settled"] {
        assert!(
            store
                .append_owner(&run.run_id, "settle", kind, None, &body, &peer(), TOKEN,)
                .is_err()
        );
    }
    let receipt_digest = records::semantic::receipt_digest(&receipt).unwrap();
    let event = serde_json::to_value(records::Event::receipt_note(
        &run.attempt_id,
        1,
        SystemTime::now(),
        1,
        records::Phase::Refused,
        &receipt_digest,
    ))
    .unwrap();
    store
        .append_source(&run.run_id, &event, &peer(), TOKEN)
        .unwrap();
    let ack = store
        .append_owner(
            &run.run_id,
            "settle",
            "settled",
            None,
            &body,
            &peer(),
            TOKEN,
        )
        .unwrap();
    assert_eq!(
        store
            .append_owner(
                &run.run_id,
                "settle",
                "settled",
                None,
                &body,
                &peer(),
                TOKEN
            )
            .unwrap(),
        ack
    );
    let record = store.show(&run.run_id).unwrap();
    assert_eq!(record.state, "settled");
    assert_eq!(record.outcome.unwrap()["cause"], "ENOENT");
    assert_eq!(record.receipts.last().unwrap()["phase"], "refused");
    assert!(store.verify(None).unwrap()[0].local_consistency);
    drop(store);
    let recovered = Store::open(&temp.path().join("data")).unwrap();
    let record = recovered.show(&run.run_id).unwrap();
    assert_eq!(record.state, "settled");
    assert_eq!(record.outcome.unwrap()["kind"], "exec_error");
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn admitted_refusal_cannot_settle_with_unproved_tree_policy_mismatch_or_source_loss() {
    for variant in [
        "refused",
        "unverified",
        "registered",
        "policy",
        "source_gap",
    ] {
        let (_temp, mut store, run) = create();
        store
            .append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                TOKEN,
            )
            .unwrap();
        let mut receipt: Value = serde_json::from_str(include_str!(
            "../../../../docs/specs/jail-v1/examples/receipt-exec-refused.json"
        ))
        .unwrap();
        receipt["attempt_id"] = json!(run.attempt_id);
        match variant {
            "refused" => receipt["outcome"]["kind"] = json!("refused"),
            "unverified" => {
                receipt["lifetime"]["tree_empty"] = Value::Null;
                receipt["lifetime"]["verified_at"] = Value::Null;
                receipt["lifetime"]["integrity"] = json!("lost");
            }
            "registered" => {
                receipt["lifetime"]["verification_scope"] = json!("registered_boundary");
            }
            "policy" => receipt["policy"]["digest"] = json!(format!("sha256:{}", "e".repeat(64))),
            _ => {}
        }
        let receipt_digest = records::semantic::receipt_digest(&receipt).unwrap();
        let event = serde_json::to_value(records::Event::receipt_note(
            &run.attempt_id,
            if variant == "source_gap" { 2 } else { 1 },
            SystemTime::now(),
            1,
            records::Phase::Refused,
            &receipt_digest,
        ))
        .unwrap();
        let appended = store.append_source(&run.run_id, &event, &peer(), TOKEN);
        assert_eq!(appended.is_err(), variant == "source_gap");
        let head = store.show(&run.run_id).unwrap().chain.head_seq;
        assert!(
            store
                .append_owner(
                    &run.run_id,
                    "settle",
                    "settled",
                    None,
                    &json!({"receipt":receipt}),
                    &peer(),
                    TOKEN
                )
                .is_err(),
            "accepted {variant}"
        );
        assert_eq!(store.show(&run.run_id).unwrap().state, "admitted");
        assert_eq!(store.show(&run.run_id).unwrap().chain.head_seq, head);
    }
}

#[test]
fn unresolved_run_keeps_a_proven_child_exit_separate_from_unknown_outcome() {
    let (_temp, mut store, run) = create();
    store
        .append_owner(
            &run.run_id,
            "unknown",
            "outcome_unknown",
            None,
            &json!({"outcome":{"kind":"exited","code":0}}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let record = store.show(&run.run_id).unwrap();
    let outcome = record.outcome.unwrap();
    assert_eq!(record.state, "outcome_unknown");
    assert_eq!(outcome["unknown"], true);
    assert_eq!(outcome["kind"], "unknown");
    assert_eq!(outcome["observed_child_outcome"]["code"], 0);
    assert_eq!(
        outcome["unknown_reason"],
        "owner or reconciliation reported an unresolved run outcome"
    );
}

#[test]
fn recovery_rechecks_admission_bindings_even_with_a_recomputed_local_chain() {
    let (temp, mut store, run) = create();
    store
        .append_owner(
            &run.run_id,
            "admit",
            "admitted",
            None,
            &json!({"receipt":prepared(&run)}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let path = store.root().join(&run.run_id).join(STREAM);
    let bytes = fs::read(&path).unwrap();
    let mut records: Vec<Value> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    records.last_mut().unwrap()["body"]["receipt"]["policy"]["digest"] =
        json!(format!("sha256:{}", "e".repeat(64)));
    let mut rewritten = Vec::new();
    for record in records {
        rewritten.extend(canonical(&record).unwrap());
        rewritten.push(b'\n');
    }
    fs::write(&path, &rewritten).unwrap();
    assert!(!store.verify(None).unwrap()[0].local_consistency);
    drop(store);
    let recovered = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(fs::read(&path).unwrap(), rewritten);
    assert_eq!(
        recovered.show(&run.run_id).unwrap().state,
        "outcome_unknown"
    );
    assert!(!recovered.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn verification_detects_projection_drift_and_recovery_rebuilds_it() {
    let (temp, store, run) = create();
    let projection = store.root().join(&run.run_id).join("run.json");
    fs::write(&projection, b"{}\n").unwrap();
    assert!(!store.verify(None).unwrap()[0].local_consistency);
    drop(store);
    let recovered = Store::open(&temp.path().join("data")).unwrap();
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
}
#[test]
fn recovery_keeps_unchanged_projections_and_manifests_in_place() {
    let (temp, store, run) = create();
    let directory = store.root().join(&run.run_id);
    let inode = |name: &str| fs::metadata(directory.join(name)).unwrap().ino();
    let before = (inode("run.json"), inode(manifest::NAME));
    drop(store);
    let recovered = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!((inode("run.json"), inode(manifest::NAME)), before);
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
    drop(recovered);
    fs::write(directory.join("run.json"), b"{}\n").unwrap();
    let recovered = Store::open(&temp.path().join("data")).unwrap();
    assert_ne!(
        inode("run.json"),
        before.0,
        "a changed projection is republished"
    );
    assert_eq!(inode(manifest::NAME), before.1);
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn a_failed_projection_write_leaves_no_temporary_file() {
    let (temp, mut store, run) = create();
    faults::arm(Plan::error(
        Scope::Note,
        Point::Replace(Replaced::Projection, Step::BeforeRename),
        temp.path().join("marker"),
    ));
    let refused = note(&mut store, &run, "unpublished", json!({"v":1}));
    faults::disarm();
    assert!(refused.is_err());
    let leftovers: Vec<_> = fs::read_dir(store.root().join(&run.run_id))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

fn segment_bytes(directory: &Path) -> Vec<u8> {
    manifest::names(directory)
        .unwrap()
        .iter()
        .flat_map(|name| fs::read(directory.join(name)).unwrap())
        .collect()
}

#[test]
fn rotation_preserves_exact_export_global_chain_and_original_replay_after_restart() {
    let (temp, mut store, run) = create();
    store.set_segment_limit(2048);
    let directory = store.root().join(&run.run_id);
    let initial = fs::read(directory.join(STREAM)).unwrap();
    let mut receipts = Vec::new();
    for i in 0..12 {
        let body = json!({"index":i,"padding":"€".repeat(300)});
        receipts.push(note(&mut store, &run, &format!("rotated-{i}"), body).unwrap());
    }
    let names = manifest::names(&directory).unwrap();
    assert!(names.len() > 3);
    assert_eq!(fs::read(directory.join(STREAM)).unwrap(), initial);
    let canonical = segment_bytes(&directory);
    let mut previous = None;
    for (i, frame) in canonical
        .split(|b| *b == b'\n')
        .filter(|f| !f.is_empty())
        .enumerate()
    {
        let record: Value = serde_json::from_slice(frame).unwrap();
        assert_eq!(record["seq"], i + 1);
        assert_eq!(record["prev"], json!(previous));
        previous = Some(sha256_prefixed(frame));
    }
    let anchored = fs::read(directory.join(manifest::NAME)).unwrap();
    assert!(store.verify(None).unwrap()[0].local_consistency);
    drop(store);
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    for (i, receipt) in receipts.iter().enumerate() {
        assert_eq!(
            *receipt,
            note(
                &mut recovered,
                &run,
                &format!("rotated-{i}"),
                json!({"index":i,"padding":"€".repeat(300)})
            )
            .unwrap()
        );
    }
    let (pages, exported) = read_all(
        &mut recovered,
        read_request(&run, crate::protocol::ReadSelector::All),
    );
    assert_eq!(exported.as_bytes(), canonical);
    assert!(pages.iter().all(|page| page.local_consistency));
    assert_eq!(fs::read(directory.join(manifest::NAME)).unwrap(), anchored);
    assert_eq!(segment_bytes(&directory), canonical);
    // Request/effect identities are global, not scoped to a file.
    assert_refused(
        note(&mut recovered, &run, "rotated-0", json!({"changed":true})),
        "request id conflicts with its immutable payload",
    );
}

#[test]
fn rotation_failure_boundaries_never_duplicate_or_truncate_history() {
    for fault in [
        Point::RotationCreated,
        Point::RotationSynced,
        Point::EventBeforeWrite,
        Point::EventPartialWrite,
        Point::EventBeforeSync,
        Point::Replace(Replaced::Projection, Step::BeforeWrite),
        Point::Replace(Replaced::Manifest, Step::BeforeWrite),
        Point::AppendBeforeDirectorySync,
    ] {
        let (temp, mut store, run) = create();
        store.set_segment_limit(1);
        let directory = store.root().join(&run.run_id);
        let first = fs::read(directory.join(STREAM)).unwrap();
        faults::arm(Plan::fail(fault));
        assert!(note(&mut store, &run, "rotation-fault", json!({"v":1})).is_err());
        faults::disarm();
        assert_refused(
            note(&mut store, &run, "different", json!({})),
            "stream is poisoned; no dependent dispatch or sequence reuse",
        );
        let second = directory.join(manifest::name(2));
        let before = fs::read(&second).unwrap();
        let original_receipt = before.strip_suffix(b"\n").map(|frame| {
            let record: Value = serde_json::from_slice(frame).unwrap();
            AppendReceipt {
                seq: record["seq"].as_u64().unwrap(),
                digest: sha256_prefixed(frame),
            }
        });
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(fs::read(directory.join(STREAM)).unwrap(), first);
        assert_eq!(fs::read(&second).unwrap(), before);
        if matches!(fault, Point::EventPartialWrite) {
            assert!(!recovered.verify(None).unwrap()[0].local_consistency);
            assert_refused(
                note(&mut recovered, &run, "rotation-fault", json!({"v":1})),
                "stream is poisoned; no dependent dispatch or sequence reuse",
            );
            assert_refused(
                recovered.prepare("new", &payload(), &peer()),
                "ambiguous recovery blocks new preparation; inspect verify",
            );
            continue;
        }
        let receipt = note(&mut recovered, &run, "rotation-fault", json!({"v":1})).unwrap();
        if let Some(original) = original_receipt {
            assert_eq!(receipt, original);
        }
        assert_eq!(
            receipt,
            note(&mut recovered, &run, "rotation-fault", json!({"v":1})).unwrap()
        );
        assert_eq!(receipt.seq, 3);
        assert_eq!(
            fs::read(&second)
                .unwrap()
                .iter()
                .filter(|&&b| b == b'\n')
                .count(),
            1
        );
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }
}

#[test]
fn rotation_recovery_syncs_each_segment_before_publishing_promoted_metadata() {
    let (temp, mut store, run) = create();
    store.set_segment_limit(1);
    let directory = store.root().join(&run.run_id);
    note(&mut store, &run, "sealed", json!({})).unwrap();
    let old = fs::read(directory.join(manifest::NAME)).unwrap();
    faults::arm(Plan::fail(Point::EventBeforeSync));
    assert!(note(&mut store, &run, "tail", json!({})).is_err());
    faults::disarm();
    let before = segment_bytes(&directory);
    drop(store);
    for failing_segment in 1..=3 {
        let seen = std::cell::Cell::new(0);
        assert!(
            Store::open_with_recovery_sync(&temp.path().join("data"), |_| {
                let n = seen.get() + 1;
                seen.set(n);
                assert_eq!(fs::read(directory.join(manifest::NAME)).unwrap(), old);
                if n == failing_segment {
                    Err(std::io::Error::from_raw_os_error(libc::EIO))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(seen.get(), failing_segment);
        assert_eq!(segment_bytes(&directory), before);
        assert_eq!(fs::read(directory.join(manifest::NAME)).unwrap(), old);
    }
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(
        note(&mut recovered, &run, "tail", json!({})).unwrap().seq,
        4
    );
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn rotated_streams_refuse_missing_changed_reordered_and_unanchored_segments() {
    for damage in [
        "missing-middle",
        "missing-last",
        "swap",
        "changed",
        "sealed-tail",
        "manifest-order",
        "no-manifest",
        "extra-empty",
        "symlink",
    ] {
        let (temp, mut store, run) = create();
        store.set_segment_limit(1);
        let directory = store.root().join(&run.run_id);
        note(&mut store, &run, "one", json!({"v":"original"})).unwrap();
        note(&mut store, &run, "two", json!({"v":"original"})).unwrap();
        drop(store);
        let second = directory.join(manifest::name(2));
        let third = directory.join(manifest::name(3));
        match damage {
            "missing-middle" => fs::remove_file(&second).unwrap(),
            "missing-last" => fs::remove_file(&third).unwrap(),
            "swap" => {
                let a = fs::read(&second).unwrap();
                let b = fs::read(&third).unwrap();
                fs::write(&second, b).unwrap();
                fs::write(&third, a).unwrap();
            }
            "changed" => fs::write(
                &second,
                fs::read_to_string(&second)
                    .unwrap()
                    .replace("original", "modified"),
            )
            .unwrap(),
            "sealed-tail" => {
                OpenOptions::new()
                    .append(true)
                    .open(&second)
                    .unwrap()
                    .write_all(b"\n")
                    .unwrap();
            }
            "manifest-order" => {
                let path = directory.join(manifest::NAME);
                let mut m: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                m["segments"].as_array_mut().unwrap().swap(0, 1);
                let mut bytes = canonical(&m).unwrap();
                bytes.push(b'\n');
                fs::write(path, bytes).unwrap();
            }
            "no-manifest" => fs::remove_file(directory.join(manifest::NAME)).unwrap(),
            "extra-empty" => {
                private_file(
                    &directory.join(manifest::name(4)),
                    OpenOptions::new().create(true),
                )
                .unwrap();
                private_file(
                    &directory.join(manifest::name(5)),
                    OpenOptions::new().create(true),
                )
                .unwrap();
            }
            "symlink" => {
                fs::remove_file(&second).unwrap();
                std::os::unix::fs::symlink(&third, &second).unwrap();
            }
            _ => unreachable!(),
        }
        let before: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("events-")
            })
            .map(|p| {
                let bytes = fs::read(&p).unwrap();
                (p, bytes)
            })
            .collect();
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert!(
            !recovered.verify(None).unwrap()[0].local_consistency,
            "{damage}"
        );
        assert_eq!(
            recovered.show(&run.run_id).unwrap().state,
            "outcome_unknown",
            "{damage}"
        );
        assert!(
            note(&mut recovered, &run, "new", json!({})).is_err(),
            "{damage}"
        );
        assert!(
            recovered.prepare("new", &payload(), &peer()).is_err(),
            "{damage}"
        );
        for (path, bytes) in before {
            assert_eq!(fs::read(path).unwrap(), bytes, "{damage}");
        }
    }
}

#[test]
fn reader_snapshot_and_lost_reply_survive_rotation_with_partial_utf8_export() {
    let (temp, mut store, run) = create();
    store.set_segment_limit(16_384);
    let directory = store.root().join(&run.run_id);
    note(&mut store, &run, "large", json!({"v":"€".repeat(90_000)})).unwrap();
    note(&mut store, &run, "last", json!({"v":3})).unwrap();
    let expected = String::from_utf8(segment_bytes(&directory)).unwrap();
    let mut request = read_request(&run, crate::protocol::ReadSelector::All);
    request.limit = 1;
    let first = store.read(&request).unwrap();
    request.cursor = first.next_cursor.clone();
    let retry_request = request.clone();
    let second = store.read(&request).unwrap();
    assert!(!second.done);
    note(&mut store, &run, "later", json!({"v":"x".repeat(20_000)})).unwrap();
    drop(store);
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(recovered.read(&retry_request).unwrap(), second);
    request.cursor = second.next_cursor.clone();
    let (pages, rest) = read_all(&mut recovered, request);
    assert_eq!(format!("{}{}{rest}", first.ndjson, second.ndjson), expected);
    assert!(
        pages
            .iter()
            .all(|p| p.snapshot == first.snapshot && p.local_consistency)
    );
    assert!(recovered.show(&run.run_id).unwrap().chain.head_seq > first.snapshot.head_seq);
}

#[test]
fn reader_cursor_refuses_replaced_later_segment_after_restart() {
    let (temp, mut store, run) = create();
    store.set_segment_limit(1);
    note(
        &mut store,
        &run,
        "second-file",
        json!({"v":"x".repeat(100_000)}),
    )
    .unwrap();
    let mut request = read_request(&run, crate::protocol::ReadSelector::All);
    request.limit = 1;
    request.cursor = store.read(&request).unwrap().next_cursor;
    let path = store.root().join(&run.run_id).join(manifest::name(2));
    let bytes = fs::read(&path).unwrap();
    drop(store);
    fs::rename(&path, path.with_extension("old")).unwrap();
    // Keep the old inode allocated but outside the canonical namespace.
    fs::rename(path.with_extension("old"), temp.path().join("old-segment")).unwrap();
    private_file(&path, OpenOptions::new().create(true))
        .unwrap()
        .write_all(&bytes)
        .unwrap();
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    assert!(recovered.verify(None).unwrap()[0].local_consistency);
    assert_refused(
        recovered.read(&request),
        "reader canonical snapshot is corrupt: identity or length changed",
    );
}

#[test]
fn legacy_manifest_and_reader_checkpoint_migrate_before_rotation() {
    let (temp, mut store, run) = create();
    note(
        &mut store,
        &run,
        "legacy-large",
        json!({"v":"x".repeat(100_000)}),
    )
    .unwrap();
    let directory = store.root().join(&run.run_id);
    let mut request = read_request(&run, crate::protocol::ReadSelector::All);
    request.limit = 1;
    let first = store.read(&request).unwrap();
    request.cursor = first.next_cursor;
    let checkpoint = store
        .root()
        .join("readers")
        .join(format!("{}.json", &request.cursor.as_ref().unwrap()[..32]));
    let mut envelope: Value = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
    envelope["checkpoint"]["schema"] = json!("ouro.ledger.reader-checkpoint/1");
    envelope["checkpoint"]
        .as_object_mut()
        .unwrap()
        .remove("segments_digest");
    envelope["digest"] = json!(digest(&envelope["checkpoint"]).unwrap());
    fs::write(&checkpoint, canonical(&envelope).unwrap()).unwrap();
    let path = directory.join(manifest::NAME);
    let mut m: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let segments = m.as_object_mut().unwrap().remove("segments").unwrap();
    m["segment"] = segments[0].clone();
    m["schema"] = json!("ouro.ledger.segments/1");
    let mut bytes = canonical(&m).unwrap();
    bytes.push(b'\n');
    fs::write(&path, bytes).unwrap();
    let original = fs::read(directory.join(STREAM)).unwrap();
    drop(store);
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    recovered.set_segment_limit(1);
    note(&mut recovered, &run, "rotate", json!({})).unwrap();
    let page = recovered.read(&request).unwrap();
    assert_eq!(page.snapshot.head_seq, 3);
    assert!(page.local_consistency);
    assert_eq!(fs::read(directory.join(STREAM)).unwrap(), original);
    let m: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(m["schema"], "ouro.ledger.segments/2");
    assert_eq!(m["segments"].as_array().unwrap().len(), 2);
}
#[test]
fn rotated_queries_preserve_source_filters_and_effect_identity() {
    use crate::protocol::ReadSelector;
    let (temp, mut store, run) = create();
    store.set_segment_limit(1);
    let effect = store
        .append_owner(
            &run.run_id,
            "effect-request",
            "note",
            Some("effect-stable"),
            &json!({"v":1}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    source_fixture(&mut store, &run, "exec", 1, None);
    source_fixture(&mut store, &run, "path", 2, Some("one"));
    source_fixture(&mut store, &run, "host", 3, None);
    source_fixture(&mut store, &run, "path", 4, Some("two"));
    let mut request = read_request(&run, ReadSelector::Paths);
    request.limit = 1;
    let first = store.read(&request).unwrap();
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.records[0]["fields"]["path"]["value"], "one");
    request.cursor = first.next_cursor;
    drop(store);
    let mut recovered = Store::open(&temp.path().join("data")).unwrap();
    let (pages, _) = read_all(&mut recovered, request);
    let records: Vec<_> = pages.iter().flat_map(|p| &p.records).collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["fields"]["path"]["value"], "two");
    assert_eq!(
        recovered
            .append_owner(
                &run.run_id,
                "effect-request",
                "note",
                Some("effect-stable"),
                &json!({"v":1}),
                &peer(),
                TOKEN
            )
            .unwrap(),
        effect
    );
    assert_refused(
        recovered.append_owner(
            &run.run_id,
            "new-request",
            "note",
            Some("effect-stable"),
            &json!({"v":1}),
            &peer(),
            TOKEN,
        ),
        "effect id conflicts with its immutable payload",
    );
    for selector in [ReadSelector::Execs, ReadSelector::Hosts] {
        let (pages, _) = read_all(&mut recovered, read_request(&run, selector));
        assert_eq!(pages.iter().map(|p| p.records.len()).sum::<usize>(), 1);
        assert!(pages.iter().all(|p| p.local_consistency));
    }
}
