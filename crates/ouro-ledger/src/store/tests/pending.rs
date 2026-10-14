//! Reconciling dead owners' pending journals through the store.
use super::*;

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
