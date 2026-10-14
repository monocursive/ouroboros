use super::*;
use crate::{
    faults::{self, Plan, Point, Scope},
    pending::Journal,
    test_support::{TOKEN, peer, prepared_receipt, request},
};

/// An admitted best-effort run whose owner wrote an empty pending journal.
fn admitted_with_journal(name: &str) -> (tempfile::TempDir, Store, RunRecord) {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let mut plan = request();
    plan["evidence"] = json!("best-effort");
    let run = store.prepare(name, &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    let mut receipt = prepared_receipt();
    receipt["attempt_id"] = json!(run.attempt_id);
    store
        .append_owner(
            &run.run_id,
            "admission",
            "admitted",
            None,
            &json!({"receipt":receipt}),
            &peer(),
            TOKEN,
        )
        .unwrap();
    let run = store.show(&run.run_id).unwrap();
    Journal::open(&store.run_dir(&run.run_id))
        .unwrap()
        .create(&run, &peer())
        .unwrap();
    (temp, store, run)
}

#[test]
fn a_journal_the_system_could_not_open_or_sync_is_not_refused() {
    // A member the kernel will not open as a file (EISDIR) is an operating
    // system failure, not a verdict on the journal's content.
    let (_temp, mut store, run) = admitted_with_journal("pending-eisdir");
    let lock = store.run_dir(&run.run_id).join("owner-pending.lock");
    fs::remove_file(&lock).unwrap();
    fs::create_dir(&lock).unwrap();
    match store.reconcile(&run.run_id, &peer(), &|_| false) {
        Err(PendingFailure::Other(error)) => {
            assert!(matches!(error.kind(), crate::protocol::ErrorKind::Io(_)));
        }
        Err(PendingFailure::Refused(class, error)) => {
            panic!("an I/O failure was recorded as {class:?}: {error}")
        }
        Ok(run) => panic!("reconciled through an unopenable journal: {run:?}"),
    }
    fs::remove_dir(&lock).unwrap();
    // So is a failed durability barrier while the journal is read.
    let (temp, mut store, run) = admitted_with_journal("pending-eio");
    faults::arm(Plan::error(
        Scope::PendingRead,
        Point::JournalReadBeforeFileSync,
        temp.path().join("marker"),
    ));
    let result = store.reconcile(&run.run_id, &peer(), &|_| false);
    faults::disarm();
    assert!(temp.path().join("marker").exists());
    match result {
        Err(PendingFailure::Other(_)) => {}
        Err(PendingFailure::Refused(class, error)) => {
            panic!("a failed sync was recorded as {class:?}: {error}")
        }
        Ok(run) => panic!("reconciled past a failed sync: {run:?}"),
    }
    assert_eq!(store.show(&run.run_id).unwrap().state, "admitted");
}

#[test]
fn a_journal_that_does_not_decode_is_refused_as_unreadable() {
    let (_temp, mut store, run) = admitted_with_journal("pending-garbage");
    fs::write(
        store.run_dir(&run.run_id).join(crate::pending::STATE),
        b"{\"damaged\":true}",
    )
    .unwrap();
    assert!(matches!(
        store.reconcile(&run.run_id, &peer(), &|_| false),
        Err(PendingFailure::Refused(
            PendingRefusal::JournalUnreadable,
            _
        ))
    ));
}
