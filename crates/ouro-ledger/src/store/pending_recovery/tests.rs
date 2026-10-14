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

#[test]
fn journal_text_reaches_the_operator_log_with_control_characters_spelled_out() {
    let (_temp, mut store, run) = admitted_with_journal("pending-log");
    // A journal key decoding quotes verbatim: a newline that would start a
    // forged log line, and an escape sequence that clears the terminal.
    fs::write(
        store.run_dir(&run.run_id).join(crate::pending::STATE),
        b"{\"evil\\nouro-ledger: FORGED\\u001b[2J\":1,\"state\":{},\"digest\":\"x\"}",
    )
    .unwrap();
    let refusal = store
        .reconcile_pending(&run.run_id, &peer(), &|_| false)
        .unwrap_err();
    assert!(refusal.message().contains('\n'), "{refusal:?}");
    let line = log_line(
        format_args!("pending recovery for {}", run.run_id),
        &refusal,
    );
    assert!(!line.contains('\n') && !line.contains('\u{1b}'), "{line:?}");
    assert!(
        line.contains("<U+000A>ouro-ledger: FORGED<U+001B>[2J"),
        "{line}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_failure_that_is_not_the_journals_backs_off_and_is_logged_once() {
    use std::time::Duration;
    let (_temp, mut store, run) = admitted_with_journal("pending-stuck");
    // The fixture owner is not this process: it is dead. Its journal's
    // temporary name is a directory, so removing the journal fails (EISDIR)
    // on every attempt, after its evidence is recorded.
    fs::create_dir(store.run_dir(&run.run_id).join("owner-pending.next")).unwrap();
    let start = std::time::Instant::now();
    let first = store.recover_pending_orphans_at(&peer(), start);
    assert_eq!(first.len(), 1, "{first:?}");
    let failed = |store: &mut Store| match store.failed_journals().get(&run.run_id) {
        Some(Failed::Other { retry_at, wait, .. }) => (*retry_at, *wait),
        other => panic!("not backing off: {other:?}"),
    };
    assert_eq!(
        failed(&mut store),
        (start + FIRST_RETRY_WAIT, FIRST_RETRY_WAIT)
    );
    // Not due yet: nothing is attempted.
    assert!(
        store
            .recover_pending_orphans_at(&peer(), start + Duration::from_secs(1))
            .is_empty()
    );
    assert_eq!(
        failed(&mut store),
        (start + FIRST_RETRY_WAIT, FIRST_RETRY_WAIT)
    );
    // Due: attempted again, the wait doubles, and the unchanged failure is
    // not logged a second time.
    let later = start + FIRST_RETRY_WAIT;
    assert!(store.recover_pending_orphans_at(&peer(), later).is_empty());
    assert_eq!(
        failed(&mut store),
        (later + 2 * FIRST_RETRY_WAIT, 2 * FIRST_RETRY_WAIT)
    );
    // The wait never exceeds its bound.
    let mut now = later;
    for _ in 0..16 {
        now += MAX_RETRY_WAIT;
        store.recover_pending_orphans_at(&peer(), now);
    }
    assert_eq!(failed(&mut store).1, MAX_RETRY_WAIT);
    assert_eq!(store.show(&run.run_id).unwrap().state, "outcome_unknown");
}
