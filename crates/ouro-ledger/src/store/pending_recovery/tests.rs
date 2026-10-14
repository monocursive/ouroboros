use std::fs;

use serde_json::{Value, json};

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
    let run = admit_with_journal(&mut store, name);
    (temp, store, run)
}

/// Such a run, in `store`.
fn admit_with_journal(store: &mut Store, name: &str) -> RunRecord {
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
    run
}

#[test]
fn journal_files_the_kernel_keeps_refusing_are_unreadable_not_retried_forever() {
    use std::os::unix::fs::PermissionsExt as _;
    type Damage = fn(&std::path::Path, &std::path::Path);
    let cases: [(&str, Damage); 5] = [
        // EISDIR, whether at the lock or at the journal itself.
        ("lock-directory", |run, _| {
            fs::remove_file(run.join("owner-pending.lock")).unwrap();
            fs::create_dir(run.join("owner-pending.lock")).unwrap();
        }),
        ("state-directory", |run, _| {
            fs::remove_file(run.join(crate::pending::STATE)).unwrap();
            fs::create_dir(run.join(crate::pending::STATE)).unwrap();
        }),
        // EACCES: owner-only, so every privacy check passes, yet unreadable.
        ("state-unreadable", |run, _| {
            fs::set_permissions(
                run.join(crate::pending::STATE),
                fs::Permissions::from_mode(0o000),
            )
            .unwrap();
        }),
        // ENXIO: a socket where the journal belongs. Bound under a short
        // path, since a run directory can exceed a socket path's limit.
        ("state-socket", |run, scratch| {
            let socket = scratch.join("s");
            std::os::unix::net::UnixListener::bind(&socket).unwrap();
            fs::remove_file(run.join(crate::pending::STATE)).unwrap();
            fs::rename(&socket, run.join(crate::pending::STATE)).unwrap();
        }),
        // ELOOP: a symlink where the journal belongs.
        ("state-symlink", |run, scratch| {
            fs::rename(run.join(crate::pending::STATE), scratch.join("moved")).unwrap();
            std::os::unix::fs::symlink(scratch.join("moved"), run.join(crate::pending::STATE))
                .unwrap();
        }),
    ];
    for (name, damage) in cases {
        if name == "state-unreadable" && crate::fsx::euid() == 0 {
            continue;
        }
        let (temp, mut store, run) = admitted_with_journal(name);
        let scratch = tempfile::tempdir_in(temp.path()).unwrap();
        damage(&store.run_dir(&run.run_id), scratch.path());
        match store.reconcile(&run.run_id, &peer(), &|_| false) {
            Err(PendingFailure::Refused(PendingRefusal::JournalUnreadable, _)) => {}
            Err(PendingFailure::Refused(class, error)) => panic!("{name}: {class:?}: {error}"),
            Err(PendingFailure::Other(error)) => {
                panic!("{name}: retried as if it could pass: {error}")
            }
            Ok(run) => panic!("{name}: reconciled: {run:?}"),
        }
        // The orphan is settled as unknown, saying why, instead of failing
        // settle-orphans on every attempt.
        store.settle_orphans(&peer(), |_| false).unwrap();
        let settled = store.show(&run.run_id).unwrap();
        assert_eq!(settled.state, "outcome_unknown", "{name}");
        let path = store.run_dir(&run.run_id).join(crate::manifest::STREAM);
        let last = fs::read_to_string(path).unwrap();
        let last: Value = serde_json::from_str(last.lines().last().unwrap()).unwrap();
        assert_eq!(last["body"]["refusal"], "journal_unreadable", "{name}");
    }
}

#[test]
fn only_a_momentary_shortage_of_the_system_is_not_the_journals_doing() {
    let failure =
        |errno| PendingFailure::unreadable(std::io::Error::from_raw_os_error(errno).into());
    for errno in [
        libc::EMFILE,
        libc::ENFILE,
        libc::ENOMEM,
        libc::ENOLCK,
        libc::ENOSPC,
        libc::EDQUOT,
        libc::EINTR,
        libc::EAGAIN,
    ] {
        assert!(
            matches!(failure(errno), PendingFailure::Other(_)),
            "{errno}"
        );
    }
    for errno in [
        libc::EACCES,
        libc::EPERM,
        libc::EISDIR,
        libc::ENXIO,
        libc::ELOOP,
        libc::EIO,
    ] {
        assert!(
            matches!(
                failure(errno),
                PendingFailure::Refused(PendingRefusal::JournalUnreadable, _)
            ),
            "{errno}"
        );
    }
    assert!(matches!(
        PendingFailure::unreadable(LedgerError::refused("not a journal")),
        PendingFailure::Refused(PendingRefusal::JournalUnreadable, _)
    ));
}

#[test]
fn a_failed_durability_barrier_is_not_the_journals_doing() {
    for point in [
        Point::JournalReadBeforeFileSync,
        Point::JournalReadBeforeDirectorySync,
    ] {
        let (temp, mut store, run) = admitted_with_journal("pending-eio");
        faults::arm(Plan::error(
            Scope::PendingRead,
            point,
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

#[test]
fn settling_orphans_skips_a_run_it_cannot_reconcile_now_and_settles_the_rest() {
    // A dead owner's journal whose lock another open description holds.
    let (_temp, mut store, stuck) = admitted_with_journal("pending-stuck");
    let _held = Journal::open(&store.run_dir(&stuck.run_id)).unwrap();
    // Dead owners without journals, at least one after it in settlement order.
    let mut settled = Vec::new();
    while !settled.iter().any(|id: &String| *id > stuck.run_id) {
        let run = store
            .prepare(&format!("orphan-{}", settled.len()), &request(), &peer())
            .unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        settled.push(run.run_id);
        assert!(settled.len() < 64);
    }
    let refusal = store.settle_orphans(&peer(), |_| false).unwrap_err();
    assert!(
        refusal.message().starts_with(&format!(
            "{}: pending evidence could not be reconciled now: ",
            stuck.run_id
        )),
        "{refusal}"
    );
    assert!(
        refusal
            .message()
            .ends_with(&format!("; {} other orphans were settled", settled.len())),
        "{refusal}"
    );
    // Nothing is recorded for the run that could not be reconciled now.
    let unchanged = store.show(&stuck.run_id).unwrap();
    assert_eq!(unchanged.state, "admitted");
    assert_eq!(unchanged.chain, stuck.chain);
    for id in settled {
        assert_eq!(store.show(&id).unwrap().state, "outcome_unknown");
    }
}

#[test]
fn settling_orphans_records_every_other_run_when_recording_one_fails() {
    use std::os::unix::fs::PermissionsExt as _;
    if crate::fsx::euid() == 0 {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    // Two orphans whose records cannot be published: a refused journal's
    // unknown outcome, and a lost owner's. Their run directories accept no
    // new entry, so each append fails after its record reaches the segment.
    let refused = admit_with_journal(&mut store, "refused");
    let journal = store.run_dir(&refused.run_id).join(crate::pending::STATE);
    fs::write(journal, b"{\"damaged\":true}").unwrap();
    let lost = store.prepare("lost", &request(), &peer()).unwrap();
    store.claim_owner(&lost.run_id, &peer()).unwrap();
    let failing = [refused.run_id.clone(), lost.run_id.clone()];
    for id in &failing {
        fs::set_permissions(store.run_dir(id), fs::Permissions::from_mode(0o500)).unwrap();
    }
    // Orphans that can be settled, at least one after a failing run.
    let first = failing.iter().min().unwrap().clone();
    let mut settled = Vec::new();
    while !settled.iter().any(|id: &String| *id > first) {
        let run = store
            .prepare(&format!("orphan-{}", settled.len()), &request(), &peer())
            .unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        settled.push(run.run_id);
        assert!(settled.len() < 64);
    }
    let failure = store.settle_orphans(&peer(), |_| false).unwrap_err();
    for id in &failing {
        fs::set_permissions(store.run_dir(id), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let message = failure.message();
    assert!(
        message.contains(&format!(
            "{}: recording why its pending evidence was refused failed: ",
            refused.run_id
        )),
        "{message}"
    );
    assert!(
        message.contains(&format!(
            "{}: recording its lost owner failed: ",
            lost.run_id
        )),
        "{message}"
    );
    assert!(
        message.ends_with(&format!("; {} other orphans were settled", settled.len())),
        "{message}"
    );
    for id in settled {
        assert_eq!(store.show(&id).unwrap().state, "outcome_unknown");
    }
}

/// A wrapper note at `seq` saying `message`.
fn note(run: &RunRecord, seq: u64, message: &str) -> Value {
    serde_json::to_value(records::Event::lifecycle_note(
        &run.attempt_id,
        seq,
        std::time::SystemTime::UNIX_EPOCH,
        seq.into(),
        message,
    ))
    .unwrap()
}

/// Queue `event` in the run's pending journal, as an owner in a writer
/// outage would.
fn journal_event(store: &Store, run: &RunRecord, event: Value) {
    let journal = Journal::open(&store.run_dir(&run.run_id)).unwrap();
    let mut state = journal.read(run).unwrap();
    state.push(event).unwrap();
    journal.save(&state).unwrap();
}

#[test]
fn pending_evidence_history_refuses_is_the_journals_refusal() {
    let (_temp, mut store, run) = admitted_with_journal("pending-conflict");
    store
        .append_source(&run.run_id, &note(&run, 1, "accepted"), &peer(), TOKEN)
        .unwrap();
    // The journal claims the same producer sequence for other evidence.
    journal_event(&store, &run, note(&run, 1, "conflicting"));
    match store.reconcile(&run.run_id, &peer(), &|_| false) {
        Err(PendingFailure::Refused(PendingRefusal::EvidenceRefused, _)) => {}
        Err(PendingFailure::Refused(class, error)) => panic!("refused as {class:?}: {error}"),
        Err(PendingFailure::Other(error)) => panic!("not the journal's refusal: {error}"),
        Ok(run) => panic!("reconciled conflicting evidence: {run:?}"),
    }
    assert!(!store.stream(&run.run_id).unwrap().is_poisoned());
}

#[test]
fn pending_evidence_the_store_failed_to_persist_is_not_the_journals_refusal() {
    let (temp, mut store, run) = admitted_with_journal("pending-persist");
    journal_event(&store, &run, note(&run, 1, "pending"));
    let marker = temp.path().join("marker");
    faults::arm(Plan::error(
        Scope::Source,
        Point::EventBeforeWrite,
        marker.clone(),
    ));
    let result = store.reconcile(&run.run_id, &peer(), &|_| false);
    faults::disarm();
    assert!(marker.exists());
    match result {
        Err(PendingFailure::Other(_)) => {}
        Err(PendingFailure::Refused(class, error)) => {
            panic!("a persistence failure was refused as {class:?}: {error}")
        }
        Ok(run) => panic!("reconciled past a failed append: {run:?}"),
    }
    assert!(store.stream(&run.run_id).unwrap().is_poisoned());
}
