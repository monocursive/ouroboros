//! The writer: its lock, acknowledgements, replay, poison and recovery.
use super::*;
use crate::protocol::StreamStatus;

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
        assert_eq!(
            poison_status(&poison(&kinds)),
            Some(StreamStatus::Corrupt),
            "{kinds:?}"
        );
    }
    assert_eq!(
        poison_status(&poison(&[PoisonKind::Incomplete])),
        Some(StreamStatus::Incomplete)
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
