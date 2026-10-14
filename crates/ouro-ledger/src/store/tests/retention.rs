//! Holds, retention previews, capture expiry and whole-run GC.
use super::*;

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
