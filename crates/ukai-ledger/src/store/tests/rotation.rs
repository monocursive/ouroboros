//! Segment rotation, and readers across rotated segments.
use super::*;

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
    envelope["checkpoint"]["schema"] = json!("ukai.ledger.reader-checkpoint/1");
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
    m["schema"] = json!("ukai.ledger.segments/1");
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
    assert_eq!(m["schema"], "ukai.ledger.segments/2");
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
