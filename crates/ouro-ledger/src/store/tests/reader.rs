//! Bounded readers and their durable checkpoints.
use super::*;

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
