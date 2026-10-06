use super::*;
use crate::protocol::{OperatorIntent, READ_CHUNK_BYTES, TailRequest};

fn peer() -> Peer {
    Peer {
        uid: unsafe { libc::geteuid() },
        pid: std::process::id(),
        birth: "test-birth".into(),
        boot_id: "test-boot".into(),
    }
}
fn create() -> (tempfile::TempDir, Store, RunRecord) {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let payload = serde_json::from_str(include_str!(
        "../../../../docs/specs/ledger-v1/fixtures/request.json"
    ))
    .unwrap();
    let run = store.prepare("prepare-1", &payload, &peer()).unwrap();
    (temp, store, run)
}
fn intent(run: &RunRecord, request: &str, kind: &str, effect: Option<&str>) -> OperatorIntent {
    OperatorIntent {
        run_id: run.run_id.clone(),
        request_id: request.into(),
        kind: kind.into(),
        effect_id: effect.map(str::to_owned),
        body: json!({"message":"explicit operator assertion"}),
    }
}
fn bytes(store: &Store, run: &RunRecord) -> Vec<u8> {
    let directory = store.root.join(&run.run_id);
    manifest::names(&directory)
        .unwrap()
        .iter()
        .flat_map(|n| fs::read(directory.join(n)).unwrap())
        .collect()
}

#[test]
fn operator_effects_replay_without_claiming_launch_state_or_observation() {
    let (temp, mut store, run) = create();
    let admitted = intent(&run, "decision-1", "admitted", Some("effect-1"));
    let receipt = store.append_operator(&admitted, &peer()).unwrap();
    let settled = intent(&run, "decision-2", "settled", Some("effect-1"));
    store.append_operator(&settled, &peer()).unwrap();
    assert_eq!(store.append_operator(&admitted, &peer()).unwrap(), receipt);
    let shown = store.show(&run.run_id).unwrap();
    assert_eq!(shown.state, run.state);
    assert_eq!(shown.owner, None);
    assert_eq!(shown.outcome, None);
    assert_eq!(shown.coverage, run.coverage);
    assert_eq!(shown.child_protection, "unprotected");
    let records = bytes(&store, &run);
    let event: Value =
        serde_json::from_slice(records.split(|b| *b == b'\n').nth(1).unwrap()).unwrap();
    assert_eq!(event["kind"], "operator_intent");
    assert_eq!(event["body"]["fields"], admitted.body);
    assert_eq!(event["provenance"]["role"], "operator");
    assert!(event["provenance"]["token_id"].is_null());
    assert_eq!(event["provenance"]["peer_pid"], std::process::id());
    assert!(
        store
            .append_operator(
                &intent(&run, "new-id", "admitted", Some("effect-1")),
                &peer()
            )
            .is_err()
    );
    let mut conflict = admitted.clone();
    conflict.body = json!({"changed":true});
    assert!(store.append_operator(&conflict, &peer()).is_err());
    drop(store);
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(store.append_operator(&admitted, &peer()).unwrap(), receipt);
    assert_eq!(bytes(&store, &run), records);
    assert!(store.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn operator_forgery_conflicts_and_unadmitted_settlement_refuse() {
    let (_temp, mut store, run) = create();
    for kind in [
        "prepared",
        "owner_claimed",
        "source",
        "hold",
        "outcome_unknown",
    ] {
        assert!(
            store
                .append_operator(&intent(&run, "bad", kind, Some("e")), &peer())
                .is_err()
        );
    }
    for kind in ["admitted", "denied", "settled"] {
        assert!(
            store
                .append_operator(&intent(&run, "bad", kind, None), &peer())
                .is_err()
        );
    }
    for key in [
        "actor",
        "role",
        "provenance",
        "run_id",
        "attempt_id",
        "seq",
        "prev",
        "received_at",
        "token_id",
    ] {
        let mut forged = intent(&run, "bad", "note", None);
        forged.body[key] = json!("forged");
        assert!(store.append_operator(&forged, &peer()).is_err());
    }
    store
        .append_operator(
            &intent(&run, "effect:operator:admitted:forged", "note", None),
            &peer(),
        )
        .unwrap();
    assert!(
        store
            .append_operator(
                &intent(&run, "forged-settle", "settled", Some("forged")),
                &peer()
            )
            .is_err()
    );
    store
        .append_operator(&intent(&run, "deny", "denied", Some("e")), &peer())
        .unwrap();
    for kind in ["admitted", "denied", "settled"] {
        assert!(
            store
                .append_operator(&intent(&run, "bad", kind, Some("e")), &peer())
                .is_err()
        );
    }
    store.claim_owner(&run.run_id, &peer()).unwrap();
    assert!(
        store
            .append_owner(
                &run.run_id,
                "owner-forgery",
                "operator_intent",
                None,
                &json!({}),
                &peer(),
                "token"
            )
            .is_err()
    );
    let mut large = intent(&run, "large", "note", None);
    large.body = json!({"text":"x".repeat(65_536)});
    assert!(store.append_operator(&large, &peer()).is_err());
    assert!(store.verify(None).unwrap()[0].local_consistency);
}

#[test]
fn operator_append_faults_recover_exactly_once_or_preserve_ambiguity() {
    for fault in [
        Fault::BeforeWrite,
        Fault::RotationCreated,
        Fault::RotationSynced,
        Fault::PartialWrite,
        Fault::EventSync,
        Fault::Projection,
        Fault::Manifest,
        Fault::DirectorySync,
    ] {
        let (temp, mut store, run) = create();
        store.segment_limit = 1;
        let request = intent(&run, "retry", "admitted", Some("external-effect"));
        store.fault = Some(fault);
        assert!(store.append_operator(&request, &peer()).is_err());
        store.fault = None;
        assert!(store.append_operator(&request, &peer()).is_err());
        let original = bytes(&store, &run);
        drop(store);
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(bytes(&store, &run), original);
        if matches!(fault, Fault::PartialWrite) {
            assert!(store.append_operator(&request, &peer()).is_err());
            assert!(
                store
                    .tail(&TailRequest {
                        run_id: run.run_id,
                        cursor: None
                    })
                    .is_err()
            );
        } else {
            let receipt = store.append_operator(&request, &peer()).unwrap();
            assert_eq!(receipt.seq, 2);
            assert_eq!(store.append_operator(&request, &peer()).unwrap(), receipt);
            assert!(store.verify(None).unwrap()[0].local_consistency);
        }
    }
}

#[test]
fn tail_chunks_rotation_restart_and_growth_preserve_exact_bytes() {
    let (temp, mut store, run) = create();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    store.segment_limit = 1;
    store
        .append_owner(
            &run.run_id,
            "large",
            "note",
            None,
            &json!({"text":"🦀".repeat(80_000)}),
            &peer(),
            &"a".repeat(32),
        )
        .unwrap();
    for n in 0..40 {
        store
            .append_operator(&intent(&run, &format!("note-{n}"), "note", None), &peer())
            .unwrap();
    }
    let expected = bytes(&store, &run);
    let mut req = TailRequest {
        run_id: run.run_id.clone(),
        cursor: None,
    };
    let mut got: Vec<u8> = Vec::new();
    let mut pages = 0;
    loop {
        let page = store.tail(&req).unwrap();
        assert!(page.ndjson.len() <= READ_CHUNK_BYTES);
        assert_eq!(
            serde_json::to_value(store.tail(&req).unwrap()).unwrap(),
            serde_json::to_value(&page).unwrap()
        );
        got.extend(page.ndjson.as_bytes());
        pages += 1;
        req.cursor = Some(page.next_cursor);
        if page.caught_up {
            break;
        }
        // Every partially emitted record position survives a writer restart.
        drop(store);
        store = Store::open(&temp.path().join("data")).unwrap();
    }
    assert!(pages > 4);
    assert_eq!(got, expected);
    let idle = store.tail(&req).unwrap();
    assert!(idle.caught_up && idle.ndjson.is_empty());
    assert!(!store.root.join("readers").exists());
    store
        .append_operator(&intent(&run, "later", "note", None), &peer())
        .unwrap();
    let grown = store.tail(&req).unwrap();
    assert!(grown.caught_up && !grown.ndjson.is_empty());
    got.extend(grown.ndjson.as_bytes());
    assert_eq!(got, bytes(&store, &run));
}

#[test]
fn tail_refuses_forged_positions_mutated_records_and_partial_tails() {
    for damage in [
        "cursor-digest",
        "cursor-run",
        "cursor-offset",
        "record",
        "extra",
        "truncate",
        "link",
    ] {
        let (_temp, store, run) = create();
        let page = store
            .tail(&TailRequest {
                run_id: run.run_id.clone(),
                cursor: None,
            })
            .unwrap();
        let mut cursor: Value = serde_json::from_str(&page.next_cursor).unwrap();
        let mut req = TailRequest {
            run_id: run.run_id.clone(),
            cursor: None,
        };
        let path = store.root.join(&run.run_id).join(STREAM);
        match damage {
            "cursor-digest" => {
                cursor["after"]["head_digest"] = json!(format!("sha256:{}", "0".repeat(64)))
            }
            "cursor-run" => cursor["run_id"] = json!("run_00000000000000000000000000000000"),
            "cursor-offset" => {
                cursor["emitted"] = json!(3);
                cursor["pending_digest"] = json!("wrong");
            }
            "record" => {
                let mut b = fs::read(&path).unwrap();
                b[20] ^= 1;
                fs::write(&path, b).unwrap();
            }
            "extra" => {
                OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"x")
                    .unwrap();
            }
            "truncate" => {
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(1)
                    .unwrap();
            }
            "link" => {
                fs::hard_link(&path, path.with_extension("copy")).unwrap();
            }
            _ => unreachable!(),
        }
        if damage.starts_with("cursor") {
            req.cursor = Some(cursor.to_string());
        }
        assert!(store.tail(&req).is_err(), "accepted {damage}");
        // Failed reads do not advance the writer or append any event.
        assert_eq!(store.show(&run.run_id).unwrap().chain.head_seq, 1);
    }
}

#[test]
fn pending_operator_effects_pin_gc_and_pruned_history_refuses_tail_but_replays_intents() {
    let (temp, mut store, run) = super::tests::gc_fixture();
    let admitted = intent(&run, "independent-admit", "admitted", Some("work"));
    let receipt = store.append_operator(&admitted, &peer()).unwrap();
    let now = super::tests::gc_future();
    let plan = store.gc_plan_at(1, None, 100, now).unwrap();
    assert!(
        plan.runs[0]
            .keep_reasons
            .contains(&"operator_effect_pending".into())
    );
    assert!(!plan.runs[0].candidate);
    drop(store);
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    assert!(!store.gc_plan_at(1, None, 100, now).unwrap().runs[0].candidate);
    store
        .append_operator(
            &intent(&run, "independent-settle", "settled", Some("work")),
            &peer(),
        )
        .unwrap();
    assert!(store.gc_plan_at(1, None, 100, now).unwrap().runs[0].candidate);
    let tail = store
        .tail(&TailRequest {
            run_id: run.run_id.clone(),
            cursor: None,
        })
        .unwrap();
    store.gc_at(1, None, 100, &peer(), now).unwrap();
    assert!(
        store
            .tail(&TailRequest {
                run_id: run.run_id.clone(),
                cursor: Some(tail.next_cursor)
            })
            .is_err()
    );
    assert_eq!(store.append_operator(&admitted, &peer()).unwrap(), receipt);
    assert!(
        store
            .append_operator(&intent(&run, "new", "note", None), &peer())
            .is_err()
    );
    drop(store);
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    assert_eq!(store.append_operator(&admitted, &peer()).unwrap(), receipt);
}
