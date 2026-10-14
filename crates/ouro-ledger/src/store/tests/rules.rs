//! The record rules, as appends and recovery apply them.
use super::*;

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
        "../../../../../docs/specs/jail-v1/examples/receipt-tool.json"
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
        "../../../../../docs/specs/jail-v1/examples/receipt-exec-refused.json"
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
        "../../../../../docs/specs/jail-v1/examples/event-exec.json"
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
        "../../../../../docs/specs/jail-v1/examples/receipt-exec-refused.json"
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
            "../../../../../docs/specs/jail-v1/examples/receipt-exec-refused.json"
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
