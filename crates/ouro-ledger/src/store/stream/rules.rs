//! The record rules: what each canonical record kind may say, in which run
//! state, and what it changes. Appends and recovery apply the same rules.
use super::*;

pub(in crate::store) fn original_payload(record: &Value) -> Value {
    if record["kind"] == "source" {
        let mut source = record.clone();
        let object = source.as_object_mut().expect("canonical source object");
        for key in [
            "run_id",
            "seq",
            "prev",
            "received_at",
            "provenance",
            "kind",
            "request_id",
        ] {
            object.remove(key);
        }
        return json!({"kind":"source","request_id":record["request_id"],"body":source});
    }
    let mut value = record.clone();
    let object = value.as_object_mut().expect("canonical record object");
    for key in [
        "schema",
        "run_id",
        "attempt_id",
        "seq",
        "prev",
        "received_at",
        "provenance",
    ] {
        object.remove(key);
    }
    value
}

/// Identity the writer assigns. No intent body may supply it, so a body can
/// never be read as the record's own provenance.
pub(in crate::store) const RESERVED_BODY_KEYS: [&str; 9] = [
    "actor",
    "role",
    "provenance",
    "run_id",
    "attempt_id",
    "seq",
    "prev",
    "received_at",
    "token_id",
];

pub(in crate::store) fn check_reserved(body: &Value, what: &str) -> Result<()> {
    match RESERVED_BODY_KEYS
        .iter()
        .find(|key| body.get(**key).is_some())
    {
        Some(key) => Err(LedgerError(format!(
            "{what} body cannot supply reserved identity {key}"
        ))),
        None => Ok(()),
    }
}

pub(in crate::store) fn validate_intent(stream: &Stream, record: &Value) -> Result<()> {
    let kind = record["kind"].as_str().unwrap_or("");
    if !["admitted", "denied", "settled", "note", "outcome_unknown"].contains(&kind) {
        return Ok(());
    }
    let body = &record["body"];
    check_reserved(body, "intent")?;
    if kind == "note"
        && ["receipt", "coverage", "outcome", "capture"]
            .iter()
            .any(|field| body.get(field).is_some())
    {
        return Err(LedgerError(
            "notes cannot replace receipt or state projections".into(),
        ));
    }
    let run = &stream.run;
    if let Some(receipt) = body.get("receipt") {
        validate_receipt(receipt)?;
        if receipt["attempt_id"] != run.attempt_id {
            return Err(LedgerError("receipt belongs to a different attempt".into()));
        }
        if let Some(claimed) = body.get("receipt_digest")
            && claimed
                != &json!(
                    records::semantic::receipt_digest(receipt).map_err(|_| LedgerError(
                        "receipt has unsupported canonical values".into()
                    ))?
                )
        {
            return Err(LedgerError(
                "intent receipt digest does not match the embedded receipt".into(),
            ));
        }
        if body
            .get("outcome")
            .is_some_and(|outcome| outcome != &receipt["outcome"])
            || body
                .get("coverage")
                .is_some_and(|coverage| coverage != &receipt["coverage"])
        {
            return Err(LedgerError(
                "intent outcome or coverage does not match its receipt".into(),
            ));
        }
        if kind == "denied" && receipt["phase"] != "refused" {
            return Err(LedgerError("denial requires a refused receipt".into()));
        }
    }
    if kind == "admitted" || kind == "settled" {
        let receipt = &body["receipt"];
        let valid_phase = if kind == "admitted" {
            receipt["phase"] == "prepared"
        } else {
            receipt["phase"] == "settled" || known_exec_failure(receipt)
        };
        if receipt["schema"] != records::SCHEMA_RECEIPT
            || !valid_phase
            || receipt["attempt_id"] != run.attempt_id
            || receipt["argv_digest"] != run.payload["argv_digest"]
            || receipt["policy"]["digest"] != run.payload["policy_digest"]
            || receipt["policy"]["requirements"] != run.payload["requirements"]
        {
            return Err(LedgerError(
                "intent receipt does not match prepared policy, argv, requirements and attempt"
                    .into(),
            ));
        }
        if run.payload["profile"] == "none" && receipt["child_protection"] != "unprotected" {
            return Err(LedgerError(
                "none cannot claim enforced child protection".into(),
            ));
        }
        if run.payload["evidence"] == "strict" && !stream.source_gaps.is_empty() {
            return Err(LedgerError(
                "strict source loss blocks admission and settlement".into(),
            ));
        }
    }
    if kind == "settled" || (kind == "denied" && body.get("receipt").is_some()) {
        let mut correlation = Vec::with_capacity(2);
        if let Some(loss) = &stream.first_loss {
            correlation.push(loss.clone());
        }
        if let Some(last) = &stream.last_source {
            correlation.push(last.clone());
        }
        if !records::semantic::trace_ends_with(&correlation, &body["receipt"]).is_empty() {
            return Err(LedgerError(
                "terminal trace and receipt do not corroborate".into(),
            ));
        }
    }
    Ok(())
}

// A jail refusal after durable admission can describe a proved failed exec,
// rather than a policy denial. The failed target never became an executing
// child, and the entire attempt boundary must still be verified empty.
pub(in crate::store) fn known_exec_failure(receipt: &Value) -> bool {
    receipt["phase"] == "refused"
        && receipt["outcome"]["kind"] == "exec_error"
        && receipt["exec_observed"] == false
        && receipt["lifetime"]["tree_empty"] == true
        && receipt["lifetime"]["integrity"] == "verified"
        && receipt["lifetime"]["verification_scope"] == "attempt_tree"
}

pub(in crate::store) fn validate_transition(stream: &Stream, record: &Value) -> Result<()> {
    let kind = record["kind"].as_str().unwrap_or("");
    if kind == "prepared" && stream.run.chain.head_seq != 0 {
        return Err(LedgerError("duplicate preparation".into()));
    }
    if let Some(effect_id) = record["effect_id"].as_str() {
        let effect_key = operator::effect_key(record, effect_id);
        if let Some(previous) = stream.replay.get(&effect_key) {
            if previous.digest != digest(record)? {
                return Err(LedgerError(
                    "effect id conflicts with its immutable payload".into(),
                ));
            }
            return Err(LedgerError(
                "effect id already belongs to another request id".into(),
            ));
        }
    }
    match kind {
        "evidence_gap" => {
            let body = &record["body"];
            if stream.run.state != "admitted"
                || stream.run.payload["evidence"] != "best-effort"
                || body["reason"] != "writer_outage"
                || body["episode"].as_u64().is_none_or(|n| n == 0)
                || body["owner"] != serde_json::to_value(&stream.run.owner)?
                || body.as_object().is_none_or(|o| o.len() != 3)
            {
                return Err(LedgerError("invalid best-effort outage marker".into()));
            }
        }
        "operator_intent" => operator::validate(stream, record)?,
        "admitted" | "denied" if stream.run.state != "prepared" => {
            return Err(LedgerError(
                "admission or refusal is only valid from prepared".into(),
            ));
        }
        "settled" if stream.run.state != "admitted" => {
            return Err(LedgerError("settlement requires durable admission".into()));
        }
        "owner_claimed" if stream.run.owner.is_some() => {
            return Err(LedgerError("owner identity is immutable".into()));
        }
        "outcome_unknown" if ["settled", "denied"].contains(&stream.run.state.as_str()) => {
            return Err(LedgerError(
                "a recorded terminal outcome is immutable".into(),
            ));
        }
        "source" => {
            if ["settled", "denied", "outcome_unknown"].contains(&stream.run.state.as_str()) {
                return Err(LedgerError(
                    "terminal run cannot ingest new observations".into(),
                ));
            }
            let source = record["body"]["source"]
                .as_str()
                .ok_or_else(|| LedgerError("source name missing".into()))?;
            let seq = record["body"]["source_seq"]
                .as_u64()
                .ok_or_else(|| LedgerError("source seq missing".into()))?;
            if seq <= stream.source_heads.get(source).copied().unwrap_or(0) {
                return Err(LedgerError(
                    "producer source sequence reused or reordered".into(),
                ));
            }
            if record["body"]["operation"] == "jail.receipt" {
                let phase = record["body"]["fields"]["phase"]
                    .as_str()
                    .ok_or_else(|| LedgerError("receipt note phase missing".into()))?;
                if stream.receipt_phase.as_deref().is_some_and(|previous| {
                    previous != phase
                        && !matches!(
                            (previous, phase),
                            ("prepared", "enforced" | "settled" | "refused")
                                | ("enforced", "settled")
                        )
                }) {
                    return Err(LedgerError(
                        "receipt note lifecycle order is invalid".into(),
                    ));
                }
            }
        }
        "hold" | "release" => {
            if record["body"] != json!({}) || record.get("effect_id").is_some() {
                return Err(LedgerError(
                    "retention intents require an empty body and no effect id".into(),
                ));
            }
        }
        "prepared" | "owner_claimed" | "admitted" | "denied" | "settled" | "note"
        | "outcome_unknown" => {}
        _ => return Err(LedgerError("unknown durable record kind".into())),
    }
    Ok(())
}

pub(in crate::store) fn apply_record(
    stream: &mut Stream,
    record: &Value,
    receipt: AppendReceipt,
    payload_digest: String,
) -> Result<()> {
    let request_id = record["request_id"]
        .as_str()
        .ok_or_else(|| LedgerError("record has no request identity".into()))?;
    if stream.replay.contains_key(request_id) {
        return Err(LedgerError(
            "duplicate request id in canonical stream".into(),
        ));
    }
    let replay = Replay {
        digest: payload_digest,
        receipt: receipt.clone(),
    };
    stream.replay.insert(request_id.into(), replay.clone());
    if let Some(effect_id) = record["effect_id"].as_str() {
        stream
            .replay
            .insert(operator::effect_key(record, effect_id), replay);
    }
    stream.run.chain = Chain {
        head_seq: receipt.seq,
        head_digest: Some(receipt.digest),
    };
    match record["kind"].as_str().unwrap_or("") {
        "evidence_gap" => stream.source_gaps.push(record["body"].clone()),
        "hold" => stream.run.holds = vec!["operator".into()],
        "release" => stream.run.holds.clear(),
        "owner_claimed" => {
            stream.run.owner = Some(serde_json::from_value(record["body"]["owner"].clone())?)
        }
        "admitted" => stream.run.state = "admitted".into(),
        "denied" => {
            stream.run.state = "denied".into();
            stream.run.settlement = "recorded".into();
        }
        "settled" => {
            stream.run.state = "settled".into();
            stream.run.settlement = "recorded".into();
        }
        "outcome_unknown" => {
            stream.run.state = "outcome_unknown".into();
            stream.run.settlement = "recorded".into();
        }
        "source" => {
            let source = record["body"]["source"].as_str().unwrap_or("");
            let seq = record["body"]["source_seq"].as_u64().unwrap_or(0);
            let previous = stream.source_heads.insert(source.into(), seq).unwrap_or(0);
            if seq != previous + 1 {
                stream.source_gaps.push(json!({"source":source,"from_source_seq":previous+1,"to_source_seq":seq-1,"at_source_seq":seq,"reason":"source sequence gap"}));
            }
            if record["body"]["fields"]["kind"] == "trace_transport_loss"
                && stream.first_loss.is_none()
            {
                stream.first_loss = Some(record["body"].clone());
                let fields = &record["body"]["fields"];
                stream.source_gaps.push(json!({"source":fields["source"],"at_source_seq":seq,"reason":"trace_transport_loss","start_ns":fields["start_ns"],"end_ns":fields["end_ns"],"classes":fields["classes"]}));
            }
            if record["body"]["operation"] == "jail.receipt" {
                stream.receipt_phase = record["body"]["fields"]["phase"]
                    .as_str()
                    .map(str::to_owned);
            }
            stream.last_source = Some(record["body"].clone());
        }
        _ => {}
    }
    // Source outcomes describe individual operations, not the terminal run.
    // Only authenticated owner/reconciliation intents update projections.
    let kind = record["kind"].as_str().unwrap_or("");
    if matches!(kind, "admitted" | "denied" | "settled" | "outcome_unknown") {
        let body = &record["body"];
        if let Some(receipt) = body.get("receipt") {
            stream.run.receipts.push(receipt.clone());
            if let Some(protection) = receipt.get("child_protection").and_then(Value::as_str)
                && (protection == "enforced" || protection == "unprotected")
            {
                stream.run.child_protection = protection.into();
            }
            if matches!(kind, "denied" | "settled") {
                stream.run.outcome = receipt.get("outcome").cloned();
            }
        }
        if kind == "outcome_unknown" {
            stream.run.outcome = Some(unknown_outcome(body.get("outcome")));
        } else if let Some(outcome) = body.get("outcome") {
            stream.run.outcome = Some(outcome.clone());
        }
        if let Some(coverage) = body.get("coverage") {
            stream.run.coverage = coverage.clone();
        }
        if let Some(capture) = body.get("capture") {
            stream.run.capture = capture.clone();
        }
    }
    // none remains unprotected regardless of an owner's requested display label.
    if stream.run.payload["profile"] == "none" {
        stream.run.child_protection = "unprotected".into();
    }
    if !stream.source_gaps.is_empty() {
        if !stream.run.coverage.is_object() {
            stream.run.coverage = json!({"source_coverage":stream.run.coverage});
        }
        stream.run.coverage["ledger"] = json!({"status":"degraded","gaps":stream.source_gaps});
    }
    Ok(())
}

pub(in crate::store) const UNRESOLVED: &str =
    "owner or reconciliation reported an unresolved run outcome";

/// The projection of an unresolved run (run projection rule 2). A child
/// outcome the owner did observe stays beside the unknown; an owner's or
/// reconciler's own unknown is not a child outcome, so its reason becomes
/// the run's.
pub(in crate::store) fn unknown_outcome(reported: Option<&Value>) -> Value {
    match reported {
        Some(child) if child["kind"] != "unknown" => json!({"kind":"unknown","unknown":true,
            "unknown_reason":UNRESOLVED,"observed_child_outcome":child}),
        reported => json!({"kind":"unknown","unknown":true,"unknown_reason":reported
            .and_then(|outcome| outcome["unknown_reason"].as_str())
            .unwrap_or(UNRESOLVED)}),
    }
}

pub(in crate::store) fn validate_recovery(
    stream: &Stream,
    record: &Value,
    role: &str,
) -> Result<()> {
    if role == "recovery"
        && (stream.run.payload["evidence"] != "best-effort"
            || stream.run.state != "admitted"
            || stream.run.owner.is_none()
            || !["source", "evidence_gap", "settled", "outcome_unknown"]
                .contains(&record["kind"].as_str().unwrap_or("")))
    {
        return Err(LedgerError(
            "recovery requires an already admitted best-effort run".into(),
        ));
    }
    if record["kind"] == "evidence_gap" && role != "recovery" {
        return Err(LedgerError(
            "outage markers require recovery provenance".into(),
        ));
    }
    Ok(())
}
