//! Independent operator assertions never update the launch owner's projections.
use super::*;
use crate::protocol::OperatorIntent;

// The slash keeps internal operator effect indexes outside caller request-id space.
pub(super) fn effect_key(record: &Value, effect: &str) -> String {
    if record["kind"] == "operator_intent" {
        format!(
            "effect:operator/{}:{effect}",
            record["body"]["kind"].as_str().unwrap_or("")
        )
    } else {
        format!("effect:{}:{effect}", record["kind"].as_str().unwrap_or(""))
    }
}

fn validate_body(kind: &str, effect: Option<&str>, body: &Value) -> Result<()> {
    if !["admitted", "denied", "settled", "note"].contains(&kind)
        || !body.is_object()
        || effect.is_some_and(|id| !valid_id(id))
        || (kind != "note" && effect.is_none())
    {
        return Err(LedgerError("operator intent needs a supported kind, object body and an effect id for lifecycle decisions".into()));
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
        if body.get(key).is_some() {
            return Err(LedgerError(format!(
                "operator body cannot supply reserved identity {key}"
            )));
        }
    }
    if canonical(body)?.len() > 65_536 {
        return Err(LedgerError("operator body exceeds 64 KiB bound".into()));
    }
    Ok(())
}

pub(super) fn validate(stream: &Stream, record: &Value) -> Result<()> {
    let kind = record["body"]["kind"].as_str().unwrap_or("");
    let effect = record["effect_id"].as_str();
    validate_body(kind, effect, &record["body"]["fields"])?;
    if let Some(effect) = effect {
        let has = |phase| {
            stream
                .replay
                .contains_key(&format!("effect:operator/{phase}:{effect}"))
        };
        if (matches!(kind, "admitted" | "denied")
            && (has("admitted") || has("denied") || has("settled")))
            || (kind == "settled" && (!has("admitted") || has("denied") || has("settled")))
        {
            return Err(LedgerError(
                "operator effect lifecycle conflicts with its durable decisions".into(),
            ));
        }
    }
    Ok(())
}

impl Store {
    pub fn append_operator(
        &mut self,
        intent: &OperatorIntent,
        peer: &Peer,
    ) -> Result<AppendReceipt> {
        if !valid_id(&intent.request_id) {
            return Err(LedgerError(
                "operator intent needs a bounded request id".into(),
            ));
        }
        validate_body(&intent.kind, intent.effect_id.as_deref(), &intent.body)?;
        self.append(
            &intent.run_id,
            json!({"kind":"operator_intent", "request_id":intent.request_id,
                "effect_id":intent.effect_id, "body":{"kind":intent.kind,"fields":intent.body}}),
            "operator",
            peer,
            None,
        )
    }
}
