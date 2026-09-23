//! A proxy result as an `ouro.event/1` proxy-source `net.connect` record
//! (§13.1). A pure function: the caller supplies the attempt, the per-source
//! sequence number and the clocks, and owns the single trace writer.

use std::time::SystemTime;

use serde_json::{Map, Value};

use super::{ProxyDecision, ProxyResult};
use crate::records::{
    Completion, Decision, Event, EventOutcome, EventSource, EventStage, SCHEMA_EVENT, rfc3339_utc,
};

/// The errno name of a connect failure, for the errors a connect can return.
fn errno_name(errno: i32) -> Option<&'static str> {
    Some(match errno {
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::ECONNRESET => "ECONNRESET",
        libc::ETIMEDOUT => "ETIMEDOUT",
        libc::EHOSTUNREACH => "EHOSTUNREACH",
        libc::ENETUNREACH => "ENETUNREACH",
        libc::ENETDOWN => "ENETDOWN",
        libc::EHOSTDOWN => "EHOSTDOWN",
        libc::EADDRNOTAVAIL => "EADDRNOTAVAIL",
        libc::EACCES => "EACCES",
        libc::EPERM => "EPERM",
        libc::EINVAL => "EINVAL",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::EMFILE => "EMFILE",
        libc::ENFILE => "ENFILE",
        libc::ENOBUFS => "ENOBUFS",
        _ => return None,
    })
}

fn saturating_ms(result: &ProxyResult) -> u64 {
    u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX)
}

/// Builds the proxy-source `net.connect` result event.
///
/// `outcome.ok` states whether the upstream connection was established;
/// `decision` is the policy decision, independent of it. Byte counters are
/// the relay's (not file bytes), `bytes_in` from the destination and
/// `bytes_out` toward it. `fields` hold the request id, request kind,
/// normalized destination, safe reason code, connected address and how a
/// relayed request ended. Nothing else from the request is recorded.
#[must_use]
pub fn proxy_event(
    result: &ProxyResult,
    attempt_id: &str,
    source_seq: u64,
    observed_at: SystemTime,
    monotonic_ns: u128,
) -> Event {
    let mut fields = Map::new();
    fields.insert("request_id".to_owned(), Value::from(result.request_id));
    fields.insert("kind".to_owned(), Value::from(result.kind.as_str()));
    fields.insert(
        "destination".to_owned(),
        result
            .destination
            .as_ref()
            .map_or(Value::Null, |destination| {
                Value::from(destination.to_string())
            }),
    );
    fields.insert("reason".to_owned(), Value::from(result.reason.as_str()));
    fields.insert(
        "connected_address".to_owned(),
        result
            .connected
            .map_or(Value::Null, |address| Value::from(address.to_string())),
    );
    fields.insert(
        "discarded_bytes".to_owned(),
        Value::from(result.discarded_bytes),
    );
    fields.insert(
        "end".to_owned(),
        result
            .end
            .map_or(Value::Null, |end| Value::from(end.as_str())),
    );
    Event {
        schema: SCHEMA_EVENT.to_owned(),
        attempt_id: attempt_id.to_owned(),
        source: EventSource::Proxy,
        source_seq,
        observed_at: rfc3339_utc(observed_at),
        monotonic_ns: monotonic_ns.to_string(),
        operation: "net.connect".to_owned(),
        stage: EventStage::Result,
        decision: Some(match result.decision {
            ProxyDecision::Allow => Decision::Allow,
            ProxyDecision::Deny => Decision::Deny,
        }),
        outcome: Some(EventOutcome {
            ok: Some(result.connected.is_some()),
            return_value: None,
            errno: result.connect_errno.and_then(errno_name).map(str::to_owned),
            completion: Completion::ProxyClose,
            bytes_in: Some(result.bytes_in),
            bytes_out: Some(result.bytes_out),
            duration_ms: Some(saturating_ms(result)),
        }),
        fields,
    }
}
