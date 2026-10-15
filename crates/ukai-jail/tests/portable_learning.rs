//! Learned output is a proposal with receipt-bound evidence, never a policy file.
use serde_json::json;

mod common;

/// One complete `ukai.event/1` result event of the fixture attempt, as the
/// trace records it (learning parses the typed event).
fn event(
    source: &str,
    source_seq: usize,
    operation: &str,
    decision: Option<&str>,
    outcome: serde_json::Value,
    fields: serde_json::Value,
) -> serde_json::Value {
    json!({
        "schema": "ukai.event/1",
        "attempt_id": "fixture",
        "source": source,
        "source_seq": source_seq,
        "observed_at": "2026-10-14T00:00:00Z",
        "monotonic_ns": "1",
        "operation": operation,
        "stage": "result",
        "decision": decision,
        "outcome": outcome,
        "fields": fields,
    })
}

#[test]
fn learning_filters_network_causes_and_never_grants_denied_writes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(
        root.join("jail.json"),
        r#"{"attempt_id":"fixture","coverage":{}}"#,
    )
    .unwrap();
    let mut events = Vec::new();
    for (destination, kind, reason) in [
        ("one.example:443", "connect", "host_not_allowed"),
        ("two.example:80", "http", "host_not_allowed"),
        ("private.example:443", "connect", "address_not_allowed"),
    ] {
        events.push(event(
            "proxy",
            events.len() + 1,
            "net.connect",
            Some("deny"),
            json!({"ok": false, "completion": "proxy_close"}),
            json!({"destination": destination, "kind": kind, "reason": reason}),
        ));
    }
    events.push(event(
        "audit",
        1,
        "fs.deny",
        None,
        json!({"ok": false, "errno": "EACCES", "return_value": -13, "completion": "syscall_return"}),
        json!({"path": "/home/operator/private", "attempted_operation": "fs.create"}),
    ));
    events.push(event(
        "audit",
        2,
        "fs.write",
        None,
        json!({"ok": false, "errno": "EROFS", "return_value": -30, "completion": "syscall_return"}),
        json!({"path": {"kind": "digest", "digest": "sha256:fixture"}, "action": "opened_for_mutation"}),
    ));
    let journal = events.iter().map(|e| format!("{e}\n")).collect::<String>();
    std::fs::write(root.join("trace.ndjson"), journal).unwrap();
    let proposal = ukai_jail::learn::derive(&root, &root.join("workspace"), 1).unwrap();
    assert_eq!(proposal.network_allow, ["one.example", "two.example:80"]);
    assert!(proposal.read_only.is_empty());
    assert_eq!(proposal.denied_writes.len(), 2);
    // Plain paths report as themselves; digest snapshots keep their shape.
    assert_eq!(proposal.denied_writes[0], "/home/operator/private");
    assert!(proposal.denied_writes[1].contains("sha256:fixture"));
    assert!(!proposal.denied_writes[0].starts_with('"'));
    let validator = &common::validators()["learned-policy"];
    let mut value = serde_json::to_value(&proposal).unwrap();
    assert!(validator.is_valid(&value), "{value}");
    value["provenance"]["receipt_digest"] = json!("invented");
    assert!(!validator.is_valid(&value));
    assert!(
        ukai_jail::learn::derive(&root, &root.join("workspace"), 2)
            .unwrap()
            .network_allow
            .is_empty()
    );
    let mut mixed = events[0].clone();
    mixed["attempt_id"] = json!("somewhere-else");
    std::fs::write(root.join("trace.ndjson"), format!("{mixed}\n")).unwrap();
    assert!(
        ukai_jail::learn::derive(&root, &root, 1)
            .unwrap_err()
            .contains("mixed attempt")
    );
}

/// A proposal asks for no more than the run was refused: an explicit port
/// admits plaintext HTTP (network-rules.md, L21), so a refused tunnel to
/// port 443 is proposed as the bare host, the TLS-only shape, and only a
/// plaintext request (absolute-form, or HTTP inside a tunnel the proxy
/// refused as `plaintext_not_granted`) is proposed with its port. Adopting
/// each proposal grants exactly the shape it was refused for.
#[test]
fn learning_proposes_tls_only_unless_plaintext_was_refused() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(
        root.join("jail.json"),
        r#"{"attempt_id":"fixture","coverage":{}}"#,
    )
    .unwrap();
    let cases = [
        (
            "tls.example:443",
            "connect",
            "host_not_allowed",
            "tls.example",
        ),
        (
            "[2001:db8::1]:443",
            "connect",
            "host_not_allowed",
            "[2001:db8::1]",
        ),
        (
            "alt.example:8443",
            "connect",
            "host_not_allowed",
            "alt.example:8443",
        ),
        (
            "plain.example:443",
            "http",
            "host_not_allowed",
            "plain.example:443",
        ),
        (
            "inner.example:443",
            "connect",
            "plaintext_not_granted",
            "inner.example:443",
        ),
        (
            "outer.example:443",
            "http",
            "plaintext_not_granted",
            "outer.example:443",
        ),
    ];
    let journal: String = cases
        .iter()
        .enumerate()
        .map(|(index, (destination, kind, reason, _))| {
            let event = event(
                "proxy",
                index + 1,
                "net.connect",
                Some("deny"),
                json!({"ok": false, "completion": "proxy_close"}),
                json!({"destination": destination, "kind": kind, "reason": reason}),
            );
            format!("{event}\n")
        })
        .collect();
    std::fs::write(root.join("trace.ndjson"), journal).unwrap();
    let proposal = ukai_jail::learn::derive(&root, &root.join("workspace"), 1).unwrap();
    let mut expected: Vec<&str> = cases.iter().map(|case| case.3).collect();
    expected.sort_unstable();
    assert_eq!(proposal.network_allow, expected);
    for (destination, kind, reason, grant) in cases {
        let rule = ukai_jail::network::HostRule::parse(grant).expect("a valid host rule");
        let plaintext = kind == "http" || reason == "plaintext_not_granted";
        assert_eq!(
            rule.explicit_port,
            plaintext || !destination.ends_with(":443"),
            "{destination} ({kind}, {reason}) proposed as {grant}"
        );
        assert_eq!(
            proposal.provenance.evidence[grant].len(),
            1,
            "{grant} keeps the event it came from"
        );
    }
}
