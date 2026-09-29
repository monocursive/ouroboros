//! Learned output is a proposal with receipt-bound evidence, never a policy file.
use serde_json::json;

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
    for (destination, reason) in [
        ("one.example:443", "host_not_allowed"),
        ("two.example:80", "host_not_allowed"),
        ("private.example:443", "address_not_allowed"),
    ] {
        events.push(json!({"attempt_id":"fixture", "source":"proxy", "source_seq":events.len()+1,"operation":"net.connect","decision":"deny","fields":{"destination":destination,"reason":reason}}));
    }
    events.push(json!({"attempt_id":"fixture", "source":"audit", "source_seq":1,"operation":"fs.deny","decision":"deny","fields":{"path":"/home/operator/private","attempted_operation":"fs.create"}}));
    events.push(json!({"attempt_id":"fixture", "source":"audit", "source_seq":2,"operation":"fs.write","outcome":{"ok":false,"errno":"EROFS","return_value":-30},"fields":{"path":{"kind":"digest","digest":"sha256:fixture"},"action":"opened_for_mutation"}}));
    let journal = events.iter().map(|e| format!("{e}\n")).collect::<String>();
    std::fs::write(root.join("trace.ndjson"), journal).unwrap();
    let proposal = ouro_jail::learn::derive(&root, &root.join("workspace"), 1).unwrap();
    assert_eq!(
        proposal.network_allow,
        ["one.example:443", "two.example:80"]
    );
    assert!(proposal.read_only.is_empty());
    assert_eq!(proposal.denied_writes.len(), 2);
    // Plain paths report as themselves; digest snapshots keep their shape.
    assert_eq!(proposal.denied_writes[0], "/home/operator/private");
    assert!(proposal.denied_writes[1].contains("sha256:fixture"));
    assert!(!proposal.denied_writes[0].starts_with('"'));
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/specs/jail-v1/learned-policy.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut value = serde_json::to_value(&proposal).unwrap();
    assert!(validator.is_valid(&value), "{value}");
    value["provenance"]["receipt_digest"] = json!("invented");
    assert!(!validator.is_valid(&value));
    assert!(
        ouro_jail::learn::derive(&root, &root.join("workspace"), 2)
            .unwrap()
            .network_allow
            .is_empty()
    );
    let mut mixed = events[0].clone();
    mixed["attempt_id"] = json!("somewhere-else");
    std::fs::write(root.join("trace.ndjson"), format!("{mixed}\n")).unwrap();
    assert!(
        ouro_jail::learn::derive(&root, &root, 1)
            .unwrap_err()
            .contains("mixed attempt")
    );
}
