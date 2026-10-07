use super::*;

fn fixture(name: &str) -> Value {
    serde_json::from_str(match name {
        "path" => include_str!("../../../../docs/specs/jail-v1/examples/event-open.json"),
        "proxy" => include_str!("../../../../docs/specs/jail-v1/examples/event-proxy-deny.json"),
        _ => unreachable!(),
    })
    .unwrap()
}
fn apply(event: &Value, policy: &Value) -> Result<Value> {
    minimize(event, policy, event["attempt_id"].as_str().unwrap())
}

#[test]
fn selective_redaction_is_idempotent_and_preserves_nonselected_facts() {
    let policy = json!({"redact":["destinations","paths"]});
    for name in ["path", "proxy"] {
        let mut original = fixture(name);
        if name == "proxy" {
            original["fields"]["origin"] = json!("https://private.example:443");
            original["fields"]["connected_address"] = json!("192.0.2.7:443");
        }
        assert_eq!(apply(&original, &json!({})).unwrap(), original);
        let minimized = apply(&original, &policy).unwrap();
        assert_eq!(minimized["outcome"], original["outcome"]);
        assert_eq!(minimized["decision"], original["decision"]);
        assert_eq!(minimized["source_seq"], original["source_seq"]);
        assert_eq!(apply(&minimized, &policy).unwrap(), minimized);
        assert!(
            validate_stored(&original, &policy, original["attempt_id"].as_str().unwrap()).is_err()
        );
        assert!(apply(&minimized, &json!({})).is_err());
        let mut forged = minimized.clone();
        forged["redaction"]["fields"] = json!(["outcome"]);
        assert!(apply(&forged, &policy).is_err());
        let mut leaked = minimized;
        leaked["fields"] = original["fields"].clone();
        assert!(apply(&leaked, &policy).is_err());
    }
}

#[test]
fn both_native_paths_and_digests_are_removed_but_unknown_paths_remain_unknown() {
    let policy = json!({"redact":["paths"]});
    for path in [
        json!({"kind":"workspace_relative","value":{"encoding":"base64","data":"/w=="}}),
        json!({"kind":"digest","digest":format!("sha256:{}", "a".repeat(64)),"reason":"external"}),
    ] {
        let mut event = fixture("path");
        event["fields"]["path"] = path.clone();
        event["fields"]["path2"] = path;
        event["fields"]["path2_complete"] = json!(true);
        let minimized = apply(&event, &policy).unwrap();
        assert_eq!(minimized["redaction"]["fields"], json!(["path", "path2"]));
        assert_eq!(
            minimized["fields"]["path"],
            json!({"kind":"unavailable","reason":"ledger_redacted"})
        );
        assert_eq!(minimized["fields"]["path2"], minimized["fields"]["path"]);
        assert_eq!(minimized["fields"]["path_complete"], true);
    }
    let mut event = fixture("path");
    event["fields"]["path"] = json!({"kind":"unavailable","reason":"argument_not_read"});
    assert_eq!(apply(&event, &policy).unwrap(), event);
    event["fields"]["path"]["reason"] = json!(REASON);
    assert!(apply(&event, &policy).is_err());
}

#[test]
fn redaction_cannot_launder_private_fields_invalid_native_bytes_or_policy() {
    let policy = json!({"redact":["paths"]});
    let mut event = fixture("path");
    event["fields"]["raw_environment"] = json!("do-not-echo-private-value");
    let error = apply(&event, &policy).unwrap_err();
    assert!(!error.0.contains("do-not-echo"));
    let mut event = fixture("path");
    event["fields"]["path"]["value"] = json!({"encoding":"base64","data":"eA=="});
    assert!(apply(&event, &policy).is_err()); // UTF-8 bytes must use the string form.
    for value in [
        json!([]),
        json!(["paths", "paths"]),
        json!(["paths", "destinations"]),
        json!(["all"]),
        json!(null),
        json!("paths"),
    ] {
        assert!(validate_policy(&json!({"redact":value})).is_err());
    }
}
