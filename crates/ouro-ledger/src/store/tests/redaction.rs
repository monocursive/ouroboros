use super::*;

#[test]
fn redaction_is_durable_before_append_and_replay_preserves_minimized_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let mut store = Store::open(&data).unwrap();
    let mut plan = payload();
    plan["redact"] = json!(["destinations", "paths"]);
    let run = store.prepare("redacted", &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    assert!(store.prepare("redacted", &payload(), &peer()).is_err());
    source_fixture(&mut store, &run, "path", 1, Some("private-file-name"));
    source_fixture(&mut store, &run, "proxy", 1, None);
    let path = store.root.join(&run.run_id).join(STREAM);
    let bytes = fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("private-file-name"));
    assert!(!String::from_utf8_lossy(&bytes).contains("blocked.example.test"));
    assert!(String::from_utf8_lossy(&bytes).contains("ouro.ledger.redaction/1"));
    let before = store.show(&run.run_id).unwrap();
    drop(store);
    let mut store = Store::open(&data).unwrap();
    assert!(store.verify(None).unwrap()[0].local_consistency);
    // Replay identity intentionally covers minimized content, not a guessable
    // digest of deleted values. Changing an unselected fact still conflicts.
    source_fixture(&mut store, &run, "path", 1, Some("different-deleted-value"));
    assert_eq!(store.show(&run.run_id).unwrap().chain, before.chain);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let mut raw: Value = serde_json::from_str(include_str!(
        "../../../../../docs/specs/jail-v1/examples/event-open.json"
    ))
    .unwrap();
    raw["attempt_id"] = json!(run.attempt_id);
    raw["outcome"]["return_value"] = json!(7);
    assert!(
        store
            .append_source(
                &run.run_id,
                &raw,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn canonical_replay_refuses_policy_bypass_and_false_redaction_markers() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("data")).unwrap();
    let mut plan = payload();
    plan["redact"] = json!(["paths"]);
    let run = store.prepare("redacted", &plan, &peer()).unwrap();
    store.claim_owner(&run.run_id, &peer()).unwrap();
    source_fixture(&mut store, &run, "path", 1, Some("private-file-name"));
    let bytes = fs::read(store.root.join(&run.run_id).join(STREAM)).unwrap();
    let lines: Vec<_> = bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    for retain_marker in [false, true] {
        let mut stream = Stream::empty(&run.run_id);
        for line in &lines[..lines.len() - 1] {
            stream.accept_canonical(&run.run_id, line).unwrap();
        }
        let mut source: Value = serde_json::from_slice(lines.last().unwrap()).unwrap();
        source["fields"]["path"] = json!({"kind":"workspace_relative","value":"private-file-name"});
        if !retain_marker {
            source.as_object_mut().unwrap().remove("redaction");
        }
        assert!(
            stream
                .accept_canonical(&run.run_id, &canonical(&source).unwrap())
                .is_err()
        );
    }
}
