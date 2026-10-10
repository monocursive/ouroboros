//! Tail preserves valid envelope bytes, including noncanonical JSON spellings.
use ouro_fixture::harness::Jail;
use serde_json::Value;

#[test]
fn k20_tail_keeps_whitespace_and_unicode_escape_spellings_byte_identically() {
    let jail = Jail::new().unwrap();
    let envelope: Value = serde_json::from_str(include_str!(
        "../../../docs/specs/jail-v1/examples/event-note-learning-read.json"
    ))
    .unwrap();
    let id = envelope["attempt_id"].as_str().unwrap();
    let attempt = jail.data_dir().join("attempts").join(id);
    std::fs::create_dir_all(&attempt).unwrap();
    std::fs::write(attempt.join("jail.lock"), b"").unwrap();
    let raw = format!(
        "  {}  \n",
        serde_json::to_string(&envelope)
            .unwrap()
            .replacen("att_", "\\u0061tt_", 1)
    );
    assert_eq!(serde_json::from_str::<Value>(&raw).unwrap(), envelope);
    std::fs::write(attempt.join("trace.ndjson"), &raw).unwrap();
    let path = attempt.join("trace.ndjson");
    let result = jail
        .args(["tail", "--attempt", id, "--json"])
        .run()
        .unwrap();
    assert_eq!(result.code(), Some(0), "{}", result.stderr_text());
    assert_eq!(result.stdout_text(), raw);
    assert_eq!(std::fs::read_to_string(path).unwrap(), raw);
}
