use super::*;
use serde_json::json;

pub(super) fn assert_minimized(event: &Value) {
    if event["source"] == "audit" {
        for key in ["path", "path2"] {
            if let Some(path) = event["fields"].get(key) {
                assert_eq!(path["kind"], "unavailable", "{event}");
                if path["reason"] == "ledger_redacted" {
                    assert!(
                        event["redaction"]["fields"]
                            .as_array()
                            .unwrap()
                            .contains(&json!(key))
                    );
                }
            }
        }
    }
    if event["source"] == "proxy" {
        for key in ["destination", "connected_address", "origin"] {
            assert!(event["fields"][key].is_null(), "{event}");
        }
    }
}

#[test]
fn real_redaction_preserves_capture_bytes_and_replay_and_verifies_offline() {
    let Some(jail) = live_jail() else { return };
    for profile in ["tool", "none"] {
        let mut fixture = Fixture::new(&jail);
        let mut command = fixture.command_with_profile("redaction", true, profile);
        command.args(["--redact", "paths", "--redact", "destinations",
            "--capture", "stdout", "--capture", "argv", "--", "/bin/sh", "-c",
            "printf x >> executions; printf sensitive-capture > private-file-name; mv private-file-name private-renamed-name; printf sensitive-capture"]);
        let (output, run) = fixture.run(&mut command);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(run.state, "settled");
        assert_eq!(run.payload["redact"], json!(["destinations", "paths"]));
        let events = fixture.events(&run);
        for event in &events {
            assert_minimized(event);
        }
        let text = serde_json::to_string(&events).unwrap();
        for secret in [
            "private-file-name",
            "private-renamed-name",
            "sensitive-capture",
        ] {
            assert!(!text.contains(secret));
            assert!(!serde_json::to_string(&run).unwrap().contains(secret));
        }
        if profile == "tool" {
            let rename = events
                .iter()
                .find(|e| e["operation"] == "fs.rename")
                .expect("real rename observation");
            assert_eq!(rename["redaction"]["fields"], json!(["path", "path2"]));
        }
        let shown = fixture.client().show_with_transcript(&run.run_id).unwrap();
        assert_eq!(
            shown["transcript"]["streams"]["stdout"]["text"],
            "sensitive-capture"
        );
        assert!(
            shown["transcript"]["streams"]["argv"]["text"]
                .as_str()
                .unwrap()
                .contains("private-file-name")
        );
        fixture.writer.kill();
        fixture.writer = Fixture::start_writer(&fixture.data);
        assert!(fixture.client().verify(Some(&run.run_id)).unwrap()[0].local_consistency);
        let targets = ouro_ledger::comparison::compare_mode(
            &mut fixture.client(),
            &run.run_id,
            &run.run_id,
            None,
            100,
            ouro_ledger::comparison::ComparisonMode::TargetCounts,
        )
        .unwrap();
        if profile == "tool" {
            assert_eq!(targets["classes"]["fs.write"]["status"], "incomparable");
            assert!(
                targets["left"]["unavailable_targets"]["fs.write"]["count"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
        }
        let (output, replay) = fixture.run(&mut command);
        assert!(output.status.success());
        assert_eq!(replay.chain, run.chain);
        assert_eq!(
            fs::read(fixture.workspace.join("executions")).unwrap(),
            b"x"
        );
        let bundle = fixture._temp.path().join("redacted-bundle");
        ouro_ledger::bundle::create(
            &mut fixture.client(),
            &fixture.data,
            &run.run_id,
            &bundle,
            &[],
        )
        .unwrap();
        assert!(
            ouro_ledger::bundle::verify(&bundle).unwrap()["local_consistency"]
                .as_bool()
                .unwrap()
        );
        assert!(!bundle.join("argv.bin").exists());
        println!(
            "redaction/{profile}: canonical metadata minimized, explicit captures unchanged, restart replay once, offline bundle verified"
        );
    }
}

#[test]
fn real_proxy_redaction_removes_destination_without_changing_denial_or_counters() {
    let Some(jail) = live_jail() else { return };
    let fixture = Fixture::new(&jail);
    let mut command = fixture.command_with_profile("redaction-proxy", true, "tool");
    command.args(["--redact", "destinations", "--", "/bin/sh", "-c",
        "curl --silent --max-time 3 --noproxy '' --proxy \"$HTTP_PROXY\" --proxytunnel https://redaction-private.invalid/ >/dev/null; test $? -ne 0"]);
    let (output, run) = fixture.run(&mut command);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = fixture.events(&run);
    let proxy = events
        .iter()
        .find(|e| e["source"] == "proxy")
        .expect("real proxy result");
    assert_minimized(proxy);
    assert_eq!(proxy["decision"], "deny");
    assert_eq!(proxy["outcome"]["bytes_in"], 0);
    assert_eq!(proxy["outcome"]["bytes_out"], 0);
    assert!(
        proxy["redaction"]["fields"]
            .as_array()
            .unwrap()
            .contains(&json!("destination"))
    );
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains("redaction-private.invalid")
    );
    println!(
        "redaction/proxy: real local denial retained, destination removed, byte counters unchanged"
    );
}
