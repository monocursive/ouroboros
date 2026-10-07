use super::*;

fn show(fixture: &Fixture, run: &RunRecord, transcript: bool, json: bool) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ouro-ledger"));
    command
        .arg("--data-dir")
        .arg(&fixture.data)
        .arg("show")
        .arg(&run.run_id);
    if transcript {
        command.arg("--with-transcript");
    }
    if json {
        command.arg("--json");
    }
    let output = Process::spawn(&mut command, true).finish();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.contains(&0x1b));
    assert!(output.stdout.len() < ouro_ledger::protocol::MAX_FRAME_BYTES);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn real_transcript_is_opt_in_bounded_and_escapes_binary_and_terminal_controls() {
    let Some(jail) = live_jail() else {
        return;
    };
    for profile in ["tool", "none"] {
        let fixture = Fixture::new(&jail);
        let mut command = fixture.command_with_profile("transcript", true, profile);
        command.args([
            "--capture",
            "stdout",
            "--capture",
            "stderr",
            "--capture-limit",
            "70000",
            "--",
            "/bin/sh",
            "-c",
            r"printf '%080000d' 0; printf 'secret\033\000\377\n' >&2",
        ]);
        let (output, run) = fixture.run(&mut command);
        assert!(output.status.success(), "{run:?}");
        let before = fixture.events(&run);
        let plain = show(&fixture, &run, false, true);
        assert!(plain.get("transcript").is_none());
        assert!(!serde_json::to_string(&plain).unwrap().contains("secret"));
        for json in [true, false] {
            let shown = show(&fixture, &run, true, json);
            let transcript = &shown["transcript"];
            assert_eq!(shown["run"], plain);
            let stdout = &transcript["streams"]["stdout"];
            assert_eq!(stdout["state"], "truncated");
            assert_eq!(stdout["capture_truncated"], true);
            assert_eq!(stdout["display_truncated"], true);
            assert_eq!(stdout["displayed_bytes"], 65_536);
            assert_eq!(stdout["text"].as_str().unwrap(), "0".repeat(65_536));
            let stderr = &transcript["streams"]["stderr"];
            assert_eq!(stderr["state"], "captured");
            assert_eq!(
                stderr["text"],
                b"secret\x1b\0\xff\n".escape_ascii().to_string()
            );
            assert_eq!(transcript["streams"]["argv"]["state"], "not_captured");
        }
        assert_eq!(fixture.events(&run), before);
        fs::remove_file(
            fixture
                .data
                .join("ledger")
                .join(&run.run_id)
                .join("artifacts/stdout.bin"),
        )
        .unwrap();
        assert_eq!(
            show(&fixture, &run, true, true)["transcript"]["streams"]["stdout"]["state"],
            "unavailable"
        );
        println!(
            "transcript/{profile}: opt-in, bounded, escaped, metadata unchanged, missing capture labeled"
        );
    }
}

#[test]
fn real_transcript_keeps_live_and_killed_owner_captures_incomplete() {
    let Some(jail) = live_jail() else {
        return;
    };
    let fixture = Fixture::new(&jail);
    let mut command = fixture.command("transcript-owner-death", true);
    command.args([
        "--capture",
        "stdout",
        "--",
        "/bin/sh",
        "-c",
        "printf partial-secret; touch started; while test ! -f finish; do sleep 0.05; done",
    ]);
    let mut owner = Process::spawn(&mut command, true);
    let run = fixture.wait_started(&mut owner);
    let live = show(&fixture, &run, true, true);
    assert_eq!(
        live["transcript"]["streams"]["stdout"]["state"],
        "incomplete"
    );
    assert!(
        live["transcript"]["streams"]["stdout"]
            .get("text")
            .is_none()
    );
    owner.kill();
    fixture.assert_tree_stopped(&run);
    fixture.client().settle_orphans().unwrap();
    let dead = show(&fixture, &run, true, true);
    assert_eq!(dead["run"]["state"], "outcome_unknown");
    assert_eq!(
        dead["transcript"]["streams"]["stdout"]["state"],
        "incomplete"
    );
    assert_eq!(
        dead["transcript"]["streams"]["stderr"]["state"],
        "not_captured"
    );
    assert!(
        dead["transcript"]["streams"]["stdout"]
            .get("text")
            .is_none()
    );
    println!(
        "transcript/owner-death: live and unfinalized captures remain incomplete, outcome unknown"
    );
}
