use super::*;
use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
};

#[test]
fn real_argv_capture_is_private_opt_in_exact_and_bounded_without_reexecution() {
    let Some(jail) = live_jail() else {
        return;
    };
    for profile in ["tool", "none"] {
        for limit in [None, Some(0), Some(9), Some(1024)] {
            let fixture = Fixture::new(&jail);
            let mut command = fixture.command_with_profile("argv", true, profile);
            if let Some(limit) = limit {
                command.args(["--capture", "argv", "--capture-limit", &limit.to_string()]);
            }
            let args: Vec<OsString> = vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf x >> executed".into(),
                "".into(),
                OsString::from_vec(b"private-arg\xff\n\x1b".to_vec()),
            ];
            command.arg("--").args(&args);
            let expected: Vec<u8> = args
                .iter()
                .flat_map(|a| a.as_bytes().iter().copied().chain([0]))
                .collect();
            let (output, run) = fixture.run(&mut command);
            assert!(
                output.status.success(),
                "{profile}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(run.state, "settled");
            let canonical = fixture.events(&run);
            assert!(
                !serde_json::to_string(&canonical)
                    .unwrap()
                    .contains("private-arg")
            );
            assert!(!serde_json::to_string(&run).unwrap().contains("private-arg"));
            let path = fixture
                .data
                .join("ledger")
                .join(&run.run_id)
                .join("artifacts/argv.bin");
            let display = fixture.client().show_with_transcript(&run.run_id).unwrap();
            if let Some(limit) = limit {
                let kept = expected.len().min(limit);
                assert_eq!(fs::read(&path).unwrap(), expected[..kept]);
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                assert_eq!(run.capture["argv"]["observed_bytes"], expected.len());
                assert_eq!(run.capture["argv"]["stored_bytes"], kept);
                assert_eq!(run.capture["argv"]["truncated"], kept < expected.len());
                assert_eq!(run.capture["argv"]["argument_count"], args.len());
                assert_eq!(run.capture["argv"]["encoding"], "nul_delimited");
                assert_eq!(
                    display["transcript"]["streams"]["argv"]["text"],
                    expected[..kept].escape_ascii().to_string()
                );
                let admission = canonical.iter().find(|v| v["kind"] == "admitted").unwrap();
                assert_eq!(admission["body"]["capture"]["argv"], run.capture["argv"]);
                let bundle = fixture._temp.path().join("argv-bundle");
                ouro_ledger::bundle::create(
                    &mut fixture.client(),
                    &fixture.data,
                    &run.run_id,
                    &bundle,
                    &["argv".into()],
                )
                .unwrap();
                assert_eq!(fs::read(bundle.join("argv.bin")).unwrap(), expected[..kept]);
            } else {
                assert!(!path.exists());
                assert_eq!(
                    display["transcript"]["streams"]["argv"]["state"],
                    "not_captured"
                );
            }
            let ordinary = fixture._temp.path().join("ordinary-bundle");
            ouro_ledger::bundle::create(
                &mut fixture.client(),
                &fixture.data,
                &run.run_id,
                &ordinary,
                &[],
            )
            .unwrap();
            assert!(!ordinary.join("argv.bin").exists());
            let (repeated, replay) = fixture.run(&mut command);
            assert!(repeated.status.success());
            assert_eq!(replay.run_id, run.run_id);
            assert_eq!(fixture.events(&run), canonical);
            assert_eq!(fs::read(fixture.workspace.join("executed")).unwrap(), b"x");
        }
        println!(
            "argv/{profile}: default private, exact native bytes, zero and partial caps, explicit bundle, one execution"
        );
    }
}

#[test]
fn real_argv_capture_survives_owner_death_without_claiming_execution_outcome() {
    let Some(jail) = live_jail() else {
        return;
    };
    for profile in ["tool", "none"] {
        let fixture = Fixture::new(&jail);
        let mut command = fixture.command_with_profile("argv-owner-death", true, profile);
        command.args([
            "--capture",
            "argv",
            "--",
            "/bin/sh",
            "-c",
            "touch started; while test ! -f finish; do sleep 0.05; done",
        ]);
        let mut owner = Process::spawn(&mut command, true);
        let run = fixture.wait_started(&mut owner);
        assert_eq!(run.capture["argv"]["state"], "captured");
        let path = fixture
            .data
            .join("ledger")
            .join(&run.run_id)
            .join("artifacts/argv.bin");
        let bytes = fs::read(&path).unwrap();
        let live = fixture.client().show_with_transcript(&run.run_id).unwrap();
        assert!(live["transcript"]["streams"]["argv"].get("text").is_none());
        owner.kill();
        fixture.assert_tree_stopped(&run);
        fixture.client().settle_orphans().unwrap();
        let dead = fixture.client().show_with_transcript(&run.run_id).unwrap();
        assert_eq!(dead["run"]["state"], "outcome_unknown");
        assert_eq!(dead["transcript"]["streams"]["argv"]["state"], "captured");
        assert_eq!(
            dead["transcript"]["streams"]["argv"]["text"],
            bytes.escape_ascii().to_string()
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        println!(
            "argv/{profile}/owner-death: admission capture retained, tree empty, outcome unknown"
        );
    }
}
