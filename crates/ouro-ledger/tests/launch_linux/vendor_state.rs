//! North Star §5.4: vendor state disappears after verified tree termination,
//! even when the ledger cannot know the outcome of the attempt.

use super::*;

#[test]
fn vendor_state_is_removed_after_normal_exit_writer_death_and_owner_death() {
    let Some(jail) = live_jail() else {
        return;
    };
    for ending in ["normal", "writer-death", "owner-death"] {
        let mut fixture = Fixture::new(&jail);
        let launch = fixture.config.join("launch");
        fs::create_dir(&launch).unwrap();
        fs::set_permissions(&launch, fs::Permissions::from_mode(0o700)).unwrap();
        let profile = launch.join("fixture.toml");
        fs::write(
            &profile,
            "name = \"fixture\"\njail = \"tool\"\nstate_var = \"FIX_HOME\"\n",
        )
        .unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o600)).unwrap();
        let mut command = fixture.command(ending, true);
        command.args([
            "--launch",
            "fixture",
            "--observe",
            "on",
            "--",
            "/bin/sh",
            "-c",
            "printf private-vendor-content > \"$FIX_HOME/session\"; \
             printf x >> executions; touch started; \
             while [ ! -f finish ]; do sleep 0.02; done",
        ]);
        let mut owner = Process::spawn(&mut command, true);
        let run = fixture.wait_started(&mut owner);
        let attempt = fixture.data.join("attempts").join(&run.attempt_id);
        let vendor = attempt.join("vendor-state");
        assert_eq!(
            fs::read(vendor.join("session")).unwrap(),
            b"private-vendor-content",
            "{ending}: the child must really populate private state before the fault"
        );
        match ending {
            "normal" => {
                fs::write(fixture.workspace.join("finish"), b"go").unwrap();
                assert!(owner.finish().status.success());
            }
            "writer-death" => {
                fixture.writer.kill();
                assert!(!owner.finish().status.success());
            }
            "owner-death" => owner.kill(),
            _ => unreachable!(),
        }
        fixture.assert_tree_stopped(&run);
        // Jail persists a terminal receipt with cleanup pending before
        // removing state. With the owner killed, there is no foreground join
        // to wait for those remaining writes; require both cleanup facts
        // within a bound instead of racing the separate publications.
        let deadline = Instant::now() + COMMAND_LIMIT;
        loop {
            let state: Value =
                serde_json::from_slice(&fs::read(attempt.join("jail-state.json")).unwrap())
                    .unwrap();
            if state["state_cleanup"] == "complete" && !vendor.try_exists().unwrap() {
                break;
            }
            assert!(Instant::now() < deadline, "{ending}: {state}");
            thread::sleep(Duration::from_millis(10));
        }
        if ending == "writer-death" {
            fixture.writer = Fixture::start_writer(&fixture.data);
        }
        fixture.client().settle_orphans().unwrap();
        let final_run = if ending == "normal" {
            let record = fixture.client().show(&run.run_id).unwrap();
            assert_eq!(record.state, "settled");
            record
        } else {
            fixture.assert_unknown(&run.run_id)
        };
        assert_eq!(final_run.child_protection, "enforced");
        let canonical_path = fixture
            .data
            .join("ledger")
            .join(&run.run_id)
            .join("events-0001.ndjson");
        let canonical = fs::read(&canonical_path).unwrap();
        assert!(
            !canonical
                .windows(b"private-vendor-content".len())
                .any(|bytes| bytes == b"private-vendor-content"),
            "{ending}: private state content must not become ledger metadata"
        );
        let retry = Process::spawn(&mut command, true).finish();
        assert_eq!(retry.status.success(), ending == "normal");
        let replay = fixture.client().show(&run.run_id).unwrap();
        assert_eq!(replay.state, final_run.state);
        assert_eq!(replay.run_id, run.run_id);
        assert_eq!(replay.attempt_id, run.attempt_id);
        assert_eq!(replay.chain, final_run.chain);
        assert_eq!(
            fs::read(fixture.workspace.join("executions")).unwrap(),
            b"x"
        );
        assert!(!vendor.try_exists().unwrap());
        let verification = fixture.client().verify(Some(&run.run_id)).unwrap();
        let report = &verification[0];
        assert_eq!(report.child_protection, "enforced");
        if !report.local_consistency {
            // An actual writer SIGKILL can interrupt a canonical frame. That
            // must stay poisoned, including after otherwise successful vendor
            // cleanup. No other verification failure is expected here.
            assert_eq!(ending, "writer-death", "{report:?}");
            assert_eq!(
                report.problems,
                vec!["oversized or interrupted canonical frame; bytes retained".to_owned()]
            );
            let tail = canonical.rsplit(|byte| *byte == b'\n').next().unwrap();
            assert!(!tail.is_empty(), "interrupted frame must lack its newline");
            assert!(tail.len() <= ouro_ledger::protocol::MAX_FRAME_BYTES);
            assert_eq!(replay.state, "outcome_unknown");
            assert_eq!(replay.coverage["status"], "degraded");
            eprintln!("vendor-state/writer-death: interrupted frame retained and reported");
        }
        assert_eq!(
            fs::read(&canonical_path).unwrap(),
            canonical,
            "verification and replay must preserve every canonical byte"
        );
        eprintln!("vendor-state/{ending}: populated, tree empty, removed, replay unchanged");
    }
}
