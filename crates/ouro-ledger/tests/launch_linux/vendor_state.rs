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
        assert!(
            !vendor.try_exists().unwrap(),
            "{ending}: verified tree termination must clean vendor state"
        );
        let state: Value =
            serde_json::from_slice(&fs::read(attempt.join("jail-state.json")).unwrap()).unwrap();
        assert_eq!(state["state_cleanup"], "complete", "{ending}: {state}");
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
        let canonical = fs::read(
            fixture
                .data
                .join("ledger")
                .join(&run.run_id)
                .join("events-0001.ndjson"),
        )
        .unwrap();
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
        assert!(fixture.client().verify(Some(&run.run_id)).unwrap()[0].local_consistency);
        eprintln!("vendor-state/{ending}: populated, tree empty, removed, replay unchanged");
    }
}
