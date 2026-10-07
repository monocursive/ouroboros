use super::*;
use crate::store::tests::{gc_fixture, gc_fixture_captures, gc_future, peer};
use std::os::unix::fs::symlink;

fn stream(store: &Store, run: &RunRecord) -> Value {
    store.show_with_transcript(&run.run_id).unwrap()["transcript"]["streams"]["stdout"].clone()
}

#[test]
fn transcript_is_opt_in_bounded_and_lossless_for_hostile_bytes() {
    let mut bytes = vec![0u8; DISPLAY_BYTES as usize + 1];
    bytes[..12].copy_from_slice(b"hello\x1b\n\r\xff\"\\\0");
    let (_temp, store, run) =
        gc_fixture_captures(&[("stdout", &bytes), ("stderr", &bytes), ("argv", &bytes)]);
    let plain = serde_json::to_value(store.show(&run.run_id).unwrap()).unwrap();
    assert!(plain.get("transcript").is_none());
    let shown = store.show_with_transcript(&run.run_id).unwrap();
    let transcript = &shown["transcript"];
    assert_eq!(shown["run"], plain);
    for name in ["stdout", "stderr", "argv"] {
        let s = &transcript["streams"][name];
        assert_eq!(s["state"], "captured");
        assert_eq!(s["displayed_bytes"], DISPLAY_BYTES);
        assert_eq!(s["display_truncated"], true);
        assert_eq!(
            s["text"],
            bytes[..DISPLAY_BYTES as usize].escape_ascii().to_string()
        );
        assert!(
            s["text"]
                .as_str()
                .unwrap()
                .chars()
                .all(|c| c.is_ascii() && !c.is_control())
        );
    }
    assert!(
        serde_json::to_vec(&store.show_with_transcript(&run.run_id).unwrap())
            .unwrap()
            .len()
            < MAX_FRAME_BYTES
    );
}

#[test]
fn transcript_keeps_capture_loss_separate_from_display_limits() {
    let (_temp, mut store, run) = gc_fixture();
    let metadata = &mut store.streams.get_mut(&run.run_id).unwrap().run.capture["stdout"];
    metadata["truncated"] = json!(true);
    assert_eq!(stream(&store, &run)["state"], "truncated");
    assert_eq!(stream(&store, &run)["display_truncated"], false);
    store.streams.get_mut(&run.run_id).unwrap().run.capture["stdout"]["state"] =
        json!("incomplete");
    let shown = stream(&store, &run);
    assert_eq!(shown["state"], "incomplete");
    assert_eq!(shown["capture_truncated"], true);
    assert_eq!(shown["text"], "private-capture");
    assert_eq!(
        store.show_with_transcript(&run.run_id).unwrap()["transcript"]["streams"]["stderr"]["state"],
        "not_captured"
    );
}

#[test]
fn transcript_never_opens_live_unfinalized_or_unselected_artifacts() {
    for state in ["prepared", "owned", "admitted", "outcome_unknown"] {
        let (_temp, mut store, run) = gc_fixture();
        let r = &mut store.streams.get_mut(&run.run_id).unwrap().run;
        r.state = state.into();
        if state == "outcome_unknown" {
            r.capture["stdout"] = json!({"state":"not_captured"});
        }
        let shown = stream(&store, &run);
        assert_eq!(shown["state"], "incomplete");
        assert!(shown.get("text").is_none());
    }
    let (_temp, mut store, run) = gc_fixture();
    store.streams.get_mut(&run.run_id).unwrap().run.payload["capture"]["streams"] = json!([]);
    assert_eq!(stream(&store, &run)["state"], "not_captured");
    assert!(stream(&store, &run).get("text").is_none());
}

#[test]
fn transcript_refuses_missing_changed_linked_and_public_files_without_blocking() {
    for case in [
        "missing",
        "size",
        "symlink",
        "hardlink",
        "fifo",
        "public",
        "directory",
        "artifacts-symlink",
        "run-symlink",
        "path",
    ] {
        let (temp, mut store, run) = gc_fixture();
        let root = store.root.join(&run.run_id);
        let path = root.join("artifacts/stdout.bin");
        match case {
            "missing" => fs::remove_file(&path).unwrap(),
            "size" => fs::write(&path, b"different").unwrap(),
            "symlink" => {
                fs::rename(&path, temp.path().join("other")).unwrap();
                symlink(temp.path().join("other"), &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, temp.path().join("other")).unwrap(),
            "fifo" => {
                fs::remove_file(&path).unwrap();
                let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            }
            "public" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "directory" => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            "artifacts-symlink" | "run-symlink" => {
                let target = if case == "run-symlink" {
                    root
                } else {
                    root.join("artifacts")
                };
                fs::rename(&target, temp.path().join("other")).unwrap();
                symlink(temp.path().join("other"), &target).unwrap();
            }
            "path" => {
                store.streams.get_mut(&run.run_id).unwrap().run.capture["stdout"]["path"] =
                    json!("../../private")
            }
            _ => unreachable!(),
        }
        let shown = stream(&store, &run);
        assert_eq!(shown["state"], "unavailable", "{case}: {shown}");
        assert!(shown.get("text").is_none(), "{case}");
    }
}

#[test]
fn transcript_reports_empty_captures_and_retention_without_changing_history() {
    let (_temp, mut store, run) = gc_fixture_captures(&[("stdout", b"")]);
    assert_eq!(stream(&store, &run)["text"], "");
    assert_eq!(stream(&store, &run)["state"], "captured");
    let result = store
        .gc_policy_at(
            ouro_records::retention::RetentionPolicy {
                retain_days: 90,
                capture_retain_days: 1,
            },
            None,
            100,
            &peer(),
            gc_future(),
        )
        .unwrap();
    assert_eq!(result.captures_pruned.len(), 1);
    let before = store.show(&run.run_id).unwrap();
    assert_eq!(stream(&store, &run)["state"], "pruned");
    assert!(stream(&store, &run).get("text").is_none());
    assert_eq!(store.show(&run.run_id).unwrap().chain, before.chain);
    store
        .gc_policy_at(
            ouro_records::retention::RetentionPolicy {
                retain_days: 1,
                capture_retain_days: 1,
            },
            None,
            100,
            &peer(),
            gc_future(),
        )
        .unwrap();
    assert_eq!(stream(&store, &run)["state"], "pruned");
    assert!(stream(&store, &run).get("text").is_none());
}

#[test]
fn argv_only_and_all_captures_follow_both_retention_paths() {
    use ouro_records::retention::RetentionPolicy;
    for captures in [
        vec![("argv", b"/bin/true\0".as_slice())],
        vec![
            ("stdout", b"out".as_slice()),
            ("stderr", b"err".as_slice()),
            ("argv", b"/bin/true\0".as_slice()),
        ],
    ] {
        for capture_first in [false, true] {
            let (_temp, mut store, run) = gc_fixture_captures(&captures);
            let root = store.root.join(&run.run_id);
            let history = fs::read(root.join("events-0001.ndjson")).unwrap();
            if capture_first {
                let result = store
                    .gc_policy_at(
                        RetentionPolicy {
                            retain_days: 90,
                            capture_retain_days: 1,
                        },
                        None,
                        100,
                        &peer(),
                        gc_future(),
                    )
                    .unwrap();
                assert_eq!(result.captures_pruned.len(), 1);
                assert_eq!(fs::read(root.join("events-0001.ndjson")).unwrap(), history);
                for (name, _) in &captures {
                    assert!(!root.join(format!("artifacts/{name}.bin")).exists());
                    assert_eq!(
                        store.show_with_transcript(&run.run_id).unwrap()["transcript"]["streams"]
                            [name]["state"],
                        "pruned"
                    );
                }
            }
            let result = store
                .gc_policy_at(
                    RetentionPolicy {
                        retain_days: 1,
                        capture_retain_days: 1,
                    },
                    None,
                    100,
                    &peer(),
                    gc_future(),
                )
                .unwrap();
            assert_eq!(result.pruned.len(), 1);
            for (name, _) in &captures {
                assert!(!root.join(format!("artifacts/{name}.bin")).exists());
            }
            drop(store);
            let store = Store::open(&_temp.path().join("data")).unwrap();
            assert_eq!(
                store.show_with_transcript(&run.run_id).unwrap()["transcript"]["streams"]["argv"]["state"],
                "pruned"
            );
        }
    }
}
