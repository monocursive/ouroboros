use ouro_ledger::{
    protocol::{Peer, ReadFilter, ReadRequest, ReadSelector},
    store::Store,
};
use serde_json::{Value, json};
use std::{fs, path::Path};
fn main() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let peer = Peer {
        uid: unsafe { libc::geteuid() },
        pid: std::process::id(),
        birth: "repro".into(),
        boot_id: "repro".into(),
    };
    let receipt: Value = serde_json::from_str(
        &fs::read_to_string(std::env::var("OURO_READER_RECEIPT_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    let payload = json!({"schema":"ouro.ledger.request/1","profile":"tool","argv_digest":receipt["argv_digest"],"policy_digest":receipt["policy"]["digest"],"requirements":receipt["policy"]["requirements"],"jail_image_digest":receipt["argv_digest"],"io":{"mode":"batch","pty":false},"capture":{"streams":[],"limit_bytes":1048576},"evidence":"strict"});
    let mut store = Store::open(&data).unwrap();
    let run = store.prepare("repro", &payload, &peer).unwrap();
    store.claim_owner(&run.run_id, &peer).unwrap();
    for n in 0..2 {
        store
            .append_owner(
                &run.run_id,
                &format!("note-{n}"),
                "note",
                None,
                &json!({"padding":"x".repeat(100000)}),
                &peer,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
    }
    let mut req = ReadRequest {
        run_id: run.run_id,
        filter: ReadFilter {
            selector: ReadSelector::All,
            stage: None,
            since: None,
            until: None,
        },
        cursor: None,
        limit: 1,
    };
    if std::env::var("OURO_READER_MODE").as_deref() == Ok("parent_sync") {
        let marker = std::env::var("OURO_READER_FSYNC_MARKER").unwrap();
        fs::write(&marker, b"fail ledger directory sync").unwrap();
        let first = store.read(&req);
        println!(
            "reader-directory creation with parent sync fault refuses: {}",
            first.is_err()
        );
        assert!(first.is_err());
        let second = store.read(&req);
        println!(
            "existing reader directory with parent sync fault still refuses: {}",
            second.is_err()
        );
        assert!(second.is_err());
        fs::remove_file(&marker).unwrap();
        let recovered = store.read(&req);
        println!(
            "fresh snapshot after parent sync fault removed succeeds: {}",
            recovered.is_ok()
        );
        assert!(recovered.is_ok());
        return;
    }
    let first = store.read(&req).unwrap();
    req.cursor = first.next_cursor;
    if let Ok(mode) = std::env::var("OURO_READER_MODE") {
        let cursor = req.cursor.clone().unwrap();
        let checkpoint = data
            .join("ledger/readers")
            .join(format!("{}.json", &cursor[..32]));
        let mut envelope: Value = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
        if mode == "corrupt" {
            envelope["digest"] = json!("invalid digest");
            fs::write(&checkpoint, serde_json::to_vec(&envelope).unwrap()).unwrap();
            req.cursor = None;
            let fresh = store.read(&req);
            println!(
                "fresh snapshot after unrelated checkpoint corruption succeeds: {}",
                fresh.is_ok()
            );
            assert!(fresh.is_ok());
            req.cursor = Some(cursor);
            let bad = store.read(&req);
            println!("corrupt checkpoint cursor still refuses: {}", bad.is_err());
            assert!(bad.is_err());
            return;
        }
        if ["labels", "state", "coverage", "empty"].contains(&mode.as_str()) {
            println!(
                "real canonical protection: {}",
                store.show(&req.run_id).unwrap().child_protection
            );
            if mode == "labels" {
                envelope["checkpoint"]["template"]["child_protection"] = json!("enforced");
            }
            if mode == "state" {
                envelope["checkpoint"]["template"]["state"] = json!("settled");
                envelope["checkpoint"]["template"]["stream_status"] = json!("complete");
            }
            if mode == "coverage" {
                envelope["checkpoint"]["template"]["coverage"]["gap_count"] = json!(1);
                envelope["checkpoint"]["template"]["coverage"]["selection_status"] =
                    json!("degraded");
            }
            if mode == "empty" {
                envelope["checkpoint"]["template"]["snapshot"] =
                    json!({"head_seq":0,"head_digest":null});
                envelope["checkpoint"]["accepted_bytes"] = json!(0);
                envelope["checkpoint"]["position"] = json!({"offset":0,"frame_start":0,"pending_bytes":0,"ready_emitted":null,"next_seq":1,"previous_digest":null,"verified":0});
                envelope["checkpoint"]["template"]["child_protection"] = json!("enforced");
                envelope["checkpoint"]["template"]["state"] = json!("settled");
                envelope["checkpoint"]["template"]["stream_status"] = json!("complete");
            }
            envelope["digest"] = json!(ouro_records::canonical::sha256_prefixed(
                &ouro_records::canonical::to_jcs(&envelope["checkpoint"]).unwrap()
            ));
            fs::write(&checkpoint, serde_json::to_vec(&envelope).unwrap()).unwrap();
            drop(store);
            let mut store = Store::open(&data).unwrap();
            let page = store.read(&req);
            println!(
                "forged {} metadata refuses: {} ({:?})",
                mode,
                page.is_err(),
                page.as_ref().err()
            );
            if let Ok(page) = &page {
                println!(
                    "accepted forged empty snapshot: protection={}, state={}, consistency={}, head_seq={}, done={}",
                    page.child_protection,
                    page.state,
                    page.local_consistency,
                    page.snapshot.head_seq,
                    page.done
                );
            }
            assert!(page.is_err());
            return;
        }
    }

    let marker = std::env::var("OURO_READER_FSYNC_MARKER").unwrap();
    fs::write(&marker, b"fail all readers directory fsync").unwrap();
    let failed = store.read(&req);
    println!("checkpoint persist result: {:?}", failed.as_ref().err());
    assert!(failed.is_err());
    let retry = store.read(&req);
    println!("retry while readers fsync still fails: {}", retry.is_ok());
    assert!(
        retry.is_err(),
        "BUG: checkpoint retry acknowledged without a successful namespace sync"
    );
    assert!(Path::new(&marker).exists());
    fs::remove_file(&marker).unwrap();
    let recovered = store.read(&req);
    println!(
        "retry after disabling sync fault succeeds: {}",
        recovered.is_ok()
    );
    assert!(recovered.is_ok());
    let repeated = store.read(&req).unwrap();
    assert_eq!(recovered.unwrap(), repeated);
    println!("successful recovered reply retries identically: true");
}
