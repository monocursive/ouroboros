use super::*;
use crate::{
    protocol::{OperatorIntent, Peer},
    store::{Store, private_directory},
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};

struct Fixture {
    temp: tempfile::TempDir,
    data: PathBuf,
    store: Store,
    run: RunRecord,
}
fn peer() -> Peer {
    Peer {
        uid: unsafe { libc::geteuid() },
        pid: std::process::id(),
        birth: "bundle-test".into(),
        boot_id: "bundle-boot".into(),
    }
}
impl Fixture {
    fn new() -> Self {
        Self::with_captures(&["stdout"])
    }
    fn with_captures(names: &[&str]) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut store = Store::open(&data).unwrap();
        let mut payload: Value = serde_json::from_str(include_str!(
            "../../../../docs/specs/ledger-v1/fixtures/request.json"
        ))
        .unwrap();
        payload["profile"] = json!("none");
        payload["capture"]["streams"] = json!(names);
        let run = store.prepare("bundle-test", &payload, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        let artifacts = data.join("ledger").join(&run.run_id).join("artifacts");
        private_directory(&artifacts).unwrap();
        let mut capture = json!({"stdout":{"state":"not_captured"},"stderr":{"state":"not_captured"},"argv":{"state":"not_captured"}});
        for name in names {
            let bytes: &[u8] = if *name == "argv" {
                b"/bin/true\0\0private-arg\xff\0"
            } else {
                b"capture"
            };
            capture[*name] = json!({"state":"captured","stored_bytes":bytes.len(),"path":format!("artifacts/{name}.bin")});
            let path = artifacts.join(format!("{name}.bin"));
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        store
            .append_owner(
                &run.run_id,
                "terminal",
                "denied",
                None,
                &json!({"outcome":{"kind":"refused"}, "capture":capture,
            "coverage":{"status":"degraded","gaps":[{"reason":"fixture gap"}]}}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        Self {
            temp,
            data,
            store,
            run,
        }
    }
    fn bundle(&mut self, captures: &[&str]) -> PathBuf {
        let path = self
            .temp
            .path()
            .join(format!("bundle-{}", uuid::Uuid::new_v4()));
        create_with_reader(
            &self.data,
            &self.run.run_id,
            &path,
            &captures.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
            |q| self.store.read(q),
        )
        .unwrap();
        path
    }
    fn artifact(&self) -> PathBuf {
        self.data
            .join("ledger")
            .join(&self.run.run_id)
            .join("artifacts/stdout.bin")
    }
}
fn alter_manifest(path: &Path, edit: impl FnOnce(&mut Value)) {
    let p = path.join("bundle.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    edit(&mut value);
    fs::write(p, canonical_json(&value).unwrap()).unwrap();
}
fn rehash(path: &Path, name: &str) {
    let bytes = fs::read(path.join(name)).unwrap();
    alter_manifest(path, |value| {
        for file in value["files"].as_array_mut().unwrap() {
            if file["name"] == name {
                file["bytes"] = json!(bytes.len());
                file["digest"] = json!(sha256_prefixed(&bytes));
            }
        }
    });
}

#[test]
fn portable_bundle_preserves_bytes_and_labels_without_implicit_captures() {
    let mut f = Fixture::new();
    let canonical = fs::read(
        f.data
            .join("ledger")
            .join(&f.run.run_id)
            .join("events-0001.ndjson"),
    )
    .unwrap();
    let path = f.bundle(&[]);
    assert!(!path.join("stdout.bin").exists());
    assert_eq!(fs::read(path.join("events.ndjson")).unwrap(), canonical);
    let moved = f.temp.path().join("moved");
    fs::rename(path, &moved).unwrap();
    drop(f.store);
    fs::remove_dir_all(&f.data).unwrap();
    let report = verify(&moved).unwrap();
    assert_eq!(report["child_protection"], "unprotected");
    assert_eq!(report["coverage"]["status"], "degraded");
    assert_eq!(report["external_custody"], false);
    assert_eq!(report["authenticity"], "unsigned");
}

#[test]
fn selected_capture_is_exact_private_and_blocks_retention() {
    let mut f = Fixture::new();
    let path = f.bundle(&["stdout"]);
    assert_eq!(fs::read(path.join("stdout.bin")).unwrap(), b"capture");
    assert_eq!(
        fs::metadata(path.join("stdout.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(verify(&path).unwrap()["captures"], json!(["stdout"]));
    let plan = f.store.gc_plan(1, None, 100).unwrap();
    assert!(
        plan.runs[0]
            .keep_reasons
            .contains(&"reader_snapshot".into())
    );
    assert!(
        plan.runs[0]
            .captures_keep_reasons
            .contains(&"reader_snapshot".into())
    );
    fs::write(path.join("stdout.bin"), b"changed").unwrap();
    assert!(verify(&path).is_err());
}

#[test]
fn altered_projection_receipts_and_inventory_refuse_even_with_new_hashes() {
    let mut f = Fixture::new();
    for mutation in 0..6 {
        let path = f.bundle(&[]);
        match mutation {
            0 => alter_manifest(&path, |v| v["run"]["child_protection"] = json!("enforced")),
            1 => alter_manifest(&path, |v| {
                v["run"]["coverage"] = json!({"status":"complete"})
            }),
            2 => {
                fs::write(path.join("receipts.json"), b"[{}]\n").unwrap();
                rehash(&path, "receipts.json");
            }
            3 => alter_manifest(&path, |v| v["files"][0]["name"] = json!("../outside")),
            4 => alter_manifest(&path, |v| v["authenticity"] = json!("signed")),
            _ => {
                fs::write(path.join("vendor-state"), b"never export").unwrap();
            }
        }
        assert!(verify(&path).is_err(), "mutation {mutation}");
    }
}

#[test]
fn broken_canonical_chain_and_interrupted_frame_refuse_rehashed_inventory() {
    let mut f = Fixture::new();
    for mutation in 0..4 {
        let path = f.bundle(&[]);
        let events = path.join("events.ndjson");
        let mut bytes = fs::read(&events).unwrap();
        match mutation {
            0 => {
                bytes.pop();
            }
            1 => {
                let start = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
                bytes.drain(..start);
            }
            2 => {
                bytes.extend_from_within(..);
            }
            _ => {
                bytes.insert(1, b' ');
            }
        }
        fs::write(events, bytes).unwrap();
        rehash(&path, "events.ndjson");
        assert!(verify(&path).is_err(), "mutation {mutation}");
    }
}

#[test]
fn unsafe_missing_or_oversized_members_refuse_without_following_links() {
    let mut f = Fixture::new();
    for mutation in 0..5 {
        let path = f.bundle(&[]);
        let p = path.join("events.ndjson");
        let saved = f.temp.path().join(format!("saved-{mutation}"));
        fs::rename(&p, &saved).unwrap();
        match mutation {
            0 => symlink(&saved, &p).unwrap(),
            1 => fs::hard_link(&saved, &p).unwrap(),
            2 => fs::create_dir(&p).unwrap(),
            3 => {
                File::create(&p)
                    .unwrap()
                    .set_len(MAX_STREAM_BYTES + 1)
                    .unwrap();
            }
            _ => {}
        }
        assert!(verify(&path).is_err(), "mutation {mutation}");
    }
}

#[test]
fn failed_exports_remove_staging_and_never_replace_destination() {
    let mut f = Fixture::new();
    let path = f.bundle(&[]);
    let before = fs::read(path.join("bundle.json")).unwrap();
    assert!(create_with_reader(&f.data, &f.run.run_id, &path, &[], |q| f.store.read(q)).is_err());
    assert_eq!(fs::read(path.join("bundle.json")).unwrap(), before);
    let new = f.temp.path().join("must-not-exist");
    fs::remove_file(f.artifact()).unwrap();
    assert!(
        create_with_reader(&f.data, &f.run.run_id, &new, &["stdout".into()], |q| f
            .store
            .read(q))
        .is_err()
    );
    assert!(!new.exists());
    assert!(
        create_with_reader(&f.data, &f.run.run_id, &new, &[], |_q| Err(error(
            "lost writer"
        )))
        .is_err()
    );
    assert!(fs::read_dir(f.temp.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".ouro-bundle-")
    }));
}

#[test]
fn unsafe_capture_source_and_bad_selection_refuse() {
    let mut f = Fixture::new();
    let original = f.artifact();
    let saved = f.temp.path().join("saved");
    fs::rename(&original, &saved).unwrap();
    symlink(&saved, &original).unwrap();
    let path = f.temp.path().join("absent");
    for selection in [
        vec!["stdout".into()],
        vec!["stderr".into()],
        vec!["stdout".into(), "stdout".into()],
        vec!["../saved".into()],
    ] {
        assert!(
            create_with_reader(&f.data, &f.run.run_id, &path, &selection, |q| f
                .store
                .read(q))
            .is_err()
        );
        assert!(!path.exists());
    }
}

#[test]
fn multi_page_snapshot_excludes_later_appends_and_rejects_changed_labels() {
    let mut f = Fixture::new();
    let intent = OperatorIntent {
        run_id: f.run.run_id.clone(),
        request_id: "large".into(),
        kind: "note".into(),
        effect_id: None,
        body: json!({"text":"z".repeat(60_000)}),
    };
    for n in 0..3 {
        let mut intent = intent.clone();
        intent.request_id = format!("large-{n}");
        f.store.append_operator(&intent, &peer()).unwrap();
    }
    let head = f.store.show(&f.run.run_id).unwrap().chain;
    let output = f.temp.path().join("snapshot");
    let mut count = 0;
    create_with_reader(&f.data, &f.run.run_id, &output, &[], |q| {
        let page = f.store.read(q)?;
        count += 1;
        if count == 1 {
            f.store.append_operator(&intent, &peer())?;
        }
        Ok(page)
    })
    .unwrap();
    assert!(count > 1);
    assert_eq!(verify(&output).unwrap()["snapshot"], json!(head));
    let output = f.temp.path().join("bad-snapshot");
    count = 0;
    assert!(
        create_with_reader(&f.data, &f.run.run_id, &output, &[], |q| {
            let mut page = f.store.read(q)?;
            count += 1;
            if count == 2 {
                page.child_protection = "enforced".into();
            }
            Ok(page)
        })
        .is_err()
    );
    assert!(!output.exists());
}

fn signed(f: &mut Fixture, key: &Path) -> PathBuf {
    let path = f
        .temp
        .path()
        .join(format!("signed-{}", uuid::Uuid::new_v4()));
    let signer = signing::Signer::load(key).unwrap();
    let report = assemble(
        &f.data,
        &f.run.run_id,
        &path,
        &["stdout".into()],
        Some(&signer),
        |q| f.store.read(q),
    )
    .unwrap();
    assert_eq!(report["signature"]["trust"], "pinned");
    path
}

#[test]
fn signed_bundle_preserves_none_and_gaps_and_requires_explicit_trust() {
    let mut f = Fixture::new();
    let keys = f.temp.path().join("keys");
    keygen(&keys).unwrap();
    let path = signed(&mut f, &keys.join("private-key.pk8"));
    let ordinary = verify(&path).unwrap();
    assert_eq!(ordinary["authenticity"], "signed");
    assert_eq!(ordinary["signature"]["trust"], "untrusted");
    assert_eq!(ordinary["child_protection"], "unprotected");
    assert_eq!(ordinary["coverage"]["status"], "degraded");
    assert_eq!(ordinary["external_custody"], false);
    assert_eq!(
        verify_with_key(&path, Some(&keys.join("public-key.json"))).unwrap()["signature"]["trust"],
        "pinned"
    );
    assert!(!path.join("private-key.pk8").exists());
    let other = f.temp.path().join("other");
    keygen(&other).unwrap();
    assert!(verify_with_key(&path, Some(&other.join("public-key.json"))).is_err());
    let unsigned = f.bundle(&[]);
    assert!(verify_with_key(&unsigned, Some(&keys.join("public-key.json"))).is_err());
    assert_eq!(
        verify(&unsigned).unwrap()["schema"],
        "ouro.ledger.bundle-verification/1"
    );
}

#[test]
fn signed_manifest_capture_inventory_and_signature_tampering_refuse() {
    let mut f = Fixture::new();
    let keys = f.temp.path().join("keys");
    keygen(&keys).unwrap();
    for mutation in 0..6 {
        let path = signed(&mut f, &keys.join("private-key.pk8"));
        match mutation {
            0 => alter_manifest(&path, |v| v["run"]["child_protection"] = json!("enforced")),
            1 => {
                fs::write(path.join("stdout.bin"), b"changed").unwrap();
                rehash(&path, "stdout.bin");
            }
            2 => {
                fs::remove_file(path.join("signature.json")).unwrap();
            }
            3 => {
                fs::write(path.join("signature.json"), vec![b' '; 4097]).unwrap();
            }
            4 => {
                let other = f.bundle(&[]);
                fs::copy(other.join("bundle.json"), path.join("bundle.json")).unwrap();
            }
            _ => {
                fs::rename(path.join("signature.json"), keys.join("signature-saved")).unwrap();
                symlink(keys.join("signature-saved"), path.join("signature.json")).unwrap();
            }
        }
        assert!(verify(&path).is_err(), "mutation {mutation}");
        assert!(
            verify_with_key(&path, Some(&keys.join("public-key.json"))).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn stripping_or_replacing_signer_never_satisfies_a_pinned_verification() {
    let mut f = Fixture::new();
    let keys = f.temp.path().join("keys");
    keygen(&keys).unwrap();
    let path = signed(&mut f, &keys.join("private-key.pk8"));
    fs::remove_file(path.join("signature.json")).unwrap();
    alter_manifest(&path, |v| {
        v["schema"] = json!("ouro.ledger.bundle/1");
        v["authenticity"] = json!("unsigned");
    });
    assert_eq!(verify(&path).unwrap()["authenticity"], "unsigned");
    assert!(verify_with_key(&path, Some(&keys.join("public-key.json"))).is_err());
    let other = f.temp.path().join("other");
    keygen(&other).unwrap();
    let replacement = signed(&mut f, &other.join("private-key.pk8"));
    assert_eq!(
        verify(&replacement).unwrap()["signature"]["trust"],
        "untrusted"
    );
    assert!(verify_with_key(&replacement, Some(&keys.join("public-key.json"))).is_err());
}

#[test]
fn valid_pinned_signature_never_overrides_canonical_semantic_checks() {
    let mut f = Fixture::new();
    let keys = f.temp.path().join("keys");
    keygen(&keys).unwrap();
    let path = signed(&mut f, &keys.join("private-key.pk8"));
    alter_manifest(&path, |v| v["run"]["child_protection"] = json!("enforced"));
    let signer = signing::Signer::load(&keys.join("private-key.pk8")).unwrap();
    let bytes = fs::read(path.join("bundle.json")).unwrap();
    let signature = signer.sign(&bytes);
    fs::write(
        path.join("signature.json"),
        canonical_json(&signature).unwrap(),
    )
    .unwrap();
    assert!(signing::verify(signature, &bytes, Some(&signer.public())).is_ok());
    let error = verify_with_key(&path, Some(&keys.join("public-key.json"))).unwrap_err();
    assert!(error.to_string().contains("canonical replay"));
}

#[test]
fn argv_is_exported_only_by_selection_and_all_three_signed_members_verify_offline() {
    let mut f = Fixture::with_captures(&["stdout", "stderr", "argv"]);
    let ordinary = f.bundle(&[]);
    assert!(!ordinary.join("argv.bin").exists());
    let events = fs::read_to_string(ordinary.join("events.ndjson")).unwrap();
    assert!(!events.contains("private-arg"));
    let selected = f.bundle(&["argv"]);
    assert_eq!(verify(&selected).unwrap()["captures"], json!(["argv"]));
    assert_eq!(
        fs::read(selected.join("argv.bin")).unwrap(),
        b"/bin/true\0\0private-arg\xff\0"
    );
    assert!(!selected.join("stdout.bin").exists());
    let keys = f.temp.path().join("keys");
    keygen(&keys).unwrap();
    let path = f.temp.path().join("all-signed");
    let signer = signing::Signer::load(&keys.join("private-key.pk8")).unwrap();
    let report = assemble(
        &f.data,
        &f.run.run_id,
        &path,
        &["stdout".into(), "stderr".into(), "argv".into()],
        Some(&signer),
        |q| f.store.read(q),
    )
    .unwrap();
    assert_eq!(report["captures"].as_array().unwrap().len(), 3);
    drop(f.store);
    fs::remove_dir_all(&f.data).unwrap();
    fs::remove_file(keys.join("private-key.pk8")).unwrap();
    assert_eq!(
        verify_with_key(&path, Some(&keys.join("public-key.json"))).unwrap(),
        report
    );
    fs::write(path.join("argv.bin"), b"tampered").unwrap();
    assert!(verify_with_key(&path, Some(&keys.join("public-key.json"))).is_err());
}
