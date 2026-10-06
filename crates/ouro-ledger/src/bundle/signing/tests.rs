use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

#[test]
fn generated_keys_are_private_unique_and_never_overwritten_or_exported() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("node");
    let public = keygen(&path).unwrap();
    let secret = fs::read(path.join("private-key.pk8")).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in ["private-key.pk8", "public-key.json"] {
        assert_eq!(
            fs::metadata(path.join(name)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        public,
        serde_json::to_value(
            Signer::load(&path.join("private-key.pk8"))
                .unwrap()
                .public()
        )
        .unwrap()
    );
    assert!(keygen(&path).is_err());
    assert_eq!(fs::read(path.join("private-key.pk8")).unwrap(), secret);
    assert_ne!(keygen(&temp.path().join("other")).unwrap(), public);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
}

#[test]
fn signature_binds_exact_bytes_domain_and_supplied_identity() {
    let temp = tempfile::tempdir().unwrap();
    let node = temp.path().join("node");
    keygen(&node).unwrap();
    let signer = Signer::load(&node.join("private-key.pk8")).unwrap();
    let bytes = b"{\"fixture\":true}\n";
    let envelope = signer.sign(bytes);
    assert_eq!(
        verify(envelope.clone(), bytes, None).unwrap()["trust"],
        "untrusted"
    );
    assert_eq!(
        verify(envelope.clone(), bytes, Some(&signer.public())).unwrap()["trust"],
        "pinned"
    );
    let other = temp.path().join("other");
    keygen(&other).unwrap();
    assert!(
        verify(
            envelope.clone(),
            bytes,
            Some(&trusted_key(&other.join("public-key.json")).unwrap())
        )
        .is_err()
    );
    assert!(verify(envelope.clone(), b"{\"fixture\":false}\n", None).is_err());
    for field in [
        "signature",
        "public_key",
        "key_id",
        "manifest_digest",
        "algorithm",
        "schema",
    ] {
        let mut altered = envelope.clone();
        altered[field] = json!("invalid");
        assert!(verify(altered, bytes, None).is_err(), "{field}");
    }
    // Even a genuine signature from this key is invalid outside the ledger domain.
    let mut wrong_domain = envelope;
    wrong_domain["signature"] = json!(hex(signer.0.sign(bytes).as_ref()));
    assert!(verify(wrong_domain, bytes, None).is_err());
}

#[test]
fn unsafe_malformed_and_oversized_private_keys_refuse() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("node");
    keygen(&path).unwrap();
    let key = path.join("private-key.pk8");
    let original = fs::read(&key).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Signer::load(&key).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&key, path.join("linked")).unwrap();
    assert!(Signer::load(&key).is_err());
    fs::remove_file(path.join("linked")).unwrap();
    fs::rename(&key, path.join("saved")).unwrap();
    symlink(path.join("saved"), &key).unwrap();
    assert!(Signer::load(&key).is_err());
    fs::remove_file(&key).unwrap();
    fs::rename(path.join("saved"), &key).unwrap();
    for contents in [vec![0; 4097], vec![0; 32], original[..20].to_vec()] {
        fs::write(&key, contents).unwrap();
        assert!(Signer::load(&key).is_err());
    }
    fs::write(&key, original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Signer::load(&key).is_err());
}

#[test]
fn public_key_is_a_bounded_explicit_pin_and_refuses_forged_fingerprint() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("node");
    let mut public = keygen(&path).unwrap();
    let key = path.join("public-key.json");
    public["key_id"] = json!(format!("sha256:{}", "0".repeat(64)));
    fs::write(&key, canonical_json(&public).unwrap()).unwrap();
    assert!(trusted_key(&key).is_err());
    fs::write(&key, vec![b'x'; 4097]).unwrap();
    assert!(trusted_key(&key).is_err());
    fs::remove_file(&key).unwrap();
    symlink(path.join("private-key.pk8"), &key).unwrap();
    assert!(trusted_key(&key).is_err());
}
