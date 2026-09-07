//! Investigation and provider-independent evidence verification.
use crate::{cli::AuditCommand, transport::Client};
use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::digest::{Context as Digest, SHA256};
use serde_json::{json, value::RawValue, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

pub async fn run(client: &Client, command: AuditCommand, machine: Option<&str>) -> Result<Value> {
    let (method, mut params) = match command {
        AuditCommand::Restore {
            directory,
            destination,
            expected_digest,
        } => return restore(&directory, &destination, &expected_digest),
        AuditCommand::Artifact { stream_id, blob } => {
            ("audit.artifact", json!({"stream_id":stream_id,"blob":blob}))
        }
        AuditCommand::Retention => ("audit.retention", json!({})),
        AuditCommand::Hold {
            stream_id,
            release,
            reason,
        } => (
            "audit.hold",
            json!({"stream_id":stream_id,"held":!release,"reason":reason}),
        ),
        AuditCommand::Purge { stream_id, reason } => (
            "audit.purge",
            json!({"stream_id":stream_id,"reason":reason}),
        ),
        AuditCommand::Status => ("audit.status", json!({})),
        AuditCommand::Doctor => ("audit.doctor", json!({})),
        AuditCommand::Reindex => ("audit.reindex", json!({})),
        AuditCommand::Flush => ("audit.flush", json!({})),
        AuditCommand::Show {
            stream_id,
            since_seq,
            limit,
        } => (
            "audit.show",
            json!({"stream_id":stream_id,"since_seq":since_seq,"limit":limit}),
        ),
        AuditCommand::Search {
            stream_id,
            session_id,
            actor_id,
            kind,
            model,
            tool,
            since,
            until,
            limit,
            offset,
        } => {
            let mut params = json!({"stream_id":stream_id,"session_id":session_id,"actor_id":actor_id,"kind":kind,"model":model,"tool":tool,"since":since,"until":until,"limit":limit,"offset":offset});
            params.as_object_mut().unwrap().retain(|_, v| !v.is_null());
            ("audit.search", params)
        }
        AuditCommand::Export {
            destination,
            stream_id,
        } => return export(client, &destination, stream_id, machine).await,
        AuditCommand::Verify {
            directory,
            expected_digest,
            trusted_keys,
        } => {
            return verify_with_keys(
                &directory,
                expected_digest.as_deref(),
                trusted_keys.as_deref(),
            )
        }
    };
    if let Some(machine) = machine {
        params["machine"] = json!(machine);
    }
    client
        .call(method, params)
        .await
        .map_err(|e| anyhow!("{method}: {e}"))
}

async fn export(
    client: &Client,
    destination: &Path,
    stream: Option<String>,
    machine: Option<&str>,
) -> Result<Value> {
    let absolute = std::path::absolute(destination)?;
    let destination = absolute.as_path();
    ensure!(!destination.try_exists()?, "destination already exists");
    no_symlinks(destination.parent().unwrap_or(Path::new(".")))?;
    let mut params = stream.map(|s| json!({"stream_id":s})).unwrap_or(json!({}));
    if let Some(machine) = machine {
        params["machine"] = json!(machine);
    }
    let result = client
        .call("audit.export", params)
        .await
        .map_err(|e| anyhow!("audit.export: {e}"))?;
    let id = result["bundle_id"].as_str().context("missing bundle id")?;
    ensure!(valid_id(id), "invalid bundle id");
    let entries = result["manifest"]["files"]
        .as_array()
        .context("missing manifest files")?;
    ensure!(entries.len() <= 100_000, "manifest too large");
    private_dir(destination)?;
    // Manifest is written last. An interrupted download is never a valid bundle.
    for path in entries
        .iter()
        .map(|e| e["path"].as_str().unwrap_or(""))
        .chain(std::iter::once("manifest.json"))
    {
        ensure!(
            path == "manifest.json" || safe_path(path),
            "unsafe evidence path"
        );
        let target = destination.join(path);
        private_dir(target.parent().context("missing parent")?)?;
        let mut file = private_file(&target)?;
        let mut offset = 0u64;
        loop {
            let part = client
                .call(
                    "audit.download",
                    with_machine(json!({"bundle_id":id,"path":path,"offset":offset}), machine),
                )
                .await
                .map_err(|e| anyhow!("audit.download: {e}"))?;
            let bytes = STANDARD.decode(part["data"].as_str().context("missing data")?)?;
            let next = part["next_offset"].as_u64().context("missing offset")?;
            let size = part["size"].as_u64().context("missing size")?;
            ensure!(
                bytes.len() <= 65_536 && next == offset + bytes.len() as u64 && next <= size,
                "invalid download framing"
            );
            file.write_all(&bytes)?;
            offset = next;
            if part["done"] == true {
                ensure!(offset == size, "incomplete download");
                break;
            }
            ensure!(!bytes.is_empty(), "download made no progress");
        }
        file.sync_all()?;
    }
    sync_dir(destination)?;
    verify(destination, Some(id))
}

fn with_machine(mut params: Value, machine: Option<&str>) -> Value {
    if let Some(machine) = machine {
        params["machine"] = json!(machine);
    }
    params
}

pub fn restore(source: &Path, destination: &Path, expected: &str) -> Result<Value> {
    let absolute = std::path::absolute(destination)?;
    let destination = absolute.as_path();
    verify(source, Some(expected))?;
    ensure!(
        !destination.try_exists()?,
        "restore destination already exists"
    );
    no_symlinks(destination.parent().unwrap_or(Path::new(".")))?;
    let mut files = BTreeSet::new();
    inventory(source, source, &mut files)?;
    private_dir(destination)?;
    // Copy the manifest last: an interrupted restore never claims completeness.
    files.remove("manifest.json");
    for path in files
        .iter()
        .map(String::as_str)
        .chain(std::iter::once("manifest.json"))
    {
        let target = destination.join(path);
        private_dir(target.parent().context("missing restore parent")?)?;
        let mut output = private_file(&target)?;
        std::io::copy(&mut File::open(source.join(path))?, &mut output)?;
        output.sync_all()?;
    }
    sync_dir(destination)?;
    let mut result = verify(destination, Some(expected))?;
    result["restored_to"] = json!(destination);
    result["scope"] = json!("evidence_only_no_operational_session_restore");
    Ok(result)
}

/// Verify exact original bytes. RawValue preserves Elixir's float representation;
/// parsing and re-encoding JSON numbers would silently change the chain algorithm.
pub fn verify(directory: &Path, expected: Option<&str>) -> Result<Value> {
    verify_with_keys(directory, expected, None)
}

pub fn verify_with_keys(
    directory: &Path,
    expected: Option<&str>,
    trusted_keys: Option<&Path>,
) -> Result<Value> {
    let keys: BTreeMap<String, String> = if let Some(path) = trusted_keys {
        ensure!(
            fs::metadata(path)?.len() <= 65_536,
            "trusted key file too large"
        );
        serde_json::from_slice(&fs::read(path)?)?
    } else {
        BTreeMap::new()
    };
    ensure!(
        trusted_keys.is_none() || !keys.is_empty(),
        "trusted key file is empty"
    );
    let mut receipts_verified = 0u64;
    no_symlinks(directory)?;
    let manifest_path = directory.join("manifest.json");
    no_symlinks(&manifest_path)?;
    ensure!(
        fs::metadata(&manifest_path)?.len() <= 16_777_216,
        "manifest too large"
    );
    let bytes = fs::read(&manifest_path)?;
    let digest = sha(&bytes);
    if let Some(anchor) = expected {
        ensure!(
            valid_id(anchor) && anchor == digest,
            "manifest does not match supplied trust anchor"
        );
    }
    let manifest: Value = serde_json::from_slice(&bytes)?;
    ensure!(manifest["version"] == 1, "unsupported bundle version");
    let files = manifest["files"].as_array().context("missing files")?;
    let streams = manifest["streams"].as_array().context("missing streams")?;
    ensure!(
        files.len() <= 100_000 && streams.len() <= 100_000,
        "manifest too large"
    );
    let mut listed = BTreeSet::new();
    for entry in files {
        let path = entry["path"].as_str().context("missing path")?;
        ensure!(
            safe_path(path) && listed.insert(path.to_owned()),
            "unsafe or duplicate evidence path"
        );
        let target = directory.join(path);
        no_symlinks(&target)?;
        let meta = fs::metadata(&target)?;
        ensure!(
            meta.is_file() && Some(meta.len()) == entry["bytes"].as_u64(),
            "file size mismatch: {path}"
        );
        ensure!(
            hash_file(&target)? == entry["sha256"].as_str().unwrap_or(""),
            "file hash mismatch: {path}"
        );
    }
    let mut actual = BTreeSet::new();
    inventory(directory, directory, &mut actual)?;
    actual.remove("manifest.json");
    ensure!(actual == listed, "bundle inventory mismatch");
    let mut ids = BTreeSet::new();
    let mut referenced = BTreeSet::new();
    for entry in streams {
        let id = entry["stream_id"].as_str().context("missing stream id")?;
        ensure!(
            valid_id(id) && ids.insert(id.to_owned()),
            "invalid or duplicate stream"
        );
        let prefix = format!("streams/{id}/");
        let paths: Vec<_> = listed.iter().filter(|p| p.starts_with(&prefix)).collect();
        ensure!(!paths.is_empty(), "missing stream");
        let mut sequence = 0u64;
        let mut previous = "0".repeat(64);
        for path in paths {
            let mut reader = BufReader::new(File::open(directory.join(path))?);
            loop {
                let mut line = Vec::new();
                let n = (&mut reader).take(1_048_578).read_until(b'\n', &mut line)?;
                if n == 0 {
                    break;
                }
                ensure!(line.pop() == Some(b'\n'), "partial or oversized record");
                ensure!(
                    !line.is_empty() && line.len() <= 1_048_576,
                    "invalid record size"
                );
                let text = std::str::from_utf8(&line)?;
                let fields: BTreeMap<String, &RawValue> = serde_json::from_str(text)?;
                // Sorting only top-level raw fields preserves nested bytes. Comparing
                // the whole record also rejects duplicate top-level fields.
                ensure!(raw_object(&fields) == text, "record is not canonical");
                ensure!(
                    canonical_raw(serde_json::from_str(text)?)? == text,
                    "nested record fields are not canonical"
                );
                let record: Value = serde_json::from_str(text)?;
                sequence += 1;
                ensure!(record["version"] == 2, "unsupported record version");
                ensure!(
                    record["stream_id"] == id
                        && record["seq"] == sequence
                        && record["event_id"] == format!("{id}:{sequence}"),
                    "record identity mismatch"
                );
                ensure!(record["prev"] == previous, "chain predecessor mismatch");
                let body: BTreeMap<_, _> = fields
                    .into_iter()
                    .filter(|(k, _)| k != "hash" && k != "prev")
                    .collect();
                previous = sha(format!("{previous}{}", raw_object(&body)).as_bytes());
                ensure!(record["hash"] == previous, "chain hash mismatch");
                blob_references(&record, &mut referenced);
                if trusted_keys.is_some() {
                    verify_receipt(directory, &record, &keys)?;
                    receipts_verified += 1;
                }
            }
            let mut file = File::open(directory.join(path))?;
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::End(-1))?;
            let mut last = [0u8; 1];
            file.read_exact(&mut last)?;
            ensure!(last[0] == b'\n', "partial final record");
        }
        ensure!(
            entry["through"] == sequence && entry["head"] == previous,
            "stream head mismatch"
        );
    }
    for path in &listed {
        if path.starts_with("streams/") {
            ensure!(
                ids.contains(path.split('/').nth(1).unwrap_or("")),
                "unlisted stream"
            );
        }
    }
    for id in referenced {
        ensure!(
            valid_id(&id) && listed.contains(&format!("blobs/{id}")),
            "missing referenced blob"
        );
    }
    Ok(
        json!({"manifest_sha256":digest,"streams":streams.len(),"files":files.len(),"scope":manifest["scope"],"receipts_verified":receipts_verified,"custody":if trusted_keys.is_some(){"every_record_has_a_trusted_receipt_inventory_completeness_requires_separate_anchor"}else{"not_verified"},"integrity":if expected.is_some(){"matches_supplied_trust_anchor"}else{"self_consistent_unanchored"}}),
    )
}

fn verify_receipt(directory: &Path, record: &Value, keys: &BTreeMap<String, String>) -> Result<()> {
    let path = directory.join(format!(
        "receipts/{}.json",
        record["hash"].as_str().context("missing hash")?
    ));
    ensure!(fs::metadata(&path)?.len() <= 65_536, "receipt too large");
    let bytes = fs::read(path)?;
    let envelope: BTreeMap<String, &RawValue> = serde_json::from_slice(&bytes)?;
    let raw = envelope.get("receipt").context("missing receipt")?.get();
    let fields: BTreeMap<String, &RawValue> = serde_json::from_str(raw)?;
    ensure!(raw_object(&fields) == raw, "receipt is not canonical");
    let receipt: Value = serde_json::from_str(raw)?;
    let signature: String = serde_json::from_str(
        envelope
            .get("signature")
            .context("missing signature")?
            .get(),
    )?;
    let key_id = receipt["key_id"]
        .as_str()
        .context("missing signing key id")?;
    let public = STANDARD.decode(keys.get(key_id).context("untrusted receipt signing key")?)?;
    ensure!(public.len() == 32, "invalid Ed25519 public key");
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
        .verify(raw.as_bytes(), &STANDARD.decode(signature)?)
        .map_err(|_| anyhow!("receipt signature verification failed"))?;
    ensure!(receipt["version"] == 1, "unsupported receipt version");
    for field in ["organization", "stream_id", "seq", "hash"] {
        ensure!(
            !record[field].is_null() && receipt[field] == record[field],
            "receipt does not bind this record"
        );
    }
    ensure!(
        receipt["accepted_at"].is_string() && receipt["retain_until"].is_string(),
        "missing custody retention statement"
    );
    Ok(())
}

// Preserve number lexemes while rejecting duplicate keys and non-canonical nested
// structure. Ordinary Value re-encoding changes Elixir exponential float bytes.
fn canonical_raw(raw: &RawValue) -> Result<String> {
    let text = raw.get();
    match text.as_bytes().first() {
        Some(b'{') => {
            let fields: BTreeMap<String, &RawValue> = serde_json::from_str(text)?;
            let entries: Result<Vec<String>> = fields
                .iter()
                .map(|(key, value)| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key)?,
                        canonical_raw(value)?
                    ))
                })
                .collect();
            Ok(format!("{{{}}}", entries?.join(",")))
        }
        Some(b'[') => {
            let values: Vec<&RawValue> = serde_json::from_str(text)?;
            let entries: Result<Vec<String>> =
                values.iter().map(|value| canonical_raw(value)).collect();
            Ok(format!("[{}]", entries?.join(",")))
        }
        Some(b'"') => Ok(serde_json::to_string(&serde_json::from_str::<String>(
            text,
        )?)?),
        _ => Ok(text.to_owned()),
    }
}

fn raw_object(fields: &BTreeMap<String, &RawValue>) -> String {
    format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), v.get()))
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn blob_references(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if map.get("store").and_then(Value::as_str) == Some("audit-v2") {
                if let Some(id) = map.get("blob").and_then(Value::as_str) {
                    ids.insert(id.to_owned());
                }
            }
            for v in map.values() {
                blob_references(v, ids);
            }
        }
        Value::Array(values) => {
            for v in values {
                blob_references(v, ids);
            }
        }
        _ => {}
    }
}
fn inventory(root: &Path, dir: &Path, files: &mut BTreeSet<String>) -> Result<()> {
    ensure!(
        dir.strip_prefix(root)?.components().count() <= 2,
        "unexpected evidence directory depth"
    );
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "symlink in bundle");
        if kind.is_dir() {
            inventory(root, &entry.path(), files)?;
        } else {
            ensure!(kind.is_file(), "non-regular evidence file");
            files.insert(
                entry
                    .path()
                    .strip_prefix(root)?
                    .to_str()
                    .context("non UTF-8 path")?
                    .replace('\\', "/"),
            );
        }
        ensure!(files.len() <= 100_001, "bundle too large");
    }
    Ok(())
}
fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn safe_path(path: &str) -> bool {
    let p: Vec<_> = path.split('/').collect();
    match p.as_slice() {
        ["blobs", id] => valid_id(id),
        ["receipts", name] => name.strip_suffix(".json").map(valid_id).unwrap_or(false),
        ["streams", id, name] => {
            valid_id(id)
                && name
                    .strip_suffix(".ndjson")
                    .map(|s| s.len() == 20 && s.bytes().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false)
        }
        _ => false,
    }
}
fn sha(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&SHA256, bytes).as_ref())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Digest::new(&SHA256);
    let mut buf = [0u8; 65_536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(hex(digest.finish().as_ref()))
}
fn no_symlinks(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut part = PathBuf::new();
    for component in absolute.components() {
        part.push(component);
        ensure!(
            !fs::symlink_metadata(&part)?.file_type().is_symlink(),
            "symlink in evidence path"
        );
    }
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        no_symlinks(path)?;
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        private_dir(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)?;
    Ok(())
}
fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifies_the_elixir_export_fixture_with_an_external_digest() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../test/support/audit_bundle");
        let result = verify(
            &path,
            Some("e1103ed2ad314c13494fa3ad05c5e6f3fa5aad896dd58afc5546c9d2a44a3a36"),
        )
        .unwrap();
        assert_eq!(result["streams"], 1);
        let keys =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../test/support/audit-trusted-keys.json");
        let witnessed = verify_with_keys(&path, None, Some(&keys)).unwrap();
        assert_eq!(witnessed["receipts_verified"], 4);
        assert!(verify(&path, Some(&"f".repeat(64))).is_err());
    }

    #[test]
    fn nested_duplicate_keys_are_not_canonical() {
        let raw: &RawValue = serde_json::from_str(r#"{"outer":{"x":1,"x":2}}"#).unwrap();
        assert_ne!(canonical_raw(raw).unwrap(), raw.get());
        let raw: &RawValue = serde_json::from_str(r#"{"a":[1.0e-4,{"b":2}]}"#).unwrap();
        assert_eq!(canonical_raw(raw).unwrap(), raw.get());
    }

    #[test]
    fn rejects_paths_and_unanchored_substitution() {
        assert!(!safe_path("../secret"));
        assert!(!safe_path("blobs/../../secret"));
        assert!(!safe_path("streams/x/1.ndjson"));
        assert!(safe_path(&format!("blobs/{}", "a".repeat(64))));
        assert_ne!(sha(b"original"), sha(b"substitution"));
    }
    #[test]
    fn preserves_wire_floats_and_rejects_duplicates() {
        let raw = r#"{"a":{"temperature":1.0e-4},"b":2}"#;
        let fields: BTreeMap<String, &RawValue> = serde_json::from_str(raw).unwrap();
        assert_eq!(raw_object(&fields), raw);
        let duplicate = r#"{"a":1,"a":2}"#;
        let fields: BTreeMap<String, &RawValue> = serde_json::from_str(duplicate).unwrap();
        assert_ne!(raw_object(&fields), duplicate);
    }
}
