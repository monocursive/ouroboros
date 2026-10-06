//! Ed25519 signatures bind the exact canonical manifest, with a ledger-only
//! domain. A bundled public key is never an implicit trust anchor.
use super::{canonical_json, error, files};
use crate::protocol::Result;
use ouro_records::canonical::sha256_prefixed;
use ring::{
    rand::SystemRandom,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub(super) const DOMAIN: &[u8] = b"ouro.ledger.bundle-signature/1\0";
const MAX_KEY_BYTES: u64 = 4096;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicKey {
    schema: String,
    algorithm: String,
    key_id: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    algorithm: String,
    key_id: String,
    public_key: String,
    manifest_digest: String,
    signature: String,
}

pub(super) struct Signer(Ed25519KeyPair);

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("String write");
    }
    result
}

fn unhex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(error("invalid Ed25519 key or signature encoding"));
    }
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(result)
}

impl PublicKey {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            schema: "ouro.ledger.signer/1".into(),
            algorithm: "ed25519".into(),
            key_id: sha256_prefixed(bytes),
            public_key: hex(bytes),
        }
    }
    fn bytes(&self) -> Result<[u8; 32]> {
        let bytes = unhex(&self.public_key)?;
        if self.schema != "ouro.ledger.signer/1"
            || self.algorithm != "ed25519"
            || self.key_id != sha256_prefixed(&bytes)
        {
            return Err(error("invalid signer identity"));
        }
        Ok(bytes)
    }
}

fn open_key(path: &Path, secret: bool) -> Result<File> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let leaf = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| error("key path needs a UTF-8 filename"))?;
    let dir = files::directory(parent)?;
    if secret {
        files::private(&dir)?;
    }
    let file = files::member(&dir, leaf, false)?;
    if secret {
        files::private(&file)?;
    }
    if file.metadata()?.len() > MAX_KEY_BYTES {
        return Err(error("key file exceeds 4 KiB"));
    }
    Ok(file)
}

fn key_bytes(file: File) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(MAX_KEY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_KEY_BYTES {
        return Err(error("key file exceeds 4 KiB"));
    }
    Ok(bytes)
}

pub(super) fn trusted_key(path: &Path) -> Result<PublicKey> {
    let bytes = key_bytes(open_key(path, false)?)?;
    let key: PublicKey = serde_json::from_slice(&bytes)?;
    key.bytes()?;
    if canonical_json(&key)? != bytes {
        return Err(error("public key file must be canonical JSON with one LF"));
    }
    Ok(key)
}

impl Signer {
    pub(super) fn load(path: &Path) -> Result<Self> {
        let bytes = key_bytes(open_key(path, true)?)?;
        // Strict PKCS#8 parsing checks the embedded public key against the seed.
        Ed25519KeyPair::from_pkcs8(&bytes)
            .map(Self)
            .map_err(|_| error("invalid Ed25519 PKCS#8 signing key"))
    }
    pub(super) fn public(&self) -> PublicKey {
        PublicKey::from_bytes(self.0.public_key().as_ref())
    }
    pub(super) fn sign(&self, manifest: &[u8]) -> Value {
        let public = self.public();
        let message = [DOMAIN, manifest].concat();
        json!({"schema":"ouro.ledger.bundle-signature/1", "algorithm":"ed25519",
            "key_id":public.key_id, "public_key":public.public_key,
            "manifest_digest":sha256_prefixed(manifest), "signature":hex(self.0.sign(&message).as_ref())})
    }
}

pub(super) fn verify(value: Value, manifest: &[u8], trusted: Option<&PublicKey>) -> Result<Value> {
    let envelope: Envelope = serde_json::from_value(value)?;
    let public = PublicKey {
        schema: "ouro.ledger.signer/1".into(),
        algorithm: envelope.algorithm.clone(),
        key_id: envelope.key_id,
        public_key: envelope.public_key,
    };
    let public_bytes = public.bytes()?;
    if envelope.schema != "ouro.ledger.bundle-signature/1"
        || envelope.manifest_digest != sha256_prefixed(manifest)
    {
        return Err(error("bundle signature does not bind this manifest"));
    }
    let signature = unhex::<64>(&envelope.signature)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, public_bytes)
        .verify(&[DOMAIN, manifest].concat(), &signature)
        .map_err(|_| error("invalid bundle signature"))?;
    if trusted.is_some_and(|key| key != &public) {
        return Err(error("bundle signer does not match the trusted public key"));
    }
    Ok(
        json!({"algorithm":"ed25519", "key_id":public.key_id, "public_key":public.public_key,
        "valid":true, "trust":if trusted.is_some() { "pinned" } else { "untrusted" }}),
    )
}

/// Explicit provisioning only. Never silently generate or replace a node key.
pub(super) fn keygen(output: &Path) -> Result<Value> {
    let stage = files::Staging::new(output)?;
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| error("signing key generation failed"))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| error("generated signing key is invalid"))?;
    let public = PublicKey::from_bytes(pair.public_key().as_ref());
    let mut file = files::member(&stage.dir, "private-key.pk8", true)?;
    file.write_all(pkcs8.as_ref())?;
    file.sync_all()?;
    super::write_json(&stage.dir, "public-key.json", &public)?;
    stage.publish()?;
    Ok(serde_json::to_value(public)?)
}

#[cfg(test)]
mod tests;
