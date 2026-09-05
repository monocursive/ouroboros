//! Immutable signed revocations. A roster rollback or reissued invitation cannot undo one.
use super::*;

const CAP: usize = 16_384;
const LIMIT: usize = 4_096;

#[derive(Serialize, Deserialize)]
struct Artifact {
    payload: String,
    attestation_pem: String,
}

#[derive(Serialize, Deserialize)]
struct Payload {
    schema: u8,
    fleet_id: String,
    node: String,
    issuer: String,
}

pub(super) fn recognized_filename(name: &str) -> bool {
    name.strip_prefix("revoke-")
        .and_then(|s| s.strip_suffix(".json"))
        .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub fn filename(node: &str) -> String {
    format!(
        "revoke-{}.json",
        crate::update::hex(ring::digest::digest(&ring::digest::SHA256, node.as_bytes()).as_ref())
    )
}

pub fn validate(encoded: &str, fleet_id: &str, ca: &str) -> Result<String> {
    if encoded.len() > CAP {
        bail!("revocation exceeds 16 KiB");
    }
    let artifact: Artifact = serde_json::from_str(encoded).context("decoding signed revocation")?;
    // A revocation is permanent. Verify its signature and digest even after the
    // attestation's issuance window has elapsed; expiry cannot restore access.
    verify_attestation_with_expiry(
        artifact.payload.as_bytes(),
        &artifact.attestation_pem,
        ca,
        "revocation",
        false,
    )?;
    let payload: Payload = serde_json::from_str(&artifact.payload)?;
    if payload.schema != 1 || payload.fleet_id != fleet_id || payload.node.len() > 512 {
        bail!("revocation belongs to another fleet or schema");
    }
    let (machine, host) = payload
        .node
        .strip_prefix("ouro-")
        .and_then(|s| s.split_once('@'))
        .ok_or_else(|| anyhow!("invalid revoked node identity"))?;
    validate_machine(machine)?;
    validate_host(host)?;
    let (issuer, host) = payload
        .issuer
        .strip_prefix("ouro-")
        .and_then(|s| s.split_once('@'))
        .ok_or_else(|| anyhow!("invalid revocation issuer identity"))?;
    if payload.issuer.len() > 512 {
        bail!("revocation issuer is too long");
    }
    validate_machine(issuer)?;
    validate_host(host)?;
    Ok(payload.node)
}

pub fn entries(data_dir: &Path, profile: &Profile) -> Result<Vec<(String, String)>> {
    let root = fleet_dir(data_dir);
    let ca = read_private(&root.join(CA_CERT_FILE), "fleet CA certificate")?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("revoke-") {
            continue;
        }
        if entries.len() == LIMIT {
            bail!("fleet revocation limit reached");
        }
        let encoded = read_private(&entry.path(), "signed revocation")?;
        let node = validate(&encoded, &profile.fleet_id, &ca)?;
        if entry.file_name().to_str() != Some(&filename(&node)) {
            bail!("revocation filename does not match signed identity");
        }
        entries.push((node, encoded));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

pub fn issue(data_dir: &Path, machine: &str, output: &Path) -> Result<String> {
    let _lock = lock_live_fleet_update(data_dir, "ouro fleet revoke")?;
    let profile = load(data_dir)?.ok_or_else(|| anyhow!("create or join a fleet first"))?;
    validate_materials(data_dir, true)?;
    let member = profile
        .members
        .iter()
        .chain(profile.tombstones.iter())
        .find(|member| member.machine == machine)
        .ok_or_else(|| anyhow!("unknown fleet machine {machine}"))?;
    if member.node == profile.node {
        bail!("the invitation authority cannot revoke itself");
    }
    let existing = entries(data_dir, &profile)?;
    if let Some((_, encoded)) = existing.iter().find(|(node, _)| node == &member.node) {
        write_private_new(output, encoded.as_bytes(), "signed revocation")?;
        return Ok(encoded.clone());
    }
    if existing.len() >= LIMIT {
        bail!("fleet revocation limit reached");
    }
    refuse_existing_output(output, "signed revocation")?;
    let root = fleet_dir(data_dir);
    let ca = read_private(&root.join(CA_CERT_FILE), "fleet CA")?;
    let key = Zeroizing::new(read_private(&root.join(CA_KEY_FILE), "fleet CA key")?);
    let payload = serde_json::to_string(&Payload {
        schema: 1,
        fleet_id: profile.fleet_id.clone(),
        node: member.node.clone(),
        issuer: profile.node.clone(),
    })?;
    let attestation_pem = signed_attestation(payload.as_bytes(), &ca, &key, "revocation")?;
    let encoded = serde_json::to_string(&Artifact {
        payload,
        attestation_pem,
    })?;
    persist(data_dir, &profile, &encoded)?;
    write_private_new(output, encoded.as_bytes(), "signed revocation").context(
        "revocation was committed locally; export failed, rerun with a fresh output path",
    )?;
    Ok(encoded)
}

pub fn import(data_dir: &Path, input: &Path) -> Result<String> {
    let _lock = lock_live_fleet_update(data_dir, "ouro fleet revocation import")?;
    let profile = load(data_dir)?.ok_or_else(|| anyhow!("create or join a fleet first"))?;
    let encoded = read_private(input, "signed revocation")?;
    persist(data_dir, &profile, &encoded)?;
    Ok(encoded)
}

fn persist(data_dir: &Path, profile: &Profile, encoded: &str) -> Result<()> {
    let root = fleet_dir(data_dir);
    let ca = read_private(&root.join(CA_CERT_FILE), "fleet CA")?;
    let node = validate(encoded, &profile.fleet_id, &ca)?;
    let entries = entries(data_dir, profile)?;
    if entries.iter().any(|(existing, _)| existing == &node) {
        return sync_parent(&root.join(filename(&node)));
    }
    if entries.len() >= LIMIT {
        bail!("fleet revocation limit reached");
    }
    let path = root.join(filename(&node));
    let staged = root.join(format!(".revocation-{}", random_hex(12)?));
    write_private_new(&staged, encoded.as_bytes(), "staged revocation")?;
    let result = (|| {
        match fs::hard_link(&staged, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let current = read_private(&path, "signed revocation")?;
                if validate(&current, &profile.fleet_id, &ca)? != node {
                    bail!("revocation identity conflict");
                }
            }
            Err(error) => return Err(error.into()),
        }
        sync_parent(&path)
    })();
    let _ = fs::remove_file(staged);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_survives_roster_replay_and_is_inherited_by_new_members() {
        let root = super::super::tests::scratch("revocation");
        let owner = root.join("owner");
        let peer = root.join("peer");
        let newcomer = root.join("new");
        for data in [&owner, &peer, &newcomer] {
            fs::DirBuilder::new().mode(0o700).create(data).unwrap();
        }
        let profile = create(&owner, None, "core", "localhost", ephemeral_ports()).unwrap();
        let invite_file = root.join("peer.ouro");
        invite(&owner, "peer", "localhost", &invite_file, ephemeral_ports()).unwrap();
        join(&peer, &invite_file, Ports::DEFAULT).unwrap();
        let file = root.join("revocation.json");
        let encoded = issue(&owner, "peer", &file).unwrap();
        let ca = read_private(&fleet_dir(&owner).join(CA_CERT_FILE), "CA").unwrap();
        assert_eq!(
            validate(&encoded, &profile.fleet_id, &ca).unwrap(),
            "ouro-peer@localhost"
        );
        let mut tampered: Artifact = serde_json::from_str(&encoded).unwrap();
        tampered.payload = tampered.payload.replace("ouro-peer", "ouro-core");
        assert!(validate(
            &serde_json::to_string(&tampered).unwrap(),
            &profile.fleet_id,
            &ca
        )
        .is_err());
        assert!(validate(&encoded, "another-fleet", &ca).is_err());
        assert!(issue(&owner, "core", &root.join("self.json")).is_err());
        assert!(invite(
            &owner,
            "peer",
            "localhost",
            &root.join("again.ouro"),
            ephemeral_ports()
        )
        .is_err());
        import(&peer, &file).unwrap();
        import(&peer, &file).unwrap();
        assert!(runtime_env(&peer)
            .unwrap_err()
            .to_string()
            .contains("revoked"));
        assert_eq!(
            entries(&peer, &load(&peer).unwrap().unwrap())
                .unwrap()
                .len(),
            1
        );
        let new_invite = root.join("new.ouro");
        invite(&owner, "new", "localhost", &new_invite, ephemeral_ports()).unwrap();
        join(&newcomer, &new_invite, Ports::DEFAULT).unwrap();
        assert_eq!(
            entries(&newcomer, &load(&newcomer).unwrap().unwrap())
                .unwrap()
                .len(),
            1
        );
        assert!(runtime_env(&newcomer).is_ok());
        // Removing a credential file is never an implicit permission to delete other files.
        assert!(!recognized_filename("revoke-😀.json"));
        assert!(recognized_filename(&filename("ouro-peer@localhost")));
        fs::remove_dir_all(root).unwrap();
    }
}
