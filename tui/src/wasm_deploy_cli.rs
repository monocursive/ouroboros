//! `ouro wasm keygen | sign | deploy | rollback | ls` — deploying a lane-W capability from
//! a terminal instead of from IEx (docs/WASM.md W12, D15).
//!
//! Everything here is a courier. This client holds no key, composes no manifest, and makes
//! no trust decision:
//!
//! * **`keygen`** is the one command that never touches a runtime. It writes an Ed25519
//!   seed in exactly the format `Ouroboros.Upgrade.Signing.Service` already reads, and
//!   prints the two configuration lines an operator needs — the signer's own
//!   `OUROBOROS_SIGNER_KEY_PATH` and the `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` entry every
//!   core node needs to accept what it signs. It refuses to overwrite: a key file that
//!   already exists may be the one a fleet trusts.
//! * **`sign`** uploads the component and asks the node to sign it. The signature is
//!   produced on a `:signer`-role host by a service that applies the whole policy and
//!   journals its decision (C4); this end sends bytes and writes the answer to a file.
//! * **`deploy`** uploads a `.ouro-wasm` bundle and asks the node to deploy it. The node
//!   verifies it against **its own** trust policy before the store, the helper, or the
//!   rollout register hears about it — so a bundle read off this disk is attacker-
//!   controlled input all the way to the far side, and nothing here pretends otherwise.
//! * **`rollback`** names a live capability to retire, and `ls` renders what a node holds.
//!
//! ## Why the bytes go up in frames
//!
//! A JSON-RPC frame is a line and the gateway bounds one at `OUROBOROS_GATEWAY_MAX_FRAME`
//! — a mebibyte by default, and this client refuses to *send* more than the same number. A
//! component is bounded at sixteen mebibytes, which is twenty-one after base64. So a file
//! crosses through `wasm.upload` in chunks, and the node's reply states the chunk size it
//! will accept so this client sizes the next frame from the answer rather than from a
//! constant of its own (D16).
//!
//! ## Why `sign` writes the file rather than downloading one
//!
//! The node answers with the bundle's *prefix* — the header and the envelope, a few
//! hundred bytes — and this client appends the component it just uploaded. It is the same
//! file the runtime's own encoder would have written, and it needs no chunked download to
//! hand an operator back their own bytes. The prefix states the component length, so this
//! client concatenates and does not compose.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde_json::{json, Map, Value};

use crate::cli::{WasmDeployArgs, WasmKeygenArgs, WasmRollbackArgs, WasmSignArgs};
use crate::model::{WasmDeployment, WasmList, WasmRollback, WasmSignature, WasmUploadReceipt};
use crate::transport::Client;

const UPLOAD_METHOD: &str = "wasm.upload";
const SIGN_METHOD: &str = "wasm.sign";
const DEPLOY_METHOD: &str = "wasm.deploy";
const ROLLBACK_METHOD: &str = "wasm.rollback";
const LIST_METHOD: &str = "wasm.list";

/// How much of a file one frame carries, before the node says otherwise. A quarter of a
/// mebibyte is 349 528 characters of base64, which clears this client's own one-mebibyte
/// outbound ceiling with two thirds to spare — and the node's reply narrows it further
/// whenever the node's own bound is smaller.
const CHUNK_BYTES: usize = 256 * 1024;

/// The largest file this client will try to upload at all. The runtime bounds it too, and
/// says so, but a sixteen-mebibyte refusal is cheaper to make before the first frame.
const MAX_UPLOAD_BYTES: u64 = 17 * 1024 * 1024;

/// An Ed25519 seed is 32 bytes. This is the whole of the private half.
const SEED_BYTES: usize = 32;

/// `ouro wasm keygen` — write a signer seed and print the two lines that put it to work.
///
/// No runtime is contacted and none is needed: this is the operator setting up custody,
/// and the key must never travel. The seed file is `0600` and is never overwritten.
pub fn keygen<O: Write>(args: &WasmKeygenArgs, out: &mut O) -> Result<()> {
    let path = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from("ouro-signer.key"));

    if path.exists() {
        bail!(
            "{} already exists; a signer key file is not something to overwrite by accident — \
             move it aside first if you really mean to mint a new identity",
            path.display()
        );
    }

    let seed = random_seed()?;
    let public = public_key(&seed)?;

    write_private(&path, &base64_line(&seed))
        .with_context(|| format!("writing the signer seed to {}", path.display()))?;

    let encoded = base64::engine::general_purpose::STANDARD.encode(public);

    let text = render_keygen(&args.id, &path, &encoded);
    out.write_all(text.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// `ouro wasm sign` — upload a component, ask the node to sign it, write the bundle.
pub async fn sign<O: Write>(client: &Client, args: &WasmSignArgs, out: &mut O) -> Result<()> {
    let bytes = read_bounded(&args.component)?;

    let upload = upload(client, &bytes, args.node.as_deref()).await?;
    let mut params = sign_params(args, &upload)?;

    if let Some(node) = &args.node {
        params.insert("node".into(), Value::String(node.clone()));
    }

    let answer = client
        .call(SIGN_METHOD, Value::Object(params))
        .await
        .map_err(|error| anyhow!("the runtime refused {SIGN_METHOD}: {error}"))?;

    let signed = WasmSignature::decode(&answer);
    let bundle = args
        .out
        .clone()
        .unwrap_or_else(|| default_bundle_path(&signed, &args.name));

    let prefix = signed
        .bundle_prefix
        .as_deref()
        .ok_or_else(|| anyhow!("the runtime answered {SIGN_METHOD} without a bundle prefix"))?;

    let prefix = base64::engine::general_purpose::STANDARD
        .decode(prefix)
        .context("the runtime's bundle prefix is not base64")?;

    // The whole of this client's knowledge of the format: the node's prefix, then the
    // bytes it just uploaded.
    let mut file = prefix;
    file.extend_from_slice(&bytes);

    std::fs::write(&bundle, &file)
        .with_context(|| format!("writing the bundle to {}", bundle.display()))?;

    let text = if args.json {
        serde_json::to_string_pretty(&answer)?
    } else {
        render_sign(&answer, &bundle)
    };

    out.write_all(text.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// `ouro wasm deploy` — upload a bundle and ask the node to run it.
///
/// Exits non-zero unless the rollout settled `live`, because "it rolled back" and "it is
/// running" are not the same answer and a script should be able to tell them apart.
pub async fn deploy<O: Write>(client: &Client, args: &WasmDeployArgs, out: &mut O) -> Result<()> {
    let bytes = read_bounded(&args.bundle)?;
    let upload = upload(client, &bytes, args.node.as_deref()).await?;

    let mut params = Map::new();
    params.insert("upload".into(), Value::String(upload));

    if let Some(nodes) = &args.nodes {
        params.insert("nodes".into(), Value::Array(node_list(nodes)?));
    }

    if let Some(node) = &args.node {
        params.insert("node".into(), Value::String(node.clone()));
    }

    let answer = client
        .call(DEPLOY_METHOD, Value::Object(params))
        .await
        .map_err(|error| anyhow!("the runtime refused {DEPLOY_METHOD}: {error}"))?;

    let text = if args.json {
        serde_json::to_string_pretty(&answer)?
    } else {
        render_deploy(&answer)
    };

    out.write_all(text.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;

    let deployment = WasmDeployment::decode(&answer);

    if deployment.live() {
        Ok(())
    } else {
        bail!(
            "the rollout settled {} rather than live",
            deployment.state.as_deref().unwrap_or("unknown")
        )
    }
}

/// `ouro wasm rollback` — retire a live capability. Bytes stay in the store (D6).
pub async fn rollback<O: Write>(
    client: &Client,
    args: &WasmRollbackArgs,
    out: &mut O,
) -> Result<()> {
    let mut params = Map::new();
    params.insert("name".into(), Value::String(args.name.clone()));

    if let Some(node) = &args.node {
        params.insert("node".into(), Value::String(node.clone()));
    }

    let answer = client
        .call(ROLLBACK_METHOD, Value::Object(params))
        .await
        .map_err(|error| anyhow!("the runtime refused {ROLLBACK_METHOD}: {error}"))?;

    let text = if args.json {
        serde_json::to_string_pretty(&answer)?
    } else {
        render_rollback(&answer)
    };

    out.write_all(text.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;

    let rolled = WasmRollback::decode(&answer);

    if rolled.rolled_back() {
        Ok(())
    } else {
        bail!(
            "the rollback settled {} rather than rolled_back; a node could not prove the \
             wrapper is gone",
            rolled.state.as_deref().unwrap_or("unknown")
        )
    }
}

/// `ouro wasm ls` — the components and rollouts a node holds.
pub async fn ls<O: Write>(client: &Client, json: bool, out: &mut O) -> Result<()> {
    let answer = client
        .call(LIST_METHOD, json!({}))
        .await
        .map_err(|error| anyhow!("the runtime refused {LIST_METHOD}: {error}"))?;

    let text = if json {
        serde_json::to_string_pretty(&answer)?
    } else {
        render_list(&answer)
    };

    out.write_all(text.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The transfer
// ---------------------------------------------------------------------------

/// Pushes `bytes` through `wasm.upload` and returns the committed upload's id.
///
/// The chunk size starts at this client's own conservative default and narrows to whatever
/// the node says it accepts, so a node with a smaller frame is obeyed rather than argued
/// with. The offset in every frame is what this client believes it has sent; the node
/// refuses a disagreement rather than appending bytes nobody sent.
async fn upload(client: &Client, bytes: &[u8], node: Option<&str>) -> Result<String> {
    if bytes.is_empty() {
        bail!("there is nothing to upload: the file is empty");
    }

    let mut id: Option<String> = None;
    let mut offset: usize = 0;
    let mut chunk = CHUNK_BYTES;

    while offset < bytes.len() {
        let end = (offset + chunk).min(bytes.len());
        let last = end == bytes.len();

        let mut params = Map::new();

        if let Some(id) = &id {
            params.insert("upload".into(), Value::String(id.clone()));
        }

        params.insert("offset".into(), Value::from(offset as u64));
        params.insert(
            "data".into(),
            Value::String(base64::engine::general_purpose::STANDARD.encode(&bytes[offset..end])),
        );

        if last {
            params.insert("final".into(), Value::Bool(true));
        }

        if let Some(node) = node {
            params.insert("node".into(), Value::String(node.to_string()));
        }

        let answer = client
            .call(UPLOAD_METHOD, Value::Object(params))
            .await
            .map_err(|error| anyhow!("the runtime refused {UPLOAD_METHOD}: {error}"))?;

        let receipt = WasmUploadReceipt::decode(&answer);

        if receipt.upload.is_empty() {
            bail!("the runtime answered {UPLOAD_METHOD} without an upload id");
        }

        // The node's own ceiling wins whenever it is narrower than this client's.
        if receipt.chunk_bytes > 0 {
            chunk = chunk.min(receipt.chunk_bytes as usize);
        }

        id = Some(receipt.upload);
        offset = end;

        if last && !receipt.complete {
            bail!("the runtime did not commit the upload after its final frame");
        }
    }

    id.ok_or_else(|| anyhow!("the upload produced no id"))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let size = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .len();

    if size > MAX_UPLOAD_BYTES {
        bail!(
            "{} is {size} bytes; the runtime will not accept more than {MAX_UPLOAD_BYTES}",
            path.display()
        );
    }

    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// The `wasm.sign` parameter object.
///
/// Note what is not here: the durable start **id**. It is derived from the name by the
/// runtime and by the signing policy, so there is no spelling of it a request could get
/// wrong (docs/WASM.md §7.5). `--start-config` supplies the config it starts with, and
/// nothing else about the block is a client's to say.
pub fn sign_params(args: &WasmSignArgs, upload: &str) -> Result<Map<String, Value>> {
    let mut params = Map::new();

    params.insert("upload".into(), Value::String(upload.to_string()));
    params.insert("name".into(), Value::String(args.name.clone()));
    params.insert("author".into(), Value::String(args.author.clone()));

    if let Some(epoch) = args.epoch {
        params.insert("epoch".into(), Value::from(epoch));
    }

    if let Some(imports) = &args.imports {
        let declared: Vec<Value> = imports
            .split(',')
            .map(str::trim)
            .filter(|import| !import.is_empty())
            .map(|import| Value::String(import.to_string()))
            .collect();

        params.insert("imports".into(), Value::Array(declared));
    }

    if let Some(language) = &args.language {
        params.insert("language".into(), Value::String(language.clone()));
    }

    if let Some(sha) = &args.source_sha256 {
        params.insert("source_sha256".into(), Value::String(sha.clone()));
    }

    if let Some(config) = &args.start_config {
        // Parsed here only to fail early on a config the guest could never read; what is
        // sent is the operator's own text, because that is what gets signed.
        serde_json::from_str::<Value>(config).context("--start-config must be JSON")?;
        params.insert("start_config".into(), Value::String(config.clone()));
    }

    if let Some(path) = &args.eval {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the eval spec at {}", path.display()))?;

        let spec: Value = serde_json::from_str(&text)
            .with_context(|| format!("{} is not JSON", path.display()))?;

        params.insert("eval".into(), spec);
    }

    Ok(params)
}

fn node_list(nodes: &str) -> Result<Vec<Value>> {
    let named: Vec<Value> = nodes
        .split(',')
        .map(str::trim)
        .filter(|node| !node.is_empty())
        .map(|node| Value::String(node.to_string()))
        .collect();

    if named.is_empty() {
        bail!("--nodes named no machines; omit it to deploy to the node you are talking to");
    }

    Ok(named)
}

fn default_bundle_path(signed: &WasmSignature, fallback: &str) -> PathBuf {
    let name = signed.name.as_deref().unwrap_or(fallback);
    let extension = signed.extension.as_deref().unwrap_or(".ouro-wasm");

    PathBuf::from(format!("{name}{extension}"))
}

// ---------------------------------------------------------------------------
// The key
// ---------------------------------------------------------------------------

fn random_seed() -> Result<[u8; SEED_BYTES]> {
    use rand::TryRngCore;

    let mut seed = [0u8; SEED_BYTES];

    rand::rngs::OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|error| anyhow!("the operating system would not supply random bytes: {error}"))?;

    Ok(seed)
}

/// The public half, derived exactly as the signing service derives it at boot.
fn public_key(seed: &[u8; SEED_BYTES]) -> Result<Vec<u8>> {
    use ring::signature::KeyPair;

    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|error| anyhow!("that seed is not a usable Ed25519 key: {error}"))?;

    Ok(pair.public_key().as_ref().to_vec())
}

/// The seed file's contents: base64 of the 32 bytes, one line.
///
/// `Ouroboros.Upgrade.Signing.Service.load_key!/1` reads either 32 raw bytes or the base64
/// of them with surrounding whitespace ignored. Text is chosen so a key file survives being
/// copied through a terminal, and so an operator can see at a glance that it is one line
/// and not a component.
fn base64_line(seed: &[u8; SEED_BYTES]) -> String {
    format!(
        "{}\n",
        base64::engine::general_purpose::STANDARD.encode(seed)
    )
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    // `create_new` is the refusal to overwrite, enforced by the filesystem rather than by
    // the `exists()` check above — which is a race on its own.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;

    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;

    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// What an operator does next, in the order they do it.
pub fn render_keygen(id: &str, path: &Path, public_key_base64: &str) -> String {
    let mut lines = Vec::new();

    lines.push(format!("wrote {} (mode 0600)", path.display()));
    lines.push(String::new());
    lines.push("On the signer node — and nowhere else — the private half:".into());
    lines.push(format!("  OUROBOROS_SIGNER_KEY_PATH={}", path.display()));
    lines.push(format!("  OUROBOROS_SIGNER_ID={id}"));
    lines.push(String::new());
    lines.push("On every core node that must accept what it signs — the public half:".into());
    lines.push(format!(
        "  OUROBOROS_UPGRADE_TRUSTED_SIGNERS={id}:{public_key_base64}"
    ));
    lines.push(String::new());
    lines.push(
        "The seed never leaves the signer. A core node needs only the line above it; anyone \
         holding the file can sign as this identity."
            .into(),
    );

    lines.join("\n")
}

/// What was signed, and where the file went.
pub fn render_sign(answer: &Value, bundle: &Path) -> String {
    let signed = WasmSignature::decode(answer);
    let mut lines = Vec::new();

    lines.push(format!(
        "signed {} as {} (epoch {})",
        signed.name.as_deref().unwrap_or("(unnamed)"),
        signed.signer.as_deref().unwrap_or("(unknown signer)"),
        signed
            .epoch
            .map(|epoch| epoch.to_string())
            .unwrap_or_else(|| "(unallocated)".into())
    ));

    lines.push(format!(
        "  component: {} ({} bytes)",
        signed.component_sha256.as_deref().unwrap_or("(unknown)"),
        signed
            .size
            .map(|size| size.to_string())
            .unwrap_or_else(|| "?".into())
    ));

    lines.push(format!(
        "  world: {}",
        signed.world.as_deref().unwrap_or("(unknown)")
    ));

    lines.push(format!(
        "  imports: {}",
        if signed.imports.is_empty() {
            "none declared".to_string()
        } else {
            signed.imports.join(", ")
        }
    ));

    if let Some(start) = signed.start_id.as_deref() {
        lines.push(format!("  starts as: {start}"));
    } else {
        lines.push("  starts as: nothing — this component runs only when a message asks".into());
    }

    lines.push(format!(
        "  artifact: {}",
        signed.artifact_id.as_deref().unwrap_or("(unknown)")
    ));
    lines.push(format!("wrote {}", bundle.display()));
    lines.push(format!(
        "deploy it with: ouro wasm deploy {}",
        bundle.display()
    ));

    lines.join("\n")
}

/// A rollout, gate by gate, node by node.
pub fn render_deploy(answer: &Value) -> String {
    let deployment = WasmDeployment::decode(answer);
    let mut lines = Vec::new();

    lines.push(format!(
        "{} {} — {}",
        deployment.name.as_deref().unwrap_or("(unnamed)"),
        deployment
            .epoch
            .map(|epoch| format!("epoch {epoch}"))
            .unwrap_or_else(|| "epoch ?".into()),
        state_sentence(&deployment)
    ));

    lines.push(format!(
        "  component: {}",
        deployment
            .component_sha256
            .as_deref()
            .unwrap_or("(unknown)")
    ));

    lines.push(format!(
        "  reached: {}",
        deployment.stage.as_deref().unwrap_or("(unknown)")
    ));

    if let Some(started) = &deployment.started {
        lines.push(format!("  wrapper: {}", started_sentence(started)));
    }

    for warning in &deployment.warnings {
        lines.push(format!("  warning: {warning}"));
    }

    for (node, evidence) in &deployment.nodes_evidence {
        lines.push(format!("  {node}:"));
        lines.push(format!("    stage:    {}", evidence.stage.describe()));
        lines.push(format!("    probe:    {}", evidence.probe.describe()));
        lines.push(format!("    eval:     {}", eval_sentence(&evidence.eval)));

        if let Some(recovery) = &evidence.recovery {
            lines.push(format!("    recovery: {recovery}"));
        }
    }

    if let Some(eval) = &deployment.eval {
        lines.push(format!(
            "  spec: {} probe(s), {} required, {} ms budget",
            eval.probes
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into()),
            eval.required.as_deref().unwrap_or("?"),
            eval.budget_ms
                .map(|ms| ms.to_string())
                .unwrap_or_else(|| "?".into())
        ));
    }

    lines.join("\n")
}

fn state_sentence(deployment: &WasmDeployment) -> String {
    match deployment.state.as_deref() {
        Some("live") => "live".into(),
        Some("rolled_back") => {
            "rolled back: every node proved the capability is not running there".into()
        }
        Some("quarantined") => {
            "QUARANTINED: a node may be running something nobody accounted for — this needs a \
             person, not a retry"
                .into()
        }
        Some(other) => other.to_string(),
        None => "the runtime named no state".into(),
    }
}

fn started_sentence(started: &crate::model::WasmStarted) -> String {
    let id = started.id.as_deref().unwrap_or("(unnamed)");

    if let Some(claimed) = &started.claimed_by {
        return format!("{id} is held by a different component ({claimed})");
    }

    match started.node.as_deref() {
        Some(node) if started.already_started => format!("{id} was already running on {node}"),
        Some(node) => format!("{id} started on {node}"),
        None => {
            let reasons = started
                .errors
                .iter()
                .map(|(node, reason)| format!("{node}: {reason}"))
                .collect::<Vec<_>>()
                .join("; ");

            if reasons.is_empty() {
                format!("{id} did not start")
            } else {
                format!("{id} did not start — {reasons}")
            }
        }
    }
}

fn eval_sentence(gate: &crate::model::WasmGate) -> String {
    match (gate.passed, gate.probes) {
        (Some(passed), Some(probes)) => format!("{} ({passed}/{probes})", gate.describe()),
        _ => gate.describe(),
    }
}

/// What a rollback proved, per node.
pub fn render_rollback(answer: &Value) -> String {
    let rolled = WasmRollback::decode(answer);
    let mut lines = Vec::new();

    lines.push(format!(
        "{} — {}",
        rolled.name.as_deref().unwrap_or("(unnamed)"),
        match rolled.state.as_deref() {
            Some("rolled_back") => "rolled back".to_string(),
            Some("quarantined") =>
                "QUARANTINED: a node could not prove the wrapper is gone".to_string(),
            Some(other) => other.to_string(),
            None => "the runtime named no state".to_string(),
        }
    ));

    if let Some(id) = rolled.start_id.as_deref() {
        lines.push(format!("  wrapper: {id}"));
    }

    for (node, recovery) in &rolled.recovery {
        lines.push(format!("  {node}: {}", recovery_sentence(recovery)));
    }

    lines.push(
        "  the component bytes stay in the store: redeploying needs a new epoch and a new \
         signature, not a new build"
            .into(),
    );

    lines.join("\n")
}

fn recovery_sentence(recovery: &str) -> String {
    match recovery {
        "rolled_back" => "stopped".into(),
        "not_needed" => "nothing was running".into(),
        "unchanged" => "left alone — the wrapper there runs a different component".into(),
        "quarantined" => "could not be shown either way".into(),
        other => other.to_string(),
    }
}

/// The two registers an operator reconciles: what the rollout plane believes, and what the
/// store actually holds.
pub fn render_list(answer: &Value) -> String {
    let list = WasmList::decode(answer);
    let mut lines = Vec::new();

    lines.push(format!(
        "{} — {} rollout(s), {} component(s)",
        list.node.as_deref().unwrap_or("(this node)"),
        count(list.rollout_count, list.rollouts.len()),
        count(list.component_count, list.components.len())
    ));

    lines.push(String::new());

    if list.rollouts.is_empty() {
        lines.push("rollouts: none".into());
    } else {
        lines.push("rollouts:".into());
        lines.push("  STATE        NAME                 EPOCH  COMPONENT         NODES".into());

        for rollout in &list.rollouts {
            lines.push(format!(
                "  {:<12} {:<20} {:>5}  {:<16}  {}",
                rollout.state.as_deref().unwrap_or("?"),
                rollout.name.as_deref().unwrap_or("(unnamed)"),
                rollout
                    .epoch
                    .map(|epoch| epoch.to_string())
                    .unwrap_or_else(|| "?".into()),
                short(rollout.component_sha256.as_deref()),
                rollout.nodes.join(", ")
            ));
        }
    }

    lines.push(String::new());

    if list.components.is_empty() {
        lines.push("components: none held".into());
    } else {
        lines.push("components:".into());
        lines.push("  SHA256            BYTES".into());

        for component in &list.components {
            lines.push(format!(
                "  {:<16}  {}",
                short(Some(&component.sha256)),
                component.size
            ));
        }
    }

    lines.join("\n")
}

/// The total the node holds, with the drawn count beside it when the list was cut.
fn count(total: Option<u64>, drawn: usize) -> String {
    match total {
        Some(total) if total as usize > drawn => format!("{drawn} of {total}"),
        Some(total) => total.to_string(),
        None => format!("{drawn} (the register did not answer)"),
    }
}

/// Sixteen characters of a digest. Enough to recognise, short enough for a row.
fn short(sha: Option<&str>) -> String {
    match sha {
        Some(sha) if sha.len() > 16 => sha[..16].to_string(),
        Some(sha) => sha.to_string(),
        None => "(unknown)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../test/support/gateway_golden")
            .join(format!("{name}.json"));

        let bytes = std::fs::read(&path).expect("the golden fixture");
        serde_json::from_slice::<Value>(&bytes).expect("valid JSON")["result"].clone()
    }

    #[test]
    fn keygen_prints_the_two_lines_and_says_which_host_each_belongs_on() {
        let text = render_keygen(
            "release-key",
            Path::new("/etc/ouroboros/release.key"),
            "AAAABBBBCCCC",
        );

        assert!(text.contains("wrote /etc/ouroboros/release.key (mode 0600)"));
        assert!(text.contains("OUROBOROS_SIGNER_KEY_PATH=/etc/ouroboros/release.key"));
        assert!(text.contains("OUROBOROS_SIGNER_ID=release-key"));
        assert!(text.contains("OUROBOROS_UPGRADE_TRUSTED_SIGNERS=release-key:AAAABBBBCCCC"));
        // The private half's whole rule, said out loud where an operator reads it.
        assert!(text.contains("never leaves the signer"));
    }

    /// The public key this client derives is the one the runtime would derive from the same
    /// seed. Pinned against a published Ed25519 test vector (RFC 8032, test 1), because a
    /// keygen that derived a *different* public half would print a `trusted_signers` line
    /// that verifies nothing, and no local round trip would catch it.
    #[test]
    fn the_public_half_matches_the_rfc_8032_vector_for_the_same_seed() {
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];

        let expected: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];

        assert_eq!(public_key(&seed).expect("a keypair"), expected.to_vec());
    }

    /// The seed file is exactly one of the two forms the signing service reads.
    #[test]
    fn the_seed_file_is_one_line_of_base64_over_thirty_two_bytes() {
        let seed = [7u8; 32];
        let line = base64_line(&seed);

        assert!(line.ends_with('\n'));

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(line.trim())
            .expect("base64");

        assert_eq!(decoded, seed.to_vec());
    }

    #[test]
    fn keygen_refuses_to_overwrite_a_key_that_already_exists() {
        let dir = std::env::temp_dir().join(format!(
            "ouro-keygen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("signer.key");

        let args = WasmKeygenArgs {
            out: Some(path.clone()),
            id: "release-key".into(),
        };

        let mut out = Vec::new();
        keygen(&args, &mut out).expect("the first keygen writes");
        assert!(path.exists());

        let error = keygen(&args, &mut Vec::new()).expect_err("the second must refuse");
        assert!(error.to_string().contains("already exists"));

        // And the file it refused to touch is unchanged.
        let contents = std::fs::read_to_string(&path).expect("the key file");
        assert_eq!(contents.lines().count(), 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "a signer key readable by anyone else");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_signature_renders_what_was_signed_and_where_the_bundle_went() {
        let text = render_sign(&fixture("wasm_sign_result"), Path::new("vet.ouro-wasm"));

        assert!(text.contains("signed vet as release-key (epoch 7)"));
        assert!(text.contains("component: aaaaaaaa"));
        assert!(text.contains("2097152 bytes"));
        assert!(text.contains("world: ouroboros:capability@0.1.0"));
        assert!(text.contains("imports: log"));
        assert!(text.contains("starts as: wasm/vet"));
        assert!(text.contains("wrote vet.ouro-wasm"));
        assert!(text.contains("ouro wasm deploy vet.ouro-wasm"));
    }

    #[test]
    fn a_manifest_with_no_start_block_says_so_rather_than_leaving_the_line_out() {
        let text = render_sign(&json!({"name": "vet", "start_id": null}), Path::new("x"));

        assert!(text.contains("starts as: nothing"));
        assert!(text.contains("imports: none declared"));
    }

    #[test]
    fn a_live_rollout_renders_every_gate_on_every_node() {
        let text = render_deploy(&fixture("wasm_deploy_result"));

        assert!(text.contains("vet epoch 7 — live"));
        assert!(text.contains("reached: evaluate"));
        assert!(text.contains("wrapper: wasm/vet started on ouroboros@golden"));
        assert!(text.contains("ouroboros@golden:"));
        assert!(text.contains("stage:    ok"));
        assert!(text.contains("probe:    ok"));
        assert!(text.contains("eval:     passed (2/2)"));
        assert!(text.contains("spec: 2 probe(s), all required, 10000 ms budget"));
    }

    /// A quarantine is the one outcome that needs a person, so it does not read like a
    /// retryable failure.
    #[test]
    fn a_quarantined_rollout_says_what_quarantine_means() {
        let text = render_deploy(&json!({
            "name": "vet",
            "epoch": 8,
            "state": "quarantined",
            "stage": "stage",
            "component_sha256": "bbbb",
            "warnings": ["{:driver_not_a_target, :c@h}"],
            "started": null,
            "eval": null,
            "deployment": {
                "a@h": {
                    "stage": {"outcome": "ambiguous", "detail": ":timeout"},
                    "probe": {"outcome": "skipped", "detail": null},
                    "eval": {"outcome": "skipped", "detail": null},
                    "recovery": "quarantined"
                }
            }
        }));

        assert!(text.contains("QUARANTINED"));
        assert!(text.contains("needs a person, not a retry"));
        assert!(text.contains("warning: {:driver_not_a_target"));
        assert!(text.contains("stage:    ambiguous — :timeout"));
        assert!(text.contains("recovery: quarantined"));
    }

    #[test]
    fn a_rolled_back_deployment_reads_as_a_clean_absence() {
        let text = render_deploy(&json!({
            "name": "vet",
            "state": "rolled_back",
            "stage": "evaluate",
            "started": {"id": "wasm/vet", "node": null, "errors": {"a@h": "boom"}},
            "deployment": {}
        }));

        assert!(text.contains("rolled back: every node proved"));
        assert!(text.contains("wasm/vet did not start — a@h: boom"));
    }

    #[test]
    fn a_rollback_says_what_each_node_proved_and_that_the_bytes_stayed() {
        let text = render_rollback(&fixture("wasm_rollback_result"));

        assert!(text.contains("vet — rolled back"));
        assert!(text.contains("wrapper: wasm/vet"));
        assert!(text.contains("ouroboros@golden: stopped"));
        assert!(text.contains("ouroboros@peer: nothing was running"));
        assert!(text.contains("component bytes stay in the store"));
    }

    #[test]
    fn a_rollback_that_could_not_prove_absence_says_so() {
        let text = render_rollback(&json!({
            "name": "vet",
            "state": "quarantined",
            "start_id": "wasm/vet",
            "recovery": {"a@h": "unchanged", "b@h": "quarantined"}
        }));

        assert!(text.contains("QUARANTINED"));
        assert!(text.contains("a@h: left alone — the wrapper there runs a different component"));
        assert!(text.contains("b@h: could not be shown either way"));
    }

    #[test]
    fn ls_renders_both_registers_with_the_totals_beside_them() {
        let text = render_list(&fixture("wasm_list_result"));

        assert!(text.contains("ouroboros@golden — 3 rollout(s), 2 component(s)"));
        assert!(text.contains("live"));
        assert!(text.contains("quarantined"));
        assert!(text.contains("vet"));
        assert!(text.contains("lint"));
        assert!(text.contains("aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn an_empty_node_and_a_silent_register_read_differently() {
        let empty = render_list(&json!({"rollouts": [], "components": [],
            "rollout_count": 0, "component_count": 0}));

        assert!(empty.contains("rollouts: none"));
        assert!(empty.contains("components: none held"));

        let silent = render_list(&json!({}));
        assert!(silent.contains("0 (the register did not answer)"));
    }

    /// A list the runtime cut shows both numbers, so a client sees the cut rather than a
    /// node that appears to hold less than it does.
    #[test]
    fn a_cut_list_shows_the_total_beside_what_was_drawn() {
        let text = render_list(&json!({
            "rollouts": [{"artifact_id": "a", "name": "vet", "state": "live"}],
            "rollout_count": 900,
            "components": [],
            "component_count": 0
        }));

        assert!(text.contains("1 of 900 rollout(s)"));
    }

    #[test]
    fn sign_params_send_the_operator_s_own_config_text_and_never_a_start_id() {
        let args = WasmSignArgs {
            component: PathBuf::from("greeter.wasm"),
            name: "greeter".into(),
            author: "ops".into(),
            epoch: Some(12),
            imports: Some("log, ".into()),
            language: Some("rust".into()),
            source_sha256: None,
            start_config: Some(r#"{"greeting":"hi"}"#.into()),
            eval: None,
            out: None,
            json: false,
            node: None,
            addr: None,
            token_file: None,
        };

        let params = sign_params(&args, "9f2c1d4e8a7b6053f1e2d3c4b5a69780").expect("params");

        assert_eq!(params["upload"], "9f2c1d4e8a7b6053f1e2d3c4b5a69780");
        assert_eq!(params["name"], "greeter");
        assert_eq!(params["author"], "ops");
        assert_eq!(params["epoch"], 12);
        assert_eq!(params["imports"], json!(["log"]));
        assert_eq!(params["language"], "rust");
        // The text, not a re-encoding of it: what the signer covers is what the operator
        // wrote, byte for byte.
        assert_eq!(params["start_config"], r#"{"greeting":"hi"}"#);

        // The durable id is derived by the runtime from the name. There is no parameter for
        // it, so there is no way for a request to name a capability it does not describe.
        assert!(!params.contains_key("start_id"));
        assert!(!params.contains_key("start"));
        assert!(!params.contains_key("source_sha256"));
    }

    #[test]
    fn a_start_config_that_is_not_json_is_refused_before_anything_is_uploaded() {
        let args = WasmSignArgs {
            component: PathBuf::from("greeter.wasm"),
            name: "greeter".into(),
            author: "ops".into(),
            epoch: None,
            imports: None,
            language: None,
            source_sha256: None,
            start_config: Some("greeting = hi".into()),
            eval: None,
            out: None,
            json: false,
            node: None,
            addr: None,
            token_file: None,
        };

        let error = sign_params(&args, "abc").expect_err("must refuse");
        assert!(error.to_string().contains("--start-config must be JSON"));
    }

    #[test]
    fn nodes_are_split_and_an_empty_list_is_a_mistake_worth_naming() {
        assert_eq!(
            node_list("a@h, b@h").expect("two"),
            vec![json!("a@h"), json!("b@h")]
        );

        assert!(node_list(" , ").is_err());
    }

    #[test]
    fn the_default_bundle_path_follows_the_name_the_runtime_signed() {
        let signed = WasmSignature::decode(&fixture("wasm_sign_result"));
        assert_eq!(
            default_bundle_path(&signed, "fallback"),
            PathBuf::from("vet.ouro-wasm")
        );

        // A runtime that named neither still produces a file this client can write.
        let bare = WasmSignature::decode(&json!({}));
        assert_eq!(
            default_bundle_path(&bare, "greeter"),
            PathBuf::from("greeter.ouro-wasm")
        );
    }
}
