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
//!   It also reads the component's **import list** first, with a local `ouro-wasm` resolved
//!   by D14's three-place rule — because the node will not read it (D15) and somebody on
//!   this side has to. `--import` and `--imports-from` still override; `--no-local-helper`
//!   requires one of them; `--dry-run` prints what would be sent and opens no socket.
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
use crate::wasm_client::{self, Helper};

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

/// What the node's manifest accepts, so a list it would refuse is refused on this side with a
/// sentence about the list rather than on the far side with one about a manifest.
const MAX_IMPORTS: usize = 8;

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
    // Absolute before anything touches the filesystem, because the path this command prints
    // is a line an operator pastes into a signer node's environment and
    // `config/runtime.exs` refuses a relative `OUROBOROS_SIGNER_KEY_PATH` outright: a
    // `:signer` node started with one does not boot. `ouro wasm keygen --out ./signer.key`
    // printed `./signer.key`, which is a working file and an instruction that cannot be
    // followed — and the refusal lands on a different machine, later, with nothing in it
    // pointing back here.
    let path = absolute(
        &args
            .out
            .clone()
            .unwrap_or_else(|| PathBuf::from("ouro-signer.key")),
    )?;

    if path.exists() {
        bail!(
            "{} already exists; a signer key file is not something to overwrite by accident — \
             move it aside first if you really mean to mint a new identity",
            path.display()
        );
    }

    signer_id(&args.id)?;

    let seed = random_seed()?;
    let public = public_key(&seed)?;

    write_private(&path, &base64_line(&seed))
        .with_context(|| format!("writing the signer seed to {}", path.display()))?;

    let encoded = base64::engine::general_purpose::STANDARD.encode(public);

    // Canonical only after the file exists: `canonicalize` resolves symlinks and `..`, and
    // it needs something to resolve. The absolute form above is what was written and is a
    // perfectly good answer, so a filesystem that will not canonicalize it is not a failure.
    let printed = std::fs::canonicalize(&path).unwrap_or_else(|_error| path.clone());

    let text = render_keygen(&args.id, &printed, &encoded);
    out.write_all(text.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Everything `ouro wasm sign` settles **before** it opens a socket: the component read once
/// into memory, and the `wasm.sign` parameters over it — including the import list, which is
/// this side's to declare (D15) and which comes from a local helper.
///
/// It is a separate step from [`sign`] so that the order is a fact about the program rather
/// than a sentence in a document. The first cut connected, read, uploaded and *then* started
/// the helper, while three documents said the helper came first; a recording gateway and a spy
/// helper showed a refused component reaching the gateway and never reaching a helper at all.
pub struct SignPlan {
    /// The component, read once. The bytes uploaded are these bytes.
    bytes: Vec<u8>,
    /// The `wasm.sign` parameters, with no `upload` yet — that is the one thing a socket
    /// produces.
    params: Map<String, Value>,
}

impl SignPlan {
    /// The parameters as they would be sent, with `upload` null. `--dry-run` prints this.
    pub fn as_params(&self) -> Map<String, Value> {
        let mut params = self.params.clone();
        params.insert("upload".into(), Value::Null);
        params
    }
}

/// Read the component and settle the parameters, contacting nothing but a local helper.
///
/// Every refusal this command can reach on its own — a file past the byte ceiling, a component
/// this machine's helper will not admit, an import list the node would not accept, a
/// `--start-config` that is not JSON — happens here, which is before a gateway has been dialled
/// and therefore before an operator's credentials have been offered to anything.
pub fn plan_sign(args: &WasmSignArgs) -> Result<SignPlan> {
    let bytes = read_bounded(&args.component)?;
    let params = sign_params(args, "", &bytes)?;

    Ok(SignPlan { bytes, params })
}

/// `ouro wasm sign` — upload the planned component, ask the node to sign it, write the bundle.
pub async fn sign<O: Write>(
    client: &Client,
    args: &WasmSignArgs,
    plan: SignPlan,
    out: &mut O,
) -> Result<()> {
    let SignPlan { bytes, mut params } = plan;

    let upload = upload(client, &bytes, args.node.as_deref()).await?;
    params.insert("upload".into(), Value::String(upload));

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

    // The manifest that came back must describe the file that went up. This client cannot
    // verify a signature — it holds no trusted key, and the node it is talking to is the
    // one that would have to be lying — but it can refuse to write a bundle whose two
    // halves disagree, which is the failure a truncated upload or a confused node produces
    // and which would otherwise surface as a quarantine on some other machine later.
    describes(&signed, &bytes, prefix.len())?;

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

/// `ouro wasm sign --dry-run` — the parameters a plan would send, and then nothing.
///
/// The plan is the same one the real run makes, so this prints the answer your helper gave
/// about these bytes. What `--dry-run` adds over the real path is only where it stops: the
/// real path also reads the component and puts it to the helper before it dials anything, and
/// then goes on to dial.
pub fn render_plan<O: Write>(plan: &SignPlan, args: &WasmSignArgs, out: &mut O) -> Result<()> {
    let mut params = plan.as_params();

    if let Some(node) = &args.node {
        params.insert("node".into(), Value::String(node.clone()));
    }

    writeln!(
        out,
        "{}",
        serde_json::to_string_pretty(&Value::Object(params))?
    )?;
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

    // Bounded, because a node that answered a different offset every time would otherwise
    // be a loop. Two resumes is one more than a retried frame needs.
    let mut resumes: u8 = 2;

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

        let answer = match client.call(UPLOAD_METHOD, Value::Object(params)).await {
            Ok(answer) => answer,

            // The node refuses a frame whose offset is not where it is, and says where it
            // is in the error's `data`. That is the one refusal a client can act on rather
            // than report: a retried or reordered frame resumes from the node's own number
            // instead of ending the transfer.
            Err(error) => match held_offset(&error) {
                Some(held) if held <= bytes.len() && held != offset && resumes > 0 => {
                    resumes -= 1;
                    offset = held;
                    continue;
                }
                _other => {
                    return Err(anyhow!("the runtime refused {UPLOAD_METHOD}: {error}"));
                }
            },
        };

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

/// Refuses a signature whose manifest is not about the bytes this client uploaded.
pub fn describes(signed: &WasmSignature, bytes: &[u8], prefix_len: usize) -> Result<()> {
    let digest = sha256_hex(bytes);

    match signed.component_sha256.as_deref() {
        Some(sha) if sha == digest => {}
        Some(sha) => bail!(
            "the runtime signed a manifest for component {sha}, but the file uploaded hashes \
             to {digest}"
        ),
        None => bail!("the runtime answered {SIGN_METHOD} without a component digest"),
    }

    match signed.size {
        Some(size) if size == bytes.len() as u64 => {}
        Some(size) => bail!(
            "the runtime signed a manifest for {size} bytes, but the file uploaded is {} bytes",
            bytes.len()
        ),
        None => bail!("the runtime answered {SIGN_METHOD} without a component size"),
    }

    let expected = prefix_len as u64 + bytes.len() as u64;

    match signed.bundle_bytes {
        Some(total) if total == expected => Ok(()),
        Some(total) => bail!(
            "the runtime says the bundle is {total} bytes; the prefix and the component are \
             {expected}"
        ),
        None => Ok(()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);

    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The offset a node says it holds, out of an `offset_mismatch` refusal's `data`.
///
/// `None` for every other error: a client resumes only where the node named a place to
/// resume from, never by guessing from a message.
pub fn held_offset(error: &crate::transport::ClientError) -> Option<usize> {
    let crate::transport::ClientError::Rpc(error) = error else {
        return None;
    };

    let data = error.data.as_ref()?;

    if data.get("reason").and_then(Value::as_str) != Some("offset_mismatch") {
        return None;
    }

    data.get("offset")
        .and_then(Value::as_u64)
        .map(|offset| offset as usize)
}

/// How much of an `ouro wasm inspect --json` report is read before it is parsed.
///
/// A real one over a component with eight imports is a couple of kilobytes. This is a file (or
/// a pipe) somebody else may have written, and an unbounded `read_to_string` on a FIFO with a
/// generous writer is a client that never returns — the same fault `check` had for
/// `ouroboros.toml` and the same fix.
const MAX_REPORT_BYTES: u64 = 64 * 1024;

/// An inspect report, from a file or from stdin, bounded either way.
///
/// `take(limit + 1)` and not a `metadata()` check: a bound taken from a stat is not a bound,
/// because `/dev/zero` and a growing file both report a length that has nothing to do with
/// what a read returns.
fn read_report(path: &Path) -> Result<String> {
    use std::io::Read as _;

    let mut buffer = Vec::new();

    if path.as_os_str() == "-" {
        std::io::stdin()
            .lock()
            .take(MAX_REPORT_BYTES + 1)
            .read_to_end(&mut buffer)
            .context("reading the inspect report from stdin")?;
    } else {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("reading the inspect report at {}", path.display()))?;

        if !metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
            bail!(
                "{} is not a regular file, so it is not an inspect report",
                path.display()
            );
        }

        std::fs::File::open(path)
            .with_context(|| format!("reading the inspect report at {}", path.display()))?
            .take(MAX_REPORT_BYTES + 1)
            .read_to_end(&mut buffer)
            .with_context(|| format!("reading the inspect report at {}", path.display()))?;
    }

    if buffer.len() as u64 > MAX_REPORT_BYTES {
        bail!(
            "that inspect report is larger than {MAX_REPORT_BYTES} bytes; a report over a \
             component with at most {MAX_IMPORTS} imports is a few kilobytes"
        );
    }

    String::from_utf8(buffer).context("--imports-from expects `ouro wasm inspect --json` output")
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
pub fn sign_params(args: &WasmSignArgs, upload: &str, bytes: &[u8]) -> Result<Map<String, Value>> {
    let mut params = Map::new();

    params.insert("upload".into(), Value::String(upload.to_string()));
    params.insert("name".into(), Value::String(args.name.clone()));
    params.insert("author".into(), Value::String(args.author.clone()));
    params.insert("imports".into(), Value::Array(imports(args, bytes)?));
    // W15. Always sent, including the default, because it is part of what gets signed and a
    // parameter the client omits is a claim the node fills in — which is the one thing a
    // manifest field deciding which world these bytes may ever enter must not be.
    params.insert("kind".into(), Value::String(args.kind.as_str().to_string()));
    // W8. Only when the operator turned it off. The default is the node's — it is the machine
    // that would do the compiling and the one that knows whether it has a helper — and a client
    // that sent `true` would be asserting something about a machine it cannot see.
    if args.no_precompile {
        params.insert("precompile".into(), Value::Bool(false));
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

/// The import list this client declares on the operator's behalf.
///
/// The node refuses a `wasm.sign` with no `imports` at all, because the alternative was the
/// node handing unsigned bytes to the one process whose job is running other people's code
/// (docs/WASM.md D15). That has not changed and is not this function's to change. What
/// changed in W10b is *who does the typing*: the list is still computed by a helper on this
/// side of the wire, and this command now starts that helper itself rather than making an
/// operator run `ouro wasm inspect --json` and paste the answer back.
///
/// Three sources, in order, and the first one that applies wins:
///
///   1. `--imports-from <report>` — an `ouro wasm inspect --json` document, file or stdin.
///   2. `--import <name>`, repeated.
///   3. This command's own local helper, resolved by D14's three-place rule and vetted the
///      same way [`crate::wasm_cli::inspect`] resolves one.
///
/// `--no-local-helper` removes the third, for a machine that has no helper: then one of the
/// first two is required rather than silently becoming an empty list. An empty list is still
/// a real answer — a component that imports nothing is in this world — and reaches the node
/// through a report whose `imports` array is empty.
fn imports(args: &WasmSignArgs, bytes: &[u8]) -> Result<Vec<Value>> {
    let Some(path) = &args.imports_from else {
        if !args.import.is_empty() {
            return Ok(args
                .import
                .iter()
                .map(|import| Value::String(import.trim().to_string()))
                .collect());
        }

        if args.no_local_helper {
            bail!(
                "--no-local-helper was given and no imports were declared. The node will not \
                 read the component to find out — it never parses bytes it has not verified — \
                 so name them with `--import <name>` (repeated) or `--imports-from <report>`."
            );
        }

        return imports_of(args, bytes);
    };

    let text = read_report(path)?;

    let report: Value = serde_json::from_str(&text)
        .context("--imports-from expects `ouro wasm inspect --json` output")?;

    // Two shapes, because the report may be the whole document or the component object
    // inside it, and an operator piping one should not have to know which.
    let imports = report
        .pointer("/imports")
        .or_else(|| report.pointer("/component/imports"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("--imports-from found no `imports` array in that inspect report"))?;

    if imports.len() > MAX_IMPORTS {
        bail!(
            "that report declares {} imports; the node accepts at most {MAX_IMPORTS}",
            imports.len()
        );
    }

    imports
        .iter()
        .map(|import| {
            import
                .as_str()
                .map(|name| Value::String(name.trim().to_string()))
                .ok_or_else(|| anyhow!("an import in that report is not a string"))
        })
        .collect()
}

/// The component's imports, read by this command's own helper.
///
/// This is the one thing `ouro wasm sign` does that touches wasmtime, and it is deliberately
/// the same thing `ouro wasm inspect` does: resolve a helper by D14's three-place rule
/// (`--helper`, an absolute `$OUROBOROS_WASM_HELPER`, the `ouro-wasm` beside the resolved
/// `ouro`), vet it, start it, ask it. Nothing is derived from the working directory, because
/// the helper is the containment boundary and the directory a component author signs from is
/// the directory the component came from.
///
/// Two questions, both the helper's:
///
///   * `inspect` says what the bytes declare. A refusal here — unreadable, oversize, too
///     complex to compile — is the answer and is named as the helper named it.
///   * `load` says whether this runtime would admit them, which is where the world is
///     actually checked (`world::check`). A component that is not in
///     `ouroboros:capability@0.1.0` is refused *here*, before a byte is uploaded and long
///     before a signing service applies a policy to it — because a signature over a component
///     no node will admit is a signature nobody can use.
fn imports_of(args: &WasmSignArgs, bytes: &[u8]) -> Result<Vec<Value>> {
    let binary = wasm_client::resolve(args.helper.helper.as_deref())?;
    let mut helper = Helper::start(&binary)?;

    let inspected = helper
        .inspect(&args.component)
        .map_err(|error| refused_by_helper(&args.component, error))?;

    // The helper opened the path for itself; this process read it a moment earlier and will
    // upload what *it* read. Between the two there is a window, and a file swapped inside it
    // produces a signed manifest whose import list describes bytes nobody uploaded — caught
    // only at stage, by the node's cross-check, on somebody else's machine. So the two are
    // bound here: the sha the helper reports must be the sha of the bytes in hand.
    let reported = inspected["sha256"].as_str().unwrap_or_default();
    let held = sha256_hex(bytes);

    if !reported.eq_ignore_ascii_case(&held) {
        bail!(
            "{} hashes to {held}, and the helper inspected {} — the file changed between this \
             command reading it and the helper opening it. Nothing is signed over bytes that \
             are not the bytes that would be uploaded.",
            args.component.display(),
            crate::wasm_client::sanitize(reported)
        );
    }

    // `load` recomputes the sha from the file it opens, so passing the one held here closes
    // the same window a second time, at the helper.
    helper
        .load(&held, &args.component)
        .map_err(|error| refused_by_helper(&args.component, error))?;

    let declared = inspected["imports"]
        .as_array()
        .ok_or_else(|| anyhow!("{binary} answered `inspect` without an `imports` array"))?;

    if declared.len() > MAX_IMPORTS {
        bail!(
            "that component declares {} imports; the node accepts at most {MAX_IMPORTS}",
            declared.len()
        );
    }

    declared
        .iter()
        .map(|import| {
            import
                .as_str()
                .map(|name| Value::String(name.trim().to_string()))
                .ok_or_else(|| anyhow!("an import in the helper's report is not a string"))
        })
        .collect()
}

/// A helper refusal, said as a reason not to sign. Anything that is not a refusal — a helper
/// that died, a broken pipe — is this command failing and keeps its own error.
fn refused_by_helper(component: &Path, error: anyhow::Error) -> anyhow::Error {
    match wasm_client::refusal_of(&error) {
        Some(refusal) => anyhow!(
            "{} was refused by your own helper and is not signed: {refusal}. A signature over \
             a component no node would admit is a signature nobody can use, so this is refused \
             here rather than at stage.",
            component.display()
        ),
        None => error,
    }
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

/// The charset a signer id may use.
///
/// `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` is a comma-separated list of `id:base64` pairs, so
/// an id holding a comma or a colon produces a line that parses into a different signer —
/// or into none — and the failure surfaces on a core node as an artifact nobody trusts,
/// far from the command that caused it. Whitespace is worse: it survives a round trip
/// through a shell and compares unequal to the id the service signs as.
pub fn signer_id(id: &str) -> Result<()> {
    let usable = !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));

    if usable {
        Ok(())
    } else {
        bail!(
            "--id must be 1 to 64 characters of letters, digits, `-`, `_` or `.`: it is one \
             half of an OUROBOROS_UPGRADE_TRUSTED_SIGNERS entry, which is `id:base64` pairs \
             separated by commas"
        )
    }
}

/// `path` made absolute against the working directory, without requiring it to exist.
///
/// `std::path::absolute` and not `canonicalize`: the file is not there yet, and the point is
/// to have an absolute path *before* deciding whether to write one.
fn absolute(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path)
        .with_context(|| format!("resolving {} against the working directory", path.display()))
}

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
    // Absolute, always: a `:signer` node refuses to boot with a relative one.
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

    // W15. What the manifest says these bytes are, which is what decides the world they will
    // ever be admitted to on any node that reads this bundle.
    lines.push(format!(
        "  kind: {}",
        signed.kind.as_deref().unwrap_or("capability")
    ));

    // W8. What the second form in this bundle is, and the exact pair of readings a node has to
    // match to use it — because "why is this deploy still slow on that box" is answered by
    // comparing two strings, and an operator should be able to read both of them here.
    match &signed.precompiled {
        Some(precompiled) => {
            lines.push(format!(
                "  precompiled: {} ({} bytes) for wasmtime {} on {}",
                short(precompiled.sha256.as_deref()),
                precompiled
                    .size
                    .map(|size| size.to_string())
                    .unwrap_or_else(|| "?".into()),
                precompiled.wasmtime.as_deref().unwrap_or("(unknown)"),
                precompiled.target.as_deref().unwrap_or("(unknown)")
            ));
        }
        None => lines.push(format!(
            "  precompiled: none ({}){}",
            signed.form.as_deref().unwrap_or("source"),
            signed
                .precompile_skipped
                .as_deref()
                .map(|why| format!(" ({why})"))
                .unwrap_or_default()
        )),
    }

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
        // W8. `FORM` is which of the two forms the answering node loads that component from,
        // which is the difference between a `load` that compiles and one that maps. `?` is that
        // node saying it cannot tell — no manifest it can read, or no helper that has reported
        // its build — and is deliberately not drawn as `source`.
        lines.push(
            "  STATE        NAME                 EPOCH  COMPONENT         FORM         NODES"
                .into(),
        );

        for rollout in &list.rollouts {
            lines.push(format!(
                "  {:<12} {:<20} {:>5}  {:<16}  {:<11}  {}",
                rollout.state.as_deref().unwrap_or("?"),
                rollout.name.as_deref().unwrap_or("(unnamed)"),
                rollout
                    .epoch
                    .map(|epoch| epoch.to_string())
                    .unwrap_or_else(|| "?".into()),
                short(rollout.component_sha256.as_deref()),
                rollout.form.as_deref().unwrap_or("?"),
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

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ouro-w12-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    /// Signing arguments for a unit test.
    ///
    /// `no_local_helper` is on, and that is not incidental: since W10b a `sign` with no
    /// declared imports resolves and starts a real `ouro-wasm`, and a unit test that did so
    /// would be an integration test that passes or fails by what is installed on the machine.
    /// The helper path has its own tests in `tui/tests/wasm_cli.rs`, against a real helper.
    fn signing_args(import: Vec<String>, imports_from: Option<PathBuf>) -> WasmSignArgs {
        WasmSignArgs {
            component: PathBuf::from("greeter.wasm"),
            name: "greeter".into(),
            author: "ops".into(),
            kind: crate::cli::WasmKind::Capability,
            import,
            imports_from,
            no_precompile: false,
            no_local_helper: true,
            dry_run: false,
            language: None,
            source_sha256: None,
            start_config: None,
            eval: None,
            out: None,
            json: false,
            node: None,
            helper: crate::cli::WasmHelperArgs { helper: None },
            addr: None,
            token_file: None,
        }
    }

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

    /// The path this command prints is a line an operator pastes into a signer node's
    /// environment, and `config/runtime.exs` refuses a relative `OUROBOROS_SIGNER_KEY_PATH`
    /// outright — the node does not boot, on a different machine, later, with nothing in the
    /// failure pointing back at the command that caused it. Remove the `absolute/1` call
    /// from `keygen` and this is red.
    ///
    /// The working directory is process-global and this test moves it, briefly, the way
    /// `wasm_client.rs`'s helper-resolution test does; it is restored before any assertion
    /// can fail out of it.
    #[test]
    fn keygen_writes_and_prints_an_absolute_path_when_asked_for_a_relative_one() {
        let dir = scratch("keygen-abs");
        let previous = std::env::current_dir().expect("a working directory");

        std::env::set_current_dir(&dir).expect("to move into the scratch directory");

        let written = keygen(
            &WasmKeygenArgs {
                out: Some(PathBuf::from("./signer.key")),
                id: "release-key".into(),
            },
            &mut Vec::new(),
        );

        // A relative default resolves against the same place, so it is asked here too while
        // the working directory is known.
        let defaulted = absolute(Path::new("ouro-signer.key"));

        std::env::set_current_dir(&previous).expect("to move back");

        written.expect("keygen writes");
        let defaulted = defaulted.expect("the default resolves");

        assert!(defaulted.is_absolute());
        assert!(defaulted.ends_with("ouro-signer.key"));

        // Re-render from the file that was actually written, so what is asserted is the line
        // an operator would paste rather than a string this test built.
        let key = std::fs::canonicalize(dir.join("signer.key")).expect("the key file");
        let printed = render_keygen("release-key", &key, "AAAA");

        let line = printed
            .lines()
            .find_map(|line| line.trim().strip_prefix("OUROBOROS_SIGNER_KEY_PATH="))
            .expect("the key path line");

        assert!(
            Path::new(line).is_absolute(),
            "a signer node refuses to boot with a relative key path, and this printed {line}"
        );

        assert!(
            !line.contains("/./"),
            "a `.` component survived into {line}"
        );
        assert!(
            Path::new(line).exists(),
            "the file is not where the line says"
        );

        assert_eq!(
            std::fs::read_to_string(line)
                .expect("the key file")
                .lines()
                .count(),
            1
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `absolute/1` is what makes that true, and it is asked directly because the call site
    /// above can only be exercised by moving the working directory.
    #[test]
    fn absolute_resolves_a_relative_path_and_leaves_an_absolute_one_alone() {
        let here = std::env::current_dir().expect("a working directory");

        let resolved = absolute(Path::new("signer.key")).expect("resolves");
        assert!(resolved.is_absolute());
        assert_eq!(resolved, here.join("signer.key"));

        let already = here.join("elsewhere/signer.key");
        assert_eq!(absolute(&already).expect("resolves"), already);
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

    /// W15. `--kind policy` reaches the wire as `kind: "policy"`.
    #[test]
    fn sign_params_carry_the_kind_the_operator_named() {
        let mut args = signing_args(vec!["log".into()], None);
        args.kind = crate::cli::WasmKind::Policy;

        let params = sign_params(&args, "9f2c1d4e8a7b6053f1e2d3c4b5a69780", b"").expect("params");
        assert_eq!(params["kind"], "policy");
    }

    /// W8. `precompile` is sent only when the operator turned it off. The default belongs to
    /// the node — it is the machine that would do the compiling and the one that knows whether
    /// it has a helper — so a client that sent `true` would be asserting something about a
    /// machine it cannot see.
    #[test]
    fn sign_params_ask_to_skip_the_precompile_only_when_told_to() {
        let mut args = signing_args(vec!["log".into()], None);

        let params = sign_params(&args, "9f2c1d4e8a7b6053f1e2d3c4b5a69780", b"").expect("params");
        assert!(params.get("precompile").is_none());

        args.no_precompile = true;
        let params = sign_params(&args, "9f2c1d4e8a7b6053f1e2d3c4b5a69780", b"").expect("params");
        assert_eq!(params["precompile"], serde_json::Value::Bool(false));
    }

    #[test]
    fn sign_params_send_the_operator_s_own_config_text_and_never_a_start_id() {
        let args = WasmSignArgs {
            language: Some("rust".into()),
            start_config: Some(r#"{"greeting":"hi"}"#.into()),
            ..signing_args(vec!["log".into()], None)
        };

        let params = sign_params(&args, "9f2c1d4e8a7b6053f1e2d3c4b5a69780", b"").expect("params");

        assert_eq!(params["upload"], "9f2c1d4e8a7b6053f1e2d3c4b5a69780");
        assert_eq!(params["name"], "greeter");
        assert_eq!(params["author"], "ops");
        assert_eq!(params["imports"], json!(["log"]));
        // W15. Always sent, including the default: it is part of what gets signed, and a
        // parameter the client omits is a claim the node fills in.
        assert_eq!(params["kind"], "capability");

        // There is no `epoch` parameter at all any more. A number a client chose could be
        // placed at the register's plausibility ceiling, which leaves no epoch that is both
        // fresh and plausible and wedges lane W on that node durably; the node allocates it.
        assert!(!params.contains_key("epoch"));
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
            start_config: Some("greeting = hi".into()),
            ..signing_args(vec!["log".into()], None)
        };

        let error = sign_params(&args, "abc", b"").expect_err("must refuse");
        assert!(error.to_string().contains("--start-config must be JSON"));
    }

    /// A component that imports nothing says so. The node refuses a `wasm.sign` with no
    /// `imports` key at all, because the alternative — it reading the bytes to find out —
    /// is the one thing this lane must not do.
    ///
    /// Since W10b an empty `--import` list is no longer how you say that: no declaration at
    /// all means "read it with my helper". The empty list arrives through a report, which is
    /// still a helper's answer and not a client's guess.
    #[test]
    fn an_empty_import_list_is_sent_as_one_rather_than_omitted() {
        let dir = scratch("imports-empty");
        let path = dir.join("report.json");
        std::fs::write(&path, r#"{"imports": []}"#).unwrap();

        let params = sign_params(&signing_args(vec![], Some(path)), "abc", b"").expect("params");

        assert_eq!(params["imports"], json!([]));
        assert!(params.contains_key("imports"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// With no helper to ask and nothing declared, this refuses rather than sending a list it
    /// made up. Delete the `no_local_helper` arm in `imports` and it starts a helper instead —
    /// on a machine that by assumption has none, so the refusal an operator gets is about a
    /// missing binary rather than about the thing they forgot to type.
    #[test]
    fn no_local_helper_with_nothing_declared_is_refused_and_names_both_flags() {
        let error = sign_params(&signing_args(vec![], None), "abc", b"")
            .expect_err("nothing to declare and nothing to ask");
        let text = error.to_string();

        assert!(text.contains("--import"), "{text}");
        assert!(text.contains("--imports-from"), "{text}");
        // And it never claims the node will work it out, because it will not.
        assert!(
            text.contains("never parses bytes it has not verified"),
            "{text}"
        );
    }

    /// `--import` still overrides, and is not second-guessed against a helper.
    #[test]
    fn a_declared_import_list_is_sent_verbatim() {
        let params =
            sign_params(&signing_args(vec!["log".into()], None), "abc", b"").expect("params");
        assert_eq!(params["imports"], json!(["log"]));
    }

    /// `ouro wasm inspect --json | ouro wasm sign --imports-from -`, without the pipe.
    #[test]
    fn imports_from_reads_an_inspect_report_in_either_shape() {
        let dir = scratch("imports-from");
        let flat = dir.join("flat.json");
        let nested = dir.join("nested.json");

        std::fs::write(&flat, r#"{"imports": ["log"], "world": "x"}"#).unwrap();
        std::fs::write(&nested, r#"{"component": {"imports": ["log", "clock"]}}"#).unwrap();

        let params = sign_params(&signing_args(vec![], Some(flat)), "abc", b"").expect("flat");
        assert_eq!(params["imports"], json!(["log"]));

        let params = sign_params(&signing_args(vec![], Some(nested)), "abc", b"").expect("nested");
        assert_eq!(params["imports"], json!(["log", "clock"]));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The node's manifest accepts at most eight imports, and a report claiming more is refused
    /// here with a sentence about the list rather than on the far side with one about a
    /// manifest. M4: delete the `imports.len() > MAX_IMPORTS` guard in `imports` and this goes
    /// red — nine imports would be uploaded and signed against.
    #[test]
    fn a_report_past_the_import_ceiling_is_refused_before_anything_is_uploaded() {
        let dir = scratch("imports-many");
        let path = dir.join("report.json");
        let many: Vec<String> = (0..=MAX_IMPORTS).map(|n| format!("i{n}")).collect();
        std::fs::write(&path, json!({ "imports": many }).to_string()).unwrap();

        let error = sign_params(&signing_args(vec![], Some(path)), "abc", b"")
            .expect_err("nine imports is more than the node accepts");
        assert!(
            error.to_string().contains("at most 8"),
            "the refusal names the ceiling: {error}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// An inspect report is somebody else's file, and every input is bounded before it is
    /// parsed. L9: delete the `take(MAX_REPORT_BYTES + 1)` in `read_report` and this goes red
    /// — a 65 KiB report would be parsed, and a FIFO with a generous writer would never return.
    #[test]
    fn an_oversize_inspect_report_is_refused_before_it_is_parsed() {
        let dir = scratch("imports-huge");
        let path = dir.join("report.json");
        // Valid JSON, so a refusal can only be the bound and never the parser.
        let padding = " ".repeat(MAX_REPORT_BYTES as usize);
        std::fs::write(&path, format!(r#"{{"imports": ["log"]}}{padding}"#)).unwrap();

        let error = sign_params(&signing_args(vec![], Some(path)), "abc", b"")
            .expect_err("a report past the bound is not read");
        assert!(
            error.to_string().contains("larger than"),
            "the refusal is about the bound: {error}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_report_with_no_imports_array_is_refused_rather_than_read_as_none() {
        let dir = scratch("imports-bad");
        let path = dir.join("report.json");
        std::fs::write(&path, r#"{"world": "x"}"#).unwrap();

        let error = sign_params(&signing_args(vec![], Some(path)), "abc", b"").expect_err("refuse");
        assert!(error.to_string().contains("no `imports` array"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// L4. The manifest that comes back must describe the file that went up. This client
    /// cannot verify a signature — it holds no trusted key — but it can refuse to write a
    /// bundle whose two halves disagree, which is what a truncated upload produces.
    #[test]
    fn a_signature_that_does_not_describe_the_uploaded_bytes_is_not_written() {
        let bytes = b"\0asm\x0d\x00\x01\x00 a component".to_vec();
        let digest = sha256_hex(&bytes);

        let good = WasmSignature::decode(&json!({
            "component_sha256": digest,
            "size": bytes.len(),
            "bundle_bytes": bytes.len() + 300
        }));

        assert!(describes(&good, &bytes, 300).is_ok());

        let wrong_sha = WasmSignature::decode(&json!({
            "component_sha256": "a".repeat(64),
            "size": bytes.len(),
        }));

        let error = describes(&wrong_sha, &bytes, 300).expect_err("a different component");
        assert!(error.to_string().contains("hashes to"));

        let wrong_size = WasmSignature::decode(&json!({
            "component_sha256": digest,
            "size": bytes.len() + 1,
        }));

        assert!(describes(&wrong_size, &bytes, 300)
            .expect_err("a different size")
            .to_string()
            .contains("bytes, but the file uploaded"));

        let wrong_total = WasmSignature::decode(&json!({
            "component_sha256": digest,
            "size": bytes.len(),
            "bundle_bytes": 7
        }));

        assert!(describes(&wrong_total, &bytes, 300)
            .expect_err("a bundle that does not add up")
            .to_string()
            .contains("the prefix and the component are"));

        // A runtime that named no digest at all is not a runtime to write a file from.
        let silent = WasmSignature::decode(&json!({}));
        assert!(describes(&silent, &bytes, 300).is_err());
    }

    /// L5. A node that answers "you are not where you think you are" says where it is, in
    /// the error's data. That number is the one thing a client acts on rather than reports.
    #[test]
    fn the_held_offset_is_read_from_the_refusal_and_from_nothing_else() {
        use crate::proto::{ErrorCode, RpcError};
        use crate::transport::ClientError;

        let mismatch = ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "params.offset must be 6, which is what this upload holds".into(),
            data: Some(json!({"reason": "offset_mismatch", "offset": 6})),
        });

        assert_eq!(held_offset(&mismatch), Some(6));

        // The sentence alone is not a protocol: without the machine-readable reason there
        // is nothing to resume from.
        let sentence_only = ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "params.offset must be 6, which is what this upload holds".into(),
            data: None,
        });

        assert_eq!(held_offset(&sentence_only), None);

        let other_reason = ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "nope".into(),
            data: Some(json!({"reason": "outside_roots", "offset": 6})),
        });

        assert_eq!(held_offset(&other_reason), None);
        assert_eq!(held_offset(&ClientError::Timeout), None);
    }

    /// L8. A signer id is one half of an `id:base64` pair in a comma-separated list.
    #[test]
    fn a_signer_id_that_would_break_the_trusted_signers_line_is_refused() {
        assert!(signer_id("release-key").is_ok());
        assert!(signer_id("release_key.2026").is_ok());

        for hostile in ["", "a:b", "a,b", "with space", "tab\there", &"x".repeat(65)] {
            assert!(
                signer_id(hostile).is_err(),
                "{hostile:?} would produce a trusted-signers line that names a different signer"
            );
        }
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
