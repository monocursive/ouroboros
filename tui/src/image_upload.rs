//! Bounded uploads to the session's owner; clipboard bytes never enter a workspace.
use crate::{transport::Client, ui::app::ClipboardRequest};
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// One local filename; shell expansions and commands are never evaluated.
pub fn local_paths(input: &str) -> Result<Vec<String>> {
    let input = input.trim();
    let value = if input.len() >= 2
        && ((input.starts_with('"') && input.ends_with('"'))
            || (input.starts_with('\'') && input.ends_with('\'')))
    {
        &input[1..input.len() - 1]
    } else {
        input
    };
    if value.is_empty() || value.contains('\0') {
        bail!("Choose one image file");
    }
    Ok(vec![value.to_string()])
}

async fn call(
    client: &Client,
    request: &ClipboardRequest,
    op: &str,
    mut args: Value,
) -> Result<Value> {
    if let Some(node) = &request.node {
        args["node"] = json!(node);
    }
    client
        .call_with_timeout(&format!("attachment.{op}"), args, Duration::from_secs(15))
        .await
        .map_err(|error| anyhow!("{error}"))
}

pub async fn upload(
    client: &Client,
    request: &ClipboardRequest,
    bytes: &[u8],
    name: &str,
    progress: impl Fn(Value),
) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > 20 * 1024 * 1024 {
        bail!("Image must be between 1 byte and 20 MiB");
    }
    let limits = call(client, request, "limits", json!({})).await?;
    if limits["image_attachments_v1"] != true {
        bail!("This runtime cannot accept image uploads. Upgrade it and check its image decoder.");
    }
    anyhow::ensure!(
        bytes.len() as u64
            <= limits["max_source_bytes"]
                .as_u64()
                .unwrap_or(20 * 1024 * 1024),
        "Image exceeds this connection's source size limit"
    );
    progress(
        json!({"state":"uploading", "received":0, "source_size":bytes.len(),
        "display_name":name, "client_ephemeral": limits["client_draft_persistence"] != "private"}),
    );
    let chunk = limits["chunk_bytes"]
        .as_u64()
        .unwrap_or(4096)
        .clamp(1, 65536) as usize;
    let mut begin = json!({"client_id": request.draft_id, "draft_id": request.draft_id,
        "client_attachment_id": request.id, "attempt_id": request.id,
        "byte_size": bytes.len(), "display_name": name,
        "source": if request.path.is_some() {"file_picker"} else {"clipboard"}});
    if let Some((_, id)) = &request.target {
        begin["session_id"] = json!(id);
    }
    // Retrying a lost acknowledgement uses exactly the same upload and turn identity.
    let mut status = match call(client, request, "begin", begin.clone()).await {
        Ok(status) => status,
        Err(_) => call(client, request, "begin", begin).await?,
    };
    let id = status["upload_id"]
        .as_str()
        .ok_or_else(|| anyhow!("Runtime omitted the upload ID"))?
        .to_string();
    progress(
        json!({"state":"uploading", "upload_id":id, "received":status["received"], "source_size":bytes.len(),
        "display_name":name, "client_ephemeral": limits["client_draft_persistence"] != "private"}),
    );
    for _ in 0..3 {
        let result = async {
            let mut offset = status["received"].as_u64().unwrap_or(0) as usize;
            while offset < bytes.len() && status["state"] == "uploading" {
                let end = (offset + chunk).min(bytes.len());
                status = call(
                    client,
                    request,
                    "append",
                    json!({"upload_id": id, "offset": offset,
                    "data": STANDARD.encode(&bytes[offset..end])}),
                )
                .await?;
                let next = status["received"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("Invalid upload offset"))?
                    as usize;
                if next <= offset || next > bytes.len() {
                    bail!("Invalid upload offset");
                }
                offset = next;
                progress(json!({"state":"uploading", "received":offset, "source_size":bytes.len(),
                    "display_name":name, "client_ephemeral": limits["client_draft_persistence"] != "private"}));
            }
            let hash = format!("{:x}", Sha256::digest(bytes));
            status = call(
                client,
                request,
                "finish",
                json!({"upload_id": id, "sha256": hash}),
            )
            .await?;
            progress(json!({"state":"preparing", "received":bytes.len(), "source_size":bytes.len(),
                "display_name":name, "client_ephemeral": limits["client_draft_persistence"] != "private"}));
            for _ in 0..120 {
                match status["state"].as_str() {
                    Some("ready") => {
                        status["client_ephemeral"] =
                            json!(limits["client_draft_persistence"] != "private");
                        return Ok(status.clone());
                    }
                    Some("failed") => bail!(
                        "{}",
                        status["error"]
                            .as_str()
                            .unwrap_or("Image preparation failed")
                    ),
                    _ => {}
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
                status = call(client, request, "status", json!({"upload_id": id})).await?;
            }
            bail!("Image preparation timed out")
        }
        .await;
        if result.is_ok() || status["state"] == "failed" {
            return result;
        }
        status = call(client, request, "status", json!({"upload_id": id})).await?;
    }
    bail!("Upload interrupted. Your message is still in the draft; remove this image and attach it again.")
}

pub async fn bind(
    client: &Client,
    node: Option<&str>,
    draft_id: &str,
    session_id: &str,
) -> Result<()> {
    let mut args = json!({"draft_id": draft_id, "session_id": session_id});
    if let Some(node) = node {
        args["node"] = json!(node);
    }
    client
        .call("attachment.bind_draft", args)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 36
        && id.starts_with("att_")
        && id[4..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A normalized, explicitly opened preview. Last ownership removes the private file.
#[derive(Debug, Clone)]
pub struct PreviewFile(std::sync::Arc<PreviewPath>);
#[derive(Debug)]
struct PreviewPath(std::path::PathBuf);
impl Drop for PreviewPath {
    fn drop(&mut self) {
        if let Some(parent) = self.0.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}
impl PreviewFile {
    pub fn path(&self) -> &std::path::Path {
        &self.0 .0
    }
    fn write(bytes: &[u8]) -> Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ouro-image-preview-{}-{stamp}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let owner = Self(std::sync::Arc::new(PreviewPath(root.join("image.png"))));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(owner.path())?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(owner)
    }
}

pub async fn preview(
    client: &Client,
    id: &str,
    node: Option<&str>,
    session: Option<&str>,
) -> Result<PreviewFile> {
    anyhow::ensure!(valid_id(id), "Invalid image ID");
    static PREVIEWS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let _permit = PREVIEWS
        .try_acquire()
        .map_err(|_| anyhow!("Two image previews are already loading; try again shortly"))?;
    let mut bytes = Vec::new();
    let mut expected: Option<(usize, String)> = None;
    loop {
        let mut args = json!({"attachment_id": id, "variant": "content", "offset": bytes.len(), "length": 65536});
        if let Some(node) = node {
            args["node"] = json!(node);
        }
        if let Some(session) = session {
            args["session_id"] = json!(session);
        }
        let part = client.call("attachment.read", args).await?;
        let total = part["total"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 20 * 1024 * 1024)
            .ok_or_else(|| anyhow!("Invalid image size"))? as usize;
        let hash = part["sha256"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing image digest"))?
            .to_string();
        anyhow::ensure!(
            part["offset"].as_u64() == Some(bytes.len() as u64)
                && part["media_type"] == "image/png",
            "Invalid image chunk"
        );
        if let Some(prior) = &expected {
            anyhow::ensure!(
                prior == &(total, hash.clone()),
                "Image changed during download"
            );
        } else {
            expected = Some((total, hash.clone()));
        }
        let chunk = STANDARD.decode(
            part["data"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing image bytes"))?,
        )?;
        anyhow::ensure!(
            !chunk.is_empty() && chunk.len() <= 65536 && bytes.len() + chunk.len() <= total,
            "Invalid image chunk size"
        );
        bytes.extend_from_slice(&chunk);
        anyhow::ensure!(
            part["next_offset"].as_u64() == Some(bytes.len() as u64),
            "Invalid next image offset"
        );
        if part["eof"] == true {
            anyhow::ensure!(
                bytes.len() == total && format!("{:x}", Sha256::digest(&bytes)) == hash,
                "Image integrity check failed"
            );
            return tokio::task::spawn_blocking(move || PreviewFile::write(&bytes)).await?;
        }
        anyhow::ensure!(bytes.len() < total, "Missing final image chunk");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preview_files_are_private_and_removed_with_their_last_owner() {
        use std::os::unix::fs::PermissionsExt;
        let preview = PreviewFile::write(b"normalized fixture").unwrap();
        let path = preview.path().to_path_buf();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let second = preview.clone();
        drop(preview);
        assert!(path.is_file());
        drop(second);
        assert!(!path.exists());
    }
    #[test]
    fn image_ids_and_local_paths_cannot_be_commands_or_remote_resources() {
        assert!(valid_id("att_abcdefghijklmnopqrstuvwx12345678"));
        assert!(!valid_id("att_../../etc/passwd"));
        assert_eq!(local_paths("'/tmp/a b.png'").unwrap(), vec!["/tmp/a b.png"]);
        assert!(local_paths("\0").is_err());
    }
}
