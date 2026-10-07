//! Explicit, bounded inspection of terminal capture artifacts. The writer
//! serializes this read with retention, so GC cannot remove a selected capture
//! between its metadata snapshot and the read. Live streams are never opened.
use super::*;
use crate::bundle::files;
use std::io::Read;

const DISPLAY_BYTES: u64 = 65_536;
const CAPTURE_BYTES: u64 = 16 * 1_048_576;

impl Store {
    /// Metadata remains identical to `show`; transcript bytes are an explicit
    /// addition, not canonical evidence or a new capture-integrity claim.
    pub fn show_with_transcript(&self, run_id: &str) -> Result<Value> {
        let run = self.show(run_id)?;
        let mut streams = serde_json::Map::new();
        for name in ["stdout", "stderr", "argv"] {
            streams.insert(name.into(), self.transcript_stream(&run, name));
        }
        let transcript = json!({
            "schema":"ouro.ledger.transcript/1",
            "limit_bytes_per_stream":DISPLAY_BYTES,
            "encoding":"escaped_bytes",
            "integrity":"unverified_local_artifact",
            "streams":streams,
        });
        Ok(json!({"schema":"ouro.ledger.show/1", "run":run, "transcript":transcript}))
    }

    fn transcript_stream(&self, run: &RunRecord, name: &str) -> Value {
        let selected = name != "argv"
            && run.payload["capture"]["streams"]
                .as_array()
                .is_some_and(|s| s.contains(&json!(name)));
        let recorded = &run.capture[name];
        let mut result = json!({
            "state":"not_captured", "displayed_bytes":0, "display_truncated":false,
        });
        if !selected {
            return result;
        }
        result["recorded_state"] = recorded["state"].clone();
        result["capture_truncated"] = recorded["truncated"].clone();
        result["stored_bytes"] = recorded["stored_bytes"].clone();
        if let Some(history) = run.history.as_ref().or(run.capture_history.as_ref()) {
            result["state"] = json!(history.state);
            return result;
        }
        result["state"] = json!("incomplete");
        if !["settled", "denied", "outcome_unknown"].contains(&run.state.as_str())
            || !matches!(recorded["state"].as_str(), Some("captured" | "incomplete"))
        {
            result["reason"] = json!("capture_not_finalized");
            return result;
        }
        let Some(stored) = recorded["stored_bytes"]
            .as_u64()
            .filter(|n| *n <= CAPTURE_BYTES)
        else {
            result["state"] = json!("unavailable");
            result["reason"] = json!("invalid_capture_metadata");
            return result;
        };
        if !recorded["path"].is_null() && recorded["path"] != format!("artifacts/{name}.bin") {
            result["state"] = json!("unavailable");
            result["reason"] = json!("invalid_capture_metadata");
            return result;
        }
        match read_prefix(&self.root, &run.run_id, name, stored) {
            Ok(bytes) => {
                result["state"] = json!(if recorded["state"] == "incomplete" {
                    "incomplete"
                } else if recorded["truncated"] == true {
                    "truncated"
                } else {
                    "captured"
                });
                result["displayed_bytes"] = json!(bytes.len());
                result["display_truncated"] = json!(stored > bytes.len() as u64);
                // Reversible ASCII byte escapes also neutralize terminal control,
                // invalid UTF-8, and Unicode directional/formatting characters.
                result["text"] = json!(bytes.escape_ascii().to_string());
            }
            Err(_) => {
                result["state"] = json!("unavailable");
                result["reason"] = json!("missing_unsafe_or_changed_capture");
            }
        }
        result
    }
}

fn read_prefix(root: &Path, run: &str, name: &str, stored: u64) -> Result<Vec<u8>> {
    // Every component below the already configured ledger root is pinned and
    // opened without symlink traversal. Never use the recorded artifact path.
    let ledger = files::directory(root)?;
    files::private(&ledger)?;
    let run = files::child_dir(&ledger, run)?;
    files::private(&run)?;
    let artifacts = files::child_dir(&run, "artifacts")?;
    files::private(&artifacts)?;
    let mut file = files::member(&artifacts, &format!("{name}.bin"), false)?;
    files::private(&file)?;
    let before = file.metadata()?;
    if before.len() != stored {
        return Err(LedgerError("capture size differs from its record".into()));
    }
    let limit = stored.min(DISPLAY_BYTES);
    let mut bytes = Vec::with_capacity(limit as usize);
    (&mut file).take(limit).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != limit
        || before.len() != after.len()
        || before.modified()? != after.modified()?
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || after.nlink() != 1
    {
        return Err(LedgerError("capture changed while being read".into()));
    }
    files::private(&file)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
