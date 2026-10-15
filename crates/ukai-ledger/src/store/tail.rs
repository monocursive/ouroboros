//! Stateless positions in a growing canonical stream. No snapshot or retention pin.
//! Each call verifies the records it emits against accepted sequence/digest anchors.
use std::io::{Read, Seek, SeekFrom};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ukai_records::canonical::sha256_prefixed;

use super::Store;
use crate::{
    manifest::STREAM,
    protocol::{
        Chain, LedgerError, MAX_FRAME_BYTES, READ_CHUNK_BYTES, READ_SCAN_BYTES, READ_SCAN_FRAMES,
        Result, StreamStatus, TailPage, TailRequest,
    },
    schemas,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    run_id: String,
    after: Chain,
    emitted: usize,
    pending_digest: Option<String>,
}

impl Store {
    pub fn tail(&self, request: &TailRequest) -> Result<TailPage> {
        let stream = self.stream(&request.run_id)?;
        if stream.pruned().is_some() {
            return Err(LedgerError::refused(
                "run history was pruned; tail cannot resume",
            ));
        }
        if stream.is_poisoned() {
            return Err(LedgerError::refused(
                "stream durability or recovery is ambiguous; tail refuses",
            ));
        }
        let mut cursor = if let Some(text) = &request.cursor {
            if text.len() > 2048 {
                return Err(LedgerError::refused("tail cursor exceeds bounded size"));
            }
            serde_json::from_str::<Cursor>(text)
                .map_err(|_| LedgerError::refused("invalid tail cursor"))?
        } else {
            Cursor {
                version: 1,
                run_id: request.run_id.clone(),
                after: Chain {
                    head_seq: 0,
                    head_digest: None,
                },
                emitted: 0,
                pending_digest: None,
            }
        };
        if cursor.version != 1
            || cursor.run_id != request.run_id
            || cursor.emitted >= MAX_FRAME_BYTES
            || ((cursor.emitted == 0) != cursor.pending_digest.is_none())
        {
            return Err(LedgerError::refused(
                "tail cursor identity or position is invalid",
            ));
        }
        let mut offset = if cursor.after.head_seq == 0 {
            if cursor.after.head_digest.is_some() {
                return Err(LedgerError::refused("tail cursor empty anchor is invalid"));
            }
            0
        } else {
            let anchor = stream
                .anchor(cursor.after.head_seq)
                .filter(|a| Some(&a.digest) == cursor.after.head_digest.as_ref())
                .ok_or_else(|| {
                    LedgerError::refused("tail cursor does not match accepted history")
                })?;
            anchor.bytes
        };
        let path = self.run_dir(&request.run_id).join(STREAM);
        let mut file = crate::segments::Snapshot::open(&path, stream.accepted_bytes())?;
        file.validate()?;
        if file.physical_bytes() != stream.accepted_bytes() {
            return Err(LedgerError::refused(
                "canonical length differs from accepted history; tail refuses",
            ));
        }
        let mut ndjson = String::new();
        let mut scanned = 0;
        for _ in 0..READ_SCAN_FRAMES {
            if cursor.after.head_seq == stream.run().chain.head_seq {
                if cursor.emitted != 0 {
                    return Err(LedgerError::refused(
                        "tail cursor points beyond the accepted head",
                    ));
                }
                break;
            }
            let seq = cursor
                .after
                .head_seq
                .checked_add(1)
                .ok_or_else(|| LedgerError::refused("tail sequence exhausted"))?;
            let anchor = stream
                .anchor(seq)
                .ok_or_else(|| LedgerError::refused("tail canonical anchor is missing"))?;
            let size = anchor
                .bytes
                .checked_sub(offset)
                .filter(|n| (1..=MAX_FRAME_BYTES as u64).contains(n))
                .ok_or_else(|| LedgerError::refused("tail canonical frame size is invalid"))?
                as usize;
            // One large legal frame can exceed the ordinary scan budget. It is
            // verified whole before any of its <=64 KiB output fragments escape.
            if scanned > 0 && scanned + size > READ_SCAN_BYTES {
                break;
            }
            if cursor.emitted >= size
                || cursor
                    .pending_digest
                    .as_ref()
                    .is_some_and(|d| d != &anchor.digest)
            {
                return Err(LedgerError::refused(
                    "tail partial record does not match accepted history",
                ));
            }
            file.seek(SeekFrom::Start(offset))?;
            let mut bytes = vec![0; size];
            file.read_exact(&mut bytes)?;
            let record: Value = serde_json::from_slice(&bytes[..size - 1])
                .map_err(|_| LedgerError::refused("tail canonical frame is invalid JSON"))?;
            if bytes.last() != Some(&b'\n')
                || sha256_prefixed(&bytes[..size - 1]) != anchor.digest
                || record["seq"].as_u64() != Some(seq)
                || record["run_id"] != request.run_id
                || record["prev"] != json!(cursor.after.head_digest)
            {
                return Err(LedgerError::refused(
                    "tail canonical record or chain changed",
                ));
            }
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| LedgerError::refused("tail record is not UTF-8"))?;
            if !text.is_char_boundary(cursor.emitted) {
                return Err(LedgerError::refused("tail cursor splits UTF-8"));
            }
            let mut end = size.min(cursor.emitted + READ_CHUNK_BYTES - ndjson.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            ndjson.push_str(&text[cursor.emitted..end]);
            scanned += size;
            if end == size {
                cursor.after = Chain {
                    head_seq: seq,
                    head_digest: Some(anchor.digest.clone()),
                };
                cursor.emitted = 0;
                cursor.pending_digest = None;
                offset = anchor.bytes;
            } else {
                cursor.emitted = end;
                cursor.pending_digest = Some(anchor.digest.clone());
            }
            if ndjson.len() >= READ_CHUNK_BYTES - 3 {
                break;
            }
        }
        file.validate()?;
        let caught_up = cursor.emitted == 0 && cursor.after == stream.run().chain;
        let mut coverage = crate::reader::coverage_summary(&stream.run().coverage);
        coverage["selection_status"] = json!(crate::reader::selection_status(
            &crate::protocol::ReadFilter {
                selector: crate::protocol::ReadSelector::All,
                stage: None,
                since: None,
                until: None
            },
            &coverage
        ));
        Ok(TailPage {
            schema: schemas::TAIL.into(),
            run_id: request.run_id.clone(),
            head: stream.run().chain.clone(),
            state: stream.run().state,
            child_protection: stream.run().child_protection,
            coverage,
            local_consistency: true,
            stream_status: if stream.run().state.is_terminal() {
                StreamStatus::Complete
            } else {
                StreamStatus::Active
            },
            ndjson,
            next_cursor: serde_json::to_string(&cursor)?,
            caught_up,
            scanned_through_seq: cursor.after.head_seq,
        })
    }
}
