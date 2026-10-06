//! Stateless positions in a growing canonical stream. No snapshot or retention pin.
//! Each call verifies the records it emits against accepted sequence/digest anchors.
use super::*;
use crate::protocol::{
    Chain, READ_CHUNK_BYTES, READ_SCAN_BYTES, READ_SCAN_FRAMES, TailPage, TailRequest,
};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};

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
        if stream.pruned.is_some() {
            return Err(LedgerError(
                "run history was pruned; tail cannot resume".into(),
            ));
        }
        if !stream.poisoned.is_empty() {
            return Err(LedgerError(
                "stream durability or recovery is ambiguous; tail refuses".into(),
            ));
        }
        let mut cursor = if let Some(text) = &request.cursor {
            if text.len() > 2048 {
                return Err(LedgerError("tail cursor exceeds bounded size".into()));
            }
            serde_json::from_str::<Cursor>(text)
                .map_err(|_| LedgerError("invalid tail cursor".into()))?
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
            return Err(LedgerError(
                "tail cursor identity or position is invalid".into(),
            ));
        }
        let mut offset = if cursor.after.head_seq == 0 {
            if cursor.after.head_digest.is_some() {
                return Err(LedgerError("tail cursor empty anchor is invalid".into()));
            }
            0
        } else {
            let anchor = stream
                .anchors
                .get(&cursor.after.head_seq)
                .filter(|a| Some(&a.digest) == cursor.after.head_digest.as_ref())
                .ok_or_else(|| LedgerError("tail cursor does not match accepted history".into()))?;
            anchor.bytes
        };
        let path = self.root.join(&request.run_id).join(STREAM);
        let mut file = crate::segments::Snapshot::open(&path, stream.accepted_bytes)?;
        file.validate()?;
        if file.physical_bytes() != stream.accepted_bytes {
            return Err(LedgerError(
                "canonical length differs from accepted history; tail refuses".into(),
            ));
        }
        let mut ndjson = String::new();
        let mut scanned = 0;
        for _ in 0..READ_SCAN_FRAMES {
            if cursor.after.head_seq == stream.run.chain.head_seq {
                if cursor.emitted != 0 {
                    return Err(LedgerError(
                        "tail cursor points beyond the accepted head".into(),
                    ));
                }
                break;
            }
            let seq = cursor
                .after
                .head_seq
                .checked_add(1)
                .ok_or_else(|| LedgerError("tail sequence exhausted".into()))?;
            let anchor = stream
                .anchors
                .get(&seq)
                .ok_or_else(|| LedgerError("tail canonical anchor is missing".into()))?;
            let size = anchor
                .bytes
                .checked_sub(offset)
                .filter(|n| (1..=MAX_FRAME_BYTES as u64).contains(n))
                .ok_or_else(|| LedgerError("tail canonical frame size is invalid".into()))?
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
                return Err(LedgerError(
                    "tail partial record does not match accepted history".into(),
                ));
            }
            file.seek(SeekFrom::Start(offset))?;
            let mut bytes = vec![0; size];
            file.read_exact(&mut bytes)?;
            let record: Value = serde_json::from_slice(&bytes[..size - 1])
                .map_err(|_| LedgerError("tail canonical frame is invalid JSON".into()))?;
            if bytes.last() != Some(&b'\n')
                || sha256_prefixed(&bytes[..size - 1]) != anchor.digest
                || record["seq"].as_u64() != Some(seq)
                || record["run_id"] != request.run_id
                || record["prev"] != json!(cursor.after.head_digest)
            {
                return Err(LedgerError("tail canonical record or chain changed".into()));
            }
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| LedgerError("tail record is not UTF-8".into()))?;
            if !text.is_char_boundary(cursor.emitted) {
                return Err(LedgerError("tail cursor splits UTF-8".into()));
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
        let caught_up = cursor.emitted == 0 && cursor.after == stream.run.chain;
        let mut coverage = crate::reader::coverage_summary(&stream.run.coverage);
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
            schema: "ouro.ledger.tail/1".into(),
            run_id: request.run_id.clone(),
            head: stream.run.chain.clone(),
            state: stream.run.state.clone(),
            child_protection: stream.run.child_protection.clone(),
            coverage,
            local_consistency: true,
            stream_status: if ["settled", "denied", "outcome_unknown"]
                .contains(&stream.run.state.as_str())
            {
                "complete"
            } else {
                "active"
            }
            .into(),
            ndjson,
            next_cursor: serde_json::to_string(&cursor)?,
            caught_up,
            scanned_through_seq: cursor.after.head_seq,
        })
    }
}
