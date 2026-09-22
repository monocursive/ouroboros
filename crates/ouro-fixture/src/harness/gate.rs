//! The scripted gate owner of jail-v1 §8.2 and acceptance row I03.
//!
//! The owner waits for `prepared` on the control channel, compares the
//! prepared receipt's attempt, policy and argv bindings with the plan it
//! authorised, and only then writes one release frame and closes the gate.
//! Every malformed variant X02 names is a value of [`Release`], so a test
//! chooses the fault instead of hand-rolling bytes.

use std::io;

use serde_json::Value;

use super::pipes::{GateWriter, LineReader};

/// The gate schema identifier, jail-v1 §8.2.
pub const GATE_SCHEMA: &str = "ouro.jail.gate/1";
/// The control schema identifier, jail-v1 §8.2.
pub const CONTROL_SCHEMA: &str = "ouro.jail.control/1";
/// Maximum frame size including the single trailing LF, jail-v1 §8.2.
pub const GATE_MAX_BYTES: usize = 1024;

/// What the owner authorised. `None` means "do not check this binding".
#[derive(Debug, Default, Clone)]
pub struct ExpectedPlan {
    pub attempt_id: Option<String>,
    pub policy_digest: Option<String>,
    pub argv_digest: Option<String>,
    pub phase: Option<String>,
}

impl ExpectedPlan {
    #[must_use]
    pub fn new() -> Self {
        ExpectedPlan {
            phase: Some("prepared".to_string()),
            ..ExpectedPlan::default()
        }
    }

    #[must_use]
    pub fn attempt_id(mut self, v: impl Into<String>) -> Self {
        self.attempt_id = Some(v.into());
        self
    }

    #[must_use]
    pub fn policy_digest(mut self, v: impl Into<String>) -> Self {
        self.policy_digest = Some(v.into());
        self
    }

    #[must_use]
    pub fn argv_digest(mut self, v: impl Into<String>) -> Self {
        self.argv_digest = Some(v.into());
        self
    }
}

/// What the jail actually proposed, read from the control message and the
/// prepared receipt.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub attempt_id: Option<String>,
    pub policy_digest: Option<String>,
    pub argv_digest: Option<String>,
    pub phase: Option<String>,
}

fn string_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str()
}

impl Proposal {
    /// Read the bindings out of a `prepared` control message and, when the
    /// test has it, the prepared receipt. The receipt is authoritative for the
    /// policy and argv digests: §8.2 binds the owner to the receipt, and the
    /// control message carries only the phase and the receipt digest.
    #[must_use]
    pub fn read(control: &Value, receipt: Option<&Value>) -> Proposal {
        let mut p = Proposal {
            attempt_id: string_at(control, &["attempt_id"]).map(str::to_string),
            phase: string_at(control, &["receipt_phase"])
                .or_else(|| string_at(control, &["kind"]))
                .map(str::to_string),
            ..Proposal::default()
        };
        if let Some(r) = receipt {
            if let Some(v) = string_at(r, &["attempt_id"]) {
                p.attempt_id = Some(v.to_string());
            }
            p.policy_digest = string_at(r, &["policy", "digest"]).map(str::to_string);
            p.argv_digest = string_at(r, &["argv_digest"]).map(str::to_string);
            if let Some(v) = string_at(r, &["phase"]) {
                p.phase = Some(v.to_string());
            }
        }
        p
    }
}

/// Compare a proposal with the authorised plan. An empty result means release
/// is authorised; otherwise every mismatch is named.
#[must_use]
pub fn mismatches(plan: &ExpectedPlan, proposal: &Proposal) -> Vec<String> {
    let mut out = Vec::new();
    let mut one = |field: &str, want: &Option<String>, got: &Option<String>| {
        if let Some(want) = want
            && want.as_str() != got.as_deref().unwrap_or("<absent>")
        {
            out.push(format!(
                "{field}: authorised {want}, proposed {}",
                got.as_deref().unwrap_or("<absent>")
            ));
        }
    };
    one("attempt_id", &plan.attempt_id, &proposal.attempt_id);
    one(
        "policy_digest",
        &plan.policy_digest,
        &proposal.policy_digest,
    );
    one("argv_digest", &plan.argv_digest, &proposal.argv_digest);
    one("phase", &plan.phase, &proposal.phase);
    out
}

/// A release frame, valid or deliberately broken. jail-v1 §8.2 and X02.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Release {
    /// One well-formed frame with exactly one trailing LF.
    Valid,
    /// Close the gate without writing anything (`empty EOF`).
    EmptyEof,
    /// A valid frame, then a second one.
    Duplicated,
    /// A valid frame with no trailing LF.
    MissingLf,
    /// A valid frame terminated with CRLF.
    Crlf,
    /// A valid frame with bytes after its LF.
    TrailingBytes,
    /// A blank line before a valid frame.
    LeadingBlankLine,
    /// A frame padded past the 1024-byte cap.
    Oversized,
    /// Valid JSON shape but `"schema"` replaced.
    WrongSchema(String),
    /// Valid JSON shape but `"action"` replaced.
    WrongAction(String),
    /// A frame naming a different attempt.
    WrongAttemptId(String),
    /// A frame naming a different policy digest.
    WrongDigest(String),
    /// Not JSON at all.
    MalformedJson,
    /// `"action"` appears twice.
    DuplicateKeys,
    /// Exactly these bytes.
    Raw(Vec<u8>),
}

/// The canonical frame body (no terminator) for an attempt and digest.
#[must_use]
pub fn frame_body(attempt_id: &str, policy_digest: &str) -> String {
    let v = serde_json::json!({
        "schema": GATE_SCHEMA,
        "action": "release",
        "attempt_id": attempt_id,
        "policy_digest": policy_digest,
    });
    // The value is four strings; serialisation cannot fail.
    serde_json::to_string(&v).unwrap_or_default()
}

/// The exact bytes a variant puts on the gate. Pure, so a test can assert the
/// fault it asked for without running a process.
#[must_use]
pub fn frame_bytes(variant: &Release, attempt_id: &str, policy_digest: &str) -> Vec<u8> {
    let body = frame_body(attempt_id, policy_digest);
    let with_lf = |s: &str| {
        let mut b = s.as_bytes().to_vec();
        b.push(b'\n');
        b
    };
    match variant {
        Release::Valid => with_lf(&body),
        Release::EmptyEof => Vec::new(),
        Release::Duplicated => {
            let mut b = with_lf(&body);
            b.extend_from_slice(&with_lf(&body));
            b
        }
        Release::MissingLf => body.into_bytes(),
        Release::Crlf => {
            let mut b = body.into_bytes();
            b.extend_from_slice(b"\r\n");
            b
        }
        Release::TrailingBytes => {
            let mut b = with_lf(&body);
            b.extend_from_slice(b"trailing");
            b
        }
        Release::LeadingBlankLine => {
            let mut b = vec![b'\n'];
            b.extend_from_slice(&with_lf(&body));
            b
        }
        Release::Oversized => {
            // Pad with JSON whitespace inside the single line, so the frame
            // stays well formed and only the byte cap is violated.
            let pad = " ".repeat(GATE_MAX_BYTES);
            let padded = body.replacen("{\"", &format!("{{{pad}\""), 1);
            with_lf(&padded)
        }
        Release::WrongSchema(s) => with_lf(&frame_with(attempt_id, policy_digest, "schema", s)),
        Release::WrongAction(a) => with_lf(&frame_with(attempt_id, policy_digest, "action", a)),
        Release::WrongAttemptId(id) => with_lf(&frame_body(id, policy_digest)),
        Release::WrongDigest(d) => with_lf(&frame_body(attempt_id, d)),
        Release::MalformedJson => with_lf(&body[..body.len().saturating_sub(3)]),
        Release::DuplicateKeys => {
            let dup = body.replacen(
                "\"action\":\"release\"",
                "\"action\":\"release\",\"action\":\"release\"",
                1,
            );
            with_lf(&dup)
        }
        Release::Raw(bytes) => bytes.clone(),
    }
}

fn frame_with(attempt_id: &str, policy_digest: &str, key: &str, value: &str) -> String {
    let mut v = serde_json::json!({
        "schema": GATE_SCHEMA,
        "action": "release",
        "attempt_id": attempt_id,
        "policy_digest": policy_digest,
    });
    v[key] = Value::String(value.to_string());
    serde_json::to_string(&v).unwrap_or_default()
}

/// The scripted owner. It holds the control reader and the gate writer for as
/// long as it is deciding, and closes the gate when it is done either way.
pub struct GateOwner<'a> {
    control: &'a mut LineReader,
    gate: &'a mut Option<GateWriter>,
    /// Every control message read so far, in order. Owned by the run, so the
    /// conversation survives the owner and appears in [`super::Run`].
    pub seen: &'a mut Vec<Value>,
}

impl<'a> GateOwner<'a> {
    pub fn new(
        control: &'a mut LineReader,
        gate: &'a mut Option<GateWriter>,
        seen: &'a mut Vec<Value>,
    ) -> GateOwner<'a> {
        GateOwner {
            control,
            gate,
            seen,
        }
    }

    /// Read control messages until the first `prepared`. Returns an error when
    /// the jail refused, closed the channel, or sent something unparsable:
    /// none of those is a silent skip.
    pub fn await_prepared(&mut self) -> io::Result<Value> {
        loop {
            let Some(line) = self.control.next_line()? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "control channel closed before `prepared`; saw {} message(s)",
                        self.seen.len()
                    ),
                ));
            };
            if line.is_empty() {
                continue;
            }
            let value: Value = serde_json::from_slice(&line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "control message is not JSON: {e}: {}",
                        String::from_utf8_lossy(&line)
                    ),
                )
            })?;
            let kind = value
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            self.seen.push(value.clone());
            match kind.as_str() {
                "prepared" => return Ok(value),
                "refused" => {
                    return Err(io::Error::other(format!(
                        "jail refused before `prepared`: {value}"
                    )));
                }
                _ => {}
            }
        }
    }

    /// Compare the proposal with the plan. `Ok(())` authorises release.
    pub fn authorise(
        &self,
        control: &Value,
        receipt: Option<&Value>,
        plan: &ExpectedPlan,
    ) -> Result<Proposal, (Proposal, Vec<String>)> {
        let proposal = Proposal::read(control, receipt);
        let problems = mismatches(plan, &proposal);
        if problems.is_empty() {
            Ok(proposal)
        } else {
            Err((proposal, problems))
        }
    }

    /// Write the chosen release variant and close the gate.
    pub fn release(
        &mut self,
        variant: &Release,
        attempt_id: &str,
        policy_digest: &str,
    ) -> io::Result<()> {
        let bytes = frame_bytes(variant, attempt_id, policy_digest);
        let mut writer = self
            .gate
            .take()
            .ok_or_else(|| io::Error::other("the gate was already closed by this owner"))?;
        if !bytes.is_empty() {
            writer.write_all(&bytes)?;
        }
        writer.close();
        Ok(())
    }

    /// Withhold the gate: close it with nothing written. X02's first case.
    pub fn withhold(&mut self) {
        self.gate.take();
    }

    /// Drain and return whatever else the jail says on the control channel.
    pub fn drain_control(&mut self) -> io::Result<Vec<Value>> {
        let mut out = Vec::new();
        for line in self.control.drain()? {
            if line.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_slice::<Value>(&line) {
                self.seen.push(v.clone());
                out.push(v);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "att_00000000-0000-4000-8000-000000000001";
    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn a_valid_frame_matches_the_specification_example() {
        let bytes = frame_bytes(&Release::Valid, ID, DIGEST);
        assert!(bytes.len() <= GATE_MAX_BYTES);
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(*bytes.last().unwrap(), b'\n');
        assert!(!bytes.contains(&b'\r'));
        let v: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        assert_eq!(v["schema"], GATE_SCHEMA);
        assert_eq!(v["action"], "release");
        assert_eq!(v["attempt_id"], ID);
        assert_eq!(v["policy_digest"], DIGEST);
        assert_eq!(v.as_object().unwrap().len(), 4, "exactly four keys");
    }

    #[test]
    fn each_fault_variant_really_carries_its_fault() {
        let f = |v: Release| frame_bytes(&v, ID, DIGEST);

        assert!(f(Release::EmptyEof).is_empty());
        assert_eq!(
            f(Release::Duplicated)
                .iter()
                .filter(|b| **b == b'\n')
                .count(),
            2
        );
        assert!(!f(Release::MissingLf).ends_with(b"\n"));
        assert!(f(Release::Crlf).ends_with(b"\r\n"));
        assert!(f(Release::TrailingBytes).ends_with(b"trailing"));
        assert!(f(Release::LeadingBlankLine).starts_with(b"\n"));
        assert!(
            f(Release::Oversized).len() > GATE_MAX_BYTES,
            "the oversized frame must exceed the cap"
        );
        assert!(
            serde_json::from_slice::<Value>(
                &f(Release::Oversized)[..f(Release::Oversized).len() - 1]
            )
            .is_ok(),
            "only the cap is violated; the JSON stays well formed"
        );
        assert!(serde_json::from_slice::<Value>(&f(Release::MalformedJson)).is_err());

        let wrong = f(Release::WrongSchema("ouro.jail.gate/999".into()));
        let v: Value = serde_json::from_slice(&wrong[..wrong.len() - 1]).unwrap();
        assert_eq!(v["schema"], "ouro.jail.gate/999");

        let wrong = f(Release::WrongAction("abort".into()));
        let v: Value = serde_json::from_slice(&wrong[..wrong.len() - 1]).unwrap();
        assert_eq!(v["action"], "abort");

        let wrong = f(Release::WrongAttemptId("att_other".into()));
        assert!(String::from_utf8_lossy(&wrong).contains("att_other"));

        let wrong = f(Release::WrongDigest("sha256:ff".into()));
        assert!(String::from_utf8_lossy(&wrong).contains("sha256:ff"));

        let dup = f(Release::DuplicateKeys);
        let text = String::from_utf8_lossy(&dup);
        assert_eq!(text.matches("\"action\"").count(), 2);

        assert_eq!(f(Release::Raw(b"anything".to_vec())), b"anything");
    }

    #[test]
    fn a_proposal_prefers_the_receipt_bindings_over_the_control_message() {
        let control = serde_json::json!({
            "schema": CONTROL_SCHEMA,
            "attempt_id": "att_from_control",
            "seq": 0,
            "kind": "prepared",
            "receipt_phase": "prepared",
        });
        let receipt = serde_json::json!({
            "attempt_id": ID,
            "phase": "prepared",
            "policy": { "digest": DIGEST },
            "argv_digest": "sha256:bb",
        });
        let p = Proposal::read(&control, Some(&receipt));
        assert_eq!(p.attempt_id.as_deref(), Some(ID));
        assert_eq!(p.policy_digest.as_deref(), Some(DIGEST));
        assert_eq!(p.argv_digest.as_deref(), Some("sha256:bb"));
        assert_eq!(p.phase.as_deref(), Some("prepared"));

        let only_control = Proposal::read(&control, None);
        assert_eq!(only_control.attempt_id.as_deref(), Some("att_from_control"));
        assert_eq!(only_control.policy_digest, None);
    }

    #[test]
    fn every_binding_mismatch_is_named_and_an_absent_one_is_not_silently_accepted() {
        let plan = ExpectedPlan::new()
            .attempt_id(ID)
            .policy_digest(DIGEST)
            .argv_digest("sha256:bb");
        let good = Proposal {
            attempt_id: Some(ID.into()),
            policy_digest: Some(DIGEST.into()),
            argv_digest: Some("sha256:bb".into()),
            phase: Some("prepared".into()),
        };
        assert!(mismatches(&plan, &good).is_empty());

        let mut bad = good.clone();
        bad.policy_digest = Some("sha256:cc".into());
        let problems = mismatches(&plan, &bad);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].starts_with("policy_digest:"), "{problems:?}");

        let mut absent = good.clone();
        absent.argv_digest = None;
        let problems = mismatches(&plan, &absent);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("<absent>"), "{problems:?}");

        let mut wrong_phase = good;
        wrong_phase.phase = Some("enforced".into());
        assert_eq!(mismatches(&plan, &wrong_phase).len(), 1);
    }

    #[test]
    fn an_unchecked_binding_is_not_compared() {
        let plan = ExpectedPlan {
            attempt_id: None,
            policy_digest: None,
            argv_digest: None,
            phase: None,
        };
        let anything = Proposal::default();
        assert!(mismatches(&plan, &anything).is_empty());
    }
}
