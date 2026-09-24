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

/// What the owner authorised.
///
/// `None` means "do not check this binding", which is a deliberate hole: it
/// used to be reachable by `ExpectedPlan::default()`, so a plan that checked
/// nothing looked exactly like a plan that checked everything. `Default` is
/// gone, [`ExpectedPlan::bound`] names all three identity bindings at once,
/// [`ExpectedPlan::complete`] adds the requirements, and
/// [`GateOwner::authorise`] refuses a plan that binds no identity at all.
#[derive(Debug, Clone)]
pub struct ExpectedPlan {
    pub attempt_id: Option<String>,
    pub policy_digest: Option<String>,
    pub argv_digest: Option<String>,
    // J5-B1 begin: I03 — §8.2 "and applied requirements"
    /// The requirement names the owner authorised, compared as a set.
    pub requirements: Option<Vec<String>>,
    // J5-B1 end
    pub phase: Option<String>,
}

impl ExpectedPlan {
    /// A plan that binds only the phase. At least one identity binding must
    /// be added before it can authorise anything.
    ///
    /// There is deliberately no `Default`: `ExpectedPlan::default()` used to
    /// be a plan that authorised anything while looking like a plan check.
    #[allow(clippy::new_without_default)]
    #[must_use]
    pub fn new() -> Self {
        ExpectedPlan {
            attempt_id: None,
            policy_digest: None,
            argv_digest: None,
            requirements: None,
            phase: Some("prepared".to_string()),
        }
    }

    // J5-B1 begin: I03
    /// Every binding §8.2 asks an owner to compare: the attempt, policy and
    /// argv bindings and the applied requirements.
    #[must_use]
    pub fn complete<I, S>(
        attempt_id: impl Into<String>,
        policy_digest: impl Into<String>,
        argv_digest: impl Into<String>,
        requirements: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        ExpectedPlan::bound(attempt_id, policy_digest, argv_digest).requirements(requirements)
    }

    /// Bind the requirement names, as a set.
    #[must_use]
    pub fn requirements<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.requirements = Some(sorted_set(names));
        self
    }
    // J5-B1 end

    /// The complete plan: every binding §8.2 asks an owner to compare.
    #[must_use]
    pub fn bound(
        attempt_id: impl Into<String>,
        policy_digest: impl Into<String>,
        argv_digest: impl Into<String>,
    ) -> Self {
        ExpectedPlan::new()
            .attempt_id(attempt_id)
            .policy_digest(policy_digest)
            .argv_digest(argv_digest)
    }

    /// The identity bindings this plan does not check.
    #[must_use]
    pub fn unbound(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.attempt_id.is_none() {
            out.push("attempt_id");
        }
        if self.policy_digest.is_none() {
            out.push("policy_digest");
        }
        if self.argv_digest.is_none() {
            out.push("argv_digest");
        }
        // J5-B1 begin: I03
        if self.requirements.is_none() {
            out.push("requirements");
        }
        // J5-B1 end
        out
    }

    /// True when the plan binds no identity at all, so it can authorise
    /// anything the jail proposes. Requirements alone are not an identity:
    /// every attempt of the same policy has them.
    #[must_use]
    pub fn binds_nothing(&self) -> bool {
        self.attempt_id.is_none() && self.policy_digest.is_none() && self.argv_digest.is_none()
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
    // J5-B1 begin: I03
    /// `policy.requirements` of the prepared receipt, as a sorted set.
    pub requirements: Option<Vec<String>>,
    // J5-B1 end
    pub phase: Option<String>,
}

// J5-B1 begin: I03
fn sorted_set<I, S>(names: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let set: std::collections::BTreeSet<String> = names.into_iter().map(Into::into).collect();
    set.into_iter().collect()
}
// J5-B1 end

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
            // J5-B1 begin: I03 — a non-string entry makes the whole list
            // absent rather than silently shorter.
            p.requirements = r
                .pointer("/policy/requirements")
                .and_then(Value::as_array)
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().map(str::to_string))
                        .collect::<Option<Vec<String>>>()
                })
                .map(sorted_set);
            // J5-B1 end
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
    // J5-B1 begin: I03
    if let Some(want) = &plan.requirements
        && proposal.requirements.as_ref() != Some(want)
    {
        out.push(format!(
            "requirements: authorised {want:?}, proposed {}",
            proposal
                .requirements
                .as_ref()
                .map_or_else(|| "<absent>".to_owned(), |got| format!("{got:?}"))
        ));
    }
    // J5-B1 end
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
    // J5-B1 begin: X02 "missing/extra LF"
    /// A valid frame followed by a second LF: a blank line after the frame.
    ExtraLf,
    // J5-B1 end
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
        // J5-B1 begin
        Release::ExtraLf => {
            let mut b = with_lf(&body);
            b.push(b'\n');
            b
        } // J5-B1 end
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
    ///
    /// The `Err` carries the proposal and every mismatch. J5-B1 gave
    /// [`Proposal`] a requirements set, which pushes the tuple past
    /// `clippy::result_large_err`'s threshold; it is a test helper whose Err
    /// is built once per refusal, so the size is allowed rather than boxed
    /// (boxing would change every caller's pattern, including files this
    /// slice does not own).
    #[allow(clippy::result_large_err)]
    pub fn authorise(
        &self,
        control: &Value,
        receipt: Option<&Value>,
        plan: &ExpectedPlan,
    ) -> Result<Proposal, (Proposal, Vec<String>)> {
        let proposal = Proposal::read(control, receipt);
        if plan.binds_nothing() {
            // A plan with no identity binding matches every proposal, so
            // releasing on it proves nothing while looking like a plan check.
            return Err((
                proposal,
                vec![
                    "the plan binds no attempt_id, policy_digest or argv_digest, \
                     so it would authorise any attempt: use ExpectedPlan::bound(..)"
                        .to_string(),
                ],
            ));
        }
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
    ///
    /// This is the owner that says no by closing. [`GateOwner::hold`] is the
    /// owner that says nothing and keeps the gate open, which the jail can
    /// only end at its gate budget.
    pub fn withhold(&mut self) {
        self.gate.take();
    }

    // J5-B1 begin: X02 — withheld (open, silent) is not closed (EOF)
    /// Take the gate writer and keep it open without writing a byte. The
    /// jail sees neither a frame nor EOF for as long as the caller holds the
    /// returned writer; dropping it closes the gate.
    pub fn hold(&mut self) -> io::Result<GateWriter> {
        self.gate
            .take()
            .ok_or_else(|| io::Error::other("the gate was already closed by this owner"))
    }

    /// Write the chosen release variant and keep the gate open: the frame is
    /// complete, but §8.2 reads through EOF before releasing, so the jail
    /// waits for a close that the caller controls by holding the writer.
    pub fn write_unclosed(
        &mut self,
        variant: &Release,
        attempt_id: &str,
        policy_digest: &str,
    ) -> io::Result<GateWriter> {
        let bytes = frame_bytes(variant, attempt_id, policy_digest);
        let mut writer = self.hold()?;
        if !bytes.is_empty() {
            writer.write_all(&bytes)?;
        }
        Ok(writer)
    }

    /// Read control messages until the first of `kind`, keeping every
    /// message read. `None` when the channel closed first.
    pub fn await_kind(&mut self, kind: &str) -> io::Result<Option<Value>> {
        loop {
            let Some(line) = self.control.next_line()? else {
                return Ok(None);
            };
            if line.is_empty() {
                continue;
            }
            let value: Value = serde_json::from_slice(&line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("control message is not JSON: {e}"),
                )
            })?;
            self.seen.push(value.clone());
            if value.get("kind").and_then(Value::as_str) == Some(kind) {
                return Ok(Some(value));
            }
        }
    }
    // J5-B1 end

    /// Drain and return whatever else the jail says on the control channel.
    ///
    /// The lines read are kept whether or not the channel reached EOF; the
    /// error is returned alongside them so a caller cannot mistake a timeout
    /// for silence.
    pub fn drain_control(&mut self) -> (Vec<Value>, Option<io::Error>) {
        let mut drained = self.control.drain();
        let mut out = Vec::new();
        for line in drained.lines {
            if line.is_empty() {
                continue;
            }
            match serde_json::from_slice::<Value>(&line) {
                Ok(v) => {
                    self.seen.push(v.clone());
                    out.push(v);
                }
                Err(e) => {
                    drained.error = Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("malformed control message: {e}"),
                    ));
                }
            }
        }
        (out, drained.error)
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

        // J5-B1: an extra LF is the valid frame plus exactly one more LF.
        let extra = f(Release::ExtraLf);
        let mut valid = f(Release::Valid);
        valid.push(b'\n');
        assert_eq!(extra, valid);
    }

    // J5-B1 begin: I03
    #[test]
    fn requirements_are_compared_as_a_set_and_an_absent_list_mismatches() {
        let receipt = serde_json::json!({
            "attempt_id": ID,
            "phase": "prepared",
            "policy": {"digest": DIGEST, "requirements": ["b", "a", "b"]},
            "argv_digest": "sha256:bb",
        });
        let control = serde_json::json!({"attempt_id": ID, "kind": "prepared"});
        let proposal = Proposal::read(&control, Some(&receipt));
        assert_eq!(
            proposal.requirements,
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
        let plan = ExpectedPlan::complete(ID, DIGEST, "sha256:bb", ["a", "b"]);
        assert!(mismatches(&plan, &proposal).is_empty());

        let wider = ExpectedPlan::complete(ID, DIGEST, "sha256:bb", ["a"]);
        let problems = mismatches(&wider, &proposal);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].starts_with("requirements:"), "{problems:?}");

        let mut absent = proposal.clone();
        absent.requirements = None;
        let problems = mismatches(&plan, &absent);
        assert!(problems[0].contains("<absent>"), "{problems:?}");

        // A list with a non-string entry is not read as a shorter list.
        let odd = serde_json::json!({"policy": {"requirements": ["a", 1]}});
        assert_eq!(Proposal::read(&control, Some(&odd)).requirements, None);
    }
    // J5-B1 end

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
            requirements: None,
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
    fn a_plan_that_binds_nothing_authorises_nothing() {
        // `mismatches` still skips an unbound field, so a partial plan works;
        // but a plan with no identity binding at all is refused before it can
        // look like a check that passed.
        let empty = ExpectedPlan::new();
        assert!(empty.binds_nothing());
        assert_eq!(
            empty.unbound(),
            vec!["attempt_id", "policy_digest", "argv_digest", "requirements"]
        );

        let partial = ExpectedPlan::new().attempt_id(ID);
        assert!(!partial.binds_nothing());
        assert_eq!(
            partial.unbound(),
            vec!["policy_digest", "argv_digest", "requirements"]
        );

        // Requirements are not an identity: a plan binding only them still
        // binds nothing that tells one attempt from another.
        assert!(ExpectedPlan::new().requirements(["x"]).binds_nothing());

        let bound = ExpectedPlan::bound(ID, DIGEST, "sha256:bb");
        assert_eq!(bound.unbound(), vec!["requirements"]);
        let complete = ExpectedPlan::complete(ID, DIGEST, "sha256:bb", ["b", "a"]);
        assert!(complete.unbound().is_empty());

        // `mismatches` alone is permissive about an unbound identity field --
        // an empty plan objects only to the phase -- which is exactly why
        // `authorise` carries the refusal instead.
        let anything = Proposal {
            phase: Some("prepared".into()),
            ..Proposal::default()
        };
        assert!(
            mismatches(&empty, &anything).is_empty(),
            "mismatches alone would authorise an unnamed attempt"
        );

        let control = serde_json::json!({"attempt_id": ID, "kind": "prepared"});
        let refusal = refuse_unbound(&empty, &control);
        assert!(
            refusal.iter().any(|p| p.contains("binds no attempt_id")),
            "{refusal:?}"
        );
        assert!(refuse_unbound(&partial, &control).is_empty());
        assert!(refuse_unbound(&complete, &control).is_empty());
    }

    /// The refusal `authorise` applies, without a live channel.
    fn refuse_unbound(plan: &ExpectedPlan, control: &Value) -> Vec<String> {
        let _ = control;
        if plan.binds_nothing() {
            vec!["the plan binds no attempt_id, policy_digest or argv_digest".to_string()]
        } else {
            Vec::new()
        }
    }
}
