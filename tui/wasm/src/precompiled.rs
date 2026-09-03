//! The container a precompiled component travels in, and the header a node reads before it
//! trusts one (docs/WASM.md §7.3, D22–D24, slice W8).
//!
//! # Why there is a container at all
//!
//! `Engine::precompile_component` answers with wasmtime's own serialized artifact: an object
//! file holding machine code for one target triple, produced by one wasmtime, valid for one
//! engine configuration. wasmtime will check all three for itself — and it checks them *inside*
//! `Component::deserialize`, which is `unsafe`, which is the one call this helper wants to make
//! only after it already believes the bytes. "Deserialize it and see what the error says" is
//! exactly the order W8 exists to avoid.
//!
//! So the bytes are wrapped in eighteen bytes of header and a small JSON block naming, in
//! plain text a reader can `head`, the four facts a node has to agree with before it maps
//! anything: the wasmtime version, the target triple, the world these bytes were compiled and
//! checked as, and the **source** component they were compiled from. A node compares the first
//! two against its own readings and refuses [`crate::refusal::PRECOMPILED_MISMATCH`] by name;
//! it compares the last against the sha its signed manifest named; and only then does it
//! deserialize.
//!
//! ```text
//! offset  0   "OUROCWASM"          magic
//! offset  9   0x01                 format version, exactly
//! offset 10   header length        uint32, big-endian, <= MAX_HEADER_BYTES
//! offset 14   payload length       uint32, big-endian, <= MAX_PAYLOAD_BYTES
//! offset 18   header               JSON, UTF-8
//!         …   payload              wasmtime's serialized artifact, raw
//!         …   nothing. Trailing data is a refusal.
//! ```
//!
//! The discipline is `Ouroboros.Wasm.Bundle`'s, deliberately: every field is bounded before it
//! is parsed, both lengths are checked against their ceilings before either slice is taken, and
//! the total must equal the header plus the two exactly — a file carrying more than it declares
//! has a region nobody described, and "the rest of it" is not a field this format has.
//!
//! # What the header is worth, and what it is not
//!
//! Nothing here is a security boundary on its own. The header is written by whoever produced
//! the file, so a header that lies is a file that lies — which is why the *whole container* is
//! what a manifest's `precompiled.sha256` covers, and why a node reads one only out of its own
//! content-addressed store under a manifest a trusted signer signed (D24). What the header buys
//! is that a mismatch is named rather than discovered, and that a node can say what a `.cwasm`
//! is without mapping a single byte of the machine code inside it.

use serde_json::{json, Value};

use crate::refusal::{self, Refusal};
use crate::world;

/// The container's magic. Nine bytes, and deliberately not `\0asm`: these are not component
/// bytes, and a reader that confused the two would hand a compiler's output to a validator.
pub const MAGIC: &[u8] = b"OUROCWASM";

/// The container format version, checked exactly. A file from a future format is refused by
/// name rather than parsed on the hope that the prefix still means what it used to.
pub const FORMAT_VERSION: u8 = 1;

/// Magic + version + two lengths.
pub const HEADER_BYTES: usize = MAGIC.len() + 1 + 4 + 4;

/// The JSON block's ceiling. Six short strings; four kibibytes is three orders of magnitude of
/// slack and small enough that a hostile header is a refusal rather than a parse.
pub const MAX_HEADER_BYTES: usize = 4 * 1024;

/// The largest serialized artifact this helper will read.
///
/// Exactly [`crate::host::MAX_COMPONENT_BYTES`], and the equality is the point: **one number**
/// bounds what this helper will read, whichever form the bytes are in. A separate, larger cap
/// for artifacts was a staging ceiling nobody had stated — `Ouroboros.Wasm.Upload` sizes its
/// slots from what a bundle may weigh, so a second cap here raised what a client could park on
/// a node's disk without anybody deciding to.
///
/// It is generous against measurement rather than a fit. What bounds a serialized artifact is
/// not the source file's size but its *code*, which §7.3 caps at
/// [`crate::shape::MAX_CODE_BYTES`]: the worst shape this helper admits — 20 000 functions and
/// just under 4 MiB of code — serializes to 11 092 495 bytes, 2.75× its source, and the 48 KiB
/// reference guest to 258 093, 5.3× its own (fixed overhead dominates a small one). Sixty-four
/// mebibytes is five times the worst artifact a signer applying §7.3 can produce.
///
/// This is the bound W8 trades the structural pass for on the loading node. Deserializing is
/// linear in the input and compiles nothing, so a byte cap is a bound on the work — which is
/// exactly what a byte cap was not while `Component::new` was on the hot path, and why §7.3
/// had to count functions instead.
pub const MAX_PAYLOAD_BYTES: u64 = crate::host::MAX_COMPONENT_BYTES;

/// What the header says, once it has been read and bounded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The wasmtime that produced the payload, spelled exactly as that build's `doctor` prints.
    pub wasmtime: String,
    /// The target triple it was produced for, spelled exactly as that build's `doctor` prints.
    pub target: String,
    /// The world the producer checked these bytes against, as `world::Kind::id` spells it.
    pub world: String,
    /// The short world name, as a `load` request spells it.
    pub kind: world::Kind,
    /// The sha256 of the **source** component this was compiled from. Lane W's identity is the
    /// component's bytes (D2), so this is what the cache is keyed under and what a manifest's
    /// `component_sha256` is held to.
    pub component_sha256: String,
    /// The size of those source bytes, so a cross-check against the signed manifest reads the
    /// same `size` whichever form was loaded.
    pub component_size: u64,
}

/// How many bytes of payload follow a header, so a reader can slice without re-parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Framing {
    pub header: Header,
    pub header_bytes: usize,
    pub payload_bytes: usize,
}

impl Framing {
    /// Where the payload starts in the whole file.
    pub fn payload_offset(&self) -> usize {
        HEADER_BYTES + self.header_bytes
    }
}

/// Whether these bytes begin like one of these containers. Cheap, and total: it reads a prefix.
///
/// Used to tell an operator that they pointed `inspect` at a `.cwasm`, and to refuse a `load`
/// that offered one as source bytes — both of which are better answers than whatever a
/// component parser would have said about an object file.
pub fn is_container(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && &bytes[..MAGIC.len()] == MAGIC
}

/// Writes one container around `payload`.
pub fn wrap(header: &Header, payload: &[u8]) -> Result<Vec<u8>, Refusal> {
    let block = serde_json::to_vec(&json!({
        "wasmtime": header.wasmtime,
        "target": header.target,
        "world": header.world,
        "kind": header.kind.name(),
        "component_sha256": header.component_sha256,
        "component_size": header.component_size,
    }))
    .map_err(|error| mismatch(format!("the header could not be encoded: {error}")))?;

    if block.len() > MAX_HEADER_BYTES {
        return Err(mismatch(format!(
            "the header is {} bytes, over the {MAX_HEADER_BYTES} byte cap",
            block.len()
        )));
    }
    if payload.len() as u64 > MAX_PAYLOAD_BYTES {
        return Err(mismatch(format!(
            "the serialized component is {} bytes, over the {MAX_PAYLOAD_BYTES} byte cap",
            payload.len()
        )));
    }

    let mut out = Vec::with_capacity(HEADER_BYTES + block.len() + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&(block.len() as u32).to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&block);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Reads the header of one container, bounding every field before it is parsed.
///
/// Nothing here touches the payload. That is the point: `inspect` on a `.cwasm` answers out of
/// this function alone, so reporting what a precompiled artifact claims to be costs no
/// `deserialize` and therefore trusts nothing (D24).
pub fn read(bytes: &[u8]) -> Result<Framing, Refusal> {
    if bytes.len() < HEADER_BYTES {
        return Err(mismatch(format!(
            "{} bytes is shorter than this format's {HEADER_BYTES} byte header",
            bytes.len()
        )));
    }
    if !is_container(bytes) {
        return Err(mismatch(
            "these bytes do not begin with this build's precompiled-component magic",
        ));
    }

    let version = bytes[MAGIC.len()];
    if version != FORMAT_VERSION {
        return Err(mismatch(format!(
            "precompiled format version {version}; this build reads {FORMAT_VERSION}"
        )));
    }

    let header_len = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    let payload_len = u32::from_be_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]) as u64;

    if header_len == 0 || header_len > MAX_HEADER_BYTES {
        return Err(mismatch(format!(
            "the header declares {header_len} bytes, outside 1..={MAX_HEADER_BYTES}"
        )));
    }
    if payload_len == 0 || payload_len > MAX_PAYLOAD_BYTES {
        return Err(mismatch(format!(
            "the payload declares {payload_len} bytes, outside 1..={MAX_PAYLOAD_BYTES}"
        )));
    }

    // Exactly, not at least: see the module header.
    let expected = HEADER_BYTES as u64 + header_len as u64 + payload_len;
    if bytes.len() as u64 != expected {
        return Err(mismatch(format!(
            "the file is {} bytes and declares {expected}",
            bytes.len()
        )));
    }

    let block = &bytes[HEADER_BYTES..HEADER_BYTES + header_len];
    let header = decode(block)?;

    Ok(Framing {
        header,
        header_bytes: header_len,
        payload_bytes: payload_len as usize,
    })
}

/// The header as `inspect` reports it: what these bytes claim, and nothing derived from them.
pub fn report(framing: &Framing, sha256: &str, size: usize) -> Value {
    json!({
        "precompiled": true,
        "sha256": sha256,
        "size": size,
        "wasmtime": framing.header.wasmtime,
        "target": framing.header.target,
        "world": framing.header.world,
        "kind": framing.header.kind.name(),
        "component_sha256": framing.header.component_sha256,
        "component_size": framing.header.component_size,
        "payload_bytes": framing.payload_bytes,
    })
}

fn decode(block: &[u8]) -> Result<Header, Refusal> {
    let value: Value = serde_json::from_slice(block)
        .map_err(|error| mismatch(format!("the header is not JSON: {error}")))?;

    let wasmtime = string(&value, "wasmtime")?;
    let target = string(&value, "target")?;
    let world = string(&value, "world")?;
    let kind_name = string(&value, "kind")?;
    let component_sha256 = string(&value, "component_sha256")?;

    let kind = world::Kind::parse(&kind_name).ok_or_else(|| {
        mismatch(format!(
            "the header names world `{kind_name}`, which this build does not implement"
        ))
    })?;

    // The two halves of the world claim have to agree with each other before either is read.
    // A header naming `policy` and `ouroboros:capability@0.1.0` is a header nobody can act on,
    // and picking one of them would be this build deciding which lie to believe.
    if world != kind.id() {
        return Err(mismatch(format!(
            "the header names world `{world}` and kind `{kind_name}`, which do not agree"
        )));
    }

    if !sha256_hex(&component_sha256) {
        return Err(mismatch(
            "the header's component_sha256 is not 64 lower-case hex characters",
        ));
    }

    let component_size = value
        .get("component_size")
        .and_then(Value::as_u64)
        .filter(|size| *size > 0)
        .ok_or_else(|| {
            mismatch("the header's component_size is missing or not a positive whole number")
        })?;

    Ok(Header {
        wasmtime,
        target,
        world,
        kind,
        component_sha256,
        component_size,
    })
}

/// A header string, bounded on the way out. Every one of these is echoed to a peer.
fn string(value: &Value, key: &str) -> Result<String, Refusal> {
    match value.get(key).and_then(Value::as_str) {
        Some(text) if !text.is_empty() && text.len() <= MAX_FIELD_BYTES => Ok(text
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()),
        Some(_other) => Err(mismatch(format!(
            "the header's {key} is empty or longer than {MAX_FIELD_BYTES} bytes"
        ))),
        None => Err(mismatch(format!(
            "the header has no {key}, which this format requires"
        ))),
    }
}

/// How long any one header string may be. A version, a triple, a world id and a digest; two
/// hundred and fifty-six bytes is far above all four and bounds what a refusal carries back.
const MAX_FIELD_BYTES: usize = 256;

fn sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn mismatch(message: impl Into<String>) -> Refusal {
    refusal::refuse(refusal::PRECOMPILED_MISMATCH, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header {
            wasmtime: "48.0.1".to_string(),
            target: "aarch64-apple-darwin".to_string(),
            world: world::CAPABILITY_ID.to_string(),
            kind: world::Kind::Capability,
            component_sha256: "a".repeat(64),
            component_size: 48_333,
        }
    }

    #[test]
    fn a_container_round_trips_and_reports_what_it_claims() {
        let bytes = wrap(&header(), b"machine code").expect("wraps");
        assert!(is_container(&bytes));

        let framing = read(&bytes).expect("reads");
        assert_eq!(framing.header, header());
        assert_eq!(framing.payload_bytes, b"machine code".len());
        assert_eq!(
            &bytes[framing.payload_offset()..],
            b"machine code",
            "the payload is where the framing says it is"
        );
    }

    /// Every way the framing can be wrong is a `precompiled_mismatch` naming what was wrong,
    /// and none of them reaches the payload. A file that is one byte longer than it declares is
    /// refused rather than read up to its claim — the `Ouroboros.Wasm.Bundle` rule, here too.
    #[test]
    fn every_framing_fault_is_refused_by_name() {
        let good = wrap(&header(), b"machine code").expect("wraps");

        let mut truncated = good.clone();
        truncated.pop();
        assert_eq!(
            read(&truncated).unwrap_err().refusal,
            "precompiled_mismatch"
        );

        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(read(&trailing).unwrap_err().refusal, "precompiled_mismatch");

        let mut versioned = good.clone();
        versioned[MAGIC.len()] = 2;
        let error = read(&versioned).unwrap_err();
        assert_eq!(error.refusal, "precompiled_mismatch");
        assert!(error.message.contains("version 2"), "{}", error.message);

        assert_eq!(read(&[]).unwrap_err().refusal, "precompiled_mismatch");
    }

    /// A file of exactly this framing, whatever the lengths say. The lengths are what the
    /// *reader* is asked to believe, so a test about the bounds on them has to be able to
    /// declare numbers no writer would.
    fn framed(version: u8, header_len: u32, payload_len: u32, tail: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(version);
        out.extend_from_slice(&header_len.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(tail);
        out
    }

    /// The magic, on a file long enough to reach the check.
    ///
    /// A short input is refused by the length clause before the magic is ever compared, so a
    /// test that only offered eight bytes proved the *length* bound twice and the magic not at
    /// all: delete the `is_container` clause from [`read`] and it stayed green. This one is a
    /// component's own preamble padded past the header, which is exactly what an operator who
    /// pointed a precompiled `load` at a `.wasm` hands over.
    #[test]
    fn bytes_that_are_not_one_of_these_containers_are_refused_by_the_magic() {
        let mut component = b"\0asm\x0d\x00\x01\x00".to_vec();
        component.resize(HEADER_BYTES + 64, 0);

        let error = read(&component).unwrap_err();
        assert_eq!(error.refusal, "precompiled_mismatch");
        assert!(
            error.message.contains("magic"),
            "the refusal must say what it did not begin with: {}",
            error.message
        );
        assert!(!is_container(&component));
    }

    /// Both declared lengths are bounded **before** either slice is taken, which is the whole of
    /// what stands between a peer-chosen `u32` and this process's heap. The ceilings are the
    /// numbers §14 names, so they are asserted by value rather than by "some refusal happened".
    #[test]
    fn a_declared_length_past_its_ceiling_is_refused_before_the_slice() {
        // A header block larger than the cap, on a file that is nothing but its own claim.
        let error = read(&framed(FORMAT_VERSION, MAX_HEADER_BYTES as u32 + 1, 1, &[])).unwrap_err();
        assert_eq!(error.refusal, "precompiled_mismatch");
        assert!(
            error.message.contains(&(MAX_HEADER_BYTES + 1).to_string()),
            "the refusal names the length that was declared: {}",
            error.message
        );

        // And a payload past the artifact cap. A `u32` cannot express more than 4 GiB, so this
        // is the ceiling that matters: 64 MiB, the same number the component read cap is.
        assert_eq!(MAX_PAYLOAD_BYTES, 64 * 1024 * 1024);
        let over = MAX_PAYLOAD_BYTES as u32 + 1;
        let error = read(&framed(FORMAT_VERSION, 16, over, &[])).unwrap_err();
        assert_eq!(error.refusal, "precompiled_mismatch");
        assert!(
            error.message.contains(&over.to_string()),
            "the refusal names the payload length that was declared: {}",
            error.message
        );

        // Zero is not a length either: a container with no header or no payload describes
        // nothing, and admitting one would mean deserializing an empty slice.
        assert_eq!(
            read(&framed(FORMAT_VERSION, 0, 1, &[]))
                .unwrap_err()
                .refusal,
            "precompiled_mismatch"
        );
        assert_eq!(
            read(&framed(FORMAT_VERSION, 16, 0, &[]))
                .unwrap_err()
                .refusal,
            "precompiled_mismatch"
        );
    }

    /// The two halves of the world claim are held to each other, so a header cannot name one
    /// world in the id and the other in the short name and leave a reader to choose.
    #[test]
    fn a_header_whose_world_and_kind_disagree_is_refused() {
        let mut lying = header();
        lying.kind = world::Kind::Policy;
        let bytes = wrap(&lying, b"machine code").expect("wraps");

        let error = read(&bytes).unwrap_err();
        assert_eq!(error.refusal, "precompiled_mismatch");
        assert!(error.message.contains("do not agree"), "{}", error.message);
    }

    #[test]
    fn a_header_without_a_component_identity_is_refused() {
        let mut short = header();
        short.component_sha256 = "not-a-digest".to_string();
        let bytes = wrap(&short, b"machine code").expect("wraps");
        assert_eq!(read(&bytes).unwrap_err().refusal, "precompiled_mismatch");
    }
}
