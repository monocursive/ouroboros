//! Fixtures the library's own tests share.
use serde_json::{Value, json};

use crate::protocol::Peer;

/// The token id the store records in provenance. The store never checks it;
/// the writer authenticates capabilities before a request reaches it.
pub(crate) const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// This process as an authenticated peer.
pub(crate) fn peer() -> Peer {
    Peer {
        uid: crate::fsx::euid(),
        pid: std::process::id(),
        birth: "fixture-birth".into(),
        boot_id: "fixture-boot".into(),
    }
}

/// The jail's example prepared receipt.
pub(crate) fn prepared_receipt() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/specs/jail-v1/examples/receipt-prepared.json"
    ))
    .expect("checked-in example receipt")
}

/// A strict, digest-only request plan bound to [`prepared_receipt`].
pub(crate) fn request() -> Value {
    let receipt = prepared_receipt();
    json!({"schema":crate::schemas::REQUEST,"profile":"tool","argv_digest":receipt["argv_digest"],
        "policy_digest":receipt["policy"]["digest"],"requirements":receipt["policy"]["requirements"],
        "jail_image_digest":receipt["argv_digest"],"io":{"mode":"batch","pty":false},
        "capture":{"streams":[],"limit_bytes":1_048_576},"evidence":"strict"})
}
