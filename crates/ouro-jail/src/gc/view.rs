//! What `gc` reads: jail state and the last receipt, as the views
//! [`super::decide`] decides on.

use std::path::Path;

use serde_json::Value;

use super::host::{LeafRecord, OwnerRecord};
use super::leaf_name_of;
use crate::records::SCHEMA_RECEIPT;
use crate::state;

/// What `gc` needs from `jail-state.json`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StateView {
    /// The attempt it claims (the attempt root's name; `parse_state`
    /// refuses any other).
    pub attempt_id: String,
    /// The claiming platform's OS.
    pub os: String,
    /// The claiming platform's architecture.
    pub arch: String,
    /// The supervisor's birth identity; `None` where the platform had none.
    pub owner: Option<OwnerRecord>,
    /// N7: the execution leaf the platform registered in jail state, by
    /// name before `mkdir` and by identity right after; the only source of
    /// the leaf gc acts on (`recorded_leaf`).
    pub leaf: Option<RegisteredLeaf>,
    /// Leaves an earlier pass removed (`gc_removed_cgroup`).
    pub gc_removed: Vec<LeafRecord>,
    /// Leaves an earlier pass verified empty: terminated and seen empty
    /// (`gc_terminated_orphan`), about to be removed after it was seen empty
    /// (`gc_removing_cgroup`, J4 wave 3: by its path only for a leaf
    /// registered by name only), or removed (`gc_removed_cgroup`, which gc
    /// records only after the kernel removed an empty cgroup).
    pub gc_verified: Vec<VerifiedLeaf>,
    /// Whether an earlier pass removed managed scratch (`gc_removed_scratch`).
    pub gc_removed_scratch: bool,
    /// When an earlier pass found nothing left to do (`gc_finished`).
    pub gc_finished: Option<String>,
}

// N7
/// The execution leaf as jail state registers it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RegisteredLeaf {
    /// Named before `mkdir`; the supervisor died before it recorded the
    /// identity, so the leaf may or may not exist, and nothing was ever
    /// placed in it by this attempt (placement follows the identity record).
    Named(std::path::PathBuf),
    /// Identified right after `mkdir`, before anything was placed in it.
    Identified(LeafRecord),
}

/// A leaf an earlier pass verified empty, as gc recorded it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifiedLeaf {
    /// The leaf's path.
    pub path: std::path::PathBuf,
    /// Its `(device, inode)`; `None` for a leaf registered by name only,
    /// whose identity gc never knew when it saw it empty.
    pub identity: Option<(u64, u64)>,
}

impl VerifiedLeaf {
    /// Whether this is gc's record of the identified leaf `leaf`.
    #[must_use]
    pub fn is_of(&self, leaf: &LeafRecord) -> bool {
        self.path == leaf.path && self.identity == Some((leaf.device, leaf.inode))
    }
}

impl From<LeafRecord> for VerifiedLeaf {
    fn from(leaf: LeafRecord) -> VerifiedLeaf {
        VerifiedLeaf {
            identity: Some((leaf.device, leaf.inode)),
            path: leaf.path,
        }
    }
}

impl RegisteredLeaf {
    /// The registered path.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            RegisteredLeaf::Named(path) => path,
            RegisteredLeaf::Identified(leaf) => &leaf.path,
        }
    }

    /// Whether the identified leaf `leaf` (a receipt's) is this
    /// registration's.
    #[must_use]
    pub fn is(&self, leaf: &LeafRecord) -> bool {
        match self {
            RegisteredLeaf::Named(path) => leaf.path == *path,
            RegisteredLeaf::Identified(registered) => registered == leaf,
        }
    }

    /// Whether gc's record `verified` is of this registration: by its path
    /// for a leaf registered by name only, by its identity otherwise.
    #[must_use]
    pub fn verified_by(&self, verified: &VerifiedLeaf) -> bool {
        match self {
            RegisteredLeaf::Named(path) => verified.path == *path,
            RegisteredLeaf::Identified(registered) => verified.is_of(registered),
        }
    }
}

/// Where the execution leaf is, as gc reads it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LeafSource {
    /// No leaf is registered; why.
    NotRecorded(String),
    /// The registration.
    Recorded(LeafRecord),
    // N7
    /// Registered by name only, before `mkdir` (N7).
    NamedOnly(std::path::PathBuf),
    /// A registration that does not have the shape the supervisor writes.
    Malformed(String),
}

/// What `gc` needs from the last receipt, `jail.json`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceiptView {
    /// The lifecycle phase.
    pub phase: String,
    /// `lifetime.tree_empty`: `Some(true)` only after a verified tree end.
    pub tree_empty: Option<bool>,
    /// `lifetime.integrity`.
    pub integrity: String,
    /// `lifetime.boundary`: `pending` when no boundary ever existed.
    pub boundary: String,
    /// The boot the recorded process identity names, when it names one.
    pub boot_id: Option<String>,
    /// The execution leaf from `lifetime.native.details.execution_cgroup`.
    pub leaf: LeafSource,
}

impl ReceiptView {
    /// Whether the receipt itself proves that no tree of the attempt can
    /// still use what it left: the proof the vendor-state cleanup accepts
    /// (`cleanup::permitted_by`), a settlement or a refusal after a verified
    /// tree end, or a refusal before any boundary existed, never after lost
    /// integrity.
    #[must_use]
    pub fn proves_tree_end(&self) -> bool {
        self.integrity != "lost"
            && match self.phase.as_str() {
                "settled" => self.tree_empty == Some(true),
                "refused" => self.tree_empty == Some(true) || self.boundary == "pending",
                _ => false,
            }
    }
}

fn leaf_from(value: &Value) -> Option<LeafRecord> {
    Some(LeafRecord {
        path: value.get("path")?.as_str()?.into(),
        device: value.get("device")?.as_u64()?,
        inode: value.get("inode")?.as_u64()?,
    })
}

/// The jail-state entry of a leaf gc identified.
pub(super) fn leaf_entry(leaf: &LeafRecord) -> state::LeafEntry {
    state::LeafEntry::new(leaf.path.clone(), Some((leaf.device, leaf.inode)))
}

/// A leaf jail state records with its device and inode.
fn identified(entry: &state::LeafEntry) -> Option<LeafRecord> {
    let (device, inode) = entry.identity()?;
    Some(LeafRecord {
        path: entry.path.clone(),
        device,
        inode,
    })
}

/// Parses jail state for the attempt named `id`: the projection of
/// [`state::JailState`] gc decides on.
///
/// # Errors
/// Why the state is corrupt: not JSON, another schema, another attempt, or
/// a field without the shape the supervisor writes.
pub fn parse_state(bytes: &[u8], id: &str) -> Result<StateView, String> {
    let state = state::JailState::parse(bytes).map_err(|error| error.to_string())?;
    if state.schema.get().map(String::as_str) != Some(state::SCHEMA_STATE) {
        return Err(format!("the schema is not {}", state::SCHEMA_STATE));
    }
    if state.attempt_id.get().map(String::as_str) != Some(id) {
        return Err("it names another attempt".to_owned());
    }
    let text = |field: &state::Field<String>, key: &str| {
        field
            .get()
            .cloned()
            .ok_or_else(|| format!("`{key}` is missing"))
    };
    let owner = state.owner.get().map(|owner| OwnerRecord {
        pid: owner.pid,
        boot_id: owner.boot_id.clone(),
        start_time_ticks: owner.start_time_ticks,
    });
    // N7: `{path, device, inode}`, or `{path, null, null}` for a leaf named
    // before `mkdir` whose identity was never recorded.
    let leaf = match state.execution_cgroup.get() {
        None => None,
        Some(entry) if entry.is_name_only() => Some(RegisteredLeaf::Named(entry.path.clone())),
        Some(entry) => Some(
            identified(entry)
                .map(RegisteredLeaf::Identified)
                .ok_or("`execution_cgroup` is malformed")?,
        ),
    };
    let mut gc_removed = Vec::new();
    let mut gc_verified = Vec::new();
    let mut gc_removed_scratch = false;
    let mut gc_finished = None;
    for action in state.gc_actions.get().into_iter().flatten() {
        let verified_empty = action.verified_empty.get() == Some(&true);
        let leaf = action.execution_cgroup.get();
        match action.action.as_str() {
            "gc_removed_cgroup" => {
                if let Some(leaf) = leaf.and_then(identified) {
                    gc_verified.push(leaf.clone().into());
                    gc_removed.push(leaf);
                }
            }
            "gc_terminated_orphan" if verified_empty => {
                gc_verified.extend(leaf.and_then(identified).map(VerifiedLeaf::from));
            }
            // J4 wave 3 (G3): the intent, recorded after the leaf was seen
            // empty and before its `rmdir`; by name only (no device and
            // inode) for a leaf registered by name only.
            "gc_removing_cgroup" if verified_empty => {
                gc_verified.extend(leaf.and_then(|leaf| {
                    identified(leaf).map(VerifiedLeaf::from).or_else(|| {
                        leaf.is_name_only().then(|| VerifiedLeaf {
                            path: leaf.path.clone(),
                            identity: None,
                        })
                    })
                }));
            }
            "gc_removed_scratch" => gc_removed_scratch = true,
            // J4 wave 3 (G4)
            "gc_finished" => {
                gc_finished = Some(
                    action
                        .at
                        .get()
                        .cloned()
                        .unwrap_or_else(|| "an unrecorded time".to_owned()),
                );
            }
            _ => {}
        }
    }
    Ok(StateView {
        attempt_id: id.to_owned(),
        os: text(&state.os, "os")?,
        arch: text(&state.arch, "arch")?,
        owner,
        leaf,
        gc_removed,
        gc_verified,
        gc_removed_scratch,
        gc_finished,
    })
}

/// Parses the last receipt of the attempt named `id`.
///
/// # Errors
/// Why the receipt is corrupt: not JSON, another schema, another attempt, or
/// no lifecycle phase.
pub fn parse_receipt(bytes: &[u8], id: &str) -> Result<ReceiptView, String> {
    let receipt: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if receipt.get("schema").and_then(Value::as_str) != Some(SCHEMA_RECEIPT) {
        return Err(format!("the schema is not {SCHEMA_RECEIPT}"));
    }
    if receipt.get("attempt_id").and_then(Value::as_str) != Some(id) {
        return Err("it names another attempt".to_owned());
    }
    let phase = receipt
        .get("phase")
        .and_then(Value::as_str)
        .filter(|phase| ["prepared", "enforced", "settled", "refused"].contains(phase))
        .ok_or("it has no lifecycle phase")?
        .to_owned();
    let lifetime = receipt.get("lifetime").unwrap_or(&Value::Null);
    let native = lifetime.get("native").unwrap_or(&Value::Null);
    let leaf = if native.get("os").and_then(Value::as_str) == Some("linux") {
        match native
            .get("details")
            .and_then(|details| details.get("execution_cgroup"))
        {
            None | Some(Value::Null) => {
                LeafSource::NotRecorded("the receipt registers no execution cgroup".to_owned())
            }
            Some(value) if value.get("unavailable").is_some() => LeafSource::NotRecorded(
                "the run had no execution cgroup (its receipt says unavailable)".to_owned(),
            ),
            Some(value) => leaf_from(value).map_or_else(
                || {
                    LeafSource::Malformed(
                        "the registered execution cgroup has no path, device and inode".to_owned(),
                    )
                },
                LeafSource::Recorded,
            ),
        }
    } else {
        LeafSource::NotRecorded("the receipt records no Linux lifetime details".to_owned())
    };
    Ok(ReceiptView {
        phase,
        tree_empty: lifetime.get("tree_empty").and_then(Value::as_bool),
        integrity: lifetime
            .get("integrity")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        boundary: lifetime
            .get("boundary")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        boot_id: receipt
            .pointer("/process/identity/value/boot_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        leaf,
    })
}

/// Where the execution leaf's identity is read from.
///
/// J4 wave 2, N7: jail state, where the platform registers the leaf by name
/// before `mkdir` and by identity right after, so a supervisor that died
/// before any receipt still left its leaf findable. The receipt is not a
/// registration; when it names a leaf too, the two must agree, and records
/// that disagree are retained (§14.2).
pub(super) fn recorded_leaf(state: &StateView, receipt: Option<&ReceiptView>) -> LeafSource {
    // J4 wave 3 (G2): the leaf carries its attempt. A registration naming
    // any other leaf (another attempt's, or no execution leaf at all) is not
    // this attempt's, and gc never acts on it, whatever identity it records.
    if let Some(registered) = &state.leaf {
        let own = leaf_name_of(&state.attempt_id);
        let path = registered.path();
        if path.file_name() != Some(std::ffi::OsStr::new(&own)) {
            return LeafSource::Malformed(format!(
                "the registered leaf's name `{}` is not this attempt's (`{own}`): gc never acts \
                 on another attempt's leaf, nor on a cgroup that is no execution leaf",
                path.file_name().map_or_else(
                    || path.display().to_string(),
                    |name| name.to_string_lossy().into_owned()
                )
            ));
        }
    }
    let in_receipt = receipt.and_then(|receipt| match &receipt.leaf {
        LeafSource::Recorded(leaf) => Some(leaf),
        _ => None,
    });
    match (&state.leaf, in_receipt) {
        (None, _) => LeafSource::NotRecorded(
            "jail state registers no execution cgroup (a receipt alone is not a registration)"
                .to_owned(),
        ),
        (Some(registered), Some(named)) if !registered.is(named) => LeafSource::Malformed(
            "jail state and the receipt name different execution cgroups".to_owned(),
        ),
        (Some(RegisteredLeaf::Named(_)), Some(_)) => LeafSource::Malformed(
            "jail state registers the leaf by name only, but a receipt names its identity"
                .to_owned(),
        ),
        (Some(RegisteredLeaf::Identified(leaf)), _) => LeafSource::Recorded(leaf.clone()),
        (Some(RegisteredLeaf::Named(path)), None) => LeafSource::NamedOnly(path.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_and_receipt_views_refuse_what_the_supervisor_does_not_write() {
        let id = "att_00000000-0000-4000-8000-000000000001";
        let good = serde_json::json!({
            "schema": "ouro.jail.state/1", "attempt_id": id, "os": "linux", "arch": "x86_64",
            "owner": {"pid": 5, "boot_id": "b", "start_time_ticks": 9},
        });
        assert!(parse_state(&serde_json::to_vec(&good).unwrap(), id).is_ok());
        for (key, value) in [
            ("schema", serde_json::json!("ouro.jail.state/2")),
            ("attempt_id", serde_json::json!("att_other")),
            ("owner", serde_json::json!({"pid": "5"})),
            (
                "owner",
                serde_json::json!({"pid": -1, "boot_id": "b", "start_time_ticks": 9}),
            ),
            ("gc_actions", serde_json::json!({})),
            ("os", Value::Null),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                parse_state(&serde_json::to_vec(&bad).unwrap(), id).is_err(),
                "{key}"
            );
        }
        let receipt = serde_json::json!({
            "schema": SCHEMA_RECEIPT, "attempt_id": id, "phase": "enforced",
            "lifetime": {"native": {"os": "linux", "details": {"execution_cgroup":
                {"path": "/p", "device": 1, "inode": 2}}}},
        });
        let view = parse_receipt(&serde_json::to_vec(&receipt).unwrap(), id).unwrap();
        assert!(matches!(view.leaf, LeafSource::Recorded(_)));
        let mut malformed = receipt.clone();
        malformed["lifetime"]["native"]["details"]["execution_cgroup"]["inode"] =
            serde_json::json!("2");
        let view = parse_receipt(&serde_json::to_vec(&malformed).unwrap(), id).unwrap();
        assert!(matches!(view.leaf, LeafSource::Malformed(_)));
        let mut phaseless = receipt;
        phaseless["phase"] = serde_json::json!("running");
        assert!(parse_receipt(&serde_json::to_vec(&phaseless).unwrap(), id).is_err());
    }

    #[test]
    fn a_name_only_registration_parses_and_half_an_identity_does_not() {
        let id = "att_00000000-0000-4000-8000-000000000001";
        let state = |leaf: Value| {
            serde_json::to_vec(&serde_json::json!({
                "schema": "ouro.jail.state/1", "attempt_id": id, "os": "linux",
                "arch": "x86_64", "execution_cgroup": leaf,
            }))
            .unwrap()
        };
        let named = parse_state(
            &state(serde_json::json!({"path": "/p", "device": null, "inode": null})),
            id,
        )
        .unwrap();
        assert_eq!(named.leaf, Some(RegisteredLeaf::Named("/p".into())));
        let identified = parse_state(
            &state(serde_json::json!({"path": "/p", "device": 1, "inode": 2})),
            id,
        )
        .unwrap();
        assert!(matches!(
            identified.leaf,
            Some(RegisteredLeaf::Identified(_))
        ));
        for bad in [
            serde_json::json!({"path": "/p", "device": 1, "inode": null}),
            serde_json::json!({"path": "/p", "device": null}),
            serde_json::json!({"path": null, "device": null, "inode": null}),
        ] {
            assert!(parse_state(&state(bad.clone()), id).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_intent_record_is_a_verification_and_finished_is_read() {
        let id = "att_00000000-0000-4000-8000-000000000001";
        let parsed = parse_state(
            &serde_json::to_vec(&serde_json::json!({
                "schema": "ouro.jail.state/1", "attempt_id": id, "os": "linux", "arch": "x86_64",
                "gc_actions": [
                    {"action": "gc_removing_cgroup", "at": "t0", "verified_empty": true,
                     "execution_cgroup": {"path": "/a", "device": 1, "inode": 2}},
                    {"action": "gc_removing_cgroup", "at": "t0", "verified_empty": true,
                     "registered": "name_only",
                     "execution_cgroup": {"path": "/b", "device": null, "inode": null}},
                    {"action": "gc_removing_cgroup", "at": "t0",
                     "execution_cgroup": {"path": "/c", "device": 1, "inode": 2}},
                    {"action": "gc_finished", "at": "t9"},
                ],
            }))
            .unwrap(),
            id,
        )
        .unwrap();
        let paths: Vec<_> = parsed
            .gc_verified
            .iter()
            .map(|leaf| leaf.path.clone())
            .collect();
        assert_eq!(paths, [std::path::PathBuf::from("/a"), "/b".into()]);
        assert_eq!(parsed.gc_finished.as_deref(), Some("t9"));
        assert_eq!(parsed.attempt_id, id);
    }
}
