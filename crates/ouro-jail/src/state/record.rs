//! `jail-state.json`, typed (§7).
//!
//! Jail state is this tool's private record of one attempt: its claim, the
//! resources it registers before it creates them, cleanup progress and
//! `gc`'s reconciliation records. Every field keeps the wire shape it has
//! always had, so a file an earlier build wrote reads the same and is
//! rewritten byte for byte:
//!
//! - a device or inode of vendor state, of the proxy directory and of its
//!   socket, and a staged credential's source facts, are decimal strings
//!   ([`Decimal`]); the execution leaf's device and inode are JSON numbers;
//! - a field a file leaves out stays left out, and one it sets to null
//!   stays null ([`Field`]);
//! - keys this build does not know are kept as they are (each `rest`);
//! - [`JailState::to_bytes`] writes the keys sorted, as every build has.
//!
//! A value of another shape is not read as "not recorded": the whole file
//! fails to parse, and every reader reports it as state it cannot read.

use std::fmt::Display;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::records::StateCleanup;

/// A field jail state may leave out, set to null, or set.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum Field<T> {
    /// The key is not in the file.
    #[default]
    Absent,
    /// The key is there, with `null`.
    Null,
    /// The key is there, with a value.
    Set(T),
}

impl<T> Field<T> {
    /// The value, when the field is set.
    #[must_use]
    pub fn get(&self) -> Option<&T> {
        match self {
            Field::Set(value) => Some(value),
            Field::Absent | Field::Null => None,
        }
    }

    /// The value, when the field is set, to change it.
    pub fn get_mut(&mut self) -> Option<&mut T> {
        match self {
            Field::Set(value) => Some(value),
            Field::Absent | Field::Null => None,
        }
    }

    /// Whether the key is left out (it is then not written either).
    #[must_use]
    pub fn is_absent(&self) -> bool {
        matches!(self, Field::Absent)
    }

    /// `Set` for `Some`, `Null` for `None`: a value or an explicit null.
    #[must_use]
    pub fn or_null(value: Option<T>) -> Field<T> {
        value.map_or(Field::Null, Field::Set)
    }
}

impl<T: Default> Field<T> {
    /// The value, set to its default first when the field is not set: a
    /// nested record a write adds to.
    pub fn get_or_insert_default(&mut self) -> &mut T {
        if !matches!(self, Field::Set(_)) {
            *self = Field::Set(T::default());
        }
        match self {
            Field::Set(value) => value,
            Field::Absent | Field::Null => unreachable!("set just above"),
        }
    }
}

impl<T: Serialize> Serialize for Field<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Field::Set(value) => value.serialize(serializer),
            Field::Absent | Field::Null => serializer.serialize_none(),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(deserializer).map(Field::or_null)
    }
}

/// A number jail state records as a decimal string.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Decimal<T>(pub T);

impl<T: Display> Serialize for Decimal<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de, T> Deserialize<'de> for Decimal<T>
where
    T: FromStr,
    T::Err: Display,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map(Decimal).map_err(serde::de::Error::custom)
    }
}

/// `jail-state.json`.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct JailState {
    /// `ouro.jail.state/1` (`state::SCHEMA_STATE`).
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub schema: Field<String>,
    /// The attempt the root's claim is for.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub attempt_id: Field<String>,
    /// The claiming platform's OS.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub os: Field<String>,
    /// The claiming platform's architecture.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub arch: Field<String>,
    /// The claiming platform's kernel.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub kernel: Field<String>,
    /// The claiming build's version.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub component_version: Field<String>,
    /// When the root was claimed.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub claimed_at: Field<String>,
    /// The supervisor's birth identity; null where the platform has none.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub owner: Field<Owner>,
    /// The registered execution boundary, as the supervisor records it.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub boundary: Field<Value>,
    /// The execution leaf, registered by name before `mkdir` and by
    /// identity right after (N7).
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub execution_cgroup: Field<LeafEntry>,
    /// Registered vendor state.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub vendor_state: Field<VendorStateEntry>,
    /// Why a vendor-state registration was withdrawn.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub vendor_state_withdrawn: Field<String>,
    /// Vendor-state cleanup progress.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub state_cleanup: Field<StateCleanup>,
    /// The safe reason recorded with a `pending` cleanup.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub cleanup_reason: Field<String>,
    /// The registered proxy directory (§10).
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub proxy_dir: Field<ProxyDirEntry>,
    /// Why a proxy-directory registration was withdrawn.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub proxy_dir_withdrawn: Field<String>,
    /// The `OURO_JAIL_TEST_*` seams in force at the claim (S9).
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub test_seams: Field<Value>,
    /// `gc`'s reconciliation records (S6).
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub gc_actions: Field<Vec<GcAction>>,
    /// Keys this build does not know, kept as they are.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

impl JailState {
    /// Parses a jail state file.
    ///
    /// # Errors
    /// The parse failure: not JSON, or a field without the shape this tool
    /// writes.
    pub fn parse(bytes: &[u8]) -> serde_json::Result<JailState> {
        serde_json::from_slice(bytes)
    }

    /// The file's bytes: pretty JSON with every object's keys sorted, which
    /// is what every build has written (through an untyped value then).
    ///
    /// # Errors
    /// The serialization failure.
    pub fn to_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec_pretty(&serde_json::to_value(self)?)
    }
}

/// The supervisor's birth identity (§7).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Owner {
    /// The pid, recorded as a number.
    pub pid: u32,
    /// The boot it was recorded in.
    pub boot_id: String,
    /// Its birth time, field 22 of `/proc/<pid>/stat`.
    pub start_time_ticks: u64,
    /// Keys this build does not know.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// An execution leaf as jail state names it: its path, and its device and
/// inode as JSON numbers, or both null when only its name is registered.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct LeafEntry {
    /// The leaf's path.
    pub path: PathBuf,
    /// Its device.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub device: Field<u64>,
    /// Its inode.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub inode: Field<u64>,
    /// Keys this build does not know.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

impl LeafEntry {
    /// A leaf by its path and, when known, its `(device, inode)`; otherwise
    /// both are recorded null.
    #[must_use]
    pub fn new(path: PathBuf, identity: Option<(u64, u64)>) -> LeafEntry {
        LeafEntry {
            path,
            device: Field::or_null(identity.map(|(device, _)| device)),
            inode: Field::or_null(identity.map(|(_, inode)| inode)),
            rest: Map::new(),
        }
    }

    /// The recorded `(device, inode)`, when both are numbers.
    #[must_use]
    pub fn identity(&self) -> Option<(u64, u64)> {
        Some((*self.device.get()?, *self.inode.get()?))
    }

    /// Whether the entry names the leaf by its path only: device and inode
    /// both recorded null.
    #[must_use]
    pub fn is_name_only(&self) -> bool {
        matches!((&self.device, &self.inode), (Field::Null, Field::Null))
    }
}

/// Registered vendor state (§7, §12).
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct VendorStateEntry {
    /// The directory's name, `vendor-state`.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub name: Field<String>,
    /// When it was registered.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub registered_at: Field<String>,
    /// Its device once created, null before.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub dev: Field<Decimal<u64>>,
    /// Its inode once created, null before.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub ino: Field<Decimal<u64>>,
    /// The private provenance of the credentials staged into it.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub credentials: Field<Vec<CredentialEntry>>,
    /// Keys this build does not know.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

impl VendorStateEntry {
    /// The recorded `(dev, ino)`, once the directory was created.
    #[must_use]
    pub fn identity(&self) -> Option<(u64, u64)> {
        Some((self.dev.get()?.0, self.ino.get()?.0))
    }
}

/// One staged credential's private provenance (`state::PrivateCredential`).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CredentialEntry {
    /// The logical id.
    pub id: String,
    /// `copy_rw` or `bind_ro`.
    pub mode: String,
    /// Source device.
    pub source_dev: Decimal<u64>,
    /// Source inode.
    pub source_ino: Decimal<u64>,
    /// Source size at staging.
    pub source_size: Decimal<u64>,
    /// The content digest staging computed, or null.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub content_digest: Field<String>,
    /// Keys this build does not know.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// The registered proxy directory (§10).
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct ProxyDirEntry {
    /// The directory's name, `proxy`.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub name: Field<String>,
    /// When it was registered.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub registered_at: Field<String>,
    /// Its device once created, null before.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub dev: Field<Decimal<u64>>,
    /// Its inode once created, null before.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub ino: Field<Decimal<u64>>,
    /// Whether it was removed.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub removed: Field<bool>,
    /// Who removed it, when `gc` did.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub removed_by: Field<String>,
    /// Why it was retained: nothing proves it this attempt's to remove.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub retained: Field<String>,
    /// Why its removal failed: reading or removing it did not complete.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub failed: Field<String>,
    /// The socket node bound in it.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub socket: Field<SocketEntry>,
    /// Keys this build does not know.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

impl ProxyDirEntry {
    /// The recorded `(dev, ino)`, once the directory was created.
    #[must_use]
    pub fn identity(&self) -> Option<(u64, u64)> {
        Some((self.dev.get()?.0, self.ino.get()?.0))
    }
}

/// The proxy socket node as bound (`state::ProxySocketIdentity`).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SocketEntry {
    /// Device.
    pub dev: Decimal<u64>,
    /// Inode.
    pub ino: Decimal<u64>,
    /// Change time, seconds.
    pub ctime_sec: Decimal<i64>,
    /// Change time, nanoseconds.
    pub ctime_nsec: Decimal<i64>,
    /// Keys this build does not know.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// One of `gc`'s reconciliation records (S6). A record gc repeats is kept
/// once, with `count` and `last_at` (J4 wave 3, G5).
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct GcAction {
    /// What gc did: `gc_removed_cgroup`, `gc_finished`, ...
    pub action: String,
    /// When it first did it.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub at: Field<String>,
    /// When it last did it, once it did it again.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub last_at: Field<String>,
    /// How often it did it, once it did it again.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub count: Field<u64>,
    /// The execution leaf it acted on.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub execution_cgroup: Field<LeafEntry>,
    /// Whether the leaf was seen empty.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub verified_empty: Field<bool>,
    /// `name_only` for a leaf registered by name only.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub registered: Field<String>,
    /// What proved a removal of managed scratch permitted.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub basis: Field<String>,
    /// The temporary files it removed.
    #[serde(default, skip_serializing_if = "Field::is_absent")]
    pub names: Field<Vec<String>>,
    /// Keys this build does not know.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

impl GcAction {
    /// Whether `other` records the same act, whenever either happened.
    #[must_use]
    pub fn same_act(&self, other: &GcAction) -> bool {
        let timeless = |action: &GcAction| GcAction {
            at: Field::Absent,
            last_at: Field::Absent,
            count: Field::Absent,
            ..action.clone()
        };
        timeless(self) == timeless(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shape the supervisor and gc write, as an earlier build wrote
    /// them through an untyped value.
    fn written() -> Value {
        serde_json::json!({
            "schema": "ouro.jail.state/1",
            "attempt_id": "att_00000000-0000-4000-8000-000000000001",
            "os": "linux",
            "arch": "x86_64",
            "kernel": "7.0.0",
            "component_version": "0.1.0",
            "claimed_at": "2026-10-14T00:00:00Z",
            "owner": {"pid": 77, "boot_id": "boot", "start_time_ticks": 5},
            "boundary": {"kind": "pid_namespace", "verification_scope": "attempt_tree",
                "backend": null, "backend_version": null, "process": null},
            "execution_cgroup": {"path": "/sys/fs/cgroup/x/ouro-a.leaf", "device": 30,
                "inode": 4242},
            "vendor_state": {"name": "vendor-state", "registered_at": "t", "dev": "64768",
                "ino": "1234567", "credentials": [{"id": "c", "mode": "copy_rw",
                "source_dev": "1", "source_ino": "2", "source_size": "3",
                "content_digest": null}]},
            "state_cleanup": "pending",
            "cleanup_reason": null,
            "proxy_dir": {"name": "proxy", "registered_at": "t", "dev": "1", "ino": "2",
                "removed": true, "removed_by": "gc", "socket": {"dev": "1", "ino": "3",
                "ctime_sec": "1760000000", "ctime_nsec": "-1"}},
            "test_seams": {"OURO_JAIL_TEST_GC_MAX_ENTRIES": "4"},
            "gc_actions": [
                {"action": "gc_removing_cgroup", "at": "t0", "verified_empty": true,
                 "registered": "name_only",
                 "execution_cgroup": {"path": "/p", "device": null, "inode": null}},
                {"action": "gc_terminating_orphan", "at": "t1", "last_at": "t2", "count": 3,
                 "execution_cgroup": {"path": "/p", "device": 1, "inode": 2}},
                {"action": "gc_removed_scratch", "at": "t3", "basis": "b"},
                {"action": "gc_removed_temp_files", "at": "t4", "names": [".jail.json.x.tmp"]},
                {"action": "gc_finished", "at": "t5"},
            ],
        })
    }

    fn round_trip(value: &Value) -> Vec<u8> {
        let bytes = serde_json::to_vec_pretty(value).unwrap();
        JailState::parse(&bytes)
            .unwrap_or_else(|error| panic!("{error}: {value:#}"))
            .to_bytes()
            .unwrap()
    }

    #[test]
    fn every_written_shape_is_rewritten_byte_for_byte() {
        let written = written();
        assert_eq!(
            round_trip(&written),
            serde_json::to_vec_pretty(&written).unwrap()
        );
        let state = JailState::parse(&serde_json::to_vec(&written).unwrap()).unwrap();
        assert_eq!(
            state.vendor_state.get().unwrap().identity(),
            Some((64_768, 1_234_567))
        );
        assert_eq!(
            state.execution_cgroup.get().unwrap().identity(),
            Some((30, 4242))
        );
        assert!(
            state.gc_actions.get().unwrap()[0]
                .execution_cgroup
                .get()
                .unwrap()
                .is_name_only()
        );
        assert!(state.rest.is_empty(), "{:?}", state.rest);
    }

    /// A key a file leaves out stays left out, a null stays null, and a key
    /// this build does not know is kept, at every level.
    #[test]
    fn absent_null_and_unknown_keys_are_kept_as_they_are() {
        for value in [
            serde_json::json!({"schema": "ouro.jail.state/1"}),
            serde_json::json!({"schema": "ouro.jail.state/1", "vendor_state": null,
                "owner": null, "future": {"a": [1, 2]}}),
            serde_json::json!({"vendor_state": {"name": "vendor-state", "dev": null,
                "ino": null, "credentials": [], "later": 1}, "state_cleanup": "pending"}),
            serde_json::json!({"proxy_dir": {"dev": null, "ino": null, "removed": false},
                "proxy_dir_withdrawn": "w", "vendor_state_withdrawn": "w"}),
            serde_json::json!({"execution_cgroup": {"path": "/p", "device": null,
                "inode": null, "extra": "x"}}),
            serde_json::json!({}),
        ] {
            assert_eq!(
                round_trip(&value),
                serde_json::to_vec_pretty(&value).unwrap(),
                "{value:#}"
            );
        }
    }

    /// A field of another shape than the one written is not "unrecorded":
    /// the file does not parse.
    #[test]
    fn a_field_of_another_shape_fails_the_whole_file() {
        let base = written();
        for (pointer, value) in [
            ("/vendor_state/dev", serde_json::json!(64_768)),
            ("/proxy_dir/socket/ino", serde_json::json!(3)),
            ("/execution_cgroup/device", serde_json::json!("30")),
            ("/owner/pid", serde_json::json!(-1)),
            ("/owner/pid", serde_json::json!("77")),
            ("/state_cleanup", serde_json::json!("started")),
            ("/gc_actions", serde_json::json!({})),
            ("/gc_actions/0/verified_empty", serde_json::json!("true")),
        ] {
            let mut bad = base.clone();
            *bad.pointer_mut(pointer).unwrap() = value.clone();
            assert!(
                JailState::parse(&serde_json::to_vec(&bad).unwrap()).is_err(),
                "{pointer} = {value}"
            );
        }
    }

    #[test]
    fn a_repeated_act_is_the_same_act_whenever_it_happened() {
        let act = |at: &str, inode: u64| GcAction {
            action: "gc_terminating_orphan".to_owned(),
            at: Field::Set(at.to_owned()),
            execution_cgroup: Field::Set(LeafEntry::new("/p".into(), Some((1, inode)))),
            ..GcAction::default()
        };
        assert!(act("t1", 2).same_act(&act("t2", 2)));
        assert!(!act("t1", 2).same_act(&act("t1", 3)));
        let mut counted = act("t1", 2);
        counted.count = Field::Set(3);
        counted.last_at = Field::Set("t9".to_owned());
        assert!(counted.same_act(&act("t5", 2)));
    }
}
