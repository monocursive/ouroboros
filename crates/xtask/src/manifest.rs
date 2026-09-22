//! The expected-capability manifest and its comparison with `doctor --json`.
//!
//! jail-v1 §16: the conformance job carries "an explicit expected-capability
//! manifest", and "a required live capability being skipped makes the
//! conformance job fail". The manifest is the pinned expectation, so *any*
//! deviation fails and has to be changed deliberately — a host that silently
//! gained a capability is as much a change as one that lost it.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

/// The `[expected]` table: capability name to expected status.
#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub expected: BTreeMap<String, String>,
}

/// The statuses recognised by jail-v1 §3.1.
pub const STATUSES: &[&str] = &[
    "available",
    "unavailable",
    "unsupported",
    "error",
    "skipped",
];

impl Manifest {
    pub fn load(path: &Path) -> Result<Manifest, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read manifest {}: {e}", path.display()))?;
        let manifest: Manifest = toml::from_str(&text)
            .map_err(|e| format!("cannot parse manifest {}: {e}", path.display()))?;
        if manifest.expected.is_empty() {
            return Err(format!(
                "{} has an empty [expected] table: a comparison that cannot fail is not a check",
                path.display()
            ));
        }
        for (name, status) in &manifest.expected {
            if !STATUSES.contains(&status.as_str()) {
                return Err(format!(
                    "{}: capability `{name}` expects `{status}`, which is not one of {}",
                    path.display(),
                    STATUSES.join(", ")
                ));
            }
        }
        Ok(manifest)
    }
}

/// One row of the comparison.
#[derive(Debug, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub expected: String,
    pub actual: Option<String>,
    pub problem: Option<String>,
}

impl Row {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.problem.is_none()
    }
}

/// Pull `name -> status` out of whatever shape `doctor --json` used.
///
/// Four shapes are accepted, because the doctor output is owned by another J1
/// slice and only the capability vocabulary is fixed between us:
/// `{"capabilities": [{"name":…,"status":…}]}`, `{"capabilities": {name: …}}`,
/// a bare array of those objects, and a bare object of `name -> status`.
/// Anything else yields an empty map, which fails every expected row rather
/// than passing silently.
#[must_use]
pub fn statuses(doctor: &Value) -> BTreeMap<String, String> {
    let node = doctor.get("capabilities").unwrap_or(doctor);
    let mut out = BTreeMap::new();
    match node {
        Value::Array(items) => {
            for item in items {
                if let (Some(name), Some(status)) = (
                    item.get("name").and_then(Value::as_str),
                    item.get("status").and_then(Value::as_str),
                ) {
                    out.insert(name.to_string(), status.to_string());
                }
            }
        }
        Value::Object(map) => {
            for (name, value) in map {
                let status = match value {
                    Value::String(s) => Some(s.clone()),
                    other => other
                        .get("status")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                };
                if let Some(status) = status {
                    out.insert(name.clone(), status);
                }
            }
        }
        _ => {}
    }
    out
}

/// Compare every manifest row with the doctor report.
#[must_use]
pub fn compare(manifest: &Manifest, doctor: &Value) -> Vec<Row> {
    let actual = statuses(doctor);
    manifest
        .expected
        .iter()
        .map(|(name, expected)| {
            let got = actual.get(name).cloned();
            let problem = match got.as_deref() {
                None => Some("not reported by doctor".to_string()),
                Some("skipped") if expected != "skipped" => Some(
                    "doctor skipped this probe; a skipped check cannot satisfy a requirement"
                        .to_string(),
                ),
                Some(s) if s == expected => None,
                Some(s) => Some(format!(
                    "manifest expects `{expected}`, doctor reported `{s}`"
                )),
            };
            Row {
                name: name.clone(),
                expected: expected.clone(),
                actual: got,
                problem,
            }
        })
        .collect()
}

/// Capabilities doctor reported that the manifest does not mention. Not a
/// failure: it is a prompt to extend the manifest deliberately.
#[must_use]
pub fn unlisted(manifest: &Manifest, doctor: &Value) -> Vec<String> {
    statuses(doctor)
        .into_keys()
        .filter(|k| !manifest.expected.contains_key(k))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest() -> Manifest {
        Manifest {
            expected: BTreeMap::from([
                ("bwrap_present".to_string(), "available".to_string()),
                (
                    "cgroup_delegated_leaf".to_string(),
                    "unavailable".to_string(),
                ),
            ]),
        }
    }

    #[test]
    fn all_four_doctor_shapes_are_understood() {
        let want = BTreeMap::from([
            ("a".to_string(), "available".to_string()),
            ("b".to_string(), "unavailable".to_string()),
        ]);

        let array_under_key = json!({"capabilities":[
            {"name":"a","status":"available"},{"name":"b","status":"unavailable"}]});
        assert_eq!(statuses(&array_under_key), want);

        let object_under_key = json!({"capabilities":{
            "a":{"status":"available"},"b":{"status":"unavailable"}}});
        assert_eq!(statuses(&object_under_key), want);

        let bare_array = json!([
            {"name":"a","status":"available"},{"name":"b","status":"unavailable"}]);
        assert_eq!(statuses(&bare_array), want);

        let bare_object = json!({"a":"available","b":"unavailable"});
        assert_eq!(statuses(&bare_object), want);
    }

    #[test]
    fn an_unrecognised_shape_yields_nothing_rather_than_a_guess() {
        assert!(statuses(&json!("ready")).is_empty());
        assert!(statuses(&json!({"capabilities": 7})).is_empty());
    }

    #[test]
    fn a_matching_report_passes_every_row() {
        let doctor = json!({"capabilities":[
            {"name":"bwrap_present","status":"available"},
            {"name":"cgroup_delegated_leaf","status":"unavailable"}]});
        let rows = compare(&manifest(), &doctor);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(Row::ok), "{rows:?}");
    }

    #[test]
    fn a_skipped_probe_never_satisfies_a_required_capability() {
        let doctor = json!({"capabilities":[
            {"name":"bwrap_present","status":"skipped","reason_code":"no_time"},
            {"name":"cgroup_delegated_leaf","status":"unavailable"}]});
        let rows = compare(&manifest(), &doctor);
        let row = rows.iter().find(|r| r.name == "bwrap_present").unwrap();
        assert!(!row.ok());
        assert!(row.problem.as_ref().unwrap().contains("skipped"), "{row:?}");
    }

    #[test]
    fn a_missing_capability_fails_rather_than_being_ignored() {
        let doctor = json!({"capabilities":[{"name":"bwrap_present","status":"available"}]});
        let rows = compare(&manifest(), &doctor);
        let row = rows
            .iter()
            .find(|r| r.name == "cgroup_delegated_leaf")
            .unwrap();
        assert_eq!(row.actual, None);
        assert_eq!(row.problem.as_deref(), Some("not reported by doctor"));
    }

    #[test]
    fn a_capability_that_improved_is_still_a_deviation() {
        let doctor = json!({"capabilities":[
            {"name":"bwrap_present","status":"available"},
            {"name":"cgroup_delegated_leaf","status":"available"}]});
        let rows = compare(&manifest(), &doctor);
        let row = rows
            .iter()
            .find(|r| r.name == "cgroup_delegated_leaf")
            .unwrap();
        assert!(!row.ok(), "an unexpected `available` must be deliberate");
    }

    #[test]
    fn an_empty_doctor_report_fails_everything() {
        let rows = compare(&manifest(), &json!({}));
        assert!(rows.iter().all(|r| !r.ok()));
    }

    #[test]
    fn unlisted_capabilities_are_surfaced_but_not_failures() {
        let doctor = json!({"capabilities":[
            {"name":"bwrap_present","status":"available"},
            {"name":"cgroup_delegated_leaf","status":"unavailable"},
            {"name":"landlock","status":"available"}]});
        assert_eq!(unlisted(&manifest(), &doctor), vec!["landlock".to_string()]);
    }

    #[test]
    fn the_checked_in_manifest_loads_and_is_not_empty() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/specs/jail-v1/conformance-manifest.toml");
        let m = Manifest::load(&path).expect("the repository manifest must load");
        assert!(m.expected.len() >= 10, "{:?}", m.expected);
        assert_eq!(m.expected.get("bwrap_present").unwrap(), "available");
        assert_eq!(
            m.expected.get("cgroup_delegated_leaf").unwrap(),
            "unavailable"
        );
        assert_eq!(
            m.expected.get("nested_user_namespace").unwrap(),
            "unavailable"
        );
    }

    #[test]
    fn a_manifest_with_an_unknown_status_is_refused() {
        let dir = std::env::temp_dir().join(format!("xtask-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "[expected]\nx = \"probably\"\n").unwrap();
        let err = Manifest::load(&path).unwrap_err();
        assert!(err.contains("not one of"), "{err}");

        std::fs::write(&path, "[expected]\n").unwrap();
        let err = Manifest::load(&path).unwrap_err();
        assert!(err.contains("empty [expected] table"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
