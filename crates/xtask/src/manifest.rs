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
use ukai_jail::capability::Capability;

use crate::util::wire;

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

/// `name -> status` of `doctor --json`'s capability rows: the array of
/// `jail-doctor.schema.json`'s `capabilities`, read as the jail's own
/// [`Capability`] type.
///
/// # Errors
/// The report has no capability rows, or they are not capability rows.
pub fn statuses(doctor: &Value) -> Result<BTreeMap<String, String>, String> {
    let rows = doctor
        .get("capabilities")
        .ok_or("doctor reported no capabilities")?;
    let rows: Vec<Capability> = serde_json::from_value(rows.clone())
        .map_err(|e| format!("doctor's capabilities are not capability rows: {e}"))?;
    Ok(rows.into_iter().map(|c| (c.name, wire(c.status))).collect())
}

/// Compare every manifest row with the doctor report.
#[must_use]
pub fn compare(manifest: &Manifest, doctor: &Value) -> Vec<Row> {
    // Rows that cannot be read fail every expectation, never pass one.
    let (actual, unreadable) = match statuses(doctor) {
        Ok(actual) => (actual, None),
        Err(e) => (BTreeMap::new(), Some(e)),
    };
    manifest
        .expected
        .iter()
        .map(|(name, expected)| {
            let got = actual.get(name).cloned();
            let problem = match got.as_deref() {
                None => Some(
                    unreadable
                        .clone()
                        .unwrap_or_else(|| "not reported by doctor".to_string()),
                ),
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
        .unwrap_or_default()
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

    /// One capability row as `doctor --json` writes it.
    fn row(name: &str, status: &str) -> Value {
        json!({"name": name, "status": status, "scope": "host", "mechanism": null,
               "reason_code": null, "measured_at": null, "evidence_ref": null})
    }

    #[test]
    fn the_doctor_schemas_shape_is_read() {
        let doctor = json!({"capabilities": [row("a", "available"), row("b", "unavailable")]});
        assert_eq!(
            statuses(&doctor).unwrap(),
            BTreeMap::from([
                ("a".to_string(), "available".to_string()),
                ("b".to_string(), "unavailable".to_string()),
            ])
        );
        // The checked-in doctor example is that shape.
        let example: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/doctor-linux.json"
        ))
        .unwrap();
        assert!(!statuses(&example).unwrap().is_empty());
    }

    /// Review XT22: the shapes an older doctor might have used are not
    /// guessed at; anything but the schema's fails every expected row.
    #[test]
    fn any_other_shape_is_an_error_that_fails_every_row() {
        for other in [
            json!("ready"),
            json!({"capabilities": 7}),
            json!({"capabilities": {"bwrap_present": {"status": "available"}}}),
            json!([row("bwrap_present", "available")]),
            json!({"capabilities": [{"name": "bwrap_present", "status": "available"}]}),
        ] {
            assert!(statuses(&other).is_err(), "{other}");
            let rows = compare(&manifest(), &other);
            assert!(rows.iter().all(|r| !r.ok()), "{other}: {rows:?}");
        }
    }

    #[test]
    fn a_matching_report_passes_every_row() {
        let doctor = json!({"capabilities":[
            row("bwrap_present", "available"),
            row("cgroup_delegated_leaf", "unavailable")]});
        let rows = compare(&manifest(), &doctor);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(Row::ok), "{rows:?}");
    }

    #[test]
    fn a_skipped_probe_never_satisfies_a_required_capability() {
        let doctor = json!({"capabilities":[
            row("bwrap_present", "skipped"),
            row("cgroup_delegated_leaf", "unavailable")]});
        let rows = compare(&manifest(), &doctor);
        let row = rows.iter().find(|r| r.name == "bwrap_present").unwrap();
        assert!(!row.ok());
        assert!(row.problem.as_ref().unwrap().contains("skipped"), "{row:?}");
    }

    #[test]
    fn a_missing_capability_fails_rather_than_being_ignored() {
        let doctor = json!({"capabilities":[row("bwrap_present", "available")]});
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
            row("bwrap_present", "available"),
            row("cgroup_delegated_leaf", "unavailable"),
            row("landlock", "available")]});
        assert_eq!(unlisted(&manifest(), &doctor), vec!["landlock".to_string()]);
    }

    #[test]
    fn the_checked_in_manifest_loads_and_is_not_empty() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/specs/jail-v1/conformance-manifest.toml");
        let m = Manifest::load(&path).expect("the repository manifest must load");
        assert!(m.expected.len() >= 14, "{:?}", m.expected);
        assert_eq!(m.expected.get("bwrap_present").unwrap(), "available");
        assert_eq!(
            m.expected.get("cgroup_delegated_leaf").unwrap(),
            "available"
        );
        assert_eq!(
            m.expected.get("nested_user_namespace").unwrap(),
            "unavailable"
        );
    }

    #[test]
    fn a_manifest_with_an_unknown_status_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "[expected]\nx = \"probably\"\n").unwrap();
        let err = Manifest::load(&path).unwrap_err();
        assert!(err.contains("not one of"), "{err}");

        std::fs::write(&path, "[expected]\n").unwrap();
        let err = Manifest::load(&path).unwrap_err();
        assert!(err.contains("empty [expected] table"), "{err}");
    }
}
