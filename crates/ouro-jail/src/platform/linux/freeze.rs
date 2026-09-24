//! The canonical renderings the milestone-1 freeze pins (jail-v1 §16: "A
//! dependency update must not silently broaden mounted files or
//! allow-hosts"; review F3).
//!
//! `cargo xtask freeze` writes these into
//! `docs/specs/jail-v1/milestone-1-freeze.toml`, and
//! `tests/portable_freeze.rs` recomputes them and fails on drift. Both call
//! the functions here, so there is one definition of each rendering; what
//! each one covers is stated where it is built.
//!
//! The baselines are portable (policy resolution is shared code); the
//! backend plans exist only where the backend does.

use crate::policy::{ProfileName, ResolveInputs, ScratchRoot};
use crate::records::Os;

/// The built-in profiles, in the order the freeze lists them.
pub const PROFILES: [ProfileName; 4] = [
    ProfileName::Agent,
    ProfileName::Tool,
    ProfileName::Build,
    ProfileName::None,
];

/// One built-in profile's resolved baseline.
#[derive(Clone, Debug, PartialEq)]
pub struct Baseline {
    /// The profile.
    pub profile: ProfileName,
    /// The snapshot's policy digest (`ouro.jail.policy/1`).
    pub digest: String,
    /// The canonical snapshot.
    pub snapshot: serde_json::Value,
}

/// Each built-in profile resolved on Linux with fixed inputs: workspace
/// `/work`, a managed scratch root, no vendor state, no operator home, no
/// environment, no narrowing layer. The snapshot is everything the profile
/// grants (read-write, read-only and denied roots, protected coverage,
/// network, limits, observation, environment), so a broadened baseline is
/// a different digest.
///
/// # Errors
/// A baseline that does not resolve.
pub fn baselines() -> Result<Vec<Baseline>, crate::records::JailError> {
    PROFILES
        .iter()
        .map(|profile| {
            let inputs = ResolveInputs {
                platform: Os::Linux,
                base_profile: *profile,
                policy_name: profile.as_str().to_owned(),
                baseline: crate::profiles::baseline(*profile, Os::Linux, &|_| None),
                workspace: b"/work".to_vec(),
                scratch: ScratchRoot::Managed,
                vendor_state: None,
                operator_home: None,
                translation_prefixes: Vec::new(),
                layers: Vec::new(),
            };
            let resolved = crate::policy::resolve(&inputs)?;
            Ok(Baseline {
                profile: *profile,
                digest: resolved.digest,
                snapshot: resolved.snapshot.to_canonical_value()?,
            })
        })
        .collect()
}

/// `value` as JSON with every object's keys sorted, whatever map type
/// serde_json was built with; `pretty` puts one member per line.
#[must_use]
pub fn canonical_json(value: &serde_json::Value, pretty: bool) -> String {
    fn write(value: &serde_json::Value, pretty: bool, depth: usize, out: &mut String) {
        let indent = |out: &mut String, depth: usize| {
            if pretty {
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
        };
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    indent(out, depth + 1);
                    out.push_str(&serde_json::Value::String((*key).clone()).to_string());
                    out.push_str(if pretty { ": " } else { ":" });
                    write(&map[*key], pretty, depth + 1, out);
                }
                if !keys.is_empty() {
                    indent(out, depth);
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    indent(out, depth + 1);
                    write(item, pretty, depth + 1, out);
                }
                if !items.is_empty() {
                    indent(out, depth);
                }
                out.push(']');
            }
            scalar => out.push_str(&scalar.to_string()),
        }
    }
    let mut out = String::new();
    write(value, pretty, 0, &mut out);
    out
}

#[cfg(target_os = "linux")]
pub use self::linux::backend_plans;

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};

    use super::super::bwrap::{BwrapPlan, ETC_PATHS, RUNTIME_ROOTS};
    use super::super::fs::RootSpec;

    /// The bubblewrap invocation each contained profile's plan renders to,
    /// argv after the backend's own path: `BwrapPlan::tool`'s namespaces,
    /// mounts, flags and environment, with the declared runtime roots and
    /// `/etc` grants as binds (not this host's resolution of them, so the
    /// rendering is the same on every host), fixed placeholder paths, and
    /// each profile's workspace access (tool and agent writable, build
    /// read-only), with the descriptors preparation hands it (filter,
    /// status, arguments); the agent plan also binds a proxy directory and
    /// vendor state by descriptor. Preparation adds attempt-specific binds
    /// (protected paths, credentials) from the snapshot, which the baselines
    /// pin.
    ///
    /// # Errors
    /// A plan that does not render.
    pub fn backend_plans() -> Result<Vec<(&'static str, Vec<String>)>, String> {
        ["tool", "build", "agent"]
            .into_iter()
            .map(|profile| {
                let mut plan = BwrapPlan::tool(
                    Path::new("/freeze/workspace"),
                    Path::new("/freeze/scratch"),
                    Path::new("/freeze/ouro-jail"),
                );
                plan.bwrap = PathBuf::from("/freeze/bwrap");
                plan.roots = RUNTIME_ROOTS
                    .iter()
                    .map(|root| RootSpec::RoBind(PathBuf::from(root)))
                    .collect();
                plan.etc_paths = ETC_PATHS.iter().map(PathBuf::from).collect();
                plan.inner = vec!["/freeze/target".into()];
                plan.workspace_access = Some(profile != "build");
                // The descriptors preparation hands bubblewrap.
                plan.seccomp_fd = Some(super::super::platform::SECCOMP_FD);
                plan.json_status_fd = Some(super::super::platform::STATUS_FD);
                plan.args_fd = Some(super::super::platform::ARGS_FD);
                if profile == "agent" {
                    plan.proxy_dir = Some(PathBuf::from("/freeze/proxy"));
                    plan.proxy_dir_fd = Some(super::super::agent::PROXY_DIR_FD);
                    plan.vendor_state = Some(PathBuf::from("/freeze/vendor"));
                    plan.vendor_state_fd = Some(super::super::platform::VENDOR_STATE_FD);
                }
                let rendered = plan
                    .render()
                    .map_err(|error| format!("{profile}: {error}"))?;
                let argv = rendered
                    .argv
                    .iter()
                    .skip(1)
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect();
                Ok((profile, argv))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_every_object_and_keeps_arrays() {
        let value = serde_json::json!({"b": [3, {"z": 1, "a": null}], "a": "x"});
        assert_eq!(
            canonical_json(&value, false),
            r#"{"a":"x","b":[3,{"a":null,"z":1}]}"#
        );
        let pretty = canonical_json(&value, true);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&pretty).unwrap(),
            value
        );
        assert!(pretty.starts_with("{\n  \"a\": \"x\","), "{pretty}");
        assert_eq!(canonical_json(&serde_json::json!({}), true), "{}");
    }

    #[test]
    fn every_built_in_profile_has_a_baseline() {
        let baselines = baselines().expect("the built-in baselines resolve");
        let profiles: Vec<ProfileName> = baselines.iter().map(|b| b.profile).collect();
        assert_eq!(profiles, PROFILES);
        for baseline in &baselines {
            assert!(baseline.digest.starts_with("sha256:"), "{baseline:?}");
            assert_eq!(baseline.snapshot["profile"], baseline.profile.as_str());
        }
    }
}
