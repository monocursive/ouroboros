//! Seam S9: how a deployment asks for a startup service without owning one.
//!
//! Supervisors are W2-C's slice. This module is the boundary the engine talks through:
//! a trait with one production implementation that invokes `ouro fleet service <action>`
//! on the machine in question — locally as a subprocess of this binary, remotely as the
//! helper's `service` op — and one counting fake for tests.
//!
//! The honest statement about what is proven here: these tests prove the engine asks for
//! the right action on the right machine and reports what it was told. That a LaunchAgent
//! or a systemd user unit is really installed is `tui/tests/fleet_service.rs`'s claim,
//! not this module's. Where no supervisor exists, the engine says so and falls back to
//! the explicitly labelled manual-start path rather than claiming persistence.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use serde_json::{json, Value};

use super::helper;
use super::{refuse, sanitize_remote_text};

/// What the engine can ask a supervisor to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAction {
    Install,
    Status,
    Remove,
    /// Stop the unit from restarting the runtime, which is the first step of taking a
    /// member out of a fleet: "Removing/stopping a managed runtime first disables its
    /// supervisor so it cannot immediately restart."
    Disable,
    Start,
}

impl ServiceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Status => "status",
            Self::Remove => "remove",
            Self::Disable => "disable",
            Self::Start => "start",
        }
    }
}

/// What a supervisor said.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceOutcome {
    pub action: ServiceAction,
    /// Whether this machine has a user supervisor this product manages at all. `false`
    /// is the "no supported user supervisor/session" row of the proposal's table, and it
    /// is a result rather than a failure.
    pub supported: bool,
    /// A short, sanitized description for the operator and the journal.
    pub detail: String,
}

impl ServiceOutcome {
    pub fn unsupported(action: ServiceAction, detail: impl Into<String>) -> Self {
        Self {
            action,
            supported: false,
            detail: detail.into(),
        }
    }
}

/// The seam. Implemented once for production and once for tests.
pub trait ServiceActions: Send + Sync {
    /// Act on this machine's own supervisor.
    fn local(&self, action: ServiceAction) -> Result<ServiceOutcome>;

    /// Act on the target's supervisor, through an open helper session.
    fn remote(
        &self,
        session: &mut helper::Session,
        action: ServiceAction,
    ) -> Result<ServiceOutcome>;
}

/// Production: [`crate::fleet_service`] here, the helper's `service` op there.
pub struct LocalServiceActions {
    pub data_dir: PathBuf,
    pub timeout: Duration,
}

impl LocalServiceActions {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            timeout: Duration::from_secs(60),
        }
    }
}

/// Turn one service [`Report`](crate::fleet_service::Report) into the engine's small
/// answer: whether this machine has a supervisor at all, and one sentence about it.
fn summarize(action: ServiceAction, report: &crate::fleet_service::Report) -> ServiceOutcome {
    summarize_fields(
        action,
        report.supervisor.code(),
        &report.persistence,
        report.prerequisite.as_deref(),
        &report.notes,
    )
}

/// The same, from the report's JSON. The remote half reads the helper's reply this way
/// rather than through the struct: `Report::action` is a `&'static str`, so the type
/// serializes but cannot be deserialized, and the four fields the engine acts on are
/// simple values that a report from a newer `ouro` will still carry.
fn summarize_value(action: ServiceAction, report: &Value) -> ServiceOutcome {
    let notes: Vec<String> = report
        .get("notes")
        .and_then(Value::as_array)
        .map(|notes| {
            notes
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    summarize_fields(
        action,
        report
            .get("supervisor")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
        report
            .get("persistence")
            .and_then(Value::as_str)
            .unwrap_or("this machine did not say what its supervisor promises"),
        report.get("prerequisite").and_then(Value::as_str),
        &notes,
    )
}

fn summarize_fields(
    action: ServiceAction,
    supervisor: &str,
    persistence: &str,
    prerequisite: Option<&str>,
    notes: &[String],
) -> ServiceOutcome {
    // "unknown" is not "unsupported": a report this client could not read says nothing
    // about whether the machine has a supervisor, and calling it unsupported would turn
    // a parsing gap into a claim about the machine.
    let supported = supervisor != "unsupported";
    let mut detail = format!("{persistence} ({supervisor})");
    if let Some(prerequisite) = prerequisite {
        detail.push_str("; ");
        detail.push_str(prerequisite);
    }
    for note in notes {
        detail.push_str("; ");
        detail.push_str(note);
    }
    ServiceOutcome {
        action,
        supported,
        detail: sanitize_remote_text(&detail, 300),
    }
}

impl ServiceActions for LocalServiceActions {
    fn local(&self, action: ServiceAction) -> Result<ServiceOutcome> {
        let plan = crate::fleet_service::Plan::for_this_machine(&self.data_dir)?;
        let programs = crate::fleet_service::Programs::from_env()?;
        let report = match action {
            ServiceAction::Install => crate::fleet_service::install(&plan, &programs, false),
            ServiceAction::Status => crate::fleet_service::status(&plan, &programs),
            ServiceAction::Remove => crate::fleet_service::remove(&plan, &programs),
            ServiceAction::Disable => crate::fleet_service::disable(&plan, &programs),
            ServiceAction::Start => crate::fleet_service::start(&plan, &programs),
        };
        match report {
            Ok(report) => Ok(summarize(action, &report)),
            // "No supervisor here" is a supported outcome, not a failure: the engine
            // falls back to the explicitly labelled manual-start path. Anything else
            // keeps the reason the service slice declared.
            Err(error) => match crate::fleet_service::service_error(&error).map(|e| e.reason) {
                Some("unsupported_platform" | "unsupported") => Ok(ServiceOutcome::unsupported(
                    action,
                    sanitize_remote_text(&format!("{error}"), 300),
                )),
                Some(reason) => Err(super::SetupError {
                    reason: known_service_reason(reason),
                    detail: format!("{error}"),
                }
                .into()),
                None => Err(error),
            },
        }
    }

    fn remote(
        &self,
        session: &mut helper::Session,
        action: ServiceAction,
    ) -> Result<ServiceOutcome> {
        match session.ask("service", json!({ "action": action.as_str() })) {
            Ok(fields) => {
                let Some(report) = fields.get("report") else {
                    return refuse(
                        "helper_protocol",
                        "the target's service reply carried no report",
                    );
                };
                Ok(summarize_value(action, report))
            }
            // An older `ouro` on the target has no `service` op, and a target with no
            // supervisor says so. Both route the operator to the manual-start
            // instruction instead of promising automatic restart.
            Err(error)
                if matches!(
                    super::reason_of(&error),
                    Some("unsupported_op" | "unsupported_platform")
                ) =>
            {
                Ok(ServiceOutcome::unsupported(
                    action,
                    sanitize_remote_text(&format!("{error}"), 300),
                ))
            }
            Err(error) => Err(error),
        }
    }
}

/// The service slice's reason codes, matched against a closed list for the same reason
/// a remote helper's are: a reason decides which branch is taken.
fn known_service_reason(reason: &str) -> &'static str {
    const KNOWN: &[&str] = &[
        "unsupported_platform",
        "unusable_executable",
        "foreign_unit",
        "manager_unavailable",
        "manager_refused",
        "no_fleet",
    ];
    KNOWN
        .iter()
        .find(|known| **known == reason)
        .copied()
        .unwrap_or("service_refused")
}

/// A fake that records what it was asked and answers from a script.
///
/// Refuses an action it was not told about, so an engine test cannot pass by observing
/// a permissive default.
pub struct CountingServiceActions {
    local_calls: Mutex<Vec<ServiceAction>>,
    remote_calls: Mutex<Vec<ServiceAction>>,
    supported: bool,
    allowed: Vec<ServiceAction>,
}

impl CountingServiceActions {
    pub fn new(supported: bool, allowed: Vec<ServiceAction>) -> Self {
        Self {
            local_calls: Mutex::new(Vec::new()),
            remote_calls: Mutex::new(Vec::new()),
            supported,
            allowed,
        }
    }

    pub fn local_calls(&self) -> Vec<ServiceAction> {
        self.local_calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn remote_calls(&self) -> Vec<ServiceAction> {
        self.remote_calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn answer(&self, action: ServiceAction) -> Result<ServiceOutcome> {
        if !self.allowed.contains(&action) {
            return refuse(
                "service_refused",
                format!("this fake was not told to answer `{}`", action.as_str()),
            );
        }
        Ok(ServiceOutcome {
            action,
            supported: self.supported,
            detail: format!("fake {}", action.as_str()),
        })
    }
}

impl ServiceActions for CountingServiceActions {
    fn local(&self, action: ServiceAction) -> Result<ServiceOutcome> {
        self.local_calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(action);
        self.answer(action)
    }

    fn remote(
        &self,
        _session: &mut helper::Session,
        action: ServiceAction,
    ) -> Result<ServiceOutcome> {
        self.remote_calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(action);
        self.answer(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The action names are the ones seam S9 fixed, on both sides of the seam.
    #[test]
    fn the_action_names_are_the_ones_the_seam_fixed() {
        assert_eq!(
            [
                ServiceAction::Install,
                ServiceAction::Status,
                ServiceAction::Remove,
                ServiceAction::Disable,
                ServiceAction::Start,
            ]
            .map(ServiceAction::as_str),
            ["install", "status", "remove", "disable", "start"]
        );
    }

    /// A report this client could not read says nothing about the machine's supervisor,
    /// and "unknown" must not become "unsupported".
    #[test]
    fn an_unreadable_service_report_is_not_read_as_an_unsupported_machine() {
        let unsupported = summarize_value(
            ServiceAction::Install,
            &json!({"supervisor": "unsupported", "persistence": "no user supervisor here"}),
        );
        assert!(!unsupported.supported);

        let unreadable = summarize_value(ServiceAction::Install, &json!({}));
        assert!(
            unreadable.supported,
            "an unparsed report is not evidence that a machine has no supervisor"
        );

        let real = summarize_value(
            ServiceAction::Start,
            &json!({
                "supervisor": "launchd_user_session",
                "persistence": "starts at login",
                "prerequisite": Value::Null,
                "notes": ["started"]
            }),
        );
        assert!(real.supported);
        assert!(real.detail.contains("starts at login"));
        assert!(real.detail.contains("started"));
    }

    /// A reason the service slice declared reaches the engine unchanged; anything it
    /// did not declare becomes the generic refusal rather than a code nobody defined.
    #[test]
    fn service_reasons_are_matched_against_the_codes_this_engine_knows() {
        assert_eq!(known_service_reason("foreign_unit"), "foreign_unit");
        assert_eq!(known_service_reason("manager_refused"), "manager_refused");
        assert_eq!(known_service_reason("something_new"), "service_refused");
    }

    /// The fake refuses what it was not told to answer.
    #[test]
    fn the_counting_fake_refuses_an_action_it_was_not_scripted_for() {
        let actions = CountingServiceActions::new(true, vec![ServiceAction::Install]);
        assert!(actions.local(ServiceAction::Install).is_ok());
        assert!(actions.local(ServiceAction::Remove).is_err());
        assert_eq!(
            actions.local_calls(),
            vec![ServiceAction::Install, ServiceAction::Remove]
        );
    }
}
