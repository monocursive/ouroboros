//! Simulated platforms for the in-process supervisor tests.
//!
//! The supervisor talks to the host only through `Platform`, so these tests
//! drive it with a platform that reports what the test scripts. What every
//! simulation shares lives here: one simulated Linux host in one boot, every
//! requirement available "through the simulation", the two boundaries the
//! Linux platforms create, and [`ScriptedPlatform`], a whole platform built
//! from an event script. A test that needs behaviour a script cannot state (a
//! side effect at a precise step, a trace sink it writes to) keeps its own
//! `PreparedExecution` and `RunningExecution` and uses the pieces.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ouro_jail::capability::{Capability, CapabilityScope, CapabilityStatus};
use ouro_jail::lifecycle::{BoundaryKind, Integrity, VerificationScope};
use ouro_jail::observer::CoverageSummary;
use ouro_jail::platform::{
    BoundaryIdentity, Deadline, OwnerIdentity, PlanRequest, Platform, PlatformIdentity,
    PreparedExecution, PreparedPlan, ReleaseFailure, RunEvent, RunningExecution, Sinks, StopReason,
    Teardown, TreeObservation,
};
use ouro_jail::records::{
    Applied, AppliedFilesystem, AppliedNetwork, AppliedSyscalls, JailError, NativeLifetime, Os,
    ProcessIdentity, ProcessRecord, rfc3339_utc,
};

/// The boot the simulated host is in.
pub const BOOT_ID: &str = "00000000-0000-4000-8000-000000000001";

/// The pid a simulated `none` boundary gives its launcher.
pub const LAUNCHER_PID: u32 = 4242;

/// This process as the supervisor, in boot `boot`.
#[must_use]
pub fn owner_in(boot: &str) -> OwnerIdentity {
    OwnerIdentity {
        pid: std::process::id(),
        boot_id: boot.to_owned(),
        start_time_ticks: 1,
    }
}

/// This process as the supervisor, in the simulated boot.
#[must_use]
pub fn owner() -> OwnerIdentity {
    owner_in(BOOT_ID)
}

/// The simulated Linux host.
#[must_use]
pub fn identity() -> PlatformIdentity {
    PlatformIdentity {
        os: Os::Linux,
        arch: "simulation".into(),
        kernel: "simulated".into(),
    }
}

/// Every requirement the plan names, available through the simulation, the
/// measurement citing `evidence`.
#[must_use]
pub fn available(plan: &PlanRequest, evidence: &str) -> Vec<Capability> {
    plan.requirements
        .iter()
        .map(|name| Capability {
            name: name.clone(),
            status: CapabilityStatus::Available,
            scope: CapabilityScope::Tree,
            mechanism: Some("simulation".into()),
            reason_code: Some("ok".into()),
            measured_at: Some(rfc3339_utc(SystemTime::now())),
            evidence_ref: Some(evidence.to_owned()),
        })
        .collect()
}

/// The boundary of a contained profile: a pid namespace, verified over the
/// attempt tree.
#[must_use]
pub fn namespace_boundary() -> BoundaryIdentity {
    BoundaryIdentity {
        boundary: BoundaryKind::PidNamespace,
        verification_scope: VerificationScope::AttemptTree,
        native: Some(NativeLifetime {
            os: Os::Linux,
            details: serde_json::Map::default(),
        }),
        process: None,
        backend: Some("simulation".into()),
        backend_version: Some("1".into()),
    }
}

/// `none`'s boundary: the supervisor's cgroup, verified over what it
/// registered, with the launcher at [`LAUNCHER_PID`].
#[must_use]
pub fn cgroup_boundary() -> BoundaryIdentity {
    BoundaryIdentity {
        boundary: BoundaryKind::SupervisorCgroup,
        verification_scope: VerificationScope::RegisteredBoundary,
        native: Some(NativeLifetime {
            os: Os::Linux,
            details: serde_json::Map::default(),
        }),
        process: Some(ProcessRecord {
            pid: LAUNCHER_PID,
            identity: ProcessIdentity {
                kind: "linux_boot_start".into(),
                value: Default::default(),
            },
        }),
        backend: Some("none".into()),
        backend_version: None,
    }
}

/// What a simulated contained boundary applied, saying it was simulated, with
/// network mode `network`.
#[must_use]
pub fn contained_applied(network: &str) -> Applied {
    Applied {
        filesystem: Some(AppliedFilesystem {
            mechanism: "simulation".into(),
            protected_coverage: "none".into(),
            mounts: Vec::new(),
        }),
        network: AppliedNetwork {
            mode: network.into(),
            mechanism: Some("simulation".into()),
            allowed_hosts: Vec::new(),
            tls_only: Vec::new(),
        },
        syscalls: Some(AppliedSyscalls {
            mechanism: "simulation".into(),
            digest: ouro_jail::canonical::sha256_prefixed(b"simulation"),
        }),
        limits: Vec::new(),
        environment_names: Vec::new(),
        removed_environment_names: Vec::new(),
    }
}

/// A tree verified empty now, over `scope`.
#[must_use]
pub fn verified_tree(scope: VerificationScope) -> TreeObservation {
    TreeObservation {
        tree_empty: Some(true),
        verified_at: Some(SystemTime::now()),
        verification_scope: scope,
        integrity: Integrity::Verified,
    }
}

/// A tree whose death was not established, over `scope`, with `integrity`.
#[must_use]
pub fn unverified_tree(scope: VerificationScope, integrity: Integrity) -> TreeObservation {
    TreeObservation {
        tree_empty: None,
        verified_at: None,
        verification_scope: scope,
        integrity,
    }
}

/// Something done at a point of the run, with what that point is given.
pub type Hook<T> = Arc<dyn Fn(&T) + Send + Sync>;

/// What the supervisor asked of a [`ScriptedPlatform`] run, in order.
#[derive(Clone, Default)]
pub struct Calls {
    /// Every `request_stop`.
    pub stops: Arc<Mutex<Vec<StopReason>>>,
    /// The budget of every `wait_tree`.
    pub tree_budgets: Arc<Mutex<Vec<Duration>>>,
}

/// A whole simulated platform, from a script: every requirement available,
/// the boundary given, `wait` reporting the scripted events in order and then
/// `then` for ever, tree verification reporting `tree`.
#[derive(Clone)]
pub struct ScriptedPlatform {
    /// What the measurements cite.
    pub evidence: &'static str,
    /// The boundary `prepare` creates.
    pub boundary: BoundaryIdentity,
    /// What it reports it applied (`None`: the supervisor's own view).
    pub applied: Option<Applied>,
    /// What `wait` reports, in order, once released.
    pub events: Vec<RunEvent>,
    /// What `wait` reports once the script is spent.
    pub then: RunEvent,
    /// What tree verification establishes. A verified tree is stamped with
    /// the time it is reported.
    pub tree: TreeObservation,
    /// What an aborted preparation's teardown establishes.
    pub abort_tree: Option<TreeObservation>,
    /// The observer's final account.
    pub observer: Option<CoverageSummary>,
    /// Run in `prepare`, before the boundary exists.
    pub on_prepare: Option<Hook<PreparedPlan>>,
    /// What the supervisor asked of the run.
    pub calls: Calls,
}

impl ScriptedPlatform {
    /// A target that execs and exits 0 inside `boundary`, whose tree is then
    /// verified empty over the boundary's own scope.
    #[must_use]
    pub fn new(evidence: &'static str, boundary: BoundaryIdentity) -> ScriptedPlatform {
        let tree = verified_tree(boundary.verification_scope);
        ScriptedPlatform {
            evidence,
            boundary,
            applied: None,
            events: vec![RunEvent::ExecConfirmed],
            then: RunEvent::TargetExited { code: 0 },
            tree,
            abort_tree: None,
            observer: None,
            on_prepare: None,
            calls: Calls::default(),
        }
    }

    /// The events `wait` reports before [`ScriptedPlatform::then`].
    #[must_use]
    pub fn events(mut self, events: impl IntoIterator<Item = RunEvent>) -> ScriptedPlatform {
        self.events = events.into_iter().collect();
        self
    }

    /// What `wait` reports once the script is spent.
    #[must_use]
    pub fn then(mut self, event: RunEvent) -> ScriptedPlatform {
        self.then = event;
        self
    }

    /// What tree verification establishes.
    #[must_use]
    pub fn tree(mut self, tree: TreeObservation) -> ScriptedPlatform {
        self.tree = tree;
        self
    }

    /// What an aborted preparation's teardown establishes.
    #[must_use]
    pub fn abort_tree(mut self, tree: TreeObservation) -> ScriptedPlatform {
        self.abort_tree = Some(tree);
        self
    }

    /// Something to do in `prepare`.
    #[must_use]
    pub fn on_prepare(
        mut self,
        hook: impl Fn(&PreparedPlan) + Send + Sync + 'static,
    ) -> ScriptedPlatform {
        self.on_prepare = Some(Arc::new(hook));
        self
    }
}

impl Platform for ScriptedPlatform {
    fn owner_identity(&self) -> Option<OwnerIdentity> {
        Some(owner())
    }
    fn identity(&self) -> PlatformIdentity {
        identity()
    }
    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        available(plan, self.evidence)
    }
    fn prepare(
        &self,
        plan: PreparedPlan,
        _: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        if let Some(hook) = &self.on_prepare {
            hook(&plan);
        }
        Ok(Box::new(ScriptedPrepared(self.clone())))
    }
}

struct ScriptedPrepared(ScriptedPlatform);

impl PreparedExecution for ScriptedPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        self.0.boundary.clone()
    }
    fn applied(&self) -> Option<Applied> {
        self.0.applied.clone()
    }
    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, Box<ReleaseFailure>> {
        Ok(Box::new(ScriptedRunning {
            events: self.0.events.clone().into(),
            script: self.0,
        }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown {
            tree: self.0.abort_tree.clone().map(stamped),
        })
    }
}

/// A verified observation reports the time it is made.
fn stamped(mut tree: TreeObservation) -> TreeObservation {
    if tree.verified_at.is_some() {
        tree.verified_at = Some(SystemTime::now());
    }
    tree
}

struct ScriptedRunning {
    script: ScriptedPlatform,
    events: std::collections::VecDeque<RunEvent>,
}

impl RunningExecution for ScriptedRunning {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        self.events
            .pop_front()
            .unwrap_or_else(|| self.script.then.clone())
    }
    fn request_stop(&mut self, reason: StopReason) {
        self.script.calls.stops.lock().unwrap().push(reason);
    }
    fn wait_tree(&mut self, budget: Duration) -> TreeObservation {
        self.script.calls.tree_budgets.lock().unwrap().push(budget);
        stamped(self.script.tree.clone())
    }
    fn observer_summary(&mut self) -> Option<CoverageSummary> {
        self.script.observer.clone()
    }
}
