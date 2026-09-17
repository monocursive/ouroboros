//! `ouro fleet add` and `ouro fleet leave --machine`, end to end over real SSH.
//!
//! Two data directories on one host, a real unprivileged `sshd` between them, and the
//! real `ouro fleet helper` on the far side. The issuer half runs in this process (it is
//! the half that holds the CA key and never speaks the protocol); everything the target
//! does crosses the SSH channel.
//!
//! What these prove that a unit test cannot: that the steps compose, that an operation
//! interrupted at a durable boundary resumes from that boundary instead of reissuing
//! credentials, that a third machine's admission updates the rosters of the first two,
//! that cooperative removal takes a member out of every remaining roster, and that the
//! journal a completed operation leaves behind contains no secret.

mod fleet_setup_support;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use fleet_setup_support::{account, scratch, ReleaseServer, Sshd, OURO};
use ouro::fleet;
use ouro::fleet_setup::challenge::{Answer, ChallengeKind};
use ouro::fleet_setup::engine::{Engine, Outcome};
use ouro::fleet_setup::gateway::ScriptedGateway;
use ouro::fleet_setup::journal::Journal;
use ouro::fleet_setup::service::{CountingServiceActions, ServiceAction};
use ouro::fleet_setup::ssh::Programs;
use ouro::fleet_setup::trust::Tools;
use ouro::fleet_setup::{
    reason_of, ChallengeRequest, Conversation, Event, IdentityChoice, OperationKind,
    OperationRequest, OperationState, PortPolicy,
};

/// A conversation that accepts host keys and plans, records everything, and refuses to
/// invent a secret it was not given.
struct Operator {
    accept_hosts: bool,
    asked: Mutex<Vec<ChallengeKind>>,
    events: Mutex<Vec<String>>,
    cancel_after: Mutex<Option<String>>,
    cancelled: AtomicBool,
    refusals: AtomicU32,
}

impl Operator {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            accept_hosts: true,
            asked: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            cancel_after: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            refusals: AtomicU32::new(0),
        })
    }

    /// Stop the operation the moment the named step is recorded, which is how the
    /// interruption tests land on an exact durable boundary.
    fn stopping_after(step: &str) -> Arc<Self> {
        let operator = Self::new();
        *operator
            .cancel_after
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(step.to_string());
        operator
    }

    fn refusing_hosts() -> Arc<Self> {
        Arc::new(Self {
            accept_hosts: false,
            asked: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            cancel_after: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            refusals: AtomicU32::new(0),
        })
    }

    fn asked(&self) -> Vec<ChallengeKind> {
        self.asked.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn steps(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl Conversation for Operator {
    fn ask(&self, request: ChallengeRequest) -> anyhow::Result<Answer> {
        self.asked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request.kind);
        match request.kind {
            ChallengeKind::HostTrust => Ok(Answer::Trust(self.accept_hosts)),
            ChallengeKind::Review => Ok(Answer::Approval {
                plan_digest: request.metadata["plan_digest"]
                    .as_str()
                    .expect("a review challenge carries the digest it is binding")
                    .to_string(),
            }),
            // A key with no passphrase and no password method: being asked for a secret
            // means the engine took a path this test did not intend.
            ChallengeKind::Password | ChallengeKind::Passphrase => {
                self.refusals.fetch_add(1, Ordering::SeqCst);
                ouro::fleet_setup::refuse(
                    "cancelled",
                    "this operation was not supposed to need a secret",
                )
            }
        }
    }

    fn notify(&self, event: Event) {
        if let Event::Step { step, outcome, .. } = &event {
            self.events
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(format!("{step}:{outcome}"));
            let stop = self
                .cancel_after
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if stop.as_deref() == Some(step.as_str()) && outcome == "ok" {
                self.cancelled.store(true, Ordering::SeqCst);
            }
        }
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Everything one end-to-end scenario needs.
struct Lab {
    rig: Sshd,
    issuer: PathBuf,
}

impl Lab {
    fn new(label: &str, machine: &str) -> Self {
        let rig = Sshd::start(label);
        let issuer = data_dir(&format!("{label}-i"));
        fleet::create(
            &issuer,
            Some("the lab"),
            machine,
            "127.0.0.1",
            ephemeral().into(),
        )
        .expect("a created fleet on the issuer");
        Self { rig, issuer }
    }

    fn request(&self, operation: &str, machine: &str, target: &Path) -> OperationRequest {
        let mut request = OperationRequest::new(operation, OperationKind::Add, machine);
        request.address = Some("127.0.0.1".into());
        request.ssh_user = Some(account());
        request.ssh_port = Some(self.rig.port);
        request.identity = IdentityChoice::Key {
            path: self.rig.client_key.clone(),
        };
        // An absolute path names an existing installation: the built `ouro` this test
        // was compiled beside. The missing-binary path is exercised separately.
        request.install_path = Some(OURO.to_string());
        request.remote_data_dir = Some(target.display().to_string());
        request.service = false;
        request.ports = OperationRequest::read(&self.issuer, operation)
            .ok()
            .and_then(|previous| previous.ports)
            .or_else(|| Some(ephemeral()));
        request
    }

    fn engine(
        &self,
        request: OperationRequest,
        conversation: Arc<dyn Conversation>,
        gateway: Arc<ScriptedGateway>,
        services: Arc<CountingServiceActions>,
    ) -> Engine {
        Engine {
            data_dir: self.issuer.clone(),
            token_file: self.issuer.join("gateway.token"),
            request,
            conversation,
            gateway,
            services,
            programs: Programs {
                ssh: PathBuf::from("/usr/bin/ssh"),
                ssh_add: PathBuf::from("/usr/bin/ssh-add"),
                keygen: PathBuf::from("/usr/bin/ssh-keygen"),
                askpass: PathBuf::from(OURO),
                agent_socket: None,
            },
            trust_tools: Tools {
                keyscan: PathBuf::from("/usr/bin/ssh-keyscan"),
                keygen: PathBuf::from("/usr/bin/ssh-keygen"),
            },
            user_known_hosts: None,
            origin: ouro::update::release::Origin::official(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            owner: Some("tester".to_string()),
        }
    }
}

fn data_dir(label: &str) -> PathBuf {
    let path = scratch(label);
    // A data directory handed to `ouro` is a private same-user boundary.
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("a private data directory");
    }
    path
}

/// `fleet::ephemeral_ports` binds to find free ports, so two threads that call it at the
/// same moment can be handed the same number. Every test here that chooses ports holds
/// this for its duration.
static PORTS: Mutex<()> = Mutex::new(());

fn ephemeral() -> PortPolicy {
    let _held = PORTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let ports = fleet::ephemeral_ports();
    PortPolicy {
        gateway: ports.gateway,
        dist: ports.dist,
        epmd: ports.epmd,
    }
}

/// A gateway that answers `fleet.status` with the given machines and refuses anything
/// else, so a test cannot pass by observing a permissive default.
fn gateway(connected: &[&str]) -> Arc<ScriptedGateway> {
    let machines: Vec<Value> = connected
        .iter()
        .map(|machine| json!({"machine": machine, "connected": true, "sessions": 0}))
        .collect();
    Arc::new(ScriptedGateway::new(
        true,
        vec![("fleet.status", json!({ "machines": machines }))],
    ))
}

fn services() -> Arc<CountingServiceActions> {
    Arc::new(CountingServiceActions::new(
        true,
        vec![
            ServiceAction::Install,
            ServiceAction::Start,
            ServiceAction::Disable,
        ],
    ))
}

/// A whole machine admitted over real SSH, with the rosters of both sides updated.
#[test]
fn a_machine_joins_over_real_ssh_and_both_rosters_name_it() {
    let lab = Lab::new("add", "studio");
    let target = data_dir("add-t");
    let operator = Operator::new();
    let gateway = gateway(&["studio", "vps"]);
    let services = services();

    let outcome = lab
        .engine(
            lab.request("op-0000000000a1", "vps", &target),
            operator.clone(),
            gateway.clone(),
            services.clone(),
        )
        .run()
        .expect("an admitted machine");

    assert_eq!(outcome.state, OperationState::Completed, "{outcome:?}");
    // Startup was deliberately manual here, so connectivity is not observed and the
    // final line says what to do next rather than claiming a connection.
    assert!(
        outcome.next.contains("Start the runtime on vps"),
        "{}",
        outcome.next
    );
    assert!(
        outcome
            .unknown
            .iter()
            .any(|note| note.contains("manual startup was chosen")),
        "an unobserved connection is named as unknown: {:?}",
        outcome.unknown
    );

    // The operator was asked exactly the two questions the proposal requires, in order.
    assert_eq!(
        operator.asked(),
        vec![ChallengeKind::HostTrust, ChallengeKind::Review],
        "an unknown host is confirmed before the plan is approved"
    );

    // The target really is a member now, with a profile of its own.
    let installed = fleet::load(&target)
        .expect("a readable target profile")
        .expect("an installed target profile");
    assert_eq!(installed.machine, "vps");
    assert_eq!(installed.host, "127.0.0.1");
    assert_eq!(installed.node, "ouro-vps@127.0.0.1");
    let mut members: Vec<&str> = installed
        .members
        .iter()
        .map(|member| member.machine.as_str())
        .collect();
    members.sort_unstable();
    assert_eq!(members, vec!["studio", "vps"]);

    // And the issuer's own roster names it.
    let issuer = fleet::load(&lab.issuer)
        .expect("a readable issuer profile")
        .expect("an issuer profile");
    assert!(issuer.members.iter().any(|member| member.machine == "vps"));

    // The steps that happened are the ones the proposal lists, and startup was left
    // manual because this run asked for it.
    let steps = outcome
        .steps
        .iter()
        .filter(|step| step.outcome == "ok")
        .map(|step| step.step.as_str())
        .collect::<Vec<_>>();
    for required in ["inspect", "prepare", "issue", "install", "roster"] {
        assert!(
            steps.contains(&required),
            "missing `{required}` in {steps:?}"
        );
    }
    assert!(
        outcome
            .steps
            .iter()
            .any(|step| step.step == "connect" && step.outcome == "skipped"),
        "connectivity is recorded as not observed, rather than claimed: {:?}",
        outcome.steps
    );
    assert!(
        services.remote_calls().is_empty(),
        "--no-service asks a supervisor for nothing"
    );
    assert!(
        gateway.calls().is_empty(),
        "an admission that starts nothing asks this machine's runtime nothing: {:?}",
        gateway.calls()
    );
    assert_eq!(gateway.refusals(), 0, "the engine asked for nothing else");

    // Rerunning the same operation is a no-op rather than a second certificate.
    let again = lab
        .engine(
            lab.request("op-0000000000a1", "vps", &target),
            Operator::new(),
            gateway.clone(),
            services.clone(),
        )
        .run()
        .expect("a completed operation is idempotent");
    assert_eq!(again.state, OperationState::Completed);
    assert!(
        again.summary.contains("already completed"),
        "{}",
        again.summary
    );
}

/// The journal a completed admission leaves behind has no secret in it — not the fleet
/// cookie, not a key, not anything from a private file.
#[test]
fn nothing_the_operation_writes_contains_a_secret() {
    let lab = Lab::new("secret", "studio");
    let target = data_dir("secret-t");

    lab.engine(
        lab.request("op-0000000000b2", "vps", &target),
        Operator::new(),
        gateway(&["studio", "vps"]),
        services(),
    )
    .run()
    .expect("an admitted machine");

    let cookie = std::fs::read_to_string(lab.issuer.join("fleet/cookie"))
        .expect("the fleet cookie")
        .trim()
        .to_string();
    assert!(cookie.len() > 16, "a cookie worth searching for");
    let ca_key = std::fs::read_to_string(lab.issuer.join("fleet/ca-key.pem")).expect("the CA key");
    let ca_body = ca_key
        .lines()
        .find(|line| !line.starts_with("-----") && line.len() > 20)
        .expect("a line of key material")
        .to_string();

    for (label, needle) in [
        ("the cookie", cookie.as_str()),
        ("the CA key", ca_body.as_str()),
    ] {
        for root in [
            ouro::fleet_setup::deploy_dir(&lab.issuer),
            ouro::fleet_setup::deploy_dir(&target),
            fleet::receipts_dir(&lab.issuer),
            fleet::receipts_dir(&target),
        ] {
            assert!(
                !contains(&root, needle),
                "{label} must not appear under {}",
                root.display()
            );
        }
    }

    // The journal is a document an operator and a broker both read; its whole shape is
    // names, times and outcomes.
    let record = Journal::read(&lab.issuer, "op-0000000000b2")
        .expect("a readable journal")
        .expect("a written journal");
    let encoded = serde_json::to_string(&record).expect("an encodable journal");
    for forbidden in ["PRIVATE KEY", "cookie", "password", "passphrase"] {
        assert!(
            !encoded.to_lowercase().contains(&forbidden.to_lowercase()),
            "the journal must not mention `{forbidden}`: {encoded}"
        );
    }
    assert_eq!(record.state, OperationState::Completed);
}

/// Interrupting at each durable boundary and resuming: no step happens twice, and no
/// certificate is minted a second time.
#[test]
fn an_interrupted_operation_resumes_from_its_durable_boundary() {
    let lab = Lab::new("resume", "studio");
    let target = data_dir("resume-t");

    // Stop right after the target's key is prepared. The issuer has issued nothing.
    let stopper = Operator::stopping_after("prepare");
    let stopped = lab
        .engine(
            lab.request("op-0000000000c3", "vps", &target),
            stopper.clone(),
            gateway(&["studio", "vps"]),
            services(),
        )
        .run()
        .expect_err("the operation was cancelled at a boundary");
    assert_eq!(reason_of(&stopped), Some("cancelled"));
    assert!(
        stopper.steps().iter().any(|step| step == "prepare:ok"),
        "the boundary was reached: {:?}",
        stopper.steps()
    );

    let mid = Journal::read(&lab.issuer, "op-0000000000c3")
        .expect("a readable journal")
        .expect("a written journal");
    assert_eq!(mid.state, OperationState::Cancelled);
    assert!(mid.completed("vps", "prepare"));
    assert!(!mid.completed("vps", "issue"), "nothing was issued");
    assert!(
        mid.residue.iter().any(|note| note.contains("prepared key")),
        "the residue a cancellation left is named: {:?}",
        mid.residue
    );
    assert!(
        fleet::load(&target).expect("a readable target").is_none(),
        "a cancelled operation leaves the target standalone"
    );

    // Resuming the same operation id finishes it, and `prepare` is not repeated.
    let resumed = lab
        .engine(
            lab.request("op-0000000000c3", "vps", &target),
            Operator::new(),
            gateway(&["studio", "vps"]),
            services(),
        )
        .run()
        .expect("a resumed operation completes");
    assert_eq!(resumed.state, OperationState::Completed);
    let prepares = resumed
        .steps
        .iter()
        .filter(|step| step.step == "prepare")
        .count();
    assert_eq!(
        prepares, 1,
        "one machine's one step appears once, whatever a resume re-verified"
    );
    let issues = resumed
        .steps
        .iter()
        .filter(|step| step.step == "issue")
        .count();
    assert_eq!(issues, 1, "exactly one certificate was ever issued");
    assert!(fleet::load(&target).expect("a readable target").is_some());
}

/// A roster that moved under a reviewed plan is a reconciliation refusal, never a lost
/// update.
#[test]
fn a_roster_that_moved_under_the_plan_is_refused_rather_than_overwritten() {
    let lab = Lab::new("roster", "studio");
    let target = data_dir("roster-t");

    let stopper = Operator::stopping_after("prepare");
    let _ = lab
        .engine(
            lab.request("op-0000000000d4", "vps", &target),
            stopper,
            gateway(&["studio"]),
            services(),
        )
        .run()
        .expect_err("cancelled at the prepare boundary");

    // An ordinary roster edit lands while the operation is paused.
    fleet::add_member(&lab.issuer, "laptop", "127.0.0.2", None).expect("an unrelated roster edit");

    let refused = lab
        .engine(
            lab.request("op-0000000000d4", "vps", &target),
            Operator::new(),
            gateway(&["studio"]),
            services(),
        )
        .run()
        .expect_err("the source roster changed under the plan");
    assert!(
        matches!(reason_of(&refused), Some("roster_changed" | "plan_changed")),
        "a moved roster is reconciled, not overwritten: {refused:#}"
    );
    assert!(
        fleet::load(&target).expect("a readable target").is_none(),
        "nothing was delivered to the target"
    );
}

/// An unaccepted host key stops the operation before anything is sent.
#[test]
fn a_declined_host_key_sends_nothing() {
    let lab = Lab::new("decline", "studio");
    let target = data_dir("declin-t");

    let refused = lab
        .engine(
            lab.request("op-0000000000e5", "vps", &target),
            Operator::refusing_hosts(),
            gateway(&["studio"]),
            services(),
        )
        .run()
        .expect_err("a declined host key stops the operation");
    assert_eq!(reason_of(&refused), Some("host_trust_declined"));
    assert!(fleet::load(&target).expect("a readable target").is_none());
    assert!(
        !ouro::fleet_setup::known_hosts_path(&lab.issuer).exists(),
        "a declined key is not recorded"
    );
}

/// A third machine joins, and the roster update reaches the second one over SSH.
#[test]
fn a_third_machine_updates_the_roster_of_the_second_over_ssh() {
    let lab = Lab::new("third", "studio");
    let second = data_dir("third-2");
    let third = data_dir("third-3");

    lab.engine(
        lab.request("op-0000000000f6", "vps", &second),
        Operator::new(),
        gateway(&["studio", "vps"]),
        services(),
    )
    .run()
    .expect("the second machine joins");

    let second_before = fleet::load(&second)
        .expect("a readable second profile")
        .expect("a second profile");

    // The third machine's admission has to reach the second one, which here is the same
    // host over the same rig but a different data directory. That is exactly what the
    // per-member access map is for: each existing member is named explicitly rather than
    // assumed to be reachable the way the target is.
    let mut request = lab.request("op-0000000000f7", "buildbox", &third);
    request.members.insert(
        "vps".to_string(),
        ouro::fleet_setup::MemberAccess {
            ssh_user: Some(account()),
            ssh_port: Some(lab.rig.port),
            install_path: Some(OURO.to_string()),
            data_dir: Some(second.display().to_string()),
        },
    );
    let outcome = lab
        .engine(
            request,
            Operator::new(),
            gateway(&["studio", "vps", "buildbox"]),
            services(),
        )
        .run()
        .expect("a third machine joins");

    assert_eq!(outcome.state, OperationState::Completed);
    let second_after = fleet::load(&second)
        .expect("a readable second profile")
        .expect("a second profile");
    assert!(
        second_after
            .members
            .iter()
            .any(|member| member.machine == "buildbox"),
        "the existing member learned about the newcomer"
    );
    assert!(
        second_after.roster_revision > second_before.roster_revision,
        "the existing member's roster moved"
    );

    // And the newcomer got the complete agreed roster, not just the issuer.
    let third_profile = fleet::load(&third)
        .expect("a readable third profile")
        .expect("a third profile");
    let mut names: Vec<&str> = third_profile
        .members
        .iter()
        .map(|member| member.machine.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["buildbox", "studio", "vps"]);
}

/// Cooperative removal: the member is stopped, its credentials are retired there, and
/// every remaining roster drops it. No tombstone is written.
#[test]
fn leave_machine_retires_a_member_and_every_remaining_roster_drops_it() {
    let lab = Lab::new("leave", "studio");
    let target = data_dir("leave-t");

    lab.engine(
        lab.request("op-000000001100", "vps", &target),
        Operator::new(),
        gateway(&["studio", "vps"]),
        services(),
    )
    .run()
    .expect("the machine joins");
    assert!(fleet::load(&target).expect("a readable target").is_some());

    let mut request = lab.request("op-000000001101", "vps", &target);
    request.kind = OperationKind::Leave;
    request.address = Some("127.0.0.1".into());
    let services = services();
    // `fleet.status` no longer names it, which is what "verify it is disconnected" reads.
    let outcome = lab
        .engine(
            request,
            Operator::new(),
            gateway(&["studio"]),
            services.clone(),
        )
        .run()
        .expect("a cooperative removal");

    assert_eq!(outcome.state, OperationState::Completed);
    assert!(
        outcome.next.contains("No tombstone is recorded"),
        "removal names the decision it did not make: {}",
        outcome.next
    );
    assert!(
        outcome.next.contains("sessions forget --machine vps"),
        "{}",
        outcome.next
    );

    // The member is standalone again, and its data directory still exists.
    assert!(
        fleet::load(&target).expect("a readable target").is_none(),
        "the member's credentials were retired on the member itself"
    );
    assert!(target.exists(), "removal retains the machine's own data");

    // The issuer's roster dropped it, and recorded no tombstone.
    let issuer = fleet::load(&lab.issuer)
        .expect("a readable issuer profile")
        .expect("an issuer profile");
    assert!(!issuer.members.iter().any(|member| member.machine == "vps"));
    assert!(
        issuer.tombstones.is_empty(),
        "cooperative removal records no tombstone: {:?}",
        issuer.tombstones
    );

    // The supervisor was disabled before anything else, so it could not restart it.
    assert_eq!(
        services.remote_calls().first(),
        Some(&ServiceAction::Disable),
        "the managed supervisor is disabled first"
    );
}

/// The missing-binary path: the exact own-version artifact, verified, uploaded through
/// the one fixed bootstrap command, installed atomically at 0755.
#[test]
fn a_target_without_ouro_gets_the_exact_release_through_the_bootstrap_command() {
    let lab = Lab::new("boot", "studio");
    let target = data_dir("boot-t");
    let version = env!("CARGO_PKG_VERSION");

    // The "release" is the `ouro` this test was compiled beside, which is what makes the
    // installed file a working helper rather than a placeholder.
    let bytes = std::fs::read(OURO).expect("the built ouro");
    let triple = ouro::update::release::target_triple(
        std::env::consts::OS,
        &uname_machine(),
        &system_version(),
    )
    .expect("this machine is on the supported matrix");
    let asset = ouro::update::release::asset_name(version, &triple);
    let server = ReleaseServer::start(version, &asset, bytes.clone());

    let mut request = lab.request("op-000000002200", "vps", &target);
    // A relative install path, under the rig's contained HOME.
    request.install_path = Some(".local/bin/ouro".into());

    let operator = Operator::new();
    let outcome = ouro::fleet_setup::engine::Engine {
        origin: ouro::update::release::Origin::loopback(&server.base)
            .expect("a loopback release origin"),
        ..lab.engine(
            request,
            operator.clone(),
            gateway(&["studio", "vps"]),
            services(),
        )
    }
    .run()
    .expect("a machine that had no ouro joins");

    assert_eq!(outcome.state, OperationState::Completed);
    let installed = lab.rig.home.join(".local/bin/ouro");
    assert!(
        installed.is_file(),
        "the release landed at {}",
        installed.display()
    );
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&installed)
                .expect("the installed file")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }
    assert_eq!(
        ReleaseServer::sha256_of(&std::fs::read(&installed).expect("the installed bytes")),
        ReleaseServer::sha256_of(&bytes),
        "the installed bytes are the ones whose checksum was verified"
    );

    // The plan named the exact artifact and flagged the unofficial origin.
    let plan = outcome.plan.as_ref().expect("a reviewed plan");
    let release = plan.release.as_ref().expect("a planned install");
    assert_eq!(release.version, version);
    assert_eq!(release.asset, asset);
    assert!(!release.official_origin);

    // The journal recorded the selected release, by digest and by name.
    let record = Journal::read(&lab.issuer, "op-000000002200")
        .expect("a readable journal")
        .expect("a written journal");
    let selected = record.release.clone().expect("a recorded release");
    assert_eq!(selected.sha256, ReleaseServer::sha256_of(&bytes));
    assert!(record.completed("vps", "install_binary"));

    // And it refuses to replace what it just installed.
    let replaced = ouro::fleet_setup::bootstrap::install(
        &bootstrap_runner(&lab, &target),
        &asset,
        &bytes,
        &ReleaseServer::sha256_of(&bytes),
        ".local/bin/ouro",
    )
    .expect_err("an existing installation is never replaced");
    assert_eq!(reason_of(&replaced), Some("installation_exists"));
}

/// A checksum that does not match what arrived stops before anything is installed.
#[test]
fn a_checksum_mismatch_installs_nothing() {
    let lab = Lab::new("sum", "studio");
    let target = data_dir("sum-t");
    let runner = bootstrap_runner(&lab, &target);

    let refused = ouro::fleet_setup::bootstrap::install(
        &runner,
        "ouro-0.0.1-test",
        b"not the bytes the checksum describes",
        &"a".repeat(64),
        ".local/bin/ouro",
    )
    .expect_err("a checksum mismatch");
    assert_eq!(reason_of(&refused), Some("checksum_mismatch"));
    assert!(
        !lab.rig.home.join(".local/bin/ouro").exists(),
        "nothing was installed"
    );
    assert!(
        !lab.rig
            .home
            .join(".ouroboros/setup/ouro-0.0.1-test")
            .exists(),
        "the staged file was removed"
    );
}

/// An `ssh` runner pointed at the rig, for the bootstrap-only tests.
fn bootstrap_runner(lab: &Lab, _target: &Path) -> ouro::fleet_setup::ssh::Runner {
    let work = scratch("bootr");
    let store = work.join("known_hosts");
    let tools = Tools {
        keyscan: PathBuf::from("/usr/bin/ssh-keyscan"),
        keygen: PathBuf::from("/usr/bin/ssh-keygen"),
    };
    if let ouro::fleet_setup::trust::Trust::Unknown { keys } = ouro::fleet_setup::trust::examine(
        &tools,
        std::slice::from_ref(&store),
        "127.0.0.1",
        lab.rig.port,
        &work,
    )
    .expect("a scan")
    {
        ouro::fleet_setup::trust::accept(&store, &keys[0]).expect("recording trust");
    }
    ouro::fleet_setup::ssh::Runner {
        programs: Programs {
            ssh: PathBuf::from("/usr/bin/ssh"),
            ssh_add: PathBuf::from("/usr/bin/ssh-add"),
            keygen: PathBuf::from("/usr/bin/ssh-keygen"),
            askpass: PathBuf::from(OURO),
            agent_socket: None,
        },
        destination: ouro::fleet_setup::ssh::Destination {
            address: "127.0.0.1".into(),
            port: lab.rig.port,
            user: account(),
        },
        identity: ouro::fleet_setup::ssh::ResolvedIdentity::Key {
            path: lab.rig.client_key.clone(),
            label: "client_key".into(),
            fingerprint: None,
        },
        known_hosts: vec![store],
        user_known_hosts: None,
        connect_timeout: ouro::fleet_setup::ssh::CONNECT_TIMEOUT,
        command_timeout: ouro::fleet_setup::ssh::COMMAND_TIMEOUT,
        bridge: None,
    }
}

fn uname_machine() -> String {
    let output = std::process::Command::new("/usr/bin/uname")
        .arg("-m")
        .output()
        .expect("uname -m");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn system_version() -> String {
    if cfg!(target_os = "macos") {
        let output = std::process::Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .expect("sw_vers");
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        let output = std::process::Command::new("/usr/bin/getconf")
            .arg("GNU_LIBC_VERSION")
            .output()
            .expect("getconf");
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }
}

/// Whether any file under `root` contains `needle`.
fn contains(root: &Path, needle: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if contains(&path, needle) {
                return true;
            }
        } else if let Ok(bytes) = std::fs::read(&path) {
            if String::from_utf8_lossy(&bytes).contains(needle) {
                eprintln!("found the needle in {}", path.display());
                return true;
            }
        }
    }
    false
}

/// A debug rendering for the assertion messages above.
impl std::fmt::Debug for Lab {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Lab")
            .field("issuer", &self.issuer)
            .field("port", &self.rig.port)
            .finish()
    }
}

#[allow(dead_code)]
fn outcome_debug(outcome: &Outcome) -> String {
    format!("{:?}", outcome.state)
}

/// Isolate the harness's own release origin: the loopback server and the updater's
/// transport have to agree before the bootstrap path can be blamed for anything.
#[test]
fn the_loopback_release_origin_serves_a_verified_artifact() {
    let version = "0.9.9";
    let asset = "ouro-0.9.9-test";
    let bytes = vec![7_u8; 3 * 1024 * 1024];
    let server = ReleaseServer::start(version, asset, bytes.clone());
    let origin = ouro::update::release::Origin::loopback(&server.base).expect("a loopback origin");
    let cancelled = std::sync::atomic::AtomicBool::new(false);

    let manifest =
        ouro::update::release::checksums(&origin, version, &cancelled).expect("a manifest");
    let expected =
        ouro::update::release::checksum_for(&manifest, asset).expect("a recorded checksum");
    assert_eq!(expected, ReleaseServer::sha256_of(&bytes));

    let fetched =
        ouro::update::release::fetch_verified(&origin, version, asset, &expected, &cancelled)
            .expect("a verified artifact");
    assert_eq!(fetched.len(), bytes.len());
}

/// `ouro fleet add --dry-run --json`, through the real command line.
///
/// Two properties the engine tests above cannot show, because they call the engine
/// directly: that the operator's flags reach it, and that a dry run really does leave
/// nothing behind — no journal, no request, no trust record, and nothing on the target.
#[test]
fn a_dry_run_prints_the_plan_and_writes_nothing() {
    let lab = Lab::new("dry", "studio");
    let target = data_dir("dry-t");

    // Trust the rig the way an accepted challenge would, so the dry run has a host it can
    // inspect without a terminal to confirm one on.
    let store = ouro::fleet_setup::known_hosts_path(&lab.issuer);
    let tools = Tools {
        keyscan: PathBuf::from("/usr/bin/ssh-keyscan"),
        keygen: PathBuf::from("/usr/bin/ssh-keygen"),
    };
    let scan = scratch("dryscan");
    let ouro::fleet_setup::trust::Trust::Unknown { keys } = ouro::fleet_setup::trust::examine(
        &tools,
        std::slice::from_ref(&store),
        "127.0.0.1",
        lab.rig.port,
        &scan,
    )
    .expect("a scan") else {
        panic!("a fresh store knows nothing");
    };
    ouro::fleet_setup::trust::accept(&store, &keys[0]).expect("recording trust");
    let trusted_before = std::fs::read_to_string(&store).expect("a trust record");

    let output = std::process::Command::new(OURO)
        .args(["fleet", "add"])
        .arg(format!("{}@127.0.0.1", account()))
        .args(["--machine", "buildbox"])
        .args(["--port", &lab.rig.port.to_string()])
        .arg("--key")
        .arg(&lab.rig.client_key)
        .args(["--install-path", OURO])
        .arg("--remote-data-dir")
        .arg(&target)
        .args(["--operation", "op-000000003300"])
        .args(["--dry-run", "--json", "--no-service"])
        .env("OUROBOROS_DATA_DIR", &lab.issuer)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the built ouro binary");

    assert!(
        output.status.success(),
        "a dry run succeeds: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is one JSON document: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(document["state"], json!("awaiting_review"));
    assert_eq!(document["plan"]["target"]["machine"], json!("buildbox"));
    assert_eq!(document["plan"]["target"]["address"], json!("127.0.0.1"));
    assert_eq!(document["plan"]["target"]["port"], json!(lab.rig.port));
    assert_eq!(document["plan"]["service"], json!("manual"));
    assert_eq!(
        document["plan"]["target"]["install_path"],
        json!(OURO),
        "an absolute install path names the installation that is already there"
    );
    assert!(
        document["plan_digest"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64),
        "the plan a later approval binds to is identified: {document}"
    );
    assert!(
        document["plan"]["grants"][0]
            .as_str()
            .is_some_and(|grant| grant.contains("broad authority")),
        "the review states what accepting grants"
    );

    // Nothing was written. Not a journal, not a request, not a roster edit, and nothing
    // on the target.
    assert!(
        Journal::read(&lab.issuer, "op-000000003300")
            .expect("a readable deploy directory")
            .is_none(),
        "a dry run journals nothing"
    );
    assert!(!ouro::fleet_setup::request_path(&lab.issuer, "op-000000003300").exists());
    assert!(!ouro::fleet_setup::scratch_dir(&lab.issuer, "op-000000003300").exists());
    // And nothing else either. This test seeds the namespace itself (recording trust is
    // what creates it), so the shape of the assertion is "exactly what I put there" —
    // `a_dry_run_does_not_create_the_deployment_namespace` covers the machine that has
    // never deployed at all.
    let mut left: Vec<String> = std::fs::read_dir(ouro::fleet_setup::deploy_dir(&lab.issuer))
        .expect("the namespace this test seeded")
        .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec!["known_hosts".to_string()],
        "a dry run wrote {left:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&store).expect("a trust record"),
        trusted_before,
        "a dry run records no new trust"
    );
    assert!(fleet::load(&target).expect("a readable target").is_none());
    let issuer = fleet::load(&lab.issuer)
        .expect("a readable issuer")
        .expect("an issuer profile");
    assert_eq!(
        issuer.members.len(),
        1,
        "a dry run changes no roster: {:?}",
        issuer.members
    );
}

/// `setup` on a machine that already has a fleet is an inspection: it reports what is
/// there, names the repair, and changes nothing.
#[test]
fn setup_on_a_configured_machine_inspects_and_changes_nothing() {
    let data = data_dir("setup2");
    fleet::create(
        &data,
        Some("the lab"),
        "studio",
        "127.0.0.1",
        ephemeral().into(),
    )
    .expect("a created fleet");
    let before = fleet::load(&data)
        .expect("a readable profile")
        .expect("a profile");

    let mut request = OperationRequest::new("op-000000004400", OperationKind::Setup, "studio");
    request.address = Some("127.0.0.1".into());
    request.service = false;
    let operator = Operator::new();
    let outcome = Engine {
        data_dir: data.clone(),
        token_file: data.join("gateway.token"),
        request,
        conversation: operator.clone(),
        // A gateway that answers nothing: an inspection asks it nothing.
        gateway: Arc::new(ScriptedGateway::new(false, vec![])),
        services: services(),
        programs: Programs::default(),
        trust_tools: Tools::default(),
        user_known_hosts: None,
        origin: ouro::update::release::Origin::official(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        owner: Some("tester".to_string()),
    }
    .run()
    .expect("an inspection");

    assert_eq!(outcome.state, OperationState::Completed);
    assert!(
        outcome.summary.contains("already studio in fleet the lab"),
        "{}",
        outcome.summary
    );
    assert!(
        outcome.next.contains("--regenerate"),
        "the inspection names the repair: {}",
        outcome.next
    );
    assert!(
        operator.asked().is_empty(),
        "an inspection asks nothing: {:?}",
        operator.asked()
    );

    let after = fleet::load(&data)
        .expect("a readable profile")
        .expect("a profile");
    assert_eq!(after.fleet_id, before.fleet_id, "the identity is untouched");
    assert_eq!(after.roster_revision, before.roster_revision);
}

/// An acceptance is written to this operation's private store and nowhere else.
///
/// No shipped test set `user_known_hosts`, so a mutation that wrote the acceptance into
/// the operator's own `~/.ssh/known_hosts` — editing a file this command has no business
/// editing — passed every suite.
#[test]
fn an_accepted_host_key_never_reaches_the_operators_own_known_hosts() {
    let lab = Lab::new("ukh", "studio");
    let target = data_dir("ukh-t");

    // A stand-in for the operator's own file, with content of its own.
    let mine = scratch("ukh-user").join("known_hosts");
    std::fs::create_dir_all(mine.parent().expect("a parent")).expect("a directory");
    std::fs::write(&mine, "# the operator's own file\n").expect("a user store");
    let before = std::fs::read_to_string(&mine).expect("a user store");

    let outcome = Engine {
        user_known_hosts: Some(mine.clone()),
        ..lab.engine(
            lab.request("op-000000005500", "vps", &target),
            Operator::new(),
            gateway(&["studio", "vps"]),
            services(),
        )
    }
    .run()
    .expect("an admitted machine");
    assert_eq!(outcome.state, OperationState::Completed);

    assert_eq!(
        std::fs::read_to_string(&mine).expect("a user store"),
        before,
        "the operator's own known_hosts is honoured and never written"
    );
    let private = std::fs::read_to_string(ouro::fleet_setup::known_hosts_path(&lab.issuer))
        .expect("the private store");
    assert!(
        private.contains("ssh-"),
        "the acceptance went to this operation's own store: {private}"
    );
}

/// A changed host key blocks the *operation*, not only a bare `ssh`.
///
/// The engine's own `Trust::Changed` arm had no test: `check_access` covered OpenSSH's
/// refusal, and a mutation that made the engine proceed on a changed key survived.
#[test]
fn the_engine_refuses_a_changed_host_key_before_it_connects() {
    let mut lab = Lab::new("chg", "studio");
    let target = data_dir("chg-t");

    // Trust the rig as it is now.
    let store = ouro::fleet_setup::known_hosts_path(&lab.issuer);
    let scan = scratch("chgscan");
    let tools = Tools {
        keyscan: PathBuf::from("/usr/bin/ssh-keyscan"),
        keygen: PathBuf::from("/usr/bin/ssh-keygen"),
    };
    let ouro::fleet_setup::trust::Trust::Unknown { keys } = ouro::fleet_setup::trust::examine(
        &tools,
        std::slice::from_ref(&store),
        "127.0.0.1",
        lab.rig.port,
        &scan,
    )
    .expect("a scan") else {
        panic!("a fresh store knows nothing");
    };
    ouro::fleet_setup::trust::accept(&store, &keys[0]).expect("recording trust");

    // The machine is reinstalled, or somebody else answers on that address.
    lab.rig.rotate_host_key();

    let refused = lab
        .engine(
            lab.request("op-000000005600", "vps", &target),
            Operator::new(),
            gateway(&["studio"]),
            services(),
        )
        .run()
        .expect_err("a changed host key blocks");
    assert_eq!(reason_of(&refused), Some("host_key_changed"), "{refused:#}");
    // The engine's own refusal, not OpenSSH's: it names the keys the destination
    // actually presented, which is what an operator needs in order to decide whether the
    // machine was reinstalled or replaced. A refusal without them is `ssh` having caught
    // it one layer down, after the connection was attempted.
    assert!(
        format!("{refused}").contains("SHA256:"),
        "the refusal names the key that was presented, so it came from the trust check rather than from the connection: {refused:#}"
    );
    assert!(
        fleet::load(&target).expect("a readable target").is_none(),
        "nothing was delivered"
    );
}

/// A roster that moved is refused *as* a roster change, separately from a changed plan.
///
/// The shipped test accepted either reason, so a mutation that deleted the roster
/// comparison entirely was caught only by the digest check — and a mutation that deleted
/// the digest check was caught only by the roster comparison. Each is tested alone here.
#[test]
fn a_moved_roster_and_a_changed_plan_are_two_separate_refusals() {
    // The roster comparison, with the plan digest deliberately left matching.
    let lab = Lab::new("recon", "studio");
    let target = data_dir("recon-t");
    let stopper = Operator::stopping_after("prepare");
    let _ = lab
        .engine(
            lab.request("op-000000005700", "vps", &target),
            stopper,
            gateway(&["studio"]),
            services(),
        )
        .run()
        .expect_err("cancelled at the prepare boundary");

    // A roster edit that does not change any fact the plan carries: the plan's member
    // list is rendered from the profile, so this is the case where only the recorded
    // snapshot can notice.
    fleet::add_member(&lab.issuer, "laptop", "127.0.0.2", None).expect("an unrelated edit");

    let refused = lab
        .engine(
            lab.request("op-000000005700", "vps", &target),
            Operator::new(),
            gateway(&["studio"]),
            services(),
        )
        .run()
        .expect_err("the source roster moved");
    assert_eq!(
        reason_of(&refused),
        Some("roster_changed"),
        "a moved roster is reconciled under its own name: {refused:#}"
    );
}

/// A resumed operation is bound to the plan that was approved.
#[test]
fn a_resumed_operation_refuses_a_plan_that_is_not_the_one_approved() {
    let lab = Lab::new("bind", "studio");
    let target = data_dir("bind-t");

    let stopper = Operator::stopping_after("prepare");
    let _ = lab
        .engine(
            lab.request("op-000000005800", "vps", &target),
            stopper,
            gateway(&["studio"]),
            services(),
        )
        .run()
        .expect_err("cancelled at the prepare boundary");

    // The same operation, resumed with a different *plan*: a different startup choice is
    // a different plan, and the roster has not moved at all.
    let mut changed = lab.request("op-000000005800", "vps", &target);
    changed.service = true;
    let refused = lab
        .engine(changed, Operator::new(), gateway(&["studio"]), services())
        .run()
        .expect_err("the plan is not the one that was approved");
    assert_eq!(reason_of(&refused), Some("plan_changed"), "{refused:#}");
}

/// Credentials that left the issuer are never reissued under the same operation.
///
/// This is the recovery table's "credentials delivered; profile not installed" row. The
/// materials carry the fleet cookie and are deliberately never written down, so they
/// cannot be produced again — and the issuer refuses to mint a second certificate for
/// one operation. What the operation owes the operator is that sentence, not a replay
/// refusal from three layers down.
#[test]
fn an_operation_that_issued_credentials_never_issues_them_again() {
    use ouro::fleet_setup::journal::Journal;

    let lab = Lab::new("issue", "studio");
    let target = data_dir("issue-t");
    let operation = "op-000000005900";

    // Exactly the durable state a crash between `issue` and `install` leaves behind.
    {
        let mut journal =
            Journal::open(&lab.issuer, operation, OperationKind::Add).expect("a journal");
        journal
            .finish_step("vps", "prepare", "ok", None, None)
            .expect("a prepare step");
        journal
            .finish_step("vps", "issue", "ok", Some("issued for vps".into()), None)
            .expect("an issue step");
    }

    let refused = lab
        .engine(
            lab.request(operation, "vps", &target),
            Operator::new(),
            gateway(&["studio"]),
            services(),
        )
        .run()
        .expect_err("credentials that left the issuer cannot be reissued");
    assert_eq!(
        reason_of(&refused),
        Some("credentials_unrecoverable"),
        "{refused:#}"
    );
    assert!(
        format!("{refused}").contains("cannot be reissued"),
        "and says what to do instead: {refused}"
    );
    assert!(
        fleet::load(&target).expect("a readable target").is_none(),
        "and nothing was delivered on this attempt"
    );
}

/// The release origin is loopback-only and the checksum decides.
#[test]
fn the_release_origin_and_its_checksum_are_both_enforced() {
    use ouro::update::release::{checksum_for, checksums, fetch_verified, Origin};

    for hostile in [
        "http://example.invalid",
        "https://github.com/monocursive/ouroboros/releases/download",
        "http://127.0.0.1:8080/path",
        "http://localhost:8080",
    ] {
        assert!(
            Origin::loopback(hostile).is_err(),
            "{hostile} must not be accepted as a release origin"
        );
    }

    let version = "0.9.8";
    let asset = "ouro-0.9.8-test";
    let bytes = vec![3_u8; 64 * 1024];
    let server = ReleaseServer::start(version, asset, bytes.clone());
    let origin = Origin::loopback(&server.base).expect("a loopback origin");
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let manifest = checksums(&origin, version, &cancelled).expect("a manifest");
    let expected = checksum_for(&manifest, asset).expect("a digest");

    // The digest the manifest records is what decides; a different one is refused even
    // though the bytes arrived whole.
    let wrong = fetch_verified(&origin, version, asset, &"b".repeat(64), &cancelled)
        .expect_err("a digest that does not describe these bytes");
    assert!(
        format!("{wrong:#}").contains("hashes to"),
        "the refusal names both digests: {wrong:#}"
    );
    assert_eq!(
        fetch_verified(&origin, version, asset, &expected, &cancelled).expect("verified bytes"),
        bytes
    );
}

/// A dry run that *accepts* an unknown host key records nothing durable.
///
/// The two other dry-run tests cannot see this: one pre-seeds the trust store (so the
/// host is already known and nothing is ever accepted), and the other has no terminal to
/// accept with. This one accepts, and then looks.
#[test]
fn a_dry_run_that_accepts_a_host_key_keeps_it_for_that_run_only() {
    let lab = Lab::new("dtrust", "studio");
    let target = data_dir("dtrust-t");
    let store = ouro::fleet_setup::known_hosts_path(&lab.issuer);
    assert!(!store.exists(), "this machine trusts nothing yet");

    let mut request = lab.request("op-000000006100", "vps", &target);
    request.dry_run = true;
    let operator = Operator::new();
    let outcome = lab
        .engine(request, operator.clone(), gateway(&["studio"]), services())
        .run()
        .expect("a dry run against an unknown host");

    assert_eq!(outcome.state, OperationState::AwaitingReview);
    assert!(
        operator.asked().contains(&ChallengeKind::HostTrust),
        "the host key was an explicit question even in a dry run: {:?}",
        operator.asked()
    );
    assert!(
        !store.exists(),
        "and the acceptance was not recorded: {} exists",
        store.display()
    );
    assert!(
        !ouro::fleet_setup::deploy_dir(&lab.issuer).exists(),
        "nor was the namespace it would live in created"
    );
    // The plan still names the key that was accepted for this run, so the operator can
    // see what they agreed to.
    let plan = outcome.plan.as_ref().expect("a plan");
    assert!(
        plan.target
            .host_fingerprint
            .as_deref()
            .is_some_and(|fingerprint| fingerprint.starts_with("SHA256:")),
        "{:?}",
        plan.target.host_fingerprint
    );
}

#[test]
fn resume_after_own_roster_write_retries_startup() {
    for unrelated_edit in [false, true] {
        let lab = Lab::new("rvrost", "studio");
        let target = data_dir("rvrost-t");
        let mut request = lab.request("op-review-roster", "vps", &target);
        request.service = true;
        let refused = Arc::new(CountingServiceActions::new(true, vec![]));
        let first = lab
            .engine(
                request.clone(),
                Operator::new(),
                gateway(&["studio", "vps"]),
                refused,
            )
            .run()
            .unwrap_err();
        println!("first: {first:#}");
        assert!(Journal::read(&lab.issuer, &request.operation)
            .unwrap()
            .unwrap()
            .completed("studio", "roster"));
        if unrelated_edit {
            fleet::add_member(&lab.issuer, "unrelated", "127.0.0.2", None).unwrap();
        }
        let second = lab
            .engine(
                request,
                Operator::new(),
                gateway(&["studio", "vps"]),
                services(),
            )
            .run();
        if unrelated_edit {
            assert_eq!(reason_of(&second.unwrap_err()), Some("roster_changed"));
        } else {
            assert!(
                second.is_ok(),
                "resume after this operation's own roster write: {second:?}"
            );
        }
    }
}
#[test]
fn resume_verifies_and_reuses_the_installed_release() {
    for changed_binary in [false, true] {
        let lab = Lab::new("rvbin", "studio");
        let target = data_dir("rvbin-t");
        let version = env!("CARGO_PKG_VERSION");
        let bytes = std::fs::read(OURO).unwrap();
        let triple = ouro::update::release::target_triple(
            std::env::consts::OS,
            &uname_machine(),
            &system_version(),
        )
        .unwrap();
        let asset = ouro::update::release::asset_name(version, &triple);
        let server = ReleaseServer::start(version, &asset, bytes);
        let mut request = lab.request("op-review-binary", "vps", &target);
        request.install_path = Some(".local/bin/ouro".into());
        let first = Engine {
            origin: ouro::update::release::Origin::loopback(&server.base).unwrap(),
            ..lab.engine(
                request.clone(),
                Operator::stopping_after("prepare"),
                gateway(&["studio", "vps"]),
                services(),
            )
        }
        .run()
        .unwrap_err();
        println!("first: {first:#}");
        assert!(Journal::read(&lab.issuer, &request.operation)
            .unwrap()
            .unwrap()
            .completed("vps", "install_binary"));
        if changed_binary {
            std::fs::write(lab.rig.home.join(".local/bin/ouro"), b"different binary").unwrap();
        }
        let second = Engine {
            origin: ouro::update::release::Origin::loopback(&server.base).unwrap(),
            ..lab.engine(
                request,
                Operator::new(),
                gateway(&["studio", "vps"]),
                services(),
            )
        }
        .run();
        if changed_binary {
            assert_eq!(reason_of(&second.unwrap_err()), Some("plan_changed"));
        } else {
            assert!(
                second.is_ok(),
                "resume after this operation installed its binary: {second:?}"
            );
        }
    }
}
#[test]
fn setup_resumes_after_service_installation_failure() {
    let lab = Lab::new("rvsetup", "studio");
    let local = data_dir("rvlocal");
    let mut request = OperationRequest::new("op-review-setup", OperationKind::Setup, "local");
    request.address = Some("127.0.0.1".into());
    request.ports = Some(ephemeral());
    let stopped = Arc::new(ScriptedGateway::new(false, vec![]));
    let first = Engine {
        data_dir: local.clone(),
        token_file: local.join("gateway.token"),
        ..lab.engine(
            request.clone(),
            Operator::new(),
            stopped.clone(),
            Arc::new(CountingServiceActions::new(true, vec![])),
        )
    }
    .run()
    .unwrap_err();
    println!("first: {first:#}");
    assert!(fleet::load(&local).unwrap().is_some());
    let actions = services();
    let second = Engine {
        data_dir: local.clone(),
        token_file: local.join("gateway.token"),
        ..lab.engine(request, Operator::new(), stopped, actions.clone())
    }
    .run()
    .unwrap();
    assert!(
        actions.local_calls().contains(&ServiceAction::Install),
        "reported {:?} with no service retry: {:?}",
        second.state,
        actions.local_calls()
    );
}

struct HeldAdmission {
    inner: Arc<Operator>,
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}
impl Conversation for HeldAdmission {
    fn ask(&self, request: ChallengeRequest) -> anyhow::Result<Answer> {
        self.inner.ask(request)
    }
    fn notify(&self, event: Event) {
        self.inner.notify(event.clone());
        if let Event::Step { step, outcome, .. } = event {
            if step == "install" && outcome == "ok" {
                self.entered.wait();
                self.release.wait();
            }
        }
    }
}
#[test]
fn simultaneous_admissions_are_serialized_before_credentials_and_retry_updates_every_member() {
    let lab = Lab::new("rvconc", "studio");
    let first = data_dir("rvconc-a");
    let second = data_dir("rvconc-b");
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let engine_a = lab.engine(
        lab.request("op-review-concurrent-a", "alpha", &first),
        Arc::new(HeldAdmission {
            inner: Operator::new(),
            entered: entered.clone(),
            release: release.clone(),
        }),
        gateway(&["studio", "alpha", "beta"]),
        services(),
    );
    let request_b = lab.request("op-review-concurrent-b", "beta", &second);
    let a = std::thread::spawn(move || engine_a.run());
    entered.wait();
    let refused = lab
        .engine(
            request_b.clone(),
            Operator::new(),
            gateway(&["studio", "alpha", "beta"]),
            services(),
        )
        .run();
    release.wait();
    let outcome_a = a.join().unwrap().unwrap();
    assert_eq!(
        reason_of(&refused.unwrap_err()),
        Some("operation_in_progress")
    );
    assert!(fleet::load(&second).unwrap().is_none());
    let outcome_b = lab
        .engine(
            request_b,
            Operator::new(),
            gateway(&["studio", "alpha", "beta"]),
            services(),
        )
        .run()
        .unwrap();
    assert_eq!(outcome_a.state, OperationState::Completed);
    assert_eq!(outcome_b.state, OperationState::Completed);
    let issuer = fleet::load(&lab.issuer).unwrap().unwrap();
    for target in [&first, &second] {
        let member = fleet::load(target).unwrap().unwrap();
        assert_eq!(member.members, issuer.members);
    }
}

#[test]
fn admission_rejects_a_valid_csr_for_an_unreviewed_identity() {
    use std::os::unix::fs::PermissionsExt;
    let lab = Lab::new("rvid", "studio");
    let target = data_dir("rvid-t");
    let shim = lab.rig.dir.join("identity-shim");
    let body = r#"#!/usr/bin/env python3
import json, subprocess, sys
ouro = __OURO__
if sys.argv[1:] != ['fleet', 'helper']:
    raise SystemExit(subprocess.call([ouro] + sys.argv[1:]))
p = subprocess.Popen([ouro, 'fleet', 'helper'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
for line in sys.stdin:
    request = json.loads(line)
    if request.get('op') == 'prepare':
        request['machine'] = 'unreviewed'
    p.stdin.write(json.dumps(request) + '\n')
    p.stdin.flush()
    reply = p.stdout.readline()
    print(reply, end='', flush=True)
    if request.get('op') == 'bye': break
p.stdin.close()
p.wait()
"#.replace("__OURO__", &serde_json::to_string(OURO).unwrap());
    std::fs::write(&shim, body).unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut request = lab.request("op-review-identity", "vps", &target);
    request.install_path = Some(shim.display().to_string());
    let result = lab
        .engine(
            request,
            Operator::new(),
            gateway(&["studio", "vps"]),
            services(),
        )
        .run();
    println!("result: {:?}", result.as_ref().map(|r| r.state));
    let installed = fleet::load(&target).unwrap();
    println!(
        "installed: {:?}",
        installed.as_ref().map(|p| (&p.machine, &p.host))
    );
    assert!(
        result.is_err(),
        "must reject a valid CSR for an identity the operator did not review"
    );
    assert!(installed.is_none());
}

#[test]
fn later_admission_reuses_existing_member_access_without_private_overrides() {
    let lab = Lab::new("rvaccess", "studio");
    let existing = data_dir("rvaccess-a");
    let target = data_dir("rvaccess-b");
    lab.engine(
        lab.request("op-review-access-a", "alpha", &existing),
        Operator::new(),
        gateway(&["studio", "alpha"]),
        services(),
    )
    .run()
    .unwrap();
    // No public CLI/RPC field supplies OperationRequest.members. Keep its default,
    // and exercise an existing member deployed with the supported data_dir field.
    let second_host = Sshd::start("rvaccess-other");
    let mut request = lab.request("op-review-access-b", "beta", &target);
    request.ssh_port = Some(second_host.port);
    request.identity = IdentityChoice::Key {
        path: second_host.client_key.clone(),
    };
    assert!(request.members.is_empty());
    let outcome = lab
        .engine(
            request,
            Operator::new(),
            gateway(&["studio", "alpha", "beta"]),
            services(),
        )
        .run();
    assert!(
        outcome.is_ok(),
        "existing member access from the completed admission must be reused: {outcome:?}"
    );
}

#[test]
fn the_explicit_model_check_submits_and_observes_one_turn_in_the_reviewed_workspace() {
    for terminal in ["completed", "failed"] {
        let lab = Lab::new("model-check", "studio");
        let target = data_dir("model-check-t");
        let operation = "op-model-check";
        let mut request = lab.request(operation, "vps", &target);
        request.run_test_task = true;
        request.test_workspace = Some("/srv/project".into());
        let id = format!("fleet-check-{operation}");
        let turn = format!("{id}-turn");
        let calls = Arc::new(ScriptedGateway::new(
            true,
            vec![
                (
                    "interactive.start",
                    json!({"id": id, "ready": true, "node": "ouro-vps@127.0.0.1"}),
                ),
                ("interactive.send_message", json!({"turn_id": turn})),
                (
                    "interactive.info",
                    json!({"turns": {turn.clone(): {"status": terminal}}}),
                ),
            ],
        ));
        let outcome = lab
            .engine(request, Operator::new(), calls.clone(), services())
            .run();
        if terminal == "completed" {
            let outcome = outcome.unwrap();
            assert_eq!(outcome.state, OperationState::Completed);
            assert_eq!(
                outcome.plan.unwrap().test_workspace.as_deref(),
                Some("/srv/project")
            );
        } else {
            assert_eq!(reason_of(&outcome.unwrap_err()), Some("test_task_failed"));
        }
        let sent = calls.calls();
        let start = &sent
            .iter()
            .find(|(method, _)| method == "interactive.start")
            .unwrap()
            .1;
        assert_eq!(start["workspace"], "/srv/project");
        assert_eq!(start["machine"], "vps");
        assert_eq!(start["max_turns"], 1);
        assert_eq!(calls.called("interactive.send_message"), 1);
        assert_eq!(calls.called("interactive.info"), 1);
        for (method, params) in &sent {
            if matches!(
                method.as_str(),
                "interactive.send_message" | "interactive.info" | "interactive.interrupt"
            ) {
                assert_eq!(params["node"], "ouro-vps@127.0.0.1");
                assert!(params.get("machine").is_none());
            }
        }
        let record = Journal::read(&lab.issuer, operation).unwrap().unwrap();
        assert_eq!(
            record.completed("vps", "test_task"),
            terminal == "completed"
        );
    }
}

#[test]
fn a_model_check_without_a_destination_workspace_refuses_before_mutation() {
    let lab = Lab::new("model-no-path", "studio");
    let target = data_dir("model-no-path-t");
    let mut request = lab.request("op-model-no-path", "vps", &target);
    request.run_test_task = true;
    let error = lab
        .engine(request, Operator::new(), gateway(&[]), services())
        .run()
        .unwrap_err();
    assert_eq!(reason_of(&error), Some("invalid_request"));
    assert!(fleet::load(&target).unwrap().is_none());
}

#[test]
fn a_running_target_refuses_before_issuance_and_can_retry_after_stopping() {
    use std::os::unix::fs::PermissionsExt;
    let lab = Lab::new("rvrun", "studio");
    let target = data_dir("rvrun-t");
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("180")
        .spawn()
        .unwrap();
    let pid = child.id() as i32;
    let birth = ouro::runtime::process_birth(pid).unwrap().unwrap();
    let owner = target.join("runtime.owner");
    std::fs::write(
        &owner,
        json!({"pid":pid,"birth":birth,"owner":"review-fixture"}).to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&owner, std::fs::Permissions::from_mode(0o600)).unwrap();
    let request = lab.request("op-running-target", "vps", &target);
    let result = lab
        .engine(
            request.clone(),
            Operator::new(),
            gateway(&["studio"]),
            services(),
        )
        .run();
    child.kill().unwrap();
    child.wait().unwrap();
    let first = result.unwrap_err();
    let journal = Journal::read(&lab.issuer, &request.operation)
        .unwrap()
        .unwrap();
    println!(
        "FIRST={first:#}; ISSUE_RECORDED={}",
        journal.completed("vps", "issue")
    );
    assert_eq!(reason_of(&first), Some("runtime_running"));
    assert!(!journal.completed("vps", "issue"));
    assert!(fleet::read_receipt(&lab.issuer, &request.operation)
        .unwrap()
        .is_none());
    let second = lab
        .engine(request, Operator::new(), gateway(&["studio"]), services())
        .run()
        .unwrap();
    assert_eq!(second.state, OperationState::Completed);
}
#[test]
fn removal_resumes_after_the_local_roster_entry_has_gone() {
    let lab = Lab::new("rvleave", "studio");
    let second = data_dir("rvl-2");
    let third = data_dir("rvl-3");
    lab.engine(
        lab.request("op-admit-vps", "vps", &second),
        Operator::new(),
        gateway(&["studio", "vps"]),
        services(),
    )
    .run()
    .unwrap();
    lab.engine(
        lab.request("op-admit-third", "buildbox", &third),
        Operator::new(),
        gateway(&["studio", "vps", "buildbox"]),
        services(),
    )
    .run()
    .unwrap();
    let mut request = lab.request("op-leave-vps", "vps", &second);
    request.kind = OperationKind::Leave;
    let first = lab
        .engine(
            request.clone(),
            Operator::stopping_after("roster"),
            gateway(&["studio", "buildbox"]),
            services(),
        )
        .run()
        .unwrap_err();
    println!("INTERRUPTED={first:#}");
    let local = fleet::load(&lab.issuer).unwrap().unwrap();
    assert!(!local.members.iter().any(|m| m.machine == "vps"));
    assert!(fleet::load(&third)
        .unwrap()
        .unwrap()
        .members
        .iter()
        .any(|m| m.machine == "vps"));
    let outcome = lab
        .engine(
            request,
            Operator::new(),
            gateway(&["studio", "buildbox"]),
            services(),
        )
        .run()
        .unwrap();
    assert_eq!(outcome.state, OperationState::Completed);
    assert!(!fleet::load(&third)
        .unwrap()
        .unwrap()
        .members
        .iter()
        .any(|m| m.machine == "vps"));
}
#[test]
fn a_cooperatively_removed_member_can_be_admitted_again() {
    let lab = Lab::new("rvreadd", "studio");
    let target = data_dir("rvrea-t");
    lab.engine(
        lab.request("op-first-admit", "vps", &target),
        Operator::new(),
        gateway(&["studio", "vps"]),
        services(),
    )
    .run()
    .unwrap();
    let mut request = lab.request("op-first-leave", "vps", &target);
    request.kind = OperationKind::Leave;
    lab.engine(request, Operator::new(), gateway(&["studio"]), services())
        .run()
        .unwrap();
    let outcome = lab
        .engine(
            lab.request("op-second-admit", "vps", &target),
            Operator::new(),
            gateway(&["studio"]),
            services(),
        )
        .run()
        .unwrap();
    assert_eq!(outcome.state, OperationState::Completed);
    let old = fleet::read_receipt(&lab.issuer, "op-first-admit")
        .unwrap()
        .unwrap();
    assert!(old.has_step("issue") && old.has_step("retire"));
    let current = fleet::read_receipt(&lab.issuer, "op-second-admit")
        .unwrap()
        .unwrap();
    assert!(current.has_step("issue") && !current.has_step("retire"));
}

struct EditDuringReview {
    issuer: PathBuf,
    inner: Arc<Operator>,
}
impl Conversation for EditDuringReview {
    fn ask(&self, request: ChallengeRequest) -> anyhow::Result<Answer> {
        if request.kind == ChallengeKind::Review {
            fleet::add_member(&self.issuer, "concurrent", "127.0.0.2", None)?;
        }
        self.inner.ask(request)
    }
    fn notify(&self, event: Event) {
        self.inner.notify(event);
    }
    fn cancelled(&self) -> bool {
        false
    }
}
#[test]
fn roster_changes_during_approval_refuse_before_credential_issuance() {
    let lab = Lab::new("rvstale", "studio");
    let target = data_dir("rvst-t");
    let operator = Arc::new(EditDuringReview {
        issuer: lab.issuer.clone(),
        inner: Operator::new(),
    });
    let result = lab
        .engine(
            lab.request("op-stale-review", "vps", &target),
            operator,
            gateway(&["studio"]),
            services(),
        )
        .run()
        .unwrap_err();
    println!("STALE_REVIEW={result:#}");
    assert_eq!(reason_of(&result), Some("roster_conflict"));
    assert!(fleet::load(&target).unwrap().is_none());
    assert!(fleet::read_receipt(&lab.issuer, "op-stale-review")
        .unwrap()
        .is_none());
}
