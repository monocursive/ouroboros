//! What an operator types, and how it becomes an operation.
//!
//! This layer does three things the engine deliberately does not: it resolves a device
//! name to the overlay IPv4 the engine will connect to (which needs the async network
//! adapter), it builds the terminal conversation, and it renders the result — human
//! lines on stderr and a stable document on stdout under `--json`, with a nonzero exit
//! whenever setup is incomplete.
//!
//! The engine itself is blocking, so it runs on a blocking thread. That is not an
//! implementation detail to tidy away: it is what lets the same code run inside the
//! detached worker, which has no async runtime at all.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::fleet_network;
use crate::runtime::Paths;
use crate::update::release;

use super::engine::{Engine, Outcome};
use super::gateway::LocalGateway;
use super::journal::Journal;
use super::service::LocalServiceActions;
use super::terminal::TerminalConversation;
use super::{refuse, IdentityChoice, OperationKind, OperationRequest, OperationState, PortPolicy};

/// The flags every setup surface shares.
#[derive(Clone, Debug, Default)]
pub struct CommonArgs {
    pub dry_run: bool,
    pub yes: bool,
    pub json: bool,
    pub no_service: bool,
    /// Resume (or name) a specific operation instead of minting one.
    pub operation: Option<String>,
}

/// `ouro fleet setup`.
#[derive(Clone, Debug, Default)]
pub struct SetupArgs {
    pub machine: Option<String>,
    pub address: Option<String>,
    pub common: CommonArgs,
}

/// `ouro fleet add`.
#[derive(Clone, Debug, Default)]
pub struct AddArgs {
    /// `[user@]host`, where host is an overlay IPv4 or a visible device's name.
    pub destination: Option<String>,
    pub machine: Option<String>,
    pub port: Option<u16>,
    pub key: Option<PathBuf>,
    pub agent: Option<String>,
    pub ask_password: bool,
    pub install_path: Option<String>,
    pub remote_data_dir: Option<String>,
    pub run_test_task: bool,
    pub test_workspace: Option<String>,
    pub common: CommonArgs,
}

/// `ouro fleet leave --machine NAME`.
#[derive(Clone, Debug, Default)]
pub struct LeaveArgs {
    pub machine: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub key: Option<PathBuf>,
    pub agent: Option<String>,
    pub ask_password: bool,
    /// An explicit override for where `ouro` lives on that member.
    pub remote_executable: Option<String>,
    pub common: CommonArgs,
}

/// Everything the engine needs that is not in the request.
fn engine_for(
    paths: &Paths,
    request: OperationRequest,
    conversation: Arc<TerminalConversation>,
) -> Result<Engine> {
    let executable = std::env::current_exe().context("resolving this executable")?;
    Ok(Engine {
        data_dir: paths.data_dir.clone(),
        token_file: paths.token_file(),
        gateway: Arc::new(LocalGateway::new(&paths.data_dir, &paths.token_file())),
        services: Arc::new(LocalServiceActions::new(&paths.data_dir)),
        programs: super::ssh::Programs {
            askpass: executable,
            ..super::ssh::Programs::default()
        },
        trust_tools: super::trust::Tools::default(),
        user_known_hosts: default_known_hosts(),
        origin: release::Origin::resolve()?,
        version: env!("CARGO_PKG_VERSION").to_string(),
        // A CLI operation belongs to whoever is typing, and that is this account. The
        // worker's owner is instead the first client that attaches to it.
        owner: Some(local_account()),
        conversation,
        request,
    })
}

/// The account this process runs as, which is the subject a CLI operation belongs to.
fn local_account() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| format!("uid {}", unsafe { libc::geteuid() }))
}

/// The operator's own `known_hosts`, honoured but never written.
fn default_known_hosts() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let path = PathBuf::from(home).join(".ssh").join("known_hosts");
    path.is_file().then_some(path)
}

fn identity_choice(
    key: &Option<PathBuf>,
    agent: &Option<String>,
    ask_password: bool,
) -> Result<IdentityChoice> {
    match (key, agent, ask_password) {
        (Some(path), None, false) => Ok(IdentityChoice::Key { path: path.clone() }),
        (None, Some(fingerprint), false) => Ok(IdentityChoice::Agent {
            fingerprint: fingerprint.clone(),
        }),
        (None, None, true) => Ok(IdentityChoice::Password),
        (None, None, false) => Ok(IdentityChoice::Default),
        _ => refuse(
            "invalid_request",
            "choose one authentication method: --key, --agent or --ask-password",
        ),
    }
}

/// Split `[user@]host`.
pub fn split_destination(destination: &str) -> (Option<String>, String) {
    match destination.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() && !host.is_empty() => {
            (Some(user.to_string()), host.to_string())
        }
        _ => (None, destination.to_string()),
    }
}

/// Turn a device name or an address into the overlay IPv4 the engine will connect to.
///
/// An address is used as typed. A name is resolved through the network client's visible
/// peer set — and only that: a peer's self-reported hostname is display information, so
/// the resolution result is an address and the engine never carries the name as an
/// identity.
pub async fn resolve_address(data_dir: &std::path::Path, host: &str) -> Result<String> {
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return Ok(address.to_string());
    }
    let summary = crate::fleet::summary(data_dir);
    let inventory = fleet_network::inventory().await;
    match fleet_network::resolve_peer(&summary, &inventory, host) {
        fleet_network::PeerResolution::One(address) => Ok(address.to_string()),
        // Two visible devices calling themselves the same thing is not something to
        // guess about: the operator says which address they meant.
        fleet_network::PeerResolution::Ambiguous(addresses) => refuse(
            "peer_ambiguous",
            format!(
                "`{host}` names more than one visible device ({}). Give the private IPv4 address of the one you mean",
                addresses
                    .iter()
                    .map(|address| address.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        fleet_network::PeerResolution::None => refuse(
            "unresolved_address",
            format!(
                "`{host}` is not an address and this machine's network client does not report a device by that name. {} Run `ouro fleet devices` to see what it can see, or give the device's private IPv4 address",
                inventory.headline()
            ),
        ),
    }
}

/// This machine's own overlay IPv4, for `setup`.
pub async fn resolve_self_address() -> Result<String> {
    let inventory = fleet_network::inventory().await;
    match inventory
        .self_device
        .as_ref()
        .and_then(|device| device.ipv4)
    {
        Some(address) => Ok(address.to_string()),
        None => refuse(
            "unresolved_address",
            format!(
                "this machine's private network address could not be read. {} Give it explicitly with --address once the device is signed in",
                inventory.headline()
            ),
        ),
    }
}

/// `ouro fleet setup`.
pub async fn setup(paths: &Paths, args: SetupArgs) -> Result<()> {
    let address = match &args.address {
        Some(address) => address.clone(),
        None => resolve_self_address().await?,
    };
    let machine = match &args.machine {
        Some(machine) => machine.clone(),
        None => crate::fleet::resolve_identity(None, Some(&address))?.machine,
    };
    let mut request =
        OperationRequest::new(operation_id(&args.common)?, OperationKind::Setup, machine);
    request.address = Some(address);
    request.service = !args.common.no_service;
    request.dry_run = args.common.dry_run;
    request.assume_yes = args.common.yes;
    request.ports = test_ports();
    drive(paths, request, &args.common).await
}

/// `ouro fleet add`.
pub async fn add(paths: &Paths, args: AddArgs) -> Result<()> {
    let Some(destination) = args.destination.clone() else {
        return refuse(
            "invalid_request",
            "name the machine to add as `user@address`. The Tailscale owner is never used as the target account, so the account cannot be inferred",
        );
    };
    let (user, host) = split_destination(&destination);
    let address = resolve_address(&paths.data_dir, &host).await?;
    let machine = match &args.machine {
        Some(machine) => machine.clone(),
        None => derived_machine(&host)?,
    };
    let mut request =
        OperationRequest::new(operation_id(&args.common)?, OperationKind::Add, machine);
    let (peer_id, stable_id) = peer_identity_for(&address).await;
    request.address = Some(address);
    request.ssh_user = user;
    request.ssh_port = args.port;
    request.identity = identity_choice(&args.key, &args.agent, args.ask_password)?;
    request.install_path = args.install_path.clone();
    request.remote_data_dir = args.remote_data_dir.clone();
    request.service = !args.common.no_service;
    request.dry_run = args.common.dry_run;
    request.assume_yes = args.common.yes;
    request.run_test_task = args.run_test_task;
    request.test_workspace = args.test_workspace.clone();
    request.ports = test_ports();
    request.peer_id = peer_id;
    request.stable_id = stable_id;
    drive(paths, request, &args.common).await
}

/// A typed destination is display information until `--machine` names it; this is how
/// `me@Build-Linux` and `me@build-linux.tailnet.ts.net` become the same short name.
fn derived_machine(host: &str) -> Result<String> {
    if host.parse::<Ipv4Addr>().is_ok() {
        return refuse(
            "invalid_request",
            "give the new machine a short name with --machine; an address is not a name",
        );
    }
    crate::fleet::machine_from_host(host)
}

/// Tailscale node key and stable id for this overlay address, when discovery names one.
async fn peer_identity_for(address: &str) -> (Option<String>, Option<String>) {
    let inventory = fleet_network::inventory().await;
    for device in inventory.self_device.iter().chain(inventory.peers.iter()) {
        if device.ipv4.map(|ip| ip.to_string()).as_deref() == Some(address) {
            return (device.node_key.clone(), device.stable_id.clone());
        }
    }
    (None, None)
}

/// `ouro fleet leave --machine NAME`.
pub async fn leave_machine(paths: &Paths, args: LeaveArgs) -> Result<()> {
    let mut request = OperationRequest::new(
        operation_id(&args.common)?,
        OperationKind::Leave,
        args.machine.clone(),
    );
    request.ssh_user = args.user.clone();
    request.ssh_port = args.port;
    request.identity = identity_choice(&args.key, &args.agent, args.ask_password)?;
    request.install_path = args.remote_executable.clone();
    request.dry_run = args.common.dry_run;
    request.assume_yes = args.common.yes;
    // The member's address comes from this machine's roster, which the engine reads.
    if let Some(profile) = crate::fleet::load(&paths.data_dir)? {
        if let Some(member) = profile
            .members
            .iter()
            .find(|member| crate::fleet::same_name(&member.machine, &args.machine))
        {
            request.address = Some(member.host.clone());
            let (peer_id, stable_id) = peer_identity_for(&member.host).await;
            request.peer_id = peer_id;
            request.stable_id = stable_id;
        }
    }
    drive(paths, request, &args.common).await
}

/// Ephemeral ports for a test fleet, when a harness asked for them. Production derives
/// its ports from the fleet id; this is how an integration test keeps two fleets on one
/// host out of the production port spaces.
fn test_ports() -> Option<PortPolicy> {
    let read = |name: &str| -> Option<u16> { std::env::var(name).ok()?.parse().ok() };
    let gateway = read("OUROBOROS_TEST_GATEWAY_PORT");
    let dist = read("OUROBOROS_TEST_DIST_PORT");
    let epmd = read("OUROBOROS_TEST_EPMD_PORT");
    (gateway.is_some() || dist.is_some() || epmd.is_some()).then_some(PortPolicy {
        gateway,
        dist,
        epmd,
    })
}

fn operation_id(common: &CommonArgs) -> Result<String> {
    match &common.operation {
        Some(operation) => {
            super::validate_operation_id(operation)?;
            Ok(operation.clone())
        }
        None => super::new_operation_id(),
    }
}

/// Run the engine off the async runtime, then report.
async fn drive(paths: &Paths, request: OperationRequest, common: &CommonArgs) -> Result<()> {
    paths.ensure_private_data_dir()?;
    // The engine writes the request so a crash can resume it. Completed and cancelled
    // operations fold the identity choice into the journal and delete the file; failed
    // and interrupted ones keep it for resume.
    let conversation = Arc::new(TerminalConversation::new(common.yes, common.json));
    let engine = engine_for(paths, request, conversation)?;
    let json = common.json;
    let data_dir = paths.data_dir.clone();
    let result = tokio::task::spawn_blocking(move || engine.run())
        .await
        .context("the deployment engine stopped unexpectedly")?;
    let _ = Journal::prune_terminal(&data_dir, 50, Duration::from_secs(30 * 86400));

    match result {
        Ok(outcome) => {
            report(&outcome, json)?;
            if outcome.state == OperationState::Completed
                || outcome.state == OperationState::AwaitingReview
            {
                Ok(())
            } else {
                // The proposal: incomplete setup exits non-zero even when some steps
                // succeeded.
                refuse(
                    "incomplete",
                    format!("setup is incomplete: {}", outcome.summary),
                )
            }
        }
        Err(error) => {
            if json {
                let reason = super::reason_of(&error).unwrap_or("failed");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "state": "failed",
                        "reason": reason,
                        "detail": format!("{error:#}"),
                    }))?
                );
            }
            Err(error)
        }
    }
}

fn report(outcome: &Outcome, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&outcome.to_value())?);
        return Ok(());
    }
    if let Some(plan) = &outcome.plan {
        if outcome.state == OperationState::AwaitingReview {
            print!("{}", plan.render());
        }
    }
    println!("\n{}", outcome.summary);
    for note in &outcome.unknown {
        println!("  unknown: {note}");
    }
    for note in &outcome.residue {
        println!("  left behind: {note}");
    }
    println!("\nNext: {}", outcome.next);
    Ok(())
}

// ---------------------------------------------------------------- hidden surfaces

/// `ouro fleet worker start|run`.
pub fn worker_start(paths: &Paths, operation: &str) -> Result<()> {
    let started = super::worker::start(&paths.data_dir, operation)?;
    println!("{}", started.to_value());
    Ok(())
}

pub fn worker_run(paths: &Paths, operation: &str) -> Result<()> {
    let executable = std::env::current_exe().context("resolving this executable")?;
    super::worker::run(
        super::worker::WorkerConfig {
            data_dir: paths.data_dir.clone(),
            token_file: paths.token_file(),
            gateway: Arc::new(LocalGateway::new(&paths.data_dir, &paths.token_file())),
            services: Arc::new(LocalServiceActions::new(&paths.data_dir)),
            programs: super::ssh::Programs {
                askpass: executable,
                ..super::ssh::Programs::default()
            },
            trust_tools: super::trust::Tools::default(),
            user_known_hosts: default_known_hosts(),
            origin: release::Origin::resolve()?,
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        operation,
    )
}

/// `ouro fleet askpass`: what OpenSSH executes when it needs a secret.
pub fn askpass(prompt: Option<String>) -> Result<()> {
    super::askpass::client_main(prompt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `user@host` splits the way ssh does, and a bare host has no account.
    #[test]
    fn a_destination_splits_into_an_account_and_a_host() {
        assert_eq!(
            split_destination("me@100.64.0.2"),
            (Some("me".into()), "100.64.0.2".into())
        );
        assert_eq!(split_destination("buildbox"), (None, "buildbox".into()),);
        assert_eq!(
            split_destination("me@buildbox"),
            (Some("me".into()), "buildbox".into())
        );
        // An address with an `@` in it is not a thing, and the last `@` wins so an
        // account containing one still resolves the host.
        assert_eq!(
            split_destination("me@example@100.64.0.2"),
            (Some("me@example".into()), "100.64.0.2".into())
        );
    }

    /// One authentication method at a time, and none of them takes a secret.
    #[test]
    fn exactly_one_authentication_method_may_be_selected() {
        assert!(matches!(
            identity_choice(&None, &None, false).expect("the default"),
            IdentityChoice::Default
        ));
        assert!(matches!(
            identity_choice(&Some(PathBuf::from("/k")), &None, false).expect("a key"),
            IdentityChoice::Key { .. }
        ));
        assert!(matches!(
            identity_choice(&None, &Some("SHA256:a".into()), false).expect("an agent identity"),
            IdentityChoice::Agent { .. }
        ));
        assert!(matches!(
            identity_choice(&None, &None, true).expect("a password"),
            IdentityChoice::Password
        ));
        assert!(identity_choice(&Some(PathBuf::from("/k")), &None, true).is_err());
        assert!(identity_choice(&Some(PathBuf::from("/k")), &Some("x".into()), false).is_err());
    }

    /// An address resolves to itself without touching the network client at all.
    #[tokio::test]
    async fn an_address_resolves_to_itself() {
        let data = std::env::temp_dir();
        assert_eq!(
            resolve_address(&data, "100.64.0.2")
                .await
                .expect("an address"),
            "100.64.0.2"
        );
        assert_eq!(
            resolve_address(&data, "127.0.0.1")
                .await
                .expect("an address"),
            "127.0.0.1"
        );
    }

    /// A named operation is validated; an unnamed one is minted.
    #[test]
    fn an_operation_id_is_validated_or_minted() {
        let named = CommonArgs {
            operation: Some("op-0123456789ab".into()),
            ..CommonArgs::default()
        };
        assert_eq!(operation_id(&named).expect("a valid id"), "op-0123456789ab");

        let hostile = CommonArgs {
            operation: Some("../etc".into()),
            ..CommonArgs::default()
        };
        assert!(operation_id(&hostile).is_err());

        let minted = operation_id(&CommonArgs::default()).expect("a minted id");
        assert!(super::super::validate_operation_id(&minted).is_ok());
    }

    #[test]
    fn a_typed_destination_becomes_a_valid_machine_name() {
        assert_eq!(
            derived_machine("Build-Linux").expect("a name"),
            "build-linux"
        );
        assert_eq!(
            derived_machine("build-linux.tailnet.ts.net").expect("a MagicDNS name"),
            "build-linux"
        );
        assert!(
            derived_machine("100.64.0.2").is_err(),
            "an address is not a name"
        );
    }
}
