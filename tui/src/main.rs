//! `ouro`: start or find an Ouroboros runtime and speak its operator protocol.
//!
//! This file owns process lifecycle and nothing else. Attaching means connecting,
//! completing the handshake, and handing the connection to [`ouro::ui`], which draws it
//! until the operator picks something from the quit dialog; what happens to the runtime
//! afterwards is that choice, executed here.
//!
//! The non-UI commands are unchanged and deliberately so: `ouro daemon` still starts and
//! exits, `ouro stop` still prefers `runtime.shutdown` and falls back to a signal for a
//! pid it can prove it owns, and `ouro attach --print` renders the same one-shot page for
//! a pipe or a terminal that is not a tty.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde_json::json;

use ouro::cli::{Cli, Command};
use ouro::model::{ApprovalMode, Plane, StartError, StartRequest, StartedRef};
use ouro::proto::Hello;
use ouro::runtime::{Daemon, Launcher, Output, Paths, Publication};
use ouro::transport::{
    Client, ClientError, Connected, NoReconnectHook, ReconnectHook, Secret, TransportConfig,
};
use ouro::ui::{self, App, Mode, Quit};
use ouro::{proto, runtime, status, transport};

/// How long a runtime is given to stop before it is killed. `System.stop/0` and a
/// SIGTERM both run the same orderly shutdown, and a runtime with durable journals is
/// owed the chance to finish it.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(20);

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ouro: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let paths = Paths::discover(cli.dev)?;

    match cli.command {
        None => attach_local(&paths, cli.dev).await,
        Some(Command::New {
            provider,
            workspace,
            approval_mode,
            message,
            print,
        }) => {
            new_session(
                &paths,
                cli.dev,
                provider,
                workspace,
                approval_mode,
                message,
                print,
            )
            .await
        }
        Some(Command::Daemon) => daemon(&paths, cli.dev).await,
        Some(Command::Attach {
            addr,
            token_file,
            print,
        }) => attach_remote(&paths, addr, token_file, print).await,
        Some(Command::Stop) => stop(&paths).await,
        Some(Command::Version) => {
            print!("{}", version());
            Ok(())
        }
    }
}

fn version() -> String {
    let mut text = format!("ouro {}\n", env!("CARGO_PKG_VERSION"));
    text.push_str(&format!("  protocol  {}\n", proto::PROTOCOL));
    text.push_str(&format!("  release   {}\n", embedded_release()));
    text
}

#[cfg(feature = "embed")]
fn embedded_release() -> String {
    match runtime::embed::embedded() {
        Some(release) => format!(
            "{} (sha256 {})",
            release.version,
            &release.sha256[..release.sha256.len().min(16)]
        ),
        None => "none embedded; --dev or attach".into(),
    }
}

#[cfg(not(feature = "embed"))]
fn embedded_release() -> String {
    "none embedded; --dev or attach".into()
}

/// The default command: adopt a running runtime or start one, then draw it.
async fn attach_local(paths: &Paths, dev: bool) -> Result<()> {
    let (publication, token, daemon) = local_runtime(paths, dev).await?;

    draw(
        local_address(publication.port),
        token,
        supervision(&daemon),
        daemon,
        None,
    )
    .await
}

/// `ouro new`: state every choice, start the session, and attach to it.
///
/// The validation is [`StartRequest`]'s — the same code the `n` dialog runs — so a
/// parameter this client would refuse in one surface is refused in both, and neither can
/// invent an option the gateway's allowlist does not contain.
#[allow(clippy::too_many_arguments)]
async fn new_session(
    paths: &Paths,
    dev: bool,
    provider: String,
    workspace: Option<PathBuf>,
    approval_mode: Option<String>,
    message: Option<String>,
    print: bool,
) -> Result<()> {
    let request = StartRequest {
        plane: Plane::Interactive,
        provider,
        workspace: workspace.map(absolute).transpose()?.unwrap_or_default(),
        approval_mode: match &approval_mode {
            None => None,
            Some(name) => Some(ApprovalMode::parse(name).ok_or_else(|| {
                anyhow!(
                    "{}",
                    StartError::UnknownApprovalMode(name.clone()).message()
                )
            })?),
        },
        objective: String::new(),
    };

    // Refused before a runtime is started: a missing provider is not worth a daemon.
    let params = request
        .params()
        .map_err(|refusal| anyhow!("{}", refusal.message()))?;

    let (publication, token, mut daemon) = local_runtime(paths, dev).await?;
    let address = local_address(publication.port);
    let mode = supervision(&daemon);

    let (hook, channel) = ui::hook();
    let attached = attach_with(address, token, true, hook).await?;

    if !attached.hello.serves(&request.method()) || !attached.hello.operates() {
        bail!(
            "this gateway does not serve {} at scope `{}`; starting a session mutates the \
             runtime and needs OUROBOROS_GATEWAY_SCOPE=operate",
            request.method(),
            attached.hello.scope
        );
    }

    let started = attached
        .client
        .call_with_timeout(&request.method(), params, ui::app::START_TIMEOUT)
        .await
        .map_err(|error| match &error {
            // Most of what makes a start refusal actionable is Wire-encoded into `data`;
            // the message alone is often "the runtime refused the call".
            ClientError::Rpc(rpc) if rpc.data.as_ref().is_some_and(|data| !data.is_null()) => {
                anyhow!(
                    "{} was refused: {rpc} — {}",
                    request.method(),
                    ouro::model::compact(rpc.data.as_ref().expect("checked"))
                )
            }
            other => anyhow!("{} was refused: {other}", request.method()),
        })?;

    let started = StartedRef::decode(&started).ok_or_else(|| {
        anyhow!(
            "the runtime started a session but answered a reference this build cannot read: \
             {started}"
        )
    })?;

    println!("{}", started.id);

    if let Some(message) = message {
        // `interactive.start` waits for provider readiness before it answers, so the
        // session is ready to take this by the time it is sent.
        attached
            .client
            .call(
                "interactive.send_message",
                json!({ "id": started.id, "input": message }),
            )
            .await
            .map_err(|error| anyhow!("the session started but the message was refused: {error}"))?;
    }

    if print {
        attached.client.stop().await;

        // The session outlives this process only if the runtime does.
        if let Some(daemon) = daemon.as_mut() {
            let pid = daemon.pid();
            daemon.detach();
            println!("the runtime is still running (pid {pid}); `ouro` attaches to it");
        }

        return Ok(());
    }

    run_ui(
        address,
        mode,
        daemon,
        attached,
        channel,
        Some((Plane::Interactive, started.id)),
    )
    .await
}

fn absolute(path: PathBuf) -> Result<String> {
    let here = std::env::current_dir().context("reading the working directory")?;

    Ok(runtime::resolve_workspace(&path, &here))
}

/// Whether this client supervises the runtime it is about to draw.
fn supervision(daemon: &Option<Daemon>) -> Mode {
    match daemon {
        Some(daemon) => Mode::Spawned { pid: daemon.pid() },
        // An adopted daemon is not one this client has a `Child` for, so the quit dialog
        // offers a disconnect rather than a shutdown it could not carry out. `ouro stop`
        // is the verb that ends a daemon this process did not start.
        None => Mode::Attached,
    }
}

/// Adopts the runtime this data directory already has, or starts one.
async fn local_runtime(paths: &Paths, dev: bool) -> Result<(Publication, Secret, Option<Daemon>)> {
    let existing = runtime::read_owned_publication(&paths.data_dir)?;

    match existing {
        Some(publication) if runtime::pid_alive(publication.pid) => {
            let token = runtime::read_token(&paths.token_file()).with_context(|| {
                format!(
                    "a runtime is already running (pid {}, port {}), but its token is not \
                     readable, so this client cannot reach it. Stop it and start again, or \
                     attach with --addr and --token-file",
                    publication.pid, publication.port
                )
            })?;

            println!(
                "adopted the runtime already running in {} (pid {})",
                paths.data_dir.display(),
                publication.pid
            );

            Ok((publication, token, None))
        }
        other => {
            if other.is_some() {
                // The pid is gone, so the file describes a runtime that no longer exists.
                runtime::remove_publication(&paths.data_dir)?;
            }

            start(paths, dev, Output::Ring).await
        }
    }
}

/// `ouro daemon`: start (or find) a runtime, say how to reach it, and exit.
async fn daemon(paths: &Paths, dev: bool) -> Result<()> {
    if let Some(publication) = runtime::read_owned_publication(&paths.data_dir)? {
        if runtime::pid_alive(publication.pid) {
            println!(
                "a runtime is already running\n  port        {}\n  pid         {}\n  node        {}\n  scope       {}\n  token-file  {}",
                publication.port,
                publication.pid,
                publication.node,
                publication.scope,
                paths.token_file().display()
            );

            return Ok(());
        }

        runtime::remove_publication(&paths.data_dir)?;
    }

    let (publication, _token, child) = start(paths, dev, Output::File(paths.daemon_log())).await?;

    // Detached: this process is about to exit and the runtime must not go with it. A
    // `None` here is a runtime that appeared under the spawn lock, which nothing owns.
    if let Some(mut child) = child {
        child.detach();
    }

    println!(
        "runtime started\n  port        {}\n  pid         {}\n  node        {}\n  scope       {}\n  token-file  {}\n  log         {}",
        publication.port,
        publication.pid,
        publication.node,
        publication.scope,
        paths.token_file().display(),
        paths.daemon_log().display()
    );

    Ok(())
}

/// `ouro attach`: connect to something this client did not start.
async fn attach_remote(
    paths: &Paths,
    addr: Option<String>,
    token_file: Option<PathBuf>,
    print: bool,
) -> Result<()> {
    let address = match addr {
        Some(addr) => resolve(&addr).await?,
        None => {
            let publication = runtime::read_publication(&paths.data_dir)?.ok_or_else(|| {
                anyhow!(
                    "no runtime published {}; start one with `ouro daemon`, or name a \
                     listener with --addr",
                    paths.publication().display()
                )
            })?;

            local_address(publication.port)
        }
    };

    let token_path = token_file.unwrap_or_else(|| paths.token_file());

    let token = runtime::read_token(&token_path).with_context(|| {
        format!(
            "the gateway token is read from a file, never from a flag; --token-file names \
             one (tried {})",
            token_path.display()
        )
    })?;

    if print {
        let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);

        return print_page(address, attach_with(address, token, false, hook).await?).await;
    }

    draw(address, token, Mode::Attached, None, None).await
}

/// Connects and runs the terminal UI, then carries out whatever the quit dialog chose.
async fn draw(
    address: SocketAddr,
    token: Secret,
    mode: Mode,
    daemon: Option<Daemon>,
    open: Option<(Plane, String)>,
) -> Result<()> {
    let (hook, channel) = ui::hook();
    let attached = attach_with(address, token, true, hook).await?;

    run_ui(address, mode, daemon, attached, channel, open).await
}

/// The UI half, on a connection the caller already has.
///
/// `open` focuses a session before the first frame, which is how `ouro new` hands off:
/// the subscribe it queues is drained by the driver's first pass, so the transcript is
/// live by the time anything is drawn.
async fn run_ui(
    address: SocketAddr,
    mode: Mode,
    daemon: Option<Daemon>,
    attached: Connected,
    channel: ui::UiChannel,
    open: Option<(Plane, String)>,
) -> Result<()> {
    let Connected {
        client,
        hello,
        notifications,
    } = attached;

    let logs = daemon.as_ref().map(Daemon::logs);
    let mut app = App::new(mode, address.to_string(), hello.clone(), logs);

    // The workspace the new-session dialog offers. A default, not a decision: it is
    // prefilled and editable, because the directory a terminal sits in is a good guess.
    app.launch_dir = std::env::current_dir()
        .ok()
        .map(|here| here.display().to_string());

    if let Some((plane, id)) = open {
        app.open_session(plane, id);
    }

    if hello.protocol != proto::PROTOCOL {
        app.inform(
            format!(
                "the gateway completed a handshake but reports protocol {}, not {}",
                hello.protocol,
                proto::PROTOCOL
            ),
            ouro::ui::app::NoticeKind::Warn,
        );
    }

    let mut daemon = daemon;

    let quit = ui::run(app, client.clone(), notifications, channel, daemon.as_mut()).await?;

    finish(quit, &client, &hello, daemon).await
}

/// The quit dialog's choice, executed through the same paths the CLI already used: an
/// acknowledged `runtime.shutdown` where the gateway serves it, then SIGTERM, then
/// SIGKILL, all of which `Daemon::terminate` already sequences.
async fn finish(quit: Quit, client: &Client, hello: &Hello, daemon: Option<Daemon>) -> Result<()> {
    let Some(mut daemon) = daemon else {
        client.stop().await;
        println!("disconnected; the runtime keeps running");

        return Ok(());
    };

    match quit {
        Quit::Detach | Quit::Disconnect => {
            let pid = daemon.pid();
            daemon.detach();
            println!("detached; the runtime is still running (pid {pid})");
        }
        Quit::Shutdown => {
            if hello.serves("runtime.shutdown") && hello.operates() {
                match client.call("runtime.shutdown", json!({})).await {
                    Ok(_result) => println!("the runtime accepted runtime.shutdown"),
                    // The runtime stopping is what was asked for, and it may stop before
                    // it can answer.
                    Err(ClientError::ConnectionClosed) => {
                        println!("the runtime accepted runtime.shutdown and closed the connection")
                    }
                    Err(error) => println!("runtime.shutdown failed ({error}); signalling instead"),
                }
            } else {
                println!(
                    "this build does not serve runtime.shutdown at this scope; signalling pid {}",
                    daemon.pid()
                );
            }

            client.stop().await;

            match daemon.terminate(SHUTDOWN_GRACE).await? {
                Some(status) => println!("the runtime exited: {status}"),
                None => println!("the runtime had already exited"),
            }
        }
    }

    Ok(())
}

/// The one-shot page `ouro attach --print` renders, for a pipe or a terminal without a
/// tty. It is the whole of what this client showed before there was a UI, kept because a
/// status page that can be redirected into a file is not the same tool as a UI.
async fn print_page(address: SocketAddr, attached: Connected) -> Result<()> {
    let Connected { client, hello, .. } = attached;

    print!("{}", status::render_hello(&address.to_string(), &hello));
    print_protocol_warning(&hello);
    println!();

    let status = client
        .call("runtime.status", json!({}))
        .await
        .context("calling runtime.status")?;

    print!("{}", status::render_status(&status));

    client.stop().await;

    Ok(())
}

/// `ouro stop`: ask the runtime this client started to exit, and fall back to a signal
/// only for a pid this client can prove it owns.
async fn stop(paths: &Paths) -> Result<()> {
    let publication = runtime::read_owned_publication(&paths.data_dir)?.ok_or_else(|| {
        anyhow!(
            "no runtime published {}, so there is nothing here to stop",
            paths.publication().display()
        )
    })?;

    if !runtime::pid_alive(publication.pid) {
        runtime::remove_publication(&paths.data_dir)?;
        println!(
            "no runtime is running: pid {} from {} is gone, and the stale publication has \
             been removed",
            publication.pid,
            paths.publication().display()
        );

        return Ok(());
    }

    let token = runtime::read_token(&paths.token_file())?;
    let address = local_address(publication.port);

    // Reconnect is off: this connection exists to end the thing on the other side of it,
    // so the close that follows is the answer rather than a fault to repair.
    let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);
    let attached = attach_with(address, token, false, hook).await?;

    if attached.hello.node != publication.node {
        bail!(
            "{} names node {} but the listener on port {} is {}; refusing to signal a pid \
             this publication may no longer describe",
            paths.publication().display(),
            publication.node,
            publication.port,
            attached.hello.node
        );
    }

    if attached.hello.serves("runtime.shutdown") && attached.hello.operates() {
        match attached.client.call("runtime.shutdown", json!({})).await {
            Ok(_result) => println!("the runtime accepted runtime.shutdown"),
            // The runtime stopping is exactly what was asked for, and it may stop before
            // it can answer.
            Err(ClientError::ConnectionClosed) => {
                println!("the runtime accepted runtime.shutdown and closed the connection")
            }
            Err(error) => bail!("runtime.shutdown failed: {error}"),
        }
    } else {
        println!(
            "this build does not serve runtime.shutdown at this scope; sending SIGTERM to \
             pid {}",
            publication.pid
        );

        runtime::send_signal(publication.pid, libc::SIGTERM)?;
    }

    attached.client.stop().await;

    let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;

    while runtime::pid_alive(publication.pid) {
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "pid {} is still running {}s after being asked to stop; it was not killed, \
                 because a runtime with durable journals is not something this client kills \
                 on a timer",
                publication.pid,
                SHUTDOWN_GRACE.as_secs()
            );
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("the runtime stopped (pid {})", publication.pid);

    Ok(())
}

/// Starts a runtime and waits for it to publish a port, under the spawn lock.
///
/// `None` for the daemon means another `ouro` published one while this call was taking
/// the lock: the check the caller made and the spawn it asked for are not one operation,
/// and the lock is where that gap is closed. Adopting is the right answer there — a
/// second runtime in the same data directory would overwrite the first one's token.
async fn start(
    paths: &Paths,
    dev: bool,
    output: Output,
) -> Result<(Publication, Secret, Option<Daemon>)> {
    // Held until this function returns, which is the whole spawn window: check, spawn,
    // and wait for the publication. Not longer — a client that held it while attached
    // would stop the next `ouro` from adopting the daemon it just started.
    let _lock = runtime::acquire_spawn_lock(&paths.data_dir)?;

    if let Some(publication) = runtime::read_owned_publication(&paths.data_dir)? {
        if runtime::pid_alive(publication.pid) {
            let token = runtime::read_token(&paths.token_file()).with_context(|| {
                format!(
                    "another client started a runtime here (pid {}), but its token is not \
                     readable by this one",
                    publication.pid
                )
            })?;

            println!(
                "adopted the runtime another client just started (pid {})",
                publication.pid
            );

            return Ok((publication, token, None));
        }

        runtime::remove_publication(&paths.data_dir)?;
    }

    let launcher = launcher(dev, paths)?;
    let token_path = paths.token_file();
    let token = runtime::write_token(&token_path)?;

    println!("starting a runtime in {}", paths.data_dir.display());

    let mut daemon = runtime::spawn(&launcher, &paths.data_dir, &token_path, output)?;
    let deadline = launcher.ready_deadline();

    let publication = daemon.wait_ready(&paths.data_dir, deadline).await?;

    if publication.protocol != proto::PROTOCOL {
        println!(
            "warning: {} publishes protocol {}, this client speaks {}",
            paths.publication().display(),
            publication.protocol,
            proto::PROTOCOL
        );
    }

    Ok((publication, token, Some(daemon)))
}

fn launcher(dev: bool, paths: &Paths) -> Result<Launcher> {
    if dev {
        let here = std::env::current_dir().context("reading the working directory")?;

        return Ok(Launcher::Dev {
            repo_root: runtime::find_repo_root(&here)?,
        });
    }

    release_launcher(paths)
}

#[cfg(feature = "embed")]
fn release_launcher(paths: &Paths) -> Result<Launcher> {
    let release = runtime::embed::embedded().ok_or_else(|| {
        anyhow!(
            "this binary was built without a release; run it in a checkout with --dev, or \
             attach to a runtime with `ouro attach`"
        )
    })?;

    let root = runtime::embed::extract_embedded(&release, &paths.releases())?;

    // Collection failing is not a reason to refuse to start.
    let _ = runtime::embed::gc(&paths.releases(), runtime::embed::KEEP);

    Ok(Launcher::Release { root })
}

#[cfg(not(feature = "embed"))]
fn release_launcher(_paths: &Paths) -> Result<Launcher> {
    bail!(
        "this binary was built without an embedded release; run it in a checkout with \
         --dev, or attach to a runtime with `ouro attach`"
    )
}

async fn attach_with(
    address: SocketAddr,
    token: Secret,
    reconnect: bool,
    hook: Arc<dyn ReconnectHook>,
) -> Result<Connected> {
    let mut config = TransportConfig::new(address, token);
    config.reconnect = reconnect;

    transport::connect(config, hook)
        .await
        .map_err(|error| match error.code() {
            Some(proto::ErrorCode::Unauthenticated) => anyhow!(
                "the gateway refused this token. The token file must be the one the running \
                 daemon was started with ({error})"
            ),
            Some(proto::ErrorCode::ProtocolMismatch) => anyhow!(
                "this client speaks protocol {}, the gateway does not ({error})",
                proto::PROTOCOL
            ),
            _ => anyhow!("cannot reach the gateway at {address}: {error}"),
        })
}

fn print_protocol_warning(hello: &Hello) {
    if hello.protocol != proto::PROTOCOL {
        println!(
            "warning: the gateway completed a handshake but reports protocol {}, not {}",
            hello.protocol,
            proto::PROTOCOL
        );
    }
}

fn local_address(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

async fn resolve(addr: &str) -> Result<SocketAddr> {
    if let Ok(address) = addr.parse::<SocketAddr>() {
        return Ok(address);
    }

    tokio::net::lookup_host(addr)
        .await
        .with_context(|| format!("resolving --addr {addr}"))?
        .next()
        .ok_or_else(|| anyhow!("--addr {addr} resolved to no address"))
}
