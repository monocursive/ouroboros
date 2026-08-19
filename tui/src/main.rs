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
//!
//! ## Where the screen begins
//!
//! Every path that ends in the full-screen UI takes the terminal *before* it starts a
//! runtime, through [`ouro::ui::boot`], and hands that same live terminal to the App when
//! the handshake completes. Spawning is otherwise unchanged: the boot screen drives the
//! same futures this file always awaited, and [`ouro::ui::boot::Progress::Plain`] prints
//! exactly the lines it always printed wherever there is no screen to draw on — a pipe,
//! `ouro daemon`, or any `--print`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde_json::json;

use ouro::cli::{Cli, Command};
use ouro::config::{self, Loaded, StartFlags};
use ouro::model::{ApprovalMode, Plane, SandboxMode, StartError, StartRequest, StartedRef};
use ouro::proto::Hello;
use ouro::runtime::{Daemon, Launcher, Output, Paths, Publication};
use ouro::transport::{
    Client, ClientError, Connected, NoReconnectHook, ReconnectHook, Secret, TransportConfig,
};
use ouro::ui::boot::{Boot, BootEvent, Progress};
use ouro::ui::{self, App, Mode, Quit, Screen};
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

    // Read once, for the surfaces that consult it. A file that does not parse costs the
    // sentence in `Loaded::problems` and nothing else — `ouro` starting a runtime must not
    // depend on a preference file being well-formed. `--dev` reads the same one: which
    // provider a person prefers is a fact about the person, not about which runtime they
    // started.
    let config = config::load_default();

    match cli.command {
        None => attach_local(&paths, cli.dev, config).await,
        Some(Command::New {
            provider,
            workspace,
            approval_mode,
            sandbox_mode,
            message,
            print,
        }) => {
            new_session(
                &paths,
                cli.dev,
                config,
                StartFlags {
                    provider,
                    workspace: workspace.map(absolute).transpose()?,
                    approval_mode,
                    sandbox_mode,
                },
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
        }) => attach_remote(&paths, addr, token_file, print, config).await,
        Some(Command::Stop) => stop(&paths).await,
        Some(Command::Version) => {
            print!("{}", version());
            Ok(())
        }
    }
}

/// This client's own facts, for the panes that show them beside the runtime's.
///
/// Kept apart from everything the gateway answered, and labelled apart on screen: a data
/// directory this process chose and a node name a handshake reported are two different
/// kinds of claim, and a UI that ran them together would be asserting the runtime had
/// confirmed something it was never asked.
struct Local {
    /// Where this client told the runtime to keep its files, when it started one. `None`
    /// in attach mode, because then it did not choose.
    data_dir: Option<String>,
    config: Loaded,
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
///
/// The screen is taken first, so the seconds a cold start costs are seconds of visible
/// progress rather than of silence, and a boot that fails does so somewhere it can show
/// the runtime's own output.
async fn attach_local(paths: &Paths, dev: bool, config: Loaded) -> Result<()> {
    let mut boot = Boot::begin();
    let progress = boot.progress();

    let (publication, token, daemon) = match boot.drive(local_runtime(paths, dev, &progress)).await
    {
        Ok(started) => started,
        Err(error) => return Err(boot.fail(error).await),
    };

    let local = Local {
        data_dir: Some(paths.data_dir.display().to_string()),
        config,
    };

    draw(
        boot,
        local_address(publication.port),
        token,
        supervision(&daemon),
        daemon,
        None,
        local,
    )
    .await
}

/// `ouro new`: state every choice, start the session, and attach to it.
///
/// The validation is [`StartRequest`]'s — the same code the `n` dialog runs — so a
/// parameter this client would refuse in one surface is refused in both, and neither can
/// invent an option the gateway's allowlist does not contain. What the config file adds is
/// a second place each flag can be answered from, resolved by
/// [`config::resolve_start`] before any of that runs.
async fn new_session(
    paths: &Paths,
    dev: bool,
    config: Loaded,
    flags: StartFlags,
    message: Option<String>,
    print: bool,
) -> Result<()> {
    let resolved = config::resolve_start(&flags, &config.config.defaults)
        .map_err(|missing| anyhow!("{}", missing.message(&config.path)))?;

    let request = StartRequest {
        plane: Plane::Interactive,
        provider: resolved.provider.clone(),
        // A stored workspace is resolved the way a typed one is. A relative path across a
        // socket would be resolved against the *runtime's* working directory, which for a
        // spawned daemon is a release root — nowhere the operator ever stood.
        workspace: match &resolved.workspace {
            Some(path) => absolute(PathBuf::from(path))?,
            None => String::new(),
        },
        approval_mode: match &resolved.approval_mode {
            None => None,
            Some(name) => Some(ApprovalMode::parse(name).ok_or_else(|| {
                anyhow!(
                    "{}",
                    StartError::UnknownApprovalMode(name.clone()).message()
                )
            })?),
        },
        sandbox_mode: match &resolved.sandbox_mode {
            None => None,
            Some(name) => Some(SandboxMode::parse(name).ok_or_else(|| {
                anyhow!("{}", StartError::UnknownSandboxMode(name.clone()).message())
            })?),
        },
        objective: String::new(),
    };

    // Refused before a runtime is started: a missing provider is not worth a daemon.
    let params = request
        .params()
        .map_err(|refusal| anyhow!("{}", refusal.message()))?;

    // `--print` is a surface whose whole point is bytes on stdout, so it keeps the plain
    // lines even on a tty.
    let mut boot = if print { Boot::plain() } else { Boot::begin() };
    let progress = boot.progress();

    if !boot.on_screen() {
        // Nowhere to draw them, so they go where the rest of this client's complaints go.
        // On a screen they arrive as a notice instead, from `run_ui`.
        for problem in &config.problems {
            eprintln!("ouro: {problem}");
        }
    }

    let (publication, token, mut daemon) =
        match boot.drive(local_runtime(paths, dev, &progress)).await {
            Ok(started) => started,
            Err(error) => return Err(boot.fail(error).await),
        };

    let address = local_address(publication.port);
    let mode = supervision(&daemon);

    let (hook, channel) = ui::hook();
    progress.report(BootEvent::Connecting {
        address: address.to_string(),
    });

    let attached = match boot.drive(attach_with(address, token, true, hook)).await {
        Ok(attached) => attached,
        Err(error) => return Err(boot.fail(error).await),
    };

    progress.report(BootEvent::Connected {
        node: attached.hello.node.clone(),
    });

    if !attached.hello.serves(&request.method()) || !attached.hello.operates() {
        return Err(boot
            .fail(anyhow!(
                "this gateway does not serve {} at scope `{}`; starting a session mutates \
                 the runtime and needs OUROBOROS_GATEWAY_SCOPE=operate",
                request.method(),
                attached.hello.scope
            ))
            .await);
    }

    progress.report(BootEvent::StartingSession {
        provider: resolved.provider.clone(),
    });

    // Driven by the boot screen because it is allowed to take two minutes: provider
    // readiness is `:infinity` upstream, and this is the one call that waits for it.
    let started = boot
        .drive(
            attached
                .client
                .call_with_timeout(&request.method(), params, ui::app::START_TIMEOUT),
        )
        .await
        .map_err(|error| match &error {
            // Most of what makes a start refusal actionable is Wire-encoded into `data`;
            // the message alone is often "the runtime refused the call". `model::refusal`
            // is the one place that becomes text, so this stderr and the two dialogs say
            // the same sentence.
            ClientError::Rpc(rpc) => {
                anyhow!(
                    "{} was refused: {}",
                    request.method(),
                    ouro::model::refusal(rpc)
                )
            }
            other => anyhow!("{} was refused: {other}", request.method()),
        });

    let started = match started {
        Ok(started) => started,
        Err(error) => return Err(boot.fail(error).await),
    };

    let Some(started) = StartedRef::decode(&started) else {
        return Err(boot
            .fail(anyhow!(
                "the runtime started a session but answered a reference this build cannot \
                 read: {started}"
            ))
            .await);
    };

    progress.report(BootEvent::SessionStarted {
        id: started.id.clone(),
    });

    // On a screen the id is on the boot panel, in the notice line, and on the Sessions
    // tab; printing it into the alternate buffer would only overwrite a frame with it.
    if !boot.on_screen() {
        println!("{}", started.id);
    }

    if let Some(message) = message {
        // `interactive.start` waits for provider readiness before it answers, so the
        // session is ready to take this by the time it is sent.
        let sent = attached
            .client
            .call(
                "interactive.send_message",
                json!({ "id": started.id, "input": message }),
            )
            .await
            .map_err(|error| anyhow!("the session started but the message was refused: {error}"));

        if let Err(error) = sent {
            return Err(boot.fail(error).await);
        }
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
        boot.finish(),
        Local {
            data_dir: Some(paths.data_dir.display().to_string()),
            config,
        },
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
async fn local_runtime(
    paths: &Paths,
    dev: bool,
    progress: &Progress,
) -> Result<(Publication, Secret, Option<Daemon>)> {
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

            progress.report(BootEvent::Adopted {
                pid: publication.pid,
                data_dir: paths.data_dir.display().to_string(),
            });

            Ok((publication, token, None))
        }
        other => {
            if other.is_some() {
                // The pid is gone, so the file describes a runtime that no longer exists.
                runtime::remove_publication(&paths.data_dir)?;
            }

            start(paths, dev, Output::Ring, progress).await
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

    // Plain by construction: `ouro daemon` prints how to reach the runtime and exits, and
    // a screen it would tear down a second later helps nobody.
    let (publication, _token, child) = start(
        paths,
        dev,
        Output::File(paths.daemon_log()),
        &Progress::Plain,
    )
    .await?;

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
    config: Loaded,
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

    // No spawn to watch, so the boot screen is one phase long — but it is still where the
    // terminal is taken, so the handshake to a runtime on the other end of a tunnel has
    // somewhere to be slow in.
    draw(
        Boot::begin(),
        address,
        token,
        Mode::Attached,
        None,
        None,
        Local {
            // This client did not start it, so it does not know where that runtime keeps
            // anything.
            data_dir: None,
            config,
        },
    )
    .await
}

/// Connects with the boot screen still live, and hands the terminal to the UI.
async fn draw(
    mut boot: Boot,
    address: SocketAddr,
    token: Secret,
    mode: Mode,
    daemon: Option<Daemon>,
    open: Option<(Plane, String)>,
    local: Local,
) -> Result<()> {
    let (hook, channel) = ui::hook();
    let progress = boot.progress();

    progress.report(BootEvent::Connecting {
        address: address.to_string(),
    });

    let attached = match boot.drive(attach_with(address, token, true, hook)).await {
        Ok(attached) => attached,
        Err(error) => return Err(boot.fail(error).await),
    };

    progress.report(BootEvent::Connected {
        node: attached.hello.node.clone(),
    });

    run_ui(
        address,
        mode,
        daemon,
        attached,
        channel,
        open,
        boot.finish(),
        local,
    )
    .await
}

/// The UI half, on a connection the caller already has.
///
/// `open` focuses a session before the first frame, which is how `ouro new` hands off:
/// the subscribe it queues is drained by the driver's first pass, so the transcript is
/// live by the time anything is drawn.
///
/// `screen` is the terminal the boot screen took over. Passing it on rather than entering
/// a second one is what makes the handoff seamless — and what makes a `None` here mean
/// exactly one thing: there was no tty, and [`ui::run`] is where that is refused.
#[allow(clippy::too_many_arguments)]
async fn run_ui(
    address: SocketAddr,
    mode: Mode,
    daemon: Option<Daemon>,
    attached: Connected,
    channel: ui::UiChannel,
    open: Option<(Plane, String)>,
    screen: Option<Screen>,
    local: Local,
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

    app.data_dir = local.data_dir;
    app.config_path = Some(local.config.path.clone());
    app.config = local.config.config;

    // A preference file that did not parse is one sentence, not a refusal to run. It is
    // said before the protocol warning below so that the more urgent of the two is the one
    // left on screen.
    if !local.config.problems.is_empty() {
        app.inform(
            local.config.problems.join(" · "),
            ouro::ui::app::NoticeKind::Warn,
        );
    }

    let opened = open.is_some();

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

    // `open` is `Some` only for `ouro new`, which stated on its command line exactly what
    // the home composer exists to ask, and is already looking at what it started.
    if !opened {
        app.open_home();
    }

    let mut daemon = daemon;

    let quit = ui::run(
        screen,
        app,
        client.clone(),
        notifications,
        channel,
        daemon.as_mut(),
    )
    .await?;

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
    progress: &Progress,
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

            progress.report(BootEvent::AdoptedUnderLock {
                pid: publication.pid,
            });

            return Ok((publication, token, None));
        }

        runtime::remove_publication(&paths.data_dir)?;
    }

    // The slow part of a genuinely cold start on an embedded build: the tarball's digest
    // is verified and the release unpacked. It printed nothing before there was a screen
    // and still prints nothing without one.
    progress.report(BootEvent::Preparing);

    let launcher = launcher(dev, paths)?;
    let token_path = paths.token_file();
    let token = runtime::write_token(&token_path)?;

    progress.report(BootEvent::Starting {
        data_dir: paths.data_dir.display().to_string(),
    });

    let mut daemon = runtime::spawn(&launcher, &paths.data_dir, &token_path, output)?;

    // Handed over before the wait, so a boot that is slow because the runtime is saying
    // something has that something on screen while it happens.
    progress.attach_logs(daemon.logs());
    progress.report(BootEvent::Spawned { pid: daemon.pid() });

    let deadline = launcher.ready_deadline();

    let publication = daemon.wait_ready(&paths.data_dir, deadline).await?;

    progress.report(BootEvent::Published {
        port: publication.port,
    });

    if publication.protocol != proto::PROTOCOL {
        progress.report(BootEvent::Warning(format!(
            "warning: {} publishes protocol {}, this client speaks {}",
            paths.publication().display(),
            publication.protocol,
            proto::PROTOCOL
        )));
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
