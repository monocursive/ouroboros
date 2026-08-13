//! `ouro`: start or find an Ouroboros runtime and speak its operator protocol.
//!
//! Slice 3a is the plumbing half. "Attaching" here means connecting, completing the
//! handshake, printing one page of status, and holding the connection open until ctrl-c
//! — the ratatui UI replaces that page in Slice 3b without changing anything under it.
//! Notifications are routed to a channel and drained, not interpreted: event streaming
//! does not exist in the gateway yet, and a client that pretended to consume it would be
//! claiming something untrue.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde_json::json;

use ouro::cli::{Cli, Command};
use ouro::proto::Hello;
use ouro::runtime::{Daemon, Launcher, Output, Paths, Publication};
use ouro::transport::{
    Client, ClientError, Connected, NoReconnectHook, ReconnectHook, Secret, TransportConfig,
};
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
        Some(Command::Daemon) => daemon(&paths, cli.dev).await,
        Some(Command::Attach { addr, token_file }) => attach_remote(&paths, addr, token_file).await,
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

/// The default command: adopt a running runtime or start one, then attach.
async fn attach_local(paths: &Paths, dev: bool) -> Result<()> {
    let existing = runtime::read_owned_publication(&paths.data_dir)?;

    let (publication, token, daemon) = match existing {
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

            (publication, token, None)
        }
        other => {
            if other.is_some() {
                // The pid is gone, so the file describes a runtime that no longer exists.
                runtime::remove_publication(&paths.data_dir)?;
            }

            let (publication, token, daemon) = start(paths, dev, Output::Ring).await?;
            (publication, token, Some(daemon))
        }
    };

    let address = local_address(publication.port);
    let attached = attach(address, token, true).await?;

    // Held for the rest of this function: dropping it would close the connection the
    // command exists to hold open.
    let _client = present(address, attached).await?;

    match daemon {
        None => {
            println!("attached; ctrl-c disconnects and leaves the runtime running");
            wait_for_exit(None).await?;
        }
        Some(mut daemon) => {
            println!("attached; ctrl-c stops the runtime this client started");

            match wait_for_exit(Some(&mut daemon)).await? {
                Exit::ChildExited(reason) => {
                    println!("the runtime exited on its own: {reason}");
                    print!("{}", daemon.log_tail(40));
                }
                Exit::Interrupted => {
                    println!("stopping the runtime (pid {})", daemon.pid());

                    match daemon.terminate(SHUTDOWN_GRACE).await? {
                        Some(status) => println!("the runtime exited: {status}"),
                        None => println!("the runtime had already exited"),
                    }
                }
            }
        }
    }

    Ok(())
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

    let (publication, _token, mut child) =
        start(paths, dev, Output::File(paths.daemon_log())).await?;

    // Detached: this process is about to exit and the runtime must not go with it.
    child.detach();

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

    let attached = attach(address, token, true).await?;
    let _client = present(address, attached).await?;

    println!("attached; ctrl-c disconnects and leaves the runtime running");

    wait_for_exit(None).await?;

    Ok(())
}

/// The one page Slice 3a shows in place of a UI, and the notification drain behind it.
///
/// The returned [`Client`] is the connection: a caller that drops it disconnects, so
/// every command that means to stay attached holds it for as long as it does.
async fn present(address: SocketAddr, attached: Connected) -> Result<Client> {
    let Connected {
        client,
        hello,
        notifications,
    } = attached;

    print!("{}", status::render_hello(&address.to_string(), &hello));
    print_protocol_warning(&hello);
    println!();

    let status = client
        .call("runtime.status", json!({}))
        .await
        .context("calling runtime.status")?;

    print!("{}", status::render_status(&status));
    println!();

    drain_notifications(notifications);

    Ok(client)
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
    let attached = attach(address, token, false).await?;

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

/// Starts a runtime and waits for it to publish a port.
async fn start(paths: &Paths, dev: bool, output: Output) -> Result<(Publication, Secret, Daemon)> {
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

    Ok((publication, token, daemon))
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

async fn attach(address: SocketAddr, token: Secret, reconnect: bool) -> Result<Connected> {
    let mut config = TransportConfig::new(address, token);
    config.reconnect = reconnect;

    let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);

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

/// Slice 3a consumes no events. Draining is still routing: the channel exists, it is
/// read, and anything that arrives is printed rather than silently discarded.
fn drain_notifications(mut notifications: tokio::sync::mpsc::Receiver<proto::Notification>) {
    tokio::spawn(async move {
        while let Some(notification) = notifications.recv().await {
            println!("notification {}", notification.method);
        }
    });
}

enum Exit {
    Interrupted,
    ChildExited(String),
}

/// Waits for ctrl-c, or for a supervised child to exit first.
async fn wait_for_exit(daemon: Option<&mut Daemon>) -> Result<Exit> {
    let Some(daemon) = daemon else {
        tokio::signal::ctrl_c().await?;
        return Ok(Exit::Interrupted);
    };

    loop {
        tokio::select! {
            interrupted = tokio::signal::ctrl_c() => {
                interrupted?;
                return Ok(Exit::Interrupted);
            }
            _tick = tokio::time::sleep(Duration::from_millis(250)) => {
                if let Some(status) = daemon.exited() {
                    return Ok(Exit::ChildExited(status.to_string()));
                }
            }
        }
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
