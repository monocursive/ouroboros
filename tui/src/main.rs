//! `ouro`: start or find an Ouroboros runtime and speak its operator protocol.
//!
//! This file owns process lifecycle and nothing else. Attaching means connecting,
//! completing the handshake, and handing the connection to [`ouro::ui`], which draws it
//! until the operator picks something from the quit dialog; what happens to the runtime
//! afterwards is that choice, executed here.
//!
//! The non-UI commands are unchanged and deliberately so: `ouro daemon` still starts and
//! exits, `ouro stop` uses authenticated `runtime.shutdown` and never signals a PID read
//! from a replaceable publication, and `ouro attach --print` renders the same one-shot
//! page for a pipe or a terminal that is not a tty.
//!
//! ## Where the screen begins
//!
//! Every path that ends in the full-screen UI takes the terminal *before* it starts a
//! runtime, through [`ouro::ui::boot`], and hands that same live terminal to the App when
//! the handshake completes. Spawning is otherwise unchanged: the boot screen drives the
//! same futures this file always awaited, and [`ouro::ui::boot::Progress::Plain`] prints
//! exactly the lines it always printed wherever there is no screen to draw on — a pipe,
//! `ouro daemon`, or any `--print`.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rand::TryRngCore;
use serde_json::{json, Value};

use ouro::cli::{
    Cli, Command, FleetCommand, HookCommand, InviteCommand, LedgerArgs, RunArgs, ServiceCommand,
    SessionsCommand, SyncCommand,
};
use ouro::config::{self, Loaded, StartFlags};
use ouro::fleet_add;
use ouro::model::{ApprovalMode, Plane, SandboxMode, StartError, StartRequest, StartedRef};
use ouro::proto::Hello;
use ouro::runtime::{Daemon, Launcher, Output, Paths, Publication};
use ouro::transport::{
    Client, ClientError, Connected, NoReconnectHook, ReconnectHook, Secret, TransportConfig,
};
use ouro::ui::boot::{Boot, BootEvent, BootProgress, Progress};
use ouro::ui::{self, App, Mode, Quit, Screen};
use ouro::{fleet, proto, runtime, status, transport};

/// How long a runtime is given to stop before it is killed. `System.stop/0` and a
/// SIGTERM both run the same orderly shutdown, and a runtime with durable journals is
/// owed the chance to finish it.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(20);

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        // `ouro run` documents its exit codes, so it ends by carrying one out rather than
        // by describing a failure. It has already said whatever it had to say, on the
        // stream it chose, so nothing is printed here.
        Err(error) => match error.downcast_ref::<ouro::run::Exit>() {
            Some(exit) => ExitCode::from(exit.code()),
            None => {
                eprintln!("ouro: {error:#}");
                ExitCode::FAILURE
            }
        },
    }
}

async fn run(cli: Cli) -> Result<()> {
    // `mcp-serve` is not a terminal command. Its stdout is a protocol the process that
    // spawned it is already reading, so it is answered before anything here discovers a
    // data directory, parses a config file, or decides what to do with a terminal.
    if matches!(cli.command, Some(Command::McpServe)) {
        return ouro::mcp_serve::serve().await;
    }

    // A hook is answered here for the same reason and one more: it runs inside somebody
    // else's turn, on a five-second budget, and a data directory it cannot discover must
    // not turn into a failure the vendor reads as a refused edit.
    if let Some(Command::Hook { command }) = &cli.command {
        return match command {
            HookCommand::PostToolUse => ouro::hook::post_tool_use().await,
        };
    }

    let paths = Paths::discover(cli.dev)?;

    // Read once, for the surfaces that consult it. A file that does not parse costs the
    // sentence in `Loaded::problems` and nothing else — `ouro` starting a runtime must not
    // depend on a preference file being well-formed. `--dev` reads the same one: which
    // provider a person prefers is a fact about the person, not about which runtime they
    // started.
    let mut config = config::load_default();

    // Stated before anything takes over a terminal. The boot screen enters the alternate
    // screen ahead of the App, and a mouse captured there and released a second later would
    // already have cost the operator the selection this setting exists to keep.
    ui::set_mouse_capture(config.config.terminal.mouse);

    // Same rule, for the same reason: the boot screen draws before there is an `App`, and a
    // client that spent its first two seconds in the wrong palette and then switched would
    // be doing the silent screen-model change this client refuses to make.
    //
    // `NO_COLOR` is read here rather than inside the theme module so that resolution stays
    // a pure function of its arguments. Presence is the signal, per <https://no-color.org>;
    // an empty value is the documented way to say nothing.
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    ui::set_theme(config.config.theme.name(), no_color);

    let accessibility = ouro::ui::access::resolve(
        &config.config.accessibility,
        cli.ax_screen_reader,
        &ouro::ui::access::Env::from_env(),
    );
    ouro::ui::access::install(accessibility);

    // A palette that is not the one the file asked for is a fact the operator is owed. The
    // terminal-background half of this is only known after a screen exists, so it is said
    // again from `App` on the first tick; this half is knowable now and reaches a `--print`
    // run and a piped `ouro run`, which never get a notice row at all.
    if let Some(note) = ui::theme_note() {
        config.problems.push(note);
    }

    match cli.command {
        None => attach_local(&paths, cli.dev, config).await,
        Some(Command::New {
            provider,
            workspace,
            approval_mode,
            sandbox_mode,
            message,
            machine,
            worktree,
            print,
        }) => {
            new_session(
                &paths,
                cli.dev,
                config,
                StartFlags {
                    provider,
                    workspace: workspace.map(workspace_argument).transpose()?,
                    approval_mode,
                    sandbox_mode,
                    machine,
                },
                message,
                worktree,
                print,
            )
            .await
        }
        Some(Command::Run(args)) => run_prompt(&paths, cli.dev, config, *args).await,
        Some(Command::Agents {
            json,
            addr,
            token_file,
        }) => agents_page(&paths, json, addr, token_file).await,
        Some(Command::Daemon) => daemon(&paths, cli.dev).await,
        Some(Command::Attach {
            addr,
            token_file,
            print,
        }) => attach_remote(&paths, cli.dev, addr, token_file, print, config).await,
        Some(Command::Stop) => stop(&paths, cli.dev).await,
        Some(Command::Ledger(args)) => ledger(&paths, args).await,
        Some(Command::Fleet { command }) => fleet_command(&paths, cli.dev, command).await,
        Some(Command::ServiceRun) => service_run(&paths, cli.dev).await,
        // Answered at the top of this function, before the terminal existed as far as
        // this process is concerned. The arms keep the match total.
        Some(Command::McpServe) => ouro::mcp_serve::serve().await,
        Some(Command::Hook {
            command: HookCommand::PostToolUse,
        }) => ouro::hook::post_tool_use().await,
        Some(Command::ProcessBirth { pid }) => {
            let birth = runtime::process_birth(pid)?
                .ok_or_else(|| anyhow!("process pid {pid} is not alive"))?;
            println!("{birth}");
            Ok(())
        }
        Some(Command::HoldRuntimeRecoveryLock { path }) => {
            runtime::hold_runtime_recovery_lock(&path)
        }
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
    /// After a standalone→fleet restart, land on Machines so the operator sees the add.
    open_machines: bool,
    /// Progress lines from the add that triggered that restart. Empty on a normal start.
    add_log: Vec<String>,
    /// Enroll recipe from that add, if the destination still needs a command. Never
    /// contains invitation bytes.
    add_recipe: Option<String>,
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
    attach_local_with(paths, dev, config, false, None).await
}

async fn attach_local_with(
    paths: &Paths,
    dev: bool,
    config: Loaded,
    open_machines: bool,
    add_outcome: Option<fleet_add::Outcome>,
) -> Result<()> {
    paths.ensure_private_data_dir()?;

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
        open_machines,
        add_log: add_outcome
            .as_ref()
            .map(|outcome| outcome.log.clone())
            .unwrap_or_default(),
        add_recipe: add_outcome.and_then(|outcome| outcome.recipe.map(|recipe| recipe.text())),
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
    worktree: bool,
    print: bool,
) -> Result<()> {
    paths.ensure_private_data_dir()?;

    let resolved = config::resolve_start(&flags, &config.config.defaults)
        .map_err(|missing| anyhow!("{}", missing.message(&config.path)))?;
    // This identity exists before the mutation and survives its one safe reconciliation.
    let session_id = new_client_session_id()?;
    let machine = resolved.machine.unwrap_or_default();

    let request = StartRequest {
        id: session_id.clone(),
        plane: Plane::Interactive,
        provider: resolved.provider.clone(),
        machine: machine.clone(),
        // A stored workspace is resolved the way a typed one is. A relative path across a
        // socket would be resolved against the *runtime's* working directory, which for a
        // spawned daemon is a release root — nowhere the operator ever stood.
        workspace: start_workspace(&machine, resolved.workspace.as_deref())?,
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
        worktree,
    };

    // Mint the durable identity before the mutation. If the reply disappears after the
    // gateway accepted the request, replaying these exact params can only adopt the same
    // session (or report an id conflict); it cannot silently create and bill another one.
    let params = cli_start_params(&request, &session_id)?;

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
        Err(error) => {
            return Err(fail_boot_with_owned_daemon(
                boot,
                &mut daemon,
                None,
                error,
                "connecting to the newly started runtime failed",
            )
            .await)
        }
    };

    progress.report(BootEvent::Connected {
        node: attached.hello.node.clone(),
    });

    if !attached.hello.serves(&request.method()) || !attached.hello.operates() {
        let error = anyhow!(
            "this gateway does not serve {} at scope `{}`; starting a session mutates \
                 the runtime and needs OUROBOROS_GATEWAY_SCOPE=operate",
            request.method(),
            attached.hello.scope
        );

        return Err(fail_boot_with_owned_daemon(
            boot,
            &mut daemon,
            Some(&attached.client),
            error,
            "the newly started runtime could not host this session",
        )
        .await);
    }

    progress.report(BootEvent::StartingSession {
        provider: resolved.provider.clone(),
    });

    // Driven by the boot screen because it is allowed to take two minutes: provider
    // readiness is `:infinity` upstream, and this is the one call that waits for it. A
    // transport loss or upstream timeout may happen after durable creation, so retry once
    // with the exact same id and options before asking the operator to inspect that id.
    let method = request.method();
    let first = boot
        .drive(
            attached
                .client
                .call_with_timeout(&method, params.clone(), ui::app::START_TIMEOUT),
        )
        .await;

    let started = match first {
        Ok(started) => started,
        Err(error) => {
            let first_failure = start_failure(&error);

            if !first_failure.outcome_unknown {
                let error = anyhow!("{method} was refused: {}", first_failure.rendered);
                return Err(fail_boot_with_owned_daemon(
                    boot,
                    &mut daemon,
                    Some(&attached.client),
                    error,
                    "starting the session on the newly started runtime failed",
                )
                .await);
            }

            let retry = boot
                .drive(attached.client.call_with_timeout(
                    &method,
                    params.clone(),
                    ui::app::START_TIMEOUT,
                ))
                .await;

            match retry {
                Ok(started) => started,
                Err(retry_error) => {
                    let retry_failure = start_failure(&retry_error);
                    let error = anyhow!(
                        "{}",
                        start_outcome_unknown(
                            &method,
                            &session_id,
                            &first_failure.rendered,
                            &retry_failure.rendered,
                            retry_failure.outcome_unknown,
                        )
                    );

                    return Err(fail_boot_with_owned_daemon(
                        boot,
                        &mut daemon,
                        Some(&attached.client),
                        error,
                        "starting the session on the newly started runtime remained ambiguous",
                    )
                    .await);
                }
            }
        }
    };

    let Some(started) = StartedRef::decode(&started) else {
        let error = anyhow!(
            "the runtime answered client session {session_id} with a reference this build cannot \
                 read: {started}"
        );

        return Err(fail_boot_with_owned_daemon(
            boot,
            &mut daemon,
            Some(&attached.client),
            error,
            "the newly started runtime returned an unreadable session reference",
        )
        .await);
    };

    if started.id != session_id {
        let error = anyhow!(
            "the runtime answered client session {session_id} with a different session id {}; \
             refusing to send a message because the start identity contract was violated",
            started.id
        );

        return Err(fail_boot_with_owned_daemon(
            boot,
            &mut daemon,
            Some(&attached.client),
            error,
            "the newly started runtime returned the wrong session reference",
        )
        .await);
    }

    progress.report(BootEvent::SessionStarted {
        id: started.id.clone(),
    });

    // On a screen the id is on the boot panel, in the notice line, and on the Sessions
    // tab; printing it into the alternate buffer would only overwrite a frame with it.
    if !boot.on_screen() {
        println!("{}", started.id);
    }

    let created_start_failure = created_start_failure_handoff(&started, message.as_deref());
    let mut first_message_reconciliation = None;
    let mut print_message_failure = if print {
        created_start_failure
            .as_ref()
            .map(|failure| failure.notice.clone())
    } else {
        None
    };
    let mut first_message_accepted = false;

    if let (None, Some(message)) = (started.start_failure.as_ref(), message) {
        // `interactive.start` waits for provider readiness before it answers, so the
        // session is ready to take this by the time it is sent. The session id was minted
        // by this client before start: if the reply is lost after dispatch, every
        // reconciliation or deliberate retry names the same logical session and turn.
        let turn_id = format!("ouro-first:{}", started.id);
        let sent = attached
            .client
            .call(
                "interactive.send_message",
                first_message_params(&started, &message, &turn_id),
            )
            .await;

        let failure = match &sent {
            Ok(value) => successful_first_message_failure(value),
            Err(error) => Some(first_message_failure(error)),
        };
        first_message_accepted = failure.is_none();

        if let Some(failure) = failure {
            if failure.outcome_unknown {
                if print {
                    // There is no UI subscription in `--print` mode. Use the one safe
                    // recovery action available here: replay the exact mutation under the
                    // same caller-owned id. The runtime accepts it only if the original
                    // request never arrived, reports a now-known dispatch, or leaves the
                    // checkpointed uncertain intent outcome-unknown without redispatching.
                    let retry = attached
                        .client
                        .call(
                            "interactive.send_message",
                            first_message_params(&started, &message, &turn_id),
                        )
                        .await;

                    match retry {
                        Ok(value) => match successful_first_message_failure(&value) {
                            None => first_message_accepted = true,
                            Some(retry) if retry.outcome_unknown => {
                                print_message_failure = Some(print_outcome_unknown(
                                    &started.id,
                                    &turn_id,
                                    &failure.rendered,
                                    &retry.rendered,
                                ));
                            }
                            Some(retry) => {
                                print_message_failure = Some(print_turn_rejected(
                                    &started.id,
                                    &turn_id,
                                    &retry.rendered,
                                ));
                            }
                        },
                        Err(retry_error) => {
                            // A refusal to this reconciliation call does not prove what
                            // happened to the first call. Only a same-id durable turn read
                            // above can turn the unknown outcome into a known terminal one.
                            let retry = first_message_failure(&retry_error);
                            print_message_failure = Some(print_outcome_unknown(
                                &started.id,
                                &turn_id,
                                &failure.rendered,
                                &retry.rendered,
                            ));
                        }
                    }
                } else {
                    first_message_reconciliation = Some(FirstMessageReconciliation {
                        id: started.id.clone(),
                        input: message,
                        turn_id: turn_id.clone(),
                        notice: format!(
                            "first message outcome unknown; retrying the same turn id \
                             {turn_id} while attached: {}",
                            failure.rendered
                        ),
                    });
                }
            } else {
                let error = anyhow!(
                    "the session started but the message was not accepted: {}",
                    failure.rendered
                );

                return Err(fail_boot_with_owned_daemon(
                    boot,
                    &mut daemon,
                    Some(&attached.client),
                    error,
                    "the first message failed on the newly started runtime",
                )
                .await);
            }
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

        if let Some(failure) = print_message_failure {
            return Err(anyhow!(failure));
        }

        return Ok(());
    }

    run_ui(
        address,
        mode,
        daemon,
        attached,
        channel,
        Some((Plane::Interactive, started.id, started.node)),
        boot.finish(),
        Local {
            data_dir: Some(paths.data_dir.display().to_string()),
            config,
            open_machines: false,
            add_log: Vec::new(),
            add_recipe: None,
        },
        created_start_failure,
        first_message_reconciliation,
        first_message_accepted,
    )
    .await
}

/// `ouro run`: the session `ouro new` starts, streamed to a pipe instead of to a screen.
///
/// This function is the seam and nothing else. Every refusal it can make happens *before*
/// a runtime is started — a prompt with no provider must not leave a daemon behind it —
/// and everything from `interactive.start` onwards belongs to [`ouro::run::drive`], which
/// the integration tests drive against a scripted gateway without any of this.
async fn run_prompt(paths: &Paths, dev: bool, config: Loaded, args: RunArgs) -> Result<()> {
    let options = ouro::run::Options {
        output: if args.stream_json {
            ouro::run::Output::StreamJson
        } else if args.json {
            ouro::run::Output::Json
        } else {
            ouro::run::Output::Text
        },
        approve_all: args.approve_all,
        timeout: Duration::from_secs(args.timeout),
        verbose: args.verbose,
    };

    if args.timeout == 0 {
        return Err(refuse_run(
            &options,
            "--timeout 0 has no meaning here: a run with no ceiling is the hang this \
             command exists to prevent",
        ));
    }

    let prompt = args.prompt.trim().to_string();

    if prompt.is_empty() {
        return Err(refuse_run(
            &options,
            "the prompt is empty; `ouro run` has nothing to send",
        ));
    }

    for problem in &config.problems {
        eprintln!("ouro run: {problem}");
    }

    let plan = match args.resume.as_deref().map(str::trim) {
        Some(id) if !id.is_empty() => ouro::run::Plan::Resume {
            session_id: id.to_string(),
            prompt,
        },
        Some(_blank) => {
            return Err(refuse_run(&options, "--resume needs a session id"));
        }
        None => {
            let flags = StartFlags {
                provider: args.provider,
                workspace: args.workspace.map(workspace_argument).transpose()?,
                approval_mode: args.approval_mode,
                sandbox_mode: args.sandbox_mode,
                machine: args.machine,
            };

            let plan = ouro::run::start_plan(
                &flags,
                &config.config.defaults,
                &config.path,
                new_client_session_id()?,
                |machine, workspace| {
                    start_workspace(machine, workspace).map_err(|error| format!("{error:#}"))
                },
                prompt,
            );

            match plan {
                Ok(plan) => plan,
                Err(refusal) => return Err(refuse_run(&options, &refusal.to_string())),
            }
        }
    };

    // A silent sink for the machinery `ouro new` reports its boot through. The lines exist
    // and are read back below; what they must never do is land on stdout, which here is a
    // contract rather than a place to talk.
    let boot = Arc::new(std::sync::Mutex::new(BootProgress::new()));
    let progress = Progress::Screen(boot.clone());

    let (address, token, mut daemon) = if args.addr.is_some() || args.token_file.is_some() {
        let (address, token) = remote_endpoint(paths, args.addr, args.token_file).await?;
        (address, token, None)
    } else {
        paths.ensure_private_data_dir()?;
        let (publication, token, daemon) = local_runtime(paths, dev, &progress).await?;
        (local_address(publication.port), token, daemon)
    };

    report_boot(&boot, args.verbose);

    let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);
    // Reconnect stays off deliberately. A silent re-handshake would drop this run's
    // subscription and leave it waiting out its whole `--timeout` on a stream that is
    // never coming back; a closed connection is instead an observable `lost`.
    let attached = match attach_with(address, token, false, hook).await {
        Ok(attached) => attached,
        Err(error) => {
            return Err(clean_up_owned_daemon_after_error(
                &mut daemon,
                error,
                "connecting to the newly started runtime failed",
            )
            .await)
        }
    };

    let Connected {
        client,
        hello,
        mut notifications,
    } = attached;

    let report = {
        let mut out = std::io::stdout().lock();
        let mut err = std::io::stderr().lock();
        let mut sinks = ouro::run::Sinks {
            out: &mut out,
            err: &mut err,
        };

        ouro::run::drive(
            &client,
            &mut notifications,
            &hello,
            plan,
            &options,
            &mut sinks,
        )
        .await
    };

    client.stop().await;

    // The session outlives this process only if the runtime does, and `ouro run` is a
    // command a script calls repeatedly: tearing the daemon down between prompts would
    // make every one of them pay a cold start.
    if let Some(daemon) = daemon.as_mut() {
        let pid = daemon.pid();
        daemon.detach();
        eprintln!("the runtime is still running (pid {pid}); `ouro` attaches to it");
    }

    match report {
        Ok(report) if report.status == ouro::run::Status::Completed => Ok(()),
        Ok(report) => Err(anyhow!(report.exit())),
        Err(refusal) => Err(refuse_run(&options, &refusal.to_string())),
    }
}

/// A refusal: the sentence on stderr, the object on stdout where stdout is JSON, and the
/// documented usage code. Nothing ran, so there is no result object to print.
fn refuse_run(options: &ouro::run::Options, message: &str) -> anyhow::Error {
    eprintln!("ouro run: {message}");

    if matches!(
        options.output,
        ouro::run::Output::Json | ouro::run::Output::StreamJson
    ) {
        let refusal = ouro::run::Refusal(message.to_string());

        if let Ok(line) = serde_json::to_string(&refusal.to_json()) {
            println!("{line}");
        }
    }

    anyhow!(ouro::run::Exit::USAGE)
}

/// The boot's own lines, on stderr where a headless command's progress belongs.
///
/// Warnings are unconditional because they are about this host — an overridden data
/// directory, a protocol skew — and a script that never sees them debugs the wrong thing.
fn report_boot(boot: &Arc<std::sync::Mutex<BootProgress>>, verbose: bool) {
    let Ok(mut boot) = boot.lock() else {
        return;
    };

    boot.settle();

    for warning in boot.warnings() {
        eprintln!("ouro run: {warning}");
    }

    if verbose {
        for step in boot.steps() {
            eprintln!("ouro run: {}", step.label);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn fleet_add_command(
    paths: &Paths,
    target: Option<String>,
    machine: Option<String>,
    host: Option<String>,
    via: String,
    binary: Option<PathBuf>,
    print_script: bool,
    init: bool,
    owner_host: Option<String>,
    owner_machine: Option<String>,
) -> Result<()> {
    // Argument shape is settled before any state changes: a named target means SSH and
    // --print-script means no SSH, so together they are refused rather than silently
    // narrowed.
    match target.as_deref() {
        Some(target) if print_script => bail!(
            "--print-script does not use TARGET; drop --print-script to run `{target}` over SSH, or omit the target to only write the invitation"
        ),
        None if !print_script => bail!(
            "name the destination as `ouro fleet add user@host`, or pass `--print-script --machine NAME --host HOST` to enroll it yourself. `ouro fleet list` shows Tailscale and SSH hosts this Mac already knows"
        ),
        _ => {}
    }

    if init && fleet::load(&paths.data_dir)?.is_none() {
        let owner_host = owner_host.as_deref().ok_or_else(|| {
            anyhow!(
                "`ouro fleet add --init` needs --owner-host with this Mac's Tailscale MagicDNS name or private IPv4 address"
            )
        })?;
        let identity = fleet::resolve_identity(owner_machine.as_deref(), Some(owner_host))?;
        fleet::create(
            &paths.data_dir,
            None,
            &identity.machine,
            &identity.host,
            fleet::Ports::DEFAULT,
        )?;
        println!(
            "Created this Mac as fleet owner `{machine}` at {host}.",
            machine = identity.machine,
            host = identity.host
        );
    }

    let owner_host = fleet::load(&paths.data_dir)?
        .map(|profile| profile.host)
        .or(owner_host);

    if print_script || target.is_none() {
        let machine = machine.ok_or_else(|| {
            anyhow!("`--machine NAME` is required when printing an enroll script")
        })?;
        let host = host
            .ok_or_else(|| anyhow!("`--host HOST` is required when printing an enroll script"))?;
        let outcome = fleet_add::prepare(&paths.data_dir, &machine, &host, owner_host.as_deref())?;
        print!("{}", fleet_add::render_outcome(&outcome));
        return Ok(());
    }

    let target = target.expect("target is present when not printing a script");
    let via = fleet_add::Via::parse(&via)?;
    let outcome = fleet_add::add(
        &paths.data_dir,
        &target,
        machine.as_deref(),
        host.as_deref(),
        via,
        binary.as_deref(),
        owner_host.as_deref(),
    )?;
    print!("{}", fleet_add::render_outcome(&outcome));
    Ok(())
}

async fn fleet_enroll_command(
    paths: &Paths,
    invitation: PathBuf,
    delete: bool,
    service: bool,
    ports: fleet::Ports,
) -> Result<()> {
    fleet_add::enroll_preflight(&invitation)?;
    let profile = fleet::join(&paths.data_dir, &invitation, ports)?;
    println!(
        "Joined fleet {} as {} at {}.",
        profile.name, profile.machine, profile.host
    );
    if delete {
        fs::remove_file(&invitation).with_context(|| {
            format!(
                "joined, but could not delete invitation {}",
                invitation.display()
            )
        })?;
    }
    if service {
        match fleet::service_install(&paths.data_dir) {
            Ok(installed) => {
                println!(
                    "Recovery unit written at {}.\nActivate with:\n  {}\n",
                    installed.path.display(),
                    installed.activation
                );
            }
            Err(error) => {
                println!(
                    "joined, but recovery was not installed: {error:#}\nRun `ouro fleet service install` after this daemon is healthy."
                );
            }
        }
    }
    daemon(paths, false).await
}

async fn fleet_command(paths: &Paths, dev: bool, command: FleetCommand) -> Result<()> {
    paths.ensure_private_data_dir()?;

    match command {
        FleetCommand::Create {
            name,
            machine,
            host,
            gateway_port,
            dist_port,
        } => {
            if dev {
                bail!(
                    "`ouro --dev fleet create` is not supported: secure fleet startup requires the packaged release boot path. Run `ouro fleet create` with the packaged binary; development runtimes should use a separate standalone data directory"
                );
            }
            let identity = fleet::resolve_identity(machine.as_deref(), host.as_deref())?;
            let profile = fleet::create(
                &paths.data_dir,
                name.as_deref(),
                &identity.machine,
                &identity.host,
                fleet::Ports {
                    gateway: gateway_port,
                    dist: dist_port,
                },
            )?;
            let address_note = if fleet::host_is_local_only(&profile.host) {
                "\n  note         loopback is local-only; use a Tailscale/private IPv4 name on separate machines"
            } else {
                ""
            };
            println!(
                "Fleet created securely.\n  fleet        {}\n  machine      {}\n  address      {}{}\n  transport    TLS\n  profile      {}\n\nNext:\n  1. Verify the local interface and credentials: `ouro fleet doctor`\n  2. Start this machine: `ouro daemon`\n  3. Verify the live runtime: `ouro fleet doctor`\n  4. Add another from this machine: `ouro fleet add user@host --machine NAME --host HOST`\n  5. If SSH is unavailable, `ouro fleet add --print-script --machine NAME --host HOST` then run the printed enroll command there\n\nAllow TCP {} (this fleet's EPMD port) and {}..{} only between private fleet addresses; do not open the gateway port, which remains loopback-only. Ouroboros requests the advertised private IPv4 interface for EPMD, pins TLS distribution to it, and doctor checks an incumbent EPMD is not listening on another local IPv4 interface.\n\nThis machine is the fleet's sole invitation/roster authority. Back up {} securely; automatic service recovery does not protect against disk loss. For optional login/crash recovery, run `ouro fleet service install` and follow its activation step.",
                profile.name,
                profile.machine,
                profile.host,
                address_note,
                fleet::profile_path(&paths.data_dir).display(),
                profile.epmd_port,
                profile.dist_port_min,
                profile.dist_port_max,
                fleet::fleet_dir(&paths.data_dir).display()
            );
            Ok(())
        }
        FleetCommand::List => {
            print!(
                "{}",
                fleet_add::render_list(&fleet_add::discover_candidates())
            );
            Ok(())
        }
        FleetCommand::Add {
            target,
            machine,
            host,
            via,
            binary,
            print_script,
            init,
            owner_host,
            owner_machine,
        } => {
            if dev {
                bail!("fleet add belongs to the packaged runtime data directory; omit --dev");
            }
            fleet_add_command(
                paths,
                target,
                machine,
                host,
                via,
                binary,
                print_script,
                init,
                owner_host,
                owner_machine,
            )
            .await
        }
        FleetCommand::Enroll {
            invitation,
            delete,
            service,
            gateway_port,
            dist_port,
        } => {
            if dev {
                bail!("fleet enroll belongs to the packaged runtime; omit --dev");
            }
            fleet_enroll_command(
                paths,
                invitation,
                delete,
                service,
                fleet::Ports {
                    gateway: gateway_port,
                    dist: dist_port,
                },
            )
            .await
        }
        FleetCommand::Invite {
            command,
            machine,
            host,
            out,
            gateway_port,
            dist_port,
            replace,
        } => {
            if dev {
                bail!(
                    "fleet invitations belong to the packaged runtime data directory; omit --dev"
                );
            }
            if let Some(InviteCommand::Cancel {
                machine: cancel_machine,
                out: roster_output,
            }) = command
            {
                if machine.is_some()
                    || host.is_some()
                    || out.is_some()
                    || gateway_port.is_some()
                    || dist_port.is_some()
                    || replace
                {
                    bail!(
                        "`ouro fleet invite cancel` accepts only --machine NAME and --out ROSTER; invitation creation flags cannot be mixed with cancellation"
                    );
                }
                let (removed, revision) =
                    fleet::cancel_invite(&paths.data_dir, &cancel_machine, &roster_output)?;
                let roster_arg = fleet::shell_quote_path(&roster_output)?;
                println!(
                    "Stopped expecting invitation for {} ({}).\n  roster       revision {} in {} (mode 0600)\n\nExisting fleet machines still have their older saved seed list. Copy this roster privately to each one. On every recipient:\n  1. `chmod 600 {}`\n  2. Run `ouro fleet service status`. If a recovery unit is installed, run the exact deactivation command it prints; otherwise run `ouro stop`.\n  3. `ouro fleet sync import {}`\n  4. If it had a recovery unit, run the exact activation command from service status; otherwise run `ouro daemon`.\n  5. `ouro fleet doctor`\n\nThis owner already saved the new roster but also loads seed topology only at boot; restart it with the same service-aware stop/start flow when convenient (no import needed). This update does NOT revoke any copied invitation, certificate, or shared cookie. A leaked invitation compromises the fleet until whole-fleet credential rotation: deactivate/remove recovery on every machine, leave them, recreate the fleet, and issue fresh invitations.",
                    removed.machine,
                    removed.node,
                    revision,
                    roster_output.display(),
                    roster_arg,
                    roster_arg
                );
                println!(
                    "\nOffline session-owner evidence for {} is deliberately preserved on every machine. Only after the signed roster is installed and each runtime restarted, if you knowingly accept that its offline sessions may become undiscoverable, run this locally on every remaining machine:\n  ouro fleet sessions forget --machine {} --accept-state-loss\nThis is irreversible per machine and does not revoke credentials or delete the removed machine's journals.",
                    removed.machine, removed.machine
                );
                return Ok(());
            }
            let machine = machine.ok_or_else(|| {
                anyhow!("`ouro fleet invite` requires --machine NAME (or use `ouro fleet invite cancel --machine NAME`)")
            })?;
            let host = host.ok_or_else(|| {
                anyhow!("`ouro fleet invite` requires --host HOST for the new machine")
            })?;
            let out = out.ok_or_else(|| {
                anyhow!("`ouro fleet invite` requires --out FILE for the private invitation")
            })?;
            let member = fleet::invite_with_replace(
                &paths.data_dir,
                &machine,
                &host,
                &out,
                fleet::Ports {
                    gateway: gateway_port,
                    dist: dist_port,
                },
                replace,
            )?;
            let invitation_arg = fleet::shell_quote_path(&out)?;
            let address_note = if fleet::host_is_local_only(&member.host) {
                "\n  note         loopback is local-only; this invitation is for a same-host lab"
            } else {
                ""
            };
            let replacement_note = if replace {
                "\n  replacement  reissued for the same identity; this does NOT revoke an old copied credential"
            } else {
                ""
            };
            println!(
                "Private invitation created.\n  machine      {}\n  address      {}{}{}\n  invitation   {} (mode 0600)\n\nCopy it through a private channel. Copy tools may widen permissions; on the receiving machine run:\n  chmod 600 {}\n  ouro fleet join {}\n\nAfter it joins, delete the copied invitation from both machines. Its contents are secret and were not printed. The seven-day wrapper-age check prevents stale setup mistakes, but an already copied credential remains usable material; a leak requires whole-fleet credential rotation.",
                member.machine,
                member.host,
                address_note,
                replacement_note,
                out.display(),
                invitation_arg,
                invitation_arg
            );
            Ok(())
        }
        FleetCommand::Join {
            invitation,
            gateway_port,
            dist_port,
        } => {
            if dev {
                bail!(
                    "`ouro --dev fleet join` is not supported: secure fleet startup requires the packaged release. Run `ouro fleet join INVITE` without --dev"
                );
            }
            let profile = fleet::join(
                &paths.data_dir,
                &invitation,
                fleet::Ports {
                    gateway: gateway_port,
                    dist: dist_port,
                },
            )?;
            let address_note = if fleet::host_is_local_only(&profile.host) {
                " Loopback makes this a same-host lab; use a reachable private IPv4 name for separate machines."
            } else {
                ""
            };
            println!(
                "Joined {} securely.\n  machine      {}\n  address      {}\n  expects      {} other machine{}\n  transport    TLS\n\nNext: run `ouro fleet doctor` to verify the local private interface, then `ouro daemon`, then `ouro fleet doctor` again for live connectivity. Ouroboros will keep retrying any machine that is offline.{} For optional login/crash recovery, run `ouro fleet service install` and follow its activation step. Delete {} after confirming this profile; the invitation contains secrets.",
                profile.name,
                profile.machine,
                profile.host,
                profile.expected_peers(),
                if profile.expected_peers() == 1 { "" } else { "s" },
                address_note,
                invitation.display()
            );
            Ok(())
        }
        FleetCommand::Status => {
            let mut rendered = None;
            if let Some(publication) = runtime::read_live_publication(&paths.data_dir)? {
                let query = async {
                    let token = runtime::read_token(&paths.token_file())?;
                    let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);
                    let attached = attach_with(local_address(publication.port), token, false, hook)
                        .await
                        .context("connecting to the local runtime")?;
                    let result = attached
                        .client
                        .call_with_timeout("fleet.status", json!({}), Duration::from_secs(5))
                        .await
                        .context("calling fleet.status");
                    attached.client.stop().await;
                    result
                }
                .await;
                match query {
                    Ok(value) => rendered = fleet::render_live_status(&paths.data_dir, &value),
                    Err(error) => eprintln!(
                        "ouro: live fleet details are temporarily unavailable ({error}); showing this machine's saved profile"
                    ),
                }
            }
            print!(
                "{}",
                rendered.unwrap_or(fleet::render_status(&paths.data_dir)?)
            );
            Ok(())
        }
        FleetCommand::Doctor => {
            let local = fleet::doctor(&paths.data_dir);
            let report = if let Some(publication) = runtime::read_live_publication(&paths.data_dir)?
            {
                let query = async {
                    let token = runtime::read_token(&paths.token_file())?;
                    let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);
                    let attached = attach_with(local_address(publication.port), token, false, hook)
                        .await
                        .context("connecting to the local runtime")?;
                    let result = attached
                        .client
                        .call_with_timeout("fleet.doctor", json!({}), Duration::from_secs(5))
                        .await
                        .context("calling fleet.doctor");
                    attached.client.stop().await;
                    result
                }
                .await;
                match query {
                    Ok(value) => fleet::merge_live_doctor(local, &value),
                    Err(error) => fleet::doctor_live_unavailable(local, format!("{error:#}")),
                }
            } else {
                fleet::doctor_stopped(local)
            };
            print!("{}", report.text);
            if report.healthy {
                Ok(())
            } else {
                bail!("fleet doctor found setup problems")
            }
        }
        FleetCommand::Sync { command } => match command {
            SyncCommand::Export { out } => {
                let revision = fleet::export_roster(&paths.data_dir, &out)?;
                let roster_arg = fleet::shell_quote_path(&out)?;
                println!(
                    "Signed fleet roster exported.\n  revision     {}\n  roster       {} (mode 0600)\n\nCopy it privately to existing fleet machines. On each recipient:\n  1. `chmod 600 {}`\n  2. Run `ouro fleet service status`. If a recovery unit is installed, run the exact deactivation command it prints; otherwise run `ouro stop`.\n  3. `ouro fleet sync import {}`\n  4. If it had a recovery unit, run the exact activation command from service status; otherwise run `ouro daemon`.\n  5. `ouro fleet doctor`\n\nThe roster contains no cookie or private key, but machine topology remains private and its CA attestation must not be replaced.",
                    revision,
                    out.display(),
                    roster_arg,
                    roster_arg
                );
                Ok(())
            }
            SyncCommand::Import { roster } => {
                let imported = fleet::import_roster(&paths.data_dir, &roster)?;
                if imported.changed {
                    let forget_commands = imported
                        .removed
                        .iter()
                        .map(|member| {
                            format!(
                                "  ouro fleet sessions forget --machine {} --accept-state-loss",
                                member.machine
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    let removed = imported
                        .removed
                        .iter()
                        .map(|member| member.machine.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!(
                        "Signed fleet roster installed.\n  revision     {} → {}\n  expected     {} machine{}\n  removed      {}\n\nNext: if you deactivated a recovery unit, run its exact activation command from `ouro fleet service status`; otherwise run `ouro daemon`. Then run `ouro fleet doctor`. Delete the copied roster after every intended machine imports it.",
                        imported.previous_revision,
                        imported.revision,
                        imported.members,
                        if imported.members == 1 { "" } else { "s" },
                        if removed.is_empty() { "none" } else { &removed }
                    );
                    if !forget_commands.is_empty() {
                        println!(
                            "\nOffline session-owner evidence for removed machines is still preserved locally. After this runtime restarts, only if you explicitly accept losing that offline discovery evidence, run the matching command below on every remaining fleet machine:\n{}\nThis is irreversible per machine; skip it while you may need to recover or find sessions from a removed owner.",
                            forget_commands
                        );
                    }
                } else {
                    println!(
                        "Roster revision {} is already installed; no profile field changed.",
                        imported.revision
                    );
                }
                Ok(())
            }
        },
        FleetCommand::Sessions { command } => match command {
            SessionsCommand::Forget {
                machine,
                accept_state_loss,
            } => {
                if dev {
                    bail!(
                        "fleet session-owner evidence belongs to the packaged runtime; omit --dev and run this command on each remaining fleet machine"
                    );
                }
                if !accept_state_loss {
                    bail!(
                        "refusing irreversible session-owner evidence loss without --accept-state-loss"
                    );
                }
                let publication = runtime::read_live_publication(&paths.data_dir)?
                    .ok_or_else(|| {
                        anyhow!(
                            "this machine's fleet runtime is not running. Start its recovery service or run `ouro daemon`, wait for `ouro fleet doctor`, then retry; no session-owner evidence was changed"
                        )
                    })?;
                let token = runtime::read_token(&paths.token_file())?;
                let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);
                let attached = attach_with(local_address(publication.port), token, false, hook)
                    .await
                    .context("connecting to this machine's local runtime")?;
                let result = attached
                    .client
                    .call_with_timeout(
                        "fleet.forget_session_owner",
                        forget_session_owner_params(&machine),
                        Duration::from_secs(5),
                    )
                    .await
                    .context("calling fleet.forget_session_owner");
                attached.client.stop().await;
                let result = result?;
                let (result_machine, node, roster_revision) =
                    parse_forget_session_owner_result(&machine, &result)?;
                println!(
                    "Session-owner evidence permanently forgotten on this machine.\n  machine      {}\n  node         {}\n  roster       revision {}\n\nState loss was explicitly accepted: sessions discoverable only through this machine's saved evidence for {} may now be unavailable while that former owner is offline. This changed only the local evidence checkpoint; it did not delete journals on the removed machine and did not revoke fleet credentials. Repeat this exact command on every remaining fleet machine after each has imported the signed roster and restarted.",
                    result_machine, node, roster_revision, result_machine
                );
                Ok(())
            }
        },
        FleetCommand::Leave {
            discard_incomplete,
            machine,
        } => {
            let fleet_exists = fleet::fleet_dir(&paths.data_dir)
                .try_exists()
                .context("inspecting the fleet directory before leave")?;
            let epmd_program = if fleet_exists {
                if dev {
                    bail!(
                        "`ouro --dev fleet leave` cannot safely retire a packaged fleet EPMD. Run `ouro fleet leave` with the packaged binary; no profile or daemon was changed"
                    );
                }
                let launcher = launcher(false, paths).await?;
                Some(launcher.packaged_epmd_program()?.ok_or_else(|| {
                    anyhow!("the packaged release did not expose its EPMD control binary")
                })?)
            } else {
                None
            };
            let removed = if discard_incomplete {
                let machine = machine.as_deref().ok_or_else(|| {
                    anyhow!("--discard-incomplete requires --machine NAME so the recovery unit can be checked")
                })?;
                match epmd_program.as_deref() {
                    Some(epmd) => {
                        fleet::discard_incomplete_with_epmd(&paths.data_dir, machine, epmd)?
                    }
                    None => fleet::discard_incomplete(&paths.data_dir, machine)?,
                }
            } else {
                match epmd_program.as_deref() {
                    Some(epmd) => fleet::leave_with_epmd(&paths.data_dir, epmd)?,
                    None => fleet::leave(&paths.data_dir)?,
                }
            };
            if removed {
                println!(
                    "Fleet credentials removed from this stopped machine. The rest of the fleet was not changed.\n\nThis machine is standalone again. To rejoin it, create a fresh invitation on the fleet owner."
                );
            } else {
                println!(
                    "This machine is already standalone; there was no fleet profile to remove."
                );
            }
            Ok(())
        }
        FleetCommand::Service { command } => match command {
            ServiceCommand::Install => {
                if dev {
                    bail!("recovery services require the packaged ouro; omit --dev");
                }
                let service = fleet::service_install(&paths.data_dir)?;
                let recovery = match service.kind {
                    fleet::ServiceKind::Launchd => {
                        "Once activated, launchd starts Ouroboros in this user's login session and restarts it after a crash."
                    }
                    fleet::ServiceKind::SystemdUser => {
                        "Once activated, systemd restarts Ouroboros after a crash and starts it after this user logs in. For optional pre-login boot, run `loginctl enable-linger \"$USER\"`; `ouro fleet service status` reports the boundary."
                    }
                };
                println!(
                    "{}\n  manager      {}\n  unit         {}\n\nThe unit was not started behind your back. It preserves this shell's absolute PATH, whitelisted provider CLI paths, admitted workspace roots, Codex network policy, and validated gateway frame/queue bounds, but copies no API keys or arbitrary environment variables; HOME remains owned by the user service manager. Activate it with:\n  {}\n\nThen verify it with:\n  `ouro fleet service status`\n\nTo deactivate it later:\n  {}\n\n{} If `ouro daemon` is already running, the service waits and takes over only after that process stops—never a duplicate. No fleet secret is stored in the unit.",
                    if service.installed {
                        "Fleet recovery service installed."
                    } else {
                        "Fleet recovery service is already installed with the expected contents."
                    },
                    service.kind.label(),
                    service.path.display(),
                    service.activation,
                    service.deactivation,
                    recovery
                );
                Ok(())
            }
            ServiceCommand::Status => {
                print!("{}", fleet::render_service_status(&paths.data_dir)?);
                Ok(())
            }
            ServiceCommand::Remove => match fleet::service_remove(&paths.data_dir)? {
                Some(path) => {
                    println!(
                        "Removed the inactive fleet recovery unit {}. Fleet credentials and runtime data were not changed.",
                        path.display()
                    );
                    Ok(())
                }
                None => {
                    println!("No generated recovery unit was installed for this machine.");
                    Ok(())
                }
            },
        },
    }
}

fn forget_session_owner_params(machine: &str) -> Value {
    json!({
        "machine": machine,
        "accept_state_loss": true,
    })
}

fn parse_forget_session_owner_result<'a>(
    requested_machine: &str,
    result: &'a Value,
) -> Result<(&'a str, &'a str, u64)> {
    let result_machine = result
        .get("machine")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("gateway success omitted the forgotten machine"))?;
    let node = result
        .get("node")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("gateway success omitted the forgotten owner node"))?;
    let roster_revision = result
        .get("roster_revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("gateway success omitted the roster revision"))?;
    if result_machine != requested_machine {
        bail!(
            "gateway confirmed session-owner loss for `{result_machine}` instead of requested `{requested_machine}`; inspect `ouro fleet doctor` before retrying anything"
        );
    }
    Ok((result_machine, node, roster_revision))
}

/// Foreground ownership bridge for launchd/systemd. The generated unit points here, not
/// at `ouro daemon`: daemon intentionally detaches, which would make a service manager
/// think it exited and start duplicates. This command lives as long as its BEAM child,
/// forwards termination, and lets the manager's restart policy perform recovery.
async fn service_run(paths: &Paths, dev: bool) -> Result<()> {
    if dev {
        bail!("service-run only supports the packaged runtime");
    }
    paths.ensure_private_data_dir()?;
    if fleet::load(&paths.data_dir)?.is_none() {
        bail!("service-run requires a fleet profile; run `ouro fleet create` or `ouro fleet join` first");
    }
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing the service termination handler")?;
    let mut waiting_for = None;
    loop {
        let live_publication = live_publication_to_adopt(paths)?.map(|publication| publication.pid);
        let live_owner = runtime::read_live_runtime_owner(&paths.data_dir)?.map(|owner| owner.pid);
        let Some(pid) = live_publication.or(live_owner) else {
            break;
        };
        if waiting_for != Some(pid) {
            eprintln!(
                "ouro service: runtime pid {pid} already owns {}; waiting to take over after it stops",
                paths.data_dir.display()
            );
            waiting_for = Some(pid);
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = terminate.recv() => return Ok(()),
            interrupt = tokio::signal::ctrl_c() => {
                interrupt.context("waiting for the service interrupt signal")?;
                return Ok(());
            }
        }
    }

    let (_publication, _token, child) = start(
        paths,
        false,
        Output::File(paths.daemon_log()),
        &Progress::Plain,
        StartRequirement::Fleet,
    )
    .await?;
    let mut daemon = child.ok_or_else(|| {
        anyhow!("a runtime appeared while service-run was starting; refusing to supervise a process it did not create")
    })?;

    tokio::select! {
        status = daemon.wait() => {
            let status = status?;
            if !status.success() {
                bail!("the runtime exited with {status}; the service manager will restart it");
            }
        }
        _ = terminate.recv() => {
            daemon.terminate(SHUTDOWN_GRACE).await?;
        }
        interrupt = tokio::signal::ctrl_c() => {
            interrupt.context("waiting for the service interrupt signal")?;
            daemon.terminate(SHUTDOWN_GRACE).await?;
        }
    }
    Ok(())
}

struct FirstMessageReconciliation {
    id: String,
    input: String,
    turn_id: String,
    notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreatedStartFailure {
    id: String,
    input: Option<String>,
    notice: String,
}

struct FirstMessageFailure {
    rendered: String,
    outcome_unknown: bool,
}

struct StartFailure {
    rendered: String,
    outcome_unknown: bool,
}

fn created_start_failure_handoff(
    started: &StartedRef,
    input: Option<&str>,
) -> Option<CreatedStartFailure> {
    let failure = started.start_failure.as_deref()?;
    let draft = input.map(str::to_string);
    let draft_status = if draft.is_some() {
        " The requested first message was not dispatched and is restored in the composer."
    } else {
        ""
    };

    Some(CreatedStartFailure {
        id: started.id.clone(),
        input: draft,
        notice: format!(
            "created durable session {}, but it did not become ready: {failure}.{draft_status}",
            started.id
        ),
    })
}

/// Add the identity `ouro new` will use for both the first start and any reconciliation.
///
/// The shared [`StartRequest`] owns the id as part of its wire contract. This CLI boundary
/// verifies that the pre-mutation id survived validation unchanged before it permits the
/// one exact same-request retry below.
fn cli_start_params(request: &StartRequest, session_id: &str) -> Result<Value> {
    if session_id.trim().is_empty() {
        bail!("the client-generated session id was empty");
    }

    if request.id != session_id {
        bail!("the CLI session id and validated start request disagree");
    }
    let params = request
        .params()
        .map_err(|refusal| anyhow!("{}", refusal.message()))?;
    if params.get("id").and_then(Value::as_str) != Some(session_id) {
        bail!("the validated start request did not preserve its stable session id");
    }
    Ok(params)
}

fn new_client_session_id() -> Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0_u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|error| anyhow!("the operating system could not mint a session id: {error}"))?;

    let mut id = String::with_capacity("ouro-cli-".len() + random.len() * 2);
    id.push_str("ouro-cli-");
    for byte in random {
        id.push(HEX[usize::from(byte >> 4)] as char);
        id.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(id)
}

/// Start is a durable mutation. Only a typed RPC decision that did not declare an
/// indeterminate outcome may safely be called a refusal; every transport failure may
/// have happened after the request crossed the gateway boundary.
fn start_failure(error: &ClientError) -> StartFailure {
    match error {
        ClientError::Rpc(rpc) => StartFailure {
            rendered: ouro::model::refusal(rpc),
            outcome_unknown: ouro::model::start_outcome_unknown(error),
        },
        other => StartFailure {
            rendered: other.to_string(),
            outcome_unknown: ouro::model::start_outcome_unknown(error),
        },
    }
}

fn start_outcome_unknown(
    method: &str,
    session_id: &str,
    first_error: &str,
    retry_error: &str,
    retry_unknown: bool,
) -> String {
    let retry_status = if retry_unknown {
        "also had an unknown outcome"
    } else {
        "returned a definite refusal, but cannot prove the first request did not create the session"
    };

    format!(
        "the {method} outcome is unknown for session {session_id}; the exact same-id retry \
         {retry_status}. Run `ouro` and inspect session {session_id} before starting another \
         session. first attempt: {first_error}; retry: {retry_error}"
    )
}

/// Build the mutation that immediately follows `interactive.start`.
///
/// Fleet starts may return a reference owned by another BEAM node. The friendly
/// `machine` selector belongs only on `interactive.start`; every operation on the
/// resulting session must instead carry the returned full owner node. Keeping this in
/// one helper makes the initial call and the same-id print-mode reconciliation identical.
fn first_message_params(started: &StartedRef, input: &str, turn_id: &str) -> Value {
    let mut params = json!({
        "id": started.id,
        "input": input,
        "turn_id": turn_id
    });

    if let (Some(node), Some(fields)) = (started.node.as_deref(), params.as_object_mut()) {
        fields.insert("node".into(), Value::String(node.to_string()));
    }

    params
}

/// A first-message mutation can fail after crossing the dispatch boundary. Typed RPC
/// data decides whether it is safe to call that a refusal; transport failures are also
/// indeterminate because the stable turn id may already have reached the runtime.
fn first_message_failure(error: &ClientError) -> FirstMessageFailure {
    match error {
        ClientError::Rpc(rpc) => FirstMessageFailure {
            rendered: ouro::model::refusal(rpc),
            outcome_unknown: rpc.code == proto::ErrorCode::UpstreamTimeout
                || ouro::model::outcome_unknown(rpc.data.as_ref()),
        },
        other => FirstMessageFailure {
            rendered: other.to_string(),
            outcome_unknown: true,
        },
    }
}

/// A same-id turn read arrives in a successful JSON-RPC envelope even when the durable
/// turn itself is failed or still ambiguous. Classify the turn, not merely the envelope.
fn successful_first_message_failure(value: &Value) -> Option<FirstMessageFailure> {
    match ouro::model::turn_reply(value) {
        ouro::model::TurnReply::Accepted => None,
        ouro::model::TurnReply::OutcomeUnknown => Some(FirstMessageFailure {
            rendered: ouro::model::turn_reply_diagnostic(value),
            outcome_unknown: true,
        }),
        ouro::model::TurnReply::Rejected => Some(FirstMessageFailure {
            rendered: ouro::model::turn_reply_diagnostic(value),
            outcome_unknown: false,
        }),
    }
}

fn print_outcome_unknown(
    session_id: &str,
    turn_id: &str,
    first_error: &str,
    retry_error: &str,
) -> String {
    format!(
        "the first message outcome remains unknown after retrying turn {turn_id}; session \
         {session_id} may still be running it. Run `ouro`, open that session, and inspect \
         its transcript before sending another turn. first attempt: {first_error}; retry: \
         {retry_error}"
    )
}

fn print_turn_rejected(session_id: &str, turn_id: &str, diagnostic: &str) -> String {
    format!(
        "the first message was not accepted: turn {turn_id} in session {session_id} is \
         terminal. Run `ouro`, open that session, and inspect its transcript before deciding \
         whether to send a fresh turn. {diagnostic}"
    )
}

fn absolute(path: PathBuf) -> Result<String> {
    let here = std::env::current_dir().context("reading the working directory")?;

    Ok(runtime::resolve_workspace(&path, &here))
}

fn workspace_argument(path: PathBuf) -> Result<String> {
    path.into_os_string().into_string().map_err(|path| {
        anyhow!(
            "--workspace is not valid UTF-8: {}",
            PathBuf::from(path).display()
        )
    })
}

/// Resolve local paths where the developer typed them, but never reinterpret a remote
/// destination against this caller's filesystem.
fn start_workspace(machine: &str, workspace: Option<&str>) -> Result<String> {
    if machine.trim().is_empty() {
        return match workspace {
            Some(path) => absolute(PathBuf::from(path)),
            None => absolute(PathBuf::from(".")),
        };
    }

    let Some(workspace) = workspace.map(str::trim).filter(|path| !path.is_empty()) else {
        bail!(
            "remote machine `{}` requires `--workspace /absolute/path/on/{}/project`; name the destination path on that machine",
            machine.trim(),
            machine.trim()
        );
    };
    if !Path::new(workspace).is_absolute() {
        bail!(
            "remote machine `{}` cannot use relative workspace `{workspace}`: it would resolve on this caller, not the destination. Pass `--workspace /absolute/path/on/{}/project`",
            machine.trim(),
            machine.trim()
        );
    }
    Ok(workspace.to_string())
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
    report_dev_data_dir_override(paths, dev, progress);

    match live_publication_to_adopt(paths)? {
        Some(publication) => {
            ensure_publication_matches_runtime_owner(paths, &publication)?;

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
        None => start(paths, dev, Output::Ring, progress, StartRequirement::Any).await,
    }
}

/// Pre-lock discovery may decide only whether a live runtime is immediately adoptable.
/// A dead publication remains in place for [`start`]'s locked re-read; removing it here
/// would let a concurrent starter publish between this check and the unlink.
fn live_publication_to_adopt(paths: &Paths) -> Result<Option<Publication>> {
    runtime::read_live_publication(&paths.data_dir)
}

fn report_dev_data_dir_override(paths: &Paths, dev: bool, progress: &Progress) {
    if let Some(warning) = dev_data_dir_override_warning(paths, dev) {
        progress.report(BootEvent::Warning(warning));
    }
}

fn dev_data_dir_override_warning(paths: &Paths, dev: bool) -> Option<String> {
    (dev && paths.data_dir_overridden).then(|| {
        format!(
            "warning: --dev is using the explicit OUROBOROS_DATA_DIR={} exactly; the \
             default ouroboros-dev isolation is disabled, so this command may adopt a \
             release runtime already published there. Use a dedicated directory when \
             isolation is intended",
            paths.data_dir.display()
        )
    })
}

/// `ouro daemon`: start (or find) a runtime, say how to reach it, and exit.
async fn daemon(paths: &Paths, dev: bool) -> Result<()> {
    paths.ensure_private_data_dir()?;
    report_dev_data_dir_override(paths, dev, &Progress::Plain);

    if let Some(publication) = live_publication_to_adopt(paths)? {
        ensure_publication_matches_runtime_owner(paths, &publication)?;

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

    // Plain by construction: `ouro daemon` prints how to reach the runtime and exits, and
    // a screen it would tear down a second later helps nobody.
    let (publication, _token, child) = start(
        paths,
        dev,
        Output::File(paths.daemon_log()),
        &Progress::Plain,
        StartRequirement::Any,
    )
    .await?;

    // Detached: this process is about to exit and the runtime must not go with it. A
    // `None` here is a runtime that appeared under the spawn lock, which nothing owns.
    if let Some(mut child) = child {
        child.detach();
    }

    println!(
        "runtime started\n  port          {}\n  pid           {}\n  node          {}\n  scope         {}\n  token-file    {}\n  runtime-log   {} (live rotation: {} MiB, {} archives)\n  bootstrap-log {} (pre-start rotation: {} MiB, {} backups; raw uninterrupted output can exceed the threshold)",
        publication.port,
        publication.pid,
        publication.node,
        publication.scope,
        paths.token_file().display(),
        paths.runtime_log().display(),
        runtime::RUNTIME_LOG_MAX_BYTES / (1024 * 1024),
        runtime::RUNTIME_LOG_BACKUPS,
        paths.daemon_log().display(),
        runtime::DAEMON_LOG_MAX_BYTES / (1024 * 1024),
        runtime::DAEMON_LOG_BACKUPS
    );

    Ok(())
}

/// `ouro agents` (G2): every session this runtime can see, grouped by what it needs.
///
/// Read-only and one-shot: two list calls, the same grouping the rail draws, and out. It
/// deliberately starts no runtime — a command whose whole job is to answer "is anything
/// waiting on me" must not answer it by creating something to wait on — so an unreachable
/// runtime is an error rather than a cold start.
async fn agents_page(
    paths: &Paths,
    json_output: bool,
    addr: Option<String>,
    token_file: Option<PathBuf>,
) -> Result<()> {
    let (address, token) = remote_endpoint(paths, addr, token_file).await?;
    let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);
    let Connected { client, hello, .. } = attach_with(address, token, false, hook).await?;

    // `hello.methods` is the gate here as everywhere: a gateway that serves neither list
    // is told apart from one whose lists are empty, because those are different answers.
    let mut missing = Vec::new();

    let interactive = if hello.serves("interactive.list") {
        client
            .call("interactive.list", json!({}))
            .await
            .context("calling interactive.list")?
    } else {
        missing.push("interactive.list");
        json!([])
    };

    let coding = if hello.serves("coding.list") {
        client
            .call("coding.list", json!({}))
            .await
            .context("calling coding.list")?
    } else {
        missing.push("coding.list");
        json!([])
    };

    client.stop().await;

    for method in &missing {
        eprintln!("ouro agents: this gateway does not serve {method}; its rows are missing");
    }

    let (interactive, coding) = ouro::agents::decode(&interactive, &coding);
    let rows = ouro::agents::group(&interactive, &coding);

    if json_output {
        println!("{}", ouro::agents::render_json(&rows));
    } else {
        print!("{}", ouro::agents::render(&rows));
    }

    Ok(())
}

/// `ouro attach`: connect to something this client did not start.
async fn attach_remote(
    paths: &Paths,
    dev: bool,
    addr: Option<String>,
    token_file: Option<PathBuf>,
    print: bool,
    config: Loaded,
) -> Result<()> {
    let (address, token) = remote_endpoint(paths, addr, token_file).await?;

    if print {
        report_dev_data_dir_override(paths, dev, &Progress::Plain);
        let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);

        return print_page(address, attach_with(address, token, false, hook).await?).await;
    }

    // No spawn to watch, so the boot screen is one phase long — but it is still where the
    // terminal is taken, so the handshake to a runtime on the other end of a tunnel has
    // somewhere to be slow in.
    let boot = Boot::begin();
    report_dev_data_dir_override(paths, dev, &boot.progress());

    draw(
        boot,
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
            open_machines: false,
            add_log: Vec::new(),
            add_recipe: None,
        },
    )
    .await
}

/// `ouro ledger`: one read against a runtime that is already up.
///
/// No spawn and no boot screen. A ledger query is a question about history, and starting a
/// machine to answer it would change the thing being asked about.
async fn ledger(paths: &Paths, args: LedgerArgs) -> Result<()> {
    let (address, token) = remote_endpoint(paths, args.addr, args.token_file).await?;
    let hook: Arc<dyn ReconnectHook> = Arc::new(NoReconnectHook);
    let connected = attach_with(address, token, false, hook).await?;

    let options = ouro::ledger_cli::Options {
        fleet: args.fleet,
        since: args.since,
        json: args.json,
        limit: args.limit,
    };

    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();

    ouro::ledger_cli::run(&connected.client, &options, &mut out, &mut err).await
}

/// Where a runtime this client did not start listens, and the token to present to it.
///
/// Shared by `ouro attach` and `ouro run --addr/--token-file` so the two surfaces cannot
/// disagree about which file a token is read from or when the cleartext warning is owed.
async fn remote_endpoint(
    paths: &Paths,
    addr: Option<String>,
    token_file: Option<PathBuf>,
) -> Result<(SocketAddr, Secret)> {
    // An explicit address plus token file is fully remote and must not touch local runtime
    // state. Every other form consults the local publication or default token path.
    if addr.is_none() || token_file.is_none() {
        paths.ensure_private_data_dir()?;
    }

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

    // The gateway protocol is cleartext, and the token rides in the first frame. A
    // loopback address is the boundary that makes that safe; anything else deserves a
    // line on stderr saying so before the handshake sends the credential.
    if !address.ip().is_loopback() {
        eprintln!(
            "warning: {address} is not loopback and this protocol is cleartext: the token \
             and every payload after it cross the network readable by anyone on the path. \
             Prefer an SSH tunnel (ssh -L <port>:127.0.0.1:<port> host) and attach to \
             127.0.0.1."
        );
    }

    Ok((address, token))
}

/// Connects with the boot screen still live, and hands the terminal to the UI.
async fn draw(
    mut boot: Boot,
    address: SocketAddr,
    token: Secret,
    mode: Mode,
    mut daemon: Option<Daemon>,
    open: Option<(Plane, String, Option<String>)>,
    local: Local,
) -> Result<()> {
    let (hook, channel) = ui::hook();
    let progress = boot.progress();

    progress.report(BootEvent::Connecting {
        address: address.to_string(),
    });

    let attached = match boot.drive(attach_with(address, token, true, hook)).await {
        Ok(attached) => attached,
        Err(error) => {
            return Err(fail_boot_with_owned_daemon(
                boot,
                &mut daemon,
                None,
                error,
                "connecting to the newly started runtime failed",
            )
            .await)
        }
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
        None,
        None,
        false,
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
    open: Option<(Plane, String, Option<String>)>,
    screen: Option<Screen>,
    local: Local,
    created_start_failure: Option<CreatedStartFailure>,
    first_message_reconciliation: Option<FirstMessageReconciliation>,
    first_message_accepted: bool,
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

    app.data_dir = local.data_dir.clone();
    app.fleet_profile = app
        .data_dir
        .as_deref()
        .and_then(|data_dir| fleet::load(Path::new(data_dir)).ok().flatten());
    app.can_invite = app
        .data_dir
        .as_deref()
        .zip(app.fleet_profile.as_ref())
        .is_some_and(|(data_dir, profile)| profile.can_invite(Path::new(data_dir)));
    app.open_machines_on_start = local.open_machines;
    app.resume_add_log = local.add_log;
    app.resume_add_recipe = local.add_recipe;
    app.config_path = Some(local.config.path.clone());
    app.config = local.config.config;

    // B8. The keymap is resolved once, here, from the `[keys]` table that was just read.
    // Everything that acts on a chord and everything that *draws* one reads this one map,
    // which is what makes a rebound key the key the UI shows (D14).
    app.reload_keymap();

    // A preference file that did not parse is one sentence, not a refusal to run. It is
    // said before the protocol warning below so that the more urgent of the two is the one
    // left on screen. A `[keys]` line this build could not act on joins it: the map ran on
    // its defaults for that action, and an operator who mistyped a chord finds out now
    // rather than by pressing it.
    let problems = local
        .config
        .problems
        .iter()
        .cloned()
        .chain(app.keymap.problems().iter().cloned())
        .collect::<Vec<_>>();

    if !problems.is_empty() {
        app.inform(problems.join(" · "), ouro::ui::app::NoticeKind::Warn);
    }

    let opened = open.is_some();

    if let Some((plane, id, node)) = open {
        app.open_session_on(plane, id, node);
    }

    // `ouro new -m` already used the one immediate-message slot before handing the
    // session to the UI. The next composer submission is a durable follow-up whether the
    // first turn is still active (queue it) or already idle (start it immediately).
    if first_message_accepted {
        let id = app
            .sessions
            .open
            .as_ref()
            .and_then(|(plane, id)| (*plane == Plane::Interactive).then(|| id.clone()));

        if let Some(id) = id {
            app.continue_after_first_message(&id);
        }
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

    if let Some(failure) = created_start_failure {
        app.restore_created_start_failure(
            Plane::Interactive,
            &failure.id,
            failure.input,
            failure.notice,
        );
    }

    // Reissuing the exact mutation is safe on both sides of a lost acknowledgement: the
    // caller-owned turn id lets the runtime accept a genuinely first arrival, report a
    // now-known dispatch, or keep a checkpointed uncertain intent outcome-unknown without
    // redispatching it. The normal FirstMessage answer path keeps the same id and draft if
    // this attempt also remains outcome-unknown; a definite refusal restores a fresh id.
    if let Some(reconciliation) = first_message_reconciliation {
        app.retry_first_message(
            reconciliation.id,
            reconciliation.input,
            reconciliation.turn_id,
        );
        app.inform(reconciliation.notice, ouro::ui::app::NoticeKind::Warn);
    }

    let mut daemon = daemon;

    let quit = match ui::run(
        screen,
        app,
        client.clone(),
        notifications,
        channel,
        daemon.as_mut(),
    )
    .await
    {
        Ok(quit) => quit,
        Err(error) => {
            client.stop().await;

            return Err(clean_up_owned_daemon_after_error(
                &mut daemon,
                error,
                "the terminal UI stopped before runtime handoff",
            )
            .await);
        }
    };

    if quit == Quit::ApplyFleetIntent {
        finish(Quit::Shutdown, &client, &hello, daemon).await?;
        let data_dir = local.data_dir.ok_or_else(|| {
            anyhow!(
                "cannot create a fleet from an attached client that has no local data directory"
            )
        })?;
        let outcome = fleet_add::apply_pending(Path::new(&data_dir))?;
        print!("{}", fleet_add::render_outcome(&outcome));
        let paths = runtime::Paths::discover(false)?;
        // Reattach with this session's own configuration source rather than defaults:
        // the restart is an implementation detail of one add, not a new invocation.
        return Box::pin(attach_local_with(
            &paths,
            false,
            config::load(local.config.path),
            true,
            Some(outcome),
        ))
        .await;
    }

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
        Quit::Shutdown | Quit::ApplyFleetIntent => {
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

/// `ouro stop`: ask the authenticated runtime to exit without ever signalling a PID
/// learned from a replaceable publication.
async fn stop(paths: &Paths, dev: bool) -> Result<()> {
    paths.ensure_private_data_dir()?;
    stop_with_locked_publication(paths, dev, || std::future::ready(())).await
}

async fn stop_with_locked_publication<F, Fut>(paths: &Paths, dev: bool, after_lock: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    report_dev_data_dir_override(paths, dev, &Progress::Plain);

    // A stop that observed a publication and released the namespace before acting on it
    // allowed a starter to replace that publication in the gap. Hold the same lock all
    // starters use until the observed pid is gone; every early return drops it safely.
    let lock = runtime::acquire_spawn_lock(&paths.data_dir)?;

    let publication = match runtime::reconcile_publication_under_spawn_lock(&paths.data_dir, &lock)?
    {
        runtime::LockedPublication::Absent => {
            bail!(
                "no runtime published {}, so there is nothing here to stop",
                paths.publication().display()
            )
        }
        runtime::LockedPublication::RemovedStale(publication) => {
            println!(
                "no runtime is running: pid {} from {} is gone, and the stale publication \
                 has been removed",
                publication.pid,
                paths.publication().display()
            );

            return Ok(());
        }
        runtime::LockedPublication::Live(publication) => publication,
    };

    // Keep the publication namespace frozen from the observation above through owner,
    // token and hello validation, the shutdown request/signal, and the observed pid exit.
    // Releasing here used to let a concurrent starter replace gateway.json between the
    // stop's read and action (an ABA publication race).
    after_lock().await;

    ensure_publication_matches_runtime_owner(paths, &publication)?;

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
        bail!(
            "this runtime does not serve authenticated runtime.shutdown at operate scope. Ouro will never signal a PID learned from a replaceable publication; stop it through its existing launchd/systemd supervisor or upgrade/restart it with a current ouro"
        );
    }

    attached.client.stop().await;

    let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;

    let exact_identity = publication.identity()?;
    while match &exact_identity {
        Some(identity) => runtime::process_identity_is_live(identity)?,
        None => runtime::pid_alive(publication.pid),
    } {
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

    drop(lock);
    println!("the runtime stopped (pid {})", publication.pid);

    Ok(())
}

/// Starts a runtime and waits for it to publish a port, under the spawn lock.
///
/// `None` for the daemon means another `ouro` published one while this call was taking
/// the lock: the check the caller made and the spawn it asked for are not one operation,
/// and the lock is where that gap is closed. Adopting is the right answer there — a
/// second runtime in the same data directory would overwrite the first one's token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartRequirement {
    Any,
    Fleet,
}

fn ensure_start_requirement(paths: &Paths, requirement: StartRequirement) -> Result<()> {
    if requirement == StartRequirement::Fleet && fleet::load(&paths.data_dir)?.is_none() {
        bail!(
            "service-run lost its fleet profile before acquiring runtime ownership. The runtime was not started; deactivate/remove the stale recovery unit or recreate/join the fleet first"
        );
    }
    Ok(())
}

async fn start(
    paths: &Paths,
    dev: bool,
    output: Output,
    progress: &Progress,
    requirement: StartRequirement,
) -> Result<(Publication, Secret, Option<Daemon>)> {
    // Held until this function returns, which is the whole spawn window: check, spawn,
    // and wait for the publication. Not longer — a client that held it while attached
    // would stop the next `ouro` from adopting the daemon it just started.
    let lock = runtime::acquire_spawn_lock(&paths.data_dir)?;

    let publication = runtime::reconcile_publication_under_spawn_lock(&paths.data_dir, &lock)?;
    // A recovery service may wait for an old runtime while `fleet leave` wins the lock
    // and removes the profile. Revalidate under this same lock before adoption, release
    // extraction, token creation, or spawn; never turn that race into a standalone child.
    ensure_start_requirement(paths, requirement)?;

    match publication {
        runtime::LockedPublication::Live(publication) => {
            ensure_publication_matches_runtime_owner(paths, &publication)?;

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
        runtime::LockedPublication::Absent | runtime::LockedPublication::RemovedStale(_) => {}
    }

    // `gateway.json` is a replaceable discovery record, not the durable store's
    // ownership boundary. Refuse a hidden live owner before release extraction and,
    // critically, before generating a token that would strand that runtime's clients.
    runtime::ensure_no_live_runtime_owner(&paths.data_dir)?;

    // The slow part of a genuinely cold start on an embedded build: the tarball's digest
    // is verified and the release unpacked. It printed nothing before there was a screen
    // and still prints nothing without one.
    progress.report(BootEvent::Preparing);

    let launcher = launcher(dev, paths).await?;
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

    let publication = match daemon.wait_ready(&paths.data_dir, deadline).await {
        Ok(publication) => publication,
        Err(error) => {
            return Err(clean_up_daemon_after_error(
                &mut daemon,
                error,
                "startup validation failed",
            )
            .await)
        }
    };

    if let Err(error) = ensure_spawned_runtime_matches_owner(paths, daemon.identity(), &publication)
    {
        return Err(
            clean_up_daemon_after_error(&mut daemon, error, "startup validation failed").await,
        );
    }

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

/// A child is still this client's responsibility until all three identities agree: the
/// process it spawned, the replaceable gateway publication, and the lifetime owner. Any
/// readiness or identity failure stops that child before returning, because dropping a
/// Tokio `Child` handle would otherwise detach a hidden runtime that still owns journals.
async fn clean_up_daemon_after_error(
    daemon: &mut Daemon,
    error: anyhow::Error,
    activity: &str,
) -> anyhow::Error {
    let pid = daemon.pid();

    match daemon.terminate(SHUTDOWN_GRACE).await {
        Ok(Some(status)) => error.context(format!(
            "{activity}; runtime pid {pid} was stopped ({status})"
        )),
        Ok(None) => error.context(format!("{activity}; runtime pid {pid} had already exited")),
        Err(cleanup_error) => error.context(format!(
            "{activity}; runtime pid {pid} could not be stopped: {cleanup_error}"
        )),
    }
}

/// Ends only a runtime this invocation spawned. `None` means the client adopted an
/// existing daemon, so an error closes this connection but never changes that runtime's
/// lifecycle.
async fn clean_up_owned_daemon_after_error(
    daemon: &mut Option<Daemon>,
    error: anyhow::Error,
    activity: &str,
) -> anyhow::Error {
    let Some(owned) = daemon.as_mut() else {
        return error;
    };

    let error = clean_up_daemon_after_error(owned, error, activity).await;
    *daemon = None;
    error
}

/// Restores the boot surface only after the spawned child has been reaped. Keeping the
/// boot screen until then preserves its log tail, while stopping the connection first
/// lets the runtime perform an orderly shutdown without an attached reconnect loop.
async fn fail_boot_with_owned_daemon(
    boot: Boot,
    daemon: &mut Option<Daemon>,
    client: Option<&Client>,
    error: anyhow::Error,
    activity: &str,
) -> anyhow::Error {
    if let Some(client) = client {
        client.stop().await;
    }

    let error = clean_up_owned_daemon_after_error(daemon, error, activity).await;
    boot.fail(error).await
}

fn ensure_spawned_runtime_matches_owner(
    paths: &Paths,
    daemon: &runtime::ProcessIdentity,
    publication: &Publication,
) -> Result<()> {
    let daemon_pid = daemon.pid;
    if publication.pid != daemon_pid {
        bail!(
            "{} names pid {}, but this client spawned pid {}; refusing to adopt the new \
             publication",
            paths.publication().display(),
            publication.pid,
            daemon_pid
        );
    }

    let owner = runtime::read_owned_runtime_owner(&paths.data_dir)?.ok_or_else(|| {
        anyhow!(
            "runtime pid {daemon_pid} published {}, but did not claim {}; refusing to \
             return a daemon with no durable-directory owner",
            paths.publication().display(),
            paths.runtime_owner().display()
        )
    })?;

    if owner.pid != daemon_pid {
        bail!(
            "this client spawned pid {daemon_pid}, but {} names pid {}; refusing to \
             return a daemon whose durable-directory owner does not match",
            paths.runtime_owner().display(),
            owner.pid
        );
    }
    if publication.birth.as_deref() != Some(daemon.birth.as_str())
        || owner.birth.as_deref() != Some(daemon.birth.as_str())
    {
        bail!(
            "runtime pid {daemon_pid} did not publish the exact process-birth identity claimed by the child handle; refusing startup handoff"
        );
    }

    Ok(())
}

fn ensure_publication_matches_runtime_owner(
    paths: &Paths,
    publication: &Publication,
) -> Result<()> {
    let Some(owner) = runtime::read_owned_runtime_owner(&paths.data_dir)? else {
        // Releases predating runtime.owner remain adoptable during upgrades.
        return Ok(());
    };

    if owner.pid != publication.pid {
        bail!(
            "{} names live pid {}, but {} names pid {}; refusing to attach because the \
             discovery publication and durable runtime owner disagree",
            paths.publication().display(),
            publication.pid,
            paths.runtime_owner().display(),
            owner.pid
        );
    }
    if let (Some(publication_birth), Some(owner_birth)) =
        (publication.birth.as_deref(), owner.birth.as_deref())
    {
        if publication_birth != owner_birth {
            bail!(
                "{} and {} name pid {} but different process incarnations; refusing to attach",
                paths.publication().display(),
                paths.runtime_owner().display(),
                publication.pid
            );
        }
    } else if publication.birth.is_some() || owner.birth.is_some() {
        bail!(
            "{} and {} disagree about whether pid {} has an exact process incarnation; refusing to attach",
            paths.publication().display(),
            paths.runtime_owner().display(),
            publication.pid
        );
    }

    Ok(())
}

/// Prepares the launch target off the async runtime.
///
/// A cold embedded start verifies a digest and unpacks a release tarball here, which is
/// blocking filesystem work no tokio worker should be doing while clients and log pumps
/// share it.
async fn launcher(dev: bool, paths: &Paths) -> Result<Launcher> {
    let paths = paths.clone();

    tokio::task::spawn_blocking(move || launcher_blocking(dev, &paths))
        .await
        .context("the release preparation task failed")?
}

fn launcher_blocking(dev: bool, paths: &Paths) -> Result<Launcher> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_private_test_data_dir(path: &Path) {
        use std::os::unix::fs::DirBuilderExt;

        std::fs::remove_dir_all(path).ok();
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .expect("a private scratch data directory");
    }

    fn interactive_request(machine: &str) -> StartRequest {
        StartRequest {
            id: "test-start-id".into(),
            plane: Plane::Interactive,
            provider: "stub".into(),
            machine: machine.into(),
            workspace: "/tmp/workspace".into(),
            approval_mode: None,
            sandbox_mode: None,
            objective: String::new(),
            worktree: false,
        }
    }

    #[test]
    fn service_start_revalidates_fleet_after_leave_wins_the_lifecycle_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "ouro-service-start-requirement-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        create_private_test_data_dir(&data_dir);
        let paths = Paths {
            cache_dir: data_dir.join("cache"),
            data_dir: data_dir.clone(),
            data_dir_overridden: true,
        };
        fleet::create(
            &data_dir,
            None,
            "service-race",
            "127.0.0.1",
            fleet::Ports::DEFAULT,
        )
        .unwrap();
        ensure_start_requirement(&paths, StartRequirement::Fleet).unwrap();

        // This is the settled ordering of the real race: leave held/released spawn.lock
        // first, then service-run acquired it. The required-fleet check is invoked by
        // start while this same guard remains held and before token creation.
        std::fs::remove_dir_all(fleet::fleet_dir(&data_dir)).unwrap();
        let lock = runtime::acquire_spawn_lock(&data_dir).unwrap();
        let error = ensure_start_requirement(&paths, StartRequirement::Fleet)
            .unwrap_err()
            .to_string();
        assert!(error.contains("lost its fleet profile"), "{error}");
        assert!(!paths.token_file().exists());
        ensure_start_requirement(&paths, StartRequirement::Any).unwrap();

        drop(lock);
        std::fs::remove_dir_all(data_dir).ok();
    }

    #[test]
    fn cli_start_retries_the_exact_stable_id_and_machine_request() {
        let request = interactive_request("studio-mini");
        let id = "ouro-cli-00112233445566778899aabbccddeeff";
        let mut request = request;
        request.id = id.into();
        let first = cli_start_params(&request, id).expect("validated CLI start params");
        let retry = first.clone();

        assert_eq!(first, retry);
        assert_eq!(first["id"], id);
        assert_eq!(first["machine"], "studio-mini");
        assert_eq!(first["provider"], "stub");
        assert_eq!(first["workspace"], "/tmp/workspace");
    }

    #[test]
    fn remote_workspace_is_never_absolutized_on_the_callers_machine() {
        assert_eq!(
            start_workspace("vps", Some("/srv/project")).unwrap(),
            "/srv/project"
        );
        for source in ["relative CLI flag", "relative config default"] {
            let error = start_workspace("vps", Some("project"))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("cannot use relative workspace"),
                "{source}: {error}"
            );
            assert!(error.contains("destination"), "{source}: {error}");
            assert!(
                error.contains("/absolute/path/on/vps/project"),
                "{source}: {error}"
            );
        }
        let missing = start_workspace("vps", None).unwrap_err().to_string();
        assert!(missing.contains("requires `--workspace"), "{missing}");
    }

    #[test]
    fn client_session_ids_are_nonsecret_random_lowercase_identifiers() {
        let first = new_client_session_id().expect("an OS-random session id");
        let second = new_client_session_id().expect("another OS-random session id");

        assert!(first.starts_with("ouro-cli-"));
        assert_eq!(first.len(), "ouro-cli-".len() + 32);
        assert!(first["ouro-cli-".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert_ne!(first, second);
    }

    #[test]
    fn fleet_session_forget_uses_the_explicit_irreversible_gateway_contract() {
        assert_eq!(
            forget_session_owner_params("retired-vps"),
            json!({
                "machine": "retired-vps",
                "accept_state_loss": true
            })
        );
        let result = json!({
            "machine": "retired-vps",
            "node": "ouro-retired-vps@100.64.0.9",
            "roster_revision": 4
        });
        assert_eq!(
            parse_forget_session_owner_result("retired-vps", &result).unwrap(),
            ("retired-vps", "ouro-retired-vps@100.64.0.9", 4)
        );
        let mismatch = parse_forget_session_owner_result("another-vps", &result)
            .unwrap_err()
            .to_string();
        assert!(mismatch.contains("instead of requested"), "{mismatch}");
    }

    #[test]
    fn start_transport_and_runtime_failures_are_unknown_but_pre_dispatch_refusals_are_definite() {
        for error in [
            ClientError::ConnectionClosed,
            ClientError::Timeout,
            ClientError::Io("connection reset".into()),
            ClientError::Stopped("reader ended".into()),
        ] {
            assert!(start_failure(&error).outcome_unknown, "{error}");
        }

        let timeout = ClientError::Rpc(proto::RpcError {
            code: proto::ErrorCode::UpstreamTimeout,
            message: "the runtime timed out".into(),
            data: None,
        });
        assert!(start_failure(&timeout).outcome_unknown);

        let upstream = ClientError::Rpc(proto::RpcError {
            code: proto::ErrorCode::UpstreamError,
            message: "the provider failed after durable creation".into(),
            data: None,
        });
        assert!(start_failure(&upstream).outcome_unknown);

        let owner_lost = ClientError::Rpc(proto::RpcError {
            code: proto::ErrorCode::Unavailable,
            message: "the remote owner disappeared while answering".into(),
            data: Some(serde_json::json!({
                "reason": "owner_unavailable",
                "outcome": "unknown"
            })),
        });
        assert!(start_failure(&owner_lost).outcome_unknown);

        let refused = ClientError::Rpc(proto::RpcError {
            code: proto::ErrorCode::InvalidParams,
            message: "params.machine is unknown".into(),
            data: None,
        });
        assert!(!start_failure(&refused).outcome_unknown);

        let explicit = ClientError::Rpc(proto::RpcError {
            code: proto::ErrorCode::UpstreamError,
            message: "the request was refused before dispatch".into(),
            data: Some(serde_json::json!({ "outcome": "not_dispatched" })),
        });
        assert!(!start_failure(&explicit).outcome_unknown);

        let placement = ClientError::Rpc(proto::RpcError {
            code: proto::ErrorCode::Unavailable,
            message: "the selected machine is incompatible".into(),
            data: Some(serde_json::json!({ "outcome": "not_dispatched" })),
        });
        assert!(!start_failure(&placement).outcome_unknown);
    }

    #[test]
    fn a_known_created_start_hands_the_stable_id_and_unsent_message_to_the_ui() {
        let started = StartedRef {
            id: "durable-failed-session".into(),
            node: Some("ouroboros@golden".into()),
            start_failure: Some("workspace admission failed".into()),
        };

        let handoff = created_start_failure_handoff(
            &started,
            Some("keep this exact first message as a draft"),
        )
        .expect("a typed created-failure handoff");

        assert_eq!(handoff.id, started.id);
        assert_eq!(
            handoff.input.as_deref(),
            Some("keep this exact first message as a draft")
        );
        assert!(handoff.notice.contains("did not become ready"));
        assert!(handoff.notice.contains("was not dispatched"));

        let ready = StartedRef {
            start_failure: None,
            ..started
        };
        assert_eq!(created_start_failure_handoff(&ready, None), None);
    }

    #[test]
    fn ambiguous_start_names_the_inspectable_id_even_after_a_definite_retry() {
        let id = "ouro-cli-00112233445566778899aabbccddeeff";
        let message = start_outcome_unknown(
            "interactive.start",
            id,
            "the connection closed",
            "params.provider is unavailable",
            false,
        );

        assert!(message.contains("outcome is unknown"), "{message}");
        assert!(message.contains(id), "{message}");
        assert!(message.contains("exact same-id retry"), "{message}");
        assert!(message.contains("Run `ouro`"), "{message}");
        assert!(message.contains("before starting another"), "{message}");
        assert!(!message.contains("was refused"), "{message}");
    }

    #[test]
    fn an_indeterminate_first_message_keeps_the_wire_diagnostic_and_the_ui_path() {
        let error = ClientError::Rpc(proto::RpcError {
            code: proto::ErrorCode::UpstreamTimeout,
            message: "the runtime could not confirm the turn dispatch".into(),
            data: Some(json!({
                "outcome": "unknown",
                "turn_id": "ouro-first:session-1",
                "error": [
                    "turn_dispatch_checkpoint_failed",
                    "dispatch_may_have_started",
                    "ouro-first:session-1"
                ]
            })),
        });

        let failure = first_message_failure(&error);

        assert!(failure.outcome_unknown);
        assert!(failure.rendered.contains("outcome unknown"));
        assert!(
            failure.rendered.contains("turn_dispatch_checkpoint_failed"),
            "{}",
            failure.rendered
        );
    }

    #[test]
    fn a_remote_new_session_routes_its_first_message_and_same_id_retry_to_the_owner() {
        let started = StartedRef {
            id: "interactive-remote-1".into(),
            node: Some("ouro-alpha@alpha.example.test".into()),
            start_failure: None,
        };

        let first = first_message_params(
            &started,
            "please inspect this workspace",
            "ouro-first:interactive-remote-1",
        );
        let retry = first_message_params(
            &started,
            "please inspect this workspace",
            "ouro-first:interactive-remote-1",
        );

        assert_eq!(
            first, retry,
            "reconciliation must replay the exact mutation"
        );
        assert_eq!(
            first,
            json!({
                "id": "interactive-remote-1",
                "input": "please inspect this workspace",
                "turn_id": "ouro-first:interactive-remote-1",
                "node": "ouro-alpha@alpha.example.test"
            })
        );

        let local_legacy = StartedRef {
            id: "interactive-local-1".into(),
            node: None,
            start_failure: None,
        };
        assert_eq!(
            first_message_params(&local_legacy, "hello", "ouro-first:interactive-local-1"),
            json!({
                "id": "interactive-local-1",
                "input": "hello",
                "turn_id": "ouro-first:interactive-local-1"
            })
        );
    }

    #[test]
    fn the_legacy_false_refusal_is_also_indeterminate_but_a_real_refusal_is_not() {
        let legacy = ClientError::Rpc(proto::RpcError {
            code: proto::ErrorCode::UpstreamError,
            message: "the runtime refused the call".into(),
            data: Some(json!([
                "turn_dispatch_checkpoint_failed",
                "dispatch_may_have_started",
                "ouro-first:session-1"
            ])),
        });

        let legacy = first_message_failure(&legacy);
        assert!(legacy.outcome_unknown);
        assert!(legacy.rendered.contains("turn_dispatch_checkpoint_failed"));

        let refused = ClientError::Rpc(proto::RpcError {
            code: proto::ErrorCode::InvalidParams,
            message: "params.input must be nonempty".into(),
            data: Some(json!({ "field": "input" })),
        });

        let refused = first_message_failure(&refused);
        assert!(!refused.outcome_unknown);
        assert!(refused.rendered.contains("\"field\":\"input\""));
    }

    #[test]
    fn losing_the_transport_after_send_is_not_permission_to_duplicate_the_turn() {
        let failure = first_message_failure(&ClientError::ConnectionClosed);

        assert!(failure.outcome_unknown);
        assert_eq!(failure.rendered, "the connection closed");
    }

    #[test]
    fn successful_rpc_envelopes_still_classify_the_durable_first_turn() {
        assert!(successful_first_message_failure(&json!({
            "id": "turn-1",
            "status": "running"
        }))
        .is_none());

        for status in ["dispatching", "ambiguous"] {
            let failure = successful_first_message_failure(&json!({
                "id": "turn-1",
                "status": status
            }))
            .expect("an unresolved durable turn");
            assert!(failure.outcome_unknown, "{status}");
            assert!(failure.rendered.contains(status), "{}", failure.rendered);
        }

        for status in ["failed", "interrupted"] {
            let failure = successful_first_message_failure(&json!({
                "id": "turn-1",
                "status": status,
                "error": "provider stopped"
            }))
            .expect("a terminal nonaccepted turn");
            assert!(!failure.outcome_unknown, "{status}");
            assert!(failure.rendered.contains(status), "{}", failure.rendered);
        }
    }

    #[test]
    fn print_mode_names_the_session_without_claiming_it_will_stay_attached() {
        let message = print_outcome_unknown(
            "session-1",
            "ouro-first:session-1",
            "the connection closed",
            "the request exceeded its client ceiling",
        );

        assert!(message.contains("session-1"));
        assert!(message.contains("Run `ouro`"));
        assert!(message.contains("inspect its transcript"));
        assert!(!message.contains("staying attached"));
    }

    #[test]
    fn print_mode_reports_a_same_id_failed_read_as_terminal_not_accepted() {
        let message = print_turn_rejected(
            "session-1",
            "ouro-first:session-1",
            "turn ouro-first:session-1 is failed — error=provider_refused",
        );

        assert!(message.contains("was not accepted"), "{message}");
        assert!(message.contains("session-1"), "{message}");
        assert!(message.contains("failed"), "{message}");
        assert!(!message.contains("outcome remains unknown"), "{message}");
    }

    #[test]
    fn adoption_refuses_a_publication_that_disagrees_with_the_durable_owner() {
        let paths = owner_paths("adoption-owner-mismatch", 42);
        let publication = publication(43);

        let error = ensure_publication_matches_runtime_owner(&paths, &publication)
            .expect_err("a mismatched owner");

        assert!(error.to_string().contains("disagree"));
        assert!(error.to_string().contains("pid 43"));
        assert!(error.to_string().contains("pid 42"));

        std::fs::remove_dir_all(&paths.data_dir).ok();
    }

    #[test]
    fn pre_lock_discovery_leaves_a_dead_publication_for_locked_reconciliation() {
        use std::os::unix::fs::PermissionsExt;

        let data_dir =
            std::env::temp_dir().join(format!("ouro-main-stale-preflight-{}", std::process::id()));
        create_private_test_data_dir(&data_dir);
        std::fs::write(
            data_dir.join(runtime::PUBLICATION_FILE),
            br#"{"port":4560,"protocol":1,"node":"stale@test","pid":2147483647,"birth":"test:dead:2147483647","scope":"operate"}"#,
        )
        .expect("a stale publication");
        std::fs::set_permissions(
            data_dir.join(runtime::PUBLICATION_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("a private stale publication");

        let paths = Paths {
            cache_dir: data_dir.join("cache"),
            data_dir: data_dir.clone(),
            data_dir_overridden: false,
        };

        assert!(live_publication_to_adopt(&paths)
            .expect("safe discovery")
            .is_none());
        assert!(
            paths.publication().exists(),
            "local and daemon preflight must not unlink outside spawn.lock"
        );

        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_holds_the_spawn_lock_from_publication_read_through_shutdown() {
        use std::os::unix::fs::PermissionsExt;

        let data_dir =
            std::env::temp_dir().join(format!("ouro-main-stop-lock-window-{}", std::process::id()));
        create_private_test_data_dir(&data_dir);
        let pid = std::process::id() as i32;
        let birth = runtime::process_birth(pid)
            .expect("a readable process incarnation")
            .expect("this test process is live");
        std::fs::write(
            data_dir.join(runtime::PUBLICATION_FILE),
            format!(
                r#"{{"port":4560,"protocol":1,"node":"stop@test","pid":{pid},"birth":"{birth}","scope":"operate"}}"#
            ),
        )
        .expect("a live publication");
        std::fs::set_permissions(
            data_dir.join(runtime::PUBLICATION_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("a private live publication");
        std::fs::write(
            data_dir.join(runtime::RUNTIME_OWNER_FILE),
            format!(r#"{{"pid":{pid},"owner":"test-vm","birth":"{birth}"}}"#),
        )
        .expect("a matching runtime owner");
        std::fs::set_permissions(
            data_dir.join(runtime::RUNTIME_OWNER_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("a private runtime owner");

        let paths = Paths {
            cache_dir: data_dir.join("cache"),
            data_dir: data_dir.clone(),
            data_dir_overridden: false,
        };
        let worker_paths = paths.clone();
        let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let stopper = tokio::spawn(async move {
            stop_with_locked_publication(&worker_paths, false, || async move {
                let _ = locked_tx.send(());
                let _ = release_rx.await;
            })
            .await
        });

        locked_rx.await.expect("stop reached the locked window");
        let error = runtime::acquire_spawn_lock(&data_dir)
            .expect_err("a starter cannot replace publication while stop acts on it");
        assert!(error.to_string().contains("another ouro"), "{error:#}");

        stopper.abort();
        let _ = stopper.await;
        let released = runtime::acquire_spawn_lock(&data_dir)
            .expect("cancelling stop releases its owned publication lock");
        drop(released);

        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn dev_override_warning_is_visible_and_only_disables_default_isolation() {
        let paths = Paths {
            data_dir: PathBuf::from("/var/lib/ouroboros-shared"),
            cache_dir: PathBuf::from("/cache"),
            data_dir_overridden: true,
        };
        let state = Arc::new(std::sync::Mutex::new(ouro::ui::boot::BootProgress::new()));
        let progress = Progress::Screen(state.clone());

        report_dev_data_dir_override(&paths, true, &progress);

        let warning = state
            .lock()
            .expect("boot progress")
            .warnings()
            .first()
            .cloned()
            .expect("a visible warning");
        assert!(warning.contains("--dev"));
        assert!(warning.contains("OUROBOROS_DATA_DIR=/var/lib/ouroboros-shared"));
        assert!(warning.contains("may adopt a release runtime"));
        assert!(warning.contains("dedicated directory"));

        let mut default_paths = paths.clone();
        default_paths.data_dir_overridden = false;
        assert!(dev_data_dir_override_warning(&default_paths, true).is_none());
        assert!(dev_data_dir_override_warning(&paths, false).is_none());
    }

    #[test]
    fn a_new_spawn_requires_its_child_publication_and_owner_to_name_one_pid() {
        let paths = owner_paths("spawn-owner-mismatch", 52);
        let child = runtime::ProcessIdentity {
            pid: 51,
            birth: "test:51".into(),
        };

        let publication_error =
            ensure_spawned_runtime_matches_owner(&paths, &child, &publication(53))
                .expect_err("another process's publication");
        assert!(publication_error
            .to_string()
            .contains("this client spawned pid 51"));

        let owner_error = ensure_spawned_runtime_matches_owner(&paths, &child, &publication(51))
            .expect_err("another process's owner marker");
        assert!(owner_error.to_string().contains("names pid 52"));

        std::fs::remove_dir_all(&paths.data_dir).ok();
    }

    #[tokio::test]
    async fn an_adopted_runtime_is_never_reclassified_as_owned_during_error_cleanup() {
        let mut adopted = None;
        let error = clean_up_owned_daemon_after_error(
            &mut adopted,
            anyhow!("the session request was refused"),
            "this context is only for an owned child",
        )
        .await;

        assert!(adopted.is_none());
        assert_eq!(error.to_string(), "the session request was refused");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_post_start_attach_failure_reaps_the_owned_runtime() {
        if std::env::var("OUROBOROS_TUI_INTEGRATION").as_deref() != Ok("1") {
            eprintln!("skipped: set OUROBOROS_TUI_INTEGRATION=1 for the real-runtime cleanup test");
            return;
        }

        let data_dir = std::env::temp_dir().join(format!(
            "ouro-main-cleanup-integration-{}",
            std::process::id()
        ));
        create_private_test_data_dir(&data_dir);
        let paths = Paths {
            cache_dir: data_dir.join("cache"),
            data_dir: data_dir.clone(),
            data_dir_overridden: false,
        };
        let boot = Boot::plain();
        let progress = boot.progress();
        let (publication, _token, daemon) =
            start(&paths, true, Output::Ring, &progress, StartRequirement::Any)
                .await
                .expect("a real dev runtime");
        let pid = publication.pid;
        let mode = supervision(&daemon);

        let error = draw(
            boot,
            local_address(publication.port),
            Secret::new("deliberately-wrong-token-for-cleanup-regression".into()),
            mode,
            daemon,
            None,
            Local {
                data_dir: Some(data_dir.display().to_string()),
                config: Loaded {
                    config: config::Config::default(),
                    path: data_dir.join("config.toml"),
                    problems: vec![],
                },
                open_machines: false,
                add_log: Vec::new(),
                add_recipe: None,
            },
        )
        .await
        .expect_err("the gateway refuses the wrong token");

        assert!(error.to_string().contains("runtime pid"));
        assert!(error.to_string().contains("was stopped"));
        assert!(!runtime::pid_alive(pid));
        assert!(
            runtime::read_owned_runtime_owner(&data_dir)
                .expect("a readable data directory")
                .is_none(),
            "bounded cleanup lets the core release its lifetime owner"
        );

        std::fs::remove_dir_all(&data_dir).ok();
    }

    fn publication(pid: i32) -> Publication {
        Publication {
            port: 4560,
            protocol: proto::PROTOCOL,
            node: "ouro@test".into(),
            pid,
            birth: None,
            scope: "operate".into(),
        }
    }

    fn owner_paths(label: &str, pid: i32) -> Paths {
        use std::os::unix::fs::PermissionsExt;

        let data_dir =
            std::env::temp_dir().join(format!("ouro-main-{label}-{}", std::process::id()));
        create_private_test_data_dir(&data_dir);

        let owner = data_dir.join(runtime::RUNTIME_OWNER_FILE);
        std::fs::write(&owner, format!(r#"{{"pid":{pid},"owner":"test-vm"}}"#))
            .expect("an owner marker");
        std::fs::set_permissions(&owner, std::fs::Permissions::from_mode(0o600))
            .expect("a private owner marker");

        Paths {
            cache_dir: data_dir.join("cache"),
            data_dir,
            data_dir_overridden: false,
        }
    }
}
