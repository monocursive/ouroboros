//! GPUI desktop client.
//!
//! GPUI owns pixels and native input. [`crate::ui::app::App`] still owns protocol
//! decisions. A Tokio connection driver lives on one background thread and sends the
//! reducer the same `Msg` values as the terminal driver; every native action calls a
//! semantic method on that reducer and drains its ordinary `Call` queue.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use gpui::{
    actions, div, prelude::*, px, size, uniform_list, App as GpuiApp, Application, Bounds, Context,
    Entity, FocusHandle, KeyBinding, KeyDownEvent, Menu, MenuItem, ScrollHandle, Subscription,
    SystemMenuType, Task, Timer, TitlebarOptions, UniformListScrollHandle, Window, WindowBounds,
    WindowOptions,
};
use gpui_component::alert::Alert;
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::spinner::Spinner;
use gpui_component::text::TextView;
use gpui_component::{Disableable as _, Icon, IconName, Root, Sizable as _};
use gpui_component_assets::Assets as ComponentAssets;
use tokio::sync::mpsc as tokio_mpsc;

use crate::config;
use crate::desktop_design::{self as design, DesktopTokens, Tone};
use crate::model::{ApprovalDecision, ApprovalScope, Plane, Triage};
use crate::runtime::{self, Paths};
use crate::transport::{self, Secret, TransportConfig};
use crate::ui::app::{
    App, Call, Connection, DesktopApprovalChoice, DesktopCell, DesktopCellKind, DesktopTone, Mode,
    Msg, NoticeKind,
};
use crate::ui::{self, TICK};

const LAUNCHER_ERROR_LIMIT: usize = 16 * 1024;

actions!(ouro_desktop, [QuitDesktop]);

#[derive(Debug, Clone)]
pub struct LaunchOptions {
    pub dev: bool,
    pub addr: Option<SocketAddr>,
    pub token_file: Option<PathBuf>,
}

pub fn run(options: LaunchOptions) -> Result<()> {
    let driver = Driver::spawn(options);

    Application::new()
        .with_assets(ComponentAssets)
        .run(move |cx: &mut GpuiApp| {
            gpui_component::init(cx);
            design::install_component_theme(cx);
            cx.bind_keys([KeyBinding::new("cmd-q", QuitDesktop, None)]);
            cx.on_action(|_: &QuitDesktop, cx| cx.quit());
            cx.set_menus(vec![Menu {
                name: "Ouroboros".into(),
                items: vec![
                    MenuItem::os_submenu("Services", SystemMenuType::Services),
                    MenuItem::separator(),
                    MenuItem::action("Quit Ouroboros", QuitDesktop),
                ],
            }]);
            cx.on_window_closed(|cx| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();

            let bounds = Bounds::centered(None, size(px(1240.0), px(820.0)), cx);
            cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    window_min_size: Some(size(px(860.0), px(600.0))),
                    focus: true,
                    app_id: Some("dev.ouroboros.desktop".to_string()),
                    titlebar: Some(TitlebarOptions {
                        title: Some("Ouroboros".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                move |window, cx| {
                    let view = cx.new(|cx| DesktopView::new(driver, window, cx));
                    cx.new(|cx| Root::new(view, window, cx))
                },
            )
            .expect("opening the Ouroboros desktop window");
            cx.activate(true);
        });

    Ok(())
}

enum DriverCommand {
    Call(Box<Call>),
    Stop,
}

enum DriverEvent {
    Status(String),
    Connected {
        address: SocketAddr,
        hello: crate::proto::Hello,
        cursors: crate::ui::Cursors,
        data_dir: Option<String>,
    },
    Message(Msg),
    Failed(String),
}

struct Driver {
    commands: tokio_mpsc::UnboundedSender<DriverCommand>,
    events: Receiver<DriverEvent>,
}

impl Driver {
    fn spawn(options: LaunchOptions) -> Self {
        let (event_tx, events) = mpsc::channel();
        let (commands, command_rx) = tokio_mpsc::unbounded_channel();

        std::thread::Builder::new()
            .name("ouro-desktop-runtime".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .thread_name("ouro-desktop-io")
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = event_tx.send(DriverEvent::Failed(format!(
                            "could not start the desktop I/O runtime: {error}"
                        )));
                        return;
                    }
                };

                if let Err(error) =
                    runtime.block_on(run_driver(options, command_rx, event_tx.clone()))
                {
                    let _ = event_tx.send(DriverEvent::Failed(format!("{error:#}")));
                }
            })
            .expect("spawning the Ouroboros desktop runtime thread");

        Self { commands, events }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.commands.send(DriverCommand::Stop);
    }
}

async fn run_driver(
    options: LaunchOptions,
    mut commands: tokio_mpsc::UnboundedReceiver<DriverCommand>,
    events: Sender<DriverEvent>,
) -> Result<()> {
    let (address, token, data_dir) = endpoint(&options, &events).await?;
    let _ = events.send(DriverEvent::Status(format!("Connecting to {address}…")));

    let (hook, channel) = ui::hook();
    let (cursors, ui_sender, mut ui_receiver) = channel.into_parts();
    let mut config = TransportConfig::new(address, token);
    config.reconnect = true;

    let connected = transport::connect(config, hook)
        .await
        .map_err(|error| anyhow!("cannot reach the gateway at {address}: {error}"))?;
    let client = connected.client;
    let mut notifications = connected.notifications;

    events
        .send(DriverEvent::Connected {
            address,
            hello: connected.hello,
            cursors,
            data_dir,
        })
        .map_err(|_| anyhow!("the desktop window closed while connecting"))?;

    let mut health = tokio::time::interval(Duration::from_millis(500));
    health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut dropped_seen = 0;

    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(DriverCommand::Call(call)) => {
                    let client = client.clone();
                    let events = events.clone();
                    tokio::spawn(async move {
                        let result = match call.timeout {
                            Some(timeout) => client.call_with_timeout(&call.method, call.params, timeout).await,
                            None => client.call(&call.method, call.params).await,
                        };
                        let _ = events.send(DriverEvent::Message(Msg::Answer {
                            tag: call.tag,
                            result,
                        }));
                    });
                }
                Some(DriverCommand::Stop) | None => {
                    client.stop().await;
                    return Ok(());
                }
            },
            notification = notifications.recv() => match notification {
                Some(notification) => {
                    if events.send(DriverEvent::Message(Msg::Notification(notification))).is_err() {
                        client.stop().await;
                        return Ok(());
                    }
                }
                None => return Err(anyhow!("the gateway notification stream closed")),
            },
            message = ui_receiver.recv() => if let Some(message) = message {
                if events.send(DriverEvent::Message(message)).is_err() {
                    client.stop().await;
                    return Ok(());
                }
            },
            _ = health.tick() => {
                let dropped = client.dropped_notifications();
                if dropped != dropped_seen {
                    dropped_seen = dropped;
                    let _ = ui_sender.send(Msg::NotificationsDropped(dropped));
                }
            }
        }
    }
}

async fn endpoint(
    options: &LaunchOptions,
    events: &Sender<DriverEvent>,
) -> Result<(SocketAddr, Secret, Option<String>)> {
    if let Some(address) = options.addr {
        let token_file = options
            .token_file
            .as_deref()
            .ok_or_else(|| anyhow!("--addr requires --token-file"))?;
        let token = runtime::read_token(token_file)
            .with_context(|| format!("reading the token from {}", token_file.display()))?;
        return Ok((address, token, None));
    }

    let paths = Paths::discover(options.dev)?;
    paths.ensure_private_data_dir()?;
    let _ = events.send(DriverEvent::Status(
        "Starting or adopting the local Ouroboros runtime…".to_string(),
    ));

    let dev = options.dev;
    let paths_for_start = paths.clone();
    tokio::task::spawn_blocking(move || ensure_local_runtime(&paths_for_start, dev))
        .await
        .context("the local runtime launcher stopped")??;

    let publication = runtime::read_live_publication(&paths.data_dir)?.ok_or_else(|| {
        anyhow!(
            "the launcher returned without a live publication in {}",
            paths.data_dir.display()
        )
    })?;
    let token = runtime::read_token(&paths.token_file())?;
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), publication.port);

    Ok((address, token, Some(paths.data_dir.display().to_string())))
}

/// Delegates local process ownership to the existing CLI lifecycle. This keeps desktop
/// startup on the same spawn lock, release verification, stale-publication recovery, and
/// process-incarnation checks as `ouro`, instead of growing a subtly different launcher.
fn ensure_local_runtime(paths: &Paths, dev: bool) -> Result<()> {
    let mut command = launcher_command(dev)?;
    if dev {
        command.arg("--dev");
    }
    command.arg("daemon");

    let output = command
        .output()
        .with_context(|| format!("starting the runtime for {}", paths.data_dir.display()))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = output_tail(&output.stderr);
    let stdout = output_tail(&output.stdout);
    let detail = [stderr.trim(), stdout.trim()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
    bail!(
        "the Ouroboros launcher exited with {}{}{}",
        output.status,
        if detail.is_empty() { "" } else { ": " },
        detail
    )
}

fn output_tail(output: &[u8]) -> String {
    let omitted = output.len().saturating_sub(LAUNCHER_ERROR_LIMIT);
    let tail = &output[omitted..];
    let text = String::from_utf8_lossy(tail).trim().to_string();
    if omitted == 0 {
        text
    } else {
        format!("… {omitted} earlier bytes omitted …\n{text}")
    }
}

fn launcher_command(dev: bool) -> Result<Command> {
    if let Some(path) = std::env::var_os("OUROBOROS_CLI") {
        return Ok(Command::new(path));
    }

    let executable = std::env::current_exe().context("locating ouro-desktop")?;
    if let Some(sibling) = executable.parent().map(|parent| parent.join("ouro")) {
        if sibling.is_file() {
            return Ok(Command::new(sibling));
        }
    }

    if !dev {
        bail!(
            "ouro-desktop could not find its `ouro` launcher beside {}; reinstall both binaries or set OUROBOROS_CLI",
            executable.display()
        );
    }

    let here = std::env::current_dir().context("reading the working directory")?;
    let root = runtime::find_repo_root(&here)?;
    let manifest = root.join("tui/Cargo.toml");
    if !manifest.is_file() {
        bail!("the development launcher is missing {}", manifest.display());
    }

    let mut command = Command::new("cargo");
    command
        .arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--bin")
        .arg("ouro")
        .arg("--");
    Ok(command)
}

struct DesktopView {
    driver: Driver,
    app: Option<App>,
    status: String,
    fatal: Option<String>,
    composer: Entity<InputState>,
    provider: Entity<InputState>,
    model: Entity<InputState>,
    workspace: Entity<InputState>,
    show_new: bool,
    action_error: Option<String>,
    transcript_scroll: ScrollHandle,
    session_scroll: UniformListScrollHandle,
    transcript_len: usize,
    focus_handle: FocusHandle,
    _subscriptions: Vec<Subscription>,
    _poll: Task<()>,
}

impl DesktopView {
    fn new(driver: Driver, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus_handle = cx.focus_handle();
        focus_handle.focus(window);
        let composer = cx.new(|cx| {
            InputState::new(window, cx)
                .auto_grow(2, 8)
                .placeholder("Message the open session…")
        });
        let provider = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Provider")
                .default_value("native")
        });
        let model = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Model (optional)")
                .default_value("openai_codex:gpt-5.6-sol")
        });
        let workspace_value = std::env::current_dir()
            .ok()
            .filter(|path| path != Path::new("/"))
            .or_else(dirs::home_dir)
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let workspace = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Absolute workspace path")
                .default_value(workspace_value)
        });
        let mut subscriptions = Vec::new();
        for input in [
            composer.clone(),
            provider.clone(),
            model.clone(),
            workspace.clone(),
        ] {
            subscriptions.push(cx.subscribe_in(
                &input,
                window,
                |_this, _input, event, _window, cx| {
                    if matches!(event, InputEvent::Change) {
                        cx.notify();
                    }
                },
            ));
        }

        let poll = cx.spawn(async move |view, cx| loop {
            Timer::after(TICK).await;
            let Some(view) = view.upgrade() else {
                break;
            };
            if view
                .update(cx, |this, cx| {
                    this.poll(cx);
                    cx.notify();
                })
                .is_err()
            {
                break;
            }
        });

        Self {
            driver,
            app: None,
            status: "Preparing the desktop client…".to_string(),
            fatal: None,
            composer,
            provider,
            model,
            workspace,
            show_new: false,
            action_error: None,
            transcript_scroll: ScrollHandle::new(),
            session_scroll: UniformListScrollHandle::new(),
            transcript_len: 0,
            focus_handle,
            _subscriptions: subscriptions,
            _poll: poll,
        }
    }

    fn poll(&mut self, cx: &mut Context<Self>) {
        while let Ok(event) = self.driver.events.try_recv() {
            match event {
                DriverEvent::Status(status) => self.status = status,
                DriverEvent::Failed(error) => self.fatal = Some(error),
                DriverEvent::Connected {
                    address,
                    hello,
                    cursors,
                    data_dir,
                } => {
                    let loaded = config::load_default();
                    let mut app = App::new(Mode::Attached, address.to_string(), hello, None);
                    app.cursors = cursors;
                    app.launch_dir = std::env::current_dir()
                        .ok()
                        .map(|path| path.display().to_string());
                    app.data_dir = data_dir;
                    app.config_path = Some(loaded.path);
                    app.config = loaded.config;
                    app.reload_keymap();
                    for problem in loaded.problems {
                        app.inform(problem, crate::ui::app::NoticeKind::Warn);
                    }
                    app.apply(Msg::Tick);
                    self.status = format!("Connected · {} · {}", app.hello.node, app.hello.scope);
                    self.app = Some(app);
                }
                DriverEvent::Message(message) => {
                    if let Some(app) = self.app.as_mut() {
                        app.apply(message);
                    }
                }
            }
        }

        let open_url = self.app.as_mut().and_then(|app| {
            app.apply(Msg::Tick);
            app.take_open_url()
        });
        if let Some(url) = open_url {
            if url.starts_with("https://") {
                cx.open_url(&url);
            } else {
                self.action_error = Some(
                    "the account service returned a non-HTTPS sign-in URL; it was not opened"
                        .to_string(),
                );
            }
        }
        self.flush_calls();
        if let Some(app) = self.app.as_ref() {
            let len = app.desktop_transcript().len();
            if len > self.transcript_len {
                self.transcript_scroll.scroll_to_bottom();
            }
            self.transcript_len = len;
        }
    }

    fn flush_calls(&mut self) {
        let Some(app) = self.app.as_mut() else {
            return;
        };
        for call in app.drain() {
            if self
                .driver
                .commands
                .send(DriverCommand::Call(Box::new(call)))
                .is_err()
            {
                self.fatal = Some("the connection driver stopped".to_string());
                break;
            }
        }
    }

    fn select_session(
        &mut self,
        plane: Plane,
        id: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(app) = self.app.as_mut() {
            app.open_session(plane, id);
            self.composer
                .update(cx, |input, cx| input.set_value("", window, cx));
            self.transcript_len = 0;
            self.transcript_scroll.scroll_to_bottom();
            self.action_error = None;
            self.flush_calls();
            cx.notify();
        }
    }

    fn send_message(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.composer.read(cx).value().to_string();
        let result = self
            .app
            .as_mut()
            .ok_or_else(|| "the runtime is not connected yet".to_string())
            .and_then(|app| app.desktop_submit_message(&text));

        match result {
            Ok(()) => {
                self.composer
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.action_error = None;
                self.flush_calls();
            }
            Err(error) => self.action_error = Some(error),
        }
        cx.notify();
    }

    fn start_session(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let provider = self.provider.read(cx).value().to_string();
        let model = self.model.read(cx).value().to_string();
        let workspace = self.workspace.read(cx).value().to_string();
        let result = self
            .app
            .as_mut()
            .ok_or_else(|| "the runtime is not connected yet".to_string())
            .and_then(|app| {
                app.desktop_start_session(
                    provider,
                    (!model.trim().is_empty()).then_some(model),
                    workspace,
                )
            });

        match result {
            Ok(id) => {
                self.composer
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.action_error = None;
                self.status = format!("Starting {id}…");
                self.show_new = false;
                self.flush_calls();
            }
            Err(error) => self.action_error = Some(error),
        }
        cx.notify();
    }

    fn start_chatgpt_login(&mut self, cx: &mut Context<Self>) {
        let result = self
            .app
            .as_mut()
            .ok_or_else(|| "the runtime is not connected yet".to_string())
            .and_then(|app| {
                let local_runtime = app.data_dir.is_some();
                app.desktop_start_chatgpt_login(local_runtime)
            });
        match result {
            Ok(()) => {
                self.action_error = None;
                self.flush_calls();
            }
            Err(error) => self.action_error = Some(error),
        }
        cx.notify();
    }

    fn cancel_chatgpt_login(&mut self, cx: &mut Context<Self>) {
        if let Some(app) = self.app.as_mut() {
            app.desktop_cancel_chatgpt_login();
            self.flush_calls();
        }
        cx.notify();
    }

    fn respond(
        &mut self,
        request_id: String,
        choice: DesktopApprovalChoice,
        cx: &mut Context<Self>,
    ) {
        let result = match self.app.as_mut() {
            None => Err("the runtime is not connected".to_string()),
            Some(app) => match (choice.plan, choice.decision, choice.scope) {
                (Some(plan), _, _) => app.desktop_respond_plan(&request_id, plan),
                (None, Some(decision), Some(scope)) => {
                    app.desktop_respond_approval(&request_id, decision, scope)
                }
                _ => Err("this provider option cannot be mapped safely".to_string()),
            },
        };
        match result {
            Ok(()) => {
                self.action_error = None;
                self.flush_calls();
            }
            Err(error) => self.action_error = Some(error),
        }
        cx.notify();
    }

    fn interrupt(&mut self, cx: &mut Context<Self>) {
        if let Some(app) = self.app.as_mut() {
            app.desktop_interrupt();
            self.action_error = None;
            self.flush_calls();
            cx.notify();
        }
    }

    fn toggle_new_session(&mut self, cx: &mut Context<Self>) {
        if self.app.is_some() {
            self.show_new = !self.show_new;
            self.action_error = None;
            cx.notify();
        }
    }

    fn handle_key_down(
        &mut self,
        event: &KeyDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let modifiers = event.keystroke.modifiers;
        if !modifiers.platform || modifiers.control || modifiers.alt || modifiers.shift {
            return;
        }

        let handled = match event.keystroke.key.as_str() {
            "enter" => {
                self.send_message(window, cx);
                true
            }
            "." => {
                self.interrupt(cx);
                true
            }
            "n" => {
                self.toggle_new_session(cx);
                true
            }
            _ => false,
        };
        if handled {
            window.prevent_default();
            cx.stop_propagation();
        }
    }

    fn render_session_rail(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = design::tokens(cx);
        let rows = self
            .app
            .as_ref()
            .map(App::desktop_sessions)
            .unwrap_or_default();
        let row_count = rows.len();
        let rows = Arc::new(rows);

        div()
            .flex()
            .flex_col()
            .w(px(276.0))
            .h_full()
            .flex_none()
            .bg(tokens.canvas)
            .border_r_1()
            .border_color(tokens.line)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .h(px(68.0))
                    .px_3()
                    .border_b_1()
                    .border_color(tokens.line)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(design::icon_tile(
                                tokens,
                                cx,
                                Tone::Accent,
                                IconName::GalleryVerticalEnd,
                            ))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .child("Ouroboros"),
                                    )
                                    .child(design::eyebrow(tokens, "WORKSPACE")),
                            ),
                    )
                    .child(
                        design::secondary_button("new-session", "New")
                            .icon(IconName::Plus)
                            .tooltip("New session · ⌘N")
                            .disabled(self.app.is_none())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.show_new = !this.show_new;
                                this.action_error = None;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px_3()
                    .pt_4()
                    .pb_2()
                    .child(design::eyebrow(tokens, "SESSIONS"))
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.ink_3)
                            .child(row_count.to_string()),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .when(row_count == 0, |view| {
                        view.items_center().justify_center().px_5().child(
                            div()
                                .flex()
                                .flex_col()
                                .items_center()
                                .gap_1()
                                .text_center()
                                .text_color(tokens.ink_3)
                                .child(Icon::new(IconName::Inbox).small())
                                .child(div().text_xs().child("No sessions yet")),
                        )
                    })
                    .when(row_count > 0, |view| {
                        view.child(
                            uniform_list(
                                "session-rail",
                                row_count,
                                cx.processor(
                                    move |_this, range: Range<usize>, _window, cx| {
                                        range
                                            .filter_map(|index| {
                                                rows.get(index).cloned().map(|row| (index, row))
                                            })
                                            .map(|(index, row)| {
                                                let id = row.id.clone();
                                                let plane = row.plane;
                                                let selected = row.selected;
                                                let triage_tone = match row.triage {
                                                    Triage::NeedsInput => Tone::Warning,
                                                    Triage::Working => Tone::Accent,
                                                    Triage::Done => Tone::Neutral,
                                                };
                                                let title = display_session_id(&row.id);
                                                let meta = format!(
                                                    "{}{}{}",
                                                    row.plane.tag(),
                                                    row.provider
                                                        .map(|provider| format!(" · {provider}"))
                                                        .unwrap_or_default(),
                                                    if row.pending_approvals > 0 {
                                                        format!(
                                                            " · {} pending",
                                                            row.pending_approvals
                                                        )
                                                    } else {
                                                        String::new()
                                                    }
                                                );
                                                div()
                                                    .id(("session", index))
                                                    .flex()
                                                    .gap_2()
                                                    .mx_2()
                                                    .mb_1()
                                                    .p_2()
                                                    .ml(px(
                                                        8.0 + (row.depth as f32) * 12.0,
                                                    ))
                                                    .rounded(tokens.radius)
                                                    .bg(if selected {
                                                        tokens.surface
                                                    } else {
                                                        tokens.canvas
                                                    })
                                                    .border_1()
                                                    .border_color(if selected {
                                                        tokens.line
                                                    } else {
                                                        tokens.canvas
                                                    })
                                                    .hover(|style| style.bg(tokens.hover))
                                                    .on_click(cx.listener(
                                                        move |this, _, window, cx| {
                                                            this.select_session(
                                                                plane,
                                                                id.clone(),
                                                                window,
                                                                cx,
                                                            );
                                                        },
                                                    ))
                                                    .child(
                                                        div()
                                                            .w(px(2.0))
                                                            .flex_none()
                                                            .rounded_full()
                                                            .bg(if selected {
                                                                tokens.accent
                                                            } else {
                                                                tokens.canvas
                                                            }),
                                                    )
                                                    .child(
                                                        div()
                                                            .flex()
                                                            .flex_col()
                                                            .flex_1()
                                                            .min_w_0()
                                                            .gap_1()
                                                            .child(
                                                                div()
                                                                    .flex()
                                                                    .items_center()
                                                                    .justify_between()
                                                                    .gap_2()
                                                                    .child(
                                                                        div()
                                                                            .flex_1()
                                                                            .min_w_0()
                                                                            .text_sm()
                                                                            .font_weight(
                                                                                gpui::FontWeight::MEDIUM,
                                                                            )
                                                                            .text_ellipsis()
                                                                            .child(title),
                                                                    )
                                                                    .child(design::status_tag(
                                                                        tokens,
                                                                        cx,
                                                                        triage_tone,
                                                                        row.status,
                                                                    )),
                                                            )
                                                            .child(
                                                                div()
                                                                    .text_xs()
                                                                    .text_color(tokens.ink_3)
                                                                    .text_ellipsis()
                                                                    .child(meta),
                                                            ),
                                                    )
                                            })
                                            .collect::<Vec<_>>()
                                    },
                                ),
                            )
                            .track_scroll(self.session_scroll.clone())
                            .py_1()
                            .flex_1(),
                        )
                    }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px_3()
                    .py_2()
                    .border_t_1()
                    .border_color(tokens.line)
                    .text_xs()
                    .text_color(tokens.ink_3)
                    .child("Create a session")
                    .child(design::keycap(tokens, "⌘N")),
            )
    }

    fn render_new_session(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = design::tokens(cx);
        let requires_chatgpt = self.provider.read(cx).value().trim() == "native"
            && self
                .model
                .read(cx)
                .value()
                .trim()
                .starts_with("openai_codex:");
        let account_usable = self
            .app
            .as_ref()
            .is_some_and(|app| app.desktop_account().usable);
        let can_start = !requires_chatgpt || account_usable;
        let starting = self.status.starts_with("Starting ");

        design::panel(tokens)
            .flex()
            .flex_col()
            .w_full()
            .max_w(px(880.0))
            .mx_auto()
            .mt_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .px_4()
                    .py_3()
                    .border_b_1()
                    .border_color(tokens.line)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(design::icon_tile(tokens, cx, Tone::Accent, IconName::Plus))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_lg()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .child("New session"),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(tokens.ink_2)
                                            .child("Choose where and how this agent works"),
                                    ),
                            ),
                    )
                    .child(
                        design::icon_button(
                            "close-new-session",
                            IconName::Close,
                            "Close new session",
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.show_new = false;
                            this.action_error = None;
                            cx.notify();
                        })),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .p_4()
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                design::field(
                                    tokens,
                                    "Provider",
                                    Some("Required".into()),
                                    Input::new(&self.provider)
                                        .prefix(Icon::new(IconName::Bot).small()),
                                )
                                .flex_1(),
                            )
                            .child(
                                design::field(
                                    tokens,
                                    "Model",
                                    Some("Optional".into()),
                                    Input::new(&self.model)
                                        .cleanable(true)
                                        .prefix(Icon::new(IconName::Settings2).small()),
                                )
                                .flex_1(),
                            ),
                    )
                    .child(design::field(
                        tokens,
                        "Workspace",
                        Some("Absolute path".into()),
                        Input::new(&self.workspace)
                            .cleanable(true)
                            .prefix(Icon::new(IconName::Folder).small()),
                    ))
                    .child(div().text_xs().text_color(tokens.ink_3).child(
                        "Approval and sandbox defaults come from your Ouroboros configuration.",
                    )),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_end()
                    .gap_2()
                    .px_4()
                    .py_3()
                    .border_t_1()
                    .border_color(tokens.line)
                    .child(
                        design::secondary_button("cancel-new", "Cancel").on_click(cx.listener(
                            |this, _, _, cx| {
                                this.show_new = false;
                                cx.notify();
                            },
                        )),
                    )
                    .child(
                        design::primary_button(
                            "start-new",
                            if can_start {
                                "Start session"
                            } else {
                                "Connect ChatGPT first"
                            },
                        )
                        .icon(IconName::ArrowRight)
                        .loading(starting)
                        .disabled(!can_start || starting)
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.start_session(window, cx);
                        })),
                    ),
            )
    }

    fn render_account(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let tokens = design::tokens(cx);
        let requires_chatgpt = if self.show_new {
            self.provider.read(cx).value().trim() == "native"
                && self
                    .model
                    .read(cx)
                    .value()
                    .trim()
                    .starts_with("openai_codex:")
        } else {
            self.app
                .as_ref()
                .and_then(|app| {
                    app.desktop_sessions()
                        .into_iter()
                        .find(|session| session.selected)
                })
                .is_some_and(|session| {
                    session.provider.as_deref() == Some("native")
                        && session
                            .model
                            .as_deref()
                            .is_some_and(|model| model.starts_with("openai_codex:"))
                })
        };
        if !requires_chatgpt {
            return None;
        }

        let account = self.app.as_ref()?.desktop_account();
        if account.usable {
            return None;
        }
        let pending = account.pending;
        let url = account.url.clone();
        let code = account.code.clone();
        let error = account.error.clone();
        let title = if !account.resolved {
            "Checking ChatGPT sign-in…"
        } else if pending {
            "Waiting for ChatGPT sign-in"
        } else {
            "ChatGPT sign-in required"
        };

        Some(
            design::card(tokens, cx, Tone::Warning)
                .flex()
                .flex_col()
                .gap_2()
                .w_full()
                .max_w(px(880.0))
                .mx_auto()
                .mt_3()
                .p_4()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .text_color(tokens.tone(cx, Tone::Warning).foreground)
                        .child(if pending || !account.resolved {
                            Spinner::new().small().into_any_element()
                        } else {
                            Icon::new(IconName::TriangleAlert).into_any_element()
                        })
                        .child(
                            div()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(title),
                        ),
                )
                .child(div().text_sm().text_color(tokens.ink_2).child(
                    "The selected openai_codex model uses ChatGPT subscription OAuth. Credentials remain private on the runtime host.",
                ))
                .when_some(code, |view, code| {
                    view.child(
                        div()
                            .text_lg()
                            .font_family("monospace")
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(format!("Device code · {code}")),
                    )
                })
                .when_some(url.clone(), |view, url| {
                    view.child(
                        div()
                            .text_xs()
                            .font_family("monospace")
                            .text_color(tokens.ink_3)
                            .child(url),
                    )
                })
                .when_some(error, |view, error| {
                    view.child(
                        div()
                            .text_sm()
                            .text_color(tokens.tone(cx, Tone::Danger).foreground)
                            .child(error),
                    )
                })
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .when_some(url, |row, url| {
                            row.child(
                                design::secondary_button(
                                    "open-chatgpt-login",
                                    "Open sign-in page",
                                )
                                    .icon(IconName::ExternalLink)
                                    .on_click(cx.listener(move |_, _, _, cx| {
                                        if url.starts_with("https://") {
                                            cx.open_url(&url);
                                        }
                                    })),
                            )
                        })
                        .when(!pending && account.resolved, |row| {
                            row.child(
                                design::primary_button(
                                    "start-chatgpt-login",
                                    "Connect ChatGPT",
                                )
                                    .icon(IconName::ArrowRight)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.start_chatgpt_login(cx);
                                    })),
                            )
                        })
                        .when(pending, |row| {
                            row.child(
                                design::secondary_button("cancel-chatgpt-login", "Cancel")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.cancel_chatgpt_login(cx);
                                    })),
                            )
                        }),
                )
                .into_any_element(),
        )
    }

    fn render_transcript(&self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = design::tokens(cx);
        let cells = self
            .app
            .as_ref()
            .map(App::desktop_transcript)
            .unwrap_or_default();
        let approval_pending = self.app.as_ref().and_then(App::desktop_approval).is_some();
        let mut cells = cells
            .into_iter()
            .filter(|cell| !(approval_pending && cell.label == "Approval needed"))
            .collect::<Vec<_>>();
        cells.dedup_by(|next, previous| {
            next.kind == previous.kind && next.label == previous.label && next.body == previous.body
        });
        let empty = cells.is_empty();
        let has_open_session = self
            .app
            .as_ref()
            .and_then(|app| app.sessions.open.as_ref())
            .is_some();
        let rendered_cells = cells
            .into_iter()
            .enumerate()
            .map(|(index, cell)| render_cell(index, cell, tokens, window, cx))
            .collect::<Vec<_>>();

        div()
            .id("transcript")
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .track_scroll(&self.transcript_scroll)
            .bg(tokens.page)
            .px_6()
            .py_4()
            .gap_1()
            .when(empty, |view| {
                view.items_center().justify_center().child(
                    design::empty_state(
                        tokens,
                        cx,
                        if self.show_new {
                            IconName::Settings2
                        } else if has_open_session {
                            IconName::Bot
                        } else {
                            IconName::GalleryVerticalEnd
                        },
                        if self.show_new {
                            "Configure your session"
                        } else if has_open_session {
                            "Ready when you are"
                        } else {
                            "Start a focused session"
                        },
                        if self.show_new {
                            "The session will appear here as soon as it starts."
                        } else if has_open_session {
                            "Send a message below to begin this session."
                        } else {
                            "Choose a workspace and model, then let Ouroboros keep the work visible."
                        },
                    )
                    .when(!has_open_session && !self.show_new, |state| {
                        state.child(
                            design::primary_button("empty-new-session", "New session")
                                .icon(IconName::Plus)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.show_new = true;
                                    this.action_error = None;
                                    cx.notify();
                                })),
                        )
                    }),
                )
            })
            .children(rendered_cells)
    }

    fn render_approval(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let tokens = design::tokens(cx);
        let approval = self.app.as_ref()?.desktop_approval()?;
        let request_id = approval.request_id.clone();
        let reason = approval
            .reason
            .clone()
            .filter(|reason| !approval.subject.contains(reason));
        let actions = div()
            .flex()
            .flex_wrap()
            .gap_2()
            .py_3()
            .border_y_1()
            .border_color(tokens.tone(cx, Tone::Warning).border)
            .children(
                approval
                    .choices
                    .into_iter()
                    .enumerate()
                    .map(|(index, choice)| {
                        let choice_for_click = choice.clone();
                        let request_id = request_id.clone();
                        let valid = choice.plan.is_some()
                            || (choice.decision.is_some() && choice.scope.is_some());
                        let button = match (choice.decision, choice.scope) {
                            (Some(ApprovalDecision::Approve), Some(ApprovalScope::Once)) => {
                                design::primary_button(("approval", index), choice.label)
                            }
                            (Some(ApprovalDecision::Deny), _) => {
                                design::danger_button(("approval", index), choice.label)
                            }
                            _ => design::secondary_button(("approval", index), choice.label),
                        };
                        button
                            .disabled(!valid)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.respond(request_id.clone(), choice_for_click.clone(), cx);
                            }))
                    }),
            );

        Some(
            design::card(tokens, cx, Tone::Warning)
                .id("approval-card")
                .flex()
                .flex_col()
                .gap_3()
                .w_full()
                .max_w(px(880.0))
                .mx_auto()
                .mb_3()
                .p_4()
                .max_h(px(420.0))
                .overflow_y_scroll()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(design::icon_tile(
                                    tokens,
                                    cx,
                                    Tone::Warning,
                                    IconName::TriangleAlert,
                                ))
                                .child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(
                                            div()
                                                .text_sm()
                                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                                .child("Approval required"),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(tokens.ink_2)
                                                .child("Review the exact scope before continuing"),
                                        ),
                                ),
                        )
                        .when_some(approval.kind.clone(), |row, kind| {
                            row.child(design::status_tag(tokens, cx, Tone::Warning, kind))
                        }),
                )
                .child(
                    div()
                        .text_sm()
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .child(approval.subject),
                )
                .when_some(approval.title, |view, title| {
                    view.child(
                        div()
                            .text_sm()
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .child(title),
                    )
                })
                .when_some(reason, |view, reason| {
                    view.child(div().text_sm().text_color(tokens.ink_2).child(reason))
                })
                .child(actions)
                .when_some(approval.command, |view, command| {
                    view.child(
                        design::inset(tokens)
                            .p_3()
                            .text_xs()
                            .font_family("monospace")
                            .text_color(tokens.ink)
                            .child(command),
                    )
                })
                .when_some(approval.cwd, |view, cwd| {
                    view.child(
                        div()
                            .text_xs()
                            .font_family("monospace")
                            .text_color(tokens.ink_3)
                            .child(cwd),
                    )
                })
                .when(!approval.locations.is_empty(), |view| {
                    view.child(
                        div()
                            .text_xs()
                            .font_family("monospace")
                            .text_color(tokens.ink_3)
                            .child(approval.locations.join("\n")),
                    )
                })
                .when_some(approval.diff, |view, diff| {
                    view.child(
                        design::inset(tokens)
                            .flex()
                            .flex_col()
                            .gap_2()
                            .p_3()
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_color(tokens.tone(cx, Tone::Warning).foreground)
                                    .child(diff.label),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .font_family("monospace")
                                    .whitespace_normal()
                                    .child(diff.text),
                            ),
                    )
                })
                .when(!approval.edits.is_empty(), |view| {
                    view.child(
                        div()
                            .text_xs()
                            .font_family("monospace")
                            .text_color(tokens.ink_3)
                            .child(approval.edits.join("\n")),
                    )
                })
                .when_some(approval.suggested_rule, |view, rule| {
                    view.child(
                        div()
                            .text_xs()
                            .text_color(tokens.ink_2)
                            .child(format!("Suggested remembered rule · {rule}")),
                    )
                })
                .into_any_element(),
        )
    }

    fn render_composer(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = design::tokens(cx);
        let selected = self.app.as_ref().and_then(|app| {
            app.desktop_sessions()
                .into_iter()
                .find(|session| session.selected)
        });
        let requires_chatgpt = selected.as_ref().is_some_and(|session| {
            session.provider.as_deref() == Some("native")
                && session
                    .model
                    .as_deref()
                    .is_some_and(|model| model.starts_with("openai_codex:"))
        });
        let account_usable = self
            .app
            .as_ref()
            .is_some_and(|app| app.desktop_account().usable);
        let can_send = selected
            .as_ref()
            .is_some_and(|session| session.plane == Plane::Interactive)
            && (!requires_chatgpt || account_usable);
        let working = selected
            .as_ref()
            .is_some_and(|session| session.triage == Triage::Working);
        let composer_empty = self.composer.read(cx).value().trim().is_empty();
        let session_context = selected
            .as_ref()
            .and_then(|session| session.model.clone())
            .unwrap_or_else(|| "Interactive session".to_string());
        div()
            .px_6()
            .pt_3()
            .pb_4()
            .border_t_1()
            .border_color(tokens.line)
            .bg(tokens.page)
            .child(
                design::panel(tokens)
                    .flex()
                    .flex_col()
                    .w_full()
                    .max_w(px(880.0))
                    .mx_auto()
                    .child(
                        div()
                            .flex()
                            .items_end()
                            .gap_2()
                            .p_2()
                            .child(
                                div().flex_1().min_w_0().px_1().child(
                                    Input::new(&self.composer)
                                        .appearance(false)
                                        .disabled(!can_send),
                                ),
                            )
                            .when(working, |row| {
                                row.child(
                                    design::secondary_button("interrupt", "Stop")
                                        .icon(IconName::CircleX)
                                        .tooltip("Interrupt the active turn · ⌘.")
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.interrupt(cx);
                                        })),
                                )
                            })
                            .child(
                                design::primary_button("send", "Send")
                                    .icon(IconName::ArrowUp)
                                    .tooltip("Send message · ⌘↩")
                                    .disabled(!can_send || composer_empty)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.send_message(window, cx)
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .px_3()
                            .py_2()
                            .border_t_1()
                            .border_color(tokens.line)
                            .text_xs()
                            .text_color(tokens.ink_3)
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .text_ellipsis()
                                    .child(session_context),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .when(working, |status| {
                                        status
                                            .text_color(tokens.accent)
                                            .child(Spinner::new().small().color(tokens.accent))
                                            .child("Agent working")
                                    })
                                    .when(!working, |status| {
                                        status.child("Send").child(design::keycap(tokens, "⌘↩"))
                                    }),
                            ),
                    ),
            )
    }
}

impl Render for DesktopView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = design::tokens(cx);
        let open_title = self
            .app
            .as_ref()
            .and_then(|app| app.sessions.open_info())
            .map(|session| format!("{} · {}", session.id, session.status.as_str()))
            .unwrap_or_else(|| "Ouroboros".to_string());
        let window_title = if open_title == "Ouroboros" {
            open_title.clone()
        } else {
            format!("{open_title} — Ouroboros")
        };
        window.set_window_title(&window_title);
        let header_title = self
            .app
            .as_ref()
            .and_then(|app| app.sessions.open_info())
            .map(|session| display_session_id(&session.id))
            .unwrap_or_else(|| "Ouroboros".to_string());
        let selected = self.app.as_ref().and_then(|app| {
            app.desktop_sessions()
                .into_iter()
                .find(|session| session.selected)
        });
        let header_eyebrow = selected
            .as_ref()
            .map(|session| format!("{} SESSION", session.plane.tag().to_uppercase()))
            .unwrap_or_else(|| "SESSION WORKSPACE".to_string());
        let header_meta = selected
            .as_ref()
            .map(|session| {
                [
                    session.provider.clone(),
                    session.model.clone(),
                    session.workspace.clone(),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" · ")
            })
            .filter(|meta| !meta.is_empty())
            .unwrap_or_else(|| "Select a session or create a new one".to_string());
        let notice = self
            .action_error
            .clone()
            .or_else(|| self.fatal.clone())
            .map(|text| (text, Tone::Danger))
            .or_else(|| {
                self.app
                    .as_ref()
                    .and_then(|app| app.notice.as_ref())
                    .and_then(|notice| match notice.kind {
                        // Routine acknowledgements already appear in the transcript and
                        // session status. Reserving alerts for warnings and failures keeps
                        // the high-attention surface meaningful.
                        NoticeKind::Info => None,
                        NoticeKind::Warn => Some((notice.text.clone(), Tone::Warning)),
                        NoticeKind::Error => Some((notice.text.clone(), Tone::Danger)),
                    })
            });
        let approval_pending = self.app.as_ref().and_then(App::desktop_approval).is_some();
        let connection_tone = match self.app.as_ref().map(|app| &app.connection) {
            Some(Connection::Live) => Tone::Success,
            Some(Connection::Lost { .. }) => Tone::Warning,
            None if self.fatal.is_some() => Tone::Danger,
            None => Tone::Accent,
        };
        let (connection_label, connection_detail, connection_icon) =
            match self.app.as_ref().map(|app| &app.connection) {
                Some(Connection::Live) => (
                    "Connected",
                    self.app
                        .as_ref()
                        .map(|app| format!("{} · {}", app.hello.node, app.hello.scope))
                        .unwrap_or_default(),
                    Icon::new(IconName::CircleCheck)
                        .text_color(tokens.tone(cx, Tone::Success).foreground)
                        .into_any_element(),
                ),
                Some(Connection::Lost { reason }) => (
                    "Reconnecting",
                    reason.clone(),
                    Spinner::new()
                        .small()
                        .color(tokens.tone(cx, Tone::Warning).foreground)
                        .into_any_element(),
                ),
                None if self.fatal.is_some() => (
                    "Offline",
                    "The local runtime could not start".to_string(),
                    Icon::new(IconName::CircleX)
                        .text_color(tokens.tone(cx, Tone::Danger).foreground)
                        .into_any_element(),
                ),
                None => (
                    "Connecting",
                    self.status.clone(),
                    Spinner::new()
                        .small()
                        .color(tokens.accent)
                        .into_any_element(),
                ),
            };

        div()
            .track_focus(&self.focus_handle)
            .capture_key_down(cx.listener(Self::handle_key_down))
            .flex()
            .size_full()
            .bg(tokens.page)
            .text_color(tokens.ink)
            .text_sm()
            .child(self.render_session_rail(cx))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .h(px(68.0))
                            .flex_none()
                            .px_6()
                            .border_b_1()
                            .border_color(tokens.line)
                            .bg(tokens.page)
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .flex_1()
                                    .min_w_0()
                                    .gap_1()
                                    .child(design::eyebrow(tokens, header_eyebrow))
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .text_ellipsis()
                                            .child(header_title),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(tokens.ink_3)
                                            .text_ellipsis()
                                            .child(header_meta),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .max_w(px(420.0))
                                    .child(connection_icon)
                                    .child(design::status_tag(
                                        tokens,
                                        cx,
                                        connection_tone,
                                        connection_label,
                                    ))
                                    .child(
                                        div()
                                            .max_w(px(240.0))
                                            .text_xs()
                                            .text_color(tokens.ink_3)
                                            .text_ellipsis()
                                            .child(connection_detail),
                                    ),
                            ),
                    )
                    .when(self.show_new, |view| {
                        view.child(self.render_new_session(cx))
                    })
                    .when_some(notice, |view, (notice, tone)| {
                        let alert = match tone {
                            Tone::Danger => Alert::error("desktop-notice", notice),
                            Tone::Warning => Alert::warning("desktop-notice", notice),
                            Tone::Accent => Alert::info("desktop-notice", notice),
                            Tone::Success => Alert::success("desktop-notice", notice),
                            Tone::Neutral => Alert::new("desktop-notice", notice),
                        };
                        view.child(
                            div()
                                .w_full()
                                .max_w(px(880.0))
                                .mx_auto()
                                .mt_3()
                                .child(alert.small()),
                        )
                    })
                    .children(self.render_account(cx))
                    .child(self.render_transcript(window, cx))
                    .children(self.render_approval(cx))
                    .when(!self.show_new && !approval_pending, |view| {
                        view.child(self.render_composer(cx))
                    }),
            )
    }
}

fn render_cell(
    index: usize,
    cell: DesktopCell,
    tokens: DesktopTokens,
    window: &mut Window,
    cx: &mut Context<DesktopView>,
) -> gpui::AnyElement {
    let tone = match cell.tone {
        DesktopTone::Neutral | DesktopTone::Muted => Tone::Neutral,
        DesktopTone::Accent => Tone::Accent,
        DesktopTone::Success => Tone::Success,
        DesktopTone::Warning => Tone::Warning,
        DesktopTone::Error => Tone::Danger,
    };
    let colors = tokens.tone(cx, tone);
    let label_color = if cell.tone == DesktopTone::Muted {
        tokens.ink_3
    } else {
        colors.foreground
    };
    let compact = matches!(
        cell.kind,
        DesktopCellKind::Divider | DesktopCellKind::Status | DesktopCellKind::Thinking
    );
    let mono = matches!(cell.kind, DesktopCellKind::Tool | DesktopCellKind::Diff);
    let rich_text = matches!(
        cell.kind,
        DesktopCellKind::Message
            | DesktopCellKind::Plan
            | DesktopCellKind::File
            | DesktopCellKind::Runtime
    );
    let icon = match cell.kind {
        DesktopCellKind::Message if cell.label.eq_ignore_ascii_case("you") => IconName::User,
        DesktopCellKind::Message => IconName::Bot,
        DesktopCellKind::Thinking => IconName::LoaderCircle,
        DesktopCellKind::Plan => IconName::GalleryVerticalEnd,
        DesktopCellKind::Tool => IconName::SquareTerminal,
        DesktopCellKind::File => IconName::File,
        DesktopCellKind::Diff => IconName::Replace,
        DesktopCellKind::Runtime => IconName::Settings2,
        DesktopCellKind::Status => IconName::Info,
        DesktopCellKind::Divider => IconName::Dash,
    };
    let body = cell.body;

    div()
        .flex()
        .gap_3()
        .w_full()
        .max_w(px(880.0))
        .mx_auto()
        .px_2()
        .py(if compact { px(8.0) } else { px(12.0) })
        .rounded(tokens.radius)
        .when(cell.tone == DesktopTone::Accent, |row| {
            row.bg(colors.background)
                .border_1()
                .border_color(colors.border)
        })
        .child(design::icon_tile(tokens, cx, tone, icon))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w_0()
                .gap_2()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .text_xs()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(label_color)
                        .child(cell.label)
                        .when(cell.streaming, |row| {
                            row.child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_1()
                                    .font_weight(gpui::FontWeight::NORMAL)
                                    .text_color(tokens.accent)
                                    .child(Spinner::new().small().color(tokens.accent))
                                    .child("Working"),
                            )
                        }),
                )
                .when(!body.trim().is_empty(), |view| {
                    if mono {
                        view.child(
                            design::inset(tokens)
                                .p_3()
                                .text_sm()
                                .font_family("monospace")
                                .whitespace_normal()
                                .child(body),
                        )
                    } else if rich_text {
                        view.child(
                            TextView::markdown(("transcript-markdown", index), body, window, cx)
                                .selectable(true)
                                .w_full()
                                .text_sm(),
                        )
                    } else {
                        view.child(
                            div()
                                .text_sm()
                                .whitespace_normal()
                                .text_color(if cell.tone == DesktopTone::Muted {
                                    tokens.ink_2
                                } else {
                                    tokens.ink
                                })
                                .child(body),
                        )
                    }
                }),
        )
        .into_any_element()
}

fn display_session_id(id: &str) -> String {
    const HEAD: usize = 15;
    const TAIL: usize = 8;
    const MAX: usize = HEAD + TAIL + 1;

    let count = id.chars().count();
    if count <= MAX {
        return id.to_string();
    }

    let head = id.chars().take(HEAD).collect::<String>();
    let tail = id
        .chars()
        .rev()
        .take(TAIL)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_remote_endpoint_requires_a_token_file() {
        let options = LaunchOptions {
            dev: false,
            addr: Some("127.0.0.1:7777".parse().unwrap()),
            token_file: None,
        };
        let (_tx, rx) = mpsc::channel::<DriverEvent>();
        drop(rx);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime.block_on(endpoint(&options, &_tx)).unwrap_err();
        assert!(format!("{error:#}").contains("requires --token-file"));
    }

    #[test]
    fn launcher_errors_are_bounded_to_their_tail() {
        let output = vec![b'x'; LAUNCHER_ERROR_LIMIT + 37];
        let tail = output_tail(&output);
        assert!(tail.starts_with("… 37 earlier bytes omitted …\n"));
        assert!(tail.len() < LAUNCHER_ERROR_LIMIT + 128);
    }

    #[test]
    fn long_session_ids_keep_their_recognisable_ends() {
        assert_eq!(display_session_id("short-session"), "short-session");
        assert_eq!(
            display_session_id("ouro-session-f99c08009a6c9ac5d14171ff20f5cccd"),
            "ouro-session-f9…20f5cccd"
        );
    }
}
