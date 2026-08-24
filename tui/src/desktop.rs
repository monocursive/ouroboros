//! GPUI desktop client.
//!
//! GPUI owns pixels and native input. [`crate::ui::app::App`] still owns protocol
//! decisions. A Tokio connection driver lives on one background thread and sends the
//! reducer the same `Msg` values as the terminal driver; every native action calls a
//! semantic method on that reducer and drains its ordinary `Call` queue.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use gpui::{
    actions, div, prelude::*, px, rgb, size, uniform_list, App as GpuiApp, Application, Bounds,
    Context, Entity, FocusHandle, KeyBinding, KeyDownEvent, Menu, MenuItem, ScrollHandle,
    Subscription, SystemMenuType, Task, Timer, TitlebarOptions, UniformListScrollHandle, Window,
    WindowBounds, WindowOptions,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputState};
use gpui_component::{Disableable as _, Root};
use tokio::sync::mpsc as tokio_mpsc;

use crate::config;
use crate::model::{Plane, Triage};
use crate::runtime::{self, Paths};
use crate::transport::{self, Secret, TransportConfig};
use crate::ui::app::{
    App, Call, Connection, DesktopApprovalChoice, DesktopCell, DesktopCellKind, DesktopTone, Mode,
    Msg,
};
use crate::ui::{self, TICK};

const BG: u32 = 0x0b0e14;
const PANEL: u32 = 0x111722;
const PANEL_RAISED: u32 = 0x171e2b;
const BORDER: u32 = 0x283244;
const TEXT: u32 = 0xe8edf5;
const MUTED: u32 = 0x8d98aa;
const CYAN: u32 = 0x55c2d9;
const AMBER: u32 = 0xf0b35b;
const GREEN: u32 = 0x62c99a;
const RED: u32 = 0xf07878;
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

    Application::new().run(move |cx: &mut GpuiApp| {
        gpui_component::init(cx);
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
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let workspace = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Absolute workspace path")
                .default_value(workspace_value)
        });

        let poll = cx.spawn(async move |view, cx| loop {
            Timer::after(TICK).await;
            let Some(view) = view.upgrade() else {
                break;
            };
            if view
                .update(cx, |this, cx| {
                    this.poll();
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
            _subscriptions: Vec::new(),
            _poll: poll,
        }
    }

    fn poll(&mut self) {
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

        if let Some(app) = self.app.as_mut() {
            app.apply(Msg::Tick);
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
        let rows = self
            .app
            .as_ref()
            .map(App::desktop_sessions)
            .unwrap_or_default();
        let rows = Arc::new(rows);

        div()
            .flex()
            .flex_col()
            .w(px(280.0))
            .h_full()
            .flex_none()
            .bg(rgb(PANEL))
            .border_r_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .h(px(56.0))
                    .px_4()
                    .border_b_1()
                    .border_color(rgb(BORDER))
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("Sessions"),
                    )
                    .child(
                        Button::new("new-session")
                            .compact()
                            .primary()
                            .label("New")
                            .disabled(self.app.is_none())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.show_new = !this.show_new;
                                this.action_error = None;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                uniform_list(
                    "session-rail",
                    rows.len(),
                    cx.processor(move |_this, range: Range<usize>, _window, cx| {
                        range
                            .filter_map(|index| rows.get(index).cloned().map(|row| (index, row)))
                            .map(|(index, row)| {
                                let id = row.id.clone();
                                let plane = row.plane;
                                let selected = row.selected;
                                let triage_color = match row.triage {
                                    Triage::NeedsInput => rgb(AMBER),
                                    Triage::Working => rgb(CYAN),
                                    Triage::Done => rgb(MUTED),
                                };
                                div()
                                    .id(("session", index))
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .mx_2()
                                    .mt_1()
                                    .px_3()
                                    .py_2()
                                    .ml(px((row.depth as f32) * 14.0))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .bg(if selected {
                                        rgb(PANEL_RAISED)
                                    } else {
                                        rgb(PANEL)
                                    })
                                    .border_1()
                                    .border_color(if selected { rgb(CYAN) } else { rgb(PANEL) })
                                    .hover(|style| style.bg(rgb(PANEL_RAISED)))
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.select_session(plane, id.clone(), window, cx);
                                    }))
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .child(
                                                div()
                                                    .text_sm()
                                                    .font_weight(gpui::FontWeight::MEDIUM)
                                                    .child(row.id),
                                            )
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(triage_color)
                                                    .child(row.status),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(rgb(MUTED))
                                            .text_ellipsis()
                                            .child(format!(
                                                "{}{}{}",
                                                row.plane.tag(),
                                                row.provider
                                                    .map(|provider| format!(" · {provider}"))
                                                    .unwrap_or_default(),
                                                if row.pending_approvals > 0 {
                                                    " · approval"
                                                } else {
                                                    ""
                                                }
                                            )),
                                    )
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .track_scroll(self.session_scroll.clone())
                .flex_1(),
            )
    }

    fn render_new_session(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_4()
            .mx_5()
            .mt_4()
            .rounded_lg()
            .bg(rgb(PANEL_RAISED))
            .border_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .text_lg()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("New interactive session"),
            )
            .child(div().text_sm().text_color(rgb(MUTED)).child(
                "Provider, model, and workspace are explicit. Approval and sandbox defaults come from config.toml.",
            ))
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(div().flex_1().child(Input::new(&self.provider)))
                    .child(div().flex_1().child(Input::new(&self.model))),
            )
            .child(Input::new(&self.workspace))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("cancel-new")
                            .label("Cancel")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.show_new = false;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("start-new")
                            .primary()
                            .label("Start session")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.start_session(window, cx);
                            })),
                    ),
            )
    }

    fn render_transcript(&self) -> impl IntoElement {
        let cells = self
            .app
            .as_ref()
            .map(App::desktop_transcript)
            .unwrap_or_default();
        let empty = cells.is_empty();

        div()
            .id("transcript")
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .track_scroll(&self.transcript_scroll)
            .px_5()
            .py_4()
            .gap_3()
            .when(empty, |view| {
                view.items_center().justify_center().child(
                    div().text_color(rgb(MUTED)).child(
                        if self
                            .app
                            .as_ref()
                            .and_then(|app| app.sessions.open.as_ref())
                            .is_some()
                        {
                            "This session has no retained transcript yet."
                        } else {
                            "Choose a session, or start a new one."
                        },
                    ),
                )
            })
            .children(cells.into_iter().map(render_cell))
    }

    fn render_approval(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let approval = self.app.as_ref()?.desktop_approval()?;
        let request_id = approval.request_id.clone();

        Some(
            div()
                .id("approval-card")
                .flex()
                .flex_col()
                .gap_2()
                .mx_5()
                .mb_3()
                .p_4()
                .max_h(px(360.0))
                .overflow_y_scroll()
                .rounded_lg()
                .bg(rgb(0x211b12))
                .border_1()
                .border_color(rgb(AMBER))
                .child(
                    div()
                        .text_sm()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(rgb(AMBER))
                        .child("Approval required"),
                )
                .child(div().text_sm().child(approval.subject))
                .when_some(approval.title, |view, title| {
                    view.child(
                        div()
                            .text_sm()
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .child(title),
                    )
                })
                .when_some(approval.kind, |view, kind| {
                    view.child(
                        div()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child(format!("Kind · {kind}")),
                    )
                })
                .when_some(approval.reason, |view, reason| {
                    view.child(div().text_xs().text_color(rgb(MUTED)).child(reason))
                })
                .when_some(approval.command, |view, command| {
                    view.child(
                        div()
                            .text_xs()
                            .font_family("monospace")
                            .text_color(rgb(TEXT))
                            .child(command),
                    )
                })
                .when_some(approval.cwd, |view, cwd| {
                    view.child(
                        div()
                            .text_xs()
                            .font_family("monospace")
                            .text_color(rgb(MUTED))
                            .child(cwd),
                    )
                })
                .when(!approval.locations.is_empty(), |view| {
                    view.child(
                        div()
                            .text_xs()
                            .font_family("monospace")
                            .text_color(rgb(MUTED))
                            .child(approval.locations.join("\n")),
                    )
                })
                .when_some(approval.diff, |view, diff| {
                    view.child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .p_3()
                            .rounded_md()
                            .bg(rgb(BG))
                            .border_1()
                            .border_color(rgb(BORDER))
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_color(rgb(AMBER))
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
                            .text_color(rgb(MUTED))
                            .child(approval.edits.join("\n")),
                    )
                })
                .when_some(approval.suggested_rule, |view, rule| {
                    view.child(
                        div()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child(format!("Suggested remembered rule · {rule}")),
                    )
                })
                .child(
                    div().flex().flex_wrap().gap_2().children(
                        approval
                            .choices
                            .into_iter()
                            .enumerate()
                            .map(|(index, choice)| {
                                let choice_for_click = choice.clone();
                                let request_id = request_id.clone();
                                Button::new(("approval", index))
                                    .compact()
                                    .label(choice.label)
                                    .disabled(
                                        choice.plan.is_none()
                                            && (choice.decision.is_none()
                                                || choice.scope.is_none()),
                                    )
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.respond(
                                            request_id.clone(),
                                            choice_for_click.clone(),
                                            cx,
                                        );
                                    }))
                            }),
                    ),
                )
                .into_any_element(),
        )
    }

    fn render_composer(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let can_send = self
            .app
            .as_ref()
            .and_then(|app| app.sessions.open.as_ref())
            .is_some_and(|(plane, _)| *plane == Plane::Interactive);
        div()
            .flex()
            .gap_3()
            .items_end()
            .p_4()
            .border_t_1()
            .border_color(rgb(BORDER))
            .bg(rgb(PANEL))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .child(Input::new(&self.composer).disabled(!can_send)),
            )
            .child(
                Button::new("interrupt")
                    .label("Interrupt")
                    .disabled(!can_send)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.interrupt(cx);
                    })),
            )
            .child(
                Button::new("send")
                    .primary()
                    .label("Send")
                    .disabled(!can_send)
                    .on_click(cx.listener(|this, _, window, cx| this.send_message(window, cx))),
            )
    }
}

impl Render for DesktopView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
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
        let notice = self
            .action_error
            .clone()
            .or_else(|| self.fatal.clone())
            .or_else(|| {
                self.app
                    .as_ref()
                    .and_then(|app| app.notice.as_ref())
                    .map(|notice| notice.text.clone())
            });
        let connection_color = match self.app.as_ref().map(|app| &app.connection) {
            Some(Connection::Live) => rgb(GREEN),
            Some(Connection::Lost { .. }) => rgb(AMBER),
            None if self.fatal.is_some() => rgb(RED),
            None => rgb(CYAN),
        };
        let status = match self.app.as_ref().map(|app| &app.connection) {
            Some(Connection::Lost { reason }) => format!("Reconnecting · {reason}"),
            _ => self.status.clone(),
        };

        div()
            .track_focus(&self.focus_handle)
            .capture_key_down(cx.listener(Self::handle_key_down))
            .flex()
            .size_full()
            .bg(rgb(BG))
            .text_color(rgb(TEXT))
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
                            .h(px(56.0))
                            .flex_none()
                            .px_5()
                            .border_b_1()
                            .border_color(rgb(BORDER))
                            .bg(rgb(PANEL))
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(open_title),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(div().size_2().rounded_full().bg(connection_color))
                                    .child(div().text_xs().text_color(rgb(MUTED)).child(status)),
                            ),
                    )
                    .when(self.show_new, |view| {
                        view.child(self.render_new_session(cx))
                    })
                    .when_some(notice, |view, notice| {
                        view.child(
                            div()
                                .mx_5()
                                .mt_3()
                                .px_3()
                                .py_2()
                                .rounded_md()
                                .bg(rgb(0x281719))
                                .border_1()
                                .border_color(rgb(RED))
                                .text_color(rgb(0xffb0b0))
                                .child(notice),
                        )
                    })
                    .child(self.render_transcript())
                    .children(self.render_approval(cx))
                    .child(self.render_composer(cx)),
            )
    }
}

fn render_cell(cell: DesktopCell) -> gpui::AnyElement {
    let (background, border, label_color) = match cell.tone {
        DesktopTone::Neutral => (PANEL, BORDER, TEXT),
        DesktopTone::Muted => (PANEL, BORDER, MUTED),
        DesktopTone::Accent => (0x171a16, 0x5c4930, AMBER),
        DesktopTone::Success => (0x122018, 0x295a42, GREEN),
        DesktopTone::Warning => (0x211b12, 0x6a5128, AMBER),
        DesktopTone::Error => (0x281719, 0x6c3036, RED),
    };
    let compact = matches!(
        cell.kind,
        DesktopCellKind::Divider | DesktopCellKind::Status | DesktopCellKind::Thinking
    );
    let mono = matches!(cell.kind, DesktopCellKind::Tool | DesktopCellKind::Diff);

    div()
        .flex()
        .flex_col()
        .gap_2()
        .px_4()
        .py(if compact { px(8.0) } else { px(12.0) })
        .rounded_lg()
        .bg(rgb(background))
        .border_1()
        .border_color(rgb(border))
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .text_xs()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .text_color(rgb(label_color))
                .child(cell.label)
                .when(cell.streaming, |row| {
                    row.child(div().text_color(rgb(CYAN)).child("● live"))
                }),
        )
        .when(!cell.body.trim().is_empty(), |view| {
            view.child(
                div()
                    .text_sm()
                    .line_height(px(20.0))
                    .whitespace_normal()
                    .when(mono, |body| body.font_family("monospace"))
                    .child(cell.body),
            )
        })
        .into_any_element()
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
}
