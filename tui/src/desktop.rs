//! GPUI desktop client.
//!
//! GPUI owns pixels and native input. [`crate::ui::app::App`] still owns protocol
//! decisions. A Tokio connection driver lives on one background thread and sends the
//! reducer the same `Msg` values as the terminal driver; every native action calls a
//! semantic method on that reducer and drains its ordinary `Call` queue.

use std::collections::HashSet;
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
    Entity, FocusHandle, Focusable as _, KeyBinding, KeyDownEvent, Menu, MenuItem, ScrollHandle,
    Subscription, SystemMenuType, Task, Timer, TitlebarOptions, UniformListScrollHandle, Window,
    WindowBounds, WindowOptions,
};
use gpui_component::alert::Alert;
use gpui_component::button::{ButtonVariant, ButtonVariants as _};
use gpui_component::dialog::DialogButtonProps;
use gpui_component::input::{Enter as InputEnter, Input, InputEvent, InputState};
use gpui_component::menu::{ContextMenuExt as _, DropdownMenu as _, PopupMenuItem};
use gpui_component::spinner::Spinner;
use gpui_component::text::TextView;
use gpui_component::tooltip::Tooltip;
use gpui_component::{Disableable as _, Icon, IconName, Root, Sizable as _, WindowExt as _};
use gpui_component_assets::Assets as ComponentAssets;
use tokio::sync::mpsc as tokio_mpsc;

use crate::config;
use crate::desktop_design::{self as design, DesktopTokens, Tone};
use crate::model::{ApprovalDecision, ApprovalScope, Plane, SandboxMode, Triage};
use crate::runtime::{self, Paths};
use crate::transport::{self, Secret, TransportConfig};
use crate::ui::app::{
    App, Call, Connection, DesktopApprovalChoice, DesktopCell, DesktopCellKind, DesktopTone, Mode,
    Msg, NoticeKind,
};
use crate::ui::{self, TICK};

const LAUNCHER_ERROR_LIMIT: usize = 16 * 1024;
const COLLAPSED_TOOL_LINES: usize = 12;
const COLLAPSED_TOOL_HEAD_LINES: usize = 7;
const COLLAPSED_TOOL_TAIL_LINES: usize = 4;
const COLLAPSED_TOOL_CHARS: usize = 2_400;
const COLLAPSED_TOOL_HEAD_CHARS: usize = 1_600;
const COLLAPSED_TOOL_TAIL_CHARS: usize = 600;
#[cfg(target_os = "macos")]
const MACOS_APP_ICON: &str = "Ouroboros.icns";

actions!(ouro_desktop, [QuitDesktop, SubmitComposer]);

fn composer_key_bindings() -> [KeyBinding; 3] {
    [
        KeyBinding::new("enter", SubmitComposer, Some("Input")),
        KeyBinding::new("secondary-enter", SubmitComposer, Some("Input")),
        KeyBinding::new(
            "shift-enter",
            InputEnter { secondary: false },
            Some("Input"),
        ),
    ]
}

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
            #[cfg(target_os = "macos")]
            if let Err(error) = install_macos_application_icon() {
                eprintln!("warning: could not install the bundled app icon: {error:#}");
            }

            gpui_component::init(cx);
            design::install_component_theme(cx);
            // These are registered after gpui-component's defaults so the chat composer can
            // override multiline Enter without changing the behavior of the other inputs.
            cx.bind_keys(composer_key_bindings());
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

#[cfg(target_os = "macos")]
fn bundled_macos_icon_path(executable: &Path) -> Option<PathBuf> {
    let macos = executable.parent()?;
    if macos.file_name()? != "MacOS" {
        return None;
    }
    let contents = macos.parent()?;
    if contents.file_name()? != "Contents" {
        return None;
    }
    Some(contents.join("Resources").join(MACOS_APP_ICON))
}

#[cfg(target_os = "macos")]
fn install_macos_application_icon() -> Result<()> {
    use cocoa::appkit::{NSApp, NSApplication, NSImage};
    use cocoa::base::{id, nil};
    use cocoa::foundation::{NSAutoreleasePool, NSString};

    let executable = std::env::current_exe().context("locating the desktop executable")?;
    let Some(icon_path) = bundled_macos_icon_path(&executable) else {
        return Ok(());
    };
    if !icon_path.is_file() {
        return Ok(());
    }
    let icon_path = icon_path
        .to_str()
        .ok_or_else(|| anyhow!("the bundled app icon path is not valid UTF-8"))?;

    // GPUI creates NSApplication before invoking this callback. Assigning the bundle image
    // explicitly keeps a direct Contents/MacOS launch from inheriting AppKit's placeholder.
    unsafe {
        let native_path: id = NSString::alloc(nil).init_str(icon_path).autorelease();
        let image: id = NSImage::alloc(nil)
            .initWithContentsOfFile_(native_path)
            .autorelease();
        if image == nil {
            bail!("AppKit could not read {icon_path}");
        }
        let app = NSApp();
        if app == nil {
            bail!("AppKit has no shared application");
        }
        app.setApplicationIconImage_(image);
    }

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
    rename: Entity<InputState>,
    /// The new-session form's file-access answer. `None` until the operator picks one, so
    /// an untouched form still starts the session the stored configuration describes —
    /// including the case where it describes nothing and the plane decides.
    new_sandbox: Option<SandboxMode>,
    show_new: bool,
    action_error: Option<String>,
    transcript_scroll: ScrollHandle,
    session_scroll: UniformListScrollHandle,
    transcript_len: usize,
    expanded_tool_cells: HashSet<String>,
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
        let rename = cx.new(|cx| InputState::new(window, cx).placeholder("Session name"));
        let mut subscriptions = Vec::new();
        for input in [
            composer.clone(),
            provider.clone(),
            model.clone(),
            workspace.clone(),
            rename.clone(),
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
            rename,
            new_sandbox: None,
            show_new: false,
            action_error: None,
            transcript_scroll: ScrollHandle::new(),
            session_scroll: UniformListScrollHandle::new(),
            transcript_len: 0,
            expanded_tool_cells: HashSet::new(),
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
            self.expanded_tool_cells.clear();
            self.transcript_scroll.scroll_to_bottom();
            self.action_error = None;
            self.flush_calls();
            cx.notify();
        }
    }

    fn rename_session(
        &mut self,
        plane: Plane,
        id: &str,
        title: &str,
        cx: &mut Context<Self>,
    ) -> bool {
        let result = self
            .app
            .as_mut()
            .ok_or_else(|| "the runtime is not connected yet".to_string())
            .and_then(|app| app.desktop_rename_session(plane, id, title));

        match result {
            Ok(()) => {
                self.action_error = None;
                self.flush_calls();
                cx.notify();
                true
            }
            Err(error) => {
                self.action_error = Some(error);
                cx.notify();
                false
            }
        }
    }

    fn delete_session(&mut self, plane: Plane, id: &str, cx: &mut Context<Self>) -> bool {
        let result = self
            .app
            .as_mut()
            .ok_or_else(|| "the runtime is not connected yet".to_string())
            .and_then(|app| app.desktop_delete_session(plane, id));

        match result {
            Ok(()) => {
                self.action_error = None;
                self.flush_calls();
                cx.notify();
                true
            }
            Err(error) => {
                self.action_error = Some(error);
                cx.notify();
                false
            }
        }
    }

    fn open_rename_dialog(
        &mut self,
        plane: Plane,
        id: String,
        current_title: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.action_error = None;
        self.rename.update(cx, |input, cx| {
            input.set_value(current_title.unwrap_or_default(), window, cx)
        });

        let input = self.rename.clone();
        let view = cx.entity().downgrade();
        let dialog_id = id.clone();
        window.open_dialog(cx, move |dialog, _window, cx| {
            let tokens = design::tokens(cx);
            let error = view
                .read_with(cx, |this, _| this.action_error.clone())
                .ok()
                .flatten();
            let submit_input = input.clone();
            let submit_view = view.clone();
            let submit_id = id.clone();
            let close_view = view.clone();

            dialog
                .title(format!("Rename {}", display_session_id(&dialog_id)))
                .confirm()
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("Rename")
                        .cancel_text("Cancel"),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(
                            div()
                                .text_sm()
                                .text_color(tokens.ink_2)
                                .child("Give this session a short, recognisable name."),
                        )
                        .child(design::field(
                            tokens,
                            "Session name",
                            Some("Up to 120 characters".into()),
                            Input::new(&input).cleanable(true),
                        ))
                        .when_some(error, |content, error| {
                            content.child(Alert::error("rename-session-error", error).small())
                        }),
                )
                .on_ok(move |_, window, cx| {
                    let title = submit_input.read(cx).value().to_string();
                    let accepted = submit_view
                        .update(cx, |this, cx| {
                            this.rename_session(plane, &submit_id, &title, cx)
                        })
                        .unwrap_or(false);
                    if !accepted {
                        window.refresh();
                    }
                    accepted
                })
                .on_close(move |_, _, cx| {
                    let _ = close_view.update(cx, |this, cx| {
                        this.action_error = None;
                        cx.notify();
                    });
                })
        });

        let focus_input = self.rename.clone();
        window.defer(cx, move |window, cx| {
            focus_input.update(cx, |input, cx| input.focus(window, cx));
        });
    }

    fn open_delete_dialog(
        &mut self,
        plane: Plane,
        id: String,
        title: String,
        last_known: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.action_error = None;
        let view = cx.entity().downgrade();
        window.open_dialog(cx, move |dialog, _window, cx| {
            let tokens = design::tokens(cx);
            let error = view
                .read_with(cx, |this, _| this.action_error.clone())
                .ok()
                .flatten();
            let submit_view = view.clone();
            let submit_id = id.clone();
            let close_view = view.clone();
            let detail = if last_known {
                "Its owner is offline. This hides the last-known row in this client; the durable record remains on its machine."
            } else {
                "This permanently removes the completed session from its owner. This cannot be undone by reconnecting."
            };

            dialog
                .title(if last_known {
                    "Hide offline session?"
                } else {
                    "Delete session?"
                })
                .confirm()
                .button_props(
                    DialogButtonProps::default()
                        .ok_text(if last_known { "Hide session" } else { "Delete session" })
                        .ok_variant(ButtonVariant::Danger)
                        .cancel_text("Cancel"),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w_0()
                        .gap_3()
                        .child(
                            div()
                                .min_w_0()
                                .text_sm()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .whitespace_normal()
                                .child(title.clone()),
                        )
                        .child(div().text_sm().text_color(tokens.ink_2).child(detail))
                        .when_some(error, |content, error| {
                            content.child(Alert::error("delete-session-error", error).small())
                        }),
                )
                .on_ok(move |_, window, cx| {
                    let accepted = submit_view
                        .update(cx, |this, cx| this.delete_session(plane, &submit_id, cx))
                        .unwrap_or(false);
                    if !accepted {
                        window.refresh();
                    }
                    accepted
                })
                .on_close(move |_, _, cx| {
                    let _ = close_view.update(cx, |this, cx| {
                        this.action_error = None;
                        cx.notify();
                    });
                })
        });
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

    fn submit_composer(&mut self, _: &SubmitComposer, window: &mut Window, cx: &mut Context<Self>) {
        if self.composer.focus_handle(cx).is_focused(window) {
            self.send_message(window, cx);
        } else {
            // The binding shares gpui-component's Input context. Let the component's
            // ordinary Enter action handle every field except the chat composer.
            cx.propagate();
        }
    }

    fn start_session(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let provider = self.provider.read(cx).value().to_string();
        let model = self.model.read(cx).value().to_string();
        let workspace = self.workspace.read(cx).value().to_string();
        let sandbox = self.new_sandbox;
        let result = self
            .app
            .as_mut()
            .ok_or_else(|| "the runtime is not connected yet".to_string())
            .and_then(|app| {
                app.desktop_start_session(
                    provider,
                    (!model.trim().is_empty()).then_some(model),
                    workspace,
                    sandbox,
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

    /// Switches the open session's client-side auto-approve mode. The reducer answers
    /// the pending backlog inside the call, so the flush right after it is what actually
    /// clears an approval card the window is showing.
    fn set_auto_approve(&mut self, on: bool, cx: &mut Context<Self>) {
        let result = match self.app.as_mut() {
            None => Err("the runtime is not connected".to_string()),
            Some(app) => app.desktop_set_auto_approve(on),
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

    /// Moves the open session's file-access posture. The label does not follow until the
    /// runtime's answer re-lists the session, so what the trigger shows is always a
    /// posture the runtime confirmed rather than the one this window asked for.
    fn set_sandbox_mode(&mut self, mode: SandboxMode, cx: &mut Context<Self>) {
        let result = match self.app.as_mut() {
            None => Err("the runtime is not connected".to_string()),
            Some(app) => app.desktop_set_sandbox_mode(mode),
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
        let key = event.keystroke.key.as_str();

        if !modifiers.platform || modifiers.control || modifiers.alt || modifiers.shift {
            return;
        }

        let handled = match key {
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
        let desktop_view = cx.entity().downgrade();

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
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
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
                                    .flex_1()
                                    .min_w_0()
                                    .overflow_hidden()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .truncate()
                                            .child("Ouroboros"),
                                    )
                                    .child(design::eyebrow(tokens, "WORKSPACE")),
                            ),
                    )
                    .child(
                        design::secondary_button("new-session", "New")
                            .flex_none()
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
                                        let desktop_view = desktop_view.clone();
                                        range
                                            .filter_map(|index| {
                                                rows.get(index).cloned().map(|row| (index, row))
                                            })
                                            .map(move |(index, row)| {
                                                let id = row.id.clone();
                                                let plane = row.plane;
                                                let selected = row.selected;
                                                let current_title = row.title.clone();
                                                let can_rename = row.can_rename;
                                                let can_delete = row.can_delete;
                                                let terminal = row.terminal;
                                                let last_known = row.last_known;
                                                let triage_tone = match row.triage {
                                                    Triage::NeedsInput => Tone::Warning,
                                                    Triage::Working => Tone::Accent,
                                                    Triage::Done => Tone::Neutral,
                                                };
                                                let title = display_session_title(
                                                    row.title.as_deref(),
                                                    &row.id,
                                                );
                                                let full_title = row
                                                    .title
                                                    .clone()
                                                    .unwrap_or_else(|| row.id.clone());
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
                                                let select_id = id.clone();
                                                let rename_id = id.clone();
                                                let delete_id = id.clone();
                                                let delete_title = full_title.clone();
                                                let menu_view = desktop_view.clone();
                                                div()
                                                    .id(("session", index))
                                                    .flex()
                                                    .min_w_0()
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
                                                    .cursor_context_menu()
                                                    .on_click(cx.listener(
                                                        move |this, _, window, cx| {
                                                            this.select_session(
                                                                plane,
                                                                select_id.clone(),
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
                                                                            .id(("session-title", index))
                                                                            .flex_1()
                                                                            .min_w_0()
                                                                            .text_sm()
                                                                            .font_weight(
                                                                                gpui::FontWeight::MEDIUM,
                                                                            )
                                                                            .truncate()
                                                                            .child(title)
                                                                            .tooltip({
                                                                                let full_title = full_title.clone();
                                                                                move |window, cx| {
                                                                                    Tooltip::new(full_title.clone()).build(window, cx)
                                                                                }
                                                                            }),
                                                                    )
                                                                    .child(
                                                                        design::status_tag(
                                                                            tokens,
                                                                            cx,
                                                                            triage_tone,
                                                                            row.status,
                                                                        )
                                                                        .flex_none(),
                                                                    ),
                                                            )
                                                            .child(
                                                                div()
                                                                    .id(("session-meta", index))
                                                                    .w_full()
                                                                    .min_w_0()
                                                                    .text_xs()
                                                                    .text_color(tokens.ink_3)
                                                                    .truncate()
                                                                    .child(meta.clone())
                                                                    .tooltip(move |window, cx| {
                                                                        Tooltip::new(meta.clone()).build(window, cx)
                                                                    }),
                                                            ),
                                                    )
                                                    .context_menu(move |menu, _window, _cx| {
                                                        let rename_view = menu_view.clone();
                                                        let rename_id = rename_id.clone();
                                                        let rename_title = current_title.clone();
                                                        let delete_view = menu_view.clone();
                                                        let delete_id = delete_id.clone();
                                                        let delete_title = delete_title.clone();

                                                        let menu = menu
                                                            .min_w(px(190.0))
                                                            .item(
                                                                PopupMenuItem::new("Rename session…")
                                                                    .icon(IconName::ALargeSmall)
                                                                    .disabled(!can_rename)
                                                                    .on_click(move |_, window, cx| {
                                                                        let _ = rename_view.update(
                                                                            cx,
                                                                            |this, cx| {
                                                                                this.open_rename_dialog(
                                                                                    plane,
                                                                                    rename_id.clone(),
                                                                                    rename_title.clone(),
                                                                                    window,
                                                                                    cx,
                                                                                );
                                                                            },
                                                                        );
                                                                    }),
                                                            )
                                                            .item(
                                                                PopupMenuItem::new("Delete session…")
                                                                    .icon(IconName::Delete)
                                                                    .disabled(!can_delete)
                                                                    .on_click(move |_, window, cx| {
                                                                        let _ = delete_view.update(
                                                                            cx,
                                                                            |this, cx| {
                                                                                this.open_delete_dialog(
                                                                                    plane,
                                                                                    delete_id.clone(),
                                                                                    delete_title.clone(),
                                                                                    last_known,
                                                                                    window,
                                                                                    cx,
                                                                                );
                                                                            },
                                                                        );
                                                                    }),
                                                            );

                                                        if !terminal && !last_known {
                                                            menu.separator()
                                                                .label("Finish session to delete")
                                                        } else {
                                                            menu
                                                        }
                                                    })
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
                    .child("Right-click to manage")
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
        // What the form will actually send: the operator's pick, else the stored default,
        // else nothing — and "nothing" is drawn as itself rather than as a guessed row.
        let configured_sandbox = self
            .app
            .as_ref()
            .and_then(|app| app.config.defaults.sandbox_mode());
        let sandbox = self.new_sandbox.or(configured_sandbox);

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
                    .child(design::field(
                        tokens,
                        "File access",
                        Some(
                            if self.new_sandbox.is_some() {
                                "Your choice"
                            } else {
                                "From your configuration"
                            }
                            .into(),
                        ),
                        div().flex().flex_col().gap_2().children(
                            App::desktop_sandbox_choices().into_iter().enumerate().map(
                                |(index, mode)| {
                                    let chosen = sandbox == Some(mode);
                                    // The full-access row wears the warning tone whether or
                                    // not it is the current answer: it is a standing property
                                    // of that posture, not a highlight for having picked it.
                                    // Chosen rows are otherwise accent, the ordinary
                                    // "this is selected" language of the rest of the window.
                                    let tone = match (mode.warns(), chosen) {
                                        (true, _) => Tone::Warning,
                                        (false, true) => Tone::Accent,
                                        (false, false) => Tone::Neutral,
                                    };
                                    design::card(tokens, cx, tone)
                                        .id(("new-sandbox", index))
                                        .flex()
                                        .flex_col()
                                        .gap_0p5()
                                        .p_2()
                                        .when(!chosen, |row| row.bg(tokens.surface))
                                        .border_color(if chosen {
                                            tokens.tone(cx, tone).border
                                        } else {
                                            tokens.line
                                        })
                                        .hover(|style| style.bg(tokens.hover))
                                        .cursor_pointer()
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.new_sandbox = Some(mode);
                                            this.action_error = None;
                                            cx.notify();
                                        }))
                                        .child(
                                            div()
                                                .flex()
                                                .items_center()
                                                .gap_2()
                                                .text_sm()
                                                .font_weight(if chosen {
                                                    gpui::FontWeight::SEMIBOLD
                                                } else {
                                                    gpui::FontWeight::NORMAL
                                                })
                                                .when(mode.warns(), |title| {
                                                    title.text_color(
                                                        tokens.tone(cx, Tone::Warning).foreground,
                                                    )
                                                })
                                                .child(mode.title())
                                                .when(chosen, |title| {
                                                    title.child(
                                                        Icon::new(IconName::Check)
                                                            .small()
                                                            .text_color(tokens.ink_2),
                                                    )
                                                }),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(tokens.ink_3)
                                                .child(mode.describe()),
                                        )
                                },
                            ),
                        ),
                    ))
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.ink_3)
                            .child("Approval defaults come from your Ouroboros configuration."),
                    ),
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
            .map(|(index, cell)| {
                let expansion_key = (cell.kind == DesktopCellKind::Tool).then(|| {
                    cell.key
                        .clone()
                        .unwrap_or_else(|| format!("tool-row:{index}"))
                });
                let expanded = expansion_key
                    .as_ref()
                    .is_some_and(|key| self.expanded_tool_cells.contains(key));
                render_cell(index, cell, expanded, expansion_key, tokens, window, cx)
            })
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
        // Questions — the plan exit and `ask_user` — are the approvals auto-approve
        // never answers, so offering the mode from their card would be a button that
        // visibly does not do the thing it says. A card that survives with the mode
        // already on (a question, or a refused send reopened for a person) hides the
        // switch too: it is already flipped.
        let question = approval.question;
        let auto_approve_on = self
            .app
            .as_ref()
            .and_then(|app| app.desktop_auto_approve())
            .unwrap_or(false);
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
            )
            .when(!question && !auto_approve_on, |row| {
                row.child(
                    design::secondary_button("approval-auto-approve", "Auto-approve session")
                        .tooltip("Approve this and everything after it, for this session")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.set_auto_approve(true, cx);
                        })),
                )
            });

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
        let auto_approve = self.app.as_ref().and_then(|app| app.desktop_auto_approve());
        // Absent means the runtime named no posture for this session. The control is then
        // omitted rather than guessed at: a picker with a checked row is a claim about
        // what the agent may touch, and this client does not have one to make.
        let sandbox = self.app.as_ref().and_then(|app| app.desktop_sandbox_mode());
        let picker_view = cx.entity().downgrade();
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
                                    .tooltip("Send message · ↩")
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
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    // The approvals-mode picker, in the slot that already
                                    // narrates the session. Warning-variant while active:
                                    // a standing yes is a risk posture, not an action
                                    // highlight (docs/DESKTOP.md tone rule).
                                    .children(auto_approve.map(|on| {
                                        let picker_view = picker_view.clone();
                                        let trigger = if on {
                                            design::secondary_button(
                                                "approval-mode",
                                                "Auto-approve",
                                            )
                                            .warning()
                                        } else {
                                            design::secondary_button("approval-mode", "Ask first")
                                        };
                                        trigger
                                            .tooltip(
                                                "How this session's approval requests are answered",
                                            )
                                            .dropdown_menu(move |menu, _window, _cx| {
                                                let ask_view = picker_view.clone();
                                                let auto_view = picker_view.clone();
                                                menu.min_w(px(260.0))
                                                    .item(
                                                        PopupMenuItem::new("Ask first")
                                                            .checked(!on)
                                                            .on_click(move |_, _, cx| {
                                                                let _ = ask_view.update(
                                                                    cx,
                                                                    |this, cx| {
                                                                        this.set_auto_approve(
                                                                            false, cx,
                                                                        );
                                                                    },
                                                                );
                                                            }),
                                                    )
                                                    .item(
                                                        PopupMenuItem::new("Auto-approve")
                                                            .checked(on)
                                                            .on_click(move |_, _, cx| {
                                                                let _ = auto_view.update(
                                                                    cx,
                                                                    |this, cx| {
                                                                        this.set_auto_approve(
                                                                            true, cx,
                                                                        );
                                                                    },
                                                                );
                                                            }),
                                                    )
                                                    .separator()
                                                    .label("This session only; questions still ask")
                                            })
                                    }))
                                    // The OS sandbox, beside the approvals mode and read
                                    // the same way: what this session may touch, in the
                                    // runtime's own words. Warning-variant on full access
                                    // for the reason the row above wears it — a risk
                                    // posture, not an action highlight.
                                    .children(sandbox.map(|current| {
                                        let picker_view = picker_view.clone();
                                        let trigger =
                                            design::secondary_button("sandbox-mode", current.label());
                                        let trigger = if current.warns() {
                                            trigger.warning()
                                        } else {
                                            trigger
                                        };
                                        trigger
                                            .tooltip("What this session's shell may touch")
                                            .dropdown_menu(move |menu, _window, _cx| {
                                                let picker_view = picker_view.clone();
                                                App::desktop_sandbox_choices()
                                                    .into_iter()
                                                    .fold(
                                                        menu.min_w(px(280.0)),
                                                        move |menu, mode| {
                                                            let view = picker_view.clone();
                                                            menu.item(
                                                                PopupMenuItem::new(mode.title())
                                                                    .checked(mode == current)
                                                                    .on_click(move |_, _, cx| {
                                                                        let _ = view.update(
                                                                            cx,
                                                                            |this, cx| {
                                                                                this.set_sandbox_mode(
                                                                                    mode, cx,
                                                                                );
                                                                            },
                                                                        );
                                                                    }),
                                                            )
                                                        },
                                                    )
                                                    .separator()
                                                    .label("The runtime's own posture, for this session")
                                            })
                                    }))
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w_0()
                                            .text_ellipsis()
                                            .child(session_context),
                                    ),
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
                                        status
                                            .child("Send")
                                            .child(design::keycap(tokens, "↩"))
                                            .child(" · New line")
                                            .child(design::keycap(tokens, "⇧↩"))
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
            .map(|session| {
                format!(
                    "{} · {}",
                    session.title.as_deref().unwrap_or(session.id.as_str()),
                    session.status.as_str()
                )
            })
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
            .map(|session| display_session_title(session.title.as_deref(), &session.id))
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
            .on_action(cx.listener(Self::submit_composer))
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
    expanded: bool,
    expansion_key: Option<String>,
    tokens: DesktopTokens,
    window: &mut Window,
    cx: &mut Context<DesktopView>,
) -> gpui::AnyElement {
    match cell.kind {
        DesktopCellKind::Message if cell.label.eq_ignore_ascii_case("you") => {
            render_user_message(index, cell, tokens, window, cx)
        }
        DesktopCellKind::Message => render_agent_message(index, cell, tokens, window, cx),
        DesktopCellKind::Activity => render_agent_activity(cell, tokens, cx),
        DesktopCellKind::Divider => render_transcript_divider(cell, tokens, cx),
        _ => render_meta_cell(index, cell, expanded, expansion_key, tokens, window, cx),
    }
}

fn render_user_message(
    index: usize,
    cell: DesktopCell,
    tokens: DesktopTokens,
    window: &mut Window,
    cx: &mut Context<DesktopView>,
) -> gpui::AnyElement {
    div()
        .flex()
        .justify_end()
        .w_full()
        .max_w(px(880.0))
        .mx_auto()
        .py_2()
        .child(
            div()
                .flex()
                .items_end()
                .gap_2()
                .w_full()
                .max_w(px(680.0))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .items_end()
                        .flex_1()
                        .min_w_0()
                        .gap_1()
                        .child(
                            div()
                                .text_xs()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(tokens.ink_3)
                                .child(cell.label),
                        )
                        .child(
                            design::card(tokens, cx, Tone::Neutral)
                                .w_full()
                                .px_4()
                                .py_3()
                                .child(
                                    TextView::markdown(
                                        ("transcript-user-markdown", index),
                                        cell.body,
                                        window,
                                        cx,
                                    )
                                    .selectable(true)
                                    .w_full()
                                    .text_sm(),
                                ),
                        ),
                )
                .child(design::icon_tile(tokens, cx, Tone::Neutral, IconName::User)),
        )
        .into_any_element()
}

fn render_agent_message(
    index: usize,
    cell: DesktopCell,
    tokens: DesktopTokens,
    window: &mut Window,
    cx: &mut Context<DesktopView>,
) -> gpui::AnyElement {
    let metadata = Arc::new(cell.metadata);
    let has_metadata = !metadata.is_empty();
    let tooltip_metadata = metadata.clone();

    div()
        .flex()
        .justify_start()
        .w_full()
        .max_w(px(880.0))
        .mx_auto()
        .py_2()
        .child(
            div()
                .flex()
                .items_start()
                .gap_3()
                .w_full()
                .max_w(px(760.0))
                .child(design::icon_tile(tokens, cx, Tone::Accent, IconName::Bot))
                .child(
                    div()
                        .id(("agent-message", index))
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w_0()
                        .gap_1()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .text_xs()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(tokens.accent)
                                .child(cell.label)
                                .when(has_metadata, |row| {
                                    row.child(
                                        Icon::new(IconName::Info).xsmall().text_color(tokens.ink_3),
                                    )
                                })
                                .when(cell.streaming, |row| {
                                    row.child(Spinner::new().small().color(tokens.accent))
                                }),
                        )
                        .child(
                            design::card(tokens, cx, Tone::Accent).w_full().p_4().child(
                                TextView::markdown(
                                    ("transcript-agent-markdown", index),
                                    cell.body,
                                    window,
                                    cx,
                                )
                                .selectable(true)
                                .w_full()
                                .text_sm(),
                            ),
                        )
                        .when(has_metadata, move |message| {
                            message.tooltip(move |window, cx| {
                                let metadata = tooltip_metadata.clone();
                                Tooltip::element(move |_, cx| {
                                    let tokens = design::tokens(cx);
                                    div().flex().flex_col().gap_1().max_w(px(360.0)).children(
                                        metadata.iter().cloned().map(|line| {
                                            div()
                                                .text_xs()
                                                .text_color(tokens.ink_2)
                                                .whitespace_normal()
                                                .child(line)
                                        }),
                                    )
                                })
                                .build(window, cx)
                            })
                        }),
                ),
        )
        .into_any_element()
}

fn render_agent_activity(
    cell: DesktopCell,
    tokens: DesktopTokens,
    cx: &mut Context<DesktopView>,
) -> gpui::AnyElement {
    div()
        .flex()
        .justify_start()
        .w_full()
        .max_w(px(880.0))
        .mx_auto()
        .py_2()
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .max_w(px(760.0))
                .child(design::icon_tile(tokens, cx, Tone::Accent, IconName::Bot))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .px_3()
                        .py_2()
                        .rounded(tokens.radius)
                        .text_sm()
                        .text_color(tokens.ink_2)
                        .child(Spinner::new().small().color(tokens.accent))
                        .child(cell.label),
                ),
        )
        .into_any_element()
}

fn render_transcript_divider(
    cell: DesktopCell,
    tokens: DesktopTokens,
    cx: &mut Context<DesktopView>,
) -> gpui::AnyElement {
    let tone = desktop_tone(cell.tone);
    let label_color = match cell.tone {
        DesktopTone::Warning | DesktopTone::Error | DesktopTone::Success => {
            tokens.tone(cx, tone).foreground
        }
        _ => tokens.ink_3,
    };

    div()
        .flex()
        .items_center()
        .gap_3()
        .w_full()
        .max_w(px(760.0))
        .py_2()
        .child(div().h_px().flex_1().bg(tokens.line))
        .child(div().text_xs().text_color(label_color).child(cell.label))
        .child(div().h_px().flex_1().bg(tokens.line))
        .into_any_element()
}

fn render_meta_cell(
    index: usize,
    cell: DesktopCell,
    expanded: bool,
    expansion_key: Option<String>,
    tokens: DesktopTokens,
    window: &mut Window,
    cx: &mut Context<DesktopView>,
) -> gpui::AnyElement {
    let tone = desktop_tone(cell.tone);
    let colors = tokens.tone(cx, tone);
    let label_color = if cell.tone == DesktopTone::Muted {
        tokens.ink_3
    } else {
        colors.foreground
    };
    let mono = matches!(cell.kind, DesktopCellKind::Tool | DesktopCellKind::Diff);
    let rich_text = matches!(
        cell.kind,
        DesktopCellKind::Plan | DesktopCellKind::File | DesktopCellKind::Runtime
    );
    let icon = match cell.kind {
        DesktopCellKind::Message | DesktopCellKind::Activity => IconName::Bot,
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
    let preview = (cell.kind == DesktopCellKind::Tool)
        .then(|| collapsed_tool_body(&body))
        .flatten();
    let collapsible = preview.is_some();
    let shown_body = if expanded {
        body
    } else {
        preview
            .as_ref()
            .map(|preview| preview.body.clone())
            .unwrap_or(body)
    };
    let toggle_label = preview.as_ref().map(|preview| {
        if expanded {
            "Collapse output".to_string()
        } else {
            format!("Expand output · {}", preview.extent)
        }
    });

    div()
        .flex()
        .items_start()
        .gap_2()
        .w_full()
        .max_w(px(760.0))
        .py_1()
        .text_color(tokens.ink_2)
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .size_6()
                .flex_none()
                .text_color(label_color)
                .child(Icon::new(icon).small()),
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
                        .gap_2()
                        .text_xs()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(label_color)
                        .child(cell.label)
                        .when(cell.streaming, |row| {
                            row.child(Spinner::new().small().color(tokens.accent))
                        }),
                )
                .when(!shown_body.trim().is_empty(), |view| {
                    if mono {
                        let output = design::inset(tokens)
                            .id(("tool-output", index))
                            .px_3()
                            .py_2()
                            .text_xs()
                            .font_family("monospace")
                            .whitespace_normal()
                            .child(shown_body);
                        view.child(output.when(collapsible && expanded, |output| {
                            output.max_h(px(440.0)).overflow_y_scroll()
                        }))
                    } else if rich_text {
                        view.child(
                            TextView::markdown(
                                ("transcript-markdown", index),
                                shown_body,
                                window,
                                cx,
                            )
                            .selectable(true)
                            .w_full()
                            .text_xs(),
                        )
                    } else {
                        view.child(
                            div()
                                .text_xs()
                                .whitespace_normal()
                                .text_color(if cell.tone == DesktopTone::Muted {
                                    tokens.ink_2
                                } else {
                                    tokens.ink
                                })
                                .child(shown_body),
                        )
                    }
                })
                .when_some(toggle_label, |view, label| {
                    let expansion_key =
                        expansion_key.expect("a collapsible tool row always has an expansion key");
                    view.child(
                        div().flex().justify_end().child(
                            design::secondary_button(("tool-output-toggle", index), label)
                                .small()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    if !this.expanded_tool_cells.remove(&expansion_key) {
                                        this.expanded_tool_cells.insert(expansion_key.clone());
                                    }
                                    cx.notify();
                                })),
                        ),
                    )
                }),
        )
        .into_any_element()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollapsedToolBody {
    body: String,
    extent: String,
}

/// Keeps verbose tool results from owning the desktop transcript's layout by default.
/// The complete value remains in the cell and is rendered on explicit expansion.
fn collapsed_tool_body(body: &str) -> Option<CollapsedToolBody> {
    let lines = body.lines().collect::<Vec<_>>();
    let line_count = lines.len();
    let char_count = body.chars().count();
    if line_count <= COLLAPSED_TOOL_LINES && char_count <= COLLAPSED_TOOL_CHARS {
        return None;
    }

    let extent = if line_count > COLLAPSED_TOOL_LINES {
        format!(
            "{line_count} line{}",
            if line_count == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "{char_count} character{}",
            if char_count == 1 { "" } else { "s" }
        )
    };

    let line_preview = if line_count > COLLAPSED_TOOL_LINES {
        let hidden = line_count - COLLAPSED_TOOL_HEAD_LINES - COLLAPSED_TOOL_TAIL_LINES;
        let head = lines[..COLLAPSED_TOOL_HEAD_LINES].join("\n");
        let tail = lines[line_count - COLLAPSED_TOOL_TAIL_LINES..].join("\n");
        format!(
            "{head}\n… {hidden} line{} hidden …\n{tail}",
            if hidden == 1 { "" } else { "s" }
        )
    } else {
        body.to_string()
    };

    Some(CollapsedToolBody {
        body: collapse_tool_chars(&line_preview),
        extent,
    })
}

fn collapse_tool_chars(body: &str) -> String {
    let char_count = body.chars().count();
    if char_count <= COLLAPSED_TOOL_CHARS {
        return body.to_string();
    }

    let hidden = char_count - COLLAPSED_TOOL_HEAD_CHARS - COLLAPSED_TOOL_TAIL_CHARS;
    let head = body
        .chars()
        .take(COLLAPSED_TOOL_HEAD_CHARS)
        .collect::<String>();
    let tail = body
        .chars()
        .rev()
        .take(COLLAPSED_TOOL_TAIL_CHARS)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!(
        "{head}\n… {hidden} character{} hidden …\n{tail}",
        if hidden == 1 { "" } else { "s" }
    )
}

fn desktop_tone(tone: DesktopTone) -> Tone {
    match tone {
        DesktopTone::Neutral | DesktopTone::Muted => Tone::Neutral,
        DesktopTone::Accent => Tone::Accent,
        DesktopTone::Success => Tone::Success,
        DesktopTone::Warning => Tone::Warning,
        DesktopTone::Error => Tone::Danger,
    }
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

fn display_session_title(title: Option<&str>, id: &str) -> String {
    title
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| display_session_id(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composer_enter_bindings_separate_send_from_newline() {
        let [enter, secondary_enter, shift_enter] = composer_key_bindings();

        assert!(enter.action().partial_eq(&SubmitComposer));
        assert!(secondary_enter.action().partial_eq(&SubmitComposer));
        assert!(shift_enter
            .action()
            .partial_eq(&InputEnter { secondary: false }));
        assert_eq!(enter.keystrokes()[0].inner().unparse(), "enter");
        assert_eq!(
            secondary_enter.keystrokes()[0].inner().unparse(),
            gpui::Keystroke::parse("secondary-enter").unwrap().unparse()
        );
        assert_eq!(shift_enter.keystrokes()[0].inner().unparse(), "shift-enter");
    }

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

    #[test]
    fn a_session_title_replaces_the_generated_id_without_losing_the_fallback() {
        assert_eq!(
            display_session_title(Some("  Investigate the flaky build  "), "session-1"),
            "Investigate the flaky build"
        );
        assert_eq!(display_session_title(None, "session-1"), "session-1");
    }

    #[test]
    fn short_tool_output_stays_fully_visible() {
        assert_eq!(collapsed_tool_body("one\ntwo\nthree"), None);
    }

    #[test]
    fn long_tool_output_defaults_to_a_bounded_head_and_tail() {
        let body = (0..30)
            .map(|line| format!("result {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let preview = collapsed_tool_body(&body).expect("long output should collapse");

        assert_eq!(preview.extent, "30 lines");
        assert!(preview.body.starts_with("result 0\nresult 1"));
        assert!(preview.body.contains("… 19 lines hidden …"));
        assert!(preview.body.ends_with("result 29"));
        assert!(!preview.body.contains("result 15\n"));
        assert_eq!(preview.body.lines().count(), COLLAPSED_TOOL_LINES);
    }

    #[test]
    fn a_long_single_line_preview_is_unicode_safe_and_bounded() {
        let body = "🌀".repeat(COLLAPSED_TOOL_CHARS + 500);
        let preview = collapsed_tool_body(&body).expect("long output should collapse");

        assert_eq!(
            preview.extent,
            format!("{} characters", COLLAPSED_TOOL_CHARS + 500)
        );
        assert!(preview.body.contains("… 700 characters hidden …"));
        assert!(preview.body.chars().count() < COLLAPSED_TOOL_CHARS);
        assert!(preview.body.starts_with('🌀'));
        assert!(preview.body.ends_with('🌀'));
    }
}
