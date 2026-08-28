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
    actions, div, img, prelude::*, px, size, uniform_list, AnyElement, App as GpuiApp, Application,
    Bounds, Context, Entity, FocusHandle, Focusable as _, Image, ImageFormat, KeyBinding,
    KeyDownEvent, Menu, MenuItem, PathPromptOptions, ScrollHandle, SharedString, Subscription,
    SystemMenuType, Task, Timer, TitlebarOptions, UniformListScrollHandle, Window, WindowBounds,
    WindowOptions,
};
use gpui_component::alert::Alert;
use gpui_component::button::{ButtonVariant, ButtonVariants as _};
use gpui_component::checkbox::Checkbox;
use gpui_component::dialog::DialogButtonProps;
use gpui_component::input::{Enter as InputEnter, Input, InputEvent, InputState};
use gpui_component::menu::{ContextMenuExt as _, DropdownMenu as _, PopupMenuItem};
use gpui_component::resizable::{h_resizable, resizable_panel};
use gpui_component::select::{SearchableVec, Select, SelectEvent, SelectItem, SelectState};
use gpui_component::spinner::Spinner;
use gpui_component::switch::Switch;
use gpui_component::text::TextView;
use gpui_component::tooltip::Tooltip;
use gpui_component::{Disableable as _, Icon, IconName, Root, Sizable as _, WindowExt as _};
use gpui_component_assets::Assets as ComponentAssets;
use tokio::sync::mpsc as tokio_mpsc;

/// The Machines surface's state machine: fleet projection, form validation, and the card a
/// running deploy drives. Kept out of this file because none of it needs a window, which is
/// what lets it be tested without one.
mod machines;

use crate::config;
use crate::desktop_design::{self as design, DesktopTokens, Tone};
use crate::fleet::Profile as FleetProfile;
use crate::fleet_add::{spawn_add, AddEvent, AddHandle};
use crate::model::{
    ApprovalDecision, ApprovalScope, Effort, ModelsCatalog, Plane, ProviderEntry, SandboxMode,
    Triage,
};
use crate::runtime::{self, Paths};
use crate::transport::{self, Secret, TransportConfig};
use crate::ui::app::{
    provider_choices, App, Call, Connection, DesktopApprovalChoice, DesktopCell, DesktopCellKind,
    DesktopTone, Loadable, Mode, Msg, NoticeKind, ProviderChoice,
};
use crate::ui::{self, TICK};
use machines::{AddCard, AddForm, Phase as AddPhase, Presence, Stage, StageState};

const LAUNCHER_ERROR_LIMIT: usize = 16 * 1024;
const COLLAPSED_TOOL_LINES: usize = 12;
const COLLAPSED_TOOL_HEAD_LINES: usize = 7;
const COLLAPSED_TOOL_TAIL_LINES: usize = 4;
const COLLAPSED_TOOL_CHARS: usize = 2_400;
const COLLAPSED_TOOL_HEAD_CHARS: usize = 1_600;
const COLLAPSED_TOOL_TAIL_CHARS: usize = 600;
const DESKTOP_MIN_WIDTH: f32 = 860.0;
const SESSION_RAIL_DEFAULT_WIDTH: f32 = 276.0;
const SESSION_RAIL_MIN_WIDTH: f32 = 232.0;
const SESSION_RAIL_MAX_WIDTH: f32 = 520.0;
const SESSION_WORKSPACE_MIN_WIDTH: f32 = 520.0;
const _: () = {
    assert!(SESSION_RAIL_MIN_WIDTH < SESSION_RAIL_DEFAULT_WIDTH);
    assert!(SESSION_RAIL_DEFAULT_WIDTH < SESSION_RAIL_MAX_WIDTH);
    assert!(SESSION_RAIL_MIN_WIDTH + SESSION_WORKSPACE_MIN_WIDTH <= DESKTOP_MIN_WIDTH);
};
/// The three things the one composer can be, said in the box itself. Enter does something
/// different in each, and the placeholder is the only part of the control that can say so
/// before it is pressed.
const COMPOSER_MESSAGE_PLACEHOLDER: &str = "Message the open session…";
const COMPOSER_QUICK_START_PLACEHOLDER: &str = "Start a new session…";
const COMPOSER_UNAVAILABLE_PLACEHOLDER: &str = "Connect a runtime to start a session";
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
                    window_min_size: Some(size(px(DESKTOP_MIN_WIDTH), px(600.0))),
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
    /// The provider and model fields the form falls back to whenever the runtime cannot
    /// answer with a list — an unserved verb, a fetch still in flight, one that failed,
    /// or a "Custom…" pick. Seeded from the stored configuration, never from a literal.
    provider: Entity<InputState>,
    model: Entity<InputState>,
    workspace: Entity<InputState>,
    rename: Entity<InputState>,
    /// What the composer's placeholder currently says, so it is only rewritten when the
    /// answer changes: `set_placeholder` notifies, and notifying every frame never settles.
    composer_placeholder: &'static str,
    provider_select: Entity<SelectState<Vec<ProviderRow>>>,
    model_picker: ModelPicker,
    /// The rows currently installed in the two pickers. Held so a frame that would install
    /// the same rows installs nothing: `set_items` cannot compare them itself, and
    /// re-seeding a selection every frame would fight the operator's own pick.
    provider_rows: Vec<ProviderRow>,
    model_field: ModelField,
    /// What the form will actually send, held here rather than read back out of the
    /// widgets.
    ///
    /// gpui-component 0.5.1 cannot be trusted as the record of a choice while its list is
    /// searchable. Typing in the popup's search box runs `ListState::on_query_input_event`
    /// (list/list.rs:242-265), which filters the delegate and moves the list's index to
    /// row 0 of the *matches*. `SelectState::display_title` (select.rs:731-767) then draws
    /// the closed label by resolving that live index against the filtered rows, while the
    /// cached `selected_value` — written only by `SelectState::set_selected_index`
    /// (select.rs:595-606) — still holds the confirmed pick. Abandoning the search with
    /// Escape reaches `ListState::on_action_cancel` (list/list.rs:329-337), which does not
    /// clear the query, so the label keeps naming a row nobody chose.
    ///
    /// Two consequences the window has to absorb. Reading `selected_value()` is unsafe,
    /// because a programmatic `set_selected_value` made while the delegate is filtered
    /// resolves through `position()` over the *matched* rows (select.rs:397-437) and
    /// silently caches `None`. And there is no event for "popup closed without
    /// confirming": `SelectEvent` has only `Confirm`, and the inner `ListEvent::Cancel` is
    /// not re-emitted. So these fields are the record, every write to them is paired with
    /// the widget in one place, and the field's own hint line states what they hold.
    provider_choice: Option<SharedString>,
    model_choice: ModelChoice,
    /// Whether the stored configuration has been placed in the fields yet. One shot each:
    /// the config says where a control *starts*, so an answer landing later must not move
    /// a choice the operator has already made. The model has its own flag because its
    /// rows cannot exist until the catalogue arrives, which may be several frames later.
    seeded: bool,
    model_seeded: bool,
    /// The new-session form's file-access answer. `None` until the operator picks one, so
    /// an untouched form still starts the session the stored configuration describes —
    /// including the case where it describes nothing and the plane decides.
    new_sandbox: Option<SandboxMode>,
    /// The new-session form starts on High. If the selected model/provider does not offer
    /// it, the effective choice falls back to the first declared row without mutating this
    /// record; selecting another model starts at High again.
    new_reasoning_effort: Effort,
    show_new: bool,
    /// The Machines surface. A peer of the new-session form: both are full-width panels in
    /// the workspace column, both are opened from the rail header, and only one is up at a
    /// time because each wants the whole column.
    show_machines: bool,
    /// The three Add Machine fields. Target is required; the other two are what the probe
    /// would otherwise suggest, which is what their placeholders say.
    add_target: Entity<InputState>,
    add_machine: Entity<InputState>,
    add_host: Entity<InputState>,
    /// The parts of the form that are not text. Held here rather than read back out of the
    /// widgets, for the same reason the provider and model choices are — see [`ModelPicker`].
    add_toggles: AddForm,
    /// A refusal the operator has actually seen, raised by pressing Start. The form does not
    /// scold while it is being filled in.
    add_error: Option<String>,
    /// The fleet roster this window last read, and the data directory it was read from. The
    /// desktop path never fills `App::fleet_profile`, so this is the desktop's own copy;
    /// re-read when the surface opens and after an add settles, not every frame.
    fleet: Option<FleetProfile>,
    fleet_error: Option<String>,
    /// Whether the fleet CA key is present, read once with the profile. `render` asks this
    /// every frame and the answer is a file on disk.
    fleet_can_invite: bool,
    fleet_loaded: bool,
    fleet_loaded_for: Option<String>,
    /// The running add: the card the events drive, the handle that can ask it to stop, and
    /// the receiver the sink writes into. All three live and die together.
    add_card: Option<AddCard>,
    add_handle: Option<AddHandle>,
    add_events: Option<Receiver<AddEvent>>,
    add_scroll: ScrollHandle,
    action_error: Option<String>,
    transcript_scroll: ScrollHandle,
    session_scroll: UniformListScrollHandle,
    transcript_len: usize,
    expanded_tool_cells: HashSet<String>,
    focus_handle: FocusHandle,
    _subscriptions: Vec<Subscription>,
    _poll: Task<()>,
}

/// The model picker and the subscription that reads its confirmations.
///
/// One value rather than two fields because the picker is *replaced* whenever the form
/// opens, and a subscription left watching the entity it replaced would fail silently: the
/// operator would click a model, nothing would record it, and the form would keep sending
/// the previous one — a worse fault than the search-box residue the replacement exists to
/// clear. Bound together, the compiler will not let one be stored without the other, and
/// overwriting the pair drops the old subscription, which is what detaches it
/// (`Subscription`'s `Drop` unsubscribes).
///
/// Built in exactly one place: [`DesktopView::new_model_picker`].
struct ModelPicker {
    select: Entity<SelectState<SearchableVec<ModelRow>>>,
    _subscription: Subscription,
}

impl DesktopView {
    /// Builds the model picker together with the subscription that reads its confirmations.
    ///
    /// The single registration site, called by the constructor and by every replacement, so
    /// the two cannot be created apart and cannot drift — see [`ModelPicker`].
    fn new_model_picker(window: &mut Window, cx: &mut Context<Self>) -> ModelPicker {
        let select = cx.new(|cx| {
            SelectState::new(SearchableVec::new(Vec::<ModelRow>::new()), None, window, cx)
                .searchable(true)
        });

        let subscription = cx.subscribe_in(
            &select,
            window,
            |this, _select, event: &SelectEvent<SearchableVec<ModelRow>>, window, cx| {
                // Read from the event, never from `selected_value()`: confirming out of a
                // filtered list is exactly the case where the component's cache is
                // resolved against rows that are not the whole list.
                let SelectEvent::Confirm(choice) = event;
                this.model_choice = choice.clone().unwrap_or(ModelChoice::RuntimeDefault);
                this.new_reasoning_effort = Effort::High;
                // A confirmed search leaves the delegate filtered and the list index
                // pointing into it. Reinstalling unfiltered rows and re-asserting the
                // choice puts the closed label back in agreement with what will be sent.
                this.reinstall_model_rows(window, cx);
                this.action_error = None;
                cx.notify();
            },
        );

        ModelPicker {
            select,
            _subscription: subscription,
        }
    }

    fn new(driver: Driver, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus_handle = cx.focus_handle();
        focus_handle.focus(window);
        let composer = cx.new(|cx| {
            InputState::new(window, cx)
                .auto_grow(2, 8)
                .placeholder(COMPOSER_MESSAGE_PLACEHOLDER)
        });
        // No literal defaults here. Both fields are seeded from the stored configuration
        // the first time the reducer exists to read it — see `sync_pickers` — because a
        // provider and model baked into the window would be this client deciding for an
        // operator who already wrote the answer down.
        let provider = cx.new(|cx| InputState::new(window, cx).placeholder("Provider"));
        let model = cx.new(|cx| InputState::new(window, cx).placeholder("Model (optional)"));
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
        // The two optional fields say what leaving them blank means, because blank is the
        // ordinary answer: the probe already knows this machine's hostname and address.
        let add_target = cx.new(|cx| InputState::new(window, cx).placeholder("user@host"));
        let add_machine = cx
            .new(|cx| InputState::new(window, cx).placeholder("Optional — the probe suggests one"));
        let add_host = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Optional — the probe suggests a private address")
        });
        let provider_select =
            cx.new(|cx| SelectState::new(Vec::<ProviderRow>::new(), None, window, cx));
        let model_picker = Self::new_model_picker(window, cx);
        let mut subscriptions = Vec::new();
        for input in [
            composer.clone(),
            provider.clone(),
            model.clone(),
            workspace.clone(),
            rename.clone(),
            add_target.clone(),
            add_machine.clone(),
            add_host.clone(),
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

        subscriptions.push(cx.subscribe_in(
            &provider_select,
            window,
            |this, _select, event: &SelectEvent<Vec<ProviderRow>>, window, cx| {
                let SelectEvent::Confirm(name) = event;
                if let Some(name) = name.clone() {
                    this.provider_choice = Some(name);
                }

                // The operator has now stated a provider of their own, so the stored model
                // default — which belongs to the provider they left — is no longer theirs
                // to place. `sync_pickers` rebuilds the rows from here and drops a model
                // choice the new provider does not offer.
                this.model_seeded = true;
                this.sync_pickers(window, cx);
                this.new_reasoning_effort = Effort::High;
                this.action_error = None;
                cx.notify();
            },
        ));

        // Spawned against the window rather than the app: the tick puts a refused
        // quick-start prompt back into the composer, and writing an input's value needs the
        // window that draws it.
        let poll = cx.spawn_in(window, async move |view, cx| loop {
            Timer::after(TICK).await;
            if view
                .update_in(cx, |this, window, cx| {
                    this.poll(window, cx);
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
            composer_placeholder: COMPOSER_MESSAGE_PLACEHOLDER,
            provider_select,
            model_picker,
            provider_rows: Vec::new(),
            model_field: ModelField::Text { hint: None },
            provider_choice: None,
            model_choice: ModelChoice::RuntimeDefault,
            seeded: false,
            model_seeded: false,
            new_sandbox: None,
            new_reasoning_effort: Effort::High,
            show_new: false,
            show_machines: false,
            add_target,
            add_machine,
            add_host,
            add_toggles: AddForm::default(),
            add_error: None,
            fleet: None,
            fleet_error: None,
            fleet_can_invite: false,
            fleet_loaded: false,
            fleet_loaded_for: None,
            add_card: None,
            add_handle: None,
            add_events: None,
            add_scroll: ScrollHandle::new(),
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

    fn poll(&mut self, window: &mut Window, cx: &mut Context<Self>) {
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
                    // Asked once here so the new-session form has its lists the first time
                    // it opens rather than a frame or two after. A reconnect builds a new
                    // `App`, so this is genuinely once per connection.
                    app.desktop_fetch_pickers();
                    // A reconnect builds a fresh `App`; if the Machines panel is already
                    // showing, re-arm its live status polling on the new connection.
                    if self.show_machines {
                        app.desktop_machines_open(true);
                    }
                    self.status = format!("Connected · {} · {}", app.hello.node, app.hello.scope);
                    self.app = Some(app);
                    self.seeded = false;
                    self.model_seeded = false;
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

        // A start the runtime refused takes the prompt that was typed into it. The reducer
        // holds that text for exactly one hand-back and this window is the only place it
        // can go. A draft typed since the failure is newer and wins — the same rule the
        // reducer's own restore paths follow.
        let restored = self.app.as_mut().and_then(App::desktop_take_restored_draft);
        if let Some(restored) = restored {
            if self.composer.read(cx).value().trim().is_empty() {
                self.composer
                    .update(cx, |input, cx| input.set_value(restored, window, cx));
            }
        }

        self.drain_add_events();
        self.flush_calls();
        if let Some(app) = self.app.as_ref() {
            let len = app.desktop_transcript().len();
            if len > self.transcript_len {
                self.transcript_scroll.scroll_to_bottom();
            }
            self.transcript_len = len;
        }
    }

    /// Fold whatever the add pipeline has produced since the last tick into the card.
    ///
    /// The sink runs on the pipeline's own thread and does nothing but send; the window
    /// reads on the tick it already has. That is the same shape as the connection driver
    /// above, and it means the pipeline never touches GPUI state.
    fn drain_add_events(&mut self) {
        let Some(events) = self.add_events.as_ref() else {
            return;
        };
        let mut settled = false;
        while let Ok(event) = events.try_recv() {
            let terminal = matches!(event, AddEvent::Done(_) | AddEvent::Failed { .. });
            if let Some(card) = self.add_card.as_mut() {
                card.observe(event);
            }
            if terminal {
                settled = true;
                break;
            }
        }
        if settled {
            // The thread is finished by construction — the terminal event is the last thing
            // it sends — so the handle has nothing left to cancel and the roster on disk is
            // now whatever the add made it.
            self.add_events = None;
            self.add_handle = None;
            self.fleet_loaded = false;
            self.reload_fleet();
        }
    }

    /// Re-read the fleet profile for the data directory the runtime named.
    ///
    /// `App::fleet_profile` is filled in by the terminal launcher and not by the desktop
    /// driver, so this window keeps its own copy rather than reaching into a reducer field
    /// nothing populates here. One read per data directory, plus one after an add settles.
    fn reload_fleet(&mut self) {
        let data_dir = self.app.as_ref().and_then(|app| app.data_dir.clone());
        if self.fleet_loaded && self.fleet_loaded_for == data_dir {
            return;
        }
        match machines::load_profile(data_dir.as_deref()) {
            Ok(profile) => {
                self.fleet = profile;
                self.fleet_error = None;
            }
            Err(error) => {
                self.fleet = None;
                self.fleet_error = Some(error);
            }
        }
        self.fleet_can_invite = self
            .fleet
            .as_ref()
            .zip(data_dir.as_deref())
            .is_some_and(|(profile, data_dir)| profile.can_invite(Path::new(data_dir)));
        self.fleet_loaded = true;
        self.fleet_loaded_for = data_dir;
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

    /// Sends the composer's draft: to the open session, or — with none open — as the first
    /// message of a session this starts with the stored defaults.
    ///
    /// The refusal path keeps the text. A start can still be refused asynchronously, and
    /// the reducer hands that prompt back through `poll`.
    fn send_message(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.composer.read(cx).value().to_string();
        let quick_start = self
            .app
            .as_ref()
            .is_some_and(|app| app.sessions.open.is_none());
        let result = self
            .app
            .as_mut()
            .ok_or_else(|| "the runtime is not connected yet".to_string())
            .and_then(|app| {
                if quick_start {
                    app.desktop_quick_start(&text)
                } else {
                    app.desktop_submit_message(&text)
                }
            });

        match result {
            Ok(()) => {
                self.composer
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.action_error = None;
                if quick_start {
                    self.status = "Starting a new session…".to_string();
                }
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

    /// Keeps the two new-session pickers pointing at what the runtime currently reports.
    ///
    /// Driven from `render` because that is the only place holding a `Window`, and written
    /// to be a no-op whenever the rows it would install are already installed — so a frame
    /// that changes nothing costs two comparisons and touches no entity.
    fn sync_pickers(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(app) = self.app.as_ref() else {
            return;
        };
        let stored_provider = app.home_provider().to_string();
        let stored_model = app.home_model().to_string();
        let rows = provider_rows(&app.providers, Some(&stored_provider));

        if rows != self.provider_rows {
            self.provider_rows = rows.clone();
            self.provider_select
                .update(cx, |state, cx| state.set_items(rows, window, cx));

            // A refresh that reordered or re-probed the list must not move a choice the
            // operator made, so the pick is carried by name. One that this runtime has
            // stopped reporting has no row left to point at, and leaving it would put the
            // widget on the placeholder while this window still claimed the old name.
            let chosen = self
                .provider_choice
                .clone()
                .filter(|name| self.provider_rows.iter().any(|row| row.name == *name))
                .unwrap_or_else(|| SharedString::from(stored_provider.clone()));
            self.set_provider_choice(chosen, window, cx);
        }

        if !self.seeded {
            self.seeded = true;
            self.provider.update(cx, |input, cx| {
                input.set_value(&stored_provider, window, cx)
            });
            self.model
                .update(cx, |input, cx| input.set_value(&stored_model, window, cx));
            self.set_provider_choice(SharedString::from(stored_provider), window, cx);
        }

        self.sync_model_field(window, cx);

        if !self.model_seeded && matches!(self.model_field, ModelField::Rows { .. }) {
            self.model_seeded = true;
            self.place_model_choice(&stored_model, window, cx);
        }
    }

    /// Rebuilds the model rows for whichever provider is selected now.
    fn sync_model_field(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let provider = self.new_provider(cx);
        let Some(field) = self
            .app
            .as_ref()
            .map(|app| model_field(&app.models, &provider))
        else {
            return;
        };

        if field == self.model_field {
            return;
        }
        self.model_field = field;

        // A model chosen under the previous provider is not necessarily a row under this
        // one. Dropping it back to "no model option" is the only honest landing: the
        // alternative is a window claiming a model whose row the operator cannot see.
        if !self.model_field.offers(&self.model_choice) {
            self.model_choice = ModelChoice::RuntimeDefault;
        }

        self.reinstall_model_rows(window, cx);
    }

    /// Installs the model rows fresh and re-asserts the choice this window holds on them.
    ///
    /// Also how the window undoes a search it has no API to clear: a `SearchableVec` built
    /// here has `matched_items == items`, so replacing the delegate replaces a filtered one
    /// with the whole list. What it cannot reset is the text still sitting in the popup's
    /// search box, which lives in `ListState::query_input` (list/list.rs:73) behind
    /// `pub(crate)` — see the note on [`DesktopView::model_choice`].
    ///
    /// The order of the two calls below is load-bearing. `set_selected_value` resolves
    /// through `SearchableVec::position` over the *matched* rows (select.rs:397-437), so
    /// asserting a choice before the delegate is replaced would look it up in a filtered
    /// list, find nothing, and set the selection to `None`.
    fn reinstall_model_rows(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        // Installed even when there is nothing to install: a field that has stopped
        // offering rows must stop showing the row it last had selected, or its closed
        // label keeps naming a model from the provider the operator just left.
        let rows = match &self.model_field {
            ModelField::Rows { rows, .. } => rows.clone(),
            ModelField::Text { .. } | ModelField::Unsupported => Vec::new(),
        };
        let choice = self.model_choice.clone();

        self.model_picker.select.update(cx, |state, cx| {
            state.set_items(SearchableVec::new(rows), window, cx);
            state.set_selected_value(&choice, window, cx);
        });
    }

    /// Sets the provider choice and the widget together.
    ///
    /// The only writer of `provider_choice`, besides the confirm subscriber that takes it
    /// from the event. Paired here so the record and the control cannot drift apart.
    fn set_provider_choice(
        &mut self,
        name: SharedString,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.provider_choice = Some(name.clone());
        self.provider_select
            .update(cx, |state, cx| state.set_selected_value(&name, window, cx));
    }

    /// Puts `model` on the row that would actually send it.
    ///
    /// A catalogue that lists the id selects that row. One that does not is no evidence
    /// the id is wrong — the catalogue is a bounded snapshot of what a vendor published,
    /// not of what an account can reach — so the choice becomes "Custom…" over the text
    /// field that still holds the id, and the form sends exactly what it would have sent.
    fn place_model_choice(&mut self, model: &str, window: &mut Window, cx: &mut Context<Self>) {
        let wanted = ModelChoice::Catalog(SharedString::from(model.trim().to_string()));

        self.model_choice = match (model.trim().is_empty(), self.model_field.offers(&wanted)) {
            (true, _) => ModelChoice::RuntimeDefault,
            (false, true) => wanted,
            (false, false) => ModelChoice::Custom,
        };

        self.reinstall_model_rows(window, cx);
    }

    /// Whether the provider picker can stand in for the text field.
    ///
    /// Only once `runtime.providers` has answered. Before that the only row this client
    /// could build is the stored default annotated "not reported here", which is a claim
    /// about a probe that has not run.
    fn provider_picker_ready(&self) -> bool {
        !self.provider_rows.is_empty()
            && self
                .app
                .as_ref()
                .is_some_and(|app| app.providers.value.is_some())
    }

    /// The provider this form will send: the picker's choice while the picker is what is
    /// on screen, the text field otherwise. A form must not send what nobody can see.
    ///
    /// This reads the window's own record for the same reason the model field does. The
    /// provider list is a plain `Vec<ProviderRow>` whose delegate never filters — a
    /// non-searchable `Select` leaves `perform_search` at its no-op default
    /// (select.rs:118-125) — so the component's own cache would in fact be correct here.
    /// It is not read anyway: one rule for both pickers is one rule to keep true, and
    /// making this list searchable later must not quietly reintroduce the divergence.
    fn new_provider(&self, cx: &GpuiApp) -> String {
        if self.provider_picker_ready() {
            if let Some(name) = self.provider_choice.as_ref() {
                return name.to_string();
            }
        }

        self.provider.read(cx).value().trim().to_string()
    }

    /// What the form will send for the model, and the line that says so.
    fn model_intent(&self, cx: &GpuiApp) -> ModelIntent {
        model_intent(
            &self.model_field,
            &self.model_choice,
            self.model.read(cx).value().as_ref(),
        )
    }

    /// The model option this form will send. `None` sends none at all, which is what
    /// leaves the choice to the runtime.
    fn new_model(&self, cx: &GpuiApp) -> Option<String> {
        self.model_intent(cx).send
    }

    /// Whether the model field is on its "Custom…" row, which is what reveals the text
    /// input beneath the picker.
    fn model_is_custom(&self) -> bool {
        matches!(self.model_field, ModelField::Rows { .. })
            && self.model_choice == ModelChoice::Custom
    }

    /// The model this session would actually run under, as far as this client can tell.
    ///
    /// The operator's pick when there is one, and otherwise the default the *runtime*
    /// reported for the provider — a statement from the runtime rather than a guess made
    /// here. Only the sign-in notice reads this; the request still carries no model option
    /// when "Runtime default" is chosen.
    fn new_effective_model(&self, cx: &GpuiApp) -> Option<String> {
        if let Some(model) = self.new_model(cx) {
            return Some(model);
        }

        let provider = self.new_provider(cx);
        self.app
            .as_ref()?
            .models
            .value
            .as_ref()?
            .provider(&provider)?
            .default
            .clone()
    }

    fn new_reasoning_choices(&self, cx: &GpuiApp) -> Vec<Effort> {
        let provider = self.new_provider(cx);
        let model = self.new_effective_model(cx);
        self.app
            .as_ref()
            .map(|app| app.desktop_reasoning_choices_for(&provider, model.as_deref()))
            .unwrap_or_default()
    }

    /// The value the new-session request will send. High wins whenever the model offers
    /// it; a narrower model falls back to its first declared value, and an unknown model
    /// sends no effort rather than guessing.
    fn new_reasoning_effort(&self, cx: &GpuiApp) -> Option<Effort> {
        let choices = self.new_reasoning_choices(cx);
        resolved_reasoning_effort(self.new_reasoning_effort, &choices)
    }

    /// Whether the session this form describes would run on a ChatGPT-subscription model.
    fn new_requires_chatgpt(&self, cx: &GpuiApp) -> bool {
        self.new_provider(cx) == "native"
            && self
                .new_effective_model(cx)
                .is_some_and(|model| model.starts_with("openai_codex:"))
    }

    /// Opens the platform's own directory chooser and writes the pick into the workspace
    /// field. Cancelling changes nothing — the field keeps whatever was typed.
    fn browse_workspace(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let picked = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("Choose workspace".into()),
        });
        let view = cx.entity().downgrade();

        window
            .spawn(cx, async move |cx| {
                let picked = picked.await;
                _ = view.update_in(cx, |this, window, cx| {
                    match picked {
                        Ok(Ok(Some(paths))) => {
                            if let Some(path) = paths.into_iter().next() {
                                this.workspace.update(cx, |input, cx| {
                                    input.set_value(path.display().to_string(), window, cx)
                                });
                                this.action_error = None;
                            }
                        }
                        // The platform could not open a chooser at all, which is a
                        // different fact from a person deciding not to pick one.
                        Ok(Err(error)) => {
                            this.action_error =
                                Some(format!("the directory chooser did not open: {error}"));
                        }
                        Ok(Ok(None)) | Err(_) => {}
                    }
                    cx.notify();
                });
            })
            .detach();
    }

    fn start_session(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let provider = self.new_provider(cx);
        let model = self.new_model(cx);
        let workspace = self.workspace.read(cx).value().to_string();
        let sandbox = self.new_sandbox;
        let reasoning_effort = self.new_reasoning_effort(cx);
        let result = self
            .app
            .as_mut()
            .ok_or_else(|| "the runtime is not connected yet".to_string())
            .and_then(|app| {
                app.desktop_start_session(provider, model, workspace, sandbox, reasoning_effort)
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

    fn set_reasoning_effort(&mut self, effort: Effort, cx: &mut Context<Self>) {
        let result = match self.app.as_mut() {
            None => Err("the runtime is not connected".to_string()),
            Some(app) => app.desktop_set_reasoning_effort(effort),
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

    fn toggle_new_session(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.app.is_some() {
            self.show_new = !self.show_new;
            self.action_error = None;
            if self.show_new {
                self.open_new_session(window, cx);
            }
            cx.notify();
        }
    }

    /// Asks the runtime to fill the form's pickers, and gives the model picker a clean
    /// slate.
    ///
    /// Both fetches are no-ops while an answer is held or outstanding, so opening the form
    /// repeatedly asks nothing extra — but a fetch that failed earlier gets its retry here
    /// rather than on a poll cadence.
    ///
    /// The picker is rebuilt rather than reset because the crate offers no way to reset it.
    /// Text typed into the popup's search box lives in `ListState::query_input`
    /// (list/list.rs:73), which is `pub(crate)` and survives close, reopen, and any
    /// delegate swap — and the box is an ordinary text input, so a second search *appends*
    /// to the first ("terra" then "terra" becomes "terraterra", matching nothing). A fresh
    /// entity is the only way to hand back an empty box. `model_choice` is this window's
    /// own, so nothing the operator chose is lost in the exchange; the reinstall below
    /// carries the rows and the selection onto the new picker.
    ///
    /// Only the model picker needs this. The provider picker is never `.searchable(true)`,
    /// and `ListState` renders no query input unless it is (list/list.rs:585), so no text
    /// can reach a box that is never drawn.
    fn open_new_session(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(app) = self.app.as_mut() {
            app.desktop_fetch_pickers();
            self.flush_calls();
        }

        self.model_picker = Self::new_model_picker(window, cx);
        self.reinstall_model_rows(window, cx);
        self.new_reasoning_effort = Effort::High;

        self.action_error = None;
        cx.notify();
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
                self.toggle_new_session(window, cx);
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
            .w_full()
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
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .flex_none()
                            // Machines sits beside New because both are window-level
                            // actions rather than anything about the open session.
                            .child(
                                design::icon_button(
                                    "open-machines",
                                    IconName::Globe,
                                    "Machines — the fleet this runtime belongs to",
                                )
                                .disabled(self.app.is_none())
                                .on_click(cx.listener(|this, _, _, cx| {
                                    if this.show_machines {
                                        this.close_machines(cx);
                                    } else {
                                        this.open_machines(cx);
                                    }
                                })),
                            )
                            .child(
                                design::secondary_button("new-session", "New")
                                    .flex_none()
                                    .icon(IconName::Plus)
                                    .tooltip("New session · ⌘N")
                                    .disabled(self.app.is_none())
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.show_new = !this.show_new;
                                        this.action_error = None;
                                        if this.show_new {
                                            this.show_machines = false;
                                            if let Some(app) = this.app.as_mut() {
                                                app.desktop_machines_open(false);
                                            }
                                            this.open_new_session(window, cx);
                                        }
                                        cx.notify();
                                    })),
                            ),
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
                    .child(
                        div()
                            .id("session-rail-hint")
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .child("Drag divider to resize · Right-click rows")
                            .tooltip(|window, cx| {
                                Tooltip::new("Drag divider to resize · Right-click rows")
                                    .build(window, cx)
                            }),
                    )
                    .child(design::keycap(tokens, "⌘N").flex_none()),
            )
    }

    /// The provider control: the probe list once it has answered, and the text field the
    /// form always had until then.
    fn render_provider_field(&self, tokens: DesktopTokens) -> gpui::Div {
        if self.provider_picker_ready() {
            // Only the probed rows: an "unserved" row carries a different annotation, and
            // this sentence would be describing a probe that never ran on it.
            let undetected = self
                .provider_rows
                .iter()
                .filter(|row| !row.unserved && !row.detected)
                .count();

            return design::field(
                tokens,
                "Provider",
                Some("Required".into()),
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        Select::new(&self.provider_select)
                            .small()
                            .w_full()
                            .placeholder("Choose a provider"),
                    )
                    // Said once here rather than beside each row, and said as what it is:
                    // a report about a probe, not a verdict on whether a session can start.
                    .when(undetected > 0, |field| {
                        field.child(div().text_xs().text_color(tokens.ink_3).child(
                            "Dimmed entries are ones whose probe found no executable. The runtime decides whether a session starts.",
                        ))
                    }),
            );
        }

        let hint = self.app.as_ref().and_then(|app| {
            match (app.providers.error.as_deref(), app.providers.pending) {
                (Some(error), _) => Some(format!("the provider list could not be read: {error}")),
                (None, true) => Some("reading the provider list…".to_string()),
                (None, false) => None,
            }
        });

        design::field(
            tokens,
            "Provider",
            Some("Required".into()),
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(Input::new(&self.provider).prefix(Icon::new(IconName::Bot).small()))
                .when_some(hint, |field, hint| {
                    field.child(div().text_xs().text_color(tokens.ink_3).child(hint))
                }),
        )
    }

    /// The model control, which is whatever this runtime can honestly offer for the
    /// provider now selected — a filtered list, a disabled picker, or the text field.
    fn render_model_field(&self, tokens: DesktopTokens, cx: &mut Context<Self>) -> gpui::Div {
        let intent = self.model_intent(cx);
        let (hint, control) = match &self.model_field {
            ModelField::Unsupported => (
                Some(SharedString::from("Not accepted")),
                div().flex().flex_col().gap_1().child(
                    Select::new(&self.model_picker.select)
                        .small()
                        .w_full()
                        .disabled(true)
                        .placeholder("No model option"),
                ),
            ),
            ModelField::Text { hint } => (
                Some(SharedString::from("Optional")),
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        Input::new(&self.model)
                            .cleanable(true)
                            .prefix(Icon::new(IconName::Settings2).small()),
                    )
                    .when_some(hint.clone(), |field, hint| {
                        field.child(div().text_xs().text_color(tokens.ink_3).child(hint))
                    }),
            ),
            ModelField::Rows { rows, total } => {
                // The two framing rows are this window's, not the catalogue's, so they are
                // not counted against the bound the runtime reported.
                let listed = rows.len().saturating_sub(2) as u64;
                let hint = if *total > listed {
                    SharedString::from(format!("{listed} of {total}"))
                } else {
                    SharedString::from("Optional")
                };

                (
                    Some(hint),
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            Select::new(&self.model_picker.select)
                                .small()
                                .w_full()
                                .menu_width(px(420.0))
                                .placeholder("Runtime default")
                                .search_placeholder("Search models…"),
                        )
                        .when(self.model_is_custom(), |field| {
                            field.child(
                                Input::new(&self.model)
                                    .cleanable(true)
                                    .prefix(Icon::new(IconName::Settings2).small()),
                            )
                        }),
                )
            }
        };

        design::field(
            tokens,
            "Model",
            hint,
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(control)
                // The field's authoritative reading, and the only one on screen that
                // cannot be wrong. The picker's own closed label is drawn by the component
                // from its live list index, which a search moves without confirming
                // anything — see the note on `model_choice` — so this line, derived from
                // the same value the request carries, is what an operator can trust.
                .child(div().text_xs().text_color(tokens.ink_2).child(intent.hint)),
        )
    }

    fn render_new_session(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = design::tokens(cx);
        let requires_chatgpt = self.new_requires_chatgpt(cx);
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
        let reasoning_choices = self.new_reasoning_choices(cx);
        let reasoning_effort = self.new_reasoning_effort(cx);
        let reasoning_model = self.new_effective_model(cx);
        let picker_view = cx.entity().downgrade();

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
                            .items_start()
                            .gap_3()
                            .child(self.render_provider_field(tokens).flex_1())
                            .child(self.render_model_field(tokens, cx).flex_1()),
                    )
                    .child(design::field(
                        tokens,
                        "Workspace",
                        Some("Absolute path".into()),
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div().flex_1().child(
                                    Input::new(&self.workspace)
                                        .cleanable(true)
                                        .prefix(Icon::new(IconName::Folder).small()),
                                ),
                            )
                            .child(
                                design::secondary_button("browse-workspace", "Browse…")
                                    .flex_none()
                                    .icon(IconName::Folder)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.browse_workspace(window, cx);
                                    })),
                            ),
                    ))
                    .child(design::field(
                        tokens,
                        "Thinking",
                        Some(
                            reasoning_model
                                .map(|model| format!("For {model}").into())
                                .unwrap_or_else(|| "Not reported for this model".into()),
                        ),
                        match reasoning_effort {
                            Some(current) => {
                                let choices = reasoning_choices.clone();
                                design::secondary_button("new-reasoning-effort", current.label())
                                    .w_full()
                                    .icon(IconName::Settings2)
                                    .tooltip("Default thinking level for this session")
                                    .dropdown_menu(move |menu, _window, _cx| {
                                        choices
                                            .iter()
                                            .copied()
                                            .enumerate()
                                            .fold(
                                                menu.min_w(px(220.0)),
                                                |menu, (_index, effort)| {
                                                    let view = picker_view.clone();
                                                    menu.item(
                                                        PopupMenuItem::new(effort.label())
                                                            .checked(effort == current)
                                                            .on_click(move |_, _, cx| {
                                                                let _ =
                                                                    view.update(cx, |this, cx| {
                                                                        this.new_reasoning_effort =
                                                                            effort;
                                                                        this.action_error = None;
                                                                        cx.notify();
                                                                    });
                                                            }),
                                                    )
                                                },
                                            )
                                            .separator()
                                            .label("High is the default when the model supports it")
                                    })
                                    .into_any_element()
                            }
                            None => design::secondary_button(
                                "new-reasoning-unavailable",
                                "Not available",
                            )
                            .w_full()
                            .icon(IconName::Settings2)
                            .disabled(true)
                            .into_any_element(),
                        },
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
                                    // Two separate signals, deliberately. The full-access
                                    // row's *title* is warning-coloured always, because
                                    // that is a standing property of the posture and an
                                    // operator should see it before choosing. The card's
                                    // fill and border are the ordinary "this is selected"
                                    // language of the rest of the window — accent for the
                                    // two safe rows, warning for this one, so picking it
                                    // never reads as an action highlight.
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

    // ------------------------------------------------------------------------------
    // Machines.
    //
    // Placed where the new-session form is placed, for the same reason: it is a
    // full-width panel that wants the workspace column, opened from the rail header
    // where the window's other global action already lives. A fleet is not a property
    // of the open session, so it does not belong in the session rail's list or the
    // composer footer.
    // ------------------------------------------------------------------------------

    fn open_machines(&mut self, cx: &mut Context<Self>) {
        self.show_machines = true;
        // Two panels competing for one column is a layout with no winner.
        self.show_new = false;
        self.action_error = None;
        self.reload_fleet();
        if let Some(app) = self.app.as_mut() {
            app.desktop_machines_open(true);
        }
        cx.notify();
    }

    fn close_machines(&mut self, cx: &mut Context<Self>) {
        self.show_machines = false;
        self.add_error = None;
        if let Some(app) = self.app.as_mut() {
            app.desktop_machines_open(false);
        }
        cx.notify();
    }

    /// The form as it currently reads, with the text pulled out of the three inputs and
    /// the toggles taken from the record this window keeps.
    fn add_form(&self, cx: &GpuiApp) -> AddForm {
        AddForm {
            target: self.add_target.read(cx).value().to_string(),
            machine: self.add_machine.read(cx).value().to_string(),
            host: self.add_host.read(cx).value().to_string(),
            joined_without_signing_key: !self.can_invite(),
            ..self.add_toggles.clone()
        }
    }

    /// Whether this machine holds the key that signs an invitation. A member that joined
    /// from one does not — the same fact, from the same file, that the terminal client
    /// checks before its own Add. Read with the profile rather than here, because `render`
    /// asks every frame and the answer lives on disk.
    fn can_invite(&self) -> bool {
        self.fleet_can_invite
    }

    /// Launch the add on its own thread and point the card at its events.
    ///
    /// The sink is the pipeline's only contact with this window: it sends into a channel
    /// and returns, so nothing on that thread touches GPUI state and a window that has
    /// gone away is a closed channel rather than a crash.
    fn start_add(&mut self, cx: &mut Context<Self>) {
        if self
            .add_card
            .as_ref()
            .is_some_and(|card| !card.phase().settled())
        {
            return;
        }
        let request = match self.add_form(cx).validate() {
            Ok(request) => request,
            Err(refusal) => {
                self.add_error = Some(refusal.message().to_string());
                cx.notify();
                return;
            }
        };
        let Some(data_dir) = self.app.as_ref().and_then(|app| app.data_dir.clone()) else {
            self.add_error = Some(
                "this window does not know the runtime's data directory yet, so it cannot \
                 run an add. Wait for the connection to settle and try again."
                    .to_string(),
            );
            cx.notify();
            return;
        };
        // The same value the CLI passes: the owner's host, from the profile on disk.
        let owner_host = self.fleet.as_ref().map(|profile| profile.host.clone());
        let params = request.params(Path::new(&data_dir), owner_host);

        let (sender, receiver) = mpsc::channel();
        // A closed channel is a window that went away, not a reason to stop: dropping the
        // handle does not stop the pipeline, so a closed window lets the add finish on the
        // destination rather than abandoning it half-done.
        let handle = spawn_add(params, move |event| {
            let _ = sender.send(event);
        });
        self.add_card = Some(AddCard::new(request.target));
        self.add_handle = Some(handle);
        self.add_events = Some(receiver);
        self.add_error = None;
        cx.notify();
    }

    fn cancel_add(&mut self, cx: &mut Context<Self>) {
        if let Some(handle) = self.add_handle.as_ref() {
            handle.cancel();
        }
        if let Some(card) = self.add_card.as_mut() {
            card.request_cancel();
        }
        cx.notify();
    }

    fn dismiss_add_card(&mut self, cx: &mut Context<Self>) {
        if self
            .add_card
            .as_ref()
            .is_some_and(|card| card.phase().settled())
        {
            self.add_card = None;
        }
        cx.notify();
    }

    fn render_machines(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = design::tokens(cx);
        let view = self.fleet.as_ref().map(|profile| {
            machines::fleet_view(
                profile,
                self.app.as_ref().and_then(|app| app.status.value.as_ref()),
            )
        });

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
                            .child(design::icon_tile(tokens, cx, Tone::Accent, IconName::Globe))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_lg()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .child(match view.as_ref() {
                                                Some(view) => format!("Fleet · {}", view.fleet),
                                                None => "Machines".to_string(),
                                            }),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(tokens.ink_2)
                                            .child(match view.as_ref() {
                                                Some(view) => format!(
                                                    "This machine is {} at {} · {} connected · {} offline",
                                                    view.this_machine,
                                                    view.this_host,
                                                    view.connected(),
                                                    view.offline()
                                                ),
                                                None => "Fleet membership for this runtime".to_string(),
                                            }),
                                    ),
                            ),
                    )
                    .child(
                        design::icon_button("close-machines", IconName::Close, "Close Machines")
                            .on_click(cx.listener(|this, _, _, cx| this.close_machines(cx))),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .p_4()
                    .when_some(self.fleet_error.clone(), |body, error| {
                        body.child(
                            Alert::error("machines-profile-error", format!(
                                "This data directory has a fleet directory whose profile could not be read: {error}"
                            ))
                            .small(),
                        )
                    })
                    .map(|body| match view.as_ref() {
                        Some(view) => body.child(self.render_member_list(view, tokens, cx)),
                        None => body.child(design::empty_state(
                            tokens,
                            cx,
                            IconName::Globe,
                            machines::NO_FLEET_TITLE,
                            machines::NO_FLEET_BODY,
                        )),
                    })
                    .when(view.is_some(), |body| {
                        body.children(self.render_add_card(tokens, cx))
                            .child(self.render_add_form(tokens, cx))
                    }),
            )
    }

    fn render_member_list(
        &self,
        view: &machines::FleetView,
        tokens: DesktopTokens,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(design::eyebrow(tokens, "MEMBERS"))
            .children(view.members.iter().enumerate().map(|(index, member)| {
                // Connected/offline is an operational outcome, so it wears the semantic
                // tones. The accent is reserved for what an operator can act on, and a
                // machine being up is not an action.
                let tone = match member.presence {
                    Presence::Connected => Tone::Success,
                    Presence::Offline => Tone::Warning,
                    Presence::Unknown => Tone::Neutral,
                };
                design::inset(tokens)
                    .id(("fleet-member", index))
                    .flex()
                    .items_center()
                    .gap_3()
                    .p_3()
                    .child(design::icon_tile(
                        tokens,
                        cx,
                        tone,
                        if member.is_this_machine {
                            IconName::CircleUser
                        } else {
                            IconName::Globe
                        },
                    ))
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
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_weight(gpui::FontWeight::MEDIUM)
                                            .truncate()
                                            .child(member.machine.clone()),
                                    )
                                    .when(member.is_this_machine, |row| {
                                        row.child(
                                            div()
                                                .text_xs()
                                                .text_color(tokens.ink_3)
                                                .child("this machine"),
                                        )
                                    }),
                            )
                            .child(
                                div()
                                    .id(("fleet-member-meta", index))
                                    .text_xs()
                                    .text_color(tokens.ink_3)
                                    .truncate()
                                    .child(format!("{} · {}", member.host, member.node)),
                            ),
                    )
                    .child(
                        design::status_tag(tokens, cx, tone, member.presence.label()).flex_none(),
                    )
            }))
            .when(
                self.app
                    .as_ref()
                    .is_none_or(|app| app.status.value.is_none()),
                |list| {
                    list.child(div().text_xs().text_color(tokens.ink_3).child(
                        "No runtime status has arrived yet, so who is answering is unknown \
                         rather than offline.",
                    ))
                },
            )
    }

    fn render_add_form(&self, tokens: DesktopTokens, cx: &mut Context<Self>) -> gpui::Div {
        let running = self
            .add_card
            .as_ref()
            .is_some_and(|card| !card.phase().settled());
        let form = self.add_form(cx);
        let refusal = form.validate().err();
        let setup = self.add_toggles.setup_tailscale;
        let consented = self.add_toggles.consented;

        design::inset(tokens)
            .flex()
            .flex_col()
            .gap_4()
            .p_4()
            .child(design::eyebrow(tokens, "ADD A MACHINE"))
            // A standing condition rather than a form still being filled in, so it is
            // stated above the fields instead of as a nudge under the button.
            .when(refusal == Some(machines::FormRefusal::NotAnOwner), |body| {
                body.child(
                    Alert::warning(
                        "machines-not-owner",
                        machines::FormRefusal::NotAnOwner.message(),
                    )
                    .small(),
                )
            })
            .child(design::field(
                tokens,
                "Destination",
                Some("Required · reached over SSH".into()),
                Input::new(&self.add_target).cleanable(true),
            ))
            .child(
                div()
                    .flex()
                    .items_start()
                    .gap_3()
                    .child(
                        design::field(
                            tokens,
                            "Machine name",
                            None,
                            Input::new(&self.add_machine).cleanable(true),
                        )
                        .flex_1(),
                    )
                    .child(
                        design::field(
                            tokens,
                            "Private address",
                            None,
                            Input::new(&self.add_host).cleanable(true),
                        )
                        .flex_1(),
                    ),
            )
            .child(
                Switch::new("add-setup-tailscale")
                    .checked(setup)
                    .label("Set up Tailscale on the destination")
                    .on_click(cx.listener(|this, checked: &bool, _, cx| {
                        this.add_toggles.set_setup_tailscale(*checked);
                        this.add_error = None;
                        cx.notify();
                    })),
            )
            .when(setup, |body| {
                // The consequence is stated before it can be authorised, and in the
                // installer's own words rather than a paraphrase of them.
                body.child(
                    design::card(tokens, cx, Tone::Warning)
                        .flex()
                        .flex_col()
                        .gap_2()
                        .p_3()
                        .children(machines::TAILSCALE_CONSENT.iter().enumerate().map(
                            |(index, line)| {
                                let paragraph =
                                    div().text_xs().text_color(tokens.ink_2).child(*line);
                                if index == 0 {
                                    paragraph
                                } else {
                                    paragraph.mt_1()
                                }
                            },
                        ))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .p_2()
                                .rounded(tokens.radius)
                                .bg(tokens.inset)
                                .text_xs()
                                .font_family("monospace")
                                .text_color(tokens.ink)
                                .child(machines::TAILSCALE_INSTALL_COMMAND)
                                .child(machines::TAILSCALE_UP_COMMAND),
                        )
                        .child(
                            Checkbox::new("add-tailscale-consent")
                                .checked(consented)
                                .label(machines::TAILSCALE_CONSENT_ACK)
                                .on_click(cx.listener(|this, checked: &bool, _, cx| {
                                    this.add_toggles.consented = *checked;
                                    this.add_error = None;
                                    cx.notify();
                                })),
                        ),
                )
            })
            .when_some(self.add_error.clone(), |body, error| {
                body.child(
                    div()
                        .text_xs()
                        .text_color(tokens.tone(cx, Tone::Danger).foreground)
                        .child(error),
                )
            })
            .child(
                div().flex().items_center().justify_end().gap_2().child(
                    design::primary_button("start-add", "Add machine")
                        .icon(IconName::ArrowRight)
                        .loading(running)
                        .disabled(running || refusal.is_some())
                        .on_click(cx.listener(|this, _, _, cx| this.start_add(cx))),
                ),
            )
            .when_some(
                refusal
                    .filter(|_| !running)
                    // Already stated above the fields, in a louder place.
                    .filter(|refusal| *refusal != machines::FormRefusal::NotAnOwner),
                |body, refusal| {
                    body.child(
                        div()
                            .text_xs()
                            .text_color(tokens.ink_3)
                            .child(refusal.message()),
                    )
                },
            )
    }

    fn render_add_card(
        &self,
        tokens: DesktopTokens,
        cx: &mut Context<Self>,
    ) -> Option<gpui::AnyElement> {
        let card = self.add_card.as_ref()?;
        let phase = card.phase();
        let (tone, title) = match phase {
            AddPhase::Running => (Tone::Accent, format!("Adding {}", card.target)),
            AddPhase::Cancelling => (Tone::Warning, format!("Stopping {}", card.target)),
            AddPhase::Succeeded => (Tone::Success, format!("Added {}", card.target)),
            AddPhase::Failed => (Tone::Danger, format!("{} was not added", card.target)),
        };

        Some(
            design::card(tokens, cx, tone)
                .flex()
                .flex_col()
                .gap_3()
                .p_4()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(match phase {
                            AddPhase::Running | AddPhase::Cancelling => Spinner::new()
                                .small()
                                .color(tokens.tone(cx, tone).foreground)
                                .into_any_element(),
                            AddPhase::Succeeded => Icon::new(IconName::CircleCheck)
                                .text_color(tokens.tone(cx, tone).foreground)
                                .into_any_element(),
                            AddPhase::Failed => Icon::new(IconName::CircleX)
                                .text_color(tokens.tone(cx, tone).foreground)
                                .into_any_element(),
                        })
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(title),
                        )
                        .when(card.can_cancel(), |row| {
                            row.child(
                                design::danger_button("cancel-add", "Stop")
                                    .flex_none()
                                    .on_click(cx.listener(|this, _, _, cx| this.cancel_add(cx))),
                            )
                        })
                        .when(phase.settled(), |row| {
                            row.child(
                                design::icon_button(
                                    "dismiss-add",
                                    IconName::Close,
                                    "Dismiss this add",
                                )
                                .flex_none()
                                .on_click(cx.listener(|this, _, _, cx| this.dismiss_add_card(cx))),
                            )
                        }),
                )
                .when(card.cancel_requested(), |view| {
                    view.child(
                        div()
                            .text_xs()
                            .text_color(tokens.tone(cx, Tone::Warning).foreground)
                            .child(machines::CANCEL_NOTE),
                    )
                })
                .children(self.render_auth_prompt(card, tokens, cx))
                .when_some(card.countdown(), |view, countdown| {
                    // A spent budget is a failure that has not been reported yet. Saying
                    // "0s left" and nothing else would read as a wait that is still going.
                    let (color, text) = if countdown.expired() {
                        (
                            tokens.tone(cx, Tone::Warning).foreground,
                            format!(
                                "The {}s wait for a tailnet address is spent. The pipeline is \
                                 about to give up; running the add again resumes it.",
                                countdown.budget_s
                            ),
                        )
                    } else {
                        (
                            tokens.ink_2,
                            format!(
                                "Waiting for the destination to receive a tailnet address — \
                                 {}s left of {}s.",
                                countdown.remaining_s(),
                                countdown.budget_s
                            ),
                        )
                    };
                    view.child(div().text_xs().text_color(color).child(text))
                })
                .child(self.render_stage_rail(card, tokens, cx))
                .children(self.render_add_lines(card, tokens))
                .when_some(card.outcome().cloned(), |view, outcome| {
                    view.child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(tokens.tone(cx, Tone::Success).foreground)
                                    .child(machines::success_summary(&outcome)),
                            )
                            .children(outcome.recipe.as_ref().map(|recipe| {
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(design::eyebrow(tokens, "WHAT REMAINS"))
                                    .children(recipe.lines.iter().map(|line| {
                                        div()
                                            .text_xs()
                                            .font_family("monospace")
                                            .text_color(tokens.ink_2)
                                            .child(line.clone())
                                    }))
                            })),
                    )
                })
                .when_some(card.failure().cloned(), |view, failure| {
                    view.child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(tokens.tone(cx, Tone::Danger).foreground)
                                    .child(failure.error.clone()),
                            )
                            .when(!failure.residue.is_empty(), |body| {
                                body.child(design::eyebrow(tokens, "WHAT THIS LEFT BEHIND"))
                                    .children(failure.residue.iter().map(|line| {
                                        div().text_xs().text_color(tokens.ink_2).child(line.clone())
                                    }))
                            })
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.ink_2)
                                    .child(machines::RESUME_NOTE),
                            ),
                    )
                })
                .into_any_element(),
        )
    }

    /// The sign-in link's moment. It is the one thing on this card an operator must act on
    /// within a time budget, so it gets a button, and the URL is rendered as text beside it
    /// because a link that cannot be read cannot be checked.
    fn render_auth_prompt(
        &self,
        card: &AddCard,
        tokens: DesktopTokens,
        cx: &mut Context<Self>,
    ) -> Option<gpui::AnyElement> {
        let auth = card.auth()?;
        let url = auth.url().to_string();
        let openable = auth.openable();
        Some(
            design::card(tokens, cx, Tone::Warning)
                .flex()
                .flex_col()
                .gap_2()
                .p_3()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .text_color(tokens.tone(cx, Tone::Warning).foreground)
                        .child(Icon::new(IconName::ExternalLink).small())
                        .child(
                            div()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child("Approve this machine on Tailscale"),
                        ),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(tokens.ink_2)
                        .child(machines::AUTH_INSTRUCTION),
                )
                .child(
                    div()
                        .text_xs()
                        .font_family("monospace")
                        .text_color(tokens.ink_3)
                        .child(url.clone()),
                )
                .child(div().flex().items_center().gap_2().child(if openable {
                    design::primary_button("open-tailscale-signin", "Open sign-in link")
                        .icon(IconName::ExternalLink)
                        .on_click(cx.listener(move |_, _, _, cx| {
                            // Same guard as the ChatGPT card: the browser is only
                            // handed an HTTPS URL, and the check is made here rather
                            // than trusted from upstream.
                            if url.starts_with("https://") {
                                cx.open_url(&url);
                            }
                        }))
                        .into_any_element()
                } else {
                    div()
                        .text_xs()
                        .text_color(tokens.tone(cx, Tone::Danger).foreground)
                        .child(
                            "This sign-in link is not HTTPS, so it was not opened. \
                                     Check it before using it.",
                        )
                        .into_any_element()
                }))
                .into_any_element(),
        )
    }

    fn render_stage_rail(
        &self,
        card: &AddCard,
        tokens: DesktopTokens,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let running = !card.phase().settled();
        div()
            .flex()
            .flex_col()
            .gap_1()
            .when(card.only_lines_so_far() && running, |rail| {
                rail.child(
                    div()
                        .text_xs()
                        .text_color(tokens.ink_3)
                        .child(machines::LINE_ONLY_NOTE),
                )
            })
            .children(machines::STAGES.into_iter().map(|stage| {
                let state = card.stage_state(stage);
                let tone = match state {
                    StageState::Done => Tone::Success,
                    StageState::Active => Tone::Accent,
                    StageState::Failed => Tone::Danger,
                    StageState::Pending => Tone::Neutral,
                };
                let detail = self.stage_detail(card, stage);
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(match state {
                        StageState::Active => Spinner::new()
                            .small()
                            .color(tokens.tone(cx, tone).foreground)
                            .into_any_element(),
                        StageState::Done => Icon::new(IconName::CircleCheck)
                            .small()
                            .text_color(tokens.tone(cx, tone).foreground)
                            .into_any_element(),
                        StageState::Failed => Icon::new(IconName::CircleX)
                            .small()
                            .text_color(tokens.tone(cx, tone).foreground)
                            .into_any_element(),
                        StageState::Pending => Icon::new(IconName::Dash)
                            .small()
                            .text_color(tokens.ink_3)
                            .into_any_element(),
                    })
                    .child(
                        div()
                            .text_xs()
                            .font_weight(if state == StageState::Active {
                                gpui::FontWeight::SEMIBOLD
                            } else {
                                gpui::FontWeight::NORMAL
                            })
                            .text_color(if state == StageState::Pending {
                                tokens.ink_3
                            } else {
                                tokens.ink
                            })
                            .child(stage.title()),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_xs()
                            .text_color(tokens.ink_3)
                            .truncate()
                            .child(detail.unwrap_or_else(|| stage.describe().to_string())),
                    )
            }))
    }

    /// What the pipeline actually said about a stage, where it said anything. Never a
    /// summary of the log lines — only the typed events carry these.
    fn stage_detail(&self, card: &AddCard, stage: Stage) -> Option<String> {
        match stage {
            Stage::Probe => card.probe().map(str::to_string),
            Stage::Network => card.network().map(str::to_string),
            Stage::Binary => card.install().map(str::to_string),
            Stage::Copy => card.copying().map(|what| format!("sending the {what}")),
            Stage::Enroll | Stage::Finish => None,
        }
    }

    fn render_add_lines(&self, card: &AddCard, tokens: DesktopTokens) -> Option<gpui::Div> {
        let lines = card.lines().map(str::to_string).collect::<Vec<_>>();
        if lines.is_empty() {
            return None;
        }
        let omitted = card.lines_omitted();
        Some(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(design::eyebrow(tokens, "PIPELINE OUTPUT"))
                .child(
                    div()
                        .id("add-lines")
                        .flex()
                        .flex_col()
                        .max_h(px(180.0))
                        .overflow_y_scroll()
                        .track_scroll(&self.add_scroll)
                        .p_2()
                        .rounded(tokens.radius)
                        .bg(tokens.inset)
                        .text_xs()
                        .font_family("monospace")
                        .text_color(tokens.ink_2)
                        .when(omitted > 0, |body| {
                            body.child(
                                div()
                                    .text_color(tokens.ink_3)
                                    .child(format!("… {omitted} earlier lines omitted …")),
                            )
                        })
                        .children(lines.into_iter().map(|line| div().child(line))),
                ),
        )
    }

    fn render_account(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let tokens = design::tokens(cx);
        let requires_chatgpt = if self.show_new {
            self.new_requires_chatgpt(cx)
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
        // The composer below this state starts a session when none is open, so the empty
        // state points at it. Only where the reducer would actually take a start: on a
        // read-scope listener, or before the runtime answers, the composer is disabled and
        // "type below" would be a promise this client cannot keep.
        let idle_body = match self
            .app
            .as_ref()
            .filter(|app| app.sessions.open.is_none())
            .map(App::desktop_quick_start_context)
            .filter(|quick| quick.ready)
        {
            Some(quick) if !quick.workspace.is_empty() => format!(
                "Type below to start immediately in {}, or press New session to choose \
                 provider, model, and workspace.",
                quick.workspace
            ),
            Some(_) => "Type below to start immediately, or press New session to choose \
                        provider, model, and workspace."
                .to_string(),
            None => "Choose a workspace and model, then let Ouroboros keep the work visible."
                .to_string(),
        };
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
                            "The session will appear here as soon as it starts.".to_string()
                        } else if has_open_session {
                            "Send a message below to begin this session.".to_string()
                        } else {
                            idle_body
                        },
                    )
                    .when(!has_open_session && !self.show_new, |state| {
                        state.child(
                            design::primary_button("empty-new-session", "New session")
                                .icon(IconName::Plus)
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.show_new = true;
                                    this.open_new_session(window, cx);
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
                .when_some(approval.subagent, |view, subagent| {
                    view.child(
                        div()
                            .text_xs()
                            .text_color(tokens.tone(cx, Tone::Warning).foreground)
                            .child(subagent),
                    )
                })
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

    /// Keeps the composer's placeholder saying what pressing Enter will actually do.
    ///
    /// Written through the input's own state rather than the element, and only when the
    /// answer changes: `set_placeholder` notifies, and a notify every frame never settles.
    fn sync_composer_placeholder(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let wanted = match self.app.as_ref() {
            Some(app) if app.sessions.open.is_some() => COMPOSER_MESSAGE_PLACEHOLDER,
            Some(app) if app.desktop_quick_start_context().ready => {
                COMPOSER_QUICK_START_PLACEHOLDER
            }
            _ => COMPOSER_UNAVAILABLE_PLACEHOLDER,
        };
        if self.composer_placeholder == wanted {
            return;
        }
        self.composer_placeholder = wanted;
        self.composer
            .update(cx, |input, cx| input.set_placeholder(wanted, window, cx));
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
        // With nothing open the composer is a quick start rather than a disabled box that
        // offers to message a session that does not exist: the reducer starts one on the
        // stored defaults and sends what was typed as its first message.
        let quick_start = self
            .app
            .as_ref()
            .filter(|app| app.sessions.open.is_none())
            .map(App::desktop_quick_start_context);
        let can_send = match quick_start.as_ref() {
            Some(quick) => quick.ready && !quick.pending,
            None => {
                selected
                    .as_ref()
                    .is_some_and(|session| session.plane == Plane::Interactive)
                    && (!requires_chatgpt || account_usable)
            }
        };
        let working = selected
            .as_ref()
            .is_some_and(|session| session.triage == Triage::Working);
        let composer_empty = self.composer.read(cx).value().trim().is_empty();
        let (send_label, send_tooltip) = match quick_start.as_ref() {
            Some(_) => ("Start", "Start a session with this prompt · ↩"),
            None => ("Send", "Send message · ↩"),
        };
        // What Enter will do, in the same words the button wears.
        let (session_context, context_tooltip) = match quick_start.as_ref() {
            Some(quick) => {
                let mut parts = vec![
                    "New session".to_string(),
                    quick.provider.clone(),
                    quick.model.clone(),
                ];
                if !quick.workspace.is_empty() {
                    parts.push(workspace_tail(&quick.workspace).to_string());
                }
                let tooltip =
                    (!quick.workspace.is_empty()).then(|| format!("Starts in {}", quick.workspace));
                (parts.join(" · "), tooltip)
            }
            None if selected.is_some() => (
                selected
                    .as_ref()
                    .and_then(|session| session.model.clone())
                    .unwrap_or_else(|| "Interactive session".to_string()),
                None,
            ),
            // Neither a session nor a runtime to start one on.
            None => ("No session open".to_string(), None),
        };
        let auto_approve = self.app.as_ref().and_then(|app| app.desktop_auto_approve());
        // Absent means the runtime named no posture for this session. The control is then
        // omitted rather than guessed at: a picker with a checked row is a claim about
        // what the agent may touch, and this client does not have one to make.
        let sandbox = self.app.as_ref().and_then(|app| app.desktop_sandbox_mode());
        let reasoning = self.app.as_ref().and_then(App::desktop_reasoning);
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
                                design::primary_button("send", send_label)
                                    .icon(IconName::ArrowUp)
                                    .tooltip(send_tooltip)
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
                                    // posture, not an action highlight. The trigger wears
                                    // the same words as the menu row it corresponds to,
                                    // consequence included: a control that abbreviated
                                    // what the checked row spells out would be the one
                                    // place an operator could misread the posture.
                                    .children(sandbox.map(|current| {
                                        let picker_view = picker_view.clone();
                                        let trigger =
                                            design::secondary_button("sandbox-mode", current.title());
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
                                    .children(reasoning.map(|reasoning| {
                                        let current = reasoning.current;
                                        let choices = reasoning.choices;
                                        let picker_view = picker_view.clone();
                                        design::secondary_button(
                                            "reasoning-effort",
                                            format!(
                                                "Thinking · {}",
                                                current.map(Effort::label).unwrap_or("Default")
                                            ),
                                        )
                                        .tooltip("Default thinking level for future turns")
                                        .dropdown_menu(move |menu, _window, _cx| {
                                            choices.iter().copied().fold(
                                                menu.min_w(px(240.0)),
                                                |menu, effort| {
                                                    let view = picker_view.clone();
                                                    menu.item(
                                                        PopupMenuItem::new(effort.label())
                                                            .checked(current == Some(effort))
                                                            .on_click(move |_, _, cx| {
                                                                let _ = view.update(
                                                                    cx,
                                                                    |this, cx| {
                                                                        this.set_reasoning_effort(
                                                                            effort, cx,
                                                                        );
                                                                    },
                                                                );
                                                            }),
                                                    )
                                                },
                                            )
                                            .separator()
                                            .label("Applies to future turns in this session")
                                        })
                                    }))
                                    .child({
                                        let context = div()
                                            .flex_1()
                                            .min_w_0()
                                            .text_ellipsis()
                                            .child(session_context);
                                        // The workspace is shortened to fit one line, so
                                        // the path it stands for stays reachable.
                                        match context_tooltip {
                                            Some(full) => context
                                                .id("composer-context")
                                                .tooltip(move |window, cx| {
                                                    Tooltip::new(full.clone()).build(window, cx)
                                                })
                                                .into_any_element(),
                                            None => context.into_any_element(),
                                        }
                                    }),
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
                                            .child(send_label)
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
        // The pickers are reconciled here because this is the only place holding a
        // `Window`, and only while the form is on screen: it is the sole reader, and a
        // reconcile that changes nothing is what every later frame does anyway.
        if self.show_new {
            self.sync_pickers(window, cx);
        }

        let tokens = design::tokens(cx);
        self.sync_composer_placeholder(window, cx);
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

        let session_workspace = div()
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
            .when(self.show_machines, |view| {
                view.child(self.render_machines(cx))
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
            .when(
                !self.show_new && !self.show_machines && !approval_pending,
                |view| view.child(self.render_composer(cx)),
            );

        div()
            .track_focus(&self.focus_handle)
            .on_action(cx.listener(Self::submit_composer))
            .capture_key_down(cx.listener(Self::handle_key_down))
            .flex()
            .size_full()
            .bg(tokens.page)
            .text_color(tokens.ink)
            .text_sm()
            .child(
                h_resizable("desktop-workspace")
                    .child(
                        resizable_panel()
                            .size(px(SESSION_RAIL_DEFAULT_WIDTH))
                            .size_range(px(SESSION_RAIL_MIN_WIDTH)..px(SESSION_RAIL_MAX_WIDTH))
                            .child(self.render_session_rail(cx)),
                    )
                    .child(
                        resizable_panel()
                            .size_range(px(SESSION_WORKSPACE_MIN_WIDTH)..gpui::Pixels::MAX)
                            .child(session_workspace),
                    ),
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
        DesktopCellKind::Image { .. } => render_image_cell(index, cell, tokens, cx),
        _ => render_meta_cell(index, cell, expanded, expansion_key, tokens, window, cx),
    }
}

/// A11. A desktop screenshot artifact, drawn as the picture it is (§8.6).
///
/// This is the surface the two encoders never could be: GPUI decodes and rasterises the bytes
/// itself, so the drawable the artifact carried is handed to `gpui::img` and shown, rather
/// than described. Until a surface has fetched the bytes by sha the cell is a
/// placeholder-with-real-dimensions — the same honest fallback the transcript keeps — and the
/// caption ([`DesktopCell::body`]) states the size and digest either way. The pixels are read
/// from the kind, never from the body, so nothing here turns text into an image.
fn render_image_cell(
    index: usize,
    cell: DesktopCell,
    tokens: DesktopTokens,
    cx: &mut Context<DesktopView>,
) -> gpui::AnyElement {
    let (bytes, media_type) = match &cell.kind {
        DesktopCellKind::Image {
            bytes, media_type, ..
        } => (bytes.clone(), media_type.clone()),
        // render_cell only routes Image cells here; a different shape is shown as its caption
        // rather than a panic, because crashing on an unexpected cell is the worse failure.
        _other => (None, None),
    };

    let caption = cell.body;

    let picture = bytes.map(|bytes| {
        img(Arc::new(Image::from_bytes(
            image_format(media_type.as_deref()),
            bytes.as_ref().clone(),
        )))
        .id(("desktop-screenshot", index))
        .max_w(px(480.0))
        .max_h(px(360.0))
        .rounded(tokens.radius)
        .into_any_element()
    });

    let content = div()
        .flex()
        .flex_col()
        .gap_2()
        .min_w_0()
        .child(div().text_xs().text_color(tokens.ink_3).child(caption));

    let content = match picture {
        Some(picture) => content.child(picture),
        None => content,
    };

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
                .child(design::icon_tile(
                    tokens,
                    cx,
                    Tone::Neutral,
                    IconName::Frame,
                ))
                .child(
                    design::card(tokens, cx, Tone::Neutral)
                        .px_4()
                        .py_3()
                        .child(content),
                ),
        )
        .into_any_element()
}

/// The `gpui::ImageFormat` for a media type, defaulting to PNG.
///
/// GPUI reads the format from the bytes regardless, so this is the hint, not the authority;
/// PNG is the safe default because it is what a screenshot most often is and what the decoder
/// tries first anyway.
fn image_format(media_type: Option<&str>) -> ImageFormat {
    match media_type
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("image/jpeg" | "image/jpg") => ImageFormat::Jpeg,
        Some("image/gif") => ImageFormat::Gif,
        Some("image/webp") => ImageFormat::Webp,
        _png => ImageFormat::Png,
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
        .max_w(px(880.0))
        .mx_auto()
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
        // The same icon an agent message carries, because that is what this row is: work
        // another agent did, reported here.
        DesktopCellKind::Subagent => IconName::Bot,
        DesktopCellKind::Status => IconName::Info,
        DesktopCellKind::Divider => IconName::Dash,
        // Routed to `render_image_cell` before reaching here; kept so the match stays
        // exhaustive rather than needing a catch-all that would hide a future variant.
        DesktopCellKind::Image { .. } => IconName::Frame,
    };
    let label = cell.label;
    let tooltip_label = label.clone();
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
        .max_w(px(880.0))
        .mx_auto()
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
                        .w_full()
                        .min_w_0()
                        .text_xs()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(label_color)
                        .child(
                            div()
                                .id(("meta-cell-label", index))
                                .w_full()
                                .min_w_0()
                                .truncate()
                                .child(label)
                                .tooltip(move |window, cx| {
                                    Tooltip::new(tooltip_label.clone()).build(window, cx)
                                }),
                        )
                        .when(cell.streaming, |row| {
                            row.child(Spinner::new().small().color(tokens.accent))
                        }),
                )
                .when(!shown_body.trim().is_empty(), |view| {
                    if mono {
                        let output = design::inset(tokens)
                            .id(("tool-output", index))
                            .w_full()
                            .min_w_0()
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

/// The last component of a workspace path, for a footer line that has to fit beside a
/// provider and a model. The full path stays in the tooltip; this never replaces it.
fn workspace_tail(workspace: &str) -> &str {
    workspace
        .trim_end_matches('/')
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(workspace)
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

/// One row of the new-session provider picker.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderRow {
    name: SharedString,
    /// Whether `runtime.providers` reported a probe that found a usable executable.
    /// `false` is drawn dim and annotated but stays selectable: the probe found no
    /// executable, which is all it knows, and the runtime — not this window — is the
    /// authority on whether a session can start.
    detected: bool,
    /// The stored default, which this runtime's provider list does not name. Kept for the
    /// same reason the settings picker keeps it: a config written elsewhere would
    /// otherwise vanish from the form that is about to send it.
    unserved: bool,
}

impl ProviderRow {
    /// What the row says beside the name, or `None` when there is nothing to add.
    fn note(&self) -> Option<SharedString> {
        match (self.unserved, self.detected) {
            (true, _) => Some("not reported here".into()),
            (false, false) => Some("no executable found".into()),
            (false, true) => None,
        }
    }
}

impl SelectItem for ProviderRow {
    type Value = SharedString;

    fn title(&self) -> SharedString {
        self.name.clone()
    }

    fn value(&self) -> &Self::Value {
        &self.name
    }

    fn render(&self, _: &mut Window, cx: &mut GpuiApp) -> impl IntoElement {
        let tokens = design::tokens(cx);

        div()
            .flex()
            .items_center()
            .gap_2()
            .when(self.note().is_some(), |row| row.text_color(tokens.ink_2))
            .child(self.name.clone())
            .when_some(self.note(), |row, note| {
                row.child(div().text_xs().text_color(tokens.ink_3).child(note))
            })
    }
}

/// Which choice a model row stands for. This — not the row's label — is what the form
/// reads back when it builds the request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ModelChoice {
    /// Send no model option at all and let the runtime apply whatever it configured.
    RuntimeDefault,
    /// A catalogue id, already carrying whatever prefix this provider's option needs.
    Catalog(SharedString),
    /// Whatever the operator types into the text field this row reveals.
    Custom,
}

/// One row of the new-session model picker.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelRow {
    choice: ModelChoice,
    /// The closed picker's label. For a catalogue row this is the id itself, so what is
    /// on screen is exactly what the request will carry.
    label: SharedString,
    /// The vendor's name for the model and the window it was given — secondary text only,
    /// and absent when the snapshot stated neither.
    detail: Option<SharedString>,
}

impl SelectItem for ModelRow {
    type Value = ModelChoice;

    /// Also the text the searchable list filters on, which is why the detail is folded in
    /// here: a person hunting "opus" is typing the vendor's name, not the id.
    fn title(&self) -> SharedString {
        match &self.detail {
            Some(detail) => format!("{} {detail}", self.label).into(),
            None => self.label.clone(),
        }
    }

    /// The closed picker shows the label alone; the search text above would read as a
    /// claim about what is being sent.
    fn display_title(&self) -> Option<AnyElement> {
        Some(div().child(self.label.clone()).into_any_element())
    }

    fn value(&self) -> &Self::Value {
        &self.choice
    }

    fn render(&self, _: &mut Window, cx: &mut GpuiApp) -> impl IntoElement {
        let tokens = design::tokens(cx);

        div()
            .flex()
            .flex_col()
            .gap_0p5()
            .child(self.label.clone())
            .when_some(self.detail.clone(), |row, detail| {
                row.child(div().text_xs().text_color(tokens.ink_3).child(detail))
            })
    }
}

/// What the new-session model field can honestly offer for one provider.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ModelField {
    /// There is no catalogue to filter, so the field stays the free-text input it always
    /// was. `hint` says why when there is a reason worth stating; `None` is the ordinary
    /// case of a gateway that does not serve `runtime.models` at all.
    Text { hint: Option<SharedString> },
    /// The adapter normalizes no `model` option, so there is nothing a picker could send.
    Unsupported,
    /// The catalogue's rows: "Runtime default" first, "Custom…" last. `total` is the
    /// catalogue's own count, above `rows` whenever the runtime truncated the list.
    Rows { rows: Vec<ModelRow>, total: u64 },
}

impl ModelField {
    /// Whether `choice` is something this field can actually offer.
    ///
    /// Asked whenever the rows are rebuilt: a model picked under the previous provider is
    /// not necessarily a row under the new one, and a choice with no row would leave the
    /// window claiming a model the control cannot show.
    fn offers(&self, choice: &ModelChoice) -> bool {
        match self {
            // Neither field has rows at all, so the only choice either can stand behind is
            // the one that means "no model option" — the text input answers the rest.
            Self::Text { .. } | Self::Unsupported => *choice == ModelChoice::RuntimeDefault,
            Self::Rows { rows, .. } => rows.iter().any(|row| row.choice == *choice),
        }
    }
}

/// What the form will send for the model, and the sentence that says so.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelIntent {
    /// The `model` option the start request will carry. `None` sends none at all, which
    /// is what leaves the choice to the runtime.
    send: Option<String>,
    /// The line drawn under the field, stating the above in words.
    ///
    /// This is the field's authoritative reading. The picker's own closed label is
    /// resolved by the component against its *filtered* rows and can disagree with the
    /// choice this window holds — see the note on [`DesktopView::model_choice`] — so the
    /// sentence and the value are produced together, here, and never separately.
    hint: SharedString,
}

/// What the form will send for the model, given the field on screen, the choice this
/// window holds, and whatever is in the text input.
fn model_intent(field: &ModelField, choice: &ModelChoice, typed: &str) -> ModelIntent {
    let typed = typed.trim();

    let send = match (field, choice) {
        // The adapter normalizes no model option, so naming one would name something
        // nothing downstream reads.
        (ModelField::Unsupported, _) => None,
        (ModelField::Text { .. }, _) | (ModelField::Rows { .. }, ModelChoice::Custom) => {
            (!typed.is_empty()).then(|| typed.to_string())
        }
        (ModelField::Rows { .. }, ModelChoice::Catalog(id)) => Some(id.to_string()),
        (ModelField::Rows { .. }, ModelChoice::RuntimeDefault) => None,
    };

    let hint = match (field, &send) {
        (ModelField::Unsupported, _) => {
            "Sends no model option — this provider does not accept one".into()
        }
        (_, Some(model)) => format!("Sends {model}").into(),
        (_, None) => "Sends no model option (runtime default)".into(),
    };

    ModelIntent { send, hint }
}

fn resolved_reasoning_effort(selected: Effort, choices: &[Effort]) -> Option<Effort> {
    if choices.contains(&selected) {
        Some(selected)
    } else if choices.contains(&Effort::High) {
        Some(Effort::High)
    } else {
        choices.first().copied()
    }
}

/// The rows the new-session provider picker offers.
///
/// [`provider_choices`] already owns the rule that matters — the stored default gets a row
/// even when this runtime's probe list has none — so this reuses it and drops only the
/// "unset" row, which the settings picker needs and this form cannot use: a start request
/// names a provider, and this form is where that name is stated.
fn provider_rows(
    providers: &Loadable<Vec<ProviderEntry>>,
    stored: Option<&str>,
) -> Vec<ProviderRow> {
    let entries = providers.value.as_deref().unwrap_or_default();

    provider_choices(entries, stored)
        .into_iter()
        .filter_map(|choice| match choice {
            ProviderChoice::Unset => None,
            ProviderChoice::Probed { name, ready } => Some(ProviderRow {
                name: name.into(),
                detected: ready,
                unserved: false,
            }),
            ProviderChoice::Unserved { name } => Some(ProviderRow {
                name: name.into(),
                detected: false,
                unserved: true,
            }),
        })
        .collect()
}

/// What the model field becomes for `provider`, given whatever the catalogue fetch has
/// produced so far.
///
/// Every path that cannot offer a list falls back to the text input rather than to an
/// empty picker, because an empty picker claims the runtime knows of no models and none of
/// these paths know that.
fn model_field(models: &Loadable<ModelsCatalog>, provider: &str) -> ModelField {
    let provider = provider.trim();

    let Some(catalogue) = models.value.as_ref() else {
        return ModelField::Text {
            hint: match (models.error.as_deref(), models.pending) {
                (Some(error), _) => {
                    Some(format!("the model list could not be read: {error}").into())
                }
                (None, true) => Some("reading the model list…".into()),
                // Never asked, or this gateway does not serve the verb. Either way the
                // field is what it was before the verb existed, and says nothing extra.
                (None, false) => None,
            },
        };
    };

    if provider.is_empty() {
        return ModelField::Text {
            hint: Some("choose a provider to see its models".into()),
        };
    }

    let Some(row) = catalogue.provider(provider) else {
        return ModelField::Text {
            hint: Some(format!("this runtime's model list does not mention {provider}").into()),
        };
    };

    if !row.model_option {
        return ModelField::Unsupported;
    }

    let default = ModelRow {
        choice: ModelChoice::RuntimeDefault,
        label: match row
            .default
            .as_deref()
            .map(str::trim)
            .filter(|default| !default.is_empty())
        {
            Some(default) => format!("Runtime default · {default}").into(),
            None => "Runtime default".into(),
        },
        detail: Some("Send no model and let the runtime choose".into()),
    };

    let mut rows = vec![default];
    rows.extend(row.models.iter().map(|model| ModelRow {
        choice: ModelChoice::Catalog(model.id.clone().into()),
        label: model.id.clone().into(),
        detail: model.detail().map(SharedString::from),
    }));
    rows.push(ModelRow {
        choice: ModelChoice::Custom,
        label: "Custom…".into(),
        detail: Some("Type a model id this list does not carry".into()),
    });

    ModelField::Rows {
        rows,
        total: row.total,
    }
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

    /// The quick-start footer shortens the workspace to fit one line beside a provider and
    /// a model. It must never shorten it to nothing — the tooltip carries the full path,
    /// but this is the part an operator reads first.
    #[test]
    fn the_quick_start_workspace_shortens_to_a_name_that_is_still_a_name() {
        assert_eq!(workspace_tail("/Users/dev/code/ouroboros"), "ouroboros");
        assert_eq!(workspace_tail("/Users/dev/code/ouroboros/"), "ouroboros");
        assert_eq!(workspace_tail("ouroboros"), "ouroboros");
        assert_eq!(workspace_tail("/"), "/");
        assert_eq!(workspace_tail(""), "");
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

    /// GPUI widgets need a window server, so the two pickers are tested through the pure
    /// functions that decide what goes in them. What is left untested here is only the
    /// drawing.
    fn loaded<T>(value: T) -> Loadable<T> {
        Loadable {
            value: Some(value),
            error: None,
            pending: false,
            next_tick: 0,
        }
    }

    fn probes() -> Loadable<Vec<ProviderEntry>> {
        loaded(ProviderEntry::decode_list(&serde_json::json!([
            {
                "provider": "native",
                "spec": {},
                "status": { "installed": true, "compatible": true },
                "error": null
            },
            {
                "provider": "claude",
                "spec": {},
                "status": { "installed": false, "compatible": false },
                "error": null
            },
            { "provider": "kimi", "spec": {}, "status": null, "error": "probe_timeout" }
        ])))
    }

    fn catalogue() -> Loadable<ModelsCatalog> {
        loaded(
            ModelsCatalog::decode(&serde_json::json!({
                "source": "llm_db",
                "epoch": 41,
                "limit": 2,
                "providers": [
                    {
                        "provider": "native",
                        "catalog": "openai",
                        "default": "openai_codex:gpt-5.6-sol",
                        "model_option": true,
                        "total": 9,
                        "models": [
                            {
                                "id": "openai_codex:gpt-5.6-sol",
                                "name": "GPT-5.6 Sol",
                                "context_window": 400000,
                                "reasoning_efforts": ["low", "medium", "high"]
                            },
                            {
                                "id": "openai_codex:gpt-5.2-codex",
                                "reasoning_efforts": []
                            }
                        ]
                    },
                    {
                        "provider": "amp",
                        "catalog": null,
                        "default": null,
                        "model_option": false,
                        "total": 0,
                        "models": []
                    }
                ]
            }))
            .expect("a catalogue"),
        )
    }

    #[test]
    fn a_provider_whose_probe_found_nothing_is_annotated_and_still_offered() {
        let rows = provider_rows(&probes(), Some("native"));

        assert_eq!(
            rows.iter().map(|row| row.name.as_ref()).collect::<Vec<_>>(),
            ["native", "claude", "kimi"],
            "every provider the runtime reports is a row the operator can pick"
        );
        assert_eq!(rows[0].note(), None);
        // "no executable found" is what a probe can say. "unavailable" would be this
        // window overruling the runtime, which is the only thing that can actually refuse.
        assert_eq!(rows[1].note(), Some("no executable found".into()));
        assert_eq!(
            rows[2].note(),
            Some("no executable found".into()),
            "a probe that timed out is not a probe that succeeded"
        );
    }

    #[test]
    fn a_stored_default_this_runtime_does_not_report_keeps_its_row() {
        let rows = provider_rows(&probes(), Some("opencode"));

        let stored = rows.last().expect("a row for the stored default");
        assert_eq!(stored.name.as_ref(), "opencode");
        assert!(stored.unserved);
        assert_eq!(stored.note(), Some("not reported here".into()));
        assert_eq!(
            rows.len(),
            4,
            "the settings picker's \"unset\" row has no meaning in a form that must name \
             a provider: {rows:?}"
        );
    }

    #[test]
    fn an_unanswered_provider_list_offers_only_what_the_configuration_named() {
        let rows = provider_rows(&Loadable::default(), Some("native"));

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name.as_ref(), "native");
        assert!(
            rows[0].unserved,
            "before the probe answers, the only row is the stored one — which is why the \
             form still shows its text field"
        );
        assert!(provider_rows(&Loadable::default(), None).is_empty());
    }

    #[test]
    fn the_model_rows_frame_the_catalogue_with_a_default_and_an_escape_hatch() {
        let ModelField::Rows { rows, total } = model_field(&catalogue(), "native") else {
            panic!("the native row carries a model option");
        };

        assert_eq!(total, 9, "the count that did not fit is still reported");
        assert_eq!(
            rows.iter()
                .map(|row| row.choice.clone())
                .collect::<Vec<_>>(),
            [
                ModelChoice::RuntimeDefault,
                ModelChoice::Catalog("openai_codex:gpt-5.6-sol".into()),
                ModelChoice::Catalog("openai_codex:gpt-5.2-codex".into()),
                ModelChoice::Custom,
            ]
        );
        assert_eq!(
            rows[0].label.as_ref(),
            "Runtime default · openai_codex:gpt-5.6-sol",
            "the default is named when the runtime named it"
        );
        assert_eq!(
            rows[1].label.as_ref(),
            "openai_codex:gpt-5.6-sol",
            "the label is the id the request will carry, prefix and all"
        );
        assert_eq!(rows[1].detail, Some("GPT-5.6 Sol · 400K context".into()));
        assert!(
            rows[1].title().contains("GPT-5.6 Sol"),
            "the searchable text folds in the vendor's name: {:?}",
            rows[1].title()
        );
        assert_eq!(rows[2].detail, None);
    }

    #[test]
    fn a_provider_that_takes_no_model_option_gets_no_picker_to_send_from() {
        assert_eq!(model_field(&catalogue(), "amp"), ModelField::Unsupported);
    }

    #[test]
    fn a_catalogue_that_cannot_answer_leaves_the_text_field_in_place() {
        // Never asked, or a gateway that does not serve `runtime.models`. The field is
        // what it always was and says nothing it cannot support.
        assert_eq!(
            model_field(&Loadable::default(), "native"),
            ModelField::Text { hint: None }
        );

        let pending = Loadable::<ModelsCatalog> {
            pending: true,
            ..Loadable::default()
        };
        assert_eq!(
            model_field(&pending, "native"),
            ModelField::Text {
                hint: Some("reading the model list…".into())
            }
        );

        let failed = Loadable::<ModelsCatalog> {
            error: Some("upstream timeout".to_string()),
            ..Loadable::default()
        };
        assert_eq!(
            model_field(&failed, "native"),
            ModelField::Text {
                hint: Some("the model list could not be read: upstream timeout".into())
            }
        );

        assert_eq!(
            model_field(&catalogue(), "opencode"),
            ModelField::Text {
                hint: Some("this runtime's model list does not mention opencode".into())
            },
            "a provider the catalogue omits gets a text field, not an empty list that \
             would claim the runtime knows of no models"
        );
    }

    fn rows_field() -> ModelField {
        model_field(&catalogue(), "native")
    }

    /// The line on screen and the value in the request come out of one function, so this
    /// pins both at once: whatever the sentence says is what `send` carries.
    #[test]
    fn the_model_line_says_exactly_what_the_request_will_carry() {
        let field = rows_field();

        let default = model_intent(&field, &ModelChoice::RuntimeDefault, "ignored");
        assert_eq!(default.send, None);
        assert_eq!(default.hint, "Sends no model option (runtime default)");

        let chosen = model_intent(
            &field,
            &ModelChoice::Catalog("openai_codex:gpt-5.6-sol".into()),
            "ignored",
        );
        assert_eq!(chosen.send.as_deref(), Some("openai_codex:gpt-5.6-sol"));
        assert_eq!(chosen.hint, "Sends openai_codex:gpt-5.6-sol");

        let custom = model_intent(&field, &ModelChoice::Custom, "  my-private-build  ");
        assert_eq!(
            custom.send.as_deref(),
            Some("my-private-build"),
            "the typed id is trimmed before it is sent"
        );
        assert_eq!(custom.hint, "Sends my-private-build");

        let blank = model_intent(&field, &ModelChoice::Custom, "   ");
        assert_eq!(blank.send, None);
        assert_eq!(
            blank.hint, "Sends no model option (runtime default)",
            "an empty Custom field sends nothing, and says so rather than implying a model"
        );
    }

    #[test]
    fn high_is_the_reasoning_default_without_inventing_an_unsupported_level() {
        let all = [Effort::Low, Effort::Medium, Effort::High];
        assert_eq!(
            resolved_reasoning_effort(Effort::High, &all),
            Some(Effort::High)
        );

        let narrow = [Effort::Low, Effort::Medium];
        assert_eq!(
            resolved_reasoning_effort(Effort::High, &narrow),
            Some(Effort::Low)
        );
        assert_eq!(resolved_reasoning_effort(Effort::High, &[]), None);
    }

    #[test]
    fn a_text_field_reads_what_was_typed_and_a_refused_option_reads_nothing() {
        let text = ModelField::Text { hint: None };
        // The choice is irrelevant here: there are no rows behind it, and the control the
        // operator can see is the text input.
        let typed = model_intent(&text, &ModelChoice::RuntimeDefault, "claude-opus-5");
        assert_eq!(typed.send.as_deref(), Some("claude-opus-5"));
        assert_eq!(typed.hint, "Sends claude-opus-5");

        let refused = model_intent(
            &ModelField::Unsupported,
            &ModelChoice::Catalog("claude-opus-5".into()),
            "claude-opus-5",
        );
        assert_eq!(
            refused.send, None,
            "an adapter that normalizes no model option is never sent one, whatever is \
             left over in the choice or the text field"
        );
        assert_eq!(
            refused.hint,
            "Sends no model option — this provider does not accept one"
        );
    }

    /// The guard that keeps a choice from outliving the rows that justified it. Without
    /// it, changing provider would leave the window claiming a model whose row the
    /// operator can no longer see.
    #[test]
    fn a_field_only_stands_behind_a_choice_it_can_show() {
        let field = rows_field();

        assert!(field.offers(&ModelChoice::RuntimeDefault));
        assert!(field.offers(&ModelChoice::Custom));
        assert!(field.offers(&ModelChoice::Catalog("openai_codex:gpt-5.6-sol".into())));
        assert!(
            !field.offers(&ModelChoice::Catalog("claude-opus-5".into())),
            "a model from another provider's catalogue is not a row here"
        );

        for bare in [ModelField::Text { hint: None }, ModelField::Unsupported] {
            assert!(bare.offers(&ModelChoice::RuntimeDefault));
            assert!(
                !bare.offers(&ModelChoice::Custom)
                    && !bare.offers(&ModelChoice::Catalog("anything".into())),
                "a field with no rows can only stand behind \"no model option\": {bare:?}"
            );
        }
    }
}
