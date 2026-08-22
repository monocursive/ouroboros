//! The terminal driver: everything that is I/O, and nothing that is a decision.
//!
//! [`app::App`] is a state machine with no socket in it, so this module is the only place
//! that touches a terminal, spawns a task, or awaits a call. The division is what keeps
//! the render loop unblocked: a request leaves the App as a [`app::Call`] in a queue, this
//! module spawns a task for it, and the answer arrives later as [`app::Msg::Answer`]. No
//! frame ever waits on a runtime that declares 120-second ceilings.
//!
//! ## The reconnect hook is the same code path
//!
//! [`hook`] hands `transport::connect` something that, after every re-handshake,
//! resubscribes each watched session at its last seen sequence and posts the answer as an
//! ordinary `Msg::Answer { tag: Tag::Resync { .. } }`. That is deliberately the exact
//! message a lag-triggered replay produces, so reconnect, lag, a client-side notification
//! drop, and a pruned cursor converge on one reconciliation in `App`, as §3.3 requires.
//!
//! ## The terminal is entered once
//!
//! [`Screen`] is taken over before the runtime is started, not after: [`boot`] draws the
//! spawn into it and then hands the same live terminal to [`run`]. So the alternate screen
//! is entered exactly once per process, and there is no window between the boot screen and
//! the first frame in which a panic would land on a terminal nobody owns.

pub mod app;
pub mod boot;
pub mod code;
pub mod dashboard;
pub mod editor;
pub mod explorer;
pub mod logo;
pub mod logs;
pub mod sessions;
pub mod theme;
pub mod transcript;
pub mod transcript_cells;
pub mod tree;
pub mod view;

use std::env;
use std::fs;
use std::io::{self, IsTerminal, Stdout, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use crossterm::cursor::MoveTo;
use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture, Event,
    KeyEventKind, KeyboardEnhancementFlags, MouseEventKind, PopKeyboardEnhancementFlags,
    PushKeyboardEnhancementFlags,
};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, supports_keyboard_enhancement, Clear, ClearType,
    EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use serde_json::json;
use tokio::sync::mpsc;

use crate::fleet::{self, Ports};
use crate::fleet_add::{self, CandidateSource};
use crate::proto::{Hello, Notification};
use crate::runtime::Daemon;
use crate::transport::{Client, HookFuture, ReconnectHook};

pub use app::{App, Call, Cursors, Mode, Msg, Quit, Tag, TICK};

/// The App's inbox, plus the cursor table the reconnect hook reads.
pub struct UiChannel {
    pub cursors: Cursors,
    pub sender: mpsc::UnboundedSender<Msg>,
    receiver: mpsc::UnboundedReceiver<Msg>,
}

impl UiChannel {
    /// The three pieces, for a driver that is not [`run`] — which in practice means the
    /// tests, whose loop is this one without a terminal in it.
    pub fn into_parts(
        self,
    ) -> (
        Cursors,
        mpsc::UnboundedSender<Msg>,
        mpsc::UnboundedReceiver<Msg>,
    ) {
        (self.cursors, self.sender, self.receiver)
    }
}

struct StreamHook {
    cursors: Cursors,
    sender: mpsc::UnboundedSender<Msg>,
}

impl ReconnectHook for StreamHook {
    fn after_reconnect(&self, client: Client, hello: Hello) -> HookFuture {
        let cursors = self.cursors.clone();
        let sender = self.sender.clone();

        Box::pin(async move {
            let _ = sender.send(Msg::Reconnected(Box::new(hello)));

            // The subscription died with the socket, so every watched session is
            // re-registered here — at its own cursor, which is the contiguous high-water
            // mark and not the newest sequence seen.
            for (plane, id, cursor, node) in cursors.snapshot() {
                let mut params = json!({ "id": id.clone(), "cursor": cursor });
                if let (Some(node), Some(fields)) = (node, params.as_object_mut()) {
                    fields.insert("node".into(), json!(node));
                }
                let result = client.call(&plane.method("subscribe"), params).await;

                let sent = sender.send(Msg::Answer {
                    tag: Tag::Resync {
                        plane,
                        id,
                        cursor,
                        subscribe: true,
                    },
                    result,
                });

                if sent.is_err() {
                    return;
                }
            }
        })
    }
}

/// The hook to hand `transport::connect`, and the channel the UI reads.
pub fn hook() -> (Arc<dyn ReconnectHook>, UiChannel) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let cursors = Cursors::default();

    let hook = Arc::new(StreamHook {
        cursors: cursors.clone(),
        sender: sender.clone(),
    });

    (
        hook,
        UiChannel {
            cursors,
            sender,
            receiver,
        },
    )
}

/// Raw mode and the alternate screen, restored however the owner is dropped.
///
/// Public because the boot screen enters it before there is an App and hands it over
/// afterwards. Owning it is the whole contract: whoever holds one is drawing, and dropping
/// it puts the operator's shell back.
pub struct Screen {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

/// Whether this process pushed the keyboard-enhancement flags and the terminal took them.
///
/// A process-wide atomic rather than state on [`Screen`], because [`restore`] runs from the
/// panic hook, which has no handle on anything.
static ENHANCED_KEYBOARD: AtomicBool = AtomicBool::new(false);

/// Whether this terminal can tell `Shift+Enter` from `Enter`.
///
/// Without the kitty protocol the two are the same bytes — Terminal.app, iTerm2's default
/// profile, and tmux without passthrough all send a bare `CR` for both. A footer that
/// advertised `Shift+Enter` there would be telling someone to press send.
pub fn keyboard_enhanced() -> bool {
    ENHANCED_KEYBOARD.load(Ordering::SeqCst)
}

impl Screen {
    /// Whether stdout is something this client could take over, asked without taking it.
    ///
    /// [`boot::Boot`] needs the answer before it has anywhere to report a refusal, and a
    /// pipe is a perfectly ordinary thing for `ouro daemon` or a redirect to be attached
    /// to. [`enter`](Self::enter) is still the one that refuses, so the error text lives in
    /// exactly one place.
    pub fn available() -> bool {
        io::stdout().is_terminal()
    }

    pub fn enter() -> Result<Self> {
        if !Self::available() {
            bail!(
                "the terminal UI needs a tty on stdout. Use `ouro attach --print` for a \
                 one-shot status page, or run this from a terminal"
            );
        }

        // A panic that left the terminal in raw mode would take the shell with it, and
        // the backtrace would be unreadable in a screen nobody restored.
        let previous = std::panic::take_hook();

        std::panic::set_hook(Box::new(move |info| {
            restore();
            previous(info);
        }));

        enable_raw_mode().context("putting the terminal into raw mode")?;
        io::stdout()
            .execute(EnterAlternateScreen)
            .context("entering the alternate screen")?
            .execute(EnableBracketedPaste)
            .context("enabling bracketed paste")?
            .execute(EnableMouseCapture)
            .context("enabling mouse capture")?;

        // Asked rather than assumed, and only claimed where the terminal answered yes: the
        // composer advertises `Shift+Enter` for a newline, and in a terminal without this
        // protocol that keystroke is indistinguishable from `Enter` and would send.
        //
        // Not an error when it is refused. A terminal that does not speak the kitty
        // protocol is an ordinary terminal, and `Ctrl+J` is the binding that always works.
        if matches!(supports_keyboard_enhancement(), Ok(true))
            && io::stdout()
                .execute(PushKeyboardEnhancementFlags(
                    KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES,
                ))
                .is_ok()
        {
            ENHANCED_KEYBOARD.store(true, Ordering::SeqCst);
        }

        let terminal = Terminal::new(CrosstermBackend::new(io::stdout()))
            .context("taking over the terminal")?;

        Ok(Self { terminal })
    }

    /// The terminal itself, for a caller that draws its own frames into it — which is the
    /// boot screen, and nothing else.
    pub fn terminal(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }

    fn suspend(&mut self) {
        restore();
    }

    fn resume(&mut self) -> Result<()> {
        enable_raw_mode().context("restoring raw mode after $EDITOR")?;
        io::stdout()
            .execute(EnterAlternateScreen)
            .context("re-entering the alternate screen")?
            .execute(EnableBracketedPaste)
            .context("re-enabling bracketed paste")?
            .execute(EnableMouseCapture)
            .context("re-enabling mouse capture")?;

        if matches!(supports_keyboard_enhancement(), Ok(true))
            && io::stdout()
                .execute(PushKeyboardEnhancementFlags(
                    KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES,
                ))
                .is_ok()
        {
            ENHANCED_KEYBOARD.store(true, Ordering::SeqCst);
        }

        Ok(())
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        restore();
    }
}

fn restore() {
    // Popped before the screen is left, and exactly as many times as it was pushed — the
    // terminal keeps a stack, and a process that exited without unwinding its own entry
    // would leave the operator's shell reporting keys the way this client wanted them.
    // `swap` because the panic hook and `Drop` can both reach here.
    if ENHANCED_KEYBOARD.swap(false, Ordering::SeqCst) {
        let _ = io::stdout().execute(PopKeyboardEnhancementFlags);
    }

    let _ = disable_raw_mode();
    let _ = io::stdout()
        .execute(DisableMouseCapture)
        .and_then(|stdout| stdout.execute(DisableBracketedPaste))
        .and_then(|stdout| stdout.execute(LeaveAlternateScreen));
}

fn copy_pending(app: &mut App) {
    let Some(text) = app.take_copy() else {
        return;
    };

    let encoded = base64_encode(text.as_bytes());
    let _ = write!(io::stdout(), "\x1b]52;c;{encoded}\x07");
    let _ = io::stdout().flush();

    #[cfg(target_os = "macos")]
    tokio::task::spawn_blocking(move || {
        if let Ok(mut child) = ProcessCommand::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    });
}

/// Runs `$VISUAL`/`$EDITOR` over `draft` and returns what came back.
///
/// Everything here blocks for as long as the person holding the editor keeps it open,
/// which is why the driver calls it through [`tokio::task::spawn_blocking`] rather than
/// inline: the render loop and the notification pump keep running meanwhile.
fn run_external_editor(draft: &str) -> Result<String> {
    let editor = env::var("VISUAL")
        .or_else(|_| env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());
    let path = draft_path();

    let outcome = (|| {
        write_private_draft(&path, draft).with_context(|| format!("writing {}", path.display()))?;

        let status = ProcessCommand::new("sh")
            .arg("-c")
            .arg(format!("{editor} \"$1\""))
            .arg("ouro-editor")
            .arg(&path)
            .status()
            .with_context(|| format!("running {editor}"))?;

        if !status.success() {
            bail!("{editor} exited with {status}");
        }

        // An editor that saves by writing a sibling and renaming replaces the inode this
        // module created, and the replacement carries whatever mode the editor chose.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if let Ok(metadata) = fs::metadata(&path) {
                let mut permissions = metadata.permissions();
                let mode = permissions.mode();

                if mode & 0o077 != 0 {
                    permissions.set_mode(mode & !0o077);
                    let _ = fs::set_permissions(&path, permissions);
                }
            }
        }

        fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
    })();

    let _ = fs::remove_file(&path);

    outcome.map(|text| text.replace("\r\n", "\n").replace('\r', "\n"))
}

fn draft_path() -> PathBuf {
    env::temp_dir().join(format!("ouro-prompt-{}.md", std::process::id()))
}

/// Creates the draft exclusively, privately, and never through a symlink that got there
/// first. A predictable name is safe under those three properties: nothing can preplant
/// the path, and nothing but its owner can read what lands in it.
#[cfg(unix)]
fn write_private_draft(path: &Path, draft: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;

    file.write_all(draft.as_bytes())?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_draft(path: &Path, draft: &str) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;

    file.write_all(draft.as_bytes())?;
    file.sync_all()
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut index = 0;

    while index < bytes.len() {
        let b0 = bytes[index];
        let b1 = bytes.get(index + 1).copied().unwrap_or(0);
        let b2 = bytes.get(index + 2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if index + 1 < bytes.len() {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if index + 2 < bytes.len() {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        index += 3;
    }

    out
}

/// Reads the terminal on a thread of its own.
///
/// `crossterm::event::read` blocks, and blocking a tokio worker with it would stall every
/// RPC task sharing that worker. The alternative is crossterm's `event-stream` feature and
/// the futures machinery under it, for a thread this process needs exactly one of.
fn input(sender: mpsc::UnboundedSender<Msg>) {
    std::thread::spawn(move || loop {
        match crossterm::event::read() {
            Ok(Event::Key(key)) if key.kind != KeyEventKind::Release => {
                if sender.send(Msg::Key(key)).is_err() {
                    return;
                }
            }
            Ok(Event::Resize(_, _)) => {
                if sender.send(Msg::Redraw).is_err() {
                    return;
                }
            }
            Ok(Event::Paste(text)) => {
                if sender.send(Msg::Paste(text)).is_err() {
                    return;
                }
            }
            Ok(Event::Mouse(mouse)) => {
                let delta = match mouse.kind {
                    MouseEventKind::ScrollUp => -3,
                    MouseEventKind::ScrollDown => 3,
                    _ => continue,
                };
                if sender.send(Msg::Scroll(delta)).is_err() {
                    return;
                }
            }
            Ok(_other) => {}
            // A terminal that cannot be read is a terminal this loop cannot serve; the UI
            // still runs on its timer, so quitting stays possible through a signal.
            Err(_error) => return,
        }
    });
}

/// Writes the config file the App asked to have written, and says where it went.
///
/// The App decides and this writes, for the same reason it emits [`Call`]s rather than
/// making them: a state machine with a filesystem in it is one that cannot be driven by a
/// test. It is synchronous on purpose — the file is a few hundred bytes into a directory
/// this process already owns, and handing that to a task would buy a round trip through
/// the message queue to save a write that costs less than the frame it happens in.
pub fn persist(app: &mut App) {
    let Some(config) = app.take_config_save() else {
        return;
    };

    let Some(path) = app.config_path.clone() else {
        app.inform(
            "there is nowhere to keep preferences: neither XDG_CONFIG_HOME nor a home \
             directory is set",
            app::NoticeKind::Error,
        );

        return;
    };

    match config.save(&path) {
        Ok(()) => app.inform(format!("saved {}", path.display()), app::NoticeKind::Info),
        // The App keeps the change in memory either way: it is what the operator chose in
        // this session. What it must not do is claim the file has it.
        Err(error) => app.inform(
            format!("{} could not be written: {error:#}", path.display()),
            app::NoticeKind::Error,
        ),
    }
}

fn open_pending_url(app: &mut App) {
    let Some(url) = app.take_open_url() else {
        return;
    };

    if !url.starts_with("https://") {
        app.inform(
            "the account service returned a non-HTTPS sign-in URL; it was not opened",
            app::NoticeKind::Error,
        );
        return;
    }

    #[cfg(target_os = "macos")]
    let result = ProcessCommand::new("open").arg(&url).spawn();

    #[cfg(target_os = "linux")]
    let result = ProcessCommand::new("xdg-open").arg(&url).spawn();

    // `cmd.exe` re-parses its own command line after Rust has quoted the arguments, and Rust
    // quotes for the CRT rules `cmd` does not follow. Every real OAuth URL carries `&`, which
    // `cmd` reads as a command separator: the sign-in page would not open and the tail of the
    // URL would run as a command. So the line is built by hand — the URL quoted, with the one
    // character that could end that quoting refused outright.
    #[cfg(target_os = "windows")]
    let result = {
        use std::os::windows::process::CommandExt;

        if url.contains('"') {
            app.inform(
                "the account service returned a sign-in URL containing a quote; it was not \
                 opened",
                app::NoticeKind::Error,
            );
            return;
        }

        let mut command = ProcessCommand::new("cmd");
        command.raw_arg("/C");
        // The empty pair is `start`'s window title, which it would otherwise take the URL for.
        command.raw_arg(format!("start \"\" \"{url}\""));
        command.spawn()
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let result: std::io::Result<std::process::Child> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this platform has no configured browser opener",
    ));

    if let Err(error) = result {
        app.inform(
            format!("could not open the ChatGPT sign-in page: {error}"),
            app::NoticeKind::Error,
        );
    }
}

/// Runs the UI until the operator picks something from the quit dialog.
///
/// `screen` is the terminal the boot screen already took over, handed on rather than
/// re-entered. `None` means there was no boot screen, and taking the terminal here is
/// where a stdout that is not a tty becomes the error that says what to run instead.
pub async fn run(
    screen: Option<Screen>,
    mut app: App,
    client: Client,
    mut notifications: mpsc::Receiver<Notification>,
    channel: UiChannel,
    mut daemon: Option<&mut Daemon>,
) -> Result<Quit> {
    let UiChannel {
        cursors,
        sender,
        mut receiver,
    } = channel;

    app.cursors = cursors;

    let mut screen = match screen {
        Some(screen) => screen,
        None => Screen::enter()?,
    };

    // The terminal has been taken over by now, so whether it distinguishes `Shift+Enter`
    // from `Enter` is settled, and the footers can say which binding actually exists here.
    app.keyboard_enhanced = keyboard_enhanced();

    // The boot renderer and the harness share one alternate screen, but they do not share
    // one frame layout. Clear the physical terminal at the handoff so sparse areas of the
    // first transcript frame cannot retain boot copy that Ratatui's fresh buffer already
    // assumes is blank.
    screen
        .terminal
        .backend_mut()
        .execute(Clear(ClearType::All))
        .context("clearing the boot screen before the harness")?
        .execute(MoveTo(0, 0))
        .context("positioning the first harness frame")?;

    input(sender.clone());

    // File discovery is local presentation data, not a gateway concern. Keep it off the
    // draw loop and bounded: a large repository must not delay the first usable frame.
    if let Some(root) = app
        .config
        .defaults
        .workspace
        .clone()
        .or_else(|| app.launch_dir.clone())
    {
        let completion_sender = sender.clone();
        std::thread::spawn(move || {
            let files = editor::index_workspace(std::path::Path::new(&root));
            let _ = completion_sender.send(Msg::WorkspaceFiles(files));
        });
    }

    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // The first poll before the first frame, so the Dashboard is asking for its data
    // while it draws its first "waiting" state rather than after it.
    app.apply(Msg::Tick);

    loop {
        for call in app.drain() {
            spawn_call(client.clone(), call, sender.clone());
        }

        // Before the draw, so the notice naming the file is on the same frame as the
        // settings overlay closing.
        persist(&mut app);
        open_pending_url(&mut app);
        copy_pending(&mut app);
        if app.take_scan_machines() {
            spawn_machine_scan(sender.clone());
        }
        if let Some(job) = app.take_fleet_job() {
            spawn_fleet_job(app.data_dir.clone(), job, client.clone(), sender.clone());
        }
        if let Some(intent) = app.take_fleet_intent() {
            match app.data_dir.as_deref() {
                Some(data_dir) => {
                    if let Err(error) =
                        fleet_add::write_intent(std::path::Path::new(data_dir), &intent)
                    {
                        app.fleet_plan_write_failed(format!(
                            "could not save the add-machine plan: {error:#}"
                        ));
                    }
                }
                None => {
                    app.fleet_plan_write_failed(
                        "this client has no local data directory, so it cannot create a fleet",
                    );
                }
            }
        }
        if let Some(intent) = app.take_join_intent() {
            match app.data_dir.as_deref() {
                Some(data_dir) => {
                    if let Err(error) =
                        fleet_add::write_join_intent(std::path::Path::new(data_dir), &intent)
                    {
                        app.fleet_plan_write_failed(format!(
                            "could not save the join plan: {error:#}"
                        ));
                    }
                }
                None => {
                    app.fleet_plan_write_failed(
                        "this client has no local data directory, so it cannot join a fleet",
                    );
                }
            }
        }

        if let Some(draft) = app.take_external_editor() {
            screen.suspend();

            let edited = tokio::task::spawn_blocking(move || run_external_editor(&draft))
                .await
                .unwrap_or_else(|join_error| {
                    Err(anyhow::anyhow!("the editor task failed: {join_error}"))
                });

            let result = if let Err(error) = screen.resume() {
                Err(error)
            } else {
                edited
            };

            match result {
                Ok(text) => app.apply(Msg::ExternalEditor(text)),
                Err(error) => app.inform(
                    format!("external editor failed: {error:#}"),
                    app::NoticeKind::Error,
                ),
            }
        }

        screen
            .terminal
            .draw(|frame| view::draw(frame, &mut app))
            .context("drawing the terminal")?;

        if let Some(quit) = app.quit {
            return Ok(quit);
        }

        tokio::select! {
            message = receiver.recv() => match message {
                Some(message) => app.apply(message),
                // Both senders are gone, which cannot happen while this loop holds one.
                None => return Ok(Quit::Disconnect),
            },
            notification = notifications.recv() => match notification {
                Some(notification) => app.apply(Msg::Notification(notification)),
                None => app.apply(Msg::Redraw),
            },
            _instant = ticker.tick() => {
                app.apply(Msg::Tick);
                app.apply(Msg::NotificationsDropped(client.dropped_notifications()));

                if let Some(daemon) = daemon.as_mut() {
                    if let Some(status) = daemon.exited() {
                        app.apply(Msg::DaemonExited(status.to_string()));
                    }
                }
            }
        }

        // Everything already queued is applied before the next draw: a burst of events
        // costs one frame rather than one frame each.
        while let Ok(message) = receiver.try_recv() {
            app.apply(message);
        }

        while let Ok(notification) = notifications.try_recv() {
            app.apply(Msg::Notification(notification));
        }
    }
}

/// One discovery scan at a time: opening Machines twice quickly must not stack two
/// `tailscale status` processes racing to overwrite each other's candidate list.
static MACHINES_SCAN_INFLIGHT: AtomicBool = AtomicBool::new(false);

fn spawn_machine_scan(sender: mpsc::UnboundedSender<Msg>) {
    if MACHINES_SCAN_INFLIGHT.swap(true, Ordering::SeqCst) {
        let _ = sender.send(Msg::MachineScanPending);
        return;
    }
    struct ClearOnExit;
    impl Drop for ClearOnExit {
        fn drop(&mut self) {
            MACHINES_SCAN_INFLIGHT.store(false, Ordering::SeqCst);
        }
    }
    std::thread::spawn(move || {
        let _clear = ClearOnExit;
        let (candidates, local) = fleet_add::discover();
        let candidates = candidates.into_iter().map(machine_candidate).collect();
        let _ = sender.send(Msg::MachineCandidates {
            candidates,
            local_machine: local.machine,
            local_host: local.host,
        });
    });
}

fn machine_candidate(candidate: fleet_add::Candidate) -> app::MachineCandidate {
    let source = match candidate.source {
        CandidateSource::Tailscale => "tailscale",
        CandidateSource::SshConfig => "ssh",
    };
    let online = match candidate.online {
        Some(true) => "online",
        Some(false) => "offline",
        None => "",
    };
    let os = candidate.os.unwrap_or_default();
    app::MachineCandidate {
        label: candidate.label,
        target: candidate.target,
        host: candidate.host,
        detail: format!("{source} {os} {online}")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
        tailscale: candidate.source == CandidateSource::Tailscale,
    }
}

fn spawn_fleet_job(
    data_dir: Option<String>,
    job: app::FleetJob,
    client: Client,
    sender: mpsc::UnboundedSender<Msg>,
) {
    match job {
        app::FleetJob::Status => {
            tokio::spawn(async move {
                let live = client
                    .call_with_timeout("fleet.status", json!({}), Duration::from_secs(5))
                    .await;
                let result = tokio::task::spawn_blocking(move || fleet_status_text(data_dir, live))
                    .await
                    .unwrap_or_else(|error| Err(format!("{error:#}")));
                send_fleet_job(sender, Vec::new(), result);
            });
        }
        app::FleetJob::Doctor => {
            tokio::spawn(async move {
                let live = client
                    .call_with_timeout("fleet.doctor", json!({}), Duration::from_secs(8))
                    .await;
                let result = tokio::task::spawn_blocking(move || fleet_doctor_text(data_dir, live))
                    .await
                    .unwrap_or_else(|error| Err(format!("{error:#}")));
                send_fleet_job(sender, Vec::new(), result);
            });
        }
        job => {
            tokio::task::spawn_blocking(move || {
                let result = run_blocking_fleet_job(data_dir, job);
                match result {
                    Ok((log, recipe)) => send_fleet_job(sender, log, Ok(recipe)),
                    Err(error) => send_fleet_job(sender, Vec::new(), Err(error)),
                }
            });
        }
    }
}

fn send_fleet_job(
    sender: mpsc::UnboundedSender<Msg>,
    log: Vec<String>,
    result: Result<String, String>,
) {
    let _ = sender.send(Msg::FleetJobFinished { log, result });
}

fn require_data_dir(data_dir: Option<String>) -> Result<PathBuf, String> {
    data_dir.map(PathBuf::from).ok_or_else(|| {
        "this client has no local data directory; run this from the machine that owns the fleet"
            .into()
    })
}

fn fleet_status_text(
    data_dir: Option<String>,
    live: Result<serde_json::Value, crate::transport::ClientError>,
) -> Result<String, String> {
    let data_dir = require_data_dir(data_dir)?;
    match live {
        Ok(value) => fleet::render_live_status(&data_dir, &value)
            .or_else(|| fleet::render_status(&data_dir).ok())
            .ok_or_else(|| "fleet status could not be rendered".into()),
        Err(error) => fleet::render_status(&data_dir).map_err(|render| {
            format!("live fleet.status failed ({error}); local status also failed: {render:#}")
        }),
    }
}

fn fleet_doctor_text(
    data_dir: Option<String>,
    live: Result<serde_json::Value, crate::transport::ClientError>,
) -> Result<String, String> {
    let data_dir = require_data_dir(data_dir)?;
    let local = fleet::doctor(&data_dir);
    let report = match live {
        Ok(value) => fleet::merge_live_doctor(local, &value),
        Err(error) => fleet::doctor_live_unavailable(local, format!("{error:#}")),
    };
    Ok(report.text)
}

fn run_blocking_fleet_job(
    data_dir: Option<String>,
    job: app::FleetJob,
) -> Result<(Vec<String>, String), String> {
    let data_dir = require_data_dir(data_dir)?;
    match job {
        app::FleetJob::Add {
            prepare,
            target,
            machine,
            host,
            via,
            binary,
        } => {
            let outcome = if prepare {
                fleet_add::prepare(&data_dir, &machine, &host, None)
            } else {
                let target = target.ok_or_else(|| "SSH add needs user@host".to_string())?;
                let via = fleet_add::Via::parse(&via).map_err(|error| format!("{error:#}"))?;
                fleet_add::add(
                    &data_dir,
                    &target,
                    Some(&machine),
                    Some(&host),
                    via,
                    binary.as_deref().map(Path::new),
                    None,
                )
            }
            .map_err(|error| format!("{error:#}"))?;
            let recipe = outcome
                .recipe
                .as_ref()
                .map(fleet_add::Recipe::text)
                .unwrap_or_default();
            Ok((outcome.log, recipe))
        }
        app::FleetJob::Invite { machine, host, out } => {
            let output = match out.as_deref() {
                Some(path) if !path.is_empty() => PathBuf::from(path),
                _ => fleet::pending_invite_path(&data_dir, &machine)
                    .map_err(|error| format!("{error:#}"))?,
            };
            if let Some(parent) = output.parent() {
                if parent == fleet::pending_dir(&data_dir) {
                    fleet::ensure_pending_dir(&data_dir).map_err(|error| format!("{error:#}"))?;
                }
            }
            let member = fleet::invite(&data_dir, &machine, &host, &output, Ports::DEFAULT)
                .map_err(|error| format!("{error:#}"))?;
            let quoted =
                fleet::shell_quote_path(&output).unwrap_or_else(|_| output.display().to_string());
            Ok((
                vec![
                    format!("private invitation created for {}", member.machine),
                    format!("address {}", member.host),
                    format!("file {quoted} (mode 0600)"),
                ],
                format!(
                    "Copy it through a private channel. Copy tools may widen permissions; on the receiving machine:\n  chmod 600 {quoted}\n  ouro fleet enroll {quoted} --delete\n\nContents were not printed."
                ),
            ))
        }
        app::FleetJob::Service => {
            let installed =
                fleet::service_install(&data_dir).map_err(|error| format!("{error:#}"))?;
            let status = if installed.installed {
                "recovery unit written"
            } else {
                "recovery unit already matches"
            };
            Ok((
                vec![
                    status.into(),
                    format!("unit {}", installed.path.display()),
                    format!("manager {}", installed.kind.label()),
                ],
                format!(
                    "Activate (does not start on its own):\n  {}\n\nDeactivate:\n  {}",
                    installed.activation, installed.deactivation
                ),
            ))
        }
        app::FleetJob::SyncExport { out } => {
            let path = PathBuf::from(out);
            let revision =
                fleet::export_roster(&data_dir, &path).map_err(|error| format!("{error:#}"))?;
            let quoted =
                fleet::shell_quote_path(&path).unwrap_or_else(|_| path.display().to_string());
            Ok((
                vec![format!("signed roster revision {revision}")],
                format!(
                    "Wrote {quoted} (mode 0600). Copy it privately. On each recipient: stop the runtime, `ouro fleet sync import {quoted}`, then start it again."
                ),
            ))
        }
        app::FleetJob::Status | app::FleetJob::Doctor => {
            Err("status and doctor run on the live client, not this worker".into())
        }
    }
}

fn spawn_call(client: Client, call: Call, sender: mpsc::UnboundedSender<Msg>) {
    tokio::spawn(async move {
        let result = match call.timeout {
            Some(timeout) => {
                client
                    .call_with_timeout(&call.method, call.params, timeout)
                    .await
            }
            None => client.call(&call.method, call.params).await,
        };

        let _ = sender.send(Msg::Answer {
            tag: call.tag,
            result,
        });
    });
}
