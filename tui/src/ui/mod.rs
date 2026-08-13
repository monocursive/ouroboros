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

pub mod app;
pub mod dashboard;
pub mod explorer;
pub mod logs;
pub mod sessions;
pub mod theme;
pub mod transcript;
pub mod tree;
pub mod view;

use std::io::{self, IsTerminal, Stdout};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use crossterm::event::{Event, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use serde_json::json;
use tokio::sync::mpsc;

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
            for (plane, id, cursor) in cursors.snapshot() {
                let result = client
                    .call(
                        &plane.method("subscribe"),
                        json!({ "id": id, "cursor": cursor }),
                    )
                    .await;

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

/// Raw mode and the alternate screen, restored however this function is left.
struct Screen {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Screen {
    fn enter() -> Result<Self> {
        if !io::stdout().is_terminal() {
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
            .context("entering the alternate screen")?;

        let terminal = Terminal::new(CrosstermBackend::new(io::stdout()))
            .context("taking over the terminal")?;

        Ok(Self { terminal })
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        restore();
    }
}

fn restore() {
    let _ = disable_raw_mode();
    let _ = io::stdout().execute(LeaveAlternateScreen);
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
            Ok(_other) => {}
            // A terminal that cannot be read is a terminal this loop cannot serve; the UI
            // still runs on its timer, so quitting stays possible through a signal.
            Err(_error) => return,
        }
    });
}

/// Runs the UI until the operator picks something from the quit dialog.
pub async fn run(
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

    let mut screen = Screen::enter()?;
    input(sender.clone());

    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // The first poll before the first frame, so the Dashboard is asking for its data
    // while it draws its first "waiting" state rather than after it.
    app.apply(Msg::Tick);

    loop {
        for call in app.drain() {
            spawn_call(client.clone(), call, sender.clone());
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
