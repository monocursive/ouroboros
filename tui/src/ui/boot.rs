//! The first few seconds, in the terminal rather than in silence.
//!
//! A cold start extracts a release, spawns an Erlang system, and waits for it to bind and
//! publish a port — three or four seconds during which this client used to print one line
//! and then say nothing. That is the worst possible moment to be opaque: it is the first
//! thing a new operator sees, and a boot that fails there fails *before* there is a UI to
//! explain it in.
//!
//! So the alternate screen is entered first and handed to the App afterwards. The phases
//! are drawn as they happen, the child's own stdout and stderr are tailed live underneath
//! them, and a failure is shown in place — with the output that explains it — instead of
//! being dumped to a terminal the screen has already been torn off.
//!
//! ## The three pieces, and why they are separate
//!
//! * [`BootProgress`] is the state machine: events in, steps out, no terminal and no
//!   clock. It is what the tests drive.
//! * [`Progress`] is the handle the spawn code reports through. It has two shapes, and
//!   that is the whole of the tty/non-tty split: [`Progress::Plain`] prints exactly the
//!   lines this client printed before there was a boot screen, so `ouro daemon`, a pipe,
//!   and a redirected stdout are untouched by any of this.
//! * [`Boot`] owns the terminal and the redraw loop. It drives the caller's own spawn and
//!   connect futures rather than reimplementing them: [`Boot::drive`] races a future
//!   against a frame timer, which is what makes a 60-second `wait_ready` a live screen
//!   instead of a blocked one.
//!
//! ## The handoff
//!
//! [`Boot::finish`] returns the live [`Screen`], which [`super::run`] then draws the App
//! into. Nothing leaves the alternate screen in between, so there is no flicker, no
//! second `enable_raw_mode`, and no window in which a panic would land on a terminal
//! nobody owns.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::runtime::{LogRing, Stream};

use super::access;
use super::theme;
use super::Screen;

/// How often the boot screen redraws while it waits. Fast enough that the spinner reads as
/// motion, slow enough that a 60-second wait is not a busy loop.
const FRAME: Duration = Duration::from_millis(80);

/// How long a failed boot holds the screen before restoring the terminal on its own.
///
/// The screen waits for a keypress because the log tail under the error is the point of
/// showing it at all, and a screen that vanished would be a screen nobody read. It does
/// not wait *forever*: an `ouro` launched from something that owns a tty but sends it no
/// keys must still exit, and the same error is printed to stderr afterwards either way.
const FAILURE_PATIENCE: Duration = Duration::from_secs(120);

/// How many lines of the child's output the failure screen keeps room for.
const FAILURE_TAIL: usize = 200;

/// Something that happened while starting up. Reported by the code that did it, never
/// inferred here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootEvent {
    /// Working out what to start. On an embedded build this is where the release is
    /// verified and unpacked, which is the slowest part of a genuinely cold start.
    Preparing,
    /// A runtime was already running in this data directory, so nothing is being started.
    Adopted { pid: i32, data_dir: String },
    /// Another `ouro` published one while this call was taking the spawn lock. Adopting is
    /// the right answer, and it is a different sentence from the one above.
    AdoptedUnderLock { pid: i32 },
    /// About to spawn a runtime into this data directory.
    Starting { data_dir: String },
    /// The child exists and has this pid; it has not published anything yet.
    Spawned { pid: i32 },
    /// The gateway bound a port and published it.
    Published { port: u16 },
    /// Opening the connection and completing the handshake.
    Connecting { address: String },
    /// The handshake succeeded and this is who answered.
    Connected { node: String },
    /// `interactive.start`, which is allowed to take two minutes because provider
    /// readiness is unbounded upstream.
    StartingSession { provider: String },
    /// A session exists.
    SessionStarted { id: String },
    /// Worth saying, but not a phase. Rendered beside the steps rather than as one.
    Warning(String),
}

impl BootEvent {
    /// The line this client printed for this event before there was a boot screen, or
    /// `None` for the events that had no plain equivalent.
    ///
    /// This is what keeps the non-tty path *exactly* as it was: the plain surface says
    /// what it always said, and the new phases are visible only where there is a screen to
    /// draw them on.
    fn plain(&self) -> Option<String> {
        match self {
            Self::Adopted { pid, data_dir } => Some(format!(
                "adopted the runtime already running in {data_dir} (pid {pid})"
            )),
            Self::AdoptedUnderLock { pid } => Some(format!(
                "adopted the runtime another client just started (pid {pid})"
            )),
            Self::Starting { data_dir } => Some(format!("starting a runtime in {data_dir}")),
            Self::Warning(text) => Some(text.clone()),
            Self::Preparing
            | Self::Spawned { .. }
            | Self::Published { .. }
            | Self::Connecting { .. }
            | Self::Connected { .. }
            | Self::StartingSession { .. }
            | Self::SessionStarted { .. } => None,
        }
    }

    /// The phase label, or `None` for an event that is not a phase.
    fn label(&self) -> Option<String> {
        match self {
            Self::Preparing => Some("preparing the release".into()),
            Self::Adopted { pid, data_dir } => {
                Some(format!("adopted the runtime in {data_dir} (pid {pid})"))
            }
            Self::AdoptedUnderLock { pid } => Some(format!(
                "adopted a runtime another client just started (pid {pid})"
            )),
            Self::Starting { data_dir } => Some(format!("starting a runtime in {data_dir}")),
            Self::Spawned { pid } => {
                Some(format!("waiting for the gateway to publish (pid {pid})"))
            }
            Self::Published { port } => Some(format!("gateway published on port {port}")),
            Self::Connecting { address } => Some(format!("connecting to {address}")),
            Self::Connected { node } => Some(format!("connected to {node}")),
            Self::StartingSession { provider } => Some(format!("starting a {provider} session")),
            Self::SessionStarted { id } => Some(format!("session {id}")),
            Self::Warning(_) => None,
        }
    }
}

/// How far a step got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    /// Happening now. At most one step is ever in this state.
    Doing,
    Done,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub label: String,
    pub state: StepState,
}

/// The boot as a list of steps, with no terminal and no clock in it.
///
/// Every phase this client passes through is appended, and the one before it is closed:
/// arriving at "waiting for the gateway" *is* the proof that spawning finished, so nothing
/// has to report success twice. A failure closes the open step as failed and stops there,
/// which is why the screen can show which phase the error belongs to rather than only the
/// error.
#[derive(Default)]
pub struct BootProgress {
    steps: Vec<Step>,
    warnings: Vec<String>,
    failure: Option<String>,
    /// The child's output, once there is a child. Shared with the spawner rather than
    /// copied, so the pane below the steps is live.
    logs: Option<LogRing>,
}

impl BootProgress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one event: closes whatever was in flight, then opens this phase.
    pub fn apply(&mut self, event: BootEvent) {
        if let BootEvent::Warning(text) = event {
            self.warnings.push(text);
            return;
        }

        let Some(label) = event.label() else {
            return;
        };

        // A failed boot is terminal. Anything reported afterwards would be describing a
        // sequence that did not continue.
        if self.failure.is_some() {
            return;
        }

        self.close_open(StepState::Done);
        self.steps.push(Step {
            label,
            state: StepState::Doing,
        });
    }

    /// Ends the boot: the phase that was in flight is the one that failed.
    pub fn fail(&mut self, error: String) {
        if self.failure.is_some() {
            return;
        }

        self.close_open(StepState::Failed);
        self.failure = Some(error);
    }

    /// Marks the last step done, for a boot that ended without a further phase to open.
    pub fn settle(&mut self) {
        if self.failure.is_none() {
            self.close_open(StepState::Done);
        }
    }

    fn close_open(&mut self, state: StepState) {
        if let Some(step) = self.steps.last_mut() {
            if step.state == StepState::Doing {
                step.state = state;
            }
        }
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    /// The phase in flight, for a caller that wants the one-line answer to "what is it
    /// doing".
    pub fn current(&self) -> Option<&Step> {
        self.steps
            .last()
            .filter(|step| step.state == StepState::Doing)
    }

    pub fn attach_logs(&mut self, logs: LogRing) {
        self.logs = Some(logs);
    }

    pub fn logs(&self) -> Option<&LogRing> {
        self.logs.as_ref()
    }
}

/// Where a spawner reports its progress. Cheap to clone, because the code that reports is
/// inside the future the screen is driving.
#[derive(Clone)]
pub enum Progress {
    /// Plain stdout lines, exactly the ones this client printed before there was a boot
    /// screen. `ouro daemon`, `--print`, and any stdout that is not a tty take this arm.
    Plain,
    /// Live in the alternate screen.
    Screen(Arc<Mutex<BootProgress>>),
}

impl Progress {
    pub fn report(&self, event: BootEvent) {
        match self {
            Self::Plain => {
                if let Some(line) = event.plain() {
                    println!("{line}");
                }
            }
            Self::Screen(state) => {
                if let Ok(mut progress) = state.lock() {
                    progress.apply(event);
                }
            }
        }
    }

    /// Hands the screen the child's output ring, so the pane under the steps is the
    /// runtime's own words rather than a summary of them.
    pub fn attach_logs(&self, logs: LogRing) {
        if let Self::Screen(state) = self {
            if let Ok(mut progress) = state.lock() {
                progress.attach_logs(logs);
            }
        }
    }
}

/// The terminal for the duration of the boot, and the App's terminal afterwards.
pub struct Boot {
    screen: Option<Screen>,
    progress: Progress,
    state: Option<Arc<Mutex<BootProgress>>>,
    ticks: u64,
}

impl Boot {
    /// The plain path, chosen rather than fallen back to: `--print` is a surface whose
    /// whole point is bytes on stdout, and it stays that way on a tty.
    pub fn plain() -> Self {
        Self {
            screen: None,
            progress: Progress::Plain,
            state: None,
            ticks: 0,
        }
    }

    /// The full-screen path when stdout is a tty, and today's plain prints otherwise.
    ///
    /// A terminal that cannot be taken over is not a failure here. `ouro` on a pipe still
    /// has work to do — it just has no screen to do it on, and [`super::run`] is where
    /// that becomes the error, in the one place that can say what to run instead.
    pub fn begin() -> Self {
        if !Screen::available() {
            return Self::plain();
        }

        match Screen::enter() {
            Ok(screen) => {
                let state = Arc::new(Mutex::new(BootProgress::new()));

                Self {
                    screen: Some(screen),
                    progress: Progress::Screen(state.clone()),
                    state: Some(state),
                    ticks: 0,
                }
            }
            // A tty this client could not put into raw mode. Falling back to the plain
            // lines is strictly better than refusing to start a runtime over it.
            Err(_error) => Self::plain(),
        }
    }

    /// The handle to report through. Cloned rather than borrowed so a caller can hold it
    /// across a [`Boot::drive`] that needs `&mut self`.
    pub fn progress(&self) -> Progress {
        self.progress.clone()
    }

    /// Whether this boot has a screen. `false` means the plain path, and every plain line
    /// has already been printed by the time it matters.
    pub fn on_screen(&self) -> bool {
        self.screen.is_some()
    }

    /// Runs `work` to completion, redrawing the boot screen while it waits.
    ///
    /// The future is the caller's own — the same `spawn`, `wait_ready`, `connect`, and
    /// `interactive.start` the plain path awaits — so nothing about how a runtime starts
    /// changes with the screen. All this adds is a frame timer racing it.
    pub async fn drive<T, E>(&mut self, work: impl Future<Output = Result<T, E>>) -> Result<T, E> {
        let (Some(screen), Some(state)) = (self.screen.as_mut(), self.state.as_ref()) else {
            return work.await;
        };

        let mut ticker = tokio::time::interval(FRAME);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        tokio::pin!(work);

        loop {
            tokio::select! {
                outcome = &mut work => {
                    Self::paint(screen, state, self.ticks);
                    return outcome;
                }
                _instant = ticker.tick() => {
                    self.ticks += 1;
                    Self::paint(screen, state, self.ticks);
                }
            }
        }
    }

    /// Shows the failure with the runtime's own output under it, waits for a key, and
    /// gives the error back for the caller to fail with.
    ///
    /// The error is returned rather than printed here: `main` prints it to stderr after the
    /// terminal is restored, which is what keeps a script that reads stderr working exactly
    /// as it did before there was a screen.
    pub async fn fail<E: std::fmt::Display>(mut self, error: E) -> E {
        let (Some(mut screen), Some(state)) = (self.screen.take(), self.state.take()) else {
            return error;
        };

        if let Ok(mut progress) = state.lock() {
            progress.fail(format!("{error}"));
        }

        Self::paint(&mut screen, &state, self.ticks);

        // Blocking, on a thread of its own: `crossterm::event::read` would otherwise park a
        // tokio worker, and this process has nothing else to do until the key arrives.
        let _ = tokio::task::spawn_blocking(|| wait_for_key(FAILURE_PATIENCE)).await;

        // Dropped here, which restores the terminal before the caller prints anything.
        drop(screen);

        error
    }

    /// The live terminal, for the App loop to keep drawing into. `None` is the plain path.
    pub fn finish(mut self) -> Option<Screen> {
        if let Some(state) = &self.state {
            if let Ok(mut progress) = state.lock() {
                progress.settle();
            }
        }

        self.screen.take()
    }

    fn paint(screen: &mut Screen, state: &Arc<Mutex<BootProgress>>, ticks: u64) {
        let Ok(progress) = state.lock() else {
            return;
        };

        // A frame that cannot be drawn is not worth failing a boot over; the next tick
        // tries again, and the outcome of the work is what this function is beside.
        let _ = screen
            .terminal()
            .draw(|frame| draw(frame, &progress, ticks));
    }
}

/// Blocks until a key is pressed or `patience` runs out.
fn wait_for_key(patience: Duration) {
    use crossterm::event::{Event, KeyEventKind};

    let deadline = Instant::now() + patience;

    loop {
        let left = deadline.saturating_duration_since(Instant::now());

        if left.is_zero() {
            return;
        }

        // Polled in slices rather than waited on in one call, so this thread ends on its
        // own schedule instead of parking on a terminal that may never speak again.
        match crossterm::event::poll(left.min(Duration::from_millis(200))) {
            Ok(true) => match crossterm::event::read() {
                Ok(Event::Key(key)) if key.kind != KeyEventKind::Release => return,
                Ok(_other) => {}
                Err(_error) => return,
            },
            Ok(false) => {}
            // A terminal that cannot be read cannot be waited on.
            Err(_error) => return,
        }
    }
}

/// The boot screen: what it is doing, and what the runtime is saying while it does it.
pub fn draw(frame: &mut Frame, progress: &BootProgress, ticks: u64) {
    let area = frame.area();

    let steps = progress.steps().len() + progress.warnings().len();
    let failure_lines = progress.failure().map(|_| 3).unwrap_or(0);
    // Two rows of border, one of title text, one of the hint under the steps.
    let wanted = (steps + failure_lines + 5) as u16;

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(wanted.min(area.height)),
            Constraint::Min(0),
        ])
        .split(area);

    phases(frame, rows[0], progress, ticks);
    output(frame, rows[1], progress);
}

fn phases(frame: &mut Frame, area: Rect, progress: &BootProgress, ticks: u64) {
    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .title(Span::styled(
            if progress.failure().is_some() {
                " ouroboros — this runtime did not start "
            } else {
                " ouroboros "
            },
            theme::heading(),
        ));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    for step in progress.steps() {
        let (marker, style) = match step.state {
            StepState::Doing => (
                theme::spinner(ticks).to_string(),
                Style::default().fg(theme::accent()),
            ),
            StepState::Done => ("✓".to_string(), Style::default().fg(theme::good())),
            StepState::Failed => ("✗".to_string(), Style::default().fg(theme::bad())),
        };

        lines.push(Line::from(vec![
            Span::styled(format!("{marker:<2}"), style),
            Span::styled(
                step.label.clone(),
                match step.state {
                    StepState::Done => Style::default().fg(theme::muted()),
                    StepState::Failed => Style::default().fg(theme::bad()),
                    StepState::Doing => Style::default(),
                },
            ),
        ]));
    }

    for warning in progress.warnings() {
        lines.push(Line::from(Span::styled(
            format!("!  {warning}"),
            Style::default().fg(theme::warn()),
        )));
    }

    match progress.failure() {
        Some(error) => {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                error.to_string(),
                Style::default()
                    .fg(theme::bad())
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(Span::styled(
                "press any key — this is also printed to stderr on the way out",
                Style::default().fg(theme::muted()),
            )));
        }
        None => lines.push(Line::from(Span::styled(
            "the runtime is starting; nothing is being asked of you",
            Style::default().fg(theme::muted()),
        ))),
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// The child's own stdout and stderr, live. A boot that is slow because the runtime is
/// saying something is a boot whose reason is on screen.
fn output(frame: &mut Frame, area: Rect, progress: &BootProgress) {
    if area.height < 3 {
        return;
    }

    let block = Block::default()
        .borders(access::borders(Borders::ALL))
        .border_style(Style::default().fg(theme::muted()))
        .title(Span::styled(" runtime output ", theme::heading()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(ring) = progress.logs() else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "nothing has been started yet",
                Style::default().fg(theme::muted()),
            )),
            inner,
        );

        return;
    };

    // Bounded above as well as below: a failure screen on a very tall terminal should not
    // turn the whole ring into `Line`s on every frame.
    let lines = ring.tail((inner.height as usize).clamp(1, FAILURE_TAIL));

    if lines.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "the runtime has printed nothing yet",
                Style::default().fg(theme::muted()),
            )),
            inner,
        );

        return;
    }

    let rendered: Vec<Line> = lines
        .iter()
        .map(|line| {
            Line::from(Span::styled(
                line.text.clone(),
                if line.stream == Stream::Stderr {
                    // The gateway routes the default logger to stderr on purpose, so
                    // stderr here is ordinary runtime logging rather than a fault.
                    Style::default()
                } else {
                    Style::default().fg(theme::muted())
                },
            ))
        })
        .collect();

    frame.render_widget(Paragraph::new(rendered), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(progress: &BootProgress) -> Vec<(String, StepState)> {
        progress
            .steps()
            .iter()
            .map(|step| (step.label.clone(), step.state))
            .collect()
    }

    #[test]
    fn a_cold_start_walks_spawn_publish_connect_and_closes_each_phase_behind_it() {
        let mut progress = BootProgress::new();

        progress.apply(BootEvent::Preparing);
        assert_eq!(
            progress.current().map(|step| step.state),
            Some(StepState::Doing)
        );

        progress.apply(BootEvent::Starting {
            data_dir: "/data".into(),
        });
        progress.apply(BootEvent::Spawned { pid: 42 });
        progress.apply(BootEvent::Published { port: 4560 });
        progress.apply(BootEvent::Connecting {
            address: "127.0.0.1:4560".into(),
        });
        progress.apply(BootEvent::Connected {
            node: "ouroboros@golden".into(),
        });

        let steps = labels(&progress);

        // Arriving at a phase is what closes the one before it: nothing reports success
        // twice, so a step that is still `Doing` is a step that really is in flight.
        assert_eq!(steps.len(), 6);
        assert!(
            steps[..5]
                .iter()
                .all(|(_, state)| *state == StepState::Done),
            "{steps:?}"
        );
        assert_eq!(steps[5].1, StepState::Doing);

        assert!(steps[1].0.contains("/data"), "{steps:?}");
        assert!(steps[2].0.contains("42"), "{steps:?}");
        assert!(steps[3].0.contains("4560"), "{steps:?}");
        assert!(steps[5].0.contains("ouroboros@golden"), "{steps:?}");

        progress.settle();
        assert!(labels(&progress).iter().all(|(_, s)| *s == StepState::Done));
        assert_eq!(progress.current(), None);
        assert_eq!(progress.failure(), None);
    }

    #[test]
    fn an_adopted_runtime_says_so_rather_than_claiming_to_have_started_one() {
        let mut progress = BootProgress::new();

        progress.apply(BootEvent::Adopted {
            pid: 7,
            data_dir: "/data".into(),
        });
        progress.apply(BootEvent::Connecting {
            address: "127.0.0.1:4560".into(),
        });

        let steps = labels(&progress);

        assert_eq!(steps.len(), 2);
        assert!(steps[0].0.starts_with("adopted"), "{steps:?}");
        assert!(steps[0].0.contains("pid 7"), "{steps:?}");
        assert!(
            !steps
                .iter()
                .any(|(label, _)| label.contains("starting a runtime")),
            "nothing was started: {steps:?}"
        );
    }

    #[test]
    fn a_failure_marks_the_phase_that_was_in_flight_and_stops_there() {
        let mut progress = BootProgress::new();

        progress.apply(BootEvent::Starting {
            data_dir: "/data".into(),
        });
        progress.apply(BootEvent::Spawned { pid: 42 });
        progress.fail("the runtime did not publish gateway.json in 60s".into());

        let steps = labels(&progress);

        assert_eq!(steps[0].1, StepState::Done);
        assert_eq!(
            steps[1].1,
            StepState::Failed,
            "the failure belongs to the phase that was running: {steps:?}"
        );
        assert_eq!(
            progress.failure(),
            Some("the runtime did not publish gateway.json in 60s")
        );

        // Terminal: a late event cannot make a failed boot look like it continued, and a
        // second failure cannot overwrite the first reason.
        progress.apply(BootEvent::Connected {
            node: "somewhere".into(),
        });
        progress.fail("something else".into());

        assert_eq!(labels(&progress).len(), 2);
        assert_eq!(
            progress.failure(),
            Some("the runtime did not publish gateway.json in 60s")
        );
    }

    #[test]
    fn a_warning_is_shown_beside_the_steps_rather_than_becoming_one() {
        let mut progress = BootProgress::new();

        progress.apply(BootEvent::Starting {
            data_dir: "/data".into(),
        });
        progress.apply(BootEvent::Warning(
            "gateway.json publishes protocol 2, this client speaks 1".into(),
        ));

        assert_eq!(progress.steps().len(), 1);
        assert_eq!(
            progress.current().map(|step| step.state),
            Some(StepState::Doing),
            "a warning does not close the phase it arrived during"
        );
        assert_eq!(progress.warnings().len(), 1);
    }

    #[test]
    fn the_plain_surface_says_exactly_what_it_said_before_there_was_a_screen() {
        assert_eq!(
            BootEvent::Adopted {
                pid: 9,
                data_dir: "/d".into()
            }
            .plain()
            .as_deref(),
            Some("adopted the runtime already running in /d (pid 9)")
        );

        assert_eq!(
            BootEvent::AdoptedUnderLock { pid: 9 }.plain().as_deref(),
            Some("adopted the runtime another client just started (pid 9)")
        );

        assert_eq!(
            BootEvent::Starting {
                data_dir: "/d".into()
            }
            .plain()
            .as_deref(),
            Some("starting a runtime in /d")
        );

        assert_eq!(
            BootEvent::Warning("careful".into()).plain().as_deref(),
            Some("careful")
        );

        // The phases the screen adds print nothing on the plain path, which is what makes
        // `ouro daemon` and a redirected stdout byte-identical to what they were.
        for event in [
            BootEvent::Preparing,
            BootEvent::Spawned { pid: 1 },
            BootEvent::Published { port: 1 },
            BootEvent::Connecting {
                address: "a".into(),
            },
            BootEvent::Connected { node: "n".into() },
            BootEvent::StartingSession {
                provider: "p".into(),
            },
            BootEvent::SessionStarted { id: "s".into() },
        ] {
            assert_eq!(event.plain(), None, "{event:?}");
        }
    }

    #[test]
    fn the_new_session_phases_name_the_provider_and_the_session() {
        let mut progress = BootProgress::new();

        progress.apply(BootEvent::Connected {
            node: "ouroboros@golden".into(),
        });
        progress.apply(BootEvent::StartingSession {
            provider: "claude_code".into(),
        });
        progress.apply(BootEvent::SessionStarted {
            id: "session-1".into(),
        });

        let steps = labels(&progress);

        assert!(steps[1].0.contains("claude_code"), "{steps:?}");
        assert!(steps[2].0.contains("session-1"), "{steps:?}");
    }

    /// The pane under the steps is the child's ring, shared rather than copied — a line
    /// pushed after the screen was told about the ring still shows up.
    #[test]
    fn the_output_pane_reads_the_live_ring() {
        let mut progress = BootProgress::new();
        let ring = LogRing::new(10, 1024);

        progress.attach_logs(ring.clone());
        ring.push(Stream::Stderr, "starting Ouroboros".into());

        assert_eq!(
            progress.logs().map(|logs| logs.len()),
            Some(1),
            "the screen holds the same ring the spawner fills"
        );
    }

    #[test]
    fn a_plain_progress_never_touches_a_screen_state() {
        // Nothing to assert but that it does not panic: the plain arm has no state, and a
        // spawner that reports through it must be the same code that reports to a screen.
        let progress = Progress::Plain;
        progress.attach_logs(LogRing::default());
        progress.report(BootEvent::Preparing);
    }

    /// What a terminal would show, on a `TestBackend`. The screen is a pure function of
    /// [`BootProgress`], so this renders exactly what a boot does — the only thing missing
    /// is the tty, which is what `Boot` owns and this does not.
    fn screen(progress: &BootProgress, width: u16, height: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("a test terminal");

        terminal
            .draw(|frame| draw(frame, progress, 0))
            .expect("a frame");

        let buffer = terminal.backend().buffer();
        let mut rows = Vec::new();

        for y in 0..buffer.area.height {
            let mut row = String::new();

            for x in 0..buffer.area.width {
                row.push_str(buffer[(x, y)].symbol());
            }

            rows.push(row);
        }

        rows.join("\n")
    }

    #[test]
    fn the_boot_screen_draws_the_phases_and_the_runtimes_own_output() {
        let mut progress = BootProgress::new();
        let ring = LogRing::new(50, 8 * 1024);

        progress.apply(BootEvent::Starting {
            data_dir: "/home/operator/.local/share/ouroboros".into(),
        });
        progress.attach_logs(ring.clone());
        progress.apply(BootEvent::Spawned { pid: 4242 });

        ring.push(Stream::Stderr, "starting Ouroboros 0.1.0".into());

        let text = screen(&progress, 100, 20);

        assert!(text.contains("ouroboros"), "{text}");
        assert!(
            text.contains("/home/operator/.local/share/ouroboros"),
            "{text}"
        );
        assert!(text.contains("4242"), "{text}");
        assert!(
            text.contains("nothing is being asked of you"),
            "a boot screen with a question on it would be a wizard: {text}"
        );
        assert!(
            text.contains("runtime output"),
            "the child's pipes are on screen while it starts: {text}"
        );
        assert!(text.contains("starting Ouroboros 0.1.0"), "{text}");
    }

    #[test]
    fn a_failed_boot_shows_the_error_and_the_output_that_explains_it() {
        let mut progress = BootProgress::new();
        let ring = LogRing::new(50, 8 * 1024);

        progress.apply(BootEvent::Starting {
            data_dir: "/data".into(),
        });
        progress.attach_logs(ring.clone());
        progress.apply(BootEvent::Spawned { pid: 7 });

        ring.push(
            Stream::Stderr,
            "** (Mix) Could not compile dependency".into(),
        );
        progress.fail("the runtime exited before it published a gateway".into());

        let text = screen(&progress, 100, 20);

        assert!(text.contains("this runtime did not start"), "{text}");
        assert!(
            text.contains("the runtime exited before it published a gateway"),
            "{text}"
        );
        assert!(
            text.contains("Could not compile dependency"),
            "the reason is the child's, and it is on the same screen: {text}"
        );
        assert!(
            text.contains("printed to stderr on the way out"),
            "a script reading stderr still gets the error: {text}"
        );
    }

    #[test]
    fn a_boot_screen_with_nothing_started_yet_says_so_rather_than_showing_a_blank_pane() {
        let text = screen(&BootProgress::new(), 80, 12);

        assert!(text.contains("nothing has been started yet"), "{text}");
    }

    /// A terminal too short for the output pane must still draw the phases rather than
    /// panicking on a zero-height area.
    #[test]
    fn a_very_short_terminal_still_draws() {
        let mut progress = BootProgress::new();
        progress.apply(BootEvent::Preparing);

        for height in 1..8 {
            let text = screen(&progress, 60, height);
            assert!(!text.is_empty(), "height {height}");
        }
    }
}
