use super::*;

use crate::keymap::Scope;

/// The tab a digit selects, or `None` when this build has no such tab.
///
/// Bounded by [`Tab::ALL`] rather than by a literal range, which is what T1.6 asks for:
/// the range and the table used to be two numbers that agreed by accident, and a build
/// with three tabs would have gone on swallowing `4`.
fn tab_for_digit(digit: char) -> Option<Tab> {
    let index = digit.to_digit(10)?.checked_sub(1)? as usize;
    Tab::ALL.get(index).copied()
}

impl App {
    // ----- keys ----------------------------------------------------------------------

    pub(super) fn key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

        // A key that is only a release is not a press. Terminals with the kitty protocol
        // send both, and acting on each would double every keystroke.
        if key.kind == KeyEventKind::Release {
            return;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if self.leader_until.is_some() {
            self.leader_key(key);
            return;
        }

        // B8. Every chord below is looked up in the resolved keymap rather than matched
        // against a literal, which is what makes `[keys]` real and what makes the `?`
        // panel, the footer, and the palette able to *state* the effective binding (D14).
        if self.keymap.hits(Action::Palette, key) {
            if matches!(self.overlay, Some(Overlay::Commands(_))) {
                self.overlay = None;
            } else if self.overlay.is_none() {
                self.overlay = Some(Overlay::Commands(CommandPalette::default()));
            }
            return;
        }

        // Guarded like every other global chord. Without `overlay.is_none()` a `ctrl+q`
        // typed into the credential editor replaced it with the quit dialog and took the
        // keystroke with it (R1 §2.4).
        if self.keymap.hits(Action::Quit, key) && self.overlay.is_none() {
            self.open_quit();
            return;
        }

        // Prefills `/rename <current title>`, which is the same verb the composer takes
        // rather than a second surface that could disagree with it.
        if self.keymap.hits(Action::Rename, key) && self.overlay.is_none() {
            self.rename_prefill();
            return;
        }

        // The driver does the work; this only asks. See [`App::request_suspend`].
        if self.keymap.hits(Action::Suspend, key) && self.overlay.is_none() {
            self.request_suspend();
            return;
        }

        if self.keymap.hits(Action::Leader, key) && self.overlay.is_none() {
            self.leader_until = Some(self.ticks + LEADER_TICKS);
            return;
        }

        if self.keymap.hits(Action::Editor, key) && self.overlay.is_none() {
            self.request_external_editor();
            return;
        }

        // Ctrl+O is the field's "show more": it expands the conversation's own cells
        // rather than swapping in a different view. The normalized ledger keeps its own
        // verbs (`/details`, `ctrl+x d`). Ctrl+E stays readline end-of-line in the editor.
        if self.keymap.hits(Action::Verbose, key) && self.overlay.is_none() {
            self.toggle_verbose_transcript();
            return;
        }

        // Ctrl+T is the plan/tasks panel, as in Claude Code and Gemini.
        if self.keymap.hits(Action::PlanPanel, key) && self.overlay.is_none() {
            self.toggle_plan_panel();
            return;
        }

        if self.keymap.hits(Action::Cancel, key) {
            self.ctrl_c();
            return;
        }

        if self.keymap.hits(Action::QuitEmpty, key)
            && self.overlay.is_none()
            && self.focused_prompt_empty()
        {
            self.open_quit();
            return;
        }

        if self.overlay.is_some() {
            self.overlay_key(key);
            return;
        }

        // B5. The backtrack chord, claimed before the composer and the transcript keys and
        // *after* the overlays, so an Escape that is closing something still closes it.
        //
        // The first Escape of an `Esc Esc` does its ordinary job as well as arming the
        // chord — Esc always interrupts, which is Claude Code #16905 — so this returns only
        // for the second one.
        if self.backtrack_chord(key) {
            return;
        }

        // The composer is always focused, so these have to be claimed before Up/Down
        // become prompt history. The wheel is handled as Msg::Scroll, not as keys.
        if self.transcript_scroll_key(key) {
            return;
        }

        // No `!shift`: `Chord::hit` already masks SHIFT on character keys, because the
        // case of the character carries it and terminals disagree about sending both. The
        // guard here meant `?` was unreachable on every terminal that reports it with the
        // modifier (R1 §2.4).
        if self.keymap.hits(Action::Help, key) && self.focused_prompt_empty() {
            self.open_help();
            return;
        }

        if self.keymap.hits(Action::Settings, key) && self.focused_prompt_empty() {
            self.open_settings();
            return;
        }

        // A9: while the normalized ledger is the pane being drawn, its tree navigation
        // claims the keys the composer would otherwise type — but only while the draft is
        // empty, exactly as `?` and `,` do above.
        if self.details_key(key) {
            return;
        }

        // The interrupt is whatever `Action::Interrupt` is bound to, and nothing else.
        //
        // Before this it was a hardcoded `Esc` in two places, so rebinding `[keys]
        // interrupt` moved the footer hint, the `?` row, the palette column and `/keys`
        // — and left the key itself where it was. That is the exact failure this map
        // exists to prevent (R1 §2.4), and the reason it survived is that `Esc` means
        // several things at once.
        //
        // Claimed *last*, immediately before the composer, so every other reading of the
        // key keeps its turn first: closing an overlay, arming `Esc Esc`, clearing the
        // event ledger's filter. What is left after all of those is the composer's own
        // `Esc`, and interrupting is the one meaning of it that follows the binding
        // rather than the key.
        if self.interrupt_key(key) {
            return;
        }

        if self.sessions.composer.is_some() && self.tab == Tab::Sessions {
            self.composer_key(key);
            return;
        }

        // The start composer owns typing before and after account resolution.
        // Sign-in is a submit-time gate; it must never change where a letter goes.
        if self.tab == Tab::Sessions
            && self.sessions.open.is_none()
            && (!self.home_draft.is_empty() || !matches!(key.code, KeyCode::Tab | KeyCode::BackTab))
        {
            self.home_key(key);
            return;
        }

        // The list layer, reachable only from the three tabs that are lists. `i`, `s`,
        // `a` and `,` used to be here too and could never run: each of their handlers
        // returns unless `tab == Sessions`, which is the one state this match cannot be
        // reached from (R1 §2.1). They are gone rather than documented.
        match key.code {
            // Bounded by the table rather than by a literal range. `5`-`7` used to be
            // claimed here and dropped on the floor, so a digit past the last tab was a
            // keypress that was swallowed instead of falling through.
            KeyCode::Char(digit) if !ctrl && tab_for_digit(digit).is_some() => {
                if let Some(tab) = tab_for_digit(digit) {
                    self.select_tab(tab);
                }
            }
            KeyCode::Tab => self.select_tab(Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()]),
            KeyCode::BackTab => {
                let index = (self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                self.select_tab(Tab::ALL[index]);
            }
            // Kept literal: a bare `q` on a list is the field's convention (`less`,
            // `htop`, `k9s`) and is not the `quit` *chord*, which is `ctrl+q` and carries
            // its own binding. It is silenced when that binding is `off`, so an operator
            // who turned quitting off is not quit by a letter (R1 §2.1).
            KeyCode::Char('q') if self.bound(Action::Quit) => self.open_quit(),
            KeyCode::Char('?') => self.open_help(),
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char('j') | KeyCode::Down => self.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_by(-1),
            KeyCode::PageDown => self.move_by(10),
            KeyCode::PageUp => self.move_by(-10),
            KeyCode::Char('h') | KeyCode::Left => self.left(),
            KeyCode::Char('l') | KeyCode::Right => self.right(),
            KeyCode::Enter => self.activate(),
            KeyCode::Esc => self.escape(),
            KeyCode::Char('n') => self.open_new_session(),
            // Only with a session to end. Without one this opened the picker and told the
            // operator to press `x` — advice that was wrong the moment `leader.end` moved
            // to `k`, and a second spelling of a verb that has one.
            KeyCode::Char('x') if self.sessions.open.is_some() => self.open_close_confirm(),
            _ => {}
        }
    }

    /// Whether `key` is the interrupt, and there is a turn for it to interrupt.
    ///
    /// Two conditions, both necessary. The binding is what makes the map the authority;
    /// the running turn is what keeps the other meanings of `Esc` — closing a completion
    /// menu, arming `Esc Esc`, leaving an idle session — on `Esc` where they belong.
    fn interrupt_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        if !self.keymap.hits(Action::Interrupt, key) || !self.turn_running() {
            return false;
        }

        // A completion menu is the composer's own state and `Esc` dismisses it first,
        // even mid-turn: interrupting the agent because somebody wanted the `/` list to
        // go away is not what either keystroke asked for.
        if self
            .sessions
            .composer
            .as_ref()
            .is_some_and(|composer| composer.editor.completion().is_some())
        {
            return false;
        }

        self.interrupt_turn();
        true
    }

    /// Handles the backtrack chord, returning whether it consumed the key.
    ///
    /// Rebindable from `config.toml` on day one (`[keys] backtrack`), and since B8 through
    /// the same grammar as every other chord. Claude Code #43717 is what happens otherwise:
    /// a hardcoded double-Escape that "cannot be rebound or disabled" and breaks zsh
    /// vi-mode for everyone who uses it.
    ///
    /// A two-key binding arms on its first chord and **does not consume it**. That is what
    /// keeps `Esc` an interrupt while `Esc Esc` is also a chord — Claude Code #16905 is the
    /// interrupt being disabled by other state — and it is the honest reading for any other
    /// pair an operator writes: the first key keeps its own job.
    fn backtrack_chord(&mut self, key: crossterm::event::KeyEvent) -> bool {
        let Some(first) = self.keymap.first(Action::Backtrack) else {
            return false;
        };

        let Some(second) = self.keymap.rest(Action::Backtrack) else {
            if first.hit(key) {
                self.open_backtrack(None);
                return true;
            }

            return false;
        };

        // Within the window: this is the second key. The session named by the arm is the
        // one to go back through — the first key may have *left* it, and reopening the
        // thing the operator was just looking at is the only reading of the chord that is
        // not a surprise.
        if second.hit(key) {
            if let Some((until, open)) = self.backtrack_arm.take() {
                if self.ticks < until {
                    self.open_backtrack(Some(open));
                    return true;
                }
            }
        }

        if first.hit(key) {
            if let Some(open) = self.sessions.open.clone() {
                self.backtrack_arm = Some((self.ticks + BACKTRACK_TICKS, open));
            }
        }

        false
    }

    fn leader_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        self.leader_until = None;

        // Escape always abandons the leader, whatever it is bound to. A which-key overlay
        // you cannot back out of is a modal that did not say it was one.
        if key.code == KeyCode::Esc {
            return;
        }

        match self.keymap.leader_verb(key) {
            Some(Action::LeaderNew) => self.new_home(),
            Some(Action::LeaderNewOptions) => self.open_new_session(),
            Some(Action::LeaderSessions) => self.activate_command(Command::SwitchSession),
            Some(Action::LeaderWritable) => self.start_writable_session(),
            Some(Action::LeaderEditor) => self.request_external_editor(),
            Some(Action::LeaderCopy) => self.copy_last_agent(),
            Some(Action::LeaderScrollback) => self.dump_to_scrollback(),
            Some(Action::LeaderEditorView) => self.view_transcript(),
            Some(Action::LeaderOpenImage) => self.open_newest_image(),
            Some(Action::LeaderSteer) => self.compose(ComposerVerb::Steer),
            Some(Action::LeaderApproval) => self.reopen_approval(),
            Some(Action::LeaderAutoApprove) => self.set_auto_approve(None),
            Some(Action::LeaderShellRule) => self.add_shell_rule(),
            Some(Action::LeaderEnd) => self.open_close_confirm(),
            Some(Action::LeaderDetails) => self.toggle_session_details(),
            Some(Action::LeaderSettings) => self.open_settings(),
            // T2 replaces the stand-in with the preview-then-save picker.
            Some(Action::LeaderTheme) => self.open_theme_picker(),
            // Each of these runs the same code its `/` verb runs, so there is one
            // spelling of the behaviour and not two that can drift.
            Some(Action::LeaderExport) => self.activate_command(Command::Export),
            Some(Action::LeaderCompact) => self.activate_command(Command::Compact),
            Some(Action::LeaderModel) => self.prefill_composer("/model "),
            Some(Action::LeaderBacktrack) => self.activate_command(Command::Backtrack),
            Some(Action::LeaderStatus) => self.select_tab(Tab::Dashboard),
            Some(Action::LeaderRail) => self.toggle_rail(),
            Some(Action::LeaderTabDashboard) => self.select_tab(Tab::Dashboard),
            Some(Action::LeaderTabSessions) => self.select_tab(Tab::Sessions),
            Some(Action::LeaderTabUpgrade) => self.select_tab(Tab::Upgrade),
            Some(Action::LeaderTabLogs) => self.select_tab(Tab::Logs),
            Some(Action::LeaderQuit) => self.open_quit(),
            Some(Action::LeaderHelp) => self.open_help(),
            _unbound => {
                // The `,` of the global map still reaches settings from under the leader,
                // which is where it was before the verbs became data and is cheaper to
                // keep than to explain.
                if self.keymap.hits(Action::Settings, key) {
                    self.open_settings();
                    return;
                }

                // One alias that predates the map and was never drawn in the which-key
                // overlay: `o` beside `d` for details. Kept because removing a working
                // key without telling anyone is the failure R1 §2.5 names, and *not* made
                // an action because an alias is not a binding — `/keys` would then show
                // two rows for one verb.
                //
                // Its twin, `g` beside `e` for the editor, is gone: `g` is
                // `leader.backtrack` now, `leader_verb` claims it above, and an alias that
                // can never be reached is not an alias.
                match key.code {
                    KeyCode::Char('o') if self.bound(Action::LeaderDetails) => {
                        self.toggle_session_details()
                    }
                    _nothing => {
                        let hint = self.leader_hint_text();
                        self.inform(hint, NoticeKind::Info);
                    }
                }
            }
        }
    }

    /// The which-key line the leader prints when a key under it is not a verb.
    ///
    /// Built from the map rather than typed out, so a rebound leader verb is named by the
    /// key that actually reaches it (D14). Bounded to the first eight so a notice row
    /// cannot become a page.
    pub(super) fn leader_hint_text(&self) -> String {
        let verbs = self
            .keymap
            .live(Scope::Leader)
            .into_iter()
            .take(8)
            .map(|action| {
                format!(
                    "{} {}",
                    self.keymap.spec(action),
                    super::super::tree::truncate(action.describe(), 22)
                )
            })
            .collect::<Vec<_>>()
            .join(" · ");

        format!("{} {verbs}", self.keymap.label(Action::Leader))
    }

    pub(super) fn select_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.poll();
    }

    pub(super) fn move_by(&mut self, delta: isize) {
        match self.tab {
            Tab::Dashboard => {}
            Tab::Sessions => {
                if let Some(watch) = self.sessions.open_watch_mut() {
                    // Scrolling away from the bottom stops the transcript from jumping
                    // under a reader every time an event arrives; `Watch::measured`
                    // holds the rows still on the frames that follow.
                    if delta < 0 {
                        // Clamped against what the last frame drew. Left unbounded, a
                        // held PageUp on a short transcript buys hundreds of keypresses
                        // that do nothing, and then hundreds more to get back.
                        let wanted = watch
                            .scroll
                            .saturating_add(delta.unsigned_abs())
                            .min(watch.max_scroll());

                        if wanted > 0 {
                            watch.follow = false;
                            watch.scroll = wanted;
                        }
                    } else {
                        watch.scroll = watch.scroll.saturating_sub(delta as usize);

                        if watch.scroll == 0 {
                            watch.follow = true;
                        }
                    }
                }
            }
            Tab::Upgrade => match self.upgrade.focus {
                Pane::List => {
                    let len = UpgradeSection::ALL.len() as isize;
                    self.upgrade.section =
                        (self.upgrade.section as isize + delta).clamp(0, len - 1) as usize;
                    self.upgrade.tree.reset();
                    self.poll_upgrade_section();
                }
                Pane::Detail => {
                    let rows = self.upgrade_rows();
                    self.upgrade.tree.move_by(delta, rows);
                }
            },
            Tab::Logs => {
                if delta < 0 {
                    self.log_scroll = self.log_scroll.saturating_add(delta.unsigned_abs());
                } else {
                    self.log_scroll = self.log_scroll.saturating_sub(delta as usize);
                }
            }
        }
    }

    /// Transcript motion that must win over the always-on composer.
    ///
    /// Bare Up/Down stay prompt history, matching Pi and OpenCode. The wheel, PageUp, and
    /// Shift/Ctrl+Up are how you read the conversation without leaving the draft.
    fn transcript_scroll_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::{KeyCode, KeyModifiers};

        if self.tab != Tab::Sessions || self.sessions.open.is_none() {
            return false;
        }

        // `home` and `end` are the transcript's ends only on an empty draft. With text in
        // it they are what readline says they are, and the editor below claims them: a
        // client that jumped the transcript while somebody was editing the middle of a
        // line would have taken a motion key away to buy a scroll.
        if self.focused_prompt_empty() {
            if self.keymap.hits(Action::TranscriptTop, key) {
                self.transcript_to_top();
                return true;
            }

            if self.keymap.hits(Action::TranscriptBottom, key) {
                self.transcript_to_bottom();
                return true;
            }
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);

        match key.code {
            KeyCode::PageUp => self.scroll_view(-10),
            KeyCode::PageDown => self.scroll_view(10),
            KeyCode::Up if ctrl || shift => self.scroll_view(-3),
            KeyCode::Down if ctrl || shift => self.scroll_view(3),
            _ => return false,
        }

        true
    }

    /// The oldest row the last frame measured. Clamped to what was drawn, exactly as
    /// [`App::move_by`] clamps a held PageUp, so this cannot buy an offset nothing has.
    fn transcript_to_top(&mut self) {
        if let Some(watch) = self.sessions.open_watch_mut() {
            let top = watch.max_scroll();

            if top > 0 {
                watch.follow = false;
                watch.scroll = top;
            }
        }
    }

    /// Back to the newest row, and following again — which is what being at the bottom of
    /// a live transcript means.
    fn transcript_to_bottom(&mut self) {
        if let Some(watch) = self.sessions.open_watch_mut() {
            watch.scroll = 0;
            watch.follow = true;
        }
    }

    pub(super) fn scroll_view(&mut self, delta: isize) {
        if self.overlay.is_some() {
            return;
        }

        self.move_by(delta);
    }

    fn upgrade_rows(&self) -> usize {
        let section = self.upgrade.current();

        self.upgrade
            .panel(section)
            .value
            .as_ref()
            .map(|value| {
                TreeView::new(section.title(), value)
                    .rows(&self.upgrade.tree)
                    .len()
            })
            .unwrap_or(0)
    }

    fn left(&mut self) {
        match self.tab {
            Tab::Sessions => {}
            Tab::Upgrade if self.upgrade.focus == Pane::Detail => self.collapse_upgrade_or_leave(),
            _ => {}
        }
    }

    fn collapse_upgrade_or_leave(&mut self) {
        let section = self.upgrade.current();
        let selected = self.upgrade.tree.selected();

        let path = self
            .upgrade
            .panel(section)
            .value
            .as_ref()
            .and_then(|value| {
                TreeView::new(section.title(), value)
                    .rows(&self.upgrade.tree)
                    .get(selected)
                    .filter(|row| row.expanded)
                    .map(|row| row.path.clone())
            });

        match path {
            Some(path) => self.upgrade.tree.collapse(&path),
            None => self.upgrade.focus = Pane::List,
        }
    }

    fn right(&mut self) {
        match self.tab {
            Tab::Sessions => {}
            Tab::Upgrade => self.upgrade.focus = Pane::Detail,
            _ => {}
        }
    }

    fn activate(&mut self) {
        match self.tab {
            Tab::Sessions if self.sessions.open.is_some() => {
                self.compose(ComposerVerb::Message);
            }
            Tab::Upgrade => match self.upgrade.focus {
                Pane::List => self.activate_upgrade_section(),
                Pane::Detail => self.toggle_upgrade_row(),
            },
            _ => {}
        }
    }

    fn activate_upgrade_section(&mut self) {
        match self.upgrade.current() {
            UpgradeSection::Grants => {
                self.overlay = Some(Overlay::Prompt {
                    kind: PromptKind::GrantsPrincipal,
                    // `Control.Grants.list/1` is per-principal by design; there is no
                    // list-all upstream and the gateway did not add one.
                    label: "principal".into(),
                    buffer: self.upgrade.grants_principal.clone().unwrap_or_default(),
                })
            }
            _ => self.upgrade.focus = Pane::Detail,
        }
    }

    fn toggle_upgrade_row(&mut self) {
        let section = self.upgrade.current();
        let selected = self.upgrade.tree.selected();

        let path = self
            .upgrade
            .panel(section)
            .value
            .as_ref()
            .and_then(|value| {
                TreeView::new(section.title(), value)
                    .rows(&self.upgrade.tree)
                    .get(selected)
                    .filter(|row| row.expandable)
                    .map(|row| row.path.clone())
            });

        if let Some(path) = path {
            self.upgrade.tree.toggle(&path);
        }
    }

    /// `Esc` on a list tab returns to the conversation. On the Sessions tab the composer
    /// owns `Esc` (`escape_from_prompt`), so this is never reached there: the branch that
    /// used to close a composer here served a state the client cannot be in.
    fn escape(&mut self) {
        if self.tab != Tab::Sessions {
            self.select_tab(Tab::Sessions);
        }
    }
}
