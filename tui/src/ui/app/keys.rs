use super::*;

/// Chords after `Ctrl+X`. Drawn by the which-key overlay while the leader is pending.
pub const LEADER_KEYS: &[(&str, &str)] = &[
    ("n", "new session"),
    ("N", "session options"),
    ("l", "switch session"),
    ("e", "external editor"),
    ("y", "copy last message"),
    ("s", "steer"),
    ("a", "approval"),
    ("w", "writable session"),
    ("x", "end or remove session"),
    ("o", "event details"),
    ("q", "quit"),
    ("?", "keyboard help"),
];

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
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        if self.leader_until.is_some() {
            self.leader_key(key);
            return;
        }

        if ctrl && matches!(key.code, KeyCode::Char('p')) {
            if matches!(self.overlay, Some(Overlay::Commands(_))) {
                self.overlay = None;
            } else if self.overlay.is_none() {
                self.overlay = Some(Overlay::Commands(CommandPalette::default()));
            }
            return;
        }

        if ctrl && matches!(key.code, KeyCode::Char('q')) {
            self.open_quit();
            return;
        }

        if ctrl && matches!(key.code, KeyCode::Char('x')) && self.overlay.is_none() {
            self.leader_until = Some(self.ticks + LEADER_TICKS);
            return;
        }

        if ctrl && matches!(key.code, KeyCode::Char('g')) && self.overlay.is_none() {
            self.request_external_editor();
            return;
        }

        // Event details must remain reachable while the composer owns printable keys.
        // Ctrl+O is the Pi/OpenCode muscle memory for expanding tool output; Ctrl+E is
        // readline end-of-line once it reaches the editor.
        if ctrl && matches!(key.code, KeyCode::Char('o')) && self.overlay.is_none() {
            self.toggle_session_details();
            return;
        }

        if ctrl && matches!(key.code, KeyCode::Char('c')) {
            self.ctrl_c();
            return;
        }

        if ctrl
            && matches!(key.code, KeyCode::Char('d'))
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

        // The composer is always focused, so these have to be claimed before Up/Down
        // become prompt history. The wheel is handled as Msg::Scroll, not as keys.
        if self.transcript_scroll_key(key) {
            return;
        }

        if matches!(key.code, KeyCode::Char('?')) && !shift && self.focused_prompt_empty() {
            self.overlay = Some(Overlay::Help);
            return;
        }

        if matches!(key.code, KeyCode::Char(',')) && self.focused_prompt_empty() {
            self.open_settings();
            return;
        }

        let alt = key.modifiers.contains(crossterm::event::KeyModifiers::ALT);
        if self.tab == Tab::Plans && !ctrl && !alt {
            match key.code {
                KeyCode::Char('s') => {
                    self.open_control_submit();
                    return;
                }
                KeyCode::Char('c') => {
                    self.open_control_cancel();
                    return;
                }
                _ => {}
            }
        }

        if self.sessions.composer.is_some() && self.tab == Tab::Sessions {
            self.composer_key(key);
            return;
        }

        if self.tab == Tab::Sessions && self.sessions.open.is_none() && self.home_owns_key(key.code)
        {
            self.home_key(key);
            return;
        }

        match key.code {
            KeyCode::Char(digit @ '1'..='7') if !ctrl => {
                let index = digit as usize - '1' as usize;
                self.select_tab(Tab::ALL[index]);
            }
            KeyCode::Tab => self.select_tab(Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()]),
            KeyCode::BackTab => {
                let index = (self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                self.select_tab(Tab::ALL[index]);
            }
            KeyCode::Char('q') => self.open_quit(),
            KeyCode::Char('?') => self.overlay = Some(Overlay::Help),
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char('j') | KeyCode::Down => self.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_by(-1),
            KeyCode::PageDown => self.move_by(10),
            KeyCode::PageUp => self.move_by(-10),
            KeyCode::Char('h') | KeyCode::Left => self.left(),
            KeyCode::Char('l') | KeyCode::Right => self.right(),
            KeyCode::Enter => self.activate(),
            KeyCode::Esc => self.escape(),
            KeyCode::Char('i') => self.compose(ComposerVerb::Message),
            KeyCode::Char('s') => self.compose(ComposerVerb::Steer),
            KeyCode::Char('a') => self.reopen_approval(),
            KeyCode::Char('n') => self.open_new_session(),
            KeyCode::Char('x') => self.open_close_confirm(),
            KeyCode::Char(',') => self.open_settings(),
            _ => {}
        }
    }

    fn leader_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyModifiers};

        self.leader_until = None;

        let shift = key.modifiers.contains(KeyModifiers::SHIFT);

        match key.code {
            KeyCode::Esc => {}
            KeyCode::Char('n') if shift => self.open_new_session(),
            KeyCode::Char('N') => self.open_new_session(),
            KeyCode::Char('n') => self.new_home(),
            KeyCode::Char('l') => self.activate_command(Command::SwitchSession),
            KeyCode::Char('e') | KeyCode::Char('g') => self.request_external_editor(),
            KeyCode::Char('y') => self.copy_last_agent(),
            KeyCode::Char('s') => self.compose(ComposerVerb::Steer),
            KeyCode::Char('a') => self.reopen_approval(),
            KeyCode::Char('w') => self.start_writable_session(),
            KeyCode::Char('x') => self.open_close_confirm(),
            KeyCode::Char('o') | KeyCode::Char('d') => self.toggle_session_details(),
            KeyCode::Char('q') => self.open_quit(),
            KeyCode::Char('?') => self.overlay = Some(Overlay::Help),
            KeyCode::Char(',') => self.open_settings(),
            _ => self.inform(
                "ctrl+x n new · w write · l sessions · e editor · y copy · s steer · x end · q quit",
                NoticeKind::Info,
            ),
        }
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
            Tab::Agents => Self::explorer_move(&mut self.agents, delta),
            Tab::Teams => Self::explorer_move(&mut self.teams, delta),
            Tab::Plans => {
                let explorer = if self.plans_on_control {
                    &mut self.control
                } else {
                    &mut self.plans
                };

                Self::explorer_move(explorer, delta);
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

    pub(super) fn scroll_view(&mut self, delta: isize) {
        if self.overlay.is_some() {
            return;
        }

        self.move_by(delta);
    }

    fn explorer_move(explorer: &mut Explorer, delta: isize) {
        match explorer.focus {
            Pane::List => explorer.move_by(delta),
            Pane::Detail => {
                let rows = explorer
                    .detail
                    .value
                    .as_ref()
                    .map(|value| TreeView::new("state", value).rows(&explorer.tree))
                    .map(|rows| rows.len())
                    .unwrap_or(0);

                explorer.tree.move_by(delta, rows);
            }
        }
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
            Tab::Agents => Self::explorer_left(&mut self.agents),
            Tab::Teams => Self::explorer_left(&mut self.teams),
            Tab::Plans => {
                let explorer = if self.plans_on_control {
                    &mut self.control
                } else {
                    &mut self.plans
                };

                if explorer.focus == Pane::List {
                    self.plans_on_control = false;
                } else {
                    Self::explorer_left(explorer);
                }
            }
            Tab::Upgrade if self.upgrade.focus == Pane::Detail => self.collapse_upgrade_or_leave(),
            _ => {}
        }
    }

    fn explorer_left(explorer: &mut Explorer) {
        if explorer.focus == Pane::List {
            return;
        }

        let Some(value) = explorer.detail.value.as_ref() else {
            explorer.focus = Pane::List;
            return;
        };

        let view = TreeView::new("state", value);
        let rows = view.rows(&explorer.tree);

        match rows.get(explorer.tree.selected()) {
            Some(row) if row.expanded => explorer.tree.collapse(&row.path),
            // Collapsed already: left is how you get back to the list.
            _ => explorer.focus = Pane::List,
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

            Tab::Agents => self.agents.focus = Pane::Detail,
            Tab::Teams => self.teams.focus = Pane::Detail,
            Tab::Plans => {
                let on_control = self.plans_on_control;
                let explorer = if on_control {
                    &mut self.control
                } else {
                    &mut self.plans
                };

                if explorer.focus == Pane::Detail && !on_control {
                    self.plans_on_control = true;
                } else {
                    explorer.focus = Pane::Detail;
                }
            }
            Tab::Upgrade => self.upgrade.focus = Pane::Detail,
            _ => {}
        }
    }

    fn activate(&mut self) {
        match self.tab {
            Tab::Sessions => {
                if self.sessions.open.is_some() {
                    self.compose(ComposerVerb::Message);
                }
            }
            Tab::Agents => Self::explorer_activate(&mut self.agents),
            Tab::Teams => Self::explorer_activate(&mut self.teams),
            Tab::Plans => {
                let explorer = if self.plans_on_control {
                    &mut self.control
                } else {
                    &mut self.plans
                };

                Self::explorer_activate(explorer);
            }
            Tab::Upgrade => match self.upgrade.focus {
                Pane::List => self.activate_upgrade_section(),
                Pane::Detail => self.toggle_upgrade_row(),
            },
            _ => {}
        }
    }

    fn explorer_activate(explorer: &mut Explorer) {
        if explorer.focus == Pane::List {
            explorer.focus = Pane::Detail;
            return;
        }

        let Some(value) = explorer.detail.value.as_ref() else {
            return;
        };

        let view = TreeView::new("state", value);
        let rows = view.rows(&explorer.tree);

        if let Some(row) = rows.get(explorer.tree.selected()) {
            if row.expandable {
                explorer.tree.toggle(&row.path);
            }
        }
    }

    fn activate_upgrade_section(&mut self) {
        match self.upgrade.current() {
            UpgradeSection::History => {
                self.overlay = Some(Overlay::Prompt {
                    kind: PromptKind::HistoryModule,
                    label: "module (e.g. Ouroboros.Capability.Example)".into(),
                    buffer: self.upgrade.history_module.clone().unwrap_or_default(),
                })
            }
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

    fn escape(&mut self) {
        if self.tab != Tab::Sessions {
            self.select_tab(Tab::Sessions);
            return;
        }

        if self.tab == Tab::Sessions {
            if self.sessions.composer.is_some() {
                self.remember_composer_history();
                self.sessions.composer = None;
                return;
            }

            self.sessions.open = None;
        }
    }
}
