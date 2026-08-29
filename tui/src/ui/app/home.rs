use super::*;

impl App {
    // ----- harness home --------------------------------------------------------------

    /// Lands this client on the coding home and asks for what that home needs.
    ///
    /// Called once by the driver, before the first frame, and only where a session was not
    /// already asked for — `ouro new` states what it wants on the command line and opens
    /// what it started.
    ///
    /// There is no modal to dismiss and no provider picker between `ouro` and the composer.
    /// Account state, recent sessions, and the current workspace all arrive behind the
    /// first frame, so the composer is typeable while they are still in flight.
    pub fn open_home(&mut self) {
        self.tab = Tab::Sessions;
        self.issue_if_due(Tag::Account, "account.read", json!({}), ACCOUNT_TICKS);
        self.issue_if_due(
            Tag::Sessions(Plane::Interactive),
            "interactive.list",
            json!({}),
            LIST_TICKS,
        );
        self.issue_if_due(
            Tag::Sessions(Plane::Coding),
            "coding.list",
            json!({}),
            LIST_TICKS,
        );
        if self.open_machines_on_start {
            self.open_machines_on_start = false;
            self.open_machines();
            if !self.resume_add_log.is_empty() || self.resume_add_recipe.is_some() {
                if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                    let mut add = AddMachine::new();
                    add.step = AddStep::Done;
                    add.log = std::mem::take(&mut self.resume_add_log);
                    add.recipe = self.resume_add_recipe.take();
                    machines.add = Some(add);
                }
            }
        }
    }

    /// One line for the coding home: this is one machine, or how many are connected.
    pub fn machine_hint(&self) -> String {
        let summary = self.machine_summary();
        if summary.mode == "Standalone" {
            "This is one machine. /machines adds your laptop and servers.".into()
        } else {
            format!(
                "Fleet: {} connected. /machines adds or repairs others.",
                summary.connected
            )
        }
    }

    /// Records that this operator has reached the coding home once.
    ///
    /// A marker rather than a timestamp: the only question it answers is "has this person
    /// seen this client introduce itself", and a date would invite a client to decide the
    /// answer expires.
    fn mark_welcomed(&mut self) {
        if !self.config.onboarding.welcomed {
            self.config.onboarding.welcomed = true;
            self.save_pending = true;
        }
    }

    pub(super) fn home_key(&mut self, key: crossterm::event::KeyEvent) {
        if self.home_pending {
            return;
        }

        if self
            .first_message
            .as_ref()
            .is_some_and(|pending| pending.start_outcome_unknown)
        {
            if key.code == crossterm::event::KeyCode::Enter {
                self.submit_home();
            } else {
                self.home_error = Some(
                    "this start may already exist; press Enter to reconcile its same session id \
                     before changing the prompt"
                        .to_string(),
                );
            }
            return;
        }

        match self
            .home_draft
            .handle_key_with(key, &self.completion_catalog, &self.keymap)
        {
            EditorAction::Submit => self.submit_home(),
            // There is no session to steer yet, so the home composer keeps `Alt+Enter` as
            // the newline it was before B3 gave the key a second meaning on a session.
            EditorAction::SubmitAlternate => {
                let catalog = self.completion_catalog.clone();
                self.home_draft.paste("\n", &catalog);
                self.home_error = None;
            }
            EditorAction::Cancel => {
                self.home_draft.clear_text();
                self.home_error = None;
            }
            EditorAction::None => {
                self.home_error = None;
            }
            EditorAction::Scroll(_) => {}
        }
    }

    fn submit_home(&mut self) {
        let provider = self.home_provider().to_string();
        let prompt = self.home_draft.submission();

        // Navigation and account commands remain usable before direct OAuth completes. The
        // draft survives the login overlay and can be submitted unchanged afterwards.
        if prompt
            .as_deref()
            .is_some_and(|prompt| self.activate_slash_command(prompt))
        {
            self.home_draft.accept_submission();
            return;
        }

        // Only the OAuth-backed direct model needs ChatGPT sign-in. API-key and unrelated
        // providers must never be blocked by this account surface.
        if self.home_requires_chatgpt() && !self.codex_usable() {
            self.open_account();
            return;
        }

        let Some(prompt) = prompt else {
            self.home_error = Some("Type what you want the agent to do.".to_string());
            return;
        };

        if !self.hello.serves("interactive.start") {
            self.home_error = Some("this gateway does not serve interactive.start".to_string());
            return;
        }

        if !self.hello.operates() {
            self.home_error = Some(format!(
                "starting a session mutates the runtime, and this listener runs at scope `{}`",
                self.hello.scope
            ));
            return;
        }

        if let Err(refusal) = self.issue_quick_start(provider, prompt) {
            self.home_error = Some(refusal);
        }
    }

    /// Issues one interactive quick start and holds `prompt` as that session's first
    /// message until the start answers.
    ///
    /// Separate from its caller so that the request built here, the same-id replay after an
    /// outcome-unknown refusal, and the bookkeeping [`App::started`] dispatches the prompt
    /// from cannot drift apart.
    ///
    /// The caller keeps its own refusals: capability, scope, empty-prompt, and account
    /// checks are the home screen's to make, and this function makes none of them. The one
    /// refusal it can produce is the request's own — a `StartRequest` that does not
    /// describe a session — returned rather than displayed.
    ///
    /// The stored provider default and the welcome marker are written here: the provider
    /// written down is exactly the one this start used, and reaching a first session is the
    /// event the marker records.
    pub(super) fn issue_quick_start(
        &mut self,
        provider: String,
        prompt: String,
    ) -> Result<(), String> {
        let request = self
            .first_message
            .as_ref()
            .filter(|pending| pending.start_outcome_unknown && pending.input == prompt)
            .map(|pending| pending.start.clone())
            .unwrap_or_else(|| StartRequest {
                id: new_session_id(),
                plane: Plane::Interactive,
                provider: provider.clone(),
                model: Some(self.home_model().to_string()),
                machine: String::new(),
                workspace: self.default_workspace(),
                approval_mode: self.config.defaults.approval_mode(),
                sandbox_mode: self.config.defaults.sandbox_mode(),
                reasoning_effort: None,
                objective: String::new(),
                // The quick start is the shortest path there is; a worktree and plan mode
                // are choices, and they are made in the `n` dialog or on the command line.
                worktree: false,
                plan: false,
            });

        let params = request.params().map_err(|refusal| refusal.message())?;

        self.home_pending = true;
        self.home_error = None;
        match self.first_message.as_mut() {
            Some(pending)
                if pending.start_outcome_unknown
                    && pending.input == prompt
                    && pending.start.id == request.id =>
            {
                pending.start_outcome_unknown = false;
            }
            _ => {
                self.first_message = Some(PendingFirstMessage {
                    input: prompt,
                    turn_id: new_turn_id(),
                    start: request.clone(),
                    start_outcome_unknown: false,
                });
            }
        }
        self.config.defaults.provider = Some(provider);
        self.mark_welcomed();
        self.save_pending = true;

        self.issue(
            Call::new(
                Tag::Start {
                    plane: Plane::Interactive,
                    id: request.id.clone(),
                },
                request.method(),
                params,
            )
            .with_timeout(START_TIMEOUT),
        );
        Ok(())
    }

    /// Starts a new interactive session that can edit the workspace.
    ///
    /// Sandbox is a start-time option: a running read-only session cannot be promoted.
    /// This is the switch the composer chrome offers.
    pub(super) fn start_writable_session(&mut self) {
        if let Some(request) = self.pending_background_start.clone() {
            let Ok(params) = request.params() else {
                self.pending_background_start = None;
                self.inform(
                    "the saved writable-session reconciliation was invalid; no request was sent",
                    NoticeKind::Error,
                );
                return;
            };
            self.inform(
                format!(
                    "reconciling the same writable session id {}; no duplicate will be started",
                    request.id
                ),
                NoticeKind::Warn,
            );
            self.issue(
                Call::new(
                    Tag::Start {
                        plane: request.plane,
                        id: request.id.clone(),
                    },
                    request.method(),
                    params,
                )
                .with_timeout(START_TIMEOUT),
            );
            return;
        }

        if self.open_sandbox().is_some_and(|(_, writable)| writable) {
            self.inform(
                "this session can already edit files in the workspace",
                NoticeKind::Info,
            );
            return;
        }

        if self.sessions.open.is_none()
            && self
                .config
                .defaults
                .sandbox_mode()
                .is_none_or(SandboxMode::writable)
        {
            self.inform(
                "new sessions can already edit files; --sandbox-mode read_only or settings \
                 starts a read-only one",
                NoticeKind::Info,
            );
            return;
        }

        if !self.hello.serves("interactive.start") {
            self.inform(
                "this gateway does not serve interactive.start",
                NoticeKind::Warn,
            );
            return;
        }

        if !self.hello.operates() {
            self.inform(
                format!(
                    "starting a session mutates the runtime, and this listener runs at scope `{}`",
                    self.hello.scope
                ),
                NoticeKind::Warn,
            );
            return;
        }

        let provider = self
            .sessions
            .open_info()
            .and_then(|session| session.provider.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| self.home_provider().to_string());

        if provider.is_empty() {
            self.inform(
                "choose a provider before starting a writable session",
                NoticeKind::Warn,
            );
            return;
        }

        let workspace = self
            .sessions
            .open_info()
            .and_then(|session| session.workspace.clone())
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| self.default_workspace());

        let request = StartRequest {
            id: new_session_id(),
            plane: Plane::Interactive,
            provider,
            model: Some(self.home_model().to_string()),
            machine: String::new(),
            workspace,
            approval_mode: self.config.defaults.approval_mode(),
            sandbox_mode: Some(SandboxMode::WorkspaceWrite),
            reasoning_effort: None,
            objective: String::new(),
            worktree: false,
            // `/write` is the verb for "let it edit"; starting it planning would be the
            // opposite of what was asked for.
            plan: false,
        };

        let params = match request.params() {
            Ok(params) => params,
            Err(refusal) => {
                self.inform(refusal.message(), NoticeKind::Warn);
                return;
            }
        };

        self.inform(
            "starting a session that can edit files in the workspace",
            NoticeKind::Info,
        );

        self.pending_background_start = Some(request.clone());

        self.issue(
            Call::new(
                Tag::Start {
                    plane: Plane::Interactive,
                    id: request.id.clone(),
                },
                request.method(),
                params,
            )
            .with_timeout(START_TIMEOUT),
        );
    }

    pub(super) fn open_account(&mut self) {
        if self.chatgpt_connected() {
            let flow = if self.spawned() {
                AccountFlow::Browser
            } else {
                AccountFlow::DeviceCode
            };

            self.overlay = Some(Overlay::Account(Box::new(AccountDialog {
                pending: false,
                flow,
                login_id: None,
                url: None,
                code: None,
                error: None,
            })));
            return;
        }

        if !self.hello.serves("account.login.start") {
            self.home_error = Some(
                "this gateway does not expose managed ChatGPT sign-in; update the runtime"
                    .to_string(),
            );
            return;
        }

        if !self.hello.operates() {
            self.home_error = Some(format!(
                "ChatGPT sign-in changes the runtime host, and this listener runs at scope `{}`",
                self.hello.scope
            ));
            return;
        }

        let flow = if self.spawned() {
            AccountFlow::Browser
        } else {
            AccountFlow::DeviceCode
        };

        self.overlay = Some(Overlay::Account(Box::new(AccountDialog::new(flow))));

        self.issue(Call::new(
            Tag::AccountLogin,
            "account.login.start",
            json!({
                "flow": match flow {
                    AccountFlow::Browser => "browser",
                    AccountFlow::DeviceCode => "device_code",
                }
            }),
        ));
    }

    pub(super) fn new_home(&mut self) {
        self.overlay = None;
        self.tab = Tab::Sessions;
        self.remember_composer_history();
        self.sessions.open = None;
        self.sessions.composer = None;
        self.home_draft.clear_text();
        self.home_error = None;
        self.poll();
    }

    pub(super) fn paste(&mut self, text: &str) {
        if self.overlay.is_some() {
            self.overlay_paste(text);
            return;
        }

        if self.tab == Tab::Sessions {
            if let Some(composer) = self.sessions.composer.as_mut() {
                let before = composer.editor.text().to_string();
                composer.editor.paste(text, &self.completion_catalog);
                if composer.editor.text() != before {
                    composer.user_changed_draft();
                }
                return;
            }

            if self.sessions.open.is_none()
                && self.home_ready()
                && !self.home_pending
                && !self
                    .first_message
                    .as_ref()
                    .is_some_and(|pending| pending.start_outcome_unknown)
            {
                self.home_draft.paste(text, &self.completion_catalog);
                self.home_error = None;
            }
        }
    }

    /// A bracketed paste while an overlay owns the keyboard.
    ///
    /// Dropped silently before this, which made the workspace box of the `n` dialog and the
    /// settings overlay — the two fields most likely to receive a path off the clipboard —
    /// look broken in a way nothing on screen explained. Every overlay with a text field
    /// takes it; the rest say so rather than swallowing it.
    fn overlay_paste(&mut self, text: &str) {
        // These are one-line fields. A multi-line clipboard becomes one line rather than
        // being refused, because the alternative is a field that silently holds a newline
        // it cannot draw.
        let flattened = text
            .split(['\n', '\r'])
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");

        if flattened.is_empty() {
            return;
        }

        let taken = match self.overlay.as_mut() {
            // A dialog whose start is in flight takes no edits, for the same reason it
            // takes no keys: the parameters that produced the request are the ones its
            // answer is about.
            Some(Overlay::New(dialog)) if !dialog.pending => {
                push_into(dialog.text_mut(), &flattened)
            }
            Some(Overlay::Settings(settings)) => {
                let taken = push_into(settings.text_mut(), &flattened);
                settings.edited |= taken;
                taken
            }
            Some(Overlay::Commands(palette)) => {
                palette.query.push_str(&flattened);
                // The selection is derived from the query, exactly as for a typed
                // character: the visible list is already filtered to what matches, so the
                // first row is the first match.
                palette.selected = 0;
                true
            }
            Some(Overlay::Prompt { buffer, .. }) => push_into(Some(buffer), &flattened),
            _ => false,
        };

        // Said rather than swallowed: a paste that vanished with nothing on screen to
        // explain it reads as the terminal being broken.
        if !taken {
            self.inform("nothing here is taking text right now", NoticeKind::Info);
        }
    }
}
