use super::*;

/// One row of a provider picker that has to be able to show a stored default the runtime
/// does not report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderChoice {
    /// No default: every session states its own provider, as it always did.
    Unset,
    /// A provider this runtime reports, and whether its probe found an executable.
    Probed { name: String, ready: bool },
    /// The config file names it and this runtime's provider list does not.
    Unserved { name: String },
}

impl ProviderChoice {
    /// The name to store, or `None` for the "unset" row.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Unset => None,
            Self::Probed { name, .. } | Self::Unserved { name } => Some(name),
        }
    }
}

/// The rows the settings provider picker offers.
///
/// "unset" first, then whatever `runtime.providers` reported, then the stored default when
/// this runtime does not report it. That last row is why this is a function rather than an
/// index into the probe list: a config written on another machine — or before a provider
/// was removed — names something the probe will not list, and a picker that silently
/// dropped it would show an operator a default they no longer have.
pub fn provider_choices(providers: &[ProviderEntry], stored: Option<&str>) -> Vec<ProviderChoice> {
    let mut choices = vec![ProviderChoice::Unset];

    choices.extend(providers.iter().map(|entry| ProviderChoice::Probed {
        name: entry.provider.clone(),
        ready: entry.ready(),
    }));

    if let Some(stored) = stored.map(str::trim).filter(|stored| !stored.is_empty()) {
        if !providers.iter().any(|entry| entry.provider == stored) {
            choices.push(ProviderChoice::Unserved {
                name: stored.to_string(),
            });
        }
    }

    choices
}

/// One row of the new-session dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewField {
    Plane,
    Machine,
    Provider,
    Model,
    Workspace,
    ApprovalMode,
    SandboxMode,
    /// Only reachable on the coding plane, where the objective is required.
    Objective,
    /// D7. Whether the session runs in its own `git worktree` rather than the workspace
    /// itself. Offered only where the gateway serves the option, because a toggle that a
    /// runtime silently ignores is worse than no toggle.
    Worktree,
    Start,
}

/// The dialog that turns "start a session" into a set of stated choices.
///
/// Every field is on screen at once, and every one of them stays editable. What the config
/// file supplies is where the *cursor starts*, never what gets sent: a prefilled provider
/// is one the operator chose once, explicitly, in a file they can read, which is a
/// different thing from a node's default deciding for them. With no config the dialog is
/// exactly what it was — provider on row one, nothing preselected but the first entry.
///
/// The provider list comes from `runtime.providers` — the same answer the Dashboard shows
/// — and an entry whose probe found no executable is drawn dim but is **still
/// selectable**: "installed" means a file exists, the runtime is the authority on whether
/// a session can start, and refusing on a heuristic would be this client overruling it.
#[derive(Debug)]
pub struct NewSession {
    pub field: NewField,
    pub request: StartRequest,
    /// Index into the provider list, kept rather than the name so the cursor survives a
    /// providers refresh that reordered nothing.
    pub provider: usize,
    /// Index into [`App::machine_choices`]. Zero is always this machine.
    pub machine: usize,
    pub approval: usize,
    pub sandbox: usize,
    /// True while `*.start` is in flight — it declares a 120s ceiling, so this is a dialog
    /// that legitimately waits.
    pub pending: bool,
    /// Why the last attempt did not start a session. Shown here rather than in the notice
    /// line: the operator is still looking at the form that produced it.
    pub error: Option<String>,
    /// The exact request whose reply may have been lost. While present, Enter replays
    /// these immutable params and edits are held back so the id remains meaningful.
    pending_request: Option<StartRequest>,
    pub reconciling: bool,
    /// The caller's cwd is a useful local hint and an unsafe remote default. Keep it only
    /// so cycling back to this machine can restore it before the operator edits the field.
    inferred_local_workspace: Option<String>,
    /// The provider the config file names, until the probe list arrives and the cursor can
    /// be put on it.
    ///
    /// A name rather than an index because the list it indexes into is fetched
    /// asynchronously and may not exist when this dialog opens. Cleared the moment it is
    /// placed — or the moment the operator moves the cursor themselves, so a providers
    /// answer that lands late cannot move a choice they already made.
    wanted_provider: Option<String>,
}

impl NewSession {
    fn new(
        plane: Plane,
        workspace: String,
        workspace_is_inferred: bool,
        defaults: &Defaults,
    ) -> Self {
        let inferred_local_workspace = workspace_is_inferred.then(|| workspace.clone());
        Self {
            field: NewField::Provider,
            request: StartRequest {
                workspace,
                model: defaults.model.clone(),
                ..StartRequest::new(plane)
            },
            provider: 0,
            machine: 0,
            approval: approval_index(defaults.approval_mode()),
            sandbox: sandbox_index(defaults.sandbox_mode()),
            pending: false,
            error: None,
            pending_request: None,
            reconciling: false,
            inferred_local_workspace,
            wanted_provider: defaults.provider.clone().or_else(|| Some("native".into())),
        }
    }

    /// Puts the cursor on the provider the config names, once the list is known.
    ///
    /// Answers the stored name back when this runtime does not serve it, so the caller can
    /// say so rather than leaving the cursor somewhere the operator did not choose. Idle
    /// on every later call — a default is applied once, and the cursor is the operator's
    /// afterwards.
    fn place_provider(&mut self, providers: &[ProviderEntry]) -> Option<String> {
        let wanted = self.wanted_provider.clone()?;

        if providers.is_empty() {
            return None;
        }

        self.wanted_provider = None;

        match providers.iter().position(|entry| entry.provider == wanted) {
            Some(index) => {
                self.provider = index;
                if wanted == "native" && self.request.model.is_none() {
                    self.request.model = Some("openai_codex:gpt-5.6-sol".into());
                }
                None
            }
            None => Some(wanted),
        }
    }

    /// The rows this plane has. `objective` exists only where the gateway accepts it.
    pub fn fields(&self) -> Vec<NewField> {
        let mut fields = vec![
            NewField::Plane,
            NewField::Machine,
            NewField::Provider,
            NewField::Model,
        ];

        if self.request.plane == Plane::Coding {
            fields.push(NewField::Objective);
        }

        fields.extend([
            NewField::Workspace,
            NewField::ApprovalMode,
            NewField::SandboxMode,
            NewField::Worktree,
            NewField::Start,
        ]);
        fields
    }

    pub fn approval_mode(&self) -> Option<ApprovalMode> {
        approval_at(self.approval)
    }

    /// The approval row's label, including the "say nothing" option at index 0.
    pub fn approval_label(&self) -> String {
        approval_label(self.approval)
    }

    pub fn sandbox_mode(&self) -> Option<SandboxMode> {
        sandbox_at(self.sandbox)
    }

    pub fn sandbox_label(&self) -> String {
        sandbox_label(self.sandbox)
    }

    /// The provider entry the cursor is on, once `runtime.providers` has answered.
    pub fn provider_entry<'a>(&self, providers: &'a [ProviderEntry]) -> Option<&'a ProviderEntry> {
        providers.get(self.provider)
    }

    /// Why the selected approval mode cannot start a session on the selected provider.
    ///
    /// Read out of `runtime.providers` — the `normalized_values` and `session_transports`
    /// this client already receives and never used (M2 §6). The dialog greys the row
    /// rather than removing the value: a mode this provider refuses is still a mode, and
    /// an operator comparing providers needs to see which one is the obstacle.
    ///
    /// `None` also where the spec does not resolve. Greying on a guess would be this
    /// client overruling a runtime that has not spoken.
    pub fn approval_refusal(&self, providers: &[ProviderEntry]) -> Option<String> {
        let entry = self.provider_entry(providers)?;
        let reason = entry.approval_mode_refusal(self.approval_mode()?)?;

        Some(format!("not offered by {} ({reason})", entry.provider))
    }

    pub fn sandbox_refusal(&self, providers: &[ProviderEntry]) -> Option<String> {
        let entry = self.provider_entry(providers)?;
        let reason = entry.sandbox_mode_refusal(self.sandbox_mode()?)?;

        Some(format!("not offered by {} ({reason})", entry.provider))
    }

    /// The request as the fields currently read.
    pub fn resolved(&self, providers: &[ProviderEntry]) -> StartRequest {
        let mut request = self.request.clone();

        request.provider = providers
            .get(self.provider)
            .map(|entry| entry.provider.clone())
            .unwrap_or_default();

        request.approval_mode = self.approval_mode();
        request.sandbox_mode = self.sandbox_mode();
        request
    }

    fn move_field(&mut self, delta: isize) {
        let fields = self.fields();

        let index = fields
            .iter()
            .position(|field| *field == self.field)
            .unwrap_or(0) as isize;

        let next = (index + delta).rem_euclid(fields.len() as isize) as usize;
        self.field = fields[next];
    }

    fn cycle(&mut self, delta: isize, providers: usize, machines: &[MachineChoice]) {
        match self.field {
            NewField::Plane => {
                self.request.plane = match self.request.plane {
                    Plane::Interactive => Plane::Coding,
                    Plane::Coding => Plane::Interactive,
                };

                // The objective row appears and disappears with the plane; the cursor
                // must not be left pointing at a row that no longer exists.
                if !self.fields().contains(&self.field) {
                    self.field = NewField::Provider;
                }
            }
            NewField::Provider if providers > 0 => {
                // The operator is choosing now, so a providers answer still in flight must
                // not move the cursor out from under them afterwards.
                self.wanted_provider = None;
                self.provider =
                    (self.provider as isize + delta).rem_euclid(providers as isize) as usize;
                self.request.model = None;
            }
            NewField::Machine if !machines.is_empty() => {
                self.machine =
                    (self.machine as isize + delta).rem_euclid(machines.len() as isize) as usize;
                self.request.machine = machines
                    .get(self.machine)
                    .and_then(MachineChoice::wire_name)
                    .unwrap_or_default()
                    .to_string();

                if let Some(local_workspace) = self.inferred_local_workspace.as_ref() {
                    if self.request.machine.is_empty() {
                        self.request.workspace = local_workspace.clone();
                    } else {
                        self.request.workspace.clear();
                    }
                }
            }
            NewField::ApprovalMode => {
                self.approval =
                    (self.approval as isize + delta).rem_euclid(APPROVAL_ROWS as isize) as usize;
            }
            NewField::SandboxMode => {
                self.sandbox =
                    (self.sandbox as isize + delta).rem_euclid(SANDBOX_ROWS as isize) as usize;
            }
            NewField::Worktree => self.request.worktree = !self.request.worktree,
            _ => {}
        }
    }

    pub(super) fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            NewField::Workspace => {
                self.inferred_local_workspace = None;
                Some(&mut self.request.workspace)
            }
            NewField::Model => Some(self.request.model.get_or_insert_with(String::new)),
            NewField::Objective => Some(&mut self.request.objective),
            _ => None,
        }
    }
}

impl App {
    /// `n`: the dialog that starts a session.
    ///
    /// Only on the Sessions tab, because that is where the result appears, and only when
    /// the gateway serves the verb — `hello.methods` is the feature gate (§2.3), and a
    /// read listener advertises the operate verbs it will refuse, so scope is checked too.
    pub(super) fn open_new_session(&mut self) {
        if self.overlay.is_some() {
            return;
        }

        self.select_tab(Tab::Sessions);

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
                    "starting a session mutates the runtime, and this listener runs at scope \
                     `{}`",
                    self.hello.scope
                ),
                NoticeKind::Warn,
            );
            return;
        }

        // The dialog is about to list providers, and the Sessions tab never polls them.
        self.fetch_providers();

        let workspace_is_inferred = self.config.defaults.workspace.is_none()
            && self
                .launch_dir
                .as_ref()
                .is_some_and(|path| !path.is_empty());
        self.overlay = Some(Overlay::New(Box::new(NewSession::new(
            Plane::Interactive,
            self.default_workspace(),
            workspace_is_inferred,
            &self.config.defaults,
        ))));

        // The list may already be here, in which case the cursor can be placed now rather
        // than on the next answer.
        self.place_default_provider();
    }

    /// The workspace the `n` dialog and the settings overlay start from.
    ///
    /// A stored default first — it is the one the operator wrote down — then the directory
    /// this client was launched in, which is a good guess and a bad assumption. Both are
    /// prefilled and editable; neither is sent unless it is still there when start is
    /// pressed.
    pub(super) fn default_workspace(&self) -> String {
        self.config
            .defaults
            .workspace
            .clone()
            .or_else(|| self.launch_dir.clone())
            .unwrap_or_default()
    }

    /// Points whichever picker is open at the provider the config names.
    ///
    /// Called both when a dialog opens and when a providers answer lands, because the two
    /// can happen in either order and the cursor has to end up in the same place either
    /// way.
    pub(super) fn place_default_provider(&mut self) {
        let providers = self.providers.value.clone().unwrap_or_default();
        let stored = self.config.defaults.provider.clone();

        let unserved = match self.overlay.as_mut() {
            Some(Overlay::New(dialog)) => dialog.place_provider(&providers),
            Some(Overlay::Settings(settings)) => {
                let choices = provider_choices(&providers, stored.as_deref());
                settings.place_provider(&choices);
                None
            }
            _ => None,
        };

        if let Some(name) = unserved {
            // Said rather than silently ignored: a default that does not exist here is the
            // operator's to know about, and the list on screen is what this runtime does
            // serve.
            self.inform(
                format!(
                    "the default provider {name:?} is not one this runtime reports; the list \
                     here is what it does serve"
                ),
                NoticeKind::Warn,
            );
        }
    }

    /// Asks for the provider list if this connection has not got one yet.
    pub(super) fn fetch_providers(&mut self) {
        if self.providers.value.is_some() || self.providers.pending {
            return;
        }

        self.providers.started();
        self.issue(Call::new(Tag::Providers, "runtime.providers", json!({})));
    }

    pub(super) fn new_session_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let providers = self
            .providers
            .value
            .as_ref()
            .map(Vec::len)
            .unwrap_or_default();
        let machines = self.machine_choices();

        let Some(Overlay::New(dialog)) = self.overlay.as_mut() else {
            return;
        };

        // A dialog whose start is in flight takes no edits: the parameters that produced
        // the request are the ones its answer is about.
        if dialog.pending {
            if matches!(key.code, KeyCode::Esc) {
                dialog.error = Some(
                    "start is still in flight; wait for its answer before closing this form"
                        .to_string(),
                );
            }

            return;
        }

        if dialog.reconciling {
            match key.code {
                KeyCode::Tab | KeyCode::Down => dialog.move_field(1),
                KeyCode::BackTab | KeyCode::Up => dialog.move_field(-1),
                KeyCode::Enter if dialog.field == NewField::Start => self.submit_new_session(),
                _ => {
                    dialog.error = Some(format!(
                        "session {} may already exist; choose Start and press Enter to reconcile \
                         that same id before editing or closing",
                        dialog.request.id
                    ));
                }
            }
            return;
        }

        match key.code {
            KeyCode::Esc => self.overlay = None,
            KeyCode::Tab | KeyCode::Down => dialog.move_field(1),
            KeyCode::BackTab | KeyCode::Up => dialog.move_field(-1),
            KeyCode::Left => dialog.cycle(-1, providers, &machines),
            KeyCode::Right => dialog.cycle(1, providers, &machines),
            KeyCode::Backspace => {
                if let Some(text) = dialog.text_mut() {
                    text.pop();
                }
            }
            KeyCode::Enter => {
                if dialog.field == NewField::Start {
                    self.submit_new_session();
                } else {
                    // Enter never starts from a field row. A dialog that could be
                    // submitted by finishing a sentence in the workspace box would start
                    // sessions nobody asked for.
                    dialog.move_field(1);
                }
            }
            // On a picker row this is deliberately nothing: the printable keys that would
            // mean something are the ones the arrows already do, and typing into a list
            // would look like a search box that does not search.
            KeyCode::Char(c) => {
                if let Some(text) = dialog.text_mut() {
                    text.push(c)
                }
            }
            _ => {}
        }
    }

    fn submit_new_session(&mut self) {
        let providers = self.providers.value.clone().unwrap_or_default();

        let Some(Overlay::New(dialog)) = self.overlay.as_mut() else {
            return;
        };

        let request = dialog
            .pending_request
            .clone()
            .unwrap_or_else(|| dialog.resolved(&providers));

        let params = match request.params() {
            Ok(params) => params,
            Err(refusal) => {
                // This client's own refusal, shown on the form that produced it.
                dialog.error = Some(refusal.message());
                return;
            }
        };

        dialog.error = None;
        dialog.pending = true;
        dialog.pending_request = Some(request.clone());
        self.config.defaults.provider = Some(request.provider.clone());
        self.config.defaults.model = request.model.clone();
        self.save_pending = true;

        let plane = request.plane;

        // `interactive.start` and `coding.start` declare a 120s gateway ceiling: provider
        // readiness is legitimately unbounded upstream and this is the one call that
        // waits for it.
        self.issue(
            Call::new(
                Tag::Start {
                    plane,
                    id: request.id.clone(),
                },
                request.method(),
                params,
            )
            .with_timeout(START_TIMEOUT),
        );
    }

    /// A session this client just created: watch it, focus it, and open the composer so
    /// the next thing typed is the first message.
    pub(super) fn started(&mut self, plane: Plane, started: StartedRef) {
        if self.refuse_owner_conflict(plane, &started.id) {
            return;
        }

        let start_failure = started.start_failure.clone();

        self.overlay = None;
        self.home_pending = false;
        self.home_error = None;
        self.home_draft.accept_submission();

        // The lists are polled, and waiting up to three seconds for the row to appear
        // under a session the operator is already looking at reads as a bug.
        self.sessions.interactive.invalidate();
        self.sessions.coding.invalidate();

        self.open_session_on(plane, started.id.clone(), started.node.clone());

        // This exact request exists and is addressable, but its coordinator recorded a
        // readiness failure. Open that durable record and keep any home prompt as a fresh,
        // definitely-not-dispatched draft. Treating the typed result as an ordinary ready
        // reference would immediately send into a terminal session; treating it as an
        // error would trap the caller in same-id reconciliation despite a known outcome.
        if let Some(failure) = start_failure {
            if let Some(first_message) = self.first_message.take() {
                self.restore_refused_first_message(
                    plane,
                    &started.id,
                    first_message.input,
                    ComposerVerb::Message,
                );
            }

            self.inform(
                format!(
                    "created {} on the {plane} plane, but it did not become ready: {failure}. \
                     The durable session is open; no first message was dispatched.",
                    started.id
                ),
                NoticeKind::Error,
            );
            return;
        }

        // The quick-start screen's prompt. Sent here rather than beside the start, because
        // until this answer arrived there was no session to send it to — the same order
        // `ouro new -m` uses, and for the same reason: `*.start` waits for provider
        // readiness before it answers, so the session is ready to take this.
        if let Some(first_message) = self.first_message.take() {
            let method = plane.method("send_message");

            if self.hello.serves(&method) {
                if let Some(composer) = self.sessions.composer.as_mut() {
                    composer.restore_reconciliation(
                        &first_message.input,
                        &first_message.turn_id,
                        &self.completion_catalog,
                    );
                }
                self.remember_composer_history();
                let submission_sequence = self.next_composer_submission_sequence();
                self.sessions.mark_reply_pending(plane, &started.id);
                let params = self.routed_session_params(
                    plane,
                    &started.id,
                    json!({
                        "id": started.id,
                        "input": first_message.input,
                        "turn_id": first_message.turn_id
                    }),
                );
                self.issue(Call::new(
                    Tag::FirstMessage {
                        plane,
                        id: started.id.clone(),
                        turn_id: first_message.turn_id.clone(),
                        input: first_message.input.clone(),
                        submission_sequence,
                    },
                    method,
                    params,
                ));
                // The first prompt of a session is a prompt: it is the one that teaches
                // the most, and it is the one the coding home's tips were beside.
                self.count_prompt();
            } else {
                if let Some(composer) = self.sessions.composer.as_mut() {
                    composer.editor.clear_text();
                    composer
                        .editor
                        .paste(&first_message.input, &self.completion_catalog);
                    composer.user_changed_draft();
                }
                self.remember_composer_history();
                // The session exists and the message does not. Saying which is the only
                // honest answer; the composer below is where it can be retyped.
                self.inform(
                    format!(
                        "{} started, but this gateway does not serve {method}",
                        started.id
                    ),
                    NoticeKind::Warn,
                );

                self.restore_refused_first_message(
                    plane,
                    &started.id,
                    first_message.input,
                    ComposerVerb::Message,
                );

                return;
            }
        }

        self.inform(
            format!("started {} on the {plane} plane", started.id),
            NoticeKind::Info,
        );
    }

    pub(super) fn accept_first_message(&mut self, plane: Plane, id: &str, turn_id: &str) {
        self.accept_reconciled_composer_draft(plane, id, turn_id);
        self.settle_pending_reconciliation(plane, id, Some(turn_id));

        if self.sessions.open.as_ref() == Some(&(plane, id.to_string())) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                composer.verb = ComposerVerb::FollowUp;
            }
        }
    }

    pub(super) fn restore_first_message(
        &mut self,
        plane: Plane,
        id: &str,
        input: String,
        turn_id: String,
        submission_sequence: u64,
    ) {
        if plane != Plane::Interactive {
            return;
        }

        let key = (plane, id.to_string());
        let pending = self
            .sessions
            .pending_reconciliations
            .entry(key.clone())
            .or_default();
        if !pending.iter().any(|pending| pending.turn_id == turn_id) {
            pending.push_back(PendingComposerReconciliation {
                // A first message is typed on the coding home, which has no chips: the
                // envelope it replays is the prompt and nothing else.
                kind: PendingReconciliationKind::FirstMessage,
                input: TurnInput::plain(input.clone()),
                turn_id: turn_id.clone(),
                submission_sequence,
            });
            pending
                .make_contiguous()
                .sort_by_key(|pending| pending.submission_sequence);
        }

        if self.sessions.open.as_ref() == Some(&key) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                if composer.editor.is_empty() {
                    composer.restore_reconciliation(&input, &turn_id, &self.completion_catalog);
                    composer.verb = ComposerVerb::Message;
                }
            }
            self.remember_composer_history();
        }
    }

    pub(super) fn restore_refused_first_message(
        &mut self,
        plane: Plane,
        id: &str,
        input: String,
        verb: ComposerVerb,
    ) {
        if plane != Plane::Interactive {
            return;
        }

        let key = (plane, id.to_string());
        if self.sessions.open.as_ref() == Some(&key) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                let owned_retry = composer.reconciliation_owner.take().is_some();
                let restored = composer.editor.is_empty();
                if restored {
                    composer.editor.paste(&input, &self.completion_catalog);
                    composer.user_changed_draft();
                }
                if restored || owned_retry {
                    composer.verb = verb;
                }
            }
            self.remember_composer_history();
        } else {
            match self.sessions.composer_drafts.entry(key) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(SavedComposerDraft {
                        input,
                        generation: 1,
                        reconciliation_owner: None,
                        attachments: Vec::new(),
                        reasoning_effort: None,
                    });
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().reconciliation_owner = None;
                }
            }
        }
    }

    pub(super) fn restore_composer_submission(
        &mut self,
        plane: Plane,
        id: &str,
        input: TurnInput,
        retry_turn_id: Option<String>,
        verb: ComposerVerb,
        submission_sequence: u64,
    ) -> ComposerRestoreDisposition {
        if plane != Plane::Interactive {
            return ComposerRestoreDisposition::NewerDraftPreserved;
        }

        let key = (plane, id.to_string());
        let has_reconciliation = retry_turn_id.is_some();
        let reconciliation_turn_id = retry_turn_id.clone();

        if let Some(turn_id) = retry_turn_id {
            let pending = self
                .sessions
                .pending_reconciliations
                .entry(key.clone())
                .or_default();
            if !pending.iter().any(|pending| pending.turn_id == turn_id) {
                pending.push_back(PendingComposerReconciliation {
                    kind: PendingReconciliationKind::Composer(verb),
                    input: input.clone(),
                    turn_id: turn_id.clone(),
                    submission_sequence,
                });
                pending
                    .make_contiguous()
                    .sort_by_key(|pending| pending.submission_sequence);
            }
        }

        // A reply can arrive after the operator began typing the next thought. Keep that
        // newer draft intact. The stable-id queue above lives on the session, so switching
        // away before this answer or closing/reopening the composer cannot discard it.
        if self.sessions.open.as_ref() == Some(&key) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                if composer.editor.is_empty() {
                    if let Some(turn_id) = reconciliation_turn_id.as_deref() {
                        composer.restore_reconciliation(
                            input.prompt(),
                            turn_id,
                            &self.completion_catalog,
                        );
                    } else {
                        composer
                            .editor
                            .paste(input.prompt(), &self.completion_catalog);
                        composer.user_changed_draft();
                    }
                    // The chips come back with the text: a restored draft that had lost
                    // them would send a different turn from the one that was refused.
                    composer.attachments = input.attachments.clone();
                    composer.reasoning_effort = input.reasoning_effort;
                    composer.verb = verb;
                    self.remember_composer_history();
                    return ComposerRestoreDisposition::Restored;
                }

                self.remember_composer_history();
                return if has_reconciliation {
                    ComposerRestoreDisposition::ReconciliationQueued
                } else {
                    ComposerRestoreDisposition::NewerDraftPreserved
                };
            }
        }

        // A known refusal has no reconciliation id, but its exact text is still useful on
        // return to this session. Never replace a newer draft saved during the switch.
        if !has_reconciliation {
            return match self.sessions.composer_drafts.entry(key) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(SavedComposerDraft {
                        input: input.prompt.clone(),
                        generation: 1,
                        reconciliation_owner: None,
                        attachments: input.attachments.clone(),
                        reasoning_effort: input.reasoning_effort,
                    });
                    ComposerRestoreDisposition::SavedForReopen
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    ComposerRestoreDisposition::NewerDraftPreserved
                }
            };
        }

        ComposerRestoreDisposition::ReconciliationQueued
    }

    pub(super) fn start_failed(&mut self, plane: Plane, id: &str, error: ClientError) {
        let message = match &error {
            ClientError::Rpc(rpc) => model::refusal(rpc),
            other => other.to_string(),
        };
        let outcome_unknown = model::start_outcome_unknown(&error);

        if let Some(Overlay::New(dialog)) = self.overlay.as_mut() {
            if dialog
                .pending_request
                .as_ref()
                .is_some_and(|request| request.id == id && request.plane == plane)
            {
                dialog.pending = false;
                if outcome_unknown {
                    dialog.reconciling = true;
                    dialog.error = Some(format!(
                        "{message}. Session {id} may already exist; choose Start and press Enter \
                         to reconcile this exact id. Editing and closing stay locked until then."
                    ));
                } else {
                    dialog.reconciling = false;
                    dialog.pending_request = None;
                    dialog.request.id = new_session_id();
                    dialog.error = Some(message);
                }
                return;
            }
        }

        if self
            .first_message
            .as_ref()
            .is_some_and(|pending| pending.start.id == id && pending.start.plane == plane)
        {
            self.home_pending = false;
            if outcome_unknown {
                if let Some(pending) = self.first_message.as_mut() {
                    pending.start_outcome_unknown = true;
                }
                self.home_error = Some(format!(
                    "{message}. Session {id} may already exist; press Enter to reconcile the \
                     same id before changing this prompt."
                ));
            } else {
                // A definite refusal means this id cannot become a session. Keep the
                // visible draft, but the next submission mints a fresh start identity.
                self.first_message = None;
                self.home_error = Some(message);
            }
            return;
        }

        if self
            .pending_background_start
            .as_ref()
            .is_some_and(|request| request.id == id && request.plane == plane)
        {
            if outcome_unknown {
                self.inform(
                    format!(
                        "{message}. Writable session {id} may already exist; run /write again to \
                         reconcile the same id."
                    ),
                    NoticeKind::Error,
                );
            } else {
                self.pending_background_start = None;
                self.inform(
                    format!("starting writable session {id} was refused: {message}"),
                    NoticeKind::Error,
                );
            }
            return;
        }

        if self.tab == Tab::Sessions && self.sessions.open.is_none() {
            self.home_pending = false;
            self.home_error = Some(format!("start {id}: {message}"));
        } else {
            self.inform(
                format!("starting session {id} failed: {message}"),
                NoticeKind::Error,
            );
        }
    }
}
