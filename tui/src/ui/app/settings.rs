use super::*;

/// One editable row of the settings overlay. The facts above them are not rows: they are
/// what the runtime reported, and nothing here can change them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    Machines,
    Provider,
    Workspace,
    ApprovalMode,
    SandboxMode,
    Save,
}

impl SettingsField {
    pub const ALL: [SettingsField; 6] = [
        SettingsField::Machines,
        SettingsField::Provider,
        SettingsField::Workspace,
        SettingsField::ApprovalMode,
        SettingsField::SandboxMode,
        SettingsField::Save,
    ];
}

/// The `,` overlay: what the runtime says, and what this client remembers.
///
/// The two halves are labelled separately and never mixed. Above the rows are facts read
/// off the handshake and this process's own paths; the rows themselves are the config
/// file's, and saving is the only thing that writes one. A settings screen that showed a
/// stored provider beside a node name as if both came from the same place would be this
/// client claiming the runtime confirmed a preference it has never been told about.
#[derive(Debug)]
pub struct Settings {
    pub field: SettingsField,
    /// Index into [`provider_choices`], where 0 is "unset".
    pub provider: usize,
    pub workspace: String,
    pub approval: usize,
    pub sandbox: usize,
    /// The stored provider, until the probe list arrives and the cursor can be put on it.
    wanted_provider: Option<String>,
    /// Whether anything has been typed or cycled, so closing can say what it discards.
    pub edited: bool,
}

impl Settings {
    pub(super) fn place_provider(&mut self, choices: &[ProviderChoice]) {
        let Some(wanted) = self.wanted_provider.clone() else {
            return;
        };

        // One row is always present, so a list of one is a list that has not arrived.
        if choices.len() < 2 {
            return;
        }

        self.wanted_provider = None;

        // `provider_choices` appends an unserved stored default rather than dropping it,
        // so a stored name always has a row here — which is what makes this a `position`
        // that cannot silently land on "unset".
        if let Some(index) = choices
            .iter()
            .position(|choice| choice.name() == Some(wanted.as_str()))
        {
            self.provider = index;
        }
    }

    pub fn approval_label(&self) -> String {
        approval_label(self.approval)
    }

    pub fn sandbox_label(&self) -> String {
        sandbox_label(self.sandbox)
    }

    pub(super) fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            SettingsField::Workspace => Some(&mut self.workspace),
            _ => None,
        }
    }

    fn move_field(&mut self, delta: isize) {
        let index = SettingsField::ALL
            .iter()
            .position(|field| *field == self.field)
            .unwrap_or(0) as isize;

        let next = (index + delta).rem_euclid(SettingsField::ALL.len() as isize) as usize;
        self.field = SettingsField::ALL[next];
    }

    fn cycle(&mut self, delta: isize, providers: usize) {
        match self.field {
            SettingsField::Provider if providers > 0 => {
                self.wanted_provider = None;
                self.edited = true;
                self.provider =
                    (self.provider as isize + delta).rem_euclid(providers as isize) as usize;
            }
            SettingsField::ApprovalMode => {
                self.edited = true;
                self.approval =
                    (self.approval as isize + delta).rem_euclid(APPROVAL_ROWS as isize) as usize;
            }
            SettingsField::SandboxMode => {
                self.edited = true;
                self.sandbox =
                    (self.sandbox as isize + delta).rem_euclid(SANDBOX_ROWS as isize) as usize;
            }
            _ => {}
        }
    }
}

impl App {
    /// `,`: this client's preferences, from any tab.
    ///
    /// No scope check and no `hello.methods` gate, unlike `n`: writing a file this process
    /// owns is not a verb the gateway serves, and a `read` listener is no reason to stop
    /// someone recording which provider they prefer.
    pub(super) fn open_settings(&mut self) {
        if self.overlay.is_some() {
            return;
        }

        // The picker lists what the runtime reports, and most tabs never ask for it.
        self.fetch_providers();
        self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);

        self.overlay = Some(Overlay::Settings(Box::new(Settings {
            field: SettingsField::Machines,
            provider: 0,
            workspace: self.default_workspace(),
            approval: approval_index(self.config.defaults.approval_mode()),
            sandbox: sandbox_index(self.config.defaults.sandbox_mode()),
            wanted_provider: self.config.defaults.provider.clone(),
            edited: false,
        })));

        self.place_default_provider();
    }

    pub(super) fn settings_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let choices = provider_choices(
            self.providers.value.as_deref().unwrap_or_default(),
            self.config.defaults.provider.as_deref(),
        );

        let Some(Overlay::Settings(settings)) = self.overlay.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Esc => self.overlay = None,
            KeyCode::Tab | KeyCode::Down => settings.move_field(1),
            KeyCode::BackTab | KeyCode::Up => settings.move_field(-1),
            KeyCode::Left => settings.cycle(-1, choices.len()),
            KeyCode::Right => settings.cycle(1, choices.len()),
            KeyCode::Backspace => {
                if let Some(text) = settings.text_mut() {
                    text.pop();
                    settings.edited = true;
                }
            }
            KeyCode::Enter => {
                match settings.field {
                    SettingsField::Machines => self.open_machines(),
                    SettingsField::Save => self.save_settings(),
                    _ => {
                        // Enter never saves from a field row, for the same reason it never
                        // starts a session from one: finishing a sentence in a text box is not
                        // a decision to write a file.
                        settings.move_field(1);
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Some(text) = settings.text_mut() {
                    text.push(c);
                    settings.edited = true;
                }
            }
            _ => {}
        }
    }

    /// Takes the rows as they read and asks the driver to write them.
    ///
    /// The file is rewritten whole from [`Config`], so what lands on disk is exactly what
    /// the overlay showed — no merge with a file that may have changed underneath, which
    /// would be this client guessing which of two answers the operator meant.
    fn save_settings(&mut self) {
        let choices = provider_choices(
            self.providers.value.as_deref().unwrap_or_default(),
            self.config.defaults.provider.as_deref(),
        );

        let Some(Overlay::Settings(settings)) = self.overlay.take() else {
            return;
        };

        self.config.defaults.provider = choices
            .get(settings.provider)
            .and_then(ProviderChoice::name)
            .map(str::to_string);

        // A blank box is "no default", not `""`: the same statement an empty workspace
        // makes in the start dialog.
        let workspace = settings.workspace.trim();
        self.config.defaults.workspace = (!workspace.is_empty()).then(|| workspace.to_string());

        self.config.defaults.approval_mode =
            approval_at(settings.approval).map(|mode| mode.as_str().to_string());

        self.config.defaults.sandbox_mode =
            sandbox_at(settings.sandbox).map(|mode| mode.as_str().to_string());

        self.save_pending = true;
    }
}
