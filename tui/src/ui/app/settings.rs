use super::*;
use crate::model::CredentialStatus;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsSection {
    Connections,
    Defaults,
    Runtime,
    /// T2.10. The `config.toml` sections that decide how this client behaves rather than
    /// what a session is started with.
    Client,
}

/// T2.10. What a provider is called on screen.
///
/// One table, because there were two answers and they disagreed on the same list: the
/// five rows this client knows by name were capitalised properly and every other
/// credential the runtime reported fell through to `provider.replace('_', " ")`, so
/// `alibaba` and `alibaba cn` sat in a column beside `OpenAI` and `Anthropic` in the
/// runtime's own wire spelling. A wire id is an identifier; a settings list is read by a
/// person deciding which account to connect.
///
/// A provider this build has never heard of still gets a row — the list is the runtime's,
/// not this binary's — and its id is title-cased rather than invented, which is the most
/// this client can honestly do with a name nobody told it how to write.
pub fn provider_name(provider: &str) -> String {
    match provider {
        "openai" => "OpenAI",
        "anthropic" => "Anthropic",
        "xai" => "xAI",
        "alibaba" => "Alibaba",
        "alibaba_cn" | "alibaba-cn" => "Alibaba (CN)",
        "openai_codex" => "ChatGPT",
        "grok" => "Grok",
        unknown => return title_case(unknown),
    }
    .to_string()
}

/// `some_provider` as `Some Provider`: the id, made readable, and nothing added to it.
fn title_case(provider: &str) -> String {
    provider
        .split(['_', '-'])
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut characters = word.chars();
            match characters.next() {
                Some(first) => first.to_uppercase().collect::<String>() + characters.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub struct CredentialEditor {
    pub provider: String,
    pub key: Zeroizing<String>,
    pub workspace: String,
    pub field: usize,
    pub pending: bool,
    pub error: Option<String>,
}

impl std::fmt::Debug for CredentialEditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialEditor")
            .field("provider", &self.provider)
            .field("key", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct SettingsConnection {
    pub provider: String,
    pub name: String,
    pub subscription: bool,
    pub credential: Option<CredentialStatus>,
    pub stale: bool,
}

impl SettingsConnection {
    pub fn state(&self) -> &'static str {
        if self.stale {
            return "Status unavailable";
        }
        match self.credential.as_ref() {
            Some(c) if c.credential_state.as_deref() == Some("invalid") => "Needs attention",
            Some(c) if c.credential_state.as_deref() == Some("unavailable") => "Status unavailable",
            Some(c) if c.present == Some(true) => {
                if self.subscription {
                    "Connected locally"
                } else {
                    "Key configured"
                }
            }
            Some(c) if c.present == Some(false) => {
                if self.subscription {
                    "Not connected"
                } else {
                    "Not configured"
                }
            }
            _ => "Not reported",
        }
    }
    pub fn source(&self) -> &str {
        match self.credential.as_ref().and_then(|c| c.source.as_deref()) {
            Some("environment") => "Environment",
            Some("stored") => {
                if self.subscription {
                    "Local sign-in"
                } else {
                    "Private store"
                }
            }
            _ => "—",
        }
    }
    pub fn env(&self) -> &str {
        self.credential
            .as_ref()
            .map(|c| c.env.as_str())
            .unwrap_or(match self.provider.as_str() {
                "grok" => "OUROBOROS_GROK_AUTH_FILE",
                "openai_codex" => "OUROBOROS_OAUTH_FILE",
                "anthropic" => "ANTHROPIC_API_KEY",
                "xai" => "XAI_API_KEY",
                "openai" => "OPENAI_API_KEY",
                _ => "provider API key environment variable",
            })
    }
}

/// One editable row of the settings overlay. The facts above them are not rows: they are
/// what the runtime reported, and nothing here can change them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    Workspace,
    ApprovalMode,
    SandboxMode,
    Save,
}

impl SettingsField {
    pub const ALL: [SettingsField; 4] = [
        SettingsField::Workspace,
        SettingsField::ApprovalMode,
        SettingsField::SandboxMode,
        SettingsField::Save,
    ];
}

/// T2.10. One editable row of the `F4 Client` section.
///
/// The review counted eight `config.toml` sections with no UI at all. Four of them are
/// settings about *this client* that a person can reasonably want to change from inside
/// it, and they are these rows. The other four are not here on purpose, and the section
/// says so rather than leaving them to be discovered as missing:
///
/// * `[keys]` and `[statusline]` are a grammar and a shell command — a chord editor and a
///   command box are their own designs, and half of one would be worse than the pointer
///   to the file that this draws instead.
/// * `[theme]` has the picker (T2.9), which can preview; a cycler row here could not.
/// * `[location]` is the `f5` dialog, which browses the runtime's filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientField {
    /// `[terminal] mouse`.
    Mouse,
    /// `[accessibility] screen_reader`.
    ScreenReader,
    /// `[accessibility] reduced_motion`.
    ReducedMotion,
    /// `[notifications] mode`: `auto` | `bell` | `osc9` | `off`.
    NotifyMode,
    /// `[notifications] when`: `unfocused` | `always`.
    NotifyWhen,
    /// `[budget] max_cost_usd`, typed rather than cycled: it is a number, not a choice.
    Budget,
    Save,
}

impl ClientField {
    pub const ALL: [ClientField; 7] = [
        ClientField::Mouse,
        ClientField::ScreenReader,
        ClientField::ReducedMotion,
        ClientField::NotifyMode,
        ClientField::NotifyWhen,
        ClientField::Budget,
        ClientField::Save,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Mouse => "mouse",
            Self::ScreenReader => "screen reader",
            Self::ReducedMotion => "reduced motion",
            Self::NotifyMode => "notify",
            Self::NotifyWhen => "notify when",
            Self::Budget => "max cost",
            Self::Save => "",
        }
    }

    /// The `config.toml` section each row writes, so a reader can find it in the file.
    pub fn section(self) -> &'static str {
        match self {
            Self::Mouse => "[terminal]",
            Self::ScreenReader | Self::ReducedMotion => "[accessibility]",
            Self::NotifyMode | Self::NotifyWhen => "[notifications]",
            Self::Budget => "[budget]",
            Self::Save => "",
        }
    }
}

/// The `,` overlay keeps runtime-owned connections separate from local client defaults.
/// Only an explicit save writes a preference or submits a private credential update.
#[derive(Debug)]
pub struct Settings {
    pub field: SettingsField,
    pub section: SettingsSection,
    pub connection: usize,
    pub editor: Option<CredentialEditor>,
    pub message: Option<String>,
    pub workspace: String,
    pub approval: usize,
    pub sandbox: usize,
    /// Whether anything has been typed or cycled, so closing can say what it discards.
    pub edited: bool,
    // T2.10. The `F4 Client` rows, read out of `config.toml` when the overlay opened and
    // written back only by its own `[ save ]` — the same discipline `F2 Defaults` has, and
    // for the same reason: closing an overlay is not a decision to write a file.
    pub client: ClientField,
    pub mouse: bool,
    pub screen_reader: bool,
    pub reduced_motion: bool,
    pub notify_mode: usize,
    pub notify_when: usize,
    /// As typed. Kept as text rather than a parsed `f64` so a half-typed `0.` is not
    /// silently turned into something else while it is being typed, and so an unreadable
    /// entry can be refused by name instead of rounded to zero.
    pub budget: String,
}

impl Settings {
    pub fn approval_label(&self) -> String {
        approval_label(self.approval)
    }

    pub fn sandbox_label(&self) -> String {
        sandbox_label(self.sandbox)
    }

    pub(super) fn text_mut(&mut self) -> Option<&mut String> {
        if let Some(editor) = self.editor.as_mut() {
            if editor.pending {
                return None;
            }
            return match editor.field {
                0 => Some(&mut editor.key),
                1 if editor.provider == "anthropic" => Some(&mut editor.workspace),
                _ => None,
            };
        }
        // T2.10. The budget row is the section's only text field, for the same reason the
        // workspace row is `F2`'s: it is a value, not a choice between named ones.
        if self.section == SettingsSection::Client {
            return match self.client {
                ClientField::Budget => Some(&mut self.budget),
                _cycled => None,
            };
        }
        if self.section != SettingsSection::Defaults {
            return None;
        }
        match self.field {
            SettingsField::Workspace => Some(&mut self.workspace),
            _ => None,
        }
    }

    fn move_client(&mut self, delta: isize) {
        let index = ClientField::ALL
            .iter()
            .position(|field| *field == self.client)
            .unwrap_or(0) as isize;

        let next = (index + delta).rem_euclid(ClientField::ALL.len() as isize) as usize;
        self.client = ClientField::ALL[next];
    }

    /// `←`/`→` on a `F4` row. The booleans flip either way — there are two states and
    /// both arrows reach the other one — and the two enums step through their own lists.
    fn cycle_client(&mut self, delta: isize) {
        self.edited = true;

        match self.client {
            ClientField::Mouse => self.mouse = !self.mouse,
            ClientField::ScreenReader => self.screen_reader = !self.screen_reader,
            ClientField::ReducedMotion => self.reduced_motion = !self.reduced_motion,
            ClientField::NotifyMode => {
                let rows = crate::config::NotifyMode::ALL.len() as isize;
                self.notify_mode = (self.notify_mode as isize + delta).rem_euclid(rows) as usize;
            }
            ClientField::NotifyWhen => {
                let rows = crate::config::NotifyWhen::ALL.len() as isize;
                self.notify_when = (self.notify_when as isize + delta).rem_euclid(rows) as usize;
            }
            // A number is typed, and `[ save ]` is not a value.
            ClientField::Budget | ClientField::Save => self.edited = false,
        }
    }

    /// What the `F4` rows read as. Drawn from this struct rather than from the live
    /// process flags: these are the file's answers, which is what `[ save ]` writes.
    pub fn client_value(&self, field: ClientField) -> String {
        match field {
            ClientField::Mouse => yes_no(self.mouse).to_string(),
            ClientField::ScreenReader => yes_no(self.screen_reader).to_string(),
            ClientField::ReducedMotion => yes_no(self.reduced_motion).to_string(),
            ClientField::NotifyMode => crate::config::NotifyMode::ALL
                .get(self.notify_mode)
                .copied()
                .unwrap_or_default()
                .as_str()
                .to_string(),
            ClientField::NotifyWhen => crate::config::NotifyWhen::ALL
                .get(self.notify_when)
                .copied()
                .unwrap_or_default()
                .as_str()
                .to_string(),
            // Absent, not zero: no ceiling and a ceiling of nothing are different
            // statements, and `[budget]` treats the second as the first.
            ClientField::Budget => match self.budget.trim() {
                "" => "unset — no warning".to_string(),
                typed => format!("${typed}"),
            },
            ClientField::Save => "[ save ]".to_string(),
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

    fn cycle(&mut self, delta: isize) {
        match self.field {
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

fn yes_no(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

impl App {
    /// `,`: this client's preferences, from any tab.
    ///
    /// No scope check and no `hello.methods` gate, unlike `n`: writing a file this process
    /// owns is not a verb the gateway serves, and a `read` listener is no reason to stop
    /// someone recording which workspace they prefer.
    pub(super) fn open_settings(&mut self) {
        if self.overlay.is_some() {
            return;
        }

        // The facts above the rows include the provider probe, and most tabs never ask
        // for it.
        self.refresh_settings_connections();
        self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);

        self.overlay = Some(Overlay::Settings(Box::new(Settings {
            field: SettingsField::Workspace,
            section: SettingsSection::Connections,
            connection: 0,
            editor: None,
            message: None,
            workspace: self.default_workspace(),
            approval: approval_index(self.config.defaults.approval_mode()),
            sandbox: sandbox_index(self.config.defaults.sandbox_mode()),
            edited: false,
            // T2.10. Read from the file, not from the process-wide accessibility flags:
            // those are the *resolved* answer, which an environment variable or a command
            // line flag can have decided, and a row that showed the resolution while
            // editing the file would write back a setting nobody chose.
            client: ClientField::Mouse,
            mouse: self.config.terminal.mouse,
            screen_reader: self.config.accessibility.screen_reader,
            reduced_motion: self.config.accessibility.reduced_motion,
            notify_mode: crate::config::NotifyMode::ALL
                .iter()
                .position(|mode| *mode == self.config.notifications.mode())
                .unwrap_or(0),
            notify_when: crate::config::NotifyWhen::ALL
                .iter()
                .position(|when| *when == self.config.notifications.when())
                .unwrap_or(0),
            budget: self
                .config
                .budget
                .max_cost_usd
                .map(|limit| format!("{limit}"))
                .unwrap_or_default(),
        })));
    }

    pub(super) fn settings_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let Some(Overlay::Settings(settings)) = self.overlay.as_mut() else {
            return;
        };

        if settings.editor.is_some() {
            self.settings_credential_key(key);
            return;
        }
        match key.code {
            KeyCode::F(1) => settings.section = SettingsSection::Connections,
            KeyCode::F(2) => settings.section = SettingsSection::Defaults,
            KeyCode::F(3) => settings.section = SettingsSection::Runtime,
            KeyCode::F(4) => settings.section = SettingsSection::Client,
            _ => {}
        }
        if settings.section == SettingsSection::Connections {
            self.settings_connection_key(key);
            return;
        }
        if settings.section == SettingsSection::Client {
            self.settings_client_key(key);
            return;
        }
        if settings.section == SettingsSection::Runtime {
            match key.code {
                KeyCode::Esc => self.close_overlay(),
                // The proposal's Devices link, from the Runtime section it names. It
                // replaces this overlay rather than stacking on it: two full pages over
                // each other is a screen an operator cannot get out of predictably.
                KeyCode::Char('d') if self.devices_offered() => self.open_devices(),
                _other => {}
            }
            return;
        }

        match key.code {
            KeyCode::Esc => self.close_overlay(),
            KeyCode::Tab | KeyCode::Down => settings.move_field(1),
            KeyCode::BackTab | KeyCode::Up => settings.move_field(-1),
            KeyCode::Left => settings.cycle(-1),
            KeyCode::Right => settings.cycle(1),
            KeyCode::Backspace => {
                if let Some(text) = settings.text_mut() {
                    text.pop();
                    settings.edited = true;
                }
            }
            KeyCode::Enter => {
                match settings.field {
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

    /// T2.10. The `F4 Client` rows, with the same discipline `F2` has: `Enter` on a field
    /// moves, `Enter` on `[ save ]` writes, `Esc` closes and writes nothing.
    fn settings_client_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let Some(Overlay::Settings(settings)) = self.overlay.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Esc => self.close_overlay(),
            KeyCode::Tab | KeyCode::Down => settings.move_client(1),
            KeyCode::BackTab | KeyCode::Up => settings.move_client(-1),
            KeyCode::Left => settings.cycle_client(-1),
            KeyCode::Right => settings.cycle_client(1),
            KeyCode::Backspace => {
                if let Some(text) = settings.text_mut() {
                    text.pop();
                    settings.edited = true;
                }
            }
            KeyCode::Enter => match settings.client {
                ClientField::Save => self.save_settings(),
                // Enter on a field row moves, exactly as it does on `F2`: finishing a
                // sentence in a text box is not a decision to write a file.
                _field => settings.move_client(1),
            },
            // A cycler row takes the space bar as "change this", which is the key a
            // checkbox answers to everywhere else. The budget row takes it as a character,
            // because it is one.
            KeyCode::Char(' ') if settings.text_mut().is_none() => settings.cycle_client(1),
            KeyCode::Char(c) => {
                if let Some(text) = settings.text_mut() {
                    text.push(c);
                    settings.edited = true;
                }
            }
            _ => {}
        }
    }

    pub fn settings_connections(&self) -> Vec<SettingsConnection> {
        let credentials: Vec<CredentialStatus> = self
            .providers
            .value
            .as_ref()
            .into_iter()
            .flatten()
            .filter(|entry| entry.provider == "native")
            .filter_map(|entry| entry.status.as_ref())
            .flat_map(|status| status.details.credentials.iter().cloned())
            .collect();
        let mut rows = Vec::new();
        for (provider, subscription) in [
            ("openai_codex", true),
            ("grok", true),
            ("openai", false),
            ("anthropic", false),
            ("xai", false),
        ] {
            let credential = credentials.iter().find(|c| c.provider == provider).cloned();
            rows.push(SettingsConnection {
                provider: provider.into(),
                // T2.10. From the table, like every other row, so the five this client
                // knows and the ones the runtime adds cannot be capitalised differently.
                name: provider_name(provider),
                subscription,
                stale: self.providers.error.is_some()
                    || (self.providers.value.is_some() && credential.is_none()),
                credential,
            });
        }
        for credential in credentials {
            if !rows.iter().any(|row| row.provider == credential.provider) {
                rows.push(SettingsConnection {
                    name: provider_name(&credential.provider),
                    provider: credential.provider.clone(),
                    subscription: false,
                    credential: Some(credential),
                    stale: self.providers.error.is_some(),
                });
            }
        }
        rows
    }

    pub(super) fn settings_connection_identity(&self) -> Option<(String, String)> {
        let Some(Overlay::Settings(settings)) = &self.overlay else {
            return None;
        };
        self.settings_connections()
            .get(settings.connection)
            .map(|row| (row.provider.clone(), row.env().to_string()))
    }

    pub(super) fn reconcile_settings_connection(&mut self, previous: Option<(String, String)>) {
        let rows = self.settings_connections();
        if let Some(Overlay::Settings(settings)) = &mut self.overlay {
            settings.connection = previous
                .and_then(|(provider, env)| {
                    rows.iter()
                        .position(|row| row.provider == provider && row.env() == env)
                })
                .unwrap_or_else(|| settings.connection.min(rows.len().saturating_sub(1)));
        }
    }

    pub(super) fn refresh_settings_connections(&mut self) {
        if self.providers.pending {
            self.settings_refresh_queued = true;
            return;
        }
        self.settings_refresh_queued = false;
        self.providers.started();
        self.issue(Call::new(Tag::Providers, "runtime.providers", json!({})));
    }

    fn settings_connection_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        let rows = self.settings_connections();
        let Some(Overlay::Settings(settings)) = self.overlay.as_mut() else {
            return;
        };
        settings.connection = settings.connection.min(rows.len().saturating_sub(1));
        match key.code {
            KeyCode::Esc => self.close_overlay(),
            KeyCode::Up | KeyCode::BackTab => {
                settings.connection = settings.connection.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Tab => {
                settings.connection = (settings.connection + 1).min(rows.len().saturating_sub(1))
            }
            KeyCode::Char('r') => self.refresh_settings_connections(),
            KeyCode::Enter => {
                let Some(row) = rows.get(settings.connection) else {
                    return;
                };
                if row.provider == "openai_codex" {
                    if !self.config.location.machine.is_empty() {
                        settings.message = Some("These connections belong to the attached runtime. Select this computer in the Computer menu before connecting ChatGPT.".into());
                    } else if !self.hello.operates() || !self.hello.serves("account.login.start") {
                        settings.message = Some("ChatGPT sign-in requires an operate connection and a runtime with account.login.start.".into());
                    } else {
                        self.settings_return = match self.overlay.take() {
                            Some(Overlay::Settings(s)) => Some(s),
                            _ => None,
                        };
                        self.open_account();
                        if !matches!(self.overlay, Some(Overlay::Account(_))) {
                            self.restore_settings();
                        }
                    }
                    return;
                }
                let method = match row.provider.as_str() {
                    "anthropic" => "credentials.anthropic.set",
                    "xai" => "credentials.xai.set",
                    _ => {
                        settings.message = Some(
                            "Follow the setup instructions below, then press r to refresh status."
                                .into(),
                        );
                        return;
                    }
                };
                if !self.hello.operates() || !self.hello.serves(method) {
                    settings.message = Some("Adding a key requires an operate connection and a runtime that supports this credential method.".into());
                } else if row
                    .credential
                    .as_ref()
                    .is_some_and(|c| c.source.as_deref() == Some("environment"))
                {
                    settings.message = Some(format!("{} is supplied by the runtime environment. Update it there, or unset it before storing a private key.", row.env()));
                } else {
                    settings.editor = Some(CredentialEditor {
                        provider: row.provider.clone(),
                        key: Zeroizing::new(String::new()),
                        workspace: String::new(),
                        field: 0,
                        pending: false,
                        error: None,
                    });
                    settings.message = None;
                }
            }
            _ => {}
        }
    }

    pub(super) fn restore_settings(&mut self) -> bool {
        if let Some(settings) = self.settings_return.take() {
            self.overlay = Some(Overlay::Settings(settings));
            self.refresh_settings_connections();
            true
        } else {
            false
        }
    }

    fn settings_credential_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        let Some(Overlay::Settings(settings)) = self.overlay.as_mut() else {
            return;
        };
        let Some(editor) = settings.editor.as_mut() else {
            return;
        };
        if editor.pending {
            return;
        }
        let last = if editor.provider == "anthropic" { 2 } else { 1 };
        match key.code {
            KeyCode::Esc => settings.editor = None,
            KeyCode::Tab | KeyCode::Down => editor.field = (editor.field + 1) % (last + 1),
            KeyCode::BackTab | KeyCode::Up => editor.field = (editor.field + last) % (last + 1),
            KeyCode::Enter if editor.field == last => {
                let provider = editor.provider.clone();
                let method = if provider == "anthropic" {
                    "credentials.anthropic.set"
                } else {
                    "credentials.xai.set"
                };
                if !self.hello.operates() || !self.hello.serves(method) {
                    editor.error = Some("This connection cannot change credentials.".into());
                    return;
                }
                let mut params = json!({});
                if !editor.key.trim().is_empty() {
                    params["api_key"] = json!(editor.key.trim());
                }
                if provider == "anthropic" && !editor.workspace.trim().is_empty() {
                    params["workspace_id"] = json!(editor.workspace.trim());
                }
                if params.as_object().is_none_or(|p| p.is_empty()) {
                    editor.error = Some(
                        if provider == "anthropic" {
                            "Enter an API key or an Anthropic workspace ID."
                        } else {
                            "Enter an xAI API key."
                        }
                        .into(),
                    );
                    return;
                }
                editor.key.zeroize();
                editor.pending = true;
                editor.error = None;
                self.issue(Call::new(
                    Tag::SettingsCredential { provider },
                    method,
                    params,
                ));
            }
            KeyCode::Enter => editor.field = (editor.field + 1).min(last),
            KeyCode::Backspace => {
                if let Some(text) = settings.text_mut() {
                    text.pop();
                }
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
            {
                if let Some(text) = settings.text_mut() {
                    if text.len() < 16_384 {
                        text.push(c);
                    }
                }
            }
            _ => {}
        }
    }

    pub(super) fn settings_credential_answered(
        &mut self,
        provider: &str,
        result: Result<Value, ClientError>,
    ) {
        if let Some(Overlay::Settings(settings)) = self.overlay.as_mut() {
            if let Some(editor) = settings
                .editor
                .as_mut()
                .filter(|editor| editor.provider == provider && editor.pending)
            {
                match result {
                    Ok(_) => {
                        settings.editor = None;
                        settings.message = Some(
                            "Credentials saved privately on this runtime. Their values are hidden."
                                .into(),
                        );
                    }
                    Err(_) => {
                        editor.pending = false;
                        editor.error = Some("Could not save. Check the runtime connection; re-enter the key to retry.".into());
                    }
                }
            }
        }
        self.refresh_settings_connections();
    }

    /// Takes the rows as they read and asks the driver to write them.
    ///
    /// The file is rewritten whole from [`Config`], so what lands on disk is exactly what
    /// the overlay showed — no merge with a file that may have changed underneath, which
    /// would be this client guessing which of two answers the operator meant.
    fn save_settings(&mut self) {
        let Some(Overlay::Settings(settings)) = self.overlay.take() else {
            return;
        };

        // F3. Validated *before* anything reaches `self.config`. It used to write the four
        // other `F4` rows first and refuse the budget afterwards, so "nothing was saved"
        // was false twice over: reopening the section showed the flipped values, and the
        // next legitimate save — from either section — persisted them. A refusal has to
        // leave the config exactly as it found it, or it is not a refusal.
        //
        // An empty box is "no ceiling", which is what an absent key means. A number this
        // build cannot read is refused rather than rounded: silently storing `0` for
        // `12.5o` would turn a typo into a setting that reads as deliberate.
        let typed_budget = settings.budget.trim().to_string();

        let budget = match typed_budget.as_str() {
            "" => None,
            typed => match typed.parse::<f64>() {
                // `is_finite` is the guard that matters: `1e400` parses to `inf`, and an
                // infinite ceiling is one no spend can cross — a budget that silently
                // never warns. Negative is refused for the same reason: it would warn on
                // every turn, including the first.
                Ok(limit) if limit.is_finite() && limit >= 0.0 => Some(limit),
                _unreadable => {
                    let mut settings = settings;
                    settings.message = Some(format!(
                        "{typed:?} is not a number of dollars; nothing was saved."
                    ));
                    settings.section = SettingsSection::Client;
                    settings.client = ClientField::Budget;
                    self.overlay = Some(Overlay::Settings(settings));
                    return;
                }
            },
        };

        // Past here every field is readable, so the write is all of them or none.

        // A blank box is "no default", not `""`: the same statement an empty workspace
        // makes in the start dialog.
        let workspace = settings.workspace.trim();
        self.config.defaults.workspace = (!workspace.is_empty()).then(|| workspace.to_string());

        self.config.defaults.approval_mode =
            approval_at(settings.approval).map(|mode| mode.as_str().to_string());

        self.config.defaults.sandbox_mode =
            sandbox_at(settings.sandbox).map(|mode| mode.as_str().to_string());

        // T2.10. The `F4` rows, through the same path and the same write. One `[ save ]`
        // per section, and both of them land here: the file is rewritten whole from
        // `Config`, so saving from either section cannot drop what the other was showing.
        self.config.terminal.mouse = settings.mouse;
        self.config.accessibility.screen_reader = settings.screen_reader;
        self.config.accessibility.reduced_motion = settings.reduced_motion;

        self.config.notifications.mode = crate::config::NotifyMode::ALL
            .get(settings.notify_mode)
            .copied()
            .map(|mode| mode.as_str().to_string());
        self.config.notifications.when = crate::config::NotifyWhen::ALL
            .get(settings.notify_when)
            .copied()
            .map(|when| when.as_str().to_string());

        self.config.budget.max_cost_usd = budget;

        self.save_pending = true;
    }
}
