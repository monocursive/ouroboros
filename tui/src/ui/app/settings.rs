use super::*;
use crate::model::CredentialStatus;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsSection {
    Connections,
    Defaults,
    Runtime,
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
        if self.section != SettingsSection::Defaults {
            return None;
        }
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
            _ => {}
        }
        if settings.section == SettingsSection::Connections {
            self.settings_connection_key(key);
            return;
        }
        if settings.section == SettingsSection::Runtime {
            if key.code == KeyCode::Esc {
                self.overlay = None;
            }
            return;
        }

        match key.code {
            KeyCode::Esc => self.overlay = None,
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
        for (provider, name, subscription) in [
            ("openai_codex", "ChatGPT", true),
            ("grok", "Grok", true),
            ("openai", "OpenAI", false),
            ("anthropic", "Anthropic", false),
            ("xai", "xAI", false),
        ] {
            let credential = credentials.iter().find(|c| c.provider == provider).cloned();
            rows.push(SettingsConnection {
                provider: provider.into(),
                name: name.into(),
                subscription,
                stale: self.providers.error.is_some()
                    || (self.providers.value.is_some() && credential.is_none()),
                credential,
            });
        }
        for credential in credentials {
            if !rows.iter().any(|row| row.provider == credential.provider) {
                rows.push(SettingsConnection {
                    name: credential.provider.replace('_', " "),
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
            KeyCode::Esc => self.overlay = None,
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
