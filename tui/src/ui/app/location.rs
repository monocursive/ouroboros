use super::*;

#[derive(Debug, Default)]
pub struct Location {
    pub machine: String,
    pub label: String,
    pub computer: usize,
    pub browsing: bool,
    pub pending: bool,
    pub path: Option<String>,
    pub entries: Vec<(String, String)>,
    pub selected: usize,
    pub error: Option<String>,
}

impl App {
    pub(super) fn local_machine_label(&self) -> String {
        let name = self.machine_summary().machine;
        if name != "nonode" {
            return name;
        }
        self.status
            .value
            .as_ref()
            .and_then(|status| status.cluster.pointer("/fleet/machines"))
            .and_then(Value::as_array)
            .and_then(|machines| machines.iter().find(|machine| machine["state"] == "local"))
            .and_then(|machine| machine.pointer("/facts/hostname"))
            .and_then(Value::as_str)
            .unwrap_or("Connected computer")
            .to_string()
    }

    pub fn home_machine_label(&self) -> String {
        if self.config.location.machine.is_empty() {
            self.local_machine_label()
        } else if self.config.location.label.is_empty() {
            self.config.location.machine.clone()
        } else {
            self.config.location.label.clone()
        }
    }

    pub(super) fn account_call_pending(&self, tag: &Tag) -> bool {
        self.in_flight.contains(tag) || self.in_flight.iter().any(|pending|
            matches!(pending, Tag::MachineAccount { tag: inner, .. } if inner.as_ref() == tag))
    }

    pub(super) fn open_location(&mut self) {
        if self.home_pending || self.home_reconciling() {
            return;
        }
        if self.account_call_pending(&Tag::AccountLogin)
            || self.account_call_pending(&Tag::AccountCancel)
            || self.account_call_pending(&Tag::AccountLogout)
        {
            self.home_error =
                Some("Finish the current sign-in attempt before changing computers.".into());
            return;
        }
        self.status.invalidate();
        self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);
        let choices = self.machine_choices();
        self.overlay = Some(Overlay::Location(Location {
            machine: self.config.location.machine.clone(),
            label: self.home_machine_label(),
            computer: choices
                .iter()
                .position(|choice| {
                    choice.wire_name().unwrap_or_default() == self.config.location.machine
                })
                .unwrap_or_default(),
            ..Location::default()
        }));
    }

    pub(super) fn location_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        let choices = self.machine_choices();
        let Some(Overlay::Location(dialog)) = self.overlay.as_mut() else {
            return;
        };
        if key.code == KeyCode::Esc {
            if dialog.browsing {
                dialog.browsing = false;
                dialog.pending = false;
                dialog.path = None;
            } else {
                self.overlay = None;
            }
            return;
        }
        if dialog.pending {
            return;
        }
        let len = if dialog.browsing {
            dialog.entries.len()
        } else {
            choices.len()
        };
        match key.code {
            KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => {
                if dialog.browsing {
                    dialog.selected = dialog.selected.saturating_sub(1);
                } else {
                    dialog.computer = dialog.computer.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => {
                if dialog.browsing {
                    dialog.selected = (dialog.selected + 1).min(len.saturating_sub(1));
                } else {
                    dialog.computer = (dialog.computer + 1).min(len.saturating_sub(1));
                }
            }
            KeyCode::Enter if !dialog.browsing => {
                let Some(choice) = choices.get(dialog.computer) else {
                    return;
                };
                dialog.machine = choice.wire_name().unwrap_or_default().to_string();
                dialog.label = match choice {
                    MachineChoice::Local { label } => label.clone(),
                    MachineChoice::Connected { machine, .. } => machine.clone(),
                };
                dialog.browsing = true;
                self.browse_location(None);
            }
            KeyCode::Enter
                if dialog.selected == 0 && dialog.path.is_some() && dialog.error.is_none() =>
            {
                let machine = dialog.machine.clone();
                let changed = machine != self.config.location.machine;
                self.config.location = crate::config::TaskLocation {
                    machine,
                    label: dialog.label.clone(),
                    workspace: dialog.path.clone(),
                };
                self.home_login_start = None;
                if changed {
                    self.account = Loadable::default();
                }
                self.home_error = None;
                self.save_pending = true;
                self.overlay = None;
                self.poll();
            }
            KeyCode::Enter => {
                if let Some((_, path)) = dialog.entries.get(dialog.selected) {
                    let path = path.clone();
                    self.browse_location(Some(path));
                } else {
                    self.browse_location(None);
                }
            }
            _ => {}
        }
    }

    fn browse_location(&mut self, path: Option<String>) {
        let Some(Overlay::Location(dialog)) = self.overlay.as_mut() else {
            return;
        };
        dialog.pending = true;
        dialog.error = None;
        dialog.path = path.clone();
        dialog.entries.clear();
        dialog.selected = 0;
        let machine = dialog.machine.clone();
        let mut params = json!({});
        if !machine.is_empty() {
            params["machine"] = json!(machine);
        }
        if let Some(path) = &path {
            params["path"] = json!(path);
        }
        self.issue(Call::new(
            Tag::BrowseLocation { machine, path },
            "workspace.browse",
            params,
        ));
    }

    pub(super) fn location_browsed(
        &mut self,
        machine: String,
        path: Option<String>,
        result: Result<Value, ClientError>,
    ) {
        let Some(Overlay::Location(dialog)) = self.overlay.as_mut() else {
            return;
        };
        if !dialog.browsing || dialog.machine != machine || dialog.path != path || !dialog.pending {
            return;
        }
        dialog.pending = false;
        match result {
            Ok(value) => {
                let Some(path) = value["path"].as_str() else {
                    dialog.error = Some(
                        "This computer did not return a folder. Enter retries; Esc goes back."
                            .into(),
                    );
                    return;
                };
                dialog.path = Some(path.into());
                dialog.entries = vec![("Use this folder".into(), path.into())];
                if let Some(parent) = value["parent"].as_str() {
                    dialog
                        .entries
                        .push(("↑ Parent folder".into(), parent.into()));
                }
                if let Some(roots) = value["roots"].as_array() {
                    for root in roots
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|root| *root != path)
                    {
                        dialog.entries.push((format!("Root: {root}"), root.into()));
                    }
                }
                if let Some(entries) = value["entries"].as_array() {
                    for name in entries.iter().filter_map(|entry| entry["name"].as_str()) {
                        dialog.entries.push((
                            format!("{name}/"),
                            format!("{}/{name}", path.trim_end_matches('/')),
                        ));
                    }
                }
                if value["truncated"] == true {
                    // Keep the selection usable while making the bounded listing explicit.
                    dialog.entries.push((
                        "More folders exist; open a parent or another root".into(),
                        path.into(),
                    ));
                }
            }
            Err(error) => {
                dialog.path = None;
                dialog.error = Some(format!(
                    "{error}\nEnter retries; Esc chooses another computer."
                ));
            }
        }
    }
}
