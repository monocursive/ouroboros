use super::*;

/// One row in the Machines menu. Enter runs it after any form/confirm the action needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    AddHost(usize),
    AddSsh,
    AddRecipe,
    Create,
    Join,
    Invite,
    Service,
    Status,
    Doctor,
    Sync,
}

impl MenuItem {
    pub fn label(self, machines: &Machines) -> String {
        match self {
            Self::AddHost(index) => machines
                .candidates
                .get(index)
                .map(|candidate| format!("Add {}", candidate.label))
                .unwrap_or_else(|| "Add a known host".into()),
            Self::AddSsh => "Add a reachable machine".into(),
            Self::AddRecipe => "I'll set it up myself".into(),
            Self::Create => "Create a fleet".into(),
            Self::Join => "Join with an invitation".into(),
            Self::Invite => "Write an invitation file".into(),
            Self::Service => "Keep this machine running".into(),
            Self::Status => "Check the machines".into(),
            Self::Doctor => "Diagnose a connection".into(),
            Self::Sync => "Export saved membership".into(),
        }
    }

    pub fn hint(self, machines: &Machines) -> String {
        match self {
            Self::AddHost(index) => machines
                .candidates
                .get(index)
                .map(|candidate| {
                    if candidate.detail.is_empty() {
                        candidate.target.clone()
                    } else {
                        format!("{} · {}", candidate.target, candidate.detail)
                    }
                })
                .unwrap_or_default(),
            Self::AddSsh => "SSH or Tailscale from this Mac".into(),
            Self::AddRecipe => "Write a private invite; run enroll there".into(),
            Self::Create => "Make this Mac the owner (restarts once)".into(),
            Self::Join => "On the invited machine (restarts once)".into(),
            Self::Invite => "Owner-only; copy the file privately".into(),
            Self::Service => "Write a recovery unit; you activate it".into(),
            Self::Status => "Who is known, connected, or offline".into(),
            Self::Doctor => "Names, TLS, versions, recovery".into(),
            Self::Sync => "Signed roster for other existing members".into(),
        }
    }

    pub fn command(self, machines: &Machines) -> String {
        match self {
            Self::AddHost(index) => machines
                .candidates
                .get(index)
                .map(|candidate| {
                    let machine = suggested_machine_name(
                        &candidate.label,
                        candidate.host.as_deref().unwrap_or(&candidate.target),
                    );
                    let host = candidate.host.as_deref().unwrap_or(&candidate.target);
                    format!(
                        "ouro fleet add {} --machine {machine} --host {host}",
                        candidate.target
                    )
                })
                .unwrap_or_else(|| MachineAction::Add.command().into()),
            Self::AddSsh => MachineAction::Add.command().into(),
            Self::AddRecipe => "ouro fleet add --print-script --machine NAME --host HOST".into(),
            Self::Create => MachineAction::Create.command().into(),
            Self::Join => "ouro fleet enroll INVITE.ouro --delete".into(),
            Self::Invite => MachineAction::Invite.command().into(),
            Self::Service => MachineAction::Service.command().into(),
            Self::Status => MachineAction::Status.command().into(),
            Self::Doctor => MachineAction::Doctor.command().into(),
            Self::Sync => MachineAction::Sync.command().into(),
        }
    }

    pub fn preview(self) -> &'static str {
        match self {
            Self::AddHost(_) | Self::AddSsh => {
                "Enter opens a short form, then runs the add after you confirm. A Mac binary is never copied onto Linux."
            }
            Self::AddRecipe => {
                "Enter writes a private invitation on this Mac and shows the enroll command to run on the other machine."
            }
            Self::Create => {
                "Enter names this Mac, then restarts once to become the fleet owner. Add the laptop and servers afterward."
            }
            Self::Join => {
                "Enter the invitation path. This machine restarts once, joins, and comes back as a fleet member."
            }
            Self::Invite => {
                "Enter machine name and host, then writes a mode-0600 invitation. Contents never appear on screen."
            }
            Self::Service => {
                "Writes a launchd or systemd user unit. It does not start anything; review and run the activation command."
            }
            Self::Status => "Enter shows known, connected, and offline machines from this runtime.",
            Self::Doctor => {
                "Enter runs local setup checks and live fleet diagnostics. No cookies or keys are printed."
            }
            Self::Sync => {
                "Enter writes a signed roster file to copy privately. Import on other members still needs them stopped."
            }
        }
    }
}

/// Kept for CLI copy strings. The on-screen menu is [`MenuItem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineAction {
    Add,
    Create,
    Join,
    Invite,
    Service,
    Status,
    Doctor,
    Sync,
}

impl MachineAction {
    pub fn command(self) -> &'static str {
        match self {
            Self::Add => "ouro fleet add user@host --machine NAME --host HOST",
            Self::Create => "ouro fleet create --machine NAME --host HOST",
            Self::Join => "ouro fleet join INVITE.ouro",
            Self::Invite => "ouro fleet invite --machine NAME --host HOST --out INVITE.ouro",
            Self::Service => "ouro fleet service install",
            Self::Status => "ouro fleet status",
            Self::Doctor => "ouro fleet doctor",
            Self::Sync => "ouro fleet sync export --out fleet.ouro-roster",
        }
    }
}

/// Keyboard state for the Machines menu.
#[derive(Debug, Default)]
pub struct Machines {
    pub selected: usize,
    pub add: Option<AddMachine>,
    pub form: Option<MachineForm>,
    pub report: Option<MachineReport>,
    pub candidates: Vec<MachineCandidate>,
    pub local_machine: Option<String>,
    pub local_host: Option<String>,
}

/// A host this Mac already knows. The driver fills this from Tailscale and SSH config;
/// the App never probes the network itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineCandidate {
    pub label: String,
    pub target: String,
    pub host: Option<String>,
    pub detail: String,
    pub tailscale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddMethod {
    Ssh,
    Prepare,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddStep {
    Method,
    Pick,
    Form,
    Confirm,
    Working,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddField {
    Target,
    Machine,
    Host,
    Via,
    Binary,
    OwnerHost,
    OwnerMachine,
}

#[derive(Debug, Clone)]
pub struct AddMachine {
    pub step: AddStep,
    pub method: AddMethod,
    pub target: String,
    pub machine: String,
    pub host: String,
    pub via: usize,
    pub binary: String,
    pub owner_host: String,
    pub owner_machine: String,
    pub field: AddField,
    pub error: Option<String>,
    pub log: Vec<String>,
    pub recipe: Option<String>,
    pub pending: bool,
    pub candidate: usize,
}

impl AddMachine {
    pub(super) fn new() -> Self {
        Self {
            step: AddStep::Method,
            method: AddMethod::Ssh,
            target: String::new(),
            machine: String::new(),
            host: String::new(),
            via: 0,
            binary: String::new(),
            owner_host: String::new(),
            owner_machine: String::new(),
            field: AddField::Target,
            error: None,
            log: Vec::new(),
            recipe: None,
            pending: false,
            candidate: 0,
        }
    }

    pub fn via_label(&self) -> &'static str {
        if self.via == 0 {
            "ssh"
        } else {
            "tailscale"
        }
    }

    fn apply_candidate(&mut self, candidate: &MachineCandidate) {
        self.target = candidate.target.clone();
        self.host = candidate
            .host
            .clone()
            .unwrap_or_else(|| candidate.target.clone());
        self.machine = suggested_machine_name(&candidate.label, &self.host);
        if candidate.tailscale {
            self.via = 1;
        }
    }

    fn form_field(&self) -> AddField {
        match self.method {
            AddMethod::Ssh => AddField::Target,
            AddMethod::Prepare => AddField::Machine,
        }
    }

    pub fn fields(&self, standalone: bool) -> Vec<AddField> {
        let mut fields = match self.method {
            AddMethod::Ssh => vec![
                AddField::Target,
                AddField::Machine,
                AddField::Host,
                AddField::Via,
                AddField::Binary,
            ],
            AddMethod::Prepare => vec![AddField::Machine, AddField::Host],
        };
        if standalone {
            fields.extend([AddField::OwnerMachine, AddField::OwnerHost]);
        }
        fields
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormKind {
    Create,
    Join,
    Invite,
    Service,
    SyncExport,
}

#[derive(Debug, Clone)]
pub struct MachineForm {
    pub kind: FormKind,
    pub step: AddStep,
    pub field: usize,
    pub machine: String,
    pub host: String,
    pub path: String,
    pub delete_invite: bool,
    pub install_service: bool,
    pub error: Option<String>,
    pub log: Vec<String>,
    pub recipe: Option<String>,
    pub pending: bool,
}

impl MachineForm {
    fn new(kind: FormKind) -> Self {
        Self {
            kind,
            step: if kind == FormKind::Service {
                AddStep::Confirm
            } else {
                AddStep::Form
            },
            field: 0,
            machine: String::new(),
            host: String::new(),
            path: String::new(),
            delete_invite: true,
            install_service: false,
            error: None,
            log: Vec::new(),
            recipe: None,
            pending: false,
        }
    }

    pub fn fields(&self) -> Vec<FormField> {
        match self.kind {
            FormKind::Create => vec![FormField::Machine, FormField::Host],
            FormKind::Join => vec![
                FormField::Path,
                FormField::DeleteInvite,
                FormField::InstallService,
            ],
            FormKind::Invite => vec![FormField::Machine, FormField::Host, FormField::Path],
            FormKind::Service => Vec::new(),
            FormKind::SyncExport => vec![FormField::Path],
        }
    }

    fn field(&self) -> Option<FormField> {
        let fields = self.fields();
        fields
            .get(self.field.min(fields.len().saturating_sub(1)))
            .copied()
    }

    pub fn title(&self) -> &'static str {
        match self.kind {
            FormKind::Create => "Create a fleet on this Mac",
            FormKind::Join => "Join with an invitation",
            FormKind::Invite => "Write an invitation file",
            FormKind::Service => "Keep this machine running",
            FormKind::SyncExport => "Export saved membership",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Machine,
    Host,
    Path,
    DeleteInvite,
    InstallService,
}

#[derive(Debug, Clone)]
pub struct MachineReport {
    pub title: String,
    pub body: String,
    pub copy: Option<String>,
    pub pending: bool,
}

fn suggested_machine_name(label: &str, host: &str) -> String {
    if crate::fleet::validate_machine(label).is_ok() {
        return label.to_ascii_lowercase();
    }
    crate::fleet::machine_from_host(host)
        .or_else(|_| crate::fleet::machine_from_host(label))
        .unwrap_or_default()
}

/// Confirmed work the I/O driver should run against the local data directory.
#[derive(Debug, Clone)]
pub enum FleetJob {
    Add {
        prepare: bool,
        target: Option<String>,
        machine: String,
        host: String,
        via: String,
        binary: Option<String>,
    },
    Invite {
        machine: String,
        host: String,
        out: Option<String>,
    },
    Service,
    Status,
    Doctor,
    SyncExport {
        out: String,
    },
}

/// The small, intentionally non-secret view model shared by Settings, the Dashboard and
/// the Machines guide. It combines the local profile (what this machine expects) with the
/// runtime status (what is connected now), and leaves unknown facts unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineSummary {
    pub mode: String,
    pub fleet: Option<String>,
    pub machine: String,
    pub host: Option<String>,
    pub expected: Option<usize>,
    pub connected: usize,
    pub offline: Option<usize>,
    pub offline_names: Vec<String>,
    pub security: MachineSecurity,
    pub recovery: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineSecurity {
    Standalone,
    Secure,
    Insecure,
    Mismatch,
    Unknown,
}

impl MachineSecurity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Standalone => "not needed while standalone",
            Self::Secure => "encrypted and authenticated (TLS)",
            Self::Insecure => "insecure: machine traffic is not using TLS",
            Self::Mismatch => "configuration mismatch: fleet profile loaded, runtime is standalone",
            Self::Unknown => "security not reported yet",
        }
    }
}

/// One destination in the new-session form. Local is represented by an omitted wire
/// parameter, so an older standalone runtime behaves exactly as before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineChoice {
    Local { label: String },
    Connected { machine: String, node: String },
}

impl MachineChoice {
    pub fn label(&self) -> String {
        match self {
            Self::Local { label } => format!("This machine — {label}"),
            Self::Connected { machine, node } => format!("{machine} — connected ({node})"),
        }
    }

    pub fn wire_name(&self) -> Option<&str> {
        match self {
            Self::Local { .. } => None,
            Self::Connected { machine, .. } => Some(machine),
        }
    }
}

impl App {
    /// The fleet state a person needs, without the distribution vocabulary used by the
    /// runtime protocol. Local membership says what should be present; live status says
    /// what is present now. Neither source contains a cookie, key, or certificate.
    pub fn machine_summary(&self) -> MachineSummary {
        let status = self.status.value.as_ref();
        let cluster = status.map(|status| &status.cluster);
        let runtime_fleet = cluster.and_then(|cluster| cluster.get("fleet"));
        let runtime_summary = runtime_fleet.and_then(|fleet| fleet.get("summary"));
        let runtime_machines = runtime_fleet
            .and_then(|fleet| fleet.get("machines"))
            .and_then(Value::as_array);
        let connected_nodes: HashSet<&str> = status
            .map(|status| status.connected_nodes.iter().map(String::as_str).collect())
            .unwrap_or_default();

        let strategy = cluster
            .and_then(|cluster| cluster.get("formation"))
            .and_then(|formation| formation.get("strategy"))
            .and_then(Value::as_str)
            .unwrap_or("none");
        let distributed = cluster
            .and_then(|cluster| cluster.get("distributed"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let tls = cluster
            .and_then(|cluster| cluster.get("security"))
            .and_then(|security| security.get("tls"))
            .and_then(Value::as_bool);

        let fleet_mode = self.fleet_profile.is_some()
            || runtime_fleet.is_some()
            || distributed
            || strategy != "none";

        if !fleet_mode {
            return MachineSummary {
                mode: "Standalone".into(),
                fleet: None,
                machine: friendly_machine(
                    status
                        .map(|status| status.node.as_str())
                        .unwrap_or(&self.hello.node),
                ),
                host: None,
                expected: Some(1),
                connected: 1,
                offline: Some(0),
                offline_names: Vec::new(),
                security: MachineSecurity::Standalone,
                recovery:
                    "This machine runs on its own. Add another from this overlay when it is reachable."
                        .into(),
            };
        }

        let (fleet, machine, host, profile_expected, profile_connected, offline_names) = match self
            .fleet_profile
            .as_ref()
        {
            Some(profile) => {
                let mut members: BTreeMap<String, String> = profile
                    .members
                    .iter()
                    .map(|member| (member.node.clone(), member.machine.clone()))
                    .collect();
                members
                    .entry(profile.node.clone())
                    .or_insert_with(|| profile.machine.clone());

                // Invitations are intentionally independent: an early joiner does
                // not have to receive a rewritten secret bundle every time the owner
                // later invites another machine. Merge the runtime's last-known
                // directory so that a machine already observed over BEAM is still
                // counted and named here. Otherwise the UI can claim the impossible
                // “expected 2, connected 3”.
                if let Some(runtime_machines) = runtime_machines {
                    for runtime_machine in runtime_machines {
                        let Some(node) = runtime_machine.get("node").and_then(Value::as_str) else {
                            continue;
                        };
                        let machine = runtime_machine
                            .get("machine")
                            .and_then(Value::as_str)
                            .unwrap_or(node);
                        members
                            .entry(node.to_string())
                            .or_insert_with(|| machine.to_string());
                    }
                }

                let mut offline_names = members
                    .iter()
                    .filter(|(node, _machine)| {
                        node.as_str() != profile.node && !connected_nodes.contains(node.as_str())
                    })
                    .map(|(_node, machine)| machine.clone())
                    .collect::<Vec<_>>();
                if let Some(runtime_machines) = runtime_machines {
                    offline_names.extend(runtime_machines.iter().filter_map(|machine| {
                        (machine.get("state").and_then(Value::as_str) == Some("offline"))
                            .then(|| {
                                machine
                                    .get("machine")
                                    .and_then(Value::as_str)
                                    .or_else(|| machine.get("node").and_then(Value::as_str))
                                    .map(str::to_string)
                            })
                            .flatten()
                    }));
                }
                offline_names.sort();
                offline_names.dedup();
                let expected = members.len().max(1);
                let connected = expected.saturating_sub(offline_names.len());

                (
                    Some(profile.name.clone()),
                    profile.machine.clone(),
                    Some(profile.host.clone()),
                    Some(expected),
                    Some(connected),
                    offline_names,
                )
            }
            None => {
                let node = status
                    .map(|status| status.node.as_str())
                    .unwrap_or(&self.hello.node);
                let offline_names = runtime_fleet
                    .and_then(|fleet| fleet.get("machines"))
                    .and_then(Value::as_array)
                    .map(|machines| {
                        machines
                            .iter()
                            .filter(|machine| {
                                machine.get("state").and_then(Value::as_str) == Some("offline")
                            })
                            .filter_map(|machine| {
                                machine
                                    .get("machine")
                                    .and_then(Value::as_str)
                                    .or_else(|| machine.get("node").and_then(Value::as_str))
                            })
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                (
                    runtime_fleet
                        .and_then(|fleet| fleet.get("fleet_id"))
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    friendly_machine(node),
                    node.split_once('@').map(|(_name, host)| host.to_string()),
                    value_usize(runtime_summary.and_then(|summary| summary.get("expected"))),
                    value_usize(runtime_summary.and_then(|summary| summary.get("connected"))),
                    offline_names,
                )
            }
        };

        let connected = value_usize(runtime_summary.and_then(|summary| summary.get("connected")))
            .or(profile_connected)
            .unwrap_or_else(|| connected_nodes.len() + 1);
        let expected = profile_expected
            .into_iter()
            .chain(value_usize(
                runtime_summary.and_then(|summary| summary.get("expected")),
            ))
            .max()
            .map(|expected| expected.max(connected));
        let offline = value_usize(runtime_summary.and_then(|summary| summary.get("offline")))
            .into_iter()
            .chain(expected.map(|expected| expected.saturating_sub(connected)))
            .chain(std::iter::once(offline_names.len()))
            .max();

        let security = match (self.fleet_profile.is_some(), distributed, tls) {
            (true, false, Some(_)) => MachineSecurity::Mismatch,
            (_, true, Some(true)) => MachineSecurity::Secure,
            (_, true, Some(false)) => MachineSecurity::Insecure,
            (true, false, None) if status.is_some() => MachineSecurity::Mismatch,
            _ => MachineSecurity::Unknown,
        };

        let recovery = match offline {
            Some(0) => {
                "All known machines are connected. Running daemons retry membership after network interruptions."
                    .into()
            }
            Some(offline) => format!(
                "{offline} machine{} offline; running daemons keep retrying membership.",
                if offline == 1 { " is" } else { "s are" }
            ),
            None => {
                "Running daemons retry membership; expected membership is not known here."
                    .into()
            }
        };

        MachineSummary {
            mode: "Fleet".into(),
            fleet,
            machine,
            host,
            expected,
            connected,
            offline,
            offline_names,
            security,
            recovery,
        }
    }

    /// Destinations that can safely be offered for a new session right now. Expected but
    /// offline members are visible in Machines, not selectable here: a start form should
    /// never invite a request that the runtime already knows it cannot route.
    pub fn machine_choices(&self) -> Vec<MachineChoice> {
        let summary = self.machine_summary();
        let mut choices = vec![MachineChoice::Local {
            label: summary.machine,
        }];
        let Some(status) = self.status.value.as_ref() else {
            return choices;
        };

        let connected: HashSet<&str> = status.connected_nodes.iter().map(String::as_str).collect();
        let local_node = self
            .fleet_profile
            .as_ref()
            .map(|profile| profile.node.as_str())
            .unwrap_or(status.node.as_str());
        let mut remotes = BTreeMap::<String, String>::new();
        let mut incompatible_nodes = HashSet::<String>::new();

        if let Some(machines) = status
            .cluster
            .get("fleet")
            .and_then(|fleet| fleet.get("machines"))
            .and_then(Value::as_array)
        {
            for machine in machines {
                let state = machine.get("state").and_then(Value::as_str);
                let role = machine.get("role").and_then(Value::as_str);
                let Some(node) = machine.get("node").and_then(Value::as_str) else {
                    continue;
                };
                if machine.get("compatibility").and_then(Value::as_str) == Some("incompatible") {
                    incompatible_nodes.insert(node.to_string());
                    continue;
                }
                if state != Some("connected") || role.is_some_and(|role| role != "core") {
                    continue;
                }

                let Some(name) = machine.get("machine").and_then(Value::as_str) else {
                    continue;
                };
                if node != local_node {
                    remotes.insert(name.to_string(), node.to_string());
                }
            }
        }

        // A profile remains useful against an older runtime that does not yet embed the
        // fleet directory. Connectivity is still a live fact from runtime.status.
        if let Some(profile) = self.fleet_profile.as_ref() {
            for member in &profile.members {
                if member.node != profile.node
                    && connected.contains(member.node.as_str())
                    && !incompatible_nodes.contains(&member.node)
                {
                    remotes
                        .entry(member.machine.clone())
                        .or_insert_with(|| member.node.clone());
                }
            }
        }

        choices.extend(
            remotes
                .into_iter()
                .map(|(machine, node)| MachineChoice::Connected { machine, node }),
        );
        choices
    }

    pub(super) fn open_machines(&mut self) {
        self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);
        self.scan_machines_pending = true;
        self.overlay = Some(Overlay::Machines(Box::default()));
    }

    pub(super) fn machines_key(&mut self, key: crossterm::event::KeyEvent) {
        let Some(Overlay::Machines(machines)) = self.overlay.as_ref() else {
            return;
        };
        if machines.add.is_some() {
            self.add_machine_key(key);
        } else if machines.form.is_some() {
            self.machine_form_key(key);
        } else if machines.report.is_some() {
            self.machine_report_key(key);
        } else {
            self.machine_menu_key(key);
        }
    }

    pub fn machine_menu(&self) -> Vec<MenuItem> {
        let Some(Overlay::Machines(machines)) = self.overlay.as_ref() else {
            return Vec::new();
        };
        self.machine_menu_for(machines)
    }

    pub fn machine_menu_for(&self, machines: &Machines) -> Vec<MenuItem> {
        let standalone = self.fleet_profile.is_none();
        let mut items = Vec::new();
        if standalone || self.can_invite {
            for (index, _) in machines.candidates.iter().take(8).enumerate() {
                items.push(MenuItem::AddHost(index));
            }
            items.push(MenuItem::AddSsh);
            items.push(MenuItem::AddRecipe);
        }
        if standalone {
            items.push(MenuItem::Create);
            items.push(MenuItem::Join);
        }
        if self.can_invite {
            items.push(MenuItem::Invite);
        }
        if self.fleet_profile.is_some() {
            items.push(MenuItem::Service);
        }
        items.push(MenuItem::Status);
        items.push(MenuItem::Doctor);
        if self.fleet_profile.is_some() {
            items.push(MenuItem::Sync);
        }
        items
    }

    fn machine_menu_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let items = self.machine_menu();
        if items.is_empty() {
            if key.code == KeyCode::Esc {
                self.overlay = None;
            }
            return;
        }
        let last = items.len().saturating_sub(1);
        let selected = match self.overlay.as_ref() {
            Some(Overlay::Machines(machines)) => machines.selected.min(last),
            _ => 0,
        };
        let item = items[selected];

        match key.code {
            KeyCode::Esc => self.overlay = None,
            KeyCode::Tab | KeyCode::Char('j') | KeyCode::Down => {
                if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                    machines.selected = (selected + 1).min(last);
                }
            }
            KeyCode::BackTab | KeyCode::Char('k') | KeyCode::Up => {
                if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                    machines.selected = selected.saturating_sub(1);
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                self.run_menu_item(item);
            }
            KeyCode::Char('y') => {
                let command = match self.overlay.as_ref() {
                    Some(Overlay::Machines(machines)) => item.command(machines),
                    _ => String::new(),
                };
                self.copy_pending = Some(command.clone());
                self.inform(
                    format!("copied `{command}`; review any placeholders before running it"),
                    NoticeKind::Info,
                );
            }
            KeyCode::Char('r') => {
                self.status.invalidate();
                self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);
                self.scan_machines_pending = true;
            }
            _ => {}
        }
    }

    fn run_menu_item(&mut self, item: MenuItem) {
        match item {
            MenuItem::AddHost(index) => self.begin_add_from_menu(AddMethod::Ssh, Some(index)),
            MenuItem::AddSsh => self.begin_add_from_menu(AddMethod::Ssh, None),
            MenuItem::AddRecipe => self.begin_add_from_menu(AddMethod::Prepare, None),
            MenuItem::Create => self.begin_machine_form(FormKind::Create),
            MenuItem::Join => self.begin_machine_form(FormKind::Join),
            MenuItem::Invite => self.begin_machine_form(FormKind::Invite),
            MenuItem::Service => self.begin_machine_form(FormKind::Service),
            MenuItem::Sync => self.begin_machine_form(FormKind::SyncExport),
            MenuItem::Status => self.start_machine_report("Check the machines", FleetJob::Status),
            MenuItem::Doctor => {
                self.start_machine_report("Diagnose a connection", FleetJob::Doctor)
            }
        }
    }

    fn begin_add_from_menu(&mut self, method: AddMethod, host: Option<usize>) {
        let Some(Overlay::Machines(machines)) = self.overlay.as_mut() else {
            return;
        };
        let candidate = host.and_then(|index| machines.candidates.get(index).cloned());
        let mut add = AddMachine::new();
        add.method = method;
        add.step = AddStep::Form;
        add.field = add.form_field();
        if let Some(name) = machines.local_machine.as_deref() {
            add.owner_machine = name.to_string();
        }
        if let Some(host) = machines.local_host.as_deref() {
            add.owner_host = host.to_string();
        }
        if let Some(candidate) = candidate {
            add.apply_candidate(&candidate);
        }
        machines.add = Some(add);
    }

    fn begin_machine_form(&mut self, kind: FormKind) {
        let Some(Overlay::Machines(machines)) = self.overlay.as_mut() else {
            return;
        };
        let mut form = MachineForm::new(kind);
        if kind == FormKind::Create {
            if let Some(name) = machines.local_machine.as_deref() {
                form.machine = name.to_string();
            }
            if let Some(host) = machines.local_host.as_deref() {
                form.host = host.to_string();
            }
        }
        if kind == FormKind::SyncExport {
            form.path = "fleet.ouro-roster".into();
        }
        machines.form = Some(form);
    }

    fn start_machine_report(&mut self, title: &str, job: FleetJob) {
        if self.data_dir.is_none() {
            self.inform(
                "this client has no local data directory, so it cannot run that check here",
                NoticeKind::Error,
            );
            return;
        }
        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            machines.report = Some(MachineReport {
                title: title.into(),
                body: String::new(),
                copy: None,
                pending: true,
            });
        }
        self.fleet_job_pending = Some(job);
    }

    fn machine_report_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                    if machines
                        .report
                        .as_ref()
                        .is_some_and(|report| report.pending)
                    {
                        return;
                    }
                    machines.report = None;
                }
            }
            KeyCode::Char('y') => {
                let copy = match self.overlay.as_ref() {
                    Some(Overlay::Machines(machines)) => {
                        machines.report.as_ref().and_then(|report| {
                            report.copy.clone().or_else(|| {
                                Some(report.body.clone()).filter(|body| !body.is_empty())
                            })
                        })
                    }
                    _ => None,
                };
                if let Some(copy) = copy {
                    self.copy_pending = Some(copy);
                    self.inform("copied the report", NoticeKind::Info);
                }
            }
            _ => {}
        }
    }

    fn machine_form_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let step = match self.overlay.as_ref() {
            Some(Overlay::Machines(machines)) => machines.form.as_ref().map(|form| form.step),
            _ => None,
        };
        let Some(step) = step else {
            return;
        };

        match step {
            AddStep::Working => {
                if key.code == KeyCode::Esc && self.quit != Some(Quit::ApplyFleetIntent) {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(form) = machines.form.as_mut() {
                            form.step = AddStep::Confirm;
                            form.pending = false;
                            form.error =
                                Some("cancelled waiting; the work may still be running".into());
                        }
                    }
                }
            }
            AddStep::Form => match key.code {
                KeyCode::Esc => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        machines.form = None;
                    }
                }
                KeyCode::Tab | KeyCode::Down => self.move_form_field(1),
                KeyCode::BackTab | KeyCode::Up => self.move_form_field(-1),
                KeyCode::Left | KeyCode::Right => self.toggle_form_bool(),
                KeyCode::Enter => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(form) = machines.form.as_mut() {
                            form.step = AddStep::Confirm;
                        }
                    }
                }
                KeyCode::Char(c) if !c.is_control() => self.push_form_char(c),
                KeyCode::Backspace => self.pop_form_char(),
                _ => {}
            },
            AddStep::Confirm => match key.code {
                KeyCode::Esc => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(form) = machines.form.as_mut() {
                            if form.kind == FormKind::Service {
                                machines.form = None;
                            } else {
                                form.step = AddStep::Form;
                            }
                        }
                    }
                }
                KeyCode::Char('y') => {
                    let command = self.form_command_preview();
                    self.copy_pending = Some(command.clone());
                    self.inform(format!("copied `{command}`"), NoticeKind::Info);
                }
                KeyCode::Enter => self.confirm_machine_form(),
                _ => {}
            },
            AddStep::Done => match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        machines.form = None;
                    }
                }
                KeyCode::Char('y') => {
                    let recipe = match self.overlay.as_ref() {
                        Some(Overlay::Machines(machines)) => {
                            machines.form.as_ref().and_then(|form| form.recipe.clone())
                        }
                        _ => None,
                    };
                    if let Some(recipe) = recipe {
                        self.copy_pending = Some(recipe);
                        self.inform("copied the result", NoticeKind::Info);
                    }
                }
                _ => {}
            },
            AddStep::Method | AddStep::Pick => {}
        }
    }

    fn move_form_field(&mut self, delta: isize) {
        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            if let Some(form) = machines.form.as_mut() {
                let len = form.fields().len() as isize;
                if len == 0 {
                    return;
                }
                let next = (form.field as isize + delta).rem_euclid(len) as usize;
                form.field = next;
            }
        }
    }

    fn toggle_form_bool(&mut self) {
        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            if let Some(form) = machines.form.as_mut() {
                match form.field() {
                    Some(FormField::DeleteInvite) => form.delete_invite = !form.delete_invite,
                    Some(FormField::InstallService) => form.install_service = !form.install_service,
                    _ => {}
                }
            }
        }
    }

    fn push_form_char(&mut self, c: char) {
        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            if let Some(form) = machines.form.as_mut() {
                match form.field() {
                    Some(FormField::Machine) => form.machine.push(c),
                    Some(FormField::Host) => form.host.push(c),
                    Some(FormField::Path) => form.path.push(c),
                    _ => {}
                }
            }
        }
    }

    fn pop_form_char(&mut self) {
        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            if let Some(form) = machines.form.as_mut() {
                match form.field() {
                    Some(FormField::Machine) => {
                        form.machine.pop();
                    }
                    Some(FormField::Host) => {
                        form.host.pop();
                    }
                    Some(FormField::Path) => {
                        form.path.pop();
                    }
                    _ => {}
                }
            }
        }
    }

    fn form_command_preview(&self) -> String {
        let Some(Overlay::Machines(machines)) = self.overlay.as_ref() else {
            return String::new();
        };
        let Some(form) = machines.form.as_ref() else {
            return String::new();
        };
        match form.kind {
            FormKind::Create => {
                let mut command = "ouro fleet create".to_string();
                if !form.machine.trim().is_empty() {
                    command.push_str(&format!(" --machine {}", form.machine.trim()));
                }
                if !form.host.trim().is_empty() {
                    command.push_str(&format!(" --host {}", form.host.trim()));
                }
                command
            }
            FormKind::Join => {
                let mut command = format!("ouro fleet enroll {}", form.path.trim());
                if form.delete_invite {
                    command.push_str(" --delete");
                }
                if form.install_service {
                    command.push_str(" --service");
                }
                command
            }
            FormKind::Invite => format!(
                "ouro fleet invite --machine {} --host {} --out {}",
                form.machine.trim(),
                form.host.trim(),
                if form.path.trim().is_empty() {
                    "INVITE.ouro"
                } else {
                    form.path.trim()
                }
            ),
            FormKind::Service => MachineAction::Service.command().into(),
            FormKind::SyncExport => format!(
                "ouro fleet sync export --out {}",
                if form.path.trim().is_empty() {
                    "fleet.ouro-roster"
                } else {
                    form.path.trim()
                }
            ),
        }
    }

    fn confirm_machine_form(&mut self) {
        let snapshot = match self.overlay.as_ref() {
            Some(Overlay::Machines(machines)) => machines.form.clone(),
            _ => None,
        };
        let Some(form) = snapshot else {
            return;
        };

        match form.kind {
            FormKind::Create => {
                if !self.spawned() {
                    self.set_form_error(
                        "run `ouro` on this Mac (not `ouro attach`) to create the fleet from here",
                    );
                    return;
                }
                if self.fleet_profile.is_some() {
                    self.set_form_error("this machine already has a fleet");
                    return;
                }
                let host = form.host.trim().to_string();
                if host.is_empty() {
                    self.set_form_error(
                        "this Mac needs its Tailscale MagicDNS name or private IPv4 address",
                    );
                    return;
                }
                let machine = {
                    let named = form.machine.trim();
                    if named.is_empty() {
                        crate::fleet::machine_from_host(&host).unwrap_or_else(|_| "studio".into())
                    } else {
                        named.to_string()
                    }
                };
                if let Err(error) = crate::fleet::validate_machine(&machine) {
                    self.set_form_error(format!("{error:#}"));
                    return;
                }
                self.fleet_intent_pending = Some(FleetIntent {
                    schema: 1,
                    owner_machine: machine,
                    owner_host: host,
                    fleet_name: None,
                    add: None,
                });
                self.set_form_working();
                self.quit = Some(Quit::ApplyFleetIntent);
            }
            FormKind::Join => {
                if !self.spawned() {
                    self.set_form_error(
                        "run `ouro` on this machine (not `ouro attach`) to join from here",
                    );
                    return;
                }
                if self.fleet_profile.is_some() {
                    self.set_form_error("this machine already has a fleet");
                    return;
                }
                let invitation = form.path.trim().to_string();
                if invitation.is_empty() {
                    self.set_form_error("invitation path is required");
                    return;
                }
                self.join_intent_pending = Some(JoinIntent {
                    schema: 1,
                    invitation,
                    delete: form.delete_invite,
                    service: form.install_service,
                });
                self.set_form_working();
                self.quit = Some(Quit::ApplyFleetIntent);
            }
            FormKind::Invite => {
                if !self.can_invite {
                    self.set_form_error(
                        "this machine joined the fleet and cannot invite others; run this on the original owner",
                    );
                    return;
                }
                let machine = form.machine.trim().to_string();
                let host = form.host.trim().to_string();
                if machine.is_empty() || host.is_empty() {
                    self.set_form_error("machine name and fleet host are required");
                    return;
                }
                self.set_form_working();
                self.fleet_job_pending = Some(FleetJob::Invite {
                    machine,
                    host,
                    out: {
                        let path = form.path.trim();
                        (!path.is_empty()).then(|| path.to_string())
                    },
                });
            }
            FormKind::Service => {
                self.set_form_working();
                self.fleet_job_pending = Some(FleetJob::Service);
            }
            FormKind::SyncExport => {
                let out = form.path.trim().to_string();
                if out.is_empty() {
                    self.set_form_error("output path is required");
                    return;
                }
                self.set_form_working();
                self.fleet_job_pending = Some(FleetJob::SyncExport { out });
            }
        }
    }

    fn set_form_error(&mut self, error: impl Into<String>) {
        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            if let Some(form) = machines.form.as_mut() {
                form.error = Some(error.into());
                if form.kind != FormKind::Service {
                    form.step = AddStep::Form;
                }
            }
        }
    }

    fn set_form_working(&mut self) {
        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            if let Some(form) = machines.form.as_mut() {
                form.step = AddStep::Working;
                form.pending = true;
                form.error = None;
            }
        }
    }

    fn enter_add_form_or_pick(&mut self) {
        let Some(Overlay::Machines(machines)) = self.overlay.as_mut() else {
            return;
        };
        let empty = machines.candidates.is_empty();
        let Some(add) = machines.add.as_mut() else {
            return;
        };
        if empty {
            add.step = AddStep::Form;
            add.field = add.form_field();
        } else {
            add.step = AddStep::Pick;
            add.candidate = 0;
        }
    }

    fn commit_add_pick(&mut self) {
        let Some(Overlay::Machines(machines)) = self.overlay.as_mut() else {
            return;
        };
        let index = machines.add.as_ref().map(|add| add.candidate).unwrap_or(0);
        let candidate = machines.candidates.get(index).cloned();
        let Some(add) = machines.add.as_mut() else {
            return;
        };
        if let Some(candidate) = candidate {
            add.apply_candidate(&candidate);
        }
        add.step = AddStep::Form;
        add.field = add.form_field();
    }

    fn add_machine_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let standalone = self.fleet_profile.is_none();
        let step = match self.overlay.as_ref() {
            Some(Overlay::Machines(machines)) => machines.add.as_ref().map(|add| add.step),
            _ => None,
        };
        let Some(step) = step else {
            return;
        };

        match step {
            AddStep::Working => {
                if matches!(key.code, KeyCode::Esc) {
                    if self.quit == Some(Quit::ApplyFleetIntent) {
                        return;
                    }
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            add.step = AddStep::Confirm;
                            add.pending = false;
                            add.error = Some(
                                "cancelled waiting; the remote work may still be running".into(),
                            );
                        }
                    }
                }
            }
            AddStep::Method => match key.code {
                KeyCode::Esc => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        machines.add = None;
                    }
                }
                KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            add.method = AddMethod::Ssh;
                        }
                    }
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            add.method = AddMethod::Prepare;
                        }
                    }
                }
                KeyCode::Enter => self.enter_add_form_or_pick(),
                _ => {}
            },
            AddStep::Pick => match key.code {
                KeyCode::Esc => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            add.step = AddStep::Method;
                        }
                    }
                }
                KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            add.candidate = add.candidate.saturating_sub(1);
                        }
                    }
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        let last = machines.candidates.len();
                        if let Some(add) = machines.add.as_mut() {
                            add.candidate = (add.candidate + 1).min(last);
                        }
                    }
                }
                KeyCode::Char(digit) if digit.is_ascii_digit() && digit != '0' => {
                    let index = (digit as u8 - b'1') as usize;
                    let in_range = match self.overlay.as_ref() {
                        Some(Overlay::Machines(machines)) => index < machines.candidates.len(),
                        _ => false,
                    };
                    if in_range {
                        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                            if let Some(add) = machines.add.as_mut() {
                                add.candidate = index;
                            }
                        }
                        self.commit_add_pick();
                    }
                }
                KeyCode::Enter => self.commit_add_pick(),
                _ => {}
            },
            AddStep::Form => match key.code {
                KeyCode::Esc => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        let next = if machines.candidates.is_empty() {
                            AddStep::Method
                        } else {
                            AddStep::Pick
                        };
                        if let Some(add) = machines.add.as_mut() {
                            add.step = next;
                        }
                    }
                }
                KeyCode::Tab | KeyCode::Down => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            let fields = add.fields(standalone);
                            let index = fields
                                .iter()
                                .position(|field| *field == add.field)
                                .unwrap_or(0);
                            add.field = fields[(index + 1) % fields.len()];
                        }
                    }
                }
                KeyCode::BackTab | KeyCode::Up => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            let fields = add.fields(standalone);
                            let index = fields
                                .iter()
                                .position(|field| *field == add.field)
                                .unwrap_or(0);
                            add.field = fields[(index + fields.len() - 1) % fields.len()];
                        }
                    }
                }
                KeyCode::Left | KeyCode::Right => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            if add.field == AddField::Via {
                                add.via = 1 - add.via;
                            }
                        }
                    }
                }
                KeyCode::Enter => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            add.step = AddStep::Confirm;
                        }
                    }
                }
                KeyCode::Char(c) if !c.is_control() => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            match add.field {
                                AddField::Target => add.target.push(c),
                                AddField::Machine => add.machine.push(c),
                                AddField::Host => add.host.push(c),
                                AddField::Binary => add.binary.push(c),
                                AddField::OwnerHost => add.owner_host.push(c),
                                AddField::OwnerMachine => add.owner_machine.push(c),
                                AddField::Via => {}
                            }
                        }
                    }
                }
                KeyCode::Backspace => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            let buffer = match add.field {
                                AddField::Target => &mut add.target,
                                AddField::Machine => &mut add.machine,
                                AddField::Host => &mut add.host,
                                AddField::Binary => &mut add.binary,
                                AddField::OwnerHost => &mut add.owner_host,
                                AddField::OwnerMachine => &mut add.owner_machine,
                                AddField::Via => return,
                            };
                            buffer.pop();
                        }
                    }
                }
                _ => {}
            },
            AddStep::Confirm => match key.code {
                KeyCode::Esc => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        if let Some(add) = machines.add.as_mut() {
                            add.step = AddStep::Form;
                        }
                    }
                }
                KeyCode::Char('y') => {
                    let command = self.add_command_preview();
                    self.copy_pending = Some(command.clone());
                    self.inform(format!("copied `{command}`"), NoticeKind::Info);
                }
                KeyCode::Enter => self.confirm_add_machine(),
                _ => {}
            },
            AddStep::Done => match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                        machines.add = None;
                    }
                }
                KeyCode::Char('y') => {
                    let recipe = match self.overlay.as_ref() {
                        Some(Overlay::Machines(machines)) => {
                            machines.add.as_ref().and_then(|add| add.recipe.clone())
                        }
                        _ => None,
                    };
                    if let Some(recipe) = recipe {
                        self.copy_pending = Some(recipe);
                        self.inform("copied the enroll recipe", NoticeKind::Info);
                    }
                }
                _ => {}
            },
        }
    }

    pub fn add_command_preview(&self) -> String {
        let Some(Overlay::Machines(machines)) = self.overlay.as_ref() else {
            return MachineAction::Add.command().into();
        };
        let Some(add) = machines.add.as_ref() else {
            return MachineAction::Add.command().into();
        };
        match add.method {
            AddMethod::Prepare => {
                let mut command = format!(
                    "ouro fleet add --print-script --machine {} --host {}",
                    add.machine.trim(),
                    add.host.trim()
                );
                if self.fleet_profile.is_none() {
                    command.push_str(" --init");
                    if !add.owner_machine.trim().is_empty() {
                        command.push_str(&format!(" --owner-machine {}", add.owner_machine.trim()));
                    }
                    if !add.owner_host.trim().is_empty() {
                        command.push_str(&format!(" --owner-host {}", add.owner_host.trim()));
                    }
                }
                command
            }
            AddMethod::Ssh => {
                let mut command = format!(
                    "ouro fleet add {} --machine {} --host {} --via {}",
                    add.target.trim(),
                    add.machine.trim(),
                    add.host.trim(),
                    add.via_label()
                );
                if !add.binary.trim().is_empty() {
                    command.push_str(&format!(" --binary {}", add.binary.trim()));
                }
                if self.fleet_profile.is_none() {
                    command.push_str(" --init");
                    if !add.owner_machine.trim().is_empty() {
                        command.push_str(&format!(" --owner-machine {}", add.owner_machine.trim()));
                    }
                    if !add.owner_host.trim().is_empty() {
                        command.push_str(&format!(" --owner-host {}", add.owner_host.trim()));
                    }
                }
                command
            }
        }
    }

    fn confirm_add_machine(&mut self) {
        if !self.spawned() && self.fleet_profile.is_none() {
            self.set_add_error(
                "this client is attached to a standalone runtime it did not start. Run `ouro` on this Mac (not `ouro attach`) to create the fleet from here",
            );
            return;
        }
        if self.fleet_profile.is_some() && !self.can_invite {
            self.set_add_error(
                "this machine joined the fleet and cannot invite others; run Add on the original owner",
            );
            return;
        }

        let standalone = self.fleet_profile.is_none();
        let snapshot = match self.overlay.as_ref() {
            Some(Overlay::Machines(machines)) => machines.add.clone(),
            _ => None,
        };
        let Some(add) = snapshot else {
            return;
        };

        let machine = add.machine.trim().to_string();
        let host = add.host.trim().to_string();
        if machine.is_empty() || host.is_empty() {
            self.set_add_error("machine name and fleet host are required");
            self.set_add_step(AddStep::Form, None);
            return;
        }
        if let Err(error) = crate::fleet::validate_machine(&machine) {
            self.set_add_error(format!("{error:#}"));
            self.set_add_step(AddStep::Form, None);
            return;
        }

        if standalone {
            let owner_host = add.owner_host.trim().to_string();
            if owner_host.is_empty() {
                self.set_add_error(
                    "this Mac needs its Tailscale MagicDNS name or private IPv4 address in owner host",
                );
                self.set_add_step(AddStep::Form, Some(AddField::OwnerHost));
                return;
            }
            let owner_machine = {
                let named = add.owner_machine.trim();
                if named.is_empty() {
                    crate::fleet::machine_from_host(&owner_host).unwrap_or_else(|_| "studio".into())
                } else {
                    named.to_string()
                }
            };
            let intent = FleetIntent {
                schema: 1,
                owner_machine,
                owner_host,
                fleet_name: None,
                add: Some(AddPlan {
                    kind: match add.method {
                        AddMethod::Ssh => AddKind::Ssh,
                        AddMethod::Prepare => AddKind::Prepare,
                    },
                    machine,
                    host,
                    target: (add.method == AddMethod::Ssh)
                        .then(|| add.target.trim().to_string())
                        .filter(|target| !target.is_empty()),
                    via: add.via_label().into(),
                    binary: {
                        let binary = add.binary.trim();
                        (!binary.is_empty()).then(|| binary.to_string())
                    },
                }),
            };
            if intent
                .add
                .as_ref()
                .is_some_and(|add| add.kind == AddKind::Ssh && add.target.is_none())
            {
                self.set_add_error("SSH add needs user@host (or a Tailscale name)");
                self.set_add_step(AddStep::Form, Some(AddField::Target));
                return;
            }
            self.fleet_intent_pending = Some(intent);
            if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                if let Some(add) = machines.add.as_mut() {
                    add.step = AddStep::Working;
                    add.pending = true;
                    add.error = None;
                }
            }
            self.quit = Some(Quit::ApplyFleetIntent);
            return;
        }

        if add.method == AddMethod::Ssh && add.target.trim().is_empty() {
            self.set_add_error("SSH add needs user@host (or a Tailscale name)");
            self.set_add_step(AddStep::Form, Some(AddField::Target));
            return;
        }

        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            if let Some(add) = machines.add.as_mut() {
                add.step = AddStep::Working;
                add.pending = true;
                add.error = None;
            }
        }
        self.fleet_job_pending = Some(FleetJob::Add {
            prepare: add.method == AddMethod::Prepare,
            target: (add.method == AddMethod::Ssh)
                .then(|| add.target.trim().to_string())
                .filter(|target| !target.is_empty()),
            machine,
            host,
            via: add.via_label().into(),
            binary: {
                let binary = add.binary.trim();
                (!binary.is_empty()).then(|| binary.to_string())
            },
        });
    }

    fn set_add_error(&mut self, error: impl Into<String>) {
        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            if let Some(add) = machines.add.as_mut() {
                add.error = Some(error.into());
            }
        }
    }

    fn set_add_step(&mut self, step: AddStep, field: Option<AddField>) {
        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            if let Some(add) = machines.add.as_mut() {
                add.step = step;
                if let Some(field) = field {
                    add.field = field;
                }
            }
        }
    }
}

fn friendly_machine(node: &str) -> String {
    node.split_once('@')
        .map(|(name, _host)| name)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("this machine")
        .to_string()
}
