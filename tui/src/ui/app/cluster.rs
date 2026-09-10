//! The cluster readout the client shares between Settings, the Dashboard, the session
//! lists and the new-session form. It reads `runtime.status` and the local profile and
//! nothing else; no command here changes cluster membership.

use super::*;

/// The small, intentionally non-secret view model shared by Settings, the Dashboard and
/// the session lists. It combines the local profile (what this machine expects) with the
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
    pub fn machine_fact_lines(&self) -> Vec<String> {
        self.status
            .value
            .as_ref()
            .and_then(|status| status.cluster.get("fleet"))
            .and_then(|fleet| fleet.get("machines"))
            .and_then(Value::as_array)
            .map(|machines| {
                machines
                    .iter()
                    .take(4)
                    .map(|machine| {
                        let name = machine
                            .get("machine")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown");
                        format!("{name} · {}", crate::fleet::render_machine_facts(machine))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

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
                    "This machine runs on its own. Start a second runtime with the cluster environment set to form a cluster."
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

                // A profile records what this machine was configured to expect, which can
                // lag what the cluster actually observed. Merge the runtime's last-known
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
    /// offline members are deliberately not selectable: a start form should never invite
    /// a request that the runtime already knows it cannot route.
    pub fn machine_choices(&self) -> Vec<MachineChoice> {
        let mut choices = vec![MachineChoice::Local {
            label: self.local_machine_label(),
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
}

fn friendly_machine(node: &str) -> String {
    node.split_once('@')
        .map(|(name, _host)| name)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("this machine")
        .to_string()
}
