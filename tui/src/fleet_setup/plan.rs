//! The concrete plan an operator approves.
//!
//! One concrete plan before any mutation — target identity and account, resolved private
//! address, version, paths, service behaviour, and any required idle-runtime restart —
//! plus the statement that joining grants broad authority between the fleet's machines.
//!
//! §6 deleted the plan digest. It existed so an approval could not be replayed against a
//! plan whose facts had since changed, and the facts it guarded were mostly the roster
//! ceremony that §1 withdrew. What is left is [`Plan::lines`]: the sentences a person
//! read, written into the journal exactly as they were shown.
//!
//! Everything here is non-secret by construction. There is no field for a cookie, a key
//! or a password, and the whole document is shown to whoever is watching.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::OperationKind;

/// The machine the work runs on. The proposal insists this is stated on every surface,
/// because for the web UI it is the runtime's host and *not* the browser's laptop.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeploymentHost {
    pub hostname: String,
    pub user: String,
    pub os: String,
    pub arch: String,
    /// Whether this machine holds the fleet CA key, which is what makes it the issuer.
    pub issuer: bool,
}

impl DeploymentHost {
    /// This machine, as far as it can say without asking anything.
    ///
    /// `issuer` is *observed* — whether the fleet CA key is here — rather than asserted
    /// by the caller, because the header an operator reads before typing a password must
    /// not be able to claim an authority this machine does not hold.
    pub fn here(data_dir: &std::path::Path) -> Self {
        let build = crate::fleet_protocol::build_metadata();
        Self {
            hostname: hostname(),
            user: account(),
            os: build.os,
            arch: build.arch,
            issuer: crate::fleet::fleet_dir(data_dir)
                .join(crate::fleet::CA_KEY_FILE)
                .try_exists()
                .unwrap_or(false),
        }
    }
}

fn hostname() -> String {
    let mut buffer = [0_i8; 256];
    // SAFETY: the buffer is initialized local storage of exactly the length passed.
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len() - 1) };
    if result != 0 {
        return "unknown".to_string();
    }
    let bytes: Vec<u8> = buffer
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn account() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| format!("uid {}", unsafe { libc::geteuid() }))
}

/// Where the operation is going, after the address has been resolved and verified.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlanTarget {
    pub machine: String,
    pub address: String,
    pub port: u16,
    pub ssh_user: String,
    /// The identity method, by label — never a key's contents.
    pub identity: String,
    pub install_path: String,
    #[serde(default)]
    pub data_dir: Option<String>,
    /// The host key this operation trusts, so the reviewed plan names it.
    #[serde(default)]
    pub host_fingerprint: Option<String>,
    /// The node name the target will answer to.
    #[serde(default)]
    pub node: Option<String>,
}

/// The exact artifact a missing-binary install would fetch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlanRelease {
    pub version: String,
    pub target: String,
    pub asset: String,
    pub sha256: String,
    /// `false` when a harness origin is in force, so a reviewed plan cannot hide it.
    pub official_origin: bool,
}

/// One machine whose roster this operation edits.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlanMember {
    pub machine: String,
    pub host: String,
    /// `local` or `ssh`.
    pub reached_by: String,
    pub change: String,
    /// `user@address port N` for a member this operation will connect to, so the review
    /// names every machine it is about to authenticate to rather than only the target.
    #[serde(default)]
    pub ssh: Option<String>,
}

/// What the operation intends to do about startup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicePlan {
    /// Propose a managed user service.
    Managed,
    /// Explicitly labelled manual startup (`--no-service`).
    Manual,
}

impl ServicePlan {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::Manual => "manual",
        }
    }
}

/// The reviewed plan.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Plan {
    pub schema: u8,
    pub operation: String,
    pub kind: OperationKind,
    /// One sentence saying what approving this does, in the order it happens.
    ///
    /// The surfaces render the document's fields rather than [`Self::render`]'s text, so
    /// the sentence a person actually decides on has to *be* a field. Defaulted so a
    /// journal written by an older build still parses; every plan this build makes has
    /// one, and it is inside the digest like every other fact. Preserve the old shape
    /// when absent so its recorded approval can still be checked before migration.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    pub deployment_host: DeploymentHost,
    pub target: PlanTarget,
    #[serde(default)]
    pub release: Option<PlanRelease>,
    pub service: ServicePlan,
    /// The fleet this operation joins the target to, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet: Option<String>,
    pub members: Vec<PlanMember>,
    /// The idle restart this operation needs, when it needs one.
    #[serde(default)]
    pub restart: Option<String>,
    /// What accepting this grants. Stated, never implied.
    pub grants: Vec<String>,
    /// The build contract both sides agreed on, for the record.
    #[serde(default)]
    pub build: Option<Value>,
}

impl Plan {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    /// Recompute [`Self::summary`] from the plan's own facts.
    ///
    /// The sentence is a *rendering* of the rest of the document, so it is derived and
    /// never remembered. A resumed `add` restores the release its approval named after
    /// the plan has been built — the binary is on the target by then, so planning it
    /// fresh finds nothing to install — and a sentence computed before that restore
    /// would say the operation installs nothing, change the digest, and turn every
    /// resume into `plan_changed`. Whoever edits a plan calls this afterwards.
    pub fn refresh_summary(&mut self) {
        self.summary = match self.kind {
            OperationKind::Add => add_summary(
                &self.target.machine,
                &self.target.address,
                self.release.is_some(),
            ),
            OperationKind::Setup => setup_summary(&self.target.machine, &self.target.address),
            OperationKind::Leave => leave_summary(&self.target.machine),
        };
    }

    /// The plan lines §6 names, in order: what an operator is agreeing to, one clause
    /// each. These are what the journal records and what a `review` challenge carries.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match self.kind {
            OperationKind::Add => {
                match &self.release {
                    Some(release) => lines.push(format!(
                        "Install ouro {} ({}) to {}",
                        release.version, release.target, self.target.install_path
                    )),
                    None => lines.push(format!(
                        "Use the ouro already at {}",
                        self.target.install_path
                    )),
                }
                lines.push(format!(
                    "Join {} as {}",
                    self.fleet_name(),
                    self.target.machine
                ));
                lines.push(match self.service {
                    ServicePlan::Managed => "Start at login as a user service".to_string(),
                    ServicePlan::Manual => "Manual start, explicitly chosen".to_string(),
                });
                lines.push(format!("Remember {} on this machine", self.target.machine));
            }
            OperationKind::Setup => {
                lines.push(format!(
                    "Create a fleet on this machine as {} ({})",
                    self.target.machine, self.target.address
                ));
                lines.push(match self.service {
                    ServicePlan::Managed => "Start at login as a user service".to_string(),
                    ServicePlan::Manual => "Manual start, explicitly chosen".to_string(),
                });
            }
            OperationKind::Leave => lines.push(removal_note(&self.target.machine)),
        }
        lines
    }

    /// The fleet this plan joins a machine to, when the plan names one.
    fn fleet_name(&self) -> String {
        self.fleet
            .clone()
            .unwrap_or_else(|| "this fleet".to_string())
    }

    /// The lines an operator reads before answering. Deliberately plain: the same text
    /// appears in a terminal, in a `--dry-run`, and (through the broker) in the UI.
    pub fn render(&self) -> String {
        let mut text = String::new();
        // The header the proposal requires on every surface, because for the web UI this
        // is the runtime's host and not the browser's laptop. The authority note is
        // observed, and a first setup is the one case where not holding the CA key yet
        // is the point rather than a problem.
        let authority = match (self.kind, self.deployment_host.issuer) {
            (_, true) => "",
            (OperationKind::Setup, false) => " · this machine will hold the fleet's CA key",
            (_, false) => " · this machine does not hold the fleet's CA key",
        };
        text.push_str(&format!(
            "Deploying from {} · local user {}{authority}\n",
            self.deployment_host.hostname, self.deployment_host.user,
        ));
        if !self.summary.is_empty() {
            text.push_str(&format!("{}\n", self.summary));
        }
        text.push_str(&format!("\n  operation    {}\n", self.operation));
        text.push_str(&format!("  action       {}\n", self.kind.as_str()));
        text.push_str(&format!("  machine      {}\n", self.target.machine));
        text.push_str(&format!("  address      {}\n", self.target.address));
        if !self.target.ssh_user.is_empty() {
            text.push_str(&format!(
                "  ssh          {}@{} port {}\n",
                self.target.ssh_user, self.target.address, self.target.port
            ));
            text.push_str(&format!("  identity     {}\n", self.target.identity));
        }
        if let Some(fingerprint) = &self.target.host_fingerprint {
            text.push_str(&format!("  host key     {fingerprint}\n"));
        }
        if let Some(node) = &self.target.node {
            text.push_str(&format!("  node         {node}\n"));
        }
        if !self.target.install_path.is_empty() {
            text.push_str(&format!("  executable   {}\n", self.target.install_path));
        }
        if let Some(data_dir) = &self.target.data_dir {
            text.push_str(&format!("  data dir     {data_dir}\n"));
        }
        match &self.release {
            Some(release) => {
                text.push_str(&format!(
                    "  install      ouro {} ({}) sha256 {}\n",
                    release.version,
                    release.target,
                    &release.sha256[..release.sha256.len().min(16)]
                ));
                if !release.official_origin {
                    text.push_str(
                        "  origin       a loopback test origin, not the official release\n",
                    );
                }
            }
            None => text.push_str("  install      not needed; the target already has ouro\n"),
        }
        text.push_str(&format!(
            "  startup      {}\n",
            match self.service {
                ServicePlan::Managed =>
                    "propose a user service (starts at login; on Linux also at boot, when lingering can be enabled)",
                ServicePlan::Manual => "manual start, explicitly chosen",
            }
        ));
        if self.members.is_empty() {
            text.push_str("  members      none\n");
        } else {
            text.push_str("  members      ");
            for (index, member) in self.members.iter().enumerate() {
                if index > 0 {
                    text.push_str("               ");
                }
                text.push_str(&format!(
                    "{} ({}, {}, via {})\n",
                    member.machine, member.host, member.change, member.reached_by
                ));
                if let Some(ssh) = &member.ssh {
                    text.push_str(&format!("               ssh {ssh}\n"));
                }
            }
        }
        if let Some(restart) = &self.restart {
            text.push_str(&format!("  restart      {restart}\n"));
        }
        if !self.grants.is_empty() {
            text.push('\n');
            for grant in &self.grants {
                text.push_str(&format!("  ! {grant}\n"));
            }
        }
        text
    }
}

/// What a `leave` does, in one line, in the order it happens (§6).
pub fn leave_summary(machine: &str) -> String {
    removal_note(machine)
}

/// The same one-liner for a join.
pub fn add_summary(machine: &str, address: &str, installing: bool) -> String {
    format!(
        "{install} {machine} ({address}) into this fleet and remember it here.",
        install = if installing {
            "Install Ouroboros on and join"
        } else {
            "Join"
        }
    )
}

/// And for a first setup.
pub fn setup_summary(machine: &str, address: &str) -> String {
    format!("Create a fleet on this machine as {machine} ({address}).")
}

/// The sentence the proposal requires an acceptance to explain, in one place so every
/// surface says the same thing.
pub fn admission_grant() -> String {
    "Joining grants broad authority between this fleet's machines: connected nodes can \
     run work for each other and read each other's sessions. Add only machines you \
     administer and trust."
        .to_string()
}

/// §6's review sentence for `leave --machine`, word for word.
pub fn removal_note(machine: &str) -> String {
    format!(
        "Stop Ouroboros on {machine}, remove its fleet credentials and its startup service, \
         forget it here. Its sessions and data stay on that machine."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            schema: super::super::SCHEMA,
            operation: "op-0123456789ab".into(),
            kind: OperationKind::Add,
            summary: add_summary("buildbox", "100.64.0.2", false),
            deployment_host: DeploymentHost {
                hostname: "studio".into(),
                user: "me".into(),
                os: "macos".into(),
                arch: "aarch64".into(),
                issuer: true,
            },
            target: PlanTarget {
                machine: "buildbox".into(),
                address: "100.64.0.2".into(),
                port: 22,
                ssh_user: "me".into(),
                identity: "agent identity work (SHA256:abc)".into(),
                install_path: "/home/me/.local/bin/ouro".into(),
                data_dir: None,
                host_fingerprint: Some("SHA256:zzz".into()),
                node: Some("ouro-buildbox@100.64.0.2".into()),
            },
            release: None,
            service: ServicePlan::Managed,
            fleet: Some("studio's fleet".into()),
            members: Vec::new(),
            restart: None,
            grants: vec![admission_grant()],
            build: None,
        }
    }

    /// Everything the review has to show is on the page, and nothing a secret would
    /// look like is. §6 deleted the digest line.
    #[test]
    fn the_review_shows_every_fact_the_contract_requires() {
        let rendered = plan().render();
        for required in [
            "Deploying from studio · local user me",
            "machine      buildbox",
            "address      100.64.0.2",
            "ssh          me@100.64.0.2 port 22",
            "host key     SHA256:zzz",
            "executable   /home/me/.local/bin/ouro",
            "startup      propose a user service",
            "broad authority",
        ] {
            assert!(
                rendered.contains(required),
                "missing `{required}`:\n{rendered}"
            );
        }
        assert!(!rendered.contains("plan digest"), "§6 deleted the digest");
        assert!(!rendered.to_lowercase().contains("cookie"));
        assert!(!rendered.to_lowercase().contains("password"));
    }

    /// §6's `add` review is four clauses, in order.
    #[test]
    fn an_add_plan_reads_as_the_four_clauses_the_contract_names() {
        let mut plan = plan();
        plan.release = Some(PlanRelease {
            version: "0.1.10".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            asset: "ouro-0.1.10-x86_64-unknown-linux-gnu".into(),
            sha256: "f".repeat(64),
            official_origin: true,
        });
        assert_eq!(
            plan.lines(),
            vec![
                "Install ouro 0.1.10 (x86_64-unknown-linux-gnu) to /home/me/.local/bin/ouro"
                    .to_string(),
                "Join studio's fleet as buildbox".to_string(),
                "Start at login as a user service".to_string(),
                "Remember buildbox on this machine".to_string(),
            ]
        );
    }

    /// And §6's `leave` review is one sentence, word for word.
    #[test]
    fn a_leave_plan_states_what_it_does_and_what_it_leaves_alone() {
        let mut plan = plan();
        plan.kind = OperationKind::Leave;
        plan.summary = leave_summary("buildbox");
        plan.grants = vec![removal_note("buildbox")];
        assert_eq!(
            plan.lines(),
            vec![
                "Stop Ouroboros on buildbox, remove its fleet credentials and its startup \
                 service, forget it here. Its sessions and data stay on that machine."
                    .to_string()
            ]
        );
        let rendered = plan.render();
        assert!(rendered.contains("its sessions and data stay on that machine"));
        assert!(
            !rendered.to_lowercase().contains("tombstone"),
            "tombstones are gone"
        );
    }

    /// A plan that needs an install names the exact artifact and flags a non-official
    /// origin, so a harness cannot be reviewed as if it were the real release.
    #[test]
    fn a_plan_with_an_install_names_the_artifact_and_any_unofficial_origin() {
        let mut plan = plan();
        plan.release = Some(PlanRelease {
            version: "0.1.8".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            asset: "ouro-0.1.8-x86_64-unknown-linux-gnu".into(),
            sha256: "f".repeat(64),
            official_origin: false,
        });
        plan.restart = Some("this machine's runtime must be idle and will be restarted".into());
        let rendered = plan.render();
        assert!(rendered.contains("install      ouro 0.1.8 (x86_64-unknown-linux-gnu)"));
        assert!(rendered.contains("a loopback test origin, not the official release"));
        assert!(rendered.contains("restart      this machine's runtime must be idle"));
    }
}
