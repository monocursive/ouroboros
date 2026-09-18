//! The concrete plan an operator approves, and the digest that approval is bound to.
//!
//! Seam S6. The proposal requires one concrete plan before any mutation — "target
//! identity/user, resolved private address, version, paths, service behavior, affected
//! roster members, and any required idle-runtime restart" — plus the statement that
//! joining grants broad authority between the fleet's machines. Approval carries
//! `sha256(canonical(plan))`, so an approval cannot be replayed against a plan whose
//! facts have since changed: that is `plan_changed`, and it means a fresh review.
//!
//! Everything here is non-secret by construction. There is no field for a cookie, a key
//! or a password, and the whole document is written into the journal and shown to
//! whoever is watching.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{canonical_json, sha256_hex, OperationKind};

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
    /// one, and it is inside the digest like every other fact.
    #[serde(default)]
    pub summary: String,
    pub deployment_host: DeploymentHost,
    pub target: PlanTarget,
    #[serde(default)]
    pub release: Option<PlanRelease>,
    pub service: ServicePlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_workspace: Option<String>,
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
            // `members` is the machine that is leaving plus every roster this operation
            // edits, so the count of edited rosters is one less than the list.
            OperationKind::Leave => {
                leave_summary(&self.target.machine, self.members.len().saturating_sub(1))
            }
        };
    }

    /// Seam S6's digest: sha256 over the canonical JSON of this document.
    pub fn digest(&self) -> String {
        sha256_hex(canonical_json(&self.to_value()).as_bytes())
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
        if let Some(workspace) = &self.test_workspace {
            text.push_str(&format!("  model check  one turn in {workspace}\n"));
        }
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
        text.push_str(&format!("\n  plan digest  {}\n", self.digest()));
        text
    }
}

/// What a `leave` does, in one line, in the order it happens.
///
/// `rosters` is how many machines' rosters this operation edits — every remaining member
/// including this one, and not the machine that is leaving. The second half is the part
/// people ask about first, and it is the part that is easy to get wrong in a hurry: a
/// removal takes the machine out of the fleet and leaves everything on it alone.
pub fn leave_summary(machine: &str, rosters: usize) -> String {
    format!(
        "Stop Ouroboros on {machine}, retire its credentials, remove it from {rosters} \
         roster{plural}; its sessions and data stay on that machine.",
        plural = if rosters == 1 { "" } else { "s" }
    )
}

/// The same one-liner for an admission.
pub fn add_summary(machine: &str, address: &str, installing: bool) -> String {
    format!(
        "{install} {machine} ({address}) into this fleet and update every member's roster.",
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

/// The sentence a removal has to end with, since the tombstone decision stays separate.
pub fn removal_note(machine: &str) -> String {
    format!(
        "No tombstone is recorded. Session-owner evidence for {machine} is retained, so its \
         sessions stay discoverable; `ouro fleet sessions forget --machine {machine} \
         --accept-state-loss` is the separate, irreversible decision that retires it."
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
            test_workspace: None,
            members: vec![PlanMember {
                machine: "studio".into(),
                host: "100.64.0.1".into(),
                reached_by: "local".into(),
                change: "add buildbox".into(),
                ssh: None,
            }],
            restart: None,
            grants: vec![admission_grant()],
            build: None,
        }
    }

    /// The digest is a property of the plan's values: reordering fields does not change
    /// it, and changing one fact does.
    #[test]
    fn the_digest_follows_the_facts_and_not_the_encoding() {
        let plan = plan();
        let digest = plan.digest();
        assert_eq!(digest.len(), 64);

        let reencoded: Plan =
            serde_json::from_value(plan.to_value()).expect("a round-trippable plan");
        assert_eq!(reencoded.digest(), digest, "a round trip is the same plan");

        let mut moved = plan.clone();
        moved.target.address = "100.64.0.3".into();
        assert_ne!(
            moved.digest(),
            digest,
            "a different address is a different plan"
        );

        let mut service = plan.clone();
        service.service = ServicePlan::Manual;
        assert_ne!(
            service.digest(),
            digest,
            "different startup behaviour is a different plan"
        );
    }

    /// Everything the proposal requires a review to show is on the page, and nothing a
    /// secret would look like is.
    #[test]
    fn the_review_shows_every_fact_the_proposal_requires() {
        let rendered = plan().render();
        for required in [
            "Deploying from studio · local user me",
            "machine      buildbox",
            "address      100.64.0.2",
            "ssh          me@100.64.0.2 port 22",
            "host key     SHA256:zzz",
            "executable   /home/me/.local/bin/ouro",
            "startup      propose a user service",
            "members      studio (100.64.0.1, add buildbox, via local)",
            "broad authority",
            "plan digest",
        ] {
            assert!(
                rendered.contains(required),
                "missing `{required}`:\n{rendered}"
            );
        }
        assert!(!rendered.to_lowercase().contains("cookie"));
        assert!(!rendered.to_lowercase().contains("password"));
    }

    /// A member this operation will connect to is shown with the account it will
    /// authenticate as. The review is where an operator learns which machines are about
    /// to be contacted, and "via ssh" without an account is not that.
    #[test]
    fn a_member_reached_over_ssh_shows_the_account_it_is_reached_as() {
        let mut plan = plan();
        plan.members.push(PlanMember {
            machine: "vps".into(),
            host: "100.64.0.3".into(),
            reached_by: "ssh".into(),
            change: "add buildbox".into(),
            ssh: Some("me@100.64.0.3 port 22".into()),
        });
        let rendered = plan.render();
        assert!(
            rendered.contains("ssh me@100.64.0.3 port 22"),
            "every machine this operation authenticates to is named:\n{rendered}"
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

    /// A `leave` plan says what it does in one line, in a field.
    ///
    /// The surfaces render the document, not [`Plan::render`]'s text, so a sentence that
    /// lived only in the rendering was a sentence the web and the TUI could not show. It
    /// is a field, it is in the digest, and it states the two things a person removing a
    /// machine wants confirmed: what stops, and what stays.
    #[test]
    fn a_leave_plan_states_what_it_does_and_what_it_leaves_alone() {
        let mut plan = plan();
        plan.kind = OperationKind::Leave;
        plan.summary = leave_summary("buildbox", 2);
        plan.grants = vec![removal_note("buildbox")];

        assert_eq!(
            plan.summary,
            "Stop Ouroboros on buildbox, retire its credentials, remove it from 2 rosters; \
             its sessions and data stay on that machine."
        );
        assert_eq!(
            leave_summary("buildbox", 1),
            "Stop Ouroboros on buildbox, retire its credentials, remove it from 1 roster; \
             its sessions and data stay on that machine.",
            "one roster is not `1 rosters`"
        );

        // In the document, and therefore in the digest.
        assert_eq!(
            plan.to_value()["summary"],
            Value::String(plan.summary.clone())
        );
        let digest = plan.digest();
        let mut reworded = plan.clone();
        reworded.summary = "Remove buildbox.".to_string();
        assert_ne!(
            reworded.digest(),
            digest,
            "the sentence an operator approved is one of the facts the approval binds"
        );
        let reencoded: Plan =
            serde_json::from_value(plan.to_value()).expect("a round-trippable plan");
        assert_eq!(
            reencoded.digest(),
            digest,
            "and the digest is still canonical"
        );

        // And it is on the page a terminal prints, above the facts it summarises.
        let rendered = plan.render();
        let summary_at = rendered
            .find("Stop Ouroboros on buildbox")
            .expect("the summary is rendered");
        let operation_at = rendered.find("  operation").expect("the fact list");
        assert!(summary_at < operation_at, "{rendered}");
        assert!(rendered.contains("its sessions and data stay on that machine"));
    }

    /// A journal written before the summary existed still parses, and still digests.
    #[test]
    fn a_plan_from_an_older_build_has_no_summary_rather_than_no_plan() {
        let mut document = plan().to_value();
        document
            .as_object_mut()
            .expect("a plan is an object")
            .remove("summary");
        let older: Plan = serde_json::from_value(document).expect("an older plan still parses");
        assert_eq!(older.summary, "");
        assert_eq!(older.digest().len(), 64);
        assert!(
            !older.render().starts_with('\n'),
            "and it renders without a blank line where the sentence would be"
        );
    }

    /// Removal states the decision it is deliberately not making.
    #[test]
    fn removal_names_the_separate_forget_decision() {
        let note = removal_note("buildbox");
        assert!(note.contains("No tombstone is recorded"));
        assert!(note.contains("sessions forget --machine buildbox --accept-state-loss"));
    }
}
