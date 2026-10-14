//! The command line, exactly as jail-v1 §6.1 spells it.
//!
//! `PROGRAM` is mandatory except with `--label-only`, and everything after `--`
//! is taken as literal OS argument bytes: the value parser is `OsString`, so a
//! non-UTF-8 argument reaches the child unchanged and is hashed unchanged.
//! There is no shell command string anywhere.
//!
//! Usage errors exit 2 with clap's own message on stderr (§6.4).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::records::{EvidenceMode, ObserveMode};

/// `ouro-jail`: run one argv under one explicit policy and record what applied.
#[derive(Debug, Parser)]
#[command(
    name = "ouro-jail",
    about = "Run a command under an explicit policy and record what was applied.",
    disable_version_flag = true
)]
pub struct Cli {
    /// The verb.
    #[command(subcommand)]
    pub command: Command,
}

/// The verbs: §6.1's `run`, `explain`, `doctor`, `gc` and `version`, and
/// jail-v2's `tail` and `learn`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Prepare a boundary and run PROGRAM under it.
    Run(Box<RunArgs>),
    /// Replay an attempt's original journal, optionally following it live.
    Tail(TailArgs),
    /// Run contained with read observation and derive a reviewable policy proposal.
    Learn(Box<LearnArgs>),
    // Boxed: `ExplainArgs` carries the full override set and dwarfs the
    // rest. A `//` comment, not `///`: clap renders doc comments as help.
    /// Render the requested policy without probing or executing.
    Explain(Box<ExplainArgs>),
    /// Probe the capabilities the requested plan needs.
    Doctor(DoctorArgs),
    /// Report on registered attempt state.
    Gc(GcArgs),
    /// Print versions and the schema identifiers this build announces.
    Version(VersionArgs),
}

/// Policy selection and override flags, shared by `run` and `explain`
/// (§6.1). `doctor` has the narrower grammar of [`DoctorArgs`].
#[derive(Debug, Default, Args)]
pub struct PolicyArgs {
    /// Built-in profile name or a policy file path.
    #[arg(long, value_name = "agent|tool|build|none|FILE")]
    pub profile: Option<String>,
    /// Launch profile name.
    #[arg(long, value_name = "NAME")]
    pub launch: Option<String>,
    /// The writable workspace root; defaults to the invocation directory.
    #[arg(long, value_name = "PATH")]
    pub workspace: Option<PathBuf>,
    /// An explicit scratch directory; defaults to a private attempt directory.
    #[arg(long, value_name = "PATH")]
    pub scratch: Option<PathBuf>,
    /// Grant a writable path.
    #[arg(long = "rw", value_name = "PATH")]
    pub rw: Vec<PathBuf>,
    /// Grant a visible read-only path.
    #[arg(long = "ro", value_name = "PATH")]
    pub ro: Vec<PathBuf>,
    /// Deny reads beneath a path.
    #[arg(long = "deny-read", value_name = "PATH")]
    pub deny_read: Vec<PathBuf>,
    /// Allow a proxied destination.
    #[arg(long = "allow-host", value_name = "HOST[:PORT]")]
    pub allow_host: Vec<String>,
    /// Set a ceiling: `wall`, `pids`, `mem`, `swap`, `storage`, `inodes` or `cpu`.
    #[arg(long = "limit", value_name = "KEY=VALUE")]
    pub limit: Vec<String>,
    /// Observation mode; the default is `on`.
    #[arg(long, value_name = "on|off", value_enum)]
    pub observe: Option<Observe>,
    /// Evidence mode; the default is `strict`.
    #[arg(long, value_name = "strict|best-effort", value_enum)]
    pub evidence: Option<Evidence>,
}

/// `--observe`, spelled as the policy spells observation modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Observe {
    On,
    Off,
}

impl From<Observe> for ObserveMode {
    fn from(observe: Observe) -> Self {
        match observe {
            Observe::On => ObserveMode::On,
            Observe::Off => ObserveMode::Off,
        }
    }
}

/// `--evidence`, spelled as the policy spells evidence modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Evidence {
    Strict,
    BestEffort,
}

impl From<Evidence> for EvidenceMode {
    fn from(evidence: Evidence) -> Self {
        match evidence {
            Evidence::Strict => EvidenceMode::Strict,
            Evidence::BestEffort => EvidenceMode::BestEffort,
        }
    }
}

/// `ouro-jail run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Policy selection and overrides.
    #[command(flatten)]
    pub policy: PolicyArgs,
    /// Write an additional atomically replaced receipt copy here. An
    /// existing file is replaced only when it is itself a prior receipt
    /// copy; any other file, symlink or device refuses.
    #[arg(long, value_name = "PATH")]
    pub receipt: Option<PathBuf>,
    /// Inherited descriptor for the event stream.
    #[arg(long = "trace-fd", value_name = "N")]
    pub trace_fd: Option<i32>,
    /// Inherited descriptor for control messages.
    #[arg(long = "control-fd", value_name = "N")]
    pub control_fd: Option<i32>,
    /// Inherited descriptor carrying the managed release frame.
    #[arg(long = "gate-fd", value_name = "N", conflicts_with = "label_only")]
    pub gate_fd: Option<i32>,
    /// Bind this attempt to an owner's pre-existing reservation.
    #[arg(
        long = "attempt-id",
        value_name = "ID",
        requires = "gate_fd",
        conflicts_with = "label_only"
    )]
    pub attempt_id: Option<String>,
    /// Resolve, probe and print the proposed label without executing.
    #[arg(long = "label-only")]
    pub label_only: bool,
    /// PROGRAM and its arguments, after `--`.
    #[arg(
        last = true,
        value_name = "PROGRAM",
        allow_hyphen_values = true,
        value_parser = clap::value_parser!(OsString)
    )]
    pub argv: Vec<OsString>,
}

/// `ouro-jail explain`.
#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// Policy selection and overrides.
    #[command(flatten)]
    pub policy: PolicyArgs,
    /// Print JSON on stdout instead of text.
    #[arg(long)]
    pub json: bool,
}

/// `ouro-jail doctor`.
///
/// §6.1 spells `doctor [--profile NAME|FILE] [--launch NAME] [--json]`;
/// `--workspace` and `--scratch` are the same roots `run` accepts, so a
/// doctor call can check the exact plan a launch script will run instead of
/// whichever directory it was invoked from (issue: doctor --launch used the
/// current directory as the workspace).
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Built-in profile name or a policy file path.
    #[arg(long, value_name = "agent|tool|build|none|FILE")]
    pub profile: Option<String>,
    /// Launch profile name.
    #[arg(long, value_name = "NAME")]
    pub launch: Option<String>,
    /// Workspace root, like `run --workspace`; defaults to the current
    /// directory.
    #[arg(long, value_name = "PATH")]
    pub workspace: Option<std::path::PathBuf>,
    /// Scratch root, like `run --scratch`; defaults to the managed scratch.
    #[arg(long, value_name = "PATH")]
    pub scratch: Option<std::path::PathBuf>,
    /// Print JSON on stdout instead of text.
    #[arg(long)]
    pub json: bool,
}

impl DoctorArgs {
    /// The plan this doctor call checks: the policy `run` would resolve from
    /// the same selection flags and roots, with no override (§6.1's doctor
    /// grammar has none).
    #[must_use]
    pub fn policy(&self) -> PolicyArgs {
        PolicyArgs {
            profile: self.profile.clone(),
            launch: self.launch.clone(),
            workspace: self.workspace.clone(),
            scratch: self.scratch.clone(),
            ..PolicyArgs::default()
        }
    }
}

/// `ouro-jail gc`.
#[derive(Debug, Args)]
pub struct GcArgs {
    /// Report what would be done without doing it.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
    /// Print JSON on stdout instead of text.
    #[arg(long)]
    pub json: bool,
}

/// `ouro-jail version`.
#[derive(Debug, Args)]
pub struct VersionArgs {
    /// Print JSON on stdout instead of text.
    #[arg(long)]
    pub json: bool,
}

/// Read-only journal selection.
#[derive(Debug, Args)]
pub struct TailArgs {
    /// Attempt ID; defaults to the most recently updated attempt directory.
    #[arg(long)]
    pub attempt: Option<String>,
    /// Follow until the supervisor releases its attempt lock.
    #[arg(long)]
    pub follow: bool,
    /// Write original NDJSON envelopes without re-encoding them.
    #[arg(long)]
    pub json: bool,
    /// Include events at or after this UTC timestamp.
    #[arg(long)]
    pub since: Option<String>,
}

/// Candidate-policy generation. Proposals never load automatically.
#[derive(Debug, Args)]
pub struct LearnArgs {
    #[command(flatten)]
    pub policy: PolicyArgs,
    /// Proposal TOML output; default is config/learned/ATTEMPT.toml.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Review and adopt the proposals through an interactive terminal.
    #[arg(long)]
    pub adopt: bool,
    /// Minimum observations before proposing an exact path or destination.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    pub min_hits: u32,
    /// Literal command and arguments.
    #[arg(last = true, required = true, allow_hyphen_values = true)]
    pub argv: Vec<OsString>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    /// Help text is operator-facing: every subcommand's summary is its own
    /// sentence, with no implementation note carried over from a doc comment.
    #[test]
    fn subcommand_help_carries_no_implementation_notes() {
        let command = Cli::command();
        for sub in command.get_subcommands() {
            let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
            for leak in ["Boxed", "`", "dwarfs"] {
                assert!(
                    !about.contains(leak),
                    "`{}` help leaks an implementation note: {about}",
                    sub.get_name()
                );
            }
        }
    }

    /// `doctor` checks the plan `run` resolves from the same selection
    /// flags and roots.
    #[test]
    fn doctor_checks_the_policy_run_would_resolve() {
        let selection = [
            "--profile",
            "build",
            "--launch",
            "an-agent",
            "--workspace",
            "/w",
            "--scratch",
            "/s",
        ];
        let parse = |verb: &str, rest: &[&str]| {
            let mut arguments = vec!["ouro-jail", verb];
            arguments.extend(selection);
            arguments.extend(rest);
            Cli::try_parse_from(arguments).expect("parses").command
        };
        let Command::Doctor(doctor) = parse("doctor", &[]) else {
            panic!("not doctor");
        };
        let Command::Run(run) = parse("run", &["--", "/bin/true"]) else {
            panic!("not run");
        };
        assert_eq!(
            format!("{:?}", doctor.policy()),
            format!("{:?}", run.policy)
        );
    }

    #[test]
    fn label_only_rejects_the_gate_and_the_attempt_id() {
        for arguments in [
            vec!["ouro-jail", "run", "--label-only", "--gate-fd", "7"],
            vec![
                "ouro-jail",
                "run",
                "--label-only",
                "--attempt-id",
                "att_00000000-0000-4000-8000-000000000001",
            ],
        ] {
            let error = Cli::try_parse_from(arguments).expect_err("a usage error");
            assert_eq!(error.exit_code(), 2);
        }
    }

    #[test]
    fn an_attempt_id_without_a_gate_is_a_usage_error() {
        let error = Cli::try_parse_from([
            "ouro-jail",
            "run",
            "--attempt-id",
            "att_00000000-0000-4000-8000-000000000001",
            "--",
            "/bin/true",
        ])
        .expect_err("a usage error");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn argv_after_the_separator_is_taken_literally() {
        let cli = Cli::try_parse_from([
            "ouro-jail",
            "run",
            "--",
            "/bin/echo",
            "--profile",
            "-x",
            "a b",
        ])
        .expect("parses");
        let Command::Run(args) = cli.command else {
            panic!("expected run")
        };
        assert_eq!(
            args.argv,
            vec![
                OsString::from("/bin/echo"),
                OsString::from("--profile"),
                OsString::from("-x"),
                OsString::from("a b"),
            ],
            "flags after `--` belong to the child, not to the jail"
        );
        assert_eq!(args.policy.profile, None);
    }

    /// `--observe` and `--evidence` parse to the policy's own modes, with
    /// the spellings the configuration files use.
    #[test]
    fn the_mode_flags_parse_to_the_policy_modes() {
        let cli = Cli::try_parse_from([
            "ouro-jail",
            "explain",
            "--observe",
            "off",
            "--evidence",
            "best-effort",
        ])
        .expect("parses");
        let Command::Explain(args) = cli.command else {
            panic!("expected explain")
        };
        assert_eq!(
            args.policy.observe.map(ObserveMode::from),
            Some(ObserveMode::Off)
        );
        assert_eq!(
            args.policy.evidence.map(EvidenceMode::from),
            Some(EvidenceMode::BestEffort)
        );
        for (flag, value) in [("--observe", "on"), ("--evidence", "strict")] {
            Cli::try_parse_from(["ouro-jail", "explain", flag, value]).expect(value);
        }
        let error = Cli::try_parse_from(["ouro-jail", "explain", "--evidence", "best_effort"])
            .expect_err("only the documented spelling");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn an_unknown_observation_mode_is_a_usage_error() {
        let error =
            Cli::try_parse_from(["ouro-jail", "run", "--observe", "maybe", "--", "/bin/true"])
                .expect_err("a usage error");
        assert_eq!(error.exit_code(), 2);
    }
}
