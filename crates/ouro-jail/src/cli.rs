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

use clap::{Args, Parser, Subcommand};

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

/// The five verbs of §6.1.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Prepare a boundary and run PROGRAM under it.
    Run(Box<RunArgs>),
    /// Render the requested policy without probing or executing. Boxed:
    /// `ExplainArgs` carries the full override set and dwarfs the rest.
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
    /// Set a ceiling: `wall`, `pids`, `mem` or `cpu`.
    #[arg(long = "limit", value_name = "KEY=VALUE")]
    pub limit: Vec<String>,
    /// Observation mode; the default is `on`.
    #[arg(long, value_name = "on|off", value_parser = ["on", "off"])]
    pub observe: Option<String>,
    /// Evidence mode; the default is `strict`.
    #[arg(long, value_name = "strict|best-effort", value_parser = ["strict", "best-effort"])]
    pub evidence: Option<String>,
}

/// `ouro-jail run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Policy selection and overrides.
    #[command(flatten)]
    pub policy: PolicyArgs,
    /// Write an additional atomically replaced receipt copy here.
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
/// §6.1 spells `doctor [--profile NAME|FILE] [--launch NAME] [--json]`: the
/// policy override flags are not part of this verb's grammar, so they are
/// simply not defined here and clap refuses them as usage errors (§6.4).
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Built-in profile name or a policy file path.
    #[arg(long, value_name = "agent|tool|build|none|FILE")]
    pub profile: Option<String>,
    /// Launch profile name.
    #[arg(long, value_name = "NAME")]
    pub launch: Option<String>,
    /// Print JSON on stdout instead of text.
    #[arg(long)]
    pub json: bool,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_definition_is_internally_consistent() {
        Cli::command().debug_assert();
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

    #[test]
    fn an_unknown_observation_mode_is_a_usage_error() {
        let error =
            Cli::try_parse_from(["ouro-jail", "run", "--observe", "maybe", "--", "/bin/true"])
                .expect_err("a usage error");
        assert_eq!(error.exit_code(), 2);
    }
}
