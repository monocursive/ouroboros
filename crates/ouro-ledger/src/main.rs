//! CLI for the local evidence writer and gated launch owner.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use ouro_ledger::{
    daemon,
    protocol::{LedgerError, Result},
    runner,
};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(
    name = "ouro-ledger",
    version,
    about = "Durable admission and evidence around ouro-jail"
)]
struct Cli {
    /// Private node data directory, shared with the jail (also OURO_DATA_DIR).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Announce component and accepted wire schemas.
    Version {
        #[arg(long)]
        json: bool,
    },
    /// Run the single local writer in the foreground.
    Serve,
    /// Reserve a durable request id without launching any child.
    Prepare {
        #[arg(long)]
        request_id: String,
        /// Canonical request metadata; contains digests, never raw argv or environment.
        #[arg(long)]
        body_file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Resolve, reserve, durably admit and launch one jail attempt.
    Run(Box<RunArgs>),
    /// List durable runs.
    Runs {
        #[arg(long)]
        json: bool,
    },
    /// Inspect a run's outcome, coverage and protection independently.
    Show {
        run_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Verify canonical bytes, hash chains, and durable projections.
    Verify {
        run_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Reconcile dead owners without relaunching their attempts.
    SettleOrphans {
        #[arg(long)]
        json: bool,
    },
    /// Check the local writer and store; does not measure jail capabilities.
    Doctor {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
struct RunArgs {
    #[arg(long)]
    request_id: Option<String>,
    #[arg(long)]
    prepared: Option<String>,
    #[arg(long)]
    jail_bin: Option<PathBuf>,
    #[arg(long, default_value = "tool")]
    jail: String,
    #[arg(long)]
    launch: Option<String>,
    #[arg(long)]
    workspace: Option<PathBuf>,
    #[arg(long)]
    scratch: Option<PathBuf>,
    #[arg(long)]
    ro: Vec<PathBuf>,
    #[arg(long)]
    rw: Vec<PathBuf>,
    #[arg(long)]
    deny_read: Vec<PathBuf>,
    #[arg(long)]
    allow_host: Vec<String>,
    #[arg(long)]
    limit: Vec<String>,
    #[arg(long,value_parser=["on","off"],default_value="on")]
    observe: String,
    #[arg(long,value_parser=["strict","best-effort"],default_value="strict")]
    evidence: String,
    #[arg(long,value_parser=["foreground","batch"],default_value="foreground")]
    io: String,
    #[arg(long,value_parser=["stdout","stderr"])]
    capture: Vec<String>,
    #[arg(long, default_value_t = 1_048_576)]
    capture_limit: u64,
    /// JSON control requires batch mode so it cannot mix with child output.
    #[arg(long)]
    json: bool,
    #[arg(last = true, required = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

fn data_dir(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit.or_else(|| std::env::var_os("OURO_DATA_DIR").map(PathBuf::from)) {
        if !path.is_absolute() {
            return Err(LedgerError("data directory must be absolute".into()));
        }
        return Ok(path);
    }
    if let Some(base) = std::env::var_os("XDG_DATA_HOME") {
        let path = PathBuf::from(base);
        if path.is_absolute() {
            return Ok(path.join("ouro"));
        }
        return Err(LedgerError("XDG_DATA_HOME must be absolute".into()));
    }
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".local/share/ouro"))
        .ok_or_else(|| LedgerError("HOME is absent; use --data-dir".into()))
}

fn output(value: &Value, json_output: bool) -> Result<()> {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    if json_output {
        serde_json::to_writer(&mut stdout, value)?;
        writeln!(stdout)?;
    } else {
        writeln!(stdout, "{}", serde_json::to_string_pretty(value)?)?;
    }
    Ok(())
}

fn execute(cli: Cli) -> Result<i32> {
    let data = data_dir(cli.data_dir)?;
    match cli.command {
        Action::Version { json } => {
            output(
                &json!({"component":"ouro-ledger","version":env!("CARGO_PKG_VERSION"),"schemas":{"run":"ouro.ledger.run/1","event":ouro_records::records::SCHEMA_EVENT,"receipt":ouro_records::records::SCHEMA_RECEIPT},"schema_frozen":false,"execution_platform":"linux"}),
                json,
            )?;
            Ok(0)
        }
        Action::Serve => {
            daemon::serve(&data)?;
            Ok(0)
        }
        Action::Run(args) => {
            if args.json && args.io != "batch" {
                return Err(LedgerError(
                    "run --json requires --io batch so child output has an independent sink".into(),
                ));
            }
            let mut policy: Vec<OsString> = vec![
                "--profile".into(),
                args.jail.into(),
                "--observe".into(),
                args.observe.into(),
                "--evidence".into(),
                args.evidence.clone().into(),
            ];
            for (name, path) in [("--workspace", args.workspace), ("--scratch", args.scratch)] {
                if let Some(path) = path {
                    policy.push(name.into());
                    policy.push(path.into_os_string());
                }
            }
            for (name, paths) in [
                ("--ro", args.ro),
                ("--rw", args.rw),
                ("--deny-read", args.deny_read),
            ] {
                for path in paths {
                    policy.push(name.into());
                    policy.push(path.into_os_string());
                }
            }
            if let Some(launch) = args.launch {
                policy.push("--launch".into());
                policy.push(launch.into());
            }
            for (name, values) in [("--allow-host", args.allow_host), ("--limit", args.limit)] {
                for value in values {
                    policy.push(name.into());
                    policy.push(value.into());
                }
            }
            let result = runner::run(&runner::RunOptions {
                data,
                jail: runner::jail_binary(args.jail_bin)?,
                request_id: args
                    .request_id
                    .unwrap_or_else(|| format!("req_{}", uuid::Uuid::new_v4())),
                prepared: args.prepared,
                policy_args: policy,
                argv: args.argv,
                batch: args.io == "batch",
                captures: args.capture,
                capture_limit: args.capture_limit,
                best_effort: args.evidence == "best-effort",
            })?;
            if args.json {
                output(&serde_json::to_value(&result.record)?, true)?;
            } else {
                eprintln!(
                    "{}: {} (settlement {}, protection {})",
                    result.record.run_id,
                    result.record.state,
                    result.record.settlement,
                    result.record.child_protection
                );
            }
            Ok(result.exit_code)
        }
        command => {
            let mut client = runner::connect_or_start(&data)?;
            match command {
                Action::Prepare {
                    request_id,
                    body_file,
                    json,
                } => {
                    let file = std::fs::File::open(body_file)?;
                    use std::io::Read as _;
                    let mut bytes = Vec::new();
                    file.take(1_048_577).read_to_end(&mut bytes)?;
                    if bytes.len() > 1_048_576 {
                        return Err(LedgerError("prepare metadata exceeds frame bound".into()));
                    }
                    let payload: Value = serde_json::from_slice(&bytes)?;
                    output(
                        &serde_json::to_value(client.prepare(&request_id, &payload)?)?,
                        json,
                    )?;
                }
                Action::Runs { json } => output(&serde_json::to_value(client.runs()?)?, json)?,
                Action::Show { run_id, json } => {
                    output(&serde_json::to_value(client.show(&run_id)?)?, json)?
                }
                Action::Verify { run_id, json } => {
                    let reports = client.verify(run_id.as_deref())?;
                    let passed = reports.iter().all(|r| r.local_consistency);
                    output(&serde_json::to_value(reports)?, json)?;
                    return Ok(if passed { 0 } else { 1 });
                }
                Action::SettleOrphans { json } => {
                    output(&serde_json::to_value(client.settle_orphans()?)?, json)?
                }
                Action::Doctor { json } => {
                    client.ping()?;
                    let reports = client.verify(None)?;
                    let ready = reports.iter().all(|r| r.local_consistency);
                    output(
                        &json!({"component":"ouro-ledger","ready":ready,"writer":"reachable","store":reports,"execution_platform":"linux","managed_authorization":"not_implemented"}),
                        json,
                    )?;
                    return Ok(if ready { 0 } else { 1 });
                }
                Action::Serve | Action::Run(_) | Action::Version { .. } => unreachable!(),
            }
            Ok(0)
        }
    }
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(1)),
        Err(error) => {
            eprintln!(
                "ouro-ledger: {}",
                ouro_records::records::escape_control(&error.to_string())
            );
            ExitCode::FAILURE
        }
    }
}
