//! Rust operator front door; OTP coordinates and Rust ledger owns execution.
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    process::{Command, ExitCode, Stdio},
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Top,
}
#[derive(Subcommand)]
enum Top {
    Fleet(Box<Fleet>),
    Version {
        #[arg(long)]
        json: bool,
    },
}
#[derive(Args)]
struct Fleet {
    /// Provisioned private fleet client configuration, including TLS identity.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    Run(Box<Run>),
    Status {
        job: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Wait {
        job: String,
        #[arg(long, default_value_t = 3600)]
        timeout: u64,
        #[arg(long)]
        json: bool,
    },
    Kill {
        job: String,
        #[arg(long,default_value="TERM",value_parser=["TERM"])]
        signal: String,
        #[arg(long)]
        json: bool,
    },
    Ledger {
        job: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        flags: Vec<String>,
    },
    Doctor {
        #[arg(long)]
        json: bool,
    },
}
#[derive(Args)]
struct Run {
    #[arg(long)]
    request_id: String,
    #[arg(long, default_value = "auto")]
    on: String,
    #[arg(long)]
    dir: Option<String>,
    #[arg(long)]
    jail: Option<String>,
    #[arg(long)]
    launch: Option<String>,
    #[arg(long,default_value="on",value_parser=["on","off"])]
    observe: String,
    #[arg(long,default_value="strict",value_parser=["strict","best-effort"])]
    evidence: String,
    #[arg(long)]
    limit: Vec<String>,
    #[arg(long,value_parser=["stdout","stderr"])]
    capture: Vec<String>,
    #[arg(long, default_value_t = 1_048_576)]
    capture_limit: u64,
    #[arg(long)]
    tag: Vec<String>,
    #[arg(long)]
    json: bool,
    #[arg(last = true, required = true, allow_hyphen_values = true)]
    argv: Vec<String>,
}

fn invoke(config: &PathBuf, body: &Value) -> Result<Value, String> {
    let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    if bytes.len() > 524288 {
        return Err("request exceeds 512 KiB".into());
    }
    let meta = fs::symlink_metadata(config).map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() > 1_048_576
    {
        return Err("fleet configuration must be a private regular file".into());
    }
    let settings: Value = serde_json::from_slice(&fs::read(config).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let field = |key: &str| {
        settings[key]
            .as_str()
            .filter(|s| s.starts_with('/') && !s.contains(['\n', '\r', '"', '\\']))
            .ok_or_else(|| format!("invalid absolute configuration path: {key}"))
    };
    let elixir = field("elixir")?;
    let code = field("ebin")?;
    let script = field("client_script")?;
    let tls = field("tls")?;
    if tls.chars().any(char::is_whitespace) {
        return Err("TLS option-file path cannot contain whitespace".into());
    }
    let erl = format!(
        "+S 2:2 -proto_dist inet_tls -start_epmd false -epmd_module Elixir.Ouroboros.Cluster.Epmd -ssl_dist_optfile {tls}"
    );
    let mut child = Command::new(elixir)
        .args(["--erl", &erl, "-pa", code, script])
        .arg(config)
        .env_remove("OURO_FLEET_CONFIG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| e.to_string())?;
    // Include delivery in the deadline: the client may fail during TLS startup
    // before reading stdin, while a large request fills the pipe.
    let mut stdin = child.stdin.take().ok_or("missing request pipe")?;
    let (send_tx, send_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = stdin.write_all(&bytes);
        drop(stdin);
        let _ = send_tx.send(result);
    });
    let stdout = child.stdout.take().ok_or("missing reply pipe")?;
    let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut data = Vec::new();
        let result = stdout.take(1_048_577).read_to_end(&mut data).map(|_| data);
        let _ = reply_tx.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(200);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("fleet reply timed out; retry only the same request id".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let data = reply_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| "fleet reply pipe did not close; outcome unconfirmed")?
        .map_err(|e| e.to_string())?;
    send_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| "fleet request pipe did not close; admission unconfirmed")?
        .map_err(|e| format!("fleet request pipe failed; admission unconfirmed: {e}"))?;
    if data.len() > 1_048_576 {
        return Err("fleet reply exceeded 1 MiB".into());
    }
    let value: Value = serde_json::from_slice(&data)
        .map_err(|_| "invalid fleet reply; outcome unconfirmed".to_string())?;
    if !status.success() || value["ok"] != true {
        return Err(value["error"].to_string());
    }
    Ok(value["result"].clone())
}

fn run(cli: Cli) -> Result<Value, String> {
    let Top::Fleet(fleet) = cli.command else {
        return Ok(
            json!({"component":"ouro","version":env!("CARGO_PKG_VERSION"),"fleet_rpc":"ouro.fleet.rpc/1","job":"ouro.fleet.job/1","attempt":"ouro.fleet.attempt/1","fleet_schema_frozen":false}),
        );
    };
    let config = fleet
        .config
        .ok_or("--config is required for fleet commands")?;
    let body = match fleet.action {
        Action::Run(args) => {
            let mut request = json!({"schema":"ouro.fleet.request/1","request_id":args.request_id,"on":args.on,"observe":args.observe,"evidence":args.evidence,"limits":args.limit,"capture":args.capture,"capture_limit":args.capture_limit,"tags":args.tag,"argv":args.argv});
            if let Some(dir) = args.dir {
                request["dir"] = json!(dir);
            }
            if let Some(jail) = args.jail {
                request["jail"] = json!(jail);
            }
            if let Some(launch) = args.launch {
                request["launch"] = json!(launch);
            }
            json!({"operation":"run","request":request})
        }
        Action::Status { job, .. } => json!({"operation":"status","job":job}),
        Action::Kill { job, .. } => json!({"operation":"kill","job":job}),
        Action::Ledger { job, flags } => json!({"operation":"ledger","job":job,"flags":flags}),
        Action::Doctor { .. } => json!({"operation":"doctor"}),
        Action::Wait { job, timeout, .. } => {
            if !(1..=86400).contains(&timeout) {
                return Err("wait timeout must be 1..86400 seconds".into());
            }
            let deadline = Instant::now() + Duration::from_secs(timeout);
            loop {
                let row = invoke(&config, &json!({"operation":"status","job":job}))?;
                if row["stale"] != true
                    && matches!(
                        row["state"].as_str(),
                        Some("exited" | "refused" | "killed" | "outcome_unknown")
                    )
                {
                    return Ok(row);
                }
                if Instant::now() >= deadline {
                    return Err("wait timed out; job remains owned by its worker".into());
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };
    invoke(&config, &body)
}
fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ouro: {error}");
            ExitCode::FAILURE
        }
    }
}
