//! CLI for the local evidence writer and gated launch owner.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use ouro_ledger::{
    daemon,
    protocol::{
        CatalogRequest, DiscoveryRequest, LedgerError, OperatorIntent, ReadFilter, ReadRequest,
        ReadSelector, ReadStage, Result, RunFilter, TailRequest,
    },
    runner, service,
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
    /// Wait for a run's durable terminal record; disconnecting does not cancel it.
    Wait {
        run_id: String,
        #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(u64).range(1..=86400))]
        timeout: u64,
        #[arg(long)]
        json: bool,
    },
    /// Request cancellation of a detached owner; wait separately for settlement.
    Cancel {
        run_id: String,
        #[arg(long)]
        json: bool,
    },
    #[command(name = "__owner", hide = true)]
    Owner {
        #[arg(long)]
        bootstrap: PathBuf,
        #[arg(long)]
        unit: String,
    },
    /// Discover durable runs with bounded, filter-bound pagination.
    Runs(Box<RunsArgs>),
    /// Inspect a run's outcome, coverage and protection independently.
    Show {
        run_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Read bounded observations from filtered discovery or up to eight explicit runs.
    Query(Box<QueryArgs>),
    /// Compare covered event counts or recorded targets in two verified snapshots.
    Diff {
        left: String,
        right: String,
        /// Group by recorded target labels, without claiming object identity.
        #[arg(long, default_value = "counts", value_parser = ["counts", "targets"])]
        by: String,
        /// Continue the output page; refuses if either snapshot head changed.
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Stream an exact canonical snapshot; status is written to stderr.
    Export(Box<ExportArgs>),
    /// Export a portable snapshot, optionally signed with an explicit node key.
    Bundle {
        run_id: String,
        /// New directory; existing destinations are never overwritten.
        #[arg(long)]
        output: PathBuf,
        /// Include a terminal capture, which may contain secrets.
        #[arg(long, value_parser = ["stdout", "stderr"])]
        capture: Vec<String>,
        /// Private Ed25519 PKCS#8 file from bundle-keygen; no automatic identity.
        #[arg(long)]
        signing_key: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Provision a fresh Ed25519 identity in a new private directory.
    BundleKeygen {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify a portable bundle offline without opening a node store or writer.
    VerifyBundle {
        path: PathBuf,
        /// Require this separately obtained signer; rejects unsigned bundles.
        #[arg(long)]
        trusted_key: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Append an attributed operator assertion; never changes launch state.
    Append(AppendArgs),
    /// Read bounded canonical fragments, optionally following later appends.
    Tail(TailArgs),
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
    /// Keep a run and its captures until an explicit release.
    Hold(RetentionArgs),
    /// Release the operator hold; retention and reader pins still apply.
    Release(RetentionArgs),
    /// Prune eligible terminal history and captures, retaining replay and chain anchors.
    Gc {
        #[arg(long)]
        dry_run: bool,
        /// Override the writer's history retention for this invocation.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=36500))]
        retain_days: Option<u32>,
        /// Override capture retention; cannot exceed history retention.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=36500))]
        capture_retain_days: Option<u32>,
        /// Continue after the last run id returned by the previous page.
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 25, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
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
struct AppendArgs {
    #[arg(long)]
    run: String,
    /// Reuse the same identity and body when retrying an uncertain outcome.
    #[arg(long)]
    request_id: String,
    #[arg(long, value_parser = ["admitted", "denied", "settled", "note"])]
    kind: String,
    /// Required for effect lifecycle decisions; optional for notes.
    #[arg(long)]
    effect: Option<String>,
    /// Explicit operator metadata, limited to a 64 KiB JSON object.
    #[arg(long)]
    body_file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct TailArgs {
    run_id: String,
    #[arg(short = 'f', long)]
    follow: bool,
    /// Resume at the next byte after the last fully consumed page.
    #[arg(long)]
    cursor: Option<String>,
    /// Stop following after this many seconds; default follows until interrupted.
    #[arg(long, requires = "follow", value_parser = clap::value_parser!(u64).range(1..=86400))]
    timeout: Option<u64>,
    /// Emit one JSON page per line, including provenance-preserving NDJSON fragments.
    #[arg(long)]
    json: bool,
}

fn append_command(data: &std::path::Path, args: AppendArgs) -> Result<i32> {
    use std::io::Read as _;
    let result = (|| -> Result<()> {
        // Validate input size before bootstrapping a writer or making a mutation.
        let mut bytes = Vec::new();
        std::fs::File::open(&args.body_file)?
            .take(65_537)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 65_536 {
            return Err(LedgerError("operator body exceeds 64 KiB bound".into()));
        }
        let body = serde_json::from_slice(&bytes)?;
        let mut client = runner::connect_or_start(data)?;
        let receipt = client.append(&OperatorIntent {
            run_id: args.run.clone(),
            request_id: args.request_id.clone(),
            kind: args.kind,
            effect_id: args.effect,
            body,
        })?;
        output(
            &json!({"operation":"append","run_id":args.run,"request_id":args.request_id,"receipt":receipt}),
            args.json,
        )
    })();
    result.map_err(|e| {
        LedgerError(format!(
            "append request {}: {e}; inspect or retry with the same request id and body",
            args.request_id
        ))
    })?;
    Ok(0)
}

fn tail_command(data: &std::path::Path, args: TailArgs) -> Result<i32> {
    use std::{
        io::Write as _,
        time::{Duration, Instant},
    };
    let mut request = TailRequest {
        run_id: args.run_id,
        cursor: args.cursor,
    };
    let mut client = daemon::Client::connect(data)?;
    let started = Instant::now();
    let mut first = true;
    loop {
        let page = match client.tail(&request) {
            Ok(page) => page,
            Err(_) => {
                // Retry from the same byte on the existing writer only. Never
                // start a replacement writer or silently reset to a new stream.
                client = daemon::Client::connect(data)?;
                client.tail(&request)?
            }
        };
        if first || !page.ndjson.is_empty() {
            output(&serde_json::to_value(&page)?, args.json)?;
            std::io::stdout().flush()?;
        }
        first = false;
        request.cursor = Some(page.next_cursor);
        if !args.follow
            || args
                .timeout
                .is_some_and(|s| started.elapsed() >= Duration::from_secs(s))
        {
            return Ok(0);
        }
        if page.caught_up {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

#[derive(Args)]
struct RetentionArgs {
    run_id: String,
    /// Reuse this id when retrying a request whose reply was lost.
    #[arg(long)]
    request_id: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RunsArgs {
    /// Inclusive last accepted writer activity, YYYY-MM-DDTHH:MM:SSZ.
    #[arg(long)]
    since: Option<String>,
    /// Exclusive last accepted writer activity, YYYY-MM-DDTHH:MM:SSZ.
    #[arg(long)]
    until: Option<String>,
    #[arg(long)]
    launch: Option<String>,
    /// Require every repeated tag; names are exact and case-sensitive.
    #[arg(long)]
    tag: Vec<String>,
    #[arg(long, value_parser = ["pending", "refused", "exited", "signaled", "exec_error", "unknown"])]
    outcome: Option<String>,
    #[arg(long)]
    after: Option<String>,
    #[arg(long, default_value_t = 25, value_parser = clap::value_parser!(u32).range(1..=100))]
    limit: u32,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("evidence_class")
    .required(true)
    .multiple(false)
    .args(["execs", "paths", "hosts", "denials"])))]
struct QueryArgs {
    /// Repeat for independent per-run snapshots, up to eight unique runs.
    #[arg(long)]
    run: Vec<String>,
    /// Select runs by last accepted activity, independently of event --since.
    #[arg(long, conflicts_with = "run")]
    run_since: Option<String>,
    #[arg(long, conflicts_with = "run")]
    run_until: Option<String>,
    #[arg(long, conflicts_with = "run")]
    launch: Option<String>,
    #[arg(long, conflicts_with = "run")]
    tag: Vec<String>,
    #[arg(long, conflicts_with = "run", value_parser = ["pending", "refused", "exited", "signaled", "exec_error", "unknown"])]
    outcome: Option<String>,
    /// Continue automatic discovery with the same filters and limit.
    #[arg(long, conflicts_with_all = ["run", "cursor", "resume"])]
    after: Option<String>,
    #[arg(long, group = "evidence_class")]
    execs: bool,
    #[arg(long, group = "evidence_class")]
    paths: bool,
    #[arg(long, group = "evidence_class")]
    hosts: bool,
    #[arg(long, group = "evidence_class")]
    denials: bool,
    /// Original source stage, as defined by the frozen jail event contract.
    #[arg(long, value_parser = ["attempt", "result"])]
    stage: Option<String>,
    /// Inclusive writer receipt time, YYYY-MM-DDTHH:MM:SSZ.
    #[arg(long)]
    since: Option<String>,
    /// Exclusive writer receipt time, YYYY-MM-DDTHH:MM:SSZ.
    #[arg(long)]
    until: Option<String>,
    /// Resume with the same run and filters using the returned cursor.
    #[arg(long)]
    cursor: Option<String>,
    /// Multi-run continuation: repeat RUN=POSITION for each run to resume.
    #[arg(long, conflicts_with = "cursor")]
    resume: Vec<String>,
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
    limit: u32,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ExportArgs {
    run_id: String,
    /// Exact canonical records only on stdout; status goes to stderr.
    #[arg(long, required = true)]
    ndjson: bool,
    /// Resume the original snapshot using a previously returned cursor.
    #[arg(long)]
    cursor: Option<String>,
    /// Emit machine-readable checkpoints and completion status on stderr.
    #[arg(long)]
    json: bool,
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
    /// Immutable operator labels: at most sixteen unique ASCII names.
    #[arg(long)]
    tag: Vec<String>,
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
    /// Start an independent user service and return its durable run identity.
    #[arg(long)]
    detach: bool,
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

fn retention_command(data: &std::path::Path, args: RetentionArgs, hold: bool) -> Result<i32> {
    let request_id = args
        .request_id
        .unwrap_or_else(|| format!("retention_{}", uuid::Uuid::new_v4().simple()));
    let operation = if hold { "hold" } else { "release" };
    let result = (|| -> Result<()> {
        let mut client = runner::connect_or_start(data)?;
        let receipt = if hold {
            client.hold(&args.run_id, &request_id)?
        } else {
            client.release(&args.run_id, &request_id)?
        };
        output(
            &json!({"operation":operation,"run_id":args.run_id,"request_id":request_id,"receipt":receipt}),
            args.json,
        )
    })();
    result.map_err(|error| {
        LedgerError(format!(
            "{operation} request {request_id}: {error}; inspect or retry using this same request id"
        ))
    })?;
    Ok(0)
}

fn query(client: &mut daemon::Client, args: QueryArgs) -> Result<i32> {
    let selector = if args.execs {
        ReadSelector::Execs
    } else if args.paths {
        ReadSelector::Paths
    } else if args.hosts {
        ReadSelector::Hosts
    } else if args.denials {
        ReadSelector::Denials
    } else {
        return Err(LedgerError("query requires one evidence class".into()));
    };
    let stage = match args.stage.as_deref() {
        Some("attempt") => Some(ReadStage::Attempt),
        Some("result") => Some(ReadStage::Result),
        None => None,
        _ => return Err(LedgerError("unsupported source stage".into())),
    };
    let filter = ReadFilter {
        selector,
        stage,
        since: args.since,
        until: args.until,
    };
    if args.run.is_empty() {
        if args.cursor.is_some() || !args.resume.is_empty() {
            return Err(LedgerError(
                "automatic discovery uses --after; --cursor and --resume require --run".into(),
            ));
        }
        let page = client.discover(&DiscoveryRequest {
            runs: RunFilter {
                since: args.run_since,
                until: args.run_until,
                launch: args.launch,
                tags: args.tag,
                outcome: args.outcome,
            },
            filter,
            after: args.after,
            limit: args.limit,
        })?;
        let passed = page.problem.is_none() && page.page.as_ref().is_none_or(query_page_ok);
        output(&serde_json::to_value(page)?, args.json)?;
        return Ok(if passed { 0 } else { 1 });
    }
    let unique: std::collections::BTreeSet<_> = args.run.iter().collect();
    if args.run.len() > 8 || unique.len() != args.run.len() {
        return Err(LedgerError(
            "query needs one through eight unique runs".into(),
        ));
    }
    if args.run.len() > 1 && args.cursor.is_some() {
        return Err(LedgerError(
            "multi-run query needs --resume RUN=POSITION".into(),
        ));
    }
    let mut positions = std::collections::BTreeMap::new();
    for resume in args.resume {
        let (run, position) = resume
            .split_once('=')
            .ok_or_else(|| LedgerError("resume needs RUN=POSITION".into()))?;
        if !args.run.iter().any(|r| r == run)
            || position.len() != 64
            || !position.bytes().all(|b| b.is_ascii_hexdigit())
            || positions
                .insert(run.to_owned(), position.to_owned())
                .is_some()
        {
            return Err(LedgerError(
                "resume needs a unique selected run and a valid reader position".into(),
            ));
        }
    }
    if args.run.len() > 1 {
        let mut pages = Vec::new();
        let mut problems = Vec::new();
        let mut passed = true;
        for run in args.run {
            match client.read(&ReadRequest {
                cursor: positions.remove(&run),
                run_id: run.clone(),
                filter: filter.clone(),
                limit: args.limit,
            }) {
                Ok(page) => {
                    passed &= query_page_ok(&page);
                    pages.push(page);
                }
                Err(error) => {
                    passed = false;
                    problems.push(json!({"run_id":run,"message":error.to_string()}));
                }
            }
        }
        output(
            &json!({"schema":"ouro.ledger.query/1","snapshot_scope":"independent_per_run",
            "pages":pages,"problems":problems}),
            args.json,
        )?;
        return Ok(if passed { 0 } else { 1 });
    }
    let run_id = args.run.into_iter().next().unwrap();
    let page = client.read(&ReadRequest {
        cursor: args.cursor.or_else(|| positions.remove(&run_id)),
        run_id,
        filter,
        limit: args.limit,
    })?;
    output(&serde_json::to_value(&page)?, args.json)?;
    if page.oversized_record.is_some() {
        eprintln!(
            "ouro-ledger: matching record exceeds the query page bound; retrieve it with export RUN --ndjson"
        );
    }
    Ok(if query_page_ok(&page) { 0 } else { 1 })
}

fn query_page_ok(page: &ouro_ledger::protocol::ReadPage) -> bool {
    page.local_consistency
        && !matches!(page.stream_status.as_str(), "incomplete" | "corrupt")
        && page.oversized_record.is_none()
}

fn export(client: &mut daemon::Client, data: &std::path::Path, args: ExportArgs) -> Result<i32> {
    use std::io::Write as _;
    let mut request = ReadRequest {
        run_id: args.run_id,
        filter: ReadFilter {
            selector: ReadSelector::All,
            stage: None,
            since: None,
            until: None,
        },
        cursor: args.cursor,
        limit: 100,
    };
    let mut snapshot = None;
    let mut bytes_written = 0u64;
    let mut stdout = std::io::stdout().lock();
    loop {
        let page = match client.read(&request) {
            Ok(page) => page,
            Err(_) => {
                // A slow output sink can outlive the socket's idle timeout.
                // Retry the same read on the existing writer, retaining its snapshot.
                let mut reconnected = daemon::Client::connect(data)?;
                let page = reconnected.read(&request)?;
                *client = reconnected;
                page
            }
        };
        if let Some((seq, digest)) = &snapshot {
            if page.snapshot.head_seq != *seq || page.snapshot.head_digest != *digest {
                return Err(LedgerError(
                    "export snapshot changed during pagination".into(),
                ));
            }
        } else {
            snapshot = Some((page.snapshot.head_seq, page.snapshot.head_digest.clone()));
        }
        if !page.records.is_empty() || page.oversized_record.is_some() {
            return Err(LedgerError(
                "export received an invalid chunk response".into(),
            ));
        }
        stdout.write_all(page.ndjson.as_bytes())?;
        stdout.flush()?;
        bytes_written += page.ndjson.len() as u64;
        if page.done {
            let status = json!({
                "schema": "ouro.ledger.export/1",
                "event": "finished",
                "run_id": page.run_id,
                "snapshot": page.snapshot,
                "state": page.state,
                "child_protection": page.child_protection,
                "coverage": page.coverage,
                "local_consistency": page.local_consistency,
                "stream_status": page.stream_status,
                "problems": page.problems,
                "scanned_through_seq": page.scanned_through_seq,
                "bytes_written": bytes_written,
                "done": true,
                "next_cursor": null,
            });
            let mut stderr = std::io::stderr().lock();
            if args.json {
                serde_json::to_writer(&mut stderr, &status)?;
                writeln!(stderr)?;
            } else {
                writeln!(stderr, "{}", serde_json::to_string_pretty(&status)?)?;
            }
            return Ok(
                if page.local_consistency
                    && !matches!(page.stream_status.as_str(), "incomplete" | "corrupt")
                {
                    0
                } else {
                    1
                },
            );
        }
        let cursor = page
            .next_cursor
            .ok_or_else(|| LedgerError("unfinished export has no continuation cursor".into()))?;
        if request.cursor.as_ref() == Some(&cursor) {
            return Err(LedgerError("export cursor made no progress".into()));
        }
        if args.json {
            let mut stderr = std::io::stderr().lock();
            serde_json::to_writer(
                &mut stderr,
                &json!({
                    "schema": "ouro.ledger.export/1",
                    "event": "checkpoint",
                    "run_id": request.run_id,
                    "snapshot": page.snapshot,
                    "state": page.state,
                    "child_protection": page.child_protection,
                    "coverage": page.coverage,
                    "local_consistency": page.local_consistency,
                    "stream_status": page.stream_status,
                    "problems": page.problems,
                    "bytes_written": bytes_written,
                    "scanned_through_seq": page.scanned_through_seq,
                    "done": false,
                    "next_cursor": cursor,
                }),
            )?;
            writeln!(stderr)?;
        } else {
            eprintln!(
                "ouro-ledger: export checkpoint after {bytes_written} bytes; protection {}; stream {}; local consistency {}; cursor {cursor}",
                ouro_records::records::escape_control(&page.child_protection),
                ouro_records::records::escape_control(&page.stream_status),
                page.local_consistency,
            );
        }
        request.cursor = Some(cursor);
    }
}

fn execute(cli: Cli) -> Result<i32> {
    if let Action::VerifyBundle {
        path,
        trusted_key,
        json,
    } = &cli.command
    {
        output(
            &ouro_ledger::bundle::verify_with_key(path, trusted_key.as_deref())?,
            *json,
        )?;
        return Ok(0);
    }
    if let Action::BundleKeygen {
        output: destination,
        json,
    } = &cli.command
    {
        output(&ouro_ledger::bundle::keygen(destination)?, *json)?;
        return Ok(0);
    }
    let data = data_dir(cli.data_dir)?;
    match cli.command {
        Action::Version { json } => {
            output(
                &json!({"component":"ouro-ledger","version":env!("CARGO_PKG_VERSION"),"schemas":{"run":"ouro.ledger.run/1","event":ouro_records::records::SCHEMA_EVENT,"receipt":ouro_records::records::SCHEMA_RECEIPT,"read":"ouro.ledger.read/1","export":"ouro.ledger.export/1","tail":"ouro.ledger.tail/1","query":"ouro.ledger.query/1","diff":"ouro.ledger.diff/1","catalog":"ouro.ledger.catalog/1","discovery":"ouro.ledger.discovery/1","bundle":"ouro.ledger.bundle/1","bundle_verification":"ouro.ledger.bundle-verification/1","signed_bundle":"ouro.ledger.bundle/2","signed_bundle_verification":"ouro.ledger.bundle-verification/2","bundle_signature":"ouro.ledger.bundle-signature/1","signer":"ouro.ledger.signer/1"},"schema_frozen":false,"execution_platform":"linux"}),
                json,
            )?;
            Ok(0)
        }
        Action::Serve => {
            daemon::serve(&data)?;
            Ok(0)
        }
        Action::Bundle {
            run_id,
            output: destination,
            capture,
            signing_key,
            json,
        } => {
            let mut client = daemon::Client::connect(&data)?;
            let report = if let Some(key) = signing_key {
                ouro_ledger::bundle::create_signed(
                    &mut client,
                    &data,
                    &run_id,
                    &destination,
                    &capture,
                    &key,
                )?
            } else {
                ouro_ledger::bundle::create(&mut client, &data, &run_id, &destination, &capture)?
            };
            output(&report, json)?;
            Ok(0)
        }
        Action::Owner { bootstrap, unit } => {
            // SAFETY: this hidden entry point has not created any threads.
            unsafe {
                service::serve(&bootstrap, &unit)?;
            }
            Ok(0)
        }
        Action::Wait {
            run_id,
            timeout,
            json,
        } => {
            let record = service::wait(&data, &run_id, std::time::Duration::from_secs(timeout))?;
            output(&serde_json::to_value(&record)?, json)?;
            Ok(runner::record_exit(&record))
        }
        Action::Cancel { run_id, json } => {
            output(&service::cancel(&data, &run_id)?, json)?;
            Ok(0)
        }
        Action::Hold(args) => retention_command(&data, args, true),
        Action::Append(args) => append_command(&data, args),
        Action::Tail(args) => tail_command(&data, args),
        Action::Release(args) => retention_command(&data, args, false),
        Action::Gc {
            dry_run,
            retain_days,
            capture_retain_days,
            after,
            limit,
            json,
        } => {
            // A dry run must not bootstrap recovery, rebuild projections, or expire readers.
            let mut client = daemon::Client::connect(&data)?;
            if dry_run {
                output(
                    &serde_json::to_value(client.gc_plan_policy(
                        retain_days,
                        capture_retain_days,
                        after.as_deref(),
                        limit,
                    )?)?,
                    json,
                )?;
                Ok(0)
            } else {
                let result =
                    client.gc_policy(retain_days, capture_retain_days, after.as_deref(), limit)?;
                let passed = result.failed.is_empty();
                output(&serde_json::to_value(result)?, json)?;
                Ok(if passed { 0 } else { 1 })
            }
        }
        Action::Doctor { json } => {
            // A readiness read must not create a session-bound writer which
            // would subsequently prevent independent service ownership.
            let detached_owner = service::probe();
            let mut client = match daemon::Client::connect(&data) {
                Ok(client) => client,
                Err(error) => {
                    output(
                        &json!({"component":"ouro-ledger","ready":false,"writer":"unreachable","reason":error.to_string(),"store":null,"execution_platform":"linux","detached_owner":detached_owner,"managed_authorization":"not_implemented"}),
                        json,
                    )?;
                    return Ok(1);
                }
            };
            let writer = client.ping()?;
            let reports = client.verify(None)?;
            let ready = reports.iter().all(|r| r.local_consistency);
            output(
                &json!({"component":"ouro-ledger","ready":ready,"writer":"reachable","store":reports,"retention":writer["retention"],"execution_platform":"linux","detached_owner":detached_owner,"managed_authorization":"not_implemented"}),
                json,
            )?;
            Ok(if ready { 0 } else { 1 })
        }
        Action::Run(args) => {
            ouro_ledger::discovery::validate_tags(&args.tag)?;
            if args.detach && args.io != "batch" {
                return Err(LedgerError("--detach requires --io batch".into()));
            }
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
            if let Some(launch) = &args.launch {
                policy.push("--launch".into());
                policy.push(launch.into());
            }
            for (name, values) in [("--allow-host", args.allow_host), ("--limit", args.limit)] {
                for value in values {
                    policy.push(name.into());
                    policy.push(value.into());
                }
            }
            let options = runner::RunOptions {
                data,
                jail: runner::jail_binary(args.jail_bin)?,
                request_id: args
                    .request_id
                    .unwrap_or_else(|| format!("req_{}", uuid::Uuid::new_v4())),
                prepared: args.prepared,
                policy_args: policy,
                argv: args.argv,
                batch: args.io == "batch",
                detached: args.detach,
                captures: args.capture,
                capture_limit: args.capture_limit,
                best_effort: args.evidence == "best-effort",
                launch: args.launch,
                tags: args.tag,
            };
            if args.detach {
                let record = service::launch(&options).map_err(|error| LedgerError(format!(
                    "detached request {}: {}; inspect or replay this same request id, never invent a replacement",
                    options.request_id, error
                )))?;
                output(&serde_json::to_value(&record)?, args.json)?;
                return Ok(0);
            }
            let result = runner::run(&options)?;
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
                Action::Runs(args) => {
                    let page = client.catalog(&CatalogRequest {
                        filter: RunFilter {
                            since: args.since,
                            until: args.until,
                            launch: args.launch,
                            tags: args.tag,
                            outcome: args.outcome,
                        },
                        after: args.after,
                        limit: args.limit,
                    })?;
                    output(&serde_json::to_value(page)?, args.json)?;
                }
                Action::Show { run_id, json } => {
                    output(&serde_json::to_value(client.show(&run_id)?)?, json)?
                }
                Action::Query(args) => return query(&mut client, *args),
                Action::Diff {
                    left,
                    right,
                    by,
                    after,
                    limit,
                    json,
                } => {
                    let report = ouro_ledger::comparison::compare_mode(
                        &mut client,
                        &left,
                        &right,
                        after.as_deref(),
                        limit,
                        if by == "targets" {
                            ouro_ledger::comparison::ComparisonMode::TargetCounts
                        } else {
                            ouro_ledger::comparison::ComparisonMode::EventCounts
                        },
                    )?;
                    let passed = report["complete"] == true;
                    output(&report, json)?;
                    return Ok(if passed { 0 } else { 1 });
                }
                Action::Export(args) => return export(&mut client, &data, *args),
                Action::Verify { run_id, json } => {
                    let reports = client.verify(run_id.as_deref())?;
                    let passed = reports.iter().all(|r| r.local_consistency);
                    output(&serde_json::to_value(reports)?, json)?;
                    return Ok(if passed { 0 } else { 1 });
                }
                Action::SettleOrphans { json } => {
                    output(&serde_json::to_value(client.settle_orphans()?)?, json)?
                }
                Action::Serve
                | Action::Run(_)
                | Action::Doctor { .. }
                | Action::Version { .. }
                | Action::Owner { .. }
                | Action::Wait { .. }
                | Action::Cancel { .. } => unreachable!(),
                Action::Append(_)
                | Action::Tail(_)
                | Action::Hold(_)
                | Action::Release(_)
                | Action::Gc { .. }
                | Action::Bundle { .. }
                | Action::VerifyBundle { .. }
                | Action::BundleKeygen { .. } => unreachable!(),
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
