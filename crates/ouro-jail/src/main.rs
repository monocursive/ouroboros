//! The `ouro-jail` binary: dispatch, rendering and the §6.4 exit codes.
//!
//! Inspection JSON goes to stdout; diagnostics go to stderr in one line per
//! error (§6.1). `run` preserves the child's stdout and stderr byte streams and
//! has no JSON stdout mode.

use std::io::Write as _;
use std::process::ExitCode;

use clap::Parser as _;
use ouro_jail::capability::Capability;
use ouro_jail::cli::{Cli, Command, DoctorArgs, ExplainArgs, GcArgs, RunArgs, VersionArgs};
use ouro_jail::config;
use ouro_jail::observer::CoverageSummary;
use ouro_jail::platform;
use ouro_jail::records::{
    self, JailError, PlatformRecord, SCHEMA_CONTROL, SCHEMA_EVENT, SCHEMA_GATE, SCHEMA_NETWORK,
    SCHEMA_POLICY, SCHEMA_POLICY_FILE, SCHEMA_POLICY_SNAPSHOT, SCHEMA_RECEIPT,
};
use ouro_jail::supervisor::{self, Context, DoctorReport, ExplainReport, GcReport};

fn main() -> ExitCode {
    if let Some(code) = internal_subcommand() {
        return code;
    }
    let cli = Cli::parse();
    let context = match build_context() {
        Ok(context) => context,
        Err(error) => return fail(&error),
    };
    match cli.command {
        Command::Version(args) => version(&context, &args),
        Command::Explain(args) => explain(&context, &args),
        Command::Doctor(args) => doctor(&context, &args),
        Command::Gc(args) => gc(&context, &args),
        Command::Run(args) => run(&context, &args),
    }
}

fn stderr_is_a_terminal() -> bool {
    // SAFETY: isatty takes a descriptor number and dereferences nothing.
    unsafe { libc::isatty(2) == 1 }
}

fn build_context() -> Result<Context, JailError> {
    let env_settings = config::env_settings(&|name| std::env::var_os(name))?;
    let cwd = std::env::current_dir().map_err(|error| {
        JailError::new(
            records::ErrorCode::InvalidConfig,
            records::ErrorStage::Resolving,
            records::Remediation::Configuration,
            format!("the invocation directory cannot be read: {error}"),
        )
    })?;
    Ok(Context {
        platform: platform::current(),
        env_settings,
        cwd,
        home: std::env::var_os("HOME").map(std::path::PathBuf::from),
        env_lookup: Box::new(supervisor::env_bytes),
    })
}

fn fail(error: &JailError) -> ExitCode {
    eprintln!("{error}");
    exit(error.exit_code())
}

fn exit(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn print_json(value: &serde_json::Value) {
    let mut stdout = std::io::stdout().lock();
    let _ = serde_json::to_writer_pretty(&mut stdout, value);
    let _ = stdout.write_all(b"\n");
}

// ---------------------------------------------------------------------------
// version
// ---------------------------------------------------------------------------

/// The schema identifiers this build announces (§4: "the schema identifiers
/// that `ouro version --json` announces are constants tested against those
/// files").
fn schema_identifiers() -> serde_json::Value {
    serde_json::json!({
        "receipt": SCHEMA_RECEIPT,
        "event": SCHEMA_EVENT,
        "policy": SCHEMA_POLICY,
        "policy_snapshot": SCHEMA_POLICY_SNAPSHOT,
        "policy_file": SCHEMA_POLICY_FILE,
        "gate": SCHEMA_GATE,
        "control": SCHEMA_CONTROL,
        "network": SCHEMA_NETWORK,
    })
}

fn platform_json(platform: &PlatformRecord) -> serde_json::Value {
    serde_json::json!({
        "os": platform.os.as_str(),
        "arch": platform.arch,
        "kernel": platform.kernel,
    })
}

fn version(context: &Context, args: &VersionArgs) -> ExitCode {
    let identity = context.platform.identity();
    let platform = PlatformRecord {
        os: identity.os,
        arch: identity.arch,
        kernel: identity.kernel,
    };
    if args.json {
        print_json(&serde_json::json!({
            "component": "ouro-jail",
            "version": env!("CARGO_PKG_VERSION"),
            "platform": platform_json(&platform),
            "schemas": schema_identifiers(),
            "observation": { "closed_set": CoverageSummary::linux_closed_set() },
        }));
    } else {
        println!("ouro-jail {}", env!("CARGO_PKG_VERSION"));
        println!(
            "platform {} {} ({})",
            platform.os.as_str(),
            platform.arch,
            platform.kernel
        );
        println!("closed set {}", CoverageSummary::linux_closed_set());
        for (name, value) in [
            ("receipt", SCHEMA_RECEIPT),
            ("event", SCHEMA_EVENT),
            ("policy", SCHEMA_POLICY),
            ("policy_snapshot", SCHEMA_POLICY_SNAPSHOT),
            ("policy_file", SCHEMA_POLICY_FILE),
            ("gate", SCHEMA_GATE),
            ("control", SCHEMA_CONTROL),
            ("network", SCHEMA_NETWORK),
        ] {
            println!("schema {name} {value}");
        }
    }
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------

fn explain(context: &Context, args: &ExplainArgs) -> ExitCode {
    let report = match supervisor::explain(context, args) {
        Ok(report) => report,
        Err(error) => return fail(&error),
    };
    if args.json {
        match explain_json(&report) {
            Ok(value) => print_json(&value),
            Err(error) => return fail(&error),
        }
    } else {
        print_explain_text(&report);
    }
    ExitCode::SUCCESS
}

/// Renders `explain --json`.
///
/// Replaces every environment binding's value with its name.
///
/// §13.2 and §12: receipts and traces carry environment names, never values,
/// and inspection output is held to the same rule. The digest is printed
/// beside the snapshot, so an operator can still check identity without the
/// values being pasted into a bug report.
fn redact_environment(snapshot: &mut serde_json::Value) {
    let Some(bindings) = snapshot
        .get_mut("environment")
        .and_then(|environment| environment.get_mut("bindings"))
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for binding in bindings.iter_mut() {
        if let Some(object) = binding.as_object_mut() {
            object.remove("value");
        }
    }
}

// J3-launch begin: credential sources are private operational state (§12)
/// Removes every credential `source` from the snapshot's `launch` group,
/// leaving the profile's own names: `id`, `mode` and `dest`.
///
/// §12: "Source identity/paths and credential contents stay in private
/// operational state"; §14.1 holds inspection output to "without printing
/// values or user-specific paths". The digest printed beside the snapshot
/// still identifies the full policy, sources included.
fn redact_launch(snapshot: &mut serde_json::Value) {
    let Some(credentials) = snapshot
        .get_mut("launch")
        .and_then(|launch| launch.get_mut("credentials"))
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for credential in credentials.iter_mut() {
        if let Some(object) = credential.as_object_mut() {
            object.remove("source");
        }
    }
}
// J3-launch end

fn explain_json(report: &ExplainReport) -> Result<serde_json::Value, JailError> {
    let mut snapshot = report.resolved.snapshot.to_canonical_value()?;
    redact_environment(&mut snapshot);
    // J3-launch begin
    redact_launch(&mut snapshot);
    // J3-launch end
    let requirements: Vec<serde_json::Value> = report
        .resolved
        .requirements
        .iter()
        .map(|name| {
            serde_json::json!({
                "name": name,
                // `explain` does not probe (§6.1), so every capability is
                // explicitly unmeasured rather than assumed available.
                "measurement": "unmeasured",
            })
        })
        .collect();
    Ok(serde_json::json!({
        "component": "ouro-jail",
        "version": env!("CARGO_PKG_VERSION"),
        "probed": false,
        "platform": platform_json(&report.platform),
        "policy": {
            "name": report.resolved.policy_name,
            "digest": report.resolved.digest,
            // The snapshot with environment values removed; `environment_values`
            // says so rather than leaving a reader to infer it.
            "snapshot": snapshot,
            "environment_values": "omitted",
            // J3-launch begin
            "credential_sources": "omitted",
            // J3-launch end
        },
        "requirements": requirements,
        "capabilities": {
            "measured": false,
            "note": "explain resolves and renders policy; it probes nothing and executes nothing",
        },
        "provenance": report.resolved.provenance,
    }))
}

fn print_explain_text(report: &ExplainReport) {
    let snapshot = &report.resolved.snapshot;
    println!("policy {}", report.resolved.policy_name);
    println!("profile {}", snapshot.profile.as_str());
    println!("platform {}", snapshot.platform.as_str());
    println!("digest {}", report.resolved.digest);
    println!(
        "observation mode={} evidence={}",
        match snapshot.observation.mode {
            records::ObserveMode::On => "on",
            records::ObserveMode::Off => "off",
        },
        match snapshot.observation.evidence {
            records::EvidenceMode::Strict => "strict",
            records::EvidenceMode::BestEffort => "best-effort",
        }
    );
    println!("network {}", snapshot.network.mode);
    for reference in &snapshot.filesystem.read_write {
        println!("read_write {}", reference.to_display());
    }
    for reference in &snapshot.filesystem.read_only {
        println!("read_only {}", reference.to_display());
    }
    for reference in &snapshot.filesystem.deny_read {
        println!("deny_read {}", reference.to_display());
    }
    println!(
        "protected_coverage {}",
        snapshot.filesystem.protected_coverage.as_str()
    );
    for (key, ceiling) in [
        ("wall", &snapshot.limits.wall),
        ("pids", &snapshot.limits.pids),
        ("mem", &snapshot.limits.mem),
        ("cpu", &snapshot.limits.cpu),
    ] {
        if let Some(ceiling) = ceiling {
            println!(
                "limit {key}={} required={}",
                ceiling.value, ceiling.required
            );
        }
    }
    // J3-launch begin: the launch group by the profile's own names only
    if let Some(launch) = &snapshot.launch {
        println!(
            "launch state_var={} home_is_state={}",
            launch.state_var.as_deref().unwrap_or("none"),
            launch.home_is_state
        );
        for subdir in &launch.state_subdirs {
            println!("launch state_subdir {}", subdir.to_display());
        }
        for credential in &launch.credentials {
            println!(
                "launch credential {} mode={} dest={} source=omitted",
                credential.id,
                credential.mode,
                credential.dest.to_display()
            );
        }
    }
    // J3-launch end
    for requirement in &report.resolved.requirements {
        println!("requirement {requirement} unmeasured");
    }
    println!("capabilities unmeasured (explain does not probe)");
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

fn capability_json(capability: &Capability) -> serde_json::Value {
    serde_json::to_value(capability).unwrap_or(serde_json::Value::Null)
}

fn doctor(context: &Context, args: &DoctorArgs) -> ExitCode {
    let report = match supervisor::doctor(context, args) {
        Ok(report) => report,
        Err(error) => return fail(&error),
    };
    if args.json {
        print_json(&doctor_json(&report));
    } else {
        print_doctor_text(&report);
    }
    // §6.4: `doctor` uses 125 when the requested execution plan is unsupported
    // or unavailable, including macOS execution.
    if report.ready {
        ExitCode::SUCCESS
    } else {
        exit(125)
    }
}

fn doctor_json(report: &DoctorReport) -> serde_json::Value {
    serde_json::json!({
        "component": "ouro-jail",
        "version": env!("CARGO_PKG_VERSION"),
        "platform": platform_json(&report.platform),
        "requirements": report.requirements,
        "capabilities": report
            .capabilities
            .iter()
            .map(capability_json)
            .collect::<Vec<_>>(),
        "ready": report.ready,
        // J3-launch begin: §14.1 launch readiness, names and statuses only
        "launch": report.launch.as_ref().map(|launch| serde_json::json!({
            "name": launch.name,
            "support": launch.support,
            "support_reason": launch.support_reason,
            "credentials": launch
                .credentials
                .iter()
                .map(|check| serde_json::json!({
                    "id": check.id,
                    "mode": check.mode,
                    "dest": check.dest,
                    "status": if check.available { "available" } else { "unavailable" },
                    "reason_code": check.reason_code,
                }))
                .collect::<Vec<_>>(),
        })),
        // J3-launch end
    })
}

fn print_doctor_text(report: &DoctorReport) {
    println!(
        "platform {} {} ({})",
        report.platform.os.as_str(),
        report.platform.arch,
        report.platform.kernel
    );
    for capability in &report.capabilities {
        println!(
            "capability {} {} scope={} reason={}",
            capability.name,
            status_name(capability),
            scope_name(capability),
            capability.reason_code.as_deref().unwrap_or("none")
        );
    }
    // J3-launch begin: §14.1 launch readiness, names and statuses only
    if let Some(launch) = &report.launch {
        println!(
            "launch {} {} reason={}",
            launch.name, launch.support, launch.support_reason
        );
        for check in &launch.credentials {
            println!(
                "credential {} mode={} dest={} {} reason={}",
                check.id,
                check.mode,
                check.dest.to_display(),
                if check.available {
                    "available"
                } else {
                    "unavailable"
                },
                check.reason_code
            );
        }
    }
    // J3-launch end
    println!("ready {}", report.ready);
}

// ---------------------------------------------------------------------------
// gc
// ---------------------------------------------------------------------------

fn gc(context: &Context, args: &GcArgs) -> ExitCode {
    let report = match supervisor::gc(context, args) {
        Ok(report) => report,
        // §6.4: `gc` uses 1 for failed cleanup or state access, whatever the
        // underlying code's usual mapping would be.
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    if args.json {
        print_json(&gc_json(&report));
    } else {
        for entry in &report.entries {
            println!("{} {} {}", entry.attempt_id, entry.action, entry.reason);
            // J3-agent begin
            if let Some(proxy_dir) = &entry.proxy_dir {
                println!("{} proxy_dir {proxy_dir}", entry.attempt_id);
            }
            // J3-agent end
        }
        println!("scanned {}", report.entries.len());
    }
    // J3-launch begin: §6.4 — a cleanup that stopped again exits 1, after the
    // report is printed (J3 review L1).
    if !report.incomplete.is_empty() {
        eprintln!(
            "ouro-jail: cleanup did not complete for: {}",
            report.incomplete.join(", ")
        );
        return ExitCode::from(1);
    }
    // J3-launch end
    ExitCode::SUCCESS
}

fn gc_json(report: &GcReport) -> serde_json::Value {
    serde_json::json!({
        "component": "ouro-jail",
        "dry_run": report.dry_run,
        "entries": report
            .entries
            .iter()
            .map(|entry| serde_json::json!({
                "attempt_id": entry.attempt_id,
                "action": entry.action,
                "reason": entry.reason,
                // J3-agent begin
                "proxy_dir": entry.proxy_dir,
                // J3-agent end
            }))
            .collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

fn run(context: &Context, args: &RunArgs) -> ExitCode {
    let report = supervisor::run(context, args);
    // §6.1: `--label-only` prints the proposed execution label and describes
    // each capability; it executes nothing and copies no credential.
    if let Some(label) = &report.label {
        println!("{label}");
    }
    for capability in &report.capabilities {
        println!(
            "capability {} {} scope={} reason={}",
            capability.name,
            status_name(capability),
            scope_name(capability),
            capability.reason_code.as_deref().unwrap_or("none")
        );
    }
    if let Some(error) = &report.error {
        eprintln!("{error}");
    }
    // I05: evidence health is a separate fact from the attempt's outcome, so a
    // trace failure gets its own diagnostic line rather than replacing one.
    if let Some(error) = &report.trace_error {
        eprintln!("{error}");
    }
    if let Some(path) = &report.receipt_path
        && report.receipt.is_some()
        && stderr_is_a_terminal()
    {
        // §8.3: the child's stderr is inherited without capture. Writing the
        // supervisor's own diagnostic into it would make the stream differ
        // from direct execution (X05), so the line goes out only when a
        // terminal is watching, where no byte comparison is being made.
        eprintln!("ouro-jail: receipt {}", path.display());
    }
    exit(report.exit_code)
}

fn status_name(capability: &Capability) -> String {
    serde_json::to_value(capability.status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn scope_name(capability: &Capability) -> String {
    serde_json::to_value(capability.scope)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

// ---------------------------------------------------------------------------
// internal subcommands
// ---------------------------------------------------------------------------

/// The hidden subcommands the Linux platform reaches by re-executing this
/// binary: the inside launcher (`__launch`, jail-v1 §8.1 step 3), the doctor
/// probes' inside helper (`__probe-inside`, §14.1) and the seccomp table
/// printer kept as conformance evidence (`__seccomp-table`, §9.2). They take
/// no policy input and grant nothing the caller lacks; `None` means an
/// ordinary invocation that clap parses.
fn internal_subcommand() -> Option<ExitCode> {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let first = args.get(1)?;
    match first.to_str()? {
        #[cfg(target_os = "linux")]
        "__watch" => ouro_jail::platform::linux::watch::watcher_main(),
        #[cfg(target_os = "linux")]
        "__backend" => ouro_jail::platform::linux::watch::bootstrap_main(&args[2..]),
        #[cfg(target_os = "linux")]
        "__launch" => ouro_jail::platform::linux::launch::launch_main(&args[2..]),
        #[cfg(target_os = "linux")]
        "__probe-inside" => ouro_jail::platform::linux::probe::probe_inside_main(&args[2..]),
        // The table describes a Linux ABI, so the subcommand that prints it
        // exists only where that ABI does.
        #[cfg(target_os = "linux")]
        "__seccomp-table" => {
            use ouro_jail::platform::linux::seccomp;
            // J3-agent begin: the agent tables beside the tool one
            let table = match args.get(2).and_then(|arg| arg.to_str()) {
                None | Some("tool") => seccomp::tool_baseline_table(),
                Some("agent") => {
                    seccomp::agent_baseline_table(seccomp::AgentVariant::UnprivilegedInner)
                }
                Some("agent-namespace") => {
                    seccomp::agent_baseline_table(seccomp::AgentVariant::NamespaceInner)
                }
                Some(_) => return Some(ExitCode::from(2)),
            };
            // J3-agent end
            print!("{table}");
            Some(ExitCode::SUCCESS)
        }
        // J3-agent begin: the in-namespace loopback bridge (jail-v1 §10)
        #[cfg(target_os = "linux")]
        "__bridge" => ouro_jail::platform::linux::bridge::bridge_main(&args[2..]),
        // J3-agent end
        _ => None,
    }
}
