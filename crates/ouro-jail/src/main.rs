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
use ouro_jail::supervisor::{self, Context, DoctorReport, ExplainReport};

// J5-D: the build provenance rules build.rs applies (one rule, three users:
// build.rs and xtask use the tree walk, this binary the validation)
#[allow(dead_code)]
mod build_provenance;

fn main() -> ExitCode {
    if let Some(code) = internal_subcommand() {
        return code;
    }
    let cli = Cli::parse();
    // J4 autoscope: jail-v1 §9.3 — `run` and `doctor` enter a delegated user
    // scope themselves when started outside one, first, before any thread or
    // other resource exists, so an attempt gets its execution leaf. The step
    // runs `busctl` as a child and never re-executes this process; it never
    // fails the command, and every receipt and `doctor` report what it did.
    #[cfg(target_os = "linux")]
    if matches!(
        cli.command,
        Command::Run(_) | Command::Learn(_) | Command::Doctor(_)
    ) {
        let _ = ouro_jail::platform::linux::scope::enter();
    }
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
        Command::Learn(args) => match ouro_jail::learn::run(&context, *args) {
            Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(125)),
            Err(e) => {
                ouro_jail::diag!("learn: {e}");
                ExitCode::from(2)
            }
        },
        Command::Tail(args) => {
            let result = (|| {
                let data =
                    ouro_jail::state::data_dir(&context.env_settings, context.home.as_deref())
                        .map_err(|e| e.message)?;
                let attempt = ouro_jail::journal::attempt_path(&data, args.attempt.as_deref())?;
                ouro_jail::journal::tail(
                    &attempt,
                    args.follow,
                    args.json,
                    args.since.as_deref(),
                    &mut std::io::stdout().lock(),
                )
            })();
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    ouro_jail::diag!("tail: {e}");
                    ExitCode::from(2)
                }
            }
        }
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
    ouro_jail::diag!("{error}");
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
        "learned_policy": records::SCHEMA_LEARNED_POLICY,
        // J5-D
        "doctor": SCHEMA_DOCTOR,
    })
}

// J5-D begin: build provenance (§16) and the doctor record's identifier
/// The identifier of the `doctor --json` record, whose schema is
/// `docs/specs/jail-v1/jail-doctor.schema.json` (§3.2: it is the host
/// manifest every conformance run records).
const SCHEMA_DOCTOR: &str = "ouro.jail.doctor/1";

/// The revision and dirty flag as build.rs validated them (it fails the
/// build on a malformed or contradictory pair, so an error here cannot
/// happen in a built binary; it would read as unknown).
fn build_claims() -> build_provenance::Claims {
    build_provenance::validate(
        option_env!("OURO_BUILD_REVISION"),
        option_env!("OURO_BUILD_DIRTY"),
    )
    .unwrap_or(build_provenance::Claims {
        revision: None,
        dirty: None,
    })
}

/// What built this binary (§16's "build provenance"), measured where it can
/// be (review F8): the compiler's `rustc -V`, the target, the opt-level and
/// debug assertions the code was actually compiled with, and the digest of
/// the build inputs (`build_provenance`). The revision and dirty flag are
/// the build environment's validated claims, null when it made none; the
/// inputs digest is what checks them.
fn build_json() -> serde_json::Value {
    let claims = build_claims();
    serde_json::json!({
        "revision": claims.revision,
        "dirty": claims.dirty,
        "rustc": env!("OURO_BUILD_RUSTC"),
        "target": env!("OURO_BUILD_TARGET"),
        "opt_level": env!("OURO_BUILD_OPT_LEVEL"),
        "debug_assertions": cfg!(debug_assertions),
        "inputs": env!("OURO_BUILD_INPUTS"),
    })
}

/// The `build` object as text lines, for `version` without `--json`.
fn print_build_text() {
    let claims = build_claims();
    let unknown = || "unknown".to_owned();
    println!("build {}", env!("OURO_BUILD_RUSTC"));
    println!(
        "build target {} opt-level {} debug-assertions {}",
        env!("OURO_BUILD_TARGET"),
        env!("OURO_BUILD_OPT_LEVEL"),
        cfg!(debug_assertions)
    );
    println!(
        "build revision {} dirty {}",
        claims.revision.unwrap_or_else(unknown),
        claims.dirty.map_or_else(unknown, |dirty| dirty.to_string())
    );
    println!("build inputs {}", env!("OURO_BUILD_INPUTS"));
}
// J5-D end

fn platform_json(platform: &PlatformRecord) -> serde_json::Value {
    serde_json::json!({
        "os": platform.os.as_str(),
        "arch": platform.arch,
        "kernel": platform.kernel,
    })
}

// J5-D begin: the running platform's closed set (§3.2)
/// The closed set this build observes: `linux-closed-v1` on Linux built for
/// an architecture the syscall tables cover, and none anywhere else (macOS,
/// and a Linux build for another architecture, whose observer reports
/// `unsupported_architecture`; §3.2).
fn closed_set() -> Option<&'static str> {
    closed_set_for(cfg!(target_os = "linux"), std::env::consts::ARCH)
}

/// [`closed_set`] for a stated OS and architecture.
fn closed_set_for(linux: bool, arch: &str) -> Option<&'static str> {
    (linux && ouro_jail::platform::linux::seccomp::tables_cover(arch))
        .then(CoverageSummary::linux_closed_set)
}
// J5-D end

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
            // J5-C: the announced wire identifiers are frozen (jail-v1 §13)
            "frozen": ouro_jail::records::SCHEMAS_FROZEN,
            "observation": { "closed_set": closed_set() },
            // J5-D
            "build": build_json(),
        }));
    } else {
        println!("ouro-jail {}", env!("CARGO_PKG_VERSION"));
        println!(
            "platform {} {} ({})",
            platform.os.as_str(),
            platform.arch,
            platform.kernel
        );
        println!("closed set {}", closed_set().unwrap_or("none"));
        for (name, value) in [
            ("receipt", SCHEMA_RECEIPT),
            ("event", SCHEMA_EVENT),
            ("policy", SCHEMA_POLICY),
            ("policy_snapshot", SCHEMA_POLICY_SNAPSHOT),
            ("policy_file", SCHEMA_POLICY_FILE),
            ("gate", SCHEMA_GATE),
            ("control", SCHEMA_CONTROL),
            ("network", SCHEMA_NETWORK),
            ("learned_policy", records::SCHEMA_LEARNED_POLICY),
            // J5-D
            ("doctor", SCHEMA_DOCTOR),
        ] {
            println!("schema {name} {value}");
        }
        if ouro_jail::records::SCHEMAS_FROZEN {
            println!("schemas frozen (milestone 1)");
        }
        // J5-D
        print_build_text();
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

// Security 2026-10-08 (audit M1): the text rendering is a pure function, so
// the escaping of untrusted strings is unit-testable; every field a workspace
// `ouro.toml` or a child-chosen name can carry goes through
// `records::escape_control` before it reaches the terminal.
fn print_explain_text(report: &ExplainReport) {
    print!("{}", explain_text(report));
}

fn explain_text(report: &ExplainReport) -> String {
    use std::fmt::Write as _;
    let snapshot = &report.resolved.snapshot;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "policy {}",
        records::escape_control(&report.resolved.policy_name)
    );
    let _ = writeln!(out, "profile {}", snapshot.profile.as_str());
    let _ = writeln!(out, "platform {}", snapshot.platform.as_str());
    let _ = writeln!(out, "digest {}", report.resolved.digest);
    let _ = writeln!(
        out,
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
    let _ = writeln!(out, "network {}", snapshot.network.mode);
    for reference in &snapshot.filesystem.read_write {
        let _ = writeln!(
            out,
            "read_write {}",
            records::escape_control(&reference.to_display())
        );
    }
    for reference in &snapshot.filesystem.read_only {
        let _ = writeln!(
            out,
            "read_only {}",
            records::escape_control(&reference.to_display())
        );
    }
    for reference in &snapshot.filesystem.deny_read {
        let _ = writeln!(
            out,
            "deny_read {}",
            records::escape_control(&reference.to_display())
        );
    }
    let _ = writeln!(
        out,
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
            let _ = writeln!(
                out,
                "limit {key}={} required={}",
                ceiling.value, ceiling.required
            );
        }
    }
    // J3-launch begin: the launch group by the profile's own names only
    if let Some(launch) = &snapshot.launch {
        let _ = writeln!(
            out,
            "launch state_var={} home_is_state={}",
            match &launch.state_var {
                Some(state_var) => records::escape_control(state_var),
                None => "none".to_owned(),
            },
            launch.home_is_state
        );
        for subdir in &launch.state_subdirs {
            let _ = writeln!(
                out,
                "launch state_subdir {}",
                records::escape_control(&subdir.to_display())
            );
        }
        for credential in &launch.credentials {
            let _ = writeln!(
                out,
                "launch credential {} mode={} dest={} source=omitted",
                records::escape_control(&credential.id),
                records::escape_control(&credential.mode),
                records::escape_control(&credential.dest.to_display())
            );
        }
    }
    // J3-launch end
    for requirement in &report.resolved.requirements {
        let _ = writeln!(out, "requirement {requirement} unmeasured");
    }
    let _ = writeln!(out, "capabilities unmeasured (explain does not probe)");
    out
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
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut value = serde_json::json!({
        // J5-D: a versioned record (§3.2), with what built this binary
        "schema": SCHEMA_DOCTOR,
        "build": build_json(),
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
            "resolution": launch.resolution,
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
    });
    // J4 autoscope: what the supervisor scope step did for this `doctor`
    // (the `supervisor_scope` capability row carries its state too).
    #[cfg(target_os = "linux")]
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "supervisor_scope".to_owned(),
            ouro_jail::platform::linux::scope::details(),
        );
    }
    // J5-D begin: the host manifest (§3.2) and the binaries (§14.1)
    if let Some(object) = value.as_object_mut() {
        object.insert("binaries".to_owned(), binaries_json());
        #[cfg(target_os = "linux")]
        object.insert(
            "host".to_owned(),
            ouro_jail::platform::linux::host::manifest(),
        );
    }
    // J5-D end
    value
}

// J5-D begin
/// The binaries this `doctor` vouches for: itself, and on Linux the
/// bubblewrap the platform resolved. The resolution is made once per
/// process (`resolved_bwrap`), so the record names exactly the file every
/// probe and run executes, not a second lookup.
fn binaries_json() -> serde_json::Value {
    let mut binaries = serde_json::Map::new();
    binaries.insert(
        "ouro-jail".to_owned(),
        ouro_jail::platform::linux::host::own_binary(),
    );
    #[cfg(target_os = "linux")]
    binaries.insert(
        "bwrap".to_owned(),
        ouro_jail::platform::linux::host::bwrap_binary(
            ouro_jail::platform::linux::platform::resolved_bwrap().ok(),
        ),
    );
    serde_json::Value::Object(binaries)
}
// J5-D end

// Security 2026-10-08 (audit M1): the launch-profile name and credential
// fields come from a workspace `launch.toml`, so they are escaped like every
// other text rendering; the pure helper is unit-testable.
fn print_doctor_text(report: &DoctorReport) {
    print!("{}", doctor_text(report));
}

fn doctor_text(report: &DoctorReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "platform {} {} ({})",
        report.platform.os.as_str(),
        report.platform.arch,
        report.platform.kernel
    );
    for capability in &report.capabilities {
        let _ = writeln!(
            out,
            "capability {} {} scope={} reason={}",
            capability.name,
            status_name(capability),
            scope_name(capability),
            capability.reason_code.as_deref().unwrap_or("none")
        );
    }
    // J3-launch begin: §14.1 launch readiness, names and statuses only
    if let Some(launch) = &report.launch {
        let _ = writeln!(
            out,
            "launch {} {} reason={}",
            records::escape_control(&launch.name),
            launch.support,
            launch.support_reason
        );
        for check in &launch.credentials {
            let _ = writeln!(
                out,
                "credential {} mode={} dest={} {} reason={}",
                records::escape_control(&check.id),
                check.mode,
                records::escape_control(&check.dest.to_display()),
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
    let _ = writeln!(out, "ready {}", report.ready);
    out
}

// ---------------------------------------------------------------------------
// gc
// ---------------------------------------------------------------------------

fn gc(context: &Context, args: &GcArgs) -> ExitCode {
    // J4-G: the report of `gc::gc`, whose shape adds the reconciliation
    // fields (owner, cgroup, scratch, recorded), the S7 budget and the S9
    // seams to J3's.
    let report = match ouro_jail::gc::gc(context, args) {
        Ok(report) => report,
        // §6.4: `gc` uses 1 for failed cleanup or state access, whatever the
        // underlying code's usual mapping would be.
        Err(error) => {
            ouro_jail::diag!("{error}");
            return ExitCode::from(1);
        }
    };
    if args.json {
        print_json(&gc_json(&report));
    } else {
        print!("{}", gc_text(&report));
    }
    // J3-launch begin: §6.4 — a cleanup that stopped again exits 1, after the
    // report is printed (J3 review L1).
    if !report.incomplete.is_empty() {
        ouro_jail::diag!(
            "ouro-jail: cleanup did not complete for: {}",
            report.incomplete.join(", ")
        );
        return ExitCode::from(1);
    }
    // J3-launch end
    ExitCode::SUCCESS
}

// J5-D: the text rendering as a function, so its keys are unit-tested
/// Renders `gc`'s text report, one line per fact.
fn gc_text(report: &ouro_jail::gc::Report) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for entry in &report.entries {
        // Security 2026-10-08 (audit M1): the attempt id and the path-like
        // fields are child-chosen or observed on disk, so they are escaped
        // before reaching the terminal; `action` and `reason` are this
        // crate's own spellings.
        let attempt_id = records::escape_control(&entry.attempt_id);
        let _ = writeln!(out, "{} {} {}", attempt_id, entry.action, entry.reason);
        // J3-agent begin
        if let Some(proxy_dir) = &entry.proxy_dir {
            let _ = writeln!(
                out,
                "{} proxy_dir {}",
                attempt_id,
                records::escape_control(proxy_dir)
            );
        }
        // J3-agent end
        // J4-G begin
        for (key, value) in [
            ("owner", &entry.owner),
            // J5-D: the portable name of what became of the execution
            // boundary (on Linux, the recorded cgroup leaf).
            ("execution_boundary", &entry.cgroup),
            ("scratch", &entry.scratch),
        ] {
            if let Some(value) = value {
                let _ = writeln!(
                    out,
                    "{} {key} {}",
                    attempt_id,
                    records::escape_control(value)
                );
            }
        }
        for action in &entry.recorded {
            let _ = writeln!(out, "{} recorded {action}", attempt_id);
        }
        // J4-G end
        // J4 W2-S begin
        for name in &entry.leftover_temp_files {
            let _ = writeln!(
                out,
                "{} leftover_temp_file {}",
                attempt_id,
                records::escape_control(name)
            );
        }
        if let Some(temp_files) = &entry.temp_files {
            let _ = writeln!(
                out,
                "{} temp_files {}",
                attempt_id,
                records::escape_control(temp_files)
            );
        }
        // J4 W2-S end
    }
    let _ = writeln!(out, "scanned {}", report.entries.len());
    // J4-G begin: S7, S9
    let _ = writeln!(
        out,
        "entries {} of {}{}",
        report.budget.charged,
        report.budget.max_entries,
        if report.budget.listing_complete {
            ""
        } else {
            " (listing incomplete)"
        }
    );
    for (name, value) in &report.test_seams {
        let _ = writeln!(out, "test_seam {name}={value}");
    }
    // J4-G end
    out
}

fn gc_json(report: &ouro_jail::gc::Report) -> serde_json::Value {
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
                // J4-G begin
                "owner": entry.owner,
                // J5-D: portable key; the value is the platform's report
                "execution_boundary": entry.cgroup,
                "scratch": entry.scratch,
                "recorded": entry.recorded,
                // J4-G end
                // J4 W2-S: leftover `.tmp` files a crash left (§7)
                "leftover_temp_files": entry.leftover_temp_files,
                "temp_files": entry.temp_files,
            }))
            .collect::<Vec<_>>(),
        // J4-G begin: S7 and S9
        "budget": {
            "max_entries": report.budget.max_entries,
            "charged": report.budget.charged,
            "exhausted": report.budget.exhausted,
            "listing_complete": report.budget.listing_complete,
        },
        "test_seams": report.test_seams,
        // J4-G end
    })
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

fn run(context: &Context, args: &RunArgs) -> ExitCode {
    // J5-B1: X05.3 — this binary's stdout is the target's (§8.3).
    supervisor::release_stdout_after_prepare();
    let report = supervisor::run(context, args);
    // §6.1: `--label-only` prints the proposed execution label and describes
    // each capability; it executes nothing and copies no credential.
    if let Some(label) = &report.label {
        // Security 2026-10-08 (audit M1): the label carries child-chosen
        // names (target path, profile), so it is escaped like every other
        // text rendering.
        println!("{}", records::escape_control(label));
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
        ouro_jail::diag!("{error}");
    }
    // J4 W3, P5: every error no durable receipt carries reaches stderr.
    for error in &report.unrecorded {
        ouro_jail::diag!("{error}");
    }
    // I05: evidence health is a separate fact from the attempt's outcome, so a
    // trace failure gets its own diagnostic line rather than replacing one.
    if let Some(error) = &report.trace_error {
        ouro_jail::diag!("{error}");
    }
    // J4-G: control messages the consumer never took are reported, never
    // waited on (§13.3); the count comes from `RunReport.control_dropped`.
    if report.control_dropped > 0 {
        ouro_jail::diag!(
            "ouro-jail: {} control message(s) were dropped: the --control-fd consumer did not \
             read them",
            report.control_dropped
        );
    }
    if let Some(path) = &report.receipt_path
        && report.receipt.is_some()
        && stderr_is_a_terminal()
    {
        // §8.3: the child's stderr is inherited without capture. Writing the
        // supervisor's own diagnostic into it would make the stream differ
        // from direct execution (X05), so the line goes out only when a
        // terminal is watching, where no byte comparison is being made.
        ouro_jail::diag!("ouro-jail: receipt {}", path.display());
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
        "__watch" => ouro_jail::platform::linux::watch::watcher_main(&args[2..]),
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

// J5-D begin: unit tests of the renderings this binary owns
#[cfg(test)]
mod tests {
    use super::*;

    fn gc_report(boundary: Option<&str>) -> ouro_jail::gc::Report {
        ouro_jail::gc::Report {
            entries: vec![ouro_jail::gc::Entry {
                attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
                action: "retained".to_owned(),
                reason: "a reason".to_owned(),
                cgroup: boundary.map(str::to_owned),
                ..ouro_jail::gc::Entry::default()
            }],
            dry_run: true,
            incomplete: Vec::new(),
            budget: ouro_jail::gc::Budget {
                max_entries: 10,
                charged: 1,
                exhausted: false,
                listing_complete: true,
            },
            test_seams: std::collections::BTreeMap::new(),
        }
    }

    /// Decision 2026-09-24: gc names what became of the execution boundary
    /// in portable terms, in both renderings; a Linux cgroup is the value's
    /// business, not the key's.
    #[test]
    fn gc_names_the_execution_boundary_in_both_renderings() {
        let report = gc_report(Some("removed"));
        let json = gc_json(&report);
        let entry = json["entries"][0].as_object().expect("an entry");
        assert_eq!(entry["execution_boundary"], "removed", "{json:#}");
        assert!(!entry.contains_key("cgroup"), "{json:#}");

        let text = gc_text(&report);
        assert!(
            text.lines().any(|line| line
                == "att_00000000-0000-4000-8000-000000000001 execution_boundary removed"),
            "{text}"
        );
        assert!(!text.contains(" cgroup "), "{text}");

        // Absent is rendered as null in JSON and as no line in text.
        let report = gc_report(None);
        assert_eq!(
            gc_json(&report)["entries"][0]["execution_boundary"],
            serde_json::Value::Null
        );
        assert!(!gc_text(&report).contains("execution_boundary"));
    }

    // Security 2026-10-08 (audit M1): a resolved policy carrying a hostile
    // workspace `ouro.toml` string must never render raw terminal control
    // bytes. `minimal_resolved` mirrors `supervisor`'s own test helper.
    fn m1_resolved() -> ouro_jail::policy::Resolved {
        let profile = ouro_jail::policy::ProfileName::Tool;
        let baseline = ouro_jail::profiles::baseline(profile, records::Os::Macos, &|_| None);
        let inputs = ouro_jail::policy::ResolveInputs {
            platform: records::Os::Macos,
            base_profile: profile,
            policy_name: profile.as_str().to_owned(),
            baseline,
            workspace: b"/work".to_vec(),
            scratch: ouro_jail::policy::ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        };
        ouro_jail::policy::resolve(&inputs).expect("resolves")
    }

    fn m1_explain(mut resolved: ouro_jail::policy::Resolved) -> ExplainReport {
        resolved
            .snapshot
            .filesystem
            .deny_read
            .push(ouro_jail::policy::PathRef::host(
                records::NativeString::from_bytes("sec\u{1b}]52;c;SGVsbG8=\u{7}ret")
                    .expect("valid"),
            ));
        ExplainReport {
            resolved,
            platform: m1_platform(),
        }
    }

    fn m1_platform() -> PlatformRecord {
        PlatformRecord {
            os: records::Os::Macos,
            arch: std::env::consts::ARCH.to_owned(),
            kernel: "test".to_owned(),
        }
    }

    /// Audit M1: an OSC-52 payload from a workspace `ouro.toml`
    /// `deny_read` entry rendered through `explain`'s text output carries no
    /// raw ESC or BEL — the same class A6 fixed on stderr.
    #[test]
    fn an_osc52_deny_read_entry_is_escaped_in_explain_text() {
        let text = explain_text(&m1_explain(m1_resolved()));
        assert!(
            text.contains("deny_read host:sec<U+001B>]52;c;SGVsbG8=<U+0007>ret"),
            "{text}"
        );
        assert!(!text.contains('\u{1b}'), "a raw ESC reached stdout: {text}");
        assert!(!text.contains('\u{7}'), "a raw BEL reached stdout: {text}");
    }

    /// Audit M1: bidi controls in child-chosen names are escaped, and clean
    /// ASCII renders byte-identically to the pre-M1 output.
    #[test]
    fn bidi_controls_are_escaped_and_clean_text_is_unchanged() {
        let mut resolved = m1_resolved();
        resolved
            .snapshot
            .filesystem
            .read_only
            .push(ouro_jail::policy::PathRef::host(
                records::NativeString::from_bytes("sec\u{202e}ret").expect("valid"),
            ));
        let text = explain_text(&ExplainReport {
            resolved,
            platform: m1_platform(),
        });
        assert!(text.contains("read_only host:sec<U+202E>ret"), "{text}");
        assert!(!text.contains('\u{202e}'), "{text}");

        // Clean input: byte-identical to the pre-M1 renderer.
        let clean = explain_text(&ExplainReport {
            resolved: m1_resolved(),
            platform: m1_platform(),
        });
        assert!(clean.starts_with("policy tool\nprofile tool\n"), "{clean}");
        assert!(
            clean
                .lines()
                .any(|line| line == "capabilities unmeasured (explain does not probe)"),
            "{clean}"
        );
        assert!(
            clean.chars().all(|c| c.is_ascii() || !c.is_control()),
            "{clean}"
        );
    }

    /// Audit M1: a hostile attempt id in `gc`'s text rendering is escaped
    /// (the same renderer the A6 fix does not cover).
    #[test]
    fn gc_text_escapes_a_hostile_attempt_id() {
        let mut report = gc_report(Some("removed"));
        report.entries[0].attempt_id = "att\u{1b}]52;c;YQ==\u{7}".to_owned();
        let text = gc_text(&report);
        assert!(
            text.contains("att<U+001B>]52;c;YQ==<U+0007> retained"),
            "{text}"
        );
        assert!(!text.contains('\u{1b}'), "{text}");

        // And a bidi control in a leftover temp file name.
        let mut report = gc_report(None);
        report.entries[0].leftover_temp_files = vec!["\u{202e}tmp".to_owned()];
        let text = gc_text(&report);
        assert!(text.contains("leftover_temp_file <U+202E>tmp"), "{text}");
    }

    /// Review F7: `version` announces the closed set only where this build
    /// can observe it: Linux on an architecture the syscall tables cover.
    #[test]
    fn the_closed_set_is_announced_only_where_the_build_can_observe_it() {
        assert_eq!(closed_set_for(true, "x86_64"), Some("linux-closed-v1"));
        assert_eq!(closed_set_for(true, "aarch64"), Some("linux-closed-v1"));
        for arch in ["riscv64", "x86", ""] {
            assert_eq!(closed_set_for(true, arch), None, "{arch}");
        }
        for arch in ["x86_64", "aarch64"] {
            assert_eq!(closed_set_for(false, arch), None, "macOS {arch}");
        }
        // And the running binary uses exactly that rule.
        assert_eq!(
            closed_set(),
            closed_set_for(cfg!(target_os = "linux"), std::env::consts::ARCH)
        );
    }

    /// §16 build provenance: the build environment's claims are validated
    /// (build.rs fails the build with these same errors; review F8).
    #[test]
    fn build_claims_are_a_full_commit_and_a_consistent_flag() {
        use build_provenance::{Claims, validate};
        let full = "48a229ceaefd4985c50990b14116b6d856af0985";
        assert_eq!(
            validate(Some(full), Some("false")),
            Ok(Claims {
                revision: Some(full.to_owned()),
                dirty: Some(false)
            })
        );
        assert_eq!(
            validate(Some(&full.to_ascii_uppercase()), Some("1"))
                .unwrap()
                .revision
                .as_deref(),
            Some(full),
            "hex is recorded lowercased"
        );
        assert_eq!(
            validate(Some(&format!(" {full}\n")), None),
            Ok(Claims {
                revision: Some(full.to_owned()),
                dirty: None
            })
        );
        // Unset and empty are unknown, never an error.
        for (revision, dirty) in [(None, None), (Some(""), Some("")), (Some(""), None)] {
            assert_eq!(
                validate(revision, dirty),
                Ok(Claims {
                    revision: None,
                    dirty: None
                })
            );
        }
        // Malformed or contradictory claims are refused.
        for revision in [
            "48a229cea",
            "48a229ceaefd4985c50990b14116b6d856af09850",
            "g8a229ceaefd4985c50990b14116b6d856af0985",
            "HEAD",
            "0000000000000000000000000000000000000000",
        ] {
            assert!(validate(Some(revision), None).is_err(), "{revision}");
        }
        for dirty in ["yes", "dirty", "no"] {
            assert!(validate(Some(full), Some(dirty)).is_err(), "{dirty}");
        }
        assert!(
            validate(None, Some("false")).is_err(),
            "a clean claim about no revision"
        );
        assert!(validate(Some(""), Some("true")).is_err());
    }

    /// The inputs digest is the documented construction.
    #[test]
    fn the_inputs_digest_is_the_documented_construction() {
        use sha2::Digest as _;
        let files: [(&str, &[u8]); 2] = [("a", b"xy"), ("b/c", b"")];
        let mut expected = Vec::new();
        expected.extend_from_slice(b"a\0");
        expected.extend_from_slice(&2u64.to_le_bytes());
        expected.extend_from_slice(b"xy");
        expected.extend_from_slice(b"b/c\0");
        expected.extend_from_slice(&0u64.to_le_bytes());
        let hex: String = sha2::Sha256::digest(&expected)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(build_provenance::digest(files), format!("sha256:{hex}"));
        // A different path or content is a different digest.
        assert_ne!(
            build_provenance::digest([("a", &b"xy"[..])]),
            build_provenance::digest([("A", &b"xy"[..])])
        );
    }
}
// J5-D end
