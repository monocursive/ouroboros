//! Service manager installation, identity validation, and recovery readiness.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceKind {
    Launchd,
    SystemdUser,
}

impl ServiceKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Launchd => "launchd user agent",
            Self::SystemdUser => "systemd user service",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceInstall {
    pub kind: ServiceKind,
    pub path: PathBuf,
    pub activation: String,
    pub deactivation: String,
    pub installed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ServiceEnvironment {
    pub(super) path: String,
    pub(super) provider_paths: Vec<(String, String)>,
    pub(super) workspace_roots: String,
    pub(super) gateway_max_frame: u64,
    pub(super) gateway_queue_limit: u64,
}

pub(super) const DEFAULT_GATEWAY_MAX_FRAME: u64 = 1_048_576;
pub(super) const DEFAULT_GATEWAY_QUEUE_LIMIT: u64 = 1_000;

pub(super) const PROVIDER_PATH_VARIABLES: [&str; 2] = ["AMP_CLI_PATH", "GEMINI_CLI_PATH"];
pub(super) const ADVANCED_SERVICE_AUTHORITY_VARIABLES: [&str; 15] = [
    "OUROBOROS_FORGE_BUILDER_NODE",
    "OUROBOROS_SIGNER_KEY_PATH",
    "OUROBOROS_SIGNER_ID",
    "OUROBOROS_SIGNING_CALL_TIMEOUT_MS",
    "OUROBOROS_SIGNING_RATE_LIMIT_PER_MINUTE",
    "OUROBOROS_SIGNING_REQUIRE_EVAL",
    "OUROBOROS_SIGNING_NODE",
    "OUROBOROS_FORGE_SIGNER_ID",
    "OUROBOROS_ORCHESTRATION_CONCURRENCY",
    "OUROBOROS_ORCHESTRATION_FORGE_WORKSPACE",
    "OUROBOROS_ORCHESTRATION_FORGE_NODES",
    "OUROBOROS_ORCHESTRATION_TEAM_ID",
    "OUROBOROS_ORCHESTRATION_WORKER_ID",
    "OUROBOROS_CONTROL_ALLOW_FORGE_STEPS",
    "OUROBOROS_UPGRADE_TRUSTED_SIGNERS",
];

pub(super) fn capture_service_environment() -> Result<ServiceEnvironment> {
    let raw_path = std::env::var_os("PATH")
        .ok_or_else(|| anyhow!("PATH is not set; Ouroboros cannot preserve provider CLI lookup"))?;
    let entries = std::env::split_paths(&raw_path).collect::<Vec<_>>();
    if entries.is_empty() {
        bail!("PATH is empty; set an absolute provider PATH before installing recovery");
    }
    for entry in &entries {
        if !entry.is_absolute() {
            bail!(
                "PATH entry `{}` is relative; set PATH to absolute directories before running `ouro fleet service install`",
                entry.display()
            );
        }
        path_text(entry).context("validating a service PATH entry")?;
    }
    let path = std::env::join_paths(&entries)
        .context("encoding PATH for the recovery service")?
        .into_string()
        .map_err(|_| {
            anyhow!("PATH contains non-UTF-8 bytes and cannot be stored in a service unit")
        })?;

    let mut provider_paths = Vec::new();
    for variable in PROVIDER_PATH_VARIABLES {
        let Some(value) = std::env::var_os(variable) else {
            continue;
        };
        let value = PathBuf::from(value);
        if !value.is_absolute() {
            bail!(
                "{variable}={} is relative; use an absolute CLI path before installing recovery",
                value.display()
            );
        }
        let value = path_text(&value)
            .with_context(|| format!("validating {variable} for the recovery service"))?
            .to_string();
        provider_paths.push((variable.to_string(), value));
    }
    let workspace_roots = match std::env::var_os("OUROBOROS_WORKSPACE_ROOTS") {
        None => String::new(),
        Some(raw) if raw.is_empty() => String::new(),
        Some(raw) => {
            let entries = std::env::split_paths(&raw).collect::<Vec<_>>();
            if entries.is_empty() {
                bail!("OUROBOROS_WORKSPACE_ROOTS is set but contains no workspace");
            }
            for entry in &entries {
                if !entry.is_absolute() {
                    bail!(
                        "OUROBOROS_WORKSPACE_ROOTS entry {} is relative; recovery services require absolute admitted workspace roots",
                        entry.display()
                    );
                }
                path_text(entry).context("validating an admitted workspace root")?;
            }
            std::env::join_paths(entries)
                .context("encoding OUROBOROS_WORKSPACE_ROOTS for the recovery service")?
                .into_string()
                .map_err(|_| {
                    anyhow!(
                        "OUROBOROS_WORKSPACE_ROOTS contains non-UTF-8 bytes and cannot be stored in a service unit"
                    )
                })?
        }
    };
    let gateway_max_frame = capture_service_limit(
        "OUROBOROS_GATEWAY_MAX_FRAME",
        DEFAULT_GATEWAY_MAX_FRAME,
        1_024,
    )?;
    let gateway_queue_limit = capture_service_limit(
        "OUROBOROS_GATEWAY_QUEUE_LIMIT",
        DEFAULT_GATEWAY_QUEUE_LIMIT,
        1,
    )?;
    let advanced = ADVANCED_SERVICE_AUTHORITY_VARIABLES
        .into_iter()
        .filter(|variable| std::env::var_os(variable).is_some_and(|value| !value.is_empty()))
        .collect::<Vec<_>>();
    if !advanced.is_empty() {
        bail!(
            "automatic fleet recovery does not silently copy advanced signing/forge/orchestration authority ({}) into a user service. Unset these variables for the beginner recovery unit, or run service-run from your own reviewed process-manager boundary",
            advanced.join(", ")
        );
    }
    Ok(ServiceEnvironment {
        path,
        provider_paths,
        workspace_roots,
        gateway_max_frame,
        gateway_queue_limit,
    })
}

pub(super) fn capture_service_limit(name: &str, default: u64, minimum: u64) -> Result<u64> {
    let value = match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} is not valid UTF-8"),
        Ok(value) => Some(value),
    };
    parse_service_limit(name, value.as_deref(), default, minimum)
}

pub(super) fn parse_service_limit(
    name: &str,
    raw: Option<&str>,
    default: u64,
    minimum: u64,
) -> Result<u64> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };
    let value = raw
        .parse::<u64>()
        .with_context(|| format!("{name} must be a base-10 integer of at least {minimum}"))?;
    if value < minimum {
        bail!("{name} must be an integer of at least {minimum}, got {value}");
    }
    Ok(value)
}

/// The only operator authority settings a packaged fleet runtime may inherit. The
/// launcher removes every ambient `OUROBOROS_*` variable first, then reapplies these
/// normalized values beside the profile/product-owned environment.
pub(crate) fn validated_runtime_authority_env(
    caller: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    let value = |name: &str| {
        caller
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let workspace_roots = value("OUROBOROS_WORKSPACE_ROOTS")
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    validate_installed_workspace_roots(&workspace_roots)
        .context("validating inherited OUROBOROS_WORKSPACE_ROOTS")?;
    let gateway_max_frame = parse_service_limit(
        "OUROBOROS_GATEWAY_MAX_FRAME",
        value("OUROBOROS_GATEWAY_MAX_FRAME"),
        DEFAULT_GATEWAY_MAX_FRAME,
        1_024,
    )?;
    let gateway_queue_limit = parse_service_limit(
        "OUROBOROS_GATEWAY_QUEUE_LIMIT",
        value("OUROBOROS_GATEWAY_QUEUE_LIMIT"),
        DEFAULT_GATEWAY_QUEUE_LIMIT,
        1,
    )?;
    Ok(vec![
        ("OUROBOROS_WORKSPACE_ROOTS".into(), workspace_roots),
        (
            "OUROBOROS_GATEWAY_MAX_FRAME".into(),
            gateway_max_frame.to_string(),
        ),
        (
            "OUROBOROS_GATEWAY_QUEUE_LIMIT".into(),
            gateway_queue_limit.to_string(),
        ),
    ])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServiceFact {
    Yes,
    No,
    Unknown,
}

impl ServiceFact {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ServiceManagerState {
    pub(super) active: ServiceFact,
    pub(super) enabled: ServiceFact,
    pub(super) linger: Option<ServiceFact>,
    pub(super) note: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ManagerCommandOutput {
    pub(super) code: Option<i32>,
    pub(super) stdout: String,
    pub(super) stderr: String,
    pub(super) timed_out: bool,
}

pub(super) const MANAGER_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) fn service_manager_state(kind: ServiceKind, profile: &Profile) -> ServiceManagerState {
    query_service_manager_with(kind, profile, run_manager_command)
}

pub(super) fn query_service_manager_with<F>(
    kind: ServiceKind,
    profile: &Profile,
    mut run: F,
) -> ServiceManagerState
where
    F: FnMut(&str, &[String]) -> Result<ManagerCommandOutput>,
{
    match kind {
        ServiceKind::Launchd => {
            let uid = unsafe { libc::geteuid() };
            let label = format!("dev.ouroboros.{}", profile.machine);
            let domain = format!("gui/{uid}");
            let target = format!("{domain}/{label}");
            let loaded = run("/bin/launchctl", &["print".into(), target]);
            let disabled = run("/bin/launchctl", &["print-disabled".into(), domain]);

            let active = match &loaded {
                Ok(output)
                    if output.code == Some(0)
                        && !output.timed_out
                        && output
                            .stdout
                            .lines()
                            .any(|line| line.trim().eq_ignore_ascii_case("state = running")) =>
                {
                    ServiceFact::Yes
                }
                // A loaded KeepAlive job can be waiting or crash-looping. Loaded is an
                // enabled fact, not proof that its foreground service-run is alive.
                Ok(output) if output.code == Some(0) && !output.timed_out => ServiceFact::No,
                Ok(output) if launchd_not_loaded(output) => ServiceFact::No,
                _ => ServiceFact::Unknown,
            };
            let enabled = match &disabled {
                Ok(output) if output.code == Some(0) && !output.timed_out => {
                    let disabled_true =
                        [format!("\"{label}\" => true"), format!("{label} => true")]
                            .iter()
                            .any(|needle| output.stdout.contains(needle));
                    if disabled_true {
                        ServiceFact::No
                    } else {
                        ServiceFact::Yes
                    }
                }
                _ => ServiceFact::Unknown,
            };
            ServiceManagerState {
                active,
                enabled,
                linger: None,
                note: manager_query_note(&[
                    ("launchctl print", loaded),
                    ("launchctl print-disabled", disabled),
                ]),
            }
        }
        ServiceKind::SystemdUser => {
            let unit = format!("ouroboros-{}.service", profile.machine);
            let active_result = run(
                "/usr/bin/systemctl",
                &["--user".into(), "is-active".into(), unit.clone()],
            );
            let enabled_result = run(
                "/usr/bin/systemctl",
                &["--user".into(), "is-enabled".into(), unit],
            );
            let linger_result = run(
                "/usr/bin/loginctl",
                &[
                    "show-user".into(),
                    unsafe { libc::geteuid() }.to_string(),
                    "-p".into(),
                    "Linger".into(),
                    "--value".into(),
                ],
            );
            let active = match &active_result {
                Ok(output) if !output.timed_out => match output.stdout.trim() {
                    "active" => ServiceFact::Yes,
                    "activating" | "reloading" => ServiceFact::Unknown,
                    "inactive" | "failed" | "deactivating" | "unknown" => ServiceFact::No,
                    _ => ServiceFact::Unknown,
                },
                _ => ServiceFact::Unknown,
            };
            let enabled = match &enabled_result {
                Ok(output) if !output.timed_out => match output.stdout.trim() {
                    "enabled" => ServiceFact::Yes,
                    "disabled" | "masked" | "masked-runtime" | "not-found" | "enabled-runtime"
                    | "linked" | "linked-runtime" | "alias" => ServiceFact::No,
                    _ => ServiceFact::Unknown,
                },
                _ => ServiceFact::Unknown,
            };
            let linger = match &linger_result {
                Ok(output) if output.code == Some(0) && !output.timed_out => {
                    match output.stdout.trim() {
                        "yes" => ServiceFact::Yes,
                        "no" => ServiceFact::No,
                        _ => ServiceFact::Unknown,
                    }
                }
                _ => ServiceFact::Unknown,
            };
            ServiceManagerState {
                active,
                enabled,
                linger: Some(linger),
                note: manager_query_note(&[
                    ("systemctl is-active", active_result),
                    ("systemctl is-enabled", enabled_result),
                    ("loginctl Linger", linger_result),
                ]),
            }
        }
    }
}

pub(super) fn launchd_not_loaded(output: &ManagerCommandOutput) -> bool {
    !output.timed_out
        && output.code.is_some_and(|code| code != 0)
        && format!("{}\n{}", output.stdout, output.stderr)
            .to_ascii_lowercase()
            .contains("could not find service")
}

pub(super) fn manager_query_note(
    results: &[(&str, Result<ManagerCommandOutput>)],
) -> Option<String> {
    let mut problems = Vec::new();
    for (label, result) in results {
        match result {
            Err(error) => problems.push(format!("{label} could not run: {error}")),
            Ok(output) if output.timed_out => problems.push(format!("{label} timed out after 2s")),
            Ok(_) => {}
        }
    }
    (!problems.is_empty()).then(|| problems.join("; "))
}

pub(super) fn run_manager_command(program: &str, args: &[String]) -> Result<ManagerCommandOutput> {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    let output = crate::subprocess::output(command, MANAGER_QUERY_TIMEOUT, || false)
        .with_context(|| format!("querying {program}"))?;
    Ok(ManagerCommandOutput {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        timed_out: false,
    })
}

/// Installs only the declarative unit. Starting a persistent background process is left
/// as one explicit OS-native command printed to the operator.
pub fn service_install(data_dir: &Path) -> Result<ServiceInstall> {
    let profile = load(data_dir)?.ok_or_else(|| {
        anyhow!("this machine is standalone; create or join a fleet before installing recovery")
    })?;
    let executable = std::env::current_exe()
        .context("locating the current ouro executable")?
        .canonicalize()
        .context("resolving the current ouro executable")?;
    let environment = capture_service_environment()?;
    let (kind, path) = service_path(&profile)?;
    let contents = render_service_unit(kind, &profile, data_dir, &executable, &environment)?;
    let activation = service_activation(kind, &profile, &path);
    let deactivation = service_deactivation(kind, &profile, &path);

    if path
        .try_exists()
        .with_context(|| format!("inspecting {}", path.display()))?
    {
        let existing = read_private(&path, kind.label())?;
        if existing == contents {
            return Ok(ServiceInstall {
                kind,
                path,
                activation,
                deactivation,
                installed: false,
            });
        }
        bail!(
            "{} already exists with different contents; nothing was overwritten. Inspect or remove that unit explicitly",
            path.display()
        );
    }

    write_private_new(&path, contents.as_bytes(), kind.label())?;
    Ok(ServiceInstall {
        kind,
        path,
        activation,
        deactivation,
        installed: true,
    })
}

/// Activate only a generated, identity-checked unit. Called by explicit `--activate`
/// enrollment and `fleet service start`; no shell interprets the printed guidance.
pub fn service_activate(data_dir: &Path) -> Result<()> {
    let profile = load(data_dir)?.ok_or_else(|| anyhow!("no fleet profile"))?;
    let (kind, path) = service_path(&profile)?;
    let contents = read_private(&path, kind.label())?;
    validate_service_unit_identity(kind, &profile, data_dir, &contents)?;
    let state = service_manager_state(kind, &profile);
    let uid = unsafe { libc::geteuid() }.to_string();
    match kind {
        ServiceKind::Launchd => {
            let target = format!("gui/{uid}/dev.ouroboros.{}", profile.machine);
            service_action("/bin/launchctl", &["enable", &target])?;
            if state.active != ServiceFact::Yes {
                // bootstrap refuses an already loaded unit. A loaded, idle unit is
                // started with kickstart, which never kills an incumbent process.
                let loaded =
                    run_manager_command("/bin/launchctl", &["print".into(), target.clone()])?;
                if loaded.code != Some(0) {
                    service_action(
                        "/bin/launchctl",
                        &["bootstrap", &format!("gui/{uid}"), path_text(&path)?],
                    )?;
                } else {
                    service_action("/bin/launchctl", &["kickstart", &target])?;
                }
            }
        }
        ServiceKind::SystemdUser => {
            if state.linger != Some(ServiceFact::Yes) {
                service_action("/usr/bin/loginctl", &["--no-ask-password", "enable-linger", &uid])
                    .context("boot recovery requires user lingering; have the host administrator enable it, then retry fleet service start")?;
            }
            service_action("/usr/bin/systemctl", &["--user", "daemon-reload"])?;
            service_action(
                "/usr/bin/systemctl",
                &[
                    "--user",
                    "enable",
                    "--now",
                    &format!("ouroboros-{}.service", profile.machine),
                ],
            )?;
        }
    }
    Ok(())
}

pub(super) fn service_action(program: &str, args: &[&str]) -> Result<()> {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    let output = crate::subprocess::output(command, Duration::from_secs(30), || false)?;
    if !output.status.success() {
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn recovery_ready(data_dir: &Path) -> Result<()> {
    let profile = load(data_dir)?.ok_or_else(|| anyhow!("no fleet profile"))?;
    let (kind, path) = service_path(&profile)?;
    validate_service_unit_identity(
        kind,
        &profile,
        data_dir,
        &read_private(&path, kind.label())?,
    )?;
    let manager = service_manager_state(kind, &profile);
    if manager.active != ServiceFact::Yes
        || manager.enabled != ServiceFact::Yes
        || (kind == ServiceKind::SystemdUser && manager.linger != Some(ServiceFact::Yes))
    {
        bail!("recovery service is not active and persistently enabled; run ouro fleet service status");
    }
    Ok(())
}

/// A gateway listener alone is not proof of a usable distributed fleet.
pub fn validate_ready_status(status: &serde_json::Value, peer: Option<&str>) -> Result<()> {
    if status
        .pointer("/security/distributed")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
        || status
            .pointer("/security/tls")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        bail!("runtime has not established TLS distribution");
    }
    let machines = status
        .get("machines")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("fleet status has no machine inventory"))?;
    if !machines
        .iter()
        .any(|machine| machine["state"] == "local" && machine["compatibility"] == "local")
    {
        bail!("local machine is not healthy in fleet status");
    }
    if let Some(peer) = peer {
        if !machines.iter().any(|machine| {
            machine["node"] == peer
                && machine["state"] == "connected"
                && machine["compatibility"] == "compatible"
        }) {
            bail!("fleet peer {peer} is not connected with a compatible runtime");
        }
    }
    Ok(())
}

pub fn render_service_status(data_dir: &Path) -> Result<String> {
    let Some(profile) = load(data_dir)? else {
        return Ok("No fleet is configured, so no recovery service is expected.\n".into());
    };
    let (kind, path) = service_path(&profile)?;
    let installed = path.try_exists()?;
    let manager = service_manager_state(kind, &profile);
    let (configured_identity, unit_problem) = if installed {
        let contents = read_private(&path, kind.label())?;
        match validate_service_unit_identity(kind, &profile, data_dir, &contents) {
            Ok(identity) => (Some(identity), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        }
    } else {
        (None, None)
    };
    let runtime = match runtime::read_publication(data_dir)? {
        Some(publication) if runtime::publication_is_live(&publication)? => {
            format!("running (pid {})", publication.pid)
        }
        Some(publication) => format!("stopped (stale publication for pid {})", publication.pid),
        None => "stopped".into(),
    };
    let mut text = format!(
        "Fleet recovery service\n  manager       {}\n  unit          {}\n  installed     {}\n  integrity     {}\n  active        {}\n  enabled       {}\n  runtime       {}\n  runtime-log   {} (OTP live rotation after {} MiB; keeps {} private archives, .0 newest)\n  bootstrap-log {} (pre-start rotation after {} MiB; keeps {} private backups; raw output in one uninterrupted run may exceed the threshold)\n",
        kind.label(),
        path.display(),
        if installed { "yes" } else { "no" },
        match &unit_problem {
            Some(problem) => format!("DRIFTED — {problem}"),
            None if installed => "verified".into(),
            None => "not installed".into(),
        },
        manager.active.label(),
        manager.enabled.label(),
        runtime,
        data_dir.join(runtime::RUNTIME_LOG_FILE).display(),
        runtime::RUNTIME_LOG_MAX_BYTES / (1024 * 1024),
        runtime::RUNTIME_LOG_BACKUPS,
        data_dir.join(runtime::DAEMON_LOG_FILE).display(),
        runtime::DAEMON_LOG_MAX_BYTES / (1024 * 1024),
        runtime::DAEMON_LOG_BACKUPS,
    );
    if let Some(linger) = manager.linger {
        text.push_str(&format!("  linger       {}\n", linger.label()));
        match linger {
            ServiceFact::Yes => text.push_str(
                "  boot         may start before login (user lingering is enabled)\n",
            ),
            ServiceFact::No => text.push_str(
                "  boot         starts after this user logs in; for pre-login boot, optionally run `loginctl enable-linger \"$USER\"`\n",
            ),
            ServiceFact::Unknown => text.push_str(
                "  boot         pre-login behavior is unknown; inspect `loginctl show-user \"$USER\" -p Linger`\n",
            ),
        }
    }
    if let Some(note) = &manager.note {
        text.push_str(&format!("  query        {note}\n"));
    }
    text.push_str(&format!(
        "  CLI PATH     {}\n",
        configured_identity
            .as_ref()
            .map(|identity| identity.provider_path.as_str())
            .unwrap_or("not recorded")
    ));
    text.push_str(&format!(
        "  workspaces   {}\n",
        configured_identity
            .as_ref()
            .map(|identity| {
                if identity.workspace_roots.is_empty() {
                    "none admitted".to_string()
                } else {
                    identity.workspace_roots.clone()
                }
            })
            .unwrap_or_else(|| "not recorded".into())
    ));
    text.push_str(&format!(
        "  gateway cap {} bytes/frame, {} queued frames\n",
        configured_identity
            .as_ref()
            .map(|identity| identity.gateway_max_frame.to_string())
            .unwrap_or_else(|| "not recorded".into()),
        configured_identity
            .as_ref()
            .map(|identity| identity.gateway_queue_limit.to_string())
            .unwrap_or_else(|| "not recorded".into())
    ));
    text.push_str(
        "  credentials  HOME comes from the user manager; only PATH, provider CLI paths, admitted workspace roots, Codex network policy, and gateway resource bounds are copied—never API keys or arbitrary shell variables\n",
    );
    if installed && unit_problem.is_none() {
        text.push_str(&format!(
            "\nTo activate/reload it:\n  {}\n\nTo deactivate it before removal or planned maintenance:\n  {}\n",
            service_activation(kind, &profile, &path),
            service_deactivation(kind, &profile, &path)
        ));
    } else if let Some(problem) = unit_problem {
        text.push_str(&format!(
            "\nRecovery is NOT ready because the installed unit no longer matches this ouro executable/data directory: {problem}. Inspect it, deactivate it with:\n  {}\nThen run `ouro fleet service remove`, `ouro fleet service install`, and the newly printed activation command.\n",
            service_deactivation(kind, &profile, &path)
        ));
    } else {
        text.push_str("\nNext: `ouro fleet service install`.\n");
    }
    Ok(text)
}

pub fn service_remove(data_dir: &Path) -> Result<Option<PathBuf>> {
    let Some(profile) = load(data_dir)? else {
        return Ok(None);
    };
    let (kind, path) = service_path(&profile)?;
    let deactivation = service_deactivation(kind, &profile, &path);
    let manager = service_manager_state(kind, &profile);
    ensure_service_manager_inactive(kind, &manager, &deactivation)?;
    if let Some(publication) = runtime::read_publication(data_dir)? {
        if runtime::publication_is_live(&publication)? {
            bail!(
                "runtime pid {} is still running. If the unit is active, deactivate it with `{}`; then run `ouro stop` and retry. The unit was not removed",
                publication.pid, deactivation
            );
        }
    }
    runtime::ensure_no_live_runtime_owner(data_dir).with_context(|| {
        format!(
            "the recovery service or an unpublished runtime is still active. Deactivate the unit first with `{deactivation}`, then retry"
        )
    })?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let contents = read_private(&path, kind.label())?;
    let marker = service_marker(&profile);
    if !contents.contains(&marker)
        || !contents.contains("service-run")
        || !contents.contains("OUROBOROS_DATA_DIR")
    {
        bail!(
            "{} is not recognizably the generated unit for this machine; nothing was removed",
            path.display()
        );
    }
    fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    sync_parent(&path)?;
    Ok(Some(path))
}

pub(super) fn ensure_service_manager_inactive(
    kind: ServiceKind,
    manager: &ServiceManagerState,
    deactivation: &str,
) -> Result<()> {
    match manager.active {
        ServiceFact::Yes => bail!(
            "the {} still has this unit active. Deactivate it with `{deactivation}`, confirm `ouro fleet service status` says active no, then retry. The unit was not removed",
            kind.label()
        ),
        ServiceFact::Unknown => bail!(
            "Ouroboros could not prove the {} unit is inactive{}. Deactivate it with `{deactivation}`, then retry; removal fails closed while manager state is unknown",
            kind.label(),
            manager
                .note
                .as_deref()
                .map(|note| format!(" ({note})"))
                .unwrap_or_default()
        ),
        ServiceFact::No => {}
    }
    if kind == ServiceKind::SystemdUser {
        match manager.enabled {
            ServiceFact::Yes => bail!(
                "the systemd user unit is still enabled and could start again. Run `{deactivation}`, confirm `ouro fleet service status` says enabled no, then retry. The unit was not removed"
            ),
            ServiceFact::Unknown => bail!(
                "Ouroboros could not prove the systemd user unit is disabled. Run `{deactivation}`, then retry; removal fails closed while manager state is unknown"
            ),
            ServiceFact::No => {}
        }
    }
    Ok(())
}

pub(super) fn service_path(profile: &Profile) -> Result<(ServiceKind, PathBuf)> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("cannot locate the user home directory"))?;
    if cfg!(target_os = "macos") {
        Ok((
            ServiceKind::Launchd,
            home.join("Library")
                .join("LaunchAgents")
                .join(format!("dev.ouroboros.{}.plist", profile.machine)),
        ))
    } else if cfg!(target_os = "linux") {
        Ok((
            ServiceKind::SystemdUser,
            home.join(".config")
                .join("systemd")
                .join("user")
                .join(format!("ouroboros-{}.service", profile.machine)),
        ))
    } else {
        bail!(
            "automatic recovery services currently support macOS launchd and Linux systemd --user; run `ouro daemon` from your platform's process manager"
        )
    }
}

pub(super) fn render_service_unit(
    kind: ServiceKind,
    profile: &Profile,
    data_dir: &Path,
    executable: &Path,
    environment: &ServiceEnvironment,
) -> Result<String> {
    if !data_dir.is_absolute() || !executable.is_absolute() {
        bail!("service executable and data directory must be absolute paths");
    }
    let marker = service_marker(profile);
    let authority_marker = service_authority_marker(
        &environment.workspace_roots,
        environment.gateway_max_frame,
        environment.gateway_queue_limit,
    );
    match kind {
        ServiceKind::Launchd => {
            let executable = xml_escape(path_text(executable)?);
            let data_dir = xml_escape(path_text(data_dir)?);
            let service_path = xml_escape(&environment.path);
            let workspace_roots = xml_escape(&environment.workspace_roots);
            let gateway_max_frame = environment.gateway_max_frame;
            let gateway_queue_limit = environment.gateway_queue_limit;
            let provider_paths = environment
                .provider_paths
                .iter()
                .map(|(key, value)| {
                    format!(
                        "<key>{}</key><string>{}</string>",
                        xml_escape(key),
                        xml_escape(value)
                    )
                })
                .collect::<String>();
            let label = format!("dev.ouroboros.{}", profile.machine);
            Ok(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<!-- {marker} -->\n<!-- {authority_marker} -->\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{label}</string>\n  <key>ProgramArguments</key>\n  <array><string>{executable}</string><string>service-run</string></array>\n  <key>EnvironmentVariables</key>\n  <dict><key>OUROBOROS_DATA_DIR</key><string>{data_dir}</string><key>PATH</key><string>{service_path}</string><key>OUROBOROS_WORKSPACE_ROOTS</key><string>{workspace_roots}</string><key>OUROBOROS_GATEWAY_MAX_FRAME</key><string>{gateway_max_frame}</string><key>OUROBOROS_GATEWAY_QUEUE_LIMIT</key><string>{gateway_queue_limit}</string>{provider_paths}</dict>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>ThrottleInterval</key><integer>3</integer>\n  <key>ProcessType</key><string>Background</string>\n</dict>\n</plist>\n"
            ))
        }
        ServiceKind::SystemdUser => {
            let executable = systemd_quote(path_text(executable)?)?;
            let data_environment =
                systemd_quote(&format!("OUROBOROS_DATA_DIR={}", path_text(data_dir)?))?;
            let service_path = systemd_quote(&format!("PATH={}", environment.path))?;
            let workspace_roots = systemd_quote(&format!(
                "OUROBOROS_WORKSPACE_ROOTS={}",
                environment.workspace_roots
            ))?;
            let gateway_max_frame = systemd_quote(&format!(
                "OUROBOROS_GATEWAY_MAX_FRAME={}",
                environment.gateway_max_frame
            ))?;
            let gateway_queue_limit = systemd_quote(&format!(
                "OUROBOROS_GATEWAY_QUEUE_LIMIT={}",
                environment.gateway_queue_limit
            ))?;
            let provider_paths = environment
                .provider_paths
                .iter()
                .map(|(key, value)| systemd_quote(&format!("{key}={value}")))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .map(|value| format!("Environment={value}\n"))
                .collect::<String>();
            Ok(format!(
                "# {marker}\n# {authority_marker}\n[Unit]\nDescription=Ouroboros fleet machine {}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={executable} service-run\nEnvironment={data_environment}\nEnvironment={service_path}\nEnvironment={workspace_roots}\nEnvironment={gateway_max_frame}\nEnvironment={gateway_queue_limit}\n{provider_paths}Restart=always\nRestartSec=3\nTimeoutStopSec=25\n\n[Install]\nWantedBy=default.target\n",
                profile.machine
            ))
        }
    }
}

pub(super) fn service_environment_value(
    kind: ServiceKind,
    contents: &str,
    variable: &str,
) -> Option<String> {
    match kind {
        ServiceKind::Launchd => {
            let marker = format!("<key>{variable}</key><string>");
            let after = contents.split_once(&marker)?.1;
            let encoded = after.split_once("</string>")?.0;
            Some(xml_unescape(encoded))
        }
        ServiceKind::SystemdUser => {
            let marker = format!("Environment=\"{variable}=");
            let line = contents.lines().find(|line| line.starts_with(&marker))?;
            let value = line.strip_prefix(&marker)?;
            let mut decoded = String::new();
            let mut escaped = false;
            for character in value.chars() {
                if escaped {
                    decoded.push(character);
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    return Some(decoded);
                } else {
                    decoded.push(character);
                }
            }
            None
        }
    }
}

pub(super) fn required_service_environment(
    kind: ServiceKind,
    contents: &str,
    variable: &str,
) -> Result<String> {
    let marker = match kind {
        ServiceKind::Launchd => format!("<key>{variable}</key><string>"),
        ServiceKind::SystemdUser => format!("Environment=\"{variable}="),
    };
    if contents.match_indices(&marker).count() != 1 {
        bail!("recovery unit does not contain exactly one {variable} environment setting");
    }
    service_environment_value(kind, contents, variable)
        .ok_or_else(|| anyhow!("recovery unit has an unreadable {variable} environment setting"))
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ServiceUnitIdentity {
    pub(super) provider_path: String,
    pub(super) workspace_roots: String,
    pub(super) gateway_max_frame: u64,
    pub(super) gateway_queue_limit: u64,
}

pub(super) fn validate_service_unit_identity(
    kind: ServiceKind,
    profile: &Profile,
    data_dir: &Path,
    contents: &str,
) -> Result<ServiceUnitIdentity> {
    let executable = std::env::current_exe()
        .context("locating the current ouro executable for recovery-unit validation")?
        .canonicalize()
        .context("resolving the current ouro executable for recovery-unit validation")?;
    validate_service_unit_identity_with_executable(kind, profile, data_dir, &executable, contents)
}

pub(super) fn validate_service_unit_identity_with_executable(
    kind: ServiceKind,
    profile: &Profile,
    data_dir: &Path,
    executable: &Path,
    contents: &str,
) -> Result<ServiceUnitIdentity> {
    let executable_metadata = fs::symlink_metadata(executable)
        .with_context(|| format!("inspecting service executable {}", executable.display()))?;
    if !executable_metadata.file_type().is_file() {
        bail!(
            "configured ouro executable {} is not a regular file",
            executable.display()
        );
    }
    let marker = service_marker(profile);
    let (marker, exec, data) = match kind {
        ServiceKind::Launchd => (
            format!("<!-- {marker} -->"),
            format!(
                "<array><string>{}</string><string>service-run</string></array>",
                xml_escape(path_text(executable)?)
            ),
            format!(
                "<key>OUROBOROS_DATA_DIR</key><string>{}</string>",
                xml_escape(path_text(data_dir)?)
            ),
        ),
        ServiceKind::SystemdUser => (
            format!("# {marker}"),
            format!(
                "ExecStart={} service-run",
                systemd_quote(path_text(executable)?)?
            ),
            format!(
                "Environment={}",
                systemd_quote(&format!("OUROBOROS_DATA_DIR={}", path_text(data_dir)?))?
            ),
        ),
    };
    for (label, expected) in [
        ("generated marker", marker),
        ("foreground service-run executable", exec),
        ("exact OUROBOROS_DATA_DIR", data),
    ] {
        if contents.match_indices(&expected).count() != 1 {
            bail!("recovery unit does not contain exactly one expected {label}");
        }
    }
    let recovery_policy: &[&str] = match kind {
        ServiceKind::Launchd => &[
            "<key>RunAtLoad</key><true/>",
            "<key>KeepAlive</key><true/>",
            "<key>ThrottleInterval</key><integer>3</integer>",
        ],
        ServiceKind::SystemdUser => &[
            "Type=simple",
            "Restart=always",
            "RestartSec=3",
            "WantedBy=default.target",
        ],
    };
    for expected in recovery_policy {
        if contents.match_indices(expected).count() != 1 {
            bail!("recovery unit is missing or duplicates policy `{expected}`");
        }
    }
    if contents.match_indices("service-run").count() != 1 {
        bail!("recovery unit has an ambiguous service-run command");
    }
    let provider_path = required_service_environment(kind, contents, "PATH")?;
    validate_installed_service_path(&provider_path)?;
    let workspace_roots =
        required_service_environment(kind, contents, "OUROBOROS_WORKSPACE_ROOTS")?;
    validate_installed_workspace_roots(&workspace_roots)?;
    let gateway_max_frame =
        required_service_limit(kind, contents, "OUROBOROS_GATEWAY_MAX_FRAME", 1_024)?;
    let gateway_queue_limit =
        required_service_limit(kind, contents, "OUROBOROS_GATEWAY_QUEUE_LIMIT", 1)?;
    let authority_marker =
        service_authority_marker(&workspace_roots, gateway_max_frame, gateway_queue_limit);
    if contents.match_indices(&authority_marker).count() != 1 {
        bail!(
            "recovery unit authority policy digest does not match its admitted workspace roots and gateway limits"
        );
    }
    Ok(ServiceUnitIdentity {
        provider_path,
        workspace_roots,
        gateway_max_frame,
        gateway_queue_limit,
    })
}

pub(super) fn required_service_limit(
    kind: ServiceKind,
    contents: &str,
    variable: &str,
    minimum: u64,
) -> Result<u64> {
    let value = required_service_environment(kind, contents, variable)?;
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("recovery unit {variable} is not a base-10 integer"))?;
    if parsed < minimum {
        bail!("recovery unit {variable} must be at least {minimum}, got {parsed}");
    }
    Ok(parsed)
}

pub(super) fn validate_installed_service_path(value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("recovery unit PATH is empty or contains a control character");
    }
    let entries = std::env::split_paths(value).collect::<Vec<_>>();
    if entries.is_empty() || entries.iter().any(|entry| !entry.is_absolute()) {
        bail!("recovery unit PATH must contain only absolute directories");
    }
    Ok(())
}

pub(super) fn validate_installed_workspace_roots(value: &str) -> Result<()> {
    if value.chars().any(char::is_control) {
        bail!("recovery unit OUROBOROS_WORKSPACE_ROOTS contains a control character");
    }
    if value.is_empty() {
        return Ok(());
    }
    let entries = std::env::split_paths(value).collect::<Vec<_>>();
    if entries.is_empty() || entries.iter().any(|entry| !entry.is_absolute()) {
        bail!("recovery unit OUROBOROS_WORKSPACE_ROOTS must contain only absolute directories");
    }
    for entry in entries {
        path_text(&entry).context("validating a recovery-unit workspace root")?;
    }
    Ok(())
}

pub(super) fn service_marker(profile: &Profile) -> String {
    format!(
        "Generated by ouro fleet for {} ({})",
        profile.machine, profile.fleet_id
    )
}

pub(super) fn service_authority_marker(
    workspace_roots: &str,
    gateway_max_frame: u64,
    gateway_queue_limit: u64,
) -> String {
    let policy = format!(
        "OUROBOROS_WORKSPACE_ROOTS={workspace_roots}\nOUROBOROS_GATEWAY_MAX_FRAME={gateway_max_frame}\nOUROBOROS_GATEWAY_QUEUE_LIMIT={gateway_queue_limit}"
    );
    let digest = ring::digest::digest(&ring::digest::SHA256, policy.as_bytes());
    let hex = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("Ouroboros recovery authority sha256 {hex}")
}

pub(super) fn service_activation(kind: ServiceKind, profile: &Profile, path: &Path) -> String {
    match kind {
        ServiceKind::Launchd => format!(
            "launchctl bootstrap gui/{} {}",
            unsafe { libc::geteuid() },
            shell_quote(&path.display().to_string())
        ),
        ServiceKind::SystemdUser => format!(
            "systemctl --user daemon-reload && systemctl --user enable --now ouroboros-{}.service",
            profile.machine
        ),
    }
}

pub(super) fn service_deactivation(kind: ServiceKind, profile: &Profile, path: &Path) -> String {
    match kind {
        ServiceKind::Launchd => format!(
            "launchctl bootout gui/{} {}",
            unsafe { libc::geteuid() },
            shell_quote(&path.display().to_string())
        ),
        ServiceKind::SystemdUser => format!(
            "systemctl --user disable --now ouroboros-{}.service",
            profile.machine
        ),
    }
}

pub(super) fn path_text(path: &Path) -> Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow!("service path is not valid UTF-8: {}", path.display()))?;
    if text.chars().any(|character| character.is_control()) {
        bail!(
            "service path contains a control character: {}",
            path.display()
        );
    }
    Ok(text)
}

pub(super) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(super) fn xml_unescape(value: &str) -> String {
    value
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
}

pub(super) fn systemd_quote(value: &str) -> Result<String> {
    if value.chars().any(|character| character.is_control()) {
        bail!("systemd value contains a control character");
    }
    if value.contains('%') || value.contains('$') {
        bail!(
            "systemd service value `{value}` contains `%` or `$`, which systemd may expand even without a shell. Move Ouroboros/provider paths to names without those characters, then reinstall"
        );
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Quotes one filesystem path for the copy/paste shell commands printed by the CLI.
pub fn shell_quote_path(path: &Path) -> Result<String> {
    Ok(shell_quote(path_text(path)?))
}

/// A service manager saying "loaded" or "active" is not enough to promise recovery:
/// launchd/systemd can keep an unhealthy foreground command in a restart loop. Require a
/// live Ouroboros publication or durable runtime owner before the doctor calls recovery
/// active, and turn manager/runtime disagreement into an actionable failure.
pub(super) fn service_recovery_check(
    kind: ServiceKind,
    profile: &Profile,
    path: &Path,
    data_dir: &Path,
    manager: &ServiceManagerState,
    runtime_running: bool,
) -> (RecoveryReadiness, Check) {
    match manager.active {
        ServiceFact::Yes if runtime_running => (
            RecoveryReadiness::Active,
            ok(format!(
                "recovery unit is active in the {} and owns a live Ouroboros runtime",
                kind.label()
            )),
        ),
        ServiceFact::Yes => (
            RecoveryReadiness::Unknown,
            problem(format!(
                "the {} reports the recovery unit active, but no live Ouroboros runtime publication or owner exists. Inspect {} for live application history, {} for bootstrap/VM/crash output, and `ouro fleet service status`, then deactivate/re-activate with `{}`; do not rely on crash recovery until the runtime is live",
                kind.label(),
                data_dir.join(runtime::RUNTIME_LOG_FILE).display(),
                data_dir.join(runtime::DAEMON_LOG_FILE).display(),
                service_activation(kind, profile, path)
            )),
        ),
        ServiceFact::No => (
            RecoveryReadiness::Inactive,
            warn(format!(
                "recovery unit is installed at {} but inactive; activate it with `{}` before relying on crash recovery",
                path.display(),
                service_activation(kind, profile, path)
            )),
        ),
        ServiceFact::Unknown => (
            RecoveryReadiness::Unknown,
            warn(format!(
                "recovery unit is installed at {}, but the {} could not prove whether it is active{}",
                path.display(),
                kind.label(),
                manager
                    .note
                    .as_deref()
                    .map(|note| format!(" ({note})"))
                    .unwrap_or_default()
            )),
        ),
    }
}
