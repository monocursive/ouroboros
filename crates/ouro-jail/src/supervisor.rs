//! The portable supervisor: resolution, probing, the gate and the lifecycle.
//!
//! Implements jail-v1 §8.1 (preparation steps and the state machine), §8.2
//! (managed gate and control output) and the refusal tuples of §13.2 over the
//! [`Platform`](crate::platform::Platform) seam. It contains no Linux code: the
//! Linux slice supplies a platform and this file keeps owning every lifecycle
//! transition, every receipt and every budget.
//!
//! I01 is the shape of this module: nothing reaches `release` until
//! resolution, state, probing, preparation and the gate have all succeeded.
//! A failure up to the claim returns its error and writes no receipt. The
//! claim is one exclusive link, so such a failure leaves no claim, or at
//! most one whose directory sync failed after the link landed: a claim with
//! no receipt, which `gc` reconciles as one. From the claim on, the claimed
//! [`attempt::Attempt`] returns a report, never an error: every exit before
//! the target runs goes through its `refuse` (after tearing the boundary
//! down, once one exists), which writes the `refused` receipt or reports
//! that it could not, and an attempt whose target ran ends in its
//! settlement.

use std::ffi::OsString;
use std::io::Write as _;
use std::os::fd::{FromRawFd as _, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::capability::Capability;
use crate::cleanup;
use crate::cli::{DoctorArgs, ExplainArgs, PolicyArgs, RunArgs};
use crate::config::{self, EnvSettings};
use crate::launch_profile;
use crate::lifecycle::{Integrity, TreeEnd};
use crate::network::NetworkMode;
use crate::observer::CoverageClass;
use crate::platform::{
    BoundaryIdentity, ContinuousDeadline, PlanRequest, Platform, StopReason, Teardown,
};
use crate::policy::{
    self, Layer, LayerOrigin, PolicyDelta, ProfileName, ResolveInputs, Resolved, ScratchRoot,
};
use crate::profiles;
use crate::records::StateCleanup;
use crate::records::{
    Applied, AppliedLimit, AppliedNetwork, AttemptRecord, Containment, ControlKind, ControlMessage,
    ErrorCode, ErrorStage, GateExpectation, JailError, Lifetime, Phase, PlatformRecord, Receipt,
    Remediation, SCHEMA_POLICY_FILE, rfc3339_utc,
};
use crate::state::{self, AttemptDir, AttemptId};
use crate::trace::{self, FdSink, FileSink, Priority, SharedTrace, TraceSink};

mod amend;
mod attempt;

use attempt::Attempt;

/// External gate wait after `prepared` (§8.2).
pub const GATE_WAIT: Duration = Duration::from_secs(60);
/// Preparation budget (§8.2).
pub const PREPARE_BUDGET: Duration = Duration::from_secs(30);
/// Forced-stop verification budget (§9.3).
pub const TREE_BUDGET: Duration = Duration::from_secs(5);
/// Maximum size of the workspace-root `ouro.toml` (§7, H3).
///
/// The file is written by the contained party, so it has a bound. A policy
/// file that needs more than this is not a policy file.
pub const PROJECT_FILE_MAX: u64 = 256 * 1024;
/// Maximum size of the operator's `config.toml` (audit 4 B1).
///
/// A trusted layer is read with a bound like any other: a grown or planted
/// file must refuse, never wedges the supervisor in memory.
pub const OPERATOR_FILE_MAX: u64 = 256 * 1024;

/// Everything the supervisor needs from its process environment.
pub struct Context {
    /// The platform this build targets.
    pub platform: Box<dyn Platform>,
    /// The allowed environment settings (§6.2 step 3).
    pub env_settings: EnvSettings,
    /// The invocation directory, which CLI paths resolve against.
    pub cwd: PathBuf,
    /// The operator home, used to expand a leading `~/` in operator files.
    pub home: Option<PathBuf>,
    /// Reads the supervisor environment for the profile's admitted names.
    pub env_lookup: Box<crate::profiles::EnvLookup>,
}

/// What `run` established, for the caller that turns it into an exit status.
#[derive(Default)]
pub struct RunReport {
    /// The process exit status (§6.4).
    pub exit_code: i32,
    /// The last receipt this attempt persisted, when one exists.
    pub receipt: Option<Receipt>,
    /// The refusal or failure, when there was one.
    pub error: Option<JailError>,
    /// Where the canonical receipt lives.
    pub receipt_path: Option<PathBuf>,
    /// The proposed execution label, for `--label-only`.
    pub label: Option<String>,
    /// The capabilities probed, for `--label-only`.
    pub capabilities: Vec<Capability>,
    /// Evidence loss on the trace stream, reported separately from the
    /// attempt's own outcome (I05: these are separate facts).
    pub trace_error: Option<JailError>,
    /// Control messages the consumer never took. Reported, never waited on.
    pub control_dropped: u64,
    /// J4 W3, P5: errors this attempt raised that no durable receipt carries
    /// and that `error` and `trace_error` do not name (a terminal receipt
    /// that failed to persist, and whatever it would have recorded), in the
    /// order they were raised. The caller prints each one on stderr: an
    /// error that cannot reach the receipt still reaches the operator.
    pub unrecorded: Vec<crate::records::ErrorObject>,
}

/// What `explain` established, without probing anything.
pub struct ExplainReport {
    /// The resolved policy.
    pub resolved: Resolved,
    /// The platform identity.
    pub platform: PlatformRecord,
}

/// What `doctor` measured.
pub struct DoctorReport {
    /// The requested plan.
    pub requirements: Vec<String>,
    /// The measured capabilities.
    pub capabilities: Vec<Capability>,
    /// The platform identity.
    pub platform: PlatformRecord,
    /// Whether every requirement is satisfied.
    pub ready: bool,
    // `doctor --launch` (§14.1)
    /// The launch profile's own readiness, when `--launch` was given.
    pub launch: Option<LaunchReadiness>,
}

// `doctor --launch` (§14.1)
/// What `doctor --launch NAME` established about a launch profile.
///
/// §14.1: "Launch profile credential existence/type/permissions without
/// printing values or user-specific paths; experimental/supported status
/// separately." Each credential is named by the profile's own id, mode and
/// destination; the support status is reported apart from the host probes.
pub struct LaunchReadiness {
    /// `bundled` or `operator file`, the profile's `LaunchSource` spelling
    /// (the doctor schema's enum).
    pub resolution: String,
    /// The launch profile name.
    pub name: String,
    /// `experimental` or `supported`.
    pub support: &'static str,
    /// Why the profile has that status.
    pub support_reason: &'static str,
    /// One check per declared credential, in id order.
    pub credentials: Vec<crate::credentials::CredentialCheck>,
}

/// Every launch profile is `experimental` until a real run of that agent is
/// recorded (§12, A01). This build records none and keeps no registry of
/// supported profiles, so it never claims `supported`.
pub const LAUNCH_SUPPORT: &str = "experimental";
/// Why [`LAUNCH_SUPPORT`] is what it is.
pub const LAUNCH_SUPPORT_REASON: &str = "no_recorded_run";

// ---------------------------------------------------------------------------
// Resolution shared by run, explain, doctor and label-only
// ---------------------------------------------------------------------------

/// The resolved policy plus the context needed to prepare it.
pub struct Plan {
    /// The resolved policy, digest, provenance and requirements.
    pub resolved: Resolved,
    /// The absolute workspace.
    pub workspace: PathBuf,
    /// The configuration directory in use.
    pub config_dir: PathBuf,
    /// The state directory in use.
    pub data_dir: PathBuf,
}

impl Plan {
    /// The base built-in profile, as the snapshot records it.
    #[must_use]
    pub fn profile(&self) -> ProfileName {
        self.resolved.snapshot.profile
    }
}

fn usage(key: &str, message: impl Into<String>) -> JailError {
    JailError::new(
        ErrorCode::InvalidConfig,
        ErrorStage::Resolving,
        Remediation::Configuration,
        message.into(),
    )
    .with_key_path(key)
}

fn os_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

/// Resolves the §6.2 layers into an immutable snapshot.
///
/// The order is the specification's: built-in profile and operator config or
/// selected operator profile, then the environment allow-list, then explicit
/// CLI grants and limits, then the workspace-root `ouro.toml`, which may only
/// narrow. A launch profile (`--launch NAME`) is the §6.2 step-2 layer.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for a usage or syntax problem and
/// [`ErrorCode::PolicyWidening`] with the exact key path for a narrowing file
/// that adds authority.
pub fn resolve_plan(ctx: &Context, args: &PolicyArgs) -> Result<Plan, JailError> {
    resolve(ctx, args, false)
}

/// [`resolve_plan`] for `learn`: the same policy, with the observer also
/// capturing read-only opens for the proposal. It needs a contained Linux
/// run with observation on.
///
/// # Errors
/// As [`resolve_plan`], and [`ErrorCode::InvalidConfig`] at key `learn`
/// where learning cannot run.
pub fn resolve_learning_plan(ctx: &Context, args: &PolicyArgs) -> Result<Plan, JailError> {
    resolve(ctx, args, true)
}

fn resolve(ctx: &Context, args: &PolicyArgs, learning: bool) -> Result<Plan, JailError> {
    let config_dir = state::config_dir(&ctx.env_settings, ctx.home.as_deref())?;
    let data_dir = state::data_dir(&ctx.env_settings, ctx.home.as_deref())?;
    // Audit 6 F1: a `--profile none` child sees the whole host, so every
    // trusted file that predates the end of the last uncontained run could
    // have been written by that child, and none can be dated while such a run
    // is live. The markers sit in both directories, which are chosen
    // independently: a run sharing either sees them.
    let epoch = state::uncontained_epoch(&[&data_dir, &config_dir])?;
    let launch = read_launch_profile(ctx, args, &config_dir, &epoch)?;
    let workspace = canonical_root(&ctx.cwd, args.selection.workspace.as_deref(), "--workspace")?;
    if !workspace.is_dir() {
        return Err(usage(
            "--workspace",
            format!("{} is not a directory", workspace.display()),
        ));
    }

    // 1. Operator config, then the selected profile.
    let operator = read_operator_config(&config_dir, &epoch)?;
    let operator_jail = operator.jail.clone().unwrap_or_default();
    let selection = select_profile(args, &operator_jail, launch.as_ref())?;
    let base = select_base(ctx, args, &config_dir, &epoch, selection)?;
    let profile = base.profile;
    if let Some(launch) = &launch {
        check_launch_base(args, &operator_jail, profile, launch)?;
    }
    let mut layers: Vec<Layer> = base.layer.into_iter().collect();
    // The operator's own `[jail]` table is a trusted layer: it may grant.
    if operator.jail.is_some() {
        layers.push(operator_layer(&operator_jail, &config_dir)?);
    }
    // 2. The launch profile's allowed hosts, an operator grant, before the
    // environment, CLI and project layers.
    layers.extend(launch.as_ref().and_then(launch_profile::network_layer));
    // 3. The environment allow-list.
    layers.extend(environment_layer(&ctx.env_settings));
    // 4. Explicit CLI grants and limits.
    layers.extend(command_line_layer(ctx, args)?);
    // 5. The workspace-root `ouro.toml`, which may only narrow.
    layers.extend(project_layer(&workspace)?);

    let scratch = scratch_root(ctx, args)?;
    let translation_prefixes = translation_prefixes(operator.jail_host)?;
    let platform_os = ctx.platform.identity().os;
    let inputs = ResolveInputs {
        platform: platform_os,
        base_profile: profile,
        policy_name: base.policy_name,
        baseline: profiles::baseline(profile, platform_os, ctx.env_lookup.as_ref()),
        workspace: os_bytes(&workspace),
        scratch,
        vendor_state: None,
        operator_home: ctx.home.as_deref().map(os_bytes),
        translation_prefixes,
        layers,
    };
    let mut resolved = policy::resolve(&inputs)?;
    // The launch environment, vendor state and `launch` field group, then
    // the digest and requirements over the result.
    if let Some(launch) = &launch {
        resolved = launch_profile::apply(resolved, launch)?;
    }
    if !operator_jail.commands.is_empty() {
        apply_command_rules(&mut resolved, &operator_jail.commands, profile)?;
    }
    if learning {
        enable_learning(&mut resolved, profile)?;
    }
    // §6.4: `build` requires an explicit memory ceiling; the baseline leaves it
    // absent so that this refuses rather than inventing one.
    if profile == ProfileName::Build && resolved.snapshot.limits.mem.is_none() {
        return Err(usage(
            "limits.mem",
            "the `build` profile requires an explicit memory ceiling",
        ));
    }
    if let Some(launch) = &launch {
        check_launch_placement(&resolved, &workspace, launch)?;
    }

    Ok(Plan {
        resolved,
        workspace,
        config_dir,
        data_dir,
    })
}

/// §6.2 step 2: the operator launch profile `--launch NAME`, read once
/// through a no-follow walk; its content is what the snapshot records.
///
/// # Errors
/// The launch profile's refusal, or [`ErrorCode::UnsafeConfigPath`] for one
/// an uncontained run's child could have written.
fn read_launch_profile(
    ctx: &Context,
    args: &PolicyArgs,
    config_dir: &Path,
    epoch: &state::UncontainedEpoch,
) -> Result<Option<launch_profile::LaunchProfile>, JailError> {
    let Some(name) = &args.selection.launch else {
        return Ok(None);
    };
    refuse_stale_trusted_file(
        &launch_profile::launch_directory(config_dir).join(format!("{name}.toml")),
        epoch,
        "--launch",
    )?;
    launch_profile::load(config_dir, name, ctx.home.as_deref()).map(Some)
}

/// The operator's `config.toml`, or the empty configuration when there is
/// none.
///
/// # Errors
/// The read's and the parser's refusals.
fn read_operator_config(
    config_dir: &Path,
    epoch: &state::UncontainedEpoch,
) -> Result<config::OperatorConfig, JailError> {
    let config_path = config_dir.join("config.toml");
    refuse_stale_trusted_file(&config_path, epoch, "config")?;
    match read_operator_file(&config_path, "config")? {
        Some(text) => config::parse_operator_config(&text),
        None => Ok(config::OperatorConfig::default()),
    }
}

/// The profile selection, by precedence: `--profile`, then the operator's
/// configured profile, then the launch profile's default, then `tool` (§6.1:
/// "Default profile: `tool`, or the launch profile's `jail` when `--launch`
/// is set").
///
/// # Errors
/// [`ErrorCode::PolicyWidening`] at `jail.profile` for a `config.toml` that
/// selects `none`.
fn select_profile(
    args: &PolicyArgs,
    operator_jail: &config::JailSection,
    launch: Option<&launch_profile::LaunchProfile>,
) -> Result<String, JailError> {
    Ok(
        match (
            args.selection.profile.as_deref(),
            operator_jail.profile.as_deref(),
        ) {
            (Some(cli), _) => cli.to_owned(),
            // §6.1: `--profile none` is the only way to select `none`; files
            // and environment cannot select it. `config.toml` is a defaults
            // file, so a `none` written there would drop the operator onto the
            // uncontained profile without the explicit act the clause
            // demands, and it refuses instead, as a profile file's
            // `extends = "none"` does.
            (None, Some("none")) => {
                return Err(JailError::new(
                    ErrorCode::PolicyWidening,
                    ErrorStage::Resolving,
                    Remediation::Configuration,
                    "config.toml may not select the `none` profile; pass `--profile none` \
                     explicitly"
                        .to_owned(),
                )
                .with_key_path("jail.profile"));
            }
            (None, Some(configured)) => configured.to_owned(),
            // A configured profile that disagrees with the launch default
            // refuses in `check_launch_base` instead of being replaced.
            (None, None) => launch.map_or_else(
                || "tool".to_owned(),
                |launch| launch.jail.as_str().to_owned(),
            ),
        },
    )
}

/// The base profile a selection names, its display name, and the operator
/// profile file's layer when the selection names a file.
struct Base {
    profile: ProfileName,
    policy_name: String,
    layer: Option<Layer>,
}

/// Resolves a selection to its base profile: a built-in name, or an
/// operator profile file that extends one (§6.2).
///
/// # Errors
/// The profile file's refusals, [`ErrorCode::InvalidConfig`] for a base that
/// is not built in, and [`ErrorCode::PolicyWidening`] at `extends` for a file
/// that extends `none`.
fn select_base(
    ctx: &Context,
    args: &PolicyArgs,
    config_dir: &Path,
    epoch: &state::UncontainedEpoch,
    selection: String,
) -> Result<Base, JailError> {
    if let Some(profile) = ProfileName::parse(&selection) {
        return Ok(Base {
            profile,
            policy_name: selection,
            layer: None,
        });
    }
    let path = if args.selection.profile.is_some() {
        absolutize(&ctx.cwd, Path::new(&selection))
    } else if let Some(suffix) = selection.strip_prefix("~/") {
        let home = ctx
            .home
            .as_ref()
            .ok_or_else(|| usage("jail.profile", "operator home is unavailable"))?;
        config::absolute_dir(config::HOME_VAR, home)?.join(suffix)
    } else {
        absolutize(config_dir, Path::new(&selection))
    };
    refuse_stale_trusted_file(&path, epoch, "--profile")?;
    let text = read_operator_file(&path, "--profile")?
        .ok_or_else(|| usage("--profile", format!("{} does not exist", path.display())))?;
    let file = config::parse_policy_file(&text)?;
    let profile = ProfileName::parse(&file.extends).ok_or_else(|| {
        usage(
            "extends",
            format!("`{}` is not a built-in profile", file.extends),
        )
    })?;
    if profile == ProfileName::None {
        // §6.1: `--profile none` is the only way to select `none`.
        return Err(JailError::new(
            ErrorCode::PolicyWidening,
            ErrorStage::Resolving,
            Remediation::Configuration,
            "a profile file may not extend `none`".to_owned(),
        )
        .with_key_path("extends"));
    }
    let delta = config::delta_from_sections(
        "",
        &file.filesystem,
        &file.network,
        &file.limits,
        &file.observation,
    )?;
    let name = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "profile".to_owned());
    Ok(Base {
        profile,
        policy_name: name.clone(),
        layer: Some(Layer {
            origin: LayerOrigin::OperatorProfileFile(name),
            base_dir: path.parent().map(os_bytes),
            delta,
        }),
    })
}

/// §6.1: the selected base must permit the launch profile's credentials and
/// network, and `none` never runs one. A configured profile is never
/// silently replaced by a launch default, and never silently replaces one
/// either: when they name different bases the operator chooses with
/// `--profile`.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] at `jail.profile` for that disagreement, and
/// the launch profile's own refusal of the base.
fn check_launch_base(
    args: &PolicyArgs,
    operator_jail: &config::JailSection,
    profile: ProfileName,
    launch: &launch_profile::LaunchProfile,
) -> Result<(), JailError> {
    if args.selection.profile.is_none()
        && let Some(configured) = operator_jail.profile.as_deref()
        && launch.jail != profile
    {
        return Err(usage(
            "jail.profile",
            format!(
                "config.toml selects `{configured}` (base `{}`), but launch profile `{}` \
                 defaults to `{}`; pass `--profile` to choose one",
                profile.as_str(),
                launch.name,
                launch.jail.as_str()
            ),
        ));
    }
    launch_profile::check_jail_permits(profile, launch)
}

/// The operator's own `[jail]` table, a trusted layer that may grant.
///
/// # Errors
/// The table's own refusals.
fn operator_layer(
    operator_jail: &config::JailSection,
    config_dir: &Path,
) -> Result<Layer, JailError> {
    let delta = config::delta_from_sections(
        "jail.",
        &operator_jail.filesystem,
        &operator_jail.network,
        &operator_jail.limits,
        &operator_jail.observation,
    )?;
    Ok(Layer {
        origin: LayerOrigin::OperatorConfig("config.toml".to_owned()),
        // §6.2: apply paths relative to the file containing them, and
        // `config.toml` sits in `config_dir` itself, not its parent.
        base_dir: Some(os_bytes(config_dir)),
        delta,
    })
}

/// The environment allow-list's layer, when it sets anything (§6.2 step 3).
fn environment_layer(settings: &EnvSettings) -> Option<Layer> {
    (settings.observe.is_some() || settings.evidence.is_some()).then(|| Layer {
        origin: LayerOrigin::Environment,
        base_dir: None,
        delta: PolicyDelta {
            observe: settings.observe,
            evidence: settings.evidence,
            ..PolicyDelta::default()
        },
    })
}

/// The explicit CLI grants and limits' layer, when there are any (§6.2
/// step 4).
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] for a `--limit` that does not parse.
fn command_line_layer(ctx: &Context, args: &PolicyArgs) -> Result<Option<Layer>, JailError> {
    let delta = PolicyDelta {
        read_write: args.rw.iter().map(|path| os_bytes(path)).collect(),
        read_only: args.ro.iter().map(|path| os_bytes(path)).collect(),
        deny_read: args.deny_read.iter().map(|path| os_bytes(path)).collect(),
        network_allow: args.allow_host.clone(),
        limits: config::ceilings_from_cli(&args.limit)?,
        observe: args.observe.map(Into::into),
        evidence: args.evidence.map(Into::into),
        ..PolicyDelta::default()
    };
    let any = !delta.read_write.is_empty()
        || !delta.read_only.is_empty()
        || !delta.deny_read.is_empty()
        || !delta.network_allow.is_empty()
        || delta.limits != policy::Ceilings::default()
        || delta.observe.is_some()
        || delta.evidence.is_some();
    Ok(any.then(|| Layer {
        origin: LayerOrigin::CommandLine,
        base_dir: Some(os_bytes(&ctx.cwd)),
        delta,
    }))
}

/// The workspace-root `ouro.toml`'s layer, which may only narrow (§6.2
/// step 5), when the file has a `[jail]` table.
///
/// # Errors
/// The read's and the parser's refusals, and [`ErrorCode::PolicyWidening`]
/// for a key of the operator's launch layer (§6.3: "Add credentials ...
/// Refuse"), refused with its exact key path, not as a typo.
fn project_layer(workspace: &Path) -> Result<Option<Layer>, JailError> {
    let Some(text) = read_project_file(&workspace.join("ouro.toml"))? else {
        return Ok(None);
    };
    if let Some(key) = launch_layer_key_in_project(&text) {
        return Err(JailError::new(
            ErrorCode::PolicyWidening,
            ErrorStage::Resolving,
            Remediation::Configuration,
            format!(
                "`{key}` is staged only from an operator launch profile (§12); a project \
                 file may only narrow"
            ),
        )
        .with_key_path(key));
    }
    let Some(section) = config::parse_project_config(&text)?.jail else {
        return Ok(None);
    };
    config::check_schema("jail.schema", section.schema.as_deref())?;
    let delta = config::delta_from_sections(
        "jail.",
        &section.filesystem,
        &section.network,
        &section.limits,
        &section.observation,
    )?;
    Ok(Some(Layer {
        origin: LayerOrigin::ProjectConfig("ouro.toml".to_owned()),
        base_dir: Some(os_bytes(workspace)),
        delta,
    }))
}

/// The scratch root: `--scratch`, canonical, or the managed one.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] at `--scratch` for a path that cannot be
/// resolved or recorded.
fn scratch_root(ctx: &Context, args: &PolicyArgs) -> Result<ScratchRoot, JailError> {
    let Some(path) = &args.selection.scratch else {
        return Ok(ScratchRoot::Managed);
    };
    let path = canonical_root(&ctx.cwd, Some(path), "--scratch")?;
    Ok(ScratchRoot::Host {
        path: crate::records::NativeString::from_bytes(os_bytes(&path))
            .map_err(|error| usage("--scratch", error.to_string()))?,
    })
}

/// §6.2: `[jail_host.network] translation_prefixes` is host configuration,
/// merged into proxy policy before digest creation. Each entry is parsed and
/// re-rendered in canonical RFC 5952 form so equivalent spellings of one
/// prefix cannot yield two digests (§6.3).
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] for an entry that is not a prefix.
fn translation_prefixes(host: Option<config::JailHostSection>) -> Result<Vec<String>, JailError> {
    match host
        .and_then(|host| host.network)
        .map(|network| network.translation_prefixes)
    {
        Some(entries) => config::canonical_translation_prefixes(
            "jail_host.network.translation_prefixes",
            &entries,
        ),
        None => Ok(Vec::new()),
    }
}

/// jail-v2 §7.2: the operator's command rules, validated here so a refusal
/// names its key; the Linux platform compiles the same rules for the
/// observer.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] at `jail.commands` for a rule that does not
/// compile, or a run that cannot match it (only a contained Linux run with
/// observation on sees each exec).
fn apply_command_rules(
    resolved: &mut Resolved,
    rules: &crate::commands::Rules,
    profile: ProfileName,
) -> Result<(), JailError> {
    rules.compile().map_err(|e| usage("jail.commands", e))?;
    if resolved.snapshot.platform != crate::records::Os::Linux
        || profile == ProfileName::None
        || resolved.snapshot.observation.mode != crate::records::ObserveMode::On
    {
        return Err(usage(
            "jail.commands",
            "command rules require contained Linux execution with --observe on",
        ));
    }
    let rules = rules.clone();
    resolved.amend(
        vec![policy::ProvenanceEntry {
            origin: LayerOrigin::OperatorConfig("config.toml".to_owned()).label(),
            key: "jail.commands".to_owned(),
            detail: None,
        }],
        |snapshot| {
            snapshot.commands = rules;
            Ok(())
        },
    )
}

/// `learn`: the observer also captures read-only opens for the proposal.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] at `learn` where learning cannot run: it
/// needs a contained Linux run with the real observer on.
fn enable_learning(resolved: &mut Resolved, profile: ProfileName) -> Result<(), JailError> {
    if profile == ProfileName::None || resolved.snapshot.platform != crate::records::Os::Linux {
        return Err(usage(
            "learn",
            "learning requires a contained Linux run with the real observer",
        ));
    }
    if resolved.snapshot.observation.mode != crate::records::ObserveMode::On {
        return Err(usage("learn", "learning requires observation on"));
    }
    resolved.amend(
        vec![policy::ProvenanceEntry {
            origin: LayerOrigin::CommandLine.label(),
            key: "observation.learning".to_owned(),
            detail: Some("learn".to_owned()),
        }],
        |snapshot| {
            snapshot.observation.learning = true;
            Ok(())
        },
    )
}

/// §12 "A launch profile path inside any child-writable grant refuses", and
/// north star §4.5 refuses one inside the workspace; the same rule holds for
/// every credential source, by identity: the child must not be able to
/// change what it is given. A source that cannot be walked now is left to
/// staging and doctor, which report it by reason.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] for a launch profile or a credential source
/// inside a grant the child can write.
fn check_launch_placement(
    resolved: &Resolved,
    workspace: &Path,
    launch: &launch_profile::LaunchProfile,
) -> Result<(), JailError> {
    launch_profile::check_outside_writable(launch, &child_writable_roots(resolved, workspace))?;
    let forbidden = forbidden_identities(resolved, workspace)?;
    for credential in &launch.credentials {
        if let Ok(chain) = crate::credentials::source_chain(credential.source.as_bytes())
            && chain.iter().any(|identity| forbidden.contains(identity))
        {
            return Err(usage(
                &format!("launch.credentials.{}.source", credential.id),
                format!(
                    "credential `{}` lies inside a grant the child can write",
                    credential.id
                ),
            ));
        }
    }
    Ok(())
}

/// Every root the child can write under the resolved policy: the workspace,
/// an explicit scratch and every writable grant. A launch profile, a
/// credential source and an executable may lie beneath none of them.
fn child_writable_roots(resolved: &Resolved, workspace: &Path) -> Vec<PathBuf> {
    let snapshot = &resolved.snapshot;
    let scratch = match &snapshot.roots.scratch {
        ScratchRoot::Host { path } => {
            Some(PathBuf::from(OsString::from_vec(path.as_bytes().to_vec())))
        }
        ScratchRoot::Managed => None,
    };
    let mut roots = vec![workspace.to_path_buf()];
    roots.extend(scratch.clone());
    for reference in &snapshot.filesystem.read_write {
        let suffix = std::ffi::OsStr::from_bytes(reference.path.as_bytes());
        let base = match reference.root {
            crate::policy::RootToken::Host => Some(PathBuf::from("/")),
            crate::policy::RootToken::Workspace => Some(workspace.to_path_buf()),
            crate::policy::RootToken::Scratch => scratch.clone(),
            crate::policy::RootToken::VendorState => None,
        };
        if let Some(base) = base {
            roots.push(if suffix.is_empty() {
                base
            } else {
                base.join(suffix)
            });
        }
    }
    roots
}

fn absolutize(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// The one spelling of a trusted operator root (§6.3, M2).
///
/// "Equivalent semantic inputs have the same digest despite different
/// provenance", so the root that enters the snapshot is canonical: dot
/// segments, trailing and repeated slashes and symlinked ancestors are all
/// resolved. Without this, `/tmp/w`, `/tmp/w/`, `/tmp/w/.` and `/private/tmp/w`
/// are four digests for one directory, and an owner comparing a prepared
/// receipt with its plan sees four plans.
///
/// The roots are trusted operator input, which is why following symlinks here
/// is right; the untrusted-layer rule of `policy::untrusted_identities` is a
/// different question and stays separate.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] when the path cannot be resolved and
/// its parent does not exist either.
fn canonical_root(cwd: &Path, path: Option<&Path>, key: &str) -> Result<PathBuf, JailError> {
    let absolute = match path {
        Some(path) => absolutize(cwd, path),
        None => cwd.to_path_buf(),
    };
    match std::fs::canonicalize(&absolute) {
        Ok(resolved) => Ok(resolved),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A `--scratch` that this attempt will create: canonicalize the
            // parent so the stable part of the path is still canonical.
            let parent = absolute
                .parent()
                .ok_or_else(|| usage(key, format!("{} cannot be resolved", absolute.display())))?;
            let name = absolute
                .file_name()
                .ok_or_else(|| usage(key, format!("{} names no directory", absolute.display())))?;
            let parent = std::fs::canonicalize(parent)
                .map_err(|error| usage(key, format!("{}: {error}", parent.display())))?;
            Ok(parent.join(name))
        }
        Err(error) => Err(usage(key, format!("{}: {error}", absolute.display()))),
    }
}

/// Reads an operator-owned configuration file (§6.2): `config.toml` and a
/// `--profile` policy file.
///
/// `Ok(None)` means the file is absent. Every other failure is reported:
/// silently continuing without a file the operator wrote is how a tightening
/// disappears. Security 2026-09-27 (audit 4 B1): such a file is a trusted,
/// widening layer, so it is read like operator authority (§6.2): no-follow,
/// a regular file, bounded ([`state::read_capped_checked`]), and judged on
/// the open descriptor by [`operator_owned`].
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for any failure other than absence.
pub(crate) fn read_operator_file(path: &Path, key: &str) -> Result<Option<String>, JailError> {
    let refused = |what: String| usage(key, format!("{}: {what}", path.display()));
    let Some(bytes) = state::read_capped_checked(path, OPERATOR_FILE_MAX, operator_owned)
        .map_err(|error| refused(error.to_string()))?
    else {
        return Ok(None);
    };
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| refused("is not UTF-8".to_owned()))
}

/// §6.2's identity rule for an operator configuration file, on the open
/// descriptor: the operator's own uid, no group or world write (0644 is the
/// loosest mode; unlike a directory, the private-group exception does not
/// apply), and a single link (a hardlink planted from a writable copy would
/// otherwise carry the operator's uid and mode by construction). A launch
/// profile is held to 0600 by its own reader (operating.md).
fn operator_owned(metadata: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let refused = |what: &str| std::io::Error::new(std::io::ErrorKind::PermissionDenied, what);
    if metadata.uid() != state::effective_uid() {
        return Err(refused("is not owned by this operator"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(refused(
            "is writable by group or others; chmod it 0600 or 0644",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(refused("has more than one hard link"));
    }
    Ok(())
}

/// Security 2026-09-29 (audit 6 F1): refuses a trusted file an uncontained
/// (`--profile none`) run's child could have written.
///
/// An uncontained child shares the operator's uid and the whole filesystem,
/// so it can create `config.toml`, a launch profile or a `--profile FILE`
/// policy with every identity `read_operator_file` checks (operator uid,
/// 0600, one link) — the audit-5 C2 creation variant. The guard that refused
/// `none` while trusted files exist cannot see files that do not exist yet,
/// so the markers close the remaining direction ([`state::UncontainedRun`]):
/// while any uncontained run is live (or ended without settling) no trusted
/// file can be dated and each refuses; once settled, every trusted file must
/// carry a ctime newer than the settled marker's, which the supervisor
/// writes after that run's tree is gone. An operator who just ran `none`
/// re-saves (or removes) their files; a child-planted file cannot re-save
/// itself from inside a contained run, where the config directory is
/// unreachable.
///
/// What this cannot see (jail-v2 §3.2): a child that left something behind
/// that re-saves the file later — a line in a shell rc file, a crontab
/// entry, a `systemd --user` timer — dates it after the marker. The child
/// was the operator for the run's duration; the markers only bound what it
/// wrote directly.
///
/// Absent files are not this guard's business (their absence is reported by
/// the readers); an unreadable ctime on an existing file fails closed.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeConfigPath`] when the file exists while an
/// uncontained run is live, or its ctime does not postdate the settled
/// marker.
fn refuse_stale_trusted_file(
    path: &Path,
    epoch: &state::UncontainedEpoch,
    key: &str,
) -> Result<(), JailError> {
    if epoch.live.is_empty() && epoch.settled.is_none() {
        return Ok(());
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(usage(key, format!("{}: {error}", path.display()))),
    };
    let refused = |message: String| {
        JailError::new(
            ErrorCode::UnsafeConfigPath,
            ErrorStage::Resolving,
            Remediation::Configuration,
            message,
        )
        .with_key_path(key)
    };
    if let Some(live) = epoch.live.first() {
        let settled = live.parent().map_or_else(
            || PathBuf::from("uncontained.epoch"),
            state::uncontained_settled_path,
        );
        return Err(refused(format!(
            "{} cannot be trusted while an uncontained (`--profile none`) run is live or \
             ended without settling ({}); its child could write it. If no such run is \
             active, check the trusted configuration, then `touch {}` and remove {}; \
             each file must then be re-saved to be trusted again",
            path.display(),
            live.display(),
            settled.display(),
            live.display()
        )));
    }
    let changed = state::ctime_of(&metadata)
        .ok_or_else(|| usage(key, format!("{}: ctime is out of range", path.display())))?;
    if epoch.settled.is_some_and(|settled| changed <= settled) {
        return Err(refused(format!(
            "{} predates the last uncontained (`--profile none`) run on this host; \
             an uncontained child could have written it. Re-save it (touch it) or \
             remove it",
            path.display()
        )));
    }
    Ok(())
}

// P02.9
/// The key path of a launch-layer grant (`credentials`) under the project
/// file's `[jail]` table, when there is one. A file that is not TOML is left
/// to the parser, which reports it.
fn launch_layer_key_in_project(text: &str) -> Option<&'static str> {
    let table: toml::Table = toml::from_str(text).ok()?;
    table
        .get("jail")
        .and_then(toml::Value::as_table)
        .is_some_and(|jail| jail.contains_key("credentials"))
        .then_some("jail.credentials")
}

/// Reads the workspace-root `ouro.toml`, which the contained party writes.
///
/// Three properties matter and none of them came free (§2, §7, H2/H3):
///
/// - only absence is "no project file". An unreadable file, a directory, a
///   dangling symlink or an I/O error used to discard the whole narrowing
///   layer and run with the wider policy; now each one refuses.
/// - the read is bounded. A fifo here used to hang the supervisor forever and
///   a symlink to `/dev/zero` used to grow it without limit.
/// - the file must be a regular file opened without following a symlink.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] at key `jail` for every failure other
/// than absence.
fn read_project_file(path: &Path) -> Result<Option<String>, JailError> {
    match state::read_capped(path, PROJECT_FILE_MAX) {
        Ok(None) => Ok(None),
        Ok(Some(bytes)) => match String::from_utf8(bytes) {
            Ok(text) => Ok(Some(text)),
            Err(_) => Err(usage("jail", format!("{} is not UTF-8", path.display()))),
        },
        Err(error) => Err(usage("jail", format!("{}: {error}", path.display()))),
    }
}

// ---------------------------------------------------------------------------
// explain and doctor
// ---------------------------------------------------------------------------

/// Resolves and renders the requested policy without probing or executing.
///
/// # Errors
/// Returns the resolution errors of [`resolve_plan`].
pub fn explain(ctx: &Context, args: &ExplainArgs) -> Result<ExplainReport, JailError> {
    let plan = resolve_plan(ctx, &args.policy)?;
    Ok(ExplainReport {
        resolved: plan.resolved,
        platform: platform_record(ctx),
    })
}

/// Probes the capabilities the requested plan needs (§14.1).
///
/// # Errors
/// Returns the resolution errors of [`resolve_plan`].
pub fn doctor(ctx: &Context, args: &DoctorArgs) -> Result<DoctorReport, JailError> {
    // §6.1's grammar carries the selection flags; the workspace and scratch
    // roots are the same ones `run` accepts, so a doctor call can name the
    // plan it is checking instead of inheriting the invocation directory.
    let plan = resolve_plan(ctx, &args.policy())?;
    let request = plan_request(&plan);
    let capabilities = ctx.platform.probe_all(&request);
    let ready = plan
        .resolved
        .requirements
        .iter()
        .all(|requirement| satisfied(requirement, &capabilities));
    // §14.1 launch readiness; a missing or unsafe source
    // makes the plan unavailable (north star §4.5: it refuses the launch).
    // Only `--launch` has credential sources to place.
    let launch = match &args.selection.launch {
        Some(name) => {
            let forbidden = forbidden_identities(&plan.resolved, &plan.workspace)?;
            Some(LaunchReadiness {
                resolution: plan
                    .resolved
                    .provenance
                    .iter()
                    .find(|p| p.key == "launch.resolution")
                    .and_then(|p| p.detail.clone())
                    .unwrap_or_default(),
                name: name.clone(),
                support: LAUNCH_SUPPORT,
                support_reason: LAUNCH_SUPPORT_REASON,
                credentials: plan
                    .resolved
                    .snapshot
                    .launch
                    .as_ref()
                    .map(|launch| crate::credentials::inspect(launch, &forbidden))
                    .unwrap_or_default(),
            })
        }
        None => None,
    };
    let ready = ready
        && launch
            .as_ref()
            .is_none_or(|launch| launch.credentials.iter().all(|check| check.available));
    Ok(DoctorReport {
        requirements: plan.resolved.requirements,
        capabilities,
        platform: platform_record(ctx),
        ready,
        launch,
    })
}

fn plan_request(plan: &Plan) -> PlanRequest {
    PlanRequest {
        snapshot: plan.resolved.snapshot.clone(),
        requirements: plan.resolved.requirements.clone(),
    }
}

/// Who this binary is running as, for a record's `platform` group.
#[must_use]
pub fn platform_record(ctx: &Context) -> PlatformRecord {
    let identity = ctx.platform.identity();
    PlatformRecord {
        os: identity.os,
        arch: identity.arch,
        kernel: identity.kernel,
    }
}

fn satisfied(requirement: &str, capabilities: &[Capability]) -> bool {
    capabilities
        .iter()
        .any(|capability| capability.name == requirement && capability.satisfies())
}

/// The first requirement no capability satisfies, as a typed refusal.
fn first_unsatisfied(requirements: &[String], capabilities: &[Capability]) -> Option<JailError> {
    let requirement = requirements
        .iter()
        .find(|requirement| !satisfied(requirement, capabilities))?;
    let reason = capabilities
        .iter()
        .find(|capability| &capability.name == requirement)
        .and_then(|capability| capability.reason_code.as_deref())
        .unwrap_or("not_measured");
    let (code, remediation, message) = match reason {
        crate::platform::REASON_UNSUPPORTED_PLATFORM => (
            ErrorCode::UnsupportedPlatform,
            Remediation::Unsupported,
            "execution is not implemented for this platform".to_owned(),
        ),
        // A restriction `none` cannot apply is the policy's to drop.
        crate::capability::REASON_NOT_APPLIED_BY_NONE => (
            ErrorCode::MissingCapability,
            Remediation::Configuration,
            format!(
                "the uncontained profile cannot apply `{requirement}`; a contained profile can"
            ),
        ),
        _ => (
            ErrorCode::MissingCapability,
            Remediation::HostSetup,
            format!("the host does not provide `{requirement}` ({reason})"),
        ),
    };
    Some(JailError::new(
        code,
        ErrorStage::Probing,
        remediation,
        message,
    ))
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

/// Runs one attempt, or refuses before the target executes (§8.1).
///
/// Every path that claims the attempt and does not run its target writes a
/// `refused` receipt with the §13.2 tuple for the stage it failed at; a
/// refusal before the claim (usage, resolution, the state root, the output
/// channels) has no attempt to write one for. The return value carries the
/// exit status; the caller prints diagnostics.
#[must_use]
pub fn run(ctx: &Context, args: &RunArgs) -> RunReport {
    run_with(ctx, args, false)
}

/// [`run`] under [`resolve_learning_plan`]'s policy, for `learn`.
#[must_use]
pub fn run_learning(ctx: &Context, args: &RunArgs) -> RunReport {
    run_with(ctx, args, true)
}

fn run_with(ctx: &Context, args: &RunArgs, learning: bool) -> RunReport {
    match run_inner(ctx, args, learning) {
        Ok(report) => report,
        // Every error of `run_inner` comes before the claim; after it, the
        // attempt builds its own report. So a persistence failure here (the
        // claim itself) refuses with 125.
        Err(error) => RunReport {
            exit_code: error.refusal_exit_code(),
            error: Some(error),
            ..RunReport::default()
        },
    }
}

fn run_inner(ctx: &Context, args: &RunArgs, learning: bool) -> Result<RunReport, JailError> {
    // §13.1: pin the shared monotonic base before anything writes a trace
    // event, so wrapper, audit and gap intervals all count from here.
    crate::platform::mark_supervisor_start();
    let supplied_attempt_id = check_run_usage(args)?;
    // §8.3, H9: the handlers go on before anything exists, so INT/TERM/HUP
    // during resolution, preparation or the 60-second gate wait is a refusal,
    // never the default disposition killing the supervisor with a prepared
    // receipt and a blocked launcher left behind.
    let signals = signals::install();

    let plan = resolve(ctx, &args.policy, learning)?;
    let request = plan_request(&plan);
    let argv: Vec<Vec<u8>> = args
        .argv
        .iter()
        .map(|argument| argument.clone().into_vec())
        .collect();
    let argv_digest = (!argv.is_empty()).then(|| crate::canonical::argv_digest(&argv));

    validate_channels(args)?;
    check_isolation(args, &plan)?;

    if args.label_only {
        return Ok(label_only(ctx, &plan, &request));
    }

    // §8.2: "Initial preparation budget: 30 seconds". It covers steps 1 to 5
    // and is checked at each boundary, so a step that hangs on a child-created
    // object cannot hold the attempt open indefinitely.
    let budget = Budget::new(PREPARE_BUDGET);
    // Step 1: allocate and lock private state before anything else exists.
    let attempt_id = supplied_attempt_id.unwrap_or_else(AttemptId::generate);
    let attempt = Attempt::claim(ctx, args, plan, attempt_id, budget, signals, argv_digest)?;
    // From the claim on, every exit writes a receipt (I01): `run` returns a
    // report, never an error.
    Ok(attempt.run(request, argv))
}

/// The usage rules of §6.1 that clap does not express, and the supplied
/// attempt id, parsed before any path derives from it.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] for a usage error, and the id grammar's
/// refusal.
fn check_run_usage(args: &RunArgs) -> Result<Option<AttemptId>, JailError> {
    // §6.1: PROGRAM is mandatory except with --label-only.
    if !args.label_only && args.argv.is_empty() {
        return Err(usage("PROGRAM", "a program to run is required"));
    }
    if args.label_only && (args.gate_fd.is_some() || args.attempt_id.is_some()) {
        return Err(usage(
            "--label-only",
            "--label-only rejects --gate-fd and --attempt-id",
        ));
    }
    if args.attempt_id.is_some() && args.gate_fd.is_none() {
        return Err(usage(
            "--attempt-id",
            "--attempt-id is only valid together with --gate-fd",
        ));
    }
    // §7: validate the id grammar before deriving any path, and before any
    // other check, so a malformed id is the usage error X02 expects rather than
    // whatever the next check happens to find first.
    args.attempt_id.as_deref().map(AttemptId::parse).transpose()
}

/// Every isolation rule a run's paths must meet before anything is created
/// (§6.2, §7, §9.1), over the child's roots computed once.
///
/// # Errors
/// The first rule's refusal.
fn check_isolation(args: &RunArgs, plan: &Plan) -> Result<(), JailError> {
    let roots = ChildRoots::of(plan);
    check_state_isolation(plan, &roots)?;
    // Audit 3 A2: every run, not only a `--launch` one.
    check_launch_isolation(plan, &roots)?;
    // Audit 4 B1: the config directory holds the trusted, widening
    // `config.toml`, read on every run.
    check_config_isolation(plan, &roots)?;
    check_binary_isolation(plan, &roots)?;
    validate_receipt_path(args, plan, &roots)
}

/// `--label-only` (§6.1): resolve and probe, print the label, execute nothing
/// and copy no credential. No attempt state is allocated, so there is nothing
/// to clean up.
fn label_only(ctx: &Context, plan: &Plan, request: &PlanRequest) -> RunReport {
    let capabilities = ctx.platform.probe(request);
    let refusal = first_unsatisfied(&plan.resolved.requirements, &capabilities);
    RunReport {
        exit_code: refusal.as_ref().map_or(0, JailError::exit_code),
        error: refusal,
        label: Some(format!(
            "label {}@{} observe={} digest={}",
            plan.resolved.policy_name,
            plan.resolved.snapshot.platform.as_str(),
            match plan.resolved.snapshot.observation.mode {
                crate::records::ObserveMode::On => "on",
                crate::records::ObserveMode::Off => "off",
            },
            plan.resolved.digest
        )),
        capabilities,
        ..RunReport::default()
    }
}

/// The `evidence_lost` error for the evidence classes the observer's final
/// account leaves degraded, or `None` when none is. The evidence classes are
/// the ones whose loss §11.4 handles as evidence loss, the classes a trace
/// stream carries ([`trace::STREAM_CLASSES`]); `limits` is the wrapper's own.
fn settlement_loss(summary: &crate::observer::CoverageSummary) -> Option<JailError> {
    let mut classes = Vec::new();
    let mut reasons: Vec<&str> = Vec::new();
    for class in trace::STREAM_CLASSES {
        let Some(entry) = summary.classes.get(&class) else {
            continue;
        };
        if entry.status != crate::records::SourceStatus::Degraded {
            continue;
        }
        classes.push(class.as_str());
        for gap in &entry.gaps {
            if !reasons.contains(&gap.reason.as_str()) {
                reasons.push(gap.reason.as_str());
            }
        }
    }
    if classes.is_empty() {
        return None;
    }
    Some(JailError::new(
        ErrorCode::EvidenceLost,
        ErrorStage::Reconciling,
        Remediation::InspectState,
        format!(
            "coverage was lost by settlement in {} ({}); the loss reached no run event",
            classes.join(", "),
            if reasons.is_empty() {
                "no gap named".to_owned()
            } else {
                reasons.join(", ")
            }
        ),
    ))
}

fn wall_deadline(plan: &Plan) -> Option<Instant> {
    plan.resolved
        .ceilings
        .wall
        .as_ref()
        .map(|ceiling| Instant::now() + Duration::from_millis(ceiling.value))
}

/// The evidence classes whose frames this attempt's trace carries (§11.4):
/// the audit classes with observation on, `proxy.net` with a proxy. A trace
/// loss can take these and no other.
fn stream_classes(plan: &Plan) -> Vec<CoverageClass> {
    let mut classes = Vec::new();
    if plan.resolved.snapshot.observation.mode == crate::records::ObserveMode::On {
        classes.extend(CoverageClass::AUDIT);
    }
    if plan.resolved.snapshot.network.mode == NetworkMode::Proxy.as_str() {
        classes.push(CoverageClass::ProxyNet);
    }
    classes
}

/// Queued frames from any active source may have been lost in transport.
///
/// J4 W3 (integrator decision): every class whose results are trace frames,
/// that is the audit classes and `proxy.net`. Not `limits`: its count comes
/// from the cgroup counters, not from the trace (§11.4: no `limit.hit`
/// event in v1), so no frame of it can have been lost, and it keeps what the
/// platform reported.
fn degrade_trace_coverage(record: &mut AttemptRecord, journal: &Journal) {
    use crate::records::{Gap, SourceStatus};
    // J5-C, review item 15: the loss the stream's note records (§13.3), from
    // the same start and as the same (wrapper) loss. A loss the sink never
    // noted (a poisoned trace lock) has no known start: the whole attempt.
    let start = journal
        .trace
        .lock()
        .ok()
        .and_then(|writer| writer.loss_start_ns())
        .map_or_else(|| "0".to_owned(), |start| start.to_string());
    record.observer.sources.wrapper = SourceStatus::Degraded;
    for status in [
        &mut record.observer.sources.audit,
        &mut record.observer.sources.proxy,
    ] {
        if *status != SourceStatus::Unsupported {
            *status = SourceStatus::Degraded;
        }
    }
    let coverage = &mut record.coverage;
    for (class, entry) in [
        (CoverageClass::Exec, &mut coverage.exec),
        (CoverageClass::FsWrite, &mut coverage.fs_write),
        (CoverageClass::FsDeny, &mut coverage.fs_deny),
        (CoverageClass::Net, &mut coverage.net),
        (CoverageClass::ProxyNet, &mut coverage.proxy_net),
    ] {
        let name = class.as_str();
        if entry.status == SourceStatus::Unsupported {
            continue;
        }
        entry.status = SourceStatus::Degraded;
        entry.observed_count = None;
        let end = Some(crate::platform::elapsed_since_start_ns().to_string());
        // J4 W2-S: (B) — called before every receipt once a loss is known,
        // so a class's transport gap is added once and then only extended:
        // a lost sink stays lost to the end.
        let is_ours = |gap: &Gap| {
            gap.reason == trace::TRANSPORT_LOSS_REASON && gap.classes == [name.to_owned()]
        };
        if entry.gaps.iter().any(is_ours) {
            for gap in entry
                .gaps
                .iter_mut()
                .chain(record.observer.gaps.iter_mut())
                .filter(|gap| is_ours(gap))
            {
                gap.end_ns.clone_from(&end);
            }
            continue;
        }
        let gap = Gap {
            classes: vec![name.to_owned()],
            source: "wrapper".to_owned(),
            start_ns: start.clone(),
            end_ns: end,
            reason: trace::TRANSPORT_LOSS_REASON.to_owned(),
            lost_count: None,
        };
        entry.gaps.push(gap.clone());
        record.observer.gaps.push(gap);
    }
}

/// Removes this attempt's managed scratch and placeholder holders (§14.2).
///
/// Only the directories this tool created under the attempt directory: an
/// operator-supplied `--scratch` and the workspace are never touched. The
/// removal is `gc`'s own anchored, bounded traversal (I07: every wait has a
/// bound), which also takes the read-only directories a child can leave.
///
/// `Ok(complete)` once both are gone, `Ok(not_needed)` when neither existed
/// (the `none` profile makes no managed scratch), and `Err` with the safe
/// reason when a removal stopped (a tree larger than the entry bound
/// included): the scratch is retained, the receipt records the cleanup
/// `pending`, and `gc` removes the rest on that receipt's proof of the
/// tree's end, then records the receipt's cleanup `complete`.
fn remove_managed_scratch(
    attempt_dir: &AttemptDir,
    plan: &Plan,
    limits: cleanup::Limits,
) -> Result<StateCleanup, String> {
    if plan.resolved.snapshot.roots.scratch != ScratchRoot::Managed {
        return Ok(cleanup::not_needed());
    }
    let mut created = false;
    let mut left = limits.max_entries;
    for name in state::MANAGED_DIRS {
        let removal = cleanup::remove_managed_dir(
            attempt_dir,
            name,
            cleanup::Limits {
                max_entries: left,
                ..limits
            },
        );
        left = left.saturating_sub(removal.visited);
        if !removal.complete {
            return Err(format!(
                "scratch_removal_failed: {}",
                removal.reason.as_deref().unwrap_or("the removal stopped")
            ));
        }
        created |= removal.removed > 0;
    }
    Ok(if created {
        StateCleanup::Complete
    } else {
        cleanup::not_needed()
    })
}

fn apply_boundary(record: &mut AttemptRecord, boundary: &BoundaryIdentity, profile: ProfileName) {
    record.containment = if profile.is_contained() {
        Containment::Enforced
    } else {
        Containment::None
    };
    record.lifetime = Lifetime {
        boundary: boundary.boundary.as_str().to_owned(),
        native: boundary.native.clone(),
        tree_empty: None,
        verified_at: None,
        verification_scope: Some(boundary.verification_scope.as_str().to_owned()),
        integrity: Integrity::Verified.as_str().to_owned(),
    };
    record.process = boundary.process.clone();
    // §13.2 wants the backend that made the boundary and its version; only
    // the platform that made it can say.
    if boundary.backend.is_some() {
        record.jail.backend.clone_from(&boundary.backend);
        record
            .jail
            .backend_version
            .clone_from(&boundary.backend_version);
    }
}

/// Whether either path is the other or one of its ancestors.
///
/// Component-wise, so `/work/a` does not contain `/work/ab`.
fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

/// Every root the child can see under the resolved policy (§7, §9.1).
fn child_visible_roots(plan: &Plan) -> Vec<PathBuf> {
    let mut roots = vec![plan.workspace.clone()];
    let snapshot = &plan.resolved.snapshot;
    if let ScratchRoot::Host { path } = &snapshot.roots.scratch {
        roots.push(PathBuf::from(std::ffi::OsString::from_vec(
            path.as_bytes().to_vec(),
        )));
    }
    for reference in snapshot
        .filesystem
        .read_write
        .iter()
        .chain(&snapshot.filesystem.read_only)
    {
        if reference.root == crate::policy::RootToken::Host {
            roots.push(PathBuf::from(std::ffi::OsString::from_vec(
                reference.path.as_bytes().to_vec(),
            )));
        }
    }
    roots
}

/// The roots the child can reach, each canonicalized once
/// ([`canonical_existing_prefix`]) for every isolation check of a run.
struct ChildRoots {
    /// [`child_visible_roots`].
    visible: Vec<PathBuf>,
    /// [`child_writable_roots`].
    writable: Vec<PathBuf>,
}

impl ChildRoots {
    fn of(plan: &Plan) -> Self {
        let canonical = |roots: Vec<PathBuf>| {
            roots
                .iter()
                .map(|root| canonical_existing_prefix(root))
                .collect()
        };
        ChildRoots {
            visible: canonical(child_visible_roots(plan)),
            writable: canonical(child_writable_roots(&plan.resolved, &plan.workspace)),
        }
    }
}

/// Refuses a guarded tree a child-visible root reaches (§7, §9.1): one
/// that overlaps a root lexically, or that a mount beneath a root reaches
/// through a bind alias (audit 4 B4: the lexical comparison cannot see
/// those, mountinfo can). The refusal names the tree as `noun` and carries
/// `code` and `key`.
///
/// # Errors
/// `code` at `key` for an overlap or an alias, and
/// [`ErrorCode::InvalidConfig`] when the mounts cannot be inspected.
fn check_isolated(
    roots: &[PathBuf],
    guarded: &Path,
    code: ErrorCode,
    key: &'static str,
    noun: &str,
) -> Result<(), JailError> {
    let guarded = canonical_existing_prefix(guarded);
    let refused = |message: String| {
        JailError::new(
            code,
            ErrorStage::Resolving,
            Remediation::Configuration,
            message,
        )
        .with_key_path(key)
    };
    if let Some(root) = roots.iter().find(|root| overlaps(&guarded, root)) {
        return Err(refused(format!(
            "the {noun} {} overlaps the child-visible root {}",
            guarded.display(),
            root.display()
        )));
    }
    if let Some(alias) = alias_conflict(roots, &guarded, key)? {
        return Err(refused(format!(
            "a mount beneath a child-visible root reaches the {noun} through the bind alias {}",
            alias.display()
        )));
    }
    Ok(())
}

// X05.3
static RELEASE_STDOUT_AFTER_PREPARE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// For the `ouro-jail` binary only, whose stdout is the target's: once an
/// attempt is prepared, [`run`] points this process's stdout at `/dev/null`
/// so the supervisor holds no copy that postpones the caller's EOF (§8.3).
/// A program that calls the library in-process never calls this and keeps
/// its stdout.
pub fn release_stdout_after_prepare() {
    RELEASE_STDOUT_AFTER_PREPARE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Points this process's own stdout at `/dev/null`. Best effort: a failure
/// leaves the copy in place, which only delays the caller's EOF.
fn release_own_stdout() {
    // SAFETY: open takes a NUL-terminated literal; dup2 and close take
    // descriptor numbers this process owns.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if null >= 0 {
            libc::dup2(null, libc::STDOUT_FILENO);
            libc::close(null);
        }
    }
}

/// Refuses a state root that the child can reach (§7, H7).
///
/// §6.2: runtime state is "outside every child-visible grant", and §7 asks for
/// the same of the receipt path, "including a broad grant of the state
/// directory's ancestor". `OURO_DATA_DIR=$WS/state` with `--rw $WS` used to
/// run: the contained party could read every receipt and policy snapshot, and
/// on `none` rewrite them.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when the state root overlaps the
/// workspace, the scratch root or any host grant, or reaches it through a
/// bind alias (audit 4 B4).
fn check_state_isolation(plan: &Plan, roots: &ChildRoots) -> Result<(), JailError> {
    check_isolated(
        &roots.visible,
        &plan.data_dir,
        ErrorCode::UnsafeStatePath,
        "OURO_DATA_DIR",
        "state root",
    )
}

/// Security 2026-09-27 (audit 3 A2): refuses a launch directory the child can
/// reach (§9.1).
///
/// `--launch NAME` stages operator environment and credentials from
/// `<config-dir>/launch/<name>.toml`, and [`check_outside_writable`] only
/// runs when a profile is actually loaded, over that profile's own file
/// chain. A run with no `--launch` had no guard at all: a contained party
/// holding a grant that covers the launch directory could plant a
/// `<name>.toml` that passes every load check (operator uid, mode 0600, one
/// link) and stage its `[credentials]` on a later `--launch` run. Like the
/// state root in [`check_state_isolation`], the launch directory therefore
/// never overlaps a child-visible root, on every run.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeConfigPath`] when the launch directory overlaps
/// the workspace, the scratch root or any host grant, or reaches it through
/// a bind alias (audit 4 B4).
fn check_launch_isolation(plan: &Plan, roots: &ChildRoots) -> Result<(), JailError> {
    check_isolated(
        &roots.visible,
        &launch_profile::launch_directory(&plan.config_dir),
        ErrorCode::UnsafeConfigPath,
        "OURO_CONFIG_DIR",
        "launch directory",
    )
}

/// Executable code must not be replaceable through a writable child root.
fn check_binary_isolation(plan: &Plan, roots: &ChildRoots) -> Result<(), JailError> {
    if plan.profile() == ProfileName::None {
        return Ok(());
    }
    let mut binaries = vec![std::env::current_exe().map_err(|e| usage("binaries", e.to_string()))?];
    #[cfg(target_os = "linux")]
    if let Ok(path) = crate::platform::linux::platform::resolved_bwrap() {
        binaries.push(path.to_path_buf());
    }
    #[cfg(target_os = "macos")]
    binaries.push(PathBuf::from("/usr/bin/sandbox-exec"));
    let roots = &roots.writable;
    for binary in binaries {
        let binary = canonical_existing_prefix(&binary);
        let conflict = roots
            .iter()
            .find(|root| binary.starts_with(root))
            .cloned()
            .or(alias_conflict(roots, &binary, "binaries")?);
        if let Some(root) = conflict {
            return Err(JailError::new(
                ErrorCode::UnsafeStatePath,
                ErrorStage::Resolving,
                Remediation::Configuration,
                format!(
                    "writable child root {} exposes executable {}",
                    root.display(),
                    binary.display()
                ),
            )
            .with_key_path("binaries"));
        }
    }
    Ok(())
}

/// Security 2026-09-27 (audit 4 B1): refuses a config directory the child can
/// reach, on every run.
///
/// The audit 3 A2 guard covers `<config>/launch` only, but
/// `<config>/config.toml` is read on every run (§6.2) and is a trusted,
/// **widening** layer: `[jail.filesystem]` grants, `[jail.network] allow`
/// and `[jail.observation] mode = "off"` from a planted file all take
/// effect for every later invocation — a strictly larger effect than the
/// launch-profile plant A2 closed, from the same one pointed file grant
/// (`--rw <config>/config.toml` passes the launch-directory guard by
/// construction). The whole config directory is therefore isolated like
/// the state root and the launch directory: lexical overlap and bind
/// aliases both refuse.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeConfigPath`] when the config directory overlaps
/// the workspace, the scratch root or any host grant, or reaches it through
/// a bind alias.
fn check_config_isolation(plan: &Plan, roots: &ChildRoots) -> Result<(), JailError> {
    if plan.profile() == ProfileName::None {
        let mut trusted = Vec::new();
        let config = plan.config_dir.join("config.toml");
        if config.symlink_metadata().is_ok() {
            trusted.push(config);
        }
        match std::fs::read_dir(launch_profile::launch_directory(&plan.config_dir)) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry.map_err(|e| usage("OURO_CONFIG_DIR", e.to_string()))?;
                    if entry.path().extension().is_some_and(|ext| ext == "toml") {
                        trusted.push(entry.path());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(usage("OURO_CONFIG_DIR", e.to_string())),
        }
        if !trusted.is_empty() {
            return Err(JailError::new(ErrorCode::UnsafeConfigPath, ErrorStage::Resolving,
                Remediation::Configuration, format!(
                    "an uncontained child can change trusted configuration: {}; move it aside or run contained",
                    trusted.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
                )).with_key_path("OURO_CONFIG_DIR"));
        }
    }
    check_isolated(
        &roots.visible,
        &plan.config_dir,
        ErrorCode::UnsafeConfigPath,
        "OURO_CONFIG_DIR",
        "config directory",
    )
}

/// Security 2026-09-27 (audit 4 B4): mountinfo's bind-alias verdict for one
/// guarded tree, with the guard's own key naming an inspection failure.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] when the alias table cannot be read.
fn alias_conflict(
    roots: &[PathBuf],
    guarded: &Path,
    key: &'static str,
) -> Result<Option<PathBuf>, JailError> {
    state::mount_alias::alias_conflict(roots, guarded)
        .map_err(|error| usage(key, format!("the mounts cannot be inspected: {error}")))
}

/// The canonical form of the deepest existing ancestor, plus the rest.
///
/// A path that does not exist yet still has a canonical prefix, which is what
/// overlap comparisons need: `/var/folders/x/data` and `/private/var/...` are
/// the same directory on macOS.
fn canonical_existing_prefix(path: &Path) -> PathBuf {
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut probe = path.to_path_buf();
    loop {
        if let Ok(resolved) = std::fs::canonicalize(&probe) {
            let mut out = resolved;
            for component in suffix.iter().rev() {
                out.push(component);
            }
            return out;
        }
        let Some(name) = probe.file_name().map(std::ffi::OsStr::to_os_string) else {
            return path.to_path_buf();
        };
        suffix.push(name);
        if !probe.pop() {
            return path.to_path_buf();
        }
    }
}

/// Validates `--receipt PATH` before anything is written (§7, H8).
///
/// The flag had no checks at all: it wrote inside the workspace, replaced a
/// symlink, clobbered an unrelated file and could overwrite another attempt's
/// `policy.json`. §7 requires the copy to live "outside every child-visible
/// root", to not be "a symlink, device or existing unrelated file", and the
/// state directory is not a place for a second copy either. A file that is
/// itself a prior `ouro.jail.receipt/1` copy is not unrelated: the write is a
/// temp-file rename, so replacing it is the atomic replacement `--help`
/// promises, and a retry after a refused run no longer needs a fresh path.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for a path that fails any of those.
fn validate_receipt_path(args: &RunArgs, plan: &Plan, roots: &ChildRoots) -> Result<(), JailError> {
    let Some(path) = &args.receipt else {
        return Ok(());
    };
    let key = "--receipt";
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && prior_receipt_copy(path) => {}
        Ok(_) => {
            return Err(usage(
                key,
                format!(
                    "{} already exists; the receipt copy only replaces a prior \
                     receipt copy, never another file, symlink or device",
                    path.display()
                ),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(usage(key, format!("{}: {error}", path.display()))),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let parent = std::fs::canonicalize(&parent)
        .map_err(|error| usage(key, format!("{}: {error}", parent.display())))?;
    if !parent.is_dir() {
        return Err(usage(
            key,
            format!("{} is not a directory", parent.display()),
        ));
    }
    // Directional: a directory that merely *contains* the state root is an
    // ordinary place for a copy. What §7 forbids is a copy *inside* the state
    // root, or inside anything the child can see.
    let state_root = canonical_existing_prefix(&plan.data_dir);
    if parent.starts_with(&state_root) {
        return Err(usage(
            key,
            format!(
                "{} is inside the state root {}; the canonical receipt already lives there",
                parent.display(),
                state_root.display()
            ),
        ));
    }
    let roots = &roots.visible;
    for root in roots {
        if parent.starts_with(root) {
            return Err(usage(
                key,
                format!(
                    "{} is inside the child-visible root {}",
                    parent.display(),
                    root.display()
                ),
            ));
        }
    }
    // Security 2026-09-27 (audit 4 B4): a parent that is not lexically inside
    // a child-visible root can still be a bind alias of one (or of the state
    // root), which the comparisons above cannot see. The copy must not land
    // where the child, or the state store, reaches it through a mount.
    for guarded in std::iter::once(&state_root).chain(roots.iter()) {
        if let Some(alias) =
            state::mount_alias::alias_containment(std::slice::from_ref(&parent), guarded)
                .map_err(|error| usage(key, format!("cannot verify receipt aliases: {error}")))?
        {
            return Err(usage(
                key,
                format!(
                    "{} reaches {} through the bind alias {}; the receipt copy \
                     must not land inside anything the child can see",
                    parent.display(),
                    guarded.display(),
                    alias.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Whether an existing regular file is a prior receipt copy: within the
/// receipt bound every reader uses ([`cleanup::RECEIPT_MAX`]), read without
/// following a link, and carrying the `ouro.jail.receipt/1` schema
/// identifier. Anything else — truncated, huge or foreign — stays untouched.
fn prior_receipt_copy(path: &Path) -> bool {
    let Ok(Some(bytes)) = state::read_capped(path, cleanup::RECEIPT_MAX) else {
        return false;
    };
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .is_some_and(|value| {
            value
                .get("schema")
                .and_then(|schema| schema.as_str())
                .is_some_and(|schema| schema == crate::records::SCHEMA_RECEIPT)
        })
}

/// The longest single wait for the gate between deadline checks.
const GATE_POLL_STEP: Duration = Duration::from_millis(250);

/// A preparation budget with a stage-appropriate refusal (§8.2), on the
/// continuous clock (§6.4).
struct Budget {
    deadline: ContinuousDeadline,
    total: Duration,
}

impl Budget {
    fn new(total: Duration) -> Self {
        Budget {
            deadline: ContinuousDeadline::after(total),
            total,
        }
    }

    /// Refuses when the budget is spent.
    ///
    /// # Errors
    /// Returns [`ErrorCode::PrepareTimeout`].
    fn check(&self, stage: ErrorStage) -> Result<(), JailError> {
        if !self.deadline.remaining().is_zero() {
            return Ok(());
        }
        Err(JailError::new(
            ErrorCode::PrepareTimeout,
            stage,
            Remediation::Retry,
            format!(
                "preparation did not complete within its {} second budget",
                self.total.as_secs()
            ),
        ))
    }
}

/// Refuses when a signal asked this supervisor to stop (§8.3).
///
/// # Errors
/// Returns the stop refusal when the self-pipe has a byte waiting.
fn interrupted(signals: Option<&signals::SignalPipe>, stage: ErrorStage) -> Result<(), JailError> {
    match signals {
        Some(pipe) if pipe.triggered() => Err(stopped_by_signal(stage)),
        _ => Ok(()),
    }
}

/// Records the wall ceiling as the supervisor's own deadline (§13.2), when
/// the platform's `applied` reports no `wall` row.
///
/// Such a platform enforces the wall only through the deadline the
/// supervisor hands to [`RunningExecution::wait`](crate::platform::RunningExecution::wait),
/// so that deadline is the mechanism the row names. A platform that enforces
/// its own wall (Linux, on `CLOCK_BOOTTIME` from release) reports its own
/// row, which this leaves alone. The mechanism name states the clock this
/// code actually uses: `Instant` is `CLOCK_MONOTONIC`, and calling it a
/// boot-time deadline would be a claim about suspend that portable code
/// cannot make (§6.4, M10).
fn merge_wall_limit(record: &mut AttemptRecord, plan: &Plan) {
    let Some(wall) = plan.resolved.ceilings.wall.as_ref() else {
        return;
    };
    if record
        .applied
        .limits
        .iter()
        .any(|limit| limit.key == "wall")
    {
        return;
    }
    record.applied.limits.push(AppliedLimit {
        key: "wall".to_owned(),
        requested: wall.requested.clone(),
        required: wall.required,
        applied: true,
        mechanism: Some("monotonic-deadline".to_owned()),
        scope: Some("tree".to_owned()),
        hit: Some(false),
    });
}

/// Records what an aborted preparation left behind (§13.2 row 4, M14).
///
/// "true / timestamp only after teardown verification; otherwise null / null",
/// and an unverified boundary must not keep claiming `verified` integrity. The
/// teardown result used to be dropped on the floor, so a refusal after setup
/// reported the boundary as verified with a null tree and no explanation.
fn record_teardown(record: &mut AttemptRecord, teardown: &Result<Teardown, JailError>) {
    match teardown {
        Ok(Teardown { tree: Some(tree) }) => record_tree(record, tree),
        Ok(Teardown { tree: None }) => {
            // Teardown ran but verified nothing about the tree.
            record.lifetime.tree_empty = None;
            record.lifetime.verified_at = None;
        }
        Err(error) => {
            record.errors.push(error.to_object());
            record.lifetime.tree_empty = None;
            record.lifetime.verified_at = None;
            if !TreeEnd::of(&record.lifetime).no_boundary {
                record.lifetime.integrity = Integrity::Lost.as_str().to_owned();
            }
        }
    }
}

// Persistence failures, the worker's receipts, their acknowledgement

/// The coded error a storage enforcement loss records (audit 2026-10-08 L2):
/// the message names `storage_enforcement_lost` so consumers can tell it
/// from observation-evidence loss.
fn storage_loss_error(reason: String) -> JailError {
    JailError::new(
        ErrorCode::EvidenceLost,
        ErrorStage::Running,
        Remediation::InspectState,
        format!(
            "{}: {reason}",
            crate::platform::LimitCause::StorageEnforcementLost.cause()
        ),
    )
}

/// Asks the platform to stop for `reason` and records it as
/// `outcome.cause` unless an earlier stop already is (J4-D5: the first stop
/// wins, as it does in the platform's `request_stop`). The one place a stop
/// is requested, so the cause recorded and the reason sent cannot disagree.
fn stop(
    running: &mut dyn crate::platform::RunningExecution,
    record: &mut AttemptRecord,
    reason: StopReason,
) {
    record
        .outcome
        .cause
        .get_or_insert_with(|| reason.cause().to_owned());
    running.request_stop(reason);
}

/// Records a persistence failure after release and stops the tree for it
/// (§7, §13.3): in `errors[]`, as the stop cause unless one came first
/// (D5), and as the reported error unless one came first.
fn persistence_failed(
    running: &mut dyn crate::platform::RunningExecution,
    record: &mut AttemptRecord,
    outcome_error: &mut Option<JailError>,
    error: JailError,
) {
    stop(running, record, StopReason::StateWriteFailed);
    persistence_failed_after(record, outcome_error, error);
}

/// Records a persistence failure after exec that is a tool error (S5: exit
/// 1) but not a reason to stop anything: the tree is already stopped.
fn persistence_failed_after(
    record: &mut AttemptRecord,
    outcome_error: &mut Option<JailError>,
    error: JailError,
) {
    record.errors.push(error.to_object());
    outcome_error.get_or_insert(error);
}

/// J4 W3, P5: the errors of this attempt that no durable receipt carries and
/// that the report does not already name (`printed`: its `error` and
/// `trace_error`), in the order they were raised. `errors[]` only grows, and
/// every durable receipt carries a prefix of it, so what the last one lacks
/// is exactly the tail after its length.
fn unrecorded(
    record: &AttemptRecord,
    journal: &Journal,
    printed: &[Option<&JailError>],
) -> Vec<crate::records::ErrorObject> {
    let printed: Vec<crate::records::ErrorObject> = printed
        .iter()
        .flatten()
        .map(|error| error.to_object())
        .collect();
    record
        .errors
        .iter()
        .skip(journal.durable_errors)
        .filter(|error| !printed.contains(error))
        .cloned()
        .collect()
}

/// A receipt handed to the persistence worker, and what it acknowledges once
/// it is durable.
struct InFlight {
    pending: state::Pending<Result<(), JailError>>,
    receipt: Receipt,
    ack: Option<ControlKind>,
}

/// Renders the receipt for `phase` and hands it to the worker (§13.3).
///
/// The revision is spent here, before any byte carrying it can be visible
/// (§13.2): a write that fails or stalls skips its number, it never hands it
/// to a different receipt.
fn submit_receipt(
    persister: &state::Persister,
    site: state::Site,
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    args: &RunArgs,
    journal: &Journal,
) -> Result<InFlight, JailError> {
    // J4 W2-S: (B) — as in `persist_noted`.
    if journal.loss.is_some() {
        degrade_trace_coverage(record, journal);
    }
    record.updated_at = SystemTime::now();
    let receipt = record.receipt(phase);
    let bytes = cleanup::record_bytes("receipt", &receipt, ErrorStage::Running)?;
    record.revision += 1;
    let canonical = attempt_dir.receipt_path();
    let extra = args.receipt.clone();
    let pending = persister.submit(move || {
        state::replace_atomically_at(site, &canonical, &bytes)?;
        if let Some(extra) = extra {
            state::replace_atomically_at(site, &extra, &bytes)?;
        }
        Ok(())
    });
    Ok(InFlight {
        pending,
        receipt,
        ack: None,
    })
}

/// Acknowledges the receipts the worker has made durable, in order, and
/// returns the first failure. With `wait`, each is waited for within the
/// worker's progress budget; without it, only finished ones are taken. A
/// receipt that failed or stalled is never acknowledged, and neither is any
/// receipt after it (its content would claim what the earlier one did not
/// persist).
fn settle_in_flight(
    in_flight: &mut std::collections::VecDeque<InFlight>,
    wait: bool,
    mut control: Option<&mut ControlSink>,
    journal: &mut Journal,
) -> Option<JailError> {
    while let Some(front) = in_flight.front() {
        let outcome = match front.pending.poll() {
            state::Progress::Done(result) => result,
            state::Progress::Stalled(stalled) => Err(stalled_error(stalled)),
            state::Progress::Waiting if !wait => return None,
            state::Progress::Waiting => front
                .pending
                .wait()
                .unwrap_or_else(|stalled| Err(stalled_error(stalled))),
        };
        let done = in_flight.pop_front().expect("the front was just seen");
        match outcome {
            Ok(()) => acknowledge(&done, control.as_deref_mut(), journal),
            Err(error) => {
                // Nothing after a failed transition is acknowledged either;
                // dropping them makes the worker skip what has not started.
                in_flight.clear();
                return Some(error.in_stage(ErrorStage::Running));
            }
        }
    }
    None
}

fn stalled_error(stalled: state::Stalled) -> JailError {
    JailError::new(
        ErrorCode::StateWriteFailed,
        ErrorStage::Running,
        Remediation::InspectState,
        format!("{stalled} (§13.3); the transition is not acknowledged"),
    )
}

fn acknowledge(done: &InFlight, control: Option<&mut ControlSink>, journal: &mut Journal) {
    journal.receipt(&done.receipt, false);
    if let Some(kind) = done.ack {
        send_control(control, kind, &done.receipt);
    }
}

/// The control channel's bounded final drain, then its honest count (N4).
fn finish_control(control: Option<&mut ControlSink>) -> u64 {
    control.map_or(0, |control| control.finish(CONTROL_DRAIN))
}

fn pending_applied(plan: &Plan) -> Applied {
    let mode = if plan.profile().is_contained() {
        // Nothing has been applied yet.
        "pending"
    } else {
        // §13.2 and the receipt schema: a `none` receipt always says `host`.
        NetworkMode::Host.as_str()
    };
    Applied {
        filesystem: None,
        network: AppliedNetwork {
            mode: mode.to_owned(),
            mechanism: None,
            allowed_hosts: Vec::new(),
            tls_only: Vec::new(),
        },
        syscalls: None,
        limits: Vec::new(),
        environment_names: Vec::new(),
        removed_environment_names: Vec::new(),
    }
}

// Vendor state and credential staging (§7, §8.1, §12)

/// Registers and creates vendor state, stages credentials into it, records
/// their private provenance and returns the hand-off for the platform.
///
/// `record.credentials` carries every successfully staged input, including
/// those staged before a refusal (§12). From the moment vendor state is
/// registered, the receipt's cleanup status is `pending`.
fn prepare_launch(
    attempt_dir: &AttemptDir,
    plan: &Plan,
    record: &mut AttemptRecord,
    deadline: ContinuousDeadline,
) -> Result<Option<crate::credentials::LaunchHandoff>, JailError> {
    let snapshot = &plan.resolved.snapshot;
    if snapshot.roots.vendor_state.is_none() {
        if snapshot
            .launch
            .as_ref()
            .is_some_and(|launch| !launch.credentials.is_empty())
        {
            return Err(JailError::new(
                ErrorCode::InternalError,
                ErrorStage::Preparing,
                Remediation::InspectState,
                "the snapshot declares credentials but no vendor state to stage them in".to_owned(),
            ));
        }
        return Ok(None);
    }
    let Some(launch) = snapshot.launch.as_ref() else {
        return Err(JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Preparing,
            Remediation::InspectState,
            "the snapshot has managed vendor state but no launch field group".to_owned(),
        ));
    };
    record.state_cleanup = StateCleanup::Pending;
    let vendor = state::create_vendor_state(attempt_dir)?;
    // §12 and the §8.2 preparation budget: staging runs in a worker bounded
    // by what is left of it, and no source may lie in a child-writable grant.
    let mut forbidden = forbidden_identities(&plan.resolved, &plan.workspace)?;
    if launch.credentials.iter().any(|c| c.mode == "vault") {
        forbidden.extend(
            state::mount_alias::forbidden_identities(&child_visible_roots(plan)).map_err(|e| {
                usage(
                    "launch.credentials",
                    format!("visible roots cannot be inspected: {e}"),
                )
            })?,
        );
    }
    let mut staged =
        match crate::credentials::stage_within(launch, vendor.as_fd(), &forbidden, &|| {
            deadline.remaining()
        }) {
            Ok(staged) => staged,
            Err(refusal) => {
                // Both the receipt rows and the private provenance of every
                // input staged before the refusal are kept (§12).
                record.credentials = receipt_credentials(&refusal.staged);
                state::record_staged_credentials(
                    attempt_dir,
                    &private_provenance(&refusal.staged),
                )?;
                return Err(refusal.error);
            }
        };
    record.credentials = receipt_credentials(&staged);
    state::record_staged_credentials(attempt_dir, &private_provenance(&staged))?;
    crate::credentials::LaunchHandoff::new(
        attempt_dir.vendor_state_path(),
        vendor.into_fd(),
        &mut staged,
    )
    .map(Some)
    .map_err(|error| {
        JailError::new(
            ErrorCode::StateWriteFailed,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("vendor state could not be handed to the platform: {error}"),
        )
    })
}

/// Audit 2026-09-25-2, S6: the receipt rows for staged credentials. The
/// receipt is the artifact meant to be shared, and a plain content digest is
/// an offline guessing oracle for the secret, so the rows carry no digest;
/// the digest the staging computed stays in jail state's private provenance
/// (`private_provenance`), where the operator — and only the operator — can
/// verify what was staged.
fn receipt_credentials(
    staged: &[crate::credentials::StagedCredential],
) -> Vec<crate::records::CredentialRecord> {
    staged
        .iter()
        .map(|credential| {
            let mut record = credential.record.clone();
            record.digest = None;
            record.digest_unavailable_reason = Some(
                if record.mode == "vault" {
                    "never_staged"
                } else {
                    "receipt_verifier_withheld"
                }
                .to_owned(),
            );
            record
        })
        .collect()
}

/// The private provenance of staged credentials: identities, never paths.
fn private_provenance(
    staged: &[crate::credentials::StagedCredential],
) -> Vec<state::PrivateCredential> {
    staged
        .iter()
        .map(|credential| state::PrivateCredential {
            id: credential.record.id.clone(),
            mode: credential.record.mode.clone(),
            source_dev: credential.source.dev,
            source_ino: credential.source.ino,
            source_size: credential.source.size,
            content_digest: credential.record.digest.clone(),
        })
        .collect()
}

/// The `(dev, ino)` of every child-writable grant a credential source may not
/// lie in: the workspace, an explicit scratch and every writable host grant.
/// These are trusted operator roots, resolved as such; one that does not
/// exist cannot contain a source.
fn forbidden_identities(
    resolved: &Resolved,
    workspace: &Path,
) -> Result<Vec<(u64, u64)>, JailError> {
    state::mount_alias::forbidden_identities(&child_writable_roots(resolved, workspace)).map_err(
        |error| {
            usage(
                "launch.credentials",
                format!("writable grants cannot be inspected: {error}"),
            )
        },
    )
}

/// Copies a tree observation into the receipt's lifetime group: the one
/// place a verification, a teardown or a failed release reaches it.
fn record_tree(record: &mut AttemptRecord, tree: &crate::platform::TreeObservation) {
    record.lifetime.tree_empty = tree.tree_empty;
    record.lifetime.verified_at = tree.verified_at.map(rfc3339_utc);
    record.lifetime.verification_scope = Some(tree.verification_scope.as_str().to_owned());
    record.lifetime.integrity = tree.integrity.as_str().to_owned();
}

/// Retains registered vendor state, recording `reason`, why it waits (§12:
/// "Attempts with unproved live trees retain state").
///
/// A failed record of it is returned, not dropped: it is persistence like
/// any other.
fn retain_vendor_state(
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    reason: &'static str,
) -> Option<JailError> {
    record.state_cleanup = StateCleanup::Pending;
    record.cleanup_error = Some(reason.to_owned());
    state::record_cleanup(attempt_dir, StateCleanup::Pending, Some(reason)).err()
}

/// Vendor state on a refusal: removed when the refusal proves no tree can be
/// using it, retained otherwise. The refused receipt is first persisted as
/// `pending`, so a crash during the removal leaves a receipt `gc` can finish.
fn refuse_vendor_state(
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    args: &RunArgs,
    journal: &mut Journal,
) {
    match state::vendor_registration(attempt_dir) {
        Ok(None) => {
            record.state_cleanup = StateCleanup::NotNeeded;
            return;
        }
        Ok(Some(_)) => {}
        Err(error) => {
            record.state_cleanup = StateCleanup::Pending;
            record.cleanup_error = Some(format!("state_unreadable: {}", error.code.as_str()));
            return;
        }
    }
    if let Some(reason) = cleanup::wait_reason(Phase::Refused, TreeEnd::of(&record.lifetime)) {
        if let Some(error) = retain_vendor_state(attempt_dir, record, reason) {
            record.errors.push(error.to_object());
        }
        return;
    }
    record.state_cleanup = StateCleanup::Pending;
    record.cleanup_error = None;
    if let Err(error) = persist(
        state::Site::PendingReceipt,
        attempt_dir,
        record,
        Phase::Refused,
        args,
        journal,
    ) {
        record.errors.push(error.to_object());
        record.cleanup_error = Some("state_write_failed".to_owned());
        return;
    }
    let result = cleanup::remove_vendor_state(attempt_dir, cleanup::Limits::DEFAULT);
    if let Some(error) = &result.record_error {
        record.errors.push(error.to_object());
    }
    record.state_cleanup = result.status;
    record.cleanup_error = result.reason;
}

// J4-G: `gc_proxy_then_resume` moved to `gc.rs` with the rest of gc (G1).

// The proxy directory (§10)
/// Registers and creates `<attempt>/proxy/` for a proxy-mode profile and
/// returns the hand-off the platform binds the proxy socket in.
fn prepare_proxy_dir(
    attempt_dir: &AttemptDir,
    plan: &Plan,
) -> Result<Option<crate::platform::ProxyDirHandoff>, JailError> {
    if plan.resolved.snapshot.network.mode != NetworkMode::Proxy.as_str() {
        return Ok(None);
    }
    let dir = state::create_proxy_dir(attempt_dir)?;
    let identity = dir
        .stat()
        .map_err(|error| {
            JailError::new(
                ErrorCode::StateWriteFailed,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("the proxy directory could not be inspected: {error}"),
            )
        })?
        .identity();
    Ok(Some(crate::platform::ProxyDirHandoff {
        host_path: attempt_dir.proxy_dir_path(),
        fd: Arc::new(dir.into_fd()),
        identity,
        socket: Arc::new(std::sync::OnceLock::new()),
    }))
}

/// Removes the proxy directory once the platform stopped the proxy. A
/// directory that cannot be removed is retained and said so in jail state
/// and in the receipt's errors; it never changes the outcome.
///
/// J4-R: a failure to record the removal in jail state is returned too: it is
/// persistence, and after exec a tool error (S5).
fn remove_proxy_directory(
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
) -> Option<JailError> {
    match state::remove_proxy_dir(attempt_dir) {
        Ok(state::ProxyDirRemoval::Retained(reason) | state::ProxyDirRemoval::Failed(reason)) => {
            record.errors.push(
                JailError::new(
                    ErrorCode::StateWriteFailed,
                    ErrorStage::Reconciling,
                    Remediation::InspectState,
                    format!("the proxy directory was retained: {reason}"),
                )
                .to_object(),
            );
            None
        }
        Ok(_) => None,
        Err(error) => {
            record.errors.push(error.to_object());
            Some(error)
        }
    }
}

// An inherited ignored disposition is the operator's
/// Whether `signal` is ignored in this process as inherited. Only Linux runs
/// a target, so only Linux has a disposition to pass through.
fn signals_inherited_ignored(signal: libc::c_int) -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::sys::signal_ignored(signal)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = signal;
        false
    }
}

/// The wrapper source's own event stream for this attempt (§13.1).
///
/// `source_seq` starts at 1 for this source and never restarts within the
/// attempt; `monotonic_ns` is nanoseconds since this supervisor started, as a
/// decimal string, so JSON number precision cannot corrupt it.
struct Journal {
    attempt_id: String,
    trace: SharedTrace,
    loss: Option<JailError>,
    /// True while `loss` has not yet been surfaced to the supervision loop.
    loss_pending: bool,
    /// J4 W3, P5: how many `errors[]` entries the latest durable receipt
    /// carries. Every durable receipt passes [`Journal::receipt`] (or
    /// [`Journal::durable`]), so the rest never reached a receipt.
    durable_errors: usize,
}

impl Journal {
    fn new(attempt_id: &str, trace: SharedTrace) -> Self {
        Journal {
            attempt_id: attempt_id.to_owned(),
            trace,
            loss: None,
            loss_pending: false,
            durable_errors: 0,
        }
    }

    /// Notes that `receipt` is durable, without a trace note.
    fn durable(&mut self, receipt: &Receipt) {
        self.durable_errors = self.durable_errors.max(receipt.errors.len());
    }

    /// The sink loss that has not been handled yet, if any (§13.3).
    ///
    /// The supervision loop calls this once per iteration so a strict run
    /// stops on trace-sink loss without waiting for the next event; the
    /// first loss is kept in `loss` for the final report.
    fn take_new_loss(&mut self) -> Option<JailError> {
        let transport_error = match self.trace.lock() {
            Ok(mut sink) => {
                let progress = sink.poll().err();
                progress.or_else(|| {
                    sink.loss().map(|loss| {
                        JailError::new(
                            ErrorCode::EvidenceLost,
                            ErrorStage::Running,
                            Remediation::InspectState,
                            loss.reason.clone(),
                        )
                    })
                })
            }
            Err(_) => Some(JailError::new(
                ErrorCode::EvidenceLost,
                ErrorStage::Running,
                Remediation::InspectState,
                "trace writer poisoned".to_owned(),
            )),
        };
        if self.loss.is_none()
            && let Some(error) = transport_error
        {
            self.loss = Some(error);
            self.loss_pending = true;
        }
        if self.loss_pending {
            self.loss_pending = false;
            self.loss.clone()
        } else {
            None
        }
    }

    fn emit(&mut self, event: &crate::records::Event, priority: Priority) {
        let outcome = match self.trace.lock() {
            Ok(mut sink) => sink.write_event(event, priority),
            Err(_) => Err(JailError::new(
                ErrorCode::EvidenceLost,
                ErrorStage::Running,
                Remediation::InspectState,
                "the trace writer was poisoned by a panic".to_owned(),
            )),
        };
        if let Err(error) = outcome {
            // Keep the first loss: later frames fail for the same reason and a
            // later message would hide the one that started it.
            if self.loss.is_none() {
                self.loss = Some(error);
                self.loss_pending = true;
            }
        }
    }

    /// A lifecycle note (`fields.kind = lifecycle`).
    fn lifecycle(&mut self, transition: &str) {
        let event = crate::records::Event::lifecycle_note(
            &self.attempt_id,
            0, // assigned under the shared stream lock
            SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            transition,
        );
        self.emit(&event, Priority::Normal);
    }

    /// A `jail.receipt` event referencing a receipt that is already durable.
    ///
    /// The note names the receipt by `sha256:` over its RFC 8785 canonical
    /// bytes (canonicalization.md), which a consumer can recompute from
    /// `jail.json` alone. A receipt that cannot be canonicalized (a float,
    /// which no receipt field is) gets no note with an invented digest: the
    /// missing note is recorded as trace loss.
    fn receipt(&mut self, receipt: &Receipt, terminal: bool) {
        let phase = receipt.phase;
        self.durable(receipt);
        let digest = match receipt_digest(receipt) {
            Ok(digest) => digest,
            Err(reason) => {
                if self.loss.is_none() {
                    self.loss = Some(JailError::new(
                        ErrorCode::EvidenceLost,
                        ErrorStage::Running,
                        Remediation::InspectState,
                        format!("the {phase:?} receipt note has no canonical digest: {reason}"),
                    ));
                    self.loss_pending = true;
                }
                return;
            }
        };
        let event = crate::records::Event::receipt_note(
            &self.attempt_id,
            0, // assigned under the shared stream lock
            SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            phase,
            &digest,
        );
        self.emit(
            &event,
            if terminal {
                // §13.3: the reserve exists for exactly these final notes.
                Priority::Reserve
            } else {
                Priority::Normal
            },
        );
    }
}

/// `sha256:` over the receipt's RFC 8785 canonical bytes (canonicalization.md):
/// the one name a receipt has, in the trace's receipt notes (§13.1) and in
/// control messages (§8.2), recomputable from `jail.json` alone. Fails only
/// for a receipt that cannot be canonicalized (a float, which no receipt
/// field is).
fn receipt_digest(receipt: &Receipt) -> Result<String, String> {
    let value = serde_json::to_value(receipt).map_err(|error| error.to_string())?;
    let canonical = crate::canonical::to_jcs(&value).map_err(|error| error.to_string())?;
    Ok(crate::canonical::sha256_prefixed(&canonical))
}

/// Renders the receipt for `phase`, writes it durably and advances the
/// revision (§13.2).
///
/// Public so that the revision rule is testable where it lives: §13.2 says the
/// revision starts at 1 and "advances on each successful replacement", and
/// the only way to see that is to replace and read what landed. A revision
/// number is never reused: it is spent once bytes carrying it can become
/// visible, which is from the canonical rename on, so a failure after that
/// point (the directory sync, or any step of the extra copy) skips a number
/// rather than handing the same number to a different receipt. A failure
/// before it (the temporary file or its sync) exposed nothing and spends
/// nothing.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when either copy cannot be written,
/// a receipt past [`cleanup::RECEIPT_MAX`] included, which no reader would
/// accept and is never written.
pub fn write_receipt(
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    extra_copy: Option<&Path>,
) -> Result<Receipt, JailError> {
    let io = state::current_io();
    write_receipt_at(
        state::Site::Unnamed,
        attempt_dir,
        record,
        phase,
        extra_copy,
        &*io,
    )
}

/// [`write_receipt`] against an explicit persistence seam, the seam failure
/// injection uses to fail each step.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when either copy cannot be written.
pub fn write_receipt_with(
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    extra_copy: Option<&Path>,
    io: &dyn state::PersistIo,
) -> Result<Receipt, JailError> {
    write_receipt_at(
        state::Site::Unnamed,
        attempt_dir,
        record,
        phase,
        extra_copy,
        io,
    )
}

/// [`write_receipt_with`] at a named persistence site (R02).
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when either copy cannot be written.
pub fn write_receipt_at(
    site: state::Site,
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    extra_copy: Option<&Path>,
    io: &dyn state::PersistIo,
) -> Result<Receipt, JailError> {
    record.updated_at = SystemTime::now();
    let receipt = record.receipt(phase);
    let bytes = cleanup::record_bytes("receipt", &receipt, ErrorStage::Preparing)?;
    let canonical = state::TempWrite::create_at(site, &attempt_dir.receipt_path(), &bytes, io)?;
    // J4-D4: the rename below can land and a later step still fail (its
    // directory sync, or the extra copy), leaving this revision visible under
    // an error. Spending it here, before the rename, means the next receipt
    // never carries the same number with different content.
    record.revision += 1;
    canonical.commit()?;
    if let Some(path) = extra_copy {
        state::TempWrite::create_at(site, path, &bytes, io)?.commit()?;
    }
    Ok(receipt)
}

fn persist(
    site: state::Site,
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    args: &RunArgs,
    journal: &mut Journal,
) -> Result<Receipt, JailError> {
    let final_note = matches!(phase, Phase::Settled | Phase::Refused);
    persist_noted(site, attempt_dir, record, phase, args, journal, final_note)
}

/// [`persist`], with the priority of the receipt's trace note given.
fn persist_noted(
    site: state::Site,
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    args: &RunArgs,
    journal: &mut Journal,
    final_note: bool,
) -> Result<Receipt, JailError> {
    // J4 W2-S: (B) — a trace loss already known is in every receipt written
    // after it, not only in the one the settlement writes.
    if journal.loss.is_some() {
        degrade_trace_coverage(record, journal);
    }
    let io = state::current_io();
    let receipt = write_receipt_at(
        site,
        attempt_dir,
        record,
        phase,
        args.receipt.as_deref(),
        &*io,
    )?;
    journal.receipt(&receipt, final_note);
    Ok(receipt)
}

/// Finish the last note before publishing the control receipt. A loss during
/// that drain requires one durable correction, without another trace write
/// that could recursively fail and invalidate the correction.
fn persist_terminal(
    site: state::Site,
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    args: &RunArgs,
    journal: &mut Journal,
) -> Result<Receipt, JailError> {
    // J4 W2-S: (A) — the note of the attempt's final receipt is the one the
    // reserve exists for (§13.3), whatever its phase: an attempt that ends
    // unsettled keeps `enforced` or `prepared`, and its final note used to be
    // refused after a loss although the reserve had room.
    let receipt = persist_noted(site, attempt_dir, record, phase, args, journal, true)?;
    if let Ok(mut sink) = journal.trace.lock() {
        sink.finish();
    }
    if let Some(error) = journal.take_new_loss() {
        record.errors.push(error.to_object());
        degrade_trace_coverage(record, journal);
        let io = state::current_io();
        let corrected = write_receipt_at(
            site,
            attempt_dir,
            record,
            phase,
            args.receipt.as_deref(),
            &*io,
        )?;
        journal.durable(&corrected);
        return Ok(corrected);
    }
    Ok(receipt)
}

fn claim_attempt(
    attempt_dir: &AttemptDir,
    attempt_id: &AttemptId,
    ctx: &Context,
    test_seams: Option<&serde_json::Value>,
) -> Result<(), JailError> {
    let identity = ctx.platform.identity();
    let owner = ctx.platform.owner_identity();
    if identity.os == crate::records::Os::Linux && owner.is_none() {
        return Err(JailError::new(
            ErrorCode::StateWriteFailed,
            ErrorStage::Preparing,
            Remediation::InspectState,
            "the Linux supervisor birth identity could not be read".to_owned(),
        ));
    }
    let state = state::JailState {
        schema: state::Field::Set(state::SCHEMA_STATE.to_owned()),
        attempt_id: state::Field::Set(attempt_id.as_str().to_owned()),
        os: state::Field::Set(identity.os.as_str().to_owned()),
        arch: state::Field::Set(identity.arch),
        kernel: state::Field::Set(identity.kernel),
        component_version: state::Field::Set(env!("CARGO_PKG_VERSION").to_owned()),
        claimed_at: state::Field::Set(rfc3339_utc(SystemTime::now())),
        // §7: boot identity and the live owner's birth identity, so a
        // reconciler can tell this attempt's supervisor from a recycled pid
        // without parsing a receipt.
        owner: state::Field::or_null(owner.map(|owner| state::Owner {
            pid: owner.pid,
            boot_id: owner.boot_id,
            start_time_ticks: owner.start_time_ticks,
            rest: serde_json::Map::new(),
        })),
        boundary: state::Field::Null,
        // J4 W2-S: N7 — the execution leaf, registered by the platform before
        // it exists (`state::register_execution_leaf`).
        execution_cgroup: state::Field::Null,
        vendor_state: state::Field::Null,
        state_cleanup: state::Field::Set(StateCleanup::NotNeeded),
        // J4-R: S9 — a test seam in force is recorded where gc and a reader
        // of jail state see it, from the claim on.
        test_seams: test_seams
            .cloned()
            .map_or(state::Field::Absent, state::Field::Set),
        ..state::JailState::default()
    };
    let path = attempt_dir.state_path();
    // J4-R: §7, R02 — the claim is written and synced under a temporary name
    // and then linked into place, which fails when a claim exists. The link is
    // exclusive and atomic, so the claim is never visible, and never left by a
    // crash, with fewer than all its bytes (it used to be created empty and
    // then written, so every run had an unparseable claim for a moment).
    let bytes = state.to_bytes().map_err(|error| {
        JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the attempt claim could not be serialized: {error}"),
        )
    })?;
    match state::create_exclusively_at(state::Site::Claim, &path, &bytes)? {
        state::Published::Created => Ok(()),
        // A previous jail claim, live or dead, refuses rather than spawning
        // again.
        state::Published::Exists => Err(JailError::new(
            ErrorCode::AttemptExists,
            ErrorStage::Resolving,
            Remediation::InspectState,
            "this attempt directory already carries a jail claim".to_owned(),
        )),
    }
}

/// Record the registered execution boundary in the state file (§7), so crash
/// reconciliation and GC can identify the boundary without parsing a receipt.
fn register_boundary_in_state(
    attempt_dir: &AttemptDir,
    boundary: &crate::platform::BoundaryIdentity,
) -> Result<(), JailError> {
    state::update_attempt_state(state::Site::Boundary, attempt_dir, |state| {
        state.boundary = state::Field::Set(serde_json::json!({
            "kind": boundary.boundary.as_str(),
            "verification_scope": boundary.verification_scope.as_str(),
            "backend": boundary.backend,
            "backend_version": boundary.backend_version,
            "process": boundary.process,
        }));
    })
}

fn write_policy_file(attempt_dir: &AttemptDir, plan: &Plan) -> Result<(), JailError> {
    let snapshot = plan.resolved.snapshot.to_canonical_value()?;
    let envelope = serde_json::json!({
        "schema": SCHEMA_POLICY_FILE,
        "snapshot": snapshot,
        "policy_digest": plan.resolved.digest,
        "provenance": plan.resolved.provenance,
    });
    let bytes = cleanup::record_bytes("policy envelope", &envelope, ErrorStage::Preparing)?;
    state::replace_atomically_at(state::Site::Policy, &attempt_dir.policy_path(), &bytes)
}

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

/// Validates every supplied fd before preparation (§6.1).
fn validate_channels(args: &RunArgs) -> Result<(), JailError> {
    let supplied: Vec<(&str, RawFd)> = [
        ("--trace-fd", args.trace_fd),
        ("--control-fd", args.control_fd),
        ("--gate-fd", args.gate_fd),
    ]
    .into_iter()
    .filter_map(|(name, fd)| fd.map(|fd| (name, fd)))
    .collect();
    for (index, (name, fd)) in supplied.iter().enumerate() {
        if *fd <= 2 {
            return Err(invalid_fd(name, "must be distinct from stdio"));
        }
        if supplied[..index].iter().any(|(_, other)| other == fd) {
            return Err(invalid_fd(
                name,
                "is the same descriptor as another channel",
            ));
        }
        let access = fd_access(*fd).ok_or_else(|| invalid_fd(name, "is not open"))?;
        let wants_write = *name != "--gate-fd";
        let ok = if wants_write {
            access == libc::O_WRONLY || access == libc::O_RDWR
        } else {
            access == libc::O_RDONLY || access == libc::O_RDWR
        };
        if !ok {
            return Err(invalid_fd(
                name,
                if wants_write {
                    "is not open for writing"
                } else {
                    "is not open for reading"
                },
            ));
        }
    }
    Ok(())
}

fn invalid_fd(name: &str, message: &str) -> JailError {
    JailError::new(
        ErrorCode::InvalidFd,
        ErrorStage::Preparing,
        Remediation::Configuration,
        format!("{name} {message}"),
    )
    .with_key_path(name)
}

fn fd_access(fd: RawFd) -> Option<libc::c_int> {
    // SAFETY: `fcntl` with `F_GETFL` only reads the descriptor's flags. It
    // takes no pointer and writes nothing into this process.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return None;
    }
    Some(flags & libc::O_ACCMODE)
}

/// The control channel's own bounded, nonblocking writer (§8.2, §13.3).
///
/// The control channel had a blocking `write_all` on the raw descriptor. An
/// owner that stopped reading parked the supervisor inside `send_control`
/// while the child kept running, which is exactly what I07 forbids: "All
/// buffers, probes and waits have bounds; evidence pressure cannot prevent
/// deadline handling."
///
/// So control gets what the trace already had, with one addition §13.3 names:
/// capacity reserved for the terminal message, so a queue filled by `prepared`
/// and `exec_confirmed` still has room for `settled`, `unsettled` or
/// `refused`. Nothing here ever blocks; an undeliverable message is counted
/// and reported, never waited on.
pub struct ControlSink {
    file: std::fs::File,
    /// Whole frames not yet fully written, oldest first.
    frames: std::collections::VecDeque<Vec<u8>>,
    /// Bytes of the front frame already written.
    written: usize,
    /// The reader is gone (EPIPE, or any error but `WouldBlock`).
    broken: bool,
    dropped: u64,
    seq: u64,
}

/// Total control queue: four terminal frames' worth.
pub const CONTROL_QUEUE_MAX: usize = 4 * crate::records::CONTROL_FRAME_MAX;
/// Capacity inside that queue that only a terminal message may use.
pub const CONTROL_QUEUE_RESERVE: usize = crate::records::CONTROL_FRAME_MAX;
/// J4-R, N4: how long the final drain waits for a reader that makes no
/// progress, the same no-progress deadline §13.3 gives external trace writes.
pub const CONTROL_DRAIN: Duration = Duration::from_secs(1);

impl ControlSink {
    /// The next message number (§8.2: monotonically increasing per attempt).
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Bytes queued and not yet written.
    fn queued(&self) -> usize {
        self.frames.iter().map(Vec::len).sum::<usize>() - self.written
    }

    /// Queues one frame and drains what the descriptor will take right now.
    ///
    /// `terminal` messages may use the reserve. Returns whether the frame was
    /// accepted into the queue at all.
    fn send(&mut self, frame: &[u8], terminal: bool) -> bool {
        let budget = if terminal {
            CONTROL_QUEUE_MAX
        } else {
            CONTROL_QUEUE_MAX - CONTROL_QUEUE_RESERVE
        };
        if self.broken || self.queued() + frame.len() > budget {
            self.dropped += 1;
            return false;
        }
        self.frames.push_back(frame.to_vec());
        self.poll();
        true
    }

    /// Writes what fits without blocking, resuming a partly written frame at
    /// its offset. A full pipe leaves the rest queued. J4-R, N4: the
    /// supervision loop calls this every iteration, so a frame queued behind
    /// a full pipe goes out as soon as the reader makes room, not only when
    /// the next message happens to be sent.
    pub fn poll(&mut self) {
        while let Some(front) = self.frames.front() {
            if self.broken {
                return;
            }
            match self.file.write(&front[self.written..]) {
                Ok(0) => return,
                Ok(count) => {
                    self.written += count;
                    if self.written == front.len() {
                        self.frames.pop_front();
                        self.written = 0;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                // A broken pipe: the reader is gone and nothing queued can
                // reach it. The control channel is reporting, not an approval
                // protocol; the supervisor keeps going.
                Err(_) => self.broken = true,
            }
        }
    }

    /// J4-R, N4: the final drain. Keeps writing while the reader makes
    /// progress, gives up after `no_progress` without any, and counts every
    /// frame that never fully reached the descriptor (a partly written one
    /// included: the reader has a truncated frame, not a message) as dropped.
    /// Returns the total dropped. It never waits longer than `no_progress`
    /// past the reader's last progress.
    pub fn finish(&mut self, no_progress: Duration) -> u64 {
        let mut last_progress = Instant::now();
        let mut remaining = self.queued();
        loop {
            self.poll();
            if self.frames.is_empty() || self.broken {
                break;
            }
            let now_remaining = self.queued();
            if now_remaining < remaining {
                remaining = now_remaining;
                last_progress = Instant::now();
            } else if last_progress.elapsed() >= no_progress {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        self.dropped += self.frames.len() as u64;
        self.frames.clear();
        self.written = 0;
        self.dropped
    }

    /// Messages that never reached the descriptor.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

fn open_control(args: &RunArgs) -> Result<Option<ControlSink>, JailError> {
    let Some(fd) = args.control_fd else {
        return Ok(None);
    };
    // SAFETY: §6.1 requires the operator to hand this descriptor over
    // exclusively for the invocation, and `validate_channels` has established
    // that it is open for writing and distinct from every other channel.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    crate::trace::set_nonblocking(fd)?;
    Ok(Some(ControlSink {
        file,
        frames: std::collections::VecDeque::new(),
        written: 0,
        broken: false,
        dropped: 0,
        seq: 0,
    }))
}

fn open_trace(
    ctx: &Context,
    args: &RunArgs,
    attempt_dir: &AttemptDir,
) -> Result<SharedTrace, JailError> {
    if let Some(fd) = args.trace_fd {
        // J5-C, wave 3: the write-size test seam (S9), recorded like every
        // `OURO_JAIL_TEST_*` variable.
        let seam = std::env::var(trace::TRACE_FD_WRITE_SEAM).ok();
        // SAFETY: as for the control descriptor: exclusively owned for this
        // invocation and already validated as open for writing.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let sink = FdSink::for_attempt(fd, seam.as_deref())?;
        return Ok(trace::shared(sink));
    }
    let path = attempt_dir.trace_path();
    // §6.2: every file this tool writes under the state root is mode 0600, and
    // a pre-existing one is checked before it is reopened.
    state::check_state_file(&path)?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(state::FILE_MODE)
        .open(&path)
        .map_err(|error| {
            JailError::new(
                ErrorCode::StateWriteFailed,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("{}: {error}", path.display()),
            )
        })?;
    // S9 + issue draft 03: the environment inputs here are the operator's
    // trace budget and the shrink-only test seam; the sink names either in
    // every loss it records, so the receipt that reports the loss also
    // reports the override.
    let env_cap = ctx.env_settings.trace_cap.map(|cap| cap.to_string());
    Ok(trace::shared(FileSink::for_attempt(
        file,
        env_cap.as_deref(),
        std::env::var(trace::TRACE_CAP_SEAM).ok().as_deref(),
    )))
}

/// Publishes one control message (§8.2).
///
/// The message number comes from the sink, so it counts every message of the
/// attempt in order: it used to restart at 1 for a refusal, which made
/// `prepared` and `refused` indistinguishable from two separate attempts.
fn send_control(control: Option<&mut ControlSink>, kind: ControlKind, receipt: &Receipt) {
    let Some(control) = control else { return };
    // J4 W3, P6: the receipt's one name, the canonical digest its trace note
    // uses (§13.1). It used to be over the compact serialization, which only
    // a consumer with the writer's field order could reproduce. A receipt
    // with no canonical digest gets no message naming an invented one: the
    // message is counted as undelivered.
    let digest = match receipt_digest(receipt) {
        Ok(digest) => digest,
        Err(_) => {
            control.dropped += 1;
            return;
        }
    };
    // J4-R: the message states what the acknowledged receipt says, which
    // for a receipt persisted by the worker is not what the record says now.
    let message = ControlMessage {
        schema: crate::records::SCHEMA_CONTROL.to_owned(),
        attempt_id: receipt.attempt_id.clone(),
        seq: control.next_seq(),
        kind,
        receipt_phase: receipt.phase,
        receipt_digest: digest,
        outcome: receipt.outcome.clone(),
        error: receipt.outcome.error.clone(),
    };
    let terminal = matches!(
        kind,
        ControlKind::Refused | ControlKind::Settled | ControlKind::Unsettled
    );
    if let Ok(frame) = message.to_frame() {
        control.send(&frame, terminal);
    }
}

/// Waits for the owner's single release frame (§8.2).
///
/// `poll` on the gate descriptor and the signal self-pipe, with the remaining
/// budget as the timeout. Three defects are gone with the thread that used to
/// do this:
///
/// - the read is bounded. `read_to_end` had no limit, so an owner (or
///   `/dev/zero`) could push gigabytes through a channel whose maximum frame
///   is 1024 bytes; the cap was only consulted once the whole payload was in
///   memory.
/// - nothing is detached. The old reader thread outlived the refusal, holding
///   the descriptor until the process exited.
/// - a signal during the 60-second wait is handled. It used to kill the
///   supervisor with the default disposition, leaving a prepared receipt and a
///   blocked launcher behind.
///
/// # Errors
/// Returns [`ErrorCode::GateInvalid`], [`ErrorCode::GateClosed`],
/// [`ErrorCode::PrepareTimeout`], or [`ErrorCode::ExecFailed`]'s sibling for a
/// stop requested by a signal.
pub fn await_release(
    fd: RawFd,
    expected: &GateExpectation,
    budget: Duration,
    signals: Option<&signals::SignalPipe>,
) -> Result<(), JailError> {
    // SAFETY: §6.1 requires exclusive ownership of the gate descriptor for this
    // invocation, and `validate_channels` established that it is open for
    // reading and distinct from every other channel.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let deadline = ContinuousDeadline::after(budget);
    // One byte past the maximum, so an oversized frame is detected rather than
    // silently truncated into something that parses.
    let cap = crate::records::GATE_FRAME_MAX + 1;
    let mut payload: Vec<u8> = Vec::with_capacity(cap);

    loop {
        if let Some(pipe) = signals
            && pipe.triggered()
        {
            return Err(stopped_by_signal(ErrorStage::Prepared));
        }
        let remaining = deadline.remaining();
        if remaining.is_zero() {
            return Err(JailError::new(
                ErrorCode::PrepareTimeout,
                ErrorStage::Prepared,
                Remediation::Retry,
                format!(
                    "no release arrived within {} seconds of the prepared receipt",
                    budget.as_secs()
                ),
            ));
        }
        let signal_fd = signals.map(signals::SignalPipe::as_raw_fd);
        // A poll timeout runs on CLOCK_MONOTONIC, which stops during suspend:
        // bounded steps let an expiry be acted on soon after execution
        // resumes (§6.4).
        if !poll_readable(fd, signal_fd, remaining.min(GATE_POLL_STEP))? {
            continue;
        }
        let mut chunk = [0u8; 256];
        match std::io::Read::read(&mut file, &mut chunk) {
            Ok(0) => return crate::records::parse_release(&payload, expected).map(|_| ()),
            Ok(read) => {
                payload.extend_from_slice(&chunk[..read]);
                if payload.len() > cap {
                    payload.truncate(cap);
                    // The payload is already past the maximum; reading the rest
                    // of an unbounded writer would be the defect itself.
                    return crate::records::parse_release(&payload, expected).map(|_| ());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err(JailError::new(
                    ErrorCode::GateInvalid,
                    ErrorStage::Prepared,
                    Remediation::InspectState,
                    format!("the gate could not be read: {error}"),
                ));
            }
        }
    }
}

/// The refusal for an operator signal received before the target ran.
fn stopped_by_signal(stage: ErrorStage) -> JailError {
    JailError::new(
        ErrorCode::PrepareTimeout,
        stage,
        Remediation::Retry,
        "the supervisor was asked to stop before the target ran".to_owned(),
    )
}

/// Waits until `fd` (or the signal pipe) is readable, or `timeout` elapses.
///
/// Returns whether `fd` itself is readable; a signal wakeup returns `false` so
/// the caller re-checks its own conditions.
///
/// # Errors
/// Returns [`ErrorCode::GateInvalid`] when `poll` itself fails.
fn poll_readable(
    fd: RawFd,
    signal_fd: Option<RawFd>,
    timeout: Duration,
) -> Result<bool, JailError> {
    let mut fds = vec![libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    if let Some(signal_fd) = signal_fd {
        fds.push(libc::pollfd {
            fd: signal_fd,
            events: libc::POLLIN,
            revents: 0,
        });
    }
    let millis = i32::try_from(timeout.as_millis().min(1000)).unwrap_or(1000);
    // SAFETY: `poll` reads and writes the `pollfd` array it is given, which is
    // owned here and correctly sized by `fds.len()`. The descriptors are ones
    // this invocation owns.
    let ready = unsafe {
        libc::poll(
            fds.as_mut_ptr(),
            u32::try_from(fds.len()).unwrap_or(1) as libc::nfds_t,
            millis,
        )
    };
    if ready < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(JailError::new(
            ErrorCode::GateInvalid,
            ErrorStage::Prepared,
            Remediation::InspectState,
            format!("the gate could not be polled: {error}"),
        ));
    }
    if fds[0].revents & libc::POLLNVAL != 0 {
        // macOS reports `POLLNVAL` for a descriptor it cannot poll, such as a
        // character device. Spinning on that until the 60-second budget ran
        // out burned a core for a minute; saying so refuses in milliseconds.
        return Err(JailError::new(
            ErrorCode::InvalidFd,
            ErrorStage::Prepared,
            Remediation::Configuration,
            "the gate descriptor cannot be waited on; it must be a pipe".to_owned(),
        ));
    }
    // Any event on the gate itself means a read will not block. Only the
    // signal pipe firing returns false, so the caller re-checks its own
    // conditions and comes back.
    Ok(fds[0].revents != 0)
}

// ---------------------------------------------------------------------------
// Signals (§8.3)
// ---------------------------------------------------------------------------

/// The self-pipe that turns INT, TERM and HUP into a loop wakeup.
pub mod signals {
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
    use std::sync::atomic::{AtomicI32, Ordering};

    /// The write end the handler uses. `-1` means no handler is installed.
    static WRITE_FD: AtomicI32 = AtomicI32::new(-1);

    /// The read end of the self-pipe, owned by the supervisor loop.
    #[derive(Debug)]
    pub struct SignalPipe {
        read: std::fs::File,
    }

    /// Writes one byte into the self-pipe. Async-signal-safe: it allocates
    /// nothing, takes no lock and calls only `write`.
    extern "C" fn handler(_signal: libc::c_int) {
        let fd = WRITE_FD.load(Ordering::Relaxed);
        if fd < 0 {
            return;
        }
        let byte = b"x";
        // SAFETY: `write` is async-signal-safe. The descriptor is the pipe this
        // process created and never closes while a handler is installed, and
        // the buffer is a static one-byte slice.
        unsafe {
            libc::write(fd, byte.as_ptr().cast::<libc::c_void>(), 1);
        }
    }

    /// Installs handlers for INT, TERM and HUP.
    ///
    /// Returns `None` when the pipe or the handlers cannot be installed; the
    /// caller then runs without signal wakeups rather than failing the attempt,
    /// and the deadline path still works.
    #[must_use]
    pub fn install() -> Option<SignalPipe> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `pipe` fills the two-element array it is given and returns 0
        // on success. The array is correctly sized and lives across the call.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: both descriptors come from the successful `pipe` above and
        // are owned by this process from here on.
        let (read, write) = unsafe {
            (
                std::fs::File::from_raw_fd(fds[0]),
                std::fs::File::from_raw_fd(fds[1]),
            )
        };
        for file in [&read, &write] {
            // SAFETY: `fcntl` with `F_SETFL` only changes the flags of a
            // descriptor this process owns.
            unsafe {
                let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
                libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        WRITE_FD.store(write.as_raw_fd(), Ordering::SeqCst);
        // The write end must outlive every handler invocation, so it is leaked
        // deliberately: the process owns it until it exits.
        std::mem::forget(write);

        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // A signal the operator's environment ignores
            // (`nohup`, a background job of a non-interactive shell) stays
            // ignored: the supervisor honours it, and the ignored disposition
            // reaches the target across every exec. Catching it would reset
            // it to the default in every child.
            if super::signals_inherited_ignored(signal) {
                continue;
            }
            // SAFETY: `sigaction` is given a zeroed, fully initialized action
            // whose handler is an `extern "C"` function with the right
            // signature, and a null old-action pointer.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = handler as *const () as usize;
                libc::sigemptyset(&raw mut action.sa_mask);
                action.sa_flags = libc::SA_RESTART;
                if libc::sigaction(signal, &raw const action, std::ptr::null_mut()) != 0 {
                    return None;
                }
            }
        }
        Some(SignalPipe { read })
    }

    impl SignalPipe {
        /// The read end, for `poll` alongside another descriptor.
        #[must_use]
        pub fn as_raw_fd(&self) -> RawFd {
            self.read.as_raw_fd()
        }

        /// Whether a signal arrived since the last call. Drains the pipe.
        #[must_use]
        pub fn triggered(&self) -> bool {
            let mut buffer = [0u8; 64];
            let mut seen = false;
            let mut handle = &self.read;
            while let Ok(read) = handle.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                seen = true;
            }
            seen
        }
    }
}

/// Reads an environment variable as native bytes.
#[must_use]
pub fn env_bytes(name: &str) -> Option<Vec<u8>> {
    std::env::var_os(name).map(OsString::into_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::CoverageSummary;
    use crate::platform::RunEvent;
    use crate::records::{Os, Outcome};

    // Audit 2026-10-08 L22 (L04.4): the production deadline closure —
    // `ContinuousDeadline::remaining` over `elapsed_since_start_ns`, the
    // closure `stage_within` and the budgets are given in a real run —
    // expires on the continuous clock, and the budgets built on it refuse.
    #[test]
    fn the_production_deadline_closure_expires_and_the_budget_refuses() {
        let deadline = ContinuousDeadline::after(Duration::from_millis(50));
        let first = deadline.remaining();
        assert!(
            first > Duration::ZERO && first <= Duration::from_millis(50),
            "a fresh deadline has its budget left: {first:?}"
        );
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(
            deadline.remaining(),
            Duration::ZERO,
            "an expired deadline clamps at zero, it does not go negative"
        );
        let budget = Budget::new(Duration::from_millis(30));
        std::thread::sleep(Duration::from_millis(60));
        let error = budget
            .check(crate::records::ErrorStage::Preparing)
            .expect_err("a spent budget refuses");
        assert_eq!(error.code, ErrorCode::PrepareTimeout);
        assert_eq!(error.remediation, crate::records::Remediation::Retry);
    }

    #[test]
    // Audit 2026-10-08 L2: the storage enforcement loss is a coded error
    // whose message names the loss, distinguishable from observation-evidence
    // loss only by that name.
    fn a_storage_enforcement_loss_is_a_coded_error_naming_the_loss() {
        let error = storage_loss_error("tmpfs capacity changed after admission".to_owned());
        let object = error.to_object();
        assert_eq!(object.code, "evidence_lost");
        assert_eq!(object.stage, "running");
        assert!(
            object.message.starts_with("storage_enforcement_lost: "),
            "{}",
            object.message
        );
        assert!(
            object
                .message
                .contains("tmpfs capacity changed after admission")
        );
    }

    #[test]
    fn journal_detects_another_producers_loss_without_a_wrapper_write() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let trace = trace::shared(FileSink::with_bounds(file.reopen().unwrap(), 100, 40));
        let mut journal = Journal::new("att_test", trace.clone());
        // An audit producer exhausts the normal budget, without going through
        // Journal::emit. The supervisor must still see and report it once.
        assert!(
            trace
                .lock()
                .unwrap()
                .write_frame(&[b'x'; 100], Priority::Normal)
                .is_err()
        );
        assert!(journal.take_new_loss().is_some());
        assert!(journal.take_new_loss().is_none());
    }

    #[test]
    fn a_trusted_file_that_predates_the_uncontained_epoch_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let trusted = dir.path().join("config.toml");
        std::fs::write(&trusted, "[jail]\n").unwrap();
        // No markers yet: the file is trusted as before.
        let none = state::uncontained_epoch(&[dir.path()]).unwrap();
        assert!(refuse_stale_trusted_file(&trusted, &none, "config").is_ok());
        // A settled marker written after the file: the file could have come
        // from that run's child, so it refuses with the remediation.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(state::uncontained_settled_path(dir.path()), b"settled 0\n").unwrap();
        let epoch = state::uncontained_epoch(&[dir.path()]).unwrap();
        assert!(epoch.settled.is_some() && epoch.live.is_empty());
        let error = refuse_stale_trusted_file(&trusted, &epoch, "config").unwrap_err();
        assert_eq!(error.code, crate::records::ErrorCode::UnsafeConfigPath);
        assert!(error.message.contains("predates the last uncontained"));
        // A file the operator re-saves after the epoch is trusted again.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&trusted, "[jail]\n").unwrap();
        assert!(refuse_stale_trusted_file(&trusted, &epoch, "config").is_ok());
        // An absent file is none of this guard's business.
        assert!(
            refuse_stale_trusted_file(&dir.path().join("absent.toml"), &epoch, "config").is_ok()
        );
    }

    /// Audit 2026-10-08 mutation-B07 guard: the settled-marker comparison
    /// is `<=`, not `<`. A file whose ctime equals the settled marker's
    /// was written no later than the settle itself — the same clock, one
    /// tick — so it refuses exactly like one that predates it; only a
    /// strictly newer ctime is the operator's re-save and is trusted.
    #[test]
    fn a_trusted_file_with_the_settled_marker_s_ctime_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let trusted = dir.path().join("config.toml");
        std::fs::write(&trusted, "[jail]\n").unwrap();
        let metadata = std::fs::symlink_metadata(&trusted).unwrap();
        let changed = state::ctime_of(&metadata).expect("a readable ctime");
        let epoch = |settled| state::UncontainedEpoch {
            settled: Some(settled),
            live: Vec::new(),
        };
        let error = refuse_stale_trusted_file(&trusted, &epoch(changed), "config").unwrap_err();
        assert_eq!(error.code, crate::records::ErrorCode::UnsafeConfigPath);
        assert!(
            error.message.contains("predates the last uncontained"),
            "{error:?}"
        );
        let older = changed
            .checked_sub(std::time::Duration::from_nanos(1))
            .unwrap();
        assert!(
            refuse_stale_trusted_file(&trusted, &epoch(older), "config").is_ok(),
            "a ctime strictly after the settle is the operator's own re-save"
        );
    }

    /// Review of audit 6 F1: while an uncontained run is live — or ended
    /// without settling — no trusted file can be dated, however new, so a
    /// concurrent contained run refuses every one that exists; the markers
    /// are read from both directories, which are chosen independently.
    #[test]
    fn a_live_uncontained_run_in_either_marker_directory_refuses_every_trusted_file() {
        let data = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let trusted = config.path().join("config.toml");
        std::fs::write(&trusted, "[jail]\n").unwrap();
        for (live_in, other) in [(config.path(), data.path()), (data.path(), config.path())] {
            let live = live_in.join("uncontained.att_other.live");
            std::fs::write(&live, b"live\n").unwrap();
            // Re-saved after the marker, and still refused: a live run can
            // write at any moment.
            std::thread::sleep(std::time::Duration::from_millis(10));
            std::fs::write(&trusted, "[jail]\n").unwrap();
            let epoch = state::uncontained_epoch(&[other, live_in]).unwrap();
            assert_eq!(epoch.live, vec![live.clone()]);
            let error = refuse_stale_trusted_file(&trusted, &epoch, "config").unwrap_err();
            assert_eq!(error.code, crate::records::ErrorCode::UnsafeConfigPath);
            assert!(
                error.message.contains("is live or ended without settling"),
                "{error:?}"
            );
            // Absent trusted files still resolve: a contained run without
            // operator configuration is unaffected.
            assert!(
                refuse_stale_trusted_file(&config.path().join("absent.toml"), &epoch, "config")
                    .is_ok()
            );
            std::fs::remove_file(&live).unwrap();
        }
    }

    #[test]
    fn journal_detects_a_loss_that_only_appears_during_terminal_drain() {
        struct DrainFailure {
            loss: Option<trace::Loss>,
        }
        impl TraceSink for DrainFailure {
            fn write_frame(&mut self, _: &[u8], _: Priority) -> Result<(), JailError> {
                Ok(())
            }
            fn loss(&self) -> Option<&trace::Loss> {
                self.loss.as_ref()
            }
            fn finish(&mut self) {
                self.loss = Some(trace::Loss {
                    reason: "terminal drain stalled".to_owned(),
                    lost_frames: None,
                });
            }
        }
        let trace = trace::shared(DrainFailure { loss: None });
        let mut journal = Journal::new("att_test", trace.clone());
        assert!(journal.take_new_loss().is_none());
        trace.lock().unwrap().finish();
        assert!(journal.take_new_loss().is_some());
        assert!(journal.loss.is_some());
    }

    // Review item 15
    fn test_record(coverage: crate::records::Coverage) -> AttemptRecord {
        use crate::records::{
            AppliedNetwork, EvidenceMode, JailRecord, ObserveMode, PlatformRecord, PolicyRecord,
        };
        let now = SystemTime::now();
        AttemptRecord {
            attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
            revision: 1,
            platform: PlatformRecord {
                os: Os::Linux,
                arch: "x86_64".to_owned(),
                kernel: "test".to_owned(),
            },
            jail: JailRecord {
                component: "ouro-jail".to_owned(),
                version: "0.0.0".to_owned(),
                backend: None,
                backend_version: None,
            },
            policy: PolicyRecord {
                name: "tool".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
                observe: ObserveMode::On,
                evidence: EvidenceMode::BestEffort,
                requirements: Vec::new(),
                grants: Vec::new(),
            },
            containment: crate::records::Containment::Enforced,
            exec_observed: true,
            argv_digest: None,
            applied: crate::records::Applied {
                filesystem: None,
                network: AppliedNetwork {
                    mode: "none".to_owned(),
                    mechanism: None,
                    allowed_hosts: Vec::new(),
                    tls_only: Vec::new(),
                },
                syscalls: None,
                limits: Vec::new(),
                environment_names: Vec::new(),
                removed_environment_names: Vec::new(),
            },
            observer: crate::observer::CoverageSummary::unobserved().to_observer_record(),
            coverage,
            process: None,
            lifetime: crate::records::Lifetime::pending(),
            outcome: Outcome::pending(),
            state_cleanup: StateCleanup::NotNeeded,
            cleanup_error: None,
            created_at: now,
            updated_at: now,
            errors: Vec::new(),
            credentials: Vec::new(),
        }
    }

    /// A prior receipt copy is replaceable only within the receipt bound
    /// every other reader holds receipts to, and only as a regular file.
    #[test]
    fn a_prior_receipt_copy_is_held_to_the_receipt_bound() {
        let dir = tempfile::tempdir().unwrap();
        let receipt = |pad: usize| {
            serde_json::to_vec(&serde_json::json!({
                "schema": crate::records::SCHEMA_RECEIPT,
                "pad": "x".repeat(pad),
            }))
            .unwrap()
        };
        let small = dir.path().join("small.json");
        std::fs::write(&small, receipt(16)).unwrap();
        assert!(prior_receipt_copy(&small));
        let large = dir.path().join("large.json");
        std::fs::write(
            &large,
            receipt(usize::try_from(cleanup::RECEIPT_MAX).unwrap()),
        )
        .unwrap();
        assert!(!prior_receipt_copy(&large), "past the receipt bound");
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&small, &link).unwrap();
        assert!(!prior_receipt_copy(&link), "a link is not a copy");
        let foreign = dir.path().join("foreign.json");
        std::fs::write(&foreign, b"{\"schema\":\"something.else/1\"}").unwrap();
        assert!(!prior_receipt_copy(&foreign));
    }

    /// A receipt past the bound every reader holds receipts to is refused
    /// before anything is written, and spends no revision: on disk it would
    /// be a receipt that neither `gc` nor cleanup could read.
    #[test]
    fn a_receipt_past_the_reader_bound_is_never_written() {
        let (_root, attempt_dir, _plan) = scratch_fixture();
        let mut record = test_record(CoverageSummary::unobserved().to_coverage());
        let bound = usize::try_from(cleanup::RECEIPT_MAX).unwrap();
        record.errors.push(
            JailError::new(
                ErrorCode::EvidenceLost,
                ErrorStage::Running,
                Remediation::InspectState,
                "x".repeat(bound),
            )
            .to_object(),
        );
        let error = write_receipt(&attempt_dir, &mut record, Phase::Settled, None)
            .expect_err("past the bound");
        assert_eq!(error.code, ErrorCode::StateWriteFailed);
        assert!(error.message.contains("bound"), "{}", error.message);
        assert_eq!(record.revision, 1, "no revision is spent");
        assert!(!attempt_dir.receipt_path().exists());
        record.errors.clear();
        write_receipt(&attempt_dir, &mut record, Phase::Settled, None).expect("within the bound");
        assert_eq!(record.revision, 2);
    }

    /// An unsatisfied requirement refuses with the code, remediation and
    /// message its capability's reason calls for (§13.2, §3.2).
    #[test]
    fn an_unsatisfied_requirement_refuses_by_its_reason() {
        use crate::capability::{CapabilityScope, CapabilityStatus};
        let capability = |status, reason: Option<&str>| Capability {
            name: "tree_termination".to_owned(),
            status,
            scope: CapabilityScope::Tree,
            mechanism: None,
            reason_code: reason.map(str::to_owned),
            measured_at: None,
            evidence_ref: None,
        };
        let requirements = ["tree_termination".to_owned()];
        let refusal = |capabilities: &[Capability]| {
            let error = first_unsatisfied(&requirements, capabilities).expect("a refusal");
            (error.code, error.remediation, error.message)
        };
        let (code, remediation, message) = refusal(&[capability(
            CapabilityStatus::Unsupported,
            Some(crate::platform::REASON_UNSUPPORTED_PLATFORM),
        )]);
        assert_eq!(
            (code, remediation),
            (ErrorCode::UnsupportedPlatform, Remediation::Unsupported)
        );
        assert_eq!(message, "execution is not implemented for this platform");
        let (code, remediation, message) = refusal(&[capability(
            CapabilityStatus::Unsupported,
            Some(crate::capability::REASON_NOT_APPLIED_BY_NONE),
        )]);
        assert_eq!(
            (code, remediation),
            (ErrorCode::MissingCapability, Remediation::Configuration)
        );
        assert!(
            message.contains("uncontained profile cannot apply"),
            "{message}"
        );
        let (code, remediation, message) =
            refusal(&[capability(CapabilityStatus::Unavailable, Some("no_cgroup"))]);
        assert_eq!(
            (code, remediation),
            (ErrorCode::MissingCapability, Remediation::HostSetup)
        );
        assert!(message.ends_with("(no_cgroup)"), "{message}");
        let (_, _, message) = refusal(&[]);
        assert!(message.ends_with("(not_measured)"), "{message}");
        assert!(
            first_unsatisfied(
                &requirements,
                &[capability(CapabilityStatus::Available, None)]
            )
            .is_none()
        );
    }

    /// SUP-10: a stop records the cause of the very reason it sends, a
    /// persistence failure stops for `state_write_failed`, and the first
    /// stop's cause is the one that stays (J4-D5).
    #[test]
    fn a_stop_records_the_cause_of_the_reason_it_sends_and_the_first_wins() {
        struct Stops(Vec<StopReason>);
        impl crate::platform::RunningExecution for Stops {
            fn wait(&mut self, _: crate::platform::Deadline) -> RunEvent {
                RunEvent::Poll
            }
            fn request_stop(&mut self, reason: StopReason) {
                self.0.push(reason);
            }
            fn wait_tree(&mut self, _: Duration) -> crate::platform::TreeObservation {
                unreachable!("no tree is waited for")
            }
            fn observer_summary(&mut self) -> Option<CoverageSummary> {
                None
            }
        }
        let mut running = Stops(Vec::new());
        let mut record = test_record(CoverageSummary::unobserved().to_coverage());
        let mut outcome_error = None;
        let failure = JailError::new(
            ErrorCode::StateWriteFailed,
            ErrorStage::Running,
            Remediation::InspectState,
            "stalled".to_owned(),
        );
        persistence_failed(&mut running, &mut record, &mut outcome_error, failure);
        stop(&mut running, &mut record, StopReason::WallExpiry);
        assert_eq!(
            running.0,
            [StopReason::StateWriteFailed, StopReason::WallExpiry]
        );
        assert_eq!(record.outcome.cause.as_deref(), Some("state_write_failed"));
        assert_eq!(record.errors.len(), 1);
        for (reason, cause) in [
            (StopReason::CommandForbidden, "command_forbidden"),
            (StopReason::OperatorSignal, "operator_signal"),
            (StopReason::WallExpiry, "wall_expiry"),
            (StopReason::EvidenceLoss, "evidence_loss"),
            (StopReason::StateWriteFailed, "state_write_failed"),
            (StopReason::StdioFailure, "stdio_failure"),
        ] {
            let mut record = test_record(CoverageSummary::unobserved().to_coverage());
            stop(&mut running, &mut record, reason);
            assert_eq!(record.outcome.cause.as_deref(), Some(cause), "{reason:?}");
        }
    }

    /// A receipt records a trace loss as the stream's note does: on each
    /// covered evidence class, from the note's start, as a wrapper loss.
    #[test]
    fn a_receipt_records_the_trace_loss_with_the_notes_start_and_source() {
        use crate::records::{CoverageEntry, SourceStatus};
        let file = tempfile::NamedTempFile::new().unwrap();
        let trace = trace::shared(FileSink::with_bounds(file.reopen().unwrap(), 2000, 800));
        trace
            .lock()
            .unwrap()
            .set_stream_classes(&CoverageClass::AUDIT);
        let mut journal = Journal::new("att_test", trace.clone());
        let note = |transition: &str| {
            crate::records::Event::lifecycle_note("att_test", 0, SystemTime::now(), 0, transition)
        };
        // One delivered frame, so the last healthy point is after the start,
        // then an event past the 1200-byte payload budget: the first loss.
        // The elapsed clock starts at its first read (the fallback clock, and
        // the supervisor mark); read it before the sleep, or a test that runs
        // first in its process would deliver that frame at elapsed zero.
        let _ = crate::platform::elapsed_since_start_ns();
        std::thread::sleep(Duration::from_millis(2));
        trace
            .lock()
            .unwrap()
            .write_event(&note("prepared"), Priority::Normal)
            .expect("within the budget");
        assert!(
            trace
                .lock()
                .unwrap()
                .write_event(&note(&"x".repeat(1500)), Priority::Normal)
                .is_err()
        );
        assert!(journal.take_new_loss().is_some());
        let start = trace.lock().unwrap().loss_start_ns().expect("a loss start");
        assert!(start > 0, "the loss starts at the last delivered frame");
        let active = || CoverageEntry {
            status: SourceStatus::Active,
            sources: vec!["audit".to_owned()],
            observed_count: Some(0),
            gaps: Vec::new(),
            resolver_refused: None,
        };
        let mut coverage = crate::observer::CoverageSummary::unobserved().to_coverage();
        coverage.exec = active();
        coverage.fs_write = active();
        coverage.fs_deny = active();
        coverage.net = active();
        let mut record = test_record(coverage);
        degrade_trace_coverage(&mut record, &journal);
        for entry in [
            &record.coverage.exec,
            &record.coverage.fs_write,
            &record.coverage.fs_deny,
            &record.coverage.net,
        ] {
            assert_eq!(entry.status, SourceStatus::Degraded);
            let gap = &entry.gaps[0];
            assert_eq!(gap.source, "wrapper", "{gap:?}");
            assert_eq!(gap.start_ns, start.to_string(), "{gap:?}");
        }
        assert!(record.coverage.proxy_net.gaps.is_empty());
    }

    #[test]
    fn the_gate_and_preparation_budgets_are_the_ones_the_specification_names() {
        assert_eq!(GATE_WAIT, Duration::from_secs(60));
        assert_eq!(PREPARE_BUDGET, Duration::from_secs(30));
        assert_eq!(TREE_BUDGET, Duration::from_secs(5));
    }

    #[test]
    fn a_none_profile_receipt_is_unprotected_before_anything_is_applied() {
        let applied = pending_applied(&Plan {
            resolved: minimal_resolved(ProfileName::None),
            workspace: PathBuf::from("/work"),
            config_dir: PathBuf::from("/config"),
            data_dir: PathBuf::from("/data"),
        });
        assert_eq!(applied.network.mode, "host");
        assert!(applied.filesystem.is_none());
        assert!(applied.syscalls.is_none());
    }

    // Security 2026-09-27 (audit 3 A2): the launch directory is operator
    // authority to isolate, on every run.
    #[test]
    fn check_launch_isolation_refuses_a_workspace_over_the_launch_directory() {
        let root = tempfile::tempdir().unwrap();
        let config_dir = root.path().join("config");
        let launch = launch_profile::launch_directory(&config_dir);
        std::fs::create_dir_all(&launch).unwrap();
        let plan = |workspace: PathBuf| Plan {
            resolved: minimal_resolved(ProfileName::Tool),
            workspace,
            config_dir: config_dir.clone(),
            data_dir: root.path().join("data"),
        };
        // A workspace that covers the launch directory refuses, naming the
        // config directory the launch directory hangs off.
        let check = |plan: Plan| check_launch_isolation(&plan, &ChildRoots::of(&plan));
        let error = check(plan(root.path().to_path_buf())).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsafeConfigPath);
        assert_eq!(error.key_path.as_deref(), Some("OURO_CONFIG_DIR"));
        assert!(
            error.message.contains("launch directory"),
            "the refusal names the launch directory: {}",
            error.message
        );
        // A disjoint workspace passes.
        check(plan(root.path().join("elsewhere"))).expect("a disjoint workspace passes");
    }

    // Security 2026-09-27 (audit 4 B1): the config directory is operator
    // authority to isolate, on every run, and the operator config it holds
    // is read no-follow, bounded and identity-checked.
    #[test]
    fn audit4_check_config_isolation_refuses_a_workspace_over_the_config_directory() {
        let root = tempfile::tempdir().unwrap();
        let config_dir = root.path().join("config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let plan = |workspace: PathBuf| Plan {
            resolved: minimal_resolved(ProfileName::Tool),
            workspace,
            config_dir: config_dir.clone(),
            data_dir: root.path().join("data"),
        };
        // A workspace that covers the config directory refuses.
        let check = |plan: Plan| check_config_isolation(&plan, &ChildRoots::of(&plan));
        let error = check(plan(root.path().to_path_buf())).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsafeConfigPath);
        assert_eq!(error.key_path.as_deref(), Some("OURO_CONFIG_DIR"));
        assert!(
            error.message.contains("config directory"),
            "the refusal names the config directory: {}",
            error.message
        );
        // A disjoint workspace passes.
        check(plan(root.path().join("elsewhere"))).expect("a disjoint workspace passes");
    }

    #[test]
    fn audit4_the_operator_config_read_refuses_planted_shapes() {
        let root = tempfile::tempdir().unwrap();
        let key = "config";
        // A symlink is refused, not followed.
        let real = root.path().join("real.toml");
        std::fs::write(&real, b"[jail]\n").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let error = read_operator_file(&link, key).unwrap_err();
        assert!(
            error.message.contains("Too many levels of symbolic links")
                || error.message.contains("symlink"),
            "a symlink refuses: {}",
            error.message
        );
        // Group-writable is refused.
        use std::os::unix::fs::PermissionsExt as _;
        let wide = root.path().join("wide.toml");
        std::fs::write(&wide, b"[jail]\n").unwrap();
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o666)).unwrap();
        let error = read_operator_file(&wide, key).unwrap_err();
        assert!(
            error.message.contains("writable by group or others"),
            "group-writable refuses: {}",
            error.message
        );
        // A second hard link is refused.
        let single = root.path().join("single.toml");
        std::fs::write(&single, b"[jail]\n").unwrap();
        std::fs::set_permissions(&single, std::fs::Permissions::from_mode(0o600)).unwrap();
        let twin = root.path().join("twin.toml");
        std::fs::hard_link(&single, &twin).unwrap();
        let error = read_operator_file(&twin, key).unwrap_err();
        assert!(
            error.message.contains("more than one hard link"),
            "a hard link refuses: {}",
            error.message
        );
        // An honest private file reads, and so does a world-readable one:
        // §6.2 forbids writes by others, not reads.
        let honest = root.path().join("honest.toml");
        std::fs::write(&honest, b"[jail]\n").unwrap();
        for mode in [0o600, 0o644] {
            std::fs::set_permissions(&honest, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                read_operator_file(&honest, key).unwrap().as_deref(),
                Some("[jail]\n"),
                "mode {mode:o}"
            );
        }
        // Group write is refused too, private group or not.
        std::fs::set_permissions(&honest, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(read_operator_file(&honest, key).is_err());
        // A directory, and a file over the bound, refuse before any byte.
        assert!(read_operator_file(root.path(), key).is_err());
        let big = root.path().join("big.toml");
        std::fs::write(
            &big,
            vec![b'#'; usize::try_from(OPERATOR_FILE_MAX).unwrap() + 1],
        )
        .unwrap();
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = read_operator_file(&big, key).unwrap_err();
        assert!(
            error.message.contains("the maximum is"),
            "{}",
            error.message
        );
        // Absence stays absence.
        assert!(
            read_operator_file(&root.path().join("absent.toml"), key)
                .unwrap()
                .is_none()
        );
    }

    /// A claimed-shape attempt directory under a private state root, and a
    /// `tool` plan with managed scratch.
    fn scratch_fixture() -> (tempfile::TempDir, AttemptDir, Plan) {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let data = root.path().canonicalize().unwrap().join("data");
        let attempt_dir = AttemptDir::new(&data, &AttemptId::generate());
        attempt_dir.create(&data).unwrap();
        let plan = Plan {
            resolved: minimal_resolved(ProfileName::Tool),
            workspace: root.path().join("workspace"),
            config_dir: root.path().join("config"),
            data_dir: data,
        };
        (root, attempt_dir, plan)
    }

    /// I07 and §14.2: managed scratch is removed by the bounded, anchored
    /// traversal, which takes the read-only directories a child leaves
    /// (an unbounded `remove_dir_all` stops at them and leaves `pending`).
    #[test]
    fn settlement_removes_a_child_made_read_only_scratch_tree() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_root, attempt_dir, plan) = scratch_fixture();
        let locked = attempt_dir.root().join("scratch/a/b");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("kept"), b"child bytes").unwrap();
        std::fs::create_dir(attempt_dir.placeholders_path()).unwrap();
        for dir in [&locked, &attempt_dir.root().join("scratch/a")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        assert_eq!(
            remove_managed_scratch(&attempt_dir, &plan, cleanup::Limits::DEFAULT),
            Ok(StateCleanup::Complete)
        );
        assert!(!attempt_dir.scratch_path().exists());
        assert!(!attempt_dir.placeholders_path().exists());
        // Nothing left: nothing to do, and nothing claimed as done.
        assert_eq!(
            remove_managed_scratch(&attempt_dir, &plan, cleanup::Limits::DEFAULT),
            Ok(StateCleanup::NotNeeded)
        );
    }

    /// A tree past the pass bound stops with its reason and is retained for
    /// `gc`, rather than holding the supervisor for as long as it takes.
    #[test]
    fn settlement_stops_at_the_removal_bound_and_says_why() {
        let (_root, attempt_dir, plan) = scratch_fixture();
        let scratch = attempt_dir.scratch_path();
        std::fs::create_dir(&scratch).unwrap();
        for index in 0..32 {
            std::fs::write(scratch.join(format!("f{index}")), b"x").unwrap();
        }
        let limits = cleanup::Limits {
            max_entries: 8,
            max_depth: cleanup::DEFAULT_MAX_DEPTH,
        };
        let reason = remove_managed_scratch(&attempt_dir, &plan, limits)
            .expect_err("a tree past the bound is not removed in one pass");
        assert!(
            reason.starts_with("scratch_removal_failed: ")
                && reason.contains(cleanup::REASON_BUDGET),
            "{reason}"
        );
        assert!(scratch.exists(), "the stopped tree is retained for gc");
    }

    /// A platform that only names itself: resolution asks nothing else.
    struct LinuxIdentity;

    impl Platform for LinuxIdentity {
        fn identity(&self) -> crate::platform::PlatformIdentity {
            crate::platform::PlatformIdentity {
                os: Os::Linux,
                arch: "x86_64".to_owned(),
                kernel: "test".to_owned(),
            }
        }

        fn probe(&self, _: &PlanRequest) -> Vec<Capability> {
            Vec::new()
        }

        fn prepare(
            &self,
            _: crate::platform::PreparedPlan,
            _: crate::platform::Sinks,
        ) -> Result<Box<dyn crate::platform::PreparedExecution>, JailError> {
            unreachable!("resolution prepares nothing")
        }
    }

    /// POL-3: the operator's command rules and `learn`'s read capture change
    /// the snapshot after resolution; the digest is the changed snapshot's
    /// and the provenance says what changed it.
    #[test]
    fn post_resolution_changes_are_digested_and_say_why() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let config = root.join("config");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let config_toml = config.join("config.toml");
        std::fs::write(
            &config_toml,
            "[jail.commands]\ndeny = [\"git push --force\"]\n",
        )
        .unwrap();
        std::fs::set_permissions(&config_toml, std::fs::Permissions::from_mode(0o600)).unwrap();
        let ctx = Context {
            platform: Box::new(LinuxIdentity),
            env_settings: EnvSettings {
                config_dir: Some(config),
                data_dir: Some(root.join("data")),
                ..EnvSettings::default()
            },
            cwd: workspace.clone(),
            home: None,
            env_lookup: Box::new(|_| None),
        };
        let args = PolicyArgs {
            selection: crate::cli::Selection {
                workspace: Some(workspace),
                ..crate::cli::Selection::default()
            },
            ..PolicyArgs::default()
        };
        let plan = resolve_learning_plan(&ctx, &args).unwrap();
        let resolved = &plan.resolved;
        assert!(resolved.snapshot.observation.learning);
        assert_eq!(resolved.snapshot.commands.deny, ["git push --force"]);
        assert_eq!(resolved.digest, resolved.snapshot.digest().unwrap());
        assert_eq!(
            resolved.requirements,
            crate::capability::requirements(&resolved.snapshot)
        );
        let said = |origin: &str, key: &str| {
            resolved
                .provenance
                .iter()
                .any(|entry| entry.origin == origin && entry.key == key)
        };
        assert!(
            said("operator-config:config.toml", "jail.commands"),
            "{:?}",
            resolved.provenance
        );
        assert!(
            said("cli", "observation.learning"),
            "{:?}",
            resolved.provenance
        );
        let plain = resolve_plan(&ctx, &args).unwrap();
        assert_ne!(
            plain.resolved.digest, resolved.digest,
            "learning is part of the digest"
        );
    }

    fn minimal_resolved(profile: ProfileName) -> Resolved {
        let baseline = profiles::baseline(profile, Os::Macos, &|_| None);
        let inputs = ResolveInputs {
            platform: Os::Macos,
            base_profile: profile,
            policy_name: profile.as_str().to_owned(),
            baseline,
            workspace: b"/work".to_vec(),
            scratch: ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        };
        policy::resolve(&inputs).expect("resolves")
    }
}
