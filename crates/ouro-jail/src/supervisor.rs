//! The portable supervisor: resolution, probing, the gate and the lifecycle.
//!
//! Implements jail-v1 §8.1 (preparation steps and the state machine), §8.2
//! (managed gate and control output) and the refusal tuples of §13.2 over the
//! [`Platform`](crate::platform::Platform) seam. It contains no Linux code: the
//! Linux slice supplies a platform and this file keeps owning every lifecycle
//! transition, every receipt and every budget.
//!
//! I01 is the shape of this file: nothing reaches `release` until resolution,
//! state, probing, preparation and the gate have all succeeded, and every early
//! exit goes through [`refuse`], which writes a `refused` receipt.

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
use crate::cli::{DoctorArgs, ExplainArgs, GcArgs, PolicyArgs, RunArgs};
use crate::config::{self, EnvSettings};
use crate::network::NetworkMode;
use crate::observer::CoverageSummary;
use crate::platform::{
    BoundaryIdentity, PlanRequest, Platform, PreparedPlan, RunEvent, Sinks, StopReason, Teardown,
};
use crate::policy::{
    self, Layer, LayerOrigin, LimitKey, PolicyDelta, ProfileName, ResolveInputs, Resolved,
    ScratchRoot,
};
use crate::profiles;
// J3-launch begin: launch profiles, staging and cleanup
use crate::launch_profile;
use crate::records::StateCleanup;
// J3-launch end
use crate::records::{
    Applied, AppliedLimit, AppliedNetwork, AttemptRecord, Containment, ControlKind, ControlMessage,
    ErrorCode, ErrorStage, GateExpectation, JailError, JailRecord, Lifetime, Outcome, OutcomeKind,
    Phase, PlatformRecord, PolicyRecord, Receipt, Remediation, SCHEMA_POLICY_FILE, rfc3339_utc,
};
use crate::state::{self, AttemptDir, AttemptId};
use crate::trace::{self, FdSink, FileSink, Priority, SharedTrace, TraceSink};

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

/// Everything the supervisor needs from its process environment.
pub struct Context {
    /// The platform this build targets.
    pub platform: Box<dyn Platform>,
    /// The four allowed environment settings.
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
    // J3-launch begin: `doctor --launch` (§14.1)
    /// The launch profile's own readiness, when `--launch` was given.
    pub launch: Option<LaunchReadiness>,
    // J3-launch end
}

// J3-launch begin: `doctor --launch` (§14.1)
/// What `doctor --launch NAME` established about a launch profile.
///
/// §14.1: "Launch profile credential existence/type/permissions without
/// printing values or user-specific paths; experimental/supported status
/// separately." Each credential is named by the profile's own id, mode and
/// destination; the support status is reported apart from the host probes.
pub struct LaunchReadiness {
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
// J3-launch end

/// What `gc` found.
pub struct GcReport {
    /// One entry per attempt directory considered.
    pub entries: Vec<GcEntry>,
    /// Whether this was a dry run.
    pub dry_run: bool,
    // J3-launch begin: cleanups that did not complete (§6.4: exit 1)
    /// Attempts whose vendor-state cleanup ran and stopped again, with the
    /// reason; non-empty means `gc` exits 1 after printing its report.
    pub incomplete: Vec<String>,
    // J3-launch end
}

/// One attempt `gc` looked at.
pub struct GcEntry {
    /// The attempt id, when the directory name is a valid one.
    pub attempt_id: String,
    /// What `gc` did, or `skipped`.
    pub action: String,
    /// Why.
    pub reason: String,
    // J3-agent begin: the attempt's proxy directory (§10, §14.2)
    /// What became of a crashed or settled attempt's proxy directory:
    /// `removed`, `would_remove`, `retained: <reason>`, `failed: <reason>`,
    /// or `None` when there was none to act on.
    pub proxy_dir: Option<String>,
    // J3-agent end
}

// ---------------------------------------------------------------------------
// Resolution shared by run, explain, doctor and label-only
// ---------------------------------------------------------------------------

/// The resolved policy plus the context needed to prepare it.
pub struct Plan {
    /// The resolved policy, digest, provenance and requirements.
    pub resolved: Resolved,
    /// The base built-in profile.
    pub profile: ProfileName,
    /// The absolute workspace.
    pub workspace: PathBuf,
    /// The configuration directory in use.
    pub config_dir: PathBuf,
    /// The state directory in use.
    pub data_dir: PathBuf,
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
    let config_dir = state::config_dir(&ctx.env_settings, ctx.home.as_deref())?;
    // J3-launch begin: §6.2 step 2 — the operator launch profile, read once
    // through a no-follow walk; its content is what the snapshot records.
    let launch = match &args.launch {
        Some(name) => Some(launch_profile::load(
            &config_dir,
            name,
            ctx.home.as_deref(),
        )?),
        None => None,
    };
    // J3-launch end
    let data_dir = state::data_dir(&ctx.env_settings, ctx.home.as_deref())?;
    let workspace = canonical_root(&ctx.cwd, args.workspace.as_deref(), "--workspace")?;
    if !workspace.is_dir() {
        return Err(usage(
            "--workspace",
            format!("{} is not a directory", workspace.display()),
        ));
    }

    // 1. Operator config, then the selected profile.
    let config_path = config_dir.join("config.toml");
    let operator = match read_operator_file(&config_path, "config")? {
        Some(text) => config::parse_operator_config(&text)?,
        None => config::OperatorConfig::default(),
    };
    let operator_jail = operator.jail.clone().unwrap_or_default();
    config::check_schema("jail.schema", operator_jail.schema.as_deref())?;
    if operator_jail.extends.is_some() {
        return Err(usage(
            "jail.extends",
            "`extends` belongs in a profile file, not in config.toml",
        ));
    }

    // §6.1: `--profile none` is the only way to select `none`; files and
    // environment cannot select it. `config.toml` is a defaults file, so a
    // `none` written there would drop the operator onto the uncontained
    // profile without the explicit act the clause demands, and it refuses
    // instead — the same rule the profile-file `extends = "none"` refusal
    // below applies.
    let selection = match (args.profile.as_deref(), operator_jail.profile.as_deref()) {
        (Some(cli), _) => cli.to_owned(),
        (None, Some("none")) => {
            return Err(JailError::new(
                ErrorCode::PolicyWidening,
                ErrorStage::Resolving,
                Remediation::Configuration,
                "config.toml may not select the `none` profile; pass `--profile none` explicitly"
                    .to_owned(),
            )
            .with_key_path("jail.profile"));
        }
        (None, Some(configured)) => configured.to_owned(),
        // J3-launch begin: §6.1 "Default profile: `tool`, or the launch
        // profile's `jail` when `--launch` is set." Precedence: `--profile`,
        // then the operator's configured profile, then the launch default,
        // then `tool`; a configured profile that disagrees with the launch
        // default refuses below instead of being replaced (J3 review M3).
        (None, None) => launch.as_ref().map_or_else(
            || "tool".to_owned(),
            |launch| launch.jail.as_str().to_owned(),
        ),
        // J3-launch end
    };

    let mut layers: Vec<Layer> = Vec::new();
    let (profile, policy_name) = match ProfileName::parse(&selection) {
        Some(profile) => (profile, selection.clone()),
        None => {
            let path = if args.profile.is_some() {
                absolutize(&ctx.cwd, Path::new(&selection))
            } else if let Some(suffix) = selection.strip_prefix("~/") {
                ctx.home
                    .as_ref()
                    .ok_or_else(|| usage("jail.profile", "operator home is unavailable"))?
                    .join(suffix)
            } else {
                absolutize(&config_dir, Path::new(&selection))
            };
            let text = std::fs::read_to_string(&path)
                .map_err(|error| usage("--profile", format!("{}: {error}", path.display())))?;
            let file = config::parse_policy_file(&text)?;
            let base = ProfileName::parse(&file.extends).ok_or_else(|| {
                usage(
                    "extends",
                    format!("`{}` is not a built-in profile", file.extends),
                )
            })?;
            if base == ProfileName::None {
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
            let base_dir = path.parent().map(os_bytes);
            let name = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_else(|| "profile".to_owned());
            layers.push(Layer {
                origin: LayerOrigin::OperatorProfileFile(name.clone()),
                base_dir,
                key_prefix: String::new(),
                narrowing: true,
                delta,
            });
            (base, name)
        }
    };
    // J3-launch begin: §6.1 — the selected base must permit the launch
    // profile's credentials and network, and `none` never runs one. A
    // configured profile is never silently replaced by a launch default, and
    // never silently replaces one either: when they name different bases the
    // operator chooses with `--profile`.
    if let Some(launch) = &launch {
        if args.profile.is_none()
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
        launch_profile::check_jail_permits(profile, launch)?;
    }
    // J3-launch end

    // The operator's own `[jail]` table is a trusted layer: it may grant.
    if operator.jail.is_some() {
        let delta = config::delta_from_sections(
            "jail.",
            &operator_jail.filesystem,
            &operator_jail.network,
            &operator_jail.limits,
            &operator_jail.observation,
        )?;
        layers.push(Layer {
            origin: LayerOrigin::OperatorConfig("config.toml".to_owned()),
            // §6.2: apply paths relative to the file containing them, and
            // `config.toml` sits in `config_dir` itself — not its parent.
            base_dir: Some(os_bytes(&config_dir)),
            key_prefix: "jail.".to_owned(),
            narrowing: false,
            delta,
        });
    }

    // J3-launch begin: 2. The launch profile's allowed hosts, an operator
    // grant, before the environment, CLI and project layers.
    if let Some(layer) = launch.as_ref().and_then(launch_profile::network_layer) {
        layers.push(layer);
    }
    // J3-launch end

    // 3. The environment allow-list.
    if ctx.env_settings.observe.is_some() || ctx.env_settings.evidence.is_some() {
        layers.push(Layer {
            origin: LayerOrigin::Environment,
            base_dir: None,
            key_prefix: String::new(),
            narrowing: false,
            delta: PolicyDelta {
                observe: ctx.env_settings.observe,
                evidence: ctx.env_settings.evidence,
                ..PolicyDelta::default()
            },
        });
    }

    // 4. Explicit CLI grants and limits.
    let cli_delta = PolicyDelta {
        read_write: args.rw.iter().map(|path| os_bytes(path)).collect(),
        read_only: args.ro.iter().map(|path| os_bytes(path)).collect(),
        deny_read: args.deny_read.iter().map(|path| os_bytes(path)).collect(),
        network_allow: args.allow_host.clone(),
        limits: config::ceilings_from_cli(&args.limit)?,
        observe: match &args.observe {
            Some(text) => Some(config::parse_observe("--observe", text)?),
            None => None,
        },
        evidence: match &args.evidence {
            Some(text) => Some(config::parse_evidence("--evidence", text)?),
            None => None,
        },
        ..PolicyDelta::default()
    };
    let has_cli = !cli_delta.read_write.is_empty()
        || !cli_delta.read_only.is_empty()
        || !cli_delta.deny_read.is_empty()
        || !cli_delta.network_allow.is_empty()
        || cli_delta.limits != policy::Ceilings::default()
        || cli_delta.observe.is_some()
        || cli_delta.evidence.is_some();
    if has_cli {
        layers.push(Layer {
            origin: LayerOrigin::CommandLine,
            base_dir: Some(os_bytes(&ctx.cwd)),
            key_prefix: String::new(),
            narrowing: false,
            delta: cli_delta,
        });
    }

    // 5. The workspace-root `ouro.toml`, which may only narrow.
    let project_path = workspace.join("ouro.toml");
    if let Some(text) = read_project_file(&project_path)? {
        let project = config::parse_project_config(&text)?;
        if let Some(section) = project.jail {
            config::check_schema("jail.schema", section.schema.as_deref())?;
            let mut delta = config::delta_from_sections(
                "jail.",
                &section.filesystem,
                &section.network,
                &section.limits,
                &section.observation,
            )?;
            // §6.3: `profile` and `extends` are forbidden in project config.
            if section.profile.is_some() {
                delta.forbidden_key = Some("profile".to_owned());
            } else if section.extends.is_some() {
                delta.forbidden_key = Some("extends".to_owned());
            }
            layers.push(Layer {
                origin: LayerOrigin::ProjectConfig("ouro.toml".to_owned()),
                base_dir: Some(os_bytes(&workspace)),
                key_prefix: "jail.".to_owned(),
                narrowing: true,
                delta,
            });
        }
    }

    let scratch = match &args.scratch {
        Some(path) => ScratchRoot::Host {
            path: crate::records::NativeString::from_bytes(os_bytes(&canonical_root(
                &ctx.cwd,
                Some(path),
                "--scratch",
            )?))
            .map_err(|error| usage("--scratch", error.to_string()))?,
        },
        None => ScratchRoot::Managed,
    };

    // §6.2: `[jail_host.network] translation_prefixes` is host configuration,
    // merged into proxy policy before digest creation. Each entry is parsed
    // and re-rendered in canonical RFC 5952 form so equivalent spellings of
    // one prefix cannot yield two digests (§6.3).
    let translation_prefixes = match operator
        .jail_host
        .and_then(|host| host.network)
        .map(|network| network.translation_prefixes)
    {
        Some(entries) => config::canonical_translation_prefixes(
            "jail_host.network.translation_prefixes",
            &entries,
        )?,
        None => Vec::new(),
    };

    let platform_os = ctx.platform.identity().os;
    let inputs = ResolveInputs {
        platform: platform_os,
        base_profile: profile,
        policy_name,
        baseline: profiles::baseline(profile, platform_os, ctx.env_lookup.as_ref()),
        workspace: os_bytes(&workspace),
        scratch,
        vendor_state: None,
        operator_home: ctx.home.as_deref().map(os_bytes),
        translation_prefixes,
        layers,
    };
    let resolved = policy::resolve(&inputs)?;
    // J3-launch begin: the launch environment, vendor state and `launch`
    // field group, then the digest and requirements over the result.
    let resolved = match &launch {
        Some(launch) => launch_profile::apply(resolved, launch)?,
        None => resolved,
    };
    // J3-launch end

    // §6.4: `build` requires an explicit memory ceiling; the baseline leaves it
    // absent so that this refuses rather than inventing one.
    if profile == ProfileName::Build && resolved.snapshot.limits.mem.is_none() {
        return Err(usage(
            "limits.mem",
            "the `build` profile requires an explicit memory ceiling",
        ));
    }

    // J3-launch begin: §12 "A launch profile path inside any child-writable
    // grant refuses", and north star §4.5 refuses one inside the workspace.
    if let Some(launch) = &launch {
        launch_profile::check_outside_writable(
            launch,
            &launch_forbidden_roots(&resolved, &workspace),
        )?;
        // The same rule for every credential source, by identity (M2 of the
        // J3 review): the child must not be able to change what it is given.
        // A source that cannot be walked now is left to staging and doctor,
        // which report it by reason.
        let forbidden = forbidden_identities(&resolved, &workspace)?;
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
    }
    // J3-launch end

    Ok(Plan {
        resolved,
        profile,
        workspace,
        config_dir,
        data_dir,
    })
}

// J3-launch begin: the roots a launch profile may not lie beneath
/// The workspace, an explicit scratch and every writable host grant.
fn launch_forbidden_roots(resolved: &Resolved, workspace: &Path) -> Vec<PathBuf> {
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
// J3-launch end

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

/// Reads an operator-owned configuration file (§6.2).
///
/// `Ok(None)` means the file is absent. Every other failure is reported:
/// silently continuing without a file the operator wrote is how a tightening
/// disappears.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for any failure other than absence.
fn read_operator_file(path: &Path, key: &str) -> Result<Option<String>, JailError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(usage(key, format!("{}: {error}", path.display()))),
    }
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
    // §6.1 spells `doctor [--profile NAME|FILE] [--launch NAME] [--json]`:
    // the override flags belong to `run` and `explain`, and cli::DoctorArgs
    // does not define them, so only selection reaches the resolver here.
    let plan = resolve_plan(
        ctx,
        &PolicyArgs {
            profile: args.profile.clone(),
            launch: args.launch.clone(),
            ..PolicyArgs::default()
        },
    )?;
    let request = plan_request(&plan);
    let capabilities = ctx.platform.probe_all(&request);
    let ready = plan
        .resolved
        .requirements
        .iter()
        .all(|requirement| satisfied(requirement, &capabilities));
    // J3-launch begin: §14.1 launch readiness; a missing or unsafe source
    // makes the plan unavailable (north star §4.5: it refuses the launch).
    let forbidden = forbidden_identities(&plan.resolved, &plan.workspace)?;
    let launch = args.launch.as_ref().map(|name| LaunchReadiness {
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
    });
    let ready = ready
        && launch
            .as_ref()
            .is_none_or(|launch| launch.credentials.iter().all(|check| check.available));
    // J3-launch end
    Ok(DoctorReport {
        requirements: plan.resolved.requirements,
        capabilities,
        platform: platform_record(ctx),
        ready,
        // J3-launch begin
        launch,
        // J3-launch end
    })
}

/// Enumerates the registered state root without deleting anything it cannot
/// identify (§14.2).
///
/// This slice never terminates an orphan or removes an attempt: it reports what
/// it found, which is the honest half of GC until the Linux resource identity
/// checks exist.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when the state root fails its checks.
pub fn gc(ctx: &Context, args: &GcArgs) -> Result<GcReport, JailError> {
    let data_dir = state::data_dir(&ctx.env_settings, ctx.home.as_deref())?;
    // §14.2 enumerates "the registered state root". A root that fails the
    // §6.2 checks is not this operator's registered state, so `gc` says so
    // instead of printing a clean scan of a directory anyone can write.
    match std::fs::symlink_metadata(&data_dir) {
        Ok(_) => state::check_state_dir(&data_dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GcReport {
                entries: Vec::new(),
                dry_run: args.dry_run,
                // J3-launch begin
                incomplete: Vec::new(),
                // J3-launch end
            });
        }
        Err(error) => {
            return Err(JailError::new(
                ErrorCode::UnsafeStatePath,
                ErrorStage::Resolving,
                Remediation::InspectState,
                format!("{}: {error}", data_dir.display()),
            ));
        }
    }
    let attempts = data_dir.join("attempts");
    let mut entries = Vec::new();
    // J3-launch begin: attempts whose cleanup did not complete (§6.4: `gc`
    // exits 1 for failed cleanup)
    let mut incomplete: Vec<String> = Vec::new();
    // J3-launch end
    let listing = match std::fs::read_dir(&attempts) {
        Ok(listing) => listing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GcReport {
                entries,
                dry_run: args.dry_run,
                // J3-launch begin
                incomplete: Vec::new(),
                // J3-launch end
            });
        }
        Err(error) => {
            // §6.4: `gc` uses 1 "for failed cleanup or state access".
            return Err(JailError::new(
                ErrorCode::StateWriteFailed,
                ErrorStage::Resolving,
                Remediation::InspectState,
                format!("{}: {error}", attempts.display()),
            ));
        }
    };
    for entry in listing.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // J3-agent begin
        let mut proxy_dir: Option<String> = None;
        // J3-agent end
        let (action, reason) = match AttemptId::parse(&name) {
            Err(_) => (
                "skipped".to_owned(),
                "the directory name is not an attempt id".to_owned(),
            ),
            Ok(id) => {
                let dir = AttemptDir::new(&data_dir, &id);
                // J4-D3 begin: probe the lease without creating `jail.lock`;
                // a created lock would make a reserved root unclaimable
                // (§7) and a dry run would write to disk (§14.2).
                match state::Lease::probe_existing(&dir.lock_path()) {
                    Ok(state::LeaseProbe::Absent) => (
                        "retained".to_owned(),
                        match state::check_fresh_attempt(&dir) {
                            Ok(()) => "no jail.lock and no jail-owned artifact: an unclaimed \
                                       attempt root, which gc leaves untouched and claimable"
                                .to_owned(),
                            Err(error) => format!(
                                "no jail.lock, so no lease protects this attempt and gc \
                                 leaves it untouched: {}",
                                error.message
                            ),
                        },
                    ),
                    Ok(state::LeaseProbe::Held) => (
                        "retained".to_owned(),
                        "a live supervisor holds the lease".to_owned(),
                    ),
                    // J4-D3 end
                    // J3-launch begin: §12, §14.2 — resume a pending
                    // vendor-state cleanup the terminal receipt permits.
                    // J3-agent begin: the dead supervisor's proxy directory
                    // goes first; vendor state follows as before
                    Ok(state::LeaseProbe::Acquired(_lease)) => match gc_proxy_then_resume(
                        &dir,
                        &name,
                        args.dry_run,
                        &mut incomplete,
                        &mut proxy_dir,
                    ) {
                        // J3-agent end
                        Ok(cleanup::Resume::NothingPending) => (
                            "retained".to_owned(),
                            "no vendor-state cleanup is pending; receipts, policy and trace \
                             are retained"
                                .to_owned(),
                        ),
                        Ok(cleanup::Resume::Completed) => (
                            "removed_vendor_state".to_owned(),
                            "the pending vendor-state cleanup completed and the receipt \
                             records it"
                                .to_owned(),
                        ),
                        Ok(cleanup::Resume::WouldRemove) => (
                            "would_remove_vendor_state".to_owned(),
                            "the terminal receipt permits the pending vendor-state cleanup"
                                .to_owned(),
                        ),
                        Ok(cleanup::Resume::Retained(reason)) => (
                            "retained".to_owned(),
                            format!("vendor-state cleanup is not permitted: {reason}"),
                        ),
                        Ok(cleanup::Resume::StillPending(reason)) => {
                            incomplete.push(format!("{name} ({reason})"));
                            (
                                "pending".to_owned(),
                                format!("vendor-state cleanup stopped again: {reason}"),
                            )
                        }
                        Err(error) => {
                            incomplete.push(format!("{name} ({})", error.code.as_str()));
                            ("skipped".to_owned(), error.message.clone())
                        }
                    },
                    // J3-launch end
                    Err(error) => ("skipped".to_owned(), error.message.clone()),
                }
            }
        };
        entries.push(GcEntry {
            attempt_id: name,
            action,
            reason,
            // J3-agent begin
            proxy_dir,
            // J3-agent end
        });
    }
    entries.sort_by(|left, right| left.attempt_id.cmp(&right.attempt_id));
    // J3-launch begin: §6.4 "1 for failed cleanup or state access"; the
    // report still reaches the caller, which prints it before exiting 1.
    incomplete.sort();
    // J3-launch end
    Ok(GcReport {
        entries,
        dry_run: args.dry_run,
        // J3-launch begin
        incomplete,
        // J3-launch end
    })
}

fn plan_request(plan: &Plan) -> PlanRequest {
    PlanRequest {
        snapshot: plan.resolved.snapshot.clone(),
        profile: plan.profile,
        requirements: plan.resolved.requirements.clone(),
    }
}

fn platform_record(ctx: &Context) -> PlatformRecord {
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
    for requirement in requirements {
        if satisfied(requirement, capabilities) {
            continue;
        }
        let measured = capabilities
            .iter()
            .find(|capability| &capability.name == requirement);
        let reason = measured
            .and_then(|capability| capability.reason_code.clone())
            .unwrap_or_else(|| "not_measured".to_owned());
        let code = if reason == crate::platform::macos::REASON_UNSUPPORTED_PLATFORM {
            ErrorCode::UnsupportedPlatform
        } else {
            ErrorCode::MissingCapability
        };
        let message = if code == ErrorCode::UnsupportedPlatform {
            "execution is not implemented for this platform".to_owned()
        } else {
            format!("the host does not provide `{requirement}` ({reason})")
        };
        let remediation = if code == ErrorCode::UnsupportedPlatform {
            Remediation::Unsupported
        } else {
            Remediation::HostSetup
        };
        // J3-none begin: a restriction `none` cannot apply is the policy's to drop
        let (message, remediation) = if reason == crate::capability::REASON_NOT_APPLIED_BY_NONE {
            (
                format!(
                    "the uncontained profile cannot apply `{requirement}`; a contained profile can"
                ),
                Remediation::Configuration,
            )
        } else {
            (message, remediation)
        };
        // J3-none end
        return Some(JailError::new(
            code,
            ErrorStage::Probing,
            remediation,
            message,
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

/// Runs one attempt, or refuses before the target executes (§8.1).
///
/// Every path that does not reach `release` writes a `refused` receipt with the
/// §13.2 tuple for the stage it failed at. The return value carries the exit
/// status; the caller prints diagnostics.
#[must_use]
pub fn run(ctx: &Context, args: &RunArgs) -> RunReport {
    match run_inner(ctx, args) {
        Ok(report) => report,
        Err(error) => RunReport {
            exit_code: error.exit_code(),
            error: Some(error),
            ..RunReport::default()
        },
    }
}

#[allow(clippy::too_many_lines)]
fn run_inner(ctx: &Context, args: &RunArgs) -> Result<RunReport, JailError> {
    // §13.1: pin the shared monotonic base before anything writes a trace
    // event, so wrapper, audit and gap intervals all count from here.
    crate::platform::mark_supervisor_start();
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
    let supplied_attempt_id = match &args.attempt_id {
        Some(text) => Some(AttemptId::parse(text)?),
        None => None,
    };

    // §8.3, H9: the handlers go on before anything exists. They used to be
    // installed just before `release`, so INT/TERM/HUP during resolution,
    // preparation or the 60-second gate wait killed the supervisor with the
    // default disposition and left a prepared receipt and a blocked launcher
    // behind.
    let signals = signals::install();

    let plan = resolve_plan(ctx, &args.policy)?;
    let request = plan_request(&plan);
    let argv: Vec<Vec<u8>> = args
        .argv
        .iter()
        .map(|argument| argument.clone().into_vec())
        .collect();
    let argv_digest = (!argv.is_empty()).then(|| crate::canonical::argv_digest(&argv));

    validate_channels(args)?;
    check_state_isolation(&plan)?;
    validate_receipt_path(args, &plan)?;

    if args.label_only {
        // §6.1: resolve and probe, print the label, execute nothing and copy no
        // credential. No attempt state is allocated, so nothing to clean up.
        let capabilities = ctx.platform.probe(&request);
        let refusal = first_unsatisfied(&plan.resolved.requirements, &capabilities);
        return Ok(RunReport {
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
        });
    }

    // §8.2: "Initial preparation budget: 30 seconds". It covers steps 1 to 5
    // and is checked at each boundary, so a step that hangs on a child-created
    // object cannot hold the attempt open indefinitely.
    let budget = Budget::new(PREPARE_BUDGET);

    // Step 1: allocate and lock private state before anything else exists.
    let attempt_id = supplied_attempt_id.unwrap_or_else(AttemptId::generate);
    let attempt_dir = AttemptDir::new(&plan.data_dir, &attempt_id);
    attempt_dir.create(&plan.data_dir)?;
    // J3-launch begin: §7 — an existing attempt root must hold no jail-owned
    // artifact at all, not only no `jail-state.json` (J3 review H2). Checked
    // before the lease, so a `jail.lock` found here is not this supervisor's.
    state::check_fresh_attempt(&attempt_dir)?;
    // J3-launch end
    let Some(_lease) = state::Lease::acquire(&attempt_dir.lock_path())? else {
        return Err(JailError::new(
            ErrorCode::AttemptExists,
            ErrorStage::Resolving,
            Remediation::InspectState,
            "another live supervisor holds this attempt's lease".to_owned(),
        ));
    };
    claim_attempt(&attempt_dir, &attempt_id, ctx)?;
    write_policy_file(&attempt_dir, &plan)?;

    let now = SystemTime::now();
    let containment = if plan.profile.is_contained() {
        Containment::Pending
    } else {
        // I08: `none` is unprotected in every receipt, including a refusal.
        Containment::None
    };
    let mut record = AttemptRecord {
        attempt_id: attempt_id.as_str().to_owned(),
        revision: 1,
        platform: platform_record(ctx),
        jail: JailRecord {
            component: "ouro-jail".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            backend: None,
            backend_version: None,
        },
        policy: PolicyRecord {
            name: plan.resolved.policy_name.clone(),
            digest: plan.resolved.digest.clone(),
            observe: plan.resolved.snapshot.observation.mode,
            evidence: plan.resolved.snapshot.observation.evidence,
            requirements: plan.resolved.requirements.clone(),
            // §13.2: the receipt's grants are the explicit operator grants,
            // not the profile baseline every `tool` run gets.
            grants: plan.resolved.grants.clone(),
        },
        containment,
        exec_observed: false,
        argv_digest,
        applied: pending_applied(&plan),
        observer: CoverageSummary::unobserved().to_observer_record(),
        coverage: CoverageSummary::unobserved().to_coverage(),
        process: None,
        lifetime: Lifetime::pending(),
        outcome: Outcome::pending(),
        state_cleanup: cleanup::not_needed(),
        cleanup_error: None,
        created_at: now,
        updated_at: now,
        errors: Vec::new(),
        credentials: Vec::new(),
    };

    let mut control = open_control(args)?;
    let trace = open_trace(args, &attempt_dir)?;
    let mut journal = Journal::new(attempt_id.as_str(), Arc::clone(&trace));

    // Step 2: probe the selected mechanisms.
    if let Err(error) = budget
        .check(ErrorStage::Probing)
        .and(interrupted(signals.as_ref(), ErrorStage::Probing))
    {
        return Ok(refuse(
            &attempt_dir,
            &mut record,
            &error,
            args,
            control.as_mut(),
            &mut journal,
        ));
    }
    let capabilities = ctx.platform.probe(&request);
    if let Some(error) = first_unsatisfied(&plan.resolved.requirements, &capabilities) {
        return Ok(refuse(
            &attempt_dir,
            &mut record,
            &error,
            args,
            control.as_mut(),
            &mut journal,
        ));
    }

    // J3-launch begin: §8.1 step 2 and §12 — register vendor state before
    // creating it, then stage credentials into it, before any boundary.
    if let Err(error) = budget
        .check(ErrorStage::Preparing)
        .and(interrupted(signals.as_ref(), ErrorStage::Preparing))
    {
        return Ok(refuse(
            &attempt_dir,
            &mut record,
            &error,
            args,
            control.as_mut(),
            &mut journal,
        ));
    }
    let launch_handoff = match prepare_launch(&attempt_dir, &plan, &mut record, budget.deadline) {
        Ok(handoff) => handoff,
        Err(error) => {
            return Ok(refuse(
                &attempt_dir,
                &mut record,
                &error,
                args,
                control.as_mut(),
                &mut journal,
            ));
        }
    };
    // J3-launch end
    // J3-agent begin: §10 — the proxy directory is registered before it is
    // created, outside every shared root, for a proxy-mode profile only.
    let proxy_handoff = match prepare_proxy_dir(&attempt_dir, &plan) {
        Ok(handoff) => handoff,
        Err(error) => {
            return Ok(refuse(
                &attempt_dir,
                &mut record,
                &error,
                args,
                control.as_mut(),
                &mut journal,
            ));
        }
    };
    // J3-agent end

    // Steps 3 to 5: create the boundary and the blocked launcher.
    let prepared = match ctx.platform.prepare(
        PreparedPlan {
            attempt_id: attempt_id.as_str().to_owned(),
            attempt_dir: attempt_dir.root().to_path_buf(),
            request,
            argv,
            workspace: plan.workspace.clone(),
            // J3-launch begin: the staged objects, bound by descriptor
            launch: launch_handoff,
            // J3-launch end
            // J3-agent begin: the registered proxy directory
            proxy: proxy_handoff.clone(),
            // J3-agent end
        },
        Sinks {
            trace: Some(Arc::clone(&trace)),
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(refuse(
                &attempt_dir,
                &mut record,
                &error,
                args,
                control.as_mut(),
                &mut journal,
            ));
        }
    };

    // J3-agent begin: the proxy socket node the platform bound, recorded so
    // `gc` can remove exactly it after a crash (§14.2)
    if let Some(socket) = proxy_handoff
        .as_ref()
        .and_then(|handoff| handoff.socket.get())
        && let Err(error) = state::record_proxy_socket(&attempt_dir, socket)
    {
        let teardown = prepared.abort();
        record_teardown(&mut record, &teardown);
        return Ok(refuse(
            &attempt_dir,
            &mut record,
            &error,
            args,
            control.as_mut(),
            &mut journal,
        ));
    }
    // J3-agent end
    let boundary = prepared.boundary();
    apply_boundary(&mut record, &boundary, plan.profile);
    // §7: the state file names the registered execution boundary once it
    // exists, so crash reconciliation and GC can identify resources without
    // parsing a receipt.
    if let Err(error) = register_boundary_in_state(&attempt_dir, &boundary) {
        let teardown = prepared.abort();
        record_teardown(&mut record, &teardown);
        return Ok(refuse(
            &attempt_dir,
            &mut record,
            &error,
            args,
            control.as_mut(),
            &mut journal,
        ));
    }
    if let Some(applied) = prepared.applied() {
        record.applied = applied;
    }
    merge_wall_limit(&mut record, &plan);
    journal.lifecycle("prepared");

    // A failure from here on has a boundary to tear down: §8.1 step 5 is the
    // last point at which nothing has been created, and every exit after it
    // goes through `abort`.
    let prepared_receipt = match persist(
        &attempt_dir,
        &mut record,
        Phase::Prepared,
        args,
        &mut journal,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            let teardown = prepared.abort();
            record_teardown(&mut record, &teardown);
            return Ok(refuse(
                &attempt_dir,
                &mut record,
                &error,
                args,
                control.as_mut(),
                &mut journal,
            ));
        }
    };
    send_control(
        control.as_mut(),
        &record,
        ControlKind::Prepared,
        Phase::Prepared,
        &prepared_receipt,
    );

    // Step 6: wait for a valid external release, or release locally.
    let gate = match budget.check(ErrorStage::Prepared) {
        Err(error) => Err(error),
        Ok(()) => match args.gate_fd {
            None => interrupted(signals.as_ref(), ErrorStage::Prepared),
            Some(fd) => {
                let expectation = GateExpectation {
                    attempt_id: attempt_id.as_str().to_owned(),
                    policy_digest: plan.resolved.digest.clone(),
                };
                await_release(fd, &expectation, GATE_WAIT, signals.as_ref())
            }
        },
    };
    if let Err(error) = gate {
        let teardown = prepared.abort();
        record_teardown(&mut record, &teardown);
        return Ok(refuse(
            &attempt_dir,
            &mut record,
            &error,
            args,
            control.as_mut(),
            &mut journal,
        ));
    }

    // Step 7: execute the exact target argv through the blocked launcher.
    // J3-launch begin: a failed release reports its teardown, so the refused
    // receipt carries the verified tree (§13.2 row 4) and vendor state can be
    // removed rather than retained.
    let mut running = match prepared.release_reporting_teardown() {
        Ok(running) => running,
        Err(failure) => {
            let crate::platform::ReleaseFailure { error, teardown } = *failure;
            if let Some(teardown) = teardown {
                record_teardown(&mut record, &Ok(teardown));
            }
            // J3-launch end
            return Ok(refuse(
                &attempt_dir,
                &mut record,
                &error,
                args,
                control.as_mut(),
                &mut journal,
            ));
        }
    };

    let wall_deadline = wall_deadline(&plan);
    let mut outcome_error: Option<JailError> = None;
    loop {
        // §13.3 + I07: a trace-sink failure — budget exhausted, external
        // consumer stalled past its deadline — is evidence loss, and under
        // strict it stops the attempt exactly like the tracer-queue path
        // does. Checking here means the stop does not wait for the next
        // event to notice it.
        if let Some(error) = journal.take_new_loss() {
            record.errors.push(error.to_object());
            if plan.resolved.snapshot.observation.evidence == crate::records::EvidenceMode::Strict {
                record
                    .outcome
                    .cause
                    .get_or_insert("evidence_loss".to_owned());
                running.request_stop(StopReason::EvidenceLoss);
            }
            outcome_error.get_or_insert(error);
        }
        if signals.as_ref().is_some_and(signals::SignalPipe::triggered) {
            record
                .outcome
                .cause
                .get_or_insert("operator_signal".to_owned());
            running.request_stop(StopReason::OperatorSignal);
        }
        // J3-none begin: a detected integrity loss reaches the receipt now, not only at the end
        if record.lifetime.integrity != "lost" && running.integrity_lost() {
            record.lifetime.integrity = "lost".to_owned();
            record.lifetime.tree_empty = None;
            record.lifetime.verified_at = None;
            let phase = if record.exec_observed {
                Phase::Enforced
            } else {
                Phase::Prepared
            };
            if let Err(error) = persist(&attempt_dir, &mut record, phase, args, &mut journal) {
                // As for the exec confirmation: persistence that fails after
                // release stops the tree (§7).
                record.errors.push(error.to_object());
                record
                    .outcome
                    .cause
                    .get_or_insert("state_write_failed".to_owned());
                outcome_error.get_or_insert(error);
                running.request_stop(StopReason::EvidenceLoss);
            }
        }
        // J3-none end
        match running.wait(crate::platform::Deadline { at: wall_deadline }) {
            RunEvent::Poll => continue,
            RunEvent::ExecConfirmed => {
                // §11.2: exec is a confirmed transition, and there is exactly
                // one per attempt. A repeat would advance the receipt revision
                // and publish a second `exec_confirmed` for the same fact.
                if record.exec_observed {
                    continue;
                }
                record.exec_observed = true;
                journal.lifecycle("exec_confirmed");
                match persist(
                    &attempt_dir,
                    &mut record,
                    Phase::Enforced,
                    args,
                    &mut journal,
                ) {
                    Ok(receipt) => send_control(
                        control.as_mut(),
                        &record,
                        ControlKind::ExecConfirmed,
                        Phase::Enforced,
                        &receipt,
                    ),
                    Err(error) => {
                        // §7: "Failed/ambiguous persistence ... after exec it
                        // stops the tree and leaves an incomplete receipt if
                        // necessary." Returning here would have left the tree
                        // running with no one waiting for it.
                        record.errors.push(error.to_object());
                        record
                            .outcome
                            .cause
                            .get_or_insert("state_write_failed".to_owned());
                        outcome_error = Some(error);
                        running.request_stop(StopReason::EvidenceLoss);
                    }
                }
            }
            // §6.4: "Deadline or requested termination preserves the observed
            // code/signal and records its cause." Only the fields this event
            // establishes are written; `cause` and `error` were set by whatever
            // asked for the termination and must survive it.
            RunEvent::TargetExited { code } => {
                record.outcome.kind = OutcomeKind::Exited;
                record.outcome.code = Some(code);
                record.outcome.signal = None;
                break;
            }
            RunEvent::TargetSignaled { signal } => {
                record.outcome.kind = OutcomeKind::Signaled;
                record.outcome.code = None;
                record.outcome.signal = Some(signal);
                break;
            }
            RunEvent::ExecError { errno } => {
                // §8.1: an unsuccessful target exec is a pre-exec failure, and
                // §13.2 gives it its own outcome kind. It is not `refused`:
                // the attempt reached release and the kernel answered, which
                // is a different fact from a refusal before anything ran.
                record.outcome = Outcome::exec_error(&errno);
                // J3-launch begin: §13.2 row 4 — "true / timestamp only after
                // teardown verification": every contained attempt verifies the
                // teardown of a failed exec, so the refused receipt says what
                // it established and vendor state can be removed.
                if plan.profile.is_contained() {
                    let tree = running.wait_tree(TREE_BUDGET);
                    record_tree(&mut record, &tree);
                }
                // J3-launch end
                let error = JailError::new(
                    ErrorCode::ExecFailed,
                    ErrorStage::Released,
                    Remediation::Configuration,
                    format!("the target exec failed with {errno}"),
                );
                return Ok(refuse(
                    &attempt_dir,
                    &mut record,
                    &error,
                    args,
                    control.as_mut(),
                    &mut journal,
                ));
            }
            RunEvent::WallExpired => {
                // J4-D5: the first stop wins, as it does in the platform's
                // `request_stop`; an expiry during another stop's grace is
                // recorded as the limit's hit, not as the cause.
                record.outcome.cause.get_or_insert("wall_expiry".to_owned());
                // §13.2: "Limits report hits in `applied.limits[].hit` with
                // `outcome.cause`". The supervisor owns the wall deadline, so
                // it is the source of this hit.
                if let Some(wall) = record
                    .applied
                    .limits
                    .iter_mut()
                    .find(|limit| limit.key == "wall" && limit.applied)
                {
                    wall.hit = Some(true);
                }
                running.request_stop(StopReason::WallExpiry);
            }
            RunEvent::EvidenceLost { reason } => {
                let error = JailError::new(
                    ErrorCode::EvidenceLost,
                    ErrorStage::Running,
                    Remediation::InspectState,
                    reason,
                );
                record.errors.push(error.to_object());
                if plan.resolved.snapshot.observation.evidence
                    == crate::records::EvidenceMode::Strict
                {
                    // J4-D5: the first stop wins (see `WallExpired`).
                    record
                        .outcome
                        .cause
                        .get_or_insert("evidence_loss".to_owned());
                    running.request_stop(StopReason::EvidenceLoss);
                }
                outcome_error = Some(error);
            }
            RunEvent::Unknown { reason } => {
                record.outcome.kind = OutcomeKind::Unknown;
                record.outcome.code = None;
                record.outcome.signal = None;
                // A resource event the supervisor itself acted on is the
                // cause even when the target's own end is not observable:
                // the ambiguity is the outcome's kind, not its cause.
                if let Some(cause) = running.limit_cause() {
                    record.outcome.cause.get_or_insert(cause);
                }
                record.outcome.cause.get_or_insert(reason);
                break;
            }
        }
    }

    // Step 9: verify tree death, drain observations, persist settlement.
    // A sink loss that arrived after the last loop iteration still belongs
    // in the settled receipt's errors (§13.3: the receipt is the bounded
    // summary of what was lost).
    if let Some(error) = journal.take_new_loss() {
        record.errors.push(error.to_object());
        outcome_error.get_or_insert(error);
    }
    let tree = running.wait_tree(TREE_BUDGET);
    for limit in running.final_limits() {
        if let Some(recorded) = record
            .applied
            .limits
            .iter_mut()
            .find(|row| row.key == limit.key)
        {
            *recorded = limit;
        }
    }
    if let Some(cause) = running.limit_cause() {
        record.outcome.cause.get_or_insert(cause);
    }
    if let Some(summary) = running.observer_summary() {
        record.observer = summary.to_observer_record();
        record.coverage = summary.to_coverage();
    }
    // J3-agent begin: what the helpers did, known now that they stopped
    if let Some(native) = record.lifetime.native.as_mut() {
        native.details.extend(running.final_native_details());
    }
    // J3-agent end
    record.lifetime.tree_empty = tree.tree_empty;
    record.lifetime.verified_at = tree.verified_at.map(rfc3339_utc);
    record.lifetime.verification_scope = Some(tree.verification_scope);
    // J3-none begin: the last nonsettled phase without a confirmed exec is prepared (§8.1)
    let prepared_integrity = std::mem::replace(&mut record.lifetime.integrity, tree.integrity);
    // J3-none end

    let settled = tree.tree_empty == Some(true) && record.lifetime.integrity == "verified";
    // §13.2: "If tree death itself is unknown, retain the last nonsettled phase
    // and update its outcome/coverage/error as unknown."
    // J3-none begin: `enforced` is the phase after a confirmed target exec (§8.1)
    let phase = if settled {
        Phase::Settled
    } else if record.exec_observed {
        Phase::Enforced
    } else {
        // Without a confirmed exec the last nonsettled phase is `prepared`.
        // Its integrity stays the prepared one unless a loss was detected:
        // an unknown tree end does not unmake the verified boundary.
        if record.lifetime.integrity == "pending" {
            record.lifetime.integrity = prepared_integrity;
        }
        Phase::Prepared
    };
    // J3-none end
    // §14.2: default managed scratch is removed only after verified tree
    // death. Until then the child could still be writing to it, and after an
    // unverified one something may still be holding it, so it is retained and
    // the receipt says the cleanup did not complete.
    // J3-launch begin: §8.1 step 9 and §12 — with vendor state, persist the
    // settled receipt as `pending` first, then clean, then record the result;
    // an unverified tree retains vendor state.
    if matches!(state::vendor_registration(&attempt_dir), Ok(Some(_))) {
        if settled {
            record.state_cleanup = StateCleanup::Pending;
            record.cleanup_error = None;
            match persist(&attempt_dir, &mut record, phase, args, &mut journal) {
                Ok(_) => {
                    let vendor =
                        cleanup::remove_vendor_state(&attempt_dir, cleanup::Limits::DEFAULT);
                    let scratch = remove_managed_scratch(&attempt_dir, &plan);
                    match (vendor.status, scratch) {
                        (
                            StateCleanup::Complete,
                            StateCleanup::Complete | StateCleanup::NotNeeded,
                        ) => {
                            record.state_cleanup = StateCleanup::Complete;
                        }
                        (StateCleanup::Complete, _) => {
                            record.state_cleanup = StateCleanup::Pending;
                            record.cleanup_error = Some("scratch_removal_failed".to_owned());
                        }
                        (status, _) => {
                            record.state_cleanup = status;
                            record.cleanup_error = vendor.reason;
                        }
                    }
                }
                Err(error) => {
                    // No durable settled receipt, so nothing would permit a
                    // later `gc` to finish a removal started now.
                    record.errors.push(error.to_object());
                    record.cleanup_error = Some("state_write_failed".to_owned());
                }
            }
        } else {
            retain_vendor_state(&attempt_dir, &mut record);
        }
    } else if settled {
        record.state_cleanup = remove_managed_scratch(&attempt_dir, &plan);
    }
    // J3-launch end
    // J3-none begin: a detected integrity loss is not a budget overrun (§9.3)
    let tree_message = if record.lifetime.integrity == "lost" {
        "the lifetime boundary's integrity was lost (a membership escape, a replaced \
         identity or a failed verification was detected), so tree death is unknown"
    } else {
        "tree death could not be verified within its budget"
    };
    let tree_error = (!settled).then(|| {
        let error = JailError::new(
            ErrorCode::TreeUnknown,
            ErrorStage::Reconciling,
            Remediation::InspectState,
            tree_message.to_owned(),
        );
        record.errors.push(error.to_object());
        error
    });
    // J3-none end
    // J3-agent begin: the proxy stopped inside `wait_tree`
    remove_proxy_directory(&attempt_dir, &mut record);
    // J3-agent end
    // §13.3 terminal drain, before the settled receipt is written: whatever
    // the external trace consumer has not accepted within the no-progress
    // deadline is recorded as evidence loss, and that loss belongs in the
    // receipt that summarizes what was lost. (The receipt's own final note,
    // written by persist below, is drained once more after it is sent.)
    if let Ok(mut sink) = journal.trace.lock() {
        sink.finish();
    }
    if let Some(error) = journal.take_new_loss() {
        record.errors.push(error.to_object());
        outcome_error.get_or_insert(error);
    }
    if journal.loss.is_some() {
        degrade_trace_coverage(&mut record);
    }
    let receipt = match persist_terminal(&attempt_dir, &mut record, phase, args, &mut journal) {
        Ok(receipt) => receipt,
        Err(error) => {
            return Ok(RunReport {
                exit_code: error.exit_code(),
                error: Some(error),
                receipt_path: Some(attempt_dir.receipt_path()),
                trace_error: journal.loss.clone(),
                control_dropped: control.as_ref().map_or(0, ControlSink::dropped),
                ..RunReport::default()
            });
        }
    };
    if let Some(error) = journal.loss.clone() {
        outcome_error.get_or_insert(error);
    }
    send_control(
        control.as_mut(),
        &record,
        if settled {
            ControlKind::Settled
        } else {
            // §8.1: nothing after release is a refusal. An unverified tree is
            // `unsettled`: the target did run, and saying otherwise would tell
            // an owner that no command executed.
            ControlKind::Unsettled
        },
        phase,
        &receipt,
    );

    let exit_code = if let Some(error) = &tree_error {
        error.exit_code()
    } else if let Some(error) = &outcome_error {
        error.exit_code()
    } else {
        match record.outcome.kind {
            OutcomeKind::Exited => i32::from(record.outcome.code.unwrap_or(0)),
            OutcomeKind::Signaled => {
                128 + i32::try_from(record.outcome.signal.unwrap_or(0)).unwrap_or(0)
            }
            _ => 1,
        }
    };
    Ok(RunReport {
        exit_code,
        receipt: Some(receipt),
        error: tree_error.or(outcome_error),
        receipt_path: Some(attempt_dir.receipt_path()),
        trace_error: journal.loss.clone(),
        control_dropped: control.as_ref().map_or(0, ControlSink::dropped),
        ..RunReport::default()
    })
}

fn wall_deadline(plan: &Plan) -> Option<Instant> {
    plan.resolved
        .ceilings
        .wall
        .as_ref()
        .map(|ceiling| Instant::now() + Duration::from_millis(ceiling.value))
}

/// Queued frames from any active source may have been lost in transport.
fn degrade_trace_coverage(record: &mut AttemptRecord) {
    use crate::records::{Gap, SourceStatus};
    record.observer.sources.wrapper = SourceStatus::Degraded;
    for status in [
        &mut record.observer.sources.audit,
        &mut record.observer.sources.proxy,
    ] {
        if *status != SourceStatus::Unsupported {
            *status = SourceStatus::Degraded;
        }
    }
    for (name, entry) in [
        ("exec", &mut record.coverage.exec),
        ("fs.write", &mut record.coverage.fs_write),
        ("fs.deny", &mut record.coverage.fs_deny),
        ("net", &mut record.coverage.net),
        ("proxy.net", &mut record.coverage.proxy_net),
        ("limits", &mut record.coverage.limits),
    ] {
        if entry.status == SourceStatus::Unsupported {
            continue;
        }
        entry.status = SourceStatus::Degraded;
        entry.observed_count = None;
        let gap = Gap {
            classes: vec![name.to_owned()],
            source: entry
                .sources
                .first()
                .cloned()
                .unwrap_or_else(|| "wrapper".to_owned()),
            start_ns: "0".to_owned(),
            end_ns: Some(crate::platform::elapsed_since_start_ns().to_string()),
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
/// receipt records `complete` only when both are gone.
fn remove_managed_scratch(attempt_dir: &AttemptDir, plan: &Plan) -> crate::records::StateCleanup {
    use crate::records::StateCleanup;
    if plan.resolved.snapshot.roots.scratch != ScratchRoot::Managed {
        return cleanup::not_needed();
    }
    let mut complete = true;
    // J3-launch begin: `not_needed` when nothing was created (the `none`
    // profile makes no managed scratch); `complete` only for a removal.
    let mut created = false;
    // J3-launch end
    for path in [
        attempt_dir.root().join("scratch"),
        attempt_dir.root().join("placeholders"),
    ] {
        // J3-launch begin
        if std::fs::symlink_metadata(&path).is_ok() {
            created = true;
        }
        // J3-launch end
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => complete = false,
        }
    }
    // J3-launch begin
    if !created {
        return cleanup::not_needed();
    }
    // J3-launch end
    if complete {
        StateCleanup::Complete
    } else {
        StateCleanup::Pending
    }
}

fn apply_boundary(record: &mut AttemptRecord, boundary: &BoundaryIdentity, profile: ProfileName) {
    record.containment = if profile.is_contained() {
        Containment::Enforced
    } else {
        Containment::None
    };
    record.lifetime = Lifetime {
        boundary: boundary.boundary.clone(),
        native: boundary.native.clone(),
        tree_empty: None,
        verified_at: None,
        verification_scope: Some(boundary.verification_scope.clone()),
        integrity: "verified".to_owned(),
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
/// workspace, the scratch root or any host grant.
fn check_state_isolation(plan: &Plan) -> Result<(), JailError> {
    let state_root = canonical_existing_prefix(&plan.data_dir);
    for root in child_visible_roots(plan) {
        let root = canonical_existing_prefix(&root);
        if overlaps(&state_root, &root) {
            return Err(JailError::new(
                ErrorCode::UnsafeStatePath,
                ErrorStage::Resolving,
                Remediation::Configuration,
                format!(
                    "the state root {} overlaps the child-visible root {}",
                    state_root.display(),
                    root.display()
                ),
            )
            .with_key_path("OURO_DATA_DIR"));
        }
    }
    Ok(())
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
/// state directory is not a place for a second copy either.
///
/// # Errors
/// Returns [`ErrorCode::InvalidConfig`] for a path that fails any of those.
fn validate_receipt_path(args: &RunArgs, plan: &Plan) -> Result<(), JailError> {
    let Some(path) = &args.receipt else {
        return Ok(());
    };
    let key = "--receipt";
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(usage(
                key,
                format!(
                    "{} already exists; the receipt copy never replaces an existing file, symlink or device",
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
    for root in child_visible_roots(plan) {
        let root = canonical_existing_prefix(&root);
        if parent.starts_with(&root) {
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
    Ok(())
}

/// A monotonic budget with a stage-appropriate refusal (§8.2).
struct Budget {
    deadline: Instant,
    total: Duration,
}

impl Budget {
    fn new(total: Duration) -> Self {
        Budget {
            deadline: Instant::now() + total,
            total,
        }
    }

    /// Refuses when the budget is spent.
    ///
    /// # Errors
    /// Returns [`ErrorCode::PrepareTimeout`].
    fn check(&self, stage: ErrorStage) -> Result<(), JailError> {
        if Instant::now() < self.deadline {
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

/// Records the wall ceiling the supervisor itself enforces (§13.2).
///
/// The supervisor owns the wall deadline on every platform, so it is the one
/// that can say the ceiling was applied and, later, that it was hit. The
/// mechanism name states the clock this code actually uses: `Instant` is
/// `CLOCK_MONOTONIC`, and calling it a boot-time deadline would be a claim
/// about suspend that portable code cannot make (§6.4, M10).
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
        Ok(Teardown { tree: Some(tree) }) => {
            record.lifetime.tree_empty = tree.tree_empty;
            record.lifetime.verified_at = tree.verified_at.map(rfc3339_utc);
            record.lifetime.verification_scope = Some(tree.verification_scope.clone());
            record.lifetime.integrity = tree.integrity.clone();
        }
        Ok(Teardown { tree: None }) => {
            // Teardown ran but verified nothing about the tree.
            record.lifetime.tree_empty = None;
            record.lifetime.verified_at = None;
        }
        Err(error) => {
            record.errors.push(error.to_object());
            record.lifetime.tree_empty = None;
            record.lifetime.verified_at = None;
            if record.lifetime.boundary != "pending" {
                record.lifetime.integrity = "lost".to_owned();
            }
        }
    }
}

/// Writes the `refused` receipt of §13.2 and returns the report for it.
fn refuse(
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    error: &JailError,
    args: &RunArgs,
    control: Option<&mut ControlSink>,
    journal: &mut Journal,
) -> RunReport {
    // A proved exec failure keeps its own kind (§13.2); everything else that
    // reaches here refused before the target ran.
    record.outcome = if record.outcome.kind == OutcomeKind::ExecError {
        Outcome {
            error: Some(error.to_object()),
            ..record.outcome.clone()
        }
    } else {
        Outcome::refused(error)
    };
    record.errors.push(error.to_object());
    record.exec_observed = false;
    journal.lifecycle("refused");
    // J3-launch begin: §12 vendor state on a pre-exec refusal
    refuse_vendor_state(attempt_dir, record, args, journal);
    // J3-launch end
    // J3-agent begin: the proxy stopped with the boundary's teardown
    remove_proxy_directory(attempt_dir, record);
    // J3-agent end
    let receipt = persist_terminal(attempt_dir, record, Phase::Refused, args, journal);
    match receipt {
        Ok(receipt) => {
            send_control(
                control,
                record,
                ControlKind::Refused,
                Phase::Refused,
                &receipt,
            );
            RunReport {
                exit_code: error.exit_code(),
                receipt: Some(receipt),
                error: Some(error.clone()),
                receipt_path: Some(attempt_dir.receipt_path()),
                trace_error: journal.loss.clone(),
                ..RunReport::default()
            }
        }
        Err(write_error) => RunReport {
            exit_code: write_error.exit_code(),
            error: Some(write_error),
            receipt_path: Some(attempt_dir.receipt_path()),
            trace_error: journal.loss.clone(),
            ..RunReport::default()
        },
    }
}

fn pending_applied(plan: &Plan) -> Applied {
    let mode = if plan.profile.is_contained() {
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
        },
        syscalls: None,
        limits: Vec::new(),
        environment_names: Vec::new(),
        removed_environment_names: Vec::new(),
    }
}

/// The requested limits as an unapplied `applied.limits` table.
///
/// Used once a boundary exists; a refusal before boundary creation reports an
/// empty table because nothing was requested of any mechanism yet.
#[must_use]
pub fn requested_limits(plan: &Plan) -> Vec<AppliedLimit> {
    let mut out = Vec::new();
    for key in LimitKey::ALL {
        let ceiling = match key {
            LimitKey::Wall => &plan.resolved.ceilings.wall,
            LimitKey::Pids => &plan.resolved.ceilings.pids,
            LimitKey::Mem => &plan.resolved.ceilings.mem,
            LimitKey::Cpu => &plan.resolved.ceilings.cpu,
        };
        if let Some(ceiling) = ceiling {
            out.push(AppliedLimit {
                key: key.as_str().to_owned(),
                requested: ceiling.requested.clone(),
                required: ceiling.required,
                applied: false,
                mechanism: None,
                scope: None,
                hit: None,
            });
        }
    }
    out
}

// J3-launch begin: vendor state and credential staging (§7, §8.1, §12)

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
    deadline: Instant,
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
    let forbidden = forbidden_identities(&plan.resolved, &plan.workspace)?;
    let mut staged =
        match crate::credentials::stage_within(launch, vendor.as_fd(), &forbidden, deadline) {
            Ok(staged) => staged,
            Err(refusal) => {
                // Both the receipt rows and the private provenance of every
                // input staged before the refusal are kept (§12).
                record.credentials = refusal.records();
                state::record_staged_credentials(
                    attempt_dir,
                    &private_provenance(&refusal.staged),
                )?;
                return Err(refusal.error);
            }
        };
    record.credentials = staged
        .iter()
        .map(|credential| credential.record.clone())
        .collect();
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
    state::mount_alias::forbidden_identities(&launch_forbidden_roots(resolved, workspace)).map_err(
        |error| {
            usage(
                "launch.credentials",
                format!("writable grants cannot be inspected: {error}"),
            )
        },
    )
}

/// Copies a tree observation into the receipt's lifetime group.
fn record_tree(record: &mut AttemptRecord, tree: &crate::platform::TreeObservation) {
    record.lifetime.tree_empty = tree.tree_empty;
    record.lifetime.verified_at = tree.verified_at.map(rfc3339_utc);
    record.lifetime.verification_scope = Some(tree.verification_scope.clone());
    record.lifetime.integrity.clone_from(&tree.integrity);
}

/// Whether the receipt's lifetime facts permit removing vendor state (§12):
/// no boundary was ever created, or its teardown verified the tree empty.
/// Lost integrity never permits it.
fn cleanup_reason_to_wait(record: &AttemptRecord) -> Option<&'static str> {
    if record.lifetime.integrity == "lost" {
        return Some(cleanup::REASON_INTEGRITY_LOST);
    }
    if record.lifetime.boundary == "pending" || record.lifetime.tree_empty == Some(true) {
        return None;
    }
    Some(cleanup::REASON_TREE_UNVERIFIED)
}

/// Retains registered vendor state, recording why (§12: "Attempts with
/// unproved live trees retain state").
fn retain_vendor_state(attempt_dir: &AttemptDir, record: &mut AttemptRecord) {
    let reason = cleanup_reason_to_wait(record).unwrap_or(cleanup::REASON_TREE_UNVERIFIED);
    record.state_cleanup = StateCleanup::Pending;
    record.cleanup_error = Some(reason.to_owned());
    let _ = state::record_cleanup(attempt_dir, StateCleanup::Pending, Some(reason));
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
    if cleanup_reason_to_wait(record).is_some() {
        retain_vendor_state(attempt_dir, record);
        return;
    }
    record.state_cleanup = StateCleanup::Pending;
    record.cleanup_error = None;
    if let Err(error) = persist(attempt_dir, record, Phase::Refused, args, journal) {
        record.errors.push(error.to_object());
        record.cleanup_error = Some("state_write_failed".to_owned());
        return;
    }
    let result = cleanup::remove_vendor_state(attempt_dir, cleanup::Limits::DEFAULT);
    record.state_cleanup = result.status;
    record.cleanup_error = result.reason;
}
// J3-launch end

// J3-agent begin: `gc` of a dead supervisor's proxy directory (§14.2)
/// Runs [`state::gc_proxy_dir`], says in `proxy_dir` what became of the
/// directory (one whose read or removal failed is a cleanup that did not
/// complete, §6.4: `gc` exits 1; one whose identity cannot be proven is
/// retained and said so, §14.2), then resumes the vendor-state cleanup
/// exactly as before.
fn gc_proxy_then_resume(
    dir: &AttemptDir,
    name: &str,
    dry_run: bool,
    incomplete: &mut Vec<String>,
    proxy_dir: &mut Option<String>,
) -> Result<cleanup::Resume, JailError> {
    *proxy_dir = match state::gc_proxy_dir(dir, dry_run) {
        Ok(outcome) => {
            // §6.4, §14.2: an identity gc cannot prove is a skip reported
            // with its reason; a read or removal that failed is a failed
            // cleanup.
            if let state::ProxyDirGc::Failed(reason) = &outcome {
                incomplete.push(format!("{name} (proxy directory: {reason})"));
            }
            outcome.describe()
        }
        Err(error) => {
            incomplete.push(format!("{name} ({})", error.code.as_str()));
            Some(format!("failed: {}", error.code.as_str()))
        }
    };
    cleanup::resume(dir, dry_run)
}
// J3-agent end

// J3-agent begin: the proxy directory (§10)
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
fn remove_proxy_directory(attempt_dir: &AttemptDir, record: &mut AttemptRecord) {
    match state::remove_proxy_dir(attempt_dir) {
        Ok(state::ProxyDirRemoval::Retained(reason)) => {
            record.errors.push(
                JailError::new(
                    ErrorCode::StateWriteFailed,
                    ErrorStage::Reconciling,
                    Remediation::InspectState,
                    format!("the proxy directory was retained: {reason}"),
                )
                .to_object(),
            );
        }
        Ok(_) => {}
        Err(error) => record.errors.push(error.to_object()),
    }
}
// J3-agent end

// J3-agent begin: an inherited ignored disposition is the operator's
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
// J3-agent end

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
}

impl Journal {
    fn new(attempt_id: &str, trace: SharedTrace) -> Self {
        Journal {
            attempt_id: attempt_id.to_owned(),
            trace,
            loss: None,
            loss_pending: false,
        }
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
    fn receipt(&mut self, phase: Phase, receipt: &Receipt, terminal: bool) {
        let digest = serde_json::to_vec(receipt)
            .map(|bytes| crate::canonical::sha256_prefixed(&bytes))
            .unwrap_or_else(|_| "sha256:".to_owned());
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
/// Returns [`ErrorCode::StateWriteFailed`] when either copy cannot be written.
pub fn write_receipt(
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    extra_copy: Option<&Path>,
) -> Result<Receipt, JailError> {
    write_receipt_with(attempt_dir, record, phase, extra_copy, &state::Fsync)
}

/// [`write_receipt`] against an explicit durability implementation, the seam
/// failure injection uses to fail each sync step.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when either copy cannot be written.
pub fn write_receipt_with(
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    extra_copy: Option<&Path>,
    durable: &dyn state::Durable,
) -> Result<Receipt, JailError> {
    record.updated_at = SystemTime::now();
    let receipt = record.receipt(phase);
    let bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| {
        JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the receipt could not be serialized: {error}"),
        )
    })?;
    let canonical = state::TempWrite::create_with(&attempt_dir.receipt_path(), &bytes, durable)?;
    // J4-D4: the rename below can land and a later step still fail (its
    // directory sync, or the extra copy), leaving this revision visible under
    // an error. Spending it here, before the rename, means the next receipt
    // never carries the same number with different content.
    record.revision += 1;
    canonical.commit()?;
    if let Some(path) = extra_copy {
        state::replace_atomically_with(path, &bytes, durable)?;
    }
    Ok(receipt)
}

fn persist(
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    args: &RunArgs,
    journal: &mut Journal,
) -> Result<Receipt, JailError> {
    let receipt = write_receipt(attempt_dir, record, phase, args.receipt.as_deref())?;
    journal.receipt(
        phase,
        &receipt,
        matches!(phase, Phase::Settled | Phase::Refused),
    );
    Ok(receipt)
}

/// Finish the last note before publishing the control receipt. A loss during
/// that drain requires one durable correction, without another trace write
/// that could recursively fail and invalidate the correction.
fn persist_terminal(
    attempt_dir: &AttemptDir,
    record: &mut AttemptRecord,
    phase: Phase,
    args: &RunArgs,
    journal: &mut Journal,
) -> Result<Receipt, JailError> {
    let receipt = persist(attempt_dir, record, phase, args, journal)?;
    if let Ok(mut sink) = journal.trace.lock() {
        sink.finish();
    }
    if let Some(error) = journal.take_new_loss() {
        record.errors.push(error.to_object());
        degrade_trace_coverage(record);
        return write_receipt(attempt_dir, record, phase, args.receipt.as_deref());
    }
    Ok(receipt)
}

fn claim_attempt(
    attempt_dir: &AttemptDir,
    attempt_id: &AttemptId,
    ctx: &Context,
) -> Result<(), JailError> {
    use std::os::unix::fs::OpenOptionsExt as _;
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
    let state = serde_json::json!({
        "schema": "ouro.jail.state/1",
        "attempt_id": attempt_id.as_str(),
        "os": identity.os.as_str(),
        "arch": identity.arch,
        "kernel": identity.kernel,
        "component_version": env!("CARGO_PKG_VERSION"),
        "claimed_at": rfc3339_utc(SystemTime::now()),
        // §7: boot identity and the live owner's birth identity, so a
        // reconciler can tell this attempt's supervisor from a recycled pid
        // without parsing a receipt.
        "owner": owner.map_or(serde_json::Value::Null, |owner| {
            serde_json::json!({
                "pid": owner.pid,
                "boot_id": owner.boot_id,
                "start_time_ticks": owner.start_time_ticks,
            })
        }),
        "boundary": serde_json::Value::Null,
        "vendor_state": serde_json::Value::Null,
        "state_cleanup": "not_needed",
    });
    let path = attempt_dir.state_path();
    // §7: claim the root with exclusive creation while holding the lock. A
    // previous jail claim, live or dead, refuses rather than spawning again.
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(state::FILE_MODE)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(JailError::new(
                ErrorCode::AttemptExists,
                ErrorStage::Resolving,
                Remediation::InspectState,
                "this attempt directory already carries a jail claim".to_owned(),
            ));
        }
        Err(error) => {
            return Err(JailError::new(
                ErrorCode::StateWriteFailed,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("{}: {error}", path.display()),
            ));
        }
    };
    let bytes = serde_json::to_vec_pretty(&state).unwrap_or_default();
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            // §7: a claim the directory does not remember is a claim a power
            // loss can erase; every other state write syncs the parent, and
            // the exclusive create deserves the same guarantee.
            std::fs::File::open(path.parent().unwrap_or(Path::new(".")))
                .and_then(|dir| dir.sync_all())
        })
        .map_err(|error| {
            JailError::new(
                ErrorCode::StateWriteFailed,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("{}: {error}", path.display()),
            )
        })
}

/// Record the registered execution boundary in the state file (§7), so crash
/// reconciliation and GC can identify the boundary without parsing a receipt.
fn register_boundary_in_state(
    attempt_dir: &AttemptDir,
    boundary: &crate::platform::BoundaryIdentity,
) -> Result<(), JailError> {
    let path = attempt_dir.state_path();
    let raw = std::fs::read_to_string(&path).map_err(|error| {
        JailError::new(
            ErrorCode::StateWriteFailed,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("{}: {error}", path.display()),
        )
    })?;
    let mut state: serde_json::Value = serde_json::from_str(&raw).map_err(|error| {
        JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the attempt state could not be parsed back: {error}"),
        )
    })?;
    state["boundary"] = serde_json::json!({
        "kind": boundary.boundary,
        "verification_scope": boundary.verification_scope,
        "backend": boundary.backend,
        "backend_version": boundary.backend_version,
        "process": boundary.process,
    });
    let bytes = serde_json::to_vec_pretty(&state).map_err(|error| {
        JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the attempt state could not be serialized: {error}"),
        )
    })?;
    state::replace_atomically(&path, &bytes)
}

fn write_policy_file(attempt_dir: &AttemptDir, plan: &Plan) -> Result<(), JailError> {
    let snapshot = plan.resolved.snapshot.to_canonical_value()?;
    let envelope = serde_json::json!({
        "schema": SCHEMA_POLICY_FILE,
        "snapshot": snapshot,
        "policy_digest": plan.resolved.digest,
        "provenance": plan.resolved.provenance,
    });
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(|error| {
        JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the policy envelope could not be serialized: {error}"),
        )
    })?;
    state::replace_atomically(&attempt_dir.policy_path(), &bytes)
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
    queue: std::collections::VecDeque<u8>,
    dropped: u64,
    seq: u64,
}

/// Total control queue: four terminal frames' worth.
pub const CONTROL_QUEUE_MAX: usize = 4 * crate::records::CONTROL_FRAME_MAX;
/// Capacity inside that queue that only a terminal message may use.
pub const CONTROL_QUEUE_RESERVE: usize = crate::records::CONTROL_FRAME_MAX;

impl ControlSink {
    /// The next message number (§8.2: monotonically increasing per attempt).
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
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
        if self.queue.len() + frame.len() > budget {
            self.dropped += 1;
            return false;
        }
        self.queue.extend(frame.iter().copied());
        self.flush_now();
        true
    }

    /// Writes what fits without blocking. A full pipe leaves the rest queued.
    fn flush_now(&mut self) {
        while !self.queue.is_empty() {
            let chunk = self.queue.as_slices().0.to_vec();
            match self.file.write(&chunk) {
                Ok(0) => break,
                Ok(written) => {
                    self.queue.drain(..written);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                // WouldBlock or a broken pipe: the supervisor keeps going. The
                // control channel is reporting, not an approval protocol.
                Err(_) => break,
            }
        }
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
        queue: std::collections::VecDeque::new(),
        dropped: 0,
        seq: 0,
    }))
}

fn open_trace(args: &RunArgs, attempt_dir: &AttemptDir) -> Result<SharedTrace, JailError> {
    if let Some(fd) = args.trace_fd {
        // SAFETY: as for the control descriptor: exclusively owned for this
        // invocation and already validated as open for writing.
        let sink = unsafe { FdSink::from_raw_fd(fd) }?;
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
    // S9: the only environment input here is the shrink-only test seam; the
    // sink names it in every loss it records, so the receipt that reports
    // the loss also reports the seam.
    Ok(trace::shared(FileSink::for_attempt(
        file,
        std::env::var(trace::TRACE_CAP_SEAM).ok().as_deref(),
    )))
}

/// Publishes one control message (§8.2).
///
/// The message number comes from the sink, so it counts every message of the
/// attempt in order: it used to restart at 1 for a refusal, which made
/// `prepared` and `refused` indistinguishable from two separate attempts.
fn send_control(
    control: Option<&mut ControlSink>,
    record: &AttemptRecord,
    kind: ControlKind,
    phase: Phase,
    receipt: &Receipt,
) {
    let Some(control) = control else { return };
    let digest = serde_json::to_vec(receipt)
        .map(|bytes| crate::canonical::sha256_prefixed(&bytes))
        .unwrap_or_else(|_| "sha256:".to_owned());
    let message = ControlMessage {
        schema: crate::records::SCHEMA_CONTROL.to_owned(),
        attempt_id: record.attempt_id.clone(),
        seq: control.next_seq(),
        kind,
        receipt_phase: phase,
        receipt_digest: digest,
        outcome: record.outcome.clone(),
        error: record.outcome.error.clone(),
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
    let deadline = Instant::now() + budget;
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
        let remaining = deadline.saturating_duration_since(Instant::now());
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
        if !poll_readable(fd, signal_fd, remaining)? {
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
            // J3-agent begin: a signal the operator's environment ignores
            // (`nohup`, a background job of a non-interactive shell) stays
            // ignored: the supervisor honours it, and the ignored disposition
            // reaches the target across every exec. Catching it would reset
            // it to the default in every child.
            if super::signals_inherited_ignored(signal) {
                continue;
            }
            // J3-agent end
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
    use crate::records::Os;

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
            profile: ProfileName::None,
            workspace: PathBuf::from("/work"),
            config_dir: PathBuf::from("/config"),
            data_dir: PathBuf::from("/data"),
        });
        assert_eq!(applied.network.mode, "host");
        assert!(applied.filesystem.is_none());
        assert!(applied.syscalls.is_none());
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
