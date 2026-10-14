//! The contained boundary: preparation, discovery, release and teardown.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

use crate::platform::{
    BoundaryIdentity, PreparedExecution, PreparedPlan, RunningExecution, Sinks, Teardown,
    TreeObservation,
};
use crate::policy::{PolicySnapshot, ProfileName, ProtectedCoverage, ScratchRoot};
use crate::records::{
    Applied, AppliedFilesystem, AppliedMount, AppliedNetwork, AppliedSyscalls, ErrorCode,
    ErrorStage, JailError, NativeLifetime, NativeString, ObserveMode, Os,
    ProcessIdentity as RecordIdentity, ProcessRecord, Remediation,
};
use crate::supervisor::TREE_BUDGET;

use super::audit::AuditWriter;
use super::bwrap::{self, Placeholder, PlaceholderOutcome};
use super::cgroup::ExecutionCgroup;
use super::clock::{self};
use super::exec::{self, BootstrapChild, BootstrapSpawn, FdMap};
use super::fs as jfs;
use super::identity;
use super::identity::read_environment_names;
use super::mounts::{
    PlanPaths, absent_runtime_candidate, host_path_of, is_allowed_device_node,
    mount_swap_rendezvous, plan_for, prepare_mounts, read_mount_table, recordable_mounts,
    refuse_pseudo_fs_grants, refuse_unrecordable_mounts, resolve_path_ref, scan_coverage,
    skipped_protected_names, stage_sanitized_resolv_conf, staged_mounts,
};
use super::platform::{
    ARGS_FD, ERROR_FD, PINNED_FD_BASE, RELEASE_FD, SECCOMP_FD, STATUS_FD, TRACE_DATA_FD,
    VENDOR_STATE_FD, error, preparing,
};
use super::running::{LinuxRunning, WAIT_STEP, shared};
use super::seccomp;
use super::stdio::{StdioPlan, StdioRelay, validate_stdio};
use super::sys::{nap, set_nonblocking, write_all, write_until};
use super::tracer::{Tracer, TracerSummary};
use super::verdict::{AbortInputs, abort_verdict, observer_verdict};

/// Audit 2026-09-25-2, S14; reworded by audit 3 (A5): a per-attempt value for
/// the narrowing filter's `SECCOMP_RET_DATA`, unpredictable to the child. The
/// kernel's data field is sixteen bits, so this is a speed bump rather than a
/// wall. What a guess costs: a stop carrying this attempt's data on a number
/// the narrowing filter does not trace is a visible `unexpected_trace_stop`
/// gap, so forging our verdict costs the receipt its evidence one gap at a
/// time, and strict evidence fails on the first — while a stop carrying other
/// data is another filter's own request, continued and counted in
/// `requested_by_other_filters`, which the receipt's
/// `lifetime.native.details` carries. Guessing is therefore never silent:
/// every stop lands in the receipt as a gap or as a count.
pub(super) fn random_trace_data() -> u16 {
    use std::hash::{BuildHasher, Hasher as _};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(u64::from(std::process::id()));
    match (hasher.finish() & 0xffff) as u16 {
        // Zero would collide with a child filter that sets no data.
        0 => super::tracer::filter::NARROWING_TRACE_DATA,
        value => value,
    }
}

/// The most a stop gives the proxy to drain its last results (§10).
pub(super) const AGENT_STOP_BUDGET: Duration = Duration::from_secs(2);

/// The named roots the audit path classification knows besides the workspace
/// and scratch (issue draft 10): every operator grant by its in-jail
/// spelling, and the system read-only roots, so exec paths like
/// `/usr/bin/git` and writes under a `--ro` grant are named instead of
/// digested.
pub(super) fn audit_named_roots(bplan: &bwrap::BwrapPlan) -> Vec<(Vec<u8>, String)> {
    let mut roots = Vec::new();
    for (_, dest) in bplan
        .extra_ro_binds
        .iter()
        .chain(bplan.extra_rw_binds.iter())
        .chain(bplan.extra_dev_binds.iter())
    {
        roots.push((
            dest.as_os_str().as_bytes().to_vec(),
            dest.display().to_string(),
        ));
    }
    for path in bwrap::RUNTIME_ROOTS.iter().chain(std::iter::once(&"/etc")) {
        roots.push((path.as_bytes().to_vec(), "system".to_owned()));
    }
    roots
}

// ---------------------------------------------------------------------------
// Preparation
// ---------------------------------------------------------------------------

/// bubblewrap's JSON status documents, read incrementally.
pub(super) struct StatusReader {
    pub(super) fd: OwnedFd,
    pub(super) text: String,
    pub(super) eof: bool,
}

impl StatusReader {
    pub(super) fn new(fd: OwnedFd) -> Self {
        StatusReader {
            fd,
            text: String::new(),
            eof: false,
        }
    }

    /// Reads whatever is available without blocking.
    pub(super) fn pump(&mut self) {
        if self.eof {
            return;
        }
        let mut buffer = [0u8; 4096];
        loop {
            // SAFETY: the buffer is live and the length matches; the
            // descriptor is owned and non-blocking.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if n > 0 {
                let read = usize::try_from(n).unwrap_or(0);
                self.text
                    .push_str(&String::from_utf8_lossy(&buffer[..read]));
                continue;
            }
            if n == 0 {
                self.eof = true;
            }
            return;
        }
    }

    pub(super) fn parsed(&self) -> bwrap::BwrapStatus {
        bwrap::parse_json_status(&self.text)
    }

    pub(super) fn namespace(&self, key: &str) -> Option<u64> {
        let at = self.text.find(&format!("\"{key}\""))?;
        let rest = &self.text[at..];
        let colon = rest.find(':')?;
        let digits: String = rest[colon + 1..]
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    }
}

/// Everything the boundary owns, from preparation through settlement.
pub(super) struct Boundary {
    pub(super) snapshot: PolicySnapshot,
    pub(super) workspace: PathBuf,
    pub(super) child: Option<BootstrapChild>,
    pub(super) bootstrap_spawn: BootstrapSpawn,
    pub(super) bwrap_pid: libc::pid_t,
    /// A descriptor for bubblewrap, taken while it was this process's
    /// unreaped child. A pid number can come to mean another process; a
    /// pidfd cannot (§9.3).
    pub(super) bwrap_fd: OwnedFd,
    pub(super) init_pid: libc::pid_t,
    /// The same, for the namespace init. Discovery refuses without it, so it
    /// is missing only before discovery.
    pub(super) init_fd: Option<OwnedFd>,
    pub(super) launcher: identity::ProcessIdentity,
    /// The launcher's own descriptor, for the cooperative stop. Discovery
    /// refuses without it, so it is missing only before discovery.
    pub(super) launcher_fd: Option<OwnedFd>,
    pub(super) launcher_argv: Vec<Vec<u8>>,
    /// The paths the launcher will try to `execve`, derived from the same
    /// program name and `PATH` the launcher itself uses. The observer's exec
    /// snapshot must be one of them.
    pub(super) target_images: Vec<Vec<u8>>,
    pub(super) release: Option<OwnedFd>,
    pub(super) error: OwnedFd,
    pub(super) error_bytes: Vec<u8>,
    pub(super) error_eof: bool,
    pub(super) status: StatusReader,
    pub(super) tracer: Option<Tracer>,
    pub(super) tracer_summary: Option<TracerSummary>,
    pub(super) audit: AuditWriter,
    pub(super) placeholders: Vec<Placeholder>,
    pub(super) placeholder_outcomes: Vec<PlaceholderOutcome>,
    pub(super) applied: Applied,
    /// What the backend reported, read again for this attempt; `None` when
    /// it could not be asked.
    pub(super) backend_version: Option<String>,
    pub(super) resolv_sanitization: &'static str,
    pub(super) observe_on: bool,
    /// The §11.4 bounds the observer runs with, decided once; `None` with
    /// observation off.
    pub(super) observer_plan: Option<super::observed::ObserverPlan>,
    /// Audit 2026-09-25-2, S14: the narrowing filter's per-attempt
    /// `SECCOMP_RET_DATA`, shared only with the launcher (through the
    /// trace-data pipe) and the tracer.
    pub(super) trace_data: u16,
    pub(super) ns_ids: identity::NsIds,
    pub(super) cgroup: Option<ExecutionCgroup>,
    pub(super) storage: Option<super::storage::Storage>,
    /// Whether the installed baseline denies `link` and `linkat`, read from
    /// the program itself; the storage ceiling's evidence states it.
    pub(super) hard_links_denied: bool,
    pub(super) cgroup_lost: bool,
    /// Why no execution cgroup exists, when preferred ceilings run unenforced.
    pub(super) cgroup_unavailable: Option<String>,
    /// Audit 2026-10-08 H1 follow-up: the regular-file stdio streams,
    /// relayed through supervisor-owned pipes so the child holds no
    /// reopenable handle on any file.
    pub(super) stdio_relays: Vec<StdioRelay>,
    pub(super) watcher: super::watch::Watcher,
    // The agent network, and the filter count read back
    /// The proxy, mediator and bridge of an `agent` attempt.
    pub(super) agent: Option<super::agent::AgentNet>,
    /// Set before this boundary kills anything: what dies after it did not
    /// die on its own.
    pub(super) killing: std::sync::atomic::AtomicBool,
    /// `Seccomp_filters` of the blocked launcher, read back and checked
    /// against what this boundary installs.
    pub(super) seccomp_filters: Option<u32>,
}
impl Boundary {
    /// Whether the backend's pidfd reports its exit, independent of whether
    /// its status has been collected yet.
    pub(super) fn backend_exited(&self) -> bool {
        super::watch::readable(self.bwrap_fd.as_raw_fd())
    }
    /// The watcher stays until released or until this supervisor is gone
    /// (§9.3). It is released only once the backend has ended, so its end
    /// still means the backend's end to the verdicts that wait for it.
    pub(super) fn release_watcher_after_backend(&mut self) {
        if self.backend_exited() {
            self.watcher.release();
        }
    }
    pub(super) fn cgroup_empty(&self) -> bool {
        !self.cgroup_lost
            && self
                .cgroup
                .as_ref()
                .is_none_or(|leaf| matches!(leaf.populated(), Ok(false)))
    }
    #[allow(clippy::too_many_lines)]
    pub(super) fn create(
        bwrap_path: &Path,
        backend_pin: &jfs::PinnedPath,
        plan: PreparedPlan,
        sinks: Sinks,
        deadline: clock::Deadline,
    ) -> Result<Boundary, JailError> {
        let snapshot = plan.request.snapshot.clone();
        shared::refuse_privileged_supervisor()?;
        if !snapshot.profile.is_contained() {
            // `prepare` hands `none` to its own boundary before this point.
            return Err(error(
                ErrorCode::InternalError,
                ErrorStage::Preparing,
                Remediation::InspectState,
                "the contained boundary was asked to run the uncontained `none` profile".to_owned(),
            ));
        }
        let observe_on = snapshot.observation.mode == ObserveMode::On;
        let exe = std::env::current_exe().map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("this binary's own path cannot be read: {err}"),
            )
        })?;

        // `<data>/attempts/<id>` is the attempt; the state root is two levels
        // up, and everything under it is supervisor state (§7).
        let state_root = plan
            .attempt_dir
            .parent()
            .and_then(Path::parent)
            .unwrap_or(plan.attempt_dir.as_path());
        let stdio_plans = validate_stdio(state_root, &plan.config_dir)?;

        // The scratch directory the child sees as /tmp. A managed one is
        // supervisor state and gets the private identity; an operator's
        // `--scratch` is the operator's own directory (resolved and checked
        // against the state root at resolving), whose mode is theirs.
        let scratch = match &snapshot.roots.scratch {
            ScratchRoot::Managed => {
                let scratch = plan.attempt_dir.join("scratch");
                crate::state::create_private_dir(&scratch)?;
                scratch
            }
            ScratchRoot::Host { path } => {
                let scratch = PathBuf::from(OsString::from_vec(path.as_bytes().to_vec()));
                ensure_dir(&scratch)?;
                scratch
            }
        };

        let cgroup_required = [
            &snapshot.limits.pids,
            &snapshot.limits.mem,
            &snapshot.limits.swap,
            &snapshot.limits.cpu,
        ]
        .into_iter()
        .flatten()
        .any(|limit| limit.required);
        let mut cgroup_unavailable = None;
        // J4 W2-S: N7 — registered in jail state before `mkdir` and before
        // anything is placed in it; a failed registration refuses (S5).
        let created = ExecutionCgroup::create_for_attempt(&snapshot.limits, &plan.attempt_dir)?;
        let cgroup = match created {
            Ok(leaf) => Some(leaf),
            Err(err) if cgroup_required => {
                return Err(preparing(
                    ErrorCode::MissingCapability,
                    format!("required execution cgroup could not be configured: {err}"),
                ));
            }
            // Preferred ceilings run unenforced, and the record says why
            // (§6.4): the reason reaches the native details and a wrapper note.
            Err(err) => {
                cgroup_unavailable = Some(err.to_string());
                None
            }
        };

        // north-star §4.4 / jail-v1 §9.1: Linux cannot enforce
        // all_descendants; a profile that requires it refuses (125) rather
        // than underclaim.
        if snapshot.filesystem.protected_coverage == ProtectedCoverage::AllDescendants {
            return Err(error(
                ErrorCode::MissingCapability,
                ErrorStage::Preparing,
                Remediation::Unsupported,
                "the all_descendants protected-path coverage cannot be enforced on Linux; \
                 it refuses rather than underclaim (north-star §4.4)"
                    .to_owned(),
            ));
        }

        // Protected segments. A bound reached is a refusal, never a shorter
        // answer (§9.1). The walk's names are the snapshot's own segments:
        // every contained baseline carries exactly its literals (`tool` the
        // built-in `.git`/`.ouroboros`, `agent` — audit 2026-10-08 M5 — only
        // `.git/hooks` and `.git/config`, so the rest of Git metadata stays
        // writable), so merging the built-ins in again here would protect
        // more than the profile asked for.
        let mut names: Vec<String> = snapshot.filesystem.protected_segments.clone();
        names.sort_unstable();
        names.dedup();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut bplan = plan_for(
            &snapshot,
            &PlanPaths {
                bwrap: bwrap_path,
                workspace: &plan.workspace,
                scratch: &scratch,
                jail_exe: &exe,
                proxy_dir: plan
                    .proxy
                    .as_ref()
                    .map(|handoff| handoff.host_path.as_path()),
            },
        )?;
        let mut agent = if snapshot.profile == ProfileName::Agent {
            let Some(handoff) = plan.proxy.as_ref() else {
                return Err(preparing(
                    ErrorCode::MissingCapability,
                    "the `agent` proxy could not be established: no proxy directory was prepared",
                ));
            };
            let agent = super::agent::AgentNet::prepare(
                &plan.attempt_id,
                sinks.trace.clone(),
                &snapshot,
                handoff,
                &exe,
                bwrap_path,
            )?;
            Some(agent)
        } else {
            None
        };
        if let Some(handoff) = &plan.launch
            && !handoff.vault.is_empty()
        {
            use std::os::fd::AsFd as _;
            let vault_io = |e| {
                preparing(
                    ErrorCode::CredentialUnavailable,
                    format!("vault public CA cannot be staged: {e}"),
                )
            };
            let vault = std::sync::Arc::new(
                crate::vault::Vault::new(&plan.attempt_id, handoff.vault.clone())
                    .map_err(|e| preparing(ErrorCode::CredentialUnavailable, e))?,
            );
            let vendor = handoff
                .vendor_state
                .as_ref()
                .ok_or_else(|| preparing(ErrorCode::InternalError, "vault has no private state"))?;
            let dir = crate::state::anchored::Dir::from_owned(
                vendor.fd.as_fd().try_clone_to_owned().map_err(vault_io)?,
            );
            let name =
                crate::state::anchored::Name::new(b".ouro-vault-ca.pem").map_err(vault_io)?;
            let mut cert = dir.create_file_at(&name, 0o600).map_err(vault_io)?;
            use std::io::Write as _;
            cert.write_all(vault.ca_pem().as_bytes())
                .map_err(vault_io)?;
            let destination = PathBuf::from("/run/ouro/vault-ca.pem");
            bplan.extra_ro_binds.push((
                vendor.host_path.join(".ouro-vault-ca.pem"),
                destination.clone(),
            ));
            for (name, value) in vault.environment() {
                bplan.env.push((name.into(), value.into()));
            }
            for name in ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"] {
                bplan.env.retain(|(key, _)| key != name);
                bplan
                    .env
                    .push((name.into(), destination.clone().into_os_string()));
            }
            agent
                .as_mut()
                .ok_or_else(|| preparing(ErrorCode::InvalidConfig, "vault requires agent network"))?
                .configure_vault(vault);
        }
        // The staged vendor state and bind_ro sources, bound
        // by the descriptors staging examined (§9.1, §12).
        let staged = staged_mounts(&snapshot, plan.launch.as_ref())?;
        if staged.vendor.is_some() {
            bplan.vendor_state = plan
                .launch
                .as_ref()
                .and_then(|handoff| handoff.vendor_state.as_ref())
                .map(|vendor| bwrap::Staged {
                    host: vendor.host_path.clone(),
                    fd: VENDOR_STATE_FD,
                });
        }
        bplan.credential_binds = staged
            .credentials
            .iter()
            .map(|(_, destination)| bwrap::CredentialBind {
                fd: None,
                destination: destination.clone(),
            })
            .collect();

        // Operator grants are enforced, not merely recorded (I02, north-star
        // §4.2): read-only grants become additional ro-binds at their
        // resolved paths, host-rooted writable grants become binds, and
        // denied paths are masked with a sealed directory or file. A writable
        // grant inside the writable workspace or the scratch is covered by
        // their base binds already; a read-only grant there is layered over
        // them.
        for reference in &snapshot.filesystem.read_write {
            if let Ok(host) = host_path_of(reference, &plan.workspace, &scratch) {
                // Issue draft 15: an allowlisted device node (the NVIDIA
                // class) binds individually with `--dev-bind`, never as a
                // devtmpfs surface.
                if is_allowed_device_node(&host) {
                    let destination = resolve_path_ref(reference, &plan.workspace)?;
                    bplan
                        .extra_dev_binds
                        .push((host, PathBuf::from(destination)));
                    continue;
                }
                if (bplan.workspace_access == bwrap::WorkspaceAccess::Writable
                    && host.starts_with(&plan.workspace))
                    || host.starts_with(&scratch)
                {
                    // Inside a base writable bind already; layering an extra
                    // bind of the same content would add nothing.
                    continue;
                }
                let destination = resolve_path_ref(reference, &plan.workspace)?;
                bplan
                    .extra_rw_binds
                    .push((host, PathBuf::from(destination)));
            }
        }
        for reference in &snapshot.filesystem.read_only {
            if let Ok(host) = host_path_of(reference, &plan.workspace, &scratch) {
                // The runtime plan already renders merged-/usr aliases as
                // symlinks and pins their real roots. Do not reopen /bin or
                // /lib as an operator bind (or mount over those aliases).
                // Baseline runtime candidates are optional distribution
                // paths: ARM64 Debian, for example, has /lib but no /lib64.
                // BwrapPlan already discovers and records the roots that
                // exist. Do not turn an absent default into a required bind.
                // Errors other than absence still reach pinning and refuse.
                if absent_runtime_candidate(reference, &host)
                    || bplan.etc_paths.contains(&host)
                    || bplan.roots.iter().any(|root| match root {
                        jfs::RootSpec::RoBind(path) | jfs::RootSpec::Symlink { path, .. } => {
                            path == &host
                        }
                    })
                {
                    continue;
                }
                if is_allowed_device_node(&host) {
                    return Err(error(
                        ErrorCode::InvalidConfig,
                        ErrorStage::Preparing,
                        Remediation::Configuration,
                        format!(
                            "the device grant {} binds only read-write (--rw): bubblewrap has \
                             no read-only device bind",
                            host.display()
                        ),
                    ));
                }
                let destination = resolve_path_ref(reference, &plan.workspace)?;
                bplan
                    .extra_ro_binds
                    .push((host, PathBuf::from(destination)));
            }
        }
        for reference in &snapshot.filesystem.deny_read {
            let destination = resolve_path_ref(reference, &plan.workspace)?;
            let path = PathBuf::from(destination);
            // Classification changes only the overlay's type, never grants
            // access to the denied object. A type swap before mounting fails
            // setup rather than releasing an unmasked target.
            let host = host_path_of(reference, &plan.workspace, &scratch)?;
            let mask = match std::fs::metadata(&host) {
                Ok(metadata) if !metadata.is_dir() => bwrap::Mask::File(path),
                Ok(_) => bwrap::Mask::Directory(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    bwrap::Mask::Directory(path)
                }
                Err(error) => {
                    return Err(preparing(
                        ErrorCode::BackendUnavailable,
                        format!("cannot classify denied path {}: {error}", host.display()),
                    ));
                }
            };
            bplan.masked.push(mask);
        }

        // Security 2026-09-25 (audit F5): bind a sanitized resolver view.
        // The host's `/etc/resolv.conf` can carry the operator's search
        // domains — host facts the child has no grant for. The child's
        // resolver is unreachable inside its network namespace either way;
        // the copy keeps the nameservers and drops `search`/`domain` lines.
        let (resolv_source, resolv_sanitization) = stage_sanitized_resolv_conf(&plan.attempt_dir)?;
        bplan.resolv_source = Some(resolv_source);

        // §9.1: an operator grant may not expose host /proc, /sys or
        // cgroupfs. Checked here, before any mount, on the resolved source by
        // filesystem type and mount topology (never by spelling), so it
        // refuses before exec. The baseline runtime roots are on the root
        // filesystem and pass; the child's private /proc and /dev are made by
        // bubblewrap, not bound from these sources.
        refuse_pseudo_fs_grants(
            &[(plan.workspace.clone(), plan.workspace.clone())],
            "workspace",
        )?;
        if let crate::policy::ScratchRoot::Host { path } = &plan.request.snapshot.roots.scratch {
            let source = PathBuf::from(std::ffi::OsString::from_vec(path.as_bytes().to_vec()));
            refuse_pseudo_fs_grants(&[(source.clone(), source)], "scratch")?;
        }
        refuse_pseudo_fs_grants(&bplan.extra_ro_binds, "filesystem.read_only")?;
        refuse_pseudo_fs_grants(&bplan.extra_rw_binds, "filesystem.read_write")?;

        // Until the boundary owns them, every refusal drops `placeholders`,
        // which removes the directories it made in the operator's workspace.
        let (scan, pins, pinned_fds, placeholders) = prepare_mounts(
            &mut bplan,
            &plan.attempt_dir,
            &name_refs,
            snapshot.filesystem.protected_coverage,
        )?;
        // Credential views take the slots after the pins
        let credential_base = PINNED_FD_BASE + pinned_fds.len() as RawFd;
        for (index, view) in bplan.credential_binds.iter_mut().enumerate() {
            view.fd = Some(credential_base + index as RawFd);
        }

        // A storage ceiling rests on a filter that denies new mounts, which
        // the `NamespaceInner` agent variant permits.
        if bplan.bounded_storage
            && agent
                .as_ref()
                .is_some_and(|agent| agent.variant() == seccomp::AgentVariant::NamespaceInner)
        {
            return Err(preparing(
                ErrorCode::MissingCapability,
                "storage ceilings require a profile that cannot create new mounts",
            ));
        }
        // `agent` installs the baseline its network built once, in the variant
        // the measured nested-namespace capability selected (§9.2), so the
        // digest its receipt detail names is the digest of what runs.
        let filter = match agent.as_ref() {
            Some(agent) => agent.baseline().clone(),
            None => seccomp::tool_baseline_with_storage(bplan.bounded_storage).map_err(|err| {
                preparing(
                    ErrorCode::BackendUnavailable,
                    format!("the syscall filter could not be built: {err}"),
                )
            })?,
        };
        let filter_digest = filter.digest();
        // A storage ceiling rests on the hard-link denials (a link could
        // charge a foreign inode to the bounded tree), and its receipt
        // evidence states them. Both read the program that is installed, so
        // neither can claim a rule it lacks.
        let variant = agent.as_ref().map(super::agent::AgentNet::variant);
        let hard_links_denied = match installed_hard_link_rule(&filter, variant) {
            Ok(denied) if denied == bplan.bounded_storage => denied,
            Ok(denied) => {
                return Err(preparing(
                    ErrorCode::InternalError,
                    format!(
                        "the syscall filter {} hard links while a storage ceiling is {}",
                        if denied { "denies" } else { "permits" },
                        if denied { "not requested" } else { "requested" }
                    ),
                ));
            }
            Err(reason) => {
                return Err(preparing(
                    ErrorCode::InternalError,
                    format!("the syscall filter's hard-link rule cannot be read: {reason}"),
                ));
            }
        };

        let target: Vec<OsString> = plan
            .argv
            .iter()
            .map(|bytes| OsString::from_vec(bytes.clone()))
            .collect();
        // The agent launcher mediates and starts the bridge
        let trace_data = if observe_on {
            Some(random_trace_data())
        } else {
            None
        };
        bplan.inner = super::launch::LaunchArgs {
            release_fd: RELEASE_FD,
            error_fd: ERROR_FD,
            narrow: observe_on,
            read_open_fast_path: observe_on && !snapshot.observation.learning,
            trace_data_fd: trace_data.map(|_| TRACE_DATA_FD),
            mediate: agent
                .is_some()
                .then_some((super::agent::LISTENER_FD, super::agent::SOCKDIAG_FD)),
            bridge: agent.is_some().then_some(super::agent::BRIDGE_REPORT_FD),
            // bubblewrap unblocks SIGCHLD in its child: the launcher puts
            // back the mask this supervisor inherited.
            sigmask: Some(super::launch::blocked_mask()),
            argv: target.clone(),
        }
        .command_line(OsStr::new(bwrap::JAIL_INSIDE_PATH));
        bplan.seccomp_fd = Some(SECCOMP_FD);
        bplan.json_status_fd = Some(STATUS_FD);
        bplan.args_fd = Some(ARGS_FD);
        let launcher_argv: Vec<Vec<u8>> = bplan
            .inner
            .iter()
            .map(|part| part.as_bytes().to_vec())
            .collect();
        let child_path = bplan
            .env
            .iter()
            .find(|(name, _)| name == "PATH")
            .map(|(_, value)| value.clone());
        let target_images = super::launch::exec_candidate_bytes(
            target.first().map_or(OsStr::new(""), OsString::as_os_str),
            child_path.as_deref(),
        )
        .map_err(|err| {
            error(
                ErrorCode::InvalidConfig,
                ErrorStage::Preparing,
                Remediation::Configuration,
                err.to_string(),
            )
        })?;

        refuse_unrecordable_mounts(
            &bplan,
            0,
            scan.segments.len() + bplan.placeholders.len(),
            skipped_protected_names(&scan).len(),
        )?;
        let rendered = bplan.render().map_err(|err| {
            error(
                ErrorCode::InvalidConfig,
                ErrorStage::Preparing,
                Remediation::Configuration,
                err.to_string(),
            )
        })?;

        // Room for the credential views after the pins
        let mut fds = FdMap::with_target_limit(
            PINNED_FD_BASE + pinned_fds.len() as RawFd + staged.credentials.len() as RawFd,
        );
        // §8.2: a wait that the preparation budget ended (the watcher's
        // readiness, the arguments' write) refuses as the budget's timeout,
        // with remediation `retry`, not as a host failure of the step that
        // happened to be waiting.
        let io = |err: std::io::Error| {
            if err.kind() == std::io::ErrorKind::TimedOut {
                return prepare_timeout(&format!(
                    "preparation did not complete within its budget: {err}"
                ));
            }
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the boundary's channels could not be created: {err}"),
            )
        };
        fds.add(seccomp::program_pipe(&filter).map_err(io)?, SECCOMP_FD)
            .map_err(io)?;
        let (release_r, release_w) = exec::pipe().map_err(io)?;
        let (error_r, error_w) = exec::pipe().map_err(io)?;
        let (status_r, status_w) = exec::pipe().map_err(io)?;
        let (start_r, start_w) = exec::pipe().map_err(io)?;
        fds.add(start_r, super::watch::START_FD).map_err(io)?;
        fds.add(
            backend_pin.borrow_fd().try_clone_to_owned().map_err(io)?,
            super::watch::BACKEND_FD,
        )
        .map_err(io)?;
        fds.add(release_r, RELEASE_FD).map_err(io)?;
        fds.add(error_w, ERROR_FD).map_err(io)?;
        // Audit 2026-09-25-2, S14: the narrowing data is already in the pipe
        // before the spawn, so the launcher's blocking read always completes;
        // the descriptor closes in the launcher and never reaches the target.
        if let Some(data) = trace_data {
            let (trace_r, trace_w) = exec::pipe().map_err(io)?;
            // Two bytes always fit the pipe's capacity, so the write
            // completes before any reader exists.
            write_all(trace_w.as_raw_fd(), &super::sys::trace_data_bytes(data)).map_err(io)?;
            fds.add(trace_r, TRACE_DATA_FD).map_err(io)?;
        }
        fds.add(status_w, STATUS_FD).map_err(io)?;
        for (copy, target) in pinned_fds {
            fds.add(copy, target).map_err(io)?;
        }
        // Hand the staged descriptors to bubblewrap
        if let Some(vendor) = staged.vendor {
            fds.add(vendor, VENDOR_STATE_FD).map_err(io)?;
        }
        // The proxy directory, bound read-only by descriptor
        if let Some(agent) = agent.as_ref() {
            fds.add(agent.dir_fd().map_err(io)?, super::agent::PROXY_DIR_FD)
                .map_err(io)?;
        }
        for ((source, _), view) in staged.credentials.into_iter().zip(&bplan.credential_binds) {
            let Some(target) = view.fd else {
                return Err(preparing(
                    ErrorCode::InternalError,
                    "a credential view has no descriptor slot",
                ));
            };
            fds.add(source, target).map_err(io)?;
        }
        // jail-v1 §2 I07 (every wait bounded): the `--args` payload can exceed
        // the pipe's capacity, so it must be written while the reader exists.
        // bwrap is spawned below first and blocks reading ARGS_FD; writing
        // before the spawn deadlocked the supervisor on a full pipe with no
        // reader. If bwrap dies before consuming the payload, the write fails
        // with EPIPE instead of hanging. `exec::pipe` is close-on-exec on both
        // ends, so the parent's write end never reaches bwrap and its EOF is
        // seen as soon as this side closes.
        let mut args_writer = None;
        if rendered.args_payload.is_some() {
            let (args_r, args_w) = exec::pipe().map_err(io)?;
            fds.add(args_r, ARGS_FD).map_err(io)?;
            args_writer = Some(args_w);
        }
        set_nonblocking(error_r.as_raw_fd()).map_err(io)?;
        set_nonblocking(status_r.as_raw_fd()).map_err(io)?;

        let arguments: Vec<OsString> = std::iter::once(OsString::from("__backend"))
            .chain(rendered.argv.iter().cloned())
            .collect();
        // J5-B2 seam: give a test a deterministic window between pinning and
        // the mount-handoff verification below to replace a pinned source, so
        // the source-identity-swap refusal (F04) can be proved through the CLI.
        mount_swap_rendezvous();
        // §9.1 mount-handoff verification: the workspace and every pinned
        // protected segment must still resolve to the objects that were
        // scanned, or the run refuses rather than bind a replacement.
        for directory in &scan.directories {
            directory
                .verify()
                .map_err(|e| preparing(ErrorCode::MissingCapability, e.to_string()))?;
        }
        backend_pin.verify_executable().map_err(|e| {
            preparing(
                ErrorCode::InternalError,
                format!("the pinned backend changed before spawn: {e}"),
            )
        })?;
        for pin in &pins {
            pin.verify().map_err(|err| {
                preparing(
                    ErrorCode::BackendUnavailable,
                    format!("a protected path changed during preparation: {err}"),
                )
            })?;
        }
        // §8.3: stdio passes through without capture except regular files and sockets,
        // which are relayed through supervisor-owned pipes (audit
        // 2026-10-08 H1): the child gets a pipe end here and never the
        // file, so no `/dev/stdin` reopen can reach the host mount. Every
        // other descriptor the supervisor holds is closed on exec.
        let mut stdio_relays = Vec::new();
        for (fd, plan) in stdio_plans.into_iter().enumerate() {
            if let StdioPlan::Relay { socket } = plan {
                stdio_relays.push(StdioRelay::attach(
                    i32::try_from(fd).unwrap_or(-1),
                    fd == 0,
                    socket,
                    &mut fds,
                )?);
            }
        }
        let spawn_cgroup = cgroup
            .as_ref()
            .map(ExecutionCgroup::spawn_handle)
            .transpose()
            .map_err(io)?;
        let child = exec::spawn_bootstrap(&exe, &arguments, &fds, spawn_cgroup.as_ref(), deadline)
            .map_err(|err| {
                // The exec handshake spends the same preparation budget.
                if err.kind() == std::io::ErrorKind::TimedOut {
                    return io(err);
                }
                preparing(
                    ErrorCode::BackendUnavailable,
                    format!(
                        "the backend bootstrap ({}) could not be started: {err}",
                        exe.display()
                    ),
                )
            })?;
        // Until the boundary owns it, every refusal below kills and reaps the
        // backend, within a fresh tree budget (§8.1: a pre-exec failure
        // refuses and leaves no orphan).
        let child = exec::KillOnDrop::new(child);
        let bootstrap_spawn = child.spawn();
        // In particular close our duplicate of ARGS_FD before streaming: if
        // the backend exits there must be no reader left to suppress EPIPE.
        drop(fds);
        let bwrap_pid = libc::pid_t::try_from(child.id()).map_err(|_| {
            preparing(
                ErrorCode::InternalError,
                format!("the backend's pid {} does not fit a pid_t", child.id()),
            )
        })?;
        // Taken while the backend is this process's unreaped child, so the
        // descriptor names it; every later signal and exit check uses it.
        let bwrap_fd = identity::pidfd_open(bwrap_pid).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the backend's pidfd could not be opened: {err}"),
            )
        })?;
        // Root the cgroup namespace in this attempt's leaf. Moving only the
        // target after bubblewrap unshares exposes a /../../host-leaf path in
        // /proc/self/cgroup. Direct creation still requires the same parent
        // readback; the compatibility path moves the blocked bootstrap first.
        if let Some(leaf) = &cgroup {
            if child.created_in_cgroup() {
                leaf.verify_member(bwrap_pid)
            } else {
                leaf.place(bwrap_pid)
            }
            .map_err(io)?;
        }
        let cgroup_kill = cgroup
            .as_ref()
            .map(ExecutionCgroup::kill_handle)
            .transpose()
            .map_err(io)?;
        let watcher =
            super::watch::Watcher::start(&exe, bwrap_pid, cgroup_kill, deadline).map_err(io)?;
        write_all(start_w.as_raw_fd(), &[1]).map_err(io)?;
        drop(start_w);
        // The payload write happens with bwrap already blocked on ARGS_FD, so
        // a payload larger than the pipe's capacity flows through instead of
        // deadlocking. A failure here means bwrap died reading.
        if let (Some(args_w), Some(payload)) =
            (args_writer.as_ref(), rendered.args_payload.as_ref())
        {
            write_until(args_w.as_raw_fd(), payload, deadline).map_err(io)?;
        }
        drop(args_writer);

        let workspace_path = plan.workspace.clone();
        let mut boundary = Boundary {
            audit: AuditWriter::new(
                &plan.attempt_id,
                sinks.trace.clone(),
                plan.workspace.as_os_str().as_bytes(),
                bwrap::SCRATCH_INSIDE_PATH.as_bytes(),
            )
            .with_learning(snapshot.observation.learning)
            .with_roots(audit_named_roots(&bplan)),
            snapshot,
            workspace: workspace_path,
            child: Some(child.hand_over()),
            bootstrap_spawn,
            bwrap_pid,
            bwrap_fd,
            init_pid: -1,
            init_fd: None,
            launcher: identity::ProcessIdentity {
                pid: -1,
                boot_id: String::new(),
                start_time_ticks: 0,
            },
            launcher_fd: None,
            launcher_argv,
            target_images,
            release: Some(release_w),
            error: error_r,
            error_bytes: Vec::new(),
            error_eof: false,
            status: StatusReader::new(status_r),
            tracer: None,
            tracer_summary: None,
            placeholders: placeholders.hand_over(),
            placeholder_outcomes: Vec::new(),
            applied: Applied {
                filesystem: None,
                network: AppliedNetwork {
                    mode: "pending".to_owned(),
                    mechanism: None,
                    allowed_hosts: Vec::new(),
                    tls_only: Vec::new(),
                },
                syscalls: None,
                limits: Vec::new(),
                environment_names: Vec::new(),
                removed_environment_names: Vec::new(),
            },
            backend_version: None,
            resolv_sanitization,
            observe_on,
            observer_plan: observe_on.then(super::observed::ObserverPlan::from_env),
            trace_data: trace_data.unwrap_or(super::tracer::filter::NARROWING_TRACE_DATA),
            ns_ids: identity::NsIds::default(),
            cgroup,
            cgroup_lost: false,
            cgroup_unavailable,
            storage: None,
            hard_links_denied,
            stdio_relays,
            watcher,
            agent: agent.take(),
            killing: std::sync::atomic::AtomicBool::new(false),
            seccomp_filters: None,
        };
        // The proxy starts only now that the backend exists,
        // so the descriptor limit it raises never reaches the child.
        if let Some(agent) = boundary.agent.as_mut()
            && let Err(err) = agent.start_proxy()
        {
            return Err(boundary.refuse(err));
        }
        if let Some(reason) = boundary.cgroup_unavailable.clone() {
            for (key, ceiling) in [
                ("pids", &boundary.snapshot.limits.pids),
                ("mem", &boundary.snapshot.limits.mem),
                ("swap", &boundary.snapshot.limits.swap),
                ("cpu", &boundary.snapshot.limits.cpu),
            ] {
                if ceiling.is_some() {
                    boundary.audit.record_limit_unapplied(key, &reason);
                }
            }
        }

        if let Err(err) = boundary.discover(bwrap_path, deadline, &filter_digest, &scan) {
            return Err(boundary.refuse(err));
        }
        // Audit 2026-10-08 M2: storage and inode ceilings expose occupancy,
        // not refusal counters — their hit evidence is positive-only
        // saturation sampling (§11.4), so the `limits` class starts degraded
        // with a null count and names its gap.
        if boundary
            .storage
            .as_ref()
            .is_some_and(|storage| storage.limits().iter().any(|limit| limit.hit.is_none()))
        {
            boundary
                .audit
                .record_limit_evidence_missing("storage_hit_evidence_positive_only");
        }
        if let Some(leaf) = boundary.cgroup.as_mut()
            && let Err(err) = leaf
                .verify_member(boundary.launcher.pid)
                .and_then(|()| leaf.verify_member(boundary.bwrap_pid))
                .and_then(|()| leaf.verify_member(boundary.init_pid))
                .and_then(|()| leaf.arm())
        {
            // Placement can have succeeded before read-back failed. Never
            // discard that leaf and claim the target has no resource boundary.
            return Err(boundary.refuse(preparing(
                ErrorCode::MissingCapability,
                format!("target cgroup placement failed: {err}"),
            )));
        }
        if let Some(plan) = boundary.observer_plan.as_ref() {
            // §13.1: gap intervals count from supervisor start on the same
            // CLOCK_BOOTTIME base as every other monotonic_ns. §11.4: the
            // bounds are the plan's, which the receipt records.
            let mut config = plan.tracer_config(clock::mark_supervisor_start());
            // Audit 2026-09-25-2, S14: the tracer expects exactly the data
            // this attempt's narrowing filter carries.
            config.trace_data = boundary.trace_data;
            config.learning = boundary.snapshot.observation.learning;
            // Resolution validated these rules; rules that no longer
            // compile are refused, never matched in part.
            config.commands = match boundary.snapshot.commands.compile() {
                Ok(filter) => filter,
                Err(reason) => {
                    return Err(boundary.refuse(
                        error(
                            ErrorCode::InvalidConfig,
                            ErrorStage::Preparing,
                            Remediation::Configuration,
                            format!("the command rules do not compile: {reason}"),
                        )
                        .with_key_path("jail.commands"),
                    ));
                }
            };
            config.target = Some((boundary.launcher.pid, boundary.target_images.clone()));
            match Tracer::attach(boundary.launcher.pid, config) {
                Ok(tracer) => boundary.tracer = Some(tracer),
                Err(err) => {
                    // §11.4: an observer that cannot attach refuses before
                    // exec, whatever the evidence mode says.
                    return Err(boundary.refuse(error(
                        ErrorCode::ObserverUnavailable,
                        ErrorStage::Preparing,
                        Remediation::HostSetup,
                        format!("the closed-set observer could not attach: {err}"),
                    )));
                }
            }
        }
        Ok(boundary)
    }

    /// Finds the namespace init and the launcher, and reads back what the
    /// boundary actually applied.
    pub(super) fn discover(
        &mut self,
        bwrap_path: &Path,
        deadline: clock::Deadline,
        filter_digest: &str,
        scan: &jfs::ProtectedScan,
    ) -> Result<(), JailError> {
        // bubblewrap reports the namespace init's host pid as soon as the
        // namespaces exist. Waiting on that document is the synchronisation
        // point; nothing here guesses a delay.
        let init_pid = loop {
            self.status.pump();
            if let Some(pid) = self.status.parsed().child_pid {
                break pid;
            }
            if self.status.eof || self.exited() {
                let diagnostic = self.diagnostic().trim().to_owned();
                let detail = if diagnostic.is_empty() {
                    // bwrap's own message (for example "Unknown option")
                    // went to this console's stderr, which the supervisor
                    // passes through untouched; the error must still say
                    // something useful instead of ending on a colon.
                    let status = self
                        .child
                        .as_mut()
                        .and_then(|child| child.try_wait().ok().flatten())
                        .and_then(|wait| wait.code().map(|code| format!("exit {code}")))
                        .unwrap_or_else(|| "no wait status".to_owned());
                    format!(
                        "bubblewrap exited during setup ({status}) without a status \
                         document; its own stderr on this console names the cause"
                    )
                } else {
                    format!("bubblewrap exited during setup: {diagnostic}")
                };
                return Err(preparing(ErrorCode::BackendUnavailable, detail));
            }
            if deadline.expired() {
                return Err(prepare_timeout(
                    "bubblewrap did not report a namespace init",
                ));
            }
            nap();
        };
        self.init_pid = init_pid;
        // Taken now, while the kernel has just named this pid as the
        // namespace init: every later signal and liveness check goes through
        // the descriptor, so neither can reach a process that merely
        // inherited the number. Without it the tree's death could not be
        // verified, so its absence refuses.
        self.init_fd = Some(identity::pidfd_open(init_pid).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the namespace init's pidfd could not be opened: {err}"),
            )
        })?);

        // The launcher is the init's child whose argv is the one we asked for.
        let launcher = loop {
            if let Some(pid) = super::tracer::children(init_pid)
                .into_iter()
                .find(|pid| super::tracer::cmdline(*pid).as_ref() == Some(&self.launcher_argv))
            {
                break pid;
            }
            if deadline.expired() {
                return Err(prepare_timeout("the inside launcher never appeared"));
            }
            if self.exited() {
                return Err(self.launcher_setup_failure());
            }
            nap();
        };

        // Wait until it is blocked in read(2) on its release descriptor,
        // which is what the observer's attach contract requires.
        // `/proc/<pid>/syscall` names the call and its first argument, so
        // this is a read-back and not an assumption. The descriptor is part
        // of the check: the launcher reads its trace-data descriptor before
        // it installs the narrowing filter, and that read is not the gate.
        loop {
            if matches!(identity::blocked_in_read(launcher, RELEASE_FD), Ok(true)) {
                break;
            }
            if deadline.expired() {
                return Err(prepare_timeout(
                    "the inside launcher did not block on its release pipe",
                ));
            }
            if self.exited() {
                return Err(self.launcher_setup_failure());
            }
            nap();
        }

        self.launcher = identity::ProcessIdentity::capture(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's identity could not be recorded: {err}"),
            )
        })?;
        // The cooperative stop and the `agent` mediation hand-off go through
        // this descriptor; without it neither could, so its absence refuses.
        let launcher_fd = identity::pidfd_open(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's pidfd could not be opened: {err}"),
            )
        })?;
        // bubblewrap reports the namespace ids it created; `/proc` says which
        // namespaces the launcher is actually in. Recording the first without
        // checking the second would be taking the backend's word for the
        // boundary, so both are read and they must agree.
        self.ns_ids = identity::ns_ids(launcher);
        // Every namespace the plan asked for has to be one the launcher is
        // actually in, and a different one from this process's.
        // SAFETY: getpid takes no arguments and cannot fail.
        let own = identity::ns_ids(unsafe { libc::getpid() });
        for (name, inside, outside) in [
            ("pid", self.ns_ids.pid, own.pid),
            ("mnt", self.ns_ids.mnt, own.mnt),
            ("net", self.ns_ids.net, own.net),
            ("user", self.ns_ids.user, own.user),
            ("cgroup", self.ns_ids.cgroup, own.cgroup),
        ] {
            match (inside, outside) {
                (Some(inside), Some(outside)) if inside == outside => {
                    return Err(preparing(
                        ErrorCode::BackendUnavailable,
                        format!("the launcher shares this process's {name} namespace"),
                    ));
                }
                (None, _) => {
                    return Err(preparing(
                        ErrorCode::BackendUnavailable,
                        format!("the launcher's {name} namespace could not be read"),
                    ));
                }
                _ => {}
            }
        }
        for (key, seen) in [
            ("pid-namespace", self.ns_ids.pid),
            ("mnt-namespace", self.ns_ids.mnt),
            ("net-namespace", self.ns_ids.net),
        ] {
            let reported = self.status.namespace(key);
            if let (Some(reported), Some(seen)) = (reported, seen)
                && reported != seen
            {
                return Err(preparing(
                    ErrorCode::BackendUnavailable,
                    format!("the backend reports {key} {reported} but the launcher is in {seen}"),
                ));
            }
        }

        // Read back the boundary rather than trusting the flags we passed.
        // The launcher is blocked: these facts come from one kernel status
        // snapshot rather than reopening the same file for every field.
        let privilege = identity::Privilege::read(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's privilege cannot be read back: {err}"),
            )
        })?;
        if !privilege.no_new_privs {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                "no_new_privs is not set inside the boundary",
            ));
        }
        if privilege.cap_eff != 0 {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!(
                    "the boundary retains capabilities: CapEff {:016x}",
                    privilege.cap_eff
                ),
            ));
        }
        if privilege.seccomp.as_deref() != Some("2") {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!(
                    "the syscall filter is not in force: Seccomp {:?}",
                    privilege.seccomp
                ),
            ));
        }
        // The J2 gap — `Seccomp: 2` says a filter is in
        // force, not that every filter this boundary installs is: a missing
        // narrowing or mediation filter leaves the mode at 2. The count is
        // read back and must be exactly the number installed.
        let expected =
            super::agent::expected_launcher_filters(self.agent.is_some(), self.observe_on);
        self.seccomp_filters = Some(
            super::agent::verify_filter_count(
                privilege.seccomp_filters.as_deref().unwrap_or_default(),
                expected,
            )
            .map_err(|mut error| {
                error.message = format!("the launcher: {}", error.message);
                error
            })?,
        );
        let nspid = super::tracer::nspid(launcher).unwrap_or_default();
        if nspid.len() < 2 {
            return Err(preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher is not inside a pid namespace: NSpid {nspid:?}"),
            ));
        }

        // While the launcher is blocked, take its mediation
        // listener and sock_diag socket, start the mediator, and read back
        // the bridge it started (§10). Either one missing refuses, naming it.
        if let Some(agent) = self.agent.as_mut() {
            agent.take_mediation(std::os::fd::AsFd::as_fd(&launcher_fd))?;
            let bridge = agent.discover_bridge(self.init_pid, self.ns_ids, &deadline)?;
            if let Some(leaf) = self.cgroup.as_ref() {
                // Charged to the attempt (§9.3): the bridge is in the leaf.
                leaf.verify_member(bridge).map_err(|err| {
                    preparing(
                        ErrorCode::MissingCapability,
                        format!(
                            "the `agent` bridge could not be established: it is not in the \
                             attempt's cgroup: {err}"
                        ),
                    )
                })?;
            }
        }
        self.launcher_fd = Some(launcher_fd);

        // Keep this fresh readback: a process can create a new platform after
        // a backend upgrade, while its minimum-version decision is cached.
        self.backend_version = bwrap::bwrap_version(bwrap_path, deadline)
            .ok()
            .map(|version| version.raw);

        if super::storage::requested(&self.snapshot.limits) {
            self.storage = Some(
                super::storage::Storage::admit(launcher, &self.snapshot.limits, deadline).map_err(
                    |err| {
                        preparing(
                            ErrorCode::MissingCapability,
                            format!("storage ceiling unavailable: {err}"),
                        )
                    },
                )?,
            );
        }
        self.applied = self.read_applied(launcher, filter_digest, scan)?;
        Ok(())
    }

    // Why the launcher ended before it blocked
    /// The refusal for a backend that ended before the launcher blocked.
    /// The agent launcher's own setup failures carry their exit status and
    /// errno, so the refusal names the mechanism that could not be
    /// established instead of a generic backend failure.
    pub(super) fn launcher_setup_failure(&mut self) -> JailError {
        self.status.pump();
        let (mut errno_bytes, mut eof) = (Vec::new(), false);
        shared::drain_error_pipe(&self.error, &mut errno_bytes, &mut eof);
        launcher_failure(
            self.status.parsed().exit_code,
            &errno_bytes,
            self.diagnostic().trim(),
        )
    }

    /// The `applied` group, read back from the boundary that exists. A
    /// read-back that fails refuses: an empty mount table or environment in
    /// the receipt would be a claim about the child's view nothing measured.
    pub(super) fn read_applied(
        &self,
        launcher: libc::pid_t,
        filter_digest: &str,
        scan: &jfs::ProtectedScan,
    ) -> Result<Applied, JailError> {
        let mounts = read_mount_table(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's mount table cannot be read back: {err}"),
            )
        })?;
        let environment_names = read_environment_names(launcher).map_err(|err| {
            preparing(
                ErrorCode::BackendUnavailable,
                format!("the launcher's environment cannot be read back: {err}"),
            )
        })?;
        let mut limits = Vec::new();
        if let Some(storage) = &self.storage {
            limits.extend(storage.limits());
        }
        limits.extend(shared::ceiling_rows(
            &self.snapshot.limits,
            self.cgroup.as_ref(),
        ));
        let mut mounts = mounts;
        // A protected name the walk refused to follow is authority this plan
        // did not apply. The mount table is where §13.2 lists what the child's
        // view is, and `hidden` is the mode the schema has for a path that is
        // named and not granted, so each one appears there rather than being
        // left out of the record entirely.
        for name in skipped_protected_names(scan) {
            let path = self.workspace_bytes_joined(&name);
            if let Ok(native) = NativeString::from_bytes(path) {
                mounts.push(AppliedMount {
                    path: native,
                    mode: "hidden".to_owned(),
                });
            }
        }
        let mounts = recordable_mounts(mounts)?;
        Ok(Applied {
            filesystem: Some(AppliedFilesystem {
                mechanism: "bubblewrap-binds".to_owned(),
                protected_coverage: if self.snapshot.filesystem.protected_coverage
                    == ProtectedCoverage::None
                {
                    // Audit 2026-09-25-2, S5: nothing was requested or
                    // scanned, so the walk's vacuous pass must not be
                    // reported as existing-and-covered.
                    "none".to_owned()
                } else {
                    scan_coverage(scan)
                },
                mounts,
            }),
            // The agent network and its two stacked filters
            network: self.agent.as_ref().map_or_else(
                || AppliedNetwork {
                    mode: "none".to_owned(),
                    mechanism: Some("network-namespace".to_owned()),
                    allowed_hosts: Vec::new(),
                    tls_only: Vec::new(),
                },
                super::agent::AgentNet::applied_network,
            ),
            syscalls: Some(AppliedSyscalls {
                mechanism: if self.agent.is_some() {
                    "seccomp-bpf+seccomp-user-notification".to_owned()
                } else {
                    "seccomp-bpf".to_owned()
                },
                digest: filter_digest.to_owned(),
            }),
            limits,
            environment_names,
            removed_environment_names: Vec::new(),
        })
    }

    /// A workspace-relative name as the absolute bytes the child sees.
    pub(super) fn workspace_bytes_joined(&self, relative: &str) -> Vec<u8> {
        let mut out = self.workspace.as_os_str().as_bytes().to_vec();
        if out.last() != Some(&b'/') {
            out.push(b'/');
        }
        out.extend_from_slice(relative.as_bytes());
        out
    }

    pub(super) fn diagnostic(&self) -> String {
        self.status.text.clone()
    }

    /// Whether the backend has exited, collecting its status. Only for
    /// discovery: from the observer's attach on, its thread owns every
    /// `waitpid` in this process.
    pub(super) fn exited(&mut self) -> bool {
        debug_assert!(self.tracer.is_none(), "the observer owns waitpid");
        match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(Some(_))),
            None => true,
        }
    }

    /// Kills and reaps everything this boundary owns, and removes its
    /// placeholders once the tree is known dead.
    pub(super) fn teardown(&mut self) {
        let deadline = clock::Deadline::after(TREE_BUDGET);
        self.kill_boundary();
        self.stop_observer(deadline.remaining());
        if let Some(mut child) = self.child.take() {
            child.reap_until(deadline);
        }
        while !self.watcher.ended() && !deadline.expired() {
            self.release_watcher_after_backend();
            std::thread::sleep(WAIT_STEP);
        }
        self.watcher.reap();
        // The init's pidfd and the leaf report the tree's death a little
        // after the kill. Wait for them inside the same budget, so the
        // placeholders are not kept only because the first look came early.
        while self.tree_death_provable() && !self.tree_dead() && !deadline.expired() {
            std::thread::sleep(WAIT_STEP);
        }
        self.remove_placeholders();
        self.stop_agent(deadline.remaining());
    }

    /// Tears the boundary down after a refusal and returns `refusal`, which
    /// then also says which placeholders it leaves in the operator's
    /// workspace and why, when it leaves any.
    pub(super) fn refuse(&mut self, mut refusal: JailError) -> JailError {
        self.teardown();
        if let Some(left) = self.placeholders_left() {
            refusal.message = format!("{}; {left}", refusal.message);
            // What the record says is left stays left: nothing removes them
            // after the refusal named them.
            self.placeholders.clear();
        }
        refusal
    }

    /// The placeholders a teardown did not remove, for a refusal's message;
    /// `None` when every one is gone.
    pub(super) fn placeholders_left(&self) -> Option<String> {
        if self.placeholder_outcomes.is_empty() {
            if self.placeholders.is_empty() {
                return None;
            }
            let paths: Vec<String> = self
                .placeholders
                .iter()
                .map(|placeholder| placeholder.destination().display().to_string())
                .collect();
            return Some(format!(
                "the placeholder directories {} are left in the workspace: the boundary's tree \
                 was not shown dead within its budget",
                paths.join(", ")
            ));
        }
        let kept: Vec<String> = self
            .placeholder_outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                PlaceholderOutcome::Removed(_) | PlaceholderOutcome::AlreadyGone(_) => None,
                PlaceholderOutcome::KeptChanged(path, reason) => {
                    Some(format!("{} ({reason})", path.display()))
                }
                PlaceholderOutcome::KeptNotEmpty(path) => {
                    Some(format!("{} (not empty)", path.display()))
                }
                PlaceholderOutcome::KeptError(path, errno) => Some(format!(
                    "{} ({})",
                    path.display(),
                    super::sys::errno_name(*errno)
                )),
            })
            .collect();
        (!kept.is_empty()).then(|| {
            format!(
                "the placeholder directories {} are kept in the workspace",
                kept.join(", ")
            )
        })
    }

    // The agent network ends after the tree it served
    /// Stops the proxy and the mediator, draining what they last reported.
    /// Called once the tree is dead or given up on: until then the proxy and
    /// the mediator are part of the boundary the child relies on.
    pub(super) fn stop_agent(&mut self, budget: Duration) {
        if let Some(agent) = self.agent.as_mut() {
            agent.stop(
                &mut self.audit,
                self.observe_on,
                budget.min(AGENT_STOP_BUDGET),
            );
        }
    }

    /// Mediated connects and helper facts, while the target runs; the
    /// reason of a new evidence loss, when there is one.
    pub(super) fn pump_agent(&mut self) -> Option<String> {
        let (init_pid, init_fd, killing) = (self.init_pid, self.init_fd.as_ref(), &self.killing);
        // Asked only once the bridge is seen dead: the boundary was up after
        // the bridge died, so the bridge did not die with it. A namespace
        // init sets PF_EXITING before it kills its namespace, and this
        // supervisor sets `killing` before it kills anything.
        let boundary_up = || {
            super::agent::boundary_up(
                killing.load(std::sync::atomic::Ordering::SeqCst),
                &|| init_fd.is_none_or(|fd| super::watch::readable(fd.as_raw_fd())),
                &|| identity::exiting(init_pid),
            )
        };
        let agent = self.agent.as_mut()?;
        agent.pump(&mut self.audit, self.observe_on, &boundary_up)
    }

    /// Kills the namespace init and the backend through their descriptors.
    ///
    /// §9.3: never signal a pid without revalidating its identity. A pidfd
    /// taken at discovery is that revalidation made permanent — the kernel
    /// refuses to deliver through it once the process is gone, so no signal of
    /// this attempt's can land on whatever later holds the number. Killing the
    /// init makes the kernel kill the namespace; the backend outside it goes
    /// too.
    pub(super) fn kill_boundary(&self) {
        self.killing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(leaf) = &self.cgroup {
            let _ = leaf.kill();
        }
        for fd in self.init_fd.iter().chain([&self.bwrap_fd]) {
            let _ = identity::pidfd_send_signal(fd.as_raw_fd(), libc::SIGKILL);
        }
    }

    /// Stops the observer within `budget` and keeps its account.
    ///
    /// `finish_within` always returns: it interrupts the tracer thread, gives
    /// a live tree up to `budget` to end, and on expiry kills what is left
    /// and says how much it had to kill. Draining the channel first matters
    /// because finishing drops the receiver with whatever is still in it.
    pub(super) fn stop_observer(&mut self, budget: Duration) {
        let Some(tracer) = self.tracer.take() else {
            return;
        };
        let target = super::observed::Target {
            launcher: self.launcher.pid,
            images: &self.target_images,
        };
        // Late facts change nothing here: the run loop has already ended.
        let summary = super::observed::stop(tracer, budget, &mut self.audit, &target, |_| {});
        self.tracer_summary = Some(summary);
    }

    /// Whether the observer's own account permits a claim of tree death.
    pub(super) fn observer_verified_the_tree(&self) -> bool {
        observer_verdict(self.tracer_summary.as_ref())
    }

    /// Whether the tree's death can still be shown: the observer's account
    /// does not object and the leaf's identity was never lost.
    pub(super) fn tree_death_provable(&self) -> bool {
        self.observer_verified_the_tree() && !self.cgroup_lost
    }

    /// Whether the tree is seen dead now: the namespace init has ended and
    /// the leaf, when there is one, is unpopulated.
    pub(super) fn tree_dead(&self) -> bool {
        !init_alive(self.init_fd.as_ref(), self.init_pid) && self.cgroup_empty()
    }

    pub(super) fn remove_placeholders(&mut self) {
        if !(self.tree_death_provable() && self.tree_dead()) {
            return;
        }
        if self.placeholder_outcomes.is_empty() {
            self.placeholder_outcomes = self
                .placeholders
                .iter()
                .map(Placeholder::remove_if_unchanged)
                .collect();
        }
    }

    // A verified teardown for a boundary whose target never
    // ran (abort, failed release; §13.2 row 4)
    /// Kills the boundary and reports whether its death was verified.
    ///
    /// Verified means exactly what settlement requires, without the target:
    /// the namespace init's pidfd reports its death (PID-namespace semantics:
    /// every other member, the blocked launcher included, died first); the
    /// backend (this supervisor's child) and the outside watcher are dead and
    /// reaped; the execution cgroup, when one exists, was observed
    /// unpopulated and its identity was never lost; and the observer, when
    /// attached, finished without abandoning a tracee or losing a child's
    /// status. Everything is polled within one tree budget; whatever is still
    /// unknown at its end leaves the tree `pending` and `tree_empty` null.
    /// "The trusted launcher died" is not on the list: it is implied by the
    /// init's death and proves nothing without it.
    pub(super) fn verified_teardown(&mut self) -> TreeObservation {
        let deadline = clock::Deadline::after(TREE_BUDGET);
        self.kill_boundary();
        // The observer is stopped first, so after this nothing but this
        // thread waits for children; its account is kept for the verdict.
        self.stop_observer(deadline.remaining());
        // The target never ran; nothing is left to serve
        self.stop_agent(deadline.remaining());
        let backend_reaped = match self.child.take() {
            Some(mut child) => {
                child.reap_until(deadline);
                match child.try_wait() {
                    Ok(Some(_)) => true,
                    // The tracer's `waitpid(-1)` reaped it before it was
                    // stopped. Nothing else in this process waits, so an
                    // exited backend whose status is gone was reaped here.
                    Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                        self.backend_exited()
                    }
                    _ => false,
                }
            }
            None => false,
        };
        let init_dead = || {
            self.init_fd
                .as_ref()
                .is_some_and(|fd| super::watch::readable(fd.as_raw_fd()))
        };
        loop {
            // As release_watcher_after_backend, by field: `init_dead` holds
            // a borrow of the init's pidfd.
            if super::watch::readable(self.bwrap_fd.as_raw_fd()) {
                self.watcher.release();
            }
            let settled = init_dead() && self.watcher.ended() && self.cgroup_empty();
            if settled || deadline.expired() {
                break;
            }
            std::thread::sleep(WAIT_STEP);
        }
        self.watcher.reap();
        let watcher_reaped = self.watcher.ended();
        // The observer's own account, with one difference from settlement:
        // its "unreaped children" are this supervisor's own children (the
        // backend and the watcher) that were still exiting when it stopped.
        // Here they were reaped above, by this thread, so that loss has a
        // route after all. Any other unreaped child, an abandoned tracee or
        // a panicked observer still refuses the verdict.
        let verified = abort_verdict(&AbortInputs {
            backend_reaped,
            watcher_reaped,
            init_dead: init_dead(),
            cgroup_empty: self.cgroup_empty(),
            abandoned_tracees: self
                .tracer_summary
                .as_ref()
                .map_or(0, |summary| summary.loss.abandoned_tracees),
            observer_panicked: self
                .tracer_summary
                .as_ref()
                .is_some_and(|summary| summary.thread_panicked),
            unreaped_children: self
                .tracer_summary
                .as_ref()
                .map(|summary| summary.unreaped_children.clone())
                .unwrap_or_default(),
            // Security 2026-09-27 (audit 3 A5): carried for the receipt; never a
            // verdict input, because the stop was continued and nothing was
            // lost.
            requested_by_other_filters: self
                .tracer_summary
                .as_ref()
                .map_or(0, |summary| summary.requested_by_other_filters),
            backend_pid: self.bwrap_pid,
            watcher_pid: i32::try_from(self.watcher.pid()).unwrap_or(-1),
        });
        // Placeholders go only once the tree is known dead, and on this
        // verdict rather than the settlement-time one, whose observer check
        // would count the children reaped above as lost.
        if verified && self.placeholder_outcomes.is_empty() {
            self.placeholder_outcomes = self
                .placeholders
                .iter()
                .map(Placeholder::remove_if_unchanged)
                .collect();
        }
        if verified {
            TreeObservation {
                tree_empty: Some(true),
                verified_at: Some(SystemTime::now()),
                verification_scope: "attempt_tree".to_owned(),
                integrity: "verified".to_owned(),
            }
        } else {
            TreeObservation {
                tree_empty: None,
                verified_at: None,
                verification_scope: "attempt_tree".to_owned(),
                integrity: if self.cgroup_lost { "lost" } else { "pending" }.to_owned(),
            }
        }
    }

    pub(super) fn boundary_identity(&self) -> BoundaryIdentity {
        let mut details = Map::new();
        if self
            .snapshot
            .launch
            .as_ref()
            .is_some_and(|l| l.credentials.iter().any(|c| c.mode == "vault"))
        {
            details.insert("credential_injection".into(), Value::from("mitm_ca"));
        }
        details.insert("backend_exec_by".to_owned(), Value::from("descriptor"));
        details.insert(
            "command_rules".into(),
            serde_json::json!({
                "deny": self.snapshot.commands.deny.len(),
                "forbid": self.snapshot.commands.forbid.len(),
            }),
        );
        details.insert(
            "resolv_sanitization".to_owned(),
            Value::from(self.resolv_sanitization),
        );
        details.insert("watcher_pid".to_owned(), Value::from(self.watcher.pid()));
        // J4 autoscope: §9.3 — where the supervisor stood when the leaf was
        // made: already delegated, entered a scope of its own, or why not.
        details.insert("supervisor_scope".to_owned(), super::scope::details());
        details.insert(
            "bootstrap_spawn".to_owned(),
            self.bootstrap_spawn.evidence(),
        );
        details.insert(
            "execution_cgroup".to_owned(),
            match &self.cgroup {
                // The bridge is a helper charged to the leaf
                Some(leaf) => {
                    let mut registration = leaf.registration(self.bwrap_pid, self.init_pid);
                    if let Some(bridge) = self
                        .agent
                        .as_ref()
                        .and_then(super::agent::AgentNet::bridge_pid)
                        && let Some(helpers) = registration
                            .get_mut("charged_helpers")
                            .and_then(Value::as_array_mut)
                    {
                        helpers.push(serde_json::json!({"role": "bridge", "pid": bridge}));
                    }
                    registration
                }
                None => serde_json::json!({
                    "unavailable": self
                        .cgroup_unavailable
                        .as_deref()
                        .unwrap_or("not attempted"),
                }),
            },
        );
        details.insert(
            "bwrap_pid".to_owned(),
            Value::from(i64::from(self.bwrap_pid)),
        );
        if let Some(storage) = &self.storage {
            details.insert(
                "storage_ceiling".to_owned(),
                storage.evidence(self.hard_links_denied),
            );
        }
        details.insert(
            "readonly_open_fast_path".to_owned(),
            Value::from(self.observe_on && !self.snapshot.observation.learning),
        );
        details.insert(
            "namespace_init_pid".to_owned(),
            Value::from(i64::from(self.init_pid)),
        );
        details.insert(
            "launcher_pid".to_owned(),
            Value::from(i64::from(self.launcher.pid)),
        );
        // Two filters are in force and they are not the same program: the
        // baseline bubblewrap loads, recorded in `applied.syscalls`, and the
        // observer's narrowing filter the launcher installs. The receipt names
        // both, by the digest each of them reports for itself. Security
        // 2026-09-27 (audit 4 B9): `narrowing_filter_digest` names the
        // canonical program the published table freezes, and
        // `narrowing_filter_digest_installed` names the bytes this attempt
        // **installed** — the launcher installs the filter carrying the
        // per-attempt trace data (audit 2026-09-25-2, S14), so the canonical
        // digest alone no longer identifies the running program.
        details.insert(
            "narrowing_filter_digest".to_owned(),
            if self.observe_on {
                Value::from(super::tracer::narrowing_filter_digest())
            } else {
                Value::Null
            },
        );
        details.insert(
            "narrowing_filter_digest_installed".to_owned(),
            if self.observe_on {
                Value::from(super::tracer::filter::narrowing_filter_digest_for(
                    self.trace_data,
                    self.snapshot.observation.learning,
                ))
            } else {
                Value::Null
            },
        );
        // §11.4: "Record actual values in the observer plan."
        details.insert(
            "observer_plan".to_owned(),
            self.observer_plan
                .as_ref()
                .map_or(Value::Null, super::observed::ObserverPlan::details),
        );
        // The filter count read back, and the agent network
        details.insert(
            "seccomp_filters".to_owned(),
            self.seccomp_filters.map_or(Value::Null, |count| {
                serde_json::json!({
                    "expected": super::agent::expected_launcher_filters(
                        self.agent.is_some(),
                        self.observe_on,
                    ),
                    "observed": count,
                })
            }),
        );
        if let Some(agent) = self.agent.as_ref() {
            let (agent_details, helpers) = agent.details();
            details.insert("agent".to_owned(), agent_details);
            details.insert("helpers".to_owned(), helpers);
        }
        for (key, value) in [
            ("pid_namespace", self.ns_ids.pid),
            ("mnt_namespace", self.ns_ids.mnt),
            ("net_namespace", self.ns_ids.net),
            ("user_namespace", self.ns_ids.user),
            ("cgroup_namespace", self.ns_ids.cgroup),
        ] {
            details.insert(key.to_owned(), value.map_or(Value::Null, Value::from));
        }
        let mut identity_value = Map::new();
        identity_value.insert("pid".to_owned(), Value::from(i64::from(self.launcher.pid)));
        identity_value.insert(
            "boot_id".to_owned(),
            Value::from(self.launcher.boot_id.clone()),
        );
        identity_value.insert(
            "start_time_ticks".to_owned(),
            Value::from(self.launcher.start_time_ticks),
        );
        BoundaryIdentity {
            boundary: "pid_namespace".to_owned(),
            verification_scope: "attempt_tree".to_owned(),
            native: Some(NativeLifetime {
                os: Os::Linux,
                details,
            }),
            process: Some(ProcessRecord {
                pid: u32::try_from(self.launcher.pid).unwrap_or(0),
                identity: RecordIdentity {
                    kind: "linux_boot_start".to_owned(),
                    value: identity_value,
                },
            }),
            backend: Some("bubblewrap".to_owned()),
            backend_version: self.backend_version.clone(),
        }
    }
}

pub(super) fn prepare_timeout(message: &str) -> JailError {
    error(
        ErrorCode::PrepareTimeout,
        ErrorStage::Preparing,
        Remediation::Retry,
        message.to_owned(),
    )
}

// Naming the mechanism a launcher could not establish
/// The refusal for a launcher that ended before it blocked, from its exit
/// status (as bubblewrap reported it) and the errno it wrote: the agent
/// launcher's mediation and bridge failures name themselves; anything else
/// is the backend's.
pub(super) fn launcher_failure(
    exit_code: Option<i32>,
    errno_bytes: &[u8],
    diagnostic: &str,
) -> JailError {
    let errno = super::launch::decode_error_report(errno_bytes)
        .map_or("no errno reported".into(), super::sys::errno_name);
    match exit_code {
        Some(super::launch::EXIT_MEDIATION_FAILED) => preparing(
            ErrorCode::MissingCapability,
            format!(
                "the `agent` unix-peer mediation could not be established: the launcher could \
                 not install the mediation filter with its listener or open sock_diag ({errno})"
            ),
        ),
        Some(super::launch::EXIT_BRIDGE_FAILED) => preparing(
            ErrorCode::MissingCapability,
            format!(
                "the `agent` bridge could not be established: the launcher could not start it \
                 ({errno})"
            ),
        ),
        _ => preparing(
            ErrorCode::BackendUnavailable,
            format!("bubblewrap exited before the launcher blocked: {diagnostic}"),
        ),
    }
}

/// Accepts an existing directory as it is, or creates it (and its missing
/// parents) private. Only for directories that are not supervisor state:
/// [`crate::state::create_private_dir`] checks those, ancestors included.
pub(super) fn ensure_dir(path: &Path) -> Result<(), JailError> {
    use std::os::unix::fs::DirBuilderExt as _;
    if path.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|err| {
            error(
                ErrorCode::StateWriteFailed,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("{} could not be created: {err}", path.display()),
            )
        })
}

/// Whether `filter`, the baseline bubblewrap installs, denies `link` and
/// `linkat`, read from the program itself: it is matched against its
/// profile's baseline (`tool`'s, or `agent`'s in `variant`) built with and
/// without the storage rules.
///
/// # Errors
/// Why the answer is unknown: a baseline that cannot be built, or a program
/// that is neither of the two, which no preparation installs.
pub(super) fn installed_hard_link_rule(
    filter: &super::bpf::Program,
    variant: Option<seccomp::AgentVariant>,
) -> Result<bool, String> {
    let baseline = |storage| {
        match variant {
            Some(variant) => seccomp::agent_baseline_with_storage(variant, storage),
            None => seccomp::tool_baseline_with_storage(storage),
        }
        .map_err(|err| format!("its baseline cannot be built: {err}"))
    };
    if *filter == baseline(true)? {
        Ok(true)
    } else if *filter == baseline(false)? {
        Ok(false)
    } else {
        Err("it is not its profile's baseline".to_owned())
    }
}

// ---------------------------------------------------------------------------
// Prepared
// ---------------------------------------------------------------------------

pub(super) struct LinuxPrepared {
    pub(super) boundary: Boundary,
}

impl PreparedExecution for LinuxPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        self.boundary.boundary_identity()
    }

    fn applied(&self) -> Option<Applied> {
        Some(self.boundary.applied.clone())
    }

    // A failed release runs the verified teardown and says
    // what it established, instead of tearing down without a verdict.
    fn release(
        self: Box<Self>,
    ) -> Result<Box<dyn RunningExecution>, Box<crate::platform::ReleaseFailure>> {
        let mut boundary = self.boundary;
        if boundary.watcher.ended()
            || boundary
                .storage
                .as_mut()
                .is_some_and(|storage| storage.sample().is_err())
            || boundary
                .cgroup
                .as_ref()
                .is_some_and(|leaf| leaf.verify().is_err())
        {
            let tree = boundary.verified_teardown();
            return Err(Box::new(crate::platform::ReleaseFailure {
                error: preparing(
                    ErrorCode::BackendUnavailable,
                    "lifetime resources were lost before release",
                ),
                teardown: Some(Teardown { tree: Some(tree) }),
            }));
        }
        // Parsed once, before the release: an unparseable ceiling refuses
        // with the launcher still blocked, rather than after the target was
        // released without the deadline the receipt's limit row claims.
        let wall = match clock::wall_ceiling(&boundary.snapshot.limits) {
            Ok(wall) => wall,
            Err(what) => {
                let tree = boundary.verified_teardown();
                return Err(Box::new(crate::platform::ReleaseFailure {
                    error: preparing(
                        ErrorCode::InternalError,
                        format!("the wall limit cannot be enforced: {what}"),
                    ),
                    teardown: Some(Teardown { tree: Some(tree) }),
                }));
            }
        };
        let Some(release) = boundary.release.take() else {
            let tree = boundary.verified_teardown();
            return Err(Box::new(crate::platform::ReleaseFailure {
                error: preparing(
                    ErrorCode::BackendUnavailable,
                    "the release pipe is already closed",
                ),
                teardown: Some(Teardown { tree: Some(tree) }),
            }));
        };
        if let Err(err) = write_all(release.as_raw_fd(), &[1]) {
            let tree = boundary.verified_teardown();
            return Err(Box::new(crate::platform::ReleaseFailure {
                error: preparing(
                    ErrorCode::BackendUnavailable,
                    format!("the release byte could not be written: {err}"),
                ),
                teardown: Some(Teardown { tree: Some(tree) }),
            }));
        }
        // Closing it makes a second release impossible (X03).
        drop(release);
        Ok(Box::new(LinuxRunning {
            boundary,
            // The wall runs from the release.
            wall: wall.map(clock::Deadline::after),
            wall_reported: false,
            exec_confirmed: false,
            target_outcome: None,
            pending: VecDeque::new(),
            stop_requested: None,
            stop_at: None,
            hard_killed: false,
            hard_deadline: None,
            bwrap_status: None,
            finished: false,
            evidence_reported: false,
            sampled_at_ns: 0,
            storage_lost_live: false,
        }))
    }

    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        let mut boundary = self.boundary;
        // The target never ran, but the boundary existed, and
        // whether its teardown completed is a measured fact, established by
        // the same facts settlement requires (see `verified_teardown`).
        Ok(Teardown {
            tree: Some(boundary.verified_teardown()),
        })
    }
}

/// Whether the namespace init is still running: from its pidfd once
/// discovery took one, which turns readable at its exit and cannot come to
/// name another process; before that, whether bubblewrap named an init whose
/// `/proc` entry is still there.
pub(super) fn init_alive(init_fd: Option<&OwnedFd>, init_pid: libc::pid_t) -> bool {
    match init_fd {
        Some(fd) => !super::watch::readable(fd.as_raw_fd()),
        None => init_pid > 0 && Path::new(&format!("/proc/{init_pid}")).exists(),
    }
}

impl Drop for Boundary {
    fn drop(&mut self) {
        if self.child.is_some() || self.tracer.is_some() {
            self.teardown();
        } else {
            self.remove_placeholders();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::platform::tests::plan_request;
    use super::*;

    #[test]
    fn a_launcher_setup_failure_names_the_mechanism_it_could_not_establish() {
        let busy = libc::EBUSY.to_le_bytes();
        let mediation =
            launcher_failure(Some(super::super::launch::EXIT_MEDIATION_FAILED), &busy, "");
        assert_eq!(mediation.code, ErrorCode::MissingCapability);
        assert_eq!(mediation.exit_code(), 125);
        assert!(
            mediation.message.contains("unix-peer mediation"),
            "{}",
            mediation.message
        );
        assert!(mediation.message.contains("EBUSY"), "{}", mediation.message);
        let bridge = launcher_failure(Some(super::super::launch::EXIT_BRIDGE_FAILED), &[], "");
        assert!(
            bridge.message.contains("`agent` bridge"),
            "{}",
            bridge.message
        );
        assert!(bridge.message.contains("no errno reported"));
        let other = launcher_failure(Some(1), &[], "{\"exit-code\": 1}");
        assert_eq!(other.code, ErrorCode::BackendUnavailable);
        assert!(!other.message.contains("agent"));
    }

    /// The init's liveness comes from its pidfd once one is held: a zombie
    /// has exited although its `/proc` entry is still there, and a pid
    /// number can come to name another process, while the descriptor
    /// cannot.
    #[test]
    fn init_liveness_is_read_from_its_pidfd() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let fd = identity::pidfd_open(pid).unwrap();
        assert!(init_alive(Some(&fd), pid));
        child.kill().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !super::super::watch::readable(fd.as_raw_fd()) {
            assert!(
                std::time::Instant::now() < deadline,
                "SIGKILL not delivered"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            Path::new(&format!("/proc/{pid}")).exists(),
            "the unreaped zombie keeps its /proc entry"
        );
        assert!(!init_alive(Some(&fd), pid), "an exited init is not alive");
        child.wait().unwrap();
        assert!(!init_alive(None, -1), "no init named: none alive");
    }

    /// A storage or inode ceiling in the snapshot adds the hard-link denials
    /// to the `agent` baseline bubblewrap installs: the network reads the
    /// ceiling from the snapshot itself, so no caller can build it without
    /// them. The receipt's agent detail names that program — the one
    /// `applied.syscalls.digest` names — never the plain baseline, which does
    /// not run.
    #[test]
    fn the_agent_detail_names_the_installed_baseline_with_its_storage_rules() {
        use super::super::agent::AgentNet;
        use super::super::seccomp::{AgentVariant, agent_baseline_with_storage};
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let ceiling = || {
            Some(crate::policy::LimitCeiling {
                value: "1048576".to_owned(),
                required: true,
            })
        };
        for (name, storage, inodes) in [
            ("unbounded", None, None),
            ("storage", ceiling(), None),
            ("inodes", None, ceiling()),
        ] {
            let mut snapshot = plan_request(ProfileName::Agent, false).snapshot;
            snapshot.limits.storage = storage;
            snapshot.limits.inodes = inodes;
            let bounded_storage = name != "unbounded";
            let proxy = root.join(format!("proxy-{name}"));
            std::fs::create_dir(&proxy).unwrap();
            let dir = crate::state::anchored::Dir::open_trusted(&proxy).unwrap();
            let identity = dir.stat().unwrap().identity();
            let handoff = crate::platform::ProxyDirHandoff {
                host_path: proxy,
                fd: std::sync::Arc::new(dir.into_fd()),
                identity,
                socket: std::sync::Arc::new(std::sync::OnceLock::new()),
            };
            // A relative backend is never executed, so nesting measures
            // unavailable and the variant is the unprivileged one.
            let agent = AgentNet::prepare(
                "att_00000000-0000-4000-8000-000000000001",
                None,
                &snapshot,
                &handoff,
                Path::new("/nonexistent/ouro-jail"),
                Path::new("bwrap"),
            )
            .unwrap();
            assert_eq!(agent.variant(), AgentVariant::UnprivilegedInner);
            let installed =
                agent_baseline_with_storage(AgentVariant::UnprivilegedInner, bounded_storage)
                    .unwrap();
            assert_eq!(agent.baseline(), &installed, "{name}");
            assert_eq!(
                agent.details().0["baseline_filter_digest"],
                installed.digest().as_str(),
                "{name}"
            );
            assert_eq!(
                super::installed_hard_link_rule(agent.baseline(), Some(agent.variant())),
                Ok(bounded_storage),
                "{name}"
            );
        }
        assert_ne!(
            agent_baseline_with_storage(AgentVariant::UnprivilegedInner, true)
                .unwrap()
                .digest(),
            agent_baseline_with_storage(AgentVariant::UnprivilegedInner, false)
                .unwrap()
                .digest(),
            "the storage rules change the installed program"
        );
    }

    /// The storage evidence's hard-link claim is read from the installed
    /// program: each profile's baseline says whether it carries the storage
    /// rules, and a program that is not its profile's baseline has no answer.
    #[test]
    fn the_hard_link_rule_is_read_from_the_installed_program() {
        use super::super::seccomp::{
            AgentVariant, agent_baseline_with_storage, tool_baseline_with_storage,
        };
        for storage in [false, true] {
            assert_eq!(
                super::installed_hard_link_rule(
                    &tool_baseline_with_storage(storage).unwrap(),
                    None
                ),
                Ok(storage)
            );
            for variant in [
                AgentVariant::UnprivilegedInner,
                AgentVariant::NamespaceInner,
            ] {
                assert_eq!(
                    super::installed_hard_link_rule(
                        &agent_baseline_with_storage(variant, storage).unwrap(),
                        Some(variant)
                    ),
                    Ok(storage),
                    "{variant:?}"
                );
            }
        }
        // `tool`'s program is no `agent` baseline, and the reverse.
        assert!(
            super::installed_hard_link_rule(
                &tool_baseline_with_storage(true).unwrap(),
                Some(AgentVariant::UnprivilegedInner)
            )
            .is_err()
        );
        assert!(
            super::installed_hard_link_rule(
                &agent_baseline_with_storage(AgentVariant::NamespaceInner, true).unwrap(),
                None
            )
            .is_err()
        );
    }
}
