//! The `agent` profile's network boundary on Linux: the outside proxy, the
//! unix-peer mediator and the in-namespace bridge, wired into one attempt.
//!
//! jail-v1 §10 and §9.2. What this module owns, in the order preparation
//! uses it:
//!
//! 1. [`AgentNet::prepare`], before bubblewrap starts: measures the host's
//!    `nested_user_namespace` capability and picks the baseline variant it
//!    selects; binds `proxy.sock` inside the registered proxy directory (by
//!    descriptor, never by a path the child could affect), pins the node and
//!    proves the pin is the listener's own by a probe connection through it.
//! 2. [`AgentNet::start_proxy`], once the backend exists: the proxy runs in
//!    this process, outside the sandbox and the execution cgroup, with the
//!    snapshot's rules, the host resolver and the §10 budgets. It is started
//!    after the backend is spawned so the descriptor limit it raises is never
//!    inherited by the child.
//! 3. [`AgentNet::take_mediation`], while the launcher is blocked: takes the
//!    mediation listener and the attempt-netns `sock_diag` socket from it
//!    with `pidfd_getfd` and starts the mediator, which additionally allows
//!    exactly the pinned proxy socket.
//! 4. [`AgentNet::discover_bridge`]: finds the bridge the launcher started,
//!    pins it with a pidfd, and reads back that it listens on
//!    `127.0.0.1:3128` in the attempt's network namespace, under the agent
//!    filters, with no capability.
//!
//! While the target runs, [`AgentNet::pump`] turns mediation records into
//! audit-source `net.connect` results (a mediated connect is not a ptrace
//! stop, so the mediator is its witness) and records a bridge or proxy that
//! stopped. At the end, [`AgentNet::stop`] drains the proxy's results and
//! stops the mediator; its accounting decides `proxy.net` coverage.
//!
//! Evidence sources stay apart (§10, last paragraph): the proxy writes
//! proxy-source results on its own sequence; mediated connects become
//! audit-source results through the attempt's single [`AuditWriter`];
//! helper facts are wrapper notes.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

use crate::network::Rules;
use crate::observer::{ClassSummary, CoverageClass, CoverageSummary};
use crate::platform::ProxyDirHandoff;
use crate::proxy::{
    self, Budgets, ProxyConfig, ProxyDecision, ProxyHandle, ProxyResult, ProxySink, ProxySummary,
    SystemResolver,
};
use crate::records::{ErrorCode, ErrorStage, Event, Gap, JailError, Remediation, SourceStatus};
use crate::state::PROXY_SOCKET_NAME;
use crate::trace::{Priority, SharedTrace};

use super::audit::{AuditWriter, MediatedConnect};
use super::bridge;
use super::identity;
use super::probe::{self, ProbeStatus};
use super::seccomp::{self, AgentVariant};
use super::unixpeer::{self, LauncherFds, MediationRecord, MediationSink, MediatorHandle, Verdict};

/// Descriptor the proxy directory is handed to bubblewrap on.
pub const PROXY_DIR_FD: RawFd = 17;
/// Descriptor the launcher places its mediation listener at.
pub const LISTENER_FD: RawFd = 18;
/// Descriptor the launcher places its attempt-netns `sock_diag` socket at.
pub const SOCKDIAG_FD: RawFd = 19;

/// Bound on the queue between the mediator's threads and the supervision
/// loop. A record that finds it full is counted and becomes a gap.
const RECORD_QUEUE: usize = 4096;
/// How many recent proxy results are kept for diagnostics (doctor).
const RECENT_RESULTS: usize = 16;
/// The proxy's resolver concurrency.
const RESOLVER_IN_FLIGHT: usize = 16;

fn refusal(what: &str, detail: impl std::fmt::Display) -> JailError {
    JailError::new(
        ErrorCode::MissingCapability,
        ErrorStage::Preparing,
        Remediation::HostSetup,
        format!("the `agent` {what} could not be established: {detail}"),
    )
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

/// What one proxy result said, kept for diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentResult {
    /// The destination, as the proxy normalized it.
    pub destination: Option<String>,
    /// Allowed or denied.
    pub allowed: bool,
    /// The proxy's safe reason code.
    pub reason: &'static str,
}

#[derive(Default)]
struct ProxyTally {
    seq: u64,
    delivered: u64,
    lost: u64,
    recent: VecDeque<RecentResult>,
}

/// Writes each proxy result as a proxy-source `net.connect` event on the
/// proxy's own sequence (§13.1), and counts what reached the trace.
struct ProxyTraceSink {
    attempt_id: String,
    trace: Option<SharedTrace>,
    tally: Mutex<ProxyTally>,
}

impl ProxySink for ProxyTraceSink {
    fn emit(&self, result: ProxyResult) {
        let mut tally = self.tally.lock().unwrap_or_else(PoisonError::into_inner);
        tally.seq += 1;
        let event = proxy::proxy_event(
            &result,
            &self.attempt_id,
            tally.seq,
            SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
        );
        let delivered = match self.trace.as_ref() {
            Some(trace) => match trace.lock() {
                Ok(mut writer) => writer.write_event(&event, Priority::Normal).is_ok(),
                Err(_) => false,
            },
            // No trace was configured (a doctor probe): nothing was claimed
            // to be collected, so nothing is lost.
            None => true,
        };
        if delivered {
            tally.delivered += 1;
        } else {
            tally.lost += 1;
        }
        if tally.recent.len() == RECENT_RESULTS {
            tally.recent.pop_front();
        }
        tally.recent.push_back(RecentResult {
            destination: result.destination.as_ref().map(ToString::to_string),
            allowed: result.decision == ProxyDecision::Allow,
            reason: result.reason.as_str(),
        });
    }
}

/// Hands mediation records from the mediator's threads to the supervision
/// loop without ever blocking a mediation.
struct RecordQueue {
    tx: Mutex<SyncSender<MediationRecord>>,
    dropped: AtomicU64,
}

impl MediationSink for RecordQueue {
    fn record(&self, record: MediationRecord) {
        let tx = self.tx.lock().unwrap_or_else(PoisonError::into_inner);
        match tx.try_send(record) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The attempt's agent network
// ---------------------------------------------------------------------------

/// The bridge, once discovered.
struct Bridge {
    pid: libc::pid_t,
    fd: OwnedFd,
    seccomp_filters: u32,
}

/// Everything `agent` adds to a contained attempt.
pub struct AgentNet {
    attempt_id: String,
    trace: Option<SharedTrace>,
    variant: AgentVariant,
    nested: (ProbeStatus, String),
    baseline_digest: String,
    mediation_digest: String,
    allowed_hosts: Vec<String>,
    rules: Rules,
    /// The registered proxy directory, bound read-only by descriptor.
    dir: Arc<OwnedFd>,
    dir_path: PathBuf,
    /// Until [`AgentNet::start_proxy`].
    listener: Option<UnixListener>,
    /// The proxy socket node, pinned for the whole run: its inode cannot be
    /// freed and handed to a replacement while this is open.
    _socket_pin: OwnedFd,
    socket_identity: (u64, u64),
    proxy: Option<ProxyHandle>,
    proxy_sink: Arc<ProxyTraceSink>,
    proxy_summary: Option<ProxySummary>,
    mediator: Option<MediatorHandle>,
    records: Receiver<MediationRecord>,
    queue: Arc<RecordQueue>,
    lost_reported: u64,
    bridge: Option<Bridge>,
    bridge_reported: bool,
    proxy_reported: bool,
    helper_connects: u64,
    socket_removed: bool,
}

impl Drop for AgentNet {
    fn drop(&mut self) {
        // Mediator and proxy stop through their own drops; the socket node
        // is this attempt's to remove.
        self.remove_socket();
    }
}

impl AgentNet {
    /// Step 1: the variant, the proxy socket and its pin. Runs before the
    /// backend starts.
    ///
    /// # Errors
    /// A refusal naming the proxy when its rules, socket or pin cannot be
    /// established.
    pub fn prepare(
        attempt_id: &str,
        trace: Option<SharedTrace>,
        snapshot: &crate::policy::PolicySnapshot,
        handoff: &ProxyDirHandoff,
        jail_exe: &Path,
        bwrap: &Path,
    ) -> Result<AgentNet, JailError> {
        // §9.2: probe the real nesting sequence and record it; its result
        // picks the baseline, and "unavailable" never refuses `agent`.
        let nested = probe::run_one("nested_user_namespace", jail_exe, bwrap);
        let variant =
            AgentVariant::for_nested_user_namespace(nested.status == ProbeStatus::Available);
        let baseline_digest = seccomp::agent_baseline(variant)
            .map_err(|error| refusal("syscall filter", error))?
            .digest();
        let mediation_digest = unixpeer::filter_digest();

        let rules = Rules::from_strings(
            &snapshot.network.allow,
            &snapshot.network.translation_prefixes,
        )
        .map_err(|error| refusal("proxy", format!("its rules do not parse: {error}")))?;

        let dir = Arc::clone(&handoff.fd);
        let stat = crate::state::anchored::fstat(dir.as_fd())
            .map_err(|error| refusal("proxy", format!("its directory: {error}")))?;
        if stat.identity() != handoff.identity
            || stat.kind != crate::state::anchored::Kind::Directory
        {
            return Err(refusal(
                "proxy",
                "its directory descriptor is not the registered directory",
            ));
        }
        let (listener, pin, socket_identity) = bind_pinned(dir.as_fd())
            .map_err(|error| refusal("proxy", format!("its socket: {error}")))?;

        let (tx, records) = sync_channel(RECORD_QUEUE);
        Ok(AgentNet {
            attempt_id: attempt_id.to_owned(),
            trace: trace.clone(),
            variant,
            nested: (nested.status, nested.evidence),
            baseline_digest,
            mediation_digest,
            allowed_hosts: snapshot.network.allow.clone(),
            rules,
            dir,
            dir_path: handoff.host_path.clone(),
            listener: Some(listener),
            _socket_pin: pin,
            socket_identity,
            proxy: None,
            proxy_sink: Arc::new(ProxyTraceSink {
                attempt_id: attempt_id.to_owned(),
                trace,
                tally: Mutex::new(ProxyTally::default()),
            }),
            proxy_summary: None,
            mediator: None,
            records,
            queue: Arc::new(RecordQueue {
                tx: Mutex::new(tx),
                dropped: AtomicU64::new(0),
            }),
            lost_reported: 0,
            bridge: None,
            bridge_reported: false,
            proxy_reported: false,
            helper_connects: 0,
            socket_removed: false,
        })
    }

    /// The baseline variant this attempt uses.
    #[must_use]
    pub fn variant(&self) -> AgentVariant {
        self.variant
    }

    /// The host directory, for the plan's mount table.
    #[must_use]
    pub fn dir_path(&self) -> &Path {
        &self.dir_path
    }

    /// A duplicate of the proxy directory descriptor, for bubblewrap.
    ///
    /// # Errors
    /// The errno from `fcntl`.
    pub fn dir_fd(&self) -> io::Result<OwnedFd> {
        self.dir.try_clone()
    }

    /// Step 2: start the proxy on the pinned listener.
    ///
    /// # Errors
    /// A refusal naming the proxy when it cannot start (its descriptor
    /// budget does not fit, a thread cannot be created).
    pub fn start_proxy(&mut self) -> Result<(), JailError> {
        let Some(listener) = self.listener.take() else {
            return Err(refusal("proxy", "it was already started"));
        };
        let config = ProxyConfig {
            listener,
            rules: self.rules.clone(),
            budgets: Budgets::default(),
            resolver: Arc::new(SystemResolver::new(RESOLVER_IN_FLIGHT)),
        };
        let sink: Arc<dyn ProxySink> = self.proxy_sink.clone();
        self.proxy = Some(proxy::start(config, sink).map_err(|error| refusal("proxy", error))?);
        Ok(())
    }

    /// Step 3: take the mediation listener and `sock_diag` socket from the
    /// blocked launcher and start the mediator.
    ///
    /// # Errors
    /// A refusal naming the unix-peer mediation.
    pub fn take_mediation(&mut self, launcher: BorrowedFd<'_>) -> Result<(), JailError> {
        let authority = unixpeer::take_from_launcher(
            launcher,
            LauncherFds {
                listener: LISTENER_FD,
                sockdiag: SOCKDIAG_FD,
            },
        )
        .map_err(|error| refusal("unix-peer mediation", error))?
        .authorize_peer(self.socket_identity);
        let sink: Arc<dyn MediationSink> = self.queue.clone();
        self.mediator = Some(
            unixpeer::spawn(authority, sink)
                .map_err(|error| refusal("unix-peer mediation", error))?,
        );
        Ok(())
    }

    /// Step 4: find the bridge the launcher started and read back what it
    /// is. `expected` are the namespaces the launcher is in.
    ///
    /// # Errors
    /// A refusal naming the bridge.
    pub fn discover_bridge(
        &mut self,
        init_pid: libc::pid_t,
        expected: identity::NsIds,
        deadline: &super::clock::Deadline,
    ) -> Result<libc::pid_t, JailError> {
        let argv = bridge_argv();
        // The launcher waited for the intermediate child, so the bridge is
        // already a child of the namespace init; it may still be between its
        // fork and its exec, when its command line is still the launcher's.
        let pid = loop {
            if let Some(pid) = super::tracer::children(init_pid)
                .into_iter()
                .find(|pid| super::tracer::cmdline(*pid).as_ref() == Some(&argv))
            {
                break pid;
            }
            if deadline.expired() {
                return Err(refusal("bridge", "it never appeared in the namespace"));
            }
            nap();
        };
        let fd = identity::pidfd_open(pid).map_err(|error| refusal("bridge", error))?;
        let seen = identity::ns_ids(pid);
        if seen.net != expected.net || seen.mnt != expected.mnt || seen.pid != expected.pid {
            return Err(refusal(
                "bridge",
                "it is not in the attempt's network, mount and pid namespaces",
            ));
        }
        let status = |key: &str| identity::status_field(pid, key).unwrap_or_default();
        if status("NoNewPrivs") != "1" || !status("CapEff").chars().all(|c| c == '0') {
            return Err(refusal("bridge", "it holds privilege"));
        }
        let filters = verify_filter_count(&status("Seccomp_filters"), EXPECTED_BRIDGE_FILTERS)
            .map_err(|error| refusal("bridge", error.message))?;
        // Listening is read back from the attempt's own network namespace,
        // through the bridge's /proc view, and tied to a descriptor it holds.
        loop {
            match listening_socket(pid) {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => return Err(refusal("bridge", error)),
            }
            if deadline.expired() || super::watch::readable(fd.as_raw_fd()) {
                return Err(refusal(
                    "bridge",
                    format!("it is not listening on {}", bridge::LISTEN),
                ));
            }
            nap();
        }
        self.bridge = Some(Bridge {
            pid,
            fd,
            seccomp_filters: filters,
        });
        Ok(pid)
    }

    /// While running: mediated connects become audit results (when
    /// observation is on), and a bridge or proxy that stopped is recorded
    /// once each.
    pub fn pump(&mut self, audit: &mut AuditWriter, observe_on: bool) {
        while let Ok(record) = self.records.try_recv() {
            self.account(audit, observe_on, &record);
        }
        let dropped = self.queue.dropped.load(Ordering::SeqCst);
        if observe_on && dropped > self.lost_reported {
            let now = u64::try_from(crate::platform::elapsed_since_start_ns()).unwrap_or(u64::MAX);
            audit.record_mediation_loss(dropped - self.lost_reported, now, now);
            self.lost_reported = dropped;
        }
        if !self.bridge_reported
            && let Some(bridge) = &self.bridge
            && super::watch::readable(bridge.fd.as_raw_fd())
        {
            self.bridge_reported = true;
            self.helper_note("bridge", "exited");
        }
        if !self.proxy_reported
            && let Some(proxy) = &self.proxy
            && !proxy.serving()
        {
            self.proxy_reported = true;
            self.helper_note("proxy", "stopped");
        }
    }

    fn account(&mut self, audit: &mut AuditWriter, observe_on: bool, record: &MediationRecord) {
        // A helper's connect (the bridge reaching the proxy) is the jail's
        // own plumbing, not a target operation (§11.1: "Setup helpers are
        // tagged as helpers, not attributed as user target operations"). The
        // thread group was read while the task was parked in the
        // notification, and a bridge that already exited never claims one.
        let helper = self.bridge.as_ref().is_some_and(|bridge| {
            record.tgid == Some(bridge.pid) && !super::watch::readable(bridge.fd.as_raw_fd())
        });
        if helper {
            self.helper_connects += 1;
            return;
        }
        if !observe_on {
            // §11.4: `--observe off` emits no audit source.
            return;
        }
        let ret = match record.verdict {
            Verdict::Allowed => 0,
            Verdict::Denied(errno) => -i64::from(errno),
        };
        audit.record_mediated_connect(&MediatedConnect {
            tid: record.pid,
            tgid: record.tgid,
            family: record.family,
            address_complete: record.address_complete,
            ret,
            reason: record.reason,
        });
    }

    fn helper_note(&self, helper: &str, transition: &str) {
        let Some(trace) = self.trace.as_ref() else {
            return;
        };
        let mut event = Event::lifecycle_note(
            &self.attempt_id,
            0, // assigned by the shared wrapper stream writer
            SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            &format!("{helper}_{transition}"),
        );
        event
            .fields
            .insert("kind".to_owned(), Value::from("helper"));
        event
            .fields
            .insert("helper".to_owned(), Value::from(helper));
        if let Ok(mut writer) = trace.lock() {
            let _ = writer.write_event(&event, Priority::Reserve);
        }
    }

    /// At the end: stop the proxy within `budget` (its results drained or
    /// counted missing), stop the mediator, and account for what it last
    /// recorded.
    pub fn stop(&mut self, audit: &mut AuditWriter, observe_on: bool, budget: Duration) {
        // A proxy that died on its own is recorded as such before the stop
        // makes every proxy look stopped.
        self.pump(audit, observe_on);
        if let Some(proxy) = self.proxy.take() {
            self.proxy_summary = Some(proxy.stop(budget));
        }
        if let Some(mediator) = self.mediator.take() {
            mediator.stop();
        }
        self.pump(audit, observe_on);
        self.remove_socket();
    }

    /// Unlinks `proxy.sock` if the name still denotes the node this attempt
    /// bound and pinned; a replacement someone else put there is left alone
    /// (the directory is then retained, and said so, by the supervisor).
    fn remove_socket(&mut self) {
        if self.socket_removed {
            return;
        }
        self.socket_removed = true;
        let Ok(duplicate) = self.dir.try_clone() else {
            return;
        };
        let dir = crate::state::anchored::Dir::from_owned(duplicate);
        let Ok(name) = crate::state::anchored::Name::new(PROXY_SOCKET_NAME.as_bytes()) else {
            return;
        };
        if dir
            .stat_at(&name)
            .is_ok_and(|stat| stat.identity() == self.socket_identity)
        {
            let _ = dir.unlink_at(&name);
        }
    }

    /// `proxy.net` coverage (§11.4): active with the count of results that
    /// reached the trace, or degraded with a null count and a gap when a
    /// result was lost in transport or the drain was cut short.
    pub fn apply_coverage(&self, summary: &mut CoverageSummary) {
        let tally = self
            .proxy_sink
            .tally
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let class = proxy_coverage(
            tally.delivered,
            tally.lost,
            self.proxy_summary.map(|summary| summary.results_missing),
            &crate::platform::elapsed_since_start_ns().to_string(),
        );
        summary.sources.proxy = class.status;
        summary.gaps.extend(class.gaps.iter().cloned());
        summary.classes.insert(CoverageClass::ProxyNet, class);
    }

    /// The most recent proxy results, oldest first.
    #[must_use]
    pub fn recent_results(&self) -> Vec<RecentResult> {
        self.proxy_sink
            .tally
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recent
            .iter()
            .cloned()
            .collect()
    }

    /// The bridge's host pid, once discovered.
    #[must_use]
    pub fn bridge_pid(&self) -> Option<libc::pid_t> {
        self.bridge.as_ref().map(|bridge| bridge.pid)
    }

    /// Mediated connects that were the bridge's own, not the target's.
    #[must_use]
    pub fn helper_connects(&self) -> u64 {
        self.helper_connects
    }

    /// What the receipt's native details say about `agent` (§9.2: "Record
    /// the allowed setup operations and the measured nested-namespace
    /// capability in the receipt"; §9.3: helpers charged to the attempt are
    /// listed).
    #[must_use]
    pub fn details(&self) -> (Value, Value) {
        let mut agent = Map::new();
        agent.insert(
            "filter_variant".to_owned(),
            Value::from(self.variant.as_str()),
        );
        agent.insert(
            "baseline_filter_digest".to_owned(),
            Value::from(self.baseline_digest.clone()),
        );
        agent.insert(
            "mediation_filter_digest".to_owned(),
            Value::from(self.mediation_digest.clone()),
        );
        agent.insert(
            "allowed_setup_operations".to_owned(),
            Value::from(self.variant.allowed_setup_operations()),
        );
        agent.insert(
            "nested_user_namespace".to_owned(),
            Value::from(self.nested.0.to_string()),
        );
        agent.insert(
            "nested_user_namespace_evidence".to_owned(),
            Value::from(self.nested.1.clone()),
        );
        agent.insert(
            "unix_peer_mediation".to_owned(),
            Value::from("seccomp_user_notification"),
        );
        agent.insert(
            "proxy_socket".to_owned(),
            Value::from(format!(
                "{}/{PROXY_SOCKET_NAME}",
                super::bwrap::PROXY_INSIDE_PATH
            )),
        );
        let helpers = match &self.bridge {
            Some(bridge) => serde_json::json!([{
                "kind": "bridge",
                "pid": bridge.pid,
                "listen": bridge::LISTEN,
                "seccomp_filters": bridge.seccomp_filters,
                "charged_to_attempt": true,
            }]),
            None => Value::Array(Vec::new()),
        };
        (Value::Object(agent), helpers)
    }

    /// The `applied.network` group.
    #[must_use]
    pub fn applied_network(&self) -> crate::records::AppliedNetwork {
        crate::records::AppliedNetwork {
            mode: "proxy".to_owned(),
            mechanism: Some(
                "network-namespace+outside-http-proxy+loopback-bridge+unix-peer-mediation"
                    .to_owned(),
            ),
            allowed_hosts: self.allowed_hosts.clone(),
        }
    }

    /// The baseline's digest, for `applied.syscalls`.
    #[must_use]
    pub fn baseline_digest(&self) -> &str {
        &self.baseline_digest
    }
}

/// `proxy.net` from the proxy's accounting (§11.4): active with the count of
/// results delivered to the trace only when the drain completed
/// (`missing == Some(0)`) and nothing was lost in transport; otherwise
/// degraded, with a null count and a gap naming the class and the known
/// number of results that are missing. `missing == None` means the proxy was
/// never stopped and drained, which is never complete.
#[must_use]
pub fn proxy_coverage(
    delivered: u64,
    lost: u64,
    missing: Option<u64>,
    now_ns: &str,
) -> ClassSummary {
    let mut gaps = Vec::new();
    let drain_missing = missing.unwrap_or(0);
    if missing.is_none() || drain_missing > 0 || lost > 0 {
        gaps.push(Gap {
            classes: vec![CoverageClass::ProxyNet.as_str().to_owned()],
            source: "proxy".to_owned(),
            start_ns: "0".to_owned(),
            end_ns: Some(now_ns.to_owned()),
            reason: match missing {
                None => "proxy_not_drained".to_owned(),
                Some(0) => "proxy_result_undelivered".to_owned(),
                Some(_) => "proxy_drain_incomplete".to_owned(),
            },
            lost_count: missing.map(|missing| missing + lost),
        });
    }
    let status = if gaps.is_empty() {
        SourceStatus::Active
    } else {
        SourceStatus::Degraded
    };
    ClassSummary {
        status,
        observed_count: (status == SourceStatus::Active).then_some(delivered),
        gaps,
    }
}

/// The bridge runs under exactly the agent baseline and the mediation
/// filter: it is forked after the mediation filter and before the observer's
/// narrowing filter.
pub const EXPECTED_BRIDGE_FILTERS: u32 = 2;

/// The bridge's command line, as `/proc/<pid>/cmdline` shows it.
fn bridge_argv() -> Vec<Vec<u8>> {
    vec![
        super::bwrap::JAIL_INSIDE_PATH.as_bytes().to_vec(),
        bridge::SUBCOMMAND.as_bytes().to_vec(),
    ]
}

/// Binds `proxy.sock` inside the pinned directory, pins the node `O_PATH`,
/// and proves the pin is this listener's by connecting through it and
/// accepting that connection. Returns the listener, the pin and the node's
/// `(dev, ino)`.
fn bind_pinned(dir: BorrowedFd<'_>) -> io::Result<(UnixListener, OwnedFd, (u64, u64))> {
    // Through the directory descriptor: no path the child or anyone else
    // renamed can redirect the bind, and the name fits `sun_path` whatever
    // the length of the state root.
    let listener = UnixListener::bind(format!(
        "/proc/self/fd/{}/{PROXY_SOCKET_NAME}",
        dir.as_raw_fd()
    ))?;
    let dir = crate::state::anchored::Dir::from_owned(dir.try_clone_to_owned()?);
    let name = crate::state::anchored::Name::new(PROXY_SOCKET_NAME.as_bytes())?;
    let pin = dir.open_path_at(&name)?;
    let stat = crate::state::anchored::fstat(pin.as_fd())?;
    if stat.kind != crate::state::anchored::Kind::Socket {
        return Err(io::Error::other("the pinned node is not a socket"));
    }
    listener.set_nonblocking(true)?;
    let probe = UnixStream::connect(format!("/proc/self/fd/{}", pin.as_raw_fd()))?;
    let accepted = listener.accept().map_err(|error| {
        io::Error::other(format!(
            "a connection through the pinned node did not reach this listener: {error}"
        ))
    })?;
    drop((probe, accepted));
    listener.set_nonblocking(false)?;
    Ok((listener, pin, stat.identity()))
}

/// Whether `pid` holds a TCP socket listening on `127.0.0.1:3128`, read from
/// its own network namespace's `/proc/<pid>/net/tcp` and matched to one of
/// its descriptors.
fn listening_socket(pid: libc::pid_t) -> io::Result<bool> {
    let table = std::fs::read_to_string(format!("/proc/{pid}/net/tcp"))?;
    let Some(inode) = listening_inode(&table) else {
        return Ok(false);
    };
    let wanted = format!("socket:[{inode}]");
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        let Ok(entry) = entry else { continue };
        if std::fs::read_link(entry.path()).is_ok_and(|link| link.as_os_str() == wanted.as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The inode of the `LISTEN` row for `127.0.0.1:3128` in a `/proc/net/tcp`
/// table, if there is one.
#[must_use]
pub fn listening_inode(table: &str) -> Option<u64> {
    // Little-endian hex of 127.0.0.1, then the port in hex; state 0A is LISTEN.
    const LOCAL: &str = "0100007F:0C38";
    const LISTEN: &str = "0A";
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.get(1) == Some(&LOCAL) && fields.get(3) == Some(&LISTEN))
            .then(|| fields.get(9)?.parse().ok())
            .flatten()
    })
}

fn nap() {
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 200_000,
    };
    // SAFETY: `ts` is a live timespec and the second argument may be null.
    unsafe { libc::nanosleep(&raw const ts, std::ptr::null_mut()) };
}

/// The number of seccomp filters a contained launcher must be running
/// under when it blocks: the baseline bubblewrap loads, the mediation filter
/// for `agent`, and the observer's narrowing filter when observation is on.
/// The J2 check read only `Seccomp: 2` (filter mode), which a missing
/// narrowing filter does not change.
#[must_use]
pub fn expected_launcher_filters(agent: bool, observe_on: bool) -> u32 {
    1 + u32::from(agent) + u32::from(observe_on)
}

/// Checks a `Seccomp_filters:` value against the expected count.
///
/// # Errors
/// A backend refusal naming both numbers when they differ or the value does
/// not parse.
pub fn verify_filter_count(observed: &str, expected: u32) -> Result<u32, JailError> {
    match observed.trim().parse::<u32>() {
        Ok(count) if count == expected => Ok(count),
        _ => Err(JailError::new(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::HostSetup,
            format!(
                "it runs under Seccomp_filters {observed:?}, not the {expected} \
                 filters this boundary installs"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listening_row_is_found_only_for_the_bridge_address_in_listen_state() {
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let listen = "   0: 0100007F:0C38 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 4242 1 0000000000000000 100 0 0 10 0\n";
        let established = "   1: 0100007F:0C38 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1001        0 4343 1 0000000000000000 20 4 30 10 -1\n";
        let other_port = "   2: 0100007F:0C39 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 4444 1 0000000000000000 100 0 0 10 0\n";
        let any_address = "   3: 00000000:0C38 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 4545 1 0000000000000000 100 0 0 10 0\n";
        assert_eq!(listening_inode(&format!("{header}{listen}")), Some(4242));
        assert_eq!(
            listening_inode(&format!("{header}{established}{other_port}{any_address}")),
            None,
            "an established flow, another port and 0.0.0.0 are not the bridge"
        );
        assert_eq!(listening_inode(header), None);
    }

    #[test]
    fn proxy_coverage_is_active_only_for_a_complete_drain_with_nothing_lost() {
        let complete = proxy_coverage(3, 0, Some(0), "9");
        assert_eq!(complete.status, SourceStatus::Active);
        assert_eq!(complete.observed_count, Some(3));
        assert!(complete.gaps.is_empty());
        for (lost, missing, reason, count) in [
            (0, Some(2), "proxy_drain_incomplete", Some(2)),
            (1, Some(0), "proxy_result_undelivered", Some(1)),
            (1, Some(2), "proxy_drain_incomplete", Some(3)),
            (0, None, "proxy_not_drained", None),
        ] {
            let degraded = proxy_coverage(3, lost, missing, "9");
            assert_eq!(degraded.status, SourceStatus::Degraded, "{reason}");
            assert_eq!(
                degraded.observed_count, None,
                "{reason}: a degraded count is null"
            );
            assert_eq!(degraded.gaps.len(), 1);
            assert_eq!(degraded.gaps[0].reason, reason);
            assert_eq!(degraded.gaps[0].classes, vec!["proxy.net".to_owned()]);
            assert_eq!(degraded.gaps[0].source, "proxy");
            assert_eq!(degraded.gaps[0].lost_count, count);
        }
    }

    #[test]
    fn the_expected_filter_count_follows_the_profile_and_observation() {
        assert_eq!(expected_launcher_filters(false, false), 1);
        assert_eq!(expected_launcher_filters(false, true), 2);
        assert_eq!(expected_launcher_filters(true, false), 2);
        assert_eq!(expected_launcher_filters(true, true), 3);
    }

    #[test]
    fn a_filter_count_that_differs_refuses_and_names_both_numbers() {
        assert_eq!(verify_filter_count("3", 3).unwrap(), 3);
        for observed in ["2", "4", "", "x", "0"] {
            let error = verify_filter_count(observed, 3).unwrap_err();
            assert_eq!(error.code, ErrorCode::BackendUnavailable, "{observed}");
            assert!(error.message.contains('3'), "{}", error.message);
        }
    }
}
