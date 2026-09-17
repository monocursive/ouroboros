//! Talking to a local runtime: connectivity checks, readiness questions, and the one
//! authorized stop the first-setup transition performs.
//!
//! The engine is blocking — it spends its life in `ssh` children — while the gateway
//! transport is async. Rather than colour the whole engine, each call here owns a
//! current-thread Tokio runtime for its own duration. That is also why [`Gateway`] is a
//! trait: an engine test needs a counting fake that refuses methods it was not expecting,
//! and a fake is the honest way to assert what the engine asked for.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::proto;
use crate::runtime;
use crate::transport::{self, ClientError, NoReconnectHook, TransportConfig};

use super::refuse;

/// How long the runtime is given to exit after it accepts the shutdown.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);
/// One gateway call's ceiling. Connectivity polling is many short calls, not one long one.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// One local runtime, as far as the engine needs one.
pub trait Gateway: Send + Sync {
    /// Call a read or operate method. `Ok(None)` means "there is no runtime here",
    /// which is a fact the engine reports rather than an error it fails on.
    fn call(&self, method: &str, params: Value) -> Result<Option<Value>>;

    /// Whether a runtime is currently published for this data directory.
    fn running(&self) -> bool;
}

/// The real thing: the runtime published in a data directory.
pub struct LocalGateway {
    data_dir: PathBuf,
    token_file: PathBuf,
}

impl LocalGateway {
    pub fn new(data_dir: &Path, token_file: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            token_file: token_file.to_path_buf(),
        }
    }
}

impl Gateway for LocalGateway {
    fn call(&self, method: &str, params: Value) -> Result<Option<Value>> {
        let Some(publication) = runtime::read_live_publication(&self.data_dir)? else {
            return Ok(None);
        };
        let token = runtime::read_token(&self.token_file)?;
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, publication.port));
        let method = method.to_string();
        block_on(async move {
            let mut config = TransportConfig::new(address, token);
            config.reconnect = false;
            let connected = transport::connect(config, Arc::new(NoReconnectHook))
                .await
                .with_context(|| {
                    format!(
                        "connecting to the local runtime on port {}",
                        publication.port
                    )
                })?;
            let result = connected
                .client
                .call_with_timeout(&method, params, CALL_TIMEOUT)
                .await;
            connected.client.stop().await;
            match result {
                Ok(value) => Ok(Some(value)),
                Err(error) => Err(rpc_error(&method, error)),
            }
        })
    }

    fn running(&self) -> bool {
        runtime::read_live_publication(&self.data_dir)
            .ok()
            .flatten()
            .is_some()
    }
}

/// What the idle-gated stop did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopOutcome {
    /// Nothing was running.
    NotRunning,
    /// A stale publication was removed; no process was signalled.
    RemovedStale { pid: i32 },
    /// The runtime accepted the shutdown and its process is gone.
    Stopped { pid: i32 },
}

/// Ask the local runtime to stop, and refuse if it is not idle.
///
/// This is the proposal's "authenticated graceful stop only for an idle runtime the
/// operator agreed to transition", and it is the only stop the engine performs. The
/// spawn lock is held from the observation of the publication through the observed exit:
/// a stop that released the namespace in between let a concurrent starter replace the
/// publication between the read and the action.
///
/// No PID learned from a replaceable publication is ever signalled. If the runtime does
/// not serve an authenticated `runtime.shutdown` at operate scope, this refuses and says
/// to use the supervisor.
pub fn stop_require_idle(data_dir: &Path, token_file: &Path) -> Result<StopOutcome> {
    let lock = runtime::acquire_spawn_lock(data_dir)
        .with_context(|| "serializing the deployment's runtime transition with start and stop")?;

    stop_require_idle_locked(data_dir, token_file, &lock)
}

/// Keep the lifecycle namespace held while a caller subsequently disables its supervisor.
pub fn stop_require_idle_locked(
    data_dir: &Path,
    token_file: &Path,
    lock: &runtime::SpawnLock,
) -> Result<StopOutcome> {
    let publication = match runtime::reconcile_publication_under_spawn_lock(data_dir, lock)? {
        runtime::LockedPublication::Absent => return Ok(StopOutcome::NotRunning),
        runtime::LockedPublication::RemovedStale(publication) => {
            return Ok(StopOutcome::RemovedStale {
                pid: publication.pid,
            })
        }
        runtime::LockedPublication::Live(publication) => publication,
    };

    let token = runtime::read_token(token_file)?;
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, publication.port));
    let node = publication.node.clone();

    block_on(async move {
        let mut config = TransportConfig::new(address, token);
        config.reconnect = false;
        let connected = transport::connect(config, Arc::new(NoReconnectHook))
            .await
            .context("connecting to the runtime that has to stop first")?;
        if connected.hello.node != node {
            connected.client.stop().await;
            return refuse(
                "publication_mismatch",
                format!(
                    "the listener on port {} is {}, not the {node} this data directory published; nothing was signalled",
                    publication.port, connected.hello.node
                ),
            );
        }
        if !(connected.hello.serves("runtime.shutdown") && connected.hello.operates()) {
            connected.client.stop().await;
            return refuse(
                "shutdown_unavailable",
                "this runtime does not serve authenticated runtime.shutdown at operate scope, so setup cannot transition it. Stop it through its own supervisor and run setup again",
            );
        }
        let result = connected
            .client
            .call_with_timeout(
                "runtime.shutdown",
                json!({ "require_idle": true }),
                CALL_TIMEOUT,
            )
            .await;
        connected.client.stop().await;
        match result {
            // The runtime stopping is what was asked for, and it may stop before it can
            // answer.
            Ok(_) | Err(ClientError::ConnectionClosed) => Ok(()),
            Err(error) => Err(rpc_error("runtime.shutdown", error)),
        }
    })?;

    let exact = publication.identity()?;
    let deadline = std::time::Instant::now() + SHUTDOWN_GRACE;
    while match &exact {
        Some(identity) => runtime::process_identity_is_live(identity)?,
        None => runtime::pid_alive(publication.pid),
    } {
        if std::time::Instant::now() >= deadline {
            return refuse(
                "shutdown_incomplete",
                format!(
                    "pid {} is still running {} seconds after accepting the shutdown. It was not killed: a runtime with durable journals is not something setup kills on a timer",
                    publication.pid,
                    SHUTDOWN_GRACE.as_secs()
                ),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(StopOutcome::Stopped {
        pid: publication.pid,
    })
}

/// Turn a gateway refusal into an error that keeps the reason the runtime declared.
///
/// Seam C2: `runtime.shutdown {"require_idle": true}` refuses with `data.reason` of
/// `runtime_busy` or `activity_unknown` and a bounded `data.activity` summary. Those two
/// are the refusals an operator has to act on, so they keep their codes and their
/// numbers on the way out.
fn rpc_error(method: &str, error: ClientError) -> anyhow::Error {
    if let ClientError::Rpc(proto::RpcError { message, data, .. }) = &error {
        let reason = data
            .as_ref()
            .and_then(|data| data.get("reason"))
            .and_then(Value::as_str);
        let activity = data
            .as_ref()
            .and_then(|data| data.get("activity"))
            .map(|activity| format!(" ({})", describe_activity(activity)))
            .unwrap_or_default();
        match reason {
            Some("runtime_busy") => {
                return super::SetupError {
                    reason: "runtime_busy",
                    detail: format!(
                        "this machine's runtime is working, so setup will not restart it{activity}. Let the work finish, or stop the runtime yourself, then run setup again"
                    ),
                }
                .into()
            }
            Some("activity_unknown") => {
                return super::SetupError {
                    reason: "activity_unknown",
                    detail: format!(
                        "this machine's runtime could not say whether it is idle{activity}, and unknown activity does not authorize an automatic restart. Stop it yourself when you know it is safe, then run setup again"
                    ),
                }
                .into()
            }
            _ => {
                return super::SetupError {
                    reason: "gateway_refused",
                    detail: format!(
                        "{method} was refused: {}",
                        super::sanitize_remote_text(message, 200)
                    ),
                }
                .into()
            }
        }
    }
    super::SetupError {
        reason: "gateway_unavailable",
        detail: format!("{method} did not complete: {error}"),
    }
    .into()
}

/// The bounded seam-C2 activity summary, as one line an operator can act on.
pub fn describe_activity(activity: &Value) -> String {
    let mut parts = Vec::new();
    for (field, label) in [
        ("running_turns", "running turns"),
        ("queued_turns", "queued turns"),
        ("attachment_transfers", "image transfers"),
        ("attachment_normalizations", "image preparations"),
        ("operator_clients", "connected clients"),
    ] {
        match activity.get(field).and_then(Value::as_u64) {
            Some(0) => {}
            Some(count) => parts.push(format!("{count} {label}")),
            None => parts.push(format!("{label} unknown")),
        }
    }
    if let Some(unknown) = activity.get("unknown").and_then(Value::as_array) {
        if !unknown.is_empty() {
            let names: Vec<String> = unknown
                .iter()
                .filter_map(Value::as_str)
                .map(|name| super::sanitize_remote_text(name, 40))
                .collect();
            parts.push(format!("unknown: {}", names.join(", ")));
        }
    }
    if parts.is_empty() {
        "idle".to_string()
    } else {
        parts.join(", ")
    }
}

/// Run one async gateway exchange from a blocking engine thread.
///
/// A current-thread runtime, created and dropped per call. The engine runs on a plain
/// thread (the CLI hands it to `spawn_blocking`, the worker gives it one of its own), so
/// there is no outer runtime for this to be nested inside.
fn block_on<F, T>(future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting a runtime for one gateway call")?
        .block_on(future)
}

/// A gateway that answers from a fixed script and refuses everything else.
///
/// Test-only, and deliberately strict: an engine test that observed a permissive default
/// would prove nothing about what the engine asked for.
pub struct ScriptedGateway {
    answers: Mutex<Vec<(String, Value)>>,
    calls: Mutex<Vec<(String, Value)>>,
    running: bool,
    refusals: AtomicU32,
}

impl ScriptedGateway {
    /// `answers` is a list of `(method, reply)`. A method that appears more than once is
    /// answered in order; the last answer for a method repeats.
    pub fn new(running: bool, answers: Vec<(&str, Value)>) -> Self {
        Self {
            answers: Mutex::new(
                answers
                    .into_iter()
                    .map(|(method, value)| (method.to_string(), value))
                    .collect(),
            ),
            calls: Mutex::new(Vec::new()),
            running,
            refusals: AtomicU32::new(0),
        }
    }

    pub fn calls(&self) -> Vec<(String, Value)> {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn called(&self, method: &str) -> usize {
        self.calls()
            .iter()
            .filter(|(name, _)| name == method)
            .count()
    }

    pub fn refusals(&self) -> u32 {
        self.refusals.load(Ordering::SeqCst)
    }
}

impl Gateway for ScriptedGateway {
    fn call(&self, method: &str, params: Value) -> Result<Option<Value>> {
        self.calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((method.to_string(), params));
        if !self.running {
            return Ok(None);
        }
        let mut answers = self.answers.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(index) = answers.iter().position(|(name, _)| name == method) {
            let (_, value) = if answers.iter().filter(|(name, _)| name == method).count() > 1 {
                answers.remove(index)
            } else {
                answers[index].clone()
            };
            return Ok(Some(value));
        }
        self.refusals.fetch_add(1, Ordering::SeqCst);
        refuse(
            "gateway_refused",
            format!("this fake gateway was not told how to answer `{method}`"),
        )
    }

    fn running(&self) -> bool {
        self.running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal an operator has to act on says what the runtime is busy with.
    #[test]
    fn a_busy_runtime_is_described_from_the_activity_summary() {
        let busy = json!({
            "idle": false,
            "running_turns": 1,
            "queued_turns": 2,
            "attachment_transfers": 0,
            "attachment_normalizations": 0,
            "operator_clients": 1,
            "unknown": []
        });
        assert_eq!(
            describe_activity(&busy),
            "1 running turns, 2 queued turns, 1 connected clients"
        );

        let unknown = json!({
            "idle": null,
            "running_turns": null,
            "queued_turns": 0,
            "attachment_transfers": 0,
            "attachment_normalizations": 0,
            "operator_clients": 0,
            "unknown": ["running_turns"]
        });
        assert_eq!(
            describe_activity(&unknown),
            "running turns unknown, unknown: running_turns"
        );

        assert_eq!(
            describe_activity(&json!({
                "idle": true, "running_turns": 0, "queued_turns": 0,
                "attachment_transfers": 0, "attachment_normalizations": 0,
                "operator_clients": 0, "unknown": []
            })),
            "idle"
        );
    }

    /// Seam C2's two refusal reasons survive the trip out of the transport, because the
    /// engine and the operator both branch on them.
    #[test]
    fn the_idle_refusals_keep_their_reason_codes() {
        let busy = rpc_error(
            "runtime.shutdown",
            ClientError::Rpc(proto::RpcError {
                code: proto::ErrorCode::from_i64(-32004),
                message: "the runtime is busy".into(),
                data: Some(json!({"reason": "runtime_busy", "activity": {"running_turns": 1}})),
            }),
        );
        assert_eq!(super::super::reason_of(&busy), Some("runtime_busy"));
        assert!(format!("{busy}").contains("1 running turns"));

        let unknown = rpc_error(
            "runtime.shutdown",
            ClientError::Rpc(proto::RpcError {
                code: proto::ErrorCode::from_i64(-32004),
                message: "activity unknown".into(),
                data: Some(
                    json!({"reason": "activity_unknown", "activity": {"running_turns": null}}),
                ),
            }),
        );
        assert_eq!(super::super::reason_of(&unknown), Some("activity_unknown"));

        let other = rpc_error("runtime.shutdown", ClientError::Timeout);
        assert_eq!(super::super::reason_of(&other), Some("gateway_unavailable"));
    }

    /// The fake refuses what it was not told to answer, so a test cannot pass by
    /// observing a permissive default.
    #[test]
    fn the_scripted_gateway_refuses_an_unexpected_method() {
        let gateway = ScriptedGateway::new(true, vec![("fleet.status", json!({"machines": []}))]);
        assert_eq!(
            gateway
                .call("fleet.status", json!({}))
                .expect("a scripted answer"),
            Some(json!({"machines": []}))
        );
        assert!(gateway.call("runtime.shutdown", json!({})).is_err());
        assert_eq!(gateway.refusals(), 1);
        assert_eq!(gateway.called("fleet.status"), 1);

        let stopped = ScriptedGateway::new(false, vec![]);
        assert_eq!(
            stopped.call("fleet.status", json!({})).expect("no runtime"),
            None,
            "a stopped runtime is a fact, not an error"
        );
    }
}
