//! `ouro policy` against the scripted gateway (docs/SELF.md §S2, S2b).
//!
//! Four claims, and the frames come from the golden fixtures rather than from shapes
//! retyped here, so a regeneration on the Elixir side is picked up by the next `cargo test`:
//!
//!   * the params are the flags and nothing else, and `promote` never sends an actor;
//!   * `replay --out` writes the file `promote --evidence` reads back, and says where on
//!     stderr rather than on stdout;
//!   * stdout carries only the answer, in both the table and the `--json` form;
//!   * a refusal is an error rather than an empty table, and a report this client can see is
//!     malformed is refused before the socket is used at all.

mod support;

use serde_json::{json, Value};

use ouro::policy_cli::{
    self, DemoteOptions, PromoteOptions, ReplayOptions, CLEAR_METHOD, DEMOTE_METHOD,
    PROMOTE_METHOD, REPLAY_METHOD, STATUS_METHOD,
};

use support::{config, fixture, listener, Peer};

/// The `result` half of a golden fixture — what a client is actually handed.
fn result(name: &str) -> Value {
    fixture(name)["result"].clone()
}

/// A scratch directory this test owns, removed when it is done.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ouro-policy-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("a clock")
                .as_nanos()
        ));

        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }

    fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Connects, answers one call of `method`, and returns the params it was called with plus
/// the two streams the client wrote.
async fn drive<F, Fut>(method: &'static str, answer: Value, run: F) -> (Value, String, String)
where
    F: FnOnce(ouro::transport::Client, Vec<u8>, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = (anyhow::Result<()>, Vec<u8>, Vec<u8>)>,
{
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[method]).await;
        let request = peer.request_for(method).await;
        peer.result(&request["id"], answer).await;

        request
    });

    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .expect("a handshake");

    let (outcome, out, err) = run(connected.client.clone(), Vec::new(), Vec::new()).await;
    outcome.expect("a policy call");

    let request = script.await.expect("the script");

    (
        request["params"].clone(),
        String::from_utf8(out).expect("utf-8"),
        String::from_utf8(err).expect("utf-8"),
    )
}

#[tokio::test]
async fn status_sends_an_empty_object_and_prints_the_record() {
    let (params, out, err) = drive(
        STATUS_METHOD,
        result("policy_promote_result"),
        |client, mut out, mut err| async move {
            let outcome = policy_cli::status(&client, false, &mut out, &mut err).await;
            (outcome, out, err)
        },
    )
    .await;

    // The envelope is closed on the runtime's side; an empty object is the only thing it
    // accepts, and the client sends exactly that.
    assert_eq!(params, json!({}));

    assert!(out.contains("no-network-shell"), "{out}");
    assert!(out.contains("synced_checkpoint"), "{out}");
    // Promoted and not allowable, because a demotion newer than the promotion withdrew it.
    let bash = out
        .lines()
        .find(|line| line.starts_with("bash "))
        .expect("a bash row");
    assert!(bash.contains("no"), "{out}");

    assert_eq!(err, "");
}

#[tokio::test]
async fn status_json_is_the_runtime_s_own_answer() {
    let (_params, out, err) = drive(
        STATUS_METHOD,
        result("policy_status_result"),
        |client, mut out, mut err| async move {
            let outcome = policy_cli::status(&client, true, &mut out, &mut err).await;
            (outcome, out, err)
        },
    )
    .await;

    let decoded: Value = serde_json::from_str(&out).expect("a JSON object");
    assert_eq!(decoded, result("policy_status_result"));
    // Nothing but the answer on stdout, so `| jq` never has to skip a line.
    assert_eq!(err, "");
}

#[tokio::test]
async fn replay_sends_the_name_and_only_the_flags_that_were_given() {
    let (params, _out, _err) = drive(
        REPLAY_METHOD,
        result("policy_replay_result"),
        |client, mut out, mut err| async move {
            let options = ReplayOptions {
                name: "no-network-shell".into(),
                ..ReplayOptions::default()
            };

            let outcome = policy_cli::replay(&client, &options, &mut out, &mut err).await;
            (outcome, out, err)
        },
    )
    .await;

    assert_eq!(params, json!({"name": "no-network-shell"}));

    let (params, _out, _err) = drive(
        REPLAY_METHOD,
        result("policy_replay_result"),
        |client, mut out, mut err| async move {
            let options = ReplayOptions {
                name: "no-network-shell".into(),
                since: Some("2026-08-01T00:00:00Z".into()),
                ..ReplayOptions::default()
            };

            let outcome = policy_cli::replay(&client, &options, &mut out, &mut err).await;
            (outcome, out, err)
        },
    )
    .await;

    assert_eq!(
        params,
        json!({"name": "no-network-shell", "since": "2026-08-01T00:00:00Z"})
    );
}

#[tokio::test]
async fn replay_out_writes_the_file_promote_reads_back() {
    let scratch = Scratch::new("roundtrip");
    let path = scratch.join("report.json");
    let written = path.clone();

    let (_params, out, err) = drive(
        REPLAY_METHOD,
        result("policy_replay_result"),
        move |client, mut out, mut err| async move {
            let options = ReplayOptions {
                name: "no-network-shell".into(),
                out: Some(written),
                ..ReplayOptions::default()
            };

            let outcome = policy_cli::replay(&client, &options, &mut out, &mut err).await;
            (outcome, out, err)
        },
    )
    .await;

    // The file is the report, whole: `promote` hands the runtime back exactly what the
    // runtime sent, which is what lets the runtime check its own seal.
    assert_eq!(
        policy_cli::read_report(&path).expect("a readable report"),
        result("policy_replay_result")
    );

    // Where it went is a remark about the call, not the answer.
    assert!(err.contains("wrote the report to"), "{err}");
    assert!(!out.contains("wrote the report to"), "{out}");
    assert!(out.contains("277 rows, 0 unreadable"), "{out}");
}

#[tokio::test]
async fn promote_sends_the_report_whole_and_never_an_actor() {
    let scratch = Scratch::new("promote");
    let path = scratch.join("report.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&result("policy_replay_result")).expect("encodable"),
    )
    .expect("a written report");

    let evidence = path.clone();

    let (params, out, _err) = drive(
        PROMOTE_METHOD,
        result("policy_promote_result"),
        move |client, mut out, mut err| async move {
            let options = PromoteOptions {
                name: "no-network-shell".into(),
                tool: "read".into(),
                evidence,
                json: false,
            };

            let outcome = policy_cli::promote(&client, &options, &mut out, &mut err).await;
            (outcome, out, err)
        },
    )
    .await;

    assert_eq!(params["name"], "no-network-shell");
    assert_eq!(params["tool"], "read");
    assert_eq!(params["report"], result("policy_replay_result"));

    // Who promoted is the identity this client authenticated as, read by the runtime from
    // its own side of the socket. There is no spelling of it a client could send.
    assert!(params.get("actor").is_none(), "{params}");
    assert_eq!(params.as_object().expect("an object").len(), 3, "{params}");

    assert!(out.contains("no-network-shell"), "{out}");
}

#[tokio::test]
async fn promote_refuses_a_file_that_is_not_a_report_before_it_uses_the_socket() {
    let scratch = Scratch::new("bad-report");
    let path = scratch.join("report.json");
    std::fs::write(&path, "[1, 2, 3]").expect("a written array");

    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[PROMOTE_METHOD]).await;
        // Nothing else: a refusal here must not have reached the wire.
        peer.request().await
    });

    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .expect("a handshake");

    let mut out = Vec::new();
    let mut err = Vec::new();

    let options = PromoteOptions {
        name: "no-network-shell".into(),
        tool: "read".into(),
        evidence: path,
        json: false,
    };

    let refusal = policy_cli::promote(&connected.client, &options, &mut out, &mut err).await;

    assert!(refusal.is_err(), "{refusal:?}");
    assert!(format!("{:#}", refusal.unwrap_err()).contains("is not a replay report"));
    assert!(out.is_empty());

    drop(connected);
    assert_eq!(script.await.expect("the script"), None);
}

#[tokio::test]
async fn demote_carries_the_sentence_and_the_echo_lands_on_stderr() {
    let sentence = "it allowed a curl a human denied";
    let mut answer = result("policy_promote_result");
    answer["reason"] = json!(sentence);

    let (params, out, err) = drive(
        DEMOTE_METHOD,
        answer,
        |client, mut out, mut err| async move {
            let options = DemoteOptions {
                name: "no-network-shell".into(),
                tool: "bash".into(),
                reason: "it allowed a curl a human denied".into(),
                json: false,
            };

            let outcome = policy_cli::demote(&client, &options, &mut out, &mut err).await;
            (outcome, out, err)
        },
    )
    .await;

    assert_eq!(
        params,
        json!({
            "name": "no-network-shell",
            "tool": "bash",
            "reason": "it allowed a curl a human denied"
        })
    );

    // The runtime echoes the sentence because the record never stored it. It is a remark
    // about the call, so it goes where remarks go.
    assert!(err.contains(sentence), "{err}");
    assert!(!out.contains(sentence), "{out}");
}

#[tokio::test]
async fn clear_sends_an_empty_object_and_prints_what_is_left() {
    let (params, out, _err) = drive(
        CLEAR_METHOD,
        result("policy_status_result"),
        |client, mut out, mut err| async move {
            let outcome = policy_cli::clear(&client, false, &mut out, &mut err).await;
            (outcome, out, err)
        },
    )
    .await;

    assert_eq!(params, json!({}));
    assert!(out.contains("nothing promoted on this node"), "{out}");
}

#[tokio::test]
async fn a_refused_call_is_an_error_rather_than_an_empty_table() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[PROMOTE_METHOD]).await;
        let request = peer.request_for(PROMOTE_METHOD).await;

        // The refusal S2b adds: a caller the runtime cannot attribute does not promote.
        peer.error(
            &request["id"],
            -32003,
            "this call has no resolvable identity",
            Some(json!({"reason": "unattributed_actor"})),
        )
        .await;
    });

    let scratch = Scratch::new("refused");
    let path = scratch.join("report.json");
    std::fs::write(
        &path,
        serde_json::to_string(&result("policy_replay_result")).expect("encodable"),
    )
    .expect("a written report");

    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .expect("a handshake");

    let mut out = Vec::new();
    let mut err = Vec::new();

    let options = PromoteOptions {
        name: "no-network-shell".into(),
        tool: "read".into(),
        evidence: path,
        json: false,
    };

    let refusal = policy_cli::promote(&connected.client, &options, &mut out, &mut err).await;

    assert!(refusal.is_err(), "{refusal:?}");
    assert!(out.is_empty());
    assert!(format!("{:#}", refusal.unwrap_err()).contains("no resolvable identity"));

    script.await.expect("the script");
}
