//! `ouro ledger` against the scripted gateway.
//!
//! Two claims: the params are the flags and nothing else, and the two outputs put the
//! answer on stdout and the incompleteness on stderr — so `--json` stays pipeable while a
//! node that did not answer is still impossible to miss.

mod support;

use serde_json::{json, Value};

use ouro::ledger_cli::{self, Options, LIST_METHOD};

use support::{config, listener, Peer};

fn entry(node: &str, sequence: u64, id: &str, status: &str) -> Value {
    json!({
        "_struct": "Ouroboros.Agent.EffectLedger.Entry",
        "id": id,
        "sequence": sequence,
        "started_sequence": sequence,
        "effect": "permission",
        "principal": "session:abc",
        "status": status,
        "origin_node": node,
        "attempt": {"tool": "Bash"},
        "authority": {"decision": "allow"},
        "cause": {},
        "started_at": "2026-01-01T00:00:00.000000Z",
        "settled_at": "2026-01-01T00:00:00.000000Z"
    })
}

fn answer() -> Value {
    json!({
        "entries": [
            entry("ouroboros@studio", 12, "effect-2", "ok"),
            entry("ouroboros@studio", 11, "effect-1", "denied")
        ],
        "nodes": [
            {"node": "ouroboros@studio", "status": "ok"},
            {"node": "ouroboros@laptop", "status": "unavailable",
             "reason": {"erpc": "noconnection"}}
        ]
    })
}

/// Connects, answers one `ledger.list`, and returns the params it was called with plus the
/// two streams the client wrote.
async fn drive(options: Options, result: Value) -> (Value, String, String) {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[LIST_METHOD]).await;
        let request = peer.request_for(LIST_METHOD).await;
        peer.result(&request["id"], result).await;

        request
    });

    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .expect("a handshake");

    let mut out = Vec::new();
    let mut err = Vec::new();

    ledger_cli::run(&connected.client, &options, &mut out, &mut err)
        .await
        .expect("a ledger read");

    let request = script.await.expect("the script");

    (
        request["params"].clone(),
        String::from_utf8(out).expect("utf-8"),
        String::from_utf8(err).expect("utf-8"),
    )
}

#[tokio::test]
async fn the_default_call_sends_no_params_at_all() {
    // An absent flag is an absent param, so the runtime's defaults apply rather than a
    // second set of defaults living in the client.
    let (params, _out, _err) = drive(Options::default(), answer()).await;

    assert_eq!(params, json!({}));
}

#[tokio::test]
async fn every_flag_becomes_the_param_it_names() {
    let (params, _out, _err) = drive(
        Options {
            fleet: true,
            since: 40,
            json: true,
            limit: Some(7),
        },
        answer(),
    )
    .await;

    assert_eq!(
        params,
        json!({"fleet": true, "since_sequence": 40, "limit": 7})
    );
}

#[tokio::test]
async fn the_table_names_the_node_on_every_row() {
    let (_params, out, err) = drive(Options::default(), answer()).await;

    let rows: Vec<&str> = out.lines().collect();
    assert_eq!(rows.len(), 3, "{out}");

    assert!(rows[0].starts_with("node"), "{out}");
    assert!(rows[0].contains("seq"), "{out}");
    assert!(rows[0].contains("principal"), "{out}");

    // Sequences are minted per node, so a row without its node is a number that means
    // nothing across a fleet.
    assert!(rows[1].starts_with("ouroboros@studio"), "{out}");
    assert!(rows[1].contains("12"), "{out}");
    assert!(rows[1].contains("permission"), "{out}");
    assert!(rows[1].contains("effect-2"), "{out}");
    assert!(rows[2].contains("denied"), "{out}");

    // The incompleteness is real and belongs on the other stream.
    assert!(err.contains("ouroboros@laptop did not answer"), "{err}");
    assert!(!out.contains("ouroboros@laptop"), "{out}");
}

#[tokio::test]
async fn json_is_the_runtime_s_own_records_one_per_line() {
    let (_params, out, err) = drive(
        Options {
            json: true,
            ..Options::default()
        },
        answer(),
    )
    .await;

    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");

    let first: Value = serde_json::from_str(lines[0]).expect("a JSON object");
    // Unreshaped: what a pipe reads is the ledger's own record, struct tag and all.
    assert_eq!(first["_struct"], "Ouroboros.Agent.EffectLedger.Entry");
    assert_eq!(first["id"], "effect-2");
    assert_eq!(first["origin_node"], "ouroboros@studio");

    // Nothing but entries on stdout, so `| jq` never has to skip a warning line.
    assert!(!out.contains("did not answer"), "{out}");
    assert!(err.contains("did not answer"), "{err}");
}

#[tokio::test]
async fn an_empty_ledger_says_so_rather_than_printing_a_header() {
    let (_params, out, err) = drive(
        Options::default(),
        json!({"entries": [], "nodes": [{"node": "ouroboros@studio", "status": "ok"}]}),
    )
    .await;

    assert_eq!(out, "no effects retained\n");
    assert_eq!(err, "");
}

#[tokio::test]
async fn a_refused_call_is_an_error_rather_than_an_empty_table() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[LIST_METHOD]).await;
        let request = peer.request_for(LIST_METHOD).await;
        peer.error(&request["id"], -32003, "operate scope required", None)
            .await;
    });

    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .expect("a handshake");

    let mut out = Vec::new();
    let mut err = Vec::new();

    let refusal = ledger_cli::run(&connected.client, &Options::default(), &mut out, &mut err).await;

    assert!(refusal.is_err(), "{refusal:?}");
    assert!(out.is_empty());
    assert!(format!("{:#}", refusal.unwrap_err()).contains("operate scope required"));

    script.await.expect("the script");
}
