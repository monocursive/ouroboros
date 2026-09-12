//! Native checkpoint preview/import CLI contracts against a real scripted gateway.

mod support;

use clap::Parser;
use ouro::cli::Cli;
use ouro::model::{Plane, StartRequest};
use ouro::replay_cli::{
    self, NativeImportOptions, NativePreviewOptions, IMPORT_NATIVE_METHOD, PREVIEW_NATIVE_METHOD,
};
use serde_json::{json, Value};
use support::{config, listener, Peer};

#[test]
fn request_payloads_are_exact_and_optional_fields_are_omitted() {
    let preview = NativePreviewOptions {
        provider_session_id: "native-source-abc".into(),
        node: None,
        machine: Some(" alpha ".into()),
        json: false,
    };
    assert_eq!(
        preview.params(),
        json!({"provider_session_id":"native-source-abc", "machine":"alpha"})
    );

    let mut start = StartRequest::new(Plane::Interactive);
    start.id = "logical-import".into();
    start.workspace = "/tmp/workspace".into();
    let import = NativeImportOptions {
        provider_session_id: "native-source-abc".into(),
        expected_digest: "deadbeef".into(),
        acknowledge_partial_tail: false,
        start,
        json: false,
    };
    assert_eq!(
        import.params().unwrap(),
        json!({"id":"logical-import", "workspace":"/tmp/workspace", "provider_session_id":"native-source-abc", "expected_digest":"deadbeef"})
    );
}

#[test]
fn parser_requires_digest_and_rejects_two_preview_placements() {
    assert!(Cli::try_parse_from(["ouro", "import-native", "native-source-abc"]).is_err());
    assert!(Cli::try_parse_from([
        "ouro",
        "preview-native",
        "native-source-abc",
        "--node",
        "n@h",
        "--machine",
        "n"
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "ouro",
        "import-native",
        "native-source-abc",
        "--expected-digest",
        "abc"
    ])
    .is_ok());
}

#[tokio::test]
async fn preview_sends_the_provider_id_and_renders_verified_fields() {
    let (listen, address) = listener().await;
    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[PREVIEW_NATIVE_METHOD]).await;
        let request = peer.request().await.unwrap();
        peer.result(&request["id"], json!({"provider_session_id":"native-source-abc", "digest":"abc", "retained_messages":2, "offset":0, "rewind_floor":0, "owned_by":Value::Null})).await;
        request
    });
    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    replay_cli::preview_native(
        &connected.client,
        &NativePreviewOptions {
            provider_session_id: "native-source-abc".into(),
            ..Default::default()
        },
        &mut out,
    )
    .await
    .unwrap();
    let request = peer.await.unwrap();
    assert_eq!(request["method"], PREVIEW_NATIVE_METHOD);
    assert_eq!(
        request["params"],
        json!({"provider_session_id":"native-source-abc"})
    );
    assert!(String::from_utf8(out)
        .unwrap()
        .contains("retained messages  2"));
}

fn import_options() -> NativeImportOptions {
    let mut start = StartRequest::new(Plane::Interactive);
    start.id = "logical-import".into();
    start.workspace = "/tmp/workspace".into();
    NativeImportOptions {
        provider_session_id: "native-source-abc".into(),
        expected_digest: "abc".into(),
        acknowledge_partial_tail: true,
        start,
        json: false,
    }
}

#[tokio::test]
async fn unknown_outcome_retries_once_with_identical_params() {
    let (listen, address) = listener().await;
    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[IMPORT_NATIVE_METHOD]).await;
        let first = peer.request().await.unwrap();
        peer.error(
            &first["id"],
            -32005,
            "timeout",
            Some(json!({"outcome":"unknown"})),
        )
        .await;
        let second = peer.request().await.unwrap();
        peer.result(&second["id"], json!({"id":"logical-import", "provider_session_id":"native-new-xyz", "source_provider_session_id":"native-source-abc", "idempotent":true, "ready":true, "error":Value::Null})).await;
        (first, second)
    });
    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    let mut notes = Vec::new();
    replay_cli::import_native(&connected.client, &import_options(), &mut out, &mut notes)
        .await
        .unwrap();
    let (first, second) = peer.await.unwrap();
    assert_eq!(first["params"], second["params"]);
    assert_eq!(first["params"]["id"], "logical-import");
    assert!(String::from_utf8(notes).unwrap().contains("retrying once"));
}

#[tokio::test]
async fn committed_not_ready_import_renders_admission_failure() {
    let (listen, address) = listener().await;
    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[IMPORT_NATIVE_METHOD]).await;
        let request = peer.request().await.unwrap();
        peer.result(&request["id"], json!({"id":"logical-import", "provider_session_id":"native-new-xyz", "source_provider_session_id":"native-source-abc", "idempotent":false, "ready":false, "error":{"workspace":"conflict"}})).await;
    });
    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    replay_cli::import_native(
        &connected.client,
        &import_options(),
        &mut out,
        &mut Vec::new(),
    )
    .await
    .unwrap();
    peer.await.unwrap();
    let rendered = String::from_utf8(out).unwrap();
    assert!(rendered.contains("ready     false"));
    assert!(rendered.contains("admission"));
    assert!(rendered.contains("conflict"));
}

#[tokio::test]
async fn definite_error_is_not_retried() {
    let (listen, address) = listener().await;
    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[IMPORT_NATIVE_METHOD]).await;
        let request = peer.request().await.unwrap();
        peer.error(&request["id"], -32602, "invalid params", None)
            .await;
        match tokio::time::timeout(std::time::Duration::from_millis(100), peer.request()).await {
            Ok(Some(request)) => request["method"] != IMPORT_NATIVE_METHOD,
            _ => true,
        }
    });
    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .unwrap();
    assert!(replay_cli::import_native(
        &connected.client,
        &import_options(),
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .await
    .is_err());
    assert!(
        peer.await.unwrap(),
        "a definite error must not issue a retry"
    );
}

#[tokio::test]
async fn two_unknown_outcomes_report_ambiguity_and_stop() {
    let (listen, address) = listener().await;
    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[IMPORT_NATIVE_METHOD]).await;
        for _ in 0..2 {
            let request = peer.request().await.unwrap();
            peer.error(
                &request["id"],
                -32005,
                "timeout",
                Some(json!({"outcome":"unknown"})),
            )
            .await;
        }
        match tokio::time::timeout(std::time::Duration::from_millis(100), peer.request()).await {
            Ok(Some(request)) => request["method"] != IMPORT_NATIVE_METHOD,
            _ => true,
        }
    });
    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .unwrap();
    let error = replay_cli::import_native(
        &connected.client,
        &import_options(),
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(peer.await.unwrap(), "the client must stop after one retry");
    assert!(
        error.contains("outcome is unknown for session logical-import"),
        "{error}"
    );
}

#[test]
fn old_server_feature_gate_names_the_missing_method() {
    let hello: ouro::proto::Hello = serde_json::from_value(json!({"server":"old", "node":"n@h", "role":"core", "protocol":1, "scope":"operate", "methods":[]})).unwrap();
    let error = replay_cli::require_method(&hello, IMPORT_NATIVE_METHOD)
        .unwrap_err()
        .to_string();
    assert!(error.contains("runtime is older than this client"));
    assert!(error.contains(IMPORT_NATIVE_METHOD));
}
