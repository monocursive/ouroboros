//! The JSON-RPC dispatch and the `serve` loop (doc §7).
//!
//! `serve` reads one request per line from stdin and writes one response per line to stdout —
//! the mode `Native.Desktop.Pool` spawns and speaks to. Observe methods stay sequential on
//! the wire. `windows`, `state`, and `act` all run in a blocking task so a `cancel`
//! notification (or EOF) can abort them: AX walks and ScreenCaptureKit must not stall the
//! tokio `current_thread` runtime, and an in-flight act must release what it holds (doc §7.5).

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt};

use crate::codec::{self, Frame, Incoming};
use crate::doctor;

/// An observe method (`windows`/`state`) failed at runtime.
pub const OBSERVE_ERROR: i64 = -32001;
/// The resolved target app is on the helper's `--deny-app` belt (doc §7.3).
pub const DENIED_APP: i64 = -32002;
/// The method is real but this platform is not macOS.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub const UNSUPPORTED_PLATFORM: i64 = -32003;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INTERNAL_ERROR: i64 = -32603;

/// Consecutive lines that are neither a JSON object nor blank before the child gives up.
const MAX_NOISE_LINES: usize = 32;

/// The dispatcher. Holds the `--deny-app` belt.
pub struct Server {
    deny_apps: Vec<String>,
}

impl Server {
    pub fn new(deny_apps: Vec<String>) -> Self {
        Self { deny_apps }
    }

    /// The `--deny-app` list this helper was started with (doc §7.3).
    pub fn deny_apps(&self) -> &[String] {
        &self.deny_apps
    }

    /// Answers one inbound JSON object. `None` where nothing is owed: a notification (no id),
    /// or an object that is not a request at all.
    pub fn handle_message(&self, message: Value) -> Option<String> {
        let id = message.get("id").cloned();

        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return id.map(|id| encode(error_frame(id, INVALID_REQUEST, "missing method")));
        };

        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let outcome = self.dispatch(method, params);

        let id = id?;
        Some(encode(match outcome {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => error_frame(id, code, &message),
        }))
    }

    fn dispatch(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        let cancel = std::sync::atomic::AtomicBool::new(false);
        match method {
            "doctor" => Ok(doctor::report()),
            "windows" => crate::windows::handle(&cancel),
            "state" => crate::state::handle(self.deny_apps(), params, &cancel),
            "act" => crate::act::handle(&self.deny_apps, params, &cancel),
            "cancel" => Ok(Value::Null),
            other => Err((METHOD_NOT_FOUND, format!("method not found: {other}"))),
        }
    }
}

/// The `serve` loop over any reader/writer pair, so a test can be the peer.
pub async fn run<R, W>(
    server: Server,
    mut reader: R,
    mut writer: W,
    max_frame_bytes: usize,
) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !server.deny_apps().is_empty() {
        eprintln!(
            "ouro-computer-use: {} app(s) on the --deny-app belt",
            server.deny_apps().len()
        );
    }

    let mut buf = Vec::new();
    let mut noise = 0usize;

    loop {
        match codec::read_frame(&mut reader, &mut buf, max_frame_bytes).await? {
            Frame::Eof => return Ok(()),

            Frame::Oversize => {
                let frame = encode(error_frame(
                    Value::Null,
                    INVALID_REQUEST,
                    &format!("frame exceeds max_frame_bytes ({max_frame_bytes})"),
                ));
                write_line(&mut writer, &frame).await?;
                noise += 1;
            }

            Frame::Line => match codec::classify(&buf) {
                Incoming::Blank => {}
                Incoming::Noise => noise += 1,
                Incoming::Message(value) => {
                    noise = 0;
                    let method = value.get("method").and_then(Value::as_str).unwrap_or("");
                    if ["windows", "state", "act"].contains(&method) {
                        serve_blocking(
                            &server,
                            &mut reader,
                            &mut writer,
                            value,
                            max_frame_bytes,
                            &mut buf,
                        )
                        .await?;
                    } else if let Some(frame) = server.handle_message(value) {
                        write_line(&mut writer, &frame).await?;
                    }
                }
            },
        }

        if noise > MAX_NOISE_LINES {
            return Ok(());
        }
    }
}

fn error_frame(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn encode(value: Value) -> String {
    serde_json::to_string(&value).unwrap_or_else(|_| {
        format!(
            r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":{INTERNAL_ERROR},"message":"unencodable"}}}}"#
        )
    })
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, frame: &str) -> std::io::Result<()> {
    writer.write_all(frame.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

async fn serve_blocking<R, W>(
    server: &Server,
    reader: &mut R,
    writer: &mut W,
    request: Value,
    max_frame_bytes: usize,
    buf: &mut Vec<u8>,
) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let cancel = Arc::new(AtomicBool::new(false));
    let deny = server.deny_apps().to_vec();
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let id = request.get("id").cloned();
    let flag = cancel.clone();
    let mut work = tokio::task::spawn_blocking(move || match method.as_str() {
        "windows" => crate::windows::handle(&flag),
        "state" => crate::state::handle(&deny, params, &flag),
        _ => crate::act::handle(&deny, params, &flag),
    });

    loop {
        tokio::select! {
            biased;
            done = &mut work => {
                let outcome = match done {
                    Ok(result) => result,
                    Err(_) => Err((INTERNAL_ERROR, "helper task panicked".into())),
                };
                if let Some(id) = id {
                    let frame = encode(match outcome {
                        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
                        Err((code, message)) => error_frame(id, code, &message),
                    });
                    write_line(writer, &frame).await?;
                }
                return Ok(());
            }
            frame = codec::read_frame(reader, buf, max_frame_bytes) => {
                match frame? {
                    Frame::Eof => {
                        cancel.store(true, Ordering::SeqCst);
                        let _ = work.await;
                        return Ok(());
                    }
                    Frame::Oversize => {
                        let frame = encode(error_frame(
                            Value::Null,
                            INVALID_REQUEST,
                            &format!("frame exceeds max_frame_bytes ({max_frame_bytes})"),
                        ));
                        write_line(writer, &frame).await?;
                    }
                    Frame::Line => match codec::classify(buf) {
                        Incoming::Message(value)
                            if value.get("method").and_then(Value::as_str) == Some("cancel") =>
                        {
                            cancel.store(true, Ordering::SeqCst);
                            if let Some(cid) = value.get("id").cloned() {
                                let frame = encode(json!({
                                    "jsonrpc": "2.0",
                                    "id": cid,
                                    "result": Value::Null
                                }));
                                write_line(writer, &frame).await?;
                            }
                        }
                        _other => {}
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    fn server() -> Server {
        Server::new(Vec::new())
    }

    fn request(id: i64, method: &str) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method })
    }

    #[test]
    fn deny_apps_are_retained() {
        let server = Server::new(vec!["com.apple.Terminal".to_string()]);
        assert_eq!(server.deny_apps(), ["com.apple.Terminal"]);
    }

    #[test]
    fn doctor_answers_with_a_platform() {
        let frame = server().handle_message(request(1, "doctor")).unwrap();
        let value: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(value["id"], 1);
        assert!(value["result"]["platform"]["os"].is_string());
    }

    #[test]
    fn act_is_answered_never_faked() {
        let frame = server()
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "act",
                "params": { "action": "click", "point": { "x": 1, "y": 2 } }
            }))
            .unwrap();
        let value: Value = serde_json::from_str(&frame).unwrap();
        if value.get("result").is_some() {
            assert!(value["result"]["ok"].is_boolean());
        } else {
            let code = value["error"]["code"].as_i64().unwrap();
            assert!(
                (-32099..=-32000).contains(&code),
                "unexpected error code for act: {code}"
            );
        }
    }

    #[test]
    fn observe_methods_are_answered_never_faked() {
        for method in ["windows", "state"] {
            let frame = server().handle_message(request(8, method)).unwrap();
            let value: Value = serde_json::from_str(&frame).unwrap();
            if value.get("result").is_some() {
                assert!(value["error"].is_null());
            } else {
                let code = value["error"]["code"].as_i64().unwrap();
                assert!(
                    (-32099..=-32000).contains(&code),
                    "unexpected error code for {method}: {code}"
                );
            }
        }
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let frame = server().handle_message(request(2, "teleport")).unwrap();
        let value: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(value["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn a_notification_is_not_answered() {
        let notification = json!({ "jsonrpc": "2.0", "method": "cancel" });
        assert!(server().handle_message(notification).is_none());
    }

    #[test]
    fn an_object_without_a_method_but_with_an_id_is_invalid() {
        let frame = server()
            .handle_message(json!({ "jsonrpc": "2.0", "id": 3 }))
            .unwrap();
        let value: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(value["error"]["code"], INVALID_REQUEST);
    }

    #[tokio::test]
    async fn serve_answers_a_request_and_stops_at_eof() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"doctor\"}\n".to_vec();
        let reader = BufReader::new(&input[..]);
        let mut output: Vec<u8> = Vec::new();

        run(server(), reader, &mut output, 1024).await.unwrap();

        let text = String::from_utf8(output).unwrap();
        let mut lines = text.lines();
        let value: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(value["id"], 1);
        assert!(value["result"]["readiness"].is_object());
        assert!(lines.next().is_none(), "expected exactly one response line");
    }

    #[tokio::test]
    async fn serve_ignores_noise_and_writes_nothing() {
        let input = b"this is not json\n[]\n\n".to_vec();
        let reader = BufReader::new(&input[..]);
        let mut output: Vec<u8> = Vec::new();

        run(server(), reader, &mut output, 1024).await.unwrap();
        assert!(output.is_empty(), "noise must not be answered");
    }

    #[tokio::test]
    async fn serve_reports_an_oversize_frame() {
        let mut input = vec![b'x'; 100];
        input.push(b'\n');
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"doctor\"}\n");
        let reader = BufReader::new(&input[..]);
        let mut output: Vec<u8> = Vec::new();

        run(server(), reader, &mut output, 64).await.unwrap();

        let text = String::from_utf8(output).unwrap();
        let mut lines = text.lines();
        let oversize: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(oversize["error"]["code"], INVALID_REQUEST);
        let answered: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(answered["id"], 9);
    }
}
