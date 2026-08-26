//! The JSON-RPC dispatch and the `serve` loop (doc §7).
//!
//! `serve` reads one request per line from stdin and writes one response per line to stdout —
//! the mode `Native.Desktop.Pool` spawns and speaks to. The loop is strictly sequential, so
//! there is always exactly **one in-flight request**; Phase 1's long-running `act` will move
//! to a `tokio::sync::Mutex` plus a detached task (doc §7.5) but Phase 0 needs neither.
//!
//! Phase 0 answers `doctor` for real and returns a structured "not implemented in phase 0"
//! error for `windows` / `state` / `act`. Per the honesty invariant, a stub returns that
//! error — never plausible-looking window lists, trees, or screenshots.
//!
//! ## Phase-1 input invariants to honor later (NOT implemented here)
//!
//! When `act` becomes real, two rules from doc §7.4/§7.5 must hold and are easy to lose:
//!   * **Never replay input across backends after a partial failure.** If one injection path
//!     (AXPress, then CGEvent) partially lands and fails, do not re-run the sequence on the
//!     other backend — a half-applied chord replayed is double input, not a retry.
//!   * **Run stateful input in a detached, cancellation-safe task.** Key-down/up and
//!     button-hold must live in a task that releases what it is holding even when the call is
//!     cancelled mid-way (the "cancellation-safe guard" shape), so a `Command-.` interrupt
//!     never leaves a key or mouse button stuck down.

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt};

use crate::codec::{self, Frame, Incoming};
use crate::doctor;

/// The error code for a method whose real implementation lands in a later phase. -32000 sits
/// inside JSON-RPC 2.0's reserved server-error band (-32000..=-32099).
const NOT_IMPLEMENTED: i64 = -32000;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INTERNAL_ERROR: i64 = -32603;

/// Consecutive lines that are neither a JSON object nor blank before the child gives up. A
/// trusted parent emitting garbage is a broken pipe, not a peer to keep serving; any
/// well-formed message resets the count.
const MAX_NOISE_LINES: usize = 32;

/// The dispatcher. Holds the `--deny-app` belt for Phase 1; Phase 0 dispatch is stateless.
pub struct Server {
    deny_apps: Vec<String>,
}

impl Server {
    pub fn new(deny_apps: Vec<String>) -> Self {
        Self { deny_apps }
    }

    /// The `--deny-app` list this helper was started with (doc §7.3). Retained now, enforced
    /// in Phase 1 when `state`/`act` stop being stubs.
    pub fn deny_apps(&self) -> &[String] {
        &self.deny_apps
    }

    /// Answers one inbound JSON object. `None` where nothing is owed: a notification (no id),
    /// or an object that is not a request at all.
    pub fn handle_message(&self, message: Value) -> Option<String> {
        let id = message.get("id").cloned();

        let Some(method) = message.get("method").and_then(Value::as_str) else {
            // No method. If it carried an id it was trying to be a request; otherwise it is a
            // response this helper never asked for, and nothing is owed.
            return id.map(|id| encode(error_frame(id, INVALID_REQUEST, "missing method")));
        };

        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let outcome = self.dispatch(method, params);

        // A notification is acted on for its side effects and never answered.
        let id = id?;
        Some(encode(match outcome {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => error_frame(id, code, &message),
        }))
    }

    fn dispatch(&self, method: &str, _params: Value) -> Result<Value, (i64, String)> {
        match method {
            "doctor" => Ok(doctor::report()),

            // Structured stubs. Never fabricated data (honesty invariant).
            "windows" | "state" | "act" => Err(not_implemented(method)),

            // A cancel targets an in-flight `act`, of which Phase 0 has none. As a
            // notification it is dropped; as a request it gets an explicit null.
            "cancel" => Ok(Value::Null),

            other => Err((METHOD_NOT_FOUND, format!("method not found: {other}"))),
        }
    }
}

/// The message every Phase-0 stub returns: the phrase the contract names, prefixed with the
/// method so a caller reading the error knows which one it hit.
fn not_implemented(method: &str) -> (i64, String) {
    (
        NOT_IMPLEMENTED,
        format!("{method} is not implemented in phase 0"),
    )
}

/// The `serve` loop over any reader/writer pair, so a test can be the peer.
///
/// Ends cleanly on EOF, or when a run of noise exceeds [`MAX_NOISE_LINES`] (a broken pipe:
/// exiting lets the parent's `broken_ms` posture avoid respawning a dying child in a tight
/// loop). Returns `Err` only on an actual stdout write failure.
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
        // Operator signal on stderr; stdout carries protocol only.
        eprintln!(
            "ouro-computer-use: {} app(s) on the --deny-app belt, enforced when observe/act land in phase 1",
            server.deny_apps().len()
        );
    }

    let mut buf = Vec::new();
    let mut noise = 0usize;

    loop {
        match codec::read_frame(&mut reader, &mut buf, max_frame_bytes).await? {
            Frame::Eof => return Ok(()),

            Frame::Oversize => {
                // Tell the parent why the frame was dropped, then count it against the budget:
                // a flood of oversize frames is a broken pipe just like a flood of garbage.
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
                    if let Some(frame) = server.handle_message(value) {
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
    // One message per line; `serde_json` escapes any interior newline, so the frame itself
    // can never contain one — exactly what the line protocol requires.
    writer.write_all(frame.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
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
    fn stub_methods_return_not_implemented() {
        for method in ["windows", "state", "act"] {
            let frame = server().handle_message(request(7, method)).unwrap();
            let value: Value = serde_json::from_str(&frame).unwrap();
            assert_eq!(value["error"]["code"], NOT_IMPLEMENTED);
            let message = value["error"]["message"].as_str().unwrap();
            assert!(
                message.contains("not implemented in phase 0"),
                "unexpected message: {message}"
            );
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
        // No id → nothing owed, even for a real method.
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
        // A long garbage line over the cap, then a valid request under it that must still be
        // served — the cap (64) sits above the request's length and below the garbage line's.
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
