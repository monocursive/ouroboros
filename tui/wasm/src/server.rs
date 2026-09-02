//! The JSON-RPC dispatch and the `serve` loop.
//!
//! `serve` reads one request per line from stdin and writes one response per line to stdout —
//! the mode `Ouroboros.Wasm.Pool` spawns and speaks to. The method table is closed and has six
//! entries: `doctor`, `inspect`, `load`, `instantiate`, `call`, `drop`. There is no way to ask
//! this helper to do anything else, which is most of what makes it reviewable — and no way to
//! ask for any of it *unobserved*: a JSON-RPC notification, which by definition gets no reply,
//! is refused for every method that has an effect. See [`handle_message`].
//!
//! Every method runs in `spawn_blocking`. Compiling a component and running a guest are
//! blocking work — hundreds of milliseconds for the first, up to a whole deadline for the
//! second — and the `current_thread` runtime driving stdin must not be sitting inside either.
//! Requests stay sequential on the wire regardless: the peer sends one and waits.
//!
//! The transport's own three codes live here, beside the dispatch that raises them; everything
//! the *host* refuses is in [`crate::refusal`], which is the table worth reading.

use std::io::Write;
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt};

use crate::codec::{self, Frame, Incoming};
use crate::doctor;
use crate::host::Host;
use crate::refusal::{self, Refusal};

const INVALID_REQUEST: refusal::Kind = (-32600, "invalid_request");
const METHOD_NOT_FOUND: refusal::Kind = (-32601, "method_not_found");
const INTERNAL_ERROR: refusal::Kind = (-32603, "internal_error");

/// Consecutive lines that are neither a JSON object nor blank before the child gives up. The
/// peer is trusted, so noise means the pipe is broken and answering it is pointless.
const MAX_NOISE_LINES: usize = 32;

/// Answers one inbound JSON object. `None` where nothing is owed: a notification (no id), or an
/// object that is not a request at all.
///
/// # A notification is not a way to have work done unobserved
///
/// JSON-RPC says an object with no `id` is a notification and gets no reply. Five of this
/// helper's six methods have effects — `load` admits a component, `instantiate` stands a guest
/// up, `call` runs one, `drop` takes one down — and running any of those with nobody owed an
/// answer is a request whose refusals go nowhere, whose fuel accounting goes nowhere, and whose
/// failure the peer cannot see. So they are not run: a notification naming a side-effectful
/// method is refused, the refusal goes to stderr where the pool's log is, and nothing happens.
///
/// `doctor` is the exception, and only because it is the one method that does nothing: it reads
/// two table lengths. Running it for a peer that will not hear the answer is a no-op, and
/// refusing it would make the handshake's shape depend on whether an `id` was included.
pub fn handle_message(host: &Host, message: Value) -> Option<String> {
    let id = message.get("id").cloned();

    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return id.map(|id| {
            encode(error_frame(
                id,
                &refusal::refuse(INVALID_REQUEST, "missing method"),
            ))
        });
    };

    if id.is_none() && method != "doctor" {
        // Deliberately not `eprintln!`, which panics when the write fails; an owner that closed
        // this pipe is not a reason to unwind.
        let _ = writeln!(
            std::io::stderr(),
            "ouro-wasm: refused notification `{}`: {} ({}); \
             a method with effects needs an id, so its answer has somewhere to go",
            bounded(method),
            INVALID_REQUEST.1,
            INVALID_REQUEST.0,
        );
        return None;
    }

    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let outcome = dispatch(host, method, &params);

    let id = id?;
    Some(encode(match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(refusal) => error_frame(id, &refusal),
    }))
}

/// How much of a peer-chosen method name goes into that stderr line. A method name is a string
/// the peer picked, and it must not be able to forge a log line or a long one.
const MAX_METHOD_ECHO: usize = 64;

fn bounded(method: &str) -> String {
    let mut out = String::with_capacity(method.len().min(MAX_METHOD_ECHO));
    for character in method.chars() {
        if out.len() + character.len_utf8() > MAX_METHOD_ECHO {
            out.push('…');
            break;
        }
        out.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    out
}

fn dispatch(host: &Host, method: &str, params: &Value) -> Result<Value, Refusal> {
    match method {
        "doctor" => Ok(doctor::report(Some(host.census()))),
        "inspect" => host.inspect(params),
        "load" => host.load(params),
        "instantiate" => host.instantiate(params),
        "call" => host.call(params),
        "drop" => host.drop_instance(params),
        other => Err(refusal::refuse(
            METHOD_NOT_FOUND,
            format!("method not found: {other}"),
        )),
    }
}

/// The `serve` loop over any reader/writer pair, so a test can be the peer.
pub async fn run<R, W>(
    host: Arc<Host>,
    mut reader: R,
    mut writer: W,
    max_frame_bytes: usize,
) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut noise = 0usize;

    loop {
        match codec::read_frame(&mut reader, &mut buf, max_frame_bytes).await? {
            Frame::Eof => return Ok(()),

            Frame::Oversize => {
                let frame = encode(error_frame(
                    Value::Null,
                    &refusal::refuse(
                        INVALID_REQUEST,
                        format!("frame exceeds max_frame_bytes ({max_frame_bytes})"),
                    ),
                ));
                write_line(&mut writer, &frame).await?;
                noise += 1;
            }

            Frame::Line => match codec::classify(&buf) {
                Incoming::Blank => {}
                Incoming::Noise => noise += 1,
                Incoming::Message(value) => {
                    noise = 0;
                    let id = value.get("id").cloned();
                    let host = Arc::clone(&host);
                    match tokio::task::spawn_blocking(move || handle_message(&host, value)).await {
                        Ok(Some(frame)) => write_line(&mut writer, &frame).await?,
                        Ok(None) => {}
                        // A panic inside wasmtime is a bug in this helper, not a guest escape,
                        // and the peer is owed an answer rather than a silent hang.
                        Err(_) => {
                            if let Some(id) = id {
                                let frame = encode(error_frame(
                                    id,
                                    &refusal::refuse(INTERNAL_ERROR, "helper task panicked"),
                                ));
                                write_line(&mut writer, &frame).await?;
                            }
                        }
                    }
                }
            },
        }

        if noise > MAX_NOISE_LINES {
            return Ok(());
        }
    }
}

fn error_frame(id: Value, refusal: &Refusal) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": refusal.code,
            "message": refusal.message,
            "data": { "refusal": refusal.refusal },
        }
    })
}

fn encode(value: Value) -> String {
    serde_json::to_string(&value).unwrap_or_else(|_| {
        format!(
            r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":{},"message":"unencodable","data":{{"refusal":"{}"}}}}}}"#,
            INTERNAL_ERROR.0, INTERNAL_ERROR.1
        )
    })
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, frame: &str) -> std::io::Result<()> {
    writer.write_all(frame.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    fn host() -> Arc<Host> {
        Arc::new(Host::new().expect("an engine on this host"))
    }

    fn request(id: i64, method: &str) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method })
    }

    fn answer(host: &Host, message: Value) -> Value {
        serde_json::from_str(&handle_message(host, message).expect("a request is answered"))
            .expect("the answer is JSON")
    }

    #[test]
    fn doctor_answers_with_this_build() {
        let value = answer(&host(), request(1, "doctor"));
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["usable"], true);
        assert_eq!(value["result"]["worlds"][0], crate::world::ID);
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let value = answer(&host(), request(2, "evaluate"));
        assert_eq!(value["error"]["code"], METHOD_NOT_FOUND.0);
        assert_eq!(value["error"]["data"]["refusal"], METHOD_NOT_FOUND.1);
    }

    #[test]
    fn the_six_methods_answer_and_refuse_in_their_own_band() {
        // No params at all, so each is refused — but refused by *this* helper's vocabulary,
        // never by a panic and never by a code outside the private band or invalid-params.
        for method in ["inspect", "load", "instantiate", "call", "drop"] {
            let value = answer(&host(), request(3, method));
            let code = value["error"]["code"].as_i64().expect("an error code");
            assert!(
                (-32099..=-32001).contains(&code) || code == refusal::INVALID_PARAMS.0,
                "{method} answered with {code}"
            );
            assert!(value["error"]["data"]["refusal"].is_string());
        }
    }

    #[test]
    fn a_notification_is_not_answered() {
        assert!(handle_message(&host(), json!({ "jsonrpc": "2.0", "method": "doctor" })).is_none());
    }

    /// A notification naming a method with effects is refused rather than run. Unobservable
    /// here — the proof that it did not *happen* is
    /// `containment::a_notification_is_refused_rather_than_run`, which asks `doctor` afterwards —
    /// but the shape is checked: still no answer, and `doctor` is still the one carve-out.
    #[test]
    fn a_notification_naming_a_method_with_effects_is_not_answered_either() {
        for method in ["inspect", "load", "instantiate", "call", "drop"] {
            assert!(
                handle_message(&host(), json!({ "jsonrpc": "2.0", "method": method })).is_none(),
                "{method} as a notification must not be answered"
            );
        }
    }

    #[test]
    fn a_peer_chosen_method_name_cannot_forge_the_refusal_line() {
        let forged = bounded("load\nouro-wasm: second");
        assert!(!forged.contains('\n'));
        assert_eq!(forged, "load ouro-wasm: second");
        assert!(bounded(&"m".repeat(4096)).len() <= MAX_METHOD_ECHO + 3);
    }

    #[test]
    fn an_object_without_a_method_but_with_an_id_is_invalid() {
        let value = answer(&host(), json!({ "jsonrpc": "2.0", "id": 3 }));
        assert_eq!(value["error"]["code"], INVALID_REQUEST.0);
    }

    #[test]
    fn drop_is_idempotent() {
        let host = host();
        for _ in 0..2 {
            let value = answer(
                &host,
                json!({ "jsonrpc": "2.0", "id": 4, "method": "drop",
                        "params": { "instance": "never-existed" } }),
            );
            assert_eq!(value["result"]["dropped"], false);
        }
    }

    #[tokio::test]
    async fn serve_answers_a_request_and_stops_at_eof() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"doctor\"}\n".to_vec();
        let mut output: Vec<u8> = Vec::new();

        run(host(), BufReader::new(&input[..]), &mut output, 1024)
            .await
            .unwrap();

        let text = String::from_utf8(output).unwrap();
        let mut lines = text.lines();
        let value: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["usable"], true);
        assert!(lines.next().is_none(), "expected exactly one response line");
    }

    #[tokio::test]
    async fn serve_ignores_noise_and_writes_nothing() {
        let input = b"this is not json\n[]\n\n".to_vec();
        let mut output: Vec<u8> = Vec::new();

        run(host(), BufReader::new(&input[..]), &mut output, 1024)
            .await
            .unwrap();
        assert!(output.is_empty(), "noise must not be answered");
    }

    #[tokio::test]
    async fn serve_gives_up_on_a_pipe_that_is_only_noise() {
        let input = "garbage\n".repeat(MAX_NOISE_LINES + 5).into_bytes();
        let mut output: Vec<u8> = Vec::new();

        run(host(), BufReader::new(&input[..]), &mut output, 1024)
            .await
            .unwrap();
        assert!(output.is_empty());
    }

    /// The give-up is a *decision*, not the end of the stream.
    ///
    /// [`serve_gives_up_on_a_pipe_that_is_only_noise`] cannot tell the two apart: its input ends,
    /// so the loop returns and writes nothing whether the budget exists or not. Delete the budget
    /// check and that test stays green. This one puts a perfectly good request *after* the noise:
    /// if the loop is still reading, it answers it, and the assertion below fails.
    const DOCTOR: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"doctor\"}\n";

    #[tokio::test]
    async fn serve_stops_reading_past_the_noise_budget() {
        let mut input = "garbage\n".repeat(MAX_NOISE_LINES + 1).into_bytes();
        input.extend_from_slice(DOCTOR);
        let mut output: Vec<u8> = Vec::new();

        run(host(), BufReader::new(&input[..]), &mut output, 1024)
            .await
            .unwrap();
        assert!(
            output.is_empty(),
            "the loop answered a request after {} noise lines, so it never gave up: {}",
            MAX_NOISE_LINES + 1,
            String::from_utf8_lossy(&output)
        );
    }

    /// And the budget is a budget rather than a hair trigger: exactly [`MAX_NOISE_LINES`] of
    /// noise costs the peer nothing, and a message resets the count, so a long-lived pipe that
    /// hiccups now and then is never given up on.
    #[tokio::test]
    async fn noise_under_the_budget_is_survivable_and_a_message_resets_it() {
        let mut input = "garbage\n".repeat(MAX_NOISE_LINES).into_bytes();
        input.extend_from_slice(DOCTOR);
        input.extend_from_slice(&"garbage\n".repeat(MAX_NOISE_LINES).into_bytes());
        input.extend_from_slice(DOCTOR);
        let mut output: Vec<u8> = Vec::new();

        run(host(), BufReader::new(&input[..]), &mut output, 1024)
            .await
            .unwrap();

        let text = String::from_utf8(output).unwrap();
        assert_eq!(
            text.lines().count(),
            2,
            "both requests must be answered: {text}"
        );
    }

    #[tokio::test]
    async fn serve_reports_an_oversize_frame_and_keeps_going() {
        let mut input = vec![b'x'; 100];
        input.push(b'\n');
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"doctor\"}\n");
        let mut output: Vec<u8> = Vec::new();

        run(host(), BufReader::new(&input[..]), &mut output, 64)
            .await
            .unwrap();

        let text = String::from_utf8(output).unwrap();
        let mut lines = text.lines();
        let oversize: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(oversize["error"]["code"], INVALID_REQUEST.0);
        let answered: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(answered["id"], 9);
    }
}
