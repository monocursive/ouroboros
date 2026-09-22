//! N02, N04 and the proxy half of N03, in process.
//!
//! Every test runs the real proxy on a Unix listener in a private temporary
//! directory, with loopback fixture servers reached through explicit address
//! grants and a controlled resolver. No public DNS is used. Tests synchronize
//! on protocol events (a response head, a result reaching the sink, an
//! accepted connection); the only clock-based assertions are the deadline
//! tests, which check a lower bound and a generous upper bound.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use jsonschema::{Registry, Resource, Validator};
use ouro_jail::network::Rules;
use ouro_jail::observer::CoverageClass;
use ouro_jail::proxy::{
    self, Budgets, EndReason, FixtureAnswer, FixtureResolver, ProxyConfig, ProxyDecision,
    ProxyHandle, ProxyResult, ProxySink, ProxySummary, Reason, RequestKind, ResolveError, Resolver,
    SystemResolver,
};
use ouro_jail::records::{Completion, Decision};

/// Upper bound for any wait. Never reached when the behaviour is correct.
const WAIT: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Sink {
    results: Mutex<Vec<ProxyResult>>,
    changed: Condvar,
}

impl ProxySink for Sink {
    fn emit(&self, result: ProxyResult) {
        self.results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(result);
        self.changed.notify_all();
    }
}

impl Sink {
    fn wait_for(&self, count: usize) -> Vec<ProxyResult> {
        let deadline = Instant::now() + WAIT;
        let mut results = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        while results.len() < count {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for {count} results"
            );
            results = self
                .changed
                .wait_timeout(results, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        results.clone()
    }

    fn snapshot(&self) -> Vec<ProxyResult> {
        self.results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    path: PathBuf,
    handle: ProxyHandle,
    sink: Arc<Sink>,
}

fn start_with(
    allow: &[String],
    budgets: Budgets,
    resolver: Arc<dyn Resolver + Send + Sync>,
) -> Harness {
    let dir = tempfile::tempdir().expect("a private temporary directory");
    let path = dir.path().join("proxy.sock");
    let listener = UnixListener::bind(&path).expect("binds the proxy socket");
    let rules = Rules::from_strings(allow, &[]).expect("the test rules parse");
    let sink = Arc::new(Sink::default());
    let handle = proxy::start(
        ProxyConfig {
            listener,
            rules,
            budgets,
            resolver,
        },
        Arc::clone(&sink) as Arc<dyn ProxySink>,
    )
    .expect("the proxy starts");
    Harness {
        _dir: dir,
        path,
        handle,
        sink,
    }
}

fn start(allow: &[String], resolver: &Arc<FixtureResolver>) -> Harness {
    start_with(
        allow,
        Budgets::default(),
        Arc::clone(resolver) as Arc<dyn Resolver + Send + Sync>,
    )
}

impl Harness {
    fn connect(&self) -> UnixStream {
        let stream = UnixStream::connect(&self.path).expect("connects to the proxy");
        stream.set_read_timeout(Some(WAIT)).expect("sets a timeout");
        stream
            .set_write_timeout(Some(WAIT))
            .expect("sets a timeout");
        stream
    }

    /// Stops the proxy and checks the accounting identity: every accepted
    /// connection produced exactly one result, or none because it sent no
    /// byte, or is reported missing.
    fn stop(self, budget: Duration) -> (ProxySummary, Vec<ProxyResult>) {
        let summary = self.handle.stop(budget);
        let results = self.sink.snapshot();
        assert_eq!(
            summary.accepted,
            summary.results_emitted + summary.results_missing + summary.without_request,
            "{summary:?}"
        );
        assert_eq!(
            u64::try_from(results.len()).expect("fits"),
            summary.results_emitted,
            "the sink saw exactly the emitted results"
        );
        let mut ids: Vec<u64> = results.iter().map(|result| result.request_id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), results.len(), "one result per request id");
        if !budget.is_zero() {
            assert!(summary.listener_closed, "{summary:?}");
        }
        (summary, results)
    }
}

fn fixtures(host: &str, answers: &[&str]) -> Arc<FixtureResolver> {
    let resolver = Arc::new(FixtureResolver::new());
    if !host.is_empty() {
        resolver.script(
            host,
            vec![FixtureAnswer::Addresses(
                answers
                    .iter()
                    .map(|a| a.parse().expect("an address"))
                    .collect(),
            )],
        );
    }
    resolver
}

fn loopback() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("binds a loopback fixture");
    let port = listener.local_addr().expect("has an address").port();
    (listener, port)
}

/// Accepts `count` connections and echoes each until its EOF.
fn echo_server(listener: TcpListener, count: usize) -> thread::JoinHandle<usize> {
    thread::spawn(move || {
        let mut served = 0;
        for _ in 0..count {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if stream.write_all(&buf[..read]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = stream.shutdown(Shutdown::Write);
            served += 1;
        }
        served
    })
}

fn assert_no_connection(listener: &TcpListener) {
    listener.set_nonblocking(true).expect("nonblocking");
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        other => panic!("the fixture received a connection: {other:?}"),
    }
}

/// Reads one response head; returns the status and the head text.
fn read_head(stream: &mut UnixStream) -> (u16, String) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            Ok(_) => panic!("EOF before a response head: {head:?}"),
            Err(error) => panic!("reading a response head: {error}"),
        }
        assert!(head.len() < 8192, "an oversized response head");
    }
    let text = String::from_utf8(head).expect("an ASCII response head");
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("a status code");
    (status, text)
}

fn reason_of(head: &str) -> Option<&str> {
    head.lines()
        .find_map(|line| line.strip_prefix("X-Ouro-Proxy-Reason: "))
}

fn read_to_eof(stream: &mut UnixStream) -> Vec<u8> {
    let mut out = Vec::new();
    stream.read_to_end(&mut out).expect("reads to EOF");
    out
}

/// Sends a request and returns the refusal's status and reason code.
fn refused(harness: &Harness, request: &str) -> (u16, String) {
    let mut client = harness.connect();
    client.write_all(request.as_bytes()).expect("writes");
    let (status, head) = read_head(&mut client);
    let reason = reason_of(&head)
        .expect("a refusal names its reason")
        .to_owned();
    (status, reason)
}

fn connect_request(authority: &str) -> String {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
}

fn allow(rules: &[&str]) -> Vec<String> {
    rules.iter().map(|rule| (*rule).to_owned()).collect()
}

// ---------------------------------------------------------------------------
// N02: exactly one matching result per request
// ---------------------------------------------------------------------------

#[test]
fn n02_allowed_connect_tunnel_yields_one_allow_result_at_close() {
    let (listener, port) = loopback();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut hello = [0u8; 5];
        stream.read_exact(&mut hello).expect("reads");
        assert_eq!(&hello, b"hello");
        stream.write_all(b"world!").expect("writes");
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).expect("reads to EOF");
        rest
    });
    let resolver = fixtures("fixture.test", &["127.0.0.1"]);
    let harness = start(
        &allow(&[
            &format!("fixture.test:{port}"),
            &format!("127.0.0.1:{port}"),
        ]),
        &resolver,
    );
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("fixture.test:{port}")).as_bytes())
        .expect("writes");
    let (status, _) = read_head(&mut client);
    assert_eq!(status, 200);
    client.write_all(b"hello").expect("writes");
    let mut world = [0u8; 6];
    client.read_exact(&mut world).expect("reads");
    assert_eq!(&world, b"world!");
    assert!(
        harness.sink.snapshot().is_empty(),
        "a tunnel reports at close"
    );
    client.shutdown(Shutdown::Write).expect("half-closes");
    assert!(read_to_eof(&mut client).is_empty());
    assert!(server.join().expect("the server ran").is_empty());

    let results = harness.sink.wait_for(1);
    let result = &results[0];
    assert_eq!(result.decision, ProxyDecision::Allow);
    assert_eq!(result.reason, Reason::Relayed);
    assert_eq!(result.kind, RequestKind::Connect);
    assert_eq!(
        result.destination.as_ref().map(ToString::to_string),
        Some(format!("fixture.test:{port}"))
    );
    assert_eq!(
        result.connected,
        Some(SocketAddr::new("127.0.0.1".parse().expect("ip"), port))
    );
    assert_eq!((result.bytes_out, result.bytes_in), (5, 6));
    assert_eq!(result.end, Some(EndReason::ClientClosed));
    assert_eq!(resolver.calls("fixture.test"), 1);
    let (summary, results) = harness.stop(WAIT);
    assert_eq!(results.len(), 1);
    assert!(summary.complete());
    assert_eq!(summary.results_missing, 0);
}

#[test]
fn n02_denied_request_yields_one_deny_result_before_the_response() {
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&["allowed.test:443"]), &resolver);
    let (status, reason) = refused(&harness, &connect_request("denied.test:443"));
    assert_eq!((status, reason.as_str()), (403, "host_not_allowed"));
    // Emitted before the response was written: already in the sink.
    let results = harness.sink.snapshot();
    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result.decision, ProxyDecision::Deny);
    assert_eq!(result.reason, Reason::HostNotAllowed);
    assert_eq!(
        result
            .destination
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("denied.test:443")
    );
    assert_eq!(result.connected, None);
    assert_eq!((result.bytes_in, result.bytes_out), (0, 0));
    assert_eq!(
        resolver.calls("denied.test"),
        0,
        "a denied host is never resolved"
    );
    let (summary, _) = harness.stop(WAIT);
    assert_eq!(summary.results_emitted, 1);
}

fn collect_upstream(
    listener: TcpListener,
    response: &'static [u8],
    body_end: &'static [u8],
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        stream.set_read_timeout(Some(WAIT)).expect("timeout");
        let mut received = Vec::new();
        let mut byte = [0u8; 1];
        // The head, then the body up to its framing end.
        while !received.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("reads the head");
            received.push(byte[0]);
        }
        while !received.ends_with(body_end) {
            stream.read_exact(&mut byte).expect("reads the body");
            received.push(byte[0]);
        }
        stream.write_all(response).expect("responds");
        stream.shutdown(Shutdown::Write).expect("half-closes");
        // Anything after the framed body would be a smuggled request; the
        // proxy closes after the response, so EOF ends this read.
        stream.read_to_end(&mut received).expect("reads to EOF");
        received
    })
}

#[test]
fn n02_plain_http_forwards_exactly_the_framed_request_without_proxy_credentials() {
    let (listener, port) = loopback();
    let response: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let server = collect_upstream(listener, response, b"SECRET-BODY");
    let resolver = fixtures("fixture.test", &["127.0.0.1"]);
    let harness = start(
        &allow(&[
            &format!("fixture.test:{port}"),
            &format!("127.0.0.1:{port}"),
        ]),
        &resolver,
    );
    let mut client = harness.connect();
    let request = format!(
        "POST http://Fixture.TEST:{port}/secret-path?token=SECRET-QUERY HTTP/1.1\r\n\
         Host: fixture.test:{port}\r\n\
         Proxy-Authorization: Basic SECRET-PROXY-CRED\r\n\
         Proxy-Connection: keep-alive\r\n\
         Connection: X-Hop\r\n\
         X-Hop: SECRET-HOP\r\n\
         Keep-Alive: timeout=5\r\n\
         TE: trailers\r\n\
         Trailer: X-Checksum\r\n\
         Upgrade: websocket\r\n\
         X-Keep: SECRET-HEADER\r\n\
         Content-Length: 11\r\n\r\n\
         SECRET-BODYGET /smuggled HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
    );
    client.write_all(request.as_bytes()).expect("writes");
    let relayed = read_to_eof(&mut client);
    assert_eq!(relayed, response);
    let received = String::from_utf8(server.join().expect("the server ran")).expect("ASCII");
    assert_eq!(
        received,
        format!(
            "POST /secret-path?token=SECRET-QUERY HTTP/1.1\r\n\
             Host: fixture.test:{port}\r\n\
             X-Keep: SECRET-HEADER\r\n\
             Content-Length: 11\r\n\
             Connection: close\r\n\r\n\
             SECRET-BODY"
        ),
        "exactly the framed request, hop-by-hop and proxy credentials removed"
    );
    let results = harness.sink.wait_for(1);
    let result = &results[0];
    assert_eq!(result.kind, RequestKind::Http);
    assert_eq!(result.decision, ProxyDecision::Allow);
    assert_eq!(
        result.bytes_out,
        u64::try_from(received.len()).expect("fits")
    );
    assert_eq!(
        result.bytes_in,
        u64::try_from(response.len()).expect("fits")
    );
    assert_eq!(result.end, Some(EndReason::UpstreamClosed));
    assert_eq!(
        result.discarded_bytes,
        u64::try_from("GET /smuggled HTTP/1.1\r\nHost: fixture.test\r\n\r\n".len()).expect("fits"),
        "the pipelined bytes are counted, not forwarded"
    );
    let event = proxy::proxy_event(result, ATTEMPT, 1, SystemTime::now(), 1);
    let text = serde_json::to_string(&event).expect("serializes");
    assert!(
        !text.contains("SECRET"),
        "no request content in the record: {text}"
    );
    assert!(
        !text.contains("secret-path"),
        "no path in the record: {text}"
    );
    harness.stop(WAIT);
}

#[test]
fn n02_chunked_body_is_forwarded_exactly_and_nothing_after_it() {
    let (listener, port) = loopback();
    let response: &'static [u8] = b"HTTP/1.1 204 No Content\r\n\r\n";
    let server = collect_upstream(listener, response, b"0\r\n\r\n");
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let mut client = harness.connect();
    let request = format!(
        "PUT http://127.0.0.1:{port}/u HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n\
         GET /smuggled HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    );
    client.write_all(request.as_bytes()).expect("writes");
    assert_eq!(read_to_eof(&mut client), response);
    let received = String::from_utf8(server.join().expect("the server ran")).expect("ASCII");
    assert_eq!(
        received,
        format!(
            "PUT /u HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nTransfer-Encoding: chunked\r\n\
             Connection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        )
    );
    assert_eq!(
        resolver.calls("127.0.0.1"),
        0,
        "a literal is never resolved"
    );
    harness.stop(WAIT);
}

const ATTEMPT: &str = "att_12345678-1234-4123-8123-123456789abc";

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1")
}

fn jail_event_validator() -> Validator {
    let mut pairs = Vec::new();
    let mut jail_event = None;
    for name in ["event.schema.json", "jail-event.schema.json"] {
        let text = std::fs::read_to_string(specs_dir().join(name)).expect("readable schema");
        let schema: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        let id = schema["$id"].as_str().expect("an $id").to_owned();
        if name == "jail-event.schema.json" {
            jail_event = Some(schema.clone());
        }
        pairs.push((id, Resource::from_contents(schema)));
    }
    let registry = Registry::new()
        .extend(pairs)
        .expect("valid identifiers")
        .prepare()
        .expect("the registry resolves");
    let registry: &'static Registry = Box::leak(Box::new(registry));
    jsonschema::options()
        .with_registry(registry)
        .should_validate_formats(true)
        .build(&jail_event.expect("the producer schema"))
        .expect("compiles")
}

#[test]
fn n02_results_are_valid_distinct_proxy_source_events() {
    let (listener, port) = loopback();
    let server = echo_server(listener, 1);
    let closed_port = {
        let (listener, port) = loopback();
        drop(listener);
        port
    };
    let resolver = fixtures("", &[]);
    let harness = start(
        &allow(&[
            &format!("127.0.0.1:{port}"),
            &format!("127.0.0.1:{closed_port}"),
        ]),
        &resolver,
    );
    // Allowed and relayed.
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    client.write_all(b"x").expect("writes");
    let mut echo = [0u8; 1];
    client.read_exact(&mut echo).expect("echo");
    client.shutdown(Shutdown::Write).expect("half-close");
    read_to_eof(&mut client);
    harness.sink.wait_for(1);
    // Denied.
    assert_eq!(refused(&harness, &connect_request("10.0.0.1:443")).0, 403);
    // Allowed, but the connection is refused.
    let (status, reason) = refused(
        &harness,
        &connect_request(&format!("127.0.0.1:{closed_port}")),
    );
    assert_eq!((status, reason.as_str()), (502, "connect_failed"));
    server.join().expect("the server ran");

    let results = harness.sink.wait_for(3);
    let validator = jail_event_validator();
    let mut events = Vec::new();
    for (index, result) in results.iter().enumerate() {
        let seq = u64::try_from(index).expect("fits") + 1;
        let event = proxy::proxy_event(result, ATTEMPT, seq, SystemTime::now(), 42);
        let value = serde_json::to_value(&event).expect("serializes");
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{value}: {errors:?}");
        assert_eq!(value["source"], "proxy");
        assert_eq!(value["operation"], "net.connect");
        assert_eq!(value["stage"], "result");
        assert_eq!(value["outcome"]["completion"], "proxy_close");
        events.push(value);
    }
    assert_eq!(events[0]["decision"], "allow");
    assert_eq!(events[0]["outcome"]["ok"], true);
    assert_eq!(
        events[0]["fields"]["connected_address"],
        format!("127.0.0.1:{port}")
    );
    assert_eq!(events[1]["decision"], "deny");
    assert_eq!(events[1]["outcome"]["ok"], false);
    assert_eq!(events[1]["fields"]["reason"], "host_not_allowed");
    assert_eq!(
        events[2]["decision"], "allow",
        "policy allowed it; the connect failed"
    );
    assert_eq!(events[2]["outcome"]["ok"], false);
    assert_eq!(events[2]["outcome"]["errno"], "ECONNREFUSED");
    assert_ne!(
        events[0]["fields"]["request_id"],
        events[1]["fields"]["request_id"]
    );
    // Proxy facts count under proxy.net from the proxy source only, never
    // under the audit `net` class.
    assert_eq!(CoverageClass::ProxyNet.source(), "proxy");
    assert_eq!(CoverageClass::Net.source(), "audit");
    let (summary, _) = harness.stop(WAIT);
    assert_eq!(summary.results_emitted, 3);
}

#[test]
fn n02_the_proxy_writes_no_log() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![root.join("network.rs")];
    for dir in ["proxy", "network"] {
        for entry in std::fs::read_dir(root.join(dir)).expect("readable") {
            files.push(entry.expect("an entry").path());
        }
    }
    assert!(files.len() >= 9, "{files:?}");
    {
        for path in files {
            let text = std::fs::read_to_string(&path).expect("readable");
            for forbidden in [
                "println!",
                "eprintln!",
                "print!(",
                "eprint!(",
                "dbg!(",
                "log::",
                "tracing::",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{} uses {forbidden}",
                    path.display()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// N03: rebinding, private answers, mixed answers, Host mismatch, literals
// ---------------------------------------------------------------------------

#[test]
fn n03_rebinding_connects_only_to_the_single_checked_answer() {
    let (listener, port) = loopback();
    let server = echo_server(listener, 1);
    let resolver = Arc::new(FixtureResolver::new());
    resolver.script(
        "rebind.test",
        vec![
            FixtureAnswer::Addresses(vec!["127.0.0.1".parse().expect("ip")]),
            FixtureAnswer::Addresses(vec!["10.0.0.1".parse().expect("ip")]),
        ],
    );
    let harness = start(
        &allow(&[&format!("rebind.test:{port}"), &format!("127.0.0.1:{port}")]),
        &resolver,
    );
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("rebind.test:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    assert_eq!(
        resolver.calls("rebind.test"),
        1,
        "one resolution for the first request"
    );
    client.shutdown(Shutdown::Write).expect("half-close");
    read_to_eof(&mut client);
    let first = harness.sink.wait_for(1);
    assert_eq!(
        first[0].connected.map(|address| address.ip()),
        Some("127.0.0.1".parse::<IpAddr>().expect("ip"))
    );
    // The name now answers a private address: the next request is denied,
    // after exactly one more resolution.
    let (status, reason) = refused(&harness, &connect_request(&format!("rebind.test:{port}")));
    assert_eq!((status, reason.as_str()), (403, "forbidden_address"));
    assert_eq!(resolver.calls("rebind.test"), 2);
    assert_eq!(server.join().expect("the server ran"), 1);
    harness.stop(WAIT);
}

#[test]
fn n03_private_addresses_behind_an_allowed_name_are_denied() {
    let resolver = Arc::new(FixtureResolver::new());
    for (name, answer) in [
        ("private.test", "10.1.2.3"),
        ("metadata.test", "169.254.169.254"),
        ("mapped.test", "::ffff:169.254.169.254"),
        ("nat64.test", "64:ff9b::a9fe:a9fe"),
        ("loopback6.test", "::1"),
    ] {
        resolver.script(
            name,
            vec![FixtureAnswer::Addresses(vec![answer.parse().expect("ip")])],
        );
    }
    resolver.script(
        "compatible.test",
        vec![FixtureAnswer::Addresses(vec![
            "::7f00:1".parse().expect("ip"),
        ])],
    );
    let names = [
        "private.test",
        "metadata.test",
        "mapped.test",
        "nat64.test",
        "loopback6.test",
        "compatible.test",
    ];
    let rules: Vec<String> = names.iter().map(|name| format!("{name}:443")).collect();
    let harness = start(&rules, &resolver);
    for name in names {
        let (status, reason) = refused(&harness, &connect_request(&format!("{name}:443")));
        assert_eq!(
            (status, reason.as_str()),
            (403, "forbidden_address"),
            "{name}"
        );
        assert_eq!(resolver.calls(name), 1, "{name}");
    }
    harness.stop(WAIT);
}

#[test]
fn n03_mixed_answers_refuse_and_nothing_connects() {
    let (listener, port) = loopback();
    let resolver = fixtures("mixed.test", &["127.0.0.1", "10.0.0.1"]);
    let harness = start(
        &allow(&[&format!("mixed.test:{port}"), &format!("127.0.0.1:{port}")]),
        &resolver,
    );
    let (status, reason) = refused(&harness, &connect_request(&format!("mixed.test:{port}")));
    assert_eq!((status, reason.as_str()), (403, "mixed_answers"));
    assert_no_connection(&listener);
    harness.stop(WAIT);
}

#[test]
fn n03_host_and_absolute_uri_disagreement_refuses_before_resolution() {
    let (listener, port) = loopback();
    let resolver = fixtures("fixture.test", &["127.0.0.1"]);
    let harness = start(
        &allow(&[
            &format!("fixture.test:{port}"),
            &format!("127.0.0.1:{port}"),
        ]),
        &resolver,
    );
    for request in [
        format!("GET http://fixture.test:{port}/ HTTP/1.1\r\nHost: other.test:{port}\r\n\r\n"),
        format!("GET http://fixture.test:{port}/ HTTP/1.1\r\nHost: fixture.test\r\n\r\n"),
        format!("CONNECT fixture.test:{port} HTTP/1.1\r\nHost: other.test:{port}\r\n\r\n"),
    ] {
        let (status, reason) = refused(&harness, &request);
        assert_eq!(
            (status, reason.as_str()),
            (400, "host_mismatch"),
            "{request:?}"
        );
    }
    assert_eq!(resolver.calls("fixture.test"), 0);
    assert_no_connection(&listener);
    harness.stop(WAIT);
}

#[test]
fn n03_numeric_requests_need_an_exact_grant_and_are_never_resolved() {
    let (listener, port) = loopback();
    let server = echo_server(listener, 2);
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    for authority in [
        format!("127.0.0.1:{port}"),
        format!("[::ffff:127.0.0.1]:{port}"),
    ] {
        let mut client = harness.connect();
        client
            .write_all(format!("CONNECT {authority} HTTP/1.1\r\n\r\n").as_bytes())
            .expect("writes");
        assert_eq!(read_head(&mut client).0, 200, "{authority}");
        client.shutdown(Shutdown::Write).expect("half-close");
        read_to_eof(&mut client);
    }
    let results = harness.sink.wait_for(2);
    for result in &results {
        assert_eq!(
            result.connected,
            Some(SocketAddr::new("127.0.0.1".parse().expect("ip"), port)),
            "the mapped literal connects to the normalized IPv4 address"
        );
    }
    for (authority, want) in [
        (format!("127.0.0.2:{port}"), (403, "host_not_allowed")),
        (format!("127.1:{port}"), (400, "malformed_request")),
        (format!("0x7f.1:{port}"), (400, "malformed_request")),
        (format!("2130706433:{port}"), (400, "malformed_request")),
        (format!("[::127.0.0.1]:{port}"), (400, "malformed_request")),
        (
            format!("[fe80::1%25lo0]:{port}"),
            (400, "malformed_request"),
        ),
        (format!("user@127.0.0.1:{port}"), (400, "malformed_request")),
    ] {
        let (status, reason) = refused(&harness, &format!("CONNECT {authority} HTTP/1.1\r\n\r\n"));
        assert_eq!((status, reason.as_str()), want, "{authority}");
    }
    assert_eq!(server.join().expect("the server ran"), 2);
    harness.stop(WAIT);
}

#[test]
fn n03_ipv6_loopback_is_reachable_only_through_its_grant() {
    let listener = TcpListener::bind("[::1]:0").expect("IPv6 loopback is available");
    let port = listener.local_addr().expect("address").port();
    let server = echo_server(listener, 1);
    let resolver = fixtures("v6.test", &["::1"]);
    let harness = start(
        &allow(&[&format!("v6.test:{port}"), &format!("[::1]:{port}")]),
        &resolver,
    );
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("v6.test:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    client.shutdown(Shutdown::Write).expect("half-close");
    read_to_eof(&mut client);
    let results = harness.sink.wait_for(1);
    assert_eq!(
        results[0].connected,
        Some(SocketAddr::new("::1".parse().expect("ip"), port))
    );
    let (status, reason) = refused(
        &harness,
        &connect_request(&format!("[::1]:{}", port.wrapping_add(1).max(1))),
    );
    assert_eq!((status, reason.as_str()), (403, "host_not_allowed"));
    server.join().expect("the server ran");
    harness.stop(WAIT);
}

// ---------------------------------------------------------------------------
// N04: deadlines, budgets, saturation, upstream and proxy death
// ---------------------------------------------------------------------------

#[test]
fn n04_budgets_default_to_section_10() {
    let budgets = Budgets::default();
    assert_eq!(budgets.max_connections, 128);
    assert_eq!(budgets.max_header_bytes, 32 * 1024);
    assert_eq!(budgets.header_deadline, Duration::from_secs(10));
    assert_eq!(budgets.resolve_deadline, Duration::from_secs(10));
    assert_eq!(budgets.connect_deadline, Duration::from_secs(10));
    assert_eq!(budgets.relay_buffer_bytes, 1024 * 1024);
    assert_eq!(
        budgets.relay_chunk() * 2 * budgets.max_connections,
        1024 * 1024
    );
}

fn short_header_deadline() -> Budgets {
    Budgets {
        header_deadline: Duration::from_millis(400),
        ..Budgets::default()
    }
}

#[test]
fn n04_slow_headers_end_at_the_absolute_deadline_even_while_bytes_trickle() {
    let resolver = fixtures("", &[]);
    let budgets = short_header_deadline();
    let harness = start_with(
        &[],
        budgets,
        Arc::clone(&resolver) as Arc<dyn Resolver + Send + Sync>,
    );

    // A client that trickles a never-ending header: a per-read idle timeout
    // would never fire; the absolute deadline must.
    let mut client = harness.connect();
    let mut writer = client.try_clone().expect("clones");
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let started = Instant::now();
    let trickle = thread::spawn(move || {
        let _ = writer.write_all(b"CONNECT slow.test:443 HTTP/1.1\r\nX-Slow: ");
        // A load generator, not synchronization: one byte per 25 ms until
        // the proxy closes or the test ends.
        while stop_rx.recv_timeout(Duration::from_millis(25)).is_err() {
            if writer.write_all(b"a").is_err() {
                break;
            }
        }
    });
    let (status, head) = read_head(&mut client);
    let elapsed = started.elapsed();
    let _ = stop_tx.send(());
    trickle.join().expect("the trickle ran");
    assert_eq!((status, reason_of(&head)), (408, Some("header_timeout")));
    assert!(elapsed >= budgets.header_deadline, "{elapsed:?}");
    assert!(
        elapsed < budgets.header_deadline + Duration::from_secs(5),
        "{elapsed:?}"
    );

    // A client that sends nothing at all holds its slot only until the
    // deadline, and that is reported too.
    let mut silent = harness.connect();
    let (status, _) = read_head(&mut silent);
    assert_eq!(status, 408);
    let results = harness.sink.wait_for(2);
    assert!(
        results
            .iter()
            .all(|r| r.reason == Reason::HeaderTimeout && r.decision == ProxyDecision::Deny)
    );
    assert!(results.iter().all(|r| r.destination.is_none()));
    harness.stop(WAIT);
}

#[test]
fn n04_header_overflow_refuses_at_the_32_kib_budget() {
    let (listener, port) = loopback();
    let server = echo_server(listener, 1);
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let budget = Budgets::default().max_header_bytes;

    // Exactly at the budget: accepted.
    let prefix = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nX-Pad: ");
    let pad = budget - prefix.len() - 4;
    let exact = format!("{prefix}{}\r\n\r\n", "a".repeat(pad));
    assert_eq!(exact.len(), budget);
    let mut client = harness.connect();
    client.write_all(exact.as_bytes()).expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    client.shutdown(Shutdown::Write).expect("half-close");
    read_to_eof(&mut client);

    // One byte over: refused, and the proxy stops reading at the budget.
    let over = format!("{prefix}{}\r\n\r\n", "a".repeat(pad + 1));
    let mut client = harness.connect();
    let mut writer = client.try_clone().expect("clones");
    let writing = thread::spawn(move || {
        let _ = writer.write_all(over.as_bytes());
    });
    let (status, head) = read_head(&mut client);
    assert_eq!((status, reason_of(&head)), (431, Some("header_too_large")));
    writing.join().expect("the writer ran");

    // A huge header without a terminator never completes either.
    let mut client = harness.connect();
    let mut writer = client.try_clone().expect("clones");
    let writing = thread::spawn(move || {
        let _ = writer.write_all(&vec![b'a'; 4 * budget]);
    });
    let (status, _) = read_head(&mut client);
    assert_eq!(status, 431);
    writing.join().expect("the writer ran");
    server.join().expect("the server ran");
    let (_, results) = harness.stop(WAIT);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.reason == Reason::HeaderTooLarge)
            .count(),
        2
    );
}

#[test]
fn n04_saturation_refuses_with_overload_then_recovers() {
    // The §10 number itself: 128 parked connections hold 256 descriptors in
    // this one test process (client and proxy ends).
    const CAP: usize = 128;
    let (listener, port) = loopback();
    let server = echo_server(listener, 1);
    let resolver = fixtures("", &[]);
    let budgets = Budgets {
        max_connections: CAP,
        ..Budgets::default()
    };
    let harness = start_with(
        &allow(&[&format!("127.0.0.1:{port}")]),
        budgets,
        Arc::clone(&resolver) as Arc<dyn Resolver + Send + Sync>,
    );
    // Fill every slot with a connection parked in its header read.
    let mut held: Vec<UnixStream> = (0..CAP)
        .map(|_| {
            let mut stream = harness.connect();
            stream.write_all(b"C").expect("writes");
            stream
        })
        .collect();
    // Accept order is connection order, so this one meets a full budget.
    let (status, reason) = refused(&harness, &connect_request(&format!("127.0.0.1:{port}")));
    assert_eq!((status, reason.as_str()), (503, "overload"));
    assert_eq!(harness.handle.active_connections(), CAP);
    let overload = harness.sink.wait_for(1);
    assert_eq!(overload[0].reason, Reason::Overload);
    assert_eq!(
        overload[0].destination, None,
        "refused before reading anything"
    );

    // Free one slot; its result is emitted after its slot is released.
    drop(held.remove(0));
    let results = harness.sink.wait_for(2);
    assert_eq!(results[1].reason, Reason::ClientClosed);
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200, "a freed slot admits again");
    client.shutdown(Shutdown::Write).expect("half-close");
    read_to_eof(&mut client);
    server.join().expect("the server ran");
    let (summary, results) = harness.stop(WAIT);
    assert!(summary.complete());
    assert!(summary.complete());
    assert_eq!(summary.accepted, u64::try_from(CAP + 2).expect("fits"));
    // Each parked connection is closed by stop and settled once: a refused
    // request, or no request when the close beat its handler's first read.
    let stopping = results
        .iter()
        .filter(|r| r.reason == Reason::Stopping)
        .count();
    assert_eq!(
        u64::try_from(stopping).expect("fits") + summary.without_request,
        u64::try_from(CAP - 1).expect("fits"),
        "{summary:?}"
    );
    drop(held);
}

#[test]
fn n04_upstream_death_mid_tunnel_closes_the_client_and_is_reported() {
    let (listener, port) = loopback();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).expect("reads");
        // The destination dies with the tunnel open.
        drop(stream);
    });
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    client.write_all(b"ping").expect("writes");
    server.join().expect("the server ran");
    // Fail closed: the client sees the tunnel end without shutting down its
    // own sending side.
    assert!(read_to_eof(&mut client).is_empty());
    let results = harness.sink.wait_for(1);
    assert_eq!(results[0].decision, ProxyDecision::Allow);
    assert_eq!(results[0].end, Some(EndReason::UpstreamClosed));
    assert_eq!((results[0].bytes_out, results[0].bytes_in), (4, 0));
    harness.stop(WAIT);
}

#[test]
fn n04_backpressure_bounds_buffering_of_a_response_the_client_does_not_read() {
    const TARGET: usize = 256 * 1024 * 1024;
    let (listener, port) = loopback();
    let (written_tx, written_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let chunk = vec![b'z'; 64 * 1024];
        let mut written = 0usize;
        while written < TARGET {
            match stream.write(&chunk) {
                Ok(n) => written += n,
                Err(_) => break,
            }
        }
        written_tx.send(written).expect("reports");
        drop(stream);
    });
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    // The client reads nothing more. The destination must block: kernel
    // socket buffers plus one relay share, never the whole stream.
    let written = written_rx.recv_timeout(WAIT).expect("the server reports");
    assert!(
        written < TARGET,
        "the proxy buffered everything ({written} bytes)"
    );
    server.join().expect("the server ran");
    drop(client);
    harness.sink.wait_for(1);
    harness.stop(WAIT);
}

#[test]
fn n04_stop_closes_every_connection_and_accounts_for_each() {
    let (listener, port) = loopback();
    let server = echo_server(listener, 1);
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let mut tunnel = harness.connect();
    tunnel
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut tunnel).0, 200);
    tunnel.write_all(b"x").expect("writes");
    let mut echo = [0u8; 1];
    tunnel.read_exact(&mut echo).expect("echo");
    let mut partial = harness.connect();
    partial.write_all(b"CONNECT 127.0.0.1").expect("writes");
    let mut idle = harness.connect();
    // Make sure both late connections are being served before stopping: a
    // third, complete request is answered only after the earlier ones were
    // accepted (accept order is connection order).
    let (status, _) = refused(&harness, &connect_request("denied.test:443"));
    assert_eq!(status, 403);

    let path = harness.path.clone();
    let (summary, results) = harness.stop(WAIT);
    assert!(summary.complete(), "{summary:?}");
    assert_eq!(summary.accepted, 4);
    assert_eq!(summary.results_missing, 0);
    // The idle connection sent nothing: no request. The partial one is a
    // refused request, unless the stop closed it before its handler read
    // the bytes (a BSD shutdown discards unread data); then it too sent
    // nothing the proxy saw. Either way each is settled exactly once.
    let stopping = results
        .iter()
        .filter(|r| r.reason == Reason::Stopping)
        .count();
    assert_eq!(
        u64::try_from(stopping).expect("fits") + summary.without_request,
        2,
        "{summary:?}"
    );
    assert!(
        summary.without_request >= 1,
        "the idle connection sent nothing"
    );
    // Every client sees its connection end.
    assert!(read_to_eof(&mut tunnel).is_empty());
    assert!(read_to_eof(&mut partial).is_empty());
    assert!(read_to_eof(&mut idle).is_empty());
    let tunnel_result = results
        .iter()
        .find(|r| r.kind == RequestKind::Connect && r.decision == ProxyDecision::Allow)
        .expect("the tunnel reported");
    assert_eq!(tunnel_result.end, Some(EndReason::Stopped));
    assert_eq!((tunnel_result.bytes_out, tunnel_result.bytes_in), (1, 1));
    // The listener is closed: nothing accepts on the path any more.
    assert!(UnixStream::connect(&path).is_err());
    server.join().expect("the server ran");
}

// J3-agent begin: a proxy whose listener dies stops serving, visibly
/// The descriptor of this process's socket bound at `path`, found by asking
/// every open descriptor its own name.
#[cfg(target_os = "linux")]
fn socket_bound_at(path: &Path) -> Option<i32> {
    use std::os::unix::ffi::OsStrExt as _;
    (3..1024).find(|fd| {
        // SAFETY: getsockname writes at most `len` bytes into a zeroed,
        // correctly sized sockaddr_un; any fd number is safe to ask.
        unsafe {
            let mut address: libc::sockaddr_un = std::mem::zeroed();
            let mut len =
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_un>()).expect("fits");
            if libc::getsockname(*fd, std::ptr::from_mut(&mut address).cast(), &raw mut len) != 0
                || i32::from(address.sun_family) != libc::AF_UNIX
            {
                return false;
            }
            let bytes: Vec<u8> = address
                .sun_path
                .iter()
                .take_while(|byte| **byte != 0)
                .map(|byte| *byte as u8)
                .collect();
            bytes == path.as_os_str().as_bytes()
        }
    })
}

/// N04 proxy death, in process: the listener is shut down underneath the
/// proxy (what a dead listener looks like to its clients). The accept loop
/// ends, `serving()` says so, and every new connection is refused; nothing
/// accepts on the path again.
#[cfg(target_os = "linux")]
#[test]
fn n04_a_listener_shut_down_underneath_the_proxy_stops_serving_and_refuses() {
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&["127.0.0.1:1"]), &resolver);
    assert!(harness.handle.serving());
    let (status, _) = refused(&harness, &connect_request("denied.test:443"));
    assert_eq!(status, 403, "the proxy serves before its listener dies");
    let fd = socket_bound_at(&harness.path).expect("the proxy's listener is in this process");
    // SAFETY: shutting down a socket this process owns; the descriptor stays
    // open and owned by the proxy.
    assert_eq!(unsafe { libc::shutdown(fd, libc::SHUT_RDWR) }, 0);
    let deadline = Instant::now() + WAIT;
    while harness.handle.serving() {
        assert!(Instant::now() < deadline, "the accept loop never noticed");
        thread::sleep(Duration::from_millis(5));
    }
    let error = UnixStream::connect(&harness.path).expect_err("nothing accepts any more");
    assert_eq!(error.kind(), ErrorKind::ConnectionRefused, "{error}");
    let (summary, results) = harness.stop(WAIT);
    assert_eq!(summary.accepted, 1);
    assert_eq!(results.len(), 1);
}
// J3-agent end

/// A resolver that announces each call and then blocks until the deadline./// A resolver that announces each call and then blocks until the deadline.
struct GateResolver {
    entered: Mutex<mpsc::Sender<()>>,
    hold: Mutex<()>,
    never: Condvar,
}

impl Resolver for GateResolver {
    fn resolve(&self, _host: &str, deadline: Instant) -> Result<Vec<IpAddr>, ResolveError> {
        let _ = self
            .entered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(());
        let mut guard = self.hold.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ResolveError::Timeout);
            }
            guard = self
                .never
                .wait_timeout(guard, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

#[test]
fn n04_a_drain_cut_short_reports_the_missing_result() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let resolver = Arc::new(GateResolver {
        entered: Mutex::new(entered_tx),
        hold: Mutex::new(()),
        never: Condvar::new(),
    });
    let budgets = Budgets {
        resolve_deadline: Duration::from_secs(3),
        ..Budgets::default()
    };
    let harness = start_with(&allow(&["gate.test:443"]), budgets, resolver);
    let mut client = harness.connect();
    client
        .write_all(connect_request("gate.test:443").as_bytes())
        .expect("writes");
    entered_rx
        .recv_timeout(WAIT)
        .expect("the request reached the resolver");
    let (summary, results) = harness.stop(Duration::ZERO);
    assert!(!summary.complete(), "proxy.net coverage must show the gap");
    assert_eq!(summary.accepted, 1);
    assert_eq!(summary.results_emitted, 0);
    assert_eq!(summary.results_missing, 1, "{summary:?}");
    assert!(!summary.complete());
    assert!(results.is_empty());
    // The client is closed by stop, not left waiting for the resolver.
    assert!(read_to_eof(&mut client).is_empty());
}

#[test]
fn n04_resolver_deadline_bounds_the_request() {
    let resolver = Arc::new(FixtureResolver::new());
    resolver.script("hang.test", vec![FixtureAnswer::Hang]);
    let budgets = Budgets {
        resolve_deadline: Duration::from_millis(300),
        ..Budgets::default()
    };
    let harness = start_with(
        &allow(&["hang.test:443"]),
        budgets,
        Arc::clone(&resolver) as Arc<dyn Resolver + Send + Sync>,
    );
    let started = Instant::now();
    let (status, reason) = refused(&harness, &connect_request("hang.test:443"));
    let elapsed = started.elapsed();
    assert_eq!((status, reason.as_str()), (504, "resolve_timeout"));
    assert!(elapsed >= budgets.resolve_deadline, "{elapsed:?}");
    assert!(
        elapsed < budgets.resolve_deadline + Duration::from_secs(5),
        "{elapsed:?}"
    );
    harness.stop(WAIT);
}

/// A lookup that reports the name it was given and blocks until released.
struct HeldLookup {
    names: Mutex<Vec<String>>,
    released: Mutex<bool>,
    changed: Condvar,
}

impl HeldLookup {
    fn new() -> Arc<Self> {
        Arc::new(HeldLookup {
            names: Mutex::new(Vec::new()),
            released: Mutex::new(false),
            changed: Condvar::new(),
        })
    }

    fn lookup(self: &Arc<Self>) -> Arc<proxy::Lookup> {
        let this = Arc::clone(self);
        Arc::new(move |name: &str| {
            this.names
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(name.to_owned());
            this.changed.notify_all();
            // Held until released, or until WAIT passes, so a resolver that
            // ignores its deadline fails the test instead of hanging it.
            let deadline = Instant::now() + WAIT;
            let mut released = this.released.lock().unwrap_or_else(PoisonError::into_inner);
            while !*released && Instant::now() < deadline {
                released = this
                    .changed
                    .wait_timeout(released, deadline.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            Ok(vec!["127.0.0.1".parse().expect("ip")])
        })
    }

    fn release(&self) {
        *self.released.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.changed.notify_all();
    }
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn n04_system_resolver_is_bounded_absolute_and_refuses_what_is_not_a_name() {
    let refusing = SystemResolver::new(0);
    assert_eq!(
        refusing.resolve("localhost", Instant::now() + WAIT),
        Err(ResolveError::Overloaded)
    );
    let resolver = SystemResolver::new(4);
    for bad in ["127.0.0.1", "::1", "", "b\u{fc}cher.test", "example.test."] {
        assert_eq!(
            resolver.resolve(bad, Instant::now() + WAIT),
            Err(ResolveError::Invalid),
            "{bad:?} never reaches a lookup"
        );
    }
    // `localhost` comes from the host's own configuration, not public DNS.
    let answers = resolver
        .resolve("localhost", Instant::now() + WAIT)
        .expect("localhost resolves");
    assert!(!answers.is_empty());
    assert!(answers.iter().all(IpAddr::is_loopback), "{answers:?}");
    wait_until("the lookup worker exits", || resolver.in_flight() == 0);
}

#[test]
fn n04_system_resolver_looks_up_the_absolute_name_and_keeps_its_deadline() {
    let held = HeldLookup::new();
    let resolver = Arc::new(SystemResolver::with_lookup(1, held.lookup()));
    let started = Instant::now();
    let deadline = started + Duration::from_millis(300);
    // The lookup never returns in time: the caller gets Timeout at the
    // deadline, not when the lookup finishes.
    assert_eq!(
        resolver.resolve("example.test", deadline),
        Err(ResolveError::Timeout)
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    assert_eq!(
        *held.names.lock().unwrap_or_else(PoisonError::into_inner),
        vec!["example.test.".to_owned()],
        "an absolute name: search domains never apply"
    );
    assert_eq!(proxy::absolute_name("a.test"), "a.test.");
    // The abandoned lookup still counts against the cap until it ends ...
    assert_eq!(resolver.in_flight(), 1);
    assert_eq!(
        resolver.resolve("other.test", Instant::now() + WAIT),
        Err(ResolveError::Overloaded)
    );
    // ... and releases its slot when it does.
    held.release();
    wait_until("the late lookup ends", || resolver.in_flight() == 0);
    assert!(
        resolver
            .resolve("other.test", Instant::now() + WAIT)
            .is_ok()
    );
    wait_until("the second lookup ends", || resolver.in_flight() == 0);
}

#[test]
fn n04_malformed_and_unsupported_requests_are_refused_without_connecting() {
    let (listener, port) = loopback();
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let target = format!("127.0.0.1:{port}");
    for (request, want) in [
        (
            format!("GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"),
            "unsupported_request",
        ),
        (
            format!("GET https://{target}/ HTTP/1.1\r\nHost: {target}\r\n\r\n"),
            "unsupported_request",
        ),
        (
            format!(
                "POST http://{target}/ HTTP/1.1\r\nHost: {target}\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"
            ),
            "ambiguous_framing",
        ),
        (
            format!(
                "POST http://{target}/ HTTP/1.1\r\nHost: {target}\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
            ),
            "ambiguous_framing",
        ),
        (
            format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nX-Fold: a\r\n b\r\n\r\n"),
            "malformed_request",
        ),
        (
            format!("GET http://{target}/ HTTP/1.1\nHost: {target}\n\n"),
            "malformed_request",
        ),
        (
            format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\rX: y\r\n\r\n"),
            "malformed_request",
        ),
    ] {
        let (_, reason) = refused(&harness, &request);
        assert_eq!(reason, want, "{request:?}");
    }
    assert_no_connection(&listener);
    harness.stop(WAIT);
}

#[test]
fn n04_unusable_budgets_refuse_to_start() {
    for budgets in [
        Budgets {
            max_connections: 0,
            ..Budgets::default()
        },
        Budgets {
            relay_buffer_bytes: 1,
            ..Budgets::default()
        },
        Budgets {
            header_deadline: Duration::ZERO,
            ..Budgets::default()
        },
        Budgets {
            resolve_deadline: proxy::MAX_DEADLINE + Duration::from_secs(1),
            ..Budgets::default()
        },
        Budgets {
            connect_deadline: Duration::MAX,
            ..Budgets::default()
        },
    ] {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let listener = UnixListener::bind(dir.path().join("proxy.sock")).expect("binds");
        let started = proxy::start(
            ProxyConfig {
                listener,
                rules: Rules::from_strings(&[], &[]).expect("empty rules"),
                budgets,
                resolver: Arc::new(FixtureResolver::new()),
            },
            Arc::new(Sink::default()),
        );
        assert!(started.is_err(), "{budgets:?}");
    }
}

#[test]
fn n04_connect_falls_back_across_approved_answers_only() {
    let (listener, port) = loopback();
    let server = echo_server(listener, 1);
    // `[::1]:port` is granted but nothing listens there; `127.0.0.1:port` is
    // the fixture. `10.0.0.1` is never granted, so it cannot be in the set.
    let resolver = fixtures("fallback.test", &["::1", "127.0.0.1"]);
    let harness = start(
        &allow(&[
            &format!("fallback.test:{port}"),
            &format!("[::1]:{port}"),
            &format!("127.0.0.1:{port}"),
        ]),
        &resolver,
    );
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("fallback.test:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    client.shutdown(Shutdown::Write).expect("half-close");
    read_to_eof(&mut client);
    let results = harness.sink.wait_for(1);
    assert_eq!(
        results[0].connected,
        Some(SocketAddr::new("127.0.0.1".parse().expect("ip"), port))
    );
    assert_eq!(resolver.calls("fallback.test"), 1, "no second resolution");
    server.join().expect("the server ran");
    harness.stop(WAIT);
}

// ---------------------------------------------------------------------------
// Review regressions (R02-R18): one request per connection, early data,
// stop ordering, truthful failures, bounded work.
// ---------------------------------------------------------------------------

/// Waits until every proxy thread has let go of the shared state: the sink
/// is then held by the test alone.
fn wait_until_gone(sink: &Arc<Sink>) {
    wait_until("the proxy's threads exit", || Arc::strong_count(sink) == 1);
}

/// R02: requests carrying a 10,000-code-point label used to cost 67 ms
/// (macOS) to 131 ms (reference host) of supervisor CPU each; 64 in a row
/// were over four seconds. They now refuse at the IDNA mapping bound.
#[test]
fn n04_hosts_that_cost_quadratic_idna_work_refuse_fast() {
    let label: String = (0..10_000u32)
        .map(|i| char::from_u32(0x4E00 + i).expect("a CJK ideograph"))
        .collect();
    let request = format!("CONNECT {label}.example:443 HTTP/1.1\r\n\r\n");
    assert!(request.len() < 32 * 1024);
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&["*.example:443"]), &resolver);
    let started = Instant::now();
    for _ in 0..64 {
        let (status, reason) = refused(&harness, &request);
        assert_eq!((status, reason.as_str()), (400, "malformed_request"));
    }
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    harness.stop(WAIT);
}

/// R03: one request per connection. A pipelined second request after a
/// body-less GET is read, counted and dropped, never forwarded, and gets no
/// result of its own.
#[test]
fn n02_a_pipelined_second_request_is_discarded_and_stated() {
    let (listener, port) = loopback();
    let response: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let server = collect_upstream(listener, response, b"\r\n\r\n");
    let resolver = fixtures("", &[]);
    let harness = start(
        &allow(&[&format!("127.0.0.1:{port}"), "other.test:80"]),
        &resolver,
    );
    let mut client = harness.connect();
    let second = "GET http://other.test/b HTTP/1.1\r\nHost: other.test\r\n\r\n";
    let request =
        format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n{second}");
    client.write_all(request.as_bytes()).expect("writes");
    assert_eq!(read_to_eof(&mut client), response);
    let received = String::from_utf8(server.join().expect("the server ran")).expect("ASCII");
    assert!(!received.contains("other.test"), "{received:?}");
    assert!(!received.contains("/b"), "{received:?}");
    let results = harness.sink.wait_for(1);
    assert_eq!(results[0].reason, Reason::Relayed);
    assert_eq!(
        results[0].discarded_bytes,
        u64::try_from(second.len()).expect("fits")
    );
    assert_eq!(resolver.calls("other.test"), 0);
    let (summary, results) = harness.stop(WAIT);
    assert_eq!(results.len(), 1, "no result for the discarded request");
    assert_eq!(summary.accepted, 1);
}

/// R12: bytes sent with the CONNECT head are forwarded first, after the 200,
/// and counted in `bytes_out`.
#[test]
fn n02_connect_early_data_is_forwarded_in_order_and_counted() {
    let (listener, port) = loopback();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut got = Vec::new();
        stream.read_to_end(&mut got).expect("reads to EOF");
        got
    });
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let mut client = harness.connect();
    client
        .write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\nEARLY-DATA").as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    client.write_all(b"+LATE").expect("writes");
    client.shutdown(Shutdown::Write).expect("half-closes");
    assert_eq!(server.join().expect("the server ran"), b"EARLY-DATA+LATE");
    read_to_eof(&mut client);
    let results = harness.sink.wait_for(1);
    assert_eq!(results[0].bytes_out, 15);
    harness.stop(WAIT);
}

/// Y02: a half-closed client still receives the destination's answer.
#[test]
fn n02_a_half_closed_tunnel_still_delivers_the_response() {
    let (listener, port) = loopback();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut got = Vec::new();
        stream.read_to_end(&mut got).expect("reads to EOF");
        // Only after the client's EOF does the destination answer.
        stream.write_all(b"pong").expect("answers");
        got
    });
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    client.write_all(b"ping").expect("writes");
    client.shutdown(Shutdown::Write).expect("half-closes");
    assert_eq!(read_to_eof(&mut client), b"pong");
    assert_eq!(server.join().expect("the server ran"), b"ping");
    let results = harness.sink.wait_for(1);
    assert_eq!((results[0].bytes_out, results[0].bytes_in), (4, 4));
    assert_eq!(results[0].end, Some(EndReason::ClientClosed));
    harness.stop(WAIT);
}

/// R14: a client that closed completely releases its slot even while the
/// destination stays silent and open.
#[test]
fn n04_a_closed_client_with_a_silent_destination_releases_its_slot() {
    let (listener, port) = loopback();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accepts");
        // Silent and open until the test is done.
        let _ = release_rx.recv_timeout(WAIT);
        drop(stream);
    });
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    drop(client);
    let results = harness.sink.wait_for(1);
    assert_eq!(results[0].end, Some(EndReason::ClientClosed));
    assert_eq!(harness.handle.active_connections(), 0);
    let _ = release_tx.send(());
    server.join().expect("the server ran");
    harness.stop(WAIT);
}

/// R13: a result that settles after the seal is dropped, never delivered.
#[test]
fn n04_a_result_after_the_seal_is_not_delivered() {
    let held = HeldGate::new();
    let harness = start_with(
        &allow(&["gate.test:443"]),
        Budgets::default(),
        Arc::clone(&held) as Arc<dyn Resolver + Send + Sync>,
    );
    let sink = Arc::clone(&harness.sink);
    let mut client = harness.connect();
    client
        .write_all(connect_request("gate.test:443").as_bytes())
        .expect("writes");
    held.wait_entered();
    let (summary, results) = harness.stop(Duration::ZERO);
    assert_eq!(summary.results_missing, 1);
    assert!(results.is_empty());
    // The handler finishes now: its result must not reach the sink.
    held.release();
    wait_until_gone(&sink);
    assert!(
        sink.snapshot().is_empty(),
        "a result counted missing was delivered"
    );
    read_to_eof(&mut client);
}

/// A resolver that announces entry and blocks until released, then answers
/// with a forbidden address (so a late request is denied, not relayed).
struct HeldGate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
    answer: IpAddr,
}

impl HeldGate {
    fn new() -> Arc<Self> {
        HeldGate::answering("10.0.0.1".parse().expect("ip"))
    }

    fn answering(answer: IpAddr) -> Arc<Self> {
        Arc::new(HeldGate {
            state: Mutex::new((false, false)),
            changed: Condvar::new(),
            answer,
        })
    }

    fn wait_entered(&self) {
        let deadline = Instant::now() + WAIT;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while !state.0 {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "the request never reached the resolver");
            state = self
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn release(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
        self.changed.notify_all();
    }
}

impl Resolver for HeldGate {
    fn resolve(&self, _host: &str, _deadline: Instant) -> Result<Vec<IpAddr>, ResolveError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        Ok(vec![self.answer])
    }
}

/// R17: a request whose resolution completes after stop began never
/// connects upstream.
#[test]
fn n04_no_upstream_connect_after_stop_began() {
    let (listener, port) = loopback();
    listener.set_nonblocking(true).expect("nonblocking");
    let held = HeldGate::answering("127.0.0.1".parse().expect("ip"));
    let harness = start_with(
        &allow(&[&format!("gate.test:{port}"), &format!("127.0.0.1:{port}")]),
        Budgets::default(),
        Arc::clone(&held) as Arc<dyn Resolver + Send + Sync>,
    );
    let sink = Arc::clone(&harness.sink);
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("gate.test:{port}")).as_bytes())
        .expect("writes");
    held.wait_entered();
    let stopper = thread::spawn(move || harness.stop(WAIT));
    // Stop has begun once it has closed this client.
    assert!(read_to_eof(&mut client).is_empty());
    held.release();
    let (summary, results) = stopper.join().expect("stop ran");
    wait_until_gone(&sink);
    assert!(summary.complete(), "{summary:?}");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].reason, Reason::Stopping);
    assert_eq!(results[0].connected, None);
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
        "the proxy connected upstream after stop began"
    );
}

/// R16: stop closes a tunnel whose destination is silent and keeps it open.
#[test]
fn n04_stop_closes_a_tunnel_to_a_silent_destination() {
    let (listener, port) = loopback();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accepts");
        let _ = release_rx.recv_timeout(WAIT);
        drop(stream);
    });
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    let (summary, results) = harness.stop(Duration::from_secs(5));
    assert!(summary.complete(), "{summary:?}");
    assert_eq!(results[0].end, Some(EndReason::Stopped));
    let _ = release_tx.send(());
    server.join().expect("the server ran");
}

/// Z20: stop also closes the destination socket. A client that fills every
/// buffer toward a destination that never reads leaves the relay blocked in
/// a write to the destination; closing only the client cannot end that.
#[test]
fn n04_stop_ends_a_relay_blocked_writing_to_the_destination() {
    let (listener, port) = loopback();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accepts");
        // Never reads, never closes until the test is done.
        let _ = release_rx.recv_timeout(WAIT);
        drop(stream);
    });
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let mut client = harness.connect();
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    // Backpressure reaches the client once the destination's receive
    // buffer, the proxy's send buffer and the relay share are all full: a
    // write that cannot complete within a second is that event.
    client
        .set_write_timeout(Some(Duration::from_secs(1)))
        .expect("sets a timeout");
    let chunk = vec![b'x'; 64 * 1024];
    let mut written = 0usize;
    loop {
        match client.write(&chunk) {
            Ok(n) => written += n,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                break;
            }
            Err(error) => panic!("writing: {error}"),
        }
        assert!(written < 1 << 30, "no backpressure after {written} bytes");
    }
    let (summary, results) = harness.stop(Duration::from_secs(5));
    assert!(summary.complete(), "{summary:?}");
    assert_eq!(results[0].end, Some(EndReason::Stopped));
    let _ = release_tx.send(());
    server.join().expect("the server ran");
}

/// A sink that records how many connections were still admitted when each
/// result arrived.
struct ProbeSink {
    handle: Mutex<Option<ProxyHandle>>,
    active_at_emit: Mutex<Vec<usize>>,
    changed: Condvar,
}

impl ProxySink for ProbeSink {
    fn emit(&self, _result: ProxyResult) {
        let active = self
            .handle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map_or(usize::MAX, ProxyHandle::active_connections);
        self.active_at_emit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(active);
        self.changed.notify_all();
    }
}

/// A connection's slot is free before its result is delivered, so a client
/// that saw the result can connect again without meeting `overload`.
#[test]
fn n04_the_slot_is_free_before_the_result_is_delivered() {
    let dir = tempfile::tempdir().expect("a private temporary directory");
    let path = dir.path().join("proxy.sock");
    let listener = UnixListener::bind(&path).expect("binds");
    let sink = Arc::new(ProbeSink {
        handle: Mutex::new(None),
        active_at_emit: Mutex::new(Vec::new()),
        changed: Condvar::new(),
    });
    let handle = proxy::start(
        ProxyConfig {
            listener,
            rules: Rules::from_strings(&[], &[]).expect("empty rules"),
            budgets: Budgets {
                max_connections: 1,
                ..Budgets::default()
            },
            resolver: Arc::new(FixtureResolver::new()),
        },
        Arc::clone(&sink) as Arc<dyn ProxySink>,
    )
    .expect("starts");
    *sink.handle.lock().unwrap_or_else(PoisonError::into_inner) = Some(handle);
    for round in 1..=3 {
        let mut client = UnixStream::connect(&path).expect("connects");
        client.set_read_timeout(Some(WAIT)).expect("sets a timeout");
        client
            .write_all(connect_request("denied.test:443").as_bytes())
            .expect("writes");
        let (status, head) = read_head(&mut client);
        assert_eq!(
            (status, reason_of(&head)),
            (403, Some("host_not_allowed")),
            "round {round}"
        );
    }
    let recorded = sink
        .active_at_emit
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(recorded, vec![0, 0, 0]);
    let handle = sink
        .handle
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .expect("the handle");
    assert!(handle.stop(WAIT).complete());
}

/// R05: an unrepresentable stop budget waits for settlement, never panics.
#[test]
fn n04_stop_with_the_largest_budget_does_not_panic() {
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&["a.test:443"]), &resolver);
    // Stopped on its own thread, so a stop that never returns fails the
    // test instead of hanging it.
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = done_tx.send(harness.stop(Duration::MAX));
    });
    let (summary, _) = done_rx.recv_timeout(WAIT).expect("stop returns");
    assert!(summary.complete());
    assert!(summary.listener_closed);
}

/// R07: stop closes the listener even when its path is already gone.
#[test]
fn n04_stop_closes_the_listener_after_its_path_was_removed() {
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&["a.test:443"]), &resolver);
    std::fs::remove_file(&harness.path).expect("removes the socket path");
    let started = Instant::now();
    let (summary, _) = harness.stop(Duration::from_secs(5));
    assert!(summary.listener_closed, "{summary:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// R15: an overloaded resolver has its own reason, not a resolution failure.
struct Overloaded;

impl Resolver for Overloaded {
    fn resolve(&self, _host: &str, _deadline: Instant) -> Result<Vec<IpAddr>, ResolveError> {
        Err(ResolveError::Overloaded)
    }
}

#[test]
fn n04_resolver_overload_is_reported_as_such() {
    let harness = start_with(
        &allow(&["a.test:443"]),
        Budgets::default(),
        Arc::new(Overloaded),
    );
    let (status, reason) = refused(&harness, &connect_request("a.test:443"));
    assert_eq!((status, reason.as_str()), (503, "resolver_overloaded"));
    assert_eq!(
        harness.sink.wait_for(1)[0].reason,
        Reason::ResolverOverloaded
    );
    harness.stop(WAIT);
}

/// X20/R18: a handler that panics still settles once, answers 500, closes
/// its client and frees its slot.
struct Panics;

impl Resolver for Panics {
    fn resolve(&self, _host: &str, _deadline: Instant) -> Result<Vec<IpAddr>, ResolveError> {
        panic!("a resolver bug");
    }
}

#[test]
fn n04_a_panicking_handler_settles_answers_and_closes() {
    let harness = start_with(
        &allow(&["a.test:443"]),
        Budgets::default(),
        Arc::new(Panics),
    );
    let mut clients = Vec::new();
    for _ in 0..4 {
        let mut client = harness.connect();
        client
            .write_all(connect_request("a.test:443").as_bytes())
            .expect("writes");
        clients.push(client);
    }
    for client in &mut clients {
        let (status, head) = read_head(client);
        assert_eq!((status, reason_of(&head)), (500, Some("internal_error")));
        // The safe reason body, then EOF: the client is closed.
        assert_eq!(read_to_eof(client), b"internal_error\n");
    }
    let results = harness.sink.wait_for(4);
    assert!(results.iter().all(|r| r.reason == Reason::InternalError));
    assert_eq!(harness.handle.active_connections(), 0);
    let (summary, _) = harness.stop(WAIT);
    assert!(summary.complete());
}

/// X33: a CONNECT Host without a port means the CONNECT port.
#[test]
fn n03_a_connect_host_without_a_port_means_the_connect_port() {
    let (listener, port) = loopback();
    let server = echo_server(listener, 1);
    let resolver = fixtures("", &[]);
    let harness = start(&allow(&[&format!("127.0.0.1:{port}")]), &resolver);
    let mut client = harness.connect();
    client
        .write_all(
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes(),
        )
        .expect("writes");
    assert_eq!(read_head(&mut client).0, 200);
    client.shutdown(Shutdown::Write).expect("half-closes");
    read_to_eof(&mut client);
    server.join().expect("the server ran");
    harness.stop(WAIT);
}

/// The event for a proxy-side resource failure blames neither side.
#[test]
fn n02_a_resource_failure_event_is_truthful() {
    let result = ProxyResult {
        request_id: 7,
        kind: RequestKind::Connect,
        destination: None,
        decision: ProxyDecision::Allow,
        reason: Reason::ResourceExhausted,
        connected: None,
        connect_errno: Some(libc::EMFILE),
        bytes_in: 0,
        bytes_out: 0,
        discarded_bytes: 0,
        duration: Duration::from_millis(3),
        end: None,
    };
    let event = proxy::proxy_event(&result, ATTEMPT, 1, SystemTime::now(), 1);
    assert_eq!(event.decision, Some(Decision::Allow));
    let outcome = event.outcome.clone().expect("a result");
    assert_eq!(outcome.ok, Some(false));
    assert_eq!(outcome.errno.as_deref(), Some("EMFILE"));
    assert_eq!(outcome.completion, Completion::ProxyClose);
    assert_eq!(event.fields["reason"], "resource_exhausted");
    assert_eq!(event.fields["end"], serde_json::Value::Null);
    let value = serde_json::to_value(&event).expect("serializes");
    let errors: Vec<String> = jail_event_validator()
        .iter_errors(&value)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
}

// ---------------------------------------------------------------------------
// Descriptor budget and exhaustion, in helper processes with lowered limits
// ---------------------------------------------------------------------------

const HELPER_MODE: &str = "OURO_PROXY_TEST_HELPER";
const HELPER_PORT: &str = "OURO_PROXY_TEST_PORT";

/// Runs `proxy_limits_helper` in a child process whose descriptor limits
/// are first set by `ulimit` (the shell's, so no unsafe code is needed
/// here), and returns its stdout.
fn run_helper(mode: &str, ulimits: &str, port: Option<u16>) -> String {
    let exe = std::env::current_exe().expect("the test binary");
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(format!("{ulimits} && exec \"$0\" \"$@\""))
        .arg(exe)
        .args(["--ignored", "--exact", "proxy_limits_helper", "--nocapture"])
        .env(HELPER_MODE, mode);
    if let Some(port) = port {
        command.env(HELPER_PORT, port.to_string());
    }
    let output = command.output().expect("the helper runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "helper {mode} failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

fn helper_value<'a>(stdout: &'a str, key: &str) -> &'a str {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(&format!("HELPER {key}=")))
        .unwrap_or_else(|| panic!("no {key} in {stdout}"))
}

#[test]
fn n04_start_refuses_a_descriptor_budget_that_does_not_fit_and_names_it() {
    let stdout = run_helper("fit", "ulimit -S -n 100 && ulimit -H -n 200", None);
    let error = helper_value(&stdout, "error");
    assert!(error.contains("hard limit 200"), "{error}");
    assert!(
        error.contains("128 connections x 2 descriptors + 64 headroom = 320"),
        "{error}"
    );
}

#[test]
fn n04_start_raises_the_soft_descriptor_limit_to_the_hard_limit() {
    let stdout = run_helper("raise", "ulimit -S -n 64", None);
    let before: u64 = helper_value(&stdout, "soft_before")
        .parse()
        .expect("a number");
    let after: u64 = helper_value(&stdout, "soft_after")
        .parse()
        .expect("a number");
    assert_eq!(before, 64);
    assert!(after >= 320, "raised to {after}");
}

#[test]
fn n04_descriptor_exhaustion_is_reported_truthfully() {
    let (listener, port) = loopback();
    let server = thread::spawn(move || {
        let mut served = 0;
        while let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"hi");
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest);
            served += 1;
            if served == 2 {
                break;
            }
        }
        served
    });
    // Soft and hard limit both 256, so `start` cannot raise it and the
    // helper can exhaust it cheaply.
    let stdout = run_helper(
        "exhaust",
        "ulimit -S -n 256 && ulimit -H -n 256",
        Some(port),
    );
    // Two descriptors free: the client's and the accepted one. The upstream
    // socket cannot be created: a proxy-side failure, answered with 503,
    // never a connection that did not happen.
    assert_eq!(helper_value(&stdout, "free2_status"), "503");
    assert_eq!(helper_value(&stdout, "free2_header"), "resource_exhausted");
    assert_eq!(
        helper_value(&stdout, "free2_result"),
        "Allow ResourceExhausted connected=false errno=EMFILE end=None"
    );
    // Three free: the tunnel works, with no extra descriptor.
    assert_eq!(helper_value(&stdout, "free3_status"), "200");
    assert_eq!(helper_value(&stdout, "free3_relayed"), "hi");
    // One free: the accept itself fails; once descriptors return, the
    // pending connection is served.
    assert_eq!(helper_value(&stdout, "free1_status"), "200");
    assert_eq!(server.join().expect("the server ran"), 2);
}

#[test]
fn n04_a_tunnel_holds_two_descriptors() {
    let (listener, port) = loopback();
    let server = thread::spawn(move || {
        let mut held = Vec::new();
        for _ in 0..16 {
            match listener.accept() {
                Ok((stream, _)) => held.push(stream),
                Err(_) => break,
            }
        }
        held
    });
    let stdout = run_helper("fds", "true", Some(port));
    assert_eq!(helper_value(&stdout, "proxy_fds_for_16_tunnels"), "32");
    assert_eq!(helper_value(&stdout, "fds_after_close"), "0");
    drop(server.join().expect("the server ran"));
}

fn helper_connect(path: &Path) -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(WAIT))?;
    stream.set_write_timeout(Some(WAIT))?;
    Ok(stream)
}

/// The child half of the descriptor tests. Ignored so it never runs in an
/// ordinary pass; the parents invoke it by name with `--ignored` after
/// lowering the limits with `ulimit`.
#[test]
#[ignore = "child helper invoked by the n04 descriptor tests"]
fn proxy_limits_helper() {
    let mode = std::env::var(HELPER_MODE).expect("the helper needs a mode");
    let port: Option<u16> = std::env::var(HELPER_PORT)
        .ok()
        .map(|p| p.parse().expect("a port"));
    let resolver = fixtures("", &[]);
    let resolver = Arc::clone(&resolver) as Arc<dyn Resolver + Send + Sync>;
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("proxy.sock");
    let listener = UnixListener::bind(&path).expect("binds");
    let allow: Vec<String> = port
        .map(|p| vec![format!("127.0.0.1:{p}")])
        .unwrap_or_default();
    let config = |listener, budgets| ProxyConfig {
        listener,
        rules: Rules::from_strings(&allow, &[]).expect("rules"),
        budgets,
        resolver: Arc::clone(&resolver),
    };
    let sink = Arc::new(Sink::default());
    match mode.as_str() {
        "fit" => match proxy::start(config(listener, Budgets::default()), sink) {
            Ok(_) => panic!("the budget should not fit"),
            Err(error) => println!("HELPER error={error}"),
        },
        "raise" => {
            let (before, _) = proxy::nofile_limits().expect("limits");
            let handle = proxy::start(config(listener, Budgets::default()), sink).expect("starts");
            let (after, _) = proxy::nofile_limits().expect("limits");
            println!("HELPER soft_before={before}");
            println!("HELPER soft_after={after}");
            let _ = handle.stop(WAIT);
        }
        "exhaust" => {
            let port = port.expect("a port");
            let budgets = Budgets {
                max_connections: 4,
                ..Budgets::default()
            };
            let handle = proxy::start(
                config(listener, budgets),
                Arc::clone(&sink) as Arc<dyn ProxySink>,
            )
            .expect("starts");
            let connect = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n");
            let hog = || {
                let mut files = Vec::new();
                while let Ok(file) = std::fs::File::open("/dev/null") {
                    files.push(file);
                }
                files
            };
            // Two free.
            let mut files = hog();
            files.truncate(files.len() - 2);
            let mut client = helper_connect(&path).expect("connects");
            client.write_all(connect.as_bytes()).expect("writes");
            let (status, head) = read_head(&mut client);
            drop(files);
            println!("HELPER free2_status={status}");
            println!("HELPER free2_header={}", reason_of(&head).unwrap_or("-"));
            let results = sink.wait_for(1);
            let r = &results[0];
            println!(
                "HELPER free2_result={:?} {:?} connected={} errno={} end={:?}",
                r.decision,
                r.reason,
                r.connected.is_some(),
                if r.connect_errno == Some(libc::EMFILE) {
                    "EMFILE"
                } else {
                    "other"
                },
                r.end
            );
            drop(client);
            // Three free.
            let mut files = hog();
            files.truncate(files.len() - 3);
            let mut client = helper_connect(&path).expect("connects");
            client.write_all(connect.as_bytes()).expect("writes");
            let (status, _) = read_head(&mut client);
            let mut hi = [0u8; 2];
            client.read_exact(&mut hi).expect("relayed bytes");
            drop(files);
            println!("HELPER free3_status={status}");
            println!("HELPER free3_relayed={}", String::from_utf8_lossy(&hi));
            client.shutdown(Shutdown::Write).expect("half-closes");
            read_to_eof(&mut client);
            sink.wait_for(2);
            // One free: the client takes it, the accept fails and backs off.
            let mut files = hog();
            files.truncate(files.len() - 1);
            let mut client = helper_connect(&path).expect("connects");
            client.write_all(connect.as_bytes()).expect("writes");
            // Give descriptors back once the proxy has seen the pending
            // connection and failed to accept it; it then serves it.
            drop(files);
            let (status, _) = read_head(&mut client);
            println!("HELPER free1_status={status}");
            client.shutdown(Shutdown::Write).expect("half-closes");
            read_to_eof(&mut client);
            sink.wait_for(3);
            let _ = handle.stop(WAIT);
        }
        "fds" => {
            let port = port.expect("a port");
            let handle = proxy::start(
                config(listener, Budgets::default()),
                Arc::clone(&sink) as Arc<dyn ProxySink>,
            )
            .expect("starts");
            let before = proxy::open_descriptor_count().expect("countable");
            let mut clients = Vec::new();
            for _ in 0..16 {
                let mut client = helper_connect(&path).expect("connects");
                client
                    .write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n").as_bytes())
                    .expect("writes");
                assert_eq!(read_head(&mut client).0, 200);
                clients.push(client);
            }
            let after = proxy::open_descriptor_count().expect("countable");
            println!(
                "HELPER proxy_fds_for_16_tunnels={}",
                after - before - clients.len()
            );
            drop(clients);
            sink.wait_for(16);
            // Every descriptor of a settled connection is closed again, not
            // kept alive by the stop registry.
            let deadline = Instant::now() + WAIT;
            let mut now = proxy::open_descriptor_count().expect("countable");
            while now != before && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
                now = proxy::open_descriptor_count().expect("countable");
            }
            println!("HELPER fds_after_close={}", now.abs_diff(before));
            let _ = handle.stop(WAIT);
        }
        other => panic!("unknown helper mode {other}"),
    }
}
