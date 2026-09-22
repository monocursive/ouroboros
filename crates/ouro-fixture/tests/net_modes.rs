//! The network modes as real processes against loopback peers: unconnected
//! UDP, a DNS query to a named resolver, and the HTTP client directly and
//! through an in-test proxy stand-in. Portable: these run on macOS and on
//! the reference host, unprivileged and without the jail.
//!
//! Every peer here records what it saw, and every assertion about a line is
//! checked against the peer: a line that says 300 bytes went out is compared
//! with the 300 bytes that arrived.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use ouro_fixture::harness::HttpServer;
use ouro_fixture::harness::http::{SeenRequest, parse_request_head};
use serde_json::Value;

// ---------------------------------------------------------------- udp-sendto

#[test]
fn udp_sendto_delivers_exactly_the_bytes_it_reports() {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let addr = peer.local_addr().unwrap().to_string();
    let out = run(&["udp-sendto", &addr, "--bytes", "300"]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(ops(&l), ["socket", "sendto"]);
    assert_eq!(l[0]["args"]["type"], "SOCK_DGRAM");
    assert_eq!(l[1]["ret"], 300);
    assert_eq!(l[1]["args"]["connected"], false);
    assert_eq!(l[1]["args"]["addr"], addr.as_str());

    let mut buf = [0u8; 1024];
    let (n, from) = peer.recv_from(&mut buf).unwrap();
    assert_eq!(n, 300);
    assert_eq!(from.ip().to_string(), "127.0.0.1");
    for (i, b) in buf[..n].iter().enumerate() {
        assert_eq!(*b, (i % 256) as u8);
    }
}

#[test]
fn udp_sendto_over_ipv6_reaches_the_peer() {
    let Ok(peer) = UdpSocket::bind("[::1]:0") else {
        ouro_fixture::harness::skip_or_fail("no IPv6 loopback on this host");
        return;
    };
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let addr = peer.local_addr().unwrap().to_string();
    let out = run(&["udp-sendto", &addr, "--bytes", "7"]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    assert_eq!(lines(&out)[0]["args"]["family"], "AF_INET6");
    let mut buf = [0u8; 16];
    assert_eq!(peer.recv(&mut buf).unwrap(), 7);
}

#[test]
fn udp_sendto_reports_the_kernels_refusal_and_refuses_names() {
    // Above every platform's datagram limit: the kernel answers, the fixture
    // reports it rather than pre-judging.
    let out = run(&[
        "udp-sendto",
        "127.0.0.1:9",
        "--bytes",
        "70000",
        "--expect",
        "EMSGSIZE",
    ]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    assert_eq!(last(&lines(&out), "sendto")["errno"], "EMSGSIZE");

    let out = run(&["udp-sendto", "example.invalid:53"]);
    assert_eq!(code(&out), EXIT_USAGE);
    assert!(lines(&out).is_empty(), "nothing was attempted");
}

// ----------------------------------------------------------------- dns-query

/// A resolver stand-in: answers each query it receives with `reply(query)`.
fn resolver(
    reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
) -> (SocketAddr, std::thread::JoinHandle<Vec<Vec<u8>>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let addr = sock.local_addr().unwrap();
    let t = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let mut buf = [0u8; 512];
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            seen.push(buf[..n].to_vec());
            for datagram in reply(&buf[..n]) {
                sock.send_to(&datagram, from).unwrap();
            }
        }
        seen
    });
    (addr, t)
}

/// A response to `query` with `rcode` and one A record for 192.0.2.44.
fn answer(query: &[u8], rcode: u8, id_delta: u16) -> Vec<u8> {
    let id = u16::from_be_bytes([query[0], query[1]]).wrapping_add(id_delta);
    let mut r = id.to_be_bytes().to_vec();
    r.extend_from_slice(&[0x81, 0x80 | rcode, 0, 1, 0, 1, 0, 0, 0, 0]);
    r.extend_from_slice(&query[12..]); // the question, as asked
    r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 44]);
    r
}

#[test]
fn dns_query_reads_the_answer_from_the_named_resolver() {
    let (addr, t) = resolver(|q| vec![answer(q, 0, 0)]);
    let out = run(&["dns-query", &addr.to_string(), "Example.test."]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(ops(&l), ["socket", "sendto", "dns-query"]);
    let s = &l[2];
    assert_eq!(s["args"]["answered"], true);
    assert_eq!(s["args"]["rcode_name"], "NOERROR");
    assert_eq!(s["args"]["ancount"], 1);
    assert_eq!(s["args"]["a"], serde_json::json!(["192.0.2.44"]));
    assert_eq!(s["ret"], 0);

    let seen = t.join().unwrap();
    assert_eq!(seen.len(), 1);
    let q = &seen[0];
    assert_eq!(s["args"]["id"], u16::from_be_bytes([q[0], q[1]]));
    assert_eq!(
        &q[12..],
        b"\x07Example\x04test\x00\x00\x01\x00\x01",
        "sent as given"
    );
}

#[test]
fn dns_query_skips_a_forged_id_and_reports_nxdomain() {
    let (addr, t) = resolver(|q| vec![answer(q, 0, 1), answer(q, 3, 0)]);
    let out = run(&["dns-query", &addr.to_string(), "missing.test"]);
    assert_eq!(code(&out), 0, "a response arrived: {}", describe(&out));
    let s = last(&lines(&out), "dns-query").clone();
    assert_eq!(s["args"]["ignored_datagrams"], 1, "{s}");
    assert_eq!(s["args"]["rcode_name"], "NXDOMAIN");
    assert_eq!(s["ret"], 3);
    t.join().unwrap();
}

#[test]
fn dns_query_without_an_answer_stops_at_its_deadline() {
    let (addr, t) = resolver(|_| Vec::new());
    let started = Instant::now();
    let out = run(&[
        "dns-query",
        &addr.to_string(),
        "quiet.test",
        "--timeout-ms",
        "300",
    ]);
    assert!(started.elapsed() < Duration::from_secs(10), "bounded");
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
    let s = last(&lines(&out), "dns-query").clone();
    assert_eq!(s["args"]["answered"], false);
    assert_eq!(s["errno"], "ETIMEDOUT");
    assert_eq!(s["args"]["errno_source"], "fixture_deadline");
    t.join().unwrap();

    let (addr, t) = resolver(|_| Vec::new());
    let out = run(&[
        "dns-query",
        &addr.to_string(),
        "quiet.test",
        "--timeout-ms",
        "200",
        "--expect",
        "ETIMEDOUT",
    ]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    t.join().unwrap();
}

#[test]
fn dns_query_reports_a_malformed_answer_as_no_result() {
    let (addr, t) = resolver(|q| vec![q[..2].to_vec()]);
    let out = run(&["dns-query", &addr.to_string(), "short.test"]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
    let s = last(&lines(&out), "dns-query").clone();
    assert_eq!(s["args"]["answered"], true);
    assert_eq!(s["args"]["malformed"], "short_header");
    assert_eq!(s["ret"], -1);
    t.join().unwrap();

    let out = run(&["dns-query", "resolver.example", "x.test"]);
    assert_eq!(code(&out), EXIT_USAGE, "a named resolver is refused");
    let out = run(&["dns-query", "127.0.0.1", "bücher.test"]);
    assert_eq!(code(&out), EXIT_USAGE, "no IDNA in the fixture");
}

// ---------------------------------------------------------- proxy stand-in

/// A tiny forward proxy: records every request head, relays absolute-form
/// GETs (rewritten to origin form) and CONNECT tunnels to one fixed
/// upstream, whatever host the request names. `deny` answers CONNECT 403.
struct StandIn {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn read_head(s: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    head
}

fn relay(from: &mut TcpStream, to: &mut TcpStream) {
    let _ = std::io::copy(from, to);
    let _ = to.shutdown(std::net::Shutdown::Write);
}

impl StandIn {
    fn start(upstream: SocketAddr, deny: bool) -> StandIn {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, c2, stop2) = (
            Arc::clone(&seen),
            Arc::clone(&connections),
            Arc::clone(&stop),
        );
        let thread = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop2.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut client) = conn else { continue };
                c2.fetch_add(1, Ordering::SeqCst);
                client
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let head = read_head(&mut client);
                let Some(req) = parse_request_head(&head) else {
                    continue;
                };
                s2.lock().unwrap().push(req.clone());
                if req.method == "CONNECT" {
                    if deny {
                        let _ = client.write_all(
                            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied",
                        );
                        continue;
                    }
                    let mut up = TcpStream::connect(upstream).unwrap();
                    up.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    client
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .unwrap();
                    let (mut c_in, mut u_out) =
                        (client.try_clone().unwrap(), up.try_clone().unwrap());
                    let t = std::thread::spawn(move || relay(&mut c_in, &mut u_out));
                    relay(&mut up, &mut client);
                    let _ = t.join();
                } else {
                    let path = req
                        .target
                        .strip_prefix("http://")
                        .and_then(|r| r.find('/').map(|i| r[i..].to_string()))
                        .unwrap_or_else(|| req.target.clone());
                    let text = String::from_utf8_lossy(&head);
                    let rest = text.split_once("\r\n").map_or("", |(_, r)| r);
                    let mut up = TcpStream::connect(upstream).unwrap();
                    up.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    up.write_all(format!("{} {path} HTTP/1.1\r\n{rest}", req.method).as_bytes())
                        .unwrap();
                    relay(&mut up, &mut client);
                }
            }
        });
        StandIn {
            addr,
            seen,
            connections,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn seen(&self) -> Vec<SeenRequest> {
        self.seen.lock().unwrap().clone()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept with one connection of our own.
        let _ = TcpStream::connect(self.addr);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ------------------------------------------------------------------ http-get

#[test]
fn http_get_directly_sends_origin_form_and_counts_the_body() {
    let origin = HttpServer::start(b"0123456789".to_vec()).unwrap();
    let out = run(&["http-get", &origin.url("/direct?q=1")]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(ops(&l)[0], "socket");
    assert!(ops(&l).contains(&"connect".to_string()));
    let s = last(&l, "http-get");
    assert_eq!(s["args"]["via_proxy"], false);
    assert_eq!(s["args"]["request_form"], "origin");
    assert_eq!(s["args"]["status_code"], 200);
    assert_eq!(s["args"]["body_bytes"], 10);
    assert_eq!(s["args"]["body_framing"], "content_length");
    assert_eq!(s["args"]["body_complete"], true);
    assert!(s["args"]["header_bytes"].as_u64().unwrap() > 20);
    assert!(
        s["args"]["status_line"]
            .as_str()
            .unwrap()
            .starts_with("HTTP/1.1 200")
    );
    assert_eq!(s["ret"], 200);

    let seen = origin.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].target, "/direct?q=1");
    assert_eq!(
        seen[0].host.as_deref(),
        Some(origin.addr().to_string().as_str())
    );
}

#[test]
fn http_get_through_the_proxy_sends_absolute_form_and_never_resolves_the_name() {
    let origin = HttpServer::start(b"via-proxy".to_vec()).unwrap();
    let proxy = StandIn::start(origin.addr(), false);
    let url = "http://origin.test:8080/p";
    let out = run_env(&["http-get", url], &[("http_proxy", &proxy.url())]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    let connect = last(&l, "connect");
    assert_eq!(connect["args"]["addr_source"], "proxy_variable");
    assert!(
        connect["args"].get("addr").is_none(),
        "the proxy value is never printed"
    );
    let s = last(&l, "http-get");
    assert_eq!(s["args"]["via_proxy"], true);
    assert_eq!(s["args"]["proxy_var"], "http_proxy");
    assert_eq!(s["args"]["request_form"], "absolute");
    assert_eq!(s["args"]["body_bytes"], 9);
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(&proxy.addr.port().to_string()),
        "no line carries the proxy's address"
    );

    let seen = proxy.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, url, "absolute form, the name as given");
    assert_eq!(seen[0].host.as_deref(), Some("origin.test:8080"));
    assert_eq!(
        origin.requests()[0].target,
        "/p",
        "the stand-in forwarded it"
    );
}

#[test]
fn the_lowercase_variable_wins_and_an_empty_one_counts_as_unset() {
    let origin = HttpServer::start(b"x".to_vec()).unwrap();
    let lower = StandIn::start(origin.addr(), false);
    let upper = StandIn::start(origin.addr(), false);
    let out = run_env(
        &["http-get", "http://a.test/"],
        &[("http_proxy", &lower.url()), ("HTTP_PROXY", &upper.url())],
    );
    assert_eq!(code(&out), 0, "{}", describe(&out));
    assert_eq!((lower.seen().len(), upper.seen().len()), (1, 0));

    let out = run_env(
        &["http-get", "http://a.test/"],
        &[("http_proxy", ""), ("HTTP_PROXY", &upper.url())],
    );
    assert_eq!(code(&out), 0, "{}", describe(&out));
    assert_eq!(
        last(&lines(&out), "http-get")["args"]["proxy_var"],
        "HTTP_PROXY"
    );
    assert_eq!(upper.seen().len(), 1);
}

#[test]
fn an_unusable_proxy_variable_is_refused_never_bypassed_or_printed() {
    let origin = HttpServer::start(b"x".to_vec()).unwrap();
    let proxy = StandIn::start(origin.addr(), false);
    let value = format!("http://user:s3cr3t@{}", proxy.addr);
    let out = run_env(&["http-get", &origin.url("/")], &[("HTTP_PROXY", &value)]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(ops(&l), ["http-get"], "no socket was created");
    assert_eq!(l[0]["args"]["refused"], "proxy_variable_unusable");
    assert_eq!(l[0]["args"]["proxy_problem"], "userinfo_not_supported");
    assert_eq!(l[0]["args"]["proxy_var"], "HTTP_PROXY");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!all.contains("s3cr3t"), "the value never appears: {all}");
    assert_eq!(proxy.connections(), 0);
    assert_eq!(
        origin.connections(),
        0,
        "no silent direct connection either"
    );
}

#[test]
fn no_proxy_goes_direct_even_with_a_variable_set() {
    let origin = HttpServer::start(b"direct".to_vec()).unwrap();
    let proxy = StandIn::start(origin.addr(), false);
    let out = run_env(
        &["http-get", "--no-proxy", &origin.url("/bypass")],
        &[("http_proxy", &proxy.url()), ("HTTP_PROXY", &proxy.url())],
    );
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let s = last(&lines(&out), "http-get").clone();
    assert_eq!(s["args"]["ignored_proxy_variables"], true);
    assert_eq!(s["args"]["via_proxy"], false);
    assert_eq!(proxy.connections(), 0);
    assert_eq!(origin.requests()[0].target, "/bypass");
}

#[test]
fn http_get_refuses_what_it_cannot_do_honestly() {
    let out = run(&["http-get", "http://name.test/"]);
    assert_eq!(
        code(&out),
        EXIT_USAGE,
        "a name without a proxy would need a lookup"
    );
    let out = run(&["http-get", "https://127.0.0.1/"]);
    assert_eq!(code(&out), EXIT_USAGE, "no TLS");
    assert!(String::from_utf8_lossy(&out.stderr).contains("no TLS"));
}

#[test]
fn a_refused_connection_carries_its_errno_to_the_summary() {
    // Bind then drop, so the port is known to have no listener.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = format!("http://127.0.0.1:{port}/");
    let out = run(&["http-get", &url, "--expect", "ECONNREFUSED"]);
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let s = last(&lines(&out), "http-get").clone();
    assert_eq!(s["args"]["failed_step"], "connect");
    assert_eq!(s["errno"], "ECONNREFUSED");
}

#[test]
fn hostile_servers_are_bounded() {
    // Headers that never end.
    let flood = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", flood.local_addr().unwrap());
    let t = std::thread::spawn(move || {
        let (mut s, _) = flood.accept().unwrap();
        let _ = read_head(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\n");
        let line =
            b"X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
        for _ in 0..2000 {
            if s.write_all(line).is_err() {
                break;
            }
        }
    });
    let out = run(&["http-get", &url]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
    let s = last(&lines(&out), "http-get").clone();
    assert_eq!(s["args"]["reason"], "header_overflow");
    t.join().unwrap();

    // A server that accepts and never answers.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", silent.local_addr().unwrap());
    let started = Instant::now();
    let out = run(&["http-get", &url, "--timeout-ms", "300"]);
    assert!(started.elapsed() < Duration::from_secs(10));
    let s = last(&lines(&out), "http-get").clone();
    assert_eq!(s["errno"], "ETIMEDOUT", "{s}");
    assert_eq!(s["args"]["errno_source"], "fixture_deadline");
    assert_eq!(s["args"]["failed_step"], "read_head");
    drop(silent);
}

// -------------------------------------------------------------- http-connect

#[test]
fn http_connect_opens_a_tunnel_and_carries_a_request_through_it() {
    let origin = HttpServer::start(b"tunnelled".to_vec()).unwrap();
    let proxy = StandIn::start(origin.addr(), false);
    let authority = origin.addr().to_string();
    let out = run_env(
        &["http-connect", &authority, "--then-get", "/t"],
        &[("HTTPS_PROXY", &proxy.url())],
    );
    assert_eq!(code(&out), 0, "{}", describe(&out));
    let l = lines(&out);
    let outer = last(&l, "http-connect");
    assert_eq!(outer["args"]["status_code"], 200);
    assert_eq!(outer["args"]["tunnel"], true);
    assert_eq!(outer["args"]["body_framing"], "tunnel");
    assert_eq!(outer["args"]["proxy_var"], "HTTPS_PROXY");
    let inner = last(&l, "http-get");
    assert_eq!(inner["args"]["via"], "tunnel");
    assert_eq!(inner["args"]["status_code"], 200);
    assert_eq!(inner["args"]["body_bytes"], 9);

    let seen = proxy.seen();
    assert_eq!(seen[0].method, "CONNECT");
    assert_eq!(seen[0].target, authority);
    assert_eq!(seen[0].host.as_deref(), Some(authority.as_str()));
    assert_eq!(origin.requests()[0].target, "/t");
}

#[test]
fn a_denied_connect_is_a_response_with_no_tunnel() {
    let origin = HttpServer::start(Vec::new()).unwrap();
    let proxy = StandIn::start(origin.addr(), true);
    let out = run_env(
        &[
            "http-connect",
            "denied.test:443",
            "--then-get",
            "/",
            "--host-header",
            "other.test:443",
        ],
        &[("https_proxy", &proxy.url())],
    );
    assert_eq!(code(&out), 0, "a response arrived: {}", describe(&out));
    let l = lines(&out);
    let outer = last(&l, "http-connect");
    assert_eq!(outer["args"]["status_code"], 403);
    assert_eq!(outer["args"]["body_bytes"], 6);
    assert!(outer["args"].get("tunnel").is_none());
    assert!(
        !ops(&l).contains(&"http-get".to_string()),
        "no tunnel, no inner request"
    );
    assert_eq!(
        proxy.seen()[0].host.as_deref(),
        Some("other.test:443"),
        "--host-header is sent"
    );
    assert_eq!(origin.connections(), 0);
}

#[test]
fn http_connect_without_a_proxy_variable_refuses() {
    let out = run(&["http-connect", "127.0.0.1:443"]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "{}", describe(&out));
    let l = lines(&out);
    assert_eq!(ops(&l), ["http-connect"]);
    assert_eq!(l[0]["args"]["refused"], "no_proxy_variable");
    assert_eq!(l[0]["args"]["proxy_var"], Value::Null);
}
