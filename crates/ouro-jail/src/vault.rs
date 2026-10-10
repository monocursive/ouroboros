//! Attempt-scoped HTTP credentials. Secrets and CA private keys stay in memory.
use crate::network::{Destination, parse_authority};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub hosts: Vec<String>,
    #[serde(default)]
    pub allow_plaintext: bool,
    /// Where the placeholder may appear: a named header with an optional
    /// prefix before the placeholder, such as `authorization` with
    /// `Bearer `. Without one, only the complete `Authorization` value
    /// is eligible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
}

/// A declared placement for a vault placeholder: the header name and the
/// credential prefix (`Bearer `) that must precede it. The secret never
/// leaves for a host outside `Policy::hosts`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    /// The header the credential belongs in, case-insensitive.
    pub name: String,
    /// Text that must precede the placeholder in the value, without the
    /// secret itself (for example `Bearer `).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}
impl Policy {
    pub fn validate(&self) -> Result<(), String> {
        if self.hosts.is_empty() || self.hosts.len() > 64 {
            return Err("vault needs 1..64 exact HTTP(S) origins".into());
        }
        for raw in &self.hosts {
            let (scheme, _) = origin(raw)?;
            if scheme == "http" && !self.allow_plaintext {
                return Err("plaintext vault origins require allow_plaintext = true".into());
            }
        }
        if let Some(header) = &self.header {
            header.validate()?;
        }
        Ok(())
    }
    fn permits(&self, scheme: &str, destination: &Destination) -> bool {
        self.hosts
            .iter()
            .any(|h| origin(h).is_ok_and(|(s, d)| s == scheme && d == *destination))
    }
}
impl Header {
    /// An RFC 9110 token name and a printable, line-ending-free prefix.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty()
            || self.name.len() > 64
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err("vault header name must be 1..64 ASCII token characters".into());
        }
        if let Some(prefix) = &self.prefix
            && (prefix.is_empty()
                || prefix.len() > 64
                || !prefix.bytes().all(|b| (0x20..=0x7e).contains(&b)))
        {
            return Err(
                "vault header prefix must be 1..64 printable ASCII without line endings".into(),
            );
        }
        Ok(())
    }
}
fn origin(value: &str) -> Result<(&str, Destination), String> {
    let (scheme, authority) = value
        .split_once("://")
        .ok_or("vault hosts must be exact http:// or https:// origins")?;
    let port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return Err("unsupported vault scheme".into()),
    };
    if authority.contains(['/', '*', '?', '#', '@']) {
        return Err("vault origin cannot contain a path, wildcard or userinfo".into());
    }
    Ok((
        scheme,
        parse_authority(authority, Some(port)).map_err(|_| "invalid vault origin")?,
    ))
}

pub struct Secret {
    pub id: String,
    pub policy: Policy,
    pub value: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSecret")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
impl Secret {
    pub fn new(id: String, policy: Policy, bytes: Vec<u8>) -> Result<Self, String> {
        let value = Zeroizing::new(bytes);
        if value.is_empty() || value.len() > 8192 || value.iter().any(|b| !matches!(b, 0x20..=0x7e))
        {
            return Err(
                "vault value must be 1..8192 printable ASCII bytes without line endings".into(),
            );
        }
        policy.validate()?;
        Ok(Self { id, policy, value })
    }
}

pub struct Vault {
    attempt: String,
    secrets: Vec<Arc<Secret>>,
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    client: Arc<rustls::ClientConfig>,
}
impl Vault {
    pub fn new(attempt: &str, secrets: Vec<Arc<Secret>>) -> Result<Self, String> {
        let mut params = rcgen::CertificateParams::new(vec![]).map_err(|e| e.to_string())?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("Ouroboros attempt {attempt}"),
        );
        let ca = rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate().map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            attempt: attempt.into(),
            secrets,
            ca,
            client: Arc::new(client),
        })
    }
    pub fn ca_pem(&self) -> String {
        self.ca.pem()
    }
    pub fn environment(&self) -> Vec<(String, String)> {
        self.secrets
            .iter()
            .map(|s| {
                (
                    format!(
                        "OURO_VAULT_{}",
                        s.id.to_ascii_uppercase().replace(['.', '-'], "_")
                    ),
                    self.placeholder(s),
                )
            })
            .collect()
    }
    fn placeholder(&self, secret: &Secret) -> String {
        format!("vault:{}:{}", self.attempt, secret.id)
    }
    /// A placeholder is eligible exactly where its secret declares: the
    /// header name matches (case-insensitively) and the value is the
    /// declared prefix followed by the placeholder and nothing else. The
    /// default declaration is the complete `Authorization` value. Other
    /// placements of the marker are refused, never rewritten and never
    /// logged.
    pub fn inject(
        &self,
        scheme: &str,
        request: &mut crate::proxy::http::Request,
    ) -> Result<(), crate::proxy::Reason> {
        use crate::proxy::Reason;
        let mut out = Zeroizing::new(Vec::with_capacity(request.forward_head.len() + 8192));
        for line in request.forward_head.split_inclusive(|b| *b == b'\n') {
            if !line.windows(6).any(|s| s == b"vault:") {
                out.extend_from_slice(line);
                continue;
            }
            let colon = line
                .iter()
                .position(|b| *b == b':')
                .ok_or(Reason::OriginUnverified)?;
            let name = &line[..colon];
            let value = line[colon + 1..].trim_ascii();
            let mut matched: Option<(&std::sync::Arc<Secret>, Vec<u8>)> = None;
            for secret in &self.secrets {
                let header = secret.policy.header.as_ref();
                let expected_name =
                    header.map_or(b"authorization".as_slice(), |h| h.name.as_bytes());
                if !name.eq_ignore_ascii_case(expected_name) {
                    continue;
                }
                let prefix = header
                    .and_then(|header| header.prefix.as_deref())
                    .unwrap_or("");
                let mut expected = Vec::with_capacity(prefix.len() + 64);
                expected.extend_from_slice(prefix.as_bytes());
                expected.extend_from_slice(self.placeholder(secret).as_bytes());
                if value == expected.as_slice() {
                    // The emitted name is the operator's spelling; the
                    // default keeps today's canonical `Authorization`.
                    let emitted = match header {
                        Some(header) => header.name.as_bytes().to_vec(),
                        None => b"Authorization".to_vec(),
                    };
                    matched = Some((secret, emitted));
                    break;
                }
            }
            let Some((secret, emitted_name)) = matched else {
                return Err(Reason::OriginUnverified);
            };
            if !secret.policy.permits(scheme, &request.destination) {
                return Err(Reason::OriginMismatch);
            }
            out.extend_from_slice(&emitted_name);
            out.extend_from_slice(b": ");
            if let Some(prefix) = secret
                .policy
                .header
                .as_ref()
                .and_then(|header| header.prefix.as_deref())
            {
                out.extend_from_slice(prefix.as_bytes());
            }
            out.extend_from_slice(&secret.value);
            out.extend_from_slice(b"\r\n");
        }
        request.forward_head = out.to_vec();
        Ok(())
    }
    pub(crate) fn server(
        &self,
        destination: &Destination,
    ) -> Result<rustls::ServerConnection, crate::proxy::Reason> {
        use crate::proxy::Reason;
        let host = destination.host.to_string();
        let key = rcgen::KeyPair::generate().map_err(|_| Reason::InternalError)?;
        let params =
            rcgen::CertificateParams::new(vec![host]).map_err(|_| Reason::InternalError)?;
        let certificate = params
            .signed_by(&key, &self.ca)
            .map_err(|_| Reason::InternalError)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| Reason::InternalError)?
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone(), self.ca.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .map_err(|_| Reason::InternalError)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        rustls::ServerConnection::new(Arc::new(config)).map_err(|_| Reason::InternalError)
    }
    pub(crate) fn client(
        &self,
        destination: &Destination,
    ) -> Result<rustls::ClientConnection, crate::proxy::Reason> {
        let name = rustls::pki_types::ServerName::try_from(destination.host.to_string())
            .map_err(|_| crate::proxy::Reason::OriginUnverified)?;
        rustls::ClientConnection::new(self.client.clone(), name)
            .map_err(|_| crate::proxy::Reason::InternalError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        network::Rules,
        proxy::{
            self, Budgets, FixtureAnswer, FixtureResolver, ProxyConfig, ProxyResult, ProxySink,
            Reason,
        },
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;
    struct Sink(Mutex<mpsc::Sender<ProxyResult>>);
    impl ProxySink for Sink {
        fn emit(&self, result: ProxyResult) {
            let _ = self.0.lock().unwrap().send(result);
        }
    }
    fn roots(cert: rustls::pki_types::CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }
    fn head(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            reader.read_exact(&mut byte)?;
            bytes.push(byte[0]);
            if bytes.len() > 32768 {
                return Err(std::io::Error::other("oversized head"));
            }
        }
        Ok(bytes)
    }
    fn run_tls(
        trusted: bool,
        _matching_host: bool,
        authorized: bool,
        first: impl Fn(u16) -> String,
        pipeline: &[u8],
        relayed: bool,
    ) -> (ProxyResult, Vec<u8>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let generated = rcgen::generate_simple_self_signed(vec!["fixture.test".into()]).unwrap();
        let trusted_cert = generated.cert.der().clone();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![trusted_cert.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(config)).unwrap(),
                socket,
            );
            let bytes = head(&mut stream).unwrap_or_default();
            if !bytes.is_empty() {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nOK")
                    .unwrap();
                stream.conn.send_close_notify();
                stream.flush().unwrap();
            }
            bytes
        });
        let secret = Secret::new(
            "api".into(),
            Policy {
                hosts: vec![format!(
                    "https://{}:{port}",
                    if authorized {
                        "fixture.test"
                    } else {
                        "other.test"
                    }
                )],
                allow_plaintext: false,
                header: None,
            },
            b"Bearer fixture-secret".to_vec(),
        )
        .unwrap();
        let mut vault = Vault::new("test-attempt", vec![Arc::new(secret)]).unwrap();
        if trusted {
            vault.client = roots(trusted_cert);
        }
        let client_config = roots(vault.ca.der().clone());
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("proxy.sock");
        let resolver = FixtureResolver::new();
        resolver.script(
            "fixture.test",
            vec![FixtureAnswer::Addresses(vec!["127.0.0.1".parse().unwrap()])],
        );
        let (sender, receiver) = mpsc::channel();
        let proxy = proxy::start_with_vault(
            ProxyConfig {
                listener: UnixListener::bind(&path).unwrap(),
                rules: Rules::from_strings(
                    &[format!("fixture.test:{port}"), format!("127.0.0.1:{port}")],
                    &[],
                )
                .unwrap(),
                budgets: Budgets::default(),
                resolver: Arc::new(resolver),
            },
            Arc::new(Sink(Mutex::new(sender))),
            Some(Arc::new(vault)),
        )
        .unwrap();
        let mut socket = UnixStream::connect(path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            socket,
            "CONNECT fixture.test:{port} HTTP/1.1\r\nHost: fixture.test:{port}\r\n\r\n"
        )
        .unwrap();
        assert!(head(&mut socket).unwrap().starts_with(b"HTTP/1.1 200"));
        let mut child = rustls::StreamOwned::new(
            rustls::ClientConnection::new(
                client_config,
                rustls::pki_types::ServerName::try_from("fixture.test").unwrap(),
            )
            .unwrap(),
            socket,
        );
        child.write_all(first(port).as_bytes()).unwrap();
        child.write_all(pipeline).unwrap();
        child.flush().unwrap();
        let mut response = Vec::new();
        let read = child.read_to_end(&mut response);
        if relayed {
            // Keep the client's write side open through the relay's drain.
            // A close-delimited response needs a TLS close_notify; receiving
            // its body followed by an unexpected transport EOF is not success.
            read.expect("the complete response ends with a TLS close_notify");
        }
        let event = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(proxy.stop(Duration::from_secs(10)).complete());
        (event, server.join().unwrap(), response)
    }
    /// The default first flight: an authorized GET for the matching host.
    fn authorized_get(matching_host: bool) -> impl Fn(u16) -> String {
        move |port| {
            format!(
                "GET / HTTP/1.1\r\nHost: {}:{port}\r\nAuthorization: vault:test-attempt:api\r\n\r\n",
                if matching_host {
                    "fixture.test"
                } else {
                    "other.test"
                }
            )
        }
    }
    #[test]
    fn tls_vault_substitutes_only_after_both_authorities_and_the_certificate_pass() {
        let (event, upstream, response) =
            run_tls(true, true, true, authorized_get(true), b"", true);
        assert_eq!(event.reason, Reason::Relayed);
        assert_eq!(event.origin_verification.as_deref(), Some("mitm_http_host"));
        assert!(
            upstream
                .windows(b"Bearer fixture-secret".len())
                .any(|s| s == b"Bearer fixture-secret")
        );
        assert!(!upstream.windows(6).any(|s| s == b"vault:"));
        assert!(response.ends_with(b"OK"));
        for case in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let (event, upstream, _) =
                run_tls(case.0, case.1, case.2, authorized_get(case.1), b"", false);
            assert_ne!(event.reason, Reason::Relayed);
            assert!(
                upstream.is_empty(),
                "no HTTP credential bytes may reach an unverified destination"
            );
        }
    }
    #[test]
    fn tls_vault_closes_the_response_and_counts_discarded_pipeline_bytes() {
        let pipeline = b"GET /second HTTP/1.1\r\nHost: fixture.test\r\n\r\n";
        let (event, upstream, response) =
            run_tls(true, true, true, authorized_get(true), pipeline, true);
        assert_eq!(event.reason, Reason::Relayed);
        assert_eq!(event.discarded_bytes, pipeline.len() as u64);
        assert!(!upstream.windows(7).any(|bytes| bytes == b"/second"));
        assert_eq!(response, b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nOK");
    }
    #[test]
    fn a_secret_bound_to_https_never_reaches_a_plaintext_origin() {
        // jail-v2 §6.3: the scheme is part of the binding. Absolute-form
        // `http://fixture.test:443` names the very destination the https
        // secret is bound to; only the scheme distinguishes the plaintext
        // injection attempt.
        let secret = Arc::new(
            Secret::new(
                "api".into(),
                Policy {
                    hosts: vec!["https://fixture.test".into()],
                    allow_plaintext: false,
                    header: None,
                },
                b"Bearer fixture-secret".to_vec(),
            )
            .unwrap(),
        );
        let vault = Vault::new("test-attempt", vec![secret]).unwrap();
        let flight = || {
            proxy::http::parse_request(
                b"GET http://fixture.test:443/ HTTP/1.1\r\nHost: fixture.test:443\r\nAuthorization: vault:test-attempt:api\r\n\r\n",
            )
            .unwrap()
        };
        vault
            .inject("http", &mut flight())
            .expect_err("a plaintext origin must not receive an https-bound secret");
        let mut secure = flight();
        vault
            .inject("https", &mut secure)
            .expect("the bound https origin substitutes");
        assert!(
            secure
                .forward_head
                .windows(b"Bearer fixture-secret".len())
                .any(|s| s == b"Bearer fixture-secret")
        );
        // Positive control: the allow_plaintext opt-in substitutes over http
        // (default port 80 here, matching the secret's own binding).
        let plain = Arc::new(
            Secret::new(
                "api".into(),
                Policy {
                    hosts: vec!["http://fixture.test".into()],
                    allow_plaintext: true,
                    header: None,
                },
                b"Bearer fixture-secret".to_vec(),
            )
            .unwrap(),
        );
        let plain_vault = Vault::new("test-attempt", vec![plain]).unwrap();
        let mut default_port = proxy::http::parse_request(
            b"GET http://fixture.test/ HTTP/1.1\r\nHost: fixture.test\r\nAuthorization: vault:test-attempt:api\r\n\r\n",
        )
        .unwrap();
        plain_vault
            .inject("http", &mut default_port)
            .expect("the allow_plaintext opt-in substitutes");
    }
    #[test]
    fn a_placeholder_outside_authorization_is_refused_never_rewritten() {
        let secret = Arc::new(
            Secret::new(
                "api".into(),
                Policy {
                    hosts: vec!["http://fixture.test".into()],
                    allow_plaintext: true,
                    header: None,
                },
                b"Bearer fixture-secret".to_vec(),
            )
            .unwrap(),
        );
        let vault = Vault::new("test-attempt", vec![secret]).unwrap();
        let mut request = proxy::http::parse_request(
            b"POST http://fixture.test/ HTTP/1.1\r\nHost: fixture.test\r\nX-Api-Key: vault:test-attempt:api\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        let error = vault
            .inject("http", &mut request)
            .expect_err("a marker outside Authorization must refuse");
        assert_eq!(error, Reason::OriginUnverified);
        assert!(
            !request
                .forward_head
                .windows(b"Bearer fixture-secret".len())
                .any(|s| s == b"Bearer fixture-secret"),
            "the secret must not be substituted"
        );
        assert!(
            !request
                .forward_head
                .windows(15)
                .any(|s| s.eq_ignore_ascii_case(b"authorization:")),
            "the secret must not be rewritten into Authorization: {:?}",
            String::from_utf8_lossy(&request.forward_head)
        );
    }
    /// The TLS lane's post-decryption refusals (audit survivors, tls.rs):
    /// the 32 KiB decrypted-header bound, the chunked refusal and the
    /// `Expect` refusal by header name.
    #[test]
    fn the_tls_lane_refuses_oversized_chunked_and_expect_first_flights() {
        // Decrypted headers past 32 KiB refuse instead of parsing forever.
        let (event, upstream, _) = run_tls(
            true,
            true,
            true,
            |port| {
                format!(
                    "GET / HTTP/1.1\r\nHost: fixture.test:{port}\r\nX-Pad: {}\r\n\r\n",
                    "a".repeat(40_000)
                )
            },
            b"",
            false,
        );
        assert_eq!(event.reason, Reason::HeaderTooLarge);
        assert!(upstream.is_empty(), "no bytes may be forwarded");

        // Chunked framing is refused in this one-request lane.
        let (event, upstream, _) = run_tls(
            true,
            true,
            true,
            |port| {
                format!(
                    "POST / HTTP/1.1\r\nHost: fixture.test:{port}\r\n\
                     Authorization: vault:test-attempt:api\r\n\
                     Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                )
            },
            b"",
            false,
        );
        assert_eq!(event.reason, Reason::UnsupportedRequest);
        assert!(
            !upstream
                .windows(b"Bearer fixture-secret".len())
                .any(|s| s == b"Bearer fixture-secret")
        );

        // `Expect` is refused by header name at line start.
        let (event, upstream, _) = run_tls(
            true,
            true,
            true,
            |port| {
                format!(
                    "GET / HTTP/1.1\r\nHost: fixture.test:{port}\r\n\
                     Expect: 100-continue\r\n\
                     Authorization: vault:test-attempt:api\r\n\r\n"
                )
            },
            b"",
            false,
        );
        assert_eq!(event.reason, Reason::UnsupportedRequest);
        assert!(upstream.is_empty());

        // The match is by header name, not substring: a value that merely
        // mentions `expect:` is none of this lane's business and relays.
        let (event, upstream, _) = run_tls(
            true,
            true,
            true,
            |port| {
                format!(
                    "GET / HTTP/1.1\r\nHost: fixture.test:{port}\r\n\
                     X-Note: please expect: later\r\n\
                     Authorization: vault:test-attempt:api\r\n\r\n"
                )
            },
            b"",
            true,
        );
        assert_eq!(event.reason, Reason::Relayed);
        assert!(
            upstream
                .windows(b"Bearer fixture-secret".len())
                .any(|s| s == b"Bearer fixture-secret")
        );
    }
    #[test]
    fn plaintext_is_opt_in_and_substitution_is_exact() {
        assert!(
            Policy {
                hosts: vec!["http://fixture.test".into()],
                allow_plaintext: false,
                header: None
            }
            .validate()
            .is_err()
        );
        let secret = Arc::new(
            Secret::new(
                "api".into(),
                Policy {
                    hosts: vec!["http://fixture.test".into()],
                    allow_plaintext: true,
                    header: None,
                },
                b"Bearer fixture-secret".to_vec(),
            )
            .unwrap(),
        );
        let vault = Vault::new("test-attempt", vec![secret]).unwrap();
        for (host, value, ok) in [
            ("fixture.test", "vault:test-attempt:api", true),
            ("other.test", "vault:test-attempt:api", false),
            ("fixture.test", "Bearer vault:test-attempt:api", false),
        ] {
            let text = format!(
                "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nAuthorization: {value}\r\n\r\n"
            );
            let mut request = proxy::http::parse_request(text.as_bytes()).unwrap();
            assert_eq!(vault.inject("http", &mut request).is_ok(), ok);
        }
        assert!(
            Secret::new(
                "api".into(),
                Policy {
                    hosts: vec!["https://fixture.test".into()],
                    allow_plaintext: false,
                    header: None
                },
                b"secret\n".to_vec()
            )
            .is_err()
        );
    }

    /// Issue 8: a declared header placement substitutes an operator-named
    /// header (`x-api-key`) and the credential part of
    /// `Authorization: Bearer <placeholder>`, still host-restricted.
    #[test]
    fn a_declared_header_placement_substitutes_named_headers_and_bearer_prefixes() {
        let substitute = |header: Option<Header>, text: &str| -> Option<Vec<u8>> {
            let secret = Arc::new(
                Secret::new(
                    "api".into(),
                    Policy {
                        hosts: vec!["https://fixture.test".into()],
                        allow_plaintext: false,
                        header,
                    },
                    b"fixture-secret".to_vec(),
                )
                .unwrap(),
            );
            let vault = Vault::new("test-attempt", vec![secret]).unwrap();
            let mut request =
                proxy::http::parse_request(text.as_bytes()).expect("a parseable request");
            vault.inject("https", &mut request).ok()?;
            Some(request.forward_head.clone())
        };
        let key = "GET http://fixture.test:443/ HTTP/1.1\r\nHost: fixture.test:443\r\nx-api-key: vault:test-attempt:api\r\n\r\n";
        let head = substitute(
            Some(Header {
                name: "x-api-key".into(),
                prefix: None,
            }),
            key,
        )
        .expect("a declared x-api-key placement substitutes");
        assert!(
            head.windows(b"x-api-key: fixture-secret".len())
                .any(|s| s == b"x-api-key: fixture-secret")
        );
        assert!(!head.windows(6).any(|s| s == b"vault:"));

        let bearer = "GET http://fixture.test:443/ HTTP/1.1\r\nHost: fixture.test:443\r\nAuthorization: Bearer vault:test-attempt:api\r\n\r\n";
        let head = substitute(
            Some(Header {
                name: "authorization".into(),
                prefix: Some("Bearer ".into()),
            }),
            bearer,
        )
        .expect("a declared Bearer prefix substitutes");
        assert!(
            head.windows(b"authorization: Bearer fixture-secret".len())
                .any(|s| s == b"authorization: Bearer fixture-secret")
        );

        // Without the declaration neither placement is eligible.
        assert!(substitute(None, key).is_none());
        assert!(substitute(None, bearer).is_none());
        // A declared name does not accept another header.
        assert!(
            substitute(
                Some(Header {
                    name: "x-api-key".into(),
                    prefix: None,
                }),
                bearer
            )
            .is_none()
        );
        // A declared prefix must match exactly.
        assert!(
            substitute(
                Some(Header {
                    name: "authorization".into(),
                    prefix: Some("Basic ".into()),
                }),
                bearer
            )
            .is_none()
        );
    }

    #[test]
    fn header_declarations_are_validated() {
        let policy = |header: Header| Policy {
            hosts: vec!["https://fixture.test".into()],
            allow_plaintext: false,
            header: Some(header),
        };
        assert!(
            policy(Header {
                name: "X-Api-Key".into(),
                prefix: Some("Bearer ".into()),
            })
            .validate()
            .is_ok()
        );
        assert!(
            policy(Header {
                name: "bad header".into(),
                prefix: None,
            })
            .validate()
            .is_err()
        );
        assert!(
            policy(Header {
                name: "x-api-key".into(),
                prefix: Some("line\nbreak".into()),
            })
            .validate()
            .is_err()
        );
        assert!(
            policy(Header {
                name: "x-api-key".into(),
                prefix: Some(String::new()),
            })
            .validate()
            .is_err()
        );
    }
}
