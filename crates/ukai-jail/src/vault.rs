//! Attempt-scoped HTTP credentials. Secrets and CA private keys stay in memory.
use crate::network::{Destination, Host, parse_authority};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(crate) mod lifecycle;
pub(crate) mod origin;
pub(crate) use lifecycle::RefreshPolicy;

#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
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
    /// Exact paths or segment prefixes ending in `/`; empty permits any path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Absolute executable paths, checked against kernel connection origins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub binaries: Vec<String>,
    /// Optional supervisor-owned OAuth2 refresh; source becomes a token document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<RefreshPolicy>,
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
    pub(crate) fn validate(&self) -> Result<(), String> {
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
        if self.paths.len() > 64 || self.binaries.len() > 64 {
            return Err("vault path/binary binding has at most 64 entries".into());
        }
        for path in &self.paths {
            validate_path(path)?;
        }
        for binary in &self.binaries {
            if !binary.starts_with('/') || binary.contains('\0') || binary.len() > 4096 {
                return Err("vault binaries must be absolute executable paths".into());
            }
        }
        if let Some(refresh) = &self.refresh {
            refresh.validate(self.allow_plaintext)?;
        }
        Ok(())
    }
    fn permits(&self, scheme: &str, destination: &Destination) -> bool {
        self.hosts
            .iter()
            .any(|h| origin(h).is_ok_and(|(s, d)| s == scheme && d == *destination))
    }
}

fn validate_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/')
        || path.contains("//")
        || path.len() > 4096
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
        || path.split('/').any(|s| s == "." || s == "..")
    {
        return Err("vault paths need unescaped absolute paths without dot segments".into());
    }
    Ok(())
}
impl Header {
    /// An RFC 9110 token name and a printable, line-ending-free prefix.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.name.len() > 64 || !crate::proxy::http::is_token(self.name.as_bytes()) {
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

/// The longest credential value: it must fit one header line.
pub(crate) const VALUE_MAX: usize = 8192;
/// The largest vault source read: a raw key or a refresh token document.
pub(crate) const SOURCE_MAX: usize = 64 * 1024;

/// Whether `value` can be a credential: 1..=[`VALUE_MAX`] printable ASCII
/// bytes, so no line ending.
pub(crate) fn valid_value(value: &[u8]) -> bool {
    !value.is_empty() && value.len() <= VALUE_MAX && value.iter().all(|b| matches!(b, 0x20..=0x7e))
}

/// Pins every executable the policy binds its credential to.
fn executables(policy: &Policy) -> Result<Vec<origin::Executable>, String> {
    policy
        .binaries
        .iter()
        .map(|path| origin::Executable::pin(path))
        .collect()
}

/// The variable that carries a vault credential's placeholder into the
/// child: `UKAI_VAULT_` and the id in upper case with `.` and `-` as `_`.
/// Launch-profile validation refuses two ids that map to one name.
pub(crate) fn env_name(id: &str) -> String {
    format!(
        "UKAI_VAULT_{}",
        id.to_ascii_uppercase().replace(['.', '-'], "_")
    )
}

pub struct Secret {
    pub(crate) id: String,
    pub(crate) policy: Policy,
    runtime: lifecycle::Runtime,
    executables: Vec<origin::Executable>,
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSecret")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
impl Secret {
    /// A secret whose value is fixed for the attempt, for tests: staging
    /// always reads a live source ([`Secret::from_source`]).
    #[cfg(test)]
    pub(crate) fn new(id: String, policy: Policy, bytes: Vec<u8>) -> Result<Self, String> {
        let value = Zeroizing::new(bytes);
        if !valid_value(&value) {
            return Err(format!(
                "vault value must be 1..{VALUE_MAX} printable ASCII bytes without line endings"
            ));
        }
        policy.validate()?;
        if policy.refresh.is_some() {
            return Err("refresh requires a source-backed secret".into());
        }
        let runtime = lifecycle::Runtime::static_value(value);
        let executables = executables(&policy)?;
        Ok(Self {
            id,
            policy,
            runtime,
            executables,
        })
    }

    pub(crate) fn from_source(
        id: String,
        policy: Policy,
        path: Vec<u8>,
        forbidden: Vec<(u64, u64)>,
    ) -> Result<Self, String> {
        policy.validate()?;
        let executables = executables(&policy)?;
        let runtime = lifecycle::Runtime::source(path, forbidden, policy.refresh.clone())?;
        Ok(Self {
            id,
            policy,
            runtime,
            executables,
        })
    }
}

pub struct Vault {
    attempt: String,
    secrets: Vec<Arc<Secret>>,
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    client: Arc<rustls::ClientConfig>,
    pub(crate) origins: Arc<origin::Origins>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    monitor: lifecycle::Monitor,
}
impl Vault {
    // Only the Linux `agent` boundary starts a vault and binds its CA, so
    // elsewhere these three serve the unit tests alone.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn new(attempt: &str, secrets: Vec<Arc<Secret>>) -> Result<Self, String> {
        let mut params = rcgen::CertificateParams::new(vec![]).map_err(|e| e.to_string())?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("Ukai attempt {attempt}"));
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
        let monitor = lifecycle::Monitor::new(secrets.clone());
        Ok(Self {
            attempt: attempt.into(),
            secrets,
            ca,
            client: Arc::new(client),
            origins: Arc::new(origin::Origins::default()),
            monitor,
        })
    }
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn start_monitor(&self, audit: lifecycle::Audit) -> Result<(), String> {
        self.monitor.start(audit)
    }
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn has_process_bindings(&self) -> bool {
        self.secrets
            .iter()
            .any(|secret| !secret.policy.binaries.is_empty())
    }
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn details(&self) -> serde_json::Value {
        serde_json::json!({
            "source_lifecycle":"private_nofollow_live_file",
            "lease_poll_ms":lifecycle::LEASE_POLL_MS,
            "process_binding":"kernel_connection_initiator_executable",
            "peer_authority":"mediator_connect_for_pinned_sealed_bridge",
            "path_binding":"exact_or_unescaped_segment_prefix",
            "tls_websocket":"verified_rfc6455_upgrade",
            "refresh":"bounded_oauth2_persist_before_publish_no_uncertain_retry",
            "refresh_credentials":self.secrets.iter().filter(|s|s.policy.refresh.is_some()).count(),
            "process_bound_credentials":self.secrets.iter().filter(|s|!s.policy.binaries.is_empty()).count(),
            "path_bound_credentials":self.secrets.iter().filter(|s|!s.policy.paths.is_empty()).count(),
        })
    }
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn ca_pem(&self) -> String {
        self.ca.pem()
    }
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn environment(&self) -> Vec<(String, String)> {
        self.secrets
            .iter()
            .map(|s| (env_name(&s.id), self.placeholder(s)))
            .collect()
    }
    fn placeholder(&self, secret: &Secret) -> String {
        format!("vault:{}:{}", self.attempt, secret.id)
    }
    /// Substitutes the request's placeholders for a connection `initiator`
    /// started. A placeholder is eligible exactly where its secret declares:
    /// the header name matches (case-insensitively) and the value is the
    /// declared prefix followed by the placeholder and nothing else. The
    /// default declaration is the complete `Authorization` value. Other
    /// placements of the marker are refused, never rewritten and never
    /// logged.
    pub(crate) fn inject_bound(
        &self,
        scheme: &str,
        request: &mut crate::proxy::http::Request,
        initiator: &origin::Initiator,
    ) -> Result<lifecycle::Lease, crate::proxy::Reason> {
        use crate::proxy::Reason;
        let mut out = Zeroizing::new(Vec::with_capacity(request.forward_head.len() + VALUE_MAX));
        let mut lease = lifecycle::Lease::default();
        lease.bind(initiator);
        for line in crate::proxy::http::lines(&request.forward_head) {
            if !line.0.windows(6).any(|s| s == b"vault:") {
                out.extend_from_slice(line.0);
                continue;
            }
            let (name, value) = line.field().ok_or(Reason::CredentialPlacementDenied)?;
            let value = value.trim_ascii();
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
                return Err(Reason::CredentialPlacementDenied);
            };
            if !secret.policy.permits(scheme, &request.destination) {
                return Err(Reason::OriginMismatch);
            }
            if !secret.policy.paths.is_empty() {
                // A path the binding grammar cannot express is one no
                // binding grants.
                let path = request.path().ok_or(Reason::CredentialPathDenied)?;
                validate_path(path).map_err(|_| Reason::CredentialPathDenied)?;
                if !secret.policy.paths.iter().any(|allowed| {
                    path == allowed || allowed.ends_with('/') && path.starts_with(allowed)
                }) {
                    return Err(Reason::CredentialPathDenied);
                }
            }
            if !secret.policy.binaries.is_empty() {
                initiator.check(&secret.executables)?;
            }
            let (value, generation) = secret.runtime.current()?;
            lease.add(Arc::clone(secret), generation);
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
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        lease.check()?;
        request.forward_head = out.to_vec();
        Ok(lease)
    }
    pub(crate) fn server(
        &self,
        destination: &Destination,
    ) -> Result<rustls::ServerConnection, crate::proxy::Reason> {
        use crate::proxy::Reason;
        let key = rcgen::KeyPair::generate().map_err(|_| Reason::InternalError)?;
        // An IP literal must be an IP SAN: `Host`'s URI display brackets
        // IPv6, and neither rcgen's DNS names nor rustls's `ServerName`
        // accept the brackets, so a bracketed literal fails before any byte
        // is exchanged.
        let params = match &destination.host {
            Host::Name(name) => rcgen::CertificateParams::new(vec![name.clone()])
                .map_err(|_| Reason::InternalError)?,
            Host::Ip(ip) => {
                let mut ip_params =
                    rcgen::CertificateParams::new(Vec::new()).map_err(|_| Reason::InternalError)?;
                ip_params.subject_alt_names = vec![rcgen::SanType::IpAddress(*ip)];
                ip_params
            }
        };
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
    /// The origin name a lane verifies the upstream certificate against.
    /// IP literals stay IP names: `Host`'s URI display brackets IPv6, and
    /// the bracketed form is not a valid `ServerName`.
    fn server_name(
        host: &Host,
    ) -> Result<rustls::pki_types::ServerName<'static>, rustls::pki_types::InvalidDnsNameError>
    {
        match host {
            Host::Name(name) => {
                rustls::pki_types::ServerName::try_from(name.clone()).map(|name| name.to_owned())
            }
            Host::Ip(ip) => Ok(rustls::pki_types::ServerName::from(*ip)),
        }
    }

    pub(crate) fn client(
        &self,
        destination: &Destination,
    ) -> Result<rustls::ClientConnection, crate::proxy::Reason> {
        let name = Self::server_name(&destination.host)
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
    use std::time::{Duration, Instant};

    use crate::platform::linux::bridge::HTTP_PORT;

    struct Sink(Mutex<mpsc::Sender<ProxyResult>>);
    impl ProxySink for Sink {
        fn emit(&self, result: ProxyResult) {
            let _ = self.0.lock().unwrap().send(result);
        }
    }
    /// A policy for `hosts`, plaintext allowed exactly when one is `http://`.
    fn policy(hosts: &[&str]) -> Policy {
        Policy {
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            allow_plaintext: hosts.iter().any(|host| host.starts_with("http://")),
            ..Policy::default()
        }
    }
    /// The vault of one secret `api` with `policy` and `value`.
    fn vault_of(policy: Policy, value: &[u8]) -> Vault {
        let secret = Secret::new("api".into(), policy, value.to_vec()).unwrap();
        Vault::new("test-attempt", vec![Arc::new(secret)]).unwrap()
    }
    /// Substitutes as the proxy does for a connection with no process
    /// authority.
    fn inject(
        vault: &Vault,
        scheme: &str,
        request: &mut proxy::http::Request,
    ) -> Result<lifecycle::Lease, Reason> {
        vault.inject_bound(scheme, request, &origin::Initiator::default())
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
    /// One request through a vault proxy's TLS lane to a local upstream:
    /// `trusted` says whether the vault trusts the upstream's certificate,
    /// `authorized` whether the secret is bound to the upstream's host.
    fn run_tls(
        trusted: bool,
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
                if bytes
                    .windows(b"Upgrade: websocket".len())
                    .any(|v| v == b"Upgrade: websocket")
                {
                    stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").unwrap();
                    stream.flush().unwrap();
                    let mut frame = [0u8; 8];
                    stream.read_exact(&mut frame).unwrap();
                    assert_eq!(frame, [0x81, 0x82, b'a', b'b', b'c', b'd', 9, 11]);
                    stream.write_all(&[0x81, 2, b'h', b'i']).unwrap();
                } else {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nOK")
                        .unwrap();
                    if bytes.windows(6).any(|v| v == b"/large") {
                        stream.write_all(&vec![b'x'; 70000]).unwrap();
                    }
                }
                stream.conn.send_close_notify();
                stream.flush().unwrap();
            }
            bytes
        });
        let host = if authorized {
            "fixture.test"
        } else {
            "other.test"
        };
        let mut vault = vault_of(
            policy(&[&format!("https://{host}:{port}")]),
            b"Bearer fixture-secret",
        );
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
        // This test stands in for the sealed bridge, which writes the
        // connection's origin preamble first.
        socket
            .write_all(&origin::preamble_for(
                ([127, 0, 0, 1], 40000).into(),
                HTTP_PORT,
            ))
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
        let (event, upstream, response) = run_tls(true, true, authorized_get(true), b"", true);
        assert_eq!(event.reason, Reason::Relayed);
        assert_eq!(
            event.origin_verification,
            Some(proxy::Verification::MitmHttpHost)
        );
        assert!(
            upstream
                .windows(b"Bearer fixture-secret".len())
                .any(|s| s == b"Bearer fixture-secret")
        );
        assert!(!upstream.windows(6).any(|s| s == b"vault:"));
        assert!(response.ends_with(b"OK"));
        for (trusted, matching_host, authorized, reason) in [
            // An untrusted upstream certificate fails the handshake.
            (false, true, true, Reason::UpstreamProtocol),
            (true, false, true, Reason::OriginMismatch),
            (true, true, false, Reason::OriginMismatch),
        ] {
            let (event, upstream, _) = run_tls(
                trusted,
                authorized,
                authorized_get(matching_host),
                b"",
                false,
            );
            assert_eq!(
                event.reason, reason,
                "{trusted} {matching_host} {authorized}"
            );
            assert!(
                upstream.is_empty(),
                "no HTTP credential bytes may reach an unverified destination"
            );
        }
    }
    #[test]
    fn tls_vault_relays_a_verified_websocket_in_both_directions() {
        let (event, upstream, response) = run_tls(
            true,
            true,
            |port| {
                format!(
                    "GET /ws HTTP/1.1\r\nHost: fixture.test:{port}\r\nAuthorization: vault:test-attempt:api\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
                )
            },
            &[0x81, 0x82, b'a', b'b', b'c', b'd', 9, 11],
            true,
        );
        assert_eq!(event.reason, Reason::Relayed);
        assert_eq!(event.discarded_bytes, 0);
        assert!(response.starts_with(b"HTTP/1.1 101 "));
        assert!(response.ends_with(&[0x81, 2, b'h', b'i']));
        assert!(upstream.windows(14).any(|v| v == b"fixture-secret"));
    }
    #[test]
    fn tls_vault_drains_large_plaintext_before_the_upstream_close_notify() {
        let (event, _, response) = run_tls(
            true,
            true,
            |port| {
                format!(
                    "GET /large HTTP/1.1\r\nHost: fixture.test:{port}\r\nAuthorization: vault:test-attempt:api\r\n\r\n"
                )
            },
            b"",
            true,
        );
        assert_eq!(event.reason, Reason::Relayed);
        assert!(
            response.ends_with(&vec![b'x'; 70000]),
            "bytes={} event_in={} end={:?}",
            response.len(),
            event.bytes_in,
            event.end
        );
        assert_eq!(event.bytes_in, response.len() as u64);
    }
    #[test]
    fn tls_vault_closes_the_response_and_counts_discarded_pipeline_bytes() {
        let pipeline = b"GET /second HTTP/1.1\r\nHost: fixture.test\r\n\r\n";
        let (event, upstream, response) = run_tls(true, true, authorized_get(true), pipeline, true);
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
        let vault = vault_of(policy(&["https://fixture.test"]), b"Bearer fixture-secret");
        let flight = || {
            proxy::http::parse_request(
                b"GET http://fixture.test:443/ HTTP/1.1\r\nHost: fixture.test:443\r\nAuthorization: vault:test-attempt:api\r\n\r\n",
            )
            .unwrap()
        };
        inject(&vault, "http", &mut flight())
            .expect_err("a plaintext origin must not receive an https-bound secret");
        let mut secure = flight();
        inject(&vault, "https", &mut secure).expect("the bound https origin substitutes");
        assert!(
            secure
                .forward_head
                .windows(b"Bearer fixture-secret".len())
                .any(|s| s == b"Bearer fixture-secret")
        );
        // Positive control: the allow_plaintext opt-in substitutes over http
        // (default port 80 here, matching the secret's own binding).
        let plain_vault = vault_of(policy(&["http://fixture.test"]), b"Bearer fixture-secret");
        let mut default_port = proxy::http::parse_request(
            b"GET http://fixture.test/ HTTP/1.1\r\nHost: fixture.test\r\nAuthorization: vault:test-attempt:api\r\n\r\n",
        )
        .unwrap();
        inject(&plain_vault, "http", &mut default_port)
            .expect("the allow_plaintext opt-in substitutes");
    }
    /// A vault proxy reads the bridge's preamble first: a connection that
    /// closes before it is no request, not a process denial.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_vault_connection_closed_before_its_preamble_is_no_request() {
        let vault = vault_of(policy(&["https://fixture.test"]), b"fixture-secret");
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("proxy.sock");
        let (sender, receiver) = mpsc::channel();
        let proxy = proxy::start_with_vault(
            ProxyConfig {
                listener: UnixListener::bind(&path).unwrap(),
                rules: Rules::from_strings(&["fixture.test:443".to_owned()], &[]).unwrap(),
                budgets: Budgets::default(),
                resolver: Arc::new(FixtureResolver::new()),
            },
            Arc::new(Sink(Mutex::new(sender))),
            Some(Arc::new(vault)),
        )
        .unwrap();
        drop(UnixStream::connect(&path).unwrap());
        // A second connection, accepted after the first, settles with a
        // result; once neither is active both have settled.
        let mut refused = UnixStream::connect(&path).unwrap();
        refused
            .write_all(&origin::preamble_for(
                ([127, 0, 0, 1], 40000).into(),
                HTTP_PORT,
            ))
            .unwrap();
        refused
            .write_all(b"CONNECT other.test:443 HTTP/1.1\r\nHost: other.test:443\r\n\r\n")
            .unwrap();
        let result = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(result.reason, Reason::HostNotAllowed);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while proxy.active_connections() != 0 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        let summary = proxy.stop(Duration::from_secs(10));
        assert_eq!((summary.accepted, summary.results_emitted), (2, 1));
        assert_eq!(summary.without_request, 1);
        assert!(summary.complete());
    }
    #[test]
    fn a_placeholder_outside_authorization_is_refused_never_rewritten() {
        let vault = vault_of(policy(&["http://fixture.test"]), b"Bearer fixture-secret");
        let mut request = proxy::http::parse_request(
            b"POST http://fixture.test/ HTTP/1.1\r\nHost: fixture.test\r\nX-Api-Key: vault:test-attempt:api\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        let error = inject(&vault, "http", &mut request)
            .expect_err("a marker outside Authorization must refuse");
        assert_eq!(error, Reason::CredentialPlacementDenied);
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
    #[test]
    fn a_misplaced_placeholder_or_an_unbindable_path_is_named_for_what_it_is() {
        let placed = |paths: Vec<String>, text: &[u8]| {
            let vault = vault_of(
                Policy {
                    paths,
                    ..policy(&["http://fixture.test"])
                },
                b"fixture-secret",
            );
            let mut request = proxy::http::parse_request(text).unwrap();
            inject(&vault, "http", &mut request).map(|_| ())
        };
        // A placeholder in the request line is no declared placement.
        assert_eq!(
            placed(
                Vec::new(),
                b"GET http://fixture.test/vault:test-attempt:api HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
            ),
            Err(Reason::CredentialPlacementDenied)
        );
        // A path the binding grammar cannot express is not granted.
        let request = b"GET http://fixture.test/v1/%2e%2e/admin HTTP/1.1\r\nHost: fixture.test\r\nAuthorization: vault:test-attempt:api\r\n\r\n";
        assert_eq!(
            placed(vec!["/v1/".into()], request),
            Err(Reason::CredentialPathDenied)
        );
        assert_eq!(placed(Vec::new(), request), Ok(()));
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
                allow_plaintext: false,
                ..policy(&["http://fixture.test"])
            }
            .validate()
            .is_err()
        );
        let vault = vault_of(policy(&["http://fixture.test"]), b"Bearer fixture-secret");
        for (host, value, ok) in [
            ("fixture.test", "vault:test-attempt:api", true),
            ("other.test", "vault:test-attempt:api", false),
            ("fixture.test", "Bearer vault:test-attempt:api", false),
        ] {
            let text = format!(
                "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nAuthorization: {value}\r\n\r\n"
            );
            let mut request = proxy::http::parse_request(text.as_bytes()).unwrap();
            assert_eq!(inject(&vault, "http", &mut request).is_ok(), ok);
        }
        assert!(
            Secret::new(
                "api".into(),
                policy(&["https://fixture.test"]),
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
            let vault = vault_of(
                Policy {
                    header,
                    ..policy(&["https://fixture.test"])
                },
                b"fixture-secret",
            );
            let mut request =
                proxy::http::parse_request(text.as_bytes()).expect("a parseable request");
            inject(&vault, "https", &mut request).ok()?;
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
            ..Policy::default()
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

    /// Drives a full handshake between the vault's terminated server side
    /// and its re-originated client side over loopback sockets, so the
    /// certificate is verified exactly as a lane would verify it. A
    /// destination that is an IP literal only passes when the certificate
    /// carries that address as an IP SAN and the client presented
    /// `ServerName::Ip`, not the bracketed URI form.
    fn handshakes_for(host: Host) -> bool {
        let vault = Vault::new("test-attempt", Vec::new()).unwrap();
        let destination = Destination {
            host: host.clone(),
            port: 443,
        };
        let mut server = vault.server(&destination).unwrap();
        let mut client = rustls::ClientConnection::new(
            roots(vault.ca.der().clone()),
            Vault::server_name(&host).unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client_end = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut server_end = listener.accept().unwrap().0;
        // Nonblocking with a small spin: `complete_io` on blocking sockets
        // can park both ends waiting on each other forever.
        client_end.set_nonblocking(true).unwrap();
        server_end.set_nonblocking(true).unwrap();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if !client.is_handshaking() && !server.is_handshaking() {
                return true;
            }
            let _ = client.complete_io(&mut client_end);
            let _ = server.complete_io(&mut server_end);
            std::thread::sleep(Duration::from_millis(5));
        }
        !client.is_handshaking() && !server.is_handshaking()
    }

    #[test]
    fn ip_literals_become_ip_server_names_and_names_stay_dns() {
        assert!(matches!(
            Vault::server_name(&Host::Ip("2001:db8::1".parse().unwrap())).unwrap(),
            rustls::pki_types::ServerName::IpAddress(_)
        ));
        assert!(matches!(
            Vault::server_name(&Host::Name("fixture.test".into())).unwrap(),
            rustls::pki_types::ServerName::DnsName(_)
        ));
    }

    #[test]
    fn an_ipv6_literal_destination_gets_an_ip_san_not_a_bracketed_name() {
        assert!(handshakes_for(Host::Ip("2001:db8::1".parse().unwrap())));
    }

    #[test]
    fn an_ipv4_literal_destination_gets_an_ip_san() {
        assert!(handshakes_for(Host::Ip("127.0.0.1".parse().unwrap())));
    }

    #[test]
    fn a_dns_named_destination_verifies_unchanged() {
        assert!(handshakes_for(Host::Name("fixture.test".into())));
    }
}
