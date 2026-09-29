//! Attempt-scoped HTTP credentials. Secrets and CA private keys stay in memory.
use crate::network::{Destination, parse_authority};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub hosts: Vec<String>,
    #[serde(default)]
    pub allow_plaintext: bool,
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
        Ok(())
    }
    fn permits(&self, scheme: &str, destination: &Destination) -> bool {
        self.hosts
            .iter()
            .any(|h| origin(h).is_ok_and(|(s, d)| s == scheme && d == *destination))
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
    /// Only the complete Authorization value is eligible. Other placements of
    /// the marker are refused, never rewritten and never logged.
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
            if !line[..colon].eq_ignore_ascii_case(b"authorization") {
                return Err(Reason::OriginUnverified);
            }
            let value = line[colon + 1..].trim_ascii();
            let secret = self
                .secrets
                .iter()
                .find(|s| self.placeholder(s).as_bytes() == value)
                .ok_or(Reason::OriginUnverified)?;
            if !secret.policy.permits(scheme, &request.destination) {
                return Err(Reason::OriginMismatch);
            }
            out.extend_from_slice(b"Authorization: ");
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
        matching_host: bool,
        authorized: bool,
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
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
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
        write!(
            child,
            "GET / HTTP/1.1\r\nHost: {}:{port}\r\nAuthorization: vault:test-attempt:api\r\n\r\n",
            if matching_host {
                "fixture.test"
            } else {
                "other.test"
            }
        )
        .unwrap();
        child.flush().unwrap();
        let mut response = Vec::new();
        let _ = child.read_to_end(&mut response);
        let event = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(proxy.stop(Duration::from_secs(10)).complete());
        (event, server.join().unwrap(), response)
    }
    #[test]
    fn tls_vault_substitutes_only_after_both_authorities_and_the_certificate_pass() {
        let (event, upstream, response) = run_tls(true, true, true);
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
            let (event, upstream, _) = run_tls(case.0, case.1, case.2);
            assert_ne!(event.reason, Reason::Relayed);
            assert!(
                upstream.is_empty(),
                "no HTTP credential bytes may reach an unverified destination"
            );
        }
    }
    #[test]
    fn plaintext_is_opt_in_and_substitution_is_exact() {
        assert!(
            Policy {
                hosts: vec!["http://fixture.test".into()],
                allow_plaintext: false
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
                    allow_plaintext: false
                },
                b"secret\n".to_vec()
            )
            .is_err()
        );
    }
}
