//! A real, non-root OpenSSH server on a loopback high port, plus the small rig the
//! deployment tests drive it with.
//!
//! These tests use the system `sshd`, `ssh`, `ssh-keygen`, `ssh-keyscan`, `ssh-agent`
//! and `ssh-add` rather than a mock, because what is being tested is precisely the
//! behaviour of the real client: which options it honours, when it refuses a host key,
//! and how it asks for a secret. A mock SSH would prove nothing about any of that.
//!
//! Password authentication cannot be tested this way — an unprivileged `sshd` cannot
//! validate a password — so the password path uses a fake `ssh` shim that invokes
//! `$SSH_ASKPASS` exactly the way OpenSSH does. Every other path is the real client.

#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

pub const OURO: &str = env!("CARGO_BIN_EXE_ouro");

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// A private scratch directory that is removed when the test's rig drops.
///
/// The name is kept short on purpose: a data directory made here holds
/// `fleet/deploy/<operation>.sock`, and a Unix socket path is limited to about a
/// hundred bytes by `sockaddr_un`. macOS's per-user `TMPDIR` is already ~48 of them.
pub fn scratch(label: &str) -> PathBuf {
    let short: String = label.chars().take(6).collect();
    let path = std::env::temp_dir().join(format!(
        "o-{short}-{}-{}",
        std::process::id() % 100_000,
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("a writable scratch directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("a private directory");
    path
}

pub fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a free loopback port");
    listener.local_addr().expect("a bound address").port()
}

pub fn account() -> String {
    let output = Command::new("/usr/bin/id")
        .arg("-un")
        .output()
        .expect("id -un");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// One unprivileged `sshd` serving one authorized key on 127.0.0.1.
pub struct Sshd {
    pub dir: PathBuf,
    pub port: u16,
    pub client_key: PathBuf,
    pub host_key: PathBuf,
    /// The `HOME` the session gets, via `sshd_config`'s `SetEnv`.
    ///
    /// Every test here runs against localhost as the developer's own account, so
    /// without this the missing-binary path would install into their real home
    /// directory. Verified to take effect on OpenSSH 10.3 on this machine.
    pub home: PathBuf,
    child: Option<Child>,
}

impl Sshd {
    /// Start a server whose only authorized key is a fresh unencrypted client key.
    pub fn start(label: &str) -> Self {
        let dir = scratch(label);
        keygen(&dir.join("host_key"), "");
        keygen(&dir.join("client_key"), "");
        authorize(&dir, &[&dir.join("client_key.pub")]);
        Self::boot(dir, label)
    }

    /// A server that authorizes an *encrypted* key, for the passphrase path.
    pub fn start_with_encrypted_key(label: &str, passphrase: &str) -> Self {
        let dir = scratch(label);
        keygen(&dir.join("host_key"), "");
        keygen(&dir.join("client_key"), passphrase);
        authorize(&dir, &[&dir.join("client_key.pub")]);
        Self::boot(dir, label)
    }

    fn boot(dir: PathBuf, label: &str) -> Self {
        Self::boot_with(dir, label, &["host_key"])
    }

    /// Two host keys of different types, so a client that records one can be shown
    /// whether `UpdateHostKeys` rewrites the private store.
    pub fn start_with_two_host_keys(label: &str) -> Self {
        let dir = scratch(label);
        keygen(&dir.join("host_key"), "");
        keygen_type(&dir.join("host_key_rsa"), "rsa", "");
        keygen(&dir.join("client_key"), "");
        authorize(&dir, &[&dir.join("client_key.pub")]);
        Self::boot_with(dir, label, &["host_key", "host_key_rsa"])
    }

    fn boot_with(dir: PathBuf, label: &str, host_keys: &[&str]) -> Self {
        let port = free_port();
        let home = dir.join("home");
        fs::create_dir_all(&home).expect("a fake home");
        let host_key_lines: String = host_keys
            .iter()
            .map(|name| format!("HostKey {}\n", dir.join(name).display()))
            .collect();
        let config = dir.join("sshd_config");
        fs::write(
            &config,
            format!(
                "Port {port}\n\
                 ListenAddress 127.0.0.1\n\
                 {host_key_lines}\
                 AuthorizedKeysFile {authorized}\n\
                 PasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\n\
                 PubkeyAuthentication yes\n\
                 PidFile none\n\
                 UsePAM no\n\
                 StrictModes no\n\
                 SetEnv HOME={home}\n\
                 LogLevel VERBOSE\n",
                authorized = dir.join("authorized_keys").display(),
                home = home.display(),
            ),
        )
        .expect("an sshd config");

        let log = fs::File::create(dir.join("sshd.log")).expect("an sshd log");
        let errors = log.try_clone().expect("a cloned log handle");
        let child = Command::new("/usr/sbin/sshd")
            .arg("-f")
            .arg(&config)
            .arg("-D")
            .arg("-e")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(errors))
            .spawn()
            .unwrap_or_else(|error| panic!("starting sshd for {label}: {error}"));

        let rig = Self {
            client_key: dir.join("client_key"),
            host_key: dir.join("host_key"),
            home,
            dir,
            port,
            child: Some(child),
        };
        rig.await_listening();
        rig
    }

    fn await_listening(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "sshd did not listen on 127.0.0.1:{}; log:\n{}",
            self.port,
            fs::read_to_string(self.dir.join("sshd.log")).unwrap_or_default()
        );
    }

    /// Replace the server's host key and restart it, which is what a reinstalled or
    /// impersonated machine looks like from the client's side.
    pub fn rotate_host_key(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        for suffix in ["", ".pub"] {
            let _ = fs::remove_file(self.dir.join(format!("host_key{suffix}")));
        }
        keygen(&self.dir.join("host_key"), "");
        let log = fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("sshd.log"))
            .expect("the sshd log");
        let errors = log.try_clone().expect("a cloned log handle");
        self.child = Some(
            Command::new("/usr/sbin/sshd")
                .arg("-f")
                .arg(self.dir.join("sshd_config"))
                .arg("-D")
                .arg("-e")
                .stdin(Stdio::null())
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(errors))
                .spawn()
                .expect("restarting sshd"),
        );
        self.await_listening();
    }

    pub fn log(&self) -> String {
        fs::read_to_string(self.dir.join("sshd.log")).unwrap_or_default()
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn keygen(path: &Path, passphrase: &str) {
    let status = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", passphrase, "-f"])
        .arg(path)
        .stdin(Stdio::null())
        .status()
        .expect("ssh-keygen");
    assert!(status.success(), "ssh-keygen failed for {}", path.display());
}

fn keygen_type(path: &Path, algorithm: &str, passphrase: &str) {
    let status = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", algorithm, "-N", passphrase, "-f"])
        .arg(path)
        .stdin(Stdio::null())
        .status()
        .expect("ssh-keygen");
    assert!(
        status.success(),
        "ssh-keygen -t {algorithm} failed for {}",
        path.display()
    );
}

fn authorize(dir: &Path, public_keys: &[&Path]) {
    let mut authorized = String::new();
    for key in public_keys {
        authorized.push_str(&fs::read_to_string(key).expect("a public key"));
    }
    let path = dir.join("authorized_keys");
    fs::write(&path, authorized).expect("authorized_keys");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("a private file");
}

/// A private `ssh-agent`, for the agent-authentication path.
pub struct Agent {
    pub socket: PathBuf,
    dir: PathBuf,
    pid: Option<i32>,
}

impl Agent {
    /// Start an agent and load one key into it.
    pub fn start(label: &str, key: &Path) -> Self {
        let dir = scratch(label);
        let socket = dir.join("agent.sock");
        let output = Command::new("/usr/bin/ssh-agent")
            .arg("-a")
            .arg(&socket)
            .stdin(Stdio::null())
            .output()
            .expect("ssh-agent");
        assert!(
            output.status.success(),
            "ssh-agent failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let pid = text
            .split("SSH_AGENT_PID=")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .and_then(|pid| pid.trim().parse::<i32>().ok());

        let added = Command::new("/usr/bin/ssh-add")
            .arg(key)
            .env("SSH_AUTH_SOCK", &socket)
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_ASKPASS_REQUIRE")
            .stdin(Stdio::null())
            .output()
            .expect("ssh-add");
        assert!(
            added.status.success(),
            "ssh-add failed: {}",
            String::from_utf8_lossy(&added.stderr)
        );

        Self { socket, dir, pid }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            // SAFETY: the pid was printed by the agent this rig started.
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Write an executable shell script.
pub fn write_script(path: &Path, body: &str) {
    let mut file = fs::File::create(path).expect("a script");
    file.write_all(body.as_bytes()).expect("script contents");
    drop(file);
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("an executable script");
}

/// A loopback HTTP server that serves one release: `SHA256SUMS` and one artifact.
///
/// The missing-binary path is not worth having if it is never exercised end to end, and
/// an integration test cannot reach the real release host. The engine's origin override
/// is restricted to loopback, and the checksum check is unchanged.
pub struct ReleaseServer {
    pub base: String,
    handle: Option<std::thread::JoinHandle<()>>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ReleaseServer {
    /// Serve `/v<version>/SHA256SUMS` and `/v<version>/<asset>`.
    pub fn start(version: &str, asset: &str, bytes: Vec<u8>) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let mut sha256 = String::new();
        for byte in digest.as_ref() {
            use std::fmt::Write as _;
            let _ = write!(&mut sha256, "{byte:02x}");
        }
        let manifest = format!("{sha256}  {asset}\n");
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a loopback listener");
        let port = listener.local_addr().expect("an address").port();
        listener.set_nonblocking(true).expect("a pollable listener");
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = std::sync::Arc::clone(&shutdown);
        let routes = vec![
            (format!("/v{version}/SHA256SUMS"), manifest.into_bytes()),
            (format!("/v{version}/{asset}"), bytes),
        ];
        let handle = std::thread::spawn(move || serve_http(listener, routes, stop));
        Self {
            base: format!("http://127.0.0.1:{port}"),
            handle: Some(handle),
            shutdown,
        }
    }

    pub fn sha256_of(bytes: &[u8]) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
        let mut text = String::new();
        for byte in digest.as_ref() {
            use std::fmt::Write as _;
            let _ = write!(&mut text, "{byte:02x}");
        }
        text
    }
}

impl Drop for ReleaseServer {
    fn drop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve_http(
    listener: TcpListener,
    routes: Vec<(String, Vec<u8>)>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let routes = std::sync::Arc::new(routes);
    let mut workers = Vec::new();
    while !shutdown.load(std::sync::atomic::Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let routes = std::sync::Arc::clone(&routes);
                workers.push(std::thread::spawn(move || answer(stream, &routes)));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
}

fn answer(mut stream: std::net::TcpStream, routes: &[(String, Vec<u8>)]) {
    use std::io::{BufRead, BufReader};

    // An accepted socket inherits the listener's non-blocking mode on macOS, and a
    // non-blocking `write_all` of a multi-megabyte body returns EAGAIN the moment the
    // send buffer fills — which the client sees as a truncated transfer.
    stream
        .set_nonblocking(false)
        .expect("a blocking connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a bounded read");
    stream
        .set_write_timeout(Some(Duration::from_secs(60)))
        .expect("a bounded write");
    let mut reader = BufReader::new(stream.try_clone().expect("a cloned stream"));
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() {
        return;
    }
    let head = request.starts_with("HEAD ");
    let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line.trim().is_empty() => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    let body = routes
        .iter()
        .find(|(route, _)| *route == path)
        .map(|(_, body)| body.clone());
    let (status, body) = match body {
        Some(body) => ("200 OK", body),
        None => ("404 Not Found", Vec::new()),
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if let Err(error) = stream.write_all(header.as_bytes()) {
        eprintln!("release server: header write failed: {error}");
        return;
    }
    if !head {
        if let Err(error) = stream.write_all(&body) {
            eprintln!("release server: body write failed: {error}");
            return;
        }
    }
    let _ = stream.flush();
    // Half-close so the client sees a complete body rather than a reset, then let it
    // finish before the socket goes away.
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut drain = [0_u8; 1024];
    use std::io::Read as _;
    let _ = stream.read(&mut drain);
}

/// A wrapper around the built `ouro` that intercepts `stop --require-idle`.
///
/// Leave talks to the helper through this same path, so every other verb still reaches
/// the real binary; only the idle-gated stop is scripted.
pub fn stop_intercept_shim(dir: &Path, real: &Path, exit: i32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("stop-shim");
    let body = format!(
        "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \"--require-idle\" ]; then\n    echo intercept >&2\n    exit {exit}\n  fi\ndone\nexec {} \"$@\"\n",
        real.display()
    );
    fs::write(&path, body).expect("a stop intercept shim");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("an executable shim");
    path
}
