//! Every `ssh` this product runs, and the one option set that makes running one safe.
//!
//! Seam S7. The proposal's reasoning is that a deployment host's `~/.ssh/config` is the
//! operator's, not this command's: it may forward an agent, multiplex onto an unrelated
//! connection, run a `LocalCommand`, or route through a jump host. Any of those would
//! quietly change *which machine* the credentials this operation is about to mint are
//! delivered to. So every invocation is built from the normalized set below, and before
//! the first connection `ssh -G` is inspected to confirm that what OpenSSH will actually
//! do matches what was reviewed.
//!
//! What is never done, in any code path: `StrictHostKeyChecking` is never relaxed, an
//! agent is never forwarded, a private key is never copied or read by this process, and
//! a secret never reaches argv or the environment — passwords and passphrases travel
//! only over [`super::askpass`].

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use super::askpass::{Armed, Bridge};
use super::{refuse, sanitize_remote_text, IdentityChoice};

/// Seam S7's connect bound.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// The default ceiling on one remote command. The bootstrap upload raises it.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

/// Where the operation is going. The address is the *selected overlay IPv4*, which is
/// the only thing this path will connect to; a peer's reported hostname is display
/// information and never an identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Destination {
    pub address: String,
    pub port: u16,
    pub user: String,
}

impl Destination {
    pub fn label(&self) -> String {
        format!("{}@{} port {}", self.user, self.address, self.port)
    }
}

/// An identity after it has been located and validated on this host.
#[derive(Clone, Debug)]
pub enum ResolvedIdentity {
    /// No `-i`: OpenSSH's own default identity files, still with `IdentitiesOnly=yes`.
    Default,
    /// One agent identity, pinned by writing its *public* key to a private file. The
    /// agent still holds the private half; nothing is exported.
    Agent {
        public_key_file: PathBuf,
        label: String,
        fingerprint: String,
    },
    /// A private key file this host already holds, named explicitly by the operator.
    Key {
        path: PathBuf,
        label: String,
        fingerprint: Option<String>,
    },
    /// The target account's password, for this operation only.
    Password,
}

impl ResolvedIdentity {
    pub fn describe(&self) -> String {
        match self {
            Self::Default => "the deployment host's default SSH identities".to_string(),
            Self::Agent {
                label, fingerprint, ..
            } => format!("agent identity {label} ({fingerprint})"),
            Self::Key {
                label, fingerprint, ..
            } => match fingerprint {
                Some(fingerprint) => format!("key {label} ({fingerprint})"),
                None => format!("key {label}"),
            },
            Self::Password => "the target account's password".to_string(),
        }
    }

    fn needs_agent(&self) -> bool {
        matches!(self, Self::Agent { .. } | Self::Default)
    }
}

/// One identity a running agent holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentIdentity {
    pub algorithm: String,
    pub blob: String,
    pub comment: String,
    pub fingerprint: String,
}

/// The programs this module runs. Overridable so a test can put a shim in front of
/// `ssh` without changing what production does.
#[derive(Clone, Debug)]
pub struct Programs {
    pub ssh: PathBuf,
    pub ssh_add: PathBuf,
    pub keygen: PathBuf,
    /// This executable, which OpenSSH runs as `SSH_ASKPASS`.
    pub askpass: PathBuf,
    /// An explicit agent socket. `None` inherits whatever `SSH_AUTH_SOCK` this process
    /// was started with, which is the production case: a deployment uses the deployment
    /// host's own agent, and a service session that has none is reported as having none.
    pub agent_socket: Option<PathBuf>,
}

impl Default for Programs {
    fn default() -> Self {
        Self {
            ssh: PathBuf::from("ssh"),
            ssh_add: PathBuf::from("ssh-add"),
            keygen: PathBuf::from("ssh-keygen"),
            askpass: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("ouro")),
            agent_socket: None,
        }
    }
}

impl Programs {
    fn apply_agent(&self, command: &mut Command) {
        if let Some(socket) = &self.agent_socket {
            command.env("SSH_AUTH_SOCK", socket);
        }
    }
}

/// A configured `ssh` for one destination.
pub struct Runner {
    pub programs: Programs,
    pub destination: Destination,
    pub identity: ResolvedIdentity,
    /// The private deployment-host stores, in the order OpenSSH reads them. The first is
    /// the one an explicit acceptance is written to; the rest are read-only.
    pub known_hosts: Vec<PathBuf>,
    /// The operator's own file, honoured but never written.
    pub user_known_hosts: Option<PathBuf>,
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    pub bridge: Option<Arc<Bridge>>,
}

/// One bounded remote command's result.
#[derive(Clone, Debug)]
pub struct Completed {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Completed {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Remote stderr, sanitized for a person. Never printed raw: it is remote output.
    pub fn stderr_text(&self) -> String {
        sanitize_remote_text(&String::from_utf8_lossy(&self.stderr), 300)
    }

    /// Whether the remote shell said the executable is not there. `127` is the POSIX
    /// shell's own "command not found", and OpenSSH passes the remote exit code through.
    pub fn command_not_found(&self) -> bool {
        if self.code == Some(127) {
            return true;
        }
        let text = String::from_utf8_lossy(&self.stderr).to_ascii_lowercase();
        text.contains("command not found") || text.contains("no such file or directory")
    }
}

/// The options that decide what a host key means and who answers for one, set to their
/// inert values on every invocation.
///
/// `ssh -G` reports each of these, so [`Runner::inspect_effective_config`] can assert
/// afterwards that what this command line set is what is actually in force.
pub const NEUTRALIZED_OPTIONS: &[&str] = &[
    "KnownHostsCommand=none",
    "GlobalKnownHostsFile=/dev/null",
    "RevokedHostKeys=none",
    "CertificateFile=none",
    "PKCS11Provider=none",
];

/// The `ssh -G` keys whose effective value this client insists on, and the value it
/// insists on. An `ssh -G` that reports anything else means the command line did not
/// win, and the connection is refused rather than made.
const REQUIRED_EFFECTIVE: &[(&str, &str)] = &[
    ("knownhostscommand", "none"),
    ("globalknownhostsfile", "/dev/null"),
    ("revokedhostkeys", "none"),
    ("certificatefile", "none"),
    ("pkcs11provider", "none"),
    ("stricthostkeychecking", "true"),
    ("controlmaster", "false"),
    ("forwardagent", "no"),
];

/// Quote one value for `ssh -o`, whose parser splits on whitespace unless quoted.
pub fn quote_option_value(value: &str) -> String {
    // OpenSSH's tokenizer understands double quotes and has no escape inside them, so a
    // value containing one cannot be expressed. That is a refusal the caller makes, not
    // something to paper over here.
    format!("\"{value}\"")
}

impl Runner {
    /// The normalized option set, exactly as seam S7 states it.
    ///
    /// Kept as a function rather than inlined so a test can assert the list and a report
    /// can print it: this is a security boundary, and "which options did we actually
    /// pass" must be answerable without reading a process table.
    pub fn options(&self) -> Vec<String> {
        let mut known_hosts = String::new();
        for store in self.known_hosts.iter().chain(self.user_known_hosts.iter()) {
            if !known_hosts.is_empty() {
                known_hosts.push(' ');
            }
            // Quoted, because `ssh` tokenizes this value on whitespace: a data directory
            // or a `$HOME` with a space in it (`~/Library/Application Support/…` is the
            // ordinary macOS case) would otherwise become two paths that do not exist,
            // and the private trust store would be silently empty forever.
            known_hosts.push_str(&quote_option_value(&store.display().to_string()));
        }
        let mut options = vec![
            "ForwardAgent=no".to_string(),
            "ForwardX11=no".to_string(),
            "ClearAllForwardings=yes".to_string(),
            "PermitLocalCommand=no".to_string(),
            "LocalCommand=none".to_string(),
            "RemoteCommand=none".to_string(),
            "RequestTTY=no".to_string(),
            "ControlMaster=no".to_string(),
            "ControlPath=none".to_string(),
            "StrictHostKeyChecking=yes".to_string(),
            format!("UserKnownHostsFile={known_hosts}"),
            "IdentitiesOnly=yes".to_string(),
            "NumberOfPasswordPrompts=1".to_string(),
            format!("ConnectTimeout={}", self.connect_timeout.as_secs()),
            "ServerAliveInterval=15".to_string(),
            // The askpass bridge is how a prompt is answered; BatchMode=yes would turn
            // every prompt into an immediate failure instead.
            "BatchMode=no".to_string(),
        ];
        // Neutralising the options that decide *what a host key means* and *who answers
        // for a key*. `UserKnownHostsFile` alone is not the trust boundary: an operator's
        // `KnownHostsCommand` supplies host keys from a program and is consulted in
        // addition to the files, a `GlobalKnownHostsFile` adds a second trusted set, and
        // `RevokedHostKeys`/`CertificateFile` change which keys count. `IdentityAgent`
        // and `PKCS11Provider` decide which process is asked to sign. Every one of them
        // is settable in `~/.ssh/config`, and this command line is what makes the
        // reviewed trust store the only one in force.
        for neutral in NEUTRALIZED_OPTIONS {
            options.push((*neutral).to_string());
        }
        match &self.identity {
            ResolvedIdentity::Password => {
                // Explicit selection, so an agent does not spend the server's retry
                // budget offering keys before the password is ever tried.
                options.push("PreferredAuthentications=password".to_string());
                options.push("PubkeyAuthentication=no".to_string());
                options.push("IdentityAgent=none".to_string());
            }
            ResolvedIdentity::Key { .. } => {
                options.push("PreferredAuthentications=publickey".to_string());
                options.push("IdentityAgent=none".to_string());
            }
            ResolvedIdentity::Agent { .. } => {
                options.push("PreferredAuthentications=publickey".to_string());
                options.push(self.identity_agent());
            }
            // The default identity still names its methods. Leaving them open puts
            // keyboard-interactive and gssapi on the menu, and a far end that is allowed
            // to run keyboard-interactive composes the prompt text the askpass bridge
            // then has to classify — which is how a hostile destination gets a locally
            // rendered "passphrase for your key" question in front of an operator.
            ResolvedIdentity::Default => {
                options.push("PreferredAuthentications=publickey".to_string());
                options.push(self.identity_agent());
            }
        }
        options
    }

    /// The agent this invocation may talk to, named rather than inherited.
    fn identity_agent(&self) -> String {
        match &self.programs.agent_socket {
            Some(socket) => format!(
                "IdentityAgent={}",
                quote_option_value(&socket.display().to_string())
            ),
            // The literal OpenSSH understands as "the agent this process was started
            // with", which is the deployment host's own — never one a config chose.
            None => "IdentityAgent=SSH_AUTH_SOCK".to_string(),
        }
    }

    fn base_command(&self) -> Command {
        self.command_with_config(true)
    }

    fn explicit_identity(&self) -> bool {
        matches!(
            self.identity,
            ResolvedIdentity::Key { .. } | ResolvedIdentity::Agent { .. }
        )
    }

    fn command_with_config(&self, connecting: bool) -> Command {
        let mut command = Command::new(&self.programs.ssh);
        // IdentityFile is additive: -i and IdentitiesOnly do not suppress keys from
        // ssh_config. Inspect the ambient config for forbidden routing below, but
        // make an explicitly selected identity connection from our options alone.
        if connecting && self.explicit_identity() {
            command.args(["-F", "/dev/null"]);
        }
        for option in self.options() {
            command.arg("-o").arg(option);
        }
        command.arg("-p").arg(self.destination.port.to_string());
        command.arg("-l").arg(&self.destination.user);
        match &self.identity {
            ResolvedIdentity::Agent {
                public_key_file, ..
            } => {
                command.arg("-i").arg(public_key_file);
            }
            ResolvedIdentity::Key { path, .. } => {
                command.arg("-i").arg(path);
            }
            ResolvedIdentity::Default | ResolvedIdentity::Password => {}
        }
        self.apply_env(&mut command);
        command
    }

    fn apply_env(&self, command: &mut Command) {
        command.env_remove("SSH_ASKPASS");
        command.env_remove("SSH_ASKPASS_REQUIRE");
        command.env_remove("DISPLAY");
        command.env_remove(super::askpass::SOCKET_ENV);
        if self.identity.needs_agent() {
            self.programs.apply_agent(command);
        } else {
            // An explicitly named key or a password must not be quietly supplemented by
            // whatever the ambient agent holds.
            command.env_remove("SSH_AUTH_SOCK");
        }
        if let Some(bridge) = &self.bridge {
            for (name, value) in bridge.ssh_env() {
                command.env(name, value);
            }
        }
    }

    /// Build the argument vector for a remote command, for the plan and for tests. The
    /// remote command is one shell string, because that is what `ssh` sends.
    pub fn argv(&self, remote: &str) -> Vec<String> {
        let mut argv = vec![self.programs.ssh.display().to_string()];
        if self.explicit_identity() {
            argv.extend(["-F".into(), "/dev/null".into()]);
        }
        for option in self.options() {
            argv.push("-o".to_string());
            argv.push(option);
        }
        argv.push("-p".to_string());
        argv.push(self.destination.port.to_string());
        argv.push("-l".to_string());
        argv.push(self.destination.user.clone());
        match &self.identity {
            ResolvedIdentity::Agent {
                public_key_file, ..
            } => {
                argv.push("-i".to_string());
                argv.push(public_key_file.display().to_string());
            }
            ResolvedIdentity::Key { path, .. } => {
                argv.push("-i".to_string());
                argv.push(path.display().to_string());
            }
            ResolvedIdentity::Default | ResolvedIdentity::Password => {}
        }
        argv.push(self.destination.address.clone());
        argv.push(remote.to_string());
        argv
    }

    /// Run one remote command to completion, with a deadline and a bounded transcript.
    pub fn run(&self, remote: &str, stdin: Option<&[u8]>) -> Result<Completed> {
        self.run_with_timeout(remote, stdin, self.command_timeout)
    }

    pub fn run_with_timeout(
        &self,
        remote: &str,
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Completed> {
        let mut command = self.base_command();
        command.arg(&self.destination.address);
        command.arg(remote);
        run_bounded_for(command, stdin, timeout, self.bridge.as_ref())
    }

    /// Start `ssh <dest> <remote>` with piped stdin and stdout, for the framed helper
    /// session.
    ///
    /// The caller owns the child *and* the arming guard, and must keep them together:
    /// the prompt window belongs to this connection and closes when it does.
    pub fn spawn(&self, remote: &str) -> Result<(std::process::Child, Option<Armed>)> {
        let mut command = self.base_command();
        command.arg(&self.destination.address);
        command.arg(remote);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let child = command
            .spawn()
            .with_context(|| format!("starting ssh to {}", self.destination.label()))?;
        let armed = self
            .bridge
            .as_ref()
            .map(|bridge| bridge.arm(child.id() as i32));
        Ok((child, armed))
    }

    /// Inspect what OpenSSH will actually do with this destination, before connecting.
    ///
    /// Two refusals live here. An effective hostname that is not the selected overlay
    /// address means a `Host` stanza rewrote the destination, and the machine that would
    /// receive the credentials is not the one that was reviewed. Any proxy routing is
    /// out of scope for v1 and is named rather than silently followed.
    pub fn inspect_effective_config(&self) -> Result<EffectiveConfig> {
        let mut command = self.command_with_config(false);
        command.arg("-G");
        command.arg(&self.destination.address);
        let completed = run_bounded(command, None, self.connect_timeout)?;
        if !completed.success() {
            return refuse(
                "ssh_unavailable",
                format!(
                    "`ssh -G` could not resolve {}: {}",
                    self.destination.label(),
                    completed.stderr_text()
                ),
            );
        }
        let config = EffectiveConfig::parse(&String::from_utf8_lossy(&completed.stdout));

        // What the command line asked for has to be what is in force. OpenSSH takes the
        // first value it obtains and the command line is read first, so this should
        // always hold — and if a future OpenSSH ever changes that, this operation stops
        // rather than trusting a host key store it did not choose.
        for (key, required) in REQUIRED_EFFECTIVE {
            if let Some(actual) = config.value(key) {
                if !actual.eq_ignore_ascii_case(required) {
                    return refuse(
                        "unsafe_ssh_option",
                        format!(
                            "this deployment host's SSH configuration sets `{key}` to `{}`, and fleet setup requires `{required}`. That option decides which host keys are trusted or which process signs for this connection, so the connection was not made",
                            sanitize_remote_text(actual, 120)
                        ),
                    );
                }
            }
        }

        if let Some(routing) = config.routing() {
            return refuse(
                "unsupported_routing",
                format!(
                    "this deployment host's SSH configuration routes {} through {routing}. Proxy and jump routing are not supported for fleet setup: the private-network address must be reached directly. Remove the routing for this host, or deploy from a machine that reaches it directly",
                    self.destination.address
                ),
            );
        }
        match config.value("hostname") {
            Some(hostname) if hostname == self.destination.address => {}
            Some(hostname) => {
                return refuse(
                    "unsupported_routing",
                    format!(
                        "this deployment host's SSH configuration rewrites {} to {hostname}. Fleet setup connects to the selected private address itself, so that the machine receiving credentials is the one that was reviewed",
                        self.destination.address
                    ),
                )
            }
            None => {
                return refuse(
                    "ssh_unavailable",
                    "`ssh -G` reported no effective hostname for this destination",
                )
            }
        }
        Ok(config)
    }

    /// Whether this destination authenticates at all, using the selected identity.
    /// Runs `true` on the target, which is the cheapest thing a POSIX shell can do.
    pub fn check_access(&self) -> Result<()> {
        let completed = self.run_with_timeout("exec true", None, self.connect_timeout * 3)?;
        if completed.success() {
            return Ok(());
        }
        // Classified against the *whole* transcript, and only then shortened for a
        // person: OpenSSH's changed-key banner is longer than any display cap, and the
        // sentence that identifies it is at the end of it.
        let full = String::from_utf8_lossy(&completed.stderr).to_ascii_lowercase();
        let stderr = completed.stderr_text();
        if let Some(reason) = classify_ssh_failure(&full) {
            return refuse(
                reason,
                match reason {
                    "host_key_changed" => format!(
                        "{}'s host key is not the one this deployment host trusts. A changed host key blocks setup; verify the machine's identity out of band and repair the trust record deliberately. Nothing was sent",
                        self.destination.address
                    ),
                    "host_unknown" => format!(
                        "{} is not a host this deployment host has verified, and strict host checking is never relaxed. Verify its key first",
                        self.destination.address
                    ),
                    _ => format!(
                        "{} refused this authentication. {stderr}",
                        self.destination.label()
                    ),
                },
            );
        }
        refuse(
            "ssh_unavailable",
            format!("{} did not answer: {stderr}", self.destination.label()),
        )
    }
}

/// The subset of `ssh -G` this path cares about.
#[derive(Clone, Debug, Default)]
pub struct EffectiveConfig {
    values: BTreeMap<String, String>,
}

impl EffectiveConfig {
    pub fn parse(text: &str) -> Self {
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let mut fields = line.splitn(2, ' ');
            let Some(key) = fields.next() else { continue };
            let value = fields.next().unwrap_or("").trim();
            // `ssh -G` repeats `identityfile`; the first occurrence is the effective one
            // for every key this module reads.
            values
                .entry(key.to_ascii_lowercase())
                .or_insert_with(|| value.to_string());
        }
        Self { values }
    }

    pub fn value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// The proxy setting in force, if any. `ssh -G` omits these keys entirely when they
    /// are unset, and prints the literal `none` when they are explicitly disabled.
    pub fn routing(&self) -> Option<String> {
        for key in ["proxyjump", "proxycommand"] {
            if let Some(value) = self.value(key) {
                let trimmed = value.trim();
                if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("none") {
                    return Some(format!("{key} {trimmed}"));
                }
            }
        }
        None
    }
}

// ------------------------------------------------------------------ identities

/// What a running agent holds, by public fingerprint. No private key is exported and
/// no agent is forwarded; this is a list of labels to choose from.
pub fn agent_identities(programs: &Programs, scratch: &Path) -> Result<Vec<AgentIdentity>> {
    let mut command = Command::new(&programs.ssh_add);
    command.arg("-L").stdin(Stdio::null());
    command.env_remove("SSH_ASKPASS");
    command.env_remove("SSH_ASKPASS_REQUIRE");
    programs.apply_agent(&mut command);
    let completed = run_bounded(command, None, Duration::from_secs(10))?;
    if !completed.success() {
        // Exit 1 is "the agent has no identities", exit 2 is "there is no agent". Both
        // are answers: the caller shows agent authentication as unavailable.
        return Ok(Vec::new());
    }
    let mut identities = Vec::new();
    for line in String::from_utf8_lossy(&completed.stdout).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.splitn(3, ' ');
        let (Some(algorithm), Some(blob)) = (fields.next(), fields.next()) else {
            continue;
        };
        let comment = fields.next().unwrap_or("").trim().to_string();
        let fingerprint = public_key_fingerprint(programs, line, scratch)?;
        identities.push(AgentIdentity {
            algorithm: algorithm.to_string(),
            blob: blob.to_string(),
            comment,
            fingerprint,
        });
    }
    Ok(identities)
}

/// Turn the operator's choice into something that can be handed to `ssh`.
pub fn resolve_identity(
    programs: &Programs,
    choice: &IdentityChoice,
    scratch: &Path,
) -> Result<ResolvedIdentity> {
    match choice {
        IdentityChoice::Default => Ok(ResolvedIdentity::Default),
        IdentityChoice::Password => Ok(ResolvedIdentity::Password),
        IdentityChoice::Agent { fingerprint } => {
            let identities = agent_identities(programs, scratch)?;
            if identities.is_empty() {
                return refuse(
                    "agent_unavailable",
                    "no SSH agent identity is available to this process. A service session often has no agent; select a key file or a password instead",
                );
            }
            let Some(selected) = identities
                .iter()
                .find(|identity| identity.fingerprint == *fingerprint)
            else {
                return refuse(
                    "agent_identity_missing",
                    format!(
                        "the agent does not hold {fingerprint}; it holds {}",
                        identities
                            .iter()
                            .map(|identity| identity.fingerprint.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
            };
            // `-i` on a *public* key pins the agent to this one identity, which is what
            // stops it from offering every key it holds and exhausting the server's
            // retry budget. The private half never leaves the agent.
            super::ensure_private_subdir(scratch)?;
            let file = scratch.join(format!("agent-{}.pub", super::random_hex(6)?));
            let line = format!(
                "{} {} {}\n",
                selected.algorithm, selected.blob, selected.comment
            );
            super::write_private_atomic(&file, line.as_bytes())?;
            Ok(ResolvedIdentity::Agent {
                public_key_file: file,
                label: if selected.comment.is_empty() {
                    selected.algorithm.clone()
                } else {
                    selected.comment.clone()
                },
                fingerprint: selected.fingerprint.clone(),
            })
        }
        IdentityChoice::Key { path } => {
            let path = validate_key_file(path)?;
            let label = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());
            let fingerprint = public_key_fingerprint_of_file(programs, &path).ok();
            Ok(ResolvedIdentity::Key {
                path,
                label,
                fingerprint,
            })
        }
    }
}

/// An explicitly named private key must be this account's, and private.
///
/// OpenSSH enforces this itself and refuses with a wall of text; catching it here means
/// the operator gets the reason before a connection is attempted, and this process still
/// never reads the key.
pub fn validate_key_file(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return refuse(
            "key_unusable",
            format!(
                "`{}` must be an absolute path: a relative one resolves against whatever directory this process happens to be in",
                path.display()
            ),
        );
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return refuse(
                "key_unusable",
                format!("there is no key at {}", path.display()),
            )
        }
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    };
    if !metadata.file_type().is_file() {
        return refuse(
            "key_unusable",
            format!("{} is not a regular file", path.display()),
        );
    }
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != uid {
        return refuse(
            "key_unusable",
            format!(
                "{} is owned by uid {}, not by uid {uid}. A deployment uses only keys this account owns",
                path.display(),
                metadata.uid()
            ),
        );
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return refuse(
            "key_unusable",
            format!(
                "{} is readable by other accounts (mode {:o}); OpenSSH refuses such a key. `chmod 600` it",
                path.display(),
                metadata.permissions().mode() & 0o777
            ),
        );
    }
    Ok(path.to_path_buf())
}

fn public_key_fingerprint(programs: &Programs, line: &str, scratch: &Path) -> Result<String> {
    super::ensure_private_subdir(scratch)?;
    let path = scratch.join(format!("identity-{}.pub", super::random_hex(6)?));
    super::write_private_atomic(&path, format!("{line}\n").as_bytes())?;
    let fingerprint = public_key_fingerprint_of_file(programs, &path);
    let _ = std::fs::remove_file(&path);
    fingerprint
}

fn public_key_fingerprint_of_file(programs: &Programs, path: &Path) -> Result<String> {
    let mut command = Command::new(&programs.keygen);
    command.arg("-l").arg("-f").arg(path).stdin(Stdio::null());
    command.env_remove("SSH_ASKPASS");
    command.env_remove("SSH_ASKPASS_REQUIRE");
    let completed = run_bounded(command, None, Duration::from_secs(10))?;
    if !completed.success() {
        return refuse(
            "key_unusable",
            format!(
                "ssh-keygen could not read a public fingerprint for {}",
                path.display()
            ),
        );
    }
    String::from_utf8_lossy(&completed.stdout)
        .split_whitespace()
        .find(|field| field.starts_with("SHA256:"))
        .map(str::to_string)
        .ok_or_else(|| {
            super::SetupError {
                reason: "key_unusable",
                detail: format!("ssh-keygen printed no fingerprint for {}", path.display()),
            }
            .into()
        })
}

// ------------------------------------------------------------------ bounded execution

/// Output caps. A remote is not trusted to be brief, and a deployment must not be able
/// to exhaust this process's memory with a `yes` loop on the other end.
const STDOUT_CAP: usize = 4 * 1024 * 1024;
const STDERR_CAP: usize = 256 * 1024;

/// Run a command with a deadline, optional stdin, and capped output.
///
/// The child is placed in its own process group and the group is killed if the deadline
/// passes or this function is unwound, so an `ssh` that hangs on a dead network does not
/// outlive the step that started it.
pub fn run_bounded(command: Command, stdin: Option<&[u8]>, timeout: Duration) -> Result<Completed> {
    run_bounded_for(command, stdin, timeout, None)
}

/// The same, with the askpass window opened for exactly this child and closed when it
/// is reaped.
fn run_bounded_for(
    mut command: Command,
    stdin: Option<&[u8]>,
    timeout: Duration,
    bridge: Option<&Arc<Bridge>>,
) -> Result<Completed> {
    use std::io::Write as _;

    command
        .process_group(0)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = command
        .spawn()
        .with_context(|| format!("starting {:?}", command.get_program()))?;
    // Held for exactly as long as this child: the window a prompt may arrive through is
    // this connection's, and it closes with it on every path out of this function,
    // including an early `?`.
    let _armed = bridge.map(|bridge| bridge.arm(child.id() as i32));
    let mut guard = ChildGuard::new(child);

    if let Some(bytes) = stdin {
        let mut input = guard
            .child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("the child has no stdin"))?;
        // Written from a thread: a large upload can fill the pipe before the child has
        // drained it, and a blocking write here would deadlock against a child that is
        // waiting for us to read *its* output.
        let bytes = bytes.to_vec();
        let writer = std::thread::Builder::new()
            .name("ouro-ssh-stdin".to_string())
            .spawn(move || {
                let _ = input.write_all(&bytes);
                let _ = input.flush();
                drop(input);
            })
            .context("starting the upload writer")?;
        guard.writer = Some(writer);
    }

    let mut stdout = guard
        .child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("the child has no stdout"))?;
    let mut stderr = guard
        .child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("the child has no stderr"))?;
    set_nonblocking(&stdout)?;
    set_nonblocking(&stderr)?;

    let deadline = std::time::Instant::now() + timeout;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = loop {
        if std::time::Instant::now() >= deadline {
            return refuse(
                "ssh_timeout",
                format!(
                    "the command exceeded its {} second deadline",
                    timeout.as_secs()
                ),
            );
        }
        let out_done = drain(&mut stdout, &mut out, STDOUT_CAP)?;
        let err_done = drain(&mut stderr, &mut err, STDERR_CAP)?;
        if out_done && err_done {
            if let Some(status) = guard.child.try_wait()? {
                guard.reaped = true;
                break status.code();
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    };

    Ok(Completed {
        code,
        stdout: out,
        stderr: err,
    })
}

struct ChildGuard {
    child: std::process::Child,
    writer: Option<std::thread::JoinHandle<()>>,
    reaped: bool,
}

impl ChildGuard {
    fn new(child: std::process::Child) -> Self {
        Self {
            child,
            writer: None,
            reaped: false,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: the pid is this process's own freshly spawned child, still
            // unreaped, so it names the process group this call created and nothing else.
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

fn set_nonblocking(pipe: &impl std::os::fd::AsRawFd) -> Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: `fd` is owned by the pipe for the duration of both calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error()).context("configuring a subprocess pipe");
    }
    Ok(())
}

fn drain(pipe: &mut impl io::Read, sink: &mut Vec<u8>, cap: usize) -> Result<bool> {
    let mut buffer = [0_u8; 64 * 1024];
    for _ in 0..16 {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(read) => {
                if sink.len() + read > cap {
                    return refuse(
                        "output_too_large",
                        format!("the command produced more than {cap} bytes"),
                    );
                }
                sink.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

/// What OpenSSH's own diagnostics mean, in the vocabulary this module refuses in.
///
/// The order matters: a changed key and an unknown key both end with "host key
/// verification failed", and only the banner above it says which one happened.
fn classify_ssh_failure(lowered: &str) -> Option<&'static str> {
    // Revocation first: OpenSSH's revoked-key refusal also ends in "host key
    // verification failed", and calling it "unknown" would invite an operator to accept
    // the very key their own store has revoked.
    if lowered.contains("revoked") {
        return Some("host_key_revoked");
    }
    if lowered.contains("remote host identification has changed")
        || lowered.contains("host key for") && lowered.contains("has changed")
    {
        return Some("host_key_changed");
    }
    if lowered.contains("host key is known for")
        || lowered.contains("no matching host key")
        || lowered.contains("host key verification failed")
    {
        return Some("host_unknown");
    }
    if lowered.contains("permission denied")
        || lowered.contains("too many authentication")
        || lowered.contains("no supported authentication")
    {
        return Some("ssh_auth_failed");
    }
    None
}

/// Quote one word for a POSIX shell, so a path can be handed to `ssh` as data.
///
/// `ssh` runs its command through the remote login shell, so a locally built argument
/// array is not on its own protection against a remote-shell metacharacter. Everything
/// variable that enters a remote command string goes through here.
pub fn shell_quote(word: &str) -> String {
    let mut quoted = String::with_capacity(word.len() + 2);
    quoted.push('\'');
    for character in word.chars() {
        if character == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runner() -> Runner {
        Runner {
            programs: Programs {
                ssh: PathBuf::from("/usr/bin/ssh"),
                ssh_add: PathBuf::from("/usr/bin/ssh-add"),
                keygen: PathBuf::from("/usr/bin/ssh-keygen"),
                askpass: PathBuf::from("/usr/local/bin/ouro"),
                agent_socket: None,
            },
            destination: Destination {
                address: "100.64.0.2".into(),
                port: 22,
                user: "me".into(),
            },
            identity: ResolvedIdentity::Default,
            known_hosts: vec![PathBuf::from("/data/deploy/known_hosts")],
            user_known_hosts: Some(PathBuf::from("/home/me/.ssh/known_hosts")),
            connect_timeout: CONNECT_TIMEOUT,
            command_timeout: COMMAND_TIMEOUT,
            bridge: None,
        }
    }

    /// The option set is a security boundary. Every one of these is here for a reason
    /// the proposal states, and a future edit that drops one should fail this test.
    #[test]
    fn every_invocation_carries_the_normalized_option_set() {
        let options = runner().options();
        for required in [
            "ForwardAgent=no",
            "ForwardX11=no",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "LocalCommand=none",
            "RemoteCommand=none",
            "RequestTTY=no",
            "ControlMaster=no",
            "ControlPath=none",
            "StrictHostKeyChecking=yes",
            // Each store quoted: `ssh` splits this value on whitespace, so a path with a
            // space in it becomes two paths that do not exist.
            "UserKnownHostsFile=\"/data/deploy/known_hosts\" \"/home/me/.ssh/known_hosts\"",
            "IdentitiesOnly=yes",
            "NumberOfPasswordPrompts=1",
            "ConnectTimeout=15",
            "ServerAliveInterval=15",
            "BatchMode=no",
        ] {
            assert!(
                options.iter().any(|option| option == required),
                "the normalized set must contain {required}: {options:?}"
            );
        }
        assert!(
            !options
                .iter()
                .any(|option| option.contains("StrictHostKeyChecking=no")
                    || option.contains("StrictHostKeyChecking=accept-new")),
            "host checking is never relaxed"
        );

        // The options that decide *what a host key means* and *who signs*. Asserted by
        // name rather than as a literal list: a future OpenSSH option that reopens this
        // door is a change to `NEUTRALIZED_OPTIONS`, and this is what makes it visible.
        for dangerous in [
            "KnownHostsCommand",
            "GlobalKnownHostsFile",
            "RevokedHostKeys",
            "CertificateFile",
            "PKCS11Provider",
            "IdentityAgent",
        ] {
            let neutralised = options
                .iter()
                .find(|option| option.starts_with(&format!("{dangerous}=")))
                .unwrap_or_else(|| panic!("`{dangerous}` is not neutralised: {options:?}"));
            assert!(
                neutralised.ends_with("=none")
                    || neutralised.ends_with("=/dev/null")
                    || neutralised.ends_with("=SSH_AUTH_SOCK"),
                "`{dangerous}` must be inert or explicitly this host's own: {neutralised}"
            );
        }
    }

    /// Every path handed to `ssh -o` survives the option parser's own tokenizer.
    #[test]
    fn a_store_path_with_a_space_stays_one_path() {
        let mut runner = runner();
        runner.known_hosts = vec![PathBuf::from(
            "/Users/me/Library/Application Support/deploy/kh",
        )];
        runner.user_known_hosts = None;
        let value = runner
            .options()
            .into_iter()
            .find(|option| option.starts_with("UserKnownHostsFile="))
            .expect("the store option");
        assert_eq!(
            value,
            "UserKnownHostsFile=\"/Users/me/Library/Application Support/deploy/kh\"",
            "an unquoted value would be two paths that do not exist, and the private store would be silently empty forever"
        );
        assert_eq!(quote_option_value("/a b/c"), "\"/a b/c\"");
    }

    /// Every identity names its authentication methods. Leaving the default open put
    /// keyboard-interactive on the menu, and a far end that may run it composes the
    /// prompt text the askpass bridge then has to classify.
    #[test]
    fn every_identity_constrains_the_authentication_methods() {
        let mut runner = runner();
        for identity in [
            ResolvedIdentity::Default,
            ResolvedIdentity::Key {
                path: PathBuf::from("/home/me/.ssh/id_ed25519"),
                label: "id_ed25519".into(),
                fingerprint: None,
            },
            ResolvedIdentity::Agent {
                public_key_file: PathBuf::from("/tmp/agent.pub"),
                label: "work".into(),
                fingerprint: "SHA256:a".into(),
            },
            ResolvedIdentity::Password,
        ] {
            let described = identity.describe();
            runner.identity = identity;
            let options = runner.options();
            let preferred = options
                .iter()
                .find(|option| option.starts_with("PreferredAuthentications="))
                .unwrap_or_else(|| panic!("no method list for {described}"));
            assert!(
                preferred == "PreferredAuthentications=publickey"
                    || preferred == "PreferredAuthentications=password",
                "only the two methods this product supports: {preferred}"
            );
        }
    }

    /// A password attempt names the method explicitly so the agent cannot spend the
    /// server's retry budget first; a key attempt says publickey for the same reason.
    #[test]
    fn the_selected_method_is_stated_rather_than_left_to_the_client() {
        let mut runner = runner();
        runner.identity = ResolvedIdentity::Password;
        let options = runner.options();
        assert!(options
            .iter()
            .any(|o| o == "PreferredAuthentications=password"));
        assert!(options.iter().any(|o| o == "PubkeyAuthentication=no"));

        runner.identity = ResolvedIdentity::Key {
            path: PathBuf::from("/home/me/.ssh/id_ed25519"),
            label: "id_ed25519".into(),
            fingerprint: None,
        };
        assert!(runner
            .options()
            .iter()
            .any(|o| o == "PreferredAuthentications=publickey"));
        let argv = runner.argv("exec true");
        let identity = argv.windows(2).find(|pair| pair[0] == "-i");
        assert_eq!(
            identity.map(|pair| pair[1].as_str()),
            Some("/home/me/.ssh/id_ed25519")
        );
        assert_eq!(argv.last().map(String::as_str), Some("exec true"));
    }

    /// `ssh -G` prints one key per line and repeats some of them; the first wins, and
    /// an absent proxy key means no proxy.
    #[test]
    fn effective_config_reads_the_keys_that_decide_where_a_connection_goes() {
        let config = EffectiveConfig::parse(
            "user me\nhostname 100.64.0.2\nport 22\nidentityfile ~/.ssh/id_rsa\nidentityfile ~/.ssh/id_ed25519\n",
        );
        assert_eq!(config.value("hostname"), Some("100.64.0.2"));
        assert_eq!(config.value("identityfile"), Some("~/.ssh/id_rsa"));
        assert_eq!(config.routing(), None);

        assert_eq!(
            EffectiveConfig::parse("proxyjump bastion\nhostname 100.64.0.2\n").routing(),
            Some("proxyjump bastion".to_string())
        );
        assert_eq!(
            EffectiveConfig::parse("proxycommand nc %h %p\n").routing(),
            Some("proxycommand nc %h %p".to_string())
        );
        assert_eq!(
            EffectiveConfig::parse("proxycommand none\n").routing(),
            None,
            "an explicitly disabled proxy is not a proxy"
        );
    }

    /// `ssh` runs its command through a remote shell, so everything variable is quoted.
    #[test]
    fn shell_quoting_survives_the_characters_a_remote_shell_would_act_on() {
        assert_eq!(
            shell_quote("/home/me/.local/bin/ouro"),
            "'/home/me/.local/bin/ouro'"
        );
        assert_eq!(shell_quote("/tmp/a b; rm -rf /"), "'/tmp/a b; rm -rf /'");
        assert_eq!(shell_quote("it's"), r#"'it'\''s'"#);
        assert_eq!(shell_quote("$(whoami)`id`"), "'$(whoami)`id`'");
    }

    /// A key OpenSSH would refuse is refused here first, with the reason and without
    /// this process ever reading the key.
    #[test]
    fn a_key_file_must_be_an_owned_private_regular_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("ouro-ssh-key-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let loose = dir.join("loose_key");
        std::fs::write(&loose, b"not really a key").expect("a file");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644))
            .expect("a loose mode");

        let error = validate_key_file(&loose).expect_err("a world-readable key is refused");
        assert_eq!(super::super::reason_of(&error), Some("key_unusable"));

        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o600))
            .expect("a private mode");
        assert!(validate_key_file(&loose).is_ok());

        assert_eq!(
            super::super::reason_of(
                &validate_key_file(Path::new("relative/key")).expect_err("a relative key path")
            ),
            Some("key_unusable")
        );
        assert_eq!(
            super::super::reason_of(
                &validate_key_file(&dir.join("absent")).expect_err("a missing key")
            ),
            Some("key_unusable")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A changed key and an unknown key both end with the same sentence, and they are
    /// very different situations. This is what tells them apart.
    #[test]
    fn openssh_diagnostics_are_classified_into_the_two_host_refusals() {
        assert_eq!(
            classify_ssh_failure(
                "@@@ warning: remote host identification has changed! @@@ ... host key verification failed."
            ),
            Some("host_key_changed")
        );
        assert_eq!(
            classify_ssh_failure(
                "no ed25519 host key is known for [127.0.0.1]:2200 and you have requested strict checking.\nhost key verification failed."
            ),
            Some("host_unknown")
        );
        assert_eq!(
            classify_ssh_failure("me@host: permission denied (publickey,password)."),
            Some("ssh_auth_failed")
        );
        assert_eq!(
            classify_ssh_failure(
                "@@@ warning: revoked host key detected! @@@ ... host key verification failed."
            ),
            Some("host_key_revoked"),
            "a revoked key is never reported as merely unknown"
        );
        assert_eq!(classify_ssh_failure("connection timed out"), None);
    }

    /// The remote exit code the shell uses for "not there" is what starts the install.
    #[test]
    fn a_missing_remote_executable_is_recognized_from_the_remote_exit_code() {
        let missing = Completed {
            code: Some(127),
            stdout: Vec::new(),
            stderr: b"bash: ouro: command not found\n".to_vec(),
        };
        assert!(missing.command_not_found());
        let refused = Completed {
            code: Some(1),
            stdout: Vec::new(),
            stderr: b"some other failure\n".to_vec(),
        };
        assert!(!refused.command_not_found());
    }
}
