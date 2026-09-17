//! `ouro fleet service`: the one user-level startup service Ouroboros will manage.
//!
//! The proposal is explicit about the shape of this
//! (`docs/proposals/fleet-network-onboarding.md`, "Installation and service lifecycle"):
//! a generated unit runs the foreground `ouro service-run`, never the detaching
//! `ouro daemon`, with an absolute executable path, an explicit data directory and
//! private logs. Two platforms have a user supervisor worth generating for — a macOS
//! LaunchAgent in a logged-in session, and a systemd user unit — and everything else
//! is told which prerequisite is missing rather than promised automatic recovery.
//!
//! ## Only our own units
//!
//! A service manager's directory belongs to the person, not to this program. Every unit
//! this module writes carries an ownership marker naming the data directory it serves
//! and a SHA-256 of its own body, on the first line of the unit's body:
//!
//! ```text
//! ouroboros-managed v1 data-dir=<absolute path> content-sha256=<64 hex>
//! ```
//!
//! [`classify`] reads that marker back. A file with no marker, or a marker naming a
//! different data directory, is [`Ownership::Foreign`]: it is described and preserved,
//! never rewritten and never deleted. A file whose marker is ours but whose body no
//! longer hashes to the recorded digest is [`Ownership::Modified`] — the operator edited
//! our unit, so `install` refuses to overwrite it without an explicit `--adopt`.
//!
//! ## What the unit does not carry
//!
//! The unit's environment is `HOME`, a fixed system `PATH` and `OUROBOROS_DATA_DIR`,
//! and deliberately nothing else. The runtime's own environment — node name, cookie
//! file, EPMD address, roster — is derived at every start by [`crate::runtime::spawn_env`]
//! from the profile on disk, so adding a machine to the roster does not silently leave a
//! stale unit behind, and the per-boot `OUROBOROS_BOOT_COOKIE_DECOY` is never written to
//! a persistent file. An ambient `OUROBOROS_*`, `ERL_*` or `RELEASE_*` variable in the
//! shell that ran `install` reaches neither the unit nor, through it, the BEAM.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::Serialize;

/// The marker grammar version. Bumped only if the marker line itself changes shape.
const MARKER_VERSION: &str = "v1";
const MARKER_TAG: &str = "ouroboros-managed";

/// How long any one service-manager command is given before it is killed. These are
/// local queries against a manager on the same machine; a minute is already generous,
/// and a manager that has stopped answering must not leave `ouro` resident forever.
const MANAGER_TIMEOUT: Duration = Duration::from_secs(20);

/// Output bound per stream, so a manager that decides to print a novel cannot be used
/// to exhaust this process.
const MAX_MANAGER_OUTPUT: usize = 256 * 1024;

/// The service's own stdout and stderr, inside the private data directory. `service-run`
/// writes its `waiting for network` lines to the second of these.
pub const SERVICE_OUT_LOG: &str = "service.out.log";
pub const SERVICE_ERR_LOG: &str = "service.err.log";

/// A fixed, boring `PATH` for the supervised process. The operator's own `PATH` is not
/// copied into a persistent unit: it commonly points at a toolchain that moves, and a
/// unit that starts differently depending on which shell installed it is not a unit
/// anybody can reason about.
const UNIT_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

// ------------------------------------------------------------------------- the platform

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    // Spelled the way [`Platform::code`] spells it, so the JSON and the page a person
    // reads name the same platform. `snake_case` alone would make this `mac_os`.
    #[serde(rename = "macos")]
    MacOs,
    Linux,
}

impl Platform {
    /// The platform this binary is running on, or `None` where no supervisor shape is
    /// implemented. Unit generation never consults this: a [`Plan`] names its target
    /// platform outright so both units can be rendered and compared from one host.
    pub fn current() -> Option<Self> {
        match std::env::consts::OS {
            "macos" => Some(Self::MacOs),
            "linux" => Some(Self::Linux),
            _ => None,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::Linux => "linux",
        }
    }
}

// ------------------------------------------------------------ the programs we may run

/// The three service-manager programs this module is allowed to run, so a test can hand
/// it counting fakes without mutating the process environment. Absolute system locations
/// are preferred; `$PATH` is the fallback when those are not installed, and the
/// `OUROBOROS_*` overrides below still win for tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Programs {
    pub launchctl: PathBuf,
    pub systemctl: PathBuf,
    pub loginctl: PathBuf,
    /// How long any one manager command is given before its whole process group is
    /// killed. A field rather than a constant so the deadline itself is testable.
    pub deadline: Duration,
}

impl Default for Programs {
    fn default() -> Self {
        Self {
            launchctl: locate_manager_program(&["/bin/launchctl"], "launchctl"),
            systemctl: locate_manager_program(&["/usr/bin/systemctl"], "systemctl"),
            loginctl: locate_manager_program(&["/usr/bin/loginctl"], "loginctl"),
            deadline: MANAGER_TIMEOUT,
        }
    }
}

impl Programs {
    /// The same three programs, with absolute overrides for an installation this
    /// lookup does not know about. Named for the same reason `OUROBOROS_TAILSCALE` is:
    /// a relative name would let the working directory decide which program runs.
    ///
    /// An override that is not an executable file is refused outright rather than
    /// quietly falling back to `PATH`: an operator who named a program meant that one,
    /// and a directory or a missing path is a mistake worth saying out loud.
    pub fn from_env() -> Result<Self> {
        let default = Self::default();
        Ok(Self {
            launchctl: override_program("OUROBOROS_LAUNCHCTL")?.unwrap_or(default.launchctl),
            systemctl: override_program("OUROBOROS_SYSTEMCTL")?.unwrap_or(default.systemctl),
            loginctl: override_program("OUROBOROS_LOGINCTL")?.unwrap_or(default.loginctl),
            deadline: default.deadline,
        })
    }
}

fn override_program(name: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let path = PathBuf::from(&value);
    if !path.is_absolute() {
        return refuse(
            "unusable_manager_program",
            format!(
                "{name} names `{}`, and a service-manager override must be an absolute path: a relative name would let the working directory decide which program runs",
                path.display()
            ),
        );
    }
    let executable = fs::metadata(&path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    if !executable {
        return refuse(
            "unusable_manager_program",
            format!(
                "{name} names `{}`, which is not an executable file on this machine",
                path.display()
            ),
        );
    }
    Ok(Some(path))
}

/// Prefer a known absolute location, then `$PATH`, then the bare name `Command` will
/// resolve the same way a person typing it would.
fn locate_manager_program(known: &[&str], fallback_name: &str) -> PathBuf {
    locate_manager_program_with(known, fallback_name, std::env::var_os("PATH").as_deref())
}

fn locate_manager_program_with(
    known: &[&str],
    fallback_name: &str,
    search_path: Option<&std::ffi::OsStr>,
) -> PathBuf {
    for candidate in known {
        let path = PathBuf::from(candidate);
        if manager_executable(&path) {
            return path;
        }
    }
    if let Some(search_path) = search_path {
        for directory in std::env::split_paths(search_path) {
            if directory.as_os_str().is_empty() {
                continue;
            }
            let candidate = directory.join(fallback_name);
            if manager_executable(&candidate) {
                return candidate;
            }
        }
    }
    PathBuf::from(fallback_name)
}

fn manager_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

// ------------------------------------------------------------------- refusals by reason

/// A refusal with a stable code an orchestrator branches on, and a sentence for a
/// person. The codes are the helper op's `reason` field and do not change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceError {
    pub reason: &'static str,
    pub detail: String,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for ServiceError {}

impl ServiceError {
    pub fn new(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

/// The stable reason behind an error, when one was declared.
pub fn service_error(error: &anyhow::Error) -> Option<&ServiceError> {
    error.downcast_ref::<ServiceError>()
}

fn refuse<T>(reason: &'static str, detail: impl Into<String>) -> Result<T> {
    Err(ServiceError::new(reason, detail).into())
}

// ------------------------------------------------------------------------ the unit plan

/// Everything the generated unit is made of, resolved before anything is written.
///
/// Every field is explicit rather than read from the process at render time, because
/// the goldens for both platforms are generated from one host: a unit's text must be a
/// pure function of this struct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    pub platform: Platform,
    /// Absolute path of the private data directory this unit serves.
    pub data_dir: PathBuf,
    /// Absolute path of the `ouro` the unit runs.
    pub executable: PathBuf,
    /// The account's home directory, exported to the unit.
    pub home: PathBuf,
    /// Where systemd user units live for this account (`$XDG_CONFIG_HOME/systemd/user`
    /// without the trailing components). Unused on macOS.
    pub config_home: PathBuf,
    pub uid: u32,
    pub user: String,
}

impl Plan {
    /// The plan for this machine and this data directory.
    pub fn for_this_machine(data_dir: &Path) -> Result<Self> {
        let platform = Platform::current().ok_or_else(|| {
            ServiceError::new(
                "unsupported_platform",
                format!(
                    "Ouroboros generates a user service for macOS and Linux; this is {}. Start the runtime with `ouro daemon` from whatever this platform supervises with",
                    std::env::consts::OS
                ),
            )
        })?;
        let executable = std::env::current_exe().context("locating this ouro executable")?;
        let executable = executable
            .canonicalize()
            .with_context(|| format!("resolving {}", executable.display()))?;
        if !executable.is_absolute() {
            return refuse(
                "unusable_executable",
                format!(
                    "{} is not an absolute path, and a unit that names a relative program lets the working directory decide what starts",
                    executable.display()
                ),
            );
        }
        // `$HOME` first, and `dirs::home_dir()` only as the fallback. A child process
        // told where its home is must write its unit there: a test harness, a `sudo -u`
        // and a service account all say so this way. `dirs` 6 happens to read `$HOME`
        // itself on both platforms, so this branch is belt and braces rather than the
        // thing that makes it work — the property is pinned by a test that runs this
        // binary with a `HOME` of its own and checks where the unit landed.
        let home = match std::env::var_os("HOME") {
            Some(value) if !value.is_empty() && Path::new(&value).is_absolute() => {
                PathBuf::from(value)
            }
            _ => dirs::home_dir().ok_or_else(|| {
                anyhow!("this account has no home directory to install a unit into")
            })?,
        };
        let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(value) if !value.is_empty() && Path::new(&value).is_absolute() => {
                PathBuf::from(value)
            }
            _ => home.join(".config"),
        };
        let data_dir = if data_dir.is_absolute() {
            data_dir.to_path_buf()
        } else {
            std::env::current_dir()
                .context("resolving a relative data directory")?
                .join(data_dir)
        };
        // One directory is one service. `<dir>`, `<dir>/` and `<dir>/./` are the same
        // directory, and without this each spelling minted its own label and its own
        // RunAtLoad agent for the same runtime.
        let data_dir = canonical_dir(&data_dir);

        Ok(Self {
            platform,
            data_dir,
            executable,
            home,
            config_home,
            uid: unsafe { libc::geteuid() },
            user: account_name(),
        })
    }

    /// The short, stable digest of this data directory that names the unit. Two data
    /// directories on one account get two independent services; the same data directory
    /// always gets the same one, whichever way it was spelled.
    pub fn digest(&self) -> String {
        sha256_hex(canonical_dir(&self.data_dir).as_os_str().as_encoded_bytes())[..12].to_string()
    }

    /// The launchd label, which is also the systemd unit's stem.
    pub fn label(&self) -> String {
        match self.platform {
            Platform::MacOs => format!("dev.ouroboros.runtime.{}", self.digest()),
            Platform::Linux => format!("ouroboros-{}", self.digest()),
        }
    }

    /// What the manager is asked about: a launchd service target, or a unit file name.
    pub fn manager_name(&self) -> String {
        match self.platform {
            Platform::MacOs => format!("gui/{}/{}", self.uid, self.label()),
            Platform::Linux => format!("{}.service", self.label()),
        }
    }

    /// The launchd domain this account's agents live in.
    pub fn domain(&self) -> String {
        format!("gui/{}", self.uid)
    }

    pub fn unit_path(&self) -> PathBuf {
        match self.platform {
            Platform::MacOs => self
                .home
                .join("Library")
                .join("LaunchAgents")
                .join(format!("{}.plist", self.label())),
            Platform::Linux => self
                .config_home
                .join("systemd")
                .join("user")
                .join(format!("{}.service", self.label())),
        }
    }

    pub fn out_log(&self) -> PathBuf {
        self.data_dir.join(SERVICE_OUT_LOG)
    }

    pub fn err_log(&self) -> PathBuf {
        self.data_dir.join(SERVICE_ERR_LOG)
    }

    /// The unit's whole text, marker included.
    pub fn render(&self) -> Result<String> {
        let data_dir = plain_path(&self.data_dir, "data directory")?;
        let executable = plain_path(&self.executable, "ouro executable")?;
        let home = plain_path(&self.home, "home directory")?;
        let out_log = plain_path(&self.out_log(), "service stdout log")?;
        let err_log = plain_path(&self.err_log(), "service stderr log")?;
        let environment = [
            ("HOME", home.as_str()),
            ("OUROBOROS_DATA_DIR", data_dir.as_str()),
            ("PATH", UNIT_PATH),
        ];

        let (prefix, body) = match self.platform {
            Platform::MacOs => {
                let mut environment_xml = String::new();
                for (key, value) in environment {
                    environment_xml.push_str(&format!(
                        "\t\t<key>{}</key>\n\t\t<string>{}</string>\n",
                        xml_escape(key),
                        xml_escape(value)
                    ));
                }
                let body = format!(
                    r#"<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{executable}</string>
		<string>service-run</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
{environment_xml}	</dict>
	<key>WorkingDirectory</key>
	<string>{data_dir}</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>30</integer>
	<key>ExitTimeOut</key>
	<integer>30</integer>
	<key>ProcessType</key>
	<string>Adaptive</string>
	<key>StandardOutPath</key>
	<string>{out_log}</string>
	<key>StandardErrorPath</key>
	<string>{err_log}</string>
</dict>
</plist>
"#,
                    label = xml_escape(&self.label()),
                    executable = xml_escape(&executable),
                    data_dir = xml_escape(&data_dir),
                    out_log = xml_escape(&out_log),
                    err_log = xml_escape(&err_log),
                );
                (
                    concat!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
                        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
                    )
                    .to_string(),
                    body,
                )
            }
            Platform::Linux => {
                // systemd splits `ExecStart=` and `Environment=` on whitespace and
                // expands `%` specifiers in both, so an unescaped path with a space in
                // it runs the wrong program with the wrong argv and a `%h` in it runs
                // against somebody's home directory. Values are quoted and escaped per
                // systemd.unit(5)'s documented grammar; `append:` takes the rest of its
                // line and is therefore only specifier-escaped.
                let mut environment_lines = String::new();
                for (key, value) in environment {
                    environment_lines
                        .push_str(&format!("Environment={key}={}\n", systemd_quoted(value)));
                }
                let body = format!(
                    r#"[Unit]
Description=Ouroboros runtime for {description}
# No network ordering: `ouro service-run` waits for this machine's own private
# interface to become bindable before it launches the BEAM, and reports that wait
# in this unit's log. A user manager has no network-online.target to want.
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart={executable} service-run
WorkingDirectory={working_directory}
{environment_lines}Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StandardOutput=append:{out_log}
StandardError=append:{err_log}

[Install]
WantedBy=default.target
"#,
                    description = systemd_literal(&data_dir),
                    executable = systemd_quoted(&executable),
                    working_directory = systemd_quoted(&data_dir),
                    out_log = systemd_literal(&out_log),
                    err_log = systemd_literal(&err_log),
                );
                (String::new(), body)
            }
        };

        // The digest covers everything the file says except the marker line itself, so
        // removing that one line from the unit on disk reproduces exactly what was
        // hashed. An edit anywhere else — including the XML preamble — changes it.
        let content = sha256_hex(format!("{prefix}{body}").as_bytes());
        // The data directory is percent-encoded, so the marker is one token per field
        // whatever the path contains — a space, a `#`, a quote, a newline — and so the
        // encoding can never produce the `--` that XML forbids inside a comment.
        let encoded = marker_encode(&data_dir);
        let comment = match self.platform {
            Platform::MacOs => format!(
                "<!-- {MARKER_TAG} {MARKER_VERSION} data-dir={encoded} content-sha256={content} -->\n"
            ),
            Platform::Linux => format!(
                "# {MARKER_TAG} {MARKER_VERSION} data-dir={encoded} content-sha256={content}\n"
            ),
        };

        Ok(format!("{prefix}{comment}{body}"))
    }
}

/// The account this process actually runs as, from the password database rather than
/// from `$USER`.
///
/// `$USER` is whatever the environment says, and it survives `su`, `sudo -E` and a
/// service manager's inherited environment. The name here decides which account
/// `loginctl show-user` is asked about, and therefore whose lingering — whose
/// boot-and-logout persistence — is reported, so it has to be the real one.
fn account_name() -> String {
    let uid = unsafe { libc::geteuid() };
    // SAFETY: `getpwuid` returns a pointer into a static buffer owned by libc, which is
    // read here and copied out before anything else can call into libc on this thread.
    unsafe {
        let entry = libc::getpwuid(uid);
        if !entry.is_null() && !(*entry).pw_name.is_null() {
            if let Ok(name) = std::ffi::CStr::from_ptr((*entry).pw_name).to_str() {
                if !name.trim().is_empty() {
                    return name.to_string();
                }
            }
        }
    }
    uid.to_string()
}

/// A directory path reduced to one spelling: symlinks resolved and `.`/trailing
/// separators dropped where the directory exists, and a lexical normalisation where it
/// does not (so a plan for a directory that has not been created yet still has one
/// stable label).
pub fn canonical_dir(path: &Path) -> PathBuf {
    if let Ok(resolved) = fs::canonicalize(path) {
        return resolved;
    }
    // The path does not exist yet — a unit directory about to be created, a data
    // directory named before it is made. Resolve the deepest ancestor that does exist
    // and keep the rest, so `/var/...` and `/private/var/...` are one answer either way.
    let mut normalised = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            other => normalised.push(other.as_os_str()),
        }
    }
    let mut tail = Vec::new();
    let mut ancestor = normalised.as_path();
    loop {
        if let Ok(resolved) = fs::canonicalize(ancestor) {
            let mut rebuilt = resolved;
            for part in tail.iter().rev() {
                rebuilt.push(part);
            }
            return rebuilt;
        }
        let Some(parent) = ancestor.parent() else {
            return normalised;
        };
        let Some(name) = ancestor.file_name() else {
            return normalised;
        };
        tail.push(name.to_os_string());
        ancestor = parent;
    }
}

/// A path that can be written into a unit and into an ownership marker without
/// changing what either one means.
fn plain_path(path: &Path, description: &str) -> Result<String> {
    let text = path.to_str().ok_or_else(|| {
        ServiceError::new(
            "unusable_path",
            format!("the {description} {} is not valid UTF-8", path.display()),
        )
    })?;
    if text.chars().any(|c| c.is_control()) {
        return refuse(
            "unusable_path",
            format!(
                "the {description} `{text}` contains a control character, which no service unit format can carry"
            ),
        );
    }
    Ok(text.to_string())
}

/// A value for a systemd directive that expands `%` specifiers and splits on
/// whitespace: doubled specifiers, and the whole thing in double quotes with `\` and
/// `"` escaped, per systemd.unit(5) "Quoting".
fn systemd_quoted(value: &str) -> String {
    let escaped = value
        .replace('%', "%%")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// A value for a directive that takes the rest of its line (`Description=`,
/// `StandardOutput=append:…`): nothing is split, so only the specifier needs doubling.
fn systemd_literal(value: &str) -> String {
    value.replace('%', "%%")
}

/// Bytes a marker field may carry unencoded. Everything else becomes `%XX`, and a `-`
/// that would follow another `-` is encoded too, because XML forbids `--` inside a
/// comment and the plist's marker is one.
fn marker_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'/' | b':' | b'+' | b'@')
}

fn marker_encode(value: &str) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(value.len());
    let mut previous_dash = false;
    for byte in value.as_bytes() {
        if *byte == b'-' && !previous_dash {
            encoded.push('-');
            previous_dash = true;
            continue;
        }
        if marker_unreserved(*byte) {
            encoded.push(*byte as char);
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
        previous_dash = false;
    }
    encoded
}

fn marker_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hex = value.get(index + 1..index + 3)?;
                decoded.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn random_hex(bytes: usize) -> Result<String> {
    use std::fmt::Write as _;

    let mut random = vec![0_u8; bytes];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|error| anyhow!("cannot read OS randomness: {error}"))?;
    Ok(random
        .iter()
        .fold(String::with_capacity(bytes * 2), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        }))
}

// ------------------------------------------------------------------------- ownership

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    /// Nothing is installed at this path.
    Absent,
    /// Written by this code for this data directory, and unchanged since.
    Ours,
    /// Our marker, our data directory, and a body that no longer matches the recorded
    /// digest: somebody edited our unit by hand.
    Modified,
    /// Not ours. Described, preserved, and never written or deleted without `--adopt`.
    Foreign,
}

impl Ownership {
    pub fn code(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Ours => "ours",
            Self::Modified => "modified",
            Self::Foreign => "foreign",
        }
    }

    /// Whether the file at our path carries our marker for our data directory.
    pub fn is_ours(self) -> bool {
        matches!(self, Self::Ours | Self::Modified)
    }
}

/// The marker line read back out of a unit on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Marker {
    pub data_dir: String,
    pub content_sha256: String,
}

/// The line the marker has to be on, for a unit of this platform's shape.
///
/// A marker accepted from anywhere in the file, in either comment syntax, is a marker
/// that can be appended to somebody else's unit — or hidden below one. It is written at
/// a fixed place by [`Plan::render`] and it is only read from that place.
fn marker_line_index(platform: Platform) -> usize {
    match platform {
        // After the XML declaration and the DOCTYPE, which are a fixed two lines.
        Platform::MacOs => 2,
        Platform::Linux => 0,
    }
}

/// Reads the ownership marker out of a unit's text, if it has one, in the one place and
/// the one comment syntax this platform's units carry it.
///
/// The marker is not a security boundary and cannot be: anything that can write the unit
/// path can compute the digest, because the digest is over the file and has no secret in
/// it. What it distinguishes is an accident from a deliberate act — another tool's unit,
/// a hand-written one, an older copy of ours — not an adversary who already has write
/// access to this account's service directory. `docs/FLEET.md` says so where an operator
/// will read it.
pub fn read_marker(platform: Platform, text: &str) -> Option<Marker> {
    let line = text.lines().nth(marker_line_index(platform))?;
    let line = match platform {
        Platform::MacOs => line
            .trim()
            .strip_prefix("<!--")?
            .strip_suffix("-->")?
            .trim(),
        Platform::Linux => line.trim().strip_prefix('#')?.trim(),
    };
    let mut fields = line.split_whitespace();
    if fields.next()? != MARKER_TAG || fields.next()? != MARKER_VERSION {
        return None;
    }
    let mut data_dir = None;
    let mut content_sha256 = None;
    for field in fields {
        // Parsed by field name, and a repeated or unknown field makes the whole marker
        // unreadable rather than letting the last one win.
        let (name, value) = field.split_once('=')?;
        let slot = match name {
            "data-dir" => &mut data_dir,
            "content-sha256" => &mut content_sha256,
            _ => return None,
        };
        if slot.is_some() {
            return None;
        }
        *slot = Some(value.to_string());
    }
    let content_sha256 = content_sha256?;
    if content_sha256.len() != 64 || !content_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(Marker {
        data_dir: marker_decode(&data_dir?)?,
        content_sha256,
    })
}

/// What a marker's digest covers: the whole unit with its one marker line taken out.
fn marked_content(platform: Platform, text: &str) -> Option<String> {
    let index = marker_line_index(platform);
    let mut kept = String::with_capacity(text.len());
    let mut lines = 0;
    let mut rest = text;
    while lines < index {
        let end = rest.find('\n')? + 1;
        kept.push_str(&rest[..end]);
        rest = &rest[end..];
        lines += 1;
    }
    let end = rest.find('\n')? + 1;
    kept.push_str(&rest[end..]);
    Some(kept)
}

/// What, if anything, is installed at this plan's unit path.
pub fn classify(plan: &Plan) -> Result<(Ownership, Option<String>)> {
    let path = plan.unit_path();
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Ownership::Absent, None))
        }
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    };
    // A symlink or a directory where our unit goes is somebody else's arrangement: it is
    // reported and left exactly as it is, and nothing follows it.
    if !metadata.file_type().is_file() {
        return Ok((Ownership::Foreign, None));
    }
    let text = fs::read_to_string(&path)
        .with_context(|| format!("reading the existing unit {}", path.display()))?;
    let Some(marker) = read_marker(plan.platform, &text) else {
        return Ok((Ownership::Foreign, Some(sha256_hex(text.as_bytes()))));
    };
    // A marker of ours for a *different* data directory is another runtime's unit that
    // happens to sit at this path. It is not ours to rewrite or delete.
    if canonical_dir(Path::new(&marker.data_dir)) != canonical_dir(&plan.data_dir) {
        return Ok((Ownership::Foreign, Some(sha256_hex(text.as_bytes()))));
    }
    let content = marked_content(plan.platform, &text).unwrap_or_default();
    let digest = sha256_hex(content.as_bytes());
    if digest == marker.content_sha256 {
        Ok((Ownership::Ours, Some(marker.content_sha256)))
    } else {
        Ok((Ownership::Modified, Some(digest)))
    }
}

// ------------------------------------------------------------------------- detection

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorCode {
    /// macOS, with a logged-in GUI session that can hold a LaunchAgent.
    LaunchdUserSession,
    /// Linux, with a reachable `systemctl --user` manager.
    SystemdUser,
    /// No user supervisor here. `prerequisite` names what is missing.
    Unsupported,
}

impl SupervisorCode {
    pub fn code(self) -> &'static str {
        match self {
            Self::LaunchdUserSession => "launchd_user_session",
            Self::SystemdUser => "systemd_user",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Supervisor {
    pub code: SupervisorCode,
    pub platform: Option<Platform>,
    /// `Some(true)`/`Some(false)` when the login manager said; `None` when it could not
    /// be asked. Only ever meaningful on Linux.
    pub linger: Option<bool>,
    /// One sentence naming the missing prerequisite, when there is one.
    pub prerequisite: Option<String>,
    /// What this machine's supervisor does and does not promise, stated outright.
    pub persistence: String,
}

/// Which user supervisor, if any, this machine has. Contacts only the local manager.
pub fn detect(programs: &Programs) -> Supervisor {
    detect_on(Platform::current(), programs)
}

/// The same detection, against a named platform's manager rather than this host's.
///
/// Every operation goes through this with its [`Plan`]'s platform, which is what lets
/// both supervisors be exercised from one machine: on a real install the plan's platform
/// came from [`Platform::current`], and a plan built by hand for the wrong one finds no
/// manager to talk to and is told so.
pub fn detect_on(platform: Option<Platform>, programs: &Programs) -> Supervisor {
    detect_as(platform, &account_name(), programs)
}

/// The same detection again, for a named account. Only the systemd side uses the name,
/// and only to ask `loginctl` whether that account lingers.
pub fn detect_as(platform: Option<Platform>, user: &str, programs: &Programs) -> Supervisor {
    match platform {
        Some(Platform::MacOs) => detect_launchd(programs),
        Some(Platform::Linux) => detect_systemd(user, programs),
        None => Supervisor {
            code: SupervisorCode::Unsupported,
            platform: None,
            linger: None,
            prerequisite: Some(format!(
                "Ouroboros generates a user service for macOS and Linux only; this machine is {}",
                std::env::consts::OS
            )),
            persistence: "No managed service is available here; start the runtime with `ouro daemon` under whatever this platform supervises with.".to_string(),
        },
    }
}

fn detect_launchd(programs: &Programs) -> Supervisor {
    let uid = unsafe { libc::geteuid() };
    let domain = format!("gui/{uid}");
    match run(&programs.launchctl, &["print", domain.as_str()], programs.deadline) {
        Ok(outcome) if outcome.status == Some(0) => Supervisor {
            code: SupervisorCode::LaunchdUserSession,
            platform: Some(Platform::MacOs),
            linger: None,
            prerequisite: None,
            persistence: MACOS_PERSISTENCE.to_string(),
        },
        Ok(_) => Supervisor {
            code: SupervisorCode::Unsupported,
            platform: Some(Platform::MacOs),
            linger: None,
            prerequisite: Some(format!(
                "launchd has no `{domain}` domain for this account, which is what a LaunchAgent lives in. Log in to this Mac's desktop session as this user and try again; a LaunchAgent cannot run before somebody logs in"
            )),
            persistence: MACOS_PERSISTENCE.to_string(),
        },
        Err(error) => Supervisor {
            code: SupervisorCode::Unsupported,
            platform: Some(Platform::MacOs),
            linger: None,
            prerequisite: Some(format!(
                "this machine's `launchctl` could not be asked about `{domain}`: {error}"
            )),
            persistence: MACOS_PERSISTENCE.to_string(),
        },
    }
}

const MACOS_PERSISTENCE: &str =
    "A LaunchAgent starts at login and stops with the login session. It does not run \
     before anybody has logged in, so this machine is not reachable between a reboot and \
     the next login.";

fn detect_systemd(user: &str, programs: &Programs) -> Supervisor {
    let reachable = matches!(
        run(&programs.systemctl, &["--user", "show", "--property=Version"], programs.deadline),
        Ok(ref outcome) if outcome.status == Some(0)
    );
    if !reachable {
        return Supervisor {
            code: SupervisorCode::Unsupported,
            platform: Some(Platform::Linux),
            linger: None,
            prerequisite: Some(
                "`systemctl --user` could not reach a user manager for this account. A systemd user instance (and a DBUS_SESSION_BUS_ADDRESS/XDG_RUNTIME_DIR that points at it) is the prerequisite; over SSH it usually needs lingering enabled for this account first"
                    .to_string(),
            ),
            persistence:
                "No user manager answered, so nothing here starts this runtime automatically."
                    .to_string(),
        };
    }

    let linger = match run(
        &programs.loginctl,
        &["show-user", user, "--property=Linger"],
        programs.deadline,
    ) {
        Ok(outcome) if outcome.status == Some(0) => {
            property(&outcome.stdout, "Linger").map(|value| value.eq_ignore_ascii_case("yes"))
        }
        _ => None,
    };

    Supervisor {
        code: SupervisorCode::SystemdUser,
        platform: Some(Platform::Linux),
        linger,
        prerequisite: None,
        persistence: linger_sentence(user, linger),
    }
}

fn linger_sentence(user: &str, linger: Option<bool>) -> String {
    match linger {
        Some(true) => format!(
            "Lingering is enabled for {user}, so this user manager starts at boot and survives logout; the unit comes up without anybody logging in."
        ),
        Some(false) => format!(
            "Lingering is NOT enabled for {user}: this unit stops when the last session ends and does not start at boot. An administrator enables it with `loginctl enable-linger {user}`; until then this is a login-scoped service."
        ),
        None => format!(
            "Whether {user} lingers could not be established, so boot and logout persistence is unknown here. Ask `loginctl show-user {user} --property=Linger` before relying on it."
        ),
    }
}

// ---------------------------------------------------------------------------- reporting

/// What one action did and what it found, for `--json` and for a person.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub action: &'static str,
    pub platform: Option<Platform>,
    pub supervisor: SupervisorCode,
    pub label: String,
    /// The account this service belongs to, read from the password database. It is what
    /// `loginctl` is asked about, so a reader can check it is the account they meant.
    pub user: String,
    pub unit_path: String,
    pub executable: String,
    pub data_dir: String,
    pub ownership: Ownership,
    /// A unit of ours exists at `unit_path`.
    pub installed: bool,
    /// `None` wherever the manager did not say.
    pub loaded: Option<bool>,
    pub running: Option<bool>,
    pub pid: Option<u32>,
    pub last_exit: Option<i64>,
    pub linger: Option<bool>,
    pub persistence: String,
    pub prerequisite: Option<String>,
    /// Exactly the manager commands this action issued, in order, argv by argv.
    pub commands: Vec<Vec<String>>,
    /// Every externally visible step in the order it happened, manager calls and file
    /// operations interleaved. The ordering matters — a unit unlinked before its manager
    /// was told to stop supervising it is a different act from one unlinked after — and
    /// `commands` alone cannot show it.
    pub steps: Vec<String>,
    pub notes: Vec<String>,
}

impl Report {
    fn new(action: &'static str, plan: &Plan, supervisor: &Supervisor) -> Self {
        Self {
            action,
            platform: Some(plan.platform),
            supervisor: supervisor.code,
            label: plan.label(),
            user: plan.user.clone(),
            unit_path: plan.unit_path().display().to_string(),
            executable: plan.executable.display().to_string(),
            data_dir: plan.data_dir.display().to_string(),
            ownership: Ownership::Absent,
            installed: false,
            loaded: None,
            running: None,
            pid: None,
            last_exit: None,
            linger: supervisor.linger,
            persistence: supervisor.persistence.clone(),
            prerequisite: supervisor.prerequisite.clone(),
            commands: Vec::new(),
            steps: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn record(&mut self, program: &Path, args: &[&str]) {
        let mut argv = vec![program.display().to_string()];
        argv.extend(args.iter().map(|arg| (*arg).to_string()));
        self.steps.push(format!("ran {}", argv.join(" ")));
        self.commands.push(argv);
    }

    fn step(&mut self, step: impl Into<String>) {
        self.steps.push(step.into());
    }
}

/// The human rendering. Every unknown is printed as `unknown`, never as a guess.
pub fn render(report: &Report) -> String {
    let mut text = String::new();
    let platform = report
        .platform
        .map(Platform::code)
        .unwrap_or("unsupported platform");
    text.push_str(&format!(
        "Ouroboros user service ({platform}, {})\n",
        report.supervisor.code()
    ));
    text.push_str(&format!("  label        {}\n", report.label));
    text.push_str(&format!("  account      {}\n", report.user));
    text.push_str(&format!("  unit         {}\n", report.unit_path));
    text.push_str(&format!("  ownership    {}\n", report.ownership.code()));
    text.push_str(&format!(
        "  runs         {} service-run\n",
        report.executable
    ));
    text.push_str(&format!("  data dir     {}\n", report.data_dir));
    text.push_str(&format!(
        "  installed    {}\n",
        if report.installed { "yes" } else { "no" }
    ));
    text.push_str(&format!("  loaded       {}\n", tri(report.loaded)));
    text.push_str(&format!("  running      {}\n", tri(report.running)));
    text.push_str(&format!(
        "  pid          {}\n",
        report
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    ));
    text.push_str(&format!(
        "  last exit    {}\n",
        report
            .last_exit
            .map(|code| code.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    ));
    text.push_str(&format!("\n{}\n", report.persistence));
    if let Some(prerequisite) = &report.prerequisite {
        text.push_str(&format!("\nPrerequisite: {prerequisite}\n"));
    }
    if !report.notes.is_empty() {
        text.push('\n');
        for note in &report.notes {
            text.push_str(&format!("- {note}\n"));
        }
    }
    text
}

fn tri(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

// ------------------------------------------------------------------- the writing fence

/// An absolute directory that every unit this process writes must live under.
///
/// A test harness sets it to its own scratch root. Nothing in production sets it, and
/// the fence is then the account's own home directory. It exists because a test that
/// builds a [`Plan`] from the *process* environment — the helper's `service` op does
/// exactly that — writes wherever that environment points, and the only place that is
/// never acceptable is the developer's real `~/Library/LaunchAgents`.
pub const SERVICE_ROOT_ENV: &str = "OUROBOROS_SERVICE_ROOT";

fn ensure_inside_service_root(path: &Path) -> Result<()> {
    let Some(root) = std::env::var_os(SERVICE_ROOT_ENV).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return refuse(
            "outside_service_root",
            format!(
                "{SERVICE_ROOT_ENV} must be an absolute path; it names `{}`",
                root.display()
            ),
        );
    }
    let root = canonical_dir(&root);
    let parent = path.parent().unwrap_or(path);
    if !canonical_dir(parent).starts_with(&root) {
        return refuse(
            "outside_service_root",
            format!(
                "{} is outside {SERVICE_ROOT_ENV} ({}), and this process may write a unit only inside it",
                path.display(),
                root.display()
            ),
        );
    }
    Ok(())
}

/// The `Label` a launchd plist declares, read well enough to boot out the job it loaded.
///
/// Deliberately not a plist parser: it finds the `Label` key's string value, and
/// accepts it only if it looks like a launchd label — printable, bounded, no
/// whitespace — because the result becomes an argument to `launchctl`.
fn launchd_label(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let key = text.find("<key>Label</key>")?;
    let rest = &text[key..];
    let start = rest.find("<string>")? + "<string>".len();
    let end = rest[start..].find("</string>")? + start;
    let label = rest[start..end].trim();
    let plausible = !label.is_empty()
        && label.len() <= 256
        && label
            .chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, '/' | '\\'));
    plausible.then(|| label.to_string())
}

// ----------------------------------------------------------------------- the operations

/// Generate the unit, write it, and hand it to the manager.
///
/// `adopt` is the operator's explicit statement that the file already at our unit path
/// may be replaced. Without it, anything this code did not write is preserved untouched.
pub fn install(plan: &Plan, programs: &Programs, adopt: bool) -> Result<Report> {
    let supervisor = detect_as(Some(plan.platform), &plan.user, programs);
    let mut report = Report::new("install", plan, &supervisor);
    if supervisor.code == SupervisorCode::Unsupported {
        return refuse(
            "unsupported",
            supervisor
                .prerequisite
                .unwrap_or_else(|| "this machine has no user supervisor".to_string()),
        );
    }
    if crate::fleet::load(&plan.data_dir)?.is_none() {
        return refuse(
            "no_fleet",
            format!(
                "{} has no cluster identity, and `ouro service-run` refuses to start without one. Run `ouro fleet create` first; a unit installed now would only crash-loop",
                plan.data_dir.display()
            ),
        );
    }

    let (ownership, digest) = classify(plan)?;
    report.ownership = ownership;
    let mut replaced_label: Option<String> = None;
    match ownership {
        Ownership::Absent | Ownership::Ours => {}
        Ownership::Modified if adopt => report.notes.push(format!(
            "adopted an edited copy of this machine's own unit (body sha256 {}) and replaced it",
            digest.clone().unwrap_or_else(|| "unknown".to_string())
        )),
        Ownership::Foreign if adopt => {
            replaced_label = launchd_label(&plan.unit_path());
            report.notes.push(format!(
                "adopted a preexisting unit this code did not write (sha256 {}) and replaced it",
                digest.clone().unwrap_or_else(|| "unknown".to_string())
            ));
        }
        Ownership::Modified => {
            return refuse(
                "unit_modified",
                format!(
                    "{} carries this machine's ownership marker but its body no longer matches the digest in it, so somebody edited it by hand. Inspect it and rerun with `--adopt` to replace it",
                    plan.unit_path().display()
                ),
            )
        }
        Ownership::Foreign => {
            return refuse(
                "unit_foreign",
                format!(
                    "{} already exists and was not written by Ouroboros (sha256 {}). It has been left exactly as it is; inspect it and rerun with `--adopt` if it should be replaced",
                    plan.unit_path().display(),
                    digest.unwrap_or_else(|| "unreadable".to_string())
                ),
            )
        }
    }

    let lock = crate::runtime::acquire_spawn_lock(&canonical_dir(&plan.data_dir))?;
    let owner = crate::runtime::read_live_runtime_owner(&canonical_dir(&plan.data_dir))?;
    // Report an existing owner even when an unchanged, loaded service is preserved.
    if let Some(owner) = &owner {
        report.notes.push(format!(
            "a runtime already owns this data directory (pid {})",
            owner.pid
        ));
    }

    let text = plan.render()?;
    let unit_path = plan.unit_path();
    ensure_inside_service_root(&unit_path)?;
    prepare_log(&plan.out_log())?;
    prepare_log(&plan.err_log())?;
    if ownership == Ownership::Ours && fs::read_to_string(&unit_path)? == text {
        inspect_manager(plan, programs, &mut report)?;
        if report.loaded == Some(true) {
            report.installed = true;
            report
                .notes
                .push("the matching service is already loaded; it was left running".into());
            return Ok(report);
        }
    }
    // Replacing a managed unit can signal its runtime. Installation is not approval
    // for a restart, and the spawn lock closes the gap between this check and handoff.
    if owner.is_some() && ownership != Ownership::Absent {
        return refuse("runtime_running", "a runtime owns this data directory; the existing service was not replaced. Stop it with `ouro stop --require-idle`, then install again");
    }
    if owner.is_some() && plan.platform == Platform::MacOs {
        inspect_manager(plan, programs, &mut report)?;
        if report.loaded != Some(false) {
            return refuse("runtime_running", "a runtime owns this data directory and its service may be loaded; stop it with `ouro stop --require-idle` before replacing the service");
        }
    }
    write_private_atomic(&unit_path, text.as_bytes())?;
    report.step(format!("wrote {}", unit_path.display()));
    report.installed = true;
    report.ownership = Ownership::Ours;

    // If the manager will not take it, this call must not leave a RunAtLoad unit behind
    // for the next login. Only what this call created is removed: a unit of ours that
    // was already here is left, and the refusal names `remove`.
    let handoff = hand_to_manager(
        plan,
        programs,
        adopt,
        replaced_label.as_deref(),
        &mut report,
        lock,
    );
    if let Err(error) = handoff {
        if ownership == Ownership::Absent {
            let _ = fs::remove_file(&unit_path);
            report.step(format!("removed {}", unit_path.display()));
            return Err(error.context(format!(
                "the unit this call wrote was removed again, so nothing starts at the next login; {} is as it was",
                unit_path.display()
            )));
        }
        return Err(error.context(format!(
            "{} is on disk and will be used at the next login; run `ouro fleet service remove` if that is not what you want",
            unit_path.display()
        )));
    }

    inspect_manager(plan, programs, &mut report)?;
    Ok(report)
}

/// Hand the freshly written unit to the service manager.
fn hand_to_manager(
    plan: &Plan,
    programs: &Programs,
    adopt: bool,
    replaced_label: Option<&str>,
    report: &mut Report,
    lock: crate::runtime::SpawnLock,
) -> Result<()> {
    match plan.platform {
        Platform::MacOs => {
            let target = plan.manager_name();
            let domain = plan.domain();
            // Idempotent by construction: a service already bootstrapped from an older
            // copy of this file has to be booted out before the new one can replace it,
            // and a `bootout` of something that is not loaded is not an error here.
            report.record(&programs.launchctl, &["bootout", target.as_str()]);
            let _ = run(
                &programs.launchctl,
                &["bootout", target.as_str()],
                programs.deadline,
            );
            // The file being replaced may have loaded a job under its *own* label.
            // Booting out only ours would leave that job running with no file behind it.
            if adopt {
                if let Some(label) = replaced_label {
                    let orphan = format!("gui/{}/{label}", plan.uid);
                    report.record(&programs.launchctl, &["bootout", orphan.as_str()]);
                    let _ = run(
                        &programs.launchctl,
                        &["bootout", orphan.as_str()],
                        programs.deadline,
                    );
                    report.notes.push(format!(
                        "the unit replaced here had loaded the job `{label}`; it was booted out too, so nothing is left running without a file behind it"
                    ));
                }
            }
            let plist = plan.unit_path();
            let plist = plist.to_str().ok_or_else(|| {
                ServiceError::new("unusable_path", "the unit path is not valid UTF-8")
            })?;
            // No more stops after this point. The newly bootstrapped service needs
            // the spawn lock itself, so do not launch it while holding that lock.
            drop(lock);
            report.record(&programs.launchctl, &["bootstrap", domain.as_str(), plist]);
            let outcome = run(
                &programs.launchctl,
                &["bootstrap", domain.as_str(), plist],
                programs.deadline,
            )?;
            if outcome.status != Some(0) {
                return refuse(
                    "manager_refused",
                    format!(
                        "`launchctl bootstrap {domain}` refused {}: {}",
                        plan.label(),
                        first_line(&outcome.stderr, &outcome.stdout)
                    ),
                );
            }
        }
        Platform::Linux => {
            drop(lock);
            let unit = plan.manager_name();
            for args in [
                vec!["--user", "daemon-reload"],
                vec!["--user", "enable", "--now", unit.as_str()],
            ] {
                report.record(&programs.systemctl, &args);
                let outcome = run(&programs.systemctl, &args, programs.deadline)?;
                if outcome.status != Some(0) {
                    return refuse(
                        "manager_refused",
                        format!(
                            "`systemctl {}` refused: {}",
                            args.join(" "),
                            first_line(&outcome.stderr, &outcome.stdout)
                        ),
                    );
                }
            }
        }
    }
    Ok(())
}

/// What is installed and what the manager says about it. Changes nothing.
pub fn status(plan: &Plan, programs: &Programs) -> Result<Report> {
    let supervisor = detect_as(Some(plan.platform), &plan.user, programs);
    let mut report = Report::new("status", plan, &supervisor);
    let (ownership, digest) = classify(plan)?;
    report.ownership = ownership;
    report.installed = ownership.is_ours();
    if ownership == Ownership::Foreign {
        report.notes.push(format!(
            "{} exists and was not written by Ouroboros (sha256 {}); it is reported and otherwise untouched",
            plan.unit_path().display(),
            digest.clone().unwrap_or_else(|| "unreadable".to_string())
        ));
    }
    if ownership == Ownership::Modified {
        report.notes.push(format!(
            "{} is this machine's own unit, edited since it was written (body sha256 {})",
            plan.unit_path().display(),
            digest.unwrap_or_else(|| "unreadable".to_string())
        ));
    }
    // Units for the same data directory under another spelling. A plan is canonical
    // now, but one written by an older `ouro` — or by hand from a path with a trailing
    // slash — is a second RunAtLoad service for one runtime, and only a scan finds it.
    for duplicate in duplicate_units(plan) {
        report.notes.push(format!(
            "{} is another managed unit for this same data directory; two of them supervise one runtime. Remove the one you do not want",
            duplicate.display()
        ));
    }
    // The manager appends to these and creates them at its own umask if they are gone.
    if ownership.is_ours() {
        relog(plan, &mut report);
    }
    if supervisor.code == SupervisorCode::Unsupported {
        report.notes.push(
            "the manager could not be asked, so loaded/running/last exit are unknown".to_string(),
        );
        return Ok(report);
    }
    inspect_manager(plan, programs, &mut report)?;
    Ok(report)
}

/// Stop the service and stop it respawning, without removing anything.
pub fn disable(plan: &Plan, programs: &Programs) -> Result<Report> {
    let supervisor = detect_as(Some(plan.platform), &plan.user, programs);
    let mut report = Report::new("disable", plan, &supervisor);
    let (ownership, _digest) = classify(plan)?;
    report.ownership = ownership;
    report.installed = ownership.is_ours();
    if ownership == Ownership::Foreign {
        return refuse(
            "unit_foreign",
            format!(
                "{} was not written by Ouroboros, so this will not stop what it supervises. Use the manager directly if that is what you meant",
                plan.unit_path().display()
            ),
        );
    }
    // A unit we never installed is not this verb's business: a runtime the operator
    // started by hand stays running. Gate-then-disable applies only to a unit we own.
    if ownership == Ownership::Absent {
        report.notes.push(format!(
            "{} is not installed, so nothing was disabled. A runtime this account started by hand was left running",
            plan.unit_path().display()
        ));
        return Ok(report);
    }
    if supervisor.code == SupervisorCode::Unsupported {
        return refuse(
            "unsupported",
            supervisor
                .prerequisite
                .unwrap_or_else(|| "this machine has no user supervisor".to_string()),
        );
    }
    // A supervisor stop signals its child. Authorize and observe the idle shutdown
    // first, and retain the spawn lock so a restart cannot publish new work in between.
    let lock = crate::runtime::acquire_spawn_lock(&plan.data_dir)?;
    stop_idle_under_lock(plan, &lock)?;
    disable_with_manager(plan, programs, &mut report)?;
    inspect_manager(plan, programs, &mut report)?;
    Ok(report)
}

/// Disable, then delete the one file this code wrote. Nothing else is touched.
pub fn remove(plan: &Plan, programs: &Programs) -> Result<Report> {
    let supervisor = detect_as(Some(plan.platform), &plan.user, programs);
    let mut report = Report::new("remove", plan, &supervisor);
    let (ownership, digest) = classify(plan)?;
    report.ownership = ownership;
    match ownership {
        Ownership::Foreign => {
            return refuse(
                "unit_foreign",
                format!(
                    "{} was not written by Ouroboros (sha256 {}); it has been left exactly as it is. Remove it yourself if that is what you meant",
                    plan.unit_path().display(),
                    digest.unwrap_or_else(|| "unreadable".to_string())
                ),
            )
        }
        Ownership::Absent => {
            report.notes.push(format!(
                "{} did not exist; nothing was removed",
                plan.unit_path().display()
            ));
        }
        Ownership::Ours | Ownership::Modified => {}
    }

    if ownership == Ownership::Modified {
        // Still ours — our marker, our data directory — so it goes. But an operator who
        // edited it is owed the digest of what is about to be deleted.
        report.notes.push(format!(
            "the unit removed here no longer matched the digest in its own marker (body sha256 {}): it had been edited since this code wrote it",
            digest.unwrap_or_else(|| "unreadable".to_string())
        ));
    }

    // Gate first, then disable: a manager stop signals its child, and a working
    // runtime is not something this verb SIGTERMs. The spawn lock is held through
    // file removal so a restart cannot republish between the idle check and the
    // unlink. `NotRunning` / `RemovedStale` are success — nothing here to stop.
    let lock = crate::runtime::acquire_spawn_lock(&plan.data_dir)?;
    stop_idle_under_lock(plan, &lock)?;

    // Disabling first is the order the proposal asks for: a unit removed while its
    // manager still supervises it comes straight back.
    let disabled = if supervisor.code != SupervisorCode::Unsupported {
        disable_with_manager(plan, programs, &mut report)
    } else {
        report.notes.push(
            "no user supervisor answered, so the unit file was removed and nothing was stopped"
                .to_string(),
        );
        Ok(())
    };
    // A manager that refuses the disable must not make the unit impossible to delete: a
    // file left on disk comes back at the next login, which is the worse of the two
    // outcomes. The file goes, and the operator is told exactly what is still loaded.
    if let Err(error) = &disabled {
        report.notes.push(format!(
            "the service manager refused to stop this unit ({error}); the file was removed anyway, so nothing starts at the next login. Whatever is still loaded now has to be stopped by hand: `{}`",
            match plan.platform {
                Platform::MacOs => format!("launchctl bootout {}", plan.manager_name()),
                Platform::Linux => format!("systemctl --user disable --now {}", plan.manager_name()),
            }
        ));
    }

    if ownership.is_ours() {
        let path = plan.unit_path();
        ensure_inside_service_root(&path)?;
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        report.step(format!("removed {}", path.display()));
        report.notes.push(format!("removed {}", path.display()));
    }
    report.installed = false;
    report.ownership = Ownership::Absent;

    if plan.platform == Platform::Linux {
        // `systemctl --user enable` installs a symlink under `default.target.wants`.
        // Without a manager to tell, the symlink outlives the unit and the next
        // `daemon-reload` reports a dangling want forever.
        let wants = plan
            .config_home
            .join("systemd")
            .join("user")
            .join("default.target.wants")
            .join(plan.manager_name());
        if fs::symlink_metadata(&wants).is_ok_and(|metadata| metadata.file_type().is_symlink())
            && fs::remove_file(&wants).is_ok()
        {
            report.step(format!("removed {}", wants.display()));
            report.notes.push(format!("removed {}", wants.display()));
        }
        if supervisor.code != SupervisorCode::Unsupported {
            let args = ["--user", "daemon-reload"];
            report.record(&programs.systemctl, &args);
            let _ = run(&programs.systemctl, &args, programs.deadline);
        }
    }
    report.loaded = Some(false);
    report.running = Some(false);
    drop(lock);
    Ok(report)
}

/// Ask the published runtime to stop, idle, under a lock the caller already holds.
///
/// `NotRunning` and `RemovedStale` are `Ok`: there is nothing here to stop, which is
/// the state both `disable` and `remove` asked for. A busy or unknown runtime keeps
/// the gateway's reason so nothing is unlinked behind a refusal.
fn stop_idle_under_lock(
    plan: &Plan,
    lock: &crate::runtime::SpawnLock,
) -> Result<crate::fleet_setup::gateway::StopOutcome> {
    crate::fleet_setup::gateway::stop_require_idle_locked(
        &plan.data_dir,
        &plan.data_dir.join("gateway.token"),
        lock,
    )
    .map_err(|error| {
        ServiceError::new(
            crate::fleet_setup::reason_of(&error).unwrap_or("shutdown_unavailable"),
            error.to_string(),
        )
        .into()
    })
}

/// Other units in this plan's own unit directory that carry our marker for the same
/// data directory under a different spelling.
fn duplicate_units(plan: &Plan) -> Vec<PathBuf> {
    let unit_path = plan.unit_path();
    let Some(directory) = unit_path.parent() else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let ours = canonical_dir(&plan.data_dir);
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path == unit_path || !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let Some(marker) = read_marker(plan.platform, &text) else {
            continue;
        };
        if canonical_dir(Path::new(&marker.data_dir)) == ours {
            found.push(path);
        }
    }
    found.sort();
    found
}

/// Put the service's own logs back if they are gone. Log rotation and an operator
/// clearing space both remove them, and the manager recreates them at its own umask —
/// which is how a private log becomes a world-readable one.
fn relog(plan: &Plan, report: &mut Report) {
    for path in [plan.out_log(), plan.err_log()] {
        if path.exists() {
            continue;
        }
        match prepare_log(&path) {
            Ok(()) => report.notes.push(format!(
                "{} was missing and has been recreated private; the service manager would have created it at its own umask",
                path.display()
            )),
            Err(error) => report
                .notes
                .push(format!("{} could not be recreated: {error:#}", path.display())),
        }
    }
}

/// Start an installed unit through its manager.
pub fn start(plan: &Plan, programs: &Programs) -> Result<Report> {
    let supervisor = detect_as(Some(plan.platform), &plan.user, programs);
    let mut report = Report::new("start", plan, &supervisor);
    let (ownership, _digest) = classify(plan)?;
    report.ownership = ownership;
    report.installed = ownership.is_ours();
    if supervisor.code == SupervisorCode::Unsupported {
        return refuse(
            "unsupported",
            supervisor
                .prerequisite
                .unwrap_or_else(|| "this machine has no user supervisor".to_string()),
        );
    }
    if !ownership.is_ours() {
        return refuse(
            "not_installed",
            format!(
                "{} is not a unit this code wrote, so there is nothing of ours to start",
                plan.unit_path().display()
            ),
        );
    }
    relog(plan, &mut report);
    let (program, args) = match plan.platform {
        Platform::MacOs => (
            &programs.launchctl,
            vec!["kickstart".to_string(), plan.manager_name()],
        ),
        Platform::Linux => (
            &programs.systemctl,
            vec![
                "--user".to_string(),
                "start".to_string(),
                plan.manager_name(),
            ],
        ),
    };
    let borrowed = args.iter().map(String::as_str).collect::<Vec<_>>();
    report.record(program, &borrowed);
    let outcome = run(program, &borrowed, programs.deadline)
        .map_err(|error| ServiceError::new("manager_unavailable", error.to_string()))?;
    if outcome.status != Some(0) {
        return refuse(
            "manager_refused",
            format!(
                "starting {} failed: {}",
                plan.label(),
                first_line(&outcome.stderr, &outcome.stdout)
            ),
        );
    }
    inspect_manager(plan, programs, &mut report)?;
    Ok(report)
}

fn disable_with_manager(plan: &Plan, programs: &Programs, report: &mut Report) -> Result<()> {
    match plan.platform {
        Platform::MacOs => {
            let target = plan.manager_name();
            let args = ["bootout", target.as_str()];
            report.record(&programs.launchctl, &args);
            let outcome = run(&programs.launchctl, &args, programs.deadline)
                .map_err(|error| ServiceError::new("manager_unavailable", error.to_string()))?;
            // `bootout` of something that is not loaded is the state that was asked for.
            if outcome.status != Some(0) && !not_loaded(&outcome) {
                return refuse(
                    "manager_refused",
                    format!(
                        "`launchctl bootout {target}` failed: {}",
                        first_line(&outcome.stderr, &outcome.stdout)
                    ),
                );
            }
        }
        Platform::Linux => {
            let unit = plan.manager_name();
            let args = ["--user", "disable", "--now", unit.as_str()];
            report.record(&programs.systemctl, &args);
            let outcome = run(&programs.systemctl, &args, programs.deadline)
                .map_err(|error| ServiceError::new("manager_unavailable", error.to_string()))?;
            if outcome.status != Some(0) {
                return refuse(
                    "manager_refused",
                    format!(
                        "`systemctl --user disable --now {unit}` failed: {}",
                        first_line(&outcome.stderr, &outcome.stdout)
                    ),
                );
            }
        }
    }
    Ok(())
}

/// Ask the manager what it knows, leaving anything it did not say as `None`.
fn inspect_manager(plan: &Plan, programs: &Programs, report: &mut Report) -> Result<()> {
    match plan.platform {
        Platform::MacOs => {
            let target = plan.manager_name();
            let args = ["print", target.as_str()];
            report.record(&programs.launchctl, &args);
            match run(&programs.launchctl, &args, programs.deadline) {
                Ok(outcome) if outcome.status == Some(0) => {
                    let printed = parse_launchctl_print(&outcome.stdout);
                    report.loaded = Some(true);
                    report.running = printed.state.as_deref().map(|state| state == "running");
                    report.pid = printed.pid;
                    report.last_exit = printed.last_exit;
                }
                Ok(_) => {
                    report.loaded = Some(false);
                    report.running = Some(false);
                }
                Err(error) => report
                    .notes
                    .push(format!("launchctl could not be asked: {error}")),
            }
        }
        Platform::Linux => {
            let unit = plan.manager_name();
            let args = [
                "--user",
                "show",
                unit.as_str(),
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
                "--property=ExecMainStatus",
                "--property=UnitFileState",
            ];
            report.record(&programs.systemctl, &args);
            match run(&programs.systemctl, &args, programs.deadline) {
                Ok(outcome) if outcome.status == Some(0) => {
                    let shown = parse_systemctl_show(&outcome.stdout);
                    report.loaded = shown.get("LoadState").map(|state| state == "loaded");
                    report.running = shown.get("SubState").map(|state| state == "running");
                    report.pid = shown
                        .get("MainPID")
                        .and_then(|pid| pid.parse::<u32>().ok())
                        .filter(|pid| *pid != 0);
                    report.last_exit = shown
                        .get("ExecMainStatus")
                        .and_then(|code| code.parse::<i64>().ok());
                }
                Ok(_) => {
                    report.loaded = Some(false);
                    report.running = Some(false);
                }
                Err(error) => report
                    .notes
                    .push(format!("systemctl could not be asked: {error}")),
            }
        }
    }
    Ok(())
}

// -------------------------------------------------------------------- manager output

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LaunchctlPrint {
    pub state: Option<String>,
    pub pid: Option<u32>,
    pub last_exit: Option<i64>,
}

/// Reads the handful of facts `launchctl print` states, and nothing it does not.
///
/// launchd prints `last exit code = (never exited)` for a job it has not yet run: that
/// is an absence, and it stays `None` rather than becoming a zero.
pub fn parse_launchctl_print(text: &str) -> LaunchctlPrint {
    let mut printed = LaunchctlPrint::default();
    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "state" if printed.state.is_none() => printed.state = Some(value.to_string()),
            "pid" if printed.pid.is_none() => printed.pid = value.parse().ok(),
            "last exit code" if printed.last_exit.is_none() => {
                printed.last_exit = value.parse().ok()
            }
            _ => {}
        }
    }
    printed
}

/// `systemctl show --property=…` prints one `Key=Value` per line.
pub fn parse_systemctl_show(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn property(text: &str, key: &str) -> Option<String> {
    parse_systemctl_show(text).get(key).cloned()
}

fn not_loaded(outcome: &Outcome) -> bool {
    let text = format!("{} {}", outcome.stdout, outcome.stderr).to_ascii_lowercase();
    text.contains("no such process") || text.contains("could not find service")
}

/// The manager's own words, made safe to print.
///
/// This text reaches a terminal and a `--json` document. A service manager's stderr is
/// not a trusted string: it can carry ANSI escapes that rewrite the line above it, and
/// on a bad day it can carry a megabyte. Control characters (C0, DEL and the C1 range)
/// are dropped and the result is capped.
fn first_line(stderr: &str, stdout: &str) -> String {
    let line = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("the manager said nothing");
    sanitize_manager_text(line)
}

/// The longest run of a manager's own words this code will repeat.
const MAX_MANAGER_LINE: usize = 500;

fn sanitize_manager_text(text: &str) -> String {
    let mut clean = String::with_capacity(text.len().min(MAX_MANAGER_LINE));
    let mut kept = 0;
    for character in text.chars() {
        if kept >= MAX_MANAGER_LINE {
            clean.push('\u{2026}');
            break;
        }
        // C0, DEL and the C1 block. `char::is_control` covers exactly these.
        if character.is_control() {
            continue;
        }
        clean.push(character);
        kept += 1;
    }
    clean
}

// ------------------------------------------------------------------------- running them

#[derive(Clone, Debug, Default)]
struct Outcome {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Runs one manager command with a fixed argument array, under a deadline.
///
/// Nothing from a request is ever a shell string: these are argv arrays built here from
/// constants and from values this module derived, and there is no shell in the path.
fn run(program: &Path, args: &[&str], deadline: Duration) -> Result<Outcome> {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Its own process group, so the deadline below can end the whole tree. Killing the
    // immediate child alone leaves anything it spawned holding the pipes, and the
    // reader thread then blocks on a stdout that never closes — the deadline fires and
    // the process stays resident anyway.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("starting {}", program.display()))?;
    let pid = child.id() as libc::pid_t;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("stdout was not piped for {}", program.display()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("stderr was not piped for {}", program.display()))?;

    // Bound the read itself so a manager that prints a novel cannot grow this process
    // to the size of that novel. `wait_with_output` would hold every byte until the
    // child exits; `take` stops at the cap the same way the Tailscale adapter does.
    let stdout_reader = std::thread::Builder::new()
        .name("ouro-service-stdout".to_string())
        .spawn(move || read_bounded(stdout))
        .context("starting the stdout reader for a service-manager command")?;
    let stderr_reader = std::thread::Builder::new()
        .name("ouro-service-stderr".to_string())
        .spawn(move || read_bounded(stderr))
        .context("starting the stderr reader for a service-manager command")?;

    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("ouro-service-manager".to_string())
        .spawn(move || {
            let _ = sender.send(child.wait());
        })
        .context("starting the waiter for a service-manager command")?;

    match receiver.recv_timeout(deadline) {
        Ok(Ok(status)) => Ok(Outcome {
            status: status.code(),
            stdout: join_bounded(stdout_reader, "stdout")?,
            stderr: join_bounded(stderr_reader, "stderr")?,
        }),
        Ok(Err(error)) => Err(error).with_context(|| format!("waiting for {}", program.display())),
        Err(_) => {
            // The waiter still owns the child, so the deadline is enforced by
            // signalling the group rather than by dropping a handle we do not hold.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
            // Give the group a moment to die so the readers can finish, then leave it:
            // a manager that ignores SIGKILL is not something this client waits on.
            let _ = receiver.recv_timeout(Duration::from_secs(2));
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            Err(ServiceError::new(
                "manager_unavailable",
                format!(
                    "{} stopped answering: it was given {} seconds and then its process group was killed. The service manager on this machine is not responding; nothing was changed",
                    program.display(),
                    deadline.as_secs()
                ),
            )
            .into())
        }
    }
}

fn read_bounded(reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader
        .take(MAX_MANAGER_OUTPUT as u64)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

fn join_bounded(
    handle: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> Result<String> {
    match handle.join() {
        Ok(Ok(bytes)) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Ok(Err(error)) => Err(error).with_context(|| format!("reading service-manager {stream}")),
        Err(_) => Err(anyhow!(
            "the service-manager {stream} reader stopped unexpectedly"
        )),
    }
}

// ------------------------------------------------------------------------ private files

/// The service's log file, created private before the manager can create it at the
/// manager's own umask. launchd and systemd both append to a file that already exists.
fn prepare_log(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            // An existing log is re-privatised rather than trusted: the manager may have
            // created it at its own umask between two installs.
            if metadata.uid() != unsafe { libc::geteuid() } {
                return refuse(
                    "unusable_path",
                    format!("{} is not owned by this account", path.display()),
                );
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("making {} private", path.display()))
        }
        Ok(metadata) if metadata.file_type().is_symlink() => refuse(
            "unusable_path",
            format!(
                "{} is a symbolic link, and a service log is never written through one; whatever it points at was not touched",
                path.display()
            ),
        ),
        Ok(_) => refuse(
            "unusable_path",
            format!(
                "{} exists and is not a regular file; the service log will not be redirected over it",
                path.display()
            ),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // `create_new` is `O_EXCL`, which already refuses an existing path of any
            // kind, symlink included; `O_NOFOLLOW` is belt and braces beside it and
            // cannot be provoked on its own from a test, because there is no path that
            // reaches it which `O_EXCL` would not have refused first. It stays because
            // the two flags fail closed on different kernels' edge cases, and removing
            // one leaves the other carrying an assumption nobody wrote down.
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .with_context(|| format!("creating private service log {}", path.display()))?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ouroboros-unit");
    let temporary = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        random_hex(6)?
    ));
    // Same pairing as `prepare_log`: `create_new` is `O_EXCL` on a name nothing else
    // knows, and `O_NOFOLLOW` beside it is belt and braces rather than a separately
    // reachable check. The rename that follows replaces whatever is at `path` — a
    // symlink included — as a link, never writing through it.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("writing {}", path.display()));
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        // A directory where a file goes is the one case worth its own code: `rename`
        // reports `EISDIR`/`ENOTDIR` and an operator needs to be told what is there
        // rather than shown an errno.
        if path.is_dir() {
            return refuse(
                "unit_path_is_a_directory",
                format!(
                    "{} is a directory, and this code will not delete a directory to put a unit file there. Move it aside yourself",
                    path.display()
                ),
            );
        }
        return Err(error).with_context(|| format!("publishing {}", path.display()));
    }
    File::open(parent)
        .with_context(|| format!("opening {} for sync", parent.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", parent.display()))
}

// ------------------------------------------------------------------ the idle-gated stop

/// How `ouro stop --require-idle` ends when the runtime refuses.
///
/// Distinct codes, because the two refusals are different facts: the runtime said it is
/// working, or the runtime could not establish what it is doing. A script that retries
/// the first must not retry the second without looking.
pub const EXIT_RUNTIME_BUSY: u8 = 10;
pub const EXIT_ACTIVITY_UNKNOWN: u8 = 11;
/// The runtime does not serve the read method the gate is built on, so it cannot have
/// checked anything. A stop that looked like an idle-gated stop and was not is worse
/// than a refusal, because the deployment engine relies on this flag to decide it may
/// restart a machine.
pub const EXIT_IDLE_GATE_UNSUPPORTED: u8 = 12;
/// The connection closed before the runtime answered an idle-gated stop. It may have
/// stopped, it may have refused; a gate whose outcome is unknown is not a pass.
pub const EXIT_IDLE_OUTCOME_UNKNOWN: u8 = 13;

/// A `runtime.shutdown` refusal, rendered for a person and carrying its exit code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopRefusal {
    pub reason: String,
    pub exit_code: u8,
    pub rendered: String,
}

/// Maps the C2 refusal into an exit code and a page. `None` for anything that is not
/// one of the two idle refusals, which the caller then reports as an ordinary failure.
pub fn stop_refusal(
    code: crate::proto::ErrorCode,
    data: Option<&serde_json::Value>,
) -> Option<StopRefusal> {
    // Seam C2 names the code as well as the reason. A `reason` field on some other
    // error — a method-not-found from an older runtime, say — is not this refusal, and
    // reporting it as one would tell an operator their runtime is busy when it is not.
    if code != crate::proto::ErrorCode::Unavailable {
        return None;
    }
    let data = data?;
    let reason = data.get("reason")?.as_str()?;
    let exit_code = match reason {
        "runtime_busy" => EXIT_RUNTIME_BUSY,
        "activity_unknown" => EXIT_ACTIVITY_UNKNOWN,
        _ => return None,
    };
    let activity = data.get("activity");
    let mut rendered = match reason {
        "runtime_busy" => {
            "the runtime refused an idle-gated stop: it is still working\n".to_string()
        }
        _ => "the runtime refused an idle-gated stop: it could not establish what it is doing, and unknown activity does not authorize a stop\n".to_string(),
    };
    rendered.push_str(&render_activity(activity));
    Some(StopRefusal {
        reason: reason.to_string(),
        exit_code,
        rendered,
    })
}

/// The C2 activity summary as a block a person reads. Anything the runtime could not
/// establish prints `unknown`.
pub fn render_activity(activity: Option<&serde_json::Value>) -> String {
    let Some(activity) = activity else {
        return "  activity     the runtime sent no summary\n".to_string();
    };
    let mut text = String::new();
    for (label, field) in [
        ("running turns", "running_turns"),
        ("queued turns", "queued_turns"),
        ("image transfers", "attachment_transfers"),
        ("image preparation", "attachment_normalizations"),
        ("operator clients", "operator_clients"),
    ] {
        let value = activity
            .get(field)
            .and_then(serde_json::Value::as_i64)
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        text.push_str(&format!("  {label:<18} {value}\n"));
    }
    if let Some(unknown) = activity.get("unknown").and_then(|value| value.as_array()) {
        if !unknown.is_empty() {
            let names = unknown
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            text.push_str(&format!("  could not read     {names}\n"));
        }
    }
    text
}

// ---------------------------------------------------------------- waiting for a network

/// The first retry interval, doubling to [`NETWORK_WAIT_MAX`].
pub const NETWORK_WAIT_INITIAL: Duration = Duration::from_secs(1);
pub const NETWORK_WAIT_MAX: Duration = Duration::from_secs(15);
/// How often the wait says it is still waiting, after the line it prints at the start.
pub const NETWORK_WAIT_REPORT_EVERY: Duration = Duration::from_secs(60);

/// The throttled schedule: 1s, 2s, 4s, 8s, 15s, 15s, …
pub fn network_wait_backoff(attempt: u32) -> Duration {
    let doubled = NETWORK_WAIT_INITIAL
        .checked_mul(1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX))
        .unwrap_or(NETWORK_WAIT_MAX);
    doubled.min(NETWORK_WAIT_MAX)
}

/// The real probe: exactly the bind check `ouro fleet create` and a join already make,
/// on an ephemeral port that is dropped immediately.
pub fn probe_bindable(host: &str) -> Result<std::net::Ipv4Addr> {
    crate::fleet::ensure_local_bind_address(host)
}

/// Waits until this machine's advertised private address can be bound, reporting the
/// wait to the service log.
///
/// The caller selects this against SIGTERM; dropping it stops the wait where it stands,
/// having touched no credentials, no membership and no work.
pub async fn wait_for_network(host: &str) {
    wait_for_bindable_host(
        host,
        probe_bindable,
        |line| eprintln!("{line}"),
        tokio::time::sleep,
    )
    .await;
}

/// The wait itself, with its probe, its log sink and its sleeper handed in.
///
/// Elapsed time is the sum of the intervals this loop asked to sleep rather than a
/// clock reading, which is what makes "say so once a minute" mean the same thing in a
/// test as it does on a machine whose network is down.
pub async fn wait_for_bindable_host<P, L, S, F>(host: &str, mut probe: P, mut log: L, mut sleep: S)
where
    P: FnMut(&str) -> Result<std::net::Ipv4Addr>,
    L: FnMut(String),
    S: FnMut(Duration) -> F,
    F: std::future::Future<Output = ()>,
{
    let mut attempt = 0u32;
    let mut waited = Duration::ZERO;
    let mut reported = Duration::ZERO;
    loop {
        match probe(host) {
            Ok(_address) => {
                if attempt > 0 {
                    log(format!(
                        "ouro service: network ready; `{host}` is bindable after {}s of waiting",
                        waited.as_secs()
                    ));
                }
                return;
            }
            Err(error) => {
                if attempt == 0 {
                    log(format!(
                        "ouro service: waiting for network; `{host}` is not bindable on this machine yet ({error:#}). Retrying, and saying so once a minute; nothing has been changed"
                    ));
                } else if waited.saturating_sub(reported) >= NETWORK_WAIT_REPORT_EVERY {
                    reported = waited;
                    log(format!(
                        "ouro service: waiting for network; `{host}` still not bindable after {}s",
                        waited.as_secs()
                    ));
                }
            }
        }
        let interval = network_wait_backoff(attempt);
        sleep(interval).await;
        waited = waited.saturating_add(interval);
        attempt = attempt.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;

    fn plan(platform: Platform) -> Plan {
        let home = match platform {
            Platform::MacOs => PathBuf::from("/Users/tester"),
            Platform::Linux => PathBuf::from("/home/tester"),
        };
        Plan {
            platform,
            data_dir: home.join(".ouroboros"),
            executable: PathBuf::from("/usr/local/bin/ouro"),
            home: home.clone(),
            config_home: home.join(".config"),
            uid: 501,
            user: "tester".to_string(),
        }
    }

    #[test]
    fn a_known_manager_location_is_preferred_to_path() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "ouro-manager-locate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("a scratch dir");
        let on_path = root.join("launchctl");
        fs::write(&on_path, "#!/bin/sh\n").expect("a path candidate");
        fs::set_permissions(&on_path, fs::Permissions::from_mode(0o755)).expect("executable");
        let known = root.join("known-launchctl");
        fs::write(&known, "#!/bin/sh\n").expect("a known candidate");
        fs::set_permissions(&known, fs::Permissions::from_mode(0o755)).expect("executable");

        let found = locate_manager_program_with(
            &[known.to_str().expect("utf-8")],
            "launchctl",
            Some(root.as_os_str()),
        );
        assert_eq!(found, known);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_launchagent_runs_service_run_and_never_the_detaching_daemon() {
        let plan = plan(Platform::MacOs);
        let text = plan.render().expect("a rendered plist");

        assert!(
            text.contains("<string>/usr/local/bin/ouro</string>\n\t\t<string>service-run</string>"),
            "{text}"
        );
        assert!(
            !text.contains("<string>daemon</string>"),
            "a unit that names `ouro daemon` would supervise a process that detaches: {text}"
        );
        assert!(text.contains("<key>RunAtLoad</key>"), "{text}");
        assert!(
            text.contains("<key>ThrottleInterval</key>\n\t<integer>30</integer>"),
            "{text}"
        );
        assert!(text.contains("<string>Adaptive</string>"), "{text}");
        assert!(
            text.contains("<string>/Users/tester/.ouroboros/service.err.log</string>"),
            "{text}"
        );
    }

    #[test]
    fn a_systemd_user_unit_restarts_on_failure_with_a_start_limit_and_wants_default_target() {
        let plan = plan(Platform::Linux);
        let text = plan.render().expect("a rendered unit");

        assert!(
            text.contains("ExecStart=\"/usr/local/bin/ouro\" service-run"),
            "{text}"
        );
        assert!(text.contains("Restart=on-failure"), "{text}");
        assert!(text.contains("RestartSec=5"), "{text}");
        assert!(text.contains("StartLimitIntervalSec=300"), "{text}");
        assert!(text.contains("StartLimitBurst=5"), "{text}");
        assert!(text.contains("WantedBy=default.target"), "{text}");
        assert!(
            text.contains("WorkingDirectory=\"/home/tester/.ouroboros\""),
            "{text}"
        );
    }

    /// A plan whose every path carries something the two unit formats treat specially.
    fn awkward_plan(platform: Platform) -> Plan {
        let mut plan = plan(platform);
        plan.home = PathBuf::from("/home/my user");
        plan.data_dir = PathBuf::from("/srv/my data/%h/a\"quoted\"/state");
        plan.executable = PathBuf::from("/opt/my tools/100%/ouro");
        plan.config_home = plan.home.join(".config");
        plan
    }

    /// Both units are generated from one host, so a golden for the other platform is a
    /// real check rather than a thing that only runs on someone else's machine.
    #[test]
    fn both_platforms_render_byte_for_byte_from_one_host() {
        let macos = plan(Platform::MacOs).render().expect("a plist");
        let linux = plan(Platform::Linux).render().expect("a unit");

        assert_eq!(
            macos,
            include_str!("../tests/fixtures/service/launchagent.plist")
        );
        assert_eq!(
            linux,
            include_str!("../tests/fixtures/service/systemd.service")
        );
        assert_eq!(
            awkward_plan(Platform::Linux).render().expect("a unit"),
            include_str!("../tests/fixtures/service/systemd-metacharacters.service")
        );
        assert_eq!(
            awkward_plan(Platform::MacOs).render().expect("a plist"),
            include_str!("../tests/fixtures/service/launchagent-metacharacters.plist")
        );
    }

    /// systemd splits on whitespace and expands `%`, so a path with either in it has to
    /// leave the directive meaning one path and one program.
    #[test]
    fn systemd_directives_survive_a_space_a_specifier_and_a_quote() {
        let text = awkward_plan(Platform::Linux).render().expect("a unit");

        let exec = text
            .lines()
            .find(|line| line.starts_with("ExecStart="))
            .expect("an ExecStart");
        assert_eq!(
            exec, "ExecStart=\"/opt/my tools/100%%/ouro\" service-run",
            "the program is one quoted word and the specifier is doubled"
        );
        assert!(
            text.contains("WorkingDirectory=\"/srv/my data/%%h/a\\\"quoted\\\"/state\""),
            "{text}"
        );
        assert!(
            text.contains(
                "Environment=OUROBOROS_DATA_DIR=\"/srv/my data/%%h/a\\\"quoted\\\"/state\""
            ),
            "{text}"
        );
        // `append:` takes the rest of the line, so it is not quoted — but `%` still
        // expands there, so it is still doubled.
        let appended = text
            .lines()
            .find(|line| line.starts_with("StandardError="))
            .expect("a StandardError");
        assert_eq!(
            appended,
            "StandardError=append:/srv/my data/%%h/a\"quoted\"/state/service.err.log"
        );
        // No *directive* carries a single `%` that systemd would expand. Comments are
        // not directives — the ownership marker is one, and it is percent-encoded for
        // its own reasons.
        for line in text
            .lines()
            .filter(|line| line.contains('%') && !line.starts_with('#') && line.contains('='))
        {
            assert!(
                !line.replace("%%", "").contains('%'),
                "an unescaped specifier survives: {line}"
            );
        }
    }

    #[test]
    fn systemd_quoting_is_the_documented_grammar() {
        assert_eq!(systemd_quoted("/plain/path"), "\"/plain/path\"");
        assert_eq!(systemd_quoted("/a b"), "\"/a b\"");
        assert_eq!(systemd_quoted("100%"), "\"100%%\"");
        assert_eq!(systemd_quoted("a\"b"), "\"a\\\"b\"");
        assert_eq!(systemd_quoted("a\\b"), "\"a\\\\b\"");
        assert_eq!(systemd_literal("100%"), "100%%");
        assert_eq!(systemd_literal("/a b"), "/a b");
    }

    #[test]
    fn a_unit_carries_no_runtime_environment_and_no_ambient_override() {
        for platform in [Platform::MacOs, Platform::Linux] {
            let text = plan(platform).render().expect("a rendered unit");
            for forbidden in [
                "OUROBOROS_COOKIE_FILE",
                "OUROBOROS_BOOT_COOKIE_DECOY",
                "ERL_EPMD_ADDRESS",
                "OUROBOROS_NODE",
                "OUROBOROS_CLUSTER_HOSTS",
                "RELEASE_COOKIE",
                "OUROBOROS_GATEWAY_TOKEN",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{forbidden} belongs to one boot, derived at start from the profile — not to a persistent unit:\n{text}"
                );
            }
            assert!(text.contains("OUROBOROS_DATA_DIR"), "{text}");
        }
    }

    #[test]
    fn two_data_directories_get_two_independent_services() {
        let mut first = plan(Platform::MacOs);
        let mut second = first.clone();
        second.data_dir = PathBuf::from("/Users/tester/.ouroboros-two");

        assert_ne!(first.label(), second.label());
        assert_ne!(first.unit_path(), second.unit_path());

        // And the same directory always gets the same one.
        let repeat = first.label();
        first.user = "someone-else".to_string();
        assert_eq!(first.label(), repeat);
    }

    #[test]
    fn the_marker_names_this_data_directory_and_hashes_the_body() {
        for platform in [Platform::MacOs, Platform::Linux] {
            let plan = plan(platform);
            let text = plan.render().expect("a rendered unit");
            let marker = read_marker(platform, &text).expect("an ownership marker");

            assert_eq!(marker.data_dir, plan.data_dir.display().to_string());
            let content = marked_content(platform, &text).expect("a marked body");
            assert_eq!(marker.content_sha256, sha256_hex(content.as_bytes()));
            assert_eq!(marker.content_sha256.len(), 64);
            assert!(!content.contains(MARKER_TAG), "{content}");
        }
    }

    #[test]
    fn a_hand_edited_body_stops_matching_its_own_marker() {
        let plan = plan(Platform::Linux);
        let text = plan.render().expect("a rendered unit");
        let edited = text.replace("RestartSec=5", "RestartSec=1");
        let marker = read_marker(Platform::Linux, &edited).expect("the marker survives an edit");
        let content = marked_content(Platform::Linux, &edited).expect("a body");

        assert_ne!(sha256_hex(content.as_bytes()), marker.content_sha256);
    }

    #[test]
    fn a_unit_with_no_marker_is_not_ours() {
        let digest = "0".repeat(64);
        let linux = Platform::Linux;
        assert!(read_marker(linux, "[Unit]\nDescription=somebody else's\n").is_none());
        assert!(read_marker(
            linux,
            &format!("# ouroboros-managed v9 data-dir=/x content-sha256={digest}")
        )
        .is_none());
        assert!(read_marker(linux, "# ouroboros-managed v1 data-dir=/x").is_none());
        // A digest that is not a digest is not a marker.
        assert!(read_marker(
            linux,
            "# ouroboros-managed v1 data-dir=/x content-sha256=ff"
        )
        .is_none());
        // A field nobody wrote, and a field written twice, make the whole line
        // unreadable rather than letting the last one win.
        assert!(read_marker(
            linux,
            &format!("# ouroboros-managed v1 data-dir=/a data-dir=/b content-sha256={digest}")
        )
        .is_none());
        assert!(read_marker(
            linux,
            &format!("# ouroboros-managed v1 data-dir=/a content-sha256={digest} extra=1")
        )
        .is_none());
        // The real one still reads.
        assert_eq!(
            read_marker(
                linux,
                &format!("# ouroboros-managed v1 data-dir=/a content-sha256={digest}")
            )
            .expect("a marker")
            .data_dir,
            "/a"
        );
    }

    /// The marker is read from the one line and the one comment syntax the platform's
    /// units carry it on. Anywhere else is somebody appending to, or hiding under,
    /// another tool's file.
    #[test]
    fn a_marker_is_only_read_where_this_code_writes_one() {
        let digest = "0".repeat(64);
        // A systemd-shaped marker inside a plist.
        let cross =
            format!("<plist/>\n# ouroboros-managed v1 data-dir=/nowhere content-sha256={digest}\n");
        assert!(read_marker(Platform::MacOs, &cross).is_none(), "{cross}");
        assert!(read_marker(Platform::Linux, &cross).is_none(), "{cross}");
        // A real marker moved one line down.
        let moved = format!(
            "# nothing\n# ouroboros-managed v1 data-dir=/nowhere content-sha256={digest}\n"
        );
        assert!(read_marker(Platform::Linux, &moved).is_none(), "{moved}");
        // And a plist marker anywhere but after the DOCTYPE.
        let late = format!(
            "<?xml version=\"1.0\"?>\n<!DOCTYPE plist>\n<plist/>\n<!-- ouroboros-managed v1 data-dir=/nowhere content-sha256={digest} -->\n"
        );
        assert!(read_marker(Platform::MacOs, &late).is_none(), "{late}");
    }

    /// Every path a real machine can have, through the marker and back.
    #[test]
    fn a_marker_round_trips_every_path_a_directory_can_be_called() {
        for raw in [
            "/Users/tester/.ouroboros",
            "/Users/my tester/my data",
            "/srv/a\u{a0}b/data",
            "/srv/100%/data",
            "/srv/#hash/data",
            "/srv/a--b/data",
            "/srv/a-b-c/data",
            "/srv/quote\"here/data",
            "/srv/back\\slash/data",
            "/srv/héllo/データ",
            "/srv/-->escape/data",
        ] {
            let encoded = marker_encode(raw);
            assert!(
                !encoded.contains(char::is_whitespace),
                "`{raw}` encoded to `{encoded}`, which is not one token"
            );
            assert!(
                !encoded.contains("--"),
                "`{raw}` encoded to `{encoded}`, which XML forbids inside a comment"
            );
            assert_eq!(
                marker_decode(&encoded).as_deref(),
                Some(raw),
                "`{raw}` did not survive `{encoded}`"
            );
        }
        // A broken encoding is not a marker.
        assert_eq!(marker_decode("%ZZ"), None);
        assert_eq!(marker_decode("%2"), None);
    }

    /// The unit this code wrote reads back as its own, whatever the directory is called.
    #[test]
    fn a_unit_for_an_awkwardly_named_directory_is_still_ours() {
        for name in [
            "my data",
            "a--b",
            "100%",
            "quote\"here",
            "back\\slash",
            "hash#tag",
        ] {
            for platform in [Platform::MacOs, Platform::Linux] {
                let mut plan = plan(platform);
                plan.data_dir = plan.home.join(name);
                let text = plan.render().expect("a rendered unit");
                let marker = read_marker(platform, &text).expect("our own marker");
                assert_eq!(
                    Path::new(&marker.data_dir),
                    plan.data_dir,
                    "`{name}` on {:?}",
                    platform
                );
                assert_eq!(
                    sha256_hex(marked_content(platform, &text).expect("a body").as_bytes()),
                    marker.content_sha256
                );
            }
        }
    }

    /// A path that would once have broken the file it was written into now survives it.
    #[test]
    fn a_path_that_could_break_a_unit_is_encoded_rather_than_refused() {
        let mut plan = plan(Platform::MacOs);
        plan.data_dir = PathBuf::from("/Users/tester/-->evil--data");
        let text = plan.render().expect("a rendered plist");
        let marker = text.lines().nth(2).expect("a marker line");

        assert!(
            !marker
                .trim_start_matches("<!--")
                .trim_end_matches("-->")
                .contains("--"),
            "XML forbids `--` inside a comment: {marker}"
        );
        assert_eq!(
            read_marker(Platform::MacOs, &text)
                .expect("our marker")
                .data_dir,
            "/Users/tester/-->evil--data"
        );

        // A control character has no encoding that keeps a unit file readable, so it
        // stays a refusal.
        plan.data_dir = PathBuf::from("/Users/tester/two\nlines");
        let error = plan.render().expect_err("a control character");
        assert_eq!(
            service_error(&error).map(|declared| declared.reason),
            Some("unusable_path")
        );
    }

    #[test]
    fn launchctl_print_is_read_for_what_it_says_and_nothing_else() {
        let printed = parse_launchctl_print(
            "dev.ouroboros.runtime.abc = {\n\tactive count = 1\n\tstate = running\n\tpid = 4321\n\tlast exit code = 0\n}\n",
        );

        assert_eq!(printed.state.as_deref(), Some("running"));
        assert_eq!(printed.pid, Some(4321));
        assert_eq!(printed.last_exit, Some(0));

        // A job launchd has never run has no exit code, and an absence is not a zero.
        let never = parse_launchctl_print(
            "dev.ouroboros.runtime.abc = {\n\tstate = not running\n\tlast exit code = (never exited)\n}\n",
        );
        assert_eq!(never.state.as_deref(), Some("not running"));
        assert_eq!(never.pid, None);
        assert_eq!(never.last_exit, None);
    }

    /// `--json` and the page a person reads name the same things the same way.
    #[test]
    fn the_json_codes_are_the_codes_the_human_page_prints() {
        assert_eq!(
            serde_json::to_value(Platform::MacOs).expect("encodable"),
            serde_json::json!(Platform::MacOs.code())
        );
        assert_eq!(
            serde_json::to_value(Platform::Linux).expect("encodable"),
            serde_json::json!(Platform::Linux.code())
        );
        for code in [
            SupervisorCode::LaunchdUserSession,
            SupervisorCode::SystemdUser,
            SupervisorCode::Unsupported,
        ] {
            assert_eq!(
                serde_json::to_value(code).expect("encodable"),
                serde_json::json!(code.code())
            );
        }
        for ownership in [
            Ownership::Absent,
            Ownership::Ours,
            Ownership::Modified,
            Ownership::Foreign,
        ] {
            assert_eq!(
                serde_json::to_value(ownership).expect("encodable"),
                serde_json::json!(ownership.code())
            );
        }
    }

    #[test]
    fn systemctl_show_is_read_as_key_values() {
        let shown = parse_systemctl_show(
            "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=99\nExecMainStatus=0\n",
        );

        assert_eq!(shown.get("LoadState").map(String::as_str), Some("loaded"));
        assert_eq!(shown.get("SubState").map(String::as_str), Some("running"));
        assert_eq!(shown.get("MainPID").map(String::as_str), Some("99"));
    }

    #[test]
    fn the_linger_sentence_never_promises_what_was_not_established() {
        assert!(linger_sentence("tester", Some(true)).contains("survives logout"));
        assert!(linger_sentence("tester", Some(false)).contains("enable-linger"));
        assert!(linger_sentence("tester", None).contains("unknown"));
        assert!(MACOS_PERSISTENCE.contains("does not run"));
    }

    #[test]
    fn the_two_idle_refusals_get_two_exit_codes_and_a_rendered_summary() {
        let busy = stop_refusal(
            crate::proto::ErrorCode::Unavailable,
            Some(&serde_json::json!({
                "reason": "runtime_busy",
                "activity": {
                    "idle": false,
                    "running_turns": 2,
                    "queued_turns": 1,
                    "attachment_transfers": 0,
                    "attachment_normalizations": 0,
                    "operator_clients": 1,
                    "unknown": []
                }
            })),
        )
        .expect("a mapped refusal");
        assert_eq!(busy.exit_code, EXIT_RUNTIME_BUSY);
        assert!(busy.rendered.contains("running turns"), "{}", busy.rendered);
        assert!(busy.rendered.contains('2'), "{}", busy.rendered);

        let unknown = stop_refusal(
            crate::proto::ErrorCode::Unavailable,
            Some(&serde_json::json!({
                "reason": "activity_unknown",
                "activity": {
                    "idle": null,
                    "running_turns": null,
                    "queued_turns": 0,
                    "attachment_transfers": null,
                    "attachment_normalizations": 0,
                    "operator_clients": 1,
                    "unknown": ["running_turns", "attachment_transfers"]
                }
            })),
        )
        .expect("a mapped refusal");
        assert_eq!(unknown.exit_code, EXIT_ACTIVITY_UNKNOWN);
        assert_ne!(unknown.exit_code, busy.exit_code);
        assert!(unknown.rendered.contains("unknown"), "{}", unknown.rendered);
        assert!(
            unknown.rendered.contains("running_turns"),
            "{}",
            unknown.rendered
        );

        // Anything else is not an idle refusal and is reported as the failure it is.
        assert_eq!(
            stop_refusal(
                crate::proto::ErrorCode::Unavailable,
                Some(&serde_json::json!({ "reason": "something_else" }))
            ),
            None
        );
        assert_eq!(
            stop_refusal(crate::proto::ErrorCode::Unavailable, None),
            None
        );
        // The code is half the contract. A `reason` carried on some other error — a
        // method-not-found from a runtime that never heard of the gate — is not this
        // refusal, and must not be reported as a busy runtime.
        for other in [
            crate::proto::ErrorCode::MethodNotFound,
            crate::proto::ErrorCode::InvalidParams,
            crate::proto::ErrorCode::ScopeDenied,
            crate::proto::ErrorCode::Other(-32004 + 1),
        ] {
            assert_eq!(
                stop_refusal(
                    other,
                    Some(&serde_json::json!({
                        "reason": "runtime_busy",
                        "activity": { "running_turns": 1 }
                    }))
                ),
                None,
                "{other:?} is not -32004"
            );
        }
        // Every exit code this command can end with is a different number.
        let codes = [
            EXIT_RUNTIME_BUSY,
            EXIT_ACTIVITY_UNKNOWN,
            EXIT_IDLE_GATE_UNSUPPORTED,
            EXIT_IDLE_OUTCOME_UNKNOWN,
        ];
        let unique: std::collections::BTreeSet<u8> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "{codes:?}");
        assert!(!codes.contains(&0) && !codes.contains(&1) && !codes.contains(&2));
    }

    /// The runtime's summary is data, not a promise about its shape.
    #[test]
    fn a_summary_that_is_not_a_summary_renders_as_unknown() {
        for activity in [
            serde_json::json!("not an object at all"),
            serde_json::json!([1, 2, 3]),
            serde_json::json!({ "running_turns": "lots" }),
            serde_json::json!({ "unknown": "not a list" }),
        ] {
            let rendered = render_activity(Some(&activity));
            assert!(rendered.contains("unknown"), "{activity}: {rendered}");
        }
        assert!(render_activity(None).contains("no summary"));
    }

    #[test]
    fn the_wait_schedule_doubles_to_a_ceiling() {
        assert_eq!(network_wait_backoff(0), Duration::from_secs(1));
        assert_eq!(network_wait_backoff(1), Duration::from_secs(2));
        assert_eq!(network_wait_backoff(2), Duration::from_secs(4));
        assert_eq!(network_wait_backoff(3), Duration::from_secs(8));
        assert_eq!(network_wait_backoff(4), NETWORK_WAIT_MAX);
        assert_eq!(network_wait_backoff(40), NETWORK_WAIT_MAX);
    }

    #[tokio::test]
    async fn the_wait_says_it_is_waiting_once_and_then_once_a_minute() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::{Arc, Mutex};

        let attempts = Arc::new(AtomicU32::new(0));
        let probe_attempts = attempts.clone();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let logged = lines.clone();
        let slept = Arc::new(Mutex::new(Vec::new()));
        let recorded = slept.clone();

        wait_for_bindable_host(
            "100.64.0.2",
            move |host| {
                assert_eq!(host, "100.64.0.2");
                let attempt = probe_attempts.fetch_add(1, Ordering::Relaxed);
                if attempt < 30 {
                    bail!("no interface holds 100.64.0.2 yet")
                } else {
                    Ok(std::net::Ipv4Addr::new(100, 64, 0, 2))
                }
            },
            move |line| logged.lock().expect("a log").push(line),
            move |interval| {
                recorded.lock().expect("a schedule").push(interval);
                std::future::ready(())
            },
        )
        .await;

        let lines = lines.lock().expect("a log").clone();
        let slept = slept.lock().expect("a schedule").clone();
        assert_eq!(attempts.load(Ordering::Relaxed), 31);
        // The throttle: 1s doubling to the 15s ceiling, and never past it.
        assert_eq!(
            &slept[..5],
            &[
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(15),
            ]
        );
        assert!(slept.iter().all(|interval| *interval <= NETWORK_WAIT_MAX));
        assert!(
            lines[0].contains("waiting for network"),
            "the first line names the state: {lines:?}"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("waiting for network"))
                .count(),
            // One at the start, then one per minute of a wait that lasted seven.
            7,
            "{lines:?}"
        );
        assert!(
            lines.last().expect("a last line").contains("network ready"),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn a_bindable_address_is_not_waited_for_and_says_nothing() {
        use std::sync::{Arc, Mutex};

        let lines = Arc::new(Mutex::new(Vec::new()));
        let logged = lines.clone();
        let slept = Arc::new(Mutex::new(0usize));
        let counted = slept.clone();
        wait_for_bindable_host(
            "127.0.0.1",
            |_host| Ok(std::net::Ipv4Addr::LOCALHOST),
            move |line| logged.lock().expect("a log").push(line),
            move |_interval| {
                *counted.lock().expect("a counter") += 1;
                std::future::ready(())
            },
        )
        .await;

        assert!(lines.lock().expect("a log").is_empty());
        assert_eq!(*slept.lock().expect("a counter"), 0);
    }

    #[tokio::test]
    async fn dropping_the_wait_stops_it_where_it_stands() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let attempts = Arc::new(AtomicU32::new(0));
        let probe_attempts = attempts.clone();
        let wait = wait_for_bindable_host(
            "100.64.0.2",
            move |_host| {
                probe_attempts.fetch_add(1, Ordering::Relaxed);
                bail!("never bindable")
            },
            |_line| {},
            |_interval| tokio::task::yield_now(),
        );

        tokio::select! {
            biased;
            () = wait => panic!("a never-bindable address must not finish"),
            () = async {
                for _ in 0..8 {
                    tokio::task::yield_now().await;
                }
            } => {}
        }

        let seen = attempts.load(Ordering::Relaxed);
        assert!(seen > 0, "the wait probed before it was dropped");
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            seen,
            "a dropped wait must stop probing"
        );
    }
}
