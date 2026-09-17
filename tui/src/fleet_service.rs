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
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
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
/// it counting fakes without mutating the process environment. The defaults are bare
/// names resolved through `PATH` by the operating system, exactly as an operator's own
/// `launchctl`/`systemctl` would be.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Programs {
    pub launchctl: PathBuf,
    pub systemctl: PathBuf,
    pub loginctl: PathBuf,
}

impl Default for Programs {
    fn default() -> Self {
        Self {
            launchctl: PathBuf::from("launchctl"),
            systemctl: PathBuf::from("systemctl"),
            loginctl: PathBuf::from("loginctl"),
        }
    }
}

impl Programs {
    /// The same three programs, with absolute overrides for an installation this
    /// lookup does not know about. Named for the same reason `OUROBOROS_TAILSCALE` is:
    /// a relative name would let the working directory decide which program runs.
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            launchctl: override_program("OUROBOROS_LAUNCHCTL").unwrap_or(default.launchctl),
            systemctl: override_program("OUROBOROS_SYSTEMCTL").unwrap_or(default.systemctl),
            loginctl: override_program("OUROBOROS_LOGINCTL").unwrap_or(default.loginctl),
        }
    }
}

fn override_program(name: &str) -> Option<PathBuf> {
    let value = std::env::var_os(name)?;
    let path = PathBuf::from(&value);
    (!value.is_empty() && path.is_absolute()).then_some(path)
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
        let home = dirs::home_dir()
            .ok_or_else(|| anyhow!("this account has no home directory to install a unit into"))?;
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
    /// always gets the same one.
    pub fn digest(&self) -> String {
        sha256_hex(self.data_dir.as_os_str().as_encoded_bytes())[..12].to_string()
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
	<string>Background</string>
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
                let mut environment_lines = String::new();
                for (key, value) in environment {
                    environment_lines.push_str(&format!("Environment={key}={value}\n"));
                }
                let body = format!(
                    r#"[Unit]
Description=Ouroboros runtime for {data_dir}
# No network ordering: `ouro service-run` waits for this machine's own private
# interface to become bindable before it launches the BEAM, and reports that wait
# in this unit's log. A user manager has no network-online.target to want.
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart={executable} service-run
WorkingDirectory={data_dir}
{environment_lines}Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StandardOutput=append:{out_log}
StandardError=append:{err_log}

[Install]
WantedBy=default.target
"#,
                    executable = executable,
                    data_dir = data_dir,
                    out_log = out_log,
                    err_log = err_log,
                );
                (String::new(), body)
            }
        };

        // The digest covers everything the file says except the marker line itself, so
        // removing that one line from the unit on disk reproduces exactly what was
        // hashed. An edit anywhere else — including the XML preamble — changes it.
        let content = sha256_hex(format!("{prefix}{body}").as_bytes());
        let comment = match self.platform {
            Platform::MacOs => format!(
                "<!-- {MARKER_TAG} {MARKER_VERSION} data-dir={data_dir} content-sha256={content} -->\n"
            ),
            Platform::Linux => format!(
                "# {MARKER_TAG} {MARKER_VERSION} data-dir={data_dir} content-sha256={content}\n"
            ),
        };

        Ok(format!("{prefix}{comment}{body}"))
    }
}

fn account_name() -> String {
    std::env::var("USER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("LOGNAME")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| unsafe { libc::geteuid() }.to_string())
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
    if text.chars().any(|c| c.is_control()) || text.contains("-->") {
        return refuse(
            "unusable_path",
            format!(
                "the {description} `{text}` contains a character a service unit and its ownership marker cannot carry"
            ),
        );
    }
    Ok(text.to_string())
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

/// Reads the ownership marker out of a unit's text, if it has one.
pub fn read_marker(text: &str) -> Option<Marker> {
    let line = text.lines().find(|line| line.contains(MARKER_TAG))?;
    let line = line
        .trim()
        .trim_start_matches("<!--")
        .trim_end_matches("-->")
        .trim()
        .trim_start_matches('#')
        .trim();
    let mut fields = line.split_whitespace();
    if fields.next()? != MARKER_TAG || fields.next()? != MARKER_VERSION {
        return None;
    }
    let mut data_dir = None;
    let mut content_sha256 = None;
    for field in fields {
        if let Some(value) = field.strip_prefix("data-dir=") {
            data_dir = Some(value.to_string());
        } else if let Some(value) = field.strip_prefix("content-sha256=") {
            content_sha256 = Some(value.to_string());
        }
    }
    Some(Marker {
        data_dir: data_dir?,
        content_sha256: content_sha256?,
    })
}

/// What a marker's digest covers: the whole unit with the marker line taken out.
fn marked_content(text: &str) -> Option<String> {
    let start = text.find(MARKER_TAG)?;
    let line_start = text[..start]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let line_end = text[start..].find('\n').map(|index| start + index + 1)?;
    Some(format!("{}{}", &text[..line_start], &text[line_end..]))
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
    // A symlink where our unit goes is somebody else's arrangement: it is reported and
    // left exactly as it is, and nothing follows it.
    if !metadata.file_type().is_file() {
        return Ok((Ownership::Foreign, None));
    }
    let text = fs::read_to_string(&path)
        .with_context(|| format!("reading the existing unit {}", path.display()))?;
    let Some(marker) = read_marker(&text) else {
        return Ok((Ownership::Foreign, Some(sha256_hex(text.as_bytes()))));
    };
    let data_dir = plan
        .data_dir
        .to_str()
        .map(str::to_string)
        .unwrap_or_default();
    if marker.data_dir != data_dir {
        return Ok((Ownership::Foreign, Some(sha256_hex(text.as_bytes()))));
    }
    let content = marked_content(&text).unwrap_or_default();
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
    match run(&programs.launchctl, &["print", domain.as_str()]) {
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
        run(&programs.systemctl, &["--user", "show", "--property=Version"]),
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
    pub notes: Vec<String>,
}

impl Report {
    fn new(action: &'static str, plan: &Plan, supervisor: &Supervisor) -> Self {
        Self {
            action,
            platform: Some(plan.platform),
            supervisor: supervisor.code,
            label: plan.label(),
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
            notes: Vec::new(),
        }
    }

    fn record(&mut self, program: &Path, args: &[&str]) {
        let mut argv = vec![program.display().to_string()];
        argv.extend(args.iter().map(|arg| (*arg).to_string()));
        self.commands.push(argv);
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
    match ownership {
        Ownership::Absent | Ownership::Ours => {}
        Ownership::Modified if adopt => report.notes.push(format!(
            "adopted an edited copy of this machine's own unit (body sha256 {}) and replaced it",
            digest.clone().unwrap_or_else(|| "unknown".to_string())
        )),
        Ownership::Foreign if adopt => report.notes.push(format!(
            "adopted a preexisting unit this code did not write (sha256 {}) and replaced it",
            digest.clone().unwrap_or_else(|| "unknown".to_string())
        )),
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

    let text = plan.render()?;
    prepare_log(&plan.out_log())?;
    prepare_log(&plan.err_log())?;
    write_private_atomic(&plan.unit_path(), text.as_bytes())?;
    report.installed = true;
    report.ownership = Ownership::Ours;

    match plan.platform {
        Platform::MacOs => {
            let target = plan.manager_name();
            let domain = plan.domain();
            // Idempotent by construction: a service already bootstrapped from an older
            // copy of this file has to be booted out before the new one can replace it,
            // and a `bootout` of something that is not loaded is not an error here.
            report.record(&programs.launchctl, &["bootout", target.as_str()]);
            let _ = run(&programs.launchctl, &["bootout", target.as_str()]);
            let plist = plan.unit_path();
            let plist = plist.to_str().ok_or_else(|| {
                ServiceError::new("unusable_path", "the unit path is not valid UTF-8")
            })?;
            report.record(&programs.launchctl, &["bootstrap", domain.as_str(), plist]);
            let outcome = run(&programs.launchctl, &["bootstrap", domain.as_str(), plist])
                .map_err(|error| ServiceError::new("manager_unavailable", error.to_string()))?;
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
            let unit = plan.manager_name();
            for args in [
                vec!["--user", "daemon-reload"],
                vec!["--user", "enable", "--now", unit.as_str()],
            ] {
                report.record(&programs.systemctl, &args);
                let outcome = run(&programs.systemctl, &args)
                    .map_err(|error| ServiceError::new("manager_unavailable", error.to_string()))?;
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

    inspect_manager(plan, programs, &mut report)?;
    Ok(report)
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
    if supervisor.code == SupervisorCode::Unsupported {
        return refuse(
            "unsupported",
            supervisor
                .prerequisite
                .unwrap_or_else(|| "this machine has no user supervisor".to_string()),
        );
    }
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

    // Disabling first is the order the proposal asks for: a unit removed while its
    // manager still supervises it comes straight back.
    if supervisor.code != SupervisorCode::Unsupported {
        disable_with_manager(plan, programs, &mut report)?;
    } else {
        report.notes.push(
            "no user supervisor answered, so only the unit file was removed; nothing was stopped"
                .to_string(),
        );
    }

    if ownership.is_ours() {
        let path = plan.unit_path();
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        report
            .notes
            .push(format!("removed {}", plan.unit_path().display()));
    }
    report.installed = false;
    report.ownership = Ownership::Absent;

    if plan.platform == Platform::Linux && supervisor.code != SupervisorCode::Unsupported {
        let args = ["--user", "daemon-reload"];
        report.record(&programs.systemctl, &args);
        let _ = run(&programs.systemctl, &args);
    }
    report.loaded = Some(false);
    report.running = Some(false);
    Ok(report)
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
    let outcome = run(program, &borrowed)
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
            let outcome = run(&programs.launchctl, &args)
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
            let outcome = run(&programs.systemctl, &args)
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
            match run(&programs.launchctl, &args) {
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
            match run(&programs.systemctl, &args) {
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

fn first_line(stderr: &str, stdout: &str) -> String {
    stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("the manager said nothing")
        .to_string()
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
fn run(program: &Path, args: &[&str]) -> Result<Outcome> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .with_context(|| format!("starting {}", program.display()))?;
    let pid = child.id();

    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("ouro-service-manager".to_string())
        .spawn(move || {
            let _ = sender.send(child.wait_with_output());
        })
        .context("starting the reader for a service-manager command")?;

    match receiver.recv_timeout(MANAGER_TIMEOUT) {
        Ok(Ok(output)) => Ok(Outcome {
            status: output.status.code(),
            stdout: bounded(&output.stdout),
            stderr: bounded(&output.stderr),
        }),
        Ok(Err(error)) => {
            Err(error).with_context(|| format!("reading {} output", program.display()))
        }
        Err(_) => {
            // The reader thread still owns the child, so the deadline is enforced by
            // signalling the process rather than by dropping a handle we do not hold.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            bail!(
                "{} did not answer within {} seconds",
                program.display(),
                MANAGER_TIMEOUT.as_secs()
            )
        }
    }
}

fn bounded(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_MANAGER_OUTPUT);
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

// ------------------------------------------------------------------------ private files

/// The service's log file, created private before the manager can create it at the
/// manager's own umask. launchd and systemd both append to a file that already exists.
fn prepare_log(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            if metadata.uid() != unsafe { libc::geteuid() } {
                return refuse(
                    "unusable_path",
                    format!("{} is not owned by this account", path.display()),
                );
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("making {} private", path.display()))
        }
        Ok(_) => refuse(
            "unusable_path",
            format!(
                "{} exists and is not a regular file; the service log will not be redirected over it",
                path.display()
            ),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
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

/// A `runtime.shutdown` refusal, rendered for a person and carrying its exit code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopRefusal {
    pub reason: String,
    pub exit_code: u8,
    pub rendered: String,
}

/// Maps the C2 refusal into an exit code and a page. `None` for anything that is not
/// one of the two idle refusals, which the caller then reports as an ordinary failure.
pub fn stop_refusal(data: Option<&serde_json::Value>) -> Option<StopRefusal> {
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
        assert!(text.contains("<string>Background</string>"), "{text}");
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
            text.contains("ExecStart=/usr/local/bin/ouro service-run"),
            "{text}"
        );
        assert!(text.contains("Restart=on-failure"), "{text}");
        assert!(text.contains("RestartSec=5"), "{text}");
        assert!(text.contains("StartLimitIntervalSec=300"), "{text}");
        assert!(text.contains("StartLimitBurst=5"), "{text}");
        assert!(text.contains("WantedBy=default.target"), "{text}");
        assert!(
            text.contains("WorkingDirectory=/home/tester/.ouroboros"),
            "{text}"
        );
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
            let marker = read_marker(&text).expect("an ownership marker");

            assert_eq!(marker.data_dir, plan.data_dir.display().to_string());
            let content = marked_content(&text).expect("a marked body");
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
        let marker = read_marker(&edited).expect("the marker survives an edit");
        let content = marked_content(&edited).expect("a body");

        assert_ne!(sha256_hex(content.as_bytes()), marker.content_sha256);
    }

    #[test]
    fn a_unit_with_no_marker_is_not_ours() {
        assert!(read_marker("[Unit]\nDescription=somebody else's\n").is_none());
        assert!(read_marker("# ouroboros-managed v9 data-dir=/x content-sha256=ff").is_none());
        assert!(read_marker("# ouroboros-managed v1 data-dir=/x").is_none());
    }

    #[test]
    fn a_path_that_would_break_its_own_marker_is_refused() {
        let mut plan = plan(Platform::Linux);
        plan.data_dir = PathBuf::from("/home/tester/-->evil");
        let error = plan.render().expect_err("a marker-breaking path");

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
        let busy = stop_refusal(Some(&serde_json::json!({
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
        })))
        .expect("a mapped refusal");
        assert_eq!(busy.exit_code, EXIT_RUNTIME_BUSY);
        assert!(busy.rendered.contains("running turns"), "{}", busy.rendered);
        assert!(busy.rendered.contains('2'), "{}", busy.rendered);

        let unknown = stop_refusal(Some(&serde_json::json!({
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
        })))
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
            stop_refusal(Some(&serde_json::json!({ "reason": "something_else" }))),
            None
        );
        assert_eq!(stop_refusal(None), None);
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
