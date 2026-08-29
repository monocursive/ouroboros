//! Owning a runtime as a child process: where its files live, what environment it gets,
//! how readiness is decided, and how it is asked to stop.
//!
//! ## The data directory is the rendezvous
//!
//! `Ouroboros.Gateway.Listener` binds an ephemeral port and publishes it to
//! `gateway.json` in `OUROBOROS_DATA_DIR`, 0600, with the OS pid alongside it. That file
//! is the whole discovery mechanism: this client never pre-chooses a port, so there is
//! no window in which two daemons race for a number one of them picked in advance. The
//! token is written next to it, because the published facts alone are not enough to
//! connect and a token on a command line is visible to every process on the host.
//! `runtime.owner` is separate on purpose: losing a discovery publication does not make
//! the journals in that directory safe for a second runtime. The BEAM owns that marker
//! for its whole lifetime; this client reads it before any spawn that could replace the
//! token or publication.
//!
//! With no explicit data-directory override, a `--dev` daemon gets a *different* data
//! directory. `OUROBOROS_DATA_DIR` is an exact rendezvous override in both modes; the
//! client warns when `--dev` uses one because a development runtime and a release that
//! shared `gateway.json` would each be discoverable as the other.
//!
//! ## What "stale" means, and what it does not
//!
//! `gateway.json` is removed on graceful termination and left behind by a kill, which is
//! why it carries a pid. A publication whose pid is dead is stale and is removed before
//! spawning. A publication whose pid is *alive* is never overwritten: a daemon this
//! client cannot talk to is a situation to report, not to resolve by starting a second
//! one in the same directory.
//!
//! ## The child is its own session
//!
//! Every spawn calls `setsid`, so a terminal signal reaches `ouro` alone. In the
//! supervised mode that is what lets ctrl-c run an ordered SIGTERM → grace → SIGKILL
//! instead of racing the shell; in `ouro daemon` it is what lets the runtime outlive the
//! client that started it.
//!
//! ## Two clients, one data directory
//!
//! Reading `gateway.json` and then spawning is a check followed by an action, and two
//! `ouro` processes started together both pass the check. The second daemon would bind a
//! second port, overwrite the token the first one is authenticated with, and publish over
//! the first one's file — leaving one runtime unreachable and its journals owned by a
//! process nobody is watching. [`acquire_spawn_lock`] closes that window with a fully
//! written private temporary inode that is hard-linked into the lock name atomically:
//! the loser is told which pid won rather than starting anything, and no reader can see
//! an empty or partial claim. The lock covers the spawn, not the session — a client that
//! held it while attached would stop the next `ouro` from *adopting* the daemon it just
//! started, which is the case the rendezvous exists to serve.

use std::collections::VecDeque;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use zeroize::Zeroize;

use crate::transport::{EndpointSource, Secret};

#[cfg(feature = "embed")]
pub mod embed;

/// What the gateway publishes after it binds.
pub const PUBLICATION_FILE: &str = "gateway.json";

/// What the browser surface publishes after *its* endpoint binds (docs/WEB.md D5). Same
/// directory, same 0600 write discipline, deliberately the same shape as `gateway.json` —
/// minus the one field this client would most like it to carry; see [`WebPublication`].
pub const WEB_PUBLICATION_FILE: &str = "web.json";

/// Where a spawner leaves the token it generated. The gateway is told the path through
/// `OUROBOROS_GATEWAY_TOKEN_FILE` and publishes neither the path nor the secret, so this
/// name is a convention between `ouro daemon` and `ouro attach`, not a protocol fact.
pub const TOKEN_FILE: &str = "gateway.token";

/// Where a detached daemon's output goes. A daemon that outlives its spawner cannot keep
/// writing into the spawner's pipes. This is deliberately only the inherited stdout/stderr
/// sink: it keeps VM bootstrap and crash diagnostics visible without sharing the file that
/// OTP Logger rotates while the runtime is live.
pub const DAEMON_LOG_FILE: &str = "daemon.log";

/// A detached daemon starts a fresh log once the previous one reaches this size.
/// Rotation happens before the new runtime opens the file, so the runtime never needs
/// permission to rename a file it is actively writing.
pub const DAEMON_LOG_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// Number of complete detached-daemon logs retained beside [`DAEMON_LOG_FILE`].
/// Backups are named `daemon.log.1` (newest) through `daemon.log.3` (oldest).
pub const DAEMON_LOG_BACKUPS: usize = 3;

/// Where a managed runtime's Elixir/OTP Logger writes. Only `:logger_std_h` owns this
/// file, so its live rotation never races the inherited stdout/stderr descriptors that
/// remain attached to [`DAEMON_LOG_FILE`].
pub const RUNTIME_LOG_FILE: &str = "runtime.log";

/// A live Logger generation rotates after this many bytes. OTP checks after a complete
/// event, so a single event may make an individual generation slightly larger.
pub const RUNTIME_LOG_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// Number of live Logger archives retained as `runtime.log.0` (newest) through
/// `runtime.log.2` (oldest).
pub const RUNTIME_LOG_BACKUPS: usize = 3;

const RUNTIME_LOG_FILE_ENV: &str = "OUROBOROS_RUNTIME_LOG_FILE";
const RUNTIME_LOG_MAX_BYTES_ENV: &str = "OUROBOROS_RUNTIME_LOG_MAX_BYTES";
const RUNTIME_LOG_MAX_FILES_ENV: &str = "OUROBOROS_RUNTIME_LOG_MAX_FILES";

/// Held for the duration of one spawn attempt. Contains the pid of the client holding it,
/// which is the only useful thing to tell whoever loses the race.
pub const SPAWN_LOCK_FILE: &str = "spawn.lock";

/// Persistent private inode whose crash-releasing advisory lock serializes bounded
/// recovery of a dead `spawn.lock`.
pub const SPAWN_LOCK_RECOVERY_FILE: &str = "spawn.lock.recovery";

/// Held by the core BEAM runtime for its whole lifetime, independently of gateway
/// publication and client spawn serialization.
pub const RUNTIME_OWNER_FILE: &str = "runtime.owner";

/// Persistent private inode whose crash-releasing advisory lock serializes the only
/// bounded path that may replace a dead runtime owner.
pub const RUNTIME_OWNER_RECOVERY_FILE: &str = "runtime.owner.recovery";

/// Private lifecycle publications and claims are deliberately tiny. A corrupt or replaced
/// rendezvous file must not make a local client allocate an attacker-selected amount of
/// memory before it has authenticated anything.
const PRIVATE_MARKER_MAX_BYTES: u64 = 16 * 1024;

/// Versioned contents of the persistent inode whose advisory lock serializes stale
/// `spawn.lock` recovery. The bytes never change; process death releases the kernel lock.
const SPAWN_RECOVERY_HEADER: &[u8] = b"ouro-spawn-recovery-v2\n";
const RUNTIME_RECOVERY_HEADER: &[u8] = b"ouro-runtime-recovery-v2\n";

/// The absolute product executable passed to the BEAM for native process-incarnation
/// queries. It is launcher-owned and never accepted from ambient fleet service state.
pub const PROCESS_ID_HELPER_ENV: &str = "OUROBOROS_PROCESS_ID_HELPER";

const READY_POLL: Duration = Duration::from_millis(150);

/// Unique names for fully written claim inodes before their atomic publication.
static CLAIM_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A cold `mix run` compiles the whole project first, which is minutes, not seconds.
pub const DEV_READY_DEADLINE: Duration = Duration::from_secs(300);

/// An extracted release starts a compiled system; anything past this is a failure that
/// has not printed itself yet.
pub const RELEASE_READY_DEADLINE: Duration = Duration::from_secs(60);

/// Where the client's files live. An explicit `OUROBOROS_DATA_DIR` names the runtime's
/// data directory exactly; otherwise the data and cache roots follow the XDG variables
/// directly rather than the platform conventions `dirs` would otherwise apply. The
/// daemon reads the same data-dir variable, so the two halves have to agree on one path.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    /// True only when a nonblank `OUROBOROS_DATA_DIR` selected `data_dir` exactly.
    pub data_dir_overridden: bool,
}

impl Paths {
    pub fn discover(dev: bool) -> Result<Self> {
        let configured_data_dir = std::env::var_os("OUROBOROS_DATA_DIR");
        let resolved = resolve_data_dir(dev, configured_data_dir.as_deref(), || {
            xdg_root("XDG_DATA_HOME", ".local/share")
        })?;

        Ok(Self {
            data_dir: resolved.path,
            cache_dir: xdg_root("XDG_CACHE_HOME", ".cache")?.join("ouroboros"),
            data_dir_overridden: resolved.overridden,
        })
    }

    pub fn publication(&self) -> PathBuf {
        self.data_dir.join(PUBLICATION_FILE)
    }

    pub fn web_publication(&self) -> PathBuf {
        self.data_dir.join(WEB_PUBLICATION_FILE)
    }

    pub fn token_file(&self) -> PathBuf {
        self.data_dir.join(TOKEN_FILE)
    }

    pub fn daemon_log(&self) -> PathBuf {
        self.data_dir.join(DAEMON_LOG_FILE)
    }

    pub fn runtime_log(&self) -> PathBuf {
        self.data_dir.join(RUNTIME_LOG_FILE)
    }

    pub fn spawn_lock(&self) -> PathBuf {
        self.data_dir.join(SPAWN_LOCK_FILE)
    }

    pub fn runtime_owner(&self) -> PathBuf {
        self.data_dir.join(RUNTIME_OWNER_FILE)
    }

    pub fn releases(&self) -> PathBuf {
        self.cache_dir.join("releases")
    }

    /// Establishes the local runtime boundary before the boot screen takes the terminal.
    ///
    /// A derived XDG leaf belongs to this client, so an older same-user installation that
    /// created it too broadly can be restricted in place. An explicit operator path keeps
    /// the strict contract: Ouroboros never changes it implicitly.
    pub fn ensure_private_data_dir(&self) -> Result<()> {
        ensure_private_data_dir_with_policy(&self.data_dir, !self.data_dir_overridden)
    }
}

/// Resolves the rendezvous directory shared by the client and the runtime it starts.
///
/// A configured path is an operator override, not an XDG root: trim it the same way the
/// runtime config does, then do not append the normal or development leaf. Blank is the
/// same as unset; a relative value is refused because the client and a release run with
/// different working directories and would resolve it to different places.
#[derive(Debug, PartialEq, Eq)]
struct ResolvedDataDir {
    path: PathBuf,
    overridden: bool,
}

/// Establishes the durable-directory leaf as a private same-user boundary.
///
/// Parent directories retain their operator/XDG posture, but the leaf itself is created
/// atomically at 0700 and is never followed or silently repaired. This strict entrypoint
/// is used for explicit/operator paths and every lower-level revalidation.
pub fn ensure_private_data_dir(data_dir: &Path) -> Result<()> {
    ensure_private_data_dir_with_policy(data_dir, false)
}

fn ensure_private_data_dir_with_policy(
    data_dir: &Path,
    repair_same_user_permissions: bool,
) -> Result<()> {
    if !data_dir.is_absolute() {
        bail!(
            "durable data directory {} must be an absolute path",
            data_dir.display()
        );
    }
    if data_dir
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!(
            "durable data directory {} must not contain `..`; choose its normalized absolute path",
            data_dir.display()
        );
    }
    let normalized = data_dir.components().collect::<PathBuf>();
    let parent = normalized.parent().ok_or_else(|| {
        anyhow!(
            "durable data directory {} has no parent directory",
            data_dir.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating data-directory parent {}", parent.display()))?;

    match fs::symlink_metadata(&normalized) {
        Ok(metadata) => {
            validate_private_data_dir(&normalized, &metadata, repair_same_user_permissions)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&normalized) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("creating private data directory {}", normalized.display())
                    })
                }
            }

            let metadata = fs::symlink_metadata(&normalized).with_context(|| {
                format!("inspecting new data directory {}", normalized.display())
            })?;
            validate_private_data_dir(&normalized, &metadata, false)
        }
        Err(error) => Err(error)
            .with_context(|| format!("inspecting data directory {}", normalized.display())),
    }
}

fn validate_private_data_dir(
    path: &Path,
    metadata: &fs::Metadata,
    repair_same_user_permissions: bool,
) -> Result<()> {
    // SAFETY: geteuid cannot fail and touches no memory.
    let us = unsafe { libc::geteuid() };
    let mode = metadata.mode() & 0o777;
    if metadata.file_type().is_dir() && metadata.uid() == us && mode == 0o700 {
        return Ok(());
    }

    if repair_same_user_permissions && metadata.file_type().is_dir() && metadata.uid() == us {
        return restrict_owned_default_data_dir(path, metadata, us);
    }

    bail!(
        "{} must be a real mode-0700 durable data directory owned by uid {us} (directory: {}, uid: {}, mode: {mode:04o}). Ouroboros will not chmod or replace a pre-existing unsafe directory. Verify its ownership and contents, then run `chmod 700 {}` if it is truly yours, or choose a fresh absolute OUROBOROS_DATA_DIR",
        path.display(),
        metadata.file_type().is_dir(),
        metadata.uid(),
        path.display()
    )
}

/// Restricts the exact directory inode that was inspected, without following a symlink
/// substituted between validation and chmod. The path is revalidated after `fchmod` too:
/// subsequent lifecycle operations must still reach the inode that was made private.
fn restrict_owned_default_data_dir(path: &Path, inspected: &fs::Metadata, us: u32) -> Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening the app-managed data directory {}", path.display()))?;
    let opened = directory.metadata().with_context(|| {
        format!(
            "inspecting the app-managed data directory {}",
            path.display()
        )
    })?;

    if !opened.file_type().is_dir()
        || opened.uid() != us
        || opened.dev() != inspected.dev()
        || opened.ino() != inspected.ino()
    {
        bail!(
            "the app-managed data directory {} changed while Ouroboros was securing it; retry startup",
            path.display()
        );
    }

    // SAFETY: the descriptor is an O_NOFOLLOW handle for the exact same-user directory
    // inode validated above. fchmod affects that inode rather than resolving the path again.
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error()).with_context(|| {
            format!(
                "restricting the app-managed data directory {} to mode 0700",
                path.display()
            )
        });
    }

    let secured = directory.metadata().with_context(|| {
        format!(
            "verifying the app-managed data directory {} after repair",
            path.display()
        )
    })?;
    let current = fs::symlink_metadata(path).with_context(|| {
        format!(
            "revalidating the app-managed data directory {} after repair",
            path.display()
        )
    })?;

    if secured.mode() & 0o777 != 0o700
        || !current.file_type().is_dir()
        || current.uid() != us
        || current.mode() & 0o777 != 0o700
        || current.dev() != secured.dev()
        || current.ino() != secured.ino()
    {
        bail!(
            "the app-managed data directory {} did not remain the same private mode-0700 directory after repair; retry startup",
            path.display()
        );
    }

    Ok(())
}

fn resolve_data_dir<F>(
    dev: bool,
    configured: Option<&OsStr>,
    fallback_root: F,
) -> Result<ResolvedDataDir>
where
    F: FnOnce() -> Result<PathBuf>,
{
    if let Some(value) = configured {
        let value = value.to_str().ok_or_else(|| {
            anyhow!("OUROBOROS_DATA_DIR must be valid UTF-8 so the Elixir runtime can read it")
        })?;
        let value = value.trim();

        if !value.is_empty() {
            let path = PathBuf::from(value);

            if !path.is_absolute() {
                bail!(
                    "OUROBOROS_DATA_DIR must be a nonblank absolute durable directory, got: {}",
                    path.display()
                );
            }

            return Ok(ResolvedDataDir {
                path,
                overridden: true,
            });
        }
    }

    let leaf = if dev { "ouroboros-dev" } else { "ouroboros" };
    Ok(ResolvedDataDir {
        path: fallback_root()?.join(leaf),
        overridden: false,
    })
}

/// One XDG root, read from the variable directly and falling back to a path under `$HOME`.
///
/// Public because [`crate::config`] resolves `XDG_CONFIG_HOME` by the same rule, and two
/// implementations of "an absolute variable wins, otherwise the home fallback" would be
/// two chances to disagree about what a relative value means.
pub fn xdg_root(variable: &str, fallback: &str) -> Result<PathBuf> {
    if let Some(value) = std::env::var_os(variable) {
        let path = PathBuf::from(value);

        if path.is_absolute() {
            return Ok(path);
        }
    }

    let home = dirs::home_dir().ok_or_else(|| {
        anyhow!(
            "neither {variable} nor a home directory is set, so there is \
             nowhere to keep this runtime's files"
        )
    })?;

    Ok(home.join(fallback))
}

/// `gateway.json`, decoded tolerantly: a newer gateway may publish more.
#[derive(Debug, Clone, Deserialize)]
pub struct Publication {
    pub port: u16,
    #[serde(default)]
    pub protocol: u32,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub pid: i32,
    /// Exact OS process incarnation. Absent only for an upgrade-era legacy runtime.
    #[serde(default)]
    pub birth: Option<String>,
    #[serde(default)]
    pub scope: String,
}

/// `web.json`, decoded tolerantly for the reason `gateway.json` is: a newer endpoint may
/// publish more.
///
/// ## Staleness here is weaker than the gateway's, knowingly
///
/// [`Publication`] carries `birth`, the exact kernel incarnation, so a recycled PID cannot
/// make a dead runtime look live. This document carries no such field —
/// `Ouroboros.Web.Publication.document/3` writes `port`, `protocol`, `node`, `pid`, and
/// `scope`, plus `token_file` when a file supplied the token, and nothing else — so
/// [`web_publication_is_live`] can ask only whether *some* process holds that PID today.
/// Between a killed daemon and its PID being reused, this client would read a stale
/// publication as live and name a port nobody is listening on.
///
/// That is survivable because of what this record is used for and nothing more: `ouro web`
/// builds a link and hands it to a browser, which either loads a page or does not. Nothing
/// reached through here signals a process, removes a file, or authorizes anything. The
/// checks that do — `ouro stop`, spawn-lock recovery, runtime ownership — read
/// `gateway.json` or `runtime.owner`, both of which carry `birth`. Closing the gap means
/// adding `birth` to the document the daemon writes; until that happens this paragraph is
/// the honest statement of it, not a claim that PID liveness is enough in general.
#[derive(Debug, Clone, Deserialize)]
pub struct WebPublication {
    pub port: u16,
    #[serde(default)]
    pub protocol: u32,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub pid: i32,
    #[serde(default)]
    pub scope: String,
    /// The 0600 file holding the operator token, named rather than embedded. Absent
    /// exactly when no file supplied that token, which leaves nothing to point at.
    #[serde(default)]
    pub token_file: Option<String>,
}

/// The durable-directory owner written before any core runtime journal is opened.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuntimeOwner {
    pub pid: i32,
    pub owner: String,
    /// Exact OS process incarnation. Absent only on legacy/direct-release markers.
    #[serde(default)]
    pub birth: Option<String>,
}

/// A PID paired with the kernel birth fact that survives neither PID reuse nor reboot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub birth: String,
}

impl ProcessIdentity {
    pub fn current() -> Result<Self> {
        let pid = std::process::id() as i32;
        let birth = process_birth(pid)?.ok_or_else(|| {
            anyhow!("this ouro process disappeared while reading its own incarnation")
        })?;
        Ok(Self { pid, birth })
    }

    pub fn of(pid: i32, birth: &str) -> Result<Self> {
        validate_birth(birth)?;
        Ok(Self {
            pid,
            birth: birth.to_owned(),
        })
    }
}

impl Publication {
    pub fn identity(&self) -> Result<Option<ProcessIdentity>> {
        self.birth
            .as_deref()
            .map(|birth| ProcessIdentity::of(self.pid, birth))
            .transpose()
    }
}

impl RuntimeOwner {
    pub fn identity(&self) -> Result<Option<ProcessIdentity>> {
        self.birth
            .as_deref()
            .map(|birth| ProcessIdentity::of(self.pid, birth))
            .transpose()
    }
}

fn validate_birth(birth: &str) -> Result<()> {
    if birth.is_empty()
        || birth.len() > 256
        || !birth
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
    {
        bail!("process birth identity is malformed");
    }
    Ok(())
}

/// Returns the kernel identity for one live process, or `None` only when that PID is gone.
///
/// Linux combines the boot UUID with `/proc/<pid>/stat`'s start ticks. macOS combines the
/// boot-session UUID with `proc_pidinfo`'s microsecond process start. Both distinguish a
/// recycled PID, including across reboot; permission and malformed-kernel-data failures
/// remain errors rather than becoming permission to replace or signal anything.
pub fn process_birth(pid: i32) -> Result<Option<String>> {
    if pid <= 0 {
        return Ok(None);
    }
    process_birth_platform(pid)
}

#[cfg(target_os = "linux")]
fn process_birth_platform(pid: i32) -> Result<Option<String>> {
    let stat_path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = match fs::read_to_string(&stat_path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context(format!(
                "reading process incarnation from {}",
                stat_path.display()
            ))
        }
    };
    let close = stat
        .rfind(") ")
        .ok_or_else(|| anyhow!("{} has no complete process-name field", stat_path.display()))?;
    // Fields after `pid (comm)` begin with field 3 (state); starttime is field 22.
    let start_ticks = stat[close + 2..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| anyhow!("{} omits process start ticks", stat_path.display()))?;
    if start_ticks.parse::<u64>().is_err() {
        bail!(
            "{} contains invalid process start ticks",
            stat_path.display()
        );
    }
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("reading Linux boot identity")?;
    let boot = boot.trim();
    let birth = format!("linux:{boot}:{start_ticks}");
    validate_birth(&birth)?;
    Ok(Some(birth))
}

#[cfg(target_os = "macos")]
fn process_birth_platform(pid: i32) -> Result<Option<String>> {
    // SAFETY: proc_pidinfo writes at most the provided proc_bsdinfo buffer. A zero return
    // is interpreted through errno; a short result is never consumed.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let expected = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            expected,
        )
    };
    if read == 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) | Some(libc::ENOENT) => Ok(None),
            _ if !pid_alive(pid) => Ok(None),
            _ => Err(error).context(format!("reading incarnation for pid {pid}")),
        };
    }
    if read != expected || info.pbi_pid != pid as u32 {
        bail!(
            "macOS returned an incomplete or mismatched incarnation for pid {pid} ({read}/{expected} bytes, pid {})",
            info.pbi_pid
        );
    }
    let boot = macos_boot_session()?;
    let birth = format!(
        "macos:{boot}:{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    );
    validate_birth(&birth)?;
    Ok(Some(birth))
}

#[cfg(target_os = "macos")]
fn macos_boot_session() -> Result<String> {
    let name = CString::new("kern.bootsessionuuid").expect("static sysctl name");
    let mut len = 0usize;
    // SAFETY: the first call writes only the required byte length.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("reading macOS boot-session length");
    }
    if len == 0 || len > 256 {
        bail!("macOS returned an invalid boot-session length ({len})");
    }
    let mut bytes = vec![0u8; len];
    // SAFETY: bytes owns exactly the capacity supplied to sysctlbyname.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("reading macOS boot session");
    }
    bytes.truncate(len);
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    String::from_utf8(bytes).context("macOS boot-session identity is not UTF-8")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_birth_platform(pid: i32) -> Result<Option<String>> {
    if pid_alive(pid) {
        bail!("exact process incarnation is unsupported on this operating system")
    }
    Ok(None)
}

/// True only while the same PID incarnation still exists.
pub fn process_identity_is_live(identity: &ProcessIdentity) -> Result<bool> {
    Ok(process_birth(identity.pid)?.as_deref() == Some(identity.birth.as_str()))
}

/// Legacy records have no safe PID-reuse proof. They remain conservatively live while the
/// PID exists, but callers must not use this result to authorize a signal.
pub fn publication_is_live(publication: &Publication) -> Result<bool> {
    match publication.identity()? {
        Some(identity) => process_identity_is_live(&identity),
        None => Ok(pid_alive(publication.pid)),
    }
}

pub fn runtime_owner_is_live(owner: &RuntimeOwner) -> Result<bool> {
    match owner.identity()? {
        Some(identity) => process_identity_is_live(&identity),
        None => Ok(pid_alive(owner.pid)),
    }
}

/// Reads the publication, or `None` when the gateway has not written one.
pub fn read_publication(data_dir: &Path) -> Result<Option<Publication>> {
    ensure_private_data_dir(data_dir)?;
    let path = data_dir.join(PUBLICATION_FILE);
    let Some((contents, _identity)) =
        read_private_file(&path, "gateway publication", PRIVATE_MARKER_MAX_BYTES)?
    else {
        return Ok(None);
    };

    let publication: Publication = serde_json::from_slice(&contents)
        .with_context(|| format!("{} is not a gateway publication", path.display()))?;
    if publication.pid <= 0 {
        bail!("{} must contain a positive pid", path.display());
    }
    if let Some(birth) = publication.birth.as_deref() {
        validate_birth(birth).with_context(|| format!("invalid birth in {}", path.display()))?;
    }
    Ok(Some(publication))
}

/// Refuses a publication this user does not own. `ouro stop` signals the pid this file
/// names, and a file somebody else can write is a file that can name somebody else's pid.
pub fn read_owned_publication(data_dir: &Path) -> Result<Option<Publication>> {
    read_publication(data_dir)
}

pub fn read_live_publication(data_dir: &Path) -> Result<Option<Publication>> {
    match read_owned_publication(data_dir)? {
        Some(publication) if publication_is_live(&publication)? => Ok(Some(publication)),
        Some(_) | None => Ok(None),
    }
}

/// PID liveness alone. There is no incarnation in `web.json` to check it against, which is
/// the whole of what [`WebPublication`] documents and why this returns a plain `bool`
/// where [`publication_is_live`] returns a `Result`: nothing here can fail, because
/// nothing here is proved.
pub fn web_publication_is_live(publication: &WebPublication) -> bool {
    pid_alive(publication.pid)
}

/// Reads `web.json`, or `None` when no endpoint has written one.
///
/// Held to the same file discipline as [`read_publication`], through the same reader: a
/// regular 0600 file owned by this uid, opened without following its final component, and
/// bounded before a byte is allocated. The daemon writes it that way
/// (`Ouroboros.Web.Publication`), so anything else here is a file this client should
/// refuse rather than build a URL from.
pub fn read_web_publication(data_dir: &Path) -> Result<Option<WebPublication>> {
    ensure_private_data_dir(data_dir)?;
    let path = data_dir.join(WEB_PUBLICATION_FILE);
    let Some((contents, _identity)) =
        read_private_file(&path, "web publication", PRIVATE_MARKER_MAX_BYTES)?
    else {
        return Ok(None);
    };

    let publication: WebPublication = serde_json::from_slice(&contents)
        .with_context(|| format!("{} is not a web publication", path.display()))?;
    if publication.pid <= 0 {
        bail!("{} must contain a positive pid", path.display());
    }
    Ok(Some(publication))
}

/// The same read, with a publication whose PID is gone reported as absent rather than as a
/// port. A malformed or unreadable file stays an error: that is a fact worth saying, not a
/// reason to report the surface as missing.
pub fn read_live_web_publication(data_dir: &Path) -> Result<Option<WebPublication>> {
    match read_web_publication(data_dir)? {
        Some(publication) if web_publication_is_live(&publication) => Ok(Some(publication)),
        Some(_) | None => Ok(None),
    }
}

/// The gateway endpoint as the data directory publishes it right now: the port from a
/// live `gateway.json`, the token from the file beside it. Reconnect attempts consult
/// this so an attached client outlives `ouro stop` + `ouro daemon` — the restart rotates
/// the token and may move the port, and both are on disk before the new gateway accepts
/// its first connection. No live publication, or one this client cannot read, is `None`:
/// the runtime is down and the client's honest move is to keep waiting, not to guess.
#[derive(Debug)]
pub struct PublishedEndpoint {
    data_dir: PathBuf,
    token_file: PathBuf,
}

impl PublishedEndpoint {
    pub fn new(data_dir: PathBuf, token_file: PathBuf) -> Self {
        Self {
            data_dir,
            token_file,
        }
    }
}

impl EndpointSource for PublishedEndpoint {
    fn current(&self) -> Option<(std::net::SocketAddr, Secret)> {
        let publication = read_live_publication(&self.data_dir).ok().flatten()?;
        let token = read_token(&self.token_file).ok()?;

        Some((
            std::net::SocketAddr::from(([127, 0, 0, 1], publication.port)),
            token,
        ))
    }
}

/// A fixed `--addr` whose token file is re-read before each reconnect attempt. The port
/// cannot move — the caller chose it — but a restart on the other end still rotates the
/// token, and the file the caller named is where the rotation lands.
#[derive(Debug)]
pub struct TokenFileEndpoint {
    addr: std::net::SocketAddr,
    token_file: PathBuf,
}

impl TokenFileEndpoint {
    pub fn new(addr: std::net::SocketAddr, token_file: PathBuf) -> Self {
        Self { addr, token_file }
    }
}

impl EndpointSource for TokenFileEndpoint {
    fn current(&self) -> Option<(std::net::SocketAddr, Secret)> {
        let token = read_token(&self.token_file).ok()?;
        Some((self.addr, token))
    }
}

/// Reads the runtime-lifetime owner marker, refusing files this user cannot trust.
///
/// Unlike `gateway.json`, this file is not removed and treated as absent merely because
/// its pid died: stale recovery belongs to the new BEAM's atomic claim. The client only
/// needs to distinguish a live holder (never spawn) from a dead one (the child may claim
/// it), and must leave both the marker and every process untouched.
pub fn read_owned_runtime_owner(data_dir: &Path) -> Result<Option<RuntimeOwner>> {
    ensure_private_data_dir(data_dir)?;
    let path = data_dir.join(RUNTIME_OWNER_FILE);
    let Some((contents, _identity)) =
        read_private_file(&path, "runtime owner", PRIVATE_MARKER_MAX_BYTES)?
    else {
        return Ok(None);
    };
    let owner: RuntimeOwner = serde_json::from_slice(&contents)
        .with_context(|| format!("{} is not a runtime owner marker", path.display()))?;

    if owner.pid <= 0 || owner.owner.trim().is_empty() {
        bail!(
            "{} must contain a positive pid and a nonblank owner identity; refusing to \
             replace an owner this client cannot verify",
            path.display()
        );
    }
    if let Some(birth) = owner.birth.as_deref() {
        validate_birth(birth).with_context(|| format!("invalid birth in {}", path.display()))?;
    }

    Ok(Some(owner))
}

pub fn read_live_runtime_owner(data_dir: &Path) -> Result<Option<RuntimeOwner>> {
    match read_owned_runtime_owner(data_dir)? {
        Some(owner) if runtime_owner_is_live(&owner)? => Ok(Some(owner)),
        Some(_) | None => Ok(None),
    }
}

/// Refuses a spawn when a live BEAM still owns the target data directory.
///
/// Call this under the short-lived client spawn lock, after giving a usable live
/// `gateway.json` the chance to be adopted and before rewriting `gateway.token`. A dead
/// marker is deliberately left for the child runtime's bounded atomic recovery.
pub fn ensure_no_live_runtime_owner(data_dir: &Path) -> Result<()> {
    ensure_private_data_dir(data_dir)?;
    let recovery = data_dir.join(RUNTIME_OWNER_RECOVERY_FILE);
    reconcile_runtime_owner_recovery_gate(data_dir, &recovery)?;

    let Some(owner) = read_owned_runtime_owner(data_dir)? else {
        return Ok(());
    };

    if runtime_owner_is_live(&owner)? {
        bail!(
            "runtime pid {} still owns {} through {}; no usable {} was found, so this \
             client will not start a second runtime or signal the owner. The gateway may \
             still be starting or restarting; retry, or inspect that runtime without \
             deleting its owner marker",
            owner.pid,
            data_dir.display(),
            data_dir.join(RUNTIME_OWNER_FILE).display(),
            PUBLICATION_FILE
        );
    }

    Ok(())
}

fn reconcile_runtime_owner_recovery_gate(data_dir: &Path, path: &Path) -> Result<()> {
    let file = open_versioned_recovery_inode(
        path,
        RUNTIME_RECOVERY_HEADER,
        "runtime-owner recovery gate",
    )?;
    // SAFETY: a successful nonblocking lock is held only for this probe and released
    // before returning. Process death releases a claimant's lock automatically.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            bail!(
                "{} is held by another runtime-owner recovery for {}; wait for that exact startup to finish",
                path.display(),
                data_dir.display()
            );
        }
        return Err(error).context(format!("probing {}", path.display()));
    }
    // SAFETY: releases only this descriptor's successful probe lock.
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    Ok(())
}

fn remove_publication(data_dir: &Path) -> Result<()> {
    match fs::remove_file(data_dir.join(PUBLICATION_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// The publication found while holding this data directory's spawn lock.
///
/// Stale removal is part of this reconciliation rather than an action a pre-lock reader
/// may take later. That makes a concurrent starter's freshly published gateway immune to
/// a client that observed an older dead pid before the starter won the lock.
#[derive(Debug)]
pub enum LockedPublication {
    Absent,
    Live(Publication),
    RemovedStale(Publication),
}

pub fn reconcile_publication_under_spawn_lock(
    data_dir: &Path,
    lock: &SpawnLock,
) -> Result<LockedPublication> {
    let expected_lock = data_dir.join(SPAWN_LOCK_FILE);

    if lock.path() != expected_lock {
        bail!(
            "spawn lock {} cannot reconcile the publication in {}",
            lock.path().display(),
            data_dir.display()
        );
    }

    let Some(publication) = read_owned_publication(data_dir)? else {
        return Ok(LockedPublication::Absent);
    };

    if publication_is_live(&publication)? {
        return Ok(LockedPublication::Live(publication));
    }

    remove_publication(data_dir)?;
    Ok(LockedPublication::RemovedStale(publication))
}

/// Whether a pid names a live process this user can see.
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }

    // SAFETY: signal 0 performs the existence and permission check and delivers nothing.
    let outcome = unsafe { libc::kill(pid, 0) };

    outcome == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Sends one signal, naming the pid on failure.
pub fn send_signal(pid: i32, signal: i32) -> Result<()> {
    // SAFETY: kill/2 with a pid this client obtained from its own child or from a
    // publication file it verified it owns.
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();

    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }

    Err(anyhow!("cannot signal pid {pid}: {error}"))
}

/// The exclusive right to spawn into one data directory, released when dropped.
///
/// A lock file rather than an advisory `flock`: the winner's pid has to be *readable* by
/// the loser to be reportable. Its inode is written and synced under a private temporary
/// name, then hard-linked here, so the compare-and-create destination is never partial.
#[derive(Debug)]
pub struct SpawnLock {
    path: PathBuf,
    identity: FileIdentity,
}

impl SpawnLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SpawnLock {
    fn drop(&mut self) {
        // A lock this process cannot remove becomes a stale lock the next client clears,
        // which is why staleness is decided by the pid inside rather than by the file
        // existing. Failing loudly here would replace a recoverable state with a crash.
        remove_owned_claim(&self.path, self.identity);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn of(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;

        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn matches(self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.file_type().is_file()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        })
    }
}

/// Opens and reads a user-owned private regular file without following its final path
/// component, bounds the allocation, and proves the stable name still denotes that inode.
fn read_private_file(
    path: &Path,
    description: &str,
    max_bytes: u64,
) -> Result<Option<(Vec<u8>, FileIdentity)>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context(format!(
                "opening {description} {} without following links",
                path.display()
            ))
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {description} {}", path.display()))?;
    // SAFETY: geteuid cannot fail and touches no memory.
    let us = unsafe { libc::geteuid() };
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_file() || metadata.uid() != us || mode != 0o600 {
        bail!(
            "{} is not a private regular {description} at mode 0600 owned by uid {us} \
             (type regular: {}, uid: {}, mode: {mode:04o})",
            path.display(),
            metadata.file_type().is_file(),
            metadata.uid()
        );
    }
    if metadata.len() > max_bytes {
        bail!(
            "{description} {} is {} bytes, above the {max_bytes}-byte limit",
            path.display(),
            metadata.len()
        );
    }
    let identity = FileIdentity::of(&file)?;
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut contents)
        .with_context(|| format!("reading {description} {}", path.display()))?;
    if contents.len() as u64 > max_bytes {
        bail!(
            "{description} {} grew above the {max_bytes}-byte limit while being read",
            path.display()
        );
    }
    if !identity.matches(path) {
        bail!(
            "{description} {} changed while it was being read; retry without acting on it",
            path.display()
        );
    }
    Ok(Some((contents, identity)))
}

fn remove_owned_claim(path: &Path, identity: FileIdentity) {
    if identity.matches(path) {
        let _ = fs::remove_file(path);
    }
}

#[derive(Debug)]
struct SpawnLockRecovery {
    file: File,
}

/// A fully written private claim inode that has not yet been published at its stable
/// name. Dropping every arm removes the temporary link; after publication the stable
/// link has its own identity-checked owner guard.
#[derive(Debug)]
struct PreparedPidClaim {
    temporary: PathBuf,
    identity: FileIdentity,
}

impl PreparedPidClaim {
    fn publish(&self, path: &Path) -> io::Result<()> {
        fs::hard_link(&self.temporary, path)
    }
}

impl Drop for PreparedPidClaim {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temporary);
    }
}

#[derive(Debug, Clone)]
struct LockHolder {
    process: Option<ProcessIdentity>,
    legacy_pid: i32,
    identity: FileIdentity,
}

impl LockHolder {
    fn pid(&self) -> i32 {
        self.process
            .as_ref()
            .map(|identity| identity.pid)
            .unwrap_or(self.legacy_pid)
    }

    fn live(&self) -> Result<bool> {
        match &self.process {
            Some(identity) => process_identity_is_live(identity),
            None => Ok(pid_alive(self.legacy_pid)),
        }
    }
}

impl Drop for SpawnLockRecovery {
    fn drop(&mut self) {
        // SAFETY: this descriptor remains open for the guard's entire lifetime. Unlock is
        // best effort in Drop; close releases it as a second, kernel-enforced backstop.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Takes the spawn lock, clearing exactly one lock whose owner is gone.
///
/// Dead-lock recovery has its own kernel-held advisory gate. Without it, two clients can both observe
/// stale lock S, then B can unlink the new lock A created after removing S. Only the gate
/// winner re-reads, unlinks, and claims; every loser fails without touching either file.
/// Process death closes the descriptor and releases the gate, so a killed claimant cannot
/// permanently strand unattended service recovery.
pub fn acquire_spawn_lock(data_dir: &Path) -> Result<SpawnLock> {
    ensure_private_data_dir(data_dir)?;

    // A recovery claimant may have crashed after removing the old lock but before
    // publishing its replacement. An absent spawn.lock does not authorize bypassing
    // that durable warning.
    ensure_spawn_lock_recovery_available(data_dir)?;

    let path = data_dir.join(SPAWN_LOCK_FILE);

    match try_create_lock(&path) {
        Ok(lock) => return Ok(lock),
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
            return Err(anyhow::Error::from(error).context(format!("writing {}", path.display())));
        }
        Err(_taken) => {}
    }

    let Some(holder) = read_lock_holder(&path)? else {
        // The first owner released its lock between our failed hard link and our read.
        // Make one bounded claim attempt; a new winner gets a clear retry instead of an
        // unbounded loop hidden inside a command.
        ensure_spawn_lock_recovery_available(data_dir)?;
        return try_create_lock(&path).map_err(|error| {
            anyhow!(
                "cannot take spawn lock {} after the previous claim disappeared; retry: {error}",
                path.display()
            )
        });
    };

    if holder.live()? {
        bail!(
            "another ouro (pid {}) is starting a runtime in {}; wait for it to publish \
             {}, then attach — two daemons in one data directory would each overwrite \
             the other's token and publication",
            holder.pid(),
            data_dir.display(),
            PUBLICATION_FILE
        );
    }

    recover_stale_spawn_lock(data_dir, &path, || {})
}

fn try_create_lock(path: &Path) -> io::Result<SpawnLock> {
    try_create_lock_with(path, || {})
}

fn try_create_lock_with<F>(path: &Path, after_publish: F) -> io::Result<SpawnLock>
where
    F: FnOnce(),
{
    let prepared = prepare_private_pid_claim(path)?;
    prepared.publish(path)?;

    let lock = SpawnLock {
        path: path.to_path_buf(),
        identity: prepared.identity,
    };

    // Test-only callers use this boundary to prove that every concurrent reader sees
    // the complete pid. If the hook panics, both guards still remove their own links.
    after_publish();

    Ok(lock)
}

fn recover_stale_spawn_lock<F>(data_dir: &Path, path: &Path, after_claim: F) -> Result<SpawnLock>
where
    F: FnOnce(),
{
    let _recovery = claim_spawn_lock_recovery(data_dir)?;
    after_claim();

    // The observation before claiming the recovery gate authorizes nothing. Another
    // recovery may have completed first, so decide again while this claim is exclusive.
    if let Some(holder) = read_lock_holder(path)? {
        if holder.live()? {
            bail!(
                "another ouro (pid {}) now owns the spawn lock in {}; this client will \
                 not replace it after its stale observation",
                holder.pid(),
                data_dir.display()
            );
        }

        if !holder.identity.matches(path) {
            bail!(
                "{} changed while stale recovery was deciding what it owned; retry rather \
                 than unlinking a replacement claim",
                path.display()
            );
        }
    }

    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(anyhow::Error::from(error)
                .context(format!("removing the stale spawn lock {}", path.display())))
        }
    }

    try_create_lock(path).map_err(|error| {
        anyhow!(
            "cannot take the spawn lock {} after clearing a stale one under {}: {error}",
            path.display(),
            data_dir.join(SPAWN_LOCK_RECOVERY_FILE).display()
        )
    })
}

fn claim_spawn_lock_recovery(data_dir: &Path) -> Result<SpawnLockRecovery> {
    let path = data_dir.join(SPAWN_LOCK_RECOVERY_FILE);
    let file = open_spawn_recovery_inode(&path)?;
    // SAFETY: flock operates on this owned descriptor and changes no filesystem names.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            bail!(
                "another ouro is recovering the stale spawn lock in {} through {}; wait for that exact claimant to finish",
                data_dir.display(),
                path.display()
            );
        }
        return Err(error).context(format!("locking stale recovery gate {}", path.display()));
    }
    let identity = FileIdentity::of(&file)?;
    if !identity.matches(&path) {
        // SAFETY: only releases the lock acquired above.
        let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        bail!(
            "{} changed while its recovery lock was acquired; retry without touching either claim",
            path.display()
        );
    }
    Ok(SpawnLockRecovery { file })
}

fn prepare_private_pid_claim(path: &Path) -> io::Result<PreparedPidClaim> {
    let process = ProcessIdentity::current().map_err(io::Error::other)?;
    let mut contents = serde_json::to_vec(&process).map_err(io::Error::other)?;
    contents.push(b'\n');
    prepare_private_contents_claim(path, &contents)
}

fn prepare_private_contents_claim(path: &Path, contents: &[u8]) -> io::Result<PreparedPidClaim> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no directory for an atomic claim", path.display()),
        )
    })?;
    let label = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("ouro-claim");

    for _attempt in 0..128 {
        let sequence = CLAIM_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{label}.{}.{}.tmp", std::process::id(), sequence));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let identity = match FileIdentity::of(&file) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                return Err(error);
            }
        };
        let prepared = PreparedPidClaim {
            temporary,
            identity,
        };

        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(contents)?;
        file.sync_all()?;

        return Ok(prepared);
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "cannot allocate a private temporary claim beside {} after 128 attempts",
            path.display()
        ),
    ))
}

fn validate_private_open_file(path: &Path, description: &str, file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {description} {}", path.display()))?;
    // SAFETY: geteuid cannot fail.
    let us = unsafe { libc::geteuid() };
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_file() || metadata.uid() != us || mode != 0o600 {
        bail!(
            "{} is not a private regular {description} at mode 0600 owned by uid {us} (regular: {}, uid: {}, mode: {mode:04o})",
            path.display(),
            metadata.file_type().is_file(),
            metadata.uid()
        );
    }
    Ok(())
}

fn ensure_spawn_lock_recovery_available(data_dir: &Path) -> Result<()> {
    drop(claim_spawn_lock_recovery(data_dir)?);
    Ok(())
}

fn open_spawn_recovery_inode(path: &Path) -> Result<File> {
    open_versioned_recovery_inode(path, SPAWN_RECOVERY_HEADER, "spawn-lock recovery gate")
}

fn open_versioned_recovery_inode(path: &Path, header: &[u8], description: &str) -> Result<File> {
    if !path.exists() {
        let prepared = prepare_private_contents_claim(path, header)?;
        match prepared.publish(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).context(format!("publishing recovery inode {}", path.display()))
            }
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening recovery inode {}", path.display()))?;
    validate_private_open_file(path, description, &file)?;
    let identity = FileIdentity::of(&file)?;
    let mut contents = Vec::new();
    Read::by_ref(&mut file)
        .take(PRIVATE_MARKER_MAX_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents != header {
        bail!(
            "{} is a legacy or malformed recovery gate. It may belong to an older active client, so stop and inspect all Ouroboros startups using this data directory before removing exactly this file once",
            path.display()
        );
    }
    if !identity.matches(path) {
        bail!(
            "{} changed while its recovery inode was opened",
            path.display()
        );
    }
    Ok(file)
}

/// Hidden BEAM helper: hold the runtime-owner recovery flock until the owning Port closes
/// stdin. The fixed inode persists, while a claimant/VM crash releases the kernel lock.
pub fn hold_runtime_recovery_lock(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow!(
            "runtime recovery path {} has no data-directory parent",
            path.display()
        )
    })?;
    ensure_private_data_dir(parent)?;
    let file = open_versioned_recovery_inode(
        path,
        RUNTIME_RECOVERY_HEADER,
        "runtime-owner recovery gate",
    )?;
    // SAFETY: the descriptor stays owned until stdin EOF below.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            bail!("another runtime is already recovering this data directory");
        }
        return Err(error).context(format!("locking {}", path.display()));
    }
    println!("locked");
    io::stdout().flush()?;
    let mut sink = io::sink();
    io::copy(&mut io::stdin().lock(), &mut sink)?;
    Ok(())
}

/// The pid and inode inside a private lock file, or `None` only when the name vanished.
///
/// Malformed claims fail closed. New claims are atomically published only after their pid
/// is complete, but this may still encounter an interrupted legacy client or manual
/// damage; neither state authorizes guessing that no startup owns the file.
fn read_lock_holder(path: &Path) -> Result<Option<LockHolder>> {
    let Some((contents, identity)) = read_private_pid_claim(path, "spawn lock")? else {
        return Ok(None);
    };
    let trimmed = contents.trim();
    let process = serde_json::from_str::<ProcessIdentity>(trimmed)
        .ok()
        .filter(|identity| identity.pid > 0 && validate_birth(&identity.birth).is_ok());
    let legacy_pid = trimmed.parse::<i32>().ok().filter(|pid| *pid > 0);
    if process.is_none() && legacy_pid.is_none() {
        let data_dir = path.parent().unwrap_or_else(|| Path::new("."));

        bail!(
            "{} does not contain one positive pid, so this client will not clear it as \
             stale. It may be an interrupted legacy claim. Retry shortly; if it remains \
             malformed, first stop and inspect every Ouroboros startup using {}, then \
             remove exactly {} only when none can own it",
            path.display(),
            data_dir.display(),
            path.display()
        );
    }

    Ok(Some(LockHolder {
        legacy_pid: legacy_pid.unwrap_or_default(),
        process,
        identity,
    }))
}

/// Reads a private claim without following symlinks, and proves that the stable name
/// still refers to the inode read. Any ownership, type, permission, or replacement
/// ambiguity is an error rather than a stale-recovery authorization.
fn read_private_pid_claim(
    path: &Path,
    description: &str,
) -> Result<Option<(String, FileIdentity)>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context(format!(
                "opening {description} {} without following links",
                path.display()
            ))
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {description} {}", path.display()))?;
    // SAFETY: geteuid cannot fail and touches no memory.
    let us = unsafe { libc::geteuid() };

    if !metadata.file_type().is_file() || metadata.uid() != us || metadata.mode() & 0o777 != 0o600 {
        bail!(
            "{} is not a private regular {description} at mode 0600 owned by uid {us} \
             (type regular: {}, uid: {}, mode: {:o}); this client will not clear it",
            path.display(),
            metadata.file_type().is_file(),
            metadata.uid(),
            metadata.mode() & 0o777
        );
    }

    let identity = FileIdentity::of(&file)?;
    let mut contents = String::new();
    io::Read::read_to_string(&mut file, &mut contents)
        .with_context(|| format!("reading {description} {}", path.display()))?;

    if !identity.matches(path) {
        bail!(
            "{description} {} changed while it was being read; retry without clearing it",
            path.display()
        );
    }

    Ok(Some((contents, identity)))
}

/// Writes a fresh token and returns it. 32 bytes of OS randomness rendered as hex, which
/// is 64 bytes on the wire — comfortably past the gateway's 32-byte floor.
pub fn write_token(path: &Path) -> Result<Secret> {
    let mut bytes = [0u8; 32];

    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| anyhow!("cannot read OS randomness for a gateway token: {error}"))?;

    let mut token = String::with_capacity(64);

    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(token, "{byte:02x}");
    }

    bytes.zeroize();

    let parent = path.parent().ok_or_else(|| {
        anyhow!(
            "gateway token path {} has no data-directory parent",
            path.display()
        )
    })?;
    ensure_private_data_dir(parent)?;

    // A crashed daemon's token is deliberately replaced, but only through a nofollow
    // descriptor whose owner, mode, type, and stable inode were proven first.
    let (mut file, created) = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => (file, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map(|file| (file, false))
            .with_context(|| {
                format!(
                    "opening existing token {} without following links",
                    path.display()
                )
            })?,
        Err(error) => return Err(error).context(format!("creating {}", path.display())),
    };
    if created {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    validate_private_open_file(path, "gateway token", &file)?;
    let identity = FileIdentity::of(&file)?;
    if !identity.matches(path) {
        bail!(
            "gateway token {} changed before it could be written",
            path.display()
        );
    }
    file.set_len(0)?;
    file.seek(io::SeekFrom::Start(0))?;

    let outcome = file
        .write_all(token.as_bytes())
        .and_then(|()| file.sync_all());

    if let Err(error) = outcome {
        token.zeroize();
        return Err(anyhow::Error::from(error).context(format!("writing {}", path.display())));
    }

    if !identity.matches(path) {
        token.zeroize();
        bail!(
            "gateway token {} changed while it was being written",
            path.display()
        );
    }

    let secret = Secret::new(token.clone());
    token.zeroize();

    Ok(secret)
}

/// Resolves a workspace path against the directory the operator typed it in.
///
/// A relative path is ambiguous across a socket: the runtime would resolve it against
/// *its own* working directory, which for a spawned daemon is a release root and for a
/// `--dev` one is the checkout — neither of which is where the person stood. Absolutising
/// here makes the local case correct and the remote case explicit, because an absolute
/// path is at least a claim the operator can check against the runtime's filesystem.
pub fn resolve_workspace(path: &Path, base: &Path) -> String {
    if path.is_absolute() {
        return path.display().to_string();
    }

    base.join(path).display().to_string()
}

/// Reads a token file, trimming the trailing newline a human's editor adds. The gateway
/// trims the same way.
pub fn read_token(path: &Path) -> Result<Secret> {
    let Some((bytes, _identity)) = read_private_file(path, "gateway token", 4 * 1024)? else {
        bail!("gateway token {} does not exist", path.display());
    };
    let mut contents = String::from_utf8(bytes)
        .with_context(|| format!("gateway token {} is not UTF-8", path.display()))?;

    let secret = Secret::new(contents.trim().to_string());
    contents.zeroize();

    if secret.expose().is_empty() {
        bail!(
            "{} is empty; the gateway refuses a blank token",
            path.display()
        );
    }

    Ok(secret)
}

/// The environment a spawned runtime is given, as overrides onto the caller's own.
///
/// Cluster variables pass through untouched: a host that already carries
/// `OUROBOROS_CLUSTER_STRATEGY` or `OUROBOROS_NODE` is a host whose operator decided how
/// this node joins a cluster, and `OUROBOROS_DIST=none` would contradict that decision —
/// `rel/env.sh.eex` refuses the combination outright. Nothing else about an existing
/// server workflow changes, because nothing else is set.
pub fn spawn_env(
    caller: &[(String, String)],
    data_dir: &Path,
    token_file: &Path,
) -> Result<Vec<(String, String)>> {
    let clustered = ["OUROBOROS_CLUSTER_STRATEGY", "OUROBOROS_NODE"]
        .iter()
        .any(|name| {
            caller
                .iter()
                .any(|(key, value)| key == name && !value.trim().is_empty())
        });

    let mut env = vec![
        ("OUROBOROS_GATEWAY".to_string(), "1".to_string()),
        // docs/WEB.md D5: wherever the gateway is on, the browser surface is on. It has to
        // be said here rather than left to `config/runtime.exs`, because the line above is
        // what takes that file out of its defaulted single-machine branch — the branch
        // that would otherwise have enabled the web surface on its own — so a daemon this
        // client spawns and did not tell would serve nothing to a browser. Same risk class
        // answered the same way: loopback, and the one operator token this directory
        // already has. Like every other value in this list it overrides a caller's, so the
        // documented `OUROBOROS_WEB=0` opt-out belongs to a daemon an operator starts
        // themselves, not to one `ouro` starts for them.
        ("OUROBOROS_WEB".to_string(), "1".to_string()),
        ("OUROBOROS_GATEWAY_SCOPE".to_string(), "operate".to_string()),
        (
            "OUROBOROS_GATEWAY_ALLOW_SHUTDOWN".to_string(),
            "1".to_string(),
        ),
        ("OUROBOROS_GATEWAY_PORT".to_string(), "0".to_string()),
        (
            "OUROBOROS_GATEWAY_BIND".to_string(),
            "127.0.0.1".to_string(),
        ),
        (
            "OUROBOROS_GATEWAY_ALLOW_REMOTE".to_string(),
            "0".to_string(),
        ),
        (
            "OUROBOROS_GATEWAY_TOKEN_FILE".to_string(),
            token_file.display().to_string(),
        ),
        (
            "OUROBOROS_DATA_DIR".to_string(),
            data_dir.display().to_string(),
        ),
    ];

    if let Some(fleet) = crate::fleet::runtime_env(data_dir)? {
        for (key, value) in fleet {
            if let Some(existing) = env.iter_mut().find(|(name, _)| *name == key) {
                existing.1 = value;
            } else {
                env.push((key, value));
            }
        }
        for (key, value) in crate::fleet::validated_runtime_authority_env(caller)? {
            if let Some(existing) = env.iter_mut().find(|(name, _)| *name == key) {
                existing.1 = value;
            } else {
                env.push((key, value));
            }
        }
    } else if !clustered {
        env.push(("OUROBOROS_DIST".to_string(), "none".to_string()));
    }

    Ok(env)
}

fn apply_spawn_environment(
    command: &mut Command,
    caller: &[(String, String)],
    environment: Vec<(String, String)>,
) {
    let fleet_profile = environment
        .iter()
        .any(|(key, _)| key == "OUROBOROS_FLEET_ID");
    if fleet_profile {
        for (key, _) in caller {
            if key.starts_with("OUROBOROS_")
                || versioned_otp_flags(key)
                || matches!(
                    key.as_str(),
                    "ERL_AFLAGS"
                        | "ERL_FLAGS"
                        | "ERL_INETRC"
                        | "ERL_LIBS"
                        | "ERL_ZFLAGS"
                        | "ELIXIR_ERL_OPTIONS"
                        | "RELEASE_BOOT_SCRIPT"
                        | "RELEASE_COMMAND"
                        | "RELEASE_COOKIE"
                        | "RELEASE_DISTRIBUTION"
                        | "RELEASE_MODE"
                        | "RELEASE_NAME"
                        | "RELEASE_NODE"
                        | "RELEASE_REMOTE_VM_ARGS"
                        | "RELEASE_ROOT"
                        | "RELEASE_SYS_CONFIG"
                        | "RELEASE_TMP"
                        | "RELEASE_VM_ARGS"
                        | "RELEASE_VSN"
                )
            {
                command.env_remove(key);
            }
        }
    }
    if environment
        .iter()
        .any(|(key, _)| key == "OUROBOROS_GATEWAY_TOKEN_FILE")
    {
        // The product launcher always supplies the private file contract. An ambient
        // plaintext fallback must not remain readable in the child environment beside
        // it, even though runtime.exs prefers the file.
        command.env_remove("OUROBOROS_GATEWAY_TOKEN");
    }
    if environment
        .iter()
        .any(|(key, _)| key == "OUROBOROS_COOKIE_FILE")
    {
        // A persistent fleet profile owns cookie selection. Do not let legacy caller
        // variables containing the real cookie survive beside the file-based contract.
        command.env_remove("OUROBOROS_COOKIE");
        command.env_remove("RELEASE_COOKIE");
    }
    for (key, value) in environment {
        command.env(key, value);
    }
}

/// OTP 29 adds a release-specific VM flag variable such as `ERL_OTP29_FLAGS`.
/// Match only the documented numeric slot, with a small future-proof bound, instead of
/// treating every `ERL_OTP...` variable as VM authority.
fn versioned_otp_flags(key: &str) -> bool {
    let Some(version) = key
        .strip_prefix("ERL_OTP")
        .and_then(|rest| rest.strip_suffix("_FLAGS"))
    else {
        return false;
    };

    !version.is_empty() && version.len() <= 4 && version.bytes().all(|byte| byte.is_ascii_digit())
}

/// The current environment as pairs, for [`spawn_env`].
pub fn caller_env() -> Vec<(String, String)> {
    std::env::vars().collect()
}

/// What to start.
#[derive(Debug, Clone)]
pub enum Launcher {
    /// `mix run --no-halt` in a checkout. No release, no embed, and the compile is the
    /// caller's to wait for.
    Dev { repo_root: PathBuf },
    /// `bin/ouroboros start` from an extracted release. `start` runs in the foreground,
    /// which is what makes it supervisable; `daemon` would hand the process to `run_erl`
    /// and leave this client watching a pid that exits immediately.
    Release { root: PathBuf },
}

impl Launcher {
    fn program(&self) -> OsString {
        match self {
            Self::Dev { .. } => OsString::from("mix"),
            Self::Release { root } => root.join("bin").join("ouroboros").into_os_string(),
        }
    }

    fn args(&self) -> Vec<&'static str> {
        match self {
            Self::Dev { .. } => vec!["run", "--no-halt"],
            Self::Release { .. } => vec!["start"],
        }
    }

    fn working_dir(&self) -> &Path {
        match self {
            Self::Dev { repo_root } => repo_root,
            Self::Release { root } => root,
        }
    }

    pub fn ready_deadline(&self) -> Duration {
        match self {
            Self::Dev { .. } => DEV_READY_DEADLINE,
            Self::Release { .. } => RELEASE_READY_DEADLINE,
        }
    }

    /// The EPMD shipped by this exact extracted release. Fleet startup uses this rather
    /// than PATH so ownership and later port-scoped cleanup stay inside the packaged
    /// runtime boundary.
    pub fn packaged_epmd_program(&self) -> Result<Option<PathBuf>> {
        let Self::Release { root } = self else {
            return Ok(None);
        };
        let mut candidates = Vec::new();
        for entry in fs::read_dir(root)
            .with_context(|| format!("reading extracted release {}", root.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("erts-") && entry.file_type()?.is_dir() {
                let candidate = entry.path().join("bin").join("epmd");
                if candidate.is_file() {
                    candidates.push(candidate);
                }
            }
        }
        match candidates.len() {
            1 => Ok(candidates.pop()),
            0 => bail!(
                "extracted release {} has no packaged erts-*/bin/epmd",
                root.display()
            ),
            count => bail!(
                "extracted release {} has {count} packaged EPMD candidates; refusing an ambiguous lifecycle helper",
                root.display()
            ),
        }
    }
}

/// Walks up from `start` looking for this project's checkout.
pub fn find_repo_root(start: &Path) -> Result<PathBuf> {
    let start = start
        .canonicalize()
        .with_context(|| format!("resolving {}", start.display()))?;

    for candidate in start.ancestors() {
        if candidate.join("mix.exs").is_file()
            && candidate.join("lib").join("ouroboros.ex").is_file()
        {
            return Ok(candidate.to_path_buf());
        }
    }

    bail!(
        "--dev runs `mix run --no-halt` in an ouroboros checkout, and none contains {}",
        start.display()
    )
}

/// Where a spawned child's output goes.
#[derive(Debug, Clone)]
pub enum Output {
    /// Piped into this process and accumulated in a bounded ring.
    Ring,
    /// Appended to a file, for a daemon that outlives this process.
    File(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug)]
pub struct LogLine {
    pub stream: Stream,
    pub text: String,
}

/// A bounded window of child output. Slice 3b's Logs tab reads it; Slice 3a prints the
/// tail when a child exits or fails to become ready.
#[derive(Clone)]
pub struct LogRing {
    inner: Arc<Mutex<Ring>>,
}

struct Ring {
    lines: VecDeque<LogLine>,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
    dropped: u64,
}

impl Default for LogRing {
    fn default() -> Self {
        Self::new(2_000, 512 * 1024)
    }
}

impl LogRing {
    pub fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Ring {
                lines: VecDeque::new(),
                bytes: 0,
                max_lines,
                max_bytes,
                dropped: 0,
            })),
        }
    }

    pub fn push(&self, stream: Stream, text: String) {
        let Ok(mut ring) = self.inner.lock() else {
            return;
        };

        ring.bytes += text.len();
        ring.lines.push_back(LogLine { stream, text });

        while ring.lines.len() > ring.max_lines || ring.bytes > ring.max_bytes {
            match ring.lines.pop_front() {
                Some(line) => {
                    ring.bytes -= line.text.len();
                    ring.dropped += 1;
                }
                None => break,
            }
        }
    }

    /// The last `count` lines, oldest first.
    pub fn tail(&self, count: usize) -> Vec<LogLine> {
        let Ok(ring) = self.inner.lock() else {
            return Vec::new();
        };

        let skip = ring.lines.len().saturating_sub(count);
        ring.lines.iter().skip(skip).cloned().collect()
    }

    pub fn dropped(&self) -> u64 {
        self.inner.lock().map(|ring| ring.dropped).unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|ring| ring.lines.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A single log line is bounded too: one runaway `inspect` should cost a truncation,
/// not the ring.
const MAX_LOG_LINE: usize = 8 * 1024;

async fn pump<R: AsyncRead + Unpin>(mut source: R, stream: Stream, ring: LogRing) {
    let mut chunk = vec![0u8; 8 * 1024];
    let mut line: Vec<u8> = Vec::new();

    loop {
        let read = match source.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };

        for byte in &chunk[..read] {
            if *byte == b'\n' {
                ring.push(stream, String::from_utf8_lossy(&line).into_owned());
                line.clear();
            } else {
                line.push(*byte);

                if line.len() >= MAX_LOG_LINE {
                    ring.push(stream, String::from_utf8_lossy(&line).into_owned());
                    line.clear();
                }
            }
        }
    }

    if !line.is_empty() {
        ring.push(stream, String::from_utf8_lossy(&line).into_owned());
    }
}

/// A runtime this client started.
///
/// Dropping an armed handle is a last-resort kill: normal error paths call
/// [`Daemon::terminate`] for bounded graceful cleanup, while an intentional daemon/UI
/// detach calls [`Daemon::detach`] first. This guard covers cancellation and future early
/// returns that would otherwise silently orphan a live writer of durable journals.
#[must_use = "a spawned runtime must be supervised, terminated, or explicitly detached"]
pub struct Daemon {
    child: Option<Child>,
    identity: ProcessIdentity,
    logs: LogRing,
    epmd_failure: Option<tokio::sync::oneshot::Receiver<String>>,
}

impl Daemon {
    pub fn pid(&self) -> i32 {
        self.identity.pid
    }

    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    pub fn logs(&self) -> LogRing {
        self.logs.clone()
    }

    /// Whether the child has already exited, without waiting for it.
    pub fn exited(&mut self) -> Option<ExitStatus> {
        let child = self.child.as_mut()?;
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if let Some(reason) = self.take_epmd_failure() {
            eprintln!(
                "ouro fleet: {reason}; stopping the still-owned runtime so recovery can restart distribution"
            );
            let _ = send_signal(self.pid(), libc::SIGTERM);
        }
        self.child.as_mut()?.try_wait().ok().flatten()
    }

    /// Waits while retaining ownership, so cancellation leaves the drop guard armed.
    /// Used by `ouro service-run`: the service manager supervises this foreground client,
    /// and this client in turn must remain attached to the BEAM child it started.
    pub async fn wait(&mut self) -> Result<ExitStatus> {
        let pid = self.identity.pid;
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| anyhow!("cannot wait for a detached runtime"))?;
        let status = if let Some(epmd_failure) = self.epmd_failure.as_mut() {
            tokio::select! {
                status = child.wait() => status.context("waiting for the runtime")?,
                failure = epmd_failure => {
                    match failure {
                        Ok(reason) => {
                            eprintln!(
                                "ouro fleet: {reason}; stopping the still-owned runtime so recovery can restart distribution"
                            );
                            // try_wait returning None keeps this exact child unreaped, so
                            // its PID cannot be reused between the check and the signal.
                            if child.try_wait()?.is_none() {
                                send_signal(pid, libc::SIGTERM)?;
                            }
                            child.wait().await.context("waiting for the runtime after EPMD loss")?
                        }
                        Err(_) => child.wait().await.context("waiting for the runtime")?,
                    }
                }
            }
        } else {
            child.wait().await.context("waiting for the runtime")?
        };
        self.child = None;
        self.epmd_failure = None;
        Ok(status)
    }

    /// Waits for the gateway to publish a port it can be reached on.
    ///
    /// Any stale publication was removed before the spawn, so existence plus a live pid
    /// is the whole readiness test — no mtime comparison that a coarse filesystem clock
    /// could get wrong.
    pub async fn wait_ready(&mut self, data_dir: &Path, deadline: Duration) -> Result<Publication> {
        let started = Instant::now();

        loop {
            if let Some(reason) = self.take_epmd_failure() {
                eprintln!(
                    "ouro fleet: {reason}; stopping the still-owned runtime because distribution cannot recover in place"
                );
                self.terminate(Duration::from_secs(5)).await?;
                bail!("fleet discovery failed during startup: {reason}");
            }
            if let Some(status) = self.exited() {
                bail!(
                    "the runtime exited before it published a gateway ({status}){}",
                    self.log_tail(40)
                );
            }

            if let Ok(Some(publication)) = read_publication(data_dir) {
                if publication.pid == self.identity.pid
                    && publication.birth.as_deref() == Some(self.identity.birth.as_str())
                    && process_identity_is_live(&self.identity)?
                {
                    return Ok(publication);
                }
            }

            if started.elapsed() >= deadline {
                // A publication that exists but did not decode is the more useful error,
                // so it is re-read strictly once the deadline has passed.
                read_publication(data_dir)?;

                bail!(
                    "the runtime did not publish {} in {}s{}",
                    data_dir.join(PUBLICATION_FILE).display(),
                    deadline.as_secs(),
                    self.log_tail(40)
                );
            }

            tokio::time::sleep(READY_POLL).await;
        }
    }

    /// SIGTERM, a bounded grace, then SIGKILL. OTP's signal server turns SIGTERM into an
    /// orderly `init:stop`, so the grace is the runtime's shutdown, not a courtesy.
    pub async fn terminate(&mut self, grace: Duration) -> Result<Option<ExitStatus>> {
        let pid = self.identity.pid;
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };

        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }

        send_signal(pid, libc::SIGTERM)?;

        match tokio::time::timeout(grace, child.wait()).await {
            Ok(status) => Ok(Some(status?)),
            Err(_elapsed) => {
                child.kill().await?;
                Ok(Some(child.wait().await?))
            }
        }
    }

    /// Explicitly disarms the drop guard and gives up the child without stopping it.
    /// `ouro daemon` and the UI's deliberate detach choice exit this way.
    pub fn detach(&mut self) {
        self.child = None;
        self.epmd_failure = None;
    }

    pub fn log_tail(&self, count: usize) -> String {
        let lines = self.logs.tail(count);

        if lines.is_empty() {
            return String::new();
        }

        let mut rendered = String::from("\n--- last output from the runtime ---");

        for line in lines {
            rendered.push('\n');
            rendered.push_str(&line.text);
        }

        rendered
    }

    fn take_epmd_failure(&mut self) -> Option<String> {
        let receiver = self.epmd_failure.as_mut()?;
        match receiver.try_recv() {
            Ok(reason) => {
                self.epmd_failure = None;
                Some(reason)
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => None,
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                self.epmd_failure = None;
                None
            }
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            // Synchronous and best-effort by necessity: Drop cannot await. Every expected
            // error path has already used terminate(); this is the cancellation/panic
            // backstop that makes an accidental early return fail safe instead of detach.
            let _ = child.start_kill();
        }
    }
}

/// Starts a runtime as a child process in its own session.
pub fn spawn(
    launcher: &Launcher,
    data_dir: &Path,
    token_file: &Path,
    output: Output,
) -> Result<Daemon> {
    ensure_private_data_dir(data_dir)?;

    if matches!(launcher, Launcher::Dev { .. }) && crate::fleet::load(data_dir)?.is_some() {
        bail!(
            "--dev cannot start a fleet profile: Mix starts its VM before release vm.args and the private-cookie boot hook can apply. Build/run the packaged `ouro` for secure fleet distribution, or use a separate OUROBOROS_DATA_DIR for standalone development"
        );
    }

    let epmd_watch = match launcher.packaged_epmd_program()? {
        Some(epmd_program) => crate::fleet::ensure_owned_epmd_for_runtime(data_dir, &epmd_program)?,
        None => None,
    };

    let mut command = Command::new(launcher.program());
    command.args(launcher.args());
    command.current_dir(launcher.working_dir());
    command.stdin(Stdio::null());

    let caller_environment = caller_env();
    let environment = spawn_env(&caller_environment, data_dir, token_file)?;
    apply_spawn_environment(&mut command, &caller_environment, environment);
    command.env_remove(PROCESS_ID_HELPER_ENV);
    if let Some(helper) = product_process_helper(launcher)? {
        command.env(PROCESS_ID_HELPER_ENV, helper);
    }

    let logs = LogRing::default();

    // These are launcher-owned internal settings, not ambient operator overrides. A
    // foreground/ring spawn must keep Logger on stderr so its logs remain visible in the
    // TUI; a detached/service spawn installs the separate bounded file sink below.
    for name in [
        RUNTIME_LOG_FILE_ENV,
        RUNTIME_LOG_MAX_BYTES_ENV,
        RUNTIME_LOG_MAX_FILES_ENV,
    ] {
        command.env_remove(name);
    }

    match &output {
        Output::Ring => {
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
        }
        Output::File(path) => {
            let runtime_log = data_dir.join(RUNTIME_LOG_FILE);
            prepare_runtime_log(&runtime_log)?;
            command.env(RUNTIME_LOG_FILE_ENV, &runtime_log);
            command.env(RUNTIME_LOG_MAX_BYTES_ENV, RUNTIME_LOG_MAX_BYTES.to_string());
            command.env(RUNTIME_LOG_MAX_FILES_ENV, RUNTIME_LOG_BACKUPS.to_string());

            let file = prepare_daemon_log(path)?;

            let errors = file.try_clone()?;
            command.stdout(Stdio::from(file));
            command.stderr(Stdio::from(errors));
        }
    }

    configure_child_process(&mut command);

    let mut child = command.spawn().with_context(|| {
        format!(
            "starting {} in {}",
            launcher.program().to_string_lossy(),
            launcher.working_dir().display()
        )
    })?;

    let pid = child
        .id()
        .ok_or_else(|| anyhow!("the runtime exited before it could be identified"))?
        as i32;
    let birth = process_birth(pid)?.ok_or_else(|| {
        anyhow!("the runtime exited before its process incarnation could be read")
    })?;

    if matches!(output, Output::Ring) {
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(pump(stdout, Stream::Stdout, logs.clone()));
        }

        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(pump(stderr, Stream::Stderr, logs.clone()));
        }
    }

    // The detached monitor owns/reaps a foreground EPMD child when this launcher
    // created one. For a compatible incumbent it only observes NAMES health. It reports
    // loss back to this exact child owner; it never signals an unowned EPMD or a bare PID.
    let epmd_failure = epmd_watch.map(crate::fleet::EpmdRuntimeWatch::supervise);

    Ok(Daemon {
        child: Some(child),
        identity: ProcessIdentity { pid, birth },
        logs,
        epmd_failure,
    })
}

fn product_process_helper(launcher: &Launcher) -> Result<Option<PathBuf>> {
    let executable = std::env::current_exe().context("resolving the ouro lifecycle helper")?;
    resolved_process_helper(launcher, &executable)
}

fn resolved_process_helper(launcher: &Launcher, current_exe: &Path) -> Result<Option<PathBuf>> {
    match launcher {
        Launcher::Release { .. } => canonicalize_helper(current_exe).map(Some),
        Launcher::Dev { .. } => match discover_dev_process_helper(current_exe) {
            Some(helper) => canonicalize_helper(&helper).map(Some),
            None => Ok(None),
        },
    }
}

fn canonicalize_helper(executable: &Path) -> Result<PathBuf> {
    executable
        .canonicalize()
        .with_context(|| format!("resolving lifecycle helper {}", executable.display()))
}

/// Mix still needs `process-birth` and `hold-runtime-recovery-lock`. Those commands live
/// on the product `ouro` binary. Cargo test harnesses must never be advertised as that
/// helper merely because their basename contains "ouro".
fn discover_dev_process_helper(current_exe: &Path) -> Option<PathBuf> {
    if is_product_ouro_cli(current_exe) {
        return Some(current_exe.to_path_buf());
    }
    adjacent_product_ouro(current_exe)
}

fn is_product_ouro_cli(path: &Path) -> bool {
    path.file_stem().and_then(OsStr::to_str) == Some("ouro")
}

fn adjacent_product_ouro(current_exe: &Path) -> Option<PathBuf> {
    let parent = current_exe.parent()?;
    // cargo {test,bench} executables live in target/<profile>/deps/.
    if parent.file_name().and_then(OsStr::to_str) != Some("deps") {
        return None;
    }
    let candidate = parent.parent()?.join("ouro");
    candidate.is_file().then_some(candidate)
}

fn configure_child_process(command: &mut Command) {
    // SAFETY: umask and setsid are async-signal-safe and are the only calls made between
    // fork and exec. A child in its own session does not receive the terminal's signals,
    // which is what makes both the supervised shutdown sequence and the detached daemon
    // possible.
    unsafe {
        command.pre_exec(move || {
            // Runtime components create journals, checkpoints, and rotated logs after
            // exec. Their file APIs do not all expose per-open permissions, so every
            // managed runtime starts with the same private durable-file boundary.
            libc::umask(0o077);

            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        });
    }
}

#[derive(Clone, Copy, Debug)]
struct PrivateLogFile {
    identity: FileIdentity,
    len: u64,
}

/// Opens the bounded detached-daemon log without following attacker-controlled names.
///
/// Every retained file is validated before rotation changes any name. This is
/// deliberately stricter than silently repairing permissions: a symlink, foreign owner,
/// or unexpectedly broad mode means the data directory is not one this process can
/// safely mutate.
fn prepare_daemon_log(path: &Path) -> Result<File> {
    prepare_daemon_log_with_limit(path, DAEMON_LOG_MAX_BYTES)
}

fn prepare_daemon_log_with_limit(path: &Path, max_bytes: u64) -> Result<File> {
    let data_dir = path.parent().ok_or_else(|| {
        anyhow!(
            "daemon log path {} has no data-directory parent",
            path.display()
        )
    })?;
    ensure_private_data_dir(data_dir)?;

    let paths = daemon_log_paths(path);
    let snapshot = paths
        .iter()
        .map(|candidate| inspect_private_log(candidate))
        .collect::<Result<Vec<_>>>()?;
    let rotate = snapshot[0].is_some_and(|log| log.len >= max_bytes);

    if rotate {
        verify_log_snapshot(&paths, &snapshot)?;
        rotate_daemon_logs(&paths, &snapshot)?;
        open_daemon_log(path, None)
    } else {
        open_daemon_log(path, snapshot[0].map(|log| log.identity))
    }
}

/// Prepares, but never rotates, the file set that OTP Logger will own after exec.
///
/// The active file is created at mode 0600 so the handler never has to follow a name it
/// did not receive from this launcher. Existing archives (including a contiguous
/// overflow that OTP will prune at handler startup) must also be private regular files
/// owned by this uid. Once this function returns, Rust closes every descriptor and OTP
/// is the only live writer and the only component that rotates these names.
fn prepare_runtime_log(path: &Path) -> Result<()> {
    let data_dir = path.parent().ok_or_else(|| {
        anyhow!(
            "runtime log path {} has no data-directory parent",
            path.display()
        )
    })?;
    ensure_private_data_dir(data_dir)?;

    if inspect_private_log(path)?.is_none() {
        drop(open_daemon_log(path, None)?);
    }

    for index in 0..RUNTIME_LOG_BACKUPS {
        let archive = runtime_log_archive(path, index);
        let _ = inspect_private_log(&archive)?;

        let compressed = runtime_log_compressed_archive(path, index);
        if inspect_private_log(&compressed)?.is_some() {
            bail!(
                "unexpected compressed runtime log archive {}; this launcher configures uncompressed OTP rotation and will not let Logger rewrite it",
                compressed.display()
            );
        }
    }

    // `logger_std_h` removes archives starting at max_no_files until it encounters a
    // gap. Validate that exact overflow before allowing it to mutate any of those names.
    let mut index = RUNTIME_LOG_BACKUPS;
    loop {
        let archive = runtime_log_archive(path, index);
        let compressed = runtime_log_compressed_archive(path, index);
        let plain_present = inspect_private_log(&archive)?.is_some();
        let compressed_present = inspect_private_log(&compressed)?.is_some();
        if !plain_present && !compressed_present {
            break;
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| anyhow!("too many runtime log archives beside {}", path.display()))?;
    }

    Ok(())
}

fn runtime_log_archive(path: &Path, index: usize) -> PathBuf {
    let mut archive = path.as_os_str().to_os_string();
    archive.push(format!(".{index}"));
    PathBuf::from(archive)
}

fn runtime_log_compressed_archive(path: &Path, index: usize) -> PathBuf {
    let mut archive = path.as_os_str().to_os_string();
    archive.push(format!(".{index}.gz"));
    PathBuf::from(archive)
}

fn daemon_log_paths(path: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(DAEMON_LOG_BACKUPS + 1);
    paths.push(path.to_path_buf());

    for index in 1..=DAEMON_LOG_BACKUPS {
        let mut backup = path.as_os_str().to_os_string();
        backup.push(format!(".{index}"));
        paths.push(PathBuf::from(backup));
    }

    paths
}

fn inspect_private_log(path: &Path) -> Result<Option<PrivateLogFile>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context(format!(
                "opening daemon log {} without following links",
                path.display()
            ))
        }
    };

    validate_private_log(path, &file).map(Some)
}

fn validate_private_log(path: &Path, file: &File) -> Result<PrivateLogFile> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting daemon log {}", path.display()))?;
    // SAFETY: geteuid cannot fail and touches no memory.
    let us = unsafe { libc::geteuid() };
    let mode = metadata.mode() & 0o7777;

    if !metadata.file_type().is_file() || metadata.uid() != us || mode != 0o600 {
        bail!(
            "{} is not a private regular daemon log at mode 0600 owned by uid {us} \
             (type regular: {}, uid: {}, mode: {:04o}); refusing to rotate or append to it",
            path.display(),
            metadata.file_type().is_file(),
            metadata.uid(),
            mode
        );
    }

    let identity = FileIdentity::of(file)?;

    if !identity.matches(path) {
        bail!(
            "daemon log {} changed while it was being inspected; refusing to rotate or append",
            path.display()
        );
    }

    Ok(PrivateLogFile {
        identity,
        len: metadata.len(),
    })
}

fn verify_log_snapshot(paths: &[PathBuf], snapshot: &[Option<PrivateLogFile>]) -> Result<()> {
    for (path, observed) in paths.iter().zip(snapshot) {
        match observed {
            Some(log) => ensure_exact_private_log(path, log.identity, "before rotation")?,
            None => match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => bail!(
                    "daemon log {} appeared before rotation; refusing to replace any retained log",
                    path.display()
                ),
                Err(error) => {
                    return Err(error).context(format!("checking daemon log {}", path.display()))
                }
            },
        }
    }

    Ok(())
}

fn rotate_daemon_logs(paths: &[PathBuf], snapshot: &[Option<PrivateLogFile>]) -> Result<()> {
    let oldest = DAEMON_LOG_BACKUPS;

    if let Some(log) = snapshot[oldest] {
        remove_exact_log(&paths[oldest], log.identity)?;
    }

    for source_index in (0..DAEMON_LOG_BACKUPS).rev() {
        let Some(log) = snapshot[source_index] else {
            continue;
        };

        move_exact_log(&paths[source_index], &paths[source_index + 1], log.identity)?;
    }

    Ok(())
}

fn remove_exact_log(path: &Path, identity: FileIdentity) -> Result<()> {
    ensure_exact_private_log(path, identity, "during rotation")?;

    fs::remove_file(path).with_context(|| format!("removing old daemon log {}", path.display()))
}

fn move_exact_log(source: &Path, destination: &Path, identity: FileIdentity) -> Result<()> {
    ensure_exact_private_log(source, identity, "during rotation")?;

    // A hard link is the portable Unix no-clobber move primitive we need here: unlike
    // rename, it fails when a destination appears between validation and mutation.
    fs::hard_link(source, destination).with_context(|| {
        format!(
            "retaining daemon log {} as {} without replacing an existing file",
            source.display(),
            destination.display()
        )
    })?;

    ensure_exact_private_log(destination, identity, "after retaining it")?;
    ensure_exact_private_log(source, identity, "before unlinking its old name")?;

    fs::remove_file(source)
        .with_context(|| format!("finishing daemon log rotation of {}", source.display()))
}

fn ensure_exact_private_log(path: &Path, expected: FileIdentity, phase: &str) -> Result<()> {
    let Some(actual) = inspect_private_log(path)? else {
        bail!(
            "daemon log {} disappeared {phase}; refusing to continue rotation",
            path.display()
        );
    };

    if actual.identity != expected {
        bail!(
            "daemon log {} changed {phase}; refusing to remove or append to its replacement",
            path.display()
        );
    }

    Ok(())
}

fn open_daemon_log(path: &Path, expected: Option<FileIdentity>) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);

    if expected.is_some() {
        options.create(false);
    } else {
        options.create_new(true);
    }

    let file = options.open(path).with_context(|| {
        format!(
            "opening daemon log {} without following links",
            path.display()
        )
    })?;

    if expected.is_none() {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting private permissions on {}", path.display()))?;
    }

    let opened = validate_private_log(path, &file)?;

    if let Some(expected) = expected {
        if opened.identity != expected {
            bail!(
                "daemon log {} changed before it could be opened for append; refusing the replacement",
                path.display()
            );
        }
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SCRATCH: AtomicU32 = AtomicU32::new(0);

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ouro-test-{name}-{}-{}",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));

        fs::remove_dir_all(&dir).ok();
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&dir).expect("a private scratch directory");
        dir
    }

    #[test]
    fn configured_data_dir_precedes_xdg_and_matches_the_runtimes_trimmed_value() {
        for dev in [false, true] {
            let resolved = resolve_data_dir(
                dev,
                Some(OsStr::new("  /var/lib/ouroboros-e2e\t")),
                || -> Result<PathBuf> {
                    panic!("an explicit OUROBOROS_DATA_DIR must not consult XDG or HOME")
                },
            )
            .expect("an absolute configured data directory");

            assert_eq!(resolved.path, PathBuf::from("/var/lib/ouroboros-e2e"));
            assert!(resolved.overridden);
        }
    }

    #[test]
    fn missing_data_dir_leaf_is_created_private() {
        let parent = scratch("private-data-dir-create-parent");
        let data_dir = PathBuf::from(format!("{}/durable/", parent.display()));

        ensure_private_data_dir(&data_dir).expect("a missing durable leaf is created");

        let metadata = fs::symlink_metadata(&data_dir).expect("the durable leaf");
        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o777, 0o700);

        fs::remove_dir_all(parent).ok();
    }

    #[test]
    fn broad_existing_data_dir_is_refused_before_a_lock_is_written() {
        let parent = scratch("broad-data-dir-parent");
        let data_dir = parent.join("durable");
        fs::create_dir(&data_dir).expect("an explicit durable leaf");
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o755))
            .expect("a deliberately broad leaf");
        fs::write(data_dir.join("sentinel"), b"unchanged").expect("existing durable state");

        let error = acquire_spawn_lock(&data_dir)
            .expect_err("a broad pre-existing durable leaf must fail closed");
        let message = format!("{error:#}");

        assert!(
            message.contains("mode-0700 durable data directory"),
            "{message}"
        );
        assert!(message.contains("will not chmod or replace"), "{message}");
        assert_eq!(fs::read(data_dir.join("sentinel")).unwrap(), b"unchanged");
        assert!(!data_dir.join(SPAWN_LOCK_FILE).exists());
        assert!(!data_dir.join(SPAWN_LOCK_RECOVERY_FILE).exists());
        assert_eq!(fs::metadata(&data_dir).unwrap().mode() & 0o777, 0o755);

        fs::remove_dir_all(parent).ok();
    }

    #[test]
    fn app_managed_default_restricts_an_owned_legacy_leaf_in_place() {
        let parent = scratch("legacy-default-data-dir-parent");
        let data_dir = parent.join("ouroboros");
        fs::create_dir(&data_dir).expect("a legacy app data directory");
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o755))
            .expect("legacy broad permissions");
        fs::write(data_dir.join("sentinel"), b"unchanged").expect("existing durable state");
        let paths = Paths {
            data_dir: data_dir.clone(),
            cache_dir: parent.join("cache"),
            data_dir_overridden: false,
        };

        paths
            .ensure_private_data_dir()
            .expect("the derived same-user leaf is safely restricted");

        assert_eq!(fs::read(data_dir.join("sentinel")).unwrap(), b"unchanged");
        assert_eq!(fs::metadata(&data_dir).unwrap().mode() & 0o777, 0o700);

        fs::remove_dir_all(parent).ok();
    }

    #[test]
    fn explicit_data_dir_keeps_the_no_implicit_chmod_contract() {
        let parent = scratch("explicit-data-dir-parent");
        let data_dir = parent.join("ouroboros");
        fs::create_dir(&data_dir).expect("an explicit data directory");
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o755))
            .expect("deliberately broad permissions");
        let paths = Paths {
            data_dir: data_dir.clone(),
            cache_dir: parent.join("cache"),
            data_dir_overridden: true,
        };

        let error = paths
            .ensure_private_data_dir()
            .expect_err("an explicit path still requires operator repair");

        assert!(format!("{error:#}").contains("will not chmod or replace"));
        assert_eq!(fs::metadata(&data_dir).unwrap().mode() & 0o777, 0o755);

        fs::remove_dir_all(parent).ok();
    }

    #[test]
    fn symlinked_data_dir_is_refused_before_its_target_is_mutated() {
        let parent = scratch("symlink-data-dir-parent");
        let target = parent.join("target");
        let data_dir = parent.join("durable");
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&target).expect("a private target");
        fs::write(target.join("sentinel"), b"unchanged").expect("existing target state");
        std::os::unix::fs::symlink(&target, &data_dir).expect("a data-directory symlink");

        let error =
            acquire_spawn_lock(&data_dir).expect_err("a symlinked durable leaf must fail closed");
        let message = format!("{error:#}");

        assert!(
            message.contains("mode-0700 durable data directory"),
            "{message}"
        );
        assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"unchanged");
        assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
        assert!(fs::symlink_metadata(&data_dir)
            .expect("the refused symlink remains")
            .file_type()
            .is_symlink());

        fs::remove_dir_all(parent).ok();
    }

    #[test]
    fn blank_data_dir_uses_the_mode_specific_xdg_default() {
        for (configured, dev, leaf) in [
            (None, false, "ouroboros"),
            (Some(OsStr::new("  \t")), true, "ouroboros-dev"),
        ] {
            let resolved = resolve_data_dir(dev, configured, || Ok(PathBuf::from("/xdg/data")))
                .expect("the XDG fallback");

            assert_eq!(resolved.path, Path::new("/xdg/data").join(leaf));
            assert!(!resolved.overridden);
        }
    }

    #[test]
    fn relative_data_dir_is_refused_instead_of_resolved_against_two_working_directories() {
        let error = resolve_data_dir(false, Some(OsStr::new("relative/runtime")), || {
            Ok(PathBuf::from("/xdg/data"))
        })
        .expect_err("a relative configured data directory");
        let message = error.to_string();

        assert!(message.contains("OUROBOROS_DATA_DIR"));
        assert!(message.contains("nonblank absolute durable directory"));
        assert!(message.contains("relative/runtime"));
    }

    #[test]
    fn spawn_env_sets_the_gateway_posture_and_turns_distribution_off() {
        let caller = vec![
            ("OUROBOROS_GATEWAY_BIND".into(), "0.0.0.0".into()),
            ("OUROBOROS_GATEWAY_ALLOW_REMOTE".into(), "1".into()),
        ];
        let env = spawn_env(
            &caller,
            Path::new("/data"),
            Path::new("/data/gateway.token"),
        )
        .unwrap();
        let lookup = |name: &str| {
            env.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };

        assert_eq!(lookup("OUROBOROS_GATEWAY"), Some("1".into()));
        assert_eq!(lookup("OUROBOROS_GATEWAY_SCOPE"), Some("operate".into()));
        assert_eq!(lookup("OUROBOROS_GATEWAY_ALLOW_SHUTDOWN"), Some("1".into()));
        assert_eq!(lookup("OUROBOROS_GATEWAY_PORT"), Some("0".into()));
        assert_eq!(lookup("OUROBOROS_GATEWAY_BIND"), Some("127.0.0.1".into()));
        assert_eq!(lookup("OUROBOROS_GATEWAY_ALLOW_REMOTE"), Some("0".into()));
        assert_eq!(lookup("OUROBOROS_DATA_DIR"), Some("/data".into()));
        assert_eq!(
            lookup("OUROBOROS_GATEWAY_TOKEN_FILE"),
            Some("/data/gateway.token".into())
        );
        assert_eq!(lookup("OUROBOROS_DIST"), Some("none".into()));
    }

    #[tokio::test]
    async fn fleet_spawn_removes_ambient_ouroboros_authority_and_plaintext_token() {
        let env_program = [Path::new("/usr/bin/env"), Path::new("/bin/env")]
            .into_iter()
            .find(|path| path.is_file())
            .expect("a Unix env executable");
        let mut command = Command::new(env_program);
        command.env_clear();
        let caller = vec![
            (
                "OUROBOROS_GATEWAY_TOKEN".into(),
                "ambient-secret-must-not-survive".into(),
            ),
            (
                "OUROBOROS_SIGNER_KEY_PATH".into(),
                "/secret/ambient-signer".into(),
            ),
            ("OUROBOROS_CONTROL_ALLOW_FORGE_STEPS".into(), "1".into()),
            ("OUROBOROS_GATEWAY_QUEUE_LIMIT".into(), "999999".into()),
            ("ERL_AFLAGS".into(), "-pa /ambient/aflags".into()),
            ("ERL_FLAGS".into(), "-pa /ambient/flags".into()),
            ("ERL_INETRC".into(), "/ambient/inetrc".into()),
            ("ERL_LIBS".into(), "/ambient/erlang-libs".into()),
            ("ERL_OTP29_FLAGS".into(), "-pa /ambient/otp29".into()),
            ("ERL_OTPX_FLAGS".into(), "near-miss-must-survive".into()),
            (
                "ERL_OTP12345_FLAGS".into(),
                "bounded-near-miss-must-survive".into(),
            ),
            ("ERL_ZFLAGS".into(), "-pa /ambient/zflags".into()),
            ("ELIXIR_ERL_OPTIONS".into(), "-pa /ambient/elixir".into()),
            ("RELEASE_BOOT_SCRIPT".into(), "/ambient/boot".into()),
            ("RELEASE_COMMAND".into(), "ambient-command".into()),
            ("RELEASE_COOKIE".into(), "ambient-cookie".into()),
            ("RELEASE_NODE".into(), "ambient@node".into()),
            ("RELEASE_SYS_CONFIG".into(), "/ambient/sys".into()),
            ("RELEASE_VM_ARGS".into(), "/ambient/vm.args".into()),
        ];
        for (key, value) in &caller {
            command.env(key, value);
        }
        apply_spawn_environment(
            &mut command,
            &caller,
            vec![
                (
                    "OUROBOROS_FLEET_ID".into(),
                    "00112233445566778899aabb".into(),
                ),
                (
                    "OUROBOROS_GATEWAY_TOKEN_FILE".into(),
                    "/private/gateway.token".into(),
                ),
                ("OUROBOROS_WORKSPACE_ROOTS".into(), "/srv/project".into()),
                ("OUROBOROS_GATEWAY_MAX_FRAME".into(), "65536".into()),
                ("OUROBOROS_GATEWAY_QUEUE_LIMIT".into(), "64".into()),
                ("RELEASE_VM_ARGS".into(), "/private/fleet/vm.args".into()),
            ],
        );
        let output = command.output().await.unwrap();
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout).unwrap();
        assert!(environment.contains("OUROBOROS_GATEWAY_TOKEN_FILE=/private/gateway.token"));
        assert!(!environment.contains("ambient-secret-must-not-survive"));
        assert!(!environment.contains("OUROBOROS_GATEWAY_TOKEN="));
        assert!(!environment.contains("OUROBOROS_SIGNER_KEY_PATH="));
        assert!(!environment.contains("OUROBOROS_CONTROL_ALLOW_FORGE_STEPS="));
        assert!(environment.contains("OUROBOROS_WORKSPACE_ROOTS=/srv/project"));
        assert!(!environment.contains("OUROBOROS_CODEX_NETWORK_ACCESS"));
        assert!(environment.contains("OUROBOROS_GATEWAY_MAX_FRAME=65536"));
        assert!(environment.contains("OUROBOROS_GATEWAY_QUEUE_LIMIT=64"));
        assert!(!environment.contains("OUROBOROS_GATEWAY_QUEUE_LIMIT=999999"));
        for stripped in [
            "ERL_AFLAGS",
            "ERL_FLAGS",
            "ERL_INETRC",
            "ERL_LIBS",
            "ERL_OTP29_FLAGS",
            "ERL_ZFLAGS",
            "ELIXIR_ERL_OPTIONS",
            "RELEASE_BOOT_SCRIPT",
            "RELEASE_COMMAND",
            "RELEASE_COOKIE",
            "RELEASE_NODE",
            "RELEASE_SYS_CONFIG",
        ] {
            assert!(
                !environment
                    .lines()
                    .any(|line| line.starts_with(&format!("{stripped}="))),
                "ambient {stripped} survived the fleet spawn boundary"
            );
        }
        assert!(environment.contains("RELEASE_VM_ARGS=/private/fleet/vm.args"));
        assert!(!environment.contains("RELEASE_VM_ARGS=/ambient/vm.args"));
        assert!(environment.contains("ERL_OTPX_FLAGS=near-miss-must-survive"));
        assert!(environment.contains("ERL_OTP12345_FLAGS=bounded-near-miss-must-survive"));
    }

    #[test]
    fn a_packaged_launcher_uses_its_current_executable_even_with_a_versioned_name() {
        let executable = std::env::current_exe().expect("the cargo test executable");
        assert_ne!(
            executable.file_stem().and_then(OsStr::to_str),
            Some("ouro"),
            "the regression fixture must exercise a renamed/hash-suffixed executable"
        );

        let launcher = Launcher::Release {
            root: scratch("renamed-product-helper"),
        };
        let helper = product_process_helper(&launcher)
            .expect("a resolved packaged helper")
            .expect("the packaged launcher owns a helper regardless of basename");

        assert_eq!(
            helper,
            executable
                .canonicalize()
                .expect("the canonical cargo test executable")
        );
        fs::remove_dir_all(launcher.working_dir()).ok();
    }

    #[test]
    fn a_dev_launcher_never_exports_its_test_binary_as_the_native_helper() {
        let executable = std::env::current_exe().expect("the cargo test executable");
        assert_ne!(
            executable.file_stem().and_then(OsStr::to_str),
            Some("ouro"),
            "the cargo test harness must not itself look like the product CLI"
        );

        let launcher = Launcher::Dev {
            repo_root: scratch("dev-no-product-helper"),
        };
        let helper = product_process_helper(&launcher).expect("a dev helper decision");
        if let Some(helper) = helper.as_ref() {
            assert_eq!(
                helper.file_stem().and_then(OsStr::to_str),
                Some("ouro"),
                "Mix may only inherit the product ouro binary"
            );
            assert_ne!(
                helper,
                &executable
                    .canonicalize()
                    .expect("the canonical cargo test executable"),
                "a cargo test harness must never be advertised as the native helper"
            );
        }
        fs::remove_dir_all(launcher.working_dir()).ok();
    }

    #[test]
    fn a_dev_launcher_exports_the_product_ouro_binary_as_the_native_helper() {
        let dir = scratch("dev-product-helper");
        let executable = dir.join("ouro");
        fs::write(&executable, b"").expect("a product-named helper fixture");

        let launcher = Launcher::Dev {
            repo_root: dir.clone(),
        };
        let helper = resolved_process_helper(&launcher, &executable)
            .expect("a resolved Mix helper")
            .expect("ouro --dev owns the native helper");

        assert_eq!(
            helper,
            executable
                .canonicalize()
                .expect("the canonical product helper")
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_dev_launcher_discovers_the_product_ouro_binary_beside_a_cargo_harness() {
        let dir = scratch("dev-adjacent-product-helper");
        let harness = dir.join("deps").join("integration_dev-hash");
        let product = dir.join("ouro");
        fs::create_dir_all(harness.parent().expect("deps")).expect("a cargo deps directory");
        fs::write(&harness, b"").expect("a cargo test harness fixture");
        fs::write(&product, b"").expect("the product ouro binary beside that harness");

        let launcher = Launcher::Dev {
            repo_root: dir.clone(),
        };
        let helper = resolved_process_helper(&launcher, &harness)
            .expect("a resolved Mix helper")
            .expect("a cargo integration harness still locates the product helper");

        assert_eq!(
            helper,
            product
                .canonicalize()
                .expect("the canonical adjacent helper")
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_dev_launcher_does_not_treat_a_versioned_binary_as_the_native_helper() {
        let dir = scratch("dev-versioned-helper");
        let executable = dir.join("ouro-0.1.0-aarch64-apple-darwin");
        fs::write(&executable, b"").expect("a versioned helper fixture");

        let launcher = Launcher::Dev {
            repo_root: dir.clone(),
        };
        assert!(resolved_process_helper(&launcher, &executable)
            .expect("a dev helper decision")
            .is_none());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_dev_launcher_without_a_product_ouro_binary_exports_no_helper() {
        let dir = scratch("dev-missing-product-helper");
        let harness = dir.join("deps").join("runtime-hash");
        fs::create_dir_all(harness.parent().expect("deps")).expect("a cargo deps directory");
        fs::write(&harness, b"").expect("a cargo test harness fixture");

        let launcher = Launcher::Dev {
            repo_root: dir.clone(),
        };
        assert!(resolved_process_helper(&launcher, &harness)
            .expect("a dev helper decision")
            .is_none());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_clustered_caller_keeps_distribution() {
        for name in ["OUROBOROS_CLUSTER_STRATEGY", "OUROBOROS_NODE"] {
            let caller = vec![(name.to_string(), "epmd".to_string())];
            let env = spawn_env(&caller, Path::new("/data"), Path::new("/data/t")).unwrap();

            assert!(
                !env.iter().any(|(key, _)| key == "OUROBOROS_DIST"),
                "{name} must not be contradicted by OUROBOROS_DIST=none"
            );
        }
    }

    #[test]
    fn a_blank_cluster_variable_is_not_a_cluster() {
        let caller = vec![("OUROBOROS_NODE".to_string(), "  ".to_string())];
        let env = spawn_env(&caller, Path::new("/data"), Path::new("/data/t")).unwrap();

        assert!(env.iter().any(|(key, _)| key == "OUROBOROS_DIST"));
    }

    #[test]
    fn a_fleet_profile_overrides_legacy_cluster_env_without_exposing_its_cookie() {
        let dir = scratch("fleet-spawn-env");
        let profile = crate::fleet::create(
            &dir,
            Some("Test fleet"),
            "alpha",
            "127.0.0.1",
            crate::fleet::Ports {
                gateway: Some(48_501),
                dist: Some(44_501),
                ..crate::fleet::ephemeral_ports()
            },
        )
        .unwrap();
        let actual_cookie =
            fs::read_to_string(crate::fleet::fleet_dir(&dir).join("cookie")).expect("fleet cookie");
        let caller = vec![
            ("OUROBOROS_COOKIE".into(), "legacy-secret".into()),
            ("OUROBOROS_NODE".into(), "wrong@127.0.0.9".into()),
            ("OUROBOROS_WORKSPACE_ROOTS".into(), "/srv/project".into()),
            ("OUROBOROS_CODEX_NETWORK_ACCESS".into(), "false".into()),
            ("OUROBOROS_GATEWAY_MAX_FRAME".into(), "65536".into()),
            ("OUROBOROS_GATEWAY_QUEUE_LIMIT".into(), "64".into()),
            ("OUROBOROS_SIGNER_KEY_PATH".into(), "/secret/key".into()),
        ];
        let env = spawn_env(&caller, &dir, &dir.join("gateway.token")).unwrap();
        let get = |name: &str| {
            env.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };

        assert_eq!(get("OUROBOROS_NODE"), Some(profile.node.as_str()));
        assert_eq!(get("OUROBOROS_GATEWAY_PORT"), Some("48501"));
        assert!(get("OUROBOROS_COOKIE_FILE").is_some());
        assert!(get("OUROBOROS_BOOT_COOKIE_DECOY").is_some());
        assert_eq!(get("OUROBOROS_FLEET_ID"), Some(profile.fleet_id.as_str()));
        assert_eq!(get("OUROBOROS_WORKSPACE_ROOTS"), Some("/srv/project"));
        assert_eq!(get("OUROBOROS_CODEX_NETWORK_ACCESS"), None);
        assert_eq!(get("OUROBOROS_GATEWAY_MAX_FRAME"), Some("65536"));
        assert_eq!(get("OUROBOROS_GATEWAY_QUEUE_LIMIT"), Some("64"));
        assert_eq!(get("OUROBOROS_SIGNER_KEY_PATH"), None);
        assert_eq!(get("OUROBOROS_COOKIE"), None);
        assert!(env.iter().all(|(_, value)| value != actual_cookie.trim()));
        assert_eq!(get("OUROBOROS_DIST"), Some("name"));

        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn dev_spawn_refuses_a_fleet_profile_before_starting_mix() {
        let dir = scratch("fleet-dev-refusal");
        crate::fleet::create(
            &dir,
            None,
            "alpha",
            "127.0.0.1",
            crate::fleet::ephemeral_ports(),
        )
        .unwrap();
        let error = spawn(
            &Launcher::Dev {
                repo_root: dir.clone(),
            },
            &dir,
            &dir.join("gateway.token"),
            Output::Ring,
        )
        .err()
        .expect("--dev fleet startup must fail before spawning")
        .to_string();
        assert!(
            error.contains("--dev cannot start a fleet profile"),
            "{error}"
        );
        assert!(error.contains("packaged"), "{error}");

        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn daemon_log_rotation_keeps_three_private_backups_in_newest_first_order() {
        let dir = scratch("daemon-log-rotation");
        let path = dir.join(DAEMON_LOG_FILE);
        let paths = daemon_log_paths(&path);

        write_private(&paths[0], b"current!");
        write_private(&paths[1], b"previous-one");
        write_private(&paths[2], b"previous-two");
        write_private(&paths[3], b"discarded-three");

        let mut file = prepare_daemon_log_with_limit(&path, 8).expect("a rotated daemon log");
        io::Write::write_all(&mut file, b"fresh").expect("fresh daemon output");
        io::Write::flush(&mut file).expect("flushed daemon output");
        drop(file);

        assert_eq!(fs::read(&paths[0]).unwrap(), b"fresh");
        assert_eq!(fs::read(&paths[1]).unwrap(), b"current!");
        assert_eq!(fs::read(&paths[2]).unwrap(), b"previous-one");
        assert_eq!(fs::read(&paths[3]).unwrap(), b"previous-two");

        for retained in &paths {
            let metadata = fs::symlink_metadata(retained).expect("a retained private log");
            assert!(metadata.file_type().is_file());
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert_eq!(metadata.mode() & 0o7777, 0o600);
        }

        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn daemon_log_rotation_refuses_a_symlink_before_changing_any_log() {
        let dir = scratch("daemon-log-symlink");
        let path = dir.join(DAEMON_LOG_FILE);
        let paths = daemon_log_paths(&path);
        let target = dir.join("attacker-controlled-target");

        write_private(&paths[0], b"current!");
        write_private(&paths[1], b"previous-one");
        write_private(&target, b"must-not-be-read-or-changed");
        std::os::unix::fs::symlink(&target, &paths[2]).expect("a retained-log symlink");

        let error = prepare_daemon_log_with_limit(&path, 8)
            .expect_err("a symlink in the retained set must fail closed");
        let message = format!("{error:#}");

        assert!(message.contains("without following links"), "{message}");
        assert_eq!(fs::read(&paths[0]).unwrap(), b"current!");
        assert_eq!(fs::read(&paths[1]).unwrap(), b"previous-one");
        assert_eq!(fs::read(&target).unwrap(), b"must-not-be-read-or-changed");
        assert!(fs::symlink_metadata(&paths[2])
            .expect("the refused symlink remains")
            .file_type()
            .is_symlink());
        assert!(!paths[3].exists());

        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn runtime_log_preflight_creates_one_private_file_without_rotating_archives() {
        let dir = scratch("runtime-log-preflight");
        let path = dir.join(RUNTIME_LOG_FILE);
        let newest = runtime_log_archive(&path, 0);
        let oldest = runtime_log_archive(&path, RUNTIME_LOG_BACKUPS - 1);

        write_private(&newest, b"newest archive");
        write_private(&oldest, b"oldest archive");

        prepare_runtime_log(&path).expect("a private OTP-owned log set");

        assert_eq!(fs::read(&path).unwrap(), b"");
        assert_eq!(fs::read(&newest).unwrap(), b"newest archive");
        assert_eq!(fs::read(&oldest).unwrap(), b"oldest archive");
        for retained in [&path, &newest, &oldest] {
            let metadata = fs::symlink_metadata(retained).expect("a retained private log");
            assert!(metadata.file_type().is_file());
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert_eq!(metadata.mode() & 0o7777, 0o600);
        }

        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn runtime_log_preflight_refuses_a_symlink_before_otp_can_rotate_it() {
        let dir = scratch("runtime-log-symlink");
        let path = dir.join(RUNTIME_LOG_FILE);
        let archive = runtime_log_archive(&path, 1);
        let target = dir.join("attacker-controlled-target");

        write_private(&path, b"current runtime output");
        write_private(&target, b"must-not-be-read-or-changed");
        std::os::unix::fs::symlink(&target, &archive).expect("a retained-log symlink");

        let error = prepare_runtime_log(&path)
            .expect_err("a symlink in the OTP-owned set must fail closed");
        let message = format!("{error:#}");

        assert!(message.contains("without following links"), "{message}");
        assert_eq!(fs::read(&path).unwrap(), b"current runtime output");
        assert_eq!(fs::read(&target).unwrap(), b"must-not-be-read-or-changed");
        assert!(fs::symlink_metadata(&archive)
            .expect("the refused symlink remains")
            .file_type()
            .is_symlink());

        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn runtime_log_preflight_refuses_an_old_compressed_generation() {
        let dir = scratch("runtime-log-compressed");
        let path = dir.join(RUNTIME_LOG_FILE);
        let compressed = runtime_log_compressed_archive(&path, 0);

        write_private(&path, b"current runtime output");
        write_private(&compressed, b"not actually gzip; it must not be rewritten");

        let error = prepare_runtime_log(&path)
            .expect_err("managed uncompressed rotation must reject a compressed archive");
        let message = format!("{error:#}");

        assert!(message.contains("unexpected compressed runtime log archive"));
        assert_eq!(fs::read(&path).unwrap(), b"current runtime output");
        assert_eq!(
            fs::read(&compressed).unwrap(),
            b"not actually gzip; it must not be rewritten"
        );

        fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn ring_output_child_uses_a_private_umask_under_a_022_caller() {
        let dir = scratch("runtime-log-umask");
        let path = dir.join("created-by-runtime");
        let mut command = Command::new("/usr/bin/touch");
        command.arg(&path);

        // Simulate a normal 022 caller in this child only. `pre_exec` hooks run in
        // registration order, so the runtime hook below must replace it with 077 without
        // racing any other test through the process-global parent umask.
        unsafe {
            command.pre_exec(|| {
                libc::umask(0o022);
                Ok(())
            });
        }
        configure_child_process(&mut command);

        let status = command
            .spawn()
            .expect("a child process")
            .wait()
            .await
            .expect("the child exits");
        assert!(status.success());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);

        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_written_token_is_private_and_long_enough() {
        let dir = scratch("token");
        let path = dir.join("gateway.token");

        let secret = write_token(&path).expect("a token");

        assert_eq!(secret.expose().len(), 64);
        assert!(secret.expose().chars().all(|c| c.is_ascii_hexdigit()));

        let mode = fs::metadata(&path).expect("the token file").mode() & 0o777;
        assert_eq!(mode, 0o600, "the token must not be readable by anyone else");

        let read_back = read_token(&path).expect("a readable token");
        assert_eq!(read_back.expose(), secret.expose());

        let second = write_token(&path).expect("a second token");
        assert_ne!(second.expose(), secret.expose());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_publication_decodes_and_tolerates_new_fields() {
        let dir = scratch("publication");

        write_private(
            &dir.join(PUBLICATION_FILE),
            br#"{"port":54321,"protocol":1,"node":"nonode@nohost","pid":42,"scope":"operate","future":true}"#,
        );

        let publication = read_publication(&dir).expect("readable").expect("present");

        assert_eq!(publication.port, 54321);
        assert_eq!(publication.protocol, 1);
        assert_eq!(publication.pid, 42);
        assert_eq!(publication.scope, "operate");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_publication_read_is_private_bounded_nofollow_and_birth_validated() {
        let broad = scratch("publication-broad-mode");
        let broad_path = broad.join(PUBLICATION_FILE);
        fs::write(&broad_path, b"{}").expect("a broad publication");
        assert!(format!("{:#}", read_publication(&broad).unwrap_err()).contains("mode 0600"));

        let linked = scratch("publication-symlink");
        let target = linked.join("attacker-controlled");
        let linked_path = linked.join(PUBLICATION_FILE);
        write_private(&target, b"{}");
        std::os::unix::fs::symlink(&target, &linked_path).expect("a publication symlink");
        assert!(format!("{:#}", read_publication(&linked).unwrap_err())
            .contains("without following links"));
        assert!(target.exists());

        let oversized = scratch("publication-oversized");
        write_private(
            &oversized.join(PUBLICATION_FILE),
            &vec![b'x'; PRIVATE_MARKER_MAX_BYTES as usize + 1],
        );
        assert!(format!("{:#}", read_publication(&oversized).unwrap_err()).contains("byte limit"));

        let malformed_birth = scratch("publication-birth");
        write_private(
            &malformed_birth.join(PUBLICATION_FILE),
            br#"{"port":54321,"protocol":1,"node":"nonode@nohost","pid":42,"scope":"operate","birth":"../../reused"}"#,
        );
        assert!(
            format!("{:#}", read_publication(&malformed_birth).unwrap_err())
                .contains("process birth identity is malformed")
        );

        for dir in [broad, linked, oversized, malformed_birth] {
            fs::remove_dir_all(dir).ok();
        }
    }

    #[test]
    fn a_web_publication_decodes_with_and_without_a_token_file() {
        let full = scratch("web-publication-full");
        write_private(
            &full.join(WEB_PUBLICATION_FILE),
            br#"{"port":4321,"protocol":1,"node":"nonode@nohost","pid":42,"scope":"operate","token_file":"/data/gateway.token","future":true}"#,
        );

        let publication = read_web_publication(&full)
            .expect("readable")
            .expect("present");
        assert_eq!(publication.port, 4321);
        assert_eq!(publication.protocol, 1);
        assert_eq!(publication.pid, 42);
        assert_eq!(publication.scope, "operate");
        assert_eq!(
            publication.token_file.as_deref(),
            Some("/data/gateway.token")
        );

        // The endpoint omits the key entirely when no file supplied its token, and a
        // client that required one would refuse a surface that is running fine.
        let minimal = scratch("web-publication-minimal");
        write_private(
            &minimal.join(WEB_PUBLICATION_FILE),
            br#"{"port":4321,"pid":42}"#,
        );

        let publication = read_web_publication(&minimal)
            .expect("readable")
            .expect("present");
        assert_eq!(publication.port, 4321);
        assert_eq!(publication.protocol, 0);
        assert_eq!(publication.scope, "");
        assert_eq!(publication.token_file, None);

        assert!(read_web_publication(&scratch("web-publication-absent"))
            .expect("readable")
            .is_none());

        for dir in [full, minimal] {
            fs::remove_dir_all(dir).ok();
        }
    }

    #[test]
    fn a_web_publication_read_is_private_bounded_nofollow_and_refuses_garbage() {
        let garbage = scratch("web-publication-garbage");
        write_private(&garbage.join(WEB_PUBLICATION_FILE), b"not json at all");
        assert!(format!("{:#}", read_web_publication(&garbage).unwrap_err())
            .contains("is not a web publication"));

        let pidless = scratch("web-publication-pidless");
        write_private(
            &pidless.join(WEB_PUBLICATION_FILE),
            br#"{"port":4321,"pid":0}"#,
        );
        assert!(format!("{:#}", read_web_publication(&pidless).unwrap_err())
            .contains("must contain a positive pid"));

        let broad = scratch("web-publication-broad-mode");
        fs::write(
            broad.join(WEB_PUBLICATION_FILE),
            br#"{"port":4321,"pid":42}"#,
        )
        .expect("a broad web publication");
        assert!(format!("{:#}", read_web_publication(&broad).unwrap_err()).contains("mode 0600"));

        let linked = scratch("web-publication-symlink");
        let target = linked.join("attacker-controlled");
        write_private(&target, br#"{"port":4321,"pid":42}"#);
        std::os::unix::fs::symlink(&target, linked.join(WEB_PUBLICATION_FILE))
            .expect("a web publication symlink");
        assert!(format!("{:#}", read_web_publication(&linked).unwrap_err())
            .contains("without following links"));
        assert!(target.exists());

        let oversized = scratch("web-publication-oversized");
        write_private(
            &oversized.join(WEB_PUBLICATION_FILE),
            &vec![b'x'; PRIVATE_MARKER_MAX_BYTES as usize + 1],
        );
        assert!(
            format!("{:#}", read_web_publication(&oversized).unwrap_err()).contains("byte limit")
        );

        for dir in [garbage, pidless, broad, linked, oversized] {
            fs::remove_dir_all(dir).ok();
        }
    }

    #[test]
    fn a_web_publication_naming_a_dead_pid_is_stale_but_still_readable() {
        let dir = scratch("web-publication-stale");
        let path = dir.join(WEB_PUBLICATION_FILE);

        // This process is alive by construction, so its own pid is the one live pid a test
        // can name without racing a spawn.
        let live = std::process::id() as i32;
        write_private(&path, format!(r#"{{"port":4321,"pid":{live}}}"#).as_bytes());
        assert!(read_live_web_publication(&dir).expect("readable").is_some());

        fs::remove_file(&path).expect("the live publication");
        write_private(&path, br#"{"port":4321,"pid":2147483646}"#);

        // Stale to the liveness question, and still readable to the one that reports why:
        // the refusal names the pid, so the raw read has to keep working.
        assert!(read_live_web_publication(&dir).expect("readable").is_none());
        assert_eq!(
            read_web_publication(&dir)
                .expect("readable")
                .expect("present")
                .pid,
            2_147_483_646
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawn_env_enables_the_web_surface_over_a_callers_opt_out() {
        // Setting OUROBOROS_GATEWAY is what takes `config/runtime.exs` out of the defaulted
        // branch that enables the web surface on its own, so this variable is the only
        // thing standing between a spawned daemon and no browser surface at all.
        let caller = vec![("OUROBOROS_WEB".into(), "0".into())];
        let env = spawn_env(
            &caller,
            Path::new("/data"),
            Path::new("/data/gateway.token"),
        )
        .unwrap();

        assert_eq!(
            env.iter()
                .find(|(key, _)| key == "OUROBOROS_WEB")
                .map(|(_, value)| value.as_str()),
            Some("1")
        );
    }

    #[test]
    fn a_runtime_owner_decodes_at_private_mode_and_tolerates_new_fields() {
        let dir = scratch("runtime-owner");
        let path = dir.join(RUNTIME_OWNER_FILE);

        write_private(&path, br#"{"pid":42,"owner":"vm-identity","future":true}"#);

        assert_eq!(
            read_owned_runtime_owner(&dir)
                .expect("a readable owner")
                .expect("an owner marker"),
            RuntimeOwner {
                pid: 42,
                owner: "vm-identity".into(),
                birth: None,
            }
        );
        assert_eq!(
            fs::metadata(&path).expect("owner metadata").mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_live_runtime_owner_refuses_a_second_spawn_without_removing_the_marker() {
        let dir = scratch("live-runtime-owner");
        let path = dir.join(RUNTIME_OWNER_FILE);
        let contents = format!(
            r#"{{"pid":{},"owner":"this-live-process"}}"#,
            std::process::id()
        );

        write_private(&path, contents.as_bytes());

        let error = ensure_no_live_runtime_owner(&dir).expect_err("a second runtime");
        let message = error.to_string();

        assert!(message.contains(&format!("runtime pid {}", std::process::id())));
        assert!(message.contains("will not start a second runtime or signal the owner"));
        assert!(
            path.exists(),
            "preflight must never clear a live owner's claim"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_dead_runtime_owner_is_left_for_the_beams_bounded_recovery() {
        let dir = scratch("stale-runtime-owner");
        let path = dir.join(RUNTIME_OWNER_FILE);

        write_private(&path, br#"{"pid":2147483647,"owner":"stale-vm"}"#);

        ensure_no_live_runtime_owner(&dir).expect("a dead owner may be recovered by the child");
        assert!(
            path.exists(),
            "the client does not own stale recovery and must leave the marker for the BEAM"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_invalid_runtime_owner_fails_closed_before_any_spawn() {
        let dir = scratch("invalid-runtime-owner");
        let path = dir.join(RUNTIME_OWNER_FILE);

        write_private(&path, br#"{"pid":0,"owner":""}"#);

        let error = ensure_no_live_runtime_owner(&dir).expect_err("an unverifiable owner");
        let message = error.to_string();

        assert!(message.contains("positive pid"));
        assert!(path.exists());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_interrupted_recovery_gate_fails_before_spawn_with_the_safe_repair_contract() {
        let dir = scratch("interrupted-owner-recovery");
        let owner = dir.join(RUNTIME_OWNER_FILE);
        let recovery = dir.join(RUNTIME_OWNER_RECOVERY_FILE);

        write_private(&owner, br#"{"pid":2147483647,"owner":"stale-vm"}"#);
        write_private(&recovery, b"interrupted recovery");

        let error = ensure_no_live_runtime_owner(&dir).expect_err("an interrupted recovery");
        let message = error.to_string();

        assert!(message.contains(&recovery.display().to_string()));
        assert!(message.contains(&owner.display().to_string()));
        assert!(message.contains("legacy or malformed recovery gate"));
        assert!(message.contains("removing exactly this file once"));
        assert!(owner.exists());
        assert!(recovery.exists());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_symlink_runtime_owner_fails_closed_without_reading_its_target() {
        let dir = scratch("symlink-runtime-owner");
        let target = dir.join("attacker-controlled");
        let path = dir.join(RUNTIME_OWNER_FILE);

        write_private(&target, br#"{"pid":42,"owner":"other-vm"}"#);
        std::os::unix::fs::symlink(&target, &path).expect("an owner-marker symlink");

        let error = ensure_no_live_runtime_owner(&dir).expect_err("an unverifiable owner path");
        assert!(format!("{error:#}").contains(&path.display().to_string()));
        assert!(fs::symlink_metadata(&path)
            .expect("the symlink remains")
            .file_type()
            .is_symlink());
        assert!(
            target.exists(),
            "the target is neither consulted nor removed"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_publication_is_not_an_error() {
        let dir = scratch("absent");

        assert!(read_publication(&dir).expect("readable").is_none());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn our_own_pid_is_alive_and_pid_zero_is_not() {
        assert!(pid_alive(std::process::id() as i32));
        assert!(!pid_alive(0));
        assert!(!pid_alive(-1));
    }

    #[test]
    fn the_ring_drops_the_oldest_lines_and_counts_them() {
        let ring = LogRing::new(3, 1024);

        for index in 0..5 {
            ring.push(Stream::Stderr, format!("line {index}"));
        }

        let tail: Vec<String> = ring.tail(10).into_iter().map(|line| line.text).collect();

        assert_eq!(tail, vec!["line 2", "line 3", "line 4"]);
        assert_eq!(ring.dropped(), 2);
    }

    #[test]
    fn a_relative_workspace_is_resolved_where_it_was_typed() {
        assert_eq!(
            resolve_workspace(Path::new("src"), Path::new("/home/operator/project")),
            "/home/operator/project/src"
        );

        // Already absolute: the operator named a path on the runtime's filesystem, and
        // rewriting it would be this client second-guessing that.
        assert_eq!(
            resolve_workspace(Path::new("/srv/work"), Path::new("/home/operator")),
            "/srv/work"
        );

        assert_eq!(
            resolve_workspace(Path::new("."), Path::new("/home/operator")),
            "/home/operator/."
        );
    }

    #[test]
    fn only_one_client_may_hold_the_spawn_lock() {
        let dir = scratch("lock");

        let held = acquire_spawn_lock(&dir).expect("the first lock");

        assert_eq!(held.path(), dir.join(SPAWN_LOCK_FILE));
        let claim = read_test_process_identity(held.path());
        assert_eq!(claim.pid, std::process::id() as i32);
        assert!(process_identity_is_live(&claim).expect("an exact live claimant"));
        assert_eq!(
            fs::metadata(held.path()).expect("lock metadata").mode() & 0o777,
            0o600,
            "the process-local serialization claim is private"
        );

        let refused = acquire_spawn_lock(&dir).expect_err("a second lock");
        let message = format!("{refused:#}");

        assert!(
            message.contains(&format!("pid {}", std::process::id())),
            "the loser must be told which pid won: {message}"
        );
        assert!(
            fs::read_dir(&dir)
                .expect("lock directory")
                .all(|entry| !entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")),
            "a failed atomic claim must not leave its private temporary name behind"
        );

        drop(held);

        // Released, so the next attempt succeeds without any staleness reasoning.
        let _next = acquire_spawn_lock(&dir).expect("a lock after the first was released");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_stale_reader_cannot_unlink_a_publication_replaced_by_the_lock_winner() {
        use std::sync::Barrier;

        let dir = scratch("publication-recheck-race");
        let path = dir.join(PUBLICATION_FILE);
        write_private(
            &path,
            br#"{"port":4100,"protocol":1,"node":"stale@test","pid":2147483647,"scope":"operate"}"#,
        );

        let stale_seen = Arc::new(Barrier::new(2));
        let replacement_published = Arc::new(Barrier::new(2));
        let reader_dir = dir.clone();
        let reader_stale_seen = stale_seen.clone();
        let reader_replacement_published = replacement_published.clone();

        let reader = std::thread::spawn(move || {
            let observed = read_owned_publication(&reader_dir)
                .expect("the initial publication is readable")
                .expect("the stale publication exists");
            assert!(!pid_alive(observed.pid));
            reader_stale_seen.wait();
            reader_replacement_published.wait();

            let lock = acquire_spawn_lock(&reader_dir).expect("the reader takes the lock later");

            match reconcile_publication_under_spawn_lock(&reader_dir, &lock)
                .expect("locked reconciliation")
            {
                LockedPublication::Live(current) => {
                    assert_eq!(current.pid, std::process::id() as i32)
                }
                other => panic!("the replacement must survive the stale observation: {other:?}"),
            }
        });

        stale_seen.wait();
        let winner = acquire_spawn_lock(&dir).expect("the concurrent starter wins the lock");
        fs::write(
            &path,
            format!(
                r#"{{"port":4200,"protocol":1,"node":"winner@test","pid":{},"scope":"operate"}}"#,
                std::process::id()
            ),
        )
        .expect("the winner's publication");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("private winner publication");
        drop(winner);
        replacement_published.wait();
        reader.join().expect("the stale reader finishes");

        let current = read_owned_publication(&dir)
            .expect("the final publication is readable")
            .expect("the winner remains discoverable");
        assert_eq!(current.pid, std::process::id() as i32);
        assert_eq!(current.port, 4200);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_lock_whose_holder_is_gone_is_cleared_once() {
        let dir = scratch("stale-lock");
        let path = dir.join(SPAWN_LOCK_FILE);

        // Pid 2^31-1 is above every pid_max a Unix uses, so it names nothing.
        write_private(&path, b"2147483647");

        let taken = acquire_spawn_lock(&dir).expect("a lock after clearing a dead holder");

        let claim = read_test_process_identity(taken.path());
        assert_eq!(claim.pid, std::process::id() as i32);
        assert_eq!(
            fs::read(dir.join(SPAWN_LOCK_RECOVERY_FILE)).expect("persistent recovery inode"),
            SPAWN_RECOVERY_HEADER
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_malformed_spawn_lock_fails_closed_instead_of_being_cleared() {
        let dir = scratch("garbage-lock");
        let path = dir.join(SPAWN_LOCK_FILE);

        write_private(&path, b"not a pid");

        let error = acquire_spawn_lock(&dir).expect_err("a malformed lock is not stale proof");
        let message = format!("{error:#}");

        assert!(message.contains("does not contain one positive pid"));
        assert!(message.contains("will not clear it"));
        assert!(message.contains(&path.display().to_string()));
        assert!(path.exists());
        assert_eq!(
            fs::read(dir.join(SPAWN_LOCK_RECOVERY_FILE)).expect("persistent recovery inode"),
            SPAWN_RECOVERY_HEADER
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_symlink_spawn_lock_fails_closed_without_reading_or_removing_its_target() {
        let dir = scratch("symlink-spawn-lock");
        let target = dir.join("attacker-controlled");
        let path = dir.join(SPAWN_LOCK_FILE);
        write_private(&target, b"2147483647");
        std::os::unix::fs::symlink(&target, &path).expect("a spawn-lock symlink");

        let error = acquire_spawn_lock(&dir).expect_err("a symlink is not a stale claim");
        let message = format!("{error:#}");

        assert!(message.contains("without following links"));
        assert!(fs::symlink_metadata(&path)
            .expect("the symlink remains")
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_to_string(&target).expect("the untouched target"),
            "2147483647"
        );
        assert_eq!(
            fs::read(dir.join(SPAWN_LOCK_RECOVERY_FILE)).expect("persistent recovery inode"),
            SPAWN_RECOVERY_HEADER
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_one_stale_lock_recoverer_may_unlink_and_reclaim() {
        use std::sync::Barrier;

        let dir = scratch("stale-lock-two-recoverers");
        let path = dir.join(SPAWN_LOCK_FILE);
        let recovery = dir.join(SPAWN_LOCK_RECOVERY_FILE);
        write_private(&path, b"2147483647");

        let gate_claimed = Arc::new(Barrier::new(2));
        let contender_finished = Arc::new(Barrier::new(2));
        let winner_dir = dir.clone();
        let winner_path = path.clone();
        let winner_gate_claimed = gate_claimed.clone();
        let winner_contender_finished = contender_finished.clone();

        let winner = std::thread::spawn(move || {
            recover_stale_spawn_lock(&winner_dir, &winner_path, || {
                winner_gate_claimed.wait();
                winner_contender_finished.wait();
            })
            .expect("the recovery-gate winner reclaims the stale lock")
        });

        gate_claimed.wait();
        assert!(recovery.exists(), "the winner holds the recovery gate");
        assert_eq!(
            fs::metadata(&recovery).expect("recovery metadata").mode() & 0o777,
            0o600,
            "stale recovery coordination is private"
        );
        assert_eq!(
            fs::read_to_string(&path).expect("the still-stale lock"),
            "2147483647",
            "a losing recoverer must not unlink the observed stale inode"
        );

        let refused = acquire_spawn_lock(&dir).expect_err("only one recovery claimant");
        let message = format!("{refused:#}");
        assert!(message.contains("is recovering the stale spawn lock"));
        assert!(message.contains(&recovery.display().to_string()));
        assert!(path.exists());

        contender_finished.wait();
        let held = winner.join().expect("the recovery winner finishes");

        assert_eq!(
            fs::read(&recovery).expect("the persistent recovery inode"),
            SPAWN_RECOVERY_HEADER
        );
        assert_eq!(
            read_test_process_identity(&path).pid,
            std::process::id() as i32
        );

        drop(held);
        assert!(
            !path.exists(),
            "the replacement owner releases its own inode"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_interrupted_spawn_lock_recovery_gate_fails_closed_with_safe_repair_steps() {
        let dir = scratch("interrupted-spawn-lock-recovery");
        let lock = dir.join(SPAWN_LOCK_FILE);
        let recovery = dir.join(SPAWN_LOCK_RECOVERY_FILE);
        write_private(&lock, b"2147483647");
        write_private(&recovery, b"2147483647");

        let error = acquire_spawn_lock(&dir).expect_err("an interrupted recovery gate");
        let message = format!("{error:#}");

        assert!(message.contains("legacy or malformed recovery gate"));
        assert!(message.contains("removing exactly this file once"));
        assert!(message.contains(&recovery.display().to_string()));
        assert!(lock.exists());
        assert!(recovery.exists());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_reader_sees_a_complete_pid_during_initial_lock_publication() {
        use std::sync::Barrier;

        let dir = scratch("initial-lock-publication");
        let path = dir.join(SPAWN_LOCK_FILE);
        let published = Arc::new(Barrier::new(2));
        let reader_finished = Arc::new(Barrier::new(2));
        let claimant_path = path.clone();
        let claimant_published = published.clone();
        let claimant_reader_finished = reader_finished.clone();

        let claimant = std::thread::spawn(move || {
            try_create_lock_with(&claimant_path, || {
                claimant_published.wait();
                claimant_reader_finished.wait();
            })
            .expect("the initial claimant")
        });

        published.wait();
        let claim = read_test_process_identity(&path);
        assert_eq!(claim.pid, std::process::id() as i32);
        assert!(validate_birth(&claim.birth).is_ok());

        let refused = acquire_spawn_lock(&dir).expect_err("the reader sees the live claimant");
        assert!(format!("{refused:#}").contains(&format!("pid {}", std::process::id())));
        assert!(path.exists(), "the reader never unlinks the active claim");

        reader_finished.wait();
        let held = claimant.join().expect("the claimant finishes");
        assert!(
            fs::read_dir(&dir)
                .expect("lock directory")
                .all(|entry| !entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")),
            "the successful atomic claim removes its temporary name"
        );

        drop(held);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_ring_is_bounded_by_bytes_as_well_as_lines() {
        let ring = LogRing::new(1_000, 16);

        ring.push(Stream::Stdout, "0123456789".into());
        ring.push(Stream::Stdout, "abcdefghij".into());

        assert_eq!(ring.len(), 1);
        assert_eq!(ring.tail(10)[0].text, "abcdefghij");
    }

    fn write_private(path: &Path, contents: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("a private test file");

        io::Write::write_all(&mut file, contents).expect("owner contents");
        io::Write::flush(&mut file).expect("flushed owner contents");
    }

    fn read_test_process_identity(path: &Path) -> ProcessIdentity {
        serde_json::from_str(&fs::read_to_string(path).expect("a readable process claim"))
            .expect("a complete pid and birth claim")
    }

    #[tokio::test]
    async fn dropping_an_armed_daemon_does_not_silently_detach_its_child() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("a long-running child");
        let pid = child.id().expect("the child pid") as i32;
        let daemon = Daemon {
            child: Some(child),
            identity: ProcessIdentity {
                pid,
                birth: format!("test:{pid}"),
            },
            logs: LogRing::default(),
            epmd_failure: None,
        };

        assert!(pid_alive(pid));
        drop(daemon);

        let deadline = Instant::now() + Duration::from_secs(5);

        while pid_alive(pid) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert!(
            !pid_alive(pid),
            "dropping an armed Daemon must kill pid {pid}"
        );
    }

    #[tokio::test]
    async fn explicit_detach_disarms_the_drop_guard_and_keeps_the_child_running() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("a long-running child");
        let pid = child.id().expect("the child pid") as i32;
        let mut daemon = Daemon {
            child: Some(child),
            identity: ProcessIdentity {
                pid,
                birth: format!("test:{pid}"),
            },
            logs: LogRing::default(),
            epmd_failure: None,
        };

        daemon.detach();
        assert!(
            daemon.child.is_none(),
            "detach explicitly disarms ownership"
        );
        drop(daemon);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            pid_alive(pid),
            "an explicitly detached child must survive Drop"
        );

        send_signal(pid, libc::SIGTERM).expect("cleaning up the detached test child");
        let deadline = Instant::now() + Duration::from_secs(5);

        while pid_alive(pid) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        if pid_alive(pid) {
            let _ = send_signal(pid, libc::SIGKILL);
        }

        assert!(!pid_alive(pid), "the detached test child should be reaped");
    }

    #[tokio::test]
    async fn epmd_health_failure_stops_the_exact_child_owned_by_daemon_wait() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("a long-running child");
        let pid = child.id().expect("the child pid") as i32;
        let (failure, receiver) = tokio::sync::oneshot::channel();
        let mut daemon = Daemon {
            child: Some(child),
            identity: ProcessIdentity {
                pid,
                birth: format!("test:{pid}"),
            },
            logs: LogRing::default(),
            epmd_failure: Some(receiver),
        };

        failure
            .send("EPMD fixture disappeared".into())
            .expect("deliver the health failure");
        let status = tokio::time::timeout(Duration::from_secs(5), daemon.wait())
            .await
            .expect("the managed child stopped promptly")
            .expect("the managed child was reaped");
        assert!(!status.success());
        assert!(!pid_alive(pid));
        assert!(daemon.child.is_none());
    }

    #[tokio::test]
    async fn normal_runtime_exit_disarms_epmd_health_without_a_spurious_restart_signal() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("a short-lived child");
        let pid = child.id().expect("the child pid") as i32;
        let (failure, receiver) = tokio::sync::oneshot::channel();
        let mut daemon = Daemon {
            child: Some(child),
            identity: ProcessIdentity {
                pid,
                birth: format!("test:{pid}"),
            },
            logs: LogRing::default(),
            epmd_failure: Some(receiver),
        };

        let status = daemon.wait().await.expect("reap the normal runtime exit");
        assert!(status.success());
        assert!(daemon.child.is_none());
        assert!(daemon.epmd_failure.is_none());
        assert!(
            failure.send("late EPMD failure".into()).is_err(),
            "normal runtime completion must close and disarm its health receiver"
        );
    }
}
