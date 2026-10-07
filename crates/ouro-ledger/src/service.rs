//! Detached batch owners under an already provisioned lingering user manager.
//!
//! The unit command contains only bootstrap metadata. Launch arguments and the
//! caller's environment cross a bounded private socket and are never spooled.

use crate::{
    daemon::Client,
    protocol::{LedgerError, Result, RunRecord},
    runner,
};
use serde_json::{Value, json};
use std::path::Path;

pub fn terminal(run: &RunRecord) -> bool {
    matches!(run.state.as_str(), "settled" | "denied" | "outcome_unknown")
}

pub fn wait(data: &Path, run_id: &str, timeout: std::time::Duration) -> Result<RunRecord> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let mut client = Client::connect(data)?;
        let run = client.show(run_id)?;
        if terminal(&run) {
            return Ok(run);
        }
        if run
            .owner
            .as_ref()
            .is_some_and(|peer| !crate::daemon::peer_alive(peer))
        {
            return Err(LedgerError(
                "launch owner is gone; run settle-orphans to record the unknown outcome".into(),
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(LedgerError(
                "wait timed out; the run was not cancelled".into(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(target_os = "linux")]
pub use linux::{cancel, cancel_requested, launch, prepare, probe, serve, start_writer};

#[cfg(not(target_os = "linux"))]
pub fn start_writer(_: &Path) -> Result<()> {
    Err(LedgerError(
        "independent writer service requires Linux".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn prepare(_: &runner::RunOptions) -> Result<RunRecord> {
    Err(LedgerError("detached preparation requires Linux".into()))
}

#[cfg(not(target_os = "linux"))]
pub fn probe() -> Value {
    json!({"available":false,"reason":"detached launch ownership requires Linux and a lingering systemd user manager"})
}
#[cfg(not(target_os = "linux"))]
pub fn launch(_: &runner::RunOptions) -> Result<RunRecord> {
    Err(LedgerError(probe()["reason"].as_str().unwrap().into()))
}
#[cfg(not(target_os = "linux"))]
/// # Safety
/// Same entry-point-only contract as the Linux implementation.
pub unsafe fn serve(_: &Path, _: &str) -> Result<()> {
    Err(LedgerError("detached owner requires Linux".into()))
}
#[cfg(not(target_os = "linux"))]
pub fn cancel(_: &Path, _: &str) -> Result<Value> {
    Err(LedgerError("local cancellation requires Linux".into()))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::daemon::{peer_alive, peer_credentials, read_frame, write_frame};
    use serde::{Deserialize, Serialize};
    use std::{
        ffi::OsString,
        fs,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{
                ffi::OsStrExt,
                fs::PermissionsExt,
                net::{UnixListener, UnixStream},
            },
        },
        path::PathBuf,
        process::{Command, Stdio},
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };

    const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
    const START_TIMEOUT: Duration = Duration::from_secs(45);
    static CANCEL: AtomicBool = AtomicBool::new(false);

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Launch {
        schema: String,
        options: runner::RunOptions,
        cwd: PathBuf,
        environment: Vec<(OsString, OsString)>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
    enum Started {
        Owned { run: Box<RunRecord> },
        Refused { reason: String },
    }

    struct SocketPath(PathBuf);
    impl Drop for SocketPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn command_output(command: &mut Command) -> Result<String> {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait()? {
                let mut text = String::new();
                child
                    .stdout
                    .take()
                    .unwrap()
                    .take(16_385)
                    .read_to_string(&mut text)?;
                if !status.success() || text.len() > 16_384 {
                    return Err(LedgerError(
                        "systemd user-manager command failed or exceeded its output bound".into(),
                    ));
                }
                return Ok(text.trim().to_owned());
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LedgerError("systemd user-manager command timed out".into()));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn ready() -> Result<()> {
        let uid = unsafe { libc::geteuid() }.to_string();
        if command_output(Command::new("/usr/bin/loginctl").args([
            "show-user",
            &uid,
            "--property=Linger",
            "--value",
        ]))? != "yes"
        {
            return Err(LedgerError(
                "detached runs require an operator-provisioned lingering user manager".into(),
            ));
        }
        command_output(Command::new("/usr/bin/systemctl").args([
            "--user",
            "show",
            "--property=Version",
            "--value",
        ]))?;
        Ok(())
    }
    pub fn probe() -> Value {
        match ready() {
            Ok(()) => {
                json!({"available":true,"mechanism":"systemd_user_service","linger":true,"host_configuration_changed":false})
            }
            Err(error) => {
                json!({"available":false,"reason":error.to_string(),"host_configuration_changed":false})
            }
        }
    }

    fn main_pid(unit: &str) -> Result<u32> {
        command_output(Command::new("/usr/bin/systemctl").args([
            "--user",
            "show",
            unit,
            "--property=MainPID",
            "--value",
        ]))?
        .parse()
        .map_err(|_| LedgerError("user manager did not identify the launch owner".into()))
    }

    fn unit_command(unit: &str) -> Command {
        let mut command = Command::new("/usr/bin/systemd-run");
        command
            .args([
                "--user",
                "--quiet",
                "--collect",
                "--no-ask-password",
                "--service-type=exec",
                "--expand-environment=no",
                "--property=KillMode=control-group",
                "--property=StandardInput=null",
                "--property=StandardOutput=null",
                "--property=StandardError=null",
                "--unit",
            ])
            .arg(unit);
        command
    }

    pub fn prepare(options: &runner::RunOptions) -> Result<RunRecord> {
        if !options.batch || !options.detached || options.prepared.is_some() {
            return Err(LedgerError(
                "preparation requires detached batch mode and a request id".into(),
            ));
        }
        ready()?;
        let request = runner::resolve_request(options)?;
        ensure_writer(&options.data)?;
        Client::connect(&options.data)?.prepare(&options.request_id, &request)
    }

    pub fn start_writer(data: &Path) -> Result<()> {
        ready()?;
        ensure_writer(data)
    }

    fn ensure_writer(data: &Path) -> Result<()> {
        crate::store::private_directory(data)?;
        crate::store::private_directory(&data.join("ledger"))?;
        let digest = ouro_records::canonical::sha256_prefixed(
            fs::canonicalize(data)?.as_os_str().as_bytes(),
        );
        let unit = format!("ouro-ledger-writer-{}.service", &digest[7..39]);
        if Client::connect(data).is_err() {
            let mut command = unit_command(&unit);
            if let Some(config) = std::env::var_os("OURO_CONFIG_DIR") {
                let config = PathBuf::from(config);
                if !config.is_absolute() {
                    return Err(LedgerError(
                        "OURO_CONFIG_DIR must be absolute for a detached writer".into(),
                    ));
                }
                let mut setting = std::ffi::OsString::from("--setenv=OURO_CONFIG_DIR=");
                setting.push(config);
                command.arg(setting);
            }
            let started = command_output(
                command
                    .arg("--")
                    .arg(std::env::current_exe()?)
                    .arg("--data-dir")
                    .arg(data)
                    .arg("serve"),
            );
            // Another submitter may have started this same deterministic unit.
            if started.is_err() && main_pid(&unit).unwrap_or(0) == 0 {
                started?;
            }
        }
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            if let Ok(stream) = UnixStream::connect(data.join("ledger/serve.sock")) {
                let peer = peer_credentials(&stream)?;
                if peer.uid != unsafe { libc::geteuid() }
                    || peer.pid != main_pid(&unit)?
                    || !peer_alive(&peer)
                {
                    return Err(LedgerError("the existing ledger writer is not an independent user service; stop it after active runs settle before using --detach".into()));
                }
                Client::connect(data)?.ping()?;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(LedgerError(
                    "independent writer did not become ready".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn valid_unit(unit: &str) -> bool {
        unit.strip_prefix("ouro-ledger-owner-")
            .and_then(|s| s.strip_suffix(".service"))
            .is_some_and(|s| {
                s.len() == 32
                    && s.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
    }

    pub fn launch(options: &runner::RunOptions) -> Result<RunRecord> {
        if !options.batch || !options.detached {
            return Err(LedgerError("--detach requires --io batch".into()));
        }
        ready()?;
        // Start the writer before handing off. The service checks its continuing
        // availability under the existing strict-evidence contract.
        ensure_writer(&options.data)?;
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let unit = format!("ouro-ledger-owner-{nonce}.service");
        let path = SocketPath(
            options
                .data
                .join("ledger")
                .join(format!("start-{nonce}.sock")),
        );
        let listener = UnixListener::bind(&path.0)?;
        fs::set_permissions(&path.0, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        // Validate the whole frame before creating a service. No raw request
        // values occur in its command, unit properties, logs or environment.
        let launch = Launch {
            schema: "ouro.ledger.owner-launch/1".into(),
            options: options.clone(),
            cwd: std::env::current_dir()?,
            environment: std::env::vars_os().collect(),
        };
        let mut frame = Vec::new();
        write_frame(&mut frame, &launch)?;
        command_output(
            unit_command(&unit)
                .arg("--property=Delegate=yes")
                .arg("--")
                .arg(std::env::current_exe()?)
                .args(["__owner", "--bootstrap"])
                .arg(&path.0)
                .arg("--unit")
                .arg(&unit),
        )?;
        let deadline = Instant::now() + START_TIMEOUT;
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => return Err(error.into()),
            }
        };
        stream.set_read_timeout(Some(START_TIMEOUT))?;
        stream.set_write_timeout(Some(COMMAND_TIMEOUT))?;
        let peer = peer_credentials(&stream)?;
        if peer.uid != unsafe { libc::geteuid() }
            || peer.pid != main_pid(&unit)?
            || !peer_alive(&peer)
        {
            return Err(LedgerError(
                "bootstrap peer is not the independent service owner".into(),
            ));
        }
        use std::io::Write as _;
        stream.write_all(&frame)?;
        match read_frame::<Started>(&mut stream)? {
            Started::Owned { run } => Ok(*run),
            Started::Refused { reason } => Err(LedgerError(reason)),
        }
    }

    extern "C" fn request_cancel(_: libc::c_int) {
        CANCEL.store(true, Ordering::Relaxed);
    }
    pub fn cancel_requested() -> bool {
        CANCEL.load(Ordering::Relaxed)
    }

    /// Called only by the hidden CLI entry point, before creating any threads.
    /// # Safety
    /// Call only from the hidden process entry point before creating any threads.
    pub unsafe fn serve(path: &Path, unit: &str) -> Result<()> {
        if !valid_unit(unit) || main_pid(unit)? != std::process::id() {
            return Err(LedgerError(
                "owner must be started by its independent user service".into(),
            ));
        }
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(COMMAND_TIMEOUT))?;
        stream.set_write_timeout(Some(COMMAND_TIMEOUT))?;
        let peer = peer_credentials(&stream)?;
        if peer.uid != unsafe { libc::geteuid() } {
            return Err(LedgerError("bootstrap peer uid mismatch".into()));
        }
        // Remove the rendezvous before receiving secrets; a killed caller leaves
        // no abandoned socket once the service connects.
        fs::remove_file(path)?;
        let launch: Launch = read_frame(&mut stream)?;
        if launch.schema != "ouro.ledger.owner-launch/1"
            || !launch.options.batch
            || !launch.options.detached
        {
            return Err(LedgerError("invalid detached launch frame".into()));
        }
        for (key, value) in &launch.environment {
            if key.is_empty()
                || key.as_bytes().iter().any(|b| *b == 0 || *b == b'=')
                || value.as_bytes().contains(&0)
            {
                return Err(LedgerError("invalid bootstrap environment encoding".into()));
            }
        }
        std::env::set_current_dir(&launch.cwd)?;
        // SAFETY: this hidden entry point runs before any thread is created.
        // Environment is restored only in this new process, never the submitter.
        unsafe {
            for (key, _) in std::env::vars_os() {
                std::env::remove_var(key);
            }
            for (key, value) in launch.environment {
                std::env::set_var(key, value);
            }
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = request_cancel as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let mut announced = false;
        let result = runner::run_notifying(&launch.options, &mut |run| {
            announced = true;
            // A lost acknowledgement does not cancel or replay an owned attempt.
            let _ = write_frame(
                &mut stream,
                &Started::Owned {
                    run: Box::new(run.clone()),
                },
            );
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });
        if let Err(error) = result {
            if !announced {
                let _ = write_frame(
                    &mut stream,
                    &Started::Refused {
                        reason: error.to_string(),
                    },
                );
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn cancel(data: &Path, run_id: &str) -> Result<Value> {
        let run = Client::connect(data)?.show(run_id)?;
        if terminal(&run) {
            return Ok(json!({"run_id":run_id,"status":"already_terminal","run":run}));
        }
        if run.payload["owner_lifetime"] != "systemd_user_service" {
            return Err(LedgerError(
                "cancel requires a detached service owner".into(),
            ));
        }
        let peer = run
            .owner
            .ok_or_else(|| LedgerError("attempt has no launch owner".into()))?;
        // Open first, then validate birth. Signal the pinned task, never a reused pid.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, peer.pid as libc::pid_t, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        if peer.uid != unsafe { libc::geteuid() } || !peer_alive(&peer) {
            return Err(LedgerError(
                "launch owner is gone; reconcile before reporting an outcome".into(),
            ));
        }
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                libc::SIGUSR1,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(json!({"run_id":run_id,"status":"stop_requested","settlement":"pending"}))
    }
}
