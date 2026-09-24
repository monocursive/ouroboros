//! The supervisor enters a delegated user scope itself (jail-v1 §9.3).
//!
//! A supervisor started from a plain login is in `session-<n>.scope`, a
//! sibling of the delegated `user@<uid>.service` that the user cannot write.
//! The kernel's common-ancestor rule then refuses every move into an
//! execution leaf, so the attempt has none: preferred limits go unapplied and
//! the lifetime watcher has no `cgroup.kill`, which lets a supervisor killed
//! during bubblewrap's startup leave the namespace init alive (measured
//! 2026-09-23). `systemd-run --user --scope` closes that, and so does this
//! step, without the operator having to know about it.
//!
//! Before any thread or other resource exists, `run` and `doctor` look at
//! `/proc/self/cgroup`. Inside the delegated subtree already, nothing is done.
//! Outside it, the systemd user manager is asked for a transient scope that
//! contains this process's own pid, by running `busctl` as a **child**
//! (absolute path, cleared environment, no inherited descriptor, dying with
//! this process): the supervisor is never re-executed, so it keeps its pid,
//! descriptors, argv, stdio and parent. The move is then observed in
//! `/proc/self/cgroup` within a bounded wait. Whatever is missing or fails
//! (no `busctl`, no user bus, a failed call, a move not observed in time),
//! the run continues exactly as before and the record says why: this step
//! never fails a run.
//!
//! The decision is portable and tested on every host; the Linux host that
//! reads cgroups and runs `busctl` is gated.

use std::path::{Path, PathBuf};

/// Test seam (J4 decision S9): `assume-outside` makes the supervisor take the
/// branch it takes outside a delegated scope even when it is inside one, so a
/// live test run inside the conformance scope exercises the move;
/// `assume-outside-no-busctl` and `assume-outside-no-bus` take that branch
/// with `busctl` treated as absent, or with the user bus made unreachable for
/// the call, so a live test exercises the path that records `unavailable`.
/// None of them widens anything: the scope requested lies in the subtree the
/// supervisor already runs in, and a failure only records why. Any other
/// value is ignored (recorded as `null`).
pub const SEAM: &str = "OURO_JAIL_TEST_SUPERVISOR_SCOPE";

/// The whole step's budget: the call and the observed move share it.
pub const BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// Where `busctl` is looked for, in order. Never a `PATH` lookup: the
/// supervisor's `PATH` is the operator's, and this child runs before policy.
pub const BUSCTL_CANDIDATES: [&str; 2] = ["/usr/bin/busctl", "/bin/busctl"];

/// The first component of every unit this step requests.
pub const UNIT_PREFIX: &str = "ouro-jail-";

/// The address the `assume-outside-no-bus` seam gives the call: a path under
/// a regular file, so connecting fails with `ENOTDIR` and nothing is reached.
pub const UNREACHABLE_BUS: &str = "unix:path=/dev/null/ouro-jail-no-bus";

/// The seam values that are applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seam {
    /// Take the outside branch even when already inside.
    AssumeOutside,
    /// The outside branch, with `busctl` treated as absent.
    AssumeOutsideNoBusctl,
    /// The outside branch, with the call given an unreachable bus.
    AssumeOutsideNoBus,
    /// The outside branch, with lingering treated as off.
    AssumeOutsideNoLinger,
}

impl Seam {
    /// The value that selects this seam.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Seam::AssumeOutside => "assume-outside",
            Seam::AssumeOutsideNoBusctl => "assume-outside-no-busctl",
            Seam::AssumeOutsideNoBus => "assume-outside-no-bus",
            Seam::AssumeOutsideNoLinger => "assume-outside-no-linger",
        }
    }

    /// The seam `value` selects, exactly; anything else is ignored.
    #[must_use]
    pub fn parse(value: &str) -> Option<Seam> {
        [
            Seam::AssumeOutside,
            Seam::AssumeOutsideNoBusctl,
            Seam::AssumeOutsideNoBus,
            Seam::AssumeOutsideNoLinger,
        ]
        .into_iter()
        .find(|seam| seam.as_str() == value)
    }
}

/// What the seam variable asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeamSetting {
    /// Not set.
    Unset,
    /// Set to a value that is applied.
    Applied(Seam),
    /// Set to a value that is not one of [`Seam`]'s, and so ignored.
    Ignored,
}

impl SeamSetting {
    /// The setting for the variable's value, if it is set. A value that is
    /// not UTF-8 is ignored.
    #[must_use]
    pub fn from_value(value: Option<&std::ffi::OsStr>) -> SeamSetting {
        match value {
            None => SeamSetting::Unset,
            Some(value) => value
                .to_str()
                .and_then(Seam::parse)
                .map_or(SeamSetting::Ignored, SeamSetting::Applied),
        }
    }

    fn applied(self) -> Option<Seam> {
        match self {
            SeamSetting::Applied(seam) => Some(seam),
            SeamSetting::Unset | SeamSetting::Ignored => None,
        }
    }
}

/// Where the supervisor ended up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// It was inside the delegated subtree already; nothing was done.
    AlreadyDelegated,
    /// It asked for a scope and was observed inside it, in the subtree.
    Entered,
    /// It is where it started, or where it is is not known to be the scope
    /// it asked for; `reason` says why.
    Unavailable,
}

impl State {
    /// The record's spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            State::AlreadyDelegated => "already_delegated",
            State::Entered => "entered",
            State::Unavailable => "unavailable",
        }
    }
}

/// Why the state is `unavailable`, as a stable code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// This process never ran the step (a library caller, not `run` or
    /// `doctor`).
    NotAttempted,
    /// `/proc/self/cgroup` could not be read or has no unified line.
    CgroupUnreadable,
    /// There is no delegated subtree for this uid: no user manager runs.
    NoDelegatedSubtree,
    /// No `busctl` at any of [`BUSCTL_CANDIDATES`].
    BusctlMissing,
    /// `busctl` could not be started.
    SpawnFailed,
    /// `busctl` ran and reported failure: no user bus, or the manager
    /// refused the scope.
    CallFailed,
    /// `busctl` did not finish within the budget and was killed.
    CallTimedOut,
    /// The call succeeded but this process was not seen in the requested
    /// scope, inside the delegated subtree, within the budget.
    MoveNotObserved,
    /// Lingering is off: the user manager stops at the last logout and would
    /// take a moved supervisor with it.
    NoLinger,
    /// Lingering could not be established; treated as off.
    LingerUnknown,
}

impl Reason {
    /// The record's spelling.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Reason::NotAttempted => "not_attempted",
            Reason::CgroupUnreadable => "cgroup_unreadable",
            Reason::NoDelegatedSubtree => "no_delegated_subtree",
            Reason::BusctlMissing => "busctl_missing",
            Reason::SpawnFailed => "busctl_spawn_failed",
            Reason::CallFailed => "scope_call_failed",
            Reason::CallTimedOut => "scope_call_timed_out",
            Reason::MoveNotObserved => "scope_move_not_observed",
            Reason::NoLinger => "no_linger",
            Reason::LingerUnknown => "linger_unknown",
        }
    }
}

/// What the step did, as recorded in `lifetime.native.details` and in
/// `doctor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Where the supervisor ended up.
    pub state: State,
    /// The transient unit this process asked for; `None` when none was asked
    /// for.
    pub unit: Option<String>,
    /// Why the state is `unavailable`.
    pub reason: Option<Reason>,
    /// What was observed, for a human reading the record.
    pub detail: Option<String>,
    /// This process's cgroup (relative to the v2 root) when the step ended,
    /// when it could be read.
    pub cgroup: Option<String>,
    /// The seam variable, when it is set.
    pub seam: SeamSetting,
}

impl Outcome {
    fn already(cgroup: String, seam: SeamSetting) -> Outcome {
        Outcome {
            state: State::AlreadyDelegated,
            unit: None,
            reason: None,
            detail: None,
            cgroup: Some(cgroup),
            seam,
        }
    }

    fn unavailable(
        reason: Reason,
        detail: impl Into<String>,
        unit: Option<&str>,
        cgroup: Option<String>,
        seam: SeamSetting,
    ) -> Outcome {
        Outcome {
            state: State::Unavailable,
            unit: unit.map(str::to_owned),
            reason: Some(reason),
            detail: Some(detail.into()),
            cgroup,
            seam,
        }
    }

    /// Whether the supervisor is known to be inside the delegated subtree.
    #[must_use]
    pub fn delegated(&self) -> bool {
        self.state != State::Unavailable
    }

    /// One line for a human: the state, then the unit or the reason.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut line = self.state.as_str().to_owned();
        if let Some(unit) = &self.unit {
            line.push(' ');
            line.push_str(unit);
        }
        if let Some(cgroup) = &self.cgroup {
            line.push_str(" cgroup=");
            line.push_str(cgroup);
        }
        if let Some(detail) = &self.detail {
            line.push_str(": ");
            line.push_str(detail);
        }
        line
    }

    /// The record: `state`, `unit`, `reason_code`, `reason` and `cgroup`,
    /// plus `test_seam` when [`SEAM`] is set (the value applied, or `null`
    /// when ignored).
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut object = serde_json::Map::new();
        object.insert("state".to_owned(), self.state.as_str().into());
        object.insert("unit".to_owned(), self.unit.clone().into());
        object.insert(
            "reason_code".to_owned(),
            self.reason.map(Reason::code).into(),
        );
        object.insert("reason".to_owned(), self.detail.clone().into());
        object.insert("cgroup".to_owned(), self.cgroup.clone().into());
        match self.seam {
            SeamSetting::Unset => {}
            SeamSetting::Applied(seam) => {
                object.insert("test_seam".to_owned(), seam.as_str().into());
            }
            SeamSetting::Ignored => {
                object.insert("test_seam".to_owned(), serde_json::Value::Null);
            }
        }
        serde_json::Value::Object(object)
    }
}

/// Where this process is, as far as the delegated subtree is concerned. Each
/// variant but `Unreadable` carries the process's cgroup, relative to the v2
/// root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Position {
    /// Inside the delegated subtree.
    Inside(String),
    /// Outside it.
    Outside(String),
    /// There is no delegated subtree for this uid.
    NoSubtree(String),
    /// The cgroup could not be read; why.
    Unreadable(String),
}

impl Position {
    fn cgroup(&self) -> Option<String> {
        match self {
            Position::Inside(cgroup) | Position::Outside(cgroup) | Position::NoSubtree(cgroup) => {
                Some(cgroup.clone())
            }
            Position::Unreadable(_) => None,
        }
    }
}

/// Which bus the call is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bus {
    /// The user's own session bus, as the environment names it.
    Session,
    /// [`UNREACHABLE_BUS`] (the `assume-outside-no-bus` seam).
    Unreachable,
}

/// Why a call did not succeed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallFailure {
    /// [`Reason::SpawnFailed`], [`Reason::CallFailed`] or
    /// [`Reason::CallTimedOut`].
    pub reason: Reason,
    /// What was observed (the exit status and `busctl`'s own message).
    pub detail: String,
}

/// The facts and actions the step needs, so the decision can be tested
/// without a user manager.
pub trait Host {
    /// Where this process is now.
    fn position(&mut self) -> Position;
    /// Whether this uid's user manager outlives its sessions (lingering).
    fn lingering(&mut self) -> Linger {
        Linger::Yes
    }
    /// The `busctl` to run, if there is one.
    fn busctl(&mut self) -> Option<PathBuf>;
    /// Ask for `unit` containing this process, through `busctl` on `bus`.
    ///
    /// # Errors
    /// Why the call did not succeed.
    fn request(&mut self, busctl: &Path, unit: &str, bus: Bus) -> Result<(), CallFailure>;
    /// Whether the step's budget is spent.
    fn expired(&self) -> bool;
    /// Wait a little before looking again.
    fn pause(&mut self);
}

/// Whether the user manager outlives the user's sessions.
///
/// Without lingering, logind stops `user@<uid>.service` once the last session
/// ends, and every scope under it with it; a process left in its session
/// scope survives logout (Ubuntu's `KillUserProcesses=no`). A supervisor
/// moved into a user scope would therefore die at logout, so the step moves
/// it only when the manager is known to linger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Linger {
    /// The manager outlives the sessions.
    Yes,
    /// It stops with the last session.
    No,
    /// It could not be established; treated as `No`.
    Unknown(String),
}

/// The name of the unit this process asks for: `ouro-jail-<pid>-<16 hex>.scope`.
/// The pid names the supervisor; the random part makes a collision with any
/// earlier unit of a recycled pid impossible in practice.
#[must_use]
pub fn unit_name(pid: u32) -> String {
    let token = uuid::Uuid::new_v4().simple().to_string();
    format!("{UNIT_PREFIX}{pid}-{}.scope", &token[..16])
}

/// The `busctl` arguments that start `unit` as a transient scope holding
/// `pid`: `StartTransientUnit` with mode `fail`, the pid, collection when
/// inactive or failed (so a failed scope does not linger), and a description.
#[must_use]
pub fn busctl_args(unit: &str, pid: u32) -> Vec<String> {
    let mut args: Vec<String> = [
        "--user",
        "--timeout=2",
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StartTransientUnit",
        "ssa(sv)a(sa(sv))",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    args.extend([
        unit.to_owned(),
        "fail".to_owned(),
        "3".to_owned(),
        "PIDs".to_owned(),
        "au".to_owned(),
        "1".to_owned(),
        pid.to_string(),
        "CollectMode".to_owned(),
        "s".to_owned(),
        "inactive-or-failed".to_owned(),
        "Description".to_owned(),
        "s".to_owned(),
        format!("ouro-jail supervisor {pid}"),
        "0".to_owned(),
    ]);
    args
}

/// The whole environment the call gets: the bus variables and nothing else,
/// so no secret or knob of the operator's environment reaches it.
///
/// `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` are passed as they are.
/// When both are unset (a `su` or `cron` context), `XDG_RUNTIME_DIR` is set
/// to `default_runtime_dir`, when the caller found one this uid owns, which
/// is where the user's bus lives. The `assume-outside-no-bus` seam replaces
/// all of it with [`UNREACHABLE_BUS`].
#[must_use]
pub fn call_environment(
    bus: Bus,
    session_address: Option<&std::ffi::OsStr>,
    runtime_dir: Option<&std::ffi::OsStr>,
    default_runtime_dir: Option<&Path>,
) -> Vec<(String, std::ffi::OsString)> {
    if bus == Bus::Unreachable {
        return vec![(
            "DBUS_SESSION_BUS_ADDRESS".to_owned(),
            UNREACHABLE_BUS.into(),
        )];
    }
    let mut env = Vec::new();
    if let Some(address) = session_address {
        env.push(("DBUS_SESSION_BUS_ADDRESS".to_owned(), address.to_owned()));
    }
    if let Some(dir) = runtime_dir {
        env.push(("XDG_RUNTIME_DIR".to_owned(), dir.to_owned()));
    }
    if env.is_empty()
        && let Some(dir) = default_runtime_dir
    {
        env.push(("XDG_RUNTIME_DIR".to_owned(), dir.as_os_str().to_owned()));
    }
    env
}

/// The last component of a cgroup path.
fn leaf_of(cgroup: &str) -> Option<&str> {
    cgroup.trim_end_matches('/').rsplit('/').next()
}

/// Decide and, when outside, act: the step, over any [`Host`].
///
/// Returns what happened; never an error, because nothing here may fail the
/// run. `entered` is recorded only once this process is seen inside the
/// delegated subtree in the very unit it asked for: being somewhere else in
/// the subtree (the scope it started in, under the `assume-outside` seam) is
/// not the move.
pub fn decide<H: Host>(host: &mut H, seam: SeamSetting, unit: &str) -> Outcome {
    let applied = seam.applied();
    let start = match host.position() {
        Position::Unreadable(why) => {
            return Outcome::unavailable(Reason::CgroupUnreadable, why, None, None, seam);
        }
        Position::NoSubtree(cgroup) => {
            return Outcome::unavailable(
                Reason::NoDelegatedSubtree,
                "there is no delegated cgroup subtree for this uid (no systemd user manager \
                 owns one), so no user scope can hold this process",
                None,
                Some(cgroup),
                seam,
            );
        }
        Position::Inside(cgroup) if applied.is_none() => {
            return Outcome::already(cgroup, seam);
        }
        Position::Inside(cgroup) | Position::Outside(cgroup) => cgroup,
    };
    // A moved supervisor belongs to the user manager, which stops at the last
    // logout unless it lingers; one left in its session scope survives
    // logout. Trading that for the scope's kill-on-death would turn a rare
    // leak into a common kill, so without lingering the step stays put.
    let linger = if applied == Some(Seam::AssumeOutsideNoLinger) {
        Linger::No
    } else {
        host.lingering()
    };
    match linger {
        Linger::Yes => {}
        Linger::No => {
            return Outcome::unavailable(
                Reason::NoLinger,
                "lingering is off for this user, so the user manager stops when the last \
                 session ends and would take a moved supervisor with it; the supervisor stays \
                 in its session (`loginctl enable-linger` lets it enter a delegated scope)",
                None,
                Some(start),
                seam,
            );
        }
        Linger::Unknown(why) => {
            return Outcome::unavailable(
                Reason::LingerUnknown,
                format!("whether the user manager lingers could not be established ({why})"),
                None,
                Some(start),
                seam,
            );
        }
    }
    let busctl = match applied {
        Some(Seam::AssumeOutsideNoBusctl) => None,
        _ => host.busctl(),
    };
    let Some(busctl) = busctl else {
        return Outcome::unavailable(
            Reason::BusctlMissing,
            format!("no busctl at {}", BUSCTL_CANDIDATES.join(" or ")),
            None,
            Some(start),
            seam,
        );
    };
    let bus = if applied == Some(Seam::AssumeOutsideNoBus) {
        Bus::Unreachable
    } else {
        Bus::Session
    };
    if let Err(failure) = host.request(&busctl, unit, bus) {
        let now = host.position().cgroup().or(Some(start));
        return Outcome::unavailable(failure.reason, failure.detail, Some(unit), now, seam);
    }
    loop {
        let now = host.position();
        if let Position::Inside(cgroup) = &now
            && leaf_of(cgroup) == Some(unit)
        {
            return Outcome {
                state: State::Entered,
                unit: Some(unit.to_owned()),
                reason: None,
                detail: None,
                cgroup: Some(cgroup.clone()),
                seam,
            };
        }
        if host.expired() {
            return Outcome::unavailable(
                Reason::MoveNotObserved,
                format!(
                    "the scope was requested but this process was not seen in it, inside the \
                     delegated subtree, within {} s",
                    BUDGET.as_secs()
                ),
                Some(unit),
                now.cgroup(),
                seam,
            );
        }
        host.pause();
    }
}

// ---------------------------------------------------------------------------
// The Linux host and the process-wide record
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub use linux::{LinuxHost, current, details, enter, recorded};

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;

    use super::{
        BUDGET, BUSCTL_CANDIDATES, Bus, CallFailure, Host, Outcome, Position, Reason, SEAM,
        SeamSetting, busctl_args, call_environment, decide, unit_name,
    };
    use crate::platform::linux::cgroup;
    use crate::platform::linux::clock::Deadline;
    use crate::platform::linux::exec;

    /// How long [`LinuxHost::pause`] waits between two looks.
    const POLL: std::time::Duration = std::time::Duration::from_millis(5);
    /// The longest `busctl` message kept in a record.
    const DETAIL_MAX: usize = 300;

    /// The real host: `/proc/self/cgroup`, the delegated subtree for this
    /// uid, `busctl` as a child with a deadline.
    pub struct LinuxHost {
        uid: u32,
        pid: u32,
        deadline: Deadline,
        candidates: Vec<PathBuf>,
    }

    impl LinuxHost {
        /// A host for this process, with [`BUDGET`] from now.
        #[must_use]
        pub fn new() -> LinuxHost {
            LinuxHost::with_candidates(
                BUSCTL_CANDIDATES.iter().map(PathBuf::from).collect(),
                BUDGET,
            )
        }

        /// A host that looks for `busctl` at `candidates` and has `budget`.
        #[must_use]
        pub fn with_candidates(candidates: Vec<PathBuf>, budget: std::time::Duration) -> LinuxHost {
            LinuxHost {
                // SAFETY: getuid takes no arguments and cannot fail.
                uid: unsafe { libc::getuid() },
                pid: std::process::id(),
                deadline: Deadline::after(budget),
                candidates,
            }
        }

        /// This process's pid, which the request names.
        #[must_use]
        pub fn pid(&self) -> u32 {
            self.pid
        }

        /// `/run/user/<uid>` when it is a directory this uid owns, not a
        /// symlink: where the user's bus lives when the environment does not
        /// say.
        fn default_runtime_dir(&self) -> Option<PathBuf> {
            use std::os::unix::fs::MetadataExt as _;
            let dir = PathBuf::from(format!("/run/user/{}", self.uid));
            let meta = std::fs::symlink_metadata(&dir).ok()?;
            (meta.is_dir() && meta.uid() == self.uid).then_some(dir)
        }
    }

    impl Default for LinuxHost {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Whether `path` is a regular file someone may execute. The call itself
    /// is what establishes that it works.
    fn executable(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }

    /// `text` on one line, at most [`DETAIL_MAX`] bytes.
    fn one_line(text: &str) -> String {
        let mut line = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if line.len() > DETAIL_MAX {
            let mut end = DETAIL_MAX;
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            line.truncate(end);
        }
        line
    }

    /// Where logind records lingering: one empty file per user name.
    const LINGER_DIR: &str = "/var/lib/systemd/linger";

    /// The user name of `uid`, from the password database.
    fn user_name(uid: u32) -> Option<std::ffi::OsString> {
        use std::os::unix::ffi::OsStringExt as _;
        let mut buffer = vec![0_u8; 16 * 1024];
        // SAFETY: `passwd` is a plain C struct; all-zero is a valid value
        // that getpwuid_r overwrites before it is read.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is to a live local, the length is the
        // buffer's own, and getpwuid_r writes only within them.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &raw mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut result,
            )
        };
        if rc != 0 || result.is_null() || entry.pw_name.is_null() {
            return None;
        }
        // SAFETY: getpwuid_r succeeded, so pw_name is a NUL-terminated
        // string inside `buffer`, which is still alive.
        let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) };
        Some(std::ffi::OsString::from_vec(name.to_bytes().to_vec()))
    }

    /// Lingering as logind records it for `uid`.
    pub(super) fn lingering_of(uid: u32, dir: &Path) -> super::Linger {
        let Some(name) = user_name(uid) else {
            return super::Linger::Unknown(format!("uid {uid} has no user name"));
        };
        match std::fs::symlink_metadata(dir.join(&name)) {
            Ok(meta) if meta.is_file() => super::Linger::Yes,
            Ok(_) => super::Linger::Unknown(format!(
                "{} is not a regular file",
                dir.join(&name).display()
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => super::Linger::No,
            Err(error) => super::Linger::Unknown(format!("{}: {error}", dir.display())),
        }
    }

    impl Host for LinuxHost {
        fn lingering(&mut self) -> super::Linger {
            lingering_of(self.uid, Path::new(LINGER_DIR))
        }

        fn position(&mut self) -> Position {
            let own = match cgroup::own_cgroup() {
                Ok(own) => own,
                Err(error) => return Position::Unreadable(format!("/proc/self/cgroup: {error}")),
            };
            let Some(root) = cgroup::delegated_root(self.uid) else {
                return Position::NoSubtree(own);
            };
            let Ok(relative) = root.strip_prefix(cgroup::CGROUP_ROOT) else {
                return Position::NoSubtree(own);
            };
            if cgroup::common_ancestor_ok(&own, &format!("/{}", relative.display())) {
                Position::Inside(own)
            } else {
                Position::Outside(own)
            }
        }

        fn busctl(&mut self) -> Option<PathBuf> {
            self.candidates
                .iter()
                .find(|candidate| executable(candidate))
                .cloned()
        }

        fn request(&mut self, busctl: &Path, unit: &str, bus: Bus) -> Result<(), CallFailure> {
            let mut command = Command::new(busctl);
            command
                .args(busctl_args(unit, self.pid))
                .env_clear()
                .envs(call_environment(
                    bus,
                    std::env::var_os("DBUS_SESSION_BUS_ADDRESS").as_deref(),
                    std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
                    self.default_runtime_dir().as_deref(),
                ))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            // Every descriptor above stdio closes at exec (the operator's
            // control, gate and trace channels among them), and the child
            // dies with this process: a supervisor killed during the call
            // leaves no `busctl` behind.
            exec::FdMap::new().apply(&mut command);
            let child = command.spawn().map_err(|error| CallFailure {
                reason: Reason::SpawnFailed,
                detail: format!("{}: {error}", busctl.display()),
            })?;
            let captured =
                exec::finish_captured(child, self.deadline).map_err(|error| CallFailure {
                    reason: Reason::SpawnFailed,
                    detail: format!("waiting for {}: {error}", busctl.display()),
                })?;
            if captured.timed_out {
                return Err(CallFailure {
                    reason: Reason::CallTimedOut,
                    detail: format!(
                        "{} did not finish within {} s and was killed",
                        busctl.display(),
                        BUDGET.as_secs()
                    ),
                });
            }
            if captured.status.success() {
                return Ok(());
            }
            Err(CallFailure {
                reason: Reason::CallFailed,
                detail: format!(
                    "{} exited with {}: {}",
                    busctl.display(),
                    captured.status,
                    one_line(&captured.stderr)
                ),
            })
        }

        fn expired(&self) -> bool {
            self.deadline.expired()
        }

        fn pause(&mut self) {
            std::thread::sleep(POLL);
        }
    }

    static RECORD: OnceLock<Outcome> = OnceLock::new();

    /// Run the step once for this process and record what it did; later
    /// calls return the record. Call it first, before any thread or other
    /// resource exists: a process moved with threads would move them all,
    /// but one moved after it spawned helpers would leave them behind.
    pub fn enter() -> &'static Outcome {
        RECORD.get_or_init(|| {
            let seam = SeamSetting::from_value(std::env::var_os(SEAM).as_deref());
            let mut host = LinuxHost::new();
            let unit = unit_name(host.pid());
            decide(&mut host, seam, &unit)
        })
    }

    /// The record, when this process ran the step.
    #[must_use]
    pub fn recorded() -> Option<&'static Outcome> {
        RECORD.get()
    }

    /// The record, or, for a process that never ran the step, an
    /// `unavailable` outcome with reason `not_attempted` that says where the
    /// process is now: it is never `already_delegated` or `entered` on a
    /// guess.
    #[must_use]
    pub fn current() -> Outcome {
        if let Some(outcome) = recorded() {
            return outcome.clone();
        }
        let seam = SeamSetting::from_value(std::env::var_os(SEAM).as_deref());
        let now = LinuxHost::new().position();
        Outcome {
            state: super::State::Unavailable,
            unit: None,
            reason: Some(Reason::NotAttempted),
            detail: Some("this process did not run the supervisor scope step".to_owned()),
            cgroup: now.cgroup(),
            seam,
        }
    }

    /// [`current`] as the record's JSON.
    #[must_use]
    pub fn details() -> serde_json::Value {
        current().to_json()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// logind's record: a regular file named for the user lingers; no
        /// file does not; anything else is unknown, and counts as off.
        #[test]
        fn lingering_is_read_from_loginds_record() {
            let uid = unsafe { libc::getuid() };
            let name = user_name(uid).expect("the test's uid has a name");
            let dir = tempfile::tempdir().unwrap();
            assert_eq!(lingering_of(uid, dir.path()), super::super::Linger::No);
            std::fs::write(dir.path().join(&name), b"").unwrap();
            assert_eq!(lingering_of(uid, dir.path()), super::super::Linger::Yes);
            std::fs::remove_file(dir.path().join(&name)).unwrap();
            std::fs::create_dir(dir.path().join(&name)).unwrap();
            assert!(matches!(
                lingering_of(uid, dir.path()),
                super::super::Linger::Unknown(_)
            ));
        }

        #[test]
        fn a_missing_busctl_is_not_found_and_no_path_lookup_happens() {
            let mut host = LinuxHost::with_candidates(
                vec![PathBuf::from("/nonexistent/busctl"), PathBuf::from("/")],
                BUDGET,
            );
            assert_eq!(host.busctl(), None);
        }

        #[test]
        fn details_are_one_bounded_line() {
            let long = "x ".repeat(1000);
            let line = one_line(&format!("first\nsecond\t{long}"));
            assert!(line.starts_with("first second x"));
            assert!(line.len() <= DETAIL_MAX);
            assert!(!line.contains('\n'));
            assert_eq!(one_line(&"é".repeat(400)).len() % 2, 0);
        }

        /// A stand-in `busctl`: a shell script at an absolute path.
        fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
            use std::os::unix::fs::PermissionsExt as _;
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        }

        #[test]
        fn the_call_is_a_child_with_the_bus_environment_no_extra_descriptor_and_null_stdin() {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("seen");
            let busctl = script(
                dir.path(),
                "busctl",
                &format!(
                    "o={out}\n\
                     echo \"pid $$ ppid $PPID\" > $o\n\
                     for a in \"$@\"; do echo \"arg $a\" >> $o; done\n\
                     /usr/bin/tr '\\0' '\\n' < /proc/$$/environ | /usr/bin/sed 's/^/env /' >> $o\n\
                     if [ -e /proc/$$/fd/55 ]; then echo 'fd55 open' >> $o; fi\n\
                     echo \"stdin $(/usr/bin/readlink /proc/$$/fd/0)\" >> $o\n\
                     echo \"stdout $(/usr/bin/readlink /proc/$$/fd/1)\" >> $o\n",
                    out = out.display()
                ),
            );
            // A descriptor this process holds without close-on-exec, at a
            // number no shell uses: the child must not get it.
            let file = std::fs::File::open("/proc/self/status").unwrap();
            // SAFETY: dup2 onto an unused number; closed below.
            let fd = unsafe { libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&file), 55) };
            assert_eq!(fd, 55);
            let mut host = LinuxHost::with_candidates(vec![busctl.clone()], BUDGET);
            let found = host.busctl().expect("the stand-in is executable");
            let unit = unit_name(host.pid());
            let result = host.request(&found, &unit, Bus::Session);
            // SAFETY: the descriptor dup2 made above, closed once.
            unsafe { libc::close(55) };
            assert_eq!(result, Ok(()));
            let seen = std::fs::read_to_string(&out).unwrap();
            let lines: Vec<&str> = seen.lines().collect();
            assert_eq!(
                lines[0].split_whitespace().nth(3),
                Some(host.pid().to_string().as_str()),
                "busctl is this process's child: {seen}"
            );
            assert_ne!(
                lines[0].split_whitespace().nth(1),
                Some(host.pid().to_string().as_str()),
                "the call is a new process, never this one re-executed"
            );
            let args: Vec<String> = lines
                .iter()
                .filter_map(|line| line.strip_prefix("arg "))
                .map(str::to_owned)
                .collect();
            assert_eq!(args, busctl_args(&unit, host.pid()));
            for line in lines.iter().filter_map(|line| line.strip_prefix("env ")) {
                let name = line.split('=').next().unwrap_or_default();
                assert!(
                    ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"].contains(&name),
                    "the call got {line:?}: {seen}"
                );
            }
            assert!(
                !seen.contains("fd55 open"),
                "an inherited descriptor leaked: {seen}"
            );
            assert!(seen.contains("stdin /dev/null"), "{seen}");
            assert!(seen.contains("stdout /dev/null"), "{seen}");
        }

        #[test]
        fn a_failed_call_is_call_failed_with_its_message() {
            let dir = tempfile::tempdir().unwrap();
            let busctl = script(
                dir.path(),
                "busctl",
                "echo 'Failed to connect to bus: No such file or directory' >&2\nexit 1\n",
            );
            let mut host = LinuxHost::with_candidates(vec![busctl.clone()], BUDGET);
            let failure = host
                .request(&busctl, "ouro-jail-1-x.scope", Bus::Session)
                .unwrap_err();
            assert_eq!(failure.reason, Reason::CallFailed);
            assert!(
                failure
                    .detail
                    .ends_with("Failed to connect to bus: No such file or directory"),
                "{failure:?}"
            );
            assert!(failure.detail.contains("exit status: 1"), "{failure:?}");
        }

        #[test]
        fn a_call_that_hangs_is_killed_at_the_budget() {
            let dir = tempfile::tempdir().unwrap();
            let pid_file = dir.path().join("pid");
            let busctl = script(
                dir.path(),
                "busctl",
                &format!("echo $$ > {}\nexec /usr/bin/sleep 30\n", pid_file.display()),
            );
            let budget = std::time::Duration::from_millis(300);
            let mut host = LinuxHost::with_candidates(vec![busctl.clone()], budget);
            let started = std::time::Instant::now();
            let failure = host
                .request(&busctl, "ouro-jail-1-x.scope", Bus::Session)
                .unwrap_err();
            let took = started.elapsed();
            assert_eq!(failure.reason, Reason::CallTimedOut, "{failure:?}");
            assert!(took < std::time::Duration::from_secs(5), "{took:?}");
            let pid = std::fs::read_to_string(&pid_file).unwrap();
            assert!(
                !Path::new(&format!("/proc/{}", pid.trim())).exists(),
                "the hung call was killed and reaped"
            );
            // The whole step shares the budget: nothing is left for a move.
            assert!(host.expired());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DELEGATED: &str = "/user.slice/user-1001.slice/user@1001.service";
    const SESSION: &str = "/user.slice/user-1001.slice/session-3.scope";

    /// A scripted host: `positions` are returned in order (the last one
    /// repeats), `call` is the request's result, and the budget runs out
    /// after `polls` pauses.
    struct Fake {
        positions: Vec<Position>,
        next: usize,
        busctl: Option<PathBuf>,
        call: Result<(), CallFailure>,
        requests: Vec<(PathBuf, String, Bus)>,
        polls: usize,
        paused: usize,
        linger: Linger,
    }

    impl Fake {
        fn new(positions: Vec<Position>) -> Fake {
            Fake {
                positions,
                next: 0,
                busctl: Some(PathBuf::from("/usr/bin/busctl")),
                call: Ok(()),
                requests: Vec::new(),
                polls: 3,
                paused: 0,
                linger: Linger::Yes,
            }
        }
    }

    impl Host for Fake {
        fn position(&mut self) -> Position {
            let at = self.next.min(self.positions.len() - 1);
            self.next += 1;
            self.positions[at].clone()
        }
        fn busctl(&mut self) -> Option<PathBuf> {
            self.busctl.clone()
        }
        fn lingering(&mut self) -> Linger {
            self.linger.clone()
        }
        fn request(&mut self, busctl: &Path, unit: &str, bus: Bus) -> Result<(), CallFailure> {
            self.requests
                .push((busctl.to_owned(), unit.to_owned(), bus));
            self.call.clone()
        }
        fn expired(&self) -> bool {
            self.paused >= self.polls
        }
        fn pause(&mut self) {
            self.paused += 1;
        }
    }

    fn inside(rest: &str) -> Position {
        Position::Inside(format!("{DELEGATED}/{rest}"))
    }

    fn outside() -> Position {
        Position::Outside(SESSION.to_owned())
    }

    const UNIT: &str = "ouro-jail-42-0123456789abcdef.scope";

    /// Without lingering the user manager stops at the last logout and
    /// would take a moved supervisor with it; one left in its session scope
    /// survives logout. So the step asks for no scope then.
    #[test]
    fn without_lingering_no_scope_is_requested() {
        let mut host = Fake::new(vec![outside()]);
        host.linger = Linger::No;
        let outcome = decide(&mut host, SeamSetting::Unset, UNIT);
        assert!(
            host.requests.is_empty(),
            "a scope was requested without lingering"
        );
        assert_eq!(outcome.state, State::Unavailable);
        assert_eq!(outcome.reason, Some(Reason::NoLinger));
        assert_eq!(outcome.cgroup.as_deref(), Some(SESSION));
    }

    /// Lingering that cannot be established counts as off.
    #[test]
    fn unknown_lingering_is_treated_as_off() {
        let mut host = Fake::new(vec![outside()]);
        host.linger = Linger::Unknown("no linger directory".to_owned());
        let outcome = decide(&mut host, SeamSetting::Unset, UNIT);
        assert!(
            host.requests.is_empty(),
            "a scope was requested with unknown lingering"
        );
        assert_eq!(outcome.reason, Some(Reason::LingerUnknown));
    }

    /// An already delegated supervisor needs no lingering check.
    #[test]
    fn already_delegated_ignores_lingering() {
        let mut host = Fake::new(vec![inside("app.slice/run-1.scope")]);
        host.linger = Linger::No;
        let outcome = decide(&mut host, SeamSetting::Unset, UNIT);
        assert_eq!(outcome.state, State::AlreadyDelegated);
    }

    #[test]
    fn already_delegated_takes_no_action() {
        let mut host = Fake::new(vec![inside("app.slice/run-1.scope")]);
        let outcome = decide(&mut host, SeamSetting::Unset, UNIT);
        assert_eq!(outcome.state, State::AlreadyDelegated);
        assert_eq!(outcome.unit, None);
        assert_eq!(outcome.reason, None);
        assert_eq!(
            outcome.cgroup.as_deref(),
            Some(format!("{DELEGATED}/app.slice/run-1.scope").as_str())
        );
        assert!(host.requests.is_empty(), "nothing is asked for");
        assert!(outcome.delegated());
    }

    #[test]
    fn outside_asks_for_the_scope_and_records_it_once_the_move_is_seen() {
        let moved = format!("app.slice/{UNIT}");
        let mut host = Fake::new(vec![outside(), outside(), inside(&moved)]);
        let outcome = decide(&mut host, SeamSetting::Unset, UNIT);
        assert_eq!(outcome.state, State::Entered, "{outcome:?}");
        assert_eq!(outcome.unit.as_deref(), Some(UNIT));
        assert_eq!(outcome.reason, None);
        assert_eq!(
            outcome.cgroup.as_deref(),
            Some(format!("{DELEGATED}/{moved}").as_str())
        );
        assert_eq!(
            host.requests,
            vec![(
                PathBuf::from("/usr/bin/busctl"),
                UNIT.to_owned(),
                Bus::Session
            )]
        );
        assert_eq!(host.paused, 1, "one pause between the two looks");
    }

    #[test]
    fn somewhere_else_in_the_subtree_is_not_the_move() {
        // Under the seam the process starts inside; still being in the
        // scope it started in, or in another scope, is not `entered`.
        let mut host = Fake::new(vec![
            inside("app.slice/run-1.scope"),
            inside("app.slice/run-1.scope"),
            inside("app.slice/ouro-jail-42-ffffffffffffffff.scope"),
        ]);
        let seam = SeamSetting::Applied(Seam::AssumeOutside);
        let outcome = decide(&mut host, seam, UNIT);
        assert_eq!(outcome.state, State::Unavailable, "{outcome:?}");
        assert_eq!(outcome.reason, Some(Reason::MoveNotObserved));
        assert_eq!(outcome.unit.as_deref(), Some(UNIT));
        assert_eq!(host.requests.len(), 1, "the seam takes the outside branch");
        assert_eq!(host.paused, host.polls, "the whole budget was waited");
    }

    #[test]
    fn a_unit_name_that_is_only_a_prefix_of_the_leaf_is_not_the_move() {
        let mut host = Fake::new(vec![
            outside(),
            inside(&format!("app.slice/{UNIT}.evil")),
            inside(&format!("app.slice/x{UNIT}")),
        ]);
        let outcome = decide(&mut host, SeamSetting::Unset, UNIT);
        assert_eq!(outcome.reason, Some(Reason::MoveNotObserved));
    }

    #[test]
    fn the_move_outside_the_subtree_is_not_the_move() {
        // A scope of that name that is not inside the delegated subtree.
        let mut host = Fake::new(vec![
            outside(),
            Position::Outside(format!("/system.slice/{UNIT}")),
        ]);
        let outcome = decide(&mut host, SeamSetting::Unset, UNIT);
        assert_eq!(outcome.reason, Some(Reason::MoveNotObserved));
        assert_eq!(
            outcome.cgroup.as_deref(),
            Some(format!("/system.slice/{UNIT}").as_str()),
            "the record says where the process was last seen"
        );
    }

    #[test]
    fn the_seam_moves_a_process_that_is_already_inside() {
        let moved = format!("app.slice/{UNIT}");
        let mut host = Fake::new(vec![inside("app.slice/run-1.scope"), inside(&moved)]);
        let seam = SeamSetting::Applied(Seam::AssumeOutside);
        let outcome = decide(&mut host, seam, UNIT);
        assert_eq!(outcome.state, State::Entered);
        assert_eq!(outcome.to_json()["test_seam"], "assume-outside");
    }

    #[test]
    fn every_failure_is_unavailable_with_its_reason_never_an_error() {
        let cases: Vec<(&str, Fake, SeamSetting, Reason, bool)> = vec![
            (
                "unreadable cgroup",
                Fake::new(vec![Position::Unreadable("EACCES".into())]),
                SeamSetting::Unset,
                Reason::CgroupUnreadable,
                false,
            ),
            (
                "no delegated subtree",
                Fake::new(vec![Position::NoSubtree(SESSION.into())]),
                SeamSetting::Unset,
                Reason::NoDelegatedSubtree,
                false,
            ),
            (
                "no delegated subtree under the seam",
                Fake::new(vec![Position::NoSubtree(SESSION.into())]),
                SeamSetting::Applied(Seam::AssumeOutside),
                Reason::NoDelegatedSubtree,
                false,
            ),
            (
                "no busctl",
                Fake {
                    busctl: None,
                    ..Fake::new(vec![outside()])
                },
                SeamSetting::Unset,
                Reason::BusctlMissing,
                false,
            ),
            (
                "busctl hidden by the seam",
                Fake::new(vec![inside("app.slice/run-1.scope")]),
                SeamSetting::Applied(Seam::AssumeOutsideNoBusctl),
                Reason::BusctlMissing,
                false,
            ),
            (
                "spawn failed",
                Fake {
                    call: Err(CallFailure {
                        reason: Reason::SpawnFailed,
                        detail: "ENOEXEC".into(),
                    }),
                    ..Fake::new(vec![outside()])
                },
                SeamSetting::Unset,
                Reason::SpawnFailed,
                true,
            ),
            (
                "call failed",
                Fake {
                    call: Err(CallFailure {
                        reason: Reason::CallFailed,
                        detail: "exit status: 1: Failed to connect to bus".into(),
                    }),
                    ..Fake::new(vec![outside()])
                },
                SeamSetting::Unset,
                Reason::CallFailed,
                true,
            ),
            (
                "call timed out",
                Fake {
                    call: Err(CallFailure {
                        reason: Reason::CallTimedOut,
                        detail: "killed".into(),
                    }),
                    ..Fake::new(vec![outside()])
                },
                SeamSetting::Unset,
                Reason::CallTimedOut,
                true,
            ),
            (
                "move never seen",
                Fake::new(vec![outside()]),
                SeamSetting::Unset,
                Reason::MoveNotObserved,
                true,
            ),
        ];
        for (name, mut host, seam, reason, requested) in cases {
            let outcome = decide(&mut host, seam, UNIT);
            assert_eq!(outcome.state, State::Unavailable, "{name}: {outcome:?}");
            assert_eq!(outcome.reason, Some(reason), "{name}");
            assert!(!outcome.delegated(), "{name}");
            assert!(outcome.detail.is_some(), "{name}: a reason is recorded");
            assert_eq!(!host.requests.is_empty(), requested, "{name}");
            // The unit is named exactly when one was asked for.
            assert_eq!(outcome.unit.is_some(), requested, "{name}");
            let json = outcome.to_json();
            assert_eq!(json["state"], "unavailable", "{name}");
            assert_eq!(json["reason_code"], reason.code(), "{name}");
        }
    }

    #[test]
    fn the_unreachable_bus_seam_reaches_the_request() {
        let mut host = Fake {
            call: Err(CallFailure {
                reason: Reason::CallFailed,
                detail: "no bus".into(),
            }),
            ..Fake::new(vec![inside("app.slice/run-1.scope")])
        };
        let outcome = decide(
            &mut host,
            SeamSetting::Applied(Seam::AssumeOutsideNoBus),
            UNIT,
        );
        assert_eq!(outcome.reason, Some(Reason::CallFailed));
        assert_eq!(host.requests[0].2, Bus::Unreachable);
    }

    #[test]
    fn only_the_exact_seam_values_apply() {
        use std::ffi::OsStr;
        assert_eq!(SeamSetting::from_value(None), SeamSetting::Unset);
        for seam in [
            Seam::AssumeOutside,
            Seam::AssumeOutsideNoBusctl,
            Seam::AssumeOutsideNoBus,
        ] {
            assert_eq!(
                SeamSetting::from_value(Some(OsStr::new(seam.as_str()))),
                SeamSetting::Applied(seam)
            );
        }
        for ignored in [
            "",
            "1",
            "Assume-Outside",
            " assume-outside",
            "assume-outside ",
            "assume-inside",
            "assume-outside-no",
        ] {
            assert_eq!(
                SeamSetting::from_value(Some(OsStr::new(ignored))),
                SeamSetting::Ignored,
                "{ignored:?}"
            );
        }
        use std::os::unix::ffi::OsStrExt as _;
        assert_eq!(
            SeamSetting::from_value(Some(OsStr::from_bytes(b"assume-outside\xff"))),
            SeamSetting::Ignored
        );
        // An ignored seam is the unset behaviour, and says so in the record.
        let mut host = Fake::new(vec![inside("app.slice/run-1.scope")]);
        let outcome = decide(&mut host, SeamSetting::Ignored, UNIT);
        assert_eq!(outcome.state, State::AlreadyDelegated);
        assert!(host.requests.is_empty());
        let json = outcome.to_json();
        assert!(
            json.get("test_seam")
                .is_some_and(serde_json::Value::is_null)
        );
    }

    #[test]
    fn the_record_has_the_documented_shape() {
        let outcome = Outcome {
            state: State::Entered,
            unit: Some(UNIT.to_owned()),
            reason: None,
            detail: None,
            cgroup: Some(format!("{DELEGATED}/app.slice/{UNIT}")),
            seam: SeamSetting::Unset,
        };
        assert_eq!(
            outcome.to_json(),
            serde_json::json!({
                "state": "entered",
                "unit": UNIT,
                "reason_code": null,
                "reason": null,
                "cgroup": format!("{DELEGATED}/app.slice/{UNIT}"),
            })
        );
        assert_eq!(
            outcome.summary(),
            format!("entered {UNIT} cgroup={DELEGATED}/app.slice/{UNIT}")
        );
        for (state, text) in [
            (State::AlreadyDelegated, "already_delegated"),
            (State::Entered, "entered"),
            (State::Unavailable, "unavailable"),
        ] {
            assert_eq!(state.as_str(), text);
        }
    }

    #[test]
    fn unit_names_are_valid_distinct_and_name_the_pid() {
        let a = unit_name(4_194_304);
        let b = unit_name(4_194_304);
        assert_ne!(a, b);
        let token = a
            .strip_prefix("ouro-jail-4194304-")
            .and_then(|rest| rest.strip_suffix(".scope"))
            .expect("ouro-jail-<pid>-<token>.scope");
        assert_eq!(token.len(), 16);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        // systemd's unit-name alphabet, and well under its 255-byte limit.
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || ":-_.\\".contains(c))
        );
        assert!(a.len() < 64);
    }

    #[test]
    fn the_call_starts_a_transient_scope_holding_the_pid() {
        let args = busctl_args(UNIT, 42);
        assert_eq!(
            args,
            [
                "--user",
                "--timeout=2",
                "call",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "StartTransientUnit",
                "ssa(sv)a(sa(sv))",
                UNIT,
                "fail",
                "3",
                "PIDs",
                "au",
                "1",
                "42",
                "CollectMode",
                "s",
                "inactive-or-failed",
                "Description",
                "s",
                "ouro-jail supervisor 42",
                "0",
            ]
        );
    }

    #[test]
    fn the_call_gets_the_bus_variables_and_nothing_else() {
        use std::ffi::{OsStr, OsString};
        let address = OsStr::new("unix:path=/run/user/1001/bus");
        let runtime = OsStr::new("/run/user/1001");
        let fallback = Path::new("/run/user/1001");
        let pairs = |env: Vec<(String, OsString)>| -> Vec<(String, String)> {
            env.into_iter()
                .map(|(name, value)| (name, value.to_string_lossy().into_owned()))
                .collect()
        };
        assert_eq!(
            pairs(call_environment(
                Bus::Session,
                Some(address),
                Some(runtime),
                Some(fallback)
            )),
            vec![
                (
                    "DBUS_SESSION_BUS_ADDRESS".to_owned(),
                    "unix:path=/run/user/1001/bus".to_owned()
                ),
                ("XDG_RUNTIME_DIR".to_owned(), "/run/user/1001".to_owned()),
            ]
        );
        // Neither set: the runtime directory this uid owns, when there is one.
        assert_eq!(
            pairs(call_environment(Bus::Session, None, None, Some(fallback))),
            vec![("XDG_RUNTIME_DIR".to_owned(), "/run/user/1001".to_owned())]
        );
        assert!(call_environment(Bus::Session, None, None, None).is_empty());
        // One set: it is used as it is, and no default is added.
        assert_eq!(
            pairs(call_environment(
                Bus::Session,
                None,
                Some(OsStr::new("/elsewhere")),
                Some(fallback)
            )),
            vec![("XDG_RUNTIME_DIR".to_owned(), "/elsewhere".to_owned())]
        );
        // The seam replaces everything with a bus that cannot be reached.
        assert_eq!(
            pairs(call_environment(
                Bus::Unreachable,
                Some(address),
                Some(runtime),
                Some(fallback)
            )),
            vec![(
                "DBUS_SESSION_BUS_ADDRESS".to_owned(),
                UNREACHABLE_BUS.to_owned()
            )]
        );
    }
}
