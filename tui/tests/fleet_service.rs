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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

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
            },
            log,
            state,
        }
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
    fs::write(path, text).expect("a written fake");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("an executable fake");
}

fn launchctl_script(log: &Path, state: &Path) -> String {
    format!(
        r#"#!/bin/sh
printf 'launchctl %s\n' "$*" >> '{log}'
state='{state}'
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
      gui/*/*) rm -f "$state/loaded"; exit 0 ;;
      *) echo "unexpected bootout target: $2" >&2; exit 64 ;;
    esac ;;
  bootstrap)
    case "$2" in
      gui/*/*) echo "bootstrap takes a domain, not a service target: $2" >&2; exit 64 ;;
      gui/*) ;;
      *) echo "unexpected bootstrap domain: $2" >&2; exit 64 ;;
    esac
    if [ ! -f "$3" ]; then echo "no plist at $3" >&2; exit 65; fi
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
        log = log.display(),
        state = state.display()
    )
}

fn systemctl_script(log: &Path, state: &Path) -> String {
    format!(
        r#"#!/bin/sh
printf 'systemctl %s\n' "$*" >> '{log}'
state='{state}'
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
    touch "$state/enabled"; exit 0 ;;
  disable)
    if [ "$2" != "--now" ]; then echo "unexpected disable: $*" >&2; exit 64; fi
    rm -f "$state/enabled"; exit 0 ;;
  start) touch "$state/enabled"; exit 0 ;;
  *) echo "unexpected systemctl verb: $*" >&2; exit 64 ;;
esac
"#,
        log = log.display(),
        state = state.display()
    )
}

fn loginctl_script(log: &Path, state: &Path) -> String {
    format!(
        r#"#!/bin/sh
printf 'loginctl %s\n' "$*" >> '{log}'
state='{state}'
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
        log = log.display(),
        state = state.display()
    )
}

// -------------------------------------------------------------------------------- plans

fn plan_for(platform: Platform, root: &Path, data_dir: &Path) -> Plan {
    let home = root.join("home");
    fs::create_dir_all(&home).expect("a home directory");
    Plan {
        platform,
        data_dir: data_dir.to_path_buf(),
        executable: PathBuf::from(OURO),
        home: home.clone(),
        config_home: home.join(".config"),
        uid: 501,
        user: "tester".to_string(),
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
            "launchctl print gui/501".to_string(),
            format!("launchctl bootout gui/501/{label}"),
            format!("launchctl bootstrap gui/501 {}", plan.unit_path().display()),
            format!("launchctl print gui/501/{label}"),
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

    // Installing twice is the same install: the unit is replaced and re-bootstrapped,
    // and nothing accumulates.
    fakes.forget_calls();
    let again = fleet_service::install(&plan, &fakes.programs, false).expect("a second install");
    assert_eq!(again.ownership, Ownership::Ours);
    assert_eq!(fs::read_dir(agents).expect("a listing").count(), 1);
    assert_eq!(fakes.calls().len(), 4);
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
    assert_eq!(fakes.calls(), vec!["launchctl print gui/501".to_string()]);

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
            "launchctl print gui/501".to_string(),
            format!("launchctl bootout gui/501/{label}"),
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
            "launchctl print gui/501".to_string(),
            format!("launchctl bootout gui/501/{label}"),
            format!("launchctl print gui/501/{label}"),
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
            "launchctl print gui/501".to_string(),
            format!("launchctl kickstart gui/501/{label}"),
            format!("launchctl print gui/501/{label}"),
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
    fn start(data_dir: &Path, fakes: &Fakes) -> Self {
        let mut child = Command::new(OURO)
            .args(["fleet", "helper"])
            .env("OUROBOROS_DATA_DIR", data_dir)
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
    let mut helper = Helper::start(&data_dir, &fakes);

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

    let reply = helper.ask(json!({ "op": "service", "action": "remove" }));
    assert_eq!(reply["ok"], json!(true), "{reply}");
    assert_eq!(reply["report"]["installed"], json!(false));

    // The action is required, and a request that omits it is a bad request rather than
    // a default.
    let reply = helper.ask(json!({ "op": "service" }));
    assert_eq!(reply["ok"], json!(false));

    // Every call reached the fake rather than this machine's real service manager.
    assert!(
        fakes
            .calls()
            .iter()
            .any(|call| call.starts_with("launchctl bootstrap")),
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
        peer.hello_with_token(&token, &["hello", "runtime.shutdown"])
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
            peer.hello_with_token(&token, &["hello", "runtime.shutdown"])
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
    let status = child.wait().expect("a stoppable service-run");
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
/// asks the real `launchctl print` whether it is there, and removes it. Every exit path
/// runs the same cleanup, including a panic, so a failure cannot leave a LaunchAgent
/// behind.
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
    // Deliberately an address no interface here holds: the agent launchd starts sits in
    // `service-run`'s network wait for its whole life, so this test can never bring a
    // BEAM up on the operator's machine — not even when the binary under test was built
    // with an embedded release. It is still a real supervised process, which is what
    // `launchctl print` is being asked about.
    let data_dir = data_dir_with_profile(&root, "studio", "10.254.254.254");
    let plan = Plan {
        platform: Platform::MacOs,
        data_dir: data_dir.clone(),
        executable: PathBuf::from(OURO),
        home: dirs::home_dir().expect("a home directory"),
        config_home: root.join("config"),
        uid: unsafe { libc::geteuid() },
        user: std::env::var("USER").unwrap_or_else(|_| "tester".to_string()),
    };
    let programs = Programs::default();
    let unit = plan.unit_path();
    let label = plan.label();

    // The label is derived from a scratch data directory that has never existed before,
    // so nothing of this machine's own can be behind it.
    assert!(
        !unit.exists(),
        "{} already exists; refusing to touch it",
        unit.display()
    );

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
            printed.contains(&plan.unit_path().display().to_string()),
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
}
