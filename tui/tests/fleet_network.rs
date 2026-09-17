//! `ouro fleet protocol|devices|status|doctor` as a person and a script actually run them.
//!
//! The unit tests in `src/fleet_network.rs` hold the classifier to each fixture. This file
//! runs the real binary and asserts on what it printed and what it exited with, because a
//! classifier that is perfect behind a command that never reaches it is exactly the
//! failure this file exists to catch.
//!
//! # The client is always a fake
//!
//! Every case below points `$OUROBOROS_TAILSCALE` at a shell script in a private
//! directory that prints one of the sanitized fixtures under `tests/fixtures/tailscale/`,
//! optionally the version warning on stderr, and exits with a chosen status — or sleeps
//! past the adapter's deadline. Nothing here runs the real `tailscale`, reads the real
//! tailnet, or changes any network state.
//!
//! The fixtures were sanitized from one real capture. The client on that machine reported
//! version `1.102.2-teb67e5dcb` and its daemon `1.102.1-t8ebe8f7c3-gda6192991`, which is
//! why every invocation of that CLI prints a version-mismatch warning on stderr before
//! its JSON — the case [`the_version_warning_before_the_json_is_not_a_failure`] covers.
//!
//! # No runtime is started
//!
//! Every command here is read-only. The data directory each one is given is private, is
//! either empty or carries a profile written by `ouro fleet create`, and is checked
//! afterwards to be sure discovery wrote nothing into it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const OURO: &str = env!("CARGO_BIN_EXE_ouro");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tailscale");

// ------------------------------------------------------------------------- scaffolding

/// A private directory that removes itself, so no case leaves a data dir behind.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ouro-fleet-network-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("a clock after 1970")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("a private scratch directory");
        // `ouro` refuses a data directory anyone else can read.
        set_mode(&path, 0o700);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn data_dir(&self) -> PathBuf {
        let dir = self.0.join("data");
        if !dir.exists() {
            std::fs::create_dir_all(&dir).expect("a private data directory");
            set_mode(&dir, 0o700);
        }
        dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("setting a private mode");
}

/// A fake `tailscale`: prints a fixture, optionally the real client's stderr warning, and
/// exits with a chosen status.
fn fake_client(scratch: &Scratch, fixture: &str, warn: bool, status: i32) -> PathBuf {
    let warning = if warn {
        format!("cat {FIXTURES}/version-warning.stderr >&2\n")
    } else {
        String::new()
    };
    let body = format!("#!/bin/sh\n{warning}cat {FIXTURES}/{fixture}\nexit {status}\n");
    write_script(scratch, "tailscale", &body)
}

fn write_script(scratch: &Scratch, name: &str, body: &str) -> PathBuf {
    let path = scratch.path().join(name);
    std::fs::write(&path, body).expect("writing a fake client");
    set_mode(&path, 0o755);
    path
}

/// Runs `ouro fleet ...` with a private data directory and a named client.
fn ouro(scratch: &Scratch, client: Option<&Path>, args: &[&str]) -> Output {
    ouro_at(scratch, &scratch.data_dir(), client, args)
}

/// The same, with the data directory named explicitly — including one that does not
/// exist, which is what proves a command did not create it.
fn ouro_at(scratch: &Scratch, data_dir: &Path, client: Option<&Path>, args: &[&str]) -> Output {
    let mut command = Command::new(OURO);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", scratch.path())
        .env("OUROBOROS_DATA_DIR", data_dir)
        .env("OUROBOROS_DIST", "none");
    match client {
        // An absolute path to a client that is not there is how a case says "no client
        // is installed" without depending on what this machine happens to have.
        Some(path) => command.env("OUROBOROS_TAILSCALE", path),
        None => command.env("OUROBOROS_TAILSCALE", scratch.path().join("no-such-client")),
    };
    command.output().expect("running ouro")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn parse(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "`ouro` must print JSON: {error}\nstdout: {}\nstderr: {}",
            stdout(output),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Gives the scratch data directory a fleet profile, on loopback ports no lab uses.
///
/// The ledger above never hands one port out twice, but a port is released before
/// `fleet create` binds it, and another test's transient port-0 bind (a bindability
/// probe, a fake client) can take it in that window. That is a harness race, not a
/// property of the code under test, so an "already in use" refusal is retried with
/// fresh ports a bounded number of times; any other refusal fails the test at once.
fn create_fleet(scratch: &Scratch, machine: &str) {
    let mut last = String::new();
    for _attempt in 0..5 {
        let ports = ephemeral_ports();
        let output = ouro(
            scratch,
            None,
            &[
                "fleet",
                "create",
                "--machine",
                machine,
                "--host",
                "127.0.0.1",
                "--gateway-port",
                &ports.0.to_string(),
                "--dist-port",
                &ports.1.to_string(),
            ],
        );
        if output.status.success() {
            return;
        }
        last = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            last.contains("already in use"),
            "`ouro fleet create` must succeed: {last}"
        );
    }
    panic!("`ouro fleet create` kept losing its ports to a concurrent bind: {last}");
}

/// Two distinct free loopback ports. Fleet tests never touch the production port spaces;
/// this is the integration-test form of `fleet::ephemeral_ports`, which is crate private.
///
/// The handed-out set is remembered for the life of the process. `cargo test` runs these
/// cases on several threads, and the OS will happily assign one freed ephemeral port to
/// two of them within milliseconds of each other — which is a `fleet create` failing in
/// whichever case lost, days after the change that is blamed for it.
fn ephemeral_ports() -> (u16, u16) {
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::{Mutex, OnceLock};

    static TAKEN: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let taken = TAKEN.get_or_init(|| Mutex::new(HashSet::new()));
    let mut taken = taken.lock().expect("an uncontended port ledger");

    let mut held = Vec::new();
    let mut ports = Vec::new();
    while ports.len() < 2 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free port");
        let port = listener.local_addr().expect("a bound address").port();
        held.push(listener);
        // The production dist range, the derived EPMD space and the derived gateway
        // space, all of which a live same-host lab legitimately occupies.
        if port != 4369
            && port != 65_358
            && !(4370..=4380).contains(&port)
            && !(4_400..5_400).contains(&port)
            && !(49_700..50_700).contains(&port)
            && taken.insert(port)
        {
            ports.push(port);
        }
    }
    (ports[0], ports[1])
}

/// Everything a command is allowed to have left behind, which for the read-only ones is
/// nothing.
///
/// Directories count. An earlier version of this walked files only, which meant a command
/// that *created a whole data directory* passed a test named for not writing anything.
fn unchanged(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, into: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            into.push(path.clone());
            if path.is_dir() {
                walk(&path, into);
            }
        }
    }
    let mut paths = vec![root.to_path_buf()];
    if !root.exists() {
        paths.clear();
    }
    walk(root, &mut paths);
    paths.sort();
    paths
}

// ------------------------------------------------------------------ the protocol command

#[test]
fn fleet_protocol_prints_one_revision_in_both_forms() {
    let scratch = Scratch::new("protocol");
    let bare = ouro(&scratch, None, &["fleet", "protocol"]);
    assert!(bare.status.success());
    assert_eq!(
        stdout(&bare).trim(),
        "5",
        "the human form stays a bare number that a script can read"
    );

    let json = ouro(&scratch, None, &["fleet", "protocol", "--json"]);
    assert!(json.status.success());
    let value = parse(&json);
    assert_eq!(value["fleet_protocol_revision"], 5);
    assert_eq!(value["ouroboros_version"], env!("CARGO_PKG_VERSION"));
    assert!(!value["os"].as_str().expect("an os").is_empty());
    assert!(!value["arch"].as_str().expect("an arch").is_empty());
    assert_eq!(
        value["embedded_release"], false,
        "a `cargo test` build carries no release"
    );
    assert!(
        value["otp_release"].is_null() && value["elixir_version"].is_null(),
        "a build with no release reports unknown rather than guessing a peer's OTP"
    );
}

/// The command's whole point is that an onboarding preflight can call it before there is
/// any Ouroboros state. Creating that state to answer the question is not answering it.
#[test]
fn fleet_protocol_answers_without_creating_or_requiring_any_state() {
    let scratch = Scratch::new("protocol-inert");

    // A data directory that does not exist must still not exist afterwards.
    let absent = scratch.path().join("never-created");
    for args in [
        vec!["fleet", "protocol"],
        vec!["fleet", "protocol", "--json"],
    ] {
        let output = ouro_at(&scratch, &absent, None, &args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !absent.exists(),
            "{args:?} created {} just to print a number",
            absent.display()
        );
    }

    // And a data directory that exists but is unusable must not stop it answering: the
    // compatibility question precedes the state, so it cannot depend on it.
    let unusable = scratch.path().join("unusable");
    std::fs::write(&unusable, "this is a file, not a directory").expect("writing the trap");
    let output = ouro_at(&scratch, &unusable, None, &["fleet", "protocol", "--json"]);
    assert!(
        output.status.success(),
        "an unusable data directory must not stop `fleet protocol`: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(parse(&output)["fleet_protocol_revision"], 5);

    // An existing directory is left exactly as it was found.
    let before = unchanged(&scratch.data_dir());
    let output = ouro(&scratch, None, &["fleet", "protocol", "--json"]);
    assert!(output.status.success());
    assert_eq!(
        unchanged(&scratch.data_dir()),
        before,
        "`fleet protocol` wrote into the data dir"
    );
}

// -------------------------------------------------------------------- the devices command

#[test]
fn fleet_devices_lists_peers_without_claiming_anything_about_their_installations() {
    let scratch = Scratch::new("devices");
    let client = fake_client(&scratch, "running-with-peers.json", true, 0);
    let output = ouro(&scratch, Some(&client), &["fleet", "devices"]);
    assert!(output.status.success(), "a read-only listing succeeds");

    let text = stdout(&output);
    assert!(text.contains("Fleet devices"));
    assert!(text.contains("Available on this network"));
    assert!(text.contains("build-linux"));
    assert!(
        text.contains("not inspected yet · deploy Ouroboros"),
        "a discovered peer's Ouroboros state is unknown until it is inspected: {text}"
    );
    assert!(
        !text.to_lowercase().contains("uninstalled"),
        "nothing here has inspected a peer: {text}"
    );
    assert!(
        !text.contains("discovered_installation_unknown"),
        "the snake_case code is the --json contract, not a terminal column: {text}"
    );
    assert!(text.contains("no device was inspected"));
}

#[test]
fn fleet_devices_json_carries_stable_codes_and_null_for_unknown_facts() {
    let scratch = Scratch::new("devices-json");
    let client = fake_client(&scratch, "running-with-peers.json", true, 0);
    let output = ouro(&scratch, Some(&client), &["fleet", "devices", "--json"]);
    assert!(output.status.success());

    let value = parse(&output);
    assert_eq!(value["discovery"]["code"], "ok");
    assert_eq!(value["discovery"]["visible_peers"], 4);
    assert_eq!(value["fleet_protocol_revision"], 5);

    let rows = value["devices"].as_array().expect("an array of devices");
    let state = |name: &str| -> String {
        rows.iter()
            .find(|row| row["name"] == name)
            .unwrap_or_else(|| panic!("a row for {name} in {rows:#?}"))["state"]
            .as_str()
            .expect("a state code")
            .to_string()
    };
    assert_eq!(state("build-linux"), "discovered_installation_unknown");
    assert_eq!(state("old-pi"), "peer_offline");
    assert_eq!(state("pocket-phone"), "unsupported_platform");
    assert_eq!(state("ipv6-only-box"), "no_usable_ipv4");
    assert_eq!(
        rows[0]["state"], "this_device_without_profile",
        "the machine running the command has no fleet profile in this case"
    );

    let phone = rows
        .iter()
        .find(|row| row["name"] == "pocket-phone")
        .expect("the iOS row");
    assert_eq!(phone["path"], "unknown");
    assert!(
        phone["last_seen"].is_null(),
        "a connected peer has no last-seen time"
    );
}

#[test]
fn fleet_devices_keeps_known_members_when_the_client_cannot_answer() {
    let scratch = Scratch::new("devices-blind");
    create_fleet(&scratch, "studio");
    let add = ouro(
        &scratch,
        None,
        &["fleet", "members", "add", "attic", "--host", "100.64.12.77"],
    );
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );

    let client = fake_client(&scratch, "stopped.json", true, 0);
    let output = ouro(&scratch, Some(&client), &["fleet", "devices", "--json"]);
    assert!(output.status.success());

    let value = parse(&output);
    assert_eq!(value["discovery"]["code"], "unavailable");
    assert_eq!(value["discovery"]["reason"], "backend_stopped");
    let rows = value["devices"].as_array().expect("devices");
    assert_eq!(rows[0]["state"], "this_device");
    assert_eq!(rows[0]["name"], "studio");
    let attic = rows
        .iter()
        .find(|row| row["name"] == "attic")
        .expect("the roster member survives a blind client");
    assert_eq!(attic["state"], "fleet_member_not_visible");
    assert!(
        attic["online"].is_null(),
        "not visible is not the same fact as powered off"
    );
}

/// Every discovery failure the proposal names, through the real command.
#[test]
fn every_discovery_failure_state_reaches_the_command_distinctly() {
    let scratch = Scratch::new("states");

    let missing = ouro(&scratch, None, &["fleet", "devices", "--json"]);
    assert!(missing.status.success());
    assert_eq!(parse(&missing)["discovery"]["code"], "client_missing");

    for (fixture, code, reason) in [
        ("needs-login.json", "signed_out", Value::Null),
        ("running-needs-reauth.json", "signed_out", Value::Null),
        ("stopped.json", "unavailable", "backend_stopped".into()),
        ("missing-self.json", "unavailable", "missing_field".into()),
        ("no-peers.json", "no_visible_peers", Value::Null),
        ("running-with-peers.json", "ok", Value::Null),
        ("headscale-running.json", "ok", Value::Null),
    ] {
        let client = fake_client(&scratch, fixture, true, 0);
        let output = ouro(&scratch, Some(&client), &["fleet", "devices", "--json"]);
        assert!(output.status.success(), "{fixture} must still list devices");
        let value = parse(&output);
        assert_eq!(value["discovery"]["code"], code, "{fixture}");
        assert_eq!(value["discovery"]["reason"], reason, "{fixture}");
    }

    // A refusal from the local API is its own state, not a generic failure.
    let denied = write_script(
        &scratch,
        "denied",
        "#!/bin/sh\nprintf 'Access denied: not permitted\\n' >&2\nexit 1\n",
    );
    let output = ouro(&scratch, Some(&denied), &["fleet", "devices", "--json"]);
    let value = parse(&output);
    assert_eq!(value["discovery"]["code"], "permission_denied");

    // And a client that never answers is a deadline, not a hang.
    let slow = write_script(&scratch, "slow", "#!/bin/sh\nsleep 60\n");
    let started = std::time::Instant::now();
    let output = ouro(&scratch, Some(&slow), &["fleet", "devices", "--json"]);
    let value = parse(&output);
    assert_eq!(value["discovery"]["code"], "unavailable");
    assert_eq!(value["discovery"]["reason"], "timeout");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "the adapter's five second deadline bounds the command"
    );
}

/// A relative `$OUROBOROS_TAILSCALE` would make the working directory decide which
/// program this machine runs as its network client.
///
/// `./tailscale` is the spelling that matters: a bare `tailscale` is searched on `$PATH`
/// by the OS and would fail to start anyway, but a name with a slash in it is resolved
/// against the current directory — so a script dropped into a repository somebody is
/// standing in would be executed. Both spellings are checked, and the one that would
/// actually run something is checked by whether it ran.
#[test]
fn a_relative_client_override_is_never_executed() {
    let scratch = Scratch::new("relative-client");
    let flag = scratch.path().join("it-ran");
    write_script(
        &scratch,
        "tailscale",
        &format!(
            "#!/bin/sh\nprintf ran > {}\ncat {FIXTURES}/running-with-peers.json\n",
            flag.display()
        ),
    );

    for spelling in ["./tailscale", "tailscale"] {
        let mut command = Command::new(OURO);
        command
            .args(["fleet", "devices", "--json"])
            .current_dir(scratch.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", scratch.path())
            .env("OUROBOROS_DATA_DIR", scratch.data_dir())
            .env("OUROBOROS_DIST", "none")
            .env("OUROBOROS_TAILSCALE", spelling);
        let output = command.output().expect("running ouro");

        assert!(output.status.success());
        assert_eq!(
            parse(&output)["discovery"]["code"],
            "client_missing",
            "`{spelling}` names no client this build will run"
        );
        assert!(
            !flag.exists(),
            "`{spelling}` executed a program in the working directory as the network client"
        );
    }
}

/// The real client prints a client/daemon version warning on stderr before every command.
#[test]
fn the_version_warning_before_the_json_is_not_a_failure() {
    let scratch = Scratch::new("warning");
    let client = fake_client(&scratch, "running-with-peers.json", true, 0);
    let output = ouro(&scratch, Some(&client), &["fleet", "devices", "--json"]);
    assert_eq!(parse(&output)["discovery"]["code"], "ok");

    let quiet = fake_client(&scratch, "running-with-peers.json", false, 0);
    let output = ouro(&scratch, Some(&quiet), &["fleet", "devices", "--json"]);
    assert_eq!(
        parse(&output)["discovery"]["code"],
        "ok",
        "the same JSON reads the same with and without the warning"
    );
}

/// The URL in `AuthURL` is a credential: whoever opens it joins a device to the tailnet.
#[test]
fn a_login_url_in_the_document_never_reaches_any_output() {
    let scratch = Scratch::new("signed-out");
    let client = fake_client(&scratch, "needs-login.json", true, 0);
    for args in [
        vec!["fleet", "devices"],
        vec!["fleet", "devices", "--json"],
        vec!["fleet", "doctor"],
        vec!["fleet", "doctor", "--json"],
        vec!["fleet", "status", "--json"],
    ] {
        let output = ouro(&scratch, Some(&client), &args);
        let printed = format!(
            "{}{}",
            stdout(&output),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !printed.contains("login.example") && !printed.contains("0123456789abcdef"),
            "a login URL is a credential: {args:?} printed {printed}"
        );
        assert!(
            printed.contains("signed out") || printed.contains("signed_out"),
            "the state is still named: {args:?} printed {printed}"
        );
    }
}

/// HIGH-2. The same credential arrives a second way, and this one is not in a field this
/// build chose to read: `tailscale` prints `To authenticate, visit: <url>` on **stderr**
/// and exits non-zero when a node key has expired. That line becomes the `detail` an
/// operator pastes into a ticket.
#[test]
fn an_authentication_url_on_the_clients_stderr_never_reaches_any_output() {
    let scratch = Scratch::new("auth-url");
    const URL: &str = "https://login.example/a/0123456789abcdef";

    // Both the one-line form and the indented multi-line form the CLI uses.
    for body in [
        format!("#!/bin/sh\nprintf 'To authenticate, visit: {URL}\\n' >&2\nexit 1\n"),
        format!("#!/bin/sh\nprintf 'To authenticate, visit:\\n\\n\\t{URL}\\n\\n' >&2\nexit 1\n"),
    ] {
        let client = write_script(&scratch, "expired", &body);
        for args in [
            vec!["fleet", "devices"],
            vec!["fleet", "devices", "--json"],
            vec!["fleet", "doctor"],
            vec!["fleet", "doctor", "--json"],
        ] {
            let output = ouro(&scratch, Some(&client), &args);
            let printed = format!(
                "{}{}",
                stdout(&output),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !printed.contains("login.example") && !printed.contains("0123456789abcdef"),
                "{args:?} printed the client's authentication URL: {printed}"
            );
        }
    }

    // And the third way: `tailscale ping` prints it too, on the route probe's path.
    create_fleet(&scratch, "studio");
    let pinger = write_script(
        &scratch,
        "expired-ping",
        &format!(
            "#!/bin/sh\ncase \"$1\" in\n\
             status) cat {FIXTURES}/running-with-peers.json ;;\n\
             ping) printf 'To authenticate, visit: {URL}\\n' >&2; exit 1 ;;\n\
             esac\n"
        ),
    );
    for args in [
        vec!["fleet", "doctor", "--json", "--peer", "build-linux"],
        vec!["fleet", "doctor", "--peer", "build-linux"],
    ] {
        let output = ouro(&scratch, Some(&pinger), &args);
        let printed = format!(
            "{}{}",
            stdout(&output),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !printed.contains("login.example") && !printed.contains("0123456789abcdef"),
            "{args:?} printed the client's authentication URL: {printed}"
        );
        assert!(
            printed.contains("<redacted url>"),
            "and the operator is still told something happened: {printed}"
        );
    }
}

/// HIGH-1. A hostname is a string the other device wrote, and it lands in a terminal.
#[test]
fn a_hostile_name_cannot_forge_a_row_move_a_cursor_or_run_off_the_screen() {
    let scratch = Scratch::new("hostile");
    let client = fake_client(&scratch, "hostile-names.json", true, 0);

    let output = ouro(&scratch, Some(&client), &["fleet", "devices"]);
    assert!(output.status.success());
    let text = stdout(&output);

    for (index, byte) in text.bytes().enumerate() {
        assert!(
            byte >= 0x20 || byte == b'\n',
            "control byte {byte:#04x} reached the terminal at offset {index}"
        );
        assert_ne!(byte, 0x7f, "DEL reached the terminal at offset {index}");
    }
    assert!(
        !text.contains('\u{202e}'),
        "a bidi override reached the terminal"
    );

    // Six devices plus this machine. The forged row's `ouroboros    ... view device`
    // line must not have become a seventh device's.
    assert_eq!(
        text.matches("      ouroboros    ").count(),
        7,
        "exactly one state line per device:\n{text}"
    );
    assert!(
        !text.contains("ghost"),
        "the forged row did not land:\n{text}"
    );
    assert!(
        !text.contains(&"L".repeat(80)),
        "a four-thousand character name did not print in full"
    );
    for line in text.lines() {
        assert!(line.chars().count() < 400, "a runaway line: {line:?}");
    }

    // The JSON keeps what the client actually said — serde escapes it, and a machine
    // reader wants the raw value.
    let json = ouro(&scratch, Some(&client), &["fleet", "devices", "--json"]);
    let value = parse(&json);
    let names: Vec<&str> = value["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect();
    assert!(
        names.iter().any(|name| name.contains('\u{1b}')),
        "the raw name survives in --json: {names:?}"
    );
}

/// HIGH-3, through the real commands: a device that renames itself after a roster machine
/// must not take over that machine's row, its address, or its probe.
#[test]
fn a_device_that_adopts_a_roster_name_never_takes_over_that_members_row_or_probe() {
    let scratch = Scratch::new("roster-spoof");
    create_fleet(&scratch, "studio");
    let add = ouro(
        &scratch,
        None,
        &["fleet", "members", "add", "attic", "--host", "100.64.12.77"],
    );
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );

    let log = scratch.path().join("spoof-probes");
    let client = write_script(
        &scratch,
        "spoofing",
        &format!(
            "#!/bin/sh\nprintf '%s ' \"$@\" >> {log}\nprintf '\\n' >> {log}\n\
             case \"$1\" in\n\
             status) cat {FIXTURES}/roster-spoof.json ;;\n\
             ping) printf 'pong from attic (100.64.12.250) via [203.0.113.9]:41641 in 9ms\\n' ;;\n\
             *) printf 'unexpected\\n' >&2; exit 64 ;;\n\
             esac\n",
            log = log.display()
        ),
    );

    let value = parse(&ouro(
        &scratch,
        Some(&client),
        &["fleet", "devices", "--json"],
    ));
    let rows = value["devices"].as_array().expect("devices");
    let member = rows
        .iter()
        .find(|row| row["machine"] == "attic")
        .expect("the roster row");
    assert_eq!(member["state"], "fleet_member_not_visible");
    assert_eq!(member["address"], "100.64.12.77");
    assert!(
        member["os"].is_null() && member["online"].is_null(),
        "the impostor's platform and presence are not the member's: {member}"
    );

    let impostor = rows
        .iter()
        .find(|row| row["address"] == "100.64.12.250")
        .expect("the impostor is still listed as the device it is");
    assert!(impostor["machine"].is_null());
    assert_eq!(impostor["name_conflicts_with_roster"], "attic");

    let human = stdout(&ouro(&scratch, Some(&client), &["fleet", "devices"]));
    assert!(human.contains("It is not that machine."), "{human}");

    // And the probe. `--peer attic` means the machine in the roster, at the address the
    // operator bound; it is not visible, so nothing is probed at all.
    let probe = ouro(
        &scratch,
        Some(&client),
        &["fleet", "doctor", "--json", "--peer", "attic"],
    );
    assert!(!probe.status.success());
    let route = &parse(&probe)["layers"]["device_route"];
    assert_eq!(route["code"], "peer_unknown");
    assert!(route["address"].is_null());

    let invocations = std::fs::read_to_string(&log).expect("the fake ran");
    assert!(
        !invocations.contains("ping"),
        "no packet was sent to the impostor: {invocations}"
    );
}

/// Read-only means read-only: no data directory is created or written by discovery.
#[test]
fn discovery_writes_nothing_and_contacts_no_peer() {
    let scratch = Scratch::new("inert");
    create_fleet(&scratch, "studio");
    let before = unchanged(&scratch.data_dir());

    let client = write_script(
        &scratch,
        "counting",
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}/invocations\n\
             cat {FIXTURES}/running-with-peers.json\n",
            scratch.path().display()
        ),
    );
    let output = ouro(&scratch, Some(&client), &["fleet", "devices", "--json"]);
    assert!(output.status.success());

    assert_eq!(
        unchanged(&scratch.data_dir()),
        before,
        "a read-only listing must not write into the data directory"
    );
    let invocations =
        std::fs::read_to_string(scratch.path().join("invocations")).expect("the fake was run");
    assert_eq!(
        invocations, "status\n--json\n",
        "exactly one `tailscale status --json`, and nothing that contacts a peer"
    );
}

// --------------------------------------------------------------------- status and doctor

#[test]
fn fleet_status_json_reports_incomplete_setup_with_a_non_zero_exit() {
    let scratch = Scratch::new("status-empty");
    let client = fake_client(&scratch, "running-with-peers.json", true, 0);

    let output = ouro(&scratch, Some(&client), &["fleet", "status", "--json"]);
    assert!(
        !output.status.success(),
        "a machine with no fleet profile is incomplete setup"
    );
    let value = parse(&output);
    assert_eq!(value["ready"], false);
    assert!(value["profile"].is_null());
    assert_eq!(value["network"]["code"], "ok");
    assert_eq!(value["build"]["fleet_protocol_revision"], 5);
    assert!(value["live"].is_null(), "no runtime is published");

    // The human form is unchanged, including its exit code.
    let human = ouro(&scratch, Some(&client), &["fleet", "status"]);
    assert!(
        human.status.success(),
        "the existing human status still exits 0"
    );
    assert!(stdout(&human).contains("fleet"));
}

#[test]
fn fleet_status_json_reports_a_created_fleet_as_ready() {
    let scratch = Scratch::new("status-ready");
    create_fleet(&scratch, "studio");
    let client = fake_client(&scratch, "running-with-peers.json", true, 0);
    let output = ouro(&scratch, Some(&client), &["fleet", "status", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse(&output);
    assert_eq!(value["ready"], true);
    assert_eq!(value["profile"]["machine"], "studio");
    assert_eq!(value["tls"], true);

    // The bind check depends on this machine's interfaces, so the deterministic case is
    // the one where discovery established no address at all: it is `unknown`, never a
    // default that reads like an observation. `fleet_network`'s unit tests cover the
    // bindable and not-bindable answers against addresses chosen for the purpose.
    let signed_out = fake_client(&scratch, "needs-login.json", true, 0);
    let value = parse(&ouro(
        &scratch,
        Some(&signed_out),
        &["fleet", "status", "--json"],
    ));
    assert_eq!(value["network"]["code"], "signed_out");
    assert_eq!(
        value["bindable_self_address"]["code"], "unknown",
        "no discovered address is unknown, not unbindable"
    );
}

#[test]
fn fleet_doctor_reports_the_network_client_layer_in_both_forms() {
    let scratch = Scratch::new("doctor");
    create_fleet(&scratch, "studio");
    let client = fake_client(&scratch, "running-with-peers.json", true, 0);

    let human = ouro(&scratch, Some(&client), &["fleet", "doctor"]);
    let text = stdout(&human);
    assert!(
        text.contains("Fleet doctor —"),
        "the existing human report is still printed first: {text}"
    );
    assert!(text.contains("Network client — 1.102.1"), "{text}");
    assert!(
        text.contains("operator-laptop.tailnet-example.ts.net"),
        "{text}"
    );

    let json = ouro(&scratch, Some(&client), &["fleet", "doctor", "--json"]);
    let value = parse(&json);
    assert_eq!(value["layers"]["network_client"]["code"], "ok");
    assert_eq!(
        value["layers"]["network_client"]["client_version"],
        "1.102.1"
    );
    assert!(
        value["layers"]["device_route"].is_null(),
        "no route is probed unless one is asked for"
    );
    assert!(value["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .all(|check| {
            ["ok", "warning", "problem"].contains(&check["level"].as_str().expect("a level"))
        }));
    assert_eq!(value["build"]["fleet_protocol_revision"], 5);
}

/// A fleet configured by hand over a private LAN has no network client to find, and that
/// is not a broken fleet: the layer is reported, and it does not fail the command.
#[test]
fn a_missing_network_client_is_reported_without_failing_doctor() {
    let scratch = Scratch::new("doctor-no-client");
    create_fleet(&scratch, "studio");
    let output = ouro(&scratch, None, &["fleet", "doctor", "--json"]);
    let value = parse(&output);
    assert_eq!(value["layers"]["network_client"]["code"], "client_missing");
    assert_eq!(value["layers"]["network_client"]["problem"], false);
    assert_eq!(
        value["healthy"],
        output.status.success(),
        "the exit code and the reported health are the same fact"
    );
}

#[test]
fn doctor_peer_probes_exactly_one_device_and_reports_what_it_observed() {
    let scratch = Scratch::new("doctor-peer");
    create_fleet(&scratch, "studio");
    let log = scratch.path().join("probes");
    // A counting fake: it answers `status` from the fixture, answers `ping` for the one
    // address the operator named, and refuses anything else.
    let client = write_script(
        &scratch,
        "probing",
        &format!(
            "#!/bin/sh\nprintf '%s ' \"$@\" >> {log}\nprintf '\\n' >> {log}\n\
             case \"$1\" in\n\
             status) cat {FIXTURES}/running-with-peers.json ;;\n\
             ping) printf 'pong from build-linux (100.64.12.44) via DERP(lhr) in 41ms\\n' ;;\n\
             *) printf 'unexpected request\\n' >&2; exit 64 ;;\n\
             esac\n",
            log = log.display()
        ),
    );

    let output = ouro(
        &scratch,
        Some(&client),
        &["fleet", "doctor", "--json", "--peer", "build-linux"],
    );
    let value = parse(&output);
    let route = &value["layers"]["device_route"];
    assert_eq!(route["code"], "reachable");
    assert_eq!(route["address"], "100.64.12.44");
    assert_eq!(
        route["path"], "relayed",
        "a relay is a valid connection, reported as the one that was observed"
    );
    assert_eq!(route["problem"], false);

    let invocations = std::fs::read_to_string(&log).expect("the fake was run");
    assert_eq!(
        invocations, "status --json \nping -c 1 --timeout 3s 100.64.12.44 \n",
        "one status read and one probe of the one named device: {invocations}"
    );

    // A well-formed address is not an address this client reported. `--peer` must not be
    // a way to send a packet to any host on the overlay: the only thing that makes an
    // address probeable is that this machine's own client named it.
    std::fs::write(&log, "").expect("clearing the probe log");
    let stray = ouro(
        &scratch,
        Some(&client),
        &["fleet", "doctor", "--json", "--peer", "100.64.99.99"],
    );
    assert!(!stray.status.success());
    let route = &parse(&stray)["layers"]["device_route"];
    assert_eq!(route["code"], "peer_unknown");
    assert!(
        route["address"].is_null(),
        "no address is invented: {route}"
    );
    let after = std::fs::read_to_string(&log).expect("the fake log");
    assert!(
        !after.contains("ping"),
        "an unreported address was probed anyway: {after}"
    );
    assert_eq!(
        after.matches("status").count(),
        1,
        "the client is still asked once, to establish what it can see: {after}"
    );

    // Two visible devices answering to one name is refused rather than guessed at.
    std::fs::write(&log, "").expect("clearing the probe log");
    let ambiguous_client = write_script(
        &scratch,
        "ambiguous",
        &format!(
            "#!/bin/sh\nprintf '%s ' \"$@\" >> {log}\nprintf '\\n' >> {log}\n\
             case \"$1\" in status) cat {FIXTURES}/duplicate-names.json ;; esac\n",
            log = log.display()
        ),
    );
    let ambiguous = ouro(
        &scratch,
        Some(&ambiguous_client),
        &["fleet", "doctor", "--json", "--peer", "build-linux"],
    );
    assert!(!ambiguous.status.success());
    let route = &parse(&ambiguous)["layers"]["device_route"];
    assert_eq!(route["code"], "peer_ambiguous");
    assert!(
        route["detail"]
            .as_str()
            .expect("a detail")
            .contains("100.64.12.44"),
        "the candidates are named so the operator can pick one: {route}"
    );
    assert!(
        !std::fs::read_to_string(&log)
            .expect("the fake log")
            .contains("ping"),
        "nothing was probed while the name was ambiguous"
    );

    let human = ouro(
        &scratch,
        Some(&client),
        &["fleet", "doctor", "--peer", "build-linux"],
    );
    let text = stdout(&human);
    assert!(text.contains("Device route — build-linux"), "{text}");
    assert!(text.contains("relayed path observed"), "{text}");
    assert!(
        text.contains("does not establish that the distribution ports are open"),
        "an overlay ping is not a distribution check: {text}"
    );
}

/// A probe that printed nothing on stdout still has something to tell the operator, and
/// it is on stderr. Dropping it leaves `unknown` with no reason attached.
#[test]
fn a_silent_probe_reports_what_the_client_said_on_stderr() {
    let scratch = Scratch::new("probe-stderr");
    create_fleet(&scratch, "studio");
    let client = write_script(
        &scratch,
        "grumpy",
        &format!(
            "#!/bin/sh\ncase \"$1\" in\n\
             status) cat {FIXTURES}/running-with-peers.json ;;\n\
             ping) printf 'ping: peerapi is not enabled on this tailnet\\n' >&2; exit 1 ;;\n\
             esac\n"
        ),
    );
    let output = ouro(
        &scratch,
        Some(&client),
        &["fleet", "doctor", "--json", "--peer", "build-linux"],
    );
    assert!(!output.status.success());
    let route = &parse(&output)["layers"]["device_route"];
    assert_eq!(route["code"], "unknown");
    assert!(
        route["detail"]
            .as_str()
            .expect("a detail")
            .contains("peerapi is not enabled"),
        "the client's own reason survives: {route}"
    );
}

#[test]
fn a_probe_that_fails_fails_the_command_and_an_unknown_peer_is_never_invented() {
    let scratch = Scratch::new("doctor-peer-fails");
    create_fleet(&scratch, "studio");
    let client = write_script(
        &scratch,
        "timing-out",
        &format!(
            "#!/bin/sh\ncase \"$1\" in\n\
             status) cat {FIXTURES}/running-with-peers.json ;;\n\
             ping) printf 'ping \"100.64.12.10\" timed out\\n'; exit 1 ;;\n\
             esac\n"
        ),
    );

    let output = ouro(
        &scratch,
        Some(&client),
        &["fleet", "doctor", "--json", "--peer", "old-pi"],
    );
    assert!(
        !output.status.success(),
        "a probe the operator asked for that did not succeed is a problem"
    );
    let value = parse(&output);
    assert_eq!(value["healthy"], false);
    assert_eq!(value["layers"]["device_route"]["code"], "timed_out");
    assert_eq!(value["layers"]["device_route"]["path"], "unknown");

    let unknown = ouro(
        &scratch,
        Some(&client),
        &["fleet", "doctor", "--json", "--peer", "not-a-device"],
    );
    assert!(!unknown.status.success());
    let value = parse(&unknown);
    assert_eq!(value["layers"]["device_route"]["code"], "peer_unknown");
    assert!(
        value["layers"]["device_route"]["address"].is_null(),
        "an address is never invented for a device this client cannot see"
    );
}
