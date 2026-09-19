//! `ouro fleet helper`: §7's seven operations, over a pipe, against the real binary.
//!
//! The helper is the half of the setup protocol that runs on the machine being joined,
//! reached over SSH as a fixed command. Everything variable about an operation — a
//! machine name, a path, the fleet's whole secret bundle — arrives inside a frame and is
//! used as data. What is pinned here is exactly that contract: the seven ops and their
//! replies, the frame cap, the envelope, what happens to a line that is not a frame, and
//! that stdout carries frames and nothing else.
//!
//! Every test drives the built `ouro` as a child process with its stdin and stdout
//! piped, which is how an issuer's `helper::Session` drives it. The one exception is the
//! idle timeout, which is driven in process through `serve_on` so a minute's production
//! deadline can be proved in milliseconds.
//!
//! ## Isolation
//!
//! The helper's `service` and `leave` ops reach a service manager, and `leave` removes a
//! unit. Every child here is given a scratch `HOME`, the `OUROBOROS_SERVICE_ROOT` write
//! fence, and three fake managers on the paths `Programs::from_env` reads, so nothing
//! touches the account's own `~/Library/LaunchAgents` or its real launchd.

mod fleet_ports;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use ouro::fleet;

const OURO: &str = env!("CARGO_BIN_EXE_ouro");

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Claimed ports, so no other test process in this run binds them first.
fn ephemeral() -> fleet::Ports {
    let (gateway, dist) = fleet_ports::reserve();
    fleet::Ports {
        gateway: Some(gateway),
        dist: Some(dist),
    }
}

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ouro-helper-{label}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("a scratch directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("a private directory");
    path
}

fn private_dir(path: &Path) -> PathBuf {
    fs::create_dir_all(path).expect("a data directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("a private data directory");
    path.to_path_buf()
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, body).expect("a script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("an executable script");
}

// ------------------------------------------------------------------- the isolated world

/// A scratch home, a write fence, and three fake service managers.
///
/// The fakes answer the detection probe and accept every verb, so `service` and `leave`
/// exercise the real library path without any of it reaching this account's launchd.
struct World {
    home: PathBuf,
    bin: PathBuf,
    log: PathBuf,
    root: PathBuf,
}

impl World {
    fn new(label: &str) -> Self {
        let root = scratch(label);
        let home = root.join("home");
        let bin = root.join("bin");
        let log = root.join("manager.log");
        fs::create_dir_all(&home).expect("a scratch home");
        fs::create_dir_all(&bin).expect("a fake bin");
        fs::write(&log, b"").expect("a manager log");

        let record = format!("printf '%s\\n' \"$*\" >> '{}'\n", log.display());
        write_script(
            &bin.join("launchctl"),
            &format!(
                "#!/bin/sh\n{record}case \"$1\" in\n  print) case \"$2\" in gui/*/*) exit 113 ;; gui/*) exit 0 ;; esac ;;\nesac\nexit 0\n"
            ),
        );
        write_script(
            &bin.join("systemctl"),
            &format!(
                "#!/bin/sh\n{record}shift\ncase \"$1\" in\n  show) case \"$2\" in --property=Version) echo Version=255 ;; *) printf 'LoadState=not-found\\nActiveState=inactive\\nSubState=dead\\nMainPID=0\\n' ;; esac ;;\nesac\nexit 0\n"
            ),
        );
        write_script(
            &bin.join("loginctl"),
            &format!("#!/bin/sh\n{record}echo Linger=yes\nexit 0\n"),
        );

        Self {
            home,
            bin,
            log,
            root,
        }
    }

    fn apply(&self, command: &mut Command) {
        command
            .env("HOME", &self.home)
            .env_remove("XDG_CONFIG_HOME")
            .env("OUROBOROS_SERVICE_ROOT", &self.home)
            .env("OUROBOROS_LAUNCHCTL", self.bin.join("launchctl"))
            .env("OUROBOROS_SYSTEMCTL", self.bin.join("systemctl"))
            .env("OUROBOROS_LOGINCTL", self.bin.join("loginctl"));
    }

    fn manager_calls(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ----------------------------------------------------------------- the helper on a pipe

/// One `ouro fleet helper` child, spoken to the way an issuer's session speaks to it.
struct Helper {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    stderr: PathBuf,
    next_id: u32,
}

impl Helper {
    fn start(world: &World, data_dir: &Path) -> Self {
        let stderr = world.root.join(format!(
            "stderr-{}.log",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let errors = fs::File::create(&stderr).expect("a stderr log");
        let mut command = Command::new(OURO);
        command
            .args(["fleet", "helper"])
            .env("OUROBOROS_DATA_DIR", data_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(errors));
        world.apply(&mut command);
        let mut child = command.spawn().expect("the built ouro binary");
        let input = child.stdin.take().expect("a piped stdin");
        let output = BufReader::new(child.stdout.take().expect("a piped stdout"));
        Self {
            child,
            input: Some(input),
            output,
            stderr,
            next_id: 0,
        }
    }

    /// Send one request with a fresh id and read the reply, checking the envelope.
    fn ask(&mut self, op: &str, fields: Value) -> Value {
        self.next_id += 1;
        let id = format!("h{}", self.next_id);
        let reply = self.ask_with_id(&id, op, fields);
        assert_eq!(reply["id"], json!(id), "a reply echoes its request's id");
        assert_eq!(reply["v"], json!(1), "the envelope version");
        reply
    }

    fn ask_with_id(&mut self, id: &str, op: &str, fields: Value) -> Value {
        let mut request = fields.as_object().cloned().unwrap_or_default();
        request.insert("v".into(), json!(1));
        request.insert("id".into(), json!(id));
        request.insert("op".into(), json!(op));
        self.send_line(&Value::Object(request).to_string());
        self.read_frame().expect("a reply frame")
    }

    fn send_line(&mut self, line: &str) {
        let input = self.input.as_mut().expect("an open stdin");
        input
            .write_all(line.as_bytes())
            .and_then(|()| input.write_all(b"\n"))
            .and_then(|()| input.flush())
            .expect("a helper still reading");
    }

    /// The next line of stdout, decoded. `None` at end of output.
    fn read_frame(&mut self) -> Option<Value> {
        let mut line = String::new();
        loop {
            line.clear();
            if self.output.read_line(&mut line).expect("readable stdout") == 0 {
                return None;
            }
            if line.trim().is_empty() {
                continue;
            }
            return Some(serde_json::from_str(&line).unwrap_or_else(|error| {
                panic!("stdout carries one JSON object per line ({error}): {line}")
            }));
        }
    }

    fn errors(&self) -> String {
        fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    /// Close stdin and wait, with the exit code.
    fn finish(mut self) -> (Option<i32>, String) {
        self.input.take();
        let status = self.child.wait().expect("the helper exits");
        let errors = self.errors();
        (status.code(), errors)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ------------------------------------------------------------------------- the fixtures

/// A fleet on its own data directory, and the bundle a new member would be handed.
struct Issuer {
    data_dir: PathBuf,
    profile: fleet::Profile,
}

impl Issuer {
    fn new(root: &Path, machine: &str) -> Self {
        let data_dir = private_dir(&root.join(format!("issuer-{machine}")));
        let profile = fleet::create(
            &data_dir,
            Some("the lab"),
            machine,
            "127.0.0.1",
            ephemeral(),
        )
        .expect("a created fleet");
        Self { data_dir, profile }
    }

    fn bundle(&self) -> Value {
        serde_json::to_value(fleet::bundle(&self.data_dir).expect("a bundle"))
            .expect("an encodable bundle")
    }

    fn cookie(&self) -> String {
        fs::read_to_string(self.data_dir.join("fleet/cookie"))
            .expect("the fleet cookie")
            .trim()
            .to_string()
    }
}

/// A live process standing in for a runtime, with the publication that names it.
struct FakeRuntime {
    child: Child,
}

impl FakeRuntime {
    fn publish(data_dir: &Path) -> Self {
        let child = Command::new("/bin/sh")
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
        let path = data_dir.join("gateway.json");
        fs::write(
            &path,
            format!(
                r#"{{"port":1,"protocol":1,"node":"nonode@nohost","pid":{pid},"birth":"{birth}","scope":"operate"}}"#
            ),
        )
        .expect("a publication");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("a private file");
        Self { child }
    }
}

impl Drop for FakeRuntime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ================================================================================== hello

/// §7 `hello`: the version the compatibility fence compares, and the facts a plan line
/// needs to name this machine honestly.
#[test]
fn hello_names_this_build_and_this_machine() {
    let world = World::new("hello");
    let data_dir = private_dir(&world.root.join("data"));
    let mut helper = Helper::start(&world, &data_dir);

    let reply = helper.ask("hello", json!({}));

    assert_eq!(reply["ok"], json!(true), "{reply}");
    assert_eq!(reply["version"], json!(env!("CARGO_PKG_VERSION")));
    assert_eq!(reply["os"], json!(std::env::consts::OS));
    assert_eq!(reply["arch"], json!(std::env::consts::ARCH));
    assert_eq!(
        reply["data_dir"],
        json!(data_dir.display().to_string()),
        "hello names the directory this helper was started with"
    );
    assert_eq!(reply["home"], json!(world.home.display().to_string()));
    assert_eq!(reply["wire"], json!(1));
    assert!(reply["helper"].is_number(), "{reply}");
    // §12's build contract, so an operator can refuse a mismatch before a credential
    // leaves this machine.
    assert!(
        reply["build"]["ouroboros_version"].is_string(),
        "hello carries the build contract: {reply}"
    );

    // And `bye` exits 0.
    let reply = helper.ask("bye", json!({}));
    assert_eq!(reply["ok"], json!(true));
    let (code, errors) = helper.finish();
    assert_eq!(code, Some(0), "`bye` exits 0: {errors}");
}

// ================================================================================ inspect

/// §7 `inspect`: is there a fleet here, is a runtime up, is a service installed.
#[test]
fn inspect_answers_for_an_empty_directory_a_fleet_and_a_running_runtime() {
    let world = World::new("inspect");
    let data_dir = private_dir(&world.root.join("data"));

    // ---- nothing here at all
    let mut helper = Helper::start(&world, &data_dir);
    let empty = helper.ask("inspect", json!({}));
    assert_eq!(empty["ok"], json!(true), "{empty}");
    assert_eq!(empty["fleet"], Value::Null, "{empty}");
    assert_eq!(empty["runtime_running"], json!(false), "{empty}");
    assert_eq!(
        empty["service"]["installed"],
        json!(false),
        "no unit at this data directory's path: {empty}"
    );
    drop(helper);

    // ---- a fleet, made by this same binary's library
    let profile = fleet::create(&data_dir, Some("the lab"), "pi", "127.0.0.1", ephemeral())
        .expect("a created fleet");
    let mut helper = Helper::start(&world, &data_dir);
    let joined = helper.ask("inspect", json!({}));
    assert_eq!(joined["fleet"]["fleet_id"], json!(profile.fleet_id));
    assert_eq!(joined["fleet"]["name"], json!("the lab"));
    assert_eq!(joined["fleet"]["machine"], json!("pi"));
    assert_eq!(joined["fleet"]["host"], json!("127.0.0.1"));
    assert_eq!(joined["runtime_running"], json!(false));
    drop(helper);

    // ---- and a runtime that is actually up
    let _runtime = FakeRuntime::publish(&data_dir);
    let mut helper = Helper::start(&world, &data_dir);
    let running = helper.ask("inspect", json!({}));
    assert_eq!(
        running["runtime_running"],
        json!(true),
        "a live publication is a running runtime: {running}"
    );
    assert_eq!(running["fleet"]["machine"], json!("pi"));
}

/// A request naming a directory this helper does not serve is refused before anything
/// opens it, whatever the spelling.
#[test]
fn a_request_for_another_data_directory_is_refused() {
    let world = World::new("elsewhere");
    let data_dir = private_dir(&world.root.join("data"));
    let mut helper = Helper::start(&world, &data_dir);

    for hostile in [
        json!("/etc"),
        json!("relative/path"),
        json!(format!("{}/../elsewhere", data_dir.display())),
    ] {
        let reply = helper.ask("inspect", json!({ "data_dir": hostile }));
        assert_eq!(reply["ok"], json!(false), "{hostile} was accepted");
        assert_eq!(reply["reason"], json!("invalid_path"), "{reply}");
    }
    // The one it does serve is fine.
    let reply = helper.ask(
        "inspect",
        json!({ "data_dir": data_dir.display().to_string() }),
    );
    assert_eq!(reply["ok"], json!(true), "{reply}");
}

// ================================================================================ install

/// §7 `install`: the bundle lands as this machine's own identity, at §2's modes.
///
/// And the three answers the table names: a second `install` of the same fleet as the
/// same machine is `already_installed` and rewrites nothing, another fleet is
/// `fleet_present`, and `replace: true` is the operator saying so outright.
#[test]
fn install_writes_the_bundle_at_the_documented_modes_and_guards_what_is_there() {
    let world = World::new("install");
    let target = private_dir(&world.root.join("data"));
    let issuer = Issuer::new(&world.root, "studio");
    let ports = ephemeral();

    let mut helper = Helper::start(&world, &target);
    let installed = helper.ask(
        "install",
        json!({
            "bundle": issuer.bundle(),
            "machine": "pi",
            "host": "127.0.0.1",
            "ports": { "gateway": ports.gateway, "dist": ports.dist },
        }),
    );

    assert_eq!(installed["ok"], json!(true), "{installed}");
    assert_eq!(installed["machine"], json!("pi"));
    assert_eq!(installed["node"], json!("ouro-pi@127.0.0.1"));
    assert_eq!(installed["fleet_id"], json!(issuer.profile.fleet_id));
    assert_eq!(installed["dist_port"], json!(ports.dist));

    // §2's three secrets, at the mode §2 gives them. This is the contract that matters:
    // the cookie, the shared CA key and this machine's own node key are readable by
    // nobody else.
    for name in ["cookie", "ca-key.pem", "node-key.pem"] {
        assert_eq!(mode(&target.join("fleet").join(name)), 0o600, "{name}");
    }
    // **Deviation from §2, in the code's favour.** §2's table gives `profile.json`,
    // `ca-cert.pem`, `node-cert.pem`, `ssl_dist.conf` and `vm.args` mode 0644.
    // `fleet.rs` writes every file in the directory 0600 and validates them at 0600, so
    // the whole bundle is owner-only. Asserted as it is rather than as §2 spells it:
    // nothing here reads those files as another account, and loosening them to match a
    // table would be a change to make deliberately in K1, not a side effect of a test.
    for name in [
        "profile.json",
        "ca-cert.pem",
        "node-cert.pem",
        "ssl_dist.conf",
        "vm.args",
    ] {
        assert_eq!(
            mode(&target.join("fleet").join(name)),
            0o600,
            "{name} is written 0600, not §2's 0644"
        );
    }
    // The shared halves are the fleet's, byte for byte; the node key is this machine's.
    assert_eq!(
        fs::read(target.join("fleet/cookie")).expect("the target cookie"),
        fs::read(issuer.data_dir.join("fleet/cookie")).expect("the issuer cookie")
    );
    assert_ne!(
        fs::read(target.join("fleet/node-key.pem")).expect("the target key"),
        fs::read(issuer.data_dir.join("fleet/node-key.pem")).expect("the issuer key")
    );

    // ---- the same fleet, the same machine: idempotent, and nothing is rewritten
    let before = fs::read(target.join("fleet/node-cert.pem")).expect("the leaf");
    let again = helper.ask(
        "install",
        json!({
            "bundle": issuer.bundle(),
            "machine": "pi",
            "host": "127.0.0.1",
            "ports": { "gateway": ports.gateway, "dist": ports.dist },
        }),
    );
    assert_eq!(again["ok"], json!(false), "{again}");
    assert_eq!(again["reason"], json!("already_installed"), "{again}");
    assert_eq!(
        fs::read(target.join("fleet/node-cert.pem")).expect("the leaf"),
        before,
        "an `already_installed` refusal rewrites nothing"
    );

    // ---- a different fleet is `fleet_present`, and is not replaced
    let other = Issuer::new(&world.root, "other");
    let stranger = helper.ask(
        "install",
        json!({
            "bundle": other.bundle(),
            "machine": "pi",
            "host": "127.0.0.1",
            "ports": { "gateway": ports.gateway, "dist": ports.dist },
        }),
    );
    assert_eq!(stranger["ok"], json!(false), "{stranger}");
    assert_eq!(stranger["reason"], json!("fleet_present"), "{stranger}");
    assert_eq!(
        fleet::load(&target)
            .expect("a readable target")
            .expect("an installed target")
            .fleet_id,
        issuer.profile.fleet_id,
        "a `fleet_present` refusal leaves the identity that is there"
    );

    // ---- `replace: true` is the operator saying so outright
    let replaced_ports = ephemeral();
    let replaced = helper.ask(
        "install",
        json!({
            "bundle": other.bundle(),
            "machine": "pi",
            "host": "127.0.0.1",
            "replace": true,
            "ports": { "gateway": replaced_ports.gateway, "dist": replaced_ports.dist },
        }),
    );
    assert_eq!(replaced["ok"], json!(true), "{replaced}");
    assert_eq!(replaced["fleet_id"], json!(other.profile.fleet_id));
    assert_eq!(
        fs::read(target.join("fleet/cookie")).expect("the new cookie"),
        fs::read(other.data_dir.join("fleet/cookie")).expect("the other cookie")
    );

    // Neither secret was ever echoed, and stderr says nothing about them either.
    assert!(!helper.errors().contains(&issuer.cookie()));
    assert!(!helper.errors().contains(&other.cookie()));
}

/// A bundle that is not a bundle is refused as a bad request, not half-installed.
#[test]
fn a_malformed_install_request_installs_nothing() {
    let world = World::new("badbundle");
    let target = private_dir(&world.root.join("data"));
    let mut helper = Helper::start(&world, &target);

    for (fields, why) in [
        (json!({ "machine": "pi", "host": "127.0.0.1" }), "no bundle"),
        (
            json!({ "bundle": {"schema": 2}, "machine": "pi", "host": "127.0.0.1" }),
            "a bundle missing every secret",
        ),
        (
            json!({ "bundle": {}, "host": "127.0.0.1" }),
            "no machine name",
        ),
    ] {
        let reply = helper.ask("install", fields);
        assert_eq!(reply["ok"], json!(false), "{why} was accepted: {reply}");
        assert!(reply["reason"].is_string(), "{why}: {reply}");
    }
    assert!(
        !target.join("fleet").exists(),
        "a refused install wrote a fleet directory"
    );
}

// ======================================================================== service, status

/// §7 `service` with `install: false` reports and changes nothing; `status` answers for
/// a runtime that is not up without calling that an error.
#[test]
fn service_reports_without_installing_and_status_answers_for_a_stopped_runtime() {
    let world = World::new("service");
    let target = private_dir(&world.root.join("data"));
    fleet::create(&target, Some("the lab"), "pi", "127.0.0.1", ephemeral())
        .expect("a created fleet");
    let mut helper = Helper::start(&world, &target);

    // `install` is required and is a boolean; nothing else is a default.
    for fields in [json!({}), json!({ "install": "yes" })] {
        let reply = helper.ask("service", fields);
        assert_eq!(reply["ok"], json!(false), "{reply}");
    }

    let reported = helper.ask("service", json!({ "install": false }));
    assert_eq!(reported["ok"], json!(true), "{reported}");
    assert_eq!(reported["installed"], json!(false), "{reported}");
    assert_eq!(reported["supported"], json!(true), "{reported}");
    assert!(
        reported["report"]["unit_path"]
            .as_str()
            .is_some_and(|path| path.starts_with(&world.home.display().to_string())),
        "the unit path is inside the fence: {reported}"
    );
    // Reporting installs nothing.
    let agents = world.home.join("Library/LaunchAgents");
    assert!(
        fs::read_dir(&agents).into_iter().flatten().count() == 0,
        "`install: false` wrote a unit"
    );
    assert!(
        world
            .manager_calls()
            .iter()
            .all(|call| call.contains("print") || call.contains("show") || call.contains("Linger")),
        "a report only asks: {:?}",
        world.manager_calls()
    );

    // `status`: a runtime that is not up is a fact, not a failure.
    let status = helper.ask("status", json!({}));
    assert_eq!(status["ok"], json!(true), "{status}");
    assert_eq!(status["runtime_running"], json!(false), "{status}");
    assert_eq!(status["connected_to"], json!([]), "{status}");
    assert_eq!(status["version"], json!(env!("CARGO_PKG_VERSION")));

    // And with a live publication it says so.
    let _runtime = FakeRuntime::publish(&target);
    let mut helper = Helper::start(&world, &target);
    let status = helper.ask("status", json!({}));
    assert_eq!(status["runtime_running"], json!(true), "{status}");
    assert_eq!(
        status["connected_to"],
        json!([]),
        "a runtime that answers nothing is connected to nothing, not to a guess: {status}"
    );
}

// ================================================================================== leave

/// §7 `leave` on a stopped target: the fleet directory goes, and what went is named.
#[test]
fn leave_on_a_stopped_target_removes_the_fleet_directory() {
    let world = World::new("leave");
    let target = private_dir(&world.root.join("data"));
    fleet::create(&target, Some("the lab"), "pi", "127.0.0.1", ephemeral())
        .expect("a created fleet");
    let cookie = fs::read_to_string(target.join("fleet/cookie")).expect("a cookie");
    assert!(target.join("fleet").exists());

    let mut helper = Helper::start(&world, &target);
    let left = helper.ask("leave", json!({}));

    assert_eq!(left["ok"], json!(true), "{left}");
    assert_eq!(left["machine"], json!("pi"), "{left}");
    assert_eq!(left["already_standalone"], json!(false), "{left}");
    assert!(left["removed"].is_array(), "{left}");
    assert!(
        !target.join("fleet").exists(),
        "the fleet directory is gone"
    );
    assert!(fleet::load(&target).expect("a readable target").is_none());
    // Sessions, workspaces and everything else in the data directory stay.
    assert!(target.exists());

    // Running it again is the idempotent answer rather than a failure.
    let again = helper.ask("leave", json!({}));
    assert_eq!(again["ok"], json!(true), "{again}");
    assert_eq!(again["already_standalone"], json!(true), "{again}");

    // The cookie that was here is in nothing the helper said or wrote.
    let spoken = format!("{left}{again}{}", helper.errors());
    assert!(
        !spoken.contains(cookie.trim()),
        "the cookie reached the wire or stderr"
    );
}

// ========================================================================== the wire rules

/// A line over the 1 MiB cap is refused and the helper exits rather than buffering
/// whatever a peer decides to send.
#[test]
fn a_line_over_the_frame_cap_is_refused_and_the_helper_exits() {
    let world = World::new("toolarge");
    let data_dir = private_dir(&world.root.join("data"));
    let mut helper = Helper::start(&world, &data_dir);

    // One good exchange first, so the refusal is about the size and not the start.
    assert_eq!(helper.ask("hello", json!({}))["ok"], json!(true));

    let huge = "x".repeat(ouro::fleet_helper::MAX_FRAME_BYTES + 1024);
    let line = format!(r#"{{"v":1,"id":"big","op":"hello","pad":"{huge}"}}"#);
    assert!(line.len() > ouro::fleet_helper::MAX_FRAME_BYTES);
    // A peer that is not being read stops being written to; either way the helper is
    // the one that decides, so a broken pipe here is the refusal arriving early.
    let input = helper.input.as_mut().expect("an open stdin");
    let _ = input.write_all(line.as_bytes());
    let _ = input.write_all(b"\n");
    let _ = input.flush();

    let refused = helper.read_frame().expect("a refusal frame");
    assert_eq!(refused["ok"], json!(false), "{refused}");
    assert_eq!(refused["reason"], json!("frame_too_large"), "{refused}");
    assert_eq!(
        refused["id"],
        Value::Null,
        "an oversized line has no id to echo: {refused}"
    );
    assert!(
        !refused["detail"]
            .as_str()
            .unwrap_or_default()
            .contains(&huge[..64]),
        "the refusal does not quote what was sent"
    );

    // And nothing follows it: the helper is finished.
    assert!(helper.read_frame().is_none(), "the helper kept answering");
    let (code, errors) = helper.finish();
    assert_eq!(code, Some(0), "{errors}");
}

/// A line that is not a frame is refused, and the connection keeps going: one bad line
/// is not a reason to drop an operation half way through.
#[test]
fn a_line_that_is_not_json_is_refused_and_the_conversation_continues() {
    let world = World::new("notjson");
    let data_dir = private_dir(&world.root.join("data"));
    let mut helper = Helper::start(&world, &data_dir);

    for hostile in [
        "this is not json",
        "[1,2,3]",
        "\"a string\"",
        "{\"v\":1,\"id\":\"x\"}",
        "{\"v\":1,\"op\":\"hello\"}",
        "{\"v\":9,\"id\":\"x\",\"op\":\"hello\"}",
        "{\"v\":1,\"id\":\"x\",\"op\":\"prepare\"}",
    ] {
        helper.send_line(hostile);
        let reply = helper.read_frame().expect("a refusal frame");
        assert_eq!(
            reply["ok"],
            json!(false),
            "`{hostile}` was accepted: {reply}"
        );
        assert!(
            reply["reason"].is_string(),
            "`{hostile}`: a refusal carries a stable reason: {reply}"
        );
    }

    // A deleted op is named as one rather than silently ignored.
    helper.send_line(r#"{"v":1,"id":"x","op":"roster"}"#);
    let gone = helper.read_frame().expect("a refusal");
    assert_eq!(gone["reason"], json!("unsupported_op"), "{gone}");

    // The conversation is still good.
    assert_eq!(helper.ask("hello", json!({}))["ok"], json!(true));
}

/// Two requests wearing the same `id` are two requests: each is answered, in order, and
/// the second never reads as the first's reply.
#[test]
fn a_duplicate_id_is_answered_twice_and_never_confused() {
    let world = World::new("dupid");
    let data_dir = private_dir(&world.root.join("data"));
    fleet::create(&data_dir, Some("the lab"), "pi", "127.0.0.1", ephemeral())
        .expect("a created fleet");
    let mut helper = Helper::start(&world, &data_dir);

    let first = helper.ask_with_id("same", "hello", json!({}));
    let second = helper.ask_with_id("same", "inspect", json!({}));

    assert_eq!(first["id"], json!("same"));
    assert_eq!(second["id"], json!("same"));
    assert!(
        first["version"].is_string(),
        "the first is a hello: {first}"
    );
    assert!(
        second.get("version").is_none() && second["fleet"]["machine"] == json!("pi"),
        "the second is an inspect, in order: {second}"
    );

    // An id that could not be echoed safely is refused before it is.
    for bad in [json!(""), json!(7), json!("a\nb"), json!("x".repeat(200))] {
        let reply = helper.ask_with_id("placeholder", "hello", json!({}));
        assert_eq!(reply["ok"], json!(true));
        helper.send_line(&json!({"v": 1, "id": bad, "op": "hello"}).to_string());
        let refused = helper.read_frame().expect("a refusal");
        assert_eq!(refused["ok"], json!(false), "{bad} was echoed: {refused}");
        assert_eq!(refused["reason"], json!("bad_request"), "{refused}");
        assert_eq!(refused["id"], Value::Null, "{refused}");
    }
}

/// Stdout carries frames and nothing else, and stderr carries no secret.
#[test]
fn stdout_carries_frames_and_nothing_else_and_stderr_carries_no_secret() {
    let world = World::new("stdio");
    let target = private_dir(&world.root.join("data"));
    let issuer = Issuer::new(&world.root, "studio");
    let ports = ephemeral();
    let mut helper = Helper::start(&world, &target);

    // A whole conversation, including the one frame that carries the fleet's secrets.
    helper.ask("hello", json!({}));
    helper.ask("inspect", json!({}));
    helper.ask(
        "install",
        json!({
            "bundle": issuer.bundle(),
            "machine": "pi",
            "host": "127.0.0.1",
            "ports": { "gateway": ports.gateway, "dist": ports.dist },
        }),
    );
    helper.ask("service", json!({ "install": false }));
    helper.ask("status", json!({}));
    helper.ask("leave", json!({}));
    let farewell = helper.ask("bye", json!({}));
    assert_eq!(farewell["ok"], json!(true));

    let (code, errors) = helper.finish();
    assert_eq!(code, Some(0), "{errors}");

    // Every secret that crossed this pipe, in everything the helper wrote to stderr.
    let cookie = issuer.cookie();
    let ca_key = fs::read_to_string(issuer.data_dir.join("fleet/ca-key.pem"))
        .expect("the CA key")
        .lines()
        .find(|line| !line.starts_with("-----") && line.len() > 20)
        .expect("a line of key material")
        .to_string();
    for (label, needle) in [("the cookie", cookie.as_str()), ("the CA key", &ca_key)] {
        assert!(
            !errors.contains(needle),
            "{label} reached stderr:\n{errors}"
        );
    }
}

/// Stdout really is only frames: every line of a whole conversation decodes, and the
/// helper's own diagnostics go to stderr instead.
#[test]
fn every_line_of_stdout_decodes_as_one_frame() {
    let world = World::new("onlyframes");
    let data_dir = private_dir(&world.root.join("data"));
    let mut helper = Helper::start(&world, &data_dir);

    // A mix of good requests and refusals, then a timeout notice, which is the one
    // thing the helper prints on its own initiative.
    helper.ask("hello", json!({}));
    helper.send_line("not a frame at all");
    helper.read_frame().expect("a refusal");
    helper.ask("inspect", json!({}));

    let (code, errors) = helper.finish();
    assert_eq!(code, Some(0));
    // `read_frame` panics on a line that is not one object, so reaching here is the
    // assertion; what is checked explicitly is that the diagnostics went elsewhere.
    assert!(
        !errors.contains('{') || errors.starts_with("ouro fleet helper:"),
        "stderr is diagnostics, not frames: {errors}"
    );
}

// ============================================================================ idle timeout

/// §7's 60 second idle timeout: a connection that stops speaking does not leave a
/// helper resident.
///
/// Driven in process through `serve_on`, with an idle deadline of a few hundred
/// milliseconds, because the behaviour is what matters and waiting a real minute in a
/// suite is not a test of anything. The constant itself is asserted separately, so
/// shortening it here cannot hide a production value that drifted.
#[test]
fn an_idle_connection_times_out_and_the_helper_exits() {
    assert_eq!(
        ouro::fleet_helper::IDLE_TIMEOUT,
        Duration::from_secs(60),
        "§7 says sixty seconds"
    );

    let world = World::new("idle");
    let data_dir = private_dir(&world.root.join("data"));

    // A pipe whose writing half is held open and never written to: the helper's reader
    // thread blocks, and only the idle deadline can end this.
    let (reader, writer) = os_pipe();
    let started = Instant::now();
    let helper_dir = data_dir.clone();
    let worker = std::thread::spawn(move || {
        let mut out = Vec::new();
        let result = ouro::fleet_helper::serve_on(
            helper_dir,
            BufReader::new(reader),
            &mut out,
            Duration::from_millis(300),
        );
        (result.is_ok(), out)
    });

    let (ok, out) = worker.join().expect("the helper thread finishes");
    let elapsed = started.elapsed();

    assert!(ok, "an idle timeout is an ordinary exit, not a failure");
    assert!(
        out.is_empty(),
        "a timeout writes no frame: {}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(20),
        "the deadline is the one it was given: {elapsed:?}"
    );
    drop(writer);
}

// =========================================================== adversarial review, KR3

/// **Finding.** `install` with `replace: true` deletes the fleet that is there *before*
/// it validates anything about the bundle, the machine name or the host.
///
/// `Helper::install` (tui/src/fleet_helper.rs:552) runs `fleet::leave(data_dir)` as soon
/// as it has parsed the request's *shape*, and only then calls `fleet::join`, which is
/// where `validate_bundle`, `validate_joined_machine`, `canonical_host` and
/// `validate_ports` live. So a request that is refused — for a cookie that is not 64
/// lowercase hex, a `dist_port` of 0, or a machine name this build will not mint — has
/// already destroyed the cookie, the shared CA key and this machine's node key by the
/// time the refusal is written.
///
/// `a_malformed_install_request_installs_nothing` proves a refused install writes
/// nothing on a *fresh* target. This proves that on an *occupied* one, a refused install
/// unwrites what was there and leaves the machine standalone.
#[test]
fn kr3_a_refused_replace_install_has_already_destroyed_the_fleet_that_was_there() {
    let world = World::new("replace-order");
    let target = private_dir(&world.root.join("data"));
    let issuer = Issuer::new(&world.root, "studio");
    let other = Issuer::new(&world.root, "other");
    let ports = ephemeral();

    let mut helper = Helper::start(&world, &target);
    let installed = helper.ask(
        "install",
        json!({
            "bundle": issuer.bundle(),
            "machine": "pi",
            "host": "127.0.0.1",
            "ports": { "gateway": ports.gateway, "dist": ports.dist },
        }),
    );
    assert_eq!(installed["ok"], json!(true), "{installed}");
    let before = fs::read(target.join("fleet/cookie")).expect("the installed cookie");

    // A bundle that parses as a `Bundle` and fails `validate_bundle`: the cookie is not
    // 64 lowercase hex, which is the very first thing `join` checks.
    let mut poisoned = other.bundle();
    poisoned["cookie"] = json!("not-a-cookie");
    let replaced = helper.ask(
        "install",
        json!({
            "bundle": poisoned,
            "machine": "pi",
            "host": "127.0.0.1",
            "replace": true,
        }),
    );
    assert_eq!(
        replaced["ok"],
        json!(false),
        "an invalid bundle must be refused: {replaced}"
    );
    assert_eq!(replaced["reason"], json!("bundle_invalid"), "{replaced}");

    // The refusal is not the finding. This is:
    assert!(
        target.join("fleet").exists(),
        "a refused `install` destroyed {}: the cookie, the shared CA key and this \
         machine's node key were deleted by an operation that then installed nothing",
        target.join("fleet").display()
    );
    assert_eq!(
        fs::read(target.join("fleet/cookie")).expect("the cookie that was there"),
        before,
        "a refused `install` replaced the fleet that was there"
    );
}

/// The same ordering, reached through the other half of `join`'s validation: a machine
/// name this build refuses to mint. Nothing about the bundle is wrong here at all.
#[test]
fn kr3_a_replace_install_refused_for_its_machine_name_still_destroyed_the_fleet() {
    let world = World::new("replace-name");
    let target = private_dir(&world.root.join("data"));
    let issuer = Issuer::new(&world.root, "studio");
    let other = Issuer::new(&world.root, "other");
    let ports = ephemeral();

    let mut helper = Helper::start(&world, &target);
    assert_eq!(
        helper.ask(
            "install",
            json!({
                "bundle": issuer.bundle(),
                "machine": "pi",
                "host": "127.0.0.1",
                "ports": { "gateway": ports.gateway, "dist": ports.dist },
            }),
        )["ok"],
        json!(true)
    );

    // `validate_joined_machine` refuses an upper-case name: "`Pi` and `pi` would be two
    // identities for one machine". It runs inside `join`, after the replace.
    let replaced = helper.ask(
        "install",
        json!({
            "bundle": other.bundle(),
            "machine": "PI",
            "host": "127.0.0.1",
            "replace": true,
        }),
    );
    assert_eq!(replaced["ok"], json!(false), "{replaced}");
    assert_eq!(replaced["reason"], json!("invalid_request"), "{replaced}");
    assert!(
        target.join("fleet").exists(),
        "a request refused for its machine name had already deleted the fleet directory"
    );
}

/// A pipe, as two owned halves. `std::io::pipe` is not on this floor's toolchain, so
/// this is the two-line `libc` version.
fn os_pipe() -> (fs::File, fs::File) {
    use std::os::fd::FromRawFd;

    let mut fds = [0_i32; 2];
    // SAFETY: `pipe` writes two descriptors into the array it is given and takes
    // nothing else; the descriptors are immediately given owning wrappers.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "a pipe");
    unsafe { (fs::File::from_raw_fd(fds[0]), fs::File::from_raw_fd(fds[1])) }
}
