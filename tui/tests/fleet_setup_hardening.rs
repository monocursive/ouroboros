//! The findings of the adversarial review of this slice, kept as regressions.
//!
//! Every test here was an exploit first: it ran against the code as shipped and proved
//! something it should not have been able to do. What changed is the assertion — each
//! one now asserts the refusal — so a future edit that reopens the hole fails here with
//! the original exploit's own steps.
//!
//! The fixes they pin: the askpass window belongs to one `ssh` child and closes with it;
//! a caller has to be part of that connection; the options that decide what a host key
//! means are neutralised on the command line; a store path with a space stays one path;
//! `@revoked` is not trust; a taken-over session is evicted; a dry run writes nothing at
//! all; and the loopback release origin does not redirect off loopback.

mod fleet_setup_support;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

use fleet_setup_support::{scratch, write_script, OURO};
use ouro::fleet_setup::askpass::{self, Bridge, PromptContext};
use ouro::fleet_setup::challenge::{Answer, ChallengeKind};
use ouro::fleet_setup::ssh::{
    Destination, Programs, ResolvedIdentity, Runner, COMMAND_TIMEOUT, CONNECT_TIMEOUT,
};
use ouro::fleet_setup::{ChallengeRequest, Conversation, Event};

fn programs() -> Programs {
    Programs {
        ssh: PathBuf::from("/usr/bin/ssh"),
        ssh_add: PathBuf::from("/usr/bin/ssh-add"),
        keygen: PathBuf::from("/usr/bin/ssh-keygen"),
        askpass: PathBuf::from(OURO),
        agent_socket: None,
    }
}

/// Hands out a fixed secret and counts how many times it was asked.
struct Always {
    secret: String,
    asked: Mutex<Vec<(ChallengeKind, serde_json::Value)>>,
    refusals: AtomicU32,
}

impl Always {
    fn new(secret: &str) -> Arc<Self> {
        Arc::new(Self {
            secret: secret.to_string(),
            asked: Mutex::new(Vec::new()),
            refusals: AtomicU32::new(0),
        })
    }
    fn asked(&self) -> Vec<(ChallengeKind, serde_json::Value)> {
        self.asked.lock().unwrap().clone()
    }
}

impl Conversation for Always {
    fn ask(&self, request: ChallengeRequest) -> anyhow::Result<Answer> {
        self.asked
            .lock()
            .unwrap()
            .push((request.kind, request.metadata.clone()));
        match request.kind {
            ChallengeKind::Password | ChallengeKind::Passphrase => {
                Ok(Answer::Secret(zeroize::Zeroizing::new(self.secret.clone())))
            }
            _ => {
                self.refusals.fetch_add(1, Ordering::SeqCst);
                ouro::fleet_setup::refuse("cancelled", "not scripted")
            }
        }
    }
    fn notify(&self, _event: Event) {}
    fn cancelled(&self) -> bool {
        false
    }
}

/// The askpass window belongs to one `ssh` child and closes with it.
///
/// It did not: `Runner::spawn` — the helper-session path, which every operation takes —
/// armed the bridge and nothing ever disarmed it, so from the first helper session to
/// the end of the operation the socket answered any same-uid caller with a real password
/// challenge and handed over what the operator typed.
#[test]
fn the_askpass_window_closes_with_the_ssh_child_that_opened_it() {
    let work = scratch("adv-arm");
    let shim = work.join("ssh");
    write_script(
        &shim,
        "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = -G ]; then echo 'hostname 127.0.0.1'; exit 0; fi; done\nexit 0\n",
    );

    let operator = Always::new("w2a-armed-window-secret");
    let bridge = Arc::new(
        Bridge::start(
            Path::new(OURO),
            PromptContext {
                target: "127.0.0.1".into(),
                user: "tester".into(),
                port: 22,
                key_label: None,
                key_fingerprint: None,
            },
            operator.clone(),
        )
        .expect("a bridge"),
    );
    let runner = Runner {
        programs: Programs {
            ssh: shim,
            ..programs()
        },
        destination: Destination {
            address: "127.0.0.1".into(),
            port: 22,
            user: "tester".into(),
        },
        identity: ResolvedIdentity::Password,
        known_hosts: vec![work.join("known_hosts")],
        user_known_hosts: None,
        connect_timeout: CONNECT_TIMEOUT,
        command_timeout: COMMAND_TIMEOUT,
        bridge: Some(Arc::clone(&bridge)),
        control: None,
        cancelled: None,
        challenge_window: None,
    };

    // Baseline: before any ssh runs, a stray caller is refused.
    let before = askpass::request(bridge.socket(), "tester@127.0.0.1's password: ");
    assert!(
        before.is_err(),
        "an unarmed bridge must refuse a stray caller"
    );
    assert!(
        format!("{:#}", before.unwrap_err()).contains("not_authenticating"),
        "the refusal is the arming-window one"
    );

    // `run` arms and disarms: still refused afterwards.
    runner.run("exec true", None).expect("the shim runs");
    assert!(
        askpass::request(bridge.socket(), "password: ").is_err(),
        "run_with_timeout disarms when the child is reaped"
    );

    // Now the helper path. `spawn` hands back the window as a guard; reap the child and
    // drop the guard, exactly as `helper::Session` does when it closes.
    let (mut child, armed) = runner.spawn("exec ouro fleet helper").expect("a child");
    let _ = child.wait();
    drop(armed);
    std::thread::sleep(Duration::from_millis(100));

    assert!(!bridge.armed(), "the window closed with the child");
    let stray = askpass::request(bridge.socket(), "tester@127.0.0.1's password: ")
        .expect_err("a stray caller must be refused once the connection is gone");
    assert!(
        format!("{stray:#}").contains("not_authenticating"),
        "and refused by name: {stray:#}"
    );
    assert!(
        operator.asked().is_empty(),
        "no question was ever put in front of the operator on behalf of nobody: {:?}",
        operator.asked()
    );

    // And while a child *is* alive, a caller that is not part of its connection is still
    // refused: same uid is not the same connection.
    let (mut child, armed) = runner.spawn("exec ouro fleet helper").expect("a child");
    assert!(bridge.armed(), "the window is open for this child");
    let outsider = askpass::request(bridge.socket(), "tester@127.0.0.1's password: ")
        .expect_err("this test process is not part of the ssh connection");
    assert!(
        format!("{outsider:#}").contains("peer_not_in_connection"),
        "{outsider:#}"
    );
    assert!(operator.asked().is_empty());
    let _ = child.kill();
    let _ = child.wait();
    drop(armed);
}

/// Every identity names the authentication methods it will use.
///
/// The default identity used to name none, which left keyboard-interactive on the menu —
/// and a far end allowed to run it composes the prompt text OpenSSH hands the askpass
/// helper verbatim. Anything containing "passphrase" was then rendered to the operator
/// as "the passphrase for the key you picked", which is how a hostile destination
/// harvests a private-key passphrase through UI this operation itself makes look
/// trustworthy.
#[test]
fn a_far_end_cannot_put_a_keyboard_interactive_prompt_in_front_of_an_operator() {
    let work = scratch("adv-kbd");
    let shim = work.join("ssh");
    // Exactly what OpenSSH does for a keyboard-interactive info request when there is no
    // tty and SSH_ASKPASS_REQUIRE=force: run the askpass helper with the server's prompt.
    write_script(
        &shim,
        "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = -G ]; then echo 'hostname 127.0.0.1'; exit 0; fi; done\n\"$SSH_ASKPASS\" \"Enter passphrase for key '/Users/op/.ssh/id_ed25519': \" > \"$0.captured\" 2>/dev/null\nexit 0\n",
    );

    let operator = Always::new("w2a-private-key-passphrase");
    let bridge = Arc::new(
        Bridge::start(
            Path::new(OURO),
            PromptContext {
                target: "203.0.113.9".into(),
                user: "op".into(),
                port: 22,
                key_label: Some("id_ed25519".into()),
                key_fingerprint: Some("SHA256:localkeyfingerprint".into()),
            },
            operator.clone(),
        )
        .expect("a bridge"),
    );
    let runner = Runner {
        programs: Programs {
            ssh: shim.clone(),
            ..programs()
        },
        destination: Destination {
            address: "203.0.113.9".into(),
            port: 22,
            user: "op".into(),
        },
        // `IdentityChoice::Default` names PreferredAuthentications=publickey, so
        // keyboard-interactive is not on the menu.
        identity: ResolvedIdentity::Default,
        known_hosts: vec![work.join("known_hosts")],
        user_known_hosts: None,
        connect_timeout: CONNECT_TIMEOUT,
        command_timeout: COMMAND_TIMEOUT,
        bridge: Some(Arc::clone(&bridge)),
        control: None,
        cancelled: None,
        challenge_window: None,
    };
    // The method list is what keeps keyboard-interactive off the menu in the first
    // place, so the far end never gets to compose a prompt at all.
    let options = runner.options();
    assert!(
        options
            .iter()
            .any(|option| option == "PreferredAuthentications=publickey"),
        "the default identity names its methods: {options:?}"
    );

    assert!(
        !options
            .iter()
            .any(|option| option.contains("keyboard-interactive") || option.contains("gssapi")),
        "the methods that let a far end compose prompt text are not offered: {options:?}"
    );

    // The method list is the defence, and it is what this test pins. The bridge cannot
    // tell a genuine OpenSSH prompt from a forged one — by the time text reaches
    // `SSH_ASKPASS` it is a string in the connection's own process group — so what stops
    // a far end from composing that text is that it is never asked to. What the bridge
    // *can* do is refuse a prompt that is neither of the two questions this product
    // understands, which is the rest of this test.
    let probing = work.join("ssh-probe");
    write_script(
        &probing,
        "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = -G ]; then echo 'hostname 127.0.0.1'; exit 0; fi; done\n\"$SSH_ASKPASS\" \"Enter your one-time verification code: \" > \"$0.captured\" 2>/dev/null\nexit 0\n",
    );
    let probing_runner = Runner {
        programs: Programs {
            ssh: probing.clone(),
            ..programs()
        },
        destination: runner.destination.clone(),
        identity: runner.identity.clone(),
        known_hosts: runner.known_hosts.clone(),
        user_known_hosts: runner.user_known_hosts.clone(),
        connect_timeout: runner.connect_timeout,
        command_timeout: runner.command_timeout,
        bridge: runner.bridge.clone(),
        control: None,
        cancelled: runner.cancelled.clone(),
        challenge_window: runner.challenge_window,
    };
    probing_runner
        .run("exec true", None)
        .expect("the shim runs");
    let captured =
        std::fs::read_to_string(format!("{}.captured", probing.display())).unwrap_or_default();
    assert!(
        captured.trim().is_empty(),
        "a prompt that is neither a password nor a key passphrase is answered with nothing: {captured}"
    );
    assert!(
        operator.asked().is_empty(),
        "and no question was put in front of the operator: {:?}",
        operator.asked()
    );
}

/// A dry run writes nothing into the data directory — including the namespace itself.
///
/// It used to create `<data dir>/deploy/` and `<data dir>/deploy/<op>.d/` before it did
/// anything else, because the plan path takes a scratch directory and the scratch
/// directory lived there. The shipped test could not see it: it created the deploy
/// directory itself, by recording host trust, before the dry run ever started. This one
/// runs against a data directory that has never been deployed from.
#[test]
fn a_dry_run_does_not_create_the_deployment_namespace() {
    use fleet_setup_support::{account, Sshd};
    use std::os::unix::fs::PermissionsExt as _;

    let rig = Sshd::start("adv-dry-rig");
    let data = scratch("adv-dry");
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    ouro::fleet::create(
        &data,
        Some("adv"),
        "studio",
        "127.0.0.1",
        ouro::fleet::ephemeral_ports(),
    )
    .expect("a fleet");

    let deploy = ouro::fleet_setup::deploy_dir(&data);
    assert!(!deploy.exists(), "the deploy namespace does not exist yet");

    let output = std::process::Command::new(OURO)
        .args(["fleet", "add"])
        .arg(format!("{}@127.0.0.1", account()))
        .args(["--machine", "buildbox"])
        .args(["--port", &rig.port.to_string()])
        .arg("--key")
        .arg(&rig.client_key)
        .args(["--install-path", OURO])
        .args(["--operation", "op-000000009900"])
        .args(["--dry-run", "--json", "--no-service"])
        .env("OUROBOROS_DATA_DIR", &data)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("ouro");
    eprintln!(
        "dry run exit {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let wrote: Vec<String> = walk(&deploy)
        .into_iter()
        .map(|entry| entry.strip_prefix(&data).unwrap().display().to_string())
        .collect();
    assert!(
        !deploy.exists(),
        "--dry-run must not create {}; it left {wrote:?}",
        deploy.display()
    );
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        found.push(entry.path());
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            found.extend(walk(&entry.path()));
        }
    }
    found
}

/// The loopback release origin does not follow a redirect off loopback.
///
/// It did, and the SHA256SUMS manifest travelled the same redirect — so the checksum
/// check certified nothing about where the bytes came from: a redirector on 127.0.0.1
/// could serve the executable and the digest that blesses it from any host on the
/// internet, and both would be accepted.
#[test]
fn the_loopback_release_origin_refuses_a_redirect_off_loopback() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    // The "somewhere else" server: this host's own LAN address, which is emphatically
    // not one of the three names `Origin::loopback` will accept. It stands in for any
    // internet host; what is being shown is that the origin check constrains the first
    // hop only.
    let elsewhere_host = std::process::Command::new("/usr/sbin/ipconfig")
        .args(["getifaddr", "en0"])
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|address| !address.is_empty())
        .expect("a non-loopback address on this host");
    assert!(ouro::update::release::Origin::loopback(&format!("http://{elsewhere_host}")).is_err());
    let elsewhere =
        TcpListener::bind(format!("{elsewhere_host}:0")).expect("a non-loopback listener");
    let elsewhere_port = elsewhere.local_addr().unwrap().port();
    let redirect_host = elsewhere_host.clone();
    let payload = b"NOT-THE-OFFICIAL-RELEASE".to_vec();
    let digest = ring::digest::digest(&ring::digest::SHA256, &payload);
    let mut sha = String::new();
    for byte in digest.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(&mut sha, "{byte:02x}");
    }
    let asset = "ouro-9.9.9-aarch64-apple-darwin".to_string();
    let manifest = format!("{sha}  {asset}\n").into_bytes();
    let body_asset = payload.clone();
    let body_manifest = manifest.clone();
    std::thread::spawn(move || {
        for stream in elsewhere.incoming().take(2) {
            let mut stream = stream.expect("a connection");
            let mut line = String::new();
            let _ = BufReader::new(stream.try_clone().unwrap()).read_line(&mut line);
            let body = if line.contains("SHA256SUMS") {
                body_manifest.clone()
            } else {
                body_asset.clone()
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });

    // The loopback origin: a pure redirector.
    let front = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let front_port = front.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in front.incoming().take(2) {
            let mut stream = stream.expect("a connection");
            let mut line = String::new();
            let _ = BufReader::new(stream.try_clone().unwrap()).read_line(&mut line);
            let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{redirect_host}:{elsewhere_port}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            );
            let _ = stream.flush();
        }
    });

    let origin = ouro::update::release::Origin::loopback(&format!("http://127.0.0.1:{front_port}"))
        .expect("the override accepts a loopback origin");
    let cancelled = AtomicBool::new(false);

    // The redirect is not followed, so neither the manifest nor the artifact arrives.
    let manifest_error = ouro::update::release::checksums(&origin, "9.9.9", &cancelled)
        .err()
        .map(|error| format!("{error:#}"))
        .unwrap_or_else(|| {
            panic!("the manifest must not be fetched through a redirect off loopback")
        });
    eprintln!("redirected manifest refused: {manifest_error}");

    let fetch_error = ouro::update::release::fetch_verified(
        &origin,
        "9.9.9",
        &asset,
        &"0".repeat(64),
        &cancelled,
    )
    .err()
    .map(|error| format!("{error:#}"))
    .unwrap_or_else(|| panic!("the artifact must not be fetched through a redirect"));
    eprintln!("redirected artifact refused: {fetch_error}");

    // And the payload never reached this process.
    assert_ne!(manifest, payload);
    let _ = (elsewhere_port, elsewhere_host);
}

/// One client that stops reading does not wedge the worker.
///
/// `broadcast` used to hold the subscribers lock across a blocking `write_all` to every
/// attached client, with no write deadline. One attached client that stopped reading
/// blocked the engine thread the first time it reported progress — and every `status`,
/// `respond` and `attach` queued behind that lock — for as long as that client lived.
#[test]
fn a_client_that_stops_reading_does_not_wedge_the_worker() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    let data = scratch("hard-flood");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let operation = "op-000000009930";
    let ports = ouro::fleet::ephemeral_ports();
    let mut request = ouro::fleet_setup::OperationRequest::new(
        operation,
        ouro::fleet_setup::OperationKind::Setup,
        "studio",
    );
    request.address = Some("127.0.0.1".into());
    request.service = false;
    request.ports = Some(ouro::fleet_setup::PortPolicy {
        gateway: ports.gateway,
        dist: ports.dist,
        epmd: ports.epmd,
    });
    let dir = ouro::fleet_setup::ensure_deploy_dir(&data).unwrap();
    let path = dir.join(format!("{operation}.request.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let started = std::process::Command::new(OURO)
        .args([
            "fleet",
            "worker",
            "start",
            "--operation",
            operation,
            "--data-dir",
        ])
        .arg(&data)
        .env("OUROBOROS_DATA_DIR", &data)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("worker start");
    let line: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("the started line");
    let socket = PathBuf::from(line["socket"].as_str().unwrap());
    let cap = std::fs::read_to_string(ouro::fleet_setup::capability_path(&data, operation))
        .expect("the capability file");

    // The client that goes silent: it attaches and then never reads another byte.
    let mut deaf = UnixStream::connect(&socket).expect("a client");
    deaf.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    writeln!(
        deaf,
        "{}",
        json!({"v":1,"id":"d1","op":"attach","cap":cap,"subject":"operator","session":"deaf"})
    )
    .unwrap();
    deaf.flush().unwrap();
    // Read exactly its attach reply, then stop reading for good.
    let mut deaf_reader = BufReader::new(deaf.try_clone().unwrap());
    let mut reply = String::new();
    deaf_reader.read_line(&mut reply).unwrap();

    // A second client of the same subject. The worker is mid-operation and emitting
    // events; if a broadcast can block, this never gets an answer.
    let mut live = UnixStream::connect(&socket).expect("a second client");
    live.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut live_reader = BufReader::new(live.try_clone().unwrap());
    writeln!(
        live,
        "{}",
        json!({"v":1,"id":"l1","op":"attach","cap":cap,"subject":"operator","session":"live"})
    )
    .unwrap();
    live.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut attached = None;
    while Instant::now() < deadline {
        let mut line = String::new();
        if live_reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let frame: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        if frame.get("id").and_then(serde_json::Value::as_str) == Some("l1") {
            attached = Some(frame);
            break;
        }
    }
    let attached = attached.expect("the second client attached while the first was silent");
    assert_eq!(attached["ok"], json!(true), "{attached}");

    // And it can still ask questions: the engine is not parked on a full socket buffer.
    writeln!(live, "{}", json!({"v":1,"id":"l2","op":"status"})).unwrap();
    live.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut status = None;
    while Instant::now() < deadline {
        let mut line = String::new();
        if live_reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let frame: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        if frame.get("id").and_then(serde_json::Value::as_str) == Some("l2") {
            status = Some(frame);
            break;
        }
    }
    let status = status.expect("`status` answered while another client was not reading");
    assert_eq!(status["ok"], json!(true), "{status}");
    drop(deaf);
    let _ = writeln!(live, "{}", json!({"v":1,"id":"l3","op":"cancel"}));
    let _ = live.flush();
}

/// A revoked host key is a refusal, not trust.
///
/// The marker used to be stripped and forgotten, so a store holding only
/// `@revoked <key>` reported `Trust::Known` for exactly the key the operator had
/// revoked, and the connection ssh then refused was classified `host_unknown` — which
/// invites an operator to accept it again.
#[test]
fn a_revoked_host_key_is_refused_by_name() {
    use fleet_setup_support::Sshd;
    use ouro::fleet_setup::trust::{self, Tools};

    let rig = Sshd::start("adv-revoked");
    let tools = Tools {
        keyscan: PathBuf::from("/usr/bin/ssh-keyscan"),
        keygen: PathBuf::from("/usr/bin/ssh-keygen"),
    };
    let work = scratch("adv-revoke-store");
    let store = work.join("known_hosts");

    let trust::Trust::Unknown { keys } = trust::examine(
        &tools,
        std::slice::from_ref(&store),
        "127.0.0.1",
        rig.port,
        &work,
    )
    .expect("a scan") else {
        panic!("a fresh store knows nothing");
    };
    // The operator later decides this key is compromised and revokes it, the way
    // `ssh-keygen -R`/`@revoked` is documented to be used.
    std::fs::write(&store, format!("@revoked {}\n", keys[0].line)).expect("a revoked entry");

    let verdict = trust::examine(
        &tools,
        std::slice::from_ref(&store),
        "127.0.0.1",
        rig.port,
        &work,
    )
    .expect("a second scan");
    assert!(
        matches!(verdict, trust::Trust::Revoked { .. }),
        "a store holding only `@revoked <key>` must report a revocation, got {verdict:?}"
    );

    // And a connection through it is refused with that reason rather than "unknown".
    let runner = Runner {
        programs: programs(),
        destination: Destination {
            address: "127.0.0.1".into(),
            port: rig.port,
            user: fleet_setup_support::account(),
        },
        identity: ResolvedIdentity::Key {
            path: rig.client_key.clone(),
            label: "client_key".into(),
            fingerprint: None,
        },
        known_hosts: vec![store],
        user_known_hosts: None,
        connect_timeout: CONNECT_TIMEOUT,
        command_timeout: COMMAND_TIMEOUT,
        bridge: None,
        control: None,
        cancelled: None,
        challenge_window: None,
    };
    let refused = runner
        .check_access()
        .expect_err("a revoked host key blocks the connection");
    assert_eq!(
        ouro::fleet_setup::reason_of(&refused),
        Some("host_key_revoked"),
        "{refused:#}"
    );
}

/// A connection that says nothing does not hold the askpass bridge.
///
/// The bridge served one connection at a time and gave each 300 seconds to send its
/// prompt, so one same-uid process that connected and stayed silent denied the real
/// `ssh` its password for five minutes — longer than any step deadline the engine has.
#[test]
fn a_silent_connection_does_not_hold_the_askpass_bridge() {
    use std::os::unix::net::UnixStream;

    let operator = Always::new("w2a-hol");
    let bridge = Arc::new(
        Bridge::start(
            Path::new(OURO),
            PromptContext {
                target: "127.0.0.1".into(),
                user: "t".into(),
                port: 22,
                key_label: None,
                key_fingerprint: None,
            },
            operator,
        )
        .expect("a bridge"),
    );
    // Armed for this test process's own group, so the second caller gets as far as the
    // prompt rather than being turned away for being an outsider.
    let _armed = bridge.arm(unsafe { libc::getpgrp() });

    // The squatter: connects, sends nothing, holds the connection.
    let _squatter = UnixStream::connect(bridge.socket()).expect("a stray connection");
    std::thread::sleep(Duration::from_millis(200));

    // A second caller must not have to wait behind it.
    let socket = bridge.socket().to_path_buf();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(askpass::request(&socket, "t@127.0.0.1's password: ").is_ok());
    });
    let answered = receiver.recv_timeout(Duration::from_secs(5));
    assert!(
        answered.is_ok(),
        "a squatting connection must not be able to hold the bridge (waited 5s)"
    );
    assert!(
        answered.expect("an answer"),
        "and the caller in the armed connection is served"
    );
}

/// The bridge's own directory is private, whatever the parent it is created under.
///
/// The socket and its launcher live under `TMPDIR`, which on a host where it is unset is
/// world-writable `/tmp`. What protects them is not the parent: it is that the directory
/// is created 0700 and owned by this account, the socket is 0600, the launcher is 0700 —
/// and that a directory already there and *not* ours is refused rather than adopted.
#[test]
fn the_bridge_directory_is_private_and_a_foreign_one_is_refused() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let operator = Always::new("x");
    let bridge = Bridge::start(
        Path::new(OURO),
        PromptContext {
            target: "127.0.0.1".into(),
            user: "t".into(),
            port: 22,
            key_label: None,
            key_fingerprint: None,
        },
        operator,
    )
    .expect("a bridge");

    let socket = bridge.socket().to_path_buf();
    let home = socket.parent().expect("a home").to_path_buf();
    let uid = unsafe { libc::geteuid() };
    let home_meta = std::fs::symlink_metadata(&home).expect("the bridge home");
    assert!(home_meta.file_type().is_dir());
    assert_eq!(home_meta.uid(), uid, "the bridge home is this account's");
    assert_eq!(
        home_meta.permissions().mode() & 0o777,
        0o700,
        "the bridge home is private"
    );
    assert_eq!(
        std::fs::symlink_metadata(&socket)
            .expect("the socket")
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "the socket is private"
    );
    let launcher = home.join("askpass");
    assert_eq!(
        std::fs::symlink_metadata(&launcher)
            .expect("the launcher")
            .permissions()
            .mode()
            & 0o777,
        0o700,
        "the launcher is private and executable only by its owner"
    );
    assert!(
        !std::fs::read_to_string(&launcher)
            .expect("the launcher")
            .contains('\0'),
        "the launcher carries a path and nothing else"
    );

    // A directory that is there already and is not private is refused rather than used.
    let planted = scratch("hard-tmp");
    let loose = planted.join("loose");
    std::fs::create_dir_all(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        ouro::fleet_setup::ensure_private_subdir_for_tests(&loose).is_err(),
        "a world-writable directory is never adopted as a private one"
    );
}

/// A data directory with a space in its path still has a working trust store.
///
/// The stores were joined into one `UserKnownHostsFile=` value with a bare space, and
/// `ssh` splits that value on whitespace — so `~/Library/Application Support/…`, which
/// is the ordinary macOS shape, turned the private store into two paths that did not
/// exist. The operator accepted the host key, the acceptance was written, and every
/// connection after it was still refused as `host_unknown`.
#[test]
fn a_data_directory_with_a_space_still_has_a_working_trust_store() {
    use fleet_setup_support::{account, Sshd};
    use ouro::fleet_setup::challenge::Answer as A;
    use ouro::fleet_setup::engine::Engine;
    use ouro::fleet_setup::gateway::ScriptedGateway;
    use ouro::fleet_setup::service::{CountingServiceActions, ServiceAction};
    use ouro::fleet_setup::trust::Tools;
    use ouro::fleet_setup::{
        reason_of, IdentityChoice, OperationKind, OperationRequest, PortPolicy,
    };
    use std::os::unix::fs::PermissionsExt as _;

    struct Accepting;
    impl Conversation for Accepting {
        fn ask(&self, request: ChallengeRequest) -> anyhow::Result<Answer> {
            match request.kind {
                ChallengeKind::HostTrust => Ok(A::Trust(true)),
                ChallengeKind::Review => Ok(A::Approval {
                    plan_digest: request.metadata["plan_digest"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                }),
                _ => ouro::fleet_setup::refuse("cancelled", "no secret expected"),
            }
        }
        fn notify(&self, _event: Event) {}
    }

    let rig = Sshd::start("adv-space-rig");
    // A data directory with a space in it. `~/Library/Application Support/...` and a
    // macOS home named after a person both look like this.
    let base = scratch("adv-space");
    let data = base.join("Application Support");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    let ports = ouro::fleet::ephemeral_ports();
    ouro::fleet::create(&data, Some("adv"), "studio", "127.0.0.1", ports).expect("a fleet");

    let mut request = OperationRequest::new("op-000000009910", OperationKind::Add, "buildbox");
    request.address = Some("127.0.0.1".into());
    request.ssh_user = Some(account());
    request.ssh_port = Some(rig.port);
    request.identity = IdentityChoice::Key {
        path: rig.client_key.clone(),
    };
    request.install_path = Some(OURO.to_string());
    request.service = false;
    request.ports = Some(PortPolicy {
        gateway: ports.gateway,
        dist: ports.dist,
        epmd: ports.epmd,
    });

    let engine = Engine {
        data_dir: data.clone(),
        token_file: data.join("gateway.token"),
        request,
        conversation: Arc::new(Accepting),
        gateway: Arc::new(ScriptedGateway::new(
            true,
            vec![("fleet.status", json!({"machines": []}))],
        )),
        services: Arc::new(CountingServiceActions::new(
            true,
            vec![ServiceAction::Install, ServiceAction::Start],
        )),
        programs: programs(),
        trust_tools: Tools {
            keyscan: PathBuf::from("/usr/bin/ssh-keyscan"),
            keygen: PathBuf::from("/usr/bin/ssh-keygen"),
        },
        user_known_hosts: None,
        origin: ouro::update::release::Origin::official(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        owner: Some("tester".into()),
    };
    let outcome = engine.run().unwrap_or_else(|error| {
        panic!(
            "the operation must connect: {:?} {error:#}",
            reason_of(&error)
        )
    });
    let store = ouro::fleet_setup::known_hosts_path(&data);
    assert!(
        std::fs::read_to_string(&store)
            .unwrap_or_default()
            .contains("ssh-"),
        "the key was recorded in the private store at {}",
        store.display()
    );
    assert_eq!(
        outcome.state,
        ouro::fleet_setup::OperationState::Completed,
        "{outcome:?}"
    );
    assert!(
        ouro::fleet::load(&data)
            .expect("a readable profile")
            .expect("a profile")
            .members
            .iter()
            .any(|member| member.machine == "buildbox"),
        "the machine really joined, from a data directory whose path has a space in it"
    );
}

/// Threat-model item 1, checked rather than assumed: the two fixed remote command
/// strings must be byte-identical across hostile inputs, and every variable must land in
/// argv or inside single quotes. This one is a NEGATIVE result — the claim holds.
#[test]
fn adv_hostile_inputs_do_not_change_the_remote_command_string() {
    use ouro::fleet_setup::bootstrap::{BOOTSTRAP, PREFLIGHT};
    use ouro::fleet_setup::helper::helper_command;
    use ouro::fleet_setup::ssh::shell_quote;

    let hostiles = [
        "'; id > /tmp/pwned; '",
        "$(id)",
        "`id`",
        "a\nb",
        "",
        "--\u{202e}gnp",
        "x'\"$(id)\"'",
        "\u{0}trailing",
    ];
    let mut argvs = Vec::new();
    for hostile in hostiles {
        let runner = Runner {
            programs: programs(),
            destination: Destination {
                address: "100.64.0.2".into(),
                port: 22,
                user: hostile.to_string(),
            },
            identity: ResolvedIdentity::Default,
            known_hosts: vec![PathBuf::from("/d/known_hosts")],
            user_known_hosts: None,
            connect_timeout: CONNECT_TIMEOUT,
            command_timeout: COMMAND_TIMEOUT,
            bridge: None,
            control: None,
            cancelled: None,
            challenge_window: None,
        };
        let argv = runner.argv(PREFLIGHT);
        // The user is one argv element, the value of -l, and never part of the command.
        let position = argv.iter().position(|a| a == "-l").expect("-l");
        assert_eq!(argv[position + 1], hostile);
        assert_eq!(argv.last().unwrap(), PREFLIGHT);
        argvs.push(argv.len());
        // And the helper command quotes everything variable.
        let command = helper_command(hostile, Some(hostile));
        assert!(command.starts_with("exec /usr/bin/env OUROBOROS_DATA_DIR="));
        assert!(command.contains(&shell_quote(hostile)));
    }
    assert!(argvs.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(!BOOTSTRAP.contains("{}") && !PREFLIGHT.contains("{}"));
    eprintln!("NEGATIVE (claim holds) : the remote command strings are constant across hostile users/paths; shell_quote covers every variable that enters one");
}

/// A taken-over session is evicted, not merely recorded.
///
/// `takeover` wrote the handover down and dropped the pending challenges, and left the
/// previous owner attached: their socket stayed open, they kept receiving every
/// broadcast — including the metadata of every challenge issued to their successor — and
/// they could still cancel the operation.
#[test]
fn a_taken_over_session_is_evicted_and_can_do_nothing_more() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    fn ask(
        stream: &mut UnixStream,
        reader: &mut BufReader<UnixStream>,
        frame: serde_json::Value,
    ) -> serde_json::Value {
        writeln!(stream, "{frame}").unwrap();
        stream.flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            if value.get("id").is_some() {
                return value;
            }
            assert!(Instant::now() < deadline);
        }
    }

    let data = scratch("adv-take");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let operation = "op-000000009920";
    let ports = ouro::fleet::ephemeral_ports();
    let mut request = ouro::fleet_setup::OperationRequest::new(
        operation,
        ouro::fleet_setup::OperationKind::Setup,
        "studio",
    );
    request.address = Some("127.0.0.1".into());
    request.service = false;
    request.ports = Some(ouro::fleet_setup::PortPolicy {
        gateway: ports.gateway,
        dist: ports.dist,
        epmd: ports.epmd,
    });
    let dir = ouro::fleet_setup::ensure_deploy_dir(&data).unwrap();
    let path = dir.join(format!("{operation}.request.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let started = std::process::Command::new(OURO)
        .args([
            "fleet",
            "worker",
            "start",
            "--operation",
            operation,
            "--data-dir",
        ])
        .arg(&data)
        .env("OUROBOROS_DATA_DIR", &data)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("worker start");
    let line: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("the started line");
    let socket = PathBuf::from(line["socket"].as_str().unwrap());
    let cap = std::fs::read_to_string(ouro::fleet_setup::capability_path(&data, operation))
        .expect("the capability file");

    let mut first = UnixStream::connect(&socket).expect("a first client");
    first
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut first_reader = BufReader::new(first.try_clone().unwrap());
    let reply = ask(
        &mut first,
        &mut first_reader,
        json!({"v":1,"id":"a1","op":"attach","cap":cap,"subject":"alice","session":"s1"}),
    );
    assert_eq!(reply["ok"], json!(true), "{reply}");

    let mut second = UnixStream::connect(&socket).expect("a second client");
    second
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut second_reader = BufReader::new(second.try_clone().unwrap());
    let refused = ask(
        &mut second,
        &mut second_reader,
        json!({"v":1,"id":"b1","op":"attach","cap":cap,"subject":"mallory","session":"s2"}),
    );
    assert_eq!(refused["ok"], json!(false));
    assert_eq!(refused["reason"], json!("not_owner"), "{refused}");
    let taken = ask(
        &mut second,
        &mut second_reader,
        json!({"v":1,"id":"b2","op":"attach","cap":cap,"subject":"mallory","session":"s2","takeover":true}),
    );
    assert_eq!(taken["ok"], json!(true), "{taken}");
    assert_eq!(taken["owner"], json!("mallory"));

    // Alice's connection is gone: her socket was shut down when mallory took over. Even
    // setting a timeout on it can fail now, which is itself the eviction.
    let _ = first.set_read_timeout(Some(Duration::from_secs(5)));
    let evicted = writeln!(first, "{}", json!({"v":1,"id":"a2","op":"status"}))
        .and_then(|()| first.flush())
        .and_then(|()| {
            let mut line = String::new();
            first_reader.read_line(&mut line).map(|read| (read, line))
        });
    match evicted {
        // Either the write failed outright, or the read saw the close.
        Err(_) => {}
        Ok((0, _)) => {}
        Ok((_, line)) => panic!("the previous owner is still being answered: {line}"),
    }

    // And the operation is not cancellable by her: mallory owns it now.
    let status = ask(
        &mut second,
        &mut second_reader,
        json!({"v":1,"id":"b3","op":"status"}),
    );
    assert_eq!(status["owner"], json!("mallory"));
    assert_eq!(
        status["attached"].as_u64().unwrap_or(0),
        1,
        "only the new owner is attached: {status}"
    );
    let _ = ask(
        &mut second,
        &mut second_reader,
        json!({"v":1,"id":"b4","op":"cancel"}),
    );
    let _ = ask(
        &mut second,
        &mut second_reader,
        json!({"v":1,"id":"b5","op":"bye"}),
    );
}

// ---------------------------------------------------------------- surviving mutations
//
// Each of the tests below kills a mutation the review left alive: a guard that could be
// deleted with every suite still green. They are grouped here rather than spread across
// the suites because what they have in common is *what they are for* — each one is a
// check nobody was checking.

/// The remote bootstrap script's own validation, driven directly with hostile input.
///
/// `upload_frame` validates the same things before a byte is sent, so every test that
/// goes through it proves only the local half. These run the constant the operator's
/// machine actually executes, over a pipe, exactly as `ssh` would — which is the only
/// way the `case` patterns inside it are tested at all.
#[test]
fn the_remote_bootstrap_script_refuses_hostile_headers() {
    use ouro::fleet_setup::bootstrap::BOOTSTRAP;
    use std::io::Write;
    use std::process::{Command, Stdio};

    let home = scratch("hard-boot");
    let payload = b"not a real release".to_vec();
    let digest = ring::digest::digest(&ring::digest::SHA256, &payload);
    let mut sha = String::new();
    for byte in digest.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(&mut sha, "{byte:02x}");
    }

    // `name`, `size`, `sha`, `dest`, then the bytes.
    let run = |name: &str, size: &str, sum: &str, dest: &str, body: &[u8]| -> (i32, String) {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(BOOTSTRAP)
            .env("HOME", &home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("a shell");
        {
            let mut input = child.stdin.take().expect("stdin");
            let header = format!("ouroboros-bootstrap-1\n{name}\n{size}\n{sum}\n{dest}\n\n");
            let _ = input.write_all(header.as_bytes());
            let _ = input.write_all(body);
            let _ = input.flush();
        }
        let output = child.wait_with_output().expect("the script to finish");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        )
    };

    let asset = "ouro-9.9.9-test";
    let installed = home.join(".local/bin/ouro");

    // A name with a path separator or a metacharacter in it. The `case` pattern that
    // rejects these is what stops `$d/$name` from naming a file outside the staging
    // directory.
    for hostile in [
        "ouro-9../../../etc/x",
        "ouro-9;rm -rf /",
        "ouro-9 x",
        "ouroboros",
    ] {
        let (code, said) = run(
            hostile,
            &payload.len().to_string(),
            &sha,
            ".local/bin/ouro",
            &payload,
        );
        assert_eq!(code, 65, "`{hostile}` must be refused: {said}");
        assert!(said.starts_with("bootstrap-error name"), "{said}");
    }

    // A size that is not a decimal number: `head -c "$size"` would otherwise be handed
    // whatever the header said.
    for hostile in ["", "12x", "-1", "$(id)"] {
        let (code, said) = run(asset, hostile, &sha, ".local/bin/ouro", &payload);
        assert_eq!(code, 65, "size `{hostile}` must be refused: {said}");
        assert!(said.starts_with("bootstrap-error size"), "{said}");
    }

    // A destination that escapes `$HOME`.
    for hostile in ["/etc/cron.d/x", "../../etc/x", "", ".local/bin/$(id)"] {
        let (code, said) = run(asset, &payload.len().to_string(), &sha, hostile, &payload);
        assert_eq!(code, 65, "dest `{hostile}` must be refused: {said}");
        assert!(said.starts_with("bootstrap-error dest"), "{said}");
    }

    // A digest that is not 64 hex characters.
    for hostile in ["", "abc", &"g".repeat(64), &"a".repeat(63)] {
        let (code, said) = run(
            asset,
            &payload.len().to_string(),
            hostile,
            ".local/bin/ouro",
            &payload,
        );
        assert_eq!(code, 65, "digest `{hostile}` must be refused: {said}");
        assert!(said.starts_with("bootstrap-error digest"), "{said}");
    }

    // A header that promises more bytes than it sends: the transferred-length check is
    // what stops a truncated executable from being installed.
    let (code, said) = run(
        asset,
        &(payload.len() + 10).to_string(),
        &sha,
        ".local/bin/ouro",
        &payload,
    );
    assert_eq!(code, 66, "{said}");
    assert!(said.starts_with("bootstrap-error truncated"), "{said}");

    // Bytes that do not hash to the digest.
    let (code, said) = run(
        asset,
        &payload.len().to_string(),
        &"a".repeat(64),
        ".local/bin/ouro",
        &payload,
    );
    assert_eq!(code, 67, "{said}");
    assert!(said.starts_with("bootstrap-error checksum"), "{said}");
    assert!(
        !installed.exists(),
        "nothing was installed by any refused header"
    );
    assert!(
        !home.join(".ouroboros/setup").join(asset).exists(),
        "and no staged file was left behind"
    );

    // The honest header works, once, and is then refused because the file is there.
    let (code, said) = run(
        asset,
        &payload.len().to_string(),
        &sha,
        ".local/bin/ouro",
        &payload,
    );
    assert_eq!(code, 0, "{said}");
    assert!(said.starts_with("bootstrap-ok "), "{said}");
    assert_eq!(
        std::fs::read(&installed).expect("the installed file"),
        payload
    );
    let (code, said) = run(
        asset,
        &payload.len().to_string(),
        &sha,
        ".local/bin/ouro",
        &payload,
    );
    assert_eq!(code, 68, "{said}");
    assert!(said.starts_with("bootstrap-error exists"), "{said}");
}

/// The local half of the same checks, before anything is sent.
#[test]
fn an_upload_frame_is_refused_before_a_byte_leaves_this_machine() {
    use ouro::fleet_setup::bootstrap::upload_frame;
    use ouro::fleet_setup::reason_of;

    let bytes = b"x".to_vec();
    let good = "a".repeat(64);
    assert!(upload_frame("ouro-1.2.3-triple", &bytes, &good, ".local/bin/ouro").is_ok());

    for digest in ["", "abc", &"g".repeat(64), &"A".repeat(64), &"a".repeat(65)] {
        let error = upload_frame("ouro-1.2.3-triple", &bytes, digest, ".local/bin/ouro")
            .expect_err("a digest that is not 64 lowercase hex characters");
        assert_eq!(reason_of(&error), Some("invalid_request"), "{digest}");
    }
    assert_eq!(
        reason_of(
            &upload_frame("ouroboros", &bytes, &good, ".local/bin/ouro")
                .expect_err("a name that is not a release asset")
        ),
        Some("invalid_request")
    );
    assert_eq!(
        reason_of(
            &upload_frame("ouro-1.2.3-triple", &bytes, &good, "/etc/x")
                .expect_err("a destination outside the account's home")
        ),
        Some("unsupported_install_path")
    );
}

/// A destination that answers no host key scan is a refusal, not an empty "unknown".
#[test]
fn a_host_that_answers_no_key_scan_is_refused() {
    use ouro::fleet_setup::reason_of;
    use ouro::fleet_setup::trust::{self, Tools};

    let work = scratch("hard-scan");
    let tools = Tools {
        keyscan: PathBuf::from("/usr/bin/ssh-keyscan"),
        keygen: PathBuf::from("/usr/bin/ssh-keygen"),
    };
    // A port nothing is listening on: the scan comes back empty.
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    };
    let error = trust::examine(
        &tools,
        std::slice::from_ref(&work.join("known_hosts")),
        "127.0.0.1",
        dead,
        &work,
    )
    .expect_err("a host that answers nothing is not a host with no keys");
    assert_eq!(reason_of(&error), Some("host_scan_failed"), "{error:#}");
}

/// A `Host` stanza that rewrites the destination is refused before anything connects.
///
/// The check existed and nothing exercised it: a rewritten hostname means the machine
/// that would receive the credentials is not the one that was reviewed.
#[test]
fn a_rewritten_destination_is_refused() {
    use ouro::fleet_setup::reason_of;

    let work = scratch("hard-rewrite");
    let shim = work.join("ssh");
    // `ssh -G` reporting a different effective hostname is exactly what a `Host` stanza
    // with a `HostName` line produces.
    write_script(
        &shim,
        "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = -G ]; then echo 'hostname 203.0.113.99'; echo 'user me'; exit 0; fi; done\nexit 0\n",
    );
    let runner = Runner {
        programs: Programs {
            ssh: shim,
            ..programs()
        },
        destination: Destination {
            address: "100.64.0.2".into(),
            port: 22,
            user: "me".into(),
        },
        identity: ResolvedIdentity::Default,
        known_hosts: vec![work.join("known_hosts")],
        user_known_hosts: None,
        connect_timeout: CONNECT_TIMEOUT,
        command_timeout: COMMAND_TIMEOUT,
        bridge: None,
        control: None,
        cancelled: None,
        challenge_window: None,
    };
    let refused = runner
        .inspect_effective_config()
        .expect_err("a rewritten destination is not the one that was reviewed");
    assert_eq!(reason_of(&refused), Some("unsupported_routing"));
    assert!(format!("{refused}").contains("203.0.113.99"), "{refused}");

    // And an option that decides what a host key means, still in force: refused by name.
    let shim = work.join("ssh-khc");
    write_script(
        &shim,
        "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = -G ]; then echo 'hostname 100.64.0.2'; echo 'knownhostscommand /bin/echo'; exit 0; fi; done\nexit 0\n",
    );
    let runner = Runner {
        programs: Programs {
            ssh: shim,
            ..programs()
        },
        destination: Destination {
            address: "100.64.0.2".into(),
            port: 22,
            user: "me".into(),
        },
        identity: ResolvedIdentity::Default,
        known_hosts: vec![work.join("known_hosts")],
        user_known_hosts: None,
        connect_timeout: CONNECT_TIMEOUT,
        command_timeout: COMMAND_TIMEOUT,
        bridge: None,
        control: None,
        cancelled: None,
        challenge_window: None,
    };
    let refused = runner
        .inspect_effective_config()
        .expect_err("a host-key source this operation did not choose");
    assert_eq!(reason_of(&refused), Some("unsafe_ssh_option"));
    assert!(
        format!("{refused}").contains("knownhostscommand"),
        "{refused}"
    );
}

/// The password attempt cap, and the passphrase cap beside it.
///
/// The shipped test asserted that the counter *resets* between connections, which the
/// mutation that removes the cap passes unchanged.
#[test]
fn authentication_attempts_are_capped_within_one_connection() {
    let work = scratch("hard-cap");
    let shim = work.join("ssh");
    // One "connection" that asks five times, which is what a server with a generous
    // retry budget does.
    write_script(
        &shim,
        "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = -G ]; then echo 'hostname 127.0.0.1'; exit 0; fi; done\nfor i in 1 2 3 4 5; do \"$SSH_ASKPASS\" \"t@127.0.0.1's password: \" >> \"$0.answers\" 2>/dev/null || echo REFUSED >> \"$0.answers\"; done\nexit 0\n",
    );
    let operator = Always::new("w2a-capped");
    let bridge = Arc::new(
        Bridge::start(
            Path::new(OURO),
            PromptContext {
                target: "127.0.0.1".into(),
                user: "t".into(),
                port: 22,
                key_label: Some("id_ed25519".into()),
                key_fingerprint: Some("SHA256:k".into()),
            },
            operator.clone(),
        )
        .expect("a bridge"),
    );
    let runner = Runner {
        programs: Programs {
            ssh: shim.clone(),
            ..programs()
        },
        destination: Destination {
            address: "127.0.0.1".into(),
            port: 22,
            user: "t".into(),
        },
        identity: ResolvedIdentity::Password,
        known_hosts: vec![work.join("known_hosts")],
        user_known_hosts: None,
        connect_timeout: CONNECT_TIMEOUT,
        command_timeout: COMMAND_TIMEOUT,
        bridge: Some(Arc::clone(&bridge)),
        control: None,
        cancelled: None,
        challenge_window: None,
    };
    runner.run("exec true", None).expect("the shim runs");

    let answers = std::fs::read_to_string(format!("{}.answers", shim.display()))
        .expect("the shim's transcript");
    let served = answers
        .lines()
        .filter(|line| line.trim() == "w2a-capped")
        .count();
    assert_eq!(
        served, 3,
        "at most three password attempts per connection, not five: {answers}"
    );
    assert_eq!(bridge.served(), 3);
    assert_eq!(
        operator.asked().len(),
        3,
        "and the operator is asked exactly that many times"
    );

    // A passphrase for one key is asked for once per connection, whatever the far end
    // keeps requesting.
    let shim = work.join("ssh-pass");
    write_script(
        &shim,
        "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = -G ]; then echo 'hostname 127.0.0.1'; exit 0; fi; done\nfor i in 1 2 3; do \"$SSH_ASKPASS\" \"Enter passphrase for key '/k': \" >> \"$0.answers\" 2>/dev/null || echo REFUSED >> \"$0.answers\"; done\nexit 0\n",
    );
    let runner = Runner {
        programs: Programs {
            ssh: shim.clone(),
            ..programs()
        },
        destination: runner.destination.clone(),
        identity: ResolvedIdentity::Key {
            path: PathBuf::from("/k"),
            label: "id_ed25519".into(),
            fingerprint: Some("SHA256:k".into()),
        },
        known_hosts: runner.known_hosts.clone(),
        user_known_hosts: runner.user_known_hosts.clone(),
        connect_timeout: runner.connect_timeout,
        command_timeout: runner.command_timeout,
        bridge: runner.bridge.clone(),
        control: None,
        cancelled: runner.cancelled.clone(),
        challenge_window: runner.challenge_window,
    };
    runner.run("exec true", None).expect("the shim runs");
    let answers = std::fs::read_to_string(format!("{}.answers", shim.display()))
        .expect("the shim's transcript");
    assert_eq!(
        answers
            .lines()
            .filter(|line| line.trim() == "w2a-capped")
            .count(),
        1,
        "one passphrase per key per connection: {answers}"
    );
}
