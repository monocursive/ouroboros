//! The SSH runner, the host-trust decision and the askpass bridge, against a real
//! OpenSSH server.
//!
//! Everything here runs the system `ssh` against an unprivileged `sshd` on a loopback
//! high port. That matters: the properties under test are properties of the real client
//! — which options it honours, when it refuses a host key, how it asks for a secret —
//! and a mock would assert only that the mock was written to agree with the code.
//!
//! The one exception is the password path, which an unprivileged `sshd` cannot serve.
//! That uses a fake `ssh` that invokes `$SSH_ASKPASS` the way OpenSSH does, so what is
//! tested is this side of the bridge: the classification, the attempt cap, the uid
//! check, and the fact that the password never reaches argv, the environment or a file.

mod fleet_setup_support;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use fleet_setup_support::{account, scratch, write_script, Agent, Sshd, OURO};
use ouro::fleet_setup::askpass::{Bridge, PromptContext};
use ouro::fleet_setup::challenge::{Answer, ChallengeKind};
use ouro::fleet_setup::ssh::{
    Destination, Programs, ResolvedIdentity, Runner, COMMAND_TIMEOUT, CONNECT_TIMEOUT,
};
use ouro::fleet_setup::trust::{self, Trust};
use ouro::fleet_setup::{reason_of, ChallengeRequest, Conversation, Event};

/// A conversation that answers from a script and records what it was asked.
struct Scripted {
    answers: Mutex<Vec<(ChallengeKind, Answer)>>,
    asked: Mutex<Vec<(ChallengeKind, Value)>>,
    refusals: AtomicU32,
}

impl Scripted {
    fn new(answers: Vec<(ChallengeKind, Answer)>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers),
            asked: Mutex::new(Vec::new()),
            refusals: AtomicU32::new(0),
        })
    }

    fn asked(&self) -> Vec<(ChallengeKind, Value)> {
        self.asked.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn refusals(&self) -> u32 {
        self.refusals.load(Ordering::SeqCst)
    }
}

impl Conversation for Scripted {
    fn ask(&self, request: ChallengeRequest) -> anyhow::Result<Answer> {
        self.asked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((request.kind, request.metadata.clone()));
        let mut answers = self.answers.lock().unwrap_or_else(|p| p.into_inner());
        match answers.iter().position(|(kind, _)| *kind == request.kind) {
            Some(index) => Ok(answers.remove(index).1),
            None => {
                self.refusals.fetch_add(1, Ordering::SeqCst);
                ouro::fleet_setup::refuse(
                    "cancelled",
                    format!("this test was not told how to answer a {:?}", request.kind),
                )
            }
        }
    }

    fn notify(&self, _event: Event) {}
}

fn runner(
    rig: &Sshd,
    identity: ResolvedIdentity,
    known_hosts: Vec<PathBuf>,
    programs: Programs,
    bridge: Option<Arc<Bridge>>,
) -> Runner {
    Runner {
        programs,
        destination: Destination {
            address: "127.0.0.1".into(),
            port: rig.port,
            user: account(),
        },
        identity,
        known_hosts,
        // Deliberately not the operator's own file: a test must not depend on, or write
        // to, whatever this machine happens to trust.
        user_known_hosts: None,
        connect_timeout: CONNECT_TIMEOUT,
        command_timeout: COMMAND_TIMEOUT,
        bridge,
    }
}

fn tools() -> trust::Tools {
    trust::Tools {
        keyscan: PathBuf::from("/usr/bin/ssh-keyscan"),
        keygen: PathBuf::from("/usr/bin/ssh-keygen"),
    }
}

fn programs() -> Programs {
    Programs {
        ssh: PathBuf::from("/usr/bin/ssh"),
        ssh_add: PathBuf::from("/usr/bin/ssh-add"),
        keygen: PathBuf::from("/usr/bin/ssh-keygen"),
        askpass: PathBuf::from(OURO),
        agent_socket: None,
    }
}

/// Trust the rig's current host key in a private store, the way an accepted challenge
/// would. Returns the fingerprint that was recorded.
fn trust_now(rig: &Sshd, store: &Path, scratch: &Path) -> String {
    let stores = [store.to_path_buf()];
    match trust::examine(&tools(), &stores, "127.0.0.1", rig.port, scratch)
        .expect("a scan of the rig")
    {
        Trust::Unknown { keys } => {
            let key = keys.first().expect("at least one host key").clone();
            trust::accept(store, &key).expect("recording trust");
            key.fingerprint
        }
        Trust::Known { fingerprint, .. } => fingerprint,
        other => panic!("a fresh store cannot hold anything else: {other:?}"),
    }
}

/// Key authentication against the real server, with the normalized option set and
/// nothing relaxed.
#[test]
fn a_key_authenticates_against_a_real_sshd_with_strict_host_checking() {
    let rig = Sshd::start("key");
    let work = scratch("key-work");
    let store = work.join("known_hosts");

    // Strict checking is on, so an unknown host fails before any authentication.
    let cold = runner(
        &rig,
        ResolvedIdentity::Key {
            path: rig.client_key.clone(),
            label: "client_key".into(),
            fingerprint: None,
        },
        vec![store.clone()],
        programs(),
        None,
    );
    let refused = cold
        .check_access()
        .expect_err("an untrusted host is refused");
    assert_eq!(
        reason_of(&refused),
        Some("host_unknown"),
        "an unknown host fails OpenSSH's own verification, and is not a changed key: {refused:#}"
    );

    let fingerprint = trust_now(&rig, &store, &work);
    assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");

    let warm = runner(
        &rig,
        ResolvedIdentity::Key {
            path: rig.client_key.clone(),
            label: "client_key".into(),
            fingerprint: None,
        },
        vec![store.clone()],
        programs(),
        None,
    );
    warm.check_access().expect("the trusted host authenticates");

    let completed = warm
        .run("echo remote-ok", None)
        .expect("a bounded remote command");
    assert!(completed.success(), "{}", completed.stderr_text());
    assert_eq!(
        String::from_utf8_lossy(&completed.stdout).trim(),
        "remote-ok"
    );

    // `ssh -G` is inspected before the first connection and agrees with the destination.
    let config = warm
        .inspect_effective_config()
        .expect("an effective configuration");
    assert_eq!(config.value("hostname"), Some("127.0.0.1"));
    assert_eq!(config.routing(), None);

    assert!(
        rig.log().contains("Accepted publickey"),
        "the server saw a public key authentication:\n{}",
        rig.log()
    );
}

/// An unknown host is a challenge; an acceptance is recorded in the private store and
/// nowhere else.
#[test]
fn an_unknown_host_is_an_explicit_decision_recorded_in_the_private_store() {
    let rig = Sshd::start("unknown-host");
    let work = scratch("unknown-host-work");
    let store = work.join("known_hosts");

    let examined = trust::examine(
        &tools(),
        std::slice::from_ref(&store),
        "127.0.0.1",
        rig.port,
        &work,
    )
    .expect("a scan");
    let Trust::Unknown { keys } = examined else {
        panic!("a fresh private store knows nothing");
    };
    assert!(!keys.is_empty());
    let key = keys[0].clone();
    assert!(key.fingerprint.starts_with("SHA256:"));
    assert!(!store.exists(), "a scan writes nothing");

    trust::accept(&store, &key).expect("recording trust");
    let mode = std::fs::metadata(&store)
        .expect("a store")
        .permissions()
        .readonly();
    assert!(!mode);
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&store)
                .expect("a store")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the private host key store is readable only by its owner"
        );
    }

    assert!(matches!(
        trust::examine(
            &tools(),
            std::slice::from_ref(&store),
            "127.0.0.1",
            rig.port,
            &work
        )
        .expect("a second scan"),
        Trust::Known { .. }
    ));
}

/// A changed host key blocks. Nothing is overridden and nothing is sent.
#[test]
fn a_changed_host_key_blocks_and_the_connection_is_refused() {
    let mut rig = Sshd::start("changed-key");
    let work = scratch("changed-key-work");
    let store = work.join("known_hosts");
    let first = trust_now(&rig, &store, &work);

    rig.rotate_host_key();

    let examined = trust::examine(
        &tools(),
        std::slice::from_ref(&store),
        "127.0.0.1",
        rig.port,
        &work,
    )
    .expect("a scan of the rotated server");
    let Trust::Changed { presented, .. } = examined else {
        panic!("a rotated host key is a changed host key, not an unknown one");
    };
    assert!(
        presented.iter().all(|key| key.fingerprint != first),
        "the server presents a different key than the one recorded"
    );

    // And OpenSSH itself refuses, which is the property that actually protects the
    // operation: the trust check is a better message, not the enforcement.
    let runner = runner(
        &rig,
        ResolvedIdentity::Key {
            path: rig.client_key.clone(),
            label: "client_key".into(),
            fingerprint: None,
        },
        vec![store],
        programs(),
        None,
    );
    let refused = runner
        .check_access()
        .expect_err("a changed host key is refused");
    assert_eq!(reason_of(&refused), Some("host_key_changed"));
}

/// Agent authentication pins exactly one identity, and no private key is exported.
#[test]
fn agent_authentication_pins_one_identity_by_its_public_fingerprint() {
    let rig = Sshd::start("agent");
    let work = scratch("agent-work");
    let store = work.join("known_hosts");
    trust_now(&rig, &store, &work);

    let agent = Agent::start("agent-sock", &rig.client_key);
    let programs = Programs {
        agent_socket: Some(agent.socket.clone()),
        ..programs()
    };

    let identities =
        ouro::fleet_setup::ssh::agent_identities(&programs, &work).expect("the agent's identities");
    assert_eq!(identities.len(), 1, "the rig loaded exactly one key");
    let fingerprint = identities[0].fingerprint.clone();
    assert!(fingerprint.starts_with("SHA256:"));

    let resolved = ouro::fleet_setup::ssh::resolve_identity(
        &programs,
        &ouro::fleet_setup::IdentityChoice::Agent {
            fingerprint: fingerprint.clone(),
        },
        &work,
    )
    .expect("a resolved agent identity");
    let ResolvedIdentity::Agent {
        public_key_file, ..
    } = &resolved
    else {
        panic!("an agent choice resolves to an agent identity");
    };
    let pinned = std::fs::read_to_string(public_key_file).expect("the pinned public key");
    assert!(
        !pinned.contains("PRIVATE KEY"),
        "only the public half is written: {pinned}"
    );

    let runner = runner(&rig, resolved, vec![store], programs.clone(), None);
    runner
        .check_access()
        .expect("the agent identity authenticates");
    assert!(
        runner
            .options()
            .iter()
            .any(|option| option == "IdentitiesOnly=yes"),
        "the agent is pinned to the selected identity"
    );

    // An identity the agent does not hold is named rather than silently falling back.
    let missing = ouro::fleet_setup::ssh::resolve_identity(
        &programs,
        &ouro::fleet_setup::IdentityChoice::Agent {
            fingerprint: "SHA256:definitely-not-loaded".into(),
        },
        &work,
    )
    .expect_err("an identity the agent does not hold");
    assert_eq!(reason_of(&missing), Some("agent_identity_missing"));
}

/// Inherited proxy routing is refused before anything connects.
#[test]
fn inherited_proxy_routing_is_refused_by_name() {
    let rig = Sshd::start("routing");
    let work = scratch("routing-work");
    let config = work.join("ssh_config");
    std::fs::write(
        &config,
        format!(
            "Host 127.0.0.1\n  ProxyJump bastion.invalid\n  Port {}\n",
            rig.port
        ),
    )
    .expect("an ssh config");

    // The runner does not take `-F`, so the stanza is injected the way an operator's own
    // `~/.ssh/config` would reach it: through a wrapper that adds it.
    let shim = work.join("ssh");
    write_script(
        &shim,
        &format!(
            "#!/bin/sh\nexec /usr/bin/ssh -F {} \"$@\"\n",
            config.display()
        ),
    );
    let runner = runner(
        &rig,
        ResolvedIdentity::Default,
        vec![work.join("known_hosts")],
        Programs {
            ssh: shim,
            ..programs()
        },
        None,
    );

    let refused = runner
        .inspect_effective_config()
        .expect_err("proxy routing is not supported in v1");
    assert_eq!(reason_of(&refused), Some("unsupported_routing"));
    assert!(
        format!("{refused}").contains("bastion.invalid"),
        "the refusal names the routing it found: {refused}"
    );
}

/// An encrypted key is unlocked through the askpass bridge, by a real `ssh`.
///
/// This is the one place the whole chain runs end to end: OpenSSH decides it needs a
/// passphrase, runs `ouro fleet askpass`, that process connects to this operation's
/// private socket, the bridge classifies the prompt as a passphrase, the conversation
/// answers, and the key unlocks.
#[test]
fn an_encrypted_key_is_unlocked_through_the_askpass_bridge() {
    const PASSPHRASE: &str = "w2a-unique-passphrase-9f3c";
    let rig = Sshd::start_with_encrypted_key("passphrase", PASSPHRASE);
    let work = scratch("passphrase-work");
    let store = work.join("known_hosts");
    trust_now(&rig, &store, &work);

    let conversation = Scripted::new(vec![(
        ChallengeKind::Passphrase,
        Answer::Secret(zeroize::Zeroizing::new(PASSPHRASE.to_string())),
    )]);
    let bridge = Arc::new(
        Bridge::start(
            std::path::Path::new(OURO),
            PromptContext {
                target: "127.0.0.1".into(),
                user: account(),
                port: rig.port,
                key_label: Some("client_key".into()),
                key_fingerprint: Some("SHA256:test".into()),
            },
            conversation.clone(),
        )
        .expect("an askpass bridge"),
    );

    let runner = runner(
        &rig,
        ResolvedIdentity::Key {
            path: rig.client_key.clone(),
            label: "client_key".into(),
            fingerprint: Some("SHA256:test".into()),
        },
        vec![store],
        programs(),
        Some(Arc::clone(&bridge)),
    );

    let completed = runner
        .run("echo unlocked", None)
        .expect("a bounded remote command");
    assert!(
        completed.success(),
        "the encrypted key did not unlock: {}",
        completed.stderr_text()
    );
    assert_eq!(
        String::from_utf8_lossy(&completed.stdout).trim(),
        "unlocked"
    );

    let asked = conversation.asked();
    assert_eq!(asked.len(), 1, "one prompt, once");
    assert_eq!(asked[0].0, ChallengeKind::Passphrase);
    assert_eq!(
        asked[0].1,
        json!({"key_label": "client_key", "public_fingerprint": "SHA256:test"}),
        "the challenge carries the key's label and public fingerprint, not the prompt"
    );
    assert_eq!(bridge.served(), 1);
    assert_eq!(conversation.refusals(), 0);

    // The socket is gone with the bridge, and the passphrase is in no file it left.
    let socket = bridge.socket().to_path_buf();
    drop(runner);
    drop(bridge);
    assert!(!socket.exists(), "the askpass socket is removed");
    assert!(
        !grep_tree(&work, PASSPHRASE),
        "the passphrase is in no file this operation wrote"
    );
}

/// The password path, through a fake `ssh` that calls `$SSH_ASKPASS` the way OpenSSH
/// does. An unprivileged `sshd` cannot check a password, so this is where that half of
/// the contract is proven: the prompt is classified, the attempt is numbered and
/// capped, and the secret reaches the client only through the bridge.
#[test]
fn a_password_reaches_ssh_only_through_the_bridge_and_attempts_are_capped() {
    const PASSWORD: &str = "w2a-unique-password-7b21";
    let work = scratch("password-work");
    let trace = work.join("trace");

    // The fake `ssh`: answers `-G` like the real one, and otherwise asks for a password
    // exactly as OpenSSH does — by running $SSH_ASKPASS with the prompt as argv[1].
    let shim = work.join("ssh");
    write_script(
        &shim,
        &format!(
            r#"#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "-G" ]; then
    echo "user tester"
    echo "hostname 127.0.0.1"
    echo "port 2222"
    exit 0
  fi
done
echo "argv: $*" >> {trace}
echo "env: $(env | grep -c '{password}')" >> {trace}
answer=$("$SSH_ASKPASS" "tester@127.0.0.1's password: ")
if [ "$answer" = "{password}" ]; then
  echo authenticated
  exit 0
fi
echo "Permission denied, please try again." >&2
exit 255
"#,
            trace = trace.display(),
            password = PASSWORD,
        ),
    );

    let conversation = Scripted::new(vec![
        (
            ChallengeKind::Password,
            Answer::Secret(zeroize::Zeroizing::new(PASSWORD.to_string())),
        ),
        (
            ChallengeKind::Password,
            Answer::Secret(zeroize::Zeroizing::new("wrong".to_string())),
        ),
    ]);
    let bridge = Arc::new(
        Bridge::start(
            std::path::Path::new(OURO),
            PromptContext {
                target: "127.0.0.1".into(),
                user: "tester".into(),
                port: 2222,
                key_label: None,
                key_fingerprint: None,
            },
            conversation.clone(),
        )
        .expect("an askpass bridge"),
    );

    let runner = Runner {
        programs: Programs {
            ssh: shim,
            ..programs()
        },
        destination: Destination {
            address: "127.0.0.1".into(),
            port: 2222,
            user: "tester".into(),
        },
        identity: ResolvedIdentity::Password,
        known_hosts: vec![work.join("known_hosts")],
        user_known_hosts: None,
        connect_timeout: CONNECT_TIMEOUT,
        command_timeout: COMMAND_TIMEOUT,
        bridge: Some(Arc::clone(&bridge)),
    };

    // The password method is stated explicitly, so an agent cannot spend the server's
    // retry budget before the password is ever offered.
    assert!(runner
        .options()
        .iter()
        .any(|option| option == "PreferredAuthentications=password"));
    assert!(runner
        .options()
        .iter()
        .any(|option| option == "NumberOfPasswordPrompts=1"));

    let completed = runner.run("exec true", None).expect("a bounded attempt");
    assert!(completed.success(), "{}", completed.stderr_text());

    let asked = conversation.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].0, ChallengeKind::Password);
    assert_eq!(
        asked[0].1,
        json!({
            "target": "127.0.0.1", "user": "tester", "port": 2222,
            "attempt": 1, "max_attempts": 3
        }),
        "the challenge names the target and the attempt, and carries no prompt text"
    );

    // What the child actually saw: the password was in neither its argv nor its
    // environment. This is the assertion the proposal's secret-placement list demands.
    let seen = std::fs::read_to_string(&trace).expect("the shim's trace");
    assert!(
        !seen.contains(PASSWORD),
        "the password must not appear in the ssh child's arguments: {seen}"
    );
    assert!(
        seen.contains("env: 0"),
        "the password must not appear in the ssh child's environment: {seen}"
    );

    // A second connection asks again: nothing is retained for reconnection.
    let second = runner.run("exec true", None).expect("a second attempt");
    assert!(
        !second.success(),
        "the second attempt was answered with the wrong secret and must fail"
    );
    assert_eq!(conversation.asked().len(), 2);
    assert_eq!(
        conversation.asked()[1].1["attempt"],
        json!(1),
        "the attempt counter is per connection, and each `run` is a new connection"
    );

    // A third attempt has no scripted answer; the bridge reports a refusal rather than
    // inventing one, and the ssh child gets nothing.
    let third = runner.run("exec true", None).expect("a third attempt");
    assert!(!third.success());
    assert_eq!(conversation.refusals(), 1);
    assert_eq!(
        bridge.served(),
        2,
        "only the two scripted answers were served"
    );

    drop(runner);
    drop(bridge);
    assert!(
        // The fake `ssh` is the test's own fixture and has to know the right answer to
        // check it; everything else under this directory was written by the code.
        !grep_tree_except(&work, PASSWORD, &["ssh"]),
        "the password is in no file this operation wrote"
    );
}

/// A prompt the bridge does not recognise fails the attempt instead of being rendered.
#[test]
fn an_unrecognized_prompt_fails_the_attempt_rather_than_reaching_an_operator() {
    let work = scratch("prompt-work");
    let shim = work.join("ssh");
    write_script(
        &shim,
        r#"#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "-G" ]; then echo "hostname 127.0.0.1"; exit 0; fi
done
if "$SSH_ASKPASS" "Duo two-factor login for tester. Enter a passcode: " > /dev/null 2>&1; then
  echo "answered"
  exit 0
fi
echo "no answer" >&2
exit 255
"#,
    );

    let conversation = Scripted::new(vec![(
        ChallengeKind::Password,
        Answer::Secret(zeroize::Zeroizing::new("never-used".to_string())),
    )]);
    let bridge = Arc::new(
        Bridge::start(
            std::path::Path::new(OURO),
            PromptContext {
                target: "127.0.0.1".into(),
                user: "tester".into(),
                port: 22,
                key_label: None,
                key_fingerprint: None,
            },
            conversation.clone(),
        )
        .expect("an askpass bridge"),
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
    };

    let completed = runner.run("exec true", None).expect("an attempt");
    assert!(
        !completed.success(),
        "an unsupported prompt fails the attempt"
    );
    assert!(
        conversation.asked().is_empty(),
        "an unrecognized remote prompt never becomes a question for a person"
    );
    assert_eq!(bridge.served(), 0);
}

/// Whether any file under `root` contains `needle`, skipping the test's own fixtures.
///
/// A fake `ssh` that has to recognise the right password necessarily contains it; what
/// this is looking for is a file the code under test wrote.
fn grep_tree(root: &std::path::Path, needle: &str) -> bool {
    grep_tree_except(root, needle, &[])
}

fn grep_tree_except(root: &std::path::Path, needle: &str, except: &[&str]) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| except.contains(&name))
        {
            continue;
        }
        if path.is_dir() {
            if grep_tree_except(&path, needle, except) {
                return true;
            }
        } else if let Ok(bytes) = std::fs::read(&path) {
            if String::from_utf8_lossy(&bytes).contains(needle) {
                eprintln!("found `{needle}` in {}", path.display());
                return true;
            }
        }
    }
    false
}
