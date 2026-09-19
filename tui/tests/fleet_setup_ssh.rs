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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use fleet_setup_support::{account, scratch, write_script, Agent, Sshd, OURO};
use ouro::fleet_setup::askpass::{Bridge, PromptContext};
use ouro::fleet_setup::challenge::{Answer, ChallengeKind, Registry};
use ouro::fleet_setup::ssh::{
    prepare_control_socket, Destination, Programs, ResolvedIdentity, Runner, COMMAND_TIMEOUT,
    CONNECT_TIMEOUT,
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

    fn cancelled(&self) -> bool {
        false
    }
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
        control: None,
        cancelled: None,
        challenge_window: None,
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
        control: None,
        cancelled: None,
        challenge_window: None,
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
        json!(2),
        "attempts accumulate on one bridge so a mistyped password can retry"
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

/// The default identity falls back to a password, and to the *same* challenge.
///
/// This is what lets a surface have no authentication picker: an operator says "this
/// machine, this account" and nothing else, this host's own keys are offered first, and
/// if the target accepts none of them the password question arrives through the ordinary
/// `password` challenge — numbered, capped, and never on a command line. Before this,
/// `PreferredAuthentications=publickey` meant the connection simply failed with
/// `Permission denied (publickey)`, and the operator had to already know to re-run with
/// `--ask-password`.
///
/// The client here is a fake `ssh`, because an unprivileged `sshd` cannot check a
/// password. It refuses to ask for one unless the method list actually permits it, so
/// taking the fallback back out of the options fails this test rather than passing on
/// the shim's good manners.
#[test]
fn a_default_identity_falls_back_to_the_same_password_challenge() {
    const PASSWORD: &str = "w2a-default-fallback-4c19";
    let work = scratch("default-pw");
    let trace = work.join("trace");

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
methods=""
for arg in "$@"; do
  case "$arg" in
    PreferredAuthentications=*) methods="${{arg#PreferredAuthentications=}}" ;;
  esac
done
echo "methods: $methods" >> {trace}
echo "argv: $*" >> {trace}
echo "env: $(env | grep -c '{password}')" >> {trace}
# Every key this host holds is offered first and refused, in OpenSSH's own order.
echo "debug1: Offering public key: /home/tester/.ssh/id_ed25519" >&2
echo "debug1: Authentications that can continue: publickey,password" >&2
case ",$methods," in
  *,password,*) ;;
  *)
    echo "Permission denied (publickey)." >&2
    exit 255
    ;;
esac
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

    // Two typos and then the real thing: the three-attempt loop is the point.
    let conversation = Scripted::new(vec![
        (
            ChallengeKind::Password,
            Answer::Secret(zeroize::Zeroizing::new("first-typo".to_string())),
        ),
        (
            ChallengeKind::Password,
            Answer::Secret(zeroize::Zeroizing::new("second-typo".to_string())),
        ),
        (
            ChallengeKind::Password,
            Answer::Secret(zeroize::Zeroizing::new(PASSWORD.to_string())),
        ),
    ]);
    let bridge = Arc::new(
        Bridge::start(
            std::path::Path::new(OURO),
            PromptContext {
                target: "127.0.0.1".into(),
                user: "tester".into(),
                port: 2222,
                // No key was selected: this is the default identity.
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

    // Keys first, then the account's own password, and nothing a far end could use to
    // compose prompt text of its own.
    let options = runner.options();
    assert!(
        options
            .iter()
            .any(|option| option == "PreferredAuthentications=publickey,password"),
        "{options:?}"
    );
    assert!(
        !options
            .iter()
            .any(|option| option.contains("keyboard-interactive") || option.contains("gssapi")),
        "{options:?}"
    );
    // The default identity is still the one path that honours the operator's own
    // ssh_config, so it is still the one that does not pass `-F /dev/null`.
    let argv = runner.argv("exec true");
    assert!(
        !argv.iter().any(|word| word == "-F"),
        "the default identity reads the host's own configuration: {argv:?}"
    );

    runner
        .check_access()
        .expect("the third password is the right one");

    // The same challenge the `password` identity raises: the same metadata, numbered and
    // capped the same way.
    let asked = conversation.asked();
    assert_eq!(
        asked.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        vec![
            ChallengeKind::Password,
            ChallengeKind::Password,
            ChallengeKind::Password
        ],
        "a default identity that meets a password prompt raises a password challenge"
    );
    for (index, (_, metadata)) in asked.iter().enumerate() {
        assert_eq!(
            *metadata,
            json!({
                "target": "127.0.0.1", "user": "tester", "port": 2222,
                "attempt": index + 1, "max_attempts": 3
            }),
            "attempt {} carries the metadata `--ask-password` carries",
            index + 1
        );
    }

    let seen = std::fs::read_to_string(&trace).expect("the shim's trace");
    assert!(
        seen.contains("methods: publickey,password"),
        "this client is what allows the password method at all: {seen}"
    );
    assert!(
        !seen.contains(PASSWORD),
        "the password must not appear in the ssh child's arguments: {seen}"
    );
    assert!(
        !seen.contains("env: 1"),
        "the password must not appear in the ssh child's environment: {seen}"
    );
    assert_eq!(bridge.served(), 3);
    assert_eq!(bridge.password_prompts(), 3);

    drop(runner);
    drop(bridge);
    assert!(
        // The fake `ssh` has to know the right answer to check it; everything else under
        // this directory was written by the code.
        !grep_tree_except(&work, PASSWORD, &["ssh"]),
        "the password is in no file this operation wrote"
    );
}

/// A default identity refused for a key reason is *not* asked for three passwords.
///
/// The retry budget exists because a password can be mistyped. A far end that never
/// asked for one has nothing for an operator to retype, and two more password prompts
/// would be this client inventing a question the connection never asked.
#[test]
fn a_default_identity_that_was_never_asked_for_a_password_is_not_retried() {
    let work = scratch("default-nopw");
    let trace = work.join("trace");
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
echo attempt >> {trace}
echo "Permission denied (publickey)." >&2
exit 255
"#,
            trace = trace.display(),
        ),
    );

    let conversation = Scripted::new(Vec::new());
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

    let refused = runner.check_access().expect_err("publickey was refused");
    assert_eq!(reason_of(&refused), Some("ssh_auth_failed"));
    assert_eq!(
        std::fs::read_to_string(&trace)
            .expect("the shim's trace")
            .lines()
            .count(),
        1,
        "one connection, because no password was ever asked for"
    );
    assert!(
        conversation.asked().is_empty(),
        "and nothing was put in front of an operator: {:?}",
        conversation.asked()
    );
}

/// An encrypted *default* key is still a passphrase question, not a password one.
///
/// The fallback put `password` on the method list, and the two words share a substring.
/// A key this host already holds that happens to be encrypted must still be unlocked,
/// and under the challenge that names a key rather than an account.
#[test]
fn a_default_identity_asked_for_a_key_passphrase_still_raises_a_passphrase_challenge() {
    const PASSPHRASE: &str = "w2a-default-passphrase-5d30";
    let work = scratch("default-pp");
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
answer=$("$SSH_ASKPASS" "Enter passphrase for key '/home/tester/.ssh/id_ed25519': ")
if [ "$answer" = "{passphrase}" ]; then
  echo authenticated
  exit 0
fi
echo "Permission denied (publickey)." >&2
exit 255
"#,
            passphrase = PASSPHRASE,
        ),
    );

    let conversation = Scripted::new(vec![(
        ChallengeKind::Passphrase,
        Answer::Secret(zeroize::Zeroizing::new(PASSPHRASE.to_string())),
    )]);
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

    runner.check_access().expect("the key unlocks");
    let asked = conversation.asked();
    assert_eq!(
        asked.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        vec![ChallengeKind::Passphrase],
        "a key passphrase is never an account password"
    );
    assert_eq!(
        asked[0].1["key_label"],
        json!("the selected key"),
        "the passphrase challenge names a key, not a target account: {:?}",
        asked[0].1
    );
    assert_eq!(
        bridge.password_prompts(),
        0,
        "a passphrase does not spend the password budget"
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
        control: None,
        cancelled: None,
        challenge_window: None,
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

#[test]
fn explicit_key_and_agent_choices_ignore_other_configured_identities() {
    for use_agent in [false, true] {
        let rig = Sshd::start("pin-config");
        let work = scratch("pin-cfg");
        let store = work.join("known_hosts");
        trust_now(&rig, &store, &work);
        let wrong = work.join("selected_key");
        assert!(std::process::Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&wrong)
            .status()
            .unwrap()
            .success());
        let config = work.join("ssh_config");
        std::fs::write(
            &config,
            format!("Host *\n  IdentityFile {}\n", rig.client_key.display()),
        )
        .unwrap();
        let wrapper = work.join("ssh");
        write_script(
            &wrapper,
            &format!(
                "#!/bin/sh\nexec /usr/bin/ssh -F '{}' \"$@\"\n",
                config.display()
            ),
        );
        let agent = use_agent.then(|| Agent::start("pin-agent", &wrong));
        let programs = Programs {
            ssh: wrapper,
            agent_socket: agent.as_ref().map(|agent| agent.socket.clone()),
            ..programs()
        };
        let selected = if use_agent {
            let identities = ouro::fleet_setup::ssh::agent_identities(&programs, &work).unwrap();
            ouro::fleet_setup::ssh::resolve_identity(
                &programs,
                &ouro::fleet_setup::IdentityChoice::Agent {
                    fingerprint: identities[0].fingerprint.clone(),
                },
                &work,
            )
            .unwrap()
        } else {
            ResolvedIdentity::Key {
                path: wrong,
                label: "selected_key".into(),
                fingerprint: None,
            }
        };
        let mut runner = runner(&rig, selected, vec![store], programs, None);
        runner.inspect_effective_config().unwrap();
        assert!(
            runner.check_access().is_err(),
            "authenticated using the unselected configured key"
        );
        runner.identity = ResolvedIdentity::Key {
            path: rig.client_key.clone(),
            label: "authorized".into(),
            fingerprint: None,
        };
        runner
            .check_access()
            .expect("the selected authorized key still works");
        // Configured routing remains an explicit refusal, even though connections
        // with a selected key isolate the identity list from that config.
        std::fs::write(&config, "Host *\n  ProxyJump bastion.invalid\n").unwrap();
        assert_eq!(
            reason_of(&runner.inspect_effective_config().unwrap_err()),
            Some("unsupported_routing")
        );
    }
}

#[test]
fn an_unterminated_helper_reply_is_bounded_before_eof() {
    let rig = Sshd::start("frame-limit");
    let work = scratch("frame-limit");
    let wrapper = work.join("ssh");
    write_script(
        &wrapper,
        "#!/bin/sh\ndd if=/dev/zero bs=1048576 count=2 2>/dev/null\nsleep 30\n",
    );
    let runner = runner(
        &rig,
        ResolvedIdentity::Default,
        vec![],
        Programs {
            ssh: wrapper,
            ..programs()
        },
        None,
    );
    let mut session = ouro::fleet_setup::helper::Session::open(&runner, "ouro", None).unwrap();
    let start = std::time::Instant::now();
    let result = session.ask("inspect", serde_json::json!({})).unwrap_err();
    assert_eq!(reason_of(&result), Some("frame_too_large"));
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "waited for the remote producer to exit"
    );
}

/// Strict host checking is not only a string in argv: with an armed bridge that would
/// accept, an unknown host must fail as `host_unknown` without the confirmation ever
/// reaching askpass. Deleting `StrictHostKeyChecking=yes` would route the prompt here.
#[test]
fn a_cold_runner_with_an_armed_bridge_does_not_ask_about_an_unknown_host() {
    let rig = Sshd::start("cold-ask");
    let work = scratch("cold-ask");
    let store = work.join("known_hosts");
    let conversation = Scripted::new(vec![
        (
            ChallengeKind::Password,
            Answer::Secret(zeroize::Zeroizing::new("would-accept".into())),
        ),
        (
            ChallengeKind::Passphrase,
            Answer::Secret(zeroize::Zeroizing::new("would-accept".into())),
        ),
    ]);
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
    let cold = runner(
        &rig,
        ResolvedIdentity::Key {
            path: rig.client_key.clone(),
            label: "client_key".into(),
            fingerprint: None,
        },
        vec![store],
        programs(),
        Some(Arc::clone(&bridge)),
    );
    let refused = cold
        .check_access()
        .expect_err("an untrusted host is refused");
    assert_eq!(reason_of(&refused), Some("host_unknown"), "{refused:#}");
    assert_eq!(
        bridge.served(),
        0,
        "a host confirmation must not be answered"
    );
    assert_eq!(
        bridge.prompted(),
        0,
        "OpenSSH must not route the confirmation to askpass when StrictHostKeyChecking=yes"
    );
}

/// Two host keys on the server, one line in the private store: `UpdateHostKeys=no`
/// means the extra key is not appended after a successful connection.
#[test]
fn the_private_store_is_not_rewritten_with_a_second_host_key() {
    let rig = Sshd::start_with_two_host_keys("upd-hk");
    let work = scratch("upd-hk");
    let store = work.join("known_hosts");
    trust_now(&rig, &store, &work);
    let before = std::fs::read_to_string(&store).expect("the store");
    let lines = before
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    assert_eq!(
        lines, 1,
        "the test records exactly one trusted key:\n{before}"
    );

    let runner = runner(
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
    runner
        .run("echo still-one", None)
        .expect("the trusted host authenticates");
    let after = std::fs::read_to_string(&store).expect("the store after connect");
    assert_eq!(
        after.lines().filter(|line| !line.trim().is_empty()).count(),
        1,
        "UpdateHostKeys=no must not append the server's other host key:\n{after}"
    );
}

/// A muxed connection reuses authentication: the second `run` does not prompt again,
/// the control socket lives in the scratch directory, and dropping the Runner removes it.
#[test]
fn a_second_run_on_the_same_runner_does_not_prompt_again() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    const PASSPHRASE: &str = "w2a-mux-passphrase-4e1a";
    let rig = Sshd::start_with_encrypted_key("mux", PASSPHRASE);
    let work = scratch("mux");
    let store = work.join("known_hosts");
    trust_now(&rig, &store, &work);
    let control = prepare_control_socket(&work).expect("a control socket path");

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
            conversation,
        )
        .expect("an askpass bridge"),
    );

    let mut runner = runner(
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
    runner.control = Some(control.clone());

    let first = runner.run("echo first", None).expect("the first command");
    assert!(first.success(), "{}", first.stderr_text());
    assert_eq!(bridge.served(), 1, "the passphrase is asked once");

    let second = runner.run("echo second", None).expect("the second command");
    assert!(second.success(), "{}", second.stderr_text());
    assert_eq!(
        bridge.served(),
        1,
        "the muxed connection must not prompt again"
    );

    let uid = unsafe { libc::geteuid() };
    let dir = control.parent().expect("the control directory");
    let dir_meta = std::fs::symlink_metadata(dir).expect("the control directory");
    assert_eq!(dir_meta.uid(), uid);
    assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
    let sock_meta = std::fs::symlink_metadata(&control).expect("the control socket");
    assert_eq!(sock_meta.permissions().mode() & 0o777, 0o600);

    drop(runner);
    assert!(
        !control.exists(),
        "ssh -O exit must remove the control socket"
    );
}

/// A delayed answer past the child's prompt window returns promptly as
/// `challenge_expired`, unblocks the askpass thread, and refuses the late secret.
#[test]
fn a_late_password_is_refused_after_the_prompt_window_without_leaving_a_blocked_thread() {
    struct Waiting {
        registry: Arc<Registry>,
    }
    impl Conversation for Waiting {
        fn ask(&self, request: ChallengeRequest) -> anyhow::Result<Answer> {
            self.ask_from(0, request)
        }
        fn ask_from(&self, issuer: u64, request: ChallengeRequest) -> anyhow::Result<Answer> {
            let issued = self
                .registry
                .issue(request.kind, request.metadata, issuer)
                .expect("an issued challenge");
            self.registry.wait(&issued.challenge)
        }
        fn withdraw(&self, issuer: u64, reason: &'static str) {
            self.registry.invalidate_issuer(issuer, reason);
        }
        fn notify(&self, _event: Event) {}
    }

    let work = scratch("late-pw");
    let shim = work.join("ssh");
    write_script(
        &shim,
        r#"#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "-G" ]; then echo "hostname 127.0.0.1"; exit 0; fi
done
"$SSH_ASKPASS" "tester@127.0.0.1's password: " >/dev/null 2>&1
echo "Permission denied" >&2
exit 255
"#,
    );
    let registry = Arc::new(Registry::new());
    let conversation = Arc::new(Waiting {
        registry: Arc::clone(&registry),
    });
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
            conversation,
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
        connect_timeout: Duration::from_secs(2),
        command_timeout: Duration::from_secs(2),
        bridge: Some(Arc::clone(&bridge)),
        control: None,
        cancelled: None,
        challenge_window: Some(Duration::from_millis(400)),
    };

    let watch = Arc::clone(&registry);
    let watcher = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            let pending = watch.pending_kinds();
            if let Some((id, _)) = pending.into_iter().next() {
                return id;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        String::new()
    });

    let started = std::time::Instant::now();
    let result = runner.run("exec true", None);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "must return at the prompt window, not hang on the challenge lifetime"
    );
    let error = result.expect_err("a late password is a refusal");
    assert_eq!(
        reason_of(&error),
        Some("challenge_expired"),
        "the operator-facing reason is not ssh_timeout: {error:#}"
    );

    let id = watcher.join().expect("the watcher");
    assert!(
        !id.is_empty(),
        "the challenge was advertised while in flight"
    );
    let late = registry
        .respond(&id, &json!({"secret": "too-late"}))
        .expect_err("a late answer is refused by name");
    assert!(
        matches!(
            reason_of(&late),
            Some("challenge_expired" | "connection_lost" | "challenge_consumed")
        ),
        "a late answer is refused by name: {late:#}"
    );

    drop(runner);
    let dropped = std::time::Instant::now();
    drop(bridge);
    assert!(
        dropped.elapsed() < Duration::from_secs(1),
        "Bridge::drop must not wait for a human"
    );
}

/// Cancellation reaps the in-flight ssh child instead of waiting out its deadline.
#[test]
fn cancelling_kills_an_in_flight_ssh_child() {
    let work = scratch("cancel");
    let pid_file = work.join("pid");
    let shim = work.join("ssh");
    write_script(
        &shim,
        &format!(
            "#!/bin/sh\necho $$ > {}\nexec sleep 30\n",
            pid_file.display()
        ),
    );
    let stop = Arc::new(AtomicBool::new(false));
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
        identity: ResolvedIdentity::Default,
        known_hosts: vec![work.join("known_hosts")],
        user_known_hosts: None,
        connect_timeout: Duration::from_secs(2),
        command_timeout: Duration::from_secs(30),
        bridge: None,
        control: None,
        cancelled: Some({
            let stop = Arc::clone(&stop);
            Arc::new(move || stop.load(Ordering::SeqCst))
        }),
        challenge_window: None,
    };
    // Cancel once the shim has actually started and written its pid, not after a fixed
    // wait. The 150ms this used to sleep was a bet that a forked `/bin/sh` would be
    // scheduled and reach its first redirect inside that window; under a loaded machine
    // it sometimes is not, and the child was then killed before it recorded the pid this
    // test goes on to probe — a failure that says nothing about the code under test.
    let flag = Arc::clone(&stop);
    let watched = pid_file.clone();
    std::thread::spawn(move || {
        let until = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < until {
            // A non-empty pid file: the shim has written *and* flushed it, so the pid is
            // readable and the `exec sleep 30` that follows is what gets cancelled.
            if std::fs::read_to_string(&watched).is_ok_and(|text| !text.trim().is_empty()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        flag.store(true, Ordering::SeqCst);
    });
    let started = std::time::Instant::now();
    let error = runner
        .run("exec true", None)
        .expect_err("cancellation is a refusal");
    assert_eq!(reason_of(&error), Some("cancelled"), "{error:#}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the sleeping child must be killed, not awaited: {:?}",
        started.elapsed()
    );
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .expect("the shim wrote its pid")
        .trim()
        .parse()
        .expect("a pid");
    // SAFETY: a liveness probe on a pid this test spawned; signal 0 delivers nothing.
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        -1,
        "the in-flight ssh child must be dead after cancel"
    );
}

/// A mistyped password is a retry: `check_access` re-prompts up to three times.
#[test]
fn a_mistyped_password_is_retried_up_to_the_attempt_cap() {
    const PASSWORD: &str = "w2a-retry-password-3c01";
    let work = scratch("pw-try");
    let count = work.join("count");
    let shim = work.join("ssh");
    write_script(
        &shim,
        &format!(
            r#"#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "-G" ]; then echo "hostname 127.0.0.1"; exit 0; fi
done
n=0
if [ -f {count} ]; then n=$(cat {count}); fi
n=$((n + 1))
echo "$n" > {count}
answer=$("$SSH_ASKPASS" "tester@127.0.0.1's password: ")
if [ "$n" -ge 3 ] && [ "$answer" = "{password}" ]; then
  echo authenticated
  exit 0
fi
echo "Permission denied, please try again." >&2
exit 255
"#,
            count = count.display(),
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
            Answer::Secret(zeroize::Zeroizing::new(PASSWORD.to_string())),
        ),
        (
            ChallengeKind::Password,
            Answer::Secret(zeroize::Zeroizing::new(PASSWORD.to_string())),
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
        control: None,
        cancelled: None,
        challenge_window: None,
    };
    runner
        .check_access()
        .expect("the third attempt authenticates");
    let asked = conversation.asked();
    assert_eq!(asked.len(), 3, "three prompts, then success");
    assert_eq!(asked[0].1["attempt"], json!(1));
    assert_eq!(asked[1].1["attempt"], json!(2));
    assert_eq!(asked[2].1["attempt"], json!(3));
}
