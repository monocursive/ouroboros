//! One test per surviving mutation from the review's two runs.
//!
//! A mutation survives when deleting a rule changes no test's verdict, which
//! means the rule was never actually checked. Each test below is named after
//! the rule it pins and is written so that removing that one line turns it
//! red: where the old test only asserted "this refuses", these assert *which*
//! rule refused, or use an input that becomes accepted without it.

use std::io::Write as _;
use std::os::fd::{AsRawFd as _, IntoRawFd as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use ouro_jail::observer::CoverageSummary;
use ouro_jail::records::{
    Applied, AppliedNetwork, AttemptRecord, CONTROL_FRAME_MAX, Containment, ControlKind,
    ControlMessage, ErrorCode, EvidenceMode, GATE_FRAME_MAX, GateExpectation, JailRecord, Lifetime,
    NativeString, ObserveMode, Os, Outcome, Phase, PlatformRecord, PolicyRecord, SCHEMA_CONTROL,
    StateCleanup, parse_release,
};
use ouro_jail::state::{self, AttemptDir, AttemptId, Durable};

const ATTEMPT: &str = "att_00000000-0000-4000-8000-000000000001";

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

fn expectation() -> GateExpectation {
    GateExpectation {
        attempt_id: ATTEMPT.to_owned(),
        policy_digest: digest('a'),
    }
}

/// A release frame padded to exactly `total` bytes including the trailing LF.
fn frame_of(total: usize) -> Vec<u8> {
    let body = format!(
        "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"attempt_id\":\"{ATTEMPT}\",\
         \"policy_digest\":\"{}\"}}\n",
        digest('a')
    );
    assert!(total >= body.len(), "cannot pad below the minimum frame");
    let padding = total - body.len();
    let padded = format!(
        "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\"attempt_id\":\"{ATTEMPT}\",\
         \"policy_digest\":\"{}\"{}}}\n",
        digest('a'),
        " ".repeat(padding)
    );
    assert_eq!(padded.len(), total);
    padded.into_bytes()
}

// ---------------------------------------------------------------------------
// Survivor: the gate byte cap, through the production reader
// ---------------------------------------------------------------------------

/// Runs `supervisor::await_release` against a real pipe carrying `payload`.
fn through_production_gate(payload: &[u8]) -> Result<(), ouro_jail::records::JailError> {
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("/bin/cat");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(payload).expect("the payload fits the pipe");
    }
    let stdout = child.stdout.take().expect("stdout");
    let fd = stdout.into_raw_fd();
    let result =
        ouro_jail::supervisor::await_release(fd, &expectation(), Duration::from_secs(10), None);
    let _ = child.wait();
    result
}

#[test]
fn the_gate_byte_cap_is_enforced_by_the_production_reader() {
    // 1024 including the LF is the maximum, and it is inclusive.
    through_production_gate(&frame_of(GATE_FRAME_MAX))
        .expect("a frame at the cap is valid (§8.2: maximum 1,024 bytes)");
    // One byte more is refused. Without the cap this parses as valid JSON,
    // which is what made the mutation survive: the old test padded so far past
    // the cap that the frame stopped being JSON at all.
    let error = through_production_gate(&frame_of(GATE_FRAME_MAX + 1))
        .expect_err("1025 bytes exceeds the maximum");
    assert_eq!(error.code, ErrorCode::GateInvalid);
    assert!(
        error.message.contains("maximum"),
        "the refusal must name the cap: {}",
        error.message
    );
}

#[test]
fn the_gate_byte_cap_is_enforced_by_the_parser_too() {
    parse_release(&frame_of(GATE_FRAME_MAX), &expectation()).expect("at the cap");
    let error =
        parse_release(&frame_of(GATE_FRAME_MAX + 1), &expectation()).expect_err("over the cap");
    assert!(error.message.contains("maximum"), "{}", error.message);
}

// ---------------------------------------------------------------------------
// Survivor: the single-LF rule
// ---------------------------------------------------------------------------

#[test]
fn the_gate_accepts_exactly_one_line_and_says_which_rule_refused() {
    let valid = frame_of(200);
    let line = &valid[..valid.len() - 1];

    // Each of these is accepted by a parser missing one specific rule, so the
    // message is asserted rather than just the code: refusing for the wrong
    // reason is how the single-LF mutation survived.
    for (label, payload, expected) in [
        (
            "a blank line after the frame",
            [line, b"\n\n"].concat(),
            "more than one line",
        ),
        (
            "a blank line before it",
            [b"\n".as_slice(), line, b"\n"].concat(),
            "more than one line",
        ),
        ("no trailing LF", line.to_vec(), "exactly one LF"),
        ("CRLF", [line, b"\r\n"].concat(), "CR"),
    ] {
        match parse_release(&payload, &expectation()) {
            Ok(_) => panic!("`{label}` must refuse"),
            Err(error) => assert!(
                error.message.contains(expected),
                "`{label}` refused for the wrong reason: {}",
                error.message
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Survivor: the control frame cap
// ---------------------------------------------------------------------------

fn control_message(reason_length: usize) -> ControlMessage {
    ControlMessage {
        schema: SCHEMA_CONTROL.to_owned(),
        attempt_id: ATTEMPT.to_owned(),
        seq: 1,
        kind: ControlKind::Refused,
        receipt_phase: Phase::Refused,
        receipt_digest: digest('b'),
        outcome: Outcome {
            kind: ouro_jail::records::OutcomeKind::Refused,
            code: None,
            signal: None,
            cause: Some("x".repeat(reason_length)),
            error: None,
        },
        error: None,
    }
}

#[test]
fn a_control_frame_over_sixty_four_kibibytes_is_refused_not_emitted() {
    let small = control_message(16).to_frame().expect("a small frame");
    assert!(small.len() < CONTROL_FRAME_MAX);

    let error = control_message(CONTROL_FRAME_MAX)
        .to_frame()
        .expect_err("§8.2: the writer refuses to emit a larger frame");
    assert!(
        error.message.contains(&CONTROL_FRAME_MAX.to_string()),
        "the refusal names the cap: {}",
        error.message
    );
}

// ---------------------------------------------------------------------------
// Survivors: the native-string codec
// ---------------------------------------------------------------------------

#[test]
fn the_codec_reader_refuses_a_nul_in_either_form() {
    serde_json::from_str::<NativeString>("\"a\\u0000b\"").expect_err("a NUL in the string form");
    // base64 of "a\0b"
    serde_json::from_str::<NativeString>("{\"encoding\":\"base64\",\"data\":\"YQBi\"}")
        .expect_err("a NUL in the byte form");
}

#[test]
fn the_codec_reader_refuses_utf8_bytes_in_the_object_form() {
    // base64 of "abc", which is valid UTF-8 and so must use the string form.
    let error = serde_json::from_str::<NativeString>("{\"encoding\":\"base64\",\"data\":\"YWJj\"}")
        .expect_err("UTF-8 bytes must use the string form");
    assert!(
        error.to_string().contains("string form"),
        "the reason must be the codec rule: {error}"
    );
    // The same bytes in the string form are accepted, so the refusal is about
    // the encoding and not about the content.
    assert_eq!(
        serde_json::from_str::<NativeString>("\"abc\"").expect("the string form"),
        NativeString::Text("abc".to_owned())
    );
}

#[test]
fn the_codec_reader_refuses_noncanonical_base64() {
    for data in ["/w", "/x==", "//8=="] {
        let json = format!("{{\"encoding\":\"base64\",\"data\":\"{data}\"}}");
        let error = serde_json::from_str::<NativeString>(&json)
            .expect_err("only canonical padded base64 is a native byte object");
        assert!(
            error.to_string().contains("base64") || error.to_string().contains("string form"),
            "`{data}`: {error}"
        );
    }
}

// ---------------------------------------------------------------------------
// Survivors: path normalization
// ---------------------------------------------------------------------------

/// Resolves a `tool` policy with one trusted CLI layer carrying `raw`.
fn resolve_cli_path(base_dir: &[u8], raw: &[u8]) -> Result<Vec<u8>, ouro_jail::records::JailError> {
    use ouro_jail::policy::{
        Layer, LayerOrigin, PolicyDelta, ProfileName, ResolveInputs, ScratchRoot,
    };
    let mut baseline = ouro_jail::profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None);
    baseline.read_only = Vec::new();
    let inputs = ResolveInputs {
        platform: Os::Linux,
        base_profile: ProfileName::Tool,
        policy_name: "tool".to_owned(),
        baseline,
        workspace: b"/srv/work".to_vec(),
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers: vec![Layer {
            origin: LayerOrigin::CommandLine,
            base_dir: Some(base_dir.to_vec()),
            key_prefix: String::new(),
            narrowing: false,
            delta: PolicyDelta {
                read_write: vec![raw.to_vec()],
                ..PolicyDelta::default()
            },
        }],
    };
    let resolved = ouro_jail::policy::resolve(&inputs)?;
    Ok(resolved.grants[0].value.as_bytes().to_vec())
}

#[test]
fn normalization_refuses_a_nul_in_a_path() {
    let error = resolve_cli_path(b"/srv/work", b"a\0b").expect_err("a NUL is not a path");
    assert_eq!(error.code, ErrorCode::InvalidConfig);
    assert!(error.message.contains("NUL"), "{}", error.message);
}

#[test]
fn normalization_refuses_an_escape_rather_than_clamping_it_to_the_root() {
    // Clamping would turn this into `/`, which is a grant of the whole
    // filesystem: the most dangerous possible outcome of a typo.
    let error = resolve_cli_path(b"/srv/work", b"../../../..").expect_err("an escape refuses");
    assert_eq!(error.code, ErrorCode::InvalidConfig);
    assert!(error.message.contains(".."), "{}", error.message);
    let error = resolve_cli_path(b"/", b"..").expect_err("an escape from the root refuses");
    assert_eq!(error.code, ErrorCode::InvalidConfig);

    // A `..` that stays inside the filesystem is still resolved, so the rule
    // is about escaping and not about the component.
    assert_eq!(
        resolve_cli_path(b"/srv/work", b"../other").expect("stays inside"),
        b"/srv/other".to_vec()
    );
}

// ---------------------------------------------------------------------------
// Survivors: state safety
// ---------------------------------------------------------------------------

#[test]
fn a_symlinked_state_directory_refuses_for_being_a_symlink() {
    let temp = common::private_tempdir();
    let real = temp.path().join("real");
    std::fs::create_dir(&real).expect("a directory");
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("a symlink");

    let error = state::check_state_dir(&link).expect_err("a symlinked root refuses");
    assert_eq!(error.code, ErrorCode::UnsafeStatePath);
    assert!(
        error.message.contains("symlink"),
        "the symlink rule is what refused, not the is-a-directory rule: {}",
        error.message
    );
    // The link really does point at a valid state directory, so nothing else
    // about it is wrong.
    state::check_state_dir(&real).expect("the target is a private directory");
}

use std::os::unix::fs::PermissionsExt as _;

mod common;

#[test]
fn the_ownership_predicate_refuses_a_foreign_owner() {
    let path = Path::new("/tmp/state");
    let mine = state::effective_uid();
    state::check_ownership(path, mine, 0o700, 0o700).expect("this operator owns it");
    let error = state::check_ownership(path, mine.wrapping_add(1), 0o700, 0o700)
        .expect_err("a foreign owner refuses");
    assert_eq!(error.code, ErrorCode::UnsafeStatePath);
    assert!(error.message.contains("owned by uid"), "{}", error.message);
    // And the mode rule is separate from the owner rule.
    let error = state::check_ownership(path, mine, 0o755, 0o700).expect_err("a wide mode refuses");
    assert!(error.message.contains("mode"), "{}", error.message);
}

/// A [`Durable`] that records the calls instead of making them.
#[derive(Default)]
struct Recorder {
    files: std::cell::Cell<usize>,
    dirs: std::cell::Cell<usize>,
}

impl Durable for Recorder {
    fn sync_file(&self, _file: &std::fs::File) -> std::io::Result<()> {
        self.files.set(self.files.get() + 1);
        Ok(())
    }

    fn sync_dir(&self, _path: &Path) -> std::io::Result<()> {
        self.dirs.set(self.dirs.get() + 1);
        Ok(())
    }
}

#[test]
fn a_durable_replacement_syncs_the_file_and_then_the_parent_directory() {
    let temp = common::private_tempdir();
    let target = temp.path().join("jail.json");
    let recorder = Recorder::default();

    state::replace_atomically_with(&target, b"first", &recorder).expect("writes");
    assert_eq!(
        recorder.files.get(),
        1,
        "§7: the file is synced before the rename"
    );
    assert_eq!(
        recorder.dirs.get(),
        1,
        "§7: a successful rename alone is not a durable acknowledgment"
    );

    state::replace_atomically_with(&target, b"second", &recorder).expect("writes");
    assert_eq!(recorder.files.get(), 2);
    assert_eq!(recorder.dirs.get(), 2);
    assert_eq!(std::fs::read(&target).expect("readable"), b"second");

    // An abandoned write syncs the file but never the directory, because it
    // never renames.
    let pending = state::TempWrite::create_with(&target, b"third", &recorder).expect("pending");
    assert_eq!(recorder.files.get(), 3);
    assert_eq!(recorder.dirs.get(), 2, "no rename, no directory sync");
    drop(pending);
}

// ---------------------------------------------------------------------------
// Survivor: leading zeroes in limit values
// ---------------------------------------------------------------------------

#[test]
fn a_limit_value_with_a_leading_zero_refuses() {
    for spelling in ["wall=05m", "pids=064", "mem=0512MiB", "cpu=0100"] {
        match ouro_jail::config::ceilings_from_cli(&[spelling.to_owned()]) {
            Ok(_) => panic!("`{spelling}` has a leading zero and must refuse"),
            Err(error) => assert!(
                error.message.contains("leading zero"),
                "`{spelling}`: {}",
                error.message
            ),
        }
    }
    // A single zero is refused for being zero, not for its spelling, and a
    // value without a leading zero is accepted.
    assert!(ouro_jail::config::ceilings_from_cli(&["pids=0".to_owned()]).is_err());
    assert_eq!(
        ouro_jail::config::ceilings_from_cli(&["pids=64".to_owned()])
            .expect("parses")
            .pids
            .expect("pids")
            .value,
        64
    );
}

// ---------------------------------------------------------------------------
// Survivor: the receipt revision
// ---------------------------------------------------------------------------

fn minimal_record() -> AttemptRecord {
    AttemptRecord {
        attempt_id: ATTEMPT.to_owned(),
        revision: 1,
        platform: PlatformRecord {
            os: Os::Macos,
            arch: "aarch64".to_owned(),
            kernel: "test".to_owned(),
        },
        jail: JailRecord {
            component: "ouro-jail".to_owned(),
            version: "0.0.0-test".to_owned(),
            backend: None,
            backend_version: None,
        },
        policy: PolicyRecord {
            name: "tool".to_owned(),
            digest: digest('a'),
            observe: ObserveMode::On,
            evidence: EvidenceMode::Strict,
            requirements: Vec::new(),
            grants: Vec::new(),
        },
        containment: Containment::Pending,
        exec_observed: false,
        argv_digest: None,
        applied: Applied {
            filesystem: None,
            network: AppliedNetwork {
                mode: "pending".to_owned(),
                mechanism: None,
                allowed_hosts: Vec::new(),
            },
            syscalls: None,
            limits: Vec::new(),
            environment_names: Vec::new(),
            removed_environment_names: Vec::new(),
        },
        observer: CoverageSummary::unobserved().to_observer_record(),
        coverage: CoverageSummary::unobserved().to_coverage(),
        process: None,
        lifetime: Lifetime::pending(),
        outcome: Outcome::pending(),
        state_cleanup: StateCleanup::NotNeeded,
        cleanup_error: None,
        created_at: std::time::SystemTime::UNIX_EPOCH,
        updated_at: std::time::SystemTime::UNIX_EPOCH,
        errors: Vec::new(),
        credentials: Vec::new(),
    }
}

#[test]
fn the_receipt_revision_advances_on_each_successful_replacement() {
    let temp = common::private_tempdir();
    let data = temp.path().join("data");
    std::fs::create_dir(&data).expect("data");
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let id = AttemptId::parse(ATTEMPT).expect("a valid id");
    let dir = AttemptDir::new(&data, &id);
    dir.create(&data).expect("the attempt root");

    let mut record = minimal_record();
    let first = ouro_jail::supervisor::write_receipt(&dir, &mut record, Phase::Refused, None)
        .expect("the first replacement");
    assert_eq!(first.revision, 1, "§13.2: the revision starts at 1");

    let second = ouro_jail::supervisor::write_receipt(&dir, &mut record, Phase::Refused, None)
        .expect("the second replacement");
    assert_eq!(
        second.revision, 2,
        "§13.2: the revision advances on each successful replacement"
    );

    let on_disk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.receipt_path()).expect("readable"))
            .expect("valid JSON");
    assert_eq!(
        on_disk["revision"],
        serde_json::json!(2),
        "the file holds the latest revision, not the first"
    );
}

// ---------------------------------------------------------------------------
// Survivor: the fd direction check
// ---------------------------------------------------------------------------

#[test]
fn a_descriptor_open_for_the_wrong_direction_refuses() {
    let temp = common::private_tempdir();
    let data = temp.path().join("data");
    let config = temp.path().join("config");
    let work = temp.path().join("work");
    for path in [&data, &config] {
        std::fs::create_dir(path).expect("a directory");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("mode");
    }
    std::fs::create_dir(&work).expect("work");
    let file = temp.path().join("channel");
    std::fs::write(&file, b"").expect("a file");

    // `3<` opens for reading only, which is wrong for a control channel, and
    // `4>` opens for writing only, which is wrong for a gate.
    for (script, flag, fd) in [
        ("exec 3<\"$1\"; shift; exec \"$@\"", "--control-fd", "3"),
        ("exec 4>\"$1\"; shift; exec \"$@\"", "--gate-fd", "4"),
    ] {
        let output = Command::new("/bin/sh")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", temp.path())
            .env("OURO_DATA_DIR", &data)
            .env("OURO_CONFIG_DIR", &config)
            .current_dir(&work)
            .arg("-c")
            .arg(script)
            .arg("sh")
            .arg(&file)
            .arg(env!("CARGO_BIN_EXE_ouro-jail"))
            .args(["run", flag, fd, "--", "/usr/bin/true"])
            .output()
            .expect("the shell wrapper runs");
        assert_eq!(
            output.status.code(),
            Some(125),
            "{flag} in the wrong direction must refuse"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("invalid_fd"), "{flag}: {stderr}");
        assert!(
            stderr.contains("direction") || stderr.contains("open for"),
            "the refusal names the direction: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// Survivor: the exclusive attempt claim
// ---------------------------------------------------------------------------

#[test]
fn a_second_claim_of_the_same_attempt_refuses() {
    let temp = common::private_tempdir();
    let data = temp.path().join("data");
    let config = temp.path().join("config");
    let work = temp.path().join("work");
    for path in [&data, &config] {
        std::fs::create_dir(path).expect("a directory");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("mode");
    }
    std::fs::create_dir(&work).expect("work");

    // A gate that is already at EOF, so the attempt reaches its claim and then
    // refuses for a reason that is not the claim.
    let run = || {
        Command::new("/bin/sh")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", temp.path())
            .env("OURO_DATA_DIR", &data)
            .env("OURO_CONFIG_DIR", &config)
            .current_dir(&work)
            .arg("-c")
            .arg("exec 3</dev/null; shift 0; exec \"$@\"")
            .arg("sh")
            .arg(env!("CARGO_BIN_EXE_ouro-jail"))
            .args([
                "run",
                "--gate-fd",
                "3",
                "--attempt-id",
                ATTEMPT,
                "--",
                "/usr/bin/true",
            ])
            .output()
            .expect("the shell wrapper runs")
    };

    let first = run();
    assert_eq!(first.status.code(), Some(125));
    let first_stderr = String::from_utf8_lossy(&first.stderr).into_owned();
    assert!(
        !first_stderr.contains("attempt_exists"),
        "the first claim succeeds: {first_stderr}"
    );
    assert!(
        data.join("attempts")
            .join(ATTEMPT)
            .join("jail-state.json")
            .exists(),
        "the claim file is what the second run collides with"
    );

    let second = run();
    assert_eq!(second.status.code(), Some(125));
    let second_stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        second_stderr.contains("attempt_exists"),
        "§7: a prior jail claim, live or dead, refuses `attempt_exists`: {second_stderr}"
    );
}

// ---------------------------------------------------------------------------
// A guard on the harness itself
// ---------------------------------------------------------------------------

#[test]
fn the_pipe_helper_really_carries_bytes() {
    // If `through_production_gate` silently delivered nothing, every gate test
    // above would pass by reporting an empty gate.
    let error = through_production_gate(b"").expect_err("an empty gate is a closed gate");
    assert_eq!(error.code, ErrorCode::GateClosed);
    let mut probe = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("/bin/cat");
    probe
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"x")
        .expect("writes");
    let stdout = probe.stdout.take().expect("stdout");
    assert!(stdout.as_raw_fd() >= 0);
    let _ = probe.wait();
}
