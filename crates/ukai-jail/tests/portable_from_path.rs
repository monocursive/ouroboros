//! J12: zero-config launch, portable part (jail-launch-and-summary.md §3,
//! rows K33 to K44).
//!
//! These run natively on macOS and on Linux. Resolution is the real
//! `resolve_plan`; an attempt runs through the real supervisor over a
//! scripted platform, so staging, the gate's recheck and the receipt are the
//! product's while the boundary is simulated; the command line is the built
//! binary. Every program, repository and credential here is a fixture this
//! file writes; none is an operator's. What needs a real boundary (the
//! install root read-only inside, the child's working directory, a vault
//! placeholder under its own name, a process-bound credential refusing
//! curl) is in `from_path_linux.rs`.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use clap::Parser as _;
use ukai_jail::cli::{self, Cli, PolicyArgs};
use ukai_jail::config::EnvSettings;
use ukai_jail::platform::Platform;
use ukai_jail::records::{ErrorCode, JailError};
use ukai_jail::supervisor;

mod common;
use common::sim::{self, ScriptedPlatform};

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

/// A private tree: the operator's home, a config and a data directory
/// outside it, a git repository in the home, a `bin` directory on `PATH`
/// holding the agent, and a directory outside every root.
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    config: PathBuf,
    data: PathBuf,
    repo: PathBuf,
    bin: PathBuf,
}

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn write(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A 64-bit little-endian ELF header with no program header: a static
/// executable as far as the interpreter check reads it.
fn static_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 64];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf
}

/// The launch profile the tests resolve: a vault credential bound to the
/// resolved program under the agent's own variable, and an alternative.
const AGENT_PROFILE: &str = r#"name = "agent"
jail = "agent"
state_var = "AGENT_STATE"
credentials_one_of = ["first", "second"]

[credentials.first]
mode = "vault"
source = "@config/credentials/first"
env = "AGENT_TOKEN"
hosts = ["https://api.example.com"]
header = { name = "authorization", prefix = "Bearer " }
binaries = ["@program"]
hint = "store it with `ukai-jail credential set first`"

[credentials.second]
mode = "vault"
source = "@config/credentials/second"
env = "AGENT_KEY"
hosts = ["https://api.example.com"]
header = { name = "x-api-key" }
binaries = ["@program"]
hint = "store it with `ukai-jail credential set second`"

[network]
allow = ["api.example.com"]
"#;

impl Fixture {
    fn new() -> Fixture {
        let temp = common::private_tempdir();
        // Canonical: macOS's /var -> /private/var alias is a symlink a
        // no-follow walk refuses.
        let root = temp.path().canonicalize().unwrap();
        let fixture = Fixture {
            home: root.join("home"),
            config: root.join("config"),
            data: root.join("data"),
            repo: root.join("home/repo"),
            bin: root.join("tools/bin"),
            root,
            _temp: temp,
        };
        mkdir(&fixture.home, 0o700);
        mkdir(&fixture.config, 0o700);
        mkdir(&fixture.config.join("launch"), 0o700);
        mkdir(&fixture.data, 0o700);
        mkdir(&fixture.repo.join("src/deep"), 0o755);
        mkdir(&fixture.repo.join(".git"), 0o755);
        write(
            &fixture.repo.join(".git/HEAD"),
            b"ref: refs/heads/main\n",
            0o644,
        );
        mkdir(&fixture.bin, 0o755);
        std::fs::set_permissions(
            fixture.root.join("tools"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        // A static executable as the interpreter check reads it: the
        // credentials bind `@program`, which a `#!` script cannot carry.
        write(&fixture.bin.join("agent"), &static_elf(), 0o755);
        fixture.profile("agent", AGENT_PROFILE);
        fixture
    }

    fn profile(&self, name: &str, text: &str) {
        write(
            &self.config.join("launch").join(format!("{name}.toml")),
            text.as_bytes(),
            0o600,
        );
    }

    fn credential(&self, id: &str, value: &[u8]) -> PathBuf {
        let directory = self.config.join("credentials");
        mkdir(&directory, 0o700);
        let path = directory.join(id);
        write(&path, value, 0o600);
        path
    }

    fn path_value(&self) -> Vec<u8> {
        let mut path = b":relative/bin:".to_vec();
        path.extend_from_slice(self.bin.as_os_str().as_bytes());
        path.extend_from_slice(b":/usr/bin:/bin");
        path
    }

    fn context(&self, platform: Box<dyn Platform>, cwd: &Path) -> supervisor::Context {
        let path = self.path_value();
        supervisor::Context {
            platform,
            env_settings: EnvSettings {
                config_dir: Some(self.config.clone()),
                data_dir: Some(self.data.clone()),
                ..Default::default()
            },
            cwd: cwd.to_path_buf(),
            home: Some(self.home.clone()),
            env_lookup: Box::new(move |name| (name == "PATH").then(|| path.clone())),
        }
    }

    /// The policy arguments `ukai-jail VERB ARGS...` parses to.
    fn policy(verb: &str, args: &[&str]) -> PolicyArgs {
        let mut argv = vec!["ukai-jail", verb];
        argv.extend(args);
        match Cli::try_parse_from(argv).expect("parses").command {
            cli::Command::Explain(explain) => explain.policy,
            cli::Command::Run(run) => run.policy,
            _ => unreachable!(),
        }
    }

    fn plan(&self, cwd: &Path, args: &[&str]) -> Result<supervisor::Plan, JailError> {
        let ctx = self.context(Box::new(platform()), cwd);
        supervisor::resolve_plan(&ctx, &Fixture::policy("explain", args))
    }

    fn explain(&self, cwd: &Path, args: &[&str]) -> supervisor::ExplainReport {
        let ctx = self.context(Box::new(platform()), cwd);
        let mut argv = vec!["ukai-jail", "explain"];
        argv.extend(args);
        let cli::Command::Explain(explain) = Cli::try_parse_from(argv).unwrap().command else {
            unreachable!()
        };
        supervisor::explain(&ctx, &explain).unwrap_or_else(|error| panic!("{error}"))
    }

    /// `ukai-jail ARGV...` through the real supervisor over `platform`.
    fn run(&self, platform: ScriptedPlatform, cwd: &Path, argv: &[&str]) -> supervisor::RunReport {
        let argv: Vec<OsString> = std::iter::once("ukai-jail")
            .chain(argv.iter().copied())
            .map(OsString::from)
            .collect();
        let argv = cli::alias_argv(&argv).unwrap_or(argv);
        let cli::Command::Run(args) = Cli::try_parse_from(argv).unwrap().command else {
            unreachable!()
        };
        let ctx = self.context(Box::new(platform), cwd);
        supervisor::run(&ctx, &args)
    }

    /// The built binary, with a cleared environment.
    fn binary(&self, cwd: &Path, argv: &[&str], stdin: Option<&[u8]>) -> Output {
        use std::io::Write as _;
        let mut command = Command::new(env!("CARGO_BIN_EXE_ukai-jail"));
        command
            .env_clear()
            .env(
                "PATH",
                OsString::from(std::ffi::OsStr::from_bytes(&self.path_value())),
            )
            .env("HOME", &self.home)
            .env("UKAI_DATA_DIR", &self.data)
            .env("UKAI_CONFIG_DIR", &self.config)
            .current_dir(cwd)
            .args(argv)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("the binary runs");
        let mut input = child.stdin.take().unwrap();
        if let Some(bytes) = stdin {
            input.write_all(bytes).unwrap();
        }
        drop(input);
        child.wait_with_output().unwrap()
    }
}

/// A scripted contained boundary that reports what it applied, so every
/// receipt it ends in is held to the contract.
fn platform() -> ScriptedPlatform {
    let mut boundary = sim::namespace_boundary();
    boundary.process = sim::cgroup_boundary().process;
    let mut platform = ScriptedPlatform::new("j12", boundary);
    platform.applied = Some(sim::contained_applied("proxy"));
    platform
}

fn refused(result: Result<supervisor::Plan, JailError>, label: &str) -> JailError {
    match result {
        Ok(_) => panic!("{label}: resolution must refuse"),
        Err(error) => error,
    }
}

fn receipt(report: &supervisor::RunReport) -> serde_json::Value {
    common::checked_receipt(
        serde_json::to_value(report.receipt.as_ref().expect("a receipt")).unwrap(),
    )
}

/// Makes a present credential source unsafe in one way.
type Spoil = Box<dyn Fn(&Path)>;

fn text(output: &[u8]) -> String {
    String::from_utf8_lossy(output).into_owned()
}

// ---------------------------------------------------------------------------
// K33: the alias
// ---------------------------------------------------------------------------

/// K33: `ukai-jail NAME [ARG]...` is exactly `run --launch NAME --from-path
/// -- ARG...`; every following word is the agent's, jail flags included; a
/// built-in verb or an option is never a launch name.
#[test]
fn k33_the_alias_is_exactly_the_long_form() {
    let os = |words: &[&str]| -> Vec<OsString> { words.iter().map(OsString::from).collect() };
    let alias = cli::alias_argv(&os(&[
        "ukai-jail",
        "agent",
        "-p",
        "--profile",
        "none",
        "x y",
    ]))
    .expect("an alias");
    assert_eq!(
        alias,
        os(&[
            "ukai-jail",
            "run",
            "--launch",
            "agent",
            "--from-path",
            "--",
            "-p",
            "--profile",
            "none",
            "x y"
        ])
    );
    let Ok(cli::Command::Run(run)) = Cli::try_parse_from(alias).map(|cli| cli.command) else {
        panic!("the alias parses to run")
    };
    assert!(run.policy.selection.from_path);
    assert_eq!(
        run.policy.selection.profile, None,
        "an agent flag is not a jail flag"
    );
    assert_eq!(run.argv, os(&["-p", "--profile", "none", "x y"]));
    for verb in cli::VERBS {
        assert_eq!(cli::alias_argv(&os(&["ukai-jail", verb])), None, "{verb}");
    }
    for option in ["--help", "-h", "--version"] {
        assert_eq!(
            cli::alias_argv(&os(&["ukai-jail", option])),
            None,
            "{option}"
        );
    }
    assert_eq!(cli::alias_argv(&os(&["ukai-jail"])), None);
}

/// K33: the alias and the long form resolve to the same policy digest and
/// the same argv digest, through the real supervisor.
#[test]
fn k33_the_alias_and_the_long_form_have_identical_digests() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let cwd = fixture.repo.join("src");
    let alias = fixture.run(platform(), &cwd, &["agent", "-p", "fix it"]);
    let long = fixture.run(
        platform(),
        &cwd,
        &[
            "run",
            "--launch",
            "agent",
            "--from-path",
            "--",
            "-p",
            "fix it",
        ],
    );
    assert!(alias.error.is_none(), "{:?}", alias.error);
    assert!(long.error.is_none(), "{:?}", long.error);
    let (alias, long) = (receipt(&alias), receipt(&long));
    assert_eq!(alias["policy"]["digest"], long["policy"]["digest"]);
    assert_eq!(alias["argv_digest"], long["argv_digest"]);
    // The argv the digest covers is the resolved program, then the words.
    let expected = ukai_jail::canonical::argv_digest(&[
        fixture.bin.join("agent").as_os_str().as_bytes().to_vec(),
        b"-p".to_vec(),
        b"fix it".to_vec(),
    ]);
    assert_eq!(alias["argv_digest"], expected);
}

/// K33: built-in verbs win, an unknown word exits 2 naming both readings,
/// and `--from-path` refuses the managed gate and `none` with exit 2.
#[test]
fn k33_verbs_win_unknown_words_and_conflicts_exit_2() {
    let fixture = Fixture::new();
    // A launch profile named like a verb is reachable through `--launch`
    // only, and `doctor` says so.
    fixture.profile(
        "version",
        &AGENT_PROFILE.replace("name = \"agent\"", "name = \"version\""),
    );
    let version = fixture.binary(&fixture.repo, &["version"], None);
    assert_eq!(version.status.code(), Some(0), "{}", text(&version.stderr));
    assert!(
        text(&version.stdout).starts_with("ukai-jail "),
        "{}",
        text(&version.stdout)
    );
    fixture.credential("first", b"token-value");
    let doctor = fixture.binary(&fixture.repo, &["doctor", "--launch", "version"], None);
    assert!(
        text(&doctor.stdout).contains("launch version shadowed"),
        "{}",
        text(&doctor.stdout)
    );

    for word in ["claud", "Agent", "a/b"] {
        let output = fixture.binary(&fixture.repo, &[word, "-p", "x"], None);
        assert_eq!(output.status.code(), Some(2), "{word}");
        let stderr = text(&output.stderr);
        assert!(
            stderr.contains(&format!("no verb or launch profile `{word}`")),
            "{word}: {stderr}"
        );
    }
    for argv in [
        &[
            "run",
            "--launch",
            "agent",
            "--from-path",
            "--gate-fd",
            "7",
            "--",
            "x",
        ][..],
        &[
            "run",
            "--launch",
            "agent",
            "--from-path",
            "--gate-fd",
            "7",
            "--attempt-id",
            "att_00000000-0000-4000-8000-000000000001",
            "--",
            "x",
        ],
        &[
            "run",
            "--launch",
            "agent",
            "--from-path",
            "--profile",
            "none",
            "--",
            "x",
        ],
        &["run", "--from-path", "--", "x"],
        &["explain", "--from-path"],
    ] {
        let output = fixture.binary(&fixture.repo, argv, None);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{argv:?}: {}",
            text(&output.stderr)
        );
    }
}

// ---------------------------------------------------------------------------
// K34: the workspace
// ---------------------------------------------------------------------------

/// K34: discovery walks up to the nearest `.git` that is a directory holding
/// `HEAD` or a `gitdir:` file, through a symlinked invocation directory, and
/// refuses outside a repository naming `--workspace`; `git` never runs.
#[test]
fn k34_the_workspace_is_the_nearest_repository_top_level() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let args = ["--launch", "agent", "--from-path"];
    let workspace = |cwd: &Path| {
        fixture
            .plan(cwd, &args)
            .unwrap_or_else(|e| panic!("{e}"))
            .workspace
    };
    assert_eq!(workspace(&fixture.repo.join("src/deep")), fixture.repo);
    assert_eq!(workspace(&fixture.repo), fixture.repo);
    // A `.git` directory without HEAD is not a top level.
    mkdir(&fixture.repo.join("src/.git"), 0o755);
    assert_eq!(workspace(&fixture.repo.join("src/deep")), fixture.repo);
    // A `gitdir:` file is (a linked worktree or a submodule) ...
    write(
        &fixture.repo.join("src/deep/.git"),
        b"gitdir: /elsewhere/.git/worktrees/deep\n",
        0o644,
    );
    assert_eq!(
        workspace(&fixture.repo.join("src/deep")),
        fixture.repo.join("src/deep")
    );
    // ... and a file saying anything else is not.
    write(
        &fixture.repo.join("src/deep/.git"),
        b"not a gitfile\n",
        0o644,
    );
    assert_eq!(workspace(&fixture.repo.join("src/deep")), fixture.repo);
    // A symlinked invocation directory resolves to where it points.
    std::os::unix::fs::symlink(fixture.repo.join("src"), fixture.root.join("link")).unwrap();
    assert_eq!(workspace(&fixture.root.join("link")), fixture.repo);

    // Outside a repository: refused, never a guess.
    mkdir(&fixture.root.join("plain/sub"), 0o755);
    let error = refused(
        fixture.plan(&fixture.root.join("plain/sub"), &args),
        "no repository",
    );
    assert_eq!(error.code, ErrorCode::InvalidConfig);
    assert_eq!(error.key_path.as_deref(), Some("--workspace"));
    assert!(
        error.message.contains("pass --workspace"),
        "{}",
        error.message
    );
    // `--workspace` still chooses.
    let plan = fixture
        .plan(
            &fixture.root.join("plain/sub"),
            &[
                "--launch",
                "agent",
                "--from-path",
                "--workspace",
                fixture.repo.to_str().unwrap(),
            ],
        )
        .unwrap();
    assert_eq!(plan.workspace, fixture.repo);
}

/// K34: a `git` first on `PATH` is never executed by discovery.
#[test]
fn k34_a_recording_git_on_path_never_runs() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let marker = fixture.root.join("git-ran");
    write(
        &fixture.bin.join("git"),
        format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.display()).as_bytes(),
        0o755,
    );
    let output = fixture.binary(
        &fixture.repo.join("src"),
        &["explain", "--launch", "agent", "--from-path"],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(!marker.exists(), "discovery ran the git on PATH");
}

/// K34 (§7 decision 2): on every contained run, `/`, the operator's home and
/// an ancestor of it refuse as a workspace, whether discovery, `--workspace`
/// or the invocation directory chose it; `none` still runs.
#[test]
fn k34_home_its_ancestors_and_root_refuse_on_every_contained_run() {
    let fixture = Fixture::new();
    let run = |cwd: &Path, argv: &[&str]| {
        let mut platform = platform();
        if argv.contains(&"none") {
            platform = ScriptedPlatform::new("j12", sim::cgroup_boundary());
        }
        fixture.run(platform, cwd, argv)
    };
    let home = fixture.home.to_str().unwrap();
    let root = fixture.root.to_str().unwrap();
    for profile in ["agent", "tool", "build"] {
        for (cwd, workspace) in [
            (&fixture.home, None),
            (&fixture.repo, Some(home)),
            (&fixture.repo, Some(root)),
            (&fixture.repo, Some("/")),
        ] {
            let mut argv = vec!["run", "--profile", profile, "--limit", "mem=1G"];
            if let Some(workspace) = workspace {
                argv.extend(["--workspace", workspace]);
            }
            argv.extend(["--", "/bin/true"]);
            let report = run(cwd, &argv);
            let error = report
                .error
                .unwrap_or_else(|| panic!("{argv:?} from {} must refuse", cwd.display()));
            assert_eq!(error.code, ErrorCode::PolicyWidening, "{argv:?}: {error}");
            assert_eq!(error.key_path.as_deref(), Some("--workspace"), "{argv:?}");
            assert!(
                report.receipt.is_none(),
                "refused before anything was claimed"
            );
            assert_eq!(report.exit_code, 125);
        }
    }
    // `none` grants no workspace, so the check has nothing to protect.
    let report = run(
        &fixture.home,
        &["run", "--profile", "none", "--", "/bin/true"],
    );
    assert!(
        report
            .error
            .as_ref()
            .is_none_or(|error| error.key_path.as_deref() != Some("--workspace")),
        "{:?}",
        report.error
    );
    // A home that is itself a repository is what discovery would pick.
    mkdir(&fixture.home.join(".git"), 0o755);
    write(
        &fixture.home.join(".git/HEAD"),
        b"ref: refs/heads/main\n",
        0o644,
    );
    mkdir(&fixture.home.join("notes"), 0o755);
    fixture.credential("first", b"token-value");
    let error = refused(
        fixture.plan(
            &fixture.home.join("notes"),
            &["--launch", "agent", "--from-path"],
        ),
        "a home repository",
    );
    assert_eq!(error.code, ErrorCode::PolicyWidening);
    assert_eq!(error.key_path.as_deref(), Some("--workspace"));
    // `explain` without `--from-path` inspects; it runs nothing.
    assert!(fixture.plan(&fixture.home, &["--profile", "tool"]).is_ok());
    // And the binary's plain `run` from the home refuses the same way.
    let output = fixture.binary(&fixture.home, &["run", "--", "/bin/true"], None);
    assert_eq!(output.status.code(), Some(125), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("policy_widening"),
        "{}",
        text(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// K35: where the child starts
// ---------------------------------------------------------------------------

/// K35: the child starts where the operator stood beneath the workspace;
/// `roots.cwd` is in the snapshot, so it changes the digest, and it is
/// absent at the workspace root and outside it.
#[test]
fn k35_roots_cwd_records_the_invocation_directory() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let args = ["--launch", "agent", "--from-path"];
    let deep = fixture.plan(&fixture.repo.join("src/deep"), &args).unwrap();
    let top = fixture.plan(&fixture.repo, &args).unwrap();
    assert_eq!(deep.resolved.snapshot.roots.cwd.as_bytes(), b"src/deep");
    assert!(top.resolved.snapshot.roots.cwd.as_bytes().is_empty());
    assert_ne!(deep.resolved.digest, top.resolved.digest);
    let canonical = deep.resolved.snapshot.to_canonical_value().unwrap();
    assert_eq!(canonical["roots"]["cwd"], "src/deep");
    assert!(
        top.resolved.snapshot.to_canonical_value().unwrap()["roots"]
            .get("cwd")
            .is_none(),
        "the root is omitted, so a run from it keeps its digest"
    );
    assert!(
        deep.resolved
            .provenance
            .iter()
            .any(|entry| { entry.key == "roots.cwd" && entry.origin == "invocation-directory" })
    );
    // Outside the workspace: the root.
    let outside = fixture
        .plan(
            &fixture.root,
            &[
                "--profile",
                "tool",
                "--workspace",
                fixture.repo.to_str().unwrap(),
            ],
        )
        .unwrap();
    assert!(outside.resolved.snapshot.roots.cwd.as_bytes().is_empty());
    // A plain run's snapshot schema still validates with the field.
    let snapshot = deep.resolved.snapshot.to_canonical_value().unwrap();
    let errors: Vec<String> = common::validators()["policy-snapshot"]
        .iter_errors(&snapshot)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
}

// ---------------------------------------------------------------------------
// K36: resolution and its refusals
// ---------------------------------------------------------------------------

/// K36: the first absolute `PATH` entry wins (empty and relative entries are
/// skipped), symlinks are followed to the real file, and its directory is
/// the read-only root.
#[test]
fn k36_the_program_resolves_on_path_to_its_real_file() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    // A relative entry naming a directory that holds an `agent` is skipped:
    // the workspace would otherwise pick the program.
    mkdir(&fixture.repo.join("relative/bin"), 0o755);
    write(
        &fixture.repo.join("relative/bin/agent"),
        b"#!/bin/sh\n",
        0o755,
    );
    // `bin/agent` is a symlink chain into a versions directory.
    let versions = fixture.root.join("tools/share/versions");
    mkdir(&versions, 0o755);
    std::fs::set_permissions(
        fixture.root.join("tools/share"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::rename(fixture.bin.join("agent"), versions.join("2.0.1")).unwrap();
    std::os::unix::fs::symlink(
        versions.join("2.0.1"),
        fixture.root.join("tools/share/current"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        fixture.root.join("tools/share/current"),
        fixture.bin.join("agent"),
    )
    .unwrap();
    let plan = fixture
        .plan(&fixture.repo, &["--launch", "agent", "--from-path"])
        .unwrap();
    let program = plan.program.as_ref().expect("a program");
    assert_eq!(program.program.path, versions.join("2.0.1"));
    assert_eq!(program.program.root.path, versions);
    assert!(
        plan.resolved
            .snapshot
            .filesystem
            .read_only
            .iter()
            .any(|reference| reference.path.as_bytes() == versions.as_os_str().as_bytes())
    );
    // The credential is bound to the real file, not to a name on PATH.
    let launch = plan.resolved.snapshot.launch.as_ref().unwrap();
    let binaries = &launch.credentials[0].vault.as_ref().unwrap().binaries;
    assert_eq!(
        binaries,
        &[versions.join("2.0.1").to_str().unwrap().to_owned()]
    );
}

/// K36: every §3.3 step 4 refusal fires with its key and names the root.
#[test]
fn k36_every_install_root_refusal_names_its_root() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let base = AGENT_PROFILE.to_owned();
    let check = |label: &str, profile: &str, args: &[&str], root: &Path| {
        fixture.profile("agent", profile);
        let mut argv = vec!["--launch", "agent", "--from-path"];
        argv.extend(args);
        let error = refused(fixture.plan(&fixture.repo, &argv), label);
        assert_eq!(error.code, ErrorCode::PolicyWidening, "{label}: {error}");
        assert_eq!(error.key_path.as_deref(), Some("--from-path"), "{label}");
        assert!(
            error.message.contains(&root.display().to_string()),
            "{label}: {}",
            error.message
        );
    };
    // The root at the operator's home or above it.
    let deep_home = fixture.home.join("bin");
    mkdir(&deep_home, 0o755);
    write(&deep_home.join("homeagent"), &static_elf(), 0o755);
    let in_home = base.replace("name = \"agent\"", "name = \"agent\"\nprogram_root = 2");
    std::fs::rename(fixture.bin.join("agent"), fixture.root.join("agent.saved")).unwrap();
    std::fs::rename(deep_home.join("homeagent"), deep_home.join("agent")).unwrap();
    let ctx_path = fixture.home.clone();
    // PATH holds `tools/bin` first; it has no `agent` now, so `home/bin`
    // would be next, but it is not on PATH: add it through a link.
    std::fs::remove_dir(&fixture.bin).unwrap();
    std::os::unix::fs::symlink(&deep_home, &fixture.bin).unwrap();
    check("home", &in_home, &[], &ctx_path);
    std::fs::remove_file(&fixture.bin).unwrap();
    mkdir(&fixture.bin, 0o755);
    std::fs::rename(fixture.root.join("agent.saved"), fixture.bin.join("agent")).unwrap();

    // The root contains the config directory, the data directory, or a
    // credential source of this launch.
    let tools = fixture.root.join("tools");
    for (label, moved) in [("config", &fixture.config), ("data", &fixture.data)] {
        let inside = tools.join(label);
        std::fs::rename(moved, &inside).unwrap();
        std::os::unix::fs::symlink(&inside, moved).unwrap();
        let profile = base.replace("name = \"agent\"", "name = \"agent\"\nprogram_root = 2");
        let ctx = |cwd: &Path| {
            let mut ctx = fixture.context(Box::new(platform()), cwd);
            if label == "config" {
                ctx.env_settings.config_dir = Some(inside.clone());
            } else {
                ctx.env_settings.data_dir = Some(inside.clone());
            }
            ctx
        };
        write(
            &(if label == "config" {
                inside.clone()
            } else {
                fixture.config.clone()
            })
            .join("launch/agent.toml"),
            profile.as_bytes(),
            0o600,
        );
        let error = match supervisor::resolve_plan(
            &ctx(&fixture.repo),
            &Fixture::policy("explain", &["--launch", "agent", "--from-path"]),
        ) {
            Ok(_) => panic!("{label}: must refuse"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::PolicyWidening, "{label}: {error}");
        assert_eq!(error.key_path.as_deref(), Some("--from-path"), "{label}");
        assert!(
            error.message.contains(&tools.display().to_string()),
            "{label}: {error}"
        );
        std::fs::remove_file(moved).unwrap();
        std::fs::rename(&inside, moved).unwrap();
    }
    fixture.profile("agent", &base);
    // A credential source inside the root.
    let source = tools.join("token");
    write(&source, b"token-value", 0o600);
    check(
        "credential source",
        &base
            .replace("@config/credentials/first", source.to_str().unwrap())
            .replace("name = \"agent\"", "name = \"agent\"\nprogram_root = 2"),
        &[],
        &tools,
    );
    std::fs::remove_file(&source).unwrap();

    // The root inside or containing the workspace, or inside a `--rw` root.
    let ws_bin = fixture.repo.join("bin");
    mkdir(&ws_bin, 0o755);
    write(&ws_bin.join("agent"), &static_elf(), 0o755);
    std::fs::rename(fixture.bin.join("agent"), fixture.root.join("agent.saved")).unwrap();
    std::fs::remove_dir(&fixture.bin).unwrap();
    std::os::unix::fs::symlink(&ws_bin, &fixture.bin).unwrap();
    check("inside the workspace", &base, &[], &ws_bin);
    std::fs::remove_file(&fixture.bin).unwrap();
    mkdir(&fixture.bin, 0o755);
    std::fs::rename(fixture.root.join("agent.saved"), fixture.bin.join("agent")).unwrap();
    check(
        "containing the workspace",
        &base.replace("name = \"agent\"", "name = \"agent\"\nprogram_root = 2"),
        &["--workspace", tools.join("bin").to_str().unwrap()],
        &tools,
    );
    let rw = tools.to_str().unwrap();
    check("inside a --rw root", &base, &["--rw", rw], &fixture.bin);
    // A directory in the root writable by others refuses at the pin.
    std::fs::set_permissions(&fixture.bin, std::fs::Permissions::from_mode(0o757)).unwrap();
    check("writable by others", &base, &[], &fixture.bin);
    std::fs::set_permissions(&fixture.bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    // `@program` cannot bind a `#!` script run by a system interpreter:
    // its connections come from the interpreter.
    write(&fixture.bin.join("agent"), b"#!/bin/sh\nexit 0\n", 0o755);
    let error = refused(
        fixture.plan(&fixture.repo, &["--launch", "agent", "--from-path"]),
        "a script bound to @program",
    );
    assert_eq!(error.code, ErrorCode::InvalidConfig, "{error}");
    assert_eq!(
        error.key_path.as_deref(),
        Some("launch.credentials.first.binaries"),
        "{error}"
    );
    write(&fixture.bin.join("agent"), &static_elf(), 0o755);
    // No program at all: invalid_config at --from-path.
    fixture.profile(
        "nothing",
        &base.replace("name = \"agent\"", "name = \"nothing\""),
    );
    let error = refused(
        fixture.plan(&fixture.repo, &["--launch", "nothing", "--from-path"]),
        "no program",
    );
    assert_eq!(error.code, ErrorCode::InvalidConfig);
    assert_eq!(error.key_path.as_deref(), Some("--from-path"));
    assert!(
        error.message.contains("never searched"),
        "{}",
        error.message
    );
}

// ---------------------------------------------------------------------------
// K37: a swap between resolution and release
// ---------------------------------------------------------------------------

/// K37: replacing the executable, or its install root, between resolution
/// and release refuses with an identity mismatch, and nothing is released.
#[test]
fn k37_a_swap_before_release_refuses_and_nothing_runs() {
    for swap_root in [false, true] {
        let fixture = Fixture::new();
        fixture.credential("first", b"token-value");
        let bin = fixture.bin.clone();
        let tools = fixture.root.join("tools");
        let platform = platform().on_prepare(move |_plan| {
            if swap_root {
                std::fs::rename(&bin, tools.join("bin.old")).unwrap();
                mkdir(&bin, 0o755);
            } else {
                std::fs::rename(bin.join("agent"), tools.join("agent.old")).unwrap();
            }
            write(&bin.join("agent"), b"#!/bin/sh\necho another file\n", 0o755);
        });
        let calls = platform.calls.clone();
        let report = fixture.run(platform, &fixture.repo, &["agent", "-p", "x"]);
        let error = report.error.as_ref().expect("a refusal");
        assert_eq!(error.code, ErrorCode::PolicyWidening, "{error}");
        assert_eq!(error.key_path.as_deref(), Some("--from-path"));
        assert!(error.message.contains("identity mismatch"), "{error}");
        let receipt = receipt(&report);
        assert_eq!(receipt["phase"], "refused", "{receipt:#}");
        assert_eq!(
            *calls.aborts.lock().unwrap(),
            1,
            "the boundary was torn down"
        );
        assert_eq!(report.exit_code, 125);
    }
}

// ---------------------------------------------------------------------------
// K38: interpreters
// ---------------------------------------------------------------------------

/// K38: `#!/usr/bin/env NAME` with NAME outside the runtime roots is
/// expanded to `[NAME', E, ARG...]` (that argv is the digest's), and NAME's
/// directory is granted read-only too; the unsupported forms refuse naming
/// the interpreter.
#[test]
fn k38_an_env_interpreter_outside_the_runtime_roots_is_made_explicit() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let runtime = fixture.root.join("runtime/bin");
    mkdir(&runtime, 0o755);
    std::fs::set_permissions(
        fixture.root.join("runtime"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    write(&runtime.join("j12node"), &static_elf(), 0o755);
    write(
        &fixture.bin.join("agent"),
        b"#!/usr/bin/env j12node\n",
        0o755,
    );
    let mut path = fixture.path_value();
    path.push(b':');
    path.extend_from_slice(runtime.as_os_str().as_bytes());
    let context = |platform: ScriptedPlatform| {
        let mut ctx = fixture.context(Box::new(platform), &fixture.repo);
        let path = path.clone();
        ctx.env_lookup = Box::new(move |name| (name == "PATH").then(|| path.clone()));
        ctx
    };
    let argv: Vec<OsString> = ["ukai-jail", "agent", "-p", "x"]
        .iter()
        .map(OsString::from)
        .collect();
    let cli::Command::Run(args) = Cli::try_parse_from(cli::alias_argv(&argv).unwrap())
        .unwrap()
        .command
    else {
        unreachable!()
    };
    let report = supervisor::run(&context(platform()), &args);
    assert!(report.error.is_none(), "{:?}", report.error);
    let receipt = receipt(&report);
    let expected = ukai_jail::canonical::argv_digest(&[
        runtime.join("j12node").as_os_str().as_bytes().to_vec(),
        fixture.bin.join("agent").as_os_str().as_bytes().to_vec(),
        b"-p".to_vec(),
        b"x".to_vec(),
    ]);
    assert_eq!(receipt["argv_digest"], expected);
    let grants: Vec<&str> = receipt["policy"]["grants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|grant| grant["by"] == "program_resolution")
        .map(|grant| grant["value"].as_str().unwrap())
        .collect();
    assert_eq!(
        grants,
        [fixture.bin.to_str().unwrap(), runtime.to_str().unwrap()],
        "{receipt:#}"
    );
    // The credential binding follows the interpreter.
    let plan = supervisor::resolve_plan(
        &context(platform()),
        &Fixture::policy("explain", &["--launch", "agent", "--from-path"]),
    )
    .unwrap();
    let binaries = &plan.resolved.snapshot.launch.as_ref().unwrap().credentials[0]
        .vault
        .as_ref()
        .unwrap()
        .binaries;
    assert_eq!(
        binaries,
        &[runtime.join("j12node").to_str().unwrap().to_owned()]
    );
    for (script, fragment) in [
        (&b"#!/usr/bin/env -S j12node --flag\n"[..], "/usr/bin/env"),
        (b"#!/usr/bin/env j12node --flag\n", "/usr/bin/env"),
        (b"#!/bin/sh -e -x\n", "/bin/sh"),
        (b"#!/opt/elsewhere/interp\n", "/opt/elsewhere/interp"),
    ] {
        write(&fixture.bin.join("agent"), script, 0o755);
        let error = refused(
            supervisor::resolve_plan(
                &context(platform()),
                &Fixture::policy("explain", &["--launch", "agent", "--from-path"]),
            ),
            &String::from_utf8_lossy(script),
        );
        assert_eq!(error.key_path.as_deref(), Some("--from-path"));
        assert!(error.message.contains(fragment), "{}", error.message);
    }
    // A nested script behind `env` refuses naming it.
    write(
        &fixture.bin.join("agent"),
        b"#!/usr/bin/env j12node\n",
        0o755,
    );
    write(&runtime.join("j12node"), b"#!/bin/sh\n", 0o755);
    let error = refused(
        supervisor::resolve_plan(
            &context(platform()),
            &Fixture::policy("explain", &["--launch", "agent", "--from-path"]),
        ),
        "nested",
    );
    assert!(error.message.contains("nested script"), "{}", error.message);
    assert!(error.message.contains("j12node"), "{}", error.message);
}

// ---------------------------------------------------------------------------
// K39: disclosure
// ---------------------------------------------------------------------------

/// K39: each derived grant appears in `explain` (text and JSON), in the
/// provenance, and in the receipt's `policy.grants` as
/// `by: "program_resolution"`; an operator's own `--ro` of the same path
/// stays `by: "operator"` and the derived one is disclosed as covered.
#[test]
fn k39_every_derived_grant_is_disclosed_and_attributed() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let bin = fixture.bin.to_str().unwrap();
    let output = fixture.binary(
        &fixture.repo.join("src"),
        &["explain", "--launch", "agent", "--from-path"],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    for line in [
        format!("program agent = {bin}/agent format=elf"),
        format!("program argv {bin}/agent"),
        format!("program read_only {bin} by=program_resolution"),
        format!("read_only host:{bin}"),
        "cwd workspace:src".to_owned(),
    ] {
        assert!(stdout.lines().any(|l| l == line), "{line:?} in\n{stdout}");
    }
    let output = fixture.binary(
        &fixture.repo,
        &["explain", "--launch", "agent", "--from-path", "--json"],
        None,
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["program"]["name"], "agent", "{json:#}");
    assert_eq!(json["program"]["roots"][0]["path"], bin);
    assert_eq!(json["program"]["roots"][0]["status"], "granted");
    assert_eq!(json["program"]["roots"][0]["by"], "program_resolution");
    assert!(json["provenance"].as_array().unwrap().iter().any(|entry| {
        entry["origin"] == "program-resolution" && entry["key"] == "filesystem.read_only"
    }));
    assert!(
        json["provenance"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["origin"] == "program-resolution" && entry["key"] == "program" })
    );

    let report = fixture.run(platform(), &fixture.repo, &["agent"]);
    let grants = receipt(&report)["policy"]["grants"].clone();
    assert_eq!(
        grants,
        serde_json::json!([
            {"kind": "allow_host", "value": "api.example.com:443", "by": "operator"},
            {"kind": "read_only", "value": bin, "by": "program_resolution"},
        ]),
        "{grants:#}"
    );
    // The operator's own `--ro` of the same root keeps `operator`, and
    // program resolution adds nothing beside it.
    let report = fixture.run(
        platform(),
        &fixture.repo,
        &["run", "--launch", "agent", "--from-path", "--ro", bin, "--"],
    );
    assert!(report.error.is_none(), "{:?}", report.error);
    let grants = receipt(&report)["policy"]["grants"].clone();
    let read_only: Vec<&serde_json::Value> = grants
        .as_array()
        .unwrap()
        .iter()
        .filter(|grant| grant["kind"] == "read_only")
        .collect();
    assert_eq!(
        read_only,
        [&serde_json::json!({"kind": "read_only", "value": bin, "by": "operator"})],
        "{grants:#}"
    );
    let explain = fixture.explain(
        &fixture.repo,
        &["--launch", "agent", "--from-path", "--ro", bin],
    );
    let (_, roots) = explain.program.as_ref().unwrap();
    assert!(!roots[0].granted);
    assert_eq!(roots[0].covered_by.as_deref(), Some(bin));
}

// ---------------------------------------------------------------------------
// K40: a project file under the alias
// ---------------------------------------------------------------------------

/// K40: a project `ukai.toml` may deny-read the install root and shrink the
/// hosts; every widening key still refuses with its existing code.
#[test]
fn k40_a_project_file_still_only_narrows() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let project = fixture.repo.join("ukai.toml");
    let bin = fixture.bin.to_str().unwrap();
    write(
        &project,
        format!(
            "[jail]\nschema = \"ukai.jail.policy/1\"\n[jail.filesystem]\ndeny_read = [\"{bin}\"]\n\
             [jail.network]\nallow = []\n"
        )
        .as_bytes(),
        0o644,
    );
    let plan = fixture
        .plan(
            &fixture.repo.join("src"),
            &["--launch", "agent", "--from-path"],
        )
        .unwrap();
    let snapshot = &plan.resolved.snapshot;
    assert!(
        snapshot
            .filesystem
            .deny_read
            .iter()
            .any(|reference| reference.path.as_bytes() == bin.as_bytes())
    );
    assert!(
        snapshot.network.allow.is_empty(),
        "{:?}",
        snapshot.network.allow
    );
    for (body, key) in [
        (
            "[jail.credentials.x]\nsource = \"/x\"\nmode = \"vault\"\n",
            "jail.credentials",
        ),
        (
            "[jail.network]\nallow = [\"evil.example\"]\n",
            "jail.network.allow",
        ),
        (
            "[jail.filesystem]\nread_write = [\"/srv\"]\n",
            "jail.filesystem.read_write",
        ),
        ("[jail.network]\nmode = \"host\"\n", "jail.network.mode"),
    ] {
        write(
            &project,
            format!("[jail]\nschema = \"ukai.jail.policy/1\"\n{body}").as_bytes(),
            0o644,
        );
        let error = refused(
            fixture.plan(
                &fixture.repo.join("src"),
                &["--launch", "agent", "--from-path"],
            ),
            key,
        );
        assert!(
            matches!(
                error.code,
                ErrorCode::PolicyWidening | ErrorCode::InvalidConfig
            ),
            "{key}: {error}"
        );
        assert_eq!(error.key_path.as_deref(), Some(key), "{error}");
    }
}

// ---------------------------------------------------------------------------
// K42: credentials_one_of
// ---------------------------------------------------------------------------

/// K42: the first present source is staged and the rest skipped; only
/// absence counts as absent; none present refuses before anything is
/// prepared, listing every hint; the receipt lists only the staged id.
#[test]
fn k42_the_first_present_credential_is_staged() {
    let staged = |fixture: &Fixture| {
        let report = fixture.run(platform(), &fixture.repo, &["agent", "-p", "x"]);
        (
            report.error.clone(),
            report.receipt.as_ref().map(|_| receipt(&report)),
        )
    };
    // Both present: the first.
    let fixture = Fixture::new();
    fixture.credential("first", b"first-value");
    fixture.credential("second", b"second-value");
    let (error, receipt) = staged(&fixture);
    assert!(error.is_none(), "{error:?}");
    let ids: Vec<&str> = receipt.as_ref().unwrap()["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["first"]);
    let plan = fixture
        .plan(&fixture.repo, &["--launch", "agent", "--from-path"])
        .unwrap();
    assert!(plan.resolved.provenance.iter().any(|entry| {
        entry.key == "launch.credentials.second"
            && entry
                .detail
                .as_deref()
                .is_some_and(|d| d.starts_with("skipped"))
    }));
    // Only the second present: it, and the first is recorded skipped.
    let fixture = Fixture::new();
    fixture.credential("second", b"second-value");
    let (error, receipt) = staged(&fixture);
    assert!(error.is_none(), "{error:?}");
    assert_eq!(receipt.as_ref().unwrap()["credentials"][0]["id"], "second");
    assert_eq!(
        receipt.as_ref().unwrap()["credentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let plan = fixture
        .plan(&fixture.repo, &["--launch", "agent", "--from-path"])
        .unwrap();
    assert!(plan.resolved.provenance.iter().any(|entry| {
        entry.key == "launch.credentials.first"
            && entry.detail.as_deref() == Some("skipped: absent")
    }));
    // A present but unsafe first source refuses; it is never skipped for the
    // second.
    let unsafe_first: [(&str, Spoil); 3] = [
        (
            "readable by others",
            Box::new(|path: &Path| {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
            }),
        ),
        (
            "a second link",
            Box::new(|path: &Path| {
                std::fs::hard_link(path, path.with_file_name("first-link")).unwrap();
            }),
        ),
        (
            "a symlink",
            Box::new(|path: &Path| {
                let target = path.with_file_name("first-target");
                std::fs::rename(path, &target).unwrap();
                std::os::unix::fs::symlink(&target, path).unwrap();
            }),
        ),
    ];
    for (label, spoil) in unsafe_first {
        let fixture = Fixture::new();
        let first = fixture.credential("first", b"first-value");
        fixture.credential("second", b"second-value");
        spoil(&first);
        let (error, receipt) = staged(&fixture);
        let error = error.unwrap_or_else(|| panic!("{label}: must refuse"));
        assert_eq!(
            error.code,
            ErrorCode::CredentialUnavailable,
            "{label}: {error}"
        );
        if let Some(receipt) = receipt {
            assert!(
                receipt["credentials"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| row["id"] != "second"),
                "{label}: the second was staged instead"
            );
        }
    }
    // None present: refused before anything is prepared, with both hints.
    let fixture = Fixture::new();
    let (error, receipt) = staged(&fixture);
    let error = error.expect("a refusal");
    assert_eq!(error.code, ErrorCode::CredentialUnavailable);
    assert_eq!(error.key_path.as_deref(), Some("launch.credentials_one_of"));
    for hint in [
        "store it with `ukai-jail credential set first`",
        "store it with `ukai-jail credential set second`",
    ] {
        assert!(error.message.contains(hint), "{}", error.message);
    }
    assert!(receipt.is_none(), "nothing was claimed");
}

// ---------------------------------------------------------------------------
// K43: the binding to the program, reported by doctor
// ---------------------------------------------------------------------------

/// K43: `doctor` reports the expanded-interpreter binding (a credential bound
/// to `@program` then binds the interpreter), the hints of missing sources,
/// and that interactive sessions are unrecorded.
#[test]
fn k43_doctor_reports_the_binding_hints_and_the_headless_claim() {
    let fixture = Fixture::new();
    let runtime = fixture.root.join("tools/rt");
    mkdir(&runtime, 0o755);
    write(&runtime.join("j12node"), &static_elf(), 0o755);
    write(&fixture.bin.join("j12node"), &static_elf(), 0o755);
    write(
        &fixture.bin.join("agent"),
        b"#!/usr/bin/env j12node\n",
        0o755,
    );
    let output = fixture.binary(
        &fixture.repo,
        &["doctor", "--launch", "agent", "--from-path"],
        None,
    );
    let stdout = text(&output.stdout);
    assert!(
        stdout.contains(
            "program binding: a credential bound to `@program` is bound to the interpreter"
        ),
        "{stdout}\n{}",
        text(&output.stderr)
    );
    assert!(
        stdout.contains("credential first hint: store it with `ukai-jail credential set first`"),
        "{stdout}"
    );
    assert!(
        stdout.contains("interactive_sessions unrecorded"),
        "{stdout}"
    );
    // With neither source, doctor is not ready; with one, the alternative
    // is enough.
    assert!(stdout.lines().any(|line| line == "ready false"), "{stdout}");
}

// ---------------------------------------------------------------------------
// K44: credential set / rm
// ---------------------------------------------------------------------------

/// K44: `credential set` stores one value from stdin (one trailing LF
/// stripped) in a 0700 directory and a 0600 file, never prints it, refuses
/// an existing file without `--force` and a value with a line break naming
/// that cause; `rm` removes it.
#[test]
fn k44_credential_set_and_rm() {
    let fixture = Fixture::new();
    let value = b"sk-ant-oat01-fixture-value";
    let mut input = value.to_vec();
    input.push(b'\n');
    let set = fixture.binary(&fixture.repo, &["credential", "set", "first"], Some(&input));
    assert_eq!(set.status.code(), Some(0), "{}", text(&set.stderr));
    let path = fixture.config.join("credentials/first");
    assert_eq!(std::fs::read(&path).unwrap(), value);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o7777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&fixture.config.join("credentials")), 0o700);
    for (label, stream) in [("stdout", &set.stdout), ("stderr", &set.stderr)] {
        assert!(
            !stream.windows(value.len()).any(|window| window == value),
            "the value is on {label}"
        );
    }
    assert!(set.stdout.is_empty());
    // An existing file without --force: refused, unchanged.
    let again = fixture.binary(
        &fixture.repo,
        &["credential", "set", "first"],
        Some(b"other\n"),
    );
    assert_eq!(again.status.code(), Some(1));
    assert!(
        text(&again.stderr).contains("--force"),
        "{}",
        text(&again.stderr)
    );
    assert_eq!(std::fs::read(&path).unwrap(), value);
    let forced = fixture.binary(
        &fixture.repo,
        &["credential", "set", "--force", "first"],
        Some(b"replacement\n"),
    );
    assert_eq!(forced.status.code(), Some(0), "{}", text(&forced.stderr));
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    // A token pasted from a wrapped terminal line: refused, naming the
    // cause, and nothing stored.
    let wrapped = fixture.binary(
        &fixture.repo,
        &["credential", "set", "second"],
        Some(b"sk-ant-oat01-first-half\nsecond-half\n"),
    );
    assert_eq!(wrapped.status.code(), Some(1));
    let stderr = text(&wrapped.stderr);
    assert!(
        stderr.contains("line break") && stderr.contains("wrapped terminal line"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("first-half") && !stderr.contains("second-half"),
        "{stderr}"
    );
    assert!(!fixture.config.join("credentials/second").exists());
    // A malformed id is a usage error.
    let bad = fixture.binary(&fixture.repo, &["credential", "set", "../x"], Some(b"v\n"));
    assert_eq!(bad.status.code(), Some(2));
    // rm removes it; a second rm says there is none.
    let rm = fixture.binary(&fixture.repo, &["credential", "rm", "first"], None);
    assert_eq!(rm.status.code(), Some(0), "{}", text(&rm.stderr));
    assert!(!path.exists());
    let rm = fixture.binary(&fixture.repo, &["credential", "rm", "first"], None);
    assert_eq!(rm.status.code(), Some(1));
    assert!(
        text(&rm.stderr).contains("no credential"),
        "{}",
        text(&rm.stderr)
    );
    // The verbs refuse a symlink and a shared-writable directory.
    let elsewhere = fixture.root.join("elsewhere");
    write(&elsewhere, b"untouched", 0o600);
    std::os::unix::fs::symlink(&elsewhere, fixture.config.join("credentials/first")).unwrap();
    for argv in [
        &["credential", "set", "--force", "first"][..],
        &["credential", "rm", "first"],
    ] {
        let output = fixture.binary(&fixture.repo, argv, Some(b"v\n"));
        assert_eq!(output.status.code(), Some(1), "{argv:?}");
    }
    assert_eq!(std::fs::read(&elsewhere).unwrap(), b"untouched");
    std::fs::remove_file(fixture.config.join("credentials/first")).unwrap();
    std::fs::set_permissions(
        fixture.config.join("credentials"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let shared = fixture.binary(&fixture.repo, &["credential", "set", "first"], Some(b"v\n"));
    assert_eq!(shared.status.code(), Some(1));
    assert!(!fixture.config.join("credentials/first").exists());
}

/// The stored file is what a run stages: `credential set` then the alias
/// resolves the credential the profile names under `@config/`.
#[test]
fn k44_a_stored_credential_is_the_one_the_alias_stages() {
    let fixture = Fixture::new();
    let set = fixture.binary(
        &fixture.repo,
        &["credential", "set", "second"],
        Some(b"key\n"),
    );
    assert_eq!(set.status.code(), Some(0), "{}", text(&set.stderr));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let platform = platform().on_prepare(move |plan| {
        let launch = plan.request.snapshot.launch.as_ref().unwrap();
        recorded
            .lock()
            .unwrap()
            .extend(launch.credentials.iter().map(|c| c.id.clone()));
    });
    let report = fixture.run(platform, &fixture.repo, &["agent", "-p", "x"]);
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(*seen.lock().unwrap(), ["second"]);
}

// ---------------------------------------------------------------------------
// J12 adversarial review, 2026-10-16: killer tests
//
// `review_bug_*` fail on 4e40f8491: each pins a finding of the review
// (j12-adversarial-review.md). Every other `review_*` passes on 4e40f8491
// and kills a mutant of a refusal gate that the K-rows let survive.
// ---------------------------------------------------------------------------

/// The fixture's context with `path` as the operator's PATH.
fn context_with_path(
    fixture: &Fixture,
    platform: Box<dyn Platform>,
    cwd: &Path,
    path: Vec<u8>,
) -> supervisor::Context {
    let mut ctx = fixture.context(platform, cwd);
    ctx.env_lookup = Box::new(move |name| (name == "PATH").then(|| path.clone()));
    ctx
}

fn from_path_plan(ctx: &supervisor::Context) -> Result<supervisor::Plan, JailError> {
    supervisor::resolve_plan(
        ctx,
        &Fixture::policy("explain", &["--launch", "agent", "--from-path"]),
    )
}

/// The `binaries` of the first credential the plan stages.
fn bound_binaries(plan: &supervisor::Plan) -> Vec<String> {
    plan.resolved.snapshot.launch.as_ref().unwrap().credentials[0]
        .vault
        .as_ref()
        .unwrap()
        .binaries
        .clone()
}

fn join_path(dirs: &[&Path]) -> Vec<u8> {
    dirs.iter()
        .map(|dir| dir.as_os_str().as_bytes().to_vec())
        .collect::<Vec<_>>()
        .join(&b':')
}

/// Review F1 (fails on 4e40f8491): an absolute PATH entry inside the
/// workspace (direnv's `PATH_add`, an activated in-repository virtualenv, a
/// `node_modules/.bin`) lets the repository choose the program. A regular
/// file there refuses (its install root overlaps the workspace), but a
/// symlink the repository ships is canonicalized to whatever trusted file it
/// names, which is then run as the launch name and bound to `@program`. The
/// reason §3.3 step 1 gives for skipping relative entries ("the invocation
/// directory, which a hostile repository controls, [would] pick the
/// program") holds for this entry too.
#[test]
fn review_bug_a_path_entry_inside_the_workspace_never_chooses_the_program() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    // Another operator tool, outside every root, trustworthy on its own.
    let other = fixture.root.join("tools/other");
    mkdir(&other, 0o755);
    write(&other.join("tool"), &static_elf(), 0o755);
    // The repository ships `.bin/agent -> <that tool>`.
    let planted = fixture.repo.join(".bin");
    mkdir(&planted, 0o755);
    std::os::unix::fs::symlink(other.join("tool"), planted.join("agent")).unwrap();
    let ctx = context_with_path(
        &fixture,
        Box::new(platform()),
        &fixture.repo,
        join_path(&[&planted, &fixture.bin]),
    );
    match from_path_plan(&ctx) {
        Err(error) => assert_eq!(error.key_path.as_deref(), Some("--from-path"), "{error}"),
        Ok(plan) => panic!(
            "the repository chose the program: `agent` = {}, credential bound to {:?}",
            plan.program.as_ref().unwrap().program.path.display(),
            bound_binaries(&plan)
        ),
    }
}

/// Review F2 (fails on 4e40f8491): `@program` refuses a `#!` script whose
/// interpreter is a system one (its connections come from the interpreter,
/// which "would admit every script it runs"), but `#!/usr/bin/env X` with X
/// resolving inside the runtime roots is expanded and binds the credential
/// to that very system interpreter (`/bin/sh`, `/usr/bin/python3`,
/// `/usr/bin/node`), so any `sh -c`/`python3 -c` the agent's shell tool runs
/// presents it. §3.3 step 5 defines the expansion only for X outside the
/// runtime roots; inside them the script is a `#!` script with a system
/// interpreter and `@program` must refuse as it does for `#!/bin/sh`.
#[test]
fn review_bug_env_with_a_system_interpreter_cannot_carry_program() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    write(&fixture.bin.join("agent"), b"#!/usr/bin/env sh\n", 0o755);
    let ctx = fixture.context(Box::new(platform()), &fixture.repo);
    match from_path_plan(&ctx) {
        Err(error) => {
            assert_eq!(error.code, ErrorCode::InvalidConfig, "{error}");
            assert_eq!(
                error.key_path.as_deref(),
                Some("launch.credentials.first.binaries"),
                "{error}"
            );
        }
        Ok(plan) => panic!(
            "`@program` bound the credential to the system interpreter {:?}",
            bound_binaries(&plan)
        ),
    }
}

/// A relative PATH entry is never searched by the real binary, whose
/// process directory is the invocation directory (the in-process K36 plan
/// runs from the crate directory, so it never meets the planted file).
/// Kills: `find_on_path` searching relative entries.
#[test]
fn review_a_relative_path_entry_never_resolves_in_the_invocation_directory() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    // `path_value` holds `relative/bin` before `tools/bin`.
    mkdir(&fixture.repo.join("relative/bin"), 0o755);
    write(
        &fixture.repo.join("relative/bin/agent"),
        &static_elf(),
        0o755,
    );
    let output = fixture.binary(
        &fixture.repo,
        &["explain", "--launch", "agent", "--from-path"],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let expected = format!("program agent = {}/agent format=elf", fixture.bin.display());
    assert!(
        text(&output.stdout).lines().any(|line| line == expected),
        "{}",
        text(&output.stdout)
    );
}

/// A directory, or a FIFO, named like the program is passed over as a shell
/// passes it over, so the real program further down PATH is found.
/// Kills: `find_on_path` accepting a non-regular candidate.
#[test]
fn review_a_directory_named_like_the_program_is_passed_over() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let first = fixture.root.join("tools/first");
    mkdir(&first.join("agent"), 0o755);
    let ctx = context_with_path(
        &fixture,
        Box::new(platform()),
        &fixture.repo,
        join_path(&[&first, &fixture.bin]),
    );
    let plan = from_path_plan(&ctx).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        plan.program.as_ref().unwrap().program.path,
        fixture.bin.join("agent")
    );
}

/// A world-writable directory without the sticky bit above the install root
/// refuses at the pin, naming it: another user could rename the root away.
/// Kills: `check_directory` without its writable-by-others rule.
#[test]
fn review_a_world_writable_ancestor_of_the_install_root_refuses() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let tools = fixture.root.join("tools");
    std::fs::set_permissions(&tools, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error = refused(
        fixture.plan(&fixture.repo, &["--launch", "agent", "--from-path"]),
        "world-writable ancestor",
    );
    assert_eq!(error.code, ErrorCode::PolicyWidening, "{error}");
    assert_eq!(error.key_path.as_deref(), Some("--from-path"));
    assert!(
        error.message.contains(&tools.display().to_string()),
        "{error}"
    );
    std::fs::set_permissions(&tools, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The user database's home refuses as a workspace whatever HOME says
/// (here HOME is the fixture's). Kills: `operator_homes` without the
/// database entry. Inspection only: nothing is written to that home.
#[test]
fn review_the_database_home_refuses_whatever_home_says() {
    // SAFETY: getpwuid returns null or a pointer to static storage that
    // stays valid until the next call on this thread.
    let home = unsafe {
        let entry = libc::getpwuid(libc::geteuid());
        if entry.is_null() || (*entry).pw_dir.is_null() {
            return;
        }
        PathBuf::from(OsString::from(std::ffi::OsStr::from_bytes(
            std::ffi::CStr::from_ptr((*entry).pw_dir).to_bytes(),
        )))
    };
    let Ok(home) = home.canonicalize() else {
        return;
    };
    let fixture = Fixture::new();
    // A fixture beneath that home would meet other refusals first.
    if !home.is_dir() || fixture.root.starts_with(&home) {
        return;
    }
    fixture.credential("first", b"token-value");
    let error = refused(
        fixture.plan(
            &fixture.repo,
            &[
                "--launch",
                "agent",
                "--from-path",
                "--workspace",
                home.to_str().unwrap(),
            ],
        ),
        "the database home",
    );
    assert_eq!(error.code, ErrorCode::PolicyWidening, "{error}");
    assert_eq!(error.key_path.as_deref(), Some("--workspace"), "{error}");
}

/// A `.git` file longer than 4 KiB is not a gitfile, whatever it begins
/// with. Kills: `is_repository_top` without its size bound.
#[test]
fn review_an_oversized_gitfile_is_not_a_top_level() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let mut big = b"gitdir: /elsewhere/.git/worktrees/deep\n".to_vec();
    big.resize(4097, b'#');
    write(&fixture.repo.join("src/deep/.git"), &big, 0o644);
    let plan = fixture
        .plan(
            &fixture.repo.join("src/deep"),
            &["--launch", "agent", "--from-path"],
        )
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(plan.workspace, fixture.repo);
}

/// X05: with stderr a pipe, `ukai-jail NAME` adds no pre-exec line.
/// Kills: the pre-exec line without its terminal gate.
#[test]
fn review_no_pre_exec_line_when_stderr_is_not_a_terminal() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let output = fixture.binary(&fixture.repo, &["agent", "-p", "x"], None);
    let stderr = text(&output.stderr);
    assert!(!stderr.contains("ukai-jail: agent ="), "{stderr}");
}

/// K39 on a terminal: the pre-exec line names the program and its root, and
/// `--quiet` suppresses it. Runs the binary under `script(1)`, which gives
/// it a pseudo-terminal. Kills: the pre-exec line without its quiet gate.
#[test]
fn review_the_pre_exec_line_on_a_terminal_and_quiet() {
    let script = Path::new("/usr/bin/script");
    if !script.exists() {
        return;
    }
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let under_pty = |extra: &[&str]| -> String {
        let mut words: Vec<String> = vec![
            env!("CARGO_BIN_EXE_ukai-jail").to_owned(),
            "run".into(),
            "--launch".into(),
            "agent".into(),
            "--from-path".into(),
        ];
        words.extend(extra.iter().map(|word| (*word).to_owned()));
        words.extend(["--".into(), "-p".into(), "x".into()]);
        let mut command = Command::new(script);
        if cfg!(target_os = "macos") {
            command.arg("-q").arg("/dev/null").args(&words);
        } else {
            let quoted: Vec<String> = words
                .iter()
                .map(|word| format!("'{}'", word.replace('\'', "'\\''")))
                .collect();
            command
                .args(["-q", "-e", "-c"])
                .arg(quoted.join(" "))
                .arg("/dev/null");
        }
        let output = command
            .env_clear()
            .env(
                "PATH",
                OsString::from(std::ffi::OsStr::from_bytes(&fixture.path_value())),
            )
            .env("HOME", &fixture.home)
            .env("UKAI_DATA_DIR", &fixture.data)
            .env("UKAI_CONFIG_DIR", &fixture.config)
            .current_dir(&fixture.repo)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("script runs");
        text(&output.stdout)
    };
    let line = format!(
        "ukai-jail: agent = {bin}/agent (read-only: {bin})",
        bin = fixture.bin.display()
    );
    let shown = under_pty(&[]);
    assert!(shown.contains(&line), "{line:?} in {shown:?}");
    let quiet = under_pty(&["--quiet"]);
    assert!(!quiet.contains("ukai-jail: agent ="), "{quiet:?}");
}

/// A platform that runs `swap` the first time it is asked to probe: after
/// resolution, before credentials are staged.
struct SwapOnProbe {
    inner: ScriptedPlatform,
    swap: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Platform for SwapOnProbe {
    fn identity(&self) -> ukai_jail::platform::PlatformIdentity {
        self.inner.identity()
    }
    fn owner_identity(&self) -> Option<ukai_jail::platform::OwnerIdentity> {
        self.inner.owner_identity()
    }
    fn probe(
        &self,
        plan: &ukai_jail::platform::PlanRequest,
    ) -> Vec<ukai_jail::capability::Capability> {
        if let Some(swap) = self.swap.lock().unwrap().take() {
            swap();
        }
        self.inner.probe(plan)
    }
    fn prepare(
        &self,
        plan: ukai_jail::platform::PreparedPlan,
        sinks: ukai_jail::platform::Sinks,
    ) -> Result<Box<dyn ukai_jail::platform::PreparedExecution>, JailError> {
        self.inner.prepare(plan, sinks)
    }
}

/// §3.3 step 7: a swap between resolution and staging refuses at staging,
/// so a credential is never pinned to the replacement. Kills:
/// `check_program_binding` (or its call) removed, which leaves only the
/// gate's recheck to notice.
#[test]
fn review_a_swap_before_staging_refuses_at_staging() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let bin = fixture.bin.clone();
    let tools = fixture.root.join("tools");
    let platform = SwapOnProbe {
        inner: platform(),
        swap: Mutex::new(Some(Box::new(move || {
            std::fs::rename(bin.join("agent"), tools.join("agent.old")).unwrap();
            write(&bin.join("agent"), &static_elf(), 0o755);
        }))),
    };
    let ctx = fixture.context(Box::new(platform), &fixture.repo);
    let argv: Vec<OsString> = ["ukai-jail", "agent", "-p", "x"]
        .iter()
        .map(OsString::from)
        .collect();
    let cli::Command::Run(args) = Cli::try_parse_from(cli::alias_argv(&argv).unwrap())
        .unwrap()
        .command
    else {
        unreachable!()
    };
    let report = supervisor::run(&ctx, &args);
    let error = report.error.as_ref().expect("a refusal");
    assert_eq!(error.code, ErrorCode::PolicyWidening, "{error}");
    assert_eq!(error.key_path.as_deref(), Some("--from-path"));
    assert!(error.message.contains("staging"), "{error}");
}

/// Every clap subcommand is a built-in verb the alias never takes as a
/// launch name. Kills: a verb dropped from `VERBS`.
#[test]
fn review_every_subcommand_is_a_verb() {
    use clap::CommandFactory as _;
    for command in Cli::command().get_subcommands() {
        let name = command.get_name();
        assert!(cli::VERBS.contains(&name), "`{name}` is missing from VERBS");
        let argv: Vec<OsString> = ["ukai-jail", name].iter().map(OsString::from).collect();
        assert_eq!(cli::alias_argv(&argv), None, "{name}");
    }
    assert!(cli::VERBS.contains(&"help"));
}

/// Review F3 (fails on 4e40f8491): "the binary is outside every writable
/// grant" is checked by path only. A program file with a second name inside
/// the workspace (a package manager's hard-linked store: bun's and pnpm's
/// default on Linux, when the repository depends on the same package
/// version) passes every placement refusal and the recheck, and a write
/// through the workspace name rewrites, in place, the file the operator's
/// next unjailed launch runs. Credential sources already refuse a second
/// link (`source_multiply_linked`).
#[test]
fn review_bug_a_program_with_a_second_name_in_the_workspace_refuses() {
    use std::io::Write as _;
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let store = fixture.repo.join("node_modules/.store");
    mkdir(&store, 0o755);
    std::fs::hard_link(fixture.bin.join("agent"), store.join("agent")).unwrap();
    match fixture.plan(&fixture.repo, &["--launch", "agent", "--from-path"]) {
        Err(error) => assert_eq!(error.key_path.as_deref(), Some("--from-path"), "{error}"),
        Ok(plan) => {
            // What a contained writer of the workspace can then do: rewrite
            // the program in place through the workspace name. The identity
            // is unchanged, so the recheck still passes.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(store.join("agent"))
                .unwrap();
            file.write_all(b"\x7fELF-rewritten-by-the-workspace")
                .unwrap();
            drop(file);
            let program = plan.program.as_ref().unwrap();
            let recheck = program.recheck();
            let now = std::fs::read(fixture.bin.join("agent")).unwrap();
            panic!(
                "accepted {} with a second name in the workspace; after a write through \
                 that name the recheck says {:?} and the program begins {:?}",
                program.program.path.display(),
                recheck.map_err(|error| error.message),
                String::from_utf8_lossy(&now[..20])
            );
        }
    }
}

/// The install root at the operator's home refuses on its own rule, with
/// the workspace outside the home (inside it, the workspace-overlap rule
/// masks a missing home rule). Kills: the placement's home refusal removed.
#[test]
fn review_an_install_root_at_the_home_refuses_with_the_workspace_elsewhere() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let home_bin = fixture.home.join("bin");
    mkdir(&home_bin, 0o755);
    write(&home_bin.join("agent"), &static_elf(), 0o755);
    fixture.profile(
        "agent",
        &AGENT_PROFILE.replace("name = \"agent\"", "name = \"agent\"\nprogram_root = 2"),
    );
    let outside = fixture.root.join("outside");
    mkdir(&outside.join(".git"), 0o755);
    write(&outside.join(".git/HEAD"), b"ref: refs/heads/main\n", 0o644);
    let ctx = context_with_path(
        &fixture,
        Box::new(platform()),
        &outside,
        join_path(&[&home_bin]),
    );
    let error = match from_path_plan(&ctx) {
        Ok(_) => panic!("an install root at the home must refuse"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::PolicyWidening, "{error}");
    assert_eq!(error.key_path.as_deref(), Some("--from-path"));
    assert!(error.message.contains("home"), "{error}");
}

/// An install root that contains a writable root refuses even when the
/// executable is not inside that writable root. Kills: the overlap reduced
/// to "the root lies inside a writable root".
#[test]
fn review_an_install_root_containing_a_writable_root_refuses() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let tools = fixture.root.join("tools");
    let cache = tools.join("cache");
    mkdir(&cache, 0o755);
    fixture.profile(
        "agent",
        &AGENT_PROFILE.replace("name = \"agent\"", "name = \"agent\"\nprogram_root = 2"),
    );
    let error = refused(
        fixture.plan(
            &fixture.repo,
            &[
                "--launch",
                "agent",
                "--from-path",
                "--rw",
                cache.to_str().unwrap(),
            ],
        ),
        "a writable root inside the install root",
    );
    assert_eq!(error.code, ErrorCode::PolicyWidening, "{error}");
    assert_eq!(error.key_path.as_deref(), Some("--from-path"));
    assert!(
        error.message.contains(&tools.display().to_string()),
        "{error}"
    );
}

/// K35 through a symlinked invocation directory: `roots.cwd` is where the
/// operator stood, canonical; at the top level nothing is recorded, not even
/// provenance. Kills: `child_cwd` without canonicalization, and recording an
/// empty `roots.cwd`.
#[test]
fn review_roots_cwd_through_a_symlinked_invocation_directory() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    std::os::unix::fs::symlink(fixture.repo.join("src"), fixture.root.join("link")).unwrap();
    let args = ["--launch", "agent", "--from-path"];
    let plan = fixture.plan(&fixture.root.join("link"), &args).unwrap();
    assert_eq!(plan.resolved.snapshot.roots.cwd.as_bytes(), b"src");
    let top = fixture.plan(&fixture.repo, &args).unwrap();
    assert!(
        !top.resolved
            .provenance
            .iter()
            .any(|entry| entry.key == "roots.cwd"),
        "{:?}",
        top.resolved.provenance
    );
}

/// `credentials_one_of` (K42): a first source that is a dangling symlink, or
/// that lies in a directory others can write, is present and unsafe: the run
/// refuses and never stages the second (the paying) credential. Kills:
/// absence judged by a following `stat` (a dangling link reads as absent),
/// and every walk refusal read as absence.
#[test]
fn review_an_unsafe_first_source_never_falls_through_to_the_second() {
    type Prepare = Box<dyn Fn(&Fixture)>;
    let cases: [(&str, Prepare); 2] = [
        (
            "a dangling symlink",
            Box::new(|fixture: &Fixture| {
                let directory = fixture.config.join("credentials");
                mkdir(&directory, 0o700);
                std::os::unix::fs::symlink(fixture.root.join("nowhere"), directory.join("first"))
                    .unwrap();
            }),
        ),
        (
            "a shared-writable directory",
            Box::new(|fixture: &Fixture| {
                let directory = fixture.config.join("shared");
                mkdir(&directory, 0o700);
                write(&directory.join("first"), b"first-value", 0o600);
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777))
                    .unwrap();
                fixture.profile(
                    "agent",
                    &AGENT_PROFILE.replace("@config/credentials/first", "@config/shared/first"),
                );
            }),
        ),
    ];
    for (label, prepare) in cases {
        let fixture = Fixture::new();
        fixture.credential("second", b"second-value");
        prepare(&fixture);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let platform = platform().on_prepare(move |plan| {
            if let Some(launch) = plan.request.snapshot.launch.as_ref() {
                recorded
                    .lock()
                    .unwrap()
                    .extend(launch.credentials.iter().map(|c| c.id.clone()));
            }
        });
        let report = fixture.run(platform, &fixture.repo, &["agent", "-p", "x"]);
        assert!(report.error.is_some(), "{label}: must refuse");
        assert!(
            !seen.lock().unwrap().iter().any(|id| id == "second"),
            "{label}: fell through to the second credential"
        );
        if report.receipt.is_some() {
            let receipt = receipt(&report);
            assert!(
                receipt["credentials"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| row["id"] != "second"),
                "{label}: {receipt:#}"
            );
        }
    }
}

/// `@program` without `--from-path` and with a relative PROGRAM refuses at
/// the key, before anything is staged. Kills: that refusal removed (the
/// vault then refuses later under another key).
#[test]
fn review_program_token_with_a_relative_program_refuses_at_its_key() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let report = fixture.run(
        platform(),
        &fixture.repo,
        &["run", "--launch", "agent", "--", "agent"],
    );
    let error = report.error.expect("a refusal");
    assert_eq!(error.code, ErrorCode::InvalidConfig, "{error}");
    assert_eq!(
        error.key_path.as_deref(),
        Some("launch.credentials.first.binaries"),
        "{error}"
    );
}

/// The derived layer precedes the project file: a project `ukai.toml` may
/// restate the install root as read-only (a narrowing within what the
/// layers before it grant). Kills: the program layer applied after the
/// project layer.
#[test]
fn review_the_project_file_comes_after_the_derived_grant() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let bin = fixture.bin.to_str().unwrap();
    write(
        &fixture.repo.join("ukai.toml"),
        format!(
            "[jail]\nschema = \"ukai.jail.policy/1\"\n[jail.filesystem]\nread_only = [\"{bin}\"]\n"
        )
        .as_bytes(),
        0o644,
    );
    fixture
        .plan(&fixture.repo, &["--launch", "agent", "--from-path"])
        .unwrap_or_else(|error| panic!("{error}"));
}

/// `doctor` readiness with `credentials_one_of`: one present source is
/// enough, none is not. Kills: every listed id required, and none required.
#[test]
fn review_doctor_readiness_counts_one_of_once() {
    let ready = |fixture: &Fixture| {
        let ctx = fixture.context(Box::new(platform()), &fixture.repo);
        let cli::Command::Doctor(args) =
            Cli::try_parse_from(["ukai-jail", "doctor", "--launch", "agent", "--from-path"])
                .unwrap()
                .command
        else {
            unreachable!()
        };
        supervisor::doctor(&ctx, &args)
            .unwrap_or_else(|error| panic!("{error}"))
            .ready
    };
    let fixture = Fixture::new();
    assert!(!ready(&fixture), "no source present");
    fixture.credential("second", b"second-value");
    assert!(ready(&fixture), "the alternative is enough");
}

/// The covered skip is J12's alone: an operator's own `--ro` beneath a
/// grant an earlier layer made (here `config.toml`) is still listed. Kills:
/// the skip applied to every operator-grant layer.
#[test]
fn review_operator_grants_are_listed_even_when_covered() {
    let fixture = Fixture::new();
    let tools = fixture.root.join("tools");
    write(
        &fixture.config.join("config.toml"),
        format!("[jail.filesystem]\nread_only = [\"{}\"]\n", tools.display()).as_bytes(),
        0o600,
    );
    let plan = fixture
        .plan(
            &fixture.repo,
            &["--profile", "tool", "--ro", fixture.bin.to_str().unwrap()],
        )
        .unwrap_or_else(|error| panic!("{error}"));
    let listed: Vec<String> = plan
        .resolved
        .grants
        .iter()
        .filter(|grant| grant.kind == "read_only" && grant.by == "operator")
        .map(|grant| grant.value.to_display())
        .collect();
    for path in [&tools, &fixture.bin] {
        assert!(
            listed.contains(&path.to_str().unwrap().to_owned()),
            "{} in {listed:?}",
            path.display()
        );
    }
}

/// A word that is not UTF-8 is never a launch name. Kills: such a word read
/// as some other name.
#[test]
fn review_a_non_utf8_alias_word_exits_2_naming_both_readings() {
    let fixture = Fixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_ukai-jail"));
    let output = command
        .env_clear()
        .env("HOME", &fixture.home)
        .env("UKAI_DATA_DIR", &fixture.data)
        .env("UKAI_CONFIG_DIR", &fixture.config)
        .current_dir(&fixture.repo)
        .arg(std::ffi::OsStr::from_bytes(b"cl\xffaude"))
        .arg("-p")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        text(&output.stderr).contains("no verb or launch profile"),
        "{}",
        text(&output.stderr)
    );
}

/// `learn` refuses `--from-path`. Kills: that refusal removed.
#[test]
fn review_learn_refuses_from_path() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let output = fixture.binary(
        &fixture.repo,
        &["learn", "--launch", "agent", "--from-path", "--", "x"],
        None,
    );
    assert_ne!(output.status.code(), Some(0));
    assert!(
        text(&output.stderr).contains("learn does not take --from-path"),
        "{}",
        text(&output.stderr)
    );
}

/// K44 on a terminal: `credential set` turns echo off, so a pasted value
/// never comes back on the terminal. Runs the binary under `script(1)`; the
/// value is sent a second after start, once echo is off. Kills: echo left
/// on.
#[test]
fn review_credential_set_never_echoes_on_a_terminal() {
    let script = Path::new("/usr/bin/script");
    if !script.exists() {
        return;
    }
    let fixture = Fixture::new();
    let value = "sk-ant-oat01-pty-fixture-value";
    let binary = env!("CARGO_BIN_EXE_ukai-jail");
    let inner = if cfg!(target_os = "macos") {
        format!("/usr/bin/script -q /dev/null '{binary}' credential set first")
    } else {
        format!("/usr/bin/script -q -e -c \"'{binary}' credential set first\" /dev/null")
    };
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "(sleep 1; printf '{value}\\n\\004'; sleep 1) | {inner}"
        ))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &fixture.home)
        .env("UKAI_DATA_DIR", &fixture.data)
        .env("UKAI_CONFIG_DIR", &fixture.config)
        .current_dir(&fixture.repo)
        .output()
        .unwrap();
    let terminal = text(&output.stdout);
    assert_eq!(
        std::fs::read(fixture.config.join("credentials/first")).ok(),
        Some(value.as_bytes().to_vec()),
        "{terminal:?}"
    );
    assert!(!terminal.contains(value), "echoed: {terminal:?}");
}

// ---------------------------------------------------------------------------
// Review fixes (j12-adversarial-review.md)
// ---------------------------------------------------------------------------

/// Review F1: a link the lookup follows in a directory others can write
/// (without the sticky bit) refuses, as does an `env` word found through a
/// symlink inside the workspace.
#[test]
fn review_fix_links_the_lookup_follows_must_lie_where_only_the_operator_writes() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let shared = fixture.root.join("shared");
    mkdir(&shared, 0o777);
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::os::unix::fs::symlink(fixture.bin.join("agent"), shared.join("agent")).unwrap();
    let ctx = context_with_path(
        &fixture,
        Box::new(platform()),
        &fixture.repo,
        join_path(&[&shared]),
    );
    let error = from_path_plan(&ctx).err().expect("a refusal");
    assert_eq!(error.code, ErrorCode::PolicyWidening, "{error}");
    assert_eq!(error.key_path.as_deref(), Some("--from-path"));
    assert!(
        error.message.contains(&shared.display().to_string()),
        "{error}"
    );

    // `#!/usr/bin/env j12node`, `j12node` found through a symlink the
    // repository ships.
    let runtime = fixture.root.join("tools/rt");
    mkdir(&runtime, 0o755);
    write(&runtime.join("j12node"), &static_elf(), 0o755);
    write(
        &fixture.bin.join("agent"),
        b"#!/usr/bin/env j12node\n",
        0o755,
    );
    let planted = fixture.repo.join("node_modules/.bin");
    mkdir(&planted, 0o755);
    std::os::unix::fs::symlink(runtime.join("j12node"), planted.join("j12node")).unwrap();
    let ctx = context_with_path(
        &fixture,
        Box::new(platform()),
        &fixture.repo,
        join_path(&[&fixture.bin, &planted]),
    );
    let error = from_path_plan(&ctx).err().expect("a refusal");
    assert_eq!(error.key_path.as_deref(), Some("--from-path"), "{error}");
    assert!(error.message.contains("node_modules"), "{error}");
    // The same interpreter on PATH by its own name resolves.
    let ctx = context_with_path(
        &fixture,
        Box::new(platform()),
        &fixture.repo,
        join_path(&[&fixture.bin, &runtime]),
    );
    let plan = from_path_plan(&ctx).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        plan.program
            .as_ref()
            .unwrap()
            .interpreter
            .as_ref()
            .unwrap()
            .path,
        runtime.join("j12node")
    );
}

/// Review F2: `#!/usr/bin/env X` with X in the runtime roots is a `#!`
/// script with a system interpreter: no expansion, and `explain` says so.
#[test]
fn review_fix_env_with_a_system_interpreter_is_a_plain_script() {
    let fixture = Fixture::new();
    fixture.profile("plain", "name = \"plain\"\njail = \"tool\"\n");
    write(&fixture.bin.join("plain"), b"#!/usr/bin/env sh\n", 0o755);
    let report = fixture.explain(&fixture.repo, &["--launch", "plain", "--from-path"]);
    let (program, _) = report.program.as_ref().unwrap();
    assert_eq!(program.format.as_str(), "script");
    assert!(program.interpreter.is_none());
    assert_eq!(
        program.argv_prefix(),
        [fixture.bin.join("plain").as_os_str().as_bytes()]
    );
}

/// Review F3: a second link made after resolution, and a write in place,
/// both fail the recheck.
#[test]
fn review_fix_the_recheck_sees_a_new_link_and_a_write_in_place() {
    use std::io::Write as _;
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let plan = fixture
        .plan(&fixture.repo, &["--launch", "agent", "--from-path"])
        .unwrap();
    let program = plan.program.as_ref().unwrap();
    program.recheck().unwrap();
    std::fs::hard_link(fixture.bin.join("agent"), fixture.root.join("second")).unwrap();
    assert!(program.recheck().is_err(), "a new name is a change");
    std::fs::remove_file(fixture.root.join("second")).unwrap();
    let plan = fixture
        .plan(&fixture.repo, &["--launch", "agent", "--from-path"])
        .unwrap();
    let program = plan.program.as_ref().unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(fixture.bin.join("agent"))
        .unwrap();
    file.write_all(b"appended").unwrap();
    drop(file);
    let error = program.recheck().unwrap_err();
    assert!(error.message.contains("identity mismatch"), "{error}");
}

/// Review F6: a project `deny_read` over the install root is disclosed as
/// such in `explain` (text and JSON) and in the pre-exec line.
#[test]
fn review_fix_a_denied_install_root_is_disclosed_as_denied() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let bin = fixture.bin.to_str().unwrap();
    write(
        &fixture.repo.join("ukai.toml"),
        format!(
            "[jail]\nschema = \"ukai.jail.policy/1\"\n[jail.filesystem]\ndeny_read = [\"{bin}\"]\n"
        )
        .as_bytes(),
        0o644,
    );
    let output = fixture.binary(
        &fixture.repo,
        &["explain", "--launch", "agent", "--from-path"],
        None,
    );
    let stdout = text(&output.stdout);
    assert!(
        stdout.lines().any(|line| line
            == format!(
                "program read_only {bin} denied_by={bin} (the program cannot be read inside)"
            )),
        "{stdout}"
    );
    let output = fixture.binary(
        &fixture.repo,
        &["explain", "--launch", "agent", "--from-path", "--json"],
        None,
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["program"]["roots"][0]["denied_by"], bin, "{json:#}");
    let report = fixture.explain(&fixture.repo, &["--launch", "agent", "--from-path"]);
    let (program, _) = report.program.as_ref().unwrap();
    let line = supervisor::from_path::program_line(program, &report.resolved);
    assert!(line.contains("denied by deny_read"), "{line}");
}

/// Review F7: from inside a nested repository, `explain` and `doctor` say
/// the outer repository's `ukai.toml` does not apply.
#[test]
fn review_fix_a_nested_repository_is_disclosed() {
    let fixture = Fixture::new();
    fixture.credential("first", b"token-value");
    let nested = fixture.repo.join("vendor/lib");
    mkdir(&nested.join(".git"), 0o755);
    write(&nested.join(".git/HEAD"), b"ref: refs/heads/main\n", 0o644);
    for verb in ["explain", "doctor"] {
        let output = fixture.binary(&nested, &[verb, "--launch", "agent", "--from-path"], None);
        let stdout = text(&output.stdout);
        assert!(
            stdout.contains(&format!("workspace nested_in {}", fixture.repo.display())),
            "{verb}: {stdout}\n{}",
            text(&output.stderr)
        );
    }
    // Not from the outer repository itself, and not with --workspace.
    let output = fixture.binary(
        &fixture.repo,
        &["explain", "--launch", "agent", "--from-path"],
        None,
    );
    assert!(!text(&output.stdout).contains("nested_in"));
}

/// Review I3: a signal while `credential set` waits on a terminal puts echo
/// back before the process ends.
#[test]
fn review_fix_an_interrupted_credential_set_restores_echo() {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    let fixture = Fixture::new();
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: both pointers are to live integers the call fills; the name,
    // termios and window size arguments may be null.
    let rc = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: openpty returned two fresh descriptors this test now owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let echo = |fd: i32| {
        // SAFETY: termios is plain data tcgetattr fills.
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: a live descriptor and buffer.
        assert_eq!(unsafe { libc::tcgetattr(fd, &raw mut termios) }, 0);
        termios.c_lflag & libc::ECHO != 0
    };
    assert!(echo(slave.as_raw_fd()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_ukai-jail"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &fixture.home)
        .env("UKAI_DATA_DIR", &fixture.data)
        .env("UKAI_CONFIG_DIR", &fixture.config)
        .current_dir(&fixture.repo)
        .args(["credential", "set", "first"])
        .stdin(std::process::Stdio::from(slave.try_clone().unwrap()))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    common::eventually("echo off", std::time::Duration::from_secs(20), || {
        !echo(slave.as_raw_fd())
    });
    // SAFETY: signalling the child this test started.
    unsafe { libc::kill(i32::try_from(child.id()).unwrap(), libc::SIGINT) };
    let status = child.wait().unwrap();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGINT),
        "the signal still ends the process"
    );
    assert!(echo(slave.as_raw_fd()), "echo was left off");
    assert!(!fixture.config.join("credentials/first").exists());
    drop(master);
}
