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
    // A group-writable directory in the root refuses at the pin.
    std::fs::set_permissions(&fixture.bin, std::fs::Permissions::from_mode(0o775)).unwrap();
    check("group-writable", &base, &[], &fixture.bin);
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
    write(&runtime.join("node"), &static_elf(), 0o755);
    write(&fixture.bin.join("agent"), b"#!/usr/bin/env node\n", 0o755);
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
        runtime.join("node").as_os_str().as_bytes().to_vec(),
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
        &[runtime.join("node").to_str().unwrap().to_owned()]
    );
    for (script, fragment) in [
        (&b"#!/usr/bin/env -S node --flag\n"[..], "/usr/bin/env"),
        (b"#!/usr/bin/env node --flag\n", "/usr/bin/env"),
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
    write(&fixture.bin.join("agent"), b"#!/usr/bin/env node\n", 0o755);
    write(&runtime.join("node"), b"#!/bin/sh\n", 0o755);
    let error = refused(
        supervisor::resolve_plan(
            &context(platform()),
            &Fixture::policy("explain", &["--launch", "agent", "--from-path"]),
        ),
        "nested",
    );
    assert!(error.message.contains("nested script"), "{}", error.message);
    assert!(error.message.contains("node"), "{}", error.message);
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
    write(&runtime.join("node"), &static_elf(), 0o755);
    write(&fixture.bin.join("node"), &static_elf(), 0o755);
    write(&fixture.bin.join("agent"), b"#!/usr/bin/env node\n", 0o755);
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
