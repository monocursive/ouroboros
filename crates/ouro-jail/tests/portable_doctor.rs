//! J5-D: build provenance in `version --json` and `doctor --json`, and the
//! doctor report as a versioned record (jail-v1 §3.2, §14.1, §16).
//!
//! §16 freezes "observer object/build provenance and tested host manifest"
//! with the milestone report; §3.2 says `doctor --json` "produces the host
//! manifest" and supersedes `host-manifest.sh`; §14.1 asks it for "binary
//! hashes/versions, operator identity category". These tests drive the real
//! binary on every platform and check each fact against an independent
//! reading, never against the value the binary itself computed.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root exists")
}

struct Harness {
    temp: tempfile::TempDir,
    data: PathBuf,
    config: PathBuf,
    work: PathBuf,
}

impl Harness {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = common::private_tempdir();
        let make = |name: &str, mode: u32| {
            let path = temp.path().join(name);
            std::fs::create_dir(&path).expect("a directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("permissions");
            path
        };
        Harness {
            data: make("data", 0o700),
            config: make("config", 0o700),
            work: make("work", 0o755),
            temp,
        }
    }

    /// The built binary with a cleared environment and the host's usual
    /// `PATH`, so bubblewrap resolves where the operator's would.
    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ouro-jail"))
            .env_clear()
            .env("PATH", host_path())
            .env("HOME", self.temp.path())
            .env("OURO_DATA_DIR", &self.data)
            .env("OURO_CONFIG_DIR", &self.config)
            .current_dir(&self.work)
            .args(arguments)
            .output()
            .expect("the binary runs")
    }

    fn json(&self, arguments: &[&str]) -> serde_json::Value {
        let output = self.run(arguments);
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{arguments:?} prints one JSON document ({error}); exit {:?}, stderr {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }
}

/// The `PATH` the binary runs with: the system directories, which is where a
/// stock host keeps bubblewrap.
fn host_path() -> &'static str {
    "/usr/local/bin:/usr/bin:/bin"
}

/// The toolchain channel the repository pins, read from the file itself.
fn pinned_channel() -> String {
    let text = std::fs::read_to_string(repo_root().join("rust-toolchain.toml"))
        .expect("rust-toolchain.toml");
    let value: toml::Value = toml::from_str(&text).expect("TOML");
    value["toolchain"]["channel"]
        .as_str()
        .expect("a pinned channel")
        .to_owned()
}

/// What `build` must say, from facts this test reads independently.
fn assert_build(build: &serde_json::Value) {
    let object = build.as_object().expect("`build` is an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["dirty", "profile", "revision", "rustc", "target"]);

    // The compiler: `rustc -V` of the pinned toolchain.
    let rustc = build["rustc"].as_str().expect("rustc is a string");
    assert!(
        rustc.starts_with(&format!("rustc {} (", pinned_channel())),
        "{rustc}"
    );

    // The target triple names this machine's architecture and OS.
    let target = build["target"].as_str().expect("target is a string");
    let arch = std::env::consts::ARCH;
    let os = if cfg!(target_os = "macos") {
        "-apple-darwin"
    } else {
        "-unknown-linux-"
    };
    assert!(
        target.starts_with(arch) && target.contains(os),
        "{target} for {arch}{os}"
    );

    // The profile the binary was built with, which is this test's own.
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    assert_eq!(build["profile"], profile);

    // The revision and dirty flag come from the environment of the cargo
    // invocation that built both this test and the binary: null when that
    // environment did not set them, never a guess.
    match option_env!("OURO_BUILD_REVISION") {
        Some(revision)
            if revision.len() == 40 && revision.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            assert_eq!(build["revision"], revision.to_ascii_lowercase());
        }
        _ => assert_eq!(build["revision"], serde_json::Value::Null),
    }
    match option_env!("OURO_BUILD_DIRTY") {
        Some("true" | "1") => assert_eq!(build["dirty"], true),
        Some("false" | "0") => assert_eq!(build["dirty"], false),
        _ => assert_eq!(build["dirty"], serde_json::Value::Null),
    }
}

#[test]
fn version_json_carries_the_build_provenance() {
    let harness = Harness::new();
    let version = harness.json(&["version", "--json"]);
    assert_build(&version["build"]);

    // The text rendering says the same, for an operator reading it.
    let text = harness.run(&["version"]);
    let text = String::from_utf8_lossy(&text.stdout);
    let build = &version["build"];
    let word = |value: &serde_json::Value| match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Bool(flag) => flag.to_string(),
        _ => "unknown".to_owned(),
    };
    for expected in [
        format!("build {}", word(&build["rustc"])),
        format!(
            "build target {} {}",
            word(&build["target"]),
            word(&build["profile"])
        ),
        format!(
            "build revision {} dirty {}",
            word(&build["revision"]),
            word(&build["dirty"])
        ),
    ] {
        assert!(
            text.lines().any(|line| line == expected),
            "{expected}\n{text}"
        );
    }
}

#[test]
fn doctor_json_is_a_versioned_record_with_the_same_build() {
    let harness = Harness::new();
    let version = harness.json(&["version", "--json"]);
    let doctor = harness.json(&["doctor", "--json"]);
    assert_eq!(doctor["schema"], "ouro.jail.doctor/1");
    assert_eq!(version["schemas"]["doctor"], "ouro.jail.doctor/1");
    assert_build(&doctor["build"]);
    assert_eq!(doctor["build"], version["build"]);
}
