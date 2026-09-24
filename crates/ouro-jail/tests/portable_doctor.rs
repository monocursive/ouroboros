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

// ---------------------------------------------------------------------------
// The host manifest and the binaries (§3.2, §14.1)
// ---------------------------------------------------------------------------

/// One `doctor --json` for the tests below: every probe is a real sandbox,
/// fork or ptrace session, so the report is taken once per test binary.
fn doctor_once() -> &'static serde_json::Value {
    static ONCE: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let harness = Harness::new();
        harness.json(&["doctor", "--json"])
    })
}

fn sha256_of(path: &Path) -> String {
    use sha2::Digest as _;
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    sha2::Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn doctor_json_records_the_jail_binary_it_ran_as() {
    let doctor = doctor_once();
    let binary = &doctor["binaries"]["ouro-jail"];
    let built = Path::new(env!("CARGO_BIN_EXE_ouro-jail"));
    assert_eq!(
        Path::new(binary["path"].as_str().expect("a path"))
            .canonicalize()
            .expect("the recorded path exists"),
        built.canonicalize().expect("the built binary exists"),
        "{binary:#}"
    );
    assert_eq!(binary["sha256"], sha256_of(built), "{binary:#}");
}

/// The bubblewrap the product resolves: the first `bwrap` on the `PATH` it
/// was given (`platform.rs::find_bwrap`), found here independently.
#[cfg(target_os = "linux")]
fn bwrap_on_path() -> Option<PathBuf> {
    host_path()
        .split(':')
        .map(|dir| Path::new(dir).join("bwrap"))
        .find(|candidate| candidate.is_file())
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_json_records_the_bubblewrap_the_product_resolves() {
    let doctor = doctor_once();
    let recorded = &doctor["binaries"]["bwrap"];
    match bwrap_on_path() {
        None => assert_eq!(*recorded, serde_json::Value::Null, "{recorded:#}"),
        Some(path) => {
            assert_eq!(
                recorded["path"],
                path.to_str().expect("UTF-8"),
                "{recorded:#}"
            );
            assert_eq!(recorded["sha256"], sha256_of(&path), "{recorded:#}");
            let version = Command::new(&path)
                .arg("--version")
                .output()
                .expect("bwrap --version runs");
            assert_eq!(
                recorded["version"],
                String::from_utf8_lossy(&version.stdout).trim(),
                "{recorded:#}"
            );
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn doctor_json_on_macos_records_no_linux_host_or_backend() {
    let doctor = doctor_once();
    let binaries = doctor["binaries"].as_object().expect("binaries");
    assert_eq!(
        binaries.keys().collect::<Vec<_>>(),
        ["ouro-jail"],
        "macOS has no backend binary to record"
    );
    assert!(doctor.get("host").is_none(), "{doctor:#}");
}

#[cfg(target_os = "linux")]
fn proc_text(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_owned())
}

/// `/etc/os-release`'s `PRETTY_NAME` (os-release(5): `/usr/lib/os-release`
/// when the first is absent), unquoted.
#[cfg(target_os = "linux")]
fn pretty_name() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .ok()?;
    text.lines().find_map(|line| {
        let value = line.strip_prefix("PRETTY_NAME=")?;
        Some(value.trim_matches('"').trim_matches('\'').to_owned())
    })
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_json_carries_the_host_manifest_section_3_2_names() {
    use std::os::unix::fs::MetadataExt as _;
    let doctor = doctor_once();
    let host = doctor["host"].as_object().expect("a host object on Linux");
    let mut keys: Vec<&str> = host.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "apparmor_userns_restriction",
            "cgroup",
            "distribution",
            "kernel_release",
            "kernel_version",
            "linger",
            "operator_identity",
            "sysctls",
        ]
    );

    // Kernel release and build, from procfs rather than uname(2).
    assert_eq!(
        host["kernel_release"].as_str(),
        proc_text("/proc/sys/kernel/osrelease").as_deref()
    );
    assert_eq!(
        host["kernel_version"].as_str(),
        proc_text("/proc/sys/kernel/version").as_deref()
    );
    assert_eq!(host["distribution"].as_str(), pretty_name().as_deref());

    // The four sysctls §3.2 names, plus the two the manual manifest also
    // recorded (user namespaces and io_uring bear on S03 and S04).
    let sysctls = host["sysctls"].as_object().expect("sysctls");
    let mut names: Vec<&str> = sysctls.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "kernel.apparmor_restrict_unprivileged_userns",
            "kernel.io_uring_disabled",
            "kernel.perf_event_paranoid",
            "kernel.unprivileged_bpf_disabled",
            "kernel.yama.ptrace_scope",
            "user.max_user_namespaces",
        ]
    );
    for (name, value) in sysctls {
        let path = format!("/proc/sys/{}", name.replace('.', "/"));
        assert_eq!(value.as_str(), proc_text(&path).as_deref(), "{name}");
    }

    // AppArmor's user-namespace restriction, as that sysctl states it.
    let apparmor = &host["apparmor_userns_restriction"];
    let expected_state =
        match proc_text("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() {
            Some("0") => "off",
            Some(_) => "on",
            None => "absent",
        };
    assert_eq!(apparmor["state"], expected_state, "{apparmor:#}");
    match std::fs::read_dir("/etc/apparmor.d") {
        Err(_) => assert_eq!(apparmor["profile_files"], serde_json::Value::Null),
        Ok(entries) => {
            let mut expected: Vec<String> = entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| {
                    let lower = name.to_ascii_lowercase();
                    ["userns", "bwrap", "ouro"]
                        .iter()
                        .any(|word| lower.contains(word))
                })
                .collect();
            expected.sort();
            assert_eq!(apparmor["profile_files"], serde_json::json!(expected));
        }
    }

    // cgroup v2 delegation as this operator's session sees it.
    let uid = std::fs::metadata("/proc/self").expect("procfs").uid();
    let root = PathBuf::from(format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"
    ));
    let cgroup = &host["cgroup"];
    if std::fs::metadata(&root).is_ok_and(|meta| meta.is_dir() && meta.uid() == uid) {
        assert_eq!(cgroup["delegated_root"], root.to_str().expect("UTF-8"));
        let controllers: Vec<String> = proc_text(root.join("cgroup.controllers").to_str().unwrap())
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        assert_eq!(cgroup["controllers"], serde_json::json!(controllers));
    } else {
        assert_eq!(cgroup["delegated_root"], serde_json::Value::Null);
        assert_eq!(cgroup["controllers"], serde_json::Value::Null);
    }

    // Lingering, as logind records it: one file per user name.
    let user = Command::new("id").arg("-un").output().expect("id runs");
    let user = String::from_utf8_lossy(&user.stdout).trim().to_owned();
    let linger_dir = Path::new("/var/lib/systemd/linger");
    let expected_linger = if linger_dir.is_dir() {
        serde_json::json!(linger_dir.join(&user).is_file())
    } else {
        serde_json::Value::Null
    };
    assert_eq!(host["linger"], expected_linger);

    // The operator identity category (§14.1), from this process's own
    // credentials, which the doctor it started inherited.
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    let field = |name: &str| -> Vec<String> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}:")))
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    };
    let (uids, gids) = (field("Uid"), field("Gid"));
    let capable = ["CapPrm", "CapEff", "CapAmb"].iter().any(|name| {
        field(name)
            .first()
            .is_some_and(|mask| !mask.trim_start_matches('0').is_empty())
    });
    let expected_identity = if uids[1] == "0" {
        "root"
    } else if uids[0] != uids[1] || gids[0] != gids[1] {
        "set_id"
    } else if capable {
        "capable"
    } else {
        "unprivileged"
    };
    assert_eq!(host["operator_identity"], expected_identity);
}

// ---------------------------------------------------------------------------
// The schema and its examples
// ---------------------------------------------------------------------------

fn doctor_schema() -> &'static jsonschema::Validator {
    &common::validators()["jail-doctor"]
}

fn schema_errors(record: &serde_json::Value) -> Vec<String> {
    doctor_schema()
        .iter_errors(record)
        .map(|error| format!("{error} at {}", error.instance_path()))
        .collect()
}

#[test]
fn the_doctor_schema_declares_the_announced_identifier() {
    let text =
        std::fs::read_to_string(repo_root().join("docs/specs/jail-v1/jail-doctor.schema.json"))
            .expect("jail-doctor.schema.json");
    let schema: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(
        schema["properties"]["schema"]["const"],
        "ouro.jail.doctor/1"
    );
}

#[test]
fn this_hosts_doctor_report_is_valid_against_the_schema() {
    let doctor = doctor_once();
    assert_eq!(schema_errors(doctor), Vec::<String>::new(), "{doctor:#}");
}

fn examples() -> Vec<(String, serde_json::Value)> {
    let dir = repo_root().join("docs/specs/jail-v1/examples");
    let mut out: Vec<(String, serde_json::Value)> = std::fs::read_dir(&dir)
        .expect("examples")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("doctor-") && name.ends_with(".json"))
        })
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("an example");
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                serde_json::from_str(&text).expect("JSON"),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn the_checked_in_doctor_examples_are_valid() {
    let examples = examples();
    let names: Vec<&str> = examples.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["doctor-linux.json", "doctor-macos.json"]);
    for (name, example) in &examples {
        assert_eq!(schema_errors(example), Vec::<String>::new(), "{name}");
    }
}

/// Each rule the schema states, broken once on the Linux example.
#[test]
fn the_doctor_schema_rejects_what_it_must() {
    let (_, linux) = examples()
        .into_iter()
        .find(|(name, _)| name == "doctor-linux.json")
        .expect("the Linux example");
    let (_, macos) = examples()
        .into_iter()
        .find(|(name, _)| name == "doctor-macos.json")
        .expect("the macOS example");
    // The macOS cases carry the Linux example's own, valid `host` and
    // `supervisor_scope`, so the only rule that can reject them is the
    // platform partition.
    let mut macos_with_host = macos.clone();
    macos_with_host["host"] = linux["host"].clone();
    let mut macos_with_scope = macos.clone();
    macos_with_scope["supervisor_scope"] = linux["supervisor_scope"].clone();
    let mut macos_with_backend = macos.clone();
    macos_with_backend["binaries"]["bwrap"] = linux["binaries"]["bwrap"].clone();
    for (label, record) in [
        ("macOS with a host", &macos_with_host),
        ("macOS with a supervisor scope", &macos_with_scope),
        ("macOS with a backend record", &macos_with_backend),
    ] {
        assert!(
            !schema_errors(record).is_empty(),
            "the schema accepts {label}"
        );
    }
    // And each Linux-only part, removed from the Linux example, is missed.
    let mut linux_without_scope = linux.clone();
    linux_without_scope
        .as_object_mut()
        .unwrap()
        .remove("supervisor_scope");
    assert!(
        !schema_errors(&linux_without_scope).is_empty(),
        "the schema accepts Linux without a supervisor scope"
    );

    type Change = fn(&mut serde_json::Value);
    let cases: [(&str, &serde_json::Value, Change); 12] = [
        ("another identifier", &linux, |r| {
            r["schema"] = "ouro.jail.doctor/2".into()
        }),
        ("no build", &linux, |r| {
            r.as_object_mut().unwrap().remove("build");
        }),
        ("an abbreviated revision", &linux, |r| {
            r["build"]["revision"] = "48a229cea".into();
        }),
        ("a profile that is neither", &linux, |r| {
            r["build"]["profile"] = "bench".into()
        }),
        ("Linux without a host", &linux, |r| {
            r.as_object_mut().unwrap().remove("host");
        }),
        ("Linux without a backend record", &linux, |r| {
            r["binaries"].as_object_mut().unwrap().remove("bwrap");
        }),
        ("a short hash", &linux, |r| {
            r["binaries"]["ouro-jail"]["sha256"] = "abc".into();
        }),
        ("an uppercase hash", &linux, |r| {
            let upper = r["binaries"]["ouro-jail"]["sha256"]
                .as_str()
                .unwrap()
                .to_ascii_uppercase();
            r["binaries"]["ouro-jail"]["sha256"] = upper.into();
        }),
        ("an unknown identity category", &linux, |r| {
            r["host"]["operator_identity"] = "admin".into();
        }),
        ("a sysctl that is not a string or null", &linux, |r| {
            r["host"]["sysctls"]["kernel.yama.ptrace_scope"] = 1.into();
        }),
        ("macOS with a host", &macos, |r| {
            r["host"] = serde_json::json!({});
        }),
        ("macOS with a backend record", &macos, |r| {
            r["binaries"]["bwrap"] = serde_json::Value::Null;
        }),
    ];
    for (label, base, change) in cases {
        let mut record = base.clone();
        change(&mut record);
        assert!(
            !schema_errors(&record).is_empty(),
            "the schema accepts {label}"
        );
    }
}
