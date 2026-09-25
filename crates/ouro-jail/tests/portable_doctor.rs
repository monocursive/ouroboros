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

/// The build inputs' digest, computed here independently of the product
/// (review F8: provenance is measured, not asserted). The rule, which
/// build.rs documents too: SHA-256 over every file under
/// `crates/ouro-jail/src` plus `crates/ouro-jail/build.rs`,
/// `crates/ouro-jail/Cargo.toml`, `Cargo.toml`, `Cargo.lock` and
/// `rust-toolchain.toml`, sorted by their `/`-separated path relative to the
/// repository root, each as `path NUL u64-LE(length) bytes`.
fn build_inputs_digest() -> String {
    use sha2::Digest as _;
    let root = repo_root();
    let mut files: Vec<String> = [
        "crates/ouro-jail/build.rs",
        "crates/ouro-jail/Cargo.toml",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
    ]
    .map(str::to_owned)
    .to_vec();
    let mut stack = vec![root.join("crates/ouro-jail/src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(
                    path.strip_prefix(&root)
                        .expect("inside the repository")
                        .to_str()
                        .expect("UTF-8")
                        .to_owned(),
                );
            }
        }
    }
    files.sort();
    let mut hasher = sha2::Sha256::new();
    for file in &files {
        let bytes = std::fs::read(root.join(file)).expect("readable");
        hasher.update(file.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// The opt-level this test (and so the binary, built by the same cargo
/// invocation and profile) was compiled at, from the workspace manifest.
fn expected_opt_level() -> String {
    let workspace = std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("Cargo.toml");
    let workspace: toml::Value = toml::from_str(&workspace).expect("TOML");
    let profile = if cfg!(debug_assertions) {
        "dev"
    } else {
        "release"
    };
    match workspace
        .get("profile")
        .and_then(|profiles| profiles.get(profile))
        .and_then(|profile| profile.get("opt-level"))
    {
        Some(toml::Value::Integer(level)) => level.to_string(),
        Some(toml::Value::String(level)) => level.clone(),
        _ if profile == "dev" => "0".to_owned(),
        _ => "3".to_owned(),
    }
}

/// What `build` must say, from facts this test reads independently.
fn assert_build(build: &serde_json::Value) {
    let object = build.as_object().expect("`build` is an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "debug_assertions",
            "dirty",
            "inputs",
            "opt_level",
            "revision",
            "rustc",
            "target"
        ]
    );

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

    // What the compiler was actually asked to do, not a profile's name.
    assert_eq!(build["debug_assertions"], cfg!(debug_assertions));
    assert_eq!(build["opt_level"], expected_opt_level());

    // The inputs the binary was built from, measured.
    assert_eq!(build["inputs"], build_inputs_digest(), "{build:#}");

    // The revision and dirty flag come from the environment of the cargo
    // invocation that built both this test and the binary: null when that
    // environment did not set them, never a guess.
    match option_env!("OURO_BUILD_REVISION").filter(|value| !value.is_empty()) {
        Some(revision) => assert_eq!(build["revision"], revision.to_ascii_lowercase()),
        None => assert_eq!(build["revision"], serde_json::Value::Null),
    }
    match option_env!("OURO_BUILD_DIRTY").filter(|value| !value.is_empty()) {
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
            "build target {} opt-level {} debug-assertions {}",
            word(&build["target"]),
            word(&build["opt_level"]),
            word(&build["debug_assertions"])
        ),
        format!(
            "build revision {} dirty {}",
            word(&build["revision"]),
            word(&build["dirty"])
        ),
        format!("build inputs {}", word(&build["inputs"])),
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
            "apparmor_enabled",
            "apparmor_userns_restriction",
            "cgroup",
            "cpus_online",
            "distribution",
            "kernel_release",
            "kernel_version",
            "linger",
            "memory",
            "operator_identity",
            "privileged_groups",
            "sysctls",
            "systemd_version",
            "virtualization",
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
        match std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
            Ok(text) if text.trim() == "0" => "off",
            Ok(_) => "on",
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => "absent",
            Err(_) => "unknown",
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
    // Every non-empty override under local/ (review F5).
    match std::fs::read_dir("/etc/apparmor.d/local") {
        Err(_) => assert_eq!(apparmor["local_files"], serde_json::Value::Null),
        Ok(entries) => {
            let mut expected: Vec<String> = entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    std::fs::metadata(entry.path()).is_ok_and(|m| m.is_file() && m.len() > 0)
                })
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect();
            expected.sort();
            assert_eq!(apparmor["local_files"], serde_json::json!(expected));
        }
    }
    // The top-level files no dpkg package lists (operator-installed).
    let lists: Option<String> = std::fs::read_dir("/var/lib/dpkg/info").ok().map(|entries| {
        entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".list"))
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .collect()
    });
    match (std::fs::read_dir("/etc/apparmor.d"), lists) {
        (Ok(entries), Some(lists)) => {
            let owned: std::collections::BTreeSet<&str> = lists.lines().collect();
            let mut expected: Vec<String> = entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| std::fs::metadata(entry.path()).is_ok_and(|m| m.is_file()))
                .map(|entry| entry.path().to_string_lossy().into_owned())
                .filter(|path| !owned.contains(path.as_str()))
                .collect();
            expected.sort();
            assert_eq!(apparmor["unpackaged_files"], serde_json::json!(expected));
        }
        _ => assert_eq!(apparmor["unpackaged_files"], serde_json::Value::Null),
    }
    let expected_enabled = match std::fs::read_to_string("/sys/module/apparmor/parameters/enabled")
    {
        Ok(text) if text.trim() == "Y" => serde_json::json!(true),
        Ok(text) if text.trim() == "N" => serde_json::json!(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::json!(false),
        _ => serde_json::Value::Null,
    };
    assert_eq!(host["apparmor_enabled"], expected_enabled);

    // Virtualization, CPUs, memory and systemd, read with the ordinary tools.
    let first_line = |program: &str, args: &[&str]| -> serde_json::Value {
        Command::new(program)
            .args(args)
            .output()
            .ok()
            .and_then(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .map(|line| line.trim().to_owned())
            })
            .filter(|line| !line.is_empty())
            .map_or(serde_json::Value::Null, serde_json::Value::String)
    };
    assert_eq!(
        host["virtualization"],
        first_line("systemd-detect-virt", &[])
    );
    assert_eq!(
        host["systemd_version"],
        first_line("systemctl", &["--version"])
    );
    let cpus = first_line("getconf", &["_NPROCESSORS_ONLN"]);
    assert_eq!(
        host["cpus_online"].as_u64().map(|count| count.to_string()),
        cpus.as_str().map(str::to_owned)
    );
    let meminfo = std::fs::read_to_string("/proc/meminfo").expect("meminfo");
    let kib = |key: &str| -> serde_json::Value {
        meminfo
            .lines()
            .find(|line| line.starts_with(&format!("{key}:")))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u64>().ok())
            .map_or(serde_json::Value::Null, serde_json::Value::from)
    };
    assert_eq!(host["memory"]["mem_total_kib"], kib("MemTotal"));
    assert_eq!(host["memory"]["swap_total_kib"], kib("SwapTotal"));

    // The groups that confer root-equivalent authority, as facts.
    let groups = Command::new("id").arg("-Gn").output().expect("id runs");
    let mut privileged: Vec<String> = String::from_utf8_lossy(&groups.stdout)
        .split_whitespace()
        .filter(|name| {
            [
                "root",
                "sudo",
                "admin",
                "wheel",
                "docker",
                "lxd",
                "incus-admin",
                "libvirt",
                "disk",
            ]
            .contains(name)
        })
        .map(str::to_owned)
        .collect();
    privileged.sort();
    privileged.dedup();
    assert_eq!(host["privileged_groups"], serde_json::json!(privileged));

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
        let subtree: Vec<String> = proc_text(root.join("cgroup.subtree_control").to_str().unwrap())
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        assert_eq!(cgroup["subtree_control"], serde_json::json!(subtree));
    } else {
        assert_eq!(cgroup["delegated_root"], serde_json::Value::Null);
        assert_eq!(cgroup["controllers"], serde_json::Value::Null);
        assert_eq!(cgroup["subtree_control"], serde_json::Value::Null);
    }
    let root_controllers: Vec<String> = proc_text("/sys/fs/cgroup/cgroup.controllers")
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        cgroup["root_controllers"],
        serde_json::json!(root_controllers)
    );

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
    let initial_namespace = std::fs::read_to_string("/proc/self/uid_map")
        .expect("uid_map")
        .split_whitespace()
        .collect::<Vec<_>>()
        == ["0", "0", "4294967295"];
    let expected_identity = if !initial_namespace {
        "user_namespace"
    } else if uids[1] == "0" {
        "root"
    } else if uids[..3].iter().any(|uid| *uid != uids[0])
        || gids[..3].iter().any(|gid| *gid != gids[0])
    {
        "set_id"
    } else if capable {
        "capable"
    } else if !privileged.is_empty() {
        "privileged_group"
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
    // Every case below breaks one rule of a record the schema accepts; a
    // base that is already invalid would make each case pass vacuously.
    for (name, base) in [("doctor-linux.json", &linux), ("doctor-macos.json", &macos)] {
        assert_eq!(schema_errors(base), Vec::<String>::new(), "{name}");
    }
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
    let cases: &[(&str, &serde_json::Value, Change)] = &[
        ("another identifier", &linux, |r| {
            r["schema"] = "ouro.jail.doctor/2".into()
        }),
        ("no build", &linux, |r| {
            r.as_object_mut().unwrap().remove("build");
        }),
        ("an abbreviated revision", &linux, |r| {
            r["build"]["revision"] = "48a229cea".into();
        }),
        ("an all-zero revision", &linux, |r| {
            r["build"]["revision"] = "0000000000000000000000000000000000000000".into();
        }),
        ("an opt-level that is none", &linux, |r| {
            r["build"]["opt_level"] = "fast".into()
        }),
        ("an inputs digest that is not one", &linux, |r| {
            r["build"]["inputs"] = "sha256:abc".into()
        }),
        ("a profile name instead of measured settings", &linux, |r| {
            r["build"]["profile"] = "release".into()
        }),
        // The reviewer's crafted records (rev-D/schema-cases), rebuilt from
        // the real examples.
        (
            "l1: Linux ready with every capability unsupported",
            &linux,
            |r| {
                for row in r["capabilities"].as_array_mut().unwrap() {
                    row["status"] = "unsupported".into();
                }
            },
        ),
        (
            "l1b: Linux ready with one requirement unavailable",
            &linux,
            |r| {
                let row = r["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|row| row["name"] == "syscall_filter")
                    .unwrap();
                row["status"] = "unavailable".into();
                row["reason_code"] = "filter_not_enforced".into();
            },
        ),
        ("l2: dirty false without a revision", &linux, |r| {
            r["build"]["dirty"] = false.into();
            r["build"]["revision"] = serde_json::Value::Null;
        }),
        ("l3: arch aarch64 with an x86_64 target", &linux, |r| {
            r["platform"]["arch"] = "aarch64".into()
        }),
        ("l4: ready without a backend", &linux, |r| {
            r["binaries"]["bwrap"] = serde_json::Value::Null
        }),
        (
            "l5: restriction absent while the sysctl reads 1",
            &linux,
            |r| r["host"]["apparmor_userns_restriction"]["state"] = "absent".into(),
        ),
        (
            "l5b: restriction on while the sysctl reads 0",
            &linux,
            |r| r["host"]["sysctls"]["kernel.apparmor_restrict_unprivileged_userns"] = "0".into(),
        ),
        (
            "l5c: restriction off while the sysctl is unreadable",
            &linux,
            |r| {
                r["host"]["sysctls"]["kernel.apparmor_restrict_unprivileged_userns"] =
                    serde_json::Value::Null;
                r["host"]["apparmor_userns_restriction"]["state"] = "off".into();
            },
        ),
        ("l6: a missing cgroup fact", &linux, |r| {
            r["host"].as_object_mut().unwrap().remove("cgroup");
        }),
        ("controllers without a delegated root", &linux, |r| {
            r["host"]["cgroup"]["delegated_root"] = serde_json::Value::Null
        }),
        ("unprivileged while in the sudo group", &linux, |r| {
            r["host"]["privileged_groups"] = serde_json::json!(["sudo"])
        }),
        ("privileged_group with no privileged group", &linux, |r| {
            r["host"]["operator_identity"] = "privileged_group".into()
        }),
        ("a group that is not a privileged one", &linux, |r| {
            r["host"]["privileged_groups"] = serde_json::json!(["users"])
        }),
        ("a probe row named as a requirement", &linux, |r| {
            let rows = r["capabilities"].as_array_mut().unwrap();
            let row = rows.iter_mut().find(|row| row["scope"] == "host").unwrap();
            row["name"] = "syscall_filter".into();
        }),
        ("m1: macOS carries a Linux probe row", &macos, |r| {
            r["capabilities"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "name": "cgroup_delegated_leaf", "status": "available", "scope": "tree",
                    "mechanism": "cgroup-v2-delegated", "reason_code": "ok",
                    "measured_at": "2026-09-24T00:00:00Z", "evidence_ref": "probe"
                }));
        }),
        ("m2: macOS with the old requirement name", &macos, |r| {
            r["requirements"]
                .as_array_mut()
                .unwrap()
                .push("execution_cgroup".into());
        }),
        (
            "m2b: a macOS row named as the old requirement",
            &macos,
            |r| r["capabilities"][0]["name"] = "execution_cgroup".into(),
        ),
        ("m3: macOS ready", &macos, |r| r["ready"] = true.into()),
        (
            "m3b: macOS ready with nothing required or measured",
            &macos,
            |r| {
                r["ready"] = true.into();
                r["requirements"] = serde_json::json!([]);
                r["capabilities"] = serde_json::json!([]);
            },
        ),
        ("m4: macOS with a Linux build target", &macos, |r| {
            r["build"]["target"] = "x86_64-unknown-linux-gnu".into()
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
        ("l7: an unknown identity category", &linux, |r| {
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
        let mut record = (*base).clone();
        change(&mut record);
        assert!(
            !schema_errors(&record).is_empty(),
            "the schema accepts {label}"
        );
    }
}
