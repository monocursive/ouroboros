use super::*;
use std::fs::{self, Permissions};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::process::Stdio;
use std::time::Instant;

struct Fixture {
    root: PathBuf,
    installed: PathBuf,
    curl: Curl,
}
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("ouro-update-{}", install::random_suffix().unwrap()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
        let installed = root.join("ouro custom-é");
        executable(&installed, &version_script("0.1.0"));
        fs::write(
            root.join("latest"),
            format!("{REPOSITORY}/releases/tag/v0.2.0"),
        )
        .unwrap();
        let program = root.join("curl");
        let fixture = Self {
            root,
            installed,
            curl: Curl {
                program,
                timeout: Duration::from_secs(5),
                allow_http: false,
                max_redirects: 5,
            },
        };
        fixture.payload(version_script("0.2.0").as_bytes(), "0.2.0");
        fixture.curl_script("");
        fixture
    }
    fn payload(&self, bytes: &[u8], version: &str) {
        fs::write(self.root.join("payload"), bytes).unwrap();
        let digest = hex(ring::digest::digest(&SHA256, bytes).as_ref());
        fs::write(
            self.root.join("sums"),
            format!("{digest}  ouro-{version}-aarch64-apple-darwin\n"),
        )
        .unwrap();
    }
    fn curl_script(&self, before_payload: &str) {
        executable(
            &self.curl.program,
            &format!(
                r#"#!/bin/sh
set -eu
cd {}
printf '%s\n' "$@" >> calls
for arg in "$@"; do url=$arg; done
case "$url" in
  */releases/latest) cat latest ;;
  */SHA256SUMS) cat sums ;;
  *)
    {}
    cat payload ;;
esac
"#,
                quote(&self.root),
                before_payload
            ),
        );
    }
    fn request(&self, check: bool) -> Request {
        Request {
            current: Version::new(0, 1, 0),
            local: false,
            destination: (!check).then(|| self.installed.clone()),
            target: (!check).then(|| "aarch64-apple-darwin".to_string()),
        }
    }
    fn run(&self, check: bool) -> Result<(Outcome, String, String)> {
        self.run_request(&self.request(check))
    }
    fn run_request(&self, request: &Request) -> Result<(Outcome, String, String)> {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let outcome = perform(
            request,
            &self.curl,
            &AtomicBool::new(false),
            &mut out,
            &mut err,
        )?;
        Ok((
            outcome,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        ))
    }
    fn assert_original(&self) {
        assert_eq!(
            fs::read_to_string(&self.installed).unwrap(),
            version_script("0.1.0")
        );
        assert_eq!(fs::metadata(&self.installed).unwrap().mode() & 0o777, 0o755);
        self.assert_no_staging();
    }
    fn assert_no_staging(&self) {
        assert!(!fs::read_dir(&self.root).unwrap().any(|p| p
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }
    fn calls(&self) -> String {
        fs::read_to_string(self.root.join("calls")).unwrap_or_default()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn quote(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
}
fn version_script(version: &str) -> String {
    format!("#!/bin/sh\nprintf 'ouro {version}\\n'\n")
}
fn executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o755)).unwrap();
}
fn error<T: std::fmt::Debug>(result: Result<T>) -> String {
    format!("{:#}", result.unwrap_err())
}

#[test]
fn shared_release_contract() {
    let contract: serde_json::Value =
        serde_json::from_str(include_str!("../../../test/support/release-contract.json")).unwrap();
    for tag in contract["stable_tags"].as_array().unwrap() {
        assert!(latest_version(&format!(
            "{REPOSITORY}/releases/tag/{}",
            tag.as_str().unwrap()
        ))
        .is_ok());
    }
    for tag in contract["invalid_latest_tags"].as_array().unwrap() {
        assert!(latest_version(&format!(
            "{REPOSITORY}/releases/tag/{}",
            tag.as_str().unwrap()
        ))
        .is_err());
    }
    for case in contract["targets"].as_array().unwrap() {
        assert_eq!(
            select_target(
                case["os"].as_str().unwrap(),
                case["arch"].as_str().unwrap(),
                case["version"].as_str().unwrap(),
                case["rosetta"].as_bool().unwrap()
            )
            .unwrap(),
            case["target"].as_str().unwrap()
        );
    }
    for url in [
        "http://github.com/monocursive/ouroboros/releases/tag/v1.0.0",
        "https://evil.example/releases/tag/v1.0.0",
        "https://github.com/other/repo/releases/tag/v1.0.0",
    ] {
        assert!(latest_version(url).is_err());
    }
    assert!(latest_version(&format!("{REPOSITORY}/releases/tag/v1.2.3\n")).is_err());
    for (os, arch, version) in [
        ("macos", "x86_64", "14.9"),
        ("linux", "armv7", "glibc 2.39"),
        ("linux", "aarch64", "musl"),
        ("linux", "aarch64", "glibc 2.38"),
        ("windows", "x86_64", "11"),
    ] {
        assert!(select_target(os, arch, version, false).is_err());
    }
}

#[test]
fn check_is_read_only_and_noops_use_semantic_ordering() {
    for (current, expected) in [
        ("0.1.0", Outcome::Available),
        ("0.2.0", Outcome::Current),
        ("0.10.0", Outcome::Ahead),
        ("0.2.0-rc.1", Outcome::Available),
        ("0.3.0-rc.1", Outcome::Ahead),
    ] {
        let f = Fixture::new();
        let mut request = f.request(true);
        request.current = Version::parse(current).unwrap();
        fs::remove_file(&f.installed).unwrap(); // A check needs no executable path at all.
        let before = fs::read_dir(&f.root).unwrap().count();
        let (outcome, _, _) = f.run_request(&request).unwrap();
        assert_eq!(outcome, expected);
        assert_eq!(
            outcome.exit_code(),
            if outcome == Outcome::Available { 10 } else { 0 }
        );
        assert_eq!(fs::read_dir(&f.root).unwrap().count(), before + 1); // Only the test curl call log.
        assert!(!f.calls().contains("SHA256SUMS"));
        assert!(!f.calls().contains("/download/"));
        assert_eq!(f.calls().matches("/releases/latest").count(), 1);
    }
}

#[test]
fn replacement_preserves_alias_and_uses_pinned_verified_release() {
    let f = Fixture::new();
    let alias = f.root.join("alias");
    symlink(&f.installed, &alias).unwrap();
    let mut request = f.request(false);
    request.destination = Some(alias.clone());
    let (outcome, out, _) = f.run_request(&request).unwrap();
    assert_eq!(outcome, Outcome::Installed);
    assert!(out.contains("finish active work"));
    assert!(fs::symlink_metadata(alias).unwrap().is_symlink());
    assert_eq!(
        fs::read_to_string(&f.installed).unwrap(),
        version_script("0.2.0")
    );
    f.assert_no_staging();
    let calls = f.calls();
    assert_eq!(calls.matches("--disable\n").count(), 3);
    assert_eq!(
        calls
            .matches("--proto\n=https\n--proto-redir\n=https\n")
            .count(),
        3
    );
    assert_eq!(calls.matches("/releases/latest").count(), 1);
    assert_eq!(calls.matches("/download/v0.2.0/").count(), 2);
    assert!(!calls.contains("install.sh"));
}

#[test]
fn current_install_does_not_download_or_create_a_lock() {
    let f = Fixture::new();
    fs::write(
        f.root.join("latest"),
        format!("{REPOSITORY}/releases/tag/v0.1.0"),
    )
    .unwrap();
    assert_eq!(f.run(false).unwrap().0, Outcome::Current);
    f.assert_original();
    assert!(!fs::read_dir(&f.root).unwrap().any(|p| p
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".lock")));
}

#[test]
fn bad_manifest_and_candidate_fail_without_changing_installation() {
    for kind in [
        "corrupt",
        "duplicate",
        "missing",
        "invalid",
        "wrong-version",
        "unexecutable",
        "binary-missing",
    ] {
        let f = Fixture::new();
        match kind {
            "corrupt" => fs::write(f.root.join("payload"), "damaged").unwrap(),
            "duplicate" => {
                let sums = fs::read_to_string(f.root.join("sums")).unwrap();
                fs::write(f.root.join("sums"), sums.repeat(2)).unwrap();
            }
            "missing" => fs::write(f.root.join("sums"), "").unwrap(),
            "invalid" => fs::write(f.root.join("sums"), "invalid digest\n").unwrap(),
            "wrong-version" => f.payload(version_script("8.0.0").as_bytes(), "0.2.0"),
            "unexecutable" => f.payload(b"not an executable", "0.2.0"),
            "binary-missing" => f.curl_script("exit 22"),
            _ => unreachable!(),
        }
        assert!(f.run(false).is_err(), "{kind}");
        f.assert_original();
    }
}

#[test]
fn transient_download_retries_reset_file_and_digest() {
    let f = Fixture::new();
    f.curl_script("if [ ! -f retried ]; then touch retried; printf 'partial bytes'; exit 18; fi");
    assert_eq!(f.run(false).unwrap().0, Outcome::Installed);
    assert_eq!(
        fs::read_to_string(&f.installed).unwrap(),
        version_script("0.2.0")
    );
    assert_eq!(f.calls().matches("/ouro-0.2.0-").count(), 2);
}

#[test]
fn concurrent_and_changed_installations_are_preserved() {
    let f = Fixture::new();
    let destination = Destination::inspect(&f.installed, &AtomicBool::new(false)).unwrap();
    let held = destination.lock().unwrap();
    assert!(error(f.run(false)).contains("already in progress"));
    f.assert_original();
    drop(held);
    executable(&f.root.join("competitor"), &version_script("9.0.0"));
    f.curl_script(
        "cp competitor replacement; chmod 755 replacement; mv replacement 'ouro custom-é'",
    );
    assert!(error(f.run(false)).contains("changed during update"));
    assert_eq!(
        fs::read_to_string(&f.installed).unwrap(),
        version_script("9.0.0")
    );
    f.assert_no_staging();
}

#[test]
fn lock_symlink_and_unsafe_destinations_are_refused() {
    let f = Fixture::new();
    let destination = Destination::inspect(&f.installed, &AtomicBool::new(false)).unwrap();
    drop(destination.lock().unwrap());
    let lock = fs::read_dir(&f.root)
        .unwrap()
        .map(|p| p.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "lock"))
        .unwrap();
    fs::remove_file(&lock).unwrap();
    symlink(&f.installed, &lock).unwrap();
    assert!(destination.lock().is_err());
    f.assert_original();
    fs::set_permissions(&f.installed, Permissions::from_mode(0o777)).unwrap();
    assert!(Destination::inspect(&f.installed, &AtomicBool::new(false)).is_err());
    fs::set_permissions(&f.installed, Permissions::from_mode(0o755)).unwrap();
    fs::hard_link(&f.installed, f.root.join("hardlink")).unwrap();
    assert!(Destination::inspect(&f.installed, &AtomicBool::new(false)).is_err());
    fs::remove_file(f.root.join("hardlink")).unwrap();
    fs::set_permissions(&f.root, Permissions::from_mode(0o777)).unwrap();
    assert!(Destination::inspect(&f.installed, &AtomicBool::new(false)).is_err());
}

#[test]
fn stale_process_and_renamed_directory_refuse_replacement() {
    let f = Fixture::new();
    let destination = Destination::inspect(&f.installed, &AtomicBool::new(false)).unwrap();
    let moved = f.root.with_extension("moved");
    fs::rename(&f.root, &moved).unwrap();
    fs::create_dir(&f.root).unwrap();
    assert!(destination.lock().is_err());
    fs::remove_dir(&f.root).unwrap();
    fs::rename(moved, &f.root).unwrap();
    executable(&f.installed, &version_script("9.0.0"));
    assert!(error(f.run(false)).contains("installed file differs"));
    assert!(f.calls().is_empty());
}

#[test]
fn failed_rename_and_postcommit_sync_are_distinct() {
    let f = Fixture::new();
    let cancel = AtomicBool::new(false);
    let destination = Destination::inspect(&f.installed, &cancel).unwrap();
    let mut stage = destination.stage().unwrap();
    stage
        .file
        .as_mut()
        .unwrap()
        .write_all(version_script("0.2.0").as_bytes())
        .unwrap();
    destination.seal(&mut stage).unwrap();
    fs::remove_file(&stage.path).unwrap();
    assert!(destination.commit(&stage, &cancel).is_err());
    f.assert_original();
    let mut stage = destination.stage().unwrap();
    stage
        .file
        .as_mut()
        .unwrap()
        .write_all(version_script("0.2.0").as_bytes())
        .unwrap();
    destination.seal(&mut stage).unwrap();
    let warning = destination
        .commit_with_sync(&stage, &cancel, || {
            Err(std::io::Error::other("sync failed"))
        })
        .unwrap();
    assert!(warning.unwrap().contains("new executable is installed"));
    assert_eq!(
        fs::read_to_string(&f.installed).unwrap(),
        version_script("0.2.0")
    );
}

#[test]
fn output_limits_write_failure_deadline_and_cancellation_reap_children() {
    let f = Fixture::new();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf 123456789"]);
    assert!(error(capture(
        command,
        4,
        Duration::from_secs(1),
        &AtomicBool::new(false)
    ))
    .contains("exceeds"));
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "sleep 10"]);
    let start = Instant::now();
    assert!(error(capture(
        command,
        4,
        Duration::from_millis(100),
        &AtomicBool::new(false)
    ))
    .contains("deadline"));
    assert!(start.elapsed() < Duration::from_secs(2));
    let cancel = AtomicBool::new(true);
    assert!(perform(
        &f.request(false),
        &f.curl,
        &cancel,
        &mut Vec::new(),
        &mut Vec::new()
    )
    .is_err());
    f.assert_original();

    struct BrokenWriter;
    impl Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(error(f.curl.get(
        "https://example.invalid/payload",
        false,
        &mut BrokenWriter,
        BINARY_CAP,
        &AtomicBool::new(false)
    ))
    .contains("disk full"));
}

#[test]
fn cancellation_during_download_cleans_staging() {
    let f = Fixture::new();
    f.curl_script("touch downloading; sleep 10");
    let cancel = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            perform(
                &f.request(false),
                &f.curl,
                &cancel,
                &mut Vec::new(),
                &mut Vec::new(),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !f.root.join("downloading").exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        cancel.store(true, Ordering::Relaxed);
        assert!(error(worker.join().unwrap()).contains("cancelled"));
    });
    f.assert_original();
}

#[test]
fn lock_child() {
    let Some(path) = std::env::var_os("OURO_UPDATE_LOCK_TEST_CHILD") else {
        return;
    };
    let destination = Destination::inspect(Path::new(&path), &AtomicBool::new(false)).unwrap();
    let _held = destination.lock().unwrap();
    fs::write(Path::new(&path).with_extension("ready"), "ready").unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn process_death_releases_lock_without_unlinking_coordination_inode() {
    let f = Fixture::new();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "update::tests::lock_child", "--nocapture"])
        .env("OURO_UPDATE_LOCK_TEST_CHILD", &f.installed)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f.installed.with_extension("ready").exists() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("lock child did not start");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let destination = Destination::inspect(&f.installed, &AtomicBool::new(false)).unwrap();
    assert!(destination.lock().is_err());
    child.kill().unwrap();
    child.wait().unwrap();
    drop(destination.lock().unwrap());
}

/// Invoked on each native release runner with the actual packaged binary. Only
/// this test harness injects a fixture transport; the shipped CLI has no bypass.
#[test]
fn packaged_candidate_replaces_standalone_installation() {
    let Some(binary) = std::env::var_os("OURO_UPDATE_SMOKE_BINARY") else {
        return;
    };
    let f = Fixture::new();
    let version = env!("CARGO_PKG_VERSION");
    f.payload(&fs::read(binary).unwrap(), version);
    fs::write(
        f.root.join("latest"),
        format!("{REPOSITORY}/releases/tag/v{version}"),
    )
    .unwrap();
    executable(&f.installed, &version_script("0.0.0"));
    let mut request = f.request(false);
    request.current = Version::new(0, 0, 0);
    if Version::parse(version).unwrap().pre.is_empty() {
        assert_eq!(f.run_request(&request).unwrap().0, Outcome::Installed);
    } else {
        // Prereleases are published for explicit installer selection, never as
        // latest stable. Qualify their native replacement without lying to discovery.
        let cancel = AtomicBool::new(false);
        let destination = Destination::inspect(&f.installed, &cancel).unwrap();
        let _lock = destination.lock().unwrap();
        let mut stage = destination.stage().unwrap();
        stage
            .reset()
            .unwrap()
            .write_all(&fs::read(f.root.join("payload")).unwrap())
            .unwrap();
        destination.seal(&mut stage).unwrap();
        verify_version(&stage.path, &Version::parse(version).unwrap(), &cancel).unwrap();
        assert!(destination.commit(&stage, &cancel).unwrap().is_none());
    }
    verify_version(
        &f.installed,
        &Version::parse(version).unwrap(),
        &AtomicBool::new(false),
    )
    .unwrap();
    // The external release smoke also boots this artifact and checks its embed.
}
