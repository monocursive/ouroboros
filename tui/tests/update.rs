//! Drive the real CLI before runtime setup, with a local curl fixture. No test
//! changes the trusted repository or enables update eligibility at runtime.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct CliFixture(PathBuf);
impl CliFixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ouro-update-cli-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("broken-home"), "not a directory").unwrap();
        fs::write(
            path.join("curl"),
            "#!/bin/sh\nprintf 'https://github.com/monocursive/ouroboros/releases/tag/v99.0.0'\n",
        )
        .unwrap();
        fs::set_permissions(path.join("curl"), fs::Permissions::from_mode(0o755)).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ouro"))
            .args(args)
            .env_clear()
            .env("PATH", &self.0)
            .env("HOME", self.0.join("broken-home"))
            .env("OUROBOROS_DATA_DIR", "relative-and-invalid")
            .env("XDG_CONFIG_HOME", self.0.join("broken-home"))
            .env("OUROBOROS_SELF_UPDATE", "1") // Cannot enable a local build at runtime.
            .current_dir(&self.0)
            .output()
            .unwrap()
    }
}
impl Drop for CliFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn check_succeeds_with_unusable_runtime_paths_without_writing_files() {
    let fixture = CliFixture::new();
    for args in [
        vec!["update", "--check"],
        vec!["--dev", "update", "--check"],
    ] {
        let output = fixture.run(&args);
        assert_eq!(
            output.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("local build"));
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 2);
    }
}

#[test]
fn local_build_and_dev_mutation_refuse_before_network_or_runtime_discovery() {
    let fixture = CliFixture::new();
    fs::remove_file(fixture.0.join("curl")).unwrap();
    for args in [vec!["update"], vec!["--dev", "update"]] {
        let output = fixture.run(&args);
        assert_eq!(output.status.code(), Some(1));
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("local build") || error.contains("development executable"),
            "{error}"
        );
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
    }
}

#[test]
fn update_help_and_invalid_flags_are_honest() {
    let fixture = CliFixture::new();
    let output = fixture.run(&["update", "--help"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--check"));
    for args in [
        vec!["--continue", "update"],
        vec!["update", "--version", "v1.2.3"],
        vec!["update", "--force"],
        vec!["update", "--repository", "https://example.com"],
    ] {
        assert_eq!(fixture.run(&args).status.code(), Some(2));
    }
}

#[test]
fn failed_check_is_not_reported_as_current() {
    let fixture = CliFixture::new();
    fs::write(fixture.0.join("curl"), "#!/bin/sh\nexit 22\n").unwrap();
    let output = fixture.run(&["update", "--check"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("latest stable release"));
}
