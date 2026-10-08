//! Kernel-backed admission and refusal for explicitly bounded storage.
#![cfg(target_os = "linux")]
use ouro_fixture::harness::{self, Jail};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt as _;
mod common;

#[test]
fn storage_admission_counts_workspace_and_scratch_aliases_once() {
    if !common::live() {
        return;
    }
    for observe in ["on", "off"] {
        let jail = Jail::new().unwrap();
        let ws = jail.root().join("workspace");
        let scratch = jail.root().join("scratch");
        std::fs::create_dir(&ws).unwrap();
        std::fs::create_dir(&scratch).unwrap();
        let path = CString::new(ws.as_os_str().as_bytes()).unwrap();
        let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: terminated path and writable statfs output.
        assert_eq!(
            unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) },
            0
        );
        // SAFETY: successful statfs initialized the structure.
        let stats = unsafe { stats.assume_init() };
        if stats.f_type != libc::TMPFS_MAGIC || stats.f_blocks == 0 || stats.f_files == 0 {
            harness::skip_or_fail("storage admission needs a bounded tmpfs test directory");
            return;
        }
        let bytes = stats.f_blocks * u64::try_from(stats.f_bsize).unwrap();
        let run = jail.arg("run").arg("--profile").arg("tool")
            .arg("--workspace").arg(&ws).arg("--scratch").arg(&scratch)
            .args(["--observe", observe, "--limit", &format!("storage={bytes}"),
                "--limit", &format!("inodes={}", stats.f_files)])
            .args(["--limit", "mem=64MiB", "--limit", "swap=0", "--limit", "cpu=50"])
            .receipt().target(["/usr/bin/python3", "-c",
                "import errno,time\ntime.sleep(.2)\nopen('small','w').write('bounded')\ntry: open('/dev/shm/escape','w')\nexcept OSError as e: assert e.errno==errno.EROFS\nelse: raise AssertionError('writable shm')"])
            .run().unwrap();
        assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
        let receipt = common::checked_receipt(run.receipt_phase("settled").unwrap());
        assert_eq!(receipt["applied"]["limits"].as_array().unwrap().len(), 7);
        assert_eq!(receipt["lifetime"]["tree_empty"], true);
        let storage = &receipt["lifetime"]["native"]["details"]["storage_ceiling"];
        assert_eq!(storage["filesystems"], 1);
        assert_eq!(storage["capacity_bytes"], bytes);
        assert_eq!(storage["capacity_inodes"], stats.f_files);
        for key in ["storage", "inodes"] {
            let limit = receipt["applied"]["limits"]
                .as_array()
                .unwrap()
                .iter()
                .find(|l| l["key"] == key)
                .unwrap();
            assert_eq!(limit["applied"], true);
            assert_eq!(limit["required"], true);
            assert!(limit["hit"].is_null(), "unsampled refusals remain unknown");
        }
        // Audit 2026-10-08 M2 (§11.4): missing hit evidence — storage and
        // inode ceilings sample saturation positively only — degrades the
        // `limits` class and nulls its count, and the degraded class names
        // its gap.
        let limits_class = &receipt["coverage"]["limits"];
        assert_eq!(limits_class["status"], "degraded");
        assert!(limits_class["observed_count"].is_null());
        let gaps = limits_class["gaps"].as_array().unwrap();
        assert!(gaps.iter().any(|gap| gap["reason"] == "storage_hit_evidence_positive_only"));
    }
}

#[test]
fn unachievable_storage_ceilings_refuse_before_target_exec() {
    if !common::live() {
        return;
    }
    for profile in ["tool", "none"] {
        for ceiling in ["storage=1", "inodes=1"] {
            let jail = Jail::new().unwrap();
            let ws = jail.root().join("workspace");
            std::fs::create_dir(&ws).unwrap();
            let run = jail
                .arg("run")
                .args(["--profile", profile, "--limit", ceiling])
                .arg("--workspace")
                .arg(&ws)
                .receipt()
                .target(["/usr/bin/touch", "SHOULD_NOT_EXIST"])
                .run()
                .unwrap();
            assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
            assert!(!ws.join("SHOULD_NOT_EXIST").exists());
            let receipt = common::checked_receipt(
                run.receipt_phase("refused")
                    .or_else(|| run.receipt_phase("settled"))
                    .expect("refusal must produce a final receipt"),
            );
            assert_eq!(receipt["outcome"]["kind"], "refused");
        }
    }
}

#[test]
fn none_profile_reports_its_explicit_swap_ceiling() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let ws = jail.root().join("workspace");
    std::fs::create_dir(&ws).unwrap();
    let run = jail
        .arg("run")
        .args(["--profile", "none", "--limit", "swap=0"])
        .arg("--workspace")
        .arg(&ws)
        .receipt()
        .target(["/usr/bin/true"])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let receipt = common::checked_receipt(run.receipt_phase("settled").unwrap());
    let swap = receipt["applied"]["limits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["key"] == "swap")
        .unwrap();
    assert_eq!(swap["applied"], true);
    assert_eq!(swap["mechanism"], "memory.swap.max");
}

/// The storage claim §6.4 rests on (mutation-B03 guard): with a storage
/// ceiling the tool baseline refuses the hard-link syscalls, and the same
/// link without a ceiling succeeds — so the denial is the ceiling's
/// baseline, not the filesystem's. Both spellings are exercised, and the
/// receipt's storage evidence states the denial.
#[test]
fn hard_links_are_denied_under_a_storage_ceiling_and_allowed_without_it() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let ws = jail.root().join("workspace");
    let scratch = jail.root().join("scratch");
    std::fs::create_dir(&ws).unwrap();
    std::fs::create_dir(&scratch).unwrap();
    // The admission test's bounded-tmpfs gate: a ceiling needs a
    // filesystem whose capacity the kernel states.
    let path = CString::new(ws.as_os_str().as_bytes()).unwrap();
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: terminated path and writable statfs output.
    assert_eq!(unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) }, 0);
    // SAFETY: successful statfs initialized the structure.
    let stats = unsafe { stats.assume_init() };
    if stats.f_type != libc::TMPFS_MAGIC || stats.f_blocks == 0 || stats.f_files == 0 {
        harness::skip_or_fail("the hard-link denial needs a bounded tmpfs test directory");
        return;
    }
    // The fixture runs from the workspace itself: the sandbox cannot see
    // the build tree the harness resolves `target_fixture` to.
    let fixture = ws.join("ouro-fixture");
    std::fs::copy(harness::fixture_path(), &fixture).unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(ws.join("from"), b"hard link source").unwrap();
    for via in ["link", "linkat"] {
        // No ceiling: the link is an ordinary call.
        let unlimited = Jail::new()
            .unwrap()
            .env("OURO_DATA_DIR", jail.data_dir())
            .env("OURO_CONFIG_DIR", jail.config_dir())
            .arg("run")
            .arg("--profile")
            .arg("tool")
            .arg("--workspace")
            .arg(&ws)
            .arg("--scratch")
            .arg(&scratch)
            .target([
                fixture.as_os_str(),
                std::ffi::OsStr::new("link"),
                std::ffi::OsStr::new("from"),
                std::ffi::OsStr::new("to"),
                std::ffi::OsStr::new("--via"),
                std::ffi::OsStr::new(via),
                std::ffi::OsStr::new("--expect"),
                std::ffi::OsStr::new("ok"),
            ])
            .run()
            .unwrap();
        assert_eq!(unlimited.code(), Some(0), "{via}: {}", unlimited.stderr_text());
        std::fs::remove_file(ws.join("to")).unwrap();

        // The same link under a ceiling: EPERM, and the receipt says the
        // baseline is what denies it.
        let bytes = stats.f_blocks * u64::try_from(stats.f_bsize).unwrap();
        let limited = Jail::new()
            .unwrap()
            .env("OURO_DATA_DIR", jail.data_dir())
            .env("OURO_CONFIG_DIR", jail.config_dir())
            .arg("run")
            .arg("--profile")
            .arg("tool")
            .arg("--workspace")
            .arg(&ws)
            .arg("--scratch")
            .arg(&scratch)
            .args(["--observe", "on", "--limit", &format!("storage={bytes}")])
            .receipt()
            .target([
                fixture.as_os_str(),
                std::ffi::OsStr::new("link"),
                std::ffi::OsStr::new("from"),
                std::ffi::OsStr::new("to"),
                std::ffi::OsStr::new("--via"),
                std::ffi::OsStr::new(via),
                std::ffi::OsStr::new("--expect"),
                std::ffi::OsStr::new("EPERM"),
            ])
            .run()
            .unwrap();
        assert_eq!(limited.code(), Some(0), "{via}: {}", limited.stderr_text());
        let receipt = common::checked_receipt(limited.receipt_phase("settled").unwrap());
        let storage = &receipt["lifetime"]["native"]["details"]["storage_ceiling"];
        assert_eq!(storage["hard_links"], "denied", "{via}: {storage}");
        std::fs::remove_file(ws.join("to")).ok();
    }
}

/// Mutation-M03 guard: a requested ceiling over a writable filesystem the
/// runtime cannot bound — an unbounded tmpfs, `f_blocks == 0` — refuses
/// before exec instead of admitting an unbounded volume. The condition
/// needs that exact filesystem layout, so a host whose workspace is
/// bounded cannot produce it and the check says so rather than pass
/// vacuously.
#[test]
fn storage_limits_refuse_a_writable_filesystem_with_no_hard_ceiling() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let ws = jail.root().join("workspace");
    std::fs::create_dir(&ws).unwrap();
    let path = CString::new(ws.as_os_str().as_bytes()).unwrap();
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: terminated path and writable statfs output.
    assert_eq!(unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) }, 0);
    // SAFETY: successful statfs initialized the structure.
    let stats = unsafe { stats.assume_init() };
    if stats.f_type != libc::TMPFS_MAGIC || stats.f_blocks != 0 {
        eprintln!(
            "skipped: the workspace filesystem has a hard ceiling, so the \
             no-hard-ceiling refusal is not producible here"
        );
        return;
    }
    let run = jail
        .arg("run")
        .arg("--profile")
        .arg("tool")
        .arg("--workspace")
        .arg(&ws)
        .args(["--limit", "storage=1"])
        .receipt()
        .target(["/usr/bin/touch", "SHOULD_NOT_EXIST"])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    assert!(!ws.join("SHOULD_NOT_EXIST").exists());
    assert!(
        run.stderr_text().contains("no hard ceiling"),
        "{}",
        run.stderr_text()
    );
    let receipt = common::checked_receipt(
        run.receipt_phase("refused")
            .or_else(|| run.receipt_phase("settled"))
            .expect("refusal must produce a final receipt"),
    );
    assert_eq!(receipt["outcome"]["kind"], "refused");
}
