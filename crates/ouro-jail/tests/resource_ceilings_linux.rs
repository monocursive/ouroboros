//! Kernel-backed admission and refusal for explicitly bounded storage.
#![cfg(target_os = "linux")]
use ouro_fixture::harness::{self, Jail};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
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
