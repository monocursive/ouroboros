//! J2 authority: actual controller effects, helper death, and build grants.
#![cfg(target_os = "linux")]

use ouro_fixture::harness::{self, Jail, Run};
use ouro_jail::platform::linux::{identity, watch};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod common;

fn case() -> (Jail, PathBuf) {
    let jail = Jail::new().unwrap();
    let ws = jail.root().join("workspace");
    std::fs::create_dir(&ws).unwrap();
    (
        jail.arg("run")
            .arg("--workspace")
            .arg(&ws)
            .trace()
            .control(),
        ws,
    )
}

fn live() -> bool {
    if !common::live() {
        return false;
    }
    let result = ouro_jail::platform::linux::probe::run_one(
        "cgroup_memory",
        &harness::jail_path(),
        Path::new("bwrap"),
    );
    if result.status != ouro_jail::platform::linux::probe::ProbeStatus::Available {
        harness::skip_or_fail("J2 requires a delegated user scope with memory, pids and cpu");
        return false;
    }
    true
}

fn settled(run: &Run) -> Value {
    run.receipt_phase("settled")
        .unwrap_or_else(|| panic!("{}; {:?}", run.stderr_text(), run.receipts()))
}

fn limit<'a>(receipt: &'a Value, key: &str) -> &'a Value {
    receipt["applied"]["limits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["key"] == key)
        .unwrap()
}

#[test]
fn l03_explicit_same_value_limits_apply_with_observation_on_and_off() {
    if !live() {
        return;
    }
    for observe in ["on", "off"] {
        let (jail, _) = case();
        let mut spawned = jail
            .args([
                "--observe",
                observe,
                "--limit",
                "pids=256",
                "--limit",
                "mem=64MiB",
                "--limit",
                "cpu=50",
            ])
            .gate()
            .receipt()
            .target(["/usr/bin/python3", "-c", "import time; time.sleep(.2)"])
            .spawn()
            .unwrap();
        let prepared = spawned.owner().await_prepared().unwrap();
        let receipt = spawned.receipt_value().unwrap();
        let native = &receipt["lifetime"]["native"]["details"];
        let leaf = Path::new(native["execution_cgroup"]["path"].as_str().unwrap()).to_owned();
        let members = std::fs::read_to_string(leaf.join("cgroup.procs")).unwrap();
        let actual: std::collections::BTreeSet<i64> =
            members.lines().map(|pid| pid.parse().unwrap()).collect();
        let mut expected =
            std::collections::BTreeSet::from([native["launcher_pid"].as_i64().unwrap()]);
        for helper in native["execution_cgroup"]["charged_helpers"]
            .as_array()
            .unwrap()
        {
            expected.insert(helper["pid"].as_i64().unwrap());
        }
        assert_eq!(actual, expected);
        assert!(!actual.contains(&native["watcher_pid"].as_i64().unwrap()));
        assert!(!members.lines().any(|pid| pid == spawned.pid().to_string()));
        assert_eq!(
            std::fs::read_to_string(leaf.join("pids.max"))
                .unwrap()
                .trim(),
            "256"
        );
        assert_eq!(
            std::fs::read_to_string(leaf.join("memory.max"))
                .unwrap()
                .trim(),
            "67108864"
        );
        assert_eq!(
            std::fs::read_to_string(leaf.join("cpu.max"))
                .unwrap()
                .trim(),
            "50000 100000"
        );
        let id = prepared["attempt_id"].as_str().unwrap();
        spawned
            .owner()
            .release(
                &harness::gate::Release::Valid,
                id,
                receipt["policy"]["digest"].as_str().unwrap(),
            )
            .unwrap();
        let run = spawned.wait().unwrap();
        assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
        let receipt = settled(&run);
        for key in ["pids", "mem", "cpu"] {
            assert_eq!(limit(&receipt, key)["applied"], true);
            assert_eq!(limit(&receipt, key)["required"], true);
            assert_eq!(limit(&receipt, key)["scope"], "tree");
        }
        assert!(!leaf.exists(), "empty execution leaf was not removed");
    }
}

#[test]
fn l04_pids_ceiling_is_aggregate_across_forked_children() {
    if !live() {
        return;
    }
    let (jail, _) = case();
    let code = r#"
import os, signal, errno, json
children=[]
try:
    for _ in range(32):
        pid=os.fork()
        if pid == 0:
            signal.pause()
            os._exit(0)
        children.append(pid)
except OSError as e:
    print(json.dumps({'errno':e.errno,'children':len(children)}),flush=True)
finally:
    for pid in children: os.kill(pid,signal.SIGKILL)
    for pid in children: os.waitpid(pid,0)
"#;
    let run = jail
        .args(["--limit", "pids=8"])
        .target(["/usr/bin/python3", "-c", code])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let report: Value = serde_json::from_str(&run.stdout_text()).unwrap();
    assert_eq!(report["errno"], libc::EAGAIN);
    // Three slots belong to the target and the two listed backend helpers.
    assert_eq!(report["children"], 5);
    assert_eq!(limit(&settled(&run), "pids")["hit"], true);
}

#[test]
fn l03_a_ceiling_too_small_for_charged_helpers_refuses_before_target_exec() {
    if !live() {
        return;
    }
    let (jail, ws) = case();
    let marker = ws.join("target-ran");
    let code = format!("open({:?}, 'w').close()", marker.to_str().unwrap());
    let run = jail
        .args(["--limit", "pids=1"])
        .target(["/usr/bin/python3", "-c", &code])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    assert!(!marker.exists());
    assert!(run.receipt_phase("refused").is_some());
}

#[test]
fn l04_memory_events_prove_oom_but_exit_137_does_not() {
    if !live() {
        return;
    }
    // The kill is attributed from memory.events in both observation modes;
    // with observation off only the outcome's kind is ambiguous (128+9),
    // never its cause.
    for (observe, code, oom) in [
        ("on", "x=bytearray(256*1024*1024)", true),
        ("on", "import sys; sys.exit(137)", false),
        ("off", "x=bytearray(256*1024*1024)", true),
        ("off", "import sys; sys.exit(137)", false),
    ] {
        let (jail, _) = case();
        let mut spawned = jail
            .args(["--observe", observe, "--limit", "mem=64MiB"])
            .gate()
            .receipt()
            .target(["/usr/bin/python3", "-c", code])
            .spawn()
            .unwrap();
        let prepared = spawned.owner().await_prepared().unwrap();
        let before = spawned.receipt_value().unwrap();
        // memory.max limits resident memory; the host has swap. Disable swap
        // only in this test's own leaf so allocation deterministically reaches
        // OOM instead of legitimately completing through reclaim/swap.
        let leaf = Path::new(
            before["lifetime"]["native"]["details"]["execution_cgroup"]["path"]
                .as_str()
                .unwrap(),
        );
        std::fs::write(leaf.join("memory.swap.max"), "0").unwrap();
        spawned
            .owner()
            .release(
                &harness::gate::Release::Valid,
                prepared["attempt_id"].as_str().unwrap(),
                before["policy"]["digest"].as_str().unwrap(),
            )
            .unwrap();
        let run = spawned.wait().unwrap();
        let receipt = settled(&run);
        assert_eq!(limit(&receipt, "mem")["hit"], oom, "{receipt:#}");
        match (oom, observe) {
            (true, "on") => {
                assert_eq!(
                    receipt["outcome"]["kind"],
                    "signaled",
                    "{receipt:#}; stdout={} stderr={}",
                    run.stdout_text(),
                    run.stderr_text()
                );
                assert_eq!(receipt["outcome"]["signal"], libc::SIGKILL);
                assert_eq!(receipt["outcome"]["cause"], "memory_oom");
            }
            (true, _) => {
                assert_eq!(receipt["outcome"]["kind"], "unknown", "{receipt:#}");
                assert_eq!(receipt["outcome"]["cause"], "memory_oom", "{receipt:#}");
            }
            (false, "on") => {
                assert_eq!(receipt["outcome"]["kind"], "exited");
                assert_eq!(receipt["outcome"]["code"], 137);
                assert_eq!(receipt["outcome"]["cause"], Value::Null);
            }
            (false, _) => {
                assert_eq!(receipt["outcome"]["kind"], "unknown", "{receipt:#}");
                assert_ne!(receipt["outcome"]["cause"], "memory_oom", "{receipt:#}");
            }
        }
    }
}

#[test]
fn l04_cpu_is_bandwidth_throttling_not_a_failure() {
    if !live() {
        return;
    }
    let (jail, _) = case();
    let run = jail
        .args(["--limit", "cpu=10"])
        .target([
            "/usr/bin/python3",
            "-c",
            r#"
import time
start=time.monotonic(); cpu=time.process_time()
while time.process_time()-cpu < .25: pass
print(time.monotonic()-start)
"#,
        ])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(run.stdout_text().trim().parse::<f64>().unwrap() >= 1.0);
    let receipt = settled(&run);
    assert_eq!(limit(&receipt, "cpu")["hit"], true);
    assert_eq!(receipt["outcome"]["cause"], Value::Null);
}

#[test]
fn f01_build_exposes_only_declared_inputs_and_writes_scratch() {
    if !live() {
        return;
    }
    let (empty, _) = case();
    let run = empty
        .args(["--profile", "build", "--limit", "mem=64MiB"])
        .target([
            "/usr/bin/python3",
            "-c",
            r#"
import os, errno
assert os.listdir('.') == []
try:
    open('cwd-write', 'w')
    raise AssertionError('the empty working directory is writable')
except OSError as e:
    assert e.errno == errno.EROFS
open('/tmp/output', 'w').close()
"#,
        ])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let (jail, ws) = case();
    std::fs::write(ws.join("secret"), "not-an-input").unwrap();
    std::fs::write(ws.join("input"), "input").unwrap();
    let code = format!(
        r#"
import os, errno
assert not os.path.exists({secret:?})
assert os.listdir('.') == ['input']
assert open({input:?}).read() == 'input'
for path in [{input:?}, 'cwd-write']:
    try:
        open(path,'w')
        raise AssertionError(path + ' writable')
    except OSError as e:
        assert e.errno == errno.EROFS
open('/tmp/output','w').write('built')
"#,
        secret = ws.join("secret").to_str().unwrap(),
        input = ws.join("input").to_str().unwrap()
    );
    let run = jail
        .args(["--profile", "build", "--limit", "mem=64MiB"])
        .arg("--ro")
        .arg(ws.join("input"))
        .target(["/usr/bin/python3", "-c", &code])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert_eq!(settled(&run)["lifetime"]["tree_empty"], true);
}

#[test]
fn l02_every_runtime_helper_loss_ends_the_tree() {
    if !live() {
        return;
    }
    for key in [
        "supervisor",
        "watcher_pid",
        "bwrap_pid",
        "namespace_init_pid",
        "launcher_pid",
    ] {
        for observe in ["on", "off"] {
            let (jail, ws) = case();
            let marker = ws.join("running");
            let code = format!(
                "import time; open({:?},'w').close(); time.sleep(30)",
                marker.to_str().unwrap()
            );
            let mut spawned = jail
                .args(["--observe", observe])
                .gate()
                .receipt()
                .target(["/usr/bin/python3", "-c", &code])
                .spawn()
                .unwrap();
            let prepared = spawned.owner().await_prepared().unwrap();
            let receipt = spawned.receipt_value().unwrap();
            let details = &receipt["lifetime"]["native"]["details"];
            let killed = identity::pidfd_open(if key == "supervisor" {
                spawned.pid() as i32
            } else {
                details[key].as_i64().unwrap() as i32
            })
            .unwrap();
            let target =
                identity::pidfd_open(details["launcher_pid"].as_i64().unwrap() as i32).unwrap();
            spawned
                .owner()
                .release(
                    &harness::gate::Release::Valid,
                    prepared["attempt_id"].as_str().unwrap(),
                    receipt["policy"]["digest"].as_str().unwrap(),
                )
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !marker.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(marker.exists());
            use std::os::fd::AsRawFd;
            identity::pidfd_send_signal(killed.as_raw_fd(), libc::SIGKILL).unwrap();
            let run = spawned.wait().unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !watch::readable(target.as_raw_fd()) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(
                watch::readable(target.as_raw_fd()),
                "target survived {key} loss"
            );
            if key == "supervisor" {
                continue;
            }
            assert_eq!(
                settled(&run)["lifetime"]["tree_empty"],
                true,
                "{key}: {}",
                run.stderr_text()
            );
        }
    }
}

#[test]
fn l03_a_real_leaf_without_pids_refuses_required_but_runs_preferred() {
    if !live() {
        return;
    }
    use ouro_jail::platform::linux::cgroup::{self, ExecutionCgroup};
    use ouro_jail::policy::{LimitCeiling, LimitsSnapshot};
    let root = cgroup::delegated_root(unsafe { libc::getuid() })
        .unwrap()
        .join(format!("ouro-no-pids-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    // This subtree has cgroup.kill/procs/events but delegates no controllers.
    let mut limits = LimitsSnapshot {
        wall: None,
        mem: None,
        cpu: None,
        pids: Some(LimitCeiling {
            value: "256".into(),
            required: false,
        }),
    };
    {
        let mut leaf = ExecutionCgroup::create_beneath(&root, &limits).unwrap();
        assert!(!leaf.limits()[0].applied);
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        leaf.place(child.id() as i32).unwrap();
        assert!(leaf.populated().unwrap());
        leaf.kill().unwrap();
        child.wait().unwrap();
        assert!(!leaf.populated().unwrap());
        leaf.remove().unwrap();
    }
    limits.pids.as_mut().unwrap().required = true;
    assert!(ExecutionCgroup::create_beneath(&root, &limits).is_err());
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn s04_io_uring_and_compat_abis_cannot_bypass_the_filter() {
    if !common::live() {
        return;
    }
    let (jail, _) = case();
    let code = r#"
import ctypes, mmap, struct, errno
libc=ctypes.CDLL(None,use_errno=True)
for nr in [425,426,427]:
    for abi in [0,0x40000000]:
        ctypes.set_errno(0)
        assert libc.syscall(nr|abi,0,0,0,0,0,0) == -1
        assert ctypes.get_errno() == errno.EPERM
    # int 0x80 presents AUDIT_ARCH_I386 even from a native x86-64 image.
    code=b'\xb8'+struct.pack('<I',nr)+b'\xcd\x80\xc3'
    mem=mmap.mmap(-1,4096,prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
    mem.write(code)
    fn=ctypes.CFUNCTYPE(ctypes.c_int)(ctypes.addressof(ctypes.c_char.from_buffer(mem)))
    assert fn() == -errno.EPERM
print('native/x32/compat: setup, enter and register denied')
"#;
    let run = jail.target(["/usr/bin/python3", "-c", code]).run().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(
        run.stdout_text()
            .contains("setup, enter and register denied")
    );
}

/// Run in a separate process so the test can SIGKILL the actual supervisor.
#[test]
#[ignore = "subprocess helper invoked by l02_startup_parent_death_window_is_closed"]
fn startup_supervisor_helper() {
    use ouro_jail::platform::linux::{clock::Deadline, exec};
    use std::os::fd::AsRawFd;
    let root = PathBuf::from(std::env::var_os("OURO_J2_HELPER_ROOT").unwrap());
    let released = std::env::var("OURO_J2_HELPER_RELEASE").unwrap() == "yes";
    let (start_r, start_w) = exec::pipe().unwrap();
    let mut fds = exec::FdMap::new();
    fds.add(start_r, watch::START_FD).unwrap();
    let code = format!(
        "import ctypes,time; ctypes.CDLL(None).prctl(1,0,0,0,0); open({:?},'w').close(); time.sleep(30)",
        root.join("cleared").to_str().unwrap()
    );
    let mut command = std::process::Command::new(harness::jail_path());
    command.args(["__backend", "/usr/bin/python3", "-c", &code]);
    fds.apply(&mut command);
    let mut backend = command.spawn().unwrap();
    drop(fds);
    let watcher = watch::Watcher::start(
        &harness::jail_path(),
        backend.id() as i32,
        Deadline::after(Duration::from_secs(5)),
    )
    .unwrap();
    std::fs::write(
        root.join("pids"),
        format!("{} {}", backend.id(), watcher.pid()),
    )
    .unwrap();
    if released {
        assert_eq!(
            unsafe { libc::write(start_w.as_raw_fd(), [1u8].as_ptr().cast(), 1) },
            1
        );
    }
    std::fs::write(root.join("ready"), "ready").unwrap();
    backend.wait().unwrap();
}

#[test]
fn l02_startup_parent_death_window_is_closed() {
    use std::os::fd::AsRawFd;
    for released in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut supervisor = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "startup_supervisor_helper"])
            .env("OURO_J2_HELPER_ROOT", root.path())
            .env(
                "OURO_J2_HELPER_RELEASE",
                if released { "yes" } else { "no" },
            )
            .spawn()
            .unwrap();
        let ready = root.path().join(if released { "cleared" } else { "ready" });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            ready.exists(),
            "backend did not reach the synchronized startup point"
        );
        let pids = std::fs::read_to_string(root.path().join("pids")).unwrap();
        let fds: Vec<_> = pids
            .split_whitespace()
            .map(|pid| identity::pidfd_open(pid.parse().unwrap()).unwrap())
            .collect();
        supervisor.kill().unwrap();
        supervisor.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while fds.iter().any(|fd| !watch::readable(fd.as_raw_fd())) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let ended = fds.iter().all(|fd| watch::readable(fd.as_raw_fd()));
        for fd in fds {
            let _ = identity::pidfd_send_signal(fd.as_raw_fd(), libc::SIGKILL);
        }
        assert!(
            ended,
            "backend/watcher survived supervisor death (released={released})"
        );
    }
}
