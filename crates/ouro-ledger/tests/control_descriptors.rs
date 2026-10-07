//! Real CLI descriptor rejection, before any writer or jail is started.
#![cfg(unix)]
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            net::{UnixDatagram, UnixStream},
            process::CommandExt,
        },
    },
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
const CONTROL: i32 = 198;

#[test]
fn invalid_control_destinations_never_prepare_or_execute() {
    for case in [
        "closed",
        "readonly",
        "directory",
        "device",
        "datagram",
        "disconnected",
        "stdin-alias",
        "stdout-alias",
        "stderr-alias",
        "file-alias",
        "detach",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let file_path = temp.path().join("file");
        fs::write(&file_path, b"keep").unwrap();
        let mut peer = None;
        let fd: OwnedFd = match case {
            "directory" => File::open(temp.path()).unwrap().into(),
            "device" => OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .unwrap()
                .into(),
            "datagram" => UnixDatagram::unbound().unwrap().into(),
            "disconnected" => {
                let (sender, receiver) = UnixStream::pair().unwrap();
                drop(receiver);
                sender.into()
            }
            "detach" => {
                let (sender, receiver) = UnixStream::pair().unwrap();
                peer = Some(receiver);
                sender.into()
            }
            "file-alias" => OpenOptions::new()
                .write(true)
                .open(&file_path)
                .unwrap()
                .into(),
            _ => File::open(&file_path).unwrap().into(),
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_ouro-ledger"));
        command
            .arg("--data-dir")
            .arg(&data)
            .args(["run", "--control-fd", "198", "--json"]);
        if case == "detach" {
            command.args(["--detach", "--io", "batch"]);
        }
        command
            .args(["--", "/bin/true"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let source = fd.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                let source = match case {
                    "stdin-alias" => 0,
                    "stdout-alias" => 1,
                    "stderr-alias" => 2,
                    _ => source,
                };
                if libc::dup2(source, CONTROL) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if case == "closed" {
                    libc::close(CONTROL);
                }
                if case == "file-alias" && libc::dup2(CONTROL, 1) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() >= Duration::from_secs(5) {
                let _ = child.kill();
                panic!("{case} hung");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success(), "{case}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--control-fd"),
            "{case}: {:?}",
            output.stderr
        );
        assert!(output.stdout.is_empty(), "{case}");
        assert!(
            !data.exists(),
            "{case}: created a store before rejecting control"
        );
        assert_eq!(fs::read(file_path).unwrap(), b"keep");
        drop(peer);
    }
}

#[test]
fn foreground_json_without_a_control_fd_still_refuses_before_launch() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let output = Command::new(env!("CARGO_BIN_EXE_ouro-ledger"))
        .arg("--data-dir")
        .arg(&data)
        .args(["run", "--json", "--", "/bin/true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--control-fd"));
    assert!(!data.exists());
}
