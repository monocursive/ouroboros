//! Helpers shared by the network, Unix-socket and sandbox mode tests.
//!
//! Every fixture process these tests start gets an environment without the
//! proxy variables unless a test sets one, so a variable on the host running
//! the suite cannot change what a test measures.

#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use serde_json::Value;

pub const EXIT_EXPECTATION_FAILED: i32 = 3;
pub const EXIT_USAGE: i32 = 2;

pub const PROXY_VARS: [&str; 4] = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"];

pub fn fixture() -> PathBuf {
    ouro_fixture::harness::fixture_path()
}

/// A fixture command with every proxy variable removed.
pub fn command<S: AsRef<OsStr>>(args: &[S]) -> Command {
    let mut c = Command::new(fixture());
    c.args(args.iter().map(AsRef::as_ref));
    for v in PROXY_VARS {
        c.env_remove(v);
    }
    c
}

pub fn run<S: AsRef<OsStr>>(args: &[S]) -> Output {
    command(args).output().expect("the fixture binary must run")
}

pub fn run_env<S: AsRef<OsStr>>(args: &[S], env: &[(&str, &str)]) -> Output {
    let mut c = command(args);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().expect("the fixture binary must run")
}

pub fn lines(out: &Output) -> Vec<Value> {
    parse_lines(&out.stdout)
}

pub fn parse_lines(bytes: &[u8]) -> Vec<Value> {
    bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_slice(l)
                .unwrap_or_else(|e| panic!("not a JSON line: {e}: {}", String::from_utf8_lossy(l)))
        })
        .collect()
}

pub fn code(out: &Output) -> i32 {
    out.status
        .code()
        .expect("the fixture must not die on a signal")
}

pub fn ops(lines: &[Value]) -> Vec<String> {
    lines
        .iter()
        .map(|l| l["op"].as_str().unwrap_or("?").to_string())
        .collect()
}

/// The last line with this op.
pub fn last<'a>(lines: &'a [Value], op: &str) -> &'a Value {
    lines
        .iter()
        .rev()
        .find(|l| l["op"] == op)
        .unwrap_or_else(|| panic!("no `{op}` line in {lines:?}"))
}

pub fn describe(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

pub struct Dir(pub ouro_fixture::harness::TempDir);

impl Dir {
    pub fn new() -> Dir {
        Dir(ouro_fixture::harness::TempDir::new("ouro-fixture-j3").unwrap())
    }
    pub fn path(&self) -> &Path {
        self.0.path()
    }
    pub fn at(&self, name: &str) -> OsString {
        self.path().join(name).into_os_string()
    }
    pub fn at_str(&self, name: &str) -> String {
        self.at(name).into_string().expect("UTF-8 temp path")
    }
}

/// A fixture process whose report lines are read as they arrive, so a test
/// can wait for the `listen` line instead of sleeping.
pub struct Live {
    child: Child,
    reader: std::io::BufReader<std::process::ChildStdout>,
    pub seen: Vec<Value>,
}

impl Live {
    pub fn start<S: AsRef<OsStr>>(args: &[S]) -> Live {
        let mut child = command(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the fixture binary must start");
        let reader = std::io::BufReader::new(child.stdout.take().unwrap());
        Live {
            child,
            reader,
            seen: Vec::new(),
        }
    }

    /// Read lines until one with `op` arrives. The fixture's own deadline
    /// bounds this: it exits (EOF) when its timeout passes.
    pub fn wait_for(&mut self, op: &str) -> Value {
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).unwrap();
            assert!(n > 0, "EOF before a `{op}` line; saw {:?}", self.seen);
            let v: Value = serde_json::from_str(line.trim_end()).unwrap();
            self.seen.push(v.clone());
            if v["op"] == op {
                return v;
            }
        }
    }

    /// Wait for exit; return the code and every line.
    pub fn finish(mut self) -> (i32, Vec<Value>) {
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut self.reader, &mut rest).unwrap();
        self.seen.extend(parse_lines(rest.as_bytes()));
        let status = self.child.wait().unwrap();
        (
            status.code().expect("no signal"),
            std::mem::take(&mut self.seen),
        )
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        // Only the process this test started, and only if it is still ours.
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
