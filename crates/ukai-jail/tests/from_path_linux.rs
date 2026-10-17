#![cfg(target_os = "linux")]
//! J12: zero-config launch through a real boundary (jail-launch-and-summary.md
//! §3, rows K35, K36, K38, K39, K41, K43 and K44).
//!
//! Each test runs the built `ukai-jail` as an operator would, from inside a
//! fixture git repository, with the program found on `PATH`: the child
//! starts where the operator stood; the install root is readable and not
//! writable inside; an `env` interpreter outside the runtime roots runs from
//! its own read-only root; the pre-exec line reaches a terminal and nothing
//! reaches a pipe; a vault placeholder is found under the agent's own name;
//! a credential bound to `@program` is substituted for the resolved program
//! and refused to `curl`, and `credential rm` revokes it while the run
//! lives. The programs, repositories, origin and secret are fixtures this
//! file creates; nothing here is an operator's.

use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::Value;
use ukai_fixture::harness;

mod common;

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn write(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A private tree: an operator home holding a git repository, a config and a
/// data directory beside it, and `tools/bin` on `PATH`.
struct Live {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    config: PathBuf,
    data: PathBuf,
    repo: PathBuf,
    bin: PathBuf,
    path: OsString,
}

impl Live {
    fn new() -> Live {
        let temp = common::private_tempdir();
        let root = temp.path().canonicalize().unwrap();
        let live = Live {
            home: root.join("home"),
            config: root.join("config"),
            data: root.join("data"),
            repo: root.join("home/repo"),
            bin: root.join("tools/bin"),
            path: OsString::new(),
            root,
            _temp: temp,
        };
        mkdir(&live.home, 0o700);
        mkdir(&live.config.join("launch"), 0o700);
        mkdir(&live.data, 0o700);
        mkdir(&live.repo.join("src"), 0o755);
        mkdir(&live.repo.join(".git"), 0o755);
        write(
            &live.repo.join(".git/HEAD"),
            b"ref: refs/heads/main\n",
            0o644,
        );
        mkdir(&live.bin, 0o755);
        std::fs::set_permissions(
            live.root.join("tools"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut path = live.bin.clone().into_os_string();
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()));
        Live { path, ..live }
    }

    fn profile(&self, name: &str, text: &str) {
        write(
            &self.config.join("launch").join(format!("{name}.toml")),
            text.as_bytes(),
            0o600,
        );
    }

    fn command(&self, cwd: &Path, argv: &[&OsStr]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ukai-jail"));
        command
            .env("PATH", &self.path)
            .env("HOME", &self.home)
            .env("UKAI_DATA_DIR", &self.data)
            .env("UKAI_CONFIG_DIR", &self.config)
            .current_dir(cwd)
            .args(argv)
            .stdin(Stdio::null());
        command
    }

    fn output(&self, cwd: &Path, argv: &[&OsStr]) -> Output {
        self.command(cwd, argv).output().expect("the binary runs")
    }

    /// The single attempt this tree's data directory holds.
    fn attempt(&self) -> PathBuf {
        let mut found: Vec<PathBuf> = std::fs::read_dir(self.data.join("attempts"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(found.len(), 1, "{found:?}");
        found.pop().unwrap()
    }

    fn receipt(&self) -> Value {
        common::read_receipt(&self.attempt().join("jail.json"))
    }

    fn journal(&self) -> Vec<Value> {
        std::fs::read_to_string(self.attempt().join("trace.ndjson"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn os(text: &str) -> &OsStr {
    OsStr::new(text)
}

fn report(output: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn derived_grants(receipt: &Value) -> Vec<String> {
    receipt["policy"]["grants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|grant| grant["by"] == "program_resolution")
        .map(|grant| {
            assert_eq!(grant["kind"], "read_only", "{grant:#}");
            grant["value"].as_str().unwrap().to_owned()
        })
        .collect()
}

/// A program that reports where it started and whether it can write into
/// its own directory, then writes into its working directory.
const PROBE: &[u8] = b"#!/bin/sh\npwd\n\
if touch \"$(dirname \"$0\")/written\" 2>/dev/null; then echo wrote; else echo refused; fi\n\
echo made > ./made\necho child-output >&2\n";

/// K35, K36: `ukai-jail probe` from `repo/src` starts the child in
/// `repo/src`; the program's directory is bound read-only (its write fails
/// and is journaled as `fs.deny`) and recorded as a `program_resolution`
/// grant; with stderr a pipe, the jail adds no pre-exec line (X05).
#[test]
fn k35_k36_the_child_starts_where_the_operator_stood_and_its_root_is_read_only() {
    if !common::live() {
        return;
    }
    let live = Live::new();
    live.profile("probe", "name = \"probe\"\njail = \"tool\"\n");
    write(&live.bin.join("probe"), PROBE, 0o755);
    let cwd = live.repo.join("src");
    let output = live.output(&cwd, &[os("probe")]);
    assert_eq!(output.status.code(), Some(0), "{}", report(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout,
        format!("{}\nrefused\n", cwd.display()),
        "{}",
        report(&output)
    );
    assert_eq!(std::fs::read(cwd.join("made")).unwrap(), b"made\n");
    assert!(!live.bin.join("written").exists());
    // X05: the child's own stderr, and nothing the jail added.
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "child-output\n",
        "{}",
        report(&output)
    );
    let receipt = live.receipt();
    assert_eq!(receipt["phase"], "settled", "{receipt:#}");
    assert_eq!(derived_grants(&receipt), [live.bin.to_str().unwrap()]);
    let journal = live.journal();
    assert!(
        journal.iter().any(|event| event["operation"] == "fs.deny"),
        "the refused write into the install root is journaled: {journal:#?}"
    );
    let snapshot: Value =
        serde_json::from_slice(&std::fs::read(live.attempt().join("policy.json")).unwrap())
            .unwrap();
    assert_eq!(snapshot["snapshot"]["roots"]["cwd"], "src", "{snapshot:#}");
}

/// K35 under `none`: the uncontained child starts where the operator stood
/// beneath an explicit workspace too (review NL3: the `none` launcher's
/// working directory).
#[test]
fn k35_none_starts_where_the_operator_stood() {
    if !common::live() {
        return;
    }
    let live = Live::new();
    let cwd = live.repo.join("src");
    let output = live.output(
        &cwd,
        &[
            os("run"),
            os("--profile"),
            os("none"),
            os("--workspace"),
            live.repo.as_os_str(),
            os("--"),
            os("/bin/pwd"),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", report(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{}\n", cwd.display()),
        "{}",
        report(&output)
    );
}

/// K39: on a terminal, one line naming the program and its read-only root
/// precedes the child's first byte.
#[test]
fn k39_the_program_line_precedes_exec_on_a_terminal() {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    if !common::live() {
        return;
    }
    let live = Live::new();
    live.profile("probe", "name = \"probe\"\njail = \"tool\"\n");
    write(&live.bin.join("probe"), PROBE, 0o755);
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: both pointers are to live integers the call fills; the name,
    // termios and window size arguments may be null.
    let rc = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: openpty returned two fresh descriptors this test now owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let mut command = live.command(&live.repo, &[os("probe")]);
    command.stdout(Stdio::piped()).stderr(Stdio::from(slave));
    let child = command.spawn().unwrap();
    drop(command);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut terminal = std::fs::File::from(master);
        let mut seen = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match terminal.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => seen.extend_from_slice(&buffer[..n]),
            }
        }
        let _ = sender.send(seen);
    });
    let output = child.wait_with_output().unwrap();
    let seen = receiver.recv_timeout(Duration::from_secs(60)).unwrap();
    let terminal = String::from_utf8_lossy(&seen).replace('\r', "");
    assert_eq!(output.status.code(), Some(0), "{terminal}");
    let line = format!(
        "ukai-jail: probe = {}/probe (read-only: {})",
        live.bin.display(),
        live.bin.display()
    );
    let at = terminal
        .find(&line)
        .unwrap_or_else(|| panic!("{line:?} in\n{terminal}"));
    let child_at = terminal.find("child-output").expect("the child's output");
    assert!(at < child_at, "{terminal}");
}

/// K38: `#!/usr/bin/env mysh` with `mysh` outside the runtime roots runs as
/// `[mysh', E]`, with `mysh`'s directory granted read-only beside E's.
#[test]
fn k38_an_env_interpreter_outside_the_runtime_roots_runs() {
    if !common::live() {
        return;
    }
    let live = Live::new();
    let runtime = live.root.join("tools/rt");
    mkdir(&runtime, 0o755);
    let shell = Path::new("/bin/sh").canonicalize().unwrap();
    std::fs::copy(&shell, runtime.join("mysh")).unwrap();
    std::fs::set_permissions(runtime.join("mysh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    live.profile("probe", "name = \"probe\"\njail = \"tool\"\n");
    write(
        &live.bin.join("probe"),
        b"#!/usr/bin/env mysh\necho expanded \"$0\"\n",
        0o755,
    );
    let mut path = live.path.clone();
    path.push(":");
    path.push(&runtime);
    let output = live
        .command(&live.repo, &[os("probe"), os("argument")])
        .env("PATH", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", report(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("expanded {}/probe\n", live.bin.display()),
        "{}",
        report(&output)
    );
    let receipt = live.receipt();
    assert_eq!(
        derived_grants(&receipt),
        [live.bin.to_str().unwrap(), runtime.to_str().unwrap()]
    );
    assert_eq!(
        receipt["argv_digest"],
        ukai_jail::canonical::argv_digest(&[
            runtime.join("mysh").as_os_str().as_bytes().to_vec(),
            live.bin.join("probe").as_os_str().as_bytes().to_vec(),
            b"argument".to_vec(),
        ])
    );
}

/// K41: a vault `env` puts the placeholder under the agent's own name, and
/// only there: no `UKAI_VAULT_*` name and never the value.
#[test]
fn k41_the_placeholder_is_under_the_agent_s_own_name() {
    if !common::live() {
        return;
    }
    let live = Live::new();
    let secret = b"k41-fixture-secret-value";
    mkdir(&live.config.join("credentials"), 0o700);
    write(&live.config.join("credentials/api"), secret, 0o600);
    live.profile(
        "envprobe",
        "name = \"envprobe\"\njail = \"agent\"\n\n[credentials.api]\nmode = \"vault\"\n\
         source = \"@config/credentials/api\"\nenv = \"AGENT_TOKEN\"\n\
         hosts = [\"https://api.example.com\"]\n",
    );
    write(&live.bin.join("envprobe"), b"#!/bin/sh\nenv\n", 0o755);
    let output = live.output(&live.repo, &[os("envprobe")]);
    assert_eq!(output.status.code(), Some(0), "{}", report(&output));
    let receipt = live.receipt();
    let attempt = receipt["attempt_id"].as_str().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .lines()
            .any(|line| line == format!("AGENT_TOKEN=vault:{attempt}:api")),
        "{stdout}"
    );
    assert!(!stdout.contains("UKAI_VAULT_"), "{stdout}");
    // Every client's trust variable names the attempt's CA (review NL6).
    for name in ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"] {
        assert!(
            stdout
                .lines()
                .any(|line| line == format!("{name}=/run/ukai/vault-ca.pem")),
            "{name}: {stdout}"
        );
    }
    assert!(
        !contains(&output.stdout, secret),
        "the value reached the child"
    );
    assert_eq!(receipt["credentials"][0]["id"], "api", "{receipt:#}");
    assert_eq!(
        receipt["credentials"][0]["never_staged"], true,
        "{receipt:#}"
    );
}

// ---------------------------------------------------------------------------
// K43, K44: the credential bound to the resolved program
// ---------------------------------------------------------------------------

/// The credential the origin expects; the contained processes only hold the
/// attempt's placeholder.
const SECRET: &str = "k43-program-bound-fixture-secret";
const ORIGIN_BODY: &str = "program-origin-ok";

struct Origin {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Origin {
    /// A loopback HTTP origin recording each request head before answering
    /// `200` with [`ORIGIN_BODY`].
    fn start() -> Origin {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread = {
            let (seen, stopping) = (Arc::clone(&seen), Arc::clone(&stopping));
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stopping.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(mut stream) = stream else { continue };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !contains(&head, b"\r\n\r\n") && head.len() < 64 * 1024 {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(read) => head.extend_from_slice(&chunk[..read]),
                        }
                    }
                    seen.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(String::from_utf8_lossy(&head).into_owned());
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n\
                             {ORIGIN_BODY}",
                            ORIGIN_BODY.len()
                        )
                        .as_bytes(),
                    );
                }
            })
        };
        Origin {
            addr,
            seen,
            stopping,
            thread: Some(thread),
        }
    }

    fn stop(mut self) -> Vec<String> {
        self.shutdown();
        std::mem::take(&mut *self.seen.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn shutdown(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.stopping.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        let _ = thread.join();
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Run by the resolved program (a copy of Python, so its identity is its
/// own): its own request, the same placeholder from the system `curl`, then,
/// once the test has removed the credential, its own request again.
const DRIVER: &str = r#"
import json, os, subprocess, sys, time, urllib.error, urllib.request
origin, curl, workspace = sys.argv[1:4]
placeholder = os.environ["AGENT_TOKEN"]
def own(path):
    request = urllib.request.Request(origin + path, headers={"Authorization": placeholder})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return {"status": str(response.status), "body": response.read().decode()}
    except urllib.error.HTTPError as error:
        return {"status": str(error.code), "body": error.read().decode(),
                "reason": error.headers.get("X-Ukai-Proxy-Reason")}
def other(path):
    done = subprocess.run(
        [curl, "-sS", "--max-time", "20", "-H", "Authorization: " + placeholder,
         "-w", "\n%{http_code}", origin + path], capture_output=True)
    body, _, status = done.stdout.decode(errors="replace").rpartition("\n")
    return {"exit": done.returncode, "status": status, "body": body}
out = {"placeholder": placeholder, "own": own("/own"), "curl": other("/curl")}
open(os.path.join(workspace, "first-done"), "w").close()
for _ in range(600):
    if os.path.exists(os.path.join(workspace, "go")):
        break
    time.sleep(0.05)
out["after_rm"] = own("/after")
print(json.dumps(out))
"#;

/// K43, K44: the resolved program's own request carries the credential; the
/// same placeholder from `curl` inside is refused `credential_process_denied`;
/// `ukai-jail credential rm` while the run lives revokes the lease, so the
/// program's next request is refused.
#[test]
fn k43_k44_the_program_bound_credential_reaches_only_the_program_until_removed() {
    if !common::live() {
        return;
    }
    let (Ok(python), Ok(curl)) = (
        Path::new("/usr/bin/python3").canonicalize(),
        Path::new("/usr/bin/curl").canonicalize(),
    ) else {
        harness::skip_or_fail("this host lacks /usr/bin/python3 or /usr/bin/curl");
        return;
    };
    let roots: Vec<PathBuf> = ukai_jail::profiles::LINUX_RUNTIME_ROOTS
        .iter()
        .map(PathBuf::from)
        .collect();
    if let Err(error) = ukai_jail::state::mount_alias::forbidden_identities(&roots) {
        harness::skip_or_fail(&format!(
            "the runtime roots cannot be placed in this host's mountinfo ({error})"
        ));
        return;
    }
    let live = Live::new();
    let origin = Origin::start();
    let url = format!("http://{}", origin.addr);
    std::fs::copy(&python, live.bin.join("pyagent")).unwrap();
    std::fs::set_permissions(
        live.bin.join("pyagent"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let set = live
        .command(&live.repo, &[os("credential"), os("set"), os("api")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{SECRET}\n").as_bytes())?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(set.status.code(), Some(0), "{}", report(&set));
    live.profile(
        "pyagent",
        &format!(
            "name = \"pyagent\"\njail = \"agent\"\n\n[credentials.api]\nmode = \"vault\"\n\
             source = \"@config/credentials/api\"\nenv = \"AGENT_TOKEN\"\n\
             hosts = [\"{url}\"]\nallow_plaintext = true\nbinaries = [\"@program\"]\n\n\
             [network]\nallow = [\"{}\"]\n",
            origin.addr
        ),
    );
    let mut child = live
        .command(
            &live.repo,
            &[
                os("pyagent"),
                os("-c"),
                os(DRIVER),
                os(&url),
                curl.as_os_str(),
                live.repo.as_os_str(),
            ],
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    common::eventually(
        "the program's first requests",
        Duration::from_secs(60),
        || live.repo.join("first-done").exists(),
    );
    let rm = live.output(&live.repo, &[os("credential"), os("rm"), os("api")]);
    assert_eq!(rm.status.code(), Some(0), "{}", report(&rm));
    // The vault's lease poll is 100 ms; a few of them pass before the next
    // request.
    std::thread::sleep(Duration::from_millis(600));
    write(&live.repo.join("go"), b"", 0o644);
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    let status = child.wait().unwrap();
    let seen = origin.stop();
    let text = String::from_utf8_lossy(&stdout);
    assert_eq!(
        status.code(),
        Some(0),
        "stdout {text}\nstderr {}",
        String::from_utf8_lossy(&stderr)
    );
    let out: Value = serde_json::from_str(
        text.lines()
            .rev()
            .find(|line| line.starts_with('{'))
            .unwrap_or_else(|| panic!("no JSON: {text}")),
    )
    .unwrap();
    let receipt = live.receipt();
    let attempt = receipt["attempt_id"].as_str().unwrap();
    assert_eq!(
        out["placeholder"],
        format!("vault:{attempt}:api"),
        "{out:#}"
    );
    assert_eq!(out["own"]["status"], "200", "{out:#}");
    assert_eq!(out["own"]["body"], ORIGIN_BODY, "{out:#}");
    assert_eq!(out["curl"]["status"], "403", "{out:#}");
    assert_eq!(
        out["curl"]["body"], "credential_process_denied\n",
        "{out:#}"
    );
    assert_ne!(out["after_rm"]["status"], "200", "{out:#}");
    assert!(
        out["after_rm"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.starts_with("credential_")),
        "{out:#}"
    );
    // The origin saw the program's first request alone, with the secret.
    assert_eq!(seen.len(), 1, "{seen:#?}");
    assert!(
        seen[0].contains(&format!("Authorization: {SECRET}")),
        "{seen:#?}"
    );
    assert!(!seen[0].contains("vault:"), "{seen:#?}");
    // The binding names the resolved program, and the lifecycle the removal.
    let snapshot: Value =
        serde_json::from_slice(&std::fs::read(live.attempt().join("policy.json")).unwrap())
            .unwrap();
    assert_eq!(
        snapshot["snapshot"]["launch"]["credentials"][0]["vault"]["binaries"],
        serde_json::json!([live.bin.join("pyagent").to_str().unwrap()]),
        "{snapshot:#}"
    );
    let transitions: Vec<String> = live
        .journal()
        .iter()
        .filter(|event| event["fields"]["kind"] == "credential")
        .map(|event| event["fields"]["transition"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        transitions.iter().any(|t| t == "revoked"),
        "{transitions:?}"
    );
    // The value is nowhere the run wrote.
    for (label, bytes) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(
            !contains(bytes, SECRET.as_bytes()),
            "the secret is in {label}"
        );
    }
    for name in ["jail.json", "policy.json", "trace.ndjson"] {
        let bytes = std::fs::read(live.attempt().join(name)).unwrap();
        assert!(
            !contains(&bytes, SECRET.as_bytes()),
            "the secret is in {name}"
        );
    }
}

// ---------------------------------------------------------------------------
// Review F5: the window between the recheck before release and the exec
// ---------------------------------------------------------------------------

/// What a test does to the program in the window the swap seam opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    /// Nothing: the seam alone must not change the run.
    Untouched,
    /// Another file is renamed over the program in its install root.
    RenamedOver,
    /// The program is written in place, the same inode.
    WrittenInPlace,
}

/// Runs `NAME ARG...` from the repository with the swap seam
/// (`UKAI_JAIL_TEST_PROGRAM_SWAP`) holding the supervisor after its recheck
/// before release, applies `change` to the program there, and lets the run
/// go on. The replacement a rename brings would write `swapped-ran` into
/// the repository and print `swapped`.
fn run_with_change(live: &Live, name: &str, args: &[&OsStr], change: Change) -> Output {
    let seam = live.root.join(format!("seam-{name}-{change:?}"));
    mkdir(&seam, 0o700);
    let program = live.bin.join(name);
    let mut argv = vec![os(name)];
    argv.extend_from_slice(args);
    let mut child = live
        .command(&live.repo, &argv)
        .env(ukai_jail::program::SWAP_SEAM, &seam)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ended = false;
    common::eventually(
        "the supervisor past its recheck before release",
        Duration::from_secs(60),
        || {
            ended = child.try_wait().unwrap().is_some();
            ended || seam.join("rechecked").exists()
        },
    );
    if ended {
        let output = child.wait_with_output().unwrap();
        panic!(
            "{name} {change:?}: the run ended before the seam: {}",
            report(&output)
        );
    }
    match change {
        Change::Untouched => {}
        Change::RenamedOver => {
            let replacement = live.bin.join(format!(".{name}.new"));
            write(
                &replacement,
                format!(
                    "#!/bin/sh\necho swapped > {}\necho swapped\n",
                    live.repo.join("swapped-ran").display()
                )
                .as_bytes(),
                0o755,
            );
            std::fs::rename(&replacement, &program).unwrap();
        }
        Change::WrittenInPlace => {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&program)
                .unwrap();
            file.write_all(b"\0").unwrap();
        }
    }
    write(&seam.join("go"), b"", 0o600);
    child.wait_with_output().unwrap()
}

/// A changed program's refusal: exit 125, nothing printed, nothing run, and
/// a refused receipt whose exec error is `ESTALE`, `policy_widening` at
/// `--from-path`, with the seam recorded.
fn assert_refused_as_changed(live: &Live, output: &Output, label: &str) {
    assert_eq!(
        output.status.code(),
        Some(125),
        "{label}: {}",
        report(output)
    );
    assert!(output.stdout.is_empty(), "{label}: {}", report(output));
    assert!(
        !live.repo.join("swapped-ran").exists(),
        "{label}: the replacement ran"
    );
    let receipt = live.receipt();
    assert_eq!(receipt["phase"], "refused", "{label}: {receipt:#}");
    let outcome = &receipt["outcome"];
    assert_eq!(outcome["kind"], "exec_error", "{label}: {outcome:#}");
    assert_eq!(outcome["cause"], "ESTALE", "{label}: {outcome:#}");
    assert_eq!(
        outcome["error"]["code"], "policy_widening",
        "{label}: {outcome:#}"
    );
    assert_eq!(
        outcome["error"]["key_path"], "--from-path",
        "{label}: {outcome:#}"
    );
    assert!(
        outcome["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("changed between the recheck before release")),
        "{label}: {outcome:#}"
    );
    assert_eq!(
        receipt["lifetime"]["native"]["details"]["test_seams"][ukai_jail::program::SWAP_SEAM],
        live.root.join(format!("seam-{label}")).to_str().unwrap(),
        "{label}: {receipt:#}"
    );
}

/// The ELF program a test pins: a copy of the host's `/bin/sh`. Not
/// `echo`: on the reference host that is uutils' multi-call binary, which
/// names itself from `AT_EXECFN` and refuses any other name.
fn elf_shell(live: &Live, name: &str) {
    let shell = Path::new("/bin/sh").canonicalize().unwrap();
    std::fs::copy(&shell, live.bin.join(name)).unwrap();
    std::fs::set_permissions(live.bin.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        &std::fs::read(live.bin.join(name)).unwrap()[..4],
        b"\x7fELF"
    );
}

/// Review F5: an ELF program renamed over, or written in place, after the
/// supervisor's recheck before release is refused by the launcher's own
/// check, under `tool` and `agent` (`--from-path` refuses `none`): neither
/// the pinned file nor the replacement runs. Untouched, the same seam runs
/// the pinned file, through the descriptor the launcher checked: the
/// target's exec is an `execveat` and the observer confirms it.
#[test]
fn f5_an_elf_program_changed_after_the_recheck_is_refused_not_run() {
    if !common::live() {
        return;
    }
    for jail in ["tool", "agent"] {
        for change in [
            Change::Untouched,
            Change::RenamedOver,
            Change::WrittenInPlace,
        ] {
            let label = format!("{jail} {change:?}");
            let live = Live::new();
            let name = format!("f5{jail}");
            live.profile(&name, &format!("name = \"{name}\"\njail = \"{jail}\"\n"));
            elf_shell(&live, &name);
            let output = run_with_change(&live, &name, &[os("-c"), os("echo pinned-ran")], change);
            if change == Change::Untouched {
                assert_eq!(
                    output.status.code(),
                    Some(0),
                    "{label}: {}",
                    report(&output)
                );
                assert_eq!(
                    String::from_utf8_lossy(&output.stdout),
                    "pinned-ran\n",
                    "{label}"
                );
                let receipt = live.receipt();
                assert_eq!(receipt["phase"], "settled", "{label}: {receipt:#}");
                // Observation is on by default: the observer confirmed the
                // exec, and the call it witnessed is the descriptor's.
                assert_eq!(receipt["exec_observed"], true, "{label}: {receipt:#}");
                let journal = live.journal();
                let first = journal
                    .iter()
                    .find(|event| event["operation"] == "proc.exec")
                    .unwrap_or_else(|| panic!("{label}: no exec in {journal:#?}"));
                assert_eq!(first["fields"]["syscall"], "execveat", "{label}: {first:#}");
            } else {
                assert_refused_as_changed(&live, &output, &format!("{name}-{change:?}"));
            }
        }
    }
}

/// Review F5: a root-owned program runs. Inside the jail's user namespace
/// its owner reads as the overflow uid, so the launcher's check must not
/// compare owners: `sh` resolves to the host's root-owned shell under the
/// runtime roots (a covered install root), under `tool` and `agent`.
#[test]
fn f5_a_root_owned_program_runs_through_its_checked_descriptor() {
    if !common::live() {
        return;
    }
    use std::os::unix::fs::MetadataExt as _;
    let shell = Path::new("/bin/sh").canonicalize().unwrap();
    if std::fs::metadata(&shell).unwrap().uid() != 0 {
        harness::skip_or_fail("this host's /bin/sh is not owned by root");
        return;
    }
    for jail in ["tool", "agent"] {
        let live = Live::new();
        live.profile("sh", &format!("name = \"sh\"\njail = \"{jail}\"\n"));
        let output = live.output(&live.repo, &[os("sh"), os("-c"), os("echo root-owned-ran")]);
        assert_eq!(output.status.code(), Some(0), "{jail}: {}", report(&output));
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "root-owned-ran\n",
            "{jail}"
        );
        let receipt = live.receipt();
        assert_eq!(receipt["exec_observed"], true, "{jail}: {receipt:#}");
    }
    // With observation off the exec is confirmed without the observer: by
    // the error pipe's end and the launcher's image having changed, which
    // the target must live long enough for the supervisor to see.
    let live = Live::new();
    live.profile("sh", "name = \"sh\"\njail = \"tool\"\n");
    let output = live.output(
        &live.repo,
        &[
            os("run"),
            os("--observe"),
            os("off"),
            os("--launch"),
            os("sh"),
            os("--from-path"),
            os("--"),
            os("-c"),
            os("sleep 0.3; echo unobserved-ran"),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", report(&output));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "unobserved-ran\n");
    assert_eq!(live.receipt()["exec_observed"], true);
}

/// Review F5: a `#!` script renamed over after the recheck is refused by the
/// launcher's check by path, the last thing before the exec.
#[test]
fn f5_a_script_renamed_over_after_the_recheck_is_refused_not_run() {
    if !common::live() {
        return;
    }
    let live = Live::new();
    live.profile("f5script", "name = \"f5script\"\njail = \"tool\"\n");
    write(
        &live.bin.join("f5script"),
        b"#!/bin/sh\necho pinned-ran\n",
        0o755,
    );
    let output = run_with_change(&live, "f5script", &[], Change::RenamedOver);
    assert_refused_as_changed(&live, &output, "f5script-RenamedOver");
}
