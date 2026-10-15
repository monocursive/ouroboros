#![cfg(target_os = "linux")]
//! A process-bound vault credential end to end, through `ukai-jail run
//! --launch` with the real launcher, mediator, sealed bridge and proxy.
//!
//! `binaries` binds a vault credential to the executables that may initiate a
//! connection carrying it (operating.md, `vault`): the profile pins an
//! executable at preparation, the seccomp mediator pins the process behind
//! each connect to the bridge, and the proxy substitutes the secret only when
//! that process runs the pinned executable. The pin is the opened file's
//! identity (device, inode, size and ctime), not its name or its bytes, so
//! the test pins the system curl and offers the same placeholder from a
//! byte-identical copy of it and from Python, then from the pinned curl:
//! one attempt, three clients, one origin that records every
//! `Authorization` value it receives.
//!
//! The secret and its origin are fixtures this file creates; nothing here is
//! an operator's.

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::Value;
use ukai_fixture::harness::{self, Jail, Run};

mod common;

/// The credential the origin expects. The contained processes only ever hold
/// the attempt's placeholder for it.
const SECRET: &str = "Bearer pinned-client-fixture-secret";
/// The body the origin answers every request with.
const ORIGIN_BODY: &str = "pinned-origin-ok";
/// The launch profile's name.
const PROFILE: &str = "pinned";

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn fixture_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// The origin
// ---------------------------------------------------------------------------

/// What the origin received on one connection.
#[derive(Debug)]
struct Seen {
    /// The request target, when a request line arrived.
    target: Option<String>,
    /// Every `Authorization` value, in order: a duplicated or missing header
    /// is as visible as a wrong one.
    authorization: Vec<String>,
    /// The head as received, for the failure message and for checking that
    /// no placeholder travelled beside the secret.
    head: String,
}

/// A loopback HTTP origin that records every connection it accepts, then
/// answers `200` with [`ORIGIN_BODY`] and closes. A connection is recorded
/// before its response is written, so a client holding the response proves
/// the record exists; the harness's `HttpServer` keeps no header values,
/// which this test is about.
struct Origin {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Origin {
    fn start() -> Origin {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread = {
            let (seen, stopping) = (Arc::clone(&seen), Arc::clone(&stopping));
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    // The connection that wakes a stopping origin is not a
                    // request.
                    if stopping.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Ok(stream) = stream {
                        serve(stream, &seen);
                    }
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

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stops serving and returns every connection the origin recorded.
    fn stop(mut self) -> Vec<Seen> {
        self.shutdown();
        std::mem::take(&mut *self.seen.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn shutdown(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.stopping.store(true, Ordering::SeqCst);
        // Wakes the blocked accept; the loop sees the flag and ends.
        let _ = TcpStream::connect(self.addr);
        let _ = thread.join();
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn serve(mut stream: TcpStream, seen: &Mutex<Vec<Seen>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    while !contains(&head, b"\r\n\r\n") && head.len() < 64 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.split("\r\n");
    let target = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .map(str::to_owned);
    let authorization = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim().to_owned())
        .collect();
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Seen {
            target,
            authorization,
            head,
        });
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{ORIGIN_BODY}",
            ORIGIN_BODY.len()
        )
        .as_bytes(),
    );
}

// ---------------------------------------------------------------------------
// The contained clients
// ---------------------------------------------------------------------------

/// Runs the three clients in turn, each to completion before the next starts,
/// so the proxy accepts their connections in this order: the byte-identical
/// copy (`/copy`), the driver's own urllib (`/python`) and the pinned curl
/// (`/pinned`). The pinned client goes last: a proxy that trusted whichever
/// process first presented the placeholder would relay the copy's request
/// and refuse the pinned one, where pinned-first would pass it. Each sends
/// the placeholder as the complete `Authorization`
/// value, the placement a credential without a `header` declaration accepts,
/// through the proxy the agent profile names in the environment. Prints one
/// JSON line: the placeholder the child held and what each client got back.
const DRIVER: &str = r#"
import json, os, subprocess, sys, urllib.error, urllib.request
origin, pinned, copy = sys.argv[1:4]
placeholder = os.environ["UKAI_VAULT_API"]
def curl(executable, path):
    done = subprocess.run(
        [executable, "-sS", "--noproxy", "", "--max-time", "20",
         "-H", "Authorization: " + placeholder,
         "-w", "\n%{http_code}", origin + path],
        capture_output=True)
    body, _, status = done.stdout.decode(errors="replace").rpartition("\n")
    return {"exit": done.returncode, "status": status, "body": body,
            "stderr": done.stderr.decode(errors="replace")}
def python(path):
    request = urllib.request.Request(origin + path, headers={"Authorization": placeholder})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return {"status": str(response.status), "body": response.read().decode(),
                    "reason": response.headers.get("X-Ukai-Proxy-Reason")}
    except urllib.error.HTTPError as error:
        return {"status": str(error.code), "body": error.read().decode(),
                "reason": error.headers.get("X-Ukai-Proxy-Reason")}
out = {"placeholder": placeholder}
out["copy"] = curl(copy, "/copy")
out["python"] = python("/python")
out["pinned"] = curl(pinned, "/pinned")
print(json.dumps(out))
"#;

/// The JSON line the driver printed last.
fn driver_out(run: &Run) -> Value {
    let text = run.stdout_text();
    let line = text
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| {
            panic!(
                "the driver printed no JSON: stdout {text:?}, stderr {}",
                run.stderr_text()
            )
        });
    serde_json::from_str(line).unwrap()
}

/// The system curl, the client the credential is pinned to, and the Python
/// that drives the run, or `None` after `skip_or_fail` when this host lacks
/// either. The pin opens its path without following a final symlink, so the
/// canonical path is the one the profile names and the child runs.
fn clients() -> Option<(PathBuf, PathBuf)> {
    let Ok(curl) = Path::new("/usr/bin/curl").canonicalize() else {
        harness::skip_or_fail(
            "this host has no /usr/bin/curl, the client the credential is pinned to",
        );
        return None;
    };
    let Ok(python) = Path::new("/usr/bin/python3").canonicalize() else {
        harness::skip_or_fail("this host has no /usr/bin/python3, which drives the clients");
        return None;
    };
    Some((curl, python))
}

/// Whether the product can place the contained profiles' runtime roots in
/// this host's mount table, or false after `skip_or_fail`.
///
/// A vault credential's source must lie outside every child-visible grant,
/// mount aliases included, so preparation looks up each visible root's mount
/// in mountinfo and refuses the launch when none on its path has its device.
/// A host where that lookup fails refuses every vault credential, `binaries`
/// or not: an OrbStack VM does, whose `/etc/resolv.conf` resolves into an
/// overlay mount whose files report the device of the layer beneath. The
/// same library call over the same roots says so before the run, so that
/// refusal is reported as the host's, never taken for this test's subject.
/// The probe covers the runtime roots only; a refusal over another root still
/// fails the run below.
fn visible_roots_placeable() -> bool {
    let roots: Vec<PathBuf> = ukai_jail::profiles::LINUX_RUNTIME_ROOTS
        .iter()
        .map(PathBuf::from)
        .collect();
    match ukai_jail::state::mount_alias::forbidden_identities(&roots) {
        Ok(_) => true,
        Err(error) => {
            harness::skip_or_fail(&format!(
                "the runtime roots cannot be placed in this host's mountinfo ({error}), \
                 so preparation refuses every vault credential here"
            ));
            false
        }
    }
}

/// The attempt directory of a run's only attempt.
fn attempt_of(run: &Run) -> PathBuf {
    let mut found: Vec<PathBuf> = std::fs::read_dir(run.data_dir.join("attempts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
    found.pop().unwrap()
}

/// Every regular file beneath `dir`. Symlinks and special files (the proxy's
/// socket) hold no bytes of their own to search.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in
            std::fs::read_dir(&dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        {
            let path = entry.unwrap().path();
            let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                files.push(path);
            }
        }
    }
    files
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[test]
fn a_binaries_bound_vault_credential_reaches_only_the_pinned_client() {
    if !common::live() || !visible_roots_placeable() {
        return;
    }
    let Some((curl, python)) = clients() else {
        return;
    };
    let origin = Origin::start();
    let destination = origin.addr.to_string();

    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    private_dir(&workspace.join("bin"));
    // The impostor: a file named `curl` with curl's exact bytes, in the
    // workspace the child can execute from. Its name and its bytes match the
    // pinned file's; its path and its identity (device, inode, ctime) are its
    // own, so its denial shows the pin is the file's identity and not a
    // name or content check.
    let copy = workspace.join("bin/curl");
    std::fs::copy(&curl, &copy).unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(std::fs::read(&copy).unwrap(), std::fs::read(&curl).unwrap());
    let identity = |path: &Path| {
        let metadata = std::fs::metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    };
    assert_ne!(identity(&copy), identity(&curl));

    // The source sits beside the workspace, never inside a grant.
    let secrets = jail.root().join("vault");
    private_dir(&secrets);
    let source = secrets.join("token");
    fixture_file(&source, SECRET.as_bytes());
    let quoted = |path: &Path| serde_json::to_string(path.to_str().unwrap()).unwrap();
    let profile = format!(
        "name = \"{PROFILE}\"\njail = \"agent\"\n\n\
         [credentials.api]\nmode = \"vault\"\nsource = {}\n\
         hosts = [\"{}\"]\nallow_plaintext = true\nbinaries = [{}]\n\n\
         [network]\nallow = [\"{destination}\"]\n",
        quoted(&source),
        origin.url(),
        quoted(&curl),
    );
    let launch = jail.config_dir().join("launch");
    private_dir(&launch);
    fixture_file(&launch.join(format!("{PROFILE}.toml")), profile.as_bytes());

    let run = jail
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--launch")
        .arg(PROFILE)
        .trace()
        .control()
        .target([
            python.into_os_string(),
            OsString::from("-c"),
            OsString::from(DRIVER),
            OsString::from(origin.url()),
            curl.clone().into_os_string(),
            copy.into_os_string(),
        ])
        .run()
        .unwrap();
    let seen = origin.stop();
    assert_eq!(
        run.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        run.stdout_text(),
        run.stderr_text()
    );
    let receipt = common::settled(&run);
    let attempt_id = receipt["attempt_id"].as_str().unwrap();

    // What each client got back. The child held the attempt's placeholder,
    // never the secret.
    let out = driver_out(&run);
    assert_eq!(
        out["placeholder"],
        format!("vault:{attempt_id}:api"),
        "{out:#}"
    );
    assert_eq!(out["pinned"]["exit"], 0, "{out:#}");
    assert_eq!(out["pinned"]["status"], "200", "{out:#}");
    assert_eq!(out["pinned"]["body"], ORIGIN_BODY, "{out:#}");
    assert_eq!(out["copy"]["exit"], 0, "{out:#}");
    assert_eq!(out["copy"]["status"], "403", "{out:#}");
    assert_eq!(
        out["copy"]["body"], "credential_process_denied\n",
        "{out:#}"
    );
    assert_eq!(out["python"]["status"], "403", "{out:#}");
    assert_eq!(
        out["python"]["reason"], "credential_process_denied",
        "{out:#}"
    );

    // What the origin received: the pinned client's request alone, carrying
    // the secret exactly once and no placeholder. The denied requests were
    // refused before any upstream connection, so the origin never saw them.
    assert_eq!(seen.len(), 1, "{seen:#?}");
    assert_eq!(seen[0].target.as_deref(), Some("/pinned"), "{seen:#?}");
    assert_eq!(seen[0].authorization, [SECRET], "{seen:#?}");
    assert!(!seen[0].head.contains("vault:"), "{seen:#?}");

    // The trace: one proxy result per connection, in accept order (each
    // client finished before the next connected, so request ids 1, 2 and 3
    // are the copy, Python and the pinned curl).
    let events = run.trace_events();
    let proxy: Vec<&Value> = events
        .iter()
        .filter(|event| event["source"] == "proxy")
        .collect();
    assert_eq!(proxy.len(), 3, "{proxy:#?}");
    let result = |id: u64| {
        let found: Vec<&&Value> = proxy
            .iter()
            .filter(|event| event["fields"]["request_id"] == id)
            .collect();
        assert_eq!(found.len(), 1, "request {id}: {proxy:#?}");
        *found[0]
    };
    for event in &proxy {
        assert_eq!(event["operation"], "net.connect", "{event:#}");
        assert_eq!(event["stage"], "result", "{event:#}");
        assert_eq!(event["fields"]["kind"], "http", "{event:#}");
        assert_eq!(event["fields"]["destination"], destination, "{event:#}");
    }
    let relayed = result(3);
    assert_eq!(relayed["decision"], "allow", "{relayed:#}");
    assert_eq!(relayed["fields"]["reason"], "relayed", "{relayed:#}");
    assert_eq!(
        relayed["fields"]["connected_address"], destination,
        "{relayed:#}"
    );
    assert_eq!(relayed["outcome"]["ok"], true, "{relayed:#}");
    for id in [1, 2] {
        let denied = result(id);
        assert_eq!(denied["decision"], "deny", "{denied:#}");
        assert_eq!(
            denied["fields"]["reason"], "credential_process_denied",
            "{denied:#}"
        );
        assert!(
            denied["fields"]["connected_address"].is_null(),
            "{denied:#}"
        );
        assert_eq!(denied["outcome"]["ok"], false, "{denied:#}");
        assert_eq!(denied["outcome"]["bytes_out"], 0, "{denied:#}");
    }
    // The credential's lifecycle: loaded once, never revoked.
    let notes: Vec<(&str, &str)> = events
        .iter()
        .filter(|event| event["source"] == "wrapper" && event["fields"]["kind"] == "credential")
        .map(|event| {
            (
                event["fields"]["credential_id"].as_str().unwrap(),
                event["fields"]["transition"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(notes, [("api", "loaded")], "{events:#?}");

    // The receipt: the credential never staged, one process-bound
    // credential, and every proxy result accounted for. Nothing in it, or in
    // the relayed proxy event, says which request carried the secret: the
    // origin's record above is the only witness of the substitution.
    assert_eq!(
        receipt["credentials"],
        serde_json::json!([{
            "id": "api",
            "mode": "vault",
            "never_staged": true,
            "digest": null,
            "digest_unavailable_reason": "never_staged",
        }]),
        "{receipt:#}"
    );
    let authority = &receipt["lifetime"]["native"]["details"]["agent"]["vault_authority"];
    assert_eq!(authority["process_bound_credentials"], 1, "{receipt:#}");
    assert_eq!(
        authority["process_binding"], "kernel_connection_initiator_executable",
        "{receipt:#}"
    );
    assert_eq!(
        receipt["coverage"]["proxy.net"]["status"], "active",
        "{receipt:#}"
    );
    assert_eq!(
        receipt["coverage"]["proxy.net"]["observed_count"], 3,
        "{receipt:#}"
    );
    assert_eq!(
        receipt["applied"]["network"]["allowed_hosts"],
        serde_json::json!([destination]),
        "{receipt:#}"
    );

    // The policy snapshot names the pinned path, and only it.
    let attempt = attempt_of(&run);
    let snapshot: Value =
        serde_json::from_slice(&std::fs::read(attempt.join("policy.json")).unwrap()).unwrap();
    assert_eq!(
        snapshot["snapshot"]["launch"]["credentials"][0]["vault"]["binaries"],
        serde_json::json!([curl.to_str().unwrap()]),
        "{snapshot:#}"
    );

    // The secret is nowhere the run wrote or the child could reach: its
    // output, the trace (streamed to the trace descriptor, so there is no
    // local copy), every file under the data directory (receipt, policy and
    // state) and the workspace.
    for (label, bytes) in [
        ("stdout", &run.stdout),
        ("stderr", &run.stderr),
        ("trace", &run.trace_bytes),
    ] {
        assert!(
            !contains(bytes, SECRET.as_bytes()),
            "the secret is in {label}"
        );
    }
    let mut searched = files_under(&run.data_dir);
    assert!(
        searched.iter().any(|path| path.ends_with("jail.json"))
            && searched.iter().any(|path| path.ends_with("policy.json")),
        "the receipt and the policy are among the files searched: {searched:?}"
    );
    searched.extend(files_under(&workspace));
    for path in &searched {
        let bytes =
            std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert!(
            !contains(&bytes, SECRET.as_bytes()),
            "the secret is in {}",
            path.display()
        );
    }
}
