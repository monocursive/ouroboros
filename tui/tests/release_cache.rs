#![cfg(feature = "embed")]

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};

use ouro::runtime::embed::{gc, KEEP};

// A separate process test keeps forked descriptors out of the parallel unit tests
// that assert immediate release of extraction locks when their last handle closes.
#[test]
fn automatic_collection_preserves_an_older_running_release() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let dir = std::env::temp_dir().join(format!("ouro-cache-running-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let old = dir.join("1.0.0+old");
    fs::create_dir_all(&old).unwrap();
    fs::File::open(&old)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(3_600))
        .unwrap();
    for name in ["2.0.0+newer", "3.0.0+newest"] {
        fs::create_dir_all(dir.join(name)).unwrap();
    }

    let mut child = Command::new("/bin/sh")
        .args(["-c", "echo ready; read line; /bin/pwd -P"])
        .current_dir(&old)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut ready = String::new();
    output.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim(), "ready");

    let removed = gc(&dir, KEEP).expect("automatic collection");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"continue\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    let mut cwd = String::new();
    output.read_to_string(&mut cwd).unwrap();

    assert!(
        removed.is_empty(),
        "a live release was collected: {removed:?}"
    );
    assert!(
        result.status.success(),
        "the runtime lost its cwd: {result:?}"
    );
    assert_eq!(Path::new(cwd.trim()), old.canonicalize().unwrap());
    fs::remove_dir_all(&dir).ok();
}
