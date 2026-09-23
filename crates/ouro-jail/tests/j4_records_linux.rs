//! J4 slice R, live: a crash at each named point of each persistence site
//! leaves valid records (jail-v1 §7, §13.2; R02).
//!
//! The release binary runs a real `tool` attempt with
//! `OURO_JAIL_TEST_ABORT_AT=<site>:<point>` (S9), which aborts the supervisor
//! at exactly that point of the first replacement at that site: after the
//! temporary file is written, after it is synced, after the rename (or the
//! claim's link), after the directory sync. No timing is involved, so every
//! case is the crash it names, and a case whose point is never reached fails
//! instead of passing without having checked anything (N10: the sleep-timed
//! `r8_receipts_are_never_left_truncated` it replaces could).
//!
//! After each crash: every record file present parses, `jail.json` is a
//! schema- and semantically valid receipt showing the prior phase before the
//! rename and the new phase after it, the seam is recorded in the receipt and
//! in jail state, the temporary files the crash left are exactly the ones
//! named by `state::leftover_temp_files`, and a following `gc` keeps every
//! record. Needs `OURO_CONFORMANCE=1` and the reference host.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use ouro_fixture::harness::{self, Jail};
use ouro_jail::state::{self, AttemptDir, AttemptId};
use serde_json::Value;

mod common;
use common::live;

/// A crash point and what the records must show after it.
#[derive(Clone, Copy)]
struct Point {
    name: &'static str,
    /// The new content is visible under the target name.
    published: bool,
    /// The temporary name is still there.
    temp_left: bool,
}

const POINTS: [Point; 4] = [
    Point {
        name: "temp_written",
        published: false,
        temp_left: true,
    },
    Point {
        name: "temp_synced",
        published: false,
        temp_left: true,
    },
    Point {
        name: "renamed",
        published: true,
        temp_left: false,
    },
    Point {
        name: "dir_synced",
        published: true,
        temp_left: false,
    },
];

/// A site, how a run reaches it, and what it replaces.
struct Site {
    name: &'static str,
    /// The record the replacement targets.
    record: &'static str,
    /// Run with a launch profile (vendor state).
    launch: bool,
    /// The target exec fails (a missing program), so the run refuses.
    exec_fails: bool,
    /// `jail.json`'s phase before and after the replacement.
    phases: (Option<&'static str>, Option<&'static str>),
}

const SITES: [Site; 10] = [
    Site {
        name: "claim",
        record: "jail-state.json",
        launch: false,
        exec_fails: false,
        phases: (None, None),
    },
    Site {
        name: "policy",
        record: "policy.json",
        launch: false,
        exec_fails: false,
        phases: (None, None),
    },
    Site {
        name: "launch_state",
        record: "jail-state.json",
        launch: true,
        exec_fails: false,
        phases: (None, None),
    },
    Site {
        name: "boundary",
        record: "jail-state.json",
        launch: false,
        exec_fails: false,
        phases: (None, None),
    },
    Site {
        name: "prepared_receipt",
        record: "jail.json",
        launch: false,
        exec_fails: false,
        phases: (None, Some("prepared")),
    },
    Site {
        name: "enforced_receipt",
        record: "jail.json",
        launch: false,
        exec_fails: false,
        phases: (Some("prepared"), Some("enforced")),
    },
    Site {
        name: "pending_receipt",
        record: "jail.json",
        launch: true,
        exec_fails: false,
        phases: (Some("enforced"), Some("settled")),
    },
    Site {
        name: "terminal_receipt",
        record: "jail.json",
        launch: false,
        exec_fails: false,
        phases: (Some("enforced"), Some("settled")),
    },
    Site {
        name: "refused_receipt",
        record: "jail.json",
        launch: false,
        exec_fails: true,
        phases: (Some("prepared"), Some("refused")),
    },
    Site {
        name: "cleanup_record",
        record: "jail-state.json",
        launch: true,
        exec_fails: false,
        phases: (Some("settled"), Some("settled")),
    },
];

fn parse(path: &Path) -> Result<Option<Value>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("{} does not parse: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{} cannot be read: {error}", path.display())),
    }
}

/// One crash, and every problem it left.
fn crash(site: &Site, point: Point) -> Vec<String> {
    let label = format!("{}:{}", site.name, point.name);
    // The abort must not leave a core file anywhere: `ulimit -c 0`, then exec
    // the jail itself, so the harness's channels reach it unchanged.
    let mut jail = Jail::with_program("/bin/sh")
        .expect("harness")
        .args(["-c", "ulimit -c 0 && exec \"$0\" \"$@\""])
        .arg(harness::jail_path());
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let fixture = workspace.join("ouro-fixture");
    std::fs::copy(harness::fixture_path(), &fixture).expect("copy the fixture");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755))
            .expect("chmod the fixture");
    }
    if site.launch {
        let launch = jail.config_dir().join("launch");
        std::fs::create_dir_all(&launch).expect("launch dir");
        let profile = launch.join("plain.toml");
        std::fs::write(
            &profile,
            "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a/b\"]\n",
        )
        .expect("launch profile");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o600))
            .expect("a private launch profile");
    }
    let data = jail.data_dir();
    jail = jail
        .arg("run")
        .args(["--profile", "tool", "--workspace"])
        .arg(&workspace)
        .env(state::ABORT_AT_SEAM, &label)
        .control()
        .receipt();
    if site.launch {
        jail = jail.args(["--launch", "plain"]);
    }
    let jail = if site.exec_fails {
        jail.target(["/nonexistent-ouro-j4-target"])
    } else {
        jail.target([fixture.as_os_str(), "exit".as_ref(), "0".as_ref()])
    };
    let run = jail.run().expect("the run");
    let mut problems = Vec::new();
    if run.signal() != Some(libc::SIGABRT) {
        problems.push(format!(
            "{label}: the abort point was never reached (exit {:?}, signal {:?}): {}",
            run.code(),
            run.signal(),
            run.stderr_text().trim()
        ));
        return problems;
    }
    let attempts: Vec<PathBuf> = std::fs::read_dir(data.join("attempts"))
        .map(|listing| listing.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    let [dir] = attempts.as_slice() else {
        problems.push(format!("{label}: expected one attempt, found {attempts:?}"));
        return problems;
    };
    let mut records = Vec::new();
    for name in ["jail-state.json", "policy.json", "jail.json"] {
        match parse(&dir.join(name)) {
            Ok(value) => records.push((name, value)),
            Err(problem) => problems.push(format!("{label}: {problem}")),
        }
    }
    if let Some(copy) = &run.receipt_path {
        match parse(copy) {
            Ok(Some(value)) => {
                if let Err(error) = common::check_receipt(&value) {
                    problems.push(format!("{label}: the --receipt copy is invalid: {error}"));
                }
            }
            Ok(None) => {}
            Err(problem) => problems.push(format!("{label}: {problem}")),
        }
    }
    let record = |name: &str| {
        records
            .iter()
            .find(|(record, _)| *record == name)
            .and_then(|(_, value)| value.clone())
    };
    let receipt = record("jail.json");
    if let Some(receipt) = &receipt {
        if let Err(error) = common::check_receipt(receipt) {
            problems.push(format!(
                "{label}: jail.json is not a valid receipt: {error}"
            ));
        }
        // S9: the seam in force is recorded wherever native details exist.
        if receipt["lifetime"]["native"].is_object()
            && receipt["lifetime"]["native"]["details"]["test_seams"]["abort_at"] != label.as_str()
        {
            problems.push(format!(
                "{label}: the receipt does not record the abort seam: {}",
                receipt["lifetime"]["native"]["details"]
            ));
        }
    }
    let phase = receipt
        .as_ref()
        .and_then(|receipt| receipt["phase"].as_str().map(str::to_owned));
    let expected = if point.published {
        site.phases.1
    } else {
        site.phases.0
    };
    if site.record == "jail.json" && phase.as_deref() != expected {
        problems.push(format!(
            "{label}: jail.json shows {phase:?}, a crash here leaves {expected:?}"
        ));
    }
    if let Some(claim) = record("jail-state.json")
        && claim["test_seams"]["abort_at"] != label.as_str()
    {
        problems.push(format!(
            "{label}: jail state does not record the abort seam"
        ));
    }
    // What the replaced record shows.
    let target_present = dir.join(site.record).exists();
    match site.name {
        "claim" | "policy" if target_present != point.published => problems.push(format!(
            "{label}: {} present={target_present}, a crash here leaves present={}",
            site.record, point.published
        )),
        "boundary" => {
            let registered =
                record("jail-state.json").is_some_and(|state| !state["boundary"].is_null());
            if registered != point.published {
                problems.push(format!(
                    "{label}: the boundary registered={registered}, a crash here leaves {}",
                    point.published
                ));
            }
        }
        "launch_state" => {
            let registered =
                record("jail-state.json").is_some_and(|state| !state["vendor_state"].is_null());
            if registered != point.published {
                problems.push(format!(
                    "{label}: vendor state registered={registered}, a crash here leaves {}",
                    point.published
                ));
            }
        }
        "cleanup_record" => {
            let cleanup = record("jail-state.json").map(|state| state["state_cleanup"].clone());
            let want = if point.published {
                "complete"
            } else {
                "pending"
            };
            if cleanup.as_ref().and_then(Value::as_str) != Some(want) {
                problems.push(format!(
                    "{label}: jail state says cleanup {cleanup:?}, a crash here leaves {want}"
                ));
            }
        }
        _ => {}
    }
    // The explicit incomplete state: the temporary files the crash left.
    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    let attempt = AttemptDir::new(&data, &AttemptId::parse(&name).expect("an attempt id"));
    let leftover = state::leftover_temp_files(&attempt).expect("the attempt lists");
    let ours = leftover
        .iter()
        .filter(|temp| temp.starts_with(&format!(".{}.", site.record)))
        .count();
    // The claim is published by `link`, so after it (at `renamed`) the
    // temporary name is a second link to the complete claim until it is
    // removed; every other site renames it away.
    let temp_left = point.temp_left || (site.name == "claim" && point.name == "renamed");
    if temp_left != (ours == 1) || leftover.len() != ours {
        problems.push(format!(
            "{label}: leftover temporary files {leftover:?}, a crash here leaves {} of `.{}.*.tmp`",
            u8::from(temp_left),
            site.record
        ));
    }
    eprintln!("{label}: phase {phase:?}, leftover {leftover:?}");
    // A following gc keeps every record.
    let present: Vec<&str> = [
        "jail-state.json",
        "policy.json",
        "jail.json",
        "trace.ndjson",
    ]
    .into_iter()
    .filter(|name| dir.join(name).exists())
    .collect();
    let gc = std::process::Command::new(harness::jail_path())
        .args(["gc", "--json"])
        .env("OURO_DATA_DIR", &data)
        .env("OURO_CONFIG_DIR", data.with_file_name("config"))
        .output()
        .expect("gc runs");
    if serde_json::from_slice::<Value>(&gc.stdout).is_err() {
        problems.push(format!(
            "{label}: gc printed no report: {}",
            String::from_utf8_lossy(&gc.stderr)
        ));
    }
    for name in present {
        if !dir.join(name).exists() {
            problems.push(format!("{label}: gc removed {name}"));
        }
        if name.ends_with(".json")
            && let Err(problem) = parse(&dir.join(name))
        {
            problems.push(format!("{label}: after gc, {problem}"));
        }
    }
    problems
}

#[test]
fn j4_r02_a_crash_at_each_replacement_leaves_a_valid_prior_file() {
    if !live() {
        return;
    }
    let mut problems = Vec::new();
    let mut cases = 0;
    for site in &SITES {
        for point in POINTS {
            cases += 1;
            problems.extend(crash(site, point));
        }
    }
    eprintln!("crash cases run: {cases}");
    assert!(
        problems.is_empty(),
        "{} problem(s) in {cases} crashes:\n{}",
        problems.len(),
        problems.join("\n")
    );
}
