//! Candidate policy generation from one contained run. A child can manufacture
//! observations; proposals require operator review and never load implicitly.
use crate::{
    cli::{LearnArgs, RunArgs},
    journal,
    records::{Decision, Event, EventSource},
    supervisor::{self, Context},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// `fields.kind` of the observer's opt-in read-only open attempts, the events
/// a proposal's read grants come from.
pub const LEARNING_READ: &str = "learning_read";

/// The largest receipt read: the bound every receipt reader holds to.
/// Receipts are a few KiB; the bound only keeps a corrupt or hostile file
/// from being read whole.
const RECEIPT_MAX: u64 = crate::cleanup::RECEIPT_MAX;

/// The longest trace line: one event, which the trace never writes above
/// [`crate::trace::EVENT_MAX`] bytes, and its newline.
const FRAME_MAX: usize = crate::trace::EVENT_MAX + 1;

#[derive(Serialize, Debug)]
pub struct Proposal {
    pub schema: &'static str,
    pub warning: &'static str,
    pub read_only: Vec<String>,
    pub network_allow: Vec<String>,
    pub denied_writes: Vec<String>,
    pub unresolved_reads: Vec<String>,
    pub execs: Vec<String>,
    pub provenance: Provenance,
}
#[derive(Serialize, Debug)]
pub struct Provenance {
    pub attempt: String,
    pub receipt_digest: String,
    pub revision: String,
    pub build_inputs: String,
    pub event_counts: BTreeMap<String, u64>,
    pub coverage_json: String,
    pub evidence: BTreeMap<String, Vec<String>>,
}

pub fn derive(attempt: &Path, workspace: &Path, min_hits: u32) -> Result<Proposal, String> {
    let mut receipt_bytes = Vec::new();
    journal::open(attempt, "jail.json")
        .map_err(|e| e.to_string())?
        .take(RECEIPT_MAX + 1)
        .read_to_end(&mut receipt_bytes)
        .map_err(|e| e.to_string())?;
    if receipt_bytes.len() as u64 > RECEIPT_MAX {
        return Err("receipt exceeds size limit".into());
    }
    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_bytes).map_err(|e| e.to_string())?;
    let mut proposal = Proposal {
        schema: crate::records::SCHEMA_LEARNED_POLICY,
        warning: "Candidate grants from one untrusted run, not a statement of all program needs. Review every grant. Read paths are argument snapshots, not kernel-resolved identities.",
        read_only: Vec::new(),
        network_allow: Vec::new(),
        denied_writes: Vec::new(),
        unresolved_reads: Vec::new(),
        execs: Vec::new(),
        provenance: Provenance {
            attempt: receipt["attempt_id"]
                .as_str()
                .ok_or("receipt has no attempt")?
                .into(),
            receipt_digest: format!("sha256:{:x}", Sha256::digest(&receipt_bytes)),
            revision: option_env!("OURO_BUILD_REVISION")
                .unwrap_or("unknown")
                .into(),
            build_inputs: env!("OURO_BUILD_INPUTS").into(),
            event_counts: BTreeMap::new(),
            coverage_json: receipt["coverage"].to_string(),
            evidence: BTreeMap::new(),
        },
    };
    let mut reader =
        BufReader::new(journal::open(attempt, "trace.ndjson").map_err(|e| e.to_string())?);
    let mut reads = BTreeMap::<String, u32>::new();
    let mut hosts = BTreeMap::<String, u32>::new();
    loop {
        let mut line = Vec::new();
        let n = (&mut reader)
            .take(FRAME_MAX as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if !line.ends_with(b"\n") {
            return Err("incomplete or oversized journal frame".into());
        }
        if line.len() > FRAME_MAX {
            return Err("oversized journal frame".into());
        }
        let event: Event = serde_json::from_slice(&line).map_err(|e| e.to_string())?;
        if event.attempt_id != proposal.provenance.attempt {
            return Err("mixed attempt journal".into());
        }
        let op = event.operation.as_str();
        *proposal
            .provenance
            .event_counts
            .entry(op.into())
            .or_default() += 1;
        let fields = &event.fields;
        let field = |name: &str| fields.get(name).and_then(serde_json::Value::as_str);
        let source = serde_json::to_value(event.source)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "?".to_owned());
        let evidence = format!("{source}:{}", event.source_seq);
        if field("kind") == Some(LEARNING_READ)
            && matches!(field("errno"), Some("ENOENT" | "EACCES" | "EPERM"))
        {
            if let Some(path) = field("path") {
                let candidate = Path::new(path);
                if candidate.starts_with(workspace)
                    || path.starts_with("/tmp/")
                    || path.starts_with("/run/ouro/")
                {
                    continue;
                }
                let exact = exact_host_object(candidate);
                if exact
                    && candidate.is_absolute()
                    && !matches!(
                        path,
                        "/" | "/etc" | "/home" | "/Users" | "/proc" | "/sys" | "/dev"
                    )
                {
                    *reads.entry(path.into()).or_default() += 1;
                    proposal
                        .provenance
                        .evidence
                        .entry(path.into())
                        .or_default()
                        .push(evidence);
                } else {
                    proposal.unresolved_reads.push(path.into());
                }
            }
        } else if event.source == EventSource::Proxy
            && event.decision == Some(Decision::Deny)
            && matches!(
                field("reason"),
                Some("host_not_allowed" | "plaintext_not_granted")
            )
        {
            if let Some(destination) = field("destination")
                && let Ok(destination) = crate::network::parse_authority(destination, None)
            {
                let plaintext = field("kind") == Some("http")
                    || field("reason") == Some("plaintext_not_granted");
                let grant = proposed_grant(&destination, plaintext);
                *hosts.entry(grant.clone()).or_default() += 1;
                proposal
                    .provenance
                    .evidence
                    .entry(grant)
                    .or_default()
                    .push(evidence);
            }
        } else if (op == "fs.deny" && field("attempted_operation").is_some_and(|s| s.starts_with("fs.")))
            // The audit contract preserves EROFS under its original filesystem
            // operation. It is still a refused mutation for the learning report.
            || (op.starts_with("fs.")
                && event
                    .outcome
                    .as_ref()
                    .and_then(|outcome| outcome.errno.as_deref())
                    == Some("EROFS"))
        {
            // Plain paths report as themselves; digest snapshots and absent
            // fields keep their recorded JSON shape, never a quoted string.
            let path = fields.get("path").unwrap_or(&serde_json::Value::Null);
            proposal.denied_writes.push(match path.as_str() {
                Some(path) => path.to_owned(),
                None => path.to_string(),
            });
        } else if op == "proc.exec" {
            proposal
                .execs
                .push(serde_json::Value::Object(fields.clone()).to_string());
        }
    }
    proposal.read_only = reads
        .into_iter()
        .filter(|(_, n)| *n >= min_hits)
        .map(|(p, _)| p)
        .collect();
    proposal.network_allow = hosts
        .into_iter()
        .filter(|(_, n)| *n >= min_hits)
        .map(|(p, _)| p)
        .collect();
    proposal.unresolved_reads.sort();
    proposal.unresolved_reads.dedup();
    Ok(proposal)
}

/// The host grant a refused proxy request asks for, and no more.
///
/// An explicit port admits plaintext HTTP to it (network-rules.md, L21), so
/// a destination is proposed with its port written out only when the run
/// was seen sending plaintext there: an absolute-form `http://` request, or
/// a tunnel the proxy refused for an HTTP first flight. A tunnel to port 443
/// is proposed as the bare host, the TLS-only shape; a tunnel to any other
/// port can only be granted with that port.
fn proposed_grant(destination: &crate::network::Destination, plaintext: bool) -> String {
    if plaintext || destination.port != 443 {
        destination.to_string()
    } else {
        destination.host.to_string()
    }
}

// A bounded metadata-only walk: no symlink traversal, device opens or content
// reads. This establishes a candidate at lookup time, not a durable grant.
fn exact_host_object(path: &Path) -> bool {
    use crate::state::anchored::{Dir, Kind, split_absolute};
    // Proposals must not suggest authority the boundary will always refuse;
    // the Linux platform's refusal reads the real mount topology.
    #[cfg(target_os = "linux")]
    if crate::platform::linux::platform::refuse_pseudo_fs_grants(
        &[(path.to_path_buf(), path.to_path_buf())],
        "filesystem.read_only",
    )
    .is_err()
    {
        return false;
    }
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.len() > 4096 {
        return false;
    }
    let Ok(parts) = split_absolute(bytes) else {
        return false;
    };
    let Some((last, parents)) = parts.split_last() else {
        return false;
    };
    if parts.len() > 256 {
        return false;
    }
    let Ok(mut dir) = Dir::open_root_for_walk() else {
        return false;
    };
    for component in parents {
        let Ok(next) = dir.open_walk_at(component, None) else {
            return false;
        };
        dir = next;
    }
    dir.stat_at(last)
        .is_ok_and(|s| matches!(s.kind, Kind::Regular | Kind::Directory))
}

pub fn run(ctx: &Context, mut args: LearnArgs) -> Result<i32, String> {
    if args.policy.observe == Some(crate::cli::Observe::Off)
        || args.policy.evidence == Some(crate::cli::Evidence::BestEffort)
    {
        return Err("learn requires --observe on and strict evidence".into());
    }
    if args.adopt && !std::io::stdin().is_terminal() {
        return Err("--adopt requires an interactive terminal".into());
    }
    args.policy.observe = Some(crate::cli::Observe::On);
    args.policy.evidence = Some(crate::cli::Evidence::Strict);
    let plan = supervisor::resolve_learning_plan(ctx, &args.policy).map_err(|e| e.message)?;
    let run = RunArgs {
        policy: args.policy,
        argv: args.argv,
        receipt: None,
        trace_fd: None,
        control_fd: None,
        gate_fd: None,
        attempt_id: None,
        label_only: false,
    };
    let report = supervisor::run_learning(ctx, &run);
    let receipt_path = report
        .receipt_path
        .as_ref()
        .ok_or("no receipt; no proposal can be justified")?;
    let attempt = receipt_path.parent().ok_or("invalid attempt path")?;
    let proposal = derive(attempt, &plan.workspace, args.min_hits)?;
    let out = args.out.unwrap_or_else(|| {
        plan.config_dir
            .join("learned")
            .join(format!("{}.toml", proposal.provenance.attempt))
    });
    if let Some(parent) = out.parent() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| e.to_string())?;
    }
    let text = toml::to_string_pretty(&proposal).map_err(|e| e.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&out)
        .map_err(|e| e.to_string())?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())?;
    crate::diag!(
        "candidate policy: {} ({} exact paths, {} destinations)",
        out.display(),
        proposal.read_only.len(),
        proposal.network_allow.len()
    );
    if args.adopt {
        if report.error.is_some() {
            return Err("run ended with a jail error; proposal retained without adoption".into());
        }
        adopt(&plan.config_dir.join("config.toml"), &proposal)?;
    }
    if let Some(error) = report.error {
        crate::diag!("learning run: {}", error.message);
    }
    Ok(report.exit_code)
}

fn adopt(path: &Path, proposal: &Proposal) -> Result<(), String> {
    let old = supervisor::read_operator_file(path, "learn.adopt")
        .map_err(|e| e.message)?
        .unwrap_or_default();
    crate::config::parse_operator_config(&old).map_err(|e| e.message)?;
    let mut document: toml_edit::DocumentMut = old
        .parse()
        .map_err(|e: toml_edit::TomlError| e.to_string())?;
    if document.get("jail").is_none() {
        document["jail"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    for (section, key, additions) in [
        ("filesystem", "read_only", &proposal.read_only),
        ("network", "allow", &proposal.network_allow),
    ] {
        if additions.is_empty() {
            continue;
        }
        if document["jail"].get(section).is_none() {
            document["jail"][section] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        if document["jail"][section].get(key).is_none() {
            document["jail"][section][key] = toml_edit::value(toml_edit::Array::new());
        }
        let array = document["jail"][section][key]
            .as_array_mut()
            .ok_or("existing grants are not an array")?;
        for value in additions {
            if !array.iter().any(|item| item.as_str() == Some(value)) {
                array.push(value);
            }
        }
    }
    let new = format!(
        "# adopted from attempt {} (receipt {})\n{}",
        proposal.provenance.attempt, proposal.provenance.receipt_digest, document
    );
    crate::config::parse_operator_config(&new).map_err(|e| e.message)?;
    // Review the exact replacement, including any TOML formatting changes.
    eprintln!(
        "{}\nReplace {} with the text above? Type yes:",
        crate::records::escape_control(&new),
        path.display()
    );
    let mut reply = String::new();
    std::io::stdin()
        .read_line(&mut reply)
        .map_err(|e| e.to_string())?;
    if reply.trim() != "yes" {
        return Err("adoption cancelled; proposal retained".into());
    }
    let current = supervisor::read_operator_file(path, "learn.adopt")
        .map_err(|e| e.message)?
        .unwrap_or_default();
    if current != old {
        return Err("configuration changed during review; refusing to overwrite".into());
    }
    crate::state::replace_atomically(path, new.as_bytes()).map_err(|e| e.message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::symlink;

    /// One trace line: a complete `ouro.event/1` wrapper note with `fields`.
    fn note(seq: u64, fields: serde_json::Value) -> String {
        let mut event =
            Event::lifecycle_note("fixture", seq, std::time::SystemTime::UNIX_EPOCH, 0, "x");
        event.fields = fields.as_object().expect("an object").clone();
        format!("{}\n", serde_json::to_string(&event).expect("serializes"))
    }

    #[test]
    fn proposals_are_exact_filtered_and_receipt_bound() {
        let temp = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let root = temp.path().canonicalize().unwrap();
        let attempt = root.join("attempt");
        let workspace = root.join("work");
        std::fs::create_dir(&attempt).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        let object = root.join("needed");
        std::fs::write(&object, b"fixture").unwrap();
        let alias = root.join("alias");
        symlink(&object, &alias).unwrap();
        assert!(exact_host_object(&object));
        assert!(!exact_host_object(&alias));
        assert!(!exact_host_object(Path::new(
            "/sys/devices/system/cpu/online"
        )));
        assert!(!exact_host_object(Path::new("/proc/version")));
        assert!(!exact_host_object(&root.join("missing")));
        symlink(&root, root.join("indirect")).unwrap();
        assert!(!exact_host_object(&root.join("indirect/needed")));
        let receipt = br#"{"attempt_id":"fixture","coverage":{"exec":{"status":"active"}}}"#;
        std::fs::write(attempt.join("jail.json"), receipt).unwrap();
        let events = [
            json!({"kind":LEARNING_READ, "errno":"ENOENT", "path":object}),
            json!({"kind":LEARNING_READ, "errno":"ENOENT", "path":object}),
            json!({"kind":LEARNING_READ, "errno":"EPERM", "path":alias}),
            json!({"kind":LEARNING_READ, "errno":"ENOENT", "path":workspace}),
        ];
        let mut journal = String::new();
        for (seq, fields) in (1..).zip(events) {
            journal.push_str(&note(seq, fields));
        }
        std::fs::write(attempt.join("trace.ndjson"), &journal).unwrap();
        let proposal = derive(&attempt, &workspace, 2).unwrap();
        assert_eq!(proposal.read_only, vec![object.to_string_lossy()]);
        assert_eq!(proposal.unresolved_reads, vec![alias.to_string_lossy()]);
        assert!(proposal.denied_writes.is_empty());
        assert_eq!(
            proposal.provenance.receipt_digest,
            format!("sha256:{:x}", Sha256::digest(receipt))
        );
        assert_eq!(
            proposal.provenance.evidence[object.to_str().unwrap()],
            ["wrapper:1", "wrapper:2"]
        );
        assert!(
            derive(&attempt, &workspace, 3)
                .unwrap()
                .read_only
                .is_empty()
        );
        journal.pop();
        std::fs::write(attempt.join("trace.ndjson"), journal).unwrap();
        assert!(
            derive(&attempt, &workspace, 1)
                .unwrap_err()
                .contains("incomplete")
        );
    }

    /// The trace holds `ouro.event/1` events and nothing else, so a line that
    /// is not one (here: no schema, time or stage) is a corrupt journal, not
    /// evidence to read loosely; and a line longer than any event the trace
    /// writes is refused before it is parsed.
    #[test]
    fn a_trace_line_that_is_not_an_event_refuses() {
        let temp = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let attempt = temp.path().canonicalize().unwrap();
        std::fs::write(attempt.join("jail.json"), br#"{"attempt_id":"fixture"}"#).unwrap();
        let loose = json!({"attempt_id": "fixture", "operation": "note", "source": "wrapper",
            "source_seq": 1, "fields": {"kind": LEARNING_READ, "errno": "ENOENT", "path": "/x"}});
        std::fs::write(attempt.join("trace.ndjson"), format!("{loose}\n")).unwrap();
        assert!(derive(&attempt, &attempt, 1).is_err());
        // An event the trace would have refused to write: past EVENT_MAX.
        let long = note(
            1,
            json!({"kind": "lifecycle", "pad": "x".repeat(crate::trace::EVENT_MAX)}),
        );
        std::fs::write(attempt.join("trace.ndjson"), long).unwrap();
        assert!(
            derive(&attempt, &attempt, 1)
                .unwrap_err()
                .contains("oversized")
        );
        std::fs::write(
            attempt.join("trace.ndjson"),
            note(1, json!({"kind": "lifecycle"})),
        )
        .unwrap();
        assert!(derive(&attempt, &attempt, 1).is_ok());
    }

    /// The receipt is held to the bound every other receipt reader uses, so
    /// a receipt cleanup or `gc` would refuse as oversized is not evidence
    /// here either.
    #[test]
    fn the_receipt_bound_is_every_readers_bound() {
        let temp = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let attempt = temp.path().canonicalize().unwrap();
        std::fs::write(attempt.join("trace.ndjson"), b"").unwrap();
        let max = usize::try_from(crate::cleanup::RECEIPT_MAX).unwrap();
        let receipt = |size: usize| {
            let mut bytes = br#"{"attempt_id":"fixture"}"#.to_vec();
            bytes.resize(size, b' ');
            bytes
        };
        std::fs::write(attempt.join("jail.json"), receipt(max)).unwrap();
        assert!(derive(&attempt, &attempt, 1).is_ok());
        std::fs::write(attempt.join("jail.json"), receipt(max + 1)).unwrap();
        assert!(
            derive(&attempt, &attempt, 1)
                .unwrap_err()
                .contains("exceeds size limit")
        );
    }

    /// L1: the refusal list for learning roots (`/`, `/etc`, `/home`,
    /// `/Users`, `/proc`, `/sys`, `/dev`) must not be emptiable: a read of
    /// such a root is recorded as unresolved, never proposed as a grant.
    #[test]
    fn reads_of_refusal_roots_are_never_proposed() {
        let temp = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let root = temp.path().canonicalize().unwrap();
        let attempt = root.join("attempt");
        let workspace = root.join("work");
        std::fs::create_dir(&attempt).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(attempt.join("jail.json"), br#"{"attempt_id":"fixture"}"#).unwrap();
        let mut journal = String::new();
        for (seq, path) in (1..).zip(["/etc", "/"]) {
            journal.push_str(&note(
                seq,
                json!({"kind": LEARNING_READ, "errno": "EACCES", "path": path}),
            ));
        }
        std::fs::write(attempt.join("trace.ndjson"), &journal).unwrap();
        let proposal = derive(&attempt, &workspace, 1).unwrap();
        assert!(
            proposal.read_only.is_empty(),
            "no refusal root is proposed: {:?}",
            proposal.read_only
        );
        for path in ["/etc", "/"] {
            assert!(
                proposal.unresolved_reads.iter().any(|read| read == path),
                "`{path}` must be unresolved: {:?}",
                proposal.unresolved_reads
            );
        }
    }
}
