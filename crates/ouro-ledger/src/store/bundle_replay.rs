//! Read-only replay of a bounded, reassembled canonical snapshot.
use super::*;

pub(crate) fn replay(reader: impl std::io::Read, run_id: &str) -> Result<RunRecord> {
    check_run_id(run_id)?;
    let mut stream = Stream::empty(run_id);
    let mut reader = BufReader::new(reader);
    loop {
        use std::io::Read as _;
        let mut bytes = Vec::new();
        let length = reader
            .by_ref()
            .take((MAX_FRAME_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)?;
        if length == 0 {
            break;
        }
        if length > MAX_FRAME_BYTES || bytes.pop() != Some(b'\n') {
            return Err(LedgerError("oversized or interrupted bundle record".into()));
        }
        if stream.run.chain.head_seq >= crate::bundle::MAX_RECORDS
            || stream.accepted_bytes + length as u64 > crate::bundle::MAX_STREAM_BYTES
        {
            return Err(LedgerError(
                "bundle snapshot exceeds its record or byte bound".into(),
            ));
        }
        stream.accept_canonical(run_id, &bytes)?;
    }
    if stream.run.chain.head_seq == 0 {
        return Err(LedgerError("bundle snapshot is empty".into()));
    }
    Ok(stream.run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotated_records_bundle_after_capture_expiry_but_pruned_history_refuses() {
        use super::super::tests::{gc_fixture, gc_future};
        let (temp, mut store, run) = gc_fixture();
        let directory = store.root.join(&run.run_id);
        let names = manifest::names(&directory).unwrap();
        assert!(names.len() > 1);
        let original: Vec<_> = names
            .iter()
            .flat_map(|n| fs::read(directory.join(n)).unwrap())
            .collect();
        let peer = Peer {
            uid: unsafe { libc::geteuid() },
            pid: std::process::id(),
            birth: "bundle-gc".into(),
            boot_id: "bundle-gc".into(),
        };
        let policy = ouro_records::retention::RetentionPolicy {
            retain_days: 90,
            capture_retain_days: 1,
        };
        let result = store
            .gc_policy_at(policy, None, 100, &peer, gc_future())
            .unwrap();
        assert_eq!(result.captures_pruned.len(), 1);
        let data = temp.path().join("data");
        let output = temp.path().join("portable");
        crate::bundle::create_with_reader(&data, &run.run_id, &output, &[], |q| store.read(q))
            .unwrap();
        assert_eq!(fs::read(output.join("events.ndjson")).unwrap(), original);
        assert!(crate::bundle::verify(&output).is_ok());
        assert!(
            crate::bundle::create_with_reader(
                &data,
                &run.run_id,
                &temp.path().join("missing-capture"),
                &["stdout".into()],
                |q| store.read(q)
            )
            .is_err()
        );
        let result = store.gc_at(1, None, 100, &peer, gc_future()).unwrap();
        assert_eq!(result.pruned.len(), 1);
        assert!(
            crate::bundle::create_with_reader(
                &data,
                &run.run_id,
                &temp.path().join("pruned"),
                &[],
                |q| store.read(q)
            )
            .is_err()
        );
        assert!(crate::bundle::verify(&output).is_ok());
    }
}
