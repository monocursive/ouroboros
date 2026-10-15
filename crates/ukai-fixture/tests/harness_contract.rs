//! Every harness accessor that hands out a product record applies the
//! installed record contract.
//!
//! This binary installs a contract that refuses every record, then reads one
//! run of `stand-in-jail` through each accessor. Each read must panic with
//! the refusing rule: an accessor that hands the record back instead has
//! lost its wiring to the contract, and every live test that reads through
//! it would pass over a record that breaks its schema or its semantic rules.
//! The contract's own checks are proved in `harness/contract.rs`; what the
//! product's contract refuses is proved in `ukai-jail`'s `portable_records`.

use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};

use serde_json::Value;
use ukai_fixture::harness::{self, Jail, RecordContract};

fn refuse_receipt(_: &Value) -> Result<(), String> {
    Err("refusing receipt rule".to_owned())
}

fn refuse_control(_: &[Value]) -> Result<(), String> {
    Err("refusing control rule".to_owned())
}

fn refuse_trace(_: &[Value], _: Option<&Value>) -> Result<(), String> {
    Err("refusing trace rule".to_owned())
}

const REFUSING: RecordContract = RecordContract {
    receipt: refuse_receipt,
    control: refuse_control,
    trace: refuse_trace,
};

/// The stand-in's attempt id (its default).
const ATTEMPT: &str = "att_00000000-0000-4000-8000-000000000001";

/// `read` must panic with `rule`: the contract refused what it was about to
/// hand out.
fn refused(what: &str, rule: &str, read: impl FnOnce()) {
    let payload = std::panic::catch_unwind(AssertUnwindSafe(read))
        .err()
        .unwrap_or_else(|| {
            panic!("{what} handed out a record without applying the installed contract")
        });
    let text = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default();
    assert!(
        text.contains(rule),
        "{what} panicked, but not with the contract's {rule:?}: {text}"
    );
}

#[test]
fn every_accessor_applies_the_installed_contract_to_what_it_hands_out() {
    harness::hold_records_to(REFUSING);
    let mut spawned = Jail::with_program(env!("CARGO_BIN_EXE_stand-in-jail"))
        .unwrap()
        .control()
        .gate()
        .trace()
        .receipt()
        .spawn()
        .expect("the stand-in starts");

    // While the attempt is gated: the `--receipt` copy, then the owner's
    // first control message.
    let copy = spawned.root().join("receipt.json");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !copy.exists() {
        assert!(Instant::now() < deadline, "the stand-in wrote no receipt");
        std::thread::sleep(Duration::from_millis(10));
    }
    refused("Spawned::receipt_value", "refusing receipt rule", || {
        let _ = spawned.receipt_value();
    });
    refused("GateOwner::await_prepared", "refusing control rule", || {
        let _ = spawned.owner().await_prepared();
    });
    // Closed with nothing written: the stand-in refuses, which leaves a
    // refused receipt, its control message and its trace note.
    spawned.owner().withhold();
    let run = spawned.wait().expect("the stand-in exits");
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());

    refused("Run::receipts", "refusing receipt rule", || {
        let _ = run.receipts();
    });
    refused("Run::receipt_phase", "refusing receipt rule", || {
        let _ = run.receipt_phase("refused");
    });
    refused("Run::control_messages", "refusing control rule", || {
        let _ = run.control_messages();
    });
    refused("Run::control_kind", "refusing control rule", || {
        let _ = run.control_kind("refused");
    });
    refused("Run::trace_events", "refusing trace rule", || {
        let _ = run.trace_events();
    });

    // The same whole trace, kept locally beside the attempt's `jail.json`
    // as the product keeps it.
    let attempt = run.data_dir.join("attempts").join(ATTEMPT);
    assert!(
        attempt.join("jail.json").is_file(),
        "the stand-in wrote no jail.json"
    );
    std::fs::write(attempt.join("trace.ndjson"), &run.trace_bytes).unwrap();
    refused("Run::local_traces", "refusing trace rule", || {
        let _ = run.local_traces();
    });
}
