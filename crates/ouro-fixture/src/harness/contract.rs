//! The contract every record a test reads through the harness is held to.
//!
//! The harness cannot name the product's frozen schemas: that would make this
//! crate depend on `ouro-jail`. The suite that can installs its checks once
//! per test binary with [`hold_records_to`] (`ouro-jail`'s `tests/common`
//! does it in `live()`). From then on every receipt, control transcript and
//! complete trace a [`Run`](super::Run) or [`Spawned`](super::Spawned) hands
//! out has passed them, and one that does not panics with the finding instead
//! of being returned.
//!
//! A binary that installed nothing cannot read a record at all: the accessor
//! panics rather than hand out something no rule was applied to. A suite
//! whose program is a stand-in that only imitates the product's records says
//! so with [`RecordContract::STAND_IN`]. The raw fields (`trace_readback`,
//! `trace_bytes`) stay unchecked: they exist for tests about a transcript
//! that is torn, cut short or otherwise not the product's whole record.

use std::sync::OnceLock;

use serde_json::Value;

/// One check per kind of record. Each returns every rule the record breaks.
#[derive(Clone, Copy)]
pub struct RecordContract {
    /// One receipt, as written (a `jail.json`, the `--receipt` copy).
    pub receipt: fn(&Value) -> Result<(), String>,
    /// One attempt's control messages, in order.
    pub control: fn(&[Value]) -> Result<(), String>,
    /// A complete trace (§13.3), with the attempt's final receipt when there
    /// is one.
    pub trace: fn(&[Value], Option<&Value>) -> Result<(), String>,
}

impl RecordContract {
    /// For a stand-in program whose records only imitate the product's
    /// (the harness's own tests): nothing is checked, and that is said
    /// rather than defaulted to.
    pub const STAND_IN: RecordContract = RecordContract {
        receipt: accept_receipt,
        control: accept_control,
        trace: accept_trace,
    };
}

fn accept_receipt(_: &Value) -> Result<(), String> {
    Ok(())
}

fn accept_control(_: &[Value]) -> Result<(), String> {
    Ok(())
}

fn accept_trace(_: &[Value], _: Option<&Value>) -> Result<(), String> {
    Ok(())
}

static CONTRACT: OnceLock<RecordContract> = OnceLock::new();

/// Install the contract for this process. The first call wins: one test
/// binary reads one product's records.
pub fn hold_records_to(contract: RecordContract) {
    let _ = CONTRACT.set(contract);
}

fn installed() -> &'static RecordContract {
    required(CONTRACT.get())
}

/// The contract, or the panic that says none was installed.
fn required(contract: Option<&RecordContract>) -> &RecordContract {
    contract.unwrap_or_else(|| {
        panic!(
            "no record contract is installed, so no record can be read: call \
             harness::hold_records_to first (ouro-jail's tests do it in common::live), \
             or pass RecordContract::STAND_IN for a program that is not the product"
        )
    })
}

/// Hold one receipt to the installed contract; panics with the finding.
pub(super) fn receipt(receipt: &Value) {
    receipt_under(installed(), receipt);
}

/// Hold a control transcript to the installed contract; panics with the
/// finding.
pub(super) fn control(messages: &[Value]) {
    control_under(installed(), messages);
}

/// Hold a complete trace to the installed contract; panics with the finding.
pub(super) fn trace(events: &[Value], final_receipt: Option<&Value>) {
    trace_under(installed(), events, final_receipt);
}

fn receipt_under(contract: &RecordContract, receipt: &Value) {
    if let Err(error) = (contract.receipt)(receipt) {
        panic!("a product receipt fails its contract: {error}\n{receipt:#}");
    }
}

fn control_under(contract: &RecordContract, messages: &[Value]) {
    if let Err(error) = (contract.control)(messages) {
        panic!(
            "a product control transcript fails its contract: {error}\n{:#}",
            Value::from(messages.to_vec())
        );
    }
}

fn trace_under(contract: &RecordContract, events: &[Value], final_receipt: Option<&Value>) {
    if let Err(error) = (contract.trace)(events, final_receipt) {
        panic!(
            "a product trace fails its contract: {error}\n{:#}",
            Value::from(events.to_vec())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refuse_receipt(_: &Value) -> Result<(), String> {
        Err("receipt rule".to_owned())
    }

    fn refuse_control(_: &[Value]) -> Result<(), String> {
        Err("control rule".to_owned())
    }

    fn refuse_trace(_: &[Value], _: Option<&Value>) -> Result<(), String> {
        Err("trace rule".to_owned())
    }

    const REFUSING: RecordContract = RecordContract {
        receipt: refuse_receipt,
        control: refuse_control,
        trace: refuse_trace,
    };

    fn panic_text(check: impl FnOnce() + std::panic::UnwindSafe) -> String {
        let payload = std::panic::catch_unwind(check).expect_err("the check must panic");
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default()
    }

    /// No contract is not a pass: a binary that forgot to install one reads
    /// nothing rather than reading unchecked records.
    #[test]
    fn without_a_contract_no_record_can_be_read() {
        let text = panic_text(|| {
            let _ = required(None);
        });
        assert!(text.contains("no record contract is installed"), "{text}");
    }

    /// Each kind of record reaches its own check, and a broken rule panics
    /// with the rule and the record.
    #[test]
    fn a_record_that_breaks_the_contract_panics_with_the_rule() {
        let record = serde_json::json!({"phase": "settled"});
        let text = panic_text(|| receipt_under(&REFUSING, &record));
        assert!(
            text.contains("receipt rule") && text.contains("settled"),
            "{text}"
        );
        let text = panic_text(|| control_under(&REFUSING, std::slice::from_ref(&record)));
        assert!(text.contains("control rule"), "{text}");
        let text = panic_text(|| trace_under(&REFUSING, &[], None));
        assert!(text.contains("trace rule"), "{text}");
    }

    #[test]
    fn the_stand_in_contract_accepts_anything_and_says_so_by_name() {
        let record = serde_json::json!({"not": "a receipt"});
        receipt_under(&RecordContract::STAND_IN, &record);
        control_under(&RecordContract::STAND_IN, std::slice::from_ref(&record));
        trace_under(
            &RecordContract::STAND_IN,
            std::slice::from_ref(&record),
            None,
        );
    }
}
