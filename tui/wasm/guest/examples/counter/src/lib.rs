//! A capability that counts, and says enough about itself to be usable without reading this
//! file.
//!
//! Build it:
//!
//! ```text
//! cargo build --release --target wasm32-wasip2
//! ```
//!
//! and `target/wasm32-wasip2/release/counter.wasm` is a component in
//! `ouroboros:capability@0.1.0` importing exactly `log`. `tui/wasm/tests/sdk.rs` builds this
//! file and asserts both facts against the real helper.
//!
//! # What it demonstrates
//!
//! * [`Capability`], the JSON seam: a `Value` in, a `Value` out, and `&mut self` for the state
//!   the instance keeps between messages. There is no static here and no `unsafe`; the SDK
//!   holds the value.
//! * A [`Describe`] carrying all three optional fields of contract C1 — a `summary`, an
//!   `input_schema` and one `example`. That document is what a reader (and W13's `agents.list`)
//!   is shown, and it is **untrusted**: nothing above verifies a word of it, so it is written
//!   to inform rather than to assert.
//! * Refusing input without trapping. A body whose `add` is not a non-negative integer is an
//!   `Err(String)` the host records as `guest_error`; the instance stays live and answers the
//!   next message.

#![no_std]

use ouroboros_guest::{export_capability, format, json, log, Capability, Describe, String, Value};

/// One instance's state. `count` is what the messages added; `messages` is how many there were,
/// which is the evidence that a second message reached the same instance.
struct Counter {
    step: u64,
    count: u64,
    messages: u64,
}

impl Capability for Counter {
    fn describe() -> Describe {
        Describe::new("counter", env!("CARGO_PKG_VERSION"))
            .summary("Counts. Send {\"add\": n} to add n, or {} to add the configured step.")
            .input_schema(json!({
                "type": "object",
                "properties": {
                    "add": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "How much to add. Defaults to the configured step."
                    }
                },
                "additionalProperties": false
            }))
            .example(json!({ "add": 2 }), json!({ "count": 2, "messages": 1 }))
    }

    /// `{"step": n}` sets what an `add`-less message adds; anything else leaves it at one. A
    /// config that is not an object is not an error — the host may reasonably start this with
    /// `{}` — but a `step` that is present and unusable is, because silently ignoring it would
    /// make a typo look like it worked.
    fn init(config: Value) -> Result<Self, String> {
        let step = match config.get("step") {
            None => 1,
            Some(value) => value
                .as_u64()
                .ok_or_else(|| format!("`step` must be a non-negative integer, got {value}"))?,
        };

        log("info", "counter ready");

        Ok(Counter {
            step,
            count: 0,
            messages: 0,
        })
    }

    fn handle(&mut self, body: Value) -> Result<Value, String> {
        let add = match body.get("add") {
            None => self.step,
            Some(value) => value
                .as_u64()
                .ok_or_else(|| format!("`add` must be a non-negative integer, got {value}"))?,
        };

        // Saturating rather than wrapping: a counter that answered a smaller number than the
        // one before it would be a worse answer than one that stopped moving, and neither is
        // worth a trap.
        self.count = self.count.saturating_add(add);
        self.messages += 1;

        Ok(json!({ "count": self.count, "messages": self.messages }))
    }
}

export_capability!(Counter);
