//! {{name}} — an ouroboros capability, in the world `ouroboros:capability@0.1.0`.
//!
//! Build it:
//!
//! ```text
//! cargo build --release --target wasm32-wasip2
//! ```
//!
//! The component is `target/wasm32-wasip2/release/{{name_snake}}.wasm`. See README.md for what
//! to do with it.
//!
//! `#![no_std]` below is the one line of ceremony the SDK cannot own, and it is the one worth
//! keeping: `std` on this target imports thirteen `wasi:io`/`wasi:cli` interfaces the helper's
//! linker refuses, so a `std` build of this file would not instantiate at all. Everything else
//! — the allocator, the panic handler, the canonical ABI, the bindings — is behind
//! `export_capability!`.

#![no_std]

use ouroboros_guest::{export_capability, json, log, Capability, Describe, String, Value};

/// What one instance remembers between messages. It is created once by `init` and lives until
/// the host drops the instance.
struct {{Name}} {
    messages: u64,
}

impl Capability for {{Name}} {
    /// What this capability says about itself. Untrusted everywhere it is read — nothing above
    /// verifies a word of it — so write it to inform.
    fn describe() -> Describe {
        Describe::new("{{name}}", env!("CARGO_PKG_VERSION"))
            .summary("{{summary}}")
            .input_schema(json!({ "type": "object" }))
    }

    /// One instance, one config, once. Refuse here and the host is told at `instantiate`,
    /// which is the point in the lifecycle where it can still do something about it.
    fn init(_config: Value) -> Result<Self, String> {
        log("info", "{{name}} ready");
        Ok({{Name}} { messages: 0 })
    }

    /// One message in, one reply out. Never trap: a body you cannot use is an `Err(String)`,
    /// which the host records and which leaves this instance live.
    fn handle(&mut self, body: Value) -> Result<Value, String> {
        self.messages += 1;
        Ok(json!({ "echo": body, "messages": self.messages }))
    }
}

export_capability!({{Name}});
