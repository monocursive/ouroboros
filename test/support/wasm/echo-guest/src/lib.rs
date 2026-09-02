//! The lane-W acceptance guest: a capability component in `ouroboros:capability@0.1.0`.
//!
//! `tui/wasm/tests/support/mod.rs` writes its guests as WAT and assembles them in-process, so
//! the helper's containment proofs need no wasm toolchain at all. This one is the other half
//! of that story: a guest built the way a real capability author would build one —
//! `ouroboros-guest` against the checked-in world, `cargo build --release --target
//! wasm32-wasip2` — so that the world file, the helper's hard-coded `world.rs`, and an actual
//! toolchain's idea of the canonical ABI are proved to agree rather than assumed to.
//!
//! Since W9 it is also the proof that the SDK's ceremony is the right ceremony: the two
//! hundred lines this file used to carry — `no_std`'s allocator, panic handler,
//! `cabi_realloc`, `memcmp`, the `wit_bindgen::generate!` and the state cell — moved into
//! `tui/wasm/guest`, and the acceptance suite that reads this component is what says the move
//! kept the import list at exactly `log`.
//!
//! # Why `no_std`
//!
//! Because the import list is the security claim. `std` on `wasm32-wasip2` brings thirteen
//! `wasi:io`/`wasi:cli` interfaces beside `log`, the helper's linker defines none of them, and
//! such a build refuses to instantiate with `inspect` reporting `world: "unknown"`. The
//! mechanism and the full list are in `ouroboros_guest`'s module documentation; what is left
//! here is the one line that cannot be delegated — `#![no_std]` is the claim, so the author
//! states it — and one macro call that emits the rest.
//!
//! # Why `Raw` and not `Capability`
//!
//! Because this fixture's job includes stating a reply **verbatim**. The hook lane
//! (docs/WASM.md §8.1) drives this same world: a hook component's reply *is* the stdout
//! contract `Hooks.parse_output/1` reads and a `[checks]` reply is plain text injected into a
//! turn, so a test guest has to be able to hand back an arbitrary string — including one that
//! is not JSON at all. `Capability` re-encodes its answer as a JSON document, which is the
//! right seam for a capability and the wrong one for a fixture that has to be able to say
//! anything.
//!
//! # What it does
//!
//! `init` keeps the host's config, `handle-message` answers with the body it was handed, the
//! config it was started with, and how many messages it has seen. The count is the evidence
//! that state is instance-held: a second message answers `"n": 2`, and it can only do that if
//! the same instance answered both.
//!
//! # What it must never do
//!
//! Trap. Every failure this guest can have — a body that is not JSON, a config that is not
//! JSON, a message before `init` — is an `err(string)`, which the host records as a
//! `guest_error` and which leaves the instance live. A trap is a different fact about a
//! component, and this one must not manufacture it.
//!
//! # The one behaviour W9 changed
//!
//! Before the SDK, this file logged `handle-message` and *then* checked whether `init` had
//! run, so a message that arrived before `init` still produced a log line. The SDK refuses
//! first: `handle` below is not called at all until there is an instance, so that line is now
//! only emitted for a message this guest actually answers. Nothing observes the difference —
//! the pre-`init` path is unreachable through the helper's protocol, since `call` on an
//! instance that was never stood up is `unknown_instance` — but it is a difference, and this
//! guest's whole job is to be the thing nobody has to guess about.
//!
//! # Authority
//!
//! One import: `log`. The world declares no clock, no randomness, no filesystem and no
//! socket, and an import the helper's linker does not define fails instantiation — so this
//! file's authority is legible from its first line, and `inspect` reports it.

#![no_std]

use ouroboros_guest::{
    body_json, config_json, export_raw, json, log, Describe, Raw, String, ToString, Value,
};

/// What one instance remembers between messages. The SDK holds it; there is no static here.
struct Echo {
    config: Value,
    messages: u64,
}

impl Raw for Echo {
    fn describe() -> Describe {
        Describe::new("ouroboros-echo-guest", env!("CARGO_PKG_VERSION"))
    }

    /// One instance, one config. A config that is not JSON is refused here rather than carried
    /// to the first message: the host is told at instantiate, which is the point in the
    /// lifecycle where it can still do something about it.
    fn init(config: &str) -> Result<Self, String> {
        Ok(Echo {
            config: config_json(config)?,
            messages: 0,
        })
    }

    /// One message in, one JSON reply out — the body echoed, the config this instance was
    /// started with, and the running count.
    fn handle(&mut self, body: &str) -> Result<String, String> {
        // Exactly once per message, and before anything that can fail: the line is the
        // evidence that the one import in this world reaches the daemon, and a refused
        // message must not be the reason it is missing.
        log("info", "handle-message");

        // A config carrying a string `reply` is the answer, exactly, for every message — the
        // verbatim seam the hook lane needs, and the reason this guest implements `Raw`. No
        // capability test sets it, so every other test on this guest is unaffected, and the
        // authority is unchanged: a string in the config was already the host's to choose.
        if let Some(Value::String(reply)) = self.config.get("reply") {
            self.messages += 1;
            return Ok(reply.clone());
        }

        let body = body_json(body)?;

        self.messages += 1;

        Ok(json!({
            "echo": body,
            "config": self.config,
            "n": self.messages,
        })
        .to_string())
    }
}

export_raw!(Echo);
