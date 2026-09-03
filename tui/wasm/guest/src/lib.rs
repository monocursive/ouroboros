//! Write an `ouroboros:capability@0.1.0` component without writing the ceremony.
//!
//! A capability, a hook or a `[checks]` entry is the same artifact: a WebAssembly component in
//! the one world `ouro-wasm` speaks (docs/WASM.md §7.1). Before this crate existed, the only
//! worked example of one was `test/support/wasm/echo-guest`, and an author had to reproduce
//! about two hundred lines of it — `no_std`, an allocator, a panic handler, the canonical
//! ABI's `cabi_realloc`, a `memcmp`, a `wit_bindgen::generate!` and a hand-rolled state cell —
//! before the first line of their own logic, with one wrong feature flag enough to make the
//! helper report `world: "unknown"`. This crate owns all of it, once.
//!
//! What an author writes instead:
//!
//! ```ignore
//! #![no_std]
//!
//! use ouroboros_guest::{export_capability, json, Capability, Describe, Value};
//!
//! struct Counter(u64);
//!
//! impl Capability for Counter {
//!     fn describe() -> Describe {
//!         Describe::new("counter", "0.1.0").summary("Counts.")
//!     }
//!
//!     fn init(_config: Value) -> Result<Self, ouroboros_guest::String> {
//!         Ok(Counter(0))
//!     }
//!
//!     fn handle(&mut self, _body: Value) -> Result<Value, ouroboros_guest::String> {
//!         self.0 += 1;
//!         Ok(json!({ "count": self.0 }))
//!     }
//! }
//!
//! export_capability!(Counter);
//! ```
//!
//! # What this crate does not do
//!
//! It changes nothing the helper enforces. Containment is the linker (D5): the world declares
//! one import, `ouro-wasm` defines exactly that one, and an import the linker does not define
//! fails instantiation whatever an SDK generated. Nothing here can loosen that and nothing
//! here should be read as having tightened it either — this is the ergonomics of writing a
//! component, and the boundary is somewhere else entirely.
//!
//! What it *is* is the file every author copies, so its defaults are the ecosystem's posture:
//! `panic = "abort"`, LTO, `opt-level = "s"`, no `std`, and no dependency that pulls WASI. The
//! examples and the scaffold template repeat that profile verbatim, and the acceptance guest
//! is the standing proof that a build on this SDK keeps the import list at exactly `log`.
//!
//! # Why `no_std`, restated because it is the security claim
//!
//! The import list is what a reviewer reads and what the signer records. `std` on
//! `wasm32-wasip2` is not silent about being there: the same source built against it — even
//! with `panic = "abort"`, LTO and `opt-level = "s"` — imports thirteen interfaces beside
//! `log`, `wasi:io/{poll,error,streams}` and `wasi:cli/{environment,exit,stdin,stdout,stderr}`
//! plus the five `terminal-*` handles. They arrive with `std`'s stdio, environment and
//! process-exit machinery, they survive `--gc-sections` because the default panic path reaches
//! them, and the helper's linker defines none of them — so such a build refuses to instantiate
//! and `inspect` reports `world: "unknown"`. Dropping `std` drops all thirteen. What replaces
//! it is small and named, and it is what [`ceremony!`] emits: `alloc`, one allocator (the one
//! `std` itself uses on wasm), a panic handler, and the canonical ABI's `cabi_realloc`.
//!
//! An author's crate must therefore still say `#![no_std]` for itself. That one line is not
//! ceremony this crate can absorb — it is the claim — and it is the only line of it left.
//!
//! # The four seams, over two worlds
//!
//! | trait | for | the reply it produces |
//! |---|---|---|
//! | [`Capability`] | a mesh capability, [`export_capability!`] | one JSON document |
//! | [`Hook`] | a `[[hooks]]` entry, [`export_hook!`] | the stdout contract `hooks.ex` reads |
//! | [`Check`] | a `[checks]` entry, [`export_check!`] | empty for a pass, the failure text otherwise |
//! | [`Policy`] | the permission engine, [`export_policy!`] | `{"decision": …, "rule": …}` |
//!
//! [`Raw`] is underneath the first three: strings in, strings out, exactly the capability
//! world's exports. Use it when a reply must be stated verbatim rather than as JSON — which is
//! what the acceptance guest needs, and what a `[checks]` failure is.
//!
//! The first three are all [`WORLD`]; [`Policy`] is [`POLICY_WORLD`], a **second** world with
//! the same single import and a different message export (`evaluate` rather than
//! `handle-message`). One crate, two `wit_bindgen::generate!` invocations, and the `export_*`
//! macro an author calls is what decides which world the finished component implements — a
//! component cannot claim both, and `ouro-wasm` refuses one offered as the other
//! (docs/WASM.md D21).
//!
//! # What a guest must never do
//!
//! Trap. Every failure this crate can have — a body that is not JSON, a config that is not
//! JSON, a message before `init`, a re-entrant call — is an `Err(String)`, which the host
//! records as a `guest_error` and which leaves the instance live. A trap is a different fact
//! about a component, and an SDK must not manufacture it on the author's behalf. The only
//! trap [`ceremony!`] installs is the panic handler, because a panic is already a bug.

// `no_std` for every build that becomes a component, and `std` for `cargo test` alone — the
// test harness is `std`, and the alternative to this line is a wire contract (`Describe`'s
// document, `Verdict`'s reply) that can only be checked by building a component and standing a
// helper up in front of it. `make wasm-sdk-check` runs those tests on the host; the wasm32
// build they are testing never takes this branch, and `tui/wasm/tests/sdk.rs` is what proves
// that build imports exactly `log`.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod capability;
mod describe;
mod hook;
mod raw;

#[doc(hidden)]
pub mod __rt;
pub mod bindings;
pub mod policy;
pub mod policy_bindings;

pub use capability::Capability;
pub use describe::{Describe, Example, MAX_EXAMPLES, MAX_SUMMARY_CHARS};
pub use hook::{Check, CheckOutcome, Hook, HookInput, Verdict};
pub use policy::Policy;
/// A policy's answer. Named `PolicyVerdict` at the crate root because [`Verdict`] was already
/// taken by the hook contract's, which is a different document for a different reader; its own
/// module spells it [`policy::Verdict`], which is what an author who writes
/// `use ouroboros_guest::policy::*` gets.
pub use policy::Verdict as PolicyVerdict;
pub use policy::MAX_RULE_CHARS;
pub use raw::Raw;

/// `String` and `Vec` without an `extern crate alloc` in the author's crate. A guest that
/// needs more of `alloc` than this can still declare it for itself; these are what the traits
/// above put in every signature.
pub use alloc::string::{String, ToString};
pub use alloc::vec::Vec;
pub use alloc::{format, vec};

/// JSON, re-exported so a guest needs exactly one dependency. `serde_json` is what the world's
/// contract is written in — JSON in, JSON out — and an author who has this crate has it.
pub use serde_json::{json, Map, Value};

/// The whole of `serde_json`, for the corners the re-exports above do not cover.
pub use serde_json;

/// The capability world this crate binds against, and the string `describe` reports as its
/// `world` for [`Capability`], [`Hook`], [`Check`] and [`Raw`].
///
/// Version-bearing on purpose: a v2 world is a different string, never a quietly wider v1.
/// [`Describe`] fills this in itself, so a guest cannot claim a world it was not built for —
/// which is a convenience, not an assurance. `inspect` reads the component's own type, and
/// that is what the helper and the signer believe.
pub const WORLD: &str = "ouroboros:capability@0.1.0";

/// The policy world, and what a [`Policy`]'s `describe` reports. A different package, not a
/// wider capability: the two share an import list and nothing else.
pub const POLICY_WORLD: &str = "ouroboros:policy@0.1.0";

/// A line into the daemon's log — the one import in this world, and a guest's whole reach.
///
/// `level` is the string the helper prefixes the line with; `"debug"`, `"info"`, `"warn"` and
/// `"error"` are what the daemon's logger understands. The helper bounds how many of these one
/// call may emit and how long each may be, so a chatty guest is throttled rather than
/// believed; see [`log!`] for the formatting form.
///
/// A component that never calls this has no imports at all, which is still in the world — but
/// then `inspect` reports `imports: []` rather than `["log"]`, and the import list is what a
/// reviewer reads. Every example in this crate logs at least once for that reason.
pub fn log(level: &str, message: &str) {
    bindings::log(level, message);
}

/// The host's config string, parsed. The error text is the one the acceptance guest has always
/// answered, so an operator reading a `guest_error` sees the same sentence whichever guest
/// produced it.
///
/// The JSON traits call this for you; it is public for [`Raw`] implementations.
pub fn config_json(config: &str) -> Result<Value, String> {
    serde_json::from_str(config).map_err(|error| alloc::format!("config is not JSON: {error}"))
}

/// A message body, parsed. As [`config_json`], for `handle-message`.
pub fn body_json(body: &str) -> Result<Value, String> {
    serde_json::from_str(body).map_err(|error| alloc::format!("body is not JSON: {error}"))
}

/// [`log`] with `format!` arguments, without an `alloc` import in the author's crate.
///
/// ```ignore
/// ouroboros_guest::log!("info", "denied {} at {}", tool, path);
/// ```
#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)*) => {
        $crate::log($level, &$crate::__rt::format(::core::format_args!($($arg)*)))
    };
}

/// Everything a `no_std` component must bring that is not its own logic: the allocator, the
/// panic handler, the canonical ABI's `cabi_realloc`, and the one `mem*` intrinsic the
/// dependency graph references and the `wasm32-wasip2` sysroot does not carry.
///
/// The four `export_*` macros invoke this for you, so an author never writes it. It is public
/// because a guest that hand-writes its own `bindings::Guest` impl — there is no reason to,
/// and the door stays open anyway — still needs it, and because naming it is how this crate
/// documents what "the ceremony" actually is.
///
/// Invoke it exactly once per component. Twice is a duplicate `#[panic_handler]`, which is a
/// compile error and not a silent one.
#[macro_export]
macro_rules! ceremony {
    () => {
        /// The allocator a `no_std` build has to name for itself. This is the implementation
        /// `std` would have installed on this target, arriving without `std`'s imports.
        #[global_allocator]
        static __OUROBOROS_ALLOCATOR: $crate::__rt::GlobalDlmalloc = $crate::__rt::GlobalDlmalloc;

        /// A panic is a bug in this guest, and it becomes a trap the helper classifies and
        /// reports — the same outcome `panic = "abort"` would reach, without a formatter that
        /// would need somewhere to write. Nothing in this SDK panics on input: bad input is an
        /// `Err(String)`.
        #[panic_handler]
        fn __ouroboros_panic(_info: &::core::panic::PanicInfo) -> ! {
            $crate::__rt::trap()
        }

        /// The canonical ABI's allocator entry point, which the host calls to place a lifted
        /// string into this instance's memory before calling an export.
        ///
        /// `wit-bindgen` ships one of these, but not for this target: on `wasm32-wasip2` it
        /// defers to wasi-libc's, and a `no_std` build does not link wasi-libc.
        ///
        /// # Safety
        ///
        /// Called only by the canonical ABI, which owns the pointer/length/alignment triple it
        /// passes and guarantees it describes a block this allocator handed out.
        #[no_mangle]
        pub unsafe extern "C" fn cabi_realloc(
            old_ptr: *mut u8,
            old_len: usize,
            align: usize,
            new_len: usize,
        ) -> *mut u8 {
            unsafe { $crate::__rt::realloc(old_ptr, old_len, align, new_len) }
        }

        /// The one `mem*` intrinsic this graph references and the `wasm32-wasip2` sysroot's
        /// `compiler_builtins` does not carry. `std` would have brought wasi-libc's; a
        /// `no_std` build brings its own rather than linking a libc for eight lines — and a
        /// libc on the link line is a much larger surface to keep the WASI imports out of.
        ///
        /// # Safety
        ///
        /// `left` and `right` must be readable for `count` bytes, as the C contract says.
        #[no_mangle]
        pub unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, count: usize) -> i32 {
            unsafe { $crate::__rt::memcmp(left, right, count) }
        }
    };
}
