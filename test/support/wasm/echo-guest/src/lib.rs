//! The lane-W acceptance guest: a capability component in `ouroboros:capability@0.1.0`.
//!
//! `tui/wasm/tests/support/mod.rs` writes its guests as WAT and assembles them in-process, so
//! the helper's containment proofs need no wasm toolchain at all. This one is the other half
//! of that story: a guest built the way a real capability author would build one —
//! `wit-bindgen` against the checked-in world, `cargo build --release --target wasm32-wasip2`
//! — so that the world file, the helper's hard-coded `world.rs`, and an actual toolchain's
//! idea of the canonical ABI are proved to agree rather than assumed to.
//!
//! # Why `no_std`
//!
//! Because the import list is the security claim, and `std` on `wasm32-wasip2` is not silent.
//! The identical source built against `std` — with `panic = "abort"`, LTO and `opt-level =
//! "s"` — produces a component importing thirteen interfaces beside `log`:
//! `wasi:io/{poll,error,streams}` and `wasi:cli/{environment,exit,stdin,stdout,stderr}` plus
//! the four `terminal-*` handles. They arrive with `std`'s stdio, environment and process-exit
//! machinery, they survive `--gc-sections` because the default panic path reaches them, and
//! the helper's linker defines none of them — so that build refuses to instantiate and
//! `inspect` reports `world: "unknown"`. Dropping `std` drops all thirteen. What replaces it
//! is small and named: `alloc`, one allocator (the one `std` itself uses on wasm), and a
//! panic handler.
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
//! # Authority
//!
//! One import: `log`. The world declares no clock, no randomness, no filesystem and no
//! socket, and an import the helper's linker does not define fails instantiation — so this
//! file's authority is legible from its first line, and `inspect` reports it.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use serde_json::{json, Value};

wit_bindgen::generate!({
    // The world file is the artifact of record, shared with the helper that enforces it.
    path: "../../../../tui/wasm/wit",
    world: "capability",
});

/// The allocator, which a `no_std` build has to name for itself. See the module header: this
/// is the implementation `std` would have installed, arriving without `std`'s imports.
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

/// A panic is a bug in this guest, and it becomes a trap the helper classifies and reports —
/// the same outcome `panic = "abort"` would reach, without a formatter that would need
/// somewhere to write. Nothing above ever panics on input: bad input is an `err(string)`.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

/// The canonical ABI's allocator entry point, which the host calls to place a lifted string
/// into this instance's memory before calling an export.
///
/// `wit-bindgen` ships one of these, but not for this target: on `wasm32-wasip2` it defers to
/// wasi-libc's, and a `no_std` build does not link wasi-libc. So the contract is met here, in
/// the same spirit as the hand-written WAT `realloc` in `tui/wasm/tests/support/mod.rs` —
/// except this one is backed by a real allocator and frees.
///
/// The contract, in full: `old_len == 0` is an allocation (and `new_len == 0` with it is the
/// dangling-but-aligned pointer); otherwise it is a resize of a live block. A refused
/// allocation traps, because there is no value this can return that the host would not read
/// as memory it may write to.
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
    use alloc::alloc::{alloc, realloc, Layout};

    let pointer = unsafe {
        if old_len == 0 {
            if new_len == 0 {
                return align as *mut u8;
            }
            alloc(Layout::from_size_align_unchecked(new_len, align))
        } else {
            realloc(
                old_ptr,
                Layout::from_size_align_unchecked(old_len, align),
                new_len,
            )
        }
    };

    if pointer.is_null() {
        core::arch::wasm32::unreachable()
    }

    pointer
}

/// The one `mem*` intrinsic this crate's dependencies reference and the `wasm32-wasip2`
/// sysroot's `compiler_builtins` does not carry. `std` would have brought wasi-libc's; a
/// `no_std` build brings its own rather than linking a libc for eight lines — and a libc on
/// the link line is a much larger surface to keep the WASI imports out of.
///
/// # Safety
///
/// `left` and `right` must be readable for `count` bytes, as the C contract says.
#[no_mangle]
pub unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, count: usize) -> i32 {
    for offset in 0..count {
        let a = unsafe { *left.add(offset) };
        let b = unsafe { *right.add(offset) };

        if a != b {
            return i32::from(a) - i32::from(b);
        }
    }

    0
}

/// What one instance remembers between messages. `None` until `init` has run.
struct Session {
    config: Value,
    messages: u64,
}

/// Instance-held state. A component instance in this world is single-threaded and has no way
/// to become otherwise — the world imports nothing that could spawn a thread — so an
/// `UnsafeCell` behind a `Sync` wrapper is the whole synchronization story, and a mutex would
/// be a lock nobody can contend.
struct Cell<T>(core::cell::UnsafeCell<T>);

// SAFETY: single-threaded by construction, as above.
unsafe impl<T> Sync for Cell<T> {}

impl<T> Cell<T> {
    const fn new(value: T) -> Self {
        Self(core::cell::UnsafeCell::new(value))
    }

    /// SAFETY: single-threaded, and no borrow taken here outlives the statement that took
    /// it — every use below reads or writes and returns.
    #[allow(clippy::mut_from_ref)]
    fn get(&self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }
}

static SESSION: Cell<Option<Session>> = Cell::new(None);

struct Component;

impl Guest for Component {
    /// Metadata, as JSON. Pure: it reads nothing and changes nothing.
    fn describe() -> String {
        json!({
            "name": "ouroboros-echo-guest",
            "version": env!("CARGO_PKG_VERSION"),
            "world": "ouroboros:capability@0.1.0",
        })
        .to_string()
    }

    /// One instance, one config. A config that is not JSON is refused here rather than
    /// carried to the first message: the host is told at instantiate, which is the point in
    /// the lifecycle where it can still do something about it.
    fn init(config: String) -> Result<(), String> {
        match serde_json::from_str::<Value>(&config) {
            Ok(config) => {
                *SESSION.get() = Some(Session {
                    config,
                    messages: 0,
                });
                Ok(())
            }
            Err(error) => Err(format!("config is not JSON: {error}")),
        }
    }

    /// One message in, one JSON reply out — the body echoed, the config this instance was
    /// started with, and the running count.
    fn handle_message(body: String) -> Result<String, String> {
        // Exactly once per message, and before anything that can fail: the line is the
        // evidence that the one import in this world reaches the daemon, and a refused
        // message must not be the reason it is missing.
        log("info", "handle-message");

        let Some(session) = SESSION.get().as_mut() else {
            return Err("init has not run on this instance".to_string());
        };

        // The hook lane (docs/WASM.md §8.1) drives this same world: a hook component's reply
        // *is* the stdout contract `Hooks.parse_output/1` reads, so a test hook has to be able
        // to state one verbatim rather than have it wrapped in an echo envelope. A config
        // carrying a string `reply` is that: the answer, exactly, for every message. No
        // capability test sets it, so every other test on this guest is unaffected — and the
        // authority is unchanged, because a string in the config was already the host's to
        // choose.
        if let Some(Value::String(reply)) = session.config.get("reply") {
            session.messages += 1;
            return Ok(reply.clone());
        }

        let body: Value =
            serde_json::from_str(&body).map_err(|error| format!("body is not JSON: {error}"))?;

        session.messages += 1;

        Ok(json!({
            "echo": body,
            "config": session.config,
            "n": session.messages,
        })
        .to_string())
    }
}

export!(Component);
