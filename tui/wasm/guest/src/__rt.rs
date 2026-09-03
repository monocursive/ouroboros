//! What the `export_*` macros expand into. Public so the expansions can reach it, hidden from
//! the docs because none of it is API: an author writes a trait impl and one macro call.

use alloc::string::{String, ToString};
use serde_json::Value;

use crate::capability::Capability;
use crate::hook::{Check, CheckOutcome, Hook, HookInput};
use crate::policy::{Policy, Verdict};
use crate::raw::Raw;

pub use dlmalloc::GlobalDlmalloc;

/// What a guest answers a message it was handed before `init` ran.
///
/// Word for word what the acceptance guest answered before W9, and kept for that reason and no
/// stronger one: **nothing reads this text**, and no caller can reach it through the helper's
/// protocol — `call` on an instance that was never stood up is `unknown_instance`, and an
/// `instantiate` whose `init` refused leaves no instance behind. It is the answer for a host
/// that grows a way to call an export before `init`, written down now so that host is told
/// rather than handed a `None`.
const NO_INIT: &str = "init has not run on this instance";

/// What a guest answers a call that arrived while it was already inside one. See [`State`]:
/// this world cannot produce that, and the day it can the answer is a refusal rather than two
/// live `&mut` to the same value.
const REENTERED: &str = "a call arrived while this instance was already answering one";

// ------------------------------------------------------------------------------- the ceremony

/// A trap, the only one this crate installs. The non-wasm arm exists so the crate type-checks
/// for a host target; nothing links it there.
pub fn trap() -> ! {
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();
    #[cfg(not(target_arch = "wasm32"))]
    unreachable!("ouroboros-guest builds for wasm32; there is no trap instruction here")
}

/// The canonical ABI's `realloc` contract, in full: `old_len == 0` is an allocation (and
/// `new_len == 0` with it is the dangling-but-aligned pointer); otherwise it is a resize of a
/// live block. A refused allocation traps, because there is no value this can return that the
/// host would not read as memory it may write to.
///
/// # Safety
///
/// Called only by the canonical ABI, which owns the pointer/length/alignment triple it passes
/// and guarantees it describes a block this allocator handed out.
pub unsafe fn realloc(old_ptr: *mut u8, old_len: usize, align: usize, new_len: usize) -> *mut u8 {
    use alloc::alloc::{alloc, dealloc, realloc, Layout};

    let pointer = unsafe {
        if old_len == 0 {
            if new_len == 0 {
                return align as *mut u8;
            }
            alloc(Layout::from_size_align_unchecked(new_len, align))
        } else if new_len == 0 {
            // Shrinking a live block to nothing. The canonical ABI does not ask for this and
            // wit-bindgen's own implementation only `debug_assert`s that it cannot happen —
            // which in a release build with `panic = "abort"` is no check at all, and
            // `alloc::realloc` with a zero size is undefined behaviour by contract. So the
            // branch exists rather than the assertion: free the block and answer with the
            // dangling-but-aligned pointer, which is the same answer the zero-size case above
            // gives and is what the ABI's zero-length convention means. No leak, no UB, and no
            // trap for something that is not the guest's fault.
            dealloc(old_ptr, Layout::from_size_align_unchecked(old_len, align));
            return align as *mut u8;
        } else {
            realloc(
                old_ptr,
                Layout::from_size_align_unchecked(old_len, align),
                new_len,
            )
        }
    };

    if pointer.is_null() {
        trap()
    }

    pointer
}

/// The C `memcmp` contract, byte by byte.
///
/// # Safety
///
/// `left` and `right` must be readable for `count` bytes.
pub unsafe fn memcmp(left: *const u8, right: *const u8, count: usize) -> i32 {
    for offset in 0..count {
        let a = unsafe { *left.add(offset) };
        let b = unsafe { *right.add(offset) };

        if a != b {
            return i32::from(a) - i32::from(b);
        }
    }

    0
}

/// `format!` without an `extern crate alloc` in the author's crate. Behind [`crate::log!`].
pub fn format(args: core::fmt::Arguments<'_>) -> String {
    alloc::fmt::format(args)
}

// ---------------------------------------------------------------------------- instance state

/// The single value a component instance remembers between messages.
///
/// A component instance in this world is single-threaded and has no way to become otherwise:
/// the world imports nothing that could spawn a thread, threads are not in the engine's
/// proposal set (`tui/wasm/src/host.rs`), and the helper calls one export at a time on one
/// instance. That is what makes the `unsafe impl Sync` below true.
///
/// It is a `RefCell` and not a bare `UnsafeCell` because "single-threaded" is not "not
/// re-entrant": the world's one import is a host call, and a host that called back into the
/// guest while it held a `&mut` would be aliasing. Nothing in `ouro-wasm` does that today. The
/// borrow flag costs one byte and turns the day it might into an `Err(String)` the host
/// records, rather than into undefined behaviour nobody would find.
pub struct State<T>(core::cell::RefCell<T>);

// SAFETY: single-threaded by construction, as above. The value never crosses a thread because
// this target has no threads to cross to.
unsafe impl<T> Sync for State<T> {}

impl<T> State<T> {
    pub const fn new(value: T) -> Self {
        Self(core::cell::RefCell::new(value))
    }
}

/// Runs `body` with exclusive access to the instance's state, or refuses.
fn with<T, R>(cell: &State<Option<T>>, body: impl FnOnce(&mut T) -> R) -> Result<R, String> {
    let mut slot = cell
        .0
        .try_borrow_mut()
        .map_err(|_reentered| REENTERED.to_string())?;

    match slot.as_mut() {
        Some(state) => Ok(body(state)),
        None => Err(NO_INIT.to_string()),
    }
}

/// Installs the value `init` produced, or refuses without installing anything.
fn install<T>(cell: &State<Option<T>>, made: Result<T, String>) -> Result<(), String> {
    let mut slot = cell
        .0
        .try_borrow_mut()
        .map_err(|_reentered| REENTERED.to_string())?;

    *slot = Some(made?);
    Ok(())
}

// ------------------------------------------------------------------------------------- glue

pub fn raw_describe<R: Raw>() -> String {
    R::describe().to_json_string()
}

pub fn raw_init<R: Raw>(cell: &State<Option<R>>, config: String) -> Result<(), String> {
    install(cell, R::init(&config))
}

pub fn raw_handle<R: Raw>(cell: &State<Option<R>>, body: String) -> Result<String, String> {
    with(cell, |state| state.handle(&body))?
}

pub fn capability_describe<C: Capability>() -> String {
    C::describe().to_json_string()
}

pub fn capability_init<C: Capability>(
    cell: &State<Option<C>>,
    config: String,
) -> Result<(), String> {
    install(cell, crate::config_json(&config).and_then(C::init))
}

pub fn capability_handle<C: Capability>(
    cell: &State<Option<C>>,
    body: String,
) -> Result<String, String> {
    let body = crate::body_json(&body)?;
    let answer = with(cell, |state| state.handle(body))??;
    Ok(answer.to_string())
}

pub fn hook_describe<H: Hook>(name: &str, version: &str) -> String {
    H::describe(name, version).to_json_string()
}

pub fn hook_init<H: Hook>(cell: &State<Option<H>>, config: String) -> Result<(), String> {
    install(cell, crate::config_json(&config).and_then(H::init))
}

pub fn hook_handle<H: Hook>(cell: &State<Option<H>>, body: String) -> Result<String, String> {
    let payload = crate::body_json(&body)?;
    let input = HookInput::from_json(payload);
    let verdict = with(cell, |state| state.on(input))??;
    Ok(verdict.to_reply())
}

pub fn check_describe<C: Check>(name: &str, version: &str) -> String {
    C::describe(name, version).to_json_string()
}

pub fn check_init<C: Check>(cell: &State<Option<C>>, config: String) -> Result<(), String> {
    install(cell, crate::config_json(&config).and_then(C::init))
}

/// The `[checks]` payload is `{"event": "check", "name": "<key>"}` and its reply is text, not
/// JSON: empty is a pass and anything else is the failure `hooks.ex` injects into the turn.
pub fn check_handle<C: Check>(cell: &State<Option<C>>, body: String) -> Result<String, String> {
    let payload = crate::body_json(&body)?;
    let name = payload
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // Copied out of the payload before the borrow, so the closure below owns nothing of it.
    let name = String::from(name);

    let outcome = with(cell, |state| state.run(&name))??;

    Ok(match outcome {
        CheckOutcome::Pass => String::new(),
        CheckOutcome::Fail(text) => text,
    })
}

// ------------------------------------------------------------------------------ the policy world

pub fn policy_describe<P: Policy>() -> String {
    P::describe().in_world(crate::POLICY_WORLD).to_json_string()
}

pub fn policy_init<P: Policy>(cell: &State<Option<P>>, config: String) -> Result<(), String> {
    install(cell, crate::config_json(&config).and_then(P::init))
}

/// `evaluate` has no error channel, and that is the world's design rather than an oversight:
/// there is nothing an `Err` would mean here that [`Verdict::ask`] does not say better, and a
/// second way to say "I could not decide" is a second thing an author can get wrong.
///
/// So every failure this seam can have becomes an `ask` with the reason stated as the rule: a
/// request that is not JSON, a call that arrived before `init`, and the re-entrant call this
/// world cannot currently produce. The engine reads all three as `ask` whatever the rule says —
/// it is bounded, labelled untrusted, and shown to whoever is asked — and a policy that fails
/// closed to a human question is the posture D20 requires.
pub fn policy_evaluate<P: Policy>(cell: &State<Option<P>>, request: String) -> String {
    let verdict = match crate::body_json(&request) {
        Ok(request) => match with(cell, |state| state.evaluate(request)) {
            Ok(verdict) => verdict,
            Err(reason) => Verdict::ask(reason),
        },
        Err(reason) => Verdict::ask(reason),
    };

    verdict.to_reply()
}
