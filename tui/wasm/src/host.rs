//! The contained side: the wasmtime engine, the linker that *is* the boundary, and the six
//! things this helper will do with a component.
//!
//! # The boundary is the linker (docs/WASM.md D5)
//!
//! [`Host::new`] defines exactly one host function — `log` — on the component linker and
//! nothing else. There is no `wasmtime-wasi` in this binary's dependency graph at any version.
//! A component that imports a clock, a socket, a filesystem, or a random number generator has
//! nothing to bind those to and fails to instantiate. That is a structural property of the
//! linker, not a check somebody has to remember to run: a lying manifest cannot smuggle
//! authority past it, and neither can a bug in [`crate::world`], whose import check is the
//! early, legible refusal in front of the same wall.
//!
//! # The engine speaks the smallest dialect the world needs
//!
//! [`config`] turns off every WebAssembly proposal the v1 capability world does not use — relaxed
//! SIMD first among them, because it is nondeterministic by design and D4 is not negotiable —
//! and names the four bounds wasmtime would otherwise default: the wasm stack, the optimisation
//! level, and the per-memory address-space reservation and guard. Read [`config`] for the list
//! and for what is deliberately left on.
//!
//! # Compilation is bounded before it starts
//!
//! [`Host::compile`] is the one place `Component::new` is called, and [`crate::shape::check`]
//! runs in front of it. Nothing below this line — not fuel, not the epoch deadline, not the
//! memory ceiling — is armed while a component is being compiled, because there is no store yet;
//! and cranelift cannot be interrupted once it starts, so the only bound that works is one on
//! the input. See [`crate::shape`] for the measurements the numbers come from.
//!
//! # The bounds, all mandatory, re-armed per call
//!
//! Every store is created with fuel set, an epoch deadline armed, and a [`ResourceLimiter`]
//! installed. There is no unlimited default and no way to ask for one: `instantiate` refuses a
//! request that omits any of the three limits ([`Limits::parse`]).
//!
//! * **Fuel** stops a guest that computes forever, but only while it executes instructions.
//! * **The epoch deadline** is the wall-clock guarantee. One background thread bumps the
//!   engine's epoch every [`EPOCH_TICK_MS`] milliseconds, and the store's deadline is a count
//!   of those ticks; a guest in a loop is interrupted whether or not fuel would have caught it.
//! * **The memory ceiling** denies growth past `memory_bytes`, **summed across every memory in
//!   the store** and not per memory: a component may declare as many memories as it likes and
//!   they share one grant, or nine hundred small memories would be nine hundred times the
//!   ceiling. A denial is not itself a trap — `memory.grow` returns -1 and the guest decides
//!   what to do — so the refusal reported for a guest that then gives up names the ceiling
//!   rather than the guest's `unreachable`.
//! * **Resource counts** are capped far below wasmtime's defaults of ten thousand each
//!   ([`MAX_CORE_INSTANCES`], [`MAX_MEMORIES`], [`MAX_TABLES`], [`MAX_TABLE_ELEMENTS`]). The
//!   per-resource bookkeeping wasmtime allocates is not charged to the memory ceiling, so a
//!   component of a hundred instances each holding a hundred large tables costs gigabytes
//!   under a 64 KiB memory grant unless the *counts* are bounded too.
//! * **Hostcall bytes** cap what one guest-to-host transfer may hand over
//!   ([`MAX_HOSTCALL_BYTES`]) — see [`arm`].
//! * **Log lines** are budgeted per call ([`MAX_LOG_LINES_PER_CALL`]) — see below.
//!
//! `init` runs under exactly these bounds, because `init` runs guest code.
//!
//! # `log` is budgeted, because a host call is a hole in the deadline
//!
//! Neither fuel nor the epoch can interrupt a guest that is *inside* a host function: the
//! deadline is checked at wasm loop back-edges, and there are none while the host is running.
//! A guest that calls `log` in a loop therefore runs at the speed of this process's stderr, and
//! if the owner is not draining that pipe the first write into a full pipe blocks the helper —
//! not for the deadline, but forever.
//!
//! So each call gets [`MAX_LOG_LINES_PER_CALL`] lines, reset by [`arm`]. Past the budget one
//! marker line is emitted and the rest of that call's `log` invocations return immediately
//! without writing. With [`MAX_LOG_MESSAGE_BYTES`] bounding each line, a single call can put at
//! most about 13 KiB on stderr — under a 16 KiB pipe buffer, which is the smallest a platform
//! this helper runs on gives us — so **no one call can fill the pipe**, and an owner that
//! drains stderr between requests never sees this at all.
//!
//! The residual is stated rather than solved: **stderr is the owner's to drain.** A pool that
//! spawns this helper and never reads its stderr will eventually wedge it whatever the budget
//! is, exactly as it would wedge any program on the end of a pipe. Measured against a guest
//! that asks for a thousand log lines a message, with stderr piped and never once read: the
//! helper answers 87 consecutive calls and then blocks on a full pipe. Unbudgeted, the same
//! guest wedged it on the first one. The budget does not make an unread pipe safe; it makes
//! the unread pipe the only way to get there.
//!
//! # A trap poisons its instance
//!
//! A guest that traps has been stopped somewhere it did not choose: half of a message handled,
//! its own invariants unknown. There is no honest way to keep answering with it, so a trap
//! drops the instance server-side and every later `call` on that name is `unknown_instance`.
//! The peer re-instantiates, which costs one `instantiate` and buys a guest whose state is
//! whatever `init` says it is. A guest returning its own `err(string)` is *not* a trap and does
//! not poison anything — that is the guest answering, in a way the world provides for.
//!
//! # The component cache evicts, and only what nothing holds
//!
//! A compiled component stays in the cache until the cache is full and something newer wants
//! the slot. The table holds [`MAX_COMPONENTS`]; a `load` that would exceed it evicts the
//! **least recently used** component — recency being the last `load` or `instantiate` that
//! named the sha — and never one with a live instance. An instance holds its own handle on the
//! compiled code, so evicting the cache entry could not break it; but an owner that stood an
//! instance up is plainly still using that component, and a cache that forgot what its callers
//! hold would be lying to `doctor`. If every held component has a live instance the load is
//! refused `too_many_components`, which is now the only way that refusal is reached.
//!
//! Eviction is a reclaim, not a revocation. Nothing about admission changes: the evicted sha
//! is simply unknown again, the next `instantiate` naming it is refused `unknown_component`,
//! and the peer re-`load`s — which recomputes the digest from the bytes on disk and runs the
//! world check again, exactly as the first load did. Every peer in this repository loads
//! before it instantiates, so an eviction costs a recompile and nothing else.
//!
//! It is also legible, because a reclaim the owner cannot see is a fault it cannot explain: the
//! `load` that evicted names the shas it let go in its result, and `doctor` reports how many
//! evictions this process has made and the last [`MAX_EVICTION_LOG`] of them.
//!
//! Instances are never evicted. A live guest's state is its owner's, and forgetting it on a
//! timer would be a worse bug than refusing a new one; the instance table is a hard ceiling,
//! and `too_many_instances` means "drop one".

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wasmtime::component::{Component, Linker, TypedFunc};
use wasmtime::{
    Config, Engine, OptLevel, ResourceLimiter, Store, StoreContextMut, Trap, WasmFeatures,
};

use crate::refusal::{self, Refusal};
use crate::shape;
use crate::world;

/// The period of the epoch ticker, and therefore the granularity of every deadline. Ten
/// milliseconds is far finer than any deadline a capability message is worth and costs one
/// sleeping thread.
pub const EPOCH_TICK_MS: u64 = 10;

/// The largest file `inspect` and `load` will read. A component is a capability, not an image.
pub const MAX_COMPONENT_BYTES: u64 = 64 * 1024 * 1024;

/// Limit bounds. A peer asking for more than these is refused rather than obeyed: a buggy
/// caller must not be able to hand a guest the machine.
pub const MIN_MEMORY_BYTES: u64 = 64 * 1024;
pub const MAX_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_DEADLINE_MS: u64 = 60_000;
pub const MAX_FUEL: u64 = 1_000_000_000_000;

/// The largest reply a guest may return, in bytes of UTF-8.
///
/// One mebibyte, not the four the frame cap might suggest, because the reply is JSON-escaped
/// into the response line and escaping is not free: a control character becomes six bytes, so a
/// worst-case payload grows sixfold. 1 MiB is the largest guest answer that certainly fits an
/// 8 MiB frame no matter what bytes it contains.
pub const MAX_RESULT_BYTES: usize = 1024 * 1024;

/// The largest number of bytes a guest may hand the host in one guest-to-host transfer:
/// `log`'s two arguments, and the string a call's result is lifted from.
///
/// wasmtime calls this "hostcall fuel" and defaults it to 128 MiB. That default is a real
/// amplifier here: a guest returning a 100 MiB reply gets a correct `oversize_result` refusal
/// *after* the host has allocated the whole 100 MiB to look at it, and can do it again on the
/// next call. Four mebibytes is four times [`MAX_RESULT_BYTES`], so every in-contract reply and
/// every plausibly-buggy one is still lifted and refused by size with a typed refusal; only a
/// reply that is orders of magnitude too large is stopped by wasmtime instead, as a trap.
///
/// wasmtime re-seeds this budget for each guest-to-host call, and — verified against
/// `wasmtime-48.0.1/src/runtime/component/store.rs:494-509` — it does **not** meter the other
/// direction. Lowering the inbound `call` payload into guest memory is unaffected, so a payload
/// up to the frame cap still reaches the guest; what bounds *that* is the guest's own memory
/// ceiling.
pub const MAX_HOSTCALL_BYTES: usize = 4 * 1024 * 1024;

/// Resource *counts*, capped far below wasmtime's defaults of 10,000 each. What these bound is
/// not the guest's own memory — that is `memory_bytes` — but the per-resource bookkeeping the
/// runtime allocates on the guest's behalf, which no memory grant is charged for. A world with
/// three exports and one import needs a handful of core instances (the reference guests use
/// two, plus the synthetic instance a lowered import is passed through), one memory, and no
/// tables at all; these leave room for a guest built by a real toolchain without leaving room
/// for a guest built to be expensive.
pub const MAX_CORE_INSTANCES: usize = 16;
pub const MAX_MEMORIES: usize = 4;
pub const MAX_TABLES: usize = 4;

/// Table growth is bounded for the same reason memory is; nothing in this world needs a big
/// table, and an unbounded one is a memory vector wearing a different name. At a pointer per
/// element and [`MAX_TABLES`] tables, this is a few megabytes at worst.
pub const MAX_TABLE_ELEMENTS: usize = 100_000;

/// How much this helper will hold at once — ceilings the owner can read out of `doctor` rather
/// than discover.
///
/// The two tables are bounded differently on purpose. Components are a *cache*: past
/// [`MAX_COMPONENTS`], `load` evicts the least recently used component no live instance holds
/// (see the module header), so the cap bounds memory rather than the number of distinct
/// components a helper may ever see. Instances are not a cache — each is a guest's live state,
/// which is its owner's to drop — so [`MAX_INSTANCES`] is a hard ceiling and reaching it is a
/// refusal.
pub const MAX_COMPONENTS: usize = 64;
pub const MAX_INSTANCES: usize = 256;

/// How many evicted shas `doctor` keeps, newest last. Enough to explain the recent past to an
/// operator asking why a component they expected to be cached was compiled again, and a bound
/// on what would otherwise be the one unbounded log in a process whose every table is bounded.
pub const MAX_EVICTION_LOG: usize = 16;

/// The per-call log budget, and the bounds on one line. See the module header: sixteen lines of
/// at most `256 + 16 + 512` bytes of content plus a short prefix is about 13 KiB, which fits a
/// 16 KiB pipe buffer with room to spare.
pub const MAX_LOG_LINES_PER_CALL: u32 = 16;
const MAX_LOG_LEVEL_BYTES: usize = 16;
const MAX_LOG_MESSAGE_BYTES: usize = 512;

/// How much of any string the *peer* chose — a path, a sha, an instance name, an export name —
/// travels back in a refusal or a result. Without this a seven-megabyte path produces a
/// refusal too large for the frame that has to carry it, which is a peer breaking its own pipe
/// through this helper's politeness.
const MAX_ECHO_BYTES: usize = 256;

/// How many of a component's declared import and export names `inspect` and `load` report. A
/// component is only bounded by [`MAX_COMPONENT_BYTES`], so it can declare a great many names,
/// and this is a review surface rather than a manifest — the world check reads all of them.
const MAX_REPORTED_NAMES: usize = 64;

/// How much of a wasmtime error is worth putting on the wire.
const MAX_ERROR_BYTES: usize = 1024;

/// The three bounds every instance runs under. All three are required; see the module header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub deadline_ms: u64,
}

impl Limits {
    /// Reads a `limits` object. A missing or mistyped field is an invalid-params error — the
    /// request is malformed. A field that is present but outside this helper's range is a
    /// `limits_out_of_range` refusal — the request is well-formed and denied.
    pub fn parse(params: &Value) -> Result<Limits, Refusal> {
        let limits = params
            .get("limits")
            .ok_or_else(|| invalid_params("limits is required; there is no unlimited default"))?;

        let fuel = required_u64(limits, "fuel")?;
        let memory_bytes = required_u64(limits, "memory_bytes")?;
        let deadline_ms = required_u64(limits, "deadline_ms")?;

        if fuel == 0 || fuel > MAX_FUEL {
            return Err(refusal::refuse(
                refusal::LIMITS_OUT_OF_RANGE,
                format!("limits.fuel must be in 1..={MAX_FUEL}, got {fuel}"),
            ));
        }
        if !(MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&memory_bytes) {
            return Err(refusal::refuse(
                refusal::LIMITS_OUT_OF_RANGE,
                format!(
                    "limits.memory_bytes must be in {MIN_MEMORY_BYTES}..={MAX_MEMORY_BYTES}, \
                     got {memory_bytes}"
                ),
            ));
        }
        if deadline_ms == 0 || deadline_ms > MAX_DEADLINE_MS {
            return Err(refusal::refuse(
                refusal::LIMITS_OUT_OF_RANGE,
                format!("limits.deadline_ms must be in 1..={MAX_DEADLINE_MS}, got {deadline_ms}"),
            ));
        }

        Ok(Limits {
            fuel,
            memory_bytes,
            deadline_ms,
        })
    }

    /// The deadline in ticker periods, rounded up and then given one more: the ticker is free
    /// running, so up to one whole period of the first tick may already have elapsed when a
    /// store arms its deadline. The guest therefore gets at least `deadline_ms` and at most
    /// `deadline_ms + 2 * EPOCH_TICK_MS`.
    fn epoch_ticks(&self) -> u64 {
        self.deadline_ms.div_ceil(EPOCH_TICK_MS) + 1
    }
}

/// Everything one instance's store carries: who it is, its memory ceiling, and this call's log
/// budget.
struct State {
    /// Already truncated to [`MAX_ECHO_BYTES`]; it is peer-chosen and it goes into every log
    /// line this instance writes.
    instance: String,
    memory_bytes: usize,
    /// Bytes across *all* of this store's memories that growth has been approved for. Store
    /// state, not call state: memories outlive a call, so [`arm`] must not reset this.
    memory_total: usize,
    /// Set when growth was refused. A guest that then traps is reported as having hit the
    /// ceiling, which is the true cause, rather than as a mysterious `unreachable`.
    memory_denied: bool,
    logs_remaining: u32,
    log_budget_reported: bool,
    /// Lines actually written to stderr during the current call, budget notice included. The
    /// owner reads that pipe on a thread of its own, so a reply can overtake the last line
    /// the guest wrote; reporting the count in the reply is what lets an owner wait for
    /// exactly the lines that exist rather than guess with a sleep.
    log_lines_written: u32,
}

impl ResourceLimiter for State {
    /// The ceiling is on the store's memories together. `current` is the size of the one memory
    /// being grown, so subtracting it and adding `desired` re-totals without needing a table of
    /// every memory's size.
    ///
    /// Approval is recorded before the growth happens, so a growth wasmtime then fails for its
    /// own reasons leaves this over-counting. That is the safe direction: it can only make the
    /// next request more likely to be refused, never less.
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let total = self
            .memory_total
            .saturating_sub(current)
            .saturating_add(desired);
        if total > self.memory_bytes {
            self.memory_denied = true;
            return Ok(false);
        }
        self.memory_total = total;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= MAX_TABLE_ELEMENTS)
    }

    fn instances(&self) -> usize {
        MAX_CORE_INSTANCES
    }

    fn tables(&self) -> usize {
        MAX_TABLES
    }

    fn memories(&self) -> usize {
        MAX_MEMORIES
    }
}

/// A compiled component and the facts `inspect` reported about it, kept so a repeat `load` of a
/// sha already held costs nothing.
struct Loaded {
    component: Component,
    world: &'static str,
    size: usize,
    imports: Vec<String>,
    exports: Vec<String>,
    /// The cache clock's reading the last time a `load` or `instantiate` named this sha. The
    /// smallest reading among the components no instance holds is the one eviction takes.
    last_used: u64,
}

/// The component cache: what is held, when each entry was last wanted, and what has been let
/// go. See the module header for the policy; this is the bookkeeping that carries it out.
struct Components {
    held: HashMap<String, Loaded>,
    /// Advanced every time a sha is named by `load` or `instantiate`, so "least recently used"
    /// is a total order on the table rather than a wall-clock reading that could tie.
    clock: u64,
    /// Every eviction this process has made, for `doctor`.
    evictions: u64,
    /// The last [`MAX_EVICTION_LOG`] evicted shas, oldest first.
    recent: VecDeque<String>,
}

impl Components {
    fn new() -> Components {
        Components {
            held: HashMap::new(),
            clock: 0,
            evictions: 0,
            recent: VecDeque::with_capacity(MAX_EVICTION_LOG),
        }
    }

    /// The entry for `sha`, if held, marked as wanted now.
    fn touch(&mut self, sha: &str) -> Option<&Loaded> {
        self.clock += 1;
        let clock = self.clock;
        let loaded = self.held.get_mut(sha)?;
        loaded.last_used = clock;
        Some(&*loaded)
    }

    /// Admits `loaded` under `sha`, as wanted now.
    fn insert(&mut self, sha: String, mut loaded: Loaded) {
        self.clock += 1;
        loaded.last_used = self.clock;
        self.held.insert(sha, loaded);
    }

    /// Whether admitting one more component means letting one go first.
    fn full(&self) -> bool {
        self.held.len() >= MAX_COMPONENTS
    }

    /// The sha eviction would take: the least recently used of those not in `pinned`. `None`
    /// when every held component is pinned, which is the one case a full cache refuses.
    fn victim(&self, pinned: &HashSet<String>) -> Option<String> {
        self.held
            .iter()
            .filter(|(sha, _)| !pinned.contains(*sha))
            .min_by_key(|(_, loaded)| loaded.last_used)
            .map(|(sha, _)| sha.clone())
    }

    /// Lets `sha` go and records that it did. A sha not held is not an eviction.
    fn evict(&mut self, sha: &str) {
        if self.held.remove(sha).is_some() {
            self.evictions += 1;
            if self.recent.len() >= MAX_EVICTION_LOG {
                self.recent.pop_front();
            }
            self.recent.push_back(sha.to_string());
        }
    }
}

/// What `doctor` reports about the tables: how full each is, and what the cache has let go.
pub struct Census {
    pub components: usize,
    pub instances: usize,
    pub evictions: u64,
    /// The most recent evictions, oldest first — at most [`MAX_EVICTION_LOG`] of them.
    pub evicted: Vec<String>,
}

/// One live instance: its store, and the two exports `call` can reach.
struct Live {
    store: Store<State>,
    describe: TypedFunc<(), (String,)>,
    handle: TypedFunc<(String,), (Result<String, String>,)>,
    limits: Limits,
    /// The component this instance was stood up from, so eviction can see that it is held.
    sha256: String,
}

/// The helper's whole mutable world. One per process; the serve loop hands it to a blocking
/// task per request, and the wire is sequential, so the two mutexes are never contended.
pub struct Host {
    engine: Engine,
    linker: Linker<State>,
    components: Mutex<Components>,
    instances: Mutex<HashMap<String, Live>>,
}

/// The native stack one guest call may use, set explicitly rather than inherited.
///
/// wasmtime's own default is this same 512 KiB; naming it here is the point. Every guest call
/// runs on a `spawn_blocking` thread, whose stack tokio gives 2 MiB, so a wasm stack a quarter
/// of that leaves the host frames underneath it room and turns a runaway recursion into a
/// `stack overflow` trap — a refusal — rather than into this process dying on a real one.
pub const MAX_WASM_STACK_BYTES: usize = 512 * 1024;

/// The virtual address space reserved per linear memory, and the unmapped guard after it.
///
/// wasmtime's defaults are 4 GiB + 32 MiB per memory, which is right for a host that runs one
/// large module and wrong for this one: [`MAX_MEMORIES`] memories per store and
/// [`MAX_INSTANCES`] stores is up to a thousand memories, and a thousand four-gigabyte
/// reservations is four terabytes of address space asked of the kernel to run guests whose whole
/// ceiling is [`MAX_MEMORY_BYTES`]. Sixty-four mebibytes is proportionate to what a capability
/// actually gets granted; a guest whose grant exceeds it still grows past it, because
/// `memory_may_move` is left at its default and wasmtime re-maps and copies. The guard stays at
/// wasmtime's 32 MiB because that is what lets cranelift elide the bounds check on every offset
/// smaller than it — shrinking it would buy address space back at the cost of a check on every
/// load and store.
pub const MEMORY_RESERVATION_BYTES: u64 = 64 * 1024 * 1024;
pub const MEMORY_GUARD_BYTES: u64 = 32 * 1024 * 1024;

/// The engine configuration, in one place so `doctor` can prove an engine is constructible
/// without building the rest of the host.
///
/// # Every proposal this world does not need is off
///
/// wasmtime 48 enables, by default, every proposal it considers stable — which in 48 means the
/// whole of "WASM 3" plus the component model: relaxed SIMD, tail calls, typed function
/// references, extended const, multi-memory, memory64 and more. The v1 capability world is three
/// functions over strings. None of that is needed, all of it is compiler surface a component
/// nobody trusts can reach, and one of them — **relaxed SIMD** — is nondeterministic by design:
/// `f32x4.relaxed_madd` may or may not fuse the multiply and add depending on the host CPU, so
/// the same capability on two nodes can disagree. That contradicts D4, which is the reason this
/// list is enforced rather than assumed.
///
/// Disabled here, each by name:
/// relaxed SIMD, tail calls, typed function references, extended const, multi-memory, memory64,
/// GC, threads and shared-everything threads, exceptions (both the current and the legacy
/// proposal), stack switching, wide arithmetic, custom page sizes, memory control, and every
/// optional component-model extension — async (with its stackful and more-builtins variants),
/// threading, error contexts, GC, `map`, memory64, fixed-length lists, `implements`, values, and
/// nested names.
///
/// Four of those — threads, exceptions, GC types and component-model async — are *also* off
/// because the cargo features that would implement them are absent from `Cargo.toml`, which is
/// why wasmtime does not even expose a setter for them in this build. They are disabled here
/// through the low-level [`Config::wasm_features`] anyway: a feature that is off because
/// somebody did not enable a cargo feature is off by omission, and this file should say no on
/// purpose.
///
/// Left **on**, deliberately: the component model itself; SIMD, multi-value, bulk memory,
/// reference types, sign extension, saturating float conversion and mutable globals — the
/// deterministic core a real toolchain emits, and what `wasm32-wasip2` produces for the
/// reference guest. Turning those off would refuse guests this helper exists to run.
pub fn config() -> Config {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    config.epoch_interruption(true);

    // Cranelift's optimisation level, set explicitly and left where wasmtime puts it.
    // Measured on the worst component this helper will admit (20 000 functions, just under
    // 4 MiB of code) on the release build: `None` 1.00 s, `Speed` 1.19 s, `SpeedAndSize`
    // 1.22 s. Sixteen per cent off a compile that happens once per component, in exchange for
    // unoptimised code in every call that component ever answers, is not a trade this world —
    // JSON in, JSON out, per message — should take.
    config.cranelift_opt_level(OptLevel::Speed);

    // Bounds that have defaults, named rather than inherited.
    config.max_wasm_stack(MAX_WASM_STACK_BYTES);
    config.memory_reservation(MEMORY_RESERVATION_BYTES);
    config.memory_reservation_for_growth(MEMORY_RESERVATION_BYTES);
    config.memory_guard_size(MEMORY_GUARD_BYTES);

    // Proposals with a setter in this build.
    config.wasm_relaxed_simd(false);
    config.wasm_tail_call(false);
    config.wasm_extended_const(false);
    config.wasm_multi_memory(false);
    config.wasm_memory64(false);
    config.wasm_gc(false);
    config.wasm_shared_everything_threads(false);
    config.wasm_stack_switching(false);
    config.wasm_wide_arithmetic(false);
    config.wasm_custom_page_sizes(false);
    config.wasm_component_model_error_context(false);
    config.wasm_component_model_gc(false);
    config.wasm_component_model_map(false);
    config.wasm_component_model_memory64(false);
    config.wasm_component_model_fixed_length_lists(false);
    config.wasm_component_model_implements(false);

    // Proposals with no usable named setter in this build: either the cargo feature behind it is
    // absent (so wasmtime compiles the setter out) or the setter is deprecated. Off already, in
    // most cases; said out loud, in all of them.
    for feature in [
        WasmFeatures::FUNCTION_REFERENCES,
        WasmFeatures::THREADS,
        WasmFeatures::EXCEPTIONS,
        WasmFeatures::LEGACY_EXCEPTIONS,
        WasmFeatures::GC_TYPES,
        WasmFeatures::MEMORY_CONTROL,
        WasmFeatures::CM_ASYNC,
        WasmFeatures::CM_ASYNC_STACKFUL,
        WasmFeatures::CM_MORE_ASYNC_BUILTINS,
        WasmFeatures::CM_THREADING,
        WasmFeatures::CM_VALUES,
        WasmFeatures::CM_NESTED_NAMES,
    ] {
        config.wasm_features(feature, false);
    }

    config
}

impl Host {
    /// Builds the engine, defines the world's one import, and starts the epoch ticker.
    ///
    /// The ticker is a detached thread holding its own handle on the engine, so it outlives
    /// every store and is stopped by the process exiting. That is the intended lifetime: a
    /// helper with no ticker is a helper whose deadlines do not fire, which would be worse than
    /// a helper that will not start.
    pub fn new() -> wasmtime::Result<Host> {
        let engine = Engine::new(&config())?;

        let ticker = engine.clone();
        std::thread::Builder::new()
            .name("ouro-wasm-epoch".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                ticker.increment_epoch();
            })?;

        let mut linker = Linker::<State>::new(&engine);
        linker.root().func_wrap(
            world::LOG,
            |mut store: StoreContextMut<'_, State>, (level, message): (String, String)| {
                // The daemon's logger, for now, is this process's stderr — which is what the
                // Elixir pool reads. Both halves are bounded and stripped of control characters
                // so a guest cannot forge log lines, and the per-call budget is what stops a
                // guest from writing until the pipe blocks: neither fuel nor the epoch deadline
                // is checked while the guest is inside this function. See the module header.
                let state = store.data_mut();
                let line = if state.logs_remaining > 0 {
                    state.logs_remaining -= 1;
                    format!(
                        "ouro-wasm: guest {} [{}] {}",
                        state.instance,
                        bounded(&level, MAX_LOG_LEVEL_BYTES),
                        bounded(&message, MAX_LOG_MESSAGE_BYTES),
                    )
                } else if !state.log_budget_reported {
                    state.log_budget_reported = true;
                    format!(
                        "ouro-wasm: guest {} [warn] log budget of {MAX_LOG_LINES_PER_CALL} \
                         lines spent; dropping the rest of this call's",
                        state.instance
                    )
                } else {
                    return Ok(());
                };

                // Deliberately not `eprintln!`, which panics when the write fails. An owner
                // that closed this pipe is not a reason to unwind through a wasm frame.
                let _ = writeln!(std::io::stderr(), "{line}");
                state.log_lines_written = state.log_lines_written.saturating_add(1);
                Ok(())
            },
        )?;

        Ok(Host {
            engine,
            linker,
            components: Mutex::new(Components::new()),
            instances: Mutex::new(HashMap::new()),
        })
    }

    /// `inspect`: what these bytes are, without admitting them to anything.
    ///
    /// `shape` is the census [`shape::check`] already took on the way to the compiler, reported
    /// rather than discarded. It is the one part of admission an author cannot otherwise see:
    /// `doctor` names the ceilings and this names the readings, so `ouro wasm inspect` can put
    /// the two beside each other instead of leaving a refusal to be discovered. Reporting a
    /// measurement decides nothing — the same `check` in the same place still refuses the same
    /// components, and `inspect` still admits nothing to either table.
    pub fn inspect(&self, params: &Value) -> Result<Value, Refusal> {
        let path = required_str(params, "path")?;
        let bytes = read_component(path)?;
        let sha256 = sha256_hex(&bytes);
        let (component, census) = self.compile_measured(&bytes)?;
        let (imports, exports) = self.declared_names(&component);

        Ok(json!({
            "sha256": sha256,
            "world": world::identify(&component, &self.engine),
            "imports": imports,
            "exports": exports,
            "size": bytes.len(),
            "shape": shape_report(&census),
        }))
    }

    /// `load`: admit bytes to the component cache under the sha they actually hash to.
    ///
    /// The sha is recomputed from what was read and compared *before* anything is compiled: a
    /// mismatch means the file on disk is not the file that was signed, and the cheapest
    /// correct response to that is to do no work at all.
    ///
    /// A full cache is looked at twice. Once here, before the file is read, so a cache with
    /// nothing evictable refuses without spending a compile; and again at the insert, where the
    /// eviction actually happens, so the bound is enforced where it matters rather than trusted
    /// from a check a few hundred milliseconds earlier.
    pub fn load(&self, params: &Value) -> Result<Value, Refusal> {
        let expected = required_str(params, "sha256")?.to_ascii_lowercase();
        let path = required_str(params, "path")?;

        {
            let mut components = self.components.lock().expect("components lock");
            if let Some(loaded) = components.touch(&expected) {
                return Ok(json!({
                    "sha256": echo(&expected),
                    "world": loaded.world,
                    "imports": loaded.imports,
                    "exports": loaded.exports,
                    "size": loaded.size,
                    "cached": true,
                    "evicted": [],
                }));
            }
            if components.full() && components.victim(&self.pinned()).is_none() {
                return Err(nothing_evictable());
            }
        }

        let bytes = read_component(path)?;
        let actual = sha256_hex(&bytes);
        if actual != expected {
            return Err(refusal::refuse(
                refusal::SHA_MISMATCH,
                format!(
                    "{} hashes to {actual}, not the requested {}",
                    echo(path),
                    echo(&expected)
                ),
            ));
        }

        let component = self.compile(&bytes)?;
        world::check(&component, &self.engine)?;
        let (imports, exports) = self.declared_names(&component);

        let loaded = Loaded {
            component,
            world: world::ID,
            size: bytes.len(),
            imports,
            exports,
            last_used: 0,
        };
        // The same shape `inspect` reports, so the owner can cross-check a load against the
        // signed manifest without a second round trip (docs/WASM.md §7.5) — plus what this
        // load cost somebody else, so a reclaim is never a fault the owner cannot explain.
        let mut answer = json!({
            "sha256": actual,
            "world": loaded.world,
            "imports": loaded.imports,
            "exports": loaded.exports,
            "size": loaded.size,
            "cached": false,
        });

        let mut components = self.components.lock().expect("components lock");
        let mut evicted = Vec::new();
        while components.full() {
            match components.victim(&self.pinned()) {
                Some(sha) => {
                    components.evict(&sha);
                    evicted.push(echo(&sha));
                }
                None => return Err(nothing_evictable()),
            }
        }
        components.insert(actual, loaded);
        answer["evicted"] = json!(evicted);
        Ok(answer)
    }

    /// `instantiate`: a fresh store under the requested bounds, linked, and `init` run inside
    /// it. Nothing is retained unless all of that succeeded.
    pub fn instantiate(&self, params: &Value) -> Result<Value, Refusal> {
        let name = required_str(params, "instance")?.to_string();
        let sha256 = required_str(params, "sha256")?.to_ascii_lowercase();
        let config = required_str(params, "config")?.to_string();
        let limits = Limits::parse(params)?;

        {
            let instances = self.instances.lock().expect("instances lock");
            if instances.contains_key(&name) {
                return Err(refusal::refuse(
                    refusal::INSTANCE_EXISTS,
                    format!(
                        "instance `{}` is live; drop it before instantiating over it",
                        echo(&name)
                    ),
                ));
            }
            if instances.len() >= MAX_INSTANCES {
                return Err(refusal::refuse(
                    refusal::TOO_MANY_INSTANCES,
                    format!(
                        "this helper holds {MAX_INSTANCES} live instances, which is all it will \
                         hold; drop one before standing another up"
                    ),
                ));
            }
        }

        let component = {
            let mut components = self.components.lock().expect("components lock");
            let loaded = components.touch(&sha256).ok_or_else(|| {
                refusal::refuse(
                    refusal::UNKNOWN_COMPONENT,
                    format!("no component {} has been loaded", echo(&sha256)),
                )
            })?;
            loaded.component.clone()
        };

        let mut store = Store::new(
            &self.engine,
            State {
                instance: echo(&name),
                memory_bytes: usize::try_from(limits.memory_bytes).unwrap_or(usize::MAX),
                memory_total: 0,
                memory_denied: false,
                logs_remaining: MAX_LOG_LINES_PER_CALL,
                log_lines_written: 0,
                log_budget_reported: false,
            },
        );
        store.limiter(|state| state);
        arm(&mut store, limits);

        let instance = self
            .linker
            .instantiate(&mut store, &component)
            .map_err(|error| {
                classify(&error, &store, refusal::INSTANTIATE_FAILED, "instantiate")
            })?;

        let describe = instance
            .get_typed_func::<(), (String,)>(&mut store, world::DESCRIBE)
            .map_err(|error| world_gap(world::DESCRIBE, &error))?;
        let handle = instance
            .get_typed_func::<(String,), (Result<String, String>,)>(
                &mut store,
                world::HANDLE_MESSAGE,
            )
            .map_err(|error| world_gap(world::HANDLE_MESSAGE, &error))?;
        let init = instance
            .get_typed_func::<(String,), (Result<(), String>,)>(&mut store, world::INIT)
            .map_err(|error| world_gap(world::INIT, &error))?;

        // `init` is guest code and runs under the same bounds as any message. A trap here
        // retains nothing: there is no instance to poison because there is no instance yet.
        let outcome = init
            .call(&mut store, (config,))
            .map_err(|error| classify(&error, &store, refusal::TRAPPED, "init"))?;
        let fuel_used = fuel_used(&store, limits);

        match outcome {
            (Ok(()),) => {}
            (Err(message),) => {
                return Err(refusal::refuse(
                    refusal::GUEST_ERROR,
                    format!(
                        "init refused its config: {}",
                        bounded(&message, MAX_ERROR_BYTES)
                    ),
                ))
            }
        }

        let log_lines = store.data().log_lines_written;
        self.instances.lock().expect("instances lock").insert(
            name.clone(),
            Live {
                store,
                describe,
                handle,
                limits,
                sha256,
            },
        );

        Ok(json!({ "instance": echo(&name), "fuel_used": fuel_used, "log_lines": log_lines }))
    }

    /// `call`: one message into a live instance, under freshly armed bounds.
    ///
    /// The instance is taken out of the table for the duration and put back only if it is still
    /// trustworthy: a trap leaves it out, which is the poisoning described in the module
    /// header, and the next `call` on that name gets `unknown_instance`.
    pub fn call(&self, params: &Value) -> Result<Value, Refusal> {
        let name = required_str(params, "instance")?.to_string();
        let export = required_str(params, "export")?.to_string();
        let payload = required_str(params, "payload")?.to_string();

        let mut live = self
            .instances
            .lock()
            .expect("instances lock")
            .remove(&name)
            .ok_or_else(|| {
                refusal::refuse(
                    refusal::UNKNOWN_INSTANCE,
                    format!("no live instance `{}`", echo(&name)),
                )
            })?;

        if export != world::DESCRIBE && export != world::HANDLE_MESSAGE {
            // Not the guest's fault and not a reason to poison it: the dispatch table is
            // closed, so put it back and refuse the name.
            self.restore(name, live);
            return Err(refusal::refuse(
                refusal::UNKNOWN_EXPORT,
                format!(
                    "`{}` is not callable; world {} exports {} and {}",
                    echo(&export),
                    world::ID,
                    world::DESCRIBE,
                    world::HANDLE_MESSAGE
                ),
            ));
        }

        let limits = live.limits;
        arm(&mut live.store, limits);

        let outcome = if export == world::DESCRIBE {
            live.describe
                .call(&mut live.store, ())
                .map(|(text,)| Ok(text))
        } else {
            live.handle
                .call(&mut live.store, (payload,))
                .map(|(result,)| result)
        };

        let result = match outcome {
            Ok(result) => result,
            Err(error) => {
                let refusal = classify(&error, &live.store, refusal::TRAPPED, &export);
                drop(live);
                return Err(refusal);
            }
        };
        let fuel_used = fuel_used(&live.store, limits);
        let log_lines = live.store.data().log_lines_written;

        let answer = match result {
            Ok(payload) if payload.len() > MAX_RESULT_BYTES => Err(refusal::refuse(
                refusal::OVERSIZE_RESULT,
                format!(
                    "`{export}` returned {} bytes; the cap is {MAX_RESULT_BYTES}",
                    payload.len()
                ),
            )),
            Ok(payload) => Ok(json!({
                "payload": payload,
                "fuel_used": fuel_used,
                "log_lines": log_lines
            })),
            Err(message) => Err(refusal::refuse(
                refusal::GUEST_ERROR,
                bounded(&message, MAX_ERROR_BYTES),
            )),
        };

        // Everything above this line is the guest answering — badly, perhaps, but answering.
        // Its state is whatever it decided; the instance stays live.
        self.restore(name, live);
        answer
    }

    /// `drop`: idempotent, because the peer may be recovering from a refusal that already
    /// dropped this instance and must not have to care which.
    pub fn drop_instance(&self, params: &Value) -> Result<Value, Refusal> {
        let name = required_str(params, "instance")?;
        let dropped = self
            .instances
            .lock()
            .expect("instances lock")
            .remove(name)
            .is_some();
        Ok(json!({ "instance": echo(name), "dropped": dropped }))
    }

    /// How full each table is and what the cache has let go, for `doctor`.
    pub fn census(&self) -> Census {
        let (components, evictions, evicted) = {
            let components = self.components.lock().expect("components lock");
            (
                components.held.len(),
                components.evictions,
                components.recent.iter().cloned().collect(),
            )
        };
        let instances = self.instances.lock().expect("instances lock").len();
        Census {
            components,
            instances,
            evictions,
            evicted,
        }
    }

    /// The shas with a live instance, which eviction may not take. Read off the instance table
    /// each time rather than kept as a count beside each component: the table is small, and a
    /// count that every drop and every poisoning had to remember to decrement is exactly the
    /// bookkeeping that drifts. Taken with the components lock held, and only ever in that
    /// order; nothing else holds both.
    fn pinned(&self) -> HashSet<String> {
        self.instances
            .lock()
            .expect("instances lock")
            .values()
            .map(|live| live.sha256.clone())
            .collect()
    }

    /// The names a component declares, cut to what a result may carry back: at most
    /// [`MAX_REPORTED_NAMES`] of them, each at most [`MAX_ECHO_BYTES`] long. [`world::check`]
    /// reads the undecorated list, so nothing here is load-bearing for admission.
    fn declared_names(&self, component: &Component) -> (Vec<String>, Vec<String>) {
        let (imports, exports) = world::names(component, &self.engine);
        let cut = |names: Vec<String>| -> Vec<String> {
            names
                .iter()
                .take(MAX_REPORTED_NAMES)
                .map(|name| echo(name))
                .collect()
        };
        (cut(imports), cut(exports))
    }

    /// The one place `Component::new` is called, and therefore the one place the structural
    /// bound has to hold. [`shape::check`] runs first and refuses `component_too_complex`
    /// without the compiler ever seeing the bytes; see [`crate::shape`] for why a bound after
    /// the fact — a watchdog thread, a deadline — could not have done this.
    fn compile(&self, bytes: &[u8]) -> Result<Component, Refusal> {
        self.compile_measured(bytes)
            .map(|(component, _census)| component)
    }

    /// The same compile, keeping the census instead of dropping it. `inspect` is the only
    /// caller that wants it: this exists so the reading and the refusal come from one walk in
    /// one order, rather than from a second walk `inspect` could get out of step with.
    fn compile_measured(&self, bytes: &[u8]) -> Result<(Component, shape::Census), Refusal> {
        let census = shape::check(bytes)?;
        let component = Component::new(&self.engine, bytes).map_err(|error| {
            refusal::refuse(
                refusal::COMPILE_FAILED,
                bounded(&format!("{error:#}"), MAX_ERROR_BYTES),
            )
        })?;
        Ok((component, census))
    }

    fn restore(&self, name: String, live: Live) {
        self.instances
            .lock()
            .expect("instances lock")
            .insert(name, live);
    }
}

/// Arms every per-call bound on a store: fuel, the epoch deadline, the hostcall byte budget,
/// the log budget, and the memory-denial flag.
///
/// Called once at `instantiate` — so `init`, which is guest code, is bounded exactly as a
/// message is — and again before every `call`, so a budget is per message and never cumulative.
///
/// `memory_total` is deliberately *not* reset. Memories persist across calls; resetting the
/// running total would hand a guest a fresh whole ceiling on every message.
fn arm(store: &mut Store<State>, limits: Limits) {
    let state = store.data_mut();
    state.memory_denied = false;
    state.logs_remaining = MAX_LOG_LINES_PER_CALL;
    state.log_budget_reported = false;
    state.log_lines_written = 0;

    store
        .set_fuel(limits.fuel)
        .expect("fuel is enabled on this engine");
    store.set_epoch_deadline(limits.epoch_ticks());
    store.set_hostcall_fuel(MAX_HOSTCALL_BYTES);
}

fn fuel_used(store: &Store<State>, limits: Limits) -> u64 {
    limits.fuel.saturating_sub(store.get_fuel().unwrap_or(0))
}

/// Turns a wasmtime failure into the refusal that names what actually stopped the guest.
fn classify(
    error: &wasmtime::Error,
    store: &Store<State>,
    fallback: refusal::Kind,
    what: &str,
) -> Refusal {
    let detail = bounded(&format!("{error:#}"), MAX_ERROR_BYTES);
    let denied = store.data().memory_denied;

    let kind = match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => refusal::FUEL_EXHAUSTED,
        Some(Trap::Interrupt) => refusal::DEADLINE_EXCEEDED,
        Some(_) if denied => refusal::MEMORY_LIMIT,
        Some(_) => refusal::TRAPPED,
        None if denied => refusal::MEMORY_LIMIT,
        None => fallback,
    };

    refusal::refuse(kind, format!("{what}: {detail}"))
}

/// The one way a full cache is refused: every held component has a live instance, so there is
/// nothing eviction may take. The owner drops an instance, or waits for one to be dropped.
fn nothing_evictable() -> Refusal {
    refusal::refuse(
        refusal::TOO_MANY_COMPONENTS,
        format!(
            "this helper holds {MAX_COMPONENTS} components and every one of them has a live \
             instance; nothing can be evicted until an instance is dropped"
        ),
    )
}

/// A component that passed [`world::check`] at load but whose export cannot be typed here. This
/// should be unreachable; if it ever fires, the two checks have drifted and the honest answer
/// is that these bytes are not in this world.
fn world_gap(export: &str, error: &wasmtime::Error) -> Refusal {
    refusal::refuse(
        refusal::UNSUPPORTED_WORLD,
        format!(
            "export `{export}` does not have the signature world {} declares: {}",
            world::ID,
            bounded(&format!("{error:#}"), MAX_ERROR_BYTES)
        ),
    )
}

fn read_component(path: &str) -> Result<Vec<u8>, Refusal> {
    let unreadable = |detail: String| {
        refusal::refuse(
            refusal::UNREADABLE_COMPONENT,
            format!("{}: {detail}", echo(path)),
        )
    };

    // Before opening it, not after: opening a named pipe with no writer blocks in the kernel,
    // and a path is a peer-supplied string. `metadata` follows symlinks, so a link to a fifo is
    // caught here too. A component is a file; anything else is not a component.
    let metadata = std::fs::metadata(path).map_err(|error| unreadable(error.to_string()))?;
    if !metadata.is_file() {
        return Err(unreadable("not a regular file".to_string()));
    }

    let file = std::fs::File::open(path).map_err(|error| unreadable(error.to_string()))?;

    let mut bytes = Vec::new();
    // One byte past the cap, so an over-cap file is detected without being read whole.
    file.take(MAX_COMPONENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| unreadable(error.to_string()))?;

    if bytes.len() as u64 > MAX_COMPONENT_BYTES {
        return Err(unreadable(format!(
            "larger than the {MAX_COMPONENT_BYTES} byte cap"
        )));
    }
    Ok(bytes)
}

/// The census as `inspect` reports it. Every key here is the `doctor` limit key of the same
/// name without its `max_` prefix — `functions` against `max_functions`, `nesting_depth`
/// against `max_nesting_depth` — so a reading and its ceiling can be paired by name rather
/// than by a table somebody has to keep in step.
fn shape_report(census: &shape::Census) -> Value {
    json!({
        "functions": census.functions,
        "code_bytes": census.code_bytes,
        "types": census.types,
        "component_imports": census.imports,
        "component_exports": census.exports,
        "definitions": census.definitions,
        "segment_bytes": census.segment_bytes,
        "nesting_depth": census.depth,
        "core_modules": census.core_modules,
        "nested_components": census.nested_components,
        "sections": census.sections,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(DIGITS[(byte >> 4) as usize] as char);
        hex.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// A string the peer chose, cut down to what a refusal or a result may carry back. Every path,
/// sha, instance name and export name that leaves this file goes through here.
fn echo(text: &str) -> String {
    bounded(text, MAX_ECHO_BYTES)
}

/// Truncates on a character boundary and flattens every control character to a space, so a
/// string from a guest cannot forge a line break in whatever reads it.
fn bounded(text: &str, cap: usize) -> String {
    let mut out = String::with_capacity(text.len().min(cap));
    for character in text.chars() {
        if out.len() + character.len_utf8() > cap {
            out.push('…');
            break;
        }
        out.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    out
}

fn invalid_params(message: impl Into<String>) -> Refusal {
    refusal::refuse(refusal::INVALID_PARAMS, message)
}

fn required_str<'a>(params: &'a Value, key: &str) -> Result<&'a str, Refusal> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params(format!("{key} is required and must be a string")))
}

fn required_u64(params: &Value, key: &str) -> Result<u64, Refusal> {
    params.get(key).and_then(Value::as_u64).ok_or_else(|| {
        invalid_params(format!(
            "limits.{key} is required and must be a whole number"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(fuel: u64, memory_bytes: u64, deadline_ms: u64) -> Value {
        json!({ "limits": { "fuel": fuel, "memory_bytes": memory_bytes, "deadline_ms": deadline_ms } })
    }

    #[test]
    fn all_three_limits_are_required() {
        for missing in ["fuel", "memory_bytes", "deadline_ms"] {
            let mut params = limits(1_000, MIN_MEMORY_BYTES, 100);
            params["limits"].as_object_mut().unwrap().remove(missing);
            let error = Limits::parse(&params).unwrap_err();
            assert_eq!(
                error.refusal, "invalid_params",
                "omitting {missing} must be a malformed request, not a defaulted one"
            );
        }

        let error = Limits::parse(&json!({})).unwrap_err();
        assert_eq!(error.refusal, "invalid_params");
    }

    #[test]
    fn limits_are_bounded_at_both_ends() {
        let cases = [
            (0, MIN_MEMORY_BYTES, 100),
            (MAX_FUEL + 1, MIN_MEMORY_BYTES, 100),
            (1_000, MIN_MEMORY_BYTES - 1, 100),
            (1_000, MAX_MEMORY_BYTES + 1, 100),
            (1_000, MIN_MEMORY_BYTES, 0),
            (1_000, MIN_MEMORY_BYTES, MAX_DEADLINE_MS + 1),
        ];
        for (fuel, memory_bytes, deadline_ms) in cases {
            let error = Limits::parse(&limits(fuel, memory_bytes, deadline_ms)).unwrap_err();
            assert_eq!(
                error.refusal, "limits_out_of_range",
                "({fuel}, {memory_bytes}, {deadline_ms}) must be refused"
            );
        }
    }

    #[test]
    fn limits_in_range_parse() {
        let parsed = Limits::parse(&limits(5_000, 2 * MIN_MEMORY_BYTES, 250)).unwrap();
        assert_eq!(
            parsed,
            Limits {
                fuel: 5_000,
                memory_bytes: 2 * MIN_MEMORY_BYTES,
                deadline_ms: 250
            }
        );
    }

    #[test]
    fn a_deadline_is_at_least_as_many_ticks_as_it_asked_for() {
        for deadline_ms in [1, 9, 10, 11, 100, MAX_DEADLINE_MS] {
            let limits = Limits {
                fuel: 1,
                memory_bytes: MIN_MEMORY_BYTES,
                deadline_ms,
            };
            let ticks = limits.epoch_ticks();
            assert!(
                ticks * EPOCH_TICK_MS >= deadline_ms,
                "{deadline_ms}ms rounded down to {ticks} ticks"
            );
            assert!(
                ticks * EPOCH_TICK_MS <= deadline_ms + 2 * EPOCH_TICK_MS,
                "{deadline_ms}ms rounded up to {ticks} ticks, which overshoots the promise"
            );
        }
    }

    #[test]
    fn sha256_is_the_usual_one() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn log_text_cannot_forge_a_line() {
        let forged = bounded("first\nouro-wasm: second", MAX_LOG_MESSAGE_BYTES);
        assert_eq!(forged, "first ouro-wasm: second");
        assert!(!forged.contains('\n'));
    }

    #[test]
    fn log_text_is_truncated_on_a_character_boundary() {
        assert_eq!(bounded("ααααα", 5), "αα…");
    }

    /// D5's structural half, reached by going around the policy half.
    ///
    /// [`world::check`] refuses an undeclared import at `load`, before anything is compiled, so
    /// through the six methods the linker's own refusal is unobservable — which is the intended
    /// layering and not a reason to leave it untested. This puts a component wanting a clock
    /// straight into the cache and instantiates it: the linker defines `log` and nothing else,
    /// so there is nothing for `now` to bind to and the instance is never created. A bug in
    /// `world` cannot become authority.
    #[test]
    fn the_linker_refuses_an_import_it_does_not_define() {
        let host = Host::new().expect("an engine on this host");
        let bytes = wat::parse_str(r#"(component (import "now" (func (result u64))))"#)
            .expect("the probe component assembles");
        let component = Component::new(&host.engine, &bytes).expect("it is a valid component");
        let sha256 = sha256_hex(&bytes);

        host.components.lock().expect("components lock").insert(
            sha256.clone(),
            Loaded {
                component,
                world: world::UNKNOWN,
                size: bytes.len(),
                imports: vec!["now".to_string()],
                exports: Vec::new(),
                last_used: 0,
            },
        );

        let refusal = host
            .instantiate(&json!({
                "instance": "clock",
                "sha256": sha256,
                "config": "",
                "limits": {
                    "fuel": 1_000_000,
                    "memory_bytes": MIN_MEMORY_BYTES,
                    "deadline_ms": 1_000,
                },
            }))
            .expect_err("an undefined import cannot be linked");

        assert_eq!(refusal.refusal, "instantiate_failed");
        assert!(
            refusal.message.contains("now"),
            "the refusal must name the import that could not be bound: {}",
            refusal.message
        );
        assert!(
            host.instances.lock().expect("instances lock").is_empty(),
            "a failed instantiation must retain nothing"
        );
    }

    /// A cache holding `shas`, inserted in that order, each entry a compiled empty component.
    fn cache_with(shas: &[&str]) -> Components {
        let engine = Engine::new(&config()).expect("an engine on this host");
        let bytes = wat::parse_str("(component)").expect("the empty component assembles");
        let component = Component::new(&engine, &bytes).expect("it is a valid component");
        let mut cache = Components::new();
        for sha in shas {
            cache.insert(
                sha.to_string(),
                Loaded {
                    component: component.clone(),
                    world: world::UNKNOWN,
                    size: bytes.len(),
                    imports: Vec::new(),
                    exports: Vec::new(),
                    last_used: 0,
                },
            );
        }
        cache
    }

    fn pinned(shas: &[&str]) -> HashSet<String> {
        shas.iter().map(|sha| sha.to_string()).collect()
    }

    #[test]
    fn eviction_takes_the_least_recently_wanted_and_never_a_pinned_one() {
        let mut cache = cache_with(&["a", "b", "c"]);
        assert_eq!(cache.victim(&pinned(&[])).as_deref(), Some("a"));

        // Wanting `a` again makes `b` the one nobody has asked for longest.
        assert!(cache.touch("a").is_some());
        assert_eq!(cache.victim(&pinned(&[])).as_deref(), Some("b"));

        // A pinned `b` is passed over, however old.
        assert_eq!(cache.victim(&pinned(&["b"])).as_deref(), Some("c"));

        // With everything pinned there is no victim at all.
        assert_eq!(cache.victim(&pinned(&["a", "b", "c"])), None);

        // A miss is not a want.
        assert!(cache.touch("never-held").is_none());
        assert_eq!(cache.held.len(), 3);
    }

    #[test]
    fn the_eviction_log_is_bounded_and_the_count_is_not() {
        let shas: Vec<String> = (0..MAX_EVICTION_LOG + 4)
            .map(|n| format!("{n:064}"))
            .collect();
        let refs: Vec<&str> = shas.iter().map(String::as_str).collect();
        let mut cache = cache_with(&refs);

        for sha in &shas {
            cache.evict(sha);
        }
        assert!(cache.held.is_empty());
        assert_eq!(cache.evictions as usize, shas.len());
        assert_eq!(cache.recent.len(), MAX_EVICTION_LOG);
        assert_eq!(cache.recent.front(), Some(&shas[4]));
        assert_eq!(cache.recent.back(), shas.last());

        // Evicting a sha that is not held is not an eviction, and is not logged as one.
        cache.evict("never-held");
        assert_eq!(cache.evictions as usize, shas.len());
        assert_eq!(cache.recent.len(), MAX_EVICTION_LOG);
    }
}
