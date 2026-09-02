//! The guests the containment proofs are run against, written as WebAssembly *components* in
//! the text format and assembled here at test time.
//!
//! Hand-written rather than produced by `cargo component`: a checked-in `.wasm` is an opaque
//! blob nobody reviews, and a build script that shells out to a wasm toolchain makes the suite
//! unrunnable on a machine that has not installed one. The cost is that the canonical ABI is
//! spelled out by hand, so it is spelled out with comments.
//!
//! # The canonical ABI, in the shapes this world needs
//!
//! Component-level `string` is not a core wasm type. Lifting one *into* a guest means the host
//! copies bytes into the guest's linear memory through the guest's exported `realloc` and then
//! calls the core function with `(ptr, len)`. Lifting one *out* works the other way: a result
//! that does not fit in a single core value — a `string` is two words, a
//! `result<string, string>` is three — comes back as one `i32` pointing at a *return area* the
//! guest allocated for itself:
//!
//! | world signature | core signature | return area |
//! |---|---|---|
//! | `describe: func() -> string` | `() -> i32` | `{ptr: i32, len: i32}` |
//! | `init: func(string) -> result<_, string>` | `(i32, i32) -> i32` | `{tag: i32, ptr: i32, len: i32}` |
//! | `handle-message: func(string) -> result<string, string>` | `(i32, i32) -> i32` | `{tag: i32, ptr: i32, len: i32}` |
//!
//! `tag` is 0 for `ok` and 1 for `err`; the two words after it are the payload string, and go
//! unread when the `ok` case carries nothing.
//!
//! The `log` import needs a second piece of plumbing. Lowering a host function so the guest can
//! call it needs the guest's memory and `realloc` — but instantiating the guest needs the
//! lowered function. That circle is why [`echo`], the only guest here that calls `log`, is
//! split into two core modules: `$alloc` owns the memory and the allocator, the lowering is
//! done against those, and `$guest` imports all three.

#![allow(dead_code)]

/// Linear memory and a bump allocator meeting the canonical ABI's `realloc` contract. It never
/// frees — a guest in these tests answers a handful of calls and is then dropped — and it traps
/// when growth is refused, which is how a memory cap becomes an observable trap rather than a
/// silently wrong answer.
const ALLOC: &str = r#"
    (memory (export "memory") 1)
    (global $next (mut i32) (i32.const 1024))
    (func $realloc (export "realloc")
      (param $old i32) (param $old_size i32) (param $align i32) (param $new_size i32)
      (result i32)
      (local $ret i32)
      ;; round the bump pointer up to $align, which the ABI guarantees is a power of two
      (global.set $next
        (i32.and (i32.add (global.get $next) (i32.sub (local.get $align) (i32.const 1)))
                 (i32.sub (i32.const 0) (local.get $align))))
      (local.set $ret (global.get $next))
      (global.set $next (i32.add (global.get $next) (local.get $new_size)))
      ;; one page at a time until the bump pointer is back inside the memory
      (loop $grow
        (if (i32.gt_u (global.get $next) (i32.mul (memory.size) (i32.const 65536)))
          (then
            (if (i32.eq (memory.grow (i32.const 1)) (i32.const -1)) (then unreachable))
            (br $grow))))
      (local.get $ret))
"#;

/// An `init` that accepts any config and returns `ok` immediately.
const TRIVIAL_INIT: &str = r#"
    (func (export "init") (param i32 i32) (result i32)
      (local $ret i32)
      (local.set $ret (call $realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 12)))
      (i32.store (local.get $ret) (i32.const 0))
      (local.get $ret))
"#;

/// `describe` and `init` for a guest that has nothing interesting to say in either: `describe`
/// answers with `name`, and `init` is whatever the caller supplied.
fn trivial_prelude(name: &str, init: &str) -> String {
    let len = name.len();
    format!(
        r#"
    (data (i32.const 16) "{name}")
    (func (export "describe") (result i32)
      (local $ret i32)
      (local.set $ret (call $realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 8)))
      (i32.store (local.get $ret) (i32.const 16))
      (i32.store offset=4 (local.get $ret) (i32.const {len}))
      (local.get $ret))
{init}
"#
    )
}

/// The component wrapper: alias memory, `realloc` and the three core functions out of the
/// instances that hold them, then lift each export with the world's exact signature.
fn lift(memory_instance: &str, func_instance: &str) -> String {
    format!(
        r#"
  (alias core export {memory_instance} "memory" (core memory $mem))
  (alias core export {memory_instance} "realloc" (core func $realloc))
  (alias core export {func_instance} "describe" (core func $c_describe))
  (alias core export {func_instance} "init" (core func $c_init))
  (alias core export {func_instance} "handle_message" (core func $c_handle))

  (func (export "describe") (result string)
    (canon lift (core func $c_describe) (memory $mem) (realloc $realloc)))
  (func (export "init") (param "config" string) (result (result (error string)))
    (canon lift (core func $c_init) (memory $mem) (realloc $realloc)))
  (func (export "handle-message") (param "body" string) (result (result string (error string)))
    (canon lift (core func $c_handle) (memory $mem) (realloc $realloc)))
"#
    )
}

/// A guest that imports nothing: one core module holding the allocator, all three exports and
/// whatever `inner` adds to that module, plus whatever `extra` adds to the component
/// (unreferenced core instances, for the guests that exist to be expensive rather than to work).
fn solo_parts(name: &str, init: &str, handle_message: &str, inner: &str, extra: &str) -> Vec<u8> {
    let prelude = trivial_prelude(name, init);
    let lift = lift("$i", "$i");
    assemble(&format!(
        r#"(component
  (core module $m{ALLOC}{prelude}{handle_message}{inner}
  )
  (core instance $i (instantiate $m)){extra}{lift})"#
    ))
}

fn solo(name: &str, handle_message: &str) -> Vec<u8> {
    solo_parts(name, TRIVIAL_INIT, handle_message, "", "")
}

/// A guest in this world with `inner` spliced into its core module: an extra function, an extra
/// table, an opcode from a proposal the engine is supposed to have turned off.
fn solo_with(name: &str, inner: &str) -> Vec<u8> {
    solo_parts(name, TRIVIAL_INIT, SINK_HANDLE, inner, "")
}

/// A `handle-message` that answers `ok` with a fixed two-byte string whatever it is given. The
/// guest for asking what the *inbound* direction costs, since its reply cannot be the reason a
/// call succeeds or fails.
const SINK_HANDLE: &str = r#"
    (data (i32.const 64) "ok")
    (func (export "handle_message") (param i32 i32) (result i32)
      (local $ret i32)
      (local.set $ret (call $realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 12)))
      (i32.store (local.get $ret) (i32.const 0))
      (i32.store offset=4 (local.get $ret) (i32.const 64))
      (i32.store offset=8 (local.get $ret) (i32.const 2))
      (local.get $ret))
"#;

fn assemble(text: &str) -> Vec<u8> {
    wat::parse_str(text).unwrap_or_else(|error| panic!("guest does not assemble: {error}\n{text}"))
}

/// The happy-path guest: it keeps the `init` config, answers `handle-message` with
/// `"<config>|<body>"`, and calls the one import the world allows on every message. This is the
/// guest that proves `log` reaches the helper's stderr, so it carries the two-module split.
pub fn echo() -> Vec<u8> {
    with_log(ECHO_HANDLE)
}

/// A guest that calls `log` a thousand times per message before answering. The host cannot
/// interrupt a guest that is inside a host call, so what has to stop this is the helper's own
/// per-call log budget — and what proves the budget is that this guest's call *returns*.
pub fn chatty() -> Vec<u8> {
    with_log(
        r#"
    (func (export "handle_message") (param $ptr i32) (param $len i32) (result i32)
      (local $i i32)
      (local $ret i32)
      (loop $more
        (call $log (i32.const 96) (i32.const 4) (i32.const 112) (i32.const 14))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $more (i32.lt_u (local.get $i) (i32.const 1000))))
      (local.set $ret (call $realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 12)))
      (i32.store (local.get $ret) (i32.const 0))
      (i32.store offset=4 (local.get $ret) (i32.const 16))
      (i32.store offset=8 (local.get $ret) (i32.const 31))
      (local.get $ret))
"#,
    )
}

/// `handle-message` for [`echo`]: log once, then answer `"<config>|<body>"`.
const ECHO_HANDLE: &str = r#"
    (func (export "handle_message") (param $ptr i32) (param $len i32) (result i32)
      (local $out i32)
      (local $total i32)
      (local $ret i32)
      (call $log (i32.const 96) (i32.const 4) (i32.const 112) (i32.const 14))
      (local.set $total
        (i32.add (i32.add (global.get $cfg_len) (i32.const 1)) (local.get $len)))
      (local.set $out
        (call $realloc (i32.const 0) (i32.const 0) (i32.const 1) (local.get $total)))
      (memory.copy (local.get $out) (global.get $cfg) (global.get $cfg_len))
      (i32.store8 (i32.add (local.get $out) (global.get $cfg_len)) (i32.const 124))
      (memory.copy
        (i32.add (i32.add (local.get $out) (global.get $cfg_len)) (i32.const 1))
        (local.get $ptr)
        (local.get $len))
      (local.set $ret (call $realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 12)))
      (i32.store (local.get $ret) (i32.const 0))
      (i32.store offset=4 (local.get $ret) (local.get $out))
      (i32.store offset=8 (local.get $ret) (local.get $total))
      (local.get $ret))
"#;

/// A guest that imports `log`, with the two-module split the lowering circularity forces:
/// `$alloc` owns the memory and the allocator, the lowering is done against those, and `$guest`
/// imports all three. `handle_message` is the caller's.
fn with_log(handle_message: &str) -> Vec<u8> {
    let lift = lift("$a", "$i");
    assemble(&format!(
        r#"(component
  (import "log" (func $log (param "level" string) (param "message" string)))

  (core module $alloc{ALLOC}
  )
  (core instance $a (instantiate $alloc))
  (alias core export $a "memory" (core memory $amem))
  (alias core export $a "realloc" (core func $arealloc))
  (core func $log_lowered (canon lower (func $log) (memory $amem) (realloc $arealloc)))

  (core module $guest
    (import "alloc" "memory" (memory 1))
    (import "alloc" "realloc" (func $realloc (param i32 i32 i32 i32) (result i32)))
    (import "host" "log" (func $log (param i32 i32 i32 i32)))

    ;; constants live below the allocator's bump floor of 1024
    (data (i32.const 16) "ouroboros:capability@0.1.0 echo")
    (data (i32.const 96) "info")
    (data (i32.const 112) "handle-message")

    (global $cfg (mut i32) (i32.const 0))
    (global $cfg_len (mut i32) (i32.const 0))

    (func (export "describe") (result i32)
      (local $ret i32)
      (local.set $ret (call $realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 8)))
      (i32.store (local.get $ret) (i32.const 16))
      (i32.store offset=4 (local.get $ret) (i32.const 31))
      (local.get $ret))

    ;; keep a private copy of the config: instance-held state is what makes the reply below
    ;; evidence that `init` ran, and ran on this instance
    (func (export "init") (param $ptr i32) (param $len i32) (result i32)
      (local $ret i32)
      (global.set $cfg
        (call $realloc (i32.const 0) (i32.const 0) (i32.const 1) (local.get $len)))
      (global.set $cfg_len (local.get $len))
      (memory.copy (global.get $cfg) (local.get $ptr) (local.get $len))
      (local.set $ret (call $realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 12)))
      (i32.store (local.get $ret) (i32.const 0))
      (local.get $ret))

{handle_message}
  )
  (core instance $i (instantiate $guest
    (with "alloc" (instance $a))
    (with "host" (instance (export "log" (func $log_lowered)))))){lift})"#
    ))
}

/// A guest whose `handle-message` never returns. Under a small fuel budget it exhausts fuel;
/// under a large one it runs until the epoch deadline interrupts it. One guest proves both,
/// which is the point: the two bounds are independent and either alone must stop it.
pub fn spin() -> Vec<u8> {
    solo(
        "spin",
        r#"
    (func (export "handle_message") (param i32 i32) (result i32)
      (loop $forever (br $forever))
      (unreachable))
"#,
    )
}

/// A guest whose `handle-message` grows linear memory until the host refuses, then traps. The
/// trap is the guest's own `unreachable`: a memory cap does not kill a guest, it makes
/// `memory.grow` return -1, and a guest that cannot handle a failed allocation ends the only
/// way it can.
pub fn grow() -> Vec<u8> {
    solo(
        "grow",
        r#"
    (func (export "handle_message") (param i32 i32) (result i32)
      (local $i i32)
      (loop $more
        (if (i32.eq (memory.grow (i32.const 16)) (i32.const -1)) (then (unreachable)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $more (i32.lt_u (local.get $i) (i32.const 4096))))
      (unreachable))
"#,
    )
}

/// A guest whose `handle-message` returns a string of `bytes` NUL characters. Memory starts
/// zeroed and NUL is valid UTF-8, so the helper lifts the whole thing successfully and then has
/// to decide whether it fits the reply cap — which is exactly the decision under test.
pub fn oversize(bytes: u32) -> Vec<u8> {
    solo(
        "oversize",
        &format!(
            r#"
    (func (export "handle_message") (param i32 i32) (result i32)
      (local $out i32)
      (local $ret i32)
      (local.set $out
        (call $realloc (i32.const 0) (i32.const 0) (i32.const 1) (i32.const {bytes})))
      (local.set $ret (call $realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 12)))
      (i32.store (local.get $ret) (i32.const 0))
      (i32.store offset=4 (local.get $ret) (local.get $out))
      (i32.store offset=8 (local.get $ret) (i32.const {bytes}))
      (local.get $ret))
"#
        ),
    )
}

/// A guest whose `init` never returns. `init` is guest code and must be bounded exactly as a
/// message is; without this guest, deleting the helper's arming call at instantiate leaves the
/// whole suite green.
pub fn spin_init() -> Vec<u8> {
    solo_parts(
        "spin-init",
        r#"
    (func (export "init") (param i32 i32) (result i32)
      (loop $forever (br $forever))
      (unreachable))
"#,
        SINK_HANDLE,
        "",
        "",
    )
}

/// A guest that answers every message with `"ok"`, whatever it is handed. Used to ask what an
/// inbound payload costs without the answer's own size confusing the result.
pub fn sink() -> Vec<u8> {
    solo("sink", SINK_HANDLE)
}

/// A guest in this world, plus `extra` unreferenced core instances of a module holding `pages`
/// of memory and a table of `table_elements`. Perfectly valid, perfectly in-world, and shaped
/// to cost the *host* rather than to use its own memory grant: every one of those instances,
/// memories and tables is bookkeeping wasmtime allocates that no `memory_bytes` grant is
/// charged for.
///
/// Passing `pages: 0` or `table_elements: 0` leaves that resource out, so one constructor
/// serves the instance-count, table-count and aggregate-memory proofs.
pub fn bulk(extra: usize, pages: u32, table_elements: u32) -> Vec<u8> {
    let memory = if pages > 0 {
        format!("(memory {pages})")
    } else {
        String::new()
    };
    let table = if table_elements > 0 {
        format!("(table {table_elements} funcref)")
    } else {
        String::new()
    };
    let instances: String = (0..extra)
        .map(|n| format!("\n  (core instance $b{n} (instantiate $bulk))"))
        .collect();

    solo_parts(
        "bulk",
        TRIVIAL_INIT,
        SINK_HANDLE,
        "",
        &format!("\n  (core module $bulk {memory} {table}){instances}"),
    )
}

/// A guest in this world with `functions` extra core functions of `ops` arithmetic instructions
/// each, spliced into its core module. Unreferenced, and compiled anyway — which is the whole
/// point: cranelift's cost is set by what a component *declares*, not by what it runs.
///
/// This is the shape the structural bound was measured against; see `crate::shape`.
pub fn dense(functions: usize, ops: usize) -> Vec<u8> {
    // Built by hand rather than with `format!` per function: at the bound this is twenty
    // thousand functions and several megabytes of text, and a `Vec<String>` of it all is a
    // needless second copy.
    let mut body = String::with_capacity(functions * (ops * 70 + 64));
    for index in 0..functions {
        body.push_str("(func $d");
        body.push_str(&index.to_string());
        body.push_str(" (param $x i32) (result i32)");
        for op in 0..ops {
            body.push_str("(local.set $x (i32.mul (i32.add (local.get $x) (i32.const ");
            body.push_str(&op.to_string());
            body.push_str(")) (i32.const 3)))");
        }
        body.push_str("(local.get $x))\n");
    }
    solo_with("dense", &body)
}

/// `depth` components nested inside each other and nothing else. Not in this world and not meant
/// to be: nesting is the one dimension that is a handful of bytes to write and a recursion for
/// whatever walks it, so what has to refuse this is the structural pass, before the world check
/// and before the compiler.
pub fn deeply_nested(depth: usize) -> Vec<u8> {
    assemble(&format!(
        "{}{}",
        "(component ".repeat(depth),
        ")".repeat(depth)
    ))
}

/// A guest using `f32x4.relaxed_madd`, from the relaxed-SIMD proposal. Relaxed SIMD is
/// *nondeterministic by design* — whether the multiply and add fuse is the host CPU's business —
/// so a capability using it can answer differently on two nodes of the same fleet. The engine
/// has the proposal off; this is what proves it.
pub fn relaxed_simd() -> Vec<u8> {
    solo_with(
        "relaxed-simd",
        r#"
    (func $relaxed (param $a v128) (result v128)
      (f32x4.relaxed_madd (local.get $a) (local.get $a) (local.get $a)))
"#,
    )
}

/// A guest using `return_call`, from the tail-call proposal.
pub fn tail_call() -> Vec<u8> {
    solo_with(
        "tail-call",
        r#"
    (func $tail (result i32) (return_call $tail))
"#,
    )
}

/// A guest whose `handle-message` grows a table by `by` elements and traps if it is refused.
/// The mirror of [`grow`], for the other resource a store bounds by count and by size.
pub fn table_grower(by: u32) -> Vec<u8> {
    solo(
        "table-grower",
        &format!(
            r#"
    (table $t 1 funcref)
    (func (export "handle_message") (param i32 i32) (result i32)
      (local $ret i32)
      (if (i32.eq (table.grow $t (ref.null func) (i32.const {by})) (i32.const -1))
        (then (unreachable)))
      (local.set $ret (call $realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 12)))
      (i32.store (local.get $ret) (i32.const 0))
      (i32.store offset=4 (local.get $ret) (i32.const 64))
      (i32.store offset=8 (local.get $ret) (i32.const 2))
      (local.get $ret))
    (data (i32.const 64) "ok")
"#
        ),
    )
}

/// A guest in this world that also declares one component-level import, never lowered and never
/// called. The two probes built on it are the ones the world check's import half is *only*
/// checked by: `undeclared_import` below cannot tell the name check from the signature check,
/// because a clock fails both.
fn declaring_import(name: &str, params: &str) -> Vec<u8> {
    let prelude = trivial_prelude(name, TRIVIAL_INIT);
    let lift = lift("$i", "$i");
    assemble(&format!(
        r#"(component
  (import "{name}" (func $imported {params}))
  (core module $m{ALLOC}{prelude}{SINK_HANDLE}
  )
  (core instance $i (instantiate $m)){lift})"#
    ))
}

/// A guest importing `notify` — a name the world does not declare — *with `log`'s exact
/// signature*. Delete the name check in `world::check` and this component loads, because the
/// signature check has nothing to object to.
pub fn misnamed_import() -> Vec<u8> {
    declaring_import(
        "notify",
        r#"(param "level" string) (param "message" string)"#,
    )
}

/// A guest importing `log` by its right name and with the wrong signature: one string, not two.
/// Delete the signature check in `world::check` and this component loads, because the name check
/// has nothing to object to — and it then fails obscurely at every instantiation instead.
pub fn mistyped_log() -> Vec<u8> {
    declaring_import("log", r#"(param "level" string)"#)
}

/// A guest that declares an import the world does not: `now`, a clock. Nothing in the helper's
/// linker can satisfy it and nothing in the helper's world admits it — this is the artifact the
/// deny-by-default check exists for.
pub fn undeclared_import() -> Vec<u8> {
    let prelude = trivial_prelude("clock", TRIVIAL_INIT);
    let lift = lift("$i", "$i");
    assemble(&format!(
        r#"(component
  (import "log" (func $log (param "level" string) (param "message" string)))
  (import "now" (func $now (result u64)))
  (core module $m{ALLOC}{prelude}
    (func (export "handle_message") (param i32 i32) (result i32)
      (local $ret i32)
      (local.set $ret (call $realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 12)))
      (i32.store (local.get $ret) (i32.const 0))
      (i32.store offset=4 (local.get $ret) (i32.const 16))
      (i32.store offset=8 (local.get $ret) (i32.const 5))
      (local.get $ret))
  )
  (core instance $i (instantiate $m)){lift})"#
    ))
}
