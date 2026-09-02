//! `doctor`: what this build can actually contain, reported without doing anything.
//!
//! The same object serves the `doctor` subcommand an operator runs and the `doctor` request the
//! pool uses as its handshake. It reports three things a caller cannot find out any other way:
//! whether an engine can be built on this host at all, which wasmtime it is built against
//! (read from the resolved lock at compile time — see `build.rs`, because wasmtime exposes no
//! version constant), and the exact bounds `instantiate` will accept.
//!
//! `usable` is a probe, never an assumption: it is false when [`wasmtime::Engine`] refuses to
//! start, and the note says why. A helper that claimed to be usable and then failed on the
//! first `load` would cost the pool a broken-state cooldown to discover what one line of JSON
//! could have said.

use serde_json::{json, Value};

use crate::host;
use crate::shape;
use crate::world;

/// The version of wasmtime resolved into this binary, or `"unknown"` if the lock could not be
/// read when it was built.
pub const WASMTIME_VERSION: &str = env!("OURO_WASMTIME_VERSION");

/// The proposals [`host::config`] turns off, named for an operator reading this report. Prose,
/// not a contract: the enforcement is the `Config` in [`crate::host`], and the tests that put a
/// component using each of these in front of the helper and watch it be refused.
const DISABLED_PROPOSALS: &str = "relaxed-simd (nondeterministic, and D4 says no), tail-call, \
     function-references, extended-const, multi-memory, memory64, gc, threads and \
     shared-everything-threads, exceptions (current and legacy), stack-switching, \
     wide-arithmetic, custom-page-sizes, memory-control, and every optional component-model \
     extension (async, threading, error-context, gc, map, memory64, fixed-length-lists, \
     implements, values, nested-names). Left on: the component model, simd, multi-value, \
     bulk-memory, reference-types, sign-extension, saturating-float-to-int, mutable-global";

/// The `doctor` response object. `census` is the live state of the two tables — how full each
/// is, and what the component cache has let go — when a serve loop is answering, and `None`
/// for the one-shot subcommand.
pub fn report(census: Option<host::Census>) -> Value {
    let engine = wasmtime::Engine::new(&host::config());
    let mut notes = vec![
        format!(
            "the linker defines exactly one host function, `{}`; there is no WASI at any \
             version, so any other import fails to instantiate",
            world::LOG
        ),
        "every instance runs under fuel, an epoch deadline, a memory ceiling summed across its \
         memories, and caps on resource counts; there is no unlimited default"
            .to_string(),
        "a trap drops its instance server-side; the next call on that name is unknown_instance"
            .to_string(),
        format!(
            "the component cache holds {}; a load past that evicts the least recently used \
             component no live instance holds and names it in its result, and is refused \
             too_many_components only when every held component has a live instance. Instances \
             are never evicted",
            host::MAX_COMPONENTS
        ),
        format!(
            "a call may write {} lines to this helper's stderr; past that one marker line is \
             emitted and the rest are dropped. Draining that pipe is the owner's job",
            host::MAX_LOG_LINES_PER_CALL
        ),
        format!(
            "a component is walked before it is compiled and refused component_too_complex if it \
             declares more than {} functions, {} bytes of code, {} types, {} levels of nesting or \
             {} core modules; cranelift cannot be interrupted once it starts, so the bound has to \
             be taken in front of it",
            shape::MAX_FUNCTIONS,
            shape::MAX_CODE_BYTES,
            shape::MAX_TYPES,
            shape::MAX_DEPTH,
            shape::MAX_CORE_MODULES
        ),
        format!("the engine has these proposals disabled: {DISABLED_PROPOSALS}"),
        "a JSON-RPC notification — an object with no id — is refused for every method but \
         doctor: a method with effects must have somewhere to send its answer"
            .to_string(),
    ];
    if let Err(error) = &engine {
        notes.push(format!("wasmtime engine unavailable: {error}"));
    }

    let mut report = json!({
        "usable": engine.is_ok(),
        "wasmtime": WASMTIME_VERSION,
        "worlds": [world::ID],
        "imports": [world::LOG],
        "limits": {
            "max_fuel": host::MAX_FUEL,
            "min_memory_bytes": host::MIN_MEMORY_BYTES,
            "max_memory_bytes": host::MAX_MEMORY_BYTES,
            "max_deadline_ms": host::MAX_DEADLINE_MS,
            "max_result_bytes": host::MAX_RESULT_BYTES,
            "max_hostcall_bytes": host::MAX_HOSTCALL_BYTES,
            "max_component_bytes": host::MAX_COMPONENT_BYTES,
            "max_wasm_stack_bytes": host::MAX_WASM_STACK_BYTES,
            "memory_reservation_bytes": host::MEMORY_RESERVATION_BYTES,
            "memory_guard_bytes": host::MEMORY_GUARD_BYTES,
            // The structural bound in front of the compiler (`crate::shape`). These are the
            // numbers that decide whether a component is compiled at all, so they are the ones
            // an owner most needs to be able to read rather than discover.
            "max_code_bytes": shape::MAX_CODE_BYTES,
            "max_functions": shape::MAX_FUNCTIONS,
            "max_types": shape::MAX_TYPES,
            "max_component_imports": shape::MAX_IMPORTS,
            "max_component_exports": shape::MAX_EXPORTS,
            "max_definitions": shape::MAX_DEFINITIONS,
            "max_segment_bytes": shape::MAX_SEGMENT_BYTES,
            "max_nesting_depth": shape::MAX_DEPTH,
            "max_core_modules": shape::MAX_CORE_MODULES,
            "max_nested_components": shape::MAX_NESTED_COMPONENTS,
            "max_sections": shape::MAX_SECTIONS,
            "epoch_tick_ms": host::EPOCH_TICK_MS,
            "max_core_instances": host::MAX_CORE_INSTANCES,
            "max_memories": host::MAX_MEMORIES,
            "max_tables": host::MAX_TABLES,
            "max_table_elements": host::MAX_TABLE_ELEMENTS,
            "max_components": host::MAX_COMPONENTS,
            "max_instances": host::MAX_INSTANCES,
            "max_eviction_log": host::MAX_EVICTION_LOG,
            "max_log_lines_per_call": host::MAX_LOG_LINES_PER_CALL,
        },
        "notes": notes,
    });

    if let Some(census) = census {
        report["held"] = json!({
            "components": census.components,
            "instances": census.instances,
            "evictions": census.evictions,
            "evicted": census.evicted,
        });
    }
    report
}

/// The `doctor` subcommand's output: the same object, pretty-printed for a human.
pub fn report_pretty() -> String {
    serde_json::to_string_pretty(&report(None)).unwrap_or_else(|_| {
        // Serializing a value we built ourselves cannot fail in practice; if it somehow did,
        // say so rather than print nothing.
        r#"{"error":"doctor report could not be encoded"}"#.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_is_honest_about_this_host() {
        let report = report(Some(host::Census {
            components: 2,
            instances: 1,
            evictions: 3,
            evicted: vec!["a".repeat(64)],
        }));
        // Every machine this suite runs on can build an engine; if one cannot, the assertion
        // below is the right place to find that out.
        assert_eq!(report["usable"], true);
        assert_eq!(report["worlds"][0], world::ID);
        assert_eq!(report["imports"][0], world::LOG);
        assert_eq!(report["held"]["components"], 2);
        assert_eq!(report["held"]["instances"], 1);
        assert_eq!(report["held"]["evictions"], 3);
        assert_eq!(report["held"]["evicted"][0], "a".repeat(64));
        assert_eq!(report["limits"]["max_deadline_ms"], host::MAX_DEADLINE_MS);
        assert_eq!(report["limits"]["max_eviction_log"], host::MAX_EVICTION_LOG);
    }

    /// The bound in front of the compiler is a number an owner has to be able to read out of
    /// `doctor`, not one they discover from a refusal.
    #[test]
    fn the_structural_bound_is_reported() {
        let report = report(None);
        assert_eq!(report["limits"]["max_functions"], shape::MAX_FUNCTIONS);
        assert_eq!(report["limits"]["max_code_bytes"], shape::MAX_CODE_BYTES);
        assert_eq!(report["limits"]["max_nesting_depth"], shape::MAX_DEPTH);
        assert_eq!(
            report["limits"]["max_wasm_stack_bytes"],
            host::MAX_WASM_STACK_BYTES
        );

        let notes = report["notes"].as_array().expect("notes").clone();
        let joined: String = notes
            .iter()
            .filter_map(|note| note.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            joined.contains("component_too_complex"),
            "doctor must say the compiler is bounded: {joined}"
        );
        assert!(
            joined.contains("relaxed-simd"),
            "doctor must list what the engine refuses: {joined}"
        );
        assert!(
            joined.contains("notification"),
            "doctor must say notifications are refused: {joined}"
        );
    }

    #[test]
    fn the_subcommand_holds_nothing_and_says_nothing_about_it() {
        let report = report(None);
        assert!(
            report.get("held").is_none(),
            "a one-shot report has no tables to count"
        );
        assert_eq!(report["limits"]["max_components"], host::MAX_COMPONENTS);
    }

    #[test]
    fn the_wasmtime_version_is_read_not_guessed() {
        assert_ne!(
            WASMTIME_VERSION, "unknown",
            "build.rs could not find wasmtime in the workspace lock"
        );
        assert!(
            WASMTIME_VERSION.starts_with("48."),
            "doctor reports wasmtime {WASMTIME_VERSION}, which is not the pinned major"
        );
    }
}
