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
use crate::world;

/// The version of wasmtime resolved into this binary, or `"unknown"` if the lock could not be
/// read when it was built.
pub const WASMTIME_VERSION: &str = env!("OURO_WASMTIME_VERSION");

/// The `doctor` response object. `census` is the live component and instance counts when a
/// serve loop is answering, and `None` for the one-shot subcommand.
pub fn report(census: Option<(usize, usize)>) -> Value {
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
            "a call may write {} lines to this helper's stderr; past that one marker line is \
             emitted and the rest are dropped. Draining that pipe is the owner's job",
            host::MAX_LOG_LINES_PER_CALL
        ),
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
            "epoch_tick_ms": host::EPOCH_TICK_MS,
            "max_core_instances": host::MAX_CORE_INSTANCES,
            "max_memories": host::MAX_MEMORIES,
            "max_tables": host::MAX_TABLES,
            "max_table_elements": host::MAX_TABLE_ELEMENTS,
            "max_components": host::MAX_COMPONENTS,
            "max_instances": host::MAX_INSTANCES,
            "max_log_lines_per_call": host::MAX_LOG_LINES_PER_CALL,
        },
        "notes": notes,
    });

    if let Some((components, instances)) = census {
        report["held"] = json!({ "components": components, "instances": instances });
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
        let report = report(Some((2, 1)));
        // Every machine this suite runs on can build an engine; if one cannot, the assertion
        // below is the right place to find that out.
        assert_eq!(report["usable"], true);
        assert_eq!(report["worlds"][0], world::ID);
        assert_eq!(report["imports"][0], world::LOG);
        assert_eq!(report["held"]["components"], 2);
        assert_eq!(report["limits"]["max_deadline_ms"], host::MAX_DEADLINE_MS);
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
