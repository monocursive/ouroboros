//! The refusal vocabulary: every way this helper says no, with a private JSON-RPC code and a
//! stable name for each.
//!
//! A refusal is not a failure of the helper. It is the helper reporting that a *bound held* —
//! the guest ran out of fuel, the deadline arrived, the sha did not match, the component wanted
//! an import the world does not have — and the owner on the other end of the pipe has to be
//! able to tell those apart without reading English. So every one of them gets its own code in
//! the private `-32001..-32099` band and its own `data.refusal` name; the prose in `message` is
//! for a human reading a log, never for a peer to match on.
//!
//! | code | `data.refusal` | what held |
//! |---|---|---|
//! | -32001 | `sha_mismatch` | the bytes read do not hash to the sha the request named |
//! | -32002 | `unsupported_world` | exports do not match `ouroboros:capability@0.1.0` |
//! | -32003 | `undefined_import` | the component imports something the world does not declare |
//! | -32004 | `unreadable_component` | the path could not be read, or is over the byte cap |
//! | -32005 | `compile_failed` | wasmtime refused the bytes as a component |
//! | -32006 | `unknown_component` | no component with that sha has been `load`ed |
//! | -32007 | `unknown_instance` | no live instance by that name — including one just poisoned |
//! | -32008 | `instance_exists` | that instance name is already live; `drop` it first |
//! | -32009 | `limits_out_of_range` | a limit is present and outside this helper's range |
//! | -32010 | `instantiate_failed` | the linker had nothing for an import, or a count limit denied it |
//! | -32011 | `fuel_exhausted` | the guest burned its whole fuel budget |
//! | -32012 | `deadline_exceeded` | the epoch deadline interrupted the guest |
//! | -32013 | `memory_limit` | the guest was denied memory growth and could not continue |
//! | -32014 | `trapped` | the guest trapped for its own reasons |
//! | -32015 | `unknown_export` | `call` named something outside the world's exports |
//! | -32016 | `oversize_result` | the guest's reply is larger than a reply may be |
//! | -32017 | `guest_error` | the guest returned its own `err(string)` — its answer, not ours |
//! | -32018 | `too_many_components` | the component cache is full; nothing here is evicted |
//! | -32019 | `too_many_instances` | the instance table is full; drop one first |
//!
//! One standard code travels in the same shape, because it is raised in the same places: a
//! request whose parameters are missing or mistyped is `-32602` / `invalid_params`, and it is a
//! statement about the *request*, never about the component. The rest of the transport's
//! standard codes (`-32600` invalid request, `-32601` method not found, `-32603` internal
//! error) live in [`crate::server`] with the dispatch that emits them.

/// A code and the name that travels with it. Paired here so the two can never drift.
pub type Kind = (i64, &'static str);

/// The JSON-RPC standard code, given a name so it reads like every other refusal on the wire.
pub const INVALID_PARAMS: Kind = (-32602, "invalid_params");

pub const SHA_MISMATCH: Kind = (-32001, "sha_mismatch");
pub const UNSUPPORTED_WORLD: Kind = (-32002, "unsupported_world");
pub const UNDEFINED_IMPORT: Kind = (-32003, "undefined_import");
pub const UNREADABLE_COMPONENT: Kind = (-32004, "unreadable_component");
pub const COMPILE_FAILED: Kind = (-32005, "compile_failed");
pub const UNKNOWN_COMPONENT: Kind = (-32006, "unknown_component");
pub const UNKNOWN_INSTANCE: Kind = (-32007, "unknown_instance");
pub const INSTANCE_EXISTS: Kind = (-32008, "instance_exists");
pub const LIMITS_OUT_OF_RANGE: Kind = (-32009, "limits_out_of_range");
/// Instantiation failed for a reason the runtime does not type: the linker had no definition
/// for an import, or one of the store's count limits denied a memory, table, or core instance.
/// Both are refusals of the same act and wasmtime reports them the same way; the message
/// carries the runtime's own words, which name the import or the resource.
pub const INSTANTIATE_FAILED: Kind = (-32010, "instantiate_failed");
pub const FUEL_EXHAUSTED: Kind = (-32011, "fuel_exhausted");
pub const DEADLINE_EXCEEDED: Kind = (-32012, "deadline_exceeded");
pub const MEMORY_LIMIT: Kind = (-32013, "memory_limit");
pub const TRAPPED: Kind = (-32014, "trapped");
pub const UNKNOWN_EXPORT: Kind = (-32015, "unknown_export");
pub const OVERSIZE_RESULT: Kind = (-32016, "oversize_result");
pub const GUEST_ERROR: Kind = (-32017, "guest_error");
pub const TOO_MANY_COMPONENTS: Kind = (-32018, "too_many_components");
pub const TOO_MANY_INSTANCES: Kind = (-32019, "too_many_instances");

/// One refusal, ready to become a JSON-RPC error object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: i64,
    pub refusal: &'static str,
    pub message: String,
}

/// Builds a refusal. `message` is prose for a human; peers match on `code`/`refusal`.
pub fn refuse(kind: Kind, message: impl Into<String>) -> Refusal {
    Refusal {
        code: kind.0,
        refusal: kind.1,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole private vocabulary, so the table above and the constants below it are checked
    /// as a set rather than one at a time.
    const ALL: &[Kind] = &[
        SHA_MISMATCH,
        UNSUPPORTED_WORLD,
        UNDEFINED_IMPORT,
        UNREADABLE_COMPONENT,
        COMPILE_FAILED,
        UNKNOWN_COMPONENT,
        UNKNOWN_INSTANCE,
        INSTANCE_EXISTS,
        LIMITS_OUT_OF_RANGE,
        INSTANTIATE_FAILED,
        FUEL_EXHAUSTED,
        DEADLINE_EXCEEDED,
        MEMORY_LIMIT,
        TRAPPED,
        UNKNOWN_EXPORT,
        OVERSIZE_RESULT,
        GUEST_ERROR,
        TOO_MANY_COMPONENTS,
        TOO_MANY_INSTANCES,
    ];

    #[test]
    fn every_refusal_is_in_the_private_band_and_unique() {
        let mut codes: Vec<i64> = ALL.iter().map(|(code, _)| *code).collect();
        let mut names: Vec<&str> = ALL.iter().map(|(_, name)| *name).collect();

        for (code, name) in ALL {
            assert!(
                (-32099..=-32001).contains(code),
                "{name} is {code}, outside -32001..=-32099"
            );
        }

        codes.sort_unstable();
        codes.dedup();
        names.sort_unstable();
        names.dedup();
        assert_eq!(codes.len(), ALL.len(), "two refusals share a code");
        assert_eq!(names.len(), ALL.len(), "two refusals share a name");
    }
}
