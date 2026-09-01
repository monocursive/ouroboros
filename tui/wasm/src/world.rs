//! The one world this helper speaks, and the check that a set of component bytes is in it.
//!
//! ```wit
//! package ouroboros:capability@0.1.0;
//! world capability {
//!   export describe: func() -> string;
//!   export init: func(config: string) -> result<_, string>;
//!   export handle-message: func(body: string) -> result<string, string>;
//!   import log: func(level: string, message: string);
//! }
//! ```
//!
//! Exactly one world, exactly one import, and no WASI at any version (docs/WASM.md §7.1, D4).
//! A capability's whole authority is that import list: it can compute, it can hold its own
//! state between messages, and it can say something into the daemon's log. It cannot read a
//! clock, cannot see a filesystem, cannot open a socket, and cannot learn anything about the
//! host it did not arrive knowing.
//!
//! # What this module is, and what it is not
//!
//! It is the *policy* half of D5 — a check run at `load` so a component that could never link
//! is refused once, early, with a refusal that names what was wrong, instead of failing
//! obscurely at every instantiation. The *enforcement* half is [`crate::host`]'s linker, which
//! defines `log` and nothing else; an import this check somehow let through still has nothing
//! to bind to and still fails to instantiate. Neither half is allowed to weaken: this one is
//! allowed to be wrong only in the direction of refusing something that would have worked.

use wasmtime::component::types::{ComponentFunc, ComponentItem, Type};
use wasmtime::component::Component;
use wasmtime::Engine;

use crate::refusal::{self, Refusal};

/// The world's package id, reported by `doctor` and `inspect` and checked by the signer on the
/// Elixir side. Version-bearing on purpose: a v2 world is a different string, never a quietly
/// wider v1.
pub const ID: &str = "ouroboros:capability@0.1.0";

/// What `inspect` reports for bytes that are a valid component but not this world.
pub const UNKNOWN: &str = "unknown";

/// The only import the linker defines.
pub const LOG: &str = "log";

/// The exports `call` can dispatch to. `init` is deliberately absent: it runs once, from
/// `instantiate`, and is not a message.
pub const DESCRIBE: &str = "describe";
pub const HANDLE_MESSAGE: &str = "handle-message";
pub const INIT: &str = "init";

/// The import and export names a component declares, in the order the component declares them.
/// Reported by `inspect` as review surface; the signed manifest is checked against it upstream.
pub fn names(component: &Component, engine: &Engine) -> (Vec<String>, Vec<String>) {
    let ty = component.component_type();
    let imports = ty
        .imports(engine)
        .map(|(name, _)| name.to_string())
        .collect();
    let exports = ty
        .exports(engine)
        .map(|(name, _)| name.to_string())
        .collect();
    (imports, exports)
}

/// `Ok(())` when these bytes are in this world; a refusal naming what was wrong otherwise.
///
/// Imports are checked first and refused as `undefined_import` naming the offending import,
/// because that is the answer an operator needs: not "this is not a capability" but "this
/// wanted a clock".
pub fn check(component: &Component, engine: &Engine) -> Result<(), Refusal> {
    let ty = component.component_type();

    for (name, item) in ty.imports(engine) {
        if name != LOG {
            return Err(refusal::refuse(
                refusal::UNDEFINED_IMPORT,
                format!("component imports `{name}`, which world {ID} does not declare"),
            ));
        }
        let ComponentItem::ComponentFunc(func) = item.ty else {
            return Err(refusal::refuse(
                refusal::UNDEFINED_IMPORT,
                format!("component imports `{name}` as something other than a function"),
            ));
        };
        if !matches(&func, &[Type::String, Type::String], None) {
            return Err(refusal::refuse(
                refusal::UNDEFINED_IMPORT,
                format!("component imports `{name}` with a signature world {ID} does not declare"),
            ));
        }
    }

    let mut seen = [false; 3];
    for (name, item) in ty.exports(engine) {
        let index = match name {
            DESCRIBE => 0,
            INIT => 1,
            HANDLE_MESSAGE => 2,
            // Extra exports are not a refusal. A component may export more than a world names,
            // and `call` reaches none of it: the dispatch table is closed, not the component.
            _ => continue,
        };
        let ComponentItem::ComponentFunc(func) = item.ty else {
            continue;
        };
        seen[index] = match index {
            0 => matches(&func, &[], Some(&Type::String)),
            1 => matches_string_arg(&func) && result_of(&func).is_some_and(|(ok, err)| !ok && err),
            _ => matches_string_arg(&func) && result_of(&func).is_some_and(|(ok, err)| ok && err),
        };
    }

    let missing: Vec<&str> = [DESCRIBE, INIT, HANDLE_MESSAGE]
        .into_iter()
        .zip(seen)
        .filter_map(|(name, ok)| (!ok).then_some(name))
        .collect();

    if missing.is_empty() {
        Ok(())
    } else {
        Err(refusal::refuse(
            refusal::UNSUPPORTED_WORLD,
            format!(
                "component does not export {} with the signature world {ID} declares",
                missing.join(", ")
            ),
        ))
    }
}

/// The world id when these bytes are in it, `"unknown"` otherwise. `inspect` reports this
/// without refusing, so an operator can look at a component before deciding to load it.
pub fn identify(component: &Component, engine: &Engine) -> &'static str {
    if check(component, engine).is_ok() {
        ID
    } else {
        UNKNOWN
    }
}

fn matches(func: &ComponentFunc, params: &[Type], result: Option<&Type>) -> bool {
    let actual: Vec<Type> = func.params().map(|(_, ty)| ty).collect();
    if actual.len() != params.len() || !actual.iter().zip(params).all(|(a, b)| same(a, b)) {
        return false;
    }
    let results: Vec<Type> = func.results().collect();
    match (result, results.as_slice()) {
        (None, []) => true,
        (Some(want), [got]) => same(got, want),
        _ => false,
    }
}

fn matches_string_arg(func: &ComponentFunc) -> bool {
    let params: Vec<Type> = func.params().map(|(_, ty)| ty).collect();
    matches!(params.as_slice(), [Type::String])
}

/// `Some((has_ok_string, has_err_string))` when the function returns exactly one `result`.
fn result_of(func: &ComponentFunc) -> Option<(bool, bool)> {
    let results: Vec<Type> = func.results().collect();
    let [Type::Result(result)] = results.as_slice() else {
        return None;
    };
    let ok = match result.ok() {
        None => false,
        Some(Type::String) => true,
        Some(_) => return None,
    };
    let err = matches!(result.err(), Some(Type::String));
    Some((ok, err))
}

/// Structural equality over the handful of types this world uses. `Type` carries an engine
/// handle rather than deriving `PartialEq`, and the world has no nested types, so a shallow
/// match on the discriminant is both sufficient and honest about its own limits.
fn same(a: &Type, b: &Type) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}
