//! The two worlds this helper speaks, and the check that a set of component bytes is in one.
//!
//! ```wit
//! package ouroboros:capability@0.1.0;
//! world capability {
//!   export describe: func() -> string;
//!   export init: func(config: string) -> result<_, string>;
//!   export handle-message: func(body: string) -> result<string, string>;
//!   import log: func(level: string, message: string);
//! }
//!
//! package ouroboros:policy@0.1.0;
//! world policy {
//!   export describe: func() -> string;
//!   export init: func(config: string) -> result<_, string>;
//!   export evaluate: func(request: string) -> string;
//!   import log: func(level: string, message: string);
//! }
//! ```
//!
//! Two worlds, **one import**, and no WASI at any version (docs/WASM.md §7.1, §8.2, D4, D21).
//! A component's whole authority is that import list: it can compute, it can hold its own state
//! between calls, and it can say something into the daemon's log. It cannot read a clock, cannot
//! see a filesystem, cannot open a socket, and cannot learn anything about the host it did not
//! arrive knowing. That is why a *policy* component — one that decides permissions — is
//! deterministic by construction rather than by promise: there is nothing here to be
//! nondeterministic with.
//!
//! # A component is in exactly one world
//!
//! `load` is told a [`Kind`], and the check is run for that world alone. A capability offered as
//! a policy is refused `unsupported_world`, and so is the reverse. The helper has no opinion
//! about which a component *ought* to be — on the node, that opinion is the signed manifest's
//! `kind` (contract C7), and the helper is where the assertion is enforced rather than where it
//! is made. `inspect`, which admits nothing, reports whichever world the bytes satisfy.
//!
//! Bytes that satisfy **both** worlds are refused by [`check`] as ambiguous, whichever world
//! they were offered as. Extra exports are otherwise fine — a component may export more than a
//! world names and `call` reaches none of it — but the *other world's message export, with the
//! other world's signature*, is not an extra export: it is a second claim about what this
//! component is. Admitting such bytes would mean one sha standing for two different things, so
//! that the world a signature bought depended on which request arrived first. One sha, one
//! world, decided by the bytes rather than by an order of arrival.
//!
//! # What this module is, and what it is not
//!
//! It is the *policy* half of D5 — a check run at `load` so a component that could never link is
//! refused once, early, with a refusal that names what was wrong, instead of failing obscurely
//! at every instantiation. The *enforcement* half is [`crate::host`]'s linker, which defines
//! `log` and nothing else, for both worlds; an import this check somehow let through still has
//! nothing to bind to and still fails to instantiate. Neither half is allowed to weaken: this
//! one is allowed to be wrong only in the direction of refusing something that would have
//! worked.

use wasmtime::component::types::{ComponentFunc, ComponentItem, Type};
use wasmtime::component::Component;
use wasmtime::Engine;

use crate::refusal::{self, Refusal};

/// The capability world's package id — reported by `doctor` and `inspect` and checked by the
/// signer on the Elixir side. Version-bearing on purpose: a v2 world is a different string,
/// never a quietly wider v1.
pub const CAPABILITY_ID: &str = "ouroboros:capability@0.1.0";

/// The policy world's package id. A different package, not a wider capability: the two share an
/// import list and nothing else, and a component admitted to one is not admitted to the other.
pub const POLICY_ID: &str = "ouroboros:policy@0.1.0";

/// What `inspect` reports for bytes that are a valid component but in neither world.
pub const UNKNOWN: &str = "unknown";

/// The only import the linker defines, for either world.
pub const LOG: &str = "log";

/// The exports the dispatch tables are built out of. `init` is deliberately not callable: it
/// runs once, from `instantiate`, and is not a message.
pub const DESCRIBE: &str = "describe";
pub const INIT: &str = "init";
pub const HANDLE_MESSAGE: &str = "handle-message";
pub const EVALUATE: &str = "evaluate";

/// One of the two worlds. Every world-shaped decision in this helper takes one of these rather
/// than a string, so the set is closed at the type level and a third world cannot be introduced
/// by a caller spelling one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Capability,
    Policy,
}

/// The worlds this build implements, in the order `doctor` reports them.
pub const KINDS: [Kind; 2] = [Kind::Capability, Kind::Policy];

/// The name a `load` or an `instantiate` request spells a world with. Deliberately short and
/// deliberately not the package id: the id carries a version, and a peer that had to reproduce
/// `ouroboros:capability@0.1.0` to load a component would be pinned to this build's world
/// version by its own request rather than by the signed manifest.
pub const CAPABILITY_NAME: &str = "capability";
pub const POLICY_NAME: &str = "policy";

/// The one signature shape each export in either world has. Small and closed, because the whole
/// of both worlds is four functions over strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sig {
    /// `func() -> string`
    Metadata,
    /// `func(string) -> result<_, string>`
    Init,
    /// `func(string) -> result<string, string>`
    Answer,
    /// `func(string) -> string`
    Verdict,
}

const CAPABILITY_TABLE: &[(&str, Sig)] = &[
    (DESCRIBE, Sig::Metadata),
    (INIT, Sig::Init),
    (HANDLE_MESSAGE, Sig::Answer),
];

const POLICY_TABLE: &[(&str, Sig)] = &[
    (DESCRIBE, Sig::Metadata),
    (INIT, Sig::Init),
    (EVALUATE, Sig::Verdict),
];

impl Kind {
    /// The other world. There are two, so this is total; it exists because [`check`] has to ask
    /// "and is it also that one?" and a `match` at the call site would be a third place the set
    /// of worlds is written down.
    fn other(self) -> Kind {
        match self {
            Kind::Capability => Kind::Policy,
            Kind::Policy => Kind::Capability,
        }
    }

    /// The signature this world's message export carries. The one thing that tells the two
    /// worlds apart in a component's own type.
    fn message_sig(self) -> Sig {
        match self {
            Kind::Capability => Sig::Answer,
            Kind::Policy => Sig::Verdict,
        }
    }

    /// The world a request named, or `None` for a spelling this build does not implement. A
    /// caller that omits the field means `capability`, which is what every caller written before
    /// there was a second world meant.
    pub fn parse(name: &str) -> Option<Kind> {
        match name {
            CAPABILITY_NAME => Some(Kind::Capability),
            POLICY_NAME => Some(Kind::Policy),
            _unknown => None,
        }
    }

    /// The short name, as a request spells it.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Capability => CAPABILITY_NAME,
            Kind::Policy => POLICY_NAME,
        }
    }

    /// The package id, as `doctor`, `inspect` and a signed manifest spell it.
    pub fn id(self) -> &'static str {
        match self {
            Kind::Capability => CAPABILITY_ID,
            Kind::Policy => POLICY_ID,
        }
    }

    /// The one export `call` sends a payload to. `describe` is the other callable export and is
    /// shared; `init` is callable from nowhere.
    pub fn message(self) -> &'static str {
        match self {
            Kind::Capability => HANDLE_MESSAGE,
            Kind::Policy => EVALUATE,
        }
    }

    fn table(self) -> &'static [(&'static str, Sig)] {
        match self {
            Kind::Capability => CAPABILITY_TABLE,
            Kind::Policy => POLICY_TABLE,
        }
    }
}

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

/// `Ok(())` when these bytes are in world `kind`; a refusal naming what was wrong otherwise.
///
/// Imports are checked first and refused as `undefined_import` naming the offending import,
/// because that is the answer an operator needs: not "this is not a capability" but "this
/// wanted a clock". The import check is the same for both worlds — they declare the same one —
/// so a component that wants a socket is refused identically whichever world it was offered as.
pub fn check(component: &Component, engine: &Engine, kind: Kind) -> Result<(), Refusal> {
    let ty = component.component_type();
    let id = kind.id();

    for (name, item) in ty.imports(engine) {
        if name != LOG {
            return Err(refusal::refuse(
                refusal::UNDEFINED_IMPORT,
                format!("component imports `{name}`, which world {id} does not declare"),
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
                format!("component imports `{name}` with a signature world {id} does not declare"),
            ));
        }
    }

    let table = kind.table();
    let other = kind.other();
    let mut seen = [false; 3];
    // Whether the *other* world's message export is here with the other world's signature —
    // which is the one extra export that is not merely extra. See the module header.
    let mut ambidextrous = false;

    for (name, item) in ty.exports(engine) {
        let ComponentItem::ComponentFunc(func) = item.ty else {
            continue;
        };

        if name == other.message() && signed_as(&func, other.message_sig()) {
            ambidextrous = true;
        }

        // Extra exports are not a refusal. A component may export more than a world names, and
        // `call` reaches none of it: the dispatch table is closed, not the component.
        let Some(index) = table.iter().position(|(export, _)| *export == name) else {
            continue;
        };
        seen[index] = signed_as(&func, table[index].1);
    }

    let missing: Vec<&str> = table
        .iter()
        .map(|(name, _)| *name)
        .zip(seen)
        .filter_map(|(name, ok)| (!ok).then_some(name))
        .collect();

    if !missing.is_empty() {
        return Err(refusal::refuse(
            refusal::UNSUPPORTED_WORLD,
            format!(
                "component does not export {} with the signature world {id} declares",
                missing.join(", ")
            ),
        ));
    }

    if ambidextrous {
        return Err(refusal::refuse(
            refusal::UNSUPPORTED_WORLD,
            format!(
                "component exports `{}` as well as `{}`, so it claims both {id} and {}; a \
                 component is in one world",
                other.message(),
                kind.message(),
                other.id()
            ),
        ));
    }

    Ok(())
}

/// The world these bytes are in, or `"unknown"`. `inspect` reports this without refusing, so an
/// operator can look at a component before deciding to load it.
///
/// At most one world can match, because [`check`] refuses bytes that satisfy both, so the order
/// [`KINDS`] is walked in decides nothing. Bytes claiming both read as `"unknown"` here and are
/// refused by `load` whichever world they are offered as.
pub fn identify(component: &Component, engine: &Engine) -> &'static str {
    KINDS
        .iter()
        .find(|kind| check(component, engine, **kind).is_ok())
        .map_or(UNKNOWN, |kind| kind.id())
}

fn signed_as(func: &ComponentFunc, sig: Sig) -> bool {
    match sig {
        Sig::Metadata => matches(func, &[], Some(&Type::String)),
        Sig::Init => {
            matches_string_arg(func) && result_of(func).is_some_and(|(ok, err)| !ok && err)
        }
        Sig::Answer => {
            matches_string_arg(func) && result_of(func).is_some_and(|(ok, err)| ok && err)
        }
        Sig::Verdict => matches(func, &[Type::String], Some(&Type::String)),
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

/// Structural equality over the handful of types these worlds use. `Type` carries an engine
/// handle rather than deriving `PartialEq`, and neither world has a nested type, so a shallow
/// match on the discriminant is both sufficient and honest about its own limits.
///
/// The one place it is *not* sufficient is [`Sig::Verdict`] against [`Sig::Answer`]: a
/// `result<string, string>` and a bare `string` have different discriminants, so the two are
/// told apart, which is what keeps a capability from passing the policy check.
fn same(a: &Type, b: &Type) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_world_is_named_by_the_short_name_a_request_spells() {
        assert_eq!(Kind::parse("capability"), Some(Kind::Capability));
        assert_eq!(Kind::parse("policy"), Some(Kind::Policy));
        for unknown in ["", "Capability", "hook", "ouroboros:policy@0.1.0"] {
            assert_eq!(
                Kind::parse(unknown),
                None,
                "{unknown} must not name a world"
            );
        }
    }

    /// The two package ids are distinct, and so are the two message exports. Both are relied on
    /// by things that cannot see this file: the signer compares the id, and `call`'s dispatch
    /// table is keyed by the export name.
    #[test]
    fn the_two_worlds_share_an_import_and_nothing_else() {
        assert_ne!(Kind::Capability.id(), Kind::Policy.id());
        assert_ne!(Kind::Capability.message(), Kind::Policy.message());
        assert_eq!(Kind::Capability.message(), HANDLE_MESSAGE);
        assert_eq!(Kind::Policy.message(), EVALUATE);
        // One import list, stated once, for both.
        assert!(CAPABILITY_TABLE
            .iter()
            .all(|(name, _)| *name != LOG && *name != EVALUATE));
        assert!(POLICY_TABLE
            .iter()
            .all(|(name, _)| *name != LOG && *name != HANDLE_MESSAGE));
    }
}
