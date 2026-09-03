//! The generated bindings for `ouroboros:policy@0.1.0`, the second world (docs/WASM.md §8.2).
//!
//! Everything [`crate::bindings`] says applies here with one name changed: `path` is
//! `tui/wasm/wit/policy.wit`, the world is `policy`, and the generated `export!` is published as
//! `export_policy_world` so [`crate::export_policy!`] is the name an author types.
//!
//! Two `generate!` invocations in one crate is supported precisely because `pub_export_macro`
//! splits the encoded-world custom section out of the module and into the `export!` macro: a
//! guest links this crate once and emits exactly the world section for the macro it invoked. A
//! capability guest therefore does not claim to implement `policy`, and `ouro-wasm`'s `load`
//! — which reads the component's own type rather than a section — would refuse it if it did.
//!
//! The `log` import is the same function in both worlds. Its `extern` declaration appears twice,
//! once per generated module, which is a duplicate *declaration* of one symbol and not a
//! duplicate definition; the linker sees one import named `log` in the finished component,
//! which is what `inspect` reports and what the helper's linker binds.

wit_bindgen::generate!({
    path: "../wit/policy.wit",
    world: "policy",
    pub_export_macro: true,
    export_macro_name: "export_policy_world",
    default_bindings_module: "ouroboros_guest::policy_bindings",
});
