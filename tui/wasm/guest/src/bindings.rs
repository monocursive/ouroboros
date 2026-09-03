//! The generated bindings for `ouroboros:capability@0.1.0`, and the one place `generate!` is
//! invoked in the ecosystem.
//!
//! `path` points at `tui/wasm/wit/capability.wit`, the world file of record — the same artifact
//! `tui/wasm/src/world.rs` hard-codes and `test/wasm/capability_acceptance_test.exs` holds the
//! two to each other. A guest binds against this crate and therefore against that file; it has
//! no second copy of the world to drift from.
//!
//! It names the **file** rather than the directory, and since W15 it has to: a WIT directory is
//! one package, and `tui/wasm/wit/` now holds two — `ouroboros:capability@0.1.0` here and
//! `ouroboros:policy@0.1.0` in [`crate::policy_bindings`]. Two files, two packages, two
//! `generate!` invocations, and `pub_export_macro` keeps each world's encoded custom section
//! inside its own `export!` macro, so a guest that links this crate and exports one world does
//! not claim to implement the other.
//!
//! Three options make these bindings usable from a crate that does not own them, which is the
//! whole reason this module exists rather than a `generate!` in every guest:
//!
//!   * `pub_export_macro` publishes the generated `export!` macro instead of keeping it
//!     crate-private, and splits the encoded-world custom section so a crate that links this
//!     one without exporting anything does not claim to implement the world.
//!   * `export_macro_name` renames it to `export_world`, leaving the names an author actually
//!     types — [`crate::export_capability!`] and its siblings — to this crate.
//!   * `default_bindings_module` tells the generated macro where the types live, so an author
//!     writes `export_world!(T)` rather than `export_world!(T with_types_in …)` and never
//!     names this module at all.
//!
//! The consequence worth stating: a guest does **not** depend on `wit-bindgen`. Everything the
//! expansion reaches for is a path into this crate.

wit_bindgen::generate!({
    path: "../wit/capability.wit",
    world: "capability",
    pub_export_macro: true,
    export_macro_name: "export_world",
    default_bindings_module: "ouroboros_guest::bindings",
});
