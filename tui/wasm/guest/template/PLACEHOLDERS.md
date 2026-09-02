# The template's contract

This directory is a complete, minimal capability project with placeholders where a name goes.
It is what `ouro wasm new` writes (W10): copy `Cargo.toml`, `README.md` and `src/lib.rs` into
the target directory, substitute the table below, and the result builds with a plain
`cargo build --release --target wasm32-wasip2`.

**This file is not copied.** It documents the template for whoever substitutes it; a scaffolded
project has no placeholders left to explain.

| placeholder | is | example |
|---|---|---|
| `{{name}}` | the component's name, as the manifest will carry it — `Wasm.Artifact.name?/1`'s charset: lowercase alphanumerics, `-`, `_` | `my-capability` |
| `{{name_snake}}` | `{{name}}` with `-` replaced by `_`, which is the file cargo emits | `my_capability` |
| `{{Name}}` | the Rust type name, UpperCamelCase | `MyCapability` |
| `{{summary}}` | one line of plain text for `describe`, at most 200 characters | `Does one thing.` |
| `{{sdk_path}}` | where `ouroboros-guest` lives, as a cargo dependency path | `../../tui/wasm/guest` |

Substitute `{{name_snake}}` **before** `{{name}}`: a plain textual pass in the other order
turns `{{name_snake}}` into `my-capability_snake`.

`tui/wasm/tests/sdk.rs` substitutes exactly this table into a temporary directory, builds it,
and puts the result to the real helper — so a template that stops compiling, or a placeholder
added to a file and not to this table, is a failing test rather than a `new` command that hands
somebody a broken project.
