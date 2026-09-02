# The template's contract

This directory is a complete, minimal capability project with placeholders where a name goes.
It is what `ouro wasm new` writes (W10b): the command embeds these files with `include_str!`,
substitutes the table below, and the result builds with a plain `cargo build --release --target
wasm32-wasip2`.

**`PLACEHOLDERS.md` itself is not copied.** It documents the template for whoever substitutes
it; a scaffolded project has no placeholders left to explain.

## The files, and where each one lands

| here | in the scaffolded project | when |
|---|---|---|
| `Cargo.toml` | `Cargo.toml` | always |
| `README.md` | `README.md` | always |
| `gitignore` | `.gitignore` | always — dotless here so it does not shadow the repository's own ignore rules for this directory |
| `src/lib.rs` | `src/lib.rs` | a capability (the default) |
| `src/lib.hook.rs` | `src/lib.rs` | `ouro wasm new --hook` |

The two `lib` files are the two shapes over the one world: `src/lib.rs` is a `Capability`
(`export_capability!`), `src/lib.hook.rs` is a `Hook` (`export_hook!`) answering the verdict
contract `provider/native/hooks.ex` reads. Exactly one of them is written, as `src/lib.rs`, so
a scaffolded project has one crate root and no dead file beside it.

## The table

| placeholder | is | example |
|---|---|---|
| `{{name}}` | the component's name, as the manifest will carry it — `Wasm.Artifact.name?/1`'s charset: lowercase alphanumerics, `-`, `_` | `my-capability` |
| `{{name_snake}}` | `{{name}}` with `-` replaced by `_`, which is the file cargo emits | `my_capability` |
| `{{Name}}` | the Rust type name, UpperCamelCase | `MyCapability` |
| `{{summary}}` | one line of plain text for `describe`, at most 200 characters | `Does one thing.` |
| `{{sdk_path}}` | where `ouroboros-guest` lives, as a cargo dependency path | `../../tui/wasm/guest` |

Substitute in **one pass** — find each `{{…}}`, look the key up, copy the value out — rather
than as a chain of textual replacements. Two things follow. A substituted value is never itself
substituted, which matters because `{{sdk_path}}` is arbitrary text somebody typed and has to
arrive in the `Cargo.toml` as those characters. And a `{{…}}` this table does not name is an
error rather than a literal carried into somebody's project, which is what `ouro wasm new`
answers with.

(W9 documented an ordering rule here — `{{name_snake}}` before `{{name}}` — and gave as its
reason that a pass in the other order turns the first into `<name>_snake`. That reason does not
hold: `{{name}}` is not a substring of `{{name_snake}}`, because the `}}` is not there. W10b
replaced the rule with the single pass, which needs no ordering at all.)

## `{{sdk_path}}` is a fact about a filesystem

`ouroboros-guest` is not published, so `Cargo.toml` reaches it by path, and that path has to be
true on the machine the project is built on. `ouro wasm new` fills it in by walking up from the
**output directory** looking for a checkout's `tui/wasm/guest`, and writes the result relative
to the project it just created — so a project scaffolded inside a checkout moves with the
checkout. Nothing about the helper's location or the `ouro` binary's location is consulted:
this is a source path in a `Cargo.toml`, not something that gets executed, and the containment
rule about where an executable may come from (docs/WASM.md D14) is about the other thing.

Where the walk finds nothing, `ouro wasm new` refuses and asks for `--sdk-path <PATH>` rather
than guessing. The README the scaffold writes says the same, because a project whose dependency
path is wrong fails at `cargo build` with a message about a missing manifest and not about
this.

## What holds the template to its word

`tui/wasm/tests/sdk.rs` substitutes exactly this table into a temporary directory, builds
**both** shapes, and puts each result to the real helper — so a template that stops compiling,
or a placeholder added to a file and not to this table, is a failing test rather than a `new`
command that hands somebody a broken project.

`tui/src/wasm_cli.rs`'s `the_embedded_template_is_the_template_on_disk` reads these files at
run time and compares them to the bytes `ouro` embedded, so the CLI cannot drift onto a copy of
its own.
