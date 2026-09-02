# {{name}}

An ouroboros component: a WebAssembly component in the world `ouroboros:capability@0.1.0`,
built on `ouroboros-guest`. The same artifact serves all three seams — a mesh capability, a
`[[hooks]]` entry, a `[checks]` entry — and `src/lib.rs` says which one this is.

## Build

```sh
rustup target add wasm32-wasip2   # once per toolchain
cargo build --release --target wasm32-wasip2
```

The component is `target/wasm32-wasip2/release/{{name_snake}}.wasm`.

## The SDK path, which is a fact about this filesystem

`ouroboros-guest` is not published to crates.io yet, so `Cargo.toml` reaches it by **path**:

```toml
ouroboros-guest = { path = "{{sdk_path}}" }
```

`ouro wasm new` filled that in by walking up from the directory it created this project in
until it found a checkout's `tui/wasm/guest`; where there is no checkout above the output
directory it refuses and asks for `--sdk-path <PATH>` instead of guessing.

That path has to point at an ouroboros checkout on this machine, and this project stops
building the moment the checkout moves or goes away. Move the project, and the path moves with
it; hand the project to somebody else, and they need a checkout of their own and have to edit
that line. When the crate is published this becomes a version, and the dependency stops being
a fact about your filesystem.

## What it is allowed to do

One import: `log`. No clock, no randomness, no filesystem, no socket, and nothing about the
host it did not arrive knowing. That is not a promise this crate makes — it is what
`ouro-wasm`'s linker defines, and an import it does not define fails instantiation.

Check what your build actually declares before you ship it:

```sh
ouro wasm inspect target/wasm32-wasip2/release/{{name_snake}}.wasm
```

The answer must be `world: ouroboros:capability@0.1.0` and `imports: log` — a `world` of
`unknown` or any second import means something pulled `std`, or a crate that wants WASI, back
into the build, and the helper will refuse the component.

## Run it

As a capability, one message at a time, under the node's own default bounds:

```sh
ouro wasm run target/wasm32-wasip2/release/{{name_snake}}.wasm \
  --config '{}' --message '{"hello":"world"}'
```

As a hook, with both verdicts printed — what the component said, and what the node would act
on after the untrusted narrowing:

```sh
ouro wasm hook target/wasm32-wasip2/release/{{name_snake}}.wasm \
  --event PreToolUse --payload payload.json
```

## Declare it in a workspace

A component hook or check runs from a workspace nobody trusts, because containment replaces
trust here. Declare it in `ouroboros.toml`, or in `~/.config/ouroboros/hooks.toml`:

```toml
[[hooks]]
event = "PreToolUse"
matcher = "write|edit"
component = "./{{name_snake}}.wasm"
config = '{}'

[checks]
{{name}} = { component = "./{{name_snake}}.wasm" }
```

`ouro wasm check` judges those entries the way this runtime judges an untrusted workspace, and
exits non-zero on any refusal.

Its verdict is narrowed on the way back: `allow` is read as silence, `updatedInput` is dropped,
and every line of context it produces is labelled. `deny`, `ask` and context stand. See
`Verdict`'s documentation for the rule as it is enforced.

## Deploy it

Signing and rollout are the node's (docs/WASM.md §7.5, §7.6):

```sh
ouro wasm sign target/wasm32-wasip2/release/{{name_snake}}.wasm \
  --name {{name}} --author you --eval eval.json
```

`sign` reads the component's import list with your own helper and sends it with the request;
the node never parses bytes it has not verified.
