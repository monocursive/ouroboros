# {{name}}

An ouroboros capability component: a WebAssembly component in the world
`ouroboros:capability@0.1.0`, built on `ouroboros-guest`.

## Build

```sh
rustup target add wasm32-wasip2   # once per toolchain
cargo build --release --target wasm32-wasip2
```

The component is `target/wasm32-wasip2/release/{{name_snake}}.wasm`.

`ouroboros-guest` is not published to crates.io yet, so `Cargo.toml` reaches it by **path**:

```toml
ouroboros-guest = { path = "{{sdk_path}}" }
```

That path has to point at an ouroboros checkout on this machine, and this project stops
building the moment the checkout moves or goes away. Move the project, and the path moves with
it; hand the project to somebody else, and they need a checkout of their own and have to edit
that line. When the crate is published this becomes a version, and the dependency stops being
a fact about your filesystem.

## What it is allowed to do

One import: `log`. No clock, no randomness, no filesystem, no socket, and nothing about the
host it did not arrive knowing. That is not a promise this crate makes — it is what
`ouro-wasm`'s linker defines, and an import it does not define fails instantiation.

Check what your build actually declares before you ship it. Whatever asks, the answer must be
`world: "ouroboros:capability@0.1.0"` and `imports: ["log"]` — a `world` of `"unknown"` or any
second import means something pulled `std`, or a crate that wants WASI, back into the build,
and the helper will refuse the component. The helper itself answers, over its own protocol:

```sh
printf '{"jsonrpc":"2.0","id":1,"method":"inspect","params":{"path":"%s"}}\n' \
  "$PWD/target/wasm32-wasip2/release/{{name_snake}}.wasm" \
  | ouro-wasm serve
```

## Run it as a hook or a check

The same world serves all three shapes. Swap `Capability` for `Hook` (and `export_capability!`
for `export_hook!`) and declare it in `ouroboros.toml`, or in
`~/.config/ouroboros/hooks.toml`:

```toml
[[hooks]]
event = "PreToolUse"
matcher = "write|edit"
component = "./{{name_snake}}.wasm"
config = '{}'

[checks]
{{name}} = { component = "./{{name_snake}}.wasm" }
```

A component hook runs from a workspace nobody trusts, because containment replaces trust
here — but its verdict is narrowed on the way back: `allow` is read as silence,
`updatedInput` is dropped, and every line of context it produces is labelled. `deny`, `ask`
and context stand. See `Verdict`'s documentation for the rule as it is enforced.
