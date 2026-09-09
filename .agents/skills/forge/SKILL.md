---
name: forge
description: How to build, sign and deploy a WebAssembly capability with the `forge` tool — the project shape a forge accepts, the dependency lock rule, the manifest with its evaluation spec, the four operations in order, and what each fence refuses. Read this before the first `forge` call; a project that does not match the shape below is refused before anything is built, and a build costs minutes.
---

# Forging a capability

A **capability** is a WebAssembly component this node runs as a mesh agent called
`wasm/<name>`. It receives one JSON object and answers with one JSON object. Once it is
deployed you reach it with the `capability` tool, and so does anything else on this node.

Forging one is how a session changes the runtime it is running in. It is also the most
expensive thing in the tool list: a build is a cargo compile inside an OS sandbox and takes
minutes, and the last step of it holds the node's single WebAssembly helper. Get the project
right on paper first, then `preview`, then `forge`.

## The contract the component is built against

World `ouroboros:capability@0.1.0`. Exactly one import: `log`. No filesystem, no network, no
clock, no environment, no threads — the component gets a message and its own memory and
nothing else. If your idea needs any of those, it is not a capability; it is something the
ordinary tools do.

The SDK gives you the bindings, the allocator, the panic handler and JSON, so the crate you
write is `no_std` and has one dependency.

## The project, exactly

A forge accepts a directory holding **these files and no others**:

```
Cargo.toml        required
Cargo.lock        required, and pinned — see below
src/lib.rs        required (any number of further src/**.rs modules is fine)
README.md         optional
manifest.json     optional, but the signer wants what is in it — see below
```

Anything else is refused by name. In particular there is **no `build.rs`**: a build script is
code that runs at build time, and this lane does not run any.

### `Cargo.toml`

The worked example is `tui/wasm/guest/examples/counter/Cargo.toml` **in the checkout you are
working in**. Read it. Yours is the same file with a different `name`:

```toml
# Its own workspace, like every project built on this SDK: it must not join anything.
[workspace]

[package]
name = "my-capability"          # this is the capability's name; see "One name" below
version = "0.1.0"
edition = "2021"                # 2021 or 2024, nothing else
rust-version = "1.82"
description = "what it does"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
ouroboros-guest = { path = "../../tui/wasm/guest" }

# Verbatim. `panic = "abort"` keeps the unwinder out of the component and the size-shaped
# optimisation is what keeps the import list at exactly `log`. Cargo reads a profile only
# from a workspace root, and this is one, so it is repeated here rather than inherited.
[profile.release]
panic = "abort"
lto = true
opt-level = "s"
strip = true
codegen-units = 1
```

**The `ouroboros-guest` path.** `ouroboros-guest` is not published, so the dependency is a
path, and that path must reach `tui/wasm/guest` **in the checkout your workspace is** —
written relative to your project directory. If your project is at `<workspace>/capabilities/
vet`, the path is `../../tui/wasm/guest`.

The forge **rewrites this line** before it builds: whatever you wrote, the dependency it
compiles against is this node's own SDK checkout, resolved by the node and not by your file.
So the line is not the thing that decides what code runs at build time — it is the thing that
has to agree with the `Cargo.lock` you pinned and with the manifest the forge validates, and
a path that does not resolve on your side is a lock that does not match. Write it relative to
your project so the three agree. Do not copy a path out of another machine's file, do not
guess an absolute one, and do not point it at a directory you created.

### `src/lib.rs`

Read `tui/wasm/guest/examples/counter/src/lib.rs` in this checkout. It is short, it is built
by the SDK's own test suite, and it shows all of it: the `Capability` trait (`init` from the
start config, `handle` for each message), a `Describe` with a summary, an input schema and an
example, and how to refuse bad input with `Err(String)` instead of trapping.

The skeleton:

```rust
#![no_std]

use ouroboros_guest::{export_capability, json, Capability, Describe, String, Value};

struct MyCapability;

impl Capability for MyCapability {
    fn describe() -> Describe {
        Describe::new("my-capability", env!("CARGO_PKG_VERSION"))
            .summary("One line a reader can act on.")
    }

    fn init(_config: Value) -> Result<Self, String> {
        Ok(MyCapability)
    }

    fn handle(&mut self, body: Value) -> Result<Value, String> {
        Ok(json!({ "echo": body }))
    }
}

export_capability!(MyCapability);
```

`describe()` is **prose the component writes about itself**. It is shown to whoever lists
capabilities, under a label saying it is untrusted, and nothing above verifies a word of it.
Write it to inform.

### `Cargo.lock` — the pin

The lock is not yours to resolve. It must be the guest SDK's own
`tui/wasm/guest/Cargo.lock`, plus one `[[package]]` entry for your own crate and nothing
else. The forge compares it byte for byte and refuses anything else, because the lock is the
whole of what "this build resolved to the dependencies this node has already cached" means —
and the build runs offline, so a lock naming a crate the cache does not hold is a build that
cannot finish.

The reliable way to get one: copy `tui/wasm/guest/examples/counter/Cargo.lock`, and change
the one `name = "counter"` line in it to your crate's name. That file is exactly the SDK's
lock plus the example's own entry, which is the shape being asked for.

### `manifest.json` — the proposal

The same file an operator writes beside a capability they admit by hand, so one format serves
both. It supplies the name, a description, the evaluation spec and the start config; the
`forge` tool reads it from your project directory when you do not pass those as parameters.
It is never part of the build.

```json
{
  "name": "my-capability",
  "description": "what it does, in one sentence",
  "eval": {
    "probes": [
      { "input": { "ping": 1 }, "expect": "any_reply" },
      { "input": { "ping": 1 }, "expect": ["state_matches", "messages_received", 2] }
    ],
    "budget_ms": 10000,
    "required": "all"
  },
  "start": { "config": "{}" }
}
```

**The evaluation spec is not optional in practice.** This node's signer refuses to sign a
capability with no evaluation, so a forge without one fails at the signature after paying for
the whole build. `probes` are messages the rollout sends to the real component before it goes
live; `expect` is `"any_reply"`, `["equals", value]`, `["contains", text]` or
`["state_matches", key, value]`. `required` is `"all"`. Write probes that would actually fail
if the component were wrong.

**The `start` block is what makes it run.** `start.config` is the JSON *string* handed to
`init` — `"{}"` when `init` ignores it. Without the block the signed manifest declares no
durable id, so a `deploy` registers the rollout and starts nothing: the capability is `:live`
in the register and a `capability call` answers "a live rollout but no agent is running for
it on this node". Include it. The id is derived from the name and is not yours to state.

## One name

The capability's name appears in four places and they must all agree:

1. the `name` parameter you pass to `preview` and `forge`,
2. `[package] name` in `Cargo.toml`,
3. `name` in `manifest.json`,
4. the `name = "..."` entry for your crate in `Cargo.lock`.

The forge refuses a disagreement before it builds. The name is also what the operator's
permission rule is written about — `Forge(my-capability)` — and it is compared **exactly**:
lowercase letters, digits, `.`, `-` and `_`, starting with a letter or digit, at most 64
bytes, and no leading or trailing whitespace.

## The four operations, in order

**1. `preview`** — `{"operation": "preview", "name": ..., "path": ...}`

Validates everything below and runs a dry build. Signs nothing, allocates nothing, writes no
bundle. It costs a full compile, so run it once, on a project you believe in. Its answer
tells you the files it accepted, the source digest, the toolchain, whether the dry build
succeeded, and whether it found an evaluation spec.

**2. `forge`** — `{"operation": "forge", "name": ..., "path": ...}` plus optional `eval` and
`start_config` when you are not using `manifest.json`.

Builds, reads the imports off the bytes it just built, signs, allocates an epoch, and keeps
the bundle on this node. Nothing is running yet. The answer carries the **artifact id**,
which is what the next step needs.

The `author` recorded in the signed manifest is **this session**. It is not a parameter and
you cannot set it.

**3. `deploy`** — `{"operation": "deploy", "artifact_id": ...}`

Takes the bundle this session forged, verifies the signature against this node's trust
policy, stages the component, and rolls it out here: the evaluation runs against the real
component, and it goes live only if the probes pass. The answer carries the rollout state and
the evaluation's report.

A bundle **another** principal forged is refused. A session deploys what it forged.

**4. `status`** — `{"operation": "status"}`

What this session has forged and still holds, and what the register says about each.

Then, in a later turn, the `capability` tool: `{"operation": "call", "name": ...,
"message": {...}}`.

## What the fences refuse, and how it reads

Every one of these is answered before or during validation, so most of them cost nothing:

| refusal | what it means |
|---|---|
| `is not a file a capability project may contain` | something outside the five names above, or a `build.rs` |
| `the project has N files; the bound is 32` | more than 32 files |
| `the project is N bytes; the bound is …` | more than one mebibyte in total |
| `is a symlink` | a symlink anywhere in the tree; the forge follows none |
| `Cargo.lock is not the guest SDK's lock` | the pin — see above |
| `the ouroboros-guest dependency is not one this node accepts` | the path dependency is not this checkout's `tui/wasm/guest` |
| `[profile.release] may not change …` | the release profile was edited |
| `the project's Cargo package is X and this call named Y` | the four names disagree |
| `One capability, one name` | `manifest.json` names something else |
| `cargo did not produce a component` | the build failed; the compiler's own output is in the message |
| `this node has no OS sandbox to build inside` | the node cannot build at all; tell the operator |
| `the build passed its … ceiling` | the build ran past the node's ceiling and was stopped |
| `that path is not usable` | the directory is outside this session's workspace |
| `forged by another principal` | a deploy of somebody else's bundle |

The build itself runs offline, inside an OS sandbox, with the cargo cache and the SDK
readable and only its own scratch directory writable. A build that tried to reach the network
or write outside its tree fails there rather than being refused here.

## What to expect from the operator

The first `forge` or `preview` for a name asks them, unless they have written a rule. The rule
they are offered is `Forge(<name>)` — about the one capability, not about the tool. There is
deliberately no way to write an allow for the tool itself, so if you need to build several
capabilities, expect to be asked once per name.

A `deploy` names an artifact id rather than a name, but the runtime resolves that id against
the bundles it holds and verifies the signature before it asks anybody anything — so a
`deploy` is covered by the **same** `Forge(<name>)` rule as the build that produced it, and
an operator who allowed building `vet` has allowed deploying `vet`. If the bundle at that id
is no longer the one the decision was about, the deploy is refused by name rather than
shipped under somebody else's allow.

A `preview` and a `forge` also tell the engine which directory they are about to read, so a
rule that **denies or asks** about that directory covers them. An allow on `Read(…)` does not
allow a forge; only `Forge(…)` does.

Writing `ouroboros.toml` is refused by the permission engine whatever the rules say, and — on
Seatbelt and on bubblewrap — by the OS sandbox as well, so a shell cannot reach it either by
`cp`, `mv`, `tee` or a Python one-liner. On a backend that cannot fence a single file, shell
hooks from this workspace are declined instead. So is anything under `.git` or `.ouroboros`.
