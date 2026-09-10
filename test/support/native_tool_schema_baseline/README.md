# J1 frozen tool schemas

`specs.json` was captured on 2026-09-10 from `dev` at
`d6cc85309141111b6ae1ae3852b254a30092f426`, **before** replacing `Tools.spec/2` or
removing Jido AI. The provenance object records package versions, source hashes,
context inputs, and the command used. Only JSON map keys were sorted; lists and
all values are unchanged.

The oracle contains all 15 `Tools.modules/0` actions, conditional capability and
forge, six synthetic edge modules, the complete final spec for each, description
override/fallback cases, and nine composed lists. The helper creates project and
user skills (including shadowing and a budget cutoff), controls forge configuration,
provides a memory-only capability registry, and supplies a read-only MCP pool.
No developer workspace, installed skill, capability, MCP command, credential,
model provider, or network operation participates. The MCP fixture bypasses only
process startup and supplies the post-handshake tools directly; production
`Mcp.specs/2` still constructs and budgets its specs.

The frozen output must never be regenerated from the replacement adapter to make
a failed assertion pass. Public schema changes require separate review.

The pinned source has `model_schema/0` overrides for plan, capability and forge.
Agent has no such override in this revision: its generated schema is its final
parameter contract, and both forms are captured and compared. Empty keyword
schemas already produce an empty object in the pinned action converter; the
owned adapter also retains the historical defensive `%{}` fallback.

## Historical reproduction

Use a separate checkout of the source revision above with its original lock and
dependencies. Copy `test/support/native_tool_schema_baseline.ex` from this change
into that checkout, and compile the baseline test environment (`MIX_ENV=test mix
compile`). The capture used already compiled baseline BEAM files, then required
the newly authored fixture helper directly without compiling production changes.
Put this historical script at `/tmp/capture_native_schema_baseline.exs`:

```elixir
alias Ouroboros.NativeToolSchemaBaseline, as: Baseline
alias Ouroboros.Provider.Native.Tools

Baseline.with_context(fn context ->
  generated = Map.new(Baseline.all_modules(), fn module ->
    Code.ensure_loaded!(module)
    {inspect(module), Jido.AI.ToolAdapter.from_action(module).parameter_schema}
  end)

  final = Map.new(Baseline.all_modules(), fn module ->
    {inspect(module), Tools.spec(module, context.options)}
  end)

  data = %{
    generated: generated,
    final: final,
    descriptions: Baseline.description_specs(),
    composed: Baseline.composed_specs(context),
    context_inputs: Baseline.context_inputs()
  }

  File.write!("/tmp/native_tool_schema_baseline.raw.json", JSON.encode!(data))
end)
```

Run from that historical checkout:

```sh
MIX_ENV=test mix run --no-start --no-compile \
  -r test/support/native_tool_schema_baseline.ex \
  /tmp/capture_native_schema_baseline.exs
```

Compare the decoded result to `specs.json` excluding `provenance`. Map ordering
has no semantic significance; array ordering does. The checked-in JSON was
pretty-printed with Python `json.dumps(data, indent=2, sort_keys=True,
ensure_ascii=False)` plus a trailing newline, after adding the provenance object.

## Differential evidence before removal

With both adapters present, the following loop compared the 23 generated schemas
and passed without differences:

```elixir
alias Ouroboros.NativeToolSchemaBaseline, as: Baseline
alias Ouroboros.Provider.Native.Tools.Schema

for module <- Baseline.all_modules() do
  Code.ensure_loaded!(module)
  old = Jido.AI.ToolAdapter.from_action(module).parameter_schema
  new = Schema.from_action(module)
  if old != new, do: raise("schema mismatch for #{inspect(module)}")
end
```

The command was `MIX_ENV=test mix run --no-start --no-compile -r
test/support/native_tool_schema_baseline.ex -r
lib/ouroboros/provider/native/tools/schema.ex
/tmp/compare_native_schema_adapters.exs`. These old-adapter calls remain only in
this historical documentation; no production or test code loads or calls it.
The retained tests compare the owned adapter against the frozen JSON, and also
exercise cold loading of both an action's strict callback and the schema converter.

The separate [behavior baseline](../fixtures/native_tool_behavior_baseline.md)
records 47 complete validation results, 13 action observations, 60 prepared tools
across three transport contexts, and 11 null-restoration results. Its tests also
prove that invalid writes never reach permission dispatch, with a valid-call
positive control for the permission probe.

## Validation of the replacement (2026-09-10)

The four removed lock entries are `jido_ai` 2.3.0, `fsmx` 0.5.0,
`yaml_elixir` 2.12.2 and `yamerl` 0.10.0. Comparing the parsed lock against
`Map.drop(baseline_lock, [:jido_ai, :fsmx, :yaml_elixir, :yamerl])` found all 54
remaining entries unchanged, including the pinned Harness Git revision.
`mix deps.clean jido_ai fsmx yaml_elixir yamerl --build` removed stale compiled
copies across existing build environments before final validation.

| Check | Result |
| --- | --- |
| Old/new generated-schema differential, before removal | 23/23 identical |
| `mix test test/provider/native/tools_test.exs test/provider/native/model_tool_schema_test.exs` after switching | 55 passed |
| `mix test --no-compile test/provider/native/tools_schema_parity_test.exs` | 8 passed |
| `mix test test/provider/native/tools_behavior_parity_test.exs` after dependency removal | 7 passed, including the permission positive control |
| `SHELL=/bin/sh mix test test/provider/native/tools_schema_parity_test.exs test/provider/native/tools_behavior_parity_test.exs` with final strict fixture comparisons | 15 passed; integer/float identity is preserved as well as values |
| `MIX_ENV=prod MIX_BUILD_PATH=_build/j1-clean-prod mix compile` with that build path absent initially | All dependencies and 240 production source files compiled successfully |
| Recursive production application and code-path audit in that clean build | 76 applications; all four removed packages absent from both the application closure and code paths |
| `make dialyzer` | Passed; no new suppression or Jido AI-specific suppression was needed |
| `make test` | Passed: formatting and script checks; 3,697 Elixir tests passed, 14 skipped; all 20 copied-data boots; 1,505 Rust tests without `embed` and 1,514 with it; Rust formatting; Clippy for both configurations with warnings denied |
| `make protocol-docs` (includes `make golden`) | Passed; no diff in gateway fixtures or `docs/PROTOCOL.md` |
| Final `mix format --check-formatted` and `git diff --check` | Passed |

The broader focused invocation was `SHELL=/bin/sh mix test
test/provider/native/tools*_test.exs test/provider/native/model_tool_schema_test.exs
test/provider/native/loop*_test.exs test/provider/native/session*_test.exs
test/provider/native/harness_session_test.exs`. It passed 180 of 181 tests; the
permission positive control compared `/var` against macOS's canonical `/private/var`.
The assertion was corrected to use `scope.root`, and all seven behavioral tests
then passed. No production path behavior changed.

The production graph audit recursively loaded application specifications and
traversed both `:applications` and `:included_applications`, starting at
`:ouroboros`, without starting applications. It asserted that none of the four
removed packages was in that closure and that `:code.lib_dir/1` returned
`{:error, :bad_name}` for each. The recorded invocation was
`MIX_ENV=prod MIX_BUILD_PATH=_build/j1-clean-prod mix run --no-start --no-compile
_build/j1-validation/production-graph.exs`. Local command logs are under
`_build/j1-validation/`; they are build artifacts, not frozen expected outputs.

No production or test source calls or loads `Jido.AI`. The retained source-capture
script refuses the replacement implementation; transient differential scripts
were removed after recording their historical bodies above.

The copied-data boot gate matched every recorded count in ten plain boots and
ten preloaded boots, including only the existing expected grants quarantine.
No durable format or retired-atom change was needed. Reverting the converter,
its wiring and the dependency change therefore requires no data migration for
the unchanged formats exercised by those fixtures.

These are local contract, build and runtime results. No live-provider inference,
quality evaluation, latency benchmark, release or deployment was performed.
