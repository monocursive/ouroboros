# J1: Remove Jido AI without changing the tool contract

Status: proposed implementation specification, 2026-09-10. No implementation is
included. Baseline: `dev` at `d6cc85309141111b6ae1ae3852b254a30092f426`.

This is the first of three independently reviewable migrations. Continue with
[J2: the owned session contract](replace-jido-harness.md), then
[J3: the remaining core interfaces](replace-jido-core.md).

## 1. Outcome

Remove `jido_ai` from the resolved dependency graph while preserving the tool specs
seen by models, accepted and rejected arguments, effective arguments after defaults,
and tool execution behavior. Keep `req_llm`, `jido`, `jido_action`, and
`jido_harness` at their current versions in this slice.

Success is an equivalence result against the old implementation, not just a green
test suite or the absence of an import.

## 2. Current boundary

The only production Jido AI call is `ToolAdapter.from_action(module)` in
[`Tools.spec/2`](../../lib/ouroboros/provider/native/tools.ex). It builds a temporary
`ReqLLM.Tool`; Ouroboros retains its name, description, and parameter schema, then
applies its own description and `model_schema/0` overrides.

The pinned adapter delegates conversion to `Jido.Action.Schema.to_json_schema/2`,
infers strictness from an optional `strict?/0`, recursively defaults object schemas
to `additionalProperties: false`, and normalizes an empty schema into an empty
object schema. The actual model client subsequently builds its own `ReqLLM.Tool`.

Execution already belongs to Ouroboros:

- [`Tools.validate_call/3`](../../lib/ouroboros/provider/native/tools.ex) validates
  model arguments against the advertised JSON Schema before permission/execution.
- `Tools.invoke/3` converts declared top-level keys, calls the action module's
  `validate_params/1`, and then its `run/2` under Ouroboros's audit boundary.
- [`Model.ToolSchema`](../../lib/ouroboros/provider/native/model/tool_schema.ex)
  handles transport-specific strict schemas and restores synthetic optional nulls.

These are separate contracts. Preserve all three.

## 3. Scope and exclusions

Change the schema-construction boundary, dependency declarations/lock, targeted
tests, and current documentation describing Jido AI. Historical proposals may keep
their original names and explanations.

Do not change tools, permission rules, model selection, request caching, the native
loop, MCP behavior, Jido Action validation, or the session runtime. Do not remove
`jido_action`; J3 owns that work. Do not upgrade remaining dependencies as part of
lockfile cleanup.

## 4. Owned schema adapter

Add `Ouroboros.Provider.Native.Tools.Schema` with one public operation:

```elixir
@spec from_action(module()) :: map()
```

It returns the generated parameter schema only. `Tools.spec/2` obtains the name
and static description directly from the action module and retains its existing
description override and final `model_schema/0` override.

The adapter must reproduce the pinned conversion in this order:

1. Ensure the action module and `Jido.Action.Schema` are loaded before inspecting
   optional exports; lazy loading must not change strictness or output.
2. Use `module.strict?/0` when exported, otherwise `false`.
3. Call the pinned `Jido.Action.Schema.to_json_schema(module.schema(), strict: strict)`.
   There is no need for the old adapter's multi-version arity fallback.
4. Walk maps and lists recursively. On objects, or maps with `properties`, add
   `additionalProperties: false` only when that key is absent. Preserve an explicit
   `true` or schema-valued `additionalProperties`.
5. Turn an empty result into exactly
   `%{"type" => "object", "properties" => %{}, "required" => [],
   "additionalProperties" => false}`.

Do not construct a temporary `ReqLLM.Tool` or introduce a no-op execution callback
here. Keep the real transport adapter and its existing callback unchanged.

Declare `jido_action` directly in `mix.exs`, using a requirement compatible with the
current locked version: this slice now explicitly calls its schema API. Remove
`jido_ai`, then prune only unreachable lock entries. Packages still used directly
by Ouroboros or another dependency stay even if Jido AI also used them.

## 5. Equivalence evidence

### Capture before replacement

Generate a deterministic fixture from the baseline implementation before removing
Jido AI. Record the source revision, relevant package versions, context inputs, and
the command that generated it. Use synthetic workspaces and model metadata; no
credentials, live inference, or network access are needed.

Capture every module returned by `Tools.modules/0`, plus the conditional
`Tools.Capability` and `Tools.Forge` modules directly. Exercise the composed list
with fleet visible/hidden, depth restrictions, allowed/disallowed tools, required
audit mode, and deterministic skill descriptions. Supply controlled capability,
forge, and MCP fixtures rather than depending on the developer machine's state.

The fixture contains the complete final `{name, description, parameters}` values,
not a count or a list of names. Map key order may be canonicalized; list order,
required fields, descriptions, defaults, enums, and nullability may not.

### Compare at each boundary

| Boundary | Required assertion |
|---|---|
| Generated schema | New adapter equals the old adapter for each action and edge-case fixture |
| Final tool spec | Description overrides, nested `model_schema/0` overrides, tool order and filtering equal baseline |
| Local JSON Schema validation | Same acceptance/rejection and same operator/model-facing diagnostic for baseline cases |
| Action validation | Same effective arguments after declared-key conversion and defaults; same observable errors |
| Model transport | Same prepared schemas and strictness; same restoration of synthetic optional nulls |
| Execution | Invalid input reaches neither permission dispatch nor a tool effect; valid synthetic calls receive identical effective inputs |

Include missing required fields, wrong primitive types, integer bounds, omitted
defaults, explicit nulls, unknown keys, atom/string key collisions, nested arrays
and objects, empty schemas, explicit open objects, and strictness callbacks. Include
the `plan`, `agent`, `capability`, and `forge` schema overrides. MCP schemas bypass
the action converter and must remain exact/open as advertised.

Use differential assertions while both adapters exist in the working change.
Once the old dependency is removed, retain the frozen baseline fixtures and the
focused behavioral tests. Never regenerate expected output from the replacement
just to make a comparison pass. Dependency-specific exception struct names may
disappear only where they were private; visible validation messages are preserved.

## 6. Implementation sequence

1. Capture the baseline and add the parity cases while Jido AI is still available.
2. Add the owned converter and compare it with the old one.
3. Switch `Tools.spec/2`; verify final specs, validation, and model-wire preparation.
4. Declare `jido_action`, remove `jido_ai`, and prune unreachable dependencies.
5. Remove transient differential code, retaining baseline fixtures; update current
   comments/docs and dependency-specific typing suppressions that are now obsolete.

Each step belongs to the same bounded change. Do not ship two selectable converters.

## 7. Acceptance and validation

- No production or test code loads/calls `Jido.AI`; `jido_ai` is absent from both
  the lock and the resolved production application graph.
- All baseline equivalence assertions pass without Jido AI on the code path.
- A clean dependency build confirms no accidental reliance on stale BEAM files.
- Run the focused tools, model tool-schema, native loop, and native session tests;
  then the repository gate, `make test`. Run `make dialyzer` for the changed types.
- Run the existing golden/protocol drift checks; expected public fixture diff is
  empty. Inspect dependency changes for unrelated upgrades.
- Run the existing boot gate on copied data. Removing a package also removes atom
  definitions; any compatibility additions belong in the existing explicit retired
  atom mechanism, never in unsafe decoding.

No live-provider quality or latency claim follows from these tests. Record exactly
which checks ran and distinguish clean-build proof from source-only assertions.

## 8. Stop and rollback conditions

A schema or accepted-input difference blocks completion until understood and
corrected. A desirable schema improvement is a separate change, not an exception
to parity. If some adapter behavior still needs Jido AI, identify that concrete
caller rather than retaining the whole package without explanation.

This slice deliberately changes no durable format. Code rollback is therefore a
revert of the converter and dependency change; verify the unchanged-format premise
with the boot fixtures before declaring that rollback safe.
