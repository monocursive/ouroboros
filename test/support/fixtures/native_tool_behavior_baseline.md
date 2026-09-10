# Native tool behavior baseline

`native_tool_behavior_baseline.exs` freezes observations from
`d6cc85309141111b6ae1ae3852b254a30092f426` before removing its action schema adapter.
The original `Tools` source SHA-256 and the five relevant lock entries are stored
beside the observations. Map layout is formatting only; the fixture preserves
list order, complete schemas, descriptions, results, and diagnostic strings.

The authoritative capture contains 47 local JSON validation cases, 13 action
validation/execution cases, 3 complete model-transport preparations of 20 tools,
and 11 input-restoration cases. Model metadata and MCP contracts are inline,
user skills are an isolated empty directory, and audit uses `:standard` mode.
No credentials, provider calls, deployed capabilities, forge jobs, or configured
MCP servers are involved. The synthetic action sends its effective arguments to
the capture process; it performs no external effect.

The initial `--no-start` attempt was discarded: ReqLLM's schema ETS cache was not
initialized, so it reported infrastructure errors instead of validating input.
The retained capture script explicitly creates that cache, and checks a known
valid input, a required-field rejection, and the probe's effective default values
before writing a fixture.

By the corrected capture, `Tools.spec/2` had already been switched in the shared
working directory. In a separate `mix run --no-start` VM, the capture loaded the
**original source from `git show`** with `Code.compile_string(source, source_path)`
before invoking the retained capture logic. It did not edit the working source or
write historical BEAM files. That temporary invocation was:

```sh
MIX_ENV=test mix run --no-start /tmp/j1-capture-native-tool-behavior-baseline.exs
```

The temporary file was the retained
`scripts/capture_native_tool_behavior_baseline.exs`, with its working-source
equality guard replaced by `Code.compile_string(source, source_path)` and its
recorded command updated to identify that invocation. All expected observations
came from the original implementation, including the corrected validation data;
the replacement was never used to generate expected values. The discarded
capture contributed no expected validation results.

To reproduce in a separate baseline checkout, copy the retained capture script
and `test/support/native_tool_behavior_baseline.ex` there, then run:

```sh
MIX_ENV=test mix run --no-start scripts/capture_native_tool_behavior_baseline.exs
```

The retained script rejects a checkout whose `Tools` source is not byte-identical
to the recorded baseline. Do not regenerate this fixture on a changed converter
to resolve a failed parity assertion.

`tools_behavior_parity_test.exs` compares the complete frozen observations and
also runs a scripted native loop with malformed writes. A permission probe
verifies that rejected arguments reach neither permission dispatch nor file
effects. A valid write reaches the same probe and is denied, providing a positive
control for permission instrumentation. Separate valid synthetic calls cross local JSON validation and action
execution and receive the frozen effective arguments. Atom/string key collisions
are preserved independently at both validation boundaries, including the old
JSON validator's observable rejection.
