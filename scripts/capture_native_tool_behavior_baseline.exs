# Run only on the baseline Tools implementation; the captured outputs are immutable
# migration evidence. The script deliberately refuses to bless replacement output.
source_revision = "d6cc85309141111b6ae1ae3852b254a30092f426"
source_path = "lib/ouroboros/provider/native/tools.ex"
{source, 0} = System.cmd("git", ["show", "#{source_revision}:#{source_path}"])

if File.read!(source_path) != source do
  raise "baseline capture requires the original Tools implementation at #{source_revision}"
end

# ReqLLM normally creates this at application startup. Only its schema cache is needed
# here; starting the node or a provider would add unrelated machine state to the capture.
:ets.new(:req_llm_schema_cache, [:named_table, :public, :set, read_concurrency: true])

lock = Mix.Dep.Lock.read()
packages = [:jido_ai, :jido_action, :jido, :jido_harness, :req_llm]

fixture = %{
  source_revision: source_revision,
  source_sha256: Base.encode16(:crypto.hash(:sha256, source), case: :lower),
  packages: Map.new(packages, &{&1, lock[&1]}),
  command: "MIX_ENV=test mix run --no-start scripts/capture_native_tool_behavior_baseline.exs",
  context: %{
    distributed: false,
    user_skills: "isolated empty directory",
    audit: :standard,
    model_metadata: "inline, synthetic"
  },
  captured:
    Ouroboros.Test.NativeToolBehaviorBaseline.with_context(
      &Ouroboros.Test.NativeToolBehaviorBaseline.capture/0
    )
}

valid = Enum.find(fixture.captured.validation, &(&1.id == "omitted_defaults"))
{:ok, %{"path" => "README.md"}} = valid.result
invalid = Enum.find(fixture.captured.validation, &(&1.id == "missing_required"))
{:error, message} = invalid.result
false = String.contains?(message, "ETS")
false = String.contains?(message, "Invalid JSON Schema")
defaults = Enum.find(fixture.captured.action, &(&1.id == "defaults"))

{:received, %{title: "Inspect", count: 2, enabled: false, items: [], payload: nil}} =
  defaults.observation.effective_input

false = defaults.observation.result.is_error

destination = "test/support/fixtures/native_tool_behavior_baseline.exs"
File.mkdir_p!(Path.dirname(destination))

File.write!(
  destination,
  "# Frozen from the original pre-J1 action schema adapter. Do not regenerate from the replacement.\n" <>
    inspect(fixture,
      pretty: true,
      limit: :infinity,
      printable_limit: :infinity,
      width: 98,
      sort_maps: true
    ) <>
    "\n"
)

IO.puts("Captured #{destination}")
