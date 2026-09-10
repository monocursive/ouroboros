# Run only on the pre-J3 source: MIX_ENV=test mix run --no-start --no-compile scripts/capture_action_message_baseline.exs
unless function_exported?(Jido.Signal, :__struct__, 0) || Code.ensure_loaded?(Jido.Signal),
  do: raise("Capture requires the original Jido dependencies")

unless Ouroboros.Provider.Native.Tools.Read.module_info(:attributes)[:behaviour] == [Jido.Action],
  do: raise("Capture requires original action modules")

{:ok, _} = Application.ensure_all_started(:jido_signal)
Code.require_file("test/support/action_message_baseline.ex")
Application.put_env(:ouroboros, :audit, mode: :standard)
{revision, 0} = System.cmd("git", ["rev-parse", "HEAD"])
lock = Mix.Dep.Lock.read()

fixture = %{
  source_revision: String.trim(revision),
  packages: Map.take(lock, [:jido, :jido_action, :jido_signal, :nimble_options]),
  sources:
    Map.new(
      [
        "lib/ouroboros/signals.ex",
        "test/support/native_tool_behavior_baseline.ex",
        "lib/ouroboros/provider/native/tools.ex"
      ],
      fn path ->
        {path, Base.encode16(:crypto.hash(:sha256, File.read!(path)), case: :lower)}
      end
    ),
  observations: Ouroboros.Test.ActionMessageBaseline.capture()
}

File.write!(
  "test/support/fixtures/action_message_baseline.exs",
  "# Frozen with pre-J3 dependencies. Do not regenerate using the owned implementation.\n" <>
    inspect(fixture, pretty: true, limit: :infinity, printable_limit: :infinity, width: 100) <>
    "\n"
)

IO.puts("Captured pre-J3 action and message baseline")
