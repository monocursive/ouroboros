defmodule Ouroboros.Provider.Native.LoopLedgerTest.RefusingStorage do
  @moduledoc """
  A ledger checkpoint that cannot be written.

  This is how "kill the ledger" is expressed in a test: not by killing the process, which
  would take the whole node's audit trail down with it, but by taking away the one thing
  that makes a write durable. `Ouroboros.Agent.EffectLedger` answers every `record_started`
  with an error, and the loop's response to that error is the property under test.
  """

  def get_checkpoint(_key, _opts), do: :not_found
  def put_checkpoint(_key, _checkpoint, _opts), do: {:error, :storage_offline}
end

defmodule Ouroboros.Provider.Native.LoopLedgerTest do
  @moduledoc """
  I1 — every tool the native agent runs, in the durable effect ledger.

  The claims these tests pin are the ones a tool ledger is worth nothing without: the
  entry exists *before* the tool does, a ledger that cannot record refuses the call rather
  than running it unrecorded, the outcome that lands is the outcome that happened, and
  nothing the model or the workspace said ever enters the record.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.LoopLedgerTest.RefusingStorage
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Test.NativeModelScript

  @secret "sk-live-do-not-record-me"

  setup do
    root = Path.join(System.tmp_dir!(), "native-ledger-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace/lib"))
    File.mkdir_p!(Path.join(root, "session"))
    File.write!(Path.join(root, "workspace/lib/a.ex"), "defmodule A do\n  # #{@secret}\nend\n")
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)

    session_id = "ledger-sess-#{System.unique_integer([:positive, :monotonic])}"

    %{
      root: root,
      scope: scope,
      session_dir: Path.join(root, "session"),
      workspace: scope.root,
      session_id: session_id,
      principal: "session:" <> session_id
    }
  end

  describe "a tool call is recorded before it runs" do
    test "the entry is already durable at the instant the tool is observably running",
         context do
      marker = Path.join(context.root, "marker")
      gate = Path.join(context.root, "gate")

      command =
        "printf started > #{marker}; while [ ! -f #{gate} ]; do sleep 0.02; done; echo released"

      {loop, _agent} =
        start_loop(context, [
          [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => command}}}],
          [{:text, "done"}, {:finish, :stop}]
        ])

      run(loop)

      # The command has written its marker, so the tool is running. If the checkpoint were
      # best effort, or after the run, there would be nothing to find here.
      wait_until(fn -> File.exists?(marker) end)

      assert [entry] = entries(context)
      assert entry.status == :started
      assert entry.effect == :tool_call
      assert entry.attempt.tool == "bash"
      assert entry.attempt.call_id == "c1"
      assert entry.attempt.turn_id == "turn-1"
      assert entry.result == nil
      assert entry.settled_at == nil

      File.write!(gate, "go")
      collect()

      assert [settled] = entries(context)
      assert settled.status == :ok
      assert settled.result.status == :completed
      assert settled.result.output_bytes > 0
      assert is_integer(settled.result.duration_ms)
    end

    test "a ledger that cannot record refuses the call, and the tool never runs", context do
      touched = Path.join(context.root, "touched")

      {loop, _agent} =
        start_loop(context, [
          [
            {:tool_call,
             %{id: "c1", name: "bash", input: %{"command" => "printf ran > #{touched}"}}}
          ],
          [{:text, "gave up"}, {:finish, :stop}]
        ])

      events =
        with_refusing_ledger(fn ->
          run(loop)
          collect()
        end)

      result = find(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ "effect ledger could not record"
      assert result.payload["output"] =~ "so it did not run"

      refute File.exists?(touched),
             "the tool ran although its attempt could not be recorded"
    end
  end

  describe "the outcome that lands is the outcome that happened" do
    test "a tool that reports an error settles as failed", context do
      {loop, _agent} =
        start_loop(context, [
          [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/nowhere.ex"}}}],
          [{:text, "no such file"}, {:finish, :stop}]
        ])

      run(loop)
      collect()

      assert [entry] = entries(context)
      assert entry.status == :failed
      assert entry.result.status == :failed
      assert entry.error.classification == {:tool_call_not_completed, :failed}
    end

    test "a tool killed at its timeout settles as timed_out", context do
      {loop, _agent} =
        start_loop(
          context,
          [
            [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "sleep 5"}}}],
            [{:text, "too slow"}, {:finish, :stop}]
          ],
          tool_timeout_ms: 150
        )

      run(loop)
      collect()

      assert [entry] = entries(context)
      assert entry.status == :failed
      assert entry.result.status == :timed_out
      assert entry.result.duration_ms >= 150
    end

    test "a call nobody approved is one terminal refusal, and the tool never ran", context do
      touched = Path.join(context.root, "touched")

      {loop, _agent} =
        start_loop(
          context,
          [
            [
              {:tool_call,
               %{id: "c1", name: "bash", input: %{"command" => "printf ran > #{touched}"}}}
            ],
            [{:text, "refused"}, {:finish, :stop}]
          ],
          approval_mode: :prompt,
          approval_timeout_ms: 150
        )

      run(loop)
      events = collect()

      assert find(events, :approval_requested)
      assert find(events, :tool_result).payload["is_error"]

      assert [entry] = entries(context)
      assert entry.status == :denied
      assert entry.result.status == :refused
      assert entry.authority.decision == :deny
      assert entry.authority.reason == "timeout"
      assert entry.settled_at != nil
      refute File.exists?(touched)
    end
  end

  describe "identities, never contents" do
    test "a command is a digest and its text is nowhere in the entry", context do
      command = "echo #{@secret}"

      {loop, _agent} =
        start_loop(context, [
          [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => command}}}],
          [{:text, "done"}, {:finish, :stop}]
        ])

      run(loop)
      collect()

      assert [entry] = entries(context)

      assert entry.attempt.subject.command_sha256 ==
               :sha256 |> :crypto.hash(command) |> Base.encode16(case: :lower)

      refute Map.has_key?(entry.attempt.subject, :paths)
      refute inspect(entry) =~ @secret
      refute inspect(entry) =~ "echo"
    end

    test "a file tool records the path it touched and none of the file", context do
      {loop, _agent} =
        start_loop(context, [
          [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
          [{:text, "read it"}, {:finish, :stop}]
        ])

      run(loop)
      events = collect()

      # The tool really did read the secret; the ledger really does not have it.
      assert find(events, :tool_result).payload["output"] =~ @secret

      assert [entry] = entries(context)
      assert [path] = entry.attempt.subject.paths
      assert path =~ "lib/a.ex"
      refute Map.has_key?(entry.attempt.subject, :command_sha256)
      refute inspect(entry) =~ @secret
    end
  end

  describe "the reference a client draws the row from" do
    test "every gated tool_call event names the entry ledger.get takes", context do
      {loop, _agent} =
        start_loop(context, [
          [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
          [{:text, "done"}, {:finish, :stop}]
        ])

      run(loop)
      events = collect()

      ref = find(events, :tool_call).payload["ledger_ref"]
      assert ref["node"] == Atom.to_string(node())
      assert String.starts_with?(ref["id"], "tool-")

      assert {:ok, entry} = EffectLedger.get(ref["id"])
      assert entry.effect == :tool_call
      assert entry.attempt.call_id == "c1"
    end

    test "a tool the session does not have claims no entry it has no row for", context do
      {loop, _agent} =
        start_loop(context, [
          [{:tool_call, %{id: "c1", name: "teleport", input: %{}}}],
          [{:text, "no such tool"}, {:finish, :stop}]
        ])

      run(loop)
      events = collect()

      assert find(events, :tool_call).payload["ledger_ref"] == nil
      assert find(events, :tool_result).payload["is_error"]
      assert entries(context) == []
    end
  end

  # ------------------------------------------------------------------ helpers

  defp start_loop(context, script, overrides \\ []) do
    {model_spec, agent} = NativeModelScript.start(script)
    test = self()

    loop =
      struct!(
        %Loop{
          emit: fn event -> send(test, {:event, event}) end,
          model_module: NativeModelScript,
          model_spec: model_spec,
          system: "system",
          scope: context.scope,
          session_dir: context.session_dir,
          session_id: context.session_id,
          provider_session_id: "native-ledger-test",
          turn_id: "turn-1",
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000
        },
        overrides
      )

    {loop, agent}
  end

  defp run(loop, prompt \\ "do the thing") do
    parent = self()
    spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, prompt)}) end)
  end

  defp collect(acc \\ []) do
    receive do
      {:event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:event, event} ->
        collect([event | acc])
    after
      20_000 -> flunk("no terminal turn event within 20s")
    end
  end

  defp find(events, type), do: Enum.find(events, &(&1.type == type))

  # Only this session's rows. The ledger is node-wide and every other test on this node
  # writes into it, so a query that did not name its principal would be reading somebody
  # else's history.
  defp entries(context) do
    {:ok, entries} = EffectLedger.list(principal: context.principal, effect: :tool_call)
    Enum.sort_by(entries, & &1.started_sequence)
  end

  # Swaps the node's ledger for one whose storage refuses, under the registered name the
  # loop reaches it by. Safe because this module is `async: false`: ExUnit runs synchronous
  # modules one at a time, after the asynchronous ones have finished.
  defp with_refusing_ledger(fun) do
    original = Process.whereis(EffectLedger)
    Process.unregister(EffectLedger)

    {:ok, refusing} =
      EffectLedger.start_link(
        name: EffectLedger,
        storage: {RefusingStorage, table: :loop_ledger_refusing}
      )

    try do
      fun.()
    after
      Process.unregister(EffectLedger)
      GenServer.stop(refusing)
      Process.register(original, EffectLedger)
    end
  end

  defp wait_until(fun, attempts \\ 400)
  defp wait_until(_fun, 0), do: flunk("condition did not become true within 4s")

  defp wait_until(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(10)
      wait_until(fun, attempts - 1)
    end
  end
end
