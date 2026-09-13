defmodule Ouroboros.Interactive.CrashDiagnosticsTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ouroboros.Interactive.{State, Store}
  alias Ouroboros.Interactive.Task, as: InteractiveTask

  @tag :capture_log
  test "an isolated Interactive.Task crash exposes only bounded diagnostics" do
    canaries = %{
      conversation: "CONVERSATION_CANARY",
      tool: "TOOL_ARGUMENT_CANARY",
      token: "TOKEN_CANARY",
      approval: "APPROVAL_CANARY",
      grant: "GRANT_CANARY",
      authority: "AUTHORITY_CANARY"
    }

    id = "diagnostic-session-#{System.unique_integer([:positive, :monotonic])}"
    workspace = Path.join(System.tmp_dir!(), id)
    File.mkdir_p!(workspace)
    Ouroboros.Test.DurableFence.ensure_started!(workspace)
    {:ok, session} = State.new(id, provider: :native, workspace: workspace)

    session = %{
      session
      | provider: :claude,
        status: :idle,
        runtime_id: "diagnostic-runtime-id",
        provider_session_id: "diagnostic-provider-id",
        turns: %{
          "diagnostic-turn-id" => %{
            request: canaries.conversation,
            tool_args: canaries.tool,
            token: canaries.token
          },
          String.duplicate(canaries.authority, 20) => %{grant: canaries.grant}
        },
        options: %{token: canaries.token},
        runtime_snapshot: %{conversation: canaries.conversation}
    }

    :sys.replace_state(Store, fn state ->
      %{state | sessions: Map.put(state.sessions, id, session)}
    end)

    previous_trap = Process.flag(:trap_exit, true)

    on_exit(fn ->
      Process.flag(:trap_exit, previous_trap)
      File.rm_rf(workspace)

      :sys.replace_state(Store, fn state ->
        %{state | sessions: Map.delete(state.sessions, id)}
      end)
    end)

    log =
      capture_log(fn ->
        {:ok, admission} = Ouroboros.Maintenance.Fence.acquire("crash-fixture:" <> id, id)

        {:ok, pid} =
          try do
            InteractiveTask.start_link({id, admission})
          after
            :ok = Ouroboros.Maintenance.Fence.release(admission)
          end

        :sys.replace_state(pid, fn runtime ->
          runtime
          |> Map.put(:external_approvals, %{
            "diagnostic-approval-id" => %{
              approval: canaries.approval,
              grant: canaries.grant,
              authority: canaries.authority
            }
          })
          |> Map.put(:conversation, canaries.conversation)
          |> Map.put(:tool_input, canaries.tool)
          |> Map.put(:access_token, canaries.token)
          |> Map.put(:grant, canaries.grant)
          |> Map.put(:authority, canaries.authority)
        end)

        monitor = Process.monitor(pid)

        # This enters Interactive.Task.handle_cast/2 and raises while reading event.type.
        # The malformed event is also a realistic raw-argument leak vector in the crash report.
        GenServer.cast(pid, {
          :subagent_bridge_event,
          %{payload: %{raw_args: canaries.tool, authority: canaries.authority}}
        })

        assert_receive {:DOWN, ^monitor, :process, ^pid, {{:badkey, :type, _raw_event}, stack}},
                       1_000

        assert Enum.any?(stack, &match?({InteractiveTask, :handle_cast, 2, _}, &1))
        assert_receive {:EXIT, ^pid, {{:badkey, :type, _raw_event}, _stack}}, 1_000
      end)

    assert log =~ "KeyError"

    session_digest =
      :crypto.hash(:sha256, id) |> Base.encode16(case: :lower) |> binary_part(0, 16)

    assert log =~ "sha256:#{session_digest}"

    # The OTP process label necessarily names the registered public session. Every identifier
    # contained only in task state is correlated by digest and never emitted verbatim.
    for identifier <- [
          "diagnostic-runtime-id",
          "diagnostic-provider-id",
          "diagnostic-turn-id",
          "diagnostic-approval-id"
        ] do
      digest =
        :crypto.hash(:sha256, identifier)
        |> Base.encode16(case: :lower)
        |> binary_part(0, 16)

      assert log =~ "sha256:#{digest}"
      refute log =~ identifier
    end

    assert log =~ "interactive/task.ex"

    for {_kind, canary} <- canaries, do: refute(log =~ canary)
    refute log =~ "raw_args"
    assert byte_size(log) < 8_192
  end
end
