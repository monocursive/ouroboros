defmodule Ouroboros.Provider.Native.HandoffTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Context.Handoff
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-handoff-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)
    previous_dir = Application.get_env(:ouroboros, :native_data_dir)
    previous_model = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      restore(:native_data_dir, previous_dir)
      restore(:native_model_module, previous_model)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, data_dir: data_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  describe "the packet" do
    test "carries the five headings, the files, the plan, and the instruction", context do
      target = Path.join(context.workspace, "lib/a.ex")

      packet =
        Handoff.packet(
          summary: "## Goal\n\nship it\n\n## Next steps\n\nrun the tests",
          files: [target],
          plan: %{"items" => [%{"text" => "write the migration", "status" => "in_progress"}]},
          prompt: "finish the migration",
          workspace: context.workspace,
          parent: "native-a-b"
        )

      assert packet =~ "## Goal"
      assert packet =~ "ship it"
      assert packet =~ "lib/a.ex"
      assert packet =~ "sha256 "
      assert packet =~ "[in_progress] write the migration"
      assert packet =~ "finish the migration"
      assert packet =~ "native-a-b"
    end

    test "hashes each file as it is now, not as it was", context do
      target = Path.join(context.workspace, "lib/a.ex")
      before_hash = hd(Handoff.hash_files([target])).sha256

      File.write!(target, "defmodule A do\n  def x, do: 2\nend\n")
      after_hash = hd(Handoff.hash_files([target])).sha256

      refute before_hash == after_hash
      assert byte_size(after_hash) == 64
    end

    test "a file that has gone says so instead of carrying a hash", context do
      missing = Path.join(context.workspace, "lib/gone.ex")
      assert [%{sha256: nil, note: "no longer exists"}] = Handoff.hash_files([missing])

      packet = Handoff.packet(files: [missing], workspace: context.workspace)
      assert packet =~ "no longer exists"
    end

    test "an absent summary is admitted, never invented" do
      packet = Handoff.packet(summary: nil, prompt: "go")
      assert packet =~ "no summary"
      refute packet =~ "## Goal"
    end

    test "an absent instruction tells the new session to ask rather than guess" do
      packet = Handoff.packet(summary: "## Goal\n\nx", prompt: nil)
      assert packet =~ "do not start work on a guess"
    end

    test "the packet is bounded in files" do
      paths = for index <- 1..500, do: "/nonexistent/file-#{index}"
      assert length(Handoff.hash_files(paths)) == 200
    end
  end

  describe "handoff from a live session" do
    test "starts a new session seeded with the packet and records the parent's pointer",
         context do
      session =
        open(context, [
          [{:text, "did the work"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nship the thing\n\n## Next steps\n\nrun mix test"}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, "carry on from here")

      assert String.starts_with?(result.provider_session_id, "native-")
      refute result.provider_session_id == session_id(session)
      assert Process.alive?(result.pid)
      assert result.packet_bytes > 0

      {:ok, info} = Session.info(session.handle)
      assert info.handed_off_to == result.provider_session_id

      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)
    end

    test "the child's first message is the packet, and it is durable", context do
      session =
        open(context, [
          [
            {:text, "read it"},
            {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
          ],
          [{:text, "done"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nSUMMARY-FROM-THE-MODEL"}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, "OPERATOR-INSTRUCTION")
      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)

      {:ok, path, _durable?} = Checkpoint.locate(result.provider_session_id)
      {:ok, [first | rest]} = Checkpoint.read(path)

      assert rest == []
      assert first.role == :user
      assert first.content =~ "SUMMARY-FROM-THE-MODEL"
      assert first.content =~ "OPERATOR-INSTRUCTION"
      assert first.content =~ "lib/a.ex"
    end

    test "the child runs in the same workspace and can take a turn", context do
      session =
        open(context, [
          [{:text, "ok"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nx"}],
          [{:text, "child answered"}, {:usage, %{input_tokens: 7, output_tokens: 1}}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, "keep going")
      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)

      :ok = Session.send(result.pid, TurnRequest.new!(%{prompt: "next"}), "child-turn")
      events = await_terminal()

      assert Enum.any?(events, &(&1.type == :turn_completed))

      # The child was sent the packet and the operator's new turn, in that order.
      [request | _rest] = session.agent |> NativeModelScript.requests() |> Enum.reverse()
      contents = Enum.map(request.messages, &Map.get(&1, :content))
      assert Enum.any?(contents, &(is_binary(&1) and &1 =~ "Handed-off state"))
    end

    test "a handoff emits an event naming the child", context do
      session =
        open(context, [
          [{:text, "ok"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nx"}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, nil)
      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)

      event = await_provider_event("handoff")
      assert event.payload["provider_session_id"] == result.provider_session_id
      assert event.payload["packet_bytes"] > 0
    end

    test "a handoff does not close the parent", context do
      session =
        open(context, [
          [{:text, "ok"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nx"}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, nil)
      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)

      assert Process.alive?(session.handle)
    end
  end

  # ---------------------------------------------------------------- helpers

  defp session_id(session) do
    {:ok, info} = Session.info(session.handle)
    info.provider_session_id
  end

  defp open(context, script, overrides \\ %{}) do
    {model_spec, agent} = NativeModelScript.start(script)

    request =
      SessionRequest.new!(
        Map.merge(
          %{
            provider: :native,
            cwd: context.workspace,
            model: model_spec,
            approval_mode: :auto_approve,
            approval_timeout_ms: 2_000
          },
          overrides
        )
      )

    session_context = %{
      session_id: "sess-#{System.unique_integer([:positive])}",
      provider: :native,
      owner: self(),
      adapter: Ouroboros.Provider.Native,
      config: %{},
      process_manager: Jido.Harness.ProcessDriver.Erlexec,
      telemetry_context: %{}
    }

    {:ok, handle} = Session.open(request, session_context)
    on_exit(fn -> if Process.alive?(handle), do: Session.close(handle) end)
    %{handle: handle, agent: agent, model_spec: model_spec}
  end

  defp turn(session, turn_id) do
    :ok = Session.send(session.handle, TurnRequest.new!(%{prompt: "go"}), turn_id)
    await_terminal()
  end

  defp await_terminal(acc \\ []) do
    receive do
      {:session_adapter_event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:session_adapter_event, event} ->
        await_terminal([event | acc])
    after
      15_000 -> flunk("no terminal turn event; got #{inspect(Enum.map(acc, & &1.type))}")
    end
  end

  defp await_provider_event(kind, acc \\ []) do
    receive do
      {:session_adapter_event, %{type: :provider_event, payload: %{"kind" => ^kind}} = event} ->
        event

      {:session_adapter_event, event} ->
        await_provider_event(kind, [event.type | acc])
    after
      5_000 -> flunk("no #{kind} provider event; saw #{inspect(Enum.reverse(acc))}")
    end
  end

  defp drain do
    receive do
      {:session_adapter_event, _event} -> drain()
    after
      0 -> :ok
    end
  end
end
