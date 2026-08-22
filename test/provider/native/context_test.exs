defmodule Ouroboros.Provider.Native.ContextTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Context
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-context-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)
    previous_dir = Application.get_env(:ouroboros, :native_data_dir)
    previous_model = Application.get_env(:ouroboros, :native_model_module)
    previous_window = Application.get_env(:ouroboros, :native_context_window)
    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      restore(:native_data_dir, previous_dir)
      restore(:native_model_module, previous_model)
      restore(:native_context_window, previous_window)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, data_dir: data_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

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

  defp drain do
    receive do
      {:session_adapter_event, _event} -> drain()
    after
      0 -> :ok
    end
  end

  defp done, do: [{:text, "done"}, {:usage, %{input_tokens: 10, output_tokens: 2}}]

  describe "the prefix layout" do
    test "system prompt, then tools, then conversation" do
      {:ok, context} = Context.build(cwd: "/tmp", instructions: false, model_spec: "x:y")
      prefix = Context.prefix(context)

      assert is_binary(prefix.system)
      assert prefix.tools == Tools.specs(nil, nil)
      # The prefix is the two of them and nothing else: the conversation is never in it.
      assert Map.keys(prefix) |> Enum.sort() == [:system, :tools]
    end

    test "tool order is Tools.modules/0's order, not a sort" do
      {:ok, context} = Context.build(cwd: "/tmp", instructions: false)
      assert Enum.map(context.tools, & &1.name) == ["read", "write", "edit", "bash", "plan"]
    end

    test "descriptions are full where no model module declares tool search" do
      {:ok, context} =
        Context.build(cwd: "/tmp", instructions: false, model_module: NativeModelScript)

      assert context.deferred == []
      plan = Enum.find(context.tools, &(&1.name == "plan"))
      assert plan.description == Tools.spec(Ouroboros.Provider.Native.Tools.Plan).description
    end
  end

  describe "prefix_fingerprint/1" do
    test "two builds of the same session agree" do
      opts = [cwd: "/tmp", instructions: false, model_spec: "anthropic:claude-sonnet-5"]
      {:ok, one} = Context.build(opts)
      {:ok, two} = Context.build(opts)

      assert Context.prefix_fingerprint(one) == Context.prefix_fingerprint(two)
      assert byte_size(Context.prefix_fingerprint(one)) == 64
    end

    test "a different model changes it" do
      {:ok, one} = Context.build(cwd: "/tmp", instructions: false, model_spec: "a:b")
      {:ok, two} = Context.build(cwd: "/tmp", instructions: false, model_spec: "c:d")

      refute Context.prefix_fingerprint(one) == Context.prefix_fingerprint(two)
    end

    test "a different reasoning effort changes it" do
      {:ok, one} = Context.build(cwd: "/tmp", instructions: false, reasoning_effort: :low)
      {:ok, two} = Context.build(cwd: "/tmp", instructions: false, reasoning_effort: :high)

      refute Context.prefix_fingerprint(one) == Context.prefix_fingerprint(two)
    end

    test "a different tool set changes it" do
      {:ok, one} = Context.build(cwd: "/tmp", instructions: false)

      {:ok, two} =
        Context.build(cwd: "/tmp", instructions: false, tools: Tools.specs(["read"], nil))

      refute Context.prefix_fingerprint(one) == Context.prefix_fingerprint(two)
    end

    test "compaction changes it" do
      {:ok, context} = Context.build(cwd: "/tmp", instructions: false)
      compacted = Context.compacted(context, cwd: "/tmp", instructions: false)

      refute Context.prefix_fingerprint(context) == Context.prefix_fingerprint(compacted)
      assert compacted.compactions == 1
    end

    test "an instruction file changes it, and editing that file changes it again", context do
      agents = Path.join(context.workspace, "AGENTS.md")
      {:ok, without} = Context.build(cwd: context.workspace, instructions: false)

      File.write!(agents, "one")
      {:ok, one} = Context.build(cwd: context.workspace, user_scope: false)

      File.write!(agents, "two")
      {:ok, two} = Context.build(cwd: context.workspace, user_scope: false)

      assert length(Enum.uniq([without, one, two] |> Enum.map(&Context.prefix_fingerprint/1))) ==
               3
    end
  end

  describe "the fingerprint across a live session" do
    test "is the same string on every turn", context do
      session = open(context, [done(), done(), done()])

      {:ok, before_info} = Session.info(session.handle)
      turn(session, "t1")
      {:ok, after_one} = Session.info(session.handle)
      turn(session, "t2")
      {:ok, after_two} = Session.info(session.handle)

      assert before_info.prefix_fingerprint == after_one.prefix_fingerprint
      assert after_one.prefix_fingerprint == after_two.prefix_fingerprint
    end

    test "the model was actually sent that prefix, byte for byte, on every turn", context do
      session = open(context, [done(), done()])

      turn(session, "t1")
      turn(session, "t2")

      systems = session.agent |> NativeModelScript.requests() |> Enum.map(& &1.system)
      tools = session.agent |> NativeModelScript.requests() |> Enum.map(& &1.tools)

      assert length(Enum.uniq(systems)) == 1
      assert length(Enum.uniq(tools)) == 1
    end

    test "configure changes it, and only then", context do
      session = open(context, [done(), done()])

      turn(session, "t1")
      {:ok, before_configure} = Session.info(session.handle)

      :ok = Session.configure(session.handle, %{"reasoning_effort" => :high})
      {:ok, after_configure} = Session.info(session.handle)

      refute before_configure.prefix_fingerprint == after_configure.prefix_fingerprint
    end

    test "a rejected configure leaves the prefix alone", context do
      session = open(context, [done()])
      {:ok, before_configure} = Session.info(session.handle)

      assert {:error, {:unsupported_configuration, _key, _value}} =
               Session.configure(session.handle, %{"nonsense" => 1})

      {:ok, after_configure} = Session.info(session.handle)
      assert before_configure.prefix_fingerprint == after_configure.prefix_fingerprint
    end

    test "compacting changes it", context do
      session = open(context, [done(), done()])
      turn(session, "t1")
      drain()

      {:ok, before_compact} = Session.info(session.handle)
      {:ok, _report} = Session.compact(session.handle, nil)
      {:ok, after_compact} = Session.info(session.handle)

      refute before_compact.prefix_fingerprint == after_compact.prefix_fingerprint
    end
  end

  describe "public info" do
    test "names and numbers only — never the instruction text", context do
      File.write!(Path.join(context.workspace, "AGENTS.md"), "SECRET-INSTRUCTION-TEXT")
      session = open(context, [done()])

      {:ok, info} = Session.info(session.handle)

      assert Enum.any?(info.instruction_files, &String.ends_with?(&1, "workspace/AGENTS.md"))
      assert info.instruction_bytes > 0
      refute inspect(info) =~ "SECRET-INSTRUCTION-TEXT"
    end

    test "carries the fields the footer and gateway want", context do
      session = open(context, [done()])
      {:ok, info} = Session.info(session.handle)

      for key <- [
            :prefix_fingerprint,
            :context_window,
            :context_used,
            :compact_at,
            :keep_recent_tokens,
            :tools,
            :compactions,
            :archives,
            :handed_off_to
          ] do
        assert Map.has_key?(info, key), "info is missing #{key}"
      end
    end
  end
end
