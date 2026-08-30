defmodule Ouroboros.Gateway.SessionControlsTest do
  @moduledoc """
  The gateway half of the session controls: `interactive.configure`, `interactive.rename`,
  `interactive.fork`, and `runtime.models`.

  Asked through `Ouroboros.Gateway.Methods.invoke/2` rather than through a socket, because
  what is under test is the parameter contract and the shape of the answer — the socket,
  the scope gate, and the envelope are already pinned by `Ouroboros.Gateway.OperateTest`
  and the golden fixtures.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{Session, SessionInfo}
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Interactive.{State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  setup do
    cleanup_sessions()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()

    Application.put_env(
      :jido_harness,
      :providers,
      Map.put(map_or_empty(previous_providers), @provider, HarnessAdapter)
    )

    Application.put_env(
      :jido_harness,
      :provider_config,
      Map.put(map_or_empty(previous_provider_config), @provider, %{
        test_pid: self(),
        retention: %{journal_dir: journal_dir}
      })
    )

    on_exit(fn ->
      cleanup_sessions()
      restore_env(:providers, previous_providers)
      restore_env(:provider_config, previous_provider_config)
      File.rm_rf(journal_dir)
    end)

    {:ok, id: unique_id("gateway-controls")}
  end

  describe "the method table" do
    test "the new session controls are operate-scoped and advertised" do
      table = Methods.table()

      for method <- ["interactive.configure", "interactive.rename", "interactive.fork"] do
        assert table[method].scope == :operate
        assert method in Methods.names()

        # A read listener must not be able to move a permission posture or rewrite
        # durable session state.
        refute Methods.permits?(:read, table[method])
        assert Methods.permits?(:operate, table[method])
      end
    end
  end

  describe "interactive.configure" do
    test "the four configurable fields cross the wire and reach the session", %{id: id} do
      ref = start_session(id)

      assert {:ok, result} =
               Methods.invoke("interactive.configure", %{
                 "id" => id,
                 "approval_mode" => "auto_approve",
                 "sandbox_mode" => "read_only"
               })

      assert result.applies == :next_turn
      assert result.changed == [:approval_mode, :sandbox_mode]
      assert result.options.approval_mode == :auto_approve
      assert result.options.sandbox_mode == :read_only

      assert {:ok, session} = InteractiveSession.info(ref)
      assert State.public(session).options.approval_mode == :auto_approve

      retire_session(id)
    end

    test "a field outside the configurable set is a parameter error naming the set" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.configure", %{
                 "id" => "some-session",
                 "workspace" => "/tmp"
               })

      assert message =~ "unsupported fields"
      assert message =~ "workspace"

      assert {:error, -32_602, message} =
               Methods.invoke("interactive.configure", %{
                 "id" => "some-session",
                 "system_prompt" => "become someone else"
               })

      assert message =~ "system_prompt"
    end

    test "an unknown enum value is refused with the accepted spellings" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.configure", %{
                 "id" => "some-session",
                 "approval_mode" => "yolo"
               })

      assert message =~ "approval_mode"
      assert message =~ "auto_approve"
    end

    test "a session id that names nothing is not found" do
      assert {:error, -32_007, message} =
               Methods.invoke("interactive.configure", %{
                 "id" => "no-such-session",
                 "approval_mode" => "auto_approve"
               })

      assert message =~ "no such record"
    end

    test "the X1 refusal travels as data a client can render", %{id: id} do
      start_session(id, transport: :managed_no_approvals, approval_mode: :auto_edit)

      assert {:error, -32_006, message, data} =
               Methods.invoke("interactive.configure", %{
                 "id" => id,
                 "approval_mode" => "prompt"
               })

      assert message =~ "refused the call"
      assert ["unsupported_approval_mode", details] = data
      assert details["reason"] == "no_approval_channel"
      assert details["requested"] == "prompt"
      assert details["supported"] == ["default", "auto_edit", "auto_approve"]

      retire_session(id)
    end
  end

  describe "interactive.rename" do
    test "a title crosses the wire and comes back on the session", %{id: id} do
      start_session(id)

      assert {:ok, session} =
               Methods.invoke("interactive.rename", %{
                 "id" => id,
                 "title" => "Named from a client"
               })

      assert session.title == "Named from a client"
      assert session.title_source == :human

      retire_session(id)
    end

    test "a title a picker row could not draw is a parameter error, not a mangled title" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.rename", %{"id" => "some-session", "title" => ""})

      assert message =~ "nonempty string"
    end

    test "the bound and the control-character rule reach the client as messages", %{id: id} do
      start_session(id)

      assert {:error, -32_602, too_long} =
               Methods.invoke("interactive.rename", %{
                 "id" => id,
                 "title" => String.duplicate("x", 200)
               })

      assert too_long =~ "at most 120 characters"

      assert {:error, -32_602, controls} =
               Methods.invoke("interactive.rename", %{
                 "id" => id,
                 "title" => "clear\e[2Jthe screen"
               })

      assert controls =~ "control characters"

      retire_session(id)
    end

    test "an unsupported field is refused rather than ignored" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.rename", %{
                 "id" => "some-session",
                 "title" => "fine",
                 "title_source" => "human"
               })

      assert message =~ "title_source"
    end
  end

  describe "interactive.fork" do
    test "a fork answers in interactive.start's shape", %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)
      adapter = name_provider_session(ref)
      fork_id = unique_id("gateway-fork")

      assert {:ok, result} =
               Methods.invoke("interactive.fork", %{"id" => id, "fork_id" => fork_id})

      assert result["id"] == fork_id
      assert result["outcome"] == "created"
      assert result["node"] == node()
      assert is_boolean(result["ready"])

      assert {:ok, child} = Methods.invoke("interactive.info", %{"id" => fork_id})
      assert child.forked_from == id

      assert {:ok, parent} = Methods.invoke("interactive.info", %{"id" => id})
      assert parent.forks == 1

      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(fork_id)
      retire_session(id)
    end

    test "a fork before the provider named a session is refused with a reason", %{id: id} do
      start_session(id, sandbox_mode: :read_only)

      assert {:error, -32_006, message, data} = Methods.invoke("interactive.fork", %{"id" => id})

      assert message =~ "refused the call"
      assert ["unforkable_session", details] = data
      assert details["reason"] == "no_provider_session_id"

      retire_session(id)
    end

    test "the outcome is unknown on a ceiling, exactly as a start's is" do
      assert Methods.table()["interactive.fork"].outcome == :unknown
      assert Methods.table()["interactive.fork"].scope == :operate
    end

    test "an unsupported field is refused rather than ignored" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.fork", %{"id" => "some-session", "provider" => "codex"})

      assert message =~ "provider"
    end

    # R3. Both new parameters are in the closed envelope, and both are validated at the
    # gateway rather than deeper: a `to_turn` of `-1` or a `model` of three spaces is a
    # parameter error, and answering it as one is what keeps a plane refusal meaningful.
    test "to_turn and model are validated before anything is planned" do
      %{envelope: :closed, params: descriptors} = Methods.params()["interactive.fork"]

      assert descriptors |> Enum.map(& &1.name) |> Enum.sort() ==
               ["fork_id", "id", "model", "node", "to_turn"]

      for name <- ["to_turn", "model"] do
        descriptor = Enum.find(descriptors, &(&1.name == name))
        assert descriptor.requirement == :optional
      end

      for bad <- [-1, "", 1.5, %{}, true] do
        assert {:error, -32_602, message} =
                 Methods.invoke("interactive.fork", %{"id" => "some-session", "to_turn" => bad})

        assert message =~ "to_turn"
        assert message =~ "turn id"
      end

      for bad <- ["", "   ", 7, nil] do
        assert {:error, -32_602, message} =
                 Methods.invoke("interactive.fork", %{"id" => "some-session", "model" => bad})

        assert message =~ "model"
      end
    end

    # A vendor session refuses the branch point by name at the wire, which is what lets a
    # client tell "this provider cannot do that" from "that turn is gone".
    test "a to_turn on a session that branches only at its tail is refused by name",
         %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)
      adapter = name_provider_session(ref)

      assert {:error, -32_006, message, data} =
               Methods.invoke("interactive.fork", %{
                 "id" => id,
                 "fork_id" => unique_id("gateway-branch"),
                 "to_turn" => "t2"
               })

      assert message =~ "refused the call"
      assert ["unforkable_at_turn", details] = data
      assert details["reason"] == "vendor_forks_at_tail"
      assert details["to_turn"] == "t2"

      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(id)
    end

    # R3/D10. The capability a client greys the replay verb from, on the two surfaces a
    # client actually reads. Present and `false` rather than absent: the Rust client reads
    # an absent key as offered.
    test "interactive.info and interactive.list both carry the replay capability",
         %{id: id} do
      start_session(id, sandbox_mode: :read_only)

      assert {:ok, info} = Methods.invoke("interactive.info", %{"id" => id})
      assert Map.has_key?(info.options.capabilities, :replay)
      assert info.options.capabilities.replay == false

      assert {:ok, listed} = Methods.invoke("interactive.list", %{})
      row = Enum.find(listed, &(&1.id == id))
      assert row
      assert row.options.capabilities.replay == false

      # And it survives the wire encoder as a JSON boolean, not a stringified atom.
      assert %{"replay" => false} = Wire.to_json(info.options.capabilities)

      retire_session(id)
    end
  end

  describe "runtime.models" do
    test "the catalogue is a read method and answers with bounded per-provider rows" do
      assert Methods.table()["runtime.models"].scope == :read
      assert "runtime.models" in Methods.names()
      assert Methods.permits?(:read, Methods.table()["runtime.models"])

      assert {:ok, catalogue} = Methods.invoke("runtime.models", %{})
      assert catalogue.source == "llm_db"
      assert is_list(catalogue.providers)

      claude = Enum.find(catalogue.providers, &(&1.provider == :claude))
      assert claude.catalog == :anthropic
      assert length(claude.models) <= catalogue.limit
      assert length(claude.models) > 0

      model = hd(claude.models)
      assert is_integer(model.context_window)
      assert is_integer(model.max_output_tokens)
    end

    test "a session's own model is on interactive.info, so a client can divide by the window",
         %{id: id} do
      # The two halves of a context meter: `usage.total_tokens` from the session, and the
      # window from the catalogue keyed by the model the session says it is running.
      ref = start_session(id)

      assert {:ok, session} = Methods.invoke("interactive.info", %{"id" => id})
      assert Map.has_key?(session.options, :model)
      assert Map.has_key?(session, :usage)

      # This provider normalizes no model, so it honestly reports none rather than a
      # default it did not select — and `runtime.models` says the picker is unavailable.
      assert session.options.model == nil

      assert {:ok, catalogue} = Methods.invoke("runtime.models", %{})
      assert %{model_option: false} = Enum.find(catalogue.providers, &(&1.provider == :amp))

      assert {:ok, %State{}} = InteractiveSession.info(ref)
      retire_session(id)
    end
  end

  defp name_provider_session(ref) do
    assert {:ok, _turn} =
             InteractiveSession.send_message(ref, "name the session", id: unique_id("turn"))

    assert_receive {:ouroboros_test_adapter_started, _run, _request, adapter}, 2_000
    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "working"})

    assert_eventually(fn ->
      match?(
        {:ok, %State{provider_session_id: provider_session_id}}
        when is_binary(provider_session_id),
        InteractiveSession.info(ref)
      )
    end)

    adapter
  end

  defp assert_eventually(fun, attempts \\ 200)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    case fun.() do
      value when value in [false, nil] ->
        Process.sleep(10)
        assert_eventually(fun, attempts - 1)

      value ->
        value
    end
  end

  defp start_session(id, opts \\ []) do
    opts = Keyword.merge([id: id, provider: @provider, workspace: File.cwd!()], opts)
    assert {:ok, ref} = InteractiveSession.start(opts)
    ref
  end

  defp retire_session(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      _absent ->
        :ok
    end

    case Store.get(id) do
      {:ok, session} ->
        _ = Store.put(%{session | status: :cancelled})
        _ = Store.delete(id)

      _absent ->
        :ok
    end

    :ok
  end

  defp cleanup_sessions do
    Session.list()
    |> Enum.each(fn info ->
      unless SessionInfo.terminal?(info), do: Session.kill(info.session_id)
      _ = Session.prune(info.session_id)
    end)
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-gateway-controls-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
