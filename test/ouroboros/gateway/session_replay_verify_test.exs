defmodule Ouroboros.Gateway.SessionReplayVerifyTest do
  @moduledoc """
  R2's verb on the wire: `interactive.replay_verify`.

  The same two lanes `SessionJournalTest` splits into, for the same reason. The refusal lane
  runs against the ordinary harness adapter, because a transport that keeps no journal has
  to say so as wire data rather than answer "unverified" — those are different facts and a
  client that could not tell them apart would report a vendor session as a failed one. The
  native lane runs a real `provider: :native` session with the deterministic model script,
  because the only way to prove the verb verifies a session is to make a session that can be.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{Session, SessionInfo}
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.{Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Provider.Native.Journal
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Test.NativeModelScript

  @provider :ouroboros_test

  setup do
    cleanup_sessions()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()

    root = Path.join(System.tmp_dir!(), "gateway-verify-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")
    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)

    previous_native_dir = Application.get_env(:ouroboros, :native_data_dir)
    previous_native_model = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

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
      restore_harness(:providers, previous_providers)
      restore_harness(:provider_config, previous_provider_config)
      restore_ouroboros(:native_data_dir, previous_native_dir)
      restore_ouroboros(:native_model_module, previous_native_model)
      File.rm_rf(journal_dir)
      File.rm_rf(root)
    end)

    {:ok, id: unique_id("gateway-verify"), workspace: workspace}
  end

  describe "the method table" do
    test "verification is operate scope, with a ceiling of its own" do
      table = Methods.table()

      # `computer_use.status`/`probe` is the precedent: this starts a process — a real turn
      # loop per recorded turn — even though it spends nothing and writes nothing.
      assert table["interactive.replay_verify"].scope == :operate
      assert "interactive.replay_verify" in Methods.names()
      assert Methods.permits?(:operate, table["interactive.replay_verify"])
      refute Methods.permits?(:read, table["interactive.replay_verify"])

      # A long session re-derives many turns, so it does not ride the read ceiling. And it
      # admits no unknown outcome: there is nothing half-done to reconcile, because it
      # changes nothing.
      assert table["interactive.replay_verify"].timeout > table["interactive.journal"].timeout
      refute Map.has_key?(table["interactive.replay_verify"], :outcome)
    end

    test "the envelope is closed" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.replay_verify", %{"id" => "s", "since_seq" => 1})

      assert message =~ "since_seq"
    end

    test "a session id that names nothing is not found" do
      assert {:error, -32_007, message} =
               Methods.invoke("interactive.replay_verify", %{"id" => "no-such-session"})

      assert message =~ "no such record"
    end
  end

  describe "a transport that keeps no journal" do
    test "is refused as wire data naming the verb, not answered as unverified", %{id: id} do
      start_session(id)

      assert {:error, -32_006, _message, ["unsupported_on_transport", details]} =
               Methods.invoke("interactive.replay_verify", %{"id" => id})

      assert details["verb"] == "replay_verify"
      retire_session(id)
    end
  end

  describe "a native session, verified on the wire" do
    test "the turn it just ran re-derives, and the verdict says so", context do
      id = context.id
      session = start_native(id, context, [[{:text, "hello back"}, {:finish, :stop}]])

      assert {:ok, _turn} = InteractiveSession.send_message(session, "say hello")
      await_turn(session)

      assert {:ok, verdict} = Methods.invoke("interactive.replay_verify", %{"id" => id})

      assert verdict["verified"] == true
      assert verdict["turns"] == 1
      assert verdict["divergence"] == nil
      assert byte_size(verdict["head"]) == 64
      assert verdict["records"] >= 6

      # The closed envelope, exactly: nothing else rides back with it.
      assert Map.keys(verdict) |> Enum.sort() ==
               ["divergence", "head", "records", "turns", "verified"]

      retire_session(id)
    end

    test "a flipped byte mid-journal is a chain break, not a verdict", context do
      id = context.id
      session = start_native(id, context, [[{:text, "hello back"}, {:finish, :stop}]])

      assert {:ok, _turn} = InteractiveSession.send_message(session, "say hello")
      await_turn(session)

      path = journal_path(session)
      [first | rest] = path |> File.read!() |> String.split("\n", trim: true)
      tampered = first |> JSON.decode!() |> Map.put("at", "1999-01-01T00:00:00.000000Z")
      File.write!(path, Enum.join([JSON.encode!(tampered) | rest], "\n") <> "\n")

      assert {:error, _code, _message, _data} =
               Methods.invoke("interactive.replay_verify", %{"id" => id})

      retire_session(id)
    end

    test "the verdict is the same whether or not the transport is still alive", context do
      id = context.id
      session = start_native(id, context, [[{:text, "hello back"}, {:finish, :stop}]])

      assert {:ok, _turn} = InteractiveSession.send_message(session, "say hello")
      await_turn(session)

      assert {:ok, live} = Methods.invoke("interactive.replay_verify", %{"id" => id})

      # The native transport, gone. The record is on disk and the verdict is unchanged,
      # which is the whole reason this verb reads the file rather than asking the session.
      provider_session_id = provider_session_id(session)
      pid = Ouroboros.Provider.Native.Session.whereis(provider_session_id)
      if is_pid(pid), do: GenServer.stop(pid, :normal)

      assert {:ok, dead} = Methods.invoke("interactive.replay_verify", %{"id" => id})
      assert dead == live

      retire_session(id)
    end
  end

  # ------------------------------------------------------------------ helpers

  defp journal_path(session) do
    {:ok, dir, _durable?} = Paths.session_dir(provider_session_id(session))
    Journal.path(dir)
  end

  defp provider_session_id(session) do
    {:ok, info} = InteractiveSession.info(session)
    info.provider_session_id
  end

  defp start_native(id, context, script, overrides \\ []) do
    {model_spec, _agent} = NativeModelScript.start(script)

    opts =
      Keyword.merge(
        [
          id: id,
          provider: :native,
          workspace: context.workspace,
          model: model_spec,
          approval_mode: :auto_approve
        ],
        overrides
      )

    assert {:ok, session} = InteractiveSession.start(opts)
    session
  end

  defp await_turn(session) do
    wait_until(fn ->
      case InteractiveSession.replay(session, cursor: 0, limit: 200) do
        {:ok, events} -> Enum.any?(events, &(&1.type == :turn_completed))
        _other -> false
      end
    end)
  end

  defp wait_until(fun, attempts \\ 600)
  defp wait_until(_fun, 0), do: flunk("condition did not become true")

  defp wait_until(fun, attempts) do
    case fun.() do
      value when value in [false, nil] ->
        Process.sleep(25)
        wait_until(fun, attempts - 1)

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
      "ouroboros-gateway-verify-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore_harness(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_harness(key, value), do: Application.put_env(:jido_harness, key, value)

  defp restore_ouroboros(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore_ouroboros(key, value), do: Application.put_env(:ouroboros, key, value)
end
