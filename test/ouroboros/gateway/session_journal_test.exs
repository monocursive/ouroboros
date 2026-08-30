defmodule Ouroboros.Gateway.SessionJournalTest do
  @moduledoc """
  R1's read verb on the wire: `interactive.journal`.

  Two lanes, the same split `SessionContextTest` makes. The refusal lane runs against the
  ordinary test harness adapter, because what is under test there is that a transport with
  no turn journal says so as wire data rather than answering with an empty record. The
  native lane runs a real `provider: :native` session through `Ouroboros.InteractiveSession`
  with the deterministic model script, because the only way to prove the verb hands back a
  session's record is to make a session record something.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{Session, SessionInfo}
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.{Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Test.NativeModelScript

  @provider :ouroboros_test

  setup do
    cleanup_sessions()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()

    root = Path.join(System.tmp_dir!(), "gateway-journal-#{System.unique_integer([:positive])}")
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

    {:ok, id: unique_id("gateway-journal"), workspace: workspace}
  end

  describe "the method table" do
    test "the journal is read scope, and advertised" do
      table = Methods.table()

      assert table["interactive.journal"].scope == :read
      assert "interactive.journal" in Methods.names()
      assert Methods.permits?(:read, table["interactive.journal"])

      # It reads one file and starts nothing, so it takes the same ceiling as the other
      # session reads and admits no unknown outcome — there is nothing it could half-do.
      assert table["interactive.journal"].timeout == table["interactive.replay"].timeout
      refute Map.has_key?(table["interactive.journal"], :outcome)
    end

    test "the envelope is closed" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.journal", %{"id" => "s", "cursor" => 1})

      assert message =~ "cursor"
    end

    test "the cursor and the limit are bounded rather than coerced" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.journal", %{"id" => "s", "since_seq" => -1})

      assert message =~ "since_seq"

      assert {:error, -32_602, message} =
               Methods.invoke("interactive.journal", %{"id" => "s", "since_seq" => "3"})

      assert message =~ "since_seq"

      assert {:error, -32_602, message} =
               Methods.invoke("interactive.journal", %{"id" => "s", "limit" => 0})

      assert message =~ "limit"

      assert {:error, -32_602, message} =
               Methods.invoke("interactive.journal", %{"id" => "s", "limit" => 501})

      assert message =~ "limit"
    end

    test "a session id that names nothing is not found" do
      assert {:error, -32_007, message} =
               Methods.invoke("interactive.journal", %{"id" => "no-such-session"})

      assert message =~ "no such record"
    end
  end

  describe "a transport with no journal" do
    test "is refused as wire data naming the verb, not answered with an empty record",
         %{id: id} do
      start_session(id)

      assert {:error, -32_006, _message, ["unsupported_on_transport", details]} =
               Methods.invoke("interactive.journal", %{"id" => id})

      assert details["verb"] == "journal"
      retire_session(id)
    end
  end

  describe "a native session's record, on the wire" do
    test "hands back the turn it just ran, bounded by the chain state", context do
      id = context.id

      session =
        start_native(id, context, [
          [
            {:thinking, "considering"},
            {:text, "reading"},
            {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
          ],
          [{:text, "done"}, {:usage, %{input_tokens: 11, output_tokens: 4}}, {:finish, :stop}]
        ])

      assert {:ok, _turn} = InteractiveSession.send_message(session, "look at lib/a.ex")
      await_turn(session)

      assert {:ok, window} = Methods.invoke("interactive.journal", %{"id" => id})

      # The four fields that bound what the window means.
      assert byte_size(window.head) == 64
      assert window.verified_through == window.head_seq
      assert window.truncated_through == nil
      assert window.count == length(window.records)

      kinds = Enum.map(window.records, & &1["kind"])
      assert "session_opened" in kinds
      assert "turn_started" in kinds
      assert "prompt" in kinds
      assert "model_call" in kinds
      assert "model_result" in kinds
      assert "tool_result" in kinds
      assert "turn_settled" in kinds

      # Every record carries the framing a verifier needs, and the sequences are contiguous.
      assert Enum.all?(window.records, fn record ->
               is_integer(record["seq"]) and is_binary(record["at"]) and
                 byte_size(record["prev"]) == 64 and byte_size(record["hash"]) == 64
             end)

      assert Enum.map(window.records, & &1["seq"]) ==
               Enum.to_list(1..length(window.records))

      # The thinking the event stream emitted and nothing durable used to keep.
      result = Enum.find(window.records, &(&1["kind"] == "model_result"))
      assert ["thinking", "considering"] in result["chunks"]

      retire_session(id)
    end

    test "the cursor is exclusive and the limit bounds the window", context do
      id = context.id
      session = start_native(id, context, [[{:text, "hi"}, {:finish, :stop}]])

      assert {:ok, _turn} = InteractiveSession.send_message(session, "hello")
      await_turn(session)

      assert {:ok, all} = Methods.invoke("interactive.journal", %{"id" => id})
      assert all.count >= 6

      assert {:ok, window} =
               Methods.invoke("interactive.journal", %{
                 "id" => id,
                 "since_seq" => 2,
                 "limit" => 2
               })

      assert Enum.map(window.records, & &1["seq"]) == [3, 4]

      # The bounding fields describe the whole record, not the window: a caller that paged
      # into the middle still learns how far the chain is good for.
      assert window.count == all.count
      assert window.head == all.head
      assert window.verified_through == all.verified_through

      assert {:ok, past_end} =
               Methods.invoke("interactive.journal", %{"id" => id, "since_seq" => all.head_seq})

      assert past_end.records == []

      retire_session(id)
    end

    test "a session that has never run a turn still has a record of being opened", context do
      id = context.id
      _session = start_native(id, context, [[{:text, "hi"}, {:finish, :stop}]])

      assert {:ok, window} = Methods.invoke("interactive.journal", %{"id" => id})

      assert [%{"kind" => "session_opened"} = opened] = window.records
      assert opened["seq"] == 1
      assert opened["prev"] == String.duplicate("0", 64)
      assert opened["journal_version"] == 1
      assert opened["resumed"] == false
      assert window.verified_through == 1

      retire_session(id)
    end
  end

  # ------------------------------------------------------------------ helpers

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
      "ouroboros-gateway-journal-#{System.unique_integer([:positive, :monotonic])}"
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
