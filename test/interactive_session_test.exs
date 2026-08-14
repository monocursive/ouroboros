defmodule Ouroboros.InteractiveSessionTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{RunRequest, Session, SessionInfo, TurnRequest}
  alias Ouroboros.Interactive.{Event, Ref, State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  defmodule StorageFixture do
    @moduledoc false
    def get_checkpoint(_key, opts), do: Keyword.fetch!(opts, :response)
    def put_checkpoint(_key, _value, _opts), do: :ok
  end

  setup do
    cleanup_sessions()

    old_providers = Application.get_env(:jido_harness, :providers)
    old_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()

    providers = Map.put(Map.new(old_providers || %{}), @provider, HarnessAdapter)

    provider_config =
      old_config
      |> then(&Map.new(&1 || %{}))
      |> Map.put(@provider, %{test_pid: self(), retention: %{journal_dir: journal_dir}})

    Application.put_env(:jido_harness, :providers, providers)
    Application.put_env(:jido_harness, :provider_config, provider_config)

    on_exit(fn ->
      cleanup_sessions()
      restore_env(:providers, old_providers)
      restore_env(:provider_config, old_config)
      File.rm_rf(journal_dir)
    end)

    {:ok, id: unique_id("interactive")}
  end

  test "persists replay and sequential multi-turn results", %{id: id} do
    assert {:ok, %Ref{id: ^id} = ref} =
             InteractiveSession.start(
               id: id,
               provider: @provider,
               workspace: File.cwd!(),
               approval_mode: :prompt,
               sandbox_mode: :read_only
             )

    assert {:ok, backlog} = InteractiveSession.subscribe(ref, cursor: 0)
    assert Enum.map(backlog, & &1.type) == [:session_started, :session_ready, :session_idle]

    first_id = unique_id("turn-one")
    second_id = unique_id("turn-two")

    assert {:ok, %{id: ^first_id, status: :running}} =
             InteractiveSession.send_message(ref, "inspect", id: first_id)

    assert_receive {:ouroboros_test_adapter_started, _run_one, %RunRequest{prompt: "inspect"},
                    first_adapter},
                   1_000

    assert {:ok, %{id: ^second_id, status: :queued}} =
             InteractiveSession.follow_up(ref, "then explain", id: second_id)

    assert {:ok, same_first} = InteractiveSession.send_message(ref, "inspect", id: first_id)
    assert same_first.id == first_id

    assert {:error, {:turn_id_conflict, ^first_id}} =
             InteractiveSession.send_message(ref, "different", id: first_id)

    assert :ok = HarnessAdapter.emit(first_adapter, :output_text_final, %{"text" => "inspected"})
    assert :ok = HarnessAdapter.finish(first_adapter)

    assert_receive {:ouroboros_test_adapter_started, _run_two,
                    %RunRequest{prompt: "then explain"}, second_adapter},
                   1_000

    assert :ok = HarnessAdapter.emit(second_adapter, :output_text_final, %{"text" => "explained"})
    assert :ok = HarnessAdapter.finish(second_adapter)

    assert {:ok, %{status: :completed, result: %{text: "inspected"}}} =
             InteractiveSession.await(ref, first_id, 2_000)

    assert {:ok, %{status: :completed, result: %{text: "explained"}}} =
             InteractiveSession.await(ref, second_id, 2_000)

    assert {:ok, events} = InteractiveSession.replay(ref, cursor: 0, limit: 100)
    assert Enum.all?(events, &match?(%Event{}, &1))
    assert Enum.map(events, & &1.sequence) == Enum.to_list(1..length(events))
    assert Enum.count(events, &(&1.type == :turn_completed)) == 2

    assert Enum.any?(events, fn event ->
             event.type == :input_accepted and event.payload["text"] == "inspect"
           end)

    assert Enum.any?(events, fn event ->
             event.type == :input_accepted and event.payload["text"] == "then explain"
           end)

    cursor = events |> Enum.find(&(&1.type == :output_text_final)) |> Map.fetch!(:sequence)
    assert {:ok, after_cursor} = InteractiveSession.replay(ref, cursor: cursor)
    assert Enum.all?(after_cursor, &(&1.sequence > cursor))

    assert :ok = InteractiveSession.close(ref)

    assert_eventually(fn ->
      match?({:ok, %State{status: :closed}}, InteractiveSession.info(ref))
    end)
  end

  test "coordinator crash reattaches to the same Harness session and active turn", %{id: id} do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    turn_id = unique_id("recover-turn")

    assert {:ok, _turn} = InteractiveSession.send_message(ref, "survive", id: turn_id)

    assert_receive {:ouroboros_test_adapter_started, _run_id, %RunRequest{prompt: "survive"},
                    adapter},
                   1_000

    assert {:ok, %State{harness_session_id: harness_session_id}} = InteractiveSession.info(ref)
    coordinator = Task.whereis(id)
    monitor = Process.monitor(coordinator)
    Process.exit(coordinator, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^coordinator, :killed}, 1_000

    replacement =
      assert_eventually(fn ->
        case Task.whereis(id) do
          pid when is_pid(pid) and pid != coordinator -> pid
          _other -> false
        end
      end)

    assert is_pid(replacement)

    assert {:ok, %State{harness_session_id: ^harness_session_id}} = InteractiveSession.info(ref)
    refute_receive {:ouroboros_test_adapter_started, _duplicate, _request, _adapter}, 100

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "survived"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %{status: :completed, result: %{text: "survived"}}} =
             InteractiveSession.await(ref, turn_id, 2_000)

    assert :ok = InteractiveSession.close(ref)
  end

  test "periodic recovery rebuilds an active session missing from the task supervisor", %{id: id} do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    original = Task.whereis(id)
    assert is_pid(original)

    assert :ok =
             DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, original)

    # Recovery only adopts sessions whose last transition is older than its restart
    # grace, so rebuilding deliberately lags the terminate by a couple of seconds.
    replacement =
      assert_eventually(
        fn ->
          case Task.whereis(id) do
            pid when is_pid(pid) and pid != original -> pid
            _other -> false
          end
        end,
        800
      )

    assert is_pid(replacement)
    assert {:ok, %State{status: status}} = InteractiveSession.info(ref)
    assert status in [:ready, :idle]
    assert :ok = InteractiveSession.close(ref)
  end

  test "malformed public and routed requests return errors without crashing the coordinator", %{
    id: id
  } do
    assert {:error, :invalid_options} = InteractiveSession.start([:not_a_keyword])
    assert {:error, :invalid_options} = InteractiveSession.start(id: id, id: id)
    assert {:error, :invalid_owner} = InteractiveSession.start_on(nil, [])
    assert {:error, :invalid_session} = InteractiveSession.info(:not_a_session)

    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    coordinator = Task.whereis(id)
    assert {:error, :invalid_options} = InteractiveSession.subscribe(ref, %{})
    assert {:error, :duplicate_options} = InteractiveSession.replay(ref, cursor: 0, cursor: 1)
    assert {:error, :invalid_options} = InteractiveSession.send_message(ref, "x", %{})
    assert {:error, :invalid_turn_id} = InteractiveSession.await(ref, 123, 0)
    assert {:error, :invalid_turn_id} = InteractiveSession.interrupt(ref, 123)
    assert {:error, :invalid_request_id} = InteractiveSession.respond_approval(ref, "", :allow)

    assert {:error, :invalid_subscriber} =
             InteractiveSession.local_call(id, {:subscribe, :no_pid, 0})

    assert {:error, :invalid_session_operation} = InteractiveSession.local_call(id, :unknown)
    assert Process.alive?(coordinator)
    assert :ok = InteractiveSession.close(ref)
  end

  test "public snapshots hide turn requests and secret-bearing turn options are rejected", %{
    id: id
  } do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    secret_turn = unique_id("secret-turn")

    assert {:error, :secret_bearing_turn_options} =
             InteractiveSession.send_message(ref, "do not dispatch",
               id: secret_turn,
               metadata: %{api_token: "TURN-SECRET"}
             )

    refute_receive {:ouroboros_test_adapter_started, _run, _request, _adapter}, 100

    turn_id = unique_id("private-turn")

    assert {:ok, _turn} =
             InteractiveSession.send_message(ref, "visible prompt",
               id: turn_id,
               metadata: %{private_note: "PRIVATE-METADATA"}
             )

    assert_receive {:ouroboros_test_adapter_started, _run, _request, adapter}, 1_000
    assert {:ok, public} = InteractiveSession.info(ref)
    assert public.turns[turn_id].prompt == "visible prompt"
    refute Map.has_key?(public.turns[turn_id], :request)
    refute Map.has_key?(public.turns[turn_id], :fingerprint)
    refute inspect(public) =~ "PRIVATE-METADATA"

    assert :ok = HarnessAdapter.emit(adapter, :provider_event, %{"api_token" => "EVENT-SECRET"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %{status: :completed, result: %{}}} =
             InteractiveSession.await(ref, turn_id, 2_000)

    assert {:ok, events} = InteractiveSession.replay(ref, cursor: 0)
    secret_event = Enum.find(events, &(&1.type == :provider_event))
    assert secret_event.payload["api_token"] == "[REDACTED]"
    refute inspect(events) =~ "EVENT-SECRET"
    assert :ok = InteractiveSession.close(ref)
  end

  test "await timeout never interrupts provider work", %{id: id} do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    turn_id = unique_id("timeout-turn")
    assert {:ok, _turn} = InteractiveSession.send_message(ref, "keep running", id: turn_id)

    assert_receive {:ouroboros_test_adapter_started, _run, _request, adapter}, 1_000
    assert {:error, :timeout} = InteractiveSession.await(ref, turn_id, 10)
    refute_receive {:ouroboros_test_adapter_cancelled, _run_id}, 100
    assert Process.alive?(adapter)

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "done"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %{status: :completed, result: %{text: "done"}}} =
             InteractiveSession.await(ref, turn_id, 2_000)

    assert :ok = InteractiveSession.close(ref)
  end

  test "graceful close and force kill checkpoint authoritative terminal turns", %{id: id} do
    assert {:ok, close_ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    close_turn = unique_id("close-turn")
    assert {:ok, _turn} = InteractiveSession.send_message(close_ref, "close me", id: close_turn)
    assert_receive {:ouroboros_test_adapter_started, close_run, _request, _adapter}, 1_000
    assert :ok = InteractiveSession.close(close_ref)
    assert_receive {:ouroboros_test_adapter_cancelled, ^close_run}, 1_000

    assert {:ok, %{status: :interrupted, result: %{status: :interrupted}}} =
             InteractiveSession.await(close_ref, close_turn, 2_000)

    assert_eventually(fn ->
      match?({:ok, %State{status: :closed}}, InteractiveSession.info(close_ref))
    end)

    assert :ok = InteractiveSession.close(close_ref)

    kill_id = unique_id("kill-session")

    assert {:ok, kill_ref} =
             InteractiveSession.start(id: kill_id, provider: @provider, workspace: File.cwd!())

    kill_turn = unique_id("kill-turn")
    assert {:ok, _turn} = InteractiveSession.send_message(kill_ref, "kill me", id: kill_turn)
    assert_receive {:ouroboros_test_adapter_started, kill_run, _request, _adapter}, 1_000
    assert :ok = InteractiveSession.kill(kill_ref)
    assert_receive {:ouroboros_test_adapter_cancelled, ^kill_run}, 1_000

    assert {:ok, %{status: :interrupted, result: %{status: :interrupted}}} =
             InteractiveSession.await(kill_ref, kill_turn, 2_000)

    assert_eventually(fn ->
      match?({:ok, %State{status: :cancelled}}, InteractiveSession.info(kill_ref))
    end)

    assert :ok = InteractiveSession.kill(kill_ref)
  end

  test "a checkpointed but unsent intent is recovered once and stable-id retry does not duplicate",
       %{
         id: id
       } do
    assert {:ok, harness_id} =
             Session.start(@provider, %{
               cwd: File.cwd!(),
               metadata: %{ouroboros_session_id: id, ouroboros_node: Atom.to_string(node())}
             })

    assert_eventually(fn ->
      match?({:ok, %SessionInfo{state: :idle}}, Session.info(harness_id))
    end)

    assert {:ok, session} = State.new(id, provider: @provider, workspace: File.cwd!())
    turn_id = unique_id("checkpointed-turn")
    assert {:ok, request} = TurnRequest.new("resume intent")
    turn = State.new_turn(turn_id, :message, request)

    assert :ok =
             Store.create(%{
               session
               | status: :idle,
                 harness_session_id: harness_id,
                 turns: %{turn_id => turn}
             })

    ref = Ref.new(id)

    assert {:ok, %{id: ^turn_id, status: :dispatching}} =
             InteractiveSession.send_message(ref, "resume intent", id: turn_id)

    assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{prompt: "resume intent"},
                    adapter},
                   1_000

    assert {:ok, same} = InteractiveSession.send_message(ref, "resume intent", id: turn_id)
    assert same.id == turn_id
    refute_receive {:ouroboros_test_adapter_started, _duplicate, _request, _adapter}, 100
    assert :ok = HarnessAdapter.finish(adapter)
    assert {:ok, %{status: :completed}} = InteractiveSession.await(ref, turn_id, 2_000)
    assert :ok = InteractiveSession.close(ref)
  end

  test "loss of the Harness process fails closed without redispatching an active turn", %{id: id} do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    turn_id = unique_id("lost-turn")
    assert {:ok, _turn} = InteractiveSession.send_message(ref, "do not duplicate", id: turn_id)
    assert_receive {:ouroboros_test_adapter_started, _run, _request, adapter}, 1_000
    assert {:ok, %State{harness_session_id: harness_id}} = InteractiveSession.info(ref)
    waiter = Elixir.Task.async(fn -> InteractiveSession.await(ref, turn_id, 2_000) end)
    [{harness_pid, _value}] = Registry.lookup(Jido.Harness.SessionRegistry, harness_id)
    Process.exit(harness_pid, :kill)

    assert_eventually(fn ->
      match?({:ok, %State{status: :lost}}, InteractiveSession.info(ref))
    end)

    assert {:ok, %{status: :ambiguous, error: {:session_lost, :harness_session_not_found}}} =
             Elixir.Task.await(waiter, 2_500)

    refute_receive {:ouroboros_test_adapter_started, _duplicate, _request, _adapter}, 100
    if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
  end

  test "subscription is atomic across backlog and live delivery", %{id: id} do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    turn_id = unique_id("subscription-turn")
    assert {:ok, _turn} = InteractiveSession.send_message(ref, "race", id: turn_id)
    assert_receive {:ouroboros_test_adapter_started, _run, _request, adapter}, 1_000
    assert {:ok, %State{cursor: cursor}} = InteractiveSession.info(ref)
    parent = self()

    subscriber =
      spawn(fn ->
        result = InteractiveSession.subscribe(ref, cursor: cursor)
        send(parent, {:subscription_backlog, self(), result})
        send(parent, {:subscription_live, self(), receive_marker_event(id, 500)})
      end)

    assert :ok = HarnessAdapter.emit(adapter, :provider_event, %{"marker" => "race-event"})
    assert_receive {:subscription_backlog, ^subscriber, {:ok, backlog}}, 1_000

    live =
      receive do
        {:subscription_live, ^subscriber, event} -> event
      after
        1_000 -> flunk("subscriber did not finish")
      end

    projected =
      Enum.filter(backlog, &(&1.payload["marker"] == "race-event")) ++
        if(live == :none, do: [], else: [live])

    assert length(projected) == 1
    assert hd(projected).payload["marker"] == "race-event"
    assert :ok = HarnessAdapter.finish(adapter)
    assert {:ok, %{status: :completed}} = InteractiveSession.await(ref, turn_id, 2_000)
    assert :ok = InteractiveSession.close(ref)
  end

  test "store rejects nested runtime capabilities in checkpoints", %{id: id} do
    assert {:ok, session} = State.new(id, provider: @provider, workspace: File.cwd!())
    corrupt = %{session | error: %{runtime_pid: self()}}

    assert {:stop, :invalid_interactive_checkpoint} =
             Store.init(storage: {StorageFixture, response: {:ok, %{id => corrupt}}})
  end

  test "routes an interactive session through a real OS peer", %{id: id} do
    ensure_distributed!()
    peer_name = String.to_atom("ouroboros_interactive_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    assert {:ok, peer, peer_node} =
             :peer.start(%{name: peer_name, args: args, wait_boot: 15_000})

    journal_dir = unique_journal_dir()
    on_exit(fn -> :peer.stop(peer) end)
    on_exit(fn -> File.rm_rf(journal_dir) end)

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :coding_storage,
        {Jido.Storage.ETS, table: String.to_atom("#{peer_name}_coding")}
      ])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :interactive_storage,
        {Jido.Storage.ETS, table: String.to_atom("#{peer_name}_interactive")}
      ])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :jido_harness,
        :providers,
        %{@provider => HarnessAdapter}
      ])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :jido_harness,
        :provider_config,
        %{@provider => %{test_pid: self(), retention: %{journal_dir: journal_dir}}}
      ])

    assert {:ok, _apps} = :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])

    assert {:ok, %Ref{id: ^id, node: ^peer_node} = ref} =
             InteractiveSession.start_on(peer_node,
               id: id,
               provider: @provider,
               workspace: File.cwd!()
             )

    turn_id = unique_id("remote-turn")
    assert {:ok, _turn} = InteractiveSession.send_message(ref, "remote", id: turn_id)

    assert_receive {:ouroboros_test_adapter_started, _run_id, %RunRequest{prompt: "remote"},
                    adapter},
                   2_000

    assert node(adapter) == peer_node
    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "peer"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %{status: :completed, result: %{text: "peer"}}} =
             InteractiveSession.await(ref, turn_id, 3_000)

    assert :ok = InteractiveSession.close(ref)
  end

  defp cleanup_sessions do
    Session.list()
    |> Enum.each(fn info ->
      unless SessionInfo.terminal?(info), do: Session.kill(info.session_id)
      _ = Session.prune(info.session_id)
    end)
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_interactive_root_#{System.unique_integer([:positive])}")
      assert {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
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

  defp receive_marker_event(id, timeout) do
    started = System.monotonic_time(:millisecond)
    do_receive_marker_event(id, timeout, started)
  end

  defp do_receive_marker_event(id, timeout, started) do
    remaining = max(timeout - (System.monotonic_time(:millisecond) - started), 0)

    receive do
      {:ouroboros_interactive_event, ^id, event} ->
        if event.payload["marker"] == "race-event",
          do: event,
          else: do_receive_marker_event(id, timeout, started)
    after
      remaining -> :none
    end
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-interactive-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
