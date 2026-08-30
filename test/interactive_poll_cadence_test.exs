defmodule Ouroboros.InteractivePollCadenceTest do
  @moduledoc """
  The wakeup cadence of a live interactive coordinator.

  `Ouroboros.Poll.Cadence` is unit-tested as arithmetic in `poll_cadence_test.exs`. What
  this file adds is the wiring: that a coordinator which has actually gone idle actually
  decays, that a turn actually holds it at the fast interval, and that the verbs a human
  reaches for actually reset it.

  Nothing here asserts how long anything took. The cadence is read out of the coordinator's
  own state through `Ouroboros.Interactive.Task.poll_interval_ms/1`, which is a pure
  function of the policy struct, so every assertion is about a value rather than about a
  clock. The only waiting is `assert_eventually/1`, which waits for a condition under a
  generous ceiling.
  """

  use ExUnit.Case, async: false

  alias Jido.Harness.{RunRequest, Session, SessionInfo}
  alias Ouroboros.Interactive.{State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Poll.Cadence
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test
  @fast_ms 25
  @idle_cap_ms 1_000

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

    HarnessAdapter.reset_resume()

    on_exit(fn ->
      HarnessAdapter.reset_resume()
      cleanup_sessions()
      restore_env(:providers, previous_providers)
      restore_env(:provider_config, previous_provider_config)
      File.rm_rf(journal_dir)
    end)

    {:ok, id: unique_id("cadence")}
  end

  test "a conversation between turns backs off to the idle ceiling", %{id: id} do
    ref = start_session(id)
    pid = coordinator(id)

    # A session still starting is not idle: waiters are blocked on readiness, so the
    # interval must stay fast until the Harness session says it has reached `:idle`.
    assert_eventually(fn -> idle?(ref) end)

    assert_eventually(fn -> interval(pid) > @fast_ms end)
    assert_eventually(fn -> interval(pid) == @idle_cap_ms end)

    # And it stays there rather than oscillating: an idle session that keeps finding
    # nothing keeps the ceiling.
    assert_eventually(fn -> interval(pid) == @idle_cap_ms end)
    assert interval(pid) == @idle_cap_ms

    retire_session(id)
  end

  test "dispatching a turn resets the cadence and holds it fast for the whole turn", %{id: id} do
    ref = start_session(id)
    pid = coordinator(id)

    assert_eventually(fn -> idle?(ref) end)
    assert_eventually(fn -> interval(pid) == @idle_cap_ms end)

    assert {:ok, _turn} =
             InteractiveSession.send_message(ref, "hello", id: unique_id("turn"))

    # The reset is synchronous with the dispatch — `schedule_poll(runtime, 0)` is what
    # every provider-reaching verb already passed, and it is now also the reset.
    assert interval(pid) == @fast_ms

    # The turn is left running: the fixture adapter emits only when told to, so this is a
    # genuinely active turn rather than one that completed between assertions.
    assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 5_000
    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "working"})

    # The latency guarantee, stated as policy rather than measured as a duration: while a
    # turn is in flight the coordinator never decays, however many empty polls it takes.
    Enum.each(1..25, fn _check ->
      assert interval(pid) == @fast_ms
      Process.sleep(10)
    end)

    retire_session(id)
  end

  test "a subscriber attaching resets a decayed cadence", %{id: id} do
    ref = start_session(id)
    pid = coordinator(id)

    assert_eventually(fn -> idle?(ref) end)
    assert_eventually(fn -> interval(pid) == @idle_cap_ms end)

    assert {:ok, _backlog} = InteractiveSession.subscribe(ref, cursor: 0)

    assert interval(pid) == @fast_ms

    retire_session(id)
  end

  test "the coordinator holds exactly one poll timer however many verbs arrive", %{id: id} do
    ref = start_session(id)
    pid = coordinator(id)

    assert_eventually(fn -> idle?(ref) end)

    # Each of these used to arm its own timer, and each delivery scheduled its own
    # successor: the coordinator's real wakeup rate was the interval divided by the number
    # of chains it had accumulated. The runtime now holds one timer slot, and it holds one
    # timer.
    Enum.each(1..20, fn _call -> InteractiveSession.info(ref) end)
    Enum.each(1..20, fn _call -> InteractiveSession.subscribe(ref, cursor: 0) end)

    runtime = :sys.get_state(pid)

    assert match?(%{ref: timer} when is_reference(timer), runtime.poll_timer) or
             is_nil(runtime.poll_timer)

    retire_session(id)
  end

  test "the cadence bounds are the ones the module documents", %{id: id} do
    ref = start_session(id)
    pid = coordinator(id)

    assert_eventually(fn -> idle?(ref) end)

    cadence = :sys.get_state(pid).cadence

    assert %Cadence{fast_ms: @fast_ms, idle_cap_ms: @idle_cap_ms} = cadence

    retire_session(id)
  end

  defp interval(pid), do: pid |> :sys.get_state() |> Task.poll_interval_ms()

  defp coordinator(id) do
    assert_eventually(fn -> Task.whereis(id) end)
  end

  defp start_session(id, opts \\ []) do
    opts = Keyword.merge([id: id, provider: @provider, workspace: File.cwd!()], opts)
    assert {:ok, ref} = InteractiveSession.start(opts)
    ref
  end

  defp idle?(ref) do
    match?({:ok, %State{status: :idle}}, InteractiveSession.info(ref))
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

  # A generous ceiling on a condition, never an assertion about elapsed time. Reaching the
  # 1s cap from 25ms takes six empty polls and about 1.6s of real idleness, so the ceiling
  # here is several times the expected wait on purpose.
  defp assert_eventually(fun, attempts \\ 800)
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

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-interactive-cadence-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
