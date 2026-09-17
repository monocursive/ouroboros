defmodule Ouroboros.Gateway.ActivitySourcesTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  # Every source of `runtime.activity`, driven to the states a real node reaches and a
  # real node's tests do not: a session that answers slowly, a session that does not
  # answer at all, a fleet of healthy sessions large enough to outlast the walk's budget,
  # a registry that cannot be read, and named processes that answer late or answer
  # nonsense. The stand-ins are plain processes registered and named the way the real ones
  # are, so this measures the walk rather than session startup.
  #
  # Two of these cases are adopted from the adversarial review of a97f2dfb
  # (exploit_cost.exs): 30 healthy sessions taking 25ms each used to sum past the 500ms
  # budget and make a perfectly ordinary node permanently `activity_unknown`, and one
  # read-scope verb used to put an unbounded number of questions into every session's
  # mailbox. Both assertions are inverted here to the behaviour the fix owes them.

  alias Ouroboros.Gateway.Activity
  alias Ouroboros.Gateway.Methods

  defmodule FakeSession do
    @moduledoc false
    use GenServer

    def start_link(opts), do: GenServer.start_link(__MODULE__, opts)
    def asked(pid), do: GenServer.call(pid, :asked, 10_000)

    @impl true
    def init(opts) do
      {:ok, _} =
        Registry.register(
          Keyword.fetch!(opts, :registry),
          {:runtime, "w1b-fake-#{System.unique_integer([:positive])}"},
          %{}
        )

      {:ok, %{delay: Keyword.get(opts, :delay_ms, 0), reply: Keyword.get(opts, :reply), asked: 0}}
    end

    @impl true
    def handle_call(:runtime_info, _from, state) do
      if state.delay > 0, do: Process.sleep(state.delay)

      reply =
        state.reply ||
          {:ok, %{active_turn_id: nil, queued_turns: 0, busy?: false}}

      {:reply, reply, %{state | asked: state.asked + 1}}
    end

    def handle_call(:asked, _from, state), do: {:reply, state.asked, state}
  end

  # One process standing in for a `DynamicSupervisor` or for `Ouroboros.Attachments`: it
  # answers their message, and it answers it the way a broken or overloaded one would.
  defmodule FakeNamed do
    @moduledoc false
    use GenServer

    def start_link(opts),
      do: GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))

    @impl true
    def init(opts), do: {:ok, %{delay: Keyword.get(opts, :delay_ms, 0), reply: opts[:reply]}}

    @impl true
    def handle_call(_message, _from, state) do
      if state.delay > 0, do: Process.sleep(state.delay)
      {:reply, state.reply, state}
    end
  end

  setup do
    start_supervised!({DynamicSupervisor, strategy: :one_for_one, name: :w1b_sources_conns})
    registry = :"w1b_sources_registry_#{System.unique_integer([:positive])}"
    start_supervised!({Registry, keys: :unique, name: registry})
    %{registry: registry}
  end

  defp sessions(registry, count, opts) do
    Enum.map(1..count, fn _ ->
      start_supervised!({FakeSession, [{:registry, registry} | opts]},
        id: System.unique_integer([:positive])
      )
    end)
  end

  defp summary(registry, extra \\ []) do
    Methods.activity(
      Keyword.merge([session_registry: registry, conn_supervisor: :w1b_sources_conns], extra)
    )
  end

  # ---------------------------------------------------------------------------

  describe "the session walk" do
    test "a fleet of healthy but slow sessions is answered, and answered quickly", %{
      registry: registry
    } do
      # ADOPTED EXPLOIT: 30 sessions that each take 25ms — an ordinary state for a session
      # with a turn's work in front of the question. Serially that is 750ms against a
      # 500ms budget, and the node could never say whether it was idle.
      sessions(registry, 30, delay_ms: 25)

      {microseconds, summary} = :timer.tc(fn -> summary(registry) end)

      assert summary["unknown"] == []
      assert summary["silent_sessions"] == 0
      assert summary["running_turns"] == 0
      assert summary["idle"] == true

      # The cost is the slowest session and not the sum of all of them.
      assert div(microseconds, 1000) < 250,
             "the walk took #{div(microseconds, 1000)}ms; it is supposed to be concurrent"
    end

    test "one session that does not answer is named, and poisons no total", %{
      registry: registry
    } do
      sessions(registry, 3, delay_ms: 0)
      sessions(registry, 1, delay_ms: 5_000)

      {microseconds, summary} = :timer.tc(fn -> summary(registry) end)

      assert summary["silent_sessions"] == 1

      # Three sessions answered "nothing in flight" and one said nothing at all. Adding
      # the three up and reporting the total would be a number that reads as a quiet node.
      assert summary["running_turns"] == nil
      assert summary["queued_turns"] == nil
      assert summary["busy_sessions"] == nil
      assert summary["idle"] == nil

      for field <- ~w(running_turns queued_turns busy_sessions),
          do: assert(field in summary["unknown"])

      # And it costs one session's deadline, not the whole budget.
      assert div(microseconds, 1000) < 400
    end

    test "a walk that runs out of budget is unknown, never a partial total", %{
      registry: registry
    } do
      # Each of these answers well inside its own deadline; there are simply more of them
      # than the budget allows the walk to finish. Truncating here would report the work
      # of the sessions that were reached as the work of the node.
      sessions(registry, 200, delay_ms: 180)

      summary = summary(registry)

      assert summary["running_turns"] == nil
      assert summary["queued_turns"] == nil
      assert summary["busy_sessions"] == nil
      assert summary["idle"] == nil
      assert "running_turns" in summary["unknown"]
    end

    test "a registry this build cannot read is unknown, not an empty fleet" do
      summary = summary(:w1b_registry_that_never_started)

      assert summary["running_turns"] == nil
      assert summary["queued_turns"] == nil
      assert summary["busy_sessions"] == nil
      assert summary["silent_sessions"] == nil
      assert summary["idle"] == nil

      # The sources that could be read still were.
      assert summary["operator_clients"] == 0
      assert summary["in_flight_methods"] == 0
    end

    test "a session whose answer this build does not understand is silent, not empty", %{
      registry: registry
    } do
      # No `busy?`: a shape from something that is not this build's session. Reading the
      # two fields it does have and calling the rest zero is exactly the assumption that
      # hid a compaction.
      sessions(registry, 1, reply: {:ok, %{active_turn_id: nil, queued_turns: 0}})

      summary = summary(registry)

      assert summary["silent_sessions"] == 1
      assert summary["running_turns"] == nil
      assert summary["idle"] == nil
    end
  end

  # ---------------------------------------------------------------------------

  describe "the named processes" do
    test "a connection supervisor that answers late is unknown, not zero", %{registry: registry} do
      start_supervised!({FakeNamed, name: :w1b_slow_conns, delay_ms: 5_000, reply: []})

      summary = summary(registry, conn_supervisor: :w1b_slow_conns)

      assert summary["operator_clients"] == nil
      assert summary["unknown"] == ["operator_clients"]
      assert summary["idle"] == nil
    end

    test "a count this build cannot read is unknown, not zero", %{registry: registry} do
      for {name, reply} <- [
            {:w1b_garbage_conns, :nope},
            {:w1b_noninteger_conns, [specs: 1, active: :lots, supervisors: 0, workers: 1]},
            {:w1b_negative_conns, [specs: 1, active: -1, supervisors: 0, workers: 1]}
          ] do
        start_supervised!({FakeNamed, name: name, reply: reply}, id: name)

        summary = summary(registry, conn_supervisor: name)

        assert summary["operator_clients"] == nil, "#{name} must not be counted"
        assert summary["idle"] == nil
      end
    end

    test "an attachment service that answers late or answers nonsense is unknown", %{
      registry: registry
    } do
      start_supervised!({FakeNamed, name: :w1b_slow_attachments, delay_ms: 5_000, reply: %{}},
        id: :slow
      )

      start_supervised!(
        {FakeNamed, name: :w1b_odd_attachments, reply: %{transfers: "1", normalizations: nil}},
        id: :odd
      )

      for name <- [:w1b_slow_attachments, :w1b_odd_attachments] do
        summary = summary(registry, attachments: name)

        assert summary["attachment_transfers"] == nil, "#{name} must not be counted"
        assert summary["attachment_normalizations"] == nil
        assert summary["idle"] == nil
      end
    end
  end

  # ---------------------------------------------------------------------------

  describe "what one read-scope verb costs" do
    test "a loop of readers cannot loop the fan-out, because the verb is cached" do
      # ADOPTED EXPLOIT: the review drove 3,380 `:runtime_info` questions into ONE session
      # in a second from eight read-scope loopers. These fakes live in the node's own
      # registry, because the verb reads the node's own sources.
      victims =
        Enum.map(1..20, fn _ ->
          start_supervised!({FakeSession, registry: Ouroboros.SessionRegistry},
            id: System.unique_integer([:positive])
          )
        end)

      victim = hd(victims)
      parent = self()

      hammers =
        Enum.map(1..8, fn _ ->
          spawn(fn ->
            deadline = System.monotonic_time(:millisecond) + 1_000

            loop = fn loop ->
              if System.monotonic_time(:millisecond) < deadline do
                Methods.invoke("runtime.activity", %{})
                loop.(loop)
              end
            end

            loop.(loop)
            send(parent, :hammer_done)
          end)
        end)

      Enum.each(hammers, fn _ -> assert_receive :hammer_done, 20_000 end)

      asked = FakeSession.asked(victim)

      # One walk per cache window, however many readers there are. Four windows fit in a
      # second; the slack is for the walks already in flight when the loops started.
      assert asked <= 12,
             "eight loopers put #{asked} questions into one session in a second"
    end

    test "with no process to ask, every counter is unknown and nothing is idle" do
      :ok = Supervisor.terminate_child(Ouroboros.Surface.Supervisor, Activity)

      on_exit(fn ->
        {:ok, _} = Supervisor.restart_child(Ouroboros.Surface.Supervisor, Activity)
      end)

      summary = Methods.activity(conn_supervisor: :w1b_sources_conns)

      assert summary["idle"] == nil
      assert summary["running_turns"] == nil
      assert summary["in_flight_methods"] == nil
      assert summary["operator_clients"] == nil
      assert Enum.sort(summary["unknown"]) == Enum.sort(Activity.limits().counters)

      # The ledger goes with it, and says so rather than answering zero.
      assert Activity.in_flight() == nil
      assert Activity.enter("workspace.exec") == nil
      assert Activity.leave(nil) == :ok
    end

    test "a fresh read is still a fresh read, which is what the gate asks for" do
      first = Methods.activity(conn_supervisor: :w1b_sources_conns)
      token = Activity.enter("workspace.exec")
      on_exit(fn -> Activity.leave(token) end)

      assert first["idle"] == true

      # `max_age_ms: 0` means a walk, not "a summary from this millisecond". The gate
      # depends on that: it is the only caller that never accepts a cached answer.
      assert Methods.activity(conn_supervisor: :w1b_sources_conns)["idle"] == false

      # And the cached reader can lag by design, which is stated rather than hidden.
      assert Methods.activity(conn_supervisor: :w1b_sources_conns, max_age_ms: 60_000)["idle"] ==
               false
    end
  end
end
