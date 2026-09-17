defmodule Ouroboros.Gateway.Activity do
  @moduledoc """
  What work this node is holding, counted once for everybody who asks.

  This is the summary `runtime.activity` answers with and the one
  `Ouroboros.Gateway.Conn` consults for `runtime.shutdown`'s `require_idle`, so the
  method a client can read and the gate that refuses it cannot disagree.

  ## What is counted, exactly

  Four sources, each asked once and each under its own deadline:

    * **the live native session processes** registered in `Ouroboros.SessionRegistry`.
      Each answers `running_turns` (it holds an active turn), `queued_turns` (turns it
      has accepted and not started) and `busy?` — and `busy?` is the session's *own*
      idle predicate, the one `fence_idle/1` refuses a maintenance fence with. That is
      deliberate: a compaction in flight, an unresolved approval or a live loop is work
      a stop would lose, and before `busy?` existed none of it was visible here. The
      two predicates are computed from one function in
      `Ouroboros.Provider.Native.Session` so they cannot drift.
    * **in-flight operate-scope method calls**, from the ledger below. `workspace.exec`
      runs the shell in the *caller's* process — a gateway dispatch task or a LiveView's
      `Ouroboros.Web.Call` — and never in a session, so no session can see it. Read
      calls are not counted: a read that is interrupted can be read again.
    * **`Ouroboros.Attachments`**, for the uploads and decoder tasks it is holding.
    * **the gateway's own connection supervisor**, for the clients attached to it.

  Everything else this node does is *not* counted, and the honest list of what that
  leaves out is: work on another machine (this is node-local — no fan-out, no `:erpc`),
  a read-scope call in flight, and anything a plane runs without telling a session or
  taking an operate verb to start. A session that merely exists, a durable row, and a
  bound port are not activity and never were.

  ## Unknown is not zero

  A counter this build cannot establish is `nil` and named in `unknown`, and `idle` is
  `nil` whenever any of them is. Unknown activity does not authorize a stop. The one
  place absence is read as zero rather than unknown is an *absent* `Ouroboros.Attachments`
  or in-flight ledger: every transfer's staged chunks live in that process's state, every
  normalizer task is its child, and every ledger entry names a live local pid — so a
  table or a service that is not there is one that is holding nothing. A service that is
  *there* and does not answer is unknown, which is a different fact.

  `idle` is decided by the work counters alone. A connected client is somebody watching
  rather than work in flight — the caller is always one of them, and the restart this
  gate exists for expects attached clients to be interrupted and to reconnect. Its count
  is still reported, and an `operator_clients` this build could not establish still makes
  `idle` unknown, because a summary with a hole in it is not evidence that a node is
  quiet.

  ## The bound, and why this is a process

  The session walk is concurrent: `@session_timeout_ms` bounds one question to one
  session and `@turn_budget_ms` bounds the whole walk, so the cost is the slowest
  session rather than the sum of all of them. A session that does not answer inside its
  own deadline is counted in `silent_sessions` and makes every session-derived counter
  unknown — it is never quietly left out of a total.

  Everything is computed *here*, in one process, and cached for `@cache_ms`. Both halves
  matter. `runtime.activity` is a read-scope verb whose one call fans out into every
  session's mailbox, so without a cache a read-only client could put that fan-out into a
  loop; with it, a loop of any width costs one walk per cache window. And the walk being
  serialized here means the concurrent tasks it spawns are never spawned in
  `Ouroboros.Gateway.Conn`, which traps exits and owns a socket.

  The gate asks for a fresh summary (`max_age_ms: 0`) and the read verb accepts a cached
  one. A stop must not be authorized by a quarter-second-old picture of the node; a
  reader can live with one. That leaves the gate as the one uncached path, which is why
  it is behind operate scope *and* `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1`, and why every
  refusal it makes is logged.

  ## The in-flight ledger

  `enter/1` and `leave/1` wrap every operate-scope invocation in
  `Ouroboros.Gateway.Methods.invoke/2`, which is the one funnel both the gateway's
  dispatch tasks and `Ouroboros.Web.Call` go through. They are two writes to a public
  ETS table and touch no process, because they sit in front of every mutation this node
  performs.

  Cleanup is by liveness rather than by an `after` block, and that is the whole design:
  the gateway *kills* a dispatch task that outlives its ceiling
  (`Task.Supervisor.terminate_child/2` on a process that does not trap exits), so an
  `after` block is exactly what would not run. Entries name a local pid and are swept
  when they are read. A counter incremented and decremented instead would leak upward on
  every killed task until the node was permanently, wrongly busy.
  """

  use GenServer

  alias Ouroboros.Provider.Native.Session, as: NativeSession

  @table :ouroboros_gateway_in_flight

  # One question to one session, and one question to one named process. A session that
  # has a turn's work in front of this question in its mailbox is normal; one that cannot
  # answer in a fifth of a second is reported silent rather than waited for.
  @session_timeout_ms 200
  @call_timeout_ms 250

  # The whole walk, however many sessions there are. Past it the walk stops and every
  # session-derived counter is unknown — never a partial total, which would read as a
  # quiet node.
  @turn_budget_ms 500

  # How wide the walk goes at once. The cost of a walk is therefore
  # `ceil(sessions / 64) * @session_timeout_ms`, capped by the budget above.
  @max_concurrency 64

  # How stale a summary a *reader* may be given. Small enough that a client polling for
  # an idle node sees one within a frame, large enough that a loop cannot turn one
  # read-scope verb into unbounded fan-out.
  @cache_ms 250

  # What one caller waits for this process: the budget, the two named-process deadlines,
  # and room for one walk already in progress ahead of it. A caller that waits longer
  # than this is told the node is unknown, which refuses a stop.
  @call_budget_ms @turn_budget_ms * 2 + @call_timeout_ms * 2 + 500

  # The two verbs that must never count as work. `runtime.activity` would otherwise count
  # itself, and a second reader would make the node look busy to the first;
  # `runtime.shutdown` is the stop being asked for.
  @unledgered ["runtime.activity", "runtime.shutdown"]

  # The processes a caller may name in place of this node's own.
  @sources [:session_registry, :attachments, :conn_supervisor]

  @counters [
    "running_turns",
    "queued_turns",
    "busy_sessions",
    "in_flight_methods",
    "attachment_transfers",
    "attachment_normalizations",
    "operator_clients"
  ]

  # Every counter but the clients: what decides `idle`.
  @work_counters @counters -- ["operator_clients"]

  @doc "Starts the process that owns the in-flight ledger and the summary cache."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @doc "The verbs the ledger never records, and therefore the ones that can ask about it."
  @spec unledgered() :: [String.t()]
  def unledgered, do: @unledgered

  @doc "Immutable public bounds, so a doc or a test states this module's numbers rather than its own."
  @spec limits() :: map()
  def limits do
    %{
      session_timeout_ms: @session_timeout_ms,
      call_timeout_ms: @call_timeout_ms,
      turn_budget_ms: @turn_budget_ms,
      max_concurrency: @max_concurrency,
      cache_ms: @cache_ms,
      counters: @counters,
      work_counters: @work_counters
    }
  end

  # ---------------------------------------------------------------------------
  # The ledger

  @doc """
  Records that this process has begun an operate-scope call, or `nil` if it cannot.

  Never raises and never refuses the call it is wrapping: a ledger that is missing is a
  counter that reads unknown, not a mutation that does not happen.
  """
  @spec enter(String.t()) :: reference() | nil
  def enter(method) when is_binary(method) do
    token = make_ref()
    :ets.insert(@table, {{self(), token}, method})
    token
  rescue
    ArgumentError -> nil
  end

  @doc "Records that the call `enter/1` opened has finished."
  @spec leave(reference() | nil) :: :ok
  def leave(nil), do: :ok

  def leave(token) when is_reference(token) do
    :ets.delete(@table, {self(), token})
    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc """
  How many operate-scope calls this node is running, or `nil` when there is no ledger.

  Sweeps as it reads: an entry whose process is gone is a call that ended when the
  gateway killed it for outliving its ceiling, and it is deleted here rather than
  counted.
  """
  @spec in_flight() :: non_neg_integer() | nil
  def in_flight do
    @table
    |> :ets.tab2list()
    |> Enum.reduce(0, fn {{pid, _token} = key, _method}, count ->
      if Process.alive?(pid) do
        count + 1
      else
        :ets.delete(@table, key)
        count
      end
    end)
  rescue
    ArgumentError -> nil
  end

  # ---------------------------------------------------------------------------
  # The summary

  @doc """
  The activity summary, computed in this process and cached for `@cache_ms`.

  `:max_age_ms` is how stale an answer the caller will accept; `0` forces a walk. The
  other options name the sources, and exist so a test can point this at its own
  registry, attachment service or connection supervisor rather than at the node's.
  """
  @spec summary(keyword()) :: map()
  def summary(opts \\ []) do
    {max_age, sources} = Keyword.pop(opts, :max_age_ms, 0)

    GenServer.call(__MODULE__, {:summary, sources, max_age}, @call_budget_ms)
  catch
    # No process, or one that did not answer inside a bound that already contains two
    # whole walks. Either way this build cannot say what the node is doing.
    :exit, _reason -> unknown_summary()
  end

  @doc false
  @spec unknown_summary() :: map()
  def unknown_summary do
    @counters
    |> Map.new(&{&1, nil})
    |> Map.merge(%{"silent_sessions" => nil, "idle" => nil, "unknown" => @counters})
  end

  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Public, because `enter/1` and `leave/1` run in the process making the call rather
    # than in this one. This process owns the table only so that it has an owner.
    table =
      :ets.new(@table, [
        :set,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])

    {:ok, %{table: table, cached: %{}}}
  end

  @impl true
  def handle_call({:summary, sources, max_age}, _from, state) do
    now = System.monotonic_time(:millisecond)

    # The key is the sources and nothing else, taken in a fixed order so that two callers
    # naming the same three processes share one walk however they spelled the list.
    key = sources |> Keyword.take(@sources) |> Enum.sort()

    case Map.get(state.cached, key) do
      # `max_age_ms: 0` is not "a summary from this millisecond", it is a walk. The gate
      # asks for one, and a gate that could be answered from a cache because two frames
      # landed in the same millisecond would be a gate with a race in it.
      {at, summary} when max_age > 0 and now - at <= max_age ->
        {:reply, summary, state}

      _stale_or_absent ->
        summary = compute(sources)
        # One entry per distinct source set. Production has exactly one; a suite that
        # points this at its own fakes gets its own, and both are evicted by age.
        cached =
          state.cached
          |> Enum.reject(fn {_key, {at, _summary}} -> now - at > 60_000 end)
          |> Map.new()
          |> Map.put(key, {now, summary})

        {:reply, summary, %{state | cached: cached}}
    end
  end

  @impl true
  def handle_info(_message, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------

  defp compute(sources) do
    registry = Keyword.get(sources, :session_registry, Ouroboros.SessionRegistry)
    attachments = Keyword.get(sources, :attachments, Ouroboros.Attachments)
    conn_supervisor = Keyword.get(sources, :conn_supervisor, Ouroboros.Gateway.ConnSupervisor)

    {running, queued, busy, silent} = turn_activity(registry)
    {transfers, normalizations} = attachment_activity(attachments)
    methods = in_flight()
    clients = operator_clients(conn_supervisor)

    counters = [
      {"running_turns", running},
      {"queued_turns", queued},
      {"busy_sessions", busy},
      {"in_flight_methods", methods},
      {"attachment_transfers", transfers},
      {"attachment_normalizations", normalizations},
      {"operator_clients", clients}
    ]

    unknown = for {field, nil} <- counters, do: field

    work = for {field, value} <- counters, field in @work_counters, do: value

    idle = if unknown == [], do: Enum.sum(work) == 0, else: nil

    counters
    |> Map.new()
    |> Map.put("silent_sessions", silent)
    |> Map.put("idle", idle)
    |> Map.put("unknown", unknown)
  end

  # `{running, queued, busy_sessions, silent_sessions}`, any of the first three `nil`
  # when the walk could not finish or the registry could not be read. `silent_sessions`
  # is how many live sessions did not answer: it is the reason `unknown` names the
  # session counters, and it is `nil` only when there was no walk at all.
  defp turn_activity(registry) do
    case live_session_runtimes(registry) do
      :unknown ->
        {nil, nil, nil, nil}

      [] ->
        {0, 0, 0, 0}

      pids ->
        deadline = System.monotonic_time(:millisecond) + @turn_budget_ms

        pids
        |> Task.async_stream(&ask_session/1,
          max_concurrency: @max_concurrency,
          timeout: @session_timeout_ms,
          on_timeout: :kill_task,
          ordered: false
        )
        |> Enum.reduce_while({0, 0, 0, 0}, fn answer, {running, queued, busy, silent} ->
          if System.monotonic_time(:millisecond) >= deadline do
            # The walk ran out of budget with sessions still unasked. Whatever has been
            # added up so far is a *fraction* of this node's work, and a fraction that
            # reads as a smaller number is the one answer this must never give.
            {:halt, {nil, nil, nil, silent}}
          else
            {:cont, fold_session(answer, running, queued, busy, silent)}
          end
        end)
        |> hide_partial_totals()
    end
  end

  # One session that did not answer is one session's worth of work nobody has counted, so
  # the totals stop being totals. `silent_sessions` survives: it is the reason `unknown`
  # names what it names, and an operator looking at a node that will not stop wants the
  # number of sessions that went quiet rather than a bare `null`.
  defp hide_partial_totals({_running, _queued, _busy, silent}) when silent > 0,
    do: {nil, nil, nil, silent}

  defp hide_partial_totals(counted), do: counted

  defp fold_session({:ok, {:busy, active, waiting}}, running, queued, busy, silent),
    do: {running + active, queued + waiting, busy + 1, silent}

  defp fold_session({:ok, {:quiet, active, waiting}}, running, queued, busy, silent),
    do: {running + active, queued + waiting, busy, silent}

  # It retired between the registry read and the question. A session that no longer
  # exists is not work this node would lose.
  defp fold_session({:ok, :gone}, running, queued, busy, silent),
    do: {running, queued, busy, silent}

  defp fold_session(_silent, running, queued, busy, silent),
    do: {running, queued, busy, silent + 1}

  defp ask_session(pid) do
    case NativeSession.call(pid, :runtime_info, @session_timeout_ms) do
      {:ok, %{active_turn_id: active, queued_turns: waiting, busy?: busy}}
      when is_integer(waiting) and is_boolean(busy) ->
        {if(busy, do: :busy, else: :quiet), if(is_nil(active), do: 0, else: 1), waiting}

      {:error, :not_found} ->
        :gone

      # A timeout, a shape this build does not understand, or a plane that refused. None
      # of them is evidence of an empty session.
      _unanswered ->
        :silent
    end
  end

  defp live_session_runtimes(registry) do
    Registry.select(registry, [{{{:runtime, :_}, :"$1", :_}, [], [:"$1"]}])
  rescue
    ArgumentError -> :unknown
  end

  defp attachment_activity(server) do
    case GenServer.whereis(server) do
      nil ->
        {0, 0}

      pid ->
        case GenServer.call(pid, :activity, @call_timeout_ms) do
          %{transfers: transfers, normalizations: normalizations}
          when is_integer(transfers) and is_integer(normalizations) ->
            {transfers, normalizations}

          _unrecognized ->
            {nil, nil}
        end
    end
  catch
    :exit, _reason -> {nil, nil}
  end

  # `:count_children` is asked directly rather than through
  # `DynamicSupervisor.count_children/1` because that function waits `:infinity`, and
  # nothing in an idle check may wait without a deadline.
  defp operator_clients(supervisor) do
    case GenServer.whereis(supervisor) do
      nil ->
        nil

      pid ->
        case GenServer.call(pid, :count_children, @call_timeout_ms) do
          counts when is_list(counts) -> active_children(Keyword.get(counts, :active))
          %{active: active} -> active_children(active)
          _unrecognized -> nil
        end
    end
  catch
    :exit, _reason -> nil
  end

  defp active_children(active) when is_integer(active) and active >= 0, do: active
  defp active_children(_other), do: nil
end
