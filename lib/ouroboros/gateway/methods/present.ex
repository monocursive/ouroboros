defmodule Ouroboros.Gateway.Methods.Present do
  @moduledoc false

  # List projections and fleet reads. A successful array is authoritative, so a
  # required owner that does not answer fails closed rather than returning a
  # shorter list that looks complete.

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Cluster
  alias Ouroboros.CodingSession
  alias Ouroboros.Gateway.Methods.Encode
  alias Ouroboros.Gateway.Methods.Safe
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Team

  # One provider probe shells out to check an installed executable, so the fan-out is
  # bounded well inside the method ceiling: a provider that never answers costs the
  # client a null status for that provider, not a timed-out method.
  @provider_probe_timeout 5_000
  @fleet_query_timeout 5_000

  def providers do
    specs = Ouroboros.providers()

    specs
    |> Task.async_stream(&probe_provider/1,
      timeout: @provider_probe_timeout,
      on_timeout: :kill_task,
      max_concurrency: max(length(specs), 1),
      ordered: true
    )
    |> Enum.zip(specs)
    |> Enum.map(fn
      {{:ok, probed}, _spec} ->
        probed

      {{:exit, _reason}, spec} ->
        %{provider: spec.provider, spec: spec, status: nil, error: :probe_timeout}
    end)
  end

  # Session checkpoints are owner-local, so a client attached to one gateway has to ask
  # every connected compatible core. A successful array is authoritative in existing
  # clients; it must therefore include every queryable core and fail when an owner proven
  # by an earlier complete list or successful start is no longer queryable. That positive
  # observation matters for transitive peers which were never invitation seeds and for
  # peers whose last-known runtime later became incompatible. Returning [] for either
  # kind of disconnected owner made its sessions disappear even though this gateway had
  # already proved that it owned checkpoints.
  # Fail the read instead: the TUI retains its last-known rows and retries, which is both
  # backward-compatible and honest. A seed with no positive evidence does not freeze an
  # otherwise useful list during an ordinary outage. Sessions created exclusively through
  # another gateway remain owner-local until journals themselves are replicated.
  def fleet_sessions(module) when module in [InteractiveSession, CodingSession] do
    query_fleet_sessions(module, session_plane(module))
  end

  defp query_fleet_sessions(module, plane) do
    fleet = Cluster.fleet_status()
    targets = fleet_session_targets(fleet)

    case unavailable_session_owner(plane, targets) do
      {:unavailable, target} ->
        incomplete_session_list(target)

      {:error, reason} ->
        incomplete_session_evidence(reason)

      :none ->
        results =
          targets
          |> Task.async_stream(
            &fleet_session_query(&1, module),
            max_concurrency: max(length(targets), 1),
            ordered: true,
            timeout: @fleet_query_timeout,
            on_timeout: :kill_task
          )

        targets
        |> Enum.zip(results)
        |> Enum.reduce_while({:ok, []}, fn
          {target, {:ok, {:ok, sessions}}}, {:ok, observations} ->
            {:cont, {:ok, [{target, sessions} | observations]}}

          {target, _unavailable_or_foreign}, _observations ->
            {:halt, incomplete_session_list(target)}
        end)
        |> case do
          {:ok, observations} ->
            # This synchronous update happens before the successful list escapes. Every
            # queried target participates, so an empty connected owner clears its old
            # evidence while an unavailable required owner can never be cleared by accident.
            case Cluster.record_session_snapshot(plane, observations) do
              :ok ->
                sessions = Enum.flat_map(observations, &elem(&1, 1))

                {:ok,
                 Enum.sort_by(sessions, fn session ->
                   {session |> Map.get(:node, node()) |> Atom.to_string(),
                    Map.get(session, :id, "")}
                 end)}

              {:error, reason} ->
                incomplete_session_evidence(reason)
            end

          error ->
            error
        end
    end
  end

  defp session_plane(InteractiveSession), do: :interactive
  defp session_plane(CodingSession), do: :coding

  # Builders and signers deliberately run no session stores. Asking every distributed
  # node made a healthy mixed-role fleet look incomplete, so only connected, compatible
  # cores participate. Positive evidence still wins: a previously listed owner that is
  # now offline, incompatible, or no longer a core is required and fails closed below.
  defp fleet_session_targets(fleet) do
    fleet.machines
    |> Enum.filter(fn machine ->
      machine.state in [:local, :connected] and machine.role == :core and
        machine.runtime_running? == true and machine.compatibility in [:local, :compatible]
    end)
    |> Enum.map(& &1.node)
    |> Enum.uniq()
  end

  defp unavailable_session_owner(plane, targets) do
    queried = targets |> Enum.map(&Atom.to_string/1) |> MapSet.new()

    case Cluster.session_owners(plane) do
      {:ok, owners} ->
        unavailable =
          owners
          |> Enum.sort()
          |> Enum.find(&(not MapSet.member?(queried, &1)))

        if is_binary(unavailable), do: {:unavailable, unavailable}, else: :none

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp incomplete_session_evidence(_reason) do
    {:error, Ouroboros.Gateway.Methods.code(:unavailable),
     "session list is incomplete because durable fleet owner evidence is unavailable; keeping the previous fleet view is safer than hiding its sessions",
     %{
       "reason" => "owner_query_incomplete",
       "node" => "unknown",
       "evidence" => "unavailable"
     }}
  end

  defp incomplete_session_list(target) do
    owner = if(is_atom(target), do: Atom.to_string(target), else: target)

    {:error, Ouroboros.Gateway.Methods.code(:unavailable),
     "session list is incomplete because owner #{owner} did not answer; keeping the previous fleet view is safer than hiding its sessions",
     %{"reason" => "owner_query_incomplete", "node" => owner}}
  end

  # `Task.async_stream/3` bounds slow owners. Convert exceptions/exits inside each task
  # into ordinary data as well, so a dead remote Store cannot link-exit the gateway
  # caller while we are trying to report the partial read honestly.
  defp fleet_session_query(target, module) do
    sessions =
      if target == node() do
        apply(module, :list, [])
      else
        :erpc.call(target, module, :list, [], @fleet_query_timeout)
      end

    if is_list(sessions), do: {:ok, sessions}, else: {:error, :invalid_reply}
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp probe_provider(spec) do
    case Ouroboros.provider_status(spec.provider) do
      {:ok, status} -> %{provider: spec.provider, spec: spec, status: status, error: nil}
      {:error, reason} -> %{provider: spec.provider, spec: spec, status: nil, error: reason}
    end
  end

  # Projected exactly as `Ouroboros.status/0` projects it, so a client reading both sees
  # one shape for a team rather than two.
  def teams do
    Team.Store.list()
    |> Enum.map(fn team ->
      %{
        id: team.id,
        status: team.status,
        worker_count: map_size(team.workers),
        delegation_count: map_size(team.delegations),
        updated_at: team.updated_at
      }
    end)
  end

  def ledger_local_list(target, filters) do
    case ledger_query(target, filters) do
      {:ok, entries} ->
        {:ok, %{entries: entries, nodes: [%{node: target, status: :ok}]}}

      {:error, reason} ->
        {:ok,
         %{
           entries: [],
           nodes: [%{node: target, status: :unavailable, reason: Wire.to_json(reason)}]
         }}
    end
  end

  # I3. "Survives machine moves" is only true if every owner is asked, so this asks every
  # connected core node and says which ones did not answer instead of returning a shorter
  # list that looks complete. Sequences are minted per node, so there is no cross-node
  # total order to merge into: entries are ordered by `{node, sequence}` and the node is
  # part of every row.
  def ledger_fleet_list(filters) do
    targets = Cluster.fleet_status() |> fleet_session_targets() |> ensure_local_target()

    results =
      targets
      |> Task.async_stream(&{&1, ledger_query(&1, filters)},
        max_concurrency: max(length(targets), 1),
        ordered: true,
        timeout: @fleet_query_timeout + 1_000,
        on_timeout: :kill_task
      )
      |> Enum.zip(targets)
      |> Enum.map(fn
        {{:ok, {target, {:ok, entries}}}, _target} ->
          {%{node: target, status: :ok}, entries}

        {{:ok, {target, {:error, reason}}}, _target} ->
          {%{node: target, status: :unavailable, reason: Wire.to_json(reason)}, []}

        {{:exit, reason}, target} ->
          {%{node: target, status: :unavailable, reason: Wire.to_json(reason)}, []}
      end)

    entries =
      results
      |> Enum.flat_map(fn {%{node: target}, entries} ->
        Enum.map(entries, &{Atom.to_string(target), &1})
      end)
      |> Enum.sort_by(fn {name, entry} -> {name, -entry.sequence} end)
      |> Enum.map(&elem(&1, 1))
      |> Enum.take(filters[:limit])

    {:ok, %{entries: entries, nodes: Enum.map(results, &elem(&1, 0))}}
  end

  defp ensure_local_target([]), do: [node()]

  defp ensure_local_target(targets) do
    if node() in targets, do: targets, else: [node() | targets]
  end

  # Exceptions and exits become data here for the same reason `fleet_session_query/2` does
  # it: a dead remote ledger must not link-exit the gateway task that is trying to report
  # honestly that it is dead.
  defp ledger_query(target, filters) do
    result =
      if target == node() do
        EffectLedger.list(filters)
      else
        :erpc.call(target, EffectLedger, :list, [filters], @fleet_query_timeout)
      end

    case result do
      {:ok, entries} when is_list(entries) -> {:ok, entries}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_reply, other}}
    end
  rescue
    error -> {:error, {:exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  # I1's JSONL export. Each line is the exact text whose bytes the hash covers, so a client
  # verifies the chain by hashing what it was given rather than by agreeing with this
  # runtime about how to canonicalise a JSON object. The chain is computed for this answer
  # and is not stored anywhere: it makes an export self-verifying, which is a different and
  # much smaller claim than tamper-proof storage.
  def ledger_export(target, since) do
    limits = EffectLedger.query_limits()
    filters = [since_sequence: since, order: :asc, limit: limits.max]

    case ledger_query(target, filters) do
      {:ok, entries} ->
        {:ok,
         entries
         |> Encode.chain()
         |> Map.merge(%{node: target, format: "jsonl", limit: limits.max, since: since})}

      {:error, reason} ->
        Safe.unavailable("the effect ledger on #{target} did not answer: #{inspect(reason)}")
    end
  end
end
