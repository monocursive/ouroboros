defmodule Ouroboros.Cluster.Monitor do
  @moduledoc false

  use GenServer

  require Logger

  alias Ouroboros.Storage.DurableFile

  @session_owner_checkpoint {:ouroboros, :cluster_session_owners, 1}
  @session_owner_checkpoint_version 1
  @max_node_name_bytes 512
  @max_fleet_profile_bytes 2 * 1024 * 1024
  @max_fleet_roster_entries 4_096
  # A fleet profile accepted by this monitor must never exceed the evidence journal that
  # makes its session lists complete. Derive the limits from one contract so adding the
  # 257th otherwise-valid machine cannot turn all prior owner evidence unavailable.
  @max_session_owners_per_plane @max_fleet_roster_entries

  # Topology churn is the one cluster event an operator cannot reconstruct after the
  # fact: `Node.list/0` shows what is connected now, never what left. Keep a bounded,
  # secret-free last-known directory so both logs and the operator surface can explain
  # an absent machine after it has gone.
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_opts) do
    # Valid whether or not distribution has started: a node that becomes alive later
    # still delivers to this subscription.
    :ok = :net_kernel.monitor_nodes(true, [:nodedown_reason, node_type: :visible])

    now = timestamp()
    {session_owners, session_owner_evidence} = load_session_owners()

    state =
      %{
        machines: %{},
        session_owners: session_owners,
        session_owner_evidence: session_owner_evidence,
        started_at: now,
        refreshing?: true
      }
      |> refresh_expected()
      |> observe_local(now)
      |> mark_connected(Node.list(), now)

    # Connected nodes may already predate this process (for example after the formation
    # supervisor or monitor restarts). Probe them after init so a slow or half-booted peer
    # never holds this supervisor's start handshake open.
    send(self(), {:refresh_connected, Node.list()})
    {:ok, state}
  end

  @impl true
  def handle_call(:status, _from, state) do
    now = timestamp()

    state =
      state
      |> refresh_expected()
      |> observe_local(now)
      |> synchronize_connectivity(Node.list(), now)

    state = maybe_refresh_connected(state)

    {:reply, render(state, now), state}
  end

  def handle_call({:session_owners, plane}, _from, state)
      when plane in [:interactive, :coding] do
    reply =
      case Map.get(state, :session_owner_evidence, :reliable) do
        :reliable -> {:ok, state |> session_owners() |> Map.fetch!(plane)}
        {:unreliable, reason} -> {:error, reason}
      end

    {:reply, reply, state}
  end

  def handle_call({:record_session_snapshot, plane, observations}, _from, state)
      when plane in [:interactive, :coding] and is_list(observations) do
    observed =
      observations
      |> Enum.map(fn {target, _sessions} -> Atom.to_string(target) end)
      |> MapSet.new()

    present =
      observations
      |> Enum.filter(fn {_target, sessions} -> sessions != [] end)
      |> Enum.map(fn {target, _sessions} -> Atom.to_string(target) end)
      |> MapSet.new()

    owners =
      state
      |> session_owners()
      |> Map.fetch!(plane)
      |> MapSet.difference(observed)
      |> MapSet.union(present)

    current = session_owners(state)
    updated = Map.put(current, plane, owners)

    commit =
      if updated == current and Map.get(state, :session_owner_evidence, :reliable) == :reliable,
        do: :ok,
        else: persist_session_owners(updated)

    case commit do
      :ok ->
        state =
          state
          |> Map.put(:session_owners, updated)
          |> Map.put(:session_owner_evidence, :reliable)

        {:reply, :ok, state}

      {:error, reason} ->
        Logger.error(
          "cluster session-owner checkpoint failed; fleet lists will fail closed: " <>
            inspect(reason, limit: 10, printable_limit: 200)
        )

        {:reply, {:error, reason}, Map.put(state, :session_owner_evidence, {:unreliable, reason})}
    end
  end

  def handle_call({:forget_session_owner, machine}, _from, state) when is_binary(machine) do
    case forget_session_owner(state, machine) do
      {:ok, result, updated} ->
        {:reply, {:ok, result}, updated}

      {:error, {:session_owner_forget_checkpoint_failed, _failure} = reason} ->
        Logger.error(
          "session-owner retirement could not be checkpointed; fleet lists will fail closed: " <>
            inspect(reason, limit: 10, printable_limit: 200)
        )

        {:reply, {:error, reason}, Map.put(state, :session_owner_evidence, {:unreliable, reason})}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info({:nodeup, joined, _info}, state) do
    {:noreply, observe_join(state, joined)}
  end

  def handle_info({:nodeup, joined}, state), do: {:noreply, observe_join(state, joined)}

  def handle_info({:nodedown, left, info}, state) do
    reason =
      case info do
        list when is_list(list) -> Keyword.get(list, :nodedown_reason, :unknown)
        _other -> :unknown
      end

    {:noreply, observe_leave(state, left, reason)}
  end

  def handle_info({:nodedown, left}, state),
    do: {:noreply, observe_leave(state, left, :unknown)}

  def handle_info({:refresh_connected, connected}, state) do
    state =
      Enum.reduce(connected, state, fn target, acc ->
        acc = observe_up(acc, target, timestamp())
        notify_teams(:nodeup, target)
        acc
      end)

    {:noreply, %{state | refreshing?: false}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp observe_join(state, joined) do
    now = timestamp()
    state = observe_up(state, joined, now)
    machine = Map.fetch!(state.machines, joined)

    Logger.info(
      "cluster nodeup #{inspect(joined)} machine=#{inspect(machine.machine)} " <>
        "role=#{inspect(machine.role)}"
    )

    notify_teams(:nodeup, joined)
    state
  end

  # A node that just appeared is exactly the node most likely to be mid-boot,
  # unreachable again, or not running this runtime at all. Every one of those is an
  # observation to retain, never a reason to crash the monitor.
  defp observe_up(state, target, now) do
    base = Map.get(state.machines, target, new_machine(target, now))

    observed =
      case Ouroboros.Cluster.fleet_posture(target) do
        {:ok, posture} ->
          Map.merge(base, %{
            machine: posture.machine,
            role: posture.role,
            runtime_running?: posture.running,
            runtime: posture.runtime,
            probe_error: nil
          })

        {:error, reason} ->
          %{base | probe_error: reason}
      end

    observed = %{
      observed
      | state: if(target == node(), do: :local, else: :connected),
        first_seen_at: observed.first_seen_at || now,
        last_seen_at: now,
        last_up_at:
          if(observed.state in [:local, :connected] and observed.last_up_at,
            do: observed.last_up_at,
            else: now
          ),
        down_reason: nil
    }

    put_machine(state, observed)
  end

  defp observe_local(state, now) do
    # A library/test VM may start this application before `net_kernel` and acquire its
    # distributed name later. `:nonode@nohost` was never a separate machine, so replace
    # that stale local identity instead of presenting two locals forever. Session-owner
    # evidence names nodes too: migrate it in the same transition, otherwise a list made
    # before distribution can leave a phantom offline owner that makes every later list
    # fail closed depending on which test or caller happened to start `net_kernel` first.
    stale_locals =
      state.machines
      |> Enum.filter(fn {target, machine} -> target != node() and machine.state == :local end)
      |> Enum.map(fn {target, _machine} -> Atom.to_string(target) end)
      |> MapSet.new()
      |> then(fn stale ->
        if node() == :nonode@nohost,
          do: stale,
          else: MapSet.put(stale, "nonode@nohost")
      end)

    state = migrate_local_session_owners(state, stale_locals)

    machines =
      Map.reject(state.machines, fn {target, machine} ->
        target != node() and machine.state == :local
      end)

    observe_up(%{state | machines: machines}, node(), now)
  end

  defp migrate_local_session_owners(state, stale_locals) do
    current = session_owners(state)
    replacement = Atom.to_string(node())

    updated =
      Map.new(current, fn {plane, owners} ->
        if MapSet.disjoint?(owners, stale_locals) do
          {plane, owners}
        else
          {plane,
           owners
           |> MapSet.difference(stale_locals)
           |> MapSet.put(replacement)}
        end
      end)

    cond do
      Map.get(state, :session_owner_evidence, :reliable) != :reliable ->
        state

      updated == current ->
        state

      true ->
        case persist_session_owners(updated) do
          :ok ->
            %{state | session_owners: updated, session_owner_evidence: :reliable}

          {:error, reason} ->
            Logger.error(
              "cluster local session-owner migration could not be checkpointed; " <>
                "fleet lists will fail closed: " <>
                inspect(reason, limit: 10, printable_limit: 200)
            )

            %{
              state
              | session_owners: updated,
                session_owner_evidence: {:unreliable, reason}
            }
        end
    end
  end

  defp observe_leave(state, left, reason) do
    now = timestamp()
    machine = Map.get(state.machines, left, new_machine(left, now))

    machine = %{
      machine
      | state: :offline,
        last_down_at: now,
        down_reason: bounded_reason(reason),
        probe_error: :node_not_connected
    }

    Logger.warning("cluster nodedown #{inspect(left)} reason=#{inspect(reason)}")
    notify_teams(:nodedown, left)
    put_machine(state, machine)
  end

  defp mark_connected(state, connected, now) do
    Enum.reduce(connected, state, fn target, acc ->
      machine = Map.get(acc.machines, target, new_machine(target, now))

      put_machine(acc, %{
        machine
        | state: :connected,
          first_seen_at: machine.first_seen_at || now,
          last_seen_at: now,
          last_up_at:
            if(machine.state == :connected and machine.last_up_at,
              do: machine.last_up_at,
              else: now
            ),
          down_reason: nil
      })
    end)
  end

  defp synchronize_connectivity(state, connected, now) do
    connected = MapSet.new(connected)

    state = mark_connected(state, MapSet.to_list(connected), now)

    machines =
      Map.new(state.machines, fn
        {target, machine} when target == node() ->
          {target, %{machine | state: :local}}

        {target, %{state: :connected} = machine} ->
          if MapSet.member?(connected, target) do
            {target, machine}
          else
            {target,
             %{
               machine
               | state: :offline,
                 last_down_at: machine.last_down_at || now,
                 down_reason: machine.down_reason || "connection_lost",
                 probe_error: :node_not_connected
             }}
          end

        entry ->
          entry
      end)

    %{state | machines: machines}
  end

  defp maybe_refresh_connected(%{refreshing?: true} = state), do: state

  defp maybe_refresh_connected(state) do
    stale =
      Enum.filter(Node.list(), fn target ->
        case Map.get(state.machines, target) do
          %{runtime_running?: true} -> false
          _unknown_or_booting -> true
        end
      end)

    if stale == [] do
      state
    else
      send(self(), {:refresh_connected, stale})
      %{state | refreshing?: true}
    end
  end

  defp refresh_expected(state) do
    expected = MapSet.new(Ouroboros.Cluster.expected_nodes())

    machines =
      state.machines
      |> Map.new(fn {target, machine} -> {target, %{machine | expected?: false}} end)
      |> then(fn machines ->
        Enum.reduce(expected, machines, fn target, acc ->
          Map.update(
            acc,
            target,
            %{new_machine(target, nil) | expected?: true},
            &%{&1 | expected?: true}
          )
        end)
      end)

    %{state | machines: machines}
  end

  defp render(state, now) do
    local_runtime = Ouroboros.Cluster.local_fleet_posture().runtime

    machines =
      state.machines
      |> Map.values()
      |> Enum.map(fn machine ->
        compatibility = compatibility(machine, local_runtime)

        machine
        |> Map.delete(:probe_error)
        |> Map.put(:compatibility, compatibility)
      end)
      |> Enum.sort_by(fn machine ->
        {state_order(machine.state), Atom.to_string(machine.node)}
      end)

    # An early joiner may only have its invitation seeds in static configuration and
    # learn later machines through BEAM transitive connectivity. "expected 2 / connected
    # 3" reads like corrupt state to an operator, so the summary is the union of configured
    # peers and the last-known directory. Per-machine `expected?` still identifies the
    # statically configured seeds for diagnosis.
    expected = length(machines)
    connected = Enum.count(machines, &(&1.state in [:local, :connected]))
    offline = Enum.count(machines, &(&1.state == :offline))
    incompatible = Enum.count(machines, &(&1.compatibility == :incompatible))

    %{
      local_node: node(),
      generated_at: now,
      monitoring_since: state.started_at,
      summary: %{
        expected: expected,
        connected: connected,
        offline: offline,
        compatible: Enum.count(machines, &(&1.compatibility in [:local, :compatible])),
        incompatible: incompatible
      },
      machines: machines,
      formation: Ouroboros.Cluster.formation(),
      security: Ouroboros.Cluster.dist_security()
    }
  end

  defp compatibility(%{node: target}, _local_runtime) when target == node(), do: :local
  defp compatibility(%{runtime: nil}, _local_runtime), do: :unknown

  defp compatibility(%{runtime: runtime}, local_runtime) do
    if Ouroboros.Cluster.runtime_compatible?(runtime, local_runtime),
      do: :compatible,
      else: :incompatible
  end

  defp state_order(:local), do: 0
  defp state_order(:connected), do: 1
  defp state_order(:offline), do: 2

  defp new_machine(target, now) do
    %{
      node: target,
      machine: target |> Atom.to_string() |> String.split("@", parts: 2) |> List.first(),
      role: :unknown,
      state: if(target == node(), do: :local, else: :offline),
      expected?: false,
      runtime_running?: nil,
      first_seen_at: now,
      last_seen_at: if(target == node(), do: now, else: nil),
      last_up_at: if(target == node(), do: now, else: nil),
      last_down_at: nil,
      down_reason: nil,
      runtime: nil,
      probe_error: nil
    }
  end

  defp put_machine(state, machine),
    do: %{state | machines: Map.put(state.machines, machine.node, machine)}

  # The fallback supports a monitor upgraded in place from a revision whose state
  # predated session-owner evidence. A normal fresh boot always initializes this field.
  defp session_owners(state),
    do: Map.get(state, :session_owners, %{interactive: MapSet.new(), coding: MapSet.new()})

  defp load_session_owners do
    case session_owner_storage() do
      :ephemeral ->
        {empty_session_owners(), :reliable}

      {:error, reason} ->
        {empty_session_owners(), {:unreliable, reason}}

      {:ok, fleet_id, _profile, opts} ->
        case DurableFile.get_checkpoint(@session_owner_checkpoint, opts) do
          :not_found ->
            {empty_session_owners(), :reliable}

          {:ok, checkpoint} ->
            case decode_session_owner_checkpoint(checkpoint, fleet_id) do
              {:ok, owners} ->
                {owners, :reliable}

              :fleet_mismatch ->
                # The signed fleet profile is authoritative. Evidence from a prior fleet
                # in a reused data directory has no bearing on this trust domain and must
                # neither poison nor populate its first session list.
                {empty_session_owners(), :reliable}

              {:error, reason} ->
                Logger.error(
                  "cluster session-owner checkpoint is invalid; fleet lists will fail closed: " <>
                    inspect(reason, limit: 10, printable_limit: 200)
                )

                {empty_session_owners(), {:unreliable, reason}}
            end

          {:error, reason} ->
            Logger.error(
              "cluster session-owner checkpoint is unreadable; fleet lists will fail closed: " <>
                inspect(reason, limit: 10, printable_limit: 200)
            )

            {empty_session_owners(), {:unreliable, reason}}
        end
    end
  end

  defp persist_session_owners(owners) do
    with :ok <- validate_session_owners(owners) do
      case session_owner_storage() do
        :ephemeral ->
          :ok

        {:error, reason} ->
          {:error, reason}

        {:ok, fleet_id, _profile, opts} ->
          write_session_owner_checkpoint(owners, fleet_id, opts)
      end
    end
  end

  defp forget_session_owner(state, machine) do
    cond do
      not valid_profile_machine?(machine) ->
        {:error, {:invalid_session_owner_machine, machine}}

      Map.get(state, :session_owner_evidence, :reliable) != :reliable ->
        {:unreliable, reason} = state.session_owner_evidence
        {:error, {:session_owner_evidence_unavailable, reason}}

      true ->
        forget_session_owner_from_profile(state, machine)
    end
  end

  defp forget_session_owner_from_profile(state, machine) do
    case session_owner_storage() do
      :ephemeral ->
        {:error, :fleet_profile_unavailable}

      {:error, reason} ->
        {:error, {:fleet_profile_unavailable, reason}}

      {:ok, fleet_id, profile, opts} ->
        case Map.fetch(profile.tombstones, machine) do
          :error ->
            {:error, {:session_owner_not_tombstoned, machine}}

          {:ok, owner} ->
            forget_tombstoned_session_owner(state, machine, owner, profile, fleet_id, opts)
        end
    end
  end

  defp forget_tombstoned_session_owner(state, machine, owner, profile, fleet_id, opts) do
    if session_owner_connected?(owner) do
      {:error, {:session_owner_connected, machine, owner}}
    else
      current = session_owners(state)

      updated = %{
        interactive: MapSet.delete(current.interactive, owner),
        coding: MapSet.delete(current.coding, owner)
      }

      with :ok <- validate_session_owners(updated),
           :ok <- write_session_owner_checkpoint(updated, fleet_id, opts) do
        result = %{
          machine: machine,
          node: owner,
          roster_revision: profile.roster_revision,
          removed: updated != current
        }

        {:ok, result, Map.put(state, :session_owners, updated)}
      else
        {:error, reason} -> {:error, {:session_owner_forget_checkpoint_failed, reason}}
      end
    end
  end

  defp session_owner_connected?(owner) do
    [node() | Node.list()]
    |> Enum.any?(&(Atom.to_string(&1) == owner))
  end

  defp write_session_owner_checkpoint(owners, fleet_id, opts) do
    checkpoint = %{
      version: @session_owner_checkpoint_version,
      fleet_id: fleet_id,
      interactive: owners.interactive |> Enum.sort(),
      coding: owners.coding |> Enum.sort()
    }

    DurableFile.put_checkpoint(@session_owner_checkpoint, checkpoint, opts)
  end

  defp decode_session_owner_checkpoint(
         %{
           version: @session_owner_checkpoint_version,
           fleet_id: fleet_id,
           interactive: interactive,
           coding: coding
         },
         fleet_id
       ) do
    with {:ok, interactive} <- decode_owner_list(:interactive, interactive),
         {:ok, coding} <- decode_owner_list(:coding, coding),
         do: {:ok, %{interactive: interactive, coding: coding}}
  end

  defp decode_session_owner_checkpoint(
         %{
           version: @session_owner_checkpoint_version,
           fleet_id: recorded
         },
         fleet_id
       )
       when is_binary(recorded) and recorded != fleet_id,
       do: :fleet_mismatch

  defp decode_session_owner_checkpoint(_invalid, _fleet_id),
    do: {:error, :invalid_session_owner_checkpoint}

  defp validate_session_owners(%{interactive: interactive, coding: coding}) do
    with :ok <- validate_owner_set(:interactive, interactive),
         :ok <- validate_owner_set(:coding, coding),
         do: :ok
  end

  defp validate_session_owners(_invalid), do: {:error, :invalid_session_owner_checkpoint}

  defp decode_owner_list(plane, owners) when is_list(owners) do
    cond do
      length(owners) > @max_session_owners_per_plane ->
        {:error, {:too_many_session_owners, plane}}

      Enum.all?(owners, &valid_node_name?/1) ->
        {:ok, MapSet.new(owners)}

      true ->
        {:error, {:invalid_session_owner, plane}}
    end
  end

  defp decode_owner_list(plane, _invalid), do: {:error, {:invalid_session_owners, plane}}

  defp validate_owner_set(plane, %MapSet{} = owners) do
    cond do
      MapSet.size(owners) > @max_session_owners_per_plane ->
        {:error, {:too_many_session_owners, plane}}

      Enum.all?(owners, &valid_node_name?/1) ->
        :ok

      true ->
        {:error, {:invalid_session_owner, plane}}
    end
  end

  defp validate_owner_set(plane, _invalid), do: {:error, {:invalid_session_owners, plane}}

  defp valid_node_name?(name) when is_binary(name) do
    byte_size(name) in 3..@max_node_name_bytes and String.valid?(name) and
      Regex.match?(~r/\A[A-Za-z0-9_.-]+@[A-Za-z0-9_.:%-]+\z/, name)
  end

  defp valid_node_name?(_invalid), do: false

  defp session_owner_storage do
    data_dir = Application.get_env(:ouroboros, :data_dir)
    fleet_id = System.get_env("OUROBOROS_FLEET_ID")

    cond do
      not (is_binary(data_dir) and data_dir != "") ->
        :ephemeral

      is_nil(fleet_id) ->
        :ephemeral

      not valid_fleet_id?(fleet_id) ->
        {:error, :invalid_fleet_identity}

      true ->
        root = Path.join(Path.expand(data_dir), "fleet")
        profile = Path.join(root, "profile.json")

        case read_fleet_tombstones(profile, fleet_id) do
          {:ok, profile} ->
            {:ok, fleet_id, profile, [path: Path.join(root, "cluster-directory")]}

          {:error, :enoent} ->
            # Standalone mode must never resurrect evidence from a fleet that was left.
            :ephemeral

          {:error, reason} ->
            {:error, {:fleet_profile_unreadable, reason}}
        end
    end
  end

  defp read_fleet_tombstones(profile, fleet_id) do
    with {:ok, %File.Stat{type: :regular, size: size}}
         when size <= @max_fleet_profile_bytes <- File.lstat(profile),
         {:ok, encoded} <- read_bounded_fleet_profile(profile),
         {:ok, decoded} <- Jason.decode(encoded),
         {:ok, tombstones} <- decode_fleet_tombstones(decoded, fleet_id) do
      {:ok, tombstones}
    else
      {:error, :enoent} ->
        {:error, :enoent}

      {:ok, %File.Stat{size: size}} when size > @max_fleet_profile_bytes ->
        {:error, :fleet_profile_too_large}

      {:ok, %File.Stat{type: type}} ->
        {:error, {:invalid_fleet_profile_type, type}}

      {:error, %Jason.DecodeError{}} ->
        {:error, :invalid_fleet_profile_json}

      {:error, reason} ->
        {:error, reason}

      _invalid ->
        {:error, :invalid_fleet_profile}
    end
  end

  defp read_bounded_fleet_profile(profile) do
    case File.open(profile, [:read, :binary]) do
      {:ok, io} ->
        try do
          case IO.binread(io, @max_fleet_profile_bytes + 1) do
            encoded when is_binary(encoded) and byte_size(encoded) <= @max_fleet_profile_bytes ->
              {:ok, encoded}

            encoded when is_binary(encoded) ->
              {:error, :fleet_profile_too_large}

            :eof ->
              {:ok, ""}

            {:error, reason} ->
              {:error, reason}
          end
        after
          File.close(io)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp decode_fleet_tombstones(
         %{
           "schema" => 1,
           "fleet_id" => fleet_id,
           "machine" => local_machine,
           "host" => local_host,
           "node" => local_node,
           "role" => "core",
           "members" => members,
           "roster_revision" => revision
         } = profile,
         fleet_id
       )
       when is_binary(local_machine) and is_binary(local_host) and is_binary(local_node) and
              is_integer(revision) and revision > 0 do
    with true <- valid_profile_machine?(local_machine),
         true <- valid_profile_host?(local_host),
         true <- local_node == "ouro-#{local_machine}@#{local_host}",
         true <- configured_local_node?(local_node),
         {:ok, active} <- decode_profile_members(:members, members),
         true <- MapSet.member?(active.nodes, local_node),
         {:ok, removed} <-
           decode_profile_members(:tombstones, Map.get(profile, "tombstones", [])),
         true <- MapSet.disjoint?(active.nodes, removed.nodes),
         true <- MapSet.disjoint?(active.machines, removed.machines) do
      {:ok, %{roster_revision: revision, tombstones: removed.by_machine}}
    else
      _invalid -> {:error, :invalid_fleet_profile_roster}
    end
  end

  defp decode_fleet_tombstones(%{"fleet_id" => recorded}, fleet_id)
       when is_binary(recorded) and recorded != fleet_id,
       do: {:error, :fleet_profile_identity_mismatch}

  defp decode_fleet_tombstones(_invalid, _fleet_id),
    do: {:error, :invalid_fleet_profile}

  defp decode_profile_members(kind, entries) when is_list(entries) do
    if length(entries) <= @max_fleet_roster_entries do
      Enum.reduce_while(
        entries,
        {:ok, %{nodes: MapSet.new(), machines: MapSet.new(), by_machine: %{}}},
        fn
          %{"machine" => machine, "host" => host, "node" => owner}, {:ok, seen} ->
            cond do
              not valid_profile_machine?(machine) or not valid_profile_host?(host) or
                owner != "ouro-#{machine}@#{host}" or not valid_node_name?(owner) ->
                {:halt, {:error, {:invalid_fleet_profile_member, kind}}}

              MapSet.member?(seen.nodes, owner) or MapSet.member?(seen.machines, machine) ->
                {:halt, {:error, {:duplicate_fleet_profile_member, kind}}}

              true ->
                {:cont,
                 {:ok,
                  %{
                    nodes: MapSet.put(seen.nodes, owner),
                    machines: MapSet.put(seen.machines, machine),
                    by_machine: Map.put(seen.by_machine, machine, owner)
                  }}}
            end

          _invalid, _seen ->
            {:halt, {:error, {:invalid_fleet_profile_member, kind}}}
        end
      )
    else
      {:error, {:too_many_fleet_profile_members, kind}}
    end
  end

  defp decode_profile_members(kind, _invalid),
    do: {:error, {:invalid_fleet_profile_members, kind}}

  defp valid_profile_machine?(machine) when is_binary(machine) do
    byte_size(machine) in 1..40 and
      Regex.match?(~r/\A[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\z/, machine)
  end

  defp valid_profile_machine?(_invalid), do: false

  defp valid_profile_host?(host) when is_binary(host) do
    byte_size(host) in 1..253 and not String.contains?(host, ["@", ",", ":"]) and
      not String.starts_with?(host, "-") and not String.ends_with?(host, "-") and
      Regex.match?(~r/\A[A-Za-z0-9._-]+\z/, host)
  end

  defp valid_profile_host?(_invalid), do: false

  defp configured_local_node?(profile_node) do
    case System.get_env("OUROBOROS_NODE") do
      nil -> true
      configured -> configured == profile_node
    end
  end

  defp valid_fleet_id?(fleet_id),
    do: is_binary(fleet_id) and Regex.match?(~r/\A[0-9a-f]{24}\z/, fleet_id)

  defp empty_session_owners,
    do: %{interactive: MapSet.new(), coding: MapSet.new()}

  defp notify_teams(event, target) do
    case Process.whereis(Ouroboros.Team.Supervisor) do
      supervisor when is_pid(supervisor) ->
        supervisor
        |> DynamicSupervisor.which_children()
        |> Enum.each(fn
          {_id, pid, _type, _modules} when is_pid(pid) ->
            send(pid, {:ouroboros_cluster, event, target})

          _child ->
            :ok
        end)

      _absent ->
        :ok
    end
  catch
    :exit, _reason -> :ok
  end

  defp bounded_reason(reason),
    do: reason |> inspect(limit: 20, printable_limit: 200) |> String.slice(0, 500)

  defp timestamp, do: DateTime.utc_now() |> DateTime.to_iso8601()
end

defmodule Ouroboros.Cluster do
  @moduledoc """
  Node role and cluster formation: who this node is, and how it finds the others.

  The runtime's distribution *semantics* (mesh membership over `:pg`, `:erpc` routing,
  multi-node upgrade coordination) never depended on how nodes met. This module owns the
  other half — formation and identity — and is deliberately the only place that knows
  either.

  ## Roles

  Every node boots as exactly one of `:core`, `:builder`, or `:signer`, from
  `config :ouroboros, :node_role` (default `:core`). The role shapes the supervision
  tree (`Ouroboros.Application`): a `:core` node runs the full runtime, while `:builder`
  and `:signer` run this supervisor and nothing else. That is not a sandbox — see
  "Limits" below — it is a least-privilege posture: a builder host has no team store, no
  scheduler, no control plane, and no coding sessions to lose, so compromising it yields
  a compiler, not a fleet.

  An unrecognized `:node_role` refuses the boot rather than defaulting to the most
  privileged role.

  ## Formation

  Formation is off by default. `OUROBOROS_CLUSTER_STRATEGY` selects one of:

    * `none` (default) — no discovery. Nodes connect because something else connected
      them, exactly as before this module existed.
    * `epmd` — a static list of node names in `OUROBOROS_CLUSTER_HOSTS`
      (comma-separated), retried on an interval so boot order does not matter.
    * `gossip` — libcluster's multicast gossip, optionally keyed by
      `OUROBOROS_CLUSTER_GOSSIP_SECRET`.
    * `dns` — poll the A records of `OUROBOROS_CLUSTER_DNS_QUERY` and connect
      `basename@ip`.

  A strategy that is named but misconfigured refuses the boot; it does not quietly fall
  back to an unformed cluster.

  ## Limits

  Role is a *placement* concept, not a security boundary. Any node that completes the
  distribution handshake — cookie, and TLS if configured — has full `:erpc` authority
  over every other connected node, so a hostile connected node ignores every check here
  by calling whatever it likes directly. Role checks stop misconfiguration and
  accidents: work sent to a node that cannot run it, or a build sent to a node that is
  not a builder. The boundaries that hold against a hostile *artifact* are the verifier's
  namespace policy and signature verification, not this module.
  """

  use Supervisor

  @roles [:core, :builder, :signer]
  @strategies [:none, :epmd, :gossip, :dns]
  @session_planes [:interactive, :coding]
  @role_key {__MODULE__, :node_role}
  @formation_name __MODULE__.Formation
  @probe_timeout 5_000
  @directory_timeout 2_000
  @default_reconnect_ms 5_000

  # Manual distributed-runtime compatibility fence. Bump this integer whenever a change
  # makes mixed-revision fleet posture, remote session routing, or distributed ownership
  # unsafe even if the application version was accidentally left unchanged. Never derive
  # it from a build path, source hash, or host: operators need one stable, reviewable
  # protocol revision shared by every artifact in a compatible fleet.
  @fleet_protocol_revision 1
  @runtime_contract_keys [:fleet_protocol_revision, :ouroboros_version, :otp_release]

  @type role :: :core | :builder | :signer
  @type strategy :: :none | :epmd | :gossip | :dns
  @type posture :: %{node: node(), role: role(), running: boolean()}

  @doc false
  def start_link(opts), do: Supervisor.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_opts) do
    Supervisor.init(formation_children() ++ [__MODULE__.Monitor], strategy: :one_for_one)
  end

  @doc """
  Resolves, validates, and records this node's role. Called once, at application boot.

  Raises on an unrecognized role: booting the most privileged tree because a deployment
  variable was mistyped is the failure this refuses to have.
  """
  @spec boot_role!() :: role()
  def boot_role! do
    case Application.get_env(:ouroboros, :node_role, :core) do
      role when role in @roles ->
        :persistent_term.put(@role_key, role)
        role

      other ->
        raise ArgumentError,
              "config :ouroboros, :node_role must be one of #{inspect(@roles)}, got: " <>
                inspect(other)
    end
  end

  @doc "Returns every role this runtime understands."
  @spec roles() :: [role()]
  def roles, do: @roles

  @doc """
  Returns this node's role.

  Reads what `boot_role!/0` recorded. On a node where this runtime never started, it
  falls back to configuration and finally to `:core`; that fallback never widens
  authority, because every check that consumes a role also requires the target to be
  running this runtime.
  """
  @spec role() :: role()
  def role do
    case :persistent_term.get(@role_key, nil) do
      role when role in @roles ->
        role

      _absent ->
        case Application.get_env(:ouroboros, :node_role, :core) do
          role when role in @roles -> role
          _other -> :core
        end
    end
  end

  @doc """
  Returns the role a connected node claims.

  Bounded, and never raises: an unreachable node, a node without this code, and a node
  that answers something unexpected are all error tuples.
  """
  @spec role(node()) :: {:ok, role()} | {:error, term()}
  def role(target) when is_atom(target) do
    cond do
      target == node() -> {:ok, role()}
      target not in Node.list() -> {:error, :node_not_connected}
      true -> with {:ok, %{role: role}} <- probe(target), do: {:ok, role}
    end
  end

  @doc """
  Lists the connected nodes running this runtime in `role`.

  Includes this node when its own role matches. "Connected" means already in
  `Node.list/0`: this reports the cluster as formed, it does not form it.
  """
  @spec nodes_by_role(role()) :: [node()]
  def nodes_by_role(role) when role in @roles do
    postures()
    |> Enum.filter(fn {_node, posture} -> match?(%{role: ^role, running: true}, posture) end)
    |> Enum.map(fn {target, _posture} -> target end)
    |> Enum.sort()
  end

  @doc """
  Describes this node's role, the roles it can see, how it forms, and how distribution
  is protected.

  The security section reports posture, never secrets: whether a cookie is set, not
  which one.
  """
  @spec status() :: map()
  def status do
    observed = postures()
    fleet = fleet_status()

    %{
      node: node(),
      role: role(),
      distributed: Node.alive?(),
      connected_nodes: Enum.sort(Node.list()),
      roles: group_roles(observed),
      formation: formation_status(),
      security: dist_security(),
      fleet: fleet
    }
  end

  @doc "Returns the last-known fleet directory, including expected machines that are offline."
  @spec fleet_status() :: map()
  def fleet_status do
    case Process.whereis(__MODULE__.Monitor) do
      monitor when is_pid(monitor) ->
        GenServer.call(monitor, :status, @directory_timeout)

      _absent ->
        fallback_fleet_status()
    end
  catch
    :exit, _reason -> fallback_fleet_status()
  end

  @doc false
  @spec session_owners(:interactive | :coding) ::
          {:ok, MapSet.t(String.t())} | {:error, term()}
  def session_owners(plane) when plane in @session_planes do
    case Process.whereis(__MODULE__.Monitor) do
      monitor when is_pid(monitor) ->
        GenServer.call(monitor, {:session_owners, plane}, @directory_timeout)

      _absent ->
        {:error, :cluster_monitor_unavailable}
    end
  catch
    :exit, reason -> {:error, {:cluster_monitor_unavailable, reason}}
  end

  @doc false
  @spec record_session_snapshot(:interactive | :coding, [{node(), [term()]}]) ::
          :ok | {:error, term()}
  def record_session_snapshot(plane, observations)
      when plane in @session_planes and is_list(observations) do
    case Process.whereis(__MODULE__.Monitor) do
      monitor when is_pid(monitor) ->
        GenServer.call(
          monitor,
          {:record_session_snapshot, plane, observations},
          @directory_timeout
        )

      _absent ->
        {:error, :cluster_monitor_unavailable}
    end
  catch
    :exit, reason -> {:error, {:cluster_monitor_unavailable, reason}}
  end

  @doc false
  @spec forget_session_owner(String.t()) :: {:ok, map()} | {:error, term()}
  def forget_session_owner(machine) when is_binary(machine) do
    case Process.whereis(__MODULE__.Monitor) do
      monitor when is_pid(monitor) ->
        GenServer.call(monitor, {:forget_session_owner, machine}, @directory_timeout)

      _absent ->
        {:error, :cluster_monitor_unavailable}
    end
  catch
    :exit, reason -> {:error, {:cluster_monitor_unavailable, reason}}
  end

  @doc "Runs secret-free, actionable checks over the last-known fleet directory."
  @spec fleet_doctor() :: map()
  def fleet_doctor do
    fleet = fleet_status()
    checks = doctor_checks(fleet)

    %{
      healthy?: Enum.all?(checks, &(&1.status != :error)),
      generated_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      summary: %{
        ok: Enum.count(checks, &(&1.status == :ok)),
        warnings: Enum.count(checks, &(&1.status == :warning)),
        errors: Enum.count(checks, &(&1.status == :error))
      },
      checks: checks
    }
  end

  @doc "Returns the static nodes this machine expects to meet, when the topology names them."
  @spec expected_nodes() :: [node()]
  def expected_nodes do
    expected =
      case strategy() do
        {:ok, :epmd} -> node_list("OUROBOROS_CLUSTER_HOSTS")
        _other -> []
      end

    [node() | expected]
    |> Enum.uniq()
    |> Enum.sort()
  end

  @doc "Formation facts needed by an operator, without strategy credentials."
  @spec formation() :: map()
  def formation do
    formation_status()
    |> Map.put(:expected_nodes, expected_nodes())
    |> Map.put(:reconnect_ms, reconnect_interval())
  end

  @doc "Resolves an already-known node name or friendly machine name without creating an atom."
  @spec resolve_machine(String.t()) :: {:ok, node()} | {:error, term()}
  def resolve_machine(name) when is_binary(name) do
    resolve_directory_machine(name, &(&1.state in [:local, :connected]))
  end

  def resolve_machine(_name), do: {:error, :unknown_machine}

  @doc "Resolves a connected or last-known machine without creating an atom."
  @spec resolve_known_machine(String.t()) :: {:ok, node()} | {:error, term()}
  def resolve_known_machine(name) when is_binary(name) do
    resolve_directory_machine(name, fn _machine -> true end)
  end

  def resolve_known_machine(_name), do: {:error, :unknown_machine}

  @doc """
  Describes this node to a caller on another node.

  Remote-reachable by construction, and deliberately trivial: it exposes the role and
  whether the runtime's root supervisor is alive, which is what every role check needs
  and nothing else. A node with this code on its path but no running runtime answers
  honestly with `running: false`.
  """
  @spec local_posture() :: posture()
  def local_posture do
    %{node: node(), role: role(), running: is_pid(Process.whereis(Ouroboros.Supervisor))}
  end

  @doc false
  @spec local_fleet_posture() :: map()
  def local_fleet_posture do
    posture = local_posture()

    Map.merge(posture, %{
      machine: machine_name(),
      runtime: runtime_identity()
    })
  end

  @doc false
  @spec fleet_posture(node()) :: {:ok, map()} | {:error, term()}
  def fleet_posture(target) when is_atom(target) do
    cond do
      target == node() ->
        {:ok, local_fleet_posture()}

      target not in Node.list() ->
        {:error, :node_not_connected}

      true ->
        case :erpc.call(target, __MODULE__, :local_fleet_posture, [], @probe_timeout) do
          %{node: ^target, role: role, running: running, machine: machine, runtime: runtime} =
              posture
          when role in @roles and is_boolean(running) and is_binary(machine) and is_map(runtime) ->
            {:ok, posture}

          other ->
            {:error, {:invalid_fleet_posture, inspect(other)}}
        end
    end
  catch
    kind, reason -> {:error, {:fleet_probe_failed, {kind, inspect(reason)}}}
  end

  @doc false
  @spec runtime_compatible?(map(), map()) :: boolean()
  def runtime_compatible?(left, right) when is_map(left) and is_map(right) do
    # BEAM distribution and agent placement are intentionally cross-architecture. A
    # packaged arm64 Mac and x86_64 Linux machine are compatible when they speak the same
    # explicit fleet protocol on the same Ouroboros and OTP releases; architecture remains
    # useful inventory but must never become a placement fence.
    valid_runtime_contract?(left) and valid_runtime_contract?(right) and
      runtime_contract(left) == runtime_contract(right)
  end

  @doc """
  Asserts that `target` is connected, running this runtime, and in `expected` role.

  `:any` accepts any role and still requires connectivity and a running runtime. The
  error is a bare reason — `:node_not_connected`, `:runtime_not_running`,
  `{:role, actual, expected}`, or a probe failure — so each caller can name its own
  refusal around it.
  """
  @spec ensure_role(node(), role() | :any) :: :ok | {:error, term()}
  def ensure_role(target, expected)
      when is_atom(target) and (expected in @roles or expected == :any) do
    cond do
      target == node() ->
        check_role(local_posture(), expected)

      target not in Node.list() ->
        {:error, :node_not_connected}

      true ->
        with {:ok, posture} <- probe(target), do: check_role(posture, expected)
    end
  end

  @doc """
  Asserts that agents and workers may be placed on `target`.

  Placement requires a connected `:core` node running a compatible version of this
  runtime, because that is the only role whose tree contains the teams, stores, and
  schedulers a placed worker will reach for. Compatibility is the Ouroboros application
  contract, explicit fleet protocol revision, and OTP release; CPU architecture is
  inventory only and is deliberately not a placement fence. `config :ouroboros,
  :placement_role_check` (default `true`) disables the check for setups that place onto
  nodes this runtime cannot introspect.
  """
  @spec ensure_placeable(node()) :: :ok | {:error, term()}
  def ensure_placeable(target) when is_atom(target) do
    if Application.get_env(:ouroboros, :placement_role_check, true) do
      with {:ok, posture} <- fleet_posture(target),
           :ok <- check_role(posture, :core),
           :ok <- check_runtime_compatibility(posture.runtime) do
        :ok
      end
    else
      :ok
    end
  end

  @doc """
  Returns the configured formation strategy.

  An unrecognized value is an error rather than a silent `:none`, so a typo cannot
  disable clustering on a node that was deployed to cluster.
  """
  @spec strategy() :: {:ok, strategy()} | {:error, term()}
  def strategy do
    case env("OUROBOROS_CLUSTER_STRATEGY") do
      nil ->
        {:ok, :none}

      value ->
        case Enum.find(@strategies, &(Atom.to_string(&1) == value)) do
          nil -> {:error, {:unknown_cluster_strategy, value}}
          strategy -> {:ok, strategy}
        end
    end
  end

  @doc """
  Builds the libcluster topologies this node's environment describes.

  `{:ok, []}` means no formation. Every other strategy either produces a complete
  topology or an error naming the variable it needs.
  """
  @spec topologies() :: {:ok, keyword()} | {:error, term()}
  def topologies do
    with {:ok, strategy} <- strategy(), do: build_topologies(strategy)
  end

  @doc "Reports how distribution on this node is protected, without revealing secrets."
  @spec dist_security() :: map()
  def dist_security do
    proto = proto_dist()

    %{
      distributed: Node.alive?(),
      proto_dist: proto,
      tls: proto in [:inet_tls, :inet6_tls],
      cookie: if(:erlang.get_cookie() == :nocookie, do: :unset, else: :set)
    }
  end

  # `-proto_dist` is an emulator flag, so it is readable from `:init` whether it came
  # from vm.args, ELIXIR_ERL_OPTIONS, or the command line. Absent means the default
  # cleartext TCP distribution.
  defp proto_dist do
    case :init.get_argument(:proto_dist) do
      {:ok, [[value] | _rest]} -> List.to_atom(value)
      _absent -> :inet_tcp
    end
  end

  defp formation_children do
    case topologies() do
      {:ok, []} ->
        []

      {:ok, topologies} ->
        [{Cluster.Supervisor, [topologies, [name: @formation_name]]}]

      {:error, reason} ->
        raise ArgumentError,
              "cluster formation is configured but unusable: #{inspect(reason)}"
    end
  end

  defp build_topologies(:none), do: {:ok, []}

  defp build_topologies(:epmd) do
    case node_list("OUROBOROS_CLUSTER_HOSTS") do
      [] ->
        {:error, {:missing_cluster_configuration, "OUROBOROS_CLUSTER_HOSTS"}}

      hosts ->
        # `timeout` is libcluster's retry interval, not a deadline. Leaving it
        # `:infinity` would attempt connection once, at boot, and a cluster whose
        # members boot in any order would never form.
        {:ok,
         [
           ouroboros: [
             strategy: Cluster.Strategy.Epmd,
             config: [hosts: hosts, timeout: reconnect_interval()]
           ]
         ]}
    end
  end

  defp build_topologies(:gossip) do
    with {:ok, port} <- optional_port("OUROBOROS_CLUSTER_GOSSIP_PORT") do
      config =
        []
        |> put_present(:secret, env("OUROBOROS_CLUSTER_GOSSIP_SECRET"))
        |> put_present(:port, port)

      {:ok, [ouroboros: [strategy: Cluster.Strategy.Gossip, config: config]]}
    end
  end

  defp build_topologies(:dns) do
    with {:ok, query} <- required_env("OUROBOROS_CLUSTER_DNS_QUERY"),
         {:ok, basename} <- dns_basename() do
      {:ok,
       [
         ouroboros: [
           strategy: Cluster.Strategy.DNSPoll,
           config: [
             query: query,
             node_basename: basename,
             polling_interval: reconnect_interval()
           ]
         ]
       ]}
    end
  end

  # DNS polling builds `basename@ip`, so the basename must match what the peers
  # actually registered. Deriving it from this node's own name is right whenever the
  # fleet is homogeneous, which is the case this strategy is for.
  defp dns_basename do
    case env("OUROBOROS_CLUSTER_DNS_BASENAME") do
      nil ->
        case node() |> Atom.to_string() |> String.split("@", parts: 2) do
          [name, _host] when name != "" -> {:ok, name}
          _other -> {:error, {:missing_cluster_configuration, "OUROBOROS_CLUSTER_DNS_BASENAME"}}
        end

      basename ->
        {:ok, basename}
    end
  end

  defp put_present(config, _key, nil), do: config
  defp put_present(config, key, value), do: Keyword.put(config, key, value)

  defp optional_port(name) do
    case env(name) do
      nil ->
        {:ok, nil}

      value ->
        case Integer.parse(value) do
          {port, ""} when port > 0 and port < 65_536 -> {:ok, port}
          _other -> {:error, {:invalid_cluster_configuration, name}}
        end
    end
  end

  defp reconnect_interval do
    case env("OUROBOROS_CLUSTER_RECONNECT_MS") do
      nil ->
        @default_reconnect_ms

      value ->
        case Integer.parse(value) do
          {interval, ""} when interval > 0 -> interval
          _other -> @default_reconnect_ms
        end
    end
  end

  defp required_env(name) do
    case env(name) do
      nil -> {:error, {:missing_cluster_configuration, name}}
      value -> {:ok, value}
    end
  end

  defp node_list(name) do
    (env(name) || "")
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&String.to_atom/1)
  end

  defp env(name) do
    case System.get_env(name) do
      nil -> nil
      value -> if String.trim(value) == "", do: nil, else: String.trim(value)
    end
  end

  defp formation_status do
    strategy =
      case strategy() do
        {:ok, strategy} -> strategy
        {:error, reason} -> {:invalid, reason}
      end

    topologies =
      case topologies() do
        {:ok, topologies} -> Keyword.keys(topologies)
        {:error, _reason} -> []
      end

    %{
      strategy: strategy,
      topologies: topologies,
      supervised: is_pid(Process.whereis(@formation_name))
    }
  end

  defp machine_name do
    case env("OUROBOROS_MACHINE_NAME") do
      value when is_binary(value) -> String.slice(value, 0, 120)
      _absent -> node() |> Atom.to_string() |> String.split("@", parts: 2) |> List.first()
    end
  end

  defp resolve_directory_machine(name, include?) do
    candidates =
      fleet_status().machines
      |> Enum.filter(include?)
      |> Enum.filter(fn machine ->
        Atom.to_string(machine.node) == name or machine.machine == name
      end)
      |> Enum.map(& &1.node)
      |> Enum.uniq()

    case candidates do
      [target] -> {:ok, target}
      [] -> {:error, :unknown_machine}
      targets -> {:error, {:ambiguous_machine, Enum.sort(targets)}}
    end
  end

  defp runtime_identity do
    version =
      case Application.spec(:ouroboros, :vsn) do
        value when is_list(value) -> List.to_string(value)
        value when is_binary(value) -> value
        _unknown -> "unknown"
      end

    %{
      fleet_protocol_revision: @fleet_protocol_revision,
      ouroboros_version: version,
      otp_release: to_string(:erlang.system_info(:otp_release)),
      elixir_version: System.version(),
      system_architecture: to_string(:erlang.system_info(:system_architecture))
    }
  end

  defp check_runtime_compatibility(actual) do
    expected = runtime_identity()

    if runtime_compatible?(actual, expected) do
      :ok
    else
      {:error, {:runtime_incompatible, runtime_contract(actual), runtime_contract(expected)}}
    end
  end

  # Only protocol-relevant values enter a placement refusal. Architecture and Elixir
  # remain useful fleet inventory, while arbitrary values returned by a malformed or
  # hostile peer never get reflected through the gateway error.
  defp runtime_contract(runtime) when is_map(runtime),
    do: Map.take(runtime, @runtime_contract_keys)

  defp valid_runtime_contract?(runtime) do
    revision = Map.get(runtime, :fleet_protocol_revision)

    is_integer(revision) and revision > 0 and
      nonempty_binary?(Map.get(runtime, :ouroboros_version)) and
      nonempty_binary?(Map.get(runtime, :otp_release))
  end

  defp nonempty_binary?(value), do: is_binary(value) and value != ""

  defp fallback_fleet_status do
    now = DateTime.utc_now() |> DateTime.to_iso8601()
    expected = MapSet.new(expected_nodes())
    connected = MapSet.new([node() | Node.list()])

    machines =
      MapSet.union(expected, connected)
      |> Enum.map(fn target ->
        posture =
          case fleet_posture(target) do
            {:ok, value} -> value
            {:error, _reason} -> nil
          end

        %{
          node: target,
          machine:
            if(posture,
              do: posture.machine,
              else: target |> Atom.to_string() |> String.split("@", parts: 2) |> List.first()
            ),
          role: if(posture, do: posture.role, else: :unknown),
          state:
            cond do
              target == node() -> :local
              MapSet.member?(connected, target) -> :connected
              true -> :offline
            end,
          expected?: MapSet.member?(expected, target),
          runtime_running?: if(posture, do: posture.running, else: nil),
          first_seen_at: if(MapSet.member?(connected, target), do: now, else: nil),
          last_seen_at: if(MapSet.member?(connected, target), do: now, else: nil),
          last_up_at: if(MapSet.member?(connected, target), do: now, else: nil),
          last_down_at: nil,
          down_reason: if(MapSet.member?(connected, target), do: nil, else: "not_observed"),
          runtime: if(posture, do: posture.runtime, else: nil),
          compatibility:
            cond do
              target == node() ->
                :local

              posture && runtime_compatible?(posture.runtime, runtime_identity()) ->
                :compatible

              posture ->
                :incompatible

              true ->
                :unknown
            end
        }
      end)
      |> Enum.sort_by(&Atom.to_string(&1.node))

    %{
      local_node: node(),
      generated_at: now,
      monitoring_since: nil,
      summary: %{
        expected: length(machines),
        connected: Enum.count(machines, &(&1.state in [:local, :connected])),
        offline: Enum.count(machines, &(&1.state == :offline)),
        compatible: Enum.count(machines, &(&1.compatibility in [:local, :compatible])),
        incompatible: Enum.count(machines, &(&1.compatibility == :incompatible))
      },
      machines: machines,
      formation: formation(),
      security: dist_security()
    }
  end

  defp doctor_checks(fleet) do
    clustered? = fleet.summary.expected > 1 or fleet.formation.strategy != :none

    checks = [
      doctor_check(
        :distribution,
        if(clustered? and not fleet.security.distributed, do: :error, else: :ok),
        if(fleet.security.distributed,
          do: "BEAM distribution is running",
          else: "BEAM distribution is not running"
        ),
        if(clustered? and not fleet.security.distributed,
          do: "Start this machine through its Ouroboros fleet profile",
          else: nil
        )
      ),
      doctor_check(
        :distribution_encryption,
        cond do
          not clustered? -> :ok
          fleet.security.tls -> :ok
          true -> :error
        end,
        if(fleet.security.tls,
          do: "BEAM distribution is protected with TLS",
          else: "BEAM distribution is using cleartext transport"
        ),
        if(clustered? and not fleet.security.tls,
          do: "Use the generated fleet TLS profile before connecting machines across a network",
          else: nil
        )
      ),
      doctor_check(
        :cluster_cookie,
        if(clustered? and fleet.security.cookie != :set, do: :error, else: :ok),
        if(fleet.security.cookie == :set,
          do: "The distribution credential is loaded",
          else: "The distribution credential is missing"
        ),
        if(clustered? and fleet.security.cookie != :set,
          do: "Re-import or repair this machine's fleet profile",
          else: nil
        )
      ),
      doctor_check(
        :formation_supervisor,
        if(clustered? and not fleet.formation.supervised, do: :error, else: :ok),
        if(fleet.formation.supervised,
          do: "Automatic reconnection is supervised",
          else: "Automatic reconnection is not supervised"
        ),
        if(clustered? and not fleet.formation.supervised,
          do: "Select a discovery strategy and at least one reachable seed machine",
          else: nil
        )
      )
    ]

    machine_checks =
      fleet.machines
      |> Enum.flat_map(fn machine ->
        connectivity =
          doctor_check(
            {:machine_connectivity, machine.node},
            cond do
              machine.state == :local -> :ok
              machine.state == :connected and machine.expected? -> :ok
              machine.state == :connected -> :warning
              machine.expected? -> :error
              true -> :warning
            end,
            cond do
              machine.state == :local ->
                "#{machine.machine} is this machine"

              machine.state == :connected and machine.expected? ->
                "#{machine.machine} is connected"

              machine.state == :connected ->
                "#{machine.machine} is connected but is not in this machine's saved roster"

              machine.state == :offline and machine.expected? ->
                "#{machine.machine} is offline; Ouroboros will keep retrying"

              true ->
                "#{machine.machine} is offline; it was learned from another machine"
            end,
            cond do
              machine.state == :connected and not machine.expected? ->
                "If this is a newly invited member, import the owner's latest signed roster and restart this machine; if it is unexpected, treat the credential as exposed and rotate the fleet"

              machine.state != :offline ->
                nil

              machine.expected? ->
                "Check that Ouroboros is running there and that EPMD and distribution ports are reachable"

              true ->
                "If this machine should remain in the fleet, check it is running and reachable; otherwise its last-known record is informational"
            end,
            machine.node
          )

        compatibility =
          doctor_check(
            {:machine_compatibility, machine.node},
            case machine.compatibility do
              value when value in [:local, :compatible] -> :ok
              :unknown -> :warning
              :incompatible -> :error
            end,
            case machine.compatibility do
              :local ->
                "#{machine.machine} defines the local runtime version"

              :compatible ->
                "#{machine.machine} runs a compatible fleet protocol/Ouroboros/OTP build"

              :unknown ->
                "#{machine.machine}'s runtime compatibility is not known yet"

              :incompatible ->
                "#{machine.machine} runs a different fleet protocol, Ouroboros, or OTP build"
            end,
            if(machine.compatibility == :incompatible,
              do:
                "Install the same Ouroboros build and fleet protocol revision on every machine before placing agents",
              else: nil
            ),
            machine.node
          )

        runtime =
          doctor_check(
            {:machine_runtime, machine.node},
            cond do
              machine.state == :offline -> :warning
              machine.runtime_running? == true -> :ok
              true -> :error
            end,
            if(machine.runtime_running? == true,
              do: "#{machine.machine}'s Ouroboros runtime is running",
              else: "#{machine.machine}'s Ouroboros runtime could not be verified"
            ),
            if(machine.state != :offline and machine.runtime_running? != true,
              do: "Restart Ouroboros on that machine and run fleet doctor again",
              else: nil
            ),
            machine.node
          )

        [connectivity, compatibility, runtime]
      end)

    checks ++ machine_checks
  end

  defp doctor_check(id, status, message, guidance, target \\ nil) do
    %{id: id, status: status, message: message}
    |> maybe_put(:guidance, guidance)
    |> maybe_put(:node, target)
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp group_roles(observed) do
    initial = Map.new(@roles, &{&1, []})

    observed
    |> Enum.reduce(Map.put(initial, :unreachable, []), fn
      {target, %{role: role, running: true}}, acc -> Map.update!(acc, role, &[target | &1])
      {target, _other}, acc -> Map.update!(acc, :unreachable, &[target | &1])
    end)
    |> Map.new(fn {role, nodes} -> {role, Enum.sort(nodes)} end)
  end

  defp postures do
    targets = [node() | Node.list()]

    targets
    |> :erpc.multicall(__MODULE__, :local_posture, [], @probe_timeout)
    |> Enum.zip(targets)
    |> Map.new(fn
      {{:ok, %{role: role, running: running} = posture}, target}
      when role in @roles and is_boolean(running) ->
        {target, posture}

      {other, target} ->
        {target, {:error, other}}
    end)
  end

  defp probe(target) do
    case :erpc.call(target, __MODULE__, :local_posture, [], @probe_timeout) do
      %{role: role, running: running} = posture when role in @roles and is_boolean(running) ->
        {:ok, posture}

      other ->
        {:error, {:invalid_posture, inspect(other)}}
    end
  catch
    # A node without this runtime's code answers `:undef` as an `:erpc` exception, an
    # unreachable one raises `:erpc` errors, and a node mid-shutdown exits. None of
    # those may escape into a caller that is only asking a question.
    kind, reason -> {:error, {:probe_failed, {kind, inspect(reason)}}}
  end

  defp check_role(%{running: false}, _expected), do: {:error, :runtime_not_running}
  defp check_role(%{running: true}, :any), do: :ok
  defp check_role(%{role: role, running: true}, role), do: :ok
  defp check_role(%{role: role}, expected), do: {:error, {:role, role, expected}}
end
