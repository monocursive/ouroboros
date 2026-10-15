defmodule UkaiFleet.Controller do
  @moduledoc "Durable placement identity. An unreachable worker is never replaced."
  use GenServer
  alias UkaiFleet.{InvalidRequest, Protocol, Request, Store, Worker}

  # How long a caller waits for any reply.
  @call_timeout 180_000
  # Remote work stops this long before the caller gives up, leaving time to persist what
  # was observed and to reply.
  @reply_margin 10_000
  # No single worker call waits longer than this, whatever budget remains. The worker
  # bounds its own work by the same timeout (`UkaiFleet.Worker.call/2`).
  @rpc_timeout 125_000
  # Worker calls end by the deadline on their own (`rpc/3`); a status batch still
  # running this long past it is stopped. The margin lets a batch that ended on time,
  # or found no time left, report that itself.
  @batch_grace 1_000

  def start_link(config), do: GenServer.start_link(__MODULE__, config, name: __MODULE__)

  def call(message) do
    # Taken before queueing, so time spent behind another operation counts too.
    deadline = System.monotonic_time(:millisecond) + @call_timeout - @reply_margin
    GenServer.call(__MODULE__, {:call, message, deadline}, @call_timeout)
  end

  def init(config) do
    jobs = Store.directory!(Path.join(config["state"], "jobs"))
    {:ok, Map.put(config, "jobs", jobs)}
  end

  def handle_call({:call, message, deadline}, _from, config) do
    try do
      {:reply, dispatch(message, config, deadline), config}
    rescue
      # Malformed input wrote nothing; refusing it must not restart this node.
      error in InvalidRequest ->
        {:reply, {:error, InvalidRequest.reply(error.message)}, config}

      error ->
        UkaiFleet.Diagnostics.refused(error, __STACKTRACE__)
        {:stop, :normal, {:error, "controller_refused_or_persistence_unknown"}, config}
    end
  end

  defp dispatch({:run, input}, config, deadline) do
    request = Request.validate!(input)
    digest = Store.digest(request)

    key =
      "job_" <>
        String.replace_prefix(
          Store.digest([config["fleet_id"], request["request_id"]]),
          "sha256:",
          ""
        )

    path = checkpoint(config, key)

    case Store.read!(path) do
      %{"request_digest" => existing} when existing != digest ->
        {:error, "request_id_conflict"}

      nil ->
        candidates = Enum.filter(config["members"], &(request["on"] in ["auto", &1["machine"]]))

        plans =
          Enum.map(candidates, &{&1, rpc(&1, {:plan, key, request}, deadline)})

        eligible =
          for {member, {:ok, plan}} <- plans,
              do: {plan["active"], member["machine"], member, plan}

        case Enum.sort(eligible) do
          [] ->
            {:error,
             %{
               "reason" => "no_eligible_worker",
               "nodes" =>
                 Enum.map(plans, fn {member, result} ->
                   %{"machine" => member["machine"], "reason" => reason(result)}
                 end)
             }}

          [{_, _, member, plan} | _] ->
            row =
              Store.write!(path, %{
                "schema" => "ukai.fleet.job/1",
                "job_id" => key,
                "request_id" => request["request_id"],
                "request_digest" => digest,
                "worker" => member,
                "resolved" => plan["resolved"],
                "dir" => plan["workspace"],
                "created_at" => DateTime.to_iso8601(DateTime.utc_now()),
                "snapshot" => nil
              })

            submit(config, row, request, deadline)
        end

      row ->
        submit(config, row, request, deadline)
    end
  end

  defp dispatch({:status, key}, config, deadline) do
    case Store.read!(checkpoint(config, key)) do
      nil -> {:error, "unknown_job"}
      row -> {:ok, observe(config, row, rpc(row["worker"], {:status, key}, deadline))}
    end
  end

  defp dispatch({:kill, key}, config, deadline), do: route(config, key, {:kill, key}, deadline)

  defp dispatch({:ledger, key, flags}, config, deadline),
    do: route(config, key, {:ledger, key, flags}, deadline)

  defp dispatch(:status, config, deadline) do
    paths = Path.wildcard(Path.join(config["jobs"], "job_*.json"))

    if length(paths) > 4096 do
      {:error, "job_catalog_exceeds_bounded_scan"}
    else
      rows = Enum.map(paths, &Store.read!/1)
      groups = Enum.group_by(rows, & &1["worker"]["node"])

      # One status batch per worker rather than one call per job, so a catalog refresh
      # costs what the number of machines costs, not what the history costs. The batches
      # run together, so a slow worker spends its own time and not that of the others.
      replies =
        groups
        |> Task.async_stream(
          fn {_node, [row | _] = group} ->
            statuses(row["worker"], Enum.map(group, & &1["job_id"]), deadline)
          end,
          # Each batch's timeout counts from its own start, so none may wait for a slot.
          max_concurrency: max(map_size(groups), 1),
          timeout: max(deadline - System.monotonic_time(:millisecond), 0) + @batch_grace,
          on_timeout: :kill_task,
          zip_input_on_exit: true
        )
        |> Enum.flat_map(fn
          {:ok, replies} ->
            replies

          # A stopped batch's reply is lost, as `rpc/3` reports a call that timed out.
          {:exit, {{_node, group}, :timeout}} ->
            Enum.map(group, &{&1["job_id"], {:error, "worker_unreachable_or_reply_lost"}})
        end)
        |> Map.new()

      {:ok, Enum.map(rows, &observe(config, &1, replies[&1["job_id"]]))}
    end
  end

  defp dispatch(:doctor, config, deadline) do
    {:ok,
     Enum.map(config["members"], fn member ->
       case rpc(member, :doctor, deadline) do
         {:ok, health} -> Map.merge(health, %{"machine" => member["machine"], "rpc" => "ready"})
         {:error, reason} -> %{"machine" => member["machine"], "rpc" => reason}
       end
     end)}
  end

  defp dispatch(:version, _, _), do: {:ok, Protocol.version()}

  defp dispatch(_, _, _), do: {:error, "unsupported_controller_operation"}

  defp submit(config, row, request, deadline) do
    case rpc(row["worker"], {:submit, row["job_id"], request, row["resolved"]}, deadline) do
      {:ok, snapshot} ->
        remember(config, row, snapshot)

        {:ok,
         Map.merge(snapshot, %{"worker" => row["worker"]["machine"], "job_id" => row["job_id"]})}

      {:error, problem} ->
        {:ok,
         %{
           "job_id" => row["job_id"],
           "worker" => row["worker"]["machine"],
           "admission" => "unconfirmed",
           "settlement" => "unknown",
           "reason" => problem,
           "retry" => "same_request_id_only"
         }}
    end
  end

  # Each key's reply from one worker; a failed batch is that failure for every key. The
  # worker ends its batch in time for the reply to arrive before the call times out.
  defp statuses(member, keys, deadline) do
    replies =
      case rpc(member, {:statuses, keys}, deadline) do
        {:ok, replies} when is_map(replies) -> replies
        {:error, _} = failure -> Map.new(keys, &{&1, failure})
        _ -> %{}
      end

    Enum.map(keys, &{&1, Map.get(replies, &1, {:error, "worker_reply_incomplete"})})
  end

  defp observe(config, row, {:ok, snapshot}) do
    remember(config, row, snapshot)
    Map.merge(snapshot, %{"worker" => row["worker"]["machine"], "stale" => false})
  end

  defp observe(_config, row, {:error, problem}) do
    %{
      "job_id" => row["job_id"],
      "worker" => row["worker"]["machine"],
      "reachability" => "unreachable",
      "stale" => true,
      "reason" => problem,
      "last_observed" => row["snapshot"]
    }
  end

  # An unchanged snapshot is already durable. Rewriting it would cost two fsyncs (file
  # and directory) per job on every status call.
  defp remember(config, row, snapshot) do
    if snapshot != row["snapshot"],
      do: Store.write!(checkpoint(config, row["job_id"]), Map.put(row, "snapshot", snapshot))
  end

  defp route(config, key, message, deadline) do
    case Store.read!(checkpoint(config, key)) do
      nil -> {:error, "unknown_job"}
      row -> rpc(row["worker"], message, deadline)
    end
  end

  defp checkpoint(config, key) do
    if not Request.job?(key), do: Request.invalid!("invalid job id")
    Path.join(config["jobs"], key <> ".json")
  end

  defp reason({:ok, _}), do: "ready"
  defp reason({:error, reason}), do: reason

  defp rpc(member, message, deadline) do
    # Node atoms come only from bounded operator-owned membership, never a job.
    remote = String.to_atom(member["node"])

    # Each call waits only for what is left of the caller's budget. A call the budget
    # cannot cover is not made, and is reported as not made.
    call = fn operation ->
      case min(deadline - System.monotonic_time(:millisecond), @rpc_timeout) do
        left when left <= 0 -> throw(:budget_exhausted)
        left when remote == node() -> Worker.call(operation, left)
        left -> :erpc.call(remote, Worker, :call, [operation, left], left)
      end
    end

    if Protocol.compatible?(call.(:version)),
      do: call.(message),
      else: {:error, "worker_schema_mismatch"}
  catch
    :throw, :budget_exhausted -> {:error, "controller_budget_exhausted"}
    _, _ -> {:error, "worker_unreachable_or_reply_lost"}
  end
end
