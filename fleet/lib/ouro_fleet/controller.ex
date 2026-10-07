defmodule OuroFleet.Controller do
  @moduledoc "Durable placement identity. An unreachable worker is never replaced."
  use GenServer
  alias OuroFleet.{Request, Store, Worker}
  def start_link(config), do: GenServer.start_link(__MODULE__, config, name: __MODULE__)
  def call(message), do: GenServer.call(__MODULE__, message, 180_000)

  def init(config) do
    jobs = Store.directory!(Path.join(config["state"], "jobs"))
    {:ok, Map.put(config, "jobs", jobs)}
  end

  def handle_call(message, _from, config) do
    try do
      {:reply, dispatch(message, config), config}
    rescue
      error ->
        OuroFleet.Diagnostics.refused(error, __STACKTRACE__)
        {:stop, :normal, {:error, "controller_refused_or_persistence_unknown"}, config}
    end
  end

  defp dispatch({:run, input}, config) do
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
          Enum.map(candidates, fn member -> {member, rpc(member, {:plan, key, request})} end)

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
                "schema" => "ouro.fleet.job/1",
                "job_id" => key,
                "request_id" => request["request_id"],
                "request_digest" => digest,
                "worker" => member,
                "resolved" => plan["resolved"],
                "dir" => plan["workspace"],
                "created_at" => DateTime.to_iso8601(DateTime.utc_now()),
                "snapshot" => nil
              })

            submit(config, row, request)
        end

      row ->
        submit(config, row, request)
    end
  end

  defp dispatch({:status, key}, config) do
    row = Store.read!(checkpoint(config, key))
    if is_nil(row), do: {:error, "unknown_job"}, else: refresh(config, row)
  end

  defp dispatch({:kill, key}, config), do: route(config, key, {:kill, key})
  defp dispatch({:ledger, key, flags}, config), do: route(config, key, {:ledger, key, flags})

  defp dispatch(:status, config) do
    jobs = Path.wildcard(Path.join(config["jobs"], "job_*.json"))
    if length(jobs) > 4096, do: raise("job catalog exceeds bounded scan")

    {:ok,
     Enum.map(jobs, fn path ->
       {:ok, status} = refresh(config, Store.read!(path))
       status
     end)}
  end

  defp dispatch(:doctor, config) do
    {:ok,
     Enum.map(config["members"], fn member ->
       case rpc(member, :doctor) do
         {:ok, health} -> Map.merge(health, %{"machine" => member["machine"], "rpc" => "ready"})
         {:error, reason} -> %{"machine" => member["machine"], "rpc" => reason}
       end
     end)}
  end

  defp dispatch(:version, _),
    do: {:ok, %{"schema" => "ouro.fleet.rpc/1", "run" => "ouro.ledger.run/1"}}

  defp dispatch(_, _), do: {:error, "unsupported_controller_operation"}

  defp submit(config, row, request) do
    case rpc(row["worker"], {:submit, row["job_id"], request, row["resolved"]}) do
      {:ok, snapshot} ->
        Store.write!(checkpoint(config, row["job_id"]), Map.put(row, "snapshot", snapshot))

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

  defp refresh(config, row) do
    case rpc(row["worker"], {:status, row["job_id"]}) do
      {:ok, snapshot} ->
        Store.write!(checkpoint(config, row["job_id"]), Map.put(row, "snapshot", snapshot))
        {:ok, Map.merge(snapshot, %{"worker" => row["worker"]["machine"], "stale" => false})}

      {:error, problem} ->
        {:ok,
         %{
           "job_id" => row["job_id"],
           "worker" => row["worker"]["machine"],
           "reachability" => "unreachable",
           "stale" => true,
           "reason" => problem,
           "last_observed" => row["snapshot"]
         }}
    end
  end

  defp route(config, key, message) do
    case Store.read!(checkpoint(config, key)) do
      nil -> {:error, "unknown_job"}
      row -> rpc(row["worker"], message)
    end
  end

  defp checkpoint(config, key) do
    if not Regex.match?(~r/^job_[0-9a-f]{64}$/, key), do: raise("invalid job id")
    Path.join(config["jobs"], key <> ".json")
  end

  defp reason({:ok, _}), do: "ready"
  defp reason({:error, reason}), do: reason

  def rpc(member, message) do
    # Node atoms come only from bounded operator-owned membership, never a job.
    remote = String.to_atom(member["node"])

    call = fn operation ->
      if remote == node(),
        do: Worker.call(operation),
        else: :erpc.call(remote, Worker, :call, [operation], 125_000)
    end

    with {:ok, %{"schema" => "ouro.fleet.rpc/1", "run" => "ouro.ledger.run/1"}} <- call.(:version) do
      if message == :version, do: call.(:version), else: call.(message)
    else
      _ -> {:error, "worker_schema_mismatch"}
    end
  catch
    _, _ -> {:error, "worker_unreachable_or_reply_lost"}
  end
end
