defmodule OuroFleet.Worker do
  @moduledoc "Worker reservations route to Rust; only the Rust owner can launch or settle."
  use GenServer
  alias OuroFleet.{Command, Reader, Request, Store}
  def start_link(config), do: GenServer.start_link(__MODULE__, config, name: __MODULE__)
  def call(message), do: GenServer.call(__MODULE__, message, 120_000)

  def init(config) do
    path = Store.directory!(Path.join(config["state"], "attempts"))
    scratch = Store.directory!(Path.join(config["state"], "scratch"))
    {:ok, Map.merge(config, %{"attempts" => path, "scratch" => scratch}), {:continue, :reconcile}}
  end

  def handle_continue(:reconcile, config) do
    # Starting an independent writer is explicit worker provisioning. A failed
    # restart does not turn its attempts into failed jobs or authorize replay.
    command(config, ["serve", "--detach"])
    command(config, ["settle-orphans", "--json"])
    {:noreply, config}
  end

  def handle_call(message, _from, config) do
    try do
      {:reply, dispatch(message, config), config}
    rescue
      error ->
        OuroFleet.Diagnostics.refused(error, __STACKTRACE__)
        {:stop, :normal, {:error, "worker_refused_or_persistence_unknown"}, config}
    end
  end

  defp dispatch(:version, _),
    do: {:ok, %{"schema" => "ouro.fleet.rpc/1", "run" => "ouro.ledger.run/1"}}

  defp dispatch(:doctor, config) do
    with {:ok, ledger, 0} <- command(config, ["doctor", "--json"]),
         {:ok, jail, _} <- Command.json(config["jail_bin"], ["doctor", "--json"]) do
      {:ok,
       %{
         "ledger" => ledger,
         "jail" => jail,
         "detached_ready" =>
           ledger["ready"] == true and ledger["detached_owner"]["available"] == true,
         "eligibility" => "rechecked_for_each_resolved_request"
       }}
    else
      _ -> {:error, "worker_components_unavailable"}
    end
  end

  defp dispatch({:plan, key, request}, config) do
    request = Request.validate!(request)
    workspace = workspace!(key, request, config)

    with {:ok, version, 0} <- Command.json(config["ledger_bin"], ["version", "--json"]),
         true <- version["schemas"]["run"] == "ouro.ledger.run/1",
         {:ok, doctor, 0} <- command(config, ["doctor", "--json"]),
         true <- doctor["ready"] and doctor["detached_owner"]["available"],
         {:ok, label, 0} <-
           Command.raw(
             config["jail_bin"],
             ["run"] ++
               Request.policy(request, workspace) ++ ["--label-only", "--"] ++ request["argv"]
           ),
         {:ok, resolved, 0} <- launch_command(config, key, request, workspace, ["--plan-only"]) do
      {:ok,
       %{
         "resolved" => resolved,
         "workspace" => workspace,
         "label" => label,
         "active" => active(config)
       }}
    else
      _ -> {:error, "worker_required_capability_unavailable"}
    end
  end

  defp dispatch({:submit, key, request, expected}, config) do
    request = Request.validate!(request)
    path = checkpoint(config, key)
    digest = Store.digest(request)
    old = Store.read!(path)

    if old && (old["request_digest"] != digest or old["resolved"] != expected),
      do: raise("reservation conflict")

    workspace = workspace!(key, request, config)

    record =
      old ||
        Store.write!(path, %{
          "schema" => "ouro.fleet.attempt/1",
          "job_id" => key,
          "request_digest" => digest,
          "resolved" => expected,
          "run_id" => nil,
          "workspace" => workspace
        })

    # Persist the run cross-reference before any owner start. On a lost reply,
    # retry this deterministic ledger request, never allocate another attempt.
    with {:ok, resolved, 0} <- launch_command(config, key, request, workspace, ["--plan-only"]),
         true <- resolved == expected,
         {:ok, prepared, 0} <- launch_command(config, key, request, workspace, ["--prepare-only"]),
         true <- prepared["payload"] == expected,
         true <- is_nil(record["run_id"]) or record["run_id"] == prepared["run_id"] do
      record =
        Store.write!(
          path,
          Map.merge(record, %{
            "run_id" => prepared["run_id"],
            "attempt_id" => prepared["attempt_id"]
          })
        )

      case launch_command(config, key, request, workspace, ["--prepared", record["run_id"]]) do
        {:ok, run, 0} -> {:ok, render(record, run)}
        _ -> {:error, "launch_reply_unknown_retry_same_request"}
      end
    else
      _ -> {:error, "prepared_request_conflict_or_unknown"}
    end
  end

  defp dispatch({:status, key}, config) do
    case Store.read!(checkpoint(config, key)) do
      nil ->
        {:error, "attempt_not_reserved"}

      %{"run_id" => nil} = record ->
        {:ok,
         Map.merge(record, %{
           "state" => "prepared",
           "settlement" => "pending",
           "reachability" => "reachable"
         })}

      record ->
        command(config, ["settle-orphans", "--json"])

        case command(config, ["show", record["run_id"], "--json"]) do
          {:ok, run, 0} -> {:ok, render(record, run)}
          _ -> {:error, "ledger_unavailable_outcome_unknown"}
        end
    end
  end

  defp dispatch({:kill, key}, config) do
    with %{"run_id" => run} when is_binary(run) <- Store.read!(checkpoint(config, key)),
         {:ok, result, 0} <- command(config, ["cancel", run, "--json"]) do
      {:ok, result}
    else
      _ -> {:error, "cancel_unconfirmed"}
    end
  end

  defp dispatch({:ledger, key, flags}, config) do
    # Read-only routed verbs; no arbitrary subprocess or writer mutation here.
    with %{"run_id" => run} when is_binary(run) <- Store.read!(checkpoint(config, key)),
         {:ok, args} <- Reader.args(run, flags) do
      case command(config, args) do
        {:ok, result, code} -> {:ok, %{"result" => result, "exit_code" => code}}
        _ -> {:error, "reader_unavailable"}
      end
    else
      _ -> {:error, "invalid_reader"}
    end
  end

  defp dispatch(_, _), do: {:error, "unsupported_worker_operation"}

  defp active(config) do
    attempts = Path.wildcard(Path.join(config["attempts"], "job_*.json"))
    if length(attempts) > 4096, do: raise("attempt catalog exceeds bounded scan")

    attempts
    |> Enum.count(fn path ->
      case Store.read!(path) do
        %{"run_id" => run} when is_binary(run) ->
          case command(config, ["show", run, "--json"]) do
            {:ok, row, 0} -> row["state"] not in ["settled", "denied", "outcome_unknown"]
            _ -> true
          end

        _ ->
          true
      end
    end)
  end

  defp checkpoint(config, key) do
    if not Regex.match?(~r/^job_[0-9a-f]{64}$/, key), do: raise("invalid job id")
    Path.join(config["attempts"], key <> ".json")
  end

  defp workspace!(key, request, config) do
    checkpoint(config, key)

    if request["dir"] do
      if not File.dir?(request["dir"]), do: raise("workspace missing")
      request["dir"]
    else
      Store.directory!(Path.join(config["scratch"], key))
    end
  end

  defp launch_command(config, key, request, workspace, extra),
    do:
      Command.json(
        config["ledger_bin"],
        Request.ledger(request, workspace, config, key) ++ extra ++ ["--"] ++ request["argv"]
      )

  defp command(config, args),
    do: Command.json(config["ledger_bin"], ["--data-dir", config["data"] | args])

  def render(record, run) do
    Map.merge(record, %{
      "attempt_id" => run["attempt_id"],
      "owner" => run["owner"],
      "state" => execution_state(run),
      "ledger_state" => run["state"],
      "settlement" =>
        if(run["state"] == "outcome_unknown", do: "unknown", else: run["settlement"]),
      "ledger_settlement" => run["settlement"],
      "outcome" => run["outcome"],
      "child_protection" => run["child_protection"],
      "capture" => run["capture"],
      "coverage" => run["coverage"],
      "state_cleanup" => cleanup(run),
      "reachability" => "reachable",
      "evidence_health" =>
        if(run["state"] == "outcome_unknown" or degraded?(run["coverage"]),
          do: "degraded",
          else: "ok"
        )
    })
  end

  defp degraded?(map) when is_map(map),
    do:
      map["status"] in ["degraded", "poisoned"] or (is_list(map["gaps"]) and map["gaps"] != []) or
        Enum.any?(Map.values(map), &degraded?/1)

  defp degraded?(list) when is_list(list), do: Enum.any?(list, &degraded?/1)
  defp degraded?(_), do: false

  defp cleanup(run), do: (List.last(run["receipts"] || []) || %{})["state_cleanup"] || "pending"

  def execution_state(%{"state" => "prepared", "owner" => nil}), do: "prepared"
  def execution_state(%{"state" => "prepared"}), do: "starting"
  def execution_state(%{"state" => "admitted"}), do: "running"
  def execution_state(%{"state" => "denied"}), do: "refused"
  def execution_state(%{"state" => "settled", "outcome" => %{"kind" => "signaled"}}), do: "killed"
  def execution_state(%{"state" => "settled"}), do: "exited"
  def execution_state(_), do: "outcome_unknown"
end
