defmodule OuroFleet.Worker do
  @moduledoc "Worker reservations route to Rust; only the Rust owner can launch or settle."
  use GenServer
  alias OuroFleet.{Command, InvalidRequest, Protocol, Reader, Request, Store}

  # States the ledger never leaves: it refuses every transition out of them.
  @terminal ["settled", "denied", "outcome_unknown"]
  # The longest any one ledger subprocess may run.
  @command_timeout 60_000

  def start_link(config), do: GenServer.start_link(__MODULE__, config, name: __MODULE__)
  def call(message, timeout \\ 120_000), do: GenServer.call(__MODULE__, message, timeout)

  def init(config) do
    path = Store.directory!(Path.join(config["state"], "attempts"))
    scratch = Store.directory!(Path.join(config["state"], "scratch"))
    # Job ids whose run this process has seen terminal. Private to this process and
    # rebuilt by the first scan after a restart.
    terminal = :ets.new(__MODULE__, [:set, :private])
    state = %{"attempts" => path, "scratch" => scratch, "terminal" => terminal}
    {:ok, Map.merge(config, state), {:continue, :reconcile}}
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
      # Malformed input wrote nothing; refusing it must not restart this node.
      error in InvalidRequest ->
        {:reply, {:error, InvalidRequest.reply(error.message)}, config}

      error ->
        OuroFleet.Diagnostics.refused(error, __STACKTRACE__)
        {:stop, :normal, {:error, "worker_refused_or_persistence_unknown"}, config}
    end
  end

  defp dispatch(:version, _), do: {:ok, Protocol.version()}

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
         true <- version["schemas"]["run"] == Protocol.ledger_run(),
         {:ok, doctor, 0} <- command(config, ["doctor", "--json"]),
         true <- doctor["ready"] and doctor["detached_owner"]["available"],
         {:ok, label, 0} <-
           Command.raw(
             config["jail_bin"],
             ["run"] ++
               Request.policy(request, workspace) ++ ["--label-only", "--"] ++ request["argv"]
           ),
         {:ok, resolved, 0} <- launch_command(config, key, request, workspace, ["--plan-only"]),
         {:ok, active} <- active(config) do
      {:ok,
       %{
         "resolved" => resolved,
         "workspace" => workspace,
         "label" => label,
         "active" => active
       }}
    else
      {:error, "attempt_catalog_exceeds_bounded_scan"} = refused -> refused
      _ -> {:error, "worker_required_capability_unavailable"}
    end
  end

  defp dispatch({:submit, key, request, expected}, config) do
    request = Request.validate!(request)
    path = checkpoint(config, key)
    digest = Store.digest(request)
    old = Store.read!(path)

    if old && (old["request_digest"] != digest or old["resolved"] != expected) do
      # A different request or plan already holds this job id. Nothing is written or
      # started for this one, so refusing it must not restart the node.
      {:error, "reservation_conflict"}
    else
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

      prepare_and_launch(config, key, request, workspace, record)
    end
  end

  defp dispatch({:status, key}, config), do: statuses(config, [key], :infinity)[key]

  # `budget` is how long, from now, the caller can still use a reply. The caller keeps
  # its own margin for the reply's trip back.
  defp dispatch({:statuses, keys, budget}, config) when is_integer(budget) do
    if not is_list(keys) or length(keys) > 4096, do: Request.invalid!("invalid job batch")
    {:ok, statuses(config, keys, System.monotonic_time(:millisecond) + budget)}
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

  # Persist the run cross-reference before any owner start. On a lost reply, retry this
  # deterministic ledger request, never allocate another attempt.
  defp prepare_and_launch(config, key, request, workspace, record) do
    expected = record["resolved"]
    preparation = ["--prepare-only"]

    with {:ok, resolved, 0} <- launch_command(config, key, request, workspace, ["--plan-only"]),
         true <- resolved == expected,
         {:ok, prepared, 0} <- launch_command(config, key, request, workspace, preparation),
         true <- prepared["payload"] == expected,
         true <- is_nil(record["run_id"]) or record["run_id"] == prepared["run_id"] do
      record =
        Store.write!(
          checkpoint(config, key),
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

  # One `settle-orphans` for the whole batch, then one `show` per started run, each
  # bounded by what is left before `deadline`. A job the budget does not reach is
  # reported as not read, never given a state.
  defp statuses(config, keys, deadline) do
    records = Map.new(keys, &{&1, reservation(config, &1)})

    if Enum.any?(Map.values(records), &match?(%{"run_id" => run} when not is_nil(run), &1)),
      do: bounded(config, ["settle-orphans", "--json"], deadline)

    Map.new(records, fn {key, record} -> {key, status(config, key, record, deadline)} end)
  end

  defp reservation(config, key),
    do: if(Request.job?(key), do: Store.read!(checkpoint(config, key)), else: :invalid)

  defp status(_config, _key, :invalid, _deadline),
    do: {:error, InvalidRequest.reply("invalid job id")}

  defp status(_config, _key, nil, _deadline), do: {:error, "attempt_not_reserved"}

  defp status(_config, _key, %{"run_id" => nil} = record, _deadline) do
    {:ok,
     Map.merge(record, %{
       "state" => "prepared",
       "settlement" => "pending",
       "reachability" => "reachable"
     })}
  end

  defp status(config, key, record, deadline) do
    case show(config, key, record["run_id"], deadline) do
      {:ok, run} -> {:ok, render(record, run)}
      :exhausted -> {:error, "status_budget_exhausted"}
      _ -> {:error, "ledger_unavailable_outcome_unknown"}
    end
  end

  # Attempts that may still be running. A run once seen terminal is not read again, so
  # a plan reads the ledger for live and unknown attempts rather than for all history.
  # An attempt the ledger does not answer for counts as active.
  defp active(config) do
    attempts = Path.wildcard(Path.join(config["attempts"], "job_*.json"))

    if length(attempts) > 4096 do
      {:error, "attempt_catalog_exceeds_bounded_scan"}
    else
      {:ok,
       Enum.count(attempts, fn path ->
         key = Path.basename(path, ".json")
         not :ets.member(config["terminal"], key) and live?(config, key, path)
       end)}
    end
  end

  defp live?(config, key, path) do
    case Store.read!(path) do
      %{"run_id" => run} when is_binary(run) ->
        case show(config, key, run, :infinity) do
          {:ok, row} -> row["state"] not in @terminal
          _ -> true
        end

      _ ->
        true
    end
  end

  # One ledger read of a run. A terminal state is remembered for `active/1`.
  defp show(config, key, run, deadline) do
    with {:ok, row, 0} <- bounded(config, ["show", run, "--json"], deadline) do
      if row["state"] in @terminal, do: :ets.insert(config["terminal"], {key})
      {:ok, row}
    end
  end

  defp bounded(config, args, :infinity), do: command(config, args)

  defp bounded(config, args, deadline) do
    case deadline - System.monotonic_time(:millisecond) do
      left when left > 0 -> command(config, args, min(left, @command_timeout))
      _ -> :exhausted
    end
  end

  defp checkpoint(config, key) do
    if not Request.job?(key), do: Request.invalid!("invalid job id")
    Path.join(config["attempts"], key <> ".json")
  end

  defp workspace!(key, request, config) do
    checkpoint(config, key)

    if request["dir"] do
      if not File.dir?(request["dir"]), do: Request.invalid!("workspace missing")
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

  defp command(config, args, timeout \\ @command_timeout),
    do: Command.json(config["ledger_bin"], ["--data-dir", config["data"] | args], timeout)

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
