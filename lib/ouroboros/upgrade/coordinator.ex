defmodule Ouroboros.Upgrade.Coordinator do
  @moduledoc """
  Best-effort orchestration for deploying one verified artifact to explicit nodes.

  The coordinator prepares every node in parallel, commits every prepared node in
  parallel, and compensates failures with `abort/1` or `rollback/2`. This is not a
  distributed transaction: a node or network can fail after loading code but before
  returning its receipt. Such an ambiguous node is reported as quarantined and is
  never claimed to have rolled back.

  `deploy/3` accepts these coordinator options:

    * `:migrations` - a map of node names to node-local migration lists
    * `:health_check` - an optional `{module, function, arguments}` run on every node
    * `:health_expected` - an exact expected health result; absent means `:ok`,
      `true`, and `{:ok, _}` are healthy
    * `:max_concurrency` - maximum simultaneous node operations
    * `:prepare_timeout`, `:commit_timeout`, `:rollback_timeout`,
      `:promote_timeout`, `:health_timeout`, `:status_timeout`, and `:abort_timeout`

  The artifact itself is verified by each node's policy-protected `NodeExecutor`.
  Durable, reboot-persistent upgrades still require OTP release handling rather than
  this in-memory patch lane.
  """

  alias Ouroboros.Upgrade.{Artifact, NodeExecutor}

  defmodule NodeReceipt do
    @moduledoc "Per-node evidence for a coordinated deployment."

    @enforce_keys [:node]
    defstruct node: nil,
              prepare: :pending,
              token: nil,
              commit: :pending,
              executor_receipt: nil,
              health: :not_run,
              recovery: :not_needed,
              error: nil
  end

  defmodule DeploymentReceipt do
    @moduledoc "Evidence and compensation status for a best-effort deployment."

    @enforce_keys [:id, :artifact_id, :epoch, :nodes, :node_receipts, :started_at]
    defstruct id: nil,
              artifact_id: nil,
              epoch: nil,
              nodes: [],
              node_receipts: %{},
              outcome: :pending,
              recovery: :not_needed,
              atomic?: false,
              started_at: nil,
              finished_at: nil
  end

  @type node_name :: node()
  @type deployment_result ::
          {:ok, DeploymentReceipt.t()} | {:error, DeploymentReceipt.t()}

  @doc "Deploys an artifact to an explicit list of currently connected nodes."
  @spec deploy(Artifact.t(), [node_name()], keyword()) :: deployment_result()
  def deploy(artifact, nodes, opts \\ [])

  def deploy(%Artifact{} = artifact, nodes, opts) when is_list(opts) do
    receipt = new_receipt(artifact, nodes)

    with :ok <- validate_options(opts, :deploy),
         {:ok, nodes} <- validate_nodes(nodes),
         :ok <- validate_health_check(Keyword.get(opts, :health_check)) do
      receipt = %{receipt | nodes: nodes, node_receipts: initial_node_receipts(nodes)}
      prepared = prepare_all(receipt, artifact, opts)

      if all_prepared?(prepared) do
        committed = commit_all(prepared, opts)

        if all_committed?(committed) do
          finish_health_phase(committed, opts)
        else
          committed
          |> compensate_commit_failure(opts)
          |> finish_error(:commit_failed)
        end
      else
        prepared
        |> abort_prepared(opts)
        |> finish_error(:prepare_failed)
      end
    else
      {:error, reason} -> finish_validation_error(receipt, reason)
    end
  end

  def deploy(%Artifact{} = artifact, nodes, _opts) do
    artifact
    |> new_receipt(nodes)
    |> finish_validation_error(:invalid_options)
  end

  @doc "Rolls back every still-retained node-local executor receipt in parallel."
  @spec rollback(DeploymentReceipt.t(), keyword()) :: deployment_result()
  def rollback(receipt, opts \\ [])

  def rollback(%DeploymentReceipt{} = receipt, opts) when is_list(opts) do
    with :ok <- validate_options(opts, :rollback),
         :ok <- ensure_executor_receipts(receipt, :rollback) do
      updated = rollback_committed(receipt, opts)

      if retained_executor_receipts?(updated) or quarantined?(updated) do
        {:error, finish(updated, :rollback_failed, recovery_outcome(updated))}
      else
        {:ok, finish(updated, :rolled_back, :complete)}
      end
    else
      {:error, :rollback_unavailable} ->
        {:error, finish(receipt, :rollback_unavailable, :not_available)}

      {:error, reason} ->
        finish_validation_error(receipt, reason)
    end
  end

  def rollback(%DeploymentReceipt{} = receipt, _opts) do
    finish_validation_error(receipt, :invalid_options)
  end

  @doc "Soft-purges retired versions on all committed nodes, giving up fast rollback."
  @spec promote(DeploymentReceipt.t(), keyword()) :: deployment_result()
  def promote(receipt, opts \\ [])

  def promote(%DeploymentReceipt{} = receipt, opts) when is_list(opts) do
    with :ok <- validate_options(opts, :promote),
         :ok <- ensure_executor_receipts(receipt, :promote) do
      nodes = nodes_with_executor_receipts(receipt)

      results =
        parallel(nodes, opts, :promote, fn target ->
          node_receipt = Map.fetch!(receipt.node_receipts, target)

          rpc(
            target,
            NodeExecutor,
            :promote,
            [node_receipt.executor_receipt],
            timeout(opts, :promote)
          )
        end)

      updated =
        Enum.reduce(results, receipt, fn {target, result}, acc ->
          update_node(acc, target, fn node_receipt ->
            apply_promote_result(node_receipt, result)
          end)
        end)

      finish_promotion(updated)
    else
      {:error, :promote_unavailable} ->
        {:error, finish(receipt, :promotion_unavailable, :not_available)}

      {:error, reason} ->
        finish_validation_error(receipt, reason)
    end
  end

  def promote(%DeploymentReceipt{} = receipt, _opts) do
    finish_validation_error(receipt, :invalid_options)
  end

  @doc "Returns node-local executor status for explicit connected nodes."
  @spec status([node_name()] | DeploymentReceipt.t(), keyword()) ::
          {:ok, %{node_name() => map()}} | {:error, %{node_name() => term()}}
  def status(nodes_or_receipt, opts \\ [])

  def status(%DeploymentReceipt{nodes: nodes}, opts), do: status(nodes, opts)

  def status(nodes, opts) when is_list(nodes) and is_list(opts) do
    with :ok <- validate_options(opts, :status),
         {:ok, nodes} <- validate_nodes(nodes) do
      results =
        parallel(nodes, opts, :status, fn target ->
          rpc(target, NodeExecutor, :status, [], timeout(opts, :status))
        end)

      statuses =
        Map.new(results, fn
          {target, {:ok, status}} when is_map(status) -> {target, status}
          {target, {:ok, unexpected}} -> {target, {:error, {:unexpected_result, unexpected}}}
          {target, {:transport_error, reason}} -> {target, {:error, {:transport, reason}}}
        end)

      if Enum.all?(statuses, fn {_target, value} -> is_map(value) end) do
        {:ok, statuses}
      else
        {:error, statuses}
      end
    else
      {:error, reason} -> {:error, %{coordinator: reason}}
    end
  end

  def status(_nodes, _opts), do: {:error, %{coordinator: :invalid_options}}

  defp new_receipt(artifact, nodes) do
    %DeploymentReceipt{
      id: Jido.Signal.ID.generate!(),
      artifact_id: artifact.id,
      epoch: artifact.epoch,
      nodes: if(is_list(nodes), do: nodes, else: []),
      node_receipts: if(is_list(nodes), do: initial_node_receipts(nodes), else: %{}),
      started_at: now()
    }
  end

  defp initial_node_receipts(nodes) do
    Map.new(nodes, &{&1, %NodeReceipt{node: &1}})
  end

  defp prepare_all(receipt, artifact, opts) do
    results =
      parallel(receipt.nodes, opts, :prepare, fn target ->
        prepare_opts =
          opts
          |> Keyword.get(:prepare_options, [])
          |> Keyword.put(:migrations, migrations_for(opts, target))
          |> Keyword.put(:timeout, timeout(opts, :prepare))

        rpc(
          target,
          NodeExecutor,
          :prepare,
          [artifact, prepare_opts],
          timeout(opts, :prepare)
        )
      end)

    Enum.reduce(results, receipt, fn {target, result}, acc ->
      update_node(acc, target, fn node_receipt -> apply_prepare_result(node_receipt, result) end)
    end)
  end

  defp apply_prepare_result(node_receipt, {:ok, {:ok, token}}) when is_binary(token) do
    %{node_receipt | prepare: :prepared, token: token}
  end

  defp apply_prepare_result(node_receipt, {:ok, {:error, reason}}) do
    %{node_receipt | prepare: :failed, recovery: :unchanged, error: {:prepare, reason}}
  end

  defp apply_prepare_result(node_receipt, {:ok, unexpected}) do
    %{
      node_receipt
      | prepare: :unknown,
        recovery: :quarantined,
        error: {:prepare, {:unexpected_result, unexpected}}
    }
  end

  defp apply_prepare_result(node_receipt, {:transport_error, reason}) do
    %{
      node_receipt
      | prepare: :unknown,
        recovery: :quarantined,
        error: {:prepare, {:transport, reason}}
    }
  end

  defp commit_all(receipt, opts) do
    results =
      parallel(receipt.nodes, opts, :commit, fn target ->
        node_receipt = Map.fetch!(receipt.node_receipts, target)

        commit_opts =
          Keyword.put(Keyword.get(opts, :commit_options, []), :timeout, timeout(opts, :commit))

        rpc(
          target,
          NodeExecutor,
          :commit,
          [node_receipt.token, commit_opts],
          timeout(opts, :commit)
        )
      end)

    Enum.reduce(results, receipt, fn {target, result}, acc ->
      update_node(acc, target, fn node_receipt -> apply_commit_result(node_receipt, result) end)
    end)
  end

  defp apply_commit_result(node_receipt, {:ok, {:ok, %NodeExecutor.Receipt{} = executor_receipt}}) do
    %{
      node_receipt
      | commit: :committed,
        token: nil,
        executor_receipt: executor_receipt,
        recovery: :not_needed
    }
  end

  defp apply_commit_result(node_receipt, {:ok, {:error, reason, recovery}}) do
    %{
      node_receipt
      | commit: :failed,
        token: nil,
        recovery: recovery,
        error: {:commit, reason}
    }
  end

  defp apply_commit_result(node_receipt, {:ok, unexpected}) do
    %{
      node_receipt
      | commit: :unknown,
        recovery: :quarantined,
        error: {:commit, {:unexpected_result, unexpected}}
    }
  end

  defp apply_commit_result(node_receipt, {:transport_error, reason}) do
    %{
      node_receipt
      | commit: :unknown,
        recovery: :quarantined,
        error: {:commit, {:transport, reason}}
    }
  end

  defp finish_health_phase(receipt, opts) do
    case Keyword.get(opts, :health_check) do
      nil ->
        {:ok, finish(receipt, :committed, :not_needed)}

      {module, function, arguments} ->
        results =
          parallel(receipt.nodes, opts, :health, fn target ->
            rpc(target, module, function, arguments, timeout(opts, :health))
          end)

        checked =
          Enum.reduce(results, receipt, fn {target, result}, acc ->
            update_node(acc, target, fn node_receipt ->
              apply_health_result(node_receipt, result, opts)
            end)
          end)

        if all_healthy?(checked) do
          {:ok, finish(checked, :committed, :not_needed)}
        else
          checked
          |> rollback_committed(opts)
          |> finish_error(:health_failed)
        end
    end
  end

  defp apply_health_result(node_receipt, {:ok, result}, opts) do
    if healthy_result?(result, opts) do
      %{node_receipt | health: {:passed, result}}
    else
      %{node_receipt | health: {:failed, result}, error: {:health, result}}
    end
  end

  defp apply_health_result(node_receipt, {:transport_error, reason}, _opts) do
    %{
      node_receipt
      | health: :unknown,
        error: {:health, {:transport, reason}}
    }
  end

  defp healthy_result?(result, opts) do
    if Keyword.has_key?(opts, :health_expected) do
      result == Keyword.fetch!(opts, :health_expected)
    else
      result == :ok or result == true or match?({:ok, _}, result)
    end
  end

  defp compensate_commit_failure(receipt, opts) do
    receipt
    |> rollback_committed(opts)
    |> abort_unknown_commits(opts)
  end

  defp rollback_committed(receipt, opts) do
    nodes = nodes_with_executor_receipts(receipt)

    results =
      parallel(nodes, opts, :rollback, fn target ->
        node_receipt = Map.fetch!(receipt.node_receipts, target)

        rollback_opts =
          Keyword.put(
            Keyword.get(opts, :rollback_options, []),
            :timeout,
            timeout(opts, :rollback)
          )

        rpc(
          target,
          NodeExecutor,
          :rollback,
          [node_receipt.executor_receipt, rollback_opts],
          timeout(opts, :rollback)
        )
      end)

    Enum.reduce(results, receipt, fn {target, result}, acc ->
      update_node(acc, target, fn node_receipt -> apply_rollback_result(node_receipt, result) end)
    end)
  end

  defp apply_rollback_result(node_receipt, {:ok, :ok}) do
    %{node_receipt | executor_receipt: nil, recovery: :rolled_back}
  end

  defp apply_rollback_result(node_receipt, {:ok, {:error, reason, recovery}}) do
    %{node_receipt | recovery: recovery, error: {:rollback, reason}}
  end

  defp apply_rollback_result(node_receipt, {:ok, unexpected}) do
    %{
      node_receipt
      | recovery: :quarantined,
        error: {:rollback, {:unexpected_result, unexpected}}
    }
  end

  defp apply_rollback_result(node_receipt, {:transport_error, reason}) do
    %{
      node_receipt
      | recovery: :quarantined,
        error: {:rollback, {:transport, reason}}
    }
  end

  defp abort_prepared(receipt, opts) do
    nodes =
      Enum.filter(receipt.nodes, fn target ->
        node_receipt = Map.fetch!(receipt.node_receipts, target)
        node_receipt.prepare == :prepared and is_binary(node_receipt.token)
      end)

    abort_nodes(receipt, nodes, opts)
  end

  defp abort_unknown_commits(receipt, opts) do
    nodes =
      Enum.filter(receipt.nodes, fn target ->
        node_receipt = Map.fetch!(receipt.node_receipts, target)
        node_receipt.commit == :unknown and is_binary(node_receipt.token)
      end)

    abort_nodes(receipt, nodes, opts)
  end

  defp abort_nodes(receipt, nodes, opts) do
    results =
      parallel(nodes, opts, :abort, fn target ->
        token = receipt.node_receipts[target].token
        rpc(target, NodeExecutor, :abort, [token], timeout(opts, :abort))
      end)

    Enum.reduce(results, receipt, fn {target, result}, acc ->
      update_node(acc, target, fn node_receipt -> apply_abort_result(node_receipt, result) end)
    end)
  end

  defp apply_abort_result(node_receipt, {:ok, :ok}) do
    %{node_receipt | token: nil, recovery: :aborted}
  end

  defp apply_abort_result(node_receipt, {:ok, {:error, reason}}) do
    %{node_receipt | recovery: :quarantined, error: {:abort, reason}}
  end

  defp apply_abort_result(node_receipt, {:ok, unexpected}) do
    %{
      node_receipt
      | recovery: :quarantined,
        error: {:abort, {:unexpected_result, unexpected}}
    }
  end

  defp apply_abort_result(node_receipt, {:transport_error, reason}) do
    %{
      node_receipt
      | recovery: :quarantined,
        error: {:abort, {:transport, reason}}
    }
  end

  defp apply_promote_result(node_receipt, {:ok, :ok}) do
    %{node_receipt | executor_receipt: nil, recovery: :promoted_no_rollback}
  end

  defp apply_promote_result(node_receipt, {:ok, {:error, reason}}) do
    %{node_receipt | recovery: :unchanged, error: {:promote, reason}}
  end

  defp apply_promote_result(node_receipt, {:ok, unexpected}) do
    %{
      node_receipt
      | recovery: :quarantined,
        error: {:promote, {:unexpected_result, unexpected}}
    }
  end

  defp apply_promote_result(node_receipt, {:transport_error, reason}) do
    %{
      node_receipt
      | recovery: :quarantined,
        error: {:promote, {:transport, reason}}
    }
  end

  defp migrations_for(opts, target) do
    case Keyword.get(opts, :migrations, %{}) do
      migrations when is_map(migrations) -> Map.get(migrations, target, [])
      _invalid -> :invalid
    end
  end

  defp all_prepared?(receipt) do
    Enum.all?(receipt.node_receipts, fn {_target, node_receipt} ->
      node_receipt.prepare == :prepared
    end)
  end

  defp all_committed?(receipt) do
    Enum.all?(receipt.node_receipts, fn {_target, node_receipt} ->
      node_receipt.commit == :committed
    end)
  end

  defp all_healthy?(receipt) do
    Enum.all?(receipt.node_receipts, fn {_target, node_receipt} ->
      match?({:passed, _}, node_receipt.health)
    end)
  end

  defp nodes_with_executor_receipts(receipt) do
    Enum.filter(receipt.nodes, fn target ->
      match?(%NodeExecutor.Receipt{}, receipt.node_receipts[target].executor_receipt)
    end)
  end

  defp retained_executor_receipts?(receipt), do: nodes_with_executor_receipts(receipt) != []

  defp ensure_executor_receipts(receipt, operation) do
    if retained_executor_receipts?(receipt),
      do: :ok,
      else: {:error, String.to_atom("#{operation}_unavailable")}
  end

  defp finish_promotion(receipt) do
    cond do
      not retained_executor_receipts?(receipt) ->
        {:ok, finish(receipt, :promoted, :not_available)}

      promoted_any?(receipt) ->
        {:error, finish(receipt, :promotion_partial, :partial_irreversible)}

      quarantined?(receipt) ->
        {:error, finish(receipt, :promotion_failed, :quarantined)}

      true ->
        {:error, finish(receipt, :promotion_failed, :unchanged)}
    end
  end

  defp promoted_any?(receipt) do
    Enum.any?(receipt.node_receipts, fn {_target, node_receipt} ->
      node_receipt.recovery == :promoted_no_rollback
    end)
  end

  defp quarantined?(receipt) do
    Enum.any?(receipt.node_receipts, fn {_target, node_receipt} ->
      node_receipt.recovery == :quarantined
    end)
  end

  defp recovery_outcome(receipt) do
    cond do
      quarantined?(receipt) -> :quarantined
      retained_executor_receipts?(receipt) -> :incomplete
      true -> :complete
    end
  end

  defp update_node(receipt, target, fun) do
    %{receipt | node_receipts: Map.update!(receipt.node_receipts, target, fun)}
  end

  defp set_validation_error(receipt, reason) do
    node_receipts =
      Map.new(receipt.node_receipts, fn {target, node_receipt} ->
        {target, %{node_receipt | recovery: :unchanged, error: {:validation, reason}}}
      end)

    %{receipt | node_receipts: node_receipts}
  end

  defp finish_error(receipt, outcome) do
    {:error, finish(receipt, outcome, recovery_outcome(receipt))}
  end

  defp finish_validation_error(receipt, reason) do
    {:error, finish(set_validation_error(receipt, reason), :validation_failed, :unchanged)}
  end

  defp finish(receipt, outcome, recovery) do
    %{receipt | outcome: outcome, recovery: recovery, finished_at: now()}
  end

  defp validate_nodes(nodes) when is_list(nodes) do
    cond do
      nodes == [] ->
        {:error, :empty_node_list}

      not Enum.all?(nodes, &is_atom/1) ->
        {:error, {:invalid_nodes, nodes}}

      Enum.uniq(nodes) != nodes ->
        {:error, {:duplicate_nodes, nodes}}

      disconnected = Enum.reject(nodes, &connected?/1) ->
        if disconnected == [],
          do: {:ok, nodes},
          else: {:error, {:disconnected_nodes, disconnected}}
    end
  end

  defp validate_nodes(nodes), do: {:error, {:invalid_nodes, nodes}}

  defp connected?(target), do: target == node() or target in Node.list(:connected)

  defp validate_health_check(nil), do: :ok

  defp validate_health_check({module, function, arguments})
       when is_atom(module) and is_atom(function) and is_list(arguments),
       do: :ok

  defp validate_health_check(value), do: {:error, {:invalid_health_check, value}}

  defp validate_options(opts, operation) do
    with true <- Keyword.keyword?(opts),
         :ok <- validate_positive_option(opts, :max_concurrency),
         :ok <- validate_timeout_options(opts),
         :ok <- validate_option_bags(opts),
         :ok <- validate_deploy_options(opts, operation) do
      :ok
    else
      false -> {:error, :invalid_options}
      {:error, _reason} = error -> error
    end
  end

  defp validate_positive_option(opts, key) do
    case Keyword.fetch(opts, key) do
      :error -> :ok
      {:ok, value} when is_integer(value) and value > 0 -> :ok
      {:ok, value} -> {:error, {:invalid_option, key, value}}
    end
  end

  defp validate_timeout_options(opts) do
    Enum.reduce_while(
      [
        :prepare_timeout,
        :commit_timeout,
        :rollback_timeout,
        :promote_timeout,
        :health_timeout,
        :status_timeout,
        :abort_timeout
      ],
      :ok,
      fn key, :ok ->
        case validate_positive_option(opts, key) do
          :ok -> {:cont, :ok}
          {:error, _reason} = error -> {:halt, error}
        end
      end
    )
  end

  defp validate_option_bags(opts) do
    Enum.reduce_while(
      [:prepare_options, :commit_options, :rollback_options],
      :ok,
      fn key, :ok ->
        case Keyword.fetch(opts, key) do
          :error ->
            {:cont, :ok}

          {:ok, bag} when is_list(bag) ->
            if Keyword.keyword?(bag) do
              with :ok <- validate_positive_option(bag, :timeout),
                   :ok <- validate_positive_option(bag, :process_timeout) do
                {:cont, :ok}
              else
                {:error, _reason} = error -> {:halt, error}
              end
            else
              {:halt, {:error, {:invalid_option, key, bag}}}
            end

          {:ok, bag} ->
            {:halt, {:error, {:invalid_option, key, bag}}}
        end
      end
    )
  end

  defp validate_deploy_options(opts, :deploy) do
    case Keyword.fetch(opts, :migrations) do
      :error -> :ok
      {:ok, migrations} when is_map(migrations) -> :ok
      {:ok, migrations} -> {:error, {:invalid_option, :migrations, migrations}}
    end
  end

  defp validate_deploy_options(_opts, _operation), do: :ok

  defp parallel(nodes, opts, operation, fun) do
    max_concurrency = max(1, Keyword.get(opts, :max_concurrency, max(1, min(length(nodes), 8))))
    task_timeout = timeout(opts, operation) + 1_000

    stream =
      Task.async_stream(nodes, fun,
        ordered: true,
        max_concurrency: max_concurrency,
        timeout: task_timeout,
        on_timeout: :kill_task
      )

    nodes
    |> Enum.zip(Enum.to_list(stream))
    |> Map.new(fn
      {target, {:ok, result}} -> {target, result}
      {target, {:exit, reason}} -> {target, {:transport_error, {:task_exit, reason}}}
    end)
  end

  defp rpc(target, module, function, arguments, rpc_timeout) do
    try do
      result =
        if target == node() do
          apply(module, function, arguments)
        else
          :erpc.call(target, module, function, arguments, rpc_timeout)
        end

      {:ok, result}
    rescue
      exception ->
        {:transport_error, {:exception, exception.__struct__, Exception.message(exception)}}
    catch
      kind, reason -> {:transport_error, {kind, reason}}
    end
  end

  defp timeout(opts, operation) do
    key = String.to_atom("#{operation}_timeout")
    Keyword.get(opts, key, default_timeout(operation))
  end

  defp default_timeout(:prepare), do: 15_000
  defp default_timeout(:commit), do: 30_000
  defp default_timeout(:rollback), do: 30_000
  defp default_timeout(:promote), do: 15_000
  defp default_timeout(:health), do: 5_000
  defp default_timeout(:status), do: 5_000
  defp default_timeout(:abort), do: 5_000

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
