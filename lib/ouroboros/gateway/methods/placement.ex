defmodule Ouroboros.Gateway.Methods.Placement do
  @moduledoc false

  # Start-on-node placement. Params have already been validated; this module
  # decides whether the chosen owner can run the session and how a created-but-
  # not-ready start is answered. Fail closed: missing owner evidence is
  # `not_dispatched`, never a silent local fallback.

  alias Ouroboros.Cluster
  alias Ouroboros.CodingSession
  alias Ouroboros.Gateway.Methods.Safe
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.InteractiveSession

  def start_interactive(owner, opts),
    do:
      start(
        owner,
        opts,
        :interactive,
        "interactive session",
        &InteractiveSession.start_for_gateway_on(&1, opts)
      )

  def start_coding(owner, objective, opts),
    do:
      start(
        owner,
        opts,
        :coding,
        "coding task",
        &CodingSession.start_for_gateway_on(&1, objective, opts)
      )

  defp start(owner, opts, plane, label, start) do
    case destination_workspace(owner, opts) do
      :ok ->
        case Cluster.ensure_placeable(owner) do
          :ok ->
            case fence_possible_owner(plane, owner) do
              :ok ->
                owner
                |> then(fn owner -> start.(owner) end)
                |> remember_started_owner(plane, owner)
                |> start_reply()

              {:error, _reason} ->
                Safe.unavailable_not_dispatched(
                  "machine #{owner} start was not dispatched because durable fleet owner evidence could not be checkpointed; repair the Ouroboros data directory and retry"
                )
            end

          {:error, reason} ->
            Safe.unavailable_not_dispatched(
              "machine #{owner} cannot run this #{label}: #{placement_reason(reason)}"
            )
        end

      {:error, reason} ->
        Safe.invalid_params(destination_workspace_message(owner, reason))
    end
  end

  # A relative path belongs to the process that expands it. On a selected remote owner
  # that process is a packaged release whose cwd is an implementation detail, not the
  # developer's project. Require the client to name the destination path explicitly;
  # the remote plane remains responsible for checking that the directory exists.
  defp destination_workspace(owner, _opts) when owner == node(), do: :ok

  defp destination_workspace(owner, opts) do
    case Keyword.fetch(opts, :workspace) do
      {:ok, workspace} when is_binary(workspace) ->
        if Path.type(workspace) == :absolute,
          do: :ok,
          else: {:error, {:remote_workspace_not_absolute, owner}}

      :error ->
        {:error, {:remote_workspace_missing, owner}}

      {:ok, _invalid} ->
        {:error, {:remote_workspace_missing, owner}}
    end
  end

  defp destination_workspace_message(owner, {:remote_workspace_missing, owner}) do
    "params.workspace is required when params.machine or params.node selects remote " <>
      "machine #{owner}; provide a nonempty absolute path that exists on that machine"
  end

  defp destination_workspace_message(owner, {:remote_workspace_not_absolute, owner}) do
    "params.workspace must be an absolute path on remote machine #{owner}; relative paths " <>
      "would resolve inside the packaged release rather than the destination project"
  end

  defp placement_reason(:node_not_connected), do: "it is not connected"
  defp placement_reason(:runtime_not_running), do: "its Ouroboros runtime is not running"

  defp placement_reason({:runtime_incompatible, _actual, _expected}),
    do:
      "its Ouroboros version, OTP release, or fleet protocol revision differs from this gateway; " <>
        "install the same Ouroboros build before placing sessions there"

  defp placement_reason({:role, actual, :core}),
    do: "its role is #{actual}; agent sessions require a machine that runs agents"

  defp placement_reason(reason), do: inspect(reason, limit: 10, printable_limit: 200)

  # Start has a durable boundary the generic `reply/1` cannot infer. Once the exact
  # caller-owned request is checkpointed, readiness failure is still a successful
  # creation outcome: clients must open that stable failed session, not mint another or
  # remain trapped reconciling it. Conflicts are the inverse — this request definitely
  # created nothing, because the id already belongs to different immutable intent.
  # Owner-evidence failure cannot rewrite a created session into `not_dispatched`; the
  # monitor marks its evidence unreliable so subsequent lists fail closed instead.
  defp fence_possible_owner(_plane, owner) when owner == node(), do: :ok

  defp fence_possible_owner(plane, owner) do
    Cluster.record_session_snapshot(plane, [{owner, [%{possible_start: true}]}])
  end

  defp remember_started_owner({:ok, %{node: owner}} = result, plane, owner) do
    _ = Cluster.record_session_snapshot(plane, [{owner, [%{created: true}]}])
    result
  end

  defp remember_started_owner({:created, %{node: owner}, _reason} = result, plane, owner) do
    _ = Cluster.record_session_snapshot(plane, [{owner, [%{created: true}]}])
    result
  end

  defp remember_started_owner(result, _plane, _owner), do: result

  defp start_reply({:created, %{id: id, node: owner}, reason}) do
    {:ok,
     %{
       "id" => id,
       "node" => owner,
       "outcome" => "created",
       "ready" => false,
       "error" => Wire.to_json(reason)
     }}
  end

  defp start_reply({:error, {:session_id_conflict, id} = reason}) do
    {:error, Ouroboros.Gateway.Methods.code(:upstream_error),
     "session id #{inspect(id)} already belongs to different immutable start options",
     %{
       "reason" => "session_id_conflict",
       "id" => id,
       "outcome" => "not_dispatched",
       "error" => Wire.to_json(reason)
     }}
  end

  defp start_reply({:error, {:task_id_conflict, id} = reason}) do
    {:error, Ouroboros.Gateway.Methods.code(:upstream_error),
     "coding task id #{inspect(id)} already belongs to a different immutable request",
     %{
       "reason" => "task_id_conflict",
       "id" => id,
       "outcome" => "not_dispatched",
       "error" => Wire.to_json(reason)
     }}
  end

  defp start_reply(result), do: Safe.reply(result)
end
