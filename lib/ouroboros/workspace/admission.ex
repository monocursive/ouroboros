defmodule Ouroboros.Workspace.Admission do
  @moduledoc "Workspace admission with bounded retry only for the same owner's stale lease."

  def configured?,
    do: match?([_ | _], Application.get_env(:ouroboros, :workspace_allowed_roots, []))

  def acquire(workspace, id, plane, mode, server, attempts, delay) do
    result =
      try do
        Ouroboros.Workspace.acquire_managed(workspace, id, plane, mode: mode, server: server)
      catch
        :exit, reason -> {:error, {:workspace_manager_unavailable, reason}}
      end

    case result do
      {:error, {:workspace_conflict, [_ | _] = conflicts}} = error when attempts > 0 ->
        if Enum.all?(conflicts, &(Map.get(&1, :task_id) == id)) do
          Process.sleep(delay)
          acquire(workspace, id, plane, mode, server, attempts - 1, delay)
        else
          error
        end

      other ->
        other
    end
  end
end
