defmodule Ouroboros.Workspace.Admission do
  @moduledoc "Workspace admission with bounded retry only for the same owner's stale lease."

  def configured?,
    do: match?([_ | _], Application.get_env(:ouroboros, :workspace_allowed_roots, []))

  def acquire(workspace, id, plane, mode, server, attempts, delay, maintenance \\ nil) do
    with :ok <- validate_maintenance(maintenance) do
      do_acquire(workspace, id, plane, mode, server, attempts, delay, maintenance)
    end
  end

  defp do_acquire(workspace, id, plane, mode, server, attempts, delay, maintenance) do
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
          do_acquire(workspace, id, plane, mode, server, attempts - 1, delay, maintenance)
        else
          error
        end

      other ->
        other
    end
  end

  defp validate_maintenance(nil) do
    server = maintenance_server()
    if Process.whereis(server), do: {:error, :maintenance_admission_required}, else: :ok
  end

  defp validate_maintenance({server, lease, session_id}) do
    if server == maintenance_server(),
      do: Ouroboros.Maintenance.Fence.validate_admission(lease, session_id, server),
      else: {:error, :invalid_maintenance_admission}
  end

  defp validate_maintenance(_), do: {:error, :invalid_maintenance_admission}

  defp maintenance_server,
    do: Application.get_env(:ouroboros, :maintenance_fence_server, Ouroboros.Maintenance.Fence)
end
