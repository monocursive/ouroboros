defmodule Ouroboros.Provider.Native.Tools.Fleet do
  @moduledoc "Bounded live directory shared by the fleet tool and the labelled prompt snapshot."
  use Ouroboros.Action,
    name: "fleet",
    description:
      "List fleet machines, live connectivity, advisory tags and toolchains. Read this before choosing a machine for agent.",
    schema: []

  @impl true
  def run(_params, _context) do
    {:ok, %{output: render(Ouroboros.Cluster.fleet_status().machines), is_error: false}}
  end

  # Opening a session must not queue behind a slow monitor probe. This reads only the
  # cached directory with a short timeout, never probes another node.
  def snapshot do
    if Node.alive?() and is_pid(Process.whereis(Ouroboros.Cluster.Monitor)) do
      GenServer.call(Ouroboros.Cluster.Monitor, :status, 100).machines |> Enum.take(64)
    end
  catch
    :exit, _ -> nil
  end

  def render(machines) do
    lines = machines |> Enum.take(64) |> Enum.map_join("\n", &line/1)

    lines <>
      "\nPlace work with agent(machine: NAME, workspace: PATH) for a path that exists there, or sync: true to provision this repository.\nUse machine: \"tag:NAME\" only when exactly one connected machine advertises that tag; facts never grant authority."
  end

  defp line(machine) do
    facts = Map.get(machine, :facts) || %{}

    state =
      if machine.state == :offline,
        do: "offline since #{Map.get(machine, :last_down_at) || "unknown"}",
        else: to_string(machine.state)

    "#{machine.machine} (#{machine.node}) #{state} #{Map.get(facts, :os, "unknown")}/#{Map.get(facts, :arch, "unknown")} tags: #{list(facts, :tags)} toolchains: #{list(facts, :toolchains)} provisionable: #{Map.get(facts, :provisionable, "unknown")} role: #{machine.role} compatible: #{Map.get(machine, :compatibility, :unknown)}#{tag_error(facts)}"
  end

  defp list(facts, key) do
    case Map.get(facts, key, []) do
      [] -> "—"
      values -> Enum.join(values, " ")
    end
  end

  defp tag_error(%{tags_error: error}), do: " tags_error: #{error}"
  defp tag_error(_), do: ""
end
