defmodule Ouroboros.Provider.Native.Subagents do
  @moduledoc "Shared session-owned child planning and placement."
  alias Ouroboros.Provider.Native.Subagent
  alias Ouroboros.Provider.Native.Tools.Agent

  def spawn(input, parent) do
    with {:ok, spec} <- Agent.plan(input, parent) do
      case Subagent.spawn(spec) do
        {:ok, started} -> {:ok, spec, started}
        {:error, reason} -> {:error, Agent.start_refusal(reason)}
      end
    end
  end
end
