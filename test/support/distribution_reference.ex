defmodule Ouroboros.Capability.DistributionReference do
  @moduledoc """
  A mesh agent that exists to be placed on another node.

  Compiled into the test build's `ebin`, which is what makes it reachable from an OS peer
  started with this VM's code path: `Ouroboros.Mesh.start_agent_on/3` is an `:erpc` into
  the peer's own `start_agent/2`, and the module has to be loadable there.

  It routes `ouroboros.agent.message` to `Ouroboros.Mesh.ReceiveMessage` and does nothing
  else, so `test/distribution_test.exs` measures the distribution and not an agent.
  """

  @behaviour Ouroboros.Mesh.Agent

  @impl true
  def init_state(initial),
    do:
      {:ok,
       Map.merge(
         %{role: nil, objective: nil, inbox: [], last_message: nil, messages_received: 0},
         initial
       )}

  @impl true
  def handle_message(message, state, context) do
    Ouroboros.Mesh.ReceiveMessage.handle_message(message, state, context)
  end
end
