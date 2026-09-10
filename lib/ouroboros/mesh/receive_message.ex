defmodule Ouroboros.Mesh.ReceiveMessage do
  @moduledoc """
  The action that answers `ouroboros.agent.message`, and the mesh's whole message
  convention on the receiving side.

  `Ouroboros.Mesh.send_message/4` mints an `Ouroboros.Signals.AgentMessage` and calls the
  target agent with it; an agent that routes that signal here records it and answers with
  its own state, which is where `last_message` comes from. It lives beside the mesh rather
  than inside any one agent because every agent that joins the mesh needs the same answer:
  an owned agent callback can call `handle_message/3` to adopt these explicit bounds.
  """

  use Ouroboros.Action,
    name: "receive_agent_message",
    description: "Record a typed message from another agent",
    schema: [
      from: [type: :string, required: true],
      body: [type: :any, required: true],
      correlation_id: [type: :string, required: true],
      causation_id: [type: :any, default: nil]
    ]

  @max_inbox 64
  @max_inbox_bytes 1024 * 1024

  # F9. The inbox keeps the newest #{@max_inbox} messages and at most
  # #{div(@max_inbox_bytes, 1024)} KiB of them, oldest dropped first.
  #
  # It was unbounded, and a remote-reachable send is what made that reachable: any node in
  # the cluster can send this agent a 64 KiB body as often as it likes, and every one of
  # them was retained forever in a list nothing pruned. A mailbox is a *recent* record —
  # that is what makes it useful to a reader and what makes `last_message` the field the
  # rest of this runtime actually reads — so the bound is on both counts, because either
  # one alone is a way past the other: sixty-four 64 KiB bodies is four megabytes, and four
  # million one-byte bodies is the same problem spelled differently.
  @impl true
  def run(params, %{agent: agent}) do
    message = %{
      from: params.from,
      body: params.body,
      correlation_id: params.correlation_id,
      causation_id: params.causation_id
    }

    {:ok,
     Map.merge(agent.state, %{
       inbox: bound_inbox(Map.get(agent.state, :inbox, []) ++ [message]),
       last_message: message,
       messages_received: Map.get(agent.state, :messages_received, 0) + 1
     })}
  end

  @doc "Applies the bounded receive convention as a complete domain state transition."
  def handle_message(message, state, context) do
    run(message, Map.put(context, :agent, %{id: context.id, state: state}))
  end

  # Newest kept, oldest dropped, count first and then bytes. `external_size/1` measures a
  # term without building the binary, so measuring a megabyte costs nothing.
  defp bound_inbox(inbox) do
    inbox
    |> Enum.take(-@max_inbox)
    |> trim_bytes()
  end

  defp trim_bytes([_only] = inbox), do: inbox

  defp trim_bytes([_ | rest] = inbox) do
    if :erlang.external_size(inbox) > @max_inbox_bytes, do: trim_bytes(rest), else: inbox
  end

  defp trim_bytes([]), do: []
end
