defmodule Ouroboros.Web.Live.McpPanel do
  @moduledoc """
  W3.9. What MCP servers a node runs, and what its loader refused.

  Port of `App::open_mcp` / `Overlay::Mcp` and `McpList` (`tui/src/ui/app/native.rs:687-742`,
  `tui/src/model.rs:2870-2990`).

  ## The refusals are the point

  A list of *running* servers answers "what is up". It does not answer the question an
  operator actually has, which is "why is my `mcp.json` not doing anything" — and the only
  thing that can tell "it was ignored" from "it was read and rejected" is the loader's own
  refusals. So they are drawn beside the servers, with the reason kept verbatim: an
  unknown reason is still a reason worth showing.

  ## Read fresh, and nothing here mutates

  `mcp.list` is a read-scope verb and this panel calls it each time it is opened. There is
  no start, stop or restart control: the pool is the node's, and a browser is not where a
  server's lifecycle is decided.

  ## Environment variables are a count and never a name

  The runtime does not put them on the wire and this surface has nowhere to get them from.
  The count is the whole fact.

  Pure: `read/1` takes the reply and answers a map.
  """

  use Phoenix.Component

  alias Ouroboros.Web.Presentation

  # At most this many rows out of one answer, matching `MAX_MCP_ROWS`.
  @max_rows 512

  @doc "`mcp.list`'s answer as the fields this panel draws."
  @spec read(term()) :: map() | nil
  def read(answer) when is_map(answer) and not is_struct(answer) do
    %{
      enabled: at(answer, :enabled) == true,
      supervised: at(answer, :supervised) == true,
      node: text(answer, :node),
      protocol_version: text(answer, :protocol_version),
      transports: strings(answer, :transports),
      servers: answer |> list(:servers) |> Enum.take(@max_rows) |> Enum.map(&server/1),
      refusals: answer |> list(:refusals) |> Enum.take(@max_rows) |> Enum.map(&refusal/1)
    }
  end

  def read(_unreadable), do: nil

  defp server(row) when is_map(row) do
    %{
      name: text(row, :name) || "unnamed",
      state: text(row, :state),
      command: text(row, :command),
      args: strings(row, :args),
      cwd: text(row, :cwd),
      scope: text(row, :scope),
      source: text(row, :source),
      workspace: text(row, :workspace),
      transport: text(row, :transport),
      tools: count(row, :tools) || 0,
      tool_names: strings(row, :tool_names),
      env_count: count(row, :env_count) || 0,
      restarts: count(row, :restarts) || 0,
      claims: count(row, :claims) || 0,
      broken_reason: text(row, :broken_reason)
    }
  end

  defp server(_other), do: %{name: "unreadable", state: nil, tools: 0, tool_names: []}

  defp refusal(row) when is_map(row) do
    %{
      name: text(row, :name),
      reason: text(row, :reason),
      detail: text(row, :detail),
      scope: text(row, :scope),
      workspace: text(row, :workspace)
    }
  end

  defp refusal(_other), do: %{name: nil, reason: nil, detail: nil, scope: nil, workspace: nil}

  @doc "Whether the runtime named this server broken."
  @spec broken?(map()) :: boolean()
  def broken?(%{state: state}), do: state == "broken"
  def broken?(_server), do: false

  defp at(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Atom.to_string(key))
    end
  end

  defp text(map, key) do
    case at(map, key) do
      value when is_binary(value) ->
        case String.trim(value) do
          "" -> nil
          trimmed -> trimmed
        end

      value when is_atom(value) and value not in [nil, true, false] ->
        Atom.to_string(value)

      _absent ->
        nil
    end
  end

  defp count(map, key) do
    case at(map, key) do
      value when is_integer(value) and value >= 0 -> value
      _absent -> nil
    end
  end

  defp list(map, key) do
    case at(map, key) do
      value when is_list(value) -> value
      _absent -> []
    end
  end

  defp strings(map, key) do
    map
    |> list(key)
    |> Enum.take(@max_rows)
    |> Enum.flat_map(fn
      value when is_binary(value) -> if String.trim(value) == "", do: [], else: [value]
      value when is_atom(value) and value not in [nil, true, false] -> [Atom.to_string(value)]
      _unreadable -> []
    end)
  end

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  attr :mcp, :any, required: true
  attr :machines, :list, default: []
  attr :error, :any, default: nil

  def panel(assigns) do
    ~H"""
    <dialog
      id="ouro-mcp"
      class="ouro-session-dialog ouro-mcp"
      aria-modal="true"
      aria-labelledby="ouro-mcp-title"
      phx-hook="Modal"
      data-cancel-event="w3-close"
    >
      <div class="ouro-session-dialog-form">
        <h2 id="ouro-mcp-title">MCP servers</h2>

        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>

        <div :if={@mcp}>
          <p class="ouro-quiet">
            {Presentation.node_label(@mcp.node, @machines)} · {if @mcp.enabled,
              do: "MCP is on",
              else: "MCP is off on this machine"}
            <span :if={@mcp.protocol_version}>
              · protocol {@mcp.protocol_version}
            </span><span :if={@mcp.transports != []}>
              · {Enum.join(@mcp.transports, ", ")}
            </span>
          </p>

          <p :if={@mcp.servers == []} class="ouro-quiet">
            This machine holds no MCP server for the workspaces asked about.
          </p>

          <ul class="ouro-mcp-list">
            <li
              :for={server <- @mcp.servers}
              class={["ouro-mcp-row", broken?(server) && "ouro-mcp-broken"]}
            >
              <span class="ouro-mcp-name ouro-mono">{server.name}</span>
              <span class="ouro-mono ouro-quiet">{server.state || "state not reported"}</span>
              <span class="ouro-mono">{server.tools} tools</span>
              <span :if={server.scope} class="ouro-quiet">{server.scope} scope</span>
              <span :if={server.source} class="ouro-mono ouro-quiet">{server.source}</span>
              <span :if={server.env_count > 0} class="ouro-quiet">
                {server.env_count} environment {if server.env_count == 1,
                  do: "variable",
                  else: "variables"}
              </span>
              <p :if={server.broken_reason} class="ouro-rewind-warning">{server.broken_reason}</p>
            </li>
          </ul>

          <section :if={@mcp.refusals != []}>
            <h3>Entries the loader refused</h3>
            <ul class="ouro-mcp-refusals">
              <li :for={entry <- @mcp.refusals}>
                <span class="ouro-mono">{entry.name || "unnamed entry"}</span>
                <span :if={entry.reason} class="ouro-mono ouro-quiet">{entry.reason}</span>
                <span :if={entry.detail}>— {entry.detail}</span>
              </li>
            </ul>
          </section>
        </div>

        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button" phx-click="w3-close">Close</button>
        </div>
      </div>
    </dialog>
    """
  end
end
