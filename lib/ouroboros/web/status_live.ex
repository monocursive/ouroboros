defmodule Ouroboros.Web.StatusLive do
  @moduledoc """
  What this node is, read through `Ouroboros.Web.Call` like everything else.

  W0's whole surface. It exists to prove the parts underneath it are wired the way they
  claim: the token bought a cookie, the cookie reached a LiveView, the LiveView asked the
  gateway's method table rather than a plane, and the answer came back through the
  supervised task with the table's own ceiling on it.

  It renders on mount and again when asked, and does not poll. The visibility rule the
  TUI follows — only what is on screen refreshes, at that view's own cadence — arrives
  with the session lists in W3, where there is something whose staleness matters. A
  refresh button is the honest thing for a page that is one call deep.
  """

  use Phoenix.LiveView

  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Config

  @method "runtime.status"

  @impl true
  def mount(_params, _session, socket) do
    {:ok, load(socket)}
  end

  @impl true
  def handle_event("refresh", _params, socket), do: {:noreply, load(socket)}

  @impl true
  def render(assigns) do
    ~H"""
    <main class="ouro-page">
      <header class="ouro-header">
        <h1>Ouroboros</h1>
        <p class="ouro-subhead">{@scope} scope</p>
      </header>

      <section class="ouro-panel">
        <div class="ouro-panel-head">
          <h2>Runtime</h2>
          <button type="button" class="ouro-button" phx-click="refresh">Refresh</button>
        </div>

        <.status :if={@status} status={@status} />
        <.failure :if={@error} error={@error} />
      </section>
    </main>
    """
  end

  attr :status, :map, required: true

  defp status(assigns) do
    ~H"""
    <dl class="ouro-facts">
      <div class="ouro-fact">
        <dt>Node</dt>
        <dd class="ouro-mono">{@status.node}</dd>
      </div>
      <div class="ouro-fact">
        <dt>Role</dt>
        <dd class="ouro-mono">{@status.role}</dd>
      </div>
      <div class="ouro-fact">
        <dt>Connected nodes</dt>
        <dd class="ouro-mono">{@status.connected_nodes}</dd>
      </div>
      <div class="ouro-fact">
        <dt>Interactive sessions</dt>
        <dd class="ouro-mono">{@status.interactive_sessions}</dd>
      </div>
      <div class="ouro-fact">
        <dt>Coding tasks</dt>
        <dd class="ouro-mono">{@status.coding_tasks}</dd>
      </div>
    </dl>
    """
  end

  attr :error, :string, required: true

  defp failure(assigns) do
    ~H"""
    <p class="ouro-refusal">{@error}</p>
    """
  end

  defp load(socket) do
    scope = scope(socket)

    case Call.call(scope, @method, %{}, session: socket.assigns[:web_session]) do
      {:ok, status} ->
        socket
        |> assign(:scope, scope)
        |> assign(:status, summarise(status))
        |> assign(:error, nil)

      {:error, _code, message} ->
        refused(socket, scope, message)

      {:error, _code, message, %{"outcome" => "unknown"}} ->
        refused(socket, scope, message <> " (outcome unknown)")

      {:error, _code, message, _data} ->
        refused(socket, scope, message)
    end
  end

  defp refused(socket, scope, message) do
    socket
    |> assign(:scope, scope)
    |> assign(:status, nil)
    |> assign(:error, message)
  end

  # The endpoint's scope, never the session's. A cookie minted while this endpoint served
  # `:operate` must not still claim that authority after a restart at `:read`.
  defp scope(socket), do: Config.for_endpoint(socket.endpoint).scope

  # Presentation, and only presentation: counts rather than the lists themselves, because
  # W0 has nowhere to render a session and a page that dumped every one of them would be
  # the first thing to break on a busy node.
  defp summarise(status) do
    %{
      node: to_string(Map.get(status, :node, node())),
      role: to_string(Map.get(status, :role, :unknown)),
      connected_nodes: describe_nodes(Map.get(status, :connected_nodes, [])),
      interactive_sessions: count(Map.get(status, :interactive_sessions)),
      coding_tasks: count(Map.get(status, :coding_tasks))
    }
  end

  defp describe_nodes([]), do: "none"
  defp describe_nodes(nodes) when is_list(nodes), do: Enum.map_join(nodes, ", ", &to_string/1)
  defp describe_nodes(_other), do: "unknown"

  defp count(list) when is_list(list), do: list |> length() |> Integer.to_string()
  defp count(_other), do: "unknown"
end
