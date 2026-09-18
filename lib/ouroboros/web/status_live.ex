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

  # The needs-you bell is in the one top bar, so it is on this page too. This is what makes
  # that honest: the same edge computation and the same three-second `interactive.list`
  # poll the deck runs, so a bell switched on here rings rather than sitting quiet
  # (`Ouroboros.Web.NeedsYou`).
  on_mount {Ouroboros.Web.NeedsYou, :bell}

  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Layouts
  alias Ouroboros.Web.Presentation

  @method "runtime.status"

  @impl true
  def mount(_params, _session, socket) do
    # "Advanced · Runtime" named a section of a settings page this surface does not have.
    # The page is called what its heading calls it, and the top bar now links to it by that
    # name (review §3.1: `grep href="/status"` used to come back empty).
    {:ok, socket |> assign(:page_title, "Runtime status") |> load()}
  end

  @impl true
  def handle_event("refresh", _params, socket), do: {:noreply, load(socket)}

  @impl true
  def render(assigns) do
    ~H"""
    <div>
      <Layouts.topbar current={:status} />

      <main class="ouro-page">
        <header class="ouro-header">
          <p class="ouro-subhead"><a href="/">Sessions</a> · Runtime status</p>
          <h1>Runtime status</h1>
          <p>What this node is, right now, read through one call.</p>
        </header>

        <section class="ouro-panel">
          <div class="ouro-panel-head">
            <h2>Runtime</h2>
            <button type="button" class="ouro-button" phx-click="refresh">Refresh</button>
          </div>

          <.status :if={@status} status={@status} />
          <.failure :if={@error} error={@error} />

          <%!-- The boot-owned half of the same picture — web scope, listening address,
                data directory, model catalogue — belongs to Settings, and this is the page
                that says so rather than restating it. --%>
          <p class="ouro-subhead">
            <a href="/settings#runtime">How this installation is configured →</a>
          </p>

          <%!-- Fleet onboarding, slice 6. This page answers "what is this node"; Devices
                answers "what other machines are there, and how do I add one". The second
                question is the one an operator arrives at from here, so it is named here
                rather than left to the top bar alone. --%>
          <p class="ouro-subhead">
            <a href="/devices">Devices — this fleet's machines, and adding one →</a>
          </p>
        </section>
      </main>
    </div>
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
        <dt>Agent sessions</dt>
        <dd class="ouro-mono">{@status.interactive_sessions}</dd>
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

      # Every refusal shape goes through the one translator, including the
      # `outcome: unknown` marker `Ouroboros.Web.Call` carries for the verbs where "did
      # not happen" and "happened and was not reported" are different answers.
      {:error, _code, _message} = refusal ->
        refused(socket, scope, Presentation.refusal(refusal))

      {:error, _code, _message, _data} = refusal ->
        refused(socket, scope, Presentation.refusal(refusal))
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
    machines = fleet_machines(status)

    %{
      # Erlang node names never reach a template raw — the parity plan's sixth ground
      # rule, and the reason `nonode@nohost` used to be the first fact on this page.
      node: Presentation.node_label(Map.get(status, :node, node()), machines),
      role: to_string(Map.get(status, :role, :unknown)),
      connected_nodes: describe_nodes(Map.get(status, :connected_nodes, []), machines),
      interactive_sessions: count(Map.get(status, :interactive_sessions))
    }
  end

  # The cluster's own directory, where the status carries one: it is the only place a
  # machine has a name somebody chose rather than a name the BEAM assembled.
  defp fleet_machines(status) do
    status
    |> Map.get(:cluster, %{})
    |> then(&if(is_map(&1), do: Map.get(&1, :fleet, %{}), else: %{}))
    |> then(&if(is_map(&1), do: Map.get(&1, :machines, []), else: []))
    |> List.wrap()
  end

  defp describe_nodes([], _machines), do: "none"

  defp describe_nodes(nodes, machines) when is_list(nodes),
    do: Enum.map_join(nodes, ", ", &Presentation.node_label(&1, machines))

  defp describe_nodes(_other, _machines), do: "unknown"

  defp count(list) when is_list(list), do: list |> length() |> Integer.to_string()
  defp count(_other), do: "unknown"
end
