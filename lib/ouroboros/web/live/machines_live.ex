defmodule Ouroboros.Web.Live.MachinesLive do
  @moduledoc """
  The fleet, read-only: who is expected, who is answering, and who cannot be spoken for.

  This is the desktop's Machines panel with its add-machine half removed rather than
  faked. The whole pipeline that adds a machine is Rust driving `ssh` and `scp` from the
  operator's own machine (`tui/src/fleet_add.rs`); there is no Elixir enrolment path and
  moving one server-side would hand the daemon the SSH authority, which is its own design
  and not a port. So the page renders membership and names `ouro fleet add user@host`,
  and there is no Add button that cannot work — the desktop's own posture for the case it
  could not serve.

  ## Two sources, and neither is asked to answer the other's question

  `fleet.status` says who is *expected*: the last-known directory, including machines that
  are offline, which is the only place a member that is expected and absent exists at all.
  `runtime.status` says who is *answering*: `connected_nodes` lists only machines that are
  up, so a page standing on it alone could never draw an offline row.

  Presence fuses them under the desktop's exact rules (`tui/src/desktop/machines.rs:107`):

    * a member is **connected** when `connected_nodes` names its node, **or** when it is
      this machine's own node — the local runtime does not list itself among its peers,
      and drawing this machine as offline in its own page would be a false report;
    * before any runtime status has arrived every *peer* is **unknown** rather than
      assumed offline, and the list says so in a footnote.

  The chips wear the semantic tones — ink for connected, amber for offline, tertiary for
  unknown — and never `--attention-green` and never the filled-button accent. A machine
  being up is an operational outcome, not something to click, and the green means one
  thing on this surface: a human is needed here.

  ## What "offline" is allowed to mean

  Nothing here probes anything. Every answer on this page is the runtime's own view of its
  own connections, so the list says in as many words that offline means this runtime is
  not connected to that node and not that the machine is down. `fleet.doctor` is where an
  operator goes for a reading with guidance attached, and it runs **on demand only** — it
  walks the whole directory, and putting that on a three-second cadence would be this page
  spending the fleet's time to keep a panel warm.

  ## What `fleet.status` does not carry

  It names no fleet. The saved profile has a `name`, but `Ouroboros.Cluster`'s decoder
  keeps only the roster, the revision and the tombstones out of it
  (`lib/ouroboros/cluster.ex:805-839`), and the method's answer is the directory:
  `local_node`, `summary`, `machines`, `formation`, `security`. So the header names the
  fleet the way the runtime does — by this machine's node — rather than inventing a label
  the daemon never said.

  It carries no per-member address either, but it does not need to: a fleet node is
  `ouro-<machine>@<host>` by construction and the profile decoder refuses a profile whose
  node is anything else (`cluster.ex:822`), so the host is read off the node name rather
  than guessed at.

  ## Polling

  `runtime.status` every three seconds while mounted, one in flight at a time — the deck's
  discipline, because presence is the thing on this page whose staleness would mislead.
  `fleet.status` is read on mount and on Refresh: a roster changes when an operator changes
  it, not on a timer. A refused poll keeps the last status it had and says the refresh
  failed, because forgetting a good answer would report every peer unknown on one blip.
  """

  use Phoenix.LiveView

  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Config

  @poll_interval 3_000

  @doc """
  What the page says when the runtime belongs to no fleet.

  Named here rather than written into the markup so the empty state is a fact with a test,
  as it is on the desktop (`tui/src/desktop/machines.rs:161`).
  """
  def no_fleet_title, do: "This machine runs on its own"

  def no_fleet_body,
    do:
      "The runtime reports no fleet: its directory names only this machine and formation " <>
        "names no strategy, so there is no roster to show and nothing to add a machine to. " <>
        "Create one with `ouro fleet create`, or open Machines in the terminal client " <>
        "(`ouro` → Machines) to be walked through it. This page shows the roster once a " <>
        "fleet exists."

  @doc """
  The sentence that keeps the offline chip from claiming more than it knows.

  This page performs no reachability probe of its own; every word on it is the runtime's
  view of its own connections.
  """
  def offline_footnote,
    do:
      "Offline means this runtime is not connected to that node, not that the machine is " <>
        "down. This page performs no reachability probe of its own."

  @doc "Why a peer reads as unknown rather than offline before the first runtime status."
  def unknown_footnote,
    do:
      "No runtime status has arrived yet, so every machine other than this one is unknown " <>
        "rather than assumed offline."

  @doc """
  What the page says when a status refresh was refused after an earlier one answered.

  The last good status is kept rather than cleared, so this sentence is what stops the
  chips below from reading as current when they are merely the most recent thing known.
  """
  def stale_status_note,
    do:
      "The last runtime status was refused, so presence below is as of the last one that answered:"

  # ------------------------------------------------------------------------------------
  # Lifecycle
  # ------------------------------------------------------------------------------------

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:scope, Config.for_endpoint(socket.endpoint).scope)
      |> assign(:fleet, nil)
      |> assign(:fleet_error, nil)
      |> assign(:status, nil)
      |> assign(:status_error, nil)
      |> assign(:polling?, false)
      |> assign(:doctor, nil)
      |> assign(:doctor_error, nil)
      |> read_fleet()
      |> read_status()

    if connected?(socket), do: schedule_poll()

    {:ok, socket}
  end

  @impl true
  def handle_event("refresh", _params, socket), do: {:noreply, read_fleet(socket)}

  def handle_event("doctor", _params, socket), do: {:noreply, run_doctor(socket)}

  @impl true
  def handle_info(:poll, socket) do
    schedule_poll()
    {:noreply, read_status(socket)}
  end

  def handle_info(_message, socket), do: {:noreply, socket}

  defp schedule_poll, do: Process.send_after(self(), :poll, @poll_interval)

  # ------------------------------------------------------------------------------------
  # Reading
  # ------------------------------------------------------------------------------------

  defp read_fleet(socket) do
    case call(socket, "fleet.status") do
      {:ok, fleet} when is_map(fleet) ->
        socket |> assign(:fleet, fleet) |> assign(:fleet_error, nil)

      {:ok, _other} ->
        assign(socket, :fleet_error, "fleet.status answered something this build cannot read")

      {:error, message} ->
        assign(socket, :fleet_error, message)
    end
  end

  # One read at a time. The call is synchronous in this process, so the guard is against a
  # future async path rather than a race that exists today — but a second status landing on
  # top of an in-flight one is exactly the bug that stays invisible until a fleet node hangs.
  defp read_status(%{assigns: %{polling?: true}} = socket), do: socket

  defp read_status(socket) do
    socket = assign(socket, :polling?, true)

    socket =
      case call(socket, "runtime.status") do
        {:ok, status} when is_map(status) ->
          socket |> assign(:status, status) |> assign(:status_error, nil)

        {:ok, _other} ->
          assign(
            socket,
            :status_error,
            "runtime.status answered something this build cannot read"
          )

        # The last status is kept rather than cleared: this page would otherwise report
        # every peer unknown because one refresh was refused, which is a worse report than
        # a slightly old one carrying the refusal beside it.
        {:error, message} ->
          assign(socket, :status_error, message)
      end

    assign(socket, :polling?, false)
  end

  defp run_doctor(socket) do
    case call(socket, "fleet.doctor") do
      {:ok, doctor} when is_map(doctor) ->
        socket |> assign(:doctor, report(doctor)) |> assign(:doctor_error, nil)

      {:ok, _other} ->
        assign(socket, :doctor_error, "fleet.doctor answered something this build cannot read")

      {:error, message} ->
        assign(socket, :doctor_error, message)
    end
  end

  defp call(socket, method) do
    case Call.call(socket.assigns.scope, method, %{}, session: socket.assigns[:web_session]) do
      {:ok, value} ->
        {:ok, value}

      {:error, _code, message} ->
        {:error, message}

      {:error, _code, message, %{"outcome" => "unknown"}} ->
        {:error, message <> " (outcome unknown)"}

      {:error, _code, message, _data} ->
        {:error, message}
    end
  end

  # ------------------------------------------------------------------------------------
  # The projection
  #
  # Public and pure, so every rule below is a table in a test rather than a shape scraped
  # back out of HTML. `fleet` is what `fleet.status` returned; `status` is what
  # `runtime.status` returned, or `nil` when none has arrived yet.
  # ------------------------------------------------------------------------------------

  @type presence :: :connected | :offline | :unknown

  @doc """
  Fuses the runtime's last-known directory with its live peer list.

  Returns the whole page's answer: whether there is a fleet at all, which member is this
  machine, one row per member with its presence, and the counts drawn from those rows
  rather than from `fleet.status`'s own summary — the summary counts the directory's view
  of connectivity, and the chips must never be able to disagree with the number above them.
  """
  @spec view(map() | nil, map() | nil) :: map()
  def view(nil, _status), do: %{fleet?: false, members: [], connected: 0, offline: 0, unknown: 0}

  def view(fleet, status) when is_map(fleet) do
    local = fleet |> Map.get(:local_node) |> name()
    connected = connected_nodes(status)
    members = Enum.map(machines(fleet), &member_row(&1, local, connected))

    %{
      fleet?: clustered?(fleet),
      local_node: local,
      this_machine: Enum.find_value(members, & &1.this_machine?, & &1.machine),
      this_address: Enum.find_value(members, & &1.this_machine?, & &1.host),
      status_seen?: not is_nil(connected),
      generated_at: Map.get(fleet, :generated_at),
      members: members,
      connected: Enum.count(members, &(&1.presence == :connected)),
      offline: Enum.count(members, &(&1.presence == :offline)),
      unknown: Enum.count(members, &(&1.presence == :unknown))
    }
  end

  # The runtime's own definition of "in a fleet", reused rather than restated:
  # `fleet.doctor` decides which of its checks are errors by exactly this predicate
  # (`lib/ouroboros/cluster.ex:1771`). A second notion of clustered living here is how a
  # page ends up showing an empty state to a machine the daemon considers a member.
  defp clustered?(fleet) do
    expected = fleet |> Map.get(:summary, %{}) |> Map.get(:expected, 0)
    strategy = fleet |> Map.get(:formation, %{}) |> Map.get(:strategy, :none)

    (is_integer(expected) and expected > 1) or strategy != :none
  end

  defp machines(fleet), do: fleet |> Map.get(:machines, []) |> List.wrap()

  # `nil` is "no runtime status has arrived", which is not the same answer as "the status
  # arrived and named nobody" — the first makes every peer unknown, the second makes every
  # peer offline, and collapsing them is the false report this whole rule exists to avoid.
  defp connected_nodes(nil), do: nil

  defp connected_nodes(status) when is_map(status) do
    status
    |> Map.get(:connected_nodes, [])
    |> List.wrap()
    |> Enum.map(&name/1)
    |> MapSet.new()
  end

  defp member_row(machine, local, connected) do
    node = machine |> Map.get(:node) |> name()
    this_machine? = node == local

    %{
      machine: Map.get(machine, :machine) || node,
      node: node,
      host: host(node),
      this_machine?: this_machine?,
      presence: presence(node, this_machine?, connected)
    }
  end

  @doc """
  Whether a member is answering right now, or whether that is simply unknown.

  The three arms are the desktop's, in the desktop's order, and the order is the rule: this
  machine is connected *before* the status is consulted, because the local runtime never
  lists itself among its peers.
  """
  @spec presence(String.t(), boolean(), MapSet.t(String.t()) | nil) :: presence()
  def presence(_node, true = _this_machine?, _connected), do: :connected
  def presence(_node, false, nil), do: :unknown

  def presence(node, false, connected),
    do: if(MapSet.member?(connected, node), do: :connected, else: :offline)

  # A fleet node is `ouro-<machine>@<host>` by construction and the profile decoder refuses
  # anything else (`cluster.ex:822`), so this reads the address the profile stored rather
  # than deriving a new one. A node with no `@` — `nonode@nohost` aside, a machine that
  # never went distributed — has no address to show and says so by showing nothing.
  defp host(node) do
    case String.split(node, "@", parts: 2) do
      [_machine, host] when host != "" -> host
      _none -> nil
    end
  end

  defp name(nil), do: ""
  defp name(value) when is_binary(value), do: value
  defp name(value), do: to_string(value)

  # ------------------------------------------------------------------------------------
  # The doctor report
  # ------------------------------------------------------------------------------------

  # Flattened to text on purpose. `fleet.doctor` answers a list of checks with guidance
  # attached, and a table would have to decide which columns matter; a report keeps every
  # word the runtime wrote, in the order it wrote them.
  defp report(doctor) do
    checks = doctor |> Map.get(:checks, []) |> List.wrap()

    [headline(doctor), "" | Enum.flat_map(checks, &check_lines/1)]
    |> Enum.join("\n")
  end

  defp headline(doctor) do
    summary = Map.get(doctor, :summary, %{})

    healthy =
      case Map.get(doctor, :healthy?) do
        true -> "healthy"
        false -> "NOT HEALTHY"
        _unknown -> "health not reported"
      end

    "#{healthy} — ok #{Map.get(summary, :ok, 0)} · " <>
      "warnings #{Map.get(summary, :warnings, 0)} · " <>
      "errors #{Map.get(summary, :errors, 0)} · " <>
      "generated #{Map.get(doctor, :generated_at, "at an unreported time")}"
  end

  defp check_lines(check) do
    head =
      [
        "[#{Map.get(check, :status, "?")}]",
        check |> Map.get(:id) |> check_id(),
        check |> Map.get(:node) |> then(&if(&1, do: name(&1)))
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join("  ")

    guidance =
      case Map.get(check, :guidance) do
        text when is_binary(text) -> ["    → " <> text]
        _none -> []
      end

    [head, "    " <> to_string(Map.get(check, :message, ""))] ++ guidance ++ [""]
  end

  defp check_id(id) when is_tuple(id), do: id |> elem(0) |> to_string()
  defp check_id(nil), do: "check"
  defp check_id(id), do: to_string(id)

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    assigns = assign(assigns, :view, view(assigns.fleet, assigns.status))

    ~H"""
    <main class="ouro-page ouro-machines">
      <header class="ouro-header">
        <h1>Machines</h1>
        <p class="ouro-subhead">
          <a class="ouro-backlink" href="/">the deck</a>
        </p>
      </header>

      <p :if={@fleet_error} class="ouro-refusal">{@fleet_error}</p>

      <.roster :if={@fleet && @view.fleet?} view={@view} error={@status_error} />
      <.no_fleet :if={@fleet && not @view.fleet?} />

      <.doctor report={@doctor} error={@doctor_error} />
      <.terminal_add />
    </main>
    """
  end

  attr :view, :map, required: true
  attr :error, :any, required: true

  @doc """
  The roster panel: who this machine is, what the presence rule counted, and the members.

  Public, like the deck's own components, because the chip tones are a rule rather than a
  decoration — a test that could not render one row on its own would have to reach them
  through a live fleet, and there is no such fleet on a machine running the suite.
  """
  def roster(assigns) do
    ~H"""
    <section class="ouro-panel">
      <div class="ouro-panel-head">
        <h2>{@view.local_node}</h2>
        <button type="button" class="ouro-button" phx-click="refresh">Refresh</button>
      </div>

      <dl class="ouro-facts">
        <div class="ouro-fact">
          <dt>This machine</dt>
          <dd class="ouro-mono">
            {@view.this_machine || "not in this roster"}
            <span :if={@view.this_address}>
              · {@view.this_address}
            </span>
          </dd>
        </div>
        <div class="ouro-fact">
          <dt>Presence</dt>
          <dd class="ouro-mono">
            {@view.connected} connected · {@view.offline} offline<span :if={@view.unknown > 0}>
              · {@view.unknown} unknown
            </span>
          </dd>
        </div>
        <div :if={@view.generated_at} class="ouro-fact">
          <dt>Directory read</dt>
          <dd class="ouro-mono">{@view.generated_at}</dd>
        </div>
      </dl>

      <p :if={@error} class="ouro-refusal ouro-status-stale">{stale_status_note()} {@error}</p>

      <ul class="ouro-members">
        <.member :for={member <- @view.members} member={member} />
      </ul>

      <p class="ouro-footnote">{offline_footnote()}</p>
      <p :if={not @view.status_seen?} class="ouro-footnote">{unknown_footnote()}</p>
    </section>
    """
  end

  attr :member, :map, required: true

  @doc "One member row, name and marker over host · node, with its presence chip."
  def member(assigns) do
    ~H"""
    <li class="ouro-member">
      <div class="ouro-member-name">
        {@member.machine}
        <span :if={@member.this_machine?} class="ouro-self-mark">this machine</span>
      </div>
      <div class="ouro-member-meta ouro-mono">
        <span :if={@member.host}>{@member.host} · </span>{@member.node}
      </div>
      <span class={["ouro-chip", "ouro-chip-#{@member.presence}"]}>{@member.presence}</span>
    </li>
    """
  end

  defp no_fleet(assigns) do
    ~H"""
    <section class="ouro-panel">
      <div class="ouro-panel-head">
        <h2>{no_fleet_title()}</h2>
        <button type="button" class="ouro-button" phx-click="refresh">Refresh</button>
      </div>
      <p class="ouro-empty-body">{no_fleet_body()}</p>
    </section>
    """
  end

  attr :report, :any, required: true
  attr :error, :any, required: true

  defp doctor(assigns) do
    ~H"""
    <section class="ouro-panel ouro-doctor">
      <div class="ouro-panel-head">
        <h2>Doctor</h2>
        <button type="button" class="ouro-button-quiet" phx-click="doctor">Run doctor</button>
      </div>

      <p class="ouro-footnote">
        <code>fleet.doctor</code>
        walks the whole directory, so it runs when you ask it to and never on a cadence.
      </p>

      <p :if={@error} class="ouro-refusal">{@error}</p>
      <pre :if={@report} class="ouro-report ouro-mono">{@report}</pre>
    </section>
    """
  end

  defp terminal_add(assigns) do
    ~H"""
    <section class="ouro-panel">
      <div class="ouro-panel-head">
        <h2>Adding a machine</h2>
      </div>
      <p class="ouro-empty-body">
        Adds run in the terminal, not here. <code>ouro fleet add user@host</code>
        drives the probe, the binary copy, the invitation and enrolment over SSH from the
        machine you type it on, and the terminal client walks the same pipeline with a
        stepper under <code>ouro</code>
        → Machines. This page does not offer a form for it,
        because a form here would have to hand the daemon that SSH authority — a different
        design, not a port of this one.
      </p>
    </section>
    """
  end
end
