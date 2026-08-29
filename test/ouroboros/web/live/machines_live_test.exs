defmodule Ouroboros.Web.Live.MachinesLiveTest do
  @moduledoc """
  The machines page: the presence rules, the footnotes that keep them honest, and the two
  places the surface says "not here" instead of drawing a control that cannot work.

  ## What is real and what is not

  The page itself is driven headlessly against the real endpoint and the real method table:
  `fleet.status`, `fleet.doctor` and `runtime.status` are all invoked for real, and on the
  machine running this suite they answer the honest no-fleet shape — a directory of one
  machine and no formation strategy. That is the empty state's own test, so it is written
  against the real method rather than a stub.

  The presence rules cannot be reached that way: a suite host has no second machine, and a
  fleet of one can only ever produce the self-is-connected arm. So the projection is tested
  directly — `view/2` is pure and takes exactly the two shapes the two methods return — and
  the chips are pinned by rendering one member row as a component. What is therefore *not*
  proven here: that a real multi-node `runtime.status` names peers the way these fixtures
  do. The fixture shapes were read off `Ouroboros.Cluster.fleet_status/0` and
  `Ouroboros.status/0` on a live node rather than invented.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest
  import Plug.Conn, only: [put_req_cookie: 3]

  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Live.MachinesLive

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("m", 40)
  @cookie "_ouroboros_web"

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-machines-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    config = Config.new!(data_dir: dir, scope: :operate)
    start_supervised!({Ouroboros.Web, config: config, server: false})

    {:ok, conn: signed_in()}
  end

  defp signed_in do
    conn = get(build_conn(), "/auth?token=#{@token}")
    put_req_cookie(build_conn(), @cookie, conn.resp_cookies[@cookie].value)
  end

  # ------------------------------------------------------------------------------------
  # Fixtures, shaped after the real methods.
  #
  # `fleet.status` answers atoms for `local_node` and every `machines[].node`
  # (`lib/ouroboros/cluster.ex:381-423`), and `runtime.status` answers `Node.list()` — also
  # atoms — for `connected_nodes` (`lib/ouroboros.ex:20`). The fixtures keep the atoms,
  # because a projection that only worked on strings would pass here and fail on a fleet.
  # ------------------------------------------------------------------------------------

  @local :"ouro-anvil@anvil.tail1234.ts.net"
  @peer :"ouro-lathe@lathe.tail1234.ts.net"
  @third :"ouro-press@press.tail1234.ts.net"

  defp fleet(nodes, opts \\ []) do
    %{
      local_node: @local,
      generated_at: "2026-08-29T11:16:13.152773Z",
      monitoring_since: "2026-08-29T11:00:00.000000Z",
      summary: %{
        expected: length(nodes),
        connected: 1,
        offline: length(nodes) - 1,
        compatible: length(nodes),
        incompatible: 0
      },
      machines:
        Enum.map(nodes, fn node ->
          %{
            node: node,
            machine: node |> Atom.to_string() |> String.split(["-", "@"]) |> Enum.at(1),
            role: :core,
            state: :offline,
            expected?: true,
            runtime_running?: nil,
            compatibility: :unknown
          }
        end),
      formation: %{strategy: Keyword.get(opts, :strategy, :epmd), supervised: true},
      security: %{distributed: true, cookie: :set, tls: true}
    }
  end

  defp status(connected), do: %{node: @local, connected_nodes: connected}

  defp presence_of(view, machine),
    do: view.members |> Enum.find(&(&1.machine == machine)) |> Map.fetch!(:presence)

  # ------------------------------------------------------------------------------------
  # The presence rules, ported from `tui/src/desktop/machines.rs:107`
  # ------------------------------------------------------------------------------------

  describe "presence" do
    test "this machine is connected even though the runtime never lists itself" do
      # The rule that matters most: `connected_nodes` names only peers, so a page that
      # asked it about the local node would draw this machine offline in its own window.
      view = MachinesLive.view(fleet([@local, @peer]), status([@peer]))

      assert presence_of(view, "anvil") == :connected
      assert Enum.find(view.members, & &1.this_machine?).node == to_string(@local)
    end

    test "this machine is connected before any status has arrived" do
      view = MachinesLive.view(fleet([@local, @peer]), nil)

      assert presence_of(view, "anvil") == :connected
    end

    test "a peer the status names is connected" do
      view = MachinesLive.view(fleet([@local, @peer, @third]), status([@peer]))

      assert presence_of(view, "lathe") == :connected
    end

    test "a peer the status does not name is offline, once a status has arrived" do
      view = MachinesLive.view(fleet([@local, @peer, @third]), status([@peer]))

      assert presence_of(view, "press") == :offline
    end

    test "a status that arrived naming nobody makes every peer offline, not unknown" do
      # An empty `connected_nodes` is an answer; the absence of a status is not.
      view = MachinesLive.view(fleet([@local, @peer, @third]), status([]))

      assert presence_of(view, "lathe") == :offline
      assert presence_of(view, "press") == :offline
      assert view.status_seen?
    end

    test "before any status every peer is unknown rather than assumed offline" do
      view = MachinesLive.view(fleet([@local, @peer, @third]), nil)

      assert presence_of(view, "lathe") == :unknown
      assert presence_of(view, "press") == :unknown
      refute view.status_seen?
    end

    test "the counts are the presence rule's, not fleet.status's own summary" do
      # The fixture's summary claims one connected and two offline; the rule, with no
      # status yet, says one connected and two unknown. A header that read the summary
      # would contradict the chips underneath it.
      view = MachinesLive.view(fleet([@local, @peer, @third]), nil)

      assert view.connected == 1
      assert view.offline == 0
      assert view.unknown == 2
    end

    test "the address is the host half of the node the profile stored" do
      view = MachinesLive.view(fleet([@local, @peer]), nil)

      assert view.this_machine == "anvil"
      assert view.this_address == "anvil.tail1234.ts.net"
    end
  end

  # ------------------------------------------------------------------------------------
  # The chips
  # ------------------------------------------------------------------------------------

  describe "the presence chip" do
    test "wears its own class per presence and marks this machine" do
      html =
        render_component(&MachinesLive.member/1,
          member: %{
            machine: "anvil",
            node: "ouro-anvil@anvil.example",
            host: "anvil.example",
            this_machine?: true,
            presence: :connected
          }
        )

      assert html =~ "ouro-chip-connected"
      assert html =~ "this machine"
      assert html =~ "anvil.example"
      assert html =~ "ouro-anvil@anvil.example"
    end

    test "a peer carries no this-machine marker" do
      html =
        render_component(&MachinesLive.member/1,
          member: %{
            machine: "lathe",
            node: "ouro-lathe@lathe.example",
            host: "lathe.example",
            this_machine?: false,
            presence: :offline
          }
        )

      assert html =~ "ouro-chip-offline"
      refute html =~ "this machine"
    end

    test "unknown has a chip of its own rather than borrowing offline's" do
      html =
        render_component(&MachinesLive.member/1,
          member: %{
            machine: "press",
            node: "ouro-press@press.example",
            host: "press.example",
            this_machine?: false,
            presence: :unknown
          }
        )

      assert html =~ "ouro-chip-unknown"
      refute html =~ "ouro-chip-offline"
    end

    test "no chip is ever the attention green or the filled-button accent" do
      # Rule 1 of the stylesheet: --attention-green means "a human is needed here" and
      # nothing else. A machine being up is an outcome, and an up machine is not a button.
      css = File.read!("priv/static/web/app.css")

      for chip <- [
            ".ouro-chip-connected",
            ".ouro-chip-offline",
            ".ouro-chip-unknown",
            ".ouro-chip"
          ] do
        rule = rule_for(css, chip)

        assert rule, "#{chip} has no rule in app.css"
        refute rule =~ "attention-green", "#{chip} spends the attention green"
        refute rule =~ "button-bg", "#{chip} wears the filled-button accent"
        refute rule =~ "button-ink", "#{chip} wears the filled-button accent"
      end

      assert rule_for(css, ".ouro-chip-connected") =~ "var(--ink)"
      assert rule_for(css, ".ouro-chip-offline") =~ "var(--warn-amber)"
      assert rule_for(css, ".ouro-chip-unknown") =~ "var(--tertiary)"
    end
  end

  # A selector's own block, so a `refute ... =~` cannot be satisfied or defeated by a
  # neighbouring rule that happens to sit near it in the file.
  defp rule_for(css, selector) do
    case Regex.run(~r/(?<!-)#{Regex.escape(selector)}\s*\{([^}]*)\}/, css) do
      [_whole, body] -> body
      nil -> nil
    end
  end

  # ------------------------------------------------------------------------------------
  # The footnotes
  # ------------------------------------------------------------------------------------

  describe "the footnotes" do
    test "the roster says what offline is allowed to mean" do
      html = roster_html(MachinesLive.view(fleet([@local, @peer]), status([])))

      assert html =~ "Offline means this runtime is not connected to that node"
      assert html =~ "not that the machine is down"
      assert html =~ "no reachability probe of its own"
    end

    test "the roster says peers are unknown rather than offline before a status" do
      html = roster_html(MachinesLive.view(fleet([@local, @peer]), nil))

      assert html =~ "No runtime status has arrived yet"
      assert html =~ "rather than assumed offline"
    end

    test "the unknown footnote is dropped once a status has arrived" do
      html = roster_html(MachinesLive.view(fleet([@local, @peer]), status([@peer])))

      refute html =~ "No runtime status has arrived yet"
      # The offline sentence stays: it is true whether or not a status arrived.
      assert html =~ "Offline means this runtime is not connected to that node"
    end

    test "a refused status keeps the last presence and says the refresh failed" do
      html =
        roster_html(
          MachinesLive.view(fleet([@local, @peer]), status([@peer])),
          "fleet is unreachable"
        )

      assert html =~ MachinesLive.stale_status_note()
      assert html =~ "as of the last one that answered"
      assert html =~ "fleet is unreachable"
      # The chips are still drawn: a refused refresh is not a reason to forget what was
      # known, only a reason to say the page is not current.
      assert html =~ "ouro-chip-connected"
    end
  end

  defp roster_html(view, error \\ nil),
    do: render_component(&MachinesLive.roster/1, view: view, error: error)

  # ------------------------------------------------------------------------------------
  # The page, against the real methods
  # ------------------------------------------------------------------------------------

  describe "the page" do
    test "mounts and names itself", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/machines")

      assert html =~ "Machines"
    end

    test "a fleetless runtime gets the empty state naming ouro fleet create", %{conn: conn} do
      # The real `fleet.status` on a suite host: one machine, no formation strategy.
      {:ok, _view, html} = live(conn, "/machines")

      assert html =~ "This machine runs on its own"
      assert html =~ "ouro fleet create"
      assert html =~ "Machines"
      # No roster, and above all no member list claiming a fleet exists.
      refute html =~ "ouro-members"
    end

    test "the empty state offers no add control", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/machines")

      refute html =~ ~s(type="submit")
      refute html =~ "<form"
      refute html =~ "<input"
    end

    test "the terminal-add section names the command and offers no form", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/machines")

      assert html =~ "Adding a machine"
      assert html =~ "Adds run in the terminal, not here"
      assert html =~ "ouro fleet add user@host"
      refute html =~ "<form"
    end

    test "the doctor report appears only when asked for", %{conn: conn} do
      {:ok, view, html} = live(conn, "/machines")

      # Mounted, polled — and no report, because `fleet.doctor` walks the whole directory
      # and this page never puts that on a cadence.
      assert html =~ "Run doctor"
      refute html =~ "ouro-report"

      after_click = render_click(view, "doctor")

      assert after_click =~ "ouro-report"
      # The real report, rendered as the runtime wrote it.
      assert after_click =~ "healthy"
      assert after_click =~ "distribution"
    end

    test "the doctor report is preformatted quiet mono", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/machines")

      assert render_click(view, "doctor") =~ ~s(<pre class="ouro-report ouro-mono">)
    end

    test "refresh re-reads fleet.status without disturbing anything else", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/machines")

      html = render_click(view, "refresh")

      assert html =~ "This machine runs on its own"
      refute html =~ "ouro-report"
    end

    test "a poll refreshes the status and the view survives it", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/machines")

      send(view.pid, :poll)

      assert render(view) =~ "Machines"
      assert Process.alive?(view.pid)
    end
  end
end
