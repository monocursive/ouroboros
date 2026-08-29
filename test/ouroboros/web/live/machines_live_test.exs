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
      # W8. `fleet.status` carried no label until `Ouroboros.Cluster` retained the profile's
      # own `name`; `nil` is the real answer for a runtime in no named fleet, so the fixture
      # takes it as an option rather than always supplying one.
      fleet_name: Keyword.get(opts, :fleet_name),
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
  # The fleet's name (W8)
  #
  # W7 shipped without one and said so in the moduledoc: `fleet.status` answered a
  # directory and no label, so the page named the fleet by this machine's node — one member
  # standing in for the whole. `Ouroboros.Cluster` now retains the profile's `name`.
  # ------------------------------------------------------------------------------------

  describe "the fleet's name" do
    test "the header uses it when the runtime gives one" do
      view = MachinesLive.view(fleet([@local, @peer], fleet_name: "Ironworks"), status([@peer]))

      assert view.name == "Ironworks"

      html = render_component(&MachinesLive.roster/1, view: view, error: nil)
      # The roster panel is still headed by the node, which is an address: the name belongs
      # to the page, not to this machine's row in it.
      assert html =~ to_string(@local)
    end

    test "and says nothing rather than inventing one when it does not" do
      view = MachinesLive.view(fleet([@local, @peer]), status([@peer]))

      # Never the node name in its place. That substitution is the exact thing W8 fixed,
      # and a fallback here would be it again with a coat of paint.
      assert view.name == nil
    end

    test "a blank or missing name reads as unnamed" do
      for blank <- [nil, "", "   "] do
        assert MachinesLive.view(fleet([@local], fleet_name: blank), nil).name == nil
      end
    end

    test "a runtime with no fleet at all has no name to show" do
      assert MachinesLive.view(nil, nil).name == nil
    end

    test "the page draws the name it was given, and the word Machines when it has none",
         %{conn: conn} do
      # The real method, on a suite host that is in no fleet: the honest unnamed case, end
      # to end. A named one cannot be reached without a real profile, which is why the
      # projection above is tested directly.
      {:ok, _view, html} = live(conn, "/machines")

      assert html =~ "<h1>Machines</h1>"
    end
  end

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

      assert html =~ "ouro-member-chip-connected"
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

      assert html =~ "ouro-member-chip-offline"
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

      assert html =~ "ouro-member-chip-unknown"
      refute html =~ "ouro-member-chip-offline"
    end

    test "no chip is ever the attention green or the filled-button accent" do
      # Rule 1 of the stylesheet: --attention-green means "a human is needed here" and
      # nothing else. A machine being up is an outcome, and an up machine is not a button.
      css = File.read!("priv/static/web/app.css")

      for chip <- [
            ".ouro-member-chip-connected",
            ".ouro-member-chip-offline",
            ".ouro-member-chip-unknown",
            ".ouro-member-chip"
          ] do
        rule = rule_for(css, chip)

        assert rule, "#{chip} has no rule in app.css"
        refute rule =~ "attention-green", "#{chip} spends the attention green"
        refute rule =~ "button-bg", "#{chip} wears the filled-button accent"
        refute rule =~ "button-ink", "#{chip} wears the filled-button accent"
      end

      assert rule_for(css, ".ouro-member-chip-connected") =~ "var(--ink)"
      assert rule_for(css, ".ouro-member-chip-offline") =~ "var(--warn-amber)"
      assert rule_for(css, ".ouro-member-chip-unknown") =~ "var(--tertiary)"
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
      assert html =~ "ouro-member-chip-connected"
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

    test "a fleetless runtime gets the empty state naming ouro fleet create" do
      # Rendered as a component rather than through the page, because whether the machine
      # running this suite is in a fleet is not a fixed fact: a full run starts dozens of
      # distributed nodes, and the cluster directory remembers every one of them. The page
      # then correctly shows a roster, which is the *other* branch. Both must be reachable.
      html = render_component(&MachinesLive.no_fleet/1, %{})

      assert html =~ MachinesLive.no_fleet_title()
      assert html =~ "<code>ouro fleet create</code>"
      assert html =~ "open Machines in the terminal"
      # No roster, and above all no member list claiming a fleet exists.
      refute html =~ "ouro-members"
      # And no Add control, which is the whole point of the state.
      refute html =~ "<form"
      refute html =~ "<input"
    end

    test "the page shows whichever branch fleet.status actually put it in", %{conn: conn} do
      # The one assertion that survives any ambient cluster state: the page's verdict is
      # the runtime's own. `expected > 1 or strategy != :none` is how `fleet.doctor` decides
      # the same question (`lib/ouroboros/cluster.ex:1771`).
      fleet = Ouroboros.Cluster.fleet_status()
      clustered? = fleet.summary.expected > 1 or fleet.formation.strategy != :none

      {:ok, _view, html} = live(conn, "/machines")

      if clustered? do
        assert html =~ "ouro-members"
        assert html =~ MachinesLive.offline_footnote()
        refute html =~ MachinesLive.no_fleet_title()
      else
        assert html =~ MachinesLive.no_fleet_title()
        refute html =~ "ouro-members"
      end
    end

    test "no page state offers an add control", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/machines")

      refute html =~ ~s(type="submit")
      refute html =~ "<form"
      refute html =~ "<input"
    end

    test "the terminal-add section names the command and offers no form", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/machines")

      assert html =~ "Adding a machine"
      assert html =~ "Adds run in the terminal, not here"
      assert html =~ "<code>ouro fleet add user@host</code>"
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
      # The real report, rendered as the runtime wrote it. Asserted on the headline's own
      # words and the first check's id rather than on a verdict: whether this machine is
      # healthy depends on what else the suite started, and the page reports either.
      assert after_click =~ "warnings"
      assert after_click =~ "errors"
      assert after_click =~ "generated"
      assert after_click =~ "distribution"
    end

    test "the doctor report is preformatted quiet mono", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/machines")

      assert render_click(view, "doctor") =~ ~s(<pre class="ouro-report ouro-mono">)
    end

    test "refresh re-reads fleet.status and asks the doctor nothing", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/machines")

      html = render_click(view, "refresh")

      assert html =~ "Machines"
      refute html =~ "ouro-refusal"
      # Re-reading the roster must not run the doctor: that is the whole of "on demand".
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
