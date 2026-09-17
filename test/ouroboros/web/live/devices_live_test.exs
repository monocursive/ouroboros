defmodule Ouroboros.Web.Live.DevicesLiveTest do
  @moduledoc """
  `/devices`, driven the way an operator drives it, with no SSH anywhere in it.

  The fakes are the point. `Ouroboros.Test.FleetOuroFake` is a real executable file at a
  real absolute path, so `fleet.devices` really forks something and really parses what it
  printed; `Ouroboros.Test.FleetWorkerFake` is a real Unix socket speaking seam S3, so a
  challenge this page renders is a challenge that crossed a wire, and a secret this page
  submits is one a test can watch arrive. Neither is a stub standing in for the mechanism:
  the fake worker **refuses every frame it did not expect** and counts the refusal, so a
  test that passed because nothing was sent fails instead.

  Not async: it moves `config :ouroboros, :data_dir`, `config :ouroboros, :audit` and the
  `OUROBOROS_PROCESS_ID_HELPER` environment variable, all of which are node-global.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  import ExUnit.CaptureLog
  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Audit.Config, as: AuditConfig
  alias Ouroboros.Test.FleetOuroFake
  alias Ouroboros.Test.FleetWorkerFake
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Live.Devices
  alias Ouroboros.Web.Live.DevicesLive

  @endpoint Ouroboros.Web.Endpoint
  @token String.duplicate("d", 40)
  @cookie "_ouroboros_web"
  @receive_timeout 5_000

  # The inventory every rendering test reads. One row per branch of the proposal's
  # observed-state table that this build can reach, including the device that has taken a
  # roster machine's name.
  @devices %{
    "fleet_protocol_revision" => 5,
    "discovery" => %{
      "code" => "ok",
      "reason" => nil,
      "detail" => nil,
      "client" => %{"version" => "1.80.0"},
      "self" => %{"name" => "studio"},
      "visible_peers" => 3
    },
    "devices" => [
      %{
        "name" => "studio",
        "machine" => "studio",
        "os" => "macos",
        "address" => "100.64.0.1",
        "online" => true,
        "last_seen" => nil,
        "path" => "direct",
        "state" => "this_device",
        "action" => "view device",
        "name_conflicts_with_roster" => nil
      },
      %{
        "name" => "spare",
        "machine" => nil,
        "os" => "linux",
        "address" => "100.64.0.7",
        "online" => true,
        "last_seen" => nil,
        "path" => "direct",
        "state" => "this_device_without_profile",
        "action" => "set up this device",
        "name_conflicts_with_roster" => nil
      },
      %{
        "name" => "buildbox",
        "machine" => "buildbox",
        "os" => nil,
        "address" => "100.64.0.2",
        "online" => nil,
        "last_seen" => nil,
        "path" => "unknown",
        "state" => "fleet_member_not_visible",
        "action" => "diagnose",
        "name_conflicts_with_roster" => nil
      },
      %{
        "name" => "vps-1",
        "machine" => nil,
        "os" => "linux",
        "address" => "100.64.12.44",
        "online" => true,
        "last_seen" => "2026-09-16T10:00:00Z",
        "path" => "relayed",
        "state" => "discovered_installation_unknown",
        "action" => "deploy Ouroboros",
        "name_conflicts_with_roster" => nil
      },
      %{
        "name" => "studio",
        "machine" => nil,
        "os" => "linux",
        "address" => "100.64.9.9",
        "online" => true,
        "last_seen" => nil,
        "path" => "direct",
        "state" => "discovered_installation_unknown",
        "action" => "deploy Ouroboros",
        "name_conflicts_with_roster" => "studio"
      },
      %{
        "name" => "toaster",
        "machine" => nil,
        "os" => "plan9",
        "address" => "100.64.0.5",
        "online" => false,
        "last_seen" => "2026-09-01T00:00:00Z",
        "path" => "unknown",
        "state" => "unsupported_platform",
        "action" => "nothing to deploy",
        "name_conflicts_with_roster" => nil
      }
    ]
  }

  setup do
    root = Path.join(System.tmp_dir!(), "ouro-w3a-#{System.unique_integer([:positive])}")
    Ouroboros.DataDir.ensure_private!(root)
    fake_dir = Path.join(root, "bin")

    previous = %{
      data_dir: Application.get_env(:ouroboros, :data_dir),
      audit: Application.get_env(:ouroboros, :audit),
      web: Application.get_env(:ouroboros, :web),
      ouro: System.get_env("OUROBOROS_PROCESS_ID_HELPER")
    }

    Application.put_env(:ouroboros, :data_dir, root)

    on_exit(fn ->
      restore(:data_dir, previous.data_dir)
      restore(:audit, previous.audit)
      restore(:web, previous.web)

      if previous.ouro,
        do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous.ouro),
        else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      File.rm_rf!(root)
    end)

    %{root: root, fake_dir: fake_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  # ------------------------------------------------------------------------------------
  # Fixtures
  # ------------------------------------------------------------------------------------

  # The fleet CA private key is what makes this machine an issuer, which is the first thing
  # `capabilities.deploy` asks about. A file, because that is what the broker `lstat`s.
  defp issuer!(root) do
    dir = Path.join(root, "fleet")
    File.mkdir_p!(dir)
    File.write!(Path.join(dir, "ca-key.pem"), "not a key, and never read as one\n")
    File.chmod!(Path.join(dir, "ca-key.pem"), 0o600)
  end

  defp ouro!(context, opts \\ []) do
    document = Keyword.get(opts, :devices, @devices)

    path =
      FleetOuroFake.write!(
        context.fake_dir,
        Keyword.merge([devices: JSON.encode!(document) <> "\n"], Keyword.drop(opts, [:devices]))
      )

    System.put_env("OUROBOROS_PROCESS_ID_HELPER", path)
    path
  end

  defp worker!(context) do
    cap = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
    instance = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    socket_path = Path.join([context.root, "deploy", "w.sock"])

    worker =
      start_supervised!(
        {FleetWorkerFake,
         [
           socket_path: socket_path,
           cap: cap,
           instance: instance,
           operation_file: FleetOuroFake.operation_file(context.fake_dir),
           owner: self()
         ]},
        id: {FleetWorkerFake, System.unique_integer([:positive])}
      )

    ouro!(context, spawn_line: FleetWorkerFake.spawn_line(worker), cap: cap)
    worker
  end

  defp web!(context, opts \\ []) do
    token = Keyword.get(opts, :token, @token)
    token_path = Path.join(context.root, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)

    config = Config.new!(data_dir: context.root, scope: Keyword.get(opts, :scope, :operate))
    start_supervised!({Ouroboros.Web, config: config, server: false})
    freeze_recovery()

    conn = get(build_conn(), "/auth?token=#{token}")
    put_req_cookie(build_conn(), @cookie, conn.resp_cookies[@cookie].value)
  end

  # The same parking the deck's suite does, and for the same reason: this file moves
  # `:data_dir` under a running node, and the sweep would otherwise adopt whatever durable
  # rows another suite left in the directory it was pointed at.
  defp freeze_recovery do
    case Process.whereis(Ouroboros.Interactive.Recovery) do
      nil ->
        :ok

      pid ->
        :ok = :sys.suspend(pid)
        on_exit(fn -> if Process.alive?(pid), do: :sys.resume(pid) end)
    end
  end

  defp identities!(context) do
    config =
      AuditConfig.new!(
        mode: :local,
        capture: :full,
        root: Path.join(context.root, "evidence"),
        writer_id: "w3a-devices-test",
        identities: [
          identity("adele", ["administrator"], "administrator-token"),
          identity("olive", ["operator"], "operator-token")
        ]
      )

    Application.put_env(:ouroboros, :audit, config)
    config
  end

  defp identity(id, roles, token) do
    %{
      "id" => id,
      "roles" => roles,
      "token_sha256" => :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
    }
  end

  # The page reads a live worker, so what it renders lags the frame by a message or two.
  # Polling `render/1` is the honest wait: it is the same HTML a person would be looking at.
  defp await(view, needle, message \\ nil) do
    Enum.reduce_while(1..100, :missing, fn _attempt, _acc ->
      html = render(view)

      if html =~ needle do
        {:halt, html}
      else
        Process.sleep(20)
        {:cont, :missing}
      end
    end)
    |> case do
      :missing -> flunk(message || "the page never rendered #{inspect(needle)}")
      html -> html
    end
  end

  defp prepared(view, address \\ "100.64.12.44", user \\ "deploy") do
    view
    |> element(~s{button[phx-click="deploy"][phx-value-address="#{address}"]})
    |> render_click()

    view
    |> form("#ouro-deploy-connect", %{"address" => address, "ssh_user" => user})
    |> render_submit()

    assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
    operation(view)
  end

  defp operation(view), do: :sys.get_state(view.pid).socket.assigns.drawer.operation

  # Kill the connection process and wait until the broker has stopped holding it. Both
  # halves matter: the process dying is what makes the operation resumable, and the broker
  # noticing is what makes `resume` answer something other than `already_attached`.
  defp detach!(operation) do
    {:ok, pid} = Ouroboros.Fleet.Deployment.client(operation)
    reference = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^reference, :process, ^pid, _reason}, @receive_timeout

    Enum.reduce_while(1..100, :attached, fn _attempt, _acc ->
      case Ouroboros.Fleet.Deployment.client(operation) do
        {:error, :no_worker} ->
          {:halt, :ok}

        _still_there ->
          Process.sleep(20)
          {:cont, :attached}
      end
    end)
    |> case do
      :ok -> :ok
      :attached -> flunk("the broker never let go of operation #{operation}")
    end
  end

  # The worker's durable record, as this runtime would find it after an interruption.
  #
  # `owner` defaults to the identity this test is asking as, because the broker's resume
  # rule is strict about it: an operation whose owner it cannot match — including one it
  # cannot establish at all — is not resumed without an explicit takeover. A fixture that
  # left the field out would be testing the takeover path by accident.
  defp journal!(root, operation, document) do
    dir = Path.join(root, "deploy")
    File.mkdir_p!(dir)
    File.chmod!(dir, 0o700)
    path = Path.join(dir, operation <> ".json")

    body =
      document
      |> Map.put("operation", operation)
      |> Map.put_new("owner", Ouroboros.Audit.Identity.actor())

    File.write!(path, JSON.encode!(body))
    File.chmod!(path, 0o600)
    path
  end

  # ------------------------------------------------------------------------------------
  # The inventory
  # ------------------------------------------------------------------------------------

  describe "the inventory" do
    setup context do
      issuer!(context.root)
      ouro!(context)
      %{conn: web!(context)}
    end

    test "names the deployment host and says the work happens there", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "Deploying from "
      assert html =~ "local user "
      assert html =~ "data-ouro-deployment-host"

      # The proposal's "Which machine performs the work": a browser cannot lend its own
      # laptop's SSH agent to the runtime, and the page has to say so before anything is
      # typed.
      assert html =~ "not on the computer showing this page"
    end

    test "draws the two sections, with the state in words and the code in data",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "Fleet devices"
      assert html =~ "Available on this network"

      # The words are the proposal's table; the codes are data attributes and nothing else.
      assert html =~ "Discovered peer; Ouroboros installation unknown"
      assert html =~ "Known member disconnected from this runtime"
      assert html =~ ~s(data-state="discovered_installation_unknown")
      assert html =~ ~s(data-state="fleet_member_not_visible")

      # A row's own state text must never be the raw code.
      refute html =~ ">discovered_installation_unknown<"
      refute html =~ ">fleet_member_not_visible<"
    end

    test "gives the state column screen-reader text rather than colour alone", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ ~s(<span class="ouro-visually-hidden">Ouroboros state:</span>)
      assert html =~ ~s(<span class="ouro-visually-hidden">Network presence:</span>)
    end

    test "says when a device was last seen, and never calls unreported presence offline",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      # `toaster` is offline and the client said when it last saw it; `vps-1` is connected
      # now over a relay, which is a working route rather than a failure; `buildbox` has no
      # presence reported at all, which is not the same fact as being offline.
      assert html =~ "last seen 2026-09-01T00:00:00Z"
      assert html =~ "through a relay, which is a working route"
      assert html =~ "Presence not reported by the network client"
    end

    test "renders a roster name collision as a note rather than merging the row",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "This device calls itself studio, which is the name of a machine in"
      assert html =~ "It is not that machine."

      # And the impostor is still its own row under "Available", with its own address.
      assert html =~ ~s(data-address="100.64.9.9")
    end

    test "carries the proposal's observed-state table verbatim as a legend", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      for {observed, action} <- Devices.observed_states() do
        assert html =~ observed, "the legend does not carry #{inspect(observed)}"
        assert html =~ action, "the legend does not carry #{inspect(action)}"
      end
    end

    test "searches by name and by address", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      html = render_change(view, "search", %{"query" => "vps"})
      assert html =~ "vps-1"
      refute html =~ "toaster"

      html = render_change(view, "search", %{"query" => "100.64.0.5"})
      assert html =~ "toaster"
      refute html =~ "vps-1"

      html = render_change(view, "search", %{"query" => ""})
      assert html =~ "vps-1"
      assert html =~ "toaster"
    end

    test "filters to one section at a time", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      html = render_click(view, "filter", %{"filter" => "fleet"})
      assert html =~ "Fleet devices"
      refute html =~ "Available on this network"

      html = render_click(view, "filter", %{"filter" => "available"})
      assert html =~ "Available on this network"
      refute html =~ ~s(id="fleet-devices")

      html = render_click(view, "filter", %{"filter" => "all"})
      assert html =~ "Fleet devices"
      assert html =~ "Available on this network"
    end

    test "refreshes by asking again", %{conn: conn, fake_dir: fake_dir} = context do
      {:ok, view, html} = live(conn, "/devices")
      assert html =~ "vps-1"

      ouro!(context, devices: put_in(@devices["devices"], []))
      _ = fake_dir

      html = render_click(view, "refresh", %{})
      refute html =~ "vps-1"
      assert html =~ "No other device is visible to this machine"
    end

    test "offers Deploy on an uninspected peer and never on a blocked one", %{conn: conn} do
      {:ok, view, html} = live(conn, "/devices")

      assert html =~ "Deploy Ouroboros"
      assert has_element?(view, ~s{button[phx-value-address="100.64.12.44"]})

      # `unsupported_platform` is the table's fifth row: the blocker is explained and
      # deployment is disabled while it stands.
      refute has_element?(view, ~s{button[phx-value-address="100.64.0.5"]})
      assert html =~ "Deployment is disabled for this device while that blocker stands."

      # A known member is not a deployment target either; it gets its own action word.
      refute has_element?(view, ~s{button[phx-value-address="100.64.0.2"]})
      assert html =~ "Diagnose"
    end

    test "takes a manual destination through the same form", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      html = render_click(view, "deploy-manual", %{})

      assert html =~ "Private address"
      assert html =~ "SSH username on the target"
      assert has_element?(view, "#deploy-address[required]")

      # Empty, because nothing was selected — and validated by the same path a chosen
      # device takes rather than by a second one.
      assert has_element?(view, ~s{#deploy-address[value=""]})
    end

    test "the drawer is a dialog a keyboard can leave", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      html =
        view
        |> element(~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})
        |> render_click()

      assert html =~ ~s(aria-modal="true")
      assert html =~ ~s(aria-labelledby="ouro-deploy-title")
      # `Modal` is the hook that opens it, restores focus when it closes, and turns the
      # browser's own Escape into this event.
      assert html =~ ~s(phx-hook="Modal")
      assert html =~ ~s(data-cancel-event="drawer-close")
      assert html =~ ~s(aria-live="polite")
    end

    test "links Devices from the top bar and marks it as the page being read",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ ~s(href="/devices")
      assert Regex.run(~r/href="\/devices"[^>]*aria-current="page"/, html)
      assert length(String.split(html, ~s(aria-current="page"))) - 1 == 1
    end
  end

  # ------------------------------------------------------------------------------------
  # Discovery
  # ------------------------------------------------------------------------------------

  describe "discovery" do
    setup context do
      issuer!(context.root)
      :ok
    end

    for {code, needle} <- [
          {"client_missing", "No network client is installed on this deployment host."},
          {"signed_out", "installed and this deployment host is signed out"},
          {"permission_denied", "refused this runtime"},
          {"unavailable", "is installed and could not answer"},
          {"no_visible_peers", "can see no other devices"}
        ] do
      test "#{code} has an empty state of its own", context do
        code = unquote(code)
        needle = unquote(needle)

        document = %{
          @devices
          | "discovery" => %{
              "code" => code,
              "reason" => nil,
              "detail" => "the adapter said this",
              "client" => nil,
              "self" => nil,
              "visible_peers" => 0
            }
        }

        ouro!(context, devices: document)
        conn = web!(context)

        {:ok, _view, html} = live(conn, "/devices")

        assert html =~ needle
        assert html =~ ~s(data-discovery="#{code}")
        assert html =~ "the adapter said this"
      end
    end

    test "keeps known members when discovery could not answer", context do
      document = %{
        @devices
        | "discovery" => %{
            "code" => "unavailable",
            "reason" => nil,
            "detail" => nil,
            "client" => nil,
            "self" => nil,
            "visible_peers" => 0
          }
      }

      ouro!(context, devices: document)
      conn = web!(context)

      {:ok, _view, html} = live(conn, "/devices")

      # The fleet half of the listing is this machine's own roster, so it stands even when
      # nothing could be discovered — and the page says so rather than implying an empty
      # fleet.
      assert html =~ "buildbox"
      assert html =~ "is installed and could not answer"
      assert html =~ "This is not evidence that the fleet has no members."
    end

    test "a successful discovery draws no empty state at all", context do
      ouro!(context)
      conn = web!(context)

      {:ok, _view, html} = live(conn, "/devices")

      refute html =~ "ouro-devices-discovery"
    end
  end

  # ------------------------------------------------------------------------------------
  # Capability, scope and identity
  # ------------------------------------------------------------------------------------

  describe "when deployment is unavailable" do
    test "a machine with no certificate authority key is told which machine to open",
         context do
      ouro!(context)
      conn = web!(context)

      {:ok, view, html} = live(conn, "/devices")

      refute has_element?(view, ~s{button[phx-click="deploy"]})
      assert html =~ "does not hold the fleet"
      assert html =~ "Open Devices on the machine that created the fleet."
    end

    test "a cleartext non-loopback endpoint refuses credential entry and says so",
         context do
      issuer!(context.root)
      ouro!(context)
      Application.put_env(:ouroboros, :web, enabled: true, bind: "0.0.0.0", allow_remote: true)
      conn = web!(context)

      {:ok, view, html} = live(conn, "/devices")

      refute has_element?(view, ~s{button[phx-click="deploy"]})
      assert html =~ "credential entry is refused here"
      assert html =~ "tailscale serve"
    end

    test "a read-scope endpoint says it is the scope, and still shows membership",
         context do
      issuer!(context.root)
      ouro!(context)
      conn = web!(context, scope: :read)

      {:ok, view, html} = live(conn, "/devices")

      # The inventory itself is read-scoped, so it is still there; what a read endpoint
      # cannot do is start one.
      assert html =~ "Fleet devices"
      refute has_element?(view, ~s{button[phx-click="deploy"]})
      assert html =~ "OUROBOROS_WEB_SCOPE=read"
      assert html =~ "cannot start a setup or answer a credential prompt"

      assert DevicesLive.availability(:read, "fleet.deployment.prepare") == :scope
      assert DevicesLive.availability(:read, "fleet.devices") == :available
    end

    test "a non-administrator is told it is permission, not capability", context do
      issuer!(context.root)
      ouro!(context)
      identities!(context)
      conn = web!(context, token: "operator-token")

      {:ok, view, html} = live(conn, "/devices")

      assert html =~ "is not an administrator"
      assert html =~ "every machine on an operator"
      refute html =~ "This runtime does not serve fleet.devices"
      refute has_element?(view, ~s{button[phx-click="deploy"]})

      # And the fallback the proposal names: the `fleet.status` membership subset.
      assert html =~ "Machines"
    end

    test "capability absent and permission denied are different sentences", context do
      issuer!(context.root)
      ouro!(context)
      identities!(context)
      conn = web!(context, token: "operator-token")

      {:ok, _view, html} = live(conn, "/devices")

      assert DevicesLive.availability(:operate, "fleet.devices") in [:denied, :available]
      refute html =~ "It is an older build than this page"

      # The wording for a build that does not serve the method at all is a different
      # sentence from the one a refused identity gets, which is the distinction acceptance
      # item 14 asks for.
      assert Devices.unavailable(:absent, "fleet.devices") =~ "does not serve fleet.devices"
      assert Devices.unavailable(:denied, "fleet.devices") =~ "not an administrator"
      assert Devices.unavailable(:scope, "fleet.devices") =~ "OUROBOROS_WEB_SCOPE=read"

      # And the absent branch is reachable: a method this build does not serve at all.
      assert DevicesLive.availability(:operate, "fleet.devices.that.does.not.exist") == :absent
    end
  end

  # ------------------------------------------------------------------------------------
  # The deploy drawer
  # ------------------------------------------------------------------------------------

  describe "the deploy drawer" do
    setup context do
      issuer!(context.root)
      worker = worker!(context)
      %{conn: web!(context), worker: worker}
    end

    test "asks for the SSH username, and never infers it", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      html =
        view
        |> element(~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})
        |> render_click()

      assert html =~ "SSH username on the target"
      assert html =~ "never inferred from the network client"
      assert has_element?(view, ~s{#deploy-ssh-user[required]})

      # Port, identity and paths are the advanced fields the proposal puts behind a
      # disclosure rather than in front of every deployment.
      assert html =~ "Advanced — port, identity and paths"
      assert has_element?(view, "#deploy-port")
      assert has_element?(view, "#deploy-identity-kind")
      assert has_element?(view, "#deploy-install-path")
    end

    test "prepares an operation and puts its id in the address, not its secrets",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      assert String.match?(operation, ~r/\A[0-9a-f]{16}\z/)
      assert_patched(view, "/devices?operation=#{operation}")
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "sends the verb's own parameters, and a target named by address",
         %{conn: conn, fake_dir: fake_dir} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      # What actually reached `ouro fleet worker start` — the request file the broker wrote
      # and the fake worker read. `kind`, an address, an account, and no secret of any shape.
      request = JSON.decode!(FleetOuroFake.request_body(fake_dir))

      assert request["kind"] == "add"
      assert request["address"] == "100.64.12.44"
      assert request["ssh_user"] == "deploy"
      refute Map.has_key?(request, "peer_id")

      for key <- ~w(secret password passphrase), do: refute(Map.has_key?(request, key))
    end

    test "sets this device up locally, with no account and no target",
         %{conn: conn, fake_dir: fake_dir} do
      {:ok, view, _html} = live(conn, "/devices")

      html =
        view
        |> element(~s{button[phx-click="setup-device"][phx-value-address="100.64.0.7"]})
        |> render_click()

      assert html =~ "Set up this device"
      assert html =~ "This machine configures itself. No SSH connection is made to it"
      assert html =~ "This runtime restarts as part of this setup."

      # No account field at all: asking for one would be this page proposing to SSH to the
      # machine it is already running on.
      refute has_element?(view, "#deploy-ssh-user")
      assert has_element?(view, "#setup-machine")
      assert has_element?(view, "#setup-address")

      view
      |> form("#ouro-deploy-setup", %{"machine" => "studio", "address" => "100.64.0.7"})
      |> render_submit()

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      request = JSON.decode!(FleetOuroFake.request_body(fake_dir))
      assert request["kind"] == "setup"
      assert request["machine"] == "studio"
      assert request["address"] == "100.64.0.7"
      refute Map.has_key?(request, "ssh_user")
      refute Map.has_key?(request, "target")
    end

    test "renders a host-trust challenge from its metadata, with the verify guidance",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      :ok =
        FleetWorkerFake.challenge(worker, "ht-1", "host_trust", %{
          "algorithm" => "ssh-ed25519",
          "sha256_fingerprint" => "SHA256:5s0mEfIngeRPrinT",
          "address" => "100.64.12.44",
          "port" => 22,
          "user" => "deploy",
          "peer" => "vps-1"
        })

      html = await(view, "SHA256:5s0mEfIngeRPrinT")

      assert html =~ "Verify this host before continuing"
      assert html =~ "ssh-ed25519"
      assert html =~ "100.64.12.44"
      assert html =~ "deploy"
      assert html =~ "Verify this fingerprint independently"
      assert html =~ "Trust this host and continue"

      view
      |> element(~s{button[phx-value-challenge="ht-1"][phx-value-accept="true"]})
      |> render_click()

      assert_receive {:fake_worker, %{"op" => "respond"} = frame}, @receive_timeout
      assert frame["challenge"] == "ht-1"
      assert frame["response"] == %{"accept" => true}
      assert FleetWorkerFake.refusals(worker) == 0
      assert operation != nil
    end

    test "refusing a host key sends the refusal rather than nothing",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.challenge(worker, "ht-2", "host_trust", %{})
      _html = await(view, "Verify this host before continuing")

      view
      |> element(~s{button[phx-value-challenge="ht-2"][phx-value-accept="false"]})
      |> render_click()

      assert_receive {:fake_worker, %{"op" => "respond"} = frame}, @receive_timeout
      assert frame["response"] == %{"accept" => false}
    end

    for kind <- ["password", "passphrase"] do
      test "a #{kind} challenge draws a masked field with no change event",
           %{conn: conn, worker: worker} do
        kind = unquote(kind)
        {:ok, view, _html} = live(conn, "/devices")
        _operation = prepared(view)

        :ok =
          FleetWorkerFake.challenge(worker, "c-1", kind, %{
            "user" => "deploy",
            "host" => "100.64.12.44",
            "key" => "/home/ouro/.ssh/id_ed25519",
            "attempt" => 1,
            "attempts_allowed" => 3
          })

        html = await(view, "Send this credential")

        assert html =~ ~s(type="password")
        assert html =~ "data-ouro-secret"
        assert html =~ "Attempt 1 of 3."
        assert html =~ "not stored, not remembered for a reconnection"

        # The one rule the proposal states about this form: no change event, because a
        # change event on a password field streams every keystroke to this server.
        [form] = Regex.run(~r{<form id="ouro-deploy-auth"[^>]*>}, html)
        refute form =~ "phx-change"
      end
    end

    test "a secret is submitted once and is nowhere afterwards",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.challenge(worker, "pw-1", "password", %{"user" => "deploy"})
      _html = await(view, "Send this credential")

      secret = "w3a-unique-password-#{System.unique_integer([:positive])}"

      log =
        capture_log(fn ->
          view
          |> form("#ouro-deploy-auth", %{"secret" => secret})
          |> render_submit()

          # It reached the worker, which is the only proof that the path works at all: a
          # test that could not see the secret arrive could not prove it arrived.
          assert_receive {:fake_worker, %{"op" => "respond"} = frame}, @receive_timeout
          assert frame["response"]["secret"] == secret
        end)

      # And now the three places it must not be.
      refute render(view) =~ secret

      state = :sys.get_state(view.pid)
      dumped = inspect(state, limit: :infinity, printable_limit: :infinity, structs: false)
      refute dumped =~ secret, "the secret is somewhere in the LiveView's own state"

      refute log =~ secret, "the secret reached a log line"

      # The audit line for this verb is written and is the redacted one.
      assert log =~ "fleet.deployment.authenticate"
      assert log =~ "redacted"

      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "the field is replaced after a submission rather than left holding the value",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.challenge(worker, "pw-2", "password", %{})
      before = await(view, "ouro-deploy-secret-0")

      assert before =~ ~s(id="ouro-deploy-secret-0")

      view |> form("#ouro-deploy-auth", %{"secret" => "one"}) |> render_submit()
      assert_receive {:fake_worker, %{"op" => "respond"}}, @receive_timeout

      :ok = FleetWorkerFake.challenge(worker, "pw-3", "password", %{})
      after_html = await(view, "ouro-deploy-secret-1")

      # A new id is a new element, which is how the browser is made to drop what was typed
      # rather than patch a value back into it.
      assert after_html =~ ~s(id="ouro-deploy-secret-1")
      refute after_html =~ ~s(id="ouro-deploy-secret-0")
    end

    test "a refused credential is shown as a sentence, not a reason code",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.challenge(worker, "pw-4", "password", %{})
      _html = await(view, "Send this credential")

      :ok = FleetWorkerFake.refuse_next(worker, "authentication_failed")

      html =
        view
        |> form("#ouro-deploy-auth", %{"secret" => "wrong"})
        |> render_submit()

      assert html =~ "the deployment worker refused the request"
      refute html =~ ~s(>worker_refused<)
    end

    test "review shows the plan and approves exactly its digest",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      :ok =
        FleetWorkerFake.challenge(worker, "rev-1", "review", %{
          "plan" => %{
            "release" => "0.1.8",
            "machine" => "vps-1",
            "install_path" => "/usr/local/bin/ouro",
            "restarts" => ["studio"],
            "trust" => "this fleet's certificate authority signs the new member"
          },
          "plan_digest" => "sha256-of-the-plan"
        })

      html = await(view, "sha256-of-the-plan")

      assert html =~ "Review this plan"
      assert html =~ "0.1.8"
      assert html =~ "/usr/local/bin/ouro"
      assert html =~ "this fleet&#39;s certificate authority signs the new member"

      view |> element(~s{button[phx-click="approve"]}) |> render_click()

      assert_receive {:fake_worker, %{"op" => "respond"} = frame}, @receive_timeout
      assert frame["challenge"] == "rev-1"
      assert frame["response"] == %{"approve" => true, "plan_digest" => "sha256-of-the-plan"}

      # The idempotency key is the drawer's, stable for the operation, so a repeated
      # approval replays rather than starting a second deployment.
      assert :sys.get_state(view.pid).socket.assigns.drawer.approval_key =~
               ~r/\Aweb-[0-9a-f]{24}\z/

      assert operation != nil
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "a plan with no digest is not approvable at all", %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.challenge(worker, "rev-2", "review", %{"plan" => %{"release" => "x"}})
      html = await(view, "Review this plan")

      refute has_element?(view, ~s{button[phx-click="approve"]})
      assert html =~ "did not name a digest for this plan"
      assert html =~ "no digest reported"
    end

    test "progress draws the six stages and announces each step politely",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.emit(worker, %{"event" => "state", "state" => "deploying"})
      _ = await(view, "Deploying")

      :ok =
        FleetWorkerFake.emit(worker, %{
          "event" => "step",
          "name" => "install",
          "outcome" => "ok",
          "detail" => "0.1.8 from the official release"
        })

      html = await(view, "0.1.8 from the official release")

      # Every stage the proposal names, and the ones nothing has reported say so rather
      # than claiming a result.
      for {_key, label} <- Devices.stages(), do: assert(html =~ label)
      assert html =~ "not reported yet"
      assert html =~ ~s(data-step="install")

      # The live region is polite and carries the last change in words.
      assert html =~ ~s(aria-live="polite")
      assert html =~ "install: done."
    end

    test "a failure keeps the completed steps, names the cause and offers a retry",
         %{conn: conn, worker: worker, root: root} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      :ok =
        FleetWorkerFake.emit(worker, %{
          "event" => "step",
          "name" => "inspect",
          "outcome" => "ok"
        })

      :ok =
        FleetWorkerFake.emit(worker, %{
          "event" => "done",
          "state" => "failed",
          "error" => "the target refused the connection"
        })

      html = await(view, "Failed")

      assert html =~ "the target refused the connection"
      assert html =~ "Retry"
      assert html =~ ~s(data-step="inspect")

      # Retrying means resuming, and resuming needs the previous worker to be gone — which
      # is exactly the state an interrupted operation is in.
      journal!(root, operation, %{"state" => "failed", "kind" => "add"})
      detach!(operation)

      view |> element(~s{button[phx-click="resume"]}) |> render_click()
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      assert render(view) =~ "A new deployment worker was started for this operation."
    end

    test "cancelling asks the worker to stop and never claims an undo",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      html = render(view)
      assert html =~ "Cancel setup"
      assert html =~ "Closing this does not cancel anything."

      view |> element(~s{button[phx-click="cancel-setup"]}) |> render_click()

      assert_receive {:fake_worker, %{"op" => "cancel"}}, @receive_timeout
      assert render(view) =~ "asked to stop at a safe boundary"
    end

    test "closing the drawer leaves the operation running", %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      view |> element(~s{button[phx-click="drawer-close"]}) |> render_click()

      refute has_element?(view, "#ouro-deploy")
      assert_patched(view, "/devices")

      # Nothing was sent to the worker, and it is still attached.
      refute_receive {:fake_worker, %{"op" => "cancel"}}, 200
      assert {:ok, _pid} = Ouroboros.Fleet.Deployment.client(operation)
      assert FleetWorkerFake.refusals(worker) == 0
    end
  end

  # ------------------------------------------------------------------------------------
  # Recovery
  # ------------------------------------------------------------------------------------

  describe "recovery" do
    setup context do
      issuer!(context.root)
      worker = worker!(context)
      %{conn: web!(context), worker: worker}
    end

    test "a lost worker is reported as unknown-until-queried, not as a failure",
         %{conn: conn, root: root} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)
      journal!(root, operation, %{"state" => "deploying", "kind" => "add"})

      detach!(operation)

      html = await(view, "No worker is attached")

      assert html =~ "what the journal durably recorded"
      assert html =~ "not the same as what is happening now"
      refute html =~ "Failed"
    end

    test "a new page reloads the operation by its id", %{conn: conn, root: root} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)
      journal!(root, operation, %{"state" => "deploying", "kind" => "add"})

      detach!(operation)

      # A different LiveView, as if the page had been closed and opened again.
      {:ok, reopened, html} = live(conn, "/devices?operation=#{operation}")

      assert html =~ operation
      assert html =~ "Deploying"
      assert :sys.get_state(reopened.pid).socket.assigns.drawer.operation == operation
    end

    test "an unfinished operation is offered on the row it was aimed at",
         %{conn: conn, root: root} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      journal!(root, operation, %{
        "state" => "interrupted",
        "kind" => "add",
        "target" => %{"address" => "100.64.12.44"}
      })

      detach!(operation)

      {:ok, fresh, html} = live(conn, "/devices")

      assert html =~ "Setups in progress"
      assert html =~ "Interrupted"

      # The row for the device that operation targets offers Continue setup rather than a
      # second Deploy.
      assert has_element?(
               fresh,
               ~s{button[phx-click="open-operation"][phx-value-operation="#{operation}"]}
             )
    end

    test "an operation another identity started needs an explicit takeover",
         %{conn: conn, root: root} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      journal!(root, operation, %{
        "state" => "interrupted",
        "kind" => "add",
        "owner" => "somebody-else"
      })

      detach!(operation)

      {:ok, fresh, html} = live(conn, "/devices?operation=#{operation}")

      # Reading it is already refused, so the prompt is what the drawer opens on: there is
      # no Retry to press first, and nothing happens quietly.
      assert html =~ "This setup was started by another identity"
      refute has_element?(fresh, ~s{button[phx-click="resume"]:not([phx-value-takeover])})
      assert html =~ "asked of you rather than of whoever started it"
      assert has_element?(fresh, ~s{button[phx-value-takeover="true"]})

      # And taking it over is one more explicit press, which attaches a new worker.
      fresh |> element(~s{button[phx-value-takeover="true"]}) |> render_click()
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      assert render(fresh) =~ "taken over"
    end
  end

  # ------------------------------------------------------------------------------------
  # The catalogue row
  # ------------------------------------------------------------------------------------

  describe "the command row" do
    test "is offered where the inventory is, and not where it is not", context do
      issuer!(context.root)
      ouro!(context)
      _conn = web!(context)

      offered = Ouroboros.Web.Commands.available(%{scope: :operate})
      assert Enum.any?(offered, &(&1.id == "runtime.devices"))

      row = Enum.find(Ouroboros.Web.Commands.all(), &(&1.id == "runtime.devices"))
      assert row.label == "Devices"
      assert row.slash == "/devices"
      assert row.group == :runtime

      # With identities configured and a non-administrator asking, the row is not drawn:
      # `fleet.devices` is administrator-only even at read scope.
      identities!(context)

      Ouroboros.Audit.Identity.install(%{
        "id" => "olive",
        "token_sha256" => digest("operator-token")
      })

      refute Enum.any?(
               Ouroboros.Web.Commands.available(%{scope: :operate}),
               &(&1.id == "runtime.devices")
             )

      Ouroboros.Audit.Identity.install(nil)
    end
  end

  defp digest(token), do: :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
end
