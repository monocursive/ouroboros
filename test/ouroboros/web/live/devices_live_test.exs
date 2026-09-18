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
        "suggested_machine" => "studio",
        "os" => "macos",
        "address" => "100.64.0.1",
        "online" => true,
        "last_seen" => nil,
        "path" => "direct",
        "state" => "this_device",
        "action" => "view device",
        "name_conflicts_with_roster" => nil,
        "suggested_machine" => "studio"
      },
      %{
        "name" => "spare",
        "machine" => nil,
        "suggested_machine" => "spare",
        "os" => "linux",
        "address" => "100.64.0.7",
        "online" => true,
        "last_seen" => nil,
        "path" => "direct",
        "state" => "this_device_without_profile",
        "action" => "set up this device",
        "name_conflicts_with_roster" => nil,
        "suggested_machine" => "spare"
      },
      %{
        "name" => "buildbox",
        "machine" => "buildbox",
        "suggested_machine" => "buildbox",
        "os" => nil,
        "address" => "100.64.0.2",
        "online" => nil,
        "last_seen" => nil,
        "path" => "unknown",
        "state" => "fleet_member_not_visible",
        "action" => "diagnose",
        "name_conflicts_with_roster" => nil,
        "suggested_machine" => "buildbox"
      },
      %{
        "name" => "vps-1",
        "machine" => nil,
        "suggested_machine" => "vps-1",
        "os" => "linux",
        "address" => "100.64.12.44",
        "online" => true,
        "last_seen" => "2026-09-16T10:00:00Z",
        "path" => "relayed",
        "state" => "discovered_installation_unknown",
        "action" => "deploy Ouroboros",
        "name_conflicts_with_roster" => nil,
        "suggested_machine" => "vps-1"
      },
      %{
        "name" => "studio",
        "machine" => nil,
        "os" => "linux",
        "address" => "100.64.9.9",
        "suggested_machine" => "studio",
        "online" => true,
        "last_seen" => nil,
        "path" => "direct",
        "state" => "discovered_installation_unknown",
        "action" => "deploy Ouroboros",
        "name_conflicts_with_roster" => "studio",
        "suggested_machine" => "studio"
      },
      %{
        "name" => "toaster",
        "machine" => nil,
        "suggested_machine" => "toaster",
        "os" => "plan9",
        "address" => "100.64.0.5",
        "online" => false,
        "last_seen" => "2026-09-01T00:00:00Z",
        "path" => "unknown",
        "state" => "unsupported_platform",
        "action" => "nothing to deploy",
        "name_conflicts_with_roster" => nil,
        "suggested_machine" => "toaster"
      }
    ]
  }

  # Nine rows, which is the first count past the threshold that puts a search box and the
  # filter on the page (section 5.1).
  @many put_in(
          @devices["devices"],
          @devices["devices"] ++
            for index <- 1..4 do
              %{
                "name" => "filler-#{index}",
                "machine" => nil,
                "suggested_machine" => "filler-#{index}",
                "os" => "linux",
                "address" => "100.64.30.#{index}",
                "online" => true,
                "last_seen" => nil,
                "path" => "direct",
                "state" => "discovered_installation_unknown",
                "action" => "deploy Ouroboros",
                "name_conflicts_with_roster" => nil
              }
            end
        )

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

  # The noun the page uses for the machine it is running on, and the button that follows it.
  # Computed here the way the page computes it — from `:os.type/0`, which is what
  # `Deployment.host/1` reports as `host.os` — so this suite reads the same on either.
  defp host_os, do: :os.type() |> elem(1) |> Atom.to_string()
  defp self_label, do: Devices.self_label(host_os())
  defp setup_label, do: Devices.setup_label(host_os())

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

    config_opts = [data_dir: context.root, scope: Keyword.get(opts, :scope, :operate)]

    config_opts =
      case Keyword.get(opts, :bind) do
        nil ->
          config_opts

        bind ->
          Keyword.merge(config_opts,
            bind: bind,
            allow_remote: Keyword.get(opts, :allow_remote, true)
          )
      end

    config = Config.new!(config_opts)
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

  defp html_live_region(html) do
    case Regex.run(~r/id="ouro-deploy-live"[^>]*>(.*?)<\/p>/s, html) do
      [_, inner] -> String.trim(inner)
      _missing -> nil
    end
  end

  defp operation(view), do: :sys.get_state(view.pid).socket.assigns.drawer.operation

  # A mount that says which browser tab it is, the way `app.js` does with a connect param.
  defp live_with_tab(conn, path, tab) do
    conn
    |> Phoenix.LiveViewTest.put_connect_params(%{"_ouro_tab" => tab})
    |> live(path)
  end

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

  # `Plan::to_value/0` in tui/src/fleet_setup/plan.rs, field for field.
  defp plan do
    %{
      "schema" => 1,
      "operation" => "0011223344556677",
      "kind" => "add",
      "deployment_host" => %{
        "hostname" => "studio",
        "user" => "operator",
        "os" => "macos",
        "arch" => "aarch64",
        "issuer" => true
      },
      "target" => %{
        "machine" => "vps-1",
        "address" => "100.64.12.44",
        "port" => 22,
        "ssh_user" => "deploy",
        "identity" => "agent identity SHA256:anAgentKey",
        "install_path" => "/usr/local/bin/ouro",
        "data_dir" => "/home/deploy/.ouroboros",
        "host_fingerprint" => "SHA256:aHostKey",
        "node" => "ouro@vps-1"
      },
      "release" => %{
        "version" => "0.1.8",
        "target" => "x86_64-unknown-linux-gnu",
        "asset" => "ouro-0.1.8.tar.gz",
        "sha256" => "0123456789abcdef0123456789abcdef",
        "official_origin" => true
      },
      "service" => "managed",
      "members" => [
        %{
          "machine" => "studio",
          "host" => "100.64.0.1",
          "reached_by" => "local",
          "change" => "add vps-1"
        }
      ],
      "restart" => nil,
      "grants" => ["Joining grants broad authority between this fleet's machines."],
      "build" => nil
    }
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

    test "says where the work happens in one line, not in a box on every screen", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      # A browser cannot lend its own laptop's SSH agent to the runtime, so the page still
      # says whose machine acts. Once, under the title.
      assert html =~ "Actions run on "
      assert html =~ "data-ouro-deployment-host"

      # And not the three-line paragraph the review found above the list and again inside
      # every drawer.
      refute html =~ "not on the computer showing this page"
      refute html =~ "Discovery, SSH and certificate issuance run on that machine"
    end

    test "draws one list, this machine first, with the state in words and the code in data",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      # One list, not two sections split by membership.
      assert html =~ ~s(id="devices-list")
      refute html =~ "Fleet devices"
      refute html =~ "Available on this network"

      # Section 5.1's vocabulary, and none of the proposal's table.
      assert html =~ "not set up"
      assert html =~ "in the fleet"
      refute html =~ "Discovered peer; Ouroboros installation unknown"
      refute html =~ "Known member disconnected from this runtime"

      # The codes are data attributes and nothing else.
      assert html =~ ~s(data-state="discovered_installation_unknown")
      assert html =~ ~s(data-state="fleet_member_not_visible")
      refute html =~ ">discovered_installation_unknown<"
      refute html =~ ">fleet_member_not_visible<"
    end

    test "puts this machine's own row first and labels it after the host's OS",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ ~s(<span class="ouro-devices-label">#{self_label()}</span>)

      # The self rows come before the member, which comes before the discovered peers.
      order = Regex.scan(~r/data-state="([a-z_]+)"/, html) |> Enum.map(&List.last/1)

      assert Enum.take(order, 2) == ["this_device", "this_device_without_profile"]

      assert Enum.find_index(order, &(&1 == "fleet_member_not_visible")) <
               Enum.find_index(order, &(&1 == "discovered_installation_unknown"))
    end

    test "gives the state column screen-reader text rather than colour alone", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ ~s(<span class="ouro-visually-hidden">Ouroboros:</span>)
      assert html =~ ~s(<span class="ouro-visually-hidden">Network presence:</span>)

      # The dot is decoration beside a word, never the word itself.
      assert html =~ ~s(<span aria-hidden="true" class="ouro-devices-dot">)
    end

    test "says presence as a dot, a word and a relative time, and never an ISO row",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      # `toaster` is offline and the client said when it last saw it; `buildbox` has no
      # presence reported at all, which is not the same fact as being offline.
      assert html =~ "offline, seen "
      assert html =~ "presence not reported"

      # Section 5.1 bans the exact instant from a row. It lives in the details panel.
      refute html =~ "2026-09-01T00:00:00Z"
    end

    test "renders a roster name collision as a note rather than merging the row",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "This device calls itself studio, which is the name of a machine in"
      assert html =~ "It is not that machine."

      # And the impostor is still its own row, with its own address.
      assert html =~ ~s(data-address="100.64.9.9")
    end

    test "draws no legend, because the words no longer need one", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/devices")

      refute html =~ "What each state means"
      refute html =~ "Observed state"
      refute html =~ "Primary action"
    end

    test "offers no search or filter over a list this short", %{conn: conn} do
      {:ok, view, html} = live(conn, "/devices")

      # Six rows. At eight or fewer, the list is its own index (section 5.1).
      refute html =~ ~s(id="devices-search")
      refute has_element?(view, "#devices-search")
    end

    test "refreshes by asking again", %{conn: conn, fake_dir: fake_dir} = context do
      {:ok, view, html} = live(conn, "/devices")
      assert html =~ "vps-1"

      ouro!(context, devices: put_in(@devices["devices"], []))
      _ = fake_dir

      html = render_click(view, "refresh", %{})
      refute html =~ "vps-1"
      assert html =~ "No device matches"
    end

    test "offers Add to fleet on an uninspected peer and nothing at all on a blocked one",
         %{conn: conn} do
      {:ok, view, html} = live(conn, "/devices")

      assert html =~ "Add to fleet"
      assert has_element?(view, ~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})

      # Section 5.1: "A device that cannot be acted on shows no button; the reason is in its
      # details." `toaster` is an unsupported platform, so its row offers nothing — not a
      # disabled control carrying a paragraph.
      refute has_element?(view, ~s{button[phx-value-address="100.64.0.5"]})
      assert html =~ "run Ouroboros"
      refute html =~ "Deployment is disabled for this device while that blocker stands."

      # A known member is not a deployment target either; Details is a read-only panel.
      refute has_element?(view, ~s{button[phx-click="deploy"][phx-value-address="100.64.0.2"]})

      assert has_element?(
               view,
               ~s{button[phx-click="inspect-device"][phx-value-address="100.64.0.2"]}
             )

      assert html =~ "Details"
      refute html =~ "Diagnose"
      refute html =~ "View device"
    end

    test "pre-fills the name from suggested_machine and never from the display name",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      html =
        view
        |> element(~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})
        |> render_click()

      # `suggested_machine` is the one field section 5.5 puts a *valid* name in. Finding 3
      # is what happens without it: the display name went into the box and was submitted.
      assert has_element?(view, ~s{#deploy-machine[value="vps-1"]})
      assert html =~ "letters, digits, hyphens"

      # And the address that came from the list is a fact rather than something to retype.
      assert has_element?(view, "#deploy-address[readonly]")
    end

    test "leaves the name empty when no valid one could be suggested", context do
      ouro!(context,
        devices:
          put_in(@devices["devices"], [
            %{
              "name" => "Somebody's Laptop!",
              "machine" => nil,
              "suggested_machine" => nil,
              "os" => "linux",
              "address" => "100.64.12.44",
              "online" => true,
              "last_seen" => nil,
              "path" => "direct",
              "state" => "discovered_installation_unknown",
              "action" => "deploy Ouroboros",
              "name_conflicts_with_roster" => nil
            }
          ])
      )

      {:ok, view, _html} = live(context.conn, "/devices")
      render_click(view, "refresh", %{})

      view
      |> element(~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})
      |> render_click()

      assert has_element?(view, ~s{#deploy-machine[value=""]})
    end

    test "takes a manual destination through the same form, with the name required",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      html = render_click(view, "deploy-manual", %{})

      assert html =~ "Add a device by address"
      assert html =~ "Name in the fleet"
      assert html =~ "SSH user"

      # Finding 2. The manual form had no name field at all, so the worker took the address
      # as the machine name and refused it after a connection, a host key and a password.
      assert has_element?(view, "#deploy-machine[required]")
      assert has_element?(view, ~s{#deploy-machine[value=""]})

      # The address is the point of this form, so it is editable here and only here.
      assert has_element?(view, "#deploy-address[required]")
      refute has_element?(view, "#deploy-address[readonly]")
      assert has_element?(view, ~s{#deploy-address[value=""]})
    end

    test "refuses a manual submission with no name, before anything is connected to",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      render_click(view, "deploy-manual", %{})

      html =
        view
        |> form("#ouro-deploy-connect", %{
          "address" => "100.64.77.77",
          "machine" => "",
          "ssh_user" => "deploy"
        })
        |> render_submit()

      assert html =~ "This machine needs a name in the fleet."
      # Nothing was prepared: no operation id anywhere on the page.
      refute html =~ "data-ouro-operation"
    end

    test "says a bad name is bad while it is being typed, and not before", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      html = render_click(view, "deploy-manual", %{})

      # An empty box on the manual form is not yet a mistake.
      refute html =~ "deploy-machine-error"
      refute html =~ "Letters, digits and hyphens only"

      html =
        view
        |> form("#ouro-deploy-connect", %{"machine" => "not a machine name"})
        |> render_change()

      assert html =~ ~s(id="deploy-machine-error")
      assert html =~ "Letters, digits and hyphens only"
      assert has_element?(view, ~s{#deploy-machine[aria-invalid="true"]})

      assert has_element?(
               view,
               ~s{#deploy-machine[aria-describedby="deploy-machine-hint deploy-machine-error"]}
             )

      # And it goes away when the name becomes one.
      html =
        view
        |> form("#ouro-deploy-connect", %{"machine" => "raspberrypi"})
        |> render_change()

      refute html =~ "deploy-machine-error"
      refute has_element?(view, ~s{#deploy-machine[aria-invalid="true"]})
    end

    test "refuses a name that is not a machine name", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      render_click(view, "deploy-manual", %{})

      html =
        view
        |> form("#ouro-deploy-connect", %{
          "address" => "100.64.77.77",
          "machine" => "not a machine name",
          "ssh_user" => "deploy"
        })
        |> render_submit()

      assert html =~ "Letters, digits and hyphens only"
      refute html =~ "data-ouro-operation"
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
  # The controls that only a long list earns
  # ------------------------------------------------------------------------------------

  describe "past eight rows" do
    setup context do
      issuer!(context.root)
      ouro!(context, devices: @many)
      %{conn: web!(context)}
    end

    test "the search box and the filter appear", %{conn: conn} do
      {:ok, view, html} = live(conn, "/devices")

      assert html =~ ~s(id="devices-search")
      assert has_element?(view, "#devices-search")
      assert html =~ "In the fleet"
      assert html =~ "Everything else"
    end

    test "searching by name and by address narrows the one list", %{conn: conn} do
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

    test "a query that matches nothing keeps the controls on the page", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      html = render_change(view, "search", %{"query" => "nothing-matches-this"})

      # The threshold is the unfiltered count, so the box does not vanish from under the
      # cursor of the person typing into it.
      assert html =~ ~s(id="devices-search")
      assert html =~ "No device matches"
    end

    test "the filter keeps one list and changes which rows are in it", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      html = render_click(view, "filter", %{"filter" => "fleet"})
      assert html =~ ~s(data-state="fleet_member_not_visible")
      refute html =~ ~s(data-state="discovered_installation_unknown")
      assert html =~ ~s(aria-pressed="true")

      html = render_click(view, "filter", %{"filter" => "available"})
      assert html =~ ~s(data-state="discovered_installation_unknown")
      refute html =~ ~s(data-state="fleet_member_not_visible")

      html = render_click(view, "filter", %{"filter" => "all"})
      assert html =~ ~s(data-state="fleet_member_not_visible")
      assert html =~ ~s(data-state="discovered_installation_unknown")
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

    for code <- ~w(client_missing signed_out permission_denied unavailable) do
      test "#{code} is one notice quoting the client's own words", context do
        code = unquote(code)

        document = %{
          @devices
          | "discovery" => %{
              "code" => code,
              "reason" => nil,
              "detail" => "The Tailscale GUI failed to start",
              "client" => nil,
              "self" => nil,
              "visible_peers" => 0
            }
        }

        ouro!(context, devices: document)
        conn = web!(context)

        {:ok, _view, html} = live(conn, "/devices")

        # Section 5.1: one inline notice with the client's own words and the repair. Every
        # failure reads the same way, because what an operator does about it is the same
        # thing and the client is the only one of the two that knows why.
        assert html =~ "Tailscale did not answer from this runtime"
        assert html =~ "The Tailscale GUI failed to start"
        assert html =~ "Devices already in the fleet are still listed."
        assert html =~ ~s(data-discovery="#{code}")

        # Finding 1: never a claim about this build's age. The client printed something
        # and exited 0; that is not evidence about a version.
        refute html =~ "older than the client"
        refute html =~ "may be older"
      end
    end

    test "a client that said nothing still gets a notice, without inventing a quote",
         context do
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

      assert html =~ "Tailscale did not answer from this runtime."
      refute html =~ ~s(runtime: "")
    end

    test "no_visible_peers is an answer, not a failure", context do
      document = %{
        @devices
        | "discovery" => %{
            "code" => "no_visible_peers",
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

      assert html =~ "Tailscale answered and can see no other devices."
      refute html =~ "did not answer"
      assert html =~ ~s(data-discovery="no_visible_peers")
    end

    test "keeps known members when discovery could not answer", context do
      document = %{
        @devices
        | "discovery" => %{
            "code" => "unavailable",
            "reason" => nil,
            "detail" => "the client is not running",
            "client" => nil,
            "self" => nil,
            "visible_peers" => 0
          }
      }

      ouro!(context, devices: document)
      conn = web!(context)

      {:ok, _view, html} = live(conn, "/devices")

      # This machine's own roster stands even when nothing could be discovered — and the
      # page says so rather than implying an empty fleet.
      assert html =~ "buildbox"
      assert html =~ "Devices already in the fleet are still listed."
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
    test "a machine with no fleet at all is told to set itself up", context do
      # The fixture inventory carries this machine as `this_device_without_profile`, which
      # is what "standalone" means. Sending that operator to "the machine that created the
      # fleet" names a machine that does not exist.
      ouro!(context)
      conn = web!(context)

      {:ok, view, html} = live(conn, "/devices")

      # Section 5.1: the status line *is* the blocker sentence, not a second paragraph
      # under it repeating the same thing.
      assert html =~ "#{self_label()} is not in a fleet yet."
      refute html =~ "Open Devices on the machine that created the fleet."

      # And the control it points at is the one that is offered.
      assert has_element?(view, ~s{button[phx-click="setup-device"]})
    end

    test "a machine that is in a fleet and holds no key is sent to the issuer", context do
      # The same blocker, the other posture: a joiner. Its own row is `this_device`, so it
      # has a fleet — and the machine to open Devices on is the one holding the key.
      joiner =
        Map.put(@devices, "devices", [
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
          }
        ])

      ouro!(context, devices: joiner)
      conn = web!(context)

      {:ok, view, html} = live(conn, "/devices")

      assert html =~ "Open Devices on the machine that created the fleet."
      refute html =~ "is not in a fleet yet"
      refute has_element?(view, ~s{button[phx-click="setup-device"]})
    end

    test "a cleartext non-loopback endpoint refuses credential entry and says so",
         context do
      issuer!(context.root)
      ouro!(context)
      conn = web!(context, bind: {0, 0, 0, 0}, allow_remote: true)

      {:ok, view, html} = live(conn, "/devices")

      refute has_element?(view, ~s{button[phx-click="deploy"]})
      assert html =~ "credential entry is refused here"
      assert html =~ "tailscale serve"

      # The control keeps its name and reads as unavailable rather than disappearing, and
      # it carries the reason itself — as a title, and as `aria-describedby` pointing at
      # the sentence the page already draws, so it is not sighted-only.
      assert has_element?(view, ~s{button[disabled][aria-describedby="ouro-devices-blocked"]})
      assert html =~ ~s(id="ouro-devices-blocked")
      assert html =~ "Add to fleet"

      [button] = Regex.run(~r/<button[^>]*aria-describedby="ouro-devices-blocked"[^>]*>/, html)
      assert button =~ "credential entry is refused here"
      assert button =~ ~s(aria-disabled="true")
      refute button =~ "phx-click"
    end

    test "a read-scope endpoint says it is the scope, and still shows membership",
         context do
      issuer!(context.root)
      ouro!(context)
      conn = web!(context, scope: :read)

      {:ok, view, html} = live(conn, "/devices")

      # The inventory itself is read-scoped, so it is still there; what a read endpoint
      # cannot do is start one.
      assert html =~ ~s(id="devices-list")
      assert html =~ "buildbox"
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

      assert html =~ "SSH user"
      # Named after the machine rather than explained: the account on the target is not the
      # account that registered it with the network, and the label says which machine.
      assert html =~ "the account on vps-1"
      assert has_element?(view, ~s{#deploy-ssh-user[required]})

      # Port, identity and paths are the advanced fields the proposal puts behind a
      # disclosure rather than in front of every deployment.
      assert html =~ "Advanced — port, SSH key"
      assert has_element?(view, "#deploy-port")
      assert has_element?(view, "#deploy-identity-ref")

      # Section 5.2: no authentication picker. The default identity is used, and a target
      # that asks for a password raises the challenge the drawer already answers.
      refute has_element?(view, "#deploy-identity-kind")
      refute html =~ "Authentication method"
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

      assert html =~ setup_label()
      assert html =~ "Ouroboros restarts once during setup; this page reconnects by itself."

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

    test "never shows a takeover panel over an operation nobody has started yet",
         %{conn: conn} do
      # Both fields are nil on a drawer that has prepared nothing, and comparing them
      # directly drew "this setup was started by another identity" over a device nobody had
      # touched.
      {:ok, view, _html} = live(conn, "/devices")

      html =
        view
        |> element(~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})
        |> render_click()

      refute html =~ "This setup was started by another identity"
      refute has_element?(view, "[data-ouro-takeover]")

      # And it stays absent once the operation exists and is this session's own — the
      # worker claims an unowned operation for whoever attached, so the owner is us.
      _operation = prepared(view)
      refute render(view) =~ "This setup was started by another identity"

      snapshot = :sys.get_state(view.pid).socket.assigns.drawer.status
      assert snapshot["owner"] == Ouroboros.Audit.Identity.actor()
    end

    test "renders a host-trust challenge from its metadata, with the verify guidance",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      # The worker's own frame: kind-specific facts nest under `metadata`
      # (`challenge_event/2` in tui/src/fleet_setup/worker.rs), and `host_trust_metadata/5`
      # fixes the five field names.
      :ok =
        FleetWorkerFake.challenge(worker, "ht-1", "host_trust", %{
          "metadata" => %{
            "address" => "100.64.12.44",
            "port" => 22,
            "algorithm" => "ssh-ed25519",
            "sha256_fingerprint" => "SHA256:5s0mEfIngeRPrinT",
            "user" => "deploy"
          }
        })

      html = await(view, "SHA256:5s0mEfIngeRPrinT")

      # The contract this page actually consumes is the *broker's* snapshot, not the
      # worker's wire: the frame above goes through the real
      # `Ouroboros.Fleet.Deployment.Client`, which lifts `metadata` to the top of the
      # challenge (seam S4 calls these fields of the challenge) and drops the nesting. A
      # page that read them nested drew this panel with every field empty.
      [challenge] = :sys.get_state(view.pid).socket.assigns.drawer.status["challenges"]
      assert challenge["sha256_fingerprint"] == "SHA256:5s0mEfIngeRPrinT"
      refute Map.has_key?(challenge, "metadata")

      assert html =~ "First time connecting"
      assert html =~ "ssh-ed25519"
      assert html =~ "100.64.12.44"
      assert html =~ "deploy"
      assert html =~ "Check this fingerprint on the device itself"
      assert html =~ "Trust and continue"

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
      _html = await(view, "First time connecting")

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

        # `password_metadata/5` and `passphrase_metadata/2` in
        # tui/src/fleet_setup/challenge.rs: a password names a target and an account and
        # counts its attempts; a passphrase names a key and its public fingerprint, and
        # counts nothing.
        metadata =
          if kind == "password",
            do: %{
              "target" => "100.64.12.44",
              "user" => "deploy",
              "port" => 22,
              "attempt" => 1,
              "max_attempts" => 3
            },
            else: %{
              "key_label" => "/home/ouro/.ssh/id_ed25519",
              "public_fingerprint" => "SHA256:aPub1icFingerprint"
            }

        :ok = FleetWorkerFake.challenge(worker, "c-1", kind, %{"metadata" => metadata})

        html = await(view, "data-ouro-secret")

        assert html =~ ~s(type="password")
        assert html =~ "data-ouro-secret"
        assert html =~ "not stored, not remembered for a reconnection"

        if kind == "password" do
          assert html =~ "Password for deploy@100.64.12.44"
          assert html =~ "attempt 1 of 3"
        else
          assert html =~ "Passphrase for the key /home/ouro/.ssh/id_ed25519"
          assert html =~ "SHA256:aPub1icFingerprint"
          refute html =~ "Attempt"
        end

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

      :ok =
        FleetWorkerFake.challenge(worker, "pw-1", "password", %{
          "metadata" => %{"target" => "100.64.12.44", "user" => "deploy", "port" => 22}
        })

      _html = await(view, "data-ouro-secret")

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
      _html = await(view, "data-ouro-secret")

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

      # The digest the worker really would send: this runtime's own sha256 of that plan.
      # Approval will not offer a button for anything else — see `devices_plan_digest_test`.
      digest = Devices.plan_digest(plan())

      :ok =
        FleetWorkerFake.challenge(worker, "rev-1", "review", %{
          "metadata" => %{"plan" => plan(), "plan_digest" => digest}
        })

      html = await(view, digest)

      assert html =~ "Ready to deploy"
      assert html =~ "plan digest"

      # The CLI's labels, not the document's key names. `Plan::render/0` prints `executable`
      # and `data dir`; a page that printed `install_path` and `data_dir` would be showing
      # an operator the JSON rather than the plan.
      for label <-
            ~w(operation action machine address ssh identity node executable install startup members) do
        assert html =~ ">#{label}</dt>", "the review has no `#{label}` row"
      end

      refute html =~ ">install_path</dt>"
      refute html =~ ">data_dir</dt>"

      assert html =~ "data dir"
      assert html =~ "host key"
      assert html =~ "deploy@100.64.12.44 port 22"
      assert html =~ "ouro 0.1.8 (x86_64-unknown-linux-gnu) sha256 0123456789abcdef"
      assert html =~ "propose a user service"
      assert html =~ "studio (100.64.0.1, add vps-1, via local)"
      assert html =~ "Joining grants broad authority between this fleet"
      assert html =~ "Joining grants broad authority"

      view |> element(~s{button[phx-click="approve"]}) |> render_click()

      assert_receive {:fake_worker, %{"op" => "respond"} = frame}, @receive_timeout
      assert frame["challenge"] == "rev-1"
      assert frame["response"] == %{"approve" => true, "plan_digest" => digest}

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

      :ok =
        FleetWorkerFake.challenge(worker, "rev-2", "review", %{
          "metadata" => %{"plan" => plan()}
        })

      html = await(view, "Ready to deploy")

      refute has_element?(view, ~s{button[phx-click="approve"]})
      assert html =~ "did not name a digest for this plan"
      assert html =~ "no digest reported"
    end

    test "progress draws the six stages and announces each step politely",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.emit(worker, %{"event" => "state", "state" => "deploying"})
      _ = await(view, "Setting up")

      # `install_binary` is the engine's name, and it belongs to the "install if missing"
      # stage even though it is not spelled `install` — which is why the stage table names
      # the worker's steps instead of matching on a prefix.
      :ok =
        FleetWorkerFake.emit(worker, %{
          "event" => "step",
          "machine" => "vps-1",
          "step" => "install_binary",
          "outcome" => "ok",
          "detail" => "0.1.8 from the official release"
        })

      :ok =
        FleetWorkerFake.emit(worker, %{
          "event" => "step",
          "machine" => "vps-1",
          "step" => "issue",
          "outcome" => "ok",
          "detail" => nil
        })

      :ok = FleetWorkerFake.emit(worker, %{"event" => "log", "line" => "ssh said something"})

      html = await(view, "0.1.8 from the official release")

      # Every stage the proposal names, and the ones nothing has reported say so rather
      # than claiming a result.
      for {_key, label, _names} <- Devices.stages(), do: assert(html =~ label)
      assert html =~ "not reported yet"
      assert html =~ ~s(data-step="install")
      assert html =~ ~s(data-step="membership")
      assert html =~ "Install the `ouro` binary on vps-1"
      assert html =~ "Issue the new member&#39;s certificate on vps-1"

      # The worker's log lines are `line`, not `message`.
      assert html =~ "ssh said something"

      # The live region is polite and carries the last change in words. Re-rendered, because
      # the two events after the one awaited above arrive on their own schedule.
      assert html =~ ~s(aria-live="polite")
      assert await(view, "Issue the new member&#39;s certificate on vps-1: done.")
    end

    test "a failure keeps the completed steps, names the cause and offers a retry",
         %{conn: conn, worker: worker, root: root} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      :ok =
        FleetWorkerFake.emit(worker, %{
          "event" => "step",
          "machine" => "vps-1",
          "step" => "inspect",
          "outcome" => "ok"
        })

      # The engine's failure arm sends `{ok: false, reason, detail}` and **no state at
      # all**, so a page that only looked at `state` would still be drawing "Deploying".
      :ok =
        FleetWorkerFake.emit(worker, %{
          "event" => "done",
          "ok" => false,
          "reason" => "ssh_refused",
          "detail" => "the target refused the connection"
        })

      html = await(view, "the target refused the connection")

      assert html =~ "Setup failed"
      assert html =~ "Retry"
      assert html =~ ~s(data-step="inspect")
      refute html =~ "ssh_refused"

      # Retrying means resuming, and resuming needs the previous worker to be gone — which
      # is exactly the state an interrupted operation is in.
      journal!(root, operation, %{"state" => "failed", "kind" => "add"})
      detach!(operation)

      view |> element(~s{button[phx-click="resume"]}) |> render_click()
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      assert render(view) =~ "A new setup worker was started for this operation."
    end

    test "cancelling asks the worker to stop and never claims an undo",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      html = render(view)
      assert html =~ "Cancel setup"
      assert html =~ "keeps running"

      view |> element(~s{button[phx-click="cancel-setup"]}) |> render_click()

      assert_receive {:fake_worker, %{"op" => "cancel"}}, @receive_timeout

      # The broker releases the worker socket once a cancel has been answered, so the client
      # process exits right after this — normally, and by design. The page must still be
      # saying what happened, not "the result is unknown".
      html = await(view, "asked to stop at a safe boundary")

      refute html =~ "unknown until the operation is read again"
      assert html =~ "stopped at a safe boundary"
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
      assert html =~ "Setting up"
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

      # The row says it, rather than a panel above the list.
      assert html =~ "setup failed"
      refute html =~ "Setups with no device on this list"

      # The row for the device that operation targets offers Retry rather than a second
      # Add to fleet.
      assert has_element?(
               fresh,
               ~s{button[phx-click="open-operation"][phx-value-operation="#{operation}"]}
             )
    end

    test "a finished operation speaks for its row until discovery catches up",
         %{conn: conn, root: root} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)
      detach!(operation)

      target = %{"machine" => "vps-1", "address" => "100.64.12.44"}

      # Three endings, three different things for the row to say. The inventory's own
      # `state` never moves in any of them — it is a discovery fact, and the point is that
      # the operation is the fresher one.
      for {state, words, action} <- [
            {"completed", "set up just now", "Open"},
            {"failed", "setup failed", "Retry"},
            {"cancelled", "not set up", "Add to fleet"}
          ] do
        journal!(root, operation, %{"state" => state, "kind" => "add", "target" => target})

        {:ok, fresh, html} = live(conn, "/devices")

        row =
          fresh
          |> element(~s{[data-address="100.64.12.44"][data-operation-state="#{state}"]})
          |> render()

        assert row =~ words, "a #{state} operation does not say so on its row"

        assert row =~ action, "a #{state} operation does not offer #{action}"

        if state == "completed",
          do:
            refute(
              row =~ "Add to fleet",
              "a completed operation left a second deployment one press away"
            )

        # The inventory still calls it an uninspected peer — that is the discovery fact,
        # and the row is the fresher one.
        assert html =~ ~s(data-state="discovered_installation_unknown")

        # A cancelled setup left the device exactly as discovery found it, so its row goes
        # back to discovery's own words rather than carrying "cancelled" for ever.
        if state == "cancelled", do: assert(row =~ "not set up")

        # And a finished one is not held open as a setup with nowhere to be.
        refute html =~ "Setups with no device on this list"
      end
    end

    test "an operation another identity started needs an explicit takeover",
         %{conn: conn, root: root} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      # The journal is the authority when no worker is attached, and this one records an
      # owner that is not this session.
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

  # ------------------------------------------------------------------------------------
  # The gate, asked where an event cannot skip it
  # ------------------------------------------------------------------------------------

  describe "a hand-sent event" do
    setup context do
      issuer!(context.root)
      worker = worker!(context)
      %{worker: worker}
    end

    test "cannot start a deployment on a cleartext non-loopback bind", context do
      conn = web!(context, bind: {0, 0, 0, 0}, allow_remote: true)

      {:ok, view, html} = live(conn, "/devices")
      assert html =~ "credential entry is refused here"

      # The events the hidden controls would have sent, sent anyway — a console one-liner, a
      # hostile page, a stale tab. Every one is refused by the handler.
      html = render_click(view, "deploy-manual", %{})
      assert html =~ "credential entry is refused here"
      refute has_element?(view, "#ouro-deploy-connect")

      html = render_click(view, "deploy", %{"address" => "100.64.12.44"})
      assert html =~ "credential entry is refused here"

      html = render_click(view, "setup-device", %{"address" => "100.64.0.7"})
      assert html =~ "credential entry is refused here"

      refute has_element?(view, "#ouro-deploy")
      refute_receive {:fake_worker, %{"op" => "attach"}}, 400
    end

    test "cannot start one at read scope, or as a non-administrator", context do
      conn = web!(context, scope: :read)
      {:ok, view, _html} = live(conn, "/devices")

      html = render_click(view, "deploy-manual", %{})
      assert html =~ "OUROBOROS_WEB_SCOPE=read"
      refute has_element?(view, "#ouro-deploy")
      refute_receive {:fake_worker, %{"op" => "attach"}}, 400
    end

    test "cannot aim Set up this device at another machine", context do
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      # `100.64.12.44` is a remote peer. A local setup bound to its address would ask the
      # worker to configure this machine to bind somebody else's.
      html = render_click(view, "setup-device", %{"address" => "100.64.12.44"})

      assert html =~ "That address is another device"
      refute has_element?(view, "#ouro-deploy-setup")

      # And the same at submission, where the form's own field is editable.
      render_click(view, "setup-device", %{"address" => "100.64.0.7"})
      assert has_element?(view, "#ouro-deploy-setup")

      html =
        render_submit(view, "connect", %{"address" => "100.64.12.44", "machine" => "vps-1"})

      assert html =~ "A local setup binds this machine"
      refute_receive {:fake_worker, %{"op" => "attach"}}, 400
    end

    test "cannot deploy to an address this machine's inventory does not list", context do
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      html = render_click(view, "deploy", %{"address" => "10.9.9.9"})
      assert html =~ "inventory does not list that address"
      refute has_element?(view, "#ouro-deploy")
    end

    test "cannot crash the view with an operation id that is not one", context do
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      for hostile <- ["../../../etc/passwd", "a b c", "a&b=c#frag", "", "NOTHEX"] do
        html = render_click(view, "open-operation", %{"operation" => hostile})
        assert html =~ "not an operation this machine could be holding"
        assert Process.alive?(view.pid), "#{inspect(hostile)} took the view down"
      end

      # And through the address bar, which is the other way in.
      assert {:ok, _view, html} = live(conn, "/devices?operation=../../../etc/passwd")
      assert html =~ "not an operation this machine could be holding"
    end
  end

  # ------------------------------------------------------------------------------------
  # What a refusal looks like
  # ------------------------------------------------------------------------------------

  describe "a refused answer" do
    setup context do
      issuer!(context.root)
      worker = worker!(context)
      %{conn: web!(context), worker: worker}
    end

    test "draws the visible alert, not only the live region", %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.challenge(worker, "pw-1", "password", %{"metadata" => %{}})
      _ = await(view, "data-ouro-secret")

      :ok = FleetWorkerFake.refuse_next(worker, "authentication_failed")

      html = view |> form("#ouro-deploy-auth", %{"secret" => "wrong"}) |> render_submit()
      assert_receive {:fake_worker, %{"op" => "respond"}}, @receive_timeout

      # The box a sighted operator reads, with the role that makes a screen reader read it
      # out — not just the 1×1 pixel polite region the suite used to find the sentence in.
      assert html =~ ~s(id="ouro-deploy-error")
      assert html =~ ~s(role="alert")
      assert :sys.get_state(view.pid).socket.assigns.drawer.error =~ "refused the request"
    end

    test "is pointed at by the control that caused it", %{conn: conn} do
      # A refusal whose form is still on screen — the connect step, which stays. `Inspect
      # this device` names the box, so a screen reader reads the reason with the button.
      {:ok, view, _html} = live(conn, "/devices")
      render_click(view, "deploy-manual", %{})

      html = render_submit(view, "connect", %{"address" => "", "ssh_user" => "deploy"})

      assert html =~ ~s(id="ouro-deploy-error")
      assert html =~ ~s(aria-describedby="ouro-deploy-error")
    end

    test "survives for a refused host-trust answer too", %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.challenge(worker, "ht-1", "host_trust", %{"metadata" => %{}})
      _ = await(view, "Trust and continue")

      :ok = FleetWorkerFake.refuse_next(worker, "host_key_rejected")

      html =
        view
        |> element(~s{button[phx-click="trust-host"][phx-value-accept="true"]})
        |> render_click()

      assert_receive {:fake_worker, %{"op" => "respond"}}, @receive_timeout
      assert html =~ ~s(id="ouro-deploy-error")
      refute :sys.get_state(view.pid).socket.assigns.drawer.error == nil
    end

    test "offers a way out when the prompt belongs to another tab",
         %{conn: conn, worker: worker} do
      {:ok, first, _html} = live(conn, "/devices")
      operation = prepared(first)

      :ok = FleetWorkerFake.challenge(worker, "pw-2", "password", %{"metadata" => %{}})
      _ = await(first, "data-ouro-secret")

      # A second *tab*: no `_ouro_tab` of its own, so it mints one and is refused — which is
      # the property S4 wants.
      {:ok, second, _html} = live(conn, "/devices?operation=#{operation}")
      _ = await(second, "data-ouro-secret")

      html = second |> form("#ouro-deploy-auth", %{"secret" => "other-tab"}) |> render_submit()
      refute_receive {:fake_worker, %{"op" => "respond"}}, 500

      assert html =~ "This prompt belongs to another tab"
      assert has_element?(second, "[data-ouro-rebind]")
      assert html =~ "Reconnect this setup to this tab"
    end
  end

  # ------------------------------------------------------------------------------------
  # The binding is the tab's
  # ------------------------------------------------------------------------------------

  describe "the credential binding" do
    setup context do
      issuer!(context.root)
      worker = worker!(context)
      %{conn: web!(context), worker: worker}
    end

    test "survives a remount in the same tab", %{conn: conn, worker: worker} do
      tab = String.duplicate("ab", 16)

      {:ok, first, _html} = live_with_tab(conn, "/devices", tab)
      operation = prepared(first)

      :ok = FleetWorkerFake.challenge(worker, "pw-3", "password", %{"metadata" => %{}})
      _ = await(first, "data-ouro-secret")

      # The remount: a refresh, a dropped socket, or the `?operation=` address this page
      # puts in the bar itself. Same tab, so the same binding.
      {:ok, second, _html} = live_with_tab(conn, "/devices?operation=#{operation}", tab)
      _ = await(second, "data-ouro-secret")

      assert :sys.get_state(second.pid).socket.assigns.view_session == tab

      second |> form("#ouro-deploy-auth", %{"secret" => "same-tab"}) |> render_submit()

      assert_receive {:fake_worker, %{"op" => "respond"} = frame}, @receive_timeout
      assert frame["response"]["secret"] == "same-tab"
    end

    test "is refused for a different tab", %{conn: conn, worker: worker} do
      {:ok, first, _html} = live_with_tab(conn, "/devices", String.duplicate("ab", 16))
      operation = prepared(first)

      :ok = FleetWorkerFake.challenge(worker, "pw-4", "password", %{"metadata" => %{}})
      _ = await(first, "data-ouro-secret")

      {:ok, second, _html} =
        live_with_tab(conn, "/devices?operation=#{operation}", String.duplicate("cd", 16))

      _ = await(second, "data-ouro-secret")

      second |> form("#ouro-deploy-auth", %{"secret" => "other-tab"}) |> render_submit()
      refute_receive {:fake_worker, %{"op" => "respond"}}, 500
    end

    test "a tab id this page did not mint is not used", %{conn: conn} do
      {:ok, view, _html} = live_with_tab(conn, "/devices", "not-hex-and-far-too-short")

      session = :sys.get_state(view.pid).socket.assigns.view_session
      refute session == "not-hex-and-far-too-short"
      assert String.match?(session, ~r/\A[0-9a-f]{32}\z/)
    end

    test "and the deployment call carries it, not the cookie's", %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      attached = FleetWorkerFake.attached(worker)
      assigns = :sys.get_state(view.pid).socket.assigns

      assert attached.session == assigns.view_session
      refute attached.session == assigns.web_session
    end
  end

  # ------------------------------------------------------------------------------------
  # The gaps the adversarial review's surviving mutants named
  # ------------------------------------------------------------------------------------

  describe "coverage the mutants found missing" do
    setup context do
      issuer!(context.root)
      :ok
    end

    # M5b: `setup?` always true.
    test "a read-scope endpoint offers no Set up this device either", context do
      ouro!(context)
      conn = web!(context, scope: :read)

      {:ok, view, _html} = live(conn, "/devices")

      refute has_element?(view, ~s{button[phx-click="deploy"]})

      refute has_element?(view, ~s{button[phx-click="setup-device"]}),
             "a read-only endpoint drew the local-setup button"
    end

    # M5b from the other side: a blocker that is not `no_ca_key` stops a setup too.
    test "a cleartext bind offers no Set up this device", context do
      ouro!(context)
      conn = web!(context, bind: {0, 0, 0, 0}, allow_remote: true)

      {:ok, view, _html} = live(conn, "/devices")
      refute has_element?(view, ~s{button[phx-click="setup-device"]})
    end

    # M7: `stage_of` by prefix. `roster` and `service` are not prefixed by their stage keys,
    # and a prefix match files them nowhere at all.
    test "every stage the worker reported a step for stops saying 'not reported yet'",
         context do
      worker = worker!(context)
      conn = web!(context)

      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      for {step, outcome} <- [
            {"inspect", "ok"},
            {"install_binary", "ok"},
            {"roster", "ok"},
            {"service", "ok"},
            {"connect", "ok"},
            {"readiness", "skipped"}
          ] do
        :ok =
          FleetWorkerFake.emit(worker, %{
            "event" => "step",
            "machine" => "vps-1",
            "step" => step,
            "outcome" => outcome
          })
      end

      _ = await(view, ~s(data-step="membership" data-outcome="ok"))
      html = render(view)

      for stage <- ~w(inspect install membership startup connect readiness) do
        assert html =~ ~s(data-step="#{stage}" data-outcome="ok"),
               "stage #{stage} did not take the step the worker filed under it"
      end

      refute html =~ "not reported yet"
    end

    # M7b: a stage reads as done because the last frame to arrive said so.
    test "one failed step makes its whole stage failed, whatever arrived after it",
         context do
      worker = worker!(context)
      conn = web!(context)

      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok =
        FleetWorkerFake.emit(worker, %{
          "event" => "step",
          "machine" => "vps-1",
          "step" => "install_binary",
          "outcome" => "failed",
          "detail" => "the archive did not verify"
        })

      :ok =
        FleetWorkerFake.emit(worker, %{
          "event" => "step",
          "machine" => "vps-1",
          "step" => "install",
          "outcome" => "ok"
        })

      _ = await(view, "the archive did not verify")

      assert render(view) =~ ~s(data-step="install" data-outcome="failed"),
             "the stage read as done because the last frame to arrive said so"
    end

    # M4b: a fresh idempotency key per click. The same key against the same operation
    # replays; a different one is a second intention.
    test "a second approval replays the first rather than being a new intention", context do
      worker = worker!(context)
      conn = web!(context)

      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)
      digest = Devices.plan_digest(plan())

      :ok =
        FleetWorkerFake.challenge(worker, "rv-1", "review", %{
          "metadata" => %{"plan" => plan(), "plan_digest" => digest}
        })

      _ = await(view, "Ready to deploy")
      key = :sys.get_state(view.pid).socket.assigns.drawer.approval_key

      render_click(view, "approve", %{"digest" => digest})
      assert_receive {:fake_worker, %{"op" => "respond"}}, @receive_timeout
      assert :sys.get_state(view.pid).socket.assigns.announcement == "The plan was approved."

      render_click(view, "approve", %{"digest" => digest})
      Process.sleep(300)

      assert :sys.get_state(view.pid).socket.assigns.drawer.approval_key == key,
             "the second click minted a second idempotency key"

      assert :sys.get_state(view.pid).socket.assigns.announcement == "The plan was approved.",
             "the second click was treated as a second intention rather than a replay"
    end

    # M10: a device name rendered raw.
    test "a device name that is markup is rendered as text", context do
      hostile =
        Map.put(@devices, "devices", [
          %{
            "name" => "<script>window.x=1</script>",
            "machine" => nil,
            "os" => "linux",
            "address" => "100.64.3.3",
            "online" => true,
            "path" => "direct",
            "state" => "discovered_installation_unknown",
            "name_conflicts_with_roster" => nil
          }
        ])

      ouro!(context, devices: hostile)
      conn = web!(context)

      {:ok, _view, html} = live(conn, "/devices")

      refute html =~ "<script>window.x=1</script>"
      assert html =~ "&lt;script&gt;"
    end

    # F9: markup is escaped, and a name that *renders* as a lie is not drawn at all.
    test "a name that reverses or hides itself is normalised", context do
      hostile =
        Map.put(@devices, "devices", [
          %{
            "name" => "prod\u202Eyrammus\u202C",
            "machine" => nil,
            "os" => "li\u200Bnux",
            "address" => "100.64.3.4",
            "online" => true,
            "path" => "direct",
            "state" => "discovered_installation_unknown",
            "name_conflicts_with_roster" => nil
          }
        ])

      ouro!(context, devices: hostile)
      conn = web!(context)

      {:ok, _view, html} = live(conn, "/devices")

      refute html =~ "\u202E", "a bidi override reached the page"
      refute html =~ "\u200B", "a zero-width space reached the page"
      assert html =~ "prodyrammus"
      assert html =~ "linux"
    end
  end

  # ------------------------------------------------------------------------------------
  # Rows, the operations panel, and what a live region says twice
  # ------------------------------------------------------------------------------------

  describe "the inventory under pressure" do
    setup context do
      issuer!(context.root)
      ouro!(context)
      %{conn: web!(context)}
    end

    test "a peer that takes a roster machine's name does not inherit its setup",
         %{conn: conn, root: root} do
      # The impostor row calls itself `studio`, which is a roster machine. An operation
      # aimed at `studio` must stay on `studio`'s row: matching a journal target against a
      # peer's self-declared name would hand its Retry button to whoever asked for the name.
      journal!(root, "00aa11bb22cc33dd", %{
        "state" => "interrupted",
        "kind" => "add",
        "target" => %{"machine" => "studio", "address" => "100.64.0.1"}
      })

      {:ok, view, _html} = live(conn, "/devices")

      impostor = view |> element(~s{[data-address="100.64.9.9"]}) |> render()

      refute impostor =~ "Retry"
      refute impostor =~ "setup failed"
      refute impostor =~ "00aa11bb22cc33dd"

      # And the machine it belongs to does have it.
      owner = view |> element(~s{[data-address="100.64.0.1"]}) |> render()
      assert owner =~ "Retry"
      assert owner =~ "setup failed"
    end

    test "an operation this list has a row for is drawn on that row, not in a panel",
         %{conn: conn, root: root} do
      journal!(root, "00aa11bb22cc33dd", %{
        "state" => "awaiting_auth",
        "kind" => "add",
        "target" => %{"machine" => "vps-1", "address" => "100.64.12.44"}
      })

      {:ok, view, html} = live(conn, "/devices")

      row = view |> element(~s{[data-address="100.64.12.44"]}) |> render()
      assert row =~ "waiting for you"
      assert row =~ "Continue"
      assert row =~ ~s(data-operation-state="awaiting_auth")

      # Nothing is left over for a panel to hold, so there is no panel.
      refute html =~ "Setups with no device on this list"
    end

    test "two hundred stopped setups do not push the list off the page",
         %{conn: conn, root: root} do
      for index <- 1..200 do
        journal!(root, String.pad_leading(Integer.to_string(index, 16), 16, "0"), %{
          "state" => "failed",
          "kind" => "add",
          "updated_at" => "2020-01-01T00:00:00Z",
          "target" => %{"machine" => "m#{index}", "address" => "10.0.0.#{rem(index, 250)}"}
        })
      end

      {:ok, _view, html} = live(conn, "/devices")

      drawn = length(String.split(html, ~s(phx-click="open-operation"))) - 1

      assert drawn <= 12,
             "the page drew #{drawn} operation controls; a journal directory holds two hundred"

      # None of them names a device on this list, so they get the one panel that exists for
      # exactly that case — capped, rather than two hundred rows above the inventory.
      assert html =~ "Setups with no device on this list"
    end

    test "a setup whose device is not on the list still has somewhere to be",
         %{conn: conn, root: root} do
      journal!(root, "00aa11bb22cc33dd", %{
        "state" => "awaiting_auth",
        "kind" => "add",
        "target" => %{"machine" => "gone", "address" => "10.9.9.9"}
      })

      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "Setups with no device on this list"
      assert html =~ "00aa11bb22cc33dd"
      assert html =~ "Closing the page did not cancel them."
    end
  end

  describe "the live region" do
    setup context do
      issuer!(context.root)
      worker = worker!(context)
      %{conn: web!(context), worker: worker}
    end

    test "says the same thing twice as two announcements", %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      step = %{
        "event" => "step",
        "machine" => "vps-1",
        "step" => "roster",
        "outcome" => "ok"
      }

      :ok = FleetWorkerFake.emit(worker, step)
      _ = await(view, "Update a roster on vps-1: done.")
      first = render(view)
      first_live = html_live_region(first)

      :ok = FleetWorkerFake.emit(worker, step)

      # A live region announces a change. The same sentence twice is one change to the
      # announcement text unless the counter beside it changes the text node.
      second =
        Enum.reduce_while(1..100, first, fn _attempt, acc ->
          html = render(view)

          if html_live_region(html) != first_live,
            do: {:halt, html},
            else:
              (
                Process.sleep(20)
                {:cont, acc}
              )
        end)

      assert html_live_region(second) != first_live
      assert second =~ "Update a roster on vps-1: done."
    end

    test "is emptied when the drawer closes", %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.emit(worker, %{"event" => "state", "state" => "deploying"})
      _ = await(view, "Setting up.")

      view |> element(~s{button[phx-click="drawer-close"]}) |> render_click()

      assert :sys.get_state(view.pid).socket.assigns.announcement == "",
             "the last deployment's sentence is still there for the next one to read out"
    end
  end

  describe "a member the cluster can see" do
    setup context do
      issuer!(context.root)
      :ok
    end

    defp member_inventory do
      Map.put(@devices, "devices", [
        %{
          "name" => "buildbox",
          "machine" => "buildbox",
          "suggested_machine" => "buildbox",
          "os" => "linux",
          "address" => "100.64.0.2",
          "online" => false,
          "last_seen" => "2026-09-01T00:00:00Z",
          "path" => "unknown",
          "state" => "fleet_member_connected",
          "action" => "view device",
          "name_conflicts_with_roster" => nil,
          "connected" => true,
          "compatible" => true,
          "runtime_running" => true,
          "last_probe" => "2026-09-17T09:00:00Z"
        }
      ])
    end

    test "reads as in the fleet, and offers its details rather than a deployment", context do
      ouro!(context, devices: member_inventory())
      conn = web!(context)

      {:ok, view, html} = live(conn, "/devices")

      assert html =~ "in the fleet"
      assert html =~ ~s(data-state="fleet_member_connected")
      assert view |> element(~s{#devices-list}) |> render() =~ "buildbox"

      row = view |> element(~s{[data-address="100.64.0.2"]}) |> render()
      refute row =~ "Add to fleet"
      assert row =~ "Details"
    end

    test "the cluster's questions are in the details panel, with the exact instant",
         context do
      ouro!(context, devices: member_inventory())
      conn = web!(context)

      {:ok, view, _html} = live(conn, "/devices")

      html =
        view
        |> element(~s{button[phx-click="inspect-device"][phx-value-address="100.64.0.2"]})
        |> render_click()

      # Four different questions, never collapsed into one another. This runtime's cluster
      # does not know the machine the fixture invented, so each reads "not reported" —
      # which is the point: absent is not "no".
      assert html =~ "Connected to this runtime"
      assert html =~ "Compatible build"
      assert html =~ "Its runtime is running"
      assert html =~ "Last answered this runtime"

      # Section 5.1 keeps the ISO instant off the rows and puts it here, where somebody
      # opened a panel to ask for it.
      assert html =~ "2026-09-01T00:00:00Z"
    end

    test "presence on a row is the network's answer, and only that" do
      # The old row joined five facts with interpuncts, including a raw timestamp. The
      # network client's answer is one of them; the cluster's are the panel's.
      offline =
        Devices.presence_word(
          %{"online" => false, "last_seen" => "2026-09-15T00:00:00Z"},
          ~U[2026-09-18 00:00:00Z]
        )

      assert offline == "offline, seen 3 days ago"

      assert Devices.presence_word(%{"online" => true}) == "online"

      # Nothing reported is not "offline".
      assert Devices.presence_word(%{"online" => nil}) == "presence not reported"
      assert Devices.presence_word(%{}) == "presence not reported"
    end

    test "the dot follows the word rather than carrying it" do
      assert Devices.presence_dot(%{"online" => true}) == "●"
      assert Devices.presence_dot(%{"online" => false}) == "○"
      assert Devices.presence_dot(%{"online" => nil}) == "–"
    end

    test "a fact the runtime could not establish is not reported as no", context do
      unknown =
        Map.put(@devices, "devices", [
          %{
            "name" => "buildbox",
            "machine" => "buildbox",
            "suggested_machine" => "buildbox",
            "os" => "linux",
            "address" => "100.64.0.2",
            "online" => nil,
            "last_seen" => nil,
            "path" => "unknown",
            "state" => "fleet_member",
            "action" => "view device",
            "name_conflicts_with_roster" => nil,
            "connected" => nil,
            "compatible" => nil,
            "runtime_running" => nil,
            "last_probe" => nil
          }
        ])

      ouro!(context, devices: unknown)
      conn = web!(context)

      {:ok, view, _html} = live(conn, "/devices")

      row = view |> element(~s{[data-address="100.64.0.2"]}) |> render()
      assert row =~ "presence not reported"
      refute row =~ "offline"

      html =
        view
        |> element(~s{button[phx-click="inspect-device"][phx-value-address="100.64.0.2"]})
        |> render_click()

      # `nil` is "not reported", which is a different answer from "no".
      assert html =~ "not reported"
      refute html =~ "<dd>no</dd>"
    end
  end

  # ------------------------------------------------------------------------------------
  # Four claims a mutant walked past
  # ------------------------------------------------------------------------------------

  describe "what the page will not do" do
    setup context do
      issuer!(context.root)
      worker = worker!(context)
      %{conn: web!(context), worker: worker}
    end

    test "send a digest it did not vouch for, even when the click carries one",
         %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok =
        FleetWorkerFake.challenge(worker, "rv-2", "review", %{
          "metadata" => %{"plan" => plan(), "plan_digest" => Devices.plan_digest(plan())}
        })

      _ = await(view, "Ready to deploy")

      # A click is a message, and this one carries a digest of some *other* document — the
      # shape is right, the plan is not. Approval sends one thing about a plan, so it is the
      # one thing this page checks rather than repeats.
      html = render_click(view, "approve", %{"digest" => String.duplicate("a", 64)})

      refute_receive {:fake_worker, %{"op" => "respond"}}, 500
      assert html =~ "not this page"
      assert html =~ ~s(id="ouro-deploy-error")
    end

    test "ask for a handover when all it was told to do was resume",
         %{conn: conn, root: root} do
      # Retry is a resume of this identity's *own* operation, and the attach frame it sends
      # says so: `takeover: false`. The worker records a takeover when one happens and binds
      # every later challenge to whoever took it, so a page that set the flag by default
      # would make every ordinary recovery a silent handover with an audit line to match.
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)
      journal!(root, operation, %{"state" => "failed", "kind" => "add"})
      detach!(operation)

      view |> element(~s{button[phx-click="resume"]}) |> render_click()

      assert_receive {:fake_worker, %{"op" => "attach"} = frame}, @receive_timeout
      assert frame["takeover"] == false, "an ordinary retry asked the worker for a takeover"

      # And the explicit one does say so.
      detach!(operation)
      render_click(view, "resume", %{"operation" => operation, "takeover" => "true"})

      assert_receive {:fake_worker, %{"op" => "attach"} = taken}, @receive_timeout
      assert taken["takeover"] == true
    end

    test "render a step detail as markup", %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      # Both paths a detail is drawn on: a step the page files under one of the six stages,
      # and one it does not — `test_task` belongs to none of them and is drawn under its own
      # name. A test that only exercised one left the other rendering whatever arrived.
      for {step, marker} <- [{"install", "stage"}, {"test_task", "extra"}] do
        payload = "<img src=x onerror=window.#{marker}=1>"

        :ok =
          FleetWorkerFake.emit(worker, %{
            "event" => "step",
            "machine" => "vps-1",
            "step" => step,
            "outcome" => "failed",
            "detail" => payload
          })

        # Awaited on a marker unique to *this* step, because the escaped form of the other
        # one is already on the page — a wait satisfied by the previous iteration's evidence
        # would let the assertion below pass without ever seeing this step at all.
        html = await(view, "window.#{marker}=1")

        refute html =~ payload, "#{step}'s detail was rendered as markup"
        refute html =~ "<img src=x"

        # And on the element itself, so the claim cannot be satisfied by the other step's
        # escaped copy sitting elsewhere on the page.
        drawn = view |> element(~s{[data-step="#{step}"]}) |> render()
        assert drawn =~ "window.#{marker}=1"
        refute drawn =~ "<img", "#{step}'s own row carries a tag"
      end

      # And a log line, which is the third thing a worker quotes a remote machine into.
      :ok = FleetWorkerFake.emit(worker, %{"event" => "log", "line" => "<b>from ssh</b>"})
      html = await(view, "&lt;b&gt;from ssh")
      refute html =~ "<b>from ssh"
    end

    test "refuse something without saying so out loud", %{conn: conn, worker: worker} do
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.challenge(worker, "pw-9", "password", %{"metadata" => %{}})
      _ = await(view, "data-ouro-secret")
      :ok = FleetWorkerFake.refuse_next(worker, "authentication_failed")

      view |> form("#ouro-deploy-auth", %{"secret" => "wrong"}) |> render_submit()
      assert_receive {:fake_worker, %{"op" => "respond"}}, @receive_timeout

      # A refusal an operator has to notice a red box to learn about is a refusal a screen
      # reader never mentions. It goes to the live region as well.
      assert :sys.get_state(view.pid).socket.assigns.announcement =~ "refused the request"
    end
  end

  describe "a challenge's own facts" do
    test "are read from the top of the challenge, and from a nested metadata too" do
      # Both shapes, because the broker lifts and an older one did not. `metadata/1` is the
      # one place that decision lives, so it is the one place worth pinning.
      lifted = %{"challenge" => "c", "kind" => "password", "user" => "deploy", "port" => 22}
      nested = %{"challenge" => "c", "kind" => "password", "metadata" => %{"user" => "deploy"}}

      assert Devices.metadata(lifted)["user"] == "deploy"
      assert Devices.metadata(lifted)["port"] == 22
      assert Devices.metadata(nested)["user"] == "deploy"
      assert Devices.metadata(nil) == %{}

      # And the labels come out of whichever shape carried them.
      assert Devices.secret_label(Map.put(lifted, "target", "100.64.0.9")) ==
               "Password for deploy@100.64.0.9"

      assert Devices.secret_label(%{"kind" => "passphrase", "key_label" => "~/.ssh/id"}) ==
               "Passphrase for the key ~/.ssh/id"
    end
  end

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

  test "a reopened local setup can resume before its CA exists", context do
    worker!(context)
    conn = web!(context)
    {:ok, view, _} = live(conn, "/devices")
    render_click(view, "setup-device", %{"address" => "100.64.0.7"})

    view
    |> form("#ouro-deploy-setup", %{"machine" => "studio", "address" => "100.64.0.7"})
    |> render_submit()

    assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
    operation = operation(view)
    journal!(context.root, operation, %{"state" => "failed", "kind" => "setup"})
    detach!(operation)
    {:ok, reopened, _} = live(conn, "/devices?operation=" <> operation)
    socket = :sys.get_state(reopened.pid).socket
    assert socket.assigns.drawer.kind == "setup"
    assert :ok == DevicesLive.allowed?(socket, :setup)
    render_click(reopened, "resume", %{"operation" => operation})
    assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
  end

  describe "review follow-ups" do
    setup context do
      %{worker: worker!(context)}
    end

    test "local setup with no CA key still shows Cancel setup", context do
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      view
      |> element(~s{button[phx-click="setup-device"][phx-value-address="100.64.0.7"]})
      |> render_click()

      view
      |> form("#ouro-deploy-setup", %{"machine" => "studio", "address" => "100.64.0.7"})
      |> render_submit()

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      html = render(view)
      assert html =~ "Cancel setup"
      refute has_element?(view, ~s{button[phx-click="cancel-setup"][disabled]})

      view |> element(~s{button[phx-click="cancel-setup"]}) |> render_click()
      assert_receive {:fake_worker, %{"op" => "cancel"}}, @receive_timeout
    end

    test "opening a second operation resets the drawer and unsubscribes the first", context do
      issuer!(context.root)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")
      first = prepared(view)
      {:ok, first_pid} = Ouroboros.Fleet.Deployment.client(first)

      second = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
      journal!(context.root, second, %{"state" => "interrupted", "kind" => "add"})

      view |> element(~s{button[phx-click="refresh"]}) |> render_click()
      render_click(view, "open-operation", %{"operation" => second})

      drawer = :sys.get_state(view.pid).socket.assigns.drawer
      assert drawer.operation == second
      assert drawer.cancelled? == false
      assert drawer.approved == nil
      assert drawer.residue == []
      assert drawer.secret_nonce == 0
      assert drawer.takeover == nil
      refute drawer.operation == first

      # The cast has to land; the first client must no longer be notifying this view.
      Process.sleep(50)
      refute Map.has_key?(:sys.get_state(first_pid).subscribers, view.pid)
    end

    test "a bidi-control device name is sanitized in the host-trust step", context do
      issuer!(context.root)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      evil = "good\u202Etxt.exe"

      :sys.replace_state(view.pid, fn %{socket: socket} = state ->
        drawer = socket.assigns.drawer
        device = Map.put(drawer.device || %{}, "name", evil)
        %{state | socket: Phoenix.Component.assign(socket, :drawer, %{drawer | device: device})}
      end)

      :ok =
        FleetWorkerFake.challenge(context.worker, "ht-bidi", "host_trust", %{
          "metadata" => %{"address" => evil, "port" => "22"}
        })

      html = await(view, "First time connecting")
      refute html =~ <<0x202E::utf8>>
      assert html =~ "good"
    end

    test "Details opens a read-only panel on a member, and Open a link on this machine",
         context do
      issuer!(context.root)
      conn = web!(context)
      {:ok, view, html} = live(conn, "/devices")

      # The machine this runtime is on does not get a details drawer: section 5.1 sends it
      # to the machines panel instead.
      refute has_element?(
               view,
               ~s{button[phx-click="inspect-device"][phx-value-address="100.64.0.1"]}
             )

      assert html =~ ~s(<a class="ouro-button" href="/status">Open</a>)

      assert has_element?(
               view,
               ~s{button[phx-click="inspect-device"][phx-value-address="100.64.0.2"]}
             )

      assert html =~ "Details"

      html =
        view
        |> element(~s{button[phx-click="inspect-device"][phx-value-address="100.64.0.2"]})
        |> render_click()

      assert html =~ "Name in the fleet"
      assert html =~ "Name on the network"
      assert html =~ "Its runtime is running"
      assert html =~ "not reported"
      assert has_element?(view, ~s{#ouro-deploy button[phx-click="refresh"]})
    end

    test "read scope still gets the details panel", context do
      issuer!(context.root)
      conn = web!(context, scope: :read)
      {:ok, view, _html} = live(conn, "/devices")

      html =
        view
        |> element(~s{button[phx-click="inspect-device"][phx-value-address="100.64.0.2"]})
        |> render_click()

      assert html =~ "Name in the fleet"
      refute has_element?(view, ~s{button[phx-click="cancel-setup"]})
    end

    test "a pending authenticate is refused after the bind becomes cleartext", context do
      issuer!(context.root)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)

      :ok = FleetWorkerFake.challenge(context.worker, "pw-stale", "password")
      _ = await(view, ~s(data-ouro-secret))

      config = Config.for_endpoint(Ouroboros.Web.Endpoint)
      Phoenix.Config.put(Ouroboros.Web.Endpoint, :ouroboros_web, %{config | bind: {0, 0, 0, 0}})

      html =
        view
        |> form("#ouro-deploy-auth", %{"challenge" => "pw-stale", "secret" => "stale-secret"})
        |> render_submit()

      assert html =~ "credential entry is refused here"
      refute_receive {:fake_worker, %{"op" => "respond"}}, 400
    end

    test "forwarded headers do not change the cleartext bind decision", context do
      issuer!(context.root)

      conn =
        web!(context, bind: {0, 0, 0, 0}, allow_remote: true)
        |> Plug.Conn.put_req_header("x-forwarded-for", "127.0.0.1")
        |> Plug.Conn.put_req_header("x-forwarded-proto", "https")
        |> Map.put(:host, "ouro.example")

      {:ok, view, html} = live(conn, "/devices")
      assert html =~ "credential entry is refused here"
      refute has_element?(view, ~s{button[phx-click="deploy"]:not([disabled])})
    end

    test "a raise in authenticate assigns a generic error and never logs the secret",
         context do
      issuer!(context.root)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")
      _operation = prepared(view)
      :ok = FleetWorkerFake.challenge(context.worker, "pw-boom", "password")
      _ = await(view, ~s(data-ouro-secret))

      secret = "LIVE-SECRET-#{System.unique_integer([:positive])}"

      :sys.replace_state(view.pid, fn %{socket: socket} = state ->
        %{state | socket: Phoenix.Component.assign(socket, :crash_point, fn -> raise "boom" end)}
      end)

      log =
        capture_log(fn ->
          view
          |> form("#ouro-deploy-auth", %{"challenge" => "pw-boom", "secret" => secret})
          |> render_submit()
        end)

      refute log =~ secret
      assert render(view) =~ "The setup could not complete that action."
    end

    test "malformed events do not crash the view", context do
      issuer!(context.root)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      assert render_click(view, "deploy", %{})
      assert render_click(view, "filter", %{"filter" => "nope"})
      assert render_click(view, "approve", %{})
      assert render_click(view, "no-such-event", %{"x" => 1})
    end
  end

  # ------------------------------------------------------------------------------------
  # What the 2026-09-18 review asked for
  # ------------------------------------------------------------------------------------

  describe "relative time" do
    # Section 5.1: a row says how long ago, never an ISO instant. `now` is an argument so
    # this states the moment it is asking about instead of racing the wall clock.
    @now ~U[2026-09-18 12:00:00Z]

    test "reads as a person would say it" do
      assert Devices.relative_time("2026-09-18T11:59:30Z", @now) == "just now"
      assert Devices.relative_time("2026-09-18T11:57:00Z", @now) == "3 min ago"
      assert Devices.relative_time("2026-09-18T11:00:00Z", @now) == "1 hour ago"
      assert Devices.relative_time("2026-09-18T10:00:00Z", @now) == "2 hours ago"
      assert Devices.relative_time("2026-09-17T12:00:00Z", @now) == "1 day ago"
      assert Devices.relative_time("2026-09-15T12:00:00Z", @now) == "3 days ago"
    end

    test "never pluralises the abbreviation, and never counts backwards" do
      assert Devices.relative_time("2026-09-18T11:59:00Z", @now) == "1 min ago"
      refute Devices.relative_time("2026-09-18T11:55:00Z", @now) =~ "mins"

      # Two clocks that disagree is ordinary on a private network, and a negative age is
      # not a thing to show anybody.
      assert Devices.relative_time("2026-09-18T12:30:00Z", @now) == "just now"
    end

    test "answers nothing for what it cannot read, so a caller can fall back" do
      assert Devices.relative_time(nil, @now) == nil
      assert Devices.relative_time("", @now) == nil
      assert Devices.relative_time("the day before yesterday", @now) == nil
      assert Devices.relative_time(%{"at" => 1}, @now) == nil
    end
  end

  describe "the Advanced disclosure" do
    setup context do
      issuer!(context.root)
      ouro!(context)
      %{conn: web!(context)}
    end

    test "stays open across a change event on the form it lives in", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      view
      |> element(~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})
      |> render_click()

      refute has_element?(view, "details.ouro-devices-advanced[open]")

      html =
        view
        |> element(~s{summary[phx-click="advanced"]})
        |> render_click()

      assert html =~ ~s(<details class="ouro-devices-advanced" open)
      assert has_element?(view, "details.ouro-devices-advanced[open]")

      # Finding 6. The element carried no `open` attribute and the `advanced` event wrote a
      # field nothing read, so every keystroke in the form above collapsed the disclosure.
      html =
        view
        |> form("#ouro-deploy-connect", %{"ssh_user" => "d"})
        |> render_change()

      assert html =~ ~s(<details class="ouro-devices-advanced" open),
             "a change event on the form collapsed the disclosure again"

      assert has_element?(view, "details.ouro-devices-advanced[open]")

      # And it still closes when it is asked to.
      view |> element(~s{summary[phx-click="advanced"]}) |> render_click()
      refute has_element?(view, "details.ouro-devices-advanced[open]")
    end
  end

  describe "a worker that stopped" do
    setup context do
      issuer!(context.root)
      %{worker: worker!(context), conn: web!(context)}
    end

    test "is quoted in its own last words, with a Retry", %{conn: conn, root: root} do
      {:ok, view, _html} = live(conn, "/devices")
      operation = prepared(view)

      # Section 5.5: the journal is unfinished, no `done` frame exists, and the runtime can
      # say why the worker is gone. Finding 5 is the page without it — the reason was in
      # the worker's private log and the operation sat at "inspecting" saying nothing.
      #
      # The snapshot is written into the drawer directly because `Journal.@fields` does not
      # carry `worker_exit` yet: that allowlist is the runtime half of section 5.5 and is
      # landing separately. What is asserted here is this page's half — that a snapshot
      # carrying the field is drawn, in the worker's words, with the one control that does
      # something about it.
      _ = root

      :sys.replace_state(view.pid, fn state ->
        put_in(state.socket.assigns.drawer.status, %{
          "operation" => operation,
          "state" => "inspecting",
          "kind" => "add",
          "source" => "journal",
          "attached" => false,
          "worker_exit" => %{
            "code" => 1,
            "last_lines" => ["socket path is 118 bytes", "giving up"]
          }
        })
      end)

      # Any event that re-assigns the drawer republishes it; `advanced` is the one that
      # touches nothing else, so what is drawn below is the injected snapshot rather than a
      # side effect of the event.
      html = render_click(view, "advanced", %{"open" => "true"})

      assert html =~ "The setup worker stopped: socket path is 118 bytes · giving up"
      assert html =~ "data-ouro-worker-exit"

      assert has_element?(view, ~s{[data-ouro-worker-exit] button[phx-click="resume"]})
    end

    test "says nothing when the runtime did not say" do
      # No record is not an accusation. The ordinary "no worker is attached" reading stands.
      assert Devices.worker_exit(nil) == nil
      assert Devices.worker_exit(%{}) == nil
      assert Devices.worker_exit(%{"last_lines" => []}) == nil
      assert Devices.worker_exit(%{"last_lines" => ["", "  "]}) == nil
      assert Devices.worker_exit(%{"code" => 1}) == nil
    end

    test "sanitizes what the worker quoted out of a remote machine" do
      said = Devices.worker_exit(%{"last_lines" => ["<b>boom</b>", "line\ttwo"]})

      assert said == "The setup worker stopped: <b>boom</b> · line two"
    end
  end

  describe "a development runtime" do
    test "blocks setting this machine up, and says why in one sentence" do
      assert Devices.deploy_blocker("dev_runtime", nil) ==
               "This is a development runtime; the packaged `ouro` is what sets a machine up."

      assert Devices.deploy_blocker("dev_runtime", :standalone) =~ "packaged `ouro`"
    end

    test "is a reason for setup and not for adding another machine" do
      # Section 5.5: `dev_runtime` blocks `setup` only. A dev runtime cannot set *itself*
      # up — the LaunchAgent it writes exits 1 — but adding a machine over SSH installs a
      # packaged release on the target, which this runtime's own shape says nothing about.
      refute DevicesLive.setup?(socket_with(["dev_runtime"]))
      refute DevicesLive.setup?(socket_with(["dev_runtime", "no_ca_key"]))

      # And the one reason that is not a reason for a local setup still is not.
      assert DevicesLive.setup?(socket_with(["no_ca_key"]))
      assert DevicesLive.setup?(socket_with([]))

      # Any other blocker stops both.
      refute DevicesLive.setup?(socket_with(["no_data_dir"]))
    end

    defp socket_with(reasons) do
      %{
        assigns: %{
          scope: :operate,
          availability: :available,
          inventory: %{
            "host" => %{
              "os" => "darwin",
              "capabilities" => %{"deploy" => reasons == [], "reasons" => reasons}
            },
            "devices" => []
          }
        }
      }
    end
  end

  describe "removing a member" do
    setup context do
      issuer!(context.root)
      %{worker: worker!(context), conn: web!(context)}
    end

    test "is reached from the member's details panel, not from its row", %{conn: conn} do
      {:ok, view, html} = live(conn, "/devices")

      # Section 5.1: "Remove from fleet lives in the member's details panel, not on the row."
      refute html =~ "Remove from fleet"

      html =
        view
        |> element(~s{button[phx-click="inspect-device"][phx-value-address="100.64.0.2"]})
        |> render_click()

      assert html =~ "Remove from fleet"

      assert has_element?(
               view,
               ~s{button[phx-click="leave-device"][phx-value-address="100.64.0.2"]}
             )
    end

    test "sends kind leave with the roster machine, and never an address as a name",
         %{conn: conn, fake_dir: fake_dir} do
      {:ok, view, _html} = live(conn, "/devices")

      view
      |> element(~s{button[phx-click="inspect-device"][phx-value-address="100.64.0.2"]})
      |> render_click()

      html =
        view
        |> element(~s{button[phx-click="leave-device"][phx-value-address="100.64.0.2"]})
        |> render_click()

      # Section 5.4's sentence, named after the machine rather than "this device".
      assert html =~ "Remove buildbox from the fleet"
      assert html =~ "Stop Ouroboros on buildbox, retire its credentials"
      assert html =~ "Its sessions and data stay on that machine."

      # A member that cannot be reached still has a way out, and it is the CLI's.
      assert html =~ "ouro fleet sessions forget buildbox"

      _ = fake_dir

      view
      |> form("#ouro-deploy-leave", %{"ssh_user" => "deploy"})
      |> render_change()

      # The document this drawer sends. Asserted on the request rather than on what a fake
      # worker received, because `fleet.deployment.prepare` does not accept `leave` yet —
      # that is the runtime half of section 5.5, landing separately — and a page that built
      # the wrong document would otherwise be caught only after that lands.
      request = DevicesLive.prepare_params(:sys.get_state(view.pid).socket.assigns.drawer)

      assert request["kind"] == "leave"
      assert request["target"]["machine"] == "buildbox"
      assert request["ssh_user"] == "deploy"
      assert request["port"] == 22

      # A leave names a roster machine. Sending an address as the target would be asking
      # the engine to retire whatever answers at it.
      refute Map.has_key?(request["target"], "address")

      # And no secret travels in it, on any path.
      for key <- ~w(secret password passphrase), do: refute(Map.has_key?(request, key))
    end

    test "an add names both the address and the machine", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      view
      |> element(~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})
      |> render_click()

      view
      |> form("#ouro-deploy-connect", %{"ssh_user" => "deploy"})
      |> render_change()

      request = DevicesLive.prepare_params(:sys.get_state(view.pid).socket.assigns.drawer)

      assert request["kind"] == "add"
      assert request["target"]["address"] == "100.64.12.44"
      # Finding 2 and finding 3: a machine name, and the suggested one rather than the
      # display name.
      assert request["target"]["machine"] == "vps-1"
    end

    test "cannot be aimed at a device that is not a member", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      # `vps-1` is a discovered peer, not a roster member. The event is a message a browser
      # sends, so the gate is asked again where a click cannot skip it.
      html = render_click(view, "leave-device", %{"address" => "100.64.12.44"})

      assert html =~ "not a member this fleet can remove"
      refute has_element?(view, "#ouro-deploy-leave")

      html = render_click(view, "leave-device", %{"address" => "10.0.0.1"})
      assert html =~ "does not list that address"
    end
  end

  describe "the one change event this page has" do
    setup context do
      issuer!(context.root)
      ouro!(context)
      %{conn: web!(context)}
    end

    test "never carries a password, whatever is submitted to it", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/devices")

      view
      |> element(~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})
      |> render_click()

      # `connect-change` merges only the keys the form already has, so a field that is not
      # one of them is dropped rather than kept. Nothing on this page streams a secret.
      html =
        render_change(view, "connect-change", %{
          "address" => "100.64.12.44",
          "secret" => "hunter2",
          "password" => "hunter2"
        })

      form = :sys.get_state(view.pid).socket.assigns.drawer.form

      refute Map.has_key?(form, "secret")
      refute Map.has_key?(form, "password")
      refute html =~ "hunter2"
      refute render(view) =~ "hunter2"
    end

    test "is not on the form that carries one", context do
      worker = worker!(context)
      {:ok, view, _html} = live(context.conn, "/devices")
      _operation = prepared(view)

      :ok =
        FleetWorkerFake.challenge(worker, "pw-nc", "password", %{
          "metadata" => %{"user" => "deploy", "target" => "100.64.12.44"}
        })

      html = await(view, "data-ouro-secret")

      # The one rule the secret-handling section forbids breaking by name: the field that
      # takes a password is submitted once and never streamed.
      [auth_form] = Regex.run(~r/<form id="ouro-deploy-auth"[^>]*>/, html)

      refute auth_form =~ "phx-change"
      assert auth_form =~ ~s(phx-submit="authenticate")
      assert html =~ ~s(type="password")
      assert html =~ "Password for deploy@100.64.12.44"
    end
  end
end
