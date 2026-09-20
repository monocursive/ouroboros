defmodule Ouroboros.Web.Live.DevicesLiveTest do
  @moduledoc """
  `/devices`, driven the way an operator drives it, with no SSH anywhere in it.

  The fake is the point. `Ouroboros.Test.FleetFramesFake` is a real executable file at a real
  absolute path, so `fleet.devices` really runs something and really parses what it printed,
  and a deployment really opens a port and really reads §8 frames off its stdout. A challenge
  this page renders crossed a pipe; a secret this page submits is one a test can watch
  arrive.

  Not async: it moves `config :ouroboros, :data_dir`, `config :ouroboros, :audit`, the web
  config and the `OUROBOROS_*` environment, all of which are node-global.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Audit.Config, as: AuditConfig
  alias Ouroboros.Test.FleetFramesFake
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Live.Devices
  alias Ouroboros.Web.Live.DevicesLive

  @endpoint Ouroboros.Web.Endpoint
  @token String.duplicate("d", 40)
  @cookie "_ouroboros_web"

  # The inventory every rendering test reads. One row per branch of the observed-state table
  # this build can reach, including the device that has taken a member's name.
  @devices %{
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
        "name_conflicts_with_roster" => nil
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
        "name_conflicts_with_roster" => nil
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
        "name_conflicts_with_roster" => nil
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
        "name_conflicts_with_roster" => nil
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
        "name_conflicts_with_roster" => nil
      }
    ]
  }

  setup do
    root = Path.join(System.tmp_dir!(), "ouro-w3a-#{System.unique_integer([:positive])}")
    Ouroboros.DataDir.ensure_private!(root)
    bin = Path.join(root, "bin")

    previous = %{
      data_dir: Application.get_env(:ouroboros, :data_dir),
      audit: Application.get_env(:ouroboros, :audit),
      web: Application.get_env(:ouroboros, :web),
      ouro: System.get_env("OUROBOROS_PROCESS_ID_HELPER")
    }

    Application.put_env(:ouroboros, :data_dir, root)

    on_exit(fn ->
      reap_workers()
      Process.sleep(150)
      FleetFramesFake.uninstall!()
      restore(:data_dir, previous.data_dir)
      restore(:audit, previous.audit)
      restore(:web, previous.web)

      if previous.ouro,
        do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous.ouro),
        else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      _ = File.rm_rf(root)
    end)

    %{root: root, bin: bin}
  end

  # The noun the page uses for the machine it is running on, and the button that follows it.
  # Computed here the way the page computes it — from `:os.type/0`, which is what
  # `Deployment.host/1` reports as `host.os` — so this suite reads the same on either.
  defp host_os, do: :os.type() |> elem(1) |> Atom.to_string()
  defp self_label, do: Devices.self_label(host_os())
  defp setup_label, do: Devices.setup_label(host_os())

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp reap_workers do
    supervisor = Ouroboros.Fleet.Deployment.WorkerSupervisor

    supervisor
    |> DynamicSupervisor.which_children()
    |> Enum.each(fn {_id, pid, _type, _modules} ->
      if is_pid(pid), do: DynamicSupervisor.terminate_child(supervisor, pid)
    end)
  catch
    :exit, _not_running -> :ok
  end

  # ------------------------------------------------------------------------------------
  # Fixtures
  # ------------------------------------------------------------------------------------

  defp ouro!(context, opts \\ []) do
    document = Keyword.get(opts, :devices, @devices)

    FleetFramesFake.install!(context.bin, devices: JSON.encode!(document) <> "\n")
    FleetFramesFake.write_scenario!(context.bin, Keyword.get(opts, :scenario, happy()))
    :ok
  end

  # This machine's own members, which is the closed set a `leave` may name.
  defp members!(root, members) do
    dir = Path.join(root, "fleet")
    File.mkdir_p!(dir)
    path = Path.join(dir, "profile.json")

    File.write!(
      path,
      JSON.encode!(%{
        "schema" => 2,
        "machine" => "studio",
        "host" => "100.64.0.1",
        "node" => "ouro-studio@100.64.0.1",
        "dist_port" => 13_700,
        "members" => members
      })
    )

    File.chmod!(path, 0o600)
    path
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

  # The page reads a live program, so what it renders lags the frame by a message or two.
  # Polling `render/1` is the honest wait: it is the same HTML a person would be looking at.
  defp await(view, needle, message \\ nil) do
    Enum.reduce_while(1..150, :missing, fn _attempt, _acc ->
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

  defp operation(view), do: :sys.get_state(view.pid).socket.assigns.drawer.operation

  # The whole of a deployment that works, in the directives the fake reads.
  defp happy do
    [
      "state running",
      "state waiting",
      "challenge trust-1 host_trust {\"address\":\"100.64.12.44\",\"port\":22,\"algorithm\":\"ssh-ed25519\",\"sha256_fingerprint\":\"SHA256:fixtureFingerprintNotARealHostKey\",\"user\":\"deploy\"}",
      "await trust-1",
      "challenge secret-1 password {\"target\":\"100.64.12.44\",\"user\":\"deploy\",\"port\":22,\"attempt\":1,\"max_attempts\":3}",
      "await secret-1",
      "step inspect ok reachable, and no Ouroboros installed",
      "plan Install ouro 0.1.10 (Linux arm64) to /usr/local/bin/ouro",
      "plan Join the fleet as vps-1",
      "challenge review-1 review {}",
      "await review-1",
      "state running",
      "step install ok /usr/local/bin/ouro",
      "step join ok -",
      "step service ok an Ouroboros-owned user service",
      "step start ok -",
      "step connect ok -",
      "done completed vps-1 joined this fleet"
    ]
  end

  # Straight to the review, which is what a `setup` and a `leave` do in this suite: the two
  # challenges before it are the same panels the add flow already proved.
  defp review_only(plan_lines) do
    ["state running"] ++
      Enum.map(plan_lines, &"plan #{&1}") ++
      ["state waiting", "challenge review-1 review {}", "await review-1"]
  end

  # Open the add drawer on a row and submit its form.
  defp add!(view, address \\ "100.64.12.44", machine \\ "vps-1", user \\ "deploy") do
    view
    |> element(~s{button[phx-click="deploy"][phx-value-address="#{address}"]})
    |> render_click()

    view
    |> form("#ouro-deploy-connect", %{
      "address" => address,
      "machine" => machine,
      "ssh_user" => user
    })
    |> render_submit()

    view
  end

  # ------------------------------------------------------------------------------------
  # The list
  # ------------------------------------------------------------------------------------

  describe "the inventory" do
    test "is one list, in one order, with the codes on the rows", context do
      ouro!(context)
      conn = web!(context)

      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ ~s(data-state="this_device")
      assert html =~ ~s(data-state="fleet_member_not_visible")
      assert html =~ ~s(data-state="discovered_installation_unknown")
      assert html =~ ~s(data-state="unsupported_platform")

      # The self row first, then the fleet's members, then everything else.
      states = Regex.scan(~r/data-state="([a-z_]+)"/, html) |> Enum.map(&Enum.at(&1, 1))
      assert Enum.take(states, 2) == ["this_device", "this_device_without_profile"]
      assert "fleet_member_not_visible" in states

      # The words are the nine short phrases, not the proposal's table.
      assert html =~ "in the fleet · not connected"
      assert html =~ "not set up"
      assert html =~ "can&#39;t run Ouroboros"
      refute html =~ "Discovered peer; Ouroboros installation unknown"

      # One quiet line about where the work happens, and no boxed paragraph.
      assert html =~ "data-ouro-deployment-host"
      assert html =~ "Actions run on"
    end

    test "presence is a dot, a word and a relative time, never an ISO instant", context do
      ouro!(context)
      conn = web!(context)

      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "online"
      assert html =~ "offline, seen"
      assert html =~ "presence not reported"
      refute html =~ "2026-09-01T00:00:00Z"
    end

    test "the status line is the blocker sentence for a machine in no fleet", context do
      ouro!(context)
      conn = web!(context)

      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "#{self_label()} is not in a fleet yet."
      assert html =~ setup_label()
    end

    test "a profile this build refuses outranks both shapes of the status line" do
      # `fleet.status` carries `profile` as null or `{reason, message}`, and the message is
      # §2's own sentence. "Not in a fleet yet" would be the wrong repair to send somebody
      # to: this machine *is* in a fleet, one written by an older Ouroboros.
      refused = %{
        profile: %{
          reason: :unsupported_profile_schema,
          message:
            "this fleet's profile was written by a different version of Ouroboros than the one running here; run `ouro fleet leave` here and set the fleet up again"
        }
      }

      assert Devices.status_line(refused, "darwin", true) =~ "a different version of Ouroboros"
      assert Devices.status_line(refused, "darwin", false) =~ "run `ouro fleet leave` here"

      # And a runtime that reports no such thing still gets the two ordinary shapes.
      assert Devices.status_line(%{profile: nil}, "darwin", true) =~ "is not in a fleet yet."
    end

    test "a peer wearing a member's name is named as the impostor it may be", context do
      ouro!(context,
        devices:
          put_in(@devices["devices"], [
            Enum.at(@devices["devices"], 0),
            %{
              Enum.at(@devices["devices"], 3)
              | "name" => "buildbox",
                "name_conflicts_with_roster" => "buildbox"
            }
          ])
      )

      conn = web!(context)
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "It is not that machine."
    end
  end

  describe "discovery" do
    test "quotes the client's own words and never claims a build is old", context do
      ouro!(context,
        devices:
          put_in(@devices["discovery"], %{
            "code" => "client_unreadable",
            "detail" => "The Tailscale GUI failed to start"
          })
      )

      conn = web!(context)
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "The Tailscale GUI failed to start"
      assert html =~ "Devices already in the fleet are still listed."
      refute html =~ "older than the client"
    end
  end

  # ------------------------------------------------------------------------------------
  # Add
  # ------------------------------------------------------------------------------------

  describe "adding a machine" do
    test "walks host trust, the password, the review, progress and done", context do
      ouro!(context)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      view = add!(view)
      operation = operation(view)
      assert String.match?(operation, ~r/\A[0-9a-f]{16}\z/)

      # 1. The host key, with the fingerprint and the command that checks it independently.
      html = await(view, "First time connecting to 100.64.12.44")
      assert html =~ "SHA256:fixtureFingerprintNotARealHostKey"
      assert html =~ "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"

      view
      |> element(~s{button[phx-click="trust-host"][phx-value-accept="true"]})
      |> render_click()

      # 2. The password, in one masked field with no phx-change on it.
      html = await(view, "Password for deploy@100.64.12.44")
      assert html =~ "(attempt 1 of 3)"
      assert html =~ ~s(type="password")
      refute html =~ ~s(phx-change="authenticate")

      view
      |> form("#ouro-deploy-auth", %{"challenge" => "secret-1", "secret" => "hunter2"})
      |> render_submit()

      # And it arrived, which is what makes the page's silence about it evidence.
      assert Enum.any?(
               FleetFramesFake.await_response(context.bin, "hunter2"),
               &String.contains?(&1, "hunter2")
             )

      # 3. The plan, as the lines it is. No digest, and nothing behind a disclosure.
      html = await(view, "Ready to deploy")
      assert html =~ "Install ouro 0.1.10 (Linux arm64) to /usr/local/bin/ouro"
      assert html =~ "Join the fleet as vps-1"
      refute html =~ "plan digest"
      refute html =~ "data-ouro-plan-digest"
      refute html =~ "Everything in this plan"

      view |> element(~s{button[phx-click="approve"]}) |> render_click()

      # 4. Progress, with the step names of an `add` and no stage this kind never runs.
      html = await(view, ~s(data-step="connect"))
      assert html =~ ~s(data-step="inspect")
      assert html =~ ~s(data-step="join")
      refute html =~ ~s(data-step="membership")

      # 5. Done, named after the machine. The program's own `summary` is on the snapshot only
      # while a process is holding the operation — §6's journal has no field for it — so the
      # heading is what has to carry the outcome, and it does.
      html = await(view, "vps-1 is in your fleet")
      assert html =~ "Done"
    end

    test "the address bar carries the operation, and reopening it reloads by id", context do
      ouro!(context)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      view = add!(view)
      operation = operation(view)
      await(view, "First time connecting")

      # A second view on the same operation answers the same prompt: §10 deletes the per-tab
      # binding, so there is no "this prompt belongs to another tab" left to draw.
      {:ok, second, _html} = live(conn, "/devices?operation=" <> operation)
      html = await(second, "First time connecting")
      refute html =~ "data-ouro-rebind"
      refute html =~ "data-ouro-takeover"

      second
      |> element(~s{button[phx-click="trust-host"][phx-value-accept="true"]})
      |> render_click()

      await(second, "Password for deploy@100.64.12.44")
    end

    test "add by address is the same form with the address editable", context do
      ouro!(context)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      html = render_click(view, "deploy-manual", %{})
      assert html =~ "Add a device by address"

      view
      |> form("#ouro-deploy-connect", %{
        "address" => "100.64.99.99",
        "machine" => "manual-1",
        "ssh_user" => "deploy"
      })
      |> render_submit()

      await(view, "First time connecting")

      assert Enum.take(FleetFramesFake.argv(context.bin), 5) == [
               "fleet",
               "add",
               "deploy@100.64.99.99",
               "--machine",
               "manual-1"
             ]
    end

    test "a name that is not a machine name is refused before anything is run", context do
      ouro!(context)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      view
      |> element(~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})
      |> render_click()

      html =
        view
        |> form("#ouro-deploy-connect", %{
          "address" => "100.64.12.44",
          "machine" => "not a name",
          "ssh_user" => "deploy"
        })
        |> render_submit()

      assert html =~ "Letters, digits and hyphens only"
      refute "--frames" in FleetFramesFake.argv(context.bin)
    end

    test "a deployment that fails says why and offers Retry", context do
      ouro!(context,
        scenario: [
          "state running",
          "step inspect ok reachable",
          "step install failed the release archive did not verify",
          "error install_failed the release archive did not verify",
          "done failed vps-1 was not added"
        ]
      )

      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      view = add!(view)

      html = await(view, "Setup failed")
      assert html =~ "the release archive did not verify"
      assert html =~ ~s(phx-click="resume")
      assert html =~ "Retry"
    end
  end

  # ------------------------------------------------------------------------------------
  # Leave and setup
  # ------------------------------------------------------------------------------------

  test "review shows the real helper's lines alongside its structured plan", context do
    lines = ["Join the fleet as vps-1", "Remember vps-1 on this machine"]
    metadata = JSON.encode!(%{"plan" => %{"kind" => "add"}, "lines" => lines})

    ouro!(context,
      scenario: [
        "state waiting",
        "challenge review-1 review #{metadata}",
        "await review-1",
        "done completed vps-1 joined this fleet"
      ]
    )

    {:ok, view, _html} = live(web!(context), "/devices")
    add!(view)
    html = await(view, "Remember vps-1 on this machine")
    assert html =~ "Join the fleet as vps-1"
    refute has_element?(view, ~s{button[phx-click="approve"][disabled]})
    view |> element(~s{button[phx-click="approve"]}) |> render_click()
    assert await(view, "vps-1 is in your fleet")

    assert Enum.any?(
             FleetFramesFake.responses(context.bin),
             &(JSON.decode!(&1)["accept"] == true)
           )
  end

  test "review with no readable plan cannot be approved, including a direct event", context do
    ouro!(context,
      scenario: [
        "state waiting",
        "challenge review-1 review {\"plan\":{\"kind\":\"add\"}}",
        "await review-1",
        "done completed should never run"
      ]
    )

    {:ok, view, _html} = live(web!(context), "/devices")
    add!(view)
    await(view, "This operation sent no readable plan")
    assert has_element?(view, ~s{button[phx-click="approve"][disabled]})
    html = render_click(view, "approve", %{"challenge" => "review-1"})
    assert html =~ "This operation sent no readable plan"
    assert FleetFramesFake.responses(context.bin) == []

    assert :sys.get_state(view.pid).socket.assigns.drawer.status["challenge"]["challenge"] ==
             "review-1"
  end

  describe "removing a member" do
    test "is reached from the details panel and reads as a removal", context do
      members!(context.root, [
        %{
          "machine" => "buildbox",
          "host" => "100.64.0.2",
          "node" => "ouro-buildbox@100.64.0.2",
          "dist_port" => 13_700
        }
      ])

      ouro!(context,
        scenario:
          review_only([
            "Stop Ouroboros on buildbox",
            "Remove its fleet credentials and its startup service",
            "Forget it here"
          ])
      )

      conn = web!(context)
      {:ok, view, html} = live(conn, "/devices")

      # Not on the row: §5.4 puts it in the member's details.
      refute html =~ ~s(phx-click="leave-device")

      row = Enum.find(@devices["devices"], &(&1["address"] == "100.64.0.2"))
      render_click(view, "inspect-device", %{"row" => Devices.row_id(row)})
      html = render(view)
      assert html =~ "Remove from fleet" or html =~ ~s(phx-click="leave-device")

      render_click(view, "leave-device", %{"address" => "100.64.0.2"})
      html = render(view)
      assert html =~ "Remove buildbox from the fleet"

      view
      |> form("#ouro-deploy-leave", %{"ssh_user" => "deploy"})
      |> render_submit()

      html = await(view, "Ready to remove")
      assert html =~ "Stop Ouroboros on buildbox"
      # The button says the same word as the heading.
      assert html =~ ">\n          Remove\n" or html =~ "Remove\n"

      assert FleetFramesFake.argv(context.bin) == [
               "fleet",
               "leave",
               "--machine",
               "buildbox",
               "--user",
               "deploy",
               "--port",
               "22",
               "--frames",
               "--operation",
               operation(view)
             ]
    end
  end

  describe "setting this machine up" do
    test "takes no account, asks for a name and an address, and reviews", context do
      ouro!(context,
        scenario:
          review_only(["Create this fleet on this machine", "Start at login as a user service"])
      )

      conn = web!(context)
      {:ok, view, html} = live(conn, "/devices")

      assert html =~ setup_label()
      render_click(view, "setup-device", %{"address" => "100.64.0.7"})
      html = render(view)
      assert html =~ setup_label()
      refute html =~ ~s(name="ssh_user")

      view
      |> form("#ouro-deploy-setup", %{"machine" => "spare", "address" => "100.64.0.7"})
      |> render_submit()

      html = await(view, "Ready to set up")
      assert html =~ "Create this fleet on this machine"

      argv = FleetFramesFake.argv(context.bin)
      assert Enum.take(argv, 4) == ["fleet", "setup", "--machine", "spare"]
      refute Enum.any?(argv, &String.contains?(&1, "@"))
    end

    test "a setup aimed at another device's address is refused", context do
      ouro!(context)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      html = render_click(view, "setup-device", %{"address" => "100.64.12.44"})

      assert html =~ "add it to the fleet instead"
      refute "--frames" in FleetFramesFake.argv(context.bin)
    end
  end

  # ------------------------------------------------------------------------------------
  # The gates
  # ------------------------------------------------------------------------------------

  describe "what the page will not do" do
    test "a hand-sent deploy at an address the inventory does not list is refused", context do
      ouro!(context)
      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")

      html = render_click(view, "deploy", %{"address" => "10.0.0.1"})

      assert html =~ "This machine&#39;s inventory does not list that address."
      refute "--frames" in FleetFramesFake.argv(context.bin)
    end

    test "a cleartext bind refuses the credential path even when a drawer is open", context do
      ouro!(context)
      conn = web!(context, bind: "0.0.0.0")
      {:ok, view, html} = live(conn, "/devices")

      assert html =~ "credential entry is refused here"

      # And the events themselves, which is the boundary rather than the rendering.
      html = render_click(view, "deploy-manual", %{})
      assert html =~ "credential entry is refused here"
      refute "--frames" in FleetFramesFake.argv(context.bin)
    end

    test "a read endpoint draws membership and no controls", context do
      ouro!(context)
      conn = web!(context, scope: :read)

      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "OUROBOROS_WEB_SCOPE=read"
      refute html =~ ~s(phx-click="deploy-manual")
    end

    test "a non-administrator is told so rather than shown the network", context do
      ouro!(context)
      identities!(context)

      Ouroboros.Audit.Identity.install(%{
        "id" => "olive",
        "token_sha256" => :crypto.hash(:sha256, "operator-token") |> Base.encode16(case: :lower)
      })

      on_exit(fn -> Ouroboros.Audit.Identity.install(nil) end)

      # The page asks this and draws the sentence it answers with. Asserted here rather than
      # through a mounted view, because a non-administrator's browser does not get as far as
      # a LiveView socket on this endpoint — and the distinction the function makes is the
      # thing under test: denied is not absent, and neither is out of scope.
      assert DevicesLive.availability(:operate, "fleet.devices") == :denied
      assert Devices.unavailable(:denied, "fleet.devices") =~ "is not an administrator"
      assert Devices.unavailable(:scope, "fleet.devices") =~ "OUROBOROS_WEB_SCOPE=read"
      assert Devices.unavailable(:absent, "fleet.devices") =~ "older build than this page"
    end
  end

  # ------------------------------------------------------------------------------------
  # The gate function itself, which every event asks
  # ------------------------------------------------------------------------------------

  describe "allowed?/2" do
    test "a dev runtime blocks a setup and nothing else", context do
      ouro!(context)
      conn = web!(context)

      previous = Application.get_env(:ouroboros, :dev_runtime)
      Application.put_env(:ouroboros, :dev_runtime, true)
      on_exit(fn -> Application.put_env(:ouroboros, :dev_runtime, previous) end)

      {:ok, view, _html} = live(conn, "/devices")
      socket = :sys.get_state(view.pid).socket

      assert {:refused, sentence} = DevicesLive.allowed?(socket, :setup)
      assert sentence =~ "development runtime"
      assert :ok == DevicesLive.allowed?(socket, :add)
      assert :ok == DevicesLive.allowed?(socket, :leave)
    end
  end

  # ------------------------------------------------------------------------------------
  # Operations on rows
  # ------------------------------------------------------------------------------------

  describe "an operation this machine is holding" do
    test "is drawn on its device's row with the words the state gives it", context do
      ouro!(context)

      journal!(context.root, "00aa11bb22cc33dd", %{
        "schema" => 2,
        "kind" => "add",
        "state" => "waiting",
        "target" => %{"machine" => "vps-1", "address" => "100.64.12.44"}
      })

      conn = web!(context)
      {:ok, view, html} = live(conn, "/devices")

      row = view |> element(~s{[data-address="100.64.12.44"]}) |> render()
      assert row =~ "waiting for you"
      assert row =~ "Continue"
      assert row =~ ~s(data-operation-state="waiting")

      # Nothing is left over for a panel to hold, so there is no panel.
      refute html =~ "Setups with no device on this list"
    end

    test "one whose device is not on this list gets the leftovers panel", context do
      ouro!(context)

      journal!(context.root, "11bb22cc33dd44ee", %{
        "schema" => 2,
        "kind" => "add",
        "state" => "failed",
        "target" => %{"machine" => "gone", "address" => "10.9.9.9"}
      })

      conn = web!(context)
      {:ok, _view, html} = live(conn, "/devices")

      assert html =~ "Setups with no device on this list"
      assert html =~ "11bb22cc33dd44ee"
    end
  end

  defp journal!(root, operation, document) do
    dir = Path.join(root, "deploy")
    File.mkdir_p!(dir)
    File.chmod!(dir, 0o700)
    path = Path.join(dir, operation <> ".json")

    now = DateTime.utc_now() |> DateTime.to_iso8601()

    File.write!(
      path,
      JSON.encode!(
        Map.merge(
          %{
            "operation" => operation,
            "created_at" => now,
            "updated_at" => now,
            "steps" => [],
            "plan" => []
          },
          document
        )
      )
    )

    File.chmod!(path, 0o600)
    path
  end
end
