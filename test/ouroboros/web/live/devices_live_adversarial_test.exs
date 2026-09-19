defmodule Ouroboros.Web.Live.DevicesLiveAdversarialTest do
  @moduledoc """
  Slice KE adversarial review of `/devices`.

  Three questions the existing suite does not put: where a submitted secret is once the
  LiveView process has handled the form; what §10's "any administrator may answer" looks like
  to the *second* administrator; and what the page does with a string the program or the
  target wrote.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log
  @moduletag :ke_review

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Fleet.Deployment
  alias Ouroboros.Test.FleetFramesFake
  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint
  @token String.duplicate("d", 40)
  @cookie "_ouroboros_web"

  @devices %{
    "discovery" => %{"code" => "ok", "client" => %{"version" => "1.80.0"}, "visible_peers" => 1},
    "devices" => [
      %{
        "name" => "vps-1",
        "machine" => nil,
        "suggested_machine" => "vps-1",
        "os" => "linux",
        "address" => "100.64.12.44",
        "online" => true,
        "last_seen" => nil,
        "path" => "direct",
        "state" => "discovered_installation_unknown",
        "action" => "add to fleet",
        "name_conflicts_with_roster" => nil
      }
    ]
  }

  setup do
    root = Path.join(System.tmp_dir!(), "okdwebadv#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o700)
    bin = Path.join(root, "bin")

    previous = %{
      data_dir: Application.get_env(:ouroboros, :data_dir),
      dev_runtime: Application.get_env(:ouroboros, :dev_runtime),
      web: Application.get_env(:ouroboros, :web),
      ouro: System.get_env("OUROBOROS_PROCESS_ID_HELPER")
    }

    Application.put_env(:ouroboros, :data_dir, root)
    Application.put_env(:ouroboros, :dev_runtime, false)

    on_exit(fn ->
      reap_workers()
      Process.sleep(150)
      FleetFramesFake.uninstall!()
      restore(:data_dir, previous.data_dir)
      restore(:dev_runtime, previous.dev_runtime)
      restore(:web, previous.web)

      if previous.ouro,
        do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous.ouro),
        else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      _ = File.rm_rf(root)
    end)

    %{root: root, bin: bin}
  end

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

  defp ouro!(context, scenario) do
    FleetFramesFake.install!(context.bin, devices: JSON.encode!(@devices) <> "\n")
    FleetFramesFake.write_scenario!(context.bin, scenario)
    :ok
  end

  defp web!(context) do
    token_path = Path.join(context.root, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)

    config = Config.new!(data_dir: context.root, scope: :operate)
    start_supervised!({Ouroboros.Web, config: config, server: false})
    freeze_recovery()

    conn = get(build_conn(), "/auth?token=#{@token}")
    put_req_cookie(build_conn(), @cookie, conn.resp_cookies[@cookie].value)
  end

  defp freeze_recovery do
    case Process.whereis(Ouroboros.Interactive.Recovery) do
      nil ->
        :ok

      pid ->
        :ok = :sys.suspend(pid)
        on_exit(fn -> if Process.alive?(pid), do: :sys.resume(pid) end)
    end
  end

  defp await(view, needle, message \\ nil) do
    Enum.reduce_while(1..200, :missing, fn _attempt, _acc ->
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

  defp add!(view) do
    view
    |> element(~s{button[phx-click="deploy"][phx-value-address="100.64.12.44"]})
    |> render_click()

    view
    |> form("#ouro-deploy-connect", %{
      "address" => "100.64.12.44",
      "machine" => "vps-1",
      "ssh_user" => "deploy"
    })
    |> render_submit()

    view
  end

  defp operation(view), do: :sys.get_state(view.pid).socket.assigns.drawer.operation

  # ---------------------------------------------------------------------------
  # W1 — the secret after the LiveView has handled the form
  # ---------------------------------------------------------------------------

  describe "W1 the submitted secret" do
    test "is in no assign, no rendered byte and no process this page owns", context do
      ouro!(context, [
        "state running",
        "state waiting",
        "challenge secret-1 password {\"target\":\"100.64.12.44\",\"user\":\"deploy\"}",
        "await secret-1",
        "step inspect ok reachable",
        "sleep 5"
      ])

      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")
      add!(view)
      await(view, "data-ouro-secret")

      secret = "liveview-secret-#{System.unique_integer([:positive])}"

      html =
        view
        |> form("#ouro-deploy-auth", %{"challenge" => "secret-1", "secret" => secret})
        |> render_submit()

      refute html =~ secret, "the re-render must not echo it"

      # It really did arrive, so the absences below are absences and not a test that proved
      # nothing.
      arrived =
        Enum.reduce_while(1..200, false, fn _attempt, _acc ->
          if Enum.any?(FleetFramesFake.responses(context.bin), &(&1 =~ secret)),
            do: {:halt, true},
            else: Process.sleep(20) && {:cont, false}
        end)

      assert arrived, "the secret never reached the program's stdin"

      state = :sys.get_state(view.pid)
      dumped = inspect(state, limit: :infinity, printable_limit: :infinity)
      refute dumped =~ secret, "the LiveView socket holds it"

      # The LiveView process is an ordinary process: not `:sensitive`, and its mailbox and
      # dictionary are readable by anything on the node that can name it.
      refute inspect(Process.info(view.pid, :messages), limit: :infinity) =~ secret
      refute inspect(Process.info(view.pid, :dictionary), limit: :infinity) =~ secret

      # And the operation it was typed into carries nothing of it.
      assert {:ok, snapshot} = Deployment.status(operation(view))
      refute JSON.encode!(snapshot) =~ secret
    end

    test "the field is replaced rather than refilled", context do
      ouro!(context, [
        "state running",
        "state waiting",
        "challenge secret-1 password {\"user\":\"deploy\"}",
        "await secret-1",
        "challenge secret-2 password {\"user\":\"deploy\",\"attempt\":2}",
        "await secret-2",
        "sleep 5"
      ])

      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")
      add!(view)
      html = await(view, "data-ouro-secret")
      assert html =~ ~s(id="ouro-deploy-secret-0")

      view
      |> form("#ouro-deploy-auth", %{"challenge" => "secret-1", "secret" => "first"})
      |> render_submit()

      later = await(view, "ouro-deploy-secret-1")
      assert later =~ ~s(id="ouro-deploy-secret-1")
      refute later =~ ~s(value="first")
    end
  end

  # ---------------------------------------------------------------------------
  # W2 — §10: two administrators, one prompt
  # ---------------------------------------------------------------------------

  describe "W2 a second administrator on the same challenge" do
    test "the second page is told what happened to the plan it is looking at", context do
      ouro!(context, [
        "state running",
        "plan Install ouro 0.1.10 (Linux arm64) to /usr/local/bin/ouro",
        "plan Join the fleet as vps-1",
        "state waiting",
        "challenge review-1 review {}",
        "await review-1",
        "state running",
        "step install ok /usr/local/bin/ouro",
        "sleep 5"
      ])

      conn = web!(context)

      {:ok, adele, _html} = live(conn, "/devices")
      add!(adele)
      await(adele, "Ready to deploy")
      id = operation(adele)

      # The second administrator opens the same operation by its id, which is the address
      # §10 says reopens it. Both are now looking at the same plan.
      {:ok, olive, _html} = live(conn, "/devices?operation=#{id}")
      await(olive, "Ready to deploy")

      # Adele approves.
      adele
      |> element(~s{button[phx-click="approve"]})
      |> render_click()

      # Olive's page is subscribed to the worker, so it should move off the review of its own
      # accord once the program says anything more.
      moved_on =
        Enum.reduce_while(1..200, false, fn _attempt, _acc ->
          html = render(olive)

          if html =~ "Ready to deploy",
            do: Process.sleep(20) && {:cont, false},
            else: {:halt, true}
        end)

      assert moved_on, """
      Olive's drawer is still showing "Ready to deploy" with a live Deploy button after
      Adele approved the same challenge. §10 says any administrator may answer the prompt in
      front of them; it does not say the second one should keep being offered a button that
      cannot work.
      """
    end

    test "the second click on a consumed challenge is explained in words", context do
      ouro!(context, [
        "state running",
        "plan Install ouro 0.1.10 (Linux arm64) to /usr/local/bin/ouro",
        "state waiting",
        "challenge review-1 review {}",
        "await review-1",
        # The program does not move on, so the second page is still looking at the plan.
        "sleep 8"
      ])

      conn = web!(context)

      {:ok, adele, _html} = live(conn, "/devices")
      add!(adele)
      await(adele, "Ready to deploy")
      id = operation(adele)

      {:ok, olive, _html} = live(conn, "/devices?operation=#{id}")
      await(olive, "Ready to deploy")

      adele |> element(~s{button[phx-click="approve"]}) |> render_click()

      html = olive |> element(~s{button[phx-click="approve"]}) |> render_click()

      assert html =~ "already been answered",
             """
             Olive is told nothing that names what happened. The refusal the runtime gave is
             `challenge_consumed`, whose sentence is "that challenge has already been
             answered"; what the page renders instead is:

             #{html |> String.split("ouro-refusal") |> Enum.at(1) |> to_string() |> String.slice(0, 400)}
             """
    end
  end

  # ---------------------------------------------------------------------------
  # W3 — what the program and the target wrote, rendered
  # ---------------------------------------------------------------------------

  describe "W3 untrusted strings on the page" do
    test "markup, escapes and bidi in a plan line, a step detail and a log line",
         context do
      ouro!(context, [
        "state running",
        "plan <img src=x onerror=alert(1)> RIGHT-TO-LEFT",
        "state waiting",
        "challenge review-1 review {}",
        "await review-1",
        "step install failed <script>alert(2)</script>",
        "log <b>bold</b> and a tab\tinside",
        "sleep 8"
      ])

      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")
      add!(view)
      html = await(view, "Ready to deploy")

      refute html =~ "<img src=x onerror",
             "a plan line is a sentence a remote machine wrote"

      assert html =~ "&lt;img src=x onerror" or html =~ "&lt;img"

      view |> element(~s{button[phx-click="approve"]}) |> render_click()
      later = await(view, "alert(2)")

      refute later =~ "<script>alert(2)</script>"
      refute later =~ "<b>bold</b>"
    end

    test "a device that names itself with markup and a bidi override", context do
      devices = %{
        @devices
        | "devices" => [
            Map.merge(hd(@devices["devices"]), %{
              "name" => "<s>evil</s>\u202Egnp.exe",
              "suggested_machine" => "vps-1"
            })
          ]
      }

      FleetFramesFake.install!(context.bin, devices: JSON.encode!(devices) <> "\n")
      FleetFramesFake.write_scenario!(context.bin, ["state running", "sleep 1"])

      conn = web!(context)
      {:ok, _view, html} = live(conn, "/devices")

      refute html =~ "<s>evil</s>"
      refute html =~ "\u202E", "U+202E reverses everything a reader sees after it"
    end
  end

  # ---------------------------------------------------------------------------
  # W4 — the drawer after the runtime stops watching
  # ---------------------------------------------------------------------------

  describe "W4 the drawer when the worker goes" do
    test "a killed worker mid-setup is reported as unknown rather than as a failure",
         context do
      ouro!(context, [
        "state running",
        "step inspect ok reachable",
        "state waiting",
        "challenge trust-1 host_trust {\"address\":\"100.64.12.44\"}",
        "await trust-1",
        "sleep 8"
      ])

      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")
      add!(view)
      await(view, "First time connecting")
      id = operation(view)

      {:ok, worker} = Deployment.worker(id)
      Process.exit(worker, :kill)

      html =
        Enum.reduce_while(1..200, nil, fn _attempt, _acc ->
          rendered = render(view)

          if rendered =~ "journal" or rendered =~ "No worker is attached",
            do: {:halt, rendered},
            else: Process.sleep(20) && {:cont, nil}
        end)

      assert html, "the drawer never noticed the worker was gone"

      refute html =~ "Setup failed",
             "a runtime that stopped watching has not watched a failure (§8)"

      assert html =~ "No worker is attached"
    end
  end

  # ---------------------------------------------------------------------------
  # W5 — the step key the page reads is not the one either source writes
  # ---------------------------------------------------------------------------

  describe "W5 step[\"outcome\"]" do
    test "neither a worker frame nor a schema-2 journal ever carries it", context do
      ouro!(context, [
        "state running",
        "step inspect attempted reading the machine",
        "sleep 8"
      ])

      conn = web!(context)
      {:ok, view, _html} = live(conn, "/devices")
      add!(view)
      await(view, "Read the machine")

      assert {:ok, %{"steps" => [step]}} = Deployment.status(operation(view))

      # §6's journal and §8's `step` frame both name it `state`, with the four values
      # `ok|failed|skipped|attempted`.
      assert step["state"] == "attempted"

      refute Map.has_key?(step, "outcome"), """
      `Ouroboros.Web.Live.DevicesLive.current_detail/1` (devices_live.ex) looks for
      `step["outcome"] == "started"`, and `Ouroboros.Web.Live.Devices.readiness/2` and its
      `connected?/1` look for `step["outcome"] in ["ok", "skipped"]`. Neither key nor value
      exists on either side of the seam: `Worker.put_step/2` writes `step`/`state`/`detail`,
      §6's journal writes `step`/`state`/`at`/`detail`, and §6's four values do not include
      "started". `current_detail/1` therefore always falls through to its `List.last/1`
      branch; `readiness/2` always takes its `{_unreported, …}` clauses.
      """
    end

    test "readiness/2 also names a step §6 does not have" do
      # §6's setup steps are create, stop_runtime, service, start, ready — never "readiness".
      steps = [%{"step" => "ready", "state" => "ok", "detail" => nil}]

      assert Ouroboros.Web.Live.Devices.readiness(steps, %{"ok" => true}) ==
               {"This machine reported that it is ready.", true},
             """
             The function looks for a step named `readiness` and for an `outcome` key on it.
             §6 names that step `ready` and that key `state`, so with the engine's own shape
             it answers #{inspect(Ouroboros.Web.Live.Devices.readiness(steps, %{"ok" => true}))}
             — the "nothing was reported" clause — for a setup whose readiness step says
             `ok`. Its `done["ok"]` is not a field §8's `done` frame has either, and the
             function has no caller in lib/.
             """
    end
  end
end
