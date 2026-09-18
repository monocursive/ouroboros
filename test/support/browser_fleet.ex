defmodule Ouroboros.Test.BrowserFleet do
  @moduledoc """
  A deployment this browser fixture can actually walk through, with no SSH and no network.

  `test/browser/devices.spec.js` has to drive the Deploy drawer from a real browser:
  keyboard-only navigation, the polite live region, the masked field. None of that is
  reachable unless `fleet.devices` answers and `fleet.deployment.prepare` really forks a
  worker, so this stands two fixtures up inside the fixture runtime:

    * a fake `ouro` (`Ouroboros.Test.FleetOuroFake`) at an absolute path, which answers
      `fleet devices --json` with a frozen inventory and, for `fleet worker start`, writes
      the capability file and prints the socket of the fake worker below;
    * a **scripted** `Ouroboros.Test.FleetWorkerFake`, which this process owns. It receives
      every frame the broker sends and answers the way a deployment does: host trust, then a
      password, then a plan to review, then steps, then done.

  Nothing here authenticates to anything. The password the browser types goes to a socket in
  this BEAM and is dropped; there is no SSH client, no remote machine and no credential
  store anywhere in the path.

  ## Why the workers rotate, and why the warm one is replaced on a timer

  A fake worker serves one attach and then refuses a second (`already_attached`), and
  Playwright runs this spec once per project. So a worker that has been attached to is
  retired: the moment one accepts an attach, a fresh one is started on a new socket and the
  fake `ouro`'s printed spawn line is pointed at it. The next deployment gets a clean worker
  without the fixture having to guess how many runs there will be.

  The warm one is also replaced every ten seconds, because the fake's acceptor gives up
  after thirty seconds of nobody connecting — and in a full browser run the Devices spec is
  minutes apart from itself across two projects. Replaced, not stopped: an old one keeps
  listening until its own acceptor gives up, so a `prepare` that read the spawn line a
  moment before it changed still finds something at the other end.

  Which worker a frame came from is **asked**, not assumed. The fake forwards every frame
  without saying who sent it, and guessing "the one this process last pointed at" is wrong
  exactly when the refresh timer has just fired between a `prepare` and its attach — which
  is a fixture that hangs, in one project, some of the time. `FleetWorkerFake.attached/1`
  answers it for certain.

  Test support, loaded only by the fixture runtime. It is never part of a release.
  """

  use GenServer

  alias Ouroboros.Test.FleetOuroFake
  alias Ouroboros.Test.FleetWorkerFake

  @name __MODULE__

  # The fake worker's acceptor gives up after thirty seconds; a browser run is longer than
  # that, so the warm worker is replaced well inside it. `@keep` bounds how many of the
  # replaced ones this process still remembers.
  @refresh_ms 10_000
  @keep 24

  # The frozen inventory. One row per branch of the proposal's observed-state table that a
  # browser can see: this machine, a member that is not visible, a peer nothing has
  # inspected, a peer wearing a member's name, and a platform with no release.
  @inventory %{
    "fleet_protocol_revision" => 5,
    "discovery" => %{
      "code" => "ok",
      "reason" => nil,
      "detail" => nil,
      "client" => %{"version" => "1.80.0"},
      "self" => %{"name" => "fixture-studio"},
      "visible_peers" => 3
    },
    "devices" => [
      %{
        "name" => "fixture-studio",
        "machine" => "fixture-studio",
        "os" => "macos",
        "address" => "100.100.0.1",
        "online" => true,
        "last_seen" => nil,
        "path" => "direct",
        "state" => "this_device",
        "action" => "view device",
        "name_conflicts_with_roster" => nil
      },
      %{
        "name" => "fixture-buildbox",
        "machine" => "fixture-buildbox",
        "os" => nil,
        "address" => "100.100.0.2",
        "online" => nil,
        "last_seen" => nil,
        "path" => "unknown",
        "state" => "fleet_member_not_visible",
        "action" => "diagnose",
        "name_conflicts_with_roster" => nil
      },
      %{
        "name" => "fixture-toaster",
        "machine" => nil,
        "os" => "plan9",
        "address" => "100.100.0.9",
        "online" => false,
        "last_seen" => "2026-09-01T00:00:00Z",
        "path" => "unknown",
        "state" => "unsupported_platform",
        "action" => "nothing to deploy",
        "name_conflicts_with_roster" => nil
      }
    ]
  }

  # `Plan::to_value/0` in tui/src/fleet_setup/plan.rs, field for field. A fixture that
  # invented its own key names would let the page agree with itself about a shape the real
  # worker never sends.
  defp plan(request) do
    machine = machine_of(request)

    %{
      "schema" => 1,
      "operation" => "fixture",
      "kind" => request["kind"] || "add",
      "deployment_host" => %{
        "hostname" => "fixture-studio",
        "user" => "fixture",
        "os" => "macos",
        "arch" => "aarch64",
        "issuer" => true
      },
      "target" => %{
        "machine" => machine,
        "address" => request["address"],
        "port" => request["ssh_port"] || 22,
        "ssh_user" => request["ssh_user"] || "",
        "identity" => "agent identity SHA256:fixtureAgentKey",
        "install_path" => request["install_path"] || "/usr/local/bin/ouro",
        "data_dir" => request["remote_data_dir"] || "/home/deploy/.ouroboros",
        "host_fingerprint" => "SHA256:fixtureFingerprintNotARealHostKey",
        "node" => "ouro@#{machine}"
      },
      "release" => %{
        "version" => "0.1.8",
        "target" => "x86_64-unknown-linux-gnu",
        "asset" => "ouro-0.1.8-x86_64-unknown-linux-gnu.tar.gz",
        "sha256" => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "official_origin" => true
      },
      "service" => "managed",
      "members" => [
        %{
          "machine" => "fixture-studio",
          "host" => "100.100.0.1",
          "reached_by" => "local",
          "change" => "add #{machine}"
        }
      ],
      "restart" => nil,
      "grants" => [
        "Joining grants broad authority between this fleet's machines: connected nodes can reach each other's runtimes."
      ],
      "build" => nil
    }
  end

  # Ten identical uninspected peers. A deployment leaves a journal behind, and a journal is
  # what makes a row stop reading as an untouched peer — correctly, and permanently for the
  # life of this fixture runtime. Playwright runs this spec once per project against one
  # server, so a spec that reused one row would have its second test looking at the first
  # test's leftovers. A row each is the cheap, honest way out.
  @peers 10

  defp peers do
    for index <- 1..@peers do
      %{
        "name" => "fixture-peer-#{String.pad_leading("#{index}", 2, "0")}",
        "machine" => nil,
        "os" => "linux",
        "address" => "100.100.7.#{index}",
        "online" => true,
        "last_seen" => "2026-09-16T10:00:00Z",
        "path" => "relayed",
        "state" => "discovered_installation_unknown",
        "action" => "deploy Ouroboros",
        "name_conflicts_with_roster" => nil
      }
    end
  end

  defp inventory, do: %{@inventory | "devices" => @inventory["devices"] ++ peers()}

  @doc "Stands the fixture up. Called once, by the fixture runtime, after the app boots."
  @spec seed() :: {:ok, pid()}
  def seed do
    data_dir = Application.fetch_env!(:ouroboros, :data_dir)

    # The fleet CA private key is what makes this machine an issuer. It is never read as a
    # key by anything in this path; `capabilities.deploy` asks whether the file is there.
    fleet = Path.join(data_dir, "fleet")
    File.mkdir_p!(fleet)
    File.write!(Path.join(fleet, "ca-key.pem"), "browser fixture; not a key\n")
    File.chmod!(Path.join(fleet, "ca-key.pem"), 0o600)

    # Every journal this fixture wrote on a previous run, gone. The data directory outlives
    # the server — Playwright keeps `_build/playwright-j2-data` between runs — and a journal
    # is exactly the thing that makes a device's row stop offering Deploy. Left behind, the
    # second run of this spec looks at the first run's leftovers and finds no button.
    deploy = Path.join(data_dir, "deploy")

    case File.ls(deploy) do
      {:ok, names} ->
        for name <- names, String.ends_with?(name, ".json"), do: File.rm(Path.join(deploy, name))

      {:error, _absent} ->
        :ok
    end

    # `start/3`, not `start_link/3`. The fixture runtime script is a Mix task process that
    # finishes the moment it has seeded everything, and a linked fixture dies with it — which
    # is a Devices spec whose deployment never answers, in a way that looks like the page
    # being broken. Nothing supervises this; it is a fixture, and its lifetime is the node's.
    GenServer.start(__MODULE__, [data_dir: data_dir], name: @name)
  end

  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    # The fake workers are linked children of this process. Trapping exits keeps a worker
    # that fell over from taking the fixture — and with it every later Devices spec — down
    # with it.
    Process.flag(:trap_exit, true)

    data_dir = Keyword.fetch!(opts, :data_dir)
    bin = Path.join(data_dir, "fleet-fixture-bin")
    cap = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)

    # Not under the data directory: `sun_path` is 104 bytes, and a worktree's `_build` path
    # is most of that on its own. A short private directory of this fixture's own is what
    # the client's own check wants anyway — owned by this account, mode 0700.
    sockets =
      Path.join(
        System.tmp_dir!(),
        "ouro-bf-#{Base.encode16(:crypto.strong_rand_bytes(4), case: :lower)}"
      )

    File.rm_rf!(sockets)
    File.mkdir_p!(sockets)
    File.chmod!(sockets, 0o700)

    state = %{
      data_dir: data_dir,
      sockets: sockets,
      bin: bin,
      cap: cap,
      serving: nil,
      next: nil,
      workers: [],
      subject: nil,
      counter: 0
    }

    state = warm(state)

    ouro =
      FleetOuroFake.write!(bin,
        devices: JSON.encode!(inventory()) <> "\n",
        spawn_line: FleetWorkerFake.spawn_line(state.next),
        cap: cap
      )

    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)
    Process.send_after(self(), :refresh, @refresh_ms)
    {:ok, state}
  end

  # A fresh worker on a socket of its own, warm and waiting for the next `prepare`.
  defp warm(state) do
    counter = state.counter + 1
    socket = Path.join(state.sockets, "f#{counter}.sock")

    {:ok, worker} =
      FleetWorkerFake.start_link(
        socket_path: socket,
        cap: state.cap,
        instance: Base.encode16(:crypto.strong_rand_bytes(8), case: :lower),
        operation_file: FleetOuroFake.operation_file(state.bin),
        owner: self()
      )

    %{
      state
      | next: worker,
        workers: Enum.take([worker | state.workers], @keep),
        counter: counter
    }
  end

  @impl true
  # The script. Every frame the broker sends arrives here, and each one answers the next
  # thing a real deployment would ask for.
  def handle_info({:fake_worker, %{"op" => "attach"} = frame}, state) do
    case attached_worker(state) do
      nil ->
        {:noreply, state}

      serving ->
        state = %{state | serving: serving, subject: frame["subject"]} |> warm()
        FleetOuroFake.put_spawn_line!(state.bin, FleetWorkerFake.spawn_line(state.next))
        journal(state, "deploying")

        asked = request(state)

        FleetWorkerFake.challenge(serving, "fixture-host", "host_trust", %{
          "metadata" => %{
            "address" => asked["address"],
            "port" => asked["ssh_port"] || 22,
            "algorithm" => "ssh-ed25519",
            "sha256_fingerprint" => "SHA256:fixtureFingerprintNotARealHostKey",
            "user" => asked["ssh_user"]
          }
        })

        {:noreply, state}
    end
  end

  def handle_info({:fake_worker, %{"op" => "respond", "challenge" => "fixture-host"}}, state) do
    FleetWorkerFake.emit(state.serving, %{"event" => "state", "state" => "awaiting_auth"})

    asked = request(state)

    FleetWorkerFake.challenge(state.serving, "fixture-password", "password", %{
      "metadata" => %{
        "target" => asked["address"],
        "user" => asked["ssh_user"],
        "port" => asked["ssh_port"] || 22,
        "attempt" => 1,
        "max_attempts" => 3
      }
    })

    {:noreply, state}
  end

  def handle_info({:fake_worker, %{"op" => "respond", "challenge" => "fixture-password"}}, state) do
    FleetWorkerFake.emit(state.serving, %{"event" => "state", "state" => "awaiting_review"})

    FleetWorkerFake.challenge(state.serving, "fixture-review", "review", %{
      "metadata" => %{"plan" => plan(request(state)), "plan_digest" => digest(request(state))}
    })

    {:noreply, state}
  end

  def handle_info({:fake_worker, %{"op" => "respond", "challenge" => "fixture-review"}}, state) do
    FleetWorkerFake.emit(state.serving, %{"event" => "state", "state" => "deploying"})
    Process.send_after(self(), {:step, 0}, 90)
    {:noreply, state}
  end

  # The engine's own step names and outcomes (`step_event` in
  # tui/src/fleet_setup/engine.rs), including the `skipped` readiness it really records.
  def handle_info({:step, index}, state) do
    machine = machine_of(request(state))

    case Enum.at(steps(machine), index) do
      {machine, step, outcome, detail} ->
        FleetWorkerFake.emit(state.serving, %{
          "event" => "step",
          "machine" => machine,
          "step" => step,
          "outcome" => outcome,
          "detail" => detail
        })

        Process.send_after(self(), {:step, index + 1}, 90)

      nil ->
        journal(state, "completed")

        # `done_frame/1` in worker.rs: `ok`, a state, a one-line summary, the next thing to
        # do, residue and what could not be established. There is no `ready` flag.
        FleetWorkerFake.emit(state.serving, %{
          "event" => "done",
          "ok" => true,
          "state" => "completed",
          "summary" => "#{machine} joined this fleet",
          "next" => "Configure a model on #{machine}, then run a test task.",
          "residue" => [],
          "unknown" => [
            "#{machine}'s provider, model and workspace prerequisites — configure a model on #{machine}"
          ]
        })
    end

    {:noreply, state}
  end

  # Replace the warm worker before its acceptor times out. The one it replaces is left
  # listening rather than stopped, so a `prepare` that read the previous spawn line still
  # finds something at the other end.
  def handle_info(:refresh, state) do
    state = warm(state)
    FleetOuroFake.put_spawn_line!(state.bin, FleetWorkerFake.spawn_line(state.next))
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, state}
  end

  def handle_info({:EXIT, _pid, _reason}, state), do: {:noreply, state}

  def handle_info(_other, state), do: {:noreply, state}

  # The durable record the real worker writes and this runtime reads when no worker is
  # attached. Without one, `fleet.devices` lists no operations at all — and the row that a
  # deployment has touched would go back to reading as an untouched peer the moment the
  # drawer closed, which is the thing the page is supposed to stop doing.
  defp journal(state, operation_state) do
    with {:ok, id} <- File.read(FleetOuroFake.operation_file(state.bin)),
         id = String.trim(id),
         true <- id != "" do
      asked = request(state)
      now = DateTime.utc_now() |> DateTime.to_iso8601()
      dir = Path.join(state.data_dir, "deploy")
      File.mkdir_p!(dir)
      File.chmod!(dir, 0o700)
      path = Path.join(dir, id <> ".json")

      File.write!(
        path,
        JSON.encode!(%{
          "schema" => 1,
          "operation" => id,
          "owner" => state.subject,
          "kind" => asked["kind"] || "add",
          "state" => operation_state,
          "created_at" => now,
          "updated_at" => now,
          "target" => %{
            "machine" => machine_of(asked),
            "address" => asked["address"],
            "ssh_user" => asked["ssh_user"],
            "port" => asked["ssh_port"] || 22
          }
        })
      )

      File.chmod!(path, 0o600)
    else
      _no_operation_yet -> :ok
    end
  end

  defp steps(machine) do
    [
      {machine, "inspect", "ok", "reachable, and no Ouroboros installed"},
      {machine, "install_binary", "started", nil},
      {machine, "install_binary", "ok", "/usr/local/bin/ouro"},
      {machine, "prepare", "ok", nil},
      {machine, "issue", "ok", nil},
      {machine, "install", "ok", nil},
      {"fixture-studio", "roster", "ok", "revision 4"},
      {machine, "roster", "ok", "revision 4"},
      {machine, "service", "ok", "an Ouroboros-owned user service"},
      {machine, "connect", "ok", nil},
      {machine, "readiness", "skipped",
       "provider, model and workspace prerequisites on the new member are unknown from here"}
    ]
  end

  # What the broker asked for: the request file the fake `ouro` recorded before unlinking
  # it. Every fact the fixture reports about "the target" comes from here rather than from a
  # constant, so ten spare peers are ten different deployments and not ten readings of one.
  defp request(state) do
    case FleetOuroFake.request_body(state.bin) do
      body when is_binary(body) ->
        case JSON.decode(body) do
          {:ok, decoded} when is_map(decoded) -> decoded
          _unreadable -> %{}
        end

      _absent ->
        %{}
    end
  end

  defp machine_of(request), do: request["machine"] || request["address"] || "the target"

  # A real worker sends the sha256 of the plan it built (`Plan::digest/0`), and the page
  # refuses to approve anything else — so a fixture that made a digest up would be a fixture
  # that could not get past the review step. That the Elixir side of this agrees with the
  # Rust side is proved separately, against a real worker, in
  # `test/ouroboros/web/live/devices_plan_digest_test.exs`.
  defp digest(request), do: Ouroboros.Web.Live.Devices.plan_digest(plan(request))

  # The newest worker that has an attachment and is not the one already being served. The
  # fake records the attachment while handling the very frame it forwarded here, so by the
  # time this call is answered the answer is settled.
  defp attached_worker(state) do
    Enum.find(state.workers, fn worker ->
      worker != state.serving and Process.alive?(worker) and FleetWorkerFake.attached(worker)
    end)
  end
end
