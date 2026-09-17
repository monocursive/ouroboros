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
        "name" => "fixture-vps",
        "machine" => nil,
        "os" => "linux",
        "address" => "100.100.0.44",
        "online" => true,
        "last_seen" => "2026-09-16T10:00:00Z",
        "path" => "relayed",
        "state" => "discovered_installation_unknown",
        "action" => "deploy Ouroboros",
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

  @plan %{
    "release" => "0.1.8",
    "machine" => "fixture-vps",
    "install_path" => "/usr/local/bin/ouro",
    "data_dir" => "/home/deploy/.ouroboros",
    "service" => "an Ouroboros-owned user service",
    "members_to_update" => "fixture-studio",
    "trust" => "this fleet's certificate authority will sign the new member"
  }

  @digest "sha256:fixture-plan-digest"

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
      counter: 0
    }

    state = warm(state)

    ouro =
      FleetOuroFake.write!(bin,
        devices: JSON.encode!(@inventory) <> "\n",
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
  def handle_info({:fake_worker, %{"op" => "attach"}}, state) do
    case attached_worker(state) do
      nil ->
        {:noreply, state}

      serving ->
        state = %{state | serving: serving} |> warm()
        FleetOuroFake.put_spawn_line!(state.bin, FleetWorkerFake.spawn_line(state.next))

        FleetWorkerFake.challenge(serving, "fixture-host", "host_trust", %{
          "peer" => "fixture-vps",
          "address" => "100.100.0.44",
          "port" => 22,
          "user" => "deploy",
          "algorithm" => "ssh-ed25519",
          "sha256_fingerprint" => "SHA256:fixtureFingerprintNotARealHostKey"
        })

        {:noreply, state}
    end
  end

  def handle_info({:fake_worker, %{"op" => "respond", "challenge" => "fixture-host"}}, state) do
    FleetWorkerFake.emit(state.serving, %{"event" => "state", "state" => "awaiting_auth"})

    FleetWorkerFake.challenge(state.serving, "fixture-password", "password", %{
      "user" => "deploy",
      "host" => "100.100.0.44",
      "attempt" => 1,
      "attempts_allowed" => 3
    })

    {:noreply, state}
  end

  def handle_info({:fake_worker, %{"op" => "respond", "challenge" => "fixture-password"}}, state) do
    FleetWorkerFake.emit(state.serving, %{"event" => "state", "state" => "awaiting_review"})

    FleetWorkerFake.challenge(state.serving, "fixture-review", "review", %{
      "plan" => @plan,
      "plan_digest" => @digest
    })

    {:noreply, state}
  end

  def handle_info({:fake_worker, %{"op" => "respond", "challenge" => "fixture-review"}}, state) do
    FleetWorkerFake.emit(state.serving, %{"event" => "state", "state" => "deploying"})
    Process.send_after(self(), {:step, 0}, 120)
    {:noreply, state}
  end

  def handle_info({:step, index}, state) do
    steps = [
      {"inspect", "reachable, and no Ouroboros installed"},
      {"install", "0.1.8 verified against the official checksum"},
      {"membership", "the roster on both machines now names the other"},
      {"startup", "an Ouroboros-owned user service"},
      {"connect", "the new member joined the cluster"},
      {"readiness", "the runtime answered its own status"}
    ]

    case Enum.at(steps, index) do
      {name, detail} ->
        FleetWorkerFake.emit(state.serving, %{
          "event" => "step",
          "name" => name,
          "outcome" => "ok",
          "detail" => detail
        })

        Process.send_after(self(), {:step, index + 1}, 120)

      nil ->
        FleetWorkerFake.emit(state.serving, %{
          "event" => "done",
          "state" => "completed",
          "ready" => true
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

  # The newest worker that has an attachment and is not the one already being served. The
  # fake records the attachment while handling the very frame it forwarded here, so by the
  # time this call is answered the answer is settled.
  defp attached_worker(state) do
    Enum.find(state.workers, fn worker ->
      worker != state.serving and Process.alive?(worker) and FleetWorkerFake.attached(worker)
    end)
  end
end
