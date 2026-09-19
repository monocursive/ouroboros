defmodule Ouroboros.Test.BrowserFleet do
  @moduledoc """
  A deployment this browser fixture can actually walk through, with no SSH and no network.

  `test/browser/devices.spec.js` has to drive the Devices drawer from a real browser:
  keyboard-only navigation, the polite live region, the masked field. None of that is
  reachable unless `fleet.devices` answers and `fleet.deployment.start` really runs a
  program, so this stands one fixture up inside the fixture runtime: a fake `ouro`
  (`Ouroboros.Test.FleetFramesFake`) at an absolute path, which answers
  `fleet devices --json` with a frozen inventory and, for a `--frames` run, speaks §8 on its
  own stdio and writes a real schema-2 journal.

  That is the whole of it. Before fleet-kiss this module was a GenServer holding a rotating
  pool of fake workers on Unix sockets, scripting a deployment frame by frame from the BEAM,
  because the broker connected to a *detached* worker it did not own. §9 makes the program an
  ordinary port program of the runtime that asked for it, so the script is a file the program
  reads and this module is the thing that writes it.

  Nothing here authenticates to anything. The password the browser types goes to the stdin of
  a shell script and is dropped; there is no SSH client, no remote machine and no credential
  store anywhere in the path.

  Test support, loaded only by the fixture runtime. It is never part of a release.
  """

  alias Ouroboros.Test.FleetFramesFake

  # The frozen inventory. One row per state a browser can see: this machine, a member that is
  # not visible, a peer nothing has inspected, and a platform with no release.
  #
  # Every row carries `suggested_machine`: the valid name a form pre-fills with. `name` is a
  # display name and is never what a form submits.
  @inventory %{
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
        "suggested_machine" => "fixture-studio",
        "os" => "macos",
        "address" => "100.100.0.1",
        "online" => true,
        "last_seen" => nil,
        "path" => "direct",
        "state" => "this_device",
        "action" => "view device",
        "name_conflicts_with_roster" => nil
      },
      # The machine "Set up this Mac" is offered for. The self row above is a member of a
      # fleet already, so without this one the page has nothing to set up — the two together
      # are what let one inventory serve both the fleet list and the standalone flow.
      %{
        "name" => "fixture-spare",
        "machine" => nil,
        "suggested_machine" => "fixture-spare",
        "os" => "macos",
        "address" => "100.100.0.3",
        "online" => true,
        "last_seen" => nil,
        "path" => "direct",
        "state" => "this_device_without_profile",
        "action" => "set up this device",
        "name_conflicts_with_roster" => nil
      },
      %{
        "name" => "fixture-buildbox",
        "machine" => "fixture-buildbox",
        "suggested_machine" => "fixture-buildbox",
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
        "suggested_machine" => "fixture-toaster",
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

  # Twelve identical uninspected peers, six per Playwright project. A deployment leaves a
  # journal behind, and a journal is what makes a row stop reading as an untouched peer —
  # correctly, and permanently for the life of this fixture runtime. Playwright runs this
  # spec once per project against one server, so a spec that reused one row would have its
  # second test looking at the first test's leftovers. A row each is the cheap, honest way
  # out, and the spec's own `peer/1` offsets the second project past the first's.
  @peers 12

  defp peers do
    for index <- 1..@peers do
      %{
        "name" => "fixture-peer-#{String.pad_leading("#{index}", 2, "0")}",
        "machine" => nil,
        "suggested_machine" => "fixture-peer-#{String.pad_leading("#{index}", 2, "0")}",
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

  @doc """
  The scenario every drawer in the spec walks through.

  Host trust, then a password, then the plan, then the six steps of an `add`, then done — the
  order §6 runs it in, with the frame names §8 fixes. The challenge ids are fixed strings so
  the spec can name them without reading them off the page.
  """
  @spec scenario() :: [String.t()]
  def scenario do
    [
      "state running",
      "log connecting to the target",
      "state waiting",
      "challenge trust-1 host_trust {\"address\":\"100.100.7.1\",\"port\":22,\"algorithm\":\"ssh-ed25519\",\"sha256_fingerprint\":\"SHA256:fixtureFingerprintNotARealHostKey\",\"user\":\"fixture\"}",
      "await trust-1",
      "challenge secret-1 password {\"target\":\"100.100.7.1\",\"user\":\"fixture\",\"port\":22,\"attempt\":1,\"max_attempts\":3}",
      "await secret-1",
      "step inspect ok reachable, and no Ouroboros installed",
      "plan Install ouro 0.1.10 (Linux arm64) to /usr/local/bin/ouro",
      "plan Join this fleet as the target",
      "plan Start at login as a user service",
      "plan Remember it on this machine",
      "challenge review-1 review {}",
      "await review-1",
      "state running",
      "step install ok /usr/local/bin/ouro",
      "step join ok -",
      "step service ok an Ouroboros-owned user service",
      "step start ok -",
      "step connect ok -",
      "done completed the target joined this fleet"
    ]
  end

  @doc "The same up to the plan, then a failure the drawer offers Retry for."
  @spec failing_scenario() :: [String.t()]
  def failing_scenario do
    [
      "state running",
      "state waiting",
      "challenge trust-1 host_trust {\"address\":\"100.100.7.1\",\"port\":22,\"algorithm\":\"ssh-ed25519\",\"sha256_fingerprint\":\"SHA256:fixtureFingerprintNotARealHostKey\",\"user\":\"fixture\"}",
      "await trust-1",
      "challenge secret-1 password {\"target\":\"100.100.7.1\",\"user\":\"fixture\",\"port\":22,\"attempt\":1,\"max_attempts\":3}",
      "await secret-1",
      "step inspect ok reachable",
      "plan Install ouro 0.1.10 (Linux arm64) to /usr/local/bin/ouro",
      "challenge review-1 review {}",
      "await review-1",
      "state running",
      "step install failed the release archive did not verify",
      "error install_failed the release archive did not verify",
      "done failed the target was not added"
    ]
  end

  @doc "A removal: host trust, a password, the removal's own review and its three steps."
  @spec leave_scenario() :: [String.t()]
  def leave_scenario do
    [
      "state running",
      "state waiting",
      "challenge trust-1 host_trust {\"address\":\"100.100.0.2\",\"port\":22,\"algorithm\":\"ssh-ed25519\",\"sha256_fingerprint\":\"SHA256:fixtureFingerprintNotARealHostKey\",\"user\":\"fixture\"}",
      "await trust-1",
      "challenge secret-1 password {\"target\":\"100.100.0.2\",\"user\":\"fixture\",\"port\":22,\"attempt\":1,\"max_attempts\":3}",
      "await secret-1",
      "plan Stop Ouroboros on fixture-buildbox",
      "plan Remove its fleet credentials and its startup service",
      "plan Forget it here",
      "challenge review-1 review {}",
      "await review-1",
      "state running",
      "step stop ok -",
      "step remove ok -",
      "step forget ok -",
      "done completed fixture-buildbox is out of this fleet"
    ]
  end

  @doc """
  One that waits, so **Cancel setup** has something to stop.

  The program is holding a host-key question and then sitting on its stdin; a cancel is a
  `{"op":"cancel"}` frame written to it, and what the operator sees afterwards is the
  `done cancelled` it answers with. Nothing about that is reachable from a script that
  finishes on its own.
  """
  @spec cancellable_scenario() :: [String.t()]
  def cancellable_scenario do
    [
      "state running",
      "state waiting",
      "challenge trust-1 host_trust {\"address\":\"100.100.7.1\",\"port\":22,\"algorithm\":\"ssh-ed25519\",\"sha256_fingerprint\":\"SHA256:fixtureFingerprintNotARealHostKey\",\"user\":\"fixture\"}",
      "residue a partial download at /tmp/ouro.partial",
      "await trust-1",
      "sleep 30"
    ]
  end

  @doc """
  One whose key is protected, which is the other secret a deployment can ask for.

  A `passphrase` challenge is not a `password` challenge: it is for a key *this operator*
  chose rather than for an account on another machine, it carries no attempt count, and the
  label over the masked field has to say which of the two is being asked for — an operator
  who types the wrong one has told a remote machine their local key's passphrase.
  """
  @spec passphrase_scenario() :: [String.t()]
  def passphrase_scenario do
    [
      "state running",
      "state waiting",
      "challenge key-1 passphrase {\"key_label\":\"~/.ssh/id_ed25519\",\"public_fingerprint\":\"SHA256:fixturePublicFingerprint\"}",
      "await key-1",
      "plan Install ouro 0.1.10 (Linux arm64) to /usr/local/bin/ouro",
      "challenge review-1 review {}",
      "await review-1",
      "done completed the key was unlocked"
    ]
  end

  @doc "A local setup: no host key and no password, straight to the review."
  @spec setup_scenario() :: [String.t()]
  def setup_scenario do
    [
      "state running",
      "plan Create this fleet on this machine",
      "plan Start at login as a user service",
      "state waiting",
      "challenge review-1 review {}",
      "await review-1",
      "state running",
      "step create ok -",
      "step stop_runtime skipped nothing was running",
      "step service ok an Ouroboros-owned user service",
      "step start ok -",
      "step ready ok -",
      "done completed this machine is its own fleet now"
    ]
  end

  @doc "Stands the fixture up. Called once, by the fixture runtime, after the app boots."
  @spec seed() :: :ok
  def seed do
    data_dir = Application.fetch_env!(:ouroboros, :data_dir)
    bin = Path.join(data_dir, "fleet-fixture-bin")

    # Every journal a previous run wrote, gone. The data directory outlives the server —
    # Playwright keeps `_build/playwright-j2-data` between runs — and a journal is exactly
    # the thing that makes a device's row stop offering Add to fleet. Left behind, the second
    # run of this spec looks at the first run's leftovers and finds no button.
    deploy = Path.join(data_dir, "deploy")

    case File.ls(deploy) do
      {:ok, names} -> for name <- names, do: File.rm(Path.join(deploy, name))
      {:error, _absent} -> :ok
    end

    FleetFramesFake.install!(bin, devices: JSON.encode!(inventory()) <> "\n")

    # Four deployments, one runtime, and no endpoint to switch between them: the program
    # picks its own script from its argv — `<kind>-<machine>`, then `<kind>`, then `default`.
    # So the spec chooses a path by choosing a *row*, which is what an operator does.
    FleetFramesFake.write_scenarios!(bin, %{
      "add" => scenario(),
      # One peer per Playwright project whose deployment fails, so the spec can reach Retry
      # without a second server and without making every other row's deployment fail too.
      # The spec's own `peer/1` offsets the mobile project by five, so these are its
      # `peer(5)` on either.
      "add-fixture-peer-05" => failing_scenario(),
      "add-fixture-peer-11" => failing_scenario(),
      # One that waits to be cancelled, and one whose key is protected, per project.
      "add-fixture-peer-04" => cancellable_scenario(),
      "add-fixture-peer-10" => cancellable_scenario(),
      "add-fixture-peer-03" => passphrase_scenario(),
      "add-fixture-peer-09" => passphrase_scenario(),
      "leave" => leave_scenario(),
      "setup" => setup_scenario(),
      "default" => scenario()
    })

    # This machine's own members, which is the closed set a removal may name: the gateway
    # refuses a `leave` of a machine this profile does not list, before anything is run.
    profile!(data_dir)

    # This is a Mix runtime, and `dev_runtime` blocks a local `setup` on one — correctly, on
    # a person's machine. The fixture is asserting the page rather than the blocker, so it
    # answers as a packaged runtime; the blocker has its own test in the broker's suite.
    Application.put_env(:ouroboros, :dev_runtime, false)

    :ok
  end

  defp profile!(data_dir) do
    dir = Path.join(data_dir, "fleet")
    File.mkdir_p!(dir)
    path = Path.join(dir, "profile.json")

    File.write!(
      path,
      JSON.encode!(%{
        "schema" => 2,
        "fleet_id" => "f1000000000000000000000000000001",
        "name" => "fixture",
        "machine" => "fixture-studio",
        "host" => "100.100.0.1",
        "node" => "ouro-fixture-studio@100.100.0.1",
        "role" => "core",
        "dist_port" => 13_700,
        "gateway_port" => 17_342,
        "members" => [
          %{
            "machine" => "fixture-studio",
            "host" => "100.100.0.1",
            "node" => "ouro-fixture-studio@100.100.0.1",
            "dist_port" => 13_700
          },
          %{
            "machine" => "fixture-buildbox",
            "host" => "100.100.0.2",
            "node" => "ouro-fixture-buildbox@100.100.0.2",
            "dist_port" => 13_700
          }
        ],
        "tags" => []
      })
    )

    File.chmod!(path, 0o600)
  end
end
