Code.require_file("fixture.exs", __DIR__)

defmodule Ouroboros.Self.BootTest do
  @moduledoc """
  A fresh install boots what a previous one forged, and only what its operator trusts (S4).

  Every case here builds a **real** export first — the fixture signs `no-network-shell` with
  a real signing service and deploys it through the real rollout, and
  `Ouroboros.Self.Export` writes the three files out of that node's own store — and then
  hands `priv/self` to a receiving world with its own register, its own store, its own
  helper pool and its own promotion record. That second world is the fresh install.

  Not async: the rollout's targets read this node's `:upgrade_trust_policy`, and the
  supervision-spec case reads and writes `:self_ship`.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Control.PolicyPromotion
  alias Ouroboros.Self.{Boot, Export, Fixture}
  alias Ouroboros.Upgrade.Rollout.Registry

  @needs_live Fixture.tag()

  setup_all do
    Fixture.ensure!()
    :ok
  end

  setup do
    %{tmp: Fixture.tmp!("ouro-self-boot")}
  end

  describe "a fresh install with a trusted export" do
    @tag @needs_live
    test "deploys the bundle live and applies the promotion, once", context do
      %{export: export, live: live} = exported!(context)
      install = install!(context)

      report = Boot.ship(ship_opts(export, install))

      assert [%{name: "no-network-shell", kind: :policy}] = report.deployed
      assert report.skipped == []
      assert report.promoted == ["read"]
      assert report.promotions == :applied

      # The register of the *receiving* node says it is running, at the sha the exporter ran.
      assert [entry] = Registry.live(install.registry)
      assert entry.module == "wasm/no-network-shell"
      assert entry.component_sha256 == live.sha

      # And its promotion record allows exactly the tool the record shipped, bound to those
      # bytes, under an actor naming the file that carried it.
      status = PolicyPromotion.status(install.promotion)
      assert status.policy_name == "no-network-shell"
      assert status.component_sha256 == live.sha
      assert status.allowable_tools == ["read"]
      assert status.tools["read"].actor == actor(export)
      assert status.tools["read"].evidence.decisions == 57
      assert status.tools["read"].evidence.report_sha256 == String.duplicate("a", 64)
    end

    @tag @needs_live
    test "a second boot deploys nothing and promotes nothing", context do
      %{export: export} = exported!(context)
      install = install!(context)
      opts = ship_opts(export, install)

      first = Boot.ship(opts)
      assert length(first.deployed) == 1
      before = Registry.live(install.registry)
      recorded = PolicyPromotion.status(install.promotion)

      second = Boot.ship(opts)

      assert second.deployed == []
      assert [%{bundle: "no-network-shell.ouro-wasm", reason: :already_live}] = second.skipped
      assert second.promoted == []
      assert {:skipped, {:record_bound_to, "no-network-shell"}} = second.promotions

      assert Registry.live(install.registry) == before
      assert PolicyPromotion.status(install.promotion) == recorded
    end
  end

  describe "a fresh install that trusts nobody" do
    @tag @needs_live
    test "skips the bundle by name and boots with the rules it shipped with", context do
      %{export: export, live: live} = exported!(context)
      install = install!(context)

      # The receiving operator has not pasted the line out of `signers.txt`. This is what
      # every node looks like before they do.
      Fixture.trust!(allow_unsigned: false, trusted_signers: %{})

      report = Boot.ship(ship_opts(export, install))

      assert report.deployed == []
      assert [%{bundle: "no-network-shell.ouro-wasm", reason: reason}] = report.skipped
      assert reason == {:untrusted_signer, live.signer}

      assert Registry.live(install.registry) == []
      assert PolicyPromotion.status(install.promotion).policy_name == nil

      # The promotion is refused for the reason that matters — the bytes are not live here —
      # rather than passing because the record happened to be empty.
      assert {:skipped, {:policy_not_live, "no-network-shell", _sha}} = report.promotions
    end

    @tag @needs_live
    test "allow_unsigned does not rescue a signer nobody listed", context do
      %{export: export, live: live} = exported!(context)
      install = install!(context)

      # `config/config.exs` sets `allow_unsigned: true` outside production, so a development
      # checkout that turned the posture on without pasting `signers.txt` is a real shape.
      # It buys nothing here: `allow_unsigned` excuses a manifest carrying **no** signature,
      # and an exported bundle always carries one — `Bundle.encode/3` refuses to write a file
      # that could only ever be refused. So the signature is checked, and it is checked
      # against a list this node has not been given.
      Fixture.trust!(allow_unsigned: true, trusted_signers: %{})

      report = Boot.ship(ship_opts(export, install))

      assert report.deployed == []
      assert [%{reason: {:untrusted_signer, signer}}] = report.skipped
      assert signer == live.signer
      assert Registry.live(install.registry) == []
    end
  end

  describe "the promotion record is applied over an empty record and live bytes only" do
    @tag @needs_live
    test "a record naming a sha that is not live is not applied", context do
      %{export: export} = exported!(context)
      install = install!(context)

      # The bundle still deploys — the file is the same file — but the record now names bytes
      # nobody is running, so the widening it carries is not applied.
      rewrite(export, "component_sha256", String.duplicate("b", 64))

      report = Boot.ship(ship_opts(export, install))

      assert length(report.deployed) == 1
      assert report.promoted == []
      assert {:skipped, {:policy_not_live, "no-network-shell", _sha}} = report.promotions
      assert PolicyPromotion.status(install.promotion).policy_name == nil
    end

    @tag @needs_live
    test "a record naming another policy's name is not applied", context do
      %{export: export} = exported!(context)
      install = install!(context)

      rewrite(export, "policy_name", "some-other-policy")

      report = Boot.ship(ship_opts(export, install))

      assert length(report.deployed) == 1
      assert report.promoted == []
      assert {:skipped, {:policy_not_live, "some-other-policy", _sha}} = report.promotions
    end

    @tag @needs_live
    test "a node that has already promoted something of its own keeps its own record",
         context do
      %{export: export, live: live} = exported!(context)
      install = install!(context)

      {:ok, _record} =
        PolicyPromotion.promote(
          "no-network-shell",
          live.sha,
          "grep",
          Fixture.evidence(9, 0),
          "operator:ana",
          install.promotion
        )

      report = Boot.ship(ship_opts(export, install))

      assert report.promoted == []
      assert {:skipped, {:record_bound_to, "no-network-shell"}} = report.promotions

      status = PolicyPromotion.status(install.promotion)
      assert status.allowable_tools == ["grep"]
      assert status.tools["grep"].actor == "operator:ana"
    end
  end

  describe "a checkout with nothing shipped" do
    test "a priv/self that does not exist is an empty report", context do
      root = Path.join(context.tmp, "absent")

      report = Boot.ship(root: root)

      assert report == %{
               root: root,
               deployed: [],
               skipped: [],
               promoted: [],
               promotions: :absent
             }
    end

    test "a priv/self holding only its README ships nothing and applies nothing", context do
      root = Path.join(context.tmp, "priv-self")
      File.mkdir_p!(root)
      File.write!(Path.join(root, "README.md"), "# nothing here\n")

      report = Boot.ship(root: root, registry: Fixture.registry!())

      assert report.deployed == []
      assert report.skipped == []
      assert report.promotions == :absent
    end

    test "run/0 answers :ok whatever it finds", _context do
      assert Boot.run() == :ok
    end
  end

  # S4 fix wave, MEDIUM-2. `priv/self` is a directory in a repository and `ship/1` globs it,
  # so what lands there is whatever the export wrote plus whatever anybody committed beside
  # it. Only the promoted policy belongs.
  describe "only a policy ships" do
    @tag Fixture.capability_tag()
    test "a really-signed capability bundle beside the policy is skipped by kind", context do
      %{export: export, live: live} = exported!(context)
      install = install!(context)

      # Signed by the same key that signed the policy, so its trust is not what stops it.
      capability = Fixture.capability_bundle!(live)
      File.write!(Path.join(export.out, "counter.ouro-wasm"), capability.bundle)
      assert capability.artifact.kind == :capability

      report = Boot.ship(ship_opts(export, install))

      assert [%{name: "no-network-shell", kind: :policy}] = report.deployed

      assert [%{bundle: "counter.ouro-wasm", reason: {:not_a_policy, :capability}}] =
               report.skipped

      # And it is not running: nothing about where a file sits deploys a component.
      assert Registry.live(install.registry) |> Enum.map(& &1.module) == [
               "wasm/no-network-shell"
             ]
    end

    @tag Fixture.capability_tag()
    test "and a capability alone deploys nothing at all", context do
      live = Fixture.live_policy!(context.tmp)
      root = Path.join(context.tmp, "priv-self-capability")
      File.mkdir_p!(root)
      File.write!(Path.join(root, "counter.ouro-wasm"), Fixture.capability_bundle!(live).bundle)

      install = install!(context)

      report =
        Boot.ship(
          root: root,
          registry: install.registry,
          store_root: install.store_root,
          pool: install.pool,
          promotion: install.promotion
        )

      assert report.deployed == []
      assert [%{reason: {:not_a_policy, :capability}}] = report.skipped
      assert Registry.live(install.registry) == []
    end
  end

  # S4 fix wave, LOW-5: the three bounds the reviewer's mutations survived.
  describe "what ship/1 refuses to read" do
    test "a bundle larger than any legal one is not read into memory", context do
      root = Path.join(context.tmp, "priv-self-huge")
      File.mkdir_p!(root)
      path = Path.join(root, "huge.ouro-wasm")

      # Sparse: the ceiling is 80MB and `read_bundle/1` stats before it reads, which is the
      # whole point of the check. Writing 80MB to prove it would be proving the disk.
      {:ok, io} = File.open(path, [:write, :binary])
      {:ok, _position} = :file.position(io, Ouroboros.Wasm.Bundle.max_bytes() + 1)
      :ok = IO.binwrite(io, "x")
      :ok = File.close(io)
      assert File.stat!(path).size > Ouroboros.Wasm.Bundle.max_bytes()

      report = Boot.ship(root: root, registry: Fixture.registry!())

      assert [%{bundle: "huge.ouro-wasm", reason: {:bundle_too_large, size}}] = report.skipped
      assert size > Ouroboros.Wasm.Bundle.max_bytes()
      assert report.deployed == []
    end

    test "a bundle that is a directory, or empty, is skipped rather than read", context do
      root = Path.join(context.tmp, "priv-self-odd")
      File.mkdir_p!(Path.join(root, "a-directory.ouro-wasm"))
      File.write!(Path.join(root, "empty.ouro-wasm"), "")

      report = Boot.ship(root: root, registry: Fixture.registry!())

      assert [
               %{bundle: "a-directory.ouro-wasm", reason: {:not_a_regular_file, :directory}},
               # A zero-byte file fails the same guard's size half: nothing to decode, and
               # not a byte of it is read to find that out.
               %{bundle: "empty.ouro-wasm", reason: {:not_a_regular_file, :regular}}
             ] = report.skipped

      assert report.deployed == []
    end

    test "a promotions.json outside the size bound is not parsed", context do
      for {label, contents} <- [
            {"too large", String.duplicate("x", 256 * 1024 + 1)},
            {"empty", ""}
          ] do
        root = Path.join(context.tmp, "priv-self-record-#{label |> String.replace(" ", "-")}")
        File.mkdir_p!(root)
        File.write!(Path.join(root, "promotions.json"), contents)

        report = Boot.ship(root: root, registry: Fixture.registry!())

        assert {:skipped, {:promotions_unusable, {:promotions_size, _size}}} = report.promotions
        assert report.promoted == []
      end
    end

    test "a promotions.json that is a directory is skipped by its type", context do
      root = Path.join(context.tmp, "priv-self-record-dir")
      File.mkdir_p!(Path.join(root, "promotions.json"))

      report = Boot.ship(root: root, registry: Fixture.registry!())

      assert report.promotions == {:skipped, {:not_a_regular_file, :directory}}
      assert report.promoted == []
    end
  end

  describe "the switch and the supervision spec" do
    test "enabled? needs both self_ship and a durable data directory" do
      saved_ship = Application.get_env(:ouroboros, :self_ship)
      saved_dir = Application.get_env(:ouroboros, :data_dir)

      on_exit(fn ->
        restore(:self_ship, saved_ship)
        restore(:data_dir, saved_dir)
      end)

      Application.put_env(:ouroboros, :self_ship, true)
      Application.put_env(:ouroboros, :data_dir, nil)
      refute Boot.enabled?()

      Application.put_env(:ouroboros, :data_dir, "/tmp/does-not-need-to-exist")
      assert Boot.enabled?()

      # Read as exactly `true`, the way every switch that widens what a node runs is read.
      for truthy <- ["true", 1, :yes] do
        Application.put_env(:ouroboros, :self_ship, truthy)
        refute Boot.enabled?()
      end

      Application.delete_env(:ouroboros, :self_ship)
      refute Boot.enabled?()
    end

    test "the tree starts a transient task, and only under the switch" do
      saved_ship = Application.get_env(:ouroboros, :self_ship)
      saved_dir = Application.get_env(:ouroboros, :data_dir)

      on_exit(fn ->
        restore(:self_ship, saved_ship)
        restore(:data_dir, saved_dir)
      end)

      Application.delete_env(:ouroboros, :self_ship)
      assert Ouroboros.Application.self_restart_children() == []

      Application.put_env(:ouroboros, :self_ship, true)
      Application.put_env(:ouroboros, :data_dir, "/tmp/does-not-need-to-exist")

      assert [spec] = Ouroboros.Application.self_restart_children()
      assert spec.id == Ouroboros.Self.Boot
      # Transient and not temporary, for `Ouroboros.Wasm.Boot`'s reason: a supervisor drops
      # temporary children from the list it restarts after a sibling's crash, so a temporary
      # task here would run once per VM and never again.
      assert spec.restart == :transient
      assert {Task, :start_link, [fun]} = spec.start
      assert is_function(fun, 0)
    end

    # S4 fix wave, LOW-6. Two `Task` children of one supervisor start concurrently —
    # `Task.start_link` returns as soon as the process exists — and every decision
    # `Self.Boot` makes is a question about the register `Wasm.Boot` is busy restarting into.
    test "the tree starts ONE task where both halves are on, and wasm goes first" do
      saved_ship = Application.get_env(:ouroboros, :self_ship)
      saved_dir = Application.get_env(:ouroboros, :data_dir)

      on_exit(fn ->
        restore(:self_ship, saved_ship)
        restore(:data_dir, saved_dir)
      end)

      Application.put_env(:ouroboros, :self_ship, true)
      Application.put_env(:ouroboros, :data_dir, "/tmp/does-not-need-to-exist")

      assert Ouroboros.Wasm.Boot.enabled?()
      assert Boot.enabled?()

      assert [chained] = Ouroboros.Application.boot_restart_children()
      assert chained.restart == :transient
      assert chained.start == {Task, :start_link, [&Ouroboros.Self.Boot.run_after_wasm/0]}

      # And with only the lane-W half on, the tree is exactly what it was.
      Application.delete_env(:ouroboros, :self_ship)
      refute Boot.enabled?()

      assert Ouroboros.Application.boot_restart_children() ==
               Ouroboros.Application.wasm_restart_children()
    end

    test "run_after_wasm runs the lane-W boot before this one" do
      test_pid = self()

      assert Boot.run_after_wasm(
               fn -> send(test_pid, {:ran, :wasm}) end,
               fn -> send(test_pid, {:ran, :self}) end
             ) == :ok

      # The order, not merely that both ran: one sender to one receiver preserves it, and a
      # `receive` takes matching messages in mailbox order.
      assert drain() == [:wasm, :self]
    end
  end

  describe "the one-machine signing posture" do
    setup do
      saved =
        Map.new(
          [:self_posture, :signing_node, :signer_key_path, :signer_id],
          &{&1, Application.get_env(:ouroboros, &1)}
        )

      on_exit(fn -> Enum.each(saved, fn {key, value} -> restore(key, value) end) end)
      :ok
    end

    test "no posture, no service on a core node" do
      Application.delete_env(:ouroboros, :self_posture)
      Application.put_env(:ouroboros, :signer_key_path, "/tmp/whatever.key")

      assert Ouroboros.Application.self_signing_children() == []
    end

    test "the posture with a key beside the application starts one", context do
      key = Path.join(context.tmp, "signer.key")
      File.write!(key, :crypto.strong_rand_bytes(32))
      File.chmod!(key, 0o600)

      Application.put_env(:ouroboros, :self_posture, true)
      Application.delete_env(:ouroboros, :signing_node)
      Application.put_env(:ouroboros, :signer_key_path, key)

      assert [{Ouroboros.Upgrade.Signing.Service, [key_path: ^key]}] =
               Ouroboros.Application.self_signing_children()
    end

    test "the posture with a signing node starts none: the peer holds the key" do
      Application.put_env(:ouroboros, :self_posture, true)
      Application.put_env(:ouroboros, :signer_key_path, "/tmp/whatever.key")
      Application.put_env(:ouroboros, :signing_node, :signer@fleet)

      assert Ouroboros.Application.self_signing_children() == []
    end

    test "the posture with no key at all starts none rather than crashing the boot" do
      Application.put_env(:ouroboros, :self_posture, true)
      Application.delete_env(:ouroboros, :signing_node)
      Application.delete_env(:ouroboros, :signer_key_path)

      assert Ouroboros.Application.self_signing_children() == []
    end

    # S4 fix wave, HIGH-1. Holding a signing seed on a node whose sandbox cannot hide it
    # from a session's own shell is holding it in public: the review read the seed out
    # through `bash`, derived the keypair with `:crypto`, and signed arbitrary bytes.
    # `native_sandbox: :none` is the seam — it is what `detect/0` reads before its cache, and
    # a node with no backend is the honest worst case of one that cannot hide a file.
    test "a node whose sandbox cannot hide the key starts no service, and says why", context do
      key = unfenceable_key(context)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert Ouroboros.Application.self_signing_children() == []
        end)

      assert log =~ "cannot hide a named file from a read"
      assert log =~ "can read the signing seed and sign in this key's name"
      assert log =~ "OUROBOROS_SIGNING_NODE"
      assert log =~ Ouroboros.Self.Posture.unfenced_key_env()
      assert log =~ key
    end

    test "unless the operator says they accept that, in one variable", context do
      key = unfenceable_key(context)
      System.put_env(Ouroboros.Self.Posture.unfenced_key_env(), "1")
      on_exit(fn -> System.delete_env(Ouroboros.Self.Posture.unfenced_key_env()) end)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert [{Ouroboros.Upgrade.Signing.Service, [key_path: ^key]}] =
                   Ouroboros.Application.self_signing_children()
        end)

      # It starts, and the log says exactly what was accepted rather than nothing at all.
      assert log =~ "can read the signing seed and sign in this key's name"
    end

    test "a fleet posture is unaffected: the key is on another host", context do
      _key = unfenceable_key(context)
      Application.put_env(:ouroboros, :signing_node, :signer@fleet)

      assert Ouroboros.Application.self_signing_children() == []
    end

    @tag @needs_live
    test "and the spec it builds is one that signs what this node forges", context do
      key = Path.join(context.tmp, "signer.key")
      File.write!(key, :crypto.strong_rand_bytes(32))
      File.chmod!(key, 0o600)

      Application.put_env(:ouroboros, :self_posture, true)
      Application.delete_env(:ouroboros, :signing_node)
      Application.put_env(:ouroboros, :signer_key_path, key)
      Application.put_env(:ouroboros, :signer_id, "one-machine")

      assert [{module, opts}] = Ouroboros.Application.self_signing_children()

      # Started unnamed and with its own journal here, because the node running this suite
      # already has whatever it has; what is being proved is that the options the tree
      # carries load a key and answer as the identity `:signer_id` names.
      service =
        start_supervised!(
          {module,
           opts ++
             [
               name: nil,
               storage:
                 {Jido.Storage.ETS,
                  table: String.to_atom("self_boot_journal_#{System.unique_integer([:positive])}")}
             ]},
          id: {module, System.unique_integer([:positive])}
        )

      assert {:ok, %{signer_id: "one-machine", public_key: public}} =
               Ouroboros.Upgrade.Signing.Service.public_info(service)

      assert byte_size(public) == 32
    end
  end

  ## helpers

  # A real export, written by the real task, out of a real live deployment.
  defp exported!(context) do
    live = Fixture.live_policy!(context.tmp)
    promotion = Fixture.promotion!()

    {:ok, _record} =
      PolicyPromotion.promote(
        live.name,
        live.sha,
        "read",
        Fixture.evidence(),
        "operator:ana",
        promotion
      )

    {:ok, report} =
      Export.run(
        out: Path.join(context.tmp, "priv-self"),
        promotion: promotion,
        registry: live.registry,
        store_root: live.store_root,
        trust_policy: live.trust_policy
      )

    %{export: report, live: live}
  end

  # The receiving machine: nothing of the exporter's except the files in `priv/self`.
  defp install!(context) do
    %{
      registry: Fixture.registry!(),
      store_root: Path.join(context.tmp, "install-store-#{System.unique_integer([:positive])}"),
      pool: Fixture.pool!(context.tmp),
      promotion: Fixture.promotion!()
    }
  end

  defp ship_opts(export, install) do
    [
      root: export.out,
      registry: install.registry,
      store_root: install.store_root,
      pool: install.pool,
      promotion: install.promotion
    ]
  end

  defp actor(export) do
    "shipped:" <>
      Base.encode16(:crypto.hash(:sha256, File.read!(export.promotions)), case: :lower)
  end

  defp rewrite(export, key, value) do
    record = export.promotions |> File.read!() |> JSON.decode!() |> Map.put(key, value)
    File.write!(export.promotions, JSON.encode!(record))
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  # The posture, a real key file, and a node whose sandbox cannot hide it.
  defp unfenceable_key(context) do
    saved = Application.get_env(:ouroboros, :native_sandbox)

    on_exit(fn ->
      restore(:native_sandbox, saved)
      Ouroboros.Provider.Native.Sandbox.forget()
    end)

    key = Path.join(context.tmp, "signer-#{System.unique_integer([:positive])}.key")
    File.write!(key, :crypto.strong_rand_bytes(32))
    File.chmod!(key, 0o600)

    Application.put_env(:ouroboros, :self_posture, true)
    Application.delete_env(:ouroboros, :signing_node)
    Application.put_env(:ouroboros, :signer_key_path, key)
    Application.put_env(:ouroboros, :native_sandbox, :none)
    Ouroboros.Provider.Native.Sandbox.forget()

    refute Ouroboros.Provider.Native.Sandbox.hides_files?(
             Ouroboros.Provider.Native.Sandbox.detect()
           )

    key
  end

  defp drain do
    receive do
      {:ran, what} -> [what | drain()]
    after
      0 -> []
    end
  end
end
