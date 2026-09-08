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
end
