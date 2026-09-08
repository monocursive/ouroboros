Code.require_file("fixture.exs", __DIR__)

defmodule Ouroboros.Self.ExportTest do
  @moduledoc """
  What `mix ouroboros.self.export` writes, and what it refuses to write (S4, S-D42/S-D43).

  Not async: the deploy the fixture performs makes this node's `:upgrade_trust_policy` the
  fixture's for the duration, because `Ouroboros.Wasm.Rollout` hands each target no policy
  and every target reads its own.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Control.PolicyPromotion
  alias Ouroboros.Self.{Export, Fixture}
  alias Ouroboros.Wasm.Bundle

  @needs_live Fixture.tag()

  setup_all do
    Fixture.ensure!()
    :ok
  end

  setup do
    %{tmp: Fixture.tmp!("ouro-self-export"), promotion: Fixture.promotion!()}
  end

  describe "refusals, which write nothing" do
    test "an empty promotion record", context do
      out = Path.join(context.tmp, "out")

      assert Export.run(out: out, promotion: context.promotion) == {:error, :no_promoted_policy}
      refute File.exists?(out)
    end

    @tag @needs_live
    test "a policy the record names and the register does not have live", context do
      %{sha: sha} = Fixture.live_policy!(context.tmp)
      out = Path.join(context.tmp, "out")

      {:ok, _record} =
        PolicyPromotion.promote(
          "no-network-shell",
          sha,
          "read",
          Fixture.evidence(),
          "operator:ana",
          context.promotion
        )

      # A register of its own, holding nothing. The record remembers; the register is what
      # is running, and the export ships what is running.
      assert {:error, {:policy_not_live, "no-network-shell", ^sha}} =
               Export.run(
                 out: out,
                 promotion: context.promotion,
                 registry: Fixture.registry!()
               )

      refute File.exists?(out)
    end
  end

  describe "what it writes" do
    @tag @needs_live
    test "three files: a verifiable bundle, the record, and the signer line", context do
      live = Fixture.live_policy!(context.tmp)
      out = Path.join(context.tmp, "out")

      {:ok, _record} =
        PolicyPromotion.promote(
          live.name,
          live.sha,
          "read",
          Fixture.evidence(112, 0),
          "operator:ana",
          context.promotion
        )

      assert {:ok, report} =
               Export.run(
                 out: out,
                 promotion: context.promotion,
                 registry: live.registry,
                 store_root: live.store_root,
                 trust_policy: live.trust_policy
               )

      assert report.policy_name == "no-network-shell"
      assert report.component_sha256 == live.sha
      assert report.signer_id == live.signer
      assert report.tools == ["read"]

      # The bundle is a bundle: it verifies against the policy that signed it, and it
      # carries the exact component bytes the node is running.
      bundle = File.read!(report.bundle)
      assert Path.basename(report.bundle) == "no-network-shell.ouro-wasm"
      assert byte_size(bundle) == report.bundle_bytes

      assert {:ok, decoded} = Bundle.verify(bundle, live.trust_policy)
      assert decoded.artifact.component_sha256 == live.sha
      assert decoded.artifact.name == "no-network-shell"
      assert decoded.artifact.kind == :policy
      assert decoded.bytes == File.read!(Fixture.component())

      # And it does not verify against a node that trusts nobody, which is the whole point
      # of shipping `signers.txt` beside it.
      assert {:error, _reason} =
               Bundle.verify(bundle, allow_unsigned: false, trusted_signers: %{})

      # The signer line is the one `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` takes.
      signers = File.read!(report.signers)
      assert [id, encoded] = signers |> String.trim() |> String.split(":", parts: 2)
      assert id == live.signer
      assert {:ok, public} = Base.decode64(encoded)
      assert public == live.trust_policy[:trusted_signers][live.signer]

      # And a node configured from that line accepts the bundle beside it.
      assert {:ok, %{"self-export-key" => ^public}} =
               Ouroboros.Self.Posture.trusted_signers(String.trim(signers))

      record = report.promotions |> File.read!() |> JSON.decode!()
      assert record["policy_name"] == "no-network-shell"
      assert record["component_sha256"] == live.sha
      assert record["signer_id"] == live.signer
      assert record["bundle"] == "no-network-shell.ouro-wasm"
      assert record["exported_by"] == Atom.to_string(node())
      assert {:ok, _at, _offset} = DateTime.from_iso8601(record["exported_at"])

      assert record["tools"] == %{
               "read" => %{
                 "decisions" => 112,
                 "contradictions" => 0,
                 "report_sha256" => String.duplicate("a", 64),
                 "replayed_at" => "2026-09-08T00:00:00Z"
               }
             }
    end

    @tag @needs_live
    test "a tool a human contradicted is not shipped", context do
      live = Fixture.live_policy!(context.tmp)
      out = Path.join(context.tmp, "out")

      for tool <- ["read", "grep"] do
        {:ok, _record} =
          PolicyPromotion.promote(
            live.name,
            live.sha,
            tool,
            Fixture.evidence(),
            "operator:ana",
            context.promotion
          )
      end

      :ok =
        PolicyPromotion.demote(
          live.name,
          "grep",
          %{reason: :human_contradiction},
          context.promotion
        )

      assert {:ok, report} =
               Export.run(
                 out: out,
                 promotion: context.promotion,
                 registry: live.registry,
                 store_root: live.store_root,
                 trust_policy: live.trust_policy
               )

      # S-D43. Shipping a demoted tool's promotion would re-widen somewhere else exactly
      # what a human narrowed here. Export `status.tools` instead of `allowable_tools` and
      # this goes red.
      assert report.tools == ["read"]

      record = report.promotions |> File.read!() |> JSON.decode!()
      assert Map.keys(record["tools"]) == ["read"]
    end

    @tag @needs_live
    test "a second export over the same directory changes only the timestamp", context do
      live = Fixture.live_policy!(context.tmp)
      out = Path.join(context.tmp, "out")

      {:ok, _record} =
        PolicyPromotion.promote(
          live.name,
          live.sha,
          "read",
          Fixture.evidence(),
          "operator:ana",
          context.promotion
        )

      opts = [
        out: out,
        promotion: context.promotion,
        registry: live.registry,
        store_root: live.store_root,
        trust_policy: live.trust_policy
      ]

      assert {:ok, first} = Export.run(opts)
      bundle = File.read!(first.bundle)
      record = first.promotions |> File.read!() |> JSON.decode!()

      assert {:ok, second} = Export.run(opts)
      assert File.read!(second.bundle) == bundle

      again = second.promotions |> File.read!() |> JSON.decode!()
      assert Map.delete(again, "exported_at") == Map.delete(record, "exported_at")
    end

    @tag @needs_live
    test "the record is pretty, ordered, and readable in a pull request", context do
      live = Fixture.live_policy!(context.tmp)

      {:ok, _record} =
        PolicyPromotion.promote(
          live.name,
          live.sha,
          "read",
          Fixture.evidence(),
          "operator:ana",
          context.promotion
        )

      assert {:ok, report} =
               Export.run(
                 out: Path.join(context.tmp, "out"),
                 promotion: context.promotion,
                 registry: live.registry,
                 store_root: live.store_root,
                 trust_policy: live.trust_policy
               )

      text = File.read!(report.promotions)

      assert String.starts_with?(text, "{\n")
      assert String.ends_with?(text, "}\n")
      assert text =~ ~s(  "policy_name": "no-network-shell")
      assert text =~ ~s(      "decisions": 57)

      # The keys come out in the order the module writes them, not in the order a map
      # iterates: a diff a person reads should not reorder itself.
      assert index(text, "\"version\"") < index(text, "\"policy_name\"")
      assert index(text, "\"policy_name\"") < index(text, "\"component_sha256\"")
      assert index(text, "\"signer_id\"") < index(text, "\"tools\"")
    end
  end

  defp index(text, needle) do
    [{start, _length}] = :binary.matches(text, needle) |> Enum.take(1)
    start
  end
end
