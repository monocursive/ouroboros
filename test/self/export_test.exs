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
          Fixture.tool(),
          Fixture.shape(),
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
          Fixture.tool(),
          Fixture.shape(),
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
      assert report.tools == ["bash"]
      assert report.shapes == %{"bash" => ["mix test"]}

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

      # Version 2 and the per-shape record: the shapes live under the tool, and each one
      # carries the whole evidence map the promotion was granted on — all six counts, not
      # the two the first thresholds were written in terms of — plus the moment it was
      # granted. Drop any of `distinct_fingerprints`, `distinct_sessions` or
      # `would_resolve` from the export and the receiving node's ledger entry understates
      # what the widening was earned on.
      assert record["version"] == 2

      promoted_at = record["tools"]["bash"]["mix test"]["promoted_at"]
      assert {:ok, _promoted, _offset} = DateTime.from_iso8601(promoted_at)

      assert record["tools"] == %{
               "bash" => %{
                 "mix test" => %{
                   "promoted_at" => promoted_at,
                   "decisions" => 112,
                   "contradictions" => 0,
                   "distinct_fingerprints" => 24,
                   "distinct_sessions" => 3,
                   "would_resolve" => 11,
                   "report_sha256" => String.duplicate("a", 64),
                   "replayed_at" => "2026-09-08T00:00:00Z"
                 }
               }
             }
    end

    @tag @needs_live
    test "every allowable shape ships, each with its own evidence", context do
      live = Fixture.live_policy!(context.tmp)

      for {shape, decisions} <- [{"mix test", 112}, {"git status", 61}] do
        {:ok, _record} =
          PolicyPromotion.promote(
            live.name,
            live.sha,
            "bash",
            shape,
            Fixture.evidence(decisions, 0),
            "operator:ana",
            context.promotion
          )
      end

      assert {:ok, report} =
               Export.run(
                 out: Path.join(context.tmp, "out"),
                 promotion: context.promotion,
                 registry: live.registry,
                 store_root: live.store_root,
                 trust_policy: live.trust_policy
               )

      assert report.tools == ["bash"]
      assert report.shapes == %{"bash" => ["git status", "mix test"]}

      record = report.promotions |> File.read!() |> JSON.decode!()

      # Each shape's own numbers under its own key, and not one tool's evidence copied
      # across both: the record holds a promotion per `(tool, shape)` and so does the file.
      assert record["tools"]["bash"]["mix test"]["decisions"] == 112
      assert record["tools"]["bash"]["git status"]["decisions"] == 61
    end

    @tag @needs_live
    test "a shape a human contradicted is not shipped, nor a tool left with none", context do
      live = Fixture.live_policy!(context.tmp)
      out = Path.join(context.tmp, "out")

      for {tool, shape} <- [
            {"bash", "mix test"},
            {"bash", "mix format"},
            {"grep", "ouroboros"}
          ] do
        {:ok, _record} =
          PolicyPromotion.promote(
            live.name,
            live.sha,
            tool,
            shape,
            Fixture.evidence(),
            "operator:ana",
            context.promotion
          )
      end

      # One shape of a tool that keeps another, and the only shape of a tool that does not.
      for {tool, shape} <- [{"bash", "mix format"}, {"grep", "ouroboros"}] do
        :ok =
          PolicyPromotion.demote(
            live.name,
            tool,
            shape,
            %{reason: :human_contradiction},
            context.promotion
          )
      end

      assert {:ok, report} =
               Export.run(
                 out: out,
                 promotion: context.promotion,
                 registry: live.registry,
                 store_root: live.store_root,
                 trust_policy: live.trust_policy
               )

      # S-D43. Shipping a demoted shape's promotion would re-widen somewhere else exactly
      # what a human narrowed here — and a tool whose every shape was contradicted leaves
      # with them, rather than shipping as a tool with an empty object under it. Export
      # `status.tools` instead of `status.allowable` and this goes red both ways.
      assert report.tools == ["bash"]
      assert report.shapes == %{"bash" => ["mix test"]}

      record = report.promotions |> File.read!() |> JSON.decode!()
      assert Map.keys(record["tools"]) == ["bash"]
      assert Map.keys(record["tools"]["bash"]) == ["mix test"]
    end

    @tag @needs_live
    test "a second export over the same directory changes only the timestamp", context do
      live = Fixture.live_policy!(context.tmp)
      out = Path.join(context.tmp, "out")

      {:ok, _record} =
        PolicyPromotion.promote(
          live.name,
          live.sha,
          Fixture.tool(),
          Fixture.shape(),
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
          Fixture.tool(),
          Fixture.shape(),
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

      # One level deeper than it used to be: the tool at four spaces, the shape under it at
      # six, and the evidence at eight. A person reading this diff sees which prefix earned
      # what, indented under the tool it belongs to.
      assert text =~ ~s(    "bash": {)
      assert text =~ ~s(      "mix test": {)
      assert text =~ ~s(        "decisions": 57)
      assert text =~ ~s(        "distinct_fingerprints": 24)

      # The keys come out in the order the module writes them, not in the order a map
      # iterates: a diff a person reads should not reorder itself.
      assert index(text, "\"version\"") < index(text, "\"policy_name\"")
      assert index(text, "\"policy_name\"") < index(text, "\"component_sha256\"")
      assert index(text, "\"signer_id\"") < index(text, "\"tools\"")
      assert index(text, "\"promoted_at\"") < index(text, "\"decisions\"")
    end
  end

  # S4 fix wave, MEDIUM-3. `Ouroboros.Self.Boot` globs `priv/self/*.ouro-wasm`, so a bundle
  # this export did not write is a policy the next installation deploys because of where its
  # file was. The reviewer's probe proved a rename left both.
  describe "the directory it leaves behind" do
    @tag @needs_live
    test "a re-export after a rename leaves exactly one bundle, and names what it removed",
         context do
      live = Fixture.live_policy!(context.tmp)
      out = Path.join(context.tmp, "priv-self")

      {:ok, _record} =
        PolicyPromotion.promote(
          live.name,
          live.sha,
          Fixture.tool(),
          Fixture.shape(),
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
      assert first.removed == []

      # What a rename between two exports used to leave here, plus the file the repository
      # owns and an export must not touch.
      stale = Path.join(out, "old-policy.ouro-wasm")
      File.write!(stale, "STALE BUNDLE BYTES")
      File.write!(Path.join(out, "README.md"), "# committed beside them\n")

      assert {:ok, second} = Export.run(opts)

      assert second.removed == ["old-policy.ouro-wasm"]
      refute File.exists?(stale)

      assert Path.wildcard(Path.join(out, "*.ouro-wasm")) == [
               Path.join(out, "no-network-shell.ouro-wasm")
             ]

      # The three files are there and the README is untouched: this replaces files, it does
      # not replace the directory.
      assert Enum.sort(File.ls!(out)) ==
               ["README.md", "no-network-shell.ouro-wasm", "promotions.json", "signers.txt"]

      assert File.read!(Path.join(out, "README.md")) == "# committed beside them\n"

      # And no staging directory is left behind.
      assert Path.wildcard(out <> ".tmp-*") == []
    end

    @tag @needs_live
    test "the bundle it did write is not swept", context do
      live = Fixture.live_policy!(context.tmp)
      out = Path.join(context.tmp, "priv-self")

      {:ok, _record} =
        PolicyPromotion.promote(
          live.name,
          live.sha,
          Fixture.tool(),
          Fixture.shape(),
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
      assert {:ok, second} = Export.run(opts)

      assert second.removed == []
      assert File.exists?(second.bundle)
      assert File.read!(first.bundle) == File.read!(second.bundle)
    end
  end

  # S4 fix wave, LOW-4. The reviewer's probe pointed `--out` three levels above `priv/self`
  # and the export wrote a signed bundle and a trust suggestion there.
  describe "where --out may point" do
    setup context do
      root = Path.join(context.tmp, "repo")
      File.mkdir_p!(Path.join(root, "priv/self"))
      %{root: root}
    end

    test "inside the root is fine, however it is spelled", %{root: root} do
      assert {:ok, _out} = Export.confine(Path.join(root, "priv/self"), root)
      assert {:ok, _out} = Export.confine(Path.join(root, "priv/self/../self"), root)
      assert {:ok, _out} = Export.confine(root, root)
      # A directory that does not exist yet is judged by the ancestor that does.
      assert {:ok, _out} = Export.confine(Path.join(root, "priv/self/nested/deeper"), root)
    end

    test "the traversal the reviewer used is refused", %{root: root} do
      escape = Path.join(root, "priv/self/../../../escaped-self")

      assert {:error, {:out_escapes_root, resolved, inside}} = Export.confine(escape, root)
      refute String.starts_with?(resolved, inside)
      refute File.exists?(Path.expand(escape))
    end

    test "and a sibling whose name merely starts with the root's", %{root: root} do
      assert {:error, {:out_escapes_root, _resolved, _inside}} =
               Export.confine(root <> "-elsewhere", root)
    end

    # `priv/self` is a symlink in more than one packaging of this repository, and the check
    # is on where the path lands rather than on how it was written.
    test "a symlinked out is judged by where it lands", %{root: root, tmp: tmp} do
      outside = Path.join(tmp, "outside-the-repo")
      File.mkdir_p!(outside)
      link = Path.join(root, "priv/linked")
      :ok = File.ln_s(outside, link)

      assert {:error, {:out_escapes_root, _resolved, _inside}} = Export.confine(link, root)

      inside = Path.join(root, "priv/self")
      inside_link = Path.join(root, "linked-in")
      :ok = File.ln_s(inside, inside_link)
      assert {:ok, _out} = Export.confine(inside_link, root)
    end

    test "and a caller inside this application that names no root is not confined" do
      assert Export.confine("/anywhere/at/all", nil) == {:ok, "/anywhere/at/all"}
    end

    @tag @needs_live
    test "run/1 refuses the traversal before it writes anything", context do
      live = Fixture.live_policy!(context.tmp)
      root = Path.join(context.tmp, "repo")
      escape = Path.join(root, "priv/self/../../../escaped-self")

      {:ok, _record} =
        PolicyPromotion.promote(
          live.name,
          live.sha,
          Fixture.tool(),
          Fixture.shape(),
          Fixture.evidence(),
          "operator:ana",
          context.promotion
        )

      assert {:error, {:out_escapes_root, _resolved, _inside}} =
               Export.run(
                 out: escape,
                 confine_to: root,
                 promotion: context.promotion,
                 registry: live.registry,
                 store_root: live.store_root,
                 trust_policy: live.trust_policy
               )

      refute File.exists?(Path.expand(escape))
    end
  end

  # S4 fix wave, LOW-5: the two refusals the reviewer's mutations survived.
  describe "the signer line is a suggestion this node can actually make" do
    @tag @needs_live
    test "a signer this node's trust policy does not carry is a refusal", context do
      live = Fixture.live_policy!(context.tmp)
      out = Path.join(context.tmp, "out")

      {:ok, _record} =
        PolicyPromotion.promote(
          live.name,
          live.sha,
          Fixture.tool(),
          Fixture.shape(),
          Fixture.evidence(),
          "operator:ana",
          context.promotion
        )

      # The bundle verified and deployed under `live.trust_policy`; this is the *export's*
      # question, which is "can I write down the key this was verified against". A policy
      # listing somebody else cannot, and the export must not invent a line.
      other = [
        allow_unsigned: false,
        trusted_signers: %{"someone-else" => :crypto.strong_rand_bytes(32)}
      ]

      assert {:error, {:signer_not_trusted_here, signer}} =
               Export.run(
                 out: out,
                 promotion: context.promotion,
                 registry: live.registry,
                 store_root: live.store_root,
                 trust_policy: other
               )

      assert signer == live.signer
      refute File.exists?(out)

      # A key of the right id but the wrong length is not a key either.
      assert {:error, {:signer_not_trusted_here, _signer}} =
               Export.run(
                 out: out,
                 promotion: context.promotion,
                 registry: live.registry,
                 store_root: live.store_root,
                 trust_policy: [
                   allow_unsigned: false,
                   trusted_signers: %{live.signer => "too short"}
                 ]
               )

      refute File.exists?(out)
    end

    @tag @needs_live
    test "a manifest with no signature at all is a refusal, not an empty signer line",
         context do
      live = Fixture.live_unsigned!(context.tmp)
      out = Path.join(context.tmp, "out")

      {:ok, _record} =
        PolicyPromotion.promote(
          live.name,
          live.sha,
          Fixture.tool(),
          Fixture.shape(),
          Fixture.evidence(),
          "operator:ana",
          context.promotion
        )

      assert Export.run(
               out: out,
               promotion: context.promotion,
               registry: live.registry,
               store_root: live.store_root,
               trust_policy: live.trust_policy
             ) == {:error, :unsigned_manifest}

      refute File.exists?(out)
    end
  end

  # S4 fix wave, LOW-4. The task's two refusals, both of which land *before* it starts the
  # application — which is the point of having them: an export that has already booted a
  # second VM against a live daemon's journals has already done the harm.
  describe "the mix task refuses before it starts anything" do
    setup context do
      saved = System.get_env("OUROBOROS_DATA_DIR")
      data_dir = Path.join(context.tmp, "data")
      File.mkdir_p!(data_dir)
      System.put_env("OUROBOROS_DATA_DIR", data_dir)

      on_exit(fn ->
        case saved do
          nil -> System.delete_env("OUROBOROS_DATA_DIR")
          value -> System.put_env("OUROBOROS_DATA_DIR", value)
        end
      end)

      %{data_dir: data_dir}
    end

    test "a live daemon holding the data directory stops it, and says how to fix it", %{
      data_dir: data_dir
    } do
      # This VM's own OS pid: unambiguously alive, which is what the marker's pid means.
      marker = Path.join(data_dir, "gateway.json")
      File.write!(marker, JSON.encode!(%{"pid" => String.to_integer(System.pid()), "port" => 1}))

      error =
        assert_raise Mix.Error, fn -> Mix.Tasks.Ouroboros.Self.Export.run([]) end

      assert error.message =~ "already holding this data directory"
      assert error.message =~ "ouro stop"
      assert error.message =~ marker
    end

    test "the lifetime marker counts too, not only the publication", %{data_dir: data_dir} do
      marker = Ouroboros.RuntimeOwner.marker_path(data_dir)
      File.write!(marker, JSON.encode!(%{"pid" => String.to_integer(System.pid())}))

      error = assert_raise Mix.Error, fn -> Mix.Tasks.Ouroboros.Self.Export.run([]) end
      assert error.message =~ "already holding this data directory"
      assert error.message =~ "runtime.owner"
    end

    # A killed daemon leaves both files behind. The pid in them is what decides, so a stale
    # marker is not a directory nobody can ever export from again.
    test "a stale marker does not, and the --out fence still does", %{data_dir: data_dir} do
      # Pid 1 is init/launchd and is not this runtime; a pid that is not there at all is the
      # case a kill leaves. `2147483647` is above every pid_max this runs on.
      File.write!(
        Path.join(data_dir, "gateway.json"),
        JSON.encode!(%{"pid" => 2_147_483_647, "port" => 1})
      )

      error =
        assert_raise Mix.Error, fn ->
          Mix.Tasks.Ouroboros.Self.Export.run(["--out", "../../../escaped-self"])
        end

      # It got past the daemon check — and stopped at the next one, before `app.start`.
      refute error.message =~ "already holding this data directory"
      assert error.message =~ "which is outside"
      refute File.exists?(Path.expand("../../../escaped-self", File.cwd!()))
    end

    test "and with no marker at all the --out fence is what speaks" do
      error =
        assert_raise Mix.Error, fn ->
          Mix.Tasks.Ouroboros.Self.Export.run(["--out", "/tmp/anywhere-at-all"])
        end

      assert error.message =~ "which is outside"
      refute File.exists?("/tmp/anywhere-at-all")
    end
  end

  defp index(text, needle) do
    [{start, _length}] = :binary.matches(text, needle) |> Enum.take(1)
    start
  end
end
