defmodule Ouroboros.Wasm.ArtifactTest do
  # Async: nothing here reads application environment or a named process.
  use ExUnit.Case, async: true

  alias Ouroboros.Upgrade.Artifact, as: BeamArtifact
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact

  @bytes "\0asm\x01\x00\x00\x00 pretend this is a component"
  @signer "wasm-artifact-test-key"

  describe "build/2" do
    test "computes the digest and the size from the bytes, never from the attributes" do
      # The lie a caller would tell if it could: a flattering sha and a smaller size.
      assert {:ok, artifact} =
               Artifact.build(@bytes,
                 name: "greeter",
                 author: "test-agent",
                 epoch: 7,
                 component_sha256: String.duplicate("0", 64),
                 size: 1
               )

      assert artifact.component_sha256 == sha256(@bytes)
      assert artifact.size == byte_size(@bytes)
      assert artifact.world == Wasm.world()
      assert artifact.imports == []
      assert artifact.signature == nil
      assert artifact.id != ""
      assert artifact.epoch > 0
    end

    test "takes the world, the imports, the name and the provenance from the attributes" do
      spec = %{probes: [%{input: %{"n" => 1}, expect: :any_reply}], budget_ms: 1_000}

      assert {:ok, artifact} =
               Artifact.build(@bytes, %{
                 id: "artifact-1",
                 epoch: 7,
                 name: "greeter",
                 world: "ouroboros:capability@9.9.9",
                 imports: ["log"],
                 author: "test-agent",
                 language: "rust",
                 source_sha256: String.duplicate("a", 64),
                 eval: spec,
                 start: %{id: "wasm/greeter", config: "{}"}
               })

      assert artifact.id == "artifact-1"
      assert artifact.epoch == 7
      assert artifact.name == "greeter"
      assert artifact.world == "ouroboros:capability@9.9.9"
      assert artifact.imports == ["log"]

      assert artifact.metadata == %{
               author: "test-agent",
               language: "rust",
               source_sha256: String.duplicate("a", 64),
               eval: spec,
               start: %{id: "wasm/greeter", config: "{}"}
             }
    end

    test "an explicit metadata map is merged under the named keys" do
      assert {:ok, artifact} =
               Artifact.build(@bytes,
                 name: "greeter",
                 epoch: 7,
                 metadata: %{author: "from-metadata", extra: "kept"},
                 author: "from-attrs"
               )

      assert artifact.metadata.author == "from-attrs"
      assert artifact.metadata.extra == "kept"
    end

    test "has no default epoch, because a VM-local one poisons the rollout register" do
      # `Ouroboros.Upgrade.Artifact.build/2` defaults this to `System.unique_integer/1`,
      # which is safe there because lane B checks monotonicity per node against what that
      # node committed. Lane W checks it against `Rollout.Registry`, and
      # `Ouroboros.Upgrade.Epoch.next/2` never reads that register — so one artifact built
      # with a VM-local counter raises the watermark past every epoch `Epoch.next/2` will
      # mint for a long time, and recovering means hand-minting *and* re-signing.
      assert {:error, {:missing_attribute, :epoch}} =
               Artifact.build(@bytes, name: "greeter", author: "test-agent")

      assert {:error, {:missing_attribute, :epoch}} =
               Artifact.build(@bytes, %{name: "greeter", author: "test-agent"})

      # An explicitly `nil` epoch is a malformed value rather than an absent one.
      assert {:error, {:invalid_epoch, _}} =
               Artifact.build(@bytes, name: "greeter", author: "test-agent", epoch: nil)
    end

    test "refuses a shape that could not be verified later" do
      valid = [name: "greeter", author: "test-agent", epoch: 7]

      assert {:error, :empty_component} = Artifact.build("", valid)
      assert {:error, {:invalid_component, :bytes}} = Artifact.build(:not_bytes, valid)
      assert {:error, {:invalid_artifact_id, _}} = Artifact.build(@bytes, valid ++ [id: ""])
      assert {:error, {:invalid_epoch, _}} = Artifact.build(@bytes, valid ++ [epoch: 0])
      assert {:error, {:invalid_epoch, _}} = Artifact.build(@bytes, valid ++ [epoch: "1"])

      assert {:error, {:invalid_component_name, _}} =
               Artifact.build(@bytes, author: "a", epoch: 7)

      assert {:error, {:invalid_component_name, _}} = Artifact.build(@bytes, valid ++ [name: ""])
      assert {:error, {:invalid_world, _}} = Artifact.build(@bytes, valid ++ [world: :capability])
      assert {:error, {:invalid_imports, _}} = Artifact.build(@bytes, valid ++ [imports: [:log]])
      assert {:error, {:invalid_imports, _}} = Artifact.build(@bytes, valid ++ [imports: "log"])

      assert {:error, {:invalid_metadata, :author}} =
               Artifact.build(@bytes, name: "greeter", epoch: 7)

      assert {:error, {:invalid_metadata, :author}} =
               Artifact.build(@bytes, name: "greeter", epoch: 7, author: "")
    end

    test "the name is narrow, because it is a durable id and a register key" do
      valid = [author: "test-agent", epoch: 7]

      # `"wasm/" <> name` is the rollout register's `module` field and the cluster-wide
      # mesh id a signed `start` block claims. Both are compared as strings by things that
      # trust them, so a name that can hold a path separator, whitespace, or a
      # bidirectional control is a name two readers can disagree about.
      for name <- [
            "greeter/../../etc/passwd",
            "greeter/v2",
            "greeter ",
            " greeter",
            "Greeter",
            "gre\u{202E}eter",
            "-greeter",
            ".greeter",
            String.duplicate("g", 65),
            "gréeter",
            "greeter\n"
          ] do
        assert {:error, {:invalid_component_name, _rendered}} =
                 Artifact.build(@bytes, valid ++ [name: name]),
               "build accepted the name #{inspect(name)}"

        refute Artifact.name?(name)
      end

      for name <- ["greeter", "g", "greeter-v2", "greeter_v2", "greeter.v2", "g0"] do
        assert {:ok, _artifact} = Artifact.build(@bytes, valid ++ [name: name])
        assert Artifact.name?(name)
      end

      refute Artifact.name?(:greeter)
      refute Artifact.name?(nil)
    end

    test "a repeated import can never cross-check, so it is refused where it is written" do
      # `Ouroboros.Wasm.Verifier.cross_check/2` compares the sorted list a helper reports
      # against the sorted list the manifest declares. `["log", "log"]` cannot equal any
      # helper's reading of any component, so a manifest carrying one was a manifest signed
      # into a permanent quarantine.
      valid = [name: "greeter", author: "test-agent", epoch: 7]

      assert {:error, {:duplicate_imports, _rendered}} =
               Artifact.build(@bytes, valid ++ [imports: ["log", "log"]])

      assert {:ok, _artifact} = Artifact.build(@bytes, valid ++ [imports: ["log"]])
    end
  end

  describe "the signing payload" do
    test "covers the manifest and nothing else" do
      artifact = build!()
      payload = Artifact.signing_payload(artifact, @signer)

      assert {:ouroboros_wasm_v1, @signer, manifest} = :erlang.binary_to_term(payload)
      assert manifest == Artifact.manifest(artifact)
      refute Map.has_key?(manifest, :signature)

      # A signature envelope is not covered by the signature, which is what makes it
      # attachable after the fact.
      {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer, value: signature()})
      assert Artifact.signing_payload(signed, @signer) == payload
    end

    test "moving any manifest field moves the payload" do
      artifact = build!()
      payload = Artifact.signing_payload(artifact, @signer)

      for changed <- [
            %{artifact | epoch: artifact.epoch + 1},
            %{artifact | name: "other"},
            %{artifact | component_sha256: String.duplicate("b", 64)},
            %{artifact | world: "ouroboros:capability@0.0.1"},
            %{artifact | imports: ["log", "clock"]},
            %{artifact | size: artifact.size + 1},
            %{artifact | metadata: Map.put(artifact.metadata, :author, "someone-else")}
          ] do
        refute Artifact.signing_payload(changed, @signer) == payload
      end

      # And so does the identity it is signed under.
      refute Artifact.signing_payload(artifact, "another-signer") == payload
    end

    test "carries a different tag from the BEAM lane's, so a signature cannot cross" do
      wasm = Artifact.signing_payload(build!(), @signer)

      {module, binary} = beam_binary()
      {:ok, beam} = BeamArtifact.build([{module, binary, disposition: :introduce}], epoch: 1)
      beam = BeamArtifact.signing_payload(beam, @signer)

      assert {:ouroboros_wasm_v1, _signer, _manifest} = :erlang.binary_to_term(wasm)
      assert {:ouroboros_upgrade_v1, _signer, _manifest} = :erlang.binary_to_term(beam)
      refute wasm == beam
    end

    test "is deterministic across two builds of the same manifest" do
      artifact = build!()
      twin = struct(Artifact, Map.from_struct(artifact))

      assert Artifact.signing_payload(twin, @signer) ==
               Artifact.signing_payload(artifact, @signer)
    end
  end

  describe "signatures" do
    test "an envelope is admitted only in the one shape a verifier could use" do
      artifact = build!()

      refute Artifact.signed?(artifact)
      refute Artifact.signed?(%{artifact | signature: %{signer: @signer, value: "short"}})
      refute Artifact.signed?(:not_an_artifact)

      assert {:ok, signed} =
               Artifact.with_signature(artifact, %{signer: @signer, value: signature()})

      assert Artifact.signed?(signed)
      assert signed.signature.signer == @signer

      assert {:error, :invalid_signer} =
               Artifact.with_signature(artifact, %{signer: "", value: signature()})

      assert {:error, {:invalid_signature, @signer}} =
               Artifact.with_signature(artifact, %{signer: @signer, value: <<0>>})

      assert {:error, {:invalid_signature_envelope, _}} =
               Artifact.with_signature(artifact, %{signer: @signer})

      assert {:error, {:invalid_artifact, _}} =
               Artifact.with_signature(%{}, %{signer: @signer, value: signature()})
    end

    test "an envelope carrying more than the two keys is narrowed to them" do
      artifact = build!()

      assert {:ok, signed} =
               Artifact.with_signature(artifact, %{
                 signer: @signer,
                 value: signature(),
                 note: "ignored"
               })

      assert Enum.sort(Map.keys(signed.signature)) == [:signer, :value]
    end
  end

  test "sha256?/1 accepts only lower-case 64-hex" do
    assert Artifact.sha256?(sha256(@bytes))
    refute Artifact.sha256?(String.upcase(sha256(@bytes)))
    refute Artifact.sha256?(String.duplicate("a", 63))
    refute Artifact.sha256?(String.duplicate("g", 64))
    refute Artifact.sha256?(nil)
  end

  # W8, D22. The block that authorizes a loading node to `Component::deserialize` machine code
  # it did not produce, so its shape is decided where the manifest is built rather than
  # rediscovered by every reader — and it is inside `manifest/1`, which is what the signature
  # covers. Delete `:precompiled` from `manifest/1` and the last assertion here goes red: a
  # deploy could then swap the artifact digest a node maps without disturbing the signature.
  describe "precompiled (W8)" do
    test "all four keys or none, and each held to its own shape" do
      block = %{
        wasmtime: "48.0.1",
        target: "aarch64-apple-darwin",
        sha256: String.duplicate("a", 64),
        size: 258_093
      }

      assert Artifact.precompiled?(nil)
      assert Artifact.precompiled?(block)
      assert build!(precompiled: block).precompiled == block

      for {label, bad} <- [
            {"a missing key", Map.delete(block, :target)},
            {"a key this build has no home for", Map.put(block, :extra, 1)},
            {"a digest that is not one", %{block | sha256: "not-a-digest"}},
            {"an upper-case digest", %{block | sha256: String.duplicate("A", 64)}},
            {"a size that is not positive", %{block | size: 0}},
            {"an empty version", %{block | wasmtime: ""}},
            {"a version that can forge a log line", %{block | wasmtime: "48.0.1\nfake"}},
            {"a triple with leading whitespace", %{block | target: " aarch64"}},
            {"string keys", %{"wasmtime" => "48.0.1"}},
            {"not a map at all", "48.0.1"}
          ] do
        refute Artifact.precompiled?(bad), label

        assert {:error, {:invalid_precompiled, _}} =
                 Artifact.build(@bytes,
                   name: "greeter",
                   author: "test-agent",
                   epoch: 7,
                   precompiled: bad
                 ),
               label
      end
    end

    test "it is inside the signed half, so a swapped artifact digest breaks the signature" do
      block = %{
        wasmtime: "48.0.1",
        target: "aarch64-apple-darwin",
        sha256: String.duplicate("a", 64),
        size: 258_093
      }

      artifact = build!(precompiled: block)
      assert artifact |> Artifact.manifest() |> Map.fetch!(:precompiled) == block

      swapped = %{artifact | precompiled: %{block | sha256: String.duplicate("b", 64)}}

      refute Artifact.signing_payload(artifact, "s") == Artifact.signing_payload(swapped, "s")
    end
  end

  defp build!(attrs \\ []) do
    {:ok, artifact} =
      Artifact.build(
        @bytes,
        Keyword.merge([name: "greeter", author: "test-agent", epoch: 7], attrs)
      )

    artifact
  end

  defp signature, do: :binary.copy(<<7>>, 64)

  defp sha256(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  # Any real BEAM binary will do: this test is about the payload tag, not about the module.
  defp beam_binary do
    {module, binary, _filename} = :code.get_object_code(Ouroboros.Wasm.Artifact)
    {module, binary}
  end
end
