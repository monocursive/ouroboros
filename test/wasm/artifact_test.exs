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
