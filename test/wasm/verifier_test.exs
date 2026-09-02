defmodule Ouroboros.Wasm.VerifierTest do
  # Async: no application environment, no named process, no disk.
  use ExUnit.Case, async: true

  alias Ouroboros.Upgrade.Artifact, as: BeamArtifact
  alias Ouroboros.Upgrade.Verifier, as: BeamVerifier
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Verifier

  @bytes "\0asm\x01\x00\x00\x00 pretend this is a component"
  @signer "wasm-verifier-test-key"

  setup do
    {public, secret} = :crypto.generate_key(:eddsa, :ed25519)
    %{public: public, secret: secret, policy: [trusted_signers: %{@signer => public}]}
  end

  describe "verify/3" do
    test "accepts a signed manifest whose bytes hash to what it claims", context do
      artifact = signed!(context)

      assert :ok = Verifier.verify(artifact, @bytes, context.policy)
    end

    test "refuses bytes that are not the ones that were signed", context do
      artifact = signed!(context)
      other = @bytes <> "!"

      assert {:error, {:component_size_mismatch, expected, actual}} =
               Verifier.verify(artifact, other, context.policy)

      assert expected == byte_size(@bytes)
      assert actual == byte_size(other)

      # Same length, different content: the digest is the check that catches it.
      swapped = String.replace_prefix(@bytes, "\0asm", "\0ASM")
      assert byte_size(swapped) == byte_size(@bytes)

      assert {:error, {:component_sha256_mismatch, _expected, _actual}} =
               Verifier.verify(artifact, swapped, context.policy)
    end

    test "refuses an unsigned manifest unless the node was configured to allow it", context do
      artifact = build!()

      assert {:error, :signature_required} = Verifier.verify(artifact, @bytes, context.policy)
      assert :ok = Verifier.verify(artifact, @bytes, allow_unsigned: true)
    end

    test "refuses a signature by anyone this node does not trust", context do
      artifact = signed!(context)

      assert {:error, {:untrusted_signer, @signer}} = Verifier.verify(artifact, @bytes, [])

      assert {:error, {:untrusted_signer, @signer}} =
               Verifier.verify(artifact, @bytes, trusted_signers: %{"someone-else" => <<0::256>>})

      assert {:error, {:invalid_signer_key, @signer}} =
               Verifier.verify(artifact, @bytes, trusted_signers: %{@signer => "short"})
    end

    test "a manifest moved after signing no longer verifies", context do
      artifact = signed!(context)

      for moved <- [
            %{artifact | epoch: artifact.epoch + 1},
            %{artifact | name: "other"},
            %{artifact | imports: []},
            %{artifact | metadata: Map.put(artifact.metadata, :author, "someone-else")}
          ] do
        assert {:error, {:invalid_signature, @signer}} =
                 Verifier.verify(moved, @bytes, context.policy)
      end

      # Moving the sha moves the payload *and* breaks the byte recomputation. The
      # signature is the one that answers first, because it is the cheaper refusal.
      moved = %{artifact | component_sha256: String.duplicate("b", 64)}

      assert {:error, {:invalid_signature, @signer}} =
               Verifier.verify(moved, @bytes, context.policy)
    end

    test "a signature from the BEAM lane cannot be replayed onto a component", context do
      # The same key and the same signer id, over a BEAM artifact's payload. If the two
      # lanes shared a payload space this would be the attack; the tags are what stop it.
      {module, binary} = beam_binary()
      {:ok, beam} = BeamArtifact.build([{module, binary, disposition: :introduce}], epoch: 1)
      beam = BeamArtifact.sign(beam, @signer, context.secret)

      # It is a genuinely good signature in its own lane — the same helper this module's
      # signature check calls says so.
      assert :ok =
               BeamVerifier.verify_payload_signature(
                 BeamArtifact.signing_payload(beam, @signer),
                 @signer,
                 beam.signature.value,
                 %{@signer => context.public}
               )

      {:ok, replayed} = Artifact.with_signature(build!(), beam.signature)

      assert {:error, {:invalid_signature, @signer}} =
               Verifier.verify(replayed, @bytes, context.policy)
    end

    test "refuses a world this build does not implement", context do
      artifact =
        [world: "ouroboros:capability@9.9.9"] |> build!() |> sign(context.secret)

      # Before the signature, and with no configuration that could widen it.
      assert {:error, {:world_not_supported, "ouroboros:capability@9.9.9"}} =
               Verifier.verify(artifact, @bytes, context.policy)

      assert {:error, {:world_not_supported, _world}} =
               Verifier.verify(artifact, @bytes, allow_unsigned: true)
    end

    test "refuses a shape no signature could rescue", context do
      artifact = signed!(context)

      assert {:error, :invalid_artifact_id} =
               Verifier.verify(%{artifact | id: ""}, @bytes, context.policy)

      assert {:error, :invalid_artifact_epoch} =
               Verifier.verify(%{artifact | epoch: 0}, @bytes, context.policy)

      assert {:error, :invalid_component_name} =
               Verifier.verify(%{artifact | name: ""}, @bytes, context.policy)

      assert {:error, {:invalid_component_sha256, _}} =
               Verifier.verify(%{artifact | component_sha256: "nope"}, @bytes, context.policy)

      assert {:error, {:invalid_component_size, _}} =
               Verifier.verify(%{artifact | size: 0}, @bytes, context.policy)

      assert {:error, {:invalid_artifact, _}} = Verifier.verify(:nope, @bytes, context.policy)
      assert {:error, {:invalid_component, _}} = Verifier.verify(artifact, :nope, context.policy)
    end
  end

  describe "verify_manifest/2" do
    test "checks the signature and the world without reading a byte", context do
      artifact = signed!(context)

      assert :ok = Verifier.verify_manifest(artifact, context.policy)
      assert {:error, :signature_required} = Verifier.verify_manifest(build!(), context.policy)

      moved = %{artifact | size: artifact.size + 1}

      assert {:error, {:invalid_signature, @signer}} =
               Verifier.verify_manifest(moved, context.policy)
    end
  end

  describe "cross_check/2" do
    test "accepts the helper's reading when it is the manifest's", context do
      artifact = signed!(context)

      assert :ok = Verifier.cross_check(artifact, report(artifact))

      # Import order is the helper's, not the manifest's.
      assert :ok = Verifier.cross_check(artifact, %{report(artifact) | "imports" => ["log"]})

      # `load` answers with the same fields plus `cached`, and it cross-checks the same.
      assert :ok = Verifier.cross_check(artifact, Map.put(report(artifact), "cached", true))
    end

    test "names every disagreement, including one that links less", context do
      artifact = signed!(context)

      assert {:error, {:component_mismatch, :sha256, _manifest, _observed}} =
               Verifier.cross_check(artifact, %{
                 report(artifact)
                 | "sha256" => String.duplicate("b", 64)
               })

      assert {:error, {:component_mismatch, :world, _manifest, "other:world@0.1.0"}} =
               Verifier.cross_check(artifact, %{report(artifact) | "world" => "other:world@0.1.0"})

      assert {:error, {:component_mismatch, :size, _manifest, 1}} =
               Verifier.cross_check(artifact, %{report(artifact) | "size" => 1})

      # It never "just links less": a component importing fewer things than its manifest
      # declared is a component the manifest is not about.
      assert {:error, {:component_mismatch, :imports, ["log"], []}} =
               Verifier.cross_check(artifact, %{report(artifact) | "imports" => []})

      assert {:error, {:component_mismatch, :imports, ["log"], ["clock", "log"]}} =
               Verifier.cross_check(artifact, %{
                 report(artifact)
                 | "imports" => ["log", "clock"]
               })
    end

    test "a report missing or malforming a field is a refusal, not a pass", context do
      artifact = signed!(context)

      assert {:error, {:invalid_inspect_report, "sha256", :missing}} =
               Verifier.cross_check(artifact, Map.delete(report(artifact), "sha256"))

      assert {:error, {:invalid_inspect_report, "size", _}} =
               Verifier.cross_check(artifact, %{report(artifact) | "size" => "48"})

      assert {:error, {:invalid_inspect_report, "imports", _}} =
               Verifier.cross_check(artifact, %{report(artifact) | "imports" => "log"})

      assert {:error, {:invalid_inspect_report, _}} = Verifier.cross_check(artifact, :nope)
      assert {:error, {:invalid_artifact, _}} = Verifier.cross_check(:nope, report(artifact))
    end
  end

  defp report(artifact) do
    %{
      "sha256" => artifact.component_sha256,
      "world" => artifact.world,
      "imports" => artifact.imports,
      "exports" => ["describe", "handle-message", "init"],
      "size" => artifact.size
    }
  end

  defp build!(attrs \\ []) do
    {:ok, artifact} =
      Artifact.build(
        @bytes,
        Keyword.merge(
          [
            name: "greeter",
            author: "test-agent",
            imports: ["log"],
            world: Wasm.world(),
            epoch: epoch()
          ],
          attrs
        )
      )

    artifact
  end

  # Every manifest carries an allocated epoch; `build/2` has no default for it, because a
  # VM-local counter in this field poisons the rollout register's watermark.
  defp epoch, do: System.unique_integer([:positive, :monotonic])

  defp signed!(%{secret: secret}), do: build!() |> sign(secret)

  defp sign(artifact, secret) do
    payload = Artifact.signing_payload(artifact, @signer)
    value = :crypto.sign(:eddsa, :none, payload, [secret, :ed25519])
    {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer, value: value})
    signed
  end

  defp beam_binary do
    {module, binary, _filename} = :code.get_object_code(Ouroboros.Wasm.Verifier)
    {module, binary}
  end
end
