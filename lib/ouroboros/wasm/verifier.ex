defmodule Ouroboros.Wasm.Verifier do
  @moduledoc """
  What a loading node checks about a component before it stages one byte of it.

  `Ouroboros.Upgrade.Verifier` is the BEAM lane's half of this, and the split is the same
  (docs/WASM.md §7.5): the signer decides what may exist, and this decides what this node
  will admit. The two are not redundant. A signature is a statement made once, somewhere
  else, by a process that saw the bytes it was shown; this runs on the node that is about
  to run them, against the bytes actually on its disk.

  Three checks, in three functions, because they answer at three different moments:

    * `verify_manifest/2` — the signature and the world, from the manifest alone. Cheap,
      needs no bytes, and is what a boot-time restart asks before it starts anything.
    * `verify/3` — that plus the digest and the size recomputed from the bytes in hand.
      This is what a deploy asks before the `:deploying` checkpoint's effects begin.
    * `cross_check/2` — the helper's own reading of the staged file against the signed
      manifest: sha, world, imports, size. This is the one that closes the loop, because
      the signer's import list is provenance (D5) and the helper's is what the linker will
      actually be asked for.

  ## Why a cross-check mismatch is quarantine and not rollback

  A component whose declared imports are not the imports the helper found is not a
  component that will "just link less". It is a component whose manifest describes
  something other than the file this node is holding, and the honest thing to say about a
  node in that state is that nobody knows what it has. `Ouroboros.Wasm.Rollout` therefore
  treats every refusal from `cross_check/2` as ambiguity, which quarantines — the same
  rule the BEAM lane applies to a node that never answered.

  ## The trust policy is the BEAM lane's, unchanged

  `trust_policy` is the `config :ouroboros, :upgrade_trust_policy` keyword list: the same
  `:trusted_signers` map (`signer_id => raw 32-byte Ed25519 public key`) that
  `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` parses into at boot, and the same `:allow_unsigned`
  escape hatch for a development node. One key set, one format, one operator decision.
  The signature check itself is `Ouroboros.Upgrade.Verifier.verify_payload_signature/4`;
  what differs between the lanes is only which payload is derived, and the two payloads
  carry different tags so a signature cannot cross between them.
  """

  alias Ouroboros.Upgrade.Verifier, as: BeamVerifier
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact

  @doc """
  Verifies the manifest, then the bytes it describes.

  Signature and world first — refusing before hashing a component is cheaper and says
  more — then the digest and the size recomputed from `bytes`. Nothing here reads the
  store: the caller holds the bytes it is about to publish, and this says whether they
  are the ones that were signed.
  """
  @spec verify(Artifact.t(), binary(), keyword()) :: :ok | {:error, term()}
  def verify(artifact, bytes, trust_policy \\ [])

  def verify(%Artifact{} = artifact, bytes, trust_policy)
      when is_binary(bytes) and is_list(trust_policy) do
    with :ok <- verify_manifest(artifact, trust_policy) do
      verify_bytes(artifact, bytes)
    end
  end

  def verify(%Artifact{}, bytes, _trust_policy),
    do: {:error, {:invalid_component, describe(bytes)}}

  def verify(other, _bytes, _trust_policy), do: {:error, {:invalid_artifact, describe(other)}}

  @doc """
  Verifies shape, world, and signature without touching the component.

  This is the whole check a boot-time restart can afford and the whole check it needs: the
  bytes are verified again anyway, by the helper, which recomputes the digest at `load`
  and refuses `sha_mismatch` before compiling anything. A node that starts a wrapper agent
  from a manifest this accepts cannot reach bytes that are not the signed ones.
  """
  @spec verify_manifest(Artifact.t(), keyword()) :: :ok | {:error, term()}
  def verify_manifest(artifact, trust_policy \\ [])

  def verify_manifest(%Artifact{} = artifact, trust_policy) when is_list(trust_policy) do
    with :ok <- verify_policy(trust_policy),
         :ok <- verify_shape(artifact),
         :ok <- verify_world(artifact) do
      verify_signature(artifact, trust_policy)
    end
  end

  def verify_manifest(%Artifact{}, trust_policy),
    do: {:error, {:invalid_trust_policy, describe(trust_policy)}}

  def verify_manifest(other, _trust_policy), do: {:error, {:invalid_artifact, describe(other)}}

  @doc """
  Holds the helper's reading of the staged component to the signed manifest.

  `report` is what `Ouroboros.Wasm.Pool.inspect/2` or `Ouroboros.Wasm.Pool.load/3` answers
  with: string keys `"sha256"`, `"world"`, `"imports"`, `"size"`. Every one of them must
  equal what the manifest claims — imports as a set, because order is the helper's and not
  the manifest's, but neither more nor fewer. A component that imports less than it
  declared is still a component whose manifest is not about it.
  """
  @spec cross_check(Artifact.t(), map()) :: :ok | {:error, term()}
  def cross_check(%Artifact{} = artifact, report) when is_map(report) do
    with {:ok, sha} <- field(report, "sha256", &is_binary/1),
         {:ok, world} <- field(report, "world", &is_binary/1),
         {:ok, size} <- field(report, "size", &is_integer/1),
         {:ok, imports} <- field(report, "imports", &list_of_binaries?/1) do
      cond do
        String.downcase(sha) != artifact.component_sha256 ->
          {:error, {:component_mismatch, :sha256, artifact.component_sha256, sha}}

        world != artifact.world ->
          {:error, {:component_mismatch, :world, artifact.world, world}}

        size != artifact.size ->
          {:error, {:component_mismatch, :size, artifact.size, size}}

        Enum.sort(imports) != Enum.sort(artifact.imports) ->
          {:error,
           {:component_mismatch, :imports, Enum.sort(artifact.imports), Enum.sort(imports)}}

        true ->
          :ok
      end
    end
  end

  def cross_check(%Artifact{}, report), do: {:error, {:invalid_inspect_report, describe(report)}}
  def cross_check(other, _report), do: {:error, {:invalid_artifact, describe(other)}}

  defp verify_policy(policy) do
    if Keyword.keyword?(policy),
      do: :ok,
      else: {:error, {:invalid_trust_policy, describe(policy)}}
  end

  defp verify_shape(%Artifact{} = artifact) do
    cond do
      not is_binary(artifact.id) or artifact.id == "" ->
        {:error, :invalid_artifact_id}

      not is_integer(artifact.epoch) or artifact.epoch <= 0 ->
        {:error, :invalid_artifact_epoch}

      not is_binary(artifact.name) or artifact.name == "" ->
        {:error, :invalid_component_name}

      not Artifact.sha256?(artifact.component_sha256) ->
        {:error, {:invalid_component_sha256, describe(artifact.component_sha256)}}

      # W15. Held to the closed set here, before `verify_world/1` reads it: the kind arrives
      # from a manifest in a file, and it is what decides which world that manifest must
      # declare and which world the helper is told to check these bytes against.
      not Artifact.kind?(artifact.kind) ->
        {:error, {:invalid_component_kind, describe(artifact.kind)}}

      not is_integer(artifact.size) or artifact.size <= 0 ->
        {:error, {:invalid_component_size, describe(artifact.size)}}

      not is_list(artifact.imports) or not list_of_binaries?(artifact.imports) ->
        {:error, {:invalid_component_imports, describe(artifact.imports)}}

      not is_map(artifact.metadata) or is_struct(artifact.metadata) ->
        {:error, :invalid_artifact_metadata}

      true ->
        :ok
    end
  end

  # Not configurable here either. The signer refuses a world it does not implement and so
  # does the node that would run it: one build, one linker contract, checked at both ends.
  #
  # W15. The world a *kind* requires, not merely a world this build implements — the same
  # comparison the signer makes, for the same reason. Both worlds are supported, so a check
  # against a set would admit a `:policy` manifest carrying the capability world, and the
  # loading node would then hand the helper `kind: :policy` for bytes whose manifest said
  # otherwise.
  defp verify_world(%Artifact{world: world, kind: kind}) do
    if world == Wasm.world_for(kind), do: :ok, else: {:error, {:world_not_supported, world}}
  end

  defp verify_signature(%Artifact{signature: nil}, trust_policy) do
    if Keyword.get(trust_policy, :allow_unsigned, false),
      do: :ok,
      else: {:error, :signature_required}
  end

  defp verify_signature(
         %Artifact{signature: %{signer: signer, value: signature}} = artifact,
         policy
       ) do
    trusted_signers = Keyword.get(policy, :trusted_signers, %{})

    cond do
      not is_map(trusted_signers) ->
        {:error, :invalid_trusted_signers}

      not is_binary(signer) or signer == "" ->
        {:error, :invalid_signer}

      not is_binary(signature) or byte_size(signature) != 64 ->
        {:error, {:invalid_signature, signer}}

      true ->
        verify_trusted_signature(artifact, signer, signature, trusted_signers)
    end
  end

  defp verify_signature(_artifact, _policy), do: {:error, :invalid_signature_envelope}

  # The payload is lane W's — `:ouroboros_wasm_v1` — and the crypto is the BEAM verifier's.
  # Copying the Ed25519 check would have given this lane its own place for it to be wrong.
  defp verify_trusted_signature(artifact, signer, signature, trusted_signers) do
    artifact
    |> Artifact.signing_payload(signer)
    |> BeamVerifier.verify_payload_signature(signer, signature, trusted_signers)
  rescue
    _error -> {:error, {:invalid_signature, signer}}
  catch
    _kind, _reason -> {:error, {:invalid_signature, signer}}
  end

  defp verify_bytes(%Artifact{} = artifact, bytes) do
    size = byte_size(bytes)
    digest = Artifact.digest(bytes)

    cond do
      size != artifact.size ->
        {:error, {:component_size_mismatch, artifact.size, size}}

      digest != artifact.component_sha256 ->
        {:error, {:component_sha256_mismatch, artifact.component_sha256, digest}}

      true ->
        :ok
    end
  end

  defp field(report, key, valid?) do
    case Map.fetch(report, key) do
      {:ok, value} ->
        if valid?.(value),
          do: {:ok, value},
          else: {:error, {:invalid_inspect_report, key, describe(value)}}

      :error ->
        {:error, {:invalid_inspect_report, key, :missing}}
    end
  end

  defp list_of_binaries?(value), do: is_list(value) and Enum.all?(value, &is_binary/1)

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
