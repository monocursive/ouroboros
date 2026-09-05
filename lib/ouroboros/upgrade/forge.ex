defmodule Ouroboros.Upgrade.Forge do
  @moduledoc """
  Turns agent-authored Elixir source into a signed artifact a node executor will accept.

  One call, six stages, each with its own named failure:

      Source.validate/1     {:error, {:source_rejected, reason}}
      BuildPeer + Sandbox   {:error, {:build_failed, reason}}
      Beam.introduce/3      {:error, {:beam_rejected, reason}}
      Epoch.next/2          {:error, {:epoch_unavailable, reason}}
      Artifact.build/2      {:error, {:artifact_failed, reason}}
      Signer.sign/2         {:error, {:signing_failed, reason}}

  The stage order is deliberate. Parse-only hygiene runs before anything compiles, the
  compile happens in a peer that cannot reach the cluster, the compiled binary is held to
  the same introduction rules the loading node will re-check, and only then is a number
  allocated and a signature requested. Nothing after the build peer runs agent code.

  `preview/2` stops after the build peer. It never constructs a `Beam.introduce/3`
  transition, never allocates an epoch, and never asks a signer. A preview that
  compiled is not a prepared load.

  The forge produces an artifact; it does not deploy one and cannot authorize one. The
  signature comes from whatever `config :ouroboros, :forge_signer` names, which is
  `Signer.Deny` unless an operator changed it, and the artifact is verified again on
  every loading node against `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`. This module lives under
  `Ouroboros.Upgrade.` and is therefore in the protected set, so a capability forged here
  can never patch the forge that made it.

  What this does not establish: that the code is good. Its own tests passed in a peer
  chosen to resemble the targets. What it can carry is the *criteria* by which someone
  else will decide: `:eval` embeds a validated
  `Ouroboros.Upgrade.Rollout.Evaluation` spec in `metadata.forge.eval`, inside the
  signed manifest, so a rollout's gates are tamper-evident and an external signer can
  refuse to sign an artifact that declares none. The forge still does not run them; that
  happens on the target nodes, between commit and promotion. Cost regression and canary
  cohorts remain external.
  """

  alias Ouroboros.Upgrade.{Artifact, Beam, Epoch}
  alias Ouroboros.Upgrade.Forge.{BuildPeer, Signer, Source}
  alias Ouroboros.Upgrade.Rollout.Evaluation

  @type result :: {:ok, Artifact.t()} | {:error, term()}

  @doc """
  Forges one capability module into a signed, epoch-stamped artifact.

  Options:

    * `:nodes` - the nodes the artifact is destined for, used to allocate an epoch
      above every one of them. Defaults to `[node()]`.
    * `:signer_id` - the signer identity recorded in the signature envelope and covered
      by the signing payload. Defaults to `config :ouroboros, :forge_signer_id`.
    * `:timeout` - overall build deadline, defaulting to
      `config :ouroboros, :forge_build_timeout`.
    * `:storage` - explicit epoch storage, for tests.
    * `:eval` - an `Ouroboros.Upgrade.Rollout.Evaluation` spec, validated here and
      embedded in `metadata.forge.eval` so it is covered by the signature. Omitting it
      produces exactly the metadata this forge produced before evaluation existed.
  """
  @spec forge(Source.t(), keyword()) :: result()
  def forge(source, opts \\ [])

  def forge(%Source{} = source, opts) when is_list(opts) do
    with {:ok, source} <- validate(source),
         {:ok, eval} <- eval_spec(opts),
         {:ok, build} <- build(source, opts),
         {:ok, _beam} <- introduce(source, build),
         {:ok, epoch} <- epoch(opts),
         {:ok, artifact} <- assemble(source, build, epoch, eval),
         {:ok, signed} <- sign(artifact, opts) do
      {:ok, signed}
    end
  end

  def forge(source, _opts), do: {:error, {:source_rejected, {:invalid_source, source}}}

  @doc """
  Validates and compiles one capability in the build peer, then discards the binary.

  Returns module, source digest, and the peer's test report. The production node does
  not introduce, epoch, or sign anything. `:code.which/1` for the declared module stays
  `:non_existing` on this VM.
  """
  @spec preview(Source.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def preview(source, opts \\ [])

  def preview(%Source{} = source, opts) when is_list(opts) do
    with {:ok, source} <- validate(source),
         {:ok, eval} <- eval_spec(opts),
         {:ok, build} <- build(source, opts) do
      {:ok,
       %{
         module: source.module,
         source_sha256: source.sha256,
         test_report: Map.get(build, :test_report, %{}),
         peer_runtime: Map.get(build, :peer_runtime, %{}),
         eval: eval
       }}
    end
  end

  def preview(source, _opts), do: {:error, {:source_rejected, {:invalid_source, source}}}

  defp validate(source) do
    case Source.validate(source) do
      {:ok, source} -> {:ok, source}
      {:error, reason} -> {:error, {:source_rejected, reason}}
    end
  end

  # Checked before a peer is booted: a spec nobody could run is not worth a build, and a
  # spec that only fails at deploy time would already be inside a signature.
  defp eval_spec(opts) do
    case Keyword.fetch(opts, :eval) do
      :error -> {:ok, nil}
      {:ok, nil} -> {:ok, nil}
      {:ok, spec} -> Evaluation.validate(spec)
    end
  end

  defp build(source, opts) do
    case BuildPeer.build(source.module, source.source, source.test_source, opts) do
      {:ok, %{binary: binary} = build} when is_binary(binary) -> {:ok, build}
      {:ok, unexpected} -> {:error, {:build_failed, {:invalid_build_result, unexpected}}}
      {:error, reason} -> {:error, {:build_failed, reason}}
    end
  end

  # The same gate the loading node applies, applied here so a binary that could never be
  # introduced fails before an epoch is spent and a signature is requested.
  defp introduce(source, build) do
    case Beam.introduce(source.module, build.binary, filename: filename(source.module)) do
      {:ok, beam} -> {:ok, beam}
      {:error, reason} -> {:error, {:beam_rejected, reason}}
    end
  end

  defp epoch(opts) do
    nodes = Keyword.get(opts, :nodes, [node()])
    epoch_opts = Keyword.take(opts, [:storage, :status_timeout, :lock_retries])

    case Epoch.next(nodes, epoch_opts) do
      {:ok, epoch} -> {:ok, epoch}
      {:error, reason} -> {:error, {:epoch_unavailable, reason}}
    end
  end

  defp assemble(source, build, epoch, eval) do
    entry =
      {source.module, build.binary, disposition: :introduce, filename: filename(source.module)}

    case Artifact.build([entry], epoch: epoch, metadata: metadata(source, build, eval)) do
      {:ok, artifact} -> {:ok, artifact}
      {:error, reason} -> {:error, {:artifact_failed, reason}}
    end
  end

  # Metadata is inside the signed manifest and travels to every node, so it records what
  # provenance a reviewer needs and nothing that grows without bound. Failure output stays
  # in the error tuple the forge returns; only counts are shipped. An absent `:eval` key
  # is absent rather than nil: an artifact forged without gates has the metadata it
  # always had, and a reader can tell "declared no gates" from "declared empty gates".
  defp metadata(source, build, eval) do
    forge = %{
      source_id: source.id,
      source_sha256: source.sha256,
      author: source.author,
      created_at: source.created_at,
      test_report: Map.get(build, :test_report, %{}),
      peer_runtime: Map.get(build, :peer_runtime, %{})
    }

    %{forge: if(is_nil(eval), do: forge, else: Map.put(forge, :eval, eval))}
  end

  defp sign(artifact, opts) do
    {module, _signer_opts} = Signer.configured()

    with {:ok, signer_id} <- signer_id(opts),
         {:ok, signature} <- request_signature(module, artifact, signer_id),
         :ok <- validate_signature(signature) do
      {:ok, %{artifact | signature: %{signer: signer_id, value: signature}}}
    end
  end

  defp signer_id(opts) do
    id =
      Keyword.get_lazy(opts, :signer_id, fn ->
        Application.get_env(:ouroboros, :forge_signer_id)
      end)

    if is_binary(id) and id != "" do
      {:ok, id}
    else
      {:error, {:signing_failed, :signer_id_required}}
    end
  end

  # A signer that can decide on the whole artifact is asked for the whole artifact. That
  # is not a convenience: a payload is a hash of a manifest, and a signer holding only the
  # hash cannot check the manifest against the bytes it describes, which is precisely what
  # an independent signer exists to do. Signers that implement only `sign/2` — `Deny` —
  # take the path they always took, and the bytes covered by the signature are identical
  # either way. `Local` implements `sign_artifact/2` so a development forge still runs
  # `Signing.Policy` before a signature exists.
  defp request_signature(module, artifact, signer_id) do
    result =
      if Signer.artifact_signer?(module) do
        module.sign_artifact(artifact, signer_id)
      else
        module.sign(Artifact.signing_payload(artifact, signer_id), signer_id)
      end

    case result do
      {:ok, signature} -> {:ok, signature}
      {:error, reason} -> {:error, {:signing_failed, reason}}
      other -> {:error, {:signing_failed, {:invalid_signer_result, other}}}
    end
  rescue
    error -> {:error, {:signing_failed, {:signer_exception, Exception.message(error)}}}
  catch
    kind, reason -> {:error, {:signing_failed, {:signer_failure, kind, inspect(reason)}}}
  end

  defp validate_signature(signature) when is_binary(signature) and byte_size(signature) == 64,
    do: :ok

  defp validate_signature(signature),
    do: {:error, {:signing_failed, {:invalid_signature, byte_size_of(signature)}}}

  defp byte_size_of(term) when is_binary(term), do: byte_size(term)
  defp byte_size_of(term), do: {:not_a_binary, inspect(term)}

  defp filename(module), do: "ouroboros://capability/#{inspect(module)}"
end
