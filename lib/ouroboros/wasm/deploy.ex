defmodule Ouroboros.Wasm.Deploy do
  @moduledoc """
  The node-side half of `wasm.sign`, `wasm.deploy` and `wasm.rollback` (docs/WASM.md D15).

  `Ouroboros.Gateway.Methods` validates parameters and routes; this is what runs on the
  machine the verbs are about. It exists as its own module for the reason
  `Ouroboros.Wasm.Surface` does: a helper, a store, a rollout register, an upload
  directory and a signing service are node-local authorities, so the machine that holds
  them is the machine that acts on them, and what crosses `:erpc` is a small projected map
  rather than sixteen mebibytes and a struct.

  Nothing here is new authority. `sign/2` is `Ouroboros.Upgrade.Signing.Service` with a
  manifest built in front of it; `deploy/3` is `Ouroboros.Wasm.Bundle.verify/2` followed
  by `Ouroboros.Wasm.Rollout.deploy/4`; `rollback/2` is `Ouroboros.Wasm.Rollout.rollback/2`.
  Every refusal any of those three make is still made, in the same place, by the same code.

  ## The order in `deploy/3`, which is the whole of its safety

  Verify, **then** anything else. The bundle is read, parsed under its bounds, and put
  through this node's own trust policy before a byte of it reaches
  `Ouroboros.Wasm.Store`, the helper, or the rollout register. An unsigned bundle, a
  tampered manifest, a signer nobody trusts: each is a refusal with nothing written and
  nothing started. `Rollout.deploy/4` verifies again — against its own reading of the
  policy, and again on every target — and that redundancy is deliberate: the pre-flight
  here is what keeps the *checkpoint* from being written for something that was never
  going to be admitted.

  ## What `sign/2` does not take the caller's word for

  The digest, the size, and the import list.

    * the sha256 and the size are computed from the uploaded bytes by
      `Ouroboros.Wasm.Artifact.build/2` and recomputed again by the signing policy, which
      is handed the same bytes;
    * the **imports are read off the component** by this node's helper when the caller did
      not declare them, because a manifest's import list is compared against the helper's
      own reading at stage time (`Ouroboros.Wasm.Verifier.cross_check/2`) and a wrong list
      is a quarantine that costs an epoch and a signature to recover from. Declaring them
      is still allowed — the list is provenance, and an operator who knows what they built
      may say so — but guessing on their behalf is not, so a node with no helper and a
      caller with no declaration is a refusal naming `imports` rather than an empty list
      nobody meant.

  The epoch is allocated with `Ouroboros.Upgrade.Epoch.next/2` over **this node**, exactly
  as `Ouroboros.Upgrade.Forge` allocates before building a manifest. That bounds it above
  everything this node has seen and not above a peer that has seen more, so a bundle signed
  here and deployed to a busier machine can still be refused `{:stale_epoch, _, _}` — which
  is the register doing its job, and is why the epoch may also be named explicitly.

  ## The signature comes back; the bytes do not go out again

  `sign/2` answers with the bundle's **prefix** — the header and the envelope, a few
  hundred bytes — and not with the bundle. The operator running `ouro wasm sign` already
  holds the exact component they uploaded, so returning sixteen mebibytes through a
  protocol whose frame is a mebibyte would mean building a chunked *download* to send
  somebody their own file back. The client appends its bytes to the prefix and has the
  bundle; the prefix states the component length, so the client composes nothing.
  """

  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Signing.Service, as: SigningService
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.{Artifact, Bundle, Pool, Rollout, Surface, Upload}

  @default_signing_timeout 15_000
  @signing_slack 5_000

  @type sign_attrs :: %{
          required(:upload) => String.t(),
          required(:name) => String.t(),
          required(:author) => String.t(),
          optional(:epoch) => pos_integer() | nil,
          optional(:imports) => [String.t()] | nil,
          optional(:language) => String.t() | nil,
          optional(:source_sha256) => String.t() | nil,
          optional(:start_config) => String.t() | nil,
          optional(:eval) => map() | nil
        }

  @doc """
  Signs the component staged under `attrs.upload` and answers the bundle's prefix.

  Options are test seams and nothing else: `:upload_root`, `:signing_service`,
  `:signing_node`, `:pool`, `:epoch_opts`.
  """
  @spec sign(sign_attrs(), keyword()) :: {:ok, map()} | {:error, term()}
  def sign(attrs, opts \\ [])

  def sign(%{upload: upload} = attrs, opts) when is_binary(upload) and is_list(opts) do
    with {:ok, server} <- signer(opts),
         {:ok, signer_id} <- signer_id(server),
         {:ok, imports} <- imports(attrs, upload, opts),
         {:ok, bytes} <- Upload.take(upload, upload_opts(opts)),
         {:ok, epoch} <- epoch(attrs, opts),
         {:ok, artifact} <- build(bytes, attrs, imports, epoch),
         {:ok, signature} <- issue(server, artifact, signer_id, bytes),
         {:ok, signed} <- Artifact.with_signature(artifact, signature),
         {:ok, prefix} <- Bundle.prefix(signed) do
      {:ok, receipt(signed, prefix)}
    end
  end

  def sign(attrs, _opts), do: {:error, {:invalid_sign_request, describe(attrs)}}

  @doc """
  Verifies the bundle staged under `upload` against this node's trust policy, then deploys.

  Answers `{:ok, projection}` for every rollout that *ran* — `:live`, `:rolled_back` and
  `:quarantined` alike, because all three are outcomes a client renders rather than
  refusals it retries — and `{:error, reason}` only where no rollout happened at all.
  """
  @spec deploy(String.t(), [node()], keyword()) :: {:ok, map()} | {:error, term()}
  def deploy(upload, nodes, opts \\ [])

  def deploy(upload, nodes, opts) when is_binary(upload) and is_list(nodes) and is_list(opts) do
    # Verified before anything else touches it: the bytes are not handed to the store, the
    # helper or the register until this node's own policy has admitted the manifest that
    # describes them.
    with {:ok, bundle} <- Upload.take(upload, upload_opts(opts)),
         {:ok, %{artifact: artifact, bytes: bytes}} <- Bundle.verify(bundle, trust_policy(opts)) do
      artifact
      |> Rollout.deploy(bytes, nodes, rollout_opts(opts))
      |> settled()
    end
  end

  def deploy(upload, nodes, _opts),
    do: {:error, {:invalid_deploy_request, describe({upload, nodes})}}

  @doc "Retires the live rollout of `name` on this node's register, projected for the wire."
  @spec rollback(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def rollback(name, opts \\ []) when is_binary(name) and is_list(opts) do
    case Rollout.rollback(name, rollout_opts(opts)) do
      {:ok, outcome} -> {:ok, Surface.rollback(outcome)}
      {:error, reason} -> {:error, reason}
    end
  end

  ## Signing

  # An explicit service (tests), then the configured `:signer`-role node, then a service
  # running on this node. A node with none of the three refuses by name: "this node cannot
  # sign" and "this node is refusing to sign" need different operator responses, and a
  # generic error tells them apart for nobody.
  defp signer(opts) do
    configured =
      Keyword.get_lazy(opts, :signing_node, fn ->
        Application.get_env(:ouroboros, :signing_node)
      end)

    cond do
      not is_nil(Keyword.get(opts, :signing_service)) ->
        {:ok, Keyword.fetch!(opts, :signing_service)}

      is_atom(configured) and not is_nil(configured) and configured != node() ->
        {:ok, {SigningService, configured}}

      is_pid(Process.whereis(SigningService)) ->
        {:ok, SigningService}

      true ->
        {:error, :no_signing_service}
    end
  end

  # The identity the service will sign as, asked of the service rather than assumed. It
  # refuses a request naming any other id, so guessing one from configuration would turn a
  # misconfigured node into a refusal with no cause in it — and the round trip doubles as
  # the liveness check that makes `:no_signing_service` above an honest answer.
  defp signer_id(server) do
    case call(server, :public_info, [], signing_timeout()) do
      {:ok, %{signer_id: id}} when is_binary(id) and id != "" -> {:ok, id}
      {:ok, other} -> {:error, {:invalid_signer_identity, describe(other)}}
      {:error, reason} -> {:error, {:signing_service_unavailable, reason}}
      other -> {:error, {:signing_service_unavailable, describe(other)}}
    end
  end

  defp issue(server, artifact, signer_id, bytes) do
    request = %{
      requester: node(),
      # Advisory and cross-checked, exactly as `Ouroboros.Upgrade.Forge.Signer.Remote`
      # sends it: the service signs its own derivation and a disagreement is version skew
      # worth stopping at.
      payload: Artifact.signing_payload(artifact, signer_id),
      component_bytes: bytes
    }

    case call(server, :sign_artifact, [artifact, signer_id, request], signing_timeout()) do
      {:ok, value} when is_binary(value) -> {:ok, %{signer: signer_id, value: value}}
      {:refused, reason} -> {:error, {:signing_refused, reason}}
      other -> {:error, {:signing_refused, describe(other)}}
    end
  end

  # `Ouroboros.Upgrade.Signing.Service` never raises out of its public API, but the
  # transport to a remote one does, and a `:erpc` fault reaching a gateway task as an
  # exception would be reported as an upstream error with nothing in it.
  defp call({module, target}, function, args, timeout) do
    :erpc.call(target, module, function, args ++ [module], timeout + @signing_slack)
  catch
    kind, reason -> {:error, {:signer_unreachable, target, {kind, describe(reason)}}}
  end

  defp call(server, function, args, _timeout),
    do: apply(SigningService, function, args ++ [server])

  defp signing_timeout do
    case Application.get_env(:ouroboros, :signing_call_timeout, @default_signing_timeout) do
      ms when is_integer(ms) and ms > 0 -> ms
      _invalid -> @default_signing_timeout
    end
  end

  ## The manifest

  defp epoch(attrs, opts) do
    case Map.get(attrs, :epoch) do
      given when is_integer(given) and given > 0 ->
        {:ok, given}

      _absent ->
        case Epoch.next([node()], Keyword.get(opts, :epoch_opts, [])) do
          {:ok, epoch} -> {:ok, epoch}
          {:error, reason} -> {:error, {:epoch_not_allocated, reason}}
        end
    end
  end

  # Declared, or read off the component by this node's helper. Never guessed: see the
  # moduledoc. The staged file is inspected in place, so a sixteen-mebibyte component is
  # not written to a second path to be looked at.
  defp imports(attrs, upload, opts) do
    case Map.get(attrs, :imports) do
      declared when is_list(declared) ->
        {:ok, declared}

      _absent ->
        with {:ok, path} <- Upload.path(upload, upload_opts(opts)) do
          derive_imports(path, Keyword.get(opts, :pool, Pool))
        end
    end
  end

  defp derive_imports(path, pool) do
    case Pool.inspect(path, pool) do
      {:ok, %{"imports" => imports}} when is_list(imports) ->
        if Enum.all?(imports, &is_binary/1),
          do: {:ok, Enum.sort(imports)},
          else: {:error, {:imports_not_derivable, :unreadable_report}}

      {:ok, _report} ->
        {:error, {:imports_not_derivable, :unreadable_report}}

      {:error, reason} ->
        {:error, {:imports_not_derivable, describe(reason)}}
    end
  catch
    kind, reason -> {:error, {:imports_not_derivable, {kind, describe(reason)}}}
  end

  defp build(bytes, attrs, imports, epoch) do
    Artifact.build(bytes, [
      {:name, Map.get(attrs, :name)},
      {:epoch, epoch},
      {:imports, imports},
      {:world, Wasm.world()},
      {:metadata, metadata(attrs)}
    ])
  end

  # Only the keys `Ouroboros.Wasm.Artifact` names, and only where a value was given: a
  # metadata map carrying `nil`s is a manifest asserting the absence of provenance rather
  # than not asserting any.
  defp metadata(attrs) do
    %{author: Map.get(attrs, :author)}
    |> put_present(:language, Map.get(attrs, :language))
    |> put_present(:source_sha256, Map.get(attrs, :source_sha256))
    |> put_present(:eval, Map.get(attrs, :eval))
    |> put_present(:start, start_block(attrs))
  end

  # The id is derived from the name and is not a field a caller may name. It is exactly
  # what `Ouroboros.Upgrade.Signing.Policy.Default` requires and exactly what
  # `Ouroboros.Wasm.Rollout.start_block/1` re-derives, so there is no spelling of it a
  # request could get wrong (docs/WASM.md §7.5).
  defp start_block(attrs) do
    case Map.get(attrs, :start_config) do
      config when is_binary(config) ->
        %{id: "wasm/" <> to_string(Map.get(attrs, :name)), config: config}

      _absent ->
        nil
    end
  end

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  defp receipt(artifact, prefix) do
    %{
      artifact_id: artifact.id,
      name: artifact.name,
      epoch: artifact.epoch,
      component_sha256: artifact.component_sha256,
      size: artifact.size,
      world: artifact.world,
      imports: artifact.imports,
      created_at: artifact.created_at,
      signer: artifact.signature.signer,
      start_id: start_id(artifact),
      extension: Bundle.extension(),
      bundle_prefix: Base.encode64(prefix),
      bundle_bytes: byte_size(prefix) + artifact.size
    }
  end

  defp start_id(artifact) do
    case Rollout.start_block(artifact) do
      %{id: id} -> id
      nil -> nil
    end
  end

  ## Deploying

  # A rollout that ran is an answer whatever it settled as. A rollout that never started —
  # a disconnected target, a stale epoch, a registry that would not record — is a refusal,
  # and the difference is exactly whether there is an outcome to report.
  defp settled({:ok, outcome}), do: {:ok, Surface.deployment(outcome)}

  defp settled({:error, {state, outcome}})
       when state in [:rolled_back, :quarantined] and is_map(outcome),
       do: {:ok, Surface.deployment(outcome)}

  defp settled({:error, reason}), do: {:error, reason}

  defp trust_policy(opts) do
    Keyword.get_lazy(opts, :trust_policy, fn ->
      Application.get_env(:ouroboros, :upgrade_trust_policy, [])
    end)
  end

  # Only the keys `Ouroboros.Wasm.Rollout` reads, so a caller cannot pass this module's
  # own test seams through to it.
  defp rollout_opts(opts),
    do: Keyword.take(opts, [:registry, :pool, :store_root, :trust_policy, :start?, :limits])

  defp upload_opts(opts) do
    case Keyword.get(opts, :upload_root) do
      root when is_binary(root) and root != "" -> [root: root]
      _unset -> []
    end
  end

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
