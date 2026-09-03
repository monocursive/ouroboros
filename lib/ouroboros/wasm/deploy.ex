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

  ## Where verification happens, said once and accurately

  In `Ouroboros.Wasm.Rollout.deploy/4`, before its `:deploying` checkpoint, and again on
  every target before it stages a byte. This module decodes the bundle — which is where
  its *bounds* are enforced, and the reason `Bundle.decode/1` is a separate function from
  `Bundle.verify/2` — and hands the manifest and the bytes to the rollout. An earlier
  draft also verified here, and called that "the whole of its safety"; it was not, because
  the rollout was already verifying before it wrote anything, and a mutation that deleted
  the pre-flight left every test green. A second check that no test can distinguish is not
  defence in depth, it is a sentence claiming more than the code does, so it is gone. What
  is proved instead is the invariant that was always the real one: a bundle this node
  refuses consumes no epoch and leaves the rollout register byte-identical.

  ## What `sign/2` never does

  **Parse the bytes.** They are unsigned, they came from a socket, and the helper is the
  one component of this system whose job is to run other people's code — feeding it
  attacker-supplied input *before* a signature exists, upstream of the signing service's
  own rate limit, is the shape of the problem lane W exists to avoid (D15). An earlier
  draft read the import list off the component with this node's helper whenever a caller
  did not declare one. That is gone: **`imports` is required**, the *client* computes it
  with the operator's own helper (`ouro wasm inspect --json`), and a declared list that
  does not match what the component actually imports is refused at stage by
  `Ouroboros.Wasm.Verifier.cross_check/2` — which is D5's posture exactly, and the same
  answer lane W has always given for a manifest that describes something else.

  What it does not take the caller's word for is the digest and the size: both are computed
  from the uploaded bytes by `Ouroboros.Wasm.Artifact.build/2` and recomputed again by the
  signing policy, which is handed the same bytes.

  **The upload is consumed first**, before anything that can fail. A refused sign costs the
  client its transfer, which is the point: an upload that survived its own refusal was a
  blob a client could re-present without limit.

  ## The epoch is not a parameter

  It is allocated with `Ouroboros.Upgrade.Epoch.next/2` over the **connected cluster**,
  exactly as `Ouroboros.Upgrade.Forge` allocates before building a manifest. It used to be
  an optional client parameter with no ceiling, and that was a one-call, unrecoverable
  wedge: `Ouroboros.Upgrade.Rollout.Registry` admits an epoch only above its watermark and
  refuses one at its plausibility ceiling, so a single deploy *at* the ceiling left no
  number that was both, on every lane-W capability on that node, durably. Allocating over
  every connected node rather than over this one also closes the other end of it — a
  bundle signed here and deployed to a busier peer is no longer refused for a number this
  node could not see.

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
  alias Ouroboros.Wasm.{Artifact, Bundle, Rollout, Surface, Upload}

  @default_signing_timeout 15_000

  # The two processes that make a node able to hold a lane-W rollout, and therefore able to
  # call an epoch stale: the register that records one and the executor `Ouroboros.Upgrade.
  # Epoch.next/2` reads a node's last committed epoch from. A node running neither is a node
  # no epoch can be too small for.
  @rollout_plane [Ouroboros.Upgrade.Rollout.Registry, Ouroboros.Upgrade.NodeExecutor]

  # One bounded question per candidate, per process. Well under `wasm.sign`'s own ceiling,
  # because this runs before the signing round trip rather than instead of it.
  @epoch_probe_timeout 5_000
  @signing_slack 5_000

  @type sign_attrs :: %{
          required(:upload) => String.t(),
          required(:name) => String.t(),
          required(:author) => String.t(),
          required(:imports) => [String.t()],
          optional(:kind) => :capability | :policy,
          optional(:language) => String.t() | nil,
          optional(:source_sha256) => String.t() | nil,
          optional(:start_config) => String.t() | nil,
          optional(:eval) => map() | nil
        }

  @doc """
  Signs the component staged under `attrs.upload` and answers the bundle's prefix.

  `attrs.imports` is required: this node does not read a component to find out (see the
  moduledoc). `attrs.kind` is `:capability` (the default) or `:policy` and decides the world
  the manifest declares (W15, contract C7); it is a parameter rather than something derived,
  because deriving it would mean parsing the unsigned bytes this module refuses to parse, and
  a client that declares the wrong one is refused at stage by the helper's world check exactly
  as a client that declares the wrong imports is.

  Options are test seams and nothing else: `:upload_root`, `:signing_service`, `:signing_node`,
  `:epoch_nodes`, `:epoch_opts`.
  """
  @spec sign(sign_attrs(), keyword()) :: {:ok, map()} | {:error, term()}
  def sign(attrs, opts \\ [])

  def sign(%{upload: upload, imports: imports} = attrs, opts)
      when is_binary(upload) and is_list(imports) and is_list(opts) do
    # The upload is consumed first, before anything that can refuse. A staged blob that
    # outlived its own refusal is a blob a client can re-present without limit, and every
    # bound below it — the policy, its rate limit, the journal — is downstream of that.
    with {:ok, bytes} <- Upload.take(upload, upload_opts(opts)),
         {:ok, server} <- signer(opts),
         {:ok, signer_id} <- signer_id(server),
         {:ok, epoch} <- epoch(opts),
         {:ok, artifact} <- build(bytes, attrs, imports, epoch),
         {:ok, signature} <- issue(server, artifact, signer_id, bytes),
         {:ok, signed} <- Artifact.with_signature(artifact, signature),
         {:ok, prefix} <- Bundle.prefix(signed) do
      {:ok, receipt(signed, prefix)}
    end
  end

  def sign(%{upload: upload} = attrs, opts) when is_binary(upload) and is_list(opts),
    do: {:error, {:invalid_sign_request, {:imports, describe(Map.get(attrs, :imports))}}}

  def sign(attrs, _opts), do: {:error, {:invalid_sign_request, describe(attrs)}}

  @doc """
  Deploys the bundle staged under `upload`, which the rollout verifies before it records.

  Answers `{:ok, projection}` for every rollout that *ran* — `:live`, `:rolled_back` and
  `:quarantined` alike, because all three are outcomes a client renders rather than
  refusals it retries — and `{:error, reason}` only where no rollout happened at all.
  """
  @spec deploy(String.t(), [node()], keyword()) :: {:ok, map()} | {:error, term()}
  def deploy(upload, nodes, opts \\ [])

  def deploy(upload, nodes, opts) when is_binary(upload) and is_list(nodes) and is_list(opts) do
    # Decoded under the bundle's own bounds, then handed to the rollout, which verifies it
    # against this node's trust policy *before* its checkpoint and again on every target.
    # See the moduledoc for why there is no second verification here.
    with {:ok, bundle} <- Upload.take(upload, upload_opts(opts)),
         {:ok, %{artifact: artifact, bytes: bytes}} <- Bundle.decode(bundle) do
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

  # Over the nodes that could make this epoch stale, which is not the same set as the nodes
  # that are connected.
  #
  # `Ouroboros.Upgrade.Epoch.next/2` asks every node it is given for
  # `Ouroboros.Upgrade.NodeExecutor.status/0` and for its lane-W register's watermark, and a
  # node that runs neither answers neither: the call exits `:noproc` and the whole allocation
  # fails. Handing it `[node() | Node.list()]` therefore made signing impossible on exactly
  # the topology D15 prescribes — the key on a `:signer`-role node, whose supervision tree is
  # the signing service and cluster formation and nothing else — and on any `:builder` or
  # bare client node that happens to be connected. It was proved live: `wasm.sign` on a core
  # node with a signer peer refused with `{:epoch_not_allocated, {:epoch_status_unavailable,
  # …}}`, and the operator had no way to proceed at all.
  #
  # What an epoch has to be above is what some register has already admitted, because
  # `Ouroboros.Upgrade.Rollout.Registry.ensure_fresh_epoch/2` is the only thing that ever
  # calls one stale. A node with no register admits nothing, holds no watermark, and cannot
  # refuse anything later — so asking it is not merely useless, it is the failure. The
  # candidates are still every connected node; what is allocated over is the subset that runs
  # the rollout plane.
  #
  # The probe distinguishes the two answers that look alike from here. A node that answers
  # "no such process" is a node with no plane and is excluded. A node that does not answer at
  # all is **not** excluded: it may be running a register this allocation cannot see, and an
  # epoch minted below its watermark is one it will refuse at stage time, so an unreachable
  # candidate fails the allocation closed rather than quietly narrowing it.
  #
  # If no candidate holds a register — a fresh fleet, or a lone signer — the epoch is 1 and
  # the signature proceeds. Nothing can call 1 stale, because nothing has admitted anything.
  # The honest cost is that two signatures on such a fleet both carry 1: the first deploy to
  # whichever node first grows a register wins, and the second is an ordinary
  # `{:stale_epoch, 1, 1}` that re-signing clears. Once one register exists this stops
  # happening, because `Epoch.next/2`'s durable watermark advances on every allocation.
  defp epoch(opts) do
    case epoch_nodes(opts) do
      {:ok, []} ->
        {:ok, 1}

      {:ok, nodes} ->
        case Epoch.next(nodes, Keyword.get(opts, :epoch_opts, [])) do
          {:ok, epoch} -> {:ok, epoch}
          {:error, reason} -> {:error, {:epoch_not_allocated, reason}}
        end

      {:error, unreachable} ->
        {:error, {:epoch_not_allocated, {:candidates_unreachable, unreachable}}}
    end
  end

  # The connected nodes that run the rollout plane, or the ones that could not be asked.
  defp epoch_nodes(opts) do
    candidates =
      Keyword.get_lazy(opts, :epoch_nodes, fn -> Enum.uniq([node() | Node.list()]) end)

    timeout = Keyword.get(opts, :epoch_probe_timeout, @epoch_probe_timeout)

    {held, unreachable} =
      candidates
      |> Task.async_stream(&{&1, rollout_plane(&1, timeout)},
        ordered: true,
        max_concurrency: max(1, length(candidates)),
        timeout: :infinity
      )
      |> Enum.reduce({[], %{}}, fn
        {:ok, {target, :holds}}, {held, faults} ->
          {[target | held], faults}

        {:ok, {_target, :absent}}, acc ->
          acc

        {:ok, {target, {:unreachable, why}}}, {held, faults} ->
          {held, Map.put(faults, target, why)}

        {:exit, reason}, {held, faults} ->
          {held, Map.put(faults, node(), describe(reason))}
      end)

    if unreachable == %{},
      do: {:ok, Enum.reverse(held)},
      else: {:error, unreachable}
  end

  # `:erlang.whereis/1` and nothing of ours, so a node too old to hold these modules answers
  # `:undefined` rather than failing to find a function. The local branch does not go through
  # `:erpc` at all: a node cannot be unreachable from itself, and rendering it as such would
  # make the one case a lone signer needs — "I have no register either" — a hard failure.
  # A partial plane on the local node still fails closed, for the reason `classify_plane/1`
  # gives.
  defp rollout_plane(target, _timeout) when target == node() do
    classify_plane(Enum.map(@rollout_plane, &{&1, is_pid(Process.whereis(&1))}))
  end

  defp rollout_plane(target, timeout) do
    @rollout_plane
    |> Enum.map(fn name ->
      case :erpc.call(target, :erlang, :whereis, [name], timeout) do
        pid when is_pid(pid) -> {name, true}
        :undefined -> {name, false}
        other -> throw({:unexpected, describe(other)})
      end
    end)
    |> classify_plane()
  catch
    :throw, why -> {:unreachable, why}
    kind, reason -> {:unreachable, {kind, describe(reason)}}
  end

  # The whole plane is a holder; none of it is a node that admits nothing. Part of it — a
  # register with no executor, or an executor mid-restart — is neither: its register may hold
  # a watermark above the number about to be minted, and the executor `Epoch.next/2` would
  # ask is not there to say so. That is the unreachable answer, whatever node gave it.
  defp classify_plane(presence) do
    case Enum.split_with(presence, fn {_name, present?} -> present? end) do
      {_held, []} -> :holds
      {[], _missing} -> :absent
      {_held, missing} -> {:unreachable, {:partial_plane, Enum.map(missing, &elem(&1, 0))}}
    end
  end

  defp build(bytes, attrs, imports, epoch) do
    kind = kind(attrs)

    Artifact.build(bytes, [
      {:name, Map.get(attrs, :name)},
      {:epoch, epoch},
      {:imports, imports},
      {:kind, kind},
      # Derived from the kind rather than taken beside it, so a request cannot produce a
      # manifest whose two halves disagree; the signing policy checks the pair again.
      {:world, Wasm.world_for(kind)},
      {:metadata, metadata(attrs)}
    ])
  end

  # An unrecognized kind is refused rather than defaulted: `:capability` is what an *absent*
  # kind means, and a caller that named one this build does not implement has said something
  # this build cannot honour either way.
  defp kind(attrs) do
    case Map.get(attrs, :kind, :capability) do
      kind when kind in [:capability, :policy] -> kind
      other -> other
    end
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
      kind: artifact.kind,
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
