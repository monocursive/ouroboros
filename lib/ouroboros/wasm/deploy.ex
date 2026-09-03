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

  ## Compilation moved here (W8, D23)

  `sign/2` compiles the component **on this node** before it builds the manifest, with
  `ouro-wasm precompile` — the same engine configuration `serve` uses, in the same binary, under
  the same §7.3 structural bounds. What that buys the fleet is that a loading node's `load`
  stops being a `Component::new` whose cost is a function of the component's shape and becomes a
  `Component::deserialize` whose cost is a function of its size, which a byte cap bounds exactly.
  What it costs *this* node is the compile, which is the trade: the machine that signs is the
  machine that pays.

  That compile runs **inside the same OS sandbox a node's own helper runs inside** (W16, D25):
  `Ouroboros.Provider.Native.Sandbox.helper_policy/1` with **this signature's own directory**
  writable, that directory and the helper's own readable, no network at all — loopback
  included — and `$TMPDIR` below it. One signature, one directory: the shared
  `<data_dir>/wasm/sign/` root is neither readable nor writable, because the first cut made it
  both and a review read a concurrent signature's uploaded component out of it and overwrote a
  concurrent signature's artifact, which is the file the next signature is issued over. The
  bytes being compiled are a client's upload, and this is the one place on the signing path
  where a subprocess reads them. Under `helper_sandbox: :required` — the default — a signer
  that cannot apply that policy does not run the helper at all: it signs the source form and
  the receipt's `precompile_skipped` names the reason, which is the same shape as every other
  skip below.

  Three things make it safe to skip rather than a requirement. A node with no helper on disk
  signs the source form alone and says so. `precompile: false` — `ouro wasm sign
  --no-precompile` — does the same on request. And a node that cannot sandbox the helper
  refuses to spawn it (W16). In all three the manifest carries no `precompiled` block, the
  bundle carries no second section, and every node compiles the component for itself
  exactly as it did before W8. Size is no longer one of them (W19, see below).

  The compile is bounded by §7.3 and not by a timer, which is the honest statement: `shape.check`
  refuses a component shaped to be expensive *before* cranelift starts, because cranelift cannot
  be interrupted once it has. What the timeout below does is stop *waiting*; it does not stop
  the compile, and it does not need to.

  ## What the receipt can carry, and what happens past it

  `sign/2` answers with the bundle's prefix, which since W8 is the header, the envelope **and**
  the precompiled artifact — the client holds the component and has never seen the artifact, so
  the artifact is the half that has to travel. That is a few hundred kibibytes for a real
  capability (the 48 KiB reference guest compiles to 258 093 bytes) and eleven mebibytes for the
  worst shape §7.3 admits, and one gateway reply is not a file transfer. So one reply carries
  the artifact only up to `max_receipt_precompiled_bytes/0`, which is three quarters of the
  gateway's own configured frame — the number an operator already sets for this socket, since
  the artifact travels base64 at four bytes to three.

  **Past that ceiling the artifact is not dropped; it is handed over in frames** (W19, D28).
  W8 signed the source form alone there and said so, which was honest and was a limit nobody
  had chosen: a capability whose machine code happened to exceed one reply lost the fast path
  on every node in the fleet. Now `sign/2` puts the artifact in an `Ouroboros.Wasm.Download`
  slot — the upload area's discipline in the other direction, bounded slots claimed
  `O_CREAT|O_EXCL`, 0600 files, an idle clock and a total one — and the receipt carries
  `artifact: %{download:, size:, sha256:, chunk_bytes:}` beside a `bundle_prefix` that is the
  header and the envelope only. The manifest still carries the `precompiled` block, the
  signature still covers it, and the receipt still says `form: :precompiled` with
  `precompile_skipped: nil`, because nothing was skipped. The client walks the slot with
  `wasm.download`, checks the size and the digest the receipt named, and writes
  `prefix <> artifact <> component` — which is byte for byte what `Bundle.encode/3` would have
  written.

  Below the ceiling nothing changed: the prefix carries the artifact inline, `artifact` is
  `nil`, and no slot is minted. The reasoning that made the ceiling honest in the first place
  is unchanged too — one reply is still not a file transfer, and this is what a node does
  instead of pretending otherwise.

  A slot that cannot be minted — eight already in flight, a data directory that will not take
  one — is still a *skip* rather than a failure, because the slot is claimed **before** the
  manifest is signed: the block comes off, the source form is signed, and
  `precompile_skipped` names why. A signature is never issued over an artifact this node has
  no way to hand over.

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

  ## The signature comes back; the client's own bytes do not go out again

  `sign/2` answers with the bundle's **prefix** and not with the bundle. The operator running
  `ouro wasm sign` already holds the exact component they uploaded, so returning sixteen
  mebibytes of it would be this node sending somebody their own file back. That half of the
  reasoning has not moved and is not going to: the component never travels outward, in one
  reply or in a hundred.

  What W19 changed is the other half of the prefix. The artifact is **not** the client's own
  bytes — this node compiled it, from bytes it then signed, and the client has never seen it —
  so it is the one part of the file the client cannot supply. Where it fits one reply it rides
  in the prefix, exactly as W8 shipped it. Where it does not, it goes out through
  `wasm.download` in the same 512 KiB frames `wasm.upload` brought the component in, bound by
  the sha256 the signed manifest already names. The client still composes nothing: the header
  states all three lengths, and the client concatenates what it was given with what it held.
  """

  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Signing.Service, as: SigningService
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.{Artifact, Bundle, Download, Rollout, Surface, Upload}

  @default_signing_timeout 15_000

  # How long this node waits for its own helper to compile one component. §7.3's structural pass
  # bounds what reaches cranelift — the worst admissible shape is 1.46 s on this machine's
  # release helper — so thirty seconds is two orders of magnitude of slack and is here to bound
  # the *wait*, not the work: an OS process cannot be interrupted mid-compile, and a signature
  # that hung forever on a wedged helper would be worse than one that fell back.
  @precompile_timeout_ms 30_000

  # The gateway frame ceiling this node falls back to, mirroring `Ouroboros.Gateway.Config`'s
  # own default rather than inventing a second one.
  @default_gateway_max_frame 1_048_576

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
          optional(:precompile) => boolean(),
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

  `attrs.precompile` defaults to `true` and is honoured only where this node has a helper on
  disk; see the moduledoc for what a skipped precompile means and for the three ways it happens.

  Options are test seams and nothing else: `:upload_root`, `:download_root`,
  `:signing_service`, `:signing_node`, `:epoch_nodes`, `:epoch_opts`, `:helper_path`,
  `:precompile_timeout`, `:scratch_root`.
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
         # The **source** manifest: no `precompiled` block, because nothing has been compiled.
         {:ok, source} <- build(bytes, attrs, imports, epoch),
         # W8, D23. The rate limit and the whole policy, on the source manifest, before a byte
         # of this upload reaches the helper. A refusal here stops everything — which is the
         # point: the compile below is 1.4 s of a core at the worst shape §7.3 admits, and a
         # requester the limiter is about to refuse must not be able to spend it.
         {:ok, ticket} <- admit(server, source, signer_id, bytes),
         # Only now.
         {artifact_bytes, precompiled, skipped} <- precompile(bytes, attrs, opts),
         # W19. Where the artifact will not fit one reply, the slot that will carry it is
         # claimed *here* — before the manifest is signed — so a node that cannot hand an
         # artifact over signs the source form rather than signing a promise it cannot keep.
         {artifact_bytes, precompiled, skipped, download} <-
           staged(artifact_bytes, precompiled, skipped, opts) do
      sealed(
        %{
          server: server,
          signer_id: signer_id,
          bytes: bytes,
          ticket: ticket,
          source: source,
          artifact: artifact_bytes,
          precompiled: precompiled,
          skipped: skipped,
          download: download
        },
        opts
      )
    end
  end

  def sign(%{upload: upload} = attrs, opts) when is_binary(upload) and is_list(opts),
    do: {:error, {:invalid_sign_request, {:imports, describe(Map.get(attrs, :imports))}}}

  def sign(attrs, _opts), do: {:error, {:invalid_sign_request, describe(attrs)}}

  # The half of `sign/2` that runs with a download slot possibly held. It is a separate
  # function for exactly that reason: from here on every refusal has to release the slot, and
  # a slot nobody will ever ask for is ten idle minutes of this node's ceiling spent on bytes no
  # receipt names. The `else` is the whole of it, and it is why the claim happens before the
  # signature rather than after — a node that cannot hand an artifact over must be able to
  # fall back to the source form, which is a decision that has to be made before the manifest
  # is signed.
  defp sealed(plan, opts) do
    with {:ok, artifact} <- Artifact.with_precompiled(plan.source, plan.precompiled),
         {:ok, signature} <-
           issue(plan.server, artifact, plan.signer_id, plan.bytes, plan.ticket),
         {:ok, signed} <- Artifact.with_signature(artifact, signature),
         {:ok, prefix} <- prefix(signed, plan.artifact, plan.download) do
      {:ok, receipt(signed, prefix, plan.skipped, plan.download)}
    else
      refusal ->
        _released = abandon(plan.download, opts)
        refusal
    end
  end

  # W19. Which of the three shapes an artifact travels in, decided here and nowhere else:
  # inline in the receipt where it fits one reply, in a download slot where it does not, and
  # not at all where there is none.
  #
  # A slot that cannot be claimed is a *skip*, with the same posture every other precompile
  # failure has (D23): the block comes off, the source form is signed, and the reason is named
  # in the receipt. The alternative would be signing a manifest that declares an artifact this
  # node has no way to hand over, which is a bundle nobody can compose.
  defp staged(nil, _precompiled, skipped, _opts), do: {nil, nil, skipped, nil}

  defp staged(artifact_bytes, precompiled, skipped, opts) do
    if byte_size(artifact_bytes) <= max_receipt_precompiled_bytes() do
      {artifact_bytes, precompiled, skipped, nil}
    else
      case Download.put(artifact_bytes, download_opts(opts)) do
        {:ok, slot} -> {artifact_bytes, precompiled, skipped, slot}
        {:error, reason} -> {nil, nil, {:artifact_not_staged, reason}, nil}
      end
    end
  end

  # With a slot, the receipt carries the header and the envelope and the artifact travels
  # through `wasm.download`; without one, the prefix is what it has been since W8. Both are
  # the same header — the three lengths are stated either way — so a client appends what it
  # was given in the order the format already fixed.
  defp prefix(signed, artifact_bytes, nil), do: Bundle.prefix(signed, artifact_bytes)

  defp prefix(signed, artifact_bytes, _download),
    do: Bundle.prefix_without_artifact(signed, artifact_bytes)

  defp abandon(nil, _opts), do: :ok
  defp abandon(%{download: id}, opts), do: Download.release(id, download_opts(opts))

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
         {:ok, %{artifact: artifact, bytes: bytes, precompiled: precompiled}} <-
           Bundle.decode(bundle) do
      artifact
      # W8. The second form travels as an option rather than as a positional, because a rollout
      # of a manifest that declares none is exactly the rollout lane W has always run: the
      # option is absent, `stage/3` publishes and compiles the source, and nothing about the
      # four gates changes.
      |> Rollout.deploy(bytes, nodes, Keyword.put(rollout_opts(opts), :precompiled, precompiled))
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

  @doc """
  The largest precompiled artifact this verb will put **in one reply** (W8, M9; W19, D28).

  Derived from the gateway's own configured frame ceiling — `OUROBOROS_GATEWAY_MAX_FRAME`, the
  number an operator already sets for this socket — rather than invented here. The artifact
  travels base64 at four bytes to three, so three quarters of a frame decoded is about one
  frame encoded: an operator who raises the frame raises this, in one place, and the default
  1 MiB frame carries 786 432 bytes of artifact, three times the reference guest's.

  Since W19 this is a *routing* number and no longer a ceiling on what may be signed. Below it
  the artifact rides in the receipt's prefix; above it the artifact is minted into an
  `Ouroboros.Wasm.Download` slot and the receipt names it. Nothing is dropped either way, and
  what bounds the artifact itself is `Ouroboros.Wasm.Bundle.max_precompiled_bytes/0`, which is
  the ceiling on what a bundle could carry at all.
  """
  @spec max_receipt_precompiled_bytes() :: pos_integer()
  def max_receipt_precompiled_bytes, do: max(div(gateway_max_frame() * 3, 4), 1)

  defp gateway_max_frame do
    with settings when is_list(settings) <- Application.get_env(:ouroboros, :gateway, []),
         bytes when is_integer(bytes) and bytes > 0 <- Keyword.get(settings, :max_frame) do
      bytes
    else
      _unset_or_invalid -> @default_gateway_max_frame
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

  # W8, D15/D23. The admission: the rate limit charged and the policy applied to the manifest
  # this node has *not yet* compiled for. It is a separate round trip rather than a flag,
  # because what it buys is an ordering — nothing this node does on a requester's behalf that
  # costs a core is upstream of the limiter that decides whether the requester may ask.
  defp admit(server, artifact, signer_id, bytes) do
    request = %{
      requester: node(),
      payload: Artifact.signing_payload(artifact, signer_id),
      component_bytes: bytes
    }

    case call(server, :admit, [artifact, signer_id, request], signing_timeout()) do
      {:ok, %{artifact_id: id}} when is_binary(id) -> {:ok, id}
      {:refused, reason} -> {:error, {:signing_refused, reason}}
      {:error, reason} -> {:error, {:signing_service_unavailable, reason}}
      other -> {:error, {:signing_refused, describe(other)}}
    end
  end

  defp issue(server, artifact, signer_id, bytes, ticket) do
    request = %{
      requester: node(),
      # Advisory and cross-checked, exactly as `Ouroboros.Upgrade.Forge.Signer.Remote`
      # sends it: the service signs its own derivation and a disagreement is version skew
      # worth stopping at.
      payload: Artifact.signing_payload(artifact, signer_id),
      component_bytes: bytes,
      # The ticket the admission issued. It spends no second rate-limit slot, and it is
      # honoured only for the requester it was issued to and a manifest whose source half is
      # byte-identical to the admitted one; anything else pays the limiter again.
      admission: ticket
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

  ## Precompiling (W8, D23)

  # Runs this node's own helper over the uploaded bytes and answers the triple the signing path
  # needs: the artifact's bytes for the bundle, the block for the manifest, and — when there is
  # no artifact — the reason, so a receipt can say why rather than leave an operator to notice
  # an absence.
  #
  # Never an error. Every failure here is a fallback: the source form is what every node could
  # always run, so a helper that is missing, refuses, or does not answer costs the fleet a
  # compile per node and nothing else. A refusal that *is* about the component — a shape past
  # §7.3's bounds, a component that is not in its world — is still only a skip here, because the
  # loading node makes exactly that refusal again at stage and is the node entitled to make it.
  defp precompile(bytes, attrs, opts) do
    if Map.get(attrs, :precompile, true) == true do
      case helper(opts) do
        {:ok, helper} -> run_precompile(helper, bytes, kind(attrs), opts)
        {:error, reason} -> {nil, nil, reason}
      end
    else
      {nil, nil, :not_requested}
    end
  end

  defp helper(opts) do
    path = Keyword.get_lazy(opts, :helper_path, &Wasm.helper_path/0)

    if is_binary(path) and path != "" and File.regular?(path),
      do: {:ok, path},
      else: {:error, :no_helper}
  end

  defp run_precompile(helper, bytes, kind, opts) do
    case scratch_dir(opts) do
      {:ok, dir} -> compile_in(dir, helper, bytes, kind, opts)
      {:error, reason} -> {nil, nil, reason}
    end
  end

  # One signature, one directory, and the shared root is not in the policy at all (W16 fix
  # wave). The first cut wrote `sign-<tag>.wasm` and its `.cwasm` straight into
  # `<data_dir>/wasm/sign/` and made that whole root writable, which a review walked through:
  # a wrapped helper listed the root, read a **concurrent** signature's source — a client's
  # uploaded component — and overwrote a concurrent signature's artifact, which is the file the
  # next signature is then issued over. Both are gone: this directory holds the source, the
  # output and the child's `$TMPDIR`, it is the only writable root, and the root above it is
  # neither readable nor writable.
  defp compile_in(dir, helper, bytes, kind, opts) do
    run = Path.join(dir, "sign-" <> tag())

    try do
      with {:ok, run} <- private_dir(run),
           source = Path.join(run, "component.wasm"),
           out = Path.join(run, "component.cwasm"),
           {:ok, source} <- write_scratch(source, bytes),
           {:ok, report} <- invoke_helper(helper, source, out, kind, opts),
           {:ok, artifact} <- read_artifact(out) do
        block(report, artifact)
      else
        {:error, reason} -> {nil, nil, reason}
      end
    after
      # The whole directory, on every path. The component is bytes a client uploaded and the
      # artifact is several times its size; leaving either behind after a signature would be
      # this node accumulating other people's components on disk, unbounded, forever.
      _ = File.rm_rf(run)
    end
  end

  # 0700 and `lstat`-verified, the same discipline `scratch_dir/1` applies to the root above
  # it: this directory holds a client's uploaded bytes and the machine code compiled from them,
  # and it is the one place the wrapped helper may write.
  defp private_dir(path) do
    with :ok <- File.mkdir_p(path),
         :ok <- File.chmod(path, 0o700),
         {:ok, %File.Stat{type: :directory}} <- File.lstat(path) do
      {:ok, path}
    else
      {:ok, %File.Stat{type: type}} -> {:error, {:precompile_scratch, {:not_a_directory, type}}}
      {:error, reason} -> {:error, {:precompile_scratch, reason}}
    end
  end

  # 0600, and written where only this node can read it. The component is a client's upload and
  # the artifact is compiled from it, so both are somebody else's bytes: a default-umask file
  # is world-readable and a directory this process merely `mkdir_p`s under a shared `/tmp` is a
  # directory somebody else may have created, or symlinked, first. `Ouroboros.Wasm.Upload`'s
  # discipline, verbatim.
  defp write_scratch(source, bytes) do
    with :ok <- File.write(source, bytes),
         :ok <- File.chmod(source, 0o600) do
      {:ok, source}
    else
      {:error, reason} -> {:error, {:precompile_scratch, reason}}
    end
  end

  # `System.cmd/3` in a task this process can stop waiting on. The task's death does not kill
  # the OS process — nothing in the BEAM can — and that is stated rather than papered over: what
  # bounds the compile is §7.3's structural pass, which refuses an expensive shape before
  # cranelift starts precisely because cranelift cannot be interrupted afterwards. The timeout
  # bounds this *signature*, so a wedged helper costs one fallback rather than one hung verb.
  #
  # W16: what is spawned is the *wrapped* command, so the same fence a node's own helper runs
  # behind is around the signer's. The child's private `$TMPDIR` goes with the child.
  defp invoke_helper(helper, source, out, kind, opts) do
    case precompile_command(helper, source, out, kind, opts) do
      {:ok, %{executable: executable, args: args, env: env, scratch: scratch}} ->
        try do
          await_helper(executable, args, env, opts)
        after
          _ = if is_binary(scratch), do: File.rm_rf(scratch)
        end

      {:error, _reason} = error ->
        error
    end
  end

  defp await_helper(executable, args, env, opts) do
    timeout = Keyword.get(opts, :precompile_timeout, @precompile_timeout_ms)

    task = Task.async(fn -> System.cmd(executable, args, env: env, stderr_to_stdout: false) end)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, {stdout, 0}} -> decode_report(stdout)
      {:ok, {_stdout, status}} -> {:error, {:precompile_refused, status}}
      _no_answer -> {:error, :precompile_timeout}
    end
  rescue
    error -> {:error, {:precompile_failed, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:precompile_failed, "#{kind}: #{describe(reason)}"}}
  end

  # The command to spawn, and whether this node is willing to spawn it at all (W16, D25).
  #
  # The policy is the helper's own — `Sandbox.helper_policy/1`, `mode: :builder`, closed on
  # reads — with the sign scratch as the one writable root and the helper's directory as the
  # one readable root beyond the platform's. What that fences is the case D24 names from the
  # other end: the bytes here are a client's upload on their way into a compiler, and a
  # compiler that can read the node cannot be aimed at it.
  #
  # `:required` is the default and it refuses rather than degrades: no backend, a backend with
  # no read allow-set (contract C11), or no scratch this node will use, and the signature goes
  # out over the source form with the reason in `precompile_skipped`.
  defp precompile_command(helper, source, out, kind, opts) do
    argv = [helper, "precompile", source, out, "--kind", Atom.to_string(kind)]

    case sandbox_setting(opts) do
      :off ->
        {:ok, %{executable: helper, args: tl(argv), env: [], scratch: nil}}

      :required ->
        # `Path.dirname(source)` is **this signature's own** directory, not the shared sign
        # root: it is what `compile_in/5` made for this one compile and what it removes after.
        wrapped_precompile(argv, Path.dirname(helper), Path.dirname(source), Sandbox.detect())
    end
  end

  defp sandbox_setting(opts) do
    case Keyword.get(opts, :helper_sandbox) do
      posture when posture in [:required, :off] -> posture
      _absent -> Wasm.helper_sandbox()
    end
  end

  defp wrapped_precompile(argv, helper_dir, scratch_root, detection) do
    cond do
      detection.backend == :none ->
        {:error, {:helper_sandbox_unavailable, :no_backend}}

      not Sandbox.fences_reads?(detection) ->
        {:error, {:helper_sandbox_unavailable, {:cannot_fence_reads, detection.backend}}}

      true ->
        wrap_precompile(argv, helper_dir, scratch_root, detection)
    end
  end

  # `run` is this signature's own directory — created 0700 and `lstat`-verified by
  # `compile_in/5`, holding the source, the output and nothing else — and it is the **only**
  # writable root. `$TMPDIR` is a directory below it, because bubblewrap mounts a `--tmpfs` at
  # the scratch and a tmpfs over `run` itself would hide the source this node just wrote.
  defp wrap_precompile(argv, helper_dir, run, detection) do
    scratch = Path.join(run, "tmp")

    with :ok <- File.mkdir_p(scratch),
         :ok <- File.chmod(scratch, 0o700),
         {:ok, %File.Stat{type: :directory}} <- File.lstat(scratch) do
      # As named: `Sandbox.helper_policy/1` keeps every root under both its spellings, the
      # canonical one for a backend that matches the path the kernel resolves (`/var/folders`
      # is `/private/var/folders` on macOS by the time `open` sees it) and the named one for
      # bubblewrap, which binds only what it is told and is about to `execvp` the helper by
      # the path in `argv` — through `_build/…/priv` where that is a symlink.
      policy =
        Sandbox.helper_policy(
          readable: [helper_dir],
          writable: [run],
          scratch: canonical(scratch)
        )

      case Sandbox.wrap({:argv, argv}, %{}, policy, detection) do
        {:ok, {executable, args}} ->
          {:ok, %{executable: executable, args: args, env: Sandbox.env(policy), scratch: scratch}}

        {:error, reason} ->
          _ = File.rm_rf(scratch)
          {:error, {:helper_sandbox_unavailable, reason}}
      end
    else
      {:ok, %File.Stat{type: type}} ->
        {:error, {:helper_sandbox_unavailable, {:scratch_not_a_directory, type}}}

      {:error, reason} ->
        {:error, {:helper_sandbox_unavailable, {:scratch_unavailable, reason}}}
    end
  end

  defp tag, do: Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

  defp canonical(path) do
    case Ouroboros.Workspace.Path.canonicalize(path) do
      {:ok, canonical} -> canonical
      {:error, _absent} -> Path.expand(path)
    end
  end

  # The helper reports what it produced, including the wasmtime and the triple it really used.
  # Read from the report rather than from this node's configuration for that reason: what binds
  # an artifact is the build that made it, and a manifest recording what somebody believed the
  # helper was would be a manifest that could be wrong.
  defp decode_report(stdout) do
    case JSON.decode(stdout) do
      {:ok, %{"precompiled" => %{"wasmtime" => wasmtime, "target" => target, "sha256" => sha}}}
      when is_binary(wasmtime) and is_binary(target) and is_binary(sha) ->
        {:ok, %{wasmtime: wasmtime, target: target, sha256: sha}}

      _unreadable ->
        {:error, :precompile_unreadable}
    end
  rescue
    _error -> {:error, :precompile_unreadable}
  end

  # W19. The bound here is what a *bundle* may carry, not what one reply may carry: the reply's
  # own number decides how the artifact travels (see `staged/4`), and holding the read to it
  # would be this node refusing to compile something it is perfectly able to hand over. A
  # helper that wrote more than `Bundle.max_precompiled_bytes/0` wrote a file no bundle could
  # hold, and that is still a skip.
  defp read_artifact(path) do
    case File.stat(path) do
      {:ok, %{type: :regular, size: size}} when size > 0 ->
        cap = Bundle.max_precompiled_bytes()

        if size > cap,
          do: {:error, {:artifact_too_large, size, cap}},
          else: read_bounded(path)

      _absent_or_odd ->
        {:error, :precompile_missing}
    end
  end

  defp read_bounded(path) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, reason} -> {:error, {:precompile_unreadable, reason}}
    end
  end

  # The block the manifest carries, with the size taken from the bytes in hand and the digest
  # recomputed from them rather than read out of the helper's report: this node is about to sign
  # a statement that these exact bytes may be deserialized somewhere else, and taking a
  # subprocess's word for the digest would make the signature cover a number instead of a file.
  defp block(report, artifact) do
    digest = Artifact.digest(artifact)

    if digest == report.sha256 do
      {artifact, Map.merge(report, %{sha256: digest, size: byte_size(artifact)}), nil}
    else
      {nil, nil, {:precompile_digest_disagreement, report.sha256, digest}}
    end
  end

  # This node's own scratch, under its own data directory and never under a shared `/tmp`.
  #
  # `System.tmp_dir!()` is a directory every account on the machine can write to, so a root this
  # process creates with `mkdir_p` may already exist, owned by somebody else, or be a symlink
  # into a directory they control — and what would then be written into it is every component a
  # client uploads and the machine code compiled from it. So the root lives at
  # `<data_dir>/wasm/sign/`, is created 0700, and is **verified** with `lstat` to be a real
  # directory this process owns rather than a link; a node with no data directory does not
  # precompile at all, which is the same posture `Ouroboros.Wasm.Store` takes and for the same
  # reason: a store under `/tmp` is one that quietly is not one.
  defp scratch_dir(opts) do
    with {:ok, root} <- scratch_root(opts),
         :ok <- File.mkdir_p(root),
         _ = File.chmod(root, 0o700),
         {:ok, %File.Stat{type: :directory}} <- File.lstat(root) do
      {:ok, root}
    else
      {:error, :no_data_dir} -> {:error, :no_data_dir}
      {:ok, %File.Stat{type: type}} -> {:error, {:precompile_scratch, {:not_a_directory, type}}}
      {:error, reason} -> {:error, {:precompile_scratch, reason}}
    end
  end

  defp scratch_root(opts) do
    case Keyword.get(opts, :scratch_root) do
      dir when is_binary(dir) and dir != "" ->
        {:ok, dir}

      _unset ->
        case Application.get_env(:ouroboros, :data_dir) do
          dir when is_binary(dir) and dir != "" -> {:ok, Path.join([dir, "wasm", "sign"])}
          _unset -> {:error, :no_data_dir}
        end
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

  defp receipt(artifact, prefix, skipped, download) do
    %{
      # W8, M9. Which form the client is holding, said outright rather than inferred from an
      # absence: `precompiled` when the bundle carries both, `source` when it carries one, with
      # `precompile_skipped` naming why. A client that had to deduce it from a null would be a
      # client guessing at what its own file is.
      form: if(artifact.precompiled, do: :precompiled, else: :source),
      precompiled: artifact.precompiled,
      # Rendered here rather than sent as a term: this crosses `:erpc` to a gateway task and
      # then a JSON encoder, and a reason is a diagnostic line an operator reads — `no_helper`,
      # `{:artifact_too_large, 11092495, 4194304}` — never a value a client branches on.
      precompile_skipped: skip_reason(skipped),
      # W19, D28. Where the artifact did not fit this reply: the slot that holds it, its size,
      # its digest, and the chunk this node will answer with. `nil` is a client with nothing to
      # fetch, because the prefix already carries the artifact — which is the ordinary case and
      # every case there was before W19. The digest is the one the signed manifest names, so a
      # client that reassembles to something else has been handed something else.
      artifact: download,
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
      # Three parts since W19, and the third is zero in every case that is not a download. It
      # is what the file will weigh once the client has both halves, which is the only
      # arithmetic a client does about a format it does not otherwise implement.
      bundle_bytes: byte_size(prefix) + downloadable(download) + artifact.size
    }
  end

  defp downloadable(nil), do: 0
  defp downloadable(%{size: size}), do: size

  defp skip_reason(nil), do: nil
  defp skip_reason(reason), do: describe(reason)

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
    do:
      Keyword.take(opts, [
        :registry,
        :pool,
        :store_root,
        :trust_policy,
        :start?,
        :limits,
        :precompiled
      ])

  defp upload_opts(opts) do
    case Keyword.get(opts, :upload_root) do
      root when is_binary(root) and root != "" -> [root: root]
      _unset -> []
    end
  end

  defp download_opts(opts) do
    case Keyword.get(opts, :download_root) do
      root when is_binary(root) and root != "" -> [root: root]
      _unset -> []
    end
  end

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
