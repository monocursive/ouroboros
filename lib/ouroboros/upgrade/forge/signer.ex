defmodule Ouroboros.Upgrade.Forge.Signer do
  @moduledoc """
  The seam where a forged artifact stops being the agent's and becomes the operator's.

  A signer receives the canonical signing payload of an artifact
  (`Ouroboros.Upgrade.Artifact.signing_payload/2`) and returns a detached Ed25519
  signature, or refuses. It is the only step of the forge that the agent's own code
  cannot supply for itself: `Ouroboros.Upgrade.Forge` never holds a key and never
  constructs a signature, it asks whatever `config :ouroboros, :forge_signer` names.

  The shipped default is `Ouroboros.Upgrade.Forge.Signer.Deny`, which refuses everything.
  An unsigned or unsignable artifact still reaches a production node's verifier, and that
  verifier rejects it, so the failure mode of a missing signer is a refused deployment
  rather than an unreviewed one.

  In production the implementation of this behaviour should be a client of a service
  that holds the key somewhere the patchable application cannot reach — a separate
  least-privileged host, an HSM, or a review queue with a human in it. A signer module
  that reads a key out of this application's own configuration puts the key inside the
  blast radius of the code it is supposed to be authorizing.
  `Ouroboros.Upgrade.Forge.Signer.Remote` is the shipped client of exactly such a
  service: it hands the whole artifact to `Ouroboros.Upgrade.Signing.Service` on a
  `:signer`-role node, which applies its own policy and holds its own key.

  ## Two callbacks, and why

  `sign/2` receives the canonical payload and nothing else. That is all a signer needs to
  produce a signature, and it is deliberately *not* all a signer needs to decide whether
  it should. A payload is a hash of a manifest; a manifest is a set of claims; and a
  signer that can only see the hash has no way to check the claims against the bytes they
  describe. So this behaviour also declares an optional `sign_artifact/2`, which receives
  the whole artifact, and `Ouroboros.Upgrade.Forge` prefers it whenever a signer exports
  it. A signer that implements only `sign/2` is unaffected — `Deny` and `Local` both
  still work exactly as they did.

  Nothing about that choice changes what gets signed. The bytes covered by a signature
  are always `Artifact.signing_payload/2` of the artifact, and an artifact-aware signer
  is expected to derive them itself rather than accept them from its caller.
  """

  @callback sign(payload :: binary(), signer_id :: String.t()) ::
              {:ok, signature :: binary()} | {:error, term()}

  @doc """
  Signs a whole artifact, for signers whose decision depends on more than the payload.

  Preferred by `Ouroboros.Upgrade.Forge` when exported. An implementation must derive the
  payload itself from the artifact it was given; the artifact is the request, not a hint.
  """
  @callback sign_artifact(artifact :: struct(), signer_id :: String.t()) ::
              {:ok, signature :: binary()} | {:error, term()}

  @optional_callbacks sign_artifact: 2

  @doc "Returns the configured `{module, options}` signer, defaulting to `Deny`."
  @spec configured() :: {module(), keyword()}
  def configured do
    case Application.get_env(:ouroboros, :forge_signer, __MODULE__.Deny) do
      {module, opts} when is_atom(module) and is_list(opts) -> {module, opts}
      module when is_atom(module) -> {module, []}
      _invalid -> {__MODULE__.Deny, []}
    end
  end

  @doc """
  Whether `module` decides on whole artifacts rather than on payload bytes alone.

  Loads the module before asking, because `function_exported?/3` on an unloaded module
  answers "no" and would silently demote an artifact-aware signer to the payload path.
  """
  @spec artifact_signer?(module()) :: boolean()
  def artifact_signer?(module) when is_atom(module) do
    Code.ensure_loaded?(module) and function_exported?(module, :sign_artifact, 2)
  end

  def artifact_signer?(_module), do: false
end

defmodule Ouroboros.Upgrade.Forge.Signer.Deny do
  @moduledoc """
  The default signer: it signs nothing.

  Refusing by default is the same posture the durable release lane takes with
  `Ouroboros.Release.Authorizer.Deny`. A deployment that needs a signature must be given
  a signer deliberately, by configuration an operator wrote, and not acquire one because
  a default was convenient.
  """

  @behaviour Ouroboros.Upgrade.Forge.Signer

  @impl true
  def sign(_payload, _signer_id), do: {:error, :signing_denied}
end

defmodule Ouroboros.Upgrade.Forge.Signer.Local do
  @moduledoc """
  An in-VM Ed25519 signer for development and tests.

  The private key comes from this signer's own options, which means it lives in the
  configuration of the application whose code the signature is authorizing. That is
  acceptable for a dev loop and for tests that need a signature the verifier accepts. It
  is not acceptable in production: an agent that can patch this application can read
  anything this application can read, so a key stored here authorizes the agent to
  approve its own code.

  Key custody belongs outside the patchable application. Configure a signer that calls a
  separate signing service instead, and keep `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` naming
  only keys that service holds.

  Configure as `{Ouroboros.Upgrade.Forge.Signer.Local, private_key: <<32 bytes>>}`, or
  call `sign/3` with explicit options.
  """

  @behaviour Ouroboros.Upgrade.Forge.Signer

  @impl true
  def sign(payload, signer_id), do: sign(payload, signer_id, configured_options())

  @doc "Signs with an explicitly supplied key rather than the configured one."
  @spec sign(binary(), String.t(), keyword()) :: {:ok, binary()} | {:error, term()}
  def sign(payload, signer_id, opts)
      when is_binary(payload) and is_binary(signer_id) and is_list(opts) do
    with {:ok, private_key} <- private_key(opts) do
      {:ok, :crypto.sign(:eddsa, :none, payload, [private_key, :ed25519])}
    end
  rescue
    error -> {:error, {:signing_failed, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:signing_failed, {kind, inspect(reason)}}}
  end

  def sign(_payload, _signer_id, _opts), do: {:error, :invalid_signing_request}

  defp private_key(opts) do
    case Keyword.fetch(opts, :private_key) do
      {:ok, key} when is_binary(key) and byte_size(key) == 32 -> {:ok, key}
      {:ok, _key} -> {:error, :invalid_private_key}
      :error -> {:error, :private_key_not_configured}
    end
  end

  defp configured_options do
    case Ouroboros.Upgrade.Forge.Signer.configured() do
      {__MODULE__, opts} -> opts
      _other -> []
    end
  end
end

defmodule Ouroboros.Upgrade.Forge.Signer.Remote do
  @moduledoc """
  The client half of an external signer: hand the artifact to a `:signer` node, keep no key.

  Configure it as

      config :ouroboros, :forge_signer,
        {Ouroboros.Upgrade.Forge.Signer.Remote, node: :"signer-1@10.0.0.30"}

  and the forge's signing stage becomes a bounded `:erpc` into
  `Ouroboros.Upgrade.Signing.Service` on that node. This module holds no key, makes no
  policy decision, and cannot make one: everything that matters happens in the service's
  process, on the service's host, before a signature exists.

  ## What it sends, and what it does not trust

  The **whole artifact**, plus the payload this node derived, plus this node's name. The
  payload is advisory and labelled as such — the service re-derives it with
  `Ouroboros.Upgrade.Artifact.signing_payload/2` and signs only its own derivation. A
  disagreement between the two is a refusal from the service, which is how version skew
  between a core node and its signer surfaces as a stopped deployment rather than as a
  signature over bytes the requester did not expect.

  The requester node is likewise a claim. It is journaled by the service as one.

  ## Refusals are typed, and transport is never a raise

  Before anything is sent, `Ouroboros.Cluster.ensure_role/2` requires the target to be
  connected, running this runtime, and in the `:signer` role — the same check
  `Ouroboros.Upgrade.Forge.BuildPeer` applies to a builder, for the same reason: work
  sent to a node that cannot do it should fail by name rather than by timeout. Every
  outcome after that is a value:

      {:error, {:remote_signer_unconfigured, :node}}      # no node named
      {:error, {:remote_signer_refused, node, reason}}    # wrong role, absent, not running
      {:error, {:remote_signer_unavailable, node, info}}  # transport fault or deadline
      {:error, {:signing_refused, reason}}                # the service applied policy and said no

  `:erpc` exceptions, exits, and throws are converted here. A raise escaping this module
  would reach `Ouroboros.Upgrade.Forge` as `{:signer_failure, ...}` and read like a bug
  in the forge rather than like a signer that could not be reached.

  ## Options

    * `:node` — the `:signer` node. Falls back to `config :ouroboros, :signing_node`.
    * `:timeout` — the signing deadline in milliseconds, defaulting to
      `config :ouroboros, :signing_call_timeout` and then to 15s. The `:erpc` deadline is
      this plus a small slack, so the service's own typed refusal wins the race against
      an opaque transport timeout.

  ## Honest limit

  This narrows key custody to one host; it does not remove the host from the cluster. A
  signer node is a connected member, and any node that completes the distribution
  handshake can call the same service this module calls. What the policy on that host
  refuses, it refuses for everyone — that is the guarantee. Who may ask at all is
  distribution's problem, and distribution's answer is a cookie and, if configured, TLS.
  """

  @behaviour Ouroboros.Upgrade.Forge.Signer

  alias Ouroboros.Cluster
  alias Ouroboros.Upgrade.Artifact
  alias Ouroboros.Upgrade.Signing.Service

  @default_timeout 15_000
  @slack 5_000

  @impl true
  def sign(_payload, _signer_id), do: {:error, :remote_signer_requires_artifact}

  @impl true
  def sign_artifact(artifact, signer_id), do: sign_artifact(artifact, signer_id, options())

  @doc "Signs against an explicitly supplied target rather than the configured one."
  @spec sign_artifact(Artifact.t(), String.t(), keyword()) :: {:ok, binary()} | {:error, term()}
  def sign_artifact(%Artifact{} = artifact, signer_id, opts)
      when is_binary(signer_id) and signer_id != "" and is_list(opts) do
    with {:ok, target} <- target(opts),
         :ok <- ensure_signer(target),
         {:ok, signature} <- submit(target, artifact, signer_id, opts) do
      {:ok, signature}
    end
  end

  def sign_artifact(_artifact, _signer_id, _opts), do: {:error, :invalid_signing_request}

  defp target(opts) do
    configured =
      Keyword.get_lazy(opts, :node, fn -> Application.get_env(:ouroboros, :signing_node) end)

    cond do
      is_nil(configured) -> {:error, {:remote_signer_unconfigured, :node}}
      not is_atom(configured) -> {:error, {:invalid_signer_node, configured}}
      true -> {:ok, configured}
    end
  end

  defp ensure_signer(target) do
    case Cluster.ensure_role(target, :signer) do
      :ok -> :ok
      {:error, reason} -> {:error, {:remote_signer_refused, target, reason}}
    end
  end

  # The payload travels as a cross-check and nothing more; see the moduledoc. The `:erpc`
  # deadline deliberately exceeds the signing deadline so the service's typed answer
  # arrives instead of a transport timeout that says nothing about why.
  defp submit(target, artifact, signer_id, opts) do
    timeout = timeout(opts)

    request = %{
      requester: node(),
      payload: Artifact.signing_payload(artifact, signer_id)
    }

    case :erpc.call(
           target,
           Service,
           :sign_artifact,
           [artifact, signer_id, request],
           timeout + @slack
         ) do
      {:ok, signature} when is_binary(signature) -> {:ok, signature}
      {:ok, other} -> {:error, {:invalid_signature, describe(other)}}
      {:refused, reason} -> {:error, {:signing_refused, reason}}
      other -> {:error, {:invalid_signer_result, describe(other)}}
    end
  catch
    kind, reason -> {:error, {:remote_signer_unavailable, target, {kind, describe(reason)}}}
  end

  defp timeout(opts) do
    configured =
      Keyword.get_lazy(opts, :timeout, fn ->
        Application.get_env(:ouroboros, :signing_call_timeout, @default_timeout)
      end)

    if is_integer(configured) and configured > 0, do: configured, else: @default_timeout
  end

  defp options do
    case Ouroboros.Upgrade.Forge.Signer.configured() do
      {__MODULE__, opts} -> opts
      _other -> []
    end
  end

  # A remote failure can carry pids, ports, and stacktraces. Everything here ends up in a
  # forge error that is journaled and rendered, so it is reduced to text.
  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
