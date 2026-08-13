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
  """

  @callback sign(payload :: binary(), signer_id :: String.t()) ::
              {:ok, signature :: binary()} | {:error, term()}

  @doc "Returns the configured `{module, options}` signer, defaulting to `Deny`."
  @spec configured() :: {module(), keyword()}
  def configured do
    case Application.get_env(:ouroboros, :forge_signer, __MODULE__.Deny) do
      {module, opts} when is_atom(module) and is_list(opts) -> {module, opts}
      module when is_atom(module) -> {module, []}
      _invalid -> {__MODULE__.Deny, []}
    end
  end
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
