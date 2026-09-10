defmodule Ouroboros.Upgrade.Signing.Signature do
  @moduledoc """
  The Ed25519 check a loading node runs against a trusted-signer map.

  `Ouroboros.Upgrade.Signing.Service` decides what may exist; this decides whether the
  statement it made is the one in front of a node about to run the bytes. It lives beside
  the service rather than inside a verifier because it is the half both sides share: one
  key format, one trusted-signer map, one set of refusal names, and exactly one copy of
  the crypto.

  `Ouroboros.Wasm.Verifier` derives lane W's payload with lane W's tag and then asks this
  function. Nothing here parses a manifest, and nothing here knows what a payload
  describes.
  """

  @doc """
  Checks a detached Ed25519 signature over `payload` against a trusted-signer map.

  `trusted_signers` is the `:trusted_signers` map from the trust policy: signer id to raw
  32-byte public key, as `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` parses into at boot. An
  unknown signer, a key of the wrong size, and a signature that does not verify are three
  different, named refusals.
  """
  @spec verify_payload(binary(), String.t(), binary(), map()) :: :ok | {:error, term()}
  def verify_payload(payload, signer, signature, trusted_signers)
      when is_binary(payload) and is_binary(signer) and is_binary(signature) and
             is_map(trusted_signers) do
    case Map.fetch(trusted_signers, signer) do
      {:ok, public_key} when is_binary(public_key) and byte_size(public_key) == 32 ->
        try do
          if :crypto.verify(:eddsa, :none, payload, signature, [public_key, :ed25519]) do
            :ok
          else
            {:error, {:invalid_signature, signer}}
          end
        rescue
          _error -> {:error, {:invalid_signature, signer}}
        catch
          _kind, _reason -> {:error, {:invalid_signature, signer}}
        end

      {:ok, _invalid_key} ->
        {:error, {:invalid_signer_key, signer}}

      :error ->
        {:error, {:untrusted_signer, signer}}
    end
  end

  def verify_payload(_payload, signer, _signature, _trusted_signers)
      when is_binary(signer),
      do: {:error, {:invalid_signature, signer}}

  def verify_payload(_payload, _signer, _signature, _trusted_signers),
    do: {:error, :invalid_signature_envelope}
end
