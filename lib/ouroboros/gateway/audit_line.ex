defmodule Ouroboros.Gateway.AuditLine do
  @moduledoc """
  What the one audit line per operate call is allowed to say about its parameters.

  Both operator surfaces write that line — `Ouroboros.Gateway.Conn` for a listener and
  `Ouroboros.Web.Call` for a browser — and until now both computed the same SHA-256 digest
  from their own copy of the same four lines. Two copies of a redaction rule is one rule and
  one bug waiting for somebody to edit the copy they were looking at, so the rule lives here
  and both surfaces call it.

  ## The digest is the default, and it has exactly one exception

  For every method, the line names the call and not its contents: an objective, a prompt or a
  workspace path in a log is a payload the operator did not choose to write down, and the
  first sixteen hex characters of the digest are enough to correlate a log entry with a
  request a client can reproduce.

  `fleet.deployment.authenticate` is the exception, and it is the only one. Its parameters
  carry an SSH password or key passphrase, and the spec's "Secret handling and authorization"
  section names `Web.Call` and gateway parameter digests in the list of places a secret may
  never appear — *"even hashed"*. A hash of a low-entropy human password is not a redaction;
  it is the password in a form somebody can look up. So for that one method this never
  hashes: it writes the operation and the challenge, which are the allowlisted metadata, and
  the secret is not an argument to any function on that path.

  ## How that is proved rather than asserted

  `digest/1` emits `[:ouroboros, :gateway, :audit, :digest]` before it returns. A test
  attaches to that event, drives the authenticate path with a unique secret, and asserts both
  that no digest event names that method and that no emitted digest equals the digest of the
  parameters that carried the secret. That is instrumentation on the hashing function itself
  rather than a search of the log for plaintext, which is what acceptance item 16 asks for:
  grepping for the secret proves only that this particular encoding of it is absent.
  """

  alias Ouroboros.Gateway.Wire

  # method => the parameter keys its line may name. Anything else about the call is dropped,
  # and the digest is never computed for it.
  @redacted %{"fleet.deployment.authenticate" => ["operation_id", "challenge"]}

  @doc "Whether this method's parameters bypass the digest entirely."
  @spec redacted?(String.t()) :: boolean()
  def redacted?(method) when is_binary(method), do: Map.has_key?(@redacted, method)

  @doc "Every method whose parameters are redacted, for the documentation and the tests."
  @spec redacted() :: [String.t()]
  def redacted, do: @redacted |> Map.keys() |> Enum.sort()

  @doc """
  The `params=` field of one audit line.

  Returns the digest for an ordinary method, and for a redacted one a `redacted` marker
  followed by that method's allowlisted keys.
  """
  @spec params(String.t(), map()) :: iodata()
  def params(method, params) when is_binary(method) and is_map(params) do
    case Map.fetch(@redacted, method) do
      {:ok, allowlist} -> allowlisted(allowlist, params)
      :error -> digest(params, method)
    end
  end

  defp allowlisted(allowlist, params) do
    [
      "redacted",
      Enum.map(allowlist, fn key ->
        [" ", key, "=", params |> Map.get(key) |> scalar()]
      end)
    ]
  end

  # Only a scalar a challenge or an operation id can be. Anything else is named as its shape
  # rather than printed: an allowlisted key whose value is unexpectedly an object must not
  # become a way to get arbitrary parameters into the log.
  defp scalar(value) when is_binary(value), do: String.slice(value, 0, 128)
  defp scalar(value) when is_integer(value), do: Integer.to_string(value)
  defp scalar(nil), do: "absent"
  defp scalar(_other), do: "unreadable"

  @doc """
  The gateway's parameter digest: SHA-256 over the Wire encoding, first sixteen hex characters.

  Public because `params/2` is not the only thing that must be able to reach it — the test
  that proves a secret never arrives here computes the digest the redacted path would have
  produced and asserts it was never emitted.
  """
  @spec digest(map(), String.t() | nil) :: binary()
  def digest(params, method \\ nil) when is_map(params) do
    encoded = params |> Wire.to_json() |> JSON.encode_to_iodata!()

    digest =
      :sha256
      |> :crypto.hash(encoded)
      |> Base.encode16(case: :lower)
      |> binary_part(0, 16)

    :telemetry.execute(
      [:ouroboros, :gateway, :audit, :digest],
      %{bytes: IO.iodata_length(encoded)},
      %{digest: digest, method: method}
    )

    digest
  end
end
