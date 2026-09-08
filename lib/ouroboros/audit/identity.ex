defmodule Ouroboros.Audit.Identity do
  @moduledoc "Verified node-configured identities and revocable roles shared by web and gateway."
  alias Ouroboros.Audit.Config
  @key {__MODULE__, :subject}

  def current, do: Process.get(@key)
  def install(subject), do: Process.put(@key, subject)

  def with_subject(subject, function) do
    previous = current()
    install(subject)

    try do
      function.()
    after
      install(previous)
    end
  end

  def authenticate(token, local_token) when is_binary(token) do
    config = Config.current()
    digest = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

    identity =
      Enum.find(config.identities, fn identity ->
        candidate = identity["token_sha256"]
        is_binary(candidate) and secure_equal?(candidate, digest) and active?(identity)
      end)

    cond do
      identity ->
        {:ok, Map.take(identity, ["id", "token_sha256"])}

      config.identities == [] and not Config.required?(config) and
          secure_equal?(token, local_token) ->
        {:ok, %{"id" => "local-owner", "local" => true}}

      true ->
        {:error, :unauthenticated}
    end
  end

  def authenticate(_, _), do: {:error, :unauthenticated}

  def resolve(%{"local" => true, "id" => "local-owner"}) do
    config = Config.current()

    if config.identities == [] and not Config.required?(config),
      do: {:ok, %{"id" => "local-owner", "roles" => ["administrator"]}},
      else: {:error, :identity_revoked}
  end

  def resolve(%{"id" => id, "token_sha256" => hash}) do
    case Enum.find(
           Config.current().identities,
           &(&1["id"] == id and &1["token_sha256"] == hash and active?(&1))
         ) do
      nil -> {:error, :identity_revoked}
      identity -> {:ok, Map.take(identity, ["id", "roles"])}
    end
  end

  def resolve(_), do: {:error, :identity_required}

  def permits?(subject, method, scope) do
    if not Config.enabled?() and Config.current().identities == [] do
      true
    else
      case resolve(subject) do
        {:ok, %{"roles" => roles}} ->
          "administrator" in roles or required_role(method, scope) in roles

        _ ->
          false
      end
    end
  end

  def actor_active?(id) do
    Enum.any?(Config.current().identities, fn identity ->
      identity["id"] == id and active?(identity) and
        Enum.any?(identity["roles"], &(&1 in ["operator", "administrator"]))
    end)
  end

  def actor do
    case resolve(current()) do
      {:ok, %{"id" => id}} -> id
      _ -> "runtime-unattributed"
    end
  end

  defp required_role(method, _scope)
       when method in ["audit.reindex", "audit.flush", "audit.hold", "audit.purge"],
       do: "administrator"

  defp required_role("audit." <> _, _), do: "auditor"

  defp required_role(method, :operate) do
    cond do
      String.contains?(method, ["approval", "approve", "respond"]) ->
        "approver"

      String.starts_with?(method, [
        "audit.purge",
        "audit.hold",
        "permissions.",
        "grants.",
        # `policy.promote` hands a wasm component the authority to answer `allow` for a shape
        # of `bash` on every future request, which is `permissions.add` with a component in
        # place of the pattern. It belongs with the verbs beside it rather than one role below
        # them (S2b review, MEDIUM-1). `policy.status` is `:read` and is unaffected.
        "policy.",
        "credentials.",
        "release.",
        "upgrade.",
        "forge.",
        "wasm.",
        "account."
      ]) ->
        "administrator"

      true ->
        "operator"
    end
  end

  defp required_role(_, :read), do: "operator"

  defp active?(%{"expires_at" => expires}) when is_binary(expires) do
    case DateTime.from_iso8601(expires) do
      {:ok, date, _} -> DateTime.compare(date, DateTime.utc_now()) == :gt
      _ -> false
    end
  end

  defp active?(identity), do: is_nil(identity["expires_at"])

  defp secure_equal?(left, right) when is_binary(left) and is_binary(right),
    do: :crypto.hash_equals(:crypto.hash(:sha256, left), :crypto.hash(:sha256, right))

  defp secure_equal?(_, _), do: false
end
