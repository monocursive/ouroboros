defmodule Ouroboros.ProcessEnvironment do
  @moduledoc """
  Explicit child-process inheritance. Consumers own their allowlists; this module owns
  credential filtering and Port.open's unset semantics. Explicit overrides must also
  pass `sensitive?/2` before crossing the process boundary.
  """

  @sensitive_env_name ~r/(^|_)(AUTH|AUTHORIZATION|COOKIE|CREDENTIALS?|DATABASE_URL|DB_URL|DSN|MONGODB_URI|MONGO_URL|AMQP_URL|BROKER_URL|PASSWORD|PASSWD|PASSPHRASE|PRIVATE_?KEY|ACCESS_?KEY|API_?KEY|SECRET|TOKEN)($|_)/i
  @credential_uri ~r{[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@}i
  @credential_assignment ~r/(^|[^a-zA-Z0-9])(?:authorization|credential|password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*[^\s;&]+/i
  @erlang_cookie_flag ~r/(^|\s)-?setcookie(?:\s+|=)\S+/i
  @private_key ~r/-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/

  def select(environment, names, prefixes \\ []) do
    Map.filter(environment, fn {name, value} ->
      (name in names or Enum.any?(prefixes, &String.starts_with?(name, &1))) and
        not sensitive?(name, value)
    end)
  end

  @doc "Removals for Port.open, whose env option overlays ambient variables."
  def port_unsets(names, environment \\ System.get_env()) do
    allowed = select(environment, names)

    environment
    |> Enum.reject(fn {name, _value} -> Map.has_key?(allowed, name) end)
    |> Enum.map(fn {name, _value} -> {String.to_charlist(name), false} end)
  end

  def sensitive?(name, value) do
    normalized_name = String.replace(name, ~r/[^a-zA-Z0-9]+/, "_")

    Regex.match?(@sensitive_env_name, normalized_name) or
      Regex.match?(@credential_uri, value) or
      Regex.match?(@credential_assignment, value) or
      Regex.match?(@erlang_cookie_flag, value) or
      Regex.match?(@private_key, value)
  end
end
