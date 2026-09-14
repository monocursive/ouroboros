defmodule Ouroboros.Runtime.SafeStatus do
  @moduledoc """
  Closed, bounded projection of status facts supplied by an owning runtime plane.

  `session/2` is deliberately not an authorization API. `Interactive.Task` owns the session,
  constructs the typed facts, and the authenticated gateway routes to that owner. Arbitrary
  caller maps never reach this function through a supported surface. Unknown, stale, malformed,
  or incoherent facts are suppressed rather than guessed.
  """

  @max_string_bytes 128
  @max_credentials 8
  @max_output_bytes 16_384
  @max_age_ms 60_000
  @max_integer 9_223_372_036_854_775_807
  @providers ~w(openai openai_codex anthropic xai grok google gemini mistral groq together openrouter ollama)
  @credential_sources %{
    environment: "environment",
    file: "file",
    stored: "managed",
    managed: "managed",
    process: "process",
    none: "none"
  }

  @doc "Immutable public bounds."
  def limits,
    do: %{
      string_bytes: @max_string_bytes,
      credential_entries: @max_credentials,
      output_bytes: @max_output_bytes,
      default_max_age_ms: @max_age_ms
    }

  @doc "Projects a session owner's facts at a bounded monotonic timestamp."
  @spec session(map(), integer()) :: {:ok, map()} | {:error, atom()}
  def session(facts, now_ms)
      when is_map(facts) and is_integer(now_ms) and now_ms >= -@max_integer and
             now_ms <= @max_integer do
    owner = identifier(facts[:owner])
    observed = timestamp(facts[:observed_at_ms])
    freshness = freshness(observed, now_ms)
    current? = freshness == "fresh"
    identity = identity(facts[:identity], current?)
    listener = listener(facts[:listener], identity, now_ms, current?)

    status = %{
      "version" => 1,
      "scope" => "session",
      "owner" => owner,
      "observed_at_ms" => observed,
      "freshness" => freshness,
      "provenance" => "interactive_owner",
      "identity" => identity,
      "listener" => listener,
      "activity" => activity(facts[:activity], current?),
      "posture" => posture(facts[:posture], current?),
      "deadlines" => deadlines(facts[:deadlines], current?),
      "credentials" => credentials(facts[:credentials], current?)
    }

    cond do
      is_nil(owner) -> {:error, :invalid_authoritative_status}
      byte_size(JSON.encode!(status)) > @max_output_bytes -> {:error, :status_too_large}
      true -> {:ok, status}
    end
  end

  def session(_facts, _now_ms), do: {:error, :invalid_observation_time}

  @doc "Compatibility projection for the original isolated slice; only checks consistency."
  def project(facts, access) when is_map(facts) and is_map(access) do
    cond do
      facts[:scope] != :session or access[:scope] != :session -> {:error, :scope_refused}
      identifier(facts[:owner]) != identifier(access[:owner]) -> {:error, :ownership_refused}
      true -> session(facts, access[:now_ms])
    end
  end

  def project(_, _), do: {:error, :scope_refused}

  defp identity(value, true) when is_map(value) do
    %{
      "logical_id" => identifier(value[:logical_id]),
      "native_id" => identifier(value[:native_id]),
      "runtime_id" => identifier(value[:runtime_id]),
      "generation" => identifier(value[:generation]),
      "pid" => integer(value[:pid]),
      "port" => port(value[:port]),
      "birth" => birth(value[:birth])
    }
  end

  defp identity(_, _),
    do: %{
      "logical_id" => nil,
      "native_id" => nil,
      "runtime_id" => nil,
      "generation" => nil,
      "pid" => nil,
      "port" => nil,
      "birth" => nil
    }

  defp listener(value, identity, now_ms, true) when is_map(value) do
    listener_freshness = freshness(timestamp(value[:observed_at_ms]), now_ms)

    coherent? =
      listener_freshness == "fresh" and value[:port] == identity["port"] and
        value[:birth] == identity["birth"] and identity["port"] != nil and
        identity["birth"] != nil

    %{
      "publication" =>
        if(coherent? and value[:publication] == :available, do: "available", else: "unavailable"),
      "freshness" => listener_freshness,
      "port" => if(coherent?, do: identity["port"]),
      "birth" => if(coherent?, do: identity["birth"])
    }
  end

  defp listener(_, _, _, _),
    do: %{"publication" => "unavailable", "freshness" => "unknown", "port" => nil, "birth" => nil}

  defp activity(value, true) when is_map(value),
    do: %{
      "owner_active" => boolean(value[:owner_active]),
      "turn_id" => identifier(value[:turn_id])
    }

  defp activity(_, _), do: %{"owner_active" => nil, "turn_id" => nil}

  defp posture(value, true) when is_map(value) do
    %{
      "sandbox" => enum(value[:sandbox], [:read_only, :workspace_write, :unrestricted]),
      "approval" => enum(value[:approval], [:default, :prompt, :auto_edit, :auto_approve])
    }
  end

  defp posture(_, _), do: %{"sandbox" => "unavailable", "approval" => "unavailable"}

  defp deadlines(value, true) when is_map(value),
    do: %{
      "requested_ms" => integer(value[:requested_ms]),
      "effective_ms" => integer(value[:effective_ms])
    }

  defp deadlines(_, _), do: %{"requested_ms" => nil, "effective_ms" => nil}

  defp credentials(values, true) when is_list(values) do
    values
    |> Enum.reduce(%{}, fn
      row, acc when is_map(row) ->
        provider = provider(row[:provider])

        if provider && not Map.has_key?(acc, provider) do
          projected = %{
            "provider" => provider,
            "present" =>
              if(
                Map.has_key?(row, :credential_state) and
                  row[:credential_state] not in [:present, :absent],
                do: nil,
                else: boolean(row[:present])
              ),
            "source" => Map.get(@credential_sources, row[:source], "unavailable")
          }

          projected =
            if Map.has_key?(row, :credential_state),
              do:
                Map.put(
                  projected,
                  "credential_state",
                  enum(row[:credential_state], [:present, :absent, :invalid, :unavailable])
                ),
              else: projected

          Map.put(acc, provider, projected)
        else
          acc
        end

      _, acc ->
        acc
    end)
    |> Map.values()
    |> Enum.sort_by(& &1["provider"])
    |> Enum.take(@max_credentials)
  end

  defp credentials(_, _), do: []

  defp freshness(nil, _), do: "unknown"
  defp freshness(observed, now) when observed > now, do: "stale"
  defp freshness(observed, now), do: if(now - observed <= @max_age_ms, do: "fresh", else: "stale")

  defp timestamp(value)
       when is_integer(value) and value >= -@max_integer and value <= @max_integer,
       do: value

  defp timestamp(_), do: nil

  defp identifier(value) when is_binary(value) and byte_size(value) <= @max_string_bytes do
    if String.valid?(value) and Regex.match?(~r/\A[A-Za-z0-9][A-Za-z0-9._:@-]*\z/, value),
      do: value
  end

  defp identifier(_), do: nil
  defp birth("macos:" <> _ = value), do: identifier(value)
  defp birth("linux:" <> _ = value), do: identifier(value)
  defp birth(_), do: nil
  defp provider(value) when is_atom(value), do: provider(Atom.to_string(value))
  defp provider(value) when value in @providers, do: value
  defp provider(_), do: nil
  defp integer(value) when is_integer(value) and value >= 0 and value <= @max_integer, do: value
  defp integer(_), do: nil
  defp port(value) when is_integer(value) and value in 1..65_535, do: value
  defp port(_), do: nil
  defp boolean(value) when is_boolean(value), do: value
  defp boolean(_), do: nil

  defp enum(value, allowed),
    do: if(value in allowed, do: Atom.to_string(value), else: "unavailable")
end
