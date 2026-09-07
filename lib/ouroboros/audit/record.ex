defmodule Ouroboros.Audit.Record do
  @moduledoc "Versioned, portable audit records with explicit content availability."
  alias Ouroboros.Provider.Native.Journal

  @content ~w(content system messages request arguments input output stdout stderr chunks chunk text command prompt response result before after)
  @credentials ~w(authorization proxy-authorization api_key api-key access_token refresh_token password secret cookie set-cookie token)

  @metadata ~w(turn_id iteration request_sha256 system_sha256 message_count tools_sha256 ledger_effect_id call_id attempt_id model tool duration_ms is_error status session_id provider_session_id parent_session_id parent_task_id actor_id resumed forked_from_provider_session_id journal_version chunk_index capture_boundary method node workspace cwd sandbox_mode type finish_reason usage input_tokens output_tokens cached_tokens cost cost_currency cost_source bytes offset seq held request_id decision target authority provider_metadata endpoint channel max_bytes max_retries target_stream removed_head removed_through expired_at key count reason_code source read_count write_count audit_policy approval_request_id coverage)

  def content_key?(key), do: key in @content

  def build(fields, kind, stream, seq, prev, config) do
    fields
    |> Journal.jsonable()
    |> retain_fields(config.capture)
    |> capture(config.capture)
    |> Map.merge(%{
      "version" => 2,
      "event_id" => stream <> ":" <> to_string(seq),
      "stream_id" => stream,
      "seq" => seq,
      "kind" => to_string(kind),
      "at" => DateTime.to_iso8601(DateTime.utc_now()),
      "node" => to_string(node()),
      "writer_id" => Ouroboros.Audit.Config.writer_id(config),
      "runtime_version" => to_string(Application.spec(:ouroboros, :vsn) || "unknown"),
      "elixir_version" => System.version(),
      "organization" => config.organization,
      "policy_revision" => Ouroboros.Audit.Config.revision(config),
      "capture" => to_string(config.capture)
    })
    |> Map.drop(["hash", "prev"])
    |> seal(prev)
  end

  defp retain_fields(fields, :metadata) do
    fields
    |> Map.take(@metadata)
    |> restrict_metadata()
    |> Map.merge(
      Map.new(
        Enum.filter(@content, &Map.has_key?(fields, &1)),
        &{&1, %{"withheld" => "metadata_policy"}}
      )
    )
    |> Map.put("unlisted_fields_withheld", map_size(Map.drop(fields, @metadata ++ @content)))
  end

  defp retain_fields(fields, _), do: fields

  defp restrict_metadata(fields) do
    rules = %{
      "authority" => ~w(decision scope actor source kind origin rule_id expires_at),
      "target" => ~w(id session_id stream_id request_id machine),
      "decision" => ~w(decision scope approved option_id),
      "provider_metadata" => ~w(request_id response_id service_tier),
      "endpoint" => ~w(scheme host port)
    }

    Enum.reduce(rules, fields, fn {key, allowed}, fields ->
      case fields[key] do
        value when is_map(value) -> Map.put(fields, key, Map.take(value, allowed))
        nil -> fields
        _ -> Map.put(fields, key, %{"withheld" => "metadata_policy"})
      end
    end)
  end

  def seal(body, prev) do
    hash =
      :crypto.hash(:sha256, [prev, Journal.canonical_json(body)]) |> Base.encode16(case: :lower)

    Map.merge(body, %{"prev" => prev, "hash" => hash})
  end

  def valid?(record, seq, prev) when is_map(record) do
    body = Map.drop(record, ["hash", "prev"])

    record["version"] == 2 and record["seq"] == seq and record["prev"] == prev and
      seal(body, prev)["hash"] == record["hash"]
  end

  def valid?(_, _, _), do: false

  # Text redaction cannot inspect arbitrary encoded files/process bytes. A redacted
  # policy must withhold these rather than retain an apparently sanitized artifact.
  def capture(%{"encoding" => "base64"}, :redacted),
    do: %{"withheld" => "binary_redaction_not_supported"}

  def capture(value, mode) when is_map(value) do
    Map.new(value, fn {key, value} ->
      normalized = String.downcase(to_string(key))

      cond do
        normalized in @credentials -> {key, %{"withheld" => "credential"}}
        mode == :metadata and normalized in @content -> {key, %{"withheld" => "metadata_policy"}}
        true -> {key, capture(value, mode)}
      end
    end)
  end

  def capture(value, mode) when is_list(value), do: Enum.map(value, &capture(&1, mode))

  def capture(value, mode) when is_binary(value) and mode in [:redacted, :full],
    do: Jido.Harness.Redaction.redact(value)

  def capture(value, _), do: value
end
