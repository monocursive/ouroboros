defmodule Ouroboros.Audit.OTLP do
  @moduledoc "Optional OTLP/HTTP JSON projection. Canonical audit records are never sampled."
  alias Ouroboros.Audit.{Config, Query, Store}
  alias Ouroboros.Audit.File, as: Durable
  alias Ouroboros.Provider.Native.Journal
  def flush(%{otlp_endpoint: nil}), do: :ok

  def flush(config) do
    path = Path.join(config.root, "otlp-watermarks.json")

    marks =
      case Durable.read(path) do
        {:ok, bytes} -> JSON.decode!(bytes)
        {:error, :enoent} -> %{}
      end

    Enum.reduce_while(Store.streams(config.root), {:ok, marks}, fn stream, {:ok, acc} ->
      with {:ok, scanned} <- Store.read(Store.stream_path(config.root, stream)) do
        rows =
          scanned.records |> Enum.filter(&(&1["seq"] > Map.get(acc, stream, 0))) |> Enum.take(200)

        if rows == [] do
          {:cont, {:ok, acc}}
        else
          payload = payload(rows, config)

          case Req.post(config.otlp_endpoint,
                 json: payload,
                 retry: false,
                 redirect: false,
                 receive_timeout: 10_000,
                 connect_options: [timeout: 3_000]
               ) do
            {:ok, %{status: 200, body: body}} when body == %{} or body == "" ->
              {:cont, {:ok, Map.put(acc, stream, List.last(rows)["seq"])}}

            _ ->
              {:halt, {:error, :otlp_export_pending}}
          end
        end
      else
        _ -> {:halt, {:error, :canonical_evidence_unavailable}}
      end
    end)
    |> case do
      {:ok, next} -> Durable.atomic(path, JSON.encode!(next))
      error -> error
    end
  rescue
    _ -> {:error, :otlp_export_pending}
  end

  def payload(records, config \\ Config.current()) do
    spans =
      Enum.map(Query.project(records), fn row ->
        {:ok, at, _} = DateTime.from_iso8601(row["at"])
        timestamp = DateTime.to_unix(at, :nanosecond) |> Integer.to_string()

        attributes =
          Map.take(
            row,
            ~w(event_id seq kind actor_id session_id turn_id call_id model tool policy_revision)
          )

        %{
          "traceId" => String.slice(row["stream_id"], 0, 32),
          "spanId" => String.slice(Journal.digest(row["event_id"]), 0, 16),
          "name" => "ouroboros." <> row["kind"],
          "kind" => 1,
          "startTimeUnixNano" => timestamp,
          "endTimeUnixNano" => timestamp,
          "attributes" =>
            Enum.map(attributes, fn {key, value} ->
              %{"key" => "ouroboros." <> key, "value" => %{"stringValue" => to_string(value)}}
            end)
        }
      end)

    %{
      "resourceSpans" => [
        %{
          "resource" => %{
            "attributes" => [
              %{"key" => "service.name", "value" => %{"stringValue" => "ouroboros"}},
              %{
                "key" => "service.instance.id",
                "value" => %{"stringValue" => Config.writer_id(config)}
              }
            ]
          },
          "scopeSpans" => [
            %{"scope" => %{"name" => "ouroboros.audit", "version" => "2"}, "spans" => spans}
          ]
        }
      ]
    }
  end
end
