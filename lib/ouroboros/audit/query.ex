defmodule Ouroboros.Audit.Query do
  @moduledoc "Bounded investigation projections; canonical records remain independently readable."
  alias Ouroboros.Audit.{Config, Store}

  @keys ~w(event_id stream_id seq at kind turn_id call_id ledger_effect_id attempt_id model tool status is_error duration_ms policy_revision capture actor_id parent_session_id parent_task_id session_id provider_session_id workspace)
  @filters ~w(stream_id session_id provider_session_id turn_id call_id ledger_effect_id actor_id model tool kind status)

  def events(root) do
    Enum.reduce_while(Store.streams(root), {:ok, []}, fn stream, {:ok, acc} ->
      case Store.read(Store.stream_path(root, stream)) do
        {:ok, scanned} -> {:cont, {:ok, acc ++ project(scanned.records)}}
        error -> {:halt, error}
      end
    end)
  end

  def project(records) do
    {events, _} =
      Enum.map_reduce(records, %{}, fn record, context ->
        context =
          if record["kind"] == "session_opened",
            do:
              Map.merge(
                context,
                Map.take(
                  record,
                  ~w(session_id provider_session_id parent_session_id parent_task_id workspace actor_id)
                )
              ),
            else: context

        row = Map.merge(context, Map.take(record, @keys))
        {row, context}
      end)

    events
  end

  def search(params \\ %{}, config \\ Config.current()) do
    with :ok <- validate(params),
         {:ok, events} <- events(config.root) do
      {:ok, select(events, params)}
    end
  end

  def select(events, params) do
    params = normalize_times(params)

    rows =
      events
      |> Enum.filter(&matches?(&1, params))
      |> Enum.sort_by(&{&1["at"], &1["stream_id"], &1["seq"]}, :desc)

    limit = params["limit"] || 100
    offset = params["offset"] || 0
    selected = Enum.slice(rows, offset, limit)

    %{
      events: selected,
      total: length(rows),
      next_offset: if(offset + length(selected) < length(rows), do: offset + length(selected)),
      source: "journal",
      indexed_through: nil
    }
  end

  def validate(params) when is_map(params) do
    limit = params["limit"] || 100
    offset = params["offset"] || 0

    if is_integer(limit) and limit in 1..500 and is_integer(offset) and offset in 0..1_000_000 and
         Enum.all?(@filters ++ ["since", "until"], fn key ->
           is_nil(params[key]) or (is_binary(params[key]) and byte_size(params[key]) <= 500)
         end) and Enum.all?(["since", "until"], &(is_nil(params[&1]) or valid_time?(params[&1]))),
       do: :ok,
       else: {:error, :invalid_audit_query}
  end

  def validate(_), do: {:error, :invalid_audit_query}

  def normalize_times(params) do
    Enum.reduce(["since", "until"], params, fn key, acc ->
      case acc[key] do
        value when is_binary(value) ->
          case DateTime.from_iso8601(value) do
            {:ok, at, _} ->
              Map.put(
                acc,
                key,
                DateTime.to_iso8601(%{at | microsecond: {elem(at.microsecond, 0), 6}})
              )

            _ ->
              acc
          end

        _ ->
          acc
      end
    end)
  end

  defp valid_time?(value) when is_binary(value),
    do: match?({:ok, _, _}, DateTime.from_iso8601(value))

  defp valid_time?(_), do: false

  def matches?(row, params) do
    Enum.all?(@filters, fn key -> is_nil(params[key]) or row[key] == params[key] end) and
      (is_nil(params["since"]) or row["at"] >= params["since"]) and
      (is_nil(params["until"]) or row["at"] <= params["until"])
  end

  def show(stream, config \\ Config.current()) do
    with true <- Store.valid_id?(stream),
         {:ok, scanned} <- Store.read(Store.stream_path(config.root, stream)),
         false <- scanned.records == [] do
      {:ok,
       Map.merge(scanned, %{
         stream_id: stream,
         calls: calls(scanned.records),
         coverage: coverage(scanned.records),
         policy: Config.public(config)
       })}
    else
      false -> {:error, :invalid_stream_id}
      true -> {:error, :audit_stream_not_found}
      error -> error
    end
  end

  def calls(records) do
    # Linear correlation. Never scan the entire history once for every call.
    {starts, terminals} =
      Enum.reduce(records, {[], %{}}, fn record, {starts, terminals} ->
        case record["kind"] do
          kind when kind in ["model_call", "tool_dispatch"] ->
            {[record | starts], terminals}

          kind when kind in ["model_result", "model_failed", "tool_response"] ->
            {starts, Map.put(terminals, call_key(record), record)}

          _ ->
            {starts, terminals}
        end
      end)

    starts
    |> Enum.reverse()
    |> Enum.map(fn start ->
      terminal = Map.get(terminals, call_key(start))
      terminal = if terminal && terminal["seq"] > start["seq"], do: terminal

      %{
        id: start["event_id"],
        kind: start["kind"],
        name: start["model"] || start["tool"] || start["kind"],
        started_at: start["at"],
        start_seq: start["seq"],
        attempt_id: start["attempt_id"],
        start: start,
        outcome: if(terminal, do: outcome(terminal), else: "unknown"),
        terminal_event_id: terminal && terminal["event_id"]
      }
    end)
  end

  defp call_key(record) do
    if String.starts_with?(record["kind"], "model_"),
      do: {:model, record["turn_id"], record["ledger_effect_id"]},
      else: {:tool, record["turn_id"], record["attempt_id"]}
  end

  defp outcome(%{"kind" => "model_failed"}), do: "failed"

  defp outcome(%{"status" => status}) when status in ["timed_out", "interrupted", "stopped"],
    do: status

  defp outcome(%{"is_error" => true}), do: "failed"
  defp outcome(_), do: "completed"

  defp coverage(records) do
    %{
      content: records |> Enum.map(& &1["capture"]) |> Enum.uniq(),
      integrity: "local_hash_chain",
      archive: "verify_external_receipts_separately",
      unknown_outcomes: Enum.count(calls(records), &(&1.outcome == "unknown")),
      truncated: Enum.any?(records, &(&1["kind"] in ["gap", "truncated"])),
      downstream: "runtime_boundaries_only"
    }
  end
end
