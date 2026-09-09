defmodule Ouroboros.Gateway.Methods.Encode do
  @moduledoc false

  # Wire encoding and plane-result mapping that is not on the parameter-contract
  # AST path. Client bytes never become atoms here; enum strings are literals.

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Gateway.Config, as: GatewayConfig
  alias Ouroboros.Gateway.Wire

  # Where `ledger.export`'s hash chain starts. A fixed, published seed rather than a random
  # one: the point of the chain is that a client can recompute it from the answer alone.
  @chain_seed String.duplicate("0", 64)

  # Atoms the coordinator chose, rendered as the literal strings this module contains. A
  # decision is never `to_string`d out of whatever the plane happened to answer.
  def approval_answer(answer) do
    %{
      "decision" => if(answer.decision == :allow, do: "allow", else: "deny"),
      "request_id" => answer.request_id,
      "source" => approval_source(answer.source),
      "reason" => answer.reason
    }
  end

  defp approval_source(:engine), do: "engine"
  defp approval_source(:human), do: "human"
  defp approval_source(:timeout), do: "timeout"
  defp approval_source(:capacity), do: "capacity"
  defp approval_source(:session_terminal), do: "session_terminal"
  defp approval_source(:checkpoint_failed), do: "checkpoint_failed"
  defp approval_source(:caller_gone), do: "caller_gone"
  defp approval_source(:coordinator_restart), do: "coordinator_restart"
  defp approval_source(_other), do: "runtime"

  @spec chain([EffectLedger.Entry.t()]) :: map()
  def chain(entries) when is_list(entries) do
    {lines, head} =
      Enum.map_reduce(entries, @chain_seed, fn entry, previous ->
        line = entry |> Wire.to_json() |> canonical_json()
        hash = :sha256 |> :crypto.hash([previous, line]) |> Base.encode16(case: :lower)

        {%{sequence: entry.sequence, id: entry.id, line: line, previous: previous, hash: hash},
         hash}
      end)

    %{algorithm: "sha256", count: length(lines), seed: @chain_seed, head: head, lines: lines}
  end

  # Object keys sorted, no whitespace. `JSON.encode!/1` iterates a map in whatever order
  # the term happens to have, which is stable enough in practice and not a property worth
  # betting a hash chain on: two exports of the same entry have to produce the same bytes,
  # on any machine, or the chain a client verifies is a chain over an accident.
  defp canonical_json(value), do: value |> canonical() |> IO.iodata_to_binary()

  defp canonical(map) when is_map(map) do
    inner =
      map
      |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
      |> Enum.map(fn {key, value} -> [JSON.encode!(to_string(key)), ?:, canonical(value)] end)
      |> Enum.intersperse(?,)

    [?{, inner, ?}]
  end

  defp canonical(list) when is_list(list),
    do: [?[, list |> Enum.map(&canonical/1) |> Enum.intersperse(?,), ?]]

  defp canonical(other), do: JSON.encode!(other)

  # Encoded here rather than by the `Conn`, because this is the one answer that gets the
  # larger per-leaf cap: the whole point of the method is to hand back the leaf a
  # streamed event could only excerpt. What it returns is already a JSON tree, so the
  # connection's own `Wire.to_json/1` walks plain strings and maps and leaves it alone.
  def detail(event) do
    limits = GatewayConfig.event_limits()

    Wire.to_json(event,
      event_leaf_bytes: limits.detail_leaf_bytes,
      event_payload_bytes: limits.detail_leaf_bytes
    )
  end
end
