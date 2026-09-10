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
