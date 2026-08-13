defmodule Ouroboros.Gateway.Wire do
  @moduledoc """
  Runtime terms rendered as self-describing JSON trees. Lossy on purpose, and it says so.

  ## Why `Orchestration.Serializable.safe/1` cannot be the mechanism

  `Ouroboros.Orchestration.Serializable.safe/1` is all-or-nothing at the top level: one
  pid anywhere in a term replaces the *entire* term with a truncated inspect string. Pids
  are everywhere by construction — `Ouroboros.Mesh.list_agents/0` returns
  `%{id: .., pid: .., node: .., replicas: ..}` maps, `Ouroboros.status/0` embeds those,
  and `Mesh.state/1` returns a `Jido.AgentServer.State` dense with pids, refs, `:queue`
  tuples, and functions. Applied to any of them, `safe/1` would answer one opaque string
  where the client needed a table. So this module walks the tree and substitutes at the
  *leaf*: the sibling keys stay readable, and only the thing that genuinely has no JSON
  shape becomes a marker.

  ## The substitutions

    * `pid` / `port` / `reference` / `function` → `%{"_opaque" => inspect(term)}`
    * structs → their fields plus `"_struct" => "Ouroboros.Interactive.Event"`;
      `DateTime`, `NaiveDateTime`, `Date`, and `Time` become ISO-8601 strings instead
    * atoms → strings, with a leading `Elixir.` stripped so a module renders as
      `"Ouroboros.Capability.Foo"` rather than `"Elixir.Ouroboros.Capability.Foo"`
    * tuples → lists; map keys → strings; charlists stay lists of integers
    * binaries that are not valid UTF-8 → `%{"_b64" => Base.encode64(binary)}`
    * anything deeper than 32 levels, or beyond a total of 50_000 nodes →
      `%{"_truncated" => true}`

  This is why a forged `Ouroboros.Capability.*` agent's novel state renders in a client
  the moment it exists: every payload is a tree of strings, numbers, lists, and maps, and
  a generic tree widget can draw any of them without knowing what they mean.

  ## What is lost

  Stated plainly, because a client author will otherwise assume otherwise. The transform
  is one-way. `:ok` and `"ok"` encode identically. `{1, 2}` and `[1, 2]` encode
  identically. A map with both `:a` and `"a"` as keys loses one of them. A module atom
  and the plain atom of the same printed name collapse together. Nothing decoded from
  this can be sent back to the runtime as a term, and no gateway method accepts one: the
  method table takes strings and integers, and resolves the single module-shaped
  parameter through `String.to_existing_atom/1` rather than through anything this module
  emitted.

  The depth and node caps exist because a `Conn` must survive a pathological state tree
  from a plane it does not control. Truncation is visible in the payload rather than
  silent.
  """

  @max_depth 32
  @max_nodes 50_000

  @truncated %{"_truncated" => true}

  @doc """
  Converts a term to a JSON-encodable tree.
  """
  @spec to_json(term()) :: term()
  def to_json(term) do
    {value, _budget} = walk(term, 0, @max_nodes)
    value
  end

  @doc """
  Encodes an already JSON-safe map as one newline-terminated protocol frame.

  Callers build the JSON-RPC envelope themselves so that a client-supplied `id` is echoed
  exactly as it arrived rather than re-walked.
  """
  @spec frame!(term()) :: iodata()
  def frame!(value), do: [JSON.encode_to_iodata!(value), ?\n]

  defp walk(_term, _depth, budget) when budget <= 0, do: {@truncated, 0}
  defp walk(_term, depth, budget) when depth > @max_depth, do: {@truncated, budget - 1}

  defp walk(term, _depth, budget) when is_nil(term) or is_boolean(term), do: {term, budget - 1}
  defp walk(term, _depth, budget) when is_atom(term), do: {atom_to_string(term), budget - 1}
  defp walk(term, _depth, budget) when is_number(term), do: {term, budget - 1}

  defp walk(term, _depth, budget) when is_binary(term) do
    if String.valid?(term) do
      {term, budget - 1}
    else
      {%{"_b64" => Base.encode64(term)}, budget - 1}
    end
  end

  defp walk(term, _depth, budget)
       when is_pid(term) or is_port(term) or is_reference(term) or is_function(term) do
    {%{"_opaque" => inspect(term)}, budget - 1}
  end

  defp walk(%DateTime{} = term, _depth, budget), do: {DateTime.to_iso8601(term), budget - 1}

  defp walk(%NaiveDateTime{} = term, _depth, budget),
    do: {NaiveDateTime.to_iso8601(term), budget - 1}

  defp walk(%Date{} = term, _depth, budget), do: {Date.to_iso8601(term), budget - 1}
  defp walk(%Time{} = term, _depth, budget), do: {Time.to_iso8601(term), budget - 1}

  defp walk(%module{} = term, depth, budget) do
    {map, budget} = walk_map(Map.from_struct(term), depth, budget - 1)
    {Map.put(map, "_struct", inspect(module)), budget}
  end

  defp walk(term, depth, budget) when is_map(term), do: walk_map(term, depth, budget - 1)

  defp walk(term, depth, budget) when is_list(term), do: walk_list(term, depth, budget - 1, [])

  defp walk(term, depth, budget) when is_tuple(term),
    do: walk_list(Tuple.to_list(term), depth, budget - 1, [])

  # Bitstrings that are not whole bytes, and anything a future OTP grows, still have to
  # leave this function as something a client can render.
  defp walk(term, _depth, budget), do: {%{"_opaque" => inspect(term)}, budget - 1}

  defp walk_list(_list, _depth, budget, acc) when budget <= 0,
    do: {Enum.reverse([@truncated | acc]), 0}

  defp walk_list([], _depth, budget, acc), do: {Enum.reverse(acc), budget}

  defp walk_list([head | tail], depth, budget, acc) do
    {value, budget} = walk(head, depth + 1, budget)
    walk_list(tail, depth, budget, [value | acc])
  end

  # An improper tail has no list shape to preserve, so it is named rather than appended
  # as if it had been an element all along.
  defp walk_list(tail, depth, budget, acc) do
    {value, budget} = walk(tail, depth + 1, budget)
    {Enum.reverse([%{"_improper_tail" => value} | acc]), budget}
  end

  defp walk_map(map, depth, budget) do
    {pairs, budget} =
      Enum.reduce_while(map, {[], budget}, fn {key, value}, {pairs, budget} ->
        if budget <= 0 do
          {:halt, {[{"_truncated", true} | pairs], 0}}
        else
          {encoded, budget} = walk(value, depth + 1, budget - 1)
          {:cont, {[{key_to_string(key), encoded} | pairs], budget}}
        end
      end)

    {Map.new(pairs), budget}
  end

  defp key_to_string(key) when is_atom(key), do: atom_to_string(key)

  defp key_to_string(key) when is_binary(key),
    do: if(String.valid?(key), do: key, else: inspect(key))

  defp key_to_string(key) when is_integer(key), do: Integer.to_string(key)
  defp key_to_string(key), do: inspect(key)

  defp atom_to_string(nil), do: "nil"
  defp atom_to_string(true), do: "true"
  defp atom_to_string(false), do: "false"

  defp atom_to_string(atom) do
    case Atom.to_string(atom) do
      "Elixir." <> rest -> rest
      name -> name
    end
  end
end
