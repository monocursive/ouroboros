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
    * a string inside an event `payload` that is longer than its cap →
      `%{"_excerpt" => <the first bytes, cut at a UTF-8 boundary>, "_bytes" => total}`

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

  ## The byte cap on event payloads

  Depth and node counts do not bound *bytes*. Fifty thousand nodes is a cheap tree; one
  node holding a five-megabyte diff is not, and that one node used to be framed whole on
  every notification, every `replay` result, and every `subscribe` backlog. So a binary
  leaf inside the `payload` of an `Ouroboros.Interactive.Event` or an
  `Ouroboros.Coding.Event` is bounded here, in the one function all three of those paths
  reach, so the three cannot drift apart.

  The rule, whole:

  > Each string leaf inside an event `payload` may put at most `event_leaf_bytes` on the
  > wire, and one event's payload strings at most `event_payload_bytes` between them. The
  > cap for a leaf is therefore whichever of those two is smaller at the moment it is
  > reached — the per-leaf cap, or what is left of the per-event budget. A leaf longer
  > than its cap becomes `%{"_excerpt" => prefix, "_bytes" => full_size}`, and the budget
  > starts over at the next event, so a 500-event replay gives every event its own.

  Two deliberate exceptions to that arithmetic, both so the marker never costs more than
  it saves: a string of 512 bytes or fewer is never excerpted, because the marker map
  replacing it would be the larger of the two; and the envelope fields — `type`,
  `sequence`, `timestamp`, the ids, `provider` — are never touched at all, because a
  client indexes and resyncs by them and an excerpted `sequence` would break the protocol
  rather than bound it.

  A non-UTF-8 binary over its cap keeps the `_b64` spelling it already had and gains the
  same `_bytes` key, so "there was more than this" reads the same way whichever leaf kind
  it was. The budget counts *source* bytes retained; base64 costs four wire bytes for
  every three of them.

  ### What this does not bound

  A payload of tens of thousands of short strings. Each one is under the never-excerpt
  floor, so the byte caps decline to act and the node cap is what stops it — the same
  bound that was there before. This cap is aimed at the leaf that is large by itself,
  which is the shape a diff, a tool result, and a file read all have.
  """

  alias Ouroboros.Coding.Event, as: CodingEvent
  alias Ouroboros.Gateway.Config
  alias Ouroboros.Interactive.Event, as: InteractiveEvent

  @max_depth 32
  @max_nodes 50_000

  @truncated %{"_truncated" => true}

  # A string at or below this is never excerpted: `%{"_excerpt" => .., "_bytes" => ..}`
  # costs more bytes than the string it would replace, so excerpting one would make the
  # frame larger in the name of making it smaller.
  @keep_whole 512

  @doc """
  Converts a term to a JSON-encodable tree.

  `opts` may override the two event-payload byte caps — `:event_leaf_bytes` and
  `:event_payload_bytes` — which otherwise come from `Ouroboros.Gateway.Config.event_limits/0`.
  `interactive.event_detail` is the caller that overrides them: it exists to answer with
  the one event an excerpt came from, so it raises the per-leaf cap to
  `:detail_leaf_bytes` rather than handing back the same excerpt again.
  """
  @spec to_json(term()) :: term()
  def to_json(term), do: to_json(term, [])

  @spec to_json(term(), keyword()) :: term()
  def to_json(term, opts) when is_list(opts) do
    {value, _context} = walk(term, 0, context(opts))
    value
  end

  defp context(opts) do
    limits = Config.event_limits()

    %{
      nodes: @max_nodes,
      # False everywhere but inside an event payload. Every other result — `runtime.status`,
      # an agent's state, an error's `data` — is bounded by the node and depth caps alone,
      # exactly as it was before this cap existed.
      payload?: false,
      emitted: 0,
      leaf_bytes: Keyword.get(opts, :event_leaf_bytes, limits.event_leaf_bytes),
      payload_bytes: Keyword.get(opts, :event_payload_bytes, limits.event_payload_bytes)
    }
  end

  @doc """
  Encodes an already JSON-safe map as one newline-terminated protocol frame.

  Callers build the JSON-RPC envelope themselves so that a client-supplied `id` is echoed
  exactly as it arrived rather than re-walked.
  """
  @spec frame!(term()) :: iodata()
  def frame!(value), do: [JSON.encode_to_iodata!(value), ?\n]

  defp walk(_term, _depth, %{nodes: nodes} = ctx) when nodes <= 0, do: {@truncated, exhaust(ctx)}
  defp walk(_term, depth, ctx) when depth > @max_depth, do: {@truncated, tick(ctx)}

  defp walk(term, _depth, ctx) when is_nil(term) or is_boolean(term), do: {term, tick(ctx)}
  defp walk(term, _depth, ctx) when is_atom(term), do: {atom_to_string(term), tick(ctx)}
  defp walk(term, _depth, ctx) when is_number(term), do: {term, tick(ctx)}

  defp walk(term, _depth, ctx) when is_binary(term) do
    {value, ctx} = binary_leaf(term, ctx)
    {value, tick(ctx)}
  end

  defp walk(term, _depth, ctx)
       when is_pid(term) or is_port(term) or is_reference(term) or is_function(term) do
    {%{"_opaque" => inspect(term)}, tick(ctx)}
  end

  defp walk(%DateTime{} = term, _depth, ctx), do: {DateTime.to_iso8601(term), tick(ctx)}

  defp walk(%NaiveDateTime{} = term, _depth, ctx),
    do: {NaiveDateTime.to_iso8601(term), tick(ctx)}

  defp walk(%Date{} = term, _depth, ctx), do: {Date.to_iso8601(term), tick(ctx)}
  defp walk(%Time{} = term, _depth, ctx), do: {Time.to_iso8601(term), tick(ctx)}

  # The two structs whose `payload` is byte-capped, and the only two. Every event on this
  # wire is one of them, whichever direction it arrived from — a live notification, a
  # `replay` result, or a `subscribe` backlog — which is what makes this the one place the
  # cap has to exist for all three to obey it.
  defp walk(%InteractiveEvent{} = term, depth, ctx), do: walk_event(term, depth, ctx)
  defp walk(%CodingEvent{} = term, depth, ctx), do: walk_event(term, depth, ctx)

  defp walk(%module{} = term, depth, ctx) do
    {map, ctx} = walk_map(Map.from_struct(term), depth, tick(ctx))
    {Map.put(map, "_struct", inspect(module)), ctx}
  end

  defp walk(term, depth, ctx) when is_map(term), do: walk_map(term, depth, tick(ctx))

  defp walk(term, depth, ctx) when is_list(term), do: walk_list(term, depth, tick(ctx), [])

  defp walk(term, depth, ctx) when is_tuple(term),
    do: walk_list(Tuple.to_list(term), depth, tick(ctx), [])

  # Bitstrings that are not whole bytes, and anything a future OTP grows, still have to
  # leave this function as something a client can render.
  defp walk(term, _depth, ctx), do: {%{"_opaque" => inspect(term)}, tick(ctx)}

  defp walk_list(_list, _depth, %{nodes: nodes} = ctx, acc) when nodes <= 0,
    do: {Enum.reverse([@truncated | acc]), exhaust(ctx)}

  defp walk_list([], _depth, ctx, acc), do: {Enum.reverse(acc), ctx}

  defp walk_list([head | tail], depth, ctx, acc) do
    {value, ctx} = walk(head, depth + 1, ctx)
    walk_list(tail, depth, ctx, [value | acc])
  end

  # An improper tail has no list shape to preserve, so it is named rather than appended
  # as if it had been an element all along.
  defp walk_list(tail, depth, ctx, acc) do
    {value, ctx} = walk(tail, depth + 1, ctx)
    {Enum.reverse([%{"_improper_tail" => value} | acc]), ctx}
  end

  defp walk_map(map, depth, ctx) do
    {pairs, ctx} =
      Enum.reduce_while(map, {[], ctx}, fn {key, value}, {pairs, ctx} ->
        if ctx.nodes <= 0 do
          {:halt, {[{"_truncated", true} | pairs], exhaust(ctx)}}
        else
          {encoded, ctx} = walk(value, depth + 1, tick(ctx))
          {:cont, {[{key_to_string(key), encoded} | pairs], ctx}}
        end
      end)

    {Map.new(pairs), ctx}
  end

  # The envelope is walked as any struct is; only `payload` is handed the byte cap. Popping
  # it out first is what makes "never the fields a client resyncs by" a property of the
  # code rather than a promise in a comment.
  defp walk_event(%module{} = event, depth, ctx) do
    {payload, envelope} = event |> Map.from_struct() |> Map.pop(:payload)

    {map, ctx} = walk_map(envelope, depth, tick(ctx))
    {encoded, ctx} = walk_payload(payload, depth + 1, tick(ctx))

    # Interpret the bounded, redacted payload once at the runtime boundary. The raw
    # payload remains available and older clients ignore this additive field.
    semantic = Ouroboros.EventPresentation.semantic(%{event | payload: encoded})
    {semantic, ctx} = walk(semantic, depth + 1, ctx)
    map = if is_map(semantic), do: Map.put(map, "semantic", semantic), else: map
    {map |> Map.put("payload", encoded) |> Map.put("_struct", inspect(module)), ctx}
  end

  # The budget is per event and restored on the way out, so a 500-event replay gives each
  # event its own and an event that spent all of its own leaves the next one untouched.
  # The *node* budget is not restored: that one is per encode, and always was.
  defp walk_payload(payload, depth, ctx) do
    {value, spent} = walk(payload, depth, %{ctx | payload?: true, emitted: 0})

    {value, %{spent | payload?: ctx.payload?, emitted: ctx.emitted}}
  end

  # Outside an event payload a binary is what it always was: a string, or base64.
  defp binary_leaf(term, %{payload?: false} = ctx) do
    if String.valid?(term), do: {term, ctx}, else: {%{"_b64" => Base.encode64(term)}, ctx}
  end

  defp binary_leaf(term, ctx) do
    size = byte_size(term)
    cap = leaf_cap(ctx)

    cond do
      size <= max(cap, @keep_whole) ->
        {whole(term), spend(ctx, size)}

      String.valid?(term) ->
        prefix = utf8_prefix(term, cap)
        {%{"_excerpt" => prefix, "_bytes" => size}, spend(ctx, byte_size(prefix))}

      true ->
        prefix = binary_part(term, 0, cap)
        {%{"_b64" => Base.encode64(prefix), "_bytes" => size}, spend(ctx, cap)}
    end
  end

  defp whole(term) do
    if String.valid?(term), do: term, else: %{"_b64" => Base.encode64(term)}
  end

  # Whichever bound bites first: the per-leaf cap, or what is left of this event's budget.
  defp leaf_cap(ctx), do: min(ctx.leaf_bytes, max(ctx.payload_bytes - ctx.emitted, 0))

  # `binary_part/3` can cut inside a multi-byte character, and a client decoding this frame
  # is owed valid UTF-8. So the cut retreats to the last whole character, which is never
  # more than three bytes back in a binary that was valid to begin with.
  defp utf8_prefix(_term, cap) when cap <= 0, do: ""
  defp utf8_prefix(term, cap), do: term |> binary_part(0, cap) |> retreat(3)

  defp retreat(prefix, 0), do: if(String.valid?(prefix), do: prefix, else: "")

  defp retreat(prefix, tries) do
    if String.valid?(prefix),
      do: prefix,
      else: retreat(binary_part(prefix, 0, byte_size(prefix) - 1), tries - 1)
  end

  defp tick(ctx), do: %{ctx | nodes: ctx.nodes - 1}
  defp exhaust(ctx), do: %{ctx | nodes: 0}
  defp spend(ctx, bytes), do: %{ctx | emitted: ctx.emitted + bytes}

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
