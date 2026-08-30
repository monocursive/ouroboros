defmodule Ouroboros.Provider.Native.Replay do
  @moduledoc """
  Verified replay: re-run the recorded turns through the real loop and check the answer.

  REPLAY.md §5. The engine reads a session's `journal.ndjson` **from the file**, never
  through the session process — the session may be long dead, and a verdict that needed a
  live transport would be a verdict about liveness. It then re-runs each recorded turn
  through `Ouroboros.Provider.Native.Loop.run_turn/2` — the shipped decision code, not a
  simulation — with every nondeterminism source substituted by the record:

    * **model** — `Ouroboros.Provider.Native.Replay.Model`, streaming the recorded chunks
      of the `model_result` whose iteration matches, and checking the `model_call` record's
      `request_sha256` against the one re-derived from the request the loop just built;
    * **tools** — the recorded `tool_result` content per `call_id`, through the loop's
      `tool_source` seam, so nothing is dispatched and no ledger entry is written;
    * **control** — the recorded `injected` records fed at their recorded positions,
      through the loop's `control_feed` seam, in place of the mailbox drain;
    * **hooks** — preset to the empty configuration, which defeats the per-turn disk
      reload;
    * **clock** — every emitted event carries the `at` of the record being reproduced,
      rather than the instant of the replay (D9).

  ## What a verdict means

  Per turn, three comparisons, each naming its own field. The rebuilt prefix's
  `system_sha256` and `prefix_fingerprint` against `turn_started`'s; each `model_call`'s
  `request_sha256` against the digest of the request the loop just assembled (checked inside
  the model seam, where the request is in hand); and the assembled message list against
  `turn_settled.conversation_digest`, through the same canonical encoding the checkpoint
  uses (`Checkpoint.digest_of/2`) — so the two digests are the same function of the same
  list, or the loop derives differently now.

  A mismatch is `{:replay_diverged, %{seq:, turn_id:, field:, expected_sha256:,
  got_sha256:}}` and the replay stops there. Never a best-effort continuation: a diverging
  replay means either the code changed its derivation or the record is inconsistent, and
  both are findings that a partial answer would bury.

  ## What the engine re-derives rather than reads

  The journal holds the system prompt's *digest*, not its bytes, and holds no tool list at
  all. Both are therefore rebuilt from the workspace through
  `Ouroboros.Provider.Native.Context.build/1`, which is the point: verification asks whether
  *this* build, in *this* workspace, re-derives what was recorded. A session whose workspace
  has since changed diverges at `system_sha256` or `prefix_fingerprint`, and that is a true
  answer to the question, not a false negative.

  ## Honest boundaries (§5.3)

  Verification is bounded, by name, wherever the record stops being sufficient — a `gap` or
  `truncated` record, a turn with no `turn_settled` (the crash case: an inference entry left
  `:ambiguous`), a `model_call` with no `model_result`, a conversation that predates the
  journal (a resumed or forked session), a compaction or rewind that rewrote the message
  list in a way the record does not carry, an injection this engine cannot reproduce, a
  prompt whose attachments the record names but does not hold, and a blob the store has
  evicted. Each is `{:replay_boundary, reason, seq}`: the turns before it are verified and
  reported as verified, and everything after it is refused rather than guessed at.

  ## The seam this engine cannot supply for itself

  R1 defined `tool_source` and wired it into the *inference* ledger gate, but the tool
  dispatch path in `Loop` does not consult it. Until it does, replaying a turn that called
  a tool would *run* the tool and account for it — the two things replay must never do. So
  the engine asks the loop (`Ouroboros.Provider.Native.Replay.Seam`) and, where the seam is
  absent, bounds a tool-calling turn by name instead of running it. Asking rather than
  assuming is what lets this file need no edit on the day the seam lands.
  """

  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Context
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Provider.Native.Journal
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Replay.Model, as: ReplayModel
  alias Ouroboros.Provider.Native.Replay.Record
  alias Ouroboros.Provider.Native.Replay.Seam
  alias Ouroboros.Provider.Native.Tools

  @typedoc """
  What a replay found. `divergence` is `nil`, a `{:replay_diverged, …}` or a
  `{:replay_boundary, reason, seq}`; `turns` counts the turns that verified, which is why a
  boundary is reported rather than raised.
  """
  @type verdict :: %{
          verified: boolean(),
          turns: non_neg_integer(),
          records: non_neg_integer(),
          head: String.t(),
          divergence: nil | tuple(),
          events: [map()]
        }

  @doc """
  Verifies one session's journal, re-running every recorded turn.

  Options:

    * `:workspace` — the session's workspace root. The system prompt and the tool list are
      re-derived from it, so this is the input the whole comparison hangs on.
    * `:add_dirs`, `:allowed_tools`, `:disallowed_tools`, `:system_prompt`,
      `:subagent_depth` — the rest of the start request's shape, for the same reason.
    * `:model_module` — the module the recorded request digests were taken through.
      Defaults to this node's configured one, which is what the live session used.
    * `:event_limit` — the session's checkpoint limit, so the conversation digest is taken
      over the same trim the live write took it over.
  """
  @spec verify(String.t(), keyword()) :: {:ok, verdict()} | {:error, term()}
  def verify(session_dir, opts \\ []) when is_binary(session_dir) do
    case Journal.verify(Journal.path(session_dir)) do
      {:ok, %{records: []}} -> {:error, :no_journal}
      {:ok, %{records: records, head: head}} -> run(records, head, session_dir, opts)
      {:error, _reason} = error -> error
    end
  end

  @doc """
  A divergence or boundary, as the closed shape the wire carries.

  One object either way, told apart by `kind`, so a client has one thing to decode and one
  place to look for the sequence. `reason` and `detail` are the boundary's own vocabulary
  rendered as strings — a boundary names *why*, and a client that could not name it back
  would be reporting "unverified" and nothing else.
  """
  @spec describe(nil | tuple()) :: nil | map()
  def describe(nil), do: nil

  def describe({:replay_diverged, fields}) do
    %{
      "kind" => "diverged",
      "seq" => Map.get(fields, :seq),
      "turn_id" => Map.get(fields, :turn_id),
      "field" => Map.get(fields, :field),
      "expected_sha256" => Map.get(fields, :expected_sha256),
      "got_sha256" => Map.get(fields, :got_sha256)
    }
  end

  def describe({:replay_boundary, reason, seq}) do
    {name, detail} = name_reason(reason)
    %{"kind" => "boundary", "reason" => name, "detail" => detail, "seq" => seq}
  end

  defp name_reason(reason) when is_atom(reason), do: {Atom.to_string(reason), nil}

  defp name_reason(reason) when is_tuple(reason) do
    [head | rest] = Tuple.to_list(reason)
    {to_string(head), rest |> Enum.map_join(" ", &oneline/1) |> String.slice(0, 200)}
  end

  defp name_reason(reason), do: {oneline(reason), nil}

  defp oneline(value) when is_binary(value), do: value
  defp oneline(value) when is_atom(value), do: Atom.to_string(value)
  defp oneline(value), do: inspect(value, limit: 6)

  # ------------------------------------------------------------------ the walk

  defp run(records, head, session_dir, opts) do
    {steps, boundary} = plan(records)

    initial = %{
      session_dir: session_dir,
      opts: opts,
      delegate: Keyword.get(opts, :model_module) || Model.module(),
      messages: [],
      turns: 0,
      events: []
    }

    {divergence, context} =
      Enum.reduce_while(steps, {boundary, initial}, fn turn, {carried, context} ->
        case replay_turn(turn, context) do
          {:ok, context} -> {:cont, {carried, context}}
          {:error, divergence, context} -> {:halt, {divergence, context}}
        end
      end)

    {:ok,
     %{
       verified: is_nil(divergence),
       turns: context.turns,
       records: length(records),
       head: head,
       divergence: divergence,
       events: Enum.reverse(context.events)
     }}
  end

  # ------------------------------------------------------------------ planning

  # Records in sequence order, grouped into the turns a `turn_started` opens and the
  # session-level records between them. The walk stops at the first record that bounds
  # verification, so `steps` is exactly the verifiable prefix and `boundary` names why it
  # ends where it does.
  defp plan(records) do
    records
    |> Enum.chunk_by(&Map.get(&1, "turn_id"))
    |> Enum.reduce_while({[], nil}, fn group, {steps, nil} ->
      case classify(group) do
        {:turn, turn} -> {:cont, {steps ++ [turn], nil}}
        :skip -> {:cont, {steps, nil}}
        {:boundary, reason, seq} -> {:halt, {steps, {:replay_boundary, reason, seq}}}
      end
    end)
  end

  # A group with no `turn_id` is the session speaking between turns. Most of what it says is
  # inert for replay — a session opened, a posture configured, both already carried by the
  # next `turn_started`. The rest rewrote the conversation or admitted losing part of the
  # record, and each of those bounds verification by name.
  defp classify([%{"turn_id" => nil} | _rest] = group) do
    Enum.find_value(group, :skip, fn record ->
      case Map.get(record, "kind") do
        "gap" -> boundary(:gap, record)
        "truncated" -> boundary(:truncated, record)
        "compaction" -> boundary(:compaction, record)
        "rewind" -> boundary(:rewind, record)
        "session_opened" -> opened(record)
        _inert -> nil
      end
    end)
  end

  defp classify([first | _rest] = group) do
    case Enum.find(group, &(Map.get(&1, "kind") == "turn_started")) do
      # The compaction summariser's `compact_N` pair, or a turn whose head the budget
      # truncated away. Either way there is no posture to run a turn from, and inventing one
      # would be the kind of best-effort continuation §5.2 forbids.
      nil -> {:boundary, :unstarted_turn, Map.get(first, "seq")}
      started -> turn(group, started)
    end
  end

  defp opened(record) do
    cond do
      Map.get(record, "resumed") == true -> boundary(:resumed_conversation, record)
      is_binary(Map.get(record, "forked_from_provider_session_id")) -> boundary(:forked, record)
      true -> nil
    end
  end

  defp boundary(reason, record), do: {:boundary, reason, Map.get(record, "seq")}

  defp turn(group, started) do
    settled = Enum.find(group, &(Map.get(&1, "kind") == "turn_settled"))
    prompt = Enum.find(group, &(Map.get(&1, "kind") == "prompt"))
    calls = Enum.filter(group, &(Map.get(&1, "kind") == "model_call"))
    results = Enum.filter(group, &(Map.get(&1, "kind") == "model_result"))
    injections = Enum.filter(group, &(Map.get(&1, "kind") == "injected"))
    unreproducible = Enum.find(injections, &(Map.get(&1, "origin") != "steer"))

    cond do
      # §5.3's crash case: the record reached as far as it reached, the inference entry the
      # loop opened was reconciled `:ambiguous`, and the turn never settled.
      is_nil(settled) ->
        {:boundary, :unsettled_turn, Map.get(started, "seq")}

      length(calls) != length(results) ->
        {:boundary, :ambiguous_inference, Map.get(List.last(calls) || started, "seq")}

      is_nil(prompt) ->
        {:boundary, :no_prompt, Map.get(started, "seq")}

      is_nil(Map.get(settled, "conversation_digest")) ->
        {:boundary, :no_conversation_digest, Map.get(settled, "seq")}

      # A lazily-loaded rule, a `Stop` hook's context, a failing project check: each is a
      # user message the live turn appended from something outside the record — the
      # workspace's rules, the hook configuration, a command's output. This engine runs with
      # empty hooks and no rules by construction, so it would not append them, and a
      # conversation missing a message is a divergence with a boring cause. Named instead.
      unreproducible ->
        {:boundary, {:unreproducible_injection, Map.get(unreproducible, "origin")},
         Map.get(unreproducible, "seq")}

      true ->
        {:turn,
         %{
           turn_id: Map.get(started, "turn_id"),
           started: started,
           prompt: prompt,
           settled: settled,
           calls: Enum.zip(calls, results),
           tool_results: Enum.filter(group, &(Map.get(&1, "kind") == "tool_result")),
           steers: Enum.filter(injections, &(Map.get(&1, "origin") == "steer")),
           first_seq: Map.get(started, "seq"),
           last_seq: group |> List.last() |> Map.get("seq")
         }}
    end
  end

  # ------------------------------------------------------------------ one turn

  defp replay_turn(turn, context) do
    with {:ok, script} <- script(turn, context),
         {:ok, results} <- tool_results(turn, context),
         :ok <- runnable(script, turn),
         {:ok, message} <- Record.prompt(turn.prompt, context.session_dir),
         {:ok, scope} <- scope(turn, context),
         {:ok, prefix} <- prefix(turn, context, scope),
         :ok <- prefix_matches(turn, prefix) do
      execute(turn, context, script, results, message, scope, prefix)
    else
      {:boundary, reason, seq} ->
        {:error, {:replay_boundary, reason, seq}, context}

      {:diverged, fields} ->
        {:error, {:replay_diverged, fields}, context}

      {:error, reason} ->
        {:error, {:replay_boundary, {:unreplayable, reason}, turn.first_seq}, context}
    end
  end

  defp script(turn, context) do
    Enum.reduce_while(turn.calls, {:ok, []}, fn {call, result}, {:ok, acc} ->
      case Record.chunks(result, context.session_dir) do
        {:ok, chunks} ->
          {:cont, {:ok, acc ++ [recorded_call(turn, call, result, chunks)]}}

        {:error, reason} ->
          {:halt, {:boundary, {:unreadable_record, reason}, Map.get(result, "seq")}}
      end
    end)
  end

  defp recorded_call(turn, call, result, chunks) do
    %{
      iteration: Map.get(call, "iteration"),
      seq: Map.get(call, "seq"),
      at: Map.get(result, "at"),
      turn_id: turn.turn_id,
      request_sha256: Map.get(call, "request_sha256"),
      chunks: chunks
    }
  end

  defp tool_results(turn, context) do
    Enum.reduce_while(turn.tool_results, {:ok, %{}}, fn record, {:ok, acc} ->
      case Record.tool_result(record, context.session_dir) do
        {:ok, result} ->
          {:cont, {:ok, Map.put(acc, result.call_id, result)}}

        {:error, reason} ->
          {:halt, {:boundary, {:unreadable_record, reason}, Map.get(record, "seq")}}
      end
    end)
  end

  # Conservative on purpose. A turn is refused if the *record* shows the model asking for a
  # tool at all, not merely if a tool ran: an interrupted turn and a max-iterations turn
  # both hold `tool_call` chunks whose dispatch never happened, and telling those apart from
  # a turn that would dispatch is not a distinction worth betting an executed `bash` on.
  defp runnable(script, turn) do
    calls? = Enum.any?(script, fn %{chunks: chunks} -> Enum.any?(chunks, &tool_call_chunk?/1) end)

    if calls? and not Seam.tool_dispatch_honored?() do
      {:boundary, :tool_source_seam_unwired, seam_seq(turn)}
    else
      :ok
    end
  end

  defp tool_call_chunk?({:tool_call, _call}), do: true
  defp tool_call_chunk?(_chunk), do: false

  defp seam_seq(%{tool_results: [first | _rest]}), do: Map.get(first, "seq")
  defp seam_seq(turn), do: turn.first_seq

  defp scope(turn, context) do
    case Paths.scope(
           workspace(context),
           Keyword.get(context.opts, :add_dirs, []),
           atom(Map.get(turn.started, "sandbox_mode"), :workspace_write)
         ) do
      {:ok, scope} -> {:ok, scope}
      {:error, reason} -> {:boundary, {:workspace_unavailable, reason}, turn.first_seq}
    end
  end

  # The cached prefix, rebuilt from the workspace under the posture the record names. The
  # `model_module` handed to it is the *delegate*, not the replay model: the prefix's
  # fingerprint covers the tool layout, and the tool layout asks the model module whether it
  # supports tool search.
  defp prefix(turn, context, scope) do
    window = Window.resolve(Map.get(turn.started, "model_spec"))

    Context.build(
      system_prompt: Keyword.get(context.opts, :system_prompt),
      cwd: scope.root,
      add_dirs: scope.roots -- [scope.root],
      sandbox_mode: scope.sandbox_mode,
      approval_mode: atom(Map.get(turn.started, "approval_mode"), :prompt),
      tools:
        Tools.specs(
          Keyword.get(context.opts, :allowed_tools),
          Keyword.get(context.opts, :disallowed_tools),
          workspace: scope.root,
          context_window: window,
          subagent_depth: Keyword.get(context.opts, :subagent_depth, 0)
        ),
      model_module: context.delegate,
      model_spec: Map.get(turn.started, "model_spec"),
      context_window: window,
      reasoning_effort: atom(Map.get(turn.started, "reasoning_effort"), nil),
      compactions: 0
    )
    |> case do
      {:ok, prefix} -> {:ok, prefix}
      {:error, reason} -> {:boundary, {:prefix_unbuildable, reason}, turn.first_seq}
    end
  end

  # Checked before the turn runs rather than after, because a prefix that does not match is
  # the cause of every downstream difference and naming it here is the difference between
  # "your workspace changed" and "the conversation diverged".
  defp prefix_matches(turn, prefix) do
    cond do
      mismatch?(turn.started, "system_sha256", text_digest(prefix.system)) ->
        {:diverged,
         diverged(turn, "system_sha256", Map.get(turn.started, "system_sha256"),
           got: text_digest(prefix.system),
           seq: turn.first_seq
         )}

      mismatch?(turn.started, "prefix_fingerprint", prefix.fingerprint) ->
        {:diverged,
         diverged(turn, "prefix_fingerprint", Map.get(turn.started, "prefix_fingerprint"),
           got: prefix.fingerprint,
           seq: turn.first_seq
         )}

      true ->
        :ok
    end
  end

  defp mismatch?(record, key, got) do
    case Map.get(record, key) do
      nil -> false
      recorded -> recorded != got
    end
  end

  defp execute(turn, context, script, results, message, scope, prefix) do
    ReplayModel.install(script, context.delegate)
    collector = collector()
    limit = Keyword.get(context.opts, :event_limit)

    loop = %Loop{
      emit: fn event -> collect(collector, decorate(event, turn, results)) end,
      model_module: ReplayModel,
      model_spec: Map.get(turn.started, "model_spec"),
      system: prefix.system,
      context_window: prefix.context_window,
      prefix_fingerprint: prefix.fingerprint,
      scope: scope,
      # Nothing about a replay may touch the session's directory: the journal is `nil`, the
      # checkpoint is a closure that computes and returns rather than writes, and the file
      # manifest is never reached because no tool ever touches a path.
      session_dir: nil,
      session_id: Keyword.get(context.opts, :session_id),
      provider_session_id: Keyword.get(context.opts, :provider_session_id),
      turn_id: turn.turn_id,
      reasoning_effort: atom(Map.get(turn.started, "reasoning_effort"), nil),
      approval_mode: atom(Map.get(turn.started, "approval_mode"), :prompt),
      allowed_tools: Keyword.get(context.opts, :allowed_tools),
      disallowed_tools: Keyword.get(context.opts, :disallowed_tools),
      subagent_depth: Keyword.get(context.opts, :subagent_depth, 0),
      max_iterations: Map.get(turn.started, "max_iterations") || 100,
      messages: context.messages,
      message_offset: 0,
      hooks: %Hooks{workspace: scope.root},
      journal: nil,
      checkpoint: fn snapshot -> {:ok, digest(snapshot.messages, limit)} end,
      tool_source: Seam.tool_source(results),
      control_feed: control_feed(turn, collector)
    }

    try do
      {:ok, final} = Loop.run_turn(loop, message)
      settle(turn, context, final, collector, limit)
    rescue
      error ->
        {:error, {:replay_boundary, {:turn_raised, Exception.message(error)}, turn.first_seq},
         collected(context, collector)}
    catch
      kind, reason ->
        {:error,
         {:replay_boundary, {:turn_exited, kind, inspect(reason, limit: 6)}, turn.first_seq},
         collected(context, collector)}
    after
      ReplayModel.uninstall()
    end
  end

  # The model seam's finding is read first: it is the more precise of the two, because a
  # request that already diverged makes every later comparison a consequence rather than a
  # cause.
  defp settle(turn, context, final, collector, limit) do
    context = collected(context, collector)
    got = digest(final.messages, limit)
    expected = Map.get(turn.settled, "conversation_digest")

    cond do
      divergence = ReplayModel.divergence() ->
        {:error, {:replay_diverged, divergence}, context}

      got != expected ->
        {:error,
         {:replay_diverged,
          diverged(turn, "conversation_digest", expected,
            got: got,
            seq: Map.get(turn.settled, "seq")
          )}, context}

      true ->
        {:ok, %{context | messages: final.messages, turns: context.turns + 1}}
    end
  end

  defp diverged(turn, field, expected, opts) do
    %{
      seq: Keyword.fetch!(opts, :seq),
      turn_id: turn.turn_id,
      field: field,
      expected_sha256: expected,
      got_sha256: Keyword.fetch!(opts, :got)
    }
  end

  # ------------------------------------------------------------------ the clock (D9)

  # Every event carries the instant of the record it is reproducing. Two of them have a
  # record each — `turn_started` and the terminal — and a tool call and its result share the
  # `tool_result` record that is the only durable trace either has. Everything the model
  # streamed carries the `model_result`'s instant, published by the model seam as it hands
  # the stream over, because that is the one record all of those events came out of.
  defp decorate(event, turn, results), do: Map.put(event, :at, at_for(event, turn, results))

  defp at_for(%{type: :turn_started}, turn, _results), do: Map.get(turn.started, "at")

  defp at_for(%{type: type, payload: payload}, turn, results)
       when type in [:tool_call, :tool_result] do
    case Map.get(results, Map.get(payload, "call_id")) do
      %{at: at} when is_binary(at) -> at
      _unrecorded -> fallback_at(turn)
    end
  end

  defp at_for(%{type: type}, turn, _results)
       when type in [:turn_completed, :turn_failed, :turn_interrupted],
       do: Map.get(turn.settled, "at")

  defp at_for(_event, turn, _results), do: fallback_at(turn)

  defp fallback_at(turn), do: ReplayModel.current_at() || Map.get(turn.started, "at")

  # ------------------------------------------------------------------ control (D7)

  # The mailbox drain, replaced by the order that actually happened. A steer's position is
  # fixed by its `seq` relative to the `tool_result` records around it — R1 dropped the
  # `after_call_id` field precisely because the total order already says this — so a steer
  # is handed over once the loop has reproduced every tool result recorded before it.
  #
  # An interrupt has no record of its own; what the journal says is that the turn settled
  # `interrupted`, and the last record before the settle is where it stopped. So the
  # interrupt is delivered at the first drain after the whole record has been reproduced,
  # which is that same place.
  defp control_feed(turn, collector) do
    total = length(turn.tool_results)
    interrupted? = Map.get(turn.settled, "status") == "interrupted"

    fn state ->
      observed = observed_tool_results(collector)

      state =
        Enum.reduce(turn.steers, state, fn steer, state ->
          if delivered?(collector, steer) or not ready?(steer, turn, observed) do
            state
          else
            deliver(collector, steer)
            %{state | steer: state.steer ++ [steer_message(steer)]}
          end
        end)

      if interrupted? and observed >= total and Enum.empty?(pending(turn, collector)),
        do: %{state | interrupted?: true},
        else: state
    end
  end

  defp ready?(steer, turn, observed) do
    before = Enum.count(turn.tool_results, &(Map.get(&1, "seq") < Map.get(steer, "seq")))
    observed >= before
  end

  defp pending(turn, collector),
    do: Enum.reject(turn.steers, &delivered?(collector, &1))

  defp steer_message(steer) do
    case Map.get(steer, "content") do
      content when is_binary(content) -> %{role: :user, content: content}
      other -> %{role: :user, content: inspect(other)}
    end
  end

  # ------------------------------------------------------------------ collection

  # The loop runs the whole turn in the calling process — `run_turn/2` is a function call,
  # not a cast — so the events, the delivered steers and the observed tool results all live
  # in that process's own dictionary. Race-free by construction, and nothing to clean up.
  defp collector, do: {__MODULE__, make_ref()}

  defp collect(collector, event) do
    Process.put(collector, [event | Process.get(collector, [])])

    if event.type == :tool_result do
      Process.put({collector, :tool_results}, observed_tool_results(collector) + 1)
    end

    :ok
  end

  defp observed_tool_results(collector), do: Process.get({collector, :tool_results}, 0)

  defp delivered?(collector, steer),
    do: Map.get(steer, "seq") in Process.get({collector, :steers}, [])

  defp deliver(collector, steer) do
    delivered = Process.get({collector, :steers}, [])
    Process.put({collector, :steers}, [Map.get(steer, "seq") | delivered])
    :ok
  end

  # Newest-first throughout, flipped once by the caller: a turn that streamed ten thousand
  # text deltas must not pay for an append per delta.
  defp collected(context, collector) do
    events = Process.get(collector, [])
    Process.delete(collector)
    Process.delete({collector, :tool_results})
    Process.delete({collector, :steers})
    %{context | events: events ++ context.events}
  end

  # ------------------------------------------------------------------ helpers

  defp workspace(context), do: Keyword.get(context.opts, :workspace) || File.cwd!()

  defp digest(messages, limit) when is_integer(limit),
    do: Checkpoint.digest_of(messages, event_limit: limit)

  defp digest(messages, _unset), do: Checkpoint.digest_of(messages)

  defp text_digest(text) when is_binary(text),
    do: :sha256 |> :crypto.hash(text) |> Base.encode16(case: :lower)

  defp text_digest(_text), do: nil

  defp atom(nil, default), do: default
  defp atom(value, _default) when is_atom(value), do: value

  defp atom(value, default) when is_binary(value) do
    String.to_existing_atom(value)
  rescue
    ArgumentError -> default
  end
end
