defmodule Ouroboros.Web.Transcript do
  @moduledoc """
  One watched session's ordered history, projected into display cells.

  Port of `project()` (`tui/src/ui/transcript_cells.rs:841`) and the entry interleaving of
  `Watch::entries` (`tui/src/ui/transcript.rs:1237`).

  ## Clock-free and filesystem-free, by contract

  Nothing here reads a clock or touches disk. That is what keeps one watch rendering and
  exporting to the same bytes, and it is why a still-running tool is measured against the
  newest instant *the ledger holds* rather than against `System.monotonic_time/0`
  (`tui/src/ui/transcript_cells.rs:3`, `:849`, `:858-861`).

  ## What this module does not own

  Cursors, resync, subscription and trimming. The LiveView holds those; `entries/2` takes
  the events, the floor, the notes and the ended status it is given and interleaves them.
  """

  alias Ouroboros.Web.Presentation

  alias Ouroboros.Web.Presentation.{
    AgentText,
    ApprovalRequested,
    ApprovalResolved,
    CommandOutput,
    Compaction,
    DelegationEvent,
    Failure,
    FileUpdate,
    Hidden,
    Interrupted,
    Lifecycle,
    PlanUpdate,
    ProviderNote,
    QueueChanged,
    RunStart,
    ShellEvent,
    SubagentEvent,
    Thinking,
    ToolCall,
    ToolResult,
    TurnEnded,
    TurnStarted,
    UnrecordedInput,
    UsageReport,
    UserMessage,
    UserSteer
  }

  alias Ouroboros.Web.Transcript.{Approval, Cell, Entry, Text, Tools}
  alias Ouroboros.Web.Transcript.Diff, as: ParsedDiff

  @doc """
  How many ledger entries a conversation pane projects.

  A redraw budget, not a retention policy: the surface is bounded to a useful recent
  suffix and says how much it is not drawing.
  """
  def chat_entry_window, do: 128

  # How many calls one grouped exploration cell lists before it starts counting instead.
  @exploration_calls 64
  # How many rows of a runtime block's body are drawn before the count takes over.
  @block_head 8
  @block_tail 6

  @agent_output_bytes 128 * 1024
  @command_output_bytes 64 * 1024
  @thinking_bytes 128 * 1024

  @agent_truncation "\n… agent stream truncated; full updates are available in event details"
  @command_truncation "\n… command stream truncated; full updates are available in event details"
  @thinking_truncation "\n… reasoning truncated; full text is available in event details"

  # ------------------------------------------------------------------------------------
  # Entries
  # ------------------------------------------------------------------------------------

  @doc """
  The transcript in order, with the dividers interleaved where they belong.

  `events` is a sequence-keyed map. Options:

    * `:floor` — no history at or below this sequence, whether the runtime pruned it or
      the view dropped it. The marker sits **where the hole is**, not at the top: events
      obtained before a prune are real history, and dropping them to make the divider sit
      at the top would delete a transcript an operator is reading
      (`tui/src/ui/transcript.rs:1038-1043`).
    * `:notes` — a sequence-keyed map of `Entry.Note` notes, anchored at the sequence they
      were recorded after.
    * `:ended` — the terminal status, once `stream.ended` said so.
  """
  @spec entries(%{optional(non_neg_integer()) => map()}, keyword()) :: [Entry.t()]
  def entries(events, opts \\ []) when is_map(events) do
    floor = Keyword.get(opts, :floor, 0)
    notes = Keyword.get(opts, :notes, %{})
    ended = Keyword.get(opts, :ended)

    ordered = Enum.sort_by(Map.to_list(events), &elem(&1, 0))
    note_list = Enum.sort_by(Map.to_list(notes), &elem(&1, 0))

    {entries, floor_emitted, notes_from, _previous} =
      Enum.reduce(ordered, {[], floor == 0, 0, nil}, fn {sequence, event},
                                                        {entries, floor_emitted, notes_from,
                                                         previous} ->
        {entries, floor_emitted, notes_from, previous} =
          if not floor_emitted and sequence > floor do
            entries = emit_notes(entries, note_list, notes_from, floor)
            # Nothing is missing across a floor: what is below it is not a hole this view
            # can fill, and drawing both markers would say it twice.
            {[%Entry.Floor{sequence: floor} | entries], true, floor + 1, nil}
          else
            {entries, floor_emitted, notes_from, previous}
          end

        entries =
          case previous do
            previous when is_integer(previous) and sequence > previous + 1 ->
              [%Entry.Gap{from: previous + 1, to: sequence - 1} | entries]

            _contiguous ->
              entries
          end

        entries =
          entries
          |> emit_notes(note_list, notes_from, sequence)
          |> then(&[%Entry.Event{event: event} | &1])

        {entries, floor_emitted, sequence + 1, sequence}
      end)

    {entries, notes_from} =
      if floor_emitted do
        {entries, notes_from}
      else
        entries = emit_notes(entries, note_list, notes_from, floor)
        {[%Entry.Floor{sequence: floor} | entries], max(notes_from, floor + 1)}
      end

    entries =
      note_list
      |> Enum.filter(fn {at, _note} -> at >= notes_from end)
      |> Enum.reduce(entries, fn {_at, note}, acc -> [%Entry.Note{note: note} | acc] end)

    entries = if is_binary(ended), do: [%Entry.Ended{status: ended} | entries], else: entries

    Enum.reverse(entries)
  end

  defp emit_notes(entries, note_list, from, through) do
    if from > through do
      entries
    else
      note_list
      |> Enum.filter(fn {at, _note} -> at >= from and at <= through end)
      |> Enum.reduce(entries, fn {_at, note}, acc -> [%Entry.Note{note: note} | acc] end)
    end
  end

  # ------------------------------------------------------------------------------------
  # Interactive state, rebuilt from the whole ordered ledger
  # ------------------------------------------------------------------------------------

  @doc """
  The approvals this session is still waiting on, oldest first.

  **Rebuilt from the whole ordered ledger on every absorb, never folded incrementally.**
  Live notifications and replay responses are not ordered against each other, so folding
  as batches arrive can apply an older request after its newer resolution. The ordered
  map is the authority: replay overlap is idempotent, and one ordered pass makes approval
  state independent of arrival order. The hazard is the same in-process as it is on a
  socket (`tui/src/ui/transcript.rs:1331-1337`).
  """
  @spec pending_approvals(%{optional(non_neg_integer()) => map()}) :: [Approval.t()]
  def pending_approvals(events) when is_map(events) do
    events
    |> Map.to_list()
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.reduce(%{}, fn {sequence, event}, pending ->
      case {Map.get(event, :type), Map.get(event, :request_id)} do
        {_type, nil} ->
          pending

        {:approval_requested, request_id} ->
          Map.put(pending, sequence, %Approval{
            request_id: request_id,
            sequence: sequence,
            turn_id: Map.get(event, :turn_id),
            payload: payload_of(event)
          })

        {:approval_resolved, request_id} ->
          :maps.filter(fn _at, request -> request.request_id != request_id end, pending)

        _other ->
          pending
      end
    end)
    |> Map.to_list()
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.map(&elem(&1, 1))
  end

  @doc """
  B2. Whether this session is planning, where an event said so.

  `nil` means no event has spoken, which is not the same as `false`: a session list that
  predates plan mode and a runtime that just left plan mode are different facts, and only
  the second one should be able to take a badge *down*
  (`tui/src/ui/transcript.rs:1321-1329`).
  """
  @spec planning(%{optional(non_neg_integer()) => map()}) :: boolean() | nil
  def planning(events) when is_map(events) do
    events
    |> Map.to_list()
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.reduce(nil, fn {_sequence, event}, planning ->
      payload = payload_of(event)

      case {Map.get(event, :type), Map.get(payload, "kind")} do
        {:provider_event, "plan_exit"} ->
          bool_or(Map.get(payload, "plan"), planning)

        {:status, "configured"} ->
          bool_or(get_in_map(payload, ["changed", "plan"]), planning)

        _other ->
          planning
      end
    end)
  end

  defp bool_or(value, _fallback) when is_boolean(value), do: value
  defp bool_or(_value, fallback), do: fallback

  defp get_in_map(map, [key]) when is_map(map), do: Map.get(map, key)

  defp get_in_map(map, [key | rest]) when is_map(map) do
    case Map.get(map, key) do
      nested when is_map(nested) -> get_in_map(nested, rest)
      _otherwise -> nil
    end
  end

  defp get_in_map(_map, _path), do: nil

  defp payload_of(event) do
    case Map.get(event, :payload) do
      payload when is_map(payload) and not is_struct(payload) -> Presentation.wire_shape(payload)
      _absent -> %{}
    end
  end

  @doc "Whether a request is a question for a person rather than a permission."
  @spec question?(Approval.t()) :: boolean()
  defdelegate question?(request), to: Approval

  @doc "The rule the card's fifth answer would write, or the reason there is no fifth answer."
  @spec suggested_rule(String.t() | nil, [String.t()], String.t() | nil) ::
          {Approval.Rule.t() | nil, String.t() | nil}
  defdelegate suggested_rule(pattern, methods, workspace), to: Approval

  # ------------------------------------------------------------------------------------
  # Projection
  # ------------------------------------------------------------------------------------

  @doc "Projects one ordered durable transcript into display cells."
  @spec project([Entry.t()]) :: [Cell.t()]
  def project(entries) when is_list(entries) do
    # What this surface has already drawn in full from an operator verb's own reply, so
    # the runtime's durable record of the same act is not drawn beside it. Gathered in a
    # pass of its own because the two can arrive in either order: the reply usually lands
    # first, but a replay after a reconnect delivers the event before anything else.
    drawn_locally =
      for %Entry.Note{note: {:local, block}} <- entries,
          is_binary(block.key),
          into: MapSet.new(),
          do: block.key

    entries
    |> Enum.reduce(new_state(drawn_locally), &absorb_entry/2)
    |> flush_agent(true)
    |> settle_thinking()
    |> settle_exploration()
    |> settle_running_tools()
    |> materialise()
  end

  defp new_state(drawn_locally) do
    %{
      cells: %{},
      count: 0,
      pending: nil,
      thinking: nil,
      tools: %{},
      # Which row each child agent owns, so its sixty-four progress reports rewrite one
      # cell instead of appending sixty-four.
      subagents: %{},
      approvals: %{},
      # Diff cells an outstanding approval is about, so its resolution can collapse them.
      approval_diffs: %{},
      # Approval subjects still unanswered, so a diff that arrives after the request can
      # tell that it is the thing being asked about.
      open_approvals: [],
      # Which cells hold the diffs seen since the last turn boundary, for that turn's stat.
      turn_diffs: [],
      # The newest instant the ledger holds. A projection reads no clock, so this is the
      # only "now" a still-running tool can honestly be measured against.
      newest_at: nil,
      # Turn start instants, so a turn-end divider can state elapsed time instead of
      # implying one. A turn whose start this window no longer holds gets no duration.
      turn_starts: %{},
      # The last queue depth projected, so an unchanged count is not restated.
      queued: :unset,
      drawn_locally: drawn_locally
    }
  end

  defp materialise(state) do
    Enum.map(0..(state.count - 1)//1, &Map.fetch!(state.cells, &1))
  end

  defp push(state, cell) do
    {%{state | cells: Map.put(state.cells, state.count, cell), count: state.count + 1},
     state.count}
  end

  defp push!(state, cell), do: state |> push(cell) |> elem(0)

  defp put_at(state, index, cell), do: %{state | cells: Map.put(state.cells, index, cell)}

  defp at(state, index), do: Map.get(state.cells, index)

  defp last_index(state), do: state.count - 1

  # ------------------------------------------------------------------------------------

  defp absorb_entry(%Entry.Floor{}, state) do
    state
    |> flush_agent(false)
    |> push!(%Cell.Divider{
      text: "Earlier conversation is no longer available",
      tone: :warning,
      kind: :other
    })
  end

  defp absorb_entry(%Entry.Gap{from: from, to: to}, state) do
    state
    |> flush_agent(false)
    |> push!(%Cell.Divider{
      text: "Restoring #{to - from + 1} missing updates",
      tone: :warning,
      kind: :other
    })
  end

  defp absorb_entry(%Entry.Note{note: {:local, block}}, state) do
    state |> flush_agent(false) |> push!(block)
  end

  defp absorb_entry(%Entry.Note{note: {:image, cell}}, state) do
    state |> flush_agent(false) |> push!(cell)
  end

  defp absorb_entry(%Entry.Note{note: note}, state) do
    state
    |> flush_agent(false)
    |> push!(%Cell.Divider{text: chat_note(note), tone: :warning, kind: :other})
  end

  defp absorb_entry(%Entry.Ended{status: status}, state) do
    state
    |> flush_agent(false)
    |> push!(%Cell.Divider{text: "Session ended (#{status})", tone: :muted, kind: :other})
  end

  defp absorb_entry(%Entry.Event{event: event}, state) do
    state =
      case Presentation.epoch_millis(Map.get(event, :timestamp)) do
        nil -> state
        at -> %{state | newest_at: max(state.newest_at || at, at)}
      end

    project_event(state, Presentation.from_event(event))
  end

  # The divider text for a *stream* note, and only for a stream note. A local note never
  # reaches this — the clause above turns it into a runtime block, because nothing about
  # it went wrong — and nor does an image note, for the same reason. `Entry.Note.text/1`
  # is where those two are worded.
  defp chat_note({:lagged, _dropped}), do: "Some live updates were missed by the gateway"
  defp chat_note(:client_dropped), do: "Some live updates were missed by this client"
  defp chat_note(:reconnected), do: "Connection restored"

  # ------------------------------------------------------------------------------------
  # The per-presentation arms
  # ------------------------------------------------------------------------------------

  defp project_event(state, %UserMessage{text: text}) do
    state
    |> flush_agent(false)
    |> push!(%Cell.Message{speaker: :you, text: text, streaming: false})
  end

  defp project_event(state, %UserSteer{text: text}) do
    state
    |> flush_agent(false)
    |> push!(%Cell.ChatNote{
      text:
        case text do
          nil -> "You steered the agent"
          text -> "You steered the agent: #{text}"
        end
    })
  end

  defp project_event(state, %UnrecordedInput{}) do
    state |> flush_agent(false) |> push!(%Cell.ChatNote{text: "[message not recorded]"})
  end

  defp project_event(state, %AgentText{turn_id: turn_id, text: text, final_text: final?}) do
    project_agent_text(state, turn_id, text, final?)
  end

  defp project_event(state, %Thinking{turn_id: turn_id, text: text}) do
    state |> flush_agent(false) |> project_thinking(turn_id, text)
  end

  defp project_event(state, %PlanUpdate{} = plan) do
    state |> flush_agent(false) |> push!(%Cell.Plan{plan: plan})
  end

  # Folded into the session total the header and footer read. The per-event line is
  # verbose-only, where the reader has asked for the bookkeeping.
  defp project_event(state, %UsageReport{} = usage) do
    state = flush_agent(state, false)

    if UsageReport.empty?(usage) do
      state
    else
      push!(state, %Cell.Usage{usage: usage})
    end
  end

  defp project_event(state, %RunStart{} = run) do
    state |> flush_agent(false) |> push!(%Cell.ChatNote{text: run_started_note(run)})
  end

  # No cell: a running turn is already announced by the working indicator. The instant is
  # kept so the turn's own end divider can state how long it took.
  defp project_event(state, %TurnStarted{turn_id: turn_id, at: at})
       when is_binary(turn_id) and is_integer(at) do
    %{state | turn_starts: Map.put_new(state.turn_starts, turn_id, at)}
  end

  defp project_event(state, %TurnStarted{}), do: state

  defp project_event(state, %TurnEnded{} = ended) do
    state
    |> flush_agent(false)
    |> project_diffstat()
    |> project_turn_end(ended)
  end

  defp project_event(state, %QueueChanged{queued: depth}) do
    if state.queued == depth do
      state
    else
      %{state | queued: depth}
      |> flush_agent(false)
      |> push!(%Cell.ChatNote{
        text:
          case depth do
            0 -> "The follow-up queue is empty"
            1 -> "1 follow-up is queued"
            depth -> "#{depth} follow-ups are queued"
          end
      })
    end
  end

  defp project_event(state, %Lifecycle{marker: marker, detail: detail}) do
    state |> flush_agent(false) |> project_lifecycle(marker, detail)
  end

  defp project_event(state, %ProviderNote{kind: kind, detail: detail}) do
    state
    |> flush_agent(false)
    |> push!(%Cell.ChatNote{text: provider_note_text(kind, detail)})
  end

  # B7/D9. Both of these have a reply this surface may already have drawn in full. Where
  # it did, the durable record is skipped rather than drawn a second time in a thinner
  # form — and where it did not (a second viewer, a session reopened after a restart),
  # this is the only copy and it is drawn.
  defp project_event(state, %ShellEvent{} = shell) do
    state |> flush_agent(false) |> push_deduped(shell_block(shell))
  end

  defp project_event(state, %Compaction{} = report) do
    state |> flush_agent(false) |> push_deduped(compaction_block(report))
  end

  defp project_event(state, %DelegationEvent{} = delegation) do
    state |> flush_agent(false) |> push!(delegation_block(delegation))
  end

  defp project_event(state, %SubagentEvent{} = event) do
    state |> flush_agent(false) |> project_subagent(event)
  end

  defp project_event(state, %ToolCall{} = call) do
    state |> flush_agent(false) |> project_tool_call(call)
  end

  defp project_event(state, %ToolResult{} = result) do
    state |> flush_agent(false) |> project_tool_result(result)
  end

  defp project_event(state, %CommandOutput{text: text}) do
    state |> flush_agent(false) |> append_command_output(text)
  end

  defp project_event(state, %FileUpdate{} = update) do
    state = flush_agent(state, false)

    inferred_diff_path =
      case update.changes do
        [%{path: path}] -> path
        _many_or_none -> nil
      end

    state =
      Enum.reduce(update.changes, state, fn change, state ->
        project_file(state, change, update.status)
      end)

    state =
      if update.changes == [] and is_nil(update.diff) do
        push!(state, %Cell.File{path: nil, kind: update.status})
      else
        state
      end

    case update.diff do
      nil ->
        state

      diff ->
        diff = if is_nil(diff.path), do: %{diff | path: inferred_diff_path}, else: diff
        project_diff(state, diff)
    end
  end

  defp project_event(state, %ApprovalRequested{request_id: request_id, detail: detail}) do
    state = flush_agent(state, false)
    index = state.count

    state =
      if is_binary(request_id) do
        %{state | approvals: Map.put(state.approvals, request_id, index)}
      else
        state
      end

    %{state | open_approvals: state.open_approvals ++ [{request_id, detail}]}
    |> push!(%Cell.Status{label: "Approval needed", detail: detail, tone: :warning})
  end

  defp project_event(state, %ApprovalResolved{} = resolved) do
    state
    |> flush_agent(false)
    |> settle_approved_diffs(resolved.request_id)
    |> project_approval_resolution(resolved.request_id, resolved.decision, resolved.detail)
  end

  defp project_event(state, %Failure{detail: detail}) do
    state
    |> flush_agent(false)
    |> push!(%Cell.Status{label: "Agent error", detail: detail, tone: :error})
  end

  defp project_event(state, %Interrupted{detail: detail}) do
    state
    |> flush_agent(false)
    |> push!(%Cell.Status{label: "Interrupted", detail: detail, tone: :warning})
  end

  # Drawn as nothing, for a reason the presentation recorded. The event itself is still
  # available in full.
  defp project_event(state, %Hidden{}), do: state

  defp push_deduped(state, block) do
    if is_binary(block.key) and MapSet.member?(state.drawn_locally, block.key) do
      state
    else
      push!(state, block)
    end
  end

  # ------------------------------------------------------------------------------------
  # Agent text
  # ------------------------------------------------------------------------------------

  defp project_agent_text(state, turn_id, text, final?) do
    same_turn =
      case state.pending do
        nil -> not final?
        draft -> draft.turn_id == turn_id or is_nil(draft.turn_id) or is_nil(turn_id)
      end

    state = if same_turn, do: state, else: flush_agent(state, false)

    cond do
      final? ->
        fallback = if state.pending, do: state.pending.text, else: ""
        state = %{state | pending: nil}
        text = if text == "", do: fallback, else: text

        if String.trim(text) == "" do
          state
        else
          push!(state, %Cell.Message{speaker: :agent, text: text, streaming: false})
        end

      text == "" ->
        state

      true ->
        draft = state.pending || %{turn_id: turn_id, text: ""}

        {appended, _spent} =
          Text.append_bounded(draft.text, text, @agent_output_bytes, @agent_truncation)

        %{state | pending: %{draft | text: appended}}
    end
  end

  defp flush_agent(%{pending: nil} = state, _streaming), do: state

  defp flush_agent(%{pending: draft} = state, streaming) do
    state = %{state | pending: nil}

    if String.trim(draft.text) == "" do
      state
    else
      push!(state, %Cell.Message{speaker: :agent, text: draft.text, streaming: streaming})
    end
  end

  # ------------------------------------------------------------------------------------
  # Thinking
  # ------------------------------------------------------------------------------------

  defp project_thinking(state, turn_id, text) do
    open =
      case state.thinking do
        %{index: index, turn_id: open_turn} ->
          index + 1 == state.count and
            (open_turn == turn_id or is_nil(open_turn) or is_nil(turn_id)) and
            match?(%Cell.Thinking{}, at(state, index))

        nil ->
          false
      end

    if open do
      index = state.thinking.index
      %Cell.Thinking{} = cell = at(state, index)

      {appended, _spent} =
        Text.append_bounded(cell.text, text, @thinking_bytes, @thinking_truncation)

      put_at(state, index, %{cell | text: appended, lines: Text.line_count(appended)})
    else
      state = %{state | thinking: %{turn_id: turn_id, index: state.count}}

      push!(state, %Cell.Thinking{
        lines: Text.line_count(text),
        text: Text.bounded_copy(text, @thinking_bytes, @thinking_truncation),
        state: :tail
      })
    end
  end

  # Reasoning is watched while it is still arriving and folds away once it is not.
  #
  # "Still arriving" is exactly "nothing has been drawn after it yet", so the rule needs
  # no bookkeeping: every reasoning cell but the last one is collapsed to its header
  # (`tui/src/ui/transcript_cells.rs:1230`).
  defp settle_thinking(state) do
    last = last_index(state)

    cells =
      Map.new(state.cells, fn
        {index, %Cell.Thinking{} = cell} ->
          {index, %{cell | state: if(index == last, do: :tail, else: :collapsed)}}

        entry ->
          entry
      end)

    %{state | cells: cells}
  end

  # A grouped exploration cell is open exactly while it is the last thing drawn. The rule
  # needs no bookkeeping because it is the same statement as the requirement:
  # "consecutive, with no other cell between them".
  defp settle_exploration(state) do
    last = last_index(state)

    cells =
      Map.new(state.cells, fn
        {index, %Cell.Exploration{} = group} -> {index, %{group | done: index != last}}
        entry -> entry
      end)

    %{state | cells: cells}
  end

  # Gives every still-running tool the newest instant this window holds, so its row can
  # state a floor on how long it has been running.
  defp settle_running_tools(%{newest_at: nil} = state), do: state

  defp settle_running_tools(state) do
    settle = fn
      %Cell.Tool{state: :running, settled_at: nil} = tool -> %{tool | settled_at: state.newest_at}
      tool -> tool
    end

    cells =
      Map.new(state.cells, fn
        {index, %Cell.Tool{} = tool} ->
          {index, settle.(tool)}

        {index, %Cell.Exploration{} = group} ->
          {index, %{group | calls: Enum.map(group.calls, settle)}}

        entry ->
          entry
      end)

    %{state | cells: cells}
  end

  # ------------------------------------------------------------------------------------
  # Tools
  # ------------------------------------------------------------------------------------

  defp project_tool_call(state, %ToolCall{} = call) do
    slot = call.call_id && Map.get(state.tools, call.call_id)

    case slot && tool_at(state, slot) do
      %Cell.Tool{} = tool ->
        # Some providers repeat the normalized call when publishing its result. Refresh
        # the descriptive fields but retain the row's lifecycle and output.
        update_tool_at(state, slot, %{
          tool
          | name: call.name,
            kind: call.kind || tool.kind,
            input: call.input
        })

      _absent ->
        cell = %Cell.Tool{
          call_id: call.call_id,
          name: call.name,
          kind: call.kind,
          input: call.input,
          started_at: call.at
        }

        if Tools.explores?(Tools.summarise(cell).shape) do
          group_exploration(state, call.call_id, cell)
        else
          state =
            if is_binary(call.call_id) do
              %{state | tools: Map.put(state.tools, call.call_id, {state.count, nil})}
            else
              state
            end

          push!(state, cell)
        end
    end
  end

  # Codex's coalescing: an exploration call joins the group already at the end of the
  # transcript, or opens a new one.
  defp group_exploration(state, call_id, cell) do
    index = max(state.count - 1, 0)

    case at(state, index) do
      %Cell.Exploration{} = group when state.count > 0 ->
        if length(group.calls) < @exploration_calls do
          entry = length(group.calls)

          state =
            if is_binary(call_id) do
              %{state | tools: Map.put(state.tools, call_id, {index, entry})}
            else
              state
            end

          put_at(state, index, %{group | calls: group.calls ++ [cell]})
        else
          # Past the listing ceiling the call is counted, not held. What this cell would
          # lose by holding them is the bound that keeps one runaway loop from owning the
          # transcript.
          put_at(state, index, %{group | overflow: group.overflow + 1})
        end

      _not_a_group ->
        state =
          if is_binary(call_id) do
            %{state | tools: Map.put(state.tools, call_id, {state.count, 0})}
          else
            state
          end

        push!(state, %Cell.Exploration{calls: [cell], overflow: 0, done: false})
    end
  end

  defp tool_at(state, {index, nil}) do
    case at(state, index) do
      %Cell.Tool{} = tool -> tool
      _otherwise -> nil
    end
  end

  defp tool_at(state, {index, entry}) do
    case at(state, index) do
      %Cell.Exploration{calls: calls} -> Enum.at(calls, entry)
      _otherwise -> nil
    end
  end

  defp update_tool_at(state, {index, nil}, tool), do: put_at(state, index, tool)

  defp update_tool_at(state, {index, entry}, tool) do
    case at(state, index) do
      %Cell.Exploration{calls: calls} = group ->
        put_at(state, index, %{group | calls: List.replace_at(calls, entry, tool)})

      _otherwise ->
        state
    end
  end

  # Taken before the result is consumed so the tool cell and its image cells are the same
  # two-step every surface reads: the tool row, then the picture it produced. The
  # fs-free contract holds because these artifacts arrive on the event and are minted from
  # it — nothing here stats a file or reads a clock.
  defp project_tool_result(state, %ToolResult{} = result) do
    artifacts = result.artifacts

    state
    |> merge_or_push_tool_result(%{result | artifacts: []})
    |> then(fn state ->
      Enum.reduce(artifacts, state, fn artifact, state ->
        push!(state, Cell.Image.from_artifact(artifact))
      end)
    end)
  end

  defp merge_or_push_tool_result(state, %ToolResult{} = result) do
    slot = result.call_id && Map.get(state.tools, result.call_id)

    case slot && tool_at(state, slot) do
      %Cell.Tool{} = tool ->
        tool = if tool.name == "tool" and result.name, do: %{tool | name: result.name}, else: tool
        tool = if is_nil(tool.kind), do: %{tool | kind: result.kind}, else: tool

        tool = %{
          tool
          | state: if(result.is_error, do: :failed, else: :completed),
            settled_at: result.at
        }

        # Command-output deltas carry no call id, so their presence cannot prove that this
        # result is duplicate. Keep the correlated authoritative result visible; hiding it
        # because another parallel command streamed would lose evidence.
        tool = if is_nil(result.output), do: tool, else: %{tool | output: result.output}

        update_tool_at(state, slot, tool)

      _absent ->
        push!(state, %Cell.Tool{
          call_id: result.call_id,
          name: result.name || "tool result",
          kind: result.kind,
          input: %{},
          output: result.output,
          state: if(result.is_error, do: :failed, else: :completed),
          settled_at: result.at
        })
    end
  end

  defp append_command_output(state, text) do
    index = last_index(state)

    case at(state, index) do
      %Cell.CommandOutput{} = cell when state.count > 0 ->
        {appended, _spent} =
          Text.append_bounded(cell.text, text, @command_output_bytes, @command_truncation)

        put_at(state, index, %{cell | text: appended})

      _otherwise ->
        if text == "" do
          state
        else
          push!(state, %Cell.CommandOutput{
            text: Text.bounded_copy(text, @command_output_bytes, @command_truncation)
          })
        end
    end
  end

  # ------------------------------------------------------------------------------------
  # Files, diffs and the post-turn stat
  # ------------------------------------------------------------------------------------

  defp project_file(state, change, inherited_status) do
    state = push!(state, %Cell.File{path: change.path, kind: change.kind || inherited_status})

    case change.diff do
      nil ->
        state

      diff ->
        diff = if is_nil(diff.path), do: %{diff | path: change.path}, else: diff
        project_diff(state, diff)
    end
  end

  # Pushes one diff cell, parsed, with Warp's pending-approval state resolved.
  defp project_diff(state, diff) do
    parsed = ParsedDiff.parse(diff.text, diff.path)
    index = state.count

    {pending_approval, approval_diffs} =
      Enum.reduce(state.open_approvals, {false, state.approval_diffs}, fn {request_id, subject},
                                                                          {pending, diffs} ->
        if mentions_any?(subject, parsed, diff.path) do
          diffs =
            if is_binary(request_id) do
              Map.update(diffs, request_id, [index], &(&1 ++ [index]))
            else
              diffs
            end

          {true, diffs}
        else
          {pending, diffs}
        end
      end)

    %{state | approval_diffs: approval_diffs, turn_diffs: state.turn_diffs ++ [index]}
    |> push!(%Cell.Diff{diff: diff, parsed: parsed, pending_approval: pending_approval})
  end

  # Whether an outstanding approval's subject names any path this diff touches.
  #
  # Deliberately a containment test on the paths the *diff* reported, not a parse of the
  # approval payload: the payload's shape differs per dialect, and a surface that guessed
  # wrong would mark an unrelated change "pending approval" — a claim about authority
  # (`tui/src/ui/transcript_cells.rs:2294-2313`).
  defp mentions_any?(subject, parsed, fallback) do
    candidates =
      Enum.map(parsed.files, & &1.path) ++ if(is_nil(fallback), do: [], else: [fallback])

    candidates
    |> Enum.reject(&(&1 == ""))
    |> Enum.any?(fn path ->
      String.contains?(subject, path) or
        ((name = path |> String.split("/") |> List.last()) != nil and
           byte_size(name) > 3 and String.contains?(subject, name))
    end)
  end

  # Warp's second half: once the approval resolves, its diffs collapse back to their
  # header. A resolution with no id cannot be matched to one request, so nothing is
  # collapsed on the strength of it.
  defp settle_approved_diffs(state, nil), do: state

  defp settle_approved_diffs(state, request_id) do
    {indices, approval_diffs} = Map.pop(state.approval_diffs, request_id, [])

    state = %{
      state
      | approval_diffs: approval_diffs,
        open_approvals: Enum.reject(state.open_approvals, &(elem(&1, 0) == request_id))
    }

    Enum.reduce(indices, state, fn index, state ->
      case at(state, index) do
        %Cell.Diff{} = diff -> put_at(state, index, %{diff | pending_approval: false})
        _otherwise -> state
      end
    end)
  end

  # The post-turn diffstat, counted from the parses rather than from any provider's
  # summary.
  defp project_diffstat(%{turn_diffs: []} = state), do: state

  defp project_diffstat(state) do
    indices = state.turn_diffs
    state = %{state | turn_diffs: []}

    {paths, additions, deletions, in_excerpt} =
      Enum.reduce(indices, {[], 0, 0, false}, fn index, {paths, additions, deletions, excerpt} ->
        case at(state, index) do
          %Cell.Diff{} = cell ->
            excerpt = excerpt or cell.parsed.truncated or cell.diff.truncated

            Enum.reduce(cell.parsed.files, {paths, additions, deletions, excerpt}, fn file,
                                                                                      {paths,
                                                                                       additions,
                                                                                       deletions,
                                                                                       excerpt} ->
              paths = if file.path in paths, do: paths, else: paths ++ [file.path]
              {paths, additions + file.additions, deletions + file.deletions, excerpt}
            end)

          _otherwise ->
            {paths, additions, deletions, excerpt}
        end
      end)

    if paths == [] do
      state
    else
      push!(state, %Cell.DiffStat{
        files: length(paths),
        additions: additions,
        deletions: deletions,
        in_excerpt: in_excerpt
      })
    end
  end

  # ------------------------------------------------------------------------------------
  # Approvals
  # ------------------------------------------------------------------------------------

  defp project_approval_resolution(state, request_id, decision, resolution) do
    {label, tone} = approval_outcome(decision)
    {index, approvals} = Map.pop(state.approvals, request_id)
    state = %{state | approvals: approvals}

    case index && at(state, index) do
      %Cell.Status{} = status ->
        detail =
          if String.trim(resolution) != "" and resolution != "{}" do
            if String.trim(status.detail) == "" do
              status.detail <> resolution
            else
              status.detail <> "\n" <> resolution
            end
          else
            status.detail
          end

        put_at(state, index, %{status | label: label, tone: tone, detail: detail})

      _absent ->
        push!(state, %Cell.Status{label: label, detail: resolution, tone: tone})
    end
  end

  defp approval_outcome(decision) when decision in ["approve", "approved"],
    do: {"Approved", :success}

  defp approval_outcome(decision) when decision in ["deny", "denied", "decline", "declined"],
    do: {"Denied", :warning}

  defp approval_outcome(_decision), do: {"Approval resolved", :muted}

  # ------------------------------------------------------------------------------------
  # Lifecycle, turns and notes
  # ------------------------------------------------------------------------------------

  defp project_lifecycle(state, marker, detail) do
    label = Lifecycle.label(marker)
    detail = String.trim(detail)

    # `session_closed` carries `{"reason": "closed"}`, which would otherwise read as
    # "session closed · closed". A detail the label already contains adds nothing.
    text =
      if detail == "" or String.contains?(label, String.downcase(detail, :ascii)) do
        label
      else
        "#{label} · #{detail}"
      end

    # A closed session is the end of the reading path, so it reads as a rule across it
    # rather than as another muted aside.
    case marker do
      :session_closed -> push!(state, %Cell.Divider{text: text, tone: :muted, kind: :other})
      _otherwise -> push!(state, %Cell.ChatNote{text: text})
    end
  end

  defp project_turn_end(state, %TurnEnded{} = ended) do
    # A failure is still a failure: the divider terminates the turn, and the error the
    # provider reported keeps its own loud cell above it.
    state =
      case ended.outcome do
        :failed ->
          push!(state, %Cell.Status{label: "Agent error", detail: ended.detail, tone: :error})

        :interrupted ->
          push!(state, %Cell.Status{label: "Interrupted", detail: ended.detail, tone: :warning})

        :completed ->
          state
      end

    elapsed =
      with turn_id when is_binary(turn_id) <- ended.turn_id,
           start when is_integer(start) <- Map.get(state.turn_starts, turn_id),
           at when is_integer(at) <- ended.at,
           true <- at - start >= 0 do
        " · " <> duration(at - start)
      else
        _unknown -> ""
      end

    push!(state, %Cell.Divider{
      text: TurnEnded.label(ended.outcome) <> elapsed,
      tone:
        case ended.outcome do
          :completed -> :muted
          :failed -> :error
          :interrupted -> :warning
        end,
      kind: :turn_end
    })
  end

  @doc "Codex's elapsed-time phrasing: `4m 07s`, `1h 02m`, `840ms`."
  @spec duration(integer()) :: String.t()
  def duration(millis) do
    seconds = div(millis, 1_000)

    cond do
      seconds == 0 -> "#{millis}ms"
      seconds < 60 -> "#{seconds}s"
      seconds < 3_600 -> "#{div(seconds, 60)}m #{pad(rem(seconds, 60))}s"
      true -> "#{div(seconds, 3_600)}h #{pad(div(rem(seconds, 3_600), 60))}m"
    end
  end

  defp pad(value), do: String.pad_leading(Integer.to_string(value), 2, "0")

  defp run_started_note(%RunStart{} = run) do
    ["run started"]
    |> then(&if(run.model, do: &1 ++ [run.model], else: &1))
    |> then(&if(run.tool_count > 0, do: &1 ++ ["#{run.tool_count} tools"], else: &1))
    |> then(&if(run.cwd, do: &1 ++ [run.cwd], else: &1))
    |> Enum.join(" · ")
  end

  # A provider event nobody modelled, as one line that names what it was.
  defp provider_note_text(kind, detail) do
    "provider event"
    |> then(&if(String.trim(kind) == "", do: &1, else: &1 <> " · " <> String.trim(kind)))
    |> then(&if(String.trim(detail) == "", do: &1, else: &1 <> " — " <> String.trim(detail)))
  end

  # ------------------------------------------------------------------------------------
  # Runtime blocks
  # ------------------------------------------------------------------------------------

  @doc "B7. A command the operator ran through `workspace.exec`, as a transcript block."
  @spec shell_block(ShellEvent.t()) :: Cell.Runtime.t()
  def shell_block(%ShellEvent{} = shell) do
    label =
      case shell.command_digest do
        digest when is_binary(digest) -> "$ command #{String.slice(digest, 0, 12)}"
        _absent -> "$ command"
      end

    facts =
      []
      |> then(fn facts ->
        cond do
          is_binary(shell.error) -> facts ++ ["could not be started: #{shell.error}"]
          shell.exit_status == 0 -> facts ++ ["exit 0"]
          is_integer(shell.exit_status) -> facts ++ ["exit #{shell.exit_status}"]
          true -> facts ++ ["no exit status"]
        end
      end)
      |> then(&if(shell.timed_out, do: &1 ++ ["timed out"], else: &1))
      |> then(
        &if(is_integer(shell.duration_ms), do: &1 ++ [elapsed_label(shell.duration_ms)], else: &1)
      )
      |> then(
        &if(is_integer(shell.output_bytes), do: &1 ++ ["#{shell.output_bytes} bytes"], else: &1)
      )
      |> then(
        &if(is_binary(shell.spilled), do: &1 ++ ["full output at #{shell.spilled}"], else: &1)
      )

    failed = is_binary(shell.error) or shell.timed_out or shell.exit_status != 0

    %Cell.Runtime{
      label: label,
      detail: Enum.join(facts, " · "),
      body: if(shell.output_excerpt, do: body_rows(shell.output_excerpt), else: []),
      tone: if(failed, do: :warning, else: :muted),
      key: shell.command_digest
    }
  end

  @doc "D9. One fold of the conversation, as a transcript block."
  @spec compaction_block(Compaction.t()) :: Cell.Runtime.t()
  def compaction_block(%Compaction{} = report) do
    label =
      case report.trigger do
        "manual" -> "Compacted, at your request"
        "automatic" -> "Compacted automatically"
        _unnamed -> "Compacted"
      end

    %Cell.Runtime{
      label: label,
      detail: Compaction.describe(report),
      tone: :muted,
      key: report.archive_id
    }
  end

  @doc "G1. A coding task this conversation delegated, starting or finishing."
  @spec delegation_block(DelegationEvent.t()) :: Cell.Runtime.t()
  def delegation_block(%DelegationEvent{} = delegation) do
    label =
      case delegation.status do
        "started" -> "Delegated to a coding task"
        status when is_binary(status) -> "Delegation #{status}"
        nil -> "Delegation"
      end

    facts =
      []
      |> then(&if(delegation.task_id, do: &1 ++ ["task #{delegation.task_id}"], else: &1))
      |> then(&if(delegation.task_node, do: &1 ++ [delegation.task_node], else: &1))
      # A digest, never the result: the child's own transcript is the record of what it
      # did, and a parent that quoted it would be presenting a copy as the thing.
      |> then(
        &if(delegation.result_digest,
          do: &1 ++ ["result digest #{delegation.result_digest}"],
          else: &1
        )
      )

    tone =
      case delegation.status do
        status when status in ["failed", "cancelled", "lost"] -> :warning
        "completed" -> :success
        _running -> :muted
      end

    %Cell.Runtime{label: label, detail: Enum.join(facts, " · "), tone: tone}
  end

  # Folds one child-agent event onto the row that child already owns, or opens one.
  #
  # A `settled` for a `task_id` this window never saw its `spawned` for — the ordinary
  # shape after a resync — opens the row rather than being dropped: the digest is the part
  # worth having, and a parent transcript that showed nothing for a child that ran and
  # finished would be lying by omission about work this session caused.
  defp project_subagent(state, %SubagentEvent{} = event) do
    {state, index} =
      case event.task_id && Map.get(state.subagents, event.task_id) do
        index when is_integer(index) ->
          {state, index}

        _absent ->
          index = state.count
          state = push!(state, %Cell.Subagent{})

          state =
            if is_binary(event.task_id) do
              %{state | subagents: Map.put(state.subagents, event.task_id, index)}
            else
              state
            end

          {state, index}
      end

    case at(state, index) do
      %Cell.Subagent{} = cell -> put_at(state, index, Cell.Subagent.absorb(cell, event))
      _otherwise -> state
    end
  end

  # `Nms`, `Ns`, or `Nm Ns` — the same three shapes a tool row's elapsed time takes.
  defp elapsed_label(ms) when ms < 1_000, do: "#{ms}ms"
  defp elapsed_label(ms) when ms < 60_000, do: "#{div(ms, 1_000)}s"
  defp elapsed_label(ms), do: "#{div(ms, 60_000)}m #{rem(div(ms, 1_000), 60)}s"

  @doc "Splits a block of output into rows, bounded so one command cannot own the screen."
  @spec body_rows(String.t()) :: [String.t()]
  def body_rows(text), do: text |> Text.lines() |> Enum.take(@block_head + @block_tail + 1)
end
