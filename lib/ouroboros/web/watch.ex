defmodule Ouroboros.Web.Watch do
  @moduledoc """
  One watched session's held events, and the arithmetic that makes them truthful.

  Port of `tui/src/ui/transcript.rs:1-31` — the module header there is the specification
  and it is reproduced here because the reasoning is the whole design, not a comment on
  it.

  ## Why the cursor is the contiguous high-water mark and not the newest sequence

  Every repair asks the runtime for "the retained events after this cursor". After a hole
  — a prune, a dropped delivery, a view that died mid-stream — the *newest* sequence this
  view holds is an event from **after** the hole, so resuming from it would step over the
  missing history and leave a transcript that looks complete and is not. The cursor is
  therefore the largest N such that every sequence in `(floor, N]` is held, and it is the
  same number for every cause.

  ## Three causes, one repair

  Remount, the coordinator's `:DOWN`, and `{:error, {:cursor_pruned, floor}}` are three
  different things going wrong and one thing to do about them: `subscribe(cursor)`. The
  LiveView owns that call; this module owns the number it is called with. In-process
  removes the gateway's lag protocol but not the algorithm — a subscriber whose mailbox
  the plane outran loses events exactly the way a lagging socket did. `mailbox_lagged?/1`
  is that detection, measured against `window/0`; the LiveView's repair is still
  `subscribe(cursor)`.

  ## A silent prune is inferred, never waited for

  Both subscribe and replay answer "the retained events after this cursor, in order". A
  first entry above `cursor + 1` therefore *proves* the ones between are no longer
  retained — a prune the runtime had no reason to raise, since the cursor itself was still
  inside its window. `backlog/3` raises the floor on that proof, which is what stops the
  transcript showing a hole that will never fill
  (`tui/src/ui/app/streaming.rs:390-401`).

  ## Raising a floor and dropping an event are different acts

  `raise_floor/2` records that history at or below a sequence will never arrive. It does
  **not** discard what this view already holds: a prune is a fact about what the *runtime*
  still retains, and events obtained before it are real history. Dropping them to make the
  divider sit at the top would delete a transcript an operator is reading, so the divider
  is placed where the hole actually is instead.

  `trim/1` is the other direction — this view holding more than it will draw — and it
  discards, raising the floor by exactly as much as it dropped. Both produce the same
  divider, which is the point: a reader sees one sentence, "history before here is gone",
  whichever side let go of it.

  ## Bounded

  A session retains 10,000 events upstream. The window here is `window/0`, smaller than
  the TUI's 5,000 because a browser holds this per open tab and the reading pane draws a
  bounded suffix of it anyway (`Ouroboros.Web.Transcript.chat_entry_window/0`).

  Pure: no processes, no clock, no messages. The LiveView subscribes, receives, and calls
  in here; every property this module has can be tested by calling functions.
  """

  alias Ouroboros.Web.Transcript
  alias Ouroboros.Web.Transcript.Entry

  # How many events one watch holds before the oldest start costing the floor.
  @window 2_000
  # Interruption markers are cheap and a session that reconnected two hundred times does
  # not need two hundred dividers.
  @max_notes 64

  defstruct events: %{},
            notes: %{},
            floor: 0,
            cursor: 0,
            ended: nil,
            undecodable: 0

  @type note :: Entry.Note.note()
  @type t :: %__MODULE__{
          events: %{optional(non_neg_integer()) => map()},
          notes: %{optional(non_neg_integer()) => note()},
          floor: non_neg_integer(),
          cursor: non_neg_integer(),
          ended: String.t() | nil,
          undecodable: non_neg_integer()
        }

  @doc "How many events one watch holds before trimming starts costing the floor."
  @spec window() :: pos_integer()
  def window, do: @window

  @doc """
  Whether a LiveView mailbox has fallen behind the plane by a full watch of work.

  The cap is `window/0`, not a second number. A queue that long is already a hole: even
  absorbing every message would trim the oldest on the way in, and the repair is the
  same as the coordinator's `:DOWN` — `subscribe(cursor)`. In-process subscribers have
  no `stream.lagged` protocol; this is that protocol's local equivalent, measured in
  mailbox depth rather than outbound frames.

  Pure: it is a predicate on a length so the LiveView can ask
  `Process.info(self(), :message_queue_len)` after the current message is already
  dequeued and this module stays free of processes. At the window, that remaining
  length means at least one more than the window was queued.
  """
  @spec mailbox_lagged?(non_neg_integer()) :: boolean()
  def mailbox_lagged?(len) when is_integer(len) and len >= 0, do: len >= @window

  @doc """
  A watch of a session nothing has been read from yet.

  `:floor` seeds a view that already knows history below a sequence is gone — a remount
  after a prune, which would otherwise draw its first divider only once the runtime
  refused it a second time.
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) when is_list(opts) do
    floor = Keyword.get(opts, :floor, 0)
    %__MODULE__{floor: floor, cursor: floor}
  end

  @doc "The exclusive cursor every repair resubscribes from."
  @spec cursor(t()) :: non_neg_integer()
  def cursor(%__MODULE__{cursor: cursor}), do: cursor

  @doc "The sequence below which history is gone, whoever let go of it."
  @spec floor(t()) :: non_neg_integer()
  def floor(%__MODULE__{floor: floor}), do: floor

  @doc "The newest sequence held, contiguous or not."
  @spec newest(t()) :: non_neg_integer()
  def newest(%__MODULE__{events: events, floor: floor}) when map_size(events) == 0, do: floor

  def newest(%__MODULE__{events: events}) do
    events |> Map.keys() |> Enum.max()
  end

  @doc """
  Whether history is missing between the cursor and the newest event held.

  The question a resync loop asks to know whether one more round is worth making: a batch
  that answered something but left a hole above it means the runtime has more to give.
  """
  @spec has_gap?(t()) :: boolean()
  def has_gap?(%__MODULE__{} = watch), do: watch.cursor < newest(watch)

  @doc "How many events this watch is holding."
  @spec size(t()) :: non_neg_integer()
  def size(%__MODULE__{events: events}), do: map_size(events)

  @doc "Whether anything at all has been read."
  @spec empty?(t()) :: boolean()
  def empty?(%__MODULE__{events: events}), do: map_size(events) == 0

  @doc """
  Takes a batch — a live event, a subscribe backlog, a replay answer.

  Idempotent by sequence, so the overlap every repair produces costs nothing: an event
  already held is written over itself rather than duplicated, and re-absorbing a whole
  backlog leaves the cursor exactly where it was.
  """
  @spec absorb(t(), [map()] | map()) :: t()
  def absorb(%__MODULE__{} = watch, event)
      when is_map(event) and not is_struct(event, __MODULE__),
      do: absorb(watch, [event])

  def absorb(%__MODULE__{} = watch, events) when is_list(events) do
    events
    |> Enum.reduce(watch, fn event, acc ->
      case sequence_of(event) do
        sequence when is_integer(sequence) and sequence > 0 ->
          %{acc | events: Map.put(acc.events, sequence, event)}

        # An event with no sequence has no place in a sequence-keyed ledger and no honest
        # position to be drawn at. Counted, not guessed at.
        _unsequenced ->
          %{acc | undecodable: acc.undecodable + 1}
      end
    end)
    |> trim()
    |> recompute_cursor()
  end

  @doc """
  Absorbs a subscribe or replay answer, inferring the prune its first entry proves.

  `asked_from` is the cursor the batch was requested with. Both verbs answer in order and
  from that cursor forward, so a first entry above `asked_from + 1` means the sequences
  between are gone — see the moduledoc. This is the only place that inference is made, so
  the LiveView's three repair paths all get it by calling one function.
  """
  @spec backlog(t(), non_neg_integer(), [map()]) :: t()
  def backlog(%__MODULE__{} = watch, asked_from, events)
      when is_integer(asked_from) and asked_from >= 0 and is_list(events) do
    watch =
      case first_sequence(events) do
        first when is_integer(first) and first > asked_from + 1 -> raise_floor(watch, first - 1)
        _contiguous_or_empty -> watch
      end

    absorb(watch, events)
  end

  @doc """
  Records that history at or below `floor` will never arrive.

  Discards nothing: see the moduledoc. Monotonic, so a stale refusal answering after a
  newer one cannot lower a floor that has already been drawn.
  """
  @spec raise_floor(t(), non_neg_integer()) :: t()
  def raise_floor(%__MODULE__{floor: current} = watch, floor)
      when is_integer(floor) and floor <= current,
      do: watch

  def raise_floor(%__MODULE__{} = watch, floor) when is_integer(floor) do
    %{watch | floor: floor, cursor: max(watch.cursor, floor)}
    |> forget_notes_below_floor()
    |> recompute_cursor()
  end

  @doc """
  Anchors a stream interruption at the newest sequence known.

  Which is where a reader looking at the transcript would otherwise see an unexplained
  jump: the note belongs at the edge of what is held, not at the top of the pane.
  """
  @spec note(t(), note(), non_neg_integer()) :: t()
  def note(%__MODULE__{} = watch, note, at \\ 0) when is_integer(at) do
    at = max(at, newest(watch))

    %{watch | notes: Map.put(watch.notes, at, note)}
    |> trim_notes()
  end

  @doc """
  Records the terminal status, which is what turns the stream's end into a divider.

  Set from either proof: `Methods.session/2` saying the session is already terminal when
  the backlog arrived, or the coordinator's `:DOWN` afterwards.
  """
  @spec ended(t(), String.t() | nil) :: t()
  def ended(%__MODULE__{} = watch, status) when is_binary(status) or is_nil(status),
    do: %{watch | ended: status}

  @doc "Whether this watch has been told the stream is over."
  @spec ended?(t()) :: boolean()
  def ended?(%__MODULE__{ended: ended}), do: is_binary(ended)

  @doc """
  The ordered entries this watch stands for, dividers interleaved.

  A thin call into `Ouroboros.Web.Transcript.entries/2`, which owns the interleaving; this
  module owns the three inputs it takes. Kept here so a caller never has to remember to
  pass the floor.
  """
  @spec entries(t()) :: [Entry.t()]
  def entries(%__MODULE__{} = watch) do
    Transcript.entries(watch.events, floor: watch.floor, notes: watch.notes, ended: watch.ended)
  end

  @doc """
  The approvals this session is still waiting on, oldest first.

  Rebuilt from the whole held ledger, never folded — the ordering hazard the projection's
  own docs name is the same in-process.
  """
  @spec pending_approvals(t()) :: [Ouroboros.Web.Transcript.Approval.t()]
  def pending_approvals(%__MODULE__{events: events}), do: Transcript.pending_approvals(events)

  # ------------------------------------------------------------------------------------

  # Only the contiguous prefix counts: the first hole is where a repair has to resume,
  # whatever sits above it.
  defp recompute_cursor(%__MODULE__{} = watch) do
    %{watch | cursor: walk(watch.events, max(watch.cursor, watch.floor))}
  end

  defp walk(events, cursor) do
    if Map.has_key?(events, cursor + 1), do: walk(events, cursor + 1), else: cursor
  end

  # Drops the oldest events past the window, raising the floor by exactly as much as was
  # dropped so the divider states the truth rather than an approximation.
  defp trim(%__MODULE__{events: events} = watch) when map_size(events) <= @window, do: watch

  defp trim(%__MODULE__{} = watch) do
    oldest = watch.events |> Map.keys() |> Enum.min()

    %{watch | events: Map.delete(watch.events, oldest), floor: max(watch.floor, oldest)}
    |> forget_notes_below_floor()
    |> trim()
  end

  defp forget_notes_below_floor(%__MODULE__{} = watch) do
    %{watch | notes: :maps.filter(fn at, _note -> at > watch.floor end, watch.notes)}
  end

  defp trim_notes(%__MODULE__{notes: notes} = watch) when map_size(notes) <= @max_notes, do: watch

  defp trim_notes(%__MODULE__{} = watch) do
    oldest = watch.notes |> Map.keys() |> Enum.min()
    trim_notes(%{watch | notes: Map.delete(watch.notes, oldest)})
  end

  defp sequence_of(event), do: Map.get(event, :sequence)

  defp first_sequence(events) do
    events
    |> Enum.map(&sequence_of/1)
    |> Enum.filter(&is_integer/1)
    |> case do
      [] -> nil
      sequences -> Enum.min(sequences)
    end
  end
end
