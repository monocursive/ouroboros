defmodule Ouroboros.Web.Transcript.Cell.Message do
  @moduledoc "One speaker's words. `streaming` marks an agent draft still being written."
  defstruct [:speaker, text: "", streaming: false]

  @type speaker :: :you | :agent
  @type t :: %__MODULE__{speaker: speaker(), text: String.t(), streaming: boolean()}
end

defmodule Ouroboros.Web.Transcript.Cell.Thinking do
  @moduledoc """
  Reasoning for one turn, accumulated. Never rendered as the agent's answer.

  Crush's three-state collapse. `:collapsed` is the default because thinking expanded by
  default in a long session is a documented 2026 regression (Zed #52536): the reader loses
  the conversation to the model's monologue. `:tail` is what a block still being written
  shows (`tui/src/ui/transcript_cells.rs:751-762`).
  """
  defstruct text: "", lines: 0, state: :tail

  @type state :: :collapsed | :tail | :full
  @type t :: %__MODULE__{text: String.t(), lines: non_neg_integer(), state: state()}
end

defmodule Ouroboros.Web.Transcript.Cell.Plan do
  @moduledoc "One plan update, as the provider sent it."
  alias Ouroboros.Web.Presentation.PlanUpdate

  defstruct [:plan]
  @type t :: %__MODULE__{plan: PlanUpdate.t()}
end

defmodule Ouroboros.Web.Transcript.Cell.Usage do
  @moduledoc "One provider token report."
  alias Ouroboros.Web.Presentation.UsageReport

  defstruct [:usage]
  @type t :: %__MODULE__{usage: UsageReport.t()}
end

defmodule Ouroboros.Web.Transcript.Cell.Tool do
  @moduledoc "One tool call and, once it lands, its result."

  defstruct [
    :call_id,
    :kind,
    :output,
    :started_at,
    :settled_at,
    name: "tool",
    input: %{},
    state: :running
  ]

  @type state :: :running | :completed | :failed
  @type t :: %__MODULE__{
          call_id: String.t() | nil,
          name: String.t(),
          kind: String.t() | nil,
          input: term(),
          output: term() | nil,
          state: state(),
          started_at: integer() | nil,
          settled_at: integer() | nil
        }

  @doc """
  How long this call took, as far as the ledger can prove it.

  Exact once the result arrived. While the call is still running it is a **floor**: the
  projection reads no clock, so the newest event instant in the window is the latest
  moment it can honestly say the call was still going
  (`tui/src/ui/transcript_cells.rs:574`).
  """
  @spec elapsed(t()) :: integer() | nil
  def elapsed(%__MODULE__{started_at: started, settled_at: settled})
      when is_integer(started) and is_integer(settled) and settled > started,
      do: settled - started

  def elapsed(%__MODULE__{}), do: nil
end

defmodule Ouroboros.Web.Transcript.Cell.Exploration do
  @moduledoc """
  Codex's grouped exploration cell: consecutive read/search/list/glob calls, with nothing
  else drawn between them, read as one row.

  The point is not to hide the calls — expanded, every one of them is a row — but to stop
  eight filesystem lookups from occupying eight frames of a conversation about something
  else (`tui/src/ui/transcript_cells.rs:582-596`).
  """

  alias Ouroboros.Web.Transcript.Cell

  defstruct calls: [], overflow: 0, done: false

  @type t :: %__MODULE__{
          calls: [Cell.Tool.t()],
          overflow: non_neg_integer(),
          done: boolean()
        }

  @doc "Every call this group stands for, listed or merely counted."
  @spec total(t()) :: non_neg_integer()
  def total(%__MODULE__{calls: calls, overflow: overflow}), do: length(calls) + overflow

  @doc "How many of the listed calls failed."
  @spec failed(t()) :: non_neg_integer()
  def failed(%__MODULE__{calls: calls}), do: Enum.count(calls, &(&1.state == :failed))
end

defmodule Ouroboros.Web.Transcript.Cell.CommandOutput do
  @moduledoc "Streaming command output, accumulated into one cell."
  defstruct text: ""
  @type t :: %__MODULE__{text: String.t()}
end

defmodule Ouroboros.Web.Transcript.Cell.File do
  @moduledoc "One file a `file_change` event named, drawn as a row."
  defstruct [:path, :kind]
  @type t :: %__MODULE__{path: String.t() | nil, kind: String.t() | nil}
end

defmodule Ouroboros.Web.Transcript.Cell.Image do
  @moduledoc """
  An image in the conversation, drawn as a labelled placeholder.

  Everything a renderer needs is decided **before** the cell exists, because projection is
  clock-free and filesystem-free by contract: a cell that stat'd a file would make the
  export snapshot depend on what happened to be on disk
  (`tui/src/ui/transcript_cells.rs:631-669`).
  """

  alias Ouroboros.Web.Presentation.ImageArtifact

  defstruct [:pixels, :format, :note, :sha, :media_type, named: ""]

  @type t :: %__MODULE__{
          named: String.t(),
          pixels: {non_neg_integer(), non_neg_integer()} | nil,
          format: String.t() | nil,
          note: String.t() | nil,
          sha: String.t() | nil,
          media_type: String.t() | nil
        }

  @doc """
  A desktop screenshot artifact as a conversation image.

  Minted from the metadata a `tool_result` carried — there is no path on the wire, so it
  is named by a short form of its digest rather than a file
  (`tui/src/ui/transcript_cells.rs:708`).
  """
  @spec from_artifact(ImageArtifact.t()) :: t()
  def from_artifact(%ImageArtifact{} = artifact) do
    %__MODULE__{
      named: "desktop capture · #{String.slice(artifact.sha256, 0, 12)}",
      pixels:
        if(is_integer(artifact.width) and is_integer(artifact.height),
          do: {artifact.width, artifact.height}
        ),
      format: media_type_format(artifact.media_type),
      note: nil,
      sha: artifact.sha256,
      media_type: artifact.media_type
    }
  end

  @doc "The one line every surface draws, so no two word the same image differently."
  @spec label(t()) :: String.t()
  def label(%__MODULE__{} = image) do
    size =
      case {image.pixels, image.format} do
        {{width, height}, format} when is_binary(format) -> "#{width}×#{height} #{format}"
        _unknown -> "size unknown"
      end

    note =
      case image.note do
        note when is_binary(note) ->
          if String.trim(note) == "", do: "", else: " · #{String.trim(note)}"

        _absent ->
          ""
      end

    "[image " <> size <> " · " <> image.named <> note <> "]"
  end

  defp media_type_format(media_type) when is_binary(media_type) do
    case media_type |> String.trim() |> String.downcase(:ascii) do
      "image/png" -> "png"
      "image/jpeg" -> "jpeg"
      "image/jpg" -> "jpeg"
      "image/gif" -> "gif"
      "image/webp" -> "webp"
      _other -> nil
    end
  end

  defp media_type_format(_media_type), do: nil
end

defmodule Ouroboros.Web.Transcript.Cell.Diff do
  @moduledoc """
  One unified diff, parsed once at projection time.

  The parse is what every count and every row comes from. `Presentation.Diff.additions` —
  the provider's own claim — stays on the payload and is deliberately not the number this
  cell prints (`tui/src/ui/transcript_cells.rs:611-623`).
  """

  alias Ouroboros.Web.Presentation
  alias Ouroboros.Web.Transcript

  defstruct [:diff, :parsed, pending_approval: false]

  @type t :: %__MODULE__{
          diff: Presentation.Diff.t(),
          parsed: Transcript.Diff.t(),
          pending_approval: boolean()
        }
end

defmodule Ouroboros.Web.Transcript.Cell.DiffStat do
  @moduledoc "What one turn changed, drawn at its end divider: `3 files · +120 −18`."
  defstruct files: 0, additions: 0, deletions: 0, in_excerpt: false

  @type t :: %__MODULE__{
          files: non_neg_integer(),
          additions: non_neg_integer(),
          deletions: non_neg_integer(),
          in_excerpt: boolean()
        }
end

defmodule Ouroboros.Web.Transcript.Cell.Status do
  @moduledoc "A loud line: an approval, an error, an interruption."
  defstruct label: "", detail: "", tone: :muted

  @type tone :: :muted | :success | :warning | :error
  @type t :: %__MODULE__{label: String.t(), detail: String.t(), tone: tone()}
end

defmodule Ouroboros.Web.Transcript.Cell.ChatNote do
  @moduledoc """
  A muted entry in the conversation itself: something the ledger recorded happening
  without recording what was said. Not a divider — nothing was interrupted — and not a
  message, because nobody's words are being quoted.
  """
  defstruct text: ""
  @type t :: %__MODULE__{text: String.t()}
end

defmodule Ouroboros.Web.Transcript.Cell.Runtime do
  @moduledoc """
  Something *this runtime* did, rather than the provider: a fold of the conversation, a
  rewind, a delegation, a command the operator ran themselves (D9, D6, G1, B7).

  One cell for all four because they are the same kind of claim — Ouroboros recording its
  own act in the conversation it changed (`tui/src/ui/transcript_cells.rs:193-213`).
  """
  defstruct label: "", detail: "", body: [], tone: :muted, key: nil

  @type t :: %__MODULE__{
          label: String.t(),
          detail: String.t(),
          body: [String.t()],
          tone: Ouroboros.Web.Transcript.Cell.Status.tone(),
          key: String.t() | nil
        }

  @doc "The whole block as plain text, for an export and a screen reader."
  @spec text(t()) :: String.t()
  def text(%__MODULE__{} = block) do
    head =
      if String.trim(block.detail) == "" do
        block.label
      else
        block.label <> " — " <> block.detail
      end

    Enum.reduce(block.body, head, fn row, acc -> acc <> "\n" <> row end)
  end
end

defmodule Ouroboros.Web.Transcript.Cell.Subagent do
  @moduledoc """
  One child agent this session spawned, folded across its whole life.

  Its own cell rather than a runtime block because it is the one row here that is
  *rewritten* — a block is a thing that happened, and a child is a thing happening. Latest
  wins, and only for the fields an event actually carried: a progress report that omits
  its tool-call count leaves the last one it did send standing rather than resetting the
  row to zero (`tui/src/ui/transcript_cells.rs:258-297`).
  """

  alias Ouroboros.Web.Presentation.SubagentEvent

  @marker "↳"

  defstruct [
    :task_id,
    :description,
    :provider_session_id,
    :node,
    :depth,
    :turns,
    :tool_calls,
    :files,
    :input_tokens,
    :output_tokens,
    :cost_usd,
    :status,
    :error,
    :worktree_kept,
    remote: false,
    worktree: false,
    background: false,
    settled: false,
    unknown_phases: []
  ]

  @type t :: %__MODULE__{
          task_id: String.t() | nil,
          description: String.t() | nil,
          provider_session_id: String.t() | nil,
          node: String.t() | nil,
          remote: boolean(),
          worktree: boolean(),
          background: boolean(),
          depth: non_neg_integer() | nil,
          turns: non_neg_integer() | nil,
          tool_calls: non_neg_integer() | nil,
          files: non_neg_integer() | nil,
          input_tokens: non_neg_integer() | nil,
          output_tokens: non_neg_integer() | nil,
          cost_usd: float() | nil,
          status: String.t() | nil,
          settled: boolean(),
          error: String.t() | nil,
          worktree_kept: String.t() | nil,
          unknown_phases: [String.t()]
        }

  @doc "The glyph a child agent's row is marked with."
  def marker, do: @marker

  @doc """
  Folds one event onto the row.

  Idempotent: re-applying the same event — which every resync and every replay does —
  writes the same values over themselves (`tui/src/ui/transcript_cells.rs:302`).
  """
  @spec absorb(t(), SubagentEvent.t()) :: t()
  def absorb(%__MODULE__{} = cell, %SubagentEvent{} = event) do
    phase = SubagentEvent.phase(event)

    cell = if is_nil(cell.task_id), do: %{cell | task_id: event.task_id}, else: cell

    cell = %{
      cell
      | description: overwrite(cell.description, event.description),
        provider_session_id: overwrite(cell.provider_session_id, event.provider_session_id),
        node: overwrite(cell.node, event.node),
        # Facts that only ever arrive set. A progress report carries none of them, and
        # clearing them on its arrival would make a backgrounded child stop being one.
        remote: cell.remote or event.remote,
        worktree: cell.worktree or event.worktree,
        background: cell.background or event.background,
        depth: event.depth || cell.depth,
        turns: event.turns || cell.turns,
        tool_calls: event.tool_calls || cell.tool_calls,
        files: event.files_changed || cell.files
    }

    cell = if SubagentEvent.settled?(phase), do: settle(cell, event), else: cell

    case phase do
      {:other, word} -> note_phase(cell, if(word == "", do: "unnamed", else: word))
      _known -> cell
    end
  end

  defp settle(cell, event) do
    cell = %{
      cell
      | settled: true,
        status: overwrite(cell.status, event.status),
        input_tokens: event.input_tokens || cell.input_tokens,
        output_tokens: event.output_tokens || cell.output_tokens,
        cost_usd: event.cost_usd || cell.cost_usd,
        error: overwrite(cell.error, event.error)
    }

    # Only "kept" is worth a line. A worktree the runtime removed is not somewhere anyone
    # needs to go, and saying so would put a line in every transcript.
    case event.worktree_detail do
      %{retired: "kept"} = worktree ->
        %{
          cell
          | worktree_kept: worktree.path || Ouroboros.Web.Presentation.Worktree.label(worktree)
        }

      _otherwise ->
        cell
    end
  end

  # Deduped so a replayed event does not lengthen the list it already appears in.
  defp note_phase(cell, word) do
    if word in cell.unknown_phases do
      cell
    else
      %{cell | unknown_phases: cell.unknown_phases ++ [word]}
    end
  end

  # Writes a value through only where the new one is there, so a payload that omits a
  # field leaves what the last one said standing instead of blanking it.
  defp overwrite(current, nil), do: current
  defp overwrite(_current, value), do: value

  @doc "The bold first row: `Subagent <description>` and the badges that qualify it."
  @spec headline(t()) :: String.t()
  def headline(%__MODULE__{} = cell) do
    head =
      case cell.description do
        description when is_binary(description) ->
          case String.trim(description) do
            "" -> "Subagent"
            trimmed -> "Subagent " <> trimmed
          end

        _unnamed ->
          "Subagent"
      end

    Enum.reduce(badges(cell), head, fn badge, acc -> acc <> " · " <> badge end)
  end

  @doc "`⇄ <node>`, `⎇ worktree`, `background`, `depth n` — each only where it is true."
  @spec badges(t()) :: [String.t()]
  def badges(%__MODULE__{} = cell) do
    []
    |> then(fn badges ->
      cond do
        not cell.remote -> badges
        is_binary(cell.node) -> badges ++ ["⇄ #{cell.node}"]
        # Remote, but the runtime did not say where. Still worth the badge: that it left
        # this machine is the fact that changes how a reader reads the row.
        true -> badges ++ ["⇄ remote"]
      end
    end)
    |> then(fn badges -> if cell.worktree, do: badges ++ ["⎇ worktree"], else: badges end)
    |> then(fn badges -> if cell.background, do: badges ++ ["background"], else: badges end)
    # Depth 1 is every child of this session, which is not news. Deeper than that is.
    |> then(fn badges ->
      if is_integer(cell.depth) and cell.depth > 1,
        do: badges ++ ["depth #{cell.depth}"],
        else: badges
    end)
  end

  @doc "The counters, in the order they answer \"how much did this child do\"."
  @spec digest(t()) :: String.t()
  def digest(%__MODULE__{} = cell) do
    []
    |> maybe(cell.turns, &"#{&1} turns")
    |> maybe(cell.tool_calls, &"#{&1} tool calls")
    |> maybe(cell.files, &"#{&1} files")
    |> then(fn facts ->
      case {cell.input_tokens, cell.output_tokens} do
        {nil, nil} -> facts
        {input, nil} -> facts ++ ["#{input} in tokens"]
        {nil, output} -> facts ++ ["#{output} out tokens"]
        {input, output} -> facts ++ ["#{input} in / #{output} out tokens"]
      end
    end)
    |> maybe(cell.cost_usd, &"$#{:erlang.float_to_binary(&1 * 1.0, decimals: 4)}")
    |> Enum.join(" · ")
  end

  defp maybe(facts, nil, _format), do: facts
  defp maybe(facts, value, format), do: facts ++ [format.(value)]

  @doc "The rows under the digest: what went wrong, what was left behind, and where."
  @spec rows(t()) :: [String.t()]
  def rows(%__MODULE__{} = cell) do
    Enum.map(cell.unknown_phases, &"phase #{&1}, which this client does not model") ++
      maybe([], cell.error, &"Error: #{&1}") ++
      maybe([], cell.worktree_kept, &"Worktree kept (it holds uncommitted work): #{&1}") ++
      maybe([], cell.provider_session_id, &"session #{&1}")
  end

  @doc """
  The status word, once the child has settled.

  Never guessed before then: a row that said "completed" while a child was still running
  would be the worst thing here.
  """
  @spec status_word(t()) :: String.t() | nil
  def status_word(%__MODULE__{settled: false}), do: nil
  def status_word(%__MODULE__{status: status}), do: status || "settled"

  @doc "The tone this row carries."
  @spec tone(t()) :: Ouroboros.Web.Transcript.Cell.Status.tone()
  def tone(%__MODULE__{settled: true, status: "completed"}), do: :success

  def tone(%__MODULE__{settled: true, status: status}) when status in ["failed", "timed_out"],
    do: :error

  # `stopped` and any word this build does not know: something happened that was not
  # success, and claiming it was a failure would be inventing a verdict.
  def tone(%__MODULE__{}), do: :muted

  @doc "The digest with its status word in front, as one line."
  @spec detail(t()) :: String.t()
  def detail(%__MODULE__{} = cell) do
    case {status_word(cell), digest(cell)} do
      {nil, digest} -> digest
      {status, ""} -> status
      {status, digest} -> "#{status} · #{digest}"
    end
  end

  @doc "The whole row as plain text, for an export and a voice."
  @spec text(t()) :: String.t()
  def text(%__MODULE__{} = cell) do
    head =
      case detail(cell) do
        "" -> headline(cell)
        detail -> headline(cell) <> " — " <> detail
      end

    Enum.reduce(rows(cell), head, fn row, acc -> acc <> "\n" <> row end)
  end
end

defmodule Ouroboros.Web.Transcript.Cell.Divider do
  @moduledoc """
  A rule across the reading path.

  `kind` tells a turn boundary — the ones a diff view counts turns by — from "earlier
  history is gone", which their wording alone cannot
  (`tui/src/ui/transcript_cells.rs:743-749`).
  """
  defstruct text: "", tone: :muted, kind: :other

  @type kind :: :turn_end | :other
  @type t :: %__MODULE__{
          text: String.t(),
          tone: Ouroboros.Web.Transcript.Cell.Status.tone(),
          kind: kind()
        }
end

defmodule Ouroboros.Web.Transcript.Cell do
  @moduledoc """
  The output vocabulary of the projection.

  One struct per arm of the TUI's `Cell` enum (`tui/src/ui/transcript_cells.rs:764-825`).
  Projection is deliberately one-way: normalized durable events become compact display
  cells, but no decision made here is sent back to the runtime.
  """

  alias Ouroboros.Web.Transcript.Cell

  @type t ::
          Cell.Message.t()
          | Cell.Thinking.t()
          | Cell.Plan.t()
          | Cell.Usage.t()
          | Cell.Tool.t()
          | Cell.Exploration.t()
          | Cell.CommandOutput.t()
          | Cell.File.t()
          | Cell.Image.t()
          | Cell.Diff.t()
          | Cell.DiffStat.t()
          | Cell.Status.t()
          | Cell.ChatNote.t()
          | Cell.Runtime.t()
          | Cell.Subagent.t()
          | Cell.Divider.t()
end
