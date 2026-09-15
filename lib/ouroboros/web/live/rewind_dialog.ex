defmodule Ouroboros.Web.Live.RewindDialog do
  @moduledoc """
  W3.4. The one verb here that undoes, in two screens on purpose.

  Port of `App::open_rewind` / `rewind_confirm` / `rewound`
  (`tui/src/ui/app/native.rs:306-486`) and `Overlay::Rewind`, with the answer shapes of
  `tui/src/model/native.rs:344-515`.

  ## The warning comes before the choice, not after

  Every row carries its own warning — not only the highlighted one — naming the shell
  commands that ran in that turn, whose effects were never checkpointed, and the files
  with no snapshot, which cannot be rewritten. The second screen repeats it on the screen
  where the choice is actually made, and only the second confirmation sends anything
  (`docs/TUI.md:2204-2211`).

  ## `to_turn` is the turn's 1-based position, not its id

  `interactive.rewind`'s parameter contract admits either, but `InteractiveSession.rewind/3`
  guards `is_integer`, so a turn id is refused as `invalid_rewind` before it reaches the
  session. The position is exactly what this dialog already knows, having just been handed
  the list it indexes into.

  ## Restored and unrestorable are two blocks and are never merged

  The second list is the one that has to be acted on, and a mixed list buries it.

  Pure: `points/1`, `warning/1` and `outcome/1` decode terms into data. The calls are the
  LiveView's.
  """

  use Phoenix.Component

  # How many rows of one answer this surface holds, matching `native::MAX_ROWS`.
  @max_rows 512
  # How many paths one rewind point names before the rest are counted.
  @max_paths 20

  @typedoc "One row of `interactive.rewind_points`."
  @type point :: %{
          turn_id: String.t() | nil,
          at: String.t() | nil,
          files: non_neg_integer(),
          paths: [String.t()],
          commands: non_neg_integer(),
          restorable: non_neg_integer() | nil,
          dropped_turns: non_neg_integer() | nil
        }

  @doc """
  What a rewind may put back, in the order the chooser lists them.

  Exactly the three the runtime accepts and no more: `interactive.rewind`'s `what` is a
  closed enum, and a fourth row would be a promise the wire refuses
  (`tui/src/ui/app/native.rs:32-40`).
  """
  @spec what_choices() :: [{String.t(), String.t()}]
  def what_choices do
    [
      {"both", "the files and the conversation"},
      {"files", "the files only — the conversation stays as it is"},
      {"conversation", "the conversation only — the files stay as they are"}
    ]
  end

  @doc "Whether one `what` is a word the wire accepts."
  @spec what?(term()) :: boolean()
  def what?(value), do: Enum.any?(what_choices(), fn {word, _said} -> word == value end)

  @doc "`interactive.rewind_points`' answer, oldest first, as the dialog indexes it."
  @spec points(term()) :: [point()]
  def points(list) when is_list(list) do
    list
    |> Enum.take(@max_rows)
    |> Enum.flat_map(fn
      row when is_map(row) ->
        [
          %{
            turn_id: text(row, :turn_id),
            at: text(row, :at),
            files: count(row, :files) || 0,
            paths: row |> list(:paths) |> Enum.take(@max_paths) |> Enum.map(&to_string/1),
            commands: count(row, :commands) || 0,
            restorable: count(row, :restorable),
            dropped_turns: count(row, :dropped_turns)
          }
        ]

      _unreadable ->
        []
    end)
  end

  def points(_unreadable), do: []

  @doc """
  The warning one row carries, or `nil` where everything in it can come back.

  Two separate facts and both are stated: a shell command's effects were never
  checkpointed, and a file whose prior bytes were not snapshotted cannot be rewritten
  (`tui/src/model/native.rs:404-431`).
  """
  @spec warning(point()) :: String.t() | nil
  def warning(%{} = point) do
    parts =
      []
      |> commands_warning(point)
      |> snapshot_warning(point)
      |> Enum.reverse()

    case parts do
      [] -> nil
      parts -> Enum.join(parts, "; ")
    end
  end

  defp commands_warning(parts, %{commands: commands})
       when is_integer(commands) and commands > 0 do
    [
      "#{commands} shell #{plural(commands, "command")} ran in it — whatever they changed " <>
        "is not checkpointed"
      | parts
    ]
  end

  defp commands_warning(parts, _point), do: parts

  defp snapshot_warning(parts, %{restorable: restorable, files: files})
       when is_integer(restorable) and is_integer(files) and restorable < files do
    ["#{files - restorable} of #{files} files have no snapshot" | parts]
  end

  defp snapshot_warning(parts, _point), do: parts

  @doc "What `interactive.rewind` did, and what it could not do."
  @spec outcome(term()) :: map()
  def outcome(answer) when is_map(answer) do
    %{
      restored:
        answer
        |> list(:restored)
        |> Enum.take(@max_rows)
        |> Enum.flat_map(&restored_file/1),
      unrestorable:
        answer
        |> list(:unrestorable)
        |> Enum.take(@max_rows)
        |> Enum.flat_map(&unrestorable/1),
      turns: answer |> list(:turns) |> Enum.take(@max_rows) |> Enum.map(&to_string/1),
      messages: count(answer, :messages)
    }
  end

  def outcome(_unreadable),
    do: %{restored: [], unrestorable: [], turns: [], messages: nil}

  defp restored_file(row) when is_map(row) do
    case text(row, :path) do
      nil -> []
      path -> [%{path: path, action: text(row, :action) || "restored"}]
    end
  end

  defp restored_file(_other), do: []

  # A row naming neither a file nor a turn cannot be presented as either, and a bare
  # reason floating in a list would read as a claim about the whole rewind
  # (`tui/src/model/native.rs:507-528`).
  defp unrestorable(row) when is_map(row) do
    entry = %{
      path: text(row, :path),
      turn_id: text(row, :turn_id),
      reason: text(row, :reason)
    }

    if is_nil(entry.path) and is_nil(entry.turn_id), do: [], else: [entry]
  end

  defp unrestorable(_other), do: []

  @doc "What one unrestorable row is about: a file, or the turn it happened in."
  @spec subject(map()) :: String.t()
  def subject(%{path: path}) when is_binary(path), do: path
  def subject(%{turn_id: turn}) when is_binary(turn), do: "turn #{turn}"
  def subject(_entry), do: "something"

  @doc "One line for the transcript's record of a rewind, carrying only what was reported."
  @spec describe(map()) :: String.t()
  def describe(%{} = outcome) do
    facts =
      []
      |> then(fn facts ->
        case length(outcome.restored) do
          0 -> facts
          n -> ["restored #{n} #{plural(n, "file")}" | facts]
        end
      end)
      |> then(fn facts ->
        case length(outcome.unrestorable) do
          0 -> facts
          n -> ["skipped #{n}" | facts]
        end
      end)
      |> then(fn facts ->
        case outcome.messages do
          n when is_integer(n) -> ["#{n} messages kept" | facts]
          _absent -> facts
        end
      end)
      |> Enum.reverse()

    case facts do
      [] -> "nothing had to be put back"
      facts -> Enum.join(facts, " · ")
    end
  end

  defp plural(1, noun), do: noun
  defp plural(_n, noun), do: noun <> "s"

  # Atom keys in-process, string keys across JSON. Neither spelling is canonical.
  defp at(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Atom.to_string(key))
    end
  end

  defp text(map, key) do
    case at(map, key) do
      value when is_binary(value) ->
        case String.trim(value) do
          "" -> nil
          trimmed -> trimmed
        end

      value when is_atom(value) and value not in [nil, true, false] ->
        Atom.to_string(value)

      _absent ->
        nil
    end
  end

  defp count(map, key) do
    case at(map, key) do
      value when is_integer(value) and value >= 0 -> value
      _absent -> nil
    end
  end

  defp list(map, key) do
    case at(map, key) do
      value when is_list(value) -> value
      _absent -> []
    end
  end

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  @doc """
  The dialog. `screen` is `:choose`, `:confirm` or `:done`, which is the two-screen rule
  plus the answer.
  """
  attr :screen, :atom, required: true
  attr :points, :list, required: true
  attr :choice, :integer, default: 0
  attr :what, :string, default: "both"
  attr :outcome, :any, default: nil
  attr :error, :any, default: nil

  def dialog(assigns) do
    assigns =
      assigns
      |> assign(:point, Enum.at(assigns.points, assigns.choice))
      |> assign(:to_turn, assigns.choice + 1)

    ~H"""
    <dialog
      id="ouro-rewind"
      class="ouro-session-dialog ouro-rewind"
      aria-modal="true"
      aria-labelledby="ouro-rewind-title"
      phx-hook="Modal"
      data-cancel-event="w3-close"
    >
      <div class="ouro-session-dialog-form">
        <h2 id="ouro-rewind-title">Rewind to an earlier turn</h2>

        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>

        <%!-- Screen one: every row with its own warning, before anything is chosen. --%>
        <div :if={@screen == :choose}>
          <p :if={@points == []} class="ouro-quiet">
            This session has no checkpointed turns to go back to.
          </p>

          <ol class="ouro-rewind-list">
            <li :for={{point, at} <- Enum.with_index(@points)} class="ouro-rewind-row">
              <button
                type="button"
                class="ouro-rewind-pick"
                phx-click="w3-rewind-pick"
                phx-value-choice={at}
              >
                <span class="ouro-mono">turn {at + 1}</span>
                <span class="ouro-mono ouro-quiet">{point.turn_id || "no turn id"}</span>
                <span class="ouro-quiet">{point.at}</span>
                <span class="ouro-mono">
                  {point.files} {plural(point.files, "file")}
                </span>
              </button>
              <p :if={warning(point)} class="ouro-rewind-warning">{warning(point)}</p>
            </li>
          </ol>
        </div>

        <%!-- Screen two: the same warning again, where the choice is actually made. --%>
        <div :if={@screen == :confirm and @point}>
          <p>
            Rewinding to <span class="ouro-mono">turn {@to_turn}</span>
            <span :if={@point.turn_id} class="ouro-mono ouro-quiet">({@point.turn_id})</span>.
          </p>

          <p :if={warning(@point)} class="ouro-rewind-warning" role="alert">
            {warning(@point)}
          </p>
          <p :if={is_nil(warning(@point))} class="ouro-quiet">
            Nothing in this turn was reported as beyond a rewind.
          </p>

          <div class="ouro-picker">
            <span class="ouro-picker-label">Put back</span>
            <button
              :for={{word, said} <- what_choices()}
              type="button"
              class={["ouro-picker-option", @what == word && "ouro-picker-on"]}
              aria-pressed={to_string(@what == word)}
              phx-click="w3-rewind-what"
              phx-value-what={word}
            >
              {said}
            </button>
          </div>

          <div class="ouro-session-dialog-actions">
            <button type="button" class="ouro-button-quiet" phx-click="w3-rewind-back">
              Back to the list
            </button>
            <button
              type="button"
              class="ouro-button ouro-button-danger"
              phx-click="w3-rewind-confirm"
              phx-disable-with="Rewinding…"
            >
              Rewind to turn {@to_turn}
            </button>
          </div>
        </div>

        <%!-- The answer: two blocks, restored first, never merged. --%>
        <div :if={@screen == :done and @outcome}>
          <p>{describe(@outcome)}</p>

          <section class="ouro-rewind-block">
            <h3>Restored</h3>
            <p :if={@outcome.restored == []} class="ouro-quiet">Nothing had to be put back.</p>
            <ul class="ouro-mono">
              <li :for={file <- @outcome.restored}>{file.action} {file.path}</li>
            </ul>
          </section>

          <section class="ouro-rewind-block ouro-rewind-unrestorable">
            <h3>Could not be restored</h3>
            <p :if={@outcome.unrestorable == []} class="ouro-quiet">
              The runtime named nothing it could not put back.
            </p>
            <ul>
              <li :for={entry <- @outcome.unrestorable}>
                <span class="ouro-mono">{subject(entry)}</span>
                <span :if={entry.reason}>— {entry.reason}</span>
              </li>
            </ul>
          </section>
        </div>

        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button-quiet" phx-click="w3-close">Close</button>
        </div>
      </div>
    </dialog>
    """
  end
end
