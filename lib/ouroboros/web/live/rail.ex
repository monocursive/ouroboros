defmodule Ouroboros.Web.Live.Rail.Row do
  @moduledoc """
  One session as the rail draws it.

  A normalized row rather than the plane's own struct, so a rail draws a heading from
  field names it owns rather than from the checkpoint's.
  """

  defstruct [
    :plane,
    :id,
    :node,
    :status,
    :updated_at,
    :created_at,
    :title,
    :provider,
    :model,
    :workspace,
    :sandbox_mode,
    :total_tokens,
    :cost_usd,
    :error,
    :last_turn
  ]

  @type plane :: :interactive
  @type t :: %__MODULE__{
          plane: plane(),
          id: String.t(),
          node: atom() | nil,
          status: atom(),
          updated_at: String.t() | nil,
          created_at: String.t() | nil,
          title: String.t() | nil,
          provider: atom() | nil,
          model: String.t() | nil,
          workspace: String.t() | nil,
          sandbox_mode: atom() | String.t() | nil,
          total_tokens: non_neg_integer() | nil,
          cost_usd: number() | nil,
          error: term()
        }
end

defmodule Ouroboros.Web.Live.Rail do
  @moduledoc """
  Every session in one list, grouped by what each one needs.

  Port of `SessionsTab::triaged` (`tui/src/ui/app/session.rs:380`) and
  `SessionInfo::triage` (`tui/src/model.rs:237`). The grouping **is** the ordering, not a
  second pass over it: a session that is first here is first everywhere, on every surface
  that lists sessions.

  ## Why the three groups exist

  What needs a human is what a person opening this page is looking for, and it must not be
  below eleven finished sessions from yesterday. `NEEDS YOU` first, then `AT WORK`, then
  `SETTLED`, and nothing reorders across that.

  ## Why the sort has four keys

  This list is repolled every few seconds under a reader's cursor. Group, then newest
  activity, then plane, then id — the last two are there so two rows updated in the same
  second do not trade places between polls for no reason a reader could see.

  ## What is never guessed

  Triage reads *declared* state and nothing else: the plane's own status, and the
  unanswered approvals this view is holding. A row whose owner is offline keeps whichever
  group its last complete observation put it in, because "we cannot see it right now" is
  not the same claim as "it needs you", and a rail that promoted every unreachable session
  to the top would make the top of the list meaningless.
  """

  alias Ouroboros.Web.Live.Rail.Row

  @typedoc "A row with the group it landed in."
  @type triaged :: %{group: group(), depth: 0, row: Row.t()}
  @type group :: :needs_you | :at_work | :settled

  @groups [:needs_you, :at_work, :settled]

  # The plane will produce no further events. An unrecognized status is deliberately *not*
  # terminal: a client that guessed wrong here would stop rendering a live session.
  @terminal [:closed, :completed, :failed, :cancelled, :lost]
  @busy [:running, :starting, :closing]

  @doc "The three groups, in the order they are drawn."
  @spec groups() :: [group()]
  def groups, do: @groups

  @doc "The heading one group is drawn under."
  @spec label(group()) :: String.t()
  def label(:needs_you), do: "NEEDS YOU"
  def label(:at_work), do: "AT WORK"
  def label(:settled), do: "SETTLED"

  @doc "Whether the plane will produce no further events for this status."
  @spec terminal?(atom()) :: boolean()
  def terminal?(status), do: status in @terminal

  @doc "Whether this status means work is happening right now."
  @spec busy?(atom()) :: boolean()
  def busy?(status), do: status in @busy

  @doc """
  Which group one row belongs to.

  `pending` is the count of approvals this view is holding for the session that **nobody
  has answered yet**. An approval a keypress or an automation has already answered is not
  a reason to triage the row as waiting on a person.

  ## Idle is settled, on both surfaces

  `NEEDS YOU` is entered by exactly two doors — an unanswered approval, or a status of
  `awaiting_approval`. Nothing else, and in particular **not** an idle conversation.
  Idle is between turns, waiting on nobody in particular; the group meant to hold "a
  machine is blocked on you right now" must not fill with every conversation anyone has
  finished reading.

  The terminal client's `SessionInfo::triage` (`tui/src/model.rs`) uses the same rule:
  idle is `Triage::Done`. Approvals still promote the row. If one surface ever changes
  this, change the other in the same pass.
  """
  @spec triage_of(Row.t(), non_neg_integer()) :: group()
  def triage_of(%Row{} = row, pending \\ 0) when is_integer(pending) do
    cond do
      pending > 0 or row.status == :awaiting_approval -> :needs_you
      terminal?(row.status) -> :settled
      busy?(row.status) -> :at_work
      # Idle: between turns, and waiting on nobody in particular.
      row.status == :idle -> :settled
      true -> :at_work
    end
  end

  @doc """
  Every row, grouped, ordered and deduped.

  `pending` is a map from `{plane, id}` to the count of unanswered approvals this view
  holds for that session — usually one entry, for the session that is open.
  """
  @spec triaged([Row.t()], %{optional({Row.plane(), String.t()}) => non_neg_integer()}) ::
          [triaged()]
  def triaged(rows, pending \\ %{}) when is_list(rows) and is_map(pending) do
    rows
    |> Enum.map(fn row -> {triage_of(row, Map.get(pending, {row.plane, row.id}, 0)), row} end)
    |> Enum.sort_by(&key/1)
    |> dedupe()
    |> Enum.map(fn {group, row} -> %{group: group, depth: 0, row: row} end)
  end

  @doc "How many rows landed in each group."
  @spec counts([triaged()]) :: %{group() => non_neg_integer()}
  def counts(triaged) when is_list(triaged) do
    tally = Enum.frequencies_by(triaged, & &1.group)
    Map.new(@groups, &{&1, Map.get(tally, &1, 0)})
  end

  @doc """
  One row's title, and never an empty string.

  A conversation nobody named still needs a word, so it gets a friendly project label;
  its stable id remains in its route and session details.
  """
  @spec title(Row.t()) :: String.t()
  def title(%Row{} = row) do
    case row.title do
      text when is_binary(text) and text != "" -> String.trim(text) |> untitled(row.workspace)
      _ -> untitled("", row.workspace)
    end
  end

  defp untitled("", workspace) when is_binary(workspace) and workspace != "",
    do: "New conversation · " <> Path.basename(workspace)

  defp untitled("", _), do: "New conversation"
  defp untitled(title, _), do: title

  @doc """
  The word a settled row reports, from the status alone.

  `settled` for a status this build does not know: the row is in this group because
  something said the stream was over, and inventing a verdict for a word we cannot read
  would be worse than declining to.
  """
  @spec outcome(Row.t()) :: String.t()
  # Not an outcome so much as the absence of one — this group holds "nothing is happening
  # here", and for an idle conversation that is the whole truth.
  def outcome(%Row{status: :idle, last_turn: %{status: :failed}}), do: "Last turn failed"

  def outcome(%Row{status: :idle, last_turn: %{status: :completed}}),
    do: "Ready · last turn complete"

  def outcome(%Row{status: :idle, last_turn: %{status: :interrupted}}), do: "Stopped"
  def outcome(%Row{status: :idle}), do: "idle"
  def outcome(%Row{status: :completed}), do: "completed"
  def outcome(%Row{status: :closed}), do: "closed"
  def outcome(%Row{status: :failed}), do: "failed"
  def outcome(%Row{status: :cancelled}), do: "cancelled"
  def outcome(%Row{status: :lost}), do: "lost"
  def outcome(%Row{}), do: "settled"

  @doc "Whether a settled row settled badly, which is the one thing that takes the danger tone."
  @spec failed?(Row.t()) :: boolean()
  def failed?(%Row{status: :idle, last_turn: %{status: :failed}}), do: true
  def failed?(%Row{status: status}), do: status in [:failed, :lost]

  # ------------------------------------------------------------------------------------

  @doc """
  One `interactive.list` row.

  Takes a map rather than the struct: `interactive.list` answers in-process with
  `%Ouroboros.Interactive.State{}`, and a test that had to build one of those to assert a
  heading would be testing the checkpoint format.
  """
  @spec from_interactive(map()) :: Row.t()
  def from_interactive(session) when is_map(session) do
    options = Map.get(session, :options) || %{}
    usage = Map.get(session, :usage) || %{}

    %Row{
      plane: :interactive,
      last_turn: Map.get(session, :last_turn),
      id: to_string(Map.get(session, :id, "")),
      node: Map.get(session, :node),
      status: Map.get(session, :status, :unknown),
      updated_at: Map.get(session, :updated_at),
      created_at: Map.get(session, :created_at),
      title: Map.get(session, :title),
      provider: Map.get(session, :provider),
      model: Map.get(options, :model),
      workspace: Map.get(session, :workspace),
      sandbox_mode: Map.get(options, :sandbox_mode),
      total_tokens: Map.get(usage, :total_tokens),
      cost_usd: Map.get(usage, :cost_usd),
      error: Map.get(session, :error)
    }
  end

  # ------------------------------------------------------------------------------------

  # Group, then newest activity, then plane, then id — one tuple, so the tie-breaking
  # order is readable in one place rather than spread over four sort passes.
  defp key({group, row}) do
    {Enum.find_index(@groups, &(&1 == group)), inverted(row.updated_at), plane_order(row.plane),
     row.id}
  end

  # `updated_at` is an ISO-8601 string the runtime wrote, so descending order is ascending
  # order of its inverse. Sorting the string is correct for the format the runtime emits
  # and does not need a parse that could fail on a checkpoint from another build.
  # A row the runtime never dated sorts *after* every dated one. "We do not know when this
  # last moved" is not a claim that it moved recently, and putting it at the top of a group
  # would give the newest slot to the row with the least evidence for it.
  defp inverted(nil), do: {1, ""}
  defp inverted(updated_at) when is_binary(updated_at), do: {0, negate(updated_at)}
  defp inverted(other), do: {0, negate(to_string(other))}

  # Descending on a binary, without parsing it: complement each byte so the natural term
  # order runs the other way.
  defp negate(text), do: for(<<byte <- text>>, into: <<>>, do: <<255 - byte>>)

  defp plane_order(:interactive), do: 0
  defp plane_order(_other), do: 1

  # One row represents one addressable stream. A duplicate `{plane, id}` — two nodes both
  # claiming a session — is drawn once, at the place the first observation put it.
  defp dedupe(rows) do
    {kept, _seen} =
      Enum.reduce(rows, {[], MapSet.new()}, fn {group, row}, {kept, seen} ->
        key = {row.plane, row.id}

        if MapSet.member?(seen, key),
          do: {kept, seen},
          else: {[{group, row} | kept], MapSet.put(seen, key)}
      end)

    Enum.reverse(kept)
  end
end
