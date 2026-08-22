defmodule Ouroboros.Provider.Native.Context.Compaction do
  @moduledoc """
  Making a conversation smaller without making it disappear.

  Row 16 of R5's scorecard — "lossless context management: reviewable pre-compaction
  history, tunable, never loses plan state" — is an open slot because compaction is
  opaque everywhere. This module is the attempt at the row, and it is three decisions:

  ## 1. Tool results go before prose does

  Claude Code "clears older tool outputs first, then summarizes", and it is the right
  order: a 30 KB `bash` result from twelve turns ago is the largest, least re-readable
  thing in the window, and the assistant's reasoning about it is already in the
  transcript. An elided result becomes `[tool result elided: N bytes]` — the model is
  told the size, so it can re-run the tool if it needs the content, and is never left
  believing a tool returned nothing.

  ## 2. The summary has a fixed structure

  Pi's: **Goal / Constraints / Progress / Decisions / Next steps**. Fixed, because
  "summarise this conversation" produces a different shape every time and a plan that
  moved between sections is a plan the next turn cannot find. `/compact <focus>` adds the
  operator's focus text to the instruction without removing a section.

  ## 3. Nothing is destroyed

  Every message removed is written to the session's archive before the new conversation
  replaces the old one, and the `compaction` event says how many went there. Amp replaced
  compaction with Handoff precisely because summary-on-summary loses the thread; keeping
  the archive is what makes "what was folded" a question a client can answer.

  ## The thrash guard

  Two compactions inside three turns means compaction is not the fix — the tail alone
  fills the window, or the threshold is wrong. The session stops compacting and says so
  as a `status` provider event rather than looping, which is Claude Code's thrashing
  detection with the reason made visible instead of silent.
  """

  alias Ouroboros.Provider.Native.Context.Window

  @elision_marker "[tool result elided:"

  @typedoc "What one compaction did."
  @type outcome :: %{
          messages: [map()],
          archived: [map()],
          elided: non_neg_integer(),
          summarised: boolean(),
          before_tokens: non_neg_integer(),
          after_tokens: non_neg_integer(),
          summary_tokens: non_neg_integer(),
          summary: String.t() | nil
        }

  @doc """
  Compacts a conversation, in the documented order.

  Options:

    * `:keep_recent_tokens` — how much of the tail survives verbatim (default from
      `Ouroboros.Provider.Native.Context.Window`).
    * `:focus` — the operator's `/compact <focus>` text, or `nil`.
    * `:summarize` — a one-argument function taking the messages to fold and returning
      `{:ok, summary}` or `{:error, reason}`. The session passes a closure that calls the
      model; a caller that passes none gets the structural fallback below, which is worse
      prose and exactly as truthful.
    * `:target_tokens` — stop early once the conversation is this small. Defaults to
      `:keep_recent_tokens`, so eliding alone can finish the job and the model call is
      spent only when it has to be.

  Returns `{:ok, outcome}`, or `{:ok, outcome}` with `summarised: false` when there was
  nothing to fold. It does not fail: a conversation that cannot be made smaller is
  returned unchanged, which the caller reports rather than retries.
  """
  @spec compact([map()], keyword()) :: {:ok, outcome()}
  def compact(messages, opts \\ []) when is_list(messages) do
    keep_recent = Keyword.get(opts, :keep_recent_tokens, Window.default_keep_recent_tokens())
    target = Keyword.get(opts, :target_tokens, keep_recent)
    before_tokens = Window.estimate_tokens(messages)

    {elided_messages, elided_count} = elide_old_tool_results(messages, keep_recent)

    if Window.estimate_tokens(elided_messages) <= target do
      {:ok,
       finish(%{
         messages: elided_messages,
         archived: [],
         elided: elided_count,
         summarised: false,
         summary: nil,
         before_tokens: before_tokens
       })}
    else
      summarise(elided_messages, elided_count, before_tokens, keep_recent, opts)
    end
  end

  @doc """
  Replaces older tool results with a marker, keeping the newest `keep_recent_tokens`.

  Exposed for the caller that wants the cheap half on its own, and for the test that
  asserts the order: tool results first, prose only if that was not enough.
  """
  @spec elide_old_tool_results([map()], pos_integer()) :: {[map()], non_neg_integer()}
  def elide_old_tool_results(messages, keep_recent_tokens) do
    {head, tail} = split_recent(messages, keep_recent_tokens)

    {elided_head, count} =
      Enum.map_reduce(head, 0, fn message, count ->
        if elidable?(message) do
          {elide(message), count + 1}
        else
          {message, count}
        end
      end)

    {elided_head ++ tail, count}
  end

  @doc """
  Splits a conversation into `{older, newest}` at a token budget for the newest part.

  The split never separates an assistant message from the tool results answering it: a
  tool result whose call is not in the request is a hard 400 from most providers, which
  is the same rule `Ouroboros.Provider.Native.Checkpoint` already follows when it trims.
  """
  @spec split_recent([map()], pos_integer()) :: {[map()], [map()]}
  def split_recent(messages, keep_recent_tokens) do
    count = length(messages)

    kept =
      messages
      |> Enum.reverse()
      |> Enum.reduce_while({0, 0}, fn message, {taken, tokens} ->
        next = tokens + Window.estimate_tokens(Window.message_text(message))

        if taken > 0 and next > keep_recent_tokens,
          do: {:halt, {taken, tokens}},
          else: {:cont, {taken + 1, next}}
      end)
      |> elem(0)

    split_at = align(messages, count - kept)
    Enum.split(messages, split_at)
  end

  @doc """
  The instruction a summarising model is given.

  Public because the structure is the contract: a test asserts the five headings, and a
  caller wiring its own summariser must produce the same shape or the next turn's model
  will not find the plan where the last one left it.
  """
  @spec summary_instruction(String.t() | nil) :: String.t()
  def summary_instruction(focus) do
    """
    Summarise the conversation above so that another instance of you can continue the
    work with no other context. Use exactly these five headings, in this order, and put
    every fact under the heading it belongs to:

    ## Goal
    What the operator asked for, in their terms.

    ## Constraints
    Rules, versions, paths, commands, and preferences that must keep holding.

    ## Progress
    What has actually been done and verified, with file paths. Name anything that was
    changed but not verified.

    ## Decisions
    Choices made and the reason for each, including approaches that were rejected.

    ## Next steps
    What remains, in order.

    Write only the summary. Do not add a preamble, and do not claim work that the
    transcript does not show.#{focus_line(focus)}
    """
    |> String.trim()
  end

  @doc """
  A summary built from the transcript alone, for when no model is available.

  It is the same five headings filled from what the runtime can see without inference —
  the operator's messages, the files touched, the commands run. Deliberately thin, and
  labelled as such: a structural summary that pretended to be a written one would send
  the next turn off a cliff with confidence.
  """
  @spec structural_summary([map()], String.t() | nil) :: String.t()
  def structural_summary(messages, focus) do
    user_messages =
      messages
      |> Enum.filter(&(Map.get(&1, :role) == :user))
      |> Enum.map(&String.trim(to_string(Map.get(&1, :content) || "")))
      |> Enum.reject(&(&1 == ""))

    tools =
      messages
      |> Enum.filter(&(Map.get(&1, :role) == :tool))
      |> Enum.map(&Map.get(&1, :name))
      |> Enum.reject(&is_nil/1)
      |> Enum.frequencies()
      |> Enum.sort()
      |> Enum.map_join(", ", fn {name, count} -> "#{name} ×#{count}" end)

    """
    ## Goal

    #{List.first(user_messages) || "(no operator message in the folded range)"}

    ## Constraints

    (not extracted — this summary was built from the transcript's structure because no
    summarising model was available)

    ## Progress

    Tool calls in the folded range: #{if tools == "", do: "none", else: tools}.

    ## Decisions

    (not extracted — see the archived transcript for the reasoning)

    ## Next steps

    #{List.last(user_messages) || "(none stated)"}#{focus_line(focus)}
    """
    |> String.trim()
  end

  @doc "Whether a message is one this module already elided."
  @spec elided?(map()) :: boolean()
  def elided?(%{role: :tool, content: content}) when is_binary(content),
    do: String.starts_with?(content, @elision_marker)

  def elided?(_message), do: false

  # ---------------------------------------------------------------- private

  defp summarise(messages, elided_count, before_tokens, keep_recent, opts) do
    {older, recent} = split_recent(messages, keep_recent)

    if older == [] do
      {:ok,
       finish(%{
         messages: messages,
         archived: [],
         elided: elided_count,
         summarised: false,
         summary: nil,
         before_tokens: before_tokens
       })}
    else
      focus = Keyword.get(opts, :focus)
      summary = run_summariser(Keyword.get(opts, :summarize), older, focus)

      {:ok,
       finish(%{
         messages: [summary_message(summary) | recent],
         archived: older,
         elided: elided_count,
         summarised: true,
         summary: summary,
         before_tokens: before_tokens
       })}
    end
  end

  defp run_summariser(summarize, older, focus) when is_function(summarize, 1) do
    case summarize.(%{messages: older, focus: focus, instruction: summary_instruction(focus)}) do
      {:ok, summary} when is_binary(summary) ->
        case String.trim(summary) do
          "" -> structural_summary(older, focus)
          text -> text
        end

      _failed ->
        structural_summary(older, focus)
    end
  end

  defp run_summariser(_absent, older, focus), do: structural_summary(older, focus)

  # The summary is a user message, not a system one. The system prompt is the cached
  # prefix; putting a per-compaction summary in it would invalidate the cache on every
  # compaction *and* on every turn after it, which is the documented way to make a long
  # session slow and expensive (R3 §5, prompt caching).
  defp summary_message(summary) do
    %{
      role: :user,
      content:
        "The conversation up to this point was compacted. The transcript is retained " <>
          "in this session's archive and can be reviewed. Here is the summary you " <>
          "should continue from:\n\n" <> summary
    }
  end

  defp finish(outcome) do
    after_tokens = Window.estimate_tokens(outcome.messages)

    outcome
    |> Map.put(:after_tokens, after_tokens)
    |> Map.put(
      :summary_tokens,
      if(outcome.summary, do: Window.estimate_tokens(outcome.summary), else: 0)
    )
  end

  defp elidable?(%{role: :tool} = message) do
    content = to_string(Map.get(message, :content) || "")
    content != "" and not elided?(message)
  end

  defp elidable?(_message), do: false

  defp elide(message) do
    content = to_string(Map.get(message, :content) || "")

    %{
      message
      | content: "#{@elision_marker} #{byte_size(content)} bytes]"
    }
  end

  # Move the split point back over any tool results that would be orphaned by it, and
  # over the assistant message that made their calls, so the tail always begins on a
  # message that stands alone.
  defp align(_messages, index) when index <= 0, do: 0

  defp align(messages, index) do
    if index >= length(messages) do
      length(messages)
    else
      case Enum.at(messages, index) do
        %{role: :tool} -> align(messages, index - 1)
        _standalone -> index
      end
    end
  end

  defp focus_line(nil), do: ""
  defp focus_line(""), do: ""

  defp focus_line(focus),
    do: "\n\nThe operator asked the summary to focus on: #{String.trim(focus)}"
end
