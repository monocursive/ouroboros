defmodule Ouroboros.Provider.Native.Context.Window do
  @moduledoc """
  How large this model's context is, how much of it the last request used, and when that
  becomes a reason to compact.

  The window comes from `llm_db`'s `limits.context` for the resolved model spec. When
  `llm_db` does not know the model, a node may state one with
  `config :ouroboros, :native_context_window`. When neither answers, the window is
  **unknown** and stays unknown: the meter reports `nil` and the footer draws tokens
  without a percentage. A percentage divided by a number this runtime guessed would be a
  measurement-shaped lie, and the whole point of the meter is that the operator can act
  on it.

  ## What "used" means

  `context_used` is the size of the last request as the provider counted it, not a
  running total of the session's spend — the two diverge the moment anything is dropped
  from the conversation, and it is the request size that decides whether the next one
  fits.

  Providers disagree about whether cached reads are inside `input_tokens` or beside it.
  `Ouroboros.Provider.Native.Cost` already takes the inclusive reading (it subtracts the
  cached share before pricing the rest), so this module keeps the same reading and adds
  the one correction that makes it safe either way: when the cached counts alone exceed
  `input_tokens`, the provider was reporting them separately and they are added. That
  never double-counts and never undercounts.
  """

  @default_compact_at 0.85
  @default_keep_recent_tokens 20_000

  # What one image or file part of a user message is charged when the estimate cannot see
  # it. Every vendor prices an image somewhere near a thousand tokens, and a part counted
  # as free is a part that lets a conversation sail past the threshold it was measured
  # against.
  @nominal_part_tokens 1_000

  @typedoc "The window, or the fact that this node does not know it."
  @type window :: pos_integer() | nil

  @doc """
  The context window for one model spec, or `nil` when this node cannot say.

  Never raises and never guesses: `llm_db` first, node configuration second, `nil` third.
  """
  @spec resolve(String.t() | nil) :: window()
  def resolve(model_spec) do
    from_db(model_spec) || configured()
  end

  @doc """
  How many tokens the last request occupied, from one `usage` payload.

  Accepts the string-keyed payload `Ouroboros.Provider.Native.Cost` produces.
  """
  @spec used(map()) :: non_neg_integer()
  def used(payload) when is_map(payload) do
    input = number(payload, "input_tokens")
    cache_read = number(payload, "cache_read_tokens")
    cache_creation = number(payload, "cache_creation_tokens")
    cached = cache_read + cache_creation

    if cached > input, do: input + cached, else: input
  end

  def used(_payload), do: 0

  @doc """
  The meter fields to merge into a `usage` payload.

  `context_window` keeps that exact name because the TUI footer decodes it
  (`tui/src/model.rs`); a rename here is a silently dark meter there. Both keys are
  omitted when the window is unknown rather than being emitted as zero.
  """
  @spec meter(map(), window()) :: map()
  def meter(payload, nil), do: Map.put(payload, "context_used", used(payload))

  def meter(payload, window) when is_integer(window) and window > 0 do
    payload
    |> Map.put("context_used", used(payload))
    |> Map.put("context_window", window)
  end

  def meter(payload, _window), do: meter(payload, nil)

  @doc """
  Whether a request of this size is past the compaction threshold.

  Always `false` when the window is unknown. Compacting on a guess would throw away the
  operator's conversation on the strength of a number nobody reported.
  """
  @spec over_threshold?(non_neg_integer(), window(), float()) :: boolean()
  def over_threshold?(_used, nil, _fraction), do: false

  def over_threshold?(used, window, fraction)
      when is_integer(window) and window > 0 and is_number(fraction),
      do: used >= trunc(window * fraction)

  def over_threshold?(_used, _window, _fraction), do: false

  @doc "The fraction of the window at which a session compacts itself."
  @spec compact_at(map() | keyword()) :: float()
  def compact_at(options) when is_map(options) do
    case field(options, :compact_at) do
      value when is_number(value) and value > 0 and value <= 1 -> value / 1
      _unset -> @default_compact_at
    end
  end

  def compact_at(options) when is_list(options), do: compact_at(Map.new(options))
  def compact_at(_other), do: @default_compact_at

  @doc "How many tokens of the newest conversation compaction keeps verbatim."
  @spec keep_recent_tokens(map() | keyword()) :: pos_integer()
  def keep_recent_tokens(options) when is_map(options) do
    case field(options, :keep_recent_tokens) do
      value when is_integer(value) and value > 0 -> min(value, 500_000)
      _unset -> @default_keep_recent_tokens
    end
  end

  def keep_recent_tokens(options) when is_list(options), do: keep_recent_tokens(Map.new(options))
  def keep_recent_tokens(_other), do: @default_keep_recent_tokens

  @doc "The default compaction threshold, as a fraction of the window."
  @spec default_compact_at() :: float()
  def default_compact_at, do: @default_compact_at

  @doc "The default number of newest tokens compaction keeps verbatim."
  @spec default_keep_recent_tokens() :: pos_integer()
  def default_keep_recent_tokens, do: @default_keep_recent_tokens

  @doc """
  A rough token count for a message list.

  Four characters per token, the ratio every vendor publishes for English prose and code.
  It is used only to decide how much of the tail to keep verbatim, never to report a
  number to the operator: the meter's figures come from the provider's own `usage`.
  """
  @spec estimate_tokens([map()] | String.t()) :: non_neg_integer()
  def estimate_tokens(text) when is_binary(text), do: div(byte_size(text), 4) + 1

  def estimate_tokens(messages) when is_list(messages),
    do: Enum.reduce(messages, 0, &(message_tokens(&1) + &2))

  @doc """
  A rough token count for one message, its non-text parts included.

  Use this rather than `estimate_tokens(message_text(message))`: an attachment turn's
  content is a list of parts, and the image in it costs the window something no character
  count can see.
  """
  @spec message_tokens(map()) :: non_neg_integer()
  def message_tokens(message) when is_map(message),
    do: estimate_tokens(message_text(message)) + opaque_tokens(message)

  def message_tokens(_message), do: 0

  @doc false
  @spec message_text(map()) :: String.t()
  def message_text(%{role: :assistant} = message) do
    calls =
      message
      |> Map.get(:tool_calls, [])
      |> Enum.map_join(" ", fn call ->
        "#{Map.get(call, :name, "")} #{inspect(Map.get(call, :input, %{}))}"
      end)

    content_text(Map.get(message, :content)) <> " " <> calls
  end

  def message_text(message) when is_map(message),
    do: content_text(Map.get(message, :content))

  def message_text(_message), do: ""

  # ---------------------------------------------------------------- private

  # Total, deliberately. An attachment turn's content is a list of parts
  # (`Ouroboros.Provider.Native.Attachments.message/3`), and `to_string/1` on that list
  # raises — which, on the compaction path of a `restart: :temporary` session, is the
  # session gone. A checkpoint round-trip turns the parts' atom keys into string ones, so
  # both spellings are read.
  defp content_text(content) when is_binary(content), do: content

  defp content_text(parts) when is_list(parts),
    do: parts |> Enum.map(&part_text/1) |> Enum.reject(&(&1 == "")) |> Enum.join(" ")

  defp content_text(part) when is_map(part), do: part_text(part)

  defp content_text(other) when is_atom(other) or is_number(other), do: to_string(other)
  defp content_text(_other), do: ""

  defp part_text(part) when is_binary(part), do: part

  defp part_text(part) when is_map(part) do
    case field(part, :text) do
      text when is_binary(text) -> text
      _absent -> ""
    end
  end

  defp part_text(_part), do: ""

  defp opaque_tokens(%{content: parts}) when is_list(parts),
    do: @nominal_part_tokens * Enum.count(parts, &(not text_part?(&1)))

  defp opaque_tokens(_message), do: 0

  # A part with no `type`, or one typed `text`, is counted by its characters. Anything
  # else — an image, a file — is counted at the nominal charge.
  defp text_part?(part) when is_map(part), do: field(part, :type) in [nil, :text, "text"]
  defp text_part?(part), do: is_binary(part)

  defp field(map, key), do: Map.get(map, key) || Map.get(map, Atom.to_string(key))

  defp from_db(model_spec) when is_binary(model_spec) and model_spec != "" do
    with true <- Code.ensure_loaded?(LLMDB),
         {:ok, model} <- LLMDB.model(model_spec),
         limits when is_map(limits) <- Map.get(model, :limits),
         context when is_integer(context) and context > 0 <- Map.get(limits, :context) do
      context
    else
      _unknown -> nil
    end
  rescue
    _error -> nil
  catch
    :exit, _reason -> nil
  end

  defp from_db(_model_spec), do: nil

  defp configured do
    case Application.get_env(:ouroboros, :native_context_window) do
      value when is_integer(value) and value > 0 -> value
      _unset -> nil
    end
  end

  defp number(payload, key) do
    case Map.get(payload, key) do
      value when is_integer(value) and value >= 0 -> value
      value when is_float(value) and value >= 0 -> trunc(value)
      _absent -> 0
    end
  end
end
