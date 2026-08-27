defmodule Ouroboros.Provider.Native.Tools.DesktopAct do
  @moduledoc """
  Operate one desktop app: click, type, press a key, scroll, drag, or focus.

  Computer Use's act half (`docs/COMPUTER_USE.md` §5.3). It classifies as `mode: :execute`
  — plan mode refuses it, and auto-approve never answers it (D3, D10) — and it runs against
  the latest `desktop_state` for this session. Typed `text` is redacted on the emitted
  tool_call; the helper rematches in one coordinate space, refuses secure fields, and
  focuses the target before injecting.
  """

  alias Ouroboros.Provider.Native.Desktop

  use Jido.Action,
    name: "desktop_act",
    description:
      "Click, type, press a key, scroll, drag, or focus, against the latest desktop_state " <>
        "for this session. action is one of click, type, key, scroll, drag, focus. Prefer " <>
        "element_index from that state. Refused if the last state is missing, stale, or for " <>
        "a different app than this call resolves to. Never use this on Terminal, ouro, or " <>
        "ouro-desktop.",
    schema: [
      action: [
        type: :string,
        required: true,
        doc: "One of: click, type, key, scroll, drag, focus."
      ],
      element_index: [
        type: :integer,
        doc: "Index from the latest desktop_state. Preferred for click."
      ],
      x: [
        type: :integer,
        doc: "Click x, screenshot-space pixels. Use with y when no element_index."
      ],
      y: [
        type: :integer,
        doc: "Click y, screenshot-space pixels. Use with x when no element_index."
      ],
      text: [type: :string, doc: "Literal text to type (not a key combo). Max 4 KiB."],
      key: [type: :string, doc: "Key or combo for action key, e.g. Ctrl+L, Enter, Tab."],
      button: [type: :string, doc: "Mouse button: left (default), right, or middle."],
      direction: [type: :string, doc: "Scroll direction: up, down, left, or right."],
      pages: [type: :float, default: 1.0, doc: "Scroll amount in pages. Default 1."],
      from_x: [type: :integer, doc: "Drag start x, screenshot-space pixels."],
      from_y: [type: :integer, doc: "Drag start y, screenshot-space pixels."],
      to_x: [type: :integer, doc: "Drag end x, screenshot-space pixels."],
      to_y: [type: :integer, doc: "Drag end y, screenshot-space pixels."],
      app: [
        type: :string,
        doc: "Optional retarget: bundle id, app name, or app id. Default: last state."
      ],
      window_id: [
        type: :string,
        doc: "Optional retarget: a helper-issued window id. Default: last state."
      ],
      title: [
        type: :string,
        doc: "Optional retarget: a window-title substring. Default: last state."
      ]
    ]

  @not_enabled "computer use is not enabled on this node"
  @max_text_bytes 4 * 1024

  @actions ~w(click type key scroll drag focus)

  # Key grammar (§5.3), copied from the Linux crate: case-insensitive, hyphens and spaces
  # ignored, combos joined with `+`. A combo is any number of modifiers and exactly one
  # non-modifier key.
  @modifiers ~w(ctrl control alt option shift meta super cmd command)
  @named_keys ~w(enter return escape esc tab backspace delete del space home end
                 pageup pagedown up down left right)

  @impl true
  def run(params, context) when is_map(params) do
    context = if is_map(context), do: context, else: %{}

    case validate_args(params) do
      :ok ->
        if Desktop.enabled?() or Map.has_key?(context, :desktop_runner) do
          Desktop.act(params, context)
        else
          {:ok, %{output: @not_enabled, is_error: true, images: []}}
        end

      {:error, message} ->
        {:ok, %{output: message, is_error: true, images: []}}
    end
  end

  @doc """
  The pure §5.3 argument-validation table.

  `:ok` when the action's required fields are present and well-formed, `{:error, message}`
  otherwise. Accepts atom- or string-keyed params so it is testable directly and also works
  on the atom-keyed struct the executor hands `run/2`.
  """
  @spec validate_args(map()) :: :ok | {:error, String.t()}
  def validate_args(params) when is_map(params) do
    case get(params, :action) do
      "click" ->
        validate_click(params)

      "type" ->
        validate_type(params)

      "key" ->
        validate_key(params)

      "scroll" ->
        validate_scroll(params)

      "drag" ->
        validate_drag(params)

      # focus needs no explicit target: "app or window_id or title or last state" (§5.3),
      # and the last-state fallback is a runtime fact, not an argument, so any focus call
      # is well-formed here. Staleness and target resolution are later-phase runtime checks.
      "focus" ->
        :ok

      other ->
        {:error,
         "desktop_act: action must be one of #{Enum.join(@actions, ", ")}, got #{inspect(other)}"}
    end
  end

  def validate_args(_params),
    do: {:error, "desktop_act: expected an object of arguments"}

  @doc "Whether a string is a valid key or combo under the §5.3 grammar."
  @spec valid_key?(term()) :: boolean()
  def valid_key?(key) when is_binary(key) do
    tokens =
      key
      |> String.downcase()
      |> String.split("+", trim: true)
      |> Enum.map(&normalize_token/1)

    tokens != [] and
      Enum.all?(tokens, &recognized_token?/1) and
      Enum.count(tokens, &(not modifier_token?(&1))) == 1
  end

  def valid_key?(_key), do: false

  @doc "Every action name this tool accepts."
  @spec actions() :: [String.t()]
  def actions, do: @actions

  # click: element_index, or both x and y.
  defp validate_click(params) do
    cond do
      integer?(get(params, :element_index)) ->
        :ok

      integer?(get(params, :x)) and integer?(get(params, :y)) ->
        :ok

      true ->
        {:error,
         "desktop_act click: provide element_index from the latest desktop_state, or both " <>
           "x and y in screenshot-space pixels"}
    end
  end

  # type: text nonempty, at most 4 KiB.
  defp validate_type(params) do
    case get(params, :text) do
      text when is_binary(text) and text != "" ->
        if byte_size(text) <= @max_text_bytes,
          do: :ok,
          else: {:error, "desktop_act type: text exceeds #{@max_text_bytes} bytes"}

      _absent ->
        {:error, "desktop_act type: text is required and must be a non-empty string"}
    end
  end

  # key: a key matching the grammar.
  defp validate_key(params) do
    case get(params, :key) do
      key when is_binary(key) and key != "" ->
        if valid_key?(key),
          do: :ok,
          else: {:error, "desktop_act key: #{inspect(key)} is not a valid key or combo"}

      _absent ->
        {:error, "desktop_act key: key is required (e.g. Ctrl+L, Enter, Tab)"}
    end
  end

  # scroll: a direction. A target, when given, follows the click grammar; a scroll with no
  # target scrolls the last-focused window, so only direction is required here.
  defp validate_scroll(params) do
    case get(params, :direction) do
      dir when dir in ~w(up down left right) ->
        :ok

      _absent ->
        {:error, "desktop_act scroll: direction is required and must be up, down, left, or right"}
    end
  end

  # drag: all four endpoints.
  defp validate_drag(params) do
    if Enum.all?([:from_x, :from_y, :to_x, :to_y], &integer?(get(params, &1))) do
      :ok
    else
      {:error,
       "desktop_act drag: from_x, from_y, to_x, and to_y are all required (screenshot-space pixels)"}
    end
  end

  defp normalize_token(token), do: token |> String.replace(["-", " "], "") |> String.trim()

  defp recognized_token?(token), do: modifier_token?(token) or key_token?(token)

  defp modifier_token?(token), do: token in @modifiers

  defp key_token?(token), do: token in @named_keys or function_key?(token) or single_char?(token)

  defp function_key?(<<"f", rest::binary>>) when rest != "" do
    case Integer.parse(rest) do
      {n, ""} -> n >= 1 and n <= 12
      _not_an_integer -> false
    end
  end

  defp function_key?(_token), do: false

  defp single_char?(<<c>>) when c in ?a..?z, do: true
  defp single_char?(<<c>>) when c in ?0..?9, do: true
  defp single_char?(_token), do: false

  defp get(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} -> value
      :error -> Map.get(params, Atom.to_string(key))
    end
  end

  defp integer?(value), do: is_integer(value)
end
