defmodule Ouroboros.ReasoningEffort do
  @moduledoc "The closed reasoning-effort vocabulary accepted by native session requests."

  alias Ouroboros.Session.Request, as: SessionRequest
  alias Ouroboros.Session.TurnRequest

  @atoms [:none, :low, :medium, :high, :xhigh, :max]
  @names Enum.map(@atoms, &Atom.to_string/1)

  @spec atoms() :: [atom()]
  def atoms, do: @atoms

  @doc "The canonical values plus omission, for transport-level validation."
  @spec atoms_or_nil() :: [atom() | nil]
  def atoms_or_nil, do: @atoms ++ [nil]

  @spec names() :: [String.t()]
  def names, do: @names

  @doc "The values the native transport accepts, in display order."
  @spec accepted_names() :: [String.t()]
  def accepted_names, do: @names

  @spec valid?(term()) :: boolean()
  def valid?(value), do: value in @atoms or value in @names

  @doc "Builds a session request while retaining a canonical reasoning effort."
  @spec session_request(map() | keyword()) :: {:ok, SessionRequest.t()} | {:error, term()}
  def session_request(attrs) when is_map(attrs) or is_list(attrs) do
    with {:ok, attrs} <- attributes(attrs),
         {:ok, effort} <- effort(attrs),
         {:ok, request} <- SessionRequest.new(with_effort(attrs, effort)) do
      {:ok, request}
    end
  end

  @doc "Builds a turn request while retaining a canonical reasoning effort."
  @spec turn_request(map() | keyword() | String.t() | TurnRequest.t()) ::
          {:ok, TurnRequest.t()} | {:error, term()}
  def turn_request(%TurnRequest{reasoning_effort: effort} = request) do
    if valid_atom_or_nil?(effort), do: {:ok, request}, else: {:error, :invalid_reasoning_effort}
  end

  def turn_request(prompt) when is_binary(prompt), do: TurnRequest.new(prompt)

  def turn_request(attrs) when is_map(attrs) or is_list(attrs) do
    with {:ok, attrs} <- attributes(attrs),
         {:ok, effort} <- effort(attrs),
         {:ok, request} <- TurnRequest.new(with_effort(attrs, effort)) do
      {:ok, request}
    end
  end

  def turn_request(attrs), do: TurnRequest.new(attrs)

  @doc "Builds a turn request after applying the established option precedence."
  @spec turn_request(term(), keyword()) :: {:ok, TurnRequest.t()} | {:error, term()}
  def turn_request(input, options) when is_list(options) do
    if Keyword.keyword?(options) do
      attrs =
        case input do
          %TurnRequest{} = request ->
            request |> Map.from_struct() |> Map.merge(Map.new(options))

          prompt when is_binary(prompt) ->
            options |> Map.new() |> Map.put(:prompt, prompt)

          input when is_map(input) ->
            Map.merge(input, Map.new(options))

          input when is_list(input) ->
            if Keyword.keyword?(input),
              do: input |> Map.new() |> Map.merge(Map.new(options)),
              else: input

          other ->
            other
        end

      turn_request(attrs)
    else
      {:error, :invalid_turn_options}
    end
  end

  def turn_request(_input, _options), do: {:error, :invalid_turn_options}

  @doc "The bang form used by native session and subagent internals."
  @spec turn_request!(map() | keyword() | String.t() | TurnRequest.t()) :: TurnRequest.t()
  def turn_request!(attrs) do
    case turn_request(attrs) do
      {:ok, request} -> request
      {:error, reason} -> raise ArgumentError, "invalid turn request: #{inspect(reason)}"
    end
  end

  defp attributes(attrs) when is_map(attrs), do: {:ok, attrs}

  defp attributes(attrs) when is_list(attrs) do
    if Keyword.keyword?(attrs), do: {:ok, Map.new(attrs)}, else: {:error, :invalid_attributes}
  end

  defp effort(attrs) do
    value = Map.get(attrs, :reasoning_effort, Map.get(attrs, "reasoning_effort"))

    case value do
      nil ->
        {:ok, nil}

      value when value in @atoms ->
        {:ok, value}

      value when value in @names ->
        {:ok, Enum.at(@atoms, Enum.find_index(@names, &(&1 == value)))}

      _invalid ->
        {:error, :invalid_reasoning_effort}
    end
  end

  defp with_effort(attrs, effort) do
    attrs
    |> Map.delete("reasoning_effort")
    |> Map.put(:reasoning_effort, effort)
  end

  defp valid_atom_or_nil?(nil), do: true
  defp valid_atom_or_nil?(value), do: value in @atoms
end
