defmodule Ouroboros.ReasoningEffort do
  @moduledoc """
  The reasoning-effort vocabulary Ouroboros accepts and the compatibility seam to the
  pinned Harness request schemas.

  OpenAI reasoning models can declare `none`, `low`, `medium`, `high`, `xhigh`, and
  `max`. The gateway, web preferences, model catalogue, TUI, and native provider all use
  this ordering. Vendor transports remain on the three values their pinned Harness
  schemas can validate; the native provider can carry the complete vocabulary because it
  owns the model request and can validate the request before entering Harness.

  Harness currently validates only `low | medium | high` in its provider-neutral request
  structs. For native requests, the constructors below let Harness validate every other
  field with the reasoning value temporarily absent, restore a value from this closed
  vocabulary, and then enter the already-validated manager path. This is not a general
  schema bypass: it is native-only, one field wide, and the adapter's own
  `normalized_values` allowlist is still enforced by the managers.
  """

  alias Jido.Harness.{Registry, RequestResolver, RunManager, SessionManager}
  alias Jido.Harness.{RunRequest, Session, SessionRequest, TurnRequest}

  @atoms [:none, :low, :medium, :high, :xhigh, :max]
  @legacy_atoms [:low, :medium, :high]
  @names Enum.map(@atoms, &Atom.to_string/1)
  @legacy_names Enum.map(@legacy_atoms, &Atom.to_string/1)

  @spec atoms() :: [atom()]
  def atoms, do: @atoms

  @doc "The canonical values plus omission, for transport-level validation."
  @spec atoms_or_nil() :: [atom() | nil]
  def atoms_or_nil, do: @atoms ++ [nil]

  @spec names() :: [String.t()]
  def names, do: @names

  @doc "The values a provider's current transport can accept, in display order."
  @spec names_for_provider(atom() | String.t() | nil) :: [String.t()]
  def names_for_provider(provider) when provider in [:native, "native"], do: @names
  def names_for_provider(_provider), do: @legacy_names

  @spec valid?(term()) :: boolean()
  def valid?(value), do: value in @atoms or value in @names

  @doc "Starts a Harness session, preserving the native provider's wider vocabulary."
  @spec start_session(atom(), map() | keyword()) :: {:ok, String.t()} | {:error, term()}
  def start_session(:native, attrs) when is_map(attrs) or is_list(attrs) do
    with {:ok, attrs} <- attributes(attrs),
         defaults =
           Registry.provider_config(:native) |> Map.get(:session_defaults, %{}) |> Map.new(),
         merged = defaults |> Map.merge(attrs) |> Map.put(:provider, :native),
         {:ok, request} <- session_request(merged) do
      SessionManager.start(:native, request)
    end
  end

  def start_session(provider, attrs), do: Session.start(provider, attrs)

  @doc "Starts a detached Harness run, preserving the native provider's wider vocabulary."
  @spec start_run(atom(), map() | keyword()) :: {:ok, String.t()} | {:error, term()}
  def start_run(:native, attrs) when is_map(attrs) or is_list(attrs) do
    with {:ok, attrs} <- attributes(attrs),
         {:ok, request} <- native_run_request(attrs),
         {:ok, request} <- RequestResolver.resolve(:native, request) do
      RunManager.start(:native, request)
    end
  end

  def start_run(provider, attrs), do: Jido.Harness.Run.start(provider, attrs)

  @doc "Builds a session request while retaining a canonical reasoning effort."
  @spec session_request(map() | keyword()) :: {:ok, SessionRequest.t()} | {:error, term()}
  def session_request(attrs) when is_map(attrs) or is_list(attrs) do
    with {:ok, attrs} <- attributes(attrs),
         {:ok, effort} <- effort(attrs),
         {:ok, request} <- SessionRequest.new(without_effort(attrs)) do
      {:ok, %{request | reasoning_effort: effort}}
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
         {:ok, request} <- TurnRequest.new(without_effort(attrs)) do
      {:ok, %{request | reasoning_effort: effort}}
    end
  end

  def turn_request(attrs), do: TurnRequest.new(attrs)

  @doc "Builds a turn request after applying the same option precedence as Harness."
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

  @doc "The bang form used by native run and subagent internals."
  @spec turn_request!(map() | keyword() | String.t() | TurnRequest.t()) :: TurnRequest.t()
  def turn_request!(attrs) do
    case turn_request(attrs) do
      {:ok, request} -> request
      {:error, reason} -> raise ArgumentError, "invalid turn request: #{inspect(reason)}"
    end
  end

  defp native_run_request(attrs) do
    with {:ok, spec} <- Registry.spec(:native),
         config_defaults =
           Registry.provider_config(:native) |> Map.get(:request_defaults, %{}) |> Map.new(),
         explicit = attrs |> Map.delete(:provider) |> Map.delete("provider"),
         merged =
           spec.request_defaults
           |> Map.merge(config_defaults)
           |> Map.merge(explicit)
           |> Map.put(:provider, :native),
         {:ok, effort} <- effort(merged),
         {:ok, request} <- RunRequest.new(without_effort(merged)) do
      {:ok, %{request | reasoning_effort: effort}}
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

  defp without_effort(attrs) do
    attrs
    |> Map.delete("reasoning_effort")
    |> Map.put(:reasoning_effort, nil)
  end

  defp valid_atom_or_nil?(nil), do: true
  defp valid_atom_or_nil?(value), do: value in @atoms
end
