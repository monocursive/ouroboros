defmodule Ouroboros.Action do
  @moduledoc """
  The definition and validation contract for owned tools and mesh actions.

  Execution, timeouts, permissions and audit recording belong to their callers. The
  optional macro supplies metadata and NimbleOptions validation, preserving unknown
  atom or string keys in direct action calls. Native tool execution separately selects
  declared string keys before validation; dynamic MCP arguments never use this macro.
  """

  @callback name() :: String.t()
  @callback description() :: String.t()
  @callback schema() :: keyword()
  @callback validate_params(map()) :: {:ok, map()} | {:error, term()}
  @callback run(map(), map()) :: {:ok, map()} | {:error, term()}
  @callback description(keyword()) :: String.t() | nil
  @callback model_schema() :: map()
  @optional_callbacks description: 1, model_schema: 0

  defmacro __using__(opts) do
    quote do
      @behaviour Ouroboros.Action
      @action_definition unquote(opts)
      @action_schema Keyword.fetch!(@action_definition, :schema)
      @action_options NimbleOptions.new!(@action_schema)
      # Reject unsupported future declarations during compilation, including when a
      # model_schema override would otherwise hide a malformed generated schema.
      Ouroboros.Action.Schema.to_json_schema(@action_schema)

      @impl true
      def name, do: Keyword.fetch!(@action_definition, :name)
      @impl true
      def description, do: Keyword.fetch!(@action_definition, :description)
      @impl true
      def schema, do: @action_schema
      @impl true
      def validate_params(params),
        do: Ouroboros.Action.validate(params, @action_options, __MODULE__)
    end
  end

  @doc false
  @spec validate(map(), NimbleOptions.t(), module()) :: {:ok, map()} | {:error, Exception.t()}
  def validate(params, %NimbleOptions{schema: schema} = options, module) when is_map(params) do
    {known, unknown} = Map.split(params, Keyword.keys(schema))

    case NimbleOptions.validate(Map.to_list(known), options) do
      {:ok, validated} ->
        {:ok, Map.merge(unknown, Map.new(validated))}

      {:error, error} ->
        {:error,
         %Ouroboros.Action.ValidationError{message: validation_message(error, "Action", module)}}
    end
  end

  def validate(_params, _options, module) do
    {:error,
     %Ouroboros.Action.ValidationError{
       message: "Invalid parameters for Action (#{module}): expected a map"
     }}
  end

  @doc false
  def validation_message(
        %NimbleOptions.ValidationError{keys_path: path, message: message},
        context,
        module
      ) do
    location = if path == [], do: "", else: " at #{inspect(path)}"
    "Invalid parameters for #{context} (#{module})#{location}: #{message}"
  end
end
