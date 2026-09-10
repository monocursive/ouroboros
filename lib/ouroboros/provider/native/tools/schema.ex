defmodule Ouroboros.Provider.Native.Tools.Schema do
  @moduledoc """
  Converts an owned action schema into the native tool's generated parameter schema.

  Object schemas are closed unless they explicitly allow additional properties. Final
  model schema overrides belong to `Ouroboros.Provider.Native.Tools`; transport
  strictness and tool execution remain at their own boundaries.
  """

  alias Ouroboros.Action.Schema, as: ActionSchema

  @spec from_action(module()) :: map()
  def from_action(module) do
    Code.ensure_loaded!(module)
    Code.ensure_loaded!(ActionSchema)
    strict = if function_exported?(module, :strict?, 0), do: module.strict?(), else: false

    case module.schema() |> ActionSchema.to_json_schema(strict: strict) |> close_objects() do
      empty when empty == %{} ->
        %{
          "type" => "object",
          "properties" => %{},
          "required" => [],
          "additionalProperties" => false
        }

      schema ->
        schema
    end
  end

  defp close_objects(schema) when is_map(schema) do
    schema
    |> Map.new(fn {key, value} -> {key, close_objects(value)} end)
    |> close_object()
  end

  defp close_objects(schema) when is_list(schema), do: Enum.map(schema, &close_objects/1)
  defp close_objects(schema), do: schema

  defp close_object(%{"type" => "object"} = schema),
    do: Map.put_new(schema, "additionalProperties", false)

  defp close_object(%{"properties" => _properties} = schema),
    do: Map.put_new(schema, "additionalProperties", false)

  defp close_object(schema), do: schema
end
