defmodule Ouroboros.Action.Schema do
  @moduledoc """
  Converts the keyword schema subset declared by Ouroboros actions.

  Defaults remain an execution concern. `:any` has the historical generated string
  representation; tools accepting nested/open values deliberately declare a
  `model_schema/0` override. Every supported type is explicit so a future declaration
  cannot silently fall back to string or unrestricted input.
  """

  @options [:type, :required, :default, :doc]

  @spec to_json_schema(keyword() | map(), keyword()) :: map()
  def to_json_schema(schema, opts \\ []) do
    converted = convert(schema)
    if Keyword.get(opts, :strict, false), do: strict_objects(converted), else: converted
  end

  defp convert(%{"type" => "object", "properties" => properties} = schema)
       when is_map(properties), do: schema

  defp convert(schema) when is_list(schema) do
    unless Keyword.keyword?(schema),
      do: raise(ArgumentError, "action schema must be a keyword list")

    properties =
      Map.new(schema, fn {key, opts} ->
        unless Keyword.keyword?(opts),
          do: raise(ArgumentError, "invalid action schema options for #{inspect(key)}")

        unknown = Keyword.keys(opts) -- @options

        unless unknown == [],
          do:
            raise(
              ArgumentError,
              "unsupported action schema options #{inspect(unknown)} for #{inspect(key)}"
            )

        field = type_schema(Keyword.fetch!(opts, :type))

        {Atom.to_string(key),
         Map.put(field, "description", Keyword.get(opts, :doc) || "No description provided.")}
      end)

    %{
      "type" => "object",
      "properties" => properties,
      "required" =>
        for({key, opts} <- schema, Keyword.get(opts, :required, false), do: Atom.to_string(key))
    }
  end

  defp convert(schema),
    do: raise(ArgumentError, "unsupported action schema: #{inspect(schema)}")

  defp strict_objects(schema) when is_map(schema) do
    schema = Map.new(schema, fn {key, value} -> {key, strict_objects(value)} end)

    if Map.get(schema, "type") == "object",
      do: Map.put(schema, "additionalProperties", false),
      else: schema
  end

  defp strict_objects(schema) when is_list(schema), do: Enum.map(schema, &strict_objects/1)
  defp strict_objects(schema), do: schema

  defp type_schema({:in, choices}) when is_list(choices) do
    type =
      cond do
        Enum.all?(choices, &is_integer/1) -> "integer"
        Enum.all?(choices, &is_number/1) -> "number"
        Enum.all?(choices, &is_boolean/1) -> "boolean"
        Enum.all?(choices, &(is_binary(&1) or is_atom(&1))) -> "string"
        true -> nil
      end

    values = if type == "string", do: Enum.map(choices, &to_string/1), else: choices
    if type, do: %{"type" => type, "enum" => values}, else: %{"enum" => values}
  end

  defp type_schema(:string), do: %{"type" => "string"}
  defp type_schema(:boolean), do: %{"type" => "boolean"}
  defp type_schema(:non_neg_integer), do: %{"type" => "integer", "minimum" => 0}
  defp type_schema(:pos_integer), do: %{"type" => "integer", "minimum" => 1}
  defp type_schema(:any), do: %{"type" => "string"}
  defp type_schema({:list, subtype}), do: %{"type" => "array", "items" => type_schema(subtype)}

  defp type_schema(type),
    do: raise(ArgumentError, "unsupported action schema type: #{inspect(type)}")
end
