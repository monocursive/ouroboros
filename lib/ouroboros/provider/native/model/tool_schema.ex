defmodule Ouroboros.Provider.Native.Model.ToolSchema do
  @moduledoc """
  Adapts Native tool schemas to the model transport without weakening their contract.

  ReqLLM's OpenAI Responses encoder intentionally rebuilds non-strict parameter schemas,
  but in the version this runtime uses that rebuild drops the top-level `required` list.
  Native therefore uses strict tools on Responses transports when a schema can be expressed
  strictly. Optional properties become required-and-nullable on the wire, as OpenAI strict
  schemas require, and `restore_input/3` removes only the synthetic nulls before dispatch so
  the tool's own defaults still apply.

  An open object schema cannot be represented by OpenAI strict tools without changing its
  meaning. Those schemas remain non-strict and are protected by the loop's local validation
  against the original schema instead. This is chiefly the MCP budget fallback, whose whole
  contract is "the server accepts arbitrary documented arguments".
  """

  @responses_protocols ~w(openai_responses openai_codex_responses)
  @schema_shape_keys ~w(type anyOf oneOf allOf $ref enum const not if)

  # The callback every tool hands ReqLLM. It is never called — the Native loop executes
  # tools itself — but `ReqLLM.Tool.new!` verifies it exists with `function_exported?/3`,
  # which does not load code. On a lazily-loading node this name is data until something
  # calls the module, so `prepare/2` loads it itself rather than depending on whatever
  # happened to run first.
  @unused_callback {Ouroboros.Provider.Native.Model.ReqLLM, :unused_callback}

  @doc "Builds the ReqLLM tools for one model, preserving the original callable contract."
  @spec prepare([map()], String.t()) :: [ReqLLM.Tool.t()]
  def prepare(specs, model_spec) when is_list(specs) do
    {callback_module, _function} = @unused_callback
    _ = Code.ensure_loaded(callback_module)

    strict_transport? = responses_protocol?(model_spec)
    lite_transport? = responses_lite?(model_spec)
    Enum.map(specs, &prepare_one(&1, strict_transport?, lite_transport?))
  end

  @doc "Restores optional nulls introduced solely to satisfy an OpenAI strict schema."
  @spec restore_input([map()], String.t(), term()) :: term()
  def restore_input(specs, name, input)
      when is_list(specs) and is_binary(name) and is_map(input) do
    case Enum.find(specs, &(&1.name == name)) do
      %{parameters: schema} when is_map(schema) ->
        schema = stringify_keys(schema)
        restore_value(input, schema, schema)

      _unknown ->
        input
    end
  end

  def restore_input(_specs, _name, input), do: input

  @doc false
  @spec strict_compatible?(map()) :: boolean()
  def strict_compatible?(schema) when is_map(schema) do
    schema |> stringify_keys() |> compatible_schema?()
  end

  def strict_compatible?(_schema), do: false

  @doc false
  @spec strict_schema(map()) :: map()
  def strict_schema(schema) when is_map(schema) do
    schema |> stringify_keys() |> strictify()
  end

  defp prepare_one(spec, strict_transport?, lite_transport?) do
    compatible? = strict_transport? and strict_compatible?(spec.parameters)

    # Responses Lite supplies client tools in a developer `additional_tools` item rather
    # than the public API's top-level `tools` field. Keep the JSON Schema, but name its
    # required keys in prose as well so a Lite model can repair a call even when that
    # transport does not constrain arguments as strongly as the public Responses API.
    spec =
      if lite_transport? or (strict_transport? and not compatible?),
        do: %{spec | description: required_hint(spec)},
        else: spec

    if compatible? do
      req_tool(spec, strict_schema(spec.parameters), true)
    else
      req_tool(spec, spec.parameters, false)
    end
  end

  defp req_tool(spec, parameters, strict?) do
    ReqLLM.Tool.new!(
      name: spec.name,
      description: spec.description,
      parameter_schema: parameters,
      strict: strict?,
      callback: @unused_callback
    )
  end

  defp required_hint(%{description: description, parameters: parameters}) do
    required = parameters |> stringify_keys() |> Map.get("required", [])

    case required do
      [] ->
        description

      names ->
        description <> " Required arguments: " <> Enum.map_join(names, ", ", &"`#{&1}`") <> "."
    end
  end

  defp responses_protocol?(model_spec) do
    with {:ok, %{extra: extra}} <- ReqLLM.model(model_spec),
         wire when is_map(wire) <- value(extra, :wire),
         protocol when is_binary(protocol) <- value(wire, :protocol) do
      protocol in @responses_protocols
    else
      _unknown -> false
    end
  rescue
    _unresolvable -> false
  end

  defp responses_lite?(model_spec) do
    with {:ok, model} <- ReqLLM.model(model_spec) do
      ReqLLM.Providers.OpenAICodex.ResponsesLite.enabled?(model)
    else
      _unknown -> false
    end
  rescue
    _unresolvable -> false
  end

  # A strict schema cannot preserve an object whose declared contract permits arbitrary
  # keys. In JSON Schema, omitting `additionalProperties` still permits them, so only an
  # explicitly closed object can be strictified without changing its argument surface.
  defp compatible_schema?(%{"type" => "object"} = schema) do
    additional = Map.get(schema, "additionalProperties", :absent)
    patterns = Map.get(schema, "patternProperties", %{})

    additional == false and patterns in [%{}, nil] and compatible_children?(schema)
  end

  defp compatible_schema?(schema) when is_map(schema) do
    Enum.any?(@schema_shape_keys, &Map.has_key?(schema, &1)) and compatible_children?(schema)
  end

  defp compatible_schema?(_boolean_or_invalid), do: false

  defp compatible_children?(schema) do
    schema
    |> schema_children()
    |> Enum.all?(&compatible_schema?/1)
  end

  defp schema_children(schema) do
    property_children =
      case Map.get(schema, "properties") do
        properties when is_map(properties) -> Map.values(properties)
        _none -> []
      end

    definition_children =
      [Map.get(schema, "$defs"), Map.get(schema, "definitions")]
      |> Enum.flat_map(fn
        definitions when is_map(definitions) -> Map.values(definitions)
        _none -> []
      end)

    direct_children =
      ~w(items not if then else contains)
      |> Enum.flat_map(fn key ->
        case Map.get(schema, key) do
          child when is_map(child) -> [child]
          _none -> []
        end
      end)

    variant_children =
      ~w(anyOf oneOf allOf)
      |> Enum.flat_map(fn key ->
        case Map.get(schema, key) do
          children when is_list(children) -> Enum.filter(children, &is_map/1)
          _none -> []
        end
      end)

    property_children ++ definition_children ++ direct_children ++ variant_children
  end

  defp strictify(%{"type" => "object"} = schema) do
    properties = Map.get(schema, "properties", %{})
    originally_required = schema |> Map.get("required", []) |> MapSet.new(&to_string/1)

    strict_properties =
      Map.new(properties, fn {name, property_schema} ->
        name = to_string(name)
        property_schema = strictify(property_schema)

        property_schema =
          if MapSet.member?(originally_required, name) or accepts_null?(property_schema),
            do: property_schema,
            else: nullable(property_schema)

        {name, property_schema}
      end)

    schema
    |> Map.put("properties", strict_properties)
    |> Map.put("required", strict_properties |> Map.keys() |> Enum.sort())
    |> Map.put("additionalProperties", false)
    |> strictify_children()
  end

  defp strictify(schema) when is_map(schema), do: strictify_children(schema)
  defp strictify(schema) when is_list(schema), do: Enum.map(schema, &strictify/1)
  defp strictify(schema), do: schema

  defp strictify_children(schema) do
    schema
    |> update_schema("properties", fn properties ->
      Map.new(properties, fn {k, v} -> {k, strictify(v)} end)
    end)
    |> update_schema("$defs", fn definitions ->
      Map.new(definitions, fn {k, v} -> {k, strictify(v)} end)
    end)
    |> update_schema("definitions", fn definitions ->
      Map.new(definitions, fn {k, v} -> {k, strictify(v)} end)
    end)
    |> update_schema("items", &strictify/1)
    |> update_schema("not", &strictify/1)
    |> update_schema("if", &strictify/1)
    |> update_schema("then", &strictify/1)
    |> update_schema("else", &strictify/1)
    |> update_schema("contains", &strictify/1)
    |> update_schema("anyOf", &Enum.map(&1, fn child -> strictify(child) end))
    |> update_schema("oneOf", &Enum.map(&1, fn child -> strictify(child) end))
    |> update_schema("allOf", &Enum.map(&1, fn child -> strictify(child) end))
  end

  defp update_schema(schema, key, fun) do
    case Map.fetch(schema, key) do
      {:ok, value} -> Map.put(schema, key, fun.(value))
      :error -> schema
    end
  end

  defp nullable(schema), do: %{"anyOf" => [schema, %{"type" => "null"}]}

  defp accepts_null?(%{"type" => "null"}), do: true
  defp accepts_null?(%{"type" => types}) when is_list(types), do: "null" in types
  defp accepts_null?(%{"enum" => values}) when is_list(values), do: nil in values
  defp accepts_null?(%{"const" => nil}), do: true

  defp accepts_null?(schema) when is_map(schema) do
    Enum.any?(~w(anyOf oneOf), fn key ->
      case Map.get(schema, key) do
        variants when is_list(variants) -> Enum.any?(variants, &accepts_null?/1)
        _none -> false
      end
    end)
  end

  defp accepts_null?(_schema), do: false

  defp restore_value(value, %{"$ref" => ref}, root) when is_binary(ref) do
    case resolve_ref(root, ref) do
      {:ok, schema} -> restore_value(value, schema, root)
      :error -> value
    end
  end

  defp restore_value(value, %{"type" => "object", "properties" => properties} = schema, root)
       when is_map(value) and is_map(properties) do
    required = schema |> Map.get("required", []) |> MapSet.new(&to_string/1)

    Enum.reduce(properties, value, fn {name, property_schema}, restored ->
      name = to_string(name)

      case Map.fetch(restored, name) do
        {:ok, nil} ->
          if MapSet.member?(required, name) or accepts_null?(property_schema),
            do: restored,
            else: Map.delete(restored, name)

        {:ok, property_value} ->
          Map.put(restored, name, restore_value(property_value, property_schema, root))

        :error ->
          restored
      end
    end)
  end

  defp restore_value(value, %{"type" => "array", "items" => items}, root)
       when is_list(value) and is_map(items),
       do: Enum.map(value, &restore_value(&1, items, root))

  defp restore_value(value, schema, root) when is_map(schema) do
    variant =
      Enum.find_value(~w(anyOf oneOf), fn key ->
        case Map.get(schema, key) do
          variants when is_list(variants) -> Enum.find(variants, &matches_type?(value, &1))
          _none -> nil
        end
      end)

    if variant, do: restore_value(value, variant, root), else: value
  end

  defp restore_value(value, _schema, _root), do: value

  defp matches_type?(nil, schema), do: accepts_null?(schema)
  defp matches_type?(value, %{"type" => "object"}), do: is_map(value)
  defp matches_type?(value, %{"type" => "array"}), do: is_list(value)
  defp matches_type?(value, %{"type" => "string"}), do: is_binary(value)
  defp matches_type?(value, %{"type" => "integer"}), do: is_integer(value)
  defp matches_type?(value, %{"type" => "number"}), do: is_number(value)
  defp matches_type?(value, %{"type" => "boolean"}), do: is_boolean(value)
  defp matches_type?(_value, _schema), do: false

  defp resolve_ref(root, "#/" <> pointer) do
    pointer
    |> String.split("/")
    |> Enum.map(&(&1 |> String.replace("~1", "/") |> String.replace("~0", "~")))
    |> Enum.reduce_while({:ok, root}, fn segment, {:ok, current} ->
      case current do
        map when is_map(map) ->
          case Map.fetch(map, segment) do
            {:ok, value} -> {:cont, {:ok, value}}
            :error -> {:halt, :error}
          end

        _not_a_map ->
          {:halt, :error}
      end
    end)
  end

  defp resolve_ref(_root, _external_or_invalid), do: :error

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn {key, value} ->
      key = if is_atom(key), do: Atom.to_string(key), else: key
      {key, stringify_keys(value)}
    end)
  end

  defp stringify_keys(list) when is_list(list), do: Enum.map(list, &stringify_keys/1)
  defp stringify_keys(value), do: value

  defp value(map, key), do: Map.get(map, key) || Map.get(map, Atom.to_string(key))
end
