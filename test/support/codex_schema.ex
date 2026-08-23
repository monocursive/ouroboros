defmodule Ouroboros.Test.CodexSchema do
  @moduledoc """
  The Codex app-server JSON schema, as the tests read it.

  The files under `test/support/codex_schema/` are **verbatim** output of

      codex app-server generate-json-schema --out <dir>

  from codex-cli 0.147.0 — the version `Ouroboros.Provider.Session.Dialect.Codex`
  is written against. Nothing here is hand-written, so regenerating the schema and
  diffing the directory is enough to see what a Codex upgrade moved. `manifest.json`
  records each file's SHA-256 and where in the generator's output it came from
  (`v2/` for the new API, the root for server→client requests).

  ## Why a checker rather than literal fixtures

  A test that asserts a frame equals a literal it also wrote proves only that the
  literal was copied consistently. `assert_valid!/2` instead checks the frame against
  the schema itself: every `required` property present, no property the schema does
  not declare, and every `enum`/`const` honoured. Drift in Codex's own schema then
  fails here rather than in a session.

  Deliberately not a general JSON-Schema implementation. It covers the keywords these
  particular params and responses actually use — `properties`, `required`,
  `additionalProperties`, `enum`, `type`, `items`, `oneOf`, `anyOf`, `allOf`, `$ref`
  to `#/definitions/*`. A schema using anything else raises rather than passing
  quietly, because a check that silently skips what it does not understand is worse
  than no check at all.
  """

  @dir Path.join(__DIR__, "codex_schema")
  @external_resource Path.join(@dir, "manifest.json")

  @doc "The parsed schema named by its generator filename, without the `.json`."
  @spec load(String.t()) :: map()
  def load(name) do
    @dir
    |> Path.join(name <> ".json")
    |> File.read!()
    |> JSON.decode!()
  end

  @doc "The codex-cli version every file in this directory was generated from."
  @spec codex_version() :: String.t()
  def codex_version, do: manifest()["codexVersion"]

  @doc "The recorded SHA-256 of one schema file, as generated."
  @spec digest(String.t()) :: String.t()
  def digest(name), do: get_in(manifest(), ["files", name <> ".json", "sha256"])

  @doc "The manifest recording provenance for every file in this directory."
  @spec manifest() :: map()
  def manifest, do: @dir |> Path.join("manifest.json") |> File.read!() |> JSON.decode!()

  @doc """
  Raises unless `value` satisfies the schema named by `name`.

  Returns `value`, so it composes into a pipeline or an `assert`.
  """
  @spec assert_valid!(term(), String.t()) :: term()
  def assert_valid!(value, name) do
    schema = load(name)
    validate!(value, schema, schema, name)
    value
  end

  # ── the checker ──────────────────────────────────────────────────────────────────

  defp validate!(value, schema, root, path) do
    Enum.each(schema, fn {keyword, constraint} ->
      check!(keyword, constraint, value, schema, root, path)
    end)

    :ok
  end

  # Annotations. `$schema`/`title`/`description` say nothing about an instance, and
  # `default` describes what the *server* substitutes for an absent property rather
  # than something a sent frame must contain.
  defp check!(keyword, _constraint, _value, _schema, _root, _path)
       when keyword in ~w($schema title description definitions default format minimum $comment),
       do: :ok

  defp check!("$ref", "#/definitions/" <> name, value, _schema, root, path) do
    resolved = get_in(root, ["definitions", name]) || raise "no definition #{name} at #{path}"
    validate!(value, resolved, root, path <> "/" <> name)
  end

  defp check!("type", types, value, _schema, _root, path) do
    types = List.wrap(types)

    unless Enum.any?(types, &type?(&1, value)) do
      raise "#{path}: expected #{Enum.join(types, "|")}, got #{inspect(value)}"
    end
  end

  defp check!("enum", allowed, value, _schema, _root, path) do
    unless value in allowed do
      raise "#{path}: #{inspect(value)} is not one of #{inspect(allowed)}"
    end
  end

  defp check!("const", expected, value, _schema, _root, path) do
    unless value == expected do
      raise "#{path}: expected #{inspect(expected)}, got #{inspect(value)}"
    end
  end

  defp check!("required", names, value, _schema, _root, path) when is_map(value) do
    case Enum.reject(names, &Map.has_key?(value, &1)) do
      [] -> :ok
      missing -> raise "#{path}: missing required #{Enum.join(missing, ", ")}"
    end
  end

  defp check!("required", _names, _value, _schema, _root, _path), do: :ok

  defp check!("properties", properties, value, _schema, root, path) when is_map(value) do
    Enum.each(value, fn {key, member} ->
      case Map.fetch(properties, key) do
        {:ok, subschema} -> validate!(member, subschema, root, path <> "." <> key)
        # `additionalProperties` decides whether an undeclared key is allowed; a
        # schema that declares neither says nothing about it, so neither does this.
        :error -> :ok
      end
    end)
  end

  defp check!("properties", _properties, _value, _schema, _root, _path), do: :ok

  defp check!("additionalProperties", false, value, schema, _root, path) when is_map(value) do
    declared = Map.keys(schema["properties"] || %{})

    case Enum.reject(Map.keys(value), &(&1 in declared)) do
      [] -> :ok
      extra -> raise "#{path}: undeclared #{Enum.join(extra, ", ")}"
    end
  end

  defp check!("additionalProperties", _constraint, _value, _schema, _root, _path), do: :ok

  defp check!("items", subschema, value, _schema, root, path) when is_list(value) do
    value
    |> Enum.with_index()
    |> Enum.each(fn {member, index} ->
      validate!(member, subschema, root, "#{path}[#{index}]")
    end)
  end

  defp check!("items", _subschema, _value, _schema, _root, _path), do: :ok

  # `oneOf` is how this schema spells a tagged union, and the arms are distinguished
  # by their own `type`/`enum` constants — so "exactly one matches" is the real check
  # and a value matching two arms is as much a bug as one matching none.
  defp check!("oneOf", branches, value, _schema, root, path) do
    case Enum.count(branches, &matches?(value, &1, root)) do
      1 -> :ok
      0 -> raise "#{path}: #{inspect(value)} matches no oneOf branch"
      n -> raise "#{path}: #{inspect(value)} matches #{n} oneOf branches"
    end
  end

  defp check!("anyOf", branches, value, _schema, root, path) do
    unless Enum.any?(branches, &matches?(value, &1, root)) do
      raise "#{path}: #{inspect(value)} matches no anyOf branch"
    end
  end

  defp check!("allOf", branches, value, _schema, root, path) do
    Enum.each(branches, &validate!(value, &1, root, path))
  end

  defp check!(keyword, _constraint, _value, _schema, _root, path) do
    raise "#{path}: this checker does not implement the #{keyword} keyword; extend it"
  end

  defp matches?(value, schema, root) do
    validate!(value, schema, root, "?")
    true
  rescue
    _error -> false
  end

  defp type?("object", value), do: is_map(value)
  defp type?("array", value), do: is_list(value)
  defp type?("string", value), do: is_binary(value)
  defp type?("boolean", value), do: is_boolean(value)
  defp type?("integer", value), do: is_integer(value)
  defp type?("number", value), do: is_number(value)
  defp type?("null", value), do: is_nil(value)
  defp type?(other, _value), do: raise("unknown JSON type #{inspect(other)}")
end
