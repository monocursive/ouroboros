defmodule Ouroboros.CodeIntel.Results do
  @moduledoc """
  Normalises language-server answers into plain maps a client, a model, or a gateway
  method can use without knowing LSP.

  Three rules. Paths are relative to the project root when the target is inside it and
  absolute when it is not, with `external: true` saying which — a definition in a
  dependency or a standard library is a genuinely different kind of answer from one in
  the user's own tree, and collapsing them loses that. Positions stay 0-based, exactly as
  the protocol reports them, because a normaliser that quietly adds one is a bug nobody
  finds until a caller reads the wrong line. And every list is capped: `max_results`
  bounds what a `find references` on a popular symbol can cost, and the surplus is
  reported as a count rather than silently dropped.

  The protocol offers several shapes for most of these answers — `Location`,
  `Location[]`, `LocationLink[]`; hierarchical `DocumentSymbol` or flat
  `SymbolInformation`; `MarkupContent` or the deprecated `MarkedString` — and servers
  disagree about which they send. Every shape is accepted here, and anything unrecognised
  yields an empty list rather than a crash: a stranger's malformed answer must not become
  this runtime's exception.
  """

  alias Ouroboros.CodeIntel.Lsp.Server

  @symbol_kinds %{
    1 => :file,
    2 => :module,
    3 => :namespace,
    4 => :package,
    5 => :class,
    6 => :method,
    7 => :property,
    8 => :field,
    9 => :constructor,
    10 => :enum,
    11 => :interface,
    12 => :function,
    13 => :variable,
    14 => :constant,
    15 => :string,
    16 => :number,
    17 => :boolean,
    18 => :array,
    19 => :object,
    20 => :key,
    21 => :null,
    22 => :enum_member,
    23 => :struct,
    24 => :event,
    25 => :operator,
    26 => :type_parameter
  }

  # A symbol tree deeper than this is a generated file, and walking it is not free.
  @max_symbol_depth 32

  @type bounded :: %{items: [map()], truncated: non_neg_integer()}

  @doc "Locations, from any of the three shapes a server may answer with."
  @spec locations(term(), String.t(), pos_integer()) :: bounded()
  def locations(result, root, max) do
    result
    |> List.wrap()
    |> Enum.flat_map(&location(&1, root))
    |> bound(max)
  end

  @doc "Hover contents flattened to one string, or nil when the server had nothing."
  @spec hover(term(), String.t()) :: map() | nil
  def hover(%{"contents" => contents} = result, root) do
    case hover_text(contents) do
      "" -> nil
      text -> %{value: text, range: range(result["range"]), root: root}
    end
  end

  def hover(_result, _root), do: nil

  @doc "Document symbols, hierarchical or flat, capped by total node count."
  @spec document_symbols(term(), String.t(), String.t(), pos_integer()) :: bounded()
  def document_symbols(result, root, path, max) do
    result
    |> List.wrap()
    |> Enum.flat_map(&document_symbol(&1, root, path, @max_symbol_depth))
    |> bound(max)
  end

  @doc "Workspace symbols, which always carry their own location."
  @spec workspace_symbols(term(), String.t(), pos_integer()) :: bounded()
  def workspace_symbols(result, root, max) do
    result
    |> List.wrap()
    |> Enum.flat_map(&workspace_symbol(&1, root))
    |> bound(max)
  end

  @doc "Call-hierarchy items, as `prepareCallHierarchy` answers them."
  @spec call_hierarchy_items(term(), String.t(), pos_integer()) :: bounded()
  def call_hierarchy_items(result, root, max) do
    result
    |> List.wrap()
    |> Enum.flat_map(&call_hierarchy_item(&1, root))
    |> bound(max)
  end

  @doc "Incoming or outgoing calls, keyed by the field the direction uses."
  @spec calls(term(), String.t(), String.t(), pos_integer()) :: bounded()
  def calls(result, root, key, max) do
    result
    |> List.wrap()
    |> Enum.flat_map(fn
      %{^key => item} = call ->
        case call_hierarchy_item(item, root) do
          [normalized] ->
            [%{item: normalized, ranges: call |> Map.get("fromRanges", []) |> Enum.map(&range/1)}]

          [] ->
            []
        end

      _other ->
        []
    end)
    |> bound(max)
  end

  @doc false
  @spec symbol_kind(term()) :: atom() | nil
  def symbol_kind(kind) when is_integer(kind), do: Map.get(@symbol_kinds, kind)
  def symbol_kind(_kind), do: nil

  # A path relative to `root` when it is inside it, absolute when it is not.
  defp relative(path, root) do
    cond do
      path == root ->
        {".", false}

      String.starts_with?(path, root <> "/") ->
        {binary_slice(path, (byte_size(root) + 1)..-1//1), false}

      true ->
        {path, true}
    end
  end

  ## Shapes

  defp location(%{"uri" => uri, "range" => raw_range}, root),
    do: place(uri, root, %{range: range(raw_range)})

  defp location(%{"targetUri" => uri} = link, root) do
    place(uri, root, %{
      range: range(link["targetRange"]),
      selection_range: range(link["targetSelectionRange"] || link["targetRange"])
    })
  end

  defp location(%{"location" => location}, root), do: location(location, root)
  defp location(_other, _root), do: []

  defp document_symbol(_symbol, _root, _path, depth) when depth <= 0, do: []

  # The hierarchical shape: a range, a selection range, and children.
  defp document_symbol(%{"name" => name, "range" => raw_range} = symbol, root, path, depth) do
    {relative_path, external?} = relative(path, root)

    [
      %{
        name: to_string(name),
        kind: symbol_kind(symbol["kind"]),
        detail: string_or_nil(symbol["detail"]),
        path: relative_path,
        external: external?,
        range: range(raw_range),
        selection_range: range(symbol["selectionRange"] || raw_range),
        children:
          symbol
          |> Map.get("children", [])
          |> List.wrap()
          |> Enum.flat_map(&document_symbol(&1, root, path, depth - 1))
      }
    ]
  end

  # The flat shape: a `SymbolInformation` carrying its own location.
  defp document_symbol(
         %{"name" => name, "location" => %{"uri" => uri} = location},
         root,
         _path,
         _depth
       ) do
    place(uri, root, %{
      name: to_string(name),
      kind: symbol_kind(location["kind"]),
      detail: nil,
      range: range(location["range"]),
      selection_range: range(location["range"]),
      children: []
    })
  end

  defp document_symbol(_symbol, _root, _path, _depth), do: []

  defp workspace_symbol(
         %{"name" => name, "location" => %{"uri" => uri} = location} = symbol,
         root
       ) do
    place(uri, root, %{
      name: to_string(name),
      kind: symbol_kind(symbol["kind"]),
      container: string_or_nil(symbol["containerName"]),
      range: range(location["range"])
    })
  end

  defp workspace_symbol(_symbol, _root), do: []

  defp call_hierarchy_item(%{"name" => name, "uri" => uri} = item, root) do
    place(uri, root, %{
      name: to_string(name),
      kind: symbol_kind(item["kind"]),
      detail: string_or_nil(item["detail"]),
      range: range(item["range"]),
      selection_range: range(item["selectionRange"] || item["range"])
    })
  end

  defp call_hierarchy_item(_item, _root), do: []

  ## Shared

  defp place(uri, root, fields) do
    case Server.path_from_uri(uri) do
      {:ok, path} ->
        {relative_path, external?} = relative(path, root)
        [fields |> Map.put(:path, relative_path) |> Map.put(:external, external?)]

      :error ->
        []
    end
  end

  defp range(%{"start" => start_position, "end" => end_position}),
    do: %{start: position(start_position), end: position(end_position)}

  defp range(_other), do: nil

  defp position(%{"line" => line, "character" => character})
       when is_integer(line) and is_integer(character),
       do: %{line: max(line, 0), character: max(character, 0)}

  defp position(_other), do: %{line: 0, character: 0}

  defp hover_text(%{"value" => value}) when is_binary(value), do: String.trim(value)
  defp hover_text(value) when is_binary(value), do: String.trim(value)

  defp hover_text(values) when is_list(values),
    do: values |> Enum.map_join("\n\n", &hover_text/1) |> String.trim()

  defp hover_text(%{"language" => _language, "value" => value}) when is_binary(value),
    do: String.trim(value)

  defp hover_text(_other), do: ""

  defp string_or_nil(value) when is_binary(value), do: value
  defp string_or_nil(_other), do: nil

  defp bound(items, max) do
    kept = Enum.take(items, max)
    %{items: kept, truncated: length(items) - length(kept)}
  end
end
