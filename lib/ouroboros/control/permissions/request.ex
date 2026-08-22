defmodule Ouroboros.Control.Permissions.Request do
  @moduledoc """
  The normalised form of one `Ouroboros.Control.Permissions.evaluate/1` argument.

  Normalisation happens once, before any rule is consulted, so every rule sees the same
  canonical paths and the same command line. It is total: a field the caller left out, or
  left malformed, becomes the *narrowest* thing it could have been rather than an error,
  because an evaluation that refuses to happen is an evaluation that cannot deny.

  `write_paths` is the union of the declared paths (when the mode writes) and every
  redirect target found in the command line. That union is what the protected-path list
  and every `Write(…)`/`Edit(…)` rule are checked against, which is how
  `echo pwned > .git/config` is refused while `echo` itself stays allowed.
  """

  alias Ouroboros.Control.Permissions.{Paths, Shell}

  @modes [:read, :write, :execute, :network]
  @max_paths 64
  @max_domains 32

  @enforce_keys [
    :principal,
    :tool,
    :command,
    :paths,
    :write_paths,
    :mode,
    :domains,
    :context,
    :root
  ]
  defstruct @enforce_keys

  @type principal :: %{session_id: String.t() | nil, provider: atom() | nil, node: node()}
  @type t :: %__MODULE__{
          principal: principal(),
          tool: String.t(),
          command: String.t() | nil,
          paths: [String.t()],
          write_paths: [String.t()],
          mode: :read | :write | :execute | :network,
          domains: [String.t()],
          context: map(),
          root: String.t() | nil
        }

  @doc "Every mode a request may declare."
  @spec modes() :: [atom()]
  def modes, do: @modes

  @doc "Normalises a caller's map. Never raises; never returns an error."
  @spec new(map() | keyword()) :: t()
  def new(attrs) when is_list(attrs), do: attrs |> Map.new() |> new()

  def new(attrs) when is_map(attrs) do
    context = map_or_empty(Map.get(attrs, :context))
    root = root(context)
    command = command(Map.get(attrs, :command))
    mode = mode(Map.get(attrs, :mode), command)
    paths = paths(Map.get(attrs, :paths), root)

    %__MODULE__{
      principal: principal(Map.get(attrs, :principal)),
      tool: tool(Map.get(attrs, :tool)),
      command: command,
      paths: paths,
      write_paths: write_paths(paths, mode, command, root),
      mode: mode,
      domains: domains(Map.get(attrs, :domains)),
      context: context,
      root: root
    }
  end

  def new(_attrs), do: new(%{})

  defp principal(principal) when is_map(principal) do
    %{
      session_id:
        string_or_nil(Map.get(principal, :session_id) || Map.get(principal, "session_id")),
      provider: atom_or_nil(Map.get(principal, :provider) || Map.get(principal, "provider")),
      node: node_or_local(Map.get(principal, :node) || Map.get(principal, "node"))
    }
  end

  defp principal(_principal), do: %{session_id: nil, provider: nil, node: node()}

  # An unnamed tool is not "any tool"; it is one nobody can write an allow rule for.
  defp tool(tool) when is_binary(tool) and tool != "", do: tool
  defp tool(tool) when is_atom(tool) and not is_nil(tool), do: Atom.to_string(tool)
  defp tool(_tool), do: "unknown"

  defp command(command) when is_binary(command) do
    case String.trim(command) do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp command(command) when is_list(command) do
    command |> Enum.filter(&is_binary/1) |> Enum.join(" ") |> command()
  end

  defp command(_command), do: nil

  # A command line with no stated mode executes. Anything else unstated writes, which is
  # the mode with the most rules pointed at it.
  defp mode(mode, _command) when mode in @modes, do: mode
  defp mode(_mode, command) when is_binary(command), do: :execute
  defp mode(_mode, _command), do: :write

  defp paths(paths, root) when is_list(paths) do
    paths
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.take(@max_paths)
    |> Enum.flat_map(fn path ->
      case Paths.canonicalize(path, root) do
        {:ok, canonical} -> [canonical]
        {:error, _reason} -> []
      end
    end)
    |> Enum.uniq()
  end

  defp paths(_paths, _root), do: []

  defp write_paths(paths, mode, command, root) do
    declared = if mode in [:write, :execute], do: paths, else: []

    redirects =
      case command do
        nil -> []
        text -> text |> Shell.redirect_targets() |> paths(root)
      end

    Enum.uniq(declared ++ redirects)
  end

  defp domains(domains) when is_list(domains) do
    domains
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.map(&(&1 |> String.downcase() |> String.trim_leading(".")))
    |> Enum.take(@max_domains)
    |> Enum.uniq()
  end

  defp domains(_domains), do: []

  defp root(context) do
    case Map.get(context, :workspace) || Map.get(context, "workspace") || Map.get(context, :cwd) ||
           Map.get(context, "cwd") do
      root when is_binary(root) and root != "" ->
        case Paths.canonicalize(root, nil) do
          {:ok, canonical} -> canonical
          {:error, _reason} -> nil
        end

      _other ->
        nil
    end
  end

  defp map_or_empty(value) when is_map(value), do: value
  defp map_or_empty(_value), do: %{}

  defp string_or_nil(value) when is_binary(value) and value != "", do: value
  defp string_or_nil(_value), do: nil

  defp atom_or_nil(value) when is_atom(value) and not is_nil(value), do: value
  defp atom_or_nil(_value), do: nil

  defp node_or_local(value) when is_atom(value) and not is_nil(value), do: value
  defp node_or_local(_value), do: node()
end
