defmodule Ouroboros.Provider.Native.Mcp.Servers do
  @moduledoc """
  Where MCP servers are declared, and what this runtime refuses to run.

  Three sources, merged by name, in this precedence:

      config :ouroboros, :mcp_servers      node scope   — operator configuration, wins
      ~/.config/ouroboros/mcp.json         user scope
      <workspace>/.ouroboros/mcp.json      workspace scope — requires workspace trust

  The file shape is Claude Code's, unchanged, because a `mcp.json` somebody already
  wrote works here as it is and inventing a fourth shape would make this feature worth
  less than not having it:

      {"mcpServers": {"fake": {"command": "./bin/fake", "args": ["--stdio"],
                               "env": {"TOKEN": "…"}}}}

  ## Trust, and why the workspace file needs it

  A repository that ships its own `mcp.json` is a repository that runs commands on every
  machine that clones it — exactly the hazard `Ouroboros.Provider.Native.Hooks`
  documents for `ouroboros.toml`. So the workspace file is read through the same gate,
  `Hooks.trusted?/2`: `config :ouroboros, :trusted_workspaces` naming the canonical
  root, or a `.ouroboros/trusted` marker an operator wrote. Untrusted is not silent —
  `load/2` reports `trusted?: false` and how many servers it declined — and it is not
  self-healing either: `.ouroboros` is a protected segment in the permission engine's
  rule language, so the agent cannot write its own trust marker.

  ## What is refused, by name

  Nothing here is ignored. Every entry that cannot run produces a typed reason that
  reaches `mcp.list` and the docs:

    * `:unsupported_transport` — the entry names `url` (or `type` of `http`/`sse`).
      This slice implements **stdio only**. Streamable HTTP and OAuth are out of scope
      and the loader says so rather than dropping the entry on the floor.
    * `:invalid_name` — a server name that is not `[A-Za-z0-9_-]{1,64}`, or one
      containing `__`. The model-facing name is `mcp__<server>__<tool>`, split on the
      first `__`; a server name with `__` in it would make that split ambiguous.
    * `:missing_command`, `:invalid_command`, `:invalid_args`, `:invalid_env`,
      `:invalid_cwd`, `:invalid_entry` — the entry is not a runnable definition.
    * `:too_many_servers` — past `Mcp.Config.get(:max_servers)`.

  ## Environment values

  A server's `env` is a secret carrier by construction: the whole reason an entry has
  one is an API token. `%Definition{}` derives an `Inspect` that omits it, `describe/1`
  reports only how many variables there are, and nothing in this module or in
  `Ouroboros.Provider.Native.Mcp` ever puts a value into an event, a log line, or a
  status projection.
  """

  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Provider.Native.Mcp.Config

  @user_file "mcp.json"
  @workspace_file Path.join(".ouroboros", "mcp.json")

  @name_pattern ~r/\A[A-Za-z0-9_-]{1,64}\z/

  # A definition is what the pool needs to spawn one child, and nothing else. `env` is
  # excluded from `Inspect` so that a crash report, a `dbg`, or a `Logger` call that
  # happens to hold one of these cannot print a token.
  @derive {Inspect, except: [:env]}
  defstruct [
    :name,
    :command,
    :scope,
    :source,
    args: [],
    env: %{},
    cwd: nil,
    enabled?: true
  ]

  @type scope :: :node | :user | :workspace

  @type t :: %__MODULE__{
          name: String.t(),
          command: String.t(),
          scope: scope(),
          source: String.t() | nil,
          args: [String.t()],
          env: %{String.t() => String.t()},
          cwd: String.t() | nil,
          enabled?: boolean()
        }

  @type refusal :: %{name: String.t() | nil, scope: scope(), reason: atom(), detail: String.t()}

  @typedoc "Everything one workspace's configuration resolved to."
  @type loaded :: %{
          servers: [t()],
          refusals: [refusal()],
          trusted?: boolean(),
          declined: non_neg_integer(),
          errors: [String.t()]
        }

  @doc """
  Resolves every server declared for one workspace.

  `workspace_root` may be `nil`: a caller with no workspace still gets node- and
  user-scope servers, which is the right answer for a session that has not been given a
  root rather than an error.

  `opts` accepts `:user_path` and `:trusted_workspaces`, both for tests and both named
  the way `Ouroboros.Provider.Native.Hooks` names them, so a test never reads — or
  runs — the machine's real configuration.
  """
  @spec load(String.t() | nil, keyword()) :: loaded()
  def load(workspace_root, opts \\ []) do
    trusted? = workspace_root != nil and Hooks.trusted?(workspace_root, opts)

    {workspace, workspace_refusals, workspace_errors, declined} =
      load_workspace(workspace_root, trusted?)

    {user, user_refusals, user_errors} = load_user(opts)
    {node, node_refusals} = load_node()

    # Precedence is a fold from weakest to strongest, so a name declared twice keeps the
    # stronger scope's definition and the weaker one simply never existed. An operator's
    # node configuration is the last word on this machine by construction.
    merged =
      [workspace, user, node]
      |> Enum.reduce(%{}, fn servers, acc ->
        Enum.reduce(servers, acc, &Map.put(&2, &1.name, &1))
      end)
      |> Map.values()
      |> Enum.sort_by(& &1.name)

    {servers, overflow} = Enum.split(merged, Config.get(:max_servers))

    %{
      servers: servers,
      refusals:
        node_refusals ++
          user_refusals ++
          workspace_refusals ++ Enum.map(overflow, &overflow_refusal/1),
      trusted?: trusted?,
      declined: declined,
      errors: workspace_errors ++ user_errors
    }
  end

  @doc "One server's definition for a workspace, or why there is none."
  @spec fetch(String.t(), String.t() | nil, keyword()) :: {:ok, t()} | {:error, term()}
  def fetch(name, workspace_root, opts \\ []) when is_binary(name) do
    loaded = load(workspace_root, opts)

    case Enum.find(loaded.servers, &(&1.name == name)) do
      %__MODULE__{} = definition ->
        {:ok, definition}

      nil ->
        case Enum.find(loaded.refusals, &(&1.name == name)) do
          %{reason: reason} -> {:error, reason}
          nil -> {:error, :unknown_server}
        end
    end
  end

  @doc """
  A definition as `mcp.list` and the docs may show it.

  Environment values are never in here. The count is, because "this server has three
  variables set" is an operator's question and the values are nobody's.
  """
  @spec describe(t()) :: map()
  def describe(%__MODULE__{} = definition) do
    %{
      name: definition.name,
      command: definition.command,
      args: definition.args,
      scope: definition.scope,
      source: definition.source,
      cwd: definition.cwd,
      transport: :stdio,
      env_count: map_size(definition.env)
    }
  end

  @doc "Where the user-scope file lives on this node, or `nil` when it is disabled."
  @spec user_path(keyword()) :: String.t() | nil
  def user_path(opts \\ []) do
    configured =
      Keyword.get(opts, :user_path) ||
        Application.get_env(:ouroboros, :mcp_user_path) ||
        :default

    case configured do
      :default ->
        case System.user_home() do
          home when is_binary(home) and home != "" ->
            Path.join([home, ".config", "ouroboros", @user_file])

          _unknown ->
            nil
        end

      path when is_binary(path) ->
        path

      _disabled ->
        nil
    end
  end

  @doc "Where a workspace declares its own servers."
  @spec workspace_path(String.t()) :: String.t()
  def workspace_path(root), do: Path.join(root, @workspace_file)

  # ------------------------------------------------------------------ sources

  defp load_node do
    :ouroboros
    |> Application.get_env(:mcp_servers, %{})
    |> entries()
    |> parse_all(:node, nil)
    |> then(fn {servers, refusals} -> {servers, refusals} end)
  end

  defp load_user(opts) do
    case user_path(opts) do
      nil ->
        {[], [], []}

      path ->
        case read(path) do
          {:ok, document} ->
            {servers, refusals} = document |> entries() |> parse_all(:user, path)
            {servers, refusals, []}

          :absent ->
            {[], [], []}

          {:error, message} ->
            {[], [], ["#{path}: #{message}"]}
        end
    end
  end

  defp load_workspace(nil, _trusted?), do: {[], [], [], 0}

  defp load_workspace(root, trusted?) do
    path = workspace_path(root)

    case read(path) do
      {:ok, document} ->
        {servers, refusals} = document |> entries() |> parse_all(:workspace, path)

        if trusted? do
          {servers, refusals, [], 0}
        else
          # Not an error and not silence: the count is what a session says out loud when
          # a repository's servers did nothing.
          {[], refusals, [], length(servers)}
        end

      :absent ->
        {[], [], [], 0}

      {:error, message} ->
        {[], [], ["#{path}: #{message}"], 0}
    end
  end

  # `{"mcpServers": {…}}` is the documented shape. A bare map of names is accepted too,
  # because a hand-written file that skipped the wrapper is a typo rather than a
  # different format, and refusing it would teach nothing.
  defp entries(%{"mcpServers" => %{} = servers}), do: servers
  defp entries(%{mcpServers: %{} = servers}), do: servers
  defp entries(%{} = map), do: map
  defp entries(_other), do: %{}

  defp parse_all(entries, scope, source) do
    entries
    |> Enum.sort_by(fn {name, _entry} -> to_string(name) end)
    |> Enum.reduce({[], []}, fn {name, entry}, {servers, refusals} ->
      case parse(name, entry, scope, source) do
        {:ok, definition} -> {[definition | servers], refusals}
        :disabled -> {servers, refusals}
        {:error, refusal} -> {servers, [refusal | refusals]}
      end
    end)
    |> then(fn {servers, refusals} -> {Enum.reverse(servers), Enum.reverse(refusals)} end)
  end

  defp parse(name, entry, scope, source) do
    with {:ok, name} <- server_name(name, scope),
         {:ok, entry} <- entry_map(name, entry, scope),
         :ok <- stdio_only(name, entry, scope),
         {:ok, command} <- command(name, entry, scope),
         {:ok, args} <- args(name, entry, scope),
         {:ok, env} <- env(name, entry, scope),
         {:ok, cwd} <- cwd(name, entry, scope) do
      if get(entry, "disabled") == true or get(entry, "enabled") == false do
        :disabled
      else
        {:ok,
         %__MODULE__{
           name: name,
           command: command,
           args: args,
           env: env,
           cwd: cwd,
           scope: scope,
           source: source
         }}
      end
    end
  end

  defp server_name(name, scope) do
    name = to_string(name)

    cond do
      not Regex.match?(@name_pattern, name) ->
        refuse(nil, scope, :invalid_name, "`#{truncate(name)}` is not [A-Za-z0-9_-]{1,64}")

      String.contains?(name, "__") ->
        refuse(
          nil,
          scope,
          :invalid_name,
          "`#{name}` contains `__`, which would make `mcp__<server>__<tool>` ambiguous"
        )

      true ->
        {:ok, name}
    end
  end

  # Node configuration is written with atom keys and a JSON file with string ones. They
  # are normalised to strings here, once, so every rule below is written against one
  # shape — and so an atom-keyed `url:` is refused as the wrong transport rather than as
  # a missing command.
  defp entry_map(_name, %{} = entry, _scope),
    do: {:ok, Map.new(entry, fn {key, value} -> {to_string(key), value} end)}

  defp entry_map(name, other, scope),
    do: refuse(name, scope, :invalid_entry, "expected an object, got #{type_of(other)}")

  # The one place this slice's scope is enforced. An `url` server is a real server this
  # client cannot reach, so it is refused with a reason a person can act on rather than
  # skipped as if it had never been written.
  defp stdio_only(name, entry, scope) do
    type = get(entry, "type") || get(entry, "transport")

    cond do
      is_binary(get(entry, "url")) ->
        refuse(
          name,
          scope,
          :unsupported_transport,
          "`url` names an HTTP/SSE server; this client speaks stdio only"
        )

      is_binary(type) and String.downcase(type) not in ["stdio", "local"] ->
        refuse(
          name,
          scope,
          :unsupported_transport,
          "`type: #{truncate(type)}` is not stdio; this client speaks stdio only"
        )

      true ->
        :ok
    end
  end

  defp command(name, entry, scope) do
    case get(entry, "command") do
      command when is_binary(command) and command != "" ->
        if String.contains?(command, "\0"),
          do: refuse(name, scope, :invalid_command, "`command` contains a NUL byte"),
          else: {:ok, command}

      nil ->
        refuse(name, scope, :missing_command, "no `command`")

      other ->
        refuse(name, scope, :invalid_command, "`command` must be a string, got #{type_of(other)}")
    end
  end

  defp args(name, entry, scope) do
    case get(entry, "args") do
      nil ->
        {:ok, []}

      list when is_list(list) ->
        if Enum.all?(list, &is_binary/1),
          do: {:ok, list},
          else: refuse(name, scope, :invalid_args, "every `args` entry must be a string")

      other ->
        refuse(name, scope, :invalid_args, "`args` must be an array, got #{type_of(other)}")
    end
  end

  defp env(name, entry, scope) do
    case get(entry, "env") do
      nil ->
        {:ok, %{}}

      %{} = map ->
        pairs = Enum.map(map, fn {key, value} -> {to_string(key), value} end)

        if Enum.all?(pairs, fn {_key, value} -> is_binary(value) end),
          do: {:ok, Map.new(pairs)},
          # The message names no key and no value: an error about a secret must not
          # become the place the secret is written down.
          else: refuse(name, scope, :invalid_env, "every `env` value must be a string")

      other ->
        refuse(name, scope, :invalid_env, "`env` must be an object, got #{type_of(other)}")
    end
  end

  defp cwd(name, entry, scope) do
    case get(entry, "cwd") do
      nil -> {:ok, nil}
      path when is_binary(path) and path != "" -> {:ok, Path.expand(path)}
      other -> refuse(name, scope, :invalid_cwd, "`cwd` must be a path, got #{type_of(other)}")
    end
  end

  defp overflow_refusal(%__MODULE__{} = definition) do
    %{
      name: definition.name,
      scope: definition.scope,
      reason: :too_many_servers,
      detail: "past the #{Config.get(:max_servers)}-server cap for this node"
    }
  end

  defp refuse(name, scope, reason, detail),
    do: {:error, %{name: name, scope: scope, reason: reason, detail: detail}}

  defp get(entry, key) when is_map(entry), do: Map.get(entry, key)

  defp read(path) do
    case File.read(path) do
      {:ok, contents} ->
        case JSON.decode(contents) do
          {:ok, %{} = document} -> {:ok, document}
          {:ok, other} -> {:error, "expected a JSON object, got #{type_of(other)}"}
          {:error, reason} -> {:error, "invalid JSON (#{inspect(reason)})"}
        end

      {:error, :enoent} ->
        :absent

      {:error, reason} ->
        {:error, :file.format_error(reason) |> to_string()}
    end
  end

  defp type_of(value) when is_binary(value), do: "a string"
  defp type_of(value) when is_list(value), do: "an array"
  defp type_of(value) when is_map(value), do: "an object"
  defp type_of(value) when is_number(value), do: "a number"
  defp type_of(value) when is_boolean(value), do: "a boolean"
  defp type_of(nil), do: "null"
  defp type_of(_value), do: "an unexpected value"

  defp truncate(value) when byte_size(value) <= 64, do: value
  defp truncate(value), do: binary_part(value, 0, 64) <> "…"
end
