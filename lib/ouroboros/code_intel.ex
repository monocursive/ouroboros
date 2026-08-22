defmodule Ouroboros.CodeIntel do
  @moduledoc """
  Code intelligence for the workspaces this node owns: language servers as a runtime
  service, addressed by file path.

  Everything here answers an ordinary tuple. There is no call in this module that raises,
  none that blocks without a deadline, and none whose failure can fail a write. A
  language server is a convenience the runtime offers; when it is missing, starting,
  broken, or simply slow, the answer says so and the caller carries on. That is the whole
  posture, and it is deliberate: OpenCode turned its LSP integration off by default over
  memory and staleness, and Anthropic tells users to disable plugins under pressure
  (R4 §1). A subsystem with those failure modes earns its place only by being impossible
  to be hurt by.

  Nothing is installed. A language whose server is absent from the project's binaries and
  from `PATH` answers `{:error, {:server_unavailable, server_id, hint}}`, and the hint is
  the end of this runtime's involvement.

  `status/0` is the operator surface, shaped so a gateway method can hand it straight to
  a client.
  """

  alias Ouroboros.CodeIntel.Config
  alias Ouroboros.CodeIntel.Handle
  alias Ouroboros.CodeIntel.Lsp.Server
  alias Ouroboros.CodeIntel.LspPool
  alias Ouroboros.CodeIntel.Registry
  alias Ouroboros.CodeIntel.Results

  @pool Ouroboros.CodeIntel.LspPool

  @operations [
    :definition,
    :references,
    :hover,
    :document_symbols,
    :workspace_symbols,
    :implementation,
    :prepare_call_hierarchy,
    :incoming_calls,
    :outgoing_calls
  ]

  @doc """
  Claims the language server for `path` on behalf of the calling process.

  Spawns it if this is the first claim on its `{root, server}` key. The claim is released
  by `release/1` or by the owner dying, whichever happens first.
  """
  @spec acquire(String.t(), keyword()) :: {:ok, Handle.t()} | {:error, term()}
  def acquire(path, opts \\ []) when is_binary(path) do
    with :ok <- enabled(),
         {:ok, spec} <- Registry.resolve(path, opts) do
      LspPool.acquire(pool(opts), spec, opts)
    end
  end

  @spec release(Handle.t(), keyword()) :: :ok
  def release(%Handle{} = handle, opts \\ []), do: LspPool.release(pool(opts), handle)

  @doc """
  Asks one of the nine navigation questions at a position in a file.

  The operation set is the de-facto standard OpenCode, Claude Code, Kilo and Kiro all
  converged on, and SWE-Master's ablation is the reason it is worth having at all: on
  SWE-bench Verified it moved resolve rates by one to two points and cut turn counts by
  four to six percent — a modest, consistent win, and mostly a turn-count one.

      Ouroboros.CodeIntel.request(:references, %{path: "lib/a.ex", line: 12, character: 4})

  `:document_symbols` and `:workspace_symbols` need no position; the latter takes
  `query:` and uses `path` only to choose which server to ask. `:incoming_calls` and
  `:outgoing_calls` run `prepareCallHierarchy` first and follow the item it returns, so a
  caller asks "who calls the thing at this position" rather than assembling a protocol
  item by hand.

  Answers are `{:ok, %{items: [...], truncated: n}}` with paths relative to the project
  root, positions left 0-based as the protocol reports them, and `external: true` on any
  result outside the root — a definition in a dependency is a different kind of answer
  from one in your own tree. Everything is bounded: `max_results` (default 200) caps the
  list, `request_timeout_ms` (default 10 s) caps the wait, and a server that is starting,
  broken, absent, or simply slow is an error tuple, never an exception.
  """
  @spec request(atom(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def request(operation, location, opts \\ [])

  def request(operation, %{path: path} = location, opts) when is_binary(path) do
    with :ok <- enabled(),
         :ok <- known_operation(operation),
         {:ok, spec} <- Registry.resolve(path, opts),
         {:ok, server} <- checkout(spec, opts),
         :ok <- open_document(spec, opts) do
      dispatch(operation, server, spec, location, opts)
    end
  end

  def request(_operation, location, _opts), do: {:error, {:invalid_location, location}}

  @doc "The operations `request/3` understands."
  @spec operations() :: [atom()]
  def operations, do: @operations

  @doc """
  Tells the language server that a file was opened, changed on disk, or closed.

  Only a path and an action: the content is read from disk by the pool, in the same
  message that assigns the new version. Nothing accepts document text from a caller, so
  no file content crosses a process or node boundary to get here, and two writers cannot
  interleave into a state where the server holds older text under a newer version.

  `:ensure_open` is the fourth action and the one to reach for when *asking* about a file
  rather than reporting a change to it. It opens a document the server has never seen and
  does nothing at all to one it already holds, where `:open` re-reads and assigns a new
  version. That difference decides whether a question can be answered: every version bump
  invalidates the diagnostics cache, so a caller that asked "what is wrong with this file"
  by re-opening it would wait out the freshness gate for a push that a server with nothing
  new to say never sends.

  Answers `{:ok, version}` — the version every later `diagnostics/2` is gated against.
  """
  @spec touch(String.t(), :open | :ensure_open | :changed | :closed, keyword()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def touch(path, action, opts \\ [])
      when is_binary(path) and action in [:open, :ensure_open, :changed, :closed] do
    with :ok <- enabled(),
         {:ok, spec} <- Registry.resolve(path, opts) do
      apply_touch(pool(opts), spec, action)
    end
  end

  defp apply_touch(pool, spec, :ensure_open), do: LspPool.ensure_open(pool, spec)
  defp apply_touch(pool, spec, action), do: LspPool.touch(pool, spec, action)

  @doc """
  Announces an edit and answers with the picture that preceded it.

  This is `baseline/2` and `touch/3`, in that order, without a window between them. An
  external tool — Claude Code's `PostToolUse` hook, an MCP client, anything reached through
  `code_intel.touch` — has already written the file by the time it calls, so the only
  chance to learn what the server said about the *old* text is the instant before the new
  version is assigned. Doing it in two calls would leave a gap in which a push could land
  and turn a pre-existing error into a new one.

  The baseline is returned as signatures rather than items: a caller diffing two lists
  needs identity, not messages, and a file with hundreds of findings should not cost its
  own diagnostics twice. `fresh?` says whether the snapshot described the document as it
  stood; `version` is `nil` when the server had never published for it, which is the
  honest way to say "there is no baseline" rather than "the baseline was empty".

  Answers `{:ok, %{version: v, baseline: %{...}}}`. A failure to read the baseline is not
  a failure to touch: the touch is what a language server needs to stay correct, so it
  happens either way and the baseline is reported absent.
  """
  @spec touch_with_baseline(String.t(), :open | :ensure_open | :changed | :closed, keyword()) ::
          {:ok, map()} | {:error, term()}
  def touch_with_baseline(path, action, opts \\ [])
      when is_binary(path) and action in [:open, :ensure_open, :changed, :closed] do
    with :ok <- enabled(),
         {:ok, spec} <- Registry.resolve(path, opts) do
      pool = pool(opts)
      baseline = LspPool.baseline(pool, spec)

      with {:ok, version} <- apply_touch(pool, spec, action) do
        {:ok, %{version: version, baseline: baseline_projection(baseline)}}
      end
    end
  end

  defp baseline_projection({:ok, baseline}) do
    %{
      fresh?: baseline.fresh?,
      version: baseline.version,
      document_version: baseline.document_version,
      truncated: baseline.truncated,
      counts: Ouroboros.CodeIntel.Diagnostics.counts(baseline.items),
      signatures: Enum.map(baseline.items, &Ouroboros.CodeIntel.Diagnostics.signature/1)
    }
  end

  defp baseline_projection({:error, reason}) do
    %{fresh?: false, version: nil, signatures: [], truncated: 0, error: reason}
  end

  @doc """
  Diagnostics for a file, but only the ones that describe its current content.

  `{:ok, %{version: v, items: items, counts: counts}}` when the cache matches the
  document's current version; `{:pending, version}` when it does not, after waiting up to
  `wait_ms` (default 5 s) for the push that would close the gap. `{:pending, _}` is an
  ordinary answer meaning "no LSP data yet" — it is what a caller gets when a server is
  still indexing, and it must never be treated as a failure of whatever produced the
  edit.

  The document has to have been opened with `touch/3` first; this call does not open one
  behind the caller's back, because opening a document is a decision about what a
  language server spends memory on.
  """
  @spec diagnostics(String.t(), keyword()) ::
          {:ok, map()} | {:pending, non_neg_integer()} | {:error, term()}
  def diagnostics(path, opts \\ []) when is_binary(path) do
    with :ok <- enabled(),
         {:ok, spec} <- Registry.resolve(path, opts) do
      LspPool.diagnostics(pool(opts), spec, opts)
    end
  end

  @doc """
  The current diagnostics snapshot for a file, without waiting.

  This is the pre-edit baseline: capture it, write, `touch/3`, then `diagnostics/2`, and
  report only what the second call has that this one did not. `fresh?` says whether the
  snapshot describes the document as it stands; a caller diffing against a stale or empty
  baseline over-reports, and should say "no LSP data" instead.
  """
  @spec baseline(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def baseline(path, opts \\ []) when is_binary(path) do
    with :ok <- enabled(),
         {:ok, spec} <- Registry.resolve(path, opts) do
      LspPool.baseline(pool(opts), spec)
    end
  end

  @doc """
  Subscribes a process to `{:code_intel, :diagnostics_changed, payload}`.

  The payload is `%{node, root, server_id, path, version, source, counts}` — counts, not
  items, so a file with thousands of findings costs every subscriber a small map. A
  subscriber that wants the items calls `diagnostics/2` for the path it was told about.
  """
  @spec subscribe(pid(), keyword()) :: :ok | {:error, term()}
  def subscribe(subscriber \\ self(), opts \\ []) when is_pid(subscriber) do
    with :ok <- enabled(), do: LspPool.subscribe(pool(opts), subscriber)
  end

  @spec unsubscribe(pid(), keyword()) :: :ok | {:error, term()}
  def unsubscribe(subscriber \\ self(), opts \\ []) when is_pid(subscriber) do
    with :ok <- enabled(), do: LspPool.unsubscribe(pool(opts), subscriber)
  end

  @doc """
  Describes every language server this node owns.

  Shaped for a client: no pids as terms, no atoms a wire format cannot carry back, and
  each entry carries the `node()` it belongs to, because a fleet has one pool per host and
  two hosts serving the same repository are not serving the same server.
  """
  @spec status(keyword()) :: map()
  def status(opts \\ []) do
    if Config.enabled?() do
      Map.put(LspPool.status(pool(opts)), :enabled, true)
    else
      %{enabled: false, node: node(), budget_bytes: 0, used_bytes: 0, servers: []}
    end
  end

  @doc """
  Resolves a path to the language server that would serve it, without starting anything.

  Useful on its own — this is the call that answers "is there code intelligence for this
  file, and if not, why not".
  """
  @spec resolve(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  defdelegate resolve(path, opts \\ []), to: Registry

  ## Navigation

  defp dispatch(:definition, server, spec, location, opts) do
    with {:ok, result} <- ask(server, "textDocument/definition", position(spec, location), opts),
         do: {:ok, Results.locations(result, spec.root, max_results(opts))}
  end

  defp dispatch(:implementation, server, spec, location, opts) do
    with {:ok, result} <-
           ask(server, "textDocument/implementation", position(spec, location), opts),
         do: {:ok, Results.locations(result, spec.root, max_results(opts))}
  end

  defp dispatch(:references, server, spec, location, opts) do
    params =
      Map.put(position(spec, location), "context", %{
        "includeDeclaration" => Keyword.get(opts, :include_declaration, true)
      })

    with {:ok, result} <- ask(server, "textDocument/references", params, opts),
         do: {:ok, Results.locations(result, spec.root, max_results(opts))}
  end

  defp dispatch(:hover, server, spec, location, opts) do
    with {:ok, result} <- ask(server, "textDocument/hover", position(spec, location), opts) do
      case Results.hover(result || %{}, spec.root) do
        nil -> {:ok, %{items: [], truncated: 0}}
        hover -> {:ok, %{items: [hover], truncated: 0}}
      end
    end
  end

  defp dispatch(:document_symbols, server, spec, _location, opts) do
    params = %{"textDocument" => text_document(spec)}

    with {:ok, result} <- ask(server, "textDocument/documentSymbol", params, opts),
         do: {:ok, Results.document_symbols(result, spec.root, spec.path, max_results(opts))}
  end

  defp dispatch(:workspace_symbols, server, spec, location, opts) do
    query = Keyword.get(opts, :query) || Map.get(location, :query) || ""

    with {:ok, result} <- ask(server, "workspace/symbol", %{"query" => query}, opts),
         do: {:ok, Results.workspace_symbols(result, spec.root, max_results(opts))}
  end

  defp dispatch(:prepare_call_hierarchy, server, spec, location, opts) do
    with {:ok, result} <-
           ask(server, "textDocument/prepareCallHierarchy", position(spec, location), opts),
         do: {:ok, Results.call_hierarchy_items(result, spec.root, max_results(opts))}
  end

  defp dispatch(:incoming_calls, server, spec, location, opts),
    do: hierarchy_calls(server, spec, location, opts, "callHierarchy/incomingCalls", "from")

  defp dispatch(:outgoing_calls, server, spec, location, opts),
    do: hierarchy_calls(server, spec, location, opts, "callHierarchy/outgoingCalls", "to")

  # `incomingCalls` needs a `CallHierarchyItem`, which only `prepareCallHierarchy`
  # produces. Making the caller carry a raw protocol item between two calls would put LSP
  # back into an API whose whole point is not to have it, so the preparation happens here
  # and the first item is followed. Both requests are separately bounded.
  defp hierarchy_calls(server, spec, location, opts, method, key) do
    with {:ok, prepared} <-
           ask(server, "textDocument/prepareCallHierarchy", position(spec, location), opts) do
      case prepared |> List.wrap() |> List.first() do
        nil ->
          {:ok, %{items: [], truncated: 0}}

        item ->
          with {:ok, result} <- ask(server, method, %{"item" => item}, opts),
               do: {:ok, Results.calls(result, spec.root, key, max_results(opts))}
      end
    end
  end

  defp ask(server, method, params, opts) do
    timeout = Keyword.get(opts, :request_timeout_ms, Config.get(:request_timeout_ms))
    Server.request(server, method, params, timeout)
  end

  defp checkout(spec, opts) do
    LspPool.checkout(pool(opts), spec,
      wait_ready_ms: Keyword.get(opts, :wait_ready_ms, Config.get(:initialize_timeout_ms))
    )
  end

  # A navigation request against a document the server has never seen is answered wrongly
  # or not at all, so the document is opened first unless the caller says otherwise. An
  # already-open document is left at its version.
  defp open_document(spec, opts) do
    if Keyword.get(opts, :open, true) do
      with {:ok, _version} <- LspPool.ensure_open(pool(opts), spec), do: :ok
    else
      :ok
    end
  end

  defp position(spec, location) do
    spec
    |> text_document()
    |> then(&%{"textDocument" => &1})
    |> Map.put("position", %{
      "line" => max(Map.get(location, :line, 0), 0),
      "character" => max(Map.get(location, :character, 0), 0)
    })
  end

  defp text_document(spec), do: %{"uri" => Server.uri(spec.path)}

  defp max_results(opts),
    do: Keyword.get(opts, :max_results, Config.get(:max_results))

  defp known_operation(operation) do
    if operation in @operations,
      do: :ok,
      else: {:error, {:unknown_operation, operation, @operations}}
  end

  defp enabled do
    if Config.enabled?(), do: :ok, else: {:error, :disabled}
  end

  # The pool is a named process and which name is node configuration: the application
  # starts one at `Ouroboros.CodeIntel.LspPool`, and a suite that wants servers it can tear
  # down on its own schedule starts its own under another name and says so. An explicit
  # `opts[:pool]` still wins, because a caller holding a particular pool means that one.
  defp pool(opts) do
    case Keyword.get(opts, :pool) do
      name when is_atom(name) and not is_nil(name) -> name
      _unset -> configured_pool()
    end
  end

  defp configured_pool do
    case Application.get_env(:ouroboros, :code_intel, []) do
      config when is_list(config) ->
        case Keyword.get(config, :pool) do
          name when is_atom(name) and not is_nil(name) -> name
          _unset -> @pool
        end

      _other ->
        @pool
    end
  end
end
