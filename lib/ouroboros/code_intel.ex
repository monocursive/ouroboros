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
  alias Ouroboros.CodeIntel.LspPool
  alias Ouroboros.CodeIntel.Registry

  @pool Ouroboros.CodeIntel.LspPool

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
  Tells the language server that a file was opened, changed on disk, or closed.

  Only a path and an action: the content is read from disk by the pool, in the same
  message that assigns the new version. Nothing accepts document text from a caller, so
  no file content crosses a process or node boundary to get here, and two writers cannot
  interleave into a state where the server holds older text under a newer version.

  Answers `{:ok, version}` — the version every later `diagnostics/2` is gated against.
  """
  @spec touch(String.t(), :open | :changed | :closed, keyword()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def touch(path, action, opts \\ [])
      when is_binary(path) and action in [:open, :changed, :closed] do
    with :ok <- enabled(),
         {:ok, spec} <- Registry.resolve(path, opts) do
      LspPool.touch(pool(opts), spec, action)
    end
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

  defp enabled do
    if Config.enabled?(), do: :ok, else: {:error, :disabled}
  end

  defp pool(opts), do: Keyword.get(opts, :pool, @pool)
end
