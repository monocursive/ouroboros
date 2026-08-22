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
