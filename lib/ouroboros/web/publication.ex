defmodule Ouroboros.Web.Publication do
  @moduledoc """
  Writes `web.json` once the endpoint is bound, and removes it when it stops.

  This is `Ouroboros.Gateway.Listener`'s publication half, split into its own child
  because the endpoint is Phoenix's to supervise and the bound port is only knowable
  after it starts. Under the `:rest_for_one` strategy of `Ouroboros.Web` that ordering is
  also the correctness argument: an endpoint that restarts on a different port restarts
  this child too, so the file can never name a port nothing is listening on.

  The shape is `gateway.json`'s, deliberately — a client that already knows how to read
  one publication should not have to learn a second format — and so is the write: an
  exclusive temporary inode, chmodded `0600` *before* any bytes are written, synced, and
  renamed into place. The mode matters here for the same reason it does there: this file
  says where the credential lives, and the directory it sits in is the operator's.

  It never contains the token. It names the token *file* when there is one, so a browser
  that did not spawn this daemon can be pointed at the credential it must present instead
  of guessing a path by convention.

  A failure to publish stops this process, and therefore the boot. An endpoint nobody can
  find is not a degraded operator surface, it is an absent one.

  Removal is best effort and conditional on the inode still being the one this process
  wrote: a second daemon that republished over it owns the file now, and deleting another
  daemon's publication on the way out would be worse than leaving a stale one. A killed
  node removes nothing at all, which is why the file carries the OS pid — a stale
  publication is detectable rather than misleading.
  """

  use GenServer

  require Logger

  alias Ouroboros.DataDir
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Endpoint

  # The shape of this file, not a wire protocol: there is no line protocol here to
  # version. It moves when a reader of `web.json` would have to be changed.
  @protocol 1

  @doc "Starts the publisher. Options: `:config`, `:endpoint`, `:name`."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "The path this process published to."
  @spec path(GenServer.server()) :: Path.t()
  def path(server \\ __MODULE__), do: GenServer.call(server, :path)

  @doc """
  The document `web.json` holds for one bound endpoint.

  Public so the publication's shape is testable without a filesystem, and so the one
  place that decides what a browser-facing publication may contain is a function rather
  than a literal buried in a write.
  """
  @spec document(Config.t(), :inet.port_number(), pos_integer()) :: map()
  def document(%Config{} = config, port, os_pid) do
    published = %{
      "port" => port,
      "protocol" => @protocol,
      "node" => Atom.to_string(node()),
      "pid" => os_pid,
      "scope" => Atom.to_string(config.scope)
    }

    # The path to the credential, never the credential. The key is present exactly when
    # there is a file to name — a surface whose token came from the environment has none,
    # and inventing one would send a browser looking for something that does not exist.
    case config.token_file do
      path when is_binary(path) -> Map.put(published, "token_file", path)
      nil -> published
    end
  end

  @impl true
  def init(opts) do
    config = Keyword.fetch!(opts, :config)
    endpoint = Keyword.get(opts, :endpoint, Endpoint)
    Process.flag(:trap_exit, true)

    case endpoint.bound_address() do
      {:ok, {address, port}} ->
        {path, stat} = publish!(config, port)
        announce(config, address, port, path)
        {:ok, %{config: config, path: path, stat: stat, port: port}}

      :error ->
        {:stop, {:web_endpoint_not_bound, endpoint}}
    end
  end

  @impl true
  def handle_call(:path, _from, state), do: {:reply, state.path, state}

  @impl true
  def terminate(_reason, state) do
    _ = remove_if_owner(state.path, state.stat)
    :ok
  end

  defp announce(config, address, port, path) do
    Logger.info(
      "web listening on http://#{Config.bind_to_string(address)}:#{port} " <>
        "at #{config.scope} scope; published to #{path}"
    )

    unless Config.loopback?(config.bind) do
      Logger.warning(
        "web is bound to #{Config.bind_to_string(config.bind)}, which is not loopback: " <>
          "there is no TLS here, so the session cookie and every page after it cross the " <>
          "network in cleartext (OUROBOROS_WEB_ALLOW_REMOTE=1 accepted this)"
      )
    end
  end

  defp publish!(config, port) do
    DataDir.ensure_private!(config.data_dir)

    path = Endpoint.publication_path(config.data_dir)
    os_pid = os_pid()

    tmp =
      path <>
        ".tmp-#{os_pid}-#{System.unique_integer([:positive, :monotonic])}-" <>
        Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

    contents = JSON.encode_to_iodata!(document(config, port, os_pid))

    stat =
      try do
        # The exclusive empty inode makes a preplanted symlink a refusal. Its mode is
        # private before any discovery bytes are written, and the descriptor is synced
        # before the rename that publishes them.
        File.write!(tmp, "", [:exclusive, :sync])
        File.chmod!(tmp, 0o600)
        before = File.lstat!(tmp, time: :posix)

        File.open!(tmp, [:write, :binary], fn io ->
          IO.binwrite(io, contents)
          :ok = :file.sync(io)
        end)

        after_write = File.lstat!(tmp, time: :posix)

        unless same_file?(before, after_write) do
          raise "web publication temporary inode changed while it was written"
        end

        File.rename!(tmp, path)
        published = File.lstat!(path, time: :posix)

        unless same_file?(after_write, published) do
          raise "web publication inode changed while it was published"
        end

        published
      rescue
        error ->
          _ = File.rm(tmp)
          reraise error, __STACKTRACE__
      end

    {path, stat}
  end

  defp remove_if_owner(path, expected) do
    case File.lstat(path, time: :posix) do
      {:ok, current} -> if same_file?(current, expected), do: File.rm(path), else: :ok
      {:error, _reason} -> :ok
    end
  end

  defp same_file?(left, right) do
    left.uid == right.uid and left.major_device == right.major_device and
      left.inode == right.inode
  end

  defp os_pid do
    case Integer.parse(System.pid()) do
      {pid, ""} -> pid
      _other -> :os.getpid() |> List.to_string() |> String.to_integer()
    end
  end
end
