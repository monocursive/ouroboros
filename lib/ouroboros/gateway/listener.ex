defmodule Ouroboros.Gateway.Listener do
  @moduledoc """
  Binds the port, publishes it, and hands every accepted socket to its own process.

  ## Publishing is part of binding

  `OUROBOROS_GATEWAY_PORT` defaults to `0`, so the kernel picks the port and there is no
  window in which two daemons race for a number one of them chose in advance. The bound
  port is then written to `gateway.json` in the data directory — atomically, `0600`, with
  the mode set on the temporary file *before* the rename so the token-adjacent facts in
  it are never briefly world-readable.

  The file names the token *file* when there is one, so a client that did not spawn this
  daemon can find the credential it must present instead of guessing a path by convention.
  It never contains the token itself: this file says where to look, and the 0600 file it
  points at is what has to be readable.

  A failure to publish stops this process, and therefore the boot. A listener nobody can
  find is not a degraded operator surface, it is an absent one, and it would be
  discovered at the worst possible moment.

  The file is removed on graceful termination, best effort. It is not removed when the
  node is killed, which is why it carries the OS pid: a stale file is detectable rather
  than misleading.

  A release that was handed no configuration at all publishes the same way and then says
  so on stdout — the directory, the bound address, and the two files a client needs to
  find it. That notice is printed only for that posture, because it is the only one where
  nobody chose the port or the path and so nobody already knows them.

  ## Accepting

  A linked acceptor process owns the blocking `:gen_tcp.accept/1` loop so this GenServer
  keeps a responsive mailbox. Transient accept errors are retried in place; only a closed
  listen socket ends the loop. If the acceptor dies for any other reason it is restarted
  here rather than by failing upward, because the listen socket is still perfectly good
  and rebinding would move the published port out from under a connected client.

  Connections are capped. The token is what stops a stranger from being served, but it is
  not what stops a stranger from opening sockets, and "bounded everything" has to include
  the thing an unauthenticated peer can do for free.
  """

  use GenServer

  require Logger

  alias Ouroboros.DataDir
  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.RuntimeOwner

  @publication_name "gateway.json"
  @protocol 1
  @accept_retry_ms 100

  # A pinned port (fleet profiles pin the gateway) can be held at bind time by a socket
  # the kernel numbered itself — an ephemeral source port of some loopback client, often
  # this very fleet's EPMD chatter — because historical fleet defaults sit inside Linux's
  # ephemeral range (32768-60999). Such holders are gone within moments, so a bounded
  # rebind is the difference between a failed enrollment and a boot nobody noticed was
  # racing. Port 0 never retries: the kernel always has another number.
  @pinned_rebind_budget_ms 15_000
  @pinned_rebind_interval_ms 250

  @doc "Starts the listener."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "The port this listener actually bound, which is not the configured one when it was 0."
  @spec port(GenServer.server()) :: :inet.port_number()
  def port(server \\ __MODULE__), do: GenServer.call(server, :port)

  @doc "The path of the file this listener published its port to."
  @spec publication_path(Path.t()) :: Path.t()
  def publication_path(data_dir), do: Path.join(data_dir, @publication_name)

  @impl true
  def init(opts) do
    config = Keyword.fetch!(opts, :config)
    conn_supervisor = Keyword.fetch!(opts, :conn_supervisor)
    task_supervisor = Keyword.fetch!(opts, :task_supervisor)
    retry = Keyword.get(opts, :listen_retry, [])
    DataDir.ensure_private!(config.data_dir)
    Process.flag(:trap_exit, true)

    case listen_pinned_port(config, retry) do
      {:ok, listen_socket} ->
        {:ok, port} = :inet.port(listen_socket)
        {path, publication_stat} = publish!(config, port)

        state = %{
          config: config,
          conn_supervisor: conn_supervisor,
          task_supervisor: task_supervisor,
          listen_socket: listen_socket,
          port: port,
          publication: path,
          publication_stat: publication_stat,
          acceptor: nil
        }

        announce(config, port, path)

        {:ok, %{state | acceptor: start_acceptor(state)}}

      {:error, reason} ->
        {:stop, {:gateway_listen_failed, Config.bind_to_string(config.bind), config.port, reason}}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}

  @impl true
  def handle_info({:EXIT, acceptor, :normal}, %{acceptor: acceptor} = state) do
    {:stop, :normal, state}
  end

  def handle_info({:EXIT, acceptor, reason}, %{acceptor: acceptor} = state) do
    Logger.warning("gateway acceptor exited (#{inspect(reason, limit: 10)}); accepting again")
    {:noreply, %{state | acceptor: start_acceptor(state)}}
  end

  def handle_info({:EXIT, _pid, reason}, state), do: {:stop, reason, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    _ = remove_publication_if_owner(state.publication, state.publication_stat)
    _ = :gen_tcp.close(state.listen_socket)
    :ok
  end

  defp listen_options(config) do
    [
      :binary,
      ip: config.bind,
      active: false,
      reuseaddr: true,
      backlog: 16,
      packet: :line,
      packet_size: config.max_frame,
      buffer: config.max_frame
    ]
  end

  # Bind, and when the port is pinned, outlast a transient holder. Only `:eaddrinuse`
  # retries — every other refusal is a fact about the machine that waiting cannot change,
  # and it is reported immediately with the honest reason.
  defp listen_pinned_port(config, retry) do
    budget_ms = Keyword.get(retry, :budget_ms, @pinned_rebind_budget_ms)
    interval_ms = Keyword.get(retry, :interval_ms, @pinned_rebind_interval_ms)
    deadline = System.monotonic_time(:millisecond) + budget_ms
    listen_attempt(config, budget_ms, interval_ms, deadline, 0)
  end

  defp listen_attempt(config, budget_ms, interval_ms, deadline, attempts) do
    case :gen_tcp.listen(config.port, listen_options(config)) do
      {:ok, listen_socket} ->
        if attempts > 0 do
          Logger.info(
            "gateway bound pinned port #{Config.bind_to_string(config.bind)}:#{config.port} " <>
              "after #{attempts} rebind attempt(s); the earlier holder released it"
          )
        end

        {:ok, listen_socket}

      {:error, :eaddrinuse} = error when config.port != 0 ->
        if System.monotonic_time(:millisecond) < deadline do
          if attempts == 0 do
            Logger.warning(
              "pinned gateway port #{Config.bind_to_string(config.bind)}:#{config.port} is " <>
                "in use; retrying for up to #{div(budget_ms, 1000)}s — a collision with a " <>
                "kernel-assigned ephemeral port clears itself, a real listener does not"
            )
          end

          Process.sleep(interval_ms)
          listen_attempt(config, budget_ms, interval_ms, deadline, attempts + 1)
        else
          error
        end

      {:error, _reason} = error ->
        error
    end
  end

  defp announce(config, port, path) do
    Logger.info(
      "gateway listening on #{Config.bind_to_string(config.bind)}:#{port} " <>
        "at #{config.scope} scope; published to #{path}"
    )

    unless Config.loopback?(config.bind) do
      Logger.warning(
        "gateway is bound to #{Config.bind_to_string(config.bind)}, which is not " <>
          "loopback: the token and every payload after it cross the network in " <>
          "cleartext (OUROBOROS_GATEWAY_ALLOW_REMOTE=1 accepted this)"
      )
    end

    if config.token_generate and is_binary(config.token_file) do
      notice(config, port, path)
    end
  end

  # `:token_generate` is set by one caller: the branch of `config/runtime.exs` that
  # configures a release nobody configured. It is therefore also the marker for "nothing
  # about this surface was typed by anyone", which is the only case where the port, the
  # directory, and the client's name are facts the operator has not already got in front
  # of them. This goes to stdout rather than the log, because a person who ran
  # `bin/ouroboros start` in a terminal is reading stdout; the same branch of
  # `config/runtime.exs` keeps the default log handler off stdout (stderr for a foreground
  # client, the separate live-rotated runtime log for a managed daemon) so this stream
  # stays the daemon's own, whether a person or a client is holding it.
  defp notice(config, port, path) do
    distribution =
      if Node.alive?(), do: "distribution on as #{node()}", else: "distribution off"

    IO.puts("""
    ouroboros: single-machine mode, #{distribution}
      data dir  #{config.data_dir}
      gateway   #{Config.bind_to_string(config.bind)}:#{port} at #{config.scope} scope
      a client reads #{Path.basename(path)} and #{Path.basename(config.token_file)} \
    in the data dir to find and authenticate to this node
      `ouro` is that client; run it to attach\
    """)
  end

  defp publish!(config, port) do
    DataDir.ensure_private!(config.data_dir)

    path = publication_path(config.data_dir)

    tmp =
      path <>
        ".tmp-#{os_pid()}-#{System.unique_integer([:positive, :monotonic])}-#{Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)}"

    owner =
      case Process.whereis(RuntimeOwner) do
        nil -> %{pid: os_pid(), birth: nil}
        _pid -> RuntimeOwner.claim()
      end

    published = %{
      "port" => port,
      "protocol" => @protocol,
      "node" => Atom.to_string(node()),
      "pid" => owner.pid,
      "scope" => Atom.to_string(config.scope)
    }

    published =
      if is_binary(owner.birth), do: Map.put(published, "birth", owner.birth), else: published

    # The path to the credential, never the credential. A client that did not spawn this
    # daemon otherwise has to guess where the token file lives by convention, and a
    # listener whose token came from the environment cannot be attached to at all — so the
    # key is present exactly when there is a file to name, and absent when there is not.
    # The value itself stays out of this file for the same reason it stays out of logs.
    published =
      case config.token_file do
        path when is_binary(path) -> Map.put(published, "token_file", path)
        nil -> published
      end

    contents = JSON.encode_to_iodata!(published)

    publication_stat =
      try do
        # The exclusive empty inode makes a preplanted symlink a refusal. Its mode is private
        # before any discovery bytes are written, and the descriptor is synced before rename.
        File.write!(tmp, "", [:exclusive, :sync])
        File.chmod!(tmp, 0o600)
        before = File.lstat!(tmp, time: :posix)

        File.open!(tmp, [:write, :binary], fn io ->
          IO.binwrite(io, contents)
          :ok = :file.sync(io)
        end)

        after_write = File.lstat!(tmp, time: :posix)

        unless same_file?(before, after_write) do
          raise "gateway publication temporary inode changed while it was written"
        end

        File.rename!(tmp, path)
        published = File.lstat!(path, time: :posix)

        unless same_file?(after_write, published) do
          raise "gateway publication inode changed while it was published"
        end

        published
      rescue
        error ->
          _ = File.rm(tmp)
          reraise error, __STACKTRACE__
      end

    {path, publication_stat}
  end

  defp remove_publication_if_owner(path, expected) do
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

  defp start_acceptor(state) do
    listen_socket = state.listen_socket
    conn_supervisor = state.conn_supervisor
    task_supervisor = state.task_supervisor
    config = state.config

    spawn_link(fn ->
      accept_loop(listen_socket, conn_supervisor, task_supervisor, config)
    end)
  end

  defp accept_loop(listen_socket, conn_supervisor, task_supervisor, config) do
    case :gen_tcp.accept(listen_socket) do
      {:ok, socket} ->
        hand_off(socket, conn_supervisor, task_supervisor, config)
        accept_loop(listen_socket, conn_supervisor, task_supervisor, config)

      {:error, reason} when reason in [:closed, :einval] ->
        exit(:normal)

      {:error, reason} ->
        Logger.warning("gateway accept failed: #{inspect(reason)}")
        Process.sleep(@accept_retry_ms)
        accept_loop(listen_socket, conn_supervisor, task_supervisor, config)
    end
  end

  defp hand_off(socket, conn_supervisor, task_supervisor, config) do
    child = {Conn, socket: socket, config: config, task_supervisor: task_supervisor}

    case DynamicSupervisor.start_child(conn_supervisor, child) do
      {:ok, pid} ->
        case :gen_tcp.controlling_process(socket, pid) do
          :ok ->
            send(pid, :socket_ready)

          {:error, _reason} ->
            # The connection process is already armed with its own handshake deadline, so
            # it reaps itself; only the socket needs closing here.
            :gen_tcp.close(socket)
        end

      {:error, :max_children} ->
        Logger.warning("gateway refused a connection: the per-listener cap is reached")
        :gen_tcp.close(socket)

      {:error, reason} ->
        Logger.warning("gateway could not start a connection: #{inspect(reason, limit: 10)}")
        :gen_tcp.close(socket)
    end
  end
end
