defmodule Ouroboros.Upgrade.Forge.BuildPeer do
  @moduledoc """
  A short-lived OS process that compiles and tests candidate code where the cluster is not.

  `with_peer/2` starts an OTP `:peer` node, hands it to `fun`, and stops it in an `after`
  block on every path — success, error, timeout, or exception. The peer is configured to
  be unreachable rather than merely unused:

    * `connection: :standard_io` makes the control channel a pipe. The peer never joins
      the distribution mesh, so `node()` inside it is `:nonode@nohost` and
      `:erlang.is_alive/0` is false. Generated code cannot `:erpc` a production node
      because there is no distribution to do it with.
    * `-start_epmd false` keeps the peer from starting a port mapper. Even
      `Node.start/2` inside the peer has no name service to register with.
    * `-pa` entries mirror this VM's code path, so dependencies compile against the same
      libraries the target nodes run.

  Isolation is process-level, not OS-level. The peer runs as the same user with the same
  filesystem and network reach; what it cannot do is talk to the cluster. Compiling
  genuinely hostile source needs a container or VM around this peer, and the build host
  should not be the production host.

  The peer must share ERTS, Elixir version, and system architecture with the deployment
  targets, because the BEAM it produces is checked against exactly those on the loading
  node (`Ouroboros.Upgrade.Verifier`). Starting the peer from this VM's own executable
  and code path is what makes that true here; a remote build service has to establish it
  some other way.

  One deadline covers boot, the callback, and everything the callback does inside the
  peer. It comes from `config :ouroboros, :forge_build_timeout` and defaults to 60s. A
  callback that outlives it is killed and the peer is stopped regardless.
  """

  alias Ouroboros.Upgrade.Forge.Sandbox

  @default_timeout 60_000
  @default_boot_timeout 30_000

  @type peer :: pid()

  @doc """
  Starts a build peer, applies `fun` to it, and always stops it.

  Options: `:timeout` (overall deadline in milliseconds) and `:boot_timeout`.
  """
  @spec with_peer((peer() -> result), keyword()) :: result | {:error, term()}
        when result: term()
  def with_peer(fun, opts \\ []) when is_function(fun, 1) and is_list(opts) do
    deadline = deadline(opts)
    started_at = System.monotonic_time(:millisecond)

    case start_peer(min(deadline, boot_timeout(opts))) do
      {:ok, peer} ->
        try do
          remaining = deadline - (System.monotonic_time(:millisecond) - started_at)
          with_deadline(fun, peer, remaining)
        after
          stop_peer(peer)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Compiles and tests one capability source in a fresh peer.

  This is `with_peer/2` wrapped around `Ouroboros.Upgrade.Forge.Sandbox.compile_and_test/3`,
  which is the only shape the forge itself needs.
  """
  @spec build(module(), String.t(), String.t() | nil, keyword()) ::
          {:ok, map()} | {:error, term()}
  def build(module, source, test_source, opts \\ [])
      when is_atom(module) and is_binary(source) do
    with_peer(
      fn peer ->
        call(peer, Sandbox, :compile_and_test, [module, source, test_source], call_timeout(opts))
      end,
      opts
    )
  end

  @doc "Calls into the peer, converting a lost control connection into an error tuple."
  @spec call(peer(), module(), atom(), [term()], timeout()) :: term()
  def call(peer, module, function, arguments, timeout \\ @default_timeout) do
    :peer.call(peer, module, function, arguments, timeout)
  catch
    kind, reason -> {:error, {:peer_call_failed, kind, sanitize(reason)}}
  end

  defp start_peer(boot_timeout) do
    arguments = [~c"-start_epmd", ~c"false"] ++ code_path_arguments()

    case :peer.start(%{connection: :standard_io, args: arguments, wait_boot: boot_timeout}) do
      {:ok, peer} -> ensure_elixir(peer)
      {:ok, peer, _node} -> ensure_elixir(peer)
      {:error, reason} -> {:error, {:build_peer_start_failed, sanitize(reason)}}
      other -> {:error, {:build_peer_start_failed, sanitize(other)}}
    end
  catch
    kind, reason -> {:error, {:build_peer_start_failed, {kind, sanitize(reason)}}}
  end

  # A bare `erl` boot has the Elixir libraries on its path but has not started the
  # `:elixir` application, so `Code.compile_string/2` would fail on missing compiler
  # configuration rather than on the source it was given.
  defp ensure_elixir(peer) do
    case call(peer, :application, :ensure_all_started, [:elixir], @default_boot_timeout) do
      {:ok, _started} ->
        {:ok, peer}

      other ->
        stop_peer(peer)
        {:error, {:build_peer_boot_failed, sanitize(other)}}
    end
  end

  defp with_deadline(_fun, _peer, remaining) when remaining <= 0,
    do: {:error, {:build_timeout, 0}}

  defp with_deadline(fun, peer, remaining) do
    task = Task.async(fn -> fun.(peer) end)

    case Task.yield(task, remaining) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      {:exit, reason} -> {:error, {:build_crashed, sanitize(reason)}}
      nil -> {:error, {:build_timeout, remaining}}
    end
  end

  defp stop_peer(peer) do
    :peer.stop(peer)
    :ok
  catch
    _kind, _reason -> :ok
  end

  defp code_path_arguments do
    Enum.flat_map(:code.get_path(), fn directory -> [~c"-pa", directory] end)
  end

  defp deadline(opts) do
    positive_option(
      Keyword.get_lazy(opts, :timeout, fn ->
        Application.get_env(:ouroboros, :forge_build_timeout, @default_timeout)
      end),
      @default_timeout
    )
  end

  defp boot_timeout(opts) do
    positive_option(
      Keyword.get(opts, :boot_timeout, @default_boot_timeout),
      @default_boot_timeout
    )
  end

  # The peer call deadline is deliberately larger than the overall one: the overall
  # deadline is enforced by the surrounding task, and a call that is still running when it
  # expires must be abandoned rather than raced.
  defp call_timeout(opts), do: deadline(opts) + 5_000

  defp positive_option(value, _default) when is_integer(value) and value > 0, do: value
  defp positive_option(_value, default), do: default

  # A peer failure can carry ports, pids, and stacktraces. The forge records its errors in
  # a durable registry and in signed artifact metadata, so they are reduced to text here.
  defp sanitize(reason) do
    if serializable?(reason), do: reason, else: inspect(reason)
  end

  defp serializable?(term) when is_atom(term) or is_binary(term) or is_number(term), do: true
  defp serializable?(term) when is_list(term), do: Enum.all?(term, &serializable?/1)

  defp serializable?(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.all?(&serializable?/1)

  defp serializable?(term) when is_map(term) do
    Enum.all?(term, fn {key, value} -> serializable?(key) and serializable?(value) end)
  end

  defp serializable?(_term), do: false
end
