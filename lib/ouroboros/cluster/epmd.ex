defmodule Ouroboros.Cluster.Epmd do
  @moduledoc """
  The fleet's `-epmd_module`: distribution without an EPMD daemon.

  Erlang's port mapper exists to answer one question — "which TCP port is `name@host`
  listening on?" — for a machine that may run many nodes on ports nobody chose. An
  Ouroboros fleet has neither problem. One fleet has one distribution port, every member
  already carries the other members in its own profile, and the launcher exports that
  answer as `OUROBOROS_DIST_PORT` (this node's listener) and `OUROBOROS_DIST_PORTS`
  (`host=port` for every member, including this one). So the daemon is replaced by a
  lookup in this module: no extra process, no extra listening socket, and nothing to
  reach on 4369.

  The generated `vm.args` names this module with `-epmd_module` and turns the daemon off
  with `-start_epmd false`. Releases boot in embedded mode, so every module in the
  release is loaded before any application starts, which is what makes this module
  available to `net_kernel` before distribution comes up.

  ## The answers

  | Callback | Answer |
  |---|---|
  | `start_link/0` | `:ignore` — there is nothing to supervise |
  | `register_node/2,3` | `{:ok, creation}`; nothing is registered anywhere |
  | `listen_port_please/2` | `OUROBOROS_DIST_PORT`, else `{:ok, 0}` (the kernel's own range, then ephemeral) |
  | `port_please/2,3` | `OUROBOROS_DIST_PORTS[host]`, else `OUROBOROS_DIST_PORT`, else `:noport` |
  | `address_please/3` | `:inet.getaddr/2` |
  | `names/1` | `{:error, :address}` — there is no registry to enumerate |

  `port_please/2,3` is reached from `inet_tcp_dist` *after* `address_please/3` has
  resolved the host, so the host arrives as an IP tuple there and as a string elsewhere.
  Every shape is folded to the same text before the lookup, so one map entry answers a
  member whether it was spelled as a charlist, a binary or an address.

  A member that is not in the map falls back to `OUROBOROS_DIST_PORT`, which is the
  production case: one port for the whole fleet means this node's own listener names it.
  `:noport` — neither variable set — is a node that was never given a way to dial
  anyone, and is reported as such rather than guessed at.

  ## Two nodes on one host

  `OUROBOROS_DIST_PORTS` is `host=port` in production, one entry per member, because a
  fleet has one member per host. A lab or a test may put two nodes on one host, where a
  host-keyed map cannot answer for both, so an entry may also be keyed by a whole node
  name — `name@host=port` — and the full name is consulted before the bare host. A map
  written the production way behaves exactly as the table above says.
  """

  # The distribution protocol version `erl_epmd` reports, and the only one ERTS speaks.
  @dist_version 5

  # `register_node/2,3` must answer with a creation, which distinguishes an incarnation
  # of a node name from the one before it so a stale reference is recognised as stale.
  # EPMD allocated it centrally; with no registry, each node picks its own from the same
  # small range the port mapper used.
  @creations 1..3

  @doc """
  Nothing to start. `net_kernel` accepts `:ignore` and carries on.
  """
  @spec start_link() :: :ignore
  def start_link, do: :ignore

  @doc """
  Accepts the registration without recording it anywhere, and answers with a creation.

  There is no registry, so there is nothing for a second node to collide with and
  nothing to unregister on the way down. `Driver` is ignored for the same reason.
  """
  @spec register_node(charlist() | String.t(), :inet.port_number()) :: {:ok, pos_integer()}
  def register_node(name, port), do: register_node(name, port, :inet)

  @spec register_node(charlist() | String.t(), :inet.port_number(), atom()) ::
          {:ok, pos_integer()}
  def register_node(_name, _port, _driver), do: {:ok, Enum.random(@creations)}

  @doc """
  The port this node's distribution listener must bind.

  `{:ok, 0}` means "nothing was asked for": `inet_tcp_dist` then falls back to the
  `inet_dist_listen_min`/`max` kernel range, and to an ephemeral port when that is unset
  too. The generated `vm.args` sets both, so the pinned port is stated twice and agrees.
  """
  @spec listen_port_please(charlist() | String.t(), term()) :: {:ok, :inet.port_number()}
  def listen_port_please(_name, _host), do: {:ok, listen_port() || 0}

  @doc """
  The port a peer is listening on, from this node's own environment.

  `host` arrives as a charlist, a binary or an IP tuple depending on the caller, and is
  normalised to text before the lookup. `timeout` is accepted and ignored: this answer
  costs no network round trip, which is the point.
  """
  @spec port_please(charlist() | String.t(), term()) ::
          {:port, :inet.port_number(), pos_integer()} | :noport
  def port_please(name, host), do: port_please(name, host, :infinity)

  @spec port_please(charlist() | String.t(), term(), term()) ::
          {:port, :inet.port_number(), pos_integer()} | :noport
  def port_please(name, host, _timeout) do
    host = normalize(host)
    ports = dist_ports()

    port =
      case normalize(name) do
        "" -> Map.get(ports, host)
        name -> Map.get(ports, name <> "@" <> host) || Map.get(ports, host)
      end

    case port || listen_port() do
      nil -> :noport
      port -> {:port, port, @dist_version}
    end
  end

  @doc """
  Resolves a peer's host to an address, which is the one thing EPMD never did.

  A member's host is an address or a private DNS name the operator's network already
  answers for, so this is the resolver and nothing else.
  """
  @spec address_please(charlist() | String.t(), term(), :inet.address_family()) ::
          {:ok, :inet.ip_address()} | {:error, term()}
  def address_please(_name, host, family) do
    :inet.getaddr(to_charlist_host(host), family)
  end

  @doc """
  There is no registry to enumerate, and saying so is the honest answer.

  `{:error, :address}` is exactly what `erl_epmd` answers for a host with no port mapper
  listening, so every caller that already handles an absent EPMD handles this too.
  """
  @spec names(term()) :: {:error, :address}
  def names(_host), do: {:error, :address}

  # `OUROBOROS_DIST_PORTS`, as a map from a host (or a whole node name) to a port.
  #
  # Read on every lookup rather than cached: the profile is the authority for membership
  # and the launcher rewrites this environment at every refresh, so a stale copy here
  # would be a second, older roster. An entry that is not `key=port` with a port in
  # 1..65535 is ignored rather than fatal — one bad entry must not cost this node every
  # other member — and the first entry for a key wins, so a duplicate cannot change an
  # answer already given.
  defp dist_ports do
    "OUROBOROS_DIST_PORTS"
    |> env()
    |> case do
      nil -> %{}
      value -> value |> String.split(",", trim: true) |> Enum.reduce(%{}, &put_entry/2)
    end
  end

  defp put_entry(entry, ports) do
    with [key, value] <- String.split(entry, "=", parts: 2),
         key = String.trim(key),
         true <- key != "",
         {:ok, port} <- parse_port(String.trim(value)) do
      Map.put_new(ports, key, port)
    else
      _malformed -> ports
    end
  end

  defp listen_port do
    with value when is_binary(value) <- env("OUROBOROS_DIST_PORT"),
         {:ok, port} <- parse_port(value) do
      port
    else
      _absent_or_invalid -> nil
    end
  end

  defp parse_port(value) do
    case Integer.parse(value) do
      {port, ""} when port > 0 and port < 65_536 -> {:ok, port}
      _other -> :error
    end
  end

  # One spelling for a host, whatever the caller had: `inet_tcp_dist` hands
  # `port_please/2` the address `address_please/3` just resolved, while a hand call and
  # `dist_util` hand it the text out of the node name.
  defp normalize(host) when is_tuple(host) do
    case :inet.ntoa(host) do
      address when is_list(address) -> List.to_string(address)
      _invalid -> ""
    end
  end

  defp normalize(host) when is_list(host), do: List.to_string(host)
  defp normalize(host) when is_binary(host), do: host
  defp normalize(host) when is_atom(host), do: Atom.to_string(host)
  defp normalize(_other), do: ""

  # `:inet.getaddr/2` takes a hostname as a charlist or an atom, or an address tuple. A
  # binary is the one shape it refuses, so it is the one shape converted.
  defp to_charlist_host(host) when is_binary(host), do: String.to_charlist(host)
  defp to_charlist_host(host), do: host

  defp env(name) do
    case System.get_env(name) do
      nil -> nil
      value -> if String.trim(value) == "", do: nil, else: String.trim(value)
    end
  end
end
