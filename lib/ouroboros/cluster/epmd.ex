defmodule Ouroboros.Cluster.Epmd do
  @moduledoc """
  The fleet's `-epmd_module`: distribution without an EPMD daemon.

  Erlang's port mapper exists to answer one question — "which TCP port is `name@host`
  listening on?" — for a machine that may run many nodes on ports nobody chose. An
  Ouroboros fleet has neither problem. One fleet has one distribution port, every member
  already carries the other members in its own profile, and the launcher exports that
  answer as `OUROBOROS_DIST_PORT` (this node's listener) and `OUROBOROS_DIST_PORTS`. So
  the daemon is replaced by a lookup in this module: no extra process, no extra listening
  socket, and nothing to reach on 4369.

  The generated `vm.args` names this module with `-epmd_module` and turns the daemon off
  with `-start_epmd false`. Releases boot in embedded mode, so every module in the
  release is loaded before any application starts, which is what makes this module
  available to `net_kernel` before distribution comes up.

  **Being loaded is not optional, and being on the path is not enough.**
  `inet_tcp_dist:call_epmd_function/3` gates every callback but `register_node/3` on
  `erlang:function_exported/3`, which answers `false` for a module that has not been
  loaded yet — and then applies `erl_epmd` instead, with no error anywhere. A node in that
  state binds an ephemeral port and dials peers through a port mapper that is not running.
  Nothing here can detect it, because the fallback is taken before this module is reached.
  Two things keep it from happening: embedded mode above, and `erl_distribution`, which
  starts the epmd module as its first child — calling `start_link/0` loads it before
  `net_kernel` listens. A test that drives `inet_tcp_dist` directly, without starting
  distribution, has neither and must load this module itself.

  ## The map

  `OUROBOROS_DIST_PORTS` is `name@host=port`, one entry per member including this one,
  written by the launcher from the profile's members. It is keyed by the whole node name
  rather than by the host for two reasons: a lab or a test may put two nodes on one host,
  where a host-keyed map cannot answer for both; and the node name is the one string the
  dialer is actually holding. A bare `host=port` entry is still read, as a fallback for a
  hand-written map, and a node-name entry wins wherever the two disagree.

  ## The answers

  | Callback | Answer |
  |---|---|
  | `start_link/0` | `:ignore` — there is nothing to supervise |
  | `register_node/2,3` | `{:ok, creation}`; nothing is registered anywhere |
  | `listen_port_please/2` | `OUROBOROS_DIST_PORT`, else `{:ok, 0}` (the kernel's own range, then ephemeral) |
  | `address_please/3` | `{:ok, ip, port, 5}` when the map names this node, else `{:ok, ip}` |
  | `port_please/2,3` | the map, else `OUROBOROS_DIST_PORT`, else `:noport` |
  | `names/1` | `{:error, :address}` — there is no registry to enumerate |

  ## Why the port is answered from `address_please/3`

  `inet_tcp_dist:fam_setup/4` calls `address_please/3` first and, unless that answers with
  a port, calls `port_please/2` with the **address it just resolved**. So on the dial path
  `port_please/2` never sees a host's text: a member whose `host` is a private DNS name —
  which §2 of the fleet contract allows — would have its map entry looked up under
  `name@<resolved ip>`, which is in no map anyone writes, and would be dialled on this
  node's own `OUROBOROS_DIST_PORT` instead. That is invisible while one fleet shares one
  port and wrong the moment it does not.

  The lookup therefore happens in `address_please/3`, which still has the host as the
  operator wrote it, and the four-tuple skips `port_please/2` entirely. `port_please/2,3`
  stays for hand calls and for any caller that reaches it with a host of its own, and
  applies the same lookup to whatever shape it is given.

  A member the map does not name falls back to `OUROBOROS_DIST_PORT`, which is the
  production case: one port for the whole fleet means this node's own listener names it.
  `:noport` — neither variable set — is a node that was never given a way to dial anyone,
  and is reported as such rather than guessed at.
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

  Not the dial path — see the moduledoc: `inet_tcp_dist` reaches this only when
  `address_please/3` answered without a port, and then with the resolved address rather
  than the host's text. It is kept for hand calls and for any caller that has a host of
  its own, and it applies the same lookup to whichever of the three shapes it is given: a
  charlist, a binary, or an IP tuple. `timeout` is accepted and ignored, because this
  answer costs no network round trip, which is the point.
  """
  @spec port_please(charlist() | String.t(), term()) ::
          {:port, :inet.port_number(), pos_integer()} | :noport
  def port_please(name, host), do: port_please(name, host, :infinity)

  @spec port_please(charlist() | String.t(), term(), term()) ::
          {:port, :inet.port_number(), pos_integer()} | :noport
  def port_please(name, host, _timeout) do
    case lookup_port(name, normalize(host)) || listen_port() do
      nil -> :noport
      port -> {:port, port, @dist_version}
    end
  end

  @doc """
  Resolves a peer's host, and answers with its port when the map names it.

  Resolution is the one thing EPMD never did: a member's host is an address or a private
  DNS name the operator's network already answers for. The port comes with it because
  this is the last place that holds the host as the profile spelled it — the moduledoc
  has the whole of why.

  `{:ok, address}` means "resolved, and the map says nothing about this node", which
  sends `inet_tcp_dist` on to `port_please/2` and its `OUROBOROS_DIST_PORT` fallback. A
  host that does not resolve is an error tuple, never a raise: the dialer turns it into a
  refused connection and tries again later.
  """
  @spec address_please(charlist() | String.t(), term(), :inet.address_family()) ::
          {:ok, :inet.ip_address()}
          | {:ok, :inet.ip_address(), :inet.port_number(), pos_integer()}
          | {:error, term()}
  def address_please(name, host, family) do
    # One spelling before the resolver too, so an address tuple, a charlist and a binary
    # all reach `:inet.getaddr/2` — which refuses a binary — and the map lookup below in
    # the same shape.
    host = normalize(host)

    with {:ok, address} <- :inet.getaddr(String.to_charlist(host), family) do
      case lookup_port(name, host) do
        nil -> {:ok, address}
        port -> {:ok, address, port, @dist_version}
      end
    end
  end

  @doc """
  There is no registry to enumerate, and saying so is the honest answer.

  `{:error, :address}` is exactly what `erl_epmd` answers for a host with no port mapper
  listening, so every caller that already handles an absent EPMD handles this too.
  """
  @spec names(term()) :: {:error, :address}
  def names(_host), do: {:error, :address}

  # The map's answer for one node, or `nil`. The node's own name is consulted before the
  # bare host, so a map that names both — a lab running two nodes on one machine — answers
  # each of them rather than whichever entry happens to be written first.
  defp lookup_port(name, host) do
    ports = dist_ports()
    host = lookup_host(host)

    case normalize(name) do
      "" -> Map.get(ports, host)
      name -> Map.get(ports, name <> "@" <> host) || Map.get(ports, host)
    end
  end

  # A trailing dot is the DNS root and is not part of the name, so `pi.internal.` and
  # `pi.internal` are one key. Applied to the map's own keys as well as to the host being
  # looked up, because `valid_profile_host?/1` admits a fully qualified host and a fold
  # done on one side only would turn a profile that uses one into a member nothing can
  # find. Exactly one dot is stripped: anything further is a malformed host, and inventing
  # a reading for it would be guessing.
  #
  # Only the key folds. Resolution is left exactly as `:inet` does it — a trailing dot
  # tells a resolver not to append its search domains, and dropping it there could answer
  # with a different host than the one asked for.
  defp lookup_host(host), do: String.replace_suffix(host, ".", "")

  # `OUROBOROS_DIST_PORTS`, as a map from a whole node name (or a bare host) to a port.
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
         key = key |> String.trim() |> lookup_host(),
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

  defp env(name) do
    case System.get_env(name) do
      nil -> nil
      value -> if String.trim(value) == "", do: nil, else: String.trim(value)
    end
  end
end
