defmodule OuroFleet.Boot do
  @moduledoc "Start only provisioned TLS distribution; credentials never enter argv."
  import Bitwise

  def start(config, client \\ false) do
    {:ok, _} = Application.ensure_all_started(:ssl)
    {:ok, [[~c"inet_tls"]]} = :init.get_argument(:proto_dist)
    tls = private!(config["tls"])
    {:ok, [[actual_tls]]} = :init.get_argument(:ssl_dist_optfile)
    if to_string(actual_tls) != tls, do: raise("TLS configuration mismatch")
    {:ok, [options]} = :file.consult(String.to_charlist(tls))

    Enum.each([:server, :client], fn side ->
      opts = Keyword.fetch!(options, side)
      if opts[:verify] != :verify_peer, do: raise("fleet requires mutual TLS verification")

      if side == :server and opts[:fail_if_no_peer_cert] != true,
        do: raise("fleet requires peer certificates")

      Enum.each(
        [:certfile, :keyfile, :cacertfile],
        &private!(to_string(Keyword.fetch!(opts, &1)))
      )
    end)

    cookie = config["cookie"] |> private!() |> File.read!() |> String.trim()
    unless Regex.match?(~r/^[0-9a-f]{64}$/, cookie), do: raise("invalid fleet cookie")
    members = config["members"]
    if length(members) not in 1..64, do: raise("invalid fleet roster")
    {:ok, interface} = :inet.parse_address(String.to_charlist(config["host"]))
    Application.put_env(:kernel, :inet_dist_use_interface, interface)

    System.put_env(
      "OUROBOROS_DIST_PORTS",
      Enum.map_join(members, ",", fn m -> "#{m["node"]}=#{m["dist_port"]}" end)
    )

    name =
      if client do
        "ouro-client-" <>
          Base.encode16(:crypto.strong_rand_bytes(8), case: :lower) <> "@" <> config["host"]
      else
        System.put_env("OUROBOROS_DIST_PORT", to_string(config["dist_port"]))
        config["node"]
      end

    {:module, _} = Code.ensure_loaded(Ouroboros.Cluster.Epmd)

    options =
      if client, do: %{name_domain: :longnames, hidden: true}, else: %{name_domain: :longnames}

    {:ok, _} = :net_kernel.start(String.to_atom(name), options)
    true = Node.set_cookie(String.to_atom(cookie))
    :ok
  end

  def private!(path) do
    case File.lstat!(path) do
      %{type: :regular, mode: mode, links: 1} when band(mode, 0o777) == 0o600 -> path
      _ -> raise("fleet credential/configuration must be a private regular file")
    end
  end
end
