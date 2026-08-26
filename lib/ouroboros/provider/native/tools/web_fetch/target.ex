defmodule Ouroboros.Provider.Native.Tools.WebFetch.Target do
  @moduledoc """
  Whether a URL's host is one `web_fetch` will open a socket to.

  Domain rules match the hostname the model typed. They do not see the addresses
  that name resolves to, so a permitted `example.com` that rebinds to `169.254.169.254`
  — or a literal `http://127.0.0.1/` — would otherwise reach loopback, RFC1918, and
  cloud metadata. This module refuses those destinations after a DNS lookup and
  before Mint connects.

  The residual window is DNS rebinding between this lookup and the connect
  Mint does itself. Pinning the connect to the admitted address is not done
  here: it would require a custom transport that still presents the original
  hostname for TLS verification. The lookup is still the difference between
  "we never checked" and "we checked once".
  """

  @blocked_hosts MapSet.new([
                   "localhost",
                   "localhost.localdomain",
                   "metadata.google.internal",
                   "metadata.google.com"
                 ])

  @doc """
  Refuses a URI whose host is blocked by name or whose any resolved address is
  loopback, link-local, private, metadata, or otherwise non-public.
  """
  @spec admit(URI.t(), map()) :: :ok | {:error, term()}
  def admit(uri, context \\ %{})

  def admit(%URI{host: host}, context) when is_binary(host) and host != "" do
    normalized =
      host
      |> String.downcase()
      |> String.trim_leading("[")
      |> String.trim_trailing("]")

    cond do
      blocked_hostname?(normalized) ->
        {:error, {:blocked_host, host}}

      true ->
        with {:ok, addresses} <- lookup(normalized),
             :ok <- admit_addresses(host, addresses, context) do
          :ok
        end
    end
  end

  def admit(_uri, _context), do: {:error, {:no_host, ""}}

  defp blocked_hostname?(host) do
    host in @blocked_hosts or
      String.ends_with?(host, ".localhost") or
      String.ends_with?(host, ".local")
  end

  defp lookup(host) do
    char = String.to_charlist(host)

    case :inet.parse_strict_address(char) do
      {:ok, address} ->
        {:ok, [address]}

      {:error, :einval} ->
        case resolve(char) do
          [] -> {:error, {:unresolvable, host}}
          addresses -> {:ok, Enum.uniq(addresses)}
        end
    end
  end

  defp resolve(char) do
    inet = lookup_family(char, :inet)
    inet6 = lookup_family(char, :inet6)
    inet ++ inet6
  end

  defp lookup_family(char, family) do
    case :inet.getaddrs(char, family) do
      {:ok, addresses} -> addresses
      {:error, _reason} -> []
    end
  end

  defp admit_addresses(host, addresses, context) do
    case Enum.filter(addresses, &blocked_address?(&1, context)) do
      [] -> :ok
      blocked -> {:error, {:blocked_address, host, format_address(hd(blocked))}}
    end
  end

  defp blocked_address?(address, context) do
    case classify(address) do
      :loopback -> not allow_loopback?(context)
      :blocked -> true
      :public -> false
    end
  end

  # Test-only: the loopback listener in `web_fetch_test` sets this on the tool
  # context so its own fetches can reach 127.0.0.1. Production never sets it.
  defp allow_loopback?(context) when is_map(context),
    do: Map.get(context, :web_fetch_allow_loopback) == true

  defp allow_loopback?(_context), do: false

  defp classify({a, b, c, d}) when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255 do
    cond do
      a == 127 -> :loopback
      a == 0 -> :loopback
      blocked_v4?({a, b, c, d}) -> :blocked
      true -> :public
    end
  end

  defp classify({0, 0, 0, 0, 0, 65535, a, b}) do
    classify_embedded_v4(a, b)
  end

  # Deprecated IPv4-compatible literals are still interpreted as IPv4 destinations by
  # some socket stacks. Classify the embedded address instead of treating `::127.0.0.1`
  # as an otherwise-public IPv6 literal.
  defp classify({0, 0, 0, 0, 0, 0, a, b}) do
    classify_embedded_v4(a, b)
  end

  # The well-known NAT64 prefix carries the IPv4 destination in its final 32 bits. A
  # private or metadata address does not become public merely because a translator gave
  # it IPv6 syntax.
  defp classify({0x64, 0xFF9B, 0, 0, 0, 0, a, b}) do
    classify_embedded_v4(a, b)
  end

  defp classify(address) when tuple_size(address) == 8 do
    {a, b, _c, _d, _e, _f, _g, _h} = address

    cond do
      # Public IPv6 unicast is allocated from 2000::/3. Refusing everything outside the
      # range also covers unspecified, link/site-local, unique-local, multicast, discard,
      # local NAT64, and future special-use blocks fail-closed.
      a not in 0x2000..0x3FFF -> :blocked
      # IETF protocol assignments include Teredo and benchmarking space. A few narrow
      # anycast exceptions are globally reachable, but none is a useful web origin; the
      # conservative /23 keeps tunnel-embedded and non-global destinations closed.
      a == 0x2001 and b in 0x0000..0x01FF -> :blocked
      a == 0x2001 and b == 0x0DB8 -> :blocked
      # 6to4 embeds an IPv4 address and has no stable global-reachability guarantee.
      a == 0x2002 -> :blocked
      # RFC 9637 documentation space, 3fff::/20.
      a == 0x3FFF and b in 0x0000..0x0FFF -> :blocked
      true -> :public
    end
  end

  defp classify(_other), do: :blocked

  defp blocked_v4?({10, _, _, _}), do: true
  defp blocked_v4?({169, 254, _, _}), do: true
  defp blocked_v4?({172, second, _, _}) when second in 16..31, do: true
  defp blocked_v4?({192, 0, 0, last}) when last in [9, 10], do: false
  defp blocked_v4?({192, 0, 0, _}), do: true
  defp blocked_v4?({192, 168, _, _}), do: true
  defp blocked_v4?({192, 0, 2, _}), do: true
  defp blocked_v4?({192, 88, 99, _}), do: true
  defp blocked_v4?({198, second, _, _}) when second in 18..19, do: true
  defp blocked_v4?({198, 51, 100, _}), do: true
  defp blocked_v4?({203, 0, 113, _}), do: true
  defp blocked_v4?({100, second, _, _}) when second in 64..127, do: true
  defp blocked_v4?({first, _, _, _}) when first >= 224, do: true
  defp blocked_v4?(_addr), do: false

  defp classify_embedded_v4(a, b) do
    <<w::8, x::8, y::8, z::8>> = <<a::16, b::16>>
    classify({w, x, y, z})
  end

  defp format_address({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

  defp format_address(address) when tuple_size(address) == 8 do
    address
    |> Tuple.to_list()
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.join(":")
  end

  defp format_address(other), do: inspect(other)
end
