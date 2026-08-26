defmodule Ouroboros.Provider.Native.Tools.WebFetch.Target do
  @moduledoc """
  Whether a URL's host is one `web_fetch` will open a socket to.

  Domain rules match the hostname the model typed. They do not see the addresses
  that name resolves to, so a permitted `example.com` that rebinds to `169.254.169.254`
  — or a literal `http://127.0.0.1/` — would otherwise reach loopback, RFC1918, and
  cloud metadata. This module refuses those destinations after a DNS lookup and
  before `:httpc` runs.

  The residual window is DNS rebinding between this lookup and the connect
  `:httpc` does itself. Pinning the connect to the admitted address is not available
  on `:httpc` without dropping TLS hostname verification; the lookup is still the
  difference between "we never checked" and "we checked once".
  """

  @blocked_hosts MapSet.new([
                   "localhost",
                   "localhost.localdomain",
                   "metadata.google.internal",
                   "metadata.google.com"
                 ])

  @doc """
  Refuses a URI whose host is blocked by name or whose every resolved address is
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

  defp classify({0, 0, 0, 0, 0, 0, 0, 0}), do: :loopback
  defp classify({0, 0, 0, 0, 0, 0, 0, 1}), do: :loopback

  defp classify({0, 0, 0, 0, 0, 65535, a, b}) do
    <<w::8, x::8, y::8, z::8>> = <<a::16, b::16>>
    classify({w, x, y, z})
  end

  defp classify(address) when tuple_size(address) == 8 do
    {a, b, _c, _d, _e, _f, _g, _h} = address

    cond do
      a in 0xFE80..0xFEBF -> :blocked
      a in 0xFC00..0xFDFF -> :blocked
      a >= 0xFF00 -> :blocked
      a == 0x2001 and b == 0xDB8 -> :blocked
      true -> :public
    end
  end

  defp classify(_other), do: :blocked

  defp blocked_v4?({10, _, _, _}), do: true
  defp blocked_v4?({169, 254, _, _}), do: true
  defp blocked_v4?({172, second, _, _}) when second in 16..31, do: true
  defp blocked_v4?({192, 168, _, _}), do: true
  defp blocked_v4?({192, 0, 2, _}), do: true
  defp blocked_v4?({198, 51, 100, _}), do: true
  defp blocked_v4?({203, 0, 113, _}), do: true
  defp blocked_v4?({100, second, _, _}) when second in 64..127, do: true
  defp blocked_v4?({first, _, _, _}) when first >= 224, do: true
  defp blocked_v4?(_addr), do: false

  defp format_address({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

  defp format_address(address) when tuple_size(address) == 8 do
    address
    |> Tuple.to_list()
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.join(":")
  end

  defp format_address(other), do: inspect(other)
end
