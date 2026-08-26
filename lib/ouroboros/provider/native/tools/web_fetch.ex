defmodule Ouroboros.Provider.Native.Tools.WebFetch do
  @moduledoc """
  Fetch one HTTP(S) URL and hand the model its text.

  This is the only tool in the set that reaches off the machine, so its refusals are
  narrower than everything else's and all of them are structural rather than advisory:

    * **GET only, `http` or `https` only.** No other method and no other scheme, so the
      tool cannot be turned into a `POST` of the workspace to somewhere.
    * **No redirect off the host that was permitted.** `:httpc` is called with
      `autoredirect: false` and this module follows a `3xx` only while the host is
      unchanged, at most #{3} times. A redirect that crosses hosts is reported with the
      new URL and *not* followed: the new host was never evaluated by the permission
      engine, and following it would turn one allowed domain into an open proxy. The
      model can call the tool again with that URL and be gated on it properly. This is
      Claude Code's own stated reason for preferring `WebFetch(domain:)` over
      argument-constrained `Bash` rules (R3 §8d).
    * **Public destinations only.** The host is resolved and refused when any address
      is loopback, link-local, RFC1918, CGNAT, multicast, documentation space, or
      IPv6 unique-local; `localhost`, `*.local`, and cloud metadata names are refused
      before lookup. Domain rules still match the hostname; this is the address gate
      those rules cannot see. Residual DNS-rebinding between this lookup and
      `:httpc`'s own connect is documented on `WebFetch.Target`.
    * **One mebibyte, fifteen seconds.** The body is read with a cap and the request
      with a deadline; both are stated in the result when they bite.

  The permission evaluation happens in `Ouroboros.Provider.Native.Loop`'s gate, before
  this module runs at all, because `Ouroboros.Provider.Native.Tools.classify/3` reports
  `mode: :network` and the URL's host as the request's `domains` — which is what makes
  a `WebFetch(domain:docs.example.com)` rule mean something. This module re-parses the
  URL and refuses anything the classifier could not read, so a URL that reached the
  engine as unparseable cannot become a request here.

  HTML becomes text through a bounded stripper: `script` and `style` bodies are dropped
  whole, tags are removed, the five named entities and numeric references are decoded,
  and whitespace is collapsed. It is not a renderer and does not pretend to be one — the
  result says the page was converted, so a model reading a mangled table knows why.
  """

  use Jido.Action,
    name: "web_fetch",
    description:
      "Fetch an http(s) URL with GET and return its text. HTML is converted to text. " <>
        "Bounded to 1 MiB and 15 seconds; redirects to another host are reported, not " <>
        "followed. Loopback, private, link-local, and metadata destinations are refused.",
    schema: [
      url: [type: :string, required: true, doc: "The absolute http:// or https:// URL to fetch."],
      max_bytes: [
        type: :pos_integer,
        default: 1_048_576,
        doc: "Stop reading after this many bytes. Maximum 1048576."
      ]
    ]

  @max_bytes 1024 * 1024
  @timeout_ms 15_000
  @max_redirects 3
  @max_text_bytes 100 * 1024

  alias Ouroboros.Provider.Native.Tools.WebFetch.Target

  @impl true
  def run(params, context) do
    with {:ok, uri} <- parse(params.url),
         {:ok, response} <-
           fetch(uri, min(params.max_bytes, @max_bytes), @max_redirects, context) do
      {:ok, present(response)}
    else
      {:error, {:http_status, _url, _status, _phrase, _body} = reason} ->
        {:ok, %{output: describe(reason), is_error: true}}

      {:error, reason} ->
        {:ok, %{output: "web_fetch failed: #{describe(reason)}", is_error: true}}
    end
  end

  @doc """
  The host a URL names, for the permission engine's `domains`.

  `nil` for anything this tool would refuse anyway. A request whose domain cannot be
  named cannot be matched by a `WebFetch(domain:…)` rule, and the engine must see that
  rather than an empty list that reads as "no network involved".
  """
  @spec host(term()) :: String.t() | nil
  def host(url) when is_binary(url) do
    case parse(url) do
      {:ok, %URI{host: host}} -> host
      {:error, _reason} -> nil
    end
  end

  def host(_url), do: nil

  # ---------------------------------------------------------------- request

  defp parse(url) when is_binary(url) do
    case URI.parse(String.trim(url)) do
      %URI{scheme: scheme, host: host} = uri
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        {:ok, uri}

      %URI{scheme: scheme} when scheme in ["http", "https"] ->
        {:error, {:no_host, url}}

      %URI{scheme: nil} ->
        {:error, {:not_absolute, url}}

      %URI{scheme: scheme} ->
        {:error, {:bad_scheme, scheme}}
    end
  end

  defp parse(url), do: {:error, {:not_absolute, inspect(url)}}

  defp fetch(_uri, _max_bytes, 0, _context), do: {:error, :too_many_redirects}

  defp fetch(%URI{} = uri, max_bytes, remaining, context) do
    with :ok <- Target.admit(uri, context) do
      request_uri(uri, max_bytes, remaining, context)
    end
  end

  defp request_uri(%URI{} = uri, max_bytes, remaining, context) do
    request = {String.to_charlist(URI.to_string(uri)), [{~c"user-agent", ~c"ouroboros-native"}]}

    http_options = [
      timeout: @timeout_ms,
      connect_timeout: @timeout_ms,
      autoredirect: false,
      ssl: ssl_options(uri.host)
    ]

    case :httpc.request(:get, request, http_options, body_format: :binary) do
      {:ok, {{_version, status, _phrase}, headers, body}} when status in 200..299 ->
        {:ok,
         %{
           url: URI.to_string(uri),
           status: status,
           content_type: header(headers, "content-type"),
           body: clamp(body, max_bytes),
           truncated?: byte_size(body) > max_bytes
         }}

      {:ok, {{_version, status, _phrase}, headers, _body}} when status in 300..399 ->
        redirect(uri, header(headers, "location"), max_bytes, remaining, context)

      {:ok, {{_version, status, phrase}, _headers, body}} ->
        {:error,
         {:http_status, URI.to_string(uri), status, to_string(phrase), clamp(body, 2_000)}}

      {:error, reason} ->
        {:error, {:request_failed, reason}}
    end
  rescue
    error -> {:error, {:request_failed, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:request_failed, reason}}
  end

  defp redirect(_uri, nil, _max_bytes, _remaining, _context),
    do: {:error, :redirect_without_location}

  defp redirect(uri, location, max_bytes, remaining, context) do
    target = URI.merge(uri, location)

    cond do
      target.scheme not in ["http", "https"] ->
        {:error, {:redirect_off_scheme, URI.to_string(target)}}

      target.host != uri.host ->
        {:error, {:redirect_off_host, uri.host, URI.to_string(target)}}

      true ->
        fetch(target, max_bytes, remaining - 1, context)
    end
  rescue
    _error -> {:error, :redirect_without_location}
  end

  # Certificate verification is on and the CA bundle is the host's own. `:httpc`'s
  # default is `verify_none`, which would make `https` decorative.
  defp ssl_options(host) do
    [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      depth: 3,
      server_name_indication: String.to_charlist(host),
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ]
    ]
  rescue
    # A host with no usable trust store is a refusal, not a downgrade to no verification.
    _error -> [verify: :verify_peer, cacerts: []]
  end

  defp header(headers, name) do
    Enum.find_value(headers, fn {key, value} ->
      if to_string(key) |> String.downcase() == name, do: to_string(value)
    end)
  end

  defp clamp(body, max_bytes) when is_binary(body) do
    if byte_size(body) > max_bytes, do: binary_part(body, 0, max_bytes), else: body
  end

  defp clamp(body, _max_bytes), do: to_string(body)

  # ---------------------------------------------------------------- present

  defp present(response) do
    {text, converted?} = to_text(response.body, response.content_type)
    {shown, clipped?} = clip(text)

    notes =
      []
      |> then(&if converted?, do: ["HTML converted to text" | &1], else: &1)
      |> then(&if response.truncated?, do: ["body truncated at the byte cap" | &1], else: &1)
      |> then(&if clipped?, do: ["text clipped at #{@max_text_bytes} bytes" | &1], else: &1)

    note = if notes == [], do: "", else: "\n(" <> Enum.join(Enum.reverse(notes), "; ") <> ")"

    %{
      output:
        "#{response.url} — HTTP #{response.status}" <>
          content_type_note(response.content_type) <> "\n\n" <> shown <> note,
      is_error: false
    }
  end

  defp content_type_note(nil), do: ""
  defp content_type_note(type), do: ", #{type |> String.split(";") |> hd() |> String.trim()}"

  defp to_text(body, content_type) do
    cond do
      not String.valid?(body) ->
        {"(binary response, #{byte_size(body)} bytes — not shown)", false}

      html?(body, content_type) ->
        {strip_html(body), true}

      true ->
        {body, false}
    end
  end

  defp html?(body, content_type) do
    String.contains?(to_string(content_type), "html") or
      Regex.match?(~r/\A\s*<(!doctype html|html)\b/i, body)
  end

  @doc """
  Turns an HTML document into readable text, bounded and without a parser.

  Public because it is the part with the interesting failure modes and the part the
  tests exercise directly.
  """
  @spec strip_html(binary()) :: binary()
  def strip_html(html) do
    html
    |> String.replace(~r{<script\b[^>]*>.*?</script>}is, " ")
    |> String.replace(~r{<style\b[^>]*>.*?</style>}is, " ")
    |> String.replace(~r{<!--.*?-->}s, " ")
    |> String.replace(~r{<(br|/p|/div|/li|/h[1-6]|/tr)\b[^>]*>}i, "\n")
    |> String.replace(~r{<[^>]*>}, " ")
    |> decode_entities()
    |> String.replace(~r/[ \t\x{00A0}]+/u, " ")
    |> String.replace(~r/\n[ \t]*/, "\n")
    |> String.replace(~r/\n{3,}/, "\n\n")
    |> String.trim()
  end

  defp decode_entities(text) do
    text
    |> String.replace("&lt;", "<")
    |> String.replace("&gt;", ">")
    |> String.replace("&quot;", "\"")
    |> String.replace("&#39;", "'")
    |> String.replace("&nbsp;", " ")
    |> String.replace(~r/&#(\d{1,7});/, fn full ->
      case Regex.run(~r/&#(\d{1,7});/, full) do
        [_all, digits] -> codepoint(String.to_integer(digits), full)
        _none -> full
      end
    end)
    |> String.replace("&amp;", "&")
  end

  defp codepoint(value, _fallback) when value in 0x20..0x10FFFF, do: <<value::utf8>>
  defp codepoint(0x0A, _fallback), do: "\n"
  defp codepoint(0x09, _fallback), do: "\t"
  defp codepoint(_value, fallback), do: fallback

  defp clip(text) when byte_size(text) <= @max_text_bytes, do: {text, false}
  defp clip(text), do: {binary_part(text, 0, @max_text_bytes), true}

  # ---------------------------------------------------------------- refusals

  defp describe({:bad_scheme, scheme}),
    do: "`#{scheme}` is not a scheme this tool fetches. Only http and https."

  defp describe({:not_absolute, url}), do: "#{url} is not an absolute http(s) URL."
  defp describe({:no_host, url}), do: "#{url} names no host."

  defp describe({:redirect_off_host, from, to}),
    do:
      "the response redirected from #{from} to #{to}, which is a different host. " <>
        "It was not followed. Call web_fetch again with #{to} if that host is what you want."

  defp describe({:redirect_off_scheme, to}),
    do: "the response redirected to #{to}, which is not http(s). It was not followed."

  defp describe(:redirect_without_location), do: "the response redirected without a Location."
  defp describe(:too_many_redirects), do: "more than #{@max_redirects} redirects on one host."

  defp describe({:http_status, url, 404, phrase, _body}) do
    "HTTP 404#{phrase_note(phrase)} from #{url}. " <>
      "The server was reached, but no resource exists at that URL. " <>
      "Verify the exact path and version/ref; do not retry the unchanged URL. " <>
      "For dependency source, prefer the locally installed source or the dependency's " <>
      "pinned tag/commit over a moving default branch."
  end

  defp describe({:http_status, url, status, phrase, body}) do
    detail = String.slice(to_string(body), 0, 500) |> String.trim()
    suffix = if detail == "", do: "", else: " #{detail}"
    "HTTP #{status}#{phrase_note(phrase)} from #{url}.#{suffix}"
  end

  defp describe({:request_failed, reason}), do: "the request failed: #{inspect(reason)}"

  defp describe({:blocked_host, host}),
    do:
      "#{host} is a loopback, link-local, or metadata name. web_fetch does not open " <>
        "sockets to those destinations."

  defp describe({:blocked_address, host, address}),
    do:
      "#{host} resolved to #{address}, which is not a public address. web_fetch does " <>
        "not open sockets to loopback, link-local, private, or metadata destinations."

  defp describe({:unresolvable, host}),
    do: "#{host} did not resolve to an address this tool will connect to."

  defp describe(reason), do: inspect(reason)

  defp phrase_note(phrase) do
    case String.trim(to_string(phrase)) do
      "" -> ""
      text -> " #{text}"
    end
  end
end
