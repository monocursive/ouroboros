defmodule Ouroboros.Provider.Native.Mcp.Result do
  @moduledoc """
  Turns one `tools/call` result into the shape the native loop already carries.

  MCP answers with a list of content blocks and an `isError` flag. The loop's tool
  result is a string and a boolean. This module is the whole of that translation, and
  every rule in it exists because a server on the other end of a pipe wrote the bytes:

    * **Text is text.** `structuredContent` is appended as JSON when it is present,
      because a server that returns both means both, and dropping half of an answer is
      the kind of silent loss this runtime does not do.
    * **Binary is described, never inlined.** An image or an audio block becomes
      `[image, image/png, 41 kB]`. Base64 in a tool result is a context window spent on
      bytes no model in this loop can look at, and a 2 MB screenshot pasted into a
      conversation is how a session runs out of window in one call.
    * **`isError: true` is an error result, not a failure.** The model sees it, in band,
      exactly like a failed `bash` — that is what tool errors are for.
    * **Everything is capped, visibly.** Past `max_result_bytes` the output ends with
      `… +N bytes` and the count is real. Truncating without saying so teaches a model
      that a truncated answer is a complete one.
  """

  alias Ouroboros.Provider.Native.Mcp.Config

  @doc """
  Renders one MCP `tools/call` result.

  `opts` accepts `:max_result_bytes`, which tests set and which otherwise comes from
  `Ouroboros.Provider.Native.Mcp.Config`.
  """
  @spec render(map(), keyword()) :: %{output: String.t(), is_error: boolean()}
  def render(%{} = result, opts \\ []) do
    limit = Keyword.get(opts, :max_result_bytes) || Config.get(:max_result_bytes)

    body =
      [content(Map.get(result, "content")), structured(Map.get(result, "structuredContent"))]
      |> Enum.reject(&(&1 == ""))
      |> Enum.join("\n")

    %{output: cap(body, limit), is_error: Map.get(result, "isError") == true}
  end

  @doc "How an error from the transport or the server reads to the model."
  @spec describe_error(term()) :: String.t()
  def describe_error(:timeout), do: "the server did not answer before the call timeout"
  def describe_error(:busy), do: "the server has too many requests in flight"
  def describe_error(:not_ready), do: "the server has not finished its handshake yet"
  def describe_error(:broken), do: "the server failed to start repeatedly and is disabled"

  def describe_error(:restarting),
    do: "the server died and is inside its restart backoff; try again in a moment"

  def describe_error(:too_many_servers),
    do: "this node is already running the most MCP servers it allows"

  def describe_error(:shutting_down), do: "the server is shutting down"

  def describe_error({:rpc_error, code, message}) when is_binary(message),
    do: "the server refused the call (JSON-RPC #{inspect(code)}): #{message}"

  def describe_error({:rpc_error, code, _message}),
    do: "the server refused the call (JSON-RPC #{inspect(code)})"

  def describe_error({:server_exited, status}),
    do: "the server exited (status #{inspect(status)}) while the call was in flight"

  def describe_error({:server_unavailable, _reason}),
    do: "the server process died while the call was in flight"

  def describe_error({:transport_closed, _reason}),
    do: "the server closed its pipe while the call was in flight"

  def describe_error(:handshake_timeout),
    do: "the server did not finish its handshake before the deadline"

  def describe_error({:malformed_result, detail}),
    do: "the server answered with something that is not an MCP result: #{detail}"

  def describe_error({:unknown_server, name, []}),
    do: "no MCP server named `#{name}` is configured for this workspace, and none is"

  def describe_error({:unknown_server, name, available}),
    do:
      "no MCP server named `#{name}` is configured for this workspace. " <>
        "Available: #{Enum.join(available, ", ")}."

  def describe_error({:unknown_tool, server, name, []}),
    do: "the MCP server `#{server}` advertises no tool named `#{name}`, and no tools at all"

  def describe_error({:unknown_tool, server, name, available}),
    do:
      "the MCP server `#{server}` advertises no tool named `#{name}`. " <>
        "Available: #{Enum.join(available, ", ")}."

  def describe_error({:unsupported_transport, name}),
    do: "the MCP server `#{name}` is configured for HTTP/SSE; this client speaks stdio only"

  def describe_error({:invalid_name, name}),
    do: "`#{name}` is not a `mcp__<server>__<tool>` name"

  def describe_error({:invalid_arguments, detail}),
    do: "the arguments are not an object: #{detail}"

  def describe_error(:disabled), do: "MCP servers are disabled on this node"
  def describe_error(:pool_unavailable), do: "this node is not running the MCP subtree"

  def describe_error({:pool_unavailable, _reason}),
    do: "this node is not running the MCP subtree"

  def describe_error(reason), do: inspect(reason, limit: 10)

  ## Content blocks

  defp content(blocks) when is_list(blocks) do
    blocks
    |> Enum.map(&block/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n")
  end

  defp content(_absent), do: ""

  defp block(%{"type" => "text", "text" => text}) when is_binary(text), do: text

  defp block(%{"type" => type, "data" => data, "mimeType" => mime})
       when type in ["image", "audio"] and is_binary(data),
       do: "[#{type}, #{safe(mime)}, #{byte_size(data)} base64 bytes]"

  defp block(%{"type" => "resource_link"} = block) do
    "[resource #{safe(Map.get(block, "uri"))}#{name_suffix(block)}]"
  end

  defp block(%{"type" => "resource", "resource" => %{} = resource}) do
    case Map.get(resource, "text") do
      text when is_binary(text) -> "[resource #{safe(Map.get(resource, "uri"))}]\n#{text}"
      _binary -> "[resource #{safe(Map.get(resource, "uri"))}, not text]"
    end
  end

  # A block kind this client has never heard of is named, not dropped. The MCP spec adds
  # them; a session that says "the server returned something I cannot render" is honest,
  # and a session that returns an empty string for it is not.
  defp block(%{"type" => type}) when is_binary(type), do: "[#{safe(type)} content]"
  defp block(_block), do: ""

  defp name_suffix(block) do
    case Map.get(block, "name") do
      name when is_binary(name) and name != "" -> " (#{safe(name)})"
      _absent -> ""
    end
  end

  defp structured(nil), do: ""

  # A value a JSON encoder refuses is a value that never came off the wire as JSON, so
  # it cannot happen — and if it somehow does, dropping the line is better than failing
  # a tool result the model was going to read.
  defp structured(value) do
    "structuredContent: " <> JSON.encode!(value)
  rescue
    _unencodable -> ""
  end

  defp safe(value) when is_binary(value) and byte_size(value) <= 200, do: value
  defp safe(value) when is_binary(value), do: binary_part(value, 0, 200) <> "…"
  defp safe(_value), do: "unknown"

  defp cap("", _limit), do: "(the server returned no content)"
  defp cap(body, limit) when byte_size(body) <= limit, do: body

  defp cap(body, limit) do
    dropped = byte_size(body) - limit

    body
    |> binary_part(0, limit)
    |> valid_prefix()
    |> Kernel.<>("\n… +#{dropped} bytes (MCP result truncated at #{limit} bytes)")
  end

  defp valid_prefix(<<>>), do: <<>>

  defp valid_prefix(binary) do
    if String.valid?(binary),
      do: binary,
      else: binary |> binary_part(0, byte_size(binary) - 1) |> valid_prefix()
  end
end
