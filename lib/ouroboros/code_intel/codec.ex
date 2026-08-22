defmodule Ouroboros.CodeIntel.Codec do
  @moduledoc """
  `Content-Length` framing and JSON-RPC 2.0 message construction for the language-server
  transport.

  A language server is a stranger's program reading and writing a byte stream this
  runtime does not control, so every decode here is bounded twice: the header block must
  terminate inside `@max_header_bytes`, and a declared `Content-Length` larger than the
  caller's `max_frame_bytes` is an error rather than an allocation. Neither bound is
  configurable downward past zero and neither is `:infinity`.

  `decode/2` is incremental and returns the bytes it could not use, so the owning process
  keeps exactly one buffer. It rescans the header block of a partially received frame on
  every chunk; that rescan is capped at `@max_header_bytes` rather than the buffer size,
  which is why a multi-megabyte body arriving in small chunks does not become quadratic.
  """

  # A header block that has not terminated within this many bytes is not a header block.
  # Real ones are two short lines; anything larger is a server writing garbage at us, and
  # buffering it forever is how an unbounded mailbox starts.
  @max_header_bytes 8 * 1024

  @type frame :: map()

  @doc "Encodes a JSON-RPC request frame with an id."
  @spec request(term(), String.t(), term()) :: iodata()
  def request(id, method, params) do
    %{"jsonrpc" => "2.0", "id" => id, "method" => method}
    |> put_params(params)
    |> frame()
  end

  @doc "Encodes a JSON-RPC notification frame, which carries no id and gets no answer."
  @spec notification(String.t(), term()) :: iodata()
  def notification(method, params) do
    %{"jsonrpc" => "2.0", "method" => method}
    |> put_params(params)
    |> frame()
  end

  @doc "Encodes a successful response to a server-initiated request."
  @spec response(term(), term()) :: iodata()
  def response(id, result) do
    frame(%{"jsonrpc" => "2.0", "id" => id, "result" => result})
  end

  @doc "Encodes an error response to a server-initiated request this client does not serve."
  @spec error_response(term(), integer(), String.t()) :: iodata()
  def error_response(id, code, message) do
    frame(%{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{"code" => code, "message" => message}
    })
  end

  @doc """
  Consumes as many complete frames as `buffer` holds.

  Returns the decoded frames in arrival order together with the unconsumed remainder.
  A malformed header, an unparseable body, or a frame larger than `max_frame_bytes`
  is an error: the caller's contract is to drop the transport, because a stream whose
  framing is wrong cannot be resynchronised by guessing.
  """
  @spec decode(binary(), pos_integer()) :: {:ok, [frame()], binary()} | {:error, term()}
  def decode(buffer, max_frame_bytes)
      when is_binary(buffer) and is_integer(max_frame_bytes) and max_frame_bytes > 0 do
    decode(buffer, max_frame_bytes, [])
  end

  defp decode(buffer, max_frame_bytes, acc) do
    case split_headers(buffer) do
      :incomplete ->
        {:ok, Enum.reverse(acc), buffer}

      {:error, reason} ->
        {:error, reason}

      {:ok, headers, body} ->
        with {:ok, length} <- content_length(headers) do
          cond do
            length > max_frame_bytes ->
              {:error, {:frame_too_large, length, max_frame_bytes}}

            byte_size(body) < length ->
              {:ok, Enum.reverse(acc), buffer}

            true ->
              <<payload::binary-size(^length), rest::binary>> = body

              case JSON.decode(payload) do
                {:ok, frame} when is_map(frame) -> decode(rest, max_frame_bytes, [frame | acc])
                {:ok, other} -> {:error, {:unexpected_frame, other}}
                {:error, reason} -> {:error, {:invalid_json, reason}}
              end
          end
        end
    end
  end

  # Servers in the wild terminate the header block with CRLFCRLF; a handful use bare
  # LFLF. Both are accepted, and the scan is confined to the first `@max_header_bytes`
  # so a large pending body is never rescanned.
  defp split_headers(buffer) do
    window_size = min(byte_size(buffer), @max_header_bytes)
    window = binary_part(buffer, 0, window_size)

    case :binary.match(window, ["\r\n\r\n", "\n\n"]) do
      {offset, length} ->
        headers = binary_part(buffer, 0, offset)
        body = binary_part(buffer, offset + length, byte_size(buffer) - offset - length)
        {:ok, headers, body}

      :nomatch when window_size >= @max_header_bytes ->
        {:error, {:header_too_large, @max_header_bytes}}

      :nomatch ->
        :incomplete
    end
  end

  defp content_length(headers) do
    headers
    |> String.split(["\r\n", "\n"], trim: true)
    |> Enum.find_value(:missing, fn line ->
      case String.split(line, ":", parts: 2) do
        [name, value] ->
          if String.downcase(String.trim(name)) == "content-length" do
            case Integer.parse(String.trim(value)) do
              {length, ""} when length >= 0 -> {:ok, length}
              _other -> {:error, {:invalid_content_length, line}}
            end
          end

        _other ->
          nil
      end
    end)
    |> case do
      :missing -> {:error, {:missing_content_length, headers}}
      result -> result
    end
  end

  defp put_params(frame, nil), do: frame
  defp put_params(frame, params), do: Map.put(frame, "params", params)

  defp frame(message) do
    body = JSON.encode_to_iodata!(message)
    ["Content-Length: ", Integer.to_string(:erlang.iolist_size(body)), "\r\n\r\n", body]
  end
end
