defmodule Ouroboros.Provider.Native.Mcp.Codec do
  @moduledoc """
  Newline-delimited JSON-RPC 2.0 framing for the MCP stdio transport.

  MCP's stdio transport is not LSP's. There is no `Content-Length` header: one message
  is one line of UTF-8 JSON terminated by `\\n`, and a message may not contain an
  embedded newline. That makes framing trivial and makes the *bound* the whole job — a
  stranger's program writing to a pipe we own can otherwise make this node buffer
  forever simply by never sending a newline.

  So `decode/2` refuses twice. A line longer than `max_frame_bytes` is an error rather
  than an allocation, and an unterminated remainder past that same bound is an error
  rather than a buffer. `decode/2` is incremental and returns the bytes it could not
  use, so the owning process keeps exactly one buffer.

  The spec says a server must write nothing but MCP messages to stdout. Real servers
  sometimes write a banner anyway. A line that is not a JSON object is therefore counted
  as noise and skipped rather than killing the transport — but it is counted, and
  `Ouroboros.Provider.Native.Mcp.Server` stops when the count passes its bound. Skipping
  silently and forever is how a server that has started logging to stdout becomes a
  session that hangs with no explanation.
  """

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
  def response(id, result), do: frame(%{"jsonrpc" => "2.0", "id" => id, "result" => result})

  @doc "Encodes an error response to a server-initiated request this client does not serve."
  @spec error_response(term(), integer(), String.t()) :: iodata()
  def error_response(id, code, message) do
    frame(%{"jsonrpc" => "2.0", "id" => id, "error" => %{"code" => code, "message" => message}})
  end

  @doc """
  Consumes as many complete lines as `buffer` holds.

  Returns `{:ok, frames, noise, rest}` where `frames` are decoded JSON objects in arrival
  order, `noise` counts the complete lines that were not JSON objects, and `rest` is the
  unterminated remainder to carry into the next chunk.
  """
  @spec decode(binary(), pos_integer()) ::
          {:ok, [frame()], non_neg_integer(), binary()} | {:error, term()}
  defdelegate decode(buffer, max_frame_bytes), to: Ouroboros.Transport.JsonLines

  defp put_params(message, nil), do: message
  defp put_params(message, params), do: Map.put(message, "params", params)

  # `\n` is the frame delimiter, so the encoder must not produce one inside a message.
  # `JSON.encode_to_iodata!/1` never does — it escapes control characters — which is
  # why this is a one-line function and not a scrubber.
  defp frame(message), do: [JSON.encode_to_iodata!(message), ?\n]
end
