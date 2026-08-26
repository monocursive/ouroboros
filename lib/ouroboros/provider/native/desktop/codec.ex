defmodule Ouroboros.Provider.Native.Desktop.Codec do
  @moduledoc """
  Newline-delimited JSON-RPC 2.0 framing for the Computer Use helper's stdio transport.

  The same shape as `Ouroboros.Provider.Native.Mcp.Codec`, deliberately a separate module
  (D5): one message is one line of UTF-8 JSON terminated by `\\n`, and a message may not
  contain an embedded newline. The helper is ours, not a stranger's server, but the pipe
  gets the same two refusals anyway — a child that goes wrong writes bytes exactly like one
  that does not, and the bound is what keeps a confused helper from making this node buffer
  forever.

  `decode/2` is incremental: a line longer than `max_frame_bytes` is an error rather than an
  allocation, an unterminated remainder past that same bound is an error rather than a
  buffer, and a complete line that is not a JSON object is counted as noise and skipped so
  the owning `Ouroboros.Provider.Native.Desktop.Pool` can stop a helper that has started
  logging to stdout instead of hanging on it.
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

  @doc """
  Consumes as many complete lines as `buffer` holds.

  Returns `{:ok, frames, noise, rest}` where `frames` are decoded JSON objects in arrival
  order, `noise` counts the complete lines that were not JSON objects, and `rest` is the
  unterminated remainder to carry into the next chunk.
  """
  @spec decode(binary(), pos_integer()) ::
          {:ok, [frame()], non_neg_integer(), binary()} | {:error, term()}
  def decode(buffer, max_frame_bytes) when is_binary(buffer) do
    consume(buffer, max_frame_bytes, [], 0)
  end

  defp consume(buffer, max_frame_bytes, frames, noise) do
    case :binary.split(buffer, "\n") do
      [rest] ->
        if byte_size(rest) > max_frame_bytes do
          {:error, {:frame_too_large, byte_size(rest), max_frame_bytes}}
        else
          {:ok, Enum.reverse(frames), noise, rest}
        end

      [line, rest] ->
        cond do
          byte_size(line) > max_frame_bytes ->
            {:error, {:frame_too_large, byte_size(line), max_frame_bytes}}

          blank?(line) ->
            consume(rest, max_frame_bytes, frames, noise)

          true ->
            case JSON.decode(line) do
              {:ok, %{} = frame} -> consume(rest, max_frame_bytes, [frame | frames], noise)
              _not_a_message -> consume(rest, max_frame_bytes, frames, noise + 1)
            end
        end
    end
  end

  # A `\r` from a helper built on a stdio wrapper that emits `\r\n` is not part of the JSON.
  defp blank?(line), do: String.trim(line) == ""

  defp put_params(message, nil), do: message
  defp put_params(message, params), do: Map.put(message, "params", params)

  # `\n` is the frame delimiter, so the encoder must not produce one inside a message.
  # `JSON.encode_to_iodata!/1` escapes control characters, so this is one line, not a
  # scrubber.
  defp frame(message), do: [JSON.encode_to_iodata!(message), ?\n]
end
