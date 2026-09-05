defmodule Ouroboros.Provider.Native.Desktop.Codec do
  @moduledoc """
  Newline-delimited JSON-RPC 2.0 framing for the Computer Use helper's stdio transport.

  Framing is shared with MCP and WASM, while this pool owns its limits and noise budget.

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
  defdelegate decode(buffer, max_frame_bytes), to: Ouroboros.Transport.JsonLines

  defp put_params(message, nil), do: message
  defp put_params(message, params), do: Map.put(message, "params", params)

  # `\n` is the frame delimiter, so the encoder must not produce one inside a message.
  # `JSON.encode_to_iodata!/1` escapes control characters, so this is one line, not a
  # scrubber.
  defp frame(message), do: [JSON.encode_to_iodata!(message), ?\n]
end
