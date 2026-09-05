defmodule Ouroboros.Wasm.Codec do
  @moduledoc """
  Newline-delimited JSON-RPC 2.0 framing for the `ouro-wasm` helper's stdio transport.

  Framing is shared with MCP and Desktop; the owning pool supplies this pipe's limit
  independently of those transports. The helper's own frame cap is 8 MiB.

  `decode/2` is incremental. A line longer than `max_frame_bytes` is an error rather than a
  buffered read, an unterminated remainder past that same bound is an error rather than a
  growing buffer, and a complete line that is not a JSON object is counted as noise and
  skipped, so the owning `Ouroboros.Wasm.Pool` can stop a helper that has started writing to
  stdout instead of hanging on it.

  The cap bounds the **wire**, not the heap. It caps the raw bytes read off the pipe before a
  line completes; it does not cap the term those bytes decode to. A within-cap frame of
  deeply nested JSON can drive `JSON.decode/1` to allocate far more than its own size, so a
  hostile helper still has a heap-amplification lever here — one the pool answers separately
  with a soft `max_heap_size` ceiling on its own process, not one this cap closes.
  """

  @type frame :: map()

  @doc "Encodes a JSON-RPC request frame with an id."
  @spec request(term(), String.t(), map()) :: iodata()
  def request(id, method, params) when is_binary(method) and is_map(params) do
    frame(%{"jsonrpc" => "2.0", "id" => id, "method" => method, "params" => params})
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

  # `\n` is the frame delimiter, so the encoder must not produce one inside a message.
  # `JSON.encode_to_iodata!/1` escapes control characters, so this is one line, not a
  # scrubber.
  defp frame(message), do: [JSON.encode_to_iodata!(message), ?\n]
end
