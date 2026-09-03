defmodule Ouroboros.Wasm.Codec do
  @moduledoc """
  Newline-delimited JSON-RPC 2.0 framing for the `ouro-wasm` helper's stdio transport.

  The third copy of this shape in the repo, after `Ouroboros.Provider.Native.Mcp.Codec` and
  `Ouroboros.Provider.Native.Desktop.Codec`, and separate for the reason those two are
  separate from each other: the bounds are per-pipe. This one's ceiling is the helper's own
  read-bounded 8 MiB frame cap (`tui/wasm/src/codec.rs`), so a frame this side refuses is
  one the other side would never have written — a property that stops being true the moment
  two pipes share a module and one of them changes its cap.

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

  # A `\r` from a stdio wrapper that emits `\r\n` is not part of the JSON.
  defp blank?(line), do: String.trim(line) == ""

  # `\n` is the frame delimiter, so the encoder must not produce one inside a message.
  # `JSON.encode_to_iodata!/1` escapes control characters, so this is one line, not a
  # scrubber.
  defp frame(message), do: [JSON.encode_to_iodata!(message), ?\n]
end
