defmodule Ouroboros.Transport.JsonLines do
  @moduledoc """
  Bounded incremental JSON-line decoder. The caller supplies its own per-pipe limit
  and owns the incomplete suffix and noise budget. Only JSON objects are frames.
  """
  @spec decode(binary(), pos_integer()) ::
          {:ok, [map()], non_neg_integer(), binary()} | {:error, term()}
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

  # `\r\n` is not MCP framing, but a server built on a Windows-flavoured stdio wrapper
  # emits it and the trailing carriage return is not part of the JSON.
  defp blank?(line), do: String.trim(line) == ""
end
