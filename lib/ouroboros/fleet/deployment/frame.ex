defmodule Ouroboros.Fleet.Deployment.Frame do
  @moduledoc """
  The NDJSON envelope the broker and the deployment worker speak (seams C3/S3).

  One JSON object per line, at most #{div(1024 * 1024, 1024)} KiB including the newline, in
  both directions. A request carries `{"v":1,"id":…,"op":…}`; a reply carries the same `id`
  with `ok` true or false and, when false, a stable snake_case `reason`; an unsolicited
  worker frame carries `event` instead of `id`.

  The cap is enforced on both sides of this module and again by the socket itself
  (`packet_size`), which is the one that matters: a peer that writes a gigabyte must not be
  able to make this runtime buffer it before anybody looks at the length.
  """

  @max_bytes 1024 * 1024

  @doc "The frame cap, in bytes, newline included."
  @spec max_bytes() :: pos_integer()
  def max_bytes, do: @max_bytes

  @doc """
  Encodes one frame as a line.

  Refuses rather than truncates: a frame this runtime cannot send whole is a frame the
  worker would read as a different frame.
  """
  @spec encode(map()) :: {:ok, iodata()} | {:error, {:frame_too_large, pos_integer()}}
  def encode(frame) when is_map(frame) do
    line = [JSON.encode_to_iodata!(frame), ?\n]
    size = IO.iodata_length(line)

    if size > @max_bytes, do: {:error, {:frame_too_large, size}}, else: {:ok, line}
  end

  @doc """
  Decodes one line into a frame.

  Every failure is named, because the four of them mean different things to an operator: a
  line over the cap is a worker this build refuses to read, a line that is not JSON is a
  worker writing something else to its socket, a JSON value that is not an object is a
  protocol mismatch, and a missing or wrong `v` is a version this build does not speak.
  """
  @spec decode(binary()) ::
          {:ok, map()}
          | {:error,
             {:frame_too_large, pos_integer()}
             | :frame_not_json
             | :frame_not_object
             | :frame_version}
  def decode(line) when is_binary(line) do
    if byte_size(line) > @max_bytes do
      {:error, {:frame_too_large, byte_size(line)}}
    else
      line |> String.trim_trailing("\n") |> decode_body()
    end
  end

  defp decode_body(body) do
    case JSON.decode(body) do
      {:ok, %{"v" => 1} = frame} -> {:ok, frame}
      {:ok, frame} when is_map(frame) -> {:error, :frame_version}
      {:ok, _other} -> {:error, :frame_not_object}
      {:error, _reason} -> {:error, :frame_not_json}
    end
  end

  @doc """
  Whether a decoded frame is an unsolicited worker event rather than a reply.

  The two are told apart by shape rather than by order: a reply names the `id` it answers
  and an event names the `event` it is, so an event that arrives between a request and its
  reply is not mistaken for that reply.
  """
  @spec event?(map()) :: boolean()
  def event?(%{"event" => event}) when is_binary(event), do: true
  def event?(_frame), do: false
end
