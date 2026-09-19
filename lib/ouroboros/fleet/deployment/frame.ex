defmodule Ouroboros.Fleet.Deployment.Frame do
  @moduledoc """
  The NDJSON the deployment port program speaks on its own stdio (§8).

  One JSON object per line, at most #{div(1024 * 1024, 1024)} KiB including the newline, in
  both directions.

  Out of the program, one per line:

      {"event":"state","state":"running|waiting|completed|failed|cancelled"}
      {"event":"step","step":"install","state":"ok","detail":"…"}
      {"event":"log","line":"…"}
      {"event":"challenge","challenge":"<id>","kind":"host_trust|password|passphrase|review",
       "expires_at":"…","metadata":{…}}
      {"event":"done","state":"completed|failed|cancelled","summary":"…"}

  In:

      {"op":"respond","challenge":"<id>","accept":true|false}
      {"op":"respond","challenge":"<id>","secret":"…"}
      {"op":"cancel"}

  ## No envelope version, and why that is not a regression

  The socket protocol this replaces carried `{"v":1,…}` on every frame and refused anything
  else. §8's frames carry no version, because there is no handshake to negotiate one over:
  the program is the runtime's own `ouro`, found at the absolute path the launcher exported,
  and a mismatch between the two is a mismatched *installation* rather than a peer speaking
  an older protocol. A `v` that is present and is not 1 is still refused — an older `ouro`
  that stamps one is named rather than half-read — and its absence is the ordinary case.

  The cap is enforced here and again by the port itself (`{:line, 1_048_576}`), which is the
  one that matters: a program that writes a gigabyte without a newline must not be able to
  make this runtime buffer it before anybody looks at the length. A line that arrives
  without its newline is a fragment, and a fragment is refused rather than measured.
  """

  @max_bytes 1024 * 1024

  @doc "The frame cap, in bytes, newline included."
  @spec max_bytes() :: pos_integer()
  def max_bytes, do: @max_bytes

  @doc """
  Encodes one frame as a line.

  Refuses rather than truncates: a frame this runtime cannot send whole is a frame the
  program would read as a different frame.
  """
  @spec encode(map()) :: {:ok, iodata()} | {:error, {:frame_too_large, pos_integer()}}
  def encode(frame) when is_map(frame) do
    line = [JSON.encode_to_iodata!(frame), ?\n]
    size = IO.iodata_length(line)

    if size > @max_bytes, do: {:error, {:frame_too_large, size}}, else: {:ok, line}
  end

  @doc """
  Decodes one line into a frame.

  Every failure is named, because they mean different things to an operator: a line over the
  cap is a program this build refuses to read, a line that is not JSON is a program writing
  something else to its stdout, a JSON value that is not an object is a protocol mismatch,
  and a `v` this build does not speak is an `ouro` that does not match this runtime.
  """
  @spec decode(binary()) ::
          {:ok, map()}
          | {:error,
             {:frame_too_large, pos_integer()}
             | :frame_not_json
             | :frame_not_object
             | :frame_version}
  def decode(line) when is_binary(line) do
    # The cap is the whole line, newline included, on both sides of this module: `encode/1`
    # measures `[json, ?\n]`, and the port hands a line over with the newline already
    # removed. So the byte it removed is added back before the measurement rather than
    # quietly forgiven — a body of exactly the cap is a line of one byte more than it.
    body = String.trim_trailing(line, "\n")
    size = byte_size(body) + 1

    if size > @max_bytes, do: {:error, {:frame_too_large, size}}, else: decode_body(body)
  end

  defp decode_body(body) do
    case JSON.decode(body) do
      {:ok, %{"v" => 1} = frame} -> {:ok, frame}
      {:ok, %{"v" => _other}} -> {:error, :frame_version}
      {:ok, frame} when is_map(frame) -> {:ok, frame}
      {:ok, _other} -> {:error, :frame_not_object}
      {:error, _reason} -> {:error, :frame_not_json}
    end
  end

  @doc """
  The name of an out-frame, as one of the five §8 fixes, or `nil` for anything else.

  Told apart by shape rather than by order: every frame the program writes names the event
  it is, so nothing has to be inferred from what came before it.
  """
  @spec event(map()) :: String.t() | nil
  def event(%{"event" => event}) when event in ~w(state step log challenge done), do: event
  def event(_frame), do: nil
end
