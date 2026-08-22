defmodule Ouroboros.CodeIntel.CodecTest do
  use ExUnit.Case, async: true

  alias Ouroboros.CodeIntel.Codec

  @max 1_024 * 1_024

  defp bytes(iodata), do: IO.iodata_to_binary(iodata)

  test "a request frame carries an id, a method, and a byte-accurate Content-Length" do
    frame = bytes(Codec.request(7, "textDocument/hover", %{"a" => 1}))
    assert {:ok, [decoded], <<>>} = Codec.decode(frame, @max)

    assert decoded == %{
             "jsonrpc" => "2.0",
             "id" => 7,
             "method" => "textDocument/hover",
             "params" => %{"a" => 1}
           }

    ["Content-Length: " <> length, body] = String.split(frame, "\r\n\r\n", parts: 2)
    assert String.to_integer(length) == byte_size(body)
  end

  test "a notification frame carries no id and omits absent params" do
    assert {:ok, [decoded], <<>>} = Codec.decode(bytes(Codec.notification("exit", nil)), @max)
    assert decoded == %{"jsonrpc" => "2.0", "method" => "exit"}
    refute Map.has_key?(decoded, "id")
  end

  test "responses and error responses round-trip" do
    assert {:ok, [%{"id" => 1, "result" => nil}], <<>>} =
             Codec.decode(bytes(Codec.response(1, nil)), @max)

    assert {:ok, [%{"error" => %{"code" => -32_601, "message" => "no"}}], <<>>} =
             Codec.decode(bytes(Codec.error_response(1, -32_601, "no")), @max)
  end

  test "several frames in one chunk decode in arrival order" do
    stream =
      bytes([Codec.request(1, "a", nil), Codec.request(2, "b", nil), Codec.request(3, "c", nil)])

    assert {:ok, frames, <<>>} = Codec.decode(stream, @max)
    assert Enum.map(frames, & &1["id"]) == [1, 2, 3]
  end

  test "a frame split across arbitrary chunk boundaries reassembles" do
    stream =
      bytes(Codec.request(42, "textDocument/definition", %{"deep" => %{"nested" => [1, 2, 3]}}))

    {frames, rest} =
      stream
      |> :binary.bin_to_list()
      |> Enum.reduce({[], <<>>}, fn byte, {frames, buffer} ->
        assert {:ok, new, rest} = Codec.decode(buffer <> <<byte>>, @max)
        {frames ++ new, rest}
      end)

    assert rest == <<>>
    assert [%{"id" => 42, "method" => "textDocument/definition"}] = frames
  end

  test "trailing bytes of an incomplete frame are handed back untouched" do
    full = bytes(Codec.request(1, "a", nil))
    partial = binary_part(full, 0, byte_size(full) - 3)
    assert {:ok, [], ^partial} = Codec.decode(partial, @max)
  end

  test "a bare LF header terminator is accepted" do
    body = ~s({"jsonrpc":"2.0","id":1,"method":"ping"})
    stream = "Content-Length: #{byte_size(body)}\n\n" <> body
    assert {:ok, [%{"method" => "ping"}], <<>>} = Codec.decode(stream, @max)
  end

  test "a header naming more bytes than the caller allows is an error, not an allocation" do
    stream = "Content-Length: 99999999\r\n\r\n"
    assert {:error, {:frame_too_large, 99_999_999, @max}} = Codec.decode(stream, @max)
  end

  test "a header block that never terminates is bounded rather than buffered forever" do
    assert {:error, {:header_too_large, _bound}} =
             Codec.decode(String.duplicate("x", 9_000), @max)
  end

  test "a missing Content-Length and an unparseable body are both errors" do
    assert {:error, {:missing_content_length, _headers}} =
             Codec.decode("Content-Type: x\r\n\r\n", @max)

    assert {:error, {:invalid_json, _reason}} = Codec.decode("Content-Length: 3\r\n\r\nnot", @max)
  end
end
