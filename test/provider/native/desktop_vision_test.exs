defmodule Ouroboros.Provider.Native.Model.ReqLLMVisionTest do
  use ExUnit.Case, async: true

  # Alias the client as `Client` so the top-level `ReqLLM` package (and its ContentPart
  # struct) is not shadowed by `Ouroboros.Provider.Native.Model.ReqLLM`.
  alias Ouroboros.Provider.Native.Model.ReqLLM, as: Client
  alias ReqLLM.Message.ContentPart

  describe "vision?/1 — a best-effort hint on the model spec (§8.2)" do
    test "defaults to true for an unknown model and for nil" do
      assert Client.vision?("no-such-provider:no-such-model")
      assert Client.vision?(nil)
      assert Client.vision?("")
    end
  end

  describe "tool_result_parts/2 — the loop's tool-result seam (§8.2)" do
    test "a vision model keeps the screenshot as an image part" do
      bytes = jpeg()
      path = temp_image(bytes)

      parts =
        Client.tool_result_parts(
          [%{type: :text, text: "tree"}, image_part(path, bytes)],
          true
        )

      assert [%ContentPart{type: :text, text: "tree"}, %ContentPart{type: :image} = image] = parts
      assert image.data == bytes
      assert image.media_type == "image/jpeg"
    end

    test "a non-vision model drops the image and keeps only the tree" do
      bytes = jpeg()
      path = temp_image(bytes)

      parts =
        Client.tool_result_parts(
          [%{type: :text, text: "tree"}, image_part(path, bytes)],
          false
        )

      assert [%ContentPart{type: :text, text: "tree"}] = parts
    end

    test "a staged image that has gone missing degrades to a text marker, never raises (Δ2)" do
      bytes = jpeg()

      parts =
        Client.tool_result_parts(
          [%{type: :text, text: "tree"}, image_part("/gone/screenshot.jpg", bytes)],
          true
        )

      assert [%ContentPart{type: :text, text: "tree"}, %ContentPart{type: :text, text: marker}] =
               parts

      assert marker =~ "no longer available"
    end

    test "an image whose bytes changed under the sha also degrades rather than lying" do
      path = temp_image(jpeg())

      parts =
        Client.tool_result_parts(
          [image_part(path, <<"different bytes entirely">>)],
          true
        )

      assert [%ContentPart{type: :text, text: marker}] = parts
      assert marker =~ "no longer available"
    end
  end

  defp jpeg, do: <<0xFF, 0xD8, 0xFF, 0xE0>> <> :crypto.strong_rand_bytes(48) <> <<0xFF, 0xD9>>

  defp image_part(path, bytes) do
    %{
      type: :image,
      path: path,
      media_type: "image/jpeg",
      sha256: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower),
      size: byte_size(bytes)
    }
  end

  defp temp_image(bytes) do
    path =
      Path.join(System.tmp_dir!(), "ouro-cu-vision-#{System.unique_integer([:positive])}.jpg")

    File.write!(path, bytes)
    on_exit(fn -> File.rm_rf(path) end)
    path
  end
end
