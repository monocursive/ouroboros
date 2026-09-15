defmodule Ouroboros.AttachmentNormalizerTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Attachments.Normalizer

  test "the real helper normalizes in the runtime sandbox and removes its scratch files" do
    if Normalizer.available?() do
      root =
        Path.join(System.tmp_dir!(), "image-normalizer-#{System.unique_integer([:positive])}")

      File.mkdir!(root)
      on_exit(fn -> File.rm_rf(root) end)
      chunk = Path.join(root, "chunk")

      File.write!(
        chunk,
        Ouroboros.Audit.Content.encode(File.read!("test/support/images/two-pixels.png"))
      )

      assert {:ok, image} = Normalizer.normalize([chunk], root)
      assert image.width == 2 and image.height == 1
      assert <<137, "PNG", _::binary>> = image.content
      assert byte_size(image.thumbnail) < 256 * 1024
      assert File.ls!(root) == ["chunk"]
      File.write!(chunk, "corrupt")
      assert {:error, _} = Normalizer.normalize([chunk], root)
      assert File.ls!(root) == ["chunk"]
    else
      # Platforms without OS containment must advertise the feature as unavailable.
      refute Ouroboros.Attachments.available?()
    end
  end
end
