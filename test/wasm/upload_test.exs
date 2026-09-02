defmodule Ouroboros.Wasm.UploadTest do
  # Not async: two cases move `:signing_max_artifact_bytes`, which is what
  # `Ouroboros.Wasm.Bundle.max_bytes/0` — and therefore this module's total ceiling — is
  # derived from.
  use ExUnit.Case, async: false

  alias Ouroboros.Wasm.Upload

  @moduletag :capture_log

  setup do
    root =
      Path.join(System.tmp_dir!(), "ouro-wasm-uploads-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf(root) end)
    %{opts: [root: root], root: root}
  end

  describe "the transfer" do
    test "a file arrives in frames and comes back whole", %{opts: opts} do
      assert {:ok, first} = Upload.append(nil, 0, "hello ", false, opts)

      assert first.upload =~ ~r/\A[0-9a-f]{32}\z/
      assert first.received == 6
      refute first.complete
      # A digest over half a file is a number that means nothing, so it is not offered.
      assert first.sha256 == nil
      assert first.chunk_bytes == Upload.max_chunk_bytes()

      assert {:ok, last} = Upload.append(first.upload, 6, "component", true, opts)

      assert last.upload == first.upload
      assert last.received == 15
      assert last.complete
      assert last.sha256 == sha256("hello component")

      assert {:ok, "hello component"} = Upload.take(first.upload, opts)
    end

    test "an upload is consumed once, because a transfer is not a name to share",
         %{opts: opts} do
      {:ok, %{upload: id}} = Upload.append(nil, 0, "bytes", true, opts)

      assert {:ok, "bytes"} = Upload.take(id, opts)
      assert {:error, {:unknown_upload, ^id}} = Upload.take(id, opts)
    end

    test "an uncommitted upload is not readable", %{opts: opts} do
      {:ok, %{upload: id}} = Upload.append(nil, 0, "half", false, opts)

      assert {:error, {:upload_incomplete, ^id}} = Upload.take(id, opts)
      assert {:error, {:upload_incomplete, ^id}} = Upload.path(id, opts)
    end

    test "a committed upload takes no further frames", %{opts: opts} do
      {:ok, %{upload: id}} = Upload.append(nil, 0, "done", true, opts)

      assert {:error, {:upload_closed, ^id}} = Upload.append(id, 4, "more", false, opts)
      # And the bytes are still exactly what was committed.
      assert {:ok, "done"} = Upload.take(id, opts)
    end

    test "the path is the staged file, for the one caller that wants the file", %{opts: opts} do
      {:ok, %{upload: id}} = Upload.append(nil, 0, "component", true, opts)

      assert {:ok, path} = Upload.path(id, opts)
      assert File.read!(path) == "component"
      # Reading the path does not consume it: `take/2` still does that.
      assert {:ok, "component"} = Upload.take(id, opts)
    end
  end

  describe "the bounds" do
    # Delete `positioned/3`'s `offset != held` clause and a retried frame is appended
    # twice, which produces a file nobody sent and a sha nobody can explain.
    test "an offset that is not where the node is is refused, naming where it is",
         %{opts: opts} do
      {:ok, %{upload: id}} = Upload.append(nil, 0, "abcdef", false, opts)

      assert {:error, {:offset_mismatch, 6, 0}} = Upload.append(id, 0, "abcdef", false, opts)
      assert {:error, {:offset_mismatch, 6, 99}} = Upload.append(id, 99, "abcdef", false, opts)

      # Nothing was written by either refusal.
      assert {:ok, %{received: 12}} = Upload.append(id, 6, "ghijkl", true, opts)
    end

    test "a chunk above the frame ceiling is refused before it is written", %{opts: opts} do
      over = :binary.copy("x", Upload.max_chunk_bytes() + 1)

      assert {:error, {:chunk_too_large, _max}} = Upload.append(nil, 0, over, false, opts)
      assert {:error, :empty_chunk} = Upload.append(nil, 0, "", false, opts)

      # A refused first frame leaves no upload behind to expire — the chunk is bounded
      # before the directory is even prepared.
      refute File.dir?(opts[:root])
    end

    test "a total above the largest legal bundle is refused mid-transfer", %{opts: opts} do
      previous = Application.get_env(:ouroboros, :signing_max_artifact_bytes)
      Application.put_env(:ouroboros, :signing_max_artifact_bytes, 1_024)
      on_exit(fn -> restore(:signing_max_artifact_bytes, previous) end)

      total = Upload.max_total_bytes()
      {:ok, %{upload: id, received: received}} = Upload.append(nil, 0, chunk(total), false, opts)

      # The ceiling is checked against what the file already holds plus this frame, so it
      # cannot be reached and then exceeded.
      assert {:error, {:upload_too_large, ^total}} =
               Upload.append(id, received, chunk(total), false, opts)
    end

    test "a node holds only so many uploads at once", %{opts: opts} do
      ids =
        for _ <- 1..Upload.max_in_flight() do
          {:ok, %{upload: id}} = Upload.append(nil, 0, "x", false, opts)
          id
        end

      assert length(Enum.uniq(ids)) == Upload.max_in_flight()

      assert {:error, {:too_many_uploads, _held, _max}} = Upload.append(nil, 0, "x", false, opts)

      # Room is made by finishing one, which is the ordinary way out.
      {:ok, _committed} = Upload.append(hd(ids), 1, "y", true, opts)
      {:ok, "xy"} = Upload.take(hd(ids), opts)

      assert {:ok, _fresh} = Upload.append(nil, 0, "x", false, opts)
    end

    # Delete the `expire/2` call from `prepared/1` and an abandoned upload owns disk until
    # somebody notices — which, with no timer anywhere in this module, is never.
    test "an upload abandoned past the window is swept by the next call", %{opts: opts} do
      {:ok, %{upload: stale}} = Upload.append(nil, 0, "forgotten", false, opts)
      {:ok, path} = staged_path(opts, stale)

      age(path, 11 * 60)

      assert {:ok, %{upload: fresh}} = Upload.append(nil, 0, "new", false, opts)
      refute fresh == stale
      assert {:error, {:unknown_upload, ^stale}} = Upload.append(stale, 9, "!", false, opts)

      # A committed one expires too: bytes nobody deployed are still bytes on a disk.
      {:ok, %{upload: committed}} = Upload.append(nil, 0, "done", true, opts)
      age(Path.join(opts[:root], committed <> ".done"), 11 * 60)

      assert Upload.sweep(opts) == 1
      assert {:error, {:unknown_upload, ^committed}} = Upload.take(committed, opts)
    end

    test "an id this node did not mint never reaches a path", %{opts: opts} do
      for hostile <- [
            "../../../etc/passwd",
            "..",
            "",
            String.duplicate("a", 33),
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "9f2c1d4e8a7b6053f1e2d3c4b5a6978"
          ] do
        assert {:error, {:invalid_upload_id, _}} = Upload.take(hostile, opts)
        assert {:error, {:invalid_upload_id, _}} = Upload.path(hostile, opts)
        assert {:error, {:invalid_upload_id, _}} = Upload.append(hostile, 0, "x", false, opts)
      end

      # Nothing was created by any of them.
      refute File.dir?(opts[:root]) and File.ls!(opts[:root]) != []
    end

    test "a node with no data directory stages nothing rather than guessing at a path" do
      previous = Application.get_env(:ouroboros, :data_dir)
      Application.delete_env(:ouroboros, :data_dir)
      on_exit(fn -> restore(:data_dir, previous) end)

      assert {:error, :no_data_dir} = Upload.root()
      assert {:error, :no_data_dir} = Upload.append(nil, 0, "x", false, [])
      assert Upload.sweep([]) == 0
    end
  end

  describe "what an upload is not" do
    test "it says nothing about whether anybody should run what it holds", %{opts: opts} do
      # The sha is a receipt for a transfer. It is computed over whatever arrived, and
      # nothing in this module has an opinion about it.
      {:ok, receipt} = Upload.append(nil, 0, "not a component at all", true, opts)

      assert receipt.sha256 == sha256("not a component at all")
      assert {:ok, "not a component at all"} = Upload.take(receipt.upload, opts)
    end

    test "the staging directory is the owner's alone", %{opts: opts} do
      {:ok, _receipt} = Upload.append(nil, 0, "x", false, opts)

      assert {:ok, %File.Stat{mode: mode}} = File.stat(opts[:root])
      assert Bitwise.band(mode, 0o077) == 0
    end
  end

  ## Helpers

  defp chunk(total), do: :binary.copy("x", min(total, Upload.max_chunk_bytes()))

  defp staged_path(opts, id), do: {:ok, Path.join(opts[:root], id <> ".part")}

  # Moves a file's mtime into the past. The mtime is this module's expiry clock, so this is
  # how a test reaches ten minutes without waiting ten minutes.
  defp age(path, seconds) do
    File.touch!(path, System.os_time(:second) - seconds)
  end

  defp sha256(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
