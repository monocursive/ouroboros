defmodule Ouroboros.Wasm.DownloadTest do
  # Not async: two cases move `:signing_max_artifact_bytes`, which is what
  # `Ouroboros.Wasm.Bundle.max_precompiled_bytes/0` — and therefore this module's total
  # ceiling — is derived from, and one moves `:data_dir`.
  use ExUnit.Case, async: false

  @moduledoc """
  W19 — the reply direction of `Ouroboros.Wasm.Upload` (docs/WASM.md D28).

  What is proved here is that a download is the upload's discipline read backwards: bounded
  slots a filesystem claims, files nobody else can read, two clocks, offsets that are the
  node's own answers rather than a seek, and — the claim that matters for the threat model —
  no way at all for a client to *put* bytes here. A node hands out what its own `sign/2`
  compiled and signed, or it hands out nothing.
  """

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Wasm.Bundle
  alias Ouroboros.Wasm.Download
  alias Ouroboros.Wasm.Upload

  @moduletag :capture_log

  setup do
    root =
      Path.join(System.tmp_dir!(), "ouro-wasm-downloads-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf(root) end)
    %{opts: [root: root], root: root}
  end

  describe "the transfer" do
    test "an artifact goes out in frames and comes back whole", %{opts: opts} do
      bytes = artifact(Download.max_chunk_bytes() * 2 + 17)

      assert {:ok, slot} = Download.put(bytes, opts)

      assert slot.download =~ ~r/\A[0-9a-f]{32}\z/
      assert slot.size == byte_size(bytes)
      assert slot.sha256 == sha256(bytes)
      # The node states its own chunk so a client walks the file from the answer rather than
      # from a constant compiled into it — `wasm.upload`'s rule, in the other direction.
      assert slot.chunk_bytes == Upload.max_chunk_bytes()

      {reassembled, chunks} = fetch!(slot, opts)

      assert reassembled == bytes
      assert sha256(reassembled) == slot.sha256

      # Three frames for two chunks and a remainder, and every one of them repeats the whole
      # artifact's digest and size: what a client checks against never depends on which frame
      # it happened to read it from.
      assert length(chunks) == 3

      assert Enum.map(chunks, & &1.offset) == [
               0,
               Download.max_chunk_bytes(),
               Download.max_chunk_bytes() * 2
             ]

      assert Enum.map(chunks, & &1.final) == [false, false, true]
      assert Enum.all?(chunks, &(&1.sha256 == slot.sha256))
      assert Enum.all?(chunks, &(&1.size == byte_size(bytes)))
      assert Enum.all?(chunks, &(&1.download == slot.download))
    end

    test "a short artifact is one frame, and that frame is final", %{opts: opts} do
      assert {:ok, slot} = Download.put("machine code", opts)
      assert {:ok, chunk} = Download.read(slot.download, 0, opts)

      assert Base.decode64!(chunk.data) == "machine code"
      assert chunk.final
    end

    # The decision D28 records, as a test. Reading the final chunk ends the slot: there is no
    # frame in which a client says "done" other than that one, and a slot held for half an
    # hour after a finished transfer is ceiling spent on nothing. Delete the `if final?,
    # do: discard(dir, id)` line in `read/3` and this is green in its first half and red in
    # its second, which is exactly the mutation worth seeing.
    test "the final chunk releases the slot, and asking again is a signature to make again",
         %{opts: opts, root: root} do
      bytes = artifact(Download.max_chunk_bytes() + 1)
      {:ok, slot} = Download.put(bytes, opts)

      assert {:ok, %{final: false}} = Download.read(slot.download, 0, opts)
      # Still there: a transfer in progress holds its slot.
      assert File.exists?(Path.join(root, slot.download <> ".bin"))

      assert {:ok, %{final: true}} =
               Download.read(slot.download, Download.max_chunk_bytes(), opts)

      refute File.exists?(Path.join(root, slot.download <> ".bin"))
      assert root |> File.ls!() |> Enum.filter(&String.starts_with?(&1, "slot-")) == []

      id = slot.download
      assert {:error, {:unknown_download, ^id}} = Download.read(id, 0, opts)
    end

    test "a caller that abandons a transfer releases it, and the ceiling comes back",
         %{opts: opts, root: root} do
      {:ok, slot} = Download.put("machine code", opts)

      assert :ok = Download.release(slot.download, opts)
      refute File.exists?(Path.join(root, slot.download <> ".bin"))

      id = slot.download
      assert {:error, {:unknown_download, ^id}} = Download.release(id, opts)
    end

    # A download is *not* consume-once, and that is the difference from an upload worth
    # stating. An upload's `take/2` must be a rename because two `wasm.deploy` frames naming
    # one upload both receiving the bytes is a replay; a download is a node re-reading a file
    # it made, and a client that lost a frame retrying it is a retry rather than a replay.
    test "a chunk that is not the last may be read again", %{opts: opts} do
      bytes = artifact(Download.max_chunk_bytes() * 2)
      {:ok, slot} = Download.put(bytes, opts)

      assert {:ok, first} = Download.read(slot.download, 0, opts)
      assert {:ok, again} = Download.read(slot.download, 0, opts)
      assert first == again
    end
  end

  describe "the bounds" do
    # Delete the `rem(offset, chunk) != 0` clause in `positioned/2` and a client that lost its
    # place is answered with bytes from the middle of something, which reassembles into a file
    # that hashes to nothing.
    test "an offset that is not a chunk boundary is refused rather than seeked to",
         %{opts: opts} do
      chunk = Download.max_chunk_bytes()
      {:ok, slot} = Download.put(artifact(chunk * 2), opts)

      for hostile <- [1, chunk - 1, chunk + 1, div(chunk, 2)] do
        assert {:error, {:offset_not_a_chunk_boundary, ^hostile, ^chunk}} =
                 Download.read(slot.download, hostile, opts)
      end

      # And the boundaries themselves are still answered, so the refusal is about the
      # boundary rather than about the file being unreadable.
      assert {:ok, _first} = Download.read(slot.download, 0, opts)
    end

    # Delete the `offset >= size` clause and a client is answered `final: true` with no bytes
    # at the end of every file, which is a transfer that never terminates on the far side.
    test "an offset at or past the size is refused, naming the size", %{opts: opts} do
      chunk = Download.max_chunk_bytes()
      {:ok, slot} = Download.put(artifact(chunk), opts)
      size = slot.size

      assert {:error, {:offset_past_size, ^chunk, ^size}} =
               Download.read(slot.download, chunk, opts)

      big = chunk * 100
      assert {:error, {:offset_past_size, ^big, ^size}} = Download.read(slot.download, big, opts)
    end

    test "an id this node did not mint never reaches a path", %{opts: opts, root: root} do
      for hostile <- [
            "../../../etc/passwd",
            "..",
            "",
            String.duplicate("a", 33),
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "9f2c1d4e8a7b6053f1e2d3c4b5a6978"
          ] do
        assert {:error, {:invalid_download_id, _}} = Download.read(hostile, 0, opts)
        assert {:error, {:invalid_download_id, _}} = Download.release(hostile, opts)
      end

      # A well-formed id nobody minted is a different mistake and is named as one.
      unknown = String.duplicate("a", 32)
      assert {:error, {:unknown_download, ^unknown}} = Download.read(unknown, 0, opts)

      # None of them created anything.
      refute File.dir?(root) and File.ls!(root) != []
    end

    # Delete the `claim_slot/4` recursion's ceiling — or the `[:exclusive]` on the slot write —
    # and a node holds as many artifacts on disk as anybody asks it to sign.
    test "a node holds only so many downloads at once", %{opts: opts} do
      slots =
        for _ <- 1..Download.max_in_flight() do
          {:ok, slot} = Download.put("machine code", opts)
          slot
        end

      assert length(Enum.uniq(Enum.map(slots, & &1.download))) == Download.max_in_flight()

      assert {:error, {:too_many_downloads, _held, _max}} = Download.put("more", opts)

      # Room is made by finishing one, which is the ordinary way out: the final chunk.
      assert {:ok, %{final: true}} = Download.read(hd(slots).download, 0, opts)
      assert {:ok, _fresh} = Download.put("machine code", opts)
    end

    test "the ceiling is what a bundle could carry, not what a reply could", %{opts: opts} do
      previous = Application.get_env(:ouroboros, :signing_max_artifact_bytes)
      Application.put_env(:ouroboros, :signing_max_artifact_bytes, 256)
      on_exit(fn -> restore(:signing_max_artifact_bytes, previous) end)

      assert Download.max_total_bytes() == Bundle.max_precompiled_bytes()
      total = Download.max_total_bytes()

      assert {:error, {:download_too_large, ^total}} = Download.put(artifact(total + 1), opts)
      assert {:error, :empty_download} = Download.put("", opts)

      # A refused put leaves nothing behind — the bound is checked before the directory is
      # even prepared.
      refute File.dir?(opts[:root])

      assert {:ok, _slot} = Download.put(artifact(total), opts)
    end

    test "a node with no data directory hands out nothing rather than guessing at a path" do
      previous = Application.get_env(:ouroboros, :data_dir)
      Application.delete_env(:ouroboros, :data_dir)
      on_exit(fn -> restore(:data_dir, previous) end)

      assert {:error, :no_data_dir} = Download.root()
      assert {:error, :no_data_dir} = Download.put("machine code", [])
      assert {:error, :no_data_dir} = Download.read(String.duplicate("a", 32), 0, [])
      assert Download.sweep([]) == 0
    end
  end

  describe "the two clocks, and the sweep that reads them" do
    # Delete the `expire/1` call from `swept/1` and a download past its clocks is still
    # readable, which is this module handing out bytes it had already promised were gone —
    # the same defect `Ouroboros.Wasm.Upload`'s L1 found on its own read path.
    test "a download past its idle clock is gone, for a reader too", %{opts: opts, root: root} do
      {:ok, slot} = Download.put("machine code", opts)

      age(Path.join(root, slot.download <> ".bin"), div(Download.idle_ms(), 1_000) + 60)

      id = slot.download
      assert {:error, {:unknown_download, ^id}} = Download.read(id, 0, opts)
      refute File.exists?(Path.join(root, id <> ".bin"))
    end

    # Delete the lifetime branch from `expired?/4` and a client that reads one chunk every
    # nine minutes holds a slot for as long as it likes; eight of them hold the node.
    test "a download past its total lifetime is reclaimed however freshly it was read",
         %{opts: opts, root: root} do
      bytes = artifact(Download.max_chunk_bytes() * 2)
      {:ok, slot} = Download.put(bytes, opts)

      # Freshly written — the idle clock says nothing — but claimed thirty-one minutes ago.
      rewrite_slot!(
        root,
        slot.download,
        System.system_time(:millisecond) - (Download.max_lifetime_ms() + 60_000)
      )

      assert Download.sweep(opts) >= 1

      id = slot.download
      assert {:error, {:unknown_download, ^id}} = Download.read(id, 0, opts)
      refute File.exists?(Path.join(root, id <> ".bin"))
    end

    # The slot is the authority, not the file. Take the slot away and the bytes beside it are
    # not a download, whatever they still are on disk — which is what makes an expired slot an
    # answer rather than a race with whoever is reading.
    test "a file whose slot is gone is not readable and is swept", %{opts: opts, root: root} do
      {:ok, slot} = Download.put("machine code", opts)

      root
      |> File.ls!()
      |> Enum.filter(&String.starts_with?(&1, "slot-"))
      |> Enum.each(&File.rm!(Path.join(root, &1)))

      # Still on disk, and already not a download.
      assert File.exists?(Path.join(root, slot.download <> ".bin"))

      id = slot.download
      assert {:error, {:unknown_download, ^id}} = Download.read(id, 0, opts)

      # And the sweep reclaims it once it is past the grace a claim in progress gets.
      age(Path.join(root, id <> ".bin"), 60)
      assert Download.sweep(opts) == 1
      refute File.exists?(Path.join(root, id <> ".bin"))
    end
  end

  describe "whose bytes these are" do
    # Delete the `File.chmod(path, 0o600)` in `written/4` and every artifact this node
    # compiles is readable by every account on the machine — machine code a signer produced,
    # which is exactly what D24 says a node must be careful with.
    test "the file and the directory are the owner's alone", %{opts: opts, root: root} do
      {:ok, slot} = Download.put("machine code", opts)

      assert {:ok, %File.Stat{mode: dir_mode}} = File.stat(root)
      assert Bitwise.band(dir_mode, 0o077) == 0

      assert {:ok, %File.Stat{mode: file_mode}} =
               File.stat(Path.join(root, slot.download <> ".bin"))

      assert Bitwise.band(file_mode, 0o077) == 0

      # A directory that already existed loosely is tightened on the next call rather than
      # accepted as found.
      File.chmod!(root, 0o755)
      {:ok, _slot} = Download.put("more machine code", opts)

      assert {:ok, %File.Stat{mode: relaxed}} = File.stat(root)
      assert Bitwise.band(relaxed, 0o077) == 0
    end

    test "a staging root that is a symlink is refused rather than chmod-ed through",
         %{root: root} do
      target = root <> "-target"
      File.mkdir_p!(target)
      on_exit(fn -> File.rm_rf(target) end)

      File.mkdir_p!(Path.dirname(root))
      :ok = File.ln_s(target, root)

      assert {:error, {:download_directory_not_a_directory, :symlink}} =
               Download.put("machine code", root: root)

      assert File.ls!(target) == []
    end

    test "a staged file that is a symlink is not a staged file", %{opts: opts, root: root} do
      File.mkdir_p!(root)

      target = Path.join(root, "secret")
      File.write!(target, "somebody else's bytes")

      id = String.duplicate("d", 32)
      :ok = File.ln_s(target, Path.join(root, id <> ".bin"))

      # A live slot, so the sweep leaves this alone and the answer under test is the refusal
      # rather than the cleanup.
      File.write!(
        Path.join(root, "slot-0"),
        "#{id} #{System.system_time(:millisecond)} #{String.duplicate("f", 64)}\n"
      )

      assert {:error, {:download_not_a_file, :symlink}} = Download.read(id, 0, opts)
      assert File.read!(target) == "somebody else's bytes"
    end
  end

  # ---------------------------------------------------------------------------------------
  # The threat model's own claim: a node hands out only what it made
  # ---------------------------------------------------------------------------------------

  describe "there is no verb that puts" do
    test "`wasm.download` is `:operate`, closed, and takes no bytes" do
      assert {:ok, entry} = Methods.fetch("wasm.download")
      assert entry.scope == :operate
      refute Methods.permits?(:read, entry)

      assert {:ok, %{envelope: :closed, params: params}} = Methods.params("wasm.download")

      # Exactly three, and none of them is a payload. A `data` parameter here would be a
      # download area a client could fill, which is a node storing other people's bytes on
      # request — the one thing this module must not become.
      assert Enum.map(params, & &1.name) |> Enum.sort() == ["download", "node", "offset"]
    end

    test "no lane-W verb creates a slot, whatever it is handed", %{root: root} do
      previous = Application.get_env(:ouroboros, :data_dir)
      dir = Path.join(System.tmp_dir!(), "ouro-wasm-noput-#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      Application.put_env(:ouroboros, :data_dir, dir)

      on_exit(fn ->
        restore(:data_dir, previous)
        File.rm_rf(dir)
      end)

      # Every verb this lane serves, given the shapes a client would use to smuggle bytes in.
      # None of them has a way to reach `put/2`: the only caller is `Wasm.Deploy.sign/2`, and
      # what it hands over is an artifact this node's own helper compiled from bytes this
      # node's own signing service signed.
      for verb <- Enum.filter(Methods.names(), &String.starts_with?(&1, "wasm.")),
          params <- [
            %{},
            %{"data" => Base.encode64("machine code")},
            %{"download" => String.duplicate("a", 32), "offset" => 0},
            %{"download" => String.duplicate("a", 32), "data" => Base.encode64("x")}
          ] do
        _answer = Methods.invoke(verb, params)
      end

      # `<data_dir>/wasm/download/` is either absent or empty: nothing above minted a slot.
      {:ok, download_root} = Download.root()
      assert not File.dir?(download_root) or File.ls!(download_root) == []

      # And this test's own root is untouched, which is the seam the rest of the module uses.
      refute File.dir?(root)
    end
  end

  ## Helpers

  # Reads a slot the way `ouro wasm sign` does: sequentially, from the offsets the answers
  # hand back, until one says it was the last.
  defp fetch!(slot, opts) do
    Enum.reduce_while(Stream.iterate(0, & &1), {<<>>, []}, fn _step, {bytes, chunks} ->
      {:ok, chunk} = Download.read(slot.download, byte_size(bytes), opts)
      acc = {bytes <> Base.decode64!(chunk.data), chunks ++ [chunk]}

      if chunk.final, do: {:halt, acc}, else: {:cont, acc}
    end)
  end

  # Bytes that look like what a helper writes, so a test reading one is reading the shape a
  # real artifact has rather than a run of the same byte.
  defp artifact(size) do
    prefix = "OUROCWASM"
    filler = :binary.copy("machine code, more or less. ", div(size, 28) + 1)
    binary_part(prefix <> filler, 0, size)
  end

  defp sha256(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  # Moves a download's *claim* time into the past without touching its mtime, which is how a
  # test reaches the total-lifetime clock without waiting half an hour or looking idle.
  defp rewrite_slot!(root, id, opened_ms) do
    root
    |> File.ls!()
    |> Enum.filter(&String.starts_with?(&1, "slot-"))
    |> Enum.each(fn name ->
      path = Path.join(root, name)
      contents = File.read!(path)

      if String.starts_with?(contents, id) do
        [^id, _opened, sha] = contents |> String.trim() |> String.split(" ", parts: 3)
        File.write!(path, "#{id} #{opened_ms} #{sha}\n")
      end
    end)
  end

  defp age(path, seconds), do: File.touch!(path, System.os_time(:second) - seconds)

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
