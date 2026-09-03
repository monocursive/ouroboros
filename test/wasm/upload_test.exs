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

  describe "the two things a filesystem does atomically" do
    # M1 (review). `take/2` was `File.read` then `File.rm`, so two `wasm.deploy` frames
    # naming the same upload could both receive the bytes — exactly the replay the
    # moduledoc said could not happen. A rename to a private name either wins or is
    # `:enoent`. Replace the rename with a read and this finds a doubled take within a few
    # hundred attempts.
    test "two concurrent takers: exactly one receives the bytes", %{opts: opts} do
      doubled =
        Enum.reduce_while(1..300, 1, fn _attempt, _acc ->
          {:ok, %{upload: id}} = Upload.append(nil, 0, "payload", true, opts)

          winners =
            [1, 2]
            |> Enum.map(fn _ -> Task.async(fn -> Upload.take(id, opts) end) end)
            |> Task.await_many(5_000)
            |> Enum.count(&match?({:ok, "payload"}, &1))

          if winners == 1, do: {:cont, 1}, else: {:halt, winners}
        end)

      assert doubled == 1
    end

    # M2 (review). `in_flight/1` counted and then created — two syscalls — so thirty-two
    # concurrent openers all counted seven and all created a file. A slot is claimed with
    # `O_CREAT|O_EXCL` now, which is the one thing a filesystem will decide for you.
    test "thirty-two concurrent openers cannot exceed eight", %{opts: opts, root: root} do
      results =
        1..32
        |> Enum.map(fn _ -> Task.async(fn -> Upload.append(nil, 0, "x", false, opts) end) end)
        |> Task.await_many(15_000)

      opened = Enum.count(results, &match?({:ok, _receipt}, &1))
      refused = Enum.count(results, &match?({:error, {:too_many_uploads, _, _}}, &1))

      assert opened == Upload.max_in_flight()
      assert opened + refused == 32
      assert root |> File.ls!() |> Enum.count(&String.ends_with?(&1, ".part")) == opened
    end

    # The slot files *are* the ceiling, so a directory already holding eight of them admits
    # nothing, whatever is or is not beside them.
    test "eight claimed slots admit no ninth upload", %{opts: opts, root: root} do
      File.mkdir_p!(root)

      # Each slot names a real staged file, because a slot whose upload does not exist is
      # litter and the sweep reclaims it — which is itself the right answer and is why this
      # has to be built properly to test the ceiling rather than the cleanup.
      for n <- 0..(Upload.max_in_flight() - 1) do
        id = String.duplicate(Integer.to_string(n), 32)
        File.write!(Path.join(root, id <> ".part"), "x")

        File.write!(
          Path.join(root, "slot-#{n}"),
          "#{id} #{System.system_time(:millisecond)}\n"
        )
      end

      assert {:error, {:too_many_uploads, _held, _max}} = Upload.append(nil, 0, "x", false, opts)
    end
  end

  # A claim is two writes with a moment between them, and a sweep in a concurrent call can
  # land in that moment: it read a slot empty, took it for litter, and then reclaimed the
  # part that slot was about to name (hosted run 33692982947: thirty-two openers, seven
  # winners). Nothing regular and young is reclaimed on the strength of how it looks.
  describe "a claim in progress is not litter" do
    test "an empty slot that is young is a claim, and nothing slotless is reclaimed beside it",
         %{opts: opts, root: root} do
      File.mkdir_p!(root)
      id = String.duplicate("a", 32)
      File.write!(Path.join(root, "slot-0"), "")
      File.write!(Path.join(root, id <> ".part"), "x")

      assert Upload.sweep(opts) == 0
      assert File.exists?(Path.join(root, "slot-0"))
      assert File.exists?(Path.join(root, id <> ".part"))
    end

    test "an empty slot past the grace is litter, and so is the slotless file beside it",
         %{opts: opts, root: root} do
      File.mkdir_p!(root)
      id = String.duplicate("b", 32)
      File.write!(Path.join(root, "slot-0"), "")
      File.write!(Path.join(root, id <> ".part"), "x")
      age(Path.join(root, "slot-0"), 60)
      age(Path.join(root, id <> ".part"), 60)

      assert Upload.sweep(opts) == 1
      refute File.exists?(Path.join(root, "slot-0"))
      refute File.exists?(Path.join(root, id <> ".part"))
    end

    test "a young slot whose part is not written yet is kept, and an old one is not",
         %{opts: opts, root: root} do
      File.mkdir_p!(root)
      young = String.duplicate("c", 32)
      old = String.duplicate("d", 32)
      now = System.system_time(:millisecond)
      File.write!(Path.join(root, "slot-0"), "#{young} #{now}\n")
      File.write!(Path.join(root, "slot-1"), "#{old} #{now - 60_000}\n")

      assert Upload.sweep(opts) == 0
      assert File.exists?(Path.join(root, "slot-0"))
      refute File.exists?(Path.join(root, "slot-1"))
    end

    test "a slotless part is reclaimed only once it is past the grace",
         %{opts: opts, root: root} do
      File.mkdir_p!(root)
      id = String.duplicate("e", 32)
      path = Path.join(root, id <> ".part")
      File.write!(path, "x")

      assert Upload.sweep(opts) == 0
      assert File.exists?(path)

      age(path, 60)
      assert Upload.sweep(opts) == 1
      refute File.exists?(path)
    end

    test "the files of a slot expired by its clocks are reclaimed whatever their age",
         %{opts: opts, root: root} do
      {:ok, %{upload: id}} = Upload.append(nil, 0, "payload", true, opts)
      rewrite_slot!(root, id, System.system_time(:millisecond) - Upload.max_lifetime_ms() - 1)

      assert Upload.sweep(opts) >= 1
      refute File.exists?(Path.join(root, id <> ".done"))
    end
  end

  describe "the two clocks, and the sweep that reads them" do
    # L1. Only `append/5` swept, so `take/2` and `path/2` handed back files the module had
    # already promised were gone. Delete the `expire/1` call from `swept/1` and this is red.
    test "an expired upload is not consumable by a reader either", %{opts: opts, root: root} do
      {:ok, %{upload: id}} = Upload.append(nil, 0, "payload", true, opts)

      age(Path.join(root, id <> ".done"), 3_600)

      assert {:error, _reclaimed} = Upload.take(id, opts)
      assert {:error, _reclaimed} = Upload.path(id, opts)
    end

    # L2. The idle clock alone is not a bound: a client writing one byte every nine minutes
    # holds a slot for as long as it likes, and eight such clients hold the node. Delete the
    # lifetime branch from `expired?/3` and this upload lives forever.
    test "an upload past its total lifetime is reclaimed however busy it looks",
         %{opts: opts, root: root} do
      {:ok, %{upload: id}} = Upload.append(nil, 0, "still going", false, opts)

      # Freshly written — the idle clock says nothing — but claimed thirty-one minutes ago.
      opened = System.system_time(:millisecond) - (Upload.max_lifetime_ms() + 60_000)
      rewrite_slot!(root, id, opened)

      assert File.exists?(Path.join(root, id <> ".part"))
      assert Upload.sweep(opts) >= 1

      assert {:error, {:unknown_upload, ^id}} = Upload.append(id, 11, "more", false, opts)
      refute File.exists?(Path.join(root, id <> ".part"))
    end

    test "the slot is released when the upload is taken, so the ceiling is not a leak",
         %{opts: opts, root: root} do
      ids =
        for _ <- 1..Upload.max_in_flight() do
          {:ok, %{upload: id}} = Upload.append(nil, 0, "x", true, opts)
          id
        end

      assert {:error, {:too_many_uploads, _, _}} = Upload.append(nil, 0, "x", false, opts)

      {:ok, "x"} = Upload.take(hd(ids), opts)

      assert {:ok, _fresh} = Upload.append(nil, 0, "x", false, opts)
      assert root |> File.ls!() |> Enum.count(&String.starts_with?(&1, "slot-")) == 8
    end
  end

  describe "nothing here follows a symlink" do
    # L3. A staging root that is a symlink is a root whose owner is whoever made the link,
    # and `chmod 0700` through it is a mode set on their target.
    test "a staging root that is a symlink is refused rather than chmod-ed through",
         %{root: root} do
      target = root <> "-target"
      File.mkdir_p!(target)
      on_exit(fn -> File.rm_rf(target) end)

      File.mkdir_p!(Path.dirname(root))
      :ok = File.ln_s(target, root)

      assert {:error, {:upload_directory_not_a_directory, :symlink}} =
               Upload.append(nil, 0, "x", false, root: root)

      # Nothing was written through it.
      assert File.ls!(target) == []
    end

    test "a staged file that is a symlink is not a staged file", %{opts: opts, root: root} do
      File.mkdir_p!(root)

      target = Path.join(root, "secret")
      File.write!(target, "somebody else's bytes")

      id = String.duplicate("d", 32)
      :ok = File.ln_s(target, Path.join(root, id <> ".done"))

      # A live slot and a real `.part` beside it, so the sweep leaves this alone and the
      # answer under test is the refusal rather than the cleanup.
      File.write!(Path.join(root, id <> ".part"), "in progress")

      File.write!(
        Path.join(root, "slot-0"),
        "#{id} #{System.system_time(:millisecond)}\n"
      )

      assert {:error, {:upload_not_a_file, :symlink}} = Upload.take(id, opts)
      assert {:error, {:upload_not_a_file, :symlink}} = Upload.path(id, opts)
      assert File.read!(target) == "somebody else's bytes"
    end

    # And a symlink nobody vouched for is litter: the sweep unlinks it and never reads or
    # writes through it.
    test "a symlink with no live slot is reclaimed, and its target is untouched",
         %{opts: opts, root: root} do
      File.mkdir_p!(root)

      target = Path.join(root, "secret")
      File.write!(target, "somebody else's bytes")

      link = Path.join(root, String.duplicate("e", 32) <> ".done")
      :ok = File.ln_s(target, link)

      assert Upload.sweep(opts) >= 1

      refute File.exists?(link, [:raw])
      assert File.read!(target) == "somebody else's bytes"
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

    test "the staging directory is the owner's alone, however it got there",
         %{opts: opts, root: root} do
      # Created by this module: 0700 from the start.
      {:ok, _receipt} = Upload.append(nil, 0, "x", false, opts)

      assert {:ok, %File.Stat{mode: mode}} = File.stat(root)
      assert Bitwise.band(mode, 0o077) == 0

      # And a directory that already existed, loosely: tightened on the next call rather
      # than accepted as found. These are two branches of `ensure_directory/1` and a
      # mutation of either must be visible.
      File.chmod!(root, 0o755)
      {:ok, _receipt} = Upload.append(nil, 0, "x", false, opts)

      assert {:ok, %File.Stat{mode: relaxed}} = File.stat(root)

      assert Bitwise.band(relaxed, 0o077) == 0,
             "a staging directory somebody else could read was left that way"
    end
  end

  ## Helpers

  defp chunk(total), do: :binary.copy("x", min(total, Upload.max_chunk_bytes()))

  defp staged_path(opts, id), do: {:ok, Path.join(opts[:root], id <> ".part")}

  # Moves an upload's *claim* time into the past without touching its mtime, which is how a
  # test reaches the total-lifetime clock without waiting half an hour or looking idle.
  defp rewrite_slot!(root, id, opened_ms) do
    root
    |> File.ls!()
    |> Enum.filter(&String.starts_with?(&1, "slot-"))
    |> Enum.each(fn name ->
      path = Path.join(root, name)

      if path |> File.read!() |> String.starts_with?(id) do
        File.write!(path, "#{id} #{opened_ms}\n")
      end
    end)
  end

  # Moves a file's mtime into the past. The mtime is this module's expiry clock, so this is
  # how a test reaches ten minutes without waiting ten minutes.
  defp age(path, seconds) do
    File.touch!(path, System.os_time(:second) - seconds)
  end

  defp sha256(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
