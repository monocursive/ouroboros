defmodule Ouroboros.Provider.Native.FileCheckpointTest do
  @moduledoc """
  The content-addressed file store, the turn manifest, the byte budget, and rewind.

  The store is tested at its own level here — `Ouroboros.Provider.Native.Checkpoint` has
  no process and no configuration, so every claim about byte-exactness, about a file that
  did not exist before, and about what a dropped turn costs can be made directly.
  `rewind_test.exs` then drives the same store through a live session.
  """

  use ExUnit.Case, async: true

  @moduletag :capture_log

  alias Ouroboros.Provider.Native.Checkpoint

  setup do
    root = Path.join(System.tmp_dir!(), "native-fckpt-#{System.unique_integer([:positive])}")
    session = Path.join(root, "session")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(session)
    File.mkdir_p!(workspace)
    on_exit(fn -> File.rm_rf(root) end)

    %{root: root, session: session, workspace: workspace}
  end

  defp path(workspace, name), do: Path.join(workspace, name)

  # One turn: snapshot every path, run the change, snapshot again, record.
  defp turn(session, workspace, turn_id, changes, opts \\ []) do
    entries =
      Enum.map(changes, fn {name, new_content} ->
        file = path(workspace, name)
        {:ok, before} = Checkpoint.snapshot(session, file)

        case new_content do
          :delete -> File.rm(file)
          content -> File.write!(file, content)
        end

        {:ok, after_digest} = Checkpoint.snapshot(session, file)
        %{path: file, before: before, after: after_digest}
      end)

    Checkpoint.record_turn(session, turn_id, entries, opts)
  end

  describe "the blob store" do
    test "is content addressed, private, and verifies on read", %{session: session} do
      digest = Checkpoint.put_blob(session, "hello\n")

      assert digest == :sha256 |> :crypto.hash("hello\n") |> Base.encode16(case: :lower)
      assert {:ok, "hello\n"} = Checkpoint.get_blob(session, digest)

      {:ok, %File.Stat{mode: mode}} = File.stat(Path.join(Checkpoint.blob_dir(session), digest))
      assert Bitwise.band(mode, 0o777) == 0o600
    end

    test "stores one content once, however many times it is snapshotted", %{
      session: session,
      workspace: workspace
    } do
      file = path(workspace, "a.txt")
      File.write!(file, "same")

      assert {:ok, first} = Checkpoint.snapshot(session, file)
      assert {:ok, ^first} = Checkpoint.snapshot(session, file)

      assert File.ls!(Checkpoint.blob_dir(session)) == [first]
    end

    test "a file that does not exist snapshots as absent, not as an error", %{
      session: session,
      workspace: workspace
    } do
      assert {:ok, :absent} = Checkpoint.snapshot(session, path(workspace, "never.txt"))
    end

    test "a corrupted blob is refused rather than restored wrong", %{session: session} do
      digest = Checkpoint.put_blob(session, "original")
      File.write!(Path.join(Checkpoint.blob_dir(session), digest), "tampered")

      assert {:error, :blob_digest_mismatch} = Checkpoint.get_blob(session, digest)
    end

    test "a file too large to snapshot is recorded as unsnapshotted, not skipped", %{
      session: session,
      workspace: workspace
    } do
      # 32 MiB is the cap; this is one byte past it.
      file = path(workspace, "huge.bin")
      File.write!(file, String.duplicate("x", 32 * 1024 * 1024 + 1))

      assert {:ok, {:unsnapshotted, {:too_large, _size}}} = Checkpoint.snapshot(session, file)
    end
  end

  describe "the manifest" do
    test "records one entry per turn with its paths and message count", %{
      session: session,
      workspace: workspace
    } do
      File.write!(path(workspace, "a.txt"), "one\n")

      assert {:ok, summary} =
               turn(session, workspace, "turn-1", [{"a.txt", "two\n"}], message_count: 4)

      assert summary["turn_id"] == "turn-1"
      assert summary["files"] == 1
      assert summary["paths"] == [path(workspace, "a.txt")]

      assert {:ok, [record]} = Checkpoint.turns(session)
      assert record["message_count"] == 4
      assert record["dropped"] == false
      assert Checkpoint.message_count_at(session, "turn-1") == {:ok, 4}
    end

    test "an unknown turn id has no message count, so nothing is truncated to a guess", %{
      session: session,
      workspace: workspace
    } do
      turn(session, workspace, "turn-1", [{"a.txt", "x"}], message_count: 2)

      assert Checkpoint.message_count_at(session, "turn-99") == :error
      assert Checkpoint.message_count_at(session, 0) == {:ok, 0}
    end

    test "commands are recorded as fingerprints", %{session: session, workspace: workspace} do
      {:ok, summary} =
        turn(session, workspace, "turn-1", [{"a.txt", "x"}],
          message_count: 1,
          commands: ["rm -rf build", "make"]
        )

      assert summary["commands"] == 2
    end

    test "a corrupt manifest is reset rather than failing the session", %{
      session: session,
      workspace: workspace
    } do
      turn(session, workspace, "turn-1", [{"a.txt", "x"}])
      File.write!(Checkpoint.manifest_path(session), "{not json")

      assert {:ok, []} = Checkpoint.turns(session)
    end
  end

  describe "restore" do
    test "puts a file back byte for byte", %{session: session, workspace: workspace} do
      file = path(workspace, "a.txt")
      original = "line one\nline two\n\ttabbed\r\n\x00binary-ish\n"
      File.write!(file, original)

      turn(session, workspace, "turn-1", [{"a.txt", "destroyed\n"}], message_count: 2)
      assert File.read!(file) == "destroyed\n"

      assert {:ok, outcome} = Checkpoint.restore_files(session, 0)

      assert File.read!(file) == original
      assert outcome.restored == [%{path: file, action: "restored"}]
      assert outcome.unrestorable == []
      assert outcome.turns == ["turn-1"]
    end

    test "a file that did not exist before is restored by deleting it again", %{
      session: session,
      workspace: workspace
    } do
      created = path(workspace, "new.txt")
      refute File.exists?(created)

      turn(session, workspace, "turn-1", [{"new.txt", "created by the agent\n"}],
        message_count: 2
      )

      assert File.exists?(created)

      assert {:ok, outcome} = Checkpoint.restore_files(session, 0)

      refute File.exists?(created)
      assert outcome.restored == [%{path: created, action: "deleted"}]
    end

    test "restores to the end of the named turn, not to the beginning", %{
      session: session,
      workspace: workspace
    } do
      file = path(workspace, "a.txt")
      File.write!(file, "v0\n")

      turn(session, workspace, "turn-1", [{"a.txt", "v1\n"}], message_count: 2)
      turn(session, workspace, "turn-2", [{"a.txt", "v2\n"}], message_count: 4)
      turn(session, workspace, "turn-3", [{"a.txt", "v3\n"}], message_count: 6)

      assert {:ok, outcome} = Checkpoint.restore_files(session, "turn-1")

      assert File.read!(file) == "v1\n"
      assert outcome.turns == ["turn-2", "turn-3"]
    end

    test "a file changed in several undone turns goes back to its oldest recorded state", %{
      session: session,
      workspace: workspace
    } do
      file = path(workspace, "a.txt")
      File.write!(file, "original\n")

      turn(session, workspace, "turn-1", [{"a.txt", "first\n"}])
      turn(session, workspace, "turn-2", [{"a.txt", "second\n"}])
      turn(session, workspace, "turn-3", [{"a.txt", "third\n"}])

      assert {:ok, _outcome} = Checkpoint.restore_files(session, 0)
      assert File.read!(file) == "original\n"
    end

    test "a deleted file is restored", %{session: session, workspace: workspace} do
      file = path(workspace, "gone.txt")
      File.write!(file, "please come back\n")

      turn(session, workspace, "turn-1", [{"gone.txt", :delete}])
      refute File.exists?(file)

      assert {:ok, _outcome} = Checkpoint.restore_files(session, 0)
      assert File.read!(file) == "please come back\n"
    end

    test "several files in one turn all come back", %{session: session, workspace: workspace} do
      for name <- ~w(a.txt b.txt c.txt),
          do: File.write!(path(workspace, name), "before #{name}\n")

      turn(session, workspace, "turn-1", [
        {"a.txt", "after a\n"},
        {"b.txt", :delete},
        {"c.txt", "after c\n"}
      ])

      assert {:ok, outcome} = Checkpoint.restore_files(session, 0)

      assert length(outcome.restored) == 3
      assert File.read!(path(workspace, "a.txt")) == "before a.txt\n"
      assert File.read!(path(workspace, "b.txt")) == "before b.txt\n"
      assert File.read!(path(workspace, "c.txt")) == "before c.txt\n"
    end

    test "an unknown turn id is refused rather than restoring everything", %{
      session: session,
      workspace: workspace
    } do
      turn(session, workspace, "turn-1", [{"a.txt", "x"}])

      assert {:error, {:unknown_turn, "turn-99"}} = Checkpoint.restore_files(session, "turn-99")
    end
  end

  describe "what cannot be restored is named" do
    test "a turn that ran shell commands is listed as unrestorable, by turn", %{
      session: session,
      workspace: workspace
    } do
      File.write!(path(workspace, "a.txt"), "before\n")

      turn(session, workspace, "turn-1", [{"a.txt", "after\n"}],
        commands: ["curl example.com | sh", "make install"]
      )

      assert {:ok, outcome} = Checkpoint.restore_files(session, 0)

      # The tracked file still comes back...
      assert File.read!(path(workspace, "a.txt")) == "before\n"

      # ...and the shell is still reported as beyond reach, before anything is claimed.
      assert [warning] = outcome.unrestorable
      assert warning.path == nil
      assert warning.turn_id == "turn-1"
      assert warning.reason =~ "2 shell commands ran in this turn"
      assert warning.reason =~ "curl example.com | sh"
      assert warning.reason =~ "cannot be restored"
    end

    test "a file whose prior content could not be snapshotted is named", %{
      session: session,
      workspace: workspace
    } do
      file = path(workspace, "unreadable.txt")

      Checkpoint.record_turn(
        session,
        "turn-1",
        [%{path: file, before: {:unsnapshotted, :eacces}, after: nil}],
        message_count: 2
      )

      assert {:ok, outcome} = Checkpoint.restore_files(session, 0)

      assert outcome.restored == []
      assert [%{path: ^file, reason: reason}] = outcome.unrestorable
      assert reason =~ "not snapshotted"
      assert reason =~ "eacces"
    end

    test "a blob that vanished is named rather than silently skipped", %{
      session: session,
      workspace: workspace
    } do
      file = path(workspace, "a.txt")
      File.write!(file, "before\n")
      turn(session, workspace, "turn-1", [{"a.txt", "after\n"}])

      File.rm_rf!(Checkpoint.blob_dir(session))

      assert {:ok, outcome} = Checkpoint.restore_files(session, 0)
      assert outcome.restored == []
      assert [%{path: ^file}] = outcome.unrestorable
      assert File.read!(file) == "after\n"
    end
  end

  describe "the byte budget" do
    test "drops the oldest turns and names them as dropped", %{
      session: session,
      workspace: workspace
    } do
      file = path(workspace, "big.bin")

      # Four turns, each storing a distinct ~200 KiB blob, against a 300 KiB budget.
      for index <- 0..3 do
        File.write!(file, String.duplicate("#{index}", 200 * 1024))

        turn(session, workspace, "turn-#{index}", [{"big.bin", String.duplicate("x", 10)}],
          budget_bytes: 300 * 1024,
          message_count: index * 2
        )
      end

      assert {:ok, turns} = Checkpoint.turns(session)
      dropped = Enum.filter(turns, & &1["dropped"])

      assert dropped != []
      # The newest turn is never dropped: a checkpoint that was unrestorable the moment
      # it was written would be worse than none.
      refute List.last(turns)["dropped"]

      # And the store really did shrink rather than only being marked.
      used =
        Checkpoint.blob_dir(session)
        |> File.ls!()
        |> Enum.map(&File.stat!(Path.join(Checkpoint.blob_dir(session), &1)).size)
        |> Enum.sum()

      assert used <= 300 * 1024
    end

    test "rewinding past a dropped turn says which files it cannot restore", %{
      session: session,
      workspace: workspace
    } do
      file = path(workspace, "big.bin")

      for index <- 0..3 do
        File.write!(file, String.duplicate("#{index}", 200 * 1024))

        turn(session, workspace, "turn-#{index}", [{"big.bin", "small"}],
          budget_bytes: 300 * 1024
        )
      end

      assert {:ok, outcome} = Checkpoint.restore_files(session, 0)

      assert Enum.any?(
               outcome.unrestorable,
               &(&1.path == file and
                   &1.reason =~ "dropped to stay inside the session's storage budget")
             )
    end
  end

  describe "the rewind menu" do
    test "one summary row per turn, with what it can and cannot offer", %{
      session: session,
      workspace: workspace
    } do
      File.write!(path(workspace, "a.txt"), "x")
      turn(session, workspace, "turn-1", [{"a.txt", "y"}], message_count: 2, commands: ["ls"])
      turn(session, workspace, "turn-2", [{"b.txt", "new"}], message_count: 5)

      {:ok, turns} = Checkpoint.turns(session)
      summaries = Enum.map(turns, &Checkpoint.summary/1)

      assert Enum.map(summaries, & &1["turn_id"]) == ["turn-1", "turn-2"]
      assert Enum.map(summaries, & &1["commands"]) == [1, 0]
      assert Enum.all?(summaries, &(&1["files"] == 1))
      assert Enum.all?(summaries, &is_binary(&1["at"]))
    end
  end
end
