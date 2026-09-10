defmodule Ouroboros.Storage.DurableFileTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Storage.DurableFile

  setup do
    root =
      Path.join(System.tmp_dir!(), "ouroboros-durable-file-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf!(root) end)
    %{root: root}
  end

  test "checkpoint success follows write, file sync, atomic rename, and directory sync order", %{
    root: root
  } do
    owner = self()

    hook = fn event ->
      send(owner, {:durability, event})
      :ok
    end

    opts = [path: root, durability_hook: hook]

    assert :ok = DurableFile.put_checkpoint(:journal, %{sequence: 1}, opts)
    assert {:ok, %{sequence: 1}} = DurableFile.get_checkpoint(:journal, opts)

    assert drain_events() == [
             :before_open_temp,
             :before_write,
             :before_file_sync,
             :before_close,
             :before_rename,
             :before_directory_sync,
             :directory_sync
           ]
  end

  test "failure before rename preserves the prior committed checkpoint", %{root: root} do
    assert :ok = DurableFile.put_checkpoint(:journal, %{sequence: 1}, path: root)

    hook = fn
      :before_rename -> {:error, :injected_before_rename}
      _event -> :ok
    end

    assert {:error, :injected_before_rename} =
             DurableFile.put_checkpoint(:journal, %{sequence: 2},
               path: root,
               durability_hook: hook
             )

    assert {:ok, %{sequence: 1}} = DurableFile.get_checkpoint(:journal, path: root)
    assert Path.wildcard(Path.join([root, "checkpoints", "*.tmp-*"])) == []
  end

  test "failure after rename is reported as an unknown commit outcome", %{root: root} do
    assert :ok = DurableFile.put_checkpoint(:journal, %{sequence: 1}, path: root)

    hook = fn
      :before_directory_sync -> {:error, :injected_before_directory_sync}
      _event -> :ok
    end

    assert {:error, {:commit_outcome_unknown, :injected_before_directory_sync}} =
             DurableFile.put_checkpoint(:journal, %{sequence: 2},
               path: root,
               durability_hook: hook
             )

    # The rename happened, so the value is visible. The caller is told that fact is
    # ambiguous rather than incorrectly treating this as a definite refusal.
    assert {:ok, %{sequence: 2}} = DurableFile.get_checkpoint(:journal, path: root)
  end

  test "a temporary file orphaned by a crash is swept by the next adapter start", %{root: root} do
    hook = fn
      :before_rename -> raise "died before rename"
      _event -> :ok
    end

    assert {:error, %RuntimeError{}} =
             DurableFile.put_checkpoint(:journal, %{sequence: 1},
               path: root,
               durability_hook: hook
             )

    assert [orphan] = Path.wildcard(Path.join([root, "checkpoints", "*.tmp-*"]))

    # Old enough to be from a run that is over rather than a commit in flight.
    File.touch!(orphan, System.os_time(:second) - 3_600)

    # A fresh process is a fresh user of the adapter, and sweeps on its first write.
    task = Task.async(fn -> DurableFile.put_checkpoint(:journal, %{sequence: 2}, path: root) end)
    assert :ok = Task.await(task)

    assert Path.wildcard(Path.join([root, "checkpoints", "*.tmp-*"])) == []
    assert {:ok, %{sequence: 2}} = DurableFile.get_checkpoint(:journal, path: root)
  end

  test "a temporary file a live commit may still hold is left alone", %{root: root} do
    hook = fn
      :before_rename -> raise "died before rename"
      _event -> :ok
    end

    assert {:error, %RuntimeError{}} =
             DurableFile.put_checkpoint(:journal, %{sequence: 1},
               path: root,
               durability_hook: hook
             )

    assert [recent] = Path.wildcard(Path.join([root, "checkpoints", "*.tmp-*"]))

    task = Task.async(fn -> DurableFile.put_checkpoint(:journal, %{sequence: 2}, path: root) end)
    assert :ok = Task.await(task)

    assert Path.wildcard(Path.join([root, "checkpoints", "*.tmp-*"])) == [recent]
  end

  test "unsupported thread operations fail closed", %{root: root} do
    assert {:error, :thread_operations_not_supported} =
             DurableFile.load_thread("thread", path: root)

    assert {:error, :thread_operations_not_supported} =
             DurableFile.append_thread("thread", [], path: root)

    assert {:error, :thread_operations_not_supported} =
             DurableFile.delete_thread("thread", path: root)
  end

  defp drain_events(acc \\ []) do
    receive do
      {:durability, event} -> drain_events([event | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end
