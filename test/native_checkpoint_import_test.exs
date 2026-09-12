defmodule Ouroboros.NativeCheckpointImportTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Provider.Native.Checkpoint

  setup do
    root = Path.join(System.tmp_dir!(), "native-import-#{System.unique_integer([:positive])}")
    data = Path.join(root, "data")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(workspace)
    previous = Application.get_env(:ouroboros, :native_data_dir)
    Application.put_env(:ouroboros, :native_data_dir, Path.join(data, "native"))

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :native_data_dir, previous),
        else: Application.delete_env(:ouroboros, :native_data_dir)

      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace}
  end

  test "preview is read-only and import preserves source while creating context-only provenance",
       ctx do
    {source, path, digest} = source_checkpoint(offset: 7)
    before = tree(ctx.root)

    assert {:ok, preview} = InteractiveSession.preview_native(source)
    assert preview.digest == digest
    assert preview.offset == 7
    assert preview.retained_messages == 2
    assert tree(ctx.root) == before

    id = "import-#{System.unique_integer([:positive])}"

    assert {:error, :partial_tail_acknowledgement_required} =
             InteractiveSession.import_native(source, digest,
               id: id,
               workspace: ctx.workspace,
               sandbox_mode: :read_only
             )

    assert tree(ctx.root) == before

    assert {:ok, imported} =
             InteractiveSession.import_native(source, digest,
               id: id,
               workspace: ctx.workspace,
               sandbox_mode: :read_only,
               acknowledge_partial_tail: true
             )

    refute imported.provider_session_id == source
    assert File.read!(path) == before[path]
    assert {:ok, info} = InteractiveSession.info(id)
    assert info.forked_from == nil and info.handed_off_from == nil
    assert info.cursor >= 1
    [marker | _] = info.events
    assert marker.type == :native_checkpoint_imported
    assert marker.payload["omitted_prefix"] == 7
    refute Enum.any?(info.events, &(&1.type in [:approval_requested, :turn_completed]))
    assert {:ok, seeded, _} = Checkpoint.locate(imported.provider_session_id)
    assert {:ok, conversation} = Checkpoint.load(seeded)
    assert Enum.map(conversation.messages, & &1.content) == ["remember import sentinel", "ack"]
    assert {:ok, effects} = EffectLedger.list(effect: :native_import, limit: 100)
    assert Enum.any?(effects, &(&1.attempt.session_id == id and &1.status == :ok))
  end

  test "exact retry converges and changed or competing requests conflict without source mutation",
       ctx do
    {source, path, digest} = source_checkpoint()
    bytes = File.read!(path)
    id = "import-idem-#{System.unique_integer([:positive])}"
    opts = [id: id, workspace: ctx.workspace, sandbox_mode: :read_only]
    assert {:ok, first} = InteractiveSession.import_native(source, digest, opts)
    assert {:ok, second} = InteractiveSession.import_native(source, digest, opts)
    assert second.idempotent and second.provider_session_id == first.provider_session_id

    assert {:error, {:session_id_conflict, ^id}} =
             InteractiveSession.import_native(
               source,
               digest,
               Keyword.put(opts, :model, "openai:changed")
             )

    other = "other-#{System.unique_integer([:positive])}"

    assert {:error, {:native_checkpoint_owned, ^id}} =
             InteractiveSession.import_native(source, digest, Keyword.put(opts, :id, other))

    assert File.read!(path) == bytes
  end

  test "unknown unsafe corrupt stale and direct-owned sources refuse", ctx do
    assert {:error, {:invalid_provider_session_id, _}} =
             InteractiveSession.preview_native("../conversation.json")

    assert {:error, :native_checkpoint_not_found} =
             InteractiveSession.preview_native("native-node-missing")

    {source, path, _digest} = source_checkpoint()
    payload = path |> File.read!() |> JSON.decode!()
    File.write!(path, JSON.encode!(%{payload | "version" => 999}))
    assert {:error, {:checkpoint_version, 999}} = InteractiveSession.preview_native(source)
    File.write!(path, JSON.encode!(payload))

    assert {:error, :checkpoint_digest_changed} =
             InteractiveSession.import_native(source, String.duplicate("0", 64),
               id: "stale",
               workspace: ctx.workspace
             )

    owned = "owned-#{System.unique_integer([:positive])}"

    assert {:ok, _} =
             InteractiveSession.start(
               id: owned,
               workspace: ctx.workspace,
               sandbox_mode: :read_only,
               provider_session_id: source
             )

    assert {:error, {:native_checkpoint_owned, ^owned}} =
             InteractiveSession.preview_native(source)
             |> then(fn {:ok, p} ->
               if p.owned_by, do: {:error, {:native_checkpoint_owned, p.owned_by}}
             end)
  end

  defp source_checkpoint(opts \\ []) do
    source = "native-test-#{System.unique_integer([:positive])}"
    {:ok, path, true} = Checkpoint.locate(source)

    messages = [
      %{role: :user, content: "remember import sentinel"},
      %{role: :assistant, content: "ack", tool_calls: []}
    ]

    {:ok, digest} = Checkpoint.write(path, messages, offset: Keyword.get(opts, :offset, 0))
    {source, path, digest}
  end

  defp tree(root) do
    root
    |> Path.join("**/*")
    |> Path.wildcard(match_dot: true)
    |> Enum.filter(&File.regular?/1)
    |> Map.new(&{&1, File.read!(&1)})
  end
end
