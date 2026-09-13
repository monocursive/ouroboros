defmodule Ouroboros.Gateway.NativeImportTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Methods.Placement
  alias Ouroboros.Provider.Native.Checkpoint

  defmodule PlacementFixture do
    def ensure_placeable(owner) do
      send(test_pid(), {:ensure_placeable, owner})
      :ok
    end

    def record_session_snapshot(plane, observations) do
      send(test_pid(), {:snapshot, plane, observations})
      :ok
    end

    defp test_pid, do: Application.fetch_env!(:ouroboros, :native_import_placement_test_pid)
  end

  setup do
    root =
      Path.join(System.tmp_dir!(), "gateway-native-import-#{System.unique_integer([:positive])}")

    native = Path.join(root, "native")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(workspace)
    previous = Application.get_env(:ouroboros, :native_data_dir)
    Application.put_env(:ouroboros, :native_data_dir, native)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :native_data_dir, previous),
        else: Application.delete_env(:ouroboros, :native_data_dir)

      File.rm_rf(root)
    end)

    source = "native-gateway-#{System.unique_integer([:positive])}"
    {:ok, path, true} = Checkpoint.locate(source)
    {:ok, digest} = Checkpoint.write(path, [%{role: :user, content: "retained"}])
    %{source: source, digest: digest, workspace: workspace}
  end

  test "contracts are operate scoped, closed, advertised, and carry unknown import outcome" do
    table = Methods.table()
    assert table["interactive.preview_native"].scope == :operate
    assert table["interactive.import_native"].scope == :operate
    assert table["interactive.import_native"].outcome == :unknown
    assert "interactive.preview_native" in Methods.names()
    assert "interactive.import_native" in Methods.names()

    assert {:error, -32602, _} =
             Methods.invoke("interactive.preview_native", %{
               "provider_session_id" => "native-a-b",
               "path" => "/tmp/x"
             })

    assert {:error, -32602, _} =
             Methods.invoke("interactive.import_native", %{
               "provider_session_id" => "native-a-b",
               "expected_digest" => "x",
               "acknowledge_partial_tail" => "yes"
             })
  end

  test "preview accepts explicit local placement and refuses an unavailable remote", ctx do
    assert {:ok, preview} =
             Methods.invoke("interactive.preview_native", %{
               "provider_session_id" => ctx.source,
               "node" => Atom.to_string(node())
             })

    assert preview["digest"] == ctx.digest

    assert {:error, _, _} =
             Methods.invoke("interactive.preview_native", %{
               "provider_session_id" => ctx.source,
               "node" => "ouroboros@not-connected"
             })
  end

  test "gateway preview and import preserve source and expose fresh identities", ctx do
    {:ok, preview} =
      Methods.invoke("interactive.preview_native", %{"provider_session_id" => ctx.source})

    assert preview["digest"] == ctx.digest
    source_path = Checkpoint.locate(ctx.source) |> elem(1)
    source_bytes = File.read!(source_path)
    id = "gateway-import-#{System.unique_integer([:positive])}"

    assert {:ok, imported} =
             Methods.invoke("interactive.import_native", %{
               "provider_session_id" => ctx.source,
               "expected_digest" => ctx.digest,
               "id" => id,
               "workspace" => ctx.workspace,
               "sandbox_mode" => "read_only"
             })

    assert imported["id"] == id
    assert imported["provider_session_id"] != ctx.source
    assert File.read!(source_path) == source_bytes
  end

  test "explicit false is accepted for a whole checkpoint", ctx do
    id = "gateway-import-false-#{System.unique_integer([:positive])}"

    assert {:ok, imported} =
             Methods.invoke("interactive.import_native", %{
               "provider_session_id" => ctx.source,
               "expected_digest" => ctx.digest,
               "id" => id,
               "workspace" => ctx.workspace,
               "acknowledge_partial_tail" => false
             })

    assert imported["id"] == id
    assert imported["provider_session_id"] != ctx.source
  end

  test "partial-tail import refuses false and accepts true through the gateway", ctx do
    {:ok, source_path, _created?} = Checkpoint.locate(ctx.source)
    {:ok, conversation} = Checkpoint.load(source_path)
    {:ok, _digest} = Checkpoint.write(source_path, conversation.messages, offset: 1)
    {:ok, snapshot} = Checkpoint.snapshot(source_path)
    id = "gateway-import-tail-#{System.unique_integer([:positive])}"

    assert {:error, _, message, detail} =
             Methods.invoke("interactive.import_native", %{
               "provider_session_id" => ctx.source,
               "expected_digest" => snapshot.digest,
               "id" => id,
               "workspace" => ctx.workspace,
               "acknowledge_partial_tail" => false
             })

    assert message == "the runtime refused the call"
    assert detail == "partial_tail_acknowledgement_required"

    assert {:ok, imported} =
             Methods.invoke("interactive.import_native", %{
               "provider_session_id" => ctx.source,
               "expected_digest" => snapshot.digest,
               "id" => id,
               "workspace" => ctx.workspace,
               "acknowledge_partial_tail" => true
             })

    assert imported["id"] == id
  end

  test "placement records possible then created evidence for a remotely committed settlement error" do
    owner = :fixture@remote
    Application.put_env(:ouroboros, :native_import_placement_test_pid, self())
    on_exit(fn -> Application.delete_env(:ouroboros, :native_import_placement_test_pid) end)

    result =
      Placement.import_native(
        owner,
        [workspace: "/remote/workspace"],
        fn -> {:error, {:import_settlement_failed, :disk_full}} end,
        PlacementFixture
      )

    assert_receive {:ensure_placeable, ^owner}
    assert_receive {:snapshot, :interactive, [{^owner, [%{possible_start: true}]}]}
    assert_receive {:snapshot, :interactive, [{^owner, [%{created: true}]}]}
    assert {:error, _, _, _} = result
  end
end
