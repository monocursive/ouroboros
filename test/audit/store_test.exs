defmodule Ouroboros.Audit.StoreTest do
  use ExUnit.Case, async: true
  alias Ouroboros.Audit.{Config, Store}
  alias Ouroboros.Provider.Native.Journal

  setup do
    {:ok, temporary} = Ouroboros.Workspace.Path.canonicalize(System.tmp_dir!())
    root = Path.join(temporary, "ouro-audit-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(root) end)
    %{root: root, stream: Journal.digest("test-session")}
  end

  defp start_store(root, options \\ [], hook \\ nil) do
    config = Config.new!([mode: :local, root: root, capture: :full] ++ options)
    start_supervised!({Store, config: config, name: nil, durability_hook: hook})
  end

  test "rotated records remain linked and survive writer restart", %{root: root, stream: stream} do
    server = start_store(root, segment_bytes: 1100)

    for n <- 1..5 do
      assert {:ok, %{"seq" => ^n}} =
               Store.append(
                 stream,
                 "model_call",
                 %{iteration: n, request: %{messages: ["hello"]}},
                 server
               )
    end

    path = Store.stream_path(root, stream)
    assert length(Store.segments(path)) > 1
    assert {:ok, %{verified_through: 5, records: records}} = Store.read(path)
    assert length(records) == 5
    stop_supervised!(Store)
    server = start_store(root)
    assert {:ok, %{"seq" => 6}} = Store.append(stream, "model_result", %{output: "done"}, server)
    assert {:ok, %{verified_through: 6}} = Store.read(path)
  end

  test "metadata capture withholds content and credentials before disk", %{
    root: root,
    stream: stream
  } do
    server = start_store(root, capture: :metadata)

    assert {:ok, record} =
             Store.append(
               stream,
               "model_call",
               %{
                 request: %{messages: ["private prompt"]},
                 api_key: "private key",
                 model: "test:model"
               },
               server
             )

    assert record["request"] == %{"withheld" => "metadata_policy"}
    contents = Store.stream_path(root, stream) |> Store.segments() |> Enum.map_join(&File.read!/1)
    refute contents =~ "private prompt"
    refute contents =~ "private key"
    assert contents =~ "test:model"
  end

  test "a failed sync prevents a later append in the same writer", %{root: root, stream: stream} do
    server =
      start_store(root, [], fn point ->
        if point == :before_sync, do: {:error, :enospc}, else: :ok
      end)

    assert {:error, :enospc} = Store.append(stream, "model_call", %{}, server)
    assert {:error, :stream_requires_recovery} = Store.append(stream, "model_result", %{}, server)
    assert Store.status(server).error == "stream_requires_recovery"
  end

  test "capacity refuses new evidence instead of trimming history", %{root: root, stream: stream} do
    server = start_store(root, segment_bytes: 1024, capacity_bytes: 1400)
    assert {:ok, first} = Store.append(stream, "model_call", %{}, server)
    _ = Store.append(stream, "model_result", %{output: String.duplicate("x", 2000)}, server)
    assert {:ok, %{records: [^first]}} = Store.read(Store.stream_path(root, stream))
  end

  test "changed content and an incomplete tail fail verification", %{root: root, stream: stream} do
    server = start_store(root)
    assert {:ok, _} = Store.append(stream, "model_result", %{output: "original"}, server)
    [file] = Store.segments(Store.stream_path(root, stream))
    original = File.read!(file)
    File.write!(file, String.replace(original, "original", "modified"))
    assert {:error, {:chain_broken, 1}} = Store.read(Store.stream_path(root, stream))
    File.write!(file, original <> "{")
    assert {:error, {:partial_segment, _}} = Store.read(Store.stream_path(root, stream))
  end

  test "encrypted payloads need the right key and carry verified blob references", %{
    root: root,
    stream: stream
  } do
    key = :crypto.strong_rand_bytes(32)
    server = start_store(root, encryption_key_id: "key-1", encryption_keys: %{"key-1" => key})

    assert {:ok, record} =
             Store.append(stream, "model_call", %{request: %{messages: ["sensitive"]}}, server)

    assert record["request"]["store"] == "audit-v2"

    assert {:ok, %{"messages" => ["sensitive"]}} =
             Store.blob(Store.config(server), record["request"])

    refute inspect(File.read!(Path.join([root, "blobs", record["request"]["blob"]]))) =~
             "sensitive"

    refute match?(
             {:ok, _},
             Store.blob(%{Store.config(server) | encryption_keys: %{}}, record["request"])
           )
  end

  test "an audit file cannot be replaced by a symlink", %{root: root, stream: stream} do
    server = start_store(root)
    assert {:ok, _} = Store.append(stream, "model_call", %{}, server)
    [file] = Store.segments(Store.stream_path(root, stream))
    target = Path.join(root, "target")
    File.write!(target, "unchanged")
    File.rm!(file)
    File.ln_s!(target, file)
    assert {:error, :unsafe_audit_file} = Store.append(stream, "model_result", %{}, server)
    assert File.read!(target) == "unchanged"
  end
end
