defmodule Ouroboros.Provider.Native.CheckpointTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Checkpoint

  setup do
    dir = Path.join(System.tmp_dir!(), "native-ckpt-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    %{path: Path.join(dir, "conversation.json")}
  end

  @conversation [
    %{role: :user, content: "add a function"},
    %{
      role: :assistant,
      content: "reading",
      tool_calls: [%{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}]
    },
    %{role: :tool, tool_call_id: "c1", name: "read", content: "1\tdefmodule A", is_error: false},
    %{role: :assistant, content: "done", tool_calls: []}
  ]

  test "round-trips a conversation byte-for-byte in shape", %{path: path} do
    assert :ok = Checkpoint.write(path, @conversation)
    assert {:ok, restored} = Checkpoint.read(path)
    assert restored == @conversation
  end

  test "is written 0600 and atomically, leaving no temporary behind", %{path: path} do
    assert :ok = Checkpoint.write(path, @conversation)
    {:ok, %File.Stat{mode: mode}} = File.stat(path)
    assert Bitwise.band(mode, 0o777) == 0o600

    assert path |> Path.dirname() |> File.ls!() == ["conversation.json"]
  end

  test "a missing checkpoint is not an error", %{path: path} do
    assert {:error, :no_checkpoint} = Checkpoint.read(path)
  end

  test "a tampered checkpoint is refused rather than partially replayed", %{path: path} do
    assert :ok = Checkpoint.write(path, @conversation)

    payload = path |> File.read!() |> JSON.decode!()
    tampered = %{payload | "messages" => Enum.take(payload["messages"], 2)}
    File.write!(path, JSON.encode!(tampered))

    assert {:error, :checkpoint_digest_mismatch} = Checkpoint.read(path)
  end

  test "a corrupt file is refused", %{path: path} do
    File.write!(path, "{not json")
    assert {:error, :checkpoint_corrupt} = Checkpoint.read(path)
  end

  test "a future version is refused rather than guessed at", %{path: path} do
    File.write!(path, JSON.encode!(%{"version" => 99, "digest" => "x", "messages" => []}))
    assert {:error, {:checkpoint_version, 99}} = Checkpoint.read(path)
  end

  test "trims to the event limit without leaving an orphan tool result", %{path: path} do
    long = List.duplicate(%{role: :user, content: "x"}, 10) ++ @conversation

    assert :ok = Checkpoint.write(path, long, event_limit: 3)
    assert {:ok, restored} = Checkpoint.read(path)

    assert length(restored) <= 3
    # The head must never be a tool result whose assistant call was trimmed away.
    refute match?([%{role: :tool} | _], restored)
  end

  test "limit/1 honours a session's event_limit and clamps it" do
    assert Checkpoint.limit(%{}) == 400
    assert Checkpoint.limit(%{event_limit: 10}) == 10
    assert Checkpoint.limit(%{"event_limit" => 25}) == 25
    assert Checkpoint.limit(%{event_limit: 1_000_000}) == 10_000
    assert Checkpoint.limit(%{event_limit: -1}) == 400
  end
end
