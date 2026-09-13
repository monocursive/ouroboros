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
    assert {:ok, _digest} = Checkpoint.write(path, @conversation)
    assert {:ok, restored} = Checkpoint.read(path)
    assert restored == @conversation
  end

  test "round-trips and authenticates synthetic non-UTF-8 tool bytes", %{path: path} do
    synthetic = <<0x6F, 0x94, 0x75>>

    conversation = [
      %{role: :assistant, content: "tool", tool_calls: [%{id: "c1", name: "bash", input: %{}}]},
      %{role: :tool, tool_call_id: "c1", name: "bash", content: synthetic, is_error: false}
    ]

    assert {:ok, digest} = Checkpoint.write(path, conversation)
    assert {:ok, %{digest: ^digest, messages: ^conversation}} = Checkpoint.snapshot(path)
    assert String.valid?(File.read!(path))
  end

  test "literal tag-shaped maps remain maps through current checkpoint", %{path: path} do
    binary_lookalike = %{"$ouroboros_binary" => "YWJj", "bytes" => 3}
    map_lookalike = %{"$ouroboros_map" => [["key", "value"]]}
    nested = %{"literal" => binary_lookalike, "nested" => [map_lookalike]}

    conversation = [
      %{role: :tool, tool_call_id: "c1", name: "json", content: nested, is_error: false}
    ]

    assert {:ok, _} = Checkpoint.write(path, conversation)
    assert {:ok, %{messages: ^conversation}} = Checkpoint.snapshot(path)
  end

  test "legacy checkpoint tag-shaped maps remain ordinary maps", %{path: path} do
    literal = %{"$ouroboros_binary" => "YWJj", "bytes" => 3}

    conversation = [
      %{role: :tool, tool_call_id: "c1", name: "json", content: literal, is_error: false}
    ]

    assert {:ok, _} = Checkpoint.write(path, conversation)

    payload = path |> File.read!() |> JSON.decode!()

    legacy_messages = [
      %{
        "role" => "tool",
        "tool_call_id" => "c1",
        "name" => "json",
        "content" => literal,
        "is_error" => false
      }
    ]

    digest = :crypto.hash(:sha256, JSON.encode!(legacy_messages)) |> Base.encode16(case: :lower)

    legacy =
      payload
      |> Map.put("version", 2)
      |> Map.put("messages", legacy_messages)
      |> Map.put("digest", digest)
      |> Map.delete("value_encoding")
      |> Map.delete("plan_digest")

    File.write!(path, JSON.encode!(legacy))

    assert {:ok, %{messages: [%{content: ^literal}]}} = Checkpoint.snapshot(path)
  end

  test "round-trips and authenticates the current work-item plan", %{path: path} do
    plan = %{"plan" => [%{"id" => "P0", "step" => "Persist", "status" => "pending"}]}
    assert {:ok, _digest} = Checkpoint.write(path, @conversation, plan: plan)
    assert {:ok, %{plan: ^plan}} = Checkpoint.load(path)

    payload = path |> File.read!() |> JSON.decode!()
    File.write!(path, JSON.encode!(put_in(payload, ["plan", "plan"], [])))
    assert {:error, :checkpoint_plan_digest_mismatch} = Checkpoint.load(path)
  end

  test "legacy message-only checksums never promote a mutable plan", %{path: path} do
    assert {:ok, _digest} = Checkpoint.write(path, @conversation, plan: %{"plan" => []})
    current = path |> File.read!() |> JSON.decode!()

    forged = %{
      "plan" => [
        %{
          "id" => "forged",
          "step" => "Claim completion",
          "status" => "completed",
          "acceptance" => %{"basis" => "model_judgment", "actor" => "operator"}
        }
      ]
    }

    for version <- [1, 2] do
      legacy =
        current
        |> Map.put("version", version)
        |> Map.put("plan", forged)
        |> Map.delete("plan_digest")

      File.write!(path, JSON.encode!(legacy))
      assert {:ok, %{plan: nil}} = Checkpoint.snapshot(path)
    end
  end

  test "is written 0600 and atomically, leaving no temporary behind", %{path: path} do
    assert {:ok, _digest} = Checkpoint.write(path, @conversation)
    {:ok, %File.Stat{mode: mode}} = File.stat(path)
    assert Bitwise.band(mode, 0o777) == 0o600

    assert path |> Path.dirname() |> File.ls!() == ["conversation.json"]
  end

  test "a failed replacement removes its generated temporary file", %{path: path} do
    File.mkdir_p!(path)

    assert {:error, {:checkpoint_write_failed, _}} = Checkpoint.write(path, @conversation)

    assert path
           |> Path.dirname()
           |> File.ls!()
           |> Enum.reject(&(&1 == "conversation.json")) == []
  end

  test "a missing checkpoint is not an error", %{path: path} do
    assert {:error, :no_checkpoint} = Checkpoint.read(path)
  end

  test "a tampered checkpoint is refused rather than partially replayed", %{path: path} do
    assert {:ok, _digest} = Checkpoint.write(path, @conversation)

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

    assert {:ok, _digest} = Checkpoint.write(path, long, event_limit: 3)
    assert {:ok, restored} = Checkpoint.read(path)

    assert length(restored) <= 3
    # The head must never be a tool result whose assistant call was trimmed away.
    refute match?([%{role: :tool} | _], restored)
  end

  # The turn manifest counts messages from the start of the session. The list on disk may
  # not start there, and how far in it does start is the number a rewind needs.
  test "records what the trim dropped, cumulatively", %{path: path} do
    assert {:ok, whole} = write_and_load(path, @conversation, [])
    assert whole.offset == 0
    assert whole.rewind_floor == 0

    long = List.duplicate(%{role: :user, content: "x"}, 10) ++ @conversation

    assert {:ok, trimmed} = write_and_load(path, long, event_limit: 4)
    assert trimmed.offset == length(long) - length(trimmed.messages)

    # A session resuming onto that tail and trimming again is a further offset, not the
    # same one: the offset it was opened with is what the next write counts from.
    assert {:ok, again} =
             write_and_load(path, trimmed.messages, event_limit: 2, offset: trimmed.offset)

    assert again.offset == trimmed.offset + (length(trimmed.messages) - length(again.messages))
  end

  test "the floor a rewind cannot cut below never moves backwards", %{path: path} do
    long = List.duplicate(%{role: :user, content: "x"}, 10)

    assert {:ok, conversation} =
             write_and_load(path, long, event_limit: 4, offset: 2, rewind_floor: 9)

    assert conversation.offset == 8
    assert conversation.rewind_floor == 9

    assert {:ok, higher} = write_and_load(path, long, event_limit: 4, offset: 20)
    assert higher.rewind_floor == higher.offset
  end

  test "a checkpoint written before the offset existed reads as a whole conversation",
       %{path: path} do
    assert {:ok, _digest} = Checkpoint.write(path, @conversation)

    payload = path |> File.read!() |> JSON.decode!()
    File.write!(path, JSON.encode!(Map.drop(payload, ["offset", "rewind_floor"])))

    assert {:ok, conversation} = Checkpoint.load(path)
    assert conversation.offset == 0
    assert conversation.rewind_floor == 0
    assert conversation.messages == @conversation
  end

  test "a trimmed checkpoint without offset infers it from the sibling manifest", %{path: path} do
    kept = Enum.take(@conversation, -2)
    assert {:ok, _digest} = Checkpoint.write(path, kept)

    payload = path |> File.read!() |> JSON.decode!() |> Map.drop(["offset", "rewind_floor"])
    File.write!(path, JSON.encode!(payload))

    last_count = 10

    File.write!(
      Path.join(Path.dirname(path), "manifest.json"),
      JSON.encode!(%{
        "version" => 1,
        "turns" => [
          %{
            "turn_id" => "t1",
            "at" => "2026-01-01T00:00:00Z",
            "message_count" => last_count,
            "commands" => [],
            "dropped" => false,
            "files" => []
          }
        ]
      })
    )

    assert {:ok, conversation} = Checkpoint.load(path)
    assert conversation.offset == last_count - length(kept)
    assert conversation.rewind_floor == conversation.offset
    assert conversation.messages == kept
  end

  defp write_and_load(path, messages, opts) do
    {:ok, _digest} = Checkpoint.write(path, messages, opts)
    Checkpoint.load(path)
  end

  test "limit/1 honours a session's event_limit and clamps it" do
    assert Checkpoint.limit(%{}) == 400
    assert Checkpoint.limit(%{event_limit: 10}) == 10
    assert Checkpoint.limit(%{"event_limit" => 25}) == 25
    assert Checkpoint.limit(%{event_limit: 1_000_000}) == 10_000
    assert Checkpoint.limit(%{event_limit: -1}) == 400
  end
end
