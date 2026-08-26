defmodule Ouroboros.Provider.Native.Context.CompactionImageTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Context.Compaction

  # An image part costs the window a nominal ~1000 tokens (Window.@nominal_part_tokens), so a
  # keep budget just over that keeps the most recent screenshot turn and folds the older one.
  @keep_recent 1_100

  defp image_part(size),
    do: %{
      type: :image,
      path: "/desktop/x.jpg",
      media_type: "image/jpeg",
      sha256: "abc",
      size: size
    }

  defp state_message(id, text, image_size) do
    %{
      role: :tool,
      name: "desktop_state",
      tool_call_id: id,
      content: [%{type: :text, text: text}, image_part(image_size)],
      is_error: false
    }
  end

  describe "elide_old_tool_results/2 with image content (§8.3)" do
    test "folds an old screenshot turn to a marker whose byte count includes the image" do
      old = state_message("a", "old tree", 50_000)
      recent = state_message("b", "recent tree", 40_000)

      messages = [
        %{role: :user, content: "start"},
        old,
        %{role: :user, content: "later"},
        recent
      ]

      {elided, count} = Compaction.elide_old_tool_results(messages, @keep_recent)

      assert count == 1

      folded = Enum.at(elided, 1)
      assert Compaction.elided?(folded)
      # byte_size("old tree") == 8, plus the 50_000-byte image.
      assert folded.content =~ "50008 bytes]"

      # The most recent screenshot turn is untouched: its image part stays in the tail.
      kept = List.last(elided)
      assert kept == recent
      assert Enum.any?(kept.content, &(&1[:type] == :image))
    end

    test "a tool result that is already a marker is not re-elided" do
      messages = [
        %{
          role: :tool,
          name: "desktop_state",
          tool_call_id: "a",
          content: "[tool result elided: 10 bytes]"
        },
        %{role: :user, content: String.duplicate("tail ", 500)}
      ]

      {elided, count} = Compaction.elide_old_tool_results(messages, 50)
      assert count == 0
      assert Enum.at(elided, 0).content == "[tool result elided: 10 bytes]"
    end
  end

  describe "compact/2 end to end with image content" do
    test "does not crash estimating list content and folds the old image turn" do
      old = state_message("a", "old", 60_000)
      recent = state_message("b", "recent", 30_000)

      messages = [
        %{role: :user, content: "goal"},
        old,
        %{role: :user, content: "more"},
        recent
      ]

      assert {:ok, outcome} =
               Compaction.compact(messages,
                 keep_recent_tokens: @keep_recent,
                 target_tokens: 10_000_000
               )

      assert outcome.elided == 1
      refute outcome.summarised

      folded = Enum.find(outcome.messages, &Compaction.elided?/1)
      assert folded.content =~ "60003 bytes]"
    end
  end
end
