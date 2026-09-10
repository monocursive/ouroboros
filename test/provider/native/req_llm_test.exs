defmodule Ouroboros.Provider.Native.Model.ReqLLMTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Model.ReqLLM
  alias Ouroboros.Provider.Native.Checkpoint

  describe "pre-reduction screenshot history" do
    @describetag :tmp_dir

    setup %{tmp_dir: dir} do
      bytes = "stored screenshot bytes"
      image = Path.join(dir, "screen.png")
      File.write!(image, bytes)
      digest = :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

      messages = [
        %{role: :user, content: "Describe the screen"},
        %{
          role: :assistant,
          content: "",
          tool_calls: [%{id: "screen", name: "desktop_state", input: %{}}]
        },
        %{
          role: :tool,
          tool_call_id: "screen",
          name: "desktop_state",
          content: [
            %{type: :text, text: "Saved screen tree"},
            %{type: :image, path: image, media_type: "image/png", sha256: digest}
          ]
        },
        %{role: :user, content: "Continue"}
      ]

      checkpoint = Path.join(dir, "conversation.json")
      assert {:ok, _} = Checkpoint.write(checkpoint, messages)
      assert {:ok, restored} = Checkpoint.read(checkpoint)

      %{
        request: %{model: "anthropic:claude-sonnet-5", tools: [], messages: restored},
        image: image,
        digest: digest,
        checkpoint: checkpoint
      }
    end

    test "a restored result preserves text and available image bytes in the model request", %{
      request: request,
      digest: digest,
      checkpoint: checkpoint
    } do
      before = File.read!(checkpoint)
      assert {:ok, projection} = ReqLLM.project(request)

      assert %{"content" => [text, image], "tool_call_id" => "screen"} =
               Enum.find(projection["messages"], &(&1["role"] == "tool"))

      assert text["type"] == "text"
      assert text["text"] == "Saved screen tree"
      assert image["type"] == "image"
      assert image["media_type"] == "image/png"
      assert image["data_sha256"] == digest
      assert File.read!(checkpoint) == before
    end

    for condition <- [:missing, :changed] do
      test "a #{condition} screenshot leaves a marker without blocking the next request", %{
        request: request,
        image: image,
        digest: digest
      } do
        case unquote(condition) do
          :missing -> File.rm!(image)
          :changed -> File.write!(image, "different bytes")
        end

        assert {:ok, projection} = ReqLLM.project(request)
        tool = Enum.find(projection["messages"], &(&1["role"] == "tool"))
        assert [text, marker] = tool["content"]
        assert text["text"] == "Saved screen tree"
        assert marker["type"] == "text"
        assert marker["text"] =~ "no longer available"
        assert marker["text"] =~ String.slice(digest, 0, 12)
        refute marker["text"] =~ "call desktop_state"
      end
    end

    test "a model without image support keeps the saved text", %{request: request} do
      request = %{request | model: "openai:gpt-4"}
      assert {:ok, projection} = ReqLLM.project(request)
      tool = Enum.find(projection["messages"], &(&1["role"] == "tool"))
      assert [%{"type" => "text", "text" => "Saved screen tree"}] = tool["content"]
    end
  end

  test "normalizes the finite finish-reason vocabulary" do
    assert ReqLLM.normalize_finish_reason("stop") == :stop
    assert ReqLLM.normalize_finish_reason("completed") == :stop
    assert ReqLLM.normalize_finish_reason("tool_use") == :tool_calls
    assert ReqLLM.normalize_finish_reason("max_output_tokens") == :length
    assert ReqLLM.normalize_finish_reason("content_filter") == :content_filter
    assert ReqLLM.normalize_finish_reason(:cancelled) == :cancelled
    assert ReqLLM.normalize_finish_reason(:provider_extension) == :unknown
  end

  test "provider-defined finish reasons cannot allocate atoms" do
    reason = "provider_finish_reason_#{System.unique_integer([:positive])}"

    assert_raise ArgumentError, fn -> String.to_existing_atom(reason) end
    assert ReqLLM.normalize_finish_reason(reason) == :unknown

    assert_raise ArgumentError, fn -> String.to_existing_atom(reason) end
  end
end
