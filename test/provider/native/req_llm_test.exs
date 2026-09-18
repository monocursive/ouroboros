defmodule Ouroboros.Provider.Native.Model.ReqLLMTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Model.ReqLLM
  alias Ouroboros.Provider.Native.Checkpoint

  @cookie_canary "SYNTH_COOKIE_CANARY_7f21"
  @authorization_canary "SYNTH_AUTHORIZATION_CANARY_6c42"
  @request_canary "SYNTH_REQUEST_BODY_CANARY_930a"
  @response_canary "SYNTH_RESPONSE_BODY_CANARY_18de"

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

  test "replays a message's thinking on the xAI lanes and nowhere else" do
    messages = [
      %{role: :user, content: "Read the file"},
      %{
        role: :assistant,
        content: "It defines A.",
        thinking: "The file is short; summarise it.",
        tool_calls: []
      },
      %{role: :user, content: "Now edit it"}
    ]

    parts = fn model ->
      request = %{model: model, tools: [], messages: messages}
      assert {:ok, projection} = ReqLLM.project(request)
      assistant = Enum.find(projection["messages"], &(&1["role"] == "assistant"))
      Enum.map(assistant["content"], &{&1["type"], &1["text"]})
    end

    for lane <- ["xai:grok-4.6", "grok:grok-4.6"] do
      assert parts.(lane) == [
               {"thinking", "The file is short; summarise it."},
               {"text", "It defines A."}
             ]
    end

    # Anthropic binds thinking to signed blocks and refuses an unsigned one; the OpenAI
    # lanes carry theirs as encrypted reasoning items. Neither ever sees the text.
    for lane <- ["anthropic:claude-sonnet-5", "openai:gpt-5.6", "openai_codex:gpt-5.6-sol"] do
      assert parts.(lane) == [{"text", "It defines A."}]
    end

    assert ReqLLM.replays_thinking?("xai:grok-4.6")
    assert ReqLLM.replays_thinking?("grok:grok-4.6")
    refute ReqLLM.replays_thinking?("anthropic:claude-opus-5")
    refute ReqLLM.replays_thinking?(nil)
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

  test "formats API request failures without transport headers or bodies" do
    error =
      Elixir.ReqLLM.Error.API.Request.exception(
        reason: :timeout,
        status: 503,
        headers: [
          {"set-cookie", @cookie_canary},
          {"authorization", "Bearer " <> @authorization_canary}
        ],
        request_body: %{"prompt" => @request_canary},
        response_body: %{
          "error" => %{"message" => @response_canary, "code" => "upstream_timeout"}
        },
        provider_code: "upstream_timeout",
        retryable: true
      )

    formatted = ReqLLM.format_error(error)

    assert formatted ==
             "category=api status=503 provider_code=upstream_timeout retryable=true " <>
               "diagnostic=API request failed (503): timeout"

    assert byte_size(formatted) <= 1_024
    refute_canaries(formatted)
  end

  test "unwraps nested API classes and keeps policy rejection non-retryable" do
    leaf =
      Elixir.ReqLLM.Error.API.Request.exception(
        reason: "request rejected by provider policy",
        status: 400,
        headers: [{"set-cookie", @cookie_canary}],
        request_body: @request_canary,
        response_body: @response_canary,
        provider_code: "content_policy_violation",
        retryable: false
      )

    formatted = ReqLLM.format_error(Elixir.ReqLLM.Error.API.exception(errors: [leaf]))

    assert formatted =~ "category=api"
    assert formatted =~ "status=400"
    assert formatted =~ "provider_code=content_policy_violation"
    assert formatted =~ "retryable=false"
    assert formatted =~ "diagnostic=API request failed (400): request rejected by provider policy"
    assert byte_size(formatted) <= 1_024
    refute_canaries(formatted)
  end

  test "bounds malformed and nested causes without inspecting them" do
    cause = %{
      reason: String.duplicate("malformed ", 300),
      headers: [{"set-cookie", @cookie_canary}],
      body: @response_canary
    }

    error =
      Elixir.ReqLLM.Error.API.Request.exception(
        reason: nil,
        cause: {:error, {:http_task_failed, cause}},
        request_body: @request_canary
      )

    formatted = ReqLLM.format_error(error)

    assert formatted =~ "category=unknown"
    assert formatted =~ "retryable=false"
    assert formatted =~ "diagnostic=API request failed"
    assert byte_size(formatted) <= 1_024
    refute_canaries(formatted)
  end

  test "lazy streaming wrappers preserve structured API and transport causes" do
    for {cause, expected} <- [
          {Elixir.ReqLLM.Error.API.Request.exception(
             status: 429,
             provider_code: "rate_limit_exceeded",
             retryable: true
           ), "category=api status=429 provider_code=rate_limit_exceeded retryable=true"},
          {Req.TransportError.exception(reason: :timeout),
           "category=transport retryable=true diagnostic=transport failed: timeout"}
        ] do
      wrapped = %Elixir.ReqLLM.Error.API.Stream{reason: "SECRET signed URL cookie", cause: cause}
      assert ReqLLM.format_error(wrapped) =~ expected
      refute ReqLLM.format_error(wrapped) =~ "SECRET"
    end
  end

  defp refute_canaries(formatted) do
    refute formatted =~ @cookie_canary
    refute formatted =~ @authorization_canary
    refute formatted =~ @request_canary
    refute formatted =~ @response_canary
    refute formatted =~ "set-cookie"
    refute formatted =~ "authorization"
    refute formatted =~ "request_body"
    refute formatted =~ "response_body"
  end

  test "provider-controlled codes and unknown Unicode messages cannot become diagnostics" do
    for secret <- [
          "sk-proj-secret",
          "Bearer private",
          "https://private/?sig=secret",
          String.duplicate("é", 5000),
          <<255>>
        ] do
      error =
        Elixir.ReqLLM.Error.API.Request.exception(
          status: 403,
          provider_code: secret,
          reason: secret
        )

      formatted = ReqLLM.format_error(error)
      assert String.valid?(formatted)
      assert byte_size(formatted) < 1024
      assert formatted =~ "status=403"
      assert formatted =~ "provider_code=redacted"
      refute formatted =~ secret

      assert Ouroboros.Provider.Native.Model.format_error(
               __MODULE__,
               RuntimeError.exception(secret)
             ) =~ "category=unknown"
    end
  end
end
