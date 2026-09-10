defmodule Ouroboros.SessionRequestContractTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Session.{ApprovalResponse, Error, Request, RuntimeEvent, TurnRequest}

  test "session defaults and timeout refusals remain stable" do
    assert {:ok, request} = Request.new(%{})
    assert request.cwd == File.cwd!()
    assert request.approval_mode == :default
    assert request.sandbox_mode == :default
    assert request.env_mode == :overlay
    assert request.turn_runtime_timeout_ms == :infinity
    assert request.approval_timeout_ms == :infinity
    refute request.plan

    for field <- [
          :turn_runtime_timeout_ms,
          :turn_idle_timeout_ms,
          :session_idle_timeout_ms,
          :approval_timeout_ms
        ],
        invalid <- [0, -1, 1.5, "100"] do
      assert {:error, %Error{category: :validation, message: message}} =
               Request.new(%{field => invalid})

      assert message == "#{field} must be :infinity or a positive integer"
    end

    assert {:error, %Error{message: "cwd must be an existing directory"}} =
             Request.new(%{cwd: Path.join(File.cwd!(), "absent-session-cwd")})
  end

  test "plan is explicit and options cannot shadow normalized authority" do
    assert {:ok, %{plan: true, approval_mode: :prompt}} =
             Request.new(%{"plan" => true, "approval_mode" => :prompt})

    for key <- [:plan, "approval_mode", :reasoning_effort] do
      assert {:error, %Error{message: "provider_options cannot shadow normalized fields"}} =
               Request.new(%{provider_options: %{key => true}})
    end
  end

  test "turn input preserves prompt and multimodal validation" do
    assert {:ok, %TurnRequest{prompt: "hello"}} = TurnRequest.new("hello")
    content = [%{type: "text", text: "look"}, %{type: "image", data: "image-ref"}]
    assert {:ok, %TurnRequest{content: ^content}} = TurnRequest.new(%{content: content})

    for attrs <- [%{}, %{prompt: " "}, %{prompt: "hello", content: content}] do
      assert {:error,
              %Error{message: "turn requires either a non-empty prompt or content blocks"}} =
               TurnRequest.new(attrs)
    end

    assert {:error, %Error{message: "unknown turn request option"}} =
             TurnRequest.new(%{"prompt" => "hello", "new_atom_must_not_exist" => true})
  end

  test "approval decisions and correlation options retain their shape" do
    assert {:ok, %ApprovalResponse{decision: :deny, scope: :once, provider_options: %{}}} =
             ApprovalResponse.new(:deny)

    assert {:ok, %ApprovalResponse{scope: :session, provider_options: %{actor: "operator"}}} =
             ApprovalResponse.new(%{
               decision: :approve,
               scope: :session,
               provider_options: %{actor: "operator"}
             })

    assert {:error, %Error{message: "invalid approval response"}} =
             ApprovalResponse.new(%{decision: :allow})
  end

  test "event payloads keep string keys and generation-local identity" do
    event =
      RuntimeEvent.new!(
        type: :tool_call,
        provider: :native,
        session_id: "runtime-1",
        provider_session_id: "native-1",
        generation: "generation-1",
        sequence: 3,
        payload: %{arguments: %{path: "file"}, items: [%{ok: true}]}
      )

    assert event.payload == %{
             "arguments" => %{"path" => "file"},
             "items" => [%{"ok" => true}]
           }

    assert event.session_id != event.provider_session_id
    assert event.sequence == 3
    assert event.generation == "generation-1"
  end
end
