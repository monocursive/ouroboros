defmodule Ouroboros.Provider.Session.DialectTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Session
  alias Ouroboros.Provider.Session.Dialect
  alias Ouroboros.Test.CodexSchema

  test "every shipped dialect implements the full callback set" do
    dialects = Session.dialects()
    assert Dialect.Codex in dialects
    assert Dialect.ACP in dialects

    for module <- Session.dialects() do
      assert :ok = Dialect.verify!(module)
      caps = module.capabilities()
      assert caps.approvals == :native
      assert caps.interrupt == :native
    end

    # Steering is the one interaction the two dialects no longer answer alike, so each
    # one's refusal is asserted by name rather than through a shared loop. ACP has no
    # steer verb at all and says so; the app server has `turn/steer` but its
    # `expectedTurnId` is a precondition, so a runtime with no open thread is refused
    # here rather than on the wire.
    assert Dialect.ACP.capabilities().steer == false
    assert Dialect.ACP.steer(%{}, %{prompt: "x"}, "req") == {:error, :unsupported}

    assert Dialect.Codex.capabilities().steer == :native
    assert Dialect.Codex.steer(%{}, %{prompt: "x"}, "req") == {:error, :session_not_open}

    assert Dialect.Codex.steer(
             %{provider_session_id: "thread-1", provider_turn_id: nil},
             %{prompt: "x"},
             "req"
           ) == {:error, :no_active_turn}

    # `configure` is where the two dialects genuinely differ, so the completeness test
    # asserts each one's own answer rather than a shared refusal. The app server rebuilds
    # model, effort, approval policy and sandbox on every `turn/start`, so a change is
    # accepted and lands next turn. ACP's only configuration verb takes an agent-invented
    # mode id that Ouroboros's normalized vocabulary does not map onto, so it refuses.
    assert Dialect.Codex.configure(%{}, %{approval_mode: :auto_approve}) == :ok
    assert Dialect.Codex.configure(%{}, %{}) == :ok

    assert Dialect.Codex.configure(%{}, %{system_prompt: "x"}) ==
             {:error, {:unsupported_configuration, :system_prompt}}

    assert Dialect.ACP.configure(%{}, %{approval_mode: :auto_approve}) == {:error, :unsupported}
  end

  test "the app server's compaction frame is built, and a capability now claims it" do
    assert Dialect.Codex.compact_request(%{provider_session_id: "thread-1"}) ==
             {:request, "thread/compact/start", %{"threadId" => "thread-1"}}

    CodexSchema.assert_valid!(%{"threadId" => "thread-1"}, "ThreadCompactStartParams")

    assert Dialect.Codex.compact_request(%{provider_session_id: nil}) ==
             {:error, :session_not_open}

    # C4 routed it, so the honesty half moved rather than disappeared: there is now a
    # `compact` capability key, it says `:provider` for Codex, and it is still not an
    # `InteractionCapabilities` field — the harness has no notion of folding a session, so
    # the claim is derived from the dialect's own `compact_option/0`.
    assert :compact in Ouroboros.Provider.capability_keys()
    assert Ouroboros.Provider.session_compact(:codex) == :provider
    assert Dialect.Codex.compact_option() == {:compact, :provider}
    refute Map.has_key?(Dialect.Codex.capabilities(), :compact)

    # `ask/3` is the only route to the wire, and a focus is refused there rather than
    # dropped, because `ThreadCompactStartParams` has nowhere to put one.
    assert {:request, "thread/compact/start", %{"threadId" => "thread-1"}} =
             Dialect.Codex.ask(:compact, %{focus: nil}, %{provider_session_id: "thread-1"})

    assert {:error, {:unsupported_on_transport, %{reason: :focus_not_supported}}} =
             Dialect.Codex.ask(:compact, %{focus: "the plan"}, %{provider_session_id: "thread-1"})
  end

  test "model/list sends only the options that were stated" do
    assert Dialect.Codex.model_list_request() == {:request, "model/list", %{}}

    assert {:request, "model/list", params} =
             Dialect.Codex.model_list_request(limit: 5, include_hidden: false)

    assert params == %{"limit" => 5, "includeHidden" => false}
    CodexSchema.assert_valid!(params, "ModelListParams")

    # `includeHidden: nil` is "unstated", not "false" — the schema's default is the
    # server's to choose and this must not choose it for them.
    assert {:request, "model/list", %{}} = Dialect.Codex.model_list_request(include_hidden: nil)
  end

  test "a model/list result reads its rows from data, dropping any the runtime cannot name" do
    # Trimmed from a real `codex app-server --stdio` answer. The rows live under `data`
    # — the key `ModelListResponse` requires — which is checked here rather than taken on
    # trust, because reading a plausible-looking `models` instead is exactly the mistake
    # a literal fixture would have preserved.
    result = %{
      "data" => [
        %{
          "id" => "gpt-5.6-sol",
          "model" => "gpt-5.6-sol",
          "displayName" => "GPT-5.6-Sol",
          "description" => "Latest frontier agentic coding model.",
          "isDefault" => false,
          "hidden" => false,
          "defaultReasoningEffort" => "low",
          "inputModalities" => ["text", "image"],
          "supportedReasoningEfforts" => [
            %{"reasoningEffort" => "low", "description" => "Fast responses"}
          ]
        }
      ],
      "nextCursor" => "page-2"
    }

    CodexSchema.assert_valid!(result, "ModelListResponse")

    assert %{models: [model], next_cursor: "page-2"} = Dialect.Codex.models(result)
    assert model.id == "gpt-5.6-sol"
    assert model.display_name == "GPT-5.6-Sol"
    assert model.default_reasoning_effort == "low"
    refute model.default
    refute model.hidden
    assert model.input_modalities == ["text", "image"]

    # An absent field is absent, not `nil`: a picker must be able to tell "the server said
    # nothing" from "the server said no". A row with no `id` is dropped outright, because
    # there is nothing to select it by. Neither shape is schema-valid — the point is what
    # this reader does when a future server sends one anyway.
    sparse = %{"data" => [%{"id" => "only-an-id"}, %{"displayName" => "a row with no id"}]}

    assert %{models: [row], next_cursor: nil} = Dialect.Codex.models(sparse)
    assert row == %{id: "only-an-id", default: false, hidden: false, input_modalities: []}

    assert Dialect.Codex.models(%{}) == %{models: [], next_cursor: nil}
  end

  test "a dialect that omits a callback is refused by name" do
    defmodule Incomplete do
    end

    assert_raise ArgumentError, ~r/missing/, fn ->
      Dialect.verify!(Incomplete)
    end
  end

  test "kimi and opencode interactive sessions use the shared ACP adapter" do
    {:ok, kimi} = Jido.Harness.Registry.spec(:kimi)
    {:ok, opencode} = Jido.Harness.Registry.spec(:opencode)

    assert hd(kimi.session_transports).adapter == Session.ACP
    assert hd(opencode.session_transports).adapter == Session.ACP
    assert hd(kimi.session_transports).capabilities.approvals == :native
    assert hd(opencode.session_transports).capabilities.approvals == :native
  end
end
