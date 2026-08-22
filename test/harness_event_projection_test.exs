defmodule Ouroboros.HarnessEventProjectionTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.Event, as: HarnessEvent
  alias Jido.Harness.{EventLog, ProcessEvent, RunRequest, SessionRequest}
  alias Jido.Harness.Session.{EventStore, State}
  alias Ouroboros.Coding.Event, as: CodingEvent
  alias Ouroboros.Interactive.Event, as: InteractiveEvent
  alias Ouroboros.Provider.CodexAdapter

  defmodule CodexProcessManager do
    @moduledoc false

    def start_owned_process(spec, owner) do
      send(owner, {:codex_process_spec, spec})
      {:ok, "codex-process"}
    end

    def stream_process("codex-process") do
      started = %{
        "type" => "item.started",
        "thread_id" => "provider-session",
        "item" => %{
          "type" => "command_execution",
          "id" => "journalled-command",
          "command" => "mix test --token private-adapter-secret",
          "cwd" => "/tmp/project",
          "status" => "in_progress"
        }
      }

      completed = %{
        "type" => "item.completed",
        "thread_id" => "provider-session",
        "item" => %{
          "type" => "command_execution",
          "id" => "journalled-command",
          "command" => "mix test --token private-adapter-secret",
          "cwd" => "/tmp/project",
          "aggregated_output" => "private-adapter-secret output",
          "exit_code" => 0,
          "status" => "completed"
        }
      }

      started_event =
        ProcessEvent.new!(
          process_id: "codex-process",
          sequence: 1,
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
          type: :stdout,
          stream: :stdout,
          data: Jason.encode!(started) <> "\n"
        )

      completed_event =
        ProcessEvent.new!(
          process_id: "codex-process",
          sequence: 2,
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
          type: :stdout,
          stream: :stdout,
          data: Jason.encode!(completed) <> "\n"
        )

      {:ok, [started_event, completed_event]}
    end
  end

  test "Codex command start becomes the same durable redacted tool call in both planes" do
    harness_event =
      HarnessEvent.new!(
        provider: :codex,
        type: :provider_event,
        session_id: "harness-session",
        sequence: 7,
        payload: %{"type" => "item.started", "mapped" => false},
        raw: %{
          "type" => "item.started",
          "thread_id" => "provider-session",
          "item" => %{
            "type" => "command_execution",
            "id" => "item-42",
            "command" => "curl -H 'Authorization: Bearer live-secret'",
            "cwd" => "/tmp/project",
            "status" => "in_progress"
          }
        }
      )

    interactive = InteractiveEvent.from_harness("interactive-session", harness_event)
    coding = CodingEvent.from_harness("coding-task", 11, harness_event)

    expected_payload = %{
      "call_id" => "item-42",
      "name" => "exec_command",
      "input" => %{
        "cmd" => "curl -H 'Authorization: Bearer [REDACTED]",
        "cwd" => "/tmp/project"
      }
    }

    assert interactive.type == :tool_call
    assert interactive.payload == expected_payload
    assert interactive.sequence == 7

    assert coding.type == :tool_call
    assert coding.payload == expected_payload
    assert coding.sequence == 11
    assert coding.harness_sequence == 7

    refute Map.has_key?(Map.from_struct(interactive), :raw)
    refute Map.has_key?(Map.from_struct(coding), :raw)
    refute inspect(interactive) =~ "live-secret"
    refute inspect(coding) =~ "live-secret"
  end

  test "other opaque provider events retain their canonical type and payload" do
    harness_event =
      HarnessEvent.new!(
        provider: :codex,
        type: :provider_event,
        sequence: 3,
        payload: %{"type" => "item.started", "mapped" => false},
        raw: %{
          "type" => "item.started",
          "item" => %{"type" => "agent_message", "id" => "item-7"}
        }
      )

    interactive = InteractiveEvent.from_harness("interactive-session", harness_event)
    coding = CodingEvent.from_harness("coding-task", 5, harness_event)

    assert interactive.type == :provider_event
    assert interactive.payload == %{"type" => "item.started", "mapped" => false}
    assert coding.type == :provider_event
    assert coding.payload == interactive.payload
  end

  test "the configured Codex adapter redacts effective provider env before session journal replay" do
    journal_dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-command-start-journal-#{System.unique_integer([:positive, :monotonic])}"
      )

    on_exit(fn -> File.rm_rf(journal_dir) end)

    assert {:ok, CodexAdapter} = Jido.Harness.Registry.lookup(:codex)

    run_spec = Jido.Harness.Adapters.Codex.spec()
    spec = CodexAdapter.spec()
    assert spec.normalized_options == run_spec.normalized_options
    assert spec.default_session_transport == :app_server
    assert Enum.map(spec.session_transports, & &1.name) == [:app_server, :exec_jsonl_resume]
    assert hd(spec.session_transports).adapter == Ouroboros.Provider.CodexSession
    assert hd(spec.session_transports).capabilities.approvals == :native

    run_request =
      RunRequest.new!(
        prompt: "build",
        cwd: File.cwd!(),
        env: %{}
      )

    context = %{
      run_id: "run-command-start",
      provider: :codex,
      config: %{
        cli_path: "/configured/codex",
        env: %{"CODEX_API_KEY" => "private-adapter-secret"}
      },
      telemetry_context: %{},
      process_manager: CodexProcessManager,
      run_owner: self()
    }

    assert {:ok, stream} = CodexAdapter.run(run_request, context)
    events = Enum.to_list(stream)
    assert [started_event, completed_call, completed_result] = events
    assert Enum.map(events, & &1.type) == [:tool_call, :tool_call, :tool_result]

    Enum.each(events, fn event ->
      assert event.raw != nil
      refute inspect(event.payload) =~ "private-adapter-secret"
      refute inspect(event.raw) =~ "private-adapter-secret"
    end)

    assert started_event.payload["input"]["cmd"] == "mix test --token [REDACTED]"
    assert completed_call.payload["input"]["cmd"] == "mix test --token [REDACTED]"
    assert completed_result.payload["output"] == "[REDACTED] output"

    assert_receive {:codex_process_spec,
                    %{
                      executable: "/configured/codex",
                      argv: argv,
                      env: %{"CODEX_API_KEY" => "private-adapter-secret"}
                    }}

    assert Enum.take(argv, 2) == ["exec", "--json"]

    request = SessionRequest.new!(cwd: File.cwd!())

    state = %State{
      id: "production-shaped-session",
      provider: :codex,
      request: request,
      adapter: CodexAdapter,
      session_adapter: Jido.Harness.SessionAdapters.Managed,
      transport_spec: nil,
      context: %{},
      started_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      buffer: EventLog.new_buffer(1_048_576),
      journal: EventLog.open("production-shaped-session", %{journal_dir: journal_dir})
    }

    assert state.journal != nil

    state = Enum.reduce(events, state, &EventStore.append(&2, &1))
    assert {replayed, _state} = EventStore.replay(state, 0, 10)
    assert length(replayed) == 3

    Enum.each(replayed, fn event ->
      assert event.raw == nil
      refute inspect(event.payload) =~ "private-adapter-secret"
    end)

    replayed_start = hd(replayed)
    replayed_result = List.last(replayed)

    assert replayed_start.type == :tool_call

    assert replayed_start.payload == %{
             "call_id" => "journalled-command",
             "name" => "exec_command",
             "input" => %{"cmd" => "mix test --token [REDACTED]", "cwd" => "/tmp/project"}
           }

    assert replayed_result.type == :tool_result
    assert replayed_result.payload["output"] == "[REDACTED] output"

    projected = InteractiveEvent.from_harness("interactive-session", replayed_start)
    assert projected.type == :tool_call
    assert projected.payload == replayed_start.payload

    coding = CodingEvent.from_harness("coding-task", 1, replayed_start)
    assert coding.type == :tool_call
    assert coding.payload == replayed_start.payload
  end
end
