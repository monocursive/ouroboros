defmodule Ouroboros.Gateway.OperateTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  @moduletag :capture_log

  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Coding.Store, as: CodingStore
  alias Ouroboros.Coding.Task, as: CodingTask
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Interactive.Ref, as: InteractiveRef
  alias Ouroboros.Interactive.Store, as: InteractiveStore
  alias Ouroboros.Interactive.Task, as: InteractiveTask
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager

  @token String.duplicate("o", 40)
  @receive_timeout 2_000

  setup context do
    start_supervised!({Task.Supervisor, name: :gateway_operate_test_tasks})

    start_supervised!(
      {DynamicSupervisor, strategy: :one_for_one, name: :gateway_operate_test_conns}
    )

    config =
      Config.new!(
        token: @token,
        data_dir: System.tmp_dir!(),
        scope: Map.get(context, :scope, :operate),
        allow_shutdown: Map.get(context, :allow_shutdown, false)
      )

    {client, conn} = connect(config)
    on_exit(fn -> :gen_tcp.close(client) end)

    %{client: client, conn: conn, config: config}
  end

  defp connect(config) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listen)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    {:ok, server} = :gen_tcp.accept(listen, 1_000)
    :ok = :gen_tcp.close(listen)

    {:ok, conn} =
      DynamicSupervisor.start_child(
        :gateway_operate_test_conns,
        {Conn, socket: server, config: config, task_supervisor: :gateway_operate_test_tasks}
      )

    :ok = :gen_tcp.controlling_process(server, conn)
    send(conn, :socket_ready)

    {client, conn}
  end

  defp call(client, method, params \\ %{}) do
    id = System.unique_integer([:positive])

    :ok =
      :gen_tcp.send(client, [
        JSON.encode_to_iodata!(%{
          "jsonrpc" => "2.0",
          "id" => id,
          "method" => method,
          "params" => params
        }),
        ?\n
      ])

    recv(client)
  end

  defp recv(client, timeout \\ @receive_timeout) do
    :ok = :inet.setopts(client, packet: :line, active: false, buffer: 1_048_576)

    case :gen_tcp.recv(client, 0, timeout) do
      {:ok, line} -> JSON.decode!(String.trim_trailing(line, "\n"))
      {:error, reason} -> {:error, reason}
    end
  end

  defp hello(client) do
    call(client, "hello", %{"token" => @token, "protocol" => 1, "client" => "operate-test"})
  end

  defp operate_methods do
    Methods.table()
    |> Enum.filter(fn {_name, entry} -> entry.scope == :operate end)
    |> Enum.map(fn {name, _entry} -> name end)
    |> Enum.sort()
  end

  describe "scope is the gate, and it is closed by default" do
    @describetag scope: :read

    test "every operate method is refused on a read listener", %{client: client} do
      assert hello(client)["result"]["scope"] == "read"

      # Enumerated from the table rather than listed here: a verb added with
      # `scope: :operate` is covered the moment it exists, and a verb that quietly loses
      # its scope fails this.
      for method <- operate_methods() do
        response = call(client, method)

        assert response["error"]["code"] == -32003, "#{method} was not refused under read scope"
        assert response["error"]["message"] =~ "OUROBOROS_GATEWAY_SCOPE=read"
      end

      # The connection survives every refusal.
      assert is_list(call(client, "agents.list")["result"])
    end

    test "a refused operate call never reaches a handler", %{client: client} do
      assert hello(client)["result"]

      log =
        capture_log(fn ->
          assert call(client, "interactive.kill", %{"id" => "whatever"})["error"]["code"] ==
                   -32003
        end)

      # No audit line, because there was no operate call — only an attempt.
      refute log =~ "gateway operate"
    end

    test "the read listener still advertises the operate methods it will refuse", %{
      client: client
    } do
      # A client feature-gates on `hello`, and hiding the verbs would make a read listener
      # look like an older build rather than like a listener with less authority.
      methods = hello(client)["result"]["methods"]

      for method <- operate_methods(), do: assert(method in methods)
    end
  end

  describe "an operate listener" do
    test "answers operate verbs, and refuses their parameters honestly", %{client: client} do
      assert hello(client)["result"]["scope"] == "operate"

      assert call(client, "interactive.kill", %{"id" => "no-such-session"})["error"]["code"] in [
               -32004,
               -32006,
               -32007
             ]

      assert call(client, "interactive.send_message", %{"id" => "x"})["error"]["code"] == -32602
      assert call(client, "teams.close", %{})["error"]["code"] == -32602
      assert call(client, "coding.start", %{})["error"]["code"] == -32602
    end

    test "a post-dispatch checkpoint failure is outcome-unknown, not a refusal" do
      turn_id = "caller-owned-turn"
      reason = {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn_id}

      assert {:error, -32_005, message, data} = Methods.turn_error_reply(reason)
      assert message =~ "may already be running"
      assert data["outcome"] == "unknown"
      assert data["turn_id"] == turn_id

      assert data["error"] == [
               "turn_dispatch_checkpoint_failed",
               "dispatch_may_have_started",
               turn_id
             ]

      # A Harness call exit and a refused call whose failure checkpoint was lost have the
      # same retry hazard. Every shape retains the caller's id for reconciliation.
      for ambiguous <- [
            {:turn_dispatch_ambiguous, turn_id},
            {:turn_dispatch_ambiguous, turn_id, :checkpoint_failed},
            {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn_id,
             {:harness_refused, :busy}},
            {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn_id,
             {:request_exposure_failed, :invalid_runtime_capture}}
          ] do
        assert {:error, -32_005, _message, %{"outcome" => "unknown", "turn_id" => ^turn_id}} =
                 Methods.turn_error_reply(ambiguous)
      end

      # A validation failure happened before dispatch and remains a definite refusal.
      assert {:error, -32_006, "the runtime refused the call", "invalid_turn"} =
               Methods.turn_error_reply(:invalid_turn)

      assert {:error, -32_006, busy_message,
              %{
                "reason" => "busy",
                "outcome" => "not_dispatched",
                "retry_with" => "interactive.follow_up",
                "error" => ["turn_dispatch_failed", "busy"]
              }} = Methods.turn_error_reply({:turn_dispatch_failed, :busy})

      assert busy_message =~ "already running a turn"
      assert busy_message =~ "interactive.follow_up"

      assert Methods.table()["interactive.send_message"].outcome == :unknown
      assert Methods.table()["interactive.follow_up"].outcome == :unknown
      assert Methods.table()["interactive.start"].outcome == :unknown
      assert Methods.table()["coding.start"].outcome == :unknown
    end

    test "structured turn input is closed and validated before dispatch", %{client: client} do
      assert hello(client)["result"]

      unknown =
        call(client, "interactive.send_message", %{
          "id" => "session",
          "input" => %{"prompt" => "inspect", "provider_options" => %{"unsafe" => true}}
        })

      assert unknown["error"]["code"] == -32602
      assert unknown["error"]["message"] =~ "provider_options"

      reasoning =
        call(client, "interactive.follow_up", %{
          "id" => "session",
          "input" => %{"prompt" => "continue", "reasoning_effort" => "unbounded"}
        })

      assert reasoning["error"]["code"] == -32602
      assert reasoning["error"]["message"] =~ "high, low, medium"

      attachments =
        call(client, "interactive.send_message", %{
          "id" => "session",
          "input" => %{"prompt" => "look", "attachments" => ["ok.png", ""]}
        })

      assert attachments["error"]["code"] == -32602
      assert attachments["error"]["message"] =~ "nonempty strings"

      extra_top_level =
        call(client, "interactive.send_message", %{
          "id" => "session",
          "input" => "inspect",
          "provider_options" => %{}
        })

      assert extra_top_level["error"]["code"] == -32602
      assert extra_top_level["error"]["message"] =~ "provider_options"
    end

    test "steer refuses a false idempotency key and accepts only its actual envelope", %{
      client: client
    } do
      assert hello(client)["result"]

      # Unlike dispatched turns, a steer is not durably keyed by the interactive plane.
      # Silently accepting this field would tell a client that replay is safe when it can
      # inject the same text twice.
      false_idempotency =
        call(client, "interactive.steer", %{
          "id" => "no-such-session",
          "input" => "go left",
          "turn_id" => "turn-1"
        })

      assert false_idempotency["error"]["code"] == -32602
      assert false_idempotency["error"]["message"] =~ "turn_id"

      steered =
        call(client, "interactive.steer", %{
          "id" => "no-such-session",
          "input" => "go left"
        })

      assert steered["error"]["code"] == -32007

      unknown =
        call(client, "interactive.steer", %{
          "id" => "session",
          "input" => "go left",
          "provider_options" => %{"unsafe" => true}
        })

      assert unknown["error"]["code"] == -32602
      assert unknown["error"]["message"] =~ "provider_options"

      structured =
        call(client, "interactive.steer", %{
          "id" => "session",
          "input" => %{"prompt" => "go left", "reasoning_effort" => "unbounded"}
        })

      assert structured["error"]["code"] == -32602
      assert structured["error"]["message"] =~ "high, low, medium"
    end

    test "an option outside the allowlist is refused rather than dropped", %{client: client} do
      assert hello(client)["result"]

      response =
        call(client, "interactive.start", %{"provider" => "codex", "env" => %{"KEY" => "value"}})

      assert response["error"]["code"] == -32602
      assert response["error"]["message"] =~ "env"

      # Naming the accepted set is what turns a refusal into something a client author can
      # act on without reading this build's source.
      assert response["error"]["message"] =~ "sandbox_mode"
      assert response["error"]["message"] =~ "runtime_exposure"
    end

    test "an unknown provider is a parameter error, not a new atom", %{client: client} do
      assert hello(client)["result"]

      response =
        call(client, "interactive.start", %{"provider" => "definitely_not_a_provider_atom"})

      assert response["error"]["code"] == -32602
      assert response["error"]["message"] =~ "must name a provider this node serves"

      # The atom table is never garbage collected, so "was it refused" is not the whole
      # question — "did the refusal cost an atom" is the other half, and this is the only
      # way to ask it that other tests running in the same VM cannot perturb.
      assert_raise ArgumentError, fn ->
        String.to_existing_atom("definitely_not_a_provider_atom")
      end
    end

    test "an enum value outside the schema is refused", %{client: client} do
      assert hello(client)["result"]

      response = call(client, "coding.start", %{"objective" => "x", "sandbox_mode" => "yolo"})

      assert response["error"]["code"] == -32602
      assert response["error"]["message"] =~ "workspace_write"
    end

    test "delete removes a terminal session and refuses a live one", %{client: client} do
      assert hello(client)["result"]

      live_id = "gateway-delete-live-#{System.unique_integer([:positive, :monotonic])}"
      dead_id = "gateway-delete-dead-#{System.unique_integer([:positive, :monotonic])}"

      {:ok, live} =
        Ouroboros.Interactive.State.new(live_id, provider: :codex, workspace: File.cwd!())

      {:ok, dead} =
        Ouroboros.Interactive.State.new(dead_id, provider: :codex, workspace: File.cwd!())

      assert :ok = InteractiveStore.create(live)
      assert :ok = InteractiveStore.create(%{dead | status: :lost, error: :provider_gone})

      live_error = call(client, "interactive.delete", %{"id" => live_id})["error"]
      assert live_error["code"] == -32006
      assert live_error["data"]["reason"] == "session_not_terminal"
      assert {:ok, _} = InteractiveStore.get(live_id)
      assert :ok = InteractiveStore.put(%{live | status: :cancelled})
      assert :ok = InteractiveStore.delete(live_id)

      assert call(client, "interactive.delete", %{"id" => dead_id})["result"] == "ok"
      assert :not_found = InteractiveStore.get(dead_id)

      assert call(client, "interactive.delete", %{"id" => "no-such-session"})["error"]["code"] ==
               -32007

      coding_live = "gateway-coding-delete-live-#{System.unique_integer([:positive, :monotonic])}"
      coding_dead = "gateway-coding-delete-dead-#{System.unique_integer([:positive, :monotonic])}"

      {:ok, coding_live_task} =
        Ouroboros.Coding.TaskState.new(coding_live, "still running",
          provider: :codex,
          workspace: File.cwd!()
        )

      {:ok, coding_dead_task} =
        Ouroboros.Coding.TaskState.new(coding_dead, "already failed",
          provider: :codex,
          workspace: File.cwd!()
        )

      assert :ok = CodingStore.create(coding_live_task)
      assert :ok = CodingStore.create(%{coding_dead_task | status: :failed, error: :boom})

      coding_live_error = call(client, "coding.delete", %{"id" => coding_live})["error"]
      assert coding_live_error["code"] == -32006
      assert coding_live_error["data"]["reason"] == "task_not_terminal"
      assert :ok = CodingStore.put(%{coding_live_task | status: :cancelled})
      assert :ok = CodingStore.delete(coding_live)

      assert call(client, "coding.delete", %{"id" => coding_dead})["result"] == "ok"
      assert :not_found = CodingStore.get(coding_dead)
    end

    test "durable failed starts return their stable reference and mismatches are definite", %{
      client: client
    } do
      assert hello(client)["result"]

      previous_providers = Application.get_env(:jido_harness, :providers)
      previous_config = Application.get_env(:jido_harness, :provider_config)
      suffix = System.unique_integer([:positive, :monotonic])
      workspace = Path.join(File.cwd!(), ".ouro-gateway-created-start-#{suffix}")
      File.mkdir_p!(workspace)

      Application.put_env(
        :jido_harness,
        :providers,
        Map.put(Map.new(previous_providers || %{}), :ouroboros_test, HarnessAdapter)
      )

      Application.put_env(
        :jido_harness,
        :provider_config,
        previous_config
        |> then(&Map.new(&1 || %{}))
        |> Map.put(:ouroboros_test, %{test_pid: self()})
      )

      unless is_pid(Process.whereis(WorkspaceManager)) do
        start_supervised!(
          {Workspace,
           allowed_roots: [File.cwd!()],
           name: WorkspaceManager,
           id: {:gateway_created_start_workspace, suffix}}
        )
      end

      holder_id = "gateway-workspace-holder-#{suffix}"
      interactive_id = "gateway-failed-interactive-#{suffix}"
      coding_id = "gateway-failed-coding-#{suffix}"

      on_exit(fn ->
        for {task, supervisor, id} <- [
              {InteractiveTask, Ouroboros.Interactive.TaskSupervisor, holder_id},
              {InteractiveTask, Ouroboros.Interactive.TaskSupervisor, interactive_id},
              {CodingTask, Ouroboros.Coding.TaskSupervisor, coding_id}
            ],
            pid = task.whereis(id),
            is_pid(pid) do
          _ = DynamicSupervisor.terminate_child(supervisor, pid)
        end

        # A non-terminal session cannot be deleted directly, and leaving one behind
        # whose workspace this callback is about to remove would poison every later
        # full-boot recovery with an unavailable path. Terminalize first, then delete.
        for session_id <- [holder_id, interactive_id] do
          case InteractiveStore.get(session_id) do
            {:ok, session} ->
              unless Ouroboros.Interactive.State.terminal?(session) do
                _ = InteractiveStore.put(%{session | status: :cancelled})
              end

              _ = InteractiveStore.delete(session_id)

            _absent ->
              :ok
          end
        end

        _ = CodingStore.delete(coding_id)

        if is_nil(previous_providers),
          do: Application.delete_env(:jido_harness, :providers),
          else: Application.put_env(:jido_harness, :providers, previous_providers)

        if is_nil(previous_config),
          do: Application.delete_env(:jido_harness, :provider_config),
          else: Application.put_env(:jido_harness, :provider_config, previous_config)

        File.rm_rf(workspace)
      end)

      assert call(client, "interactive.start", %{
               "id" => holder_id,
               "provider" => "ouroboros_test",
               "workspace" => workspace
             })["result"]["id"] == holder_id

      interactive_params = %{
        "id" => interactive_id,
        "provider" => "ouroboros_test",
        "workspace" => workspace
      }

      interactive = call(client, "interactive.start", interactive_params)["result"]
      assert interactive["id"] == interactive_id
      assert interactive["outcome"] == "created"
      assert interactive["ready"] == false
      assert interactive["error"]

      # The exact replay reads the terminal checkpoint and returns promptly with the same
      # reference; it does not wait through another gateway ceiling.
      retry = call(client, "interactive.start", interactive_params)["result"]
      assert retry["id"] == interactive_id
      assert retry["outcome"] == "created"

      interactive_conflict =
        call(
          client,
          "interactive.start",
          Map.put(interactive_params, "sandbox_mode", "read_only")
        )["error"]

      assert interactive_conflict["data"]["reason"] == "session_id_conflict"
      assert interactive_conflict["data"]["outcome"] == "not_dispatched"

      coding_params = %{
        "id" => coding_id,
        "objective" => "cannot acquire the held workspace",
        "provider" => "ouroboros_test",
        "workspace" => workspace
      }

      coding = call(client, "coding.start", coding_params)["result"]
      assert coding["id"] == coding_id
      assert coding["outcome"] == "created"
      assert coding["ready"] == false
      assert coding["error"]

      coding_retry = call(client, "coding.start", coding_params)["result"]
      assert coding_retry["id"] == coding_id
      assert coding_retry["outcome"] == "created"

      coding_conflict =
        call(client, "coding.start", Map.put(coding_params, "objective", "different request"))[
          "error"
        ]

      assert coding_conflict["data"]["reason"] == "task_id_conflict"
      assert coding_conflict["data"]["outcome"] == "not_dispatched"

      assert :ok = InteractiveSession.close(InteractiveRef.new(holder_id))
    end

    test "an approval response outside the allowlist is refused", %{client: client} do
      assert hello(client)["result"]

      for response <- ["maybe", %{"decision" => "approve", "provider_options" => %{"a" => 1}}] do
        answer =
          call(client, "interactive.respond_approval", %{
            "id" => "session",
            "request_id" => "request",
            "response" => response
          })

        assert answer["error"]["code"] == -32602
        assert answer["error"]["message"] =~ "approve"
      end
    end

    test "every operate call leaves one audit line naming the call and not its contents", %{
      client: client
    } do
      assert hello(client)["result"]

      log =
        capture_log(fn ->
          assert call(client, "control.submit", %{
                   "objective" => "a secret objective nobody should read in a log"
                 })
        end)

      lines = log |> String.split("\n") |> Enum.filter(&(&1 =~ "gateway operate"))

      assert [line] = lines
      assert line =~ "control.submit"
      assert line =~ "peer=127.0.0.1:"
      assert line =~ ~r/params=[0-9a-f]{16}/
      refute line =~ "a secret objective"
    end

    test "read methods leave no audit line", %{client: client} do
      assert hello(client)["result"]

      log = capture_log(fn -> assert call(client, "agents.list")["result"] end)

      refute log =~ "gateway operate"
    end
  end

  describe "runtime.shutdown needs a permission beyond its scope" do
    test "an operate listener without the flag is refused", %{client: client} do
      assert hello(client)["result"]

      response = call(client, "runtime.shutdown")

      assert response["error"]["code"] == -32003
      assert response["error"]["message"] =~ "OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1"
    end

    @tag allow_shutdown: true
    test "with the flag, the node stops only after the acknowledgement is written", %{
      client: client
    } do
      test_pid = self()

      # The stop is indirected exactly so this can be observed without stopping the VM
      # running the suite. What is under test is the *ordering*: by the time the stop
      # fires, the client's frame has already left this process.
      Application.put_env(:ouroboros, :gateway_stop_mfa, {Kernel, :send, [test_pid, :node_stop]})
      on_exit(fn -> Application.delete_env(:ouroboros, :gateway_stop_mfa) end)

      assert hello(client)["result"]

      log =
        capture_log(fn ->
          response = call(client, "runtime.shutdown")

          assert response["result"]["stopping"] == true
          assert response["result"]["node"] == Atom.to_string(node())

          assert_receive :node_stop, @receive_timeout
        end)

      assert log =~ "gateway accepted runtime.shutdown"
    end
  end
end
