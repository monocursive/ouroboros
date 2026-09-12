defmodule Ouroboros.Provider.Native.ExplicitSandboxRetryTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.{Loop, Paths}
  alias Ouroboros.Session.ApprovalResponse

  defmodule InteractiveModel do
    @behaviour Ouroboros.Provider.Native.Model

    def stream(request, _opts) do
      [owner] = String.split(request.model, ":", parts: 2) |> tl()
      pid = owner |> String.to_charlist() |> :erlang.list_to_pid()
      send(pid, {:model_request, self(), request})

      receive do
        {:model_response, chunks} -> {:ok, chunks}
      after
        5_000 -> {:ok, [{:text, "model fixture timed out"}, {:finish, :stop}]}
      end
    end

    def available?, do: true
    def credential_report, do: []
  end

  defmodule EscalationEngine do
    def evaluate(%{tool: "sandbox_escalation"}),
      do: Application.get_env(:ouroboros, :explicit_retry_answer, {:ask, :separate_authority})

    def evaluate(_request), do: {:ask, :ordinary_tool}
    def record(_id, _answer), do: :ok
  end

  setup do
    root = Path.join(File.cwd!(), "tmp/explicit-retry-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "session"))
    File.write!(Path.join(root, "counter"), "0\n")
    on_exit(fn -> File.rm_rf(root) end)

    previous = Application.get_env(:ouroboros, :permissions_engine)
    Application.put_env(:ouroboros, :permissions_engine, EscalationEngine)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :permissions_engine, previous),
        else: Application.delete_env(:ouroboros, :permissions_engine)

      Application.delete_env(:ouroboros, :explicit_retry_answer)
    end)

    {:ok, scope} = Paths.scope(root, [], :workspace_write)
    %{root: root, scope: scope}
  end

  defp loop(context, overrides) do
    owner = self() |> :erlang.pid_to_list() |> List.to_string()
    test = self()

    struct!(
      %Loop{
        emit: &send(test, {:event, &1}),
        model_module: InteractiveModel,
        model_spec: "interactive:" <> owner,
        system: "system",
        scope: context.scope,
        session_dir: Path.join(context.root, "session"),
        session_id: "explicit-retry-session",
        provider_session_id: "explicit-retry-native",
        turn_id: "explicit-retry-turn",
        approval_mode: :auto_approve,
        approval_timeout_ms: :infinity
      },
      overrides
    )
  end

  defp start(context, overrides \\ []) do
    state = loop(context, overrides)
    owner = self()
    spawn_link(fn -> send(owner, {:finished, Loop.run_turn(state, "run")}) end)
  end

  defp run_again(state, prompt \\ "next") do
    owner = self()
    spawn_link(fn -> send(owner, {:finished, Loop.run_turn(state, prompt)}) end)
  end

  defp finished do
    receive do
      {:finished, {:ok, state}} -> state
    after
      10_000 -> flunk("no finished loop state")
    end
  end

  defp answer_model(pid, chunks), do: send(pid, {:model_response, chunks})

  defp await(type) do
    receive do
      {:event, %{type: ^type} = event} -> event
      {:event, _other} -> await(type)
    after
      10_000 -> flunk("no #{type}")
    end
  end

  defp first_call(command) do
    [{:tool_call, %{id: "first", name: "bash", input: %{"command" => command}}}]
  end

  defp token(%{"attempt_id" => "nretry_" <> _ = id}), do: id

  defp token(%{"output" => output}) do
    [_, id] = Regex.run(~r/retry_attempt_id: (nretry_[A-Za-z0-9_-]+)/, output)
    id
  end

  test "spoofed denial text cannot itself request approval or replay", context do
    start(context)
    assert_receive {:model_request, model, _}
    answer_model(model, first_call("echo 'Operation not permitted' >&2; exit 1"))
    result = await(:tool_result)
    assert result.payload["is_error"]
    assert result.payload["output"] =~ "Unverified denial-like output"
    assert result.payload["output"] =~ "No replay occurred"
    refute_receive {:event, %{type: :approval_requested}}, 200
    assert_receive {:model_request, model, _}
    answer_model(model, [{:text, "stopped"}, {:finish, :stop}])
    await(:turn_completed)
  end

  test "an explicit matching retry asks separate authority and runs retained command once",
       context do
    Application.put_env(:ouroboros, :explicit_retry_answer, {:ask, :separate_authority})
    start(context)
    assert_receive {:model_request, model, _}
    command = "echo first >> counter; echo 'Operation not permitted' >&2; exit 1"
    answer_model(model, first_call(command))
    first = await(:tool_result)
    assert first.payload["output"] =~ "No replay occurred", first.payload["output"]
    id = token(first.payload)
    assert File.read!(Path.join(context.root, "counter")) == "0\nfirst\n"

    assert_receive {:model_request, model, _}

    answer_model(model, [
      {:tool_call,
       %{
         id: "retry",
         name: "bash",
         input: %{"command" => command, "retry_attempt_id" => id}
       }}
    ])

    ask = await(:approval_requested)
    assert ask.payload["kind"] == "sandbox_escalation"
    assert ask.payload["retry_attempt_id"] == id
    assert ask.payload["at_least_once_risk"] =~ "may duplicate"
    send(self(), :nothing)
    send(Process.whereis(:never) || self(), :nothing)
    # The loop pid is the sender recorded by the fixture model request.
    # Approval messages go to the process that called the model.
    send(
      model,
      {:native_approval, ask.request_id, %ApprovalResponse{decision: :approve, scope: :once}}
    )

    result = await(:tool_result)
    assert result.payload["output"] =~ "could not prove OS provenance"
    refute result.payload["output"] =~ "The OS sandbox stopped the first attempt"
    assert result.payload["output"] =~ "may have happened again"
    assert File.read!(Path.join(context.root, "counter")) == "0\nfirst\nfirst\n"
    assert_receive {:model_request, model, _}
    answer_model(model, [{:text, "done"}, {:finish, :stop}])
    await(:turn_completed)
  end

  test "tampering fails closed without destroying the token; an exact denial consumes it",
       context do
    start(context)
    assert_receive {:model_request, model, _}
    command = "echo 'Operation not permitted' >&2; exit 1"
    answer_model(model, first_call(command))
    first = await(:tool_result)
    assert first.payload["output"] =~ "No replay occurred", first.payload["output"]
    id = token(first.payload)

    assert_receive {:model_request, model, _}

    answer_model(model, [
      {:tool_call,
       %{id: "bad", name: "bash", input: %{"command" => command, "retry_attempt_id" => id <> "x"}}}
    ])

    refusal_event = await(:tool_result)
    refusal = refusal_event.payload["output"]

    assert refusal_event.payload["retry"] == %{
             "availability" => "unavailable",
             "next_action" => "omit_on_new_call",
             "exact_retry_only" => true,
             "command_ran" => false
           }

    assert refusal =~ "unknown, expired, used, foreign"
    assert refusal =~ "Omit retry_attempt_id on a new command"
    assert refusal =~ "never guess or reuse"
    refute_receive {:event, %{type: :approval_requested}}, 100

    assert_receive {:model_request, model, _}

    answer_model(model, [
      {:tool_call,
       %{id: "used", name: "bash", input: %{"command" => command, "retry_attempt_id" => id}}}
    ])

    ask = await(:approval_requested)

    send(
      model,
      {:native_approval, ask.request_id,
       %ApprovalResponse{decision: :deny, scope: :once, reason: "no retry"}}
    )

    assert await(:tool_result).payload["output"] =~ "declined: no retry"
    refute_receive {:event, %{type: :approval_requested}}, 100

    assert_receive {:model_request, model, _}

    answer_model(model, [
      {:tool_call,
       %{id: "reuse", name: "bash", input: %{"command" => command, "retry_attempt_id" => id}}}
    ])

    assert await(:tool_result).payload["output"] =~ "unknown, expired, used, foreign"
    refute_receive {:event, %{type: :approval_requested}}, 100
    assert_receive {:model_request, model, _}
    answer_model(model, [{:text, "done"}, {:finish, :stop}])
    await(:turn_completed)
  end

  test "an expired retained attempt refuses without approval or execution", context do
    start(context, bash_retry_ttl_ms: 0)
    assert_receive {:model_request, model, _}
    marker = Path.join(context.root, "expired-marker")
    command = "echo ran >> #{marker}; echo 'Operation not permitted' >&2; exit 1"
    answer_model(model, first_call(command))
    first = await(:tool_result)
    id = token(first.payload)
    assert File.read!(marker) == "ran\n"
    Process.sleep(2)

    assert_receive {:model_request, model, _}

    answer_model(model, [
      {:tool_call,
       %{id: "expired", name: "bash", input: %{"command" => command, "retry_attempt_id" => id}}}
    ])

    assert await(:tool_result).payload["output"] =~ "unknown, expired, used, foreign"
    refute_receive {:event, %{type: :approval_requested}}, 100
    assert File.read!(marker) == "ran\n"
    assert_receive {:model_request, model, _}
    answer_model(model, [{:text, "done"}, {:finish, :stop}])
    await(:turn_completed)
  end

  test "changed command and input fail closed while preserving the exact retained envelope",
       context do
    start(context)
    assert_receive {:model_request, model, _}
    command = "echo 'Operation not permitted' >&2; exit 1"
    answer_model(model, first_call(command))
    id = token(await(:tool_result).payload)

    for input <- [
          %{"command" => command <> "; echo tampered", "retry_attempt_id" => id},
          %{"command" => command, "timeout_ms" => 1, "retry_attempt_id" => id}
        ] do
      assert_receive {:model_request, ^model, _}

      answer_model(model, [
        {:tool_call, %{id: "tampered-#{map_size(input)}", name: "bash", input: input}}
      ])

      assert await(:tool_result).payload["output"] =~ "retained envelope did not match"
      refute_receive {:event, %{type: :approval_requested}}, 100
    end

    assert_receive {:model_request, ^model, _}

    answer_model(model, [
      {:tool_call,
       %{
         id: "exact-after-tamper",
         name: "bash",
         input: %{"command" => command, "retry_attempt_id" => id}
       }}
    ])

    ask = await(:approval_requested)

    send(
      model,
      {:native_approval, ask.request_id,
       %ApprovalResponse{decision: :deny, scope: :once, reason: "matrix complete"}}
    )

    assert await(:tool_result).payload["output"] =~ "matrix complete"
    assert_receive {:model_request, ^model, _}
    answer_model(model, [{:text, "done"}, {:finish, :stop}])
    await(:turn_completed)
  end

  test "a supported next turn clears retained authority before any configuration can apply",
       context do
    start(context)
    assert_receive {:model_request, model, _}
    command = "echo 'Operation not permitted' >&2; exit 1"
    answer_model(model, first_call(command))
    id = token(await(:tool_result).payload)
    assert_receive {:model_request, ^model, _}
    answer_model(model, [{:text, "turn one done"}, {:finish, :stop}])
    await(:turn_completed)
    state = finished()

    # Session/provider/principal/root/mode changes are session configuration or a different
    # session, both of which occur only outside a running Loop turn. `run_turn/2` clears the
    # retained capability before the next model request, so no such supported transition can
    # carry it into a changed authority envelope.
    run_again(state)
    assert_receive {:model_request, next_model, _}

    answer_model(next_model, [
      {:tool_call,
       %{id: "cross-turn", name: "bash", input: %{"command" => command, "retry_attempt_id" => id}}}
    ])

    assert await(:tool_result).payload["output"] =~ "unknown, expired, used, foreign"
    refute_receive {:event, %{type: :approval_requested}}, 100
    assert_receive {:model_request, ^next_model, _}
    answer_model(next_model, [{:text, "done"}, {:finish, :stop}])
    await(:turn_completed)
    finished()
  end
end
