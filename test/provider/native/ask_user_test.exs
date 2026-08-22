defmodule Ouroboros.Provider.Native.AskUserTest do
  @moduledoc """
  `ask_user` through the loop, because that is the only place it exists.

  It is the one tool the loop answers itself, on the approval channel, so every test
  here drives a real turn and reads the `approval_requested` the loop emitted.
  """

  use ExUnit.Case, async: true

  alias Jido.Harness.ApprovalResponse
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.AskUser
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-ask-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace"))
    File.mkdir_p!(Path.join(root, "session"))
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)
    %{root: root, scope: scope, session_dir: Path.join(root, "session")}
  end

  defp start_loop(context, script, overrides \\ []) do
    {model_spec, agent} = NativeModelScript.start(script)
    test = self()

    loop =
      struct!(
        %Loop{
          emit: fn event -> send(test, {:event, event}) end,
          model_module: NativeModelScript,
          model_spec: model_spec,
          system: "system",
          scope: context.scope,
          session_dir: context.session_dir,
          session_id: "sess-1",
          provider_session_id: "native-x-y",
          turn_id: "turn-1",
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000
        },
        overrides
      )

    {loop, agent}
  end

  defp run(loop) do
    parent = self()
    spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "do the thing")}) end)
  end

  defp collect(acc \\ []) do
    receive do
      {:event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:event, event} ->
        collect([event | acc])
    after
      15_000 -> flunk("no terminal turn event within 15s")
    end
  end

  defp await_request(type) do
    receive do
      {:event, %{type: ^type} = event} -> event
    after
      10_000 -> flunk("no #{type} within 10s")
    end
  end

  @script [
    [
      {:tool_call,
       %{
         id: "q1",
         name: "ask_user",
         input: %{
           "question" => "Postgres or SQLite?",
           "options" => ["Postgres", "SQLite"],
           "header" => "Datastore"
         }
       }}
    ],
    [{:text, "understood"}, {:finish, :stop}]
  ]

  test "emits an approval-shaped question and blocks until it is answered", context do
    {loop, _agent} = start_loop(context, @script)
    pid = run(loop)

    request = await_request(:approval_requested)

    assert request.payload["kind"] == "question"
    assert request.payload["question"] == "Postgres or SQLite?"
    assert request.payload["options"] == ["Postgres", "SQLite"]
    assert request.payload["header"] == "Datastore"
    assert is_binary(request.request_id)

    send(
      pid,
      {:native_approval, request.request_id,
       ApprovalResponse.new!(%{decision: :approve, provider_options: %{"answer" => "SQLite"}})}
    )

    events = collect()
    [result] = Enum.filter(events, &(&1.type == :tool_result))

    refute result.payload["is_error"]
    assert result.payload["output"] =~ "The operator answered: SQLite"
  end

  test "a client that only knows approvals can answer with the reason field", context do
    {loop, _agent} = start_loop(context, @script)
    pid = run(loop)
    request = await_request(:approval_requested)

    send(
      pid,
      {:native_approval, request.request_id,
       ApprovalResponse.new!(%{decision: :approve, reason: "Postgres, we already run it"})}
    )

    [result] = collect() |> Enum.filter(&(&1.type == :tool_result))
    assert result.payload["output"] =~ "Postgres, we already run it"
  end

  test "declining to answer is information, not a tool failure", context do
    {loop, _agent} = start_loop(context, @script)
    pid = run(loop)
    request = await_request(:approval_requested)

    send(
      pid,
      {:native_approval, request.request_id,
       ApprovalResponse.new!(%{decision: :deny, reason: "you decide"})}
    )

    [result] = collect() |> Enum.filter(&(&1.type == :tool_result))

    refute result.payload["is_error"]
    assert result.payload["output"] =~ "declined to answer"
    assert result.payload["output"] =~ "you decide"
  end

  test "nobody answering is the approval timeout, and the turn continues", context do
    {loop, _agent} = start_loop(context, @script, approval_timeout_ms: 150)
    run(loop)
    await_request(:approval_requested)

    events = collect()
    [result] = Enum.filter(events, &(&1.type == :tool_result))

    refute result.payload["is_error"]
    assert result.payload["output"] =~ "Nobody answered the question within 150 ms"
    assert List.last(events).type == :turn_completed
  end

  test "an interrupt while waiting stops the turn", context do
    {loop, _agent} = start_loop(context, @script)
    pid = run(loop)
    await_request(:approval_requested)

    send(pid, :native_interrupt)

    assert List.last(collect()).type == :turn_interrupted
  end

  test "a question with no text is refused in-band without asking anybody", context do
    script = [
      [{:tool_call, %{id: "q1", name: "ask_user", input: %{"options" => ["a"]}}}],
      [{:text, "ok"}, {:finish, :stop}]
    ]

    {loop, _agent} = start_loop(context, script)
    run(loop)
    events = collect()

    assert Enum.filter(events, &(&1.type == :approval_requested)) == []
    [result] = Enum.filter(events, &(&1.type == :tool_result))
    assert result.payload["is_error"]
    assert result.payload["output"] =~ "needs a `question`"
  end

  describe "the payload itself" do
    test "is bounded: the question, the header, and the number of options" do
      {:ok, payload} =
        AskUser.question(%{
          "question" => String.duplicate("q", 10_000),
          "header" => String.duplicate("h", 500),
          "options" => Enum.map(1..50, &"option #{&1} #{String.duplicate("o", 1_000)}")
        })

      assert byte_size(payload["question"]) <= 2_010
      assert byte_size(payload["header"]) <= 90
      assert length(payload["options"]) == 8
      assert Enum.all?(payload["options"], &(byte_size(&1) <= 210))
    end

    test "options that are not usable strings are dropped rather than rendered" do
      {:ok, payload} = AskUser.question(%{"question" => "q", "options" => ["a", "", "  "]})
      assert payload["options"] == ["a"]

      {:ok, bare} = AskUser.question(%{"question" => "q"})
      assert bare["options"] == []
    end
  end

  test "outside an interactive session the tool says there is nobody to ask", context do
    result =
      Tools.execute(
        AskUser,
        %{"question" => "anyone?"},
        %{scope: context.scope, session_dir: context.session_dir, reads: %{}},
        5_000
      )

    assert result.is_error
    assert result.output =~ "there is nobody to ask"
  end

  test "ask_user reads: it touches no path and runs no command", %{scope: scope} do
    classified = Tools.classify("ask_user", %{"question" => "q"}, scope)

    assert classified.mode == :read
    assert classified.paths == []
    assert classified.command == nil
  end
end
