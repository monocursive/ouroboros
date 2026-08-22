defmodule Ouroboros.Provider.Native.CompactionTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Context.Archive
  alias Ouroboros.Provider.Native.Context.Compaction
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-compact-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)

    previous = %{
      dir: Application.get_env(:ouroboros, :native_data_dir),
      model: Application.get_env(:ouroboros, :native_model_module),
      window: Application.get_env(:ouroboros, :native_context_window)
    }

    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      restore(:native_data_dir, previous.dir)
      restore(:native_model_module, previous.model)
      restore(:native_context_window, previous.window)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, data_dir: data_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  # ---------------------------------------------------------------- fixtures

  defp user(text), do: %{role: :user, content: text}

  defp assistant(text, calls \\ []),
    do: %{role: :assistant, content: text, tool_calls: calls}

  defp tool_result(id, name, content),
    do: %{role: :tool, tool_call_id: id, name: name, content: content, is_error: false}

  # A conversation whose old half is dominated by two very large tool results and whose
  # new half is small prose. The sizes are what makes the ordering assertion meaningful.
  defp conversation do
    [
      user("start the work"),
      assistant("reading", [%{id: "c1", name: "read", input: %{"path" => "a.ex"}}]),
      tool_result("c1", "read", String.duplicate("A", 40_000)),
      assistant("running", [%{id: "c2", name: "bash", input: %{"command" => "ls"}}]),
      tool_result("c2", "bash", String.duplicate("B", 40_000)),
      assistant("that is what I found"),
      user("carry on"),
      assistant("carrying on")
    ]
  end

  # ---------------------------------------------------------------- the meter

  describe "the meter" do
    test "reports the last request's size and the window" do
      payload = %{"input_tokens" => 1_200, "cache_read_tokens" => 0, "cache_creation_tokens" => 0}
      metered = Window.meter(payload, 200_000)

      assert metered["context_used"] == 1_200
      assert metered["context_window"] == 200_000
    end

    test "says unknown by omitting the window, never by inventing one" do
      metered = Window.meter(%{"input_tokens" => 10}, nil)

      assert metered["context_used"] == 10
      refute Map.has_key?(metered, "context_window")
    end

    test "an unknown model resolves to no window at all" do
      assert Window.resolve("not-a-provider:not-a-model") == nil
      assert Window.resolve(nil) == nil
    end

    test "a node may state a window llm_db does not know" do
      Application.put_env(:ouroboros, :native_context_window, 123_456)
      assert Window.resolve("not-a-provider:not-a-model") == 123_456
    end

    test "cached reads counted inside input are not added twice" do
      payload = %{
        "input_tokens" => 1_000,
        "cache_read_tokens" => 900,
        "cache_creation_tokens" => 0
      }

      assert Window.used(payload) == 1_000
    end

    test "cached reads counted beside input are added" do
      payload = %{
        "input_tokens" => 100,
        "cache_read_tokens" => 900,
        "cache_creation_tokens" => 0
      }

      assert Window.used(payload) == 1_000
    end

    test "the threshold never fires on an unknown window" do
      refute Window.over_threshold?(999_999_999, nil, 0.85)
      assert Window.over_threshold?(85, 100, 0.85)
      refute Window.over_threshold?(84, 100, 0.85)
    end

    test "the defaults are the documented ones" do
      assert Window.default_compact_at() == 0.85
      assert Window.default_keep_recent_tokens() == 20_000
      assert Window.compact_at(%{}) == 0.85
      assert Window.compact_at(%{compact_at: 0.5}) == 0.5
      assert Window.keep_recent_tokens(%{"keep_recent_tokens" => 42}) == 42
    end

    test "the loop merges the meter into every usage event", context do
      Application.put_env(:ouroboros, :native_context_window, 50_000)
      session = open(context, [[{:text, "hi"}, {:usage, %{input_tokens: 700, output_tokens: 3}}]])

      events = turn(session, "t1")
      usage = Enum.find(events, &(&1.type == :usage))

      assert usage.payload["context_window"] == 50_000
      assert usage.payload["context_used"] == 700
    end
  end

  # ---------------------------------------------------------------- ordering

  describe "tool results go first" do
    test "eliding alone is enough when it gets under the target" do
      {:ok, outcome} = Compaction.compact(conversation(), keep_recent_tokens: 200)

      assert outcome.elided == 2
      refute outcome.summarised
      assert outcome.archived == []
    end

    test "an elided result names its own size so the model can re-run the tool" do
      {:ok, outcome} = Compaction.compact(conversation(), keep_recent_tokens: 200)

      elided =
        outcome.messages
        |> Enum.filter(&(Map.get(&1, :role) == :tool))
        |> Enum.map(& &1.content)

      assert Enum.all?(elided, &String.starts_with?(&1, "[tool result elided:"))
      assert Enum.any?(elided, &(&1 =~ "40000 bytes"))
    end

    test "the newest turns are kept verbatim" do
      {:ok, outcome} = Compaction.compact(conversation(), keep_recent_tokens: 200)
      tail = Enum.take(outcome.messages, -3)

      assert tail == Enum.take(conversation(), -3)
    end

    test "an already-elided result is not elided again" do
      {:ok, once} = Compaction.compact(conversation(), keep_recent_tokens: 200)
      {:ok, twice} = Compaction.compact(once.messages, keep_recent_tokens: 200)

      assert twice.elided == 0
    end

    test "summarising happens only when eliding was not enough" do
      long = for index <- 1..400, do: user("a fairly wordy operator message number #{index}")

      {:ok, outcome} =
        Compaction.compact(long,
          keep_recent_tokens: 50,
          summarize: fn _payload -> {:ok, "## Goal\n\nx"} end
        )

      assert outcome.summarised
      assert outcome.archived != []
    end
  end

  # ---------------------------------------------------------------- summary

  describe "the summary" do
    test "the instruction names Pi's five headings in order" do
      instruction = Compaction.summary_instruction(nil)

      positions =
        for heading <- [
              "## Goal",
              "## Constraints",
              "## Progress",
              "## Decisions",
              "## Next steps"
            ] do
          assert instruction =~ heading
          instruction |> String.split(heading) |> hd() |> byte_size()
        end

      assert positions == Enum.sort(positions)
    end

    test "a focus is added without removing a heading" do
      instruction = Compaction.summary_instruction("the migration only")

      assert instruction =~ "focus on: the migration only"
      assert instruction =~ "## Next steps"
    end

    test "the structural fallback keeps the same five headings" do
      summary = Compaction.structural_summary(conversation(), nil)

      for heading <- ["## Goal", "## Constraints", "## Progress", "## Decisions", "## Next steps"] do
        assert summary =~ heading
      end

      assert summary =~ "read ×1"
      assert summary =~ "bash ×1"
    end

    test "a summariser that fails falls back to the structural summary rather than losing it" do
      long = for index <- 1..400, do: user("wordy operator message number #{index}")

      {:ok, outcome} =
        Compaction.compact(long,
          keep_recent_tokens: 50,
          summarize: fn _payload -> {:error, :no_model} end
        )

      assert outcome.summarised
      assert outcome.summary =~ "## Goal"
    end

    test "the summary enters the conversation as a user message, never the system prompt" do
      long = for index <- 1..400, do: user("wordy operator message number #{index}")

      {:ok, outcome} =
        Compaction.compact(long,
          keep_recent_tokens: 50,
          summarize: fn _payload -> {:ok, "## Goal\n\nship it"} end
        )

      assert [%{role: :user, content: first} | _rest] = outcome.messages
      assert first =~ "ship it"
      refute Enum.any?(outcome.messages, &(Map.get(&1, :role) == :system))
    end
  end

  # ---------------------------------------------------------------- archive

  describe "the archive" do
    test "round-trips content-addressed", context do
      {:ok, entry} = Archive.write(context.data_dir, conversation())
      assert byte_size(entry.id) == 64
      assert {:ok, restored} = Archive.read(context.data_dir, entry.id)
      assert length(restored) == length(conversation())
      assert Enum.map(restored, & &1.role) == Enum.map(conversation(), & &1.role)
    end

    test "the same messages archive to the same id", context do
      {:ok, one} = Archive.write(context.data_dir, conversation())
      {:ok, two} = Archive.write(context.data_dir, conversation())
      assert one.id == two.id
    end

    test "a tampered archive is refused, not repaired", context do
      {:ok, entry} = Archive.write(context.data_dir, conversation())
      payload = entry.path |> File.read!() |> JSON.decode!()
      tampered = put_in(payload, ["messages"], [%{"role" => "user", "content" => "forged"}])
      File.write!(entry.path, JSON.encode!(tampered))

      assert {:error, :archive_digest_mismatch} = Archive.read(context.data_dir, entry.id)
    end

    test "an unknown id is an honest miss", context do
      assert {:error, :no_archive} = Archive.read(context.data_dir, String.duplicate("a", 64))
      assert {:error, :invalid_archive_id} = Archive.read(context.data_dir, "../etc/passwd")
    end

    test "the message-count bound is stated when it bites", context do
      long = for index <- 1..50, do: user("message #{index}")
      {:ok, entry} = Archive.write(context.data_dir, long, event_limit: 10)

      assert entry.message_count == 10
      assert entry.truncated
    end

    test "listing reports names and numbers", context do
      {:ok, entry} = Archive.write(context.data_dir, conversation())
      assert [listed] = Archive.list(context.data_dir)
      assert listed.id == entry.id
      assert listed.message_count == length(conversation())
    end
  end

  # ---------------------------------------------------------------- session

  describe "compaction in a live session" do
    test "/compact retains the archive and lists it", context do
      session = open(context, [[{:text, "ok"}, {:usage, %{input_tokens: 5, output_tokens: 1}}]])
      turn(session, "t1")
      drain()

      {:ok, report} = Session.compact(session.handle, nil)
      {:ok, info} = Session.info(session.handle)

      assert report.trigger == "manual"
      assert is_integer(report.before_tokens)
      assert length(info.compactions) == 1
      # This conversation is tiny, so eliding finished the job and nothing was archived.
      assert report.archived_messages == 0
    end

    test "a big conversation is archived, and the event says how much", context do
      session = open(context, big_script())
      turn(session, "t1")
      drain()

      {:ok, report} = Session.compact(session.handle, "the failing test")

      assert report.archived_messages > 0
      assert is_binary(report.archive_id)

      {:ok, info} = Session.info(session.handle)
      assert [archive | _rest] = info.archives
      assert {:ok, restored} = Archive.read(archive_dir(context, info), archive.id)
      assert length(restored) == report.archived_messages
    end

    test "the compaction event carries the four numbers a client shows", context do
      session = open(context, big_script())
      turn(session, "t1")
      drain()

      {:ok, _report} = Session.compact(session.handle, nil)
      event = await_provider_event("compaction")

      for key <- ["archived_messages", "summary_tokens", "before_tokens", "after_tokens"] do
        assert Map.has_key?(event.payload, key), "compaction event is missing #{key}"
      end
    end

    test "the thrash guard stops the second compaction and names itself", context do
      session = open(context, big_script())
      turn(session, "t1")
      drain()

      {:ok, _first} = Session.compact(session.handle, nil)
      drain()

      assert {:error, :compaction_thrashing} = Session.compact(session.handle, nil)
      event = await_provider_event("status")

      assert event.payload["status"] == "compaction_thrashing"
      assert event.payload["message"] =~ "two compactions within three turns"

      {:ok, info} = Session.info(session.handle)
      assert info.compaction_thrashing
    end

    test "an archive that cannot be written refuses the compaction rather than dropping it",
         context do
      session = open(context, big_script())
      turn(session, "t1")
      drain()

      {:ok, before_info} = Session.info(session.handle)

      # Put a regular file where the archive directory has to go. `Archive.write/3` then
      # cannot create it, the transcript cannot be kept — and the invariant says the
      # conversation is not folded either.
      File.write!(
        Path.join([context.data_dir, before_info.provider_session_id, "compaction"]),
        "not a directory"
      )

      assert {:error, {:archive_unwritable, _reason}} = Session.compact(session.handle, nil)

      event = await_provider_event("status")
      assert event.payload["status"] == "compaction_refused"
      assert event.payload["message"] =~ "Nothing was dropped."

      {:ok, after_info} = Session.info(session.handle)
      assert after_info.messages == before_info.messages
      assert after_info.compactions == []
    end

    test "auto-compaction fires when usage crosses the threshold", context do
      Application.put_env(:ouroboros, :native_context_window, 1_000)

      session =
        open(context, [
          [{:text, "one"}, {:usage, %{input_tokens: 950, output_tokens: 1}}],
          [{:text, "two"}, {:usage, %{input_tokens: 5, output_tokens: 1}}],
          [{:text, "summary"}]
        ])

      turn(session, "t1")
      drain()
      turn(session, "t2")

      {:ok, info} = Session.info(session.handle)
      assert length(info.compactions) == 1
      assert hd(info.compactions).trigger == "automatic"
    end

    test "no compaction when the window is unknown, however large the usage", context do
      session =
        open(context, [
          [{:text, "one"}, {:usage, %{input_tokens: 9_000_000, output_tokens: 1}}],
          [{:text, "two"}, {:usage, %{input_tokens: 1, output_tokens: 1}}]
        ])

      turn(session, "t1")
      drain()
      turn(session, "t2")

      {:ok, info} = Session.info(session.handle)
      assert info.compactions == []
      assert info.context_window == nil
    end
  end

  # ---------------------------------------------------------------- helpers

  defp archive_dir(_context, info), do: Path.dirname(Path.dirname(hd(info.archives).path))

  # Enough conversation that eliding cannot get under `keep_recent_tokens` on its own.
  defp big_script do
    [
      [
        {:text, "reading"},
        {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
      ],
      [
        {:text, String.duplicate("a long stretch of assistant prose. ", 4_000)},
        {:usage, %{input_tokens: 10, output_tokens: 5}}
      ]
    ]
  end

  defp open(context, script, overrides \\ %{}) do
    {model_spec, agent} = NativeModelScript.start(script)

    request =
      SessionRequest.new!(
        Map.merge(
          %{
            provider: :native,
            cwd: context.workspace,
            model: model_spec,
            approval_mode: :auto_approve,
            approval_timeout_ms: 2_000,
            provider_options: %{keep_recent_tokens: 200}
          },
          overrides
        )
      )

    session_context = %{
      session_id: "sess-#{System.unique_integer([:positive])}",
      provider: :native,
      owner: self(),
      adapter: Ouroboros.Provider.Native,
      config: %{},
      process_manager: Jido.Harness.ProcessDriver.Erlexec,
      telemetry_context: %{}
    }

    {:ok, handle} = Session.open(request, session_context)
    on_exit(fn -> if Process.alive?(handle), do: Session.close(handle) end)
    %{handle: handle, agent: agent, model_spec: model_spec}
  end

  defp turn(session, turn_id) do
    :ok = Session.send(session.handle, TurnRequest.new!(%{prompt: "go"}), turn_id)
    await_terminal()
  end

  defp await_terminal(acc \\ []) do
    receive do
      {:session_adapter_event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:session_adapter_event, event} ->
        await_terminal([event | acc])
    after
      15_000 -> flunk("no terminal turn event; got #{inspect(Enum.map(acc, & &1.type))}")
    end
  end

  defp await_provider_event(kind, acc \\ []) do
    receive do
      {:session_adapter_event, %{type: :provider_event, payload: %{"kind" => ^kind}} = event} ->
        event

      {:session_adapter_event, event} ->
        await_provider_event(kind, [event.type | acc])
    after
      5_000 -> flunk("no #{kind} provider event; saw #{inspect(Enum.reverse(acc))}")
    end
  end

  defp drain do
    receive do
      {:session_adapter_event, _event} -> drain()
    after
      0 -> :ok
    end
  end
end
