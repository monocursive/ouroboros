defmodule Ouroboros.Provider.Native.CompactionTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Session.Request, as: SessionRequest
  alias Ouroboros.Session.TurnRequest
  alias Ouroboros.Provider.Native.Context.Archive
  alias Ouroboros.Provider.Native.Context.Compaction
  alias Ouroboros.Provider.Native.Context.CompactionOperation
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Maintenance.Epoch
  alias Ouroboros.Test.NativeSessionFixture, as: Session
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
      epoch: Application.get_env(:ouroboros, :native_epoch_server),
      window: Application.get_env(:ouroboros, :native_context_window),
      writer: Application.get_env(:ouroboros, :native_compaction_operation_writer),
      starter: Application.get_env(:ouroboros, :native_compaction_task_starter)
    }

    epoch = start_supervised!({Epoch, name: nil, data_dir: Path.join(root, "epoch")})

    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)
    Application.put_env(:ouroboros, :native_epoch_server, epoch)

    on_exit(fn ->
      restore(:native_data_dir, previous.dir)
      restore(:native_model_module, previous.model)
      restore(:native_epoch_server, previous.epoch)
      restore(:native_context_window, previous.window)
      restore(:native_compaction_operation_writer, previous.writer)
      restore(:native_compaction_task_starter, previous.starter)
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

  # ------------------------------------------------------- structured content

  # `Ouroboros.Provider.Native.Attachments.message/3` builds a user message whose content
  # is a list of parts. Everything on the compaction path used to call `to_string/1` on
  # that list, which raises — and the session that was compacting is `restart: :temporary`,
  # so `/compact` after an image was attached killed it.
  describe "a message whose content is a list of parts" do
    defp attachment_parts do
      [
        %{type: :text, text: "look at this diagram"},
        %{type: :image, path: "/tmp/d.png", media_type: "image/png", sha256: "ab", size: 12}
      ]
    end

    # What a checkpoint round-trip leaves: JSON has no atoms.
    defp round_tripped_parts do
      [
        %{"type" => "text", "text" => "look at this diagram"},
        %{"type" => "image", "path" => "/tmp/d.png", "media_type" => "image/png"}
      ]
    end

    test "is estimated rather than raised on" do
      message = %{role: :user, content: attachment_parts()}

      tokens = Window.estimate_tokens([message])

      assert is_integer(tokens)
      assert tokens > 0
    end

    test "counts its text and charges its image" do
      text_only = Window.estimate_tokens([%{role: :user, content: "look at this diagram"}])
      with_image = Window.estimate_tokens([%{role: :user, content: attachment_parts()}])

      assert with_image > text_only
      assert Window.message_text(%{role: :user, content: attachment_parts()}) =~ "diagram"
    end

    test "reads the string keys a checkpoint round-trip leaves" do
      atoms = Window.estimate_tokens([%{role: :user, content: attachment_parts()}])
      strings = Window.estimate_tokens([%{role: :user, content: round_tripped_parts()}])

      assert strings == atoms
      assert Window.message_text(%{role: :user, content: round_tripped_parts()}) =~ "diagram"
    end

    test "an assistant message with structured content is estimated too" do
      message = %{
        role: :assistant,
        content: [%{type: :text, text: "I see it"}],
        tool_calls: [%{id: "c1", name: "read", input: %{"path" => "a.ex"}}]
      }

      assert Window.estimate_tokens([message]) > 0
      assert Window.message_text(message) =~ "I see it"
      assert Window.message_text(message) =~ "read"
    end

    test "compaction folds a conversation that contains one" do
      long = for index <- 1..400, do: user("a fairly wordy operator message number #{index}")
      messages = [%{role: :user, content: attachment_parts()} | long]

      assert {:ok, outcome} =
               Compaction.compact(messages,
                 keep_recent_tokens: 50,
                 summarize: fn _payload -> {:ok, "## Goal\n\nx"} end
               )

      assert outcome.summarised
      assert is_integer(outcome.before_tokens)
    end

    test "the structural summary reads the text of one rather than raising" do
      summary =
        Compaction.structural_summary([%{role: :user, content: attachment_parts()}], nil)

      assert summary =~ "look at this diagram"
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
      assert info.context_used == 0
      assert info.context_state == :compacted
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

    test "the automatic thrash latch does not overrule an explicit operator compaction",
         context do
      session = open(context, big_script())
      turn(session, "t1")
      drain()

      {:ok, _first} = Session.compact(session.handle, nil)
      drain()

      # `/compact` is an operator action, so a recent automatic/manual fold is context for
      # the person rather than authority to refuse them. The permanent latch applies only
      # to the threshold-driven path.
      assert {:ok, second} = Session.compact(session.handle, "operator requested")
      assert second.trigger == "manual"
      event = await_provider_event("compaction")
      assert event.payload["trigger"] == "manual"

      {:ok, info} = Session.info(session.handle)
      refute info.compaction_thrashing
    end

    test "a cancelled operation leaves one fold and automatic status describes the prevented second",
         context do
      parent = self()

      blocker = fn _request ->
        send(parent, :cancelled_compaction_model_called)
        receive do: (:never -> [{:text, "unused summary"}])
      end

      script =
        big_script() ++
          [
            [{:text, "summary"}, {:finish, :stop}],
            blocker,
            [{:text, "more"}, {:usage, %{input_tokens: 100, output_tokens: 1}}],
            [{:text, "after latch"}, {:finish, :stop}]
          ]

      session =
        open(context, script, %{
          provider_options: %{keep_recent_tokens: 200, unknown_compact_tokens: 1}
        })

      turn(session, "t1")
      drain()
      assert {:ok, _first} = Session.compact(session.handle, nil)
      assert {:ok, %{status: :running}} = Session.compact_start(session.handle, "cancelled", nil)
      assert_receive :cancelled_compaction_model_called
      assert {:ok, %{status: :cancelled}} = Session.compact_cancel(session.handle, "cancelled")
      send(session.agent, :never)
      assert eventually(fn -> Process.info(session.agent, :status) == {:status, :waiting} end)
      assert {:ok, %{status: :cancelled}} = Session.compact_status(session.handle, "cancelled")
      assert {:ok, after_cancel} = Session.info(session.handle)
      assert length(after_cancel.compactions) == 1

      # Automatic eligibility is based on the preceding provider-metered request. The
      # first post-fold turn establishes that measurement; the next turn asks for the
      # prevented second fold. The cancelled operation consumed neither a fold nor its
      # following scripted turn response.
      turn(session, "t2")
      drain()
      events = turn(session, "t3")

      status =
        Enum.find(events, fn event ->
          event.type == :provider_event and event.payload["kind"] == "status"
        end)

      assert status, "expected automatic latch status, got #{inspect(events)}"
      assert status.payload["status"] == "compaction_thrashing"
      assert status.payload["message"] =~ "a second compaction was requested"
      refute status.payload["message"] =~ "two compactions"

      {:ok, info} = Session.info(session.handle)
      assert length(info.compactions) == 1
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

    test "unknown capacity uses an absolute measured-request safety budget", context do
      session =
        open(
          context,
          [
            [{:text, "one"}, {:usage, %{input_tokens: 101, output_tokens: 1}}],
            [{:text, "two"}, {:usage, %{input_tokens: 1, output_tokens: 1}}]
          ],
          %{provider_options: %{keep_recent_tokens: 200, unknown_compact_tokens: 100}}
        )

      turn(session, "t1")
      drain()
      turn(session, "t2")

      {:ok, info} = Session.info(session.handle)
      assert [compaction] = info.compactions
      assert compaction.trigger == "automatic"
      assert info.context_window == nil
    end

    test "unknown capacity does not invent a budget unless explicitly configured", context do
      session =
        open(context, [
          [{:text, "one"}, {:usage, %{input_tokens: 9_000_000, total_tokens: 99_000_000}}],
          [{:text, "two"}, {:usage, %{input_tokens: 1, total_tokens: 99_000_001}}]
        ])

      turn(session, "t1")
      drain()
      turn(session, "t2")

      assert {:ok, info} = Session.info(session.handle)
      assert info.context_window == nil
      assert info.context_used == 1
      assert info.compactions == []
    end

    test "provider reported zero is measured rather than unmeasured", context do
      session = open(context, [[{:text, "zero"}, {:usage, %{input_tokens: 0, output_tokens: 0}}]])
      turn(session, "t1")
      assert {:ok, info} = Session.info(session.handle)
      assert info.context_used == 0
      assert info.context_state == :measured
    end

    test "a caller id reconciles one asynchronous compaction and conflicting reuse refuses",
         context do
      session = open(context, big_script())
      turn(session, "t1")
      drain()

      assert {:ok, %{status: :running}} = Session.compact_start(session.handle, "op-1", nil)
      assert {:ok, %{status: :running}} = Session.compact_start(session.handle, "op-1", nil)

      assert {:error, :compaction_id_conflict} =
               Session.compact_start(session.handle, "op-1", "other")

      assert eventually(fn ->
               match?(
                 {:ok, %{status: :completed}},
                 Session.compact_status(session.handle, "op-1")
               )
             end)

      assert {:ok, %{status: :completed, result: report}} =
               Session.compact_status(session.handle, "op-1")

      assert report.trigger == "manual"
      assert {:ok, info} = Session.info(session.handle)
      assert length(info.compactions) == 1
    end

    test "a blocked operation keeps status responsive and serializes turns and configuration",
         context do
      parent = self()

      blocker = fn _request ->
        send(parent, :compaction_model_called)
        receive do: (:release_compaction -> [{:text, "summary"}])
      end

      session = open(context, big_script() ++ [blocker])
      turn(session, "t1")
      drain()

      assert {:ok, %{status: :running}} = Session.compact_start(session.handle, "blocked", nil)
      assert_receive :compaction_model_called
      assert {:ok, %{status: :running}} = Session.compact_status(session.handle, "blocked")

      assert {:error, :compaction_in_progress} =
               Session.send(session.handle, TurnRequest.new!(%{prompt: "race"}), "t2")

      assert {:error, :compaction_in_progress} =
               Session.configure(session.handle, %{model: session.model_spec})

      send(session.agent, :release_compaction)

      assert eventually(fn ->
               match?(
                 {:ok, %{status: :completed}},
                 Session.compact_status(session.handle, "blocked")
               )
             end)
    end

    test "cancellation wins over a blocked worker and leaves no fold", context do
      blocker = fn _request ->
        receive do
          :never -> [{:text, "summary"}]
        end
      end

      session = open(context, big_script() ++ [blocker])
      turn(session, "t1")
      drain()
      assert {:ok, %{status: :running}} = Session.compact_start(session.handle, "cancelled", nil)
      assert {:ok, %{status: :cancelled}} = Session.compact_cancel(session.handle, "cancelled")
      Process.sleep(20)
      assert Process.alive?(session.handle)
      assert {:ok, %{status: :cancelled}} = Session.compact_status(session.handle, "cancelled")
      assert {:ok, info} = Session.info(session.handle)
      assert info.compactions == []
    end

    test "checkpoint failure settles failed without exposing a successful fold", context do
      session = open(context, [[{:text, "ok"}, {:usage, %{input_tokens: 5}}]])
      turn(session, "t1")
      drain()
      assert {:ok, info} = Session.info(session.handle)

      {:ok, checkpoint_path, _durable?} =
        Ouroboros.Provider.Native.Checkpoint.locate(info.provider_session_id)

      File.rm!(checkpoint_path)
      File.mkdir!(checkpoint_path)

      assert {:ok, %{status: :running}} =
               Session.compact_start(session.handle, "bad-checkpoint", nil)

      assert eventually(fn ->
               match?(
                 {:ok, %{status: :failed}},
                 Session.compact_status(session.handle, "bad-checkpoint")
               )
             end)

      assert {:ok, after_info} = Session.info(session.handle)
      assert after_info.compactions == []

      refute_receive {:native_test_event,
                      %{type: :provider_event, payload: %{"kind" => "compaction"}}}
    end

    test "durable running intent becomes interrupted and remains so on another load", context do
      operation = %{
        id: "restart-op",
        fingerprint: "focus-hash",
        source_digest: "source-hash",
        focus: nil,
        status: :running,
        requested_at: DateTime.utc_now()
      }

      assert {:ok, _} = CompactionOperation.put(context.data_dir, %{}, operation)
      assert %{"restart-op" => interrupted} = CompactionOperation.load(context.data_dir)
      assert interrupted.status == :interrupted
      assert %{"restart-op" => persisted} = CompactionOperation.load(context.data_dir)
      assert persisted.status == :interrupted
      assert persisted.finished_at == interrupted.finished_at
    end

    test "operation retention refuses capacity rather than forgetting replay identity", context do
      retained =
        Enum.reduce(1..32, %{}, fn index, operations ->
          id = "capacity-op-#{index}"

          operation = %{
            id: id,
            fingerprint: id,
            status: :completed,
            requested_at: DateTime.utc_now()
          }

          {:ok, next} = CompactionOperation.put(context.data_dir, operations, operation)
          next
        end)

      extra = %{
        id: "capacity-op-33",
        fingerprint: "new",
        status: :running,
        requested_at: DateTime.utc_now()
      }

      assert {:error, :compaction_operation_capacity} =
               CompactionOperation.put(context.data_dir, retained, extra)

      assert map_size(CompactionOperation.load(context.data_dir)) == 32
    end

    test "operation intent persistence failure calls no summarizer", context do
      session = open(context, big_script())
      turn(session, "t1")
      drain()
      assert {:ok, info} = Session.info(session.handle)

      operation_path =
        Path.join([context.data_dir, info.provider_session_id, "compaction-operations.term"])

      File.mkdir!(operation_path)
      calls_before = NativeModelScript.call_count(session.agent)

      assert {:error, {:compaction_operation_write_failed, _reason}} =
               Session.compact_start(session.handle, "unrecordable", nil)

      assert NativeModelScript.call_count(session.agent) == calls_before

      assert {:error, :unknown_compaction} =
               Session.compact_status(session.handle, "unrecordable")
    end

    test "summarizer failure settles failed and exact retry does not call it again", context do
      # Build the raising enumerable in the linked fixture Agent, but raise only when the
      # compaction worker consumes it. Raising directly in this callback would test the
      # fixture owner's link, not runtime worker settlement.
      crashing = fn _request ->
        Stream.map([:boom], fn _ -> raise "summary exploded" end)
      end

      session = open(context, big_script() ++ [crashing])
      turn(session, "t1")
      drain()

      assert {:ok, %{status: :running}} =
               Session.compact_start(session.handle, "failed-op", nil)

      assert eventually(fn ->
               case Session.compact_status(session.handle, "failed-op") do
                 {:ok, %{status: status}} when status != :running -> true
                 _ -> false
               end
             end)

      assert {:ok, %{status: :failed}} = Session.compact_status(session.handle, "failed-op")

      calls = NativeModelScript.call_count(session.agent)
      assert {:ok, %{status: :failed}} = Session.compact_start(session.handle, "failed-op", nil)
      assert NativeModelScript.call_count(session.agent) == calls
    end

    test "task start settlement write failure is ambiguous without inference", context do
      Application.put_env(:ouroboros, :native_compaction_task_starter, fn _ ->
        {:error, :injected_start_failure}
      end)

      Application.put_env(:ouroboros, :native_compaction_operation_writer, fn directory,
                                                                              operations,
                                                                              operation ->
        if operation.status == :failed,
          do: {:error, {:compaction_operation_write_failed, :injected_settlement_failure}},
          else: CompactionOperation.put(directory, operations, operation)
      end)

      session = open(context, big_script())
      turn(session, "t1")
      drain()
      calls = NativeModelScript.call_count(session.agent)

      assert {:error, {:compaction_task_start_failed, :injected_start_failure}} =
               Session.compact_start(session.handle, "start-write-failed", nil)

      assert {:ok, %{status: :ambiguous}} =
               Session.compact_status(session.handle, "start-write-failed")

      assert NativeModelScript.call_count(session.agent) == calls
    end

    test "task start failure settles durable intent immediately and retry reconciles", context do
      Application.put_env(:ouroboros, :native_compaction_task_starter, fn _fun ->
        {:error, :injected_start_failure}
      end)

      session = open(context, big_script())
      turn(session, "t1")
      drain()
      calls = NativeModelScript.call_count(session.agent)

      assert {:error, {:compaction_task_start_failed, :injected_start_failure}} =
               Session.compact_start(session.handle, "start-failed", nil)

      assert {:ok, %{status: :failed}} = Session.compact_status(session.handle, "start-failed")

      assert {:ok, %{status: :failed}} =
               Session.compact_start(session.handle, "start-failed", nil)

      assert NativeModelScript.call_count(session.agent) == calls
    end

    test "terminal result write failure is ambiguous and exact retry never folds twice",
         context do
      writer = fn directory, operations, operation ->
        if operation.status == :completed,
          do: {:error, {:compaction_operation_write_failed, :injected_result_failure}},
          else: CompactionOperation.put(directory, operations, operation)
      end

      Application.put_env(:ouroboros, :native_compaction_operation_writer, writer)
      session = open(context, big_script())
      turn(session, "t1")
      drain()

      assert {:ok, %{status: :running}} = Session.compact_start(session.handle, "ambiguous", nil)

      assert eventually(fn ->
               match?(
                 {:ok, %{status: :ambiguous}},
                 Session.compact_status(session.handle, "ambiguous")
               )
             end)

      assert {:ok, info} = Session.info(session.handle)
      assert length(info.compactions) == 1
      calls = NativeModelScript.call_count(session.agent)

      assert {:ok, %{status: :ambiguous}} =
               Session.compact_start(session.handle, "ambiguous", nil)

      assert NativeModelScript.call_count(session.agent) == calls

      assert %{"ambiguous" => recovered} =
               CompactionOperation.load(Path.join(context.data_dir, info.provider_session_id))

      assert recovered.status == :ambiguous
    end

    test "close cancels a running operation durably and late completion cannot mutate it",
         context do
      parent = self()

      blocker = fn _ ->
        send(parent, :close_worker_started)

        receive do
          :release -> [{:text, "late"}]
        end
      end

      session = open(context, big_script() ++ [blocker])
      turn(session, "t1")
      drain()
      assert {:ok, %{status: :running}} = Session.compact_start(session.handle, "close-op", nil)
      assert_receive :close_worker_started
      assert :ok = Session.close(session.handle)
      send(session.agent, :release)
      Process.sleep(20)

      assert %{"close-op" => %{status: :cancelled}} =
               CompactionOperation.load(
                 Path.join(
                   context.data_dir,
                   Session.info(session.handle) |> elem(1) |> Map.fetch!(:provider_session_id)
                 )
               )
    end

    test "kill cancels a running operation durably", context do
      blocker = fn _ ->
        receive do
          :never -> [{:text, "late"}]
        end
      end

      session = open(context, big_script() ++ [blocker])
      turn(session, "t1")
      drain()
      assert {:ok, info} = Session.info(session.handle)
      assert {:ok, %{status: :running}} = Session.compact_start(session.handle, "kill-op", nil)
      assert :ok = Ouroboros.Session.kill(session.handle)

      assert %{"kill-op" => %{status: :cancelled}} =
               CompactionOperation.load(Path.join(context.data_dir, info.provider_session_id))
    end

    test "close continues after cancellation settlement write failure and reopen is interrupted",
         context do
      Application.put_env(:ouroboros, :native_compaction_operation_writer, fn directory,
                                                                              operations,
                                                                              operation ->
        if operation.status == :cancelled,
          do: {:error, {:compaction_operation_write_failed, :injected_cancel_failure}},
          else: CompactionOperation.put(directory, operations, operation)
      end)

      blocker = fn _ ->
        receive do
          :never -> [{:text, "late"}]
        end
      end

      session = open(context, big_script() ++ [blocker])
      turn(session, "t1")
      drain()
      assert {:ok, before_close} = Session.info(session.handle)

      assert {:ok, %{status: :running}} =
               Session.compact_start(session.handle, "close-write-failed", nil)

      assert :ok = Session.close(session.handle)

      assert %{"close-write-failed" => %{status: :interrupted}} =
               CompactionOperation.load(
                 Path.join(context.data_dir, before_close.provider_session_id)
               )
    end

    test "unknown-capacity budget is live configurable and reported with null capacity",
         context do
      Application.delete_env(:ouroboros, :native_context_window)
      session = open(context, [[{:text, "ok"}, {:usage, %{input_tokens: 0}}]])
      assert :ok = Ouroboros.Session.configure(session.handle, %{unknown_compact_tokens: 12_345})
      assert {:ok, info} = Session.info(session.handle)
      assert info.context_window == nil
      assert info.unknown_compact_tokens == 12_345
      assert :ok = Ouroboros.Session.configure(session.handle, %{unknown_compact_tokens: nil})
      assert {:ok, disabled} = Session.info(session.handle)
      assert disabled.unknown_compact_tokens == nil
    end

    test "public compaction operation ids are bounded by bytes with typed errors" do
      oversized = String.duplicate("å", 65)

      for result <- [
            InteractiveSession.compact_start("missing", oversized, nil),
            InteractiveSession.compact_status("missing", oversized),
            InteractiveSession.compact_cancel("missing", oversized)
          ] do
        assert {:error, {:invalid_compaction_id, details}} = result
        assert details.max_bytes == 128
      end
    end

    test "completed operation survives a real native session stop and reopen", context do
      session = open(context, big_script())
      turn(session, "t1")
      drain()
      assert {:ok, info} = Session.info(session.handle)

      assert {:ok, %{status: :running}} =
               Session.compact_start(session.handle, "completed-reopen", nil)

      assert eventually(fn ->
               match?(
                 {:ok, %{status: :completed}},
                 Session.compact_status(session.handle, "completed-reopen")
               )
             end)

      calls = NativeModelScript.call_count(session.agent)
      reopened = reopen(context, session, info.provider_session_id)

      assert {:ok, %{status: :completed}} =
               Session.compact_start(reopened.handle, "completed-reopen", nil)

      assert {:error, :compaction_id_conflict} =
               Session.compact_start(reopened.handle, "completed-reopen", "different")

      assert NativeModelScript.call_count(session.agent) == calls
      assert {:ok, reopened_info} = Ouroboros.Session.context_info(reopened.handle)
      assert reopened_info.messages > 0

      assert {:ok, %{status: :completed, result: result}} =
               Session.compact_status(reopened.handle, "completed-reopen")

      assert result.after_tokens > 0
    end

    test "work-item identity and evidence survive compaction and real session reopen", context do
      item = %{
        "id" => "P0-persist",
        "step" => "Retain campaign state",
        "status" => "in_progress",
        "deliverable" => "validation",
        "work_state" => "reviewing",
        "criteria" => ["reopen preserves exact item"],
        "evidence" => ["receipt:before-compaction"],
        "child_settlement" => "completed"
      }

      script = [
        [
          {:tool_call,
           %{id: "plan-persist", name: "plan", input: %{"steps" => [item], "explanation" => "P0"}}}
        ],
        [
          {:tool_call,
           %{
             id: "plan-accept",
             name: "plan",
             input: %{"steps" => [item], "accept" => ["P0-persist"], "explanation" => "P0"}
           }}
        ],
        [{:text, String.duplicate("old context. ", 8_000)}, {:finish, :stop}]
      ]

      session = open(context, script)
      turn(session, "plan-turn")
      assert {:ok, before} = Session.info(session.handle)
      [accepted] = before.current_plan["plan"]
      assert accepted["id"] == "P0-persist"
      assert accepted["work_state"] == "accepted"
      assert accepted["evidence"] == ["receipt:before-compaction"]
      assert accepted["acceptance"]["basis"] == "model_judgment"
      assert accepted["acceptance"]["deterministic"] == false

      assert {:ok, _report} = Session.compact(session.handle, "retain the campaign record")
      assert {:ok, compacted} = Session.info(session.handle)
      assert compacted.current_plan == before.current_plan

      reopened = reopen(context, session, before.provider_session_id)
      assert {:ok, after_reopen} = Ouroboros.Session.context_info(reopened.handle)
      assert after_reopen.current_plan == before.current_plan
    end

    test "running operation becomes interrupted through a real native session reopen", context do
      blocker = fn _ ->
        receive do
          :never -> [{:text, "late"}]
        end
      end

      session = open(context, big_script() ++ [blocker])
      turn(session, "t1")
      drain()
      assert {:ok, info} = Session.info(session.handle)

      assert {:ok, %{status: :running}} =
               Session.compact_start(session.handle, "running-reopen", nil)

      Process.exit(session.handle, :kill)
      assert eventually(fn -> not Process.alive?(session.handle) end)
      reopened = reopen(context, session, info.provider_session_id)

      assert {:ok, %{status: :interrupted}} =
               Session.compact_start(reopened.handle, "running-reopen", nil)

      assert {:error, :compaction_id_conflict} =
               Session.compact_start(reopened.handle, "running-reopen", "different")

      assert NativeModelScript.call_count(session.agent) == 2
    end

    test "owner kill terminates the actual blocked compaction worker", context do
      test_pid = self()

      blocker = fn _ ->
        send(test_pid, :ownership_worker_blocked)

        receive do
          :never -> [{:text, "late"}]
        end
      end

      session = open(context, big_script() ++ [blocker])
      turn(session, "t1")
      drain()

      assert {:ok, %{status: :running}} =
               Session.compact_start(session.handle, "owned-worker", nil)

      assert_receive :ownership_worker_blocked
      worker = :sys.get_state(session.handle).compaction_operation.pid
      refute worker == session.agent
      assert Process.alive?(worker)
      Process.exit(session.handle, :kill)
      assert eventually(fn -> not Process.alive?(session.handle) end)
      assert eventually(fn -> not Process.alive?(worker) end)

      refute_receive {:native_test_event,
                      %{type: :provider_event, payload: %{"kind" => "compaction"}}}
    end

    test "committing operation becomes ambiguous through a real native session reopen", context do
      session = open(context, big_script())
      turn(session, "t1")
      drain()
      assert {:ok, info} = Session.info(session.handle)
      directory = Path.join(context.data_dir, info.provider_session_id)

      fingerprint =
        :crypto.hash(:sha256, :erlang.term_to_binary(nil)) |> Base.encode16(case: :lower)

      operation = %{
        id: "committing-reopen",
        fingerprint: fingerprint,
        focus: nil,
        source_digest: "source",
        status: :committing,
        requested_at: DateTime.utc_now()
      }

      assert {:ok, _} = CompactionOperation.put(directory, %{}, operation)
      Process.exit(session.handle, :kill)
      assert eventually(fn -> not Process.alive?(session.handle) end)
      reopened = reopen(context, session, info.provider_session_id)

      assert {:ok, %{status: :ambiguous}} =
               Session.compact_start(reopened.handle, "committing-reopen", nil)

      assert {:error, :compaction_id_conflict} =
               Session.compact_start(reopened.handle, "committing-reopen", "different")

      assert NativeModelScript.call_count(session.agent) == 2
    end

    test "corrupt operation storage refuses a real session reopen without changing bytes",
         context do
      session = open(context, big_script())
      assert {:ok, info} = Session.info(session.handle)
      Process.exit(session.handle, :kill)
      assert eventually(fn -> not Process.alive?(session.handle) end)
      path = CompactionOperation.path(Path.join(context.data_dir, info.provider_session_id))
      File.write!(path, "not an erlang term")
      before = File.read!(path)

      assert {:error, {%ArgumentError{message: message}, _stack}} =
               Ouroboros.Session.open(
                 "corrupt-reopen",
                 resume_request(context, session, info.provider_session_id)
               )

      assert message =~ "invalid compaction operation store"

      assert File.read!(path) == before
    end

    test "unreadable operation storage refuses reopen and preserves the path", context do
      session = open(context, big_script())
      assert {:ok, info} = Session.info(session.handle)
      Process.exit(session.handle, :kill)
      assert eventually(fn -> not Process.alive?(session.handle) end)
      path = CompactionOperation.path(Path.join(context.data_dir, info.provider_session_id))
      File.mkdir!(path)

      assert {:error, {%ArgumentError{message: message}, _}} =
               Ouroboros.Session.open(
                 "unreadable-reopen",
                 resume_request(context, session, info.provider_session_id)
               )

      assert message =~ "unreadable compaction operation store"
      assert File.dir?(path)
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
      process_manager: Ouroboros.Provider.Native.ProcessSignal,
      telemetry_context: %{}
    }

    {:ok, handle} = Session.open(request, session_context)
    cleanup_runtime(handle)
    %{handle: handle, agent: agent, model_spec: model_spec}
  end

  defp reopen(context, session, provider_session_id) do
    logical_id = "reopen-#{System.unique_integer([:positive])}"

    {:ok, runtime_id} =
      Ouroboros.Session.open(logical_id, resume_request(context, session, provider_session_id))

    {:ok, info} = Ouroboros.Session.info(runtime_id)
    cleanup_runtime(info.pid)
    %{handle: info.pid, agent: session.agent, model_spec: session.model_spec}
  end

  defp cleanup_runtime(pid) do
    # Native owners belong to the application supervisor. Reap the exact owner even
    # after a failed assertion or after the test's private Epoch has stopped.
    on_exit(fn ->
      monitor = Process.monitor(pid)
      DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, pid)
      assert_receive {:DOWN, ^monitor, :process, ^pid, _reason}, 1_000
    end)
  end

  defp resume_request(context, session, provider_session_id) do
    SessionRequest.new!(%{
      provider: :native,
      cwd: context.workspace,
      model: session.model_spec,
      provider_session_id: provider_session_id,
      approval_mode: :auto_approve,
      provider_options: %{keep_recent_tokens: 200}
    })
  end

  defp turn(session, turn_id) do
    :ok = Session.send(session.handle, TurnRequest.new!(%{prompt: "go"}), turn_id)
    await_terminal()
  end

  defp eventually(fun, attempts \\ 100)

  defp eventually(fun, attempts) when attempts > 0 do
    if fun.() do
      true
    else
      Process.sleep(10)
      eventually(fun, attempts - 1)
    end
  end

  defp eventually(_fun, 0), do: false

  defp await_terminal(acc \\ []) do
    receive do
      {:native_test_event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:native_test_event, event} ->
        await_terminal([event | acc])
    after
      15_000 -> flunk("no terminal turn event; got #{inspect(Enum.map(acc, & &1.type))}")
    end
  end

  defp await_provider_event(kind, acc \\ []) do
    receive do
      {:native_test_event, %{type: :provider_event, payload: %{"kind" => ^kind}} = event} ->
        event

      {:native_test_event, event} ->
        await_provider_event(kind, [event.type | acc])
    after
      5_000 -> flunk("no #{kind} provider event; saw #{inspect(Enum.reverse(acc))}")
    end
  end

  defp drain do
    receive do
      {:native_test_event, _event} -> drain()
    after
      0 -> :ok
    end
  end
end
