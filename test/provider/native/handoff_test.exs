defmodule Ouroboros.Provider.Native.HandoffTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Session.Request, as: SessionRequest
  alias Ouroboros.Session.TurnRequest
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Context.Handoff
  alias Ouroboros.Test.NativeSessionFixture, as: Session
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-handoff-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)
    previous_dir = Application.get_env(:ouroboros, :native_data_dir)
    previous_model = Application.get_env(:ouroboros, :native_model_module)
    previous_handoff_writer = Application.get_env(:ouroboros, :native_handoff_operation_writer)
    previous_recovery_writer = Application.get_env(:ouroboros, :native_handoff_recovery_writer)

    previous_checkpoint_writer =
      Application.get_env(:ouroboros, :native_handoff_checkpoint_writer)

    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      restore(:native_data_dir, previous_dir)
      restore(:native_model_module, previous_model)
      restore(:native_handoff_operation_writer, previous_handoff_writer)
      restore(:native_handoff_recovery_writer, previous_recovery_writer)
      restore(:native_handoff_checkpoint_writer, previous_checkpoint_writer)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, data_dir: data_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  describe "the packet" do
    test "carries the five headings, the files, the plan, and the instruction", context do
      target = Path.join(context.workspace, "lib/a.ex")

      packet =
        Handoff.packet(
          summary: "## Goal\n\nship it\n\n## Next steps\n\nrun the tests",
          files: [target],
          plan: %{"items" => [%{"text" => "write the migration", "status" => "in_progress"}]},
          prompt: "finish the migration",
          workspace: context.workspace,
          parent: "native-a-b"
        )

      assert packet =~ "## Goal"
      assert packet =~ "ship it"
      assert packet =~ "lib/a.ex"
      assert packet =~ "sha256 "
      assert packet =~ "[in_progress] write the migration"
      assert packet =~ "finish the migration"
      assert packet =~ "native-a-b"
    end

    test "carries the native plan tool's additive work-item shape", context do
      packet =
        Handoff.packet(
          plan: %{
            "plan" => [
              %{
                "id" => "P0-handoff",
                "step" => "retain accepted evidence",
                "status" => "completed",
                "work_state" => "accepted",
                "evidence" => ["receipt:p0-review"]
              }
            ]
          },
          workspace: context.workspace,
          prompt: "continue"
        )

      assert packet =~ "[completed] retain accepted evidence"
      assert packet =~ "authoritative-plan-digest: sha256:"
      assert packet =~ "id=P0-handoff work_state=accepted"
      assert packet =~ "evidence=[receipt:p0-review]"
      assert packet =~ "continue"
    end

    test "hashes each file as it is now, not as it was", context do
      target = Path.join(context.workspace, "lib/a.ex")
      before_hash = hd(Handoff.hash_files([target])).sha256

      File.write!(target, "defmodule A do\n  def x, do: 2\nend\n")
      after_hash = hd(Handoff.hash_files([target])).sha256

      refute before_hash == after_hash
      assert byte_size(after_hash) == 64
    end

    test "a file that has gone says so instead of carrying a hash", context do
      missing = Path.join(context.workspace, "lib/gone.ex")
      assert [%{sha256: nil, note: "no longer exists"}] = Handoff.hash_files([missing])

      packet = Handoff.packet(files: [missing], workspace: context.workspace)
      assert packet =~ "no longer exists"
    end

    test "an absent summary is admitted, never invented" do
      packet = Handoff.packet(summary: nil, prompt: "go")
      assert packet =~ "no summary"
      refute packet =~ "## Goal"
    end

    test "an absent instruction tells the new session to ask rather than guess" do
      packet = Handoff.packet(summary: "## Goal\n\nx", prompt: nil)
      assert packet =~ "do not start work on a guess"
    end

    test "the packet is bounded in files" do
      paths = for index <- 1..500, do: "/nonexistent/file-#{index}"
      assert length(Handoff.hash_files(paths)) == 200
    end

    test "the packet discloses real touched files omitted by the cap", context do
      paths =
        for index <- 1..201 do
          path =
            Path.join(
              context.workspace,
              "lib/file-#{String.pad_leading(to_string(index), 3, "0")}.ex"
            )

          File.write!(path, "defmodule F#{index}, do: nil\n")
          path
        end

      hashed = Handoff.hash_files(paths)
      assert length(hashed) == 200
      assert Enum.all?(hashed, &is_binary(&1.sha256))

      packet = Handoff.packet(files: paths, workspace: context.workspace, prompt: "continue")
      assert packet =~ "1 touched file omitted"
    end
  end

  describe "handoff from a live session" do
    test "caller-owned native handoff retries return one child without repeated inference",
         context do
      session =
        open(context, [
          [{:text, "did work"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\none child"}]
        ])

      turn(session, "t1")
      drain()

      assert {:ok, first} =
               Session.handoff(session.handle, "continue", open_child: false, id: "op-1")

      calls = NativeModelScript.call_count(session.agent)

      assert {:ok, retried} =
               Session.handoff(session.handle, "continue", open_child: false, id: "op-1")

      assert retried.provider_session_id == first.provider_session_id
      assert NativeModelScript.call_count(session.agent) == calls

      assert {:error, :handoff_id_conflict} =
               Session.handoff(session.handle, "different", open_child: false, id: "op-1")
    end

    test "uncertain completion never overwrites an advanced opened child on retry or reopen",
         context do
      {:ok, writes} = Agent.start_link(fn -> 0 end)

      Application.put_env(:ouroboros, :native_handoff_operation_writer, fn directory,
                                                                           operations,
                                                                           operation ->
        write = Agent.get_and_update(writes, fn count -> {count + 1, count + 1} end)

        if write == 4,
          do: {:error, {:handoff_operation_write_failed, :completed_injected}},
          else:
            Ouroboros.Provider.Native.Context.HandoffOperation.put(
              directory,
              operations,
              operation
            )
      end)

      session =
        open(context, [
          [{:text, "parent work"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\ncontinue safely"}],
          [{:text, "child advanced"}]
        ])

      turn(session, "parent-turn")
      drain()

      assert {:error, {:handoff_result_write_failed, _}} =
               Session.handoff(session.handle, "continue", id: "uncertain-completion")

      {:ok, parent_info} = Session.info(session.handle)

      operation_path =
        parent_info.provider_session_id
        |> then(&Path.join(context.data_dir, &1))
        |> Ouroboros.Provider.Native.Context.HandoffOperation.path()

      [operation] = operation_path |> File.read!() |> :erlang.binary_to_term([:safe])
      assert operation.status == :committing
      child = Ouroboros.Provider.Native.Session.whereis(operation.child_id)
      assert is_pid(child)
      :ok = Session.send(child, TurnRequest.new!(%{prompt: "advance child"}), "child-turn")

      wait_until(fn ->
        case Checkpoint.locate(operation.child_id) do
          {:ok, path, _} -> match?({:ok, [_, _ | _]}, Checkpoint.read(path))
          _ -> false
        end
      end)

      Session.close(child)

      {:ok, checkpoint_path, _} = Checkpoint.locate(operation.child_id)
      advanced_bytes = File.read!(checkpoint_path)
      assert {:ok, messages} = Checkpoint.read(checkpoint_path)
      assert length(messages) > 1
      calls = NativeModelScript.call_count(session.agent)

      assert {:error, {:handoff_incomplete, %{status: :ambiguous}}} =
               Session.handoff(session.handle, "continue",
                 open_child: false,
                 id: "uncertain-completion"
               )

      assert File.read!(checkpoint_path) == advanced_bytes
      assert NativeModelScript.call_count(session.agent) == calls
      Session.close(session.handle)
      reopened = open(context, [], %{provider_session_id: parent_info.provider_session_id})

      assert {:error, {:handoff_incomplete, %{status: :ambiguous}}} =
               Session.handoff(reopened.handle, "continue",
                 open_child: false,
                 id: "uncertain-completion"
               )

      assert File.read!(checkpoint_path) == advanced_bytes
      assert NativeModelScript.call_count(session.agent) == calls
    end

    test "handoff intent write failure creates no child and calls no summarizer", context do
      Application.put_env(:ouroboros, :native_handoff_operation_writer, fn _, _, _ ->
        {:error, {:handoff_operation_write_failed, :injected}}
      end)

      session =
        open(context, [
          [{:text, "did work"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "MUST-NOT-BE-CALLED"}]
        ])

      turn(session, "t1")
      drain()
      calls = NativeModelScript.call_count(session.agent)

      assert {:error, {:handoff_operation_write_failed, :injected}} =
               Session.handoff(session.handle, "continue", open_child: false, id: "write-failed")

      assert NativeModelScript.call_count(session.agent) == calls
      assert File.ls!(context.data_dir) |> Enum.count(&String.starts_with?(&1, "native-")) == 1
    end

    test "checkpoint failure remains committing and retry refuses without another inference",
         context do
      {:ok, failures} = Agent.start_link(fn -> 1 end)

      Application.put_env(:ouroboros, :native_handoff_checkpoint_writer, fn path,
                                                                            messages,
                                                                            opts ->
        if Agent.get_and_update(failures, fn left -> {left, max(left - 1, 0)} end) > 0,
          do: {:error, {:checkpoint_write_failed, :injected}},
          else: Checkpoint.write(path, messages, opts)
      end)

      session =
        open(context, [
          [{:text, "did work"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nretry packet"}]
        ])

      turn(session, "t1")
      drain()

      assert {:error,
              {:handoff_checkpoint_outcome_unknown, {:checkpoint_write_failed, :injected}}} =
               Session.handoff(session.handle, "continue",
                 open_child: false,
                 id: "checkpoint-retry"
               )

      calls = NativeModelScript.call_count(session.agent)

      assert {:error, {:handoff_incomplete, %{status: :ambiguous}}} =
               Session.handoff(session.handle, "continue",
                 open_child: false,
                 id: "checkpoint-retry"
               )

      assert NativeModelScript.call_count(session.agent) == calls
    end

    test "checkpoint uncertainty after installing the seed never overwrites child progress",
         context do
      {:ok, writes} = Agent.start_link(fn -> 0 end)

      Application.put_env(:ouroboros, :native_handoff_checkpoint_writer, fn path,
                                                                            messages,
                                                                            opts ->
        assert {:ok, _} = Checkpoint.write(path, messages, opts)
        Agent.update(writes, &(&1 + 1))
        {:error, {:checkpoint_write_failed, :outcome_unknown}}
      end)

      session =
        open(context, [
          [{:text, "parent work"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nuncertain seed"}]
        ])

      turn(session, "t1")
      drain()

      assert {:error, {:handoff_checkpoint_outcome_unknown, _}} =
               Session.handoff(session.handle, "continue",
                 open_child: false,
                 id: "checkpoint-uncertain"
               )

      {:ok, parent_info} = Session.info(session.handle)
      directory = Path.join(context.data_dir, parent_info.provider_session_id)
      operation_path = Ouroboros.Provider.Native.Context.HandoffOperation.path(directory)
      [operation] = operation_path |> File.read!() |> :erlang.binary_to_term([:safe])
      {:ok, path, _} = Checkpoint.locate(operation.child_id)
      {:ok, seeded} = Checkpoint.read(path)

      assert {:ok, _digest} =
               Checkpoint.write(path, seeded ++ [%{role: :assistant, content: "advanced"}])

      advanced = File.read!(path)
      calls = NativeModelScript.call_count(session.agent)

      assert {:error, {:handoff_incomplete, %{status: :ambiguous}}} =
               Session.handoff(session.handle, "continue",
                 open_child: false,
                 id: "checkpoint-uncertain"
               )

      assert File.read!(path) == advanced
      assert Agent.get(writes, & &1) == 1
      assert NativeModelScript.call_count(session.agent) == calls
    end

    test "handoff ids are nonblank and bounded by UTF-8 bytes", context do
      session = open(context, [])
      id128 = String.duplicate("å", 64)
      id129 = id128 <> "x"

      assert {:error, :invalid_handoff_id} =
               Session.handoff(session.handle, nil, open_child: false, id: "  ")

      assert {:ok, _result} = Session.handoff(session.handle, nil, open_child: false, id: id128)

      assert {:error, {:invalid_handoff_id, %{max_bytes: 128}}} =
               Session.handoff(session.handle, nil, open_child: false, id: id129)
    end

    test "running caller-owned handoff intent fails closed after native session reopen",
         context do
      session = open(context, [[{:text, "ok"}]])
      {:ok, info} = Session.info(session.handle)
      directory = Path.join(context.data_dir, info.provider_session_id)

      {:ok, _} =
        Ouroboros.Provider.Native.Context.HandoffOperation.put(directory, %{}, %{
          id: "running-handoff",
          fingerprint:
            :crypto.hash(:sha256, :erlang.term_to_binary("continue"))
            |> Base.url_encode64(padding: false),
          status: :running,
          started_at: DateTime.utc_now()
        })

      Session.close(session.handle)
      reopened = open(context, [], %{provider_session_id: info.provider_session_id})

      assert {:error, {:handoff_incomplete, %{status: :interrupted}}} =
               Session.handoff(reopened.handle, "continue",
                 open_child: false,
                 id: "running-handoff"
               )
    end

    test "prepared handoff resumes after real native session reopen without repeated inference",
         context do
      session = open(context, [[{:text, "ok"}]])
      {:ok, info} = Session.info(session.handle)
      directory = Path.join(context.data_dir, info.provider_session_id)
      child_id = "native-prepared-child"
      packet = "prepared packet"

      operation = %{
        id: "prepared-handoff",
        fingerprint:
          :crypto.hash(:sha256, :erlang.term_to_binary("continue"))
          |> Base.url_encode64(padding: false),
        status: :prepared,
        child_id: child_id,
        packet: packet,
        packet_bytes: byte_size(packet),
        files: 201,
        files_in_packet: 200,
        files_omitted: 1,
        started_at: DateTime.utc_now()
      }

      {:ok, _} =
        Ouroboros.Provider.Native.Context.HandoffOperation.put(directory, %{}, operation)

      calls = NativeModelScript.call_count(session.agent)
      Session.close(session.handle)
      reopened = open(context, [], %{provider_session_id: info.provider_session_id})

      assert {:ok, result} =
               Session.handoff(reopened.handle, "continue",
                 open_child: false,
                 id: "prepared-handoff"
               )

      assert result.provider_session_id == child_id
      assert result.files == 201
      assert result.files_in_packet == 200
      assert result.files_omitted == 1
      assert NativeModelScript.call_count(session.agent) == calls
      {:ok, path, _} = Checkpoint.locate(child_id)
      assert {:ok, [%{content: ^packet}]} = Checkpoint.read(path)
    end

    test "semantically corrupt handoff operation storage refuses native session reopen",
         context do
      session = open(context, [[{:text, "ok"}]])
      {:ok, info} = Session.info(session.handle)
      directory = Path.join(context.data_dir, info.provider_session_id)
      path = Ouroboros.Provider.Native.Context.HandoffOperation.path(directory)
      Session.close(session.handle)
      bytes = :erlang.term_to_binary([%{id: "missing-status"}])
      File.write!(path, bytes)

      assert {:error, _reason} =
               Session.open(
                 SessionRequest.new!(%{
                   provider: :native,
                   cwd: context.workspace,
                   model: session.model_spec,
                   provider_session_id: info.provider_session_id
                 }),
                 %{session_id: "corrupt-reopen", provider: :native, owner: self()}
               )

      assert File.read!(path) == bytes
    end

    test "unknown handoff status and unreadable store refuse reopen without replacement",
         context do
      session = open(context, [[{:text, "ok"}]])
      {:ok, info} = Session.info(session.handle)
      directory = Path.join(context.data_dir, info.provider_session_id)
      path = Ouroboros.Provider.Native.Context.HandoffOperation.path(directory)
      Session.close(session.handle)

      unknown =
        :erlang.term_to_binary([
          %{id: "unknown", fingerprint: handoff_fingerprint("continue"), status: :future}
        ])

      File.write!(path, unknown)
      assert {:error, _} = reopen(context, session, info.provider_session_id)
      assert File.read!(path) == unknown

      File.rm!(path)
      File.mkdir!(path)
      assert {:error, _} = reopen(context, session, info.provider_session_id)
      assert {:ok, %{type: :directory}} = File.lstat(path)
    end

    test "malformed completed and ambiguous operation records refuse reopen", context do
      session = open(context, [[{:text, "ok"}]])
      {:ok, info} = Session.info(session.handle)
      directory = Path.join(context.data_dir, info.provider_session_id)
      path = Ouroboros.Provider.Native.Context.HandoffOperation.path(directory)
      Session.close(session.handle)
      packet = "retained"

      retained = %{
        id: "malformed",
        fingerprint: handoff_fingerprint("continue"),
        child_id: "native-malformed-child",
        packet: packet,
        packet_bytes: byte_size(packet),
        files: 1,
        files_in_packet: 1,
        files_omitted: 0
      }

      for operation <- [
            Map.merge(retained, %{
              status: :completed,
              result: %{provider_session_id: retained.child_id}
            }),
            Map.put(retained, :status, :ambiguous)
          ] do
        bytes = :erlang.term_to_binary([operation])
        File.write!(path, bytes)
        assert {:error, _} = reopen(context, session, info.provider_session_id)
        assert File.read!(path) == bytes
      end
    end

    test "running recovery rewrite failure refuses reopen and preserves operation bytes",
         context do
      session = open(context, [[{:text, "ok"}]])
      {:ok, info} = Session.info(session.handle)
      directory = Path.join(context.data_dir, info.provider_session_id)

      {:ok, _} =
        Ouroboros.Provider.Native.Context.HandoffOperation.put(directory, %{}, %{
          id: "rewrite-failure",
          fingerprint: handoff_fingerprint("continue"),
          status: :running,
          started_at: DateTime.utc_now()
        })

      path = Ouroboros.Provider.Native.Context.HandoffOperation.path(directory)
      Session.close(session.handle)
      bytes = File.read!(path)

      Application.put_env(:ouroboros, :native_handoff_recovery_writer, fn _, _ ->
        {:error, {:handoff_operation_write_failed, :injected}}
      end)

      assert {:error, _reason} = reopen(context, session, info.provider_session_id)
      assert File.read!(path) == bytes
    end

    test "starts a new session seeded with the packet and records the parent's pointer",
         context do
      session =
        open(context, [
          [{:text, "did the work"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nship the thing\n\n## Next steps\n\nrun mix test"}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, "carry on from here")

      assert String.starts_with?(result.provider_session_id, "native-")
      refute result.provider_session_id == session_id(session)
      assert Process.alive?(result.pid)
      assert result.packet_bytes > 0

      {:ok, info} = Session.info(session.handle)
      assert info.handed_off_to == result.provider_session_id

      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)
    end

    test "the child's first message is the packet, and it is durable", context do
      session =
        open(context, [
          [
            {:text, "read it"},
            {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
          ],
          [{:text, "done"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nSUMMARY-FROM-THE-MODEL"}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, "OPERATOR-INSTRUCTION")
      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)

      {:ok, path, _durable?} = Checkpoint.locate(result.provider_session_id)
      {:ok, [first | rest]} = Checkpoint.read(path)

      assert rest == []
      assert first.role == :user
      assert first.content =~ "SUMMARY-FROM-THE-MODEL"
      assert first.content =~ "OPERATOR-INSTRUCTION"
      assert first.content =~ "lib/a.ex"
    end

    test "structured plan state is digest-bound and survives child reopen", context do
      session =
        open(context, [
          [
            {:tool_call,
             %{
               id: "p1",
               name: "plan",
               input: %{
                 "steps" => [
                   %{
                     "id" => "analysis-1",
                     "step" => "Review evidence",
                     "status" => "in_progress",
                     "deliverable" => "analysis",
                     "work_state" => "reviewing",
                     "criteria" => ["report retained"],
                     "evidence" => ["review.md"]
                   }
                 ]
               }
             }}
          ],
          [{:text, "planned"}],
          [{:text, "## Goal\n\ncarry the campaign"}]
        ])

      turn(session, "t1")
      drain()
      {:ok, result} = Session.handoff(session.handle, "continue")
      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)

      {:ok, path, _} = Checkpoint.locate(result.provider_session_id)
      assert {:ok, snapshot} = Checkpoint.snapshot(path)
      assert snapshot.plan["inherited_from"] == session_id(session)
      assert snapshot.plan["inheritance"] == "context_only"
      assert [%{"id" => "analysis-1"}] = snapshot.plan["plan"]

      assert :ok = Session.close(result.pid)
      assert {:ok, reopened} = reopen(context, session, result.provider_session_id)
      on_exit(fn -> if Process.alive?(reopened), do: Session.close(reopened) end)
      inherited_plan = snapshot.plan
      assert {:ok, %{current_plan: ^inherited_plan}} = Session.plan_state(reopened)
    end

    test "the child runs in the same workspace and can take a turn", context do
      session =
        open(context, [
          [{:text, "ok"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nx"}],
          [{:text, "child answered"}, {:usage, %{input_tokens: 7, output_tokens: 1}}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, "keep going")
      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)

      :ok = Session.send(result.pid, TurnRequest.new!(%{prompt: "next"}), "child-turn")
      events = await_terminal()

      assert Enum.any?(events, &(&1.type == :turn_completed))

      # The child was sent the packet and the operator's new turn, in that order.
      [request | _rest] = session.agent |> NativeModelScript.requests() |> Enum.reverse()
      contents = Enum.map(request.messages, &Map.get(&1, :content))
      assert Enum.any?(contents, &(is_binary(&1) and &1 =~ "Handed-off state"))
    end

    test "a handoff emits compatible retained and omitted file counts", context do
      paths =
        for index <- 1..201 do
          relative = "lib/read-#{String.pad_leading(to_string(index), 3, "0")}.ex"
          File.write!(Path.join(context.workspace, relative), "defmodule Read#{index}, do: nil\n")
          relative
        end

      calls =
        Enum.with_index(paths, 1)
        |> Enum.map(fn {path, index} ->
          {:tool_call, %{id: "read-#{index}", name: "read", input: %{"path" => path}}}
        end)

      session =
        open(context, [
          calls,
          [{:text, "read them"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\ncontinue with all files"}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, "continue")
      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)

      assert result.files == 201
      assert result.files_in_packet == 200
      assert result.files_omitted == 1

      event = await_provider_event("handoff")
      assert event.payload["files"] == 201
      assert event.payload["files_in_packet"] == 200
      assert event.payload["files_omitted"] == 1

      {:ok, path, _durable?} = Checkpoint.locate(result.provider_session_id)
      {:ok, [first]} = Checkpoint.read(path)
      assert first.content =~ "1 touched file omitted"
    end

    test "a handoff emits an event naming the child", context do
      session =
        open(context, [
          [{:text, "ok"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nx"}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, nil)
      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)

      event = await_provider_event("handoff")
      assert event.payload["provider_session_id"] == result.provider_session_id
      assert event.payload["packet_bytes"] > 0
      assert event.payload["files"] == 0
      assert event.payload["files_in_packet"] == 0
      assert event.payload["files_omitted"] == 0
      refute result.packet_bytes == 0
    end

    test "a handoff does not close the parent", context do
      session =
        open(context, [
          [{:text, "ok"}, {:usage, %{input_tokens: 5, output_tokens: 2}}],
          [{:text, "## Goal\n\nx"}]
        ])

      turn(session, "t1")
      drain()

      {:ok, result} = Session.handoff(session.handle, nil)
      on_exit(fn -> if Process.alive?(result.pid), do: Session.close(result.pid) end)

      assert Process.alive?(session.handle)
    end
  end

  # ---------------------------------------------------------------- helpers

  defp session_id(session) do
    {:ok, info} = Session.info(session.handle)
    info.provider_session_id
  end

  defp handoff_fingerprint(prompt) do
    :crypto.hash(:sha256, :erlang.term_to_binary(prompt))
    |> Base.url_encode64(padding: false)
  end

  defp reopen(context, session, provider_session_id) do
    Session.open(
      SessionRequest.new!(%{
        provider: :native,
        cwd: context.workspace,
        model: session.model_spec,
        provider_session_id: provider_session_id
      }),
      %{
        session_id: "reopen-#{System.unique_integer([:positive])}",
        provider: :native,
        owner: self()
      }
    )
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
            approval_timeout_ms: 2_000
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
    on_exit(fn -> if Process.alive?(handle), do: Session.close(handle) end)
    %{handle: handle, agent: agent, model_spec: model_spec}
  end

  defp turn(session, turn_id) do
    :ok = Session.send(session.handle, TurnRequest.new!(%{prompt: "go"}), turn_id)
    await_terminal()
  end

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

  defp wait_until(fun, attempts \\ 100)

  defp wait_until(fun, attempts) when attempts > 0 do
    if fun.() do
      :ok
    else
      Process.sleep(20)
      wait_until(fun, attempts - 1)
    end
  end

  defp wait_until(_fun, 0), do: flunk("condition did not become true")

  defp drain do
    receive do
      {:native_test_event, _event} -> drain()
    after
      0 -> :ok
    end
  end
end
