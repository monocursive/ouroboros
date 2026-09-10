defmodule Ouroboros.InteractiveControlsTest do
  @moduledoc """
  The session controls the 2026 grammar expects: change the posture mid-session, name a
  session, and branch one.

  Everything asserted here is asked of a live coordinator rather than of a projection,
  because the questions that matter are durability questions — does the change survive a
  coordinator restart, does the provider actually get told, does the parent stay untouched
  — and only a running session can answer them.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Test.ModelRequest, as: RunRequest
  alias Ouroboros.Session
  alias Ouroboros.Session.RuntimeInfo, as: SessionInfo
  alias Ouroboros.Interactive.{Ref, State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.ControlledModel, as: HarnessAdapter

  @provider :native

  setup do
    cleanup_sessions()

    previous_provider_config = Ouroboros.Test.NativeConfig.snapshot()
    journal_dir = unique_journal_dir()

    previous_native_dir = Application.get_env(:ouroboros, :native_data_dir)
    Ouroboros.Test.NativeConfig.configure(%{native: %{test_pid: self()}})
    Application.put_env(:ouroboros, :native_data_dir, journal_dir)

    on_exit(fn ->
      cleanup_sessions()
      Ouroboros.Test.NativeConfig.configure(previous_provider_config)
      restore_native_dir(previous_native_dir)
      File.rm_rf(journal_dir)
    end)

    {:ok, id: unique_id("controls")}
  end

  describe "interactive.configure" do
    test "a change is carried to the live session and the answer says when it lands",
         %{id: id} do
      ref = start_session(id)

      assert {:ok, result} = InteractiveSession.configure(ref, %{approval_mode: :auto_approve})

      # `:now`, because the one transport carries the change to a live session process
      # rather than to the next re-execution of a CLI. The field stays on the wire because
      # a footer has to be able to state when a change lands rather than imply it.
      assert result.applies == :now
      assert result.changed == [:approval_mode]
      assert result.options.approval_mode == :auto_approve

      # And `interactive.info` reflects it, which is the only place a client looks.
      assert {:ok, session} = InteractiveSession.info(ref)
      assert State.public(session).options.approval_mode == :auto_approve

      retire_session(id)
    end

    test "the change reaches the provider's own request, not just the checkpoint", %{id: id} do
      ref = start_session(id, approval_mode: :auto_edit, sandbox_mode: :workspace_write)

      assert {:ok, _result} =
               InteractiveSession.configure(ref, %{
                 approval_mode: :auto_approve,
                 sandbox_mode: :read_only
               })

      assert {:ok, _turn} =
               InteractiveSession.send_message(ref, "after the change", id: unique_id("turn"))

      # The managed transport rebuilds its run request per turn from the session request
      # the worker holds. If `configure` had only written Ouroboros's checkpoint, this
      # turn would still carry the options the session was started with.
      assert_receive {:ouroboros_test_model_started, _run,
                      %RunRequest{approval_mode: :auto_approve, sandbox_mode: :read_only},
                      adapter},
                     2_000

      assert :ok = HarnessAdapter.finish(adapter)
      retire_session(id)
    end

    test "the effective options survive a coordinator restart", %{id: id} do
      ref = start_session(id)
      assert {:ok, _result} = InteractiveSession.configure(ref, %{sandbox_mode: :read_only})

      pid = Task.whereis(id)
      monitor = Process.monitor(pid)
      Process.exit(pid, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^pid, _reason}, 2_000

      # Read the durable record directly: this is what a restarted node rebuilds the
      # provider request from, and a configuration that lived only in process memory
      # would silently revert the session to the posture it was started with.
      assert {:ok, %State{} = stored} = Store.get(id)
      assert stored.options.sandbox_mode == :read_only

      reloaded =
        assert_eventually(fn ->
          case InteractiveSession.info(Ref.new(id)) do
            {:ok, %State{} = session} -> session
            _not_yet -> false
          end
        end)

      assert State.public(reloaded).options.sandbox_mode == :read_only

      retire_session(id)
    end

    test "the change is a durable event in the session's own log", %{id: id} do
      ref = start_session(id)
      assert {:ok, _result} = InteractiveSession.configure(ref, %{approval_mode: :auto_approve})

      configured =
        assert_eventually(fn ->
          with {:ok, events} <- InteractiveSession.replay(ref, cursor: 0, limit: 500) do
            Enum.find(events, &(&1.type == :status and &1.payload["kind"] == "configured"))
          end
        end)

      assert configured.payload == %{
               "kind" => "configured",
               "applies" => "now",
               "changed" => %{"approval_mode" => :auto_approve}
             }

      assert configured.provider == @provider

      # The runtime event is drawn from the same strictly increasing series as every
      # provider event, and the session goes on ingesting provider events afterwards
      # rather than skipping the one whose number the marker took.
      assert {:ok, events} = InteractiveSession.replay(ref, cursor: 0, limit: 500)
      sequences = Enum.map(events, & &1.sequence)
      assert sequences == Enum.sort(sequences)
      assert sequences == Enum.uniq(sequences)

      assert {:ok, _turn} =
               InteractiveSession.send_message(ref, "keep going", id: unique_id("turn"))

      assert_receive {:ouroboros_test_model_started, _run, %RunRequest{}, adapter}, 2_000
      assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "still here"})

      later =
        assert_eventually(fn ->
          with {:ok, events} <- InteractiveSession.replay(ref, cursor: 0, limit: 500) do
            Enum.any?(events, &(&1.sequence > configured.sequence)) && events
          end
        end)

      sequences = Enum.map(later, & &1.sequence)
      assert sequences == Enum.sort(sequences)
      assert sequences == Enum.uniq(sequences)

      assert :ok = HarnessAdapter.finish(adapter)
      retire_session(id)
    end

    test "a field the transport cannot change is refused by name", %{id: id} do
      ref = start_session(id)

      assert {:error, {:invalid_configuration, details}} =
               InteractiveSession.configure(ref, %{system_prompt: "replace instructions"})

      assert details.reason == :unknown_field
      assert details.field == :system_prompt
      assert {:ok, session} = Store.get(id)
      assert Map.get(session.options, :system_prompt) == nil

      retire_session(id)
    end

    test "a value outside the transport's allowlist is refused with the allowlist", %{id: id} do
      ref = start_session(id)

      # Exactly what a start is held to: the adapter's `normalized_values`. Configuring
      # into a value the provider cannot enforce would be the sandbox equivalent of the
      # X1 hole — a policy that reads as applied and is not.
      assert {:error, {:unconfigurable_session, details}} =
               InteractiveSession.configure(ref, %{sandbox_mode: :not_a_sandbox})

      assert details.reason == :value_not_accepted
      assert details.field == :sandbox_mode
      assert details.value == :not_a_sandbox
      assert details.accepted_values == [:default, :read_only, :workspace_write, :unrestricted]

      assert {:ok, session} = InteractiveSession.info(ref)
      assert State.public(session).options.sandbox_mode == :workspace_write

      retire_session(id)
    end

    test "an empty or unknown change is refused before any provider is called", %{id: id} do
      ref = start_session(id)

      assert {:error, {:invalid_configuration, %{reason: :no_changes}}} =
               InteractiveSession.configure(ref, %{})

      assert {:error, {:invalid_configuration, %{reason: :unknown_field, field: :workspace}}} =
               InteractiveSession.configure(ref, %{workspace: "/tmp"})

      retire_session(id)
    end

    test "the model a session is running is on its public state, before and after a change" do
      # A context meter divides `usage.total_tokens` by the window `runtime.models` gives
      # for *this* model, so the session has to say which model that is.
      assert {:ok, session} =
               State.new("controls-model-projection",
                 provider: :native,
                 approval_mode: :auto_edit,
                 model: "anthropic:claude-sonnet-5"
               )

      assert State.public(session).options.model == "anthropic:claude-sonnet-5"

      configured = State.configure(session, %{model: "anthropic:claude-opus-5"})
      assert State.public(configured).options.model == "anthropic:claude-opus-5"

      # And the request a resume rebuilds carries it, so the change is not projection-only.
      assert State.request(configured).model == "anthropic:claude-opus-5"
    end

    test "a terminal session is not configurable", %{id: id} do
      ref = start_session(id)
      assert :ok = InteractiveSession.kill(ref)

      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{} = session} -> State.terminal?(session) && session
          _other -> false
        end
      end)

      assert {:error, {:session_not_configurable, status}} =
               InteractiveSession.configure(ref, %{approval_mode: :auto_approve})

      assert status in [:closed, :cancelled, :failed, :lost]
      retire_session(id)
    end
  end

  describe "interactive.rename and the auto-title" do
    test "a session starts unnamed and takes the title a person gives it", %{id: id} do
      ref = start_session(id)

      assert {:ok, session} = InteractiveSession.info(ref)
      assert State.title(session) == nil
      assert State.title_source(session) == nil

      assert {:ok, renamed} = InteractiveSession.rename(ref, "  Ledger retention sweep  ")

      # Trimmed at the boundary, so every client draws the same string.
      assert renamed.title == "Ledger retention sweep"
      assert renamed.title_source == :human

      assert {:ok, reread} = InteractiveSession.info(ref)
      assert State.public(reread).title == "Ledger retention sweep"

      retire_session(id)
    end

    test "the title survives a coordinator restart", %{id: id} do
      ref = start_session(id)
      assert {:ok, _renamed} = InteractiveSession.rename(ref, "Survives the BEAM")

      pid = Task.whereis(id)
      monitor = Process.monitor(pid)
      Process.exit(pid, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^pid, _reason}, 2_000

      assert {:ok, %State{} = stored} = Store.get(id)
      assert State.title(stored) == "Survives the BEAM"
      assert State.title_source(stored) == :human

      retire_session(id)
    end

    test "an unnamed session takes its title from the first accepted prompt", %{id: id} do
      ref = start_session(id)

      assert {:ok, _turn} =
               InteractiveSession.send_message(
                 ref,
                 "Trace the retention sweep\nand then explain what it deletes",
                 id: unique_id("turn")
               )

      assert_receive {:ouroboros_test_model_started, _run, %RunRequest{}, adapter}, 2_000

      titled =
        assert_eventually(fn ->
          case InteractiveSession.info(ref) do
            {:ok, %State{} = session} -> State.title(session) && session
            _other -> false
          end
        end)

      # First line only, and marked as a guess rather than a decision.
      assert State.title(titled) == "Trace the retention sweep"
      assert State.title_source(titled) == :auto

      # A second prompt does not rename the conversation: the first one is the one that
      # says what it is about.
      assert :ok = HarnessAdapter.finish(adapter)
      assert_eventually(fn -> ready_for_next_turn?(ref) end)

      assert {:ok, _turn} =
               InteractiveSession.send_message(ref, "now do something else entirely",
                 id: unique_id("turn")
               )

      assert_receive {:ouroboros_test_model_started, _run, %RunRequest{}, second}, 2_000

      assert_eventually(fn -> accepted_inputs(ref) >= 2 end)
      assert {:ok, session} = InteractiveSession.info(ref)
      assert State.title(session) == "Trace the retention sweep"

      if Process.alive?(second), do: HarnessAdapter.finish(second)
      retire_session(id)
    end

    test "a human title is never overwritten by a later prompt", %{id: id} do
      ref = start_session(id)
      assert {:ok, _renamed} = InteractiveSession.rename(ref, "What I called it")

      assert {:ok, _turn} =
               InteractiveSession.send_message(ref, "a prompt that would have titled it",
                 id: unique_id("turn")
               )

      assert_receive {:ouroboros_test_model_started, _run, %RunRequest{}, adapter}, 2_000

      assert_eventually(fn ->
        match?({:ok, [_ | _]}, InteractiveSession.replay(ref, cursor: 0, limit: 100))
      end)

      Process.sleep(100)
      assert {:ok, session} = InteractiveSession.info(ref)
      assert State.title(session) == "What I called it"
      assert State.title_source(session) == :human

      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(id)
    end

    test "a rename overrides an auto-title and the auto-title never comes back", %{id: id} do
      ref = start_session(id)

      assert {:ok, _turn} =
               InteractiveSession.send_message(ref, "the runtime's guess", id: unique_id("turn"))

      assert_receive {:ouroboros_test_model_started, _run, %RunRequest{}, adapter}, 2_000

      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{} = session} -> State.title_source(session) == :auto && session
          _other -> false
        end
      end)

      assert {:ok, renamed} = InteractiveSession.rename(ref, "the human's decision")
      assert renamed.title_source == :human

      assert :ok = HarnessAdapter.finish(adapter)
      assert_eventually(fn -> ready_for_next_turn?(ref) end)

      assert {:ok, _turn} =
               InteractiveSession.send_message(ref, "another prompt", id: unique_id("turn"))

      assert_receive {:ouroboros_test_model_started, _run, %RunRequest{}, second}, 2_000
      assert_eventually(fn -> accepted_inputs(ref) >= 2 end)

      assert {:ok, session} = InteractiveSession.info(ref)
      assert State.title(session) == "the human's decision"

      if Process.alive?(second), do: HarnessAdapter.finish(second)
      retire_session(id)
    end

    test "a title that would break a picker row is refused rather than mangled", %{id: id} do
      ref = start_session(id)

      assert {:error, {:invalid_title, %{reason: :blank}}} = InteractiveSession.rename(ref, "   ")

      assert {:error, {:invalid_title, %{reason: :too_long, limit: 120}}} =
               InteractiveSession.rename(ref, String.duplicate("x", 121))

      assert {:error, {:invalid_title, %{reason: :control_characters}}} =
               InteractiveSession.rename(ref, "clear\e[2Jthe screen")

      assert {:error, {:invalid_title, %{reason: :control_characters}}} =
               InteractiveSession.rename(ref, "two\nlines")

      assert {:error, {:invalid_title, %{reason: :not_a_string}}} =
               InteractiveSession.rename(ref, 42)

      # Exactly at the bound is fine.
      assert {:ok, renamed} = InteractiveSession.rename(ref, String.duplicate("x", 120))
      assert String.length(renamed.title) == 120

      retire_session(id)
    end

    test "a terminal session can still be named", %{id: id} do
      ref = start_session(id)
      assert :ok = InteractiveSession.kill(ref)

      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{} = session} -> State.terminal?(session) && session
          _other -> false
        end
      end)

      assert {:ok, renamed} = InteractiveSession.rename(ref, "the one that failed")
      assert renamed.title == "the one that failed"

      retire_session(id)
    end
  end

  describe "interactive.fork" do
    test "a fork is a new session carrying the parent's provider session and branch flag",
         %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)
      adapter = name_provider_session(ref)

      assert {:ok, child} = InteractiveSession.fork(ref, unique_id("fork"))
      assert child.node == node()
      assert child.id != id

      assert {:ok, %State{} = forked} = InteractiveSession.info(Ref.new(child.id))
      assert State.forked_from(forked) == id
      assert forked.provider == @provider
      assert forked.workspace == File.cwd!()

      # The child's start request is what makes it a fork: the parent's provider session
      # to branch from, and the option this adapter declares as "branch it". Read from the
      # durable record rather than the public projection, because the request is what a
      # restart rebuilds and the projection deliberately hides provider options.
      assert {:ok, %State{} = durable} = Store.get(child.id)
      request = State.request(durable)
      assert durable.options.provider_session_id == provider_session_id(ref)
      assert durable.options.provider_options.fork_session == true
      assert request.provider_session_id == forked.provider_session_id
      refute request.provider_session_id == provider_session_id(ref)

      # And it is the request the provider is actually handed, not just the checkpoint.
      assert {:ok, _turn} =
               InteractiveSession.send_message(Ref.new(child.id), "carry on the branch",
                 id: unique_id("turn")
               )

      assert_receive {:ouroboros_test_model_started, _run,
                      %RunRequest{
                        provider_session_id: fork_source_id,
                        provider_options: %{fork_session: true}
                      }, child_adapter},
                     2_000

      assert fork_source_id == provider_session_id(ref)

      # And the parent is untouched but for the count of branches it has started.
      assert {:ok, %State{} = parent} = InteractiveSession.info(ref)
      assert State.forks(parent) == 1
      assert State.forked_from(parent) == nil
      refute State.terminal?(parent)

      if Process.alive?(child_adapter), do: HarnessAdapter.finish(child_adapter)
      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(child.id)
      retire_session(id)
    end

    test "the child inherits the options the parent is actually running with", %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only, approval_mode: :auto_edit)
      adapter = name_provider_session(ref)

      # Changed mid-life, so the durable options are no longer the ones it started with.
      assert {:ok, _result} = InteractiveSession.configure(ref, %{approval_mode: :auto_approve})

      assert {:ok, child} = InteractiveSession.fork(ref, unique_id("fork"))

      assert {:ok, _turn} =
               InteractiveSession.send_message(Ref.new(child.id), "carry on the branch",
                 id: unique_id("turn")
               )

      assert_receive {:ouroboros_test_model_started, _run,
                      %RunRequest{approval_mode: :auto_approve, sandbox_mode: :read_only},
                      child_adapter},
                     2_000

      if Process.alive?(child_adapter), do: HarnessAdapter.finish(child_adapter)
      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(child.id)
      retire_session(id)
    end

    test "an unnamed historical session has nothing to branch", %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)

      :sys.replace_state(Task.whereis(id), fn runtime ->
        %{runtime | session: %{runtime.session | provider_session_id: nil}}
      end)

      assert {:error, {:unforkable_session, details}} = InteractiveSession.fork(ref)
      assert details.reason == :no_provider_session_id
      assert details.message =~ "nothing to branch from"

      retire_session(id)
    end

    # R3. `model` is the one piece of the parent's start intent a fork may replace. It is
    # asserted on the plan because the plan *is* the child's start request — the projection
    # a client sees deliberately hides provider options — and because a plan starts
    # nothing, which keeps the assertion clear of provider readiness. That the substituted
    # spec then reaches a live child and its journal is
    # `Ouroboros.Provider.Native.InteractivePlaneTest`, on a provider that has real models.
    test "a fork may substitute the child's model, and inherits the parent's otherwise",
         %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)
      adapter = name_provider_session(ref)

      # Nothing named: the child's start intent is the parent's, untouched. This is the
      # behaviour every fork before this parameter relied on.
      assert {:ok, inherited} =
               GenServer.call(Task.whereis(id), {:fork_plan, unique_id("inherit"), %{}})

      # This provider normalizes no `:model`, so the parent has none and neither does the
      # plan. A fork that invented one would be starting a different session.
      refute inherited[:model]

      assert {:ok, substituted} =
               GenServer.call(
                 Task.whereis(id),
                 {:fork_plan, unique_id("substitute"), %{model: "challenger-model"}}
               )

      assert substituted[:model] == "challenger-model"

      # Exactly one key moved. Everything else about the child is still the parent's own
      # start intent, which is what keeps a model substitution from being a second start.
      assert substituted[:forked_from] == id
      assert substituted[:provider] == @provider
      assert substituted[:provider_session_id] == provider_session_id(ref)
      assert substituted[:provider_options][:fork_session] == true
      assert substituted[:sandbox_mode] == :read_only

      assert Keyword.delete(substituted, :model)
             |> Keyword.equal?(
               Keyword.delete(inherited, :model)
               |> Keyword.put(:id, substituted[:id])
             )

      # A plan is intent, not a session: naming a model started nothing.
      assert Store.get(substituted[:id]) == :not_found

      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(id)
    end

    # The two-element call is what a parent coordinator on an older build in the same fleet
    # still receives. It has to keep planning a tail fork rather than killing the parent
    # with a `function_clause` on a message shape it has never seen.
    test "the coordinator still answers the fork_plan call that carries no overrides",
         %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)
      adapter = name_provider_session(ref)
      planned = unique_id("legacy-plan")

      assert {:ok, opts} = GenServer.call(Task.whereis(id), {:fork_plan, planned})
      assert opts[:id] == planned
      assert opts[:forked_from] == id
      refute Map.has_key?(Map.new(opts[:provider_options]), :fork_to_turn)

      assert {:ok, %State{id: ^id}} = InteractiveSession.info(ref)

      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(id)
    end

    test "the fork id is caller-owned, so a repeat opens the same child", %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)
      adapter = name_provider_session(ref)
      fork_id = unique_id("stable-fork")

      assert {:ok, first} = InteractiveSession.fork(ref, fork_id)
      assert {:ok, second} = InteractiveSession.fork(ref, fork_id)
      assert second.id == first.id

      # Idempotent, not duplicated: the second call matched the existing durable session
      # rather than creating a second one under the same id.
      assert {:ok, %State{} = forked} = InteractiveSession.info(Ref.new(first.id))
      assert State.forked_from(forked) == id

      # The parent counts both calls: it started a fork twice, and the second one found
      # the first. A count is a hint, and it says so.
      assert {:ok, %State{} = parent} = InteractiveSession.info(ref)
      assert State.forks(parent) == 2

      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(first.id)
      retire_session(id)
    end

    test "the coordinator plans a fork and starts nothing", %{id: id} do
      # A session start waits on provider readiness with no bound. If that wait happened
      # inside the parent's coordinator, the parent would answer nothing — not `info`, not
      # `interrupt`, not its own turns — until a child it does not own had finished
      # starting. So the coordinator's whole job is the child's start intent.
      ref = start_session(id, sandbox_mode: :read_only)
      adapter = name_provider_session(ref)
      planned = unique_id("planned-child")

      assert {:ok, opts} = GenServer.call(Task.whereis(id), {:fork_plan, planned})

      assert opts[:id] == planned
      assert opts[:forked_from] == id
      assert opts[:provider] == @provider
      assert opts[:workspace] == File.cwd!()
      assert opts[:provider_session_id] == provider_session_id(ref)
      assert opts[:provider_options][:fork_session] == true

      # A plan is intent, not a session: nothing was created and nothing was started.
      assert Store.get(planned) == :not_found
      assert Task.whereis(planned) == nil

      # And the parent still answers, having never left its own loop.
      assert {:ok, %State{id: ^id}} = InteractiveSession.info(ref)

      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(id)
    end

    test "the parent answers while a fork is in flight", %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)
      adapter = name_provider_session(ref)

      forker =
        Elixir.Task.async(fn -> InteractiveSession.fork(ref, unique_id("concurrent-fork")) end)

      for _attempt <- 1..5 do
        assert {:ok, %State{id: ^id}} = InteractiveSession.info(ref)
      end

      assert {:ok, child} = Elixir.Task.await(forker, 5_000)

      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(child.id)
      retire_session(id)
    end

    test "an invalid fork id is refused before anything is started", %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)

      assert {:error, :invalid_fork_id} = InteractiveSession.fork(ref, "   ")
      assert {:error, :invalid_fork_id} = InteractiveSession.fork(ref, 42)

      retire_session(id)
    end
  end

  describe "interactive.list rows" do
    test "a row carries title, cursor, and a usage summary, and no event window", %{id: id} do
      ref = start_session(id)
      assert {:ok, _renamed} = InteractiveSession.rename(ref, "A row in the picker")

      assert {:ok, _turn} =
               InteractiveSession.send_message(ref, "spend something", id: unique_id("turn"))

      assert_receive {:ouroboros_test_model_started, _run, %RunRequest{}, adapter}, 2_000

      assert :ok =
               HarnessAdapter.emit(adapter, :usage, %{
                 "input_tokens" => 120,
                 "output_tokens" => 30,
                 "total_tokens" => 150
               })

      assert :ok = HarnessAdapter.finish(adapter)

      row =
        assert_eventually(fn ->
          case Enum.find(InteractiveSession.list(), &(&1.id == id)) do
            %State{usage: %{total_tokens: total}} = row when is_integer(total) and total > 0 ->
              row

            _not_yet ->
              false
          end
        end)

      assert row.title == "A row in the picker"
      assert row.title_source == :human

      # The integer H1 found a client had to fetch a whole transcript to read.
      assert is_integer(row.cursor) and row.cursor > 0

      # A summary, not the whole account: two numbers, and `nil` for a cost nobody stated.
      assert row.usage == %{total_tokens: 150, cost_usd: nil}

      # Bounded by construction. The session itself has both of these.
      assert row.events == []
      assert row.turns == %{}

      assert {:ok, %State{} = whole} = InteractiveSession.info(ref)
      assert whole.events != []
      assert map_size(whole.turns) > 0

      # And the capability map a footer greys its verbs from is still on the row.
      assert row.options.capabilities.fork == :native
      assert Map.has_key?(row.options, :approval_mode)

      # R3/D10. Present and false rather than absent: a client reads an absent capability
      # as offered, so omitting it here would advertise replay for a session that has no
      # journal because its tool loop ran in a vendor process.
      assert row.options.capabilities.replay == true

      assert :ok = HarnessAdapter.finish(adapter)
      retire_session(id)
    end

    test "an unspent session reports no tokens rather than a zero that reads as free",
         %{id: id} do
      start_session(id)

      row = Enum.find(InteractiveSession.list(), &(&1.id == id))
      assert row.usage == %{total_tokens: nil, cost_usd: nil}

      retire_session(id)
    end

    test "a fork's parentage is visible from the list without opening either session",
         %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)
      adapter = name_provider_session(ref)
      fork_id = unique_id("listed-fork")

      assert {:ok, _child} = InteractiveSession.fork(ref, fork_id)

      rows = InteractiveSession.list()
      assert %State{forked_from: ^id} = Enum.find(rows, &(&1.id == fork_id))
      assert %State{forks: 1, forked_from: nil} = Enum.find(rows, &(&1.id == id))

      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(fork_id)
      retire_session(id)
    end
  end

  describe "State.auto_title/1" do
    test "takes the first line, bounds it, and refuses to invent one" do
      assert State.auto_title("one line") == "one line"
      assert State.auto_title("first\nsecond") == "first"
      assert State.auto_title("first\r\nsecond") == "first"
      assert State.auto_title("  padded  \nrest") == "padded"

      long = String.duplicate("a", 200)
      titled = State.auto_title(long)
      assert String.length(titled) == 60
      assert String.ends_with?(titled, "…")

      assert State.auto_title("") == nil
      assert State.auto_title("   \n  ") == nil
      assert State.auto_title(nil) == nil
      assert State.auto_title(%{}) == nil

      # A control character never reaches a picker row, whichever half of the rule it hits.
      refute State.auto_title("bell\ain the middle") =~ "\a"
    end
  end

  defp start_session(id, opts \\ []) do
    opts = Keyword.merge([id: id, provider: @provider, workspace: File.cwd!()], opts)
    assert {:ok, ref} = InteractiveSession.start(opts)
    ref
  end

  # Nothing can be branched until the provider has named its own session, which it does by
  # emitting anything at all. Returns the adapter process so the caller can finish it.
  defp name_provider_session(ref) do
    assert {:ok, _turn} =
             InteractiveSession.send_message(ref, "name the session", id: unique_id("turn"))

    assert_receive {:ouroboros_test_model_started, _run, %RunRequest{}, adapter}, 2_000
    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "working"})
    assert :ok = HarnessAdapter.finish(adapter)
    assert_eventually(fn -> ready_for_next_turn?(ref) end)

    assert_eventually(fn ->
      match?(
        {:ok, %State{provider_session_id: id}} when is_binary(id),
        InteractiveSession.info(ref)
      )
    end)

    adapter
  end

  defp ready_for_next_turn?(ref) do
    with {:ok, %State{status: :idle, harness_session_id: id}} <- InteractiveSession.info(ref),
         {:ok, %{state: :idle, active_turn_id: nil}} <- Session.info(id),
         do: true,
         else: (_ -> false)
  end

  defp provider_session_id(ref) do
    {:ok, session} = InteractiveSession.info(ref)
    session.provider_session_id
  end

  defp accepted_inputs(ref) do
    case InteractiveSession.replay(ref, cursor: 0, limit: 500) do
      {:ok, events} -> Enum.count(events, &(&1.type == :input_accepted))
      _other -> 0
    end
  end

  defp retire_session(id) do
    _ = InteractiveSession.kill(id)

    case Task.whereis(id) do
      pid when is_pid(pid) ->
        DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      _ ->
        :ok
    end

    case Store.get(id) do
      {:ok, session} ->
        _ = Store.put(%{session | status: :cancelled})
        _ = Store.delete(id)

      _ ->
        :ok
    end

    :ok
  end

  defp cleanup_sessions do
    Session.list()
    |> Enum.each(fn info ->
      unless SessionInfo.terminal?(info), do: Session.kill(info.session_id)

      if is_pid(info.pid) and Process.alive?(info.pid),
        do: DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, info.pid)
    end)
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end

  defp assert_eventually(fun, attempts \\ 200)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    case fun.() do
      value when value in [false, nil] ->
        Process.sleep(10)
        assert_eventually(fun, attempts - 1)

      value ->
        value
    end
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-interactive-controls-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp restore_native_dir(nil), do: Application.delete_env(:ouroboros, :native_data_dir)
  defp restore_native_dir(value), do: Application.put_env(:ouroboros, :native_data_dir, value)
end
