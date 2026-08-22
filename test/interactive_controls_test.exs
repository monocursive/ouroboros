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

  alias Jido.Harness.{RunRequest, Session, SessionInfo}
  alias Ouroboros.Interactive.{Ref, State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Provider
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  setup do
    cleanup_sessions()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()

    Application.put_env(
      :jido_harness,
      :providers,
      Map.put(map_or_empty(previous_providers), @provider, HarnessAdapter)
    )

    Application.put_env(
      :jido_harness,
      :provider_config,
      Map.put(map_or_empty(previous_provider_config), @provider, %{
        test_pid: self(),
        retention: %{journal_dir: journal_dir}
      })
    )

    HarnessAdapter.reset_resume()

    on_exit(fn ->
      HarnessAdapter.reset_resume()
      cleanup_sessions()
      restore_env(:providers, previous_providers)
      restore_env(:provider_config, previous_provider_config)
      File.rm_rf(journal_dir)
    end)

    {:ok, id: unique_id("controls")}
  end

  describe "interactive.configure" do
    test "a managed transport takes the change and says it lands on the next turn", %{id: id} do
      ref = start_session(id)

      assert {:ok, result} = InteractiveSession.configure(ref, %{approval_mode: :auto_approve})

      # The honesty invariant, as data. A managed transport re-executes the CLI per turn,
      # so the turn already running keeps the policy it started under and the answer says
      # so rather than letting a footer imply otherwise.
      assert result.applies == :next_turn
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
      assert_receive {:ouroboros_test_adapter_started, _run,
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
               "applies" => "next_turn",
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

      assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 2_000
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

    test "X1 holds on the configure path: a mode that asks nobody is refused", %{id: id} do
      # A transport with no approvals channel cannot be *started* into `:prompt`. The
      # hole this closes is the other door: a session started into a mode that works
      # being moved into one that is silently denied.
      ref = start_session(id, transport: :managed_no_approvals, approval_mode: :auto_edit)

      assert {:error, {:unsupported_approval_mode, details}} =
               InteractiveSession.configure(ref, %{approval_mode: :prompt})

      assert details.requested == :prompt
      assert details.reason == :no_approval_channel
      assert details.transport == :managed_no_approvals
      assert details.supported == [:default, :auto_edit, :auto_approve]
      assert details.message =~ "no approvals channel"

      # Refused means nothing moved.
      assert {:ok, session} = InteractiveSession.info(ref)
      assert State.public(session).options.approval_mode == :auto_edit

      retire_session(id)
    end

    test "a transport that declares no dynamic configuration refuses by declaration", %{id: id} do
      ref = start_session(id, transport: :managed_frozen)

      assert {:error, {:unconfigurable_session, details}} =
               InteractiveSession.configure(ref, %{approval_mode: :auto_approve})

      assert details.reason == :no_dynamic_configuration
      assert details.transport == :managed_frozen
      assert details.message =~ "declares no dynamic configuration"

      retire_session(id)
    end

    test "a field the transport cannot change is refused by name", %{id: id} do
      ref = start_session(id)

      # This adapter normalizes no `:model`, so its managed transport's `dynamic_model`
      # is false — the same narrowing the harness applies to the synthetic transport.
      assert {:error, {:unconfigurable_session, details}} =
               InteractiveSession.configure(ref, %{model: "some-model"})

      assert details.reason == :no_dynamic_model
      assert details.message =~ "declares no dynamic model"

      retire_session(id)
    end

    test "a value outside the transport's allowlist is refused with the allowlist", %{id: id} do
      ref = start_session(id)

      # Exactly what a start is held to: the adapter's `normalized_values`. Configuring
      # into a value the provider cannot enforce would be the sandbox equivalent of the
      # X1 hole — a policy that reads as applied and is not.
      assert {:error, {:unconfigurable_session, details}} =
               InteractiveSession.configure(ref, %{sandbox_mode: :unrestricted})

      assert details.reason == :value_not_accepted
      assert details.field == :sandbox_mode
      assert details.value == :unrestricted
      assert details.accepted_values == [:default, :read_only, :workspace_write]

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
      # for *this* model, so the session has to say which model that is. Asserted against
      # a provider that normalizes `:model`, without starting its CLI.
      assert {:ok, session} =
               State.new("controls-model-projection",
                 provider: :claude,
                 approval_mode: :auto_edit,
                 model: "claude-sonnet-5"
               )

      assert State.public(session).options.model == "claude-sonnet-5"

      configured = State.configure(session, %{model: "claude-opus-5"})
      assert State.public(configured).options.model == "claude-opus-5"

      # And the request a resume rebuilds carries it, so the change is not projection-only.
      assert State.request(configured).model == "claude-opus-5"
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

      assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 2_000

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
      assert_eventually(fn -> idle?(ref) end)

      assert {:ok, _turn} =
               InteractiveSession.send_message(ref, "now do something else entirely",
                 id: unique_id("turn")
               )

      assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, second}, 2_000

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

      assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 2_000

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

      assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 2_000

      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{} = session} -> State.title_source(session) == :auto && session
          _other -> false
        end
      end)

      assert {:ok, renamed} = InteractiveSession.rename(ref, "the human's decision")
      assert renamed.title_source == :human

      assert :ok = HarnessAdapter.finish(adapter)
      assert_eventually(fn -> idle?(ref) end)

      assert {:ok, _turn} =
               InteractiveSession.send_message(ref, "another prompt", id: unique_id("turn"))

      assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, second}, 2_000
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
      assert request.provider_session_id == "ouroboros-test-session"
      assert request.provider_options.fork_session == true

      # And it is the request the provider is actually handed, not just the checkpoint.
      assert {:ok, _turn} =
               InteractiveSession.send_message(Ref.new(child.id), "carry on the branch",
                 id: unique_id("turn")
               )

      assert_receive {:ouroboros_test_adapter_started, _run,
                      %RunRequest{
                        provider_session_id: "ouroboros-test-session",
                        provider_options: %{fork_session: true}
                      }, child_adapter},
                     2_000

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

      assert_receive {:ouroboros_test_adapter_started, _run,
                      %RunRequest{approval_mode: :auto_approve, sandbox_mode: :read_only},
                      child_adapter},
                     2_000

      if Process.alive?(child_adapter), do: HarnessAdapter.finish(child_adapter)
      if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
      retire_session(child.id)
      retire_session(id)
    end

    test "a session the provider has not named yet has nothing to branch", %{id: id} do
      ref = start_session(id, sandbox_mode: :read_only)

      assert {:error, {:unforkable_session, details}} = InteractiveSession.fork(ref)
      assert details.reason == :no_provider_session_id
      assert details.message =~ "nothing to branch from"

      retire_session(id)
    end

    test "a transport that declares no branch verb refuses by capability", %{id: id} do
      ref = start_session(id, transport: :managed_frozen, sandbox_mode: :read_only)
      adapter = name_provider_session(ref)

      # `:managed_frozen` is `Ouroboros.Test.ManagedSessionTransport` with no
      # `configuration_options`; it still inherits the adapter's fork declaration, so the
      # honest per-transport refusal is exercised through ACP below and through the
      # capability map here.
      assert Provider.session_capabilities(@provider, :managed_frozen).fork == :native

      for provider <- [:opencode, :kimi] do
        assert Provider.session_capabilities(provider).fork == false

        assert {:error, {:unforkable_session, details}} =
                 Provider.session_fork_options(provider)

        assert details.transport == :acp
        assert details.reason == :transport_cannot_fork
        assert details.message =~ "declares no way to branch one"
      end

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

      assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 2_000

      assert :ok =
               HarnessAdapter.emit(adapter, :usage, %{
                 "input_tokens" => 120,
                 "output_tokens" => 30,
                 "total_tokens" => 150
               })

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

    assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 2_000
    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "working"})

    assert_eventually(fn ->
      match?({:ok, %State{provider_session_id: id}} when is_binary(id), InteractiveSession.info(ref))
    end)

    adapter
  end

  defp idle?(ref) do
    match?({:ok, %State{status: :idle}}, InteractiveSession.info(ref))
  end

  defp accepted_inputs(ref) do
    case InteractiveSession.replay(ref, cursor: 0, limit: 500) do
      {:ok, events} -> Enum.count(events, &(&1.type == :input_accepted))
      _other -> 0
    end
  end

  # A stubbed provider session never answers `close`, so these coordinators are retired
  # directly rather than left retrying for the rest of the suite.
  defp retire_session(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      _absent ->
        :ok
    end

    case Store.get(id) do
      {:ok, session} ->
        _ = Store.put(%{session | status: :cancelled})
        _ = Store.delete(id)

      _absent ->
        :ok
    end

    :ok
  end

  defp cleanup_sessions do
    Session.list()
    |> Enum.each(fn info ->
      unless SessionInfo.terminal?(info), do: Session.kill(info.session_id)
      _ = Session.prune(info.session_id)
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

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
