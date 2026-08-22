defmodule Ouroboros.InteractiveResumeTest do
  @moduledoc """
  A session survives the runtime: the Harness session is disposable, the provider
  session is not.

  Every test here removes the Harness session out from under a live coordinator — the
  same event a BEAM or host restart produces, minus the restart — and asks what the
  session does next. The answer these tests pin down is: resume onto a new Harness
  session while the provider session id is durable and the transport can carry it, and
  only then `:lost`.
  """

  use ExUnit.Case, async: false

  alias Jido.Harness.{RunRequest, Session, SessionInfo}
  alias Ouroboros.Interactive.{Ref, State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test
  @provider_session_id "ouroboros-test-session"

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
      assert {:ok, _started} = Application.ensure_all_started(:ouroboros)
    end)

    {:ok, id: unique_id("resume")}
  end

  test "a Harness session that disappears mid-life is resumed, not lost", %{id: id} do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    turn_id = unique_id("in-flight-turn")
    assert {:ok, _turn} = InteractiveSession.send_message(ref, "start something", id: turn_id)

    assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{provider_session_id: nil},
                    adapter},
                   1_000

    # The provider names its own session. Until it has, there is nothing to resume with
    # — which is the case the last test in this file covers.
    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "working"})

    %State{harness_session_id: gone, cursor: cursor_before} =
      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{provider_session_id: @provider_session_id} = session} -> session
          _other -> false
        end
      end)

    kill_harness_session(gone)

    resumed =
      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{harness_session_id: current} = session}
          when is_binary(current) and current != gone ->
            session

          _other ->
            false
        end
      end)

    refute State.terminal?(resumed)
    assert resumed.status != :lost
    assert resumed.resumes == 1
    assert resumed.provider_session_id == @provider_session_id

    # The turn that was in flight at the break is finalised outcome-unknown. The
    # provider may well have finished it; nothing on this side can tell, and nothing
    # redispatches it.
    assert %{status: :ambiguous, error: {:session_resumed, :outcome_unknown}} =
             resumed.turns[turn_id]

    # The new Harness session replays its own `session_started` / `session_ready`, and
    # they become Ouroboros events above the resume marker rather than restarting the
    # numbering at one and colliding with the log the session already has.
    events =
      assert_eventually(fn ->
        with {:ok, events} <- InteractiveSession.replay(ref, cursor: 0, limit: 500),
             true <- Enum.any?(events, &(&1.type == :status)),
             marker = Enum.find(events, &(&1.type == :status)),
             true <-
               Enum.any?(events, &(&1.type == :session_started and &1.sequence > marker.sequence)) do
          events
        else
          _not_yet -> false
        end
      end)

    sequences = Enum.map(events, & &1.sequence)
    assert sequences == Enum.sort(sequences)
    assert sequences == Enum.uniq(sequences)

    assert [status_event] = Enum.filter(events, &(&1.type == :status))

    assert status_event.payload == %{
             "kind" => "resumed",
             "provider_session_id" => @provider_session_id,
             "previous_harness_session_id" => gone
           }

    # The marker sits above everything the session had before the break — the coordinator
    # may have ingested another event or two between reading the cursor and the kill —
    # and below everything the resumed Harness session produces.
    assert status_event.sequence > cursor_before

    {before_resume, after_resume} =
      Enum.split_while(events, &(&1.sequence < status_event.sequence))

    assert Enum.all?(before_resume, &(&1.harness_session_id == gone))
    assert [^status_event | after_resume] = after_resume
    assert after_resume != []
    assert Enum.all?(after_resume, &(&1.harness_session_id == resumed.harness_session_id))

    # And the session still works: the next turn reaches the provider carrying the
    # provider session id that was resumed, which is what `--resume` / `thread/resume` /
    # `session/load` are built from.
    next_turn_id = unique_id("after-resume-turn")
    assert {:ok, _turn} = InteractiveSession.send_message(ref, "keep going", id: next_turn_id)

    assert_receive {:ouroboros_test_adapter_started, _resumed_run,
                    %RunRequest{provider_session_id: @provider_session_id}, resumed_adapter},
                   2_000

    assert :ok = HarnessAdapter.finish(resumed_adapter)
    if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
    retire_session(id)
  end

  test "one resume per coordinator: a second disappearance loses the session", %{id: id} do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    assert {:ok, _turn} =
             InteractiveSession.send_message(ref, "name the session", id: unique_id("turn"))

    assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 1_000
    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "working"})

    %State{harness_session_id: first} =
      assert_eventually(fn -> session_with_provider_session_id(ref) end)

    kill_harness_session(first)

    %State{harness_session_id: second} =
      assert_eventually(fn -> session_resumed_from(ref, first) end)

    kill_harness_session(second)

    lost =
      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{status: :lost} = session} -> session
          _other -> false
        end
      end)

    assert lost.error == :harness_session_not_found
    assert lost.resumes == 1
    if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
    retire_session(id)
  end

  test "a provider that refuses the resume loses the session, naming the refusal", %{id: id} do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    assert {:ok, _turn} =
             InteractiveSession.send_message(ref, "name the session", id: unique_id("turn"))

    assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 1_000
    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "working"})

    %State{harness_session_id: gone} =
      assert_eventually(fn -> session_with_provider_session_id(ref) end)

    # The provider still declares that it can resume; it just does not know this thread
    # any more. That is a refusal, and it is the only thing that may end as `:lost`.
    HarnessAdapter.accept_resume(["some-other-thread"])
    kill_harness_session(gone)

    lost =
      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{status: :lost} = session} -> session
          _other -> false
        end
      end)

    assert {:resume_failed, _reason} = lost.error
    assert lost.resumes == 0
    assert lost.harness_session_id == gone
    if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
    retire_session(id)
  end

  test "a session the caller killed is ended, not resumed", %{id: id} do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    assert {:ok, _turn} =
             InteractiveSession.send_message(ref, "name the session", id: unique_id("turn"))

    assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 1_000
    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "working"})

    # Everything a resume needs is in place. What is missing is a reason to: the Harness
    # session is about to go away because someone asked for it to.
    %State{harness_session_id: harness} =
      assert_eventually(fn -> session_with_provider_session_id(ref) end)

    assert :ok = InteractiveSession.kill(ref)

    ended =
      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{} = session} -> State.terminal?(session) && session
          _other -> false
        end
      end)

    assert ended.resumes == 0
    assert ended.harness_session_id == harness
    if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
    retire_session(id)
  end

  test "a session with no provider session id is lost exactly as before", %{id: id} do
    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: File.cwd!())

    turn_id = unique_id("unnamed-turn")
    assert {:ok, _turn} = InteractiveSession.send_message(ref, "never answered", id: turn_id)
    assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{}, adapter}, 1_000

    %State{harness_session_id: gone} =
      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{harness_session_id: harness} = session} when is_binary(harness) ->
            session

          _other ->
            false
        end
      end)

    # The provider never emitted anything, so it never named a session. There is nothing
    # to resume with, and the honest answer is the one this branch always gave.
    assert {:ok, %State{provider_session_id: nil}} = InteractiveSession.info(ref)
    kill_harness_session(gone)

    lost =
      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{status: :lost} = session} -> session
          _other -> false
        end
      end)

    assert lost.error == :harness_session_not_found
    assert lost.resumes == 0

    assert %{status: :ambiguous, error: {:session_lost, :harness_session_not_found}} =
             lost.turns[turn_id]

    refute_receive {:ouroboros_test_adapter_started, _duplicate, _request, _adapter}, 100
    if Process.alive?(adapter), do: HarnessAdapter.finish(adapter)
    retire_session(id)
  end

  test "a session checkpointed before a full restart is resumed when the runtime returns" do
    id = unique_id("restart-resume")
    base = unique_base()
    workspace = Path.join(base, "workspace")
    File.mkdir_p!(workspace)

    previous_roots = Application.get_env(:ouroboros, :workspace_allowed_roots)

    # The workspace manager reads its allowed roots once, at boot. Restoring the env
    # without stopping the runtime would leave this test's temporary root in force for
    # every session started after it; the setup's `on_exit` starts the runtime again.
    on_exit(fn ->
      stop_application()
      restore_ouroboros_env(:workspace_allowed_roots, previous_roots)
      File.rm_rf(base)
    end)

    assert {:ok, session} =
             State.new(id, provider: @provider, workspace: workspace)

    # What survives a host restart: the durable record of a session whose Harness
    # session died with the BEAM, and whose provider session id is still known.
    checkpointed = %{
      session
      | status: :idle,
        harness_session_id: "harness-session-that-died-with-the-beam",
        provider_session_id: @provider_session_id,
        cursor: 7,
        event_floor: 7,
        updated_at: aged_timestamp()
    }

    stop_application()
    Application.put_env(:ouroboros, :workspace_allowed_roots, [workspace])

    assert :ok =
             Jido.Storage.ETS.put_checkpoint(
               {:ouroboros, :interactive_sessions, 1},
               %{id => checkpointed},
               table: :ouroboros_interactive
             )

    assert {:ok, _started} = Application.ensure_all_started(:ouroboros)

    resumed =
      assert_eventually(
        fn ->
          case Store.get(id) do
            {:ok, %State{harness_session_id: harness} = state}
            when is_binary(harness) and harness != "harness-session-that-died-with-the-beam" ->
              state

            _other ->
              false
          end
        end,
        500
      )

    refute State.terminal?(resumed)
    assert resumed.status != :lost
    assert resumed.resumes == 1
    assert resumed.provider_session_id == @provider_session_id

    assert [status_event] = Enum.filter(resumed.events, &(&1.type == :status))
    assert status_event.sequence == 8

    assert status_event.payload == %{
             "kind" => "resumed",
             "provider_session_id" => @provider_session_id,
             "previous_harness_session_id" => "harness-session-that-died-with-the-beam"
           }

    sequences = Enum.map(resumed.events, & &1.sequence)
    assert sequences == Enum.sort(sequences)
    assert sequences == Enum.uniq(sequences)
    assert Enum.all?(sequences, &(&1 > 7))

    assert {:ok, _turn} =
             InteractiveSession.send_message(Ref.new(id), "continue after the restart",
               id: unique_id("post-restart-turn")
             )

    assert_receive {:ouroboros_test_adapter_started, _run,
                    %RunRequest{provider_session_id: @provider_session_id}, adapter},
                   2_000

    assert :ok = HarnessAdapter.finish(adapter)
    retire_session(id)
  end

  defp session_with_provider_session_id(ref) do
    case InteractiveSession.info(ref) do
      {:ok, %State{provider_session_id: @provider_session_id} = session} -> session
      _other -> false
    end
  end

  defp session_resumed_from(ref, previous) do
    case InteractiveSession.info(ref) do
      {:ok, %State{harness_session_id: current} = session}
      when is_binary(current) and current != previous ->
        session

      _other ->
        false
    end
  end

  # Removing the Harness session is the whole premise: from the coordinator's side it is
  # indistinguishable from the runtime having been restarted under it.
  defp kill_harness_session(harness_session_id) do
    case Registry.lookup(Jido.Harness.SessionRegistry, harness_session_id) do
      [{pid, _value}] ->
        monitor = Process.monitor(pid)
        Process.exit(pid, :kill)
        assert_receive {:DOWN, ^monitor, :process, ^pid, _reason}, 2_000
        :ok

      [] ->
        flunk("harness session #{harness_session_id} was already gone")
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

  defp stop_application do
    case Application.stop(:ouroboros) do
      :ok -> :ok
      {:error, {:not_started, :ouroboros}} -> :ok
    end
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

  defp aged_timestamp,
    do: DateTime.utc_now() |> DateTime.add(-30, :second) |> DateTime.to_iso8601()

  defp unique_base do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-interactive-resume-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-interactive-resume-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)

  defp restore_ouroboros_env(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore_ouroboros_env(key, value), do: Application.put_env(:ouroboros, key, value)
end
