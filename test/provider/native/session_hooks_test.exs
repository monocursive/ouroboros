defmodule Ouroboros.Provider.Native.SessionHooksTest do
  @moduledoc """
  The three hook events the session dispatches rather than the loop: `SessionStart`,
  `SessionEnd`, `PreCompact`.

  Every hook here is a real `/bin/sh` script run through the real runner, the same rule
  `Ouroboros.Provider.Native.HooksTest` follows: the contract under test is a process
  contract — stdin, stdout, stderr, exit codes — and a stub of it would test nothing. Each
  script writes what it was handed to a file, so the assertions read the payload the hook
  actually received.

  Not `async`: the data directory, the model module and the user hook path are all node
  configuration.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-lifecycle-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)

    previous = %{
      dir: Application.get_env(:ouroboros, :native_data_dir),
      model: Application.get_env(:ouroboros, :native_model_module),
      hooks: Application.get_env(:ouroboros, :native_user_hooks_path)
    }

    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)
    # An absent user file by default: a test must never read, still less run, the
    # machine's own `~/.config/ouroboros/hooks.toml`.
    Application.put_env(:ouroboros, :native_user_hooks_path, Path.join(root, "absent.toml"))

    on_exit(fn ->
      restore(:native_data_dir, previous.dir)
      restore(:native_model_module, previous.model)
      restore(:native_user_hooks_path, previous.hooks)
      File.rm_rf(root)
    end)

    # The canonical root, because that is what the session resolves `cwd` to and what a
    # hook is therefore handed — on macOS `/var` is a symlink to `/private/var`.
    {:ok, scope} = Paths.scope(workspace, [], :workspace_write)

    %{root: root, workspace: workspace, canonical: scope.root, data_dir: data_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp script(root, name, body) do
    path = Path.join(root, name)
    File.write!(path, "#!/bin/sh\n" <> body)
    File.chmod!(path, 0o755)
    path
  end

  # User scope, because it needs no workspace trust and this suite is about the events
  # rather than about the trust gate, which `HooksTest` already pins.
  defp user_hooks(root, body) do
    path = Path.join(root, "user-hooks.toml")
    File.write!(path, body)
    Application.put_env(:ouroboros, :native_user_hooks_path, path)
    path
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
            approval_timeout_ms: 5_000
          },
          overrides
        )
      )

    {:ok, handle} =
      Session.open(request, %{
        session_id: "sess-lifecycle-#{System.unique_integer([:positive])}",
        provider: :native,
        owner: self(),
        adapter: Ouroboros.Provider.Native,
        config: %{},
        process_manager: Jido.Harness.ProcessDriver.Erlexec,
        telemetry_context: %{}
      })

    on_exit(fn -> if Process.alive?(handle), do: Session.close(handle) end)
    %{handle: handle, agent: agent, request: request}
  end

  defp await_event(type, timeout \\ 15_000) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> event
      {:session_adapter_event, _other} -> await_event(type, timeout)
    after
      timeout -> flunk("no #{type} within #{timeout}ms")
    end
  end

  defp await_provider_event(status, timeout \\ 15_000) do
    receive do
      {:session_adapter_event, %{type: :provider_event, payload: %{"status" => ^status}} = event} ->
        event

      {:session_adapter_event, _other} ->
        await_provider_event(status, timeout)
    after
      timeout -> flunk("no #{status} provider_event within #{timeout}ms")
    end
  end

  defp drain do
    receive do
      {:session_adapter_event, _event} -> drain()
    after
      0 -> :ok
    end
  end

  defp eventually(path, timeout \\ 5_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    wait_for_file(path, deadline)
  end

  defp wait_for_file(path, deadline) do
    case File.read(path) do
      {:ok, body} ->
        case JSON.decode(body) do
          {:ok, _payload} -> body
          {:error, _reason} -> retry_file(path, deadline)
        end

      {:error, _reason} ->
        retry_file(path, deadline)
    end
  end

  defp retry_file(path, deadline) do
    if System.monotonic_time(:millisecond) < deadline do
      Process.sleep(25)
      wait_for_file(path, deadline)
    else
      flunk("#{path} was never written as complete JSON")
    end
  end

  @simple [[{:text, "hello"}, {:finish, :stop}]]

  # ---------------------------------------------------------------- SessionStart

  describe "SessionStart" do
    test "fires when a session opens, with the documented payload", context do
      record = Path.join(context.root, "start.json")
      hook = script(context.root, "start.sh", "cat > #{record}\n")
      user_hooks(context.root, ~s([[hooks]]\nevent = "SessionStart"\ncommand = "#{hook}"\n))

      %{handle: handle} = open(context, @simple)
      await_event(:provider_event)

      payload = JSON.decode!(eventually(record))

      assert payload["hook_event_name"] == "SessionStart"
      assert payload["source"] == "startup"
      assert payload["cwd"] == context.canonical
      assert String.starts_with?(payload["provider_session_id"], "native-")
      assert payload["turn_id"] == nil
      assert Process.alive?(handle)
    end

    test "its additionalContext joins the first turn's prompt and only the first", context do
      hook =
        script(
          context.root,
          "start.sh",
          ~s(cat > /dev/null\necho '{"hookSpecificOutput":) <>
            ~s({"additionalContext":"the migration is half applied"}}'\n)
        )

      user_hooks(context.root, ~s([[hooks]]\nevent = "SessionStart"\ncommand = "#{hook}"\n))

      %{handle: handle, agent: agent} = open(context, @simple ++ @simple)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("first"), "turn-1")
      await_event(:turn_completed)
      assert :ok = Session.send(handle, TurnRequest.new!("second"), "turn-2")
      await_event(:turn_completed)

      assert [first, second] = NativeModelScript.requests(agent)

      assert List.last(first.messages).content =~ "the migration is half applied"
      assert List.last(second.messages).content == "second"

      # Never the system prompt: the prefix has a fingerprint, and a session-scoped
      # instruction in it would cost the cache on every turn after this one.
      refute first.system =~ "the migration is half applied"
    end

    test "names the source as a resume when the session was resumed", context do
      record = Path.join(context.root, "start.json")
      hook = script(context.root, "start.sh", "cat > #{record}\n")

      %{handle: handle, request: request} = open(context, @simple)
      ready = await_event(:provider_event)
      assert :ok = Session.close(handle)
      drain()

      user_hooks(context.root, ~s([[hooks]]\nevent = "SessionStart"\ncommand = "#{hook}"\n))
      {model_spec, _agent} = NativeModelScript.start(@simple)

      {:ok, resumed} =
        Session.open(
          SessionRequest.new!(%{
            provider: :native,
            cwd: request.cwd,
            model: model_spec,
            provider_session_id: ready.provider_session_id
          }),
          %{
            session_id: "sess-resumed",
            provider: :native,
            owner: self(),
            adapter: Ouroboros.Provider.Native,
            config: %{},
            process_manager: Jido.Harness.ProcessDriver.Erlexec,
            telemetry_context: %{}
          }
        )

      on_exit(fn -> if Process.alive?(resumed), do: Session.close(resumed) end)

      assert JSON.decode!(eventually(record))["source"] == "resume"
    end

    test "a hook that hangs is killed at its bound and the session still opens", context do
      hook = script(context.root, "slow.sh", "sleep 30\n")

      user_hooks(
        context.root,
        ~s([[hooks]]\nevent = "SessionStart"\ncommand = "#{hook}"\ntimeout_ms = 300\n)
      )

      started = System.monotonic_time(:millisecond)
      %{handle: handle} = open(context, @simple)
      await_event(:provider_event)
      elapsed = System.monotonic_time(:millisecond) - started

      assert Process.alive?(handle)
      assert elapsed < 10_000, "session open waited #{elapsed}ms on a hook bounded at 300ms"
    end
  end

  # ---------------------------------------------------------------- SessionEnd

  describe "SessionEnd" do
    test "fires on close with the reason", context do
      record = Path.join(context.root, "end.json")
      hook = script(context.root, "end.sh", "cat > #{record}\n")
      user_hooks(context.root, ~s([[hooks]]\nevent = "SessionEnd"\ncommand = "#{hook}"\n))

      %{handle: handle} = open(context, @simple)
      await_event(:provider_event)

      assert :ok = Session.close(handle)
      await_event(:session_closed)

      payload = JSON.decode!(eventually(record))
      assert payload["hook_event_name"] == "SessionEnd"
      assert payload["reason"] == "closed"
      assert payload["cwd"] == context.canonical
    end

    test "a hook that hangs never blocks the close", context do
      record = Path.join(context.root, "end.json")
      hook = script(context.root, "end.sh", "cat > #{record}\nsleep 30\n")
      user_hooks(context.root, ~s([[hooks]]\nevent = "SessionEnd"\ncommand = "#{hook}"\n))

      %{handle: handle} = open(context, @simple)
      await_event(:provider_event)

      started = System.monotonic_time(:millisecond)
      assert :ok = Session.close(handle)
      elapsed = System.monotonic_time(:millisecond) - started

      assert elapsed < 5_000, "close waited #{elapsed}ms on a detached SessionEnd hook"
      assert JSON.decode!(eventually(record))["reason"] == "closed"
    end
  end

  # ---------------------------------------------------------------- PreCompact

  describe "PreCompact" do
    test "fires before a compaction with the trigger and the focus", context do
      record = Path.join(context.root, "compact.json")
      hook = script(context.root, "compact.sh", "cat > #{record}\n")
      user_hooks(context.root, ~s([[hooks]]\nevent = "PreCompact"\ncommand = "#{hook}"\n))

      %{handle: handle} = open(context, @simple)
      await_event(:provider_event)
      assert :ok = Session.send(handle, TurnRequest.new!("hi"), "turn-1")
      await_event(:turn_completed)
      drain()

      assert {:ok, _report} = Session.compact(handle, "the failing test")

      payload = JSON.decode!(eventually(record))
      assert payload["hook_event_name"] == "PreCompact"
      assert payload["trigger"] == "manual"
      assert payload["custom_instructions"] == "the failing test"
      assert is_integer(payload["messages"])
    end

    test "exit 2 refuses the compaction with its stderr as the reason and keeps everything",
         context do
      hook =
        script(context.root, "veto.sh", "cat > /dev/null\necho 'mid-migration' >&2\nexit 2\n")

      user_hooks(context.root, ~s([[hooks]]\nevent = "PreCompact"\ncommand = "#{hook}"\n))

      %{handle: handle} = open(context, @simple)
      await_event(:provider_event)
      assert :ok = Session.send(handle, TurnRequest.new!("hi"), "turn-1")
      await_event(:turn_completed)

      {:ok, before} = Session.info(handle)
      drain()

      assert {:error, {:pre_compact_denied, "mid-migration"}} = Session.compact(handle, nil)

      event = await_provider_event("compaction_refused")
      assert event.payload["cause"] == "pre_compact_hook_denied"
      assert event.payload["reason"] == "mid-migration"
      assert event.payload["message"] =~ "Nothing was dropped"

      # Nothing folded, nothing archived, nothing lost.
      {:ok, unchanged} = Session.info(handle)
      assert unchanged.messages == before.messages
      assert unchanged.compactions == []
      assert unchanged.archives == []
    end

    test "a PreCompact hook that says nothing lets the compaction through", context do
      hook = script(context.root, "quiet.sh", "cat > /dev/null\n")
      user_hooks(context.root, ~s([[hooks]]\nevent = "PreCompact"\ncommand = "#{hook}"\n))

      %{handle: handle} = open(context, @simple)
      await_event(:provider_event)
      assert :ok = Session.send(handle, TurnRequest.new!("hi"), "turn-1")
      await_event(:turn_completed)
      drain()

      assert {:ok, report} = Session.compact(handle, nil)
      assert report.trigger == "manual"
    end
  end
end
