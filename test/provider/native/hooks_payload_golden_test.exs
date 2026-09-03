defmodule Ouroboros.Provider.Native.HooksPayloadGoldenTest do
  @moduledoc """
  What a component hook is *handed*, per event, pinned to
  `test/support/wasm_golden/hook_payloads.json` — the fixture docs/WASM_GUIDE.md quotes
  instead of restating.

  ## Why the payload needs a fixture of its own

  `hook_narrowing.json` (contract C6) pins what a hook may *say back*. This pins what it may
  *see*, which is the other half of D8 and the half an author has no way to observe: a guide
  that documented these payloads by hand would be a second copy of `hooks.ex`, drifting from
  the day it was written. So the guide quotes this file, this file is generated from nothing —
  every byte of it was read off the wire — and this test puts it back through the seam.

  ## Through the seam, not beside it

  Every case drives a **public** function of `Ouroboros.Provider.Native.Hooks` with the base
  map its real caller builds, and asserts on the `call` frame the helper received. Nothing
  here reaches a private function and no `@doc false` seam was added: `invoke/3`,
  `tool_response/2` and the `Map.merge` in each dispatch site are all reachable from the
  surface a turn uses, so a payload this file observed is a payload the loop would have sent.

  The **base** half of each payload — `session_id`, `provider_session_id`, `turn_id`, `cwd`,
  `workspace_trusted` — is built by the *caller*, not by `hooks.ex`: `hook_base/1` in
  `provider/native/loop.ex` for a turn and in `provider/native/session.ex` for the three
  lifecycle events. This file supplies it as those two do, and one test reads the two
  definitions out of their own source and asserts their key sets are the fixture's — so a key
  added to or removed from either goes red here rather than silently making the guide wrong.

  ## What a mutation costs

    * Delete the untrusted clause of `tool_response/2` — hand the response through — and the
      two untrusted `PostToolUse*` cases go red with the output body on the wire, which is a
      clone reading every file this session read.
    * Drop `"tool_input"` from the `PreToolUse` merge and that case goes red: a hook that may
      deny needs the arguments it is denying.
    * Rename any `@event_names` value and the case for that event goes red on
      `hook_event_name`, which is the field every compatible hook branches on.
    * Give a `[checks]` component the session base and its case goes red: a check is told its
      own name and nothing else.

  Not `async`: every case spawns an OS child for the fake helper.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Hooks

  @moduletag :capture_log

  @fixture Path.join([__DIR__, "..", "..", "support", "wasm_golden", "hook_payloads.json"])

  # The two `hook_base/1` definitions this file stands in for. Read as source, because the
  # function is private to a module whose public surface takes the map already built.
  @loop_source Path.join([
                 __DIR__,
                 "..",
                 "..",
                 "..",
                 "lib",
                 "ouroboros",
                 "provider",
                 "native",
                 "loop.ex"
               ])
  @session_source Path.join([
                    __DIR__,
                    "..",
                    "..",
                    "..",
                    "lib",
                    "ouroboros",
                    "provider",
                    "native",
                    "session.ex"
                  ])

  # The base a turn's hooks are handed, with the values this fixture uses. Every key comes
  # from `hook_base/1`; the test below proves the key set still matches.
  @base %{
    "session_id" => "sess-01HQ",
    "provider_session_id" => "prov-01HQ",
    "turn_id" => "turn-3",
    "cwd" => "/w",
    "workspace_trusted" => true
  }

  setup do
    root = Path.join(System.tmp_dir!(), "hooks-payload-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "hooks"))
    on_exit(fn -> File.rm_rf(root) end)

    # W16, D25. This lane stages a hook's bytes into the node's own component store before it
    # names a path to the helper, so a node without a data directory has nowhere to put them
    # and the hook is refused. A test is a node: it says where its data directory is.
    previous = Application.fetch_env(:ouroboros, :data_dir)
    Application.put_env(:ouroboros, :data_dir, Path.join(root, "data"))

    on_exit(fn ->
      case previous do
        {:ok, held} -> Application.put_env(:ouroboros, :data_dir, held)
        :error -> Application.delete_env(:ouroboros, :data_dir)
      end
    end)

    # Real bytes on disk: the seam stats, reads and hashes the file before it says a word to
    # the helper, so a component path naming nothing would never reach the fake.
    component = Path.join([workspace, "hooks", "vet.wasm"])
    File.write!(component, "\0asm\x01\x00\x00\x00 not a real component")

    %{root: root, workspace: workspace, fixture: fixture()}
  end

  describe "the fixture is a fixture" do
    test "it names every event this runtime dispatches, plus the check payload", %{
      fixture: fixture
    } do
      events = fixture["cases"] |> Enum.map(& &1["event"]) |> Enum.uniq() |> Enum.sort()

      dispatched =
        Hooks.events()
        |> Enum.map(&Macro.camelize(Atom.to_string(&1)))
        |> Enum.sort()

      assert Enum.sort(["check" | dispatched]) == events,
             "the fixture and `Hooks.events/0` disagree about the event vocabulary"
    end

    test "it says which events an untrusted hook is not dispatched on at all", %{
      fixture: fixture
    } do
      # The narrowing fixture (C6) proves the behaviour; this only keeps the two documents
      # naming the same three events, because a payload table that listed a payload for an
      # event nobody dispatches would be a table describing something that never happens.
      assert Enum.sort(fixture["not_dispatched_untrusted"]) ==
               Enum.sort(["Notification", "FileChanged", "SessionEnd"])

      for event <- fixture["not_dispatched_untrusted"] do
        assert [] ==
                 Enum.filter(
                   fixture["cases"],
                   &(&1["event"] == event and &1["lane"] == "untrusted")
                 )
      end
    end

    test "every case is one of the two lanes and carries a payload object", %{fixture: fixture} do
      assert length(fixture["cases"]) >= 13
      assert Enum.all?(fixture["cases"], &(&1["lane"] in ["trusted", "untrusted"]))
      assert Enum.all?(fixture["cases"], &is_map(&1["payload"]))
      assert Enum.all?(fixture["cases"], &(is_binary(&1["name"]) and &1["name"] != ""))
    end
  end

  describe "the base half is the base the callers build" do
    test "`hook_base/1` in the loop and in the session name the fixture's keys", %{
      fixture: fixture
    } do
      expected = Enum.sort(fixture["base_keys"])

      assert base_keys(@loop_source) == expected,
             "loop.ex's hook_base/1 no longer builds the keys hook_payloads.json documents"

      assert base_keys(@session_source) == expected,
             "session.ex's hook_base/1 no longer builds the keys hook_payloads.json documents"
    end
  end

  describe "every event hands a component exactly the fixture's payload" do
    test "the turn's seven events", context do
      assert_case(context, "UserPromptSubmit", "trusted", fn config ->
        Hooks.notify(config, :user_prompt_submit, base(true))
      end)

      assert_case(context, "PreToolUse", "trusted", fn config ->
        Hooks.pre_tool_use(config, "write", %{"path" => "src/a.ex", "content" => "x"}, base(true))
      end)

      assert_case(context, "PostToolUse", "trusted", &read_result(&1, true))
      assert_case(context, "PostToolUse", "untrusted", &read_result(&1, false))
      assert_case(context, "PostToolUseFailure", "trusted", &failed_bash(&1, true))
      assert_case(context, "PostToolUseFailure", "untrusted", &failed_bash(&1, false))

      assert_case(context, "Stop", "trusted", fn config ->
        Hooks.notify(config, :stop, base(true))
      end)

      assert_case(context, "Notification", "trusted", fn config ->
        Hooks.notify(config, :notification, Map.put(base(true), "tool_name", "bash"))
      end)

      assert_case(context, "FileChanged", "trusted", fn config ->
        Hooks.notify(
          config,
          :file_changed,
          Map.put(base(true), "paths", ["lib/a.ex", "lib/b.ex"])
        )
      end)
    end

    test "the three lifecycle events", context do
      assert_case(context, "SessionStart", "trusted", fn config ->
        Hooks.session_start(config, Map.put(lifecycle(), "source", "startup"))
      end)

      assert_case(context, "SessionEnd", "trusted", fn config ->
        Hooks.session_end(config, Map.put(lifecycle(), "reason", "closed"))
      end)

      assert_case(context, "PreCompact", "trusted", fn config ->
        Hooks.pre_compact(
          config,
          Map.merge(base(true), %{
            "trigger" => "automatic",
            "custom_instructions" => "keep the migration notes",
            "messages" => 128
          })
        )
      end)
    end

    test "a [checks] component, which is told its own name and nothing else", context do
      assert_case(context, "check", "trusted", &Hooks.run_checks/1)
    end
  end

  # ================================================================ the assertion

  defp assert_case(context, event, lane, drive) do
    fixture_case =
      Enum.find(context.fixture["cases"], &(&1["event"] == event and &1["lane"] == lane)) ||
        flunk("hook_payloads.json has no #{lane} case for #{event}")

    handed = handed(context, event, lane, drive)

    assert handed == fixture_case["payload"],
           """
           #{fixture_case["name"]}
             event:    #{event} (#{lane})
             expected: #{inspect(fixture_case["payload"])}
             handed:   #{inspect(handed)}
           """
  end

  # One component entry for `event`, driven through the public function its real caller uses,
  # with the payload read off the wire rather than out of anything this file built.
  defp handed(context, event, lane, drive) do
    fake = helper(context)
    trusted? = lane == "trusted"

    File.write!(Path.join(context.workspace, "ouroboros.toml"), toml(event))

    config =
      Hooks.load(context.workspace,
        pool: pool(context, fake),
        trusted_workspaces: if(trusted?, do: [context.workspace], else: []),
        # Never the machine's own user file, and never one this test did not write.
        user_hooks_path: Path.join(context.root, "no-such-user-hooks.toml")
      )

    entries = if event == "check", do: config.checks, else: config.hooks
    assert [%{kind: :component, trusted: ^trusted?}] = entries

    drive.(config)

    fake.journal
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.map(&JSON.decode!/1)
    |> Enum.find(&(&1["method"] == "call"))
    |> case do
      nil -> flunk("no `call` reached the helper for #{event}: #{File.read!(fake.journal)}")
      frame -> JSON.decode!(frame["params"]["payload"])
    end
  end

  defp toml("check"),
    do: """
    [checks]
    vet = { component = "./hooks/vet.wasm" }
    """

  defp toml(event),
    do: """
    [[hooks]]
    event = "#{event}"
    component = "./hooks/vet.wasm"
    """

  defp base(trusted?), do: Map.put(@base, "workspace_trusted", trusted?)

  # The lifecycle base: the same map without a turn, because none of the three happens in one.
  defp lifecycle, do: Map.put(@base, "turn_id", nil)

  defp read_result(config, trusted?) do
    Hooks.post_tool_use(
      config,
      "read",
      %{"path" => "src/a.ex"},
      %{"output" => "defmodule A do\nend\n", "is_error" => false},
      base(trusted?)
    )
  end

  defp failed_bash(config, trusted?) do
    Hooks.post_tool_use(
      config,
      "bash",
      %{"command" => "mix test"},
      %{"output" => "1 failure\n", "is_error" => true},
      base(trusted?)
    )
  end

  # The string keys of a `defp hook_base(state) do %{…} end` in a source file, sorted. A
  # regular expression over source is a blunt instrument, and it is the right one here: the
  # claim is about a literal map in a private function, and the alternative — trusting the
  # fixture to still describe it — is what this test exists to refuse.
  defp base_keys(path) do
    source = File.read!(Path.expand(path))

    [_whole, body] =
      Regex.run(~r/defp hook_base\(state\) do\n(.*?)\n  end\n/s, source) ||
        flunk("no `defp hook_base(state)` in #{path}")

    ~r/"([a-z_]+)" =>/
    |> Regex.scan(body)
    |> Enum.map(fn [_whole, key] -> key end)
    |> Enum.sort()
  end

  defp fixture, do: @fixture |> File.read!() |> JSON.decode!()

  # ================================================================ the harness

  defp pool(context, fake) do
    name = :"hooks_payload_pool_#{System.unique_integer([:positive])}"

    # Detached, like `Ouroboros.Wasm.PoolTest`'s: a child's exit must not travel through the
    # test process, and teardown reaps the helper through `terminate/2`.
    {:ok, pid} =
      Ouroboros.Wasm.Pool.start(
        [name: name, helper_path: fake.path, handshake_timeout_ms: 15_000] ++
          Ouroboros.Wasm.SandboxFixture.pool_opts(context.root)
      )

    on_exit(fn ->
      if Process.alive?(pid) do
        try do
          GenServer.stop(pid, :normal, 1_000)
        catch
          :exit, _reason -> :ok
        end
      end
    end)

    pid
  end

  ## The fake helper
  #
  # `awk`, as in `Ouroboros.Wasm.PoolTest` and `HooksNarrowingGoldenTest`: a line at a time
  # with `fflush()` so no shell buffering sits between the answer and the pipe. Every request
  # is journaled, which is where the payload under test is read from; `call` answers the empty
  # reply, because what a hook *said* is another fixture's subject.

  @doctor_ok ~S(\"usable\":true,\"worlds\":[\"ouroboros:capability@0.1.0\"],) <>
               ~S(\"limits\":{\"max_deadline_ms\":60000})

  defp helper(context) do
    unique = System.unique_integer([:positive])
    journal = Path.join(context.root, "journal-#{unique}.jsonl")
    File.write!(journal, "")

    path = Path.join(context.root, "ouro-wasm-fake-#{unique}.sh")
    File.write!(path, script(journal))
    File.chmod!(path, 0o755)

    %{path: path, journal: journal}
  end

  defp script(journal) do
    """
    #!/bin/sh
    exec awk -v journal="#{journal}" '
    {
      print $0 >> journal
      close(journal)
      id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      if ($0 ~ /"method":"doctor"/) {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{#{@doctor_ok}}}\\n", id)
      } else if ($0 ~ /"method":"call"/) {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"payload\\":\\"\\",\\"fuel_used\\":1}}\\n", id)
      } else {
        method = $0
        sub(/.*"method":"/, "", method)
        sub(/".*/, "", method)
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"method\\":\\"%s\\",\\"echo_id\\":%s}}\\n", id, method, id)
      }
      fflush()
    }
    '
    """
  end
end
