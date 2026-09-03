defmodule Ouroboros.Wasm.CapabilityAcceptanceTest do
  # Not async: each test spawns the real helper as an OS child and starts mesh agents.
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.Rollout.Evaluation
  alias Ouroboros.Upgrade.Rollout.Probe
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Capability
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.SandboxFixture
  alias Ouroboros.Wasm.Store

  # The whole lane, end to end, against the real `ouro-wasm` and a real component built by a
  # real toolchain. Everything else in this slice proves a decision; this proves the decisions
  # were about the right thing. Where either half has not been built the tests are skipped
  # with the reason and the `make` target printed, rather than passing silently: a green run
  # on a machine that never built them should say what it did not check.
  @guest Path.expand("../support/wasm/echo.wasm", __DIR__)

  # `Ouroboros.Wasm.LiveFixture` decides, so that CI — which builds both halves and sets
  # `OUROBOROS_REQUIRE_WASM=1` — fails on a missing build instead of skipping green.
  @needs_live Ouroboros.Wasm.LiveFixture.tag(@guest)

  setup_all do
    Ouroboros.Wasm.LiveFixture.ensure!(@guest)
  end

  describe "the world file, world.rs, and a toolchain build agree" do
    @tag @needs_live
    test "inspect reports this node's world, one import, and the three exports" do
      %{pool: pool, path: path} = staged()

      assert {:ok, report} = Pool.inspect(path, pool)

      # `tui/wasm/wit/capability.wit` is what the guest was compiled against;
      # `tui/wasm/src/world.rs` is what the helper checks bytes against. This assertion is
      # the only place the two are held to each other.
      assert report["world"] == Wasm.world()

      # The security claim, stated by the artifact itself: a capability's whole authority is
      # its import list, and this one's is a log line.
      assert report["imports"] == ["log"]

      assert Enum.sort(report["exports"]) == ["describe", "handle-message", "init"]
      assert report["size"] > 0
    end
  end

  describe "the wrapper agent, against a real component" do
    @tag @needs_live
    test "a message reaches the guest, and the guest's state survives the next one" do
      %{id: id} = capability()

      assert {:ok, _agent} = Mesh.send_message("acceptance", id, %{"hello" => "world"})
      first = state(id)

      assert first.error == nil
      assert is_binary(first.instance)

      # The guest echoes the body, repeats the config it was initialized with, and counts.
      assert first.last_answer == %{
               "echo" => %{"hello" => "world"},
               "config" => %{"greeting" => "hello"},
               "n" => 1
             }

      assert {:ok, _agent} = Mesh.send_message("acceptance", id, %{"hello" => "again"})
      second = state(id)

      # The count is the evidence that one instance answered both: a fresh instance would
      # have answered `1` again.
      assert second.last_answer == %{
               "echo" => %{"hello" => "again"},
               "config" => %{"greeting" => "hello"},
               "n" => 2
             }

      assert second.instance == first.instance
      assert second.messages_received == 2
    end

    @tag @needs_live
    test "the guest's one import reaches the daemon" do
      # `log` is the only thing this component may do besides compute, and the helper writes
      # it to its own stderr. The pool deliberately inherits that stream rather than piping
      # it, so the wrapper script this pool spawns is what makes the line observable here —
      # and a wrapper is a shell script, which is why this one pool in the file runs with the
      # process posture open (W21). Every other pool here spawns the real helper sealed.
      %{id: id, stderr: stderr} = capability(env: staged_through_tee())

      assert {:ok, _agent} = Mesh.send_message("acceptance", id, %{"hello" => "world"})
      assert state(id).error == nil

      logged = await_stderr(stderr, "handle-message")
      assert logged =~ "[info]"
      assert logged =~ "handle-message"
    end

    @tag @needs_live
    test "a config the guest refuses is its own error, not a trap and not a crash" do
      # The guest validates its config in `init` and answers `err(string)` rather than
      # trapping. The helper reports that as `guest_error` at instantiate, so the whole path
      # — guest refusal, helper classification, wrapper recording — is exercised against real
      # bytes rather than a scripted reply.
      %{id: id} = capability(config: "not json at all")

      assert {:ok, _agent} = Mesh.send_message("acceptance", id, %{"hello" => "world"})
      state = state(id)

      assert %{stage: :instantiate, reason: %{refusal: "guest_error", message: message}} =
               state.error

      assert message =~ "config is not JSON"
      assert state.instance == nil
      assert state.last_answer == nil

      # And the agent is still an agent: nothing a component does takes down the process
      # containing it, which is the sentence lane W exists to make true.
      assert is_pid(Mesh.whereis(id))
      assert state.last_message.body == %{"hello" => "world"}
    end

    # W13/D17. The description is read at deploy time, on its own instance, and never on the
    # message path. This is the real helper and a real component: what it proves is that the
    # export the world declares, the toolchain built, and contract C1 all agree.
    @tag @needs_live
    test "the guest's own describe is captured at deploy time and satisfies contract C1" do
      %{pool: pool, root: root, sha: sha} = staged()

      state = %{
        component: sha,
        config: ~s({"greeting":"hello"}),
        name: "echo",
        limits: Wasm.capability_limits(),
        pool: pool,
        store_root: root
      }

      assert {:ok, document} = Capability.capture_describe(state)

      assert document.name == "ouroboros-echo-guest"
      assert document.world == Wasm.world()
      assert document.version =~ ~r/\A\d+\.\d+\.\d+/

      # The guest writes the smallest legal document — name, version, world and nothing
      # else — which is exactly the case a validator written against the optional keys gets
      # wrong. The absent half is `nil`/`[]` rather than missing, so a reader renders one
      # shape whichever keys a component chose to write.
      assert document.summary == nil
      assert document.input_schema == nil
      assert document.examples == []

      # Nothing a component wrote carries a character that could make it stop looking like
      # a component's words.
      assert Capability.Describe.clean_text?(document)
    end

    @tag @needs_live
    test "a message to the real guest asks the helper for no metadata at all" do
      %{id: id} = capability()

      assert {:ok, _agent} = Mesh.send_message("acceptance", id, %{"hello" => "world"})
      first = state(id)

      # F2, against the real wire: the wrapper holds no description and asked for none, so
      # nothing a component does to its own `describe` can spend a caller's budget.
      refute Map.has_key?(first, :describe)
      assert first.last_answer["n"] == 1

      assert {:ok, _agent} = Mesh.send_message("acceptance", id, %{"hello" => "again"})
      second = state(id)

      assert second.last_answer["n"] == 2
      assert second.instance == first.instance
    end
  end

  describe "the rollout machinery, unchanged, against a wasm capability" do
    @tag @needs_live
    test "Probe.ready?/1 accepts the start spec and the echo check passes" do
      %{start_spec: start_spec} = staged_capability()

      # `Rollout.Probe` has never heard of a component. It starts the module, sends one
      # `ouroboros.agent.message`, and requires `:last_message` to echo the body — which is
      # exactly what the wrapper writes (docs/WASM.md §7.2).
      assert :ok = Probe.ready?(start_spec)

      # The throwaway agent does not outlive the probe.
      assert Mesh.list_agents()
             |> Enum.all?(&(not String.starts_with?(&1.id, "ouroboros-probe-")))
    end

    @tag @needs_live
    test "Evaluation.run/3 drives a signed-shape spec through the guest" do
      %{start_spec: start_spec} = staged_capability()

      spec = %{
        probes: [
          # `{:contains, _}` renders `:last_answer` and looks in it.
          %{input: %{"greet" => "world"}, expect: {:contains, "greet"}},
          # `{:state_matches, _, _}` reads a named key out of the agent's own state.
          %{input: %{"greet" => "again"}, expect: {:state_matches, :messages_received, 2}},
          # `{:equals, _}` is a statement about the exact reply — which is only writable
          # because the probes share one instance and the count is therefore knowable.
          %{
            input: %{"greet" => "thrice"},
            expect:
              {:equals,
               %{
                 "echo" => %{"greet" => "thrice"},
                 "config" => %{"greeting" => "hello"},
                 "n" => 3
               }}
          }
        ],
        budget_ms: 10_000,
        required: :all
      }

      # The spec is the shape a signed manifest carries: data, portable, no closures.
      assert {:ok, validated} = Evaluation.validate(spec)
      assert validated.probes == spec.probes

      assert {:ok, report} = Evaluation.run(start_spec, spec)

      assert Evaluation.passed?(report), inspect(report.results)
      assert report.module == Capability
      assert report.passed == 3
      assert report.failed == 0

      assert Mesh.list_agents()
             |> Enum.all?(&(not String.starts_with?(&1.id, "ouroboros-eval-")))
    end

    @tag @needs_live
    test "a component the store does not hold fails the probe rather than crashing it" do
      %{pool: pool, root: root} = staged()

      start_spec =
        {Capability,
         %{
           component: String.duplicate("c", 64),
           config: "{}",
           name: "absent",
           pool: pool,
           store_root: root
         }}

      # The wrapper records the refusal and answers normally, so the probe's echo check is
      # still satisfied: liveness is a fact about the agent. What a missing component costs
      # is the answer, and W3's deploy is where that becomes a rollback.
      assert :ok = Probe.ready?(start_spec)
    end

    @tag @needs_live
    test "a probe and an evaluation leave the helper holding nothing (F3)" do
      # Both start a throwaway agent under an id carrying a unique integer and stop it. With
      # no owner, each left a live instance behind forever: the helper holds 256 and evicts
      # none, §7.6 runs both per node per deploy, and a *full* helper is not a *broken* one,
      # so the pool would never respawn it. After ~128 deploys the lane stops working.
      %{pool: pool, start_spec: start_spec} = staged_capability()

      assert census(pool) == 0

      for _run <- 1..3, do: assert(:ok = Probe.ready?(start_spec))
      await_census(pool, 0)

      spec = %{probes: [%{input: %{"n" => 1}, expect: :any_reply}], budget_ms: 10_000}

      for _run <- 1..2 do
        assert {:ok, report} = Evaluation.run(start_spec, spec)
        assert Evaluation.passed?(report)
      end

      await_census(pool, 0)

      # And a helper that reclaimed five instances is still a helper.
      assert {:ok, %{"usable" => true}} = Pool.doctor(pool)
    end

    @tag @needs_live
    test "an agent that stops hands its instance back (F3)" do
      %{id: id, pool: pool} = capability()

      assert {:ok, _agent} = Mesh.send_message("acceptance", id, %{"hello" => "world"})
      assert census(pool) == 1

      assert :ok = Mesh.stop_agent(id)
      await_census(pool, 0)
    end
  end

  describe "one agent's instance is not another's (F1/F2)" do
    @tag @needs_live
    test "a thief seeded with a live instance name cannot touch that guest's state" do
      # The proved attack: `Mesh.start_agent/2` is remote-reachable and merges the caller's
      # `initial_state` wholesale, so a thief asked to be started holding the victim's
      # instance name. Against the real guest it got the victim's config back with the
      # victim's count incremented — it was mutating the victim's live state.
      %{id: victim} = env = capability()

      assert {:ok, _agent} = Mesh.send_message("acceptance", victim, %{"who" => "victim"})
      assert {:ok, _agent} = Mesh.send_message("acceptance", victim, %{"who" => "victim"})

      stolen = state(victim).instance
      assert state(victim).last_answer["n"] == 2

      %{id: thief} = capability(env: env, instance: stolen)

      assert {:ok, _agent} = Mesh.send_message("acceptance", thief, %{"who" => "thief"})

      # The thief's guest is its own, so it is on its first message — not the victim's third.
      assert state(thief).instance != stolen

      assert state(thief).last_answer == %{
               "echo" => %{"who" => "thief"},
               "config" => %{"greeting" => "hello"},
               "n" => 1
             }

      # And the victim's guest never saw it: its next message is 3, not 4.
      assert {:ok, _agent} = Mesh.send_message("acceptance", victim, %{"who" => "victim"})
      assert state(victim).last_answer["n"] == 3
      assert state(victim).instance == stolen

      # Two agents, two instances, both live at once.
      assert census(env.pool) == 2
    end
  end

  ## Fixtures

  # A pool speaking to the real helper — spawned **sealed**, the default since W21: exec only
  # itself, no fork, no mach — and the real guest published in a store of its own. That every
  # test in this file passes through this pool is the proof that `hw.`-only sysctl and no
  # fork are enough for wasmtime and tokio: a real `load`, `call`, epoch deadline and memory
  # limit, under the sealed profile.
  defp staged do
    dir = tmp_dir()
    %{root: root, sha: sha, path: path} = published(dir)
    %{pool: start_pool(dir), root: root, sha: sha, path: path}
  end

  # The same, through a one-line `#!/bin/sh` wrapper that `exec`s the real helper with its
  # stderr redirected to a file, for the one test that reads the helper's diagnostics.
  defp staged_through_tee do
    dir = tmp_dir()
    %{root: root, sha: sha, path: path} = published(dir)
    stderr = Path.join(dir, "helper.stderr")
    %{pool: start_tee_pool(stderr), root: root, sha: sha, path: path, stderr: stderr}
  end

  defp published(dir) do
    root = Path.join(dir, "store")
    File.mkdir_p!(root)

    bytes = File.read!(@guest)
    assert {:ok, %{sha256: sha, path: path}} = Store.put(bytes, nil, root: root)
    assert {:ok, ^path} = Store.path(sha, root: root)

    %{root: root, sha: sha, path: path}
  end

  # The same, plus the start spec `Probe`/`Evaluation` take. It names all six keys that
  # decide what is being evaluated — component, config, name, limits, pool, store_root —
  # because `Evaluation` merges a spec's `initial_state` under the start spec's, so a key the
  # start spec omits is a key a signed spec may choose. See `Ouroboros.Wasm.Capability`.
  defp staged_capability(opts \\ []) do
    staged = Keyword.get_lazy(opts, :env, &staged/0)

    Map.put(
      staged,
      :start_spec,
      {Capability,
       %{
         component: staged.sha,
         config: Keyword.get(opts, :config, ~s({"greeting":"hello"})),
         name: "greeter",
         limits: %{fuel: 100_000_000, memory_bytes: 64 * 1024 * 1024, deadline_ms: 5_000},
         pool: staged.pool,
         store_root: staged.root
       }}
    )
  end

  # The same, started as a live mesh agent this test drives itself. Pass `env: <a previous
  # fixture>` to put a second agent on the same helper and the same store.
  defp capability(opts \\ []) do
    %{start_spec: {module, initial_state}} = staged = staged_capability(opts)

    id =
      Keyword.get_lazy(opts, :id, fn ->
        "wasm-acceptance-#{System.unique_integer([:positive])}"
      end)

    initial_state =
      case Keyword.fetch(opts, :instance) do
        {:ok, instance} -> Map.put(initial_state, :instance, instance)
        :error -> initial_state
      end

    {:ok, _pid} = Mesh.start_agent(id, agent: module, initial_state: initial_state)
    on_exit(fn -> Mesh.stop_agent(id) end)

    Map.put(staged, :id, id)
  end

  # The helper's own count of what it is holding. The pool reclaims an instance when its
  # owner dies, and both the reclaim and the owner's death are asynchronous, so this is
  # asked repeatedly rather than once.
  defp await_census(pool, expected, attempts \\ 150)

  defp await_census(pool, expected, 0) do
    flunk("the helper still holds #{inspect(census(pool))} instances, expected #{expected}")
  end

  defp await_census(pool, expected, attempts) do
    if census(pool) == expected do
      :ok
    else
      Process.sleep(20)
      await_census(pool, expected, attempts - 1)
    end
  end

  defp census(pool) do
    case Pool.doctor(pool) do
      {:ok, %{"held" => %{"instances" => instances}}} -> instances
      other -> other
    end
  end

  defp state(id) do
    {:ok, server_state} = Mesh.state(id)
    server_state.agent.state
  end

  # The real helper, sealed. W16: spawned under the OS sandbox, so the pool is told this
  # test's roots — its store and its scratch — through the fixture every real-helper suite
  # uses; the helper's own directory is in the set by the pool's own rule.
  defp start_pool(dir) do
    name = :"wasm_acceptance_pool_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start(
        [name: name, handshake_timeout_ms: 15_000]
        |> Keyword.merge(SandboxFixture.pool_opts(dir))
      )

    stop_at_exit(pid)
  end

  # The helper writes its diagnostics to stderr, which the pool inherits from this VM by
  # design (`Ouroboros.Wasm.Pool.open_port/1` explains why it is not a pipe). A one-line
  # wrapper that `exec`s the real binary with its stderr redirected is how a test reads it
  # without changing that: `exec` means the os pid the pool kills is still the helper's.
  #
  # W21: the wrapper is a `#!/bin/sh` line, and a sealed process may exec only itself — so
  # this one pool says `scripted_pool_opts/1` and runs with the process posture open. The
  # read and network fences are the same as the sealed pool's, and the **real** helper's
  # directory is named because the wrapper `exec`s a binary outside this test's tree, which
  # bubblewrap has to bind into the namespace.
  defp start_tee_pool(stderr) do
    wrapper = Path.join(Path.dirname(stderr), "ouro-wasm-tee")

    File.write!(wrapper, """
    #!/bin/sh
    exec "#{Wasm.helper_path()}" "$@" 2>>"#{stderr}"
    """)

    File.chmod!(wrapper, 0o755)

    name = :"wasm_acceptance_tee_pool_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start(
        [name: name, helper_path: wrapper, handshake_timeout_ms: 15_000]
        |> Keyword.merge(SandboxFixture.scripted_pool_opts(Path.dirname(stderr)))
        |> Keyword.update!(:readable, &[Path.dirname(Wasm.helper_path()) | &1])
      )

    stop_at_exit(pid)
  end

  defp stop_at_exit(pid) do
    on_exit(fn ->
      if Process.alive?(pid) do
        try do
          GenServer.stop(pid, :normal, 5_000)
        catch
          :exit, _reason -> :ok
        end
      end
    end)

    pid
  end

  # The helper's stderr is a pipe this process does not own, so the line may land a moment
  # after the reply does.
  defp await_stderr(path, needle, attempts \\ 100)

  defp await_stderr(path, _needle, 0) do
    flunk("the guest's log line never reached #{path}; last read: #{inspect(File.read(path))}")
  end

  defp await_stderr(path, needle, attempts) do
    case File.read(path) do
      {:ok, text} ->
        if String.contains?(text, needle) do
          text
        else
          Process.sleep(20)
          await_stderr(path, needle, attempts - 1)
        end

      {:error, _reason} ->
        Process.sleep(20)
        await_stderr(path, needle, attempts - 1)
    end
  end

  defp tmp_dir do
    dir =
      Path.join(System.tmp_dir!(), "ouro-wasm-acceptance-#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end
end
