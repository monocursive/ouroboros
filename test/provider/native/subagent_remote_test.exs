defmodule Ouroboros.Provider.Native.SubagentRemoteTest do
  @moduledoc """
  G3 across two nodes — a subagent placed on another machine of the fleet.

  Every claim here needs a second VM, which is why it is a separate module: a real peer
  node boots the whole `:ouroboros` application, and a parent native session on this node
  spawns children onto it with `machine:` and `workspace:`.

  The claims:

    * a remote child **runs on the peer**, and every node-scoped decision was made there —
      the request was validated against the peer's filesystem and the transcript was
      written under the *peer's* `:native_data_dir`, which this node's app env does not
      name;
    * an approval the remote child raises reaches **this** session's channel, and the
      answer lands as an effect on the peer;
    * a remote child whose subscriber dies is **stopped on the peer**, not left running
      against a workspace nobody watches;
    * `worktree: true` is leased against the **peer's** `workspace_allowed_roots`: the same
      argument is refused here and provisioned there, in one turn;
    * the refusals a remote target makes possible — no `workspace:`, a relative one, a
      directory that is not there — say which machine they are about.

  ## What one machine cannot prove

  Both nodes run on this host and therefore share a filesystem, so "a directory that
  exists only on the peer" is not a thing this suite can construct. What it constructs
  instead is *node-scoped configuration*: the two nodes are given different
  `:native_data_dir`s, and a child whose transcript lands under the peer's proves the
  launch ran there. `:erpc` on the peer is used for every observation about the peer, so
  no assertion here is satisfiable by something that happened locally.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log
  # Booting a peer VM and an application inside it is slow, and every deadline in this
  # suite is `:infinity` or generous for the same reason: under load a short one does not
  # fail the feature, it lies about it.
  @moduletag timeout: 180_000

  alias Jido.Harness.ApprovalResponse
  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Provider.Native.Subagent
  alias Ouroboros.Test.NativeModelScript

  setup do
    ensure_distributed!()

    origin_root = tmp_dir!("origin")
    origin_data = Path.join(origin_root, "data")
    origin_workspace = Path.join(origin_root, "workspace")
    File.mkdir_p!(origin_data)
    File.mkdir_p!(origin_workspace)

    previous =
      Map.new(
        [:native_data_dir, :native_model_module, :data_dir, :workspace_allowed_roots],
        &{&1, Application.get_env(:ouroboros, &1)}
      )

    Application.put_env(:ouroboros, :native_data_dir, origin_data)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    peer = start_app_peer!()

    # The peer's own directories, created *by the peer*, under app env only the peer has.
    peer_root = peer_call(peer, Path, :join, [System.tmp_dir!(), "ouro-peer-#{unique()}"])
    peer_data = Path.join(peer_root, "data")
    peer_workspace = Path.join(peer_root, "workspace")
    :ok = peer_call(peer, File, :mkdir_p!, [peer_data])
    :ok = peer_call(peer, File, :mkdir_p!, [Path.join(peer_workspace, "lib")])

    :ok =
      peer_call(peer, File, :write!, [
        Path.join(peer_workspace, "lib/remote.ex"),
        "defmodule Remote do\n  def only_here, do: :peer\nend\n"
      ])

    put_peer_env!(peer, :native_data_dir, peer_data)
    put_peer_env!(peer, :native_model_module, NativeModelScript)

    on_exit(fn ->
      Enum.each(previous, fn {key, value} -> restore(key, value) end)
      File.rm_rf(origin_root)
      # The peer is stopped by its own `on_exit`; its directories go with the host's tmp.
    end)

    %{
      peer: peer,
      peer_root: peer_root,
      peer_data: peer_data,
      peer_workspace: peer_workspace,
      origin_data: origin_data,
      origin_workspace: origin_workspace
    }
  end

  # ---------------------------------------------------------------- the round trip

  describe "a child placed on another machine" do
    test "runs there, reads a file there, and reports back here", context do
      %{handle: handle} =
        open(
          context,
          [
            [
              agent_call(%{
                "prompt" => "read lib/remote.ex and say what it defines",
                "description" => "remote read",
                "machine" => Atom.to_string(context.peer),
                "workspace" => context.peer_workspace
              })
            ],
            finish("asked the other machine")
          ],
          [
            [{:tool_call, %{id: "r1", name: "read", input: %{"path" => "lib/remote.ex"}}}],
            [
              {:text, "Remote.only_here/0 returns :peer."},
              {:usage, %{input_tokens: 33, output_tokens: 7}},
              {:finish, :stop}
            ]
          ]
        )

      send_turn(handle)
      events = collect_until(:turn_completed, [], 90_000)

      [spawned] = subagent_events(events, "spawned")
      assert spawned.payload["node"] == Atom.to_string(context.peer)
      assert spawned.payload["remote"] == true
      assert spawned.payload["workspace"] == context.peer_workspace
      assert spawned.payload["worktree"] == false
      assert spawned.payload["depth"] == 1

      assert [progress | _] = subagent_events(events, "progress")
      assert progress.payload["node"] == Atom.to_string(context.peer)

      [settled] = subagent_events(events, "settled")
      assert settled.payload["status"] == "completed"
      assert settled.payload["node"] == Atom.to_string(context.peer)
      assert settled.payload["remote"] == true
      assert settled.payload["tool_calls"] == 1
      assert settled.payload["input_tokens"] == 33

      # The parent's tool result carries the child's own words, and says where they came
      # from — "completed" about a machine the reader did not pick is half a sentence.
      result = tool_result(events, "agent")
      assert result.payload["is_error"] == false
      assert result.payload["output"] =~ "Remote.only_here/0 returns :peer."
      assert result.payload["output"] =~ "completed on #{context.peer}."

      # And the proof that the launch ran on the peer rather than here: the transcript is
      # under the *peer's* `:native_data_dir`, a path this node's app env does not name.
      child_id = settled.payload["provider_session_id"]
      child_dir = Path.join(context.peer_data, child_id)

      wait_until(fn -> peer_call(context.peer, File, :dir?, [child_dir]) end)

      transcript =
        peer_call(context.peer, File, :read!, [Path.join(child_dir, "conversation.json")])

      assert transcript =~ "def only_here, do: :peer"

      refute File.exists?(Path.join(context.origin_data, child_id))
    end

    test "an approval it raises is answered here and the effect lands there", context do
      %{handle: handle} =
        open(
          context,
          [
            [
              agent_call(%{
                "prompt" => "write lib/written_remotely.ex",
                "description" => "remote write",
                "machine" => Atom.to_string(context.peer),
                "workspace" => context.peer_workspace
              })
            ],
            finish("it wrote")
          ],
          [
            [
              {:tool_call,
               %{
                 id: "w1",
                 name: "write",
                 input: %{
                   "path" => "lib/written_remotely.ex",
                   "content" => "defmodule WrittenRemotely do\nend\n"
                 }
               }}
            ],
            [{:text, "wrote it on the peer"}, {:finish, :stop}]
          ],
          %{approval_mode: :prompt}
        )

      send_turn(handle)

      # The `agent` call itself is an effect and asks first, on this node.
      spawn_request = await_approval()
      refute Map.has_key?(spawn_request.payload, "subagent")
      approve(handle, spawn_request.request_id)

      # Then the child's own write asks — relayed from the peer onto *this* session's
      # channel, with a request id this session minted, naming the machine it is about.
      child_request = await_approval(90_000)
      assert child_request.payload["kind"] == "file_change"
      assert child_request.payload["subagent"]["description"] == "remote write"
      assert child_request.payload["subagent"]["node"] == Atom.to_string(context.peer)
      assert child_request.request_id != spawn_request.request_id
      approve(handle, child_request.request_id)

      events = collect_until(:turn_completed, [], 90_000)

      [settled] = subagent_events(events, "settled")
      assert settled.payload["status"] == "completed"
      assert settled.payload["remote"] == true
      assert settled.payload["files_changed"] == 1

      # The answer given here changed a file there.
      written = Path.join(context.peer_workspace, "lib/written_remotely.ex")
      assert peer_call(context.peer, File, :read!, [written]) =~ "defmodule WrittenRemotely"
    end

    test "is stopped on the peer when the subscriber it reports to dies", context do
      %{handle: handle} =
        open(
          context,
          [
            [
              agent_call(%{
                "prompt" => "look around",
                "description" => "orphan",
                "background" => true,
                "machine" => Atom.to_string(context.peer),
                "workspace" => context.peer_workspace
              })
            ],
            finish("spawned it")
          ],
          [
            [
              {:text, "had a look"},
              {:usage, %{input_tokens: 4, output_tokens: 1}},
              {:finish, :stop}
            ]
          ]
        )

      send_turn(handle)
      events = collect_until(:turn_completed, [], 90_000)

      [spawned] = subagent_events(events, "spawned")
      task_id = spawned.payload["task_id"]
      assert spawned.payload["remote"] == true

      # A background child's subscriber is the session process, and a settled one stays
      # alive on the peer until somebody collects it: that is the state this test needs,
      # because a child nobody is watching any more is the thing that must not survive.
      assert {:ok, child} = GenServer.call(handle, {:subagent_lookup, task_id})
      assert node(child) == context.peer
      assert peer_call(context.peer, Process, :alive?, [child])

      # The collection seam, across the link: `agent_result` reaches a child by pid, and
      # this one's pid is on another machine. A settled child answers without being
      # released, so the containment claim below is still about a child that exists.
      assert {:ok, summary} = Subagent.await(child, 10_000)
      assert summary.status == :completed
      assert summary.node == context.peer
      assert summary.remote == true
      assert Subagent.render(summary) =~ "completed on #{context.peer}."

      # Killed rather than closed. `Session.close/1` stops its children on purpose; what is
      # under test is the monitor, which is the only thing left when the parent dies badly.
      Process.exit(handle, :kill)

      wait_until(fn -> not peer_call(context.peer, Process, :alive?, [child]) end, 60_000)
    end

    test "counting a running child on another node does not take the session down", context do
      %{handle: handle} =
        open(
          context,
          [[{:text, "unused"}, {:finish, :stop}]],
          [[{:text, "unused"}, {:finish, :stop}]]
        )

      # A live process on the peer, tracked exactly as a real remote spawn tracks one.
      # `Process.alive?/1` **raises** for a pid of another node, and the running count is the
      # one place a session asks that question about every child it holds — so before this
      # was node-aware, one remote child made `agent`'s own capacity check kill the session.
      remote = Node.spawn(context.peer, :timer, :sleep, [60_000])
      assert node(remote) == context.peer

      assert :ok = GenServer.call(handle, {:subagent_track, "remote-live", remote, %{}})
      assert %{running: 1, tracked: 1} = GenServer.call(handle, :subagent_counts)
      assert Process.alive?(handle)

      # …and the close path walks the same table with a remote pid in it.
      assert :ok = Session.close(handle)
      assert peer_call(context.peer, Process, :exit, [remote, :kill])
    end
  end

  # ---------------------------------------------------------------- worktrees

  describe "a remote child in its own worktree" do
    setup context do
      git!(context, ["init", "--initial-branch=main"])
      git!(context, ["add", "."])

      git!(context, [
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "user.name=Ouroboros Test",
        "commit",
        "-m",
        "base"
      ])

      # `Worktree.root/1` falls back to a temp directory keyed by `:erlang.phash2(node())`,
      # so the two nodes have different ones by construction. The peer's is admitted on the
      # peer; this node admits nothing at all.
      peer_worktree_root = peer_call(context.peer, Ouroboros.Workspace.Worktree, :root, [[]])
      :ok = peer_call(context.peer, File, :mkdir_p!, [peer_worktree_root])
      put_peer_env!(context.peer, :workspace_allowed_roots, [peer_worktree_root])
      Application.put_env(:ouroboros, :workspace_allowed_roots, [])

      # The path the worktree reports is canonical, and on this host the temp root is a
      # symlink (`/var` → `/private/var`), so the prefix to compare against is the resolved
      # one — resolved on the peer, like everything else about the peer.
      {:ok, canonical_root} =
        peer_call(context.peer, Ouroboros.Workspace.Path, :canonicalize, [
          peer_worktree_root
        ])

      %{peer_worktree_root: canonical_root}
    end

    test "is leased against the peer's roots, and this node's answer is a different one",
         context do
      machine = Atom.to_string(context.peer)

      %{handle: handle} =
        open(
          context,
          [
            # Same argument, two machines: refused here, provisioned there. Nothing but a
            # per-node evaluation of `Worktree.admissible?/0` produces those two answers in
            # one turn.
            [agent_call(%{"prompt" => "isolate me here", "worktree" => true}, "c1")],
            [
              agent_call(
                %{
                  "prompt" => "add lib/isolated.ex",
                  "description" => "remote worktree",
                  "worktree" => true,
                  "machine" => machine,
                  "workspace" => context.peer_workspace
                },
                "c2"
              )
            ],
            finish()
          ],
          [
            [
              {:tool_call,
               %{
                 id: "w1",
                 name: "write",
                 input: %{
                   "path" => "lib/isolated.ex",
                   "content" => "defmodule Isolated do\nend\n"
                 }
               }}
            ],
            [{:text, "wrote it in the remote worktree"}, {:finish, :stop}]
          ]
        )

      send_turn(handle)
      events = collect_until(:turn_completed, [], 90_000)

      [local_attempt, remote_attempt] =
        events
        |> Enum.filter(&(&1.type == :tool_result and &1.payload["name"] == "agent"))
        |> Enum.map(& &1.payload)

      assert local_attempt["is_error"] == true
      assert local_attempt["output"] =~ "this node's worktree root is not inside"
      assert local_attempt["output"] =~ "OUROBOROS_WORKSPACE_ROOTS"

      assert remote_attempt["is_error"] == false
      assert remote_attempt["output"] =~ "wrote it in the remote worktree"
      assert remote_attempt["output"] =~ "completed on #{context.peer}."
      assert remote_attempt["output"] =~ "Worktree kept"

      [spawned] = subagent_events(events, "spawned")
      assert spawned.payload["worktree"] == true
      assert spawned.payload["node"] == machine
      assert String.starts_with?(spawned.payload["workspace"], context.peer_worktree_root)
      refute spawned.payload["workspace"] == context.peer_workspace

      [settled] = subagent_events(events, "settled")
      assert settled.payload["files_changed"] == 1
      assert settled.payload["worktree"]["retired"] == "kept"

      worktree_path = settled.payload["worktree"]["path"]
      on_exit(fn -> File.rm_rf(worktree_path) end)

      # The edit is in the worktree on the peer, and the tree it was cut from is untouched.
      assert peer_call(context.peer, File, :read!, [Path.join(worktree_path, "lib/isolated.ex")]) =~
               "defmodule Isolated"

      refute peer_call(context.peer, File, :exists?, [
               Path.join(context.peer_workspace, "lib/isolated.ex")
             ])
    end
  end

  # ---------------------------------------------------------------- refusals

  describe "what a remote spawn refuses" do
    test "a machine with no workspace, a relative one, and one that is not a directory",
         context do
      machine = Atom.to_string(context.peer)
      missing = Path.join(context.peer_root, "not-there-at-all")

      calls = [
        [agent_call(%{"prompt" => "x", "machine" => machine}, "c1")],
        [agent_call(%{"prompt" => "x", "machine" => machine, "workspace" => "repo"}, "c2")],
        [agent_call(%{"prompt" => "x", "machine" => machine, "workspace" => missing}, "c3")],
        finish()
      ]

      %{handle: handle} = open(context, calls, [[{:text, "unused"}, {:finish, :stop}]])

      send_turn(handle)
      events = collect_until(:turn_completed, [], 90_000)

      results =
        events
        |> Enum.filter(&(&1.type == :tool_result and &1.payload["name"] == "agent"))
        |> Enum.map(& &1.payload["output"])

      assert [no_workspace, relative, not_a_dir] = results

      assert no_workspace =~ "resolves to #{context.peer}"
      assert no_workspace =~ "needs a `workspace:`"
      assert no_workspace =~ "mean nothing on that"

      assert relative =~ "`workspace: \"repo\"` is not an absolute path"
      assert relative =~ Atom.to_string(context.peer)

      # This one is the F2 claim in one sentence: the node named in the refusal is the
      # node `SessionRequest.new/1` ran on, so the workspace was validated against the
      # target's filesystem rather than this one's.
      assert not_a_dir =~ "is not a usable workspace on #{context.peer}"
      assert not_a_dir =~ missing

      assert not_a_dir =~ "give\n  `workspace:` a directory that exists there" or
               not_a_dir =~ "a directory that exists there"

      assert subagent_events(events, "spawned") == []
    end
  end

  # ---------------------------------------------------------------- harness

  defp open(context, parent_script, child_script, overrides \\ %{}) do
    {parent_spec, _parent_agent} = NativeModelScript.start(parent_script)

    # The child's scripted model is started **on the peer**, and that is a finding about the
    # test harness rather than a choice: `NativeModelScript`'s spec carries the agent's pid
    # as `:erlang.pid_to_list/1` text, which names a different process on every other VM. A
    # child pointed at an origin agent by that text calls a pid that does not exist on the
    # peer — which is also the truthful shape of the feature, since a real remote child uses
    # the target's own model configuration and credentials.
    {child_spec, _child_agent} =
      peer_call(context.peer, NativeModelScript, :start_unlinked, [child_script])

    options =
      overrides
      |> Map.get(:provider_options, %{})
      |> Map.put("subagent_model", child_spec)

    session_id = "remote-sub-#{unique()}"

    request =
      SessionRequest.new!(%{
        provider: :native,
        cwd: context.origin_workspace,
        model: parent_spec,
        approval_mode: Map.get(overrides, :approval_mode, :auto_approve),
        # `:infinity`, because an approval relayed from another node crosses two mailboxes
        # and a peer VM under test-suite load; a short deadline here would fail the suite
        # rather than the feature.
        approval_timeout_ms: :infinity,
        provider_options: options
      })

    session_context = %{
      session_id: session_id,
      provider: :native,
      owner: self(),
      adapter: Ouroboros.Provider.Native,
      config: %{},
      process_manager: Jido.Harness.ProcessDriver.Erlexec,
      telemetry_context: %{}
    }

    {:ok, handle} = Session.open(request, session_context)
    on_exit(fn -> if Process.alive?(handle), do: Session.close(handle) end)

    %{handle: handle, session_id: session_id}
  end

  defp agent_call(input, id \\ "c1"), do: {:tool_call, %{id: id, name: "agent", input: input}}

  defp finish(text \\ "done"),
    do: [{:text, text}, {:usage, %{input_tokens: 10, output_tokens: 3}}, {:finish, :stop}]

  defp send_turn(handle, text \\ "go", turn_id \\ "turn-1"),
    do: :ok = Session.send(handle, TurnRequest.new!(text), turn_id)

  defp collect_until(type, acc \\ [], timeout \\ 60_000) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> Enum.reverse([event | acc])
      {:session_adapter_event, event} -> collect_until(type, [event | acc], timeout)
    after
      timeout -> flunk("no #{type}; saw #{inspect(Enum.map(acc, & &1.type))}")
    end
  end

  defp subagent_events(events, phase) do
    Enum.filter(events, fn event ->
      event.type == :provider_event and event.payload["kind"] == "subagent" and
        event.payload["phase"] == phase
    end)
  end

  defp tool_result(events, name),
    do: Enum.find(events, &(&1.type == :tool_result and &1.payload["name"] == name))

  defp await_approval(timeout \\ 60_000) do
    receive do
      {:session_adapter_event, %{type: :approval_requested} = event} -> event
      {:session_adapter_event, _other} -> await_approval(timeout)
    after
      timeout -> flunk("no approval_requested within #{timeout}ms")
    end
  end

  defp approve(handle, request_id) do
    :ok =
      Session.respond_approval(
        handle,
        request_id,
        ApprovalResponse.new!(%{decision: :approve, scope: :once})
      )
  end

  defp wait_until(fun, budget_ms \\ 30_000) do
    deadline = System.monotonic_time(:millisecond) + budget_ms
    do_wait_until(fun, deadline)
  end

  defp do_wait_until(fun, deadline) do
    cond do
      fun.() -> :ok
      System.monotonic_time(:millisecond) > deadline -> flunk("condition never held")
      true -> Process.sleep(100) && do_wait_until(fun, deadline)
    end
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp unique, do: System.unique_integer([:positive])

  defp tmp_dir!(tag) do
    dir = Path.join(System.tmp_dir!(), "ouro-#{tag}-#{unique()}")
    File.mkdir_p!(dir)
    dir
  end

  # ---------------------------------------------------------------- the peer

  # The same shape `test/cluster_test.exs` uses: a peer booted on this VM's code path,
  # running the whole application, with the storages a second node must not share.
  defp start_app_peer! do
    name = String.to_atom("ouroboros_subagent_peer_#{unique()}")

    {:ok, peer, peer_node} =
      :peer.start(%{name: name, args: code_path_args(), wait_boot: 30_000})

    on_exit(fn -> stop_peer(peer) end)

    put_peer_env!(peer_node, :coding_storage, {Jido.Storage.ETS, table: peer_table(peer_node)})

    {:ok, _applications} =
      :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros], 60_000)

    peer_node
  end

  defp peer_call(peer_node, module, function, args),
    do: :erpc.call(peer_node, module, function, args, 30_000)

  # `git` run by the peer, in the peer's workspace, so the repository the worktree is cut
  # from is one that node made.
  defp git!(context, argv) do
    {output, status} =
      peer_call(context.peer, System, :cmd, [
        "git",
        argv,
        [cd: context.peer_workspace, stderr_to_stdout: true]
      ])

    assert status == 0, "git #{Enum.join(argv, " ")} failed on the peer: #{output}"
    :ok
  end

  defp put_peer_env!(peer_node, key, value),
    do: :ok = :erpc.call(peer_node, Application, :put_env, [:ouroboros, key, value])

  defp peer_table(peer_node),
    do: peer_node |> Atom.to_string() |> String.replace(~r/[^a-zA-Z0-9]/, "_") |> String.to_atom()

  defp code_path_args, do: Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

  defp stop_peer(peer) do
    :peer.stop(peer)
  catch
    _kind, _reason -> :ok
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_subagent_root_#{unique()}")
      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end

    :ok
  end
end
