defmodule OuroFleet.ControllerTest do
  use ExUnit.Case, async: false
  alias OuroFleet.{Controller, Protocol, Store}

  defmodule StubWorker do
    use GenServer

    def start_link(_) do
      state = %{plans: 0, submits: 0, batches: 0, budget: nil}
      GenServer.start_link(__MODULE__, state, name: OuroFleet.Worker)
    end

    def init(state), do: {:ok, state}

    # `OuroFleet.Worker.call/2` wraps each message with the deadline the worker works to.
    def handle_call({:call, message, deadline}, _, state),
      do: reply(message, %{state | budget: deadline - System.monotonic_time(:millisecond)})

    defp reply(:version, %{incompatible: true} = state),
      do: {:reply, {:ok, Map.put(Protocol.version(), "schema", "ouro.fleet.rpc/999")}, state}

    defp reply(:version, state), do: {:reply, {:ok, Protocol.version()}, state}
    defp reply({:status, job}, state), do: {:reply, observed(job, state), state}

    defp reply({:statuses, jobs}, state) do
      Process.sleep(Map.get(state, :delay, 0))
      replies = Map.new(jobs, &{&1, observed(&1, state)})
      {:reply, {:ok, replies}, %{state | batches: state.batches + 1}}
    end

    defp reply({:plan, _, _}, state),
      do:
        {:reply,
         {:ok,
          %{"active" => 0, "resolved" => %{"policy_digest" => "fixed"}, "workspace" => "/test"}},
         %{state | plans: state.plans + 1}}

    defp reply({:submit, job, _, _}, state),
      do: {:reply, {:ok, snapshot(job)}, %{state | submits: state.submits + 1}}

    defp snapshot(job), do: %{"job_id" => job, "run_id" => "same-run", "state" => "running"}

    # Status is unavailable until a test sets `:observed`; then each job reports its
    # submitted snapshot unless the map overrides it.
    defp observed(job, %{observed: overrides}), do: {:ok, Map.get(overrides, job, snapshot(job))}
    defp observed(_job, _state), do: {:error, "test_worker_unavailable"}
  end

  setup do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouro-fleet-controller-" <> Base.encode16(:crypto.strong_rand_bytes(8))
      )

    File.mkdir!(root)
    File.chmod!(root, 0o700)
    on_exit(fn -> File.rm_rf!(root) end)
    worker = start_supervised!(StubWorker)

    config = %{
      "state" => root,
      "fleet_id" => "test",
      "members" => [%{"machine" => "test", "node" => to_string(node())}]
    }

    start_supervised!({Controller, config})
    %{worker: worker, config: config, root: root}
  end

  test "lost replies and controller restart keep placement, changed requests refuse", context do
    request = %{
      "schema" => "ouro.fleet.request/1",
      "request_id" => "same",
      "argv" => ["/bin/true"]
    }

    assert {:ok, first} = Controller.call({:run, request})
    assert {:ok, ^first} = Controller.call({:run, request})
    stop_supervised!(Controller)
    start_supervised!({Controller, context.config})
    assert {:ok, ^first} = Controller.call({:run, request})

    assert {:error, "request_id_conflict"} =
             Controller.call({:run, Map.put(request, "capture", ["stdout"])})

    assert %{plans: 1, submits: 3} = :sys.get_state(context.worker)
    [path] = Path.wildcard(context.root <> "/jobs/*.json")
    record = Store.read!(path)
    refute Map.has_key?(record, "argv")
    assert record["snapshot"]["run_id"] == "same-run"
  end

  test "schema mismatch refuses before planning or admission", context do
    :sys.replace_state(context.worker, &Map.put(&1, :incompatible, true))

    request = %{
      "schema" => "ouro.fleet.request/1",
      "request_id" => "mismatch",
      "argv" => ["/bin/true"]
    }

    assert {:error, %{"reason" => "no_eligible_worker"}} = Controller.call({:run, request})
    assert :sys.get_state(context.worker).plans == 0
    assert :sys.get_state(context.worker).submits == 0
    assert Path.wildcard(context.root <> "/jobs/*.json") == []
  end

  test "malformed input is refused without restarting the controller", context do
    controller = Process.whereis(Controller)

    for {message, detail} <- [
          {{:run, %{"schema" => "ouro.fleet.request/1", "request_id" => "typo", "argv" => []}},
           "invalid argv"},
          {{:run, "not an object"}, "request must be an object"},
          {{:run, Map.put(request("x"), "tags", ["a", "a"])}, "invalid tags list"},
          {{:status, "job_not-a-digest"}, "invalid job id"},
          {{:status, 7}, "invalid job id"},
          {{:kill, nil}, "invalid job id"},
          {{:ledger, "../escape", ["show"]}, "invalid job id"}
        ] do
      assert {:error, %{"reason" => "invalid_request", "detail" => ^detail}} =
               Controller.call(message)
    end

    assert Process.whereis(Controller) == controller
    assert %{plans: 0, submits: 0} = :sys.get_state(context.worker)
    assert Path.wildcard(context.root <> "/jobs/*.json") == []
  end

  test "an unavailable worker keeps its last observation and never invents failure" do
    request = %{
      "schema" => "ouro.fleet.request/1",
      "request_id" => "stale",
      "argv" => ["/bin/true"]
    }

    assert {:ok, first} = Controller.call({:run, request})
    assert {:ok, stale} = Controller.call({:status, first["job_id"]})
    assert stale["stale"] == true
    assert stale["reachability"] == "unreachable"
    assert stale["last_observed"]["run_id"] == first["run_id"]
    refute Map.has_key?(stale, "state")
    refute Map.has_key?(stale, "outcome")
  end

  test "a catalog refresh asks each worker once and rewrites only what changed", context do
    jobs =
      for id <- ["a", "b", "c"] do
        assert {:ok, %{"job_id" => job}} = Controller.call({:run, request(id)})
        job
      end

    [first | _] = jobs
    path = Path.join([context.root, "jobs", first <> ".json"])
    :sys.replace_state(context.worker, &Map.put(&1, :observed, %{}))
    before = inodes(context.root)

    assert {:ok, rows} = Controller.call(:status)
    assert Enum.sort(Enum.map(rows, & &1["job_id"])) == Enum.sort(jobs)
    assert Enum.all?(rows, &(&1["stale"] == false))
    assert {:ok, %{"stale" => false}} = Controller.call({:status, first})
    assert :sys.get_state(context.worker).batches == 1
    assert inodes(context.root) == before

    changed = %{"job_id" => first, "run_id" => "same-run", "state" => "exited"}
    :sys.replace_state(context.worker, &Map.put(&1, :observed, %{first => changed}))
    assert {:ok, rows} = Controller.call(:status)
    assert Enum.find(rows, &(&1["job_id"] == first))["state"] == "exited"
    rewritten = for {file, inode} <- inodes(context.root), before[file] != inode, do: file
    assert rewritten == [path]
    assert Store.read!(path)["snapshot"] == changed
  end

  test "worker calls never outlast the caller's deadline", context do
    # Placement and submission carry the call's time too, less the worker's margin.
    assert {:ok, _} = Controller.call({:run, request("late")})
    assert %{submits: 1, budget: budget} = :sys.get_state(context.worker)
    assert budget in 100_000..120_000
    :sys.replace_state(context.worker, &Map.put(&1, :observed, %{}))

    # Past the deadline, no worker call is made at all.
    past = System.monotonic_time(:millisecond) - 1
    assert {:ok, [row]} = GenServer.call(Controller, {:call, :status, past})
    assert %{"stale" => true, "reason" => "controller_budget_exhausted"} = row
    assert :sys.get_state(context.worker).batches == 0

    # With time left, the worker is given a deadline a margin before the call ends.
    soon = System.monotonic_time(:millisecond) + 8_000
    assert {:ok, [%{"stale" => false}]} = GenServer.call(Controller, {:call, :status, soon})
    assert %{batches: 1, budget: budget} = :sys.get_state(context.worker)
    assert budget in 1..3_000

    # A worker slower than the time left is cut off at the deadline.
    :sys.replace_state(context.worker, &Map.put(&1, :delay, 2_000))
    started = System.monotonic_time(:millisecond)
    assert {:ok, [row]} = GenServer.call(Controller, {:call, :status, started + 300})
    assert System.monotonic_time(:millisecond) - started < 1_500
    assert %{"stale" => true, "reason" => "worker_unreachable_or_reply_lost"} = row
    assert row["last_observed"]["run_id"] == "same-run"
  end

  defp request(id),
    do: %{"schema" => "ouro.fleet.request/1", "request_id" => id, "argv" => ["/bin/true"]}

  defp inodes(root),
    do: Map.new(Path.wildcard(root <> "/jobs/*.json"), &{&1, File.stat!(&1).inode})
end
