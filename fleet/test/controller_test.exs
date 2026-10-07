defmodule OuroFleet.ControllerTest do
  use ExUnit.Case, async: false
  alias OuroFleet.{Controller, Store}

  defmodule StubWorker do
    use GenServer

    def start_link(_),
      do: GenServer.start_link(__MODULE__, %{plans: 0, submits: 0}, name: OuroFleet.Worker)

    def init(state), do: {:ok, state}

    def handle_call(:version, _, %{incompatible: true} = state),
      do:
        {:reply, {:ok, %{"schema" => "ouro.fleet.rpc/999", "run" => "ouro.ledger.run/1"}}, state}

    def handle_call({:status, _}, _, state),
      do: {:reply, {:error, "test_worker_unavailable"}, state}

    def handle_call(:version, _, state),
      do: {:reply, {:ok, %{"schema" => "ouro.fleet.rpc/1", "run" => "ouro.ledger.run/1"}}, state}

    def handle_call({:plan, _, _}, _, state),
      do:
        {:reply,
         {:ok,
          %{"active" => 0, "resolved" => %{"policy_digest" => "fixed"}, "workspace" => "/test"}},
         %{state | plans: state.plans + 1}}

    def handle_call({:submit, job, _, _}, _, state),
      do:
        {:reply, {:ok, %{"job_id" => job, "run_id" => "same-run", "state" => "running"}},
         %{state | submits: state.submits + 1}}
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

    assert :sys.get_state(context.worker) == %{plans: 1, submits: 3}
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
end
