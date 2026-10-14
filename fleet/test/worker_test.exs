defmodule OuroFleet.WorkerTest do
  use ExUnit.Case, async: false
  alias OuroFleet.{Store, Worker}

  setup do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouro-fleet-worker-" <> Base.encode16(:crypto.strong_rand_bytes(8))
      )

    File.mkdir!(root)
    File.chmod!(root, 0o700)
    on_exit(fn -> File.rm_rf!(root) end)
    log = Path.join(root, "ledger.log")
    ledger = Path.join(root, "ledger")
    File.write!(ledger, fake_ledger(log))
    File.chmod!(ledger, 0o700)
    config = %{"state" => root, "data" => root, "ledger_bin" => ledger, "jail_bin" => ledger}
    start_supervised!({Worker, config})
    # The first reply follows the start-up reconcile, so its ledger calls are logged.
    {:ok, _} = Worker.call(:version)
    %{root: root, log: log}
  end

  test "malformed input is refused without restarting the worker", context do
    worker = Process.whereis(Worker)
    key = "job_" <> String.duplicate("a", 64)

    request = %{
      "schema" => "ouro.fleet.request/1",
      "request_id" => "typo",
      "argv" => ["/bin/true"]
    }

    missing = Map.put(request, "dir", Path.join(context.root, "missing"))

    for {message, detail} <- [
          {{:plan, key, Map.delete(request, "argv")}, "invalid argv"},
          {{:plan, key, Map.put(request, "request_id", "")}, "invalid request_id"},
          {{:plan, "job_typo", request}, "invalid job id"},
          {{:plan, key, missing}, "workspace missing"},
          {{:submit, key, missing, %{}}, "workspace missing"},
          {{:status, 7}, "invalid job id"},
          {{:kill, "job_typo"}, "invalid job id"},
          {{:ledger, "job_typo", ["show"]}, "invalid job id"}
        ] do
      # The reply names the check that failed, never the value that failed it.
      assert {:error, %{"reason" => "invalid_request", "detail" => ^detail}} =
               Worker.call(message)
    end

    assert Process.whereis(Worker) == worker
    # Only the start-up reconcile reached the ledger.
    assert ["--data-dir " <> _, "--data-dir " <> _] = ledger_calls(context.log)
  end

  test "a null option plans with its default instead of reaching argv", context do
    worker = Process.whereis(Worker)
    key = "job_" <> String.duplicate("b", 64)

    request = %{
      "schema" => "ouro.fleet.request/1",
      "request_id" => "null",
      "argv" => ["/bin/true"],
      "jail" => nil,
      "limits" => nil
    }

    assert {:ok, %{"active" => 0}} = Worker.call({:plan, key, request})
    assert Process.whereis(Worker) == worker
    assert Enum.any?(ledger_calls(context.log), &(&1 =~ " --profile tool "))
  end

  test "placement reads a run's ledger state until it is terminal, then no more", context do
    attempt(context.root, "c", "run-done")
    attempt(context.root, "d", "run-live")
    attempt(context.root, "e", nil)
    key = "job_" <> String.duplicate("a", 64)

    request = %{
      "schema" => "ouro.fleet.request/1",
      "request_id" => "place",
      "argv" => ["/bin/true"]
    }

    # The live run and the attempt without a run count; the settled run does not.
    assert {:ok, %{"active" => 2}} = Worker.call({:plan, key, request})
    assert {:ok, %{"active" => 2}} = Worker.call({:plan, key, request})
    calls = ledger_calls(context.log)
    assert Enum.count(calls, &(&1 =~ " show run-done ")) == 1
    assert Enum.count(calls, &(&1 =~ " show run-live ")) == 2
  end

  test "a status batch settles once, reads each run once, and marks what it did not read",
       context do
    done = attempt(context.root, "c", "run-done")
    live = attempt(context.root, "d", "run-live")
    prepared = attempt(context.root, "e", nil)
    missing = "job_" <> String.duplicate("f", 64)
    File.write!(context.log, "")

    batch = [done, live, prepared, missing, "job_x"]
    assert {:ok, replies} = Worker.call({:statuses, batch, 60_000})
    assert {:ok, %{"state" => "exited"}} = replies[done]
    assert {:ok, %{"state" => "running"}} = replies[live]
    assert {:ok, %{"state" => "prepared"}} = replies[prepared]
    assert {:error, "attempt_not_reserved"} = replies[missing]

    assert {:error, %{"reason" => "invalid_request", "detail" => "invalid job id"}} =
             replies["job_x"]

    assert [settle, _, _] = ledger_calls(context.log)
    assert settle =~ " settle-orphans "

    File.write!(context.log, "")
    assert {:ok, replies} = Worker.call({:statuses, [done, live], 0})
    assert Map.values(replies) == List.duplicate({:error, "status_budget_exhausted"}, 2)
    assert ledger_calls(context.log) == []
  end

  defp attempt(root, letter, run) do
    key = "job_" <> String.duplicate(letter, 64)
    record = %{"schema" => "ouro.fleet.attempt/1", "job_id" => key, "run_id" => run}
    Store.write!(Path.join([root, "attempts", key <> ".json"]), record)
    key
  end

  defp ledger_calls(log), do: log |> File.read!() |> String.split("\n", trim: true)

  # Answers each ledger verb the worker uses with the smallest reply it accepts, and
  # logs every argv so a test can count what reached the ledger.
  defp fake_ledger(log) do
    """
    #!/bin/sh
    printf '%s\\n' "$*" >> '#{log}'
    case " $* " in
      *" version --json "*) echo '{"schemas":{"run":"#{OuroFleet.Protocol.ledger_run()}"}}' ;;
      *" doctor --json "*) echo '{"ready":true,"detached_owner":{"available":true}}' ;;
      *" show run-live "*) echo '{"state":"admitted"}' ;;
      *" show "*) echo '{"state":"settled"}' ;;
      *) echo '{}' ;;
    esac
    """
  end
end
