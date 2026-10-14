defmodule OuroFleet.WorkerTest do
  use ExUnit.Case, async: false
  alias OuroFleet.Worker

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

    for message <- [
          {:plan, key, Map.delete(request, "argv")},
          {:plan, "job_typo", request},
          {:plan, key, missing},
          {:submit, key, missing, %{}},
          {:status, 7},
          {:kill, "job_typo"},
          {:ledger, "job_typo", ["show"]}
        ] do
      assert {:error, "invalid_request"} = Worker.call(message)
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
