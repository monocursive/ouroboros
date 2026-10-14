defmodule OuroFleet.ContractsTest do
  use ExUnit.Case, async: true
  alias OuroFleet.{Request, Store}

  test "JSON null remains null across wire and checkpoint round trips" do
    value = %{
      "run_id" => nil,
      "snapshot" => %{"outcome" => nil},
      "bool" => true,
      "array" => [nil, false]
    }

    bytes = value |> OuroFleet.JSON.encode() |> IO.iodata_to_binary()
    assert OuroFleet.JSON.decode(bytes) == value
    refute bytes =~ "\"nil\""
    assert OuroFleet.JSON.decode(~s({"job":null})) == %{"job" => nil}
  end

  test "request identities are stable, private and bind all execution inputs" do
    request =
      Request.validate!(%{
        "schema" => "ouro.fleet.request/1",
        "request_id" => "a",
        "argv" => ["/bin/echo", "private-value"]
      })

    digest = Store.digest(request)
    assert digest == Store.digest(Map.new(Enum.reverse(Map.to_list(request))))

    for {key, value} <- [
          {"argv", ["/bin/true"]},
          {"capture", ["stdout"]},
          {"evidence", "best-effort"},
          {"dir", "/tmp"},
          {"jail", "none"},
          {"on", "pi"}
        ] do
      refute digest == Store.digest(Map.put(request, key, value))
    end

    refute digest =~ "private-value"

    for changed <- [
          Map.put(request, "actor", "forged"),
          Map.put(request, "dir", "relative"),
          Map.put(request, "argv", []),
          Map.put(request, "capture", ["argv"]),
          Map.put(request, "capture_limit", 16_777_217),
          Map.put(request, "argv", ["a\0b"])
        ] do
      assert_raise OuroFleet.InvalidRequest, fn -> Request.validate!(changed) end
    end
  end

  test "JSON null asks for a field's default; any other non-text value refuses" do
    base = %{"schema" => "ouro.fleet.request/1", "request_id" => "a", "argv" => ["/bin/true"]}
    defaults = Request.validate!(base)

    for key <- ~w(on jail observe evidence capture limits tags capture_limit) do
      assert Request.validate!(Map.put(base, key, nil)) == defaults

      assert_raise OuroFleet.InvalidRequest, fn ->
        Request.validate!(Map.put(base, key, false))
      end
    end

    assert Request.validate!(Map.put(base, "dir", nil))["dir"] == nil

    for key <- ["dir", "launch"] do
      assert_raise OuroFleet.InvalidRequest, fn ->
        Request.validate!(Map.put(base, key, false))
      end
    end
  end

  test "unsafe checkpoints refuse; durable replacement survives reread" do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouro-fleet-store-" <> Base.encode16(:crypto.strong_rand_bytes(8))
      )

    File.mkdir!(root)
    File.chmod!(root, 0o700)
    on_exit(fn -> File.rm_rf!(root) end)
    path = Path.join(root, "job.json")
    assert Store.read!(path) == nil
    assert Store.write!(path, %{"request" => "first"}) == Store.read!(path)
    assert Store.write!(path, %{"request" => "second"}) == Store.read!(path)
    File.chmod!(path, 0o644)
    assert_raise RuntimeError, fn -> Store.read!(path) end
    File.chmod!(path, 0o600)
    link = Path.join(root, "link")
    File.ln_s!(path, link)
    assert_raise RuntimeError, fn -> Store.read!(link) end
    File.write!(path, "broken")
    assert_raise ErlangError, fn -> Store.read!(path) end
  end

  test "the subprocess adapter bounds output and distinguishes failed JSON from a reply" do
    assert {:ok, %{"value" => 1}, 0} = OuroFleet.Command.json("/bin/echo", ["{\"value\":1}"])

    assert {:error, "component_response_invalid"} =
             OuroFleet.Command.json("/bin/echo", ["not-json"])
  end

  test "a component past its time or output bound is killed, not only disconnected" do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouro-fleet-command-" <> Base.encode16(:crypto.strong_rand_bytes(8))
      )

    File.mkdir!(root)
    on_exit(fn -> File.rm_rf!(root) end)
    pidfile = Path.join(root, "pid")
    # `exec` keeps the shell's pid, so the recorded pid is the process left running.
    silent = ~s(echo $$ > "$0"; exec /bin/sleep 30)
    noisy = ~s(echo $$ > "$0"; head -c 1100000 /dev/zero; exec /bin/sleep 30)

    assert {:error, "component_timeout_outcome_unknown"} =
             OuroFleet.Command.raw("/bin/sh", ["-c", silent, pidfile], 1_000)

    assert gone?(File.read!(pidfile))

    assert {:error, "component_response_too_large"} =
             OuroFleet.Command.raw("/bin/sh", ["-c", noisy, pidfile], 20_000)

    assert gone?(File.read!(pidfile))
    refute_received {_port, _message}
  end

  # The VM's child reaper collects a killed child within moments; a live one answers
  # `kill -0` for the full 30 seconds of its sleep.
  defp gone?(pid, tries \\ 100) do
    case System.cmd("/bin/kill", ["-0", String.trim(pid)], stderr_to_stdout: true) do
      {_, 0} when tries > 0 ->
        Process.sleep(50)
        gone?(pid, tries - 1)

      {_, status} ->
        status != 0
    end
  end
end

defmodule OuroFleet.StatusTest do
  use ExUnit.Case, async: true
  alias OuroFleet.{Reader, Worker}

  test "routed readers cannot replace the owning run or data store" do
    assert {:ok, ["show", "run-own", "--with-transcript", "--json"]} =
             Reader.args("run-own", ["show", "--with-transcript"])

    assert {:ok, ["query", "--run", "run-own", "--execs", "--limit", "10", "--json"]} =
             Reader.args("run-own", ["query", "--execs", "--limit", "10"])

    for flags <- [
          ["show", "run-other"],
          ["show", "--data-dir", "/other"],
          ["query", "--execs", "--run", "run-other"],
          ["tail", "--follow"],
          ["query", "--limit", "--data-dir"],
          ["gc"]
        ] do
      assert {:error, _} = Reader.args("run-own", flags)
    end
  end

  test "nested ledger gaps and unresolved outcomes never display healthy settlement" do
    run = %{
      "state" => "settled",
      "settlement" => "recorded",
      "outcome" => %{"kind" => "exited", "code" => 0},
      "child_protection" => "unprotected",
      "coverage" => %{
        "exec" => %{"status" => "active"},
        "ledger" => %{"status" => "degraded", "gaps" => [%{"reason" => "lost"}]}
      }
    }

    row = Worker.render(%{}, run)
    assert row["state"] == "exited"
    assert row["evidence_health"] == "degraded"
    assert row["child_protection"] == "unprotected"
    unknown = Worker.render(%{}, Map.put(run, "state", "outcome_unknown"))
    assert unknown["settlement"] == "unknown"
    assert unknown["ledger_settlement"] == "recorded"
    assert unknown["state"] == "outcome_unknown"

    assert Worker.execution_state(%{"state" => "settled", "outcome" => %{"kind" => "signaled"}}) ==
             "killed"

    assert Worker.execution_state(%{"state" => "prepared", "owner" => nil}) == "prepared"
    assert Worker.execution_state(%{"state" => "prepared", "owner" => %{}}) == "starting"
  end
end
