defmodule Ouroboros.Fleet.DeploymentRealWorkerTest do
  @moduledoc """
  The broker against the **real** Rust deployment worker, not a fake of it.

  Every other test in this slice drives `Ouroboros.Test.FleetWorkerFake`, and a fake is only
  ever as right as the person who wrote it. Two of them written from the same seam document
  agree with each other whether or not either agrees with the program — which is exactly what
  happened: the request file this broker wrote was a shape `fleet_setup::OperationRequest`
  refuses (it is `deny_unknown_fields`), and the challenge metadata it published was one level
  deeper than seam S4 describes. Both were found by running this, and neither could have been
  found without it.

  So this suite exists to be the one place where the other side of seams S2, S3 and S5 is the
  actual program. It forks a real `ouro fleet worker start`, lets it write its own capability
  file and journal, attaches over its Unix socket, answers its real `review` challenge with
  the digest it really computed, and reads the fleet profile it really created.

  ## When it does not run

  It needs a built `ouro`. Set `OUROBOROS_TEST_OURO` to one, or build `tui/target/debug/ouro`;
  absent that the module is skipped with a message naming both. The check is at compile time,
  so a binary built *after* this file was compiled needs `mix compile --force` (or a touch of
  this file) before the suite will see it.

  ## Two constraints worth knowing before editing

  The data directory has to be **short**: the worker binds `<data dir>/deploy/<id>.sock` and
  `sun_path` is 104 bytes on this platform, so a scratch path under the usual session
  directory fails with `path must be shorter than SUN_LEN`. And a `setup` really does create
  a fleet in that directory — which is why each case gets its own and removes it.
  """

  use ExUnit.Case, async: false

  import Bitwise

  @moduletag :capture_log
  # A real setup writes a fleet; a real add dials a socket. Neither is instant.
  @moduletag timeout: 180_000

  @ouro System.get_env("OUROBOROS_TEST_OURO") ||
          Path.expand("tui/target/debug/ouro", File.cwd!())

  @present (case File.lstat(@ouro) do
              {:ok, %File.Stat{type: :regular, mode: mode}} -> (mode &&& 0o111) != 0
              _absent -> false
            end)

  # The ceiling for one externally visible step. Generous, because it covers a real process
  # forking, a real socket and a real fleet being written — and bounded, because a test that
  # waits forever on a worker that died is a test that reports nothing.
  @step 30_000

  if @present do
    # Inside the branch, because the other branch defines no test that uses them and an
    # unused alias is a warning this suite is compiled with as an error.
    alias Ouroboros.Fleet.Deployment
    alias Ouroboros.Fleet.Deployment.Journal
    alias Ouroboros.Web.Call

    setup do
      # Every case goes in through `Ouroboros.Web.Call`, not `Deployment` directly: the bug
      # this suite was written after was in the *translation* from the method's parameters to
      # the worker's request shape, and a test that handed the broker an already-correct
      # request would have walked straight past it.
      start_supervised!({Task.Supervisor, name: Ouroboros.Web.TaskSupervisor})

      # Short, for `sun_path`. See the module note.
      root = Path.join(System.tmp_dir!(), "ow2r#{System.unique_integer([:positive])}")
      File.mkdir_p!(root)
      File.chmod!(root, 0o700)

      previous_data_dir = Application.get_env(:ouroboros, :data_dir)
      previous_ouro = System.get_env("OUROBOROS_PROCESS_ID_HELPER")

      Application.put_env(:ouroboros, :data_dir, root)
      System.put_env("OUROBOROS_PROCESS_ID_HELPER", @ouro)

      on_exit(fn ->
        # The worker outlives this runtime by design, so a case that leaves one running would
        # leave it running past the suite. Ask each one to stop, then take the directory.
        {operations, _total} = Deployment.operations(root)

        Enum.each(operations, fn %{"operation" => operation} ->
          _ = Deployment.cancel(operation, bound())
        end)

        if previous_data_dir,
          do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
          else: Application.delete_env(:ouroboros, :data_dir)

        if previous_ouro,
          do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous_ouro),
          else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

        File.rm_rf!(root)
      end)

      %{root: root}
    end

    # -------------------------------------------------------------------------
    # (a) The first local fleet, end to end

    test "a setup is inspected, reviewed, approved and completed", context do
      assert {:ok, %{"operation_id" => operation, "state" => "attaching"}} =
               prepare(%{
                 "kind" => "setup",
                 "machine" => "lab",
                 "address" => "127.0.0.1",
                 "service" => false
               })

      # Seam S2: the worker wrote its own capability and socket, and the broker attached to
      # the instance the spawn line named.
      snapshot = await(operation, &(&1["attached"] == true), "the worker to attach")

      assert snapshot["source"] == "worker"
      assert String.match?(snapshot["instance"], ~r/\A[0-9a-f]{16,64}\z/)

      # Seam S5's owner, echoed by the worker from the attach frame this broker sent.
      assert snapshot["owner"] == subject()

      # (d) The request file was consumed by the worker, and every file it left is private.
      deploy = Journal.deploy_dir(context.root)
      refute File.exists?(Journal.request_path(context.root, operation))
      assert_private(deploy)

      # It inspects, then asks for a review carrying the plan it built and the digest of it.
      review = await_challenge(operation, "review")

      assert is_map(review["plan"])
      assert review["plan"]["kind"] == "setup"
      assert review["plan"]["target"]["machine"] == "lab"

      # Seam S4 says a challenge's kind-specific fields are fields of the challenge. This is
      # the assertion that caught them being one level deeper than that.
      digest = review["plan_digest"]
      assert String.match?(digest, ~r/\A[0-9a-f]{64}\z/)

      state = await(operation, &(&1["state"] == "awaiting_review"), "the review state")
      assert state["state"] == "awaiting_review"

      assert {:ok, _approved} =
               Call.call(
                 :operate,
                 "fleet.deployment.start",
                 %{
                   "operation_id" => operation,
                   "plan_digest" => digest,
                   "idempotency_key" => "real-worker-key"
                 },
                 session: session()
               )

      completed = await(operation, &(&1["state"] == "completed"), "the operation to complete")
      assert completed["state"] == "completed"
      assert length(completed["steps"]) > 0

      # A setup on a data directory with no runtime really does create the fleet.
      assert File.exists?(Path.join([context.root, "fleet", "profile.json"]))

      # And the journal agrees, read from disk after the worker is gone.
      assert {:ok, journal} = Journal.read(context.root, operation)
      assert journal["state"] == "completed"
      assert journal["owner"] == subject()

      # The fleet's own cookie is a credential. Nothing this operation wrote may carry it.
      assert_cookie_absent(context.root, operation)
    end

    # -------------------------------------------------------------------------
    # (b) A target that is not there

    test "an add to an unreachable target fails with a reason rather than hanging", context do
      # An `add` needs a fleet to add *to*. Without one the worker refuses before it dials
      # anything — "this machine is standalone, so it cannot admit another" — which is a real
      # answer but not the one this case is about, so the fleet is created first.
      create_fleet(context)

      assert {:ok, %{"operation_id" => operation}} = prepare(unreachable_add())

      # No wait for an attach, and that is a finding rather than an omission: a worker whose
      # target refuses a host-key scan is finished in well under a second, so it can be gone
      # — capability file and all — before this runtime connects. `prepare` still answers
      # with the operation id, because the journal it left is the record of what happened.
      #
      # Either source may therefore answer here. The state event and the `done` frame are two
      # frames and the first can arrive without the second, so this waits until the answer is
      # complete: the worker has said `done`, or it is gone and the journal is answering.
      settled =
        await(
          operation,
          fn snapshot ->
            snapshot["state"] in ["failed", "cancelled", "interrupted"] and
              (snapshot["source"] == "journal" or is_map(snapshot["done"]))
          end,
          "the operation to settle"
        )

      # It is *named*, and named in the way the spec asks for: a stable snake_case reason
      # with a sentence beside it. Nothing here waits forever on a port nothing answers, and
      # nothing reports "failed" with no account of why.
      assert settled["state"] == "failed"

      if settled["source"] == "worker" do
        done = settled["done"]
        assert done["ok"] == false

        # The reason code is the contract, so it is pinned: a rename should show up here as
        # a diff rather than be absorbed by a shape check. The sentence beside it is not —
        # `detail` is written for a person and may be reworded at any time, so this asserts
        # only that there is one.
        assert done["reason"] == "host_scan_failed"
        assert is_binary(done["detail"]) and done["detail"] != ""
      end

      # The durable half, which is what an operator reads after the worker is gone. This is
      # asserted whichever source answered above.
      assert {:ok, journal} = Journal.read(context.root, operation)
      assert journal["state"] == "failed"

      assert is_binary(journal["last_error"]) and journal["last_error"] != "",
             "the journal does not say why: #{inspect(journal["last_error"])}"

      assert_cookie_absent(context.root, operation)
    end

    # -------------------------------------------------------------------------
    # (c) Stopping one

    test "a cancel ends the worker, and it removes its socket and capability", context do
      # A setup waits for its plan to be approved, so it is an operation that is genuinely
      # running when the cancel arrives — which is what this case is about. An `add` that
      # cannot reach its target is gone before there is anything to cancel.
      assert {:ok, %{"operation_id" => operation}} =
               prepare(%{
                 "kind" => "setup",
                 "machine" => "lab",
                 "address" => "127.0.0.1",
                 "service" => false
               })

      _review = await_challenge(operation, "review")
      assert %{"attached" => true} = await(operation, &(&1["attached"] == true), "the attach")

      deploy = Journal.deploy_dir(context.root)
      socket = Path.join(deploy, operation <> ".sock")
      cap = Path.join(deploy, operation <> ".cap")

      assert {:ok, _reply} =
               Call.call(:operate, "fleet.deployment.cancel", %{"operation_id" => operation},
                 session: session()
               )

      assert wait_until(fn -> not File.exists?(socket) and not File.exists?(cap) end),
             "the worker left #{inspect(File.ls!(deploy))} behind after a cancel\n" <>
               worker_log(operation)

      # The journal survives it — that is the point of the journal.
      assert {:ok, journal} = Journal.read(context.root, operation)
      assert is_binary(journal["state"])
    end

    # -------------------------------------------------------------------------

    # `Ouroboros.Web.Call` installs no identity in this suite, so the actor is the one
    # `Audit.Identity.actor/0` answers with when none resolves. The worker echoes exactly
    # that back as the operation's owner, which is what the ownership assertions check.
    defp session, do: "real-worker-view"
    defp subject, do: "runtime-unattributed"
    defp bound, do: %{subject: subject(), session: session()}

    defp prepare(params) do
      Call.call(:operate, "fleet.deployment.prepare", params, session: session())
    end

    # The full setup flow, for a case that needs this machine to already be in a fleet.
    defp create_fleet(_context) do
      assert {:ok, %{"operation_id" => operation}} =
               prepare(%{
                 "kind" => "setup",
                 "machine" => "lab",
                 "address" => "127.0.0.1",
                 "service" => false
               })

      review = await_challenge(operation, "review")

      assert {:ok, _} =
               Call.call(
                 :operate,
                 "fleet.deployment.start",
                 %{
                   "operation_id" => operation,
                   "plan_digest" => review["plan_digest"],
                   "idempotency_key" => "create-fleet"
                 },
                 session: session()
               )

      await(operation, &(&1["state"] == "completed"), "the fleet to be created")
      operation
    end

    defp unreachable_add do
      %{
        "kind" => "add",
        "target" => %{"address" => "127.0.0.1", "machine" => "nowhere"},
        "ssh_user" => "nobody",
        # Nothing listens on port 1, and the worker must say so rather than wait.
        "port" => 1,
        "service" => false
      }
    end

    defp await(operation, predicate, what) do
      deadline = System.monotonic_time(:millisecond) + @step

      Stream.repeatedly(fn ->
        result = Deployment.status(operation, bound())
        unless match?({:ok, _}, result), do: Process.sleep(100)
        result
      end)
      |> Enum.find_value(fn
        {:ok, snapshot} ->
          cond do
            predicate.(snapshot) ->
              snapshot

            System.monotonic_time(:millisecond) > deadline ->
              flunk(timed_out(operation, what, snapshot))

            true ->
              Process.sleep(100)
              false
          end

        {:error, reason} ->
          if System.monotonic_time(:millisecond) > deadline,
            do: flunk(timed_out(operation, what, reason)),
            else: false
      end)
    end

    # The worker is a separate process with its own log, and a timeout here is almost always
    # something *it* said rather than something this side did. Printing the tail of that log
    # is the difference between a reproducible failure and a rerun.
    defp timed_out(operation, what, last) do
      """
      waited #{@step}ms for #{what}
      last answer: #{inspect(last, limit: 20, printable_limit: 400)}
      #{worker_log(operation)}
      """
    end

    defp worker_log(operation) do
      deploy = Journal.deploy_dir(Application.get_env(:ouroboros, :data_dir))
      path = Path.join(deploy, operation <> ".log")

      case File.read(path) do
        {:ok, ""} -> "#{path}: empty"
        {:ok, body} -> "#{path}, last 40 lines:\n" <> tail(body, 40)
        {:error, reason} -> "#{path}: unreadable (#{inspect(reason)})"
      end
    end

    defp tail(body, count) do
      body
      |> String.split("\n")
      |> Enum.take(-count)
      |> Enum.map_join("\n", &("  " <> &1))
    end

    defp await_challenge(operation, kind) do
      snapshot =
        await(
          operation,
          fn snapshot -> Enum.any?(snapshot["challenges"], &(&1["kind"] == kind)) end,
          "a #{kind} challenge"
        )

      Enum.find(snapshot["challenges"], &(&1["kind"] == kind))
    end

    # `Enum.reduce_while`, not `Enum.find_value`: a `find_value` whose callback answers `nil`
    # past the deadline keeps iterating, because `nil` is what "not found" looks like to it.
    # The previous version of this spun until the whole test timed out at three minutes
    # instead of failing in thirty seconds with a reason — a bug in the test, which is the
    # kind that costs the most to diagnose because it looks like a bug in the code.
    defp wait_until(predicate) do
      deadline = System.monotonic_time(:millisecond) + @step

      Enum.reduce_while(Stream.cycle([:tick]), false, fn _tick, _acc ->
        cond do
          predicate.() -> {:halt, true}
          System.monotonic_time(:millisecond) > deadline -> {:halt, false}
          true -> Process.sleep(100) && {:cont, false}
        end
      end)
    end

    # Seam S3: the directory is 0700 and every file in it is 0600. Asserted against what the
    # worker actually wrote rather than against what this side would have written.
    defp assert_private(deploy) do
      assert %File.Stat{type: :directory, mode: mode} = File.lstat!(deploy)
      assert (mode &&& 0o077) == 0, "the deploy directory is #{Integer.to_string(mode, 8)}"

      for name <- File.ls!(deploy) do
        path = Path.join(deploy, name)
        %File.Stat{mode: file_mode, type: type} = File.lstat!(path)

        assert (file_mode &&& 0o077) == 0,
               "#{name} is #{Integer.to_string(file_mode, 8)}, readable beyond this account"

        assert type in [:regular, :other], "#{name} is a #{type}"
      end
    end

    # The fleet's distribution cookie is the credential that joining a fleet hands out. The
    # spec's one list forbids it from journals and receipts; this reads the real cookie the
    # real setup wrote and looks for it in everything beside it.
    defp assert_cookie_absent(root, operation) do
      case File.read(Path.join([root, "fleet", "cookie"])) do
        {:ok, cookie} ->
          cookie = String.trim(cookie)
          assert byte_size(cookie) > 8, "the cookie is too short to be worth searching for"

          deploy = Journal.deploy_dir(root)

          for name <- File.ls!(deploy), File.regular?(Path.join(deploy, name)) do
            body = File.read!(Path.join(deploy, name))

            refute String.contains?(body, cookie),
                   "#{name} carries the fleet cookie"
          end

          assert {:ok, journal} = Journal.read(root, operation)
          refute JSON.encode!(journal) =~ cookie

        {:error, :enoent} ->
          # No fleet was created by this case, so there is no cookie to leak.
          :ok
      end
    end
  else
    @moduletag skip:
                 "the real `ouro` is not built at #{@ouro}; build it with " <>
                   "`cd tui && cargo build -p ouro`, or set OUROBOROS_TEST_OURO to one, then " <>
                   "`mix compile --force` so this module sees it"

    test "drives the real deployment worker" do
      flunk("unreachable: this module is skipped when the binary is absent")
    end
  end
end
