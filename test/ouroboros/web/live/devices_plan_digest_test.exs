defmodule Ouroboros.Web.Live.DevicesPlanDigestTest do
  @moduledoc """
  Seam S6's digest, checked against the program that computes it.

  `approve` sends one thing about the plan — its digest — so a surface that forwarded
  whatever string the worker put in the challenge would be asking an operator to authorise a
  document by a name it had not read. `Ouroboros.Web.Live.Devices.plan_digest/1` recomputes
  it, and this file is the evidence that the recomputation is the worker's.

  Two tests, and they prove different things on purpose.

  The first is arithmetic, and it runs everywhere: a document whose canonical form and
  sha256 were computed by a third implementation (Python's `json` and `hashlib`, written out
  in the comment below) rather than by this one. It pins the rules — keys sorted at every
  depth, arrays left in order, scalars as JSON writes them, no whitespace — against
  something that cannot agree with a mistake in this build by sharing it.

  The second forks the **real** `ouro fleet worker start`, lets it build a real plan for a
  real local setup, and compares the digest it really computed with this runtime's. That is
  the only check that can catch the two drifting apart, and it needs a built binary: set
  `OUROBOROS_TEST_OURO` or build `tui/target/debug/ouro`. Absent one, it says so rather than
  passing quietly. An explicitly selected binary that is missing or not executable fails
  instead of skipping; `make test` and CI build and select this checkout's binary first.
  """

  use ExUnit.Case, async: false

  import Bitwise

  @moduletag :capture_log

  alias Ouroboros.Web.Live.Devices

  # ------------------------------------------------------------------------------------
  # The rules, against an implementation that is not this one
  # ------------------------------------------------------------------------------------

  describe "canonical JSON" do
    # Computed with:
    #
    #   def canon(v):
    #       if isinstance(v, dict):
    #           return "{" + ",".join(json.dumps(k) + ":" + canon(v[k]) for k in sorted(v)) + "}"
    #       if isinstance(v, list):
    #           return "[" + ",".join(canon(i) for i in v) + "]"
    #       return json.dumps(v, ensure_ascii=False)
    #   hashlib.sha256(canon(doc).encode()).hexdigest()
    @document %{
      "target" => %{
        "port" => 22,
        "machine" => "lab",
        "address" => "127.0.0.1",
        "data_dir" => nil
      },
      "kind" => "setup",
      "members" => [
        %{"machine" => "b", "change" => "add"},
        %{"change" => "add", "machine" => "a"}
      ],
      "service" => "managed",
      "grants" => [],
      "build" => %{},
      "schema" => 1,
      "official" => true,
      "ratio" => 1.5,
      "note" => "café · 日本"
    }

    @expected "5376a4ea2a49ac35e7c154bfeb2f23b50bcba4b677c8421fa42c216f4ed931f9"

    test "sorts keys at every depth, keeps array order, and hashes the result" do
      assert Devices.plan_digest(@document) == @expected
    end

    test "one document written two ways has one digest" do
      shuffled = %{
        "note" => "café · 日本",
        "ratio" => 1.5,
        "official" => true,
        "schema" => 1,
        "build" => %{},
        "grants" => [],
        "service" => "managed",
        "members" => [
          %{"change" => "add", "machine" => "b"},
          %{"machine" => "a", "change" => "add"}
        ],
        "kind" => "setup",
        "target" => %{
          "data_dir" => nil,
          "address" => "127.0.0.1",
          "machine" => "lab",
          "port" => 22
        }
      }

      assert Devices.plan_digest(shuffled) == @expected
    end

    test "array order is content, not presentation" do
      # The two members swapped. A canonicaliser that sorted arrays as well as objects would
      # give these one digest, and two different plans would approve each other.
      reversed = Map.put(@document, "members", Enum.reverse(@document["members"]))

      refute Devices.plan_digest(reversed) == @expected
    end

    # Forty keys, because Elixir changes map representation at thirty-two: at or below it a
    # map iterates in key order and an implementation that forgot to sort agrees with this
    # one by accident; above it the order is arbitrary. Every object in a real plan is small,
    # which is exactly why a missing sort survives a suite built only out of real plans.
    @wide %{"target" => Map.new(1..40, fn index -> {"k#{index}", index} end), "kind" => "add"}
    @wide_expected "fdcaa9e4cdd70a8cef94df701e73ce21a26b2b2621585e0a8ddf216074daae29"

    test "sorts an object too wide for map iteration to sort it by accident" do
      keys = Map.keys(@wide["target"])

      refute keys == Enum.sort(keys),
             "this map still iterates in key order, so it no longer tests what it is for"

      assert Devices.plan_digest(@wide) == @wide_expected
    end

    test "a wide object written two ways still has one digest" do
      reversed = %{
        "kind" => "add",
        "target" => Map.new(40..1//-1, fn index -> {"k#{index}", index} end)
      }

      assert Devices.plan_digest(reversed) == @wide_expected
    end

    test "a plan this build cannot canonicalise has no digest, and is not approvable" do
      assert Devices.plan_digest(%{"at" => ~D[2026-09-17]}) == nil
      assert Devices.plan_digest(nil) == nil
      assert Devices.plan_digest("a string") == nil
    end
  end

  describe "the shape approval will send" do
    test "is sixty-four lowercase hex characters and nothing else" do
      assert Devices.digest?(String.duplicate("a", 64))
      assert Devices.digest?(Devices.plan_digest(@document))

      refute Devices.digest?(String.duplicate("A", 64))
      refute Devices.digest?(String.duplicate("a", 63))
      refute Devices.digest?(String.duplicate("a", 65))
      refute Devices.digest?("sha256:" <> String.duplicate("a", 64))
      refute Devices.digest?("")
      refute Devices.digest?(nil)
    end
  end

  # ------------------------------------------------------------------------------------
  # The worker's own answer
  # ------------------------------------------------------------------------------------

  @ouro System.get_env("OUROBOROS_TEST_OURO") ||
          Path.expand("tui/target/debug/ouro", File.cwd!())

  @present (case File.lstat(@ouro) do
              {:ok, %File.Stat{type: :regular, mode: mode}} -> (mode &&& 0o111) != 0
              _absent -> false
            end)

  if @present do
    @moduletag timeout: 180_000

    test "this runtime's digest is the one the real worker computed" do
      start_supervised!({Task.Supervisor, name: Ouroboros.Web.TaskSupervisor})

      # Short, because the worker binds `<data dir>/deploy/<id>.sock` and `sun_path` is 104
      # bytes on this platform.
      root = Path.join(System.tmp_dir!(), "owpd#{System.unique_integer([:positive])}")
      File.mkdir_p!(root)
      File.chmod!(root, 0o700)

      previous = Application.get_env(:ouroboros, :data_dir)
      previous_ouro = System.get_env("OUROBOROS_PROCESS_ID_HELPER")
      Application.put_env(:ouroboros, :data_dir, root)
      System.put_env("OUROBOROS_PROCESS_ID_HELPER", @ouro)

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ouroboros, :data_dir, previous),
          else: Application.delete_env(:ouroboros, :data_dir)

        if previous_ouro,
          do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous_ouro),
          else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

        File.rm_rf!(root)
      end)

      session = "digest-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

      {:ok, %{"operation_id" => operation}} =
        Ouroboros.Web.Call.call(
          :operate,
          "fleet.deployment.prepare",
          %{"kind" => "setup", "machine" => "lab", "address" => "127.0.0.1", "service" => false},
          session: session
        )

      review = await_review(operation, session)

      assert is_map(review["plan"]), "the real worker sent no plan to review"
      assert Devices.digest?(review["plan_digest"]), "the worker's digest is not sha256 hex"

      assert Devices.plan_digest(review["plan"]) == review["plan_digest"],
             "this runtime's canonical JSON is not the worker's; approval would refuse a " <>
               "plan the operator really was shown"
    end

    defp await_review(operation, session) do
      Enum.reduce_while(1..600, nil, fn _attempt, _acc ->
        case Ouroboros.Web.Call.call(
               :read,
               "fleet.deployment.status",
               %{"operation_id" => operation},
               session: session
             ) do
          {:ok, %{"challenges" => challenges}} ->
            case Enum.find(challenges, &(&1["kind"] == "review")) do
              nil ->
                Process.sleep(100)
                {:cont, nil}

              found ->
                {:halt, found}
            end

          _not_yet ->
            Process.sleep(100)
            {:cont, nil}
        end
      end)
      |> case do
        nil -> flunk("the real worker never asked for a review")
        review -> review
      end
    end
  else
    @tag skip: is_nil(System.get_env("OUROBOROS_TEST_OURO"))
    test "this runtime's digest is the one the real worker computed" do
      flunk("no `ouro` at #{@ouro}; set OUROBOROS_TEST_OURO or build tui/target/debug/ouro")
    end
  end
end
