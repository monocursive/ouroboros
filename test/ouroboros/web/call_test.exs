defmodule Ouroboros.Web.CallTest do
  @moduledoc """
  The one seam between the browser and the runtime.

  What matters here is that the answers are the gateway's answers — same codes, same
  shapes, same ceilings — because the whole argument for this module is that a second
  surface must not become a second policy.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Web.Call

  # An operate verb with no ambiguity marker, and one with it. Both are read from the
  # gateway's own table, so a slice that changes what they cost changes this test too.
  @operate "permissions.add"
  @operate_unknown_outcome "interactive.start"
  @read "runtime.status"

  setup do
    start_supervised!({Task.Supervisor, name: Ouroboros.Web.TaskSupervisor})
    :ok
  end

  describe "the scope gate" do
    test "a read endpoint refuses an operate method with the gateway's own code" do
      assert {:error, code, message} = Call.call(:read, @operate, %{})

      assert code == Methods.code(:scope_denied)
      assert code == -32_003
      assert message =~ @operate
      # The refusal names the variable an operator would have to change, which for this
      # surface is the web's own rather than the gateway's.
      assert message =~ "OUROBOROS_WEB_SCOPE=read"
    end

    test "an operate endpoint may run it" do
      # The call itself is allowed to fail on its parameters; what is asserted is that it
      # was not refused for scope.
      refute match?({:error, -32_003, _message}, Call.call(:operate, @operate, %{}))
    end

    test "the same gate answers the feature question a page asks" do
      assert Call.available?(:read, @read)
      assert Call.available?(:operate, @read)
      assert Call.available?(:operate, @operate)

      refute Call.available?(:read, @operate)
      refute Call.available?(:operate, "runtime.invent_a_verb")
    end
  end

  describe "a method this build does not serve" do
    test "is not found, in the gateway's shape" do
      assert {:error, code, message} = Call.call(:operate, "runtime.invent_a_verb", %{})

      assert code == Methods.code(:method_not_found)
      assert code == -32_601
      assert message == "this build does not serve runtime.invent_a_verb"
    end

    test "and scope does not change the answer" do
      assert Call.call(:read, "runtime.invent_a_verb", %{}) ==
               Call.call(:operate, "runtime.invent_a_verb", %{})
    end
  end

  describe "a read method" do
    test "answers with what the runtime knows" do
      assert {:ok, status} = Call.call(:read, @read, %{})

      assert status.node == node()
      assert is_list(status.connected_nodes)
      assert is_list(status.interactive_sessions)
    end

    test "and leaves no audit line, because nothing was mutated" do
      log = capture_log(fn -> Call.call(:read, @read, %{}) end)

      refute log =~ "web operate"
    end
  end

  describe "the audit line" do
    test "names the call and never its contents" do
      log =
        capture_log(fn ->
          Call.call(:operate, @operate, %{"pattern" => "Bash(rm -rf /secret-project)"},
            session: "session-under-test"
          )
        end)

      assert log =~ "web operate #{@operate}"
      assert log =~ "session=session-under-test"
      assert log =~ ~r/params=[0-9a-f]{16}/

      # The payload is the operator's own trust domain, and a log is not where they chose
      # to write it down.
      refute log =~ "secret-project"
    end

    test "attributes a call with no session honestly rather than inventing one" do
      log = capture_log(fn -> Call.call(:operate, @operate, %{}) end)

      assert log =~ "session=unattributed"
    end

    test "is the gateway's digest, so one request reads the same in both logs" do
      params = %{"pattern" => "Bash(git status)", "decision" => "allow"}

      digest =
        :sha256
        |> :crypto.hash(params |> Ouroboros.Gateway.Wire.to_json() |> JSON.encode_to_iodata!())
        |> Base.encode16(case: :lower)
        |> binary_part(0, 16)

      log = capture_log(fn -> Call.call(:operate, @operate, params) end)

      assert log =~ "params=#{digest}"
    end
  end

  describe "the timeout answer" do
    test "says the runtime may still be working, and names the ceiling it used" do
      {:ok, entry} = Methods.fetch(@operate)

      assert {:error, code, message} = Call.timeout_answer(@operate, entry)

      assert code == Methods.code(:upstream_timeout)
      assert code == -32_005
      assert message =~ "#{entry.timeout}ms"
      assert message =~ "may still be working on it"
    end

    test "carries the ambiguity marker for the methods the table marks ambiguous" do
      {:ok, entry} = Methods.fetch(@operate_unknown_outcome)

      assert entry.outcome == :unknown

      assert {:error, _code, _message, %{"outcome" => "unknown"}} =
               Call.timeout_answer(@operate_unknown_outcome, entry)
    end
  end
end
