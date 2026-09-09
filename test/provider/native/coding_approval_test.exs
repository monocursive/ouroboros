defmodule Ouroboros.Provider.Native.CodingApprovalTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.CodingSession
  alias Ouroboros.Control.PolicyEvidence
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Test.NativeModelScript

  # A node with no OS sandbox has no denial to escalate: `workspace_write` there
  # refuses `bash` rather than wrapping it.
  @needs_sandbox (case Sandbox.detect().backend do
                    :none ->
                      [skip: "no OS sandbox on this node, so there is no denial to escalate"]

                    _present ->
                      []
                  end)

  setup do
    root =
      Path.join(System.tmp_dir!(), "native-coding-approval-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)

    previous_model = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      if previous_model,
        do: Application.put_env(:ouroboros, :native_model_module, previous_model),
        else: Application.delete_env(:ouroboros, :native_model_module)

      File.rm_rf(root)
    end)

    %{workspace: root}
  end

  test "a coding approval is persisted before the Native run receives it", %{workspace: workspace} do
    {model, _agent} =
      NativeModelScript.start([
        [
          {:tool_call,
           %{
             id: "write-1",
             name: "write",
             input: %{"path" => "approved.txt", "content" => "approved\n"}
           }}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ])

    id = "coding-approval-#{System.unique_integer([:positive])}"

    assert {:ok, task} =
             CodingSession.start("write the approved file",
               id: id,
               provider: :native,
               model: model,
               workspace: workspace,
               approval_mode: :prompt,
               sandbox_mode: :workspace_write
             )

    assert {:ok, backlog} = CodingSession.subscribe(task, cursor: 0)
    approval = Enum.find(backlog, &(&1.type == :approval_requested)) || await_approval(id)
    assert is_binary(approval.request_id)

    assert :ok =
             CodingSession.respond_approval(task, approval.request_id, %{
               decision: :approve,
               scope: :once,
               actor: :human
             })

    assert {:ok, final} = CodingSession.await(task, 15_000)
    assert final.status == :completed
    assert File.read!(Path.join(workspace, "approved.txt")) == "approved\n"

    assert {:ok, events} = CodingSession.replay(task, cursor: 0, limit: 200)
    requested = Enum.find_index(events, &(&1.type == :approval_requested))
    resolved = Enum.find_index(events, &(&1.type == :approval_resolved))
    tool_result = Enum.find_index(events, &(&1.type == :tool_result))
    assert requested < resolved
    assert resolved < tool_result
  end

  # The coding plane runs the same loop as an interactive session, so a sandbox
  # escalation should reach a coding operator through the same `approval_requested` /
  # `respond_approval` pair every other approval uses. "Should" is what this test is for.
  @tag @needs_sandbox
  test "a sandbox escalation reaches a coding operator and re-runs the command", %{
    workspace: workspace
  } do
    target = Path.join(workspace, ".git/escalated.txt")
    File.mkdir_p!(Path.dirname(target))

    {model, _agent} =
      NativeModelScript.start([
        [
          {:tool_call,
           %{
             id: "c1",
             name: "bash",
             input: %{
               "command" => "dir=$(printf '\\056git'); echo escaped > \"$PWD/$dir/escalated.txt\""
             }
           }}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ])

    id = "coding-escalation-#{System.unique_integer([:positive])}"

    assert {:ok, task} =
             CodingSession.start("write repository metadata",
               id: id,
               provider: :native,
               model: model,
               workspace: workspace,
               approval_mode: :auto_approve,
               sandbox_mode: :workspace_write
             )

    assert {:ok, backlog} = CodingSession.subscribe(task, cursor: 0)

    approval =
      Enum.find(backlog, &(&1.type == :approval_requested)) || await_approval(id)

    assert approval.payload["kind"] == "sandbox_escalation"

    assert :ok =
             CodingSession.respond_approval(task, approval.request_id, %{
               decision: :approve,
               scope: :once,
               actor: :human
             })

    assert {:ok, final} = CodingSession.await(task, 20_000)
    assert final.status == :completed
    assert File.read!(target) == "escaped\n"
  end

  # S2's fix wave asked for this one on the coding lane, and S2b's brief carries the request.
  #
  # `ouro run --approve-all` and every other headless client answers with `actor: "headless"`,
  # and `Jido.Harness.ApprovalResponse` has four fields, none of them the actor. The gateway
  # therefore puts the fact in `provider_options`, which is the one field on that struct that
  # survives the trip into a native run's loop; the loop reads it and labels the `:permission`
  # entry `:automation`, and `Control.PolicyEvidence` writes a corpus row only for an answer
  # that says a human gave it (S-D20).
  #
  # The whole chain is here because every link of it was invisible from the coding plane:
  # `Methods.handle_coding_respond_approval/1` at one end and a `:permission` ledger entry at
  # the other. Drop the `provider_options` half of `declared_by/2` and this goes red — the
  # entry says `:human` and the command lands in the corpus a promotion is measured against.
  test "a headless coding approval is automation in the ledger and nothing in the corpus", %{
    workspace: workspace
  } do
    corpus = Path.join(workspace, "corpus")
    File.mkdir_p!(corpus)
    Application.put_env(:ouroboros, :policy_evidence_root, corpus)
    on_exit(fn -> Application.delete_env(:ouroboros, :policy_evidence_root) end)

    command = "echo coding-headless-#{System.unique_integer([:positive, :monotonic])}"

    {model, _agent} =
      NativeModelScript.start([
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => command}}}],
        [{:text, "done"}, {:finish, :stop}]
      ])

    id = "coding-headless-#{System.unique_integer([:positive])}"

    assert {:ok, task} =
             CodingSession.start("run it",
               id: id,
               provider: :native,
               model: model,
               workspace: workspace,
               approval_mode: :prompt
             )

    assert {:ok, backlog} = CodingSession.subscribe(task, cursor: 0)
    approval = Enum.find(backlog, &(&1.type == :approval_requested)) || await_approval(id)

    # Through the gateway verb, with the params a client actually sends: the actor is a
    # declaration in the response object, and there is no other way to make one.
    assert {:ok, _answered} =
             Methods.invoke("coding.respond_approval", %{
               "id" => id,
               "request_id" => approval.request_id,
               "response" => %{"decision" => "approve", "actor" => "headless"}
             })

    assert {:ok, final} = CodingSession.await(task, 20_000)
    assert final.status == :completed

    {:ok, permissions} = EffectLedger.list(effect: :permission, limit: 500)

    entry =
      Enum.find(permissions, fn entry ->
        Map.get(entry.attempt, :tool) == "bash" and
          get_in(entry.attempt, [:principal, :session_id]) == id
      end) ||
        Enum.find(permissions, &(Map.get(&1.attempt, :tool) == "bash"))

    assert entry, "no :permission entry was written for the bash call"
    assert entry.result.actor == :automation
    refute entry.result.actor == :human

    # And no row reached the corpus a promotion is measured against.
    assert Enum.to_list(PolicyEvidence.stream()) == []
  end

  defp await_approval(id) do
    receive do
      {:ouroboros_coding_event, ^id, %{type: :approval_requested} = event} -> event
      {:ouroboros_coding_event, ^id, _event} -> await_approval(id)
    after
      10_000 -> flunk("coding run did not request approval")
    end
  end
end
