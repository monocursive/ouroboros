defmodule Ouroboros.Provider.Native.CodingApprovalTest do
  use ExUnit.Case, async: false

  alias Ouroboros.CodingSession
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Test.NativeModelScript

  # A node with no OS sandbox has no denial to escalate: `workspace_write` there is
  # already unsandboxed and the command simply succeeds.
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
    outside =
      Path.join(System.tmp_dir!(), "native-coding-escape-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm(outside) end)

    {model, _agent} =
      NativeModelScript.start([
        [
          {:tool_call,
           %{id: "c1", name: "bash", input: %{"command" => "echo escaped > #{outside}"}}}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ])

    id = "coding-escalation-#{System.unique_integer([:positive])}"

    assert {:ok, task} =
             CodingSession.start("write outside the workspace",
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
    assert File.read!(outside) == "escaped\n"
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
