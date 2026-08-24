defmodule Ouroboros.Provider.Native.CodingApprovalTest do
  use ExUnit.Case, async: false

  alias Ouroboros.CodingSession
  alias Ouroboros.Test.NativeModelScript

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

  defp await_approval(id) do
    receive do
      {:ouroboros_coding_event, ^id, %{type: :approval_requested} = event} -> event
      {:ouroboros_coding_event, ^id, _event} -> await_approval(id)
    after
      10_000 -> flunk("coding run did not request approval")
    end
  end
end
