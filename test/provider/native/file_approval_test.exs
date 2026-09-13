defmodule Ouroboros.Provider.Native.FileApprovalTest do
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias Ouroboros.Provider.Native.{Loop, Paths}
  alias Ouroboros.Session.ApprovalResponse
  alias Ouroboros.Test.NativeModelScript
  alias Ouroboros.Web.Live.ApprovalCard
  alias Ouroboros.Web.Transcript.Approval

  @patch "*** Begin Patch\n*** Add File: proof.txt\n+<script>not HTML</script>\n*** End Patch"

  setup do
    root = Path.join(System.tmp_dir!(), "file-approval-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace"))
    File.mkdir_p!(Path.join(root, "session"))
    on_exit(fn -> File.rm_rf(root) end)
    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)
    %{scope: scope, session_dir: Path.join(root, "session")}
  end

  defp request(context, name, input) do
    {model, _agent} =
      NativeModelScript.start([
        [{:tool_call, %{id: "change", name: name, input: input}}],
        [{:text, "finished"}, {:finish, :stop}]
      ])

    parent = self()

    loop = %Loop{
      emit: fn event -> send(parent, {:event, event}) end,
      model_module: NativeModelScript,
      model_spec: model,
      system: "system",
      scope: context.scope,
      session_dir: context.session_dir,
      session_id: "file-approval",
      provider_session_id: "native-file-approval",
      turn_id: "turn",
      allowed_tools: [name],
      approval_mode: :prompt,
      approval_timeout_ms: :infinity
    }

    pid = spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "propose a change")}) end)
    assert_receive {:event, %{type: :approval_requested} = event}, 30_000
    {pid, event}
  end

  defp answer(pid, event, decision) do
    send(pid, {:native_approval, event.request_id, ApprovalResponse.new!(%{decision: decision})})
    assert_receive {:finished, _}, 30_000
  end

  defp card(event) do
    # Exercise the same redacted event projection the authenticated web surface receives.
    runtime_event = Ouroboros.Session.RuntimeEvent.new!(Map.put(event, :provider, :native))
    payload = Ouroboros.Interactive.Event.from_execution("file-approval", runtime_event).payload
    request = %Approval{request_id: event.request_id, payload: payload}

    render_component(&ApprovalCard.card/1,
      request: request,
      detail: Approval.detail(request),
      node: nil,
      rule: nil,
      rule_refusal: nil,
      notice: nil
    )
  end

  test "pending native patch is visible as escaped input before once approval executes it",
       context do
    {pid, event} = request(context, "apply_patch", %{"patch" => @patch})
    refute File.exists?(Path.join(context.scope.root, "proof.txt"))
    html = card(event)
    assert html =~ "Proposed file change"
    assert html =~ "*** Add File: proof.txt"
    assert html =~ "&lt;script&gt;not HTML&lt;/script&gt;"
    refute html =~ "<script>not HTML</script>"
    assert event.payload["proposed_change"]["patch"] == @patch
    assert html =~ ~s(phx-value-scope="once")
    answer(pid, event, :approve)
    assert File.read!(Path.join(context.scope.root, "proof.txt")) == "<script>not HTML</script>"
  end

  test "write preview includes path and replacement, and denial leaves the file untouched",
       context do
    {pid, event} =
      request(context, "write", %{"path" => "proof.txt", "content" => "replacement\n"})

    html = card(event)
    assert html =~ "proof.txt"
    assert html =~ "Replacement content"
    assert html =~ "replacement"
    answer(pid, event, :deny)
    refute File.exists?(Path.join(context.scope.root, "proof.txt"))
  end

  test "edit preview shows old/new text and replace-all intent without reading a file", context do
    input = %{
      "path" => "proof.txt",
      "old_string" => "old",
      "new_string" => "new",
      "replace_all" => true
    }

    {pid, event} = request(context, "edit", input)
    assert event.payload["proposed_change"] == input
    html = card(event)
    assert html =~ "Text to replace"
    assert html =~ "Replacement text"
    assert html =~ "Replace every occurrence"
    assert html =~ "true"
    answer(pid, event, :deny)
    assert_receive {:event, %{type: :tool_result, payload: result}}, 1_000
    assert result["is_error"]
    assert result["output"] =~ "Refused: the operator denied this edit call"
    refute File.exists?(Path.join(context.scope.root, "proof.txt"))
  end

  test "preview keeps V4A move/delete directives and whitespace verbatim" do
    patch =
      "*** Begin Patch\n*** Update File: old.txt\n*** Move to: new.txt\n@@\n-old \n+new  \n*** Delete File: gone.txt\n*** End Patch\n"

    payload =
      Ouroboros.Provider.Native.FileApproval.attach(%{}, %{
        name: "apply_patch",
        input: %{"patch" => patch}
      })

    assert payload["proposed_change"] == %{"patch" => patch}
  end

  test "known-field projection does not copy unrelated arguments or non-file tools" do
    call = %{name: "write", input: %{"path" => "a", "content" => "", "metadata" => "do not copy"}}

    assert Ouroboros.Provider.Native.FileApproval.attach(%{}, call) ==
             %{"proposed_change" => %{"path" => "a", "content" => ""}}

    assert Ouroboros.Provider.Native.FileApproval.attach(%{"kind" => "command"}, %{
             call
             | name: "bash"
           }) ==
             %{"kind" => "command"}
  end

  test "large Unicode input is explicitly excerpted without changing execution arguments",
       context do
    content = String.duplicate("🦀", 10_000) <> "hidden ending"
    {pid, event} = request(context, "write", %{"path" => "large.txt", "content" => content})
    preview = event.payload["proposed_change"]["content"]
    assert preview["_bytes"] == byte_size(content)
    assert byte_size(preview["_excerpt"]) <= 32 * 1024
    assert String.valid?(preview["_excerpt"])
    html = card(event)
    assert html =~ "Only an excerpt is shown"
    assert html =~ "including the part not shown"
    refute html =~ "hidden ending"
    answer(pid, event, :approve)
    assert File.read!(Path.join(context.scope.root, "large.txt")) == content
  end

  test "redaction precedes excerpting and does not expose a bearer prefix at the cut" do
    content =
      String.duplicate("x", 32 * 1024 - 12) <>
        " Bearer fixture-credential-must-not-leak more text"

    payload =
      Ouroboros.Provider.Native.FileApproval.attach(%{}, %{
        name: "write",
        input: %{"path" => "a", "content" => content}
      })

    excerpt = payload["proposed_change"]["content"]["_excerpt"]
    refute excerpt =~ "fixt"
    assert excerpt =~ "Bearer"
  end

  test "known-secret redaction precedes the cut even without a bearer prefix" do
    # Process-local cache seam: no real environment/credential is read or modified.
    key = {Ouroboros.Redaction, :system_secrets}
    previous = Process.get(key)
    secret = "SYNTHETIC_BOUNDARY_SECRET"
    Process.put(key, [secret])

    try do
      content = String.duplicate("x", 32 * 1024 - 8) <> secret <> String.duplicate("z", 100)

      payload =
        Ouroboros.Provider.Native.FileApproval.attach(%{}, %{
          name: "write",
          input: %{"path" => "a", "content" => content}
        })

      excerpt = payload["proposed_change"]["content"]["_excerpt"]
      refute excerpt =~ "SYNTHET"
      assert excerpt =~ "[REDACTE"
    after
      if previous, do: Process.put(key, previous), else: Process.delete(key)
    end
  end
end
