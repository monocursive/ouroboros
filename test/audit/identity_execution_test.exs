defmodule Ouroboros.Audit.IdentityExecutionTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log
  alias Ouroboros.Audit.{Config, Store}
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Test.NativeModelScript

  setup do
    {:ok, tmp} = Ouroboros.Workspace.Path.canonicalize(System.tmp_dir!())
    root = Path.join(tmp, "ouro-audit-identity-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(workspace)

    previous =
      Map.new(
        [:audit, :native_data_dir, :native_model_module],
        &{&1, Application.get_env(:ouroboros, &1)}
      )

    :ok = Supervisor.terminate_child(Ouroboros.Supervisor, Store)
    Application.put_env(:ouroboros, :native_data_dir, Path.join(root, "native"))
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      Enum.each(previous, fn
        {key, nil} -> Application.delete_env(:ouroboros, key)
        {key, value} -> Application.put_env(:ouroboros, key, value)
      end)

      Supervisor.restart_child(Ouroboros.Supervisor, Store)
      File.rm_rf!(root)
    end)

    %{root: root, workspace: workspace}
  end

  for mode <- [:local, :required] do
    test "#{mode} audit starts both gateway planes with trusted attribution", ctx do
      identity = %{
        "id" => "alice",
        "roles" => ["operator"],
        "token_sha256" => :crypto.hash(:sha256, "test-token") |> Base.encode16(case: :lower)
      }

      config =
        Config.new!(
          mode: unquote(mode),
          capture: :full,
          identities: [identity],
          root: Path.join(ctx.root, "evidence")
        )

      Application.put_env(:ouroboros, :audit, config)
      start_supervised!({Store, config: config})
      subject = Map.take(identity, ["id", "token_sha256"])

      for method <- ["interactive.start", "coding.start"] do
        {model, script} = NativeModelScript.start([[{:text, "done"}, {:finish, :stop}]])
        id = "audit-start-#{System.unique_integer([:positive])}"

        params = %{
          "id" => id,
          "provider" => "native",
          "workspace" => ctx.workspace,
          "model" => model,
          "worktree" => false,
          "runtime_exposure" => false
        }

        params =
          if method == "coding.start", do: Map.put(params, "objective", "say done"), else: params

        assert {:ok, _} = Methods.invoke_as(subject, method, params)

        if method == "coding.start" do
          on_exit(fn -> Ouroboros.CodingSession.cancel(id) end)
          assert {:ok, task} = Ouroboros.CodingSession.await(id, 5000)
          assert task.status == :completed
          assert length(NativeModelScript.requests(script)) == 1
          assert {:ok, task} = Ouroboros.Coding.Store.get(id)
          assert task.options.audit_actor_id == "alice"
          assert Ouroboros.Audit.actor_id(Ouroboros.Coding.TaskState.request(task)) == "alice"
        else
          on_exit(fn -> Ouroboros.InteractiveSession.close(id) end)
          turn_id = "audit-turn"
          assert {:ok, _} = Ouroboros.InteractiveSession.send_message(id, "say done", id: turn_id)
          assert {:ok, turn} = Ouroboros.InteractiveSession.await(id, turn_id, 5000)
          assert turn.status == :completed
          assert length(NativeModelScript.requests(script)) == 1
          assert {:ok, state} = Ouroboros.Interactive.Store.get(id)
          assert Ouroboros.Audit.actor_id(Ouroboros.Interactive.State.request(state)) == "alice"
          assert :ok = Ouroboros.InteractiveSession.close(id)
        end
      end

      {:ok, rows} = Ouroboros.Audit.Query.events(config.root)
      opened = Enum.filter(rows, &(&1["kind"] == "session_opened"))
      assert length(opened) == 2
      assert Enum.all?(opened, &(&1["actor_id"] == "alice"))

      assert {:error, -32602, _} =
               Methods.invoke_as(subject, "interactive.start", %{
                 "provider" => "native",
                 "workspace" => ctx.workspace,
                 "audit_actor_id" => "mallory"
               })

      assert {:error, -32602, _} =
               Methods.invoke_as(subject, "interactive.start", %{
                 "provider" => "native",
                 "workspace" => ctx.workspace,
                 "provider_options" => %{"audit_actor_id" => "mallory"}
               })
    end
  end

  test "native children inherit request attribution and cannot supply it in tool input", ctx do
    alias Jido.Harness.SessionRequest, as: Request
    alias Ouroboros.Provider.Native.Tools.Agent, as: AgentTool

    config =
      Config.new!(
        mode: :required,
        root: Path.join(ctx.root, "evidence"),
        identities: [
          %{"id" => "alice", "roles" => ["operator"], "token_sha256" => String.duplicate("a", 64)}
        ]
      )

    Application.put_env(:ouroboros, :audit, config)
    {:ok, scope} = Ouroboros.Provider.Native.Paths.scope(ctx.workspace, [], :workspace_write)

    request =
      Request.new!(%{provider: :native, cwd: ctx.workspace, metadata: %{audit_actor_id: "alice"}})

    parent = %{
      depth: 0,
      provider_session_id: "parent",
      session_id: "session",
      session_pid: self(),
      request: request,
      context: %{owner: self(), session_id: "session", provider: :native},
      scope: scope,
      model_spec: "scripted:parent",
      approval_mode: :auto_approve,
      tool_names: [],
      options: %{"audit_actor_id" => "mallory"},
      subscriber: self(),
      background_subscriber: self(),
      running: 0,
      tracked: 0
    }

    assert {:ok, child} =
             AgentTool.plan(%{"prompt" => "look", "audit_actor_id" => "mallory"}, parent)

    assert Ouroboros.Audit.actor_id(child.request_attrs) == "alice"
    refute Map.has_key?(child.request_attrs.provider_options, "audit_actor_id")
    assert :ok = Ouroboros.Audit.ensure_actor(child.request_attrs)

    Application.put_env(:ouroboros, :audit, %{
      config
      | identities: [Map.put(hd(config.identities), "roles", ["auditor"])]
    })

    assert_raise Ouroboros.Audit.Unavailable, fn ->
      Ouroboros.Audit.ensure_actor(child.request_attrs)
    end
  end
end
