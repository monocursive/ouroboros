defmodule Ouroboros.Provider.NativeTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.RunRequest
  alias Ouroboros.Provider
  alias Ouroboros.Provider.Native
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-provider-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)

    previous_dir = Application.get_env(:ouroboros, :native_data_dir)
    previous_model = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      restore(:native_data_dir, previous_dir)
      restore(:native_model_module, previous_model)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  describe "registration" do
    test "is a registered provider like the three this runtime already overrides" do
      assert Map.get(Jido.Harness.Registry.providers(), :native) == Native
      assert {:ok, spec} = Jido.Harness.Registry.spec(:native)
      assert spec.provider == :native
    end

    test "appears in the runtime's own provider list, with no list to keep in sync" do
      assert :native in Enum.map(Ouroboros.providers(), & &1.provider)
    end
  end

  describe "spec/0" do
    test "declares the full normalized option set the slice specifies" do
      spec = Native.spec()

      assert Enum.sort(spec.normalized_options) ==
               Enum.sort([
                 :model,
                 :system_prompt,
                 :max_turns,
                 :approval_mode,
                 :sandbox_mode,
                 :reasoning_effort,
                 :attachments,
                 :provider_session_id,
                 :allowed_tools,
                 :disallowed_tools,
                 :add_dirs
               ])
    end

    test "offers every approval mode and no sandbox mode it cannot enforce" do
      spec = Native.spec()

      assert spec.normalized_values.approval_mode == [
               :default,
               :prompt,
               :auto_edit,
               :auto_approve
             ]

      assert spec.normalized_values.sandbox_mode == [:default, :read_only, :workspace_write]
      refute :unrestricted in spec.normalized_values.sandbox_mode
    end

    test "declares one transport, and it is the one the session adapter implements" do
      spec = Native.spec()

      assert spec.default_session_transport == :native
      assert [transport] = spec.session_transports
      assert transport.name == :native
      assert transport.adapter == Ouroboros.Provider.Native.Session

      assert transport.configuration_options == [
               :model,
               :reasoning_effort,
               :approval_mode,
               :sandbox_mode
             ]
    end

    test "the only transport is selectable by default, so choosing the provider is enough" do
      [transport] = Native.spec().session_transports

      # `Jido.Harness.Session.Manager` refuses to default to an `:experimental`
      # transport (`session/manager.ex:128`). Since this is the provider's only one,
      # marking it experimental would make `provider: :native` refuse to start unless
      # every caller also passed `transport: :native`.
      assert transport.capabilities.maturity == :stable
    end
  end

  describe "session_capabilities/2" do
    test "reports the native transport, including the steer eight of nine cannot do" do
      assert Provider.session_capabilities(:native) == %{
               transport: :native,
               process: :persistent,
               multi_turn: :native,
               follow_up: :managed,
               interrupt: :native,
               approvals: :native,
               steer: :native,
               multimodal: false,
               dynamic_model: :native,
               dynamic_configuration: :native,
               fork: false
             }
    end

    test "every declared capability is answered by an exported callback" do
      adapter = Ouroboros.Provider.Native.Session
      capabilities = Provider.session_capabilities(:native)

      assert capabilities.approvals != false
      assert function_exported?(adapter, :respond_approval, 3)
      assert capabilities.steer != false
      assert function_exported?(adapter, :steer, 3)
      assert capabilities.dynamic_configuration != false
      assert function_exported?(adapter, :configure, 2)
    end
  end

  describe "safety_options/3" do
    test "accepts both plane defaults on both planes" do
      assert {:ok, [approval_mode: :prompt, sandbox_mode: :workspace_write]} =
               Provider.safety_options(:native, [], :coding)

      assert {:ok, [approval_mode: :prompt, sandbox_mode: :workspace_write]} =
               Provider.safety_options(:native, [], {:interactive, nil})
    end

    test "`:prompt` is answerable here, unlike on a managed transport" do
      # X1's refusal fires only where the transport has no approvals channel. This one
      # does, so the plane default survives.
      assert {:ok, options} = Provider.safety_options(:native, [], {:interactive, :native})
      assert Keyword.get(options, :approval_mode) == :prompt
    end

    test "refuses a sandbox mode it cannot enforce, by name" do
      assert {:error, {:unsupported_safety_options, detail}} =
               Provider.safety_options(:native, [sandbox_mode: :unrestricted], :coding)

      assert detail.provider == :native
      assert detail.message =~ "cannot enforce sandbox_mode: :unrestricted"
      assert detail.message =~ ":workspace_write"
    end

    test "accepts read_only" do
      assert {:ok, options} =
               Provider.safety_options(:native, [sandbox_mode: :read_only], :coding)

      assert Keyword.get(options, :sandbox_mode) == :read_only
    end
  end

  describe "status/1" do
    test "reports credential presence by environment variable name, never by value" do
      System.put_env("OUROBOROS_NATIVE_STATUS_PROBE", "sk-must-not-appear")
      on_exit(fn -> System.delete_env("OUROBOROS_NATIVE_STATUS_PROBE") end)

      # Probe the real client, not the scripted one: the claim under test is about what
      # `Model.ReqLLM.credential_report/0` puts on the wire.
      Application.put_env(
        :ouroboros,
        :native_model_module,
        Ouroboros.Provider.Native.Model.ReqLLM
      )

      assert {:ok, status} = Native.status(%{})

      assert status.provider == :native
      assert status.executable == "in-process"
      assert status.details["model_env"] == "OUROBOROS_NATIVE_MODEL"

      assert status.details["sandbox"] ==
               Ouroboros.Provider.Native.Sandbox.label(Ouroboros.Provider.Native.Sandbox.detect())

      credentials = status.details["credentials"]
      assert is_list(credentials)
      assert Enum.all?(credentials, &(is_binary(&1["env"]) and is_boolean(&1["present"])))

      serialized = JSON.encode!(status.details)
      refute serialized =~ "sk-must-not-appear"

      for %{"env" => env} <- credentials do
        case System.get_env(env) do
          value when is_binary(value) and value != "" -> refute serialized =~ value
          _unset -> :ok
        end
      end
    end

    # C5. `sandbox` names the backend this node actually has, so a client footer may say
    # "no OS sandbox" for a native session only when it reads `none` — never inferred,
    # never a boolean, and never a claim the node cannot back.
    test "names the OS sandbox backend this node has, or none" do
      detection = Ouroboros.Provider.Native.Sandbox.detect()
      assert {:ok, status} = Native.status(%{})

      assert status.details["sandbox"] == Ouroboros.Provider.Native.Sandbox.label(detection)
      assert status.details["sandbox"] in ["sandbox-exec", "bwrap", "none"]
      assert status.details["sandbox_notes"] == detection.notes

      case detection.backend do
        :none ->
          assert status.details["enforced"] =~ "read_only refuses write/edit/bash"
          assert status.details["enforced"] =~ "no OS sandbox on this node"

        _present ->
          assert status.details["enforced"] =~ "runs bash under #{status.details["sandbox"]}"
          assert status.details["enforced"] =~ "the network denied"
      end
    end
  end

  describe "run/2 on the coding plane" do
    test "runs one finite turn to completion and returns its event stream", context do
      {model_spec, _agent} =
        NativeModelScript.start([
          [
            {:text, "reading"},
            {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
          ],
          [{:text, "all good"}, {:usage, %{input_tokens: 9, output_tokens: 3}}, {:finish, :stop}]
        ])

      request =
        RunRequest.new!(%{
          prompt: "look at lib/a.ex",
          provider: :native,
          cwd: context.workspace,
          model: model_spec,
          approval_mode: :auto_approve
        })

      run_context = %{
        run_id: "run-1",
        provider: :native,
        config: %{},
        telemetry_context: %{},
        process_manager: Jido.Harness.ProcessDriver.Erlexec
      }

      assert {:ok, stream} = Native.run(request, run_context)
      events = Enum.to_list(stream)

      assert Enum.map(events, & &1.type) == [
               :turn_started,
               :output_text_delta,
               :output_text_final,
               :tool_call,
               :tool_result,
               :output_text_delta,
               :output_text_final,
               :usage,
               :turn_completed
             ]

      assert Enum.all?(events, &(&1.provider == :native))
      assert Enum.all?(events, &String.starts_with?(&1.provider_session_id, "native-"))

      result = Enum.find(events, &(&1.type == :tool_result))
      assert result.payload["output"] =~ "def x, do: 1"
    end

    test "refuses to run with no model rather than starting a turn it cannot finish", context do
      request =
        RunRequest.new!(%{prompt: "hello", provider: :native, cwd: context.workspace})

      run_context = %{
        run_id: "run-2",
        provider: :native,
        config: %{},
        telemetry_context: %{},
        process_manager: Jido.Harness.ProcessDriver.Erlexec
      }

      assert {:error, {:no_model, message}} = Native.run(request, run_context)
      assert message =~ "OUROBOROS_NATIVE_MODEL"
    end
  end

  # Defined only when a model is configured, and excluded from `mix test` even then
  # (`test/test_helper.exs`). Run it deliberately:
  #
  #     OUROBOROS_NATIVE_MODEL=anthropic:claude-sonnet-5 mix test --include live_native
  if (System.get_env("OUROBOROS_NATIVE_MODEL") || "") != "" do
    describe "a live model" do
      @tag :live_native
      @tag timeout: 300_000
      test "edits a file end to end against a real provider", context do
        model = System.get_env("OUROBOROS_NATIVE_MODEL")

        Application.put_env(
          :ouroboros,
          :native_model_module,
          Ouroboros.Provider.Native.Model.ReqLLM
        )

        request =
          RunRequest.new!(%{
            prompt:
              "Read lib/a.ex, then edit it so `x` returns 2 instead of 1. " <>
                "Do not run any commands.",
            provider: :native,
            cwd: context.workspace,
            model: model,
            approval_mode: :auto_approve,
            sandbox_mode: :workspace_write
          })

        run_context = %{
          run_id: "run-live",
          provider: :native,
          config: %{},
          telemetry_context: %{},
          process_manager: Jido.Harness.ProcessDriver.Erlexec
        }

        assert {:ok, stream} = Native.run(request, run_context)
        events = Enum.to_list(stream)
        types = Enum.map(events, & &1.type)

        assert :tool_call in types
        assert :file_change in types
        assert List.last(types) == :turn_completed
        assert File.read!(Path.join(context.workspace, "lib/a.ex")) =~ "def x, do: 2"
      end
    end
  end
end
