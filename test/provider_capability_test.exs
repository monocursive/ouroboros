defmodule Ouroboros.ProviderCapabilityTest do
  @moduledoc """
  The two planes' safety defaults, checked against every bundled adapter's real spec.

  These assertions read the same specs `Jido.Harness` validates against, so a provider
  that changes what it accepts upstream fails here rather than at session start.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Interactive.State

  # provider => {interactive approval, interactive sandbox}, where `:absent` means the
  # key must not reach the harness at all so the request stays at `:default`.
  #
  # Amp declares neither option. Kimi and OpenCode reach their sessions over ACP, whose
  # transport declares neither — OpenCode's adapter accepts `approval_mode` for a run but
  # its session transport does not, which is why the lookup is per plane. Pi's RPC
  # transport declares both, and refuses only the `:prompt` approval value.
  @interactive_defaults %{
    amp: {:absent, :absent},
    claude: {:prompt, :workspace_write},
    codex: {:prompt, :workspace_write},
    gemini: {:prompt, :workspace_write},
    grok: {:prompt, :workspace_write},
    kimi: {:absent, :absent},
    opencode: {:absent, :absent},
    pi: {:absent, :absent},
    zai: {:prompt, :workspace_write}
  }

  # provider => the fields the coding plane refuses at creation under its own defaults.
  @coding_refusals %{
    amp: [:approval_mode, :sandbox_mode],
    claude: [],
    codex: [],
    gemini: [],
    grok: [],
    kimi: [:approval_mode, :sandbox_mode],
    opencode: [:sandbox_mode],
    pi: [:approval_mode, :sandbox_mode],
    zai: []
  }

  describe "interactive plane defaults" do
    for {provider, {approval, sandbox}} <- @interactive_defaults do
      test "#{provider} carries approval #{inspect(approval)} and sandbox #{inspect(sandbox)}" do
        request = interactive_request(provider: unquote(provider))

        assert Map.get(request, :approval_mode, :absent) == unquote(approval)
        assert Map.get(request, :sandbox_mode, :absent) == unquote(sandbox)
      end
    end

    test "a stated option is absolute even where the provider cannot enforce it" do
      request =
        interactive_request(
          provider: :amp,
          approval_mode: :auto_approve,
          sandbox_mode: :workspace_write
        )

      assert request.approval_mode == :auto_approve
      assert request.sandbox_mode == :workspace_write
    end

    test "an unresolvable provider is left to the harness with the defaults intact" do
      request = interactive_request(provider: :no_such_provider)

      assert request.approval_mode == :prompt
      assert request.sandbox_mode == :workspace_write
    end

    test "an unresolvable transport is left to the harness with the defaults intact" do
      request = interactive_request(provider: :amp, transport: :no_such_transport)

      assert request.approval_mode == :prompt
      assert request.sandbox_mode == :workspace_write
    end

    test "codex can start in an empty non-Git workspace and fetch dependencies" do
      request = interactive_request(provider: :codex)

      assert request.provider_options == %{
               skip_git_repo_check: true,
               network_access_enabled: true
             }
    end

    test "explicit codex restrictions win over the node defaults" do
      request =
        interactive_request(
          provider: :codex,
          provider_options: %{network_access_enabled: false, skip_git_repo_check: false}
        )

      assert request.provider_options == %{
               skip_git_repo_check: false,
               network_access_enabled: false
             }
    end
  end

  describe "coding plane defaults" do
    for {provider, refused} <- @coding_refusals, refused == [] do
      test "#{provider} keeps the workspace-write default" do
        assert {:ok, task} = coding_task(provider: unquote(provider))
        assert task.options.approval_mode == :prompt
        assert task.options.sandbox_mode == :workspace_write
      end
    end

    for {provider, refused} <- @coding_refusals, refused != [] do
      test "#{provider} refuses rather than downgrading #{inspect(refused)}" do
        assert {:error, {:unsupported_safety_options, details}} =
                 coding_task(provider: unquote(provider))

        assert details.plane == :coding
        assert details.provider == unquote(provider)
        assert Enum.map(details.options, & &1.field) == unquote(refused)
        assert Enum.all?(details.options, &(&1.source == :plane_default))

        # The refusal has to be actionable on its own: it names the provider, every
        # option and value it rejected, and the exact spelling that accepts the
        # provider's own behavior instead.
        assert details.message =~ inspect(unquote(provider))

        for field <- unquote(refused) do
          assert details.message =~ "#{field}: "
          assert details.override =~ "#{field}: :default"
        end
      end

      test "#{provider} starts once the downgrade is stated" do
        assert {:ok, task} =
                 coding_task(
                   provider: unquote(provider),
                   approval_mode: :default,
                   sandbox_mode: :default
                 )

        assert task.options.approval_mode == :default
        assert task.options.sandbox_mode == :default
      end
    end

    test "a stated value the provider cannot enforce is refused as stated, not as a default" do
      assert {:error, {:unsupported_safety_options, details}} =
               coding_task(provider: :amp, approval_mode: :default, sandbox_mode: :unrestricted)

      assert [%{field: :sandbox_mode, value: :unrestricted, source: :stated}] = details.options
      assert details.message =~ ":amp cannot enforce sandbox_mode: :unrestricted"
    end

    test "pi accepts the approval value its spec allows" do
      assert {:ok, task} =
               coding_task(provider: :pi, approval_mode: :auto_approve, sandbox_mode: :read_only)

      assert task.options.approval_mode == :auto_approve
      assert task.options.sandbox_mode == :read_only
    end

    test "an unresolvable provider is left to the harness with the defaults intact" do
      assert {:ok, task} = coding_task(provider: :no_such_provider)
      assert task.options.approval_mode == :prompt
      assert task.options.sandbox_mode == :workspace_write
    end

    test "codex execution policy is durable and publicly inspectable" do
      assert {:ok, task} = coding_task(provider: :codex)

      assert task.options.provider_options == %{
               skip_git_repo_check: true,
               network_access_enabled: true
             }

      public = TaskState.public(task)
      assert public.options.provider_execution.network_access_enabled
      refute public.options.provider_execution.git_repository_required
      refute Map.has_key?(public.options, :provider_options)
      assert TaskState.public(public) == public
    end
  end

  defp interactive_request(opts) do
    id = "capability-#{System.unique_integer([:positive, :monotonic])}"
    assert {:ok, state} = State.new(id, opts)
    State.request(state)
  end

  defp coding_task(opts) do
    id = "capability-#{System.unique_integer([:positive, :monotonic])}"
    TaskState.new(id, "probe provider capability", opts)
  end
end
