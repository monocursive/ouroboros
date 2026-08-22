defmodule Ouroboros.ProviderCapabilityTest do
  @moduledoc """
  The two planes' safety defaults, checked against every bundled adapter's real spec.

  These assertions read the same specs `Jido.Harness` validates against, so a provider
  that changes what it accepts upstream fails here rather than at session start.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Interactive.State
  alias Ouroboros.Provider
  alias Ouroboros.Provider.Session
  alias Ouroboros.Provider.Session.Dialect

  # provider => {interactive approval, interactive sandbox}, where `:absent` means the
  # key must not reach the harness at all so the request stays at `:default`.
  #
  # Amp declares neither option. Kimi and OpenCode reach their sessions over ACP, whose
  # transport declares neither — OpenCode's adapter accepts `approval_mode` for a run but
  # its session transport does not, which is why the lookup is per plane. Pi's RPC
  # transport declares both, and refuses only the `:prompt` approval value.
  #
  # Codex is the only provider left carrying the plane's `:prompt` default, because its
  # app-server transport is the only default one that can actually ask. The four managed
  # providers moved to `@interactive_prompt_refusals` below.
  @interactive_defaults %{
    amp: {:absent, :absent},
    codex: {:prompt, :workspace_write},
    kimi: {:absent, :absent},
    opencode: {:absent, :absent},
    pi: {:absent, :absent}
  }

  # provider => the transport whose missing approvals channel refuses the plane default.
  #
  # These four accept `approval_mode` at the adapter and declare no allowlist, so the
  # spec says `:prompt` is fine — and then the transport re-executes the CLI once per
  # turn with nobody to ask. `claude --print --permission-mode default` is never given a
  # `--permission-prompt-tool`, so every tool call needing permission is denied without a
  # word. Until the Claude bridge lands the session is refused instead of started.
  @interactive_prompt_refusals %{
    claude: :stream_json_resume,
    gemini: :stream_json_resume,
    grok: :streaming_json_resume,
    zai: :stream_json_resume
  }

  # provider => the capabilities its default session transport actually has, as the
  # public projection must declare them. Read from the specs Harness resolves, so a
  # provider that changes transports upstream fails here rather than in a session.
  @interactive_capabilities %{
    claude: %{transport: :stream_json_resume, approvals: false, steer: false, interrupt: :process},
    codex: %{transport: :app_server, approvals: :native, steer: false, interrupt: :native},
    opencode: %{transport: :acp, approvals: :native, steer: false, multimodal: :native},
    kimi: %{transport: :acp, approvals: :native, steer: false, multimodal: :native},
    pi: %{transport: :rpc, steer: :native, approvals: false, interrupt: :native}
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

    test "interactive Codex public state advertises approvals the exec fallback cannot" do
      assert {:ok, session} = State.new("capability-interactive-codex", provider: :codex)
      public = State.public(session)
      assert public.options.provider_execution.interactive_approvals
      assert public.options.provider_execution.escalation_behavior == :prompt

      # The exec fallback declares no approvals channel, so the plane's `:prompt` default
      # is refused there outright; a mode it can honour has to be stated to reach it.
      assert {:ok, exec} =
               State.new("capability-exec-codex",
                 provider: :codex,
                 transport: :exec_jsonl_resume,
                 approval_mode: :default
               )

      exec_public = State.public(exec)
      refute exec_public.options.provider_execution.interactive_approvals

      assert exec_public.options.provider_execution.escalation_behavior ==
               :deny_when_provider_cannot_prompt
    end
  end

  describe "declared session capabilities" do
    for {provider, expected} <- @interactive_capabilities do
      test "#{provider} declares #{inspect(expected)}" do
        capabilities = Provider.session_capabilities(unquote(provider))

        for {key, value} <- unquote(Macro.escape(expected)) do
          assert Map.fetch!(capabilities, key) == value,
                 "#{unquote(provider)} #{key}: expected #{inspect(value)}, " <>
                   "got #{inspect(Map.get(capabilities, key))}"
        end
      end
    end

    test "the ten declared keys are present for every bundled provider and Wire-safe" do
      expected =
        Enum.sort([
          :transport,
          :process,
          :multi_turn,
          :follow_up,
          :interrupt,
          :approvals,
          :steer,
          :multimodal,
          :dynamic_model,
          :dynamic_configuration
        ])

      for provider <- Map.keys(@coding_refusals) do
        capabilities = Provider.session_capabilities(provider)
        assert capabilities |> Map.keys() |> Enum.sort() == expected

        for {key, value} <- Map.delete(capabilities, :transport) do
          assert value in [:native, :managed, :process, :persistent, :per_turn, false],
                 "#{provider} #{key} is #{inspect(value)}"
        end

        # Nothing here needs an encoder that has to be taught a struct.
        assert Wire.to_json(capabilities) |> JSON.encode!() |> is_binary()
      end
    end

    test "the truth is the dialect's, not the declaration Ouroboros replaced" do
      # `upgrade_acp/1` repoints the upstream ACP transport at this runtime's adapter and
      # leaves the upstream `capabilities` in place, so the declaration describes code
      # that is no longer running. Reading through the adapter is what keeps the two from
      # drifting when a dialect gains a capability.
      assert Session.dialect(Ouroboros.Provider.Session.ACP) == Dialect.ACP
      assert Session.dialect(Ouroboros.Provider.CodexSession) == Dialect.Codex
      assert Session.dialect(Jido.Harness.SessionAdapters.Managed) == nil

      for {provider, dialect} <- [opencode: Dialect.ACP, kimi: Dialect.ACP, codex: Dialect.Codex] do
        declared = Map.from_struct(dialect.capabilities())
        resolved = Provider.session_capabilities(provider)

        for {key, value} <- resolved, key != :transport do
          assert Map.fetch!(declared, key) == value
        end
      end
    end

    test "a managed transport cannot change a setting its adapter does not normalize" do
      # Amp normalizes no `:model`, so a session on it has no model to switch even though
      # the managed transport template lists one. Claude normalizes both.
      assert Provider.session_capabilities(:amp).dynamic_model == false
      assert Provider.session_capabilities(:amp).dynamic_configuration == :managed
      assert Provider.session_capabilities(:claude).dynamic_model == :managed
    end

    test "an unresolvable provider or transport declares nothing rather than guessing" do
      assert Provider.session_capabilities(:no_such_provider) == nil
      assert Provider.session_capabilities(:amp, :no_such_transport) == nil
    end

    test "public session state carries the capabilities and survives re-projection" do
      assert {:ok, session} = State.new("capability-public-codex", provider: :codex)
      public = State.public(session)

      assert public.options.capabilities == Provider.session_capabilities(:codex)
      assert public.options.capabilities.approvals == :native
      assert State.public(public) == public
    end
  end

  describe "an approval mode nobody can answer" do
    for {provider, transport} <- @interactive_prompt_refusals do
      test "#{provider} refuses the plane default rather than starting a session that cannot ask" do
        assert {:error, {:unsupported_approval_mode, details}} =
                 State.new("capability-refusal", provider: unquote(provider))

        assert details.plane == :interactive
        assert details.provider == unquote(provider)
        assert details.transport == unquote(transport)
        assert details.requested == :prompt
        assert details.reason == :no_approval_channel

        # A refusal names what would work. `:prompt` is the one value excluded.
        assert details.supported == [:default, :auto_edit, :auto_approve]
        refute :prompt in details.supported
        assert details.message =~ inspect(unquote(provider))
        assert details.message =~ "no approvals channel"
        assert details.message =~ ":default meaning the provider's own behavior"
      end

      test "#{provider} refuses an explicitly stated :prompt the same way" do
        assert {:error, {:unsupported_approval_mode, details}} =
                 State.new("capability-refusal-stated",
                   provider: unquote(provider),
                   approval_mode: :prompt
                 )

        assert details.requested == :prompt
      end

      test "#{provider} starts once a mode the transport can honour is stated" do
        for mode <- [:default, :auto_edit, :auto_approve] do
          assert {:ok, session} =
                   State.new("capability-refusal-ok-#{mode}",
                     provider: unquote(provider),
                     approval_mode: mode
                   )

          assert Map.get(State.request(session), :approval_mode) == mode
        end
      end
    end

    test "transports that can ask are untouched" do
      for provider <- [:codex, :opencode, :kimi] do
        assert Provider.session_capabilities(provider).approvals == :native
        assert {:ok, _session} = State.new("capability-asks-#{provider}", provider: provider)
      end
    end

    test "pi and amp are untouched: their specs already exclude :prompt" do
      # Neither has an approvals channel, and neither is this refusal's business. Pi's
      # transport allowlist excludes `:prompt`, and Amp declares no `approval_mode` at
      # all, so the interactive plane omits the default exactly as it always did.
      assert Provider.session_capabilities(:pi).approvals == false
      assert Provider.session_capabilities(:amp).approvals == false

      for provider <- [:pi, :amp] do
        assert {:ok, session} = State.new("capability-omits-#{provider}", provider: provider)
        assert Map.get(State.request(session), :approval_mode, :absent) == :absent
      end

      # A stated value the transport's allowlist rejects still travels to the harness to
      # be refused by name; this clause does not intercept it.
      assert {:ok, _pi} =
               State.new("capability-pi-stated", provider: :pi, approval_mode: :prompt)
    end

    test "the coding plane is untouched" do
      # Claude's coding runs are non-interactive by construction and this refusal is
      # scoped to `{:interactive, transport}`; the coding plane keeps the behaviour its
      # own tests pin above.
      assert {:ok, task} = coding_task(provider: :claude)
      assert task.options.approval_mode == :prompt
    end

    test "an unresolvable provider is still left to the harness" do
      assert {:ok, _session} =
               State.new("capability-refusal-unknown", provider: :no_such_provider)
    end

    test "the recommended modes are the vocabulary Harness actually validates" do
      # The refusal recommends from a local list when a transport declares no allowlist.
      # If Harness grows a fifth normalized mode, this fails here rather than sending an
      # operator to a spelling the session request would reject.
      for mode <- [:default, :auto_edit, :auto_approve, :prompt] do
        assert {:ok, _request} =
                 Jido.Harness.SessionRequest.new(%{provider: :claude, approval_mode: mode})
      end

      assert {:error, _reason} =
               Jido.Harness.SessionRequest.new(%{provider: :claude, approval_mode: :invented})
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
      refute public.options.provider_execution.interactive_approvals

      assert public.options.provider_execution.escalation_behavior ==
               :deny_when_provider_cannot_prompt

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
