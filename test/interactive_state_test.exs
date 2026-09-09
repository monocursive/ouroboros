defmodule Ouroboros.InteractiveStateTest do
  @moduledoc """
  The option envelope `Ouroboros.Interactive.State` validates before a session exists.

  Until the core reduction these rules lived in `Ouroboros.Coding.TaskState.new/4` and were
  asserted only through the coding plane's own suites. The seam is unchanged and the rules
  are unchanged; only the caller moved, so they are asserted here against `State.new/2`.

  Every one of them is a durable-checkpoint rule rather than a style preference. `env`,
  `env_mode` and `mcp_config` are credentials-adjacent and are refused by name so that a
  caller is told which rule it broke; `provider_options` is an adapter allow-list *and* a
  `Jido.Harness.Redaction` fixed-point check, so a value that redaction would change never
  reaches a checkpoint; the id is what every store write is keyed by.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Interactive.State

  setup do
    {:ok, base: [provider: :native, workspace: File.cwd!()]}
  end

  describe "the session id" do
    test "is refused blank, whitespace-only, or not a binary", %{base: base} do
      assert {:error, :invalid_session_id} = State.new("", base)
      assert {:error, :invalid_session_id} = State.new("   ", base)
      assert {:error, :invalid_session_id} = State.new(:not_a_binary, base)
      assert {:error, :invalid_session_id} = State.new(nil, base)
    end

    test "is what `loadable?/1` requires of the session it reads back", %{base: base} do
      assert {:ok, session} = State.new("interactive-state-id", base)
      assert State.loadable?(session)
      refute State.loadable?(%{session | id: ""})
    end
  end

  describe "options that must never reach a durable checkpoint" do
    test "an option this plane does not accept is refused by name", %{base: base} do
      assert {:error, {:unknown_option, :surprise}} =
               State.new("interactive-state-unknown", base ++ [surprise: true])
    end

    test "an inline environment is refused, in either spelling", %{base: base} do
      assert {:error, :inline_environment_not_persisted} =
               State.new("interactive-state-env", base ++ [env: %{"TOKEN" => "shh"}])

      assert {:error, :inline_environment_not_persisted} =
               State.new("interactive-state-env-mode", base ++ [env_mode: nil])
    end

    test "an inline MCP configuration is refused", %{base: base} do
      assert {:error, :inline_mcp_config_not_persisted} =
               State.new("interactive-state-mcp", base ++ [mcp_config: %{}])
    end

    test "provider options are refused unless every key is durable by name", %{base: base} do
      # Not in `@durable_provider_options` at all: arbitrary argv is the shape this
      # allow-list exists to keep out.
      assert {:error, {:unsafe_provider_options, :native}} =
               State.new(
                 "interactive-state-argv",
                 base ++ [provider_options: %{arbitrary_argv: ["--dangerous"]}]
               )

      # Durable in general, but not something this adapter accepts.
      assert {:error, {:unsafe_provider_options, :native}} =
               State.new(
                 "interactive-state-betas",
                 base ++ [provider_options: %{betas: ["computer-use"]}]
               )
    end

    test "provider options are refused unless redaction leaves every value alone", %{
      base: base
    } do
      # `:plan` is durable and the native adapter accepts it, so only the fixed-point
      # check can refuse these two. It is the half a name-only allow-list would miss.
      assert {:error, {:unsafe_provider_options, :native}} =
               State.new(
                 "interactive-state-bearer",
                 base ++ [provider_options: %{plan: "Bearer sk-live-1234"}]
               )

      assert {:error, {:unsafe_provider_options, :native}} =
               State.new(
                 "interactive-state-nested",
                 base ++ [provider_options: %{plan: %{api_key: "sk-live-1234"}}]
               )

      assert {:ok, _session} =
               State.new(
                 "interactive-state-clean",
                 base ++ [provider_options: %{max_iterations: 7}]
               )
    end
  end

  describe "bounds the envelope states" do
    test "the event limit is a positive integer inside the ceiling", %{base: base} do
      assert {:error, :invalid_event_limit} =
               State.new("interactive-state-limit-zero", base ++ [event_limit: 0])

      assert {:error, :invalid_event_limit} =
               State.new("interactive-state-limit-big", base ++ [event_limit: 100_001])

      assert {:error, :invalid_event_limit} =
               State.new("interactive-state-limit-text", base ++ [event_limit: "10"])

      assert {:ok, %State{event_limit: 100_000}} =
               State.new("interactive-state-limit-max", base ++ [event_limit: 100_000])
    end

    test "runtime exposure is a boolean", %{base: base} do
      assert {:error, :invalid_runtime_exposure} =
               State.new("interactive-state-exposure", base ++ [runtime_exposure: :maybe])

      assert {:ok, _session} =
               State.new("interactive-state-exposure-off", base ++ [runtime_exposure: false])
    end

    test "a removed provider is refused with the migration in the reason", %{base: base} do
      assert {:error, {:provider_removed, :codex, message}} =
               State.new("interactive-state-codex", Keyword.put(base, :provider, :codex))

      assert message =~ "provider :native"
    end
  end

  describe "the workspace posture" do
    test "defaults from the sandbox mode and refuses a mode outside the vocabulary", %{
      base: base
    } do
      assert {:ok, %State{workspace_mode: :exclusive}} =
               State.new("interactive-state-write-default", base)

      assert {:ok, %State{workspace_mode: :shared_read}} =
               State.new(
                 "interactive-state-read-default",
                 base ++ [sandbox_mode: :read_only]
               )

      assert {:ok, %State{workspace_mode: :exclusive}} =
               State.new(
                 "interactive-state-write-stated",
                 base ++ [sandbox_mode: :workspace_write]
               )

      # `:write` is not a workspace mode. A lease vocabulary this validator does not know
      # is refused rather than passed to the manager to interpret.
      assert {:error, {:invalid_workspace_mode, :write}} =
               State.new("interactive-state-bad-mode", base ++ [workspace_mode: :write])
    end
  end
end
