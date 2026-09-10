# Run only against the pre-J2 compiled build, before deleting its dependency:
# elixir -pa '_build/dev/lib/*/ebin' scripts/fixture/build_j2_fixture.exs
# Synthetic records use the baseline structs and DurableFile's actual checkpoint format.
# There is deliberately no model, tool, workspace admission, or real credential involved.
alias Ouroboros.Interactive.{State, Event}
alias Ouroboros.Storage.DurableFile

root = Path.expand("test/support/j2_fixture/data")
if File.exists?(root), do: raise("refusing to replace a captured baseline")
File.mkdir_p!(root)
stamp = "2026-09-10T00:00:00Z"
store_key = {:ouroboros, :interactive_sessions, 1}
opts = [path: Path.join(root, "interactive")]

request = Jido.Harness.SessionRequest.new!(provider: :native, cwd: File.cwd!())
turn_request = Jido.Harness.TurnRequest.new!("Synthetic baseline turn")
approval = Jido.Harness.ApprovalResponse.new!(decision: :deny)

legacy_error =
  Jido.Harness.Error.validation("synthetic legacy refusal", details: %{key: :retention})

records =
  Enum.map(
    [
      :idle,
      :running,
      :queued,
      :awaiting_approval,
      :terminal,
      :resumed,
      :forked,
      :removed_provider
    ],
    fn kind ->
      id = "j2-fixture-#{kind}"
      runtime = "legacy-runtime-#{kind}"
      conversation = "native-conversation-#{kind}"
      provider = if kind == :removed_provider, do: :claude, else: :native

      status =
        case kind do
          :queued -> :running
          :terminal -> :closed
          :resumed -> :idle
          :forked -> :idle
          :removed_provider -> :idle
          other -> other
        end

      offset = if kind == :resumed, do: 40, else: 0

      legacy_event =
        Jido.Harness.Event.new!(
          type: :session_started,
          provider: provider,
          session_id: runtime,
          provider_session_id: conversation,
          sequence: 1,
          timestamp: stamp,
          payload: %{"cwd" => File.cwd!()}
        )

      event =
        struct(Event,
          id: "#{id}-event-#{offset + 1}",
          session_id: id,
          sequence: offset + 1,
          type: :provider_event,
          timestamp: stamp,
          harness_session_id: runtime,
          provider: provider,
          provider_session_id: conversation,
          payload: %{
            "synthetic" => true,
            "legacy" => %{request: request, event: legacy_event, approval: approval}
          }
        )

      turn_id = "#{id}-turn"

      turn = %{
        id: turn_id,
        mode: :message,
        fingerprint: "synthetic-fingerprint-#{kind}",
        request: turn_request,
        status: if(kind == :terminal, do: :completed, else: :running),
        created_at: stamp,
        updated_at: stamp,
        harness_turn_id: "legacy-turn-#{kind}"
      }

      turns =
        if kind in [:running, :queued, :awaiting_approval, :terminal],
          do: %{turn_id => turn},
          else: %{}

      turns =
        if kind == :queued do
          Map.put(turns, "#{turn_id}-queued", %{
            turn
            | id: "#{turn_id}-queued",
              status: :queued,
              mode: :follow_up,
              harness_turn_id: "legacy-queued-#{kind}"
          })
        else
          turns
        end

      usage = %{
        input_tokens: 7,
        output_tokens: 3,
        cache_read_tokens: 0,
        cache_creation_tokens: 0,
        total_tokens: 10,
        cost_usd: 0.001,
        turns_with_usage: 1,
        context_window: 8192,
        context_used: 10,
        last: %{turn_id: turn_id, input_tokens: 7, output_tokens: 3, total_tokens: 10}
      }

      state =
        struct(State,
          id: id,
          node: :nonode@nohost,
          provider: provider,
          workspace: "/synthetic/j2/#{kind}",
          workspace_mode: :shared_read,
          status: status,
          created_at: stamp,
          updated_at: stamp,
          harness_session_id: runtime,
          provider_session_id: conversation,
          cursor: offset + 1,
          sequence_offset: offset,
          resumes: if(kind == :resumed, do: 1, else: 0),
          forked_from: if(kind == :forked, do: "j2-fixture-idle", else: nil),
          turns: turns,
          events: [event],
          usage: usage,
          options: %{runtime_exposure: false},
          error: if(kind == :terminal, do: {:legacy_refusal, legacy_error}, else: nil)
        )

      unless State.loadable?(state), do: raise("baseline record invalid: #{kind}")
      :ok = DurableFile.put_checkpoint({store_key, :session, 2, id}, %{id => state}, opts)
      {id, state}
    end
  )

:ok =
  DurableFile.put_checkpoint(store_key, %{version: 2, ids: Enum.map(records, &elem(&1, 0))}, opts)

entry =
  struct(Ouroboros.Agent.EffectLedger.Entry,
    sequence: 2,
    started_sequence: 1,
    id: "j2-fixture-ledger-error",
    effect: :tool_call,
    principal: "j2-fixture-idle",
    attempt: %{provider: :native, session_id: "j2-fixture-idle", tool: "read"},
    authority: %{},
    cause: %{},
    status: :failed,
    started_at: stamp,
    settled_at: stamp,
    origin_node: :nonode@nohost,
    error: %{classification: {:session_start_failed, legacy_error}, fingerprint: "synthetic"}
  )

:ok =
  DurableFile.put_checkpoint(
    Ouroboros.Agent.EffectLedger.checkpoint_key(),
    %{version: 3, entries: [entry], next_sequence: 3}, path: Path.join(root, "effect-ledger"))

IO.puts("Captured #{length(records)} baseline sessions and one ledger error at #{root}")
