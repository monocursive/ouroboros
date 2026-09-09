# Writes the core-reduction integration fixture: a data directory produced by this
# (pre-reduction) build, holding every durable shape the reduction retires.
#
#     OUROBOROS_DATA_DIR=/abs/path OUROBOROS_FLEET_ID=<24 hex> \
#       mix run --no-start scripts/fixture/build_fixture.exs
#
# `--no-start` because the storage adapters have to be pointed at the data directory
# before the supervision tree reads them: `config/runtime.exs` only rewrites them in
# `:prod`, and this script reproduces exactly the leaves that block names, so the bytes
# on disk are the ones a production node would have written.
#
# Everything below goes through the store module's own public write API. Where a writer
# needed a plane that cannot run here (a build peer, a model, a team), the shape that
# writer produces is reproduced through the store's API and the deviation is printed in
# the provenance log this script emits, which MANIFEST.md quotes.

alias Ouroboros.Agent.EffectLedger
alias Ouroboros.Agent.Effects.Runner
alias Ouroboros.Control.Grants
alias Ouroboros.Control.Permissions
alias Ouroboros.Interactive.Store, as: InteractiveStore
alias Ouroboros.Interactive.State, as: InteractiveState

data_dir = Application.get_env(:ouroboros, :data_dir)

unless is_binary(data_dir) and data_dir != "" do
  raise "OUROBOROS_DATA_DIR must be set to an absolute path before running this script"
end

fleet_id = System.get_env("OUROBOROS_FLEET_ID")

unless is_binary(fleet_id) and Regex.match?(~r/\A[0-9a-f]{24}\z/, fleet_id) do
  raise "OUROBOROS_FLEET_ID must be 24 lower-case hex characters"
end

provenance = :ets.new(:fixture_provenance, [:ordered_set, :public])
counter = :counters.new(1, [])

note = fn item, api, how ->
  :counters.add(counter, 1, 1)
  :ets.insert(provenance, {:counters.get(counter, 1), item, api, how})
  IO.puts("  [#{how}] #{item} <- #{api}")
end

# ---------------------------------------------------------------- 0. configuration

leaf = fn name -> Path.join(data_dir, name) end
durable = fn name -> {Ouroboros.Storage.DurableFile, path: leaf.(name)} end

# The same eleven leaves `config/runtime.exs`'s production block names, verbatim.
Application.put_env(:ouroboros, :coding_storage, durable.("coding"))
Application.put_env(:ouroboros, :interactive_storage, durable.("interactive"))
Application.put_env(:ouroboros, :team_storage, durable.("teams"))
Application.put_env(:ouroboros, :orchestration_storage, durable.("orchestration"))
Application.put_env(:ouroboros, :control_storage, durable.("control"))
Application.put_env(:ouroboros, :grants_storage, durable.("grants"))
Application.put_env(:ouroboros, :policy_promotion_storage, durable.("policy-promotion"))
Application.put_env(:ouroboros, :permissions_storage, durable.("permissions"))
Application.put_env(:ouroboros, :effect_ledger_storage, durable.("effect-ledger"))
Application.put_env(:ouroboros, :upgrade_storage, durable.("upgrades"))
Application.put_env(:ouroboros, :release_storage, durable.("release-journal"))
Application.put_env(:ouroboros, :capability_storage, durable.("capabilities"))
Application.put_env(:ouroboros, :epoch_storage, durable.("forge-epochs"))
Application.put_env(:ouroboros, :signing_journal_storage, durable.("signing-journal"))

# Audit is node configuration; `mode: :local` is the lowest setting that writes anything.
# A small segment bound so a handful of records roll more than one segment.
Application.put_env(:ouroboros, :audit,
  mode: :local,
  capture: :metadata,
  root: leaf.("audit"),
  index: true,
  segment_bytes: 4_096,
  organization: "ouroboros-core-fixture",
  writer_id: "core-fixture"
)

# Outside the data directory on purpose: `Ouroboros.Audit.admit_scope/1` refuses a
# workspace that overlaps a protected root, and the data directory is one. They are
# siblings so a reader of the tarball can recreate them beside the extracted directory.
#
# One directory per session, because `Workspace.Manager` rebuilds a lease per non-terminal
# session at boot and refuses to start when two of them claim overlapping roots
# exclusively (`workspace/manager.ex:400`). A node with four live sessions has four
# worktrees, so this is the shape a real data directory has rather than a workaround.
workspaces_root =
  System.get_env("FIXTURE_WORKSPACES_ROOT") ||
    Path.join(Path.dirname(data_dir), "fixture-workspaces")

File.rm_rf!(workspaces_root)
File.mkdir_p!(workspaces_root)
workspace = Path.join(workspaces_root, "main")
File.mkdir_p!(workspace)

session_workspace = fn name ->
  path = Path.join(workspaces_root, name)
  File.mkdir_p!(path)
  path
end

Application.put_env(:ouroboros, :workspace_allowed_roots, [workspaces_root])

# The cluster monitor reads the fleet profile at init and again on every session-owner
# write, so it has to exist before the tree starts. This file is JSON written by
# `ouro fleet` in production; it is hand-written here because that writer is a Rust
# binary and a fleet enrollment, not an Elixir store API. It carries no Erlang term and
# therefore no atom.
machine = "fixture"
host = "fixture.invalid"
owner_node = "ouro-#{machine}@#{host}"
fleet_root = leaf.("fleet")
File.mkdir_p!(fleet_root)

File.write!(
  Path.join(fleet_root, "profile.json"),
  Jason.encode!(%{
    "schema" => 1,
    "fleet_id" => fleet_id,
    "name" => "core fixture",
    "machine" => machine,
    "host" => host,
    "node" => owner_node,
    "role" => "core",
    "roster_revision" => 1,
    "members" => [%{"machine" => machine, "host" => host, "node" => owner_node}],
    "tombstones" => [],
    "tags" => []
  })
)

IO.puts("data dir: #{data_dir}")
IO.puts("starting :ouroboros ...")
{:ok, _started} = Application.ensure_all_started(:ouroboros)
IO.puts("started.")

# The two resume loops are stopped, not configured away: a recovery tick would reopen the
# sessions this script writes and rewrite their checkpoints as `:failed` mid-run, which
# would make the fixture depend on a race. Nothing else about either store changes.
Enum.each(
  [
    {Ouroboros.Interactive.Supervisor, Ouroboros.Interactive.Recovery},
    {Ouroboros.Coding.Supervisor, Ouroboros.Coding.Recovery}
  ],
  fn {supervisor, child} ->
    _ = Supervisor.terminate_child(supervisor, child)
  end
)

# ---------------------------------------------------------------- 1. permissions

IO.puts("\n1. permissions")

rules = [
  {%{}, "ComputerUse(app:com.apple.Calculator)", :allow, :user},
  {%{}, "ComputerUse(app:*)", :deny, :user},
  {%{}, "ComputerUse(observe)", :allow, :user},
  {%{}, "ComputerUse(act)", :deny, :user},
  {%{}, "Bash(ls *)", :allow, :user},
  {%{}, "Bash(rm -rf /)", :deny, :user},
  {%{}, "Capability(echo)", :allow, :user},
  {%{}, "Capability(*)", :ask, :user},
  {%{}, "Forge(counter)", :deny, :user},
  {%{}, "Forge(*)", :ask, :user},
  {%{}, "WebFetch(domain:github.com)", :allow, :user},
  {%{}, "Tool(desktop_act)", :deny, :user},
  {%{}, "Tool(code_intel)", :deny, :user},
  {%{}, "Tool(capability)", :ask, :user},
  {%{}, "Tool(bash:timeout=1000)", :deny, :user},
  {%{}, "Read(**/*.ex)", :allow, :user},
  {%{}, "Edit(lib/**)", :ask, :user},
  {%{}, "Write(/tmp/**)", :allow, :user},
  {%{}, "mcp__linear__*", :ask, :user},
  {%{}, "mcp__linear__create_issue", :deny, :user},
  {%{workspace: workspace}, "Bash(git status *)", :allow, :workspace},
  {%{session_id: "fixture-session-native"}, "ComputerUse(act)", :allow, :session}
]

# `remember/5` is the "don't ask again" path a session answer takes and it accepts only
# `:allow` and `:deny`; an `:ask` rule is an operator writing one, which is the gateway's
# `permissions.add`. Both are real writers into the same checkpoint.
added =
  Enum.reduce(rules, 0, fn {principal, pattern, decision, scope}, acc ->
    result =
      if decision in [:allow, :deny] do
        Permissions.remember(principal, pattern, decision, scope)
      else
        Permissions.add(%{
          scope: scope,
          decision: decision,
          pattern: pattern,
          workspace: Map.get(principal, :workspace),
          session_id: Map.get(principal, :session_id)
        })
      end

    case result do
      {:ok, _rule} ->
        acc + 1

      {:error, reason} ->
        IO.puts("  !! #{pattern} (#{scope}): #{inspect(reason)}")
        acc
    end
  end)

note.(
  "permissions (#{added} rules, every pattern kind)",
  "Ouroboros.Control.Permissions.remember/4",
  "real writer"
)

# ---------------------------------------------------------------- 2. grants

IO.puts("\n2. grants")

# The runtime-minted capability atom the C3 review reproduced: a name no source line in
# any build spells, interned here by the writing VM exactly as `Upgrade.NodeExecutor`
# interned it from a receipt's BEAM bytes on a live node.
capability_atom = String.to_atom("Elixir.Ouroboros.Capability.FixtureProbe")
worker_atom = String.to_atom("Elixir.Ouroboros.Agent.Worker")
coordinator_atom = String.to_atom("Elixir.Ouroboros.Agent.Coordinator")

principal = "agent-fixture"

grant_specs = [
  # Both spellings a `:forge` allow-list can hold, held by two principals on purpose.
  # `Runner.authority/1` copies the grant's whole `constraints` map into every ledger
  # entry that grant authorizes, and `EffectLedger.sanitize_authority/1` passes it through
  # verbatim — so a runtime-minted capability atom in an allow-list the fixture *exercises*
  # would land in the effect ledger as well, which is read before anything interns it and
  # so would stop the boot on `dev` too. The atom therefore sits in a grant nothing in
  # this fixture dispatches against, which is what an operator's unexercised grant is.
  {principal, :forge, [modules: ["wasm/counter"]]},
  {"agent-fixture-capability", :forge, [modules: [capability_atom]]},
  {principal, :delegate, [teams: ["team-fixture"]]},
  {principal, :start_agent, [modules: [worker_atom, coordinator_atom]]},
  {"agent-fixture-wasm", :forge, [modules: ["wasm/*"]]},
  {principal, :deploy, [nodes: [node()]]},
  {principal, :send_message, [agents: :any]},
  {principal, :stop_agent, [agents: ["agent-fixture-child"]]}
]

Enum.each(grant_specs, fn {who, effect, constraints} ->
  case Grants.grant(who, effect, constraints) do
    {:ok, _grant} -> :ok
    {:error, reason} -> IO.puts("  !! grant #{who}/#{effect}: #{inspect(reason)}")
  end
end)

note.(
  "grants (#{length(grant_specs)}: forge/capability atom, forge/wasm string, delegate, start_agent)",
  "Ouroboros.Control.Grants.grant/4",
  "real writer"
)

# ---------------------------------------------------------------- 3. effect ledger

IO.puts("\n3. effect ledger")

# Two shapes are opt-in because they make the directory unbootable on `dev` as well as on
# the reduced tree, for a reason that is not the reduction's: `Ouroboros.Team.Server` and
# a runtime-minted `Ouroboros.Capability.<Name>` are never loaded when
# `Agent.EffectLedger.init/1` decodes its checkpoint, so `[:safe]` refuses the whole file.
# See MANIFEST.md, "What this fixture found about `dev` itself".
unloadable_atoms? = System.get_env("FIXTURE_UNLOADABLE_ATOMS") == "1"

agent_state = %{last_effects: [], effects_in_flight: [], forged: [], __partition__: nil}

context = fn signal_id ->
  %{
    agent: %{id: principal, state: agent_state},
    signal: %{id: signal_id, type: "ouroboros.fixture.effect"}
  }
end

effect_id_of = fn signal_id ->
  "effect-" <>
    (:crypto.hash(:sha256, :erlang.term_to_binary({principal, signal_id}))
     |> Base.url_encode64(padding: false))
end

await_settled = fn effect_id ->
  Enum.reduce_while(1..200, :timeout, fn _i, _acc ->
    case EffectLedger.get(effect_id) do
      {:ok, %{status: status}} when status in [:ok, :failed, :denied, :ambiguous] ->
        {:halt, status}

      _still_running ->
        Process.sleep(25)
        {:cont, :timeout}
    end
  end)
end

# 3a. A refusal written by the runner's own refuse path: `Grants.decision/4` says no,
# the runner builds `{:effect_denied, effect, {:not_granted, attempt}}` and records it.
{:error, denied_reply} =
  Runner.dispatch(
    :delegate,
    %{team: "team-nobody-granted"},
    fn _principal -> {:ok, %{}} end,
    %{from: "signal-claimed-origin"},
    context.("fixture-denied-1")
  )

note.(
  "ledger :denied `{:effect_denied, :delegate, {:not_granted, …}}` #{inspect(denied_reply) |> String.slice(0, 60)}",
  "Ouroboros.Agent.Effects.Runner.dispatch/5 (refuse path)",
  "real writer"
)

# 3b. The runner's guard vocabulary never reaches the ledger — `principal/2` and
# `effect_state/2` refuse before any write — so the three atoms they mint are put into
# the ledger through its own public API, in the shape the runner would have handed it.
Enum.each(
  [
    {:unidentified_principal, "fixture-denied-unidentified"},
    {:missing_effect_state, "fixture-denied-missing-effect-state"},
    {:missing_agent_state, "fixture-denied-missing-agent-state"}
  ],
  fn {reason, id} ->
    {:ok, _entry, _how} =
      EffectLedger.record_denied(%{
        id: id,
        effect: :delegate,
        principal: principal,
        claimed_from: "signal-claimed-origin",
        attempt: %{team: "team-fixture"},
        authority: %{decision: :denied, reason: :not_granted},
        cause: %{signal_id: id, signal_type: "ouroboros.fixture.effect"},
        error: {:effect_denied, :delegate, reason}
      })
  end
)

note.(
  "ledger :denied `{:effect_denied, :delegate, :unidentified_principal}` and the two sibling guards",
  "Ouroboros.Agent.EffectLedger.record_denied/1",
  "store API, runner shape (the runner refuses before it writes)"
)

# 3c. A settled `:start_agent` naming `Ouroboros.Agent.Worker` — `Mesh.start_agent/2`'s
# default `:agent` on this build — through the runner, so the attempt and result fields
# are the ones `@attempt_fields`/`@result_fields` take.
{:ok, _projection} =
  Runner.dispatch(
    :start_agent,
    %{module: worker_atom},
    fn _p ->
      {:ok, %{agent_id: "agent-fixture-child", module: worker_atom, node: node()}}
    end,
    %{from: nil},
    context.("fixture-start-agent-1")
  )

start_status = await_settled.(effect_id_of.("fixture-start-agent-1"))

note.(
  "ledger :start_agent settled #{inspect(start_status)}, attempt+result `module: Ouroboros.Agent.Worker`",
  "Ouroboros.Agent.Effects.Runner.dispatch/5 (accept path)",
  "real writer, stubbed work closure"
)

# 3d. A second `:start_agent`, naming the other module `Ouroboros.Mesh.start_agent/2`
# admitted under the `Elixir.Ouroboros.Agent.` prefix, so both C1-retired module atoms are
# in the ledger and not only in the grant.
{:ok, _projection} =
  Runner.dispatch(
    :start_agent,
    %{module: coordinator_atom},
    fn _p ->
      {:ok, %{agent_id: "agent-fixture-coordinator", module: coordinator_atom, node: node()}}
    end,
    %{from: nil},
    context.("fixture-start-agent-2")
  )

_ = await_settled.(effect_id_of.("fixture-start-agent-2"))

# 3e. A `:forge`, in the shape `Ouroboros.Agent.Effects.ForgeCapability.forge/2` returns.
# It is lane W deliberately: the `module` of a lane-B forge is a runtime-minted
# `Ouroboros.Capability.<Name>` atom, and an entry carrying one makes **this** build fail
# to boot, because `Agent.EffectLedger` is `application.ex` line 150 and the executor that
# interns those names from its receipts is line 166. See MANIFEST.md; the generator can
# write that entry with `FIXTURE_LEDGER_CAPABILITY_ATOM=1`, and the directory it produces
# does not boot on `dev` either. Lane W's identity is `"wasm/" <> name`, a binary, which is
# why the plan keeps it.
{:ok, _projection} =
  Runner.dispatch(
    :forge,
    %{module: "wasm/counter"},
    fn _p ->
      {:ok,
       %{
         artifact_id: "artifact-fixture-wasm",
         module: "wasm/counter",
         epoch: 2,
         signer: "fixture-signer",
         source_sha256: String.duplicate("a", 64),
         nodes: [node()]
       }}
    end,
    %{from: nil},
    context.("fixture-forge-1")
  )

forge_status = await_settled.(effect_id_of.("fixture-forge-1"))

note.(
  "ledger :forge settled #{inspect(forge_status)}, lane-W result `module: \"wasm/counter\"`; two :start_agent entries naming Ouroboros.Agent.Worker and .Coordinator",
  "Ouroboros.Agent.Effects.Runner.dispatch/5 (accept path)",
  "real writer, stubbed work closure (no build peer here)"
)

if unloadable_atoms? do
  {:ok, _projection} =
    Runner.dispatch(
      :forge,
      %{module: capability_atom},
      fn _p ->
        {:ok,
         %{
           artifact_id: "artifact-fixture-capability",
           module: capability_atom,
           epoch: 3,
           signer: "fixture-signer",
           source_sha256: String.duplicate("a", 64),
           nodes: [node()]
         }}
      end,
      %{from: nil},
      context.("fixture-forge-lane-b")
    )

  _ = await_settled.(effect_id_of.("fixture-forge-lane-b"))

  note.(
    "ledger :forge with a runtime-minted `Ouroboros.Capability.FixtureProbe` result module",
    "Ouroboros.Agent.Effects.Runner.dispatch/5 (accept path)",
    "real writer; opt-in, because the directory it produces does not boot on `dev` either"
  )
end

# 3f. A settled `:delegate`, and the runner's failure vocabulary, produced for real by
# letting the bounded closure fail, crash and time out.
{:ok, _} =
  Runner.dispatch(
    :delegate,
    %{team: "team-fixture"},
    fn _p ->
      {:ok,
       %{
         team: "team-fixture",
         worker_id: "#{node()}:session:fixture-session-delegating",
         delegation_id: "delegation-fixture-0001",
         status: :completed,
         delivery: :delivered,
         result: %{summary: "fixture"}
       }}
    end,
    %{from: nil},
    context.("fixture-delegate-ok")
  )

_ = await_settled.(effect_id_of.("fixture-delegate-ok"))

{:ok, _} =
  Runner.dispatch(
    :delegate,
    %{team: "team-fixture"},
    fn _p -> {:error, if(unloadable_atoms?, do: :team_unavailable, else: :timeout)} end,
    %{from: nil},
    context.("fixture-delegate-failed")
  )

_ = await_settled.(effect_id_of.("fixture-delegate-failed"))

{:ok, _} =
  Runner.dispatch(
    :delegate,
    %{team: "team-fixture"},
    fn _p -> raise "fixture crash" end,
    %{from: nil},
    context.("fixture-delegate-crashed")
  )

_ = await_settled.(effect_id_of.("fixture-delegate-crashed"))

previous_timeout = Application.get_env(:ouroboros, :effect_timeout)
Application.put_env(:ouroboros, :effect_timeout, 60)

{:ok, _} =
  Runner.dispatch(
    :delegate,
    %{team: "team-fixture"},
    fn _p ->
      Process.sleep(2_000)
      {:ok, %{}}
    end,
    %{from: nil},
    context.("fixture-delegate-timeout")
  )

_ = await_settled.(effect_id_of.("fixture-delegate-timeout"))

if previous_timeout,
  do: Application.put_env(:ouroboros, :effect_timeout, previous_timeout),
  else: Application.delete_env(:ouroboros, :effect_timeout)

note.(
  "ledger :delegate settled ok / :effect_failed / :effect_crashed / :effect_timeout",
  "Ouroboros.Agent.Effects.Runner.dispatch/5 (settle path)",
  "real writer"
)

# 3g. One `desktop_act` `:tool_call`, in the shape `Provider.Native.Loop`'s own
# `tool_effect/…` builds — the classifier is the loop's, so `app`, `desktop_action` and
# `window_id` are the values the real path would have put in `subject`.
desktop_input = %{
  "app" => "com.apple.Calculator",
  "action" => "click",
  "window_id" => "window-42",
  "x" => 10,
  "y" => 20
}

classified = Ouroboros.Provider.Native.Tools.classify("desktop_act", desktop_input, %{})
desktop_context = Map.get(classified, :context, %{})

tool_call_id = "fixture-tool-call-desktop-act"

{:ok, _entry, _how} =
  EffectLedger.record_started(%{
    id: tool_call_id,
    effect: :tool_call,
    principal: "fixture-session-native",
    attempt: %{
      session_id: "fixture-session-native",
      turn_id: "turn-1",
      call_id: "call-1",
      tool: classified.tool,
      provider: :native,
      subject: %{
        app: desktop_context[:app],
        desktop_action: desktop_context[:desktop_action],
        window_id: desktop_context[:window_id]
      },
      node: node(),
      permission_entry_id: "fixture-permission-entry-1"
    },
    authority: %{decision: :allow, reason: :rule, constraints: %{scope: :session}},
    cause: %{signal_type: "native.tool_call", signal_id: tool_call_id}
  })

{:ok, _entry, _how} =
  EffectLedger.settle(tool_call_id, %{
    status: :ok,
    result: %{status: :completed, duration_ms: 12, output_bytes: 128}
  })

note.(
  "ledger :tool_call `desktop_act` with subject app/desktop_action/window_id",
  "Ouroboros.Provider.Native.Tools.classify/3 + Ouroboros.Agent.EffectLedger.record_started/1",
  "store API, native-loop shape (the loop needs a live model)"
)

# 3h. Two `:permission` decisions written by the permission engine itself — one denied by
# the `ComputerUse(act)` rule above, one allowed by `Bash(ls *)` — plus the `:approval`
# entry `Interactive.Task.Approvals.record_approval/7` writes, and one `code_intel` tool
# call, so a deleted tool name is in the file too.

desktop_request = %{
  tool: "desktop_act",
  mode: :act,
  principal: %{session_id: "fixture-session-native", provider: :native, node: node()},
  context: Map.put(desktop_context, :workspace, workspace)
}

bash_request = %{
  tool: "bash",
  command: "ls -la",
  mode: :execute,
  principal: %{session_id: "fixture-session-native", provider: :native, node: node()},
  context: %{workspace: workspace, cwd: workspace}
}

IO.puts("  desktop_act evaluates to #{inspect(Permissions.evaluate(desktop_request))}")
IO.puts("  bash evaluates to #{inspect(Permissions.evaluate(bash_request))}")

# One human answer, which writes the `:permission` entry and the policy-evidence row in
# one call — the seam S2 records the decision corpus from.
permission_record =
  Permissions.record("fixture-session-native:approval-1", %{
    decision: :allow,
    scope: :session,
    actor: :human,
    reason: :human,
    request: bash_request
  })

IO.puts("  human answer recorded: #{inspect(permission_record)}")

note.(
  "ledger :permission (rule deny on `desktop_act`, rule allow on `bash`, one human answer)",
  "Ouroboros.Control.Permissions.evaluate/2 and record/2",
  "real writer"
)

# `Approvals.record_approval/7`'s exact shape: a `\"session:\" <> id` principal, a string
# `reason` and a string `origin`, and the subject the desktop classifier produced.
{:ok, _entry, _how} =
  EffectLedger.record_settled(%{
    id: "fixture-session-native:approval-1:approval",
    effect: :approval,
    principal: "session:fixture-session-native",
    attempt: %{
      session_id: "fixture-session-native",
      request_id: "approval-1",
      tool: "desktop_state",
      provider: :native,
      subject: %{app: "com.apple.Finder", desktop_action: "state", window_id: "window-7"},
      node: node()
    },
    authority: %{
      decision: :allow,
      reason: "human",
      constraints: %{scope: :once, actor: :human, origin: "provider"}
    },
    cause: %{signal_type: "interactive.respond_approval", signal_id: "approval-1"},
    result: %{decision: :allow, scope: :once, actor: :human, origin: "provider"}
  })

{:ok, _entry, _how} =
  EffectLedger.record_settled(%{
    id: "fixture-tool-call-code-intel",
    effect: :tool_call,
    principal: "fixture-session-native",
    attempt: %{
      session_id: "fixture-session-native",
      turn_id: "turn-2",
      call_id: "call-2",
      tool: "code_intel",
      provider: :native,
      subject: %{paths: [Path.join(workspace, "lib/example.ex")]},
      node: node()
    },
    authority: %{decision: :allow, reason: :rule},
    cause: %{signal_type: "native.tool_call", signal_id: "fixture-tool-call-code-intel"},
    result: %{status: :completed, duration_ms: 3, output_bytes: 42}
  })

note.(
  "ledger :approval (desktop subject) and :tool_call `code_intel`",
  "Ouroboros.Agent.EffectLedger.record_settled/1",
  "store API, `Interactive.Task.Approvals.record_approval/7` and native-loop shapes"
)

# ---------------------------------------------------------------- 4. interactive

IO.puts("\n4. interactive sessions")

{:ok, native_session} =
  InteractiveState.new("fixture-session-native",
    provider: :native,
    workspace: session_workspace.("native"),
    sandbox_mode: :workspace_write,
    model: "anthropic:claude-sonnet-4-5"
  )

turn_request = Jido.Harness.TurnRequest.new!("fixture turn")
turn = InteractiveState.new_turn("turn-1", :message, turn_request)

subagent_payload =
  Ouroboros.Provider.Native.Tools.Agent.spawned_payload(
    %{
      task_id: "subagent-fixture-1",
      description: "fixture child",
      tools: ["bash", "read"],
      background: false,
      depth: 1,
      deadline_ms: 600_000,
      node: node(),
      request_attrs: %{
        cwd: session_workspace.("native"),
        provider_options: %{"max_iterations" => 12},
        provider_session_id: "provider-session-child"
      }
    },
    %{
      provider_session_id: "provider-session-child",
      workspace: session_workspace.("native"),
      worktree: nil,
      node: node()
    }
  )
  |> Map.put("kind", "subagent")

native_session =
  native_session
  |> Map.put(:status, :idle)
  |> Map.put(:harness_session_id, "harness-fixture-native")
  |> Map.put(:provider_session_id, "provider-session-fixture")
  |> Map.put(:turns, %{"turn-1" => %{turn | status: :completed, harness_turn_id: "h-1"}})
  |> Map.put(:cursor, 1)
  |> Map.put(:sequence_offset, 1)
  |> Ouroboros.Interactive.Task.append_event(
    Ouroboros.Interactive.Event.from_runtime(
      "fixture-session-native",
      1,
      :provider_event,
      subagent_payload,
      provider: :native,
      harness_session_id: "harness-fixture-native",
      provider_session_id: "provider-session-fixture"
    )
  )
  |> InteractiveState.touch()

:ok = InteractiveStore.create(native_session)

note.(
  "interactive: native session with one turn and one `kind: \"subagent\"` provider_event",
  "Interactive.State.new/2 + Tools.Agent.spawned_payload/2 + Interactive.Store.create/1",
  "store API, real payload builder"
)

# A delegating session: the delegation record exactly as `Interactive.Task`'s private
# `record_delegation/2` writes it, and the `/delegate` transcript event its
# `append_delegation_event/3` emits.
{:ok, delegating} =
  InteractiveState.new("fixture-session-delegating",
    provider: :native,
    workspace: session_workspace.("delegating")
  )

now_iso = DateTime.utc_now() |> DateTime.to_iso8601()

delegation = %{
  id: "delegation-fixture-0001",
  team_id: "team-fixture",
  task_id: "task-fixture-0001",
  task_node: node(),
  objective_digest:
    :sha256
    |> :crypto.hash("fixture objective")
    |> Base.encode16(case: :lower)
    |> binary_slice(0, 32),
  status: :started,
  result_digest: nil,
  created_at: now_iso,
  updated_at: now_iso
}

{:ok, delegating} = InteractiveState.put_delegation(delegating, delegation)

delegation_event =
  Ouroboros.Interactive.Event.from_runtime(
    "fixture-session-delegating",
    1,
    :delegation,
    %{
      "delegation_id" => delegation.id,
      "team_id" => delegation.team_id,
      "task_id" => delegation.task_id,
      "task_node" => Atom.to_string(delegation.task_node),
      "objective_digest" => delegation.objective_digest,
      "status" => "started"
    },
    provider: :native,
    harness_session_id: nil,
    provider_session_id: nil
  )

delegating =
  delegating
  |> Map.put(:status, :idle)
  |> Map.put(:cursor, 1)
  |> Map.put(:sequence_offset, 1)
  |> Ouroboros.Interactive.Task.append_event(delegation_event)
  |> InteractiveState.touch()

:ok = InteractiveStore.create(delegating)

note.(
  "interactive: delegating session, `delegations` record + `:delegation` transcript event",
  "Interactive.State.put_delegation/2 + Interactive.Event.from_runtime/5 + Store.create/1",
  "store API, `Interactive.Task.record_delegation/2` shape (its writer needs a live team)"
)

claude_result =
  InteractiveState.new("fixture-session-claude",
    provider: :claude,
    workspace: session_workspace.("claude")
  )

case claude_result do
  {:ok, claude_session} ->
    claude_session = claude_session |> Map.put(:status, :idle) |> InteractiveState.touch()
    :ok = InteractiveStore.create(claude_session)

    note.(
      "interactive: session with `provider: :claude`",
      "Interactive.State.new/2 + Interactive.Store.create/1",
      "store API (`InteractiveSession.start/1` needs the vendor CLI)"
    )

  {:error, reason} ->
    IO.puts("  !! claude session refused: #{inspect(reason)}")
end

read_only_result =
  InteractiveState.new("fixture-session-read-only",
    provider: :native,
    workspace: session_workspace.("read-only"),
    sandbox_mode: :read_only
  )

case read_only_result do
  {:ok, ro} ->
    ro = ro |> Map.put(:status, :idle) |> InteractiveState.touch()
    :ok = InteractiveStore.create(ro)

    note.(
      "interactive: session with `sandbox_mode: :read_only`",
      "Interactive.State.new/2 + Interactive.Store.create/1",
      "store API"
    )

  {:error, reason} ->
    IO.puts("  !! read_only session refused: #{inspect(reason)}")
end

# ---------------------------------------------------------------- 5. deleted planes

IO.puts("\n5. coding tasks, teams, plans, control runs")

coding_result =
  Ouroboros.Coding.TaskState.new("fixture-coding-task", "fixture objective",
    provider: :native,
    workspace: session_workspace.("coding")
  )

case coding_result do
  {:ok, task} ->
    :ok = Ouroboros.Coding.Store.create(task)
    note.("coding task", "Ouroboros.Coding.TaskState.new/4 + Coding.Store.create/1", "store API")

  {:error, reason} ->
    IO.puts("  !! coding task refused: #{inspect(reason)}")
end

team_snapshot = Ouroboros.Team.Snapshot.new("team-fixture", "agent-fixture-coordinator", true)
:ok = Ouroboros.Team.Store.create(team_snapshot)
note.("team snapshot", "Ouroboros.Team.Snapshot.new/3 + Team.Store.create/1", "store API")

plan_result =
  Ouroboros.Orchestration.Plan.new(
    "fixture-plan",
    [
      %{id: "step-code", kind: :coding, input: %{objective: "fixture step"}},
      %{
        id: "step-forge",
        kind: :forge,
        dependencies: ["step-code"],
        input: %{
          module: "Ouroboros.Capability.FixtureProbe",
          source_path: "priv/fixture/probe.ex"
        }
      }
    ],
    metadata: %{"origin" => "core-fixture"}
  )

case plan_result do
  {:ok, plan} ->
    :ok = Ouroboros.Orchestration.Store.create(plan)

    note.(
      "orchestration plan (:coding + :forge steps)",
      "Orchestration.Plan.new/3 + Orchestration.Store.create/1",
      "store API"
    )

  {:error, reason} ->
    IO.puts("  !! plan refused: #{inspect(reason)}")
end

case Ouroboros.Control.Run.new("fixture-control-run", "fixture control objective", 2) do
  {:ok, run} ->
    :ok = Ouroboros.Control.Store.create(run)
    note.("control run", "Ouroboros.Control.Run.new/3 + Control.Store.create/1", "store API")

  {:error, reason} ->
    IO.puts("  !! control run refused: #{inspect(reason)}")
end

# ---------------------------------------------------------------- 6. cluster

IO.puts("\n6. cluster session-owner checkpoint")

interactive_owners =
  Ouroboros.Cluster.record_session_snapshot(:interactive, [
    {String.to_atom(owner_node), ["fixture-session-native"]}
  ])

coding_owners =
  Ouroboros.Cluster.record_session_snapshot(:coding, [
    {String.to_atom(owner_node), ["fixture-coding-task"]}
  ])

IO.puts("  interactive: #{inspect(interactive_owners)}  coding: #{inspect(coding_owners)}")

note.(
  "cluster session-owner checkpoint, both `interactive` and `coding` keys",
  "Ouroboros.Cluster.record_session_snapshot/2",
  "real writer (needs a fleet profile, which is hand-written JSON)"
)

# ---------------------------------------------------------------- 7. signing journal

IO.puts("\n7. signing journal")

key_path =
  Path.join(
    System.tmp_dir!(),
    "ouroboros-fixture-signer-#{System.unique_integer([:positive])}.key"
  )

File.write!(key_path, :crypto.strong_rand_bytes(32))
File.chmod!(key_path, 0o600)

signing_started =
  Ouroboros.Upgrade.Signing.Service.start_link(
    name: :fixture_signing_service,
    key_path: key_path,
    signer_id: "fixture-signer",
    storage: durable.("signing-journal")
  )

case signing_started do
  {:ok, _pid} ->
    beam_bytes = Ouroboros.DataDir |> :code.which() |> File.read!()

    {:ok, beam_artifact} =
      Ouroboros.Upgrade.Artifact.build([{Ouroboros.DataDir, beam_bytes, []}],
        id: "artifact-fixture-beam",
        epoch: 1,
        metadata: %{forge: %{author: principal}}
      )

    wasm_bytes = <<0, 97, 115, 109, 0x0D, 0x00, 0x01, 0x00>> <> :crypto.strong_rand_bytes(64)

    {:ok, wasm_artifact} =
      Ouroboros.Wasm.Artifact.build(wasm_bytes,
        id: "artifact-fixture-wasm",
        epoch: 2,
        name: "counter",
        imports: [],
        author: principal
      )

    beam_decision =
      Ouroboros.Upgrade.Signing.Service.sign_artifact(
        beam_artifact,
        "fixture-signer",
        %{requester: node()},
        :fixture_signing_service
      )

    wasm_decision =
      Ouroboros.Upgrade.Signing.Service.sign_artifact(
        wasm_artifact,
        "fixture-signer",
        %{requester: node(), component_bytes: wasm_bytes},
        :fixture_signing_service
      )

    IO.puts("  beam: #{inspect(beam_decision) |> String.slice(0, 90)}")
    IO.puts("  wasm: #{inspect(wasm_decision) |> String.slice(0, 90)}")

    note.(
      "signing journal: one `lane: :beam` and one `lane: :wasm` decision",
      "Ouroboros.Upgrade.Signing.Service.sign_artifact/4 with a throwaway key",
      "real writer (both decisions are policy refusals; the journal shape is identical)"
    )

  {:error, reason} ->
    IO.puts("  !! signing service refused to start: #{inspect(reason)}")
end

File.rm(key_path)

# ---------------------------------------------------------------- 8. rollout registry

IO.puts("\n8. rollout registry")

case Ouroboros.Upgrade.Rollout.Registry.deploying(%{
       artifact_id: "artifact-fixture-beam",
       module: capability_atom,
       epoch: 1,
       nodes: [node()],
       source_sha256: String.duplicate("a", 64)
     }) do
  {:ok, _entry} ->
    _ = Ouroboros.Upgrade.Rollout.Registry.mark("artifact-fixture-beam", :live, detail: :fixture)

    note.(
      "rollout registry: lane-B record naming the runtime-minted module",
      "Upgrade.Rollout.Registry.deploying/2 + mark/4",
      "real writer"
    )

  {:error, reason} ->
    IO.puts("  !! lane-B rollout refused: #{inspect(reason)}")
end

case Ouroboros.Upgrade.Rollout.Registry.deploying(%{
       artifact_id: "artifact-fixture-wasm",
       module: "wasm/counter",
       epoch: 2,
       nodes: [node()],
       component_sha256: String.duplicate("c", 64),
       kind: :capability
     }) do
  {:ok, _entry} ->
    _ =
      Ouroboros.Upgrade.Rollout.Registry.mark("artifact-fixture-wasm", :live,
        detail: :fixture,
        describe: {:ok, %{"name" => "counter"}}
      )

    note.(
      "rollout registry: lane-W record",
      "Upgrade.Rollout.Registry.deploying/2 + mark/4",
      "real writer"
    )

  {:error, reason} ->
    IO.puts("  !! lane-W rollout refused: #{inspect(reason)}")
end

# ---------------------------------------------------------------- 9. policy

IO.puts("\n9. policy promotion and policy evidence")

promotion =
  Ouroboros.Control.PolicyPromotion.promote(
    "fixture-policy",
    String.duplicate("d", 64),
    "bash",
    "Bash(mix test *)",
    %{
      decisions: 120,
      contradictions: 0,
      distinct_fingerprints: 41,
      distinct_sessions: 7,
      would_resolve: 33,
      report_sha256: String.duplicate("e", 64)
    },
    "fixture-operator"
  )

case promotion do
  {:ok, _record} ->
    note.("policy promotion record", "Ouroboros.Control.PolicyPromotion.promote/7", "real writer")

  {:error, reason} ->
    IO.puts("  !! promotion refused: #{inspect(reason)}")
end

# The corpus row is written by `Permissions.record/2` in section 3g, which is the one
# seam that has both the full request and a human's answer in scope.
IO.puts("  policy evidence rows: #{Ouroboros.Control.PolicyEvidence.count() |> inspect()}")

note.(
  "policy evidence row",
  "Ouroboros.Control.Permissions.record/2 -> Control.PolicyEvidence.write/3",
  "real writer"
)

# ---------------------------------------------------------------- 10. audit

IO.puts("\n10. audit segments")

stream = Ouroboros.Audit.Store.stream_id(workspace)

appended =
  Enum.reduce(1..40, 0, fn i, acc ->
    case Ouroboros.Audit.Store.append(stream, "tool_invocation", %{
           "tool" => Enum.at(["bash", "desktop_act", "code_intel", "capability"], rem(i, 4)),
           "session_id" => "fixture-session-native",
           "sequence" => i,
           "detail" => String.duplicate("x", 200)
         }) do
      {:ok, _record} ->
        acc + 1

      {:error, reason} ->
        IO.puts("  !! audit append #{i}: #{inspect(reason)}")
        acc
    end
  end)

note.(
  "audit: #{appended} records across several segments",
  "Ouroboros.Audit.Store.append/4",
  "real writer"
)

# ---------------------------------------------------------------- 11. workspace

IO.puts("\n11. workspace mirrors and returns")

# A real repository, so both planes are exercised through their own writers rather than
# described. Neither keeps a term-encoded checkpoint: a mirror is a bare git repository
# and a return is a bundle plus a receipt, so neither can hold a retired atom.
git = fn args -> System.cmd("git", args, cd: workspace, stderr_to_stdout: true) end
{_, 0} = git.(["init", "--quiet", "--initial-branch", "main", "."])
{_, 0} = git.(["config", "user.email", "fixture@ouroboros.invalid"])
{_, 0} = git.(["config", "user.name", "core fixture"])
File.write!(Path.join(workspace, "README.md"), "core reduction fixture workspace\n")
{_, 0} = git.(["add", "README.md"])
{_, 0} = git.(["commit", "--quiet", "-m", "fixture"])
{head, 0} = git.(["rev-parse", "HEAD"])
head = String.trim(head)

bundle_path =
  Path.join(System.tmp_dir!(), "ouroboros-fixture-#{System.unique_integer([:positive])}.bundle")

{_, 0} = git.(["bundle", "create", bundle_path, "HEAD", "main"])

repo_id = :sha256 |> :crypto.hash("core-fixture-repository") |> Base.encode16(case: :lower)

{:ok, bundle_metadata} =
  Ouroboros.Workspace.Bundle.metadata(bundle_path, head, "task-fixture-0001")

mirror_outcome =
  with {:ok, token} <- Ouroboros.Workspace.Mirrors.begin_import(repo_id, bundle_metadata, node()),
       bytes = File.read!(bundle_path),
       :ok <- Ouroboros.Workspace.Mirrors.put_chunk(token, 0, bytes) do
    Ouroboros.Workspace.Mirrors.finish_import(token, head)
  end

IO.puts("  mirror import: #{inspect(mirror_outcome) |> String.slice(0, 120)}")
File.rm(bundle_path)

return_outcome =
  with {:ok, snapshot} <- Ouroboros.Workspace.Snapshot.commit(workspace, "task-fixture-0001") do
    Ouroboros.Workspace.Returns.register(snapshot)
  end

IO.puts("  return registration: #{inspect(return_outcome) |> String.slice(0, 120)}")

mirrors_root = leaf.("mirrors")
returns_root = leaf.("returns")

IO.puts(
  "  mirrors dir: #{File.exists?(mirrors_root)}   returns dir: #{File.exists?(returns_root)}"
)

note.(
  "workspace mirrors (#{File.exists?(mirrors_root)}) and returns (#{File.exists?(returns_root)}) roots",
  "Ouroboros.Workspace.Mirrors.begin_import/4 + finish_import/3, Workspace.Returns.register/2",
  "real writer; neither keeps a term-encoded checkpoint"
)

# ---------------------------------------------------------------- 12. forge epoch, executor

IO.puts("\n12. forge epoch watermark and the BEAM executor journal")

case Ouroboros.Upgrade.Epoch.next([node()]) do
  {:ok, epoch} ->
    note.(
      "forge epoch watermark (epoch #{epoch})",
      "Ouroboros.Upgrade.Epoch.next/2",
      "real writer"
    )

  {:error, reason} ->
    IO.puts("  !! epoch: #{inspect(reason)}")
end

# The strongest reproduction of the hazard the C3 review found: a real BEAM module in the
# capability namespace, compiled here, introduced through the fast patch lane. The
# executor's journal then holds the receipt whose bytes used to intern
# `Ouroboros.Capability.FixtureProbe` at boot, before `Control.Grants` read its checkpoint.
capability_source = """
defmodule Ouroboros.Capability.FixtureProbe do
  @moduledoc false
  def call(_input), do: {:ok, :fixture}
end
"""

executor_outcome =
  try do
    [{compiled_module, compiled_binary} | _] = Code.compile_string(capability_source)

    # `Code.compile_string/1` loads what it compiles, and an `:introduce` disposition is
    # refused for a module this VM already holds. Purging leaves the atom interned — atoms
    # are never collected — which is exactly the state a node is in before the executor
    # applies a receipt it has never seen.
    _ = :code.purge(compiled_module)
    _ = :code.delete(compiled_module)
    _ = :code.purge(compiled_module)

    with {:ok, artifact} <-
           Ouroboros.Upgrade.Artifact.build(
             [{compiled_module, compiled_binary, [disposition: :introduce]}],
             id: "artifact-fixture-capability",
             epoch: 3,
             metadata: %{forge: %{author: principal}}
           ),
         {:ok, token} <- Ouroboros.Upgrade.NodeExecutor.prepare(artifact) do
      Ouroboros.Upgrade.NodeExecutor.commit(token)
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

IO.puts("  executor: #{inspect(executor_outcome) |> String.slice(0, 200)}")

case executor_outcome do
  {:ok, _receipt} ->
    note.(
      "BEAM executor journal: an :introduce receipt for a runtime-compiled `Ouroboros.Capability.FixtureProbe`",
      "Ouroboros.Upgrade.NodeExecutor.prepare/2 + commit/2",
      "real writer"
    )

  other ->
    IO.puts("  !! executor journal not written: #{inspect(other) |> String.slice(0, 160)}")
end

# ---------------------------------------------------------------- provenance

IO.puts("\nprovenance:")

lines =
  provenance
  |> :ets.tab2list()
  |> Enum.sort()
  |> Enum.map(fn {n, item, api, how} -> "#{n}\t#{item}\t#{api}\t#{how}" end)

File.write!(Path.join(data_dir, ".fixture-provenance.tsv"), Enum.join(lines, "\n") <> "\n")

IO.puts("\nwrote #{length(lines)} provenance rows")
IO.puts("stopping application to flush ...")
:ok = Application.stop(:ouroboros)
IO.puts("done.")
