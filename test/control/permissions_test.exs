defmodule Ouroboros.Control.PermissionsTest.RefusingStorage do
  @moduledoc false

  # An ETS adapter whose writes fail on demand, so ack ordering can be watched from
  # outside: what the caller was told, and what the authority still believes afterwards.

  @flag :permissions_test_storage_fails

  def fail!, do: Application.put_env(:ouroboros, @flag, true)
  def heal!, do: Application.delete_env(:ouroboros, @flag)

  def get_checkpoint(key, opts), do: Jido.Storage.ETS.get_checkpoint(key, opts)

  def put_checkpoint(key, data, opts) do
    if Application.get_env(:ouroboros, @flag, false),
      do: {:error, :storage_offline},
      else: Jido.Storage.ETS.put_checkpoint(key, data, opts)
  end
end

defmodule Ouroboros.Control.PermissionsTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.PermissionsTest.RefusingStorage
  alias Ouroboros.Upgrade.{Artifact, Verifier}

  @secret_command "rm -rf /etc/very-secret-inventory-of-everything"

  setup do
    on_exit(fn ->
      RefusingStorage.heal!()
      Application.delete_env(:ouroboros, :permissions)
      Application.delete_env(:ouroboros, :permissions_ledger)
    end)

    :ok
  end

  test "the application supervises a bounded, inspectable engine" do
    assert is_pid(Process.whereis(Permissions))

    status = Permissions.status()
    assert status.durability == :ephemeral_checkpoint
    assert status.limit == 500
    assert is_map(status.by_scope)
    assert "**/.git/**" in status.protected_paths
  end

  test "the fast patch lane refuses to replace or introduce the engine itself" do
    {Permissions, binary, _filename} = :code.get_object_code(Permissions)

    for disposition <- [:replace, :introduce] do
      assert {:ok, artifact} =
               Artifact.build([{Permissions, binary, disposition: disposition}],
                 epoch: System.unique_integer([:positive, :monotonic])
               )

      assert {:error, {:immutable_control_module, Permissions}} =
               Verifier.verify(artifact, allow_unsigned: true)
    end

    # The pure submodules ride the same prefix, so the matcher cannot be swapped either.
    {Ouroboros.Control.Permissions.Matcher, matcher, _file} =
      :code.get_object_code(Ouroboros.Control.Permissions.Matcher)

    assert {:ok, artifact} =
             Artifact.build(
               [{Ouroboros.Control.Permissions.Matcher, matcher, disposition: :replace}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:error, {:immutable_control_module, Ouroboros.Control.Permissions.Matcher}} =
             Verifier.verify(artifact, allow_unsigned: true)
  end

  describe "rules" do
    test "adding, listing, and removing a rule is idempotent on a derived id" do
      engine = start_engine!()

      assert {:ok, rule} =
               Permissions.add(%{scope: :user, decision: :allow, pattern: "Bash(ls *)"}, engine)

      assert rule.pattern == "Bash(ls *)"
      assert rule.fragile == false

      assert {:ok, ^rule} =
               Permissions.add(%{scope: :user, decision: :allow, pattern: "Bash(ls *)"}, engine)

      assert {:ok, [listed]} = Permissions.list([scope: :user], engine)
      assert listed.id == rule.id

      assert :ok = Permissions.remove(:user, rule.id, engine)
      assert {:ok, []} = Permissions.list([scope: :user], engine)

      assert {:error, {:unknown_permission_rule, _id}} =
               Permissions.remove(:user, rule.id, engine)
    end

    test "node scope is operator configuration, not something a caller writes" do
      engine = start_engine!()

      assert {:error, :node_scope_is_operator_configuration} =
               Permissions.add(%{scope: :node, decision: :allow, pattern: "Bash(ls *)"}, engine)

      assert {:error, :node_scope_is_operator_configuration} =
               Permissions.remove(:node, "rule-x", engine)

      assert {:error, :node_scope_is_operator_configuration} =
               Permissions.remember(%{}, "Bash(ls *)", :allow, :node, engine)
    end

    test "node rules come from configuration and are listed beside the stored ones" do
      Application.put_env(:ouroboros, :permissions, [
        {"Bash(git status *)", :allow},
        {"Bash(rm *)", :deny},
        {"not a pattern at all", :allow}
      ])

      engine = start_engine!()

      assert {:ok, rules} = Permissions.list([scope: :node], engine)
      assert Enum.map(rules, & &1.pattern) == ["Bash(git status *)", "Bash(rm *)"]
      # The malformed entry is dropped rather than crashing the engine or being guessed at.
      assert Enum.all?(rules, &(&1.scope == :node))
    end

    test "a rule whose checkpoint fails is not applied and not reported as added" do
      engine = start_engine!()
      RefusingStorage.fail!()

      assert {:error, {:permission_checkpoint_failed, :storage_offline}} =
               Permissions.add(%{scope: :user, decision: :allow, pattern: "Bash(ls *)"}, engine)

      RefusingStorage.heal!()
      assert {:ok, []} = Permissions.list([scope: :user], engine)
    end

    test "the store is bounded, and the bound refuses rather than evicting" do
      engine = start_engine!(limit: 2)

      assert {:ok, _} =
               Permissions.add(%{scope: :user, decision: :deny, pattern: "Bash(a *)"}, engine)

      assert {:ok, _} =
               Permissions.add(%{scope: :user, decision: :deny, pattern: "Bash(b *)"}, engine)

      assert {:error, {:permission_rule_limit_reached, 2}} =
               Permissions.add(%{scope: :user, decision: :allow, pattern: "Bash(c *)"}, engine)

      assert {:ok, kept} = Permissions.list([], engine)
      assert length(kept) == 2
    end
  end

  describe "evaluate/1" do
    test "a stored allow rule answers without a human, and lands in the ledger" do
      engine = start_engine!()
      session = unique("allow")

      {:ok, _rule} =
        Permissions.remember(%{session_id: session}, "Bash(ls *)", :allow, :session, engine)

      assert {:allow, %{scope: :session, pattern: "Bash(ls *)", id: rule_id}} =
               Permissions.evaluate(
                 %{
                   principal: %{session_id: session, provider: :codex, node: node()},
                   tool: "bash",
                   command: "ls -la",
                   mode: :execute
                 },
                 engine
               )

      entry = ledger_entry!(session)
      assert entry.effect == :permission
      assert entry.status == :ok
      assert entry.result == %{decision: :approve, scope: :once, actor: :rule, rule_id: rule_id}
      assert entry.attempt.tool == "bash"
      assert entry.attempt.provider == :codex
    end

    test "a deny rule refuses and names itself, and lands in the ledger too" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(rm *)", :deny}])
      engine = start_engine!()
      session = unique("deny")

      assert {:deny, %{scope: :node, pattern: "Bash(rm *)"}} =
               Permissions.evaluate(
                 %{
                   principal: %{session_id: session},
                   tool: "bash",
                   command: @secret_command,
                   mode: :execute
                 },
                 engine
               )

      entry = ledger_entry!(session)
      assert entry.status == :denied
      assert entry.result.decision == :deny
    end

    test "the command line never enters the ledger, only its digest" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(rm *)", :deny}])
      engine = start_engine!()
      session = unique("minimised")

      Permissions.evaluate(
        %{
          principal: %{session_id: session},
          tool: "bash",
          command: @secret_command,
          mode: :execute
        },
        engine
      )

      entry = ledger_entry!(session)
      refute inspect(entry) =~ "very-secret-inventory"
      assert byte_size(entry.attempt.fingerprint.sha256) == 64
      assert entry.attempt.fingerprint.bytes == byte_size(@secret_command)
    end

    test "no rule is an ask, not a refusal" do
      engine = start_engine!()

      assert {:ask, :no_rule} =
               Permissions.evaluate(
                 %{tool: "bash", command: "cargo build", mode: :execute},
                 engine
               )
    end

    test "an unavailable authority asks for what a rule would have allowed" do
      engine = offline_engine()

      assert {:ask, :authority_unavailable} =
               Permissions.evaluate(%{tool: "bash", command: "ls", mode: :execute}, engine)
    end

    test "an unavailable authority asks even where node configuration allows" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(ls *)", :allow}])
      engine = offline_engine()

      # The store is the only thing that could have held a stricter rule, so an allow
      # nobody could check against it is not an allow.
      assert {:ask, :authority_unavailable} =
               Permissions.evaluate(%{tool: "bash", command: "ls -la", mode: :execute}, engine)
    end

    test "an unavailable authority still denies a protected write" do
      root = tmp_root("offline")
      on_exit(fn -> File.rm_rf(root) end)
      engine = offline_engine()

      assert {:deny, %{id: "protected-path"}} =
               Permissions.evaluate(
                 %{
                   tool: "write",
                   mode: :write,
                   paths: [".git/config"],
                   context: %{workspace: root}
                 },
                 engine
               )
    end

    test "an unavailable authority still honours an operator deny" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(rm *)", :deny}])
      engine = offline_engine()

      assert {:deny, %{scope: :node}} =
               Permissions.evaluate(%{tool: "bash", command: "rm -rf /", mode: :execute}, engine)
    end

    test "an allow that cannot be recorded becomes an ask" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(ls *)", :allow}])
      Application.put_env(:ouroboros, :permissions_ledger, :ledger_that_is_not_running)
      engine = start_engine!()

      assert {:ask, :unrecordable} =
               Permissions.evaluate(%{tool: "bash", command: "ls -la", mode: :execute}, engine)
    end

    test "a deny that cannot be recorded is still a deny" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(rm *)", :deny}])
      Application.put_env(:ouroboros, :permissions_ledger, :ledger_that_is_not_running)
      engine = start_engine!()

      assert {:deny, _ref} =
               Permissions.evaluate(%{tool: "bash", command: "rm -rf /", mode: :execute}, engine)
    end

    test "evaluate never raises, whatever it is handed" do
      engine = start_engine!()

      for garbage <- [nil, :atom, 42, "string", [], %{tool: 5, paths: :nope, mode: :sideways}] do
        assert {:ask, _reason} = Permissions.evaluate(garbage, engine)
      end
    end
  end

  describe "record/2 and remember/4" do
    test "a human answer is recorded against its own principal" do
      session = unique("human")

      assert :ok =
               Permissions.record("decision-#{session}", %{
                 decision: :approve,
                 scope: :session,
                 actor: :human,
                 rule_ref: nil,
                 reason: "looked fine",
                 principal: %{session_id: session, provider: :opencode}
               })

      assert {:ok, entry} = EffectLedger.get("decision-#{session}")
      assert entry.effect == :permission
      assert entry.principal == session
      assert entry.result == %{decision: :approve, scope: :session, actor: :human, rule_id: nil}
      assert entry.authority.decision == :approve
    end

    test "record refuses a malformed call rather than writing a shapeless entry" do
      assert {:error, :invalid_permission_record} = Permissions.record("", %{decision: :approve})
      assert {:error, :invalid_permission_record} = Permissions.record("id", :approve)
    end

    test "remember turns one session answer into a rule that decides the next one" do
      engine = start_engine!()
      session = unique("remember")

      request = %{
        principal: %{session_id: session},
        tool: "bash",
        command: "cargo test",
        mode: :execute
      }

      assert {:ask, :no_rule} = Permissions.evaluate(request, engine)

      assert {:ok, rule} =
               Permissions.remember(
                 %{session_id: session},
                 "Bash(cargo *)",
                 :allow,
                 :session,
                 engine
               )

      assert rule.scope == :session
      assert rule.session_id == session
      assert {:allow, %{id: id}} = Permissions.evaluate(request, engine)
      assert id == rule.id

      # ...and another session is unaffected by it.
      assert {:ask, :no_rule} =
               Permissions.evaluate(
                 %{request | principal: %{session_id: unique("other")}},
                 engine
               )
    end

    test "session rules die with the session" do
      engine = start_engine!()
      session = unique("forget")

      {:ok, _rule} =
        Permissions.remember(%{session_id: session}, "Bash(cargo *)", :allow, :session, engine)

      assert :ok = Permissions.forget_session(session, engine)
      assert {:ok, []} = Permissions.list([scope: :session], engine)
    end

    test "remember refuses a scope whose key the principal does not carry" do
      engine = start_engine!()

      assert {:error, :session_rule_requires_session} =
               Permissions.remember(%{}, "Bash(ls *)", :allow, :session, engine)

      assert {:error, :workspace_rule_requires_workspace} =
               Permissions.remember(%{}, "Bash(ls *)", :allow, :workspace, engine)
    end
  end

  describe "suggest/1" do
    test "suggests the rule that would stop the next identical question" do
      assert Permissions.suggest(%{tool: "bash", command: "cargo test --all", mode: :execute}) ==
               "Bash(cargo test *)"

      assert Permissions.suggest(%{tool: "bash", command: "ls -la", mode: :execute}) ==
               "Bash(ls *)"

      assert Permissions.suggest(%{tool: "bash", command: "/usr/bin/git push", mode: :execute}) ==
               "Bash(git push *)"

      assert Permissions.suggest(%{
               tool: "web_fetch",
               mode: :network,
               domains: ["api.example.com"]
             }) ==
               "WebFetch(domain:api.example.com)"

      assert Permissions.suggest(%{tool: "websearch", mode: :network}) == "Tool(websearch)"
      assert Permissions.suggest(%{}) == nil
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────────────

  defp start_engine!(opts \\ []) do
    name = :"permissions_#{System.unique_integer([:positive])}"

    opts =
      Keyword.merge(
        [
          name: name,
          storage:
            {RefusingStorage, table: :"permissions_test_#{System.unique_integer([:positive])}"}
        ],
        opts
      )

    start_supervised!({Permissions, opts}, id: name)
    name
  end

  # A name nothing is registered under: the authority is not running on this node.
  defp offline_engine, do: :"permissions_offline_#{System.unique_integer([:positive])}"

  defp ledger_entry!(session) do
    assert {:ok, [entry]} = EffectLedger.list(principal: session, effect: :permission)
    entry
  end

  defp unique(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"

  defp tmp_root(name) do
    path =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-permissions-#{name}-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(Path.join(path, ".git"))
    {:ok, canonical} = Ouroboros.Workspace.Path.canonicalize(path)
    canonical
  end
end
