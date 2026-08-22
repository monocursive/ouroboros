defmodule Ouroboros.Control.GrantsTest.FlakyStorage do
  @moduledoc false

  # An ordinary ETS adapter whose writes can be made to fail on demand, so the ack
  # ordering can be observed from outside: what the caller was told, and what the
  # authority still believes afterwards.

  @flag :grants_test_storage_fails

  def fail!, do: Application.put_env(:ouroboros, @flag, true)
  def heal!, do: Application.delete_env(:ouroboros, @flag)

  def get_checkpoint(key, opts), do: Jido.Storage.ETS.get_checkpoint(key, opts)

  def put_checkpoint(key, data, opts) do
    if Application.get_env(:ouroboros, @flag, false) do
      {:error, :storage_offline}
    else
      Jido.Storage.ETS.put_checkpoint(key, data, opts)
    end
  end
end

defmodule Ouroboros.Control.GrantsTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Control.Grants
  alias Ouroboros.Control.Grants.Grant
  alias Ouroboros.Control.GrantsTest.FlakyStorage
  alias Ouroboros.Upgrade.{Artifact, Verifier}

  setup do
    on_exit(&FlakyStorage.heal!/0)
    :ok
  end

  test "the authority is supervised by the application and starts empty" do
    assert is_pid(Process.whereis(Grants))
    assert Grants.durability() == :ephemeral_checkpoint
    assert Grants.list("nobody-in-particular") == []
  end

  describe "deny by default" do
    test "a principal with no entry is refused every effect" do
      grants = start_grants!()

      for effect <- Grants.effects() do
        refute Grants.granted?("stranger", effect, %{module: Kernel}, grants)
        refute Grants.granted?("stranger", effect, %{agent: "a"}, grants)
        refute Grants.granted?("stranger", effect, %{team: "t"}, grants)
        refute Grants.granted?("stranger", effect, %{nodes: [node()]}, grants)
      end
    end

    test "a grant for one effect authorizes nothing else" do
      grants = start_grants!()
      assert {:ok, _grant} = Grants.grant("agent", :start_agent, [modules: :any], grants)

      assert Grants.granted?("agent", :start_agent, %{module: Ouroboros.Agent.Worker}, grants)
      refute Grants.granted?("agent", :forge, %{module: Ouroboros.Agent.Worker}, grants)
      refute Grants.granted?("agent", :send_message, %{agent: "other"}, grants)
    end

    test "inspectable decisions identify the exact grant snapshot or denial reason" do
      grants = start_grants!()

      assert %{granted?: false, grant: nil, reason: :not_granted} =
               Grants.decision("agent", :start_agent, %{module: Ouroboros.Agent.Worker}, grants)

      assert {:ok, grant} =
               Grants.grant(
                 "agent",
                 :start_agent,
                 [modules: [Ouroboros.Agent.Worker]],
                 grants
               )

      assert %{granted?: true, grant: ^grant, reason: :granted} =
               Grants.decision("agent", :start_agent, %{module: Ouroboros.Agent.Worker}, grants)

      assert %{granted?: false, grant: ^grant, reason: :outside_constraints} =
               Grants.decision("agent", :start_agent, %{module: Kernel}, grants)

      stop_supervised!(grants)

      assert %{granted?: false, grant: nil, reason: :authority_unavailable} =
               Grants.decision("agent", :start_agent, %{module: Ouroboros.Agent.Worker}, grants)
    end

    test "a grant belongs to exactly one principal" do
      grants = start_grants!()
      assert {:ok, _grant} = Grants.grant("privileged", :forge, [modules: :any], grants)

      refute Grants.granted?("bystander", :forge, %{module: Ouroboros.Capability.X}, grants)
    end

    test "an attempt that does not name what the allow-list reads is refused" do
      grants = start_grants!()
      assert {:ok, _grant} = Grants.grant("agent", :start_agent, [modules: :any], grants)

      # `:any` is "any module", not "any attempt". An attempt with no module named is
      # not a permitted one.
      refute Grants.granted?("agent", :start_agent, %{}, grants)
      refute Grants.granted?("agent", :start_agent, %{agent: "worker-1"}, grants)
    end

    test "a malformed question is refused rather than raised" do
      grants = start_grants!()
      assert {:ok, _grant} = Grants.grant("agent", :start_agent, [modules: :any], grants)

      refute Grants.granted?("agent", :start_agent, :not_a_map, grants)
      refute Grants.granted?(:not_a_principal, :start_agent, %{module: Kernel}, grants)
      refute Grants.granted?("agent", "start_agent", %{module: Kernel}, grants)
    end

    test "an authority that is not running authorizes nothing" do
      grants = start_grants!()
      assert {:ok, _grant} = Grants.grant("agent", :forge, [modules: :any], grants)
      assert Grants.granted?("agent", :forge, %{module: Ouroboros.Capability.X}, grants)

      stop_supervised!(grants)

      refute Grants.granted?("agent", :forge, %{module: Ouroboros.Capability.X}, grants)
      assert Grants.list("agent", grants) == []
      assert {:error, {:grants_unavailable, _reason}} = Grants.revoke("agent", :forge, grants)
    end
  end

  describe "constraints" do
    test "a module list admits only the modules it names" do
      grants = start_grants!()

      assert {:ok, grant} =
               Grants.grant(
                 "agent",
                 :start_agent,
                 [modules: [Ouroboros.Agent.Worker, Ouroboros.Capability.Echo]],
                 grants
               )

      assert %Grant{effect: :start_agent, constraints: %{modules: modules}} = grant
      assert modules == [Ouroboros.Agent.Worker, Ouroboros.Capability.Echo]

      assert Grants.granted?("agent", :start_agent, %{module: Ouroboros.Agent.Worker}, grants)
      assert Grants.granted?("agent", :start_agent, %{module: Ouroboros.Capability.Echo}, grants)

      refute Grants.granted?(
               "agent",
               :start_agent,
               %{module: Ouroboros.Agent.Coordinator},
               grants
             )

      refute Grants.granted?("agent", :start_agent, %{module: Kernel}, grants)
    end

    test "a team list admits only the teams it names" do
      grants = start_grants!()
      assert {:ok, _grant} = Grants.grant("agent", :delegate, %{teams: ["review-team"]}, grants)

      assert Grants.granted?("agent", :delegate, %{team: "review-team"}, grants)
      refute Grants.granted?("agent", :delegate, %{team: "payroll-team"}, grants)
    end

    test "an agent list admits only the agents it names" do
      grants = start_grants!()
      assert {:ok, _grant} = Grants.grant("agent", :send_message, [agents: ["peer"]], grants)
      assert {:ok, _grant} = Grants.grant("agent", :stop_agent, [agents: []], grants)

      assert Grants.granted?("agent", :send_message, %{agent: "peer"}, grants)
      refute Grants.granted?("agent", :send_message, %{agent: "stranger"}, grants)

      # An empty allow-list is a grant that admits nothing, not a grant that admits
      # everything.
      refute Grants.granted?("agent", :stop_agent, %{agent: "peer"}, grants)
    end

    test "a node list admits only a target set it fully covers" do
      grants = start_grants!()
      allowed = [:a@host, :b@host]
      assert {:ok, _grant} = Grants.grant("agent", :deploy, [nodes: allowed], grants)

      assert Grants.granted?("agent", :deploy, %{nodes: [:a@host]}, grants)
      assert Grants.granted?("agent", :deploy, %{nodes: allowed}, grants)

      # One node outside the list refuses the whole deployment: a rollout is a single
      # transition, not a per-node decision.
      refute Grants.granted?("agent", :deploy, %{nodes: [:a@host, :c@host]}, grants)
      refute Grants.granted?("agent", :deploy, %{nodes: []}, grants)
    end

    test "the constraint an effect is checked against is the only one it accepts" do
      grants = start_grants!()

      assert {:error, {:missing_constraint, :start_agent, :modules}} =
               Grants.grant("agent", :start_agent, [], grants)

      assert {:error, {:unknown_constraints, [:teams]}} =
               Grants.grant("agent", :start_agent, [modules: :any, teams: ["t"]], grants)

      assert {:error, {:invalid_constraint, :modules, "Kernel"}} =
               Grants.grant("agent", :start_agent, [modules: "Kernel"], grants)

      assert {:error, {:invalid_constraint, :teams, [:atom_team]}} =
               Grants.grant("agent", :delegate, [teams: [:atom_team]], grants)

      assert {:error, {:unknown_effect, :read_everything}} =
               Grants.grant("agent", :read_everything, [modules: :any], grants)

      assert {:error, {:invalid_principal, ""}} =
               Grants.grant("", :start_agent, [modules: :any], grants)

      assert Grants.list("agent", grants) == []
    end

    test "re-granting replaces the allow-list instead of widening it" do
      grants = start_grants!()
      assert {:ok, _grant} = Grants.grant("agent", :start_agent, [modules: :any], grants)
      assert Grants.granted?("agent", :start_agent, %{module: Kernel}, grants)

      assert {:ok, _grant} =
               Grants.grant("agent", :start_agent, [modules: [Ouroboros.Agent.Worker]], grants)

      refute Grants.granted?("agent", :start_agent, %{module: Kernel}, grants)
      assert Grants.granted?("agent", :start_agent, %{module: Ouroboros.Agent.Worker}, grants)
      assert [%Grant{effect: :start_agent}] = Grants.list("agent", grants)
    end
  end

  test "grant and revoke round-trip, and list reports what is held" do
    grants = start_grants!()

    assert {:ok, _grant} = Grants.grant("agent", :forge, [modules: :any], grants)
    assert {:ok, _grant} = Grants.grant("agent", :deploy, [nodes: [node()]], grants)

    assert [%Grant{effect: :deploy}, %Grant{effect: :forge}] = Grants.list("agent", grants)

    assert :ok = Grants.revoke("agent", :forge, grants)
    refute Grants.granted?("agent", :forge, %{module: Ouroboros.Capability.X}, grants)
    assert Grants.granted?("agent", :deploy, %{nodes: [node()]}, grants)
    assert [%Grant{effect: :deploy}] = Grants.list("agent", grants)

    # Revoking what is not held is not an error, and does not invent one.
    assert :ok = Grants.revoke("agent", :forge, grants)
    assert :ok = Grants.revoke("stranger", :deploy, grants)
    assert [%Grant{effect: :deploy}] = Grants.list("agent", grants)
  end

  test "grants survive a restart of the authority" do
    table = unique_table()
    storage = {Jido.Storage.ETS, table: table}
    grants = start_grants!(storage)

    assert {:ok, _grant} =
             Grants.grant("agent", :start_agent, [modules: [Ouroboros.Agent.Worker]], grants)

    assert {:ok, _grant} = Grants.grant("agent", :deploy, [nodes: [node()]], grants)
    assert :ok = Grants.revoke("agent", :deploy, grants)

    stop_supervised!(grants)
    restarted = start_grants!(storage)

    assert Grants.granted?("agent", :start_agent, %{module: Ouroboros.Agent.Worker}, restarted)
    refute Grants.granted?("agent", :start_agent, %{module: Kernel}, restarted)

    # The revocation is durable too. A restart that resurrected it would be the same
    # failure as never having written it.
    refute Grants.granted?("agent", :deploy, %{nodes: [node()]}, restarted)
    assert [%Grant{effect: :start_agent}] = Grants.list("agent", restarted)
  end

  describe "storage faults" do
    test "a grant whose checkpoint fails is refused and never takes effect" do
      grants = start_grants!({FlakyStorage, table: unique_table()})
      FlakyStorage.fail!()

      assert {:error, {:grant_checkpoint_failed, :storage_offline}} =
               Grants.grant("agent", :forge, [modules: :any], grants)

      refute Grants.granted?("agent", :forge, %{module: Ouroboros.Capability.X}, grants)
      assert Grants.list("agent", grants) == []

      FlakyStorage.heal!()
      assert {:ok, _grant} = Grants.grant("agent", :forge, [modules: :any], grants)
      assert Grants.granted?("agent", :forge, %{module: Ouroboros.Capability.X}, grants)
    end

    test "a revocation whose checkpoint fails leaves the grant standing and says so" do
      grants = start_grants!({FlakyStorage, table: unique_table()})
      assert {:ok, _grant} = Grants.grant("agent", :forge, [modules: :any], grants)

      FlakyStorage.fail!()

      assert {:error, {:grant_checkpoint_failed, :storage_offline}} =
               Grants.revoke("agent", :forge, grants)

      # The uncomfortable direction, on purpose: an authority that forgot a grant it
      # could not durably forget would hand it back on the next restart.
      assert Grants.granted?("agent", :forge, %{module: Ouroboros.Capability.X}, grants)

      FlakyStorage.heal!()
      assert :ok = Grants.revoke("agent", :forge, grants)
      refute Grants.granted?("agent", :forge, %{module: Ouroboros.Capability.X}, grants)
    end

    test "a checkpoint this build cannot interpret stops the authority instead of emptying it" do
      table = unique_table()
      storage = {Jido.Storage.ETS, table: table}
      :ok = Jido.Storage.ETS.put_checkpoint(Grants.checkpoint_key(), %{version: 99}, table: table)

      assert {:error, {{:unsupported_grant_checkpoint, 99}, _spec}} =
               start_supervised({Grants, name: unique_name(), storage: storage})
    end
  end

  test "the fast patch lane refuses to replace or introduce the authority itself" do
    {Grants, binary, _filename} = :code.get_object_code(Grants)

    assert {:ok, artifact} =
             Artifact.build([{Grants, binary, disposition: :replace}], epoch: unique_epoch())

    assert {:error, {:immutable_control_module, Grants}} =
             Verifier.verify(artifact, allow_unsigned: true)

    # Neither disposition is a way in. A capability forged by an agent cannot patch, or
    # take the name of, the authority that decided the agent could forge it.
    assert {:ok, introduced} =
             Artifact.build([{Grants, binary, disposition: :introduce}], epoch: unique_epoch())

    assert {:error, {:immutable_control_module, Grants}} =
             Verifier.verify(introduced, allow_unsigned: true)

    assert :code.which(Grants) != :non_existing
    assert Process.alive?(Process.whereis(Grants))
  end

  defp start_grants!(storage \\ nil) do
    name = unique_name()
    storage = storage || {Jido.Storage.ETS, table: unique_table()}
    start_supervised!({Grants, name: name, storage: storage}, id: name)
    name
  end

  defp unique_name,
    do: String.to_atom("grants_#{System.unique_integer([:positive, :monotonic])}")

  defp unique_table,
    do: String.to_atom("grants_storage_#{System.unique_integer([:positive, :monotonic])}")

  defp unique_epoch, do: System.unique_integer([:positive, :monotonic])
end
