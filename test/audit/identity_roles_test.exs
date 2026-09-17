defmodule Ouroboros.Audit.IdentityRolesTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Audit.Config
  alias Ouroboros.Audit.Identity

  # `required_role/2` is private, so these assert it the only way a caller ever meets it:
  # through `permits?/3`, with identities actually configured. The fleet methods below do
  # not exist in this build. That is the point — the rules land before the verbs, and a
  # verb added to the family later is gated the day it exists rather than the day somebody
  # remembers. Deleting either rule turns one of these assertions around.

  setup do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouro-identity-roles-#{System.unique_integer([:positive])}"
      )

    previous = Application.get_env(:ouroboros, :audit)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :audit, previous),
        else: Application.delete_env(:ouroboros, :audit)

      File.rm_rf(root)
    end)

    %{root: root}
  end

  defp configure(root, identities) do
    config =
      Config.new!(
        mode: :local,
        capture: :full,
        root: Path.join(root, "evidence"),
        writer_id: "test-node",
        identities: identities
      )

    Application.put_env(:ouroboros, :audit, config)
    config
  end

  defp identity(id, roles, token) do
    %{
      "id" => id,
      "roles" => roles,
      "token_sha256" => :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
    }
  end

  defp subject!(token) do
    assert {:ok, subject} = Identity.authenticate(token, "some-local-token")
    subject
  end

  describe "fleet deployment is an administrator's decision" do
    test "an operator may run the fleet it has, and may not deploy onto another machine",
         %{root: root} do
      operator = identity("olive", ["operator"], "operator-token")
      administrator = identity("adele", ["administrator"], "administrator-token")
      configure(root, [operator, administrator])

      operator_subject = subject!("operator-token")
      administrator_subject = subject!("administrator-token")

      # Unchanged: the existing fleet verbs are still an operator's.
      assert Identity.permits?(operator_subject, "fleet.tags", :operate)
      assert Identity.permits?(operator_subject, "fleet.status", :read)

      for method <- [
            "fleet.deployment.prepare",
            "fleet.deployment.start",
            "fleet.deployment.authenticate",
            "fleet.deployment.confirm_host",
            "fleet.deployment.cancel",
            "fleet.deployment.resume"
          ] do
        refute Identity.permits?(operator_subject, method, :operate),
               "#{method} must need an administrator"

        assert Identity.permits?(administrator_subject, method, :operate),
               "#{method} must be open to an administrator"
      end
    end

    test "an approver is not a deployer either", %{root: root} do
      configure(root, [identity("avery", ["approver"], "approver-token")])

      refute Identity.permits?(subject!("approver-token"), "fleet.deployment.start", :operate)
    end
  end

  describe "tailnet inventory is administrator-only at read scope" do
    test "an operator reads membership but not the network", %{root: root} do
      operator = identity("olive", ["operator"], "operator-token")
      administrator = identity("adele", ["administrator"], "administrator-token")
      configure(root, [operator, administrator])

      operator_subject = subject!("operator-token")

      refute Identity.permits?(operator_subject, "fleet.devices", :read)
      assert Identity.permits?(subject!("administrator-token"), "fleet.devices", :read)

      # The rule is `fleet.devices`, not "anything read-scoped that says fleet": every
      # other read stays exactly where it was.
      assert Identity.permits?(operator_subject, "fleet.status", :read)
      assert Identity.permits?(operator_subject, "fleet.doctor", :read)
      assert Identity.permits?(operator_subject, "runtime.activity", :read)
      assert Identity.permits?(operator_subject, "runtime.status", :read)
    end

    test "an auditor is not an operator and still is not an administrator", %{root: root} do
      configure(root, [identity("aster", ["auditor"], "auditor-token")])

      auditor = subject!("auditor-token")

      assert Identity.permits?(auditor, "audit.search", :read)
      refute Identity.permits?(auditor, "fleet.devices", :read)
      refute Identity.permits?(auditor, "runtime.activity", :read)
    end
  end

  describe "with no identities configured" do
    test "nothing is enforced, which is the posture a single-machine runtime is in" do
      Application.delete_env(:ouroboros, :audit)

      refute Config.enabled?()
      assert Config.current().identities == []

      # Not "these two rules allow it" — the check never reaches a rule at all, which is
      # why even a subject that resolves to nobody passes.
      assert Identity.permits?(nil, "fleet.devices", :read)
      assert Identity.permits?(nil, "fleet.deployment.start", :operate)
      assert Identity.permits?(nil, "runtime.activity", :read)
    end

    test "with audit on and no identities, the local owner is the administrator", %{root: root} do
      configure(root, [])

      assert {:ok, subject} = Identity.authenticate("local-token", "local-token")
      assert {:ok, %{"roles" => ["administrator"]}} = Identity.resolve(subject)

      # The two new rules are gates that only bite once identities exist.
      assert Identity.permits?(subject, "fleet.devices", :read)
      assert Identity.permits?(subject, "fleet.deployment.start", :operate)
      assert Identity.permits?(subject, "runtime.activity", :read)
    end
  end
end
