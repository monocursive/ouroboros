defmodule Ouroboros.Audit.ContainmentTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log
  alias Ouroboros.Audit.Config
  alias Ouroboros.Provider.Native.{Paths, Sandbox}
  alias Ouroboros.Provider.Native.Tools.Bash

  setup do
    {:ok, tmp} = Ouroboros.Workspace.Path.canonicalize(System.tmp_dir!())
    root = Path.join(tmp, "ouro-audit-containment-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace"))
    File.mkdir_p!(Path.join(root, "evidence"))
    File.write!(Path.join(root, "evidence/sentinel"), "audit-secret-sentinel")
    previous = Application.get_env(:ouroboros, :audit)

    Application.put_env(
      :ouroboros,
      :audit,
      Config.new!(mode: :required, root: Path.join(root, "evidence"))
    )

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :audit, previous),
        else: Application.delete_env(:ouroboros, :audit)

      File.rm_rf(root)
    end)

    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)
    %{root: root, scope: scope}
  end

  test "required mode cannot request unrestricted execution or a weak backend", ctx do
    assert {:refused, :required_audit_containment_unavailable} =
             Sandbox.decision(%{ctx.scope | sandbox_mode: :unrestricted})

    assert {:refused, :required_audit_containment_unavailable} =
             Sandbox.decision(ctx.scope, %{backend: :none})

    assert {:refused, :required_audit_containment_unavailable} =
             Sandbox.decision(ctx.scope, %{backend: :bwrap, unshare_net: false})

    refute Ouroboros.Audit.tool_supported?("mcp__unsafe__run")
    assert {:error, _} = Paths.resolve(Path.join(ctx.root, "evidence/sentinel"), ctx.scope)
  end

  test "the host sandbox permits workspace writes while blocking evidence reads and loopback",
       ctx do
    detection = Sandbox.detect()

    if Sandbox.fences_reads?(detection) and Sandbox.fences_network?(detection) do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, {_, port}} = :inet.sockname(listener)
      on_exit(fn -> :gen_tcp.close(listener) end)

      command =
        "printf allowed > allowed.txt; /bin/cat '#{ctx.root}/evidence/sentinel'; /usr/bin/curl --max-time 1 http://127.0.0.1:#{port}/"

      assert {:ok, result} =
               Bash.run(%{command: command, timeout_ms: 5000}, %{
                 scope: ctx.scope,
                 provider_options: %{},
                 session_dir: nil
               })

      assert File.read!(Path.join(ctx.scope.root, "allowed.txt")) == "allowed"
      refute result.output =~ "audit-secret-sentinel"
      assert result.is_error
      assert {:error, :timeout} = :gen_tcp.accept(listener, 100)
    else
      # No successful containment claim on a host that lacks the required backend.
      assert {:refused, _} = Sandbox.decision(ctx.scope, detection)
    end
  end
end
