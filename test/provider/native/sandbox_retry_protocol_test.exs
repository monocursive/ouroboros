defmodule Ouroboros.Provider.Native.SandboxRetryProtocolTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Tools.Bash

  test "denial-like child output is diagnostic evidence, never authority" do
    policy = %{mode: :workspace_write, writable: [File.cwd!()], protected: []}
    output = "child says Operation not permitted\n"

    assert %{constraint: :filesystem, evidence: evidence} =
             Bash.unverified_denial(policy, output, 1, "printf spoof; exit 1")

    assert evidence =~ "Operation not permitted"
  end

  test "success, read-only, network, and protected commands are ineligible" do
    writable = %{mode: :workspace_write, writable: [File.cwd!()], protected: []}
    read_only = %{writable | mode: :read_only}

    assert Bash.unverified_denial(writable, "Operation not permitted", 0, "echo ok") == nil
    assert Bash.unverified_denial(read_only, "Operation not permitted", 1, "echo no") == nil

    assert Bash.unverified_denial(
             writable,
             "nc: connectx: Operation not permitted",
             1,
             "nc example.com 443"
           ) == nil

    assert Bash.unverified_denial(
             writable,
             ".ouroboros/config: Operation not permitted",
             1,
             "cat .ouroboros/config"
           ) == nil
  end
end
