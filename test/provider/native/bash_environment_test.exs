defmodule Ouroboros.Provider.Native.BashEnvironmentTest do
  @moduledoc """
  What the model's own shell can read out of the operator's environment.

  `bench/self`'s adversarial review raised this as plausible rather than proved: the native
  `bash` tool is a child of the daemon, the daemon is started by an operator whose shell
  usually holds `ANTHROPIC_API_KEY`, and a model that can read its own provider key can
  spend the operator's money outside the loop that is counting it.

  It is not true, and this file is why anybody can know that without re-deriving it.
  `Provider.Native.Exec` passes `:clear` to erlexec and rebuilds the child's environment
  from an **allowlist** of login, terminal and toolchain variables, then drops anything
  `Ouroboros.ProcessEnvironment.sensitive?/2` recognises. A provider key is outside the
  allowlist *and* matches the credential pattern, so it is excluded twice over.

  `GITHUB_TOKEN` is asserted here for the same reason and with the opposite intent: it is
  absent too. An operator who wants their agent to use `gh` has to say so through the
  tool's own `env`, not through ambient inheritance — and even then `sensitive?/2` refuses
  it. That is a real limitation of the current posture, and stating it is better than a
  test that quietly asserts only the half that is comfortable.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Bash

  @planted %{
    "ANTHROPIC_API_KEY" => "planted-anthropic-key-must-not-reach-bash",
    "OPENAI_API_KEY" => "planted-openai-key-must-not-reach-bash",
    "AWS_SECRET_ACCESS_KEY" => "planted-aws-secret-must-not-reach-bash",
    "GITHUB_TOKEN" => "planted-github-token"
  }

  setup do
    previous = Map.take(System.get_env(), Map.keys(@planted))

    on_exit(fn ->
      Enum.each(Map.keys(@planted), &System.delete_env/1)
      Enum.each(previous, fn {name, value} -> System.put_env(name, value) end)
    end)

    System.put_env(@planted)

    root =
      Path.join(System.tmp_dir!(), "native-bash-env-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(root, [], :unrestricted)

    %{root: root, scope: scope}
  end

  test "the model's shell cannot read the operator's provider keys", %{root: root, scope: scope} do
    output = env(root, scope)

    refute output =~ "ANTHROPIC_API_KEY="
    refute output =~ "planted-anthropic-key-must-not-reach-bash"
    refute output =~ "OPENAI_API_KEY="
    refute output =~ "planted-openai-key-must-not-reach-bash"
    refute output =~ "AWS_SECRET_ACCESS_KEY="
    refute output =~ "planted-aws-secret-must-not-reach-bash"

    # The child got *an* environment, so the assertions above are about filtering rather
    # than about a command that never ran.
    assert output =~ "PATH="
  end

  test "and no other credential-shaped variable either", %{root: root, scope: scope} do
    output = env(root, scope)

    refute output =~ "GITHUB_TOKEN="
    refute output =~ "planted-github-token"
  end

  defp env(root, scope) do
    result =
      Tools.execute(
        Bash,
        %{"command" => "env"},
        %{scope: scope, session_dir: root, reads: %{}},
        30_000
      )

    refute result.is_error, "bash did not run: " <> result.output

    result.output
  end
end
