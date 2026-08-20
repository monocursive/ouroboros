defmodule Ouroboros.Provider.ProcessDriver do
  @moduledoc """
  Restores normal workspace permissions at the provider process boundary.

  The managed BEAM deliberately runs at umask `077` so journals, checkpoints, and logs
  stay private. Provider CLIs are different: they edit an operator-owned workspace, where
  normal Unix defaults are files at `0644` and directories at `0755`. Every Harness CLI
  and ACP subprocess crosses this driver, so it resets only that child to the conventional
  workspace umask before replacing itself with the original executable.

  The packaged wrapper is versioned runtime code and every dynamic value stays a
  positional argument. There is no interpolated command string. `exec` preserves the OS
  pid and process group that Erlexec owns, so cancellation, escalation, output events,
  and redaction continue to use the original Harness process specification.
  """

  @behaviour Jido.Harness.ProcessDriver

  alias Jido.Harness.ProcessDriver.Erlexec
  alias Jido.Harness.ProcessSpec

  @impl true
  def start(%ProcessSpec{} = spec, owner) do
    with {:ok, executable} <- ProcessSpec.resolve_executable(spec.executable),
         {:ok, wrapper} <- wrapper_executable() do
      wrapped = %{
        spec
        | executable: wrapper,
          argv: [executable | spec.argv]
      }

      Erlexec.start(wrapped, owner)
    end
  end

  @impl true
  defdelegate send_input(process, data), to: Erlexec

  @impl true
  defdelegate signal(process, signal), to: Erlexec

  defp wrapper_executable do
    with directory when is_list(directory) <- :code.priv_dir(:ouroboros),
         path = directory |> List.to_string() |> Path.join("provider-exec"),
         {:ok, %File.Stat{type: :regular, mode: mode}} <- File.lstat(path),
         true <- Bitwise.band(mode, 0o111) != 0 do
      {:ok, path}
    else
      failure ->
        {:error,
         {:provider_workspace_wrapper_unavailable,
          "expected a real executable priv/provider-exec file, got: #{inspect(failure)}"}}
    end
  end
end
