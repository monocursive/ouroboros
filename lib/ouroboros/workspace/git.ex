defmodule Ouroboros.Workspace.Git do
  @moduledoc false
  alias Ouroboros.Provider.Native.Exec

  # Shared by snapshot, import and return. All commands are argv lists, all output and
  # process lifetimes are bounded, and tests can observe the command-specific environment.
  def run(root, args, opts \\ []) do
    remaining =
      Keyword.get(opts, :deadline, System.monotonic_time(:millisecond) + 120_000) -
        System.monotonic_time(:millisecond)

    opts =
      Keyword.put(
        opts,
        :timeout_ms,
        min(Keyword.get(opts, :timeout_ms, 120_000), max(remaining, 1))
      )

    if remaining <= 0 do
      {:error, :provision_deadline_exceeded}
    else
      case Keyword.get(opts, :runner) do
        runner when is_function(runner, 3) -> runner.(args, root, Keyword.delete(opts, :runner))
        _ -> execute(root, args, opts)
      end
    end
  end

  defp execute(root, args, opts) do
    options = Keyword.merge([cd: root, timeout_ms: 120_000, max_bytes: 2 * 1024 * 1024], opts)

    env =
      options
      |> Keyword.get(:env, [])
      |> Map.new()
      |> Map.merge(%{
        "GIT_CONFIG_NOSYSTEM" => "1",
        "GIT_CONFIG_GLOBAL" => "/dev/null",
        "GIT_CONFIG_COUNT" => "0"
      })

    options = Keyword.put(options, :env, Map.to_list(env))

    # These are runtime bookkeeping commands, not a developer's interactive Git
    # invocation. Even update-ref can execute reference-transaction hooks; neither
    # snapshots nor bundle imports may turn that bookkeeping into extra user commands.
    args = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false" | args]

    case Exec.run("git", args, options) do
      {:ok, %{status: 0, truncated?: false, timed_out?: false, output: output}} ->
        {:ok, String.replace_suffix(output, "\n", "")}

      {:ok, %{truncated?: true}} ->
        {:error, :git_output_too_large}

      {:ok, %{timed_out?: true}} ->
        {:error, :git_timeout}

      {:ok, %{status: status, output: output}} ->
        {:error, {:git, status, output}}

      {:error, reason} ->
        {:error, {:git_unavailable, reason}}
    end
  end

  def valid_id?(id),
    do: is_binary(id) and Regex.match?(~r/\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/, id)

  def valid_commit?(id),
    do: is_binary(id) and Regex.match?(~r/\A(?:[a-f0-9]{40}|[a-f0-9]{64})\z/, id)

  def temp_directory do
    path =
      Path.join(
        System.tmp_dir!(),
        "ouro-git-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
      )

    with :ok <- File.mkdir(path), :ok <- File.chmod(path, 0o700), do: {:ok, path}
  end
end
