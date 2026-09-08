defmodule Mix.Tasks.Ouroboros.Self.Export do
  @shortdoc "Writes the promoted policy and its promotion record into priv/self/"

  @moduledoc """
  Exports what this installation learned, so the next one can carry it (docs/SELF.md §S4).

      mix ouroboros.self.export [--out priv/self]

  Three files, written out of this node's own durable state:

    * `priv/self/<name>.ouro-wasm` — the signed bundle for the policy the promotion record
      is bound to, assembled from this node's component store. The same file
      `ouro wasm sign` writes and `ouro wasm deploy` takes.
    * `priv/self/promotions.json` — the policy name, the component sha256, and the tools it
      has *currently* earned the right to resolve, each with the replay numbers that earned
      it.
    * `priv/self/signers.txt` — `signer_id:base64_public_key`, the line the receiving
      operator pastes into `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`. Until they do, a node that
      reads the bundle refuses it.

  Any other `*.ouro-wasm` in the destination is removed and named in the output: it is an
  earlier export's policy under a name this one no longer has, and `Ouroboros.Self.Boot`
  globs the directory. `README.md` is left alone.

  The outer loop's pull request commits all three; `Ouroboros.Self.Boot` reads them on a
  fresh install under `OUROBOROS_POSTURE=self`.

  ## `--out` cannot leave the repository

  It is resolved — `..`, a relative spelling, and the symlinks on the way, including a
  symlinked `priv/self` — and refused unless it lands inside the directory `mix` is running
  in. A switch that writes a signed bundle and a trust suggestion three levels above the
  checkout is doing something its name does not say (S4 fix wave, LOW-4).

  ## It runs against a node, not against a checkout

  The promotion record and the component store are the runtime's, so this task **starts the
  application** — `mix app.start`, the whole supervision tree, against whatever
  `OUROBOROS_DATA_DIR` names. There is no way around it: the record is a `GenServer`'s
  durable state and the bundle is assembled out of the store beside it.

  So it refuses, before starting anything, when a daemon already holds that data directory:
  a second VM on one directory is two runtimes claiming one set of journals, and
  `Ouroboros.RuntimeOwner` would refuse the boot with a message about a marker rather than
  about what the operator did. Stop the daemon (`ouro stop`) and run it again.

  And it starts that VM with `OUROBOROS_GATEWAY` and `OUROBOROS_WEB` set to `0`, which is
  how `config/runtime.exs` reads "no operator surface": an export is a one-shot read of
  durable state and has no business binding a port or publishing a `gateway.json` a client
  could attach to.

  Refuses, having written nothing, when the promotion record holds no policy: there is
  nothing an installation learned, and a `priv/self` full of a policy nobody promoted would
  be a widening nobody performed.
  """

  use Mix.Task

  alias Ouroboros.Self.Export

  @switches [out: :string]

  # `gateway.json` is a discovery publication and `runtime.owner` is the lifetime claim
  # beside it (`Ouroboros.RuntimeOwner`); a graceful stop removes both and a kill leaves
  # them, so each is read for the pid it names and believed only while that pid is alive.
  @markers ["gateway.json", "runtime.owner"]
  @kill_paths ["/bin/kill", "/usr/bin/kill"]

  @impl Mix.Task
  def run(argv) do
    {opts, _rest} = OptionParser.parse!(argv, strict: @switches)
    out = Keyword.get(opts, :out, Export.default_out())
    root = File.cwd!()

    # The daemon check first, because it is the graver harm: a second VM on one data
    # directory is two runtimes claiming one set of journals, and it costs one `File.read`.
    case running_daemon() do
      {:running, pid, marker} -> Mix.raise(daemon_message(pid, marker))
      :none -> :ok
    end

    case Export.confine(out, root) do
      {:ok, _out} ->
        :ok

      {:error, {:out_escapes_root, resolved, inside}} ->
        Mix.raise(escape_message(resolved, inside))

      {:error, reason} ->
        Mix.raise("--out is unusable: #{inspect(reason)}")
    end

    quiet_surfaces()
    Mix.Task.run("app.start")

    case Export.run(out: out, confine_to: root) do
      {:ok, report} ->
        Mix.shell().info(report_lines(report))

      {:error, :no_promoted_policy} ->
        Mix.raise(
          "the promotion record holds no policy, so there is nothing to export. " <>
            "Deploy a policy component, replay it (`ouro policy replay`), and promote a " <>
            "tool on the numbers (`ouro policy promote`) first — docs/SELF.md §S2."
        )

      {:error, reason} ->
        Mix.raise("self export failed: #{inspect(reason)}")
    end
  end

  # Set rather than merely read: `config/runtime.exs` is evaluated by `app.start` below, and
  # by then this process's environment is the only thing that can still say no.
  defp quiet_surfaces do
    System.put_env("OUROBOROS_GATEWAY", "0")
    System.put_env("OUROBOROS_WEB", "0")
  end

  # The data directory this VM would open, derived the way `config/runtime.exs` derives it
  # and before it has run: `Ouroboros.DataDir` is the module both sides share. With no
  # `OUROBOROS_DATA_DIR` there is no durable directory at all in this environment, so there
  # is no daemon to collide with and nothing to check.
  defp running_daemon do
    case Ouroboros.DataDir.configured!(System.get_env("OUROBOROS_DATA_DIR")) do
      nil -> :none
      data_dir -> Enum.find_value(@markers, :none, &live_marker(Path.join(data_dir, &1)))
    end
  rescue
    # A malformed OUROBOROS_DATA_DIR is `app.start`'s refusal to make, with its own message.
    _error -> :none
  end

  defp live_marker(path) do
    with {:ok, contents} <- File.read(path),
         {:ok, %{"pid" => pid}} <- JSON.decode(contents),
         true <- is_integer(pid) and pid > 0,
         true <- alive?(pid) do
      {:running, pid, path}
    else
      _absent_or_dead -> nil
    end
  end

  # `kill -0` from a trusted absolute path, the same probe `Ouroboros.RuntimeOwner` uses to
  # decide whether a marker is stale. A pid this user cannot signal answers `EPERM` and is
  # counted as alive, which is the safe direction: something is holding that directory.
  defp alive?(pid) do
    case Enum.find(@kill_paths, &File.regular?/1) do
      nil ->
        true

      kill ->
        match?(
          {_output, 0},
          System.cmd(kill, ["-0", Integer.to_string(pid)], stderr_to_stdout: true)
        )
    end
  rescue
    _error -> true
  end

  defp daemon_message(pid, marker) do
    """
    a runtime is already holding this data directory (pid #{pid}, from #{marker}).

    This task starts the whole application against that same directory, and two runtimes on \
    one set of journals is what `Ouroboros.RuntimeOwner` exists to refuse. Stop the daemon \
    and run it again:

      ouro stop
      mix ouroboros.self.export

    If that pid is not a runtime, remove #{marker} and try again.\
    """
  end

  defp escape_message(resolved, inside) do
    """
    --out resolves to #{resolved}, which is outside #{inside}.

    An export writes a signed bundle and the trust line that makes it deployable. Both \
    belong in the repository that will commit them, so `--out` has to land inside the \
    directory mix is running in — after `..`, a relative spelling, and any symlinks on the \
    way are resolved.\
    """
  end

  defp report_lines(report) do
    """
    wrote #{report.bundle} (#{report.bundle_bytes} bytes)
    wrote #{report.promotions}
    wrote #{report.signers}
    #{removed_lines(report.removed)}
    policy    #{report.policy_name} at #{report.component_sha256}
    signer    #{report.signer_id}
    promoted  #{tools(report.tools)}

    On the installation that will run this, before it boots:
      OUROBOROS_UPGRADE_TRUSTED_SIGNERS=#{signers_line(report)}
    """
  end

  defp removed_lines([]), do: ""

  defp removed_lines(removed),
    do: Enum.map_join(removed, "\n", &"removed #{&1} (not this policy's bundle)") <> "\n"

  defp tools([]), do: "(none currently allowable)"
  defp tools(tools), do: Enum.join(tools, ", ")

  defp signers_line(report) do
    case File.read(report.signers) do
      {:ok, contents} -> String.trim(contents)
      {:error, _reason} -> "#{report.signer_id}:<see #{report.signers}>"
    end
  end
end
