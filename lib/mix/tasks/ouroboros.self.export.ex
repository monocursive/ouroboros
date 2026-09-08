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

  The outer loop's pull request commits all three; `Ouroboros.Self.Boot` reads them on a
  fresh install under `OUROBOROS_POSTURE=self`.

  ## It runs against a node, not against a checkout

  The promotion record and the component store are the runtime's, so this task starts the
  application and reads them. On a machine whose daemon is already running, that is a second
  VM against the same data directory — which is why the honest way to run it is with the
  daemon stopped, and why `make self-export` says so.

  Refuses, having written nothing, when the promotion record holds no policy: there is
  nothing an installation learned, and a `priv/self` full of a policy nobody promoted would
  be a widening nobody performed.
  """

  use Mix.Task

  alias Ouroboros.Self.Export

  @switches [out: :string]

  @impl Mix.Task
  def run(argv) do
    {opts, _rest} = OptionParser.parse!(argv, strict: @switches)

    Mix.Task.run("app.start")

    case Export.run(out: Keyword.get(opts, :out, Export.default_out())) do
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

  defp report_lines(report) do
    """
    wrote #{report.bundle} (#{report.bundle_bytes} bytes)
    wrote #{report.promotions}
    wrote #{report.signers}

    policy    #{report.policy_name} at #{report.component_sha256}
    signer    #{report.signer_id}
    promoted  #{tools(report.tools)}

    On the installation that will run this, before it boots:
      OUROBOROS_UPGRADE_TRUSTED_SIGNERS=#{signers_line(report)}
    """
  end

  defp tools([]), do: "(none currently allowable)"
  defp tools(tools), do: Enum.join(tools, ", ")

  defp signers_line(report) do
    case File.read(report.signers) do
      {:ok, contents} -> String.trim(contents)
      {:error, _reason} -> "#{report.signer_id}:<see #{report.signers}>"
    end
  end
end
