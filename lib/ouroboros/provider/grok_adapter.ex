defmodule Ouroboros.Provider.GrokAdapter do
  @moduledoc """
  Ouroboros's boundary around the pinned first-party Grok Build CLI adapter.

  The CLI owns SpaceXAI subscription authentication and refresh in `~/.grok/auth.json`.
  Ouroboros never reads a token out of that file. A node-owned xAI API key is added to
  the subprocess environment only when one is available; the CLI's documented
  precedence keeps an active subscription session ahead of this `XAI_API_KEY` fallback.
  Harness redaction sees the transient environment entry before any process event can be
  journaled.
  """

  @behaviour Jido.Harness.Adapter

  alias Jido.Harness.Adapters.{Grok, Helpers}
  alias Jido.Harness.ProviderStatus
  alias Ouroboros.Provider.{GrokAuth, XAIKey}

  # This wrapper fronts the pinned Grok adapter, whose `--fork-session` option branches
  # the session named by `--resume`. Declare the wrapped adapter's native fork flag so
  # `Ouroboros.Provider.session_capabilities/2` does not lose it at this boundary.
  @spec fork_option() :: {atom(), term()}
  def fork_option, do: {:fork_session, true}

  @impl true
  def spec, do: Grok.spec()

  @impl true
  def run(request, context) do
    env = Helpers.merge_env(request, context.config, stored_key_env())
    Grok.run(%{request | env: env}, context)
  end

  @impl true
  def status(config) do
    with {:ok, status} <- Grok.status(config) do
      subscription? = GrokAuth.credential_present?()
      authenticated = XAIKey.present?() or subscription?

      details = %{
        "credentials" => [stringify(XAIKey.status())],
        "subscription" => %{"present" => subscription?}
      }

      {:ok,
       status
       |> Map.put(:authenticated, authenticated)
       |> Map.put(:details, Map.merge(status.details || %{}, details))
       |> ProviderStatus.finalize()}
    end
  end

  @impl true
  def install(config, options), do: Grok.install(config, options)

  @impl true
  def cancel(run_id, context), do: Grok.cancel(run_id, context)

  @doc false
  def build_argv(request, options), do: Grok.build_argv(request, options)

  defp stored_key_env do
    case XAIKey.fetch() do
      {:ok, key, _source} -> %{"XAI_API_KEY" => key}
      {:error, _reason} -> %{}
    end
  end

  defp stringify(map), do: Map.new(map, fn {key, value} -> {to_string(key), value} end)
end
