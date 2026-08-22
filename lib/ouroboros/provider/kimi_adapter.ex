defmodule Ouroboros.Provider.KimiAdapter do
  @moduledoc false

  @behaviour Jido.Harness.Adapter

  alias Jido.Harness.Adapters.Kimi

  @impl true
  def spec, do: Ouroboros.Provider.Session.upgrade_acp(Kimi.spec())

  @impl true
  defdelegate status(config), to: Kimi

  @impl true
  defdelegate run(request, context), to: Kimi

  @impl true
  defdelegate install(config, options), to: Kimi

  @impl true
  defdelegate cancel(run_id, context), to: Kimi
end
