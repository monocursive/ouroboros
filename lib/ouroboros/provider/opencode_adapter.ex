defmodule Ouroboros.Provider.OpenCodeAdapter do
  @moduledoc false

  @behaviour Jido.Harness.Adapter

  alias Jido.Harness.Adapters.OpenCode

  @impl true
  def spec, do: Ouroboros.Provider.Session.upgrade_acp(OpenCode.spec())

  @impl true
  defdelegate status(config), to: OpenCode

  @impl true
  defdelegate run(request, context), to: OpenCode
end
