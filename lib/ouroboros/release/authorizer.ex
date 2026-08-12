defmodule Ouroboros.Release.Authorizer do
  @moduledoc """
  Independent approval boundary for release-handler mutations.

  The callback receives a redacted artifact summary, the exact requested
  actions, and caller-supplied approval evidence. It must return `:ok` to issue
  an in-memory capability. Approval evidence and capabilities are never
  persisted by the release journal.
  """

  @type action :: :unpack | :check_install | :install | :make_permanent

  @callback authorize(map(), [action()], term()) :: :ok | {:error, term()}
end

defmodule Ouroboros.Release.Authorizer.Deny do
  @moduledoc "Default authorizer. All node-mutating operations are denied."

  @behaviour Ouroboros.Release.Authorizer

  @impl true
  def authorize(_artifact, _actions, _approval), do: {:error, :release_authorization_required}
end
