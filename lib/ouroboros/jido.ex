defmodule Ouroboros.Jido do
  @moduledoc """
  The supervised Jido runtime owned by Ouroboros.

  Jido supplies schema-checked agent state, actions, directives, and CloudEvents-style
  signals. Ouroboros deliberately builds its cluster and upgrade semantics above this
  stable core instead of forking those primitives.
  """

  use Jido, otp_app: :ouroboros
end
