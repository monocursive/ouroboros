defmodule Ouroboros.Action.ValidationError do
  @moduledoc "An owned action validation failure with stable model-facing diagnostics."
  defexception [:message]
end
