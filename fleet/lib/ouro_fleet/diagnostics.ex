defmodule OuroFleet.Diagnostics do
  @moduledoc false
  require Logger

  def refused(error, stack) do
    frames =
      Enum.take(stack, 4)
      |> Enum.map(fn {module, function, arity, location} ->
        {module, function, if(is_list(arity), do: length(arity), else: arity), location[:line]}
      end)

    # No exception message, arguments, request, state, argv or credentials.
    Logger.error("fleet refusal #{inspect(error.__struct__)} at #{inspect(frames)}")
  end
end
