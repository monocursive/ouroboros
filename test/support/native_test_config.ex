defmodule Ouroboros.Test.NativeConfig do
  @moduledoc "Scoped configuration for controlled native model tests."
  def snapshot do
    %{
      native: Ouroboros.Provider.Native.config(),
      restore: %{
        native_model_module: Application.get_env(:ouroboros, :native_model_module),
        native_model: Application.get_env(:ouroboros, :native_model)
      }
    }
  end

  def configure(settings) do
    config = Map.get(Map.new(settings || %{}), :native, %{})
    Application.put_env(:ouroboros, :native_provider, config)

    if is_pid(config[:test_pid]) do
      Application.put_env(:ouroboros, :native_model_module, Ouroboros.Test.ControlledModel)
      Application.put_env(:ouroboros, :native_model, "scripted:controlled")
    else
      Enum.each(Map.get(settings || %{}, :restore, %{}), fn
        {key, nil} -> Application.delete_env(:ouroboros, key)
        {key, value} -> Application.put_env(:ouroboros, key, value)
      end)
    end

    :ok
  end
end
