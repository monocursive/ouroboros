defmodule Ouroboros.Session.Error do
  @moduledoc "Validation and execution refusals at the owned session boundary."

  defexception category: :internal,
               provider: nil,
               message: "session error",
               details: %{},
               cause: nil

  @type t :: %__MODULE__{
          category: atom(),
          provider: atom() | nil,
          message: String.t(),
          details: map(),
          cause: term()
        }

  def new(category, message, attrs \\ %{}) when is_atom(category) and is_binary(message),
    do: struct!(__MODULE__, Map.merge(Map.new(attrs), %{category: category, message: message}))

  def validation(message, attrs \\ %{}), do: new(:validation, message, attrs)
  def execution(message, attrs \\ %{}), do: new(:execution, message, attrs)

  @impl true
  def message(%__MODULE__{provider: provider, message: message}),
    do: if(provider, do: "#{provider}: " <> message, else: message)
end
