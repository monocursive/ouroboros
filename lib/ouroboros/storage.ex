defmodule Ouroboros.Storage do
  @moduledoc """
  Checkpoint-only adapter contract. Adapters overwrite a logical key and report
  acknowledged completion separately from an uncertain durable outcome.
  """

  @callback get_checkpoint(term(), keyword()) :: {:ok, term()} | :not_found | {:error, term()}
  @callback put_checkpoint(term(), term(), keyword()) :: :ok | {:error, term()}
  @callback delete_checkpoint(term(), keyword()) :: :ok | {:error, term()}

  @doc "Normalizes an adapter module or `{module, keyword_options}`; invalid configuration raises."
  @spec normalize_storage(module() | {module(), keyword()}) :: {module(), keyword()}
  def normalize_storage({module, opts})
      when is_atom(module) and module not in [nil, true, false] do
    if Keyword.keyword?(opts),
      do: {module, opts},
      else: raise(ArgumentError, "invalid checkpoint storage options: expected a keyword list")
  end

  def normalize_storage(module) when is_atom(module) and module not in [nil, true, false],
    do: {module, []}

  def normalize_storage(_),
    do:
      raise(
        ArgumentError,
        "invalid checkpoint storage: expected an adapter module or {module, keyword_options}"
      )
end
