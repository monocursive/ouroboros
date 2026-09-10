defmodule Ouroboros.Storage.ETS do
  @moduledoc """
  Ephemeral checkpoints owned by an explicit supervised storage lifecycle.

  The application starts this process before its stores. Tables survive a store or
  caller restart and disappear when this storage owner stops. No caller creates a
  table or starts an implicit owner. `:table` is an atom namespace (default
  `:ouroboros_storage`); `:owner` selects an explicitly started isolated owner.
  Tables are unnamed, so a namespace never creates additional atoms.
  """
  use GenServer
  @behaviour Ouroboros.Storage

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, %{}, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def get_checkpoint(key, opts), do: call({:get, key}, opts)

  @impl true
  def put_checkpoint(key, value, opts), do: call({:put, key, value}, opts)

  @impl true
  def delete_checkpoint(key, opts), do: call({:delete, key}, opts)

  defp call(operation, opts) do
    with true <- Keyword.keyword?(opts),
         table when is_atom(table) and table not in [nil, true, false] <-
           Keyword.get(opts, :table, :ouroboros_storage) do
      GenServer.call(Keyword.get(opts, :owner, __MODULE__), {table, operation})
    else
      _ -> {:error, :invalid_storage_options}
    end
  catch
    :exit, _ -> {:error, :storage_owner_unavailable}
  end

  @impl true
  def handle_call({namespace, operation}, _from, state) do
    {table, state} =
      case Map.fetch(state, namespace) do
        {:ok, table} ->
          {table, state}

        :error ->
          table = :ets.new(namespace, [:set, :private])
          {table, Map.put(state, namespace, table)}
      end

    reply =
      case operation do
        {:get, key} ->
          case :ets.lookup(table, key) do
            [{^key, value}] -> {:ok, value}
            [] -> :not_found
          end

        {:put, key, value} ->
          true = :ets.insert(table, {key, value})
          :ok

        {:delete, key} ->
          true = :ets.delete(table, key)
          :ok
      end

    {:reply, reply, state}
  end
end
