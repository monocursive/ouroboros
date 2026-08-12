defmodule Ouroboros.Test.UnreadableTeamStorage do
  @moduledoc false
  @behaviour Jido.Storage

  @impl true
  def get_checkpoint(_key, _opts), do: {:error, :unreadable}

  @impl true
  def put_checkpoint(_key, _value, _opts), do: :ok

  @impl true
  def delete_checkpoint(_key, _opts), do: :ok

  @impl true
  def load_thread(_id, _opts), do: :not_found

  @impl true
  def append_thread(_id, _entries, _opts), do: {:error, :unsupported}

  @impl true
  def delete_thread(_id, _opts), do: :ok
end

defmodule Ouroboros.Test.CorruptTeamStorage do
  @moduledoc false
  @behaviour Jido.Storage

  @impl true
  def get_checkpoint(_key, _opts), do: {:ok, %{"corrupt" => %{pid: self()}}}

  @impl true
  def put_checkpoint(_key, _value, _opts), do: :ok

  @impl true
  def delete_checkpoint(_key, _opts), do: :ok

  @impl true
  def load_thread(_id, _opts), do: :not_found

  @impl true
  def append_thread(_id, _entries, _opts), do: {:error, :unsupported}

  @impl true
  def delete_thread(_id, _opts), do: :ok
end

defmodule Ouroboros.TeamStoreTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Team.Store
  alias Ouroboros.Test.{CorruptTeamStorage, UnreadableTeamStorage}

  setup do
    previous = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous) end)
    :ok
  end

  test "store fails closed when the adapter cannot read the aggregate" do
    name = unique_name("unreadable")

    assert {:error, {:team_checkpoint_unreadable, :unreadable}} =
             Store.start_link(name: name, storage: UnreadableTeamStorage)

    refute Process.whereis(name)
  end

  test "store fails closed when the aggregate is corrupt or authority-bearing" do
    name = unique_name("corrupt")

    assert {:error, :invalid_team_checkpoint} =
             Store.start_link(name: name, storage: CorruptTeamStorage)

    refute Process.whereis(name)
  end

  defp unique_name(prefix) do
    String.to_atom("ouroboros_team_store_#{prefix}_#{System.unique_integer([:positive])}")
  end
end
