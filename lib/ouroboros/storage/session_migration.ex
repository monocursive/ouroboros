defmodule Ouroboros.Storage.SessionMigration do
  @moduledoc """
  In-memory reader for checkpoints written before the owned runtime contracts.

  Safe term decoding has already checked the finite atom vocabulary. Historical data
  never selects a module to load or a constructor to call. Retired boundary structs
  become ordinary maps, preserving their fields; only the two owned domain structs
  are reconstructed, explicitly, to supply defaults added since the record was written.
  Reading a record does not write it or claim a workspace.
  """

  alias Ouroboros.Interactive.{Event, State}

  @legacy_structs [
    :"Elixir.Jido.Harness.SessionRequest",
    :"Elixir.Jido.Harness.TurnRequest",
    :"Elixir.Jido.Harness.ApprovalResponse",
    :"Elixir.Jido.Harness.Event",
    :"Elixir.Jido.Harness.Error",
    :"Elixir.Jido.Harness.SessionInfo",
    :"Elixir.Jido.Harness.TurnResult",
    :"Elixir.Jido.Harness.RunRequest",
    :"Elixir.Jido.Harness.RunResult",
    :"Elixir.Jido.Harness.RunInfo",
    :"Elixir.Jido.Harness.ProcessInfo",
    # J3's finite core shapes are historical values; no missing constructor is called.
    :"Elixir.Jido.Action.Error.InvalidInputError",
    :"Elixir.Jido.Action.Error.ExecutionFailureError",
    :"Elixir.Jido.Action.Error.ConfigurationError",
    :"Elixir.Jido.Action.Error.TimeoutError",
    :"Elixir.Jido.Action.Error.InternalError",
    :"Elixir.Jido.Action.Error.Internal.UnknownError",
    :"Elixir.Jido.Signal",
    :"Elixir.Jido.Agent",
    :"Elixir.Jido.Instruction"
  ]

  @doc "The retired struct tags the boundary is allowed to normalize."
  def legacy_structs, do: @legacy_structs

  @doc "Normalizes only known retired tags, recursively, without constructing modules."
  # Every manifest field, including arbitrary nested metadata, participates in the
  # signature. Keep this owned envelope byte-exact as inert data: stripping a legacy
  # tag or exception flag inside it would invalidate an otherwise valid old signature.
  def normalize(%{__struct__: Ouroboros.Wasm.Artifact} = artifact), do: artifact

  def normalize(%{__struct__: :"Elixir.Jido.Harness.SessionRequest"} = value) do
    value
    |> Map.drop([:__struct__, :__exception__])
    |> Map.new(&normalize_pair/1)
    |> migrate_plan()
  end

  def normalize(%{__struct__: module} = value) when module in @legacy_structs,
    do: value |> Map.drop([:__struct__, :__exception__]) |> Map.new(&normalize_pair/1)

  def normalize(value) when is_map(value),
    do: value |> Map.to_list() |> Map.new(&normalize_pair/1)

  def normalize(value) when is_list(value), do: Enum.map(value, &normalize/1)

  def normalize(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.map(&normalize/1) |> List.to_tuple()

  def normalize(value), do: value

  @doc "Rehydrates one owned domain record and migrates its private runtime fields."
  def decode(id, %State{id: id} = stored) when is_binary(id) do
    with version when version in [1, 2] <- Map.get(stored, :format_version, 1),
         fields <- stored |> normalize() |> Map.delete(:__struct__),
         fields <- migrate_fields(fields, version),
         session <- struct(State, fields),
         true <- State.loadable?(session) do
      {:ok, session}
    else
      _ -> :error
    end
  rescue
    _ -> :error
  end

  def decode(_id, _stored), do: :error

  defp migrate_fields(fields, version) do
    fields =
      fields
      |> Map.update(:events, [], fn events ->
        Enum.map(events, fn
          %Event{} = event -> struct(Event, Map.delete(event, :__struct__))
          other -> other
        end)
      end)
      |> Map.update(:turns, %{}, fn turns ->
        Map.new(turns, fn {id, turn} ->
          migrated = Map.put_new(turn, :runtime_turn_id, Map.get(turn, :harness_turn_id))
          {id, migrated}
        end)
      end)

    if version == 1 do
      fields
      |> Map.put(:format_version, 2)
      |> Map.update(:options, %{}, &migrate_plan/1)
      |> Map.put_new(:runtime_id, Map.get(fields, :harness_session_id))
      |> Map.put_new(:runtime_generation, nil)
      |> Map.put_new(
        :runtime_cursor,
        Map.get(fields, :cursor, 0) - Map.get(fields, :sequence_offset, 0)
      )
    else
      fields
    end
  end

  defp migrate_plan(%{provider_options: options} = fields) when is_map(options) do
    {plan, options} =
      if Map.has_key?(options, :plan),
        do: Map.pop(options, :plan),
        else: Map.pop(options, "plan")

    fields = Map.put(fields, :provider_options, Map.delete(options, "plan"))
    if is_boolean(plan), do: Map.put_new(fields, :plan, plan), else: fields
  end

  defp migrate_plan(fields), do: fields

  # Keys are identity, including maps/tuples containing retired tags. Rewriting a
  # key can collide with an existing plain-map key and silently discard history.
  defp normalize_pair({key, value}), do: {key, normalize(value)}
end
