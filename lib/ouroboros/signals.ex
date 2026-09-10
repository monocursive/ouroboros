defmodule Ouroboros.Signals.AgentMessage do
  @moduledoc """
  An owned typed point-to-point message between logical agents.

  The serialized envelope preserves its existing CloudEvents metadata and typed data.
  Delivery belongs to `Ouroboros.Mesh`; extensions are opaque data, with no registry,
  dispatcher, or executable module loading.
  """

  @derive {Jason.Encoder, except: [:jido_dispatch]}
  @enforce_keys [:id, :source, :type]
  defstruct [
    :id,
    :source,
    :type,
    :subject,
    :time,
    :dataschema,
    :data,
    # Historical metadata retained as data for map inspection; never dispatched.
    :jido_dispatch,
    specversion: "1.0.2",
    datacontenttype: "application/json",
    extensions: %{}
  ]

  @type t :: %__MODULE__{id: String.t(), source: String.t(), type: String.t(), data: map()}
  @schema [
    from: [type: :string, required: true],
    body: [type: :any, required: true],
    correlation_id: [type: :string, required: true],
    causation_id: [type: :any, default: nil]
  ]
  @options NimbleOptions.new!(@schema)
  @core ~w(id source type subject time dataschema data specversion datacontenttype extensions jido_dispatch)

  def type, do: "ouroboros.agent.message"
  def default_source, do: "/ouroboros/mesh"
  def schema, do: @schema

  @spec new(map(), keyword()) :: {:ok, t()} | {:error, String.t()}
  def new(data \\ %{}, opts \\ []) do
    with {:ok, validated} <- validate_data(data) do
      defaults = %{
        "id" => Ouroboros.ID.generate!(),
        "time" => DateTime.to_iso8601(DateTime.utc_now()),
        "source" => default_source(),
        "type" => type(),
        "specversion" => "1.0.2",
        "data" => validated
      }

      attrs =
        Enum.reduce(opts, defaults, fn {key, value}, acc ->
          Map.put(acc, to_string(key), value)
        end)

      from_attrs(attrs)
    end
  end

  @spec new!(map(), keyword()) :: t()
  def new!(data \\ %{}, opts \\ []) do
    case new(data, opts) do
      {:ok, message} -> message
      {:error, reason} -> raise ArgumentError, reason
    end
  end

  @spec validate_data(map()) :: {:ok, map()} | {:error, String.t()}
  def validate_data(data) when is_map(data) or is_list(data) do
    case NimbleOptions.validate(Enum.to_list(data), @options) do
      {:ok, validated} ->
        {:ok, Map.new(validated)}

      {:error, error} ->
        {:error, Ouroboros.Action.validation_message(error, "Signal", __MODULE__)}
    end
  end

  def validate_data(_data),
    do: {:error, "Invalid parameters for Signal (#{__MODULE__}): expected a map"}

  @doc "Validates an owned envelope before mesh dispatch."
  @spec validate(t()) :: {:ok, t()} | {:error, term()}
  def validate(%__MODULE__{type: "ouroboros.agent.message"} = message) do
    with {:ok, data} <- validate_data(message.data),
         {:ok, _source} <- required_string(message.source, "source"),
         {:ok, _id} <- required_string(message.id, "id") do
      {:ok, %{message | data: data}}
    end
  end

  def validate(_message), do: {:error, :unsupported_message_contract}

  defp from_attrs(attrs) do
    with :ok <- specversion(attrs["specversion"]),
         {:ok, message_type} <- required_string(attrs["type"], "type"),
         {:ok, source} <- required_string(attrs["source"], "source"),
         {:ok, id} <- identifier(attrs["id"]),
         {:ok, subject} <- optional_string(attrs["subject"], "subject"),
         {:ok, time} <- optional_string(attrs["time"], "time"),
         {:ok, content_type} <- optional_string(attrs["datacontenttype"], "datacontenttype"),
         {:ok, data_schema} <- optional_string(attrs["dataschema"], "dataschema") do
      extensions = if is_map(attrs["extensions"]), do: attrs["extensions"], else: %{}
      extensions = Map.merge(extensions, Map.drop(attrs, @core))

      {:ok,
       %__MODULE__{
         id: id,
         source: source,
         type: message_type,
         subject: subject,
         time: time,
         dataschema: data_schema,
         datacontenttype: content_type || "application/json",
         data: attrs["data"],
         extensions: extensions,
         jido_dispatch: attrs["jido_dispatch"]
       }}
    end
  end

  defp specversion("1.0.2"), do: :ok
  defp specversion(value), do: {:error, "parse error: unexpected specversion #{value}"}

  defp required_string(value, _field) when is_binary(value) and byte_size(value) > 0,
    do: {:ok, value}

  defp required_string(_value, field), do: {:error, "parse error: missing #{field}"}
  defp identifier(""), do: {:error, "parse error: id given but empty"}
  defp identifier(value) when is_binary(value), do: {:ok, value}
  defp identifier(_value), do: {:ok, Ouroboros.ID.generate!()}
  defp optional_string("", field), do: {:error, "parse error: #{field} given but empty"}
  defp optional_string(value, _field) when is_binary(value), do: {:ok, value}
  defp optional_string(_value, _field), do: {:ok, nil}
end
