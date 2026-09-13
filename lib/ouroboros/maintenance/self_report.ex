defmodule Ouroboros.Maintenance.SelfReport do
  @moduledoc """
  Target-owned bounded Epoch and identity observations for cooperative maintenance.

  These files are self-reports consumed by the external controller. They are not
  authentication and are useful only when compared with independent process,
  listener, publication and imported-generation observations.
  """

  alias Ouroboros.Maintenance.Epoch

  @max_id 256

  @spec write_epoch(Path.t(), GenServer.server()) :: {:ok, map()} | {:error, term()}
  def write_epoch(data_dir, epoch_server \\ Epoch) do
    observation = Epoch.observe(epoch_server)

    with %{epoch: epoch, pending: pending} when is_integer(epoch) and epoch >= 0 <- observation,
         true <- is_list(pending),
         document = %{
           "schema" => 1,
           "epoch" => epoch,
           "pending" => Enum.map(pending, &reservation/1)
         },
         :ok <- publish(data_dir, "maintenance-epoch-observation.json", document) do
      {:ok, document}
    else
      false -> {:error, :invalid_epoch_observation}
      _ -> {:error, :invalid_epoch_observation}
    end
  catch
    :exit, reason -> {:error, {:epoch_observation_unavailable, reason}}
  end

  @spec write(Path.t(), map(), GenServer.server()) :: {:ok, map()} | {:error, term()}
  def write(data_dir, attrs, epoch_server \\ Epoch)

  def write(data_dir, attrs, epoch_server) when is_map(attrs) do
    with :ok <- fields(attrs),
         %{epoch: epoch, pending: []} <- Epoch.observe(epoch_server),
         document = %{
           "schema" => 1,
           "transaction_id" => attrs.transaction_id,
           "pid" => attrs.pid,
           "birth" => attrs.birth,
           "port" => attrs.port,
           "generation_digest" => attrs.generation_digest,
           "build_id" => attrs.build_id,
           "write_epoch" => epoch,
           "node" => Atom.to_string(node()),
           "distribution" => Node.alive?()
         },
         :ok <- publish(data_dir, "maintenance-self-report.json", document) do
      {:ok, document}
    else
      %{pending: [_ | _]} -> {:error, :pending_epoch_write}
      {:error, _} = error -> error
      _ -> {:error, :invalid_self_report}
    end
  catch
    :exit, reason -> {:error, {:epoch_observation_unavailable, reason}}
  end

  def write(_data_dir, _attrs, _epoch), do: {:error, :invalid_self_report}

  defp reservation(value) when is_map(value),
    do: Map.new(value, fn {key, item} -> {Atom.to_string(key), item} end)

  defp reservation(value), do: value

  defp fields(attrs) do
    required = [:transaction_id, :pid, :birth, :port, :generation_digest, :build_id]

    cond do
      Map.keys(attrs) |> Enum.sort() != Enum.sort(required) ->
        {:error, :invalid_self_report}

      not is_integer(attrs.pid) or attrs.pid <= 0 ->
        {:error, :invalid_self_report}

      not is_integer(attrs.port) or attrs.port < 1 or attrs.port > 65_535 ->
        {:error, :invalid_self_report}

      not Enum.all?(
        [attrs.transaction_id, attrs.birth, attrs.generation_digest, attrs.build_id],
        &id?/1
      ) ->
        {:error, :invalid_self_report}

      true ->
        :ok
    end
  end

  defp id?(value),
    do: is_binary(value) and value != "" and byte_size(value) <= @max_id and String.valid?(value)

  defp publish(data_dir, name, value) when is_binary(data_dir) do
    File.mkdir_p!(data_dir)
    final = Path.join(data_dir, name)
    temporary = final <> ".tmp-#{System.unique_integer([:positive])}"
    bytes = JSON.encode!(value)

    with :ok <- File.write(temporary, bytes, [:binary, :exclusive]),
         :ok <- File.chmod(temporary, 0o600),
         :ok <- fsync(temporary),
         :ok <- File.rename(temporary, final),
         :ok <- fsync(data_dir) do
      :ok
    else
      {:error, reason} ->
        _ = File.rm(temporary)
        {:error, {:self_report_publish_failed, reason}}
    end
  end

  defp publish(_, _, _), do: {:error, :invalid_data_dir}

  defp fsync(path) do
    options = if File.dir?(path), do: [:read, :raw, :directory], else: [:read, :raw]

    with {:ok, file} <- :file.open(String.to_charlist(path), options) do
      result = :file.sync(file)
      :ok = :file.close(file)
      result
    end
  end
end
