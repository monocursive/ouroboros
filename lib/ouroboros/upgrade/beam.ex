defmodule Ouroboros.Upgrade.Beam do
  @moduledoc """
  One verified BEAM replacement and the pre-image needed for rollback.

  This struct is data only. It never compiles source and never loads code.
  """

  @enforce_keys [
    :module,
    :filename,
    :binary,
    :sha256,
    :md5,
    :vsn,
    :old_filename,
    :old_binary,
    :old_sha256,
    :old_md5,
    :old_vsn
  ]
  defstruct @enforce_keys ++ [stateful: false, migration_extra: nil]

  @type t :: %__MODULE__{
          module: module(),
          filename: charlist(),
          binary: binary(),
          sha256: String.t(),
          md5: binary(),
          vsn: term(),
          old_filename: charlist(),
          old_binary: binary(),
          old_sha256: String.t(),
          old_md5: binary(),
          old_vsn: term(),
          stateful: boolean(),
          migration_extra: term()
        }

  @doc "Builds a replacement from a BEAM binary and the node's current pre-image."
  @spec build(module(), binary(), keyword()) :: {:ok, t()} | {:error, term()}
  def build(module, binary, opts \\ []) when is_atom(module) and is_binary(binary) do
    stateful = Keyword.get(opts, :stateful, false)
    migration_extra = Keyword.get(opts, :migration_extra)

    with :ok <- validate_stateful(stateful),
         :ok <- validate_migration_extra(stateful, migration_extra),
         {:ok, new_info} <- inspect_binary(binary),
         :ok <- ensure_module(module, new_info.module),
         {:ok, {old_binary, old_filename}} <- old_object_code(module, opts),
         {:ok, old_info} <- inspect_binary(old_binary),
         :ok <- ensure_module(module, old_info.module),
         :ok <- ensure_current_md5(module, old_info.md5) do
      {:ok,
       %__MODULE__{
         module: module,
         filename: normalize_filename(Keyword.get(opts, :filename, "ouroboros://#{module}")),
         binary: binary,
         sha256: sha256(binary),
         md5: new_info.md5,
         vsn: new_info.vsn,
         old_filename: normalize_filename(old_filename),
         old_binary: old_binary,
         old_sha256: sha256(old_binary),
         old_md5: old_info.md5,
         old_vsn: old_info.vsn,
         stateful: stateful,
         migration_extra: migration_extra
       }}
    end
  end

  @doc false
  @spec inspect_binary(binary()) :: {:ok, map()} | {:error, term()}
  def inspect_binary(binary) when is_binary(binary) do
    with info when is_list(info) <- :beam_lib.info(binary),
         {:ok, module} <- Keyword.fetch(info, :module),
         {:ok, {^module, md5}} <- :beam_lib.md5(binary),
         {:ok, {^module, [attributes: attributes]}} <- :beam_lib.chunks(binary, [:attributes]),
         {:ok, {^module, [imports: imports]}} <- :beam_lib.chunks(binary, [:imports]) do
      {:ok,
       %{
         module: module,
         md5: md5,
         vsn: attributes |> Keyword.get(:vsn, [nil]) |> List.first(),
         on_load?: Keyword.has_key?(attributes, :on_load),
         protocol?:
           Keyword.has_key?(attributes, :__protocol__) or Keyword.has_key?(attributes, :__impl__),
         nif?: Enum.any?(imports, &match?({:erlang, :load_nif, 2}, &1))
       }}
    else
      {:error, reason} -> {:error, {:invalid_beam, reason}}
      other -> {:error, {:invalid_beam, other}}
    end
  rescue
    error -> {:error, {:invalid_beam, error}}
  end

  @doc false
  @spec sha256(binary()) :: String.t()
  def sha256(binary), do: :crypto.hash(:sha256, binary) |> Base.encode16(case: :lower)

  @doc false
  @spec portable_term?(term()) :: boolean()
  def portable_term?(term) when is_atom(term) or is_binary(term) or is_number(term), do: true
  def portable_term?(term) when is_list(term), do: Enum.all?(term, &portable_term?/1)

  def portable_term?(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.all?(&portable_term?/1)

  def portable_term?(term) when is_map(term) do
    not is_struct(term) and
      Enum.all?(term, fn {key, value} -> portable_term?(key) and portable_term?(value) end)
  end

  def portable_term?(_term), do: false

  @doc false
  @spec migration_extra_allowed?(term(), term()) :: boolean()
  def migration_extra_allowed?({:one_of, allowed}, actual) when is_list(allowed),
    do: actual in allowed

  def migration_extra_allowed?(expected, actual), do: expected == actual

  defp old_object_code(module, opts) do
    case Keyword.fetch(opts, :old_binary) do
      {:ok, old_binary} when is_binary(old_binary) ->
        {:ok, {old_binary, Keyword.get(opts, :old_filename, "ouroboros://preimage/#{module}")}}

      _ ->
        case :code.get_object_code(module) do
          {^module, old_binary, old_filename} -> {:ok, {old_binary, old_filename}}
          :error -> {:error, {:current_object_code_unavailable, module}}
        end
    end
  end

  defp ensure_module(module, module), do: :ok
  defp ensure_module(expected, actual), do: {:error, {:module_mismatch, expected, actual}}

  defp ensure_current_md5(module, expected_md5) do
    with {:module, ^module} <- Code.ensure_loaded(module),
         ^expected_md5 <- module.module_info(:md5) do
      :ok
    else
      {:error, reason} -> {:error, {:module_not_loaded, module, reason}}
      actual -> {:error, {:stale_preimage, module, expected_md5, actual}}
    end
  end

  defp normalize_filename(filename) when is_binary(filename), do: String.to_charlist(filename)
  defp normalize_filename(filename) when is_list(filename), do: filename

  defp validate_stateful(value) when is_boolean(value), do: :ok
  defp validate_stateful(value), do: {:error, {:invalid_stateful, value}}

  defp validate_migration_extra(false, nil), do: :ok

  defp validate_migration_extra(false, _extra),
    do: {:error, :migration_extra_for_stateless_module}

  defp validate_migration_extra(true, extra) do
    cond do
      not portable_term?(extra) ->
        {:error, :invalid_migration_extra}

      match?({:one_of, []}, extra) ->
        {:error, :empty_migration_extra_policy}

      match?({:one_of, values} when is_list(values), extra) and
          extra |> elem(1) |> Enum.uniq() != elem(extra, 1) ->
        {:error, :duplicate_migration_extra_policy}

      true ->
        :ok
    end
  end
end
