defmodule Ouroboros.Release.Metadata do
  @moduledoc """
  Pure builders and fail-closed validators for OTP release metadata.

  This module only works with Erlang terms. It does not write files, load code,
  or call `:release_handler`. `encode/1` emits the textual term format expected
  by `.rel`, `.appup`, and `relup` files.
  """

  @application_types [:permanent, :transient, :temporary, :load, :none]
  @purge_modes [:soft_purge, :brutal_purge]
  @module_types [:dynamic, :static]

  @type summary :: map()

  @spec rel(String.t(), String.t(), [{atom(), String.t()} | tuple()], keyword()) ::
          {:ok, term()} | {:error, term()}
  def rel(name, version, applications, opts \\ [])

  def rel(name, version, applications, opts)
      when is_binary(name) and is_binary(version) and is_list(applications) and is_list(opts) do
    with true <- Keyword.keyword?(opts) || {:error, :invalid_options},
         {:ok, erts_version} <- normalize_version(Keyword.get(opts, :erts, erts_version())),
         {:ok, name} <- normalize_text(name, :release_name),
         {:ok, version} <- normalize_version(version),
         :ok <- validate_application_entries(applications) do
      term =
        {:release, {String.to_charlist(name), String.to_charlist(version)},
         {:erts, String.to_charlist(erts_version)},
         Enum.map(applications, &external_application/1)}

      {:ok, term}
    end
  end

  def rel(_name, _version, _applications, _opts), do: {:error, :invalid_release_metadata}

  @spec appup(String.t(), list(), list()) :: {:ok, term()} | {:error, term()}
  def appup(version, upgrades, downgrades)
      when is_binary(version) and is_list(upgrades) and is_list(downgrades) do
    term =
      {String.to_charlist(version), external_transitions(upgrades),
       external_transitions(downgrades)}

    case validate_appup(term) do
      {:ok, _summary} -> {:ok, term}
      {:error, _reason} = error -> error
    end
  end

  def appup(_version, _upgrades, _downgrades), do: {:error, :invalid_appup}

  @spec relup(String.t(), list(), list()) :: {:ok, term()} | {:error, term()}
  def relup(version, upgrades, downgrades)
      when is_binary(version) and is_list(upgrades) and is_list(downgrades) do
    term =
      {String.to_charlist(version), external_transitions(upgrades),
       external_transitions(downgrades)}

    case validate_relup(term) do
      {:ok, _summary} -> {:ok, term}
      {:error, _reason} = error -> error
    end
  end

  def relup(_version, _upgrades, _downgrades), do: {:error, :invalid_relup}

  @spec validate_rel(term()) :: {:ok, summary()} | {:error, term()}
  def validate_rel({:release, {name, version}, {:erts, erts_version}, applications})
      when is_list(applications) do
    with {:ok, name} <- normalize_text(name, :release_name),
         {:ok, version} <- normalize_version(version),
         {:ok, erts_version} <- normalize_version(erts_version),
         :ok <- validate_application_entries(applications) do
      {:ok,
       %{
         name: name,
         version: version,
         erts_version: erts_version,
         applications: Enum.map(applications, &summarize_application/1)
       }}
    end
  end

  def validate_rel(_term), do: {:error, :invalid_rel}

  @spec validate_appup(term()) :: {:ok, summary()} | {:error, term()}
  def validate_appup({version, upgrades, downgrades})
      when is_list(upgrades) and is_list(downgrades) do
    with {:ok, version} <- normalize_version(version),
         {:ok, upgrades} <- validate_transitions(upgrades, :appup),
         {:ok, downgrades} <- validate_transitions(downgrades, :appup) do
      {:ok, %{version: version, upgrades: upgrades, downgrades: downgrades}}
    end
  end

  def validate_appup(_term), do: {:error, :invalid_appup}

  @spec validate_relup(term()) :: {:ok, summary()} | {:error, term()}
  def validate_relup({version, upgrades, downgrades})
      when is_list(upgrades) and is_list(downgrades) do
    with {:ok, version} <- normalize_version(version),
         {:ok, upgrades} <- validate_transitions(upgrades, :relup),
         {:ok, downgrades} <- validate_transitions(downgrades, :relup) do
      {:ok, %{version: version, upgrades: upgrades, downgrades: downgrades}}
    end
  end

  def validate_relup(_term), do: {:error, :invalid_relup}

  @doc "Encodes one metadata term without evaluating it or writing it to disk."
  @spec encode(term()) :: binary()
  def encode(term) do
    IO.iodata_to_binary(:io_lib.format(~c"~tp.~n", [term]))
  end

  @doc false
  @spec parse(binary(), atom()) :: {:ok, term()} | {:error, term()}
  def parse(binary, kind) when is_binary(binary) and byte_size(binary) <= 262_144 do
    with {:ok, tokens, _end_location} <- :erl_scan.string(String.to_charlist(binary)),
         {:ok, term} <- :erl_parse.parse_term(tokens),
         {:ok, summary} <- validate(kind, term) do
      {:ok, {term, summary}}
    else
      {:error, reason} -> {:error, {:invalid_metadata, kind, reason}}
      {:error, reason, location} -> {:error, {:invalid_metadata, kind, location, reason}}
      other -> {:error, {:invalid_metadata, kind, other}}
    end
  rescue
    error -> {:error, {:invalid_metadata, kind, error}}
  catch
    kind, reason -> {:error, {:invalid_metadata, kind, reason}}
  end

  def parse(_binary, kind), do: {:error, {:invalid_metadata_size, kind}}

  defp validate(:rel, term), do: validate_rel(term)
  defp validate(:appup, term), do: validate_appup(term)
  defp validate(:relup, term), do: validate_relup(term)
  defp validate(kind, _term), do: {:error, {:unsupported_metadata_kind, kind}}

  defp validate_application_entries(applications) do
    with :ok <- reduce_valid(applications, &validate_application/1),
         names <- Enum.map(applications, &elem(&1, 0)),
         true <- names == Enum.uniq(names) || {:error, :duplicate_applications} do
      :ok
    end
  end

  defp validate_application({name, version}) when is_atom(name) do
    normalize_version(version) |> ok_only()
  end

  defp validate_application({name, version, included})
       when is_atom(name) and is_list(included) do
    with {:ok, _version} <- normalize_version(version),
         true <- Enum.all?(included, &is_atom/1) || {:error, {:invalid_included_apps, name}} do
      :ok
    end
  end

  defp validate_application({name, version, type})
       when is_atom(name) and type in @application_types do
    normalize_version(version) |> ok_only()
  end

  defp validate_application({name, version, type, included})
       when is_atom(name) and type in @application_types and is_list(included) do
    with {:ok, _version} <- normalize_version(version),
         true <- Enum.all?(included, &is_atom/1) || {:error, {:invalid_included_apps, name}} do
      :ok
    end
  end

  defp validate_application(application), do: {:error, {:invalid_application, application}}

  defp external_application({name, version}), do: {name, String.to_charlist(version)}

  defp external_application({name, version, third}) when is_binary(version),
    do: {name, String.to_charlist(version), third}

  defp external_application({name, version, type, included}) when is_binary(version),
    do: {name, String.to_charlist(version), type, included}

  defp external_application(application), do: application

  defp summarize_application(application) do
    application
    |> Tuple.to_list()
    |> List.update_at(1, fn version -> normalize_version!(version) end)
    |> List.to_tuple()
  end

  defp validate_transitions(transitions, kind) do
    with :ok <- reduce_valid(transitions, &validate_transition(&1, kind)),
         versions <- Enum.map(transitions, &transition_version/1),
         true <- versions == Enum.uniq(versions) || {:error, :duplicate_transition_versions} do
      {:ok,
       Enum.map(transitions, fn {version, _description, instructions} ->
         applies = Enum.flat_map(instructions, &apply_summary/1)

         %{
           version: normalize_version!(version),
           instruction_count: length(instructions),
           restart?: Enum.any?(instructions, &restart_instruction?/1),
           point_of_no_return?: :point_of_no_return in instructions,
           brutal_purge?: Enum.any?(instructions, &brutal_purge_instruction?/1),
           applies: applies
         }
       end)}
    end
  end

  defp validate_transition({version, _description, instructions}, kind)
       when is_list(instructions) do
    with {:ok, _version} <- normalize_version(version),
         false <- instructions == [] && {:error, :empty_upgrade_script},
         :ok <- reduce_valid(instructions, &validate_instruction(&1, kind)) do
      :ok
    end
  end

  defp validate_transition(transition, _kind), do: {:error, {:invalid_transition, transition}}

  defp validate_instruction(instruction, :appup), do: validate_appup_instruction(instruction)
  defp validate_instruction(instruction, :relup), do: validate_relup_instruction(instruction)

  defp validate_appup_instruction({:update, module}) when is_atom(module), do: :ok

  defp validate_appup_instruction({:update, module, change})
       when is_atom(module) and (change == :soft or is_tuple(change)),
       do: :ok

  defp validate_appup_instruction({:update, module, modules})
       when is_atom(module) and is_list(modules),
       do: validate_modules(modules)

  defp validate_appup_instruction({:update, module, change, modules})
       when is_atom(module) and (change == :soft or is_tuple(change)) and is_list(modules),
       do: validate_modules(modules)

  defp validate_appup_instruction({:update, module, change, pre, post, modules})
       when is_atom(module) and is_list(modules) do
    validate_update_fields(change, pre, post, modules)
  end

  defp validate_appup_instruction({:update, module, timeout, change, pre, post, modules})
       when is_atom(module) and is_list(modules) do
    with :ok <- validate_timeout(timeout),
         :ok <- validate_update_fields(change, pre, post, modules) do
      :ok
    end
  end

  defp validate_appup_instruction({:update, module, type, timeout, change, pre, post, modules})
       when is_atom(module) and type in @module_types and is_list(modules) do
    with :ok <- validate_timeout(timeout),
         :ok <- validate_update_fields(change, pre, post, modules) do
      :ok
    end
  end

  defp validate_appup_instruction({:load_module, module}) when is_atom(module), do: :ok

  defp validate_appup_instruction({:load_module, module, modules})
       when is_atom(module) and is_list(modules),
       do: validate_modules(modules)

  defp validate_appup_instruction({:load_module, module, pre, post, modules})
       when is_atom(module) and pre in @purge_modes and post in @purge_modes and is_list(modules),
       do: validate_modules(modules)

  defp validate_appup_instruction({operation, module})
       when operation in [:add_module, :delete_module] and is_atom(module),
       do: :ok

  defp validate_appup_instruction({operation, module, modules})
       when operation in [:add_module, :delete_module] and is_atom(module) and is_list(modules),
       do: validate_modules(modules)

  defp validate_appup_instruction({:restart_application, application}) when is_atom(application),
    do: :ok

  defp validate_appup_instruction({:remove_application, application}) when is_atom(application),
    do: :ok

  defp validate_appup_instruction({:add_application, application}) when is_atom(application),
    do: :ok

  defp validate_appup_instruction({:add_application, application, type})
       when is_atom(application) and type in @application_types,
       do: :ok

  defp validate_appup_instruction({:apply, {module, function, args}})
       when is_atom(module) and is_atom(function) and is_list(args),
       do: :ok

  defp validate_appup_instruction(instruction)
       when instruction in [:restart, :reboot, :restart_new_emulator, :restart_emulator],
       do: :ok

  defp validate_appup_instruction(instruction),
    do: {:error, {:invalid_appup_instruction, instruction}}

  defp validate_relup_instruction(:point_of_no_return), do: :ok
  defp validate_relup_instruction(:restart_new_emulator), do: :ok
  defp validate_relup_instruction(:restart_emulator), do: :ok

  defp validate_relup_instruction({:load_object_code, {library, version, modules}})
       when is_atom(library) and is_list(modules) do
    with {:ok, _version} <- normalize_version(version), :ok <- validate_modules(modules), do: :ok
  end

  defp validate_relup_instruction({operation, {module, pre, post}})
       when operation in [:load, :remove] and is_atom(module) and pre in @purge_modes and
              post in @purge_modes,
       do: :ok

  defp validate_relup_instruction({operation, modules})
       when operation in [:purge, :resume, :stop, :start] and is_list(modules),
       do: validate_modules(modules)

  defp validate_relup_instruction({:suspend, modules}) when is_list(modules) do
    reduce_valid(modules, fn
      module when is_atom(module) -> :ok
      {module, timeout} when is_atom(module) -> validate_timeout(timeout)
      other -> {:error, {:invalid_suspend_target, other}}
    end)
  end

  defp validate_relup_instruction({:code_change, changes}) when is_list(changes),
    do: validate_code_changes(changes)

  defp validate_relup_instruction({:code_change, mode, changes})
       when mode in [:up, :down] and is_list(changes),
       do: validate_code_changes(changes)

  defp validate_relup_instruction({:sync_nodes, _id, {module, function, args}})
       when is_atom(module) and is_atom(function) and is_list(args),
       do: :ok

  defp validate_relup_instruction({:sync_nodes, _id, nodes}) when is_list(nodes) do
    if Enum.all?(nodes, &is_atom/1), do: :ok, else: {:error, :invalid_sync_nodes}
  end

  defp validate_relup_instruction({:apply, {module, function, args}})
       when is_atom(module) and is_atom(function) and is_list(args),
       do: :ok

  defp validate_relup_instruction(instruction),
    do: {:error, {:invalid_relup_instruction, instruction}}

  defp validate_update_fields(change, pre, post, modules) do
    with true <- (change == :soft or match?({:advanced, _}, change)) || {:error, :invalid_change},
         true <- pre in @purge_modes || {:error, :invalid_pre_purge},
         true <- post in @purge_modes || {:error, :invalid_post_purge},
         :ok <- validate_modules(modules) do
      :ok
    end
  end

  defp validate_code_changes(changes) do
    reduce_valid(changes, fn
      {module, _extra} when is_atom(module) -> :ok
      other -> {:error, {:invalid_code_change, other}}
    end)
  end

  defp validate_modules(modules) do
    if Enum.all?(modules, &is_atom/1), do: :ok, else: {:error, :invalid_modules}
  end

  defp validate_timeout(:default), do: :ok
  defp validate_timeout(:infinity), do: :ok
  defp validate_timeout(timeout) when is_integer(timeout) and timeout > 0, do: :ok
  defp validate_timeout(timeout), do: {:error, {:invalid_timeout, timeout}}

  defp normalize_text(value, label) when is_binary(value) do
    if valid_text?(value), do: {:ok, value}, else: {:error, {:invalid_text, label}}
  end

  defp normalize_text(value, label) when is_list(value) do
    case List.to_string(value) do
      value when is_binary(value) -> normalize_text(value, label)
    end
  rescue
    _error -> {:error, {:invalid_text, label}}
  end

  defp normalize_text(_value, label), do: {:error, {:invalid_text, label}}

  defp normalize_version(value) do
    with {:ok, value} <- normalize_text(value, :version),
         true <- byte_size(value) <= 128 || {:error, :version_too_long} do
      {:ok, value}
    end
  end

  defp normalize_version!(value) do
    {:ok, version} = normalize_version(value)
    version
  end

  defp valid_text?(value) do
    value != "" and byte_size(value) <= 512 and String.valid?(value) and
      not String.contains?(value, [<<0>>, "\n", "\r"])
  end

  defp external_transitions(transitions) do
    Enum.map(transitions, fn
      {version, description, instructions} when is_binary(version) ->
        {String.to_charlist(version), description, instructions}

      transition ->
        transition
    end)
  end

  defp transition_version({version, _description, _instructions}), do: normalize_version!(version)

  defp restart_instruction?(instruction),
    do: instruction in [:restart, :reboot, :restart_emulator, :restart_new_emulator]

  defp brutal_purge_instruction?(instruction) when is_tuple(instruction) do
    instruction
    |> Tuple.to_list()
    |> Enum.any?(&contains_brutal_purge?/1)
  end

  defp brutal_purge_instruction?(_instruction), do: false

  defp contains_brutal_purge?(:brutal_purge), do: true
  defp contains_brutal_purge?(value) when is_tuple(value), do: brutal_purge_instruction?(value)

  defp contains_brutal_purge?(value) when is_list(value),
    do: Enum.any?(value, &contains_brutal_purge?/1)

  defp contains_brutal_purge?(_value), do: false

  defp apply_summary({:apply, {module, function, args}})
       when is_atom(module) and is_atom(function) and is_list(args) do
    [%{module: module, function: function, arity: length(args)}]
  end

  defp apply_summary(_instruction), do: []

  defp reduce_valid(enumerable, validator) do
    Enum.reduce_while(enumerable, :ok, fn item, :ok ->
      case validator.(item) do
        :ok -> {:cont, :ok}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp ok_only({:ok, _value}), do: :ok
  defp ok_only({:error, _reason} = error), do: error

  defp erts_version, do: :erlang.system_info(:version) |> to_string()
end
