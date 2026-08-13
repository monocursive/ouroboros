defmodule Ouroboros.Upgrade.Forge.Source do
  @moduledoc """
  Agent-authored Elixir source for one new capability module, and its parse-only checks.

  `validate/1` never evaluates, expands, or compiles anything. It reads the declared
  module name, asks `Code.string_to_quoted/1` for an AST, and walks that AST looking for
  constructs a capability has no business containing. Nothing in this module can define a
  module, start a process, or touch the filesystem, which is why a rejected source leaves
  `:code.which/1` answering `:non_existing` for the name it declared.

  ## This is hygiene, not a sandbox

  The deny list catches accidents and obvious mistakes: a capability that shells out, a
  capability that rewrites application environment, a capability that spawns onto another
  node. It does not and cannot stop a determined author. A macro expands after this walk
  has finished, so `use SomethingInnocent` may inject every denied construct at once;
  `apply/3` resolves module and function at runtime; `Module.concat/1` builds names out of
  strings. Treating this list as a security boundary would be a mistake.

  The real boundaries are elsewhere and each is enforced by something other than string
  inspection: the build peer is a separate, non-distributed OS process that compiles and
  runs the candidate's tests where the production cluster is unreachable
  (`Ouroboros.Upgrade.Forge.BuildPeer`); the verifier re-checks the compiled BEAM's
  features and the module's absence on the loading node
  (`Ouroboros.Upgrade.Verifier`); and the `Ouroboros.Capability.` namespace policy keeps
  a forged module from taking a name that already means something. Even those are policy,
  not a sandbox: any BEAM the loader accepts runs with full ambient VM authority.

  ## One module per source

  A forged capability is exactly one BEAM module. Nested `defmodule`s parse fine here and
  are rejected by the sandbox, which sees the real compiler output. Helper modules an
  agent wants to call must already exist on the target nodes.
  """

  alias Ouroboros.Upgrade.Beam

  @enforce_keys [:id, :module, :source, :author, :created_at, :sha256]
  defstruct @enforce_keys ++ [test_source: nil]

  @type t :: %__MODULE__{
          id: String.t(),
          module: module(),
          source: String.t(),
          test_source: String.t() | nil,
          author: String.t(),
          created_at: String.t(),
          sha256: String.t()
        }

  @capability_name ~r/^Ouroboros\.Capability\.[A-Z][A-Za-z0-9_]*(\.[A-Z][A-Za-z0-9_]*)*$/

  # Every function of these modules is refused. Reaching the code server, the filesystem,
  # another node, or an OS process is not something a capability does by accident.
  @denied_elixir_modules [Code, Port, Node, File]
  @denied_erlang_modules [:code, :file, :erpc, :rpc, :persistent_term]

  # Modules a capability may legitimately use, minus the specific calls it may not.
  @denied_elixir_calls [{System, :cmd}, {System, :shell}, {Application, :put_env}]
  @denied_erlang_calls [{:erlang, :load_nif}, {:os, :cmd}, {:ets, :give_away}]

  # `spawn(node, fun)` and `spawn(node, m, f, a)` name a node; their 1- and 3-argument
  # siblings are local. The arity is the whole signal.
  @spawn_functions [:spawn, :spawn_link, :spawn_monitor]
  @remote_spawn_arities [2, 4]

  @doc """
  Builds a source record, computing its id, creation time, and content digest.
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, term()}
  def new(attrs) when is_list(attrs) do
    with {:ok, module} <- fetch_module(attrs),
         {:ok, source} <- fetch_string(attrs, :source),
         {:ok, test_source} <- fetch_optional_string(attrs, :test_source),
         {:ok, author} <- fetch_string(attrs, :author) do
      {:ok,
       %__MODULE__{
         id: Keyword.get_lazy(attrs, :id, &Jido.Signal.ID.generate!/0),
         module: module,
         source: source,
         test_source: test_source,
         author: author,
         created_at: Keyword.get_lazy(attrs, :created_at, &now/0),
         sha256: Beam.sha256(source)
       }}
    end
  end

  @doc """
  Checks a source record without evaluating it.

  Returns the record unchanged on success. Failures are named:
  `{:invalid_module_name, name}`, `{:parse_failed, where, reason}`,
  `{:expected_single_module, names}`, `{:module_mismatch, declared, defined}`,
  `{:unexpected_top_level_form, line}`, and `{:forbidden_construct, construct, line}`.
  """
  @spec validate(t()) :: {:ok, t()} | {:error, term()}
  def validate(%__MODULE__{} = source) do
    with :ok <- validate_shape(source),
         :ok <- validate_module_name(source.module),
         {:ok, ast} <- parse(source.source, :source),
         :ok <- validate_single_module(ast, source.module),
         :ok <- scan(ast),
         :ok <- validate_test_source(source.test_source) do
      {:ok, source}
    end
  end

  def validate(other), do: {:error, {:invalid_source, other}}

  defp validate_shape(%__MODULE__{} = source) do
    cond do
      not is_atom(source.module) -> {:error, {:invalid_module_name, source.module}}
      not is_binary(source.source) or source.source == "" -> {:error, :empty_source}
      not is_binary(source.author) or source.author == "" -> {:error, :missing_author}
      source.sha256 != Beam.sha256(source.source) -> {:error, :source_digest_mismatch}
      true -> :ok
    end
  end

  defp validate_module_name(module) do
    name = module |> Atom.to_string() |> String.replace_prefix("Elixir.", "")

    if Regex.match?(@capability_name, name) do
      :ok
    else
      {:error, {:invalid_module_name, name}}
    end
  end

  defp validate_test_source(nil), do: :ok

  defp validate_test_source(test_source) do
    with {:ok, ast} <- parse(test_source, :test_source) do
      scan(ast)
    end
  end

  defp parse(string, where) when is_binary(string) do
    case Code.string_to_quoted(string) do
      {:ok, ast} -> {:ok, ast}
      {:error, reason} -> {:error, {:parse_failed, where, reason}}
    end
  rescue
    error -> {:error, {:parse_failed, where, Exception.message(error)}}
  end

  defp parse(other, where), do: {:error, {:parse_failed, where, {:not_a_string, other}}}

  defp validate_single_module(ast, declared) do
    forms = top_level_forms(ast)

    case Enum.split_with(forms, &defmodule?/1) do
      {[module_form], []} ->
        ensure_declared_module(module_form, declared)

      {[_module_form], [other | _rest]} ->
        {:error, {:unexpected_top_level_form, form_line(other)}}

      {modules, _other} ->
        {:error, {:expected_single_module, Enum.map(modules, &module_name/1)}}
    end
  end

  defp top_level_forms({:__block__, _meta, forms}), do: forms
  defp top_level_forms(form), do: [form]

  defp defmodule?({:defmodule, _meta, [_name, _body]}), do: true
  defp defmodule?(_form), do: false

  defp ensure_declared_module(form, declared) do
    case module_name(form) do
      ^declared -> :ok
      other -> {:error, {:module_mismatch, declared, other}}
    end
  end

  defp module_name({:defmodule, _meta, [{:__aliases__, _alias_meta, parts}, _body]}),
    do: alias_module(parts)

  defp module_name({:defmodule, _meta, [name, _body]}) when is_atom(name), do: name
  defp module_name({:defmodule, _meta, [other, _body]}), do: other

  defp form_line({_form, meta, _args}) when is_list(meta), do: Keyword.get(meta, :line, 0)
  defp form_line(_form), do: 0

  # Every violation is collected rather than only the first, so the walk cannot be steered
  # by ordering; the earliest one is reported.
  defp scan(ast) do
    {_ast, violations} = Macro.prewalk(ast, [], &collect_violation/2)

    case Enum.reverse(violations) do
      [] -> :ok
      [{construct, line} | _rest] -> {:error, {:forbidden_construct, construct, line}}
    end
  end

  defp collect_violation(node, violations) do
    case violation(node) do
      nil -> {node, violations}
      violation -> {node, [violation | violations]}
    end
  end

  defp violation({:@, meta, [{:on_load, _attribute_meta, _value}]}), do: {:on_load, line(meta)}

  defp violation({directive, meta, [_ | _] = args})
       when directive in [:defprotocol, :defimpl] and is_list(meta),
       do: if(protocol_definition?(args), do: {directive, line(meta)})

  defp violation({directive, meta, [{:__aliases__, _alias_meta, parts} | _rest]})
       when directive in [:alias, :import, :require] do
    module = alias_module(parts)
    if module in reachable_denied_modules(), do: {{directive, module}, line(meta)}
  end

  defp violation({{:., _dot_meta, [{:__aliases__, _alias_meta, parts}, function]}, meta, _args}) do
    module = alias_module(parts)

    cond do
      module in @denied_elixir_modules -> {module, line(meta)}
      {module, function} in @denied_elixir_calls -> {{module, function}, line(meta)}
      true -> nil
    end
  end

  defp violation({{:., _dot_meta, [module, function]}, meta, args}) when is_atom(module) do
    cond do
      module in @denied_erlang_modules ->
        {module, line(meta)}

      {module, function} in @denied_erlang_calls ->
        {{module, function}, line(meta)}

      module == :erlang and function in @spawn_functions and remote_spawn_arity?(args) ->
        {:remote_spawn, line(meta)}

      true ->
        nil
    end
  end

  defp violation({function, meta, args})
       when function in @spawn_functions and is_list(meta) do
    if remote_spawn_arity?(args), do: {:remote_spawn, line(meta)}
  end

  defp violation(_node), do: nil

  defp remote_spawn_arity?(args) when is_list(args), do: length(args) in @remote_spawn_arities
  defp remote_spawn_arity?(_args), do: false

  # `defimpl Enumerable, for: X` and `defprotocol Shape` define or extend a consolidated
  # protocol. A bare `defimpl`-shaped call with no arguments is not one.
  defp protocol_definition?([{:__aliases__, _meta, _parts} | _rest]), do: true
  defp protocol_definition?(_args), do: false

  defp reachable_denied_modules do
    @denied_elixir_modules ++ Enum.map(@denied_elixir_calls, &elem(&1, 0))
  end

  # A name built out of `unquote/1` is not a name this walk can read, and pretending
  # otherwise would raise inside the validator.
  defp alias_module([:"Elixir" | parts]) when parts != [], do: alias_module(parts)

  defp alias_module(parts) when is_list(parts) do
    if Enum.all?(parts, &is_atom/1), do: Module.concat(parts)
  end

  defp alias_module(_parts), do: nil

  defp line(meta) when is_list(meta), do: Keyword.get(meta, :line, 0)
  defp line(_meta), do: 0

  defp fetch_module(attrs) do
    case Keyword.fetch(attrs, :module) do
      {:ok, module} when is_atom(module) -> {:ok, module}
      {:ok, other} -> {:error, {:invalid_module_name, other}}
      :error -> {:error, {:missing_attribute, :module}}
    end
  end

  defp fetch_string(attrs, key) do
    case Keyword.fetch(attrs, key) do
      {:ok, value} when is_binary(value) and value != "" -> {:ok, value}
      {:ok, other} -> {:error, {:invalid_attribute, key, other}}
      :error -> {:error, {:missing_attribute, key}}
    end
  end

  defp fetch_optional_string(attrs, key) do
    case Keyword.get(attrs, key) do
      nil -> {:ok, nil}
      value when is_binary(value) and value != "" -> {:ok, value}
      other -> {:error, {:invalid_attribute, key, other}}
    end
  end

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
