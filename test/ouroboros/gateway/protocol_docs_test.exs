defmodule Ouroboros.Gateway.ProtocolDocsTest.Contract do
  @moduledoc """
  What a source file actually enforces about a `params` map, read out of its own AST.

  This exists so that `Ouroboros.Gateway.Methods`'s `@params` — the data
  `mix ouroboros.protocol.docs` generates the reference from — cannot drift from the
  validators in the same file. The alternative was to make every `invoke/2` clause read
  its allowlist out of one map, which would have meant rewriting thirty-eight clauses in a
  module three other slices are editing; parsing is the change that stays out of their way
  and proves the same thing.

  Nothing here is specific to a method. It resolves four mechanisms generically:

    * `only_keys(params, <keys>)`, where `<keys>` may be a literal list, a list splicing
      `Map.keys(@attr)`, or a variable bound to one of the function's own arguments — which
      is how `with_session(params, plane, ["id", "node"], fun)` passes its allowlist in.
    * `options(params, @attr)` / `options(params, @attr, <positional>)`, whose allowlist is
      the attribute's keys plus the positional arguments it drops first.
    * A call to any other function in the file that takes `params`, resolved recursively —
      which is how `with_replay/3`, `with_turn/3`, `session_target/2` and `team/1` are
      followed without naming them.
    * `fetch_*(params, "key")` and `Map.get(params, "key" [, default])`, which say which
      keys a clause with no allowlist reads at all.

  Requirement is inferred only from a helper whose *name* states it — `fetch_optional_*`
  is optional, `fetch_string`/`fetch_request_string` are required, `permission_scope/4`
  carries it as an argument, and a three-argument `Map.get` names its default. Everything
  else contributes the key and no claim about it, because a guess in a test is worse than
  a gap in one.
  """

  @doc "Parses one file into the attribute keys and the function clauses it defines."
  @spec read(Path.t()) :: %{attrs: map(), funs: map()}
  def read(path) do
    ast = path |> File.read!() |> Code.string_to_quoted!()
    %{attrs: attributes(ast), funs: functions(ast)}
  end

  @doc """
  The effective contract of one method: `%{envelope:, keys:, requirements:}`.

  `entry` is `{env, {function, arity}}` for a method the connection answers, or
  `{env, {:invoke, method}}` for one dispatched through `Methods.invoke/2`.
  """
  @spec of(term()) :: %{envelope: :closed | :open, keys: [String.t()], requirements: map()}
  def of({env, {:invoke, method}}) do
    case invoke_clause(env, method) do
      nil -> %{envelope: :open, keys: [], requirements: %{}}
      clause -> clause |> resolve_clause(env, %{}, MapSet.new()) |> present()
    end
  end

  def of({env, {name, arity}}) do
    env |> resolve(name, arity, %{}, MapSet.new()) |> present()
  end

  @doc "The `invoke/2` clause for one method name, or `nil` when the module has none."
  @spec invoke_clause(map(), String.t()) :: map() | nil
  def invoke_clause(env, method) do
    env.funs
    |> Map.get({:invoke, 2}, [])
    |> Enum.find(fn clause -> match?([^method | _], clause.args) end)
  end

  defp present(%{allow: allow, reads: reads, req: req}) do
    {envelope, keys} =
      case allow do
        nil -> {:open, MapSet.to_list(reads)}
        keys -> {:closed, keys}
      end

    %{envelope: envelope, keys: Enum.sort(keys), requirements: req}
  end

  # ---------------------------------------------------------------------------
  # Resolution
  # ---------------------------------------------------------------------------

  defp resolve(env, name, arity, bound, seen) do
    key = {name, arity}

    if MapSet.member?(seen, key) do
      empty()
    else
      seen = MapSet.put(seen, key)

      env.funs
      |> Map.get(key, [])
      |> Enum.reduce(empty(), fn clause, acc ->
        merge(acc, resolve_clause(clause, env, bound, seen))
      end)
    end
  end

  defp resolve_clause(clause, env, bound, seen) do
    names = arg_names(clause.args)
    analysed = analyse(clause.body, env.attrs, names)

    own = %{
      allow: resolve_allow(analysed.allow, bound),
      reads: analysed.reads,
      req: analysed.req
    }

    Enum.reduce(analysed.calls, own, fn {name, arity, args}, acc ->
      sub_bound =
        args
        |> Enum.with_index()
        |> Enum.reduce(%{}, fn {arg, index}, map ->
          case resolve_keys(arg, env.attrs, names) do
            {:ok, keys} -> Map.put(map, index, keys)
            _other -> map
          end
        end)

      merge(acc, resolve(env, name, arity, sub_bound, seen))
    end)
  end

  defp resolve_allow({:keys, keys}, _bound), do: keys
  defp resolve_allow({:from_arg, index}, bound), do: Map.get(bound, index)
  defp resolve_allow(_other, _bound), do: nil

  defp empty, do: %{allow: nil, reads: MapSet.new(), req: %{}}

  defp merge(a, b) do
    %{
      allow: a.allow || b.allow,
      reads: MapSet.union(a.reads, b.reads),
      req: Map.merge(b.req, a.req)
    }
  end

  # ---------------------------------------------------------------------------
  # Reading the tree
  # ---------------------------------------------------------------------------

  defp attributes(ast) do
    {_ast, acc} =
      Macro.prewalk(ast, %{}, fn
        {:@, _, [{name, _, [{:%{}, _, pairs}]}]} = node, acc when is_atom(name) ->
          keys = for {key, _value} <- pairs, is_binary(key), do: key
          if keys == [], do: {node, acc}, else: {node, Map.put(acc, name, Enum.sort(keys))}

        node, acc ->
          {node, acc}
      end)

    acc
  end

  defp functions(ast) do
    {_ast, acc} =
      Macro.prewalk(ast, %{}, fn
        {kind, _, [head, body]} = node, acc when kind in [:def, :defp] ->
          case clause_head(head) do
            {name, args} ->
              key = {name, length(args)}

              {node,
               Map.update(
                 acc,
                 key,
                 [%{args: args, body: body}],
                 &[%{args: args, body: body} | &1]
               )}

            :none ->
              {node, acc}
          end

        node, acc ->
          {node, acc}
      end)

    acc
  end

  defp clause_head({:when, _, [inner, _guard]}), do: clause_head(inner)
  defp clause_head({name, _, args}) when is_atom(name) and is_list(args), do: {name, args}
  defp clause_head(_other), do: :none

  defp arg_names(args) do
    Enum.map(args, fn
      {name, _, context} when is_atom(name) and is_atom(context) -> name
      _other -> nil
    end)
  end

  defp analyse(body, attrs, names) do
    {_ast, acc} =
      Macro.prewalk(body, %{allow: nil, reads: MapSet.new(), req: %{}, calls: []}, fn node, acc ->
        {node, visit(node, acc, attrs, names)}
      end)

    acc
  end

  defp visit({:only_keys, _, [_params, expr]}, acc, attrs, names) do
    case resolve_keys(expr, attrs, names) do
      {:ok, keys} -> %{acc | allow: acc.allow || {:keys, keys}}
      {:from_arg, index} -> %{acc | allow: acc.allow || {:from_arg, index}}
      :error -> %{acc | allow: acc.allow || {:unresolved, Macro.to_string(expr)}}
    end
  end

  defp visit({:options, meta, [params, allowed]}, acc, attrs, names),
    do: visit({:options, meta, [params, allowed, []]}, acc, attrs, names)

  defp visit({:options, _, [_params, allowed, positional]}, acc, attrs, names) do
    with {:ok, keys} <- resolve_keys(allowed, attrs, names),
         {:ok, extra} <- resolve_keys(positional, attrs, names) do
      %{acc | allow: acc.allow || {:keys, Enum.sort(keys ++ extra)}}
    else
      _other -> acc
    end
  end

  defp visit({fun, _, [_params, key | rest]}, acc, _attrs, _names)
       when is_atom(fun) and is_binary(key) and length(rest) <= 1 do
    if String.starts_with?(Atom.to_string(fun), "fetch_") do
      acc = %{acc | reads: MapSet.put(acc.reads, key)}

      case requirement_of(fun) do
        nil -> acc
        requirement -> %{acc | req: Map.put_new(acc.req, key, requirement)}
      end
    else
      acc
    end
  end

  defp visit({:permission_scope, _, [_params, key, _allowed, requirement]}, acc, _attrs, _names)
       when is_binary(key) and requirement in [:required, :optional] do
    %{acc | reads: MapSet.put(acc.reads, key), req: Map.put_new(acc.req, key, requirement)}
  end

  defp visit({{:., _, [{:__aliases__, _, [:Map]}, _fun]}, _, args}, acc, _attrs, _names) do
    case args do
      [_params, key] when is_binary(key) ->
        %{acc | reads: MapSet.put(acc.reads, key)}

      [_params, key, default] when is_binary(key) ->
        acc = %{acc | reads: MapSet.put(acc.reads, key)}

        if literal?(default),
          do: %{acc | req: Map.put_new(acc.req, key, {:optional, default})},
          else: acc

      _other ->
        acc
    end
  end

  defp visit({fun, _, args}, acc, _attrs, _names) when is_atom(fun) and is_list(args) do
    index =
      Enum.find_index(args, fn
        {name, _, context} when is_atom(name) and is_atom(context) -> name in [:params, :request]
        _other -> false
      end)

    if index, do: %{acc | calls: [{fun, length(args), args} | acc.calls]}, else: acc
  end

  defp visit(_node, acc, _attrs, _names), do: acc

  defp requirement_of(fun) do
    cond do
      String.starts_with?(Atom.to_string(fun), "fetch_optional") -> :optional
      fun in [:fetch_string, :fetch_request_string] -> :required
      true -> nil
    end
  end

  defp literal?(value),
    do: is_binary(value) or is_integer(value) or is_boolean(value) or is_atom(value)

  # `["a", "b" | Map.keys(@attr)]`, `["a"]`, `Map.keys(@attr)`, `@attr`, or a bound variable.
  defp resolve_keys(list, attrs, names) when is_list(list) do
    list
    |> Enum.reduce_while({:ok, []}, fn
      key, {:ok, acc} when is_binary(key) ->
        {:cont, {:ok, [key | acc]}}

      {:|, _, [head, tail]}, {:ok, acc} when is_binary(head) ->
        case resolve_keys(tail, attrs, names) do
          {:ok, more} -> {:cont, {:ok, more ++ [head | acc]}}
          other -> {:halt, other}
        end

      _other, {:ok, _acc} ->
        {:halt, :error}
    end)
    |> case do
      {:ok, keys} -> {:ok, Enum.sort(keys)}
      other -> other
    end
  end

  defp resolve_keys({{:., _, [{:__aliases__, _, [:Map]}, :keys]}, _, [inner]}, attrs, names),
    do: resolve_keys(inner, attrs, names)

  defp resolve_keys({:@, _, [{name, _, nil}]}, attrs, _names) do
    case Map.fetch(attrs, name) do
      {:ok, keys} -> {:ok, keys}
      :error -> :error
    end
  end

  defp resolve_keys({name, _, context}, _attrs, names) when is_atom(name) and is_atom(context) do
    case Enum.find_index(names, &(&1 == name)) do
      nil -> :error
      index -> {:from_arg, index}
    end
  end

  defp resolve_keys(_other, _attrs, _names), do: :error
end

defmodule Ouroboros.Gateway.ProtocolDocsTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Mix.Tasks.Ouroboros.Protocol.Docs
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.ProtocolDocsTest.Contract

  # `docs/PROTOCOL.md` is the exhaustive reference and it is generated; `docs/TUI.md` §2 is
  # the narrative and it is written. This suite is the seam: it proves the generated file
  # is what this build produces, that the data it is generated from is what the validators
  # enforce, and that the two documents name the same set of methods.

  @methods_source "lib/ouroboros/gateway/methods.ex"
  @conn_source "lib/ouroboros/gateway/conn.ex"
  @tui "docs/TUI.md"

  # The six methods `Methods.invoke/2` never sees, and where their parameters are actually
  # validated. `Docs.connection_answered/0` is proved equal to this set below.
  @connection_answered %{
    "hello" => {:conn, {:hello, 3}},
    "runtime.shutdown" => {:conn, {:shutdown, 2}},
    "interactive.subscribe" => {:methods, {:subscription_params, 2}},
    "coding.subscribe" => {:methods, {:subscription_params, 2}},
    "interactive.unsubscribe" => {:methods, {:session_param, 2}},
    "coding.unsubscribe" => {:methods, {:session_param, 2}}
  }

  # `hello` is documented in `docs/TUI.md` §2.3 with the rest of the handshake rather than
  # in §2.4's catalog, which is a placement decision and not a gap.
  @tui_catalog_exempt ~w(hello)

  # Methods in `@table` that `docs/TUI.md` §2.4 does not catalogue, each recorded here
  # rather than quietly fixed. Deleting a name from this list is what closing a gap looks
  # like: D6's two rewind verbs sat here until the client slice that wired `/rewind`
  # documented them, and the list has been empty since.
  @tui_catalog_gaps ~w()

  describe "the generated reference" do
    test "on disk is exactly what this build generates" do
      assert File.read!(Docs.path()) == Docs.document(),
             """
             docs/PROTOCOL.md has drifted from the code it is generated from.
             Run `mix ouroboros.protocol.docs` and commit the diff — it is the review
             artifact for a protocol change.
             """
    end

    test "gives every method this build serves a section of its own" do
      document = File.read!(Docs.path())

      for method <- Map.keys(Methods.table()) do
        assert document =~ "\n#### `#{method}`\n",
               "docs/PROTOCOL.md has no section for #{method}"
      end
    end

    test "gives every band a section, and the contents an entry" do
      document = File.read!(Docs.path())

      bands =
        Methods.table()
        |> Map.keys()
        |> Enum.map(fn
          "hello" -> "handshake"
          name -> name |> String.split(".") |> hd()
        end)
        |> Enum.uniq()

      for band <- bands do
        assert document =~ "\n### #{band}\n",
               "docs/PROTOCOL.md has no section for the #{band} band"

        assert document =~ "  - [#{band}](##{band})", "the contents do not link the #{band} band"
      end
    end

    test "embeds every golden fixture, and embeds no fixture that is not there" do
      document = File.read!(Docs.path())
      declared = Enum.map(Golden.fixtures(), fn {name, _frame} -> name end)

      assert Enum.sort(declared) == Enum.sort(Map.keys(Docs.fixture_owners())),
             "mix ouroboros.protocol.docs places fixtures by name; one has appeared or gone"

      for name <- declared do
        assert document =~ "`#{name}.json`", "docs/PROTOCOL.md never names #{name}.json"

        assert document =~ File.read!(Golden.path(name)),
               "docs/PROTOCOL.md does not embed the current bytes of #{name}.json"
      end
    end

    test "names every protocol error a client can be sent" do
      document = File.read!(Docs.path())

      for {name, code} <- Methods.codes() do
        assert document =~ "| `#{code}` | `#{name}` |",
               "docs/PROTOCOL.md does not list #{name} (#{code})"
      end
    end
  end

  describe "the parameter contract" do
    test "covers exactly the methods the table serves" do
      assert Methods.params() |> Map.keys() |> Enum.sort() ==
               Methods.table() |> Map.keys() |> Enum.sort()
    end

    test "is the envelope and the key set the validators actually enforce" do
      for {method, declared} <- Methods.params() do
        enforced = Contract.of(target(method))

        assert declared.envelope == enforced.envelope,
               "#{method}: #{@methods_source} enforces a #{enforced.envelope} envelope, " <>
                 "@params declares #{declared.envelope}"

        assert Enum.sort(Enum.map(declared.params, & &1.name)) == enforced.keys,
               "#{method}: the validators accept #{inspect(enforced.keys)}, " <>
                 "@params declares #{inspect(Enum.sort(Enum.map(declared.params, & &1.name)))}"
      end
    end

    test "marks a parameter required where the source demands one and optional where it does not" do
      for {method, declared} <- Methods.params(),
          enforced = Contract.of(target(method)),
          param <- declared.params,
          source = Map.get(enforced.requirements, param.name),
          source != nil do
        assert compatible?(param.requirement, source),
               "#{method}.#{param.name}: the source says #{inspect(source)}, " <>
                 "@params declares #{inspect(param.requirement)}"
      end
    end

    test "names as connection-answered exactly the methods with no invoke/2 clause" do
      env = Contract.read(@methods_source)

      without_clause =
        Methods.table()
        |> Map.keys()
        |> Enum.reject(&Contract.invoke_clause(env, &1))
        |> Enum.sort()

      assert Enum.sort(Docs.connection_answered()) == without_clause
      assert Enum.sort(Map.keys(@connection_answered)) == without_clause
    end
  end

  describe "docs/TUI.md §2.4" do
    test "names no method this build does not serve" do
      assert catalog() -- Map.keys(Methods.table()) == [],
             "docs/TUI.md §2.4 documents a method that is not in Ouroboros.Gateway.Methods"
    end

    test "names every method this build serves, but for the gaps recorded here" do
      missing = (Methods.table() |> Map.keys()) -- catalog()

      assert Enum.sort(missing) == Enum.sort(@tui_catalog_exempt ++ @tui_catalog_gaps),
             """
             docs/TUI.md §2.4 and Ouroboros.Gateway.Methods have moved apart.
             Either document the new method in §2.4, or record it in @tui_catalog_gaps
             with a reason — a gap nobody named is a gap nobody closes.
             """
    end
  end

  # ---------------------------------------------------------------------------

  defp target(method) do
    case Map.fetch(@connection_answered, method) do
      {:ok, {file, entry}} -> {env(file), entry}
      :error -> {env(:methods), {:invoke, method}}
    end
  end

  defp env(:methods), do: Contract.read(@methods_source)
  defp env(:conn), do: Contract.read(@conn_source)

  defp compatible?(same, same), do: true
  defp compatible?({:optional, _}, :optional), do: true
  defp compatible?(:optional, {:optional, _}), do: true
  defp compatible?(_declared, _source), do: false

  # Every method `docs/TUI.md` §2.4's two tables name in their first column. A cell may
  # write a family as `coding.info/replay/subscribe` or as `interactive.send_message` /
  # `follow_up`, so a bare word inherits the band of the last dotted name beside it.
  defp catalog do
    @tui
    |> File.read!()
    |> String.split("### 2.4 Method catalog (v1)")
    |> Enum.at(1)
    |> String.split("### 2.5 Event streaming")
    |> hd()
    |> String.split("\n")
    |> Enum.filter(&String.starts_with?(&1, "|"))
    |> Enum.map(fn row -> row |> String.split("|") |> Enum.at(1, "") end)
    |> Enum.flat_map(&methods_named_in/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp methods_named_in(cell) do
    ~r/`([^`]+)`/
    |> Regex.scan(cell)
    |> Enum.map(&List.last/1)
    |> Enum.reject(&String.starts_with?(&1, "{"))
    |> Enum.reduce({[], nil}, fn span, acc ->
      span
      |> String.split(~r{[/\s,]+}, trim: true)
      |> Enum.reduce(acc, fn part, {found, band} ->
        cond do
          Regex.match?(~r/^[a-z_]+(\.[a-z_]+)+$/, part) ->
            {[part | found], part |> String.split(".") |> hd()}

          band && Regex.match?(~r/^[a-z_]+$/, part) ->
            {[band <> "." <> part | found], band}

          true ->
            {found, band}
        end
      end)
    end)
    |> elem(0)
  end
end
