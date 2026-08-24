defmodule Ouroboros.Provider.Native.Context do
  @moduledoc """
  The stable half of every request this session sends, and the fingerprint that proves it.

  Manus calls prompt-cache hit rate "the single most important metric"; Anthropic's own
  write-up on building Claude Code says the same and lists what invalidates the prefix —
  a model switch, an effort switch, a change to the tool list, compaction (R3 §5). The
  discipline that follows is not subtle, it is just easy to lose track of: **the prefix
  changes only when the operator changed something, or when the conversation itself was
  rewritten.**

  So the request is laid out in one order and built in one place:

      system prompt  →  identity, rules, workspace posture, project instruction files
      tool defs      →  a fixed order, deferred descriptions where the provider can search
      conversation   →  everything that moves

  and `prefix_fingerprint/1` is a digest over the first two. A session reports it in its
  public info, `test/provider/native/context_test.exs` asserts it is the same string
  across turns, and the two things allowed to change it — `configure/2` and compaction —
  are asserted to change it. A fingerprint is cheaper than a cache-hit metric and it
  fails loudly: an accidental "insert today's date into the system prompt" shows up as a
  failing equality rather than as a bill.

  ## Deferred tool descriptions

  Anthropic measured 72 k tokens of tool definitions before tool search existed, and the
  Claude Code team shipped `defer_loading` stubs to keep the prefix stable (R3 §8d, §5).
  The same idea applies here, gated on a fact rather than a hope: a model module may
  declare `tool_search?/0`, and only when it declares `true` do rarely-used tools ship a
  one-line stub instead of a full description. No module declares it today, so today
  every description is full — which is the honest default, because a stub the provider
  cannot expand is a tool the model cannot use.
  """

  alias Ouroboros.Prompt.Assembler
  alias Ouroboros.Provider.Native.Context.Instructions
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.Provider.Native.Prompt
  alias Ouroboros.Provider.Native.Tools

  # `plan` is the tool a session may go a hundred turns without calling. It is the only
  # candidate for deferral in today's five; the list grows with D2's later tool groups.
  @deferred_tools ["plan"]

  @enforce_keys [:system, :tools, :fingerprint]
  defstruct [
    :system,
    :tools,
    :fingerprint,
    :model_spec,
    :context_window,
    instructions: nil,
    deferred: [],
    compactions: 0
  ]

  @type t :: %__MODULE__{
          system: String.t(),
          tools: [map()],
          fingerprint: String.t(),
          model_spec: String.t() | nil,
          context_window: pos_integer() | nil,
          instructions: map() | nil,
          deferred: [String.t()],
          compactions: non_neg_integer()
        }

  @doc """
  Builds the cached prefix for one session.

  Takes everything `Ouroboros.Provider.Native.Prompt.build/1` takes, plus:

    * `:instructions` — a discovery result from
      `Ouroboros.Provider.Native.Context.Instructions.discover/2`, or `false` to skip
      instruction files entirely.
    * `:model_module` — the model module, asked whether it supports tool search.
    * `:model_spec` — the resolved model, for the context window.
    * `:context_window` — a resolved window shared with dynamic tool descriptions, so
      model metadata is looked up once while building the prefix.
    * `:compactions` — how many times this session has compacted, which is part of the
      fingerprint because compaction is a documented cache invalidator and pretending
      otherwise would make the fingerprint claim something it cannot.

  Returns the assembler's own refusal unchanged when a caller's prompt or an instruction
  file carries a reserved runtime delimiter.
  """
  @spec build(keyword()) :: {:ok, t()} | {:error, term()}
  def build(opts) do
    tools = Keyword.get(opts, :tools) || Tools.specs(nil, nil)
    model_module = Keyword.get(opts, :model_module)
    laid_out = lay_out_tools(tools, model_module)

    with {:ok, instruction_text, discovery} <- instruction_section(opts),
         {:ok, base} <-
           Prompt.build(Keyword.merge(opts, tools: tools, instructions: instruction_text)) do
      model_spec = Keyword.get(opts, :model_spec)

      context = %__MODULE__{
        system: base,
        tools: laid_out.specs,
        deferred: laid_out.deferred,
        instructions: discovery,
        model_spec: model_spec,
        context_window: Keyword.get(opts, :context_window) || Window.resolve(model_spec),
        compactions: Keyword.get(opts, :compactions, 0),
        fingerprint: nil
      }

      {:ok, %{context | fingerprint: fingerprint(context, opts)}}
    end
  end

  @doc """
  The digest of this session's cached prefix.

  Stable across turns by construction. It changes on exactly three things: the system
  prompt (which includes the model and effort the session was configured with), the tool
  list, and the compaction counter.
  """
  @spec prefix_fingerprint(t()) :: String.t()
  def prefix_fingerprint(%__MODULE__{fingerprint: fingerprint}), do: fingerprint

  @doc "The prefix as the model request carries it."
  @spec prefix(t()) :: %{system: String.t(), tools: [map()]}
  def prefix(%__MODULE__{} = context), do: %{system: context.system, tools: context.tools}

  @doc """
  The context's public facts, for `interactive.info` and the footer.

  Names only and numbers only: which instruction files were loaded and which were
  dropped, how large the prefix is, the fingerprint, and the window. Never the text — an
  instruction file is repository content and a session listing is not the place to
  republish it.
  """
  @spec info(t()) :: map()
  def info(%__MODULE__{} = context) do
    %{
      prefix_fingerprint: context.fingerprint,
      prefix_bytes: byte_size(context.system) + tools_bytes(context.tools),
      tools: Enum.map(context.tools, & &1.name),
      deferred_tools: context.deferred,
      context_window: context.context_window,
      compactions: context.compactions,
      instruction_files: instruction_files(context.instructions),
      instruction_files_dropped: instruction_dropped(context.instructions),
      instruction_bytes: instruction_bytes(context.instructions),
      lazy_rules: lazy_rules(context.instructions)
    }
  end

  @doc "The same context with its compaction counter advanced, and its fingerprint with it."
  @spec compacted(t(), keyword()) :: t()
  def compacted(%__MODULE__{} = context, opts \\ []) do
    context = %{context | compactions: context.compactions + 1}
    %{context | fingerprint: fingerprint(context, opts)}
  end

  @doc "The rules held back for lazy loading, for the loop to consult on a file touch."
  @spec rules(t()) :: [map()]
  def rules(%__MODULE__{instructions: %{rules: rules}}), do: rules
  def rules(%__MODULE__{}), do: []

  # ---------------------------------------------------------------- private

  defp instruction_section(opts) do
    case Keyword.get(opts, :instructions, :discover) do
      false ->
        {:ok, nil, nil}

      nil ->
        {:ok, nil, nil}

      :discover ->
        case Keyword.get(opts, :cwd) do
          root when is_binary(root) and root != "" ->
            render(Instructions.discover(root, Keyword.take(opts, [:budget, :user_scope])))

          _absent ->
            {:ok, nil, nil}
        end

      %{sources: _sources} = discovery ->
        render(discovery)
    end
  end

  defp render(discovery) do
    case Instructions.render(discovery) do
      {:ok, text} -> {:ok, text, discovery}
      {:error, _reason} = error -> error
    end
  end

  # The order is `Tools.modules/0`'s order, which is a hand-written list rather than a
  # sort: it is the order the model has seen since D1 and reordering it would be a cache
  # miss with nothing gained.
  defp lay_out_tools(tools, model_module) do
    if tool_search?(model_module) do
      deferred = Enum.filter(tools, &(&1.name in @deferred_tools))

      %{
        specs: Enum.map(tools, &defer/1),
        deferred: Enum.map(deferred, & &1.name)
      }
    else
      %{specs: tools, deferred: []}
    end
  end

  defp defer(%{name: name} = spec) when name in @deferred_tools do
    %{spec | description: first_sentence(spec.description) <> " (full schema on request)"}
  end

  defp defer(spec), do: spec

  defp first_sentence(description) do
    description
    |> to_string()
    |> String.split(". ", parts: 2)
    |> List.first()
    |> String.trim_trailing(".")
    |> Kernel.<>(".")
  end

  defp tool_search?(module) when is_atom(module) and not is_nil(module) do
    Code.ensure_loaded?(module) and function_exported?(module, :tool_search?, 0) and
      module.tool_search?() == true
  end

  defp tool_search?(_module), do: false

  # The digest covers the system prompt byte for byte, each tool's name, description and
  # schema, and the compaction counter. It deliberately does *not* cover the conversation
  # — that is the part that is supposed to change.
  defp fingerprint(context, opts) do
    payload = [
      "v1",
      context.system,
      Enum.map_join(context.tools, " ", fn tool ->
        tool.name <> "" <> to_string(tool.description) <> "" <> canonical(tool.parameters)
      end),
      Integer.to_string(context.compactions),
      to_string(Keyword.get(opts, :model_spec)),
      to_string(Keyword.get(opts, :reasoning_effort))
    ]

    :sha256
    |> :crypto.hash(Enum.join(payload, ""))
    |> Base.encode16(case: :lower)
  end

  # Map iteration order is not part of a map's identity, so a JSON encode of a schema
  # could differ between two structurally identical schemas. Sorting every key makes the
  # digest depend on the schema and not on the VM's hashing.
  defp canonical(value) when is_map(value) do
    value
    |> Enum.map(fn {key, inner} -> {to_string(key), canonical(inner)} end)
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.map_join(",", fn {key, inner} -> key <> ":" <> inner end)
    |> then(&("{" <> &1 <> "}"))
  end

  defp canonical(value) when is_list(value),
    do: "[" <> Enum.map_join(value, ",", &canonical/1) <> "]"

  defp canonical(value) when is_binary(value), do: value
  defp canonical(value) when is_atom(value), do: to_string(value)
  defp canonical(value), do: inspect(value)

  defp tools_bytes(tools) do
    Enum.reduce(tools, 0, fn tool, acc ->
      acc + byte_size(tool.name) + byte_size(to_string(tool.description))
    end)
  end

  defp instruction_files(%{sources: sources}), do: Enum.map(sources, & &1.path)
  defp instruction_files(_absent), do: []

  defp instruction_dropped(%{dropped: dropped}),
    do: Enum.map(dropped, &%{path: &1.path, bytes: &1.bytes, reason: Atom.to_string(&1.reason)})

  defp instruction_dropped(_absent), do: []

  defp instruction_bytes(%{bytes: bytes}), do: bytes
  defp instruction_bytes(_absent), do: 0

  defp lazy_rules(%{rules: rules}),
    do: Enum.map(rules, &%{path: &1.path, globs: &1.globs})

  defp lazy_rules(_absent), do: []

  @doc false
  @spec deferred_tools() :: [String.t()]
  def deferred_tools, do: @deferred_tools

  @doc """
  The `Assembler` version this context's prompt was rendered at.

  Exposed so a caller can tell two prefixes apart across a runtime upgrade without
  re-reading the prompt itself.
  """
  @spec prompt_version() :: pos_integer()
  def prompt_version, do: Assembler.version()
end
