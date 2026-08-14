defmodule Ouroboros.Prompt.Assembler do
  @moduledoc """
  Deterministically renders an `Ouroboros.AgentProfile` as a system prompt.

  The user's objective or turn text never enters this module. It remains a
  separate Harness `prompt`, preserving the trust boundary between durable
  profile instructions and untrusted task input. This module only assembles
  prompt text and trace metadata; it neither selects nor executes tools.

  The rendered prompt states its own structure: profile text inside an
  `<ouroboros-agent-profile>` block, the caller's session prompt inside an
  `<ouroboros-session-instructions>` block. That structure is enforced, not merely
  documented — text containing either tag is rejected with
  `{:error, {:reserved_prompt_delimiter, field}}`, on both sides, so neither block can
  close itself and open the other. Rejection rather than escaping: a prompt this module
  rewrote would no longer be the prompt its author wrote or its digest describes.
  Attribute injection is not reachable either; profile and tool ids admit no `<` or `"`.

  A profile that renders no sections is refused as `:empty_rendered_profile`. Providers
  treat a system prompt as a replacement for their own built-in prompt, so an empty
  envelope is not a neutral one.

  Passing no profile is a compatibility path: there is no block to forge, and the
  caller's existing system prompt is returned byte-for-byte, with no profile trace
  emitted. That path refuses exactly one thing — a binary that is not valid UTF-8.

  Tool descriptions fail closed: a profile tool is rendered only when its name
  is present in the request's explicit `allowed_tools`; `disallowed_tools`
  always removes it. With no allowlist, no tool manifest is advertised. Caller-supplied
  tool names are trimmed, as profile tool names already are.
  """

  alias Ouroboros.AgentProfile
  alias Ouroboros.Prompt.Trace

  @accepted_options [:system_prompt, :allowed_tools, :disallowed_tools]

  defmodule Assembly do
    @moduledoc "A rendered prompt plus content-free deterministic trace metadata."

    @enforce_keys [:version, :system_prompt, :digest]
    defstruct [
      :profile_id,
      :profile_version,
      :profile_digest,
      :system_prompt,
      :digest,
      version: 1
    ]

    @type t :: %__MODULE__{
            version: pos_integer(),
            profile_id: String.t() | nil,
            profile_version: pos_integer() | nil,
            profile_digest: String.t() | nil,
            system_prompt: String.t() | nil,
            digest: String.t() | nil
          }
  end

  @doc "Returns the prompt-format version used by this build."
  @spec version() :: pos_integer()
  def version, do: Trace.version()

  @doc "Assembles one optional profile and optional caller system prompt."
  @spec assemble(AgentProfile.t() | nil, keyword()) ::
          {:ok, Assembly.t()} | {:error, term()}
  def assemble(profile, opts \\ [])

  def assemble(nil, opts) do
    with :ok <- validate_options(opts),
         {:ok, system_prompt} <- legacy_prompt(Keyword.get(opts, :system_prompt)) do
      {:ok,
       %Assembly{
         version: Trace.version(),
         system_prompt: system_prompt,
         digest: digest_text(system_prompt)
       }}
    end
  end

  def assemble(%AgentProfile{} = profile, opts) do
    with :ok <- validate_options(opts),
         :ok <- AgentProfile.validate(profile),
         {:ok, profile_digest} <- AgentProfile.digest(profile),
         {:ok, allowed_tools} <- tool_names(Keyword.get(opts, :allowed_tools), :allowed_tools),
         {:ok, disallowed_tools} <-
           tool_names(Keyword.get(opts, :disallowed_tools, []), :disallowed_tools),
         {:ok, session_prompt} <- normalized_session_prompt(Keyword.get(opts, :system_prompt)),
         tools = active_tools(profile.tools, allowed_tools, disallowed_tools),
         {:ok, system_prompt} <- render(profile, session_prompt, tools) do
      {:ok,
       %Assembly{
         version: Trace.version(),
         profile_id: profile.id,
         profile_version: profile.version,
         profile_digest: profile_digest,
         system_prompt: system_prompt,
         digest: digest_text(system_prompt)
       }}
    end
  end

  def assemble(_profile, _opts), do: {:error, :invalid_agent_profile}

  @doc "Returns trace metadata without any prompt or profile content."
  @spec trace(Assembly.t()) :: Trace.t() | nil
  def trace(%Assembly{} = assembly), do: Trace.build(assembly)

  defp render(profile, session_prompt, tools) do
    sections =
      []
      |> maybe_section("Base behavior", profile.base_prompt)
      |> maybe_collection("Instructions", profile.instructions, &instruction/1)
      |> maybe_collection("Skills", profile.skills, &skill/1)
      |> maybe_collection("Tool manifest", tools, &tool/1)

    # Providers treat a system prompt as a replacement for their own, not an addition to
    # it. A profile that renders to nothing — a tools-only profile with no allowlist to
    # advertise against — would install an empty envelope in place of the provider's
    # built-in prompt. Refuse: an empty policy is not a policy.
    if sections == [] do
      {:error, :empty_rendered_profile}
    else
      {:ok, envelope(profile, Enum.join(sections, "\n\n"), session_prompt)}
    end
  end

  defp envelope(profile, profile_body, session_prompt) do
    rendered =
      "<ouroboros-agent-profile id=\"#{profile.id}\" version=\"#{profile.version}\">\n" <>
        profile_body <> "\n</ouroboros-agent-profile>"

    if session_prompt do
      rendered <>
        "\n\n<ouroboros-session-instructions>\n" <>
        session_prompt <> "\n</ouroboros-session-instructions>"
    else
      rendered
    end
  end

  defp maybe_section(sections, _title, nil), do: sections
  defp maybe_section(sections, title, body), do: sections ++ ["## #{title}\n\n#{body}"]

  defp maybe_collection(sections, _title, [], _renderer), do: sections

  defp maybe_collection(sections, title, entries, renderer) do
    body = entries |> Enum.map(renderer) |> Enum.join("\n\n")
    sections ++ ["## #{title}\n\n#{body}"]
  end

  defp instruction(entry), do: "### #{entry.id}\n\n#{entry.text}"

  defp skill(entry),
    do: "### #{entry.id}@#{entry.version}\n\n#{entry.instructions}"

  defp tool(entry), do: "- `#{entry.name}`: #{entry.description}"

  defp validate_options(opts) do
    cond do
      not is_list(opts) or not Keyword.keyword?(opts) ->
        {:error, :invalid_prompt_assembler_options}

      Keyword.keys(opts) != Enum.uniq(Keyword.keys(opts)) ->
        {:error, :duplicate_prompt_assembler_options}

      unknown = Enum.find(Keyword.keys(opts), &(&1 not in @accepted_options)) ->
        {:error, {:unknown_prompt_assembler_option, unknown}}

      true ->
        :ok
    end
  end

  # No profile means no boundary to forge: the whole prompt is the caller's, and it is
  # returned byte for byte — no line-ending rewrite, no NFC, no trim. The one thing this
  # path refuses is a binary that is not UTF-8, which nothing downstream can render and
  # which the digest would otherwise pin as prompt identity.
  defp legacy_prompt(nil), do: {:ok, nil}

  defp legacy_prompt(prompt) when is_binary(prompt) do
    if String.valid?(prompt), do: {:ok, prompt}, else: {:error, :invalid_system_prompt}
  end

  defp legacy_prompt(_prompt), do: {:error, :invalid_system_prompt}

  defp normalized_session_prompt(nil), do: {:ok, nil}

  defp normalized_session_prompt(prompt) when is_binary(prompt) do
    if String.valid?(prompt) do
      normalized =
        prompt
        |> String.replace("\r\n", "\n")
        |> String.replace("\r", "\n")
        |> String.normalize(:nfc)
        |> String.trim()

      cond do
        normalized == "" -> {:ok, nil}
        AgentProfile.reserved_delimiter?(normalized) -> reserved(:system_prompt)
        true -> {:ok, normalized}
      end
    else
      {:error, :invalid_system_prompt}
    end
  end

  defp normalized_session_prompt(_prompt), do: {:error, :invalid_system_prompt}

  defp reserved(field), do: {:error, {:reserved_prompt_delimiter, field}}

  # `nil` means the caller did not establish which tools are active, so the safe
  # manifest is empty. This deliberately differs from an empty disallow list.
  defp tool_names(nil, _field), do: {:ok, MapSet.new()}

  # Profile tool names are trimmed at normalization, so caller entries are trimmed too:
  # `" Read "` naming `Read` is one name, and a set that disagreed would silently drop
  # the tool from the manifest — or, on the deny side, silently fail to remove it.
  # Trimming only: tool names are ASCII-constrained by `@id_regex`, so there is no case
  # folding or Unicode form to reconcile.
  defp tool_names(names, field) when is_list(names) do
    if Enum.all?(names, &(is_binary(&1) and String.trim(&1) != "")) do
      {:ok, names |> Enum.map(&String.trim/1) |> MapSet.new()}
    else
      {:error, {:invalid_prompt_assembler_option, field}}
    end
  end

  defp tool_names(_names, field), do: {:error, {:invalid_prompt_assembler_option, field}}

  defp active_tools(tools, allowed, disallowed) do
    Enum.filter(tools, fn tool ->
      MapSet.member?(allowed, tool.name) and not MapSet.member?(disallowed, tool.name)
    end)
  end

  defp digest_text(nil), do: nil
  defp digest_text(text), do: Trace.digest(text)
end
