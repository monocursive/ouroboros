defmodule Ouroboros.Prompt.Assembler do
  @moduledoc """
  Deterministically renders an `Ouroboros.AgentProfile` as a system prompt.

  The user's objective or turn text never enters this module. It remains a
  separate Harness `prompt`, preserving the trust boundary between durable
  profile instructions and untrusted task input. This module only assembles
  prompt text and trace metadata; it neither selects nor executes tools.

  Passing no profile is a compatibility path: the caller's existing system
  prompt is returned byte-for-byte and no profile trace is emitted.

  Tool descriptions fail closed: a profile tool is rendered only when its name
  is present in the request's explicit `allowed_tools`; `disallowed_tools`
  always removes it. With no allowlist, no tool manifest is advertised.
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
         {:ok, system_prompt} <- legacy_system_prompt(Keyword.get(opts, :system_prompt)) do
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
         {:ok, session_prompt} <- normalized_session_prompt(Keyword.get(opts, :system_prompt)) do
      tools = active_tools(profile.tools, allowed_tools, disallowed_tools)
      system_prompt = render(profile, session_prompt, tools)

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

    profile_body = Enum.join(sections, "\n\n")

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

  defp legacy_system_prompt(nil), do: {:ok, nil}
  defp legacy_system_prompt(prompt) when is_binary(prompt), do: {:ok, prompt}
  defp legacy_system_prompt(_prompt), do: {:error, :invalid_system_prompt}

  defp normalized_session_prompt(nil), do: {:ok, nil}

  defp normalized_session_prompt(prompt) when is_binary(prompt) do
    if String.valid?(prompt) do
      normalized =
        prompt
        |> String.replace("\r\n", "\n")
        |> String.replace("\r", "\n")
        |> String.normalize(:nfc)
        |> String.trim()

      {:ok, if(normalized == "", do: nil, else: normalized)}
    else
      {:error, :invalid_system_prompt}
    end
  end

  defp normalized_session_prompt(_prompt), do: {:error, :invalid_system_prompt}

  # `nil` means the caller did not establish which tools are active, so the safe
  # manifest is empty. This deliberately differs from an empty disallow list.
  defp tool_names(nil, _field), do: {:ok, MapSet.new()}

  defp tool_names(names, field) when is_list(names) do
    if Enum.all?(names, &(is_binary(&1) and String.trim(&1) != "")) do
      {:ok, MapSet.new(names)}
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
