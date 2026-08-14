defmodule Ouroboros.AgentProfile do
  @moduledoc """
  A versioned, provider-neutral description of an agent's prompt policy.

  A profile is data, not an executor. Its tool entries are candidates for the
  prompt manifest, grant no authority, and start no tool loop. The prompt
  assembler advertises one only when the request's explicit `allowed_tools`
  contains its name, with `disallowed_tools` taking precedence. Provider
  execution remains owned by `Jido.Harness`.

  Lists preserve caller-declared order because instruction precedence is part of
  the profile. Maps are normalized into a fixed shape, text uses LF line endings,
  and digests use deterministic Erlang encoding so the same normalized profile
  has the same identity on every node.
  """

  @current_version 1
  @id_regex ~r/^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,127}$/
  @profile_keys [:id, :version, :base_prompt, :instructions, :skills, :tools]

  @enforce_keys [:id]
  defstruct id: nil,
            version: @current_version,
            base_prompt: nil,
            instructions: [],
            skills: [],
            tools: []

  @type instruction :: %{required(:id) => String.t(), required(:text) => String.t()}

  @type skill :: %{
          required(:id) => String.t(),
          required(:version) => String.t(),
          required(:instructions) => String.t()
        }

  @type tool :: %{required(:name) => String.t(), required(:description) => String.t()}

  @type t :: %__MODULE__{
          id: String.t(),
          version: pos_integer(),
          base_prompt: String.t() | nil,
          instructions: [instruction()],
          skills: [skill()],
          tools: [tool()]
        }

  @doc "Returns the only profile schema version this build accepts."
  @spec current_version() :: pos_integer()
  def current_version, do: @current_version

  @doc "Builds and normalizes a strict schema-v1 agent profile."
  @spec new(map() | keyword()) :: {:ok, t()} | {:error, term()}
  def new(attrs) when is_list(attrs) do
    cond do
      not Keyword.keyword?(attrs) -> {:error, :invalid_profile}
      Keyword.keys(attrs) != Enum.uniq(Keyword.keys(attrs)) -> {:error, :duplicate_profile_keys}
      true -> new(Map.new(attrs))
    end
  end

  def new(attrs) when is_map(attrs) do
    with {:ok, attrs} <- normalize_keys(attrs, @profile_keys, :profile),
         {:ok, id} <- normalize_id(Map.get(attrs, :id), :profile_id),
         {:ok, version} <- normalize_version(Map.get(attrs, :version, @current_version)),
         {:ok, base_prompt} <- normalize_optional_text(Map.get(attrs, :base_prompt)),
         {:ok, instructions} <- normalize_instructions(Map.get(attrs, :instructions, [])),
         {:ok, skills} <- normalize_skills(Map.get(attrs, :skills, [])),
         {:ok, tools} <- normalize_tools(Map.get(attrs, :tools, [])),
         :ok <- require_content(base_prompt, instructions, skills, tools) do
      {:ok,
       %__MODULE__{
         id: id,
         version: version,
         base_prompt: base_prompt,
         instructions: instructions,
         skills: skills,
         tools: tools
       }}
    end
  end

  def new(_attrs), do: {:error, :invalid_profile}

  @doc "Builds a profile, raising `ArgumentError` when its manifest is invalid."
  @spec new!(map() | keyword()) :: t()
  def new!(attrs) do
    case new(attrs) do
      {:ok, profile} -> profile
      {:error, reason} -> raise ArgumentError, "invalid agent profile: #{inspect(reason)}"
    end
  end

  @doc "Validates a profile, including structs reconstructed from durable storage."
  @spec validate(term()) :: :ok | {:error, term()}
  def validate(%__MODULE__{} = profile) do
    case new(Map.from_struct(profile)) do
      {:ok, ^profile} -> :ok
      {:ok, _normalized} -> {:error, :non_normalized_profile}
      {:error, _reason} = error -> error
    end
  end

  def validate(_profile), do: {:error, :invalid_profile}

  @doc "Returns whether a value is a valid normalized profile."
  @spec valid?(term()) :: boolean()
  def valid?(profile), do: validate(profile) == :ok

  @doc "Returns a deterministic SHA-256 digest of a valid normalized profile."
  @spec digest(t()) :: {:ok, String.t()} | {:error, term()}
  def digest(%__MODULE__{} = profile) do
    with :ok <- validate(profile) do
      {:ok, fingerprint(canonical(profile))}
    end
  end

  def digest(_profile), do: {:error, :invalid_profile}

  @doc "Returns a content-free profile identity suitable for public snapshots."
  @spec summary(t()) :: {:ok, map()} | {:error, term()}
  def summary(%__MODULE__{} = profile) do
    with {:ok, digest} <- digest(profile) do
      {:ok, %{id: profile.id, version: profile.version, digest: digest}}
    end
  end

  def summary(_profile), do: {:error, :invalid_profile}

  @doc false
  @spec canonical(t()) :: map()
  def canonical(%__MODULE__{} = profile) do
    %{
      id: profile.id,
      version: profile.version,
      base_prompt: profile.base_prompt,
      instructions: profile.instructions,
      skills: profile.skills,
      tools: profile.tools
    }
  end

  defp normalize_instructions(entries) when is_list(entries) do
    with {:ok, normalized} <- normalize_entries(entries, &normalize_instruction/1),
         :ok <- unique(normalized, :id, :duplicate_instruction) do
      {:ok, normalized}
    end
  end

  defp normalize_instructions(_entries), do: {:error, :invalid_instructions}

  defp normalize_instruction(entry) when is_map(entry) do
    with {:ok, entry} <- normalize_keys(entry, [:id, :text], :instruction),
         {:ok, id} <- normalize_id(Map.get(entry, :id), :instruction_id),
         {:ok, text} <- normalize_required_text(Map.get(entry, :text), :instruction_text) do
      {:ok, %{id: id, text: text}}
    end
  end

  defp normalize_instruction(_entry), do: {:error, :invalid_instruction}

  defp normalize_skills(entries) when is_list(entries) do
    with {:ok, normalized} <- normalize_entries(entries, &normalize_skill/1),
         :ok <- unique(normalized, :id, :duplicate_skill) do
      {:ok, normalized}
    end
  end

  defp normalize_skills(_entries), do: {:error, :invalid_skills}

  defp normalize_skill(entry) when is_map(entry) do
    with {:ok, entry} <- normalize_keys(entry, [:id, :version, :instructions], :skill),
         {:ok, id} <- normalize_id(Map.get(entry, :id), :skill_id),
         {:ok, version} <- normalize_id(Map.get(entry, :version), :skill_version),
         {:ok, instructions} <-
           normalize_required_text(Map.get(entry, :instructions), :skill_instructions) do
      {:ok, %{id: id, version: version, instructions: instructions}}
    end
  end

  defp normalize_skill(_entry), do: {:error, :invalid_skill}

  defp normalize_tools(entries) when is_list(entries) do
    with {:ok, normalized} <- normalize_entries(entries, &normalize_tool/1),
         :ok <- unique(normalized, :name, :duplicate_tool) do
      {:ok, normalized}
    end
  end

  defp normalize_tools(_entries), do: {:error, :invalid_tools}

  defp normalize_tool(entry) when is_map(entry) do
    with {:ok, entry} <- normalize_keys(entry, [:name, :description], :tool),
         {:ok, name} <- normalize_id(Map.get(entry, :name), :tool_name),
         {:ok, description} <-
           normalize_required_text(Map.get(entry, :description), :tool_description) do
      {:ok, %{name: name, description: description}}
    end
  end

  defp normalize_tool(_entry), do: {:error, :invalid_tool}

  defp normalize_entries(entries, normalizer) do
    Enum.reduce_while(entries, {:ok, []}, fn entry, {:ok, acc} ->
      case normalizer.(entry) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, normalized} -> {:ok, Enum.reverse(normalized)}
      {:error, _reason} = error -> error
    end
  end

  defp normalize_keys(map, allowed, context) do
    strings = Map.new(allowed, &{Atom.to_string(&1), &1})

    Enum.reduce_while(map, {:ok, %{}}, fn {key, value}, {:ok, acc} ->
      with {:ok, normalized} <- normalize_key(key, allowed, strings, context),
           false <- Map.has_key?(acc, normalized) do
        {:cont, {:ok, Map.put(acc, normalized, value)}}
      else
        true -> {:halt, {:error, {:duplicate_profile_key, context, normalized_key(key, strings)}}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp normalize_key(key, allowed, strings, context) do
    case do_normalize_key(key, allowed, strings) do
      :unknown -> {:error, {:unknown_profile_key, context, key}}
      result -> result
    end
  end

  defp do_normalize_key(key, allowed, _strings) when is_atom(key) do
    if key in allowed, do: {:ok, key}, else: :unknown
  end

  defp do_normalize_key(key, _allowed, strings) when is_binary(key) do
    case Map.fetch(strings, key) do
      {:ok, normalized} -> {:ok, normalized}
      :error -> :unknown
    end
  end

  defp do_normalize_key(_key, _allowed, _strings), do: :unknown

  defp normalized_key(key, strings) when is_binary(key), do: Map.get(strings, key, key)
  defp normalized_key(key, _strings), do: key

  defp normalize_id(value, field) when is_binary(value) do
    if String.valid?(value) do
      normalized = value |> normalize_text() |> String.trim()

      if Regex.match?(@id_regex, normalized),
        do: {:ok, normalized},
        else: {:error, {:invalid_profile_field, field}}
    else
      {:error, {:invalid_profile_field, field}}
    end
  end

  defp normalize_id(_value, field), do: {:error, {:invalid_profile_field, field}}

  defp normalize_version(@current_version), do: {:ok, @current_version}
  defp normalize_version(version), do: {:error, {:unsupported_profile_version, version}}

  defp normalize_optional_text(nil), do: {:ok, nil}

  defp normalize_optional_text(value) when is_binary(value) do
    if String.valid?(value) do
      case value |> normalize_text() |> String.trim() do
        "" -> {:ok, nil}
        normalized -> {:ok, normalized}
      end
    else
      {:error, {:invalid_profile_field, :base_prompt}}
    end
  end

  defp normalize_optional_text(_value), do: {:error, {:invalid_profile_field, :base_prompt}}

  defp normalize_required_text(value, field) when is_binary(value) do
    if String.valid?(value) do
      case value |> normalize_text() |> String.trim() do
        "" -> {:error, {:invalid_profile_field, field}}
        normalized -> {:ok, normalized}
      end
    else
      {:error, {:invalid_profile_field, field}}
    end
  end

  defp normalize_required_text(_value, field), do: {:error, {:invalid_profile_field, field}}

  defp normalize_text(text) do
    text
    |> String.replace("\r\n", "\n")
    |> String.replace("\r", "\n")
    |> String.normalize(:nfc)
  end

  defp unique(entries, key, error) do
    values = Enum.map(entries, &Map.fetch!(&1, key))
    if values == Enum.uniq(values), do: :ok, else: {:error, error}
  end

  defp require_content(nil, [], [], []), do: {:error, :empty_profile}
  defp require_content(_base_prompt, _instructions, _skills, _tools), do: :ok

  defp fingerprint(term) do
    :sha256
    |> :crypto.hash(:erlang.term_to_binary(term, [:deterministic]))
    |> Base.encode16(case: :lower)
  end
end
