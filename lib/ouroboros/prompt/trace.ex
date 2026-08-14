defmodule Ouroboros.Prompt.Trace do
  @moduledoc """
  The content-free record of which prompt a durable task or session is running.

  A trace names the profile and pins the exact bytes the assembler produced: an id, a
  profile version, and two SHA-256 digests. It carries no prompt or profile text, which
  is what lets it travel into public projections, provider metadata, and logs.

  Both planes and the assembler share this module rather than each restating the shape.
  The duplicated copies had already drifted from `build/1`, and a checkpoint validated
  against a stale key list is a checkpoint validated against nothing.

  `validate/2` is strict about the format version by design: a trace written by a newer
  build describes a prompt this build cannot reproduce. That strictness belongs at the
  gates that accept new writes and at the moment a request is built, never at load —
  refusing to load such a task would take the whole node down with it.
  """

  alias Ouroboros.Prompt.Assembler.Assembly

  @version 1
  @keys [:digest, :profile_digest, :profile_id, :profile_version, :version]

  @type t :: %{
          required(:version) => pos_integer(),
          required(:digest) => String.t(),
          required(:profile_id) => String.t(),
          required(:profile_version) => pos_integer(),
          required(:profile_digest) => String.t()
        }

  @doc "Returns the prompt-format version this build writes and accepts."
  @spec version() :: pos_integer()
  def version, do: @version

  @doc "Returns the exact key set a trace carries."
  @spec keys() :: [atom()]
  def keys, do: @keys

  @doc "Builds the trace for one assembly, or `nil` when no profile was assembled."
  @spec build(Assembly.t()) :: t() | nil
  def build(%Assembly{profile_id: nil}), do: nil

  def build(%Assembly{} = assembly) do
    %{
      version: assembly.version,
      digest: assembly.digest,
      profile_id: assembly.profile_id,
      profile_version: assembly.profile_version,
      profile_digest: assembly.profile_digest
    }
  end

  @doc """
  Returns whether a trace describes exactly the given system prompt.

  An absent trace is valid: a task from before profiles existed, or one assembled
  without a profile, has no prompt identity to contradict.
  """
  @spec validate(term(), term()) :: :ok | {:error, term()}
  def validate(nil, _system_prompt), do: :ok

  def validate(trace, system_prompt) when is_map(trace) do
    cond do
      trace |> Map.keys() |> Enum.sort() != @keys ->
        {:error, :malformed_prompt_trace}

      trace.version != @version ->
        {:error, {:unsupported_prompt_trace_version, trace.version}}

      not (is_binary(trace.profile_id) and trace.profile_id != "") ->
        {:error, :invalid_prompt_trace_profile}

      not (is_integer(trace.profile_version) and trace.profile_version > 0) ->
        {:error, :invalid_prompt_trace_profile}

      not (valid_digest?(trace.digest) and valid_digest?(trace.profile_digest)) ->
        {:error, :invalid_prompt_trace_digest}

      not is_binary(system_prompt) ->
        {:error, :traced_prompt_missing}

      digest(system_prompt) != trace.digest ->
        {:error, :traced_prompt_digest_mismatch}

      true ->
        :ok
    end
  end

  def validate(_trace, _system_prompt), do: {:error, :malformed_prompt_trace}

  @doc "Returns whether a trace describes exactly the given system prompt."
  @spec valid?(term(), term()) :: boolean()
  def valid?(trace, system_prompt), do: validate(trace, system_prompt) == :ok

  @doc "Adds a trace to a metadata or projection map, omitting an absent one."
  @spec put(map(), t() | nil, atom()) :: map()
  def put(map, trace, key \\ :prompt_assembly)
  def put(map, nil, _key), do: map
  def put(map, trace, key), do: Map.put(map, key, trace)

  @doc "Returns the digest a trace pins for one rendered prompt."
  @spec digest(binary()) :: String.t()
  def digest(prompt) when is_binary(prompt) do
    :sha256
    |> :crypto.hash(prompt)
    |> Base.encode16(case: :lower)
  end

  @doc "Returns whether a value is a lowercase hex SHA-256 digest."
  @spec valid_digest?(term()) :: boolean()
  def valid_digest?(digest) when is_binary(digest) do
    case Base.decode16(digest, case: :lower) do
      {:ok, decoded} -> byte_size(decoded) == 32
      :error -> false
    end
  end

  def valid_digest?(_digest), do: false
end
