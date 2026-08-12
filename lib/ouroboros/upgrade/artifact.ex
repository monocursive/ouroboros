defmodule Ouroboros.Upgrade.Artifact do
  @moduledoc """
  A content-addressed, optionally signed hot-upgrade bundle.

  Source compilation is intentionally absent. Production nodes accept BEAM artifacts,
  not source strings or quoted forms whose compilation would execute arbitrary code.
  """

  alias Ouroboros.Upgrade.Beam

  @enforce_keys [
    :id,
    :epoch,
    :modules,
    :otp_release,
    :elixir_version,
    :system_architecture,
    :created_at
  ]
  defstruct @enforce_keys ++ [metadata: %{}, signature: nil]

  @type signature :: %{signer: String.t(), value: binary()}
  @type t :: %__MODULE__{
          id: String.t(),
          epoch: pos_integer(),
          modules: [Beam.t()],
          otp_release: String.t(),
          elixir_version: String.t(),
          system_architecture: String.t(),
          created_at: String.t(),
          metadata: map(),
          signature: signature() | nil
        }

  @doc "Builds an artifact from already compiled BEAM replacements."
  @spec build([{module(), binary(), keyword()}], keyword()) :: {:ok, t()} | {:error, term()}
  def build(entries, opts \\ []) when is_list(entries) and is_list(opts) do
    epoch = Keyword.get(opts, :epoch, System.unique_integer([:positive, :monotonic]))

    with :ok <- validate_epoch(epoch),
         {:ok, modules} <- build_modules(entries),
         :ok <- ensure_unique_modules(modules),
         :ok <- ensure_nonempty(modules) do
      {:ok,
       %__MODULE__{
         id: Keyword.get_lazy(opts, :id, &Jido.Signal.ID.generate!/0),
         epoch: epoch,
         modules: modules,
         otp_release: to_string(:erlang.system_info(:otp_release)),
         elixir_version: System.version(),
         system_architecture: to_string(:erlang.system_info(:system_architecture)),
         created_at: DateTime.utc_now() |> DateTime.to_iso8601(),
         metadata: Keyword.get(opts, :metadata, %{})
       }}
    end
  end

  @doc "Signs the canonical manifest with an Ed25519 private key."
  @spec sign(t(), String.t(), binary()) :: t()
  def sign(%__MODULE__{} = artifact, signer, private_key)
      when is_binary(signer) and is_binary(private_key) do
    signature =
      :crypto.sign(:eddsa, :none, signing_payload(artifact, signer), [private_key, :ed25519])

    %{artifact | signature: %{signer: signer, value: signature}}
  end

  @doc false
  @spec signing_payload(t()) :: binary()
  def signing_payload(%__MODULE__{} = artifact) do
    :erlang.term_to_binary({:ouroboros_upgrade_v1, manifest(artifact)}, [:deterministic])
  end

  @doc false
  @spec signing_payload(t(), String.t()) :: binary()
  def signing_payload(%__MODULE__{} = artifact, signer) when is_binary(signer) do
    :erlang.term_to_binary({:ouroboros_upgrade_v1, signer, manifest(artifact)}, [:deterministic])
  end

  @doc false
  @spec manifest(t()) :: map()
  def manifest(%__MODULE__{} = artifact) do
    %{
      id: artifact.id,
      epoch: artifact.epoch,
      otp_release: artifact.otp_release,
      elixir_version: artifact.elixir_version,
      system_architecture: artifact.system_architecture,
      created_at: artifact.created_at,
      metadata: artifact.metadata,
      modules:
        Enum.map(artifact.modules, fn beam ->
          %{
            module: beam.module,
            filename: beam.filename,
            sha256: beam.sha256,
            md5: beam.md5,
            vsn: beam.vsn,
            old_sha256: beam.old_sha256,
            old_filename: beam.old_filename,
            old_md5: beam.old_md5,
            old_vsn: beam.old_vsn,
            stateful: beam.stateful,
            migration_extra: beam.migration_extra
          }
        end)
    }
  end

  defp build_modules(entries) do
    entries
    |> Enum.reduce_while({:ok, []}, fn
      {module, binary, entry_opts}, {:ok, acc} when is_list(entry_opts) ->
        case Beam.build(module, binary, entry_opts) do
          {:ok, beam} -> {:cont, {:ok, [beam | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end

      invalid, _acc ->
        {:halt, {:error, {:invalid_module_entry, invalid}}}
    end)
    |> case do
      {:ok, modules} -> {:ok, Enum.reverse(modules)}
      error -> error
    end
  end

  defp validate_epoch(epoch) when is_integer(epoch) and epoch > 0, do: :ok
  defp validate_epoch(epoch), do: {:error, {:invalid_epoch, epoch}}

  defp ensure_unique_modules(modules) do
    names = Enum.map(modules, & &1.module)
    if names == Enum.uniq(names), do: :ok, else: {:error, :duplicate_modules}
  end

  defp ensure_nonempty([]), do: {:error, :empty_artifact}
  defp ensure_nonempty(_modules), do: :ok
end
