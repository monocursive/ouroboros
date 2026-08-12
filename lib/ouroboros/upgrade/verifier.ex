defmodule Ouroboros.Upgrade.Verifier do
  @moduledoc """
  Fail-closed policy checks for fast-lane BEAM artifacts.

  The fast lane can replace agent behavior, but not this verifier, the upgrade
  executor, the application root, NIF/on-load code, or consolidated protocols.
  """

  alias Ouroboros.Upgrade.{Artifact, Beam}

  @protected_modules [Ouroboros.Application]
  @protected_prefix "Elixir.Ouroboros.Upgrade."

  @spec verify(Artifact.t(), keyword()) :: :ok | {:error, term()}
  def verify(artifact, trust_policy \\ [])

  def verify(%Artifact{} = artifact, trust_policy) when is_list(trust_policy) do
    verify_artifact(artifact, trust_policy, %{})
  end

  def verify(other, _trust_policy), do: {:error, {:invalid_artifact, other}}

  @doc false
  @spec verify_with_expected(Artifact.t(), keyword(), map()) :: :ok | {:error, term()}
  def verify_with_expected(%Artifact{} = artifact, trust_policy, expected_modules)
      when is_list(trust_policy) and is_map(expected_modules) do
    verify_artifact(artifact, trust_policy, expected_modules)
  end

  def verify_with_expected(other, _trust_policy, _expected_modules),
    do: {:error, {:invalid_artifact, other}}

  defp verify_artifact(artifact, trust_policy, expected_modules) do
    with :ok <- verify_policy(trust_policy),
         :ok <- verify_artifact_shape(artifact),
         :ok <- verify_runtime(artifact),
         :ok <- verify_modules(artifact.modules, expected_modules),
         :ok <- verify_signature(artifact, trust_policy) do
      :ok
    end
  end

  defp verify_policy(policy) do
    if Keyword.keyword?(policy), do: :ok, else: {:error, :invalid_trust_policy}
  end

  defp verify_artifact_shape(%Artifact{} = artifact) do
    modules = artifact.modules

    cond do
      not is_binary(artifact.id) or artifact.id == "" ->
        {:error, :invalid_artifact_id}

      not is_integer(artifact.epoch) or artifact.epoch <= 0 ->
        {:error, :invalid_artifact_epoch}

      not is_list(modules) or modules == [] ->
        {:error, :empty_artifact}

      not Enum.all?(modules, &match?(%Beam{}, &1)) ->
        {:error, :invalid_artifact_modules}

      modules |> Enum.map(& &1.module) |> Enum.uniq() |> length() != length(modules) ->
        {:error, :duplicate_modules}

      not Enum.all?(modules, &is_boolean(&1.stateful)) ->
        {:error, :invalid_stateful_declaration}

      not Enum.all?(modules, &Beam.portable_term?(&1.migration_extra)) ->
        {:error, :invalid_migration_extra}

      Enum.any?(modules, &(not &1.stateful and not is_nil(&1.migration_extra))) ->
        {:error, :migration_extra_for_stateless_module}

      not is_map(artifact.metadata) ->
        {:error, :invalid_artifact_metadata}

      true ->
        :ok
    end
  end

  defp verify_runtime(artifact) do
    expected = %{
      otp_release: to_string(:erlang.system_info(:otp_release)),
      elixir_version: System.version(),
      system_architecture: to_string(:erlang.system_info(:system_architecture))
    }

    actual = Map.take(artifact, [:otp_release, :elixir_version, :system_architecture])
    if actual == expected, do: :ok, else: {:error, {:runtime_mismatch, expected, actual}}
  end

  defp verify_modules(modules, expected_modules) do
    Enum.reduce_while(modules, :ok, fn beam, :ok ->
      case verify_module(beam, expected_modules) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp verify_module(%Beam{} = beam, expected_modules) do
    with :ok <- allowed_module(beam.module),
         false <- :code.is_sticky(beam.module),
         false <- :erlang.check_old_code(beam.module),
         {:ok, new_info} <- Beam.inspect_binary(beam.binary),
         {:ok, old_info} <- Beam.inspect_binary(beam.old_binary),
         true <- new_info.module == beam.module,
         true <- old_info.module == beam.module,
         true <- Beam.sha256(beam.binary) == beam.sha256,
         true <- Beam.sha256(beam.old_binary) == beam.old_sha256,
         true <- new_info.md5 == beam.md5,
         true <- old_info.md5 == beam.old_md5,
         true <- new_info.vsn == beam.vsn,
         true <- old_info.vsn == beam.old_vsn,
         false <- new_info.on_load?,
         false <- new_info.nif?,
         false <- new_info.protocol?,
         false <- old_info.on_load?,
         false <- old_info.nif?,
         false <- old_info.protocol?,
         :ok <- verify_current_object_code(beam, expected_modules),
         true <- beam.old_md5 == beam.module.module_info(:md5) do
      :ok
    else
      true -> {:error, {:forbidden_beam_feature, beam.module}}
      false -> {:error, {:module_verification_failed, beam.module}}
      {:error, reason} -> {:error, reason}
      actual -> {:error, {:module_verification_failed, beam.module, actual}}
    end
  rescue
    error -> {:error, {:module_verification_failed, beam.module, error}}
  end

  defp allowed_module(module) do
    name = Atom.to_string(module)

    if module in @protected_modules or String.starts_with?(name, @protected_prefix) do
      {:error, {:immutable_control_module, module}}
    else
      :ok
    end
  end

  defp verify_current_object_code(%Beam{} = beam, expected_modules) do
    case Map.get(expected_modules, beam.module) do
      %{sha256: sha256, md5: md5}
      when is_binary(sha256) and is_binary(md5) ->
        if sha256 == beam.old_sha256 and md5 == beam.old_md5,
          do: :ok,
          else: {:error, {:stale_preimage_sha256, beam.module}}

      nil ->
        verify_code_path_object(beam)

      _invalid ->
        {:error, {:invalid_expected_module_identity, beam.module}}
    end
  end

  defp verify_code_path_object(%Beam{} = beam) do
    case :code.get_object_code(beam.module) do
      {module, binary, _filename} when module == beam.module ->
        if Beam.sha256(binary) == beam.old_sha256,
          do: :ok,
          else: {:error, {:stale_preimage_sha256, beam.module}}

      :error ->
        {:error, {:current_object_code_unavailable, beam.module}}
    end
  end

  defp verify_signature(%Artifact{signature: nil}, trust_policy) do
    if Keyword.get(trust_policy, :allow_unsigned, false),
      do: :ok,
      else: {:error, :signature_required}
  end

  defp verify_signature(
         %Artifact{signature: %{signer: signer, value: signature}} = artifact,
         policy
       ) do
    trusted_signers = Keyword.get(policy, :trusted_signers, %{})

    cond do
      not is_map(trusted_signers) ->
        {:error, :invalid_trusted_signers}

      not is_binary(signer) or signer == "" ->
        {:error, :invalid_signer}

      not is_binary(signature) or byte_size(signature) != 64 ->
        {:error, {:invalid_signature, signer}}

      true ->
        verify_trusted_signature(artifact, signer, signature, trusted_signers)
    end
  end

  defp verify_signature(_artifact, _policy), do: {:error, :invalid_signature_envelope}

  defp verify_trusted_signature(artifact, signer, signature, trusted_signers) do
    case Map.fetch(trusted_signers, signer) do
      {:ok, public_key} when is_binary(public_key) and byte_size(public_key) == 32 ->
        try do
          if :crypto.verify(
               :eddsa,
               :none,
               Artifact.signing_payload(artifact, signer),
               signature,
               [public_key, :ed25519]
             ) do
            :ok
          else
            {:error, {:invalid_signature, signer}}
          end
        rescue
          _error -> {:error, {:invalid_signature, signer}}
        catch
          _kind, _reason -> {:error, {:invalid_signature, signer}}
        end

      {:ok, _invalid_key} ->
        {:error, {:invalid_signer_key, signer}}

      :error ->
        {:error, {:untrusted_signer, signer}}
    end
  end
end
